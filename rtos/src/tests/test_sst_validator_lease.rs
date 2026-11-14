// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Actual Engine-owned named-CF SST maintenance; no networking/physical GC claim.
use crate::{
    history_read_budget::HistoryReadBudget,
    internal_db::state_gc_resolver::AllowStateGcSmartResolver,
    publication_dependency_leases::{
        disk_full_tests::{control, enospc_root, Filler},
        sst_fixture_for_test, LeaseState,
    },
    test_helper::TestEngine,
};
use rtos_block::{Result, UInt256};
use std::{collections::BTreeMap, path::Path, sync::Arc, time::Duration};
use storage::{
    db::rocksdb::RocksDb, shardstate_db_async::AllowStateGcResolver, sst_native_test as rocksdb,
};

const TIMEOUT: Duration = Duration::from_secs(30);
const LEASE_CF: &str = "repair_dependency_leases_v1";

async fn joined<T: Send + 'static>(task: impl FnOnce() -> T + Send + 'static) -> T {
    let mut owner = tokio::task::spawn_blocking(task);
    tokio::time::timeout(TIMEOUT, &mut owner)
        .await
        .expect("native SST owner timed out; cold reopen forbidden")
        .expect("native SST owner panicked")
}

fn configure(db: &RocksDb) -> Result<()> {
    for name in rocksdb::DB::list_cf(&rocksdb::Options::default(), db.path())? {
        let options = [("disable_auto_compactions", "true"), ("write_buffer_size", "16777216")];
        if name == "default" {
            db.db().set_options(&options)?;
        } else {
            let family = db.db().cf_handle(&name).expect("existing named CF");
            db.db().set_options_cf(&family, &options)?;
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Input {
    name: String,
    level: i32,
    size: usize,
    start: Vec<u8>,
    end: Vec<u8>,
    hash: UInt256,
}

fn files(db: &RocksDb, cf: &str) -> Vec<Input> {
    let mut files: Vec<_> = db
        .db()
        .live_files()
        .unwrap()
        .into_iter()
        .filter(|file| file.column_family_name == cf)
        .map(|file| Input {
            hash: UInt256::calc_file_hash(
                &std::fs::read(db.path().join(file.name.trim_start_matches('/'))).unwrap(),
            ),
            name: file.name,
            level: file.level,
            size: file.size,
            start: file.start_key.expect("registered SST start key"),
            end: file.end_key.expect("registered SST end key"),
        })
        .collect();
    files.sort_by(|a, b| a.name.cmp(&b.name));
    files
}

fn snapshot(db: &Arc<RocksDb>, cf: &str) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let table = db.clone().table::<String>(cf, false).unwrap();
    let mut bytes = BTreeMap::new();
    table
        .for_each(&mut |key, value| {
            assert!(bytes.insert(key.to_vec(), value.to_vec()).is_none());
            Ok(true)
        })
        .unwrap();
    bytes
}

async fn flush(db: Arc<RocksDb>, cf: &'static str) -> Result<()> {
    joined(move || db.table::<String>(cf, false)?.flush_family()).await
}

async fn compact(db: Arc<RocksDb>, cf: &'static str, force: bool) {
    joined(move || {
        let family = db.db().cf_handle(cf).unwrap();
        let mut options = rocksdb::CompactOptions::default();
        options.set_exclusive_manual_compaction(true);
        options.set_change_level(true);
        options.set_target_level(6);
        options.set_bottommost_level_compaction(if force {
            rocksdb::BottommostLevelCompaction::Force
        } else {
            rocksdb::BottommostLevelCompaction::Skip
        });
        db.db().compact_range_cf_opt::<&[u8], &[u8]>(&family, None, None, &options);
    })
    .await;
    eprintln!("SST-OBS compact-return=unit cf={cf}");
}

async fn seed(db: &Arc<RocksDb>, cf: &'static str) -> Vec<Input> {
    flush(db.clone(), cf).await.unwrap();
    compact(db.clone(), cf, false).await;
    let seed = files(db, cf);
    assert_eq!(seed.len(), 1, "one registered seed SST in target CF");
    assert_eq!(seed[0].level, 6);
    seed
}

async fn inputs(db: &Arc<RocksDb>, cf: &'static str, seed: &[Input], rewrite: bool) -> Vec<Input> {
    assert_eq!(files(db, cf), seed, "second ACK dataset unexpectedly auto-flushed");
    if rewrite {
        flush(db.clone(), cf).await.unwrap();
    }
    let before = files(db, cf);
    assert_eq!(before.len(), if rewrite { 2 } else { 1 });
    if rewrite {
        let l0 = before.iter().find(|file| file.level == 0).expect("target L0 input");
        assert!(l0.start <= seed[0].end && seed[0].start <= l0.end, "actual input ranges overlap");
    }
    for file in &before {
        eprintln!(
            "SST-INPUT name={} cf={} level={} size={} range={:?}/{:?} sha256={:x}",
            file.name, cf, file.level, file.size, file.start, file.end, file.hash
        );
    }
    before
}

fn fresh(db: &RocksDb, cf: &str, before: &[Input], rewrite: bool) {
    let after = files(db, cf);
    let outputs: Vec<_> =
        after.iter().filter(|file| !before.iter().any(|old| old.name == file.name)).collect();
    assert!(!outputs.is_empty(), "no fresh registered target SST output");
    for file in outputs {
        if rewrite {
            assert_eq!(file.level, 6);
        }
        eprintln!(
            "SST-OUTPUT name={} cf={} level={} size={} sha256={:x}",
            file.name, cf, file.level, file.size, file.hash
        );
    }
}

async fn maintenance(
    db: &Arc<RocksDb>,
    cf: &'static str,
    rewrite: bool,
    fault: bool,
    before: &[Input],
) {
    if rewrite {
        compact(db.clone(), cf, true).await;
    } else {
        let result = flush(db.clone(), cf).await;
        eprintln!("SST-OBS flush-result={result:?} cf={cf}");
        if fault {
            let error = result.expect_err("full-disk named-CF flush acknowledged");
            assert!(format!("{error:#}").contains("No space left on device"));
        } else {
            result.unwrap();
        }
    }
    for property in [
        "rocksdb.background-errors",
        "rocksdb.num-running-flushes",
        "rocksdb.num-running-compactions",
    ] {
        eprintln!("SST-OBS {property}={:?}", db.db().property_int_value(property).unwrap());
    }
    eprintln!("SST-OBS independent-sync={:?}", db.sync_wal());
    if fault {
        assert_eq!(files(db, cf), before, "failed maintenance changed acknowledged inputs");
    } else {
        fresh(db, cf, before, rewrite);
    }
}

async fn close(engine: TestEngine) {
    let (node, catchain) = engine.db.sst_databases_for_test();
    tokio::time::timeout(TIMEOUT, engine.db.stop_states_db())
        .await
        .expect("archive/state owners timed out; cold reopen forbidden")
        .unwrap();
    assert_eq!(Arc::strong_count(&engine.db), 1, "InternalDb owners remain");
    drop(engine);
    tokio::time::timeout(TIMEOUT, async {
        while Arc::strong_count(&node) != 1 || Arc::strong_count(&catchain) != 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("physical DB owners did not drain; cold reopen forbidden");
    eprintln!("SST-OBS node-owners=1 catchain-owners=1");
    joined(move || {
        node.db().cancel_all_background_work(true);
        catchain.db().cancel_all_background_work(true);
        drop(node);
        drop(catchain);
    })
    .await;
    eprintln!("SST-OBS both-native-close=complete");
}

async fn open(path: &Path) -> TestEngine {
    let engine = TestEngine::new_db_dir(path.to_str().unwrap(), None).await.unwrap();
    let (node, catchain) = engine.db.sst_databases_for_test();
    configure(&node).unwrap();
    configure(&catchain).unwrap();
    engine
}

fn lease_ack(engine: &TestEngine) {
    let (base, deps, id) = sst_fixture_for_test();
    let leases = engine.db.repair_leases();
    for generation in [1, 2] {
        let mut binding = base.clone();
        binding.record_id = generation;
        binding.close_generation = generation;
        let record =
            leases.lookup(generation, &HistoryReadBudget::new(Default::default())).unwrap();
        assert_eq!(record.binding, binding.encode().unwrap());
        assert_eq!(record.binding().unwrap(), binding);
        assert_eq!(record.generation, generation);
        assert_eq!(record.dependencies, deps);
        assert_eq!(
            record.dependency_digest,
            format!(
                "{:x}",
                crate::publication_dependency_leases::dependency_digest(&deps).unwrap()
            )
        );
        assert_eq!(
            record.state,
            if generation == 1 { LeaseState::DurableCustody } else { LeaseState::Protecting }
        );
        assert_eq!(
            leases
                .begin(&binding, deps.clone(), &HistoryReadBudget::new(Default::default()))
                .unwrap(),
            generation
        );
    }
    assert_eq!(leases.protection().references(&id).0, 2);
    let protected =
        AllowStateGcSmartResolver::with_repair_protection(0, leases.protection().clone());
    let unprotected = AllowStateGcSmartResolver::new(0);
    protected.test_advance_expired_mc_boundary(id.seq_no() + 1);
    unprotected.test_advance_expired_mc_boundary(id.seq_no() + 1);
    assert!(AllowStateGcResolver::allow_state_gc(&unprotected, &id, 0, 0).unwrap());
    assert!(!AllowStateGcResolver::allow_state_gc(&protected, &id, 0, 0).unwrap());
}

async fn lease_case(path: &Path, rewrite: bool, fault: bool) {
    std::fs::create_dir_all(path).unwrap();
    let engine = open(path).await;
    let (node, catchain) = engine.db.sst_databases_for_test();
    drop(catchain);
    let (mut binding, deps, _) = sst_fixture_for_test();
    let budget = HistoryReadBudget::new(Default::default());
    assert_eq!(engine.db.repair_leases().begin(&binding, deps.clone(), &budget).unwrap(), 1);
    engine.db.repair_leases().durable(1, &budget).unwrap();
    let initial = seed(&node, LEASE_CF).await;
    binding.record_id = 2;
    binding.close_generation = 2;
    assert_eq!(engine.db.repair_leases().begin(&binding, deps.clone(), &budget).unwrap(), 2);
    engine.db.repair_leases().durable(1, &budget).unwrap();
    lease_ack(&engine);
    let acknowledged = snapshot(&node, LEASE_CF);
    assert_eq!(acknowledged.get(b"next".as_slice()).unwrap(), &2u64.to_le_bytes());
    let before = inputs(&node, LEASE_CF, &initial, rewrite).await;
    let filler = fault.then(|| Filler::fill(path));
    maintenance(&node, LEASE_CF, rewrite, fault, &before).await;
    if let Some(filler) = filler {
        filler.free();
    }
    lease_ack(&engine);
    assert_eq!(snapshot(&node, LEASE_CF), acknowledged);
    drop(node);
    close(engine).await;
    let engine = open(path).await;
    lease_ack(&engine);
    let (node, catchain) = engine.db.sst_databases_for_test();
    drop(catchain);
    assert_eq!(snapshot(&node, LEASE_CF), acknowledged, "first cold before retry");
    // A control cold boot has no memtable to flush. Re-ACK the same record
    // through its producer so retry tests a real flush, preserving every byte.
    if !rewrite {
        engine.db.repair_leases().durable(1, &budget).unwrap();
    }
    let before = files(&node, LEASE_CF);
    maintenance(&node, LEASE_CF, rewrite, false, &before).await;
    lease_ack(&engine);
    assert_eq!(snapshot(&node, LEASE_CF), acknowledged);
    drop(node);
    close(engine).await;
    let engine = open(path).await;
    lease_ack(&engine);
    let (node, catchain) = engine.db.sst_databases_for_test();
    assert_eq!(snapshot(&node, LEASE_CF), acknowledged, "second cold");
    drop(node);
    drop(catchain);
    binding.record_id = 3;
    binding.close_generation = 3;
    assert_eq!(engine.db.repair_leases().begin(&binding, deps, &budget).unwrap(), 3);
    close(engine).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "disk-full harness only"]
async fn disk_full_node_lease_sst_flush_preserves_acknowledged_consumers() {
    lease_case(&enospc_root().join("node-lease-sst-flush"), false, !control()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "disk-full harness only"]
async fn disk_full_node_lease_sst_compact_preserves_acknowledged_consumers() {
    lease_case(&enospc_root().join("node-lease-sst-compact"), true, !control()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_lease_sst_consumer_and_all_owner_teardown_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    lease_case(dir.path(), true, false).await;
}

fn checkpoint() -> rtos_block::BlockIdExt {
    rtos_block::BlockIdExt::with_params(
        rtos_block::ShardIdent::masterchain(),
        42,
        UInt256::from([42; 32]),
        UInt256::from([43; 32]),
    )
}

fn cleanup(byte: u8, v2: bool) -> consensus_common::validator_cleanup::PendingValidatorCleanup {
    use consensus_common::{
        session_runtime::{SessionNetworkPin, SessionRecoveryBinding, SessionRecoveryCoordinates},
        validator_cleanup::{
            make_record, CleanupIdentity, CleanupJournal, JournalPayload, NamespaceLayout,
        },
    };
    let id = checkpoint();
    let mut record = make_record(
        &UInt256::from([byte; 32]),
        &if v2 { NamespaceLayout::V2Validator } else { NamespaceLayout::V1 },
        &rtos_block::ShardIdent::masterchain(),
        5,
        &id,
    )
    .unwrap();
    if v2 {
        record = record
            .with_identity(CleanupIdentity {
                pin: SessionNetworkPin { global_id: -239, zerostate: id.clone() },
                binding: SessionRecoveryBinding {
                    governing_masterchain: id,
                    coordinates: SessionRecoveryCoordinates {
                        shard: rtos_block::ShardIdent::masterchain(),
                        catchain_seqno: 5,
                        vertical_seqno: 0,
                        last_key_block_seqno: 0,
                        new_catchain_ids: false,
                    },
                },
                local_adnl: UInt256::from([4; 32]),
            })
            .unwrap();
        record.journal = CleanupJournal::Deleting(JournalPayload {
            attempt: (1 << 32) | u64::from(byte),
            generation: 1,
            manifest_digest: UInt256::from([5; 32]),
            inventory_digest: UInt256::from([6; 32]),
            associations: Vec::new(),
        });
    }
    record
}

fn deleted(byte: u8) -> consensus_common::validator_cleanup::PendingValidatorCleanup {
    use consensus_common::validator_cleanup::CleanupJournal;
    let mut record = cleanup(byte, true);
    let CleanupJournal::Deleting(payload) = record.journal else { unreachable!() };
    record.journal = CleanupJournal::Deleted(payload);
    record
}

fn keeper(
    engine: &TestEngine,
) -> (Arc<crate::shard_states_keeper::ShardStatesKeeper>, Arc<crate::engine::Stopper>) {
    let stopper = Arc::new(crate::engine::Stopper::new());
    let keeper = crate::shard_states_keeper::ShardStatesKeeper::new(
        engine.db.clone(),
        false,
        true,
        0,
        0,
        crate::config::ShardStatesCacheMode::Moderate,
        3600.0,
        stopper.clone(),
        100,
        #[cfg(feature = "telemetry")]
        crate::collator_test_bundle::create_engine_telemetry(),
        crate::collator_test_bundle::create_engine_allocated(),
    )
    .unwrap();
    (keeper, stopper)
}

async fn adopt_floor(engine: &TestEngine) {
    let (keeper, stopper) = keeper(engine);
    let id = checkpoint();
    let handle = engine.db.create_test_block_handle(&id).unwrap();
    let mut header =
        rtos_block::ShardStateUnsplit::with_ident(rtos_block::ShardIdent::masterchain());
    header.set_seq_no(42);
    // A GC floor is a masterchain state: it carries the masterchain extra.
    header.write_custom(Some(&rtos_block::McStateExtra::default())).unwrap();
    let state = crate::shard_state::ShardStateStuff::from_state(
        id.clone(),
        header,
        #[cfg(feature = "telemetry")]
        &crate::collator_test_bundle::create_engine_telemetry(),
        &crate::collator_test_bundle::create_engine_allocated(),
    )
    .unwrap();
    keeper.store_state(&handle, state, None, true).await.unwrap();
    let guard = tokio::time::timeout(TIMEOUT, async {
        loop {
            if let Ok(pin) = keeper.pin_cleanup_candidate(&id) {
                break pin;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("floor state did not become physically readable");
    keeper.adopt_cleanup_floor(&id, guard, keeper.cleanup_floor_epoch()).unwrap();
    engine.db.sync_publication_metadata(&handle).await.unwrap();
    let (node, catchain) = engine.db.sst_databases_for_test();
    node.sync_wal().unwrap();
    catchain.sync_wal().unwrap();
    stopper.set_stop();
    drop(keeper);
}

fn validator_ack(engine: &TestEngine) {
    use crate::{
        internal_db::DESTROYED_VALIDATOR_SESSIONS, validator::validator_cleanup_gc::load_record,
    };
    use consensus_common::validator_cleanup::{
        candidate_claim_key, decode_checkpoint, encode_record, record_key, GC_FLOOR_KEY,
    };
    for byte in [7, 9] {
        let expected = deleted(byte);
        assert_eq!(load_record(&engine.db, &expected.namespace).unwrap(), Some(expected.clone()));
        assert_eq!(
            engine
                .db
                .load_validator_state_key_bounded(&record_key(&expected.namespace), 1 << 20)
                .unwrap(),
            Some(encode_record(&expected).unwrap())
        );
    }
    let c = cleanup(11, false);
    assert!(load_record(&engine.db, &c.namespace).unwrap().is_none());
    assert_eq!(
        engine
            .db
            .load_validator_state_key_bounded(&candidate_claim_key(&c.session_id), 1 << 20)
            .unwrap(),
        Some(c.namespace.into_bytes())
    );
    let fence = std::collections::HashSet::from([
        cleanup(7, true).session_id,
        cleanup(9, true).session_id,
        c.session_id,
    ]);
    assert_eq!(
        engine.db.load_validator_state_key_bounded(DESTROYED_VALIDATOR_SESSIONS, 1 << 20).unwrap(),
        Some(crate::engine_operations::serialize_destroyed_session_ids(&fence))
    );
    let raw = engine.db.load_validator_state_key_bounded(GC_FLOOR_KEY, 256).unwrap().unwrap();
    assert_eq!(decode_checkpoint(&raw), Some(checkpoint()));
    assert!(engine.db.check_truncation_above_cleanup_floor(41).is_err());
    engine.db.check_truncation_above_cleanup_floor(42).unwrap();
    let (keeper, stopper) = keeper(engine);
    let (id, state) =
        keeper.cleanup_floor().expect("cold cleanup floor must be physically re-pinned");
    assert_eq!(id, checkpoint());
    assert_eq!(state.block_id(), &checkpoint());
    assert!(keeper.begin_truncation(41).is_err());
    drop(keeper.begin_truncation(42).unwrap());
    stopper.set_stop();
    drop(keeper);
}

async fn validator_case(path: &Path, rewrite: bool, fault: bool) {
    use crate::validator::validator_cleanup_gc::{erase_record, persist_retirement, write_journal};
    const CF: &str = storage::block_handle_db::VALIDATOR_STATE_DB_NAME;
    std::fs::create_dir_all(path).unwrap();
    let engine = open(path).await;
    let (node, catchain) = engine.db.sst_databases_for_test();
    drop(node);
    let (a, b, c) = (cleanup(7, true), cleanup(9, true), cleanup(11, false));
    let mut fence = std::collections::HashSet::from([a.session_id.clone(), c.session_id.clone()]);
    persist_retirement(&engine.db, &fence, &[a.clone(), c.clone()]).unwrap();
    erase_record(&engine.db, &c.namespace, Some(&c.session_id)).unwrap();
    adopt_floor(&engine).await;
    let initial = seed(&catchain, CF).await;
    fence.insert(b.session_id.clone());
    persist_retirement(&engine.db, &fence, std::slice::from_ref(&b)).unwrap();
    write_journal(&engine.db, &a, &deleted(7)).unwrap().unwrap();
    write_journal(&engine.db, &b, &deleted(9)).unwrap().unwrap();
    validator_ack(&engine);
    let acknowledged = snapshot(&catchain, CF);
    let before = inputs(&catchain, CF, &initial, rewrite).await;
    let filler = fault.then(|| Filler::fill(path));
    maintenance(&catchain, CF, rewrite, fault, &before).await;
    if let Some(filler) = filler {
        filler.free();
    }
    validator_ack(&engine);
    assert_eq!(snapshot(&catchain, CF), acknowledged);
    drop(catchain);
    close(engine).await;
    let engine = open(path).await;
    validator_ack(&engine);
    let (node, catchain) = engine.db.sst_databases_for_test();
    drop(node);
    assert_eq!(snapshot(&catchain, CF), acknowledged, "first cold before retry");
    if !rewrite {
        write_journal(&engine.db, &deleted(7), &deleted(7)).unwrap().unwrap();
    }
    let before = files(&catchain, CF);
    maintenance(&catchain, CF, rewrite, false, &before).await;
    validator_ack(&engine);
    assert_eq!(snapshot(&catchain, CF), acknowledged);
    drop(catchain);
    close(engine).await;
    let engine = open(path).await;
    validator_ack(&engine);
    let (node, catchain) = engine.db.sst_databases_for_test();
    assert_eq!(snapshot(&catchain, CF), acknowledged, "second cold");
    drop(node);
    drop(catchain);
    close(engine).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "disk-full harness only"]
async fn disk_full_validator_sst_flush_preserves_acknowledged_consumers() {
    validator_case(&enospc_root().join("validator-sst-flush"), false, !control()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "disk-full harness only"]
async fn disk_full_validator_sst_compact_preserves_acknowledged_consumers() {
    validator_case(&enospc_root().join("validator-sst-compact"), true, !control()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validator_sst_consumer_and_all_owner_teardown_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    validator_case(dir.path(), true, false).await;
}
