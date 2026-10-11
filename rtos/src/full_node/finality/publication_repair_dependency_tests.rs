// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Independent dependency failures after real MC1/MC2 application and cold reopen.
use super::*;
use consensus_common::session_runtime::AuthenticatedSessionRuntime;
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};
use storage::db::rocksdb::{AccessType, RocksDb, NODE_DB_NAME};

struct Fixture {
    dir: tempfile::TempDir,
    engine: Arc<Engine>,
    parent: BlockStuff,
    target: BlockStuff,
    request: McFinalRepairRequest,
}

async fn fixture(key_parent: bool) -> Fixture {
    let input: serde_json::Value =
        serde_json::from_str(include_str!("testdata/mc-repair-dependencies.json")).unwrap();
    let row = &input["rows"][usize::from(key_parent)];
    let zero: BlockIdExt = input["zero"].as_str().unwrap().parse().unwrap();
    let zero_bytes = decode(&input["state_boc"]);
    let dir = tempfile::tempdir().unwrap();
    write_recovery_config(dir.path(), &zero, true);
    let config_path = dir.path().join("config.json");
    let mut config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
    config["gc"] = serde_json::json!({"enable_for_archives":false,
        "enable_for_shard_state_persistent":false,
        "cells_gc_config":{"gc_interval_sec":1,"cells_lifetime_sec":0}});
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    config["ip_address_quic"] = socket.local_addr().unwrap().to_string().into();
    drop(socket);
    std::fs::write(config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    let engine = open_engine(dir.path()).await;
    let setup = std::panic::AssertUnwindSafe(async {
        let zero_state = ShardStateStuff::from_root_cell(
            zero.clone(),
            read_single_root_boc(&zero_bytes).unwrap(),
            #[cfg(feature = "telemetry")]
            engine.engine_telemetry(),
            engine.engine_allocated(),
        )
        .unwrap();
        let (_, zero_handle) = engine.store_zerostate(zero_state, &zero_bytes).await.unwrap();
        engine.set_applied(&zero_handle, 0).await.unwrap();
        engine.save_last_applied_mc_block_id(&zero).unwrap();
        engine.save_shard_client_mc_block_id(&zero).unwrap();
        let mut blocks = Vec::new();
        for name in ["parent", "target"] {
            let data = &row[name];
            let block = fixture_block(data);
            let proof = BlockProofStuff::deserialize(block.id(), decode(&data["proof_boc"]), false)
                .unwrap();
            let handle = engine.store_block(&block).await.unwrap().to_any();
            engine.store_block_proof(block.id(), Some(handle.clone()), &proof).await.unwrap();
            assert!(!handle.is_applied());
            // Real production proof authentication, parent application, Merkle state
            // calculation and archive/metadata transition. Never set_applied here.
            engine
                .clone()
                .download_and_apply_block(block.id(), block.id().seq_no(), false)
                .await
                .unwrap();
            assert!(handle.is_applied());
            assert_eq!(
                engine.load_state(block.id()).await.unwrap().root_cell().repr_hash(),
                read_single_root_boc(&decode(&data["state_boc"])).unwrap().repr_hash()
            );
            assert_eq!(
                engine.load_last_applied_mc_block_id().unwrap().as_deref(),
                Some(block.id())
            );
            blocks.push(block);
        }
        let target = blocks.pop().unwrap();
        let parent = blocks.pop().unwrap();
        let context = engine
            .historical_pq_publication_context(target.id(), target.block().unwrap())
            .await
            .unwrap();
        let request = McFinalRepairRequest {
            pin: SessionNetworkPin {
                global_id: context.global_id(),
                zerostate: context.zerostate().clone(),
            },
            history_init: context.history_init().clone(),
            block_id: target.id().clone(),
            session_id: context.verifier().expected_session_id().clone(),
            profile: context.profile().clone(),
            protocol: context.protocol(),
            carrier_version: context.carrier_version(),
            wire_profile: WireProfile::T0,
        };
        drop(repair_mc_final(engine.clone(), request.clone()).await.unwrap());
        (parent, target, request)
    })
    .catch_unwind()
    .await;
    match setup {
        Ok((parent, target, request)) => Fixture { dir, engine, parent, target, request },
        Err(panic) => {
            engine.wait_stop().await.unwrap();
            std::panic::resume_unwind(panic)
        }
    }
}

async fn close(engine: Arc<Engine>) {
    engine.clone().wait_stop().await.unwrap();
    let weak = Arc::downgrade(&engine);
    drop(engine);
    assert!(
        weak.upgrade().is_none(),
        "cold fixture must release the old Engine and verifier cache"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mc_live_repair_dependency_missing_parent_state_defers_with_history_intact() {
    let Fixture { dir, engine, parent, target, request } = fixture(false).await;
    close(engine).await;
    let engine = open_engine(dir.path()).await;
    let result = std::panic::AssertUnwindSafe(async {
        engine.shard_states_keeper().test_retire_history_state(parent.id());
        tokio::time::timeout(Duration::from_secs(15), async {
            while engine.db().test_contains_dynamic_state_record(parent.id()).unwrap() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("actual GC must delete nonzero parent state");
        assert!(engine.db().test_contains_dynamic_state_record(target.id()).unwrap());
    })
    .catch_unwind()
    .await;
    close(engine).await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    let engine = open_engine(dir.path()).await;
    let result = std::panic::AssertUnwindSafe(async {
        assert!(!engine.db().test_contains_dynamic_state_record(parent.id()).unwrap());
        assert!(engine.db().test_contains_dynamic_state_record(target.id()).unwrap());
        assert!(engine.load_block_handle(target.id()).unwrap().unwrap().is_applied());
        // Target Final authenticates from zero. This deliberately verifies that
        // missing parent is isolated from the separate history-failure scenario.
        engine
            .load_block_proof(&engine.load_block_handle(target.id()).unwrap().unwrap(), false)
            .await
            .unwrap()
            .check_proof(engine.as_ref())
            .await
            .unwrap();
        assert!(repair_mc_final(engine.clone(), request).await.is_err());
        assert!(
            !engine.db().test_contains_dynamic_state_record(parent.id()).unwrap(),
            "repair must not secretly reconstruct an unbounded parent chain"
        );
    })
    .catch_unwind()
    .await;
    close(engine).await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

// Corrupt only the exact proof payload, preserving package entry offsets and
// all other artifacts. Backups permit a cold positive restoration control.
fn withdraw_proof(root: &Path, proof: &[u8]) -> Vec<(PathBuf, Vec<u8>)> {
    let mut pending = vec![root.join("archive")];
    let mut backups = Vec::new();
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            if path.extension().is_some_and(|ext| ext == "pack")
                || path.parent().is_some_and(|p| p.ends_with("unapplied"))
            {
                let mut bytes = std::fs::read(&path).unwrap();
                let positions = bytes
                    .windows(proof.len())
                    .enumerate()
                    .filter_map(|(i, data)| (data == proof).then_some(i))
                    .collect::<Vec<_>>();
                if !positions.is_empty() {
                    backups.push((path.clone(), bytes.clone()));
                    for position in positions {
                        bytes[position] ^= 0xff;
                    }
                    std::fs::write(&path, bytes).unwrap();
                }
            }
        }
    }
    assert!(!backups.is_empty(), "actual ordinary key proof must be withdrawn");
    backups
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mc_live_repair_dependency_cold_missing_key_history_and_capsule_defers() {
    let Fixture { dir, engine, parent, target, request } = fixture(true).await;
    let setup = std::panic::AssertUnwindSafe(async {
        let state = engine.load_state(parent.id()).await.unwrap();
        let config = state.config_params().unwrap();
        let (committee, _) = config
            .validator_set()
            .unwrap()
            .calc_subset(&config.catchain_config().unwrap(), SHARD_FULL, -1, 0)
            .unwrap();
        let runtime = AuthenticatedSessionRuntime::from_authenticated_config(
            request.pin.clone(),
            config,
            rtos_api::session_identity::SessionCoordinates {
                shard: target.id().shard(),
                catchain_seqno: 0,
                vertical_seqno: 0,
                last_key_block_seqno: 1,
                new_catchain_ids: false,
            },
            committee,
            rtos_block::KeyId::from_data([0x91; 32]),
        )
        .unwrap()
        .bind_recovery_anchor(parent.id().clone())
        .unwrap();
        crate::retired_history::prepare(engine.clone(), Arc::new(runtime), target.id().clone())
            .await
            .unwrap();
        let proof = engine
            .load_block_proof(&engine.load_block_handle(parent.id()).unwrap().unwrap(), false)
            .await
            .unwrap();
        (PathBuf::from(engine.db_root_dir().unwrap()), proof.data().to_vec())
    })
    .catch_unwind()
    .await;
    close(engine).await;
    let (root, proof) = setup.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    let backups = withdraw_proof(&root, &proof);
    let capsule = root.join("retired-history-v1");
    let withdrawn = root.join("withdrawn-history");
    assert!(capsule.is_dir());
    std::fs::rename(&capsule, &withdrawn).unwrap();
    let engine = open_engine(dir.path()).await;
    let result = std::panic::AssertUnwindSafe(async {
        // First authentication on this cold Engine is the actual repair request.
        // No context factory or check_proof before it can warm authority caches.
        assert!(engine.db().test_contains_dynamic_state_record(parent.id()).unwrap());
        assert!(engine.db().test_contains_dynamic_state_record(target.id()).unwrap());
        let outcome = tokio::time::timeout(
            Duration::from_secs(40),
            repair_mc_final(engine.clone(), request.clone()),
        )
        .await
        .unwrap();
        assert!(outcome.is_err(), "missing ordinary+capsule+peer history cannot produce custody");
        assert!(engine.load_block_handle(target.id()).unwrap().unwrap().is_applied());
    })
    .catch_unwind()
    .await;
    close(engine).await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    for (path, bytes) in backups {
        std::fs::write(path, bytes).unwrap();
    }
    std::fs::rename(withdrawn, capsule).unwrap();
    let engine = open_engine(dir.path()).await;
    let result = std::panic::AssertUnwindSafe(async {
        let custody = repair_mc_final(engine.clone(), request).await.unwrap();
        assert_eq!(custody.block_id(), target.id());
        drop(custody);
    })
    .catch_unwind()
    .await;
    close(engine).await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

fn cells(root: &Cell) -> HashMap<UInt256, Cell> {
    let mut found = HashMap::new();
    let mut stack = vec![root.clone()];
    while let Some(cell) = stack.pop() {
        if found.contains_key(cell.repr_hash()) {
            continue;
        }
        for i in 0..cell.references_count() {
            stack.push(cell.reference(i).unwrap());
        }
        found.insert(cell.repr_hash().clone(), cell);
    }
    found
}

// Raw fault injection must replay the same merge operands as production.
// Opening with default CF options can stop WAL recovery at a counter Merge.
fn open_cells_for_fault_injection(root: &Path) -> Arc<RocksDb> {
    use storage::{dynamic_boc_rc_db::DynamicBocDb, shardstate_db_async::CellsDbConfig};
    let config = CellsDbConfig::default();
    let (cells, cells_cache) = DynamicBocDb::build_cells_cf_options(&config);
    let (counters, counters_cache) = DynamicBocDb::build_counters_cf_options(&config);
    let options = HashMap::from([
        ("cells_db_v6".to_owned(), cells),
        ("cells_db_v6_counters".to_owned(), counters),
    ]);
    let db = RocksDb::new(root, NODE_DB_NAME, options, AccessType::ReadWrite).unwrap();
    db.register_cache(cells_cache);
    db.register_cache(counters_cache);
    db
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mc_live_repair_dependency_missing_target_only_child_never_returns_custody() {
    let Fixture { dir, engine, parent, target, request } = fixture(false).await;
    let setup = std::panic::AssertUnwindSafe(async {
        let parent_state = engine.load_state(parent.id()).await.unwrap();
        let zero = engine.load_mc_zero_state().await.unwrap();
        let target_state = engine.load_state(target.id()).await.unwrap();
        let excluded: HashSet<_> = cells(parent_state.root_cell())
            .into_keys()
            .chain(cells(zero.root_cell()).into_keys())
            .collect();
        let all = cells(target_state.root_cell());
        let children = all
            .iter()
            .filter(|(hash, _)| {
                *hash != target_state.root_cell().repr_hash() && !excluded.contains(*hash)
            })
            .map(|(hash, _)| hash.clone())
            .collect::<Vec<_>>();
        assert!(!children.is_empty(), "fixture needs target-only descendants");
        (
            PathBuf::from(engine.db_root_dir().unwrap()),
            children,
            target_state.root_cell().repr_hash().clone(),
        )
    })
    .catch_unwind()
    .await;
    close(engine).await;
    let (root, mut children, expected_root) =
        setup.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    let db = open_cells_for_fault_injection(&root);
    let table = db.clone().table::<UInt256>("cells_db_v6", false).unwrap();
    assert!(table.try_get_raw(expected_root.as_slice()).unwrap().is_some());
    children.sort();
    let child = children.into_iter().next().unwrap();
    let bytes = table
        .try_get_raw(child.as_slice())
        .unwrap()
        .expect("selected target-only descendant must physically exist")
        .to_vec();
    table.delete_raw(child.as_slice()).unwrap();
    db.sync_wal().unwrap();
    drop(table);
    drop(db);
    let engine = open_engine(dir.path()).await;
    let result = std::panic::AssertUnwindSafe(async {
        assert!(engine.db().test_contains_dynamic_state_record(target.id()).unwrap());
        let root_cell = engine.db().load_cell(&expected_root).unwrap();
        assert_eq!(root_cell.repr_hash(), &expected_root, "physical root still exists");
        assert!(engine.db().load_cell(&child).is_err(), "physical descendant is unavailable");
        assert!(
            repair_mc_final(engine.clone(), request.clone()).await.is_err(),
            "broken descendant must defer"
        );
        assert!(
            engine.db().load_cell(&child).is_err(),
            "repair must not silently rebuild a present root"
        );
    })
    .catch_unwind()
    .await;
    close(engine).await;
    let db = open_cells_for_fault_injection(&root);
    let table = db.clone().table::<UInt256>("cells_db_v6", false).unwrap();
    table.put_raw_sync(child.as_slice(), &bytes).unwrap();
    drop(table);
    drop(db);
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    let engine = open_engine(dir.path()).await;
    let result = std::panic::AssertUnwindSafe(async {
        drop(repair_mc_final(engine.clone(), request).await.unwrap());
    })
    .catch_unwind()
    .await;
    close(engine).await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_state_actual_engine_cold_warm_and_budget_rejection() {
    use crate::history_read_budget::{HistoryBudgetExceeded, HistoryReadBudget, HistoryReadLimits};
    let Fixture { dir, engine, parent: _, target, request: _ } = fixture(false).await;
    close(engine).await;
    let engine = open_engine(dir.path()).await;
    let result = std::panic::AssertUnwindSafe(async {
        let expected = target.block().unwrap().read_state_update().unwrap().new_hash;
        for _ in 0..2 {
            let state = engine
                .load_state_bounded(target.id(), HistoryReadBudget::new(Default::default()))
                .await
                .unwrap();
            assert_eq!(state.root_cell().repr_hash(), &expected);
            let denied = engine
                .load_state_bounded(
                    target.id(),
                    HistoryReadBudget::new(HistoryReadLimits { cells: 0, ..Default::default() }),
                )
                .await
                .err()
                .unwrap();
            assert!(denied.downcast_ref::<HistoryBudgetExceeded>().is_some());
            // The failure does not poison global cells, state caches or ordinary boot.
            assert_eq!(
                engine.load_state(target.id()).await.unwrap().root_cell().repr_hash(),
                &expected
            );
        }
        let budget = HistoryReadBudget::new(Default::default());
        let (entered, release) = budget.pause_next_cell();
        let reader_engine = engine.clone();
        let id = target.id().clone();
        let reader =
            tokio::spawn(async move { reader_engine.load_state_bounded(&id, budget).await });
        entered.await.unwrap();
        reader.abort();
        assert!(reader.await.unwrap_err().is_cancelled());
        let stopper_engine = engine.clone();
        let mut stopped = tokio::spawn(async move { stopper_engine.wait_stop().await });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut stopped).await.is_err(),
            "caller cancellation must not release the real blocking reader"
        );
        release.send(()).unwrap();
        stopped.await.unwrap().unwrap();
    })
    .catch_unwind()
    .await;
    close(engine).await;
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
