// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Validator consensus cleanup driven by the manager: the tick, the storage
//! cleanup reservation, owned delete workers, the durable erase and its retry.
use super::*;
use crate::{
    collator_test_bundle::{create_block_handle_storage, create_engine_allocated},
    shard_state::ShardStateStuff,
    validator::validator_cleanup_gc::{delete_candidate_table, delete_v1_namespace},
};
use consensus_common::validator_cleanup::{
    make_record, record_key, NamespaceLayout, Page, PendingValidatorCleanup,
};
use rtos_block::{
    ExtBlkRef, HashmapAugType, KeyExtBlkRef, KeyMaxLt, McStateExtra, ShardStateUnsplit,
};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, AtomicU8, AtomicUsize},
        Mutex,
    },
};

/// How the engine's blocking delete behaves for one session.
#[derive(Clone)]
enum DeleteBehaviour {
    Real,
    Panic,
    /// Blocks until a message arrives on the channel.
    Held(Arc<Mutex<std::sync::mpsc::Receiver<()>>>),
}

struct CleanupEngine {
    root: tempfile::TempDir,
    root_str: String,
    status: AtomicU8,
    floor: Mutex<Option<(BlockIdExt, Arc<ShardStateStuff>)>>,
    records: Mutex<BTreeMap<String, PendingValidatorCleanup>>,
    behaviour: Mutex<HashMap<UInt256, DeleteBehaviour>>,
    erase_failures: AtomicUsize,
    claims: Mutex<BTreeMap<UInt256, String>>,
    claim_erase_failures: AtomicUsize,
    admitted: Mutex<HashSet<UInt256>>,
    registry: Arc<crate::validator::finality_recovery_owner::RecoveryRegistry>,
    v2_verdict: Mutex<Option<consensus_common::validator_cleanup::CleanupVerdict>>,
    v2_attempts: AtomicUsize,
    page_reads: AtomicUsize,
    stop: AtomicBool,
}

impl CleanupEngine {
    fn new() -> Arc<Self> {
        let root = tempfile::tempdir().unwrap();
        let root_str = root.path().to_str().unwrap().to_owned();
        Arc::new(Self {
            root,
            root_str,
            status: AtomicU8::new(0),
            floor: Mutex::new(None),
            records: Mutex::new(BTreeMap::new()),
            behaviour: Mutex::new(HashMap::new()),
            erase_failures: AtomicUsize::new(0),
            claims: Mutex::new(BTreeMap::new()),
            claim_erase_failures: AtomicUsize::new(0),
            admitted: Mutex::new(HashSet::new()),
            registry: Default::default(),
            v2_verdict: Mutex::new(None),
            v2_attempts: AtomicUsize::new(0),
            page_reads: AtomicUsize::new(0),
            stop: AtomicBool::new(false),
        })
    }
    fn put(&self, record: &PendingValidatorCleanup) {
        self.records.lock().unwrap().insert(record_key(&record.namespace), record.clone());
    }
    fn has_record(&self, record: &PendingValidatorCleanup) -> bool {
        self.records.lock().unwrap().contains_key(&record_key(&record.namespace))
    }
    fn has_claim(&self, session: &UInt256) -> bool {
        self.claims.lock().unwrap().contains_key(session)
    }
    fn namespace_dir(&self, record: &PendingValidatorCleanup) -> std::path::PathBuf {
        self.root.path().join("catchains/consensus").join(&record.namespace)
    }
    fn candidates_dir(&self, session: &UInt256) -> std::path::PathBuf {
        self.root.path().join("catchains").join(format!("candidates{:x}", session))
    }
    /// Lays out a retired V1 namespace with a database child and a
    /// candidate table on disk.
    fn materialize(&self, record: &PendingValidatorCleanup) {
        let db = self.namespace_dir(record).join(record.session_id.to_hex_string());
        std::fs::create_dir_all(&db).unwrap();
        std::fs::write(db.join("CURRENT"), b"x").unwrap();
        std::fs::create_dir_all(self.candidates_dir(&record.session_id)).unwrap();
    }
    fn gone(&self, record: &PendingValidatorCleanup) -> bool {
        !self.namespace_dir(record).exists()
    }
    fn table_gone(&self, session: &UInt256) -> bool {
        !self.candidates_dir(session).exists()
    }
}

#[async_trait::async_trait]
impl EngineOperations for CleanupEngine {
    fn validation_status(&self) -> ValidationStatus {
        ValidationStatus::from_u8(self.status.load(Ordering::Relaxed))
    }
    fn set_validation_status(&self, status: ValidationStatus) {
        self.status.store(status as u8, Ordering::Relaxed);
    }
    fn set_will_validate(&self, _: bool) {}
    fn save_destroyed_session_ids(&self, _: &HashSet<UInt256>) -> Result<()> {
        Ok(())
    }
    fn check_stop(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }
    fn db_root_dir(&self) -> Result<&str> {
        Ok(&self.root_str)
    }
    async fn wait_next_applied_mc_block(
        &self,
        _prev_handle: &storage::block_handle_db::BlockHandle,
        _timeout_ms: Option<u64>,
    ) -> Result<(Arc<storage::block_handle_db::BlockHandle>, crate::block::BlockStuff)> {
        // A busy masterchain: every wait ends quickly.
        tokio::time::sleep(Duration::from_millis(5)).await;
        fail!("next masterchain block is not materialized in this test")
    }
    async fn maintain_validator_cleanup_floor(&self) -> Result<()> {
        Ok(())
    }
    fn validator_cleanup_floor(&self) -> Option<(BlockIdExt, Arc<ShardStateStuff>)> {
        self.floor.lock().unwrap().clone()
    }
    fn load_validator_cleanup_page(&self, after: &str, max_keys: usize) -> Result<Page> {
        self.page_reads.fetch_add(1, Ordering::Relaxed);
        let records = self.records.lock().unwrap();
        let mut page = Page::default();
        for (key, record) in records.range::<String, _>((
            std::ops::Bound::Excluded(after.to_owned()),
            std::ops::Bound::Unbounded,
        )) {
            if page.records.len() == max_keys {
                break;
            }
            page.records.push(record.clone());
            page.last_key = key.clone();
        }
        page.reached_end = page.records.len() < max_keys;
        Ok(page)
    }
    fn load_validator_cleanup_record(
        &self,
        namespace: &str,
    ) -> Result<Option<PendingValidatorCleanup>> {
        Ok(self.records.lock().unwrap().get(&record_key(namespace)).cloned())
    }
    fn erase_validator_cleanup_record(
        &self,
        namespace: &str,
        claim: Option<&UInt256>,
    ) -> Result<()> {
        if self
            .erase_failures
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .is_ok()
        {
            fail!("injected erase failure");
        }
        self.records.lock().unwrap().remove(&record_key(namespace));
        if let Some(session) = claim {
            self.claims.lock().unwrap().insert(session.clone(), namespace.to_owned());
        }
        Ok(())
    }
    fn session_has_other_cleanup_records(
        &self,
        namespace: &str,
        session: &UInt256,
    ) -> Result<bool> {
        Ok(self
            .records
            .lock()
            .unwrap()
            .values()
            .any(|record| &record.session_id == session && record.namespace != namespace))
    }
    fn load_candidate_claims_page(
        &self,
        after: &str,
        max_keys: usize,
    ) -> Result<(Vec<(UInt256, String)>, String, bool)> {
        let claims = self.claims.lock().unwrap();
        let mut page = Vec::new();
        let mut last = String::new();
        for (session, namespace) in claims.iter() {
            let key = consensus_common::validator_cleanup::candidate_claim_key(session);
            if key.as_str() <= after {
                continue;
            }
            if page.len() == max_keys {
                break;
            }
            page.push((session.clone(), namespace.clone()));
            last = key;
        }
        let end = page.len() < max_keys;
        Ok((page, last, end))
    }
    fn erase_candidate_claim(&self, session: &UInt256) -> Result<()> {
        if self
            .claim_erase_failures
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .is_ok()
        {
            // The delete applied but its sync reported an error.
            self.claims.lock().unwrap().remove(session);
            fail!("injected claim erase sync failure");
        }
        self.claims.lock().unwrap().remove(session);
        Ok(())
    }
    fn reserve_cleanup_admission(
        &self,
        session: &UInt256,
        layout: &NamespaceLayout,
    ) -> Result<Option<crate::validator::finality_recovery_owner::RecoveryReservation>> {
        self.registry.reserve_cleanup(session, layout)
    }
    async fn prepare_v2_cleanup(
        self: Arc<Self>,
        record: PendingValidatorCleanup,
        storage: consensus_common::StorageCleanupReservation,
    ) -> Result<consensus_common::validator_cleanup::CleanupVerdict> {
        self.v2_attempts.fetch_add(1, Ordering::Relaxed);
        // The attempt holds the namespace's storage reservation and admission.
        let parsed = consensus_common::validator_cleanup::parse_canonical_namespace_name(
            &record.namespace,
            &record.session_id,
        )
        .unwrap();
        assert!(self.registry.reserve_cleanup(&record.session_id, &parsed.layout)?.is_none());
        assert!(storage.key().ends_with(record.session_id.to_hex_string()));
        Ok(self.v2_verdict.lock().unwrap().clone().unwrap_or(
            consensus_common::validator_cleanup::CleanupVerdict::WouldDelete { closes: 0 },
        ))
    }
    fn admit_candidate_table(&self, session: &UInt256) -> Result<()> {
        self.admitted.lock().unwrap().insert(session.clone());
        Ok(())
    }
    fn delete_candidate_table(&self, session: &UInt256) -> Result<bool> {
        delete_candidate_table(&self.root_str, session, &|session| {
            self.admitted.lock().unwrap().remove(session);
            Ok(true)
        })
    }
    fn delete_validator_consensus_namespace(
        &self,
        record: &PendingValidatorCleanup,
    ) -> Result<bool> {
        let behaviour = self
            .behaviour
            .lock()
            .unwrap()
            .get(&record.session_id)
            .cloned()
            .unwrap_or(DeleteBehaviour::Real);
        match behaviour {
            DeleteBehaviour::Real => {}
            DeleteBehaviour::Panic => panic!("injected delete worker panic"),
            DeleteBehaviour::Held(release) => {
                let _ = release.lock().unwrap().recv();
            }
        }
        delete_v1_namespace(&self.root_str, record)
    }
}

fn mc_id(seqno: u32, hash: u8) -> BlockIdExt {
    BlockIdExt::with_params(
        ShardIdent::masterchain(),
        seqno,
        UInt256::from([hash; 32]),
        UInt256::from([hash; 32]),
    )
}

/// A floor state at `id` whose masterchain catchain seqno is `cc` and whose
/// history records `prev`.
fn floor_state(id: &BlockIdExt, cc: u32, prev: Option<&BlockIdExt>) -> Arc<ShardStateStuff> {
    let mut header = ShardStateUnsplit::with_ident(ShardIdent::masterchain());
    header.set_seq_no(id.seq_no());
    let mut extra = McStateExtra::default();
    extra.validator_info.catchain_seqno = cc;
    if let Some(prev) = prev {
        let reference = KeyExtBlkRef {
            key: false,
            blk_ref: ExtBlkRef {
                end_lt: 0,
                seq_no: prev.seq_no(),
                root_hash: prev.root_hash().clone(),
                file_hash: prev.file_hash().clone(),
            },
        };
        extra
            .prev_blocks
            .set(&prev.seq_no(), &reference, &KeyMaxLt { key: false, max_end_lt: 0 })
            .unwrap();
    }
    header.write_custom(Some(&extra)).unwrap();
    ShardStateStuff::from_state(
        id.clone(),
        header,
        #[cfg(feature = "telemetry")]
        &crate::collator_test_bundle::create_engine_telemetry(),
        &create_engine_allocated(),
    )
    .unwrap()
}

fn v1_record(byte: u8, catchain_seqno: u32, checkpoint: &BlockIdExt) -> PendingValidatorCleanup {
    make_record(
        &UInt256::from([byte; 32]),
        &NamespaceLayout::V1,
        &ShardIdent::masterchain(),
        catchain_seqno,
        checkpoint,
    )
    .unwrap()
}

fn manager(engine: Arc<CleanupEngine>) -> ValidatorManagerImpl {
    ValidatorManagerImpl::create(
        engine,
        tokio::runtime::Handle::current(),
        ValidatorManagerConfig::default(),
    )
}

/// GC floor at MC 50 with catchain seqno 10, recording MC 40 in its history.
fn set_floor(engine: &CleanupEngine) {
    let id = mc_id(50, 5);
    *engine.floor.lock().unwrap() = Some((id.clone(), floor_state(&id, 10, Some(&mc_id(40, 4)))));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cleanup_deletes_an_eligible_v1_namespace_once_and_erases_its_record() {
    let engine = CleanupEngine::new();
    let record = v1_record(1, 5, &mc_id(40, 4));
    engine.put(&record);
    engine.materialize(&record);
    let mut manager = manager(engine.clone());
    // Without a published floor nothing is read or deleted.
    manager.run_cleanup_tick().await;
    assert_eq!(engine.page_reads.load(Ordering::Relaxed), 0);
    set_floor(&engine);
    manager.run_cleanup_tick().await;
    assert!(manager.cleanup.is_delete_in_flight(&record.session_id));
    manager.drain_cleanup_workers().await;
    assert!(engine.gone(&record), "namespace removed");
    assert!(!engine.has_record(&record), "record erased");
    assert!(engine.has_claim(&record.session_id), "the last namespace wrote the claim");
    assert!(!engine.table_gone(&record.session_id), "the shared table waits for the claim");
    assert!(manager.cleanup_storage.is_empty(), "reservation released after the erase ack");
    // The next tick executes the claim: the table goes, then the claim.
    manager.run_cleanup_tick().await;
    assert!(manager.cleanup.is_delete_in_flight(&record.session_id), "creation defers meanwhile");
    manager.drain_cleanup_workers().await;
    assert!(engine.table_gone(&record.session_id));
    assert!(!engine.has_claim(&record.session_id));
    assert!(!manager.cleanup.is_delete_in_flight(&record.session_id));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cleanup_keeps_records_the_gate_or_custody_refuses() {
    let engine = CleanupEngine::new();
    set_floor(&engine);
    // Retired on a fork the floor does not record, at the floor's own
    // catchain seqno, and an authenticated (v2) namespace.
    let fork = v1_record(1, 5, &mc_id(40, 9));
    let same_cc = v1_record(2, 10, &mc_id(40, 4));
    let v2 = make_record(
        &UInt256::from([3; 32]),
        &NamespaceLayout::V2Validator,
        &ShardIdent::masterchain(),
        5,
        &mc_id(40, 4),
    )
    .unwrap();
    for record in [&fork, &same_cc, &v2] {
        engine.put(record);
    }
    engine.materialize(&fork);
    engine.materialize(&same_cc);
    let mut manager = manager(engine.clone());
    manager.run_cleanup_tick().await;
    assert!(manager.cleanup_workers.is_empty(), "nothing was dispatched");
    for record in [&fork, &same_cc, &v2] {
        assert!(engine.has_record(&record));
        assert!(!manager.cleanup.is_delete_in_flight(&record.session_id));
    }
    assert!(!engine.gone(&fork) && !engine.gone(&same_cc));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cleanup_never_deletes_a_namespace_with_a_live_storage_instance() {
    let engine = CleanupEngine::new();
    set_floor(&engine);
    let record = v1_record(1, 5, &mc_id(40, 4));
    engine.put(&record);
    // A real database instance lives in the namespace.
    let open = consensus_common::ConsensusCommonFactory::create_async_key_value_storage(
        engine.namespace_dir(&record),
        &record.session_id.to_hex_string(),
        consensus_common::AsyncKeyValueStorageOptions { use_callback_thread: false },
    )
    .unwrap();
    std::fs::create_dir_all(engine.candidates_dir(&record.session_id)).unwrap();
    let mut manager = manager(engine.clone());
    manager.run_cleanup_tick().await;
    assert!(manager.cleanup_workers.is_empty(), "occupied storage is not deleted");
    assert!(!manager.cleanup.is_delete_in_flight(&record.session_id));
    assert!(engine.has_record(&record));
    // After a clean teardown the next tick deletes it.
    drop(open);
    manager.run_cleanup_tick().await;
    manager.drain_cleanup_workers().await;
    assert!(engine.gone(&record));
    assert!(!engine.has_record(&record));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cleanup_failed_erase_stays_in_flight_and_is_retried() {
    let engine = CleanupEngine::new();
    set_floor(&engine);
    let record = v1_record(1, 5, &mc_id(40, 4));
    engine.put(&record);
    engine.materialize(&record);
    engine.erase_failures.store(1, Ordering::Release);
    let mut manager = manager(engine.clone());
    manager.run_cleanup_tick().await;
    manager.drain_cleanup_workers().await;
    assert!(engine.gone(&record));
    assert!(engine.has_record(&record), "the erase failed");
    assert!(manager.cleanup.is_delete_in_flight(&record.session_id), "creation stays deferred");
    assert_eq!(manager.cleanup_storage.len(), 1, "the reservation is still held");
    manager.run_cleanup_tick().await;
    assert!(!engine.has_record(&record), "the next tick retried the erase");
    assert!(manager.cleanup_storage.is_empty());
    // The same tick runs the session's claim; once it completes nothing of
    // the session is in flight.
    manager.drain_cleanup_workers().await;
    assert!(!manager.cleanup.is_delete_in_flight(&record.session_id));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cleanup_disabled_reads_nothing() {
    let engine = CleanupEngine::new();
    set_floor(&engine);
    let record = v1_record(1, 5, &mc_id(40, 4));
    engine.put(&record);
    let config = ValidatorManagerConfig { consensus_cleanup_enabled: false, ..Default::default() };
    let mut manager =
        ValidatorManagerImpl::create(engine.clone(), tokio::runtime::Handle::current(), config);
    manager.cleanup_tick_at = tokio::time::Instant::now();
    manager.run_cleanup_tick_if_due().await;
    assert_eq!(engine.page_reads.load(Ordering::Relaxed), 0);
    assert!(engine.has_record(&record));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cleanup_drain_tolerates_a_panicking_worker_and_waits_for_a_held_one() {
    let engine = CleanupEngine::new();
    set_floor(&engine);
    let panicking = v1_record(1, 5, &mc_id(40, 4));
    let held = v1_record(2, 5, &mc_id(40, 4));
    for record in [&panicking, &held] {
        engine.put(record);
        engine.materialize(record);
    }
    let (release, wait) = std::sync::mpsc::channel();
    {
        let mut behaviour = engine.behaviour.lock().unwrap();
        behaviour.insert(panicking.session_id.clone(), DeleteBehaviour::Panic);
        behaviour
            .insert(held.session_id.clone(), DeleteBehaviour::Held(Arc::new(Mutex::new(wait))));
    }
    let mut manager = manager(engine.clone());
    manager.run_cleanup_tick().await;
    assert_eq!(manager.cleanup_workers.len(), 2);
    let key = |record: &PendingValidatorCleanup| {
        (engine.namespace_dir(record), record.session_id.to_hex_string())
    };
    let (held_parent, held_id) = key(&held);
    {
        let drain = manager.drain_cleanup_workers();
        tokio::pin!(drain);
        assert!(
            tokio::time::timeout(Duration::from_millis(300), &mut drain).await.is_err(),
            "a held worker keeps the drain from returning"
        );
        assert!(
            consensus_common::reserve_storage_cleanup(&held_parent, &held_id).unwrap().is_none(),
            "the held attempt keeps its reservation"
        );
        release.send(()).unwrap();
        drain.await;
    }
    // The panic counted as not gone: record kept, nothing in flight, and its
    // storage is reservable again.
    assert!(engine.has_record(&panicking));
    assert!(!manager.cleanup.is_delete_in_flight(&panicking.session_id));
    let (parent, id) = key(&panicking);
    assert!(consensus_common::reserve_storage_cleanup(&parent, &id).unwrap().is_some());
    // The held worker completed normally after release.
    assert!(engine.gone(&held));
    assert!(!engine.has_record(&held));
    assert!(manager.cleanup_storage.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_shutdown_waits_for_a_held_delete_worker_before_returning() {
    let engine = CleanupEngine::new();
    set_floor(&engine);
    let record = v1_record(1, 5, &mc_id(40, 4));
    engine.put(&record);
    engine.materialize(&record);
    let (release, wait) = std::sync::mpsc::channel();
    engine
        .behaviour
        .lock()
        .unwrap()
        .insert(record.session_id.clone(), DeleteBehaviour::Held(Arc::new(Mutex::new(wait))));
    let mut manager = manager(engine.clone());
    manager.run_cleanup_tick().await;
    let parent = engine.namespace_dir(&record);
    let id = record.session_id.to_hex_string();
    {
        let stop = manager.stop_validation();
        tokio::pin!(stop);
        assert!(
            tokio::time::timeout(Duration::from_millis(300), &mut stop).await.is_err(),
            "shutdown must not return while a delete worker runs"
        );
        assert!(consensus_common::reserve_storage_cleanup(&parent, &id).unwrap().is_none());
        release.send(()).unwrap();
        stop.await.unwrap();
    }
    assert!(engine.gone(&record));
    assert!(!engine.has_record(&record), "the completion was fed through the erase");
    assert!(manager.cleanup_storage.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cleanup_tick_deadline_survives_a_busy_masterchain() {
    let engine = CleanupEngine::new();
    set_floor(&engine);
    let record = v1_record(1, 5, &mc_id(40, 4));
    engine.put(&record);
    engine.materialize(&record);
    let config = ValidatorManagerConfig {
        consensus_cleanup_tick: Duration::from_millis(100),
        ..Default::default()
    };
    let mut manager =
        ValidatorManagerImpl::create(engine.clone(), tokio::runtime::Handle::current(), config);
    let handles = create_block_handle_storage(None).unwrap();
    let current = handles
        .create_handle(mc_id(60, 6), storage::types::BlockMeta::default(), None)
        .unwrap()
        .unwrap();
    // Every wait ends after ~5 ms, far inside the 100 ms tick period; a
    // deadline reset per wait would never fire.
    for _ in 0..200 {
        let _ = manager.wait_next_mc_or_materialization_retry(&current, 0).await;
        if !engine.has_record(&record) {
            break;
        }
    }
    manager.drain_cleanup_workers().await;
    assert!(engine.gone(&record), "cleanup progressed despite constant MC wakeups");
    assert!(!engine.has_record(&record));
}

#[test]
fn test_delete_v1_namespace_validates_its_path_before_destroying() {
    let checkpoint = mc_id(40, 4);
    let root = tempfile::tempdir().unwrap();
    let root_str = root.path().to_str().unwrap();
    let consensus = root.path().join("catchains/consensus");
    std::fs::create_dir_all(&consensus).unwrap();
    let candidates =
        |sid: &UInt256| root.path().join("catchains").join(format!("candidates{:x}", sid));

    // Already absent counts as gone.
    assert!(delete_v1_namespace(root_str, &v1_record(1, 5, &checkpoint)).unwrap());

    // A symlinked namespace is refused, and its target is untouched.
    let linked = v1_record(2, 5, &checkpoint);
    let target = root.path().join("elsewhere");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("keep"), b"x").unwrap();
    std::os::unix::fs::symlink(&target, consensus.join(&linked.namespace)).unwrap();
    assert!(!delete_v1_namespace(root_str, &linked).unwrap());
    assert!(target.join("keep").exists());

    // A v2 layout and a non-canonical name are never deleted here.
    let v2 = make_record(
        &UInt256::from([5; 32]),
        &NamespaceLayout::V2Validator,
        &ShardIdent::masterchain(),
        5,
        &checkpoint,
    )
    .unwrap();
    assert!(!delete_v1_namespace(root_str, &v2).unwrap());
    let mut forged = v1_record(6, 5, &checkpoint);
    forged.namespace = format!("{}/../../elsewhere", forged.namespace);
    assert!(!delete_v1_namespace(root_str, &forged).unwrap());
    assert!(target.join("keep").exists());

    // The real case removes the namespace and never the shared table.
    let real = v1_record(7, 5, &checkpoint);
    let db = consensus.join(&real.namespace).join(real.session_id.to_hex_string());
    std::fs::create_dir_all(&db).unwrap();
    std::fs::write(db.join("CURRENT"), b"x").unwrap();
    std::fs::create_dir_all(candidates(&real.session_id)).unwrap();
    assert!(delete_v1_namespace(root_str, &real).unwrap());
    assert!(!consensus.join(&real.namespace).exists());
    assert!(candidates(&real.session_id).exists(), "the candidate table is session-scoped");
}

#[test]
fn test_delete_candidate_table_validates_its_path_before_destroying() {
    let root = tempfile::tempdir().unwrap();
    let root_str = root.path().to_str().unwrap();
    let catchains = root.path().join("catchains");
    std::fs::create_dir_all(&catchains).unwrap();
    let candidates = |sid: &UInt256| catchains.join(format!("candidates{:x}", sid));
    let ok = |_: &UInt256| Ok(true);

    // Already absent counts as gone.
    assert!(delete_candidate_table(root_str, &UInt256::from([1; 32]), &ok).unwrap());

    // A symlinked table refuses before the pool is touched.
    let linked = UInt256::from([2; 32]);
    let target = root.path().join("elsewhere");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("keep"), b"x").unwrap();
    std::os::unix::fs::symlink(&target, candidates(&linked)).unwrap();
    let touched = std::sync::atomic::AtomicBool::new(false);
    let watch = |_: &UInt256| {
        touched.store(true, Ordering::Relaxed);
        Ok(true)
    };
    assert!(!delete_candidate_table(root_str, &linked, &watch).unwrap());
    assert!(!touched.load(Ordering::Relaxed));
    assert!(target.join("keep").exists());

    // A shared open table refuses: not confirmed gone.
    let shared = UInt256::from([3; 32]);
    std::fs::create_dir_all(candidates(&shared)).unwrap();
    assert!(!delete_candidate_table(root_str, &shared, &|_| Ok(false)).unwrap());
    assert!(candidates(&shared).exists());

    // The real case.
    let real = UInt256::from([4; 32]);
    std::fs::create_dir_all(candidates(&real)).unwrap();
    assert!(delete_candidate_table(root_str, &real, &ok).unwrap());
    assert!(!candidates(&real).exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cleanup_claim_is_written_by_the_last_namespace_of_a_session() {
    let engine = CleanupEngine::new();
    set_floor(&engine);
    let session = UInt256::from([7; 32]);
    let make = |layout: NamespaceLayout| {
        make_record(&session, &layout, &ShardIdent::masterchain(), 5, &mc_id(40, 4)).unwrap()
    };
    // Two V1-shaped namespaces of one session cannot exist, so the second is
    // an authenticated namespace kept by the custody veto: it holds the table.
    let v1 = make(NamespaceLayout::V1);
    let v2 = make(NamespaceLayout::V2Validator);
    engine.put(&v1);
    engine.put(&v2);
    engine.materialize(&v1);
    let mut manager = manager(engine.clone());
    manager.run_cleanup_tick().await;
    manager.drain_cleanup_workers().await;
    assert!(engine.gone(&v1) && !engine.has_record(&v1));
    assert!(!engine.has_claim(&session), "another durable namespace still holds the session");
    assert!(engine.has_record(&v2));
    manager.run_cleanup_tick().await;
    manager.drain_cleanup_workers().await;
    assert!(!engine.table_gone(&session), "the shared table survives");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cleanup_claim_of_a_live_session_is_erased_without_deleting() {
    let engine = CleanupEngine::new();
    set_floor(&engine);
    let record = v1_record(1, 5, &mc_id(40, 4));
    engine.materialize(&record);
    engine.claims.lock().unwrap().insert(record.session_id.clone(), record.namespace.clone());
    // A durable record of the session means a newer incarnation holds it.
    let newer = make_record(
        &record.session_id,
        &NamespaceLayout::V2Validator,
        &ShardIdent::masterchain(),
        5,
        &mc_id(40, 4),
    )
    .unwrap();
    engine.put(&newer);
    let mut manager = manager(engine.clone());
    manager.run_cleanup_tick().await;
    manager.drain_cleanup_workers().await;
    assert!(!engine.has_claim(&record.session_id), "the superseded claim is erased");
    assert!(!engine.table_gone(&record.session_id), "and the table is kept");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_session_creation_requires_a_successful_synced_claim_erase() {
    let engine = CleanupEngine::new();
    let session = UInt256::from([9; 32]);
    engine.claims.lock().unwrap().insert(session.clone(), "unused".to_owned());
    // The delete applies but its sync errs: creation defers even though a
    // later read would find the claim absent.
    engine.claim_erase_failures.store(1, Ordering::Release);
    let manager = manager(engine.clone());
    assert!(!manager.admit_session_creation(&session));
    assert!(!engine.has_claim(&session), "the key reads absent");
    assert!(!engine.admitted.lock().unwrap().contains(&session), "but nothing was admitted");
    // The next pass issues the synced delete again and only then admits.
    assert!(manager.admit_session_creation(&session));
    assert!(engine.admitted.lock().unwrap().contains(&session));
}

#[test]
fn test_candidate_tables_open_only_for_admitted_sessions() {
    use crate::validator::candidate_db::CandidateDbPool;
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(root.path().join("catchains")).unwrap();
    let pool = CandidateDbPool::with_path(root.path().to_str().unwrap());
    let session = UInt256::from([0x5a; 32]);
    let table = root.path().join("catchains").join(format!("candidates{:x}", session));
    let refused = pool.get_db(&session).err().expect("not admitted").to_string();
    assert!(refused.contains("not admitted"), "{refused}");
    assert!(!table.exists(), "a refused open creates nothing");
    pool.admit(&session).unwrap();
    drop(pool.get_db(&session).unwrap());
    assert!(table.exists());
    assert!(pool.revoke_and_destroy(&session).unwrap());
    assert!(pool.get_db(&session).is_err(), "revoked with the destroy");
}

fn v2_record(byte: u8, identity: bool) -> PendingValidatorCleanup {
    use consensus_common::{
        session_runtime::{SessionNetworkPin, SessionRecoveryBinding, SessionRecoveryCoordinates},
        validator_cleanup::CleanupIdentity,
    };
    let record = make_record(
        &UInt256::from([byte; 32]),
        &NamespaceLayout::V2Validator,
        &ShardIdent::masterchain(),
        5,
        &mc_id(40, 4),
    )
    .unwrap();
    if !identity {
        return record;
    }
    record
        .with_identity(CleanupIdentity {
            pin: SessionNetworkPin { global_id: -239, zerostate: mc_id(0, 1) },
            binding: SessionRecoveryBinding {
                governing_masterchain: mc_id(30, 3),
                coordinates: SessionRecoveryCoordinates {
                    shard: ShardIdent::masterchain(),
                    catchain_seqno: 5,
                    vertical_seqno: 0,
                    last_key_block_seqno: 0,
                    new_catchain_ids: false,
                },
            },
            local_adnl: UInt256::from([0x5c; 32]),
        })
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_v2_cleanup_runs_a_dry_attempt_under_storage_and_admission_then_keeps_everything() {
    use consensus_common::validator_cleanup::CleanupVerdict;
    let engine = CleanupEngine::new();
    set_floor(&engine);
    let record = v2_record(1, true);
    let without_identity = v2_record(2, false);
    engine.put(&record);
    engine.put(&without_identity);
    let namespace = engine.namespace_dir(&record);
    std::fs::create_dir_all(namespace.join(record.session_id.to_hex_string())).unwrap();
    let mut manager = manager(engine.clone());
    manager.run_cleanup_tick().await;
    manager.drain_cleanup_workers().await;
    assert_eq!(engine.v2_attempts.load(Ordering::Relaxed), 1, "only the record with an identity");
    assert_eq!(
        manager.cleanup_v2_verdicts.get(&record.namespace),
        Some(&CleanupVerdict::WouldDelete { closes: 0 })
    );
    // A dry run deletes nothing and releases everything it held.
    assert!(engine.has_record(&record) && engine.has_record(&without_identity));
    assert!(namespace.exists());
    assert!(!manager.cleanup.is_delete_in_flight(&record.session_id));
    assert!(consensus_common::reserve_storage_cleanup(
        &namespace,
        &record.session_id.to_hex_string()
    )
    .unwrap()
    .is_some());
    let admission =
        engine.registry.reserve_cleanup(&record.session_id, &NamespaceLayout::V2Validator);
    admission.unwrap().expect("the attempt released its admission").release();
    // A namespace held by a session is never attempted.
    let live = engine
        .registry
        .reserve_cleanup(&record.session_id, &NamespaceLayout::V2Validator)
        .unwrap()
        .unwrap();
    *engine.v2_verdict.lock().unwrap() = Some(CleanupVerdict::Veto("never asked".into()));
    manager.run_cleanup_tick().await;
    manager.drain_cleanup_workers().await;
    assert_eq!(engine.v2_attempts.load(Ordering::Relaxed), 1, "an occupied admission refuses");
    live.release();
}
