/* Copyright (C) 2026 RTOS contributors. GPL-3.0; see LICENSE. */
use super::*;
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Default)]
struct LifecycleEngine {
    services: std::sync::OnceLock<crate::types::service_tasks::ServiceTasks>,
    status: AtomicU8,
    persisted: std::sync::Mutex<HashSet<UInt256>>,
    acquired: std::sync::atomic::AtomicBool,
    released: std::sync::atomic::AtomicBool,
    stopping: std::sync::atomic::AtomicBool,
    fail_teardown: std::sync::atomic::AtomicBool,
    invocations: std::sync::atomic::AtomicUsize,
    panic_invocation: std::sync::atomic::AtomicBool,
    invalid_transport: std::sync::atomic::AtomicBool,
    reported: std::sync::Mutex<Vec<(u32, String)>>,
    stopper: Arc<crate::engine::Stopper>,
    candidate_deletes: std::sync::atomic::AtomicUsize,
    fail_candidates: std::sync::atomic::AtomicBool,
    state_gate: Option<Arc<StateGate>>,
    retired_records:
        std::sync::Mutex<Vec<consensus_common::validator_cleanup::PendingValidatorCleanup>>,
    retirement_fence: std::sync::Mutex<HashSet<UInt256>>,
    fail_retirement: std::sync::atomic::AtomicBool,
    no_applied_mc: std::sync::atomic::AtomicBool,
    rotation: std::sync::Mutex<Option<BlockIdExt>>,
    fail_rotation: std::sync::atomic::AtomicBool,
}

struct StateGate {
    entered: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
    panic: bool,
}

#[async_trait::async_trait]
impl EngineOperations for LifecycleEngine {
    fn register_service_task(
        &self,
        name: &'static str,
        mask: u32,
        start: Box<dyn FnOnce() -> tokio::task::JoinHandle<()> + Send>,
    ) -> Result<tokio::task::JoinHandle<()>> {
        self.services
            .get_or_init(|| crate::types::service_tasks::ServiceTasks::new(self.stopper.clone()))
            .register(name, mask, start)
    }

    fn load_last_applied_mc_block_id(&self) -> Result<Option<Arc<BlockIdExt>>> {
        if self.no_applied_mc.load(Ordering::Relaxed) {
            return Ok(None);
        }
        Ok(Some(Arc::new(BlockIdExt::with_params(
            ShardIdent::masterchain(),
            9,
            UInt256::from([1; 32]),
            UInt256::from([2; 32]),
        ))))
    }
    fn persist_validator_retirement(
        &self,
        fence: &HashSet<UInt256>,
        records: &[consensus_common::validator_cleanup::PendingValidatorCleanup],
    ) -> Result<()> {
        if self.fail_retirement.load(Ordering::Relaxed) {
            fail!("controlled retirement persistence failure");
        }
        *self.retirement_fence.lock().unwrap() = fence.clone();
        self.retired_records.lock().unwrap().extend_from_slice(records);
        Ok(())
    }
    fn load_last_rotation_block_id(&self) -> Result<Option<Arc<BlockIdExt>>> {
        Ok(self.rotation.lock().unwrap().clone().map(Arc::new))
    }
    fn save_last_rotation_block_id(&self, id: &BlockIdExt) -> Result<()> {
        if self.fail_rotation.load(Ordering::Relaxed) {
            fail!("controlled rotation block failure");
        }
        *self.rotation.lock().unwrap() = Some(id.clone());
        Ok(())
    }
    fn remove_last_validation_time(&self, _: &ShardIdent) {}
    fn remove_last_collation_time(&self, _: &ShardIdent) {}
    fn destroy_block_candidates(&self, _: &UInt256) -> Result<bool> {
        self.candidate_deletes.fetch_add(1, Ordering::Relaxed);
        if self.fail_candidates.load(Ordering::Relaxed) {
            fail!("controlled candidate delete failure");
        }
        Ok(true)
    }
    async fn wait_state(
        self: Arc<Self>,
        _: &BlockIdExt,
        timeout: Option<u64>,
        download: bool,
    ) -> Result<Arc<ShardStateStuff>> {
        assert_eq!(timeout, Some(10_000));
        assert!(!download);
        let gate = self.state_gate.as_ref().expect("actual precalc state request");
        gate.entered.add_permits(1);
        gate.release.acquire().await.unwrap().forget();
        assert!(!gate.panic, "controlled split task panic");
        fail!("controlled state read completion")
    }
    fn report_service_failure(&self, mask: u32, error: String) {
        self.stopper.report_service_failure(mask, error.clone());
        self.reported.lock().unwrap().push((mask, error));
        self.stopping.store(true, Ordering::Release);
    }
    fn get_validator_status(&self) -> bool {
        !self.invalid_transport.load(Ordering::Acquire)
    }
    fn consensus_transport_bindings(
        &self,
    ) -> Result<Vec<crate::config::ConsensusTransportBinding>> {
        if self.invalid_transport.load(Ordering::Acquire) {
            fail!("controlled invalid transport configuration");
        }
        Ok(Vec::new())
    }
    fn acquire_stop(&self, mask: u32) {
        assert_eq!(mask, Engine::MASK_SERVICE_VALIDATOR_MANAGER);
        self.acquired.store(true, Ordering::Release);
        self.stopper.acquire_stop(mask);
    }
    fn release_stop(&self, mask: u32) {
        assert_eq!(mask, Engine::MASK_SERVICE_VALIDATOR_MANAGER);
        self.released.store(true, Ordering::Release);
        self.stopper.release_stop(mask);
    }
    fn check_stop(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }
    fn load_destroyed_session_ids(&self) -> Result<Vec<UInt256>> {
        self.invocations.fetch_add(1, Ordering::Relaxed);
        assert!(!self.panic_invocation.load(Ordering::Relaxed), "controlled invocation panic");
        fail!("controlled invocation failure")
    }
    fn validation_status(&self) -> ValidationStatus {
        ValidationStatus::from_u8(self.status.load(Ordering::Relaxed))
    }
    fn set_validation_status(&self, status: ValidationStatus) {
        self.status.store(status as u8, Ordering::Relaxed);
    }
    fn set_will_validate(&self, _: bool) {}
    fn save_destroyed_session_ids(&self, ids: &HashSet<UInt256>) -> Result<()> {
        if self.fail_teardown.load(Ordering::Relaxed) {
            fail!("controlled persistence failure");
        }
        *self.persisted.lock().unwrap() = ids.clone();
        self.stopping.store(true, Ordering::Release);
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn test_manager_lifecycle_service_mask_and_restart_refused_after_teardown_error() {
    for failing in [false, true] {
        let engine = Arc::new(LifecycleEngine::default());
        engine.fail_teardown.store(failing, Ordering::Relaxed);
        let task = spawn_validator_manager(
            engine.clone(),
            tokio::runtime::Handle::current(),
            ValidatorManagerConfig::default(),
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(5), task).await.unwrap().unwrap();
        assert!(engine.acquired.load(Ordering::Acquire));
        assert_eq!(engine.released.load(Ordering::Acquire), !failing);
        let reported = engine.reported.lock().unwrap();
        assert_eq!(reported.len(), usize::from(failing));
        if failing {
            assert_eq!(reported[0].0, Engine::MASK_SERVICE_VALIDATOR_MANAGER);
            assert!(reported[0].1.contains("persistence failure"));
            assert!(engine.stopping.load(Ordering::Acquire));
        }
        drop(reported);
        let terminal = engine.stopper.clone().wait_stop().await;
        if failing {
            assert!(terminal.unwrap_err().to_string().contains("persistence failure"));
        } else {
            terminal.unwrap();
        }
        assert_eq!(
            engine.invocations.load(Ordering::Relaxed),
            1,
            "failed teardown must not start a replacement manager"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_manager_lifecycle_drains_current_future_and_observer_before_restart() {
    use super::super::{
        block_sync_observer::lifecycle_tests::observer_fixture,
        validator_group::tests::gated_lifecycle_group,
    };
    let engine = Arc::new(LifecycleEngine::default());
    let mut manager = ValidatorManagerImpl::create(
        engine.clone(),
        tokio::runtime::Handle::current(),
        ValidatorManagerConfig::default(),
    );
    let (current, current_entered, release_current) = gated_lifecycle_group().await;
    let (future, future_entered, release_future) = gated_lifecycle_group().await;
    let current_id = UInt256::rand();
    let future_id = UInt256::rand();
    manager.current_sessions.insert(current_id.clone(), current);
    manager.future_sessions.insert(future_id.clone(), future);
    let (observer, fixture) = observer_fixture().await;
    manager.block_sync_observers.insert(fixture.session_id.clone(), observer.clone());
    let stop = tokio::spawn(async move {
        manager.stop_validation().await.unwrap();
        manager
    });
    tokio::time::timeout(Duration::from_secs(5), current_entered).await.unwrap().unwrap();
    tokio::time::timeout(Duration::from_secs(5), future_entered).await.unwrap().unwrap();
    let returned_early = stop.is_finished();
    release_current.send(()).unwrap();
    release_future.send(()).unwrap();
    let manager = tokio::time::timeout(Duration::from_secs(5), stop).await.unwrap().unwrap();
    assert!(!returned_early, "manager returned before old sessions exited");
    assert!(manager.current_sessions.is_empty() && manager.future_sessions.is_empty());
    assert!(manager.block_sync_observers.is_empty());
    // Shutdown is not a retirement: no fence and no cleanup record.
    assert!(engine.persisted.lock().unwrap().is_empty(), "{current_id:x} {future_id:x}");
    assert!(engine.retired_records.lock().unwrap().is_empty());
    // A new same-ID observer must register only after the old manager is drained.
    let replacement = fixture.create().unwrap();
    replacement.stop_and_wait().await.unwrap();
    observer.stop_and_wait().await.unwrap();
}

fn manager_fixture(engine: Arc<LifecycleEngine>) -> ValidatorManagerImpl {
    ValidatorManagerImpl::create(
        engine,
        tokio::runtime::Handle::current(),
        ValidatorManagerConfig::default(),
    )
}
fn group_fixture(engine: Arc<LifecycleEngine>) -> Arc<ValidatorGroup> {
    super::super::validator_group::tests::make_simplex_group_for_engine(engine)
}

#[tokio::test(flavor = "current_thread")]
async fn test_manager_lifecycle_gc_then_preserving_shutdown_keeps_first_policy() {
    let engine = Arc::new(LifecycleEngine::default());
    let mut manager = manager_fixture(engine.clone());
    let id = UInt256::rand();
    let group = group_fixture(engine.clone());
    manager.current_sessions.insert(id.clone(), group.clone());
    manager.stop_and_remove_sessions(&HashSet::from([id.clone()])).await.unwrap();
    assert!(manager.current_sessions.is_empty() && manager.retiring_groups.is_empty());
    // Retirement records a durable cleanup intent with the fence and deletes
    // nothing: the namespace and its candidates wait for the cleanup gate.
    let records = engine.retired_records.lock().unwrap().clone();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].session_id, id);
    assert!(engine.retirement_fence.lock().unwrap().contains(&id));
    assert_eq!(engine.candidate_deletes.load(Ordering::Relaxed), 0);
    manager.stop_validation().await.unwrap();
    assert_eq!(engine.candidate_deletes.load(Ordering::Relaxed), 0);
    // Manager must not obtain success by weakening the group's policy check.
    assert!(group
        .stop(tokio::runtime::Handle::current(), true)
        .await
        .unwrap_err()
        .to_string()
        .contains("preserve/destroy"));
}

#[tokio::test(flavor = "current_thread")]
async fn test_manager_lifecycle_retirement_persists_before_any_group_closes() {
    for path in ["current_gc", "future_gc", "map_swap", "future_cull"] {
        let engine = Arc::new(LifecycleEngine::default());
        engine.fail_retirement.store(true, Ordering::Relaxed);
        let mut manager = manager_fixture(engine.clone());
        let id = UInt256::rand();
        let group = group_fixture(engine.clone());
        let failure = match path {
            "current_gc" => {
                manager.current_sessions.insert(id.clone(), group.clone());
                manager.stop_and_remove_sessions(&HashSet::from([id.clone()])).await
            }
            "future_gc" => {
                manager.future_sessions.insert(id.clone(), group.clone());
                manager.stop_and_remove_sessions(&HashSet::from([id.clone()])).await
            }
            "map_swap" => {
                manager.current_sessions.insert(id.clone(), group.clone());
                manager.replace_current_sessions(HashMap::new()).await
            }
            "future_cull" => {
                manager.current_sessions.insert(UInt256::rand(), group_fixture(engine.clone()));
                manager.future_sessions.insert(id.clone(), group.clone());
                manager.cull_stale_future_sessions().await
            }
            _ => unreachable!(),
        }
        .unwrap_err();
        assert!(
            failure.to_string().contains("retirement persistence failure"),
            "{path}: {failure}"
        );
        // No durable record means no group may begin to close.
        assert!(
            !group.stop_requested.is_cancelled(),
            "{path}: closed before its record was durable"
        );
        assert!(manager
            .retiring_groups
            .iter()
            .any(|(_, owner, generation)| Arc::ptr_eq(owner, &group) && generation.is_some()));
        assert_eq!(manager.pending_cleanup_records.len(), 1, "{path}: the record stays pending");
        // Once persistence recovers, the same record is written and the group
        // closes, while the latched failure is still reported, not erased.
        engine.fail_retirement.store(false, Ordering::Relaxed);
        let error = manager.stop_validation().await.unwrap_err();
        assert!(error.to_string().contains("retirement persistence failure"), "{path}: {error}");
        assert!(group.stop_requested.is_cancelled());
        let records = engine.retired_records.lock().unwrap().clone();
        assert!(records.iter().any(|record| record.session_id == id), "{path}");
        assert!(manager.retiring_groups.is_empty());
        assert_eq!(engine.candidate_deletes.load(Ordering::Relaxed), 0);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn test_manager_lifecycle_fence_is_durable_before_close_even_without_record() {
    let engine = Arc::new(LifecycleEngine::default());
    engine.no_applied_mc.store(true, Ordering::Relaxed);
    engine.fail_retirement.store(true, Ordering::Relaxed);
    let mut manager = manager_fixture(engine.clone());
    let id = UInt256::rand();
    let group = group_fixture(engine.clone());
    manager.current_sessions.insert(id.clone(), group.clone());
    let error = manager.stop_and_remove_sessions(&HashSet::from([id.clone()])).await.unwrap_err();
    assert!(error.to_string().contains("retirement persistence failure"), "{error}");
    assert!(manager.pending_cleanup_records.is_empty(), "no record could be built");
    assert!(!group.stop_requested.is_cancelled(), "a fence that is not durable blocks the close");
    engine.fail_retirement.store(false, Ordering::Relaxed);
    assert!(manager.stop_validation().await.is_err(), "the latched failure stays reported");
    assert!(group.stop_requested.is_cancelled());
    assert!(engine.retirement_fence.lock().unwrap().contains(&id), "fence synced before close");
    assert!(engine.retired_records.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn test_manager_lifecycle_authenticated_group_without_runtime_writes_no_record() {
    let engine = Arc::new(LifecycleEngine::default());
    let mut manager = manager_fixture(engine.clone());
    let id = UInt256::rand();
    let options = simplex::SessionOptions {
        protocol: consensus_common::simplex_protocol::SimplexProtocol::PrivateObserversPlumtree,
        ..Default::default()
    };
    let group = super::super::validator_group::tests::make_simplex_group_with_options(
        engine.clone(),
        options,
    );
    assert!(group.authenticated_runtime().is_none());
    manager.current_sessions.insert(id.clone(), group.clone());
    let _ = manager.stop_and_remove_sessions(&HashSet::from([id.clone()])).await;
    assert!(engine.retirement_fence.lock().unwrap().contains(&id), "the fence keeps the session");
    assert!(
        engine.retired_records.lock().unwrap().is_empty(),
        "an authenticated group is never recorded as a V1 directory"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_manager_lifecycle_cancelled_gc_retains_all_owners_and_policy() {
    let engine = Arc::new(LifecycleEngine::default());
    let mut manager = manager_fixture(engine.clone());
    let first = group_fixture(engine.clone());
    let second = group_fixture(engine.clone());
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    for group in [&first, &second] {
        let release = gate.clone();
        group.spawn_root_task(&tokio::runtime::Handle::current(), async move {
            release.acquire().await.unwrap().forget();
        });
        manager.current_sessions.insert(UInt256::rand(), group.clone());
    }
    let ids = manager.current_sessions.keys().cloned().collect();
    {
        let mut gc = Box::pin(manager.stop_and_remove_sessions(&ids));
        assert!(futures::poll!(&mut gc).is_pending());
        tokio::join!(first.stop_requested.cancelled(), second.stop_requested.cancelled());
        // Dropping this waiter must retain both registered retirement owners.
    }
    assert_eq!(manager.retiring_groups.len(), 2);
    assert_eq!(engine.retired_records.lock().unwrap().len(), 2, "records durable before close");
    let mut stop = Box::pin(manager.stop_validation());
    assert!(futures::poll!(&mut stop).is_pending());
    gate.add_permits(2);
    tokio::time::timeout(Duration::from_secs(5), stop).await.unwrap().unwrap();
    assert_eq!(engine.candidate_deletes.load(Ordering::Relaxed), 0);
    assert!(manager.retiring_groups.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn test_manager_lifecycle_tracks_actual_split_precalculation_and_panic() {
    for panic in [false, true] {
        let gate = Arc::new(StateGate {
            entered: tokio::sync::Semaphore::new(0),
            release: tokio::sync::Semaphore::new(0),
            panic,
        });
        let engine =
            Arc::new(LifecycleEngine { state_gate: Some(gate.clone()), ..Default::default() });
        let mut manager = manager_fixture(engine.clone());
        if panic {
            engine.fail_retirement.store(true, Ordering::Relaxed);
            // A rotation failure and a background panic must both survive aggregation.
            let group = group_fixture(engine.clone());
            let id = UInt256::rand();
            manager.current_sessions.insert(id.clone(), group);
            manager.stop_and_remove_sessions(&HashSet::from([id])).await.unwrap_err();
        }
        let owners_before = Arc::strong_count(&engine);
        manager.spawn_split_queue_precalculation(BlockIdExt::default());
        tokio::time::timeout(Duration::from_secs(5), gate.entered.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
        let mut stop = Box::pin(manager.stop_validation());
        assert!(futures::poll!(&mut stop).is_pending(), "precalc must hold manager stop");
        gate.release.add_permits(1);
        let result = tokio::time::timeout(Duration::from_secs(5), stop).await.unwrap();
        if panic {
            let error = result.unwrap_err().to_string();
            assert!(error.contains("background task panicked"));
            assert!(error.contains("retirement persistence failure"));
        } else {
            result.unwrap();
        }
        assert!(manager.background_tasks.is_empty());
        assert_eq!(
            Arc::strong_count(&engine),
            owners_before,
            "precalc retained Engine after drain"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn test_manager_lifecycle_failed_observer_remains_owned_after_removal() {
    use super::super::block_sync_observer::lifecycle_tests::{
        abort_listener_for_test, observer_fixture,
    };
    let engine = Arc::new(LifecycleEngine::default());
    let mut manager = manager_fixture(engine);
    let (observer, fixture) = observer_fixture().await;
    abort_listener_for_test(&observer);
    manager.block_sync_observers.insert(fixture.session_id.clone(), observer.clone());
    manager.retire_observer(&fixture.session_id);
    let error = manager.drain_retiring().await.unwrap_err();
    assert!(error.to_string().contains("observer task join failed"));
    assert!(manager.block_sync_observers.is_empty());
    assert_eq!(manager.retiring_observers.len(), 1);
    assert!(Arc::ptr_eq(&manager.retiring_observers[0], &observer));
    // Shutdown of the remaining owners must preserve the earlier failure.
    let error = manager.stop_validation().await.unwrap_err();
    assert!(error.to_string().contains("observer task join failed"));
}

#[tokio::test(flavor = "current_thread")]
async fn test_manager_lifecycle_lost_observer_completion_does_not_exempt_service() {
    use super::super::block_sync_observer::lifecycle_tests::{
        lose_completion_for_test, observer_fixture, restore_completion_for_test,
    };
    let engine = Arc::new(LifecycleEngine::default());
    engine.acquire_stop(Engine::MASK_SERVICE_VALIDATOR_MANAGER);
    let mut manager = manager_fixture(engine.clone());
    let (observer, fixture) = observer_fixture().await;
    lose_completion_for_test(&observer);
    manager.block_sync_observers.insert(fixture.session_id.clone(), observer.clone());
    let error = manager.stop_validation().await.unwrap_err();
    manager.report_teardown_failure(error.to_string());
    assert_eq!(
        engine.reported.lock().unwrap()[0].0,
        0,
        "live observer must not be exempted from stop mask"
    );
    let mut wait = Box::pin(engine.stopper.clone().wait_stop());
    assert!(futures::poll!(&mut wait).is_pending());
    restore_completion_for_test(&observer);
    // The old failure remains sticky, but this owner can now certify actual drain.
    let error = manager.stop_validation().await.unwrap_err();
    assert!(observer.teardown_drained());
    manager.report_teardown_failure(error.to_string());
    assert_eq!(engine.reported.lock().unwrap()[1].0, Engine::MASK_SERVICE_VALIDATOR_MANAGER);
    assert!(tokio::time::timeout(Duration::from_secs(5), wait).await.unwrap().is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn test_manager_lifecycle_invocation_panic_drains_before_terminal_failure() {
    let engine = Arc::new(LifecycleEngine::default());
    engine.panic_invocation.store(true, Ordering::Relaxed);
    let task = spawn_validator_manager(
        engine.clone(),
        tokio::runtime::Handle::current(),
        ValidatorManagerConfig::default(),
    )
    .unwrap();
    tokio::time::timeout(Duration::from_secs(5), task).await.unwrap().unwrap();
    assert_eq!(engine.invocations.load(Ordering::Relaxed), 1);
    assert!(!engine.released.load(Ordering::Acquire));
    assert_eq!(engine.reported.lock().unwrap()[0].0, Engine::MASK_SERVICE_VALIDATOR_MANAGER);
    assert!(engine
        .stopper
        .clone()
        .wait_stop()
        .await
        .unwrap_err()
        .to_string()
        .contains("invocation panicked"));
}

#[tokio::test(flavor = "current_thread")]
async fn test_manager_lifecycle_observer_callback_panic_retains_owner_until_join() {
    use super::super::block_sync_observer::lifecycle_tests::{
        gate_listener_exit_for_test, observer_fixture, panic_during_deletion_for_test,
    };
    let engine = Arc::new(LifecycleEngine::default());
    let mut manager = manager_fixture(engine.clone());
    let (observer, fixture) = observer_fixture().await;
    let callback_entered = panic_during_deletion_for_test(&observer);
    let gate = gate_listener_exit_for_test(&observer);
    manager.block_sync_observers.insert(fixture.session_id.clone(), observer.clone());
    {
        let mut stop = Box::pin(manager.stop_validation());
        assert!(futures::poll!(&mut stop).is_pending());
        tokio::time::timeout(Duration::from_secs(5), callback_entered).await.unwrap().unwrap();
        tokio::time::timeout(Duration::from_secs(5), gate.entered.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
        assert!(
            !observer.teardown_drained(),
            "callback panic cannot certify a still-live listener"
        );
        assert!(futures::poll!(&mut stop).is_pending());
    }
    assert_eq!(manager.retiring_observers.len(), 1, "cancelled waiter forgot failed observer");
    assert!(Arc::ptr_eq(&manager.retiring_observers[0], &observer));
    manager.report_teardown_failure("observer still stopping".to_owned());
    assert_eq!(engine.reported.lock().unwrap()[0].0, 0);
    gate.release.add_permits(1);
    let error = tokio::time::timeout(Duration::from_secs(5), manager.stop_validation())
        .await
        .unwrap()
        .unwrap_err();
    assert!(error.to_string().contains("observer cleanup callback panicked"));
    assert!(observer.teardown_drained());
    manager.report_teardown_failure(error.to_string());
    assert_eq!(engine.reported.lock().unwrap()[1].0, Engine::MASK_SERVICE_VALIDATOR_MANAGER);
}

#[tokio::test(flavor = "current_thread")]
async fn test_manager_lifecycle_invalid_transport_releases_unstarted_owner() {
    let engine = Arc::new(LifecycleEngine::default());
    engine.invalid_transport.store(true, Ordering::Release);
    let task = spawn_validator_manager(
        engine.clone(),
        tokio::runtime::Handle::current(),
        ValidatorManagerConfig::default(),
    )
    .unwrap();
    tokio::time::timeout(Duration::from_secs(5), task).await.unwrap().unwrap();
    assert!(engine.acquired.load(Ordering::Acquire));
    assert!(engine.released.load(Ordering::Acquire));
    assert_eq!(engine.invocations.load(Ordering::Relaxed), 0);
    let terminal = tokio::time::timeout(Duration::from_secs(5), engine.stopper.clone().wait_stop())
        .await
        .expect("invalid startup retained a live manager mask");
    assert!(terminal.unwrap_err().to_string().contains("invalid transport configuration"));
    assert_eq!(engine.reported.lock().unwrap().len(), 1);
}

fn mc(seqno: u32) -> BlockIdExt {
    BlockIdExt::with_params(
        ShardIdent::masterchain(),
        seqno,
        UInt256::from([seqno as u8; 32]),
        UInt256::from([seqno as u8; 32]),
    )
}

#[tokio::test(flavor = "current_thread")]
async fn test_manager_lifecycle_rotation_prunes_exactly_the_captured_fence() {
    let engine = Arc::new(LifecycleEngine::default());
    let mut manager = manager_fixture(engine.clone());
    let (a, b) = (UInt256::rand(), UInt256::rand());
    manager.destroyed_sessions = HashSet::from([a.clone(), b.clone()]);
    *engine.retirement_fence.lock().unwrap() = manager.destroyed_sessions.clone();
    manager.rotate_init_block(&mc(20)).unwrap();
    assert_eq!(*engine.rotation.lock().unwrap(), Some(mc(20)));
    assert!(manager.destroyed_sessions.is_empty(), "the captured sessions are pruned");
    assert!(engine.retirement_fence.lock().unwrap().is_empty(), "durably");
    assert!(engine.retired_records.lock().unwrap().is_empty(), "records are never written");
    // An empty fence: the rotation block still advances, nothing is written.
    engine.fail_retirement.store(true, Ordering::Relaxed);
    manager.rotate_init_block(&mc(21)).unwrap();
    assert_eq!(*engine.rotation.lock().unwrap(), Some(mc(21)));
}

#[tokio::test(flavor = "current_thread")]
async fn test_manager_lifecycle_failed_rotation_writes_prune_nothing_and_are_retried() {
    let id = UInt256::rand();
    // The rotation block save fails: nothing is pruned, the failure latches.
    let engine = Arc::new(LifecycleEngine::default());
    let mut manager = manager_fixture(engine.clone());
    manager.destroyed_sessions = HashSet::from([id.clone()]);
    *engine.retirement_fence.lock().unwrap() = manager.destroyed_sessions.clone();
    engine.fail_rotation.store(true, Ordering::Relaxed);
    let error = manager.rotate_init_block(&mc(20)).unwrap_err().to_string();
    assert!(error.contains("controlled rotation block failure"), "{error}");
    assert!(manager.destroyed_sessions.contains(&id));
    assert!(engine.retirement_fence.lock().unwrap().contains(&id));
    assert_eq!(*engine.rotation.lock().unwrap(), None);
    // The fence write fails after the rotation block was saved: the
    // in-memory fence keeps the captured IDs and the failure latches.
    let engine = Arc::new(LifecycleEngine::default());
    let mut manager = manager_fixture(engine.clone());
    manager.destroyed_sessions = HashSet::from([id.clone()]);
    *engine.retirement_fence.lock().unwrap() = manager.destroyed_sessions.clone();
    engine.fail_retirement.store(true, Ordering::Relaxed);
    let error = manager.rotate_init_block(&mc(20)).unwrap_err().to_string();
    assert!(error.contains("fence pruning"), "{error}");
    assert!(manager.destroyed_sessions.contains(&id), "not published before the write");
    assert!(engine.retirement_fence.lock().unwrap().contains(&id));
    assert_eq!(*engine.rotation.lock().unwrap(), Some(mc(20)));
    // A later rotation retries the pruning once the failure is resolved.
    engine.fail_retirement.store(false, Ordering::Relaxed);
    manager.lifecycle_errors.clear();
    manager.rotate_init_block(&mc(21)).unwrap();
    assert!(manager.destroyed_sessions.is_empty());
    assert!(engine.retirement_fence.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn test_manager_lifecycle_disable_reasons_keep_fence_and_rotation() {
    for reason in [DisableReason::Retire, DisableReason::Shutdown] {
        let engine = Arc::new(LifecycleEngine::default());
        *engine.rotation.lock().unwrap() = Some(mc(20));
        let mut manager = manager_fixture(engine.clone());
        let earlier = UInt256::rand();
        manager.destroyed_sessions.insert(earlier.clone());
        let id = UInt256::rand();
        manager.current_sessions.insert(id.clone(), group_fixture(engine.clone()));
        manager.disable_validation(reason).await.unwrap();
        assert_eq!(*engine.rotation.lock().unwrap(), Some(mc(20)), "{reason:?} keeps the rotation");
        assert!(manager.destroyed_sessions.contains(&earlier), "{reason:?} keeps the fence");
        assert!(engine.persisted.lock().unwrap().contains(&earlier));
        let records = engine.retired_records.lock().unwrap().clone();
        match reason {
            DisableReason::Retire => {
                assert_eq!(records.len(), 1, "a retirement records the group");
                assert_eq!(records[0].session_id, id);
                assert!(manager.destroyed_sessions.contains(&id), "and fences it");
            }
            DisableReason::Shutdown => {
                assert!(records.is_empty(), "a shutdown records nothing");
                assert!(!manager.destroyed_sessions.contains(&id), "and fences nothing");
            }
        }
    }
}
