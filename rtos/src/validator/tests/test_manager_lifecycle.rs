/* Copyright (C) 2026 RTOS contributors. GPL-3.0; see LICENSE. */
use super::*;
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Default)]
struct LifecycleEngine {
    status: AtomicU8,
    persisted: std::sync::Mutex<HashSet<UInt256>>,
    acquired: std::sync::atomic::AtomicBool,
    released: std::sync::atomic::AtomicBool,
    stopping: std::sync::atomic::AtomicBool,
    fail_teardown: std::sync::atomic::AtomicBool,
    invocations: std::sync::atomic::AtomicUsize,
    candidate_deletes: std::sync::atomic::AtomicUsize,
    fail_candidates: std::sync::atomic::AtomicBool,
    state_gate: Option<Arc<StateGate>>,
}

struct StateGate {
    entered: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
    panic: bool,
}

#[async_trait::async_trait]
impl EngineOperations for LifecycleEngine {
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
    fn get_validator_status(&self) -> bool {
        true
    }
    fn acquire_stop(&self, mask: u32) {
        assert_eq!(mask, Engine::MASK_SERVICE_VALIDATOR_MANAGER);
        self.acquired.store(true, Ordering::Release);
    }
    fn release_stop(&self, mask: u32) {
        assert_eq!(mask, Engine::MASK_SERVICE_VALIDATOR_MANAGER);
        self.released.store(true, Ordering::Release);
    }
    fn check_stop(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }
    fn load_destroyed_session_ids(&self) -> Result<Vec<UInt256>> {
        self.invocations.fetch_add(1, Ordering::Relaxed);
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
        );
        tokio::time::timeout(Duration::from_secs(5), task).await.unwrap().unwrap();
        assert!(engine.acquired.load(Ordering::Acquire));
        assert_eq!(engine.released.load(Ordering::Acquire), !failing);
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
    assert_eq!(*engine.persisted.lock().unwrap(), HashSet::from([current_id, future_id]));
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
    manager.stop_and_remove_sessions(&HashSet::from([id]), true).await.unwrap();
    assert!(manager.current_sessions.is_empty() && manager.retiring_groups.is_empty());
    manager.stop_validation().await.unwrap();
    assert_eq!(engine.candidate_deletes.load(Ordering::Relaxed), 1);
    // Manager must not obtain success by weakening the group's policy check.
    assert!(group
        .stop(tokio::runtime::Handle::current(), false)
        .await
        .unwrap_err()
        .to_string()
        .contains("preserve/destroy"));
}

#[tokio::test(flavor = "current_thread")]
async fn test_manager_lifecycle_retirement_errors_survive_all_group_removal_paths() {
    for path in ["current_gc", "future_gc", "map_swap", "future_cull"] {
        let bad = Arc::new(LifecycleEngine::default());
        bad.fail_candidates.store(true, Ordering::Relaxed);
        let engine = Arc::new(LifecycleEngine::default());
        let mut manager = manager_fixture(engine.clone());
        let id = UInt256::rand();
        let group = group_fixture(bad.clone());
        let failure = match path {
            "current_gc" => {
                manager.current_sessions.insert(id.clone(), group.clone());
                manager.stop_and_remove_sessions(&HashSet::from([id]), true).await
            }
            "future_gc" => {
                manager.future_sessions.insert(id.clone(), group.clone());
                manager.stop_and_remove_sessions(&HashSet::from([id]), true).await
            }
            "map_swap" => {
                manager.current_sessions.insert(id, group.clone());
                manager.replace_current_sessions(HashMap::new()).await
            }
            "future_cull" => {
                manager.current_sessions.insert(UInt256::rand(), group_fixture(engine.clone()));
                manager.future_sessions.insert(id, group.clone());
                manager.cull_stale_future_sessions().await
            }
            _ => unreachable!(),
        }
        .unwrap_err();
        assert!(failure.to_string().contains("candidate delete failure"), "{path}: {failure}");
        assert!(manager
            .retiring_groups
            .iter()
            .any(|(_, owner, destroy)| Arc::ptr_eq(owner, &group) && *destroy));
        // A recovered underlying service must not erase the uncertified result.
        bad.fail_candidates.store(false, Ordering::Relaxed);
        let error = manager.stop_validation().await.unwrap_err();
        assert!(error.to_string().contains("candidate delete failure"), "{path}: {error}");
        assert!(!error.to_string().contains("conflicting"), "retirement policy was changed");
        assert_eq!(bad.candidate_deletes.load(Ordering::Relaxed), 1);
        assert_eq!(manager.retiring_groups.len(), 1, "healthy sibling must still drain");
    }
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
        let mut gc = Box::pin(manager.stop_and_remove_sessions(&ids, true));
        assert!(futures::poll!(&mut gc).is_pending());
        tokio::join!(first.stop_requested.cancelled(), second.stop_requested.cancelled());
        // Dropping this waiter must retain both registered retirement owners.
    }
    assert_eq!(manager.retiring_groups.len(), 2);
    let mut stop = Box::pin(manager.stop_validation());
    assert!(futures::poll!(&mut stop).is_pending());
    gate.add_permits(2);
    tokio::time::timeout(Duration::from_secs(5), stop).await.unwrap().unwrap();
    assert_eq!(engine.candidate_deletes.load(Ordering::Relaxed), 2);
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
            assert!(result.unwrap_err().to_string().contains("background task panicked"));
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
