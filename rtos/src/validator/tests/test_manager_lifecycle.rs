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
}

#[async_trait::async_trait]
impl EngineOperations for LifecycleEngine {
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
