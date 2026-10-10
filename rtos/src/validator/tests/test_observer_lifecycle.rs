/* Copyright (C) 2026 RTOS contributors. GPL-3.0; see LICENSE. */
use super::*;
use adnl::node::{AdnlNode, AdnlNodeConfig};
use rtos_block::{Ed25519KeyOption, ZeroizingBytes};

struct NoSigningEngine;
#[async_trait::async_trait]
impl EngineOperations for NoSigningEngine {}

pub(crate) struct ListenerExitGate {
    pub(crate) entered: tokio::sync::Semaphore,
    pub(crate) release: tokio::sync::Semaphore,
}

#[tokio::test(flavor = "current_thread")]
async fn test_observer_lifecycle_waits_for_listener_after_overlay_deletion() {
    let (observer, _) = observer_fixture().await;
    let gate = Arc::new(ListenerExitGate {
        entered: tokio::sync::Semaphore::new(0),
        release: tokio::sync::Semaphore::new(0),
    });
    *observer.listener_exit_gate.lock().unwrap() = Some(gate.clone());
    let mut stop = Box::pin(observer.stop_and_wait());
    assert!(futures::poll!(&mut stop).is_pending());
    tokio::time::timeout(std::time::Duration::from_secs(5), gate.entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    let returned_before_listener = futures::poll!(&mut stop).is_ready();
    gate.release.add_permits(1);
    assert!(!returned_before_listener, "overlay deletion is not listener completion");
    tokio::time::timeout(std::time::Duration::from_secs(5), stop).await.unwrap().unwrap();
}

pub(crate) struct ObserverFixture {
    overlay: Arc<OverlayNode>,
    local_key: Arc<dyn KeyOption>,
    params: BlockSyncOverlayParams,
    pub(crate) session_id: UInt256,
}
impl ObserverFixture {
    pub(crate) fn create(&self) -> Result<Arc<BlockSyncObserver>> {
        BlockSyncObserver::create(
            tokio::runtime::Handle::current(),
            self.overlay.clone(),
            self.local_key.clone(),
            self.params.clone(),
            self.session_id.clone(),
            ShardIdent::masterchain(),
            Arc::new(NoSigningEngine),
            false,
            None,
            1,
        )
    }
}
pub(crate) async fn observer_fixture() -> (Arc<BlockSyncObserver>, ObserverFixture) {
    // No socket is started: this exercises the real overlay registry and queue locally.
    let (_, config) =
        AdnlNodeConfig::from_ip_address_and_private_keys("127.0.0.1:0", vec![([37; 32], 0)])
            .unwrap();
    let local_key = config.key_by_tag(0).unwrap().clone();
    let adnl = AdnlNode::with_config(config).await.unwrap();
    let overlay = OverlayNode::with_params(adnl, &[63; 32], 0).unwrap();
    let validator = Ed25519KeyOption::<ZeroizingBytes>::generate().unwrap();
    let params = BlockSyncOverlayParams {
        members: vec![local_key.id().clone(), validator.id().clone()],
        authorized_keys: [(validator.id().clone(), 1 << 20)].into_iter().collect(),
        current_set: vec![validator.id().clone()],
        slots_per_leader_window: 1,
        max_broadcast_size: 1 << 20,
        overlay_id: None,
        shard: None,
        session_id: None,
    };
    let fixture = ObserverFixture { overlay, local_key, params, session_id: UInt256::rand() };
    (fixture.create().unwrap(), fixture)
}

#[tokio::test(flavor = "current_thread")]
async fn test_observer_lifecycle_real_overlay_stop_rejoin_and_idempotency() {
    let (observer, fixture) = observer_fixture().await;
    assert!(fixture.create().is_err(), "live same-ID observer must not be replaced");
    let (a, b) = tokio::join!(observer.stop_and_wait(), observer.stop_and_wait());
    a.unwrap();
    b.unwrap();
    let replacement = fixture.create().unwrap();
    replacement.stop_and_wait().await.unwrap();
    observer.stop_and_wait().await.unwrap();
}

pub(crate) fn abort_listener_for_test(observer: &BlockSyncObserver) {
    observer.listener_handle.lock().unwrap().as_ref().unwrap().abort();
}

#[tokio::test(flavor = "current_thread")]
async fn test_observer_lifecycle_aggregates_worker_errors_after_both_joins() {
    let (observer, _) = observer_fixture().await;
    abort_listener_for_test(&observer);
    observer.ticker_handle.lock().unwrap().as_ref().unwrap().abort();
    let error = observer.stop_and_wait().await.unwrap_err().to_string();
    assert!(error.contains("join failed (listener)"));
    assert!(error.contains("join failed (ticker)"));
    assert!(observer.teardown_drained());
}

#[tokio::test(flavor = "current_thread")]
async fn test_observer_lifecycle_lost_completion_does_not_certify_live_workers() {
    let (observer, _) = observer_fixture().await;
    let (sender, receiver) = tokio::sync::watch::channel(None);
    *observer.stop_completion.lock().unwrap() = Some(receiver);
    drop(sender);
    let error = observer.stop_and_wait().await.unwrap_err().to_string();
    assert!(error.contains("completion lost"));
    assert!(!observer.teardown_drained());
    // Restore a real cleanup owner and join both actual worker handles.
    *observer.stop_completion.lock().unwrap() = None;
    observer.stop_and_wait().await.unwrap();
    assert!(observer.teardown_drained());
}

pub(crate) fn lose_completion_for_test(observer: &BlockSyncObserver) {
    let (sender, receiver) = tokio::sync::watch::channel(None);
    *observer.stop_completion.lock().unwrap() = Some(receiver);
    drop(sender);
}
pub(crate) fn restore_completion_for_test(observer: &BlockSyncObserver) {
    *observer.stop_completion.lock().unwrap() = None;
}

pub(crate) fn panic_during_deletion_for_test(
    observer: &BlockSyncObserver,
) -> tokio::sync::oneshot::Receiver<()> {
    let (entered, receiver) = tokio::sync::oneshot::channel();
    *observer.deletion_hook.lock().unwrap() = Some(Box::new(move || {
        let _ = entered.send(());
        panic!("controlled observer deletion callback panic");
    }));
    receiver
}

pub(crate) fn gate_listener_exit_for_test(observer: &BlockSyncObserver) -> Arc<ListenerExitGate> {
    let gate = Arc::new(ListenerExitGate {
        entered: tokio::sync::Semaphore::new(0),
        release: tokio::sync::Semaphore::new(0),
    });
    *observer.listener_exit_gate.lock().unwrap() = Some(gate.clone());
    gate
}
