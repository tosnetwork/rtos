// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{common::Answer, node::AdnlNodeConfig};
use futures::FutureExt;
use tokio::sync::Notify;

async fn node(seed: u8) -> Arc<AdnlNode> {
    let (_, config) =
        AdnlNodeConfig::from_ip_address_and_private_keys("127.0.0.1:0", vec![([seed; 32], 0)])
            .unwrap();
    AdnlNode::with_config(
        config,
        #[cfg(feature = "dump")]
        None,
    )
    .await
    .unwrap()
}
async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("owned overlay drain watchdog")
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlay_owned_real_post_insert_failure_rolls_back_only_owned_generation() {
    let adnl = node(91).await;
    let remote = node(92).await;
    let overlay = OverlayNode::with_params(adnl.clone(), &[1; 32], 0).unwrap();
    let rldp = RldpNode::with_params(
        adnl.clone(),
        vec![overlay.clone()],
        None,
        #[cfg(feature = "debug")]
        None,
        #[cfg(feature = "debug")]
        None,
    )
    .unwrap();
    overlay.set_rldp(rldp).unwrap();
    let id = KeyId::from_data([93; 32]);
    let foreign = remote.key_by_tag(0).unwrap();
    let peer = KeyId::from_data([94; 32]);
    let error = overlay
        .add_private_overlay(OverlayParams::with_id_only(&id), &foreign, &[peer], false, None)
        .unwrap_err();
    assert!(error.to_string().contains("unknown local key"));
    assert!(overlay.overlays.get(&id).is_none());
    let rolled_back = overlay.retired.lock().unwrap().get(&id).and_then(std::sync::Weak::upgrade);
    if let Some(owner) = rolled_back {
        bounded(owner.wait()).await.unwrap();
        assert!(owner.drained());
    }
    let key = adnl.key_by_tag(0).unwrap();
    assert!(overlay
        .add_private_overlay(OverlayParams::with_id_only(&id), &key, &[], false, None)
        .unwrap());
    let original = overlay.get_overlay(&id, "fixture").unwrap();
    let generation = overlay.overlay_generation(&id).unwrap();
    assert!(!overlay
        .add_private_overlay(
            OverlayParams::with_id_only(&id),
            &foreign,
            &[KeyId::from_data([95; 32])],
            false,
            None
        )
        .unwrap());
    assert!(Arc::ptr_eq(&original, &overlay.get_overlay(&id, "preserved generation").unwrap()));
    drop(original);
    bounded(overlay.delete_private_overlay_checked(&generation)).await.unwrap();
    adnl.stop_checked().await.unwrap();
    remote.stop_checked().await.unwrap();
}
struct HeldConsumer {
    entered: Notify,
    release: Notify,
}
#[async_trait::async_trait]
impl Subscriber for HeldConsumer {
    async fn try_consume_query(&self, _: TLObject, _: &AdnlPeers) -> Result<QueryResult> {
        self.entered.notify_one();
        self.release.notified().await;
        Ok(QueryResult::Consumed(QueryAnswer::Ready(None::<Answer>)))
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn overlay_owned_checked_delete_waits_real_inbound_and_survives_waiter_cancel() {
    let adnl = node(96).await;
    let remote = node(97).await;
    let overlay = OverlayNode::with_params(adnl.clone(), &[1; 32], 0).unwrap();
    let rldp = RldpNode::with_params(
        adnl.clone(),
        vec![overlay.clone()],
        None,
        #[cfg(feature = "debug")]
        None,
        #[cfg(feature = "debug")]
        None,
    )
    .unwrap();
    overlay.set_rldp(rldp.clone()).unwrap();
    let key = adnl.key_by_tag(0).unwrap();
    let other = remote.key_by_tag(0).unwrap();
    adnl.add_peer(key.id(), remote.ip_address_adnl(), None, &other).unwrap();
    let id = KeyId::from_data([98; 32]);
    assert!(overlay
        .add_private_overlay(
            OverlayParams::with_id_only(&id),
            &key,
            &[other.id().clone()],
            false,
            None
        )
        .unwrap());
    let generation = overlay.overlay_generation(&id).unwrap();
    let weak = Arc::downgrade(&overlay.get_overlay(&id, "fixture").unwrap());
    let consumer = Arc::new(HeldConsumer { entered: Notify::new(), release: Notify::new() });
    overlay.add_consumer(&id, consumer.clone()).unwrap();
    let request_owner = overlay.clone();
    let peers = AdnlPeers::with_keys(key.id().clone(), other.id().clone());
    let prefix =
        rtos_api::ton::rpc::overlay::Query { overlay: UInt256::from(*id.data()) }.into_tl_object();
    let request = tokio::spawn(async move {
        request_owner
            .try_consume_query_bundle(
                vec![prefix, rtos_api::ton::rpc::adnl::Ping { value: 1 }.into_tl_object()],
                &peers,
            )
            .await
    });
    bounded(consumer.entered.notified()).await;
    let owner = overlay.clone();
    let stop_generation = generation.clone();
    let mut waiter =
        tokio::spawn(async move { owner.delete_private_overlay_checked(&stop_generation).await });
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut waiter).await.is_err());
    waiter.abort();
    let _ = waiter.await;
    assert!(!generation.drained());
    assert!(overlay
        .add_private_overlay(
            OverlayParams::with_id_only(&id),
            &key,
            &[other.id().clone()],
            false,
            None
        )
        .unwrap());
    let replacement = overlay.overlay_generation(&id).unwrap();
    assert_eq!(rldp.inbound_cap_leases_for_test(other.id()), 2);
    consumer.release.notify_one();
    bounded(request).await.unwrap().unwrap();
    bounded(overlay.delete_private_overlay_checked(&generation)).await.unwrap();
    assert!(generation.drained());
    assert_eq!(rldp.inbound_cap_leases_for_test(other.id()), 1);
    assert!(weak.upgrade().is_none(), "old maintenance and inbound owners still retain generation");

    assert!(!bounded(overlay.delete_private_overlay_checked(&generation)).await.unwrap());
    assert!(overlay.overlays.get(&id).is_some());
    bounded(overlay.delete_private_overlay_checked(&replacement)).await.unwrap();
    assert_eq!(rldp.inbound_cap_leases_for_test(other.id()), 0);
    adnl.stop_checked().await.unwrap();
    remote.stop_checked().await.unwrap();
}

struct PendingConsumer {
    entered: Arc<Notify>,
    release: Arc<Notify>,
    resource: Arc<()>,
}
#[async_trait::async_trait]
impl Subscriber for PendingConsumer {
    async fn try_consume_query(&self, _: TLObject, _: &AdnlPeers) -> Result<QueryResult> {
        let entered = self.entered.clone();
        let release = self.release.clone();
        let resource = self.resource.clone();
        Ok(QueryResult::Consumed(QueryAnswer::Pending(tokio::spawn(async move {
            let _resource = resource;
            entered.notify_one();
            release.notified().await;
            Ok(crate::common::TimedAnswer {
                answer: None,
                #[cfg(feature = "telemetry")]
                actual_start_at: None,
            })
        }))))
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn overlay_owned_pending_response_is_joined_after_proxy_is_dropped() {
    let adnl = node(101).await;
    let remote = node(102).await;
    let overlay = OverlayNode::with_params(adnl.clone(), &[1; 32], 0).unwrap();
    let key = adnl.key_by_tag(0).unwrap();
    let other = remote.key_by_tag(0).unwrap();
    adnl.add_peer(key.id(), remote.ip_address_adnl(), None, &other).unwrap();
    let id = KeyId::from_data([103; 32]);
    overlay
        .add_private_overlay(
            OverlayParams::with_id_only(&id),
            &key,
            &[other.id().clone()],
            false,
            None,
        )
        .unwrap();
    let generation = overlay.overlay_generation(&id).unwrap();
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let resource = Arc::new(());
    let weak = Arc::downgrade(&resource);
    overlay
        .add_consumer(
            &id,
            Arc::new(PendingConsumer {
                entered: entered.clone(),
                release: release.clone(),
                resource,
            }),
        )
        .unwrap();
    let peers = AdnlPeers::with_keys(key.id().clone(), other.id().clone());
    let prefix =
        rtos_api::ton::rpc::overlay::Query { overlay: UInt256::from(*id.data()) }.into_tl_object();
    let response = overlay
        .try_consume_query_bundle(
            vec![prefix, rtos_api::ton::rpc::adnl::Ping { value: 1 }.into_tl_object()],
            &peers,
        )
        .await
        .unwrap();
    bounded(entered.notified()).await;
    drop(response);
    let owner = overlay.clone();
    let receipt = generation.clone();
    let mut waiter =
        tokio::spawn(async move { owner.delete_private_overlay_checked(&receipt).await });
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut waiter).await.is_err());
    waiter.abort();
    let _ = waiter.await;
    assert!(!generation.drained());
    assert!(weak.upgrade().is_some());
    release.notify_one();
    bounded(overlay.delete_private_overlay_checked(&generation)).await.unwrap();
    assert!(generation.drained());
    assert!(weak.upgrade().is_none());
    adnl.stop_checked().await.unwrap();
    remote.stop_checked().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlay_owned_retirement_index_does_not_accumulate_completed_sessions() {
    let adnl = node(104).await;
    let overlay = OverlayNode::with_params(adnl.clone(), &[1; 32], 0).unwrap();
    let key = adnl.key_by_tag(0).unwrap();
    let mut receipts = Vec::new();
    for index in 0u32..100 {
        let mut bytes = [105; 32];
        bytes[..4].copy_from_slice(&index.to_le_bytes());
        let id = KeyId::from_data(bytes);
        overlay
            .add_private_overlay(OverlayParams::with_id_only(&id), &key, &[], false, None)
            .unwrap();
        let generation = overlay.overlay_generation(&id).unwrap();
        bounded(overlay.delete_private_overlay_checked(&generation)).await.unwrap();
        assert!(overlay.retired.lock().unwrap().len() <= 1);
        receipts.push(generation);
    }
    assert!(receipts.iter().all(OverlayShutdown::drained));
    adnl.stop_checked().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlay_owned_real_fec_encoder_and_distribution_release_generation() {
    let adnl = node(106).await;
    let overlay = OverlayNode::with_params(adnl.clone(), &[1; 32], 0).unwrap();
    let key = adnl.key_by_tag(0).unwrap();
    let id = KeyId::from_data([107; 32]);
    overlay.add_private_overlay(OverlayParams::with_id_only(&id), &key, &[], false, None).unwrap();
    let generation = overlay.overlay_generation(&id).unwrap();
    let weak = Arc::downgrade(&overlay.get_overlay(&id, "fixture").unwrap());
    let payload = vec![0x5a; 128 * 1024];
    let info = overlay
        .broadcast(
            &id,
            &TaggedByteSlice {
                object: &payload,
                #[cfg(feature = "telemetry")]
                tag: 0,
            },
            None,
            0,
            AdnlSendMethod::Fast,
        )
        .await
        .unwrap();
    assert!(info.packets > 0, "real FEC encoder was not admitted");
    bounded(overlay.delete_private_overlay_checked(&generation)).await.unwrap();
    assert!(generation.drained());
    assert!(weak.upgrade().is_none());
    adnl.stop_checked().await.unwrap();
}

struct DelayedPendingConsumer {
    accepted: Notify,
    handoff: Notify,
    child: PendingConsumer,
}
#[async_trait::async_trait]
impl Subscriber for DelayedPendingConsumer {
    async fn try_consume_query(&self, object: TLObject, peers: &AdnlPeers) -> Result<QueryResult> {
        self.accepted.notify_one();
        self.handoff.notified().await;
        self.child.try_consume_query(object, peers).await
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn overlay_owned_pending_handoff_after_close_survives_cancelled_public_caller() {
    let adnl = node(108).await;
    let remote = node(109).await;
    let overlay = OverlayNode::with_params(adnl.clone(), &[1; 32], 0).unwrap();
    let key = adnl.key_by_tag(0).unwrap();
    let other = remote.key_by_tag(0).unwrap();
    adnl.add_peer(key.id(), remote.ip_address_adnl(), None, &other).unwrap();
    let id = KeyId::from_data([110; 32]);
    overlay
        .add_private_overlay(
            OverlayParams::with_id_only(&id),
            &key,
            &[other.id().clone()],
            false,
            None,
        )
        .unwrap();
    let generation = overlay.overlay_generation(&id).unwrap();
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let resource = Arc::new(());
    let weak = Arc::downgrade(&resource);
    let consumer = Arc::new(DelayedPendingConsumer {
        accepted: Notify::new(),
        handoff: Notify::new(),
        child: PendingConsumer { entered: entered.clone(), release: release.clone(), resource },
    });
    overlay.add_consumer(&id, consumer.clone()).unwrap();
    let peers = AdnlPeers::with_keys(key.id().clone(), other.id().clone());
    let prefix =
        rtos_api::ton::rpc::overlay::Query { overlay: UInt256::from(*id.data()) }.into_tl_object();
    let request_owner = overlay.clone();
    let request = tokio::spawn(async move {
        request_owner
            .try_consume_query_bundle(
                vec![prefix, rtos_api::ton::rpc::adnl::Ping { value: 1 }.into_tl_object()],
                &peers,
            )
            .await
    });
    bounded(consumer.accepted.notified()).await;
    // Close while the real consumer is still awaiting its result handoff.
    overlay.delete_private_overlay(&id).unwrap();
    assert!(!generation.drained());
    consumer.handoff.notify_one();
    bounded(entered.notified()).await;
    request.abort();
    drop(request.await);
    drop(consumer);
    let mut waiting = Box::pin(overlay.delete_private_overlay_checked(&generation));
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut waiting).await.is_err());
    assert!(!generation.drained());
    assert!(weak.upgrade().is_some());
    release.notify_one();
    bounded(waiting).await.unwrap();
    assert!(generation.drained());
    assert!(weak.upgrade().is_none());
    adnl.stop_checked().await.unwrap();
    remote.stop_checked().await.unwrap();
}

struct CountingConsumer(std::sync::atomic::AtomicUsize);
#[async_trait::async_trait]
impl Subscriber for CountingConsumer {
    async fn try_consume_query(&self, _: TLObject, _: &AdnlPeers) -> Result<QueryResult> {
        self.0.fetch_add(1, Ordering::AcqRel);
        Ok(QueryResult::Consumed(QueryAnswer::Ready(None)))
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn overlay_owned_incoming_admission_and_consumer_stay_in_same_generation() {
    let adnl = node(111).await;
    let remote = node(112).await;
    let overlay = OverlayNode::with_params(adnl.clone(), &[1; 32], 0).unwrap();
    let key = adnl.key_by_tag(0).unwrap();
    let other = remote.key_by_tag(0).unwrap();
    adnl.add_peer(key.id(), remote.ip_address_adnl(), None, &other).unwrap();
    let id = KeyId::from_data([113; 32]);
    overlay
        .add_private_overlay(
            OverlayParams::with_id_only(&id),
            &key,
            &[other.id().clone()],
            false,
            None,
        )
        .unwrap();
    let old = overlay.overlay_generation(&id).unwrap();
    let old_consumer = Arc::new(CountingConsumer(std::sync::atomic::AtomicUsize::new(0)));
    overlay.add_consumer_for_generation(&old, old_consumer.clone()).unwrap();
    let gate = Arc::new((Notify::new(), Notify::new()));
    *overlay.receive_admission_gate.lock().unwrap() = Some(gate.clone());
    let owner = overlay.clone();
    let query_id = id.clone();
    let peers = AdnlPeers::with_keys(key.id().clone(), other.id().clone());
    let request = tokio::spawn(async move {
        owner
            .try_consume_query_bundle(
                vec![
                    rtos_api::ton::rpc::overlay::Query { overlay: UInt256::from(*query_id.data()) }
                        .into_tl_object(),
                    rtos_api::ton::rpc::adnl::Ping { value: 1 }.into_tl_object(),
                ],
                &peers,
            )
            .await
    });
    bounded(gate.0.notified()).await;
    overlay.delete_private_overlay(&id).unwrap();
    overlay
        .add_private_overlay(
            OverlayParams::with_id_only(&id),
            &key,
            &[other.id().clone()],
            false,
            None,
        )
        .unwrap();
    let new = overlay.overlay_generation(&id).unwrap();
    let new_consumer = Arc::new(CountingConsumer(std::sync::atomic::AtomicUsize::new(0)));
    assert!(overlay.add_consumer_for_generation(&old, new_consumer.clone()).is_err());
    overlay.add_consumer_for_generation(&new, new_consumer.clone()).unwrap();
    gate.1.notify_one();
    bounded(request).await.unwrap().unwrap();
    assert_eq!(old_consumer.0.load(Ordering::Acquire), 1);
    assert_eq!(new_consumer.0.load(Ordering::Acquire), 0);
    bounded(overlay.delete_private_overlay_checked(&old)).await.unwrap();
    bounded(overlay.delete_private_overlay_checked(&new)).await.unwrap();
    adnl.stop_checked().await.unwrap();
    remote.stop_checked().await.unwrap();
}
struct SourceObserver {
    sources: tokio::sync::mpsc::UnboundedSender<Arc<KeyId>>,
    release: Notify,
    finished: std::sync::atomic::AtomicBool,
    calls: std::sync::atomic::AtomicUsize,
}
impl SourceObserver {
    fn finish(&self) {
        self.finished.store(true, Ordering::Release);
        self.release.notify_waiters();
    }
}
#[async_trait::async_trait]
impl Subscriber for SourceObserver {
    async fn try_consume_query_bundle(
        &self,
        _: Vec<TLObject>,
        peers: &AdnlPeers,
    ) -> Result<QueryResult> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.sources.send(peers.other().clone()).unwrap();
        let released = self.release.notified();
        tokio::pin!(released);
        released.as_mut().enable();
        if !self.finished.load(Ordering::Acquire) {
            released.await;
        }
        QueryResult::consume_boxed(
            Pong::Overlay_Pong,
            #[cfg(feature = "telemetry")]
            None,
        )
    }
}
async fn udp_node(keys: Vec<([u8; 32], usize)>) -> Arc<AdnlNode> {
    let _socket_lifecycle = crate::test_process::socket_lifecycle().await;
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    let (_, config) =
        AdnlNodeConfig::from_ip_address_and_private_keys(&format!("127.0.0.1:{port}"), keys)
            .unwrap();
    AdnlNode::with_config(
        config,
        #[cfg(feature = "dump")]
        None,
    )
    .await
    .unwrap()
}
struct OutboundGenerationFixture {
    adnl: Arc<AdnlNode>,
    remote: Arc<AdnlNode>,
    overlay: Arc<OverlayNode>,
    observer: Arc<SourceObserver>,
    observed: tokio::sync::mpsc::UnboundedReceiver<Arc<KeyId>>,
    gate: Arc<(Notify, Notify)>,
    generations: Vec<OverlayShutdown>,
    query: Option<tokio::task::JoinHandle<Result<Option<TLObject>>>>,
}

fn inject_failure(injection: Option<u8>, stage: u8) {
    if injection == Some(stage) {
        std::panic::panic_any("outbound generation injected failure");
    }
}

impl OutboundGenerationFixture {
    async fn new() -> Self {
        let adnl = udp_node(vec![([114; 32], 0), ([115; 32], 1)]).await;
        let remote = udp_node(vec![([116; 32], 0)]).await;
        let overlay = OverlayNode::with_params(adnl.clone(), &[1; 32], 0).unwrap();
        let (sources, observed) = tokio::sync::mpsc::unbounded_channel();
        let observer = Arc::new(SourceObserver {
            sources,
            release: Notify::new(),
            finished: std::sync::atomic::AtomicBool::new(false),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        Self {
            adnl,
            remote,
            overlay,
            observer,
            observed,
            gate: Arc::new((Notify::new(), Notify::new())),
            generations: Vec::new(),
            query: None,
        }
    }

    async fn exercise(&mut self, injection: Option<u8>) {
        let adnl = self.adnl.clone();
        let remote = self.remote.clone();
        let overlay = self.overlay.clone();
        let observer = self.observer.clone();
        let old_key = adnl.key_by_tag(0).unwrap();
        let new_key = adnl.key_by_tag(1).unwrap();
        let other = remote.key_by_tag(0).unwrap();
        for key in [&old_key, &new_key] {
            adnl.add_peer(key.id(), remote.ip_address_adnl(), None, &other).unwrap();
            remote.add_peer(other.id(), adnl.ip_address_adnl(), None, key).unwrap();
        }
        remote.start_over_udp(vec![observer.clone()]).await.unwrap();
        inject_failure(injection, 0);
        adnl.start_over_udp(Vec::new()).await.unwrap();
        let id = KeyId::from_data([117; 32]);
        overlay
            .add_private_overlay(
                OverlayParams::with_id_only(&id),
                &old_key,
                &[other.id().clone()],
                false,
                None,
            )
            .unwrap();
        let old = overlay.overlay_generation(&id).unwrap();
        self.generations.push(old.clone());
        let gate = self.gate.clone();
        *overlay.send_admission_gate.lock().unwrap() = Some(gate.clone());
        let owner = overlay.clone();
        let query_id = id.clone();
        let dst = other.id().clone();
        let query_started = std::time::Instant::now();
        self.query = Some(tokio::spawn(async move {
            owner
                .query(
                    &dst,
                    &TaggedTlObject {
                        object: rtos_api::ton::rpc::adnl::Ping { value: 1 }.into_tl_object(),
                        #[cfg(feature = "telemetry")]
                        tag: 0,
                    },
                    &query_id,
                    Some(4000),
                )
                .await
        }));
        bounded(gate.0.notified()).await;
        inject_failure(injection, 1);
        overlay.delete_private_overlay(&id).unwrap();
        overlay
            .add_private_overlay(
                OverlayParams::with_id_only(&id),
                &new_key,
                &[other.id().clone()],
                false,
                None,
            )
            .unwrap();
        let new = overlay.overlay_generation(&id).unwrap();
        self.generations.push(new.clone());
        gate.1.notify_one();
        let source = bounded(self.observed.recv()).await.unwrap();
        // Preserve the held-generation assertions on the valid path, but release
        // real network workers before reporting a source mismatch. Otherwise a
        // regression panics with the observer held and runtime teardown cannot join.
        if &source == old_key.id() {
            bounded(overlay.delete_private_overlay_checked(&new)).await.unwrap();
            assert!(new.drained());
            assert!(!old.drained());
        }
        inject_failure(injection, 2);
        observer.release.notify_one();
        let answer = bounded(self.query.as_mut().unwrap()).await;
        self.query.take(); // A completed JoinHandle must never be polled twice.
        let answer = answer.unwrap().unwrap();
        inject_failure(injection, 3);
        if answer.is_none() {
            eprintln!("OUTBOUND_GENERATION_NO_ANSWER elapsed_ms={} observer_calls={} old_drained={} new_drained={}", query_started.elapsed().as_millis(), observer.calls.load(Ordering::Relaxed), old.drained(), new.drained());
        }
        assert!(answer.is_some());
        assert_eq!(&source, old_key.id(), "old admission switched to replacement transport key");
    }

    fn drained(&self) -> bool {
        self.query.is_none()
            && self.adnl.tasks().drained()
            && self.remote.tasks().drained()
            && self.generations.iter().all(OverlayShutdown::drained)
    }

    async fn cleanup(&mut self) -> Result<()> {
        self.gate.1.notify_one();
        // Wake current callbacks and let any callback entering during shutdown
        // pass. Normal exercise still releases only its original one answer.
        self.observer.finish();
        let query_join = if let Some(query) = self.query.as_mut() {
            query.abort();
            tokio::time::timeout(Duration::from_secs(5), query).await.map(|_| ())
        } else {
            Ok(())
        };
        if query_join.is_ok() {
            self.query.take();
        }
        let generations = tokio::time::timeout(
            Duration::from_secs(5),
            futures::future::join_all(
                self.generations.iter().map(|g| self.overlay.delete_private_overlay_checked(g)),
            ),
        )
        .await;
        // Attempt both node drains even if the query or generation join failed.
        let nodes = tokio::time::timeout(
            Duration::from_secs(5),
            futures::future::join_all([self.adnl.stop_checked(), self.remote.stop_checked()]),
        )
        .await;
        query_join?;
        for result in generations? {
            result?;
        }
        for result in nodes? {
            result?;
        }
        anyhow::ensure!(self.drained(), "outbound fixture retains an owner after cleanup");
        Ok(())
    }

    async fn checked(&mut self, injection: Option<u8>) -> std::thread::Result<()> {
        let outcome = std::panic::AssertUnwindSafe(self.exercise(injection)).catch_unwind().await;
        let cleanup = self.cleanup().await;
        if outcome.is_err() {
            if let Err(error) = cleanup {
                eprintln!("outbound fixture cleanup also failed: {error:#}");
            }
        } else {
            cleanup.unwrap();
        }
        outcome
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn overlay_owned_outbound_uses_admitted_generation_after_id_replacement() {
    let mut fixture = OutboundGenerationFixture::new().await;
    if let Err(panic) = fixture.checked(None).await {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn overlay_outbound_generation_fixture_failure_drains_actual_owners() {
    // Partial startup, held admission, held application answer, and the point
    // where the original query-result assertion could strand active nodes.
    for stage in 0..4 {
        let mut fixture = OutboundGenerationFixture::new().await;
        let outcome = fixture.checked(Some(stage)).await;
        let before_rescue = fixture.drained();
        // Independent rescue also makes an omitted-cleanup negative control
        // fail normally rather than hanging Tokio runtime destruction.
        fixture.cleanup().await.unwrap();
        assert!(before_rescue, "fixture did not drain before reporting failure at stage {stage}");
        let panic = outcome.expect_err("injected assertion must propagate after cleanup");
        assert_eq!(panic.downcast_ref::<&str>(), Some(&"outbound generation injected failure"));
    }
}
