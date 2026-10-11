// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{common::Answer, node::AdnlNodeConfig};
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
    let rldp = RldpNode::with_params(adnl.clone(), vec![overlay.clone()], None).unwrap();
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
    let rldp = RldpNode::with_params(adnl.clone(), vec![overlay.clone()], None).unwrap();
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
