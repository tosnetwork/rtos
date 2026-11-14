// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use super::*;
use crate::node::AdnlNodeConfig;
use rtos_block::{Ed25519KeyOption, ZeroizingBytes};
use std::collections::BTreeMap;

#[derive(Default)]
struct Edge {
    messages: std::sync::Mutex<Vec<Vec<u8>>>,
    methods: std::sync::Mutex<Vec<BroadcastTransportMethod>>,
}
#[async_trait::async_trait]
impl OverlayBroadcastTransport for Edge {
    fn has_peer(&self, _: &[u8; 32], _: &[u8; 32]) -> bool {
        true
    }
    async fn send_message(
        &self,
        data: &[u8],
        _: &AdnlPeers,
        method: BroadcastTransportMethod,
    ) -> Result<()> {
        self.messages.lock().unwrap().push(data.to_vec());
        self.methods.lock().unwrap().push(method);
        Ok(())
    }
}
fn key(seed: u8) -> Arc<dyn KeyOption> {
    Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[seed; 32]).unwrap()
}
async fn node(seed: u8) -> (Arc<AdnlNode>, Arc<OverlayNode>, Arc<dyn KeyOption>) {
    let (_, config) =
        AdnlNodeConfig::from_ip_address_and_private_keys("127.0.0.1:0", vec![([seed; 32], 0)])
            .unwrap();
    let adnl = AdnlNode::with_config(
        config,
        #[cfg(feature = "dump")]
        None,
    )
    .await
    .unwrap();
    let overlay =
        OverlayNode::with_params_and_profile(adnl.clone(), &[0; 32], 0, rtos_api::WireProfile::T0)
            .unwrap();
    (adnl, overlay, key(seed))
}

#[tokio::test]
async fn owned_broadcast_transport_is_bound_before_generation_and_drains() {
    let (adnl, node, source) = node(201).await;
    let edge = Arc::new(Edge::default());
    node.install_broadcast_transport(edge.clone()).unwrap();
    let id = OverlayShortId::from_data([202; 32]);
    node.add_fixed_member_overlay(
        OverlayParams::with_id_only(&id),
        &source,
        &[key(203).id().clone()],
        OverlayPrivacyRules::new(1024, 3, BTreeMap::new()),
    )
    .unwrap();
    let generation = node.overlay_generation(&id).unwrap();
    let data = TaggedByteSlice {
        object: b"owned transport",
        #[cfg(feature = "telemetry")]
        tag: 0,
    };
    let sent = node.broadcast(&id, &data, None, 0, AdnlSendMethod::Fast).await.unwrap();
    assert_eq!(sent.send_to, 1);
    assert_eq!(edge.messages.lock().unwrap().len(), 1);
    assert!(node.install_broadcast_transport(Arc::new(Edge::default())).is_err());
    node.delete_private_overlay_checked(&generation).await.unwrap();
    assert!(node.broadcast(&id, &data, None, 0, AdnlSendMethod::Fast).await.is_err());
    assert_eq!(edge.messages.lock().unwrap().len(), 1);
    adnl.stop_checked().await.unwrap();

    // A first binding after an overlay already exists must also be refused:
    // that generation would otherwise retain a different edge than new ones.
    let (adnl, node, source) = self::node(204).await;
    node.add_fixed_member_overlay(
        OverlayParams::with_id_only(&id),
        &source,
        &[],
        OverlayPrivacyRules::new(1024, 3, BTreeMap::new()),
    )
    .unwrap();
    let generation = node.overlay_generation(&id).unwrap();
    let late = node.install_broadcast_transport(Arc::new(Edge::default())).is_err();
    node.delete_private_overlay_checked(&generation).await.unwrap();
    adnl.stop_checked().await.unwrap();
    assert!(late);
}

#[tokio::test]
async fn fixed_member_rules_ignore_source_certificate_and_explicit_fec_stays_fec() {
    let (adnl, node, source) = node(205).await;
    let edge = Arc::new(Edge::default());
    node.install_broadcast_transport(edge.clone()).unwrap();
    let id = OverlayShortId::from_data([206; 32]);
    let issuer = key(207);
    let ephemeral = key(208);
    node.add_fixed_member_overlay(
        OverlayParams::with_id_only(&id),
        &source,
        &[key(209).id().clone()],
        OverlayPrivacyRules::new(
            0,
            0,
            BTreeMap::from([(*issuer.id().data(), 1024), (*source.id().data(), 1024)]),
        ),
    )
    .unwrap();
    let generation = node.overlay_generation(&id).unwrap();
    let certificate = OverlayCertificate::sign(
        &issuer,
        id.data(),
        ephemeral.id().data(),
        Version::get() + 3600,
        1024,
        3,
    )
    .unwrap();
    node.update_certificate(&id, ephemeral.id(), Some(certificate)).unwrap();
    let data = TaggedByteSlice {
        object: &[9; 50],
        #[cfg(feature = "telemetry")]
        tag: 0,
    };
    assert!(node.broadcast_fec(&id, &data, Some(&ephemeral), 0).await.is_err());
    assert!(edge.messages.lock().unwrap().is_empty());
    node.broadcast_fec(&id, &data, Some(&source), 0).await.unwrap();
    let packet = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(packet) = edge.messages.lock().unwrap().first().cloned() {
                break packet;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    node.delete_private_overlay_checked(&generation).await.unwrap();
    adnl.stop_checked().await.unwrap();
    let (_, offset) = rtos_api::WireProfile::T0.deserialize_with_suffix(&packet).unwrap();
    let payload = rtos_api::WireProfile::T0
        .deserialize(&packet[offset..])
        .unwrap()
        .downcast::<Broadcast>()
        .unwrap();
    assert!(matches!(payload, Broadcast::Overlay_BroadcastFec(_)));
}

#[tokio::test]
async fn tos_fec_source_decodes_own_parts_and_completes_four_symbol_waves() {
    let (adnl, node, source) = node(210).await;
    let edge = Arc::new(Edge::default());
    node.install_broadcast_transport(edge.clone()).unwrap();
    let id = OverlayShortId::from_data([211; 32]);
    node.add_fixed_member_overlay(
        OverlayParams::with_id_only(&id),
        &source,
        &[key(212).id().clone()],
        OverlayPrivacyRules::new(2048, 3, BTreeMap::new()),
    )
    .unwrap();
    let generation = node.overlay_generation(&id).unwrap();
    let mut subscription = node.subscribe_broadcast(&id).unwrap();
    let _ = tokio::time::timeout(Duration::from_millis(1), subscription.recv()).await;
    let mut observations = Vec::new();
    for size in [50, 1500] {
        let data = vec![size as u8; size];
        let tagged = TaggedByteSlice {
            object: &data,
            #[cfg(feature = "telemetry")]
            tag: 0,
        };
        let sent = node.broadcast_fec(&id, &tagged, None, 0).await.unwrap();
        let decoded = tokio::time::timeout(Duration::from_secs(1), subscription.recv()).await;
        observations.push((size, sent.packets, decoded, edge.messages.lock().unwrap().len()));
    }
    node.delete_private_overlay_checked(&generation).await.unwrap();
    adnl.stop_checked().await.unwrap();
    for (index, (size, packets, received, emitted)) in observations.into_iter().enumerate() {
        let received = received.expect("source bypassed its decoder").unwrap().unwrap();
        assert_eq!(received.data, vec![size as u8; size]);
        assert_eq!(received.recv_from, *source.id());
        assert_eq!(packets, 4);
        assert_eq!(emitted, (index + 1) * 4);
    }
}

struct CountingCheck {
    calls: std::sync::atomic::AtomicUsize,
    accept: std::sync::atomic::AtomicBool,
}
#[async_trait::async_trait]
impl PublicBroadcastCheck for CountingCheck {
    async fn check_broadcast(&self, _: &Arc<KeyId>, _: &[u8]) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.accept.load(Ordering::SeqCst) {
            Ok(())
        } else {
            fail!("application refused")
        }
    }
}

#[tokio::test]
async fn tos_local_simple_and_fec_check_application_once_before_delivery_and_relay() {
    let (adnl, node, source) = node(213).await;
    let edge = Arc::new(Edge::default());
    node.install_broadcast_transport(edge.clone()).unwrap();
    let id = OverlayShortId::from_data([214; 32]);
    node.add_fixed_member_overlay(
        OverlayParams::with_id_only(&id),
        &source,
        &[key(215).id().clone()],
        OverlayPrivacyRules::new(2048, 1, BTreeMap::new()),
    )
    .unwrap();
    let generation = node.overlay_generation(&id).unwrap();
    let check = Arc::new(CountingCheck { calls: 0.into(), accept: true.into() });
    node.set_broadcast_check(&id, Some(check.clone())).unwrap();
    let mut subscription = node.subscribe_broadcast(&id).unwrap();
    let _ = tokio::time::timeout(Duration::from_millis(1), subscription.recv()).await;
    let mut observations = Vec::new();
    for fec in [false, true] {
        for accept in [true, false] {
            check.accept.store(accept, Ordering::SeqCst);
            let before = check.calls.load(Ordering::SeqCst);
            let emitted = edge.messages.lock().unwrap().len();
            let data = [fec as u8, accept as u8];
            let tagged = TaggedByteSlice {
                object: &data,
                #[cfg(feature = "telemetry")]
                tag: 0,
            };
            let sent = if fec {
                node.broadcast_fec(&id, &tagged, None, 0).await
            } else {
                node.broadcast(&id, &tagged, None, 0, AdnlSendMethod::Fast).await
            };
            let received =
                tokio::time::timeout(Duration::from_millis(100), subscription.recv()).await;
            observations.push((
                fec,
                accept,
                sent.is_ok(),
                received.ok().and_then(|r| r.ok().flatten()).map(|r| r.data),
                check.calls.load(Ordering::SeqCst) - before,
                edge.messages.lock().unwrap().len() - emitted,
            ));
        }
    }
    node.delete_private_overlay_checked(&generation).await.unwrap();
    adnl.stop_checked().await.unwrap();
    for (fec, accept, sent, received, calls, emitted) in observations {
        assert!(sent, "TOS source admission completes before the asynchronous application verdict");
        assert_eq!(calls, 1, "fec={fec}, accept={accept}");
        assert_eq!(received, accept.then(|| vec![fec as u8, accept as u8]));
        assert_eq!(
            emitted,
            if accept {
                if fec {
                    4
                } else {
                    1
                }
            } else {
                0
            }
        );
    }
}

async fn first_packet(edge: &Edge) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(packet) = edge.messages.lock().unwrap().first().cloned() {
                break packet;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap()
}
fn broadcast_payload(packet: &[u8]) -> Broadcast {
    let (_, offset) = rtos_api::WireProfile::T0.deserialize_with_suffix(packet).unwrap();
    rtos_api::WireProfile::T0.deserialize(&packet[offset..]).unwrap().downcast().unwrap()
}

#[tokio::test]
async fn tos_twostep_mode_gates_ingress_and_keeps_signing_source_distinct_from_adnl() {
    use crate::common::Subscriber;
    let (sender_adnl, sender, sender_key) = node(216).await;
    let (receiver_adnl, receiver, receiver_key) = node(217).await;
    let signing_key = key(218);
    let edge = Arc::new(Edge::default());
    sender.install_broadcast_transport(edge.clone()).unwrap();
    receiver.install_broadcast_transport(Arc::new(Edge::default())).unwrap();
    let id = OverlayShortId::from_data([219; 32]);
    let rules = OverlayPrivacyRules::new(2048, 3, BTreeMap::new());
    sender
        .add_fixed_member_overlay_with_options(
            OverlayParams::with_id_only(&id),
            &sender_key,
            &[receiver_key.id().clone()],
            rules.clone(),
            FixedMemberOverlayOptions { twostep: true, ..Default::default() },
        )
        .unwrap();
    receiver
        .add_fixed_member_overlay(
            OverlayParams::with_id_only(&id),
            &receiver_key,
            &[sender_key.id().clone()],
            rules.clone(),
        )
        .unwrap();
    let sender_generation = sender.overlay_generation(&id).unwrap();
    let old_generation = receiver.overlay_generation(&id).unwrap();
    let data = TaggedByteSlice {
        object: b"separate signing source",
        #[cfg(feature = "telemetry")]
        tag: 0,
    };
    sender.broadcast_fec(&id, &data, Some(&signing_key), 1).await.unwrap();
    let packet = first_packet(&edge).await;
    let peers = AdnlPeers::with_keys(receiver_key.id().clone(), sender_key.id().clone());
    let disabled = receiver.try_consume_custom(&packet, &peers).await.is_err();
    receiver.delete_private_overlay_checked(&old_generation).await.unwrap();
    receiver
        .add_fixed_member_overlay_with_options(
            OverlayParams::with_id_only(&id),
            &receiver_key,
            &[sender_key.id().clone()],
            rules,
            FixedMemberOverlayOptions { twostep: true, ..Default::default() },
        )
        .unwrap();
    let receiver_generation = receiver.overlay_generation(&id).unwrap();
    let mut subscription = receiver.subscribe_broadcast(&id).unwrap();
    let _ = tokio::time::timeout(Duration::from_millis(1), subscription.recv()).await;
    let consumed = receiver.try_consume_custom(&packet, &peers).await;
    let delivered = tokio::time::timeout(Duration::from_secs(1), subscription.recv()).await;
    sender.delete_private_overlay_checked(&sender_generation).await.unwrap();
    receiver.delete_private_overlay_checked(&receiver_generation).await.unwrap();
    sender_adnl.stop_checked().await.unwrap();
    receiver_adnl.stop_checked().await.unwrap();
    assert!(disabled);
    assert!(consumed.unwrap());
    let delivered = delivered.unwrap().unwrap().unwrap();
    assert_eq!(delivered.recv_from, *signing_key.id());
    assert_ne!(delivered.recv_from, *sender_key.id());
    assert_eq!(delivered.data, data.object);
    assert!(matches!(
        edge.methods.lock().unwrap().first(),
        Some(BroadcastTransportMethod::Sender { reliable: true })
    ));
}

#[tokio::test]
async fn tos_twostep_selection_uses_five_intermediates_half_recovery_and_no_twostep_flag() {
    let mut observations = Vec::new();
    for (neighbours, size, flags) in [(4, 513, 0), (5, 513, 0), (7, 2000, 1), (1, 50, 256)] {
        let (adnl, node, source) = node(220).await;
        let edge = Arc::new(Edge::default());
        node.install_broadcast_transport(edge.clone()).unwrap();
        let id = OverlayShortId::from_data([221; 32]);
        let peers = (0..neighbours).map(|i| key(222 + i).id().clone()).collect::<Vec<_>>();
        node.add_fixed_member_overlay_with_options(
            OverlayParams::with_id_only(&id),
            &source,
            &peers,
            OverlayPrivacyRules::new(4096, 3, BTreeMap::new()),
            FixedMemberOverlayOptions { twostep: true, ..Default::default() },
        )
        .unwrap();
        let generation = node.overlay_generation(&id).unwrap();
        let bytes = vec![size as u8; size];
        let data = TaggedByteSlice {
            object: &bytes,
            #[cfg(feature = "telemetry")]
            tag: 0,
        };
        node.broadcast_fec(&id, &data, None, flags).await.unwrap();
        let payload = broadcast_payload(&first_packet(&edge).await);
        observations.push((neighbours, flags, payload));
        node.delete_private_overlay_checked(&generation).await.unwrap();
        adnl.stop_checked().await.unwrap();
    }
    for (neighbours, flags, payload) in observations {
        match (neighbours, flags, payload) {
            (4, 0, Broadcast::Overlay_BroadcastTwostepSimple(_)) => (),
            (5, 0, Broadcast::Overlay_BroadcastTwostepFec(v)) => assert_eq!(v.part.len(), 257),
            (7, 1, Broadcast::Overlay_BroadcastTwostepFec(v)) => assert_eq!(v.part.len(), 667),
            (1, 256, Broadcast::Overlay_BroadcastFec(v)) => assert_eq!(v.flags, 0),
            value => panic!("wrong TOS carrier/threshold: {value:?}"),
        }
    }
}

#[tokio::test]
async fn tos_twostep_without_sender_falls_back_to_ordinary_fec() {
    let (adnl, node, source) = node(230).await;
    let id = OverlayShortId::from_data([231; 32]);
    node.add_fixed_member_overlay_with_options(
        OverlayParams::with_id_only(&id),
        &source,
        &[key(232).id().clone()],
        OverlayPrivacyRules::new(1024, 3, BTreeMap::new()),
        FixedMemberOverlayOptions { twostep: true, ..Default::default() },
    )
    .unwrap();
    let generation = node.overlay_generation(&id).unwrap();
    let enabled = node
        .get_overlay(&id, "sender fallback test")
        .unwrap()
        .overlay_type
        .twostep_sender_enabled();
    let mut subscription = node.subscribe_broadcast(&id).unwrap();
    let _ = tokio::time::timeout(Duration::from_millis(1), subscription.recv()).await;
    let data = TaggedByteSlice {
        object: &[3; 50],
        #[cfg(feature = "telemetry")]
        tag: 0,
    };
    let sent = node.broadcast_fec(&id, &data, None, 0).await;
    let received = tokio::time::timeout(Duration::from_secs(1), subscription.recv()).await;
    node.delete_private_overlay_checked(&generation).await.unwrap();
    adnl.stop_checked().await.unwrap();
    assert!(!enabled, "missing sender must disable two-step, as in CPP");
    assert_eq!(sent.unwrap().packets, 4);
    assert_eq!(received.unwrap().unwrap().unwrap().data, data.object);
}

#[derive(Default)]
struct RepairEdge {
    edge: Edge,
    queries: std::sync::atomic::AtomicUsize,
    entered: tokio::sync::Notify,
}
#[async_trait::async_trait]
impl OverlayBroadcastTransport for RepairEdge {
    fn has_peer(&self, _: &[u8; 32], _: &[u8; 32]) -> bool {
        true
    }
    async fn send_message(
        &self,
        data: &[u8],
        peers: &AdnlPeers,
        method: BroadcastTransportMethod,
    ) -> Result<()> {
        self.edge.send_message(data, peers, method).await
    }
    async fn query(
        &self,
        data: &[u8],
        _: &AdnlPeers,
        answer_limit: usize,
    ) -> Result<Option<Vec<u8>>> {
        assert!(!data.is_empty());
        assert!(answer_limit > 0);
        self.queries.fetch_add(1, Ordering::AcqRel);
        self.entered.notify_one();
        std::future::pending().await
    }
}
fn edge_plumtree_policy(original_sender: bool) -> PlumtreeConfig {
    PlumtreeConfig {
        authorized_keys: BTreeMap::new(),
        max_untrusted_size: 1 << 20,
        untrusted_flags: 3,
        fixed_members: true,
        original_sender,
        eager_limit: if original_sender { 1 } else { 4 },
        max_retained_bytes: 32 << 20,
        max_broadcasts: 1024,
    }
}

#[tokio::test]
async fn plumtree_owned_edge_publishes_native_carriers_and_cancels_pending_repair() {
    let id = OverlayShortId::from_data([235; 32]);
    let (adnl_a, a, source) = node(236).await;
    let (adnl_b, b, receiver) = node(237).await;
    let edge_a = Arc::new(Edge::default());
    let edge_b = Arc::new(RepairEdge::default());
    a.install_broadcast_transport(edge_a.clone()).unwrap();
    b.install_broadcast_transport(edge_b.clone()).unwrap();
    for (node, local, remote) in [(&a, &source, &receiver), (&b, &receiver, &source)] {
        node.add_fixed_member_overlay(
            OverlayParams::with_id_only(&id),
            local,
            &[remote.id().clone()],
            OverlayPrivacyRules::new(1 << 20, 3, BTreeMap::new()),
        )
        .unwrap();
    }
    let ga = a.overlay_generation(&id).unwrap();
    let gb = b.overlay_generation(&id).unwrap();
    // The actual subscription must be active, not just allocated.
    assert!(a
        .configure_plumtree(&id, edge_plumtree_policy(true), &tokio::runtime::Handle::current())
        .is_err());
    let mut sa = a.subscribe_broadcast(&id).unwrap();
    let mut sb = b.subscribe_broadcast(&id).unwrap();
    let _ = tokio::time::timeout(Duration::from_millis(1), sa.recv()).await;
    let _ = tokio::time::timeout(Duration::from_millis(1), sb.recv()).await;
    a.configure_plumtree(&id, edge_plumtree_policy(true), &tokio::runtime::Handle::current())
        .unwrap();
    b.configure_plumtree(&id, edge_plumtree_policy(false), &tokio::runtime::Handle::current())
        .unwrap();
    let invalid = a
        .broadcast_plumtree(
            &id,
            &source,
            rtos_api::ton::overlay::Certificate::Overlay_EmptyCertificate,
            0,
            Some([1; 32]),
            &[],
        )
        .await
        .unwrap_err();
    assert!(matches!(
        invalid.downcast_ref::<PlumtreeRefusal>(),
        Some(PlumtreeRefusal::InvalidSendSize)
    ));
    let unauthorized = a
        .broadcast_plumtree(
            &id,
            &source,
            rtos_api::ton::overlay::Certificate::Overlay_EmptyCertificate,
            1,
            Some([1; 32]),
            &[7; 50],
        )
        .await
        .unwrap_err();
    assert!(matches!(
        unauthorized.downcast_ref::<PlumtreeRefusal>(),
        Some(PlumtreeRefusal::SourceNotAllowed)
    ));
    assert!(edge_a.messages.lock().unwrap().is_empty());
    assert!(tokio::time::timeout(Duration::from_millis(1), sa.recv()).await.is_err());
    for fec in [false, true] {
        let data = vec![if fec { 9 } else { 7 }; if fec { 6000 } else { 50 }];
        a.broadcast_plumtree(
            &id,
            &source,
            rtos_api::ton::overlay::Certificate::Overlay_EmptyCertificate,
            0,
            if fec { None } else { Some(rtos_block::sha256_digest(&data)) },
            &data,
        )
        .await
        .unwrap();
        let delivered = tokio::time::timeout(Duration::from_secs(1), sa.recv())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(delivered.data, data);
        assert_eq!(delivered.recv_from, source.id().clone());
    }
    let messages = edge_a.messages.lock().unwrap().clone();
    assert_eq!(messages.len(), 46, "one simple plus45native FEC advertisements");
    assert!(edge_a
        .methods
        .lock()
        .unwrap()
        .iter()
        .all(|m| matches!(m, BroadcastTransportMethod::Sender { reliable: true })));
    for message in &messages {
        let (_, offset) = rtos_api::WireProfile::T0.deserialize_with_suffix(message).unwrap();
        assert!(matches!(
            rtos_api::WireProfile::T0
                .deserialize(&message[offset..])
                .unwrap()
                .downcast::<rtos_api::ton::overlay::Broadcast>()
                .unwrap(),
            rtos_api::ton::overlay::Broadcast::Overlay_BroadcastPlumtreeIHave(_)
        ));
    }
    let peers = AdnlPeers::with_keys(receiver.id().clone(), source.id().clone());
    b.try_consume_custom(&messages[0], &peers).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), edge_b.entered.notified()).await.unwrap();
    assert_eq!(edge_b.queries.load(Ordering::Acquire), 1);
    // Deleting this generation must cancel the indefinitely blocked edge query.
    tokio::time::timeout(Duration::from_secs(1), b.delete_private_overlay_checked(&gb))
        .await
        .unwrap()
        .unwrap();
    assert!(sb.recv().await.unwrap().is_none());
    a.delete_private_overlay_checked(&ga).await.unwrap();
    adnl_a.stop_checked().await.unwrap();
    adnl_b.stop_checked().await.unwrap();
}
