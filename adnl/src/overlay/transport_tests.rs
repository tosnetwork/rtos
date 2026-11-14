// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use super::*;
use crate::node::AdnlNodeConfig;
use rtos_block::{Ed25519KeyOption, ZeroizingBytes};
use std::collections::BTreeMap;

#[derive(Default)]
struct Edge {
    messages: std::sync::Mutex<Vec<Vec<u8>>>,
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
        _: BroadcastTransportMethod,
    ) -> Result<()> {
        self.messages.lock().unwrap().push(data.to_vec());
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
