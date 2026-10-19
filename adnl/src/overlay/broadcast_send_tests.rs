/*
 * RTOS project additions (2026-10-19): public overlay broadcast sending rules.
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Sender admission and certificate attachment, observed by a real peer over
//! UDP that enforces the same privacy rules.

use super::{
    privacy_tests::{seed_key, shard_rules, TestCheck, ISSUER},
    *,
};
use crate::{
    node::{AdnlNode, AdnlNodeConfig, AdnlSendMethod},
    overlay::{
        privacy::{
            OverlayCertificate as SourceCertificate, CERTIFICATE_FLAG_ALLOW_FEC,
            CERTIFICATE_FLAG_TRUSTED,
        },
        BroadcastSubscription, OverlayParams, OverlayShortId,
    },
};

struct Endpoint {
    adnl: Arc<AdnlNode>,
    node: Arc<OverlayNode>,
    subscription: BroadcastSubscription,
}

async fn endpoint(seed: u8, id: &Arc<OverlayShortId>) -> Endpoint {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    let (_, config) = AdnlNodeConfig::from_ip_address_and_private_keys(
        &format!("127.0.0.1:{port}"),
        vec![([seed; 32], 0)],
    )
    .unwrap();
    let adnl = AdnlNode::with_config(
        config,
        #[cfg(feature = "dump")]
        None,
    )
    .await
    .unwrap();
    let node = OverlayNode::with_params(adnl.clone(), &[3; 32], 0).unwrap();
    adnl.start_over_udp(vec![node.clone()]).await.unwrap();
    assert!(node
        .add_public_overlay_with_rules(OverlayParams::with_id_only(id), shard_rules())
        .unwrap());
    let mut subscription = node.subscribe_broadcast(id).unwrap();
    let _ = tokio::time::timeout(Duration::from_millis(1), subscription.recv()).await;
    Endpoint { adnl, node, subscription }
}

async fn pair(seed: u8) -> (Endpoint, Endpoint, Arc<OverlayShortId>) {
    let id = OverlayShortId::from_data([seed; 32]);
    let a = endpoint(seed, &id).await;
    let b = endpoint(seed + 1, &id).await;
    for (local, remote) in [(&a, &b), (&b, &a)] {
        let node = remote.node.get_signed_node(&id, false).unwrap();
        local.node.add_public_peer(remote.adnl.ip_address_adnl(), &node, &id).unwrap();
        tokio::time::timeout(Duration::from_secs(5), local.node.wait_for_peers(&id))
            .await
            .unwrap()
            .unwrap();
    }
    (a, b, id)
}

async fn delivered(endpoint: &mut Endpoint, wait_ms: u64) -> Option<Vec<u8>> {
    tokio::time::timeout(Duration::from_millis(wait_ms), endpoint.subscription.recv())
        .await
        .ok()
        .and_then(|r| r.ok().flatten())
        .map(|info| info.data)
}

fn self_certificate(id: &Arc<OverlayShortId>, source: &Arc<dyn KeyOption>) -> SourceCertificate {
    SourceCertificate::sign(
        &seed_key(ISSUER),
        id.data(),
        source.id().data(),
        Version::get() + 3600,
        MAX_FEC_BROADCAST_SIZE,
        CERTIFICATE_FLAG_TRUSTED | CERTIFICATE_FLAG_ALLOW_FEC,
    )
    .unwrap()
}

async fn send(
    endpoint: &Endpoint,
    id: &Arc<OverlayShortId>,
    source: &Arc<dyn KeyOption>,
    data: &[u8],
    flags: u32,
) -> Result<BroadcastSendInfo> {
    let tagged = TaggedByteSlice {
        object: data,
        #[cfg(feature = "telemetry")]
        tag: 0,
    };
    endpoint.node.broadcast(id, &tagged, Some(source), flags, AdnlSendMethod::Fast).await
}

// Observations are collected first and checked after both nodes stop, so a
// failed expectation reports instead of leaving the transport running.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn certified_ephemeral_source_reaches_an_enforcing_peer() {
    let (a, mut b, id) = pair(120).await;
    let ephemeral = seed_key(121);
    let data: Vec<u8> = (0..4000u32).map(|i| (i * 5) as u8).collect();
    // Without a certificate the any-sender FEC source is refused locally.
    let refused = send(&a, &id, &ephemeral, &data, BROADCAST_FLAG_ANY_SENDER).await.is_err();
    a.node
        .update_certificate(&id, ephemeral.id(), Some(self_certificate(&id, &ephemeral)))
        .unwrap();
    let sent = send(&a, &id, &ephemeral, &data, BROADCAST_FLAG_ANY_SENDER).await.is_ok();
    let fec = delivered(&mut b, 3000).await;
    // The simple carrier attaches the certificate too.
    let sent_small = send(&a, &id, &ephemeral, b"small", BROADCAST_FLAG_ANY_SENDER).await.is_ok();
    let small = delivered(&mut b, 3000).await;
    // Removing the certificate stops the source again.
    a.node.update_certificate(&id, ephemeral.id(), None).unwrap();
    let refused_again =
        send(&a, &id, &ephemeral, &data[1..], BROADCAST_FLAG_ANY_SENDER).await.is_err();
    a.adnl.stop_checked().await.unwrap();
    b.adnl.stop_checked().await.unwrap();
    assert!(refused && sent && sent_small && refused_again);
    assert_eq!(fec, Some(data));
    assert_eq!(small.as_deref(), Some(&b"small"[..]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn need_check_source_sends_after_its_own_application_check() {
    let (a, mut b, id) = pair(122).await;
    let stranger = seed_key(123);
    // NeedCheck without an application check: refused before sending.
    let unchecked = send(&a, &id, &stranger, b"payload", 0).await.is_err();
    let own = TestCheck::new(true, false);
    a.node.set_public_broadcast_check(&id, Some(own.clone())).unwrap();
    let remote = TestCheck::new(true, false);
    b.node.set_public_broadcast_check(&id, Some(remote.clone())).unwrap();
    let sent = send(&a, &id, &stranger, b"payload", 0).await.is_ok();
    let own_calls = own.calls();
    let first = delivered(&mut b, 3000).await;
    let remote_calls = remote.calls();
    // A refusing local check stops the broadcast.
    a.node.set_public_broadcast_check(&id, Some(TestCheck::new(false, false))).unwrap();
    let refused = send(&a, &id, &stranger, b"refused", 0).await.is_err();
    let none = delivered(&mut b, 300).await;
    // NeedCheck FEC with FixedNeighbours is admitted the same way.
    a.node.set_public_broadcast_check(&id, Some(own.clone())).unwrap();
    let data: Vec<u8> = (0..2400u32).map(|i| i as u8).collect();
    let sent_fec = send(&a, &id, &stranger, &data, BROADCAST_FLAG_FIXED_NEIGHBOURS).await.is_ok();
    let fec = delivered(&mut b, 3000).await;
    a.adnl.stop_checked().await.unwrap();
    b.adnl.stop_checked().await.unwrap();
    assert!(unchecked && sent && refused && sent_fec);
    assert_eq!((own_calls, remote_calls), (1, 1));
    assert_eq!(first.as_deref(), Some(&b"payload"[..]));
    assert!(none.is_none());
    assert_eq!(fec, Some(data));
}
