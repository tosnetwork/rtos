/*
 * RTOS project additions (2026-10-19): overlay member flags.
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The member flags a node signs into its overlay.node, against the flags the
//! reference overlay actors computed for the same overlay types and options
//! (testdata/overlay-member-flags.tsv, printed by a driver over real reference
//! public, private and certificated-member overlays).

use super::*;
use crate::node::{AdnlNode, AdnlNodeConfig};

fn reference() -> HashMap<String, (u32, u32)> {
    include_str!("testdata/overlay-member-flags.tsv")
        .lines()
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            let value = |name: &str| {
                fields
                    .iter()
                    .find_map(|f| f.strip_prefix(&format!("{name}=")))
                    .and_then(|v| v.parse::<u32>().ok())
                    .unwrap()
            };
            (fields[0].to_owned(), (value("local_flags"), value("permanent_default")))
        })
        .collect()
}

async fn node(seed: u8) -> (Arc<AdnlNode>, Arc<OverlayNode>) {
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
    let overlay = OverlayNode::with_params(adnl.clone(), &[seed; 32], 0).unwrap();
    let quic = crate::QuicNode::new(
        vec![overlay.clone()],
        tokio_util::sync::CancellationToken::new(),
        tokio::runtime::Handle::current(),
        None,
    );
    overlay.set_quic(quic).unwrap();
    (adnl, overlay)
}

fn plumtree(original_sender: bool) -> PlumtreeConfig {
    PlumtreeConfig {
        authorized_keys: std::collections::BTreeMap::new(),
        max_untrusted_size: 0,
        untrusted_flags: 0,
        fixed_members: false,
        original_sender,
        eager_limit: 4,
        max_retained_bytes: plumtree::MAX_PLUMTREE_PAYLOAD,
        max_broadcasts: 16,
    }
}

fn signed_flags(node: &OverlayNode, id: &Arc<OverlayShortId>) -> u32 {
    let info = node.get_signed_node(id, false).unwrap();
    let flags = match &info {
        OverlayNodeInfo::V1(node) => node.flags(),
        OverlayNodeInfo::V2(node) => node.flags(),
    };
    u32::try_from(flags).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn member_flags_match_the_reference_overlays() {
    let table = reference();
    let (adnl, node) = node(0x61).await;
    let mut index = 0u8;
    let mut next_id = || {
        index += 1;
        OverlayShortId::from_data([index; 32])
    };
    // Public overlays: Plumtree off (with or without a QUIC sender the
    // reference disables it alike), on as a receiver, on as an original sender.
    for (name, policy) in [
        ("public plumtree=0 original=0", None),
        ("public plumtree=0 original=1", None),
        ("public plumtree=1 nosender original=0", None),
        ("public plumtree=1 original=0", Some(false)),
        ("public plumtree=1 original=1", Some(true)),
    ] {
        let id = next_id();
        assert!(node.add_local_workchain_overlay(OverlayParams::with_id_only(&id)).unwrap());
        if let Some(original) = policy {
            let _subscription = node.subscribe_broadcast(&id).unwrap();
            node.configure_plumtree(&id, plumtree(original), &tokio::runtime::Handle::current())
                .unwrap();
        }
        assert_eq!(signed_flags(&node, &id), table[name].0, "{name}");
    }
    // Certificated-member (fast-sync) overlays sign their configured flags.
    let peer = KeyId::from_data([0x71; 32]);
    for name in [
        "fastsync plumtree=1 receive=1 member=0",
        "fastsync plumtree=1 receive=0 member=1",
        "fastsync plumtree=0 receive=1 member=1 mc",
        "fastsync plumtree=0 receive=1 member=1 shard",
    ] {
        let id = next_id();
        assert!(node
            .add_semiprivate_overlay(
                OverlayParams::with_id_only(&id),
                None,
                &[peer.clone()],
                &[peer.clone()],
                None,
                4,
                false,
            )
            .unwrap());
        let (local, permanent) = table[name];
        node.set_member_flags(&id, local, permanent).unwrap();
        assert_eq!(signed_flags(&node, &id), local, "{name}");
    }
    // A private overlay signs no flag.
    let id = next_id();
    let key: Arc<dyn KeyOption> =
        rtos_block::Ed25519KeyOption::<rtos_block::ZeroizingBytes>::from_private_key(&[0x61; 32])
            .unwrap();
    assert!(node
        .add_private_overlay(OverlayParams::with_id_only(&id), &key, &[peer.clone()], false, None)
        .unwrap());
    assert_eq!(signed_flags(&node, &id), table["private"].0);
    // Flags outside the reference mask are refused.
    assert!(node.set_member_flags(&id, 4, 0).is_err());
    assert!(node.set_member_flags(&id, 0, 4).is_err());
    adnl.stop_checked().await.unwrap();
}

async fn deliver(received: &mut BroadcastSubscription) -> Option<Vec<u8>> {
    tokio::time::timeout(Duration::from_millis(2000), received.recv())
        .await
        .ok()
        .and_then(|r| r.ok().flatten())
        .map(|info| info.data)
}

/// As the reference overlay drops regular broadcasts at a member whose flags
/// say it receives none, a node signing DoNotReceiveBroadcasts delivers no
/// broadcast while the same node without the flag does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_that_receives_no_broadcasts_drops_them() {
    let id = OverlayShortId::from_data([0x55; 32]);
    let (adnl_a, a) = node(0x62).await;
    let (adnl_b, b) = node(0x63).await;
    adnl_a.start_over_udp(vec![a.clone()]).await.unwrap();
    adnl_b.start_over_udp(vec![b.clone()]).await.unwrap();
    for overlay in [&a, &b] {
        assert!(overlay.add_local_workchain_overlay(OverlayParams::with_id_only(&id)).unwrap());
    }
    let mut received = b.subscribe_broadcast(&id).unwrap();
    for (local, remote, adnl) in [(&a, &b, &adnl_b), (&b, &a, &adnl_a)] {
        let node = remote.get_signed_node(&id, false).unwrap();
        local.add_public_peer(adnl.ip_address_adnl(), &node, &id).unwrap();
        tokio::time::timeout(Duration::from_secs(5), local.wait_for_peers(&id))
            .await
            .unwrap()
            .unwrap();
    }
    let send = |data: &'static [u8]| {
        let a = a.clone();
        let id = id.clone();
        async move {
            let tagged = TaggedByteSlice {
                object: data,
                #[cfg(feature = "telemetry")]
                tag: 0,
            };
            a.broadcast(&id, &tagged, None, 0, crate::node::AdnlSendMethod::Fast).await.is_ok()
        }
    };
    let sent = send(b"received").await;
    let first = deliver(&mut received).await;
    b.set_member_flags(&id, OverlayNode::MEMBER_DO_NOT_RECEIVE_BROADCASTS, 0).unwrap();
    let flagged = signed_flags(&b, &id);
    let sent_dropped = send(b"dropped").await;
    let dropped = deliver(&mut received).await;
    adnl_a.stop_checked().await.unwrap();
    adnl_b.stop_checked().await.unwrap();
    assert!(sent && sent_dropped);
    assert_eq!(first.as_deref(), Some(&b"received"[..]));
    // A public overlay without Plumtree adds its Plumtree flag.
    assert_eq!(flagged, 3);
    assert!(dropped.is_none(), "a member receiving no broadcasts delivered one");
}
