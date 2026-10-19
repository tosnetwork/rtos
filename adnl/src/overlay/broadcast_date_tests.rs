// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
// Broadcast date window parity with the fixed C++ baseline (OverlayImpl::check_date).
use super::*;
use crate::{
    adnl::common::AdnlPeers,
    node::{AdnlNode, AdnlNodeConfig},
    overlay::{OverlayNode, OverlayParams},
    RldpNode,
};

#[test]
fn date_window_matches_cpp_at_integral_time() {
    let now = 1_800_000_000.0;
    let at = |offset: i64| (1_800_000_000i64 + offset) as i32;
    assert!(broadcast_date_admissible(at(0), now));
    assert!(broadcast_date_admissible(at(-20), now));
    assert!(broadcast_date_admissible(at(20), now));
    assert!(!broadcast_date_admissible(at(-21), now));
    assert!(!broadcast_date_admissible(at(21), now));
}

#[test]
fn date_window_matches_cpp_at_fractional_time() {
    // C++ compares the integral date with the fractional clock: at now = T + 0.5
    // the window is [T - 19.5, T + 20.5], so T - 20 is too old and T + 20 is accepted.
    let base = 1_800_000_000i64;
    let now = base as f64 + 0.5;
    let at = |offset: i64| (base + offset) as i32;
    assert!(!broadcast_date_admissible(at(-20), now));
    assert!(broadcast_date_admissible(at(-19), now));
    assert!(broadcast_date_admissible(at(20), now));
    assert!(!broadcast_date_admissible(at(21), now));
}

#[test]
fn date_window_reads_the_wire_date_as_unsigned() {
    // A negative TL int is a date far in the future for C++ (uint32), not the past.
    let now = 1_800_000_000.0;
    assert!(!broadcast_date_admissible(-1, now));
    assert!(!broadcast_date_admissible(i32::MIN, now));
    assert!(!broadcast_date_admissible(i32::MAX, now));
    assert!(!broadcast_date_admissible(0, now));
    // Past i32::MAX the window is still evaluated in unsigned arithmetic.
    let late = 3_000_000_000u32;
    assert!(broadcast_date_admissible(late as i32, late as f64));
    assert!(!broadcast_date_admissible(late as i32, late as f64 - 21.0));
}

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

fn simple_broadcast(key: &Arc<dyn KeyOption>, data: &[u8], date: i32) -> BroadcastSimple {
    let bcast_id = BroadcastSimpleProtocol::calc_broadcast_id(data, key, 0).unwrap();
    let to_sign = BroadcastSimpleProtocol::calc_to_sign(&bcast_id, date).unwrap();
    BroadcastSimple {
        src: key.try_into().unwrap(),
        certificate: OverlayCertificate::Overlay_EmptyCertificate,
        flags: 0,
        data: data.to_vec(),
        date,
        signature: key.sign(&to_sign).unwrap(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broadcast_outside_the_date_window_is_neither_delivered_nor_relayed() {
    let adnl = node(71).await;
    let sender = node(72).await;
    let overlay_node = OverlayNode::with_params(adnl.clone(), &[7; 32], 0).unwrap();
    let rldp = RldpNode::with_params(adnl.clone(), vec![overlay_node.clone()], None).unwrap();
    overlay_node.set_rldp(rldp).unwrap();
    let id = KeyId::from_data([73; 32]);
    let local = adnl.key_by_tag(0).unwrap();
    let source = sender.key_by_tag(0).unwrap();
    assert!(overlay_node
        .add_private_overlay(
            OverlayParams::with_id_only(&id),
            &local,
            &[source.id().clone()],
            false,
            None
        )
        .unwrap());
    let overlay = overlay_node.get_overlay(&id, "date window test").unwrap();
    let peers = AdnlPeers::with_keys(local.id().clone(), source.id().clone());
    let now = system_clock_secs() as i64;

    for (name, offset, delivered) in
        [("too old", -40i64, false), ("too new", 40, false), ("current", 0, true)]
    {
        let data = format!("date window {name}").into_bytes();
        let bcast = simple_broadcast(&source, &data, (now + offset) as i32);
        let bcast_id = BroadcastSimpleProtocol::calc_broadcast_id(&data, &source, 0).unwrap();
        let ctx = BroadcastRecvContext {
            data: BroadcastData::None,
            hops: Some(0),
            overlay: &overlay,
            peers: &peers,
            verdict: super::BroadcastCheckResult::Allowed,
        };
        BroadcastSimpleProtocol.recv(bcast, ctx).await.unwrap();
        // A refused broadcast is dropped before it is registered, so it can be neither
        // delivered nor relayed; an accepted one is registered and delivered.
        assert_eq!(overlay.owned_broadcasts.get(&bcast_id).is_some(), delivered, "{name}");
        let received =
            tokio::time::timeout(Duration::from_millis(200), overlay.received_rawbytes.pop()).await;
        match received {
            Ok(item) => {
                assert!(delivered, "{name}: refused broadcast was delivered");
                assert_eq!(item.unwrap().unwrap().data, data, "{name}");
            }
            Err(_) => assert!(!delivered, "{name}: accepted broadcast was not delivered"),
        }
    }
    drop(overlay);
    adnl.stop_checked().await.unwrap();
    sender.stop_checked().await.unwrap();
}
