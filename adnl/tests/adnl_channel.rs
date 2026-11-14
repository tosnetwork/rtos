// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use adnl::{
    channel::Channel,
    packet::Refusal,
    wire_keys::{KeyRefusal, NetworkPrivateKey, NetworkPublicKey},
};
use rtos_api::{ton, IntoBoxed, WireProfile};
fn private(seed: [u8; 32]) -> NetworkPrivateKey {
    NetworkPrivateKey::from_wire(
        &WireProfile::T0
            .serialize(&ton::pk::privatekey::Ed25519 { key: seed.into() }.into_boxed())
            .unwrap(),
    )
    .unwrap()
}
fn reason(e: anyhow::Error) -> &'static str {
    e.downcast_ref::<Refusal>()
        .map(|e| e.0)
        .or_else(|| e.downcast_ref::<KeyRefusal>().map(|e| e.0))
        .unwrap()
}
fn pair(equal: bool) -> (Channel, Channel, ton::PublicKey) {
    let a = private([1; 32]);
    let b = private([2; 32]);
    let pa = a.public_key().unwrap();
    let pb = b.public_key().unwrap();
    let aid = pa.short_id().unwrap();
    let bid = if equal { aid } else { pb.short_id().unwrap() };
    let public = WireProfile::T0
        .deserialize_value_bounded(&pa.to_wire().unwrap(), pa.to_wire().unwrap().len())
        .unwrap();
    (
        Channel::from_keys(&a, &pb, aid, bid).unwrap(),
        Channel::from_keys(&b, &pa, bid, aid).unwrap(),
        public,
    )
}
fn contents() -> ton::adnl::packetcontents::PacketContents {
    ton::adnl::packetcontents::PacketContents {
        rand1: vec![1; 7],
        rand2: vec![2; 15],
        message: Some(ton::adnl::Message::Adnl_Message_Nop),
        ..Default::default()
    }
}
fn wire(v: ton::adnl::packetcontents::PacketContents) -> Vec<u8> {
    WireProfile::T0.serialize(&v.into_boxed()).unwrap()
}
#[test]
fn ids_match_literal_clean_cpp_reference_and_bidirectional_roles() {
    let seed: [u8; 32] =
        hex::decode("ebe10025febbce38ef36999c5277cba8484bc299a056a6c2f3889dab6d7edd25")
            .unwrap()
            .try_into()
            .unwrap();
    let peer_bytes: [u8; 32] =
        hex::decode("a217a9fffa2ecbd98ec852717bb60da4f6d251d675164919b23c047364701604")
            .unwrap()
            .try_into()
            .unwrap();
    let peer = ton::pub_::publickey::Ed25519 { key: peer_bytes.into() }.into_boxed();
    let bytes = WireProfile::T0.serialize(&peer).unwrap();
    let peer = NetworkPublicKey::from_wire(&bytes).unwrap();
    let local_id = hex::decode("f805211aae0dafb0eff8c3e8e0b6bb4bf5e98230843d54ebbb3973f0ff5172e2")
        .unwrap()
        .try_into()
        .unwrap();
    let peer_id = hex::decode("5c9a7364703361a9ac4195d0be0ea15509583233f3f73da09421e47fafe5f995")
        .unwrap()
        .try_into()
        .unwrap();
    let channel = Channel::from_keys(&private(seed), &peer, local_id, peer_id).unwrap();
    assert_eq!(
        hex::encode(channel.in_id()),
        "d9ed32de7837272a09ad35965f5d5068349860498eda582bc3c6e1cd17eaec8b"
    );
    assert_eq!(
        hex::encode(channel.out_id()),
        "32390757b57d92f7bd6552a2027090df3531c71900a513b7de8956691e336d64"
    );
    for equal in [false, true] {
        let (a, b, _) = pair(equal);
        assert_eq!(a.in_id(), b.out_id());
        assert_eq!(a.out_id(), b.in_id());
        if equal {
            assert_eq!(a.in_id(), a.out_id());
        }
        let received = b.receive(&a.send(&wire(contents()))).unwrap();
        assert_eq!(received.messages().len(), 1);
    }
}
#[test]
fn receive_routes_then_checks_digest_tl_and_peer_identity() {
    let (a, b, public) = pair(false);
    assert_eq!(reason(b.receive(&[]).err().unwrap()), "datagram_short");
    assert_eq!(reason(b.receive(&[0; 32]).err().unwrap()), "unknown_channel");
    assert_eq!(reason(b.receive(&b.in_id()).err().unwrap()), "ciphertext_short");
    let mut packet = a.send(&wire(contents()));
    packet[35] ^= 1;
    assert_eq!(reason(b.receive(&packet).err().unwrap()), "digest_mismatch");
    assert_eq!(reason(b.receive(&a.send(&[])).err().unwrap()), "tl_truncated");
    assert_eq!(reason(b.receive(&a.send(&[0; 4])).err().unwrap()), "tl_unknown_constructor");
    let mut p = contents();
    p.from_short = Some(ton::adnl::id::short::Short { id: [0; 32].into() });
    assert_eq!(
        reason(b.receive(&a.send(&wire(p.clone()))).err().unwrap()),
        "channel_source_mismatch"
    );
    p.from = Some(public);
    assert_eq!(reason(b.receive(&a.send(&wire(p))).err().unwrap()), "packet_source_mismatch");
}
#[test]
fn channel_authentication_does_not_require_a_packet_signature() {
    let (a, b, public) = pair(false);
    let mut p = contents();
    p.from = Some(public);
    p.signature = Some(vec![0; 64]);
    let received = b.receive(&a.send(&wire(p))).unwrap();
    assert_eq!(reason(received.verify_signature().unwrap_err()), "invalid_signature");
    let p = contents();
    assert!(b.receive(&a.send(&wire(p))).unwrap().source().is_none());
}
#[test]
fn raw_unsigned_y_key_conversion_retains_degenerate_peer_refusal() {
    let local = private([1; 32]);
    let peer = ton::pub_::publickey::Ed25519 {
        key: {
            let mut b = [0; 32];
            b[0] = 1;
            b.into()
        },
    }
    .into_boxed();
    let peer = NetworkPublicKey::from_wire(&WireProfile::T0.serialize(&peer).unwrap()).unwrap();
    assert_eq!(
        reason(Channel::from_keys(&local, &peer, [1; 32], [2; 32]).err().unwrap()),
        "degenerate_public_key"
    );
}
