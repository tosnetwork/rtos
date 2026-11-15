// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use adnl::{
    packet::{AddressList, NetworkMessage, Packet, Refusal},
    wire_keys::{KeyRefusal, NetworkPrivateKey},
};
use rtos_api::{
    ton::{
        self,
        adnl::{
            addresslist::AddressList as TlList, packetcontents::PacketContents, Address, Message,
        },
    },
    IntoBoxed, WireProfile,
};
fn wire(p: PacketContents) -> Vec<u8> {
    WireProfile::T0.serialize(&p.into_boxed()).unwrap()
}
fn packet() -> PacketContents {
    PacketContents { rand1: vec![1; 7], rand2: vec![2; 15], ..Default::default() }
}
fn extra_flag(p: PacketContents, extra: u32) -> Vec<u8> {
    let mut bytes = wire(p);
    let flags = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    bytes[12..16].copy_from_slice(&(flags | extra).to_le_bytes());
    bytes
}
fn reason(e: anyhow::Error) -> &'static str {
    e.downcast_ref::<Refusal>()
        .map(|e| e.0)
        .or_else(|| e.downcast_ref::<KeyRefusal>().map(|e| e.0))
        .unwrap()
}
fn udp(port: i32) -> Address {
    Address::Adnl_Address_Udp(ton::adnl::address::address::Udp { ip: 0x7f000001, port })
}
fn list(version: i32, addrs: Vec<Address>) -> TlList {
    TlList { version, addrs, reinit_date: 7, priority: 3, expire_at: 9 }
}
fn private(value: ton::PrivateKey) -> NetworkPrivateKey {
    NetworkPrivateKey::from_wire(&WireProfile::T0.serialize(&value).unwrap()).unwrap()
}
fn signer() -> NetworkPrivateKey {
    private(ton::pk::privatekey::Ed25519 { key: [3; 32].into() }.into_boxed())
}
fn source() -> ton::PublicKey {
    let bytes = signer().public_key().unwrap().to_wire().unwrap();
    WireProfile::T0.deserialize_value_bounded(&bytes, bytes.len()).unwrap()
}
#[test]
fn raw_priority_is_retained_but_excluded_from_canonical_signing() {
    let mut p = packet();
    p.from = Some(source());
    p.signature = Some(vec![0; 64]);
    p.seqno = Some(-1);
    let plain = Packet::from_wire(&wire(p.clone())).unwrap();
    let priority = Packet::from_wire(&extra_flag(p.clone(), 0x1000)).unwrap();
    assert_eq!(priority.flags(), plain.flags() | 0x1000);
    assert!(priority.priority());
    assert_eq!(priority.to_wire().unwrap(), plain.to_wire().unwrap());
    assert_eq!(priority.to_sign().unwrap(), plain.to_sign().unwrap());
    let signed_bytes = priority.to_sign().unwrap();
    let signed: ton::adnl::PacketContents =
        WireProfile::T0.deserialize_value_bounded(&signed_bytes, signed_bytes.len()).unwrap();
    assert!(signed.only().signature.is_none());
    assert_eq!(priority.seqno(), u64::MAX);
    assert_eq!(priority.source_short(), Some(signer().public_key().unwrap().short_id().unwrap()));
    let normalized: ton::adnl::PacketContents = WireProfile::T0
        .deserialize_value_bounded(&priority.to_wire().unwrap(), priority.to_wire().unwrap().len())
        .unwrap();
    assert!(normalized.only().from_short.is_none());
    assert_eq!(reason(priority.verify_signature().unwrap_err()), "invalid_signature");
}
#[test]
fn construction_and_basic_checks_keep_reference_first_refusal_order() {
    let mut p = packet();
    p.from = Some(ton::pub_::publickey::Aes { key: [7; 32].into() }.into_boxed());
    p.address = Some(list(0, vec![udp(1); 9]));
    assert_eq!(reason(Packet::from_wire(&extra_flag(p, 0x2000)).err().unwrap()), "not_ed25519");
    let mut p = packet();
    p.address = Some(list(0, vec![udp(1); 9]));
    assert_eq!(
        reason(Packet::from_wire(&extra_flag(p, 0x2000)).err().unwrap()),
        "address_list_oversize"
    );
    let mut p = packet();
    p.from = Some(source());
    p.from_short = Some(ton::adnl::id::short::Short { id: [0; 32].into() });
    p.address = Some(list(-1, vec![udp(1)]));
    assert_eq!(reason(Packet::from_wire(&wire(p)).err().unwrap()), "packet_source_mismatch");
    let mut p = packet();
    p.message = Some(Message::Adnl_Message_Nop);
    p.messages = Some(Vec::new());
    p.address = Some(list(-1, Vec::new()));
    assert_eq!(reason(Packet::from_wire(&wire(p)).err().unwrap()), "packet_message_flags");
}
#[test]
fn address_partitioning_normalizes_ports_and_deduplicates_reverse() {
    let value = list(
        -1,
        vec![
            Address::Adnl_Address_Reverse,
            Address::Adnl_Address_Quic(ton::adnl::address::address::Quic { ip: -1, port: 65537 }),
            udp(-1),
            Address::Adnl_Address_Reverse,
        ],
    );
    let l = AddressList::from_tl(value).unwrap();
    assert!(l.empty());
    assert!(l.public_only());
    assert_eq!(l.serialized_size(), 52);
    assert_eq!(l.quic()[0].port(), 1);
    assert_eq!(l.quic()[0].ip().to_string(), "255.255.255.255");
    let encoded = l.to_wire().unwrap();
    let parsed: ton::adnl::AddressList =
        WireProfile::T0.deserialize_value_bounded(&encoded, encoded.len()).unwrap();
    let values = parsed.only().addrs;
    assert!(matches!(&values[0],Address::Adnl_Address_Udp(v) if v.port==65535));
    assert!(matches!(values[1], Address::Adnl_Address_Reverse));
    assert!(matches!(values[2], Address::Adnl_Address_Quic(_)));
    let mut p = packet();
    p.address = Some(list(0, Vec::new()));
    assert!(Packet::from_wire(&wire(p)).is_ok());
    let mut p = packet();
    p.address = Some(list(-1, vec![udp(1)]));
    assert_eq!(reason(Packet::from_wire(&wire(p)).err().unwrap()), "packet_address_list_empty");
}
#[test]
fn bounded_vector_guard_checks_multiplicity_against_bytes_before_elements() {
    let bytes = WireProfile::T0.serialize(&list(0, Vec::new()).into_boxed()).unwrap();
    for (count, expected) in [
        (-1, "tl_bad_length"),
        (16, "tl_unknown_constructor"),
        (17, "tl_bad_length"),
        (i32::MAX, "tl_bad_length"),
    ] {
        let mut value = bytes.clone();
        value[4..8].copy_from_slice(&count.to_le_bytes());
        assert_eq!(reason(AddressList::from_wire(&value).err().unwrap()), expected, "count{count}");
    }
    let mut suffix = wire(packet());
    suffix.push(0);
    assert_eq!(reason(Packet::from_wire(&suffix).err().unwrap()), "tl_trailing_data");
    let mut negative = extra_flag(packet(), 1 << 31);
    negative.truncate(16);
    assert_eq!(reason(Packet::from_wire(&negative).err().unwrap()), "tl_negative_flags");
}
#[test]
fn native_message_size_tracks_padded_bytes_and_unsigned_part_range() {
    for n in [0, 1, 252, 253, 254, 255, 256] {
        let m = NetworkMessage::from_tl(
            ton::adnl::message::message::Custom { data: vec![7; n] }.into_boxed(),
        );
        assert_eq!(m.serialized_size() as usize, m.to_wire().unwrap().len());
    }
    let m = NetworkMessage::from_tl(
        ton::adnl::message::message::Part {
            hash: [0; 32].into(),
            total_size: -1,
            offset: i32::MIN,
            data: vec![7; 254],
        }
        .into_boxed(),
    );
    assert_eq!(m.part_range(), Some((u32::MAX, 1 << 31)));
    assert_eq!(m.serialized_size() as usize, m.to_wire().unwrap().len());
}
#[test]
fn datagram_routes_before_decryption_then_authenticates_canonical_packet() {
    let sign = signer();
    let dest = private(ton::pk::privatekey::Aes { key: [9; 32].into() }.into_boxed());
    let mut p = packet();
    p.from = Some(source());
    p.message = Some(Message::Adnl_Message_Nop);
    p.signature = Some(Vec::new());
    let unsigned = Packet::from_wire(&wire(p.clone())).unwrap();
    p.signature = Some(sign.sign(&unsigned.to_sign().unwrap()).unwrap());
    let bytes = wire(p.clone());
    let mut datagram = dest.public_key().unwrap().short_id().unwrap().to_vec();
    datagram.extend(dest.public_key().unwrap().encrypt_deterministic(&bytes).unwrap());
    let received = Packet::from_datagram(&dest, &datagram).unwrap();
    received.verify_signature().unwrap();
    assert_eq!(received.messages().len(), 1);
    assert_eq!(reason(Packet::from_datagram(&dest, &[]).err().unwrap()), "datagram_short");
    let mut bad = vec![0; 32];
    assert_eq!(reason(Packet::from_datagram(&dest, &bad).err().unwrap()), "unknown_destination");
    bad = dest.public_key().unwrap().short_id().unwrap().to_vec();
    assert_eq!(reason(Packet::from_datagram(&dest, &bad).err().unwrap()), "ciphertext_short");
    let overlay = private(ton::pk::privatekey::Overlay { name: vec![1] }.into_boxed());
    let error = Packet::from_datagram(&overlay, &overlay.public_key().unwrap().short_id().unwrap())
        .err()
        .unwrap();
    assert!(!error.is::<Refusal>() && !error.is::<KeyRefusal>());
    datagram[65] ^= 1;
    assert_eq!(reason(Packet::from_datagram(&dest, &datagram).err().unwrap()), "digest_mismatch");
    p.signature.as_mut().unwrap()[0] ^= 1;
    assert!(Packet::from_wire(&wire(p.clone())).is_ok());
    assert_eq!(
        reason(Packet::from_wire(&wire(p)).unwrap().verify_signature().unwrap_err()),
        "invalid_signature"
    );
}
