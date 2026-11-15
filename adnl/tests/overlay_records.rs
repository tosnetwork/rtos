// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use adnl::{
    records::{overlay_public_key, MemberCertificate, MemberFlags, NodeRecord},
    wire_keys::{KeyRefusal, NetworkPrivateKey},
    BroadcastCheckResult as Verdict, OverlayCertificate, OverlayPrivacyRules,
};
use rtos_api::{ton, IntoBoxed, WireProfile};
use std::collections::BTreeMap;
fn private() -> NetworkPrivateKey {
    NetworkPrivateKey::from_wire(
        &WireProfile::T0
            .serialize(&ton::pk::privatekey::Ed25519 { key: [17; 32].into() }.into_boxed())
            .unwrap(),
    )
    .unwrap()
}
fn unenc() -> ton::PublicKey {
    ton::pub_::publickey::Unenc { data: vec![3] }.into_boxed()
}
#[test]
fn flags_and_privacy_preserve_unknown_bits_and_authorized_precedence() {
    for f in [0, 1, 2, 3, 4, 8, u32::MAX, 1 << 31] {
        assert_eq!(MemberFlags::valid(f), f <= 3);
        assert_eq!(MemberFlags::receives_regular(f), f == 0 || f == 2);
        assert_eq!(MemberFlags::receives_plumtree(f), f == 0);
        for enabled in [false, true] {
            for sender in [false, true] {
                assert_eq!(
                    MemberFlags::public_flags(f, enabled, sender),
                    f | if enabled && !sender { 0 } else { 2 }
                );
            }
        }
    }
    let rules = OverlayPrivacyRules::new(768, 0, BTreeMap::from([([1; 32], 900)]));
    assert_eq!(rules.max_broadcast_size(), 900);
    assert_eq!(rules.check_rules(&[1; 32], 900, true, true), Verdict::Allowed);
    assert_eq!(rules.check_rules(&[1; 32], 901, false, false), Verdict::Forbidden);
    assert_eq!(rules.check_rules(&[2; 32], 768, false, false), Verdict::NeedCheck);
    assert_eq!(rules.check_rules(&[2; 32], 768, true, false), Verdict::Forbidden);
    assert_eq!(rules.check_rules(&[2; 32], 0, false, true), Verdict::Forbidden);
}
#[test]
fn broadcast_certificate_reuses_network_key_profiles_and_normalizes_default_flags() {
    let cert = OverlayCertificate::new(unenc(), 1000, 768, 2, vec![9; 7]).unwrap();
    assert_eq!(cert.check(&[1; 32], &[2; 32], 1000, 768, false, false), Verdict::Allowed);
    assert_eq!(cert.check(&[1; 32], &[2; 32], 1001, 768, false, false), Verdict::Forbidden);
    assert_eq!(cert.check(&[1; 32], &[2; 32], 1000, 769, false, false), Verdict::Forbidden);
    assert_eq!(cert.check(&[1; 32], &[2; 32], 1000, 768, true, false), Verdict::Forbidden);
    assert!(matches!(cert.to_tl(), ton::overlay::Certificate::Overlay_Certificate(_)));
    let v2 = ton::overlay::certificate::CertificateV2 {
        issued_by: unenc(),
        expire_at: 1000,
        max_size: 768,
        flags: 2,
        signature: vec![1],
    }
    .into_boxed();
    let wire = WireProfile::T0.serialize(&v2).unwrap();
    let normalized = OverlayCertificate::from_wire(&wire).unwrap().unwrap();
    assert!(matches!(normalized.to_tl(), ton::overlay::Certificate::Overlay_Certificate(_)));
    for key in [
        ton::pub_::publickey::Aes { key: [0; 32].into() }.into_boxed(),
        ton::pub_::publickey::Overlay { name: vec![] }.into_boxed(),
    ] {
        let c = OverlayCertificate::new(key, 1000, 768, 2, vec![]).unwrap();
        assert_eq!(c.check(&[1; 32], &[2; 32], 0, 1, false, false), Verdict::Forbidden);
    }
}
#[test]
fn member_certificate_signed_fields_and_signed_expiry_grace_are_preserved() {
    let tl = ton::overlay::membercertificate::MemberCertificate {
        issued_by: unenc(),
        flags: -1,
        slot: i32::MIN,
        expire_at: -1,
        signature: vec![4],
    }
    .into_boxed();
    let wire = WireProfile::T0.serialize(&tl).unwrap();
    let c = MemberCertificate::from_wire(&wire).unwrap();
    assert!(!c.is_expired(2.0));
    assert!(c.is_expired(2.5));
    assert_eq!(WireProfile::T0.serialize(c.tl()).unwrap(), wire);
    c.verify_signature([5; 32]).unwrap();
    assert_ne!(c.to_sign([5; 32]).unwrap(), c.to_sign([6; 32]).unwrap());
    let empty =
        MemberCertificate::from_tl(ton::overlay::MemberCertificate::Overlay_EmptyMemberCertificate);
    assert_eq!(empty.expire_at(), i32::MAX);
    assert!(!empty.is_expired(i32::MAX as f64));
    assert!(empty.to_sign([0; 32]).unwrap().is_none());
}
#[test]
fn node_record_checks_flags_before_key_then_authenticates_all_signed_fields() {
    let key = private();
    let public = key.public_key().unwrap().to_wire().unwrap();
    let id = WireProfile::T0.deserialize_value_bounded(&public, public.len()).unwrap();
    let node = ton::overlay::node::Node {
        id,
        overlay: [2; 32].into(),
        flags: 2,
        version: 123,
        signature: vec![],
        certificate: ton::overlay::MemberCertificate::Overlay_EmptyMemberCertificate,
    };
    let record = NodeRecord::from_tl(node.clone()).unwrap();
    let mut node = node;
    node.signature = key.sign(&record.to_sign().unwrap()).unwrap();
    let record = NodeRecord::from_tl(node.clone()).unwrap();
    record.verify_signature().unwrap();
    assert_eq!(
        NodeRecord::from_wire(&record.to_wire().unwrap()).unwrap().short_id(),
        record.short_id()
    );
    node.flags = 1;
    assert_eq!(
        NodeRecord::from_tl(node.clone())
            .unwrap()
            .verify_signature()
            .unwrap_err()
            .downcast_ref::<KeyRefusal>()
            .unwrap()
            .0,
        "invalid_signature"
    );
    node.id = unenc();
    node.flags = 4;
    assert_eq!(
        NodeRecord::from_tl(node.clone()).err().unwrap().to_string(),
        "overlay_node_invalid"
    );
    node.flags = 0;
    assert_eq!(NodeRecord::from_tl(node).err().unwrap().to_string(), "not_ed25519");
    let a = overlay_public_key(b"a").unwrap();
    assert_ne!(a.short_id().unwrap(), overlay_public_key(b"b").unwrap().short_id().unwrap());
}
