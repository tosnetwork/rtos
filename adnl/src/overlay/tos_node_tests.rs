// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

#[test]
fn native_node_matches_cpp_serialization() {
    let vectors = include_str!("testdata/tos-overlay-node-vectors.txt");
    let vector = |name: &str| {
        let value = vectors
            .lines()
            .find_map(|line| line.strip_prefix(name).and_then(|rest| rest.strip_prefix('=')))
            .expect("frozen production serializer vector");
        hex::decode(value).unwrap()
    };
    let to_sign = NodeToSign {
        id: AdnlShortId { id: UInt256::from([0x33; 32]) },
        overlay: UInt256::from([0x22; 32]),
        flags: 2,
        version: 1_700_000_000,
    }
    .into_boxed();
    assert_eq!(serialize_boxed(&to_sign).unwrap(), vector("to_sign"));
    let node = NodeV1 {
        id: rtos_api::ton::pub_::publickey::Ed25519 { key: UInt256::from([0x11; 32]) }.into_boxed(),
        overlay: UInt256::from([0x22; 32]),
        flags: 2,
        version: 1_700_000_000,
        signature: vec![0x44; 64],
        certificate: MemberCertificateBoxed::default(),
    }
    .into_boxed();
    let bytes = vector("node");
    assert_eq!(serialize_boxed(&node).unwrap(), bytes);
    let decoded: rtos_api::ton::overlay::Node = rtos_api::deserialize_typed(&bytes).unwrap();
    assert_eq!(serialize_boxed(&decoded).unwrap(), bytes);
}

#[test]
fn native_node_authenticates_flags_and_rejects_unknown_bits() {
    let (_, key) =
        rtos_block::Ed25519KeyOption::<rtos_block::ZeroizingBytes>::from_private_key_with_json(
            &[71; 32],
        )
        .unwrap();
    let overlay = OverlayShortId::from_data([93; 32]);
    for flags in [0, 1, 2, 3, 4, -1] {
        let mut node = NodeV1 {
            id: (&key).try_into().unwrap(),
            overlay: UInt256::from(*overlay.data()),
            flags,
            version: 1_700_000_000,
            signature: vec![],
            certificate: MemberCertificateBoxed::default(),
        };
        let to_sign = OverlayUtils::get_node_to_sign(&key, &node.overlay, flags, node.version);
        node.signature = key.sign(&serialize_boxed(&to_sign).unwrap()).unwrap();
        assert_eq!(OverlayUtils::verify_node(&overlay, &node).is_ok(), (0..=3).contains(&flags));
        if (0..=3).contains(&flags) {
            node.flags ^= 1;
            assert!(OverlayUtils::verify_node(&overlay, &node).is_err(), "flags are signed");
            node.flags = flags;
            node.signature[0] ^= 1;
            assert!(OverlayUtils::verify_node(&overlay, &node).is_err(), "signature is checked");
        }
    }
}
