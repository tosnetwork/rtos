/*
 * Copyright (C) 2026 RTOS contributors.
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
use super::*;
use rtos_block::{PqConsensusKey, SigPubKey, UInt256};

fn classical(transport: Option<u8>) -> ValidatorDescr {
    ValidatorDescr::with_params(
        SigPubKey::from_bytes(&[7; 32]).unwrap(),
        1,
        transport.map(|byte| UInt256::from([byte; 32])),
    )
}

fn pq(transport: u8) -> ValidatorDescr {
    // Authority extraction must not interpret these consensus-namespace fields
    // as transport keys. Cryptographic validation belongs to descriptor admission.
    ValidatorDescr::with_pq_params(
        UInt256::from([21; 32]),
        PqConsensusKey {
            algorithm_id: 1,
            key_id: UInt256::from([31; 32]),
            public_key: vec![41; 1312],
        },
        1,
        UInt256::from([transport; 32]),
    )
}

#[test]
fn fast_sync_transport_authority_target_uses_only_transport_roots() {
    let validators = vec![pq(9), classical(Some(3)), pq(9), pq(2)];
    let (members, roots) = fast_sync_transport_authority(&validators, WireProfile::T0).unwrap();
    let expected: Vec<_> = [2, 3, 9].map(|byte| KeyId::from_data([byte; 32])).into();
    assert_eq!(roots, expected);
    assert_eq!(members, expected);
    assert!(!roots.contains(validators[1].public_key().unwrap().pub_key().id()));
    for excluded in [21, 31, 41] {
        assert!(!roots.contains(&KeyId::from_data([excluded; 32])));
    }
    let mut reversed = validators;
    reversed.reverse();
    assert_eq!(
        fast_sync_transport_authority(&reversed, WireProfile::T0).unwrap(),
        (members, roots)
    );
}

#[test]
fn fast_sync_transport_authority_target_implicit_classical_and_invalid_pq() {
    let implicit = classical(None);
    let zero = classical(Some(0));
    let expected = implicit.public_key().unwrap().pub_key().id().clone();
    // Independently emitted by the fixed reference transport-authority helper.
    let reference: UInt256 =
        "9fd606bdd97bc13617a8a03373c3ef9699b04c8b8f1e32c6ae67f1b64aa0c159".parse().unwrap();
    assert_eq!(expected.data(), reference.as_array());
    assert_eq!(
        fast_sync_transport_authority(&[implicit, zero], WireProfile::T0).unwrap(),
        (vec![expected.clone()], vec![expected])
    );
    assert!(fast_sync_transport_authority(&[pq(0)], WireProfile::T0).is_err());
    let mut missing = pq(9);
    missing.adnl_addr = None;
    assert!(fast_sync_transport_authority(&[missing], WireProfile::T0).is_err());
    assert_eq!(fast_sync_transport_authority(&[], WireProfile::T0).unwrap(), (vec![], vec![]));
}

#[test]
fn fast_sync_transport_authority_legacy_keeps_classical_certificate_roots() {
    let descriptor = classical(Some(3));
    let signing_id = descriptor.public_key().unwrap().pub_key().id().clone();
    let (members, roots) =
        fast_sync_transport_authority(&[descriptor], WireProfile::Legacy).unwrap();
    assert_eq!(members, vec![KeyId::from_data([3; 32])]);
    assert_eq!(roots, vec![signing_id]);
    assert!(fast_sync_transport_authority(&[pq(9)], WireProfile::Legacy).is_err());
}
