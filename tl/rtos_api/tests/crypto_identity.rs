// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use rtos_api::session_identity::session_members;
use rtos_block::{PqConsensusKey, SigPubKey, UInt256, ValidatorDescr, ValidatorSet};

#[test]
fn zero_algorithm_uses_classical_wire_profile_without_admitting_the_descriptor() {
    let descriptor = ValidatorDescr::with_pq_params(
        UInt256::from([17; 32]),
        PqConsensusKey { algorithm_id: 0, key_id: UInt256::from([18; 32]), public_key: vec![] },
        1,
        UInt256::from([19; 32]),
    );
    let members = session_members(&[descriptor.clone()]).unwrap();
    let wire = rtos_api::serialize_boxed(&members[0]).unwrap();
    assert_eq!(&wire[..4], &0x8b9465e4u32.to_le_bytes());
    let classical = ValidatorDescr::with_params(
        SigPubKey::from_bytes(&[0; 32]).unwrap(),
        1,
        descriptor.adnl_addr.clone(),
    );
    let expected = session_members(&[classical]).unwrap();
    assert_eq!(wire, rtos_api::serialize_boxed(&expected[0]).unwrap());
    assert!(ValidatorSet::new(0, 1, 1, vec![descriptor]).is_err());
}

#[test]
fn raw_member_wire_weight_does_not_admit_an_overweight_governing_set() {
    for weight in [i64::MAX as u64 + 1, u64::MAX] {
        let validator =
            ValidatorDescr::with_params(SigPubKey::from_bytes(&[17; 32]).unwrap(), weight, None);
        let members = session_members(&[validator.clone()]).unwrap();
        let bytes = rtos_api::serialize_boxed(&members[0]).unwrap();
        assert_eq!(&bytes[bytes.len() - 8..], &weight.to_le_bytes());
        assert!(ValidatorSet::new(0, 1, 1, vec![validator]).is_err());
    }
}
