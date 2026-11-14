// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use rtos_api::session_identity::session_members;
use rtos_block::{SigPubKey, ValidatorDescr, ValidatorSet};

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
