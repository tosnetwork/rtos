// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use rtos_pq_crypto::lms_fee::{self, Outcome};

#[test]
fn lms_fee_reference_vectors() {
    let rows: Vec<_> = include_str!("data/lms-fee.tsv").lines().collect();
    assert_eq!(rows.len(), 166);
    for line in rows {
        let f: Vec<_> = line.split('\t').collect();
        let message = hex::decode(f[3]).unwrap();
        let signature = hex::decode(f[4]).unwrap();
        let key = hex::decode(f[5]).unwrap();
        let expected = match f[1] {
            "V" => Outcome::Valid,
            "I" => Outcome::Invalid,
            "M" => Outcome::Malformed,
            _ => panic!("verdict"),
        };
        assert_eq!(lms_fee::verify(&message, &signature, &key), expected, "{}", f[0]);
        assert_eq!(
            lms_fee::worst_compressions(&key, message.len()),
            if f[2] == "-" { None } else { Some(f[2].parse().unwrap()) },
            "{}",
            f[0]
        );
    }
}

#[test]
fn lms_fee_cost_bounds() {
    let mut key = [0u8; lms_fee::PUBLIC_KEY_BYTES];
    key[3] = 1;
    key[7] = 8;
    key[11] = 3;
    let maximum =
        (0u32..=960).map(|s| s + 45 - ((s >> 8) + (s >> 4 & 15) + (s & 15))).max().unwrap();
    assert_eq!(maximum, 990);
    for size in 0..=lms_fee::MAX_MESSAGE_BYTES {
        let q_blocks = (54 + size + 9 + 63) / 64;
        assert_eq!(
            lms_fee::worst_compressions(&key, size),
            Some(q_blocks as u64 + 34 + 990 + 1 + 40)
        );
    }
    assert_eq!(lms_fee::worst_compressions(&key, 32), Some(1067));
    for size in [8193, usize::MAX] {
        assert_eq!(lms_fee::worst_compressions(&key, size), None);
    }
}
