// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use rtos_pq_crypto::falcon512;

#[test]
fn falcon512_official_and_profile_vectors() {
    let rows: Vec<_> = include_str!("data/falcon512.tsv").lines().collect();
    assert_eq!(rows.len(), 228);
    for line in rows {
        let f: Vec<_> = line.split('\t').collect();
        let message = hex::decode(f[2]).unwrap();
        let signature = hex::decode(f[3]).unwrap();
        let public_key = hex::decode(f[4]).unwrap();
        let result = falcon512::verify(&message, &signature, &public_key);
        let actual = match result {
            Ok(true) => "V",
            Ok(false) => "I",
            Err(falcon512::VerifyError::Backend(code)) => panic!("{}: backend {code}", f[0]),
            Err(_) => "M",
        };
        assert_eq!(actual, f[1], "{}", f[0]);
    }
}
