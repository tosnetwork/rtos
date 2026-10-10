// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use rtos_pq_crypto::slhdsa128s::{self, VerifyError, SIGNATURE_BYTES};

#[test]
fn public_acvp_pure_sha2_128s() {
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("data/slhdsa128s-acvp.json")).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 14);
    for row in rows.as_array().unwrap() {
        let get = |name| hex::decode(row[name].as_str().unwrap()).unwrap();
        let (m, c, s, k) = (get("message"), get("context"), get("signature"), get("public_key"));
        let expected = if s.len() != SIGNATURE_BYTES {
            Err(VerifyError::SignatureLength(s.len()))
        } else {
            Ok(row["expected"].as_bool().unwrap())
        };
        assert_eq!(slhdsa128s::verify(&m, &c, &s, &k), expected, "{}", row["id"]);
    }
}

#[test]
fn independent_circl_boundary_signatures() {
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("data/slhdsa128s-circl.json")).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 16);
    for row in rows.as_array().unwrap() {
        let get = |name| hex::decode(row[name].as_str().unwrap()).unwrap();
        let (m, c, s, k) = (get("message"), get("context"), get("signature"), get("public_key"));
        assert_eq!(slhdsa128s::verify(&m, &c, &s, &k), Ok(true), "{}", row["id"]);
    }
}

// Results are frozen from the unmodified fixed C++ wrapper and native library.
// The Rust backend must agree on all input bytes, context separation and bounds.
#[test]
fn frozen_cpp_boundary_matrix() {
    use std::collections::BTreeMap;
    let mut expected: BTreeMap<&str, i32> = include_str!("data/slhdsa128s-boundaries.tsv")
        .lines()
        .map(|line| {
            let (id, result) = line.split_once('\t').unwrap();
            (id, result.parse().unwrap())
        })
        .collect();
    let mut bases = BTreeMap::new();
    for text in [
        include_str!("data/slhdsa128s-acvp.json"),
        include_str!("data/slhdsa128s-circl.json"),
        include_str!("data/slhdsa128s-other-profiles.json"),
    ] {
        let rows: serde_json::Value = serde_json::from_str(text).unwrap();
        for row in rows.as_array().unwrap() {
            let values = ["message", "context", "signature", "public_key"]
                .map(|k| hex::decode(row[k].as_str().unwrap()).unwrap());
            bases.insert(row["id"].as_str().unwrap().to_owned(), values);
        }
    }
    let count = expected.len();
    let mut check = |id: &str, v: &[Vec<u8>; 4]| {
        let result = slhdsa128s::verify(&v[0], &v[1], &v[2], &v[3]);
        let code = match result {
            Ok(valid) => i32::from(valid),
            Err(VerifyError::Backend(code)) => panic!("backend fault in {id}: {code}"),
            Err(_) => 2,
        };
        assert_eq!(code, expected.remove(id).expect("case absent from C++ fixture"), "{id}");
    };
    for (id, values) in &bases {
        check(id, values);
    }
    for (prefix, base, field, offsets) in [
        ("signature-byte", "circl-m0-c0", 2, (0..7856).collect::<Vec<_>>()),
        ("key-byte", "circl-m0-c0", 3, (0..32).collect()),
        ("context-byte", "circl-m1-c255", 1, (0..255).collect()),
        ("message-byte", "circl-m8192-c0", 0, (0..8192).step_by(64).chain([8191]).collect()),
    ] {
        for offset in offsets {
            let mut v = bases[base].clone();
            v[field][offset] ^= 1;
            check(&format!("{prefix}-{offset}"), &v);
        }
    }
    for (field, lengths) in [
        (3, vec![0, 1, 15, 16, 31, 33, 64]),
        (2, vec![0, 1, 15, 16, 7839, 7840, 7855, 7857, 8192]),
        (0, vec![8193, 8194]),
        (1, vec![256, 257]),
    ] {
        for n in lengths {
            let mut v = bases["circl-m8192-c255"].clone();
            v[field].resize(n, 0);
            check(&format!("length-{field}-{n}"), &v);
        }
    }
    for field in 0..4 {
        for (name, byte) in [("zero", 0), ("ff", 255)] {
            let mut v = bases["circl-m1-c255"].clone();
            v[field].fill(byte);
            check(&format!("{name}-{field}"), &v);
        }
    }
    assert!(expected.is_empty(), "unexecuted C++ cases: {} of {count}", expected.len());
}
