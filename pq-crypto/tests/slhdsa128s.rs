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
