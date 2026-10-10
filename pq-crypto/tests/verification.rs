// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use rtos_pq_crypto::{verify, verify_simplex, VerifyError, SIMPLEX_CONTEXT};
use serde_json::Value;
use std::collections::BTreeMap;

fn bytes(case: &Value, field: &str) -> Vec<u8> {
    if let Some(hex) = case.get(format!("{field}Hex")) {
        hex::decode(hex.as_str().unwrap()).unwrap()
    } else {
        let spec = &case[format!("{field}Repeat")];
        vec![spec["byte"].as_u64().unwrap() as u8; spec["count"].as_u64().unwrap() as usize]
    }
}

#[test]
fn openssl_vectors_bind_message_context_key_and_signature() {
    let data: Value = serde_json::from_str(include_str!("data/openssl-mldsa44.json")).unwrap();
    let key = hex::decode(data["publicKeyHex"].as_str().unwrap()).unwrap();
    assert_eq!(data["cases"].as_array().unwrap().len(), 3);
    for case in data["cases"].as_array().unwrap() {
        let message = bytes(case, "message");
        let context = bytes(case, "context");
        let signature = bytes(case, "signature");
        assert_eq!(verify(&message, &context, &signature, &key), Ok(true), "{}", case["id"]);
        for field in 0..4 {
            let mut changed = [message.clone(), context.clone(), signature.clone(), key.clone()];
            if changed[field].is_empty() {
                changed[field].push(1);
            } else {
                changed[field][0] ^= 1;
            }
            assert_eq!(
                verify(&changed[0], &changed[1], &changed[2], &changed[3]),
                Ok(false),
                "{} mutation {field}",
                case["id"]
            );
        }
        // A wallet/authentication or empty-context signature cannot be reused
        // in consensus merely because it is valid under the same public key.
        assert_eq!(verify_simplex(&message, &signature, &key), Ok(false));
    }
    assert_eq!(SIMPLEX_CONTEXT, b"TOS-CONSENSUS-SIMPLEX-v1");
}

#[test]
fn fixed_external_conformance_vectors() {
    let mut counts = BTreeMap::<String, usize>::new();
    let mut seen = std::collections::BTreeSet::new();
    for row in include_str!("data/verification-vectors.tsv").lines() {
        let fields: Vec<_> = row.split('\t').collect();
        assert_eq!(fields.len(), 6);
        assert!(seen.insert(fields[0]));
        let input: Vec<_> = fields[2..].iter().map(|s| hex::decode(s).unwrap()).collect();
        let actual = verify(&input[0], &input[1], &input[2], &input[3]);
        match fields[1] {
            "V" => assert_eq!(actual, Ok(true), "{}", fields[0]),
            "I" => assert_eq!(actual, Ok(false), "{}", fields[0]),
            "M" => assert!(
                matches!(
                    actual,
                    Err(VerifyError::PublicKeyLength(_)
                        | VerifyError::SignatureLength(_)
                        | VerifyError::MessageLength(_)
                        | VerifyError::ContextLength(_))
                ),
                "{}: {actual:?}",
                fields[0]
            ),
            other => panic!("unexpected vector verdict {other}"),
        }
        let source = fields[0].split('-').next().unwrap();
        *counts.entry(format!("{source}.{}", fields[1])).or_default() += 1;
    }
    let expected: BTreeMap<_, _> = [
        ("acvp.V", 3),
        ("acvp.I", 12),
        ("openssl.V", 3),
        ("wycheproof.V", 77),
        ("wycheproof.I", 91),
        ("wycheproof.M", 12),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value))
    .collect();
    assert_eq!(counts, expected);
    assert_eq!(seen.len(), 198);
}

#[test]
fn simplex_context_accepts_only_consensus_signatures() {
    let data: Value = serde_json::from_str(include_str!("data/simplex-context.json")).unwrap();
    let message = hex::decode(data["messageHex"].as_str().unwrap()).unwrap();
    let key = hex::decode(data["publicKeyHex"].as_str().unwrap()).unwrap();
    assert_eq!(data["cases"].as_array().unwrap().len(), 3);
    for case in data["cases"].as_array().unwrap() {
        let signature = bytes(case, "signature");
        let context = bytes(case, "context");
        assert_eq!(verify(&message, &context, &signature, &key), Ok(true));
        assert_eq!(verify_simplex(&message, &signature, &key), Ok(case["id"] == "simplex"));
    }
}
