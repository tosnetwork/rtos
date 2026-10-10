/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */

use super::*;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, str::FromStr};

const EXPECTED_CASES: [&str; 23] = [
    "valid-1",
    "valid-21",
    "duplicate-validator-id",
    "unknown-algorithm",
    "wrong-signature-length-short",
    "wrong-signature-length-long",
    "noncanonical-pqbytes",
    "sig-count-mismatch",
    "dictionary-gap",
    "dictionary-extra-entry",
    "candidate-data-oversize",
    "candidate-data-noncanonical-chunk",
    "candidate-data-non-byte-aligned",
    "candidate-data-multiple-refs",
    "candidate-data-overlong-chain",
    "candidate-data-trailing-ref",
    "candidate-data-trailing-tl",
    "401-signers",
    "claimed-weight-mismatch",
    "unknown-validator-id",
    "validator-algorithm-mismatch",
    "old-11-under-pq-vset",
    "old-12-under-pq-vset",
];

fn parse_list<T: FromStr>(text: &str) -> Vec<T>
where
    T::Err: std::fmt::Debug,
{
    if text == "-" {
        Vec::new()
    } else {
        text.split(',').map(|item| item.parse().unwrap()).collect()
    }
}

#[test]
fn shared_pq_block_signature_codec_parity_does_not_verify_finality() {
    // This gate proves byte-identical C++/Rust #13 codec behavior. Rust tooling
    // does not establish validator authority or verify finality in this path.
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/pq-block-signature-vectors.txt");
    let text = std::fs::read_to_string(path).expect("shared post-quantum block-signature vectors");
    let expected: BTreeSet<&str> = EXPECTED_CASES.into_iter().collect();
    let mut seen = BTreeSet::new();

    for line in text.lines().filter(|line| !line.is_empty() && !line.starts_with('#')) {
        let row: Vec<&str> = line.split('\t').collect();
        assert_eq!(row.len(), 14, "RUST_VECTOR_BAD_ROW fields={}", row.len());
        let case = row[0];
        assert!(expected.contains(case), "RUST_VECTOR_UNCLAIMED_ROW case={case}");
        assert!(seen.insert(case), "RUST_VECTOR_DUPLICATE_ROW case={case}");

        let boc = hex::decode(row[4]).expect("RUST_VECTOR_BAD_BOC_HEX");
        let ids: Vec<UInt256> = parse_list(row[9]);
        let algorithms: Vec<u16> = parse_list(row[10]);
        assert_eq!(ids.len(), algorithms.len(), "RUST_VECTOR_METADATA_MISMATCH case={case}");
        let validators: Vec<PqBlockValidatorWeight> = ids
            .iter()
            .zip(&algorithms)
            .map(|(validator_id, algorithm_id)| PqBlockValidatorWeight {
                validator_id: validator_id.clone(),
                algorithm_id: *algorithm_id,
                weight: 1,
            })
            .collect();

        let parsed = BlockSignaturesSimplexPq::construct_from_pq_boc(&boc, &validators);
        if row[1] == "reject" {
            let error = match parsed {
                Ok(_) => panic!("RUST_VECTOR_UNEXPECTED_ACCEPT case={case} expected={}", row[2]),
                Err(error) => error,
            };
            let actual = pq_block_signature_reason_code(&error)
                .map(PqBlockSignatureReasonCode::as_str)
                .unwrap_or("unclassified");
            assert_eq!(actual, row[2], "RUST_VECTOR_REASON_CODE_MISMATCH case={case}");
            continue;
        }

        assert_eq!(row[1], "accept", "RUST_VECTOR_BAD_OUTCOME case={case}");
        let parsed = parsed.unwrap_or_else(|error| {
            panic!("RUST_VECTOR_UNEXPECTED_REJECT case={case} actual={error}")
        });
        assert_eq!(row[2], "-", "RUST_VECTOR_METADATA_MISMATCH case={case}");
        assert_eq!(row[5], "#13", "RUST_VECTOR_METADATA_MISMATCH case={case}");
        assert_eq!(parsed.validator_info.validator_list_hash_short, row[6].parse().unwrap());
        assert_eq!(parsed.validator_info.catchain_seqno, row[7].parse().unwrap());
        assert_eq!(parsed.sig_count, row[8].parse().unwrap());
        assert_eq!(
            parsed.signatures.iter().map(|pair| &pair.validator_id).collect::<Vec<_>>(),
            ids.iter().collect::<Vec<_>>()
        );
        assert_eq!(
            parsed.signatures.iter().map(|pair| pair.algorithm_id).collect::<Vec<_>>(),
            algorithms
        );
        assert_eq!(parsed.session_id, UInt256::from_str(row[11]).unwrap());
        assert_eq!(parsed.slot, row[12].parse().unwrap());
        let candidate = read_candidate_data(&parsed.candidate_data).unwrap();
        assert_eq!(hex::encode_upper(Sha256::digest(candidate)), row[13]);

        let reserialized = parsed.write_to_bytes().unwrap_or_else(|error| {
            panic!("RUST_VECTOR_RESERIALIZATION_FAILED case={case} actual={error}")
        });
        assert_eq!(reserialized, boc, "RUST_VECTOR_RESERIALIZATION_DRIFT case={case}");
    }

    if let Some(missing) = expected.difference(&seen).next() {
        panic!("RUST_VECTOR_MISSING_ROW case={missing}");
    }
    println!("RUST_PQ_BLOCK_SIGNATURE_VECTORS_OK rows={}", seen.len());
}

fn valid_carrier() -> BlockSignaturesSimplexPq {
    let text = include_str!("../../tests/data/pq-block-signature-vectors.txt");
    let row: Vec<_> =
        text.lines().find(|l| l.starts_with("valid-1\t")).unwrap().split('\t').collect();
    BlockSignaturesSimplexPq::construct_from_bytes(&hex::decode(row[4]).unwrap()).unwrap()
}
#[test]
fn pq_carrier_reuse_duplicates_and_classical_view_refusal() {
    let original = valid_carrier();
    let root = original.serialize().unwrap();
    let mut reused = BlockSignaturesSimplexPq::default();
    for _ in 0..2 {
        reused.read_from(&mut SliceData::load_cell_ref(&root).unwrap()).unwrap();
        assert_eq!(original, reused);
    }
    let variant = BlockSignaturesVariant::SimplexPq(reused.clone());
    assert!(variant.pure_signatures().is_err());
    assert_eq!(variant.declared_signature_count(), 1);
    let member = PqBlockValidatorWeight {
        validator_id: original.signatures[0].validator_id.clone(),
        algorithm_id: 1,
        weight: original.sig_weight,
    };
    let mut duplicate = original.clone();
    duplicate.sig_count = 2;
    duplicate.signatures.push(duplicate.signatures[0].clone());
    duplicate.sig_weight *= 2;
    let err = duplicate.check_structural_membership_and_weight(&[member.clone()]).unwrap_err();
    assert_eq!(
        pq_block_signature_reason_code(&err),
        Some(PqBlockSignatureReasonCode::DuplicateValidatorId)
    );
    assert!(duplicate.serialize().is_err());
    assert!(original.check_structural_membership_and_weight(&[member.clone(), member]).is_err());
    let mut trailing = BuilderData::from_cell(&root).unwrap();
    trailing.append_bit_one().unwrap();
    assert!(BlockSignaturesSimplexPq::construct_from_cell(trailing.into_cell().unwrap()).is_err());
}
#[test]
fn pq_carrier_count_is_bounded_before_dictionary_allocation() {
    let mut root = BuilderData::new();
    root.append_u8(0x13).unwrap();
    ValidatorBaseInfo::default().write_to(&mut root).unwrap();
    root.append_u32(401).unwrap();
    let err = BlockSignaturesSimplexPq::construct_from_cell(root.into_cell().unwrap()).unwrap_err();
    assert_eq!(pq_block_signature_reason_code(&err), Some(PqBlockSignatureReasonCode::SignerCount));
    let err = BlockSignaturesSimplexPq::construct_from_pq_boc(
        &vec![0; PQ_SIGNATURE_BOC_MAX_BYTES + 1],
        &[],
    )
    .unwrap_err();
    assert_eq!(
        pq_block_signature_reason_code(&err),
        Some(PqBlockSignatureReasonCode::CarrierOversize)
    );
}

#[test]
fn pq_carrier_400_signers_matches_fixed_cpp_size_and_digest() {
    // Deterministic size fixture from the fixed reference carrier harness.
    // These exact-width payloads are not valid cryptographic signatures.
    let hash = |bytes: &[u8]| -> UInt256 { UInt256::from(crate::sha256_digest(bytes)) };
    let mut candidate = 0x8354642du32.to_le_bytes().to_vec();
    candidate.extend_from_slice(&(-1i32).to_le_bytes());
    candidate.extend_from_slice(&0x8000000000000000u64.to_le_bytes());
    candidate.extend_from_slice(&42u32.to_le_bytes());
    candidate.extend_from_slice(hash(b"carrier-root").as_slice());
    candidate.extend_from_slice(hash(b"carrier-file").as_slice());
    candidate.extend_from_slice(&2718280u32.to_le_bytes());
    candidate.extend_from_slice(hash(b"carrier-parent").as_slice());
    assert_eq!(candidate.len(), 120);
    let mut carrier = BlockSignaturesSimplexPq {
        validator_info: ValidatorBaseInfo::with_params(0x31415926, 1789434),
        sig_count: 400,
        sig_weight: 400,
        session_id: hash(b"persisted-pq-block-signature-session"),
        slot: 2718281,
        candidate_data: BlockSignaturesSimplex::bytes_to_cell_tree(&candidate).unwrap(),
        signatures: Vec::new(),
    };
    for index in 0..400 {
        let mut seed = format!("persisted-pq-signature-{index}").into_bytes();
        let mut bytes = Vec::new();
        while bytes.len() < PQ_SIGNATURE_BYTES {
            seed = hash(&seed).as_slice().to_vec();
            let n = 32.min(PQ_SIGNATURE_BYTES - bytes.len());
            bytes.extend_from_slice(&seed[..n]);
        }
        carrier.signatures.push(PqBlockSignaturePair {
            validator_id: hash(format!("persisted-validator-{index}").as_bytes()),
            algorithm_id: 1,
            signature: bytes,
        });
    }
    let boc = carrier.write_to_bytes().unwrap();
    assert_eq!(boc.len(), 1020996);
    assert_eq!(
        hex::encode_upper(Sha256::digest(&boc)),
        "0C05E72DD2095B0B3497CEF3422DFBC65B42891BB011C75E769AC245FA0B9B63"
    );
    assert_eq!(BlockSignaturesSimplexPq::construct_from_bytes(&boc).unwrap(), carrier);
    carrier.sig_count = 401;
    carrier.signatures.push(PqBlockSignaturePair {
        validator_id: hash(b"extra"),
        ..carrier.signatures[0].clone()
    });
    assert!(carrier.serialize().is_err());
}
