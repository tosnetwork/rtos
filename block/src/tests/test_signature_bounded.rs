// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::sync::Mutex;
#[derive(Debug)]
struct Refused;
impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bounded proof test refused")
    }
}
impl std::error::Error for Refused {}
struct Budget(Mutex<(usize, usize)>);
impl Budget {
    fn ample() -> Self {
        Self(Mutex::new((10_000_000, 128 << 20)))
    }
}
impl ConfigReadBudget for Budget {
    fn step(&self) -> Result<()> {
        let mut u = self.0.lock().unwrap();
        if u.0 == 0 {
            return Err(Refused.into());
        }
        u.0 -= 1;
        Ok(())
    }
    fn workspace(&self, n: usize) -> Result<()> {
        let mut u = self.0.lock().unwrap();
        if n > u.1 {
            return Err(Refused.into());
        }
        u.1 -= n;
        Ok(())
    }
}
#[test]
fn bounded_proof_classical_signatures_and_count_preserve_checks() {
    let key = Ed25519KeyOption::<ZeroizingBytes>::generate().unwrap();
    let validator = ValidatorDescr::with_params(
        SigPubKey::from_bytes(key.pub_key().unwrap()).unwrap(),
        10,
        None,
    );
    let message = b"bounded proof real signature";
    let pair = CryptoSignaturePair::with_params(
        validator.compute_node_id_short().unwrap(),
        CryptoSignature::from_bytes(&key.sign(message).unwrap()).unwrap(),
    );
    let mut signatures = BlockSignaturesPure::new();
    signatures.add_sigpair(pair.clone());
    assert_eq!(signatures.signatures_count_bounded(&Budget::ample()).unwrap(), 1);
    assert_eq!(
        signatures
            .check_signatures_bounded(&[validator.clone()], message, &Budget::ample())
            .unwrap(),
        signatures.check_signatures(&[validator.clone()], message).unwrap()
    );
    assert!(signatures
        .check_signatures_bounded(&[validator.clone()], b"tampered", &Budget::ample())
        .is_err());
    let error = signatures.signatures_count_bounded(&Budget(Mutex::new((0, 1 << 20)))).unwrap_err();
    assert!(error.downcast_ref::<Refused>().is_some());
    signatures.add_sigpair(pair);
    assert!(signatures.check_signatures_bounded(&[validator], message, &Budget::ample()).is_err());
}
#[test]
fn bounded_proof_pq_raw_shared_vectors_and_budget() {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/pq-block-signature-vectors.txt"
    ))
    .unwrap();
    let mut cases = 0;
    for line in text.lines().filter(|line| !line.is_empty() && !line.starts_with('#')) {
        let row: Vec<_> = line.split('\t').collect();
        let bytes = hex::decode(row[4]).unwrap();
        let root = read_single_root_boc(&bytes).unwrap();
        let mut validators = Vec::new();
        if row[9] != "-" {
            for (id, algorithm) in row[9].split(',').zip(row[10].split(',')) {
                validators.push(PqBlockValidatorWeight {
                    validator_id: UInt256::from_str(id).unwrap(),
                    algorithm_id: algorithm.parse().unwrap(),
                    weight: 1,
                });
            }
        }
        let parsed = BlockSignaturesSimplexPq::construct_bounded(root.clone(), &Budget::ample())
            .and_then(|value| {
                value.check_structural_membership_and_weight_bounded(
                    &validators,
                    &Budget::ample(),
                )?;
                Ok(value)
            });
        let ordinary = BlockSignaturesSimplexPq::construct_from_pq_boc(&bytes, &validators);
        assert_eq!(
            parsed.is_ok(),
            ordinary.is_ok(),
            "case {} bounded={:?}",
            row[0],
            parsed.as_ref().err()
        );
        if let Ok(parsed) = parsed {
            assert_eq!(parsed, ordinary.unwrap());
            assert_eq!(
                parsed.candidate_bytes_bounded(&Budget::ample()).unwrap(),
                parsed.candidate_bytes().unwrap()
            );
            let proof = BlockProof::with_params(
                BlockIdExt::default(),
                Cell::default(),
                Some(BlockSignaturesVariant::SimplexPq(parsed)),
            );
            let root = proof.serialize().unwrap();
            assert_eq!(
                BlockProof::construct_from_cell_bounded(root.clone(), &Budget::ample()).unwrap(),
                proof
            );
            let error =
                BlockProof::construct_from_cell_bounded(root, &Budget(Mutex::new((0, 128 << 20))))
                    .unwrap_err();
            assert!(error.downcast_ref::<Refused>().is_some());
        }
        cases += 1;
    }
    assert_eq!(cases, 23);
}
#[test]
fn bounded_proof_value_flow_visits_bad_late_currency_and_shared_paths() {
    use crate::{ValueFlow, VarUInteger32};
    let mut flow = ValueFlow::default();
    for i in 0u32..8 {
        flow.burned.other.set(&i, &VarUInteger32::from(i)).unwrap();
    }
    flow.read_in_full_depth().unwrap();
    flow.read_in_full_depth_bounded(&Budget::ample()).unwrap();
    let error = flow.read_in_full_depth_bounded(&Budget(Mutex::new((0, 1 << 20)))).unwrap_err();
    assert!(error.downcast_ref::<Refused>().is_some());
    // A raw dictionary leaf declares 31 bytes but provides none. Validation
    // must reach the last ValueFlow collection, not just inspect root views.
    let mut raw = HashmapE::with_bit_len(32);
    let mut truncated = BuilderData::new();
    truncated.append_bits(31, 5).unwrap();
    raw.set_builder(9u32.write_to_bitstring().unwrap(), &truncated).unwrap();
    flow.burned.other = crate::ExtraCurrencyCollection::with_hashmap(raw.data().cloned());
    assert!(flow.read_in_full_depth().is_err());
    assert!(flow.read_in_full_depth_bounded(&Budget::ample()).is_err());
}
#[test]
fn bounded_proof_candidate_cell_construction_matches_and_refuses_before_cell() {
    for len in [0, 1, 127, 128, 160, 1024] {
        let bytes = vec![7; len];
        assert_eq!(
            BlockSignaturesSimplex::bytes_to_cell_tree_bounded(&bytes, &Budget::ample()).unwrap(),
            BlockSignaturesSimplex::bytes_to_cell_tree(&bytes).unwrap()
        );
    }
    let error =
        BlockSignaturesSimplex::bytes_to_cell_tree_bounded(&[7], &Budget(Mutex::new((10, 0))))
            .unwrap_err();
    assert!(error.downcast_ref::<Refused>().is_some());
    assert!(BlockSignaturesSimplex::bytes_to_cell_tree_bounded(&vec![0; 1025], &Budget::ample())
        .is_err());
}
