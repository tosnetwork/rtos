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

fn unique_balanced_graph(leaves: usize, payload: usize) -> Cell {
    assert!(payload >= 4 && payload <= 127);
    let mut level: Vec<_> = (0..leaves)
        .map(|index| {
            let mut bytes = vec![0x65; payload];
            bytes[..4].copy_from_slice(&(index as u32).to_be_bytes());
            BuilderData::with_raw(bytes, payload * 8).unwrap().into_cell().unwrap()
        })
        .collect();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| {
                if pair.len() == 1 {
                    return pair[0].clone();
                }
                let mut node = BuilderData::new();
                for child in pair {
                    node.checked_append_reference(child.clone()).unwrap();
                }
                node.into_cell().unwrap()
            })
            .collect();
    }
    level.pop().unwrap()
}
fn assert_measured_boc(root: &Cell) -> usize {
    let ordinary = crate::write_boc(root).unwrap().len();
    assert_eq!(bounded_signature_boc_size(root, &Budget::ample()).unwrap(), ordinary);
    ordinary
}
#[test]
fn bounded_proof_materialization_precedes_candidate_and_root_reads() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let original = unique_balanced_graph(2, 8);
    let pruned =
        crate::MerkleUpdate::make_pruned_branch_cell(&original, 0).unwrap().into_cell().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let source = original.clone();
    let loader: crate::CellLoader = Arc::new(move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
        Ok(source.clone())
    });
    let lazy = Cell::lazy_from_pruned(&pruned, loader, 0).unwrap();
    assert!(read_candidate_data_bounded(&lazy, &Budget::ample()).is_err());
    assert!(bounded_signature_boc_size(&lazy, &Budget::ample()).is_err());
    assert!(BlockProof::construct_from_cell_bounded(lazy, &Budget::ample()).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0, "bounded admission invoked the real loader");
    let mut parent = BuilderData::new();
    parent.checked_append_reference(pruned).unwrap();
    let virtualized = parent.into_cell().unwrap().virtualize(1);
    assert_ne!(virtualized.virtualization(), 0);
    assert!(read_candidate_data_bounded(&virtualized, &Budget::ample()).is_err());
    assert!(bounded_signature_boc_size(&virtualized, &Budget::ample()).is_err());
    assert!(crate::write_boc(&virtualized).is_err());
}
#[test]
fn bounded_proof_boc_measurement_width_shared_and_exotic_graphs() {
    let small = unique_balanced_graph(128, 8); // 128 leaves +127 branches =255.
    let bytes = crate::write_boc(&small).unwrap();
    assert_eq!(bytes[4] & 7, 1);
    assert_eq!(bytes[6], 255);
    assert_measured_boc(&small);
    let mut outer = BuilderData::new();
    outer.checked_append_reference(small.clone()).unwrap();
    let wide = outer.into_cell().unwrap();
    let bytes = crate::write_boc(&wide).unwrap();
    assert_eq!(bytes[4] & 7, 2);
    assert_eq!(&bytes[6..8], &[1, 0]);
    assert_measured_boc(&wide);
    let mut shared = BuilderData::new();
    for _ in 0..4 {
        shared.checked_append_reference(wide.clone()).unwrap();
    }
    assert_measured_boc(&shared.into_cell().unwrap());
    let pruned =
        crate::MerkleUpdate::make_pruned_branch_cell(&small, 0).unwrap().into_cell().unwrap();
    assert_eq!(pruned.cell_type(), CellType::PrunedBranch);
    assert_measured_boc(&pruned);
    let proof = crate::MerkleProof::create(&small, |id| id == &small.repr_hash())
        .unwrap()
        .serialize()
        .unwrap();
    assert_eq!(proof.cell_type(), CellType::MerkleProof);
    assert_measured_boc(&proof);
    // Explicit stored hashes are stripped by BocWriter::None. They must not
    // accidentally inflate the bounded measurement or change its identity.
    let leaf = unique_balanced_graph(1, 8);
    let raw = leaf.raw_data().unwrap();
    let mut stored = vec![raw[0] | 0x10, raw[1]];
    for hash in leaf.hashes() {
        stored.extend_from_slice(hash.as_slice());
    }
    for depth in leaf.depths() {
        stored.extend_from_slice(&depth.to_be_bytes());
    }
    stored.extend_from_slice(crate::cell::cell_data(raw));
    let with_hashes = Cell::with_data_and_refs(&stored, true, &[], None, None).unwrap();
    assert!(crate::cell::store_hashes(with_hashes.raw_data().unwrap()));
    assert_eq!(with_hashes.repr_hash(), leaf.repr_hash());
    assert_eq!(assert_measured_boc(&with_hashes), assert_measured_boc(&leaf));
}
#[test]
fn bounded_proof_boc_measurement_one_mib_exact_and_both_sides() {
    // Depth~13, not a deep chain. All127-byte leaves differ in their prefix,
    // so no byte/hash dedup hides the limit. Each leaf adds135 serialized bytes.
    let graph = unique_balanced_graph(7767, 127);
    let base = assert_measured_boc(&graph);
    let padding = PQ_SIGNATURE_BOC_MAX_BYTES - base;
    assert!(padding > 0 && padding < 127);
    for extra in [padding - 1, padding, padding + 1] {
        let mut root = SliceData::load_cell_ref(&graph).unwrap().as_builder().unwrap();
        root.append_raw(&vec![0x77; extra], extra * 8).unwrap();
        let root = root.into_cell().unwrap();
        let real = crate::write_boc(&root).unwrap().len();
        assert_eq!(real, base + extra);
        let bounded = bounded_signature_boc_size(&root, &Budget::ample());
        if real <= PQ_SIGNATURE_BOC_MAX_BYTES {
            assert_eq!(bounded.unwrap(), real);
        } else {
            assert_eq!(
                pq_block_signature_reason_code(&bounded.unwrap_err()),
                Some(PqBlockSignatureReasonCode::CarrierOversize)
            );
        }
    }
}
#[test]
fn bounded_proof_canonical_four_hundred_signers_without_chunk_dedup() {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/pq-block-signature-vectors.txt"
    ))
    .unwrap();
    let row: Vec<_> =
        text.lines().find(|line| line.starts_with("valid-1\t")).unwrap().split('\t').collect();
    let root = read_single_root_boc(&hex::decode(row[4]).unwrap()).unwrap();
    let mut carrier = BlockSignaturesSimplexPq::construct_bounded(root, &Budget::ample()).unwrap();
    carrier.signatures.clear();
    carrier.sig_count = 400;
    carrier.sig_weight = 400;
    for signer in 0u32..400 {
        let mut signature = vec![0x39; PQ_SIGNATURE_BYTES];
        for (chunk_index, chunk) in signature.chunks_mut(127).enumerate() {
            // Even the last partial chunk is long enough for both coordinates.
            chunk[..4].copy_from_slice(&signer.to_be_bytes());
            chunk[4..6].copy_from_slice(&(chunk_index as u16).to_be_bytes());
        }
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&(signer + 1).to_be_bytes());
        carrier.signatures.push(PqBlockSignaturePair {
            validator_id: UInt256::from(id),
            algorithm_id: MLDSA44_ALGORITHM_ID,
            signature,
        });
    }
    carrier.validate_structure_bounded(&Budget::ample()).unwrap();
    let root = carrier.serialize().unwrap();
    let actual = assert_measured_boc(&root);
    assert!(actual > 1_000_000, "unexpected signature chunk dedup: {actual}");
    assert!(actual <= 1_024_568, "canonical bound violated: {actual}");
    assert_eq!(
        BlockSignaturesSimplexPq::construct_bounded(root, &Budget::ample()).unwrap(),
        carrier
    );
    // Structural-only fixture: these bytes are not claimed to be PQ signatures.
}
