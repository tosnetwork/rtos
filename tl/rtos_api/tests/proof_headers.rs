// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use rtos_block::{
    base64_decode, check_block_header, read_single_root_boc, Block, BlockInfo, BlockProofEnvelope,
    Deserializable,
};

fn proof(name: &str) -> BlockProofEnvelope {
    let bytes = proof_bytes(name);
    BlockProofEnvelope::construct_from_full_cell(read_single_root_boc(bytes).unwrap()).unwrap()
}
fn proof_bytes(name: &str) -> Vec<u8> {
    include_str!("data/conformance/consensus/fixtures/proof-header-boundaries.jsonl")
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|row| row["metadata"]["fixture_id"] == name)
        .map(|row| base64_decode(row["context"]["block_proof"].as_str().unwrap()).unwrap())
        .expect("C++ proof control must exist")
}

#[test]
fn header_metadata_defers_previous_block_reads() {
    let proof = proof("header-pruned-references");
    let root = proof.virtual_root().unwrap();
    let (_, info) = check_block_header(&root, &proof.proof_for).unwrap();
    assert_eq!(info.seq_no(), proof.proof_for.seq_no());
    assert!(info.read_prev_ref().is_err());
    // The existing complete reader still requires those referenced cells.
    let block = Block::construct_from_cell(root).unwrap();
    assert!(BlockInfo::construct_from_cell(block.info_cell()).is_err());
}

#[test]
fn proof_unpack_rejects_oversized_shard_depths() {
    for depth in [61, 62, 63] {
        let bytes = proof_bytes(&format!("envelope-depth-{depth}"));
        assert!(BlockProofEnvelope::construct_from_full_cell(read_single_root_boc(bytes).unwrap())
            .is_err());
    }
}

#[test]
fn header_shape_rejects_reserved_and_trailing_fields() {
    for name in ["header-info-trailing-bit", "header-reserved-flag", "header-shard-low-prefix"] {
        let proof = proof(name);
        assert!(check_block_header(&proof.virtual_root().unwrap(), &proof.proof_for).is_err());
    }
}

#[test]
fn proof_envelope_checks_its_own_shape() {
    for name in ["envelope-trailing-bit", "envelope-low-prefix"] {
        assert!(BlockProofEnvelope::construct_from_full_cell(
            read_single_root_boc(proof_bytes(name)).unwrap()
        )
        .is_err());
    }
}

#[test]
fn incomplete_headers_keep_the_pruned_cell_error() {
    for name in ["pruned-block-root", "pruned-info-root"] {
        let proof = proof(name);
        let error =
            check_block_header(&proof.virtual_root().unwrap(), &proof.proof_for).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<rtos_block::BlockError>(),
            Some(rtos_block::BlockError::PrunedCellAccess(_))
        ));
    }
}
