// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use rtos_api::{
    pq_finality::PqVerificationContext,
    session_identity::{derive_session_from_options, ExplicitSessionOptions, SessionCoordinates},
};
use rtos_block::*;

fn context(name: &str) -> serde_json::Value {
    include_str!("data/conformance/consensus/fixtures/proof-config-profiles.jsonl")
        .lines()
        .chain(
            include_str!("data/conformance/consensus/fixtures/pruned-config-paths.jsonl").lines(),
        )
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|row| row["metadata"]["fixture_id"] == name)
        .unwrap()["context"]
        .clone()
}
fn block(context: &serde_json::Value, field: &str) -> (Block, BlockInfo) {
    let cell =
        read_single_root_boc(base64_decode(context[field].as_str().unwrap()).unwrap()).unwrap();
    let proof = BlockProofEnvelope::construct_from_full_cell(cell).unwrap();
    check_block_header(&proof.virtual_root().unwrap(), &proof.proof_for).unwrap()
}
fn config(block: &Block) -> ConfigParams {
    let extra = BlockExtra::construct_from_full_cell(block.extra_cell()).unwrap();
    McBlockExtra::config_from_key_block_cell(extra.custom_cell().unwrap()).unwrap()
}

#[test]
fn structural_header_does_not_validate_nested_software_constructor() {
    let ctx = context("decode_proof-block_proof-headerbit-536");
    let (block, info) = block(&ctx, "block_proof");
    assert!(info.gen_software().is_some());
    assert!(BlockInfo::construct_from_cell(block.info_cell()).is_err());
}

#[test]
fn optional_legacy_proof_config_falls_back_without_weakening_strict_accessors() {
    for name in [
        "key-config-cell72-bit0",
        "key-config-cell72-bit14",
        "key-config-cell73-bit0",
        "missing-legacy-config-0",
        "missing-legacy-config-1",
    ] {
        let ctx = context(name);
        let cfg = config(&block(&ctx, "key_block_proof").0);
        let (catchain, consensus) = cfg.legacy_proof_consensus_parameters().unwrap();
        if cfg.catchain_config().is_err() || name == "key-config-cell72-bit14" {
            assert_eq!(catchain.mc_catchain_lifetime, 200);
            assert!(!catchain.isolate_mc_validators);
        }
        if cfg.consensus_config().is_err() {
            assert_eq!(consensus.round_candidates, 3);
            assert_eq!(consensus.consensus_timeout_ms, 16000);
            assert!(!consensus.new_catchain_ids);
        }
    }
}

#[test]
fn key_config_rejects_auxiliary_trailing_data() {
    let ctx = context("key-mcextra-cell19-bit4");
    let block = block(&ctx, "key_block_proof").0;
    let extra = BlockExtra::construct_from_full_cell(block.extra_cell()).unwrap();
    let cell = extra.custom_cell().unwrap();
    assert!(McBlockExtra::construct_from_cell(cell.clone()).is_ok());
    assert!(McBlockExtra::config_from_key_block_cell(cell).is_err());
}

#[test]
fn unavailable_proof_parameters_are_not_default_configuration() {
    let mut pruned = BuilderData::new();
    pruned.set_type(CellType::PrunedBranch);
    pruned.append_u8(1).unwrap().append_u8(1).unwrap();
    pruned.append_raw(&[0; 32], 256).unwrap().append_u16(0).unwrap();
    let cell = pruned.into_cell().unwrap();
    for index in [28u32, 29] {
        let mut cfg = ConfigParams::default();
        let mut value = BuilderData::new();
        value.checked_append_reference(cell.clone()).unwrap();
        cfg.config_params.set_builder(index.write_to_bitstring().unwrap(), &value).unwrap();
        assert!(cfg.legacy_proof_consensus_parameters().is_err());
    }
}

#[test]
fn metadata_and_dictionary_paths_preserve_unavailable_proof_cells() {
    let ctx = context("pruned-65");
    let cfg = config(&block(&ctx, "key_block_proof").0);
    let error = cfg.proof_config_param_cell(19).unwrap_err();
    assert!(matches!(error.downcast_ref::<BlockError>(), Some(BlockError::PrunedCellAccess(_))));
    // A pruned dictionary edge is unavailable, rather than an absent parameter.
    let ctx = context("pruned-57");
    let cfg = config(&block(&ctx, "key_block_proof").0);
    let error = cfg.proof_config_param_cell(19).unwrap_err();
    assert_eq!(error.downcast_ref::<ExceptionCode>(), Some(&ExceptionCode::PrunedCellAccess));
}

/// Input-only exporter; all effects must be filled with clean pinned C++.
#[test]
#[ignore]
fn export_unavailable_config_contexts() {
    let source = context("header-config-global-id-differ");
    let mut rows = Vec::new();
    for index in [28u32, 29] {
        let mut ctx = source.clone();
        let cell =
            read_single_root_boc(base64_decode(ctx["key_block_proof"].as_str().unwrap()).unwrap())
                .unwrap();
        let mut envelope = BlockProofEnvelope::construct_from_full_cell(cell).unwrap();
        let raw = MerkleProof::construct_from_full_cell(envelope.root).unwrap().proof;
        let mut block = Block::construct_from_cell(raw).unwrap();
        let mut extra = block.read_extra().unwrap();
        let mut custom = extra.read_custom().unwrap().unwrap();
        let mut cfg = custom.config().unwrap().clone();
        let original = cfg
            .config_params
            .get(index.write_to_bitstring().unwrap())
            .unwrap()
            .unwrap()
            .reference(0)
            .unwrap();
        let mut pruned = BuilderData::new();
        pruned.set_type(CellType::PrunedBranch);
        pruned.append_u8(1).unwrap().append_u8(1).unwrap();
        pruned
            .append_raw(original.hash(0).as_slice(), 256)
            .unwrap()
            .append_u16(original.depth(0))
            .unwrap();
        let mut value = BuilderData::new();
        value.checked_append_reference(pruned.into_cell().unwrap()).unwrap();
        cfg.config_params.set_builder(index.write_to_bitstring().unwrap(), &value).unwrap();
        custom.set_config(cfg);
        extra.write_custom(&custom).unwrap();
        block.write_extra(&extra).unwrap();
        let root = block.serialize().unwrap();
        envelope.proof_for.root_hash = root.hash(0).clone();
        envelope.root =
            MerkleProof { hash: root.hash(0).clone(), depth: root.depth(0), proof: root }
                .serialize()
                .unwrap();
        ctx["key_block"]["root_hash"] =
            serde_json::json!(hex::encode_upper(envelope.proof_for.root_hash.as_slice()));
        ctx["key_block_proof"] =
            serde_json::json!(base64_encode(write_boc(&envelope.serialize().unwrap()).unwrap()));
        rows.push(serde_json::json!({"fixture_id":format!("pruned-param-{index}"),"context":ctx}));
    }
    std::fs::write(
        std::env::var("RTOS_PRUNED_CONFIG_CONTEXTS_OUT").unwrap(),
        rows.into_iter().map(|r| serde_json::to_string(&r).unwrap() + "\n").collect::<String>(),
    )
    .unwrap();
}

#[test]
fn structural_session_derivation_does_not_bypass_production_global_id_admission() {
    let ctx = context("header-config-global-id-differ");
    let governing = block(&ctx, "key_block_proof").0;
    let (_, info) = block(&ctx, "block_proof");
    let cfg = config(&governing);
    let (catchain, consensus) = cfg.legacy_proof_consensus_parameters().unwrap();
    let (validators, _) = cfg
        .validator_set()
        .unwrap()
        .calc_subset(&catchain, SHARD_FULL, MASTERCHAIN_ID, info.gen_catchain_seqno())
        .unwrap();
    let id = BlockIdExt::with_params(
        info.shard().clone(),
        info.seq_no(),
        ctx["block"]["root_hash"].as_str().unwrap().parse().unwrap(),
        UInt256::default(),
    );
    let selected = cfg.selected_simplex_config(true).unwrap().unwrap();
    derive_session_from_options(
        governing.global_id(),
        &ExplicitSessionOptions::from_config(&consensus, &catchain),
        &selected,
        SessionCoordinates {
            shard: id.shard(),
            catchain_seqno: info.gen_catchain_seqno(),
            vertical_seqno: info.vert_seq_no(),
            last_key_block_seqno: info.prev_key_block_seqno(),
            new_catchain_ids: consensus.new_catchain_ids,
        },
        &validators,
    )
    .unwrap();
    let error = PqVerificationContext::from_governing_config(
        governing.global_id(),
        &cfg,
        id,
        info.vert_seq_no(),
        info.prev_key_block_seqno(),
        info.gen_catchain_seqno(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("Param19"));
}
