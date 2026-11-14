// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use rtos_api::{
    pq_finality::{
        ExplicitFinalityBlock, ExplicitPqFinalityContext, ExplicitPqSignatureSet, FinalityRefusal,
    },
    proof_link::{verify_key_block_proof_link, ProofLinkInfo, ProofLinkRefusal},
};
use rtos_block::*;
use serde_json::Value;

fn context(name: &str) -> Value {
    let mut context =
        include_str!("data/conformance/consensus/fixtures/proof-link-boundaries.jsonl")
            .lines()
            .chain(
                include_str!(
                    "data/conformance/consensus/fixtures/proof-validator-boundaries.jsonl"
                )
                .lines(),
            )
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .find(|row| row["metadata"]["fixture_id"] == name)
            .unwrap()["context"]
            .clone();
    if ["key_block_proof", "block_proof"].iter().any(|name| context[name].is_object()) {
        let blobs: Value = serde_json::from_str(include_str!(
            "data/conformance/consensus/fixtures/proof-validator-boundaries.blobs.json"
        ))
        .unwrap();
        for name in ["key_block_proof", "block_proof"] {
            if let Some(key) = context[name].get("blob").and_then(Value::as_str) {
                context[name] = blobs[key].clone();
            }
        }
    }
    context
}
fn block(value: &Value) -> ExplicitFinalityBlock {
    ExplicitFinalityBlock {
        workchain: value["workchain"].as_i64().unwrap() as i32,
        shard: u64::from_str_radix(value["shard"].as_str().unwrap(), 16).unwrap(),
        seqno: value["seqno"].as_u64().unwrap() as u32,
        root_hash: value["root_hash"].as_str().unwrap().parse().unwrap(),
        file_hash: value["file_hash"].as_str().unwrap().parse().unwrap(),
    }
}
fn envelope(ctx: &Value, field: &str) -> BlockProofEnvelope {
    BlockProofEnvelope::construct_from_full_cell(
        read_single_root_boc(base64_decode(ctx[field].as_str().unwrap()).unwrap()).unwrap(),
    )
    .unwrap()
}
fn verify(ctx: &Value) -> Result<ProofLinkInfo> {
    let source = envelope(ctx, "key_block_proof");
    let destination = envelope(ctx, "block_proof");
    let certificate = destination
        .signatures
        .clone()
        .map(BlockSignaturesVariant::construct_from_full_cell)
        .transpose()?;
    verify_key_block_proof_link(
        &block(&ctx["key_block"]),
        &block(&ctx["block"]),
        ctx["is_key"].as_bool().unwrap(),
        &source,
        &destination,
        certificate.as_ref(),
    )
}

#[test]
fn selected_validator_set_pruning_keeps_the_availability_error() {
    for name in ["proof_link-prefer35-pruned97", "proof_link-without35-pruned89"] {
        let error = verify(&context(name)).unwrap_err();
        assert_eq!(error.downcast_ref::<ProofLinkRefusal>().unwrap().0, "proof_malformed");
    }
}

#[test]
fn unused_pruned_validator_fallback_stays_opaque() {
    assert!(verify(&context("proof_link-prefer35-pruned89")).unwrap().verified_weight > 0);
}

#[test]
fn proof_member_count_is_independent_of_the_explicit_context_limit() {
    for name in ["governing-1024", "governing-1025"] {
        let error = verify(&context(name)).unwrap_err();
        assert_eq!(error.downcast_ref::<FinalityRefusal>().unwrap().0, "session_mismatch");
    }
    let ctx = context("governing-1025");
    let source = envelope(&ctx, "key_block_proof");
    let cfg = Block::construct_from_full_cell(source.virtual_root().unwrap())
        .unwrap()
        .read_key_block_config()
        .unwrap();
    let set = cfg.validator_set().unwrap();
    assert_eq!(set.total(), 1025);
    assert!(ExplicitPqFinalityContext::new(
        set.list().to_vec(),
        0,
        block(&ctx["block"]),
        UInt256::default()
    )
    .is_err());
}

#[test]
fn missing_validator_set_is_a_configuration_failure() {
    let error = verify(&context("missing-current-validator-set")).unwrap_err();
    assert_eq!(error.downcast_ref::<ProofLinkRefusal>().unwrap().0, "config_unavailable");
}

#[test]
fn forward_link_checks_verified_weight_without_applying_final_claim_policy() {
    let ctx = context("declared-weight-ignored");
    let linked = verify(&ctx).unwrap();
    assert!(linked.verified_weight > 0);
    let source = envelope(&ctx, "key_block_proof");
    let destination = envelope(&ctx, "block_proof");
    let (target, info) =
        check_block_header(&destination.virtual_root().unwrap(), &destination.proof_for).unwrap();
    let _ = target;
    let source = Block::construct_from_full_cell(source.virtual_root().unwrap()).unwrap();
    let cfg = source.read_key_block_config().unwrap();
    let (nodes, _) = cfg
        .validator_set()
        .unwrap()
        .calc_subset(
            &cfg.legacy_proof_catchain_config().unwrap(),
            SHARD_FULL,
            -1,
            info.gen_catchain_seqno(),
        )
        .unwrap();
    let BlockSignaturesVariant::SimplexPq(value) =
        BlockSignaturesVariant::construct_from_full_cell(destination.signatures.unwrap()).unwrap()
    else {
        unreachable!()
    };
    assert_eq!(value.sig_weight, 0);
    let candidate = value.candidate_bytes().unwrap();
    let evidence = ExplicitPqSignatureSet::new(
        value.validator_info,
        value.session_id,
        value.slot,
        candidate,
        value.signatures,
        true,
    )
    .unwrap();
    let verifier = ExplicitPqFinalityContext::new(
        nodes,
        info.gen_catchain_seqno(),
        block(&ctx["block"]),
        linked.expected_session_id,
    )
    .unwrap();
    let error = verifier.verify(&evidence, true, Some(0)).unwrap_err();
    assert_eq!(error.downcast_ref::<FinalityRefusal>().unwrap().0, "claimed_weight_mismatch");
}

#[test]
fn zerostate_anchor_uses_state_config_and_the_real_destination_certificate() {
    let ctx = context("zerostate-anchor");
    assert_eq!(ctx["key_block"]["seqno"], 0);
    let root = envelope(&ctx, "key_block_proof").virtual_root().unwrap();
    let (global, cfg) = read_zerostate_proof_config(root).unwrap();
    assert_ne!(global, 0);
    assert!(!cfg.validator_set().unwrap().list().is_empty());
    let linked = verify(&ctx).unwrap();
    assert!(linked.verified_weight > 0 && linked.gen_utime > 0);
}

#[test]
fn legacy_certificates_do_not_read_pruned_pq_config() {
    for name in ["classical-ordinary", "classical-simplex"] {
        let ctx = context(name);
        let source = Block::construct_from_full_cell(
            envelope(&ctx, "key_block_proof").virtual_root().unwrap(),
        )
        .unwrap();
        assert!(source.read_key_block_config().unwrap().proof_config_param_cell(30).is_err());
        let linked = verify(&ctx).unwrap();
        assert_eq!(linked.expected_session_id, UInt256::default());
        assert_eq!((linked.verified_weight, linked.total_weight), (1, 1));
    }
}

#[test]
fn missing_certificate_precedes_bad_merkle_root() {
    let ctx = context("missing-before-bad-root");
    assert!(envelope(&ctx, "key_block_proof").virtual_root().is_err());
    let error = verify(&ctx).unwrap_err();
    assert_eq!(error.downcast_ref::<ProofLinkRefusal>().unwrap().0, "proof_incomplete");
}

#[test]
fn legacy_signature_failure_retains_its_native_cause() {
    let error = verify(&context("classical-invalid")).unwrap_err();
    assert!(matches!(error.downcast_ref::<BlockError>(), Some(BlockError::BadSignature)));
}
