// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::{bits, bytes, decimal, shard, u32_field, validators};
use anyhow::{ensure, Context, Result};
use rtos_api::pq_finality::{
    ExplicitFinalityBlock, ExplicitPqFinalityContext, ExplicitPqSignatureSet, FinalityRefusal,
};
use rtos_block::{
    BlockProofEnvelope, BlockSignaturesVariant, Deserializable, PqBlockSignaturePair,
    ValidatorBaseInfo,
};
use serde_json::{json, Value};

fn domain(reason: &'static str) -> anyhow::Error {
    super::proofs::ProofRefusal(reason).into()
}
pub(super) fn run(ctx: &Value) -> Result<Value> {
    run_inner(ctx).map_err(|e| {
        if let Some(reason) = e.downcast_ref::<FinalityRefusal>() {
            domain(reason.0)
        } else if rtos_block::pq_block_signature_reason_code(&e).is_some() {
            domain(super::proofs::signature_error(&e))
        } else {
            e
        }
    })
}
fn run_inner(ctx: &Value) -> Result<Value> {
    let validators = validators(ctx)?;
    let catchain_seqno = u32_field(ctx, "catchain_seqno")?;
    let block = &ctx["block"];
    let (workchain, shard) = shard(block)?;
    let block = ExplicitFinalityBlock {
        workchain,
        shard,
        seqno: u32_field(block, "seqno")?,
        root_hash: bits(&block["root_hash"])?,
        file_hash: bits(&block["file_hash"])?,
    };
    let session = bits(&ctx["expected_session_id"])?;
    let is_final = match ctx["role"].as_str() {
        Some("final") => true,
        Some("approve") => false,
        _ => anyhow::bail!("role must be final or approve"),
    };
    ensure!(
        ctx.get("block_proof").is_some() != ctx.get("signature_set").is_some(),
        "exactly one of block_proof and signature_set required"
    );
    let context = ExplicitPqFinalityContext::new(validators, catchain_seqno, block, session)?;
    let (set, claim) = if let Some(proof) = ctx.get("block_proof") {
        let cell = rtos_block::read_single_root_boc(rtos_block::base64_decode(
            proof.as_str().context("proof BOC required")?,
        )?)?;
        let envelope = BlockProofEnvelope::construct_from_full_cell(cell)
            .map_err(|_| domain("carrier_malformed"))?;
        // Like the C++ finality operation, this reads only the envelope's
        // certificate. Header/root authentication belongs to proof-link checks.
        let cell = envelope.signatures.ok_or_else(|| domain("proof_incomplete"))?;
        let value = BlockSignaturesVariant::construct_from_full_cell(cell)
            .map_err(|e| domain(super::proofs::signature_error(&e)))?;
        let BlockSignaturesVariant::SimplexPq(value) = value else {
            return Err(domain("carrier_mismatch"));
        };
        let candidate = value.candidate_bytes()?;
        let set = ExplicitPqSignatureSet::new(
            value.validator_info,
            value.session_id,
            value.slot,
            candidate,
            value.signatures,
            true,
        )?;
        (set, Some(value.sig_weight))
    } else {
        let value = &ctx["signature_set"];
        let catchain_seqno = u32_field(value, "catchain_seqno")?;
        let hash = u32_field(value, "validator_set_hash")?;
        let session = bits(&value["session_id"])?;
        let slot = u32_field(value, "slot")?;
        let candidate = bytes(&value["candidate"])?;
        let entries = value["signatures"].as_array().context("signatures required")?;
        ensure!(entries.len() <= 1024, "at most 1024 signatures");
        let mut signatures = Vec::with_capacity(entries.len());
        for entry in entries {
            signatures.push(PqBlockSignaturePair {
                validator_id: bits(&entry["validator_id"])?,
                algorithm_id: u32_field(entry, "algorithm_id")?.try_into()?,
                signature: bytes(&entry["signature"])?,
            });
        }
        let set = ExplicitPqSignatureSet::new(
            ValidatorBaseInfo::with_params(hash, catchain_seqno),
            session,
            slot,
            candidate,
            signatures,
            is_final,
        )?;
        let claim = ctx.get("claimed_weight").map(decimal).transpose()?;
        (set, claim)
    };
    let weight = context.verify(&set, is_final, claim)?;
    Ok(json!({"outcome":"finalized","weight":weight.to_string(),
        "total_weight":context.total_weight().to_string(),
        "threshold":rtos_block::quorum_threshold(context.total_weight()).to_string()}))
}
