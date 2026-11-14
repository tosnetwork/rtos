// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Two-envelope proof links relative to a caller-supplied masterchain anchor.
//! This verifies linkage, not block execution or the provenance of that anchor.
use crate::{
    pq_finality::{
        build_simplex_vote_data, ExplicitFinalityBlock, ExplicitPqFinalityContext,
        ExplicitPqSignatureSet,
    },
    session_identity::{derive_session_from_options, ExplicitSessionOptions, SessionCoordinates},
};
use rtos_block::{
    Block, BlockError, BlockIdExt, BlockProofEnvelope, BlockSignaturesVariant, ExceptionCode,
    Result, ShardIdent, UInt256, ValidatorKey,
};

#[derive(Debug)]
pub struct ProofLinkRefusal(pub &'static str);
impl std::fmt::Display for ProofLinkRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ProofLinkRefusal {}
fn reject(reason: &'static str) -> anyhow::Error {
    ProofLinkRefusal(reason).into()
}
fn classify(error: anyhow::Error, fallback: &'static str) -> anyhow::Error {
    if let Some(value) = error.downcast_ref::<rtos_block::ConfigParamReferenceError>() {
        return reject(if matches!(value.0, 34 | 35) {
            "config_unavailable"
        } else {
            "unclassified"
        });
    }
    if matches!(error.downcast_ref::<BlockError>(), Some(BlockError::PrunedCellAccess(_)))
        || matches!(error.downcast_ref::<ExceptionCode>(), Some(ExceptionCode::PrunedCellAccess))
    {
        reject("proof_malformed")
    } else {
        reject(fallback)
    }
}
fn id(value: &ExplicitFinalityBlock) -> BlockIdExt {
    BlockIdExt::with_params(
        ShardIdent::masterchain(),
        value.seqno,
        value.root_hash.clone(),
        value.file_hash.clone(),
    )
}

#[derive(Debug)]
pub struct ProofLinkInfo {
    pub gen_utime: u32,
    pub expected_session_id: UInt256,
    pub verified_weight: u64,
    pub total_weight: u64,
}

/// The input has no source-state proof. A backward link is therefore incomplete,
/// as in the corresponding C++ two-envelope harness. Decoded certificate fields
/// are separate from the two Merkle roots, just as BlockProofLink::sig_set is.
pub fn verify_key_block_proof_link(
    from: &ExplicitFinalityBlock,
    to: &ExplicitFinalityBlock,
    is_key: bool,
    source: &BlockProofEnvelope,
    destination: &BlockProofEnvelope,
    certificate: Option<&BlockSignaturesVariant>,
) -> Result<ProofLinkInfo> {
    if from.workchain != -1
        || to.workchain != -1
        || from.shard != rtos_block::SHARD_FULL
        || to.shard != rtos_block::SHARD_FULL
        || from.seqno == to.seqno
    {
        return Err(reject("link_direction"));
    }
    if from.seqno > to.seqno {
        return Err(reject("proof_incomplete"));
    }
    let certificate = certificate.ok_or_else(|| reject("proof_incomplete"))?;
    let root = source.virtual_root().map_err(|e| classify(e, "proof_malformed"))?;
    let source_block = if from.seqno != 0 {
        Some(
            rtos_block::check_block_header(&root, &id(from))
                .map_err(|e| classify(e, "header_mismatch"))?
                .0,
        )
    } else {
        if root.repr_hash() != &from.root_hash {
            return Err(reject("header_mismatch"));
        }
        None
    };
    let target = destination.virtual_root().map_err(|e| classify(e, "proof_malformed"))?;
    let (_, info) = rtos_block::check_block_header(&target, &id(to))
        .map_err(|e| classify(e, "header_mismatch"))?;
    if info.key_block() != is_key {
        return Err(reject("key_block_flag_mismatch"));
    }
    let (global_id, config) = match source_block {
        Some(block) => (
            block.global_id(),
            block.read_key_block_config().map_err(|e| classify(e, "config_unavailable"))?,
        ),
        None => rtos_block::read_zerostate_proof_config(root)
            .map_err(|e| classify(e, "config_unavailable"))?,
    };
    // Load only the fields reached at this stage. Param29/30 availability must
    // not preempt the header validator-set hash check or a legacy certificate.
    let set = config.proof_validator_set().map_err(|e| classify(e, "config_unavailable"))?;
    let catchain =
        config.legacy_proof_catchain_config().map_err(|e| classify(e, "config_unavailable"))?;
    let (nodes, hash) = set
        .calc_subset(&catchain, rtos_block::SHARD_FULL, -1, info.gen_catchain_seqno())
        .map_err(|e| classify(e, "no_validator_set"))?;
    if nodes.is_empty() {
        return Err(reject("no_validator_set"));
    }
    if hash != info.gen_validator_list_hash_short() {
        return Err(reject("validator_set_hash_mismatch"));
    }
    let total_weight = rtos_block::checked_validator_weight_sum(nodes.iter().map(|v| v.weight))?;
    let mut expected_session_id = UInt256::default();
    let verified_weight = if let BlockSignaturesVariant::SimplexPq(value) = certificate {
        config
            .proof_config_param_cell(30)
            .map_err(|e| classify(e, "consensus_config_unavailable"))?;
        let selected = config
            .selected_simplex_proof_config(true)
            .map_err(|e| classify(e, "consensus_config_unavailable"))?
            .ok_or_else(|| reject("consensus_config_unavailable"))?;
        selected
            .config
            .validate_protocol_version()
            .map_err(|e| classify(e, "consensus_config_unavailable"))?;
        let consensus = config
            .legacy_proof_session_config()
            .map_err(|e| classify(e, "consensus_config_unavailable"))?;
        let identity = derive_session_from_options(
            global_id,
            &ExplicitSessionOptions::from_config(&consensus, &catchain),
            &selected,
            SessionCoordinates {
                shard: id(to).shard(),
                catchain_seqno: info.gen_catchain_seqno(),
                vertical_seqno: info.vert_seq_no(),
                last_key_block_seqno: info.prev_key_block_seqno(),
                new_catchain_ids: consensus.new_catchain_ids,
            },
            &nodes,
        )?;
        expected_session_id = identity.session_id;
        let context = ExplicitPqFinalityContext::for_proof_link(
            nodes,
            info.gen_catchain_seqno(),
            to.clone(),
            expected_session_id.clone(),
        )?;
        let set = ExplicitPqSignatureSet::new(
            value.validator_info.clone(),
            value.session_id.clone(),
            value.slot,
            value.candidate_bytes()?,
            value.signatures.clone(),
            true,
        )?;
        // C++ forward links verify the computed weight but do not compare the
        // envelope's declared weight (unlike verify_pq_proof_signatures).
        context.verify(&set, true, None)?
    } else {
        if nodes.iter().any(|v| matches!(v.key, ValidatorKey::Pq(_))) {
            return Err(reject("carrier_mismatch"));
        }
        if matches!(certificate, BlockSignaturesVariant::Simplex(value) if !value.is_final()) {
            return Err(reject("role_mismatch"));
        }
        if certificate.validator_info().catchain_seqno != info.gen_catchain_seqno() {
            return Err(reject("catchain_seqno_mismatch"));
        }
        if certificate.validator_info().validator_list_hash_short != hash {
            return Err(reject("validator_set_hash_mismatch"));
        }
        let message = match certificate {
            BlockSignaturesVariant::Ordinary(_) => {
                Block::build_data_for_sign(&to.root_hash, &to.file_hash).to_vec()
            }
            BlockSignaturesVariant::Simplex(value) => {
                let vote = build_simplex_vote_data(
                    &value.session_id,
                    value.slot,
                    &value.candidate_data_bytes()?,
                    true,
                )
                .map_err(|_| reject("candidate_malformed"))?;
                if (vote.workchain, vote.shard, vote.seqno) != (to.workchain, to.shard, to.seqno)
                    || vote.root_hash != to.root_hash
                    || vote.file_hash != to.file_hash
                {
                    return Err(reject("block_mismatch"));
                }
                vote.data_to_sign
            }
            _ => unreachable!(),
        };
        let weight =
            certificate.pure_signatures()?.check_signatures(&nodes, &message).map_err(|e| {
                match e.downcast_ref::<BlockError>() {
                    Some(BlockError::BadSignature) => e,
                    Some(BlockError::DuplicatedSignature) => reject("duplicate_signer"),
                    _ => classify(e, "unknown_signer"),
                }
            })?;
        if !rtos_block::quorum_weight_reached(weight, total_weight) {
            return Err(reject("insufficient_weight"));
        }
        weight
    };
    Ok(ProofLinkInfo {
        gen_utime: info.gen_utime(),
        expected_session_id,
        verified_weight,
        total_weight,
    })
}
