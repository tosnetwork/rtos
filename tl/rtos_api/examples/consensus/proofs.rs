// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Native governing-proof adapters. Supplied key blocks are explicit test anchors.
use super::{bits, shard, signature_json, u32_field, ExplicitSessionOptions};
use anyhow::{ensure, Context, Result};
use rtos_api::session_identity::{
    derive_session_from_options, derive_session_identity, SessionCoordinates,
};
use rtos_block::{
    BlockIdExt, BlockProofEnvelope, BlockSignaturesVariant, ConfigParamEnum, Deserializable,
    ShardIdent, ValidatorDescr, ValidatorKey,
};
use serde_json::{json, Value};

#[derive(Debug)]
pub(super) struct ProofRefusal(pub &'static str);
impl std::fmt::Display for ProofRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ProofRefusal {}
fn domain_error(reason: &'static str) -> anyhow::Error {
    ProofRefusal(reason).into()
}
pub(super) fn proof_error(error: &anyhow::Error, fallback: &'static str) -> &'static str {
    if matches!(
        error.downcast_ref::<rtos_block::BlockError>(),
        Some(rtos_block::BlockError::PrunedCellAccess(_))
    ) {
        "proof_malformed"
    } else {
        fallback
    }
}
pub(super) fn signature_error(error: &anyhow::Error) -> &'static str {
    use rtos_block::PqBlockSignatureReasonCode::*;
    match rtos_block::pq_block_signature_reason_code(error) {
        Some(DuplicateValidatorId) => "duplicate_signer",
        Some(UnsupportedAlgorithm) => "unsupported_algorithm",
        Some(SignatureLength) => "signature_length",
        Some(SignerCount) => "too_many_signers",
        Some(CarrierOversize) => "carrier_oversize",
        Some(UnknownValidatorId) => "unknown_signer",
        Some(ValidatorAlgorithmMismatch) => "algorithm_mismatch",
        Some(WeightMismatch) => "claimed_weight_mismatch",
        // This helper classifies wire decoding, before validator/carrier policy.
        Some(UnsupportedCarrier) => "carrier_malformed",
        Some(
            CandidateOversize
            | CandidateNoncanonicalChunk
            | CandidateNonByteAligned
            | CandidateMultipleRefs
            | CandidateChainLength
            | CandidateTrailingRef
            | CandidateTl,
        ) => "candidate_malformed",
        _ => "carrier_malformed",
    }
}
fn block_id(value: &Value) -> Result<BlockIdExt> {
    let (workchain, shard) = shard(value)?;
    Ok(BlockIdExt::with_params(
        ShardIdent::with_tagged_prefix(workchain, shard)?,
        u32_field(value, "seqno")?,
        bits(&value["root_hash"])?,
        bits(&value["file_hash"])?,
    ))
}
fn read_proof(ctx: &Value, field: &str) -> Result<BlockProofEnvelope> {
    let bytes = rtos_block::base64_decode(ctx[field].as_str().context("proof BOC required")?)?;
    let root = rtos_block::read_single_root_boc(bytes)?;
    BlockProofEnvelope::construct_from_full_cell(root)
        .map_err(|_| domain_error("carrier_malformed"))
}
fn header(
    proof: &BlockProofEnvelope,
    id: &BlockIdExt,
) -> Result<(rtos_block::Block, rtos_block::BlockInfo)> {
    let root = proof.virtual_root().map_err(|_| domain_error("proof_malformed"))?;
    rtos_block::check_block_header(&root, id)
        .map_err(|e| domain_error(proof_error(&e, "header_mismatch")))
}
fn validator_json(value: &ValidatorDescr) -> Result<Value> {
    let mut result = json!({"weight":value.weight.to_string(),
        "adnl":hex::encode_upper(value.adnl_addr.clone().unwrap_or_default().as_slice())});
    match &value.key {
        ValidatorKey::Ed25519(key) => {
            result["ed25519"] = json!(hex::encode_upper(key.as_slice()));
        }
        ValidatorKey::Pq(key) => {
            result["validator_id"] = json!(hex::encode_upper(value.validator_id()?.as_slice()));
            result["key_id"] = json!(hex::encode_upper(key.key_id.as_slice()));
            result["algorithm_id"] = json!(key.algorithm_id);
            result["public_key"] = json!(hex::encode(&key.public_key));
        }
    }
    Ok(result)
}
pub(super) fn key_context(ctx: &Value) -> Result<Value> {
    let from = block_id(&ctx["key_block"])?;
    let to = block_id(&ctx["block"])?;
    ensure!(
        from.shard().is_masterchain()
            && from.shard().is_full()
            && to.shard().is_masterchain()
            && to.shard().is_full()
            && from.seq_no() != 0
            && to.seq_no() > from.seq_no(),
        "later masterchain block and nonzero key block required"
    );
    let key_proof = read_proof(ctx, "key_block_proof")?;
    let proof = read_proof(ctx, "block_proof")?;
    let (key_block, _) = header(&key_proof, &from)?;
    let (_, info) = header(&proof, &to)?;
    let extra = rtos_block::BlockExtra::construct_from_full_cell(key_block.extra_cell())
        .map_err(|_| domain_error("config_unavailable"))?;
    let custom = extra.custom_cell().ok_or_else(|| domain_error("config_unavailable"))?;
    let config = rtos_block::McBlockExtra::config_from_key_block_cell(custom)
        .map_err(|_| domain_error("config_unavailable"))?;
    let (catchain, consensus) = config
        .legacy_proof_consensus_parameters()
        .map_err(|e| domain_error(proof_error(&e, "config_unavailable")))?;
    let set = config.validator_set().map_err(|_| domain_error("config_unavailable"))?;
    let (validators, hash) = set
        .calc_subset(
            &catchain,
            to.shard().shard_prefix_with_tag(),
            to.shard().workchain_id(),
            info.gen_catchain_seqno(),
        )
        .map_err(|_| domain_error("no_validator_set"))?;
    if validators.is_empty() {
        return Err(domain_error("no_validator_set"));
    }
    let total = rtos_block::checked_validator_weight_sum(validators.iter().map(|v| v.weight))?;
    let options = ExplicitSessionOptions::from_config(&consensus, &catchain);
    let selected = config
        .selected_simplex_config(true)
        .map_err(|_| domain_error("consensus_config_unavailable"))?
        .ok_or_else(|| domain_error("consensus_config_unavailable"))?;
    let coordinates = SessionCoordinates {
        shard: to.shard(),
        catchain_seqno: info.gen_catchain_seqno(),
        vertical_seqno: info.vert_seq_no(),
        last_key_block_seqno: info.prev_key_block_seqno(),
        new_catchain_ids: options.new_catchain_ids,
    };
    let options_hash = rtos_block::UInt256::calc_file_hash(&options.bytes()?);
    let identity = derive_session_identity(
        key_block.global_id(),
        &options_hash,
        selected.cell(),
        coordinates,
        &validators,
    )?;
    let validator_identity = derive_session_from_options(
        key_block.global_id(),
        &options,
        &selected,
        coordinates,
        &validators,
    )
    .map_err(|_| domain_error("consensus_config_unavailable"))?;
    let config_global_id = match config.config(19)? {
        Some(ConfigParamEnum::ConfigParam19(v)) => Some(v as i32),
        _ => None,
    };
    let signatures = proof
        .signatures
        .map(BlockSignaturesVariant::construct_from_full_cell)
        .transpose()
        .map_err(|e| domain_error(signature_error(&e)))?;
    let signature_set = signatures.as_ref().map(signature_json).transpose()?.unwrap_or(Value::Null);
    let claimed = signatures.as_ref().map(|v| v.declared_signature_weight().to_string());
    let validators = validators.iter().map(validator_json).collect::<Result<Vec<_>>>()?;
    Ok(
        json!({"outcome":"context","global_id":key_block.global_id(),"config_global_id":config_global_id,
        "options":{"proto_version":options.proto_version,"new_catchain_ids":options.new_catchain_ids,
        "idle_timeout":options.idle_timeout,"max_deps":options.max_deps,"max_serialized_block_size":options.max_serialized_block_size,
        "block_hash_covers_data":options.block_hash_covers_data,"max_block_height_coeff":options.max_block_height_coeff,
        "debug_disable_db":options.debug_disable_db,"round_candidates":options.round_candidates,"next_candidate_delay":options.next_candidate_delay,
        "round_attempt_duration":options.round_attempt_duration,"max_round_attempts":options.max_round_attempts,
        "max_block_size":options.max_block_size,"max_collated_data_size":options.max_collated_data_size},
        "simplex_config_hash":hex::encode_upper(selected.cell_hash().as_slice()),"protocol_version":selected.config.protocol_version,
        "gen_utime":info.gen_utime(),"catchain_seqno":info.gen_catchain_seqno(),"vertical_seqno":info.vert_seq_no(),
        "prev_key_block_seqno":info.prev_key_block_seqno(),"is_key":info.key_block(),"header_validator_set_hash":info.gen_validator_list_hash_short(),
        "validator_set_hash":hash,"total_weight":total.to_string(),"validators":validators,
        "session_id":hex::encode_upper(identity.session_id.as_slice()),
        "validator_path_session_id":hex::encode_upper(validator_identity.session_id.as_slice()),
        "signature_set":signature_set,"claimed_weight":claimed}),
    )
}

#[cfg(test)]
mod exports {
    use super::*;
    use rtos_block::{
        Block, BuilderData, Cell, CellType, ChildCell, IBitstring, MerkleProof, Serializable,
    };

    fn proof_b64(proof: &BlockProofEnvelope) -> Result<String> {
        Ok(rtos_block::base64_encode(rtos_block::write_boc(&proof.serialize()?)?))
    }
    fn replace_block(proof: &mut BlockProofEnvelope, root: Cell) -> Result<()> {
        proof.proof_for.root_hash = root.hash(0).clone();
        proof.root = MerkleProof { hash: root.hash(0).clone(), depth: root.depth(0), proof: root }
            .serialize()?;
        Ok(())
    }
    fn append_bit(cell: &Cell) -> Result<Cell> {
        let mut builder = BuilderData::from_cell(cell)?;
        builder.append_bit_one()?;
        Ok(builder.into_cell()?)
    }
    fn pruned(cell: &Cell) -> Result<Cell> {
        let mut builder = BuilderData::new();
        builder.set_type(CellType::PrunedBranch);
        builder.append_u8(1)?.append_u8(1)?;
        builder.append_raw(cell.hash(0).as_slice(), 256)?.append_u16(cell.depth(0))?;
        Ok(builder.into_cell()?)
    }
    fn changed_byte(cell: &Cell, index: usize, value: u8) -> Result<Cell> {
        let mut data = cell.data().to_vec();
        data[index] = value;
        let mut builder = BuilderData::with_raw(data, cell.bit_length())?;
        for i in 0..cell.references_count() {
            builder.checked_append_reference(cell.reference(i)?)?;
        }
        Ok(builder.into_cell()?)
    }

    /// Export inputs only. Fill all effects with the clean pinned C++ CLI.
    #[test]
    #[ignore]
    fn export_structural_proof_contexts() -> Result<()> {
        let input = std::fs::read_to_string(std::env::var("RTOS_PROOF_CONTEXTS_IN")?)?;
        let contexts: Vec<Value> = serde_json::from_str(&input)?;
        let decoded = &contexts[0];
        let governing = &contexts[1];
        let original = read_proof(decoded, "block_proof")?;
        let root = MerkleProof::construct_from_full_cell(original.root.clone())?.proof;
        let block = Block::construct_from_cell(root.clone())?;
        let mut rows = Vec::new();
        let mut emit = |name: &str, proof: &BlockProofEnvelope| -> Result<()> {
            rows.push(json!({"fixture_id":name,"context":{"op":"decode_proof","block_proof":proof_b64(proof)?}}));
            Ok(())
        };
        emit("original-envelope", &original)?;
        let mut p = original.clone();
        p.signatures = None;
        emit("no-signatures", &p)?;
        let mut p = original.clone();
        p.proof_for.seq_no += 1;
        emit("wrong-declared-seqno", &p)?;
        let mut p = original.clone();
        p.proof_for.root_hash = Default::default();
        emit("wrong-declared-hash", &p)?;
        let mut p = original.clone();
        p.root = Cell::default();
        emit("ordinary-proof-root", &p)?;
        let mut p = original.clone();
        replace_block(&mut p, pruned(&root)?)?;
        emit("pruned-block-root", &p)?;
        let mut p = original.clone();
        p.signatures = Some(pruned(p.signatures.as_ref().unwrap())?);
        emit("pruned-signature-cell", &p)?;
        let mut p = original.clone();
        p.signatures = Some(Cell::default());
        emit("empty-signature-cell", &p)?;
        let mut p = original.clone();
        p.signatures = Some(append_bit(p.signatures.as_ref().unwrap())?);
        emit("signature-trailing-bit", &p)?;
        let mut b = block.clone();
        b.info = ChildCell::with_cell(append_bit(&b.info_cell())?);
        let mut p = original.clone();
        replace_block(&mut p, b.serialize()?)?;
        emit("header-info-trailing-bit", &p)?;
        let mut b = block.clone();
        let info_root = b.info_cell();
        b.info = ChildCell::with_cell(
            MerkleProof::create(&info_root, |h| h == info_root.repr_hash())?.proof,
        );
        let mut p = original.clone();
        replace_block(&mut p, b.serialize()?)?;
        emit("header-pruned-references", &p)?;
        let mut b = block.clone();
        b.info = ChildCell::with_cell(pruned(&b.info_cell())?);
        let mut p = original.clone();
        replace_block(&mut p, b.serialize()?)?;
        emit("pruned-info-root", &p)?;
        let mut b = block.clone();
        b.info = ChildCell::with_cell(changed_byte(&b.info_cell(), 9, 2)?);
        let mut p = original.clone();
        replace_block(&mut p, b.serialize()?)?;
        emit("header-reserved-flag", &p)?;
        let mut b = block.clone();
        b.info = ChildCell::with_cell(changed_byte(&b.info_cell(), 30, 1)?);
        let mut p = original.clone();
        replace_block(&mut p, b.serialize()?)?;
        emit("header-shard-low-prefix", &p)?;
        let mut b = block.clone();
        let mut info = b.read_info()?;
        info.set_version(1);
        b.write_info(&info)?;
        let mut p = original.clone();
        replace_block(&mut p, b.serialize()?)?;
        emit("header-version", &p)?;
        let mut b = block.clone();
        b.state_update = ChildCell::with_cell(Cell::default());
        let mut p = original.clone();
        replace_block(&mut p, b.serialize()?)?;
        emit("ordinary-state-update", &p)?;
        let mut context = decoded.clone();
        context["block_proof"] = json!(rtos_block::base64_encode(rtos_block::write_boc(
            &append_bit(&original.serialize()?)?
        )?));
        rows.push(json!({"fixture_id":"envelope-trailing-bit","context":context}));
        for (name, index, value) in [
            ("envelope-depth-61", 1, 61),
            ("envelope-depth-62", 1, 62),
            ("envelope-depth-63", 1, 63),
            ("envelope-low-prefix", 13, 1),
        ] {
            let mut context = decoded.clone();
            context["block_proof"] = json!(rtos_block::base64_encode(rtos_block::write_boc(
                &changed_byte(&original.serialize()?, index, value)?
            )?));
            rows.push(json!({"fixture_id":name,"context":context}));
        }

        for (version, coeff) in [(0u16, 0u32), (1, 0), (2, 0), (3, 0), (2, u32::MAX)] {
            let mut proof = read_proof(governing, "key_block_proof")?;
            let raw_root = MerkleProof::construct_from_full_cell(proof.root.clone())?.proof;
            let mut block = Block::construct_from_cell(raw_root)?;
            let mut extra = block.read_extra()?;
            let mut custom = extra.read_custom()?.context("masterchain extra required")?;
            let mut config = custom.config().cloned().context("config required")?;
            let mut options = match config.config(29)? {
                Some(ConfigParamEnum::ConfigParam29(v)) => v,
                _ => anyhow::bail!("Param29 required"),
            };
            options.proto_version = version;
            options.catchain_max_blocks_coeff = coeff;
            config.set_config(ConfigParamEnum::ConfigParam29(options))?;
            custom.set_config(config);
            extra.write_custom(&custom)?;
            block.write_extra(&extra)?;
            replace_block(&mut proof, block.serialize()?)?;
            let mut context = governing.clone();
            context["key_block_proof"] = json!(proof_b64(&proof)?);
            context["key_block"]["root_hash"] =
                json!(hex::encode_upper(proof.proof_for.root_hash.as_slice()));
            let row =
                json!({"fixture_id":format!("key-options-version-{version}"),"context":context});
            if coeff == 0 {
                rows.push(row);
            } else if let Ok(path) = std::env::var("RTOS_PROOF_RAW_CONTEXTS_OUT") {
                std::fs::write(path, serde_json::to_string(&row)? + "\n")?;
            }
        }
        let output = rows
            .iter()
            .map(|v| Ok(serde_json::to_string(v)? + "\n"))
            .collect::<Result<String>>()?;
        std::fs::write(std::env::var("RTOS_PROOF_CONTEXTS_OUT")?, output)?;
        Ok(())
    }
}
