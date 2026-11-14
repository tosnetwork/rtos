// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Explicit-input consensus adapter. Unsupported operations remain harness errors.
use anyhow::{bail, ensure, Context, Result};
use rtos_api::session_identity::{
    explicit_session_group_bytes, session_config_hash_from_hash, ExplicitSessionCoordinates,
    ExplicitSessionOptions,
};
use rtos_block::{
    BlockProofEnvelope, BlockSignaturesVariant, Deserializable, PqConsensusKey, SigPubKey, UInt256,
    ValidatorDescr, ValidatorSet,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashSet},
    io::{self, BufRead, Read, Write},
};

#[path = "consensus/finality.rs"]
mod finality;
#[path = "consensus/link.rs"]
mod link;
#[path = "consensus/proofs.rs"]
mod proofs;

fn parse_context(line: &str) -> Result<Value> {
    use serde_json::value::RawValue;
    // Keep numeric tokens until the reference's double conversion boundary.
    // Its classic iostream conversion saturates overflow to finite MAX and
    // preserves negative zero; a Value parse alone rejects overflowing tokens.
    let raw: BTreeMap<String, &RawValue> = serde_json::from_str(line)?;
    if raw.get("op").map(|v| serde_json::from_str::<String>(v.get())).transpose()?.as_deref()
        != Some("session")
    {
        return Ok(serde_json::from_str(line)?);
    }
    let mut context = serde_json::Map::new();
    for (key, value) in raw {
        if key != "options" {
            context.insert(key, serde_json::from_str(value.get())?);
            continue;
        }
        let options: BTreeMap<String, &RawValue> = serde_json::from_str(value.get())?;
        let mut parsed = serde_json::Map::new();
        for (name, value) in options {
            let value = if matches!(name.as_str(), "idle_timeout" | "next_candidate_delay") {
                let number = value.get().parse::<f64>()?;
                let number = if number.is_infinite() { f64::MAX.copysign(number) } else { number };
                Value::Number(
                    serde_json::Number::from_f64(number).context("finite double required")?,
                )
            } else {
                serde_json::from_str(value.get())?
            };
            parsed.insert(name, value);
        }
        context.insert(key, Value::Object(parsed));
    }
    Ok(Value::Object(context))
}

fn decimal(value: &Value) -> Result<u64> {
    let text = value.as_str().context("canonical unsigned decimal string required")?;
    ensure!(
        !text.is_empty()
            && text.len() <= 20
            && text.bytes().all(|b| b.is_ascii_digit())
            && (text.len() == 1 || !text.starts_with('0')),
        "canonical unsigned decimal string required"
    );
    Ok(text.parse()?)
}
fn u32_field(ctx: &Value, field: &str) -> Result<u32> {
    Ok(ctx[field].as_u64().context("unsigned integer required")?.try_into()?)
}
fn bytes(value: &Value) -> Result<Vec<u8>> {
    let text = value.as_str().context("hex string required")?;
    ensure!(text.len() <= 2 * (1 << 16), "hex input too large");
    Ok(hex::decode(text)?)
}
fn bits(value: &Value) -> Result<UInt256> {
    let bytes: [u8; 32] =
        bytes(value)?.try_into().map_err(|_| anyhow::anyhow!("32 bytes required"))?;
    Ok(bytes.into())
}
fn shard(value: &Value) -> Result<(i32, u64)> {
    let workchain: i32 = value["workchain"].as_i64().context("workchain required")?.try_into()?;
    let shard: [u8; 8] =
        bytes(&value["shard"])?.try_into().map_err(|_| anyhow::anyhow!("8-byte shard required"))?;
    let shard = u64::from_be_bytes(shard);
    ensure!(shard != 0, "zero is not a shard");
    Ok((workchain, shard))
}
fn flag(ctx: &Value, field: &str) -> Result<bool> {
    ctx[field].as_bool().context("boolean required")
}
fn double(ctx: &Value, field: &str) -> Result<f64> {
    let value = ctx[field].as_f64().context("double required")?;
    ensure!(value.is_finite(), "finite double required");
    Ok(value)
}
fn session(ctx: &Value) -> Result<Value> {
    let global_id = i32::try_from(ctx["global_id"].as_i64().context("global_id required")?)?;
    let opts = &ctx["options"];
    let options = ExplicitSessionOptions {
        proto_version: u32_field(opts, "proto_version")?,
        new_catchain_ids: flag(opts, "new_catchain_ids")?,
        idle_timeout: double(opts, "idle_timeout")?,
        max_deps: u32_field(opts, "max_deps")?,
        max_serialized_block_size: u32_field(opts, "max_serialized_block_size")?,
        block_hash_covers_data: flag(opts, "block_hash_covers_data")?,
        max_block_height_coeff: u32_field(opts, "max_block_height_coeff")?.into(),
        debug_disable_db: flag(opts, "debug_disable_db")?,
        round_candidates: u32_field(opts, "round_candidates")?,
        next_candidate_delay: double(opts, "next_candidate_delay")?,
        round_attempt_duration: u32_field(opts, "round_attempt_duration")?,
        max_round_attempts: u32_field(opts, "max_round_attempts")?,
        max_block_size: u32_field(opts, "max_block_size")?,
        max_collated_data_size: u32_field(opts, "max_collated_data_size")?,
    };
    let simplex_hash = bits(&ctx["simplex_config_hash"])?;
    let (workchain, shard) = shard(&ctx["shard"])?;
    let coordinates = ExplicitSessionCoordinates {
        workchain,
        shard,
        catchain_seqno: u32_field(ctx, "catchain_seqno")?,
        vertical_seqno: u32_field(ctx, "vertical_seqno")?,
        last_key_block_seqno: u32_field(ctx, "last_key_block_seqno")?,
        new_catchain_ids: options.new_catchain_ids,
    };
    let validators = validators(ctx)?;
    let options_hash = UInt256::calc_file_hash(&options.bytes()?);
    let config_hash = session_config_hash_from_hash(global_id, &options_hash, &simplex_hash);
    let group = explicit_session_group_bytes(coordinates, &config_hash, &validators)?;
    Ok(json!({"outcome":"session", "options_hash":hex::encode_upper(options_hash.as_slice()),
        "session_config_hash":hex::encode_upper(config_hash.as_slice()),
        "session_id":hex::encode_upper(UInt256::calc_file_hash(&group).as_slice())}))
}
fn vote(ctx: &Value) -> Result<Value> {
    use rtos_api::pq_finality::build_simplex_vote_data;
    let session_id = bits(&ctx["session_id"])?;
    let slot = u32_field(ctx, "slot")?;
    let raw = bytes(&ctx["candidate"])?;
    let is_final = flag(ctx, "final")?;
    // The explicit reference block uses raw wire coordinates, not an admitted
    // ShardIdent. Compare them before asking the node preimage helper to act.
    let block = &ctx["block"];
    let (workchain, shard) = shard(block)?;
    let seqno = u32_field(block, "seqno")?;
    let root_hash = bits(&block["root_hash"])?;
    let file_hash = bits(&block["file_hash"])?;
    ensure!(
        ctx.get("public_key").is_some() == ctx.get("signature").is_some(),
        "public_key and signature go together"
    );
    let vote = match build_simplex_vote_data(&session_id, slot, &raw, is_final) {
        Ok(value) => value,
        Err(_) => return Ok(json!({"outcome":"refused","reason":"candidate_malformed"})),
    };
    if vote.workchain != workchain
        || vote.shard != shard
        || vote.seqno != seqno
        || vote.root_hash != root_hash
        || vote.file_hash != file_hash
    {
        return Ok(json!({"outcome":"refused","reason":"block_mismatch"}));
    }
    let data = vote.data_to_sign;
    let check = if let Some(public_key) = ctx.get("public_key") {
        let public_key = bytes(public_key)?;
        let signature = bytes(&ctx["signature"])?;
        Some(match rtos_pq_crypto::verify_simplex(&data, &signature, &public_key) {
            Ok(true) => "valid",
            Ok(false) => "invalid",
            Err(rtos_pq_crypto::VerifyError::Backend(_)) => bail!("ML-DSA-44 backend failure"),
            Err(_) => "malformed",
        })
    } else {
        None
    };
    Ok(json!({"outcome":"vote", "candidate_hash":hex::encode_upper(vote.candidate_hash.as_slice()),
        "data_to_sign":hex::encode(data), "signature_check":check}))
}
fn refused(reason: &str) -> Value {
    json!({"outcome":"refused", "reason":reason})
}
fn signature_json(value: &BlockSignaturesVariant) -> Result<Value> {
    let BlockSignaturesVariant::SimplexPq(value) = value else {
        return Ok(Value::Null);
    };
    let signatures: Vec<_> = value
        .signatures
        .iter()
        .map(|pair| {
            json!({
                "validator_id":hex::encode_upper(pair.validator_id.as_slice()),
                "algorithm_id":pair.algorithm_id, "signature":hex::encode(&pair.signature),
            })
        })
        .collect();
    Ok(json!({"final":true,"catchain_seqno":value.validator_info.catchain_seqno,
        "validator_set_hash":value.validator_info.validator_list_hash_short,
        "session_id":hex::encode_upper(value.session_id.as_slice()), "slot":value.slot,
        "candidate":hex::encode(value.candidate_bytes()?), "signatures":signatures}))
}
fn decode_proof(ctx: &Value) -> Result<Value> {
    let bytes =
        rtos_block::base64_decode(ctx["block_proof"].as_str().context("block_proof required")?)?;
    let root = rtos_block::read_single_root_boc(bytes)?;
    let proof = match BlockProofEnvelope::construct_from_full_cell(root) {
        Ok(value) => value,
        Err(_) => return Ok(refused("carrier_malformed")),
    };
    let root = match proof.virtual_root() {
        Ok(value) => value,
        Err(_) => return Ok(refused("proof_malformed")),
    };
    let (block, _) = match rtos_block::check_block_header(&root, &proof.proof_for) {
        Ok(value) => value,
        Err(e) => return Ok(refused(proofs::proof_error(&e, "header_mismatch"))),
    };
    let update = match block.read_state_update() {
        Ok(value) => value,
        Err(_) => return Ok(refused("proof_malformed")),
    };
    let (signature_set, claimed) = if let Some(cell) = proof.signatures {
        let value = match BlockSignaturesVariant::construct_from_full_cell(cell) {
            Ok(value) => value,
            Err(e) => return Ok(refused(proofs::signature_error(&e))),
        };
        (signature_json(&value)?, Some(value.declared_signature_weight().to_string()))
    } else {
        (Value::Null, None)
    };
    Ok(json!({"outcome":"proof", "seqno":proof.proof_for.seq_no(),
        "root_hash":hex::encode_upper(proof.proof_for.root_hash().as_slice()),
        "file_hash":hex::encode_upper(proof.proof_for.file_hash().as_slice()),
        "state_old_hash":hex::encode_upper(update.old_hash.as_slice()),
        "state_hash":hex::encode_upper(update.new_hash.as_slice()),
        "signature_set":signature_set, "claimed_weight":claimed}))
}
fn validators(ctx: &Value) -> Result<Vec<ValidatorDescr>> {
    let list = ctx["validators"].as_array().context("validators required")?;
    ensure!(!list.is_empty() && list.len() <= 1024, "1..1024 validators required");
    let mut result = Vec::with_capacity(list.len());
    let mut ids = HashSet::new();
    let mut key_ids = HashSet::new();
    let mut total = 0;
    for item in list {
        let weight = decimal(&item["weight"])?;
        total = rtos_block::checked_add_validator_weight(total, weight)?;
        let adnl = bits(&item["adnl"])?;
        let validator = if let Some(key) = item.get("ed25519") {
            ValidatorDescr::with_params(
                SigPubKey::from_bytes(bits(key)?.as_slice())?,
                weight,
                Some(adnl),
            )
        } else {
            let algorithm_id = u16::try_from(u32_field(item, "algorithm_id")?)?;
            ensure!(algorithm_id != 0, "algorithm_id must be positive");
            ValidatorDescr::with_pq_params(
                bits(&item["validator_id"])?,
                PqConsensusKey {
                    algorithm_id,
                    key_id: bits(&item["key_id"])?,
                    public_key: bytes(&item["public_key"])?,
                },
                weight,
                adnl,
            )
        };
        // Match the reference descriptor decoder, without admitting algorithms
        // or validating a key identity before the operation itself does so.
        ensure!(ids.insert(validator.validator_id()?), "repeated validator identity");
        ensure!(key_ids.insert(validator.consensus_key_id()?), "repeated key identity");
        result.push(validator);
    }
    Ok(result)
}
fn run(ctx: &Value) -> Result<Value> {
    Ok(match ctx["op"].as_str().context("consensus op required")? {
        "quorum" => {
            let total = decimal(&ctx["total_weight"])?;
            let signed = decimal(&ctx["signed_weight"])?;
            json!({"outcome":"quorum", "threshold":rtos_block::quorum_threshold(total).to_string(),
                "has_quorum":rtos_block::quorum_weight_reached(signed,total)})
        }
        "weight_total" => {
            let weights = ctx["weights"].as_array().context("weights required")?;
            ensure!(weights.len() <= 4096, "at most 4096 weights");
            let mut total = 0;
            for weight in weights {
                let weight = decimal(weight)?;
                match rtos_block::checked_add_validator_weight(total, weight) {
                    Ok(value) => total = value,
                    Err(_) => return Ok(json!({"outcome":"refused","reason":"weight_refused"})),
                }
            }
            json!({"outcome":"weight_total","total":total.to_string()})
        }
        "validator_set" => {
            let validators = validators(ctx)?;
            let seqno = u32_field(ctx, "catchain_seqno")?;
            shard(&ctx["shard"])?;
            let total =
                rtos_block::checked_validator_weight_sum(validators.iter().map(|v| v.weight))?;
            json!({"outcome":"validator_set", "validator_set_hash":ValidatorSet::calc_subset_hash_short(&validators,seqno)?,
                "total_weight":total.to_string(), "threshold":rtos_block::quorum_threshold(total).to_string()})
        }
        "session" => session(ctx)?,
        "vote" => vote(ctx)?,
        "decode_proof" => decode_proof(ctx)?,
        "key_block_context" => proofs::key_context(ctx)?,
        "finality" => finality::run(ctx)?,
        "proof_link" => link::run(ctx)?,
        "protocol_version" => {
            let version = rtos_block::SimplexProtocolVersion(u32_field(ctx, "protocol_version")?);
            json!({"outcome":"protocol_version", "supported":version.supported(),
                "enable_block_sync":version.enable_block_sync(), "use_new_db_names":version.use_new_db_names(),
                "observers_in_private_overlay":version.observers_in_private_overlay(),
                "enable_plumtree_broadcast":version.enable_plumtree_broadcast(),
                "max_supported":rtos_block::SimplexProtocolVersion::MAX_SUPPORTED})
        }
        _ => bail!("unsupported consensus operation"),
    })
}
fn main() -> Result<()> {
    let harness = std::env::args().nth(1).unwrap_or_default();
    if harness == "--info" {
        println!("{}", json!({"harnesses":["consensus"]}));
        return Ok(());
    }
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut line = String::new();
        let size = input.by_ref().take((16 << 20) + 2).read_line(&mut line)?;
        if size == 0 {
            break;
        }
        let effect = (|| -> Result<Value> {
            ensure!(size <= 16 << 20, "context too large");
            ensure!(harness == "consensus", "unsupported harness");
            run(&parse_context(&line)?)
        })()
        .unwrap_or_else(|e| match e.downcast_ref::<proofs::ProofRefusal>() {
            Some(error) => refused(error.0),
            None if proofs::proof_error(&e, "") == "proof_malformed" => refused("proof_malformed"),
            None => json!({"harness_error":e.to_string()}),
        });
        serde_json::to_writer(&mut output, &effect)?;
        writeln!(output)?;
        output.flush()?;
        ensure!(size <= 16 << 20, "context too large");
    }
    Ok(())
}
