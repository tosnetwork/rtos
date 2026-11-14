// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Line adapter over native ValidateQuery, with explicit offline state roots.
use anyhow::{ensure, Context, Result};
use futures::FutureExt;
use rtos::{
    error::NodeError,
    validator::{offline, BlockCandidate},
};
use rtos_block::{
    base64_decode, read_single_root_boc, BlockError, BlockIdExt, CellType, Deserializable,
    ExceptionCode, MerkleProof, ShardIdent, UInt256,
};
use serde_json::{json, Value};
use std::{
    io::{self, BufRead, Read, Write},
    panic::AssertUnwindSafe,
};
fn hash(v: &Value) -> Result<UInt256> {
    let s = v.as_str().context("hash string required")?;
    ensure!(s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()), "64hex digits required");
    Ok(UInt256::from_slice(&hex::decode(s)?))
}
fn id(v: &Value) -> Result<BlockIdExt> {
    let s = v["shard"].as_str().context("shard required")?;
    ensure!(
        s.len() == 16 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "16lowercase hex required"
    );
    Ok(BlockIdExt::with_params(
        ShardIdent::with_tagged_prefix(
            v["workchain"].as_i64().context("workchain required")?.try_into()?,
            u64::from_str_radix(s, 16)?,
        )?,
        v["seqno"].as_u64().context("seqno required")?.try_into()?,
        hash(&v["root_hash"])?,
        hash(&v["file_hash"])?,
    ))
}
const MAX_CONTEXT_BYTES: u64 = 16 << 20;
const MAX_BOC_BYTES: usize = 4 << 20;
const MAX_STATES_BYTES: usize = 8 << 20;

// CPP checks this estimate before invoking any decoder (including for malformed base64).
fn decoded_size(s: &str) -> usize {
    let mut n = s.len();
    for _ in 0..2 {
        if n > 0 && s.as_bytes()[n - 1] == b'=' {
            n -= 1;
        } else {
            break;
        }
    }
    n / 4 * 3 + (n % 4).saturating_sub(1)
}
fn check_size(s: &str, limit: usize, name: &str) -> Result<usize> {
    let size = decoded_size(s);
    ensure!(size <= limit, "{name}: larger than {limit} bytes");
    Ok(size)
}
fn bytes(v: &Value, name: &str) -> Result<Vec<u8>> {
    let s = v.as_str().context("base64 BOC required")?;
    check_size(s, MAX_BOC_BYTES, name)?;
    Ok(base64_decode(s)?)
}
fn request(v: &Value) -> Result<offline::Request> {
    // Preserve the reference's field/size-check order; states are preflighted as a batch.
    let block_id = id(&v["block_id"])?;
    let data = bytes(&v["block"], "block")?;
    let collated = if v.get("collated_data").is_some() {
        bytes(&v["collated_data"], "collated_data")?
    } else {
        vec![]
    };
    let created_by = hash(&v["created_by"])?;
    let prev = v["prev"].as_array().context("prev array required")?;
    ensure!((1..=2).contains(&prev.len()), "one or two previous blocks required");
    let prev = prev.iter().map(id).collect::<Result<_>>()?;
    let min_masterchain = id(&v["min_masterchain"])?;
    let top_masterchain = id(&v["top_masterchain"])?;
    let validator_set_from = id(&v["validator_set_from"])?;
    let skip_shard_signatures = v
        .get("skip_shard_signatures")
        .map_or(Ok(false), |v| v.as_bool().context("bool required"))?;
    let values = v["states"].as_array().context("states array required")?;
    ensure!(values.len() <= 32, "states: more than 32 items");
    let mut encoded = Vec::with_capacity(values.len());
    let mut total = 0;
    for (i, value) in values.iter().enumerate() {
        ensure!(value.is_object(), "states[{i}]: object required");
        let s = value["state"].as_str().context("base64 state required")?;
        total += check_size(s, MAX_BOC_BYTES, &format!("states[{i}].state"))?;
        ensure!(total <= MAX_STATES_BYTES, "states: larger than {MAX_STATES_BYTES} bytes in total");
        encoded.push(s);
    }
    let mut states = Vec::with_capacity(values.len());
    for (value, encoded) in values.iter().zip(encoded) {
        let block = id(&value["block"])?;
        let mut root = read_single_root_boc(&base64_decode(encoded)?)?;
        if root.cell_type() == CellType::MerkleProof {
            let proof = MerkleProof::construct_from_cell(root)?;
            root = proof.proof.virtualize(1);
        }
        states.push((block, root));
    }
    Ok(offline::Request {
        candidate: BlockCandidate {
            block_id,
            data,
            collated_file_hash: UInt256::calc_file_hash(&collated),
            collated_data: collated,
            created_by,
        },
        prev,
        min_masterchain,
        top_masterchain,
        validator_set_from,
        skip_shard_signatures,
        states,
    })
}
fn reason(e: &anyhow::Error) -> &'static str {
    if matches!(e.downcast_ref::<BlockError>(), Some(BlockError::PrunedCellAccess(_)))
        || matches!(e.downcast_ref::<ExceptionCode>(), Some(ExceptionCode::PrunedCellAccess))
    {
        return "pruned_input";
    }
    if e.downcast_ref::<offline::InputUnavailable>().is_some() {
        return "input_unavailable";
    }
    let text = e.to_string();
    let table = [
        ("block catchain sequence", "validator_set_mismatch"),
        ("block validator set hash", "validator_set_mismatch"),
        ("pruned branch", "pruned_input"),
        ("last transaction mismatch", "transaction_invalid"),
        ("claims to be transaction", "transaction_invalid"),
        ("claims that the previous transaction", "transaction_invalid"),
        ("after_split mismatch in block header", "shard_mismatch"),
        ("invalid InMsg", "message_invalid"),
        ("invalid OutMsg", "message_invalid"),
        ("wrong file_hash", "candidate_id_mismatch"),
        ("wrong root_hash", "candidate_id_mismatch"),
        ("wrong root hash", "candidate_id_mismatch"),
        ("cannot split shards in masterchain", "shard_mismatch"),
        ("prunned branch", "pruned_input"),
        ("virtualization error", "pruned_input"),
        ("pruned cell", "pruned_input"),
        ("offline validation input not served", "input_unavailable"),
        ("block candidate has invalid file hash", "candidate_id_mismatch"),
        ("block candidate has invalid root hash", "candidate_id_mismatch"),
        ("different from current shard", "shard_mismatch"),
        ("shard mismatch in the block header", "shard_mismatch"),
        ("sub-shards cannot exist in the masterchain", "shard_mismatch"),
        ("block header contains block id", "shard_mismatch"),
        ("previous blocks, but we are given", "prev_block_mismatch"),
        ("mismatch: expected", "prev_block_mismatch"),
        ("has creator", "creator_mismatch"),
        ("declares cc_seqno", "validator_set_mismatch"),
        ("declares validator set hash", "validator_set_mismatch"),
        ("previous state hash mismatch", "prev_state_mismatch"),
        ("next state hash mismatch", "new_state_mismatch"),
        ("new state contains generation", "new_state_mismatch"),
        ("larger than the hard limit", "limit_exceeded"),
        ("exceeds hard limit", "limit_exceeded"),
        ("is not aligned", "utime_lt_invalid"),
        ("creation time", "utime_lt_invalid"),
        ("gen_utime", "utime_lt_invalid"),
        ("now_ms", "utime_lt_invalid"),
        ("start_lt", "utime_lt_invalid"),
        ("ValueFlow", "value_flow_invalid"),
        ("AccountBlock", "account_update_invalid"),
        ("HASH_UPDATE", "account_update_invalid"),
        ("transaction", "transaction_invalid"),
        ("OutMsg", "message_invalid"),
        ("InMsg", "message_invalid"),
        ("message", "message_invalid"),
    ];
    table.into_iter().find(|(needle, _)| text.contains(needle)).map_or("unclassified", |(_, r)| r)
}
async fn run(v: &Value) -> Result<Value> {
    let req = request(v)?;
    match AssertUnwindSafe(offline::run(req)).catch_unwind().await {
        Ok(Ok(offline::Outcome::Accepted(v))) => {
            Ok(json!({"outcome":"accepted","ok_from_utime_ms":v.ok_from_utime_ms}))
        }
        Ok(Ok(offline::Outcome::Failed(e))) => {
            eprintln!("native validation: {e:?}");
            let outcome = if matches!(
                e.downcast_ref::<NodeError>(),
                Some(NodeError::ValidatorReject(_) | NodeError::ValidatorSoftReject(_))
            ) {
                "rejected"
            } else {
                "error"
            };
            Ok(json!({"outcome":outcome,"reason":reason(&e)}))
        }
        Ok(Err(e)) => Err(e),
        Err(_) => anyhow::bail!("native validator panicked; see stderr"),
    }
}
fn main() -> Result<()> {
    let harness = std::env::args().nth(1).unwrap_or_default();
    if harness == "--info" {
        println!("{}", json!({"harnesses":["validate"]}));
        return Ok(());
    }
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut line = String::new();
        let n = input.by_ref().take(MAX_CONTEXT_BYTES + 2).read_line(&mut line)?;
        if n == 0 {
            break;
        }
        let effect = (|| -> Result<Value> {
            ensure!(n as u64 <= MAX_CONTEXT_BYTES, "context too large");
            ensure!(harness == "validate", "unsupported harness");
            runtime.block_on(run(&serde_json::from_str(&line)?))
        })()
        .unwrap_or_else(|e| json!({"harness_error":e.to_string()}));
        serde_json::to_writer(&mut output, &effect)?;
        writeln!(output)?;
        output.flush()?;
        ensure!(n as u64 <= MAX_CONTEXT_BYTES, "context too large");
    }
    Ok(())
}
