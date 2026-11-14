// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Line adapter over native ValidateQuery, with explicit offline state roots.
use anyhow::{ensure, Context, Result};
use futures::FutureExt;
use rtos::{
    error::NodeError,
    validator::{offline, BlockCandidate},
};
use rtos_block::{
    base64_decode, read_single_root_boc, BlockIdExt, CellType, Deserializable, MerkleProof,
    ShardIdent, UInt256,
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
fn bytes(v: &Value) -> Result<Vec<u8>> {
    let b = base64_decode(v.as_str().context("base64 BOC required")?)?;
    ensure!(b.len() <= 32 << 20, "BOC exceeds32MiB");
    Ok(b)
}
fn request(v: &Value) -> Result<offline::Request> {
    let mut states = vec![];
    let values = v["states"].as_array().context("states array required")?;
    ensure!(values.len() <= 32, "at most32states required");
    for s in values {
        let mut root = read_single_root_boc(&bytes(&s["state"])?)?;
        if root.cell_type() == CellType::MerkleProof {
            let proof = MerkleProof::construct_from_cell(root)?;
            root = proof.proof.virtualize(1);
        }
        states.push((id(&s["block"])?, root));
    }
    let prev = v["prev"].as_array().context("prev array required")?;
    ensure!((1..=2).contains(&prev.len()), "one or two previous blocks required");
    let collated =
        if v.get("collated_data").is_some() { bytes(&v["collated_data"])? } else { vec![] };
    Ok(offline::Request {
        candidate: BlockCandidate {
            block_id: id(&v["block_id"])?,
            data: bytes(&v["block"])?,
            collated_file_hash: UInt256::calc_file_hash(&collated),
            collated_data: collated,
            created_by: hash(&v["created_by"])?,
        },
        prev: prev.iter().map(id).collect::<Result<_>>()?,
        min_masterchain: id(&v["min_masterchain"])?,
        top_masterchain: id(&v["top_masterchain"])?,
        validator_set_from: id(&v["validator_set_from"])?,
        skip_shard_signatures: v
            .get("skip_shard_signatures")
            .map_or(Ok(false), |v| v.as_bool().context("bool required"))?,
        states,
    })
}
fn reason(e: &anyhow::Error) -> &'static str {
    if e.downcast_ref::<offline::InputUnavailable>().is_some() {
        return "input_unavailable";
    }
    let text = e.to_string();
    let table = [
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
        let n = input.by_ref().take((128 << 20) + 2).read_line(&mut line)?;
        if n == 0 {
            break;
        }
        let effect = (|| -> Result<Value> {
            ensure!(n <= 128 << 20, "context too large");
            ensure!(harness == "validate", "unsupported harness");
            runtime.block_on(run(&serde_json::from_str(&line)?))
        })()
        .unwrap_or_else(|e| json!({"harness_error":e.to_string()}));
        serde_json::to_writer(&mut output, &effect)?;
        writeln!(output)?;
        output.flush()?;
        ensure!(n <= 128 << 20, "context too large");
    }
    Ok(())
}
