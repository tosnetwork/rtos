// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Explicit-input consensus adapter. Unsupported operations remain harness errors.
use anyhow::{bail, ensure, Context, Result};
use rtos_block::{PqConsensusKey, SigPubKey, UInt256, ValidatorDescr, ValidatorSet};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    io::{self, BufRead, Read, Write},
};

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
fn validate_shard(value: &Value) -> Result<()> {
    let _: i32 = value["workchain"].as_i64().context("workchain required")?.try_into()?;
    let shard: [u8; 8] =
        bytes(&value["shard"])?.try_into().map_err(|_| anyhow::anyhow!("8-byte shard required"))?;
    ensure!(u64::from_be_bytes(shard) != 0, "zero is not a shard");
    Ok(())
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
            validate_shard(&ctx["shard"])?;
            let total =
                rtos_block::checked_validator_weight_sum(validators.iter().map(|v| v.weight))?;
            json!({"outcome":"validator_set", "validator_set_hash":ValidatorSet::calc_subset_hash_short(&validators,seqno)?,
                "total_weight":total.to_string(), "threshold":rtos_block::quorum_threshold(total).to_string()})
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
            run(&serde_json::from_str::<Value>(&line)?)
        })()
        .unwrap_or_else(|e| json!({"harness_error":e.to_string()}));
        serde_json::to_writer(&mut output, &effect)?;
        writeln!(output)?;
        output.flush()?;
        ensure!(size <= 16 << 20, "context too large");
    }
    Ok(())
}
