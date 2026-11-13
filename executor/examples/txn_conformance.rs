// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Context-only transaction target for the shared conformance runner.
use anyhow::{anyhow, bail, ensure, Result};
use rtos_block::{
    base64_decode, read_single_root_boc, Cell, ConfigParams, Deserializable, HashUpdate, HashmapE,
    Serializable, ShardAccount, SliceData, TransactionTickTock, UInt256, LT_ALIGN,
};
use rtos_executor::{
    BlockchainConfig, ExecuteParams, ExecutorError, OrdinaryTransactionExecutor,
    TickTockTransactionExecutor, TransactionExecutor,
};
use rtos_vm::{
    smart_contract_info::PrevBlocksInfo,
    stack::{integer::IntegerData, StackItem},
};
use serde_json::{json, Value};
use std::io::{self, BufRead, Read, Write};

fn boc(v: &Value) -> Result<Cell> {
    read_single_root_boc(base64_decode(v.as_str().ok_or_else(|| anyhow!("expected BOC string"))?)?)
}
// The serialized value uses VmStackValue/VmTuple, not the JSON VM-stack format.
fn stack_value(cell: Cell, depth: usize, budget: &mut usize) -> Result<StackItem> {
    ensure!(depth <= 512, "previous-block value too deep");
    *budget = budget.checked_sub(1).ok_or_else(|| anyhow!("previous-block value too large"))?;
    let mut cs = SliceData::load_cell(cell)?;
    let value = match cs.get_next_byte()? {
        0 => StackItem::None,
        1 => StackItem::int(cs.get_next_i64()?),
        2 => match cs.get_next_byte()? {
            0 => {
                StackItem::integer(IntegerData::from_bytes(cs.get_next_u256()?, 256, false, true)?)
            }
            1 => {
                let mut bytes = vec![255];
                bytes.extend_from_slice(&cs.get_next_u256()?);
                StackItem::integer(IntegerData::from_bytes(bytes, 264, true, true)?)
            }
            255 => StackItem::nan(),
            _ => bail!("invalid integer tag"),
        },
        3 => StackItem::cell(cs.checked_drain_reference()?),
        4 => {
            let start = cs.get_next_int(10)? as usize;
            let end = cs.get_next_int(10)? as usize;
            let first = cs.get_next_int(3)? as usize;
            let last = cs.get_next_int(3)? as usize;
            let cell = cs.checked_drain_reference()?;
            ensure!(start <= end && first <= last && last <= 4, "invalid slice window");
            StackItem::slice(SliceData::load_cell_with_window(cell, start..end, first..last)?)
        }
        5 => {
            let slice = SliceData::load_cell(cs.checked_drain_reference()?)?;
            StackItem::builder(slice.as_builder()?)
        }
        7 => {
            let n = cs.get_next_u16()? as usize;
            ensure!(n <= *budget, "previous-block tuple too large");
            let mut items = Vec::with_capacity(n);
            if n == 1 {
                items.push(stack_value(cs.checked_drain_reference()?, depth + 1, budget)?);
            } else if n > 1 {
                let mut head = cs.checked_drain_reference()?;
                let tail = cs.checked_drain_reference()?;
                for _ in 1..n - 1 {
                    let mut link = SliceData::load_cell(head)?;
                    head = link.checked_drain_reference()?;
                    let item = link.checked_drain_reference()?;
                    ensure!(link.is_empty_cell(), "trailing tuple link data");
                    items.push(stack_value(item, depth + 1, budget)?);
                }
                items.push(stack_value(head, depth + 1, budget)?);
                items.reverse();
                items.push(stack_value(tail, depth + 1, budget)?);
            }
            StackItem::tuple(items)
        }
        tag => bail!("unsupported previous-block value tag {tag}"),
    };
    ensure!(cs.is_empty_cell(), "trailing previous-block value data");
    Ok(value)
}
fn run_txn(ctx: &Value) -> Result<Value> {
    let config = ConfigParams::with_root(boc(&ctx["config"])?)?;
    let config = BlockchainConfig::with_config(config)?;
    let shard = boc(&ctx["shard_account"])?;
    let now = ctx["now"]
        .as_u64()
        .filter(|n| (1..=u32::MAX as u64).contains(n))
        .ok_or_else(|| anyhow!("now must be positive uint32"))? as u32;
    let lt =
        ctx["lt"].as_i64().filter(|n| *n > 0).ok_or_else(|| anyhow!("lt must be positive int64"))?
            as u64;
    let seed = ctx["rand_seed"].as_str().ok_or_else(|| anyhow!("missing rand_seed"))?;
    ensure!(
        seed.len() == 64 && seed.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "rand_seed must be 64 lowercase hex digits"
    );
    let seed = seed.parse::<UInt256>()?;
    let msg = ctx.get("message").map(boc).transpose()?;
    let tick = ctx.get("tick_tock");
    ensure!(msg.is_some() != tick.is_some(), "exactly one of message and tick_tock required");
    let tock = match tick {
        Some(v) if v == "tick" => false,
        Some(v) if v == "tock" => true,
        Some(_) => bail!("tick_tock must be tick or tock"),
        None => false,
    };
    let libs = ctx.get("libraries").map(boc).transpose()?;
    let prev_blocks = ctx
        .get("prev_blocks")
        .map(|v| -> Result<StackItem> {
            let mut budget = 1 << 20;
            let value = stack_value(boc(v)?, 0, &mut budget)?;
            ensure!(
                value.is_tuple() || matches!(value, StackItem::None),
                "prev_blocks must be tuple or null"
            );
            Ok(value)
        })
        .transpose()?
        .unwrap_or(StackItem::None);
    let threshold = config.size_limits_config().acc_state_cells_for_storage_dict;
    let exec: Box<dyn TransactionExecutor> = if msg.is_some() {
        Box::new(OrdinaryTransactionExecutor::new(config))
    } else {
        Box::new(TickTockTransactionExecutor::new(config, TransactionTickTock::new(tock)))
    };
    let params = ExecuteParams {
        block_unixtime: now,
        block_lt: lt - lt % LT_ALIGN,
        last_tr_lt: lt,
        seed_block: seed,
        prev_blocks_info: PrevBlocksInfo::Tuple(prev_blocks),
        state_libs: HashmapE::with_hashmap(256, libs),
        ..Default::default()
    };
    // Valid BOCs which the emulator cannot execute produce an error effect.
    let execute = || -> Result<Value> {
        let mut shard = ShardAccount::construct_from_cell(shard)?;
        let old_hash = shard.account_hash();
        let mut account = shard.read_account()?;
        let result = exec.execute_with_params(msg, &mut account, params);
        let mut tx = match result {
            Ok(tx) => tx,
            Err(err) => {
                return Ok(match err.downcast_ref::<ExecutorError>() {
                    Some(ExecutorError::NoAcceptError(code, _)) => {
                        json!({"outcome":"rejected", "vm_exit_code":code})
                    }
                    _ => json!({"outcome":"error"}),
                })
            }
        };
        let changed = account.precalc_storage_stat()?.is_some_and(|s| s.is_changed());
        let needs_dict = account.get_addr().is_some_and(|a| !a.is_masterchain())
            && account.dict_hash().is_none()
            && account.storage_info().is_some_and(|s| s.used().cells() >= threshold as u64);
        if changed || needs_dict {
            account.calc_storage_stat_dict(threshold)?;
        }
        tx.set_prev_trans_hash(shard.last_trans_hash().clone());
        tx.set_prev_trans_lt(shard.last_trans_lt());
        shard.write_account(&account)?;
        tx.write_state_update(&HashUpdate::with_hashes(old_hash, shard.account_hash()))?;
        let tx_lt = tx.logical_time();
        let tx = tx.serialize()?;
        shard.set_last_trans_hash(tx.repr_hash().clone());
        shard.set_last_trans_lt(tx_lt);
        Ok(json!({"outcome":"accepted", "transaction_hash":format!("{:X}",tx.repr_hash()),
            "account_hash":format!("{:X}",shard.account_hash()),
            "shard_account_hash":format!("{:X}",shard.serialize()?.repr_hash())}))
    };
    Ok(execute().unwrap_or_else(|_| json!({"outcome":"error"})))
}
fn main() -> Result<()> {
    let harness = std::env::args().nth(1).unwrap_or_default();
    if harness == "--info" {
        println!("{}", json!({"harnesses":["txn"],"protocol_version":1}));
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
            let ctx = serde_json::from_str(&line)?;
            match harness.as_str() {
                "txn" => run_txn(&ctx),
                _ => bail!("unsupported harness {harness}"),
            }
        })()
        .unwrap_or_else(|e| json!({"harness_error":e.to_string()}));
        serde_json::to_writer(&mut output, &effect)?;
        writeln!(output)?;
        output.flush()?;
        ensure!(size <= 16 << 20, "context too large");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_storage_matches_reference_for_existing_and_new_accounts() {
        fn resolve(value: Value, blobs: &Value) -> Value {
            match value {
                Value::Object(map) if map.len() == 1 && map.contains_key("blob") => {
                    blobs[map["blob"].as_str().unwrap()].clone()
                }
                Value::Object(map) => {
                    Value::Object(map.into_iter().map(|(k, v)| (k, resolve(v, blobs))).collect())
                }
                Value::Array(items) => {
                    Value::Array(items.into_iter().map(|v| resolve(v, blobs)).collect())
                }
                v => v,
            }
        }
        let blobs: Value = serde_json::from_str(include_str!(
            "../src/tests/data/conformance/txn/fixtures/seeded-storage-usage.blobs.json"
        ))
        .unwrap();
        for line in
            include_str!("../src/tests/data/conformance/txn/fixtures/seeded-storage-usage.jsonl")
                .lines()
        {
            let row: Value = serde_json::from_str(line).unwrap();
            let context = resolve(row["context"].clone(), &blobs);
            if row["metadata"]["fixture_id"] == "existing-unchanged-usage" {
                let shard =
                    ShardAccount::construct_from_cell(boc(&context["shard_account"]).unwrap())
                        .unwrap();
                let mut account = shard.read_account().unwrap();
                assert!(account.calc_and_check_storage_stat_dict(u32::MAX).is_err());
                let mut preview = shard.read_account().unwrap();
                let used = preview.storage_info().unwrap().used().clone();
                let original_data = preview.state_init().unwrap().data.clone();
                let changed = rtos_block::BuilderData::with_raw(vec![0xa5, 0x5a], 16)
                    .unwrap()
                    .into_cell()
                    .unwrap();
                preview.state_init_mut().unwrap().data = Some(changed.clone());
                preview.precalc_storage_stat().unwrap();
                preview.state_init_mut().unwrap().data = original_data.clone();
                preview.precalc_storage_stat().unwrap();
                assert_eq!(preview.storage_info().unwrap().used(), &used);
                preview.state_init_mut().unwrap().data = Some(changed);
                preview.calc_storage_stat_dict(u32::MAX).unwrap();
                preview.state_init_mut().unwrap().data = original_data;
                preview.precalc_storage_stat().unwrap();
                assert!(preview.storage_info().unwrap().used().cells() > 0);
            }
            assert_eq!(
                run_txn(&context).unwrap(),
                row["effects"],
                "{}",
                row["metadata"]["fixture_id"]
            );
        }
    }
}
