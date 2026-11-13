// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Shared getter boundary using the node's c7 construction and native VM.
#[allow(dead_code)]
#[path = "conformance.rs"]
mod shared;

use anyhow::{anyhow, ensure, Result};
use rtos_block::{
    base64_decode, read_single_root_boc, Account, BlockIdExt, Cell, ConfigParams, Deserializable,
    ExceptionCode, HashmapAugType, KeyExtBlkRef, ShardIdent, ShardStateUnsplit, UInt256,
};
use rtos_vm::{
    error::{tvm_exception_code, tvm_exception_or_custom_code},
    executor::{gas::gas_state::Gas, Engine},
    smart_contract_info::{PrevBlocksInfo, SmartContractInfo},
    stack::{integer::IntegerData, savelist::SaveList, Stack, StackItem},
};
use serde_json::{json, Value};
use std::io::{self, BufRead, Read, Write};

fn boc(value: &Value) -> Result<Cell> {
    read_single_root_boc(base64_decode(value.as_str().ok_or_else(|| anyhow!("expected BOC"))?)?)
}
fn virtual0(cell: Cell) -> Cell {
    let level = cell.level();
    cell.virtualize(level)
}
fn integer(value: &Value) -> Result<i64> {
    value.as_i64().ok_or_else(|| anyhow!("expected signed64 integer"))
}
fn hex(value: &Value, lower: bool) -> Result<UInt256> {
    let text = value.as_str().ok_or_else(|| anyhow!("expected hex string"))?;
    ensure!(
        text.len() == 64
            && text.bytes().all(|c| c.is_ascii_digit()
                || if lower { (b'a'..=b'f').contains(&c) } else { (b'A'..=b'F').contains(&c) }),
        "invalid hash case or width"
    );
    Ok(text.parse()?)
}
fn extract_config(root: Cell, current: &BlockIdExt) -> Result<(ShardStateUnsplit, ConfigParams)> {
    let state = ShardStateUnsplit::construct_from_full_cell(root)?;
    ensure!(
        state.shard().is_masterchain() && state.seq_no() == current.seq_no(),
        "snapshot identity differs"
    );
    let extra = state.read_custom()?.ok_or_else(|| anyhow!("no masterchain extra"))?;
    extra.config.get_global_version()?;
    if state.seq_no() != 0 {
        let mut zero =
            extra.prev_blocks.get_as_slice(&0)?.ok_or_else(|| anyhow!("missing zero state"))?;
        let record = KeyExtBlkRef::construct_from(&mut zero)?;
        ensure!(record.blk_ref.seq_no == 0 && zero.is_empty_cell(), "invalid zero state");
    }
    Ok((state, extra.config))
}
fn run_getter(ctx: &Value) -> Result<Value> {
    let state_root = virtual0(boc(&ctx["mc_state"])?);
    ensure!(ctx["mc_block"].is_object(), "expected masterchain block identity");
    let id = &ctx["mc_block"];
    let current = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        u32::try_from(integer(&id["seqno"])?)?,
        hex(&id["root_hash"], false)?,
        hex(&id["file_hash"], false)?,
    );
    let account_root = virtual0(boc(&ctx["account"])?);
    let now = u32::try_from(integer(&ctx["now"])?)?;
    let lt = u64::try_from(integer(&ctx["lt"])?)?;
    let seed = hex(&ctx["rand_seed"], true)?;
    let method_text =
        ctx["method_id"].as_str().ok_or_else(|| anyhow!("expected method ID text"))?;
    let method: i64 = method_text.parse()?;
    ensure!(method.to_string() == method_text, "noncanonical method ID");
    let gas = integer(&ctx["gas_limit"])?;
    ensure!(gas >= 0, "negative gas limit");
    let items = ctx["stack"].as_array().ok_or_else(|| anyhow!("expected stack"))?;
    ensure!(items.len() <= 255, "initial stack too deep");
    let mut storage = items.iter().map(|v| shared::parse_item(v, 0)).collect::<Result<Vec<_>>>()?;
    storage.push(StackItem::int(method));
    let (state, config) = match extract_config(state_root.clone(), &current) {
        Ok(result) => result,
        Err(_) => return Ok(json!({"outcome":"context_unavailable"})),
    };
    let account = match Account::construct_from_full_cell(account_root) {
        Ok(account) if account.is_active() => account,
        _ => return Ok(json!({"outcome":"no_state"})),
    };
    let mut info = SmartContractInfo::with_params(Some(&account), None, None)?;
    info.config_params = config;
    info.unix_time = now;
    info.block_lt = lt;
    info.trans_lt = lt;
    info.rand_seed = IntegerData::from_unsigned_bytes_be(seed.as_slice());
    info.prev_blocks_info = PrevBlocksInfo::Tuple(if info.config_params.global_version() >= 4 {
        SmartContractInfo::get_method_prev_blocks_info(&state, &current)?
    } else {
        StackItem::None
    });
    let c7 = info.as_get_method_data_item()?;
    let mut controls = SaveList::new();
    controls.put(7, c7)?;
    controls.put(4, StackItem::cell(account.get_data().unwrap_or_default()))?;
    let mut libraries = vec![state.libraries().clone().inner()];
    if info.config_params.global_version() < 15 {
        libraries.push(account.libraries().inner());
    }
    let mut vm = Engine::with_capabilities(info.config_params.capabilities())
        .setup_with_optional_code(
            account.get_code(),
            controls,
            Stack::with_storage(storage),
            Gas::new(gas, 0, gas, 10),
            libraries,
        )?;
    vm.set_block_version(info.config_params.global_version());
    let result = vm.execute();
    let exit = match &result {
        Ok(code) => *code,
        Err(error) if tvm_exception_code(error) == Some(ExceptionCode::OutOfGas) => -14,
        Err(error) => tvm_exception_or_custom_code(error),
    };
    let mut budget = 1 << 20;
    let output = if exit == -14 {
        vec![vm.gas_used().to_string()]
    } else {
        let marker = result.is_err()
            && vm
                .stack()
                .get(0)
                .ok()
                .and_then(|v| v.as_integer().ok())
                .is_some_and(|n| n.to_string() == exit.to_string());
        (usize::from(marker)..vm.stack().depth())
            .rev()
            .map(|i| shared::render(vm.stack().get(i)?, 0, &mut budget))
            .collect::<Result<Vec<_>>>()?
    };
    Ok(json!({"outcome":"executed", "exit_code":exit, "gas_used":vm.gas_used(),
        "stack":output, "missing_library":vm.missing_library().map(|h| format!("{:X}", h))}))
}
fn main() -> Result<()> {
    let harness = std::env::args().nth(1).unwrap_or_default();
    if harness == "--info" {
        println!("{}", json!({"harnesses":["get_method"]}));
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
        let response = (|| -> Result<Value> {
            ensure!(size <= 16 << 20, "context too large");
            ensure!(harness == "get_method", "unsupported harness");
            run_getter(&serde_json::from_str::<Value>(&line)?)
        })()
        .unwrap_or_else(|e| json!({"harness_error":e.to_string()}));
        serde_json::to_writer(&mut output, &response)?;
        writeln!(output)?;
        output.flush()?;
        ensure!(size <= 16 << 20, "context too large");
    }
    Ok(())
}
