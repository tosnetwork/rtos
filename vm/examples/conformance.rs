// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Line-protocol target for the shared C++ conformance runner.
use anyhow::{anyhow, bail, ensure, Result};
use rtos_block::{base64_decode, read_single_root_boc, Cell, ExceptionCode, HashmapE, SliceData};
use rtos_vm::{
    error::{tvm_exception_code, tvm_exception_or_custom_code},
    executor::{gas::gas_state::Gas, Engine},
    stack::{
        continuation::{ContinuationData, ContinuationType},
        savelist::SaveList,
        Stack, StackItem,
    },
};
use serde_json::{json, Value};
use std::io::{self, BufRead, Read, Write};

fn string(v: &Value) -> Result<&str> {
    v.as_str().ok_or_else(|| anyhow!("expected string"))
}
fn boc(v: &Value) -> Result<Cell> {
    read_single_root_boc(base64_decode(string(v)?)?)
}
fn integer(v: &Value) -> Result<i64> {
    v.as_i64().ok_or_else(|| anyhow!("expected signed 64-bit integer"))
}
fn array(v: &Value) -> Result<&Vec<Value>> {
    v.as_array().ok_or_else(|| anyhow!("expected array"))
}
pub(crate) fn parse_item(v: &Value, depth: usize) -> Result<StackItem> {
    ensure!(depth <= 32, "stack item nesting too deep");
    Ok(match string(&v["type"])? {
        "null" => StackItem::None,
        "nan" => StackItem::nan(),
        "int" => {
            let text = string(&v["value"])?;
            ensure!(text.len() <= 255, "integer text too long");
            // The reference decimal parser returns zero for an empty string.
            if text.is_empty() {
                StackItem::int(0)
            } else {
                let digits = text.strip_prefix('-').unwrap_or(text);
                ensure!(
                    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()),
                    "invalid decimal integer"
                );
                StackItem::big_int(text)?
            }
        }
        "cell" => StackItem::cell(boc(&v["boc"])?),
        "slice" => StackItem::slice(SliceData::load_cell(boc(&v["boc"])?)?),
        "tuple" => {
            let items = array(&v["items"])?;
            ensure!(items.len() <= 255, "tuple too long");
            StackItem::tuple(items.iter().map(|x| parse_item(x, depth + 1)).collect::<Result<_>>()?)
        }
        kind => bail!("unsupported stack type {kind}"),
    })
}
fn hash(cell: &Cell) -> String {
    format!("{:X}", cell.repr_hash())
}
pub(crate) fn render(item: &StackItem, depth: usize, budget: &mut usize) -> Result<String> {
    ensure!(depth <= 512, "final stack value nested too deep");
    *budget = budget.checked_sub(1).ok_or_else(|| anyhow!("final stack value too large"))?;
    Ok(match item {
        StackItem::None => "null".into(),
        StackItem::Integer(n) => {
            if n.is_nan() {
                "NaN".into()
            } else {
                n.to_string()
            }
        }
        StackItem::Cell(c) => format!("cell:{}", hash(c)),
        StackItem::AbsentCell => "cell:nullptr".into(),
        StackItem::Slice(s) => format!(
            "slice:{}:{}-{}:{}-{}",
            hash(&s.cell()?),
            s.pos(),
            s.pos() + s.remaining_bits(),
            s.get_references().start,
            s.get_references().end
        ),
        StackItem::Builder(b) => {
            let c = (**b).clone().into_cell()?;
            let s = SliceData::load_cell(c.clone())?;
            format!("builder:{}:{}:{}", s.remaining_bits(), s.remaining_references(), hash(&c))
        }
        StackItem::Tuple(items) => format!(
            "({})",
            items
                .iter()
                .map(|x| render(x, depth + 1, budget))
                .collect::<Result<Vec<_>>>()?
                .join(" ")
        ),
        StackItem::Continuation(c) => {
            let kind = match c.type_of {
                ContinuationType::Ordinary => "vmc_std",
                ContinuationType::Envelope(_) => "vmc_envelope",
                ContinuationType::Quit(_) => "vmc_quit",
                ContinuationType::ExcQuit => "vmc_quit_exc",
                ContinuationType::PushInt(..) => "vmc_pushint",
                ContinuationType::Repeat { .. } => "vmc_repeat",
                ContinuationType::Again { .. } => "vmc_again",
                ContinuationType::Until { .. } => "vmc_until",
                ContinuationType::While { check_cond: true, .. } => "vmc_while_cond",
                ContinuationType::While { check_cond: false, .. } => "vmc_while_body",
            };
            let mut text = format!("cont:{kind}");
            if c.has_cdata() {
                let save = [0, 1, 2, 3, 4, 5, 7]
                    .into_iter()
                    .filter(|i| c.savelist.get(*i).is_some())
                    .map(|i| format!("c{i}"))
                    .collect::<String>();
                let save = if save.is_empty() { "none" } else { &save };
                let captured = c
                    .stack
                    .iter()
                    .map(|x| render(x, depth + 1, budget))
                    .collect::<Result<Vec<_>>>()?
                    .join(" ");
                text += &format!(":nargs={}:save={save}:stack=[{captured}]", c.nargs);
            }
            text
        }
    })
}
fn run_vm(ctx: &Value) -> Result<Value> {
    let version = integer(&ctx["global_version"])?;
    ensure!((0..=255).contains(&version), "invalid global version");
    let flags = ctx.get("flags").map(integer).transpose()?.unwrap_or(0);
    ensure!((0..=255).contains(&flags), "invalid VM flags");
    let gas = &ctx["gas"];
    let limit = integer(&gas["limit"])?;
    let max = integer(&gas["max"])?;
    let credit = gas.get("credit").map(integer).transpose()?.unwrap_or(0);
    ensure!(
        limit >= 0 && max >= 0 && credit >= 0 && limit.checked_add(credit).is_some(),
        "invalid gas limits"
    );
    let mut controls = SaveList::new();
    if flags & 1 == 0 {
        controls.put(
            3,
            StackItem::continuation(ContinuationData::with_type(ContinuationType::Quit(11))),
        )?;
    }
    controls.put(
        7,
        match ctx.get("c7") {
            Some(v) => {
                let item = parse_item(v, 0)?;
                ensure!(item.is_tuple(), "c7 must be tuple");
                item
            }
            None => StackItem::tuple(vec![]),
        },
    )?;
    if let Some(data) = ctx.get("data") {
        controls.put(4, StackItem::cell(boc(data)?))?;
    }
    let items = array(&ctx["stack"])?;
    ensure!(items.len() <= 255, "initial stack too deep");
    let mut stack = Stack::new();
    for item in items {
        stack.push(parse_item(item, 0)?);
    }
    if flags & 3 == 3 {
        stack.push_int(0);
    }
    let mut libraries = vec![];
    if let Some(values) = ctx.get("libraries") {
        let values = array(values)?;
        ensure!(values.len() <= 4, "too many libraries");
        for v in values {
            libraries.push(HashmapE::with_hashmap(256, Some(boc(v)?)));
        }
    }
    let mut vm = Engine::with_capabilities(0).setup_checked(
        boc(&ctx["code"])?,
        controls,
        stack,
        Gas::new(limit, credit, max, 10),
        libraries,
    )?;
    vm.set_block_version(version as u32);
    if let Some(value) = ctx.get("max_library_loads") {
        vm.set_max_library_loads(u32::try_from(integer(value)?)?);
    }
    if let Some(value) = ctx.get("chksig_always_succeed") {
        let mut behavior = vm.behavior_modifiers().clone();
        behavior.chksig_always_succeed =
            value.as_bool().ok_or_else(|| anyhow!("expected boolean"))?;
        vm.modify_behavior(behavior);
    }
    let result = vm.execute();
    let exit = match &result {
        Ok(code) => *code,
        Err(e) if tvm_exception_code(e) == Some(ExceptionCode::OutOfGas) => -14,
        Err(e) => tvm_exception_or_custom_code(e),
    };
    let mut budget = 1 << 20;
    let output = if exit == -14 {
        vec![vm.gas_used().to_string()]
    } else {
        // RTOS exposes an uncaught VM exception code on top of the stack.
        // An internal execution error may return without that marker; preserve
        // its actual stack so the comparator reports a behavioural mismatch.
        let marker = result.is_err()
            && vm
                .stack()
                .get(0)
                .ok()
                .and_then(|item| item.as_integer().ok())
                .is_some_and(|n| n.to_string() == exit.to_string());
        (usize::from(marker)..vm.stack().depth())
            .rev()
            .map(|i| render(vm.stack().get(i)?, 0, &mut budget))
            .collect::<Result<Vec<_>>>()?
    };
    let gas_used = vm.gas_used();
    let steps = vm.steps();
    let committed = vm.is_committed_state();
    let state = vm.get_committed_state();
    Ok(json!({"exit_code": exit, "gas_used": gas_used, "steps": steps, "committed": committed,
        "c4_hash": state.as_ref().map(|(a, _)| hash(a)), "c5_hash": state.as_ref().map(|(_, b)| hash(b)), "stack": output}))
}
fn main() -> Result<()> {
    let harness = std::env::args().nth(1).ok_or_else(|| anyhow!("usage: conformance <harness>"))?;
    if harness == "--info" {
        println!("{}", json!({"harnesses": ["vm"]}));
        return Ok(());
    }
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    let mut input = io::stdin().lock();
    loop {
        let mut line = String::new();
        let size = input.by_ref().take((16 << 20) + 2).read_line(&mut line)?;
        if size == 0 {
            break;
        }
        let effect = (|| -> Result<Value> {
            ensure!(size <= 16 << 20, "context too large");
            let context = serde_json::from_str(&line)?;
            match harness.as_str() {
                "vm" => run_vm(&context),
                _ => bail!("unsupported harness {harness}"),
            }
        })()
        .unwrap_or_else(|e| json!({"harness_error": e.to_string()}));
        serde_json::to_writer(&mut stdout, &effect)?;
        writeln!(stdout)?;
        stdout.flush()?;
        ensure!(size <= 16 << 20, "context too large");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_gas_boundary_matches_reference() {
        fn resolve(value: Value, blobs: &Value) -> Value {
            match value {
                Value::Object(map) if map.len() == 1 && map.contains_key("blob") => {
                    blobs[map["blob"].as_str().unwrap()].clone()
                }
                Value::Object(map) => Value::Object(
                    map.into_iter().map(|(key, value)| (key, resolve(value, blobs))).collect(),
                ),
                Value::Array(items) => {
                    Value::Array(items.into_iter().map(|value| resolve(value, blobs)).collect())
                }
                value => value,
            }
        }
        let blobs: Value = serde_json::from_str(include_str!(
            "../tests/data/conformance/vm/fixtures/signature-gas-boundary.blobs.json"
        ))
        .unwrap();
        for line in
            include_str!("../tests/data/conformance/vm/fixtures/signature-gas-boundary.jsonl")
                .lines()
        {
            let row: Value = serde_json::from_str(line).unwrap();
            let context = resolve(row["context"].clone(), &blobs);
            assert_eq!(
                run_vm(&context).unwrap(),
                row["effects"],
                "{}",
                row["metadata"]["fixture_id"]
            );
        }
    }

    #[test]
    fn integer_context_refuses_nondecimal_and_oversized_text() {
        for text in ["0x123", "+1", "1_0", "NaN", "-", " 1", "1 "] {
            assert!(
                parse_item(&json!({"type": "int", "value": text}), 0).is_err(),
                "accepted {text}"
            );
        }
        assert!(parse_item(&json!({"type": "int", "value": "0".repeat(256)}), 0).is_err());
        assert!(parse_item(&json!({"type": "int", "value": "9".repeat(78)}), 0).is_err());
    }
}
