// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//
// Shared harness of the reference matrices: runs one code cell and renders every observable
// (exit code, gas, steps, committed roots, final stack, live c0..c3 and every reachable
// continuation as canonical structural text) in the format of the reference driver.
//
// Rendering conventions shared with the reference driver: stacks are listed top first; a null
// captured stack and an empty one both render as "[]" (no observable difference: the reference
// treats both alike when jumping, calling, capturing and returning arguments); ordinary
// continuations carry code page 0 and envelopes -1, and both values are printed, so a
// different value would show up as a mismatch; a cell-typed entry without a cell renders as
// "cell:none".
#![allow(dead_code)]
use rtos_block::{ExceptionCode, UInt256};
use rtos_vm::{
    error::{tvm_exception_code, tvm_exception_or_custom_code},
    executor::{gas::gas_state::Gas, Engine},
    stack::{
        continuation::{ContinuationData, ContinuationType},
        savelist::SaveList,
        Stack, StackItem,
    },
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

#[derive(Default)]
pub struct Renderer {
    nodes: BTreeMap<String, String>,
    memo: HashMap<usize, String>,
}

pub fn hex_hash(hash: &UInt256) -> String {
    format!("{:x}", hash)
}

pub fn slice_content(slice: &rtos_block::SliceData) -> String {
    let bits = (0..slice.remaining_bits())
        .map(|i| if slice.get_bit_opt(i).unwrap() { '1' } else { '0' })
        .collect::<String>();
    let refs = (0..slice.remaining_references())
        .map(|i| hex_hash(&slice.reference(i).unwrap().repr_hash()))
        .collect::<Vec<_>>()
        .join("|");
    format!("{bits}:{refs}")
}

impl Renderer {
    pub fn item(&mut self, item: &StackItem) -> String {
        match item {
            StackItem::None => "null".into(),
            StackItem::Integer(n) => {
                if n.is_nan() {
                    "int:NaN".into()
                } else {
                    format!("int:{n}")
                }
            }
            StackItem::Cell(cell) => format!("cell:{}", hex_hash(&cell.repr_hash())),
            StackItem::AbsentCell => "cell:none".into(),
            StackItem::Builder(builder) => {
                format!(
                    "builder:{}",
                    hex_hash(&(**builder).clone().into_cell().unwrap().repr_hash())
                )
            }
            StackItem::Slice(slice) => format!("slice:{}", slice_content(slice)),
            StackItem::Tuple(items) => {
                let items = items.iter().map(|x| self.item(x)).collect::<Vec<_>>();
                format!("tuple[{}]", items.join("|"))
            }
            StackItem::Continuation(cont) => format!("cont:{}", self.cont_arc(cont)),
        }
    }

    fn stack(&mut self, stack: &Stack) -> String {
        let items =
            (0..stack.depth()).map(|i| self.item(stack.get(i).unwrap())).collect::<Vec<_>>();
        format!("[{}]", items.join(","))
    }

    fn cdata(&mut self, cont: &ContinuationData, cp: i32) -> String {
        let stack = self.stack(&cont.stack);
        let mut save = vec![];
        for i in SaveList::REGS {
            if let Some(item) = cont.savelist.get(i) {
                save.push(format!("{i}:{}", self.item(item)));
            }
        }
        format!("cp:{cp},nargs:{},stack:{stack},save:{{{}}}", cont.nargs, save.join(","))
    }

    fn cont_arc(&mut self, cont: &Arc<ContinuationData>) -> String {
        let key = Arc::as_ptr(cont) as usize;
        if let Some(id) = self.memo.get(&key) {
            return id.clone();
        }
        let id = self.cont(cont);
        self.memo.insert(key, id.clone());
        id
    }

    fn cont(&mut self, cont: &ContinuationData) -> String {
        let has_cdata = cont.has_cdata();
        if !has_cdata {
            assert!(
                cont.nargs == -1
                    && cont.stack.is_empty()
                    && cont.savelist.is_empty()
                    && cont.code().remaining_bits() == 0
                    && cont.code().remaining_references() == 0,
                "a continuation without control data carries control data"
            );
        }
        let text = match &cont.type_of {
            ContinuationType::Ordinary => {
                format!("ord{{{},code:{}}}", self.cdata(cont, 0), slice_content(cont.code()))
            }
            ContinuationType::Envelope(next) => {
                assert_eq!(cont.code().remaining_bits(), 0);
                let data = self.cdata(cont, -1);
                format!("env{{{data},next:{}}}", self.cont_arc(next))
            }
            ContinuationType::Quit(code) => format!("quit{{{code}}}"),
            ContinuationType::ExcQuit => "excquit".into(),
            ContinuationType::PushInt(value, next) => {
                format!("pushint{{{value},next:{}}}", self.cont_arc(next))
            }
            ContinuationType::Repeat { count, body, after } => {
                let body = self.cont_arc(body);
                let after = self.cont_arc(after);
                format!("repeat{{{count},body:{body},after:{after}}}")
            }
            ContinuationType::Again { body } => format!("again{{body:{}}}", self.cont_arc(body)),
            ContinuationType::Until { body, after } => {
                let body = self.cont_arc(body);
                let after = self.cont_arc(after);
                format!("until{{body:{body},after:{after}}}")
            }
            ContinuationType::While { check_cond, cond, body, after } => {
                let cond = self.cont_arc(cond);
                let body = self.cont_arc(body);
                let after = self.cont_arc(after);
                let at = if *check_cond { "cond" } else { "body" };
                format!("while{{{at},cond:{cond},body:{body},after:{after}}}")
            }
        };
        let digest = rtos_block::sha256_digest(text.as_bytes());
        let id = format!("#{}", hex::encode(&digest[..16]));
        self.nodes.insert(id.clone(), text);
        id
    }

    fn register(&mut self, item: Option<&StackItem>) -> String {
        match item {
            None => "none".into(),
            Some(StackItem::Continuation(cont)) => self.cont_arc(cont),
            Some(other) => panic!("control register holds {other}"),
        }
    }
}

/// How the gas of a row is set up.
#[derive(Clone, Copy)]
pub enum GasSetup {
    /// The test default maximum with the row's limit (continuation matrix).
    TestLimit,
    /// Limit and maximum both equal to the row's gas (as the reference driver sets them).
    LimitIsMax,
}

pub fn run_case(
    version: u32,
    gas_limit: i64,
    gas_setup: GasSetup,
    code: rtos_block::Cell,
) -> serde_json::Value {
    let mut ctrls = SaveList::new();
    ctrls.put(7, StackItem::tuple(vec![])).unwrap();
    let mut vm = Engine::with_capabilities(0)
        .setup_checked(
            code,
            ctrls,
            Stack::new(),
            match gas_setup {
                GasSetup::TestLimit => Gas::test_with_limit(gas_limit),
                GasSetup::LimitIsMax => Gas::new(gas_limit, 0, gas_limit, 10),
            },
            vec![],
        )
        .unwrap();
    vm.set_block_version(version);
    let result = vm.execute();
    let failed = result.is_err();
    let exit = match &result {
        Ok(n) => *n,
        Err(e) if tvm_exception_code(e) == Some(ExceptionCode::OutOfGas) => -14,
        Err(e) => tvm_exception_or_custom_code(e),
    };
    let mut r = Renderer::default();
    let stack = if exit == -14 {
        vec![format!("int:{}", vm.gas_used())]
    } else {
        if failed {
            assert_eq!(
                vm.stack().get(0).unwrap().as_integer().unwrap().to_string(),
                exit.to_string()
            );
        }
        (usize::from(failed)..vm.stack().depth())
            .map(|i| r.item(vm.stack().get(i).unwrap()))
            .collect::<Vec<_>>()
    };
    let ctrls = (0..4).map(|i| r.register(vm.ctrls().get(i))).collect::<Vec<_>>();
    let gas = vm.gas_used();
    let steps = vm.steps();
    let committed = vm.is_committed_state();
    let roots = vm
        .get_committed_state()
        .map(|(a, b)| vec![hex_hash(&a.repr_hash()), hex_hash(&b.repr_hash())]);
    serde_json::json!({
        "exit": exit,
        "gas": gas,
        "steps": steps,
        "committed": committed,
        "roots": roots,
        "stack": stack,
        "ctrls": ctrls,
        "nodes": r.nodes,
    })
}

pub fn load(env: &str, embedded: &str) -> serde_json::Value {
    match std::env::var(env) {
        Ok(path) => serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap(),
        Err(_) => serde_json::from_str(embedded).unwrap(),
    }
}

/// Canonical JSON text: object keys sorted, no whitespace (independent of map ordering features).
pub fn canonical(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort();
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).unwrap());
                out.push(':');
                canonical(&map[key], out);
            }
            out.push('}');
        }
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&serde_json::to_string(other).unwrap()),
    }
}

/// Digest of the canonical JSON text of a full result.
pub fn digest(result: &serde_json::Value) -> String {
    let mut text = String::new();
    canonical(result, &mut text);
    hex::encode(rtos_block::sha256_digest(text.as_bytes()))
}

/// Code of a row: assembler source, `raw:<bits>:<hex>[:<refs>]` (that many data bits and `refs`
/// references, reference i holding the single instruction PUSHINT i+1), or `ref:<spec>` (an empty
/// cell whose only reference is the cell of `<spec>`).
pub fn code_cell(source: &str) -> rtos_block::Cell {
    if let Some(inner) = source.strip_prefix("ref:") {
        let mut b = rtos_block::BuilderData::new();
        b.checked_append_reference(code_cell(inner)).unwrap();
        return b.into_cell().unwrap();
    }
    let Some(raw) = source.strip_prefix("raw:") else {
        return rtos_assembler::compile_code_to_cell(source)
            .unwrap_or_else(|e| panic!("{source}: {e}"));
    };
    let parts = raw.split(':').collect::<Vec<_>>();
    let bits = parts[0].parse::<usize>().unwrap();
    let mut bytes = hex::decode(parts[1]).unwrap();
    if bytes.is_empty() {
        bytes.push(0);
    }
    let mut b = rtos_block::BuilderData::with_raw(bytes, bits).unwrap();
    let refs = parts.get(2).map(|r| r.parse::<usize>().unwrap()).unwrap_or(0);
    for i in 0..refs {
        let child = rtos_block::BuilderData::with_raw(vec![0x71 + i as u8], 8).unwrap();
        b.checked_append_reference(child.into_cell().unwrap()).unwrap();
    }
    b.into_cell().unwrap()
}
