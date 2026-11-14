// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Offline replay of ordered raw blocks. No intermediate states are accepted.
//! Input JSONL: {"zerostate":"path"}, then {"block":"path",
//! "root_hash":"HEX", "file_hash":"HEX"}. Paths name original BOCs.
//! The caller supplies dependency order. This tool refuses missing parents,
//! forks and split/merge; it is not a signature or full block-validity checker.
#[allow(dead_code)]
#[path = "block_conformance.rs"]
mod boundary;

use anyhow::{anyhow, ensure, Context, Result};
use boundary::Original;
use rtos_block::{
    read_single_root_boc, Block, Cell, Deserializable, ShardIdent, ShardStateUnsplit, UInt256,
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    io::{self, BufRead, Write},
};

struct State {
    seqno: u32,
    root: UInt256,
    file: UInt256,
    cell: Cell,
}

#[derive(Default)]
struct Replay {
    heads: HashMap<ShardIdent, State>,
    masters: HashMap<UInt256, (Original, Cell)>,
    started: bool,
    blocks: u64,
    transactions: u64,
}

fn load(input: &Value, key: &str) -> Result<Original> {
    let path = input[key].as_str().ok_or_else(|| anyhow!("missing {key} path"))?;
    let bytes = std::fs::read(path).with_context(|| path.to_owned())?;
    Ok(Original { root: read_single_root_boc(&bytes)?, bytes })
}

impl Replay {
    fn step(&mut self, input: &Value) -> Result<Value> {
        if input.get("zerostate").is_some() {
            ensure!(!self.started, "zerostates must precede all blocks");
            let original = load(input, "zerostate")?;
            let state = ShardStateUnsplit::construct_from_full_cell(original.root.clone())?;
            ensure!(state.seq_no() == 0, "bootstrap must be a zerostate");
            ensure!(!self.heads.contains_key(state.shard()), "duplicate zerostate");
            let root = original.root.hash(0).clone();
            let file = UInt256::calc_file_hash(&original.bytes);
            self.heads.insert(
                state.shard().clone(),
                State { seqno: 0, root: root.clone(), file: file.clone(), cell: original.root },
            );
            return Ok(json!({"bootstrap":true,"root_hash":format!("{root:X}"),
                "file_hash":format!("{file:X}")}));
        }
        self.started = true;
        let original = load(input, "block")?;
        let root = original.root.hash(0).clone();
        let file = UInt256::calc_file_hash(&original.bytes);
        ensure!(
            input["root_hash"].as_str() == Some(format!("{root:X}").as_str()),
            "archive block root mismatch"
        );
        ensure!(
            input["file_hash"].as_str() == Some(format!("{file:X}").as_str()),
            "archive block file hash mismatch"
        );
        let block = Block::construct_from_full_cell(original.root.clone())?;
        let info = block.read_info()?;
        ensure!(!info.after_merge() && !info.after_split(), "split/merge unsupported");
        let head =
            self.heads.get(info.shard()).ok_or_else(|| anyhow!("missing chain bootstrap"))?;
        let prev = info.read_prev_ref()?.prev1()?;
        ensure!(
            prev.seq_no == head.seqno && prev.root_hash == head.root && prev.file_hash == head.file,
            "predecessor block identity mismatch"
        );
        ensure!(head.seqno.checked_add(1) == Some(info.seq_no()), "nonconsecutive block");
        let master_id = info.read_master_ref()?.map(|_| info.read_master_id()).transpose()?;
        let master = master_id
            .as_ref()
            .map(|id| {
                self.masters
                    .get(&id.root_hash)
                    .ok_or_else(|| anyhow!("masterchain context not replayed"))
            })
            .transpose()?;
        let mut why = "malformed_block";
        let mut effect =
            boundary::apply(&original, &head.cell, master.map(|(b, s)| (b, s)), &mut why)
                .with_context(|| why)?;
        let (next, _) = block.read_state_update()?.apply_for(&head.cell)?;
        let state = ShardStateUnsplit::construct_from_full_cell(next.clone())?;
        ensure!(
            state.seq_no() == info.seq_no() && state.shard() == info.shard(),
            "resulting state header mismatch"
        );
        let transactions = effect["transactions"]
            .as_array()
            .ok_or_else(|| anyhow!("missing transaction effects"))?
            .len() as u64;
        self.heads.insert(
            info.shard().clone(),
            State { seqno: info.seq_no(), root, file: file.clone(), cell: next.clone() },
        );
        if info.shard().is_masterchain() {
            self.masters.insert(original.root.hash(0).clone(), (original, next));
        }
        self.blocks += 1;
        self.transactions += transactions;
        effect["file_hash"] = json!(format!("{file:X}"));
        effect["workchain"] = json!(info.shard().workchain_id());
        effect["seqno"] = json!(info.seq_no());
        Ok(effect)
    }
}

fn main() -> Result<()> {
    let mut replay = Replay::default();
    let mut output = io::stdout().lock();
    for (line_no, line) in io::stdin().lock().lines().enumerate() {
        let result = serde_json::from_str::<Value>(&line?)
            .map_err(anyhow::Error::from)
            .and_then(|input| replay.step(&input));
        match result {
            Ok(effect) => {
                serde_json::to_writer(&mut output, &effect)?;
                writeln!(output)?;
            }
            Err(error) => {
                writeln!(
                    output,
                    "{}",
                    json!({"replay_error":format!("{error:#}"),
                    "line":line_no + 1,"blocks":replay.blocks,"transactions":replay.transactions})
                )?;
                output.flush()?;
                return Err(error);
            }
        }
    }
    ensure!(replay.blocks > 0, "empty replay");
    eprintln!("{}", json!({"blocks":replay.blocks,"transactions":replay.transactions}));
    Ok(())
}
