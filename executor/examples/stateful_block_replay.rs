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
    io::{self, BufRead, Read, Seek, SeekFrom, Write},
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
    peak_master_contexts: usize,
}

fn load(input: &Value, key: &str) -> Result<Original> {
    if key == "block" && input.get("package").is_some() {
        ensure!(input.get("block").is_none(), "choose either block or package input");
        let path = input["package"].as_str().ok_or_else(|| anyhow!("missing package path"))?;
        let offset = input["offset"].as_u64().ok_or_else(|| anyhow!("missing entry offset"))?;
        let name = input["name"].as_str().ok_or_else(|| anyhow!("missing entry name"))?;
        ensure!(name.starts_with("block_(") && name.len() <= 1024, "invalid block entry name");
        let header_offset = offset
            .checked_sub(name.len() as u64 + 8)
            .ok_or_else(|| anyhow!("invalid entry offset"))?;
        ensure!(header_offset >= 4, "entry overlaps package header");
        let mut file = std::fs::File::open(path).with_context(|| path.to_owned())?;
        let mut magic = [0; 4];
        file.read_exact(&mut magic)?;
        ensure!(u32::from_le_bytes(magic) == 0xae8fdd01, "invalid package magic");
        file.seek(SeekFrom::Start(header_offset))?;
        let mut header = [0; 8];
        file.read_exact(&mut header)?;
        ensure!(u16::from_le_bytes([header[0], header[1]]) == 0x1e8b, "invalid entry tag");
        ensure!(
            usize::from(u16::from_le_bytes([header[2], header[3]])) == name.len(),
            "entry name length mismatch"
        );
        let size = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
        ensure!(size > 0 && size <= 256 << 20, "invalid entry size");
        let mut actual_name = vec![0; name.len()];
        file.read_exact(&mut actual_name)?;
        ensure!(actual_name == name.as_bytes(), "archive entry name mismatch");
        let root = input["root_hash"].as_str().ok_or_else(|| anyhow!("missing root hash"))?;
        let hash = input["file_hash"].as_str().ok_or_else(|| anyhow!("missing file hash"))?;
        ensure!(
            root.len() == 64
                && hash.len() == 64
                && name.to_ascii_uppercase().ends_with(&format!(":{root}:{hash}")),
            "archive entry identity mismatch"
        );
        let end = offset.checked_add(size as u64).ok_or_else(|| anyhow!("entry size overflow"))?;
        ensure!(end <= file.metadata()?.len(), "truncated archive entry");
        let mut bytes = vec![0; size];
        file.read_exact(&mut bytes)?;
        return Ok(Original { root: read_single_root_boc(&bytes)?, bytes });
    }
    let path = input[key].as_str().ok_or_else(|| anyhow!("missing {key} path"))?;
    let bytes = std::fs::read(path).with_context(|| path.to_owned())?;
    Ok(Original { root: read_single_root_boc(&bytes)?, bytes })
}

fn validated_block(input: &Value) -> Result<(Original, Block)> {
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
    if input.get("package").is_some() {
        let name = input["name"].as_str().ok_or_else(|| anyhow!("missing entry name"))?;
        let position = name
            .strip_prefix("block_(")
            .and_then(|s| s.split_once("):"))
            .ok_or_else(|| anyhow!("invalid archive block position"))?
            .0;
        let fields: Vec<_> = position.split(',').collect();
        ensure!(fields.len() == 3, "invalid archive block position");
        ensure!(
            fields[0].parse::<i32>()? == info.shard().workchain_id()
                && u64::from_str_radix(fields[1], 16)? == info.shard().shard_prefix_with_tag()
                && fields[2].parse::<u32>()? == info.seq_no(),
            "archive block position mismatch"
        );
    }
    ensure!(!info.after_merge() && !info.after_split(), "split/merge unsupported");
    Ok((original, block))
}

fn inspect(input: &Value) -> Result<Value> {
    let (_, block) = validated_block(input)?;
    let info = block.read_info()?;
    let previous = info.read_prev_ref()?.prev1()?;
    let master = info.read_master_ref()?.map(|_| info.read_master_id()).transpose()?;
    Ok(json!({"workchain":info.shard().workchain_id(),
        "shard":format!("{:016X}", info.shard().shard_prefix_with_tag()),
        "seqno":info.seq_no(), "prev_seqno":previous.seq_no,
        "prev_root_hash":format!("{:X}",previous.root_hash),
        "prev_file_hash":format!("{:X}",previous.file_hash),
        "master_seqno":master.as_ref().map(|m|m.seq_no),
        "master_root_hash":master.as_ref().map(|m|format!("{:X}",m.root_hash)),
        "master_file_hash":master.as_ref().map(|m|format!("{:X}",m.file_hash))}))
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
        if let Some(root) = input.get("release_master") {
            ensure!(input.as_object().is_some_and(|o| o.len() == 1), "release must be standalone");
            let hash: UInt256 =
                root.as_str().ok_or_else(|| anyhow!("invalid release hash"))?.parse()?;
            ensure!(self.masters.remove(&hash).is_some(), "master context not retained");
            return Ok(json!({"released_master":root}));
        }
        let (original, block) = validated_block(input)?;
        let root = original.root.hash(0).clone();
        let file = UInt256::calc_file_hash(&original.bytes);
        let info = block.read_info()?;
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
            self.peak_master_contexts = self.peak_master_contexts.max(self.masters.len());
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
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(args.is_empty() || args == ["--inspect"], "expected no arguments or --inspect");
    let inspect_only = !args.is_empty();
    let mut inspected = 0u64;
    let mut replay = Replay::default();
    let mut output = io::stdout().lock();
    for (line_no, line) in io::stdin().lock().lines().enumerate() {
        let result = serde_json::from_str::<Value>(&line?)
            .map_err(anyhow::Error::from)
            .and_then(|input| if inspect_only { inspect(&input) } else { replay.step(&input) });
        match result {
            Ok(effect) => {
                inspected += u64::from(inspect_only);
                serde_json::to_writer(&mut output, &effect)?;
                writeln!(output)?;
                output.flush()?;
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
    ensure!(replay.blocks > 0 || inspected > 0, "empty replay");
    eprintln!(
        "{}",
        json!({"blocks":replay.blocks,"transactions":replay.transactions,
        "inspected":inspected,"peak_master_contexts":replay.peak_master_contexts,
        "retained_master_contexts":replay.masters.len()})
    );
    Ok(())
}
