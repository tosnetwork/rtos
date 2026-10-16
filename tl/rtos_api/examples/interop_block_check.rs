// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Check a live RPC sample's full BOC against the C++ block and state identities.
use anyhow::{ensure, Context, Result};
use rtos_block::{
    base64_decode, base64_encode, read_single_root_boc, Block, Deserializable, UInt256,
};
use serde_json::{json, Value};
use std::{io::Write, path::PathBuf};

fn hash(value: &Value) -> Result<UInt256> {
    let bytes: [u8; 32] = base64_decode(value.as_str().context("base64 hash required")?)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("32-byte hash required"))?;
    Ok(UInt256::from(bytes))
}

fn identity(value: &Value) -> Result<(i64, i64, u64, UInt256, UInt256)> {
    let shard = match &value["shard"] {
        Value::String(s) => s.parse()?,
        v => v.as_i64().context("shard required")?,
    };
    Ok((
        value["workchain"].as_i64().context("workchain required")?,
        shard,
        value["seqno"].as_u64().context("seqno required")?,
        hash(&value["root_hash"])?,
        hash(&value["file_hash"])?,
    ))
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let request = PathBuf::from(args.next().context("usage: interop_block_check REQUEST OUTPUT")?);
    let output = PathBuf::from(args.next().context("output argument required")?);
    ensure!(args.next().is_none(), "unexpected argument");
    let value: Value = serde_json::from_slice(&std::fs::read(request)?)?;
    let reference = &value["reference"];
    let rust = &value["rust"];
    let zero = identity(&value["zerostate"])?;
    ensure!(zero.0 == -1 && zero.1 == i64::MIN && zero.2 == 0, "invalid pinned zerostate");
    ensure!(
        identity(&reference["init"])? == zero && identity(&rust["init"])? == zero,
        "RPC zerostates differ from the configured identity"
    );
    for id in [
        &reference["last"],
        &reference["init"],
        &rust["last"],
        &rust["init"],
        &value["block"]["id"],
    ] {
        ensure!(id["@type"] == "tos.blockIdExt", "noncanonical block ID type label");
    }
    let expected = identity(&reference["last"])?;
    ensure!(
        expected.0 == -1 && expected.1 == i64::MIN && expected.2 > 0,
        "sample must be a produced masterchain block"
    );
    ensure!(identity(&rust["last"])? == expected, "RPC block identities differ");
    ensure!(identity(&value["block"]["id"])? == expected, "block response identity differs");
    let state = hash(&reference["state_root_hash"])?;
    ensure!(hash(&rust["state_root_hash"])? == state, "RPC state roots differ");
    let data = base64_decode(value["block"]["boc"].as_str().context("block BOC required")?)?;
    ensure!(UInt256::calc_file_hash(&data) == expected.4, "block file hash differs");
    let root = read_single_root_boc(&data)?;
    ensure!(root.repr_hash() == &expected.3, "block cell hash differs");
    let block = Block::construct_from_cell(root)?;
    let info = block.read_info()?;
    ensure!(
        u64::from(info.seq_no()) == expected.2
            && info.shard().workchain_id() == -1
            && info.shard().shard_prefix_with_tag() == 1_u64 << 63,
        "block header identity differs"
    );
    ensure!(
        block.read_state_update()?.new_hash == state,
        "block state update differs from applied states"
    );
    let result = json!({"status":"block_and_state_match", "block":reference["last"],
        "state_root_hash":base64_encode(state.as_slice()), "global_id":block.global_id(),
        "file_hash_checked":true, "cell_hash_checked":true, "header_identity_checked":true,
        "state_update_matches_both":true, "active_signing_qualified":false});
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(output)?;
    file.write_all(&serde_json::to_vec_pretty(&result)?)?;
    println!("{result}");
    Ok(())
}
