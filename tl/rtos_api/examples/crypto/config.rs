// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::{identity::u32_field, Inputs, MAX_INPUT};
use anyhow::{ensure, Context, Result};
use rtos_block::{
    base64_decode, read_single_root_boc, sha256_digest, BuilderData, Cell, Deserializable,
    HashmapE, HashmapType, IBitstring, Serializable, SizeLimitsConfig, SliceData, ValidatorKey,
    ValidatorSet,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

fn refused() -> Value {
    json!({"outcome":"rejected","reason":"refused"})
}
pub(super) fn size_limits(input: &mut Inputs<'_>) -> Result<Value> {
    let root = read_single_root_boc(input.bytes("boc")?)?;
    let Ok(value) = SizeLimitsConfig::construct_from_full_cell(root) else { return Ok(refused()) };
    let mut fields = BTreeMap::new();
    macro_rules! fields { ($($name:ident),* $(,)?) => { $(fields.insert(stringify!($name),value.$name.to_string());)* }; }
    fields!(
        max_msg_bits,
        max_msg_cells,
        max_library_cells,
        max_vm_data_depth,
        max_ext_msg_size,
        max_ext_msg_depth,
        max_acc_state_cells,
        max_mc_acc_state_cells,
        max_acc_public_libraries,
        defer_out_queue_size_limit,
        max_msg_extra_currencies,
        max_acc_fixed_prefix_length,
        acc_state_cells_for_storage_dict,
        max_total_msg_bits,
        max_total_msg_cells,
        out_msg_queue_size_hard_limit,
        out_msg_queue_size_soft_limit
    );
    fields.insert(
        "max_transaction_library_loads",
        value.max_transaction_library_loads.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
    );
    Ok(json!({"outcome":"record","fields":fields}))
}
fn wrap(input: &Inputs<'_>) -> Result<Cell> {
    let v = input.values;
    let descriptors = v["descriptors"].as_array().context("descriptors array required")?;
    ensure!(!descriptors.is_empty() && descriptors.len() <= 64, "1..64 descriptors required");
    let mut dict = HashmapE::with_bit_len(16);
    for (i, value) in descriptors.iter().enumerate() {
        let text = value.as_str().context("descriptor base64 required")?;
        ensure!(text.len() <= MAX_INPUT.div_ceil(3) * 4, "descriptor too large");
        let bytes = base64_decode(text)?;
        ensure!(bytes.len() <= MAX_INPUT, "descriptor too large");
        let root = read_single_root_boc(bytes)?;
        dict.set((i as u16).write_to_bitstring()?, &SliceData::load_cell(root)?)?;
    }
    let mut cell = BuilderData::new();
    cell.append_u8(0x12)?
        .append_u32(u32_field(v, "utime_since")?)?
        .append_u32(u32_field(v, "utime_until")?)?
        .append_u16(u32_field(v, "total")?.try_into()?)?
        .append_u16(u32_field(v, "main")?.try_into()?)?
        .append_u64(input.uint64("total_weight")?)?;
    dict.write_hashmap_data(&mut cell)?;
    Ok(cell.into_cell()?)
}
pub(super) fn validators(input: &mut Inputs<'_>) -> Result<Value> {
    let root = if input.values.get("set").is_some() {
        read_single_root_boc(input.bytes("set")?)?
    } else {
        wrap(input)?
    };
    let Ok(set) = ValidatorSet::construct_from_full_cell(root) else { return Ok(refused()) };
    let mut fields = BTreeMap::new();
    fields.insert("utime_since", set.utime_since().to_string());
    fields.insert("utime_until", set.utime_until().to_string());
    fields.insert("total", set.total().to_string());
    fields.insert("main", set.main().to_string());
    fields.insert("total_weight", set.total_weight().to_string());
    let mut ids = vec![];
    let mut keys = vec![];
    let mut algorithms = vec![];
    let mut weights = vec![];
    let mut adnl = vec![];
    let mut public = vec![];
    for node in set.list() {
        ids.push(hex::encode(node.validator_id()?.as_slice()));
        keys.push(hex::encode(node.consensus_key_id()?.as_slice()));
        weights.push(node.weight.to_string());
        adnl.push(hex::encode(node.adnl_addr.clone().unwrap_or_default().as_slice()));
        match &node.key {
            ValidatorKey::Ed25519(key) => {
                algorithms.push("0".into());
                public.push(hex::encode(key.as_slice()));
            }
            ValidatorKey::Pq(key) => {
                algorithms.push(key.algorithm_id.to_string());
                public.push(hex::encode(sha256_digest(&key.public_key)));
            }
        }
    }
    for (name, values) in [
        ("validator_ids", ids),
        ("key_ids", keys),
        ("algorithm_ids", algorithms),
        ("weights", weights),
        ("adnl_addrs", adnl),
        ("public_keys", public),
    ] {
        fields.insert(name, if values.is_empty() { "-".into() } else { values.join(",") });
    }
    Ok(json!({"outcome":"record","fields":fields}))
}
