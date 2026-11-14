// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::{bytes_effect, Inputs, MAX_INPUT};
use anyhow::{bail, ensure, Context, Result};
use rtos_api::session_identity::{
    explicit_session_group_bytes, session_config_hash_from_hash, session_members,
    ExplicitSessionCoordinates, ExplicitSessionOptions,
};
use rtos_block::{base64_decode, PqConsensusKey, SigPubKey, UInt256, ValidatorDescr};
use serde_json::{json, Value};

pub(super) fn u32_field(value: &Value, name: &str) -> Result<u32> {
    Ok(value[name].as_u64().context("unsigned integer required")?.try_into()?)
}
pub(super) fn i32_field(value: &Value, name: &str) -> Result<i32> {
    Ok(value[name].as_i64().context("signed integer required")?.try_into()?)
}
fn flag(value: &Value, name: &str) -> Result<bool> {
    value[name].as_bool().context("boolean required")
}
pub(super) fn bits(value: &Value) -> Result<UInt256> {
    let text = value.as_str().context("hex identifier required")?;
    ensure!(text.len() == 64, "32-byte identifier required");
    let bytes: [u8; 32] = hex::decode(text)?.try_into().unwrap();
    Ok(bytes.into())
}
pub(super) fn descriptors(input: &Inputs<'_>) -> Result<Vec<ValidatorDescr>> {
    let list = input.values["validators"].as_array().context("validators array required")?;
    ensure!(list.len() <= 1024, "too many validators");
    list.iter()
        .map(|value| {
            let local = Inputs { values: value, edits: vec![] };
            let weight = local.uint64("weight")?;
            let adnl = bits(&value["adnl"])?;
            match value["kind"].as_str().context("descriptor kind required")? {
                "classical" => Ok(ValidatorDescr::with_params(
                    SigPubKey::from_bytes(bits(&value["public_key"])?.as_slice())?,
                    weight,
                    Some(adnl),
                )),
                "pq" => {
                    let text = value["public_key"].as_str().context("base64 key required")?;
                    ensure!(text.len() <= MAX_INPUT.div_ceil(3) * 4, "key too large");
                    let public_key = base64_decode(text)?;
                    ensure!(public_key.len() <= MAX_INPUT, "key too large");
                    Ok(ValidatorDescr::with_pq_params(
                        bits(&value["validator_id"])?,
                        PqConsensusKey {
                            algorithm_id: u32_field(value, "algorithm_id")?.try_into()?,
                            key_id: bits(&value["key_id"])?,
                            public_key,
                        },
                        weight,
                        adnl,
                    ))
                }
                _ => bail!("unknown descriptor kind"),
            }
        })
        .collect()
}
fn decimal_double(value: &Value, name: &str) -> Result<f64> {
    let text = value[name].as_str().context("decimal text required")?;
    ensure!(
        !text.is_empty()
            && text.len() <= 32
            && !text.starts_with('.')
            && !text.ends_with('.')
            && text.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            && text.bytes().filter(|b| *b == b'.').count() <= 1,
        "plain decimal required"
    );
    Ok(text.parse()?)
}
pub(super) fn run(operation: &str, input: &Inputs<'_>) -> Result<Value> {
    let v = input.values;
    Ok(match operation {
        "config_hash" => bytes_effect(
            session_config_hash_from_hash(
                i32_field(v, "global_id")?,
                &bits(&v["validator_options_hash"])?,
                &bits(&v["simplex_config_cell_hash"])?,
            )
            .as_slice(),
        ),
        "members" => {
            let members = session_members(&descriptors(input)?)?;
            let encoded = members
                .iter()
                .map(rtos_api::serialize_boxed)
                .collect::<rtos_block::Result<Vec<_>>>()?;
            let ids = encoded
                .iter()
                .map(|b| format!("{:08x}", u32::from_le_bytes(b[..4].try_into().unwrap())))
                .collect::<Vec<_>>();
            let bytes = encoded.iter().map(hex::encode).collect::<Vec<_>>();
            let join = |values: Vec<String>| {
                if values.is_empty() {
                    "-".to_owned()
                } else {
                    values.join(",")
                }
            };
            json!({"outcome":"record","fields":{"constructor_ids":join(ids),"members":join(bytes)}})
        }
        "identity" => {
            let config = session_config_hash_from_hash(
                i32_field(v, "global_id")?,
                &bits(&v["validator_options_hash"])?,
                &bits(&v["simplex_config_cell_hash"])?,
            );
            let coords = ExplicitSessionCoordinates {
                workchain: i32_field(v, "workchain")?,
                shard: input.uint64("shard")?,
                catchain_seqno: u32_field(v, "catchain_seqno")?,
                vertical_seqno: u32_field(v, "vertical_seqno")?,
                last_key_block_seqno: u32_field(v, "last_key_block_seqno")?,
                new_catchain_ids: flag(v, "new_catchain_ids")?,
            };
            let bytes = explicit_session_group_bytes(coords, &config, &descriptors(input)?)?;
            json!({"outcome":"record","fields":{"session_config_hash":hex::encode(config.as_slice()),
                "session_id":hex::encode(UInt256::calc_file_hash(&bytes).as_slice())}})
        }
        "options_hash" => {
            let options = ExplicitSessionOptions {
                proto_version: u32_field(v, "proto_version")?,
                new_catchain_ids: flag(v, "new_catchain_ids")?,
                idle_timeout: decimal_double(v, "idle_timeout")?,
                max_deps: u32_field(v, "max_deps")?,
                max_serialized_block_size: u32_field(v, "max_serialized_block_size")?,
                block_hash_covers_data: flag(v, "block_hash_covers_data")?,
                max_block_height_coeff: input.uint64("max_block_height_coeff")?,
                debug_disable_db: flag(v, "debug_disable_db")?,
                round_candidates: u32_field(v, "round_candidates")?,
                next_candidate_delay: decimal_double(v, "next_candidate_delay")?,
                round_attempt_duration: u32_field(v, "round_attempt_duration")?,
                max_round_attempts: u32_field(v, "max_round_attempts")?,
                max_block_size: u32_field(v, "max_block_size")?,
                max_collated_data_size: u32_field(v, "max_collated_data_size")?,
            };
            bytes_effect(UInt256::calc_file_hash(&options.bytes()?).as_slice())
        }
        _ => bail!("unsupported crypto operation"),
    })
}
