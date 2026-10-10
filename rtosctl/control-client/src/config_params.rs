/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use anyhow::Context;
use rtos_block::{Coins, ConfigParam15, ConfigParam16, ConfigParam17, ValidatorSet};

pub fn parse_config_param_15(bytes: &[u8]) -> anyhow::Result<ConfigParam15> {
    let param: serde_json::Value =
        serde_json::from_slice(bytes).context("config param 15 is not valid JSON")?;
    let p15 = param
        .get("p15")
        .and_then(|v| v.as_object())
        .ok_or_else(|| anyhow::anyhow!("p15 not found in config param JSON"))?;

    Ok(ConfigParam15 {
        validators_elected_for: p15
            .get("validators_elected_for")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0) as u32,
        elections_start_before: p15
            .get("elections_start_before")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0) as u32,
        elections_end_before: p15
            .get("elections_end_before")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0) as u32,
        stake_held_for: p15.get("stake_held_for").and_then(serde_json::Value::as_u64).unwrap_or(0)
            as u32,
    })
}

pub fn parse_config_param_34(bytes: &[u8]) -> anyhow::Result<ValidatorSet> {
    parse_validator_set(bytes, "p34")
}

pub fn parse_config_param_36(bytes: &[u8]) -> anyhow::Result<ValidatorSet> {
    parse_validator_set(bytes, "p36")
}

fn parse_validator_set(bytes: &[u8], key: &str) -> anyhow::Result<ValidatorSet> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    let map = value.as_object().ok_or_else(|| anyhow::anyhow!("invalid config param"))?;
    let index = match key {
        "p32" => 32,
        "p34" => 34,
        "p36" => 36,
        _ => anyhow::bail!("unsupported validator set parameter {key}"),
    };
    let config = rtos_block_json::parse_config_with_mandatory_params(map, &[index])?;
    match config.config(index)? {
        Some(rtos_block::ConfigParamEnum::ConfigParam32(param)) => Ok(param.prev_validators),
        Some(rtos_block::ConfigParamEnum::ConfigParam34(param)) => Ok(param.cur_validators),
        Some(rtos_block::ConfigParamEnum::ConfigParam36(param)) => Ok(param.next_validators),
        _ => anyhow::bail!("validator set parameter {key} is missing"),
    }
}

pub fn parse_config_param_16(bytes: &[u8]) -> anyhow::Result<ConfigParam16> {
    let param: serde_json::Value =
        serde_json::from_slice(bytes).context("config param 16 is not valid JSON")?;
    let p16 = param
        .get("p16")
        .and_then(|v| v.as_object())
        .ok_or_else(|| anyhow::anyhow!("p16 not found in JSON"))?;

    let max_validators =
        p16.get("max_validators")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| anyhow::anyhow!("max_validators not found"))? as u16;
    let max_main_validators =
        p16.get("max_main_validators")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| anyhow::anyhow!("max_main_validators not found"))? as u16;
    let min_validators =
        p16.get("min_validators")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| anyhow::anyhow!("min_validators not found"))? as u16;

    Ok(ConfigParam16 {
        max_validators: max_validators.into(),
        max_main_validators: max_main_validators.into(),
        min_validators: min_validators.into(),
    })
}

pub fn parse_config_param_17(bytes: &[u8]) -> anyhow::Result<ConfigParam17> {
    let param: serde_json::Value =
        serde_json::from_slice(bytes).context("config param 17 is not valid JSON")?;
    let p17 = param
        .get("p17")
        .and_then(|v| v.as_object())
        .ok_or_else(|| anyhow::anyhow!("p17 not found in JSON"))?;

    let parse_coins = |key: &str| -> anyhow::Result<Coins> {
        let val = p17.get(key).ok_or_else(|| anyhow::anyhow!("{} not found", key))?;
        // It can be a string (decimal) or a number
        if let Some(s) = val.as_str() {
            Ok(Coins::from(u64::from_str_radix(s, 10).context(format!("parse {} as u64", key))?))
        } else if let Some(n) = val.as_u64() {
            Ok(Coins::from(n))
        } else {
            anyhow::bail!("{} is not a valid coins value", key)
        }
    };

    let min_stake = parse_coins("min_stake_dec")?;
    let max_stake = parse_coins("max_stake_dec")?;
    let min_total_stake = parse_coins("min_total_stake_dec")?;
    let max_stake_factor =
        p17.get("max_stake_factor")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| anyhow::anyhow!("max_stake_factor not found"))? as u32;

    Ok(ConfigParam17 { min_stake, max_stake, min_total_stake, max_stake_factor })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtos_block::{MLDSA44_PUBLIC_KEY_BYTES, UInt256, derive_consensus_key_id};

    #[test]
    fn validator_set_json_preserves_pq_and_classical_addresses() {
        let key = vec![7; MLDSA44_PUBLIC_KEY_BYTES];
        let members = serde_json::json!([
            {"public_key": "03".repeat(32), "weight_dec": "1", "adnl_addr": "04".repeat(32)},
            {"key_type": "pq", "algorithm_id": 1, "public_key": hex::encode(&key),
             "key_id": format!("{:x}", derive_consensus_key_id(1, &key)),
             "validator_id": "01".repeat(32), "adnl_addr": "02".repeat(32), "weight_dec": "3"}
        ]);
        for index in [34, 36] {
            let field = format!("p{index}");
            let mut json = serde_json::json!({field.clone(): {
                "utime_since": 1, "utime_until": 100, "total": 2, "main": 1,
                "total_weight_dec": "4", "list": members.clone()
            }});
            let parse = |value: &serde_json::Value| {
                let bytes = serde_json::to_vec(value).unwrap();
                if index == 34 {
                    parse_config_param_34(&bytes)
                } else {
                    parse_config_param_36(&bytes)
                }
            };
            let set = parse(&json).unwrap();
            assert_eq!(set.total_weight(), 4);
            assert_eq!(set.list()[0].adnl_addr, Some(UInt256::from([4; 32])));
            assert_eq!(set.list()[1].validator_id().unwrap(), UInt256::from([1; 32]));
            assert_eq!(set.list()[1].pq_key().unwrap().public_key, key);
            json[&field]["list"][1]["key_id"] = serde_json::json!("05".repeat(32));
            assert!(parse(&json).is_err());
        }
    }
}
