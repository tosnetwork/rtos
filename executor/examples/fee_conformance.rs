// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Explicit-price conformance boundary using the node's native fee functions.
use anyhow::{anyhow, bail, ensure, Result};
use rtos_block::{compute_storage_fees, GasLimitsPrices, MsgPrices, StoragePrices};
use serde_json::{json, Value};
use std::io::{self, BufRead, Read, Write};

fn decimal(ctx: &Value, field: &str, max_len: usize) -> Result<u128> {
    let text = ctx[field].as_str().ok_or_else(|| anyhow!("{field}: expected decimal string"))?;
    ensure!(
        !text.is_empty() && text.len() <= max_len && text.bytes().all(|c| c.is_ascii_digit()),
        "{field}: invalid unsigned decimal"
    );
    Ok(text.parse()?)
}
fn u64_field(ctx: &Value, field: &str) -> Result<u64> {
    Ok(u64::try_from(decimal(ctx, field, 20)?)?)
}
fn u32_field(ctx: &Value, field: &str) -> Result<u32> {
    Ok(u32::try_from(ctx[field].as_i64().ok_or_else(|| anyhow!("{field}: expected integer"))?)?)
}
fn flag(ctx: &Value, field: &str) -> Result<bool> {
    ctx[field].as_bool().ok_or_else(|| anyhow!("{field}: expected boolean"))
}
fn run_fee(ctx: &Value) -> Result<Value> {
    Ok(match ctx["kind"].as_str().ok_or_else(|| anyhow!("missing fee kind"))? {
        "storage" => {
            let now = u32_field(ctx, "now")?;
            let last_paid = u32_field(ctx, "last_paid")?;
            let cells = u64_field(ctx, "cells")?;
            let bits = u64_field(ctx, "bits")?;
            let special = flag(ctx, "special")?;
            let masterchain = flag(ctx, "masterchain")?;
            let values =
                ctx["periods"].as_array().ok_or_else(|| anyhow!("expected price periods"))?;
            ensure!(values.len() <= 64, "too many price periods");
            let periods = values
                .iter()
                .map(|p| -> Result<_> {
                    Ok(StoragePrices {
                        utime_since: u32_field(p, "since")?,
                        bit_price_ps: u64_field(p, "bit_price")?,
                        cell_price_ps: u64_field(p, "cell_price")?,
                        mc_bit_price_ps: u64_field(p, "mc_bit_price")?,
                        mc_cell_price_ps: u64_field(p, "mc_cell_price")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let fee =
                compute_storage_fees(&periods, cells, bits, last_paid, now, special, masterchain);
            json!({"outcome":"storage", "fee":fee.map(|value| value.to_string())})
        }
        "gas_purchase" => {
            let prices = GasLimitsPrices {
                gas_price: u64_field(ctx, "gas_price")?,
                gas_limit: u64_field(ctx, "gas_limit")?,
                flat_gas_limit: u64_field(ctx, "flat_gas_limit")?,
                flat_gas_price: u64_field(ctx, "flat_gas_price")?,
                ..Default::default()
            };
            let balance = decimal(ctx, "balance", 39)?;
            let threshold = prices.compute_max_gas_threshold(prices.gas_limit);
            let bought = prices.gas_bought_for(
                balance,
                prices.gas_limit,
                prices.calc_max_gas_threshold(prices.gas_limit),
            )?;
            let gas = balance as u64;
            json!({"outcome":"gas_purchase", "threshold":threshold.to_string(), "gas_bought":bought.to_string(),
                "fee":prices.compute_gas_price(gas).to_string(), "simple_fee":prices.compute_simple_gas_price(gas).to_string()})
        }
        "forward" => {
            let prices = MsgPrices {
                lump_price: u64_field(ctx, "lump_price")?,
                bit_price: u64_field(ctx, "bit_price")?,
                cell_price: u64_field(ctx, "cell_price")?,
                ihr_factor: u32_field(ctx, "ihr_factor")?,
                first_frac: u32_field(ctx, "first_frac")?,
                next_frac: u32_field(ctx, "next_frac")?,
            };
            let cells = u64_field(ctx, "cells")?;
            let bits = u64_field(ctx, "bits")?;
            let disabled = ctx
                .get("ihr_disabled")
                .map(|v| v.as_bool().ok_or_else(|| anyhow!("expected boolean")))
                .transpose()?
                .unwrap_or(false);
            let fee = prices.compute_fwd_fees(cells, bits);
            let wide = prices.compute_fwd_fees256(cells, bits);
            let (ihr_fwd, ihr) = prices.compute_fwd_ihr_fees(cells, bits, disabled);
            json!({"outcome":"forward", "fwd_fee":fee.to_string(), "fwd_fee_256":wide.to_string(),
                "ihr_fwd_fee":ihr_fwd.to_string(), "ihr_fee":ihr.to_string(),
                "first_part":prices.get_first_part(fee).to_string(),
                "first_part_256":prices.get_first_part256(&wide).to_string(),
                "next_part_256":prices.get_next_part256(&wide).to_string()})
        }
        _ => bail!("unsupported fee kind"),
    })
}
fn main() -> Result<()> {
    let harness = std::env::args().nth(1).unwrap_or_default();
    if harness == "--info" {
        println!("{}", json!({"harnesses":["fee"]}));
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
        let result = (|| -> Result<Value> {
            ensure!(size <= 16 << 20, "context too large");
            ensure!(harness == "fee", "unsupported harness");
            run_fee(&serde_json::from_str::<Value>(&line)?)
        })()
        .unwrap_or_else(|e| json!({"harness_error":e.to_string()}));
        serde_json::to_writer(&mut output, &result)?;
        writeln!(output)?;
        output.flush()?;
        ensure!(size <= 16 << 20, "context too large");
    }
    Ok(())
}
