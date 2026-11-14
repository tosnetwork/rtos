// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use adnl::rldp2::{budget, FecHelper, DEFAULT_MTU, PART_SIZE, SYMBOL_SIZE};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
fn decimal(v: &Value) -> Result<u64> {
    let text = v.as_str().context("decimal string required")?;
    ensure!(
        !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()),
        "decimal string required"
    );
    Ok(text.parse()?)
}
pub(super) fn run(v: &Value) -> Result<Value> {
    if v["op"] == "rldp2_fec_helper" {
        let count = u32::try_from(v["symbols_count"].as_u64().context("uint32 required")?)?;
        let received =
            u32::try_from(v["received_symbols_count"].as_u64().context("uint32 required")?)?;
        ensure!(count <= 1 << 30 && received <= 1 << 30, "counts at most2^30");
        let helper = FecHelper { symbols_count: count, received_symbols_count: received };
        return Ok(
            json!({"outcome":"fec_helper","fec_symbols_count":helper.target().context("FEC counters overflow")?,
            "left_fec_symbols_count":helper.remaining().context("FEC counters overflow")?}),
        );
    }
    let data = decimal(&v["data_size"])?;
    let symbol = decimal(&v["symbol_size"])?;
    let count = decimal(&v["symbols_count"])?;
    Ok(
        json!({"outcome":"budget","reservation_bytes":budget::decoder_reservation_bytes(data,symbol,count).map(|x|x.to_string()),
        "solver_bytes":budget::solver_working_bytes(symbol,count).map(|x|x.to_string()),
        "part_size":PART_SIZE,"symbol_size":SYMBOL_SIZE,"default_mtu":DEFAULT_MTU}),
    )
}
