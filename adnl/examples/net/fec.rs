// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use adnl::fec::{Algorithm, Decoder, Encoder, Parameters};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};

fn uint(v: &Value) -> Result<u32> {
    Ok(v.as_u64().context("uint32 required")?.try_into()?)
}
fn ids(v: &Value) -> Result<Vec<u32>> {
    let list = v.as_array().context("symbol id array required")?;
    ensure!(list.len() <= 1024, "too many requested symbols");
    list.iter()
        .map(|v| {
            let id = uint(v)?;
            ensure!(id < 1 << 24, "symbol id out of range");
            Ok(id)
        })
        .collect()
}
fn parameters(p: Parameters) -> Value {
    json!({"data_size":p.data_size,"symbol_size":p.symbol_size,"symbols_count":p.symbols_count})
}
fn symbols(encoder: &mut Encoder, ids: Vec<u32>) -> Result<Vec<Value>> {
    ids.into_iter()
        .map(|id| {
            let (id, data) = encoder.symbol(id)?;
            Ok(json!({"id":id,"data":hex::encode(data)}))
        })
        .collect()
}
pub(super) fn run(v: &Value) -> Result<Value> {
    let algorithm = match v["algorithm"].as_str() {
        Some("raptorq") => Algorithm::RaptorQ,
        Some("round_robin") => Algorithm::RoundRobin,
        Some("online") => bail!("unsupported net operation"),
        _ => bail!("unknown FEC algorithm"),
    };
    let size = uint(&v["symbol_size"])?;
    if v["op"] == "fec_encode" {
        let data = super::bytes(v, "data", 1 << 20)?;
        let mut encoder = Encoder::new(algorithm, data, size)?;
        ensure!(encoder.parameters().symbols_count <= 10000, "too many source symbols");
        return Ok(
            json!({"outcome":"encoded","parameters":parameters(encoder.parameters()),"symbols":symbols(&mut encoder, ids(&v["symbol_ids"])?)?}),
        );
    }
    let data_size = uint(&v["data_size"])? as usize;
    ensure!(data_size <= 1 << 20, "local data size too large");
    let p = Parameters { data_size, symbol_size: size, symbols_count: uint(&v["symbols_count"])? };
    ensure!(p.symbols_count <= 10000, "too many source symbols");
    let list = v["symbols"].as_array().context("symbols array required")?;
    ensure!(list.len() <= 4096, "too many supplied symbols");
    let regenerate = v.get("regenerate").map(ids).transpose()?;
    let mut decoder = Decoder::new(algorithm, p)?;
    let mut added = Vec::new();
    for item in list {
        added.push(
            match decoder.add_symbol(uint(&item["id"])?, super::bytes(item, "data", 2049)?) {
                Ok(()) => "ok",
                Err(e) => e.0,
            },
        );
    }
    let may = decoder.may_try_decode();
    let mut effect = json!({"outcome":"decode","added":added,"may_try_decode":may,"reason":null,"data_sha256":null,"data":null,"regenerated":null});
    match decoder.try_decode() {
        Err(e) => effect["reason"] = json!(e.0),
        Ok(data) => {
            effect["data_sha256"] = json!(hex::encode(rtos_block::sha256_digest(data)));
            if data.len() <= 4096 {
                effect["data"] = json!(hex::encode(data));
            }
            if let Some(ids) = regenerate {
                let mut encoder = Encoder::new(algorithm, data.to_vec(), size)?;
                effect["regenerated"] = json!(symbols(&mut encoder, ids)?);
            }
        }
    }
    Ok(effect)
}
