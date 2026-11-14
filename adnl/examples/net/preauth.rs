// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use adnl::preauth::{preauth_source, DecryptBudget, PreauthGate};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
};
fn uint(v: &Value) -> Result<u32> {
    Ok(v.as_u64().context("uint32 required")?.try_into()?)
}
fn address(v: &Value) -> Result<SocketAddr> {
    let text = v["ip"].as_str().context("IP string required")?;
    ensure!(text.len() <= 64, "IP too long");
    let ip: IpAddr = if text.contains(':') {
        text.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(text).parse()?
    } else {
        text.parse()?
    };
    let port = uint(&v["port"])?;
    ensure!((1..=65535).contains(&port), "port1..65535 required");
    Ok(SocketAddr::new(ip, port as u16))
}
fn budget(v: &Value) -> Result<(u32, f64, usize)> {
    let burst = uint(&v["burst"])?;
    let period = v["period"].as_f64().context("number period required")?;
    let limit = uint(&v["in_flight_limit"])? as usize;
    ensure!(
        (1..=4096).contains(&burst) && period.is_finite() && (60.0..=1e9).contains(&period),
        "invalid local budget config"
    );
    Ok((burst, period, limit))
}
pub(super) fn run(v: &Value) -> Result<Value> {
    if v["op"] == "preauth_source" {
        let source = preauth_source(address(&v["address"])?);
        return Ok(
            json!({"outcome":"source","source":{"ip":source.ip().to_string(),"port":source.port()}}),
        );
    }
    let max_sources = uint(&v["max_sources"])? as usize;
    ensure!((1..=1024).contains(&max_sources), "max_sources1..1024 required");
    let (burst, period, _) = budget(&v["source"])?;
    let (pb, pp, pl) = budget(&v["process"])?;
    let (lb, lp, ll) = budget(&v["local"])?;
    let process = DecryptBudget::new(pb, pp, pl)?;
    let local = DecryptBudget::new(lb, lp, ll)?;
    let gate = PreauthGate::<i32>::new(max_sources, burst, period)?;
    let events = v["events"].as_array().context("events array required")?;
    ensure!(events.len() <= 4096, "too many events");
    let mut tickets = BTreeMap::new();
    let mut results = Vec::new();
    for (index, event) in events.iter().enumerate() {
        ensure!(event.is_object(), "event object required");
        let result = if let Some(addr) = event.get("admit") {
            match gate.admit(address(addr)?, process.clone(), local.clone()) {
                Ok(ticket) => {
                    tickets.insert(index, ticket);
                    "admitted"
                }
                Err(error) => error.code(),
            }
        } else if let Some(release) = event.get("release") {
            let index: usize =
                release.as_i64().context("int64 release index required")?.try_into()?;
            ensure!(tickets.remove(&index).is_some(), "release of event without held ticket");
            "released"
        } else {
            anyhow::bail!("admit or release required")
        };
        results.push(result);
    }
    let held = tickets.len();
    tickets.clear();
    Ok(json!({"outcome":"gate","results":results,"sources":gate.len(),"held":held}))
}
