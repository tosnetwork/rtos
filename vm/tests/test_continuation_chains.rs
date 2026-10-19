// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//
// Continuation chains, loop bodies, envelopes, PushInt, TRY and the nested-jump charge compared
// with results produced by the reference VM. Every row runs one code cell and compares the exit
// code, gas, steps, committed roots, the final stack and the live c0..c3, with every reachable
// continuation rendered as canonical structural text (node table keyed by content hash).
//
// Rendering conventions: see reference/mod.rs.
//
// Expected values are produced by the reference driver only (see the evidence directory of this
// change); nothing in the expectation file is written by hand.
mod reference;
use reference::{code_cell, digest, load, run_case, GasSetup};
use std::collections::HashMap;

fn check_all() {
    let cases = load("RTOS_CONT_CHAIN_CASES", include_str!("data/continuation-chain-cases.json"));
    let expected = load("RTOS_CONT_CHAIN_EXPECTED", include_str!("data/continuation-chain.json"));
    let export = std::env::var("RTOS_CONT_CHAIN_EXPORT").ok();
    let filter = std::env::var("RTOS_CONT_CHAIN_FILTER").unwrap_or_default();
    let mut sources: HashMap<String, (u32, String)> = HashMap::new();
    let mut rows = vec![];
    let mut mismatches = vec![];
    let mut checked = 0usize;
    for c in cases.as_array().unwrap() {
        let name = c["name"].as_str().unwrap().to_owned();
        // A row may reuse the code and version of an earlier row with another gas budget.
        let (version, source) = match c.get("of") {
            Some(of) => sources[of.as_str().unwrap()].clone(),
            None => {
                (c["version"].as_u64().unwrap() as u32, c["source"].as_str().unwrap().to_owned())
            }
        };
        sources.insert(name.clone(), (version, source.clone()));
        if !name.contains(&filter) {
            continue;
        }
        let gas = c["gas"].as_i64().unwrap();
        let code = code_cell(&source);
        let boc = hex::encode(rtos_block::write_boc(&code).unwrap());
        let actual = run_case(version, gas, GasSetup::TestLimit, code);
        if export.is_none() {
            checked += 1;
            let summary = serde_json::json!([
                actual["exit"],
                actual["gas"],
                actual["steps"],
                actual["committed"],
                digest(&actual)
            ]);
            if expected.get(&name) != Some(&summary) {
                mismatches.push(format!(
                    "{name}\n  source: {source}\n  expected: {}\n  actual:   {summary} {actual}",
                    expected.get(&name).map(|e| e.to_string()).unwrap_or_default(),
                ));
            }
        }
        rows.push(serde_json::json!({
            "name": name, "version": version, "gas": gas, "code": boc, "actual": actual
        }));
    }
    if let Some(path) = export {
        std::fs::write(path, serde_json::to_vec_pretty(&rows).unwrap()).unwrap();
        return;
    }
    assert!(checked > 0);
    if filter.is_empty() {
        assert_eq!(checked, expected.as_object().unwrap().len(), "case and expectation counts");
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} rows differ from the reference:\n{}",
        mismatches.len(),
        checked,
        mismatches.iter().take(20).cloned().collect::<Vec<_>>().join("\n")
    );
}

#[test]
fn continuation_chains_match_reference() {
    // Deep continuation graphs are rendered recursively here (test code only).
    std::thread::Builder::new().stack_size(1 << 30).spawn(check_all).unwrap().join().unwrap();
}
