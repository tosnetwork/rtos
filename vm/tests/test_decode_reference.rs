// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//
// Instruction decoding compared with the reference VM: the dispatch-table stage (unassigned
// ranges, version gates, short code, instruction gas before operand checks), instruction data
// and reference checks, and the operand rules found by the same matrix. Every expectation was
// produced by the reference driver (see the evidence directory of this change). Gas limit and
// maximum are both the row's gas, as the reference driver sets them.
//
// - decode-vectors.json: readable vectors per gap with the full expected result.
// - decode-matrix*.json: CALLCCARGS with 0..4 stack items, every argument, five versions.
//   Also the cell-typed entry without a cell that RUNVM returns before version 11 for a child
//   that did not commit (c4, c5 or both; committed, uncommitted and abnormal children; every
//   kind of consumer; versions 4 9 10 11 12 16).
// - decode-sweep-*.json (ignored test, run explicitly): every code of every length 1..16 bits
//   at versions 0 3 4 9 12 16; the first, second, middle and last opcode of every reference
//   table interval and its neighbours cut to every length 1..24 bits at versions 0..17; complete
//   instructions of those opcodes with stack operands, references, offsets, a referenced code
//   cell, a c2 handler and gas around the instruction and exception costs. Operand values are
//   sampled, not exhaustive. Results are compared as SHA-256 digests per group of rows.
mod reference;
use reference::{canonical, code_cell, digest, run_case, GasSetup};
use std::collections::HashMap;

fn run(version: u32, gas: i64, source: &str) -> serde_json::Value {
    run_case(version, gas, GasSetup::LimitIsMax, code_cell(source))
}

fn on_large_stack(test: fn()) {
    std::thread::Builder::new().stack_size(1 << 30).spawn(test).unwrap().join().unwrap();
}

fn check_vectors() {
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("data/decode-vectors.json")).unwrap();
    let mut mismatches = vec![];
    for row in rows.as_array().unwrap() {
        let name = row["name"].as_str().unwrap();
        let source = row["source"].as_str().unwrap();
        let actual =
            run(row["version"].as_u64().unwrap() as u32, row["gas"].as_i64().unwrap(), source);
        if actual != row["expected"] {
            mismatches.push(format!(
                "{name}: {source}\n  expected: {}\n  actual:   {actual}",
                row["expected"]
            ));
        }
    }
    assert!(!rows.as_array().unwrap().is_empty());
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

#[test]
fn decode_vectors_match_reference() {
    on_large_stack(check_vectors);
}

fn check_matrix() {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("data/decode-matrix-cases.json")).unwrap();
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("data/decode-matrix.json")).unwrap();
    let mut sources: HashMap<String, (u32, String)> = HashMap::new();
    let mut mismatches = vec![];
    for c in cases.as_array().unwrap() {
        let name = c["name"].as_str().unwrap().to_owned();
        let (version, source) = match c.get("of") {
            Some(of) => sources[of.as_str().unwrap()].clone(),
            None => {
                (c["version"].as_u64().unwrap() as u32, c["source"].as_str().unwrap().to_owned())
            }
        };
        sources.insert(name.clone(), (version, source.clone()));
        let actual = run(version, c["gas"].as_i64().unwrap(), &source);
        let summary = serde_json::json!([
            actual["exit"],
            actual["gas"],
            actual["steps"],
            actual["committed"],
            digest(&actual)
        ]);
        if expected.get(&name) != Some(&summary) {
            mismatches.push(format!("{name}: {source}\n  actual: {actual}"));
        }
    }
    assert_eq!(cases.as_array().unwrap().len(), expected.as_object().unwrap().len());
    assert!(
        mismatches.is_empty(),
        "{}",
        mismatches.iter().take(20).cloned().collect::<Vec<_>>().join("\n")
    );
}

#[test]
fn decode_matrix_matches_reference() {
    on_large_stack(check_matrix);
}

/// `raw:` source of the top `bits` bits of a 24-bit opcode, after an optional raw prefix.
fn raw_source(prefix: &str, prefix_bits: usize, op: u32, bits: usize, refs: usize) -> String {
    let prefix_value =
        if prefix.is_empty() { 0 } else { u128::from_str_radix(prefix, 16).unwrap() };
    let value = (prefix_value << bits) | u128::from(op >> (24 - bits));
    let total = prefix_bits + bits;
    let nbytes = total.div_ceil(8);
    let bytes = (value << (nbytes * 8 - total)).to_be_bytes();
    let data = hex::encode(&bytes[16 - nbytes..]);
    if refs > 0 {
        format!("raw:{total}:{data}:{refs}")
    } else {
        format!("raw:{total}:{data}")
    }
}

/// The sweep rows in generation order: (group, name, version, gas, source).
fn sweep_rows(samples: &[(u32, u8, i64)]) -> Vec<(String, String, u32, i64, String)> {
    let mut rows = vec![];
    for v in [0u32, 3, 4, 9, 12, 16] {
        for bits in 1..=16usize {
            for code in 0..(1u32 << bits) {
                rows.push((
                    format!("A-v{v}-b{bits}"),
                    format!("A-v{v}-b{bits}-{code:x}"),
                    v,
                    1000,
                    raw_source("", 0, code << (24 - bits), bits, 0),
                ));
            }
        }
    }
    for v in 0u32..18 {
        for &(op, _, _) in samples {
            for bits in 1..=24usize {
                rows.push((
                    format!("B-v{v}-{:02x}", op >> 16),
                    format!("B-v{v}-{op:06x}-b{bits}"),
                    v,
                    1000,
                    raw_source("", 0, op, bits, 0),
                ));
            }
        }
    }
    for v in [3u32, 4, 9, 16] {
        for &(op, tot, cost) in samples {
            let group = format!("C-v{v}-{:02x}", op >> 16);
            let n = format!("C-v{v}-{op:06x}");
            let mut add = |suffix: String, gas: i64, source: String| {
                rows.push((group.clone(), format!("{n}-{suffix}"), v, gas, source));
            };
            add("stack3".into(), 1000, raw_source("717273", 24, op, 24, 0));
            add("nop2".into(), 1000, raw_source("0000", 16, op, 24, 0));
            add("coderef".into(), 1000, format!("ref:{}", raw_source("", 0, op, 24, 0)));
            add("c2".into(), 1000, raw_source("917aed52", 32, op, 24, 0));
            for refs in 0..5 {
                add(format!("refs{refs}"), 1000, raw_source("", 0, op, 24, refs));
                let short = if tot > 0 { usize::from(tot).saturating_sub(1).max(1) } else { 8 };
                add(format!("short-refs{refs}"), 1000, raw_source("", 0, op, short, refs));
            }
            if [3, 4, 16].contains(&v) {
                let mut budgets = vec![cost - 1, cost, cost + 1, cost + 49, cost + 50, 9, 10];
                budgets.sort_unstable();
                budgets.dedup();
                for g in budgets.into_iter().filter(|g| *g > 0) {
                    add(format!("gas{g}"), g, raw_source("", 0, op, 24, 0));
                }
            }
        }
    }
    rows
}

fn check_sweeps() {
    // Sample opcodes with the reference table's total bits and instruction cost.
    let samples: serde_json::Value =
        serde_json::from_str(include_str!("data/decode-sweep-samples.json")).unwrap();
    let groups: serde_json::Value =
        serde_json::from_str(include_str!("data/decode-sweep-groups.json")).unwrap();
    let samples = samples
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            let s = s.as_array().unwrap();
            (
                u32::from_str_radix(s[0].as_str().unwrap(), 16).unwrap(),
                s[1].as_u64().unwrap() as u8,
                s[2].as_i64().unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let mut digests: Vec<(String, sha2_state::State, u64)> = vec![];
    for (group, name, version, gas, source) in sweep_rows(&samples) {
        let actual = run(version, gas, &source);
        let mut text = String::new();
        canonical(&actual, &mut text);
        if digests.last().map(|(g, _, _)| g != &group).unwrap_or(true) {
            digests.push((group.clone(), sha2_state::State::default(), 0));
        }
        let entry = digests.last_mut().unwrap();
        entry.1.update(format!("{name}\t{text}\n").as_bytes());
        entry.2 += 1;
    }
    let mut mismatches = vec![];
    for (group, state, count) in digests {
        let actual = serde_json::json!([count, state.finish()]);
        if groups.get(&group) != Some(&actual) {
            mismatches.push(format!("{group}: expected {:?}, actual {actual}", groups.get(&group)));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} groups differ:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

/// Incremental SHA-256 over the rows of a group.
mod sha2_state {
    #[derive(Default)]
    pub struct State(Vec<u8>);
    impl State {
        pub fn update(&mut self, data: &[u8]) {
            self.0.extend_from_slice(data);
        }
        pub fn finish(self) -> String {
            hex::encode(rtos_block::sha256_digest(&self.0))
        }
    }
}

#[test]
#[ignore = "about two million rows; run explicitly with --ignored"]
fn decode_sweeps_match_reference() {
    on_large_stack(check_sweeps);
}
