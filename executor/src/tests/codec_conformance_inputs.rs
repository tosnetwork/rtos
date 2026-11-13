// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Input construction only. Expected effects are filled by the clean C++ CLI.
use super::*;

fn cell(bits: &str, refs: &[Cell]) -> Cell {
    let mut builder = BuilderData::new();
    for bit in bits.bytes() {
        builder.append_bit_bool(bit == b'1').unwrap();
    }
    for child in refs {
        builder.checked_append_reference(child.clone()).unwrap();
    }
    builder.into_cell().unwrap()
}
fn zeros(n: usize) -> String {
    "0".repeat(n)
}
fn mc(aux: Cell, shards: Option<Cell>, balance: &str) -> Cell {
    let config = cell("110100000", &[Cell::default()]);
    let mut refs = vec![];
    if let Some(shards) = shards {
        refs.push(shards);
    }
    let bits = format!("{:016b}{}{}{}", 0xcc26, u8::from(!refs.is_empty()), zeros(256), balance);
    refs.extend([config, aux]);
    cell(&bits, &refs)
}
fn mc_aux(
    flags: u16,
    old: Option<Cell>,
    stats: &str,
    stats_refs: &[Cell],
    old_extra: &str,
) -> Cell {
    let bits =
        format!("{flags:016b}{}{}{}00{stats}", zeros(65), u8::from(old.is_some()), old_extra);
    let mut refs = old.into_iter().collect::<Vec<_>>();
    refs.extend_from_slice(stats_refs);
    cell(&bits, &refs)
}
fn state(queue: Cell, accounts: Cell, custom: Option<Cell>, prefix: u8) -> Cell {
    let mut refs = vec![queue, accounts, cell(&zeros(140), &[])];
    let bits = format!(
        "{:032b}{}00{prefix:06b}{}0{}",
        0x9023afe2u32,
        zeros(32),
        zeros(96 + 192),
        u8::from(custom.is_some())
    );
    refs.extend(custom);
    cell(&bits, &refs)
}

#[test]
#[ignore]
fn export_constructed_state_codec_contexts() {
    let mut rows = Vec::new();
    let mut add = |name: &str, kind: &str, root: &Cell, budget: u32| {
        rows.push(json!({"fixture_id":name,"context":{"type":kind,"boc":rtos_block::base64_encode(rtos_block::write_boc(root).unwrap()),"max_cells":budget}}));
    };
    let aux = mc_aux(0, None, "", &[], &zeros(65));
    let minimal = mc(aux.clone(), None, "00000");
    for budget in [1, 2, 3, 4, 1024] {
        add(&format!("mc-min-budget-{budget}"), "McStateExtra", &minimal, budget);
    }
    add("mc-nonminimal-balance", "McStateExtra", &mc(aux.clone(), None, "0001000000000"), 1024);
    add(
        "mc-unknown-flags",
        "McStateExtra",
        &mc(mc_aux(2, None, "", &[], &zeros(65)), None, "00000"),
        1024,
    );
    let old_leaf = cell(&format!("110100000{}", zeros(65 + 609)), &[]);
    add(
        "mc-old-block-extra-differs",
        "McStateExtra",
        &mc(mc_aux(0, Some(old_leaf), "", &[], &"1".repeat(65)), None, "00000"),
        1024,
    );
    for (name, stats) in [
        ("stats-empty", format!("{:08b}0", 0x17)),
        ("stats-aug-empty", format!("{:08b}0{}", 0x34, zeros(32))),
    ] {
        add(
            &format!("mc-{name}"),
            "McStateExtra",
            &mc(mc_aux(1, None, &stats, &[], &zeros(65)), None, "00000"),
            1024,
        );
    }
    let creator = cell(&format!("110100000000{}0100{}", zeros(32), zeros(448)), &[]);
    // hml_same for all-zero 256-bit keys is 11 0 100000000 (12 bits).
    let stats = format!("{:08b}1{}", 0x34, zeros(32));
    add(
        "mc-stats-aug-leaf",
        "McStateExtra",
        &mc(mc_aux(1, None, &stats, &[creator], &zeros(65)), None, "00000"),
        1024,
    );
    let creator_child = cell(&format!("11011111111{}0100{}", zeros(32), zeros(448)), &[]);
    let stats_fork = cell(&format!("00{}", zeros(32)), &[creator_child.clone(), creator_child]);
    let forked = mc(mc_aux(1, None, &stats, &[stats_fork], &zeros(65)), None, "00000");
    for budget in [5, 6, 1024] {
        add(&format!("mc-stats-fork-budget-{budget}"), "McStateExtra", &forked, budget);
    }
    for (label, flags) in [("valid", 0), ("bad-flags", 1)] {
        let descr = cell(
            &format!("0{:04b}{}{flags:03b}{}0{}", 0xb, zeros(704 + 5), zeros(160), zeros(10)),
            &[],
        );
        let shards = cell("110100000", &[descr]);
        add(
            &format!("mc-shard-descr-{label}"),
            "McStateExtra",
            &mc(aux.clone(), Some(shards), "00000"),
            1024,
        );
        if flags == 0 {
            let tree_leaf = cell(
                &format!("0{:04b}{}{flags:03b}{}0{}", 0xb, zeros(704 + 5), zeros(160), zeros(10)),
                &[],
            );
            let fork = cell("1", &[tree_leaf.clone(), tree_leaf]);
            let shards = cell("110100000", &[fork]);
            let forked = mc(aux.clone(), Some(shards), "00000");
            for budget in [6, 7] {
                add(&format!("mc-shard-fork-budget-{budget}"), "McStateExtra", &forked, budget);
            }
        }
    }
    let queue = cell(&zeros(67), &[]);
    let accounts = cell(&zeros(11), &[]);
    let plain = state(queue.clone(), accounts.clone(), None, 0);
    for budget in [1, 2, 3, 4, 1024] {
        add(&format!("state-min-budget-{budget}"), "ShardStateUnsplit", &plain, budget);
    }
    add(
        "state-shard-depth61",
        "ShardStateUnsplit",
        &state(queue.clone(), accounts.clone(), None, 61),
        1024,
    );
    let nonzero_queue = cell(&format!("0{:064b}00", 1u64), &[]);
    add(
        "state-empty-queue-extra1",
        "ShardStateUnsplit",
        &state(nonzero_queue, accounts.clone(), None, 0),
        1024,
    );
    let nonzero_accounts = cell("0000110001000000010", &[]);
    add(
        "state-empty-accounts-extra",
        "ShardStateUnsplit",
        &state(queue.clone(), nonzero_accounts, None, 0),
        1024,
    );
    let extra_queue = cell(&format!("{}10{}1{}", zeros(66), zeros(65), zeros(48)), &[]);
    add(
        "state-dispatch-empty",
        "ShardStateUnsplit",
        &state(extra_queue, accounts.clone(), None, 0),
        1024,
    );
    // The preceding input has only one tag bit; #0 is a four-bit tag.
    let valid_extra_queue = cell(&format!("{}10000{}1{}", zeros(66), zeros(65), zeros(48)), &[]);
    add(
        "state-dispatch-valid",
        "ShardStateUnsplit",
        &state(valid_extra_queue, accounts.clone(), None, 0),
        1024,
    );
    let custom = state(queue, accounts, Some(minimal), 0);
    for budget in [4, 6, 7, 1024] {
        add(&format!("state-custom-budget-{budget}"), "ShardStateUnsplit", &custom, budget);
    }
    let path = std::env::var("RTOS_CODEC_CONTEXTS_OUT").expect("RTOS_CODEC_CONTEXTS_OUT");
    let text = rows.iter().map(|r| format!("{r}\n")).collect::<String>();
    std::fs::write(path, text).unwrap();
}
