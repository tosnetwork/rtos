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

#[test]
#[ignore]
fn export_handwritten_state_contexts() {
    fn coins(n: u8) -> String {
        if n == 0 {
            "00000".into()
        } else {
            format!("0001{n:08b}0")
        }
    }
    fn depth_balance(depth: u8, balance: u8) -> String {
        format!("{depth:05b}{}", coins(balance))
    }
    fn account(depth: u8, balance: u8) -> Cell {
        let cast =
            if depth == 0 { "0".into() } else { format!("1{depth:05b}{}", zeros(depth as usize)) };
        cell(&format!("110{cast}{}{}{}{}00", zeros(264), zeros(42), zeros(64), coins(balance)), &[])
    }
    fn accounts_leaf(n: usize, account: Cell, extra: &str) -> Cell {
        let width = (usize::BITS - n.leading_zeros()) as usize;
        cell(&format!("110{n:0width$b}{extra}{}", zeros(320)), &[account])
    }
    fn accounts_root(root: Cell, extra: &str) -> Cell {
        cell(&format!("1{extra}"), &[root])
    }
    fn message(lt: u64) -> Cell {
        let address = format!("100{}", zeros(264));
        cell(&format!("0000{address}{address}0000000000000{lt:064b}{}00", zeros(32)), &[])
    }
    fn envelope(msg: Cell, emitted: Option<u64>, v2: bool) -> Cell {
        let tail = if !v2 {
            String::new()
        } else if let Some(lt) = emitted {
            format!("1{lt:064b}0")
        } else {
            "00".into()
        };
        cell(&format!("{:04b}{}{tail}", if v2 { 5 } else { 4 }, zeros(20)), &[msg])
    }
    fn queue_leaf(n: usize, env: Cell, extra: u64) -> Cell {
        let width = (usize::BITS - n.leading_zeros()) as usize;
        cell(&format!("110{n:0width$b}{extra:064b}{:064b}", 99), &[env])
    }
    fn queue_root(root: Cell, extra: u64) -> Cell {
        cell(&format!("1{extra:064b}00"), &[root])
    }
    let queue_empty = cell(&zeros(67), &[]);
    let accounts_empty = cell(&zeros(11), &[]);
    let minimal = state(queue_empty.clone(), accounts_empty.clone(), None, 0);
    let mut rows = Vec::new();
    let mut add = |id: String, root: Cell, budget: u32| {
        rows.push(json!({"fixture_id":id,"context":{"type":"ShardState","boc":rtos_block::base64_encode(rtos_block::write_boc(&root).unwrap()),"max_cells":budget}}))
    };
    add("empty".into(), minimal.clone(), 1024);
    for seqno in [0xffff_ffffu32, 0xffff_fffe, 0x8000_0000] {
        let mut text = bits_text(&minimal).unwrap();
        text.replace_range(168..200, &format!("{seqno:032b}"));
        let refs = (0..minimal.references_count())
            .map(|i| minimal.reference(i).unwrap())
            .collect::<Vec<_>>();
        add(format!("seqno-{seqno}"), cell(&text, &refs), 1024);
    }
    let split = cell(&format!("{:032b}", 0x5f327da5), &[minimal.clone(), minimal]);
    for budget in [1, 3, 8, 9, 1024] {
        add(format!("split-budget-{budget}"), split.clone(), budget);
    }
    add(
        "empty-queue-extra1".into(),
        state(cell(&format!("0{:064b}00", 1), &[]), accounts_empty.clone(), None, 0),
        1024,
    );
    add(
        "empty-accounts-extra1".into(),
        state(queue_empty.clone(), cell(&format!("0{}", depth_balance(1, 0)), &[]), None, 0),
        1024,
    );
    let extra = depth_balance(1, 1);
    let leaf = accounts_leaf(256, account(1, 1), &extra);
    let valid_accounts = accounts_root(leaf.clone(), &extra);
    for budget in [4, 5, 6, 7, 1024] {
        add(
            format!("account-leaf-budget-{budget}"),
            state(queue_empty.clone(), valid_accounts.clone(), None, 0),
            budget,
        );
    }
    add(
        "account-leaf-root-copy-wrong".into(),
        state(queue_empty.clone(), accounts_root(leaf, &depth_balance(1, 2)), None, 0),
        1024,
    );
    let wrong_leaf = accounts_leaf(256, account(1, 1), &depth_balance(1, 2));
    add(
        "account-leaf-balance-wrong".into(),
        state(queue_empty.clone(), accounts_root(wrong_leaf, &depth_balance(1, 2)), None, 0),
        1024,
    );
    let absent = accounts_leaf(256, cell("0", &[]), &depth_balance(0, 0));
    add(
        "account-leaf-nonexistent".into(),
        state(queue_empty.clone(), accounts_root(absent, &depth_balance(0, 0)), None, 0),
        1024,
    );
    let a = accounts_leaf(255, account(1, 1), &depth_balance(1, 1));
    let b = accounts_leaf(255, account(3, 2), &depth_balance(3, 2));
    for (name, depth, balance) in [("valid", 3, 3), ("balance-wrong", 3, 4), ("depth-wrong", 2, 3)]
    {
        let extra = depth_balance(depth, balance);
        let fork = cell(&format!("00{extra}"), &[a.clone(), b.clone()]);
        add(
            format!("account-fork-{name}"),
            state(queue_empty.clone(), accounts_root(fork, &extra), None, 0),
            1024,
        );
    }
    let msg = message(7);
    for (name, env, extra) in [
        ("legacy-valid", envelope(msg.clone(), None, false), 7),
        ("legacy-wrong", envelope(msg.clone(), None, false), 8),
        ("explicit-zero-valid", envelope(msg.clone(), Some(0), true), 0),
        ("explicit-zero-wrong", envelope(msg.clone(), Some(0), true), 7),
        ("fallback-valid", envelope(msg.clone(), None, true), 7),
    ] {
        let root = queue_root(queue_leaf(352, env, extra), extra);
        add(format!("queue-{name}"), state(root, accounts_empty.clone(), None, 0), 1024);
    }
    let inbound = cell(&format!("1000100{}000000", zeros(264)), &[]);
    add(
        "queue-inbound-no-lt".into(),
        state(
            queue_root(queue_leaf(352, envelope(inbound, None, false), 0), 0),
            accounts_empty.clone(),
            None,
            0,
        ),
        1024,
    );
    let a = queue_leaf(351, envelope(message(3), None, false), 3);
    let b = queue_leaf(351, envelope(message(5), None, false), 5);
    for (name, extra) in [("valid", 3), ("wrong-min", 5)] {
        let root = queue_root(cell(&format!("00{extra:064b}"), &[a.clone(), b.clone()]), extra);
        for budget in [10, 11, 1024] {
            add(
                format!("queue-fork-{name}-budget-{budget}"),
                state(root.clone(), accounts_empty.clone(), None, 0),
                budget,
            );
        }
    }
    let path = std::env::var("RTOS_CODEC_CONTEXTS_OUT").expect("RTOS_CODEC_CONTEXTS_OUT");
    fn currency_leaf(n: usize, currency: &rtos_block::CurrencyCollection) -> Cell {
        use rtos_block::Serializable;
        let mut acc = BuilderData::new();
        for bit in format!("1100{}{}{}", zeros(264), zeros(42), zeros(64)).bytes() {
            acc.append_bit_bool(bit == b'1').unwrap();
        }
        currency.write_to(&mut acc).unwrap();
        acc.append_bits(0, 2).unwrap();
        let extra = rtos_block::DepthBalanceInfo::new(0, currency).unwrap();
        let width = (usize::BITS - n.leading_zeros()) as usize;
        let mut leaf = BuilderData::new();
        for bit in format!("110{n:0width$b}").bytes() {
            leaf.append_bit_bool(bit == b'1').unwrap();
        }
        extra.write_to(&mut leaf).unwrap();
        leaf.append_raw(&[0; 40], 320).unwrap();
        leaf.checked_append_reference(acc.into_cell().unwrap()).unwrap();
        leaf.into_cell().unwrap()
    }
    fn currency_fork(left: Cell, right: Cell, currency: &rtos_block::CurrencyCollection) -> Cell {
        use rtos_block::Serializable;
        let extra = rtos_block::DepthBalanceInfo::new(0, currency).unwrap();
        let mut fork = BuilderData::new();
        fork.append_bits(0, 2).unwrap();
        fork.checked_append_reference(left).unwrap();
        fork.checked_append_reference(right).unwrap();
        extra.write_to(&mut fork).unwrap();
        let mut wrapper = BuilderData::new();
        wrapper.append_bit_one().unwrap();
        wrapper.checked_append_reference(fork.into_cell().unwrap()).unwrap();
        extra.write_to(&mut wrapper).unwrap();
        wrapper.into_cell().unwrap()
    }
    let mut left = rtos_block::CurrencyCollection::with_coins(1);
    left.set_other(7, 2).unwrap();
    let mut right = rtos_block::CurrencyCollection::with_coins(2);
    right.set_other(7, 3).unwrap();
    for (name, amount) in [("valid", 5), ("wrong", 6)] {
        let mut total = rtos_block::CurrencyCollection::with_coins(3);
        total.set_other(7, amount).unwrap();
        let accounts = currency_fork(currency_leaf(255, &left), currency_leaf(255, &right), &total);
        rows.push(json!({"fixture_id":format!("account-fork-extra-currency-{name}"),"context":{"type":"ShardState","boc":rtos_block::base64_encode(rtos_block::write_boc(&state(queue_empty.clone(),accounts,None,0)).unwrap())}}));
    }
    let max = rtos_block::CurrencyCollection::from_coins(rtos_block::Coins::MAX);
    let other_root = cell(&format!("10{:06b}{}00001{:08b}", 32, zeros(32), 2), &[]);
    let mut other_right = rtos_block::CurrencyCollection::with_coins(2);
    other_right.other = rtos_block::ExtraCurrencyCollection::with_hashmap(Some(other_root));
    let mut other_total = other_right.clone();
    other_total.coins = rtos_block::Coins::new(3);
    for (id, left, right) in [
        (
            "account-fork-copy-right-noncanonical",
            rtos_block::CurrencyCollection::with_coins(1),
            other_right.clone(),
        ),
        (
            "account-fork-copy-left-noncanonical",
            other_right,
            rtos_block::CurrencyCollection::with_coins(1),
        ),
    ] {
        let accounts =
            currency_fork(currency_leaf(255, &left), currency_leaf(255, &right), &other_total);
        rows.push(json!({"fixture_id":id,"context":{"type":"ShardState","boc":rtos_block::base64_encode(rtos_block::write_boc(&state(queue_empty.clone(),accounts,None,0)).unwrap())}}));
    }
    for (id, total) in [
        ("account-fork-coin-overflow", rtos_block::CurrencyCollection::new()),
        ("account-fork-overflow-stale-total", max.clone()),
    ] {
        let accounts = currency_fork(
            currency_leaf(255, &max),
            currency_leaf(255, &rtos_block::CurrencyCollection::with_coins(1)),
            &total,
        );
        rows.push(json!({"fixture_id":id,"context":{"type":"ShardState","boc":rtos_block::base64_encode(rtos_block::write_boc(&state(queue_empty.clone(),accounts,None,0)).unwrap())}}));
    }
    std::fs::write(path, rows.iter().map(|r| format!("{r}\n")).collect::<String>()).unwrap();
}

#[test]
#[ignore]
fn export_shard_ident_profile_contexts() {
    let root = state(cell(&zeros(67), &[]), cell(&zeros(11), &[]), None, 0);
    let refs = (0..root.references_count()).map(|i| root.reference(i).unwrap()).collect::<Vec<_>>();
    let original = bits_text(&root).unwrap();
    let mut rows = Vec::new();
    for depth in [0u8, 1, 2, 59, 60, 61, 62, 63] {
        let pow = 1u64 << (63 - depth);
        let mut prefixes = vec![0, 1, 1u64 << 63, u64::MAX, pow, pow - 1];
        prefixes.sort_unstable();
        prefixes.dedup();
        for workchain in [0i32, -1, i32::MIN] {
            for prefix in &prefixes {
                let mut bits = original.clone();
                bits.replace_range(66..72, &format!("{depth:06b}"));
                bits.replace_range(72..104, &format!("{:032b}", workchain as u32));
                bits.replace_range(104..168, &format!("{prefix:064b}"));
                let root = cell(&bits, &refs);
                rows.push(json!({"fixture_id":format!("depth{depth}-wc{workchain}-prefix{prefix:016x}"),"context":{"type":"ShardState","boc":rtos_block::base64_encode(rtos_block::write_boc(&root).unwrap())}}));
            }
        }
    }
    let path = std::env::var("RTOS_CODEC_CONTEXTS_OUT").expect("RTOS_CODEC_CONTEXTS_OUT");
    std::fs::write(path, rows.iter().map(|r| format!("{r}\n")).collect::<String>()).unwrap();
}
