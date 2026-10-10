// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use rtos_block::{
    BuilderData, Cell, Coins, CurrencyCollection, ExceptionCode, IBitstring, InternalMessageHeader,
    Message, MsgAddressInt, MsgForwardPrices, Serializable, SizeLimitsConfig, SliceData, StateInit,
};
use rtos_vm::{
    error::tvm_exception_code,
    executor::{gas::gas_state::Gas, Engine},
    stack::{savelist::SaveList, Stack, StackItem},
};
fn boc(c: &Cell) -> String {
    hex::encode(rtos_block::write_boc(c).unwrap())
}
fn bits(n: usize) -> Cell {
    BuilderData::with_raw(vec![0x55; n.div_ceil(8)], n).unwrap().into_cell().unwrap()
}
#[test]
fn sendmsg_matches_cpp() {
    let export = std::env::var("RTOS_SENDMSG_EXPORT").ok();
    let filter = std::env::var("RTOS_SENDMSG_CASE_FILTER").unwrap_or_default();
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("data/sendmsg.json")).unwrap();
    let addr = MsgAddressInt::standard(0, [0x11; 32]);
    let addr_cell = addr.serialize().unwrap();
    let prices = MsgForwardPrices {
        lump_price: 1000000,
        bit_price: 1000 << 16,
        cell_price: 100000 << 16,
        ihr_price_factor: 98304,
        first_frac: 21845,
        next_frac: 21845,
    };
    let prices_cell = prices.serialize().unwrap();
    let mut cases = Vec::new();
    for n in (280..=480).step_by(8) {
        for fee in [0u64, 1_000_000_000_000_000] {
            let mut h = InternalMessageHeader {
                dst: MsgAddressInt::standard(0, [0x22; 32]),
                value: CurrencyCollection::with_coins(6789),
                ihr_disabled: true,
                ..Default::default()
            };
            h.fwd_fee = Coins::from(fee);
            let mut m = Message::with_int_header(h);
            m.set_body(SliceData::load_cell(bits(n)).unwrap());
            cases.push((
                format!("packing-{n}-{fee}"),
                m.serialize().unwrap(),
                SizeLimitsConfig::default(),
            ));
        }
    }
    for maxbits in [0, 8, 16, 10000] {
        for maxcells in [0, 1, 2, 100] {
            for init in [false, true] {
                let mut m = Message::with_int_header(InternalMessageHeader {
                    dst: MsgAddressInt::standard(0, [0x22; 32]),
                    ihr_disabled: true,
                    ..Default::default()
                });
                m.set_body(SliceData::load_cell(bits(16)).unwrap());
                if init {
                    let mut s = StateInit::default();
                    s.set_code(bits(24));
                    s.set_data(bits(32));
                    m.set_state_init(s);
                }
                let c = m
                    .serialize_with_params(Some(true), Some(false))
                    .unwrap()
                    .0
                    .into_cell()
                    .unwrap();
                cases.push((
                    format!("limits-{maxbits}-{maxcells}-{init}"),
                    c,
                    SizeLimitsConfig {
                        max_msg_bits: maxbits,
                        max_msg_cells: maxcells,
                        ..Default::default()
                    },
                ));
            }
        }
    }
    for kind in ["ordinary", "library", "merkle", "partial-merkle", "shared"] {
        for init in [false, true] {
            for maxcells in [0, 1, 2, 100] {
                let root = bits(64);
                let special = match kind {
                    "library" => root.as_library_cell(),
                    "merkle" => rtos_block::MerkleProof::create(&root, |_| true)
                        .unwrap()
                        .serialize()
                        .unwrap(),
                    "partial-merkle" => {
                        let mut b = BuilderData::new();
                        b.checked_append_reference(root.clone()).unwrap();
                        let c = b.into_cell().unwrap();
                        rtos_block::MerkleProof::create(&c, |h| h == c.repr_hash())
                            .unwrap()
                            .serialize()
                            .unwrap()
                    }
                    _ => root,
                };
                let mut body = BuilderData::new();
                body.append_u32(42).unwrap();
                body.checked_append_reference(special.clone()).unwrap();
                if kind == "shared" {
                    body.checked_append_reference(special.clone()).unwrap();
                }
                let mut m = Message::with_int_header(InternalMessageHeader {
                    dst: MsgAddressInt::standard(0, [0x22; 32]),
                    value: CurrencyCollection::with_coins(10000000),
                    ..Default::default()
                });
                m.set_body(SliceData::load_cell(body.into_cell().unwrap()).unwrap());
                if init {
                    let mut state = StateInit::default();
                    state.set_code(special);
                    m.set_state_init(state);
                }
                let c = m
                    .serialize_with_params(Some(false), Some(false))
                    .unwrap()
                    .0
                    .into_cell()
                    .unwrap();
                cases.push((
                    format!("special-{kind}-{init}-{maxcells}"),
                    c,
                    SizeLimitsConfig { max_msg_cells: maxcells, ..Default::default() },
                ));
            }
        }
    }
    for n in [0, 300, 320, 336, 352, 480, 900] {
        for fee in [0u128, (1u128 << 120) - 1] {
            let mut m = Message::with_int_header(InternalMessageHeader {
                dst: MsgAddressInt::standard(0, [0x22; 32]),
                value: CurrencyCollection::with_coins(10000000),
                fwd_fee: Coins::try_from(fee).unwrap(),
                ..Default::default()
            });
            m.set_body(SliceData::load_cell(bits(n)).unwrap());
            cases.push((
                format!("wide-fee-{n}-{fee}"),
                m.serialize().unwrap(),
                SizeLimitsConfig::default(),
            ));
            let mut m = Message::with_ext_out_header(Default::default());
            m.set_body(SliceData::load_cell(bits(n)).unwrap());
            let mut init = StateInit::default();
            init.set_code(bits(32));
            init.set_data(bits(64));
            m.set_state_init(init);
            cases.push((
                format!("external-{n}-{fee}"),
                m.serialize().unwrap(),
                SizeLimitsConfig::default(),
            ));
        }
    }
    for len in [0, 1, 7, 15] {
        for n in [280usize, 304, 320, 336] {
            let h = InternalMessageHeader {
                dst: MsgAddressInt::standard(0, [0x22; 32]),
                value: CurrencyCollection::with_coins(10000000),
                ..Default::default()
            };
            let mut b = BuilderData::new();
            b.append_bits(4, 4).unwrap();
            h.src.write_to(&mut b).unwrap();
            h.dst.write_to(&mut b).unwrap();
            h.value.write_to(&mut b).unwrap();
            b.append_bits(len, 4).unwrap();
            b.append_raw(&[0; 15], len * 8).unwrap();
            h.fwd_fee.write_to(&mut b).unwrap();
            b.append_u64(0).unwrap();
            b.append_u32(0).unwrap();
            b.append_bits(0, 2).unwrap();
            b.append_raw(&vec![0x55; n.div_ceil(8)], n).unwrap();
            cases.push((
                format!("encoded-flags-{len}-{n}"),
                b.into_cell().unwrap(),
                SizeLimitsConfig::default(),
            ));
        }
    }
    for depth in [64, 512, 1000] {
        for shared in [false, true] {
            for maxcells in [0, 1, 63, 64, 65, 511, 512, 513, u32::MAX] {
                let mut child = bits(8);
                for _ in 0..depth {
                    let mut b = BuilderData::new();
                    b.append_u8(1).unwrap();
                    b.checked_append_reference(child.clone()).unwrap();
                    if shared {
                        b.checked_append_reference(child).unwrap();
                    }
                    child = b.into_cell().unwrap();
                }
                let mut m = Message::with_int_header(InternalMessageHeader {
                    dst: MsgAddressInt::standard(0, [0x22; 32]),
                    value: CurrencyCollection::with_coins(10000000),
                    ..Default::default()
                });
                m.set_body(SliceData::load_cell(child).unwrap());
                cases.push((
                    format!("deep-{depth}-{shared}-{maxcells}"),
                    m.serialize_with_params(Some(true), Some(false))
                        .unwrap()
                        .0
                        .into_cell()
                        .unwrap(),
                    SizeLimitsConfig { max_msg_cells: maxcells, ..Default::default() },
                ));
            }
        }
    }
    for field in ["value", "fee"] {
        for zero in [true, false] {
            let mut b = BuilderData::new();
            b.append_bits(4, 4).unwrap();
            rtos_block::MsgAddressIntOrNone::default().write_to(&mut b).unwrap();
            MsgAddressInt::standard(0, [0x22; 32]).write_to(&mut b).unwrap();
            if field == "value" {
                b.append_bits(2, 4).unwrap();
                b.append_u16(if zero { 0 } else { 1 }).unwrap();
            } else {
                Coins::from(10000000).write_to(&mut b).unwrap();
            }
            b.append_bit_zero().unwrap();
            b.append_bits(0, 4).unwrap();
            if field == "fee" {
                b.append_bits(2, 4).unwrap();
                b.append_u16(if zero { 0 } else { 1 }).unwrap();
            } else {
                Coins::zero().write_to(&mut b).unwrap();
            }
            b.append_u64(0).unwrap();
            b.append_u32(0).unwrap();
            b.append_bits(0, 2).unwrap();
            cases.push((
                format!("noncanonical-{field}-{zero}"),
                b.into_cell().unwrap(),
                SizeLimitsConfig::default(),
            ));
        }
    }
    for context in [
        "prices-null",
        "prices-int",
        "prices-bad",
        "prices-tag",
        "limits-int",
        "limits-bad",
        "limits-tag",
        "limits-short",
        "balance-null",
        "balance-empty",
        "balance-value-null",
        "balance-negative",
        "balance-nan",
        "balance-wide",
        "incoming-null",
        "incoming-empty",
        "incoming-value-null",
        "incoming-negative",
        "incoming-nan",
        "incoming-wide",
    ] {
        let mut m = Message::with_int_header(InternalMessageHeader {
            dst: MsgAddressInt::standard(0, [0x22; 32]),
            value: CurrencyCollection::with_coins(10000000),
            ..Default::default()
        });
        m.set_body(SliceData::load_cell(bits(336)).unwrap());
        cases.push((
            format!("context-{context}"),
            m.serialize().unwrap(),
            SizeLimitsConfig::default(),
        ));
    }
    for depth in [1, 2, 3, 4] {
        for init in [false, true] {
            let base =
                rtos_block::MerkleProof::create(&bits(64), |_| true).unwrap().serialize().unwrap();
            let mut proof = base.clone();
            for _ in 1..depth {
                proof =
                    rtos_block::MerkleProof::create(&proof, |_| true).unwrap().serialize().unwrap();
            }
            let mut b = BuilderData::new();
            b.checked_append_reference(proof).unwrap();
            let mut m = Message::with_int_header(InternalMessageHeader {
                dst: MsgAddressInt::standard(0, [0x22; 32]),
                value: CurrencyCollection::with_coins(10000000),
                ..Default::default()
            });
            m.set_body(SliceData::load_builder(b).unwrap());
            if init {
                let mut state = StateInit::default();
                state.set_code(base);
                m.set_state_init(state);
            }
            cases.push((
                format!("merkle-depth-{depth}-{init}"),
                m.serialize().unwrap(),
                SizeLimitsConfig::default(),
            ));
        }
    }
    for shared in [false, true] {
        for maxcells in [0, 1, 100] {
            let mut value = CurrencyCollection::with_coins(10000000);
            value.set_other(11, 123).unwrap();
            let extra = value.other.root().unwrap().clone();
            let mut m = Message::with_int_header(InternalMessageHeader {
                dst: MsgAddressInt::standard(0, [0x22; 32]),
                value,
                ..Default::default()
            });
            let mut b = BuilderData::new();
            b.checked_append_reference(if shared { extra } else { bits(80) }).unwrap();
            m.set_body(SliceData::load_builder(b).unwrap());
            cases.push((
                format!("extra-{shared}-{maxcells}"),
                m.serialize().unwrap(),
                SizeLimitsConfig { max_msg_cells: maxcells, ..Default::default() },
            ));
        }
    }
    for bad_source in [false, true] {
        let mut h = InternalMessageHeader {
            dst: MsgAddressInt::standard(0, [0x22; 32]),
            value: CurrencyCollection::with_coins(10000000),
            extra_flags: Coins::from(4),
            ..Default::default()
        };
        if bad_source {
            h.src = rtos_block::MsgAddressIntOrNone::Some(MsgAddressInt::standard(0, [0x33; 32]));
        }
        cases.push((
            format!("invalid-flags-source-{bad_source}"),
            Message::with_int_header(h).serialize().unwrap(),
            SizeLimitsConfig::default(),
        ));
    }
    for reversed in [false, true] {
        for maxcells in [1, 2, 3, 4, 100] {
            let mut body = BuilderData::new();
            body.append_u8(3).unwrap();
            for n in if reversed { [160, 32] } else { [32, 160] } {
                body.checked_append_reference(bits(n)).unwrap();
            }
            let mut m = Message::with_int_header(InternalMessageHeader {
                dst: MsgAddressInt::standard(0, [0x22; 32]),
                value: CurrencyCollection::with_coins(10000000),
                ..Default::default()
            });
            m.set_body(SliceData::load_builder(body).unwrap());
            cases.push((
                format!("ordered-children-{reversed}-{maxcells}"),
                m.serialize_with_params(Some(true), Some(false)).unwrap().0.into_cell().unwrap(),
                SizeLimitsConfig { max_msg_cells: maxcells, ..Default::default() },
            ));
        }
    }
    for context in [
        "incoming-max",
        "incoming-max-safe",
        "incoming-max-over",
        "balance-max",
        "myaddr-std-prefix",
        "myaddr-std-mc-prefix",
        "myaddr-std-short",
        "myaddr-var-prefix",
        "myaddr-std-extra",
        "myaddr-std-ref",
        "myaddr-anycast-zero",
        "myaddr-anycast-max",
        "myaddr-empty",
        "myaddr-one-bit",
        "myaddr-external",
        "myaddr-int",
        "legacy-extra-int",
        "legacy-extra-slice",
        "legacy-extra-tuple",
        "legacy-extra-cell",
    ] {
        let mut m = Message::with_int_header(InternalMessageHeader {
            dst: MsgAddressInt::standard(0, [0x22; 32]),
            value: CurrencyCollection::with_coins(10000000),
            ..Default::default()
        });
        if context.starts_with("legacy-") {
            let mut b = BuilderData::new();
            b.append_u8(3).unwrap();
            for n in [8, 16, 24, 32] {
                b.checked_append_reference(bits(n)).unwrap();
            }
            m.set_body(SliceData::load_builder(b).unwrap());
        } else {
            m.set_body(SliceData::load_cell(bits(80)).unwrap());
        }
        cases.push((
            format!("context-{context}"),
            m.serialize_with_params(Some(false), Some(false)).unwrap().0.into_cell().unwrap(),
            SizeLimitsConfig::default(),
        ));
    }
    let mut rows = Vec::new();
    for version in [9, 10, 12, 13, 14, 15, 19, 20] {
        for (name, msg, limits) in &cases {
            for mode in [0, 64, 128, 1024, 1088, 1152] {
                if name.starts_with("context-legacy-") {
                    if version != 9 && version != 10 {
                        continue;
                    }
                } else if version < 12
                    || (name.starts_with("context-")
                        && (version != 14 || mode == 1088 || mode == 1152))
                {
                    continue;
                }
                let context = name.strip_prefix("context-").unwrap_or("normal");
                for behavior in if name == "deep-512-false-4294967295" {
                    vec![
                        "plain",
                        "explicit",
                        "catch-implicit",
                        "catch-explicit",
                        "data-implicit",
                        "data-explicit",
                        "data-catch-explicit",
                    ]
                } else {
                    vec!["plain"]
                } {
                    for nested in
                        if name.starts_with("deep-") { vec![false, true] } else { vec![false] }
                    {
                        for budget in if name == "special-library-false-100" {
                            vec![
                                0, 9, 25, 26, 50, 100, 125, 126, 145, 146, 155, 156, 255, 256, 655,
                                656, 755, 756, 1000000,
                            ]
                        } else {
                            vec![1000000]
                        } {
                            let name = format!(
                                "{name}-v{version}-m{mode}-g{budget}-nested{nested}-{behavior}"
                            );
                            if !name.contains(&filter) {
                                continue;
                            }
                            let inner = match behavior {
                                "explicit" => "SENDMSG COMMIT",
                                "catch-implicit" => "PUSHCONT { DROP DROP PUSHINT 77 NEWC ENDC POPCTR c5 } POPCTR c2 SENDMSG",
                                "catch-explicit" => "PUSHCONT { DROP DROP PUSHINT 77 NEWC ENDC POPCTR c5 } POPCTR c2 SENDMSG COMMIT",
                                // Move the deep action chain to c4, clearing c5 so only
                                // data depth can cause automatic or explicit commit failure.
                                "data-implicit" => "SENDMSG PUSHCTR c5 POPCTR c4 NEWC ENDC POPCTR c5",
                                "data-explicit" => "SENDMSG PUSHCTR c5 POPCTR c4 NEWC ENDC POPCTR c5 COMMIT",
                                "data-catch-explicit" => "PUSHCONT { DROP DROP PUSHINT 77 NEWC ENDC DUP POPCTR c4 POPCTR c5 } POPCTR c2 SENDMSG PUSHCTR c5 POPCTR c4 NEWC ENDC POPCTR c5 COMMIT",
                                _ => "SENDMSG",
                            };
                            let source = if nested {
                                format!("PUSHINT 2 PUSHREFSLICE {{ {inner} }} PUSHCTR c7 RUNVM 16")
                            } else {
                                inner.into()
                            };
                            let code = rtos_assembler::compile_code_to_cell(&source).unwrap();
                            let limits_cell = limits.serialize().unwrap();
                            let mut conf = vec![StackItem::None; 7];
                            conf[4] = StackItem::Slice(
                                SliceData::load_cell(prices_cell.clone()).unwrap(),
                            );
                            conf[5] = conf[4].clone();
                            conf[6] = StackItem::Slice(
                                SliceData::load_cell(limits_cell.clone()).unwrap(),
                            );
                            let mut info = vec![StackItem::None; 18];
                            info[7] =
                                StackItem::tuple(vec![StackItem::int(1000000000), StackItem::None]);
                            info[8] =
                                StackItem::Slice(SliceData::load_cell(addr_cell.clone()).unwrap());
                            info[11] = info[7].clone();
                            info[14] = StackItem::tuple(conf);
                            if context.starts_with("prices-") || context.starts_with("limits-") {
                                let mut changed = info[14].as_tuple().unwrap().to_vec();
                                if context == "prices-null" {
                                    changed[4] = StackItem::None;
                                    changed[5] = StackItem::None;
                                }
                                if context == "prices-int" {
                                    changed[4] = StackItem::int(1);
                                    changed[5] = StackItem::int(1);
                                }
                                if context == "prices-tag" {
                                    changed[4] =
                                        StackItem::Slice(SliceData::load_cell(bits(8)).unwrap());
                                    changed[5] = changed[4].clone();
                                }
                                if context == "limits-tag" {
                                    changed[6] =
                                        StackItem::Slice(SliceData::load_cell(bits(8)).unwrap());
                                }
                                if context == "prices-bad" {
                                    changed[4] = StackItem::Slice(SliceData::default());
                                    changed[5] = changed[4].clone();
                                }
                                if context == "limits-int" {
                                    changed[6] = StackItem::int(1);
                                }
                                if context == "limits-bad" {
                                    changed[6] = StackItem::Slice(SliceData::default());
                                }
                                if context == "limits-short" {
                                    changed.truncate(6);
                                }
                                info[14] = StackItem::tuple(changed);
                            }
                            if context.starts_with("balance-") || context.starts_with("incoming-") {
                                let index = if context.starts_with("balance-") { 7 } else { 11 };
                                let kind = context.split_once('-').unwrap().1;
                                info[index] = match kind {
                                    "null" => StackItem::None,
                                    "empty" => StackItem::tuple(vec![]),
                                    _ => StackItem::tuple(vec![
                                        match kind {
                                            "value-null" => StackItem::None,
                                            "negative" => StackItem::int(-1),
                                            "nan" => StackItem::int(
                                                rtos_vm::stack::integer::IntegerData::nan(),
                                            ),
                                            "max" | "max-safe" | "max-over" => {
                                                let adjustment = match kind {
                                                    "max-safe" => 10000001,
                                                    "max-over" => 10000000,
                                                    _ => 1,
                                                };
                                                let value = (num::BigInt::from(1u8) << 256usize)
                                                    - num::BigInt::from(adjustment);
                                                StackItem::int(
                                                    rtos_vm::stack::integer::IntegerData::from(
                                                        value,
                                                    )
                                                    .unwrap(),
                                                )
                                            }
                                            "wide" => {
                                                let mut b = [0u8; 33];
                                                b[0] = 1;
                                                StackItem::int(rtos_vm::stack::integer::IntegerData::from_unsigned_bytes_be(&b))
                                            }
                                            _ => unreachable!(),
                                        },
                                        StackItem::None,
                                    ]),
                                };
                            }
                            if let Some(kind) = context.strip_prefix("myaddr-") {
                                if kind == "int" {
                                    info[8] = StackItem::int(0);
                                } else {
                                    let mut b = BuilderData::new();
                                    match kind {
                                        "empty" => {}
                                        "one-bit" => {
                                            b.append_bit_one().unwrap();
                                        }
                                        "external" => {
                                            b.append_bits(0, 2).unwrap();
                                        }
                                        "std-short" => {
                                            b.append_bits(4, 3).unwrap();
                                        }
                                        "std-prefix" | "std-mc-prefix" => {
                                            b.append_bits(4, 3).unwrap();
                                            b.append_u8(if kind == "std-mc-prefix" {
                                                255
                                            } else {
                                                0
                                            })
                                            .unwrap();
                                        }
                                        "var-prefix" => {
                                            b.append_bits(6, 3).unwrap();
                                            b.append_bits(1, 9).unwrap();
                                            b.append_i32(-1).unwrap();
                                        }
                                        "anycast-zero" | "anycast-max" => {
                                            b.append_bits(5, 3).unwrap();
                                            b.append_bits(
                                                if kind == "anycast-max" { 31 } else { 0 },
                                                5,
                                            )
                                            .unwrap();
                                            b.append_u8(0).unwrap();
                                        }
                                        "std-extra" | "std-ref" => {
                                            b = SliceData::load_cell(addr_cell.clone())
                                                .unwrap()
                                                .as_builder()
                                                .unwrap();
                                            if kind == "std-extra" {
                                                b.append_u8(0).unwrap();
                                            } else {
                                                b.checked_append_reference(Cell::default())
                                                    .unwrap();
                                            }
                                        }
                                        _ => unreachable!(),
                                    }
                                    info[8] = StackItem::Slice(SliceData::load_builder(b).unwrap());
                                    if kind == "std-mc-prefix" || kind == "var-prefix" {
                                        let mut changed = info[14].as_tuple().unwrap().to_vec();
                                        changed[5] = StackItem::None;
                                        info[14] = StackItem::tuple(changed);
                                    }
                                }
                            }
                            if let Some(kind) = context.strip_prefix("legacy-extra-") {
                                let extra = match kind {
                                    "int" => StackItem::int(1),
                                    "slice" => StackItem::Slice(SliceData::default()),
                                    "tuple" => StackItem::tuple(vec![]),
                                    "cell" => StackItem::Cell(Cell::default()),
                                    _ => unreachable!(),
                                };
                                info[7] = StackItem::tuple(vec![
                                    StackItem::int(1000000000),
                                    extra.clone(),
                                ]);
                                info[11] = info[7].clone();
                            }
                            let mut ctrls = SaveList::new();
                            ctrls.put(7, StackItem::tuple(vec![StackItem::tuple(info)])).unwrap();
                            let mut stack = Stack::new();
                            stack.push(StackItem::Cell(msg.clone()));
                            stack.push(StackItem::int(mode));
                            let mut vm = Engine::with_capabilities(0)
                                .setup_checked(
                                    code.clone(),
                                    ctrls,
                                    stack,
                                    Gas::test_with_limit(budget),
                                    vec![],
                                )
                                .unwrap();
                            vm.set_block_version(version);
                            let result = vm.execute();
                            let failed = result.is_err();
                            let raw_error = result
                                .as_ref()
                                .err()
                                .filter(|e| tvm_exception_code(e).is_none())
                                .map(|e| e.to_string());
                            let exit = match result {
                                Ok(n) => n,
                                Err(e) => match tvm_exception_code(&e) {
                                    Some(ExceptionCode::OutOfGas) => -14,
                                    Some(n) => n as i32,
                                    None if export.is_some() => -999,
                                    None => panic!("{name}: {e}"),
                                },
                            };
                            // Rust returns an extra exit-code item for interpreter exceptions; the
                            // C++ run() API returns the exception argument alone.
                            let skip = usize::from(failed && exit != -999);
                            if failed && exit != -14 && exit != -999 {
                                assert_eq!(
                                    vm.stack().get(0).unwrap().as_integer().unwrap().to_string(),
                                    exit.to_string(),
                                    "{name}"
                                );
                            }
                            let values = if exit == -14 {
                                vec![vm.gas_used().to_string()]
                            } else {
                                (skip..vm.stack().depth())
                                    .map(|i| {
                                        vm.stack()
                                            .get(i)
                                            .unwrap()
                                            .as_integer()
                                            .map(|n| n.to_string())
                                            .unwrap_or_else(|_| "non-int".into())
                                    })
                                    .collect::<Vec<_>>()
                            };
                            let gas = vm.gas_used();
                            let steps = vm.steps();
                            if nested {
                                assert!(
                                    steps >= 7,
                                    "{name}: child VM was not executed: {steps} steps"
                                );
                            }
                            if nested && mode == 0 {
                                if name.starts_with("deep-64-") {
                                    assert_eq!(exit, 0, "{name}: parent exit");
                                    assert_eq!(values[0], "0", "{name}: child exit");
                                    assert!(
                                        values[1].parse::<u128>().unwrap() > 0,
                                        "{name}: child fee"
                                    );
                                }
                                if name.starts_with("deep-512-false-4294967295-") {
                                    let expected = if matches!(
                                        behavior,
                                        "catch-explicit" | "data-catch-explicit"
                                    ) {
                                        ["0", "77"]
                                    } else {
                                        ["8", "0"]
                                    };
                                    assert_eq!(exit, 0, "{name}: parent exit");
                                    assert_eq!(
                                        values, expected,
                                        "{name}: child commit/catch result"
                                    );
                                }
                            }
                            let committed = vm.is_committed_state();
                            let roots = vm.get_committed_state().map(|(a, b)| {
                                vec![format!("{:x}", a.repr_hash()), format!("{:x}", b.repr_hash())]
                            });
                            let actual =
                                serde_json::json!([exit, gas, values, committed, steps, roots]);
                            if export.is_none() {
                                assert_eq!(actual, expected[&name], "{name}");
                            }
                            rows.push(serde_json::json!({"name":name,"version":version,"gas":budget,"code":boc(&code),"message":boc(msg),"mode":mode,"address":boc(&addr_cell),"prices":boc(&prices_cell),"limits":boc(&limits_cell),"actual":actual,"context":context,"raw_error":raw_error}));
                        }
                    }
                }
            }
        }
    }
    if let Some(path) = export {
        std::fs::write(path, serde_json::to_string(&rows).unwrap()).unwrap();
    } else {
        assert!(!rows.is_empty());
        assert_eq!(
            expected.as_object().unwrap().keys().filter(|name| name.contains(&filter)).count(),
            rows.len()
        );
    }
}
