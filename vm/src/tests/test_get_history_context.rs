// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::*;
use rtos_block::{
    read_single_root_boc_file, BlockIdExt, Coins, ConfigParam18, ConfigParam8, ConfigParamEnum,
    CurrencyCollection, ShardIdent, StateInit, StoragePrices,
};
fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}
fn render(value: &StackItem) -> String {
    if value.is_null() {
        "null".into()
    } else if let Ok(i) = value.as_integer() {
        i.to_str_radix(10)
    } else if let Ok(t) = value.as_tuple() {
        format!("[{}]", t.iter().map(render).collect::<Vec<_>>().join(";"))
    } else if let Ok(c) = value.as_cell() {
        format!("cell:{:x}", c.repr_hash())
    } else if let Ok(s) = value.as_slice() {
        format!("slice:{:x}", s.clone().into_cell().unwrap().repr_hash())
    } else {
        panic!("unexpected c7 value: {value:?}")
    }
}
#[test]
fn node_get_full_history_context_matches_cpp() {
    let export = std::env::var("RTOS_GET_HISTORY_EXPORT").ok();
    let filter = std::env::var("RTOS_GET_CASE_FILTER").ok();
    let mut rows = Vec::new();
    for version in [3, 4, 5, 6, 8, 9, 10, 11, 14, 15, 16, 17, 19] {
        for mode in [
            "complete",
            "recent-missing",
            "century-missing",
            "key-missing",
            "key-override",
            "current-key",
            "recent-truncated",
            "century-truncated",
            "recent-sequence",
            "zero-truncated",
            "zero-sequence",
            "precompiled-truncated",
            "precompiled-trailing",
            "precompiled-tag",
        ] {
            if mode.starts_with("precompiled") && version != 14 {
                continue;
            }
            let mut mc = ShardStateUnsplit::construct_from_cell(
                read_single_root_boc_file("../block/src/tests/data/free-ton-mc-state-61884")
                    .unwrap(),
            )
            .unwrap();
            let mut extra = mc.read_custom().unwrap().unwrap();
            let mut p8 =
                ConfigParam8 { global_version: extra.config.get_global_version().unwrap() };
            p8.global_version.version = version;
            extra.config.set_config(ConfigParamEnum::ConfigParam8(p8)).unwrap();
            let mut prices = ConfigParam18::default();
            for since in [100, 200, 300] {
                prices
                    .insert(&StoragePrices {
                        utime_since: since,
                        bit_price_ps: since as u64,
                        cell_price_ps: 2,
                        mc_bit_price_ps: 3,
                        mc_cell_price_ps: 4,
                    })
                    .unwrap();
            }
            extra.config.set_config(ConfigParamEnum::ConfigParam18(prices)).unwrap();
            match mode {
                "recent-truncated" | "century-truncated" | "zero-truncated" => {
                    let seq = match mode {
                        "recent-truncated" => 61880u32,
                        "century-truncated" => 61700u32,
                        _ => 0u32,
                    };
                    extra
                        .prev_blocks
                        .set_builder_serialized(
                            seq.write_to_bitstring().unwrap(),
                            &rtos_block::BuilderData::new(),
                            &rtos_block::KeyMaxLt { key: false, max_end_lt: 0 },
                        )
                        .unwrap();
                }
                "recent-sequence" | "zero-sequence" => {
                    let seq = if mode == "recent-sequence" { 61880u32 } else { 0u32 };
                    let mut entry = extra.prev_blocks.get(&seq).unwrap().unwrap();
                    entry.blk_ref.seq_no = seq + 1;
                    extra.prev_blocks.set_augmentable(&seq, &entry).unwrap();
                }
                "recent-missing" => extra.prev_blocks.del(&61880).unwrap(),
                "century-missing" => extra.prev_blocks.del(&61700).unwrap(),
                "key-missing" => {
                    extra.after_key_block = false;
                    extra.last_key_block = None;
                }
                "key-override" => {
                    extra.after_key_block = false;
                    extra.last_key_block = Some(ExtBlkRef {
                        seq_no: 60000,
                        end_lt: 123456,
                        root_hash: [0x22; 32].into(),
                        file_hash: [0x33; 32].into(),
                    });
                }
                "current-key" => extra.after_key_block = true,
                _ => {}
            }
            if mode.starts_with("precompiled") {
                let mut entries = rtos_block::HashmapE::with_bit_len(256);
                for source in [
                    "DROP PUSHCTR c7",
                    "PUSHCTR c7 FIRST PUSHINT 13 INDEXVAR",
                    "PUSHCTR c7 FIRST PUSHINT 14 INDEXVAR",
                ] {
                    let code = rtos_assembler::compile_code_to_cell(source).unwrap();
                    let mut entry = rtos_block::BuilderData::new();
                    if mode == "precompiled-trailing" {
                        0xb0u8.write_to(&mut entry).unwrap();
                        123u64.write_to(&mut entry).unwrap();
                        1u8.write_to(&mut entry).unwrap();
                    }
                    entries
                        .set_builder(code.repr_hash().write_to_bitstring().unwrap(), &entry)
                        .unwrap();
                }
                let mut param = rtos_block::BuilderData::new();
                (if mode == "precompiled-tag" { 0xffu8 } else { 0xc0u8 })
                    .write_to(&mut param)
                    .unwrap();
                entries.write_to(&mut param).unwrap();
                let mut value = rtos_block::BuilderData::new();
                value.checked_append_reference(param.into_cell().unwrap()).unwrap();
                extra
                    .config
                    .config_params
                    .set_builder(45u32.write_to_bitstring().unwrap(), &value)
                    .unwrap();
            }
            mc.write_custom(Some(&extra)).unwrap();
            let state = mc.serialize().unwrap();
            let id = BlockIdExt::with_params(
                ShardIdent::masterchain(),
                mc.seq_no(),
                [0x99; 32].into(),
                [0xa5; 32].into(),
            );
            let tag = format!("{version}-history-{mode}");
            if let Some(path) = &export {
                std::fs::write(
                    format!("{path}/get-state-v{tag}.boc"),
                    rtos_block::write_boc(&state).unwrap(),
                )
                .unwrap();
            }
            for now in [0, 199, 200] {
                for (probe, source) in [
                    ("context", "DROP PUSHCTR c7"),
                    ("previous", "PUSHCTR c7 FIRST PUSHINT 13 INDEXVAR"),
                    ("unpacked", "PUSHCTR c7 FIRST PUSHINT 14 INDEXVAR"),
                ] {
                    let name = format!("history-v{version}-{mode}-now{now}-{probe}");
                    if filter.as_ref().is_some_and(|f| !name.contains(f)) {
                        continue;
                    }
                    let code = rtos_assembler::compile_code_to_cell(source).unwrap();
                    let mut init = StateInit::default();
                    init.set_code(code.clone());
                    init.set_data(Cell::default());
                    let address =
                        rtos_block::MsgAddressInt::with_standart(None, -1, [0x5a; 32].into())
                            .unwrap();
                    let mut account = Account::active(
                        address,
                        CurrencyCollection::with_coins(10_000_000_000u64),
                        0,
                        0,
                        init,
                        1000,
                    )
                    .unwrap();
                    account.set_due_payment(Some(Coins::from(123u64)));
                    let result = if probe == "context" {
                        run_smc_method_with_seed(
                            &account,
                            state.clone(),
                            12345,
                            Vec::new(),
                            now,
                            2000000000,
                            [0; 32],
                            Some(&id),
                        )
                    } else {
                        run_smc_method_with_block_id(
                            &account,
                            state.clone(),
                            &id,
                            12345,
                            Vec::new(),
                            now,
                            2000000000,
                        )
                    };
                    let actual = match result {
                        Ok(result) => format!(
                            "{}\t{}\t{}",
                            result.exit_code,
                            result.gas_used,
                            result.stack.iter().map(render).collect::<Vec<_>>().join(",")
                        ),
                        Err(_) => "ERROR\tERROR\tERROR".into(),
                    };
                    if export.is_none() {
                        let expected = include_str!("data/get-history-context.tsv")
                            .lines()
                            .find(|l| l.split('\t').next() == Some(name.as_str()))
                            .expect("frozen history getter");
                        assert_eq!(format!("{name}\t{actual}"), expected, "{name}");
                    }
                    rows.push(format!(
                        "{name}\t{tag}\t{now}\t{}\t{}\t{}\t{}:{}:{}\t{actual}",
                        hex(&rtos_block::write_boc(&account.serialize().unwrap()).unwrap()),
                        hex(&rtos_block::write_boc(&code).unwrap()),
                        hex(&[0; 32]),
                        id.seq_no(),
                        hex(id.root_hash().as_slice()),
                        hex(id.file_hash().as_slice())
                    ));
                }
            }
        }
    }
    if filter.is_none() {
        assert_eq!(rows.len(), 1314);
    } else {
        assert!(!rows.is_empty());
    }
    if let Some(path) = export {
        std::fs::write(format!("{path}/get-history-input.tsv"), rows.join("\n") + "\n").unwrap();
    }
}

#[test]
fn node_get_rejects_mismatched_snapshot_identifier() {
    let state = ShardStateUnsplit::construct_from_cell(
        read_single_root_boc_file("../block/src/tests/data/free-ton-mc-state-61884").unwrap(),
    )
    .unwrap();
    let mut init = StateInit::default();
    init.set_code(rtos_assembler::compile_code_to_cell("PUSHINT 1").unwrap());
    let address = rtos_block::MsgAddressInt::with_standart(None, -1, [0x5a; 32].into()).unwrap();
    let account = Account::active(
        address,
        CurrencyCollection::with_coins(10_000_000_000u64),
        0,
        0,
        init,
        1000,
    )
    .unwrap();
    let id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        state.seq_no(),
        [0x99; 32].into(),
        [0xa5; 32].into(),
    );
    let original = account.serialize().unwrap();
    for mode in ["wrong-sequence", "wrong-shard", "non-master-state"] {
        let mut state = state.clone();
        let mut id = id.clone();
        match mode {
            "wrong-sequence" => id.seq_no += 1,
            "wrong-shard" => id.shard_id = ShardIdent::full(0),
            "non-master-state" => {
                id.shard_id = ShardIdent::full(0);
                state.set_shard(ShardIdent::full(0));
            }
            _ => unreachable!(),
        }
        let error = run_smc_method_with_block_id(
            &account,
            state.serialize().unwrap(),
            &id,
            0,
            Vec::new(),
            200,
            2000000000,
        )
        .err()
        .expect("snapshot identity mismatch must fail");
        assert!(
            error.to_string().contains("Getter masterchain block identifier disagrees"),
            "{mode}: {error}"
        );
        assert_eq!(account.serialize().unwrap(), original);
    }
}
