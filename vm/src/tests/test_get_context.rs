// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::*;
use rtos_block::{
    read_single_root_boc_file, ConfigParam8, ConfigParamEnum, CurrencyCollection, IBitstring,
    ShardAccounts, StateInit,
};

#[test]
fn getter_version16_import_slot_is_present_and_null() {
    for (version, length) in [(15, 18), (16, 19), (17, 19)] {
        let mut info = SmartContractInfo::default();
        let mut param = ConfigParam8::default();
        param.global_version.version = version;
        info.config_params.set_config(ConfigParamEnum::ConfigParam8(param)).unwrap();
        info.incoming_storage_stats =
            Some(IncomingStorageStats { hash: UInt256::default(), cells: 7, bits: 9 });
        let outer = info.as_get_method_data_item().unwrap().as_tuple_mut().unwrap();
        let fields = outer[0].as_tuple().unwrap();
        assert_eq!(fields.len(), length, "version {version}");
        if version >= 16 {
            assert!(fields[18].is_null());
        }
    }
}

#[test]
fn node_getter_without_code_does_not_read_precompiled_dictionary() {
    let ctx = include_str!(
        "../../tests/data/conformance/get_method/fixtures/review-account-boundary.jsonl"
    )
    .lines()
    .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
    .find(|record| record["metadata"]["fixture_id"] == "no-code-pruned-precompiled")
    .unwrap()["context"]
        .clone();
    let cell = |key: &str| {
        read_single_root_boc(rtos_block::base64_decode(ctx[key].as_str().unwrap()).unwrap())
            .unwrap()
    };
    let account = Account::construct_from_full_cell(cell("account")).unwrap();
    assert!(account.get_code().is_none());
    let id = &ctx["mc_block"];
    let id = BlockIdExt::with_params(
        rtos_block::ShardIdent::masterchain(),
        id["seqno"].as_u64().unwrap() as u32,
        id["root_hash"].as_str().unwrap().parse().unwrap(),
        id["file_hash"].as_str().unwrap().parse().unwrap(),
    );
    let result = run_smc_method_with_seed(
        &account,
        cell("mc_state"),
        ctx["method_id"].as_str().unwrap().parse().unwrap(),
        Vec::new(),
        ctx["now"].as_u64().unwrap() as u32,
        ctx["lt"].as_u64().unwrap(),
        [0; 32],
        Some(&id),
    )
    .unwrap();
    assert_eq!((result.exit_code, result.gas_used), (-13, 0));
    assert!(!result.code_present);
    let outer = result.initial_c7(true).unwrap().as_tuple_mut().unwrap();
    let fields = outer[0].as_tuple().unwrap();
    assert!(fields[10].is_null());
    assert!(fields[16].is_null());
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
#[test]
fn node_get_context_matches_cpp() {
    let export = std::env::var("RTOS_GET_EXPORT").ok();
    let mut rows = Vec::new();
    let filter = std::env::var("RTOS_GET_CASE_FILTER").ok();
    for version in [3, 4, 5, 6, 10, 11, 13, 14, 15, 16, 17, 18, 19] {
        let mut mc = ShardStateUnsplit::construct_from_cell(
            read_single_root_boc_file("../block/src/tests/data/free-ton-mc-state-61884").unwrap(),
        )
        .unwrap();
        mc.write_accounts(&ShardAccounts::default()).unwrap();
        let mut extra = mc.read_custom().unwrap().unwrap();
        let mut param = ConfigParam8 { global_version: extra.config.get_global_version().unwrap() };
        param.global_version.version = version;
        extra.config.set_config(ConfigParamEnum::ConfigParam8(param)).unwrap();
        let mut precompiled = rtos_block::PrecompiledContractsList::default();
        for cost in [0, 123] {
            let code = rtos_assembler::compile_code_to_cell(&format!(
                "PUSHINT {cost} DROP PUSHCTR c7 FIRST PUSHINT 16 INDEXVAR"
            ))
            .unwrap();
            precompiled.add(code.repr_hash(), cost).unwrap();
        }
        extra.config.set_config(ConfigParamEnum::ConfigParam45(precompiled)).unwrap();
        mc.write_custom(Some(&extra)).unwrap();
        let state = mc.serialize().unwrap();
        if let Some(path) = &export {
            std::fs::write(
                format!("{path}/get-state-v{version}.boc"),
                rtos_block::write_boc(&state).unwrap(),
            )
            .unwrap();
        }
        for now in [0, 200] {
            for (probe, source) in [
                ("magic", "PUSHCTR c7 FIRST FIRST"),
                ("actions", "PUSHCTR c7 FIRST PUSHINT 1 INDEXVAR"),
                ("msgs", "PUSHCTR c7 FIRST PUSHINT 2 INDEXVAR"),
                ("seed", "PUSHCTR c7 FIRST PUSHINT 6 INDEXVAR"),
                ("seed-high", "PUSHCTR c7 FIRST PUSHINT 6 INDEXVAR"),
                ("seed-max", "PUSHCTR c7 FIRST PUSHINT 6 INDEXVAR"),
                ("balance-extra", "PUSHCTR c7 FIRST PUSHINT 7 INDEXVAR PUSHINT 1 INDEXVAR ISNULL"),
                ("address", "PUSHCTR c7 FIRST PUSHINT 8 INDEXVAR NEWC STSLICE ENDC HASHCU"),
                ("config", "PUSHCTR c7 FIRST PUSHINT 9 INDEXVAR HASHCU"),
                ("precompiled-zero", "PUSHINT 0 DROP PUSHCTR c7 FIRST PUSHINT 16 INDEXVAR"),
                ("precompiled-cost", "PUSHINT 123 DROP PUSHCTR c7 FIRST PUSHINT 16 INDEXVAR"),
                ("length", "PUSHCTR c7 FIRST TLEN"),
                ("null", "PUSHCTR c7 FIRST PUSHINT 18 INDEXVAR ISNULL"),
                ("fields", "PUSHCTR c7 FIRST PUSHINT 18 INDEXVAR UNTUPLE 4"),
                ("msg-length", "PUSHCTR c7 FIRST PUSHINT 17 INDEXVAR TLEN"),
                ("msg-time", "PUSHCTR c7 FIRST PUSHINT 17 INDEXVAR PUSHINT 5 INDEXVAR"),
                ("msg-value", "PUSHCTR c7 FIRST PUSHINT 17 INDEXVAR PUSHINT 7 INDEXVAR"),
                ("msg-src", "PUSHCTR c7 FIRST PUSHINT 17 INDEXVAR PUSHINT 2 INDEXVAR SBITS"),
                ("msg-extra", "PUSHCTR c7 FIRST PUSHINT 17 INDEXVAR PUSHINT 8 INDEXVAR ISNULL"),
                ("balance", "PUSHCTR c7 FIRST PUSHINT 7 INDEXVAR FIRST"),
                ("now", "NOW"),
                ("block-lt", "BLOCKLT"),
                ("trans-lt", "LTIME"),
                ("due", "PUSHCTR c7 FIRST PUSHINT 15 INDEXVAR"),
                ("precompiled", "PUSHCTR c7 FIRST PUSHINT 16 INDEXVAR ISNULL"),
                ("code", "PUSHCTR c7 FIRST PUSHINT 10 INDEXVAR HASHCU"),
                ("throw", "PUSHINT 77 THROWANY"),
                ("underflow", "DROP DROP"),
            ] {
                let mut init = StateInit::default();
                let code = rtos_assembler::compile_code_to_cell(source).unwrap();
                init.set_code(code.clone());
                init.set_data(Cell::default());
                let address =
                    rtos_block::MsgAddressInt::with_standart(None, -1, [0x5a; 32].into()).unwrap();
                let mut account = Account::active(
                    address,
                    CurrencyCollection::with_coins(10_000_000_000u64),
                    0,
                    0,
                    init,
                    1000,
                )
                .unwrap();
                account.set_due_payment(Some(rtos_block::Coins::from(123u64)));
                let mut seed = [0u8; 32];
                if probe == "seed-high" {
                    seed[0] = 0x80;
                }
                if probe == "seed-max" {
                    seed.fill(0xff);
                }
                let result = if probe.starts_with("seed") {
                    run_smc_method_with_seed(
                        &account,
                        state.clone(),
                        12345,
                        Vec::new(),
                        now,
                        2000000000,
                        seed,
                        None,
                    )
                } else {
                    run_smc_method(&account, state.clone(), 12345, Vec::new(), now, 2000000000)
                }
                .unwrap();
                let stack = result
                    .stack
                    .iter()
                    .map(|s| {
                        if s.is_null() {
                            "null".into()
                        } else {
                            s.as_integer().unwrap().to_str_radix(10)
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                let name = format!("get-v{version}-now{now}-{probe}");
                if filter.as_ref().is_some_and(|f| !name.contains(f)) {
                    continue;
                }
                let actual = format!("{}\t{}\t{}", result.exit_code, result.gas_used, stack);
                if export.is_none() {
                    let expected = include_str!("data/get-context.tsv")
                        .lines()
                        .find(|l| l.split('\t').next() == Some(name.as_str()))
                        .expect("frozen getter");
                    assert_eq!(format!("{name}\t{actual}"), expected, "{name}");
                }
                rows.push(format!(
                    "{name}\t{version}\t{now}\t{}\t{}\t{}\t{actual}",
                    hex(&rtos_block::write_boc(&account.serialize().unwrap()).unwrap()),
                    hex(&rtos_block::write_boc(&code).unwrap()),
                    hex(&seed)
                ));
            }
        }
    }
    for version in [14, 15, 17, 19] {
        for mode in ["account", "global", "both", "missing", "shadow-invalid"] {
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
            mc.write_custom(Some(&extra)).unwrap();
            let lib = rtos_assembler::compile_code_to_cell("PUSHINT 99").unwrap();
            let mut b = rtos_block::BuilderData::new();
            b.append_u8(0x88).unwrap();
            b.checked_append_reference(lib.as_library_cell()).unwrap();
            b.append_builder(
                &rtos_assembler::compile_code_to_builder("CTOS DROP PUSHINT 99").unwrap(),
            )
            .unwrap();
            let code = b.into_cell().unwrap();
            let mut init = StateInit::default();
            init.set_code(code.clone());
            init.set_data(Cell::default());
            if mode == "account" || mode == "both" {
                init.set_library_code(lib.clone(), true).unwrap();
            }
            if mode == "shadow-invalid" {
                let mut dict = rtos_block::StateInitLib::default();
                dict.set(lib.repr_hash(), &rtos_block::SimpleLib::new(Cell::default(), true))
                    .unwrap();
                init.set_library(dict.root().unwrap().clone());
            }
            if mode == "global" || mode == "both" || mode == "shadow-invalid" {
                mc.libraries_mut()
                    .set(
                        lib.repr_hash(),
                        &rtos_block::LibDescr::from_lib_data_by_publisher(
                            lib.clone(),
                            [0x5a; 32].into(),
                        ),
                    )
                    .unwrap();
            }
            let state = mc.serialize().unwrap();
            let tag = format!("{version}-{mode}");
            if let Some(path) = &export {
                std::fs::write(
                    format!("{path}/get-state-v{tag}.boc"),
                    rtos_block::write_boc(&state).unwrap(),
                )
                .unwrap();
            }
            let address =
                rtos_block::MsgAddressInt::with_standart(None, -1, [0x5a; 32].into()).unwrap();
            let mut account = Account::active(
                address,
                CurrencyCollection::with_coins(10_000_000_000u64),
                0,
                0,
                init,
                1000,
            )
            .unwrap();
            account.set_due_payment(Some(rtos_block::Coins::from(123u64)));
            let result =
                run_smc_method(&account, state, 12345, Vec::new(), 200, 2000000000).unwrap();
            let stack = result
                .stack
                .iter()
                .map(|s| {
                    if s.is_null() {
                        "null".into()
                    } else {
                        s.as_integer().unwrap().to_str_radix(10)
                    }
                })
                .collect::<Vec<_>>()
                .join(",");
            let name = format!("get-v{version}-library-{mode}");
            if filter.as_ref().is_some_and(|f| !name.contains(f)) {
                continue;
            }
            let actual = format!("{}\t{}\t{}", result.exit_code, result.gas_used, stack);
            if export.is_none() {
                let expected = include_str!("data/get-context.tsv")
                    .lines()
                    .find(|l| l.split('\t').next() == Some(name.as_str()))
                    .expect("frozen getter");
                assert_eq!(format!("{name}\t{actual}"), expected, "{name}");
            }
            rows.push(format!(
                "{name}\t{tag}\t200\t{}\t{}\t{}\t{actual}",
                hex(&rtos_block::write_boc(&account.serialize().unwrap()).unwrap()),
                hex(&rtos_block::write_boc(&code).unwrap()),
                hex(&[0; 32])
            ));
        }
    }
    if filter.is_none() {
        assert_eq!(rows.len(), 748);
    } else {
        assert!(!rows.is_empty(), "case filter matched no rows");
    }
    if let Some(path) = export {
        std::fs::write(format!("{path}/get-input.tsv"), rows.join("\n") + "\n").unwrap();
    }
}

#[test]
fn node_get_seed_source_and_public_entry() {
    let state =
        read_single_root_boc_file("../block/src/tests/data/free-ton-mc-state-61884").unwrap();
    let mut init = StateInit::default();
    init.set_code(
        rtos_assembler::compile_code_to_cell("PUSHCTR c7 FIRST PUSHINT 6 INDEXVAR").unwrap(),
    );
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
    struct FixedRng {
        calls: usize,
        bytes: usize,
        fail: bool,
    }
    impl rand::CryptoRng for FixedRng {}
    impl rand::RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            panic!("expected a byte fill")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("expected a byte fill")
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.calls += 1;
            self.bytes += dest.len();
            dest.fill(0x5a);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand::Error> {
            if self.fail {
                return Err(rand::Error::new(std::io::Error::other("injected entropy failure")));
            }
            self.fill_bytes(dest);
            Ok(())
        }
    }
    let mut rng = FixedRng { calls: 0, bytes: 0, fail: false };
    let result = run_smc_method_with_rng(
        &account,
        state.clone(),
        0,
        Vec::new(),
        200,
        2000000000,
        None,
        &mut rng,
    )
    .unwrap();
    assert_eq!(rng.calls, 1);
    assert_eq!(rng.bytes, 32);
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.smc_info.rand_seed, IntegerData::from_unsigned_bytes_be(&[0x5a; 32]));
    assert_eq!(result.stack.last().unwrap().as_integer().unwrap(), &result.smc_info.rand_seed);
    let reduced = result.initial_c7_with_rng(false, &mut rng).unwrap();
    assert_eq!(rng.calls, 2);
    assert_eq!(rng.bytes, 64);
    let fields = reduced.as_tuple().unwrap()[0].as_tuple().unwrap();
    assert_eq!(fields.len(), 10);
    assert!(fields[9].is_null());
    assert_eq!(fields[6].as_integer().unwrap(), &IntegerData::from_unsigned_bytes_be(&[0x5a; 32]));
    result.initial_c7_with_rng(true, &mut rng).unwrap();
    assert_eq!(rng.calls, 2, "full c7 retains the execution seed");
    rng.fail = true;
    assert!(result
        .initial_c7_with_rng(false, &mut rng)
        .err()
        .unwrap()
        .to_string()
        .contains("injected entropy failure"));
    let error = run_smc_method_with_rng(
        &account,
        state.clone(),
        0,
        Vec::new(),
        200,
        2000000000,
        None,
        &mut rng,
    )
    .err()
    .expect("entropy failure must propagate");
    assert!(error.to_string().contains("injected entropy failure"));
    // Smoke-test the actual OS source without probabilistic entropy assertions.
    let public = run_smc_method(&account, state, 0, Vec::new(), 200, 2000000000).unwrap();
    assert_eq!(public.exit_code, 0);
    assert_eq!(public.stack.last().unwrap().as_integer().unwrap(), &public.smc_info.rand_seed);
}
