// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::*;
use rtos_block::{
    read_single_root_boc_file, ConfigParam8, ConfigParamEnum, CurrencyCollection, ShardIdent,
    StateInit,
};
fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}
#[test]
fn node_get_signed_method_id_matches_cpp() {
    let export = std::env::var("RTOS_GET_METHOD_ID_EXPORT").ok();
    let filter = std::env::var("RTOS_GET_CASE_FILTER").ok();
    let mut rows = Vec::new();
    for version in [3, 14, 17, 19] {
        let mut mc = ShardStateUnsplit::construct_from_cell(
            read_single_root_boc_file("../block/src/tests/data/free-ton-mc-state-61884").unwrap(),
        )
        .unwrap();
        let mut extra = mc.read_custom().unwrap().unwrap();
        let mut p8 = ConfigParam8 { global_version: extra.config.get_global_version().unwrap() };
        p8.global_version.version = version;
        extra.config.set_config(ConfigParamEnum::ConfigParam8(p8)).unwrap();
        mc.write_custom(Some(&extra)).unwrap();
        let state = mc.serialize().unwrap();
        let id = BlockIdExt::with_params(
            ShardIdent::masterchain(),
            mc.seq_no(),
            [0x99; 32].into(),
            [0xa5; 32].into(),
        );
        let tag = format!("{version}-method-id");
        if let Some(path) = &export {
            std::fs::write(
                format!("{path}/get-state-v{tag}.boc"),
                rtos_block::write_boc(&state).unwrap(),
            )
            .unwrap();
        }
        for (index, method_id) in [
            i64::MIN,
            -4294967296,
            -1,
            0,
            1,
            12345,
            u32::MAX as i64,
            4294967296,
            4294979641,
            i64::MAX,
        ]
        .into_iter()
        .enumerate()
        {
            for probe in ["echo", "dispatch"] {
                let name = format!("method-v{version}-{index}-{probe}");
                if filter.as_ref().is_some_and(|f| !name.contains(f)) {
                    continue;
                }
                let source = if probe == "echo" {
                    "NOP".into()
                } else {
                    format!("PUSHINT {method_id} EQUAL PUSHCONT {{ PUSHINT 111 }} PUSHCONT {{ PUSHINT 222 }} IFELSE")
                };
                let code = rtos_assembler::compile_code_to_cell(&source).unwrap();
                let mut init = StateInit::default();
                init.set_code(code.clone());
                init.set_data(Cell::default());
                let mut account = Account::active(
                    rtos_block::MsgAddressInt::with_standart(None, -1, [0x5a; 32].into()).unwrap(),
                    CurrencyCollection::with_coins(10_000_000_000u64),
                    0,
                    0,
                    init,
                    1000,
                )
                .unwrap();
                account.set_due_payment(Some(rtos_block::Coins::from(123u64)));
                let result = run_smc_method_with_block_id(
                    &account,
                    state.clone(),
                    &id,
                    method_id,
                    Vec::new(),
                    200,
                    2000000000,
                )
                .unwrap();
                // Existing u32 callers retain the same dispatch behavior.
                if let Ok(legacy_id) = u32::try_from(method_id) {
                    let legacy = run_smc_method(
                        &account,
                        state.clone(),
                        legacy_id,
                        Vec::new(),
                        200,
                        2000000000,
                    )
                    .unwrap();
                    assert_eq!(legacy.exit_code, result.exit_code, "legacy {name}");
                    assert_eq!(legacy.gas_used, result.gas_used, "legacy {name}");
                    assert_eq!(legacy.stack, result.stack, "legacy {name}");
                }
                let actual = format!(
                    "{}\t{}\t{}",
                    result.exit_code,
                    result.gas_used,
                    result
                        .stack
                        .iter()
                        .map(|x| x.as_integer().unwrap().to_str_radix(10))
                        .collect::<Vec<_>>()
                        .join(",")
                );
                if export.is_none() {
                    let expected = include_str!("data/get-method-id-context.tsv")
                        .lines()
                        .find(|l| l.split('\t').next() == Some(name.as_str()))
                        .expect("frozen method-id fixture");
                    assert_eq!(
                        actual,
                        expected.split('\t').skip(4).collect::<Vec<_>>().join("\t"),
                        "{name}"
                    );
                }
                rows.push(format!(
                    "{name}\t{tag}\t200\t{}\t{}\t{}\t{}:{}:{}\t{method_id}\t{actual}",
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
    if filter.is_none() {
        assert_eq!(rows.len(), 80);
    } else {
        assert!(!rows.is_empty());
    }
    if let Some(path) = export {
        std::fs::write(format!("{path}/get-method-id-input.tsv"), rows.join("\n") + "\n").unwrap();
    }
}
