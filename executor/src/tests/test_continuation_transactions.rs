// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
// Complete transactions whose contract code uses continuation chains, loops with non-ordinary
// bodies, BOOLEVAL and TRY. The transaction and account roots in
// data/continuation-transactions.tsv were produced by the reference transaction driver from the
// rows this test exports with RTOS_CONT_TX_EXPORT.
use crate::{BlockchainConfig, ExecuteParams, OrdinaryTransactionExecutor, TransactionExecutor};
use rtos_block::{
    Account, Cell, ConfigParam8, ConfigParamEnum, CurrencyCollection, ExternalInboundMessageHeader,
    GetRepresentationHash, HashUpdate, InternalMessageHeader, Message, MsgAddressInt, Serializable,
    StateInit,
};
mod common;
use common::create_config;

fn boc(c: Cell) -> String {
    rtos_block::write_boc(&c).unwrap().iter().map(|b| format!("{b:02x}")).collect()
}
fn hex_bytes(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}
fn config(version: u32) -> BlockchainConfig {
    let mut raw = create_config("real_boc/config.boc").unwrap();
    let mut p8 = ConfigParam8 { global_version: raw.get_global_version().unwrap() };
    p8.global_version.version = version;
    raw.set_config(ConfigParamEnum::ConfigParam8(p8)).unwrap();
    BlockchainConfig::with_config(raw).unwrap()
}

fn run(name: &str, config: BlockchainConfig, mut account: Account, msg: Cell) -> String {
    let decoded =
        <Message as rtos_block::Deserializable>::construct_from_cell(msg.clone()).unwrap();
    let address = decoded.dst().unwrap();
    let input = format!(
        "{name}\t200\t2000000001\t{}\t{}\t{}\t-\t0\t{}\t{}",
        boc(config.raw_config().serialize().unwrap()),
        boc(account.serialize().unwrap()),
        boc(msg.clone()),
        address.workchain_id(),
        hex_bytes(address.address().get_bytestring(0).as_ref())
    );
    let old = account.hash().unwrap();
    let dict_threshold = config.size_limits_config().acc_state_cells_for_storage_dict;
    let params = ExecuteParams {
        block_unixtime: 200,
        block_lt: 2_000_000_000,
        last_tr_lt: 2_000_000_001,
        ..Default::default()
    };
    match OrdinaryTransactionExecutor::new(config).execute_with_params(
        Some(msg),
        &mut account,
        params,
    ) {
        Ok(mut tx) => {
            let changed =
                account.precalc_storage_stat().unwrap().is_some_and(|stat| stat.is_changed());
            let needs_dict = account.get_addr().is_some_and(|a| !a.is_masterchain())
                && account.dict_hash().is_none()
                && account
                    .storage_info()
                    .is_some_and(|s| s.used().cells() >= dict_threshold as u64);
            if changed || needs_dict {
                account.calc_storage_stat_dict(dict_threshold).unwrap();
            }
            tx.write_state_update(&HashUpdate::with_hashes(old, account.hash().unwrap())).unwrap();
            format!("{input}\t{:x}\t{:x}", tx.hash().unwrap(), account.hash().unwrap())
        }
        Err(_) => format!("{input}\tERROR\tERROR"),
    }
}

#[test]
fn continuation_transactions_match_reference() {
    let chain = |op: &str, n: usize, tail: &str| format!("{} {tail}", vec![op; n].join(" "));
    let store = "DEPTH NEWC STU 32 ENDC POPROOT";
    let mut programs: Vec<(String, String)> = vec![];
    for depth in [7, 8, 9, 12] {
        programs.push((
            format!("repeatend-d{depth}"),
            chain("PUSHINT 1 REPEATEND", depth, &format!("PUSHINT 5 {store}")),
        ));
        programs.push((
            format!("repeatendbrk-d{depth}"),
            chain("PUSHINT 1 REPEATENDBRK", depth, &format!("PUSHINT 5 {store}")),
        ));
        programs.push((
            format!("untilend-d{depth}"),
            format!("{} {store}", chain("UNTILEND", depth, &vec!["TRUE"; depth].join(" "))),
        ));
    }
    programs.extend(
        [
            ("repeat-cap1", "PUSHINT 3 PUSHINT 100 PUSHCONT { INC } SETCONTARGS 1 REPEAT"),
            ("repeat-nargs1", "PUSHINT 3 PUSHCONT { INC } SETNUMARGS 1 REPEAT"),
            ("repeat-body-c0", "PUSHINT 3 PUSHCONT { PUSHINT 99 } PUSHCONT { INC } SETCONTCTR c0 REPEAT"),
            ("repeat-loop-body", "PUSHINT 2 PUSHINT 2 PUSHCONT { PUSHCTR c0 } REPEAT REPEAT"),
            ("while-pushint", "PUSHCONT { DUP PUSHINT 3 LESS } PUSHCONT { PUSHCTR c1 } BOOLEVAL DROP WHILE"),
            ("booleval-jmpx", "PUSHCONT { PUSHCTR c0 JMPX } BOOLEVAL"),
            ("booleval-callx", "PUSHCONT { PUSHCTR c1 CALLX } BOOLEVAL"),
            ("booleval-callxargs", "PUSHCONT { PUSHCTR c0 CALLXARGS 0, 1 } BOOLEVAL"),
            ("try-envelope", "PUSHCONT { THROW 73 } PUSHCONT { PUSHINT 62 } PUSHCTR c0 SETCONTCTR c1 TRY"),
            ("try-handler-c0", "PUSHCONT { THROW 73 } PUSHCONT { PUSHINT 63 } PUSHCONT { PUSHINT 64 } SETCONTCTR c0 TRY"),
            ("try-quit1", "PUSHCONT { THROW 73 } PUSHCTR c1 TRY"),
            ("try-outer", "PUSHCONT { PUSHCONT { THROW 85 } PUSHCONT { DROP DROP } TRY THROW 86 } PUSHCONT { PUSHINT 87 } TRY"),
            ("tryargs-pushint", "PUSHCONT { THROW 73 } PUSHCONT { PUSHCTR c1 } BOOLEVAL DROP TRYARGS 1, 1"),
            ("c2-dispatch-failure", "PUSHCONT { PUSHINT 1 } SETNUMARGS 3 POPCTR c2 THROW 90"),
            ("chain-after-nargs", "PUSHCONT { PUSHINT 8 DEPTH NEWC STU 32 ENDC POPROOT } SETNUMARGS 1 POPCTR c0 PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 5"),
        ]
        .iter()
        .map(|(n, c)| (n.to_string(), format!("{c} {store}"))),
    );
    let mut rows = vec![];
    for version in [8, 9, 12, 16] {
        for external in [false, true] {
            for (case, source) in &programs {
                let name = format!("cont-{case}-v{version}-external{external}");
                let address = MsgAddressInt::with_standart(None, 0, [0x5e; 32].into()).unwrap();
                let cfg = config(version);
                let mut state = StateInit::default();
                let code = if external { format!("ACCEPT {source}") } else { source.clone() };
                state.set_code(rtos_assembler::compile_code_to_cell(&code).unwrap());
                state.set_data(Cell::default());
                let account = Account::active(
                    address.clone(),
                    CurrencyCollection::with_coins(10_000_000_000u64),
                    0,
                    100,
                    state,
                    cfg.size_limits_config().acc_state_cells_for_storage_dict,
                )
                .unwrap();
                let msg = if external {
                    Message::with_ext_in_header(ExternalInboundMessageHeader {
                        dst: address.clone(),
                        ..Default::default()
                    })
                } else {
                    let mut header = InternalMessageHeader::with_addresses(
                        MsgAddressInt::with_standart(None, 0, [0x11; 32].into()).unwrap(),
                        address,
                        CurrencyCollection::with_coins(1_000_000_000u64),
                    );
                    header.created_lt = 1000;
                    Message::with_int_header(header)
                };
                rows.push(run(&name, cfg, account, msg.serialize().unwrap()));
            }
        }
    }
    assert_eq!(rows.len(), 216);
    if let Ok(path) = std::env::var("RTOS_CONT_TX_EXPORT") {
        std::fs::write(path, rows.join("\n") + "\n").unwrap();
        return;
    }
    let expected = include_str!("data/continuation-transactions.tsv")
        .lines()
        .map(|l| {
            let f = l.split('\t').collect::<Vec<_>>();
            (f[0], (f[1], f[2]))
        })
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(expected.len(), rows.len());
    for row in &rows {
        let f = row.split('\t').collect::<Vec<_>>();
        assert_eq!(Some(&(f[10], f[11])), expected.get(f[0]), "{}", f[0]);
    }
}
