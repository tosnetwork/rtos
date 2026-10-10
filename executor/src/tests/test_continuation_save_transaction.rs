// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use crate::{BlockchainConfig, ExecuteParams, OrdinaryTransactionExecutor, TransactionExecutor};
use rtos_block::{
    Account, Cell, ConfigParam31, ConfigParam8, ConfigParamEnum, CurrencyCollection,
    ExternalInboundMessageHeader, GetRepresentationHash, HashUpdate, InternalMessageHeader,
    Message, MsgAddressInt, Serializable, StateInit,
};
mod common;
use common::create_config;

fn boc(c: Cell) -> String {
    rtos_block::write_boc(&c).unwrap().iter().map(|b| format!("{b:02x}")).collect()
}
fn config(version: u32, special: bool, address: &MsgAddressInt) -> BlockchainConfig {
    let mut raw = create_config("real_boc/config.boc").unwrap();
    let mut p8 = ConfigParam8 { global_version: raw.get_global_version().unwrap() };
    p8.global_version.version = version;
    raw.set_config(ConfigParamEnum::ConfigParam8(p8)).unwrap();
    if special {
        let mut p31 = ConfigParam31::default();
        p31.add_address(address.address().clone());
        raw.set_config(ConfigParamEnum::ConfigParam31(p31)).unwrap();
    }
    BlockchainConfig::with_config(raw).unwrap()
}
fn message(address: MsgAddressInt, bounce: bool) -> Message {
    let mut header = InternalMessageHeader::with_addresses(
        MsgAddressInt::with_standart(None, 0, [0x11; 32].into()).unwrap(),
        address,
        CurrencyCollection::with_coins(1_000_000_000u64),
    );
    header.bounce = bounce;
    header.created_lt = 1000;
    Message::with_int_header(header)
}
fn run(
    name: &str,
    config: BlockchainConfig,
    mut account: Account,
    msg: Message,
    special: bool,
    rows: &mut Vec<String>,
) -> (rtos_block::Transaction, Account) {
    let address = msg.dst().unwrap();
    let input = format!(
        "{name}\t200\t2000000001\t{}\t{}\t{}\t-\t{}\t{}\t{}",
        boc(config.raw_config().serialize().unwrap()),
        boc(account.serialize().unwrap()),
        boc(msg.serialize().unwrap()),
        u8::from(special),
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
    let mut tx = match OrdinaryTransactionExecutor::new(config).execute_with_params(
        Some(msg.serialize().unwrap()),
        &mut account,
        params,
    ) {
        Ok(tx) => tx,
        Err(err) => {
            if std::env::var_os("RTOS_CONTINUATION_TRANSACTION_EXPORT").is_none() {
                panic!("{name}: {err}");
            }
            rows.push(format!("{input}\tERROR\tERROR"));
            return (rtos_block::Transaction::default(), account);
        }
    };
    // The node caller finalizes storage statistics before committing the account hash.
    let changed = account.precalc_storage_stat().unwrap().is_some_and(|stat| stat.is_changed());
    let needs_dict = account.get_addr().is_some_and(|a| !a.is_masterchain())
        && account.dict_hash().is_none()
        && account.storage_info().is_some_and(|s| s.used().cells() >= dict_threshold as u64);
    if changed || needs_dict {
        account.calc_storage_stat_dict(dict_threshold).unwrap();
    }
    tx.write_state_update(&HashUpdate::with_hashes(old, account.hash().unwrap())).unwrap();
    if let Ok(dir) = std::env::var("RTOS_CONTINUATION_TRANSACTION_DETAIL") {
        let path = std::path::Path::new(&dir);
        std::fs::write(
            path.join("rust-transaction.boc"),
            rtos_block::write_boc(&tx.serialize().unwrap()).unwrap(),
        )
        .unwrap();
        std::fs::write(
            path.join("rust-description.txt"),
            format!("{:#?}", tx.read_description().unwrap()),
        )
        .unwrap();
        if let Ok(bytes) = std::fs::read(path.join("cpp-transaction.boc")) {
            use rtos_block::Deserializable;
            let cpp = rtos_block::Transaction::construct_from_bytes(&bytes).unwrap();
            std::fs::write(
                path.join("cpp-description.txt"),
                format!("{:#?}", cpp.read_description().unwrap()),
            )
            .unwrap();
        }
    }
    let th = format!("{:x}", tx.hash().unwrap());
    let ah = format!("{:x}", account.hash().unwrap());
    if std::env::var_os("RTOS_CONTINUATION_TRANSACTION_EXPORT").is_none() {
        let expected = include_str!("data/continuation-save.tsv")
            .lines()
            .map(|l| l.split('\t').collect::<Vec<_>>())
            .find(|f| f[0] == name)
            .expect("frozen transaction");
        assert_eq!(th, expected[1], "{name} transaction");
        assert_eq!(ah, expected[2], "{name} account");
    }
    rows.push(format!("{input}\t{th}\t{ah}"));
    (tx, account)
}
fn hex_bytes(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn continuation_save_complete_transactions() {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("data/continuation-save-cases.json")).unwrap();
    let filter = std::env::var("RTOS_CONTINUATION_TRANSACTION_FILTER").unwrap_or_default();
    let mut rows = vec![];
    for c in cases.as_array().unwrap() {
        let versions = [3, 4, 12, 13, 14];
        for version in versions {
            for context in ["direct", "catch", "nested"] {
                if context == "nested" && version < 4 {
                    continue;
                }
                for kind in ["internal", "bounce", "external"] {
                    for special in [false, true] {
                        let name = format!(
                            "{}-v{version}-{context}-{kind}-special{special}",
                            c["name"].as_str().unwrap()
                        );
                        if !name.contains(&filter) {
                            continue;
                        }
                        let addr =
                            MsgAddressInt::standard(if special { -1 } else { 0 }, [0x62; 32]);
                        let cfg = config(version, special, &addr);
                        let store = if c["self_store"].as_bool().unwrap_or(false) {
                            ""
                        } else if c["unsigned"].as_bool().unwrap_or(false) {
                            "NEWC STU 256 ENDC POPROOT"
                        } else {
                            "NEWC STI 16 ENDC POPROOT"
                        };
                        let inner = c["source"].as_str().unwrap().to_owned();
                        let code_source = match context {
                            "catch" => format!(
                                "PUSHCONT {{ SWAP DROP NEWC STI 16 ENDC POPROOT }} POPCTR c2 {inner} {store}"
                            ),
                            "nested" => format!(
                                "PUSHINT 0 PUSHREFSLICE {{ {inner} }} PUSHCTR c7 RUNVM 16 {store}"
                            ),
                            _ => format!("{inner} {store}"),
                        };
                        let code_source = format!("ACCEPT BLKDROP 5 {code_source}");
                        let mut init = StateInit::default();
                        init.set_code(rtos_assembler::compile_code_to_cell(&code_source).unwrap());
                        init.set_data(Cell::default());
                        let account = Account::active(
                            addr.clone(),
                            CurrencyCollection::with_coins(10_000_000_000u64),
                            0,
                            if special { 0 } else { 100 },
                            init,
                            cfg.size_limits_config().acc_state_cells_for_storage_dict,
                        )
                        .unwrap();
                        let msg = if kind == "external" {
                            Message::with_ext_in_header(ExternalInboundMessageHeader {
                                dst: addr,
                                ..Default::default()
                            })
                        } else {
                            message(addr, kind == "bounce")
                        };
                        run(&name, cfg, account, msg, special, &mut rows);
                    }
                }
            }
        }
    }
    assert!(!rows.is_empty());
    if let Ok(path) = std::env::var("RTOS_CONTINUATION_TRANSACTION_EXPORT") {
        std::fs::write(path, rows.join("\n") + "\n").unwrap()
    } else {
        assert_eq!(
            rows.len(),
            include_str!("data/continuation-save.tsv")
                .lines()
                .filter(|line| line.split('\t').next().unwrap().contains(&filter))
                .count()
        );
    }
}
