// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use crate::{BlockchainConfig, ExecuteParams, OrdinaryTransactionExecutor, TransactionExecutor};
use rtos_block::{
    Account, BuilderData, Cell, ConfigParam31, ConfigParam8, ConfigParamEnum, CurrencyCollection,
    Deserializable, GetRepresentationHash, HashUpdate, InternalMessageHeader, Message,
    MsgAddressInt, Serializable, SizeLimitsConfig, SliceData, StateInit,
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
            if std::env::var_os("RTOS_SENDMSG_TRANSACTION_EXPORT").is_none() {
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
    let th = format!("{:x}", tx.hash().unwrap());
    let ah = format!("{:x}", account.hash().unwrap());
    if std::env::var_os("RTOS_SENDMSG_TRANSACTION_EXPORT").is_none() {
        let expected = include_str!("data/sendmsg.tsv")
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
fn sendmsg_complete_transactions() {
    let filter = std::env::var("RTOS_SENDMSG_CASE_FILTER").unwrap_or_default();
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("data/sendmsg-cases.json")).unwrap();
    let mut rows = Vec::new();
    for case in cases.as_array().unwrap() {
        for bounce in [false, true] {
            for special in [false, true] {
                let name =
                    format!("{}-bounce{bounce}-special{special}", case["name"].as_str().unwrap());
                if !name.contains(&filter) {
                    continue;
                }
                let version = case["version"].as_u64().unwrap() as u32;
                let mode = case["mode"].as_u64().unwrap();
                let addr = MsgAddressInt::standard(if special { -1 } else { 0 }, [0x61; 32]);
                let mut raw = config(version, special, &addr).raw_config().clone();
                let limits = SizeLimitsConfig::construct_from_bytes(&hex_decode(
                    case["limits"].as_str().unwrap(),
                ))
                .unwrap();
                raw.set_config(ConfigParamEnum::ConfigParam43(limits)).unwrap();
                let cfg = BlockchainConfig::with_config(raw).unwrap();
                let setup = case["setup"].as_str().unwrap_or("");
                let source = format!(
                    "{setup} DROP LDREF ENDS PUSHINT {mode} SENDMSG NEWC STU 128 ENDC POPROOT"
                );
                let code = rtos_assembler::compile_code_to_cell(&source).unwrap();
                let mut init = StateInit::default();
                init.set_code(code);
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
                let mut msg = message(addr, bounce);
                let mut body = BuilderData::new();
                body.checked_append_reference(
                    rtos_block::read_single_root_boc(&hex_decode(
                        case["message"].as_str().unwrap(),
                    ))
                    .unwrap(),
                )
                .unwrap();
                msg.set_body(SliceData::load_builder(body).unwrap());
                run(&name, cfg, account, msg, special, &mut rows);
            }
        }
    }
    if let Ok(path) = std::env::var("RTOS_SENDMSG_TRANSACTION_EXPORT") {
        std::fs::write(path, rows.join("\n") + "\n").unwrap();
    } else {
        assert!(!rows.is_empty());
        assert_eq!(
            include_str!("data/sendmsg.tsv")
                .lines()
                .filter(|line| line.split('\t').next().unwrap().contains(&filter))
                .count(),
            rows.len()
        );
    }
}
fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
