// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use crate::{BlockchainConfig, ExecuteParams, OrdinaryTransactionExecutor, TransactionExecutor};
use rtos_block::{
    Account, BuilderData, Cell, ConfigParam31, ConfigParam8, ConfigParamEnum, CurrencyCollection,
    GetRepresentationHash, HashUpdate, IBitstring, InternalMessageHeader, Message, MsgAddressInt,
    Serializable, SliceData, StateInit,
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
            if std::env::var_os("RTOS_LMS_FEE_EXPORT").is_none() {
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
    if std::env::var_os("RTOS_LMS_FEE_EXPORT").is_none() {
        let expected = include_str!("data/lms-fee.tsv")
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
fn lms_fee_complete_transactions() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../vm/tests/data/lms-fee.json")).unwrap();
    let cells: Vec<_> = fixture["cells"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            let bytes = v
                .as_str()
                .unwrap()
                .as_bytes()
                .chunks_exact(2)
                .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
                .collect::<Vec<_>>();
            rtos_block::read_single_root_boc(bytes).unwrap()
        })
        .collect();
    let mut rows = Vec::new();
    for case in fixture["cases"].as_array().unwrap() {
        if case["version"] != 17
            || case["gas"] != 1000000
            || case["repeats"] != 1
            || case["ignore"] != false
            || !case["program"].is_null()
        {
            continue;
        }
        let args = case["operands"].as_array().unwrap();
        if [2, 3].iter().any(|i| args[*i].as_u64().is_none()) {
            continue;
        }
        if [0, 1]
            .iter()
            .any(|i| !args[*i].as_str().is_some_and(|s| s.starts_with("int:") || s == "nan"))
        {
            continue;
        }
        for version in [16, 17, 19] {
            for bounce in [false, true] {
                let name = format!("{}-v{version}-bounce{bounce}", case["name"].as_str().unwrap());
                let mut prefix = "DROP ".to_owned();
                let mut body = BuilderData::new();
                for i in [0, 1] {
                    let value = args[i].as_str().unwrap();
                    if value == "nan" {
                        prefix.push_str("PUSHNAN SWAP ");
                    } else {
                        let value =
                            value[4..].parse::<rtos_vm::stack::integer::IntegerData>().unwrap();
                        body.append_builder(&value.as_builder(257, true, true).unwrap()).unwrap();
                        prefix.push_str("PUSHINT 257 LDIX ");
                    }
                }
                prefix.push_str("LDREF LDREF ENDS LMSCHECKFEEHASH THROWIFNOT 99 PUSHROOT CTOS LDREF ENDS PUSHINT 0 SENDRAWMSG PUSHINT 77 NEWC STU 8 ENDC POPROOT");
                let code = rtos_assembler::compile_code_to_cell(&prefix).unwrap();
                let address = MsgAddressInt::with_standart(None, 0, [0x5a; 32].into()).unwrap();
                let cfg = config(version, false, &address);
                let outgoing = Message::with_int_header(InternalMessageHeader::with_addresses(
                    address.clone(),
                    MsgAddressInt::with_standart(None, 0, [0x33; 32].into()).unwrap(),
                    CurrencyCollection::with_coins(100_000_000u64),
                ));
                let mut stored = BuilderData::new();
                stored.checked_append_reference(outgoing.serialize().unwrap()).unwrap();
                let mut init = StateInit::default();
                init.set_code(code);
                init.set_data(stored.into_cell().unwrap());
                let account = Account::active(
                    address.clone(),
                    CurrencyCollection::with_coins(10_000_000_000u64),
                    0,
                    100,
                    init,
                    cfg.size_limits_config().acc_state_cells_for_storage_dict,
                )
                .unwrap();
                for i in [2, 3] {
                    body.checked_append_reference(
                        cells[args[i].as_u64().unwrap() as usize].clone(),
                    )
                    .unwrap();
                }
                let mut msg = message(address, bounce);
                msg.set_body(SliceData::load_builder(body).unwrap());
                let (tx, _) = run(&name, cfg, account, msg, false, &mut rows);
                let rtos_block::TransactionDescr::Ordinary(desc) = tx.read_description().unwrap()
                else {
                    panic!("ordinary");
                };
                let rtos_block::TrComputePhase::Vm(compute) = desc.compute_ph else {
                    panic!("compute");
                };
                let expected = if version < 17 {
                    6
                } else {
                    match case["expected"][0].as_i64().unwrap() {
                        0 => {
                            if case["expected"][2] == -1 {
                                0
                            } else {
                                99
                            }
                        }
                        n => n as i32,
                    }
                };
                assert_eq!(compute.exit_code, expected, "{name}");
                assert_eq!(desc.aborted, expected != 0, "{name}");
                if expected == 0 {
                    assert!(desc.action.unwrap().success);
                    assert_eq!(tx.msg_count(), 1);
                }
            }
        }
    }
    assert_eq!(rows.len(), 726);
    if let Some(path) = std::env::var_os("RTOS_LMS_FEE_EXPORT") {
        std::fs::write(path, rows.join("\n") + "\n").unwrap();
    }
}
