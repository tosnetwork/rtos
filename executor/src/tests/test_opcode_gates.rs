// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use crate::{BlockchainConfig, ExecuteParams, OrdinaryTransactionExecutor, TransactionExecutor};
use rtos_block::{
    Account, Cell, ConfigParam31, ConfigParam8, ConfigParamEnum, CurrencyCollection,
    GetRepresentationHash, HashUpdate, InternalMessageHeader, Message, MsgAddressInt, Serializable,
    SliceData, StateInit,
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
            if std::env::var_os("RTOS_OPCODE_GATE_EXPORT").is_none() {
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
    if std::env::var_os("RTOS_OPCODE_GATE_EXPORT").is_none() {
        let expected = include_str!("data/opcode-gates.tsv")
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
fn opcode_activation_complete_transactions() {
    let mut rows = Vec::new();
    for version in [0, 3, 4, 5, 13, 14, 15, 16, 18, 19] {
        for opcode in ["sha", "mldsa"] {
            for special in [false, true] {
                for bounce in [false, true] {
                    let name = format!("gate-v{version}-{opcode}-special{special}-bounce{bounce}");
                    let source = if opcode == "sha" {
                        "DROP NEWC STSLICE ENDC SHA256C NEWC STU 256 ENDC POPROOT"
                    } else {
                        "DROP LDREF LDREF LDREF LDREF ENDS PQCHECKSIG_MLDSA44 THROWIFNOT 99 PUSHINT 77 NEWC STU 8 ENDC POPROOT"
                    };
                    let code = rtos_assembler::compile_code_to_cell(source).unwrap();
                    let address = MsgAddressInt::with_standart(
                        None,
                        if special { -1 } else { 0 },
                        [0x61; 32].into(),
                    )
                    .unwrap();
                    let cfg = config(version, special, &address);
                    let mut init = StateInit::default();
                    init.set_code(code);
                    init.set_data(Cell::default());
                    let account = Account::active(
                        address.clone(),
                        CurrencyCollection::with_coins(10_000_000_000u64),
                        0,
                        if special { 0 } else { 100 },
                        init,
                        cfg.size_limits_config().acc_state_cells_for_storage_dict,
                    )
                    .unwrap();
                    let mut msg = message(address, bounce);
                    if opcode == "mldsa" {
                        msg.set_body(
                            SliceData::load_cell(
                                rtos_block::read_single_root_boc(include_bytes!(
                                    "data/pq-valid-body.boc"
                                ))
                                .unwrap(),
                            )
                            .unwrap(),
                        );
                    }
                    let (tx, _) = run(&name, cfg, account, msg, special, &mut rows);
                    let rtos_block::TransactionDescr::Ordinary(desc) =
                        tx.read_description().unwrap()
                    else {
                        panic!("ordinary")
                    };
                    let rtos_block::TrComputePhase::Vm(compute) = desc.compute_ph else {
                        panic!("compute")
                    };
                    let active = version >= if opcode == "sha" { 14 } else { 16 };
                    assert_eq!(compute.success, active, "{name}");
                    assert_eq!(compute.exit_code, if active { 0 } else { 6 }, "{name}");
                }
            }
        }
    }
    special_gas_cases(&mut rows);
    assert_eq!(rows.len(), 120);
    if let Some(path) = std::env::var_os("RTOS_OPCODE_GATE_EXPORT") {
        std::fs::write(path, rows.join("\n") + "\n").unwrap();
    }
}

fn special_gas_cases(rows: &mut Vec<String>) {
    for version in [4, 5] {
        for accept in [false, true] {
            for amount in [0u64, 1, 1000, 1_000_000, 1_000_000_000] {
                for bounce in [false, true] {
                    let name = format!(
                        "special-gas-v{version}-accept{accept}-amount{amount}-bounce{bounce}"
                    );
                    let address =
                        MsgAddressInt::with_standart(None, -1, [0x62; 32].into()).unwrap();
                    let cfg = config(version, true, &address);
                    let code = rtos_assembler::compile_code_to_cell(if accept {
                        "ACCEPT NOP"
                    } else {
                        "NOP"
                    })
                    .unwrap();
                    let mut init = StateInit::default();
                    init.set_code(code);
                    init.set_data(Cell::default());
                    let account = Account::active(
                        address.clone(),
                        CurrencyCollection::with_coins(10_000_000_000u64),
                        0,
                        0,
                        init,
                        cfg.size_limits_config().acc_state_cells_for_storage_dict,
                    )
                    .unwrap();
                    let mut msg = message(address, bounce);
                    msg.int_header_mut().unwrap().value = CurrencyCollection::with_coins(amount);
                    run(&name, cfg, account, msg, true, rows);
                }
            }
        }
    }
}
