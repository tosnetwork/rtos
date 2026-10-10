// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use crate::{BlockchainConfig, ExecuteParams, OrdinaryTransactionExecutor, TransactionExecutor};
use rtos_block::{
    Account, BuilderData, Cell, ConfigParam31, ConfigParam8, ConfigParamEnum, CurrencyCollection,
    GetRepresentationHash, HashUpdate, IBitstring, InternalMessageHeader, Message, MsgAddressInt,
    OutAction, OutActions, Serializable, SliceData, StateInit,
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
            if std::env::var_os("RTOS_EXOTIC_ACTION_EXPORT").is_none() {
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
    if std::env::var_os("RTOS_EXOTIC_ACTION_EXPORT").is_none() {
        let expected = include_str!("data/exotic-actions.tsv")
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
fn exotic_action_complete_transactions() {
    let code =
        rtos_assembler::compile_code_to_cell("DROP LDREF LDREF ENDS POPROOT POPCTR c5").unwrap();
    let mut branch = BuilderData::new();
    branch.append_u8(77).unwrap();
    branch.checked_append_reference(Cell::default()).unwrap();
    let full = branch.into_cell().unwrap();
    let partial = rtos_block::MerkleProof::create(&full, |hash| hash == full.repr_hash()).unwrap();
    let pruned = partial.proof.reference(0).unwrap();
    assert!(pruned.level() > 0);
    let mut library = BuilderData::new();
    library.append_u8(2).unwrap();
    library.append_raw(Cell::default().repr_hash().as_slice(), 256).unwrap();
    library.set_type(rtos_block::CellType::LibraryReference);
    let forms = [
        ("ordinary", full.clone()),
        (
            "full-proof",
            rtos_block::MerkleProof::create(&full, |_| true).unwrap().serialize().unwrap(),
        ),
        ("partial-proof", partial.serialize().unwrap()),
        ("library-ref", library.into_cell().unwrap()),
        (
            "update",
            rtos_block::MerkleUpdate::create(&Cell::default(), &full).unwrap().serialize().unwrap(),
        ),
    ];
    let mut rows = Vec::new();
    for version in [14, 15, 19] {
        for special in [false, true] {
            for (shape, cell) in &forms {
                for action in ["code", "private", "public", "data"] {
                    for failure in [false, true] {
                        let name = format!(
                            "exotic-v{version}-special{special}-{shape}-{action}-fail{failure}"
                        );
                        let address = MsgAddressInt::with_standart(
                            None,
                            if special { -1 } else { 0 },
                            [0x5e; 32].into(),
                        )
                        .unwrap();
                        let cfg = config(version, special, &address);
                        let mut init = StateInit::default();
                        init.set_code(code.clone());
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
                        let mut actions = OutActions::new();
                        match action {
                            "code" => actions.push_back(OutAction::new_set(cell.clone())),
                            "private" => actions.push_back(OutAction::new_change_library(
                                3,
                                Some(cell.clone()),
                                None,
                            )),
                            "public" => actions.push_back(OutAction::new_change_library(
                                5,
                                Some(cell.clone()),
                                None,
                            )),
                            _ => (),
                        }
                        if failure {
                            actions.push_back(OutAction::new_reserve(
                                0,
                                CurrencyCollection::with_coins(1_000_000_000_000u64),
                            ));
                        }
                        let mut body = BuilderData::new();
                        body.checked_append_reference(actions.serialize().unwrap()).unwrap();
                        body.checked_append_reference(if action == "data" {
                            cell.clone()
                        } else {
                            Cell::default()
                        })
                        .unwrap();
                        let mut msg = message(address, true);
                        msg.set_body(SliceData::load_builder(body).unwrap());
                        run(&name, cfg, account, msg, special, &mut rows);
                    }
                }
            }
        }
    }
    generated_pruned_cases(&pruned, &mut rows);
    frozen_special_cases(&code, &mut rows);
    assert_eq!(rows.len(), 396);
    if let Some(path) = std::env::var_os("RTOS_EXOTIC_ACTION_EXPORT") {
        std::fs::write(path, rows.join("\n") + "\n").unwrap();
    }
}

fn generated_pruned_cases(pruned: &Cell, rows: &mut Vec<String>) {
    for version in [14, 15, 19] {
        for special in [false, true] {
            for target in ["SETCODE", "POPROOT", "PUSHINT 2 SETLIBCODE"] {
                for explicit in [false, true] {
                    let source = format!(
                        "DROP NEWC STSLICE PUSHINT 1 ENDXC {target} {}",
                        if explicit { "COMMIT" } else { "" }
                    );
                    let code = rtos_assembler::compile_code_to_cell(&source).unwrap();
                    let address = MsgAddressInt::with_standart(
                        None,
                        if special { -1 } else { 0 },
                        [0x5f; 32].into(),
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
                    let mut msg = message(address, true);
                    msg.set_body(
                        SliceData::load_cell(
                            BuilderData::with_raw(pruned.data().to_vec(), pruned.bit_length())
                                .unwrap()
                                .into_cell()
                                .unwrap(),
                        )
                        .unwrap(),
                    );
                    assert_eq!(msg.serialize().unwrap().level(), 0);
                    let name =
                        format!("generated-v{version}-special{special}-{target}-commit{explicit}");
                    let (tx, _) = run(&name, cfg, account, msg, special, rows);
                    let rtos_block::TransactionDescr::Ordinary(desc) =
                        tx.read_description().unwrap()
                    else {
                        panic!("ordinary")
                    };
                    let rtos_block::TrComputePhase::Vm(compute) = desc.compute_ph else {
                        panic!("compute")
                    };
                    assert!(!compute.success, "{name}");
                    assert_eq!(compute.exit_code, 8, "{name}");
                    assert!(desc.action.is_none(), "{name}");
                }
            }
        }
    }
}

fn frozen_special_cases(code: &Cell, rows: &mut Vec<String>) {
    for version in [11, 12, 14, 15, 19] {
        for public in [false, true] {
            for count in [0, 1, 2] {
                for cap in [0, 1] {
                    for cells in [1, 100] {
                        let name=format!("frozen-special-v{version}-public{public}-count{count}-cap{cap}-cells{cells}");
                        let address =
                            MsgAddressInt::with_standart(None, -1, [0x60; 32].into()).unwrap();
                        let base = config(version, true, &address);
                        let mut raw = base.raw_config().clone();
                        let mut limits = raw.size_limits_config().unwrap();
                        limits.max_acc_public_libraries = cap;
                        limits.max_acc_state_cells = cells;
                        limits.max_mc_acc_state_cells = cells;
                        raw.set_config(ConfigParamEnum::ConfigParam43(limits)).unwrap();
                        let cfg = BlockchainConfig::with_config(raw).unwrap();
                        let mut init = StateInit::default();
                        init.set_code(code.clone());
                        init.set_data(Cell::default());
                        for i in 0..count {
                            init.set_library_code(
                                BuilderData::with_raw(vec![i as u8], 8)
                                    .unwrap()
                                    .into_cell()
                                    .unwrap(),
                                public,
                            )
                            .unwrap();
                        }
                        let account = Account::frozen(
                            address.clone(),
                            CurrencyCollection::with_coins(10_000_000_000u64),
                            0,
                            0,
                            None,
                            init.hash().unwrap(),
                        );
                        let mut body = BuilderData::new();
                        body.checked_append_reference(OutActions::new().serialize().unwrap())
                            .unwrap();
                        body.checked_append_reference(Cell::default()).unwrap();
                        let mut msg = message(address, true);
                        msg.set_state_init(init);
                        msg.set_body(SliceData::load_builder(body).unwrap());
                        run(&name, cfg, account, msg, true, rows);
                    }
                }
            }
        }
    }
}
