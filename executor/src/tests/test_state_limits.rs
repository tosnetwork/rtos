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
            if std::env::var_os("RTOS_STATE_LIMIT_EXPORT").is_none() {
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
    if std::env::var_os("RTOS_STATE_LIMIT_EXPORT").is_none() {
        let expected = include_str!("data/state-limits.tsv")
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
fn state_limit_complete_transactions() {
    let mut rows = Vec::new();
    let code =
        rtos_assembler::compile_code_to_cell("DROP LDREF LDREF ENDS POPROOT POPCTR c5").unwrap();
    let mut big = Cell::default();
    for i in 0..5 {
        let mut b = BuilderData::new();
        b.append_u8(i).unwrap();
        b.checked_append_reference(big).unwrap();
        big = b.into_cell().unwrap();
    }
    for version in [11, 12, 13, 14, 15, 19] {
        for kind in ["base", "master", "master-low", "special"] {
            for change in [
                "none",
                "data",
                "code",
                "library",
                "library-public",
                "unchanged-public",
                "data-with-public",
            ] {
                for failure in [false, true] {
                    for send_label in ["false", "true", "delete"] {
                        let send = send_label != "false";
                        if send_label == "delete"
                            && (!matches!(version, 14 | 15)
                                || kind != "base"
                                || !matches!(change, "data" | "code"))
                        {
                            continue;
                        }
                        for limit in [1u32, 2, 7, 100] {
                            let name = format!("state-v{version}-{kind}-{change}-fail{failure}-send{send_label}-limit{limit}");
                            let special = kind == "special";
                            let address = MsgAddressInt::with_standart(
                                None,
                                if kind == "base" { 0 } else { -1 },
                                [0x5a; 32].into(),
                            )
                            .unwrap();
                            let base = config(version, special, &address);
                            let mut raw = base.raw_config().clone();
                            let mut limits = raw.size_limits_config().unwrap();
                            limits.max_acc_state_cells = limit;
                            limits.max_mc_acc_state_cells = 100;
                            if kind == "master-low" {
                                limits.max_acc_state_cells = 100;
                                limits.max_mc_acc_state_cells = limit;
                            }
                            if change.contains("public") {
                                limits.max_acc_public_libraries = 0;
                            }
                            raw.set_config(ConfigParamEnum::ConfigParam43(limits)).unwrap();
                            let cfg = BlockchainConfig::with_config(raw).unwrap();
                            let mut init = StateInit::default();
                            init.set_code(code.clone());
                            init.set_data(Cell::default());
                            if change == "unchanged-public" || change == "data-with-public" {
                                init.set_library_code(big.clone(), true).unwrap();
                            }
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
                            if send {
                                let dst = MsgAddressInt::with_standart(None, 0, [0x33; 32].into())
                                    .unwrap();
                                let mut out = Message::with_int_header(
                                    InternalMessageHeader::with_addresses(
                                        address.clone(),
                                        dst,
                                        CurrencyCollection::with_coins(100_000_000u64),
                                    ),
                                );
                                let mut body = BuilderData::new();
                                body.checked_append_reference(big.clone()).unwrap();
                                out.set_body(SliceData::load_builder(body).unwrap());
                                actions.push_back(OutAction::new_send(
                                    if send_label == "delete" { 160 } else { 0 },
                                    out,
                                ));
                            }
                            if change == "code" {
                                actions.push_back(OutAction::new_set(big.clone()));
                            }
                            if change.starts_with("library") {
                                actions.push_back(OutAction::new_change_library(
                                    if change == "library-public" { 5 } else { 3 },
                                    Some(big.clone()),
                                    None,
                                ));
                            }
                            if failure {
                                actions.push_back(OutAction::new_reserve(
                                    0,
                                    CurrencyCollection::with_coins(1_000_000_000_000u64),
                                ));
                            }
                            let mut body = BuilderData::new();
                            body.checked_append_reference(actions.serialize().unwrap()).unwrap();
                            body.checked_append_reference(if change.starts_with("data") {
                                big.clone()
                            } else {
                                Cell::default()
                            })
                            .unwrap();
                            let mut msg = message(address, true);
                            msg.set_body(SliceData::load_builder(body).unwrap());
                            let mut inspected_state = account.clone();
                            if !failure {
                                if change.starts_with("data") {
                                    inspected_state.set_data(big.clone());
                                }
                                if change == "code" {
                                    inspected_state.set_code(big.clone());
                                }
                            }
                            if change.starts_with("library")
                                && (version < 15 || (special && change == "library-public"))
                            {
                                let mut libraries = StateInit::default();
                                libraries
                                    .set_library_code(big.clone(), change == "library-public")
                                    .unwrap();
                                *inspected_state.library_mut().unwrap() =
                                    libraries.libraries().clone();
                            }
                            let old_roots = account.storage_roots();
                            let (tx, final_account) =
                                run(&name, cfg, account, msg, special, &mut rows);
                            if let Ok(rtos_block::TransactionDescr::Ordinary(desc)) =
                                tx.read_description()
                            {
                                if let Some(action) = desc.action {
                                    assert_eq!(
                                        tx.account_updates(),
                                        inspected_state.storage_roots().as_slice(),
                                        "{name}: roots inspected by state-size validation"
                                    );
                                    if action.result_code == 50 {
                                        assert_eq!(
                                            final_account.storage_roots(),
                                            old_roots,
                                            "{name}: state rollback"
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    frozen_library_cases(&code, &mut rows);
    merkle_cases(&code, &mut rows);
    public_library_cases(&code, &mut rows);
    if let Some(path) = std::env::var_os("RTOS_STATE_LIMIT_EXPORT") {
        std::fs::write(path, rows.join("\n") + "\n").unwrap();
    }
}

fn merkle_cases(code: &Cell, rows: &mut Vec<String>) {
    for version in [14, 15, 19] {
        for depth in [1, 2, 3] {
            let mut tree = Cell::default();
            for _ in 0..depth {
                tree =
                    rtos_block::MerkleProof::create(&tree, |_| true).unwrap().serialize().unwrap();
            }
            for change_code in [false, true] {
                for failure in [false, true] {
                    let name =
                        format!("merkle-v{version}-depth{depth}-code{change_code}-fail{failure}");
                    let address = MsgAddressInt::with_standart(None, 0, [0x5b; 32].into()).unwrap();
                    let cfg = config(version, false, &address);
                    let mut init = StateInit::default();
                    init.set_code(code.clone());
                    init.set_data(Cell::default());
                    let account = Account::active(
                        address.clone(),
                        CurrencyCollection::with_coins(10_000_000_000u64),
                        0,
                        100,
                        init,
                        cfg.size_limits_config().acc_state_cells_for_storage_dict,
                    )
                    .unwrap();
                    let old_roots = account.storage_roots();
                    let mut candidate = account.clone();
                    let mut actions = OutActions::new();
                    if change_code {
                        actions.push_back(OutAction::new_set(tree.clone()));
                        if !failure {
                            candidate.set_code(tree.clone());
                        }
                    } else if !failure {
                        candidate.set_data(tree.clone());
                    }
                    if failure {
                        actions.push_back(OutAction::new_reserve(
                            0,
                            CurrencyCollection::with_coins(1_000_000_000_000u64),
                        ));
                    }
                    let mut body = BuilderData::new();
                    body.checked_append_reference(actions.serialize().unwrap()).unwrap();
                    body.checked_append_reference(if change_code {
                        Cell::default()
                    } else {
                        tree.clone()
                    })
                    .unwrap();
                    let mut msg = message(address, true);
                    msg.set_body(SliceData::load_builder(body).unwrap());
                    let (tx, final_account) = run(&name, cfg, account, msg, false, rows);
                    if let Ok(rtos_block::TransactionDescr::Ordinary(desc)) = tx.read_description()
                    {
                        if let Some(action) = desc.action {
                            assert_eq!(
                                tx.account_updates(),
                                candidate.storage_roots().as_slice(),
                                "{name}: inspected roots"
                            );
                            if action.result_code == 50 {
                                assert_eq!(
                                    final_account.storage_roots(),
                                    old_roots,
                                    "{name}: rollback"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

fn public_library_cases(code: &Cell, rows: &mut Vec<String>) {
    for (version, special) in [(14, false), (15, true)] {
        for cap in [0, 1, 2] {
            for count in [1, 2] {
                for failure in [false, true] {
                    let name = format!(
                        "public-v{version}-special{special}-cap{cap}-count{count}-fail{failure}"
                    );
                    let address =
                        MsgAddressInt::with_standart(None, -1, [0x5b; 32].into()).unwrap();
                    let base = config(version, special, &address);
                    let mut raw = base.raw_config().clone();
                    let mut limits = raw.size_limits_config().unwrap();
                    limits.max_acc_public_libraries = cap;
                    raw.set_config(ConfigParamEnum::ConfigParam43(limits)).unwrap();
                    let cfg = BlockchainConfig::with_config(raw).unwrap();
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
                    let old_roots = account.storage_roots();
                    let mut candidate = account.clone();
                    let mut libraries = StateInit::default();
                    let mut actions = OutActions::new();
                    for i in 0..count {
                        let cell =
                            BuilderData::with_raw(vec![i as u8], 8).unwrap().into_cell().unwrap();
                        libraries.set_library_code(cell.clone(), true).unwrap();
                        actions.push_back(OutAction::new_change_library(5, Some(cell), None));
                    }
                    *candidate.library_mut().unwrap() = libraries.libraries().clone();
                    if failure {
                        actions.push_back(OutAction::new_reserve(
                            0,
                            CurrencyCollection::with_coins(1_000_000_000_000u64),
                        ));
                    }
                    let mut body = BuilderData::new();
                    body.checked_append_reference(actions.serialize().unwrap()).unwrap();
                    body.checked_append_reference(Cell::default()).unwrap();
                    let mut msg = message(address, true);
                    msg.set_body(SliceData::load_builder(body).unwrap());
                    let (tx, final_account) = run(&name, cfg, account, msg, special, rows);
                    if let Ok(rtos_block::TransactionDescr::Ordinary(desc)) = tx.read_description()
                    {
                        if let Some(action) = desc.action {
                            assert_eq!(
                                tx.account_updates(),
                                candidate.storage_roots().as_slice(),
                                "{name}: inspected roots"
                            );
                            if action.result_code == 50 {
                                assert_eq!(
                                    final_account.storage_roots(),
                                    old_roots,
                                    "{name}: rollback"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

fn frozen_library_cases(code: &Cell, rows: &mut Vec<String>) {
    for version in [14, 15, 19] {
        for public in [false, true] {
            for cap in [0, 1, 2] {
                let name = format!("frozen-v{version}-public{public}-cap{cap}");
                let address = MsgAddressInt::with_standart(None, -1, [0x5c; 32].into()).unwrap();
                let base = config(version, false, &address);
                let mut raw = base.raw_config().clone();
                let mut limits = raw.size_limits_config().unwrap();
                limits.max_acc_public_libraries = cap;
                raw.set_config(ConfigParamEnum::ConfigParam43(limits)).unwrap();
                let cfg = BlockchainConfig::with_config(raw).unwrap();
                let mut init = StateInit::default();
                init.set_code(code.clone());
                init.set_data(Cell::default());
                init.set_library_code(Cell::default(), public).unwrap();
                let account = Account::frozen(
                    address.clone(),
                    CurrencyCollection::with_coins(10_000_000_000u64),
                    0,
                    100,
                    None,
                    init.hash().unwrap(),
                );
                let mut body = BuilderData::new();
                body.checked_append_reference(OutActions::new().serialize().unwrap()).unwrap();
                body.checked_append_reference(Cell::default()).unwrap();
                let mut msg = message(address, true);
                msg.set_state_init(init);
                msg.set_body(SliceData::load_builder(body).unwrap());
                run(&name, cfg, account, msg, false, rows);
            }
        }
    }
}
