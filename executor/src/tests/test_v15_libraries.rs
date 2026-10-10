// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use crate::{BlockchainConfig, ExecuteParams, OrdinaryTransactionExecutor, TransactionExecutor};
use rtos_block::{
    Account, AccountStatus, BuilderData, Cell, ConfigParam31, ConfigParam8, ConfigParamEnum,
    CurrencyCollection, GetRepresentationHash, HashUpdate, IBitstring, InternalMessageHeader,
    Message, MsgAddressInt, OutAction, OutActions, Serializable, SliceData, StateInit,
    TrComputePhase, TransactionDescr,
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
    let mut tx = OrdinaryTransactionExecutor::new(config)
        .execute_with_params(Some(msg.serialize().unwrap()), &mut account, params)
        .unwrap();
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
    if std::env::var_os("RTOS_V15_LIBRARY_EXPORT").is_none() {
        let expected = include_str!("data/v15-libraries.tsv")
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
fn v15_library_deploy_and_actions() {
    let mut rows = Vec::new();
    let code =
        rtos_assembler::compile_code_to_cell("ACCEPT PUSHINT 77 NEWC STU 8 ENDC POPROOT").unwrap();
    let library = rtos_assembler::compile_code_to_cell("PUSHINT 1").unwrap();
    for throws in [false, true] {
        let code = if throws {
            rtos_assembler::compile_code_to_cell("ACCEPT THROW 99").unwrap()
        } else {
            code.clone()
        };
        for version in [13, 14, 15, 16, 19] {
            for wc in [0, -1] {
                for state in ["new", "uninit", "frozen"] {
                    for lib in ["none", "private", "public"] {
                        for bounce in [false, true] {
                            let name = format!("deploy-v{version}-wc{wc}-{state}-{lib}-bounce{bounce}-throw{throws}");
                            let mut init = StateInit::default();
                            init.set_code(code.clone());
                            init.set_data(Cell::default());
                            if lib != "none" {
                                init.set_library_code(library.clone(), lib == "public").unwrap();
                            }
                            let address =
                                MsgAddressInt::with_standart(None, wc, init.hash().unwrap().into())
                                    .unwrap();
                            let cfg = config(version, false, &address);
                            let balance = CurrencyCollection::with_coins(10_000_000_000u64);
                            let account = match state {
                                "new" => Account::default(),
                                "uninit" => Account::uninit(address.clone(), balance, 0, 100),
                                _ => Account::frozen(
                                    address.clone(),
                                    balance,
                                    0,
                                    100,
                                    None,
                                    init.hash().unwrap(),
                                ),
                            };
                            let mut msg = message(address, bounce);
                            msg.set_state_init(init);
                            let (tx, account) = run(&name, cfg, account, msg, false, &mut rows);
                            let rejected = state != "frozen"
                                && lib != "none"
                                && (version >= 15 || wc == -1 && lib == "public");
                            let TransactionDescr::Ordinary(desc) = tx.read_description().unwrap()
                            else {
                                panic!("ordinary")
                            };
                            assert_eq!(desc.aborted, rejected || throws, "{name}");
                            if let TrComputePhase::Vm(ref phase) = desc.compute_ph {
                                assert!(phase.msg_state_used, "{name}");
                                assert_eq!(
                                    phase.account_activated,
                                    !throws || version < 14,
                                    "{name}"
                                );
                            }
                            assert_eq!(
                                account.status() == AccountStatus::AccStateActive,
                                !rejected && (!throws || version < 14),
                                "{name}"
                            );
                        }
                    }
                }
            }
        }
    }
    let code = rtos_assembler::compile_code_to_cell(
        "DROP LDREF ENDS POPCTR c5 PUSHINT 77 NEWC STU 8 ENDC POPROOT",
    )
    .unwrap();
    for later_failure in [false, true] {
        for version in [14, 15, 19] {
            for kind in ["base", "master", "special"] {
                for mode in [0u8, 1, 2, 3, 16, 17, 18, 19, 32] {
                    for by_hash in [false, true] {
                        for old in ["none", "private", "public"] {
                            let name =
                            format!("action-v{version}-{kind}-mode{mode}-hash{by_hash}-{old}-later{later_failure}");
                            let wc = if kind == "base" { 0 } else { -1 };
                            let special = kind == "special";
                            let address =
                                MsgAddressInt::with_standart(None, wc, [0x5a; 32].into()).unwrap();
                            let cfg = config(version, special, &address);
                            let mut init = StateInit::default();
                            init.set_code(code.clone());
                            init.set_data(Cell::default());
                            if old != "none" {
                                init.set_library_code(library.clone(), old == "public").unwrap();
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
                            let raw = (mode << 1) | u8::from(!by_hash);
                            let mut actions = OutActions::new();
                            actions.push_back(OutAction::new_change_library(
                                raw,
                                if by_hash { None } else { Some(library.clone()) },
                                if by_hash { Some(library.repr_hash().clone()) } else { None },
                            ));
                            if later_failure {
                                actions.push_back(OutAction::new_reserve(
                                    0,
                                    CurrencyCollection::with_coins(1_000_000_000_000u64),
                                ));
                            }
                            let mut body = BuilderData::new();
                            body.checked_append_reference(actions.serialize().unwrap()).unwrap();
                            let mut msg = message(address, true);
                            msg.set_body(SliceData::load_builder(body).unwrap());
                            let (tx, account) = run(&name, cfg, account, msg, special, &mut rows);
                            let TransactionDescr::Ordinary(desc) = tx.read_description().unwrap()
                            else {
                                panic!("ordinary")
                            };
                            let TrComputePhase::Vm(compute) = desc.compute_ph else { panic!("VM") };
                            assert!(compute.success, "{name}");
                            let base_mode = mode & !16;
                            let expected = if base_mode > 2 {
                                34
                            } else if version >= 15 && (base_mode == 1 || !special) {
                                46
                            } else if base_mode != 0 && by_hash && old == "none" {
                                41
                            } else {
                                0
                            };
                            let expected =
                                if expected == 0 && later_failure { 37 } else { expected };
                            assert_eq!(desc.action.unwrap().result_code, expected, "{name}");
                            if expected == 37 {
                                assert_eq!(
                                    tx.account_updates(),
                                    account.storage_roots().as_slice(),
                                    "{name}: persisted library proof roots"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    for version in [14, 15, 19] {
        for mode in [2u8, 3, 32, 33] {
            for suffix in ["missing", "bits", "refs"] {
                let name = format!("malformed-v{version}-raw{mode}-{suffix}");
                let address = MsgAddressInt::with_standart(None, 0, [0x5a; 32].into()).unwrap();
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
                let mut action = BuilderData::new();
                action.checked_append_reference(Cell::default()).unwrap();
                action.append_u32(rtos_block::ACTION_CHANGE_LIB).unwrap();
                action.append_u8(mode).unwrap();
                if suffix != "missing" {
                    if mode & 1 == 0 {
                        action.append_raw(library.repr_hash().as_slice(), 256).unwrap();
                    } else {
                        action.checked_append_reference(library.clone()).unwrap();
                    }
                    if suffix == "bits" {
                        action.append_bit_one().unwrap();
                    } else {
                        action.checked_append_reference(Cell::default()).unwrap();
                    }
                }
                let mut body = BuilderData::new();
                body.checked_append_reference(action.into_cell().unwrap()).unwrap();
                let mut msg = message(address, true);
                msg.set_body(SliceData::load_builder(body).unwrap());
                let (tx, _) = run(&name, cfg, account, msg, false, &mut rows);
                let TransactionDescr::Ordinary(desc) = tx.read_description().unwrap() else {
                    panic!("ordinary")
                };
                let action = desc.action.unwrap();
                assert_eq!(action.result_code, 34, "{name}");
                assert_eq!(action.skipped_actions, 0, "{name}");
                assert!(desc.bounce.is_none(), "{name}");
            }
        }
    }
    for version in [14, 15, 19] {
        for state in ["new", "uninit"] {
            for prefix in [8, 9] {
                for bad_suffix in [false, true] {
                    for throws in [false, true] {
                        let name = format!(
                            "prefix-v{version}-{state}-bits{prefix}-bad{bad_suffix}-throw{throws}"
                        );
                        let code = rtos_assembler::compile_code_to_cell(if throws {
                            "ACCEPT THROW 99"
                        } else {
                            "ACCEPT"
                        })
                        .unwrap();
                        let mut init = StateInit::default();
                        init.set_code(code);
                        init.set_data(Cell::default());
                        init.set_fixed_prefix_length(prefix.try_into().unwrap());
                        let mut bytes: [u8; 32] = *init.hash().unwrap().as_slice();
                        bytes[0] ^= 255;
                        if bad_suffix {
                            bytes[31] ^= 1;
                        }
                        let address = MsgAddressInt::with_standart(None, 0, bytes.into()).unwrap();
                        let cfg = config(version, false, &address);
                        assert_eq!(cfg.size_limits_config().max_acc_fixed_prefix_length, 8);
                        let account = if state == "new" {
                            Account::default()
                        } else {
                            Account::uninit(
                                address.clone(),
                                CurrencyCollection::with_coins(10_000_000_000u64),
                                0,
                                100,
                            )
                        };
                        let mut msg = message(address, false);
                        msg.set_state_init(init);
                        let (tx, account) = run(&name, cfg, account, msg, false, &mut rows);
                        let TransactionDescr::Ordinary(desc) = tx.read_description().unwrap()
                        else {
                            panic!("ordinary")
                        };
                        let rejected = prefix > 8 || bad_suffix;
                        assert_eq!(desc.aborted, rejected || throws, "{name}");
                        assert_eq!(account.is_active(), !rejected && !throws, "{name}");
                    }
                }
            }
        }
    }
    if let Some(path) = std::env::var_os("RTOS_V15_LIBRARY_EXPORT") {
        std::fs::write(path, rows.join("\n") + "\n").unwrap();
    } else {
        assert_eq!(include_str!("data/v15-libraries.tsv").lines().count(), rows.len());
    }
}
