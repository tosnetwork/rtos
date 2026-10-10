// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use crate::{BlockchainConfig, ExecuteParams, OrdinaryTransactionExecutor, TransactionExecutor};
use rtos_block::{
    Account, AccountStatus, AnycastInfo, BuilderData, Cell, ComputeSkipReason, ConfigParam31,
    ConfigParam8, ConfigParamEnum, CurrencyCollection, ExternalInboundMessageHeader,
    GetRepresentationHash, HashUpdate, InternalMessageHeader, Message, MsgAddressInt, Serializable,
    SliceData, StateInit, TrComputePhase, TransactionDescr,
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
    account: Account,
    msg: Message,
    special: bool,
    rows: &mut Vec<String>,
) -> (Option<rtos_block::Transaction>, Account) {
    run_at(name, config, account, msg, special, rows, 200)
}
fn run_at(
    name: &str,
    config: BlockchainConfig,
    mut account: Account,
    msg: Message,
    special: bool,
    rows: &mut Vec<String>,
    now: u32,
) -> (Option<rtos_block::Transaction>, Account) {
    let address = msg.dst().unwrap();
    let input = format!(
        "{name}\t{now}\t{}\t{}\t{}\t{}\t-\t{}\t{}\t{}",
        2_000_000_001u64 + u64::from(now - 200) * 1000,
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
        block_unixtime: now,
        block_lt: 2_000_000_000,
        last_tr_lt: 2_000_000_001u64 + u64::from(now - 200) * 1000,
        ..Default::default()
    };
    let result = if name.starts_with("tick-address-") {
        crate::TickTockTransactionExecutor::new(
            config,
            if name.contains("-tock-") {
                rtos_block::TransactionTickTock::Tock
            } else {
                rtos_block::TransactionTickTock::Tick
            },
        )
        .execute_with_params(None, &mut account, params)
    } else {
        OrdinaryTransactionExecutor::new(config).execute_with_params(
            Some(msg.serialize().unwrap()),
            &mut account,
            params,
        )
    };
    let mut tx = match result {
        Ok(tx) => tx,
        Err(err) => {
            assert!(
                matches!(
                    err.downcast_ref::<crate::ExecutorError>(),
                    Some(
                        crate::ExecutorError::ExtMsgComputeSkipped(_)
                            | crate::ExecutorError::NoAcceptError(_, _)
                    )
                ),
                "{name}: unexpected error {err}"
            );
            if std::env::var_os("RTOS_FROZEN_PREFIX_EXPORT").is_none() {
                let expected = include_str!("data/frozen-prefix.tsv")
                    .lines()
                    .find(|l| l.split('\t').next() == Some(name))
                    .expect("frozen external rejection");
                assert_eq!(expected, format!("{name}\tERROR\tERROR"));
            }
            rows.push(format!("{input}\tERROR\tERROR"));
            return (None, account);
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
    if std::env::var_os("RTOS_FROZEN_PREFIX_EXPORT").is_none() {
        let expected = include_str!("data/frozen-prefix.tsv")
            .lines()
            .map(|l| l.split('\t').collect::<Vec<_>>())
            .find(|f| f[0] == name)
            .expect("frozen transaction");
        assert_eq!(th, expected[1], "{name} transaction");
        assert_eq!(ah, expected[2], "{name} account");
    }
    rows.push(format!("{input}\t{th}\t{ah}"));
    (Some(tx), account)
}
fn hex_bytes(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn frozen_prefix_complete_transactions() {
    let mut rows = Vec::new();
    for version in [14, 15, 16, 17, 19] {
        for prefix in [None, Some(0u32), Some(1), Some(8), Some(30), Some(31)] {
            for special in [false, true] {
                for mode in ["ok", "throw-before", "throw-after"] {
                    let code = rtos_assembler::compile_code_to_cell(match mode {
                        "ok" => "ACCEPT PUSHINT 77 NEWC STU 8 ENDC POPROOT",
                        "throw-before" => "THROW 77",
                        _ => "ACCEPT THROW 77",
                    })
                    .unwrap();
                    let mut init = StateInit::default();
                    init.set_code(code);
                    init.set_data(Cell::default());
                    if let Some(prefix) = prefix {
                        init.set_fixed_prefix_length(prefix.try_into().unwrap());
                    }
                    let hash = init.hash().unwrap();
                    let mut addr_bytes = *hash.as_array();
                    // The nonzero-prefix address preserves all non-rewritable bits.
                    // Zero-prefix models use a former deployment StateInit with
                    // different data, as ordinary contract execution can produce.
                    if prefix.unwrap_or(0) > 0 {
                        addr_bytes[0] ^= 0x80;
                    } else {
                        let mut deployed = init.clone();
                        deployed.set_data(
                            BuilderData::with_raw(vec![1], 8).unwrap().into_cell().unwrap(),
                        );
                        addr_bytes = *deployed.hash().unwrap().as_array();
                    }
                    let address = MsgAddressInt::with_standart(
                        None,
                        if special { -1 } else { 0 },
                        addr_bytes.into(),
                    )
                    .unwrap();
                    for transport in ["internal", "bounce", "external"] {
                        for inbound in ["match", "wrong-hash", "none"] {
                            let name=format!("matrix-v{version}-p{prefix:?}-special{special}-{mode}-{transport}-{inbound}");
                            let cfg = config(version, special, &address);
                            let account = Account::frozen(
                                address.clone(),
                                CurrencyCollection::with_coins(10_000_000_000u64),
                                0,
                                if special { 0 } else { 100 },
                                None,
                                hash.clone(),
                            );
                            let mut msg = if transport == "external" {
                                Message::with_ext_in_header(ExternalInboundMessageHeader {
                                    dst: address.clone(),
                                    ..Default::default()
                                })
                            } else {
                                message(address.clone(), transport == "bounce")
                            };
                            if inbound != "none" {
                                let mut state = init.clone();
                                if inbound == "wrong-hash" {
                                    state.set_data(
                                        BuilderData::with_raw(vec![3], 8)
                                            .unwrap()
                                            .into_cell()
                                            .unwrap(),
                                    );
                                }
                                msg.set_state_init(state);
                            }
                            let (tx, account) = run(&name, cfg, account, msg, special, &mut rows);
                            let prefix_rejected = version < 16 && prefix.unwrap_or(0) != 0;
                            if let Some(tx) = tx {
                                let TransactionDescr::Ordinary(desc) =
                                    tx.read_description().unwrap()
                                else {
                                    panic!("ordinary")
                                };
                                if inbound != "match" || prefix_rejected {
                                    let TrComputePhase::Skipped(skip) = desc.compute_ph else {
                                        panic!("{name}: expected compute skip")
                                    };
                                    assert_eq!(
                                        skip.reason,
                                        if inbound == "none" {
                                            ComputeSkipReason::NoState
                                        } else {
                                            ComputeSkipReason::BadState
                                        },
                                        "{name}"
                                    );
                                    assert_eq!(
                                        account.status(),
                                        AccountStatus::AccStateFrozen,
                                        "{name}"
                                    );
                                } else {
                                    let TrComputePhase::Vm(vm) = desc.compute_ph else {
                                        panic!("{name}: expected VM")
                                    };
                                    assert_eq!(
                                        vm.exit_code,
                                        if mode == "ok" { 0 } else { 77 },
                                        "{name}"
                                    );
                                }
                            } else {
                                assert_eq!(transport, "external", "{name}");
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(rows.len(), 1620);
    saved_rewrite_cases(&mut rows);
    external_admission_cases(&mut rows);
    reachable_histories(&mut rows);
    assert_eq!(rows.len(), 1911);
    address_commit_boundaries(&mut rows);
    tick_address_boundaries(&mut rows);
    legacy_myaddr_cases(&mut rows);
    assert_eq!(rows.len(), 1995);
    if let Some(path) = std::env::var_os("RTOS_FROZEN_PREFIX_EXPORT") {
        std::fs::write(path, rows.join("\n") + "\n").unwrap();
    }
}

// Stored pre-v10 anycast addresses remain meaningful during unpack, even when
// current inbound destinations must be ordinary standard addresses.
fn saved_rewrite_cases(rows: &mut Vec<String>) {
    for version in [9, 10, 14, 15, 16, 17, 19] {
        for prefix in [0u32, 1, 8, 30, 31] {
            let mut init = StateInit::default();
            init.set_fixed_prefix_length(prefix.try_into().unwrap());
            init.set_code(rtos_assembler::compile_code_to_cell("ACCEPT").unwrap());
            init.set_data(Cell::default());
            let mut original = init.clone();
            original.set_data(BuilderData::with_raw(vec![1], 8).unwrap().into_cell().unwrap());
            let original_hash = original.hash().unwrap();
            let mut bytes = *original_hash.as_array();
            bytes[0] ^= 0x80;
            let destination = MsgAddressInt::with_standart(None, 0, bytes.into()).unwrap();
            let rewrite =
                AnycastInfo::with_rewrite_pfx(SliceData::from_raw(vec![bytes[0]], 1)).unwrap();
            let stored =
                MsgAddressInt::with_standart(Some(rewrite), 0, original_hash.into()).unwrap();
            for external in [false, true] {
                let name = format!("saved-rewrite1-v{version}-p{prefix}-ext{external}");
                let account = Account::frozen(
                    stored.clone(),
                    CurrencyCollection::with_coins(10_000_000_000u64),
                    0,
                    100,
                    None,
                    init.hash().unwrap(),
                );
                let mut msg = if external {
                    Message::with_ext_in_header(ExternalInboundMessageHeader {
                        dst: destination.clone(),
                        ..Default::default()
                    })
                } else {
                    message(destination.clone(), true)
                };
                msg.set_state_init(init.clone());
                run(&name, config(version, false, &destination), account, msg, false, rows);
            }
        }
    }
}

fn external_admission_cases(rows: &mut Vec<String>) {
    for version in [7, 8, 14, 15, 16, 17, 19] {
        for status in ["active", "uninit", "frozen"] {
            for mismatch in [false, true] {
                for mode in ["ok", "throw-before", "throw-after"] {
                    let code = rtos_assembler::compile_code_to_cell(match mode {
                        "ok" => "ACCEPT",
                        "throw-before" => "THROW 77",
                        _ => "ACCEPT THROW 77",
                    })
                    .unwrap();
                    let mut init = StateInit::default();
                    init.set_code(code);
                    init.set_data(Cell::default());
                    let mut bytes = *init.hash().unwrap().as_array();
                    if mismatch {
                        bytes[0] ^= 0x80;
                    }
                    let address = MsgAddressInt::with_standart(None, 0, bytes.into()).unwrap();
                    let cfg = config(version, false, &address);
                    let balance = CurrencyCollection::with_coins(10_000_000_000u64);
                    let account = match status {
                        "active" => Account::active(
                            address.clone(),
                            balance,
                            0,
                            100,
                            init.clone(),
                            cfg.size_limits_config().acc_state_cells_for_storage_dict,
                        )
                        .unwrap(),
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
                    let mut msg = Message::with_ext_in_header(ExternalInboundMessageHeader {
                        dst: address.clone(),
                        ..Default::default()
                    });
                    msg.set_state_init(init);
                    run(
                        &format!("external-rule-v{version}-{status}-mismatch{mismatch}-{mode}"),
                        cfg,
                        account,
                        msg,
                        false,
                        rows,
                    );
                }
            }
        }
    }
}

fn history_config(version: u32, special: bool, address: &MsgAddressInt) -> BlockchainConfig {
    let cfg = config(version, special, address);
    let mut raw = cfg.raw_config().clone();
    let mut limits = cfg.size_limits_config().clone();
    limits.max_acc_fixed_prefix_length = 30;
    raw.set_config(ConfigParamEnum::ConfigParam43(limits)).unwrap();
    let mut prices = rtos_block::ConfigParam18::default();
    prices
        .map
        .set(
            &0,
            &rtos_block::StoragePrices {
                utime_since: 0,
                bit_price_ps: 65536,
                cell_price_ps: 65536,
                mc_bit_price_ps: 65536,
                mc_cell_price_ps: 65536,
            },
        )
        .unwrap();
    raw.set_config(ConfigParamEnum::ConfigParam18(prices)).unwrap();
    for mc in [false, true] {
        let mut gas = cfg.get_gas_config(mc).clone();
        gas.freeze_due_limit = 1;
        gas.delete_due_limit = 1_000_000_000;
        raw.set_config(if mc {
            ConfigParamEnum::ConfigParam20(gas)
        } else {
            ConfigParamEnum::ConfigParam21(gas)
        })
        .unwrap();
    }
    BlockchainConfig::with_config(raw).unwrap()
}

// Every next account is the actual previous transaction result. Matching the
// complete roots at each hop proves the same deployment/storage-freeze history
// in the fixed C++ emulator. Special accounts are promoted only after freezing:
// an already-special account is storage-fee exempt and cannot freeze this way.
fn reachable_histories(rows: &mut Vec<String>) {
    for prefix in [None, Some(0u32), Some(1), Some(8), Some(30)] {
        for mc in [false, true] {
            let code=rtos_assembler::compile_code_to_cell("ACCEPT DROP LDU 8 DROP PUSHCONT { PUSHROOT CTOS LDREF ENDS PUSHINT 128 SENDRAWMSG } IF PUSHINT 77 NEWC STU 8 ENDC POPROOT").unwrap();
            let outgoing = Message::with_int_header(InternalMessageHeader::with_addresses(
                MsgAddressInt::with_standart(None, if mc { -1 } else { 0 }, [0; 32].into())
                    .unwrap(),
                MsgAddressInt::with_standart(None, 0, [0x44; 32].into()).unwrap(),
                CurrencyCollection::default(),
            ));
            // Source is rewritten to the account by mode 128; use addr_none in the
            // relaxed outgoing message to avoid circular address/hash dependence.
            let mut outgoing = outgoing;
            outgoing.int_header_mut().unwrap().src = rtos_block::MsgAddressIntOrNone::None;
            let mut data = BuilderData::new();
            data.checked_append_reference(outgoing.serialize().unwrap()).unwrap();
            let mut init = StateInit::default();
            init.set_code(code);
            init.set_data(data.into_cell().unwrap());
            if let Some(p) = prefix {
                init.set_fixed_prefix_length(p.try_into().unwrap());
            }
            let mut bytes = *init.hash().unwrap().as_array();
            if prefix.unwrap_or(0) > 0 {
                bytes[0] ^= 0x80;
            }
            let address =
                MsgAddressInt::with_standart(None, if mc { -1 } else { 0 }, bytes.into()).unwrap();
            let mut deploy = message(address.clone(), false);
            deploy.set_state_init(init);
            deploy.set_body(SliceData::from_raw(vec![1], 8));
            let (deploy_tx, active) = run_at(
                &format!("history-p{prefix:?}-mc{mc}-deploy"),
                history_config(14, false, &address),
                Account::uninit(address.clone(), CurrencyCollection::default(), 0, 200),
                deploy,
                false,
                rows,
                200,
            );
            assert!(
                active.is_active(),
                "deploy p{prefix:?} mc{mc}: {:?}",
                deploy_tx.unwrap().read_description().unwrap()
            );
            assert!(active.balance().unwrap().is_zero().unwrap());
            let restore_init = active.state_init().unwrap().clone();
            let mut freeze = message(address.clone(), false);
            freeze.int_header_mut().unwrap().value = CurrencyCollection::default();
            freeze.set_body(SliceData::from_raw(vec![0], 8));
            let (_, frozen) = run_at(
                &format!("history-p{prefix:?}-mc{mc}-freeze"),
                history_config(14, false, &address),
                active,
                freeze,
                false,
                rows,
                201,
            );
            assert!(frozen.is_frozen(), "prefix {prefix:?} master {mc}");
            assert_eq!(frozen.frozen_hash(), Some(&restore_init.hash().unwrap()));
            for version in [14, 15, 16, 17, 19] {
                for special in [false, true] {
                    if special && !mc {
                        continue;
                    }
                    let mut msg = message(address.clone(), true);
                    msg.set_state_init(restore_init.clone());
                    msg.set_body(SliceData::from_raw(vec![0], 8));
                    // Internal restore supplies funds to the actual zero-balance frozen account.
                    run_at(
                        &format!("history-p{prefix:?}-mc{mc}-restore-v{version}-special{special}"),
                        history_config(version, special, &address),
                        frozen.clone(),
                        msg,
                        special,
                        rows,
                        202,
                    );
                }
            }
        }
    }
}

fn address_commit_boundaries(rows: &mut Vec<String>) {
    for version in [12, 13, 15, 16] {
        for mode in [
            "no-gas",
            "no-state",
            "suspended",
            "precompiled-no-gas",
            "vm-fail",
            "vm-ok",
            "storage-freeze",
            "storage-delete",
        ] {
            let mut init = StateInit::default();
            init.set_fixed_prefix_length(1.try_into().unwrap());
            init.set_code(
                rtos_assembler::compile_code_to_cell(if mode == "vm-fail" {
                    "ACCEPT THROW 77"
                } else {
                    "ACCEPT"
                })
                .unwrap(),
            );
            init.set_data(Cell::default());
            let mut former = init.clone();
            former.set_data(BuilderData::with_raw(vec![1], 8).unwrap().into_cell().unwrap());
            let former_hash = former.hash().unwrap();
            let mut bytes = *former_hash.as_array();
            bytes[0] ^= 0x80;
            let destination = MsgAddressInt::with_standart(None, 0, bytes.into()).unwrap();
            let stored = MsgAddressInt::with_standart(
                Some(
                    AnycastInfo::with_rewrite_pfx(SliceData::from_raw(vec![bytes[0]], 1)).unwrap(),
                ),
                0,
                former_hash.into(),
            )
            .unwrap();
            let empty = matches!(mode, "no-gas" | "storage-freeze" | "storage-delete");
            let balance = CurrencyCollection::with_coins(if empty { 0 } else { 10_000_000_000u64 });
            let mut cfg = history_config(version, false, &destination);
            let account = if mode == "suspended" {
                Account::uninit(stored.clone(), balance, 0, 200)
            } else if mode == "storage-freeze" {
                Account::active(
                    stored.clone(),
                    balance,
                    0,
                    199,
                    init.clone(),
                    cfg.size_limits_config().acc_state_cells_for_storage_dict,
                )
                .unwrap()
            } else {
                Account::frozen(
                    stored.clone(),
                    balance,
                    0,
                    if mode == "storage-delete" { 199 } else { 200 },
                    if mode == "storage-delete" { Some(2_000_000_000u64.into()) } else { None },
                    init.hash().unwrap(),
                )
            };
            let mut raw = cfg.raw_config().clone();
            if mode == "suspended" {
                let mut list = rtos_block::SuspendedAddressList::default();
                list.set_suspended_until(300);
                // Both aliases are suspended; this case isolates the commit point,
                // not suspension-list lookup of rewritten historical addresses.
                for addr in [&stored, &destination] {
                    list.add_suspended_address(0, addr.address().clone()).unwrap();
                }
                raw.set_config(ConfigParamEnum::ConfigParam44(list)).unwrap();
            }
            if mode == "precompiled-no-gas" {
                let mut list = rtos_block::PrecompiledContractsList::default();
                list.add(&init.code.as_ref().unwrap().repr_hash(), 100_000_000).unwrap();
                raw.set_config(ConfigParamEnum::ConfigParam45(list)).unwrap();
            }
            cfg = BlockchainConfig::with_config(raw).unwrap();
            let mut msg = message(destination.clone(), false);
            if empty {
                msg.int_header_mut().unwrap().value = CurrencyCollection::default();
            }
            if !matches!(mode, "no-state" | "storage-freeze" | "storage-delete") {
                msg.set_state_init(init);
            }
            let (tx, account) =
                run(&format!("address-commit-v{version}-{mode}"), cfg, account, msg, false, rows);
            let TransactionDescr::Ordinary(desc) = tx.unwrap().read_description().unwrap() else {
                panic!("ordinary")
            };
            let early = matches!(mode, "no-gas" | "no-state" | "storage-freeze");
            assert_eq!(desc.destroyed, mode == "storage-delete" && version >= 13);
            if mode == "storage-delete" {
                assert!(account.is_none());
            } else {
                assert_eq!(
                    account.get_addr().unwrap().rewrite_pfx().is_some(),
                    early,
                    "{version} {mode}"
                );
            }
            match mode {
                "vm-fail" | "vm-ok" => {
                    let TrComputePhase::Vm(vm) = desc.compute_ph else { panic!("VM") };
                    assert_eq!(vm.exit_code, if mode == "vm-fail" { 77 } else { 0 });
                }
                _ => {
                    let TrComputePhase::Skipped(skip) = desc.compute_ph else { panic!("skip") };
                    assert_eq!(
                        skip.reason,
                        match mode {
                            "no-state" => ComputeSkipReason::NoState,
                            "suspended" => ComputeSkipReason::Suspended,
                            _ => ComputeSkipReason::NoGas,
                        }
                    );
                }
            }
        }
    }
}

// Active masterchain contracts with enabled tick/tock flags. The stored anycast
// cases model an inherited pre-v10 address; the zero-prefix cases are controls.
fn tick_address_boundaries(rows: &mut Vec<String>) {
    for version in [9, 10, 19] {
        for rewrite in [false, true] {
            for tock in [false, true] {
                for mode in ["ok", "fail", "no-gas", "myaddr"] {
                    let mut init = StateInit::default();
                    if rewrite {
                        init.set_fixed_prefix_length(1.try_into().unwrap());
                    }
                    init.set_special(rtos_block::TickTock::with_values(true, true));
                    init.set_code(
                        rtos_assembler::compile_code_to_cell(match mode {
                            "fail" => "ACCEPT THROW 77",
                            "myaddr" => "ACCEPT MYADDR NEWC STSLICE ENDC POPROOT",
                            _ => "ACCEPT",
                        })
                        .unwrap(),
                    );
                    init.set_data(Cell::default());
                    let mut former = init.clone();
                    former
                        .set_data(BuilderData::with_raw(vec![1], 8).unwrap().into_cell().unwrap());
                    let hash = former.hash().unwrap();
                    let mut bytes = *hash.as_array();
                    if rewrite {
                        bytes[0] ^= 0x80;
                    }
                    let destination = MsgAddressInt::with_standart(None, -1, bytes.into()).unwrap();
                    let stored = MsgAddressInt::with_standart(
                        if rewrite {
                            Some(
                                AnycastInfo::with_rewrite_pfx(SliceData::from_raw(
                                    vec![bytes[0]],
                                    1,
                                ))
                                .unwrap(),
                            )
                        } else {
                            None
                        },
                        -1,
                        hash.into(),
                    )
                    .unwrap();
                    let cfg = config(version, true, &destination);
                    let account = Account::active(
                        stored,
                        CurrencyCollection::with_coins(if mode == "no-gas" {
                            0
                        } else {
                            10_000_000_000u64
                        }),
                        0,
                        0,
                        init,
                        cfg.size_limits_config().acc_state_cells_for_storage_dict,
                    )
                    .unwrap();
                    run(
                        &format!(
                            "tick-address-v{version}-rewrite{rewrite}-{}-{mode}",
                            if tock { "tock" } else { "tick" }
                        ),
                        cfg,
                        account,
                        message(destination, false),
                        true,
                        rows,
                    );
                }
            }
        }
    }
}

fn legacy_myaddr_cases(rows: &mut Vec<String>) {
    for version in [9, 10] {
        for external in [false, true] {
            let mut init = StateInit::default();
            init.set_fixed_prefix_length(1.try_into().unwrap());
            init.set_code(
                rtos_assembler::compile_code_to_cell("ACCEPT MYADDR NEWC STSLICE ENDC POPROOT")
                    .unwrap(),
            );
            init.set_data(Cell::default());
            let mut former = init.clone();
            former.set_data(BuilderData::with_raw(vec![1], 8).unwrap().into_cell().unwrap());
            let hash = former.hash().unwrap();
            let mut bytes = *hash.as_array();
            bytes[0] ^= 0x80;
            let destination = MsgAddressInt::with_standart(None, 0, bytes.into()).unwrap();
            let stored = MsgAddressInt::with_standart(
                Some(
                    AnycastInfo::with_rewrite_pfx(SliceData::from_raw(vec![bytes[0]], 1)).unwrap(),
                ),
                0,
                hash.into(),
            )
            .unwrap();
            let account = Account::frozen(
                stored,
                CurrencyCollection::with_coins(10_000_000_000u64),
                0,
                100,
                None,
                init.hash().unwrap(),
            );
            let mut msg = if external {
                Message::with_ext_in_header(ExternalInboundMessageHeader {
                    dst: destination.clone(),
                    ..Default::default()
                })
            } else {
                message(destination.clone(), true)
            };
            msg.set_state_init(init);
            run(
                &format!("legacy-myaddr-v{version}-external{external}"),
                config(version, false, &destination),
                account,
                msg,
                false,
                rows,
            );
        }
    }
}
