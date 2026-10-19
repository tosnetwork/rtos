// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use crate::{BlockchainConfig, ExecuteParams, TickTockTransactionExecutor, TransactionExecutor};
use rtos_block::{
    Account, Cell, ConfigParam31, ConfigParam8, ConfigParamEnum, CurrencyCollection,
    GetRepresentationHash, HashUpdate, MsgAddressInt, Serializable, SliceData, StateInit,
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
fn run(
    name: &str,
    config: BlockchainConfig,
    mut account: Account,
    tt: rtos_block::TransactionTickTock,
    special: bool,
    rows: &mut Vec<String>,
) -> (rtos_block::Transaction, Account) {
    let address = account.get_addr().unwrap();
    let input = format!(
        "{name}\t200\t2000000001\t{}\t{}\t{}\t-\t{}\t{}\t{}",
        boc(config.raw_config().serialize().unwrap()),
        boc(account.serialize().unwrap()),
        "-",
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
    let mut tx = TickTockTransactionExecutor::new(config, tt)
        .execute_with_params(None, &mut account, params)
        .unwrap_or_else(|error| panic!("{name}: {error}"));
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
    if std::env::var_os("RTOS_TICKTOCK_EXPORT").is_none() {
        let expected = include_str!("data/ticktock-context.tsv")
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
fn ticktock_context_matches_cpp_transactions() {
    let mut rows = Vec::new();
    for version in [10, 11, 13, 14, 16, 17, 18, 19] {
        for tock in [false, true] {
            for balance in [0u64, 1, 10_000_000_000] {
                for (probe, source) in [
                    ("length", "PUSHCTR c7 FIRST TLEN NEWC STU 8 ENDC POPROOT"),
                    ("null", "PUSHCTR c7 FIRST PUSHINT 18 INDEXVAR ISNULL NEWC STI 8 ENDC POPROOT"),
                    ("fields", "PUSHCTR c7 FIRST PUSHINT 18 INDEXVAR UNTUPLE 4 NEWC STU 64 STU 64 STU 256 STU 8 ENDC POPROOT"),
                    ("msg-length", "PUSHCTR c7 FIRST PUSHINT 17 INDEXVAR TLEN NEWC STU 8 ENDC POPROOT"),
                    ("msg-value", "PUSHCTR c7 FIRST PUSHINT 17 INDEXVAR PUSHINT 7 INDEXVAR NEWC STU 64 ENDC POPROOT"),
                    ("msg-time", "PUSHCTR c7 FIRST PUSHINT 17 INDEXVAR PUSHINT 5 INDEXVAR NEWC STU 32 ENDC POPROOT"),
                    ("msg-src", "PUSHCTR c7 FIRST PUSHINT 17 INDEXVAR PUSHINT 2 INDEXVAR NEWC STSLICE ENDC POPROOT"),
                    ("stack", "NEWC STI 8 STI 8 STU 256 STU 64 ENDC POPROOT"),
                    ("throw", "PUSHINT 77 THROWANY"),
                    ("action-fail", "PUSHROOT PUSHINT 255 SENDRAWMSG"),
                ] {
                    let address = MsgAddressInt::with_standart(None,-1,[0x5a;32].into()).unwrap();
                    let cfg=config(version,true,&address);
                    let mut state=StateInit::default();
                    state.set_code(rtos_assembler::compile_code_to_cell(source).unwrap());
                    state.set_data(Cell::default());
                    state.set_special(rtos_block::TickTock{tick:true,tock:true});
                    let account=Account::active(address,CurrencyCollection::with_coins(balance),0,0,state,cfg.size_limits_config().acc_state_cells_for_storage_dict).unwrap();
                    let name=format!("context-v{version}-{}-balance{balance}-{probe}",if tock{"tock"}else{"tick"});
                    let tt=if tock {rtos_block::TransactionTickTock::Tock}else{rtos_block::TransactionTickTock::Tick};
                    let (tx, account)=run(&name,cfg,account,tt,true,&mut rows);
                    let rtos_block::TransactionDescr::TickTock(desc)=tx.read_description().unwrap() else {panic!("ticktock")};
                    let rtos_block::TrComputePhase::Vm(compute)=desc.compute_ph else { assert_eq!(balance,0,"{name}"); continue; };
                    let success=match probe {"fields"|"throw"=>false,"null"=>version>=16,p if p.starts_with("msg-")=>version>=11,_=>true};
                    assert_eq!(compute.success,success,"{name}");
                    if probe=="length" {assert_eq!(SliceData::load_cell(account.get_data().unwrap()).unwrap().get_next_byte().unwrap(),if version>=16{19}else if version>=11{18}else{17},"{name}");}
                    if probe=="null" && version>=16 {assert_eq!(SliceData::load_cell(account.get_data().unwrap()).unwrap().get_next_byte().unwrap(),255,"{name}");}
                }
            }
        }
    }
    assert_eq!(rows.len(), 480);
    if let Ok(path) = std::env::var("RTOS_TICKTOCK_EXPORT") {
        std::fs::write(path, rows.join("\n") + "\n").unwrap();
    }
}

/// Complete transactions whose compute phase exercises VM charges and step counts aligned with
/// the reference VM (truncated code, debug opcodes, code pages, PushInt returns, extra-balance
/// cheap calls). Transaction and account roots are frozen from the reference emulator.
#[test]
fn ticktock_vm_alignment_matches_cpp_transactions() {
    fn raw(bytes: &[u8], bits: usize) -> Cell {
        let mut b = rtos_block::BuilderData::new();
        b.append_raw(bytes, bits).unwrap();
        b.into_cell().unwrap()
    }
    fn asm(source: &str) -> Cell {
        rtos_assembler::compile_code_to_cell(source).unwrap()
    }
    let store = "NEWC STU 8 ENDC POPROOT";
    let extra_calls = |n: u32| {
        let calls = (0..n).map(|i| format!("PUSHINT {i} GETEXTRABALANCE DROP")).collect::<Vec<_>>();
        format!("{} PUSHINT 7 GETEXTRABALANCE NEWC STU 64 ENDC POPROOT", calls.join(" "))
    };
    let cases: Vec<(&str, Cell, bool)> = vec![
        ("merged-fragment-b14", raw(&[0x00, 0x6c], 14), false),
        ("merged-fragment-b16", raw(&[0x68, 0x6c], 16), false),
        ("truncated-b16-b7a9", raw(&[0xb7, 0xa9], 16), false),
        ("truncated-b17-16f6d", raw(&[0xb7, 0xb6, 0x80], 17), false),
        ("debug-fe0f-fef1", raw(&[0xfe, 0x0f, 0xfe, 0xf1, 0xc3, 0xa9, 0x77], 56), false),
        ("debug-fe40", raw(&[0xfe, 0x40, 0x77], 24), false),
        ("setcp-ff01", raw(&[0x77, 0xff, 0x01, 0x77], 32), false),
        ("setcpx-zero", asm("PUSHINT 0 SETCPX PUSHINT 7 NEWC STU 8 ENDC POPROOT"), false),
        ("booleval-ret", asm(&format!("PUSHCONT {{ PUSHINT 5 }} BOOLEVAL DROP {store}")), false),
        (
            "booleval-nested",
            asm(&format!("PUSHCONT {{ PUSHCONT {{ RETALT }} BOOLEVAL }} BOOLEVAL {store}")),
            false,
        ),
        ("extrabalance-1", asm(&extra_calls(0)), true),
        ("extrabalance-5", asm(&extra_calls(4)), true),
        ("extrabalance-8", asm(&extra_calls(7)), true),
    ];
    let mut rows = Vec::new();
    for version in [16] {
        for (probe, code, extra) in &cases {
            let address = MsgAddressInt::with_standart(None, -1, [0x5a; 32].into()).unwrap();
            let cfg = config(version, true, &address);
            let mut state = StateInit::default();
            state.set_code(code.clone());
            state.set_data(Cell::default());
            state.set_special(rtos_block::TickTock { tick: true, tock: true });
            let mut balance = CurrencyCollection::with_coins(10_000_000_000);
            if *extra {
                for key in 0..8u32 {
                    balance.set_other(key, 1_000 + u128::from(key)).unwrap();
                }
            }
            let account = Account::active(
                address,
                balance,
                0,
                0,
                state,
                cfg.size_limits_config().acc_state_cells_for_storage_dict,
            )
            .unwrap();
            let name = format!("align-v{version}-tick-{probe}");
            run(&name, cfg, account, rtos_block::TransactionTickTock::Tick, true, &mut rows);
        }
    }
    assert_eq!(rows.len(), cases.len());
    if let Ok(path) = std::env::var("RTOS_TICKTOCK_ALIGN_EXPORT") {
        std::fs::write(path, rows.join("\n") + "\n").unwrap();
    }
}

#[test]
fn ticktock_rejects_inbound_message_without_mutating_account() {
    let address = MsgAddressInt::with_standart(None, -1, [0x5a; 32].into()).unwrap();
    let cfg = config(17, true, &address);
    let mut init = StateInit::default();
    init.set_code(rtos_assembler::compile_code_to_cell("PUSHINT 1").unwrap());
    init.set_special(rtos_block::TickTock { tick: true, tock: true });
    let mut account = Account::active(
        address,
        CurrencyCollection::with_coins(10_000_000_000u64),
        0,
        0,
        init,
        1000,
    )
    .unwrap();
    let original = account.serialize().unwrap();
    for tt in [rtos_block::TransactionTickTock::Tick, rtos_block::TransactionTickTock::Tock] {
        let error = TickTockTransactionExecutor::new(cfg.clone(), tt)
            .execute_with_params(Some(Cell::default()), &mut account, ExecuteParams::default())
            .unwrap_err();
        assert!(error.to_string().contains("must not have input message"));
        assert_eq!(account.serialize().unwrap(), original);
    }
}

#[test]
fn ticktock_message_lt_uses_transaction_floor() {
    use rtos_block::{InternalMessageHeader, Message};
    let mut rows = Vec::new();
    let mut mismatches = Vec::new();
    for version in [4, 10, 13, 14, 17, 19] {
        for tock in [false, true] {
            for supplied in [2_000_000_001u64, 2_000_000_004, 2_000_000_007] {
                for sends in [0usize, 1, 3] {
                    let address =
                        MsgAddressInt::with_standart(None, -1, [0x5a; 32].into()).unwrap();
                    let cfg = config(version, true, &address);
                    let dst = MsgAddressInt::with_standart(None, -1, [0x6b; 32].into()).unwrap();
                    let msg = Message::with_int_header(InternalMessageHeader::with_addresses(
                        address.clone(),
                        dst,
                        CurrencyCollection::with_coins(10_000_000u64),
                    ));
                    let source = if sends == 0 {
                        "NOP".to_owned()
                    } else {
                        "PUSHROOT PUSHINT 1 SENDRAWMSG ".repeat(sends)
                    };
                    let mut init = StateInit::default();
                    init.set_code(rtos_assembler::compile_code_to_cell(&source).unwrap());
                    init.set_data(msg.serialize().unwrap());
                    init.set_special(rtos_block::TickTock { tick: true, tock: true });
                    let threshold = cfg.size_limits_config().acc_state_cells_for_storage_dict;
                    let mut account = Account::active(
                        address.clone(),
                        CurrencyCollection::with_coins(10_000_000_000u64),
                        2_000_000_004,
                        0,
                        init,
                        threshold,
                    )
                    .unwrap();
                    let name = format!(
                        "lt-v{version}-{}-floor{supplied}-sends{sends}",
                        if tock { "tock" } else { "tick" }
                    );
                    let old = account.hash().unwrap();
                    let input = format!(
                        "{name}\t200\t{supplied}\t{}\t{}\t-\t-\t1\t-1\t{}",
                        boc(cfg.raw_config().serialize().unwrap()),
                        boc(account.serialize().unwrap()),
                        "5a".repeat(32)
                    );
                    let tt = if tock {
                        rtos_block::TransactionTickTock::Tock
                    } else {
                        rtos_block::TransactionTickTock::Tick
                    };
                    let mut tx = TickTockTransactionExecutor::new(cfg, tt)
                        .execute_with_params(
                            None,
                            &mut account,
                            ExecuteParams {
                                block_unixtime: 200,
                                block_lt: 2_000_000_000,
                                last_tr_lt: supplied,
                                ..Default::default()
                            },
                        )
                        .unwrap();
                    account.calc_storage_stat_dict(threshold).unwrap();
                    if version < 11 {
                        account.del_storage_stat();
                    }
                    tx.write_state_update(&HashUpdate::with_hashes(old, account.hash().unwrap()))
                        .unwrap();
                    rows.push(format!(
                        "{input}\t{:x}\t{:x}",
                        tx.hash().unwrap(),
                        account.hash().unwrap()
                    ));
                    let logical_time = supplied.max(2_000_000_004);
                    assert_eq!(tx.logical_time(), logical_time, "{name}");
                    assert_eq!(tx.out_msgs.len().unwrap(), sends, "{name}");
                    let mut created = Vec::new();
                    tx.iterate_out_msgs(|message| {
                        created.push(message.created_lt().unwrap());
                        Ok(true)
                    })
                    .unwrap();
                    let want = (1..=sends).map(|i| logical_time + i as u64).collect::<Vec<_>>();
                    if created != want
                        || account.last_tr_time() != Some(logical_time + sends as u64 + 1)
                    {
                        mismatches.push(format!(
                            "{name}: messages {created:?} expected {want:?}; end {:?}",
                            account.last_tr_time()
                        ));
                    }
                }
            }
        }
    }
    assert_eq!(rows.len(), 108);
    if let Ok(path) = std::env::var("RTOS_TICKTOCK_LT_EXPORT") {
        std::fs::write(path, rows.join("\n") + "\n").unwrap();
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
    let expected = include_str!("data/ticktock-message-lt.tsv");
    assert_eq!(expected.lines().count(), rows.len());
    for row in rows {
        let fields = row.split('\t').collect::<Vec<_>>();
        let reference = expected
            .lines()
            .find(|line| line.split('\t').next() == Some(fields[0]))
            .expect("fixed reference transaction");
        assert_eq!(
            format!("{}\t{}\t{}", fields[0], fields[10], fields[11]),
            reference,
            "complete transaction and account roots"
        );
    }
}
