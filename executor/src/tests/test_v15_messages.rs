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
    if std::env::var_os("RTOS_V15_MESSAGE_EXPORT").is_none() {
        let expected = include_str!("data/v15-messages.tsv")
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
fn v15_message_limits_and_fines() {
    let mut rows = Vec::new();
    let code = rtos_assembler::compile_code_to_cell(
        "DROP LDREF ENDS POPCTR c5 PUSHINT 77 NEWC STU 8 ENDC POPROOT",
    )
    .unwrap();
    for pre_skip in [false, true] {
        for poor in [false, true] {
            for version in [14, 15, 19] {
                for special in [false, true] {
                    for external in [false, true] {
                        for mode in [0u8, 2, 16, 18, 64, 80, 82, 128, 144, 146] {
                            if pre_skip && (poor || special || external || mode < 64) {
                                continue;
                            }
                            if external && mode >= 64 {
                                continue;
                            }
                            for later_failure in [false, true] {
                                let mut total_bits = 0;
                                let mut total_cells = 0;
                                for limit_name in [
                                    "unlimited",
                                    "zero-bits",
                                    "zero-cells",
                                    "one-message",
                                    "two-messages",
                                    "exact-bits",
                                    "bits-minus-one",
                                    "bits-plus-one",
                                    "exact-cells",
                                    "cells-minus-one",
                                    "cells-plus-one",
                                ] {
                                    if pre_skip && limit_name != "unlimited" {
                                        continue;
                                    }
                                    let (bits, cells) = match limit_name {
                                        "zero-bits" => (0, u32::MAX),
                                        "zero-cells" => (u32::MAX, 0),
                                        "one-message" => (u32::MAX, 2),
                                        "two-messages" => (u32::MAX, 4),
                                        "exact-bits" => (total_bits, u32::MAX),
                                        "bits-minus-one" => (total_bits - 1, u32::MAX),
                                        "bits-plus-one" => (total_bits + 1, u32::MAX),
                                        "exact-cells" => (u32::MAX, total_cells),
                                        "cells-minus-one" => (u32::MAX, total_cells - 1),
                                        "cells-plus-one" => (u32::MAX, total_cells + 1),
                                        _ => (u32::MAX, u32::MAX),
                                    };
                                    let name = format!("messages-v{version}-special{special}-external{external}-mode{mode}-later{later_failure}-{limit_name}");
                                    let name =
                                        if poor { format!("{name}-low-balance") } else { name };
                                    let name = if pre_skip {
                                        format!("{name}-after-skipped-send")
                                    } else {
                                        name
                                    };
                                    let address = MsgAddressInt::with_standart(
                                        None,
                                        if special { -1 } else { 0 },
                                        [0x5a; 32].into(),
                                    )
                                    .unwrap();
                                    let base = config(version, special, &address);
                                    let mut raw = base.raw_config().clone();
                                    let mut limits = raw.size_limits_config().unwrap();
                                    limits.max_total_msg_bits = bits;
                                    limits.max_total_msg_cells = cells;
                                    raw.set_config(ConfigParamEnum::ConfigParam43(limits)).unwrap();
                                    let cfg = BlockchainConfig::with_config(raw).unwrap();
                                    let mut init = StateInit::default();
                                    init.set_code(code.clone());
                                    init.set_data(Cell::default());
                                    let account = Account::active(
                                        address.clone(),
                                        CurrencyCollection::with_coins(if poor {
                                            0
                                        } else {
                                            10_000_000_000u64
                                        }),
                                        0,
                                        if special { 0 } else { 100 },
                                        init,
                                        cfg.size_limits_config().acc_state_cells_for_storage_dict,
                                    )
                                    .unwrap();
                                    let mut actions = OutActions::new();
                                    for i in 0..2 {
                                        let mut out = if external {
                                            let header = rtos_block::ExtOutMessageHeader::default();
                                            Message::with_ext_out_header(header)
                                        } else {
                                            let dst = MsgAddressInt::with_standart(
                                                None,
                                                0,
                                                [0x33; 32].into(),
                                            )
                                            .unwrap();
                                            Message::with_int_header(
                                                InternalMessageHeader::with_addresses(
                                                    address.clone(),
                                                    dst,
                                                    CurrencyCollection::with_coins(100_000_000u64),
                                                ),
                                            )
                                        };
                                        let mut body = BuilderData::new();
                                        body.append_u8(i).unwrap();
                                        body.checked_append_reference(
                                            BuilderData::with_raw(vec![0x55; 100], 800)
                                                .unwrap()
                                                .into_cell()
                                                .unwrap(),
                                        )
                                        .unwrap();
                                        out.set_body(SliceData::load_builder(body).unwrap());
                                        let send_mode = if pre_skip && i == 0 {
                                            out.int_header_mut().unwrap().value =
                                                CurrencyCollection::with_coins(20_000_000_000u64);
                                            2
                                        } else {
                                            mode
                                        };
                                        actions.push_back(OutAction::new_send(send_mode, out));
                                    }
                                    if later_failure {
                                        actions.push_back(OutAction::new_reserve(
                                            0,
                                            CurrencyCollection::with_coins(1_000_000_000_000u64),
                                        ));
                                    }
                                    let mut body = BuilderData::new();
                                    body.checked_append_reference(actions.serialize().unwrap())
                                        .unwrap();
                                    let mut msg = message(address, true);
                                    if poor {
                                        msg.int_header_mut().unwrap().value =
                                            CurrencyCollection::with_coins(1_000_000u64);
                                    }
                                    msg.set_body(SliceData::load_builder(body).unwrap());
                                    let (tx, _) = run(&name, cfg, account, msg, special, &mut rows);
                                    if limit_name == "unlimited" {
                                        let rtos_block::TransactionDescr::Ordinary(desc) =
                                            tx.read_description().unwrap()
                                        else {
                                            panic!("ordinary");
                                        };
                                        let action = desc.action.unwrap();
                                        total_bits = action.tot_msg_size.bits() as u32;
                                        total_cells = action.tot_msg_size.cells() as u32;
                                        if poor && total_cells == 0 {
                                            // No send reached serialization: there is no aggregate boundary.
                                            break;
                                        }
                                        assert!(total_bits > 0 && total_cells > 0);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    for version in [14, 15, 19] {
        for bounce in [false, true] {
            let name = format!("fine-exceeds-inbound-v{version}-bounce{bounce}");
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
            let mut actions = OutActions::new();
            for _ in 0..110 {
                let dst = MsgAddressInt::with_standart(None, 0, [0x33; 32].into()).unwrap();
                let mut out = Message::with_int_header(InternalMessageHeader::with_addresses(
                    address.clone(),
                    dst,
                    CurrencyCollection::with_coins(10_000_000u64),
                ));
                let mut body = BuilderData::new();
                body.checked_append_reference(
                    BuilderData::with_raw(vec![0x55; 100], 800).unwrap().into_cell().unwrap(),
                )
                .unwrap();
                out.set_body(SliceData::load_builder(body).unwrap());
                actions.push_back(OutAction::new_send(0, out));
            }
            actions.push_back(OutAction::new_reserve(
                if bounce { 16 } else { 0 },
                CurrencyCollection::with_coins(1_000_000_000_000u64),
            ));
            let mut body = BuilderData::new();
            body.checked_append_reference(actions.serialize().unwrap()).unwrap();
            let mut msg = message(address, true);
            msg.int_header_mut().unwrap().value = CurrencyCollection::with_coins(1_000_000u64);
            msg.set_body(SliceData::load_builder(body).unwrap());
            run(&name, cfg, account, msg, false, &mut rows);
        }
    }
    if let Some(path) = std::env::var_os("RTOS_V15_MESSAGE_EXPORT") {
        std::fs::write(path, rows.join("\n") + "\n").unwrap();
    }
}
