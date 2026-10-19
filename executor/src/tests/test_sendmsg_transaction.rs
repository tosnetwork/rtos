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

// Complete transactions whose inbound message or account carries a
// VarUInteger field in a non-minimal encoding (a leading zero byte or the
// longest length), against minimal controls. The frozen expectations in
// data/nonminimal-coins.tsv were produced by the reference transaction
// emulator from the exported inputs; ERROR means no transaction (the
// message or account is refused).

use rtos_block::IBitstring;

/// `value` as a VarUInteger 16 payload of exactly `len` bytes.
fn coins_bits(builder: &mut BuilderData, value: u128, len: usize) {
    builder.append_bits(len, 4).unwrap();
    let bytes = value.to_be_bytes();
    assert!(bytes[..16 - len].iter().all(|b| *b == 0), "{value} does not fit {len} bytes");
    builder.append_raw(&bytes[16 - len..], len * 8).unwrap();
}

/// `value` as a VarUInteger 7 payload of exactly `len` bytes.
fn varuint7_bits(builder: &mut BuilderData, value: u64, len: usize) {
    builder.append_bits(len, 3).unwrap();
    let bytes = value.to_be_bytes();
    assert!(bytes[..8 - len].iter().all(|b| *b == 0), "{value} does not fit {len} bytes");
    builder.append_raw(&bytes[8 - len..], len * 8).unwrap();
}

fn minimal_len(value: u128) -> usize {
    (128 - value.leading_zeros() as usize).div_ceil(8)
}

/// Encodings of a value: minimal, with one leading zero byte, and padded to
/// the longest length.
fn coins_lengths(value: u128) -> [(&'static str, usize); 3] {
    let min = minimal_len(value);
    [("min", min), ("lead", min + 1), ("len15", 15)]
}

struct IntFields {
    value: (u128, usize),
    extra_flags: (u128, usize),
    fwd_fee: (u128, usize),
}

fn internal_message_cell(src: &MsgAddressInt, dst: &MsgAddressInt, f: &IntFields) -> Cell {
    let mut b = BuilderData::new();
    b.append_bit_zero().unwrap(); // int_msg_info$0
    b.append_bit_one().unwrap(); // ihr_disabled
    b.append_bit_zero().unwrap(); // bounce
    b.append_bit_zero().unwrap(); // bounced
    src.write_to(&mut b).unwrap();
    dst.write_to(&mut b).unwrap();
    coins_bits(&mut b, f.value.0, f.value.1);
    b.append_bit_zero().unwrap(); // no extra currencies
    coins_bits(&mut b, f.extra_flags.0, f.extra_flags.1);
    coins_bits(&mut b, f.fwd_fee.0, f.fwd_fee.1);
    b.append_u64(1000).unwrap(); // created_lt
    b.append_u32(0).unwrap(); // created_at
    b.append_bit_zero().unwrap(); // no init
    b.append_bit_zero().unwrap(); // inline empty body
    b.into_cell().unwrap()
}

fn external_message_cell(dst: &MsgAddressInt, import_fee: (u128, usize)) -> Cell {
    let mut b = BuilderData::new();
    b.append_bits(0b10, 2).unwrap(); // ext_in_msg_info$10
    b.append_bits(0b00, 2).unwrap(); // src: addr_none$00
    dst.write_to(&mut b).unwrap();
    coins_bits(&mut b, import_fee.0, import_fee.1);
    b.append_bit_zero().unwrap(); // no init
    b.append_bit_zero().unwrap(); // inline empty body
    b.into_cell().unwrap()
}

/// The account cell with its storage usage re-encoded with the given lengths.
fn account_with_storage_used(account: &Account, cells_len: usize, bits_len: usize) -> Cell {
    let mut slice = SliceData::load_cell(account.serialize().unwrap()).unwrap();
    assert!(slice.get_next_bit().unwrap());
    let addr = MsgAddressInt::construct_from(&mut slice).unwrap();
    let cells = rtos_block::VarUInteger7::construct_from(&mut slice).unwrap();
    let bits = rtos_block::VarUInteger7::construct_from(&mut slice).unwrap();
    let mut b = BuilderData::new();
    b.append_bit_one().unwrap();
    addr.write_to(&mut b).unwrap();
    varuint7_bits(&mut b, cells.as_u64(), cells_len);
    varuint7_bits(&mut b, bits.as_u64(), bits_len);
    b.checked_append_references_and_data(&slice).unwrap();
    b.into_cell().unwrap()
}

fn run_cells(
    name: &str,
    config: BlockchainConfig,
    account_cell: Cell,
    msg_cell: Cell,
    address: &MsgAddressInt,
    rows: &mut Vec<String>,
) {
    let input = format!(
        "{name}\t200\t2000000001\t{}\t{}\t{}\t-\t0\t{}\t{}",
        boc(config.raw_config().serialize().unwrap()),
        boc(account_cell.clone()),
        boc(msg_cell.clone()),
        address.workchain_id(),
        hex_bytes(address.address().get_bytestring(0).as_ref())
    );
    let outcome = (|| -> rtos_block::Result<(String, String)> {
        let mut account = Account::construct_from_cell(account_cell)?;
        let old = account.hash()?;
        let dict_threshold = config.size_limits_config().acc_state_cells_for_storage_dict;
        let params = ExecuteParams {
            block_unixtime: 200,
            block_lt: 2_000_000_000,
            last_tr_lt: 2_000_000_001,
            ..Default::default()
        };
        let mut tx = OrdinaryTransactionExecutor::new(config).execute_with_params(
            Some(msg_cell),
            &mut account,
            params,
        )?;
        let changed = account.precalc_storage_stat()?.is_some_and(|stat| stat.is_changed());
        let needs_dict = account.get_addr().is_some_and(|a| !a.is_masterchain())
            && account.dict_hash().is_none()
            && account.storage_info().is_some_and(|s| s.used().cells() >= dict_threshold as u64);
        if changed || needs_dict {
            account.calc_storage_stat_dict(dict_threshold)?;
        }
        tx.write_state_update(&HashUpdate::with_hashes(old, account.hash()?))?;
        Ok((format!("{:x}", tx.hash()?), format!("{:x}", account.hash()?)))
    })();
    let (th, ah) = outcome.unwrap_or_else(|_| ("ERROR".to_string(), "ERROR".to_string()));
    rows.push(format!("{input}\t{th}\t{ah}"));
}

#[test]
fn nonminimal_coins_complete_transactions() {
    let src = MsgAddressInt::with_standart(None, 0, [0x11; 32].into()).unwrap();
    let addr = MsgAddressInt::standard(0, [0x62; 32]);
    let mut rows = Vec::new();
    for version in [11u32, 12, 16] {
        let cfg = config(version, false, &addr);
        let mut init = StateInit::default();
        init.set_code(rtos_assembler::compile_code_to_cell("ACCEPT").unwrap());
        init.set_data(Cell::default());
        let account = Account::active(
            addr.clone(),
            CurrencyCollection::with_coins(10_000_000_000u64),
            0,
            100,
            init,
            cfg.size_limits_config().acc_state_cells_for_storage_dict,
        )
        .unwrap();
        let minimal = IntFields { value: (1_000_000_000, 4), extra_flags: (0, 0), fwd_fee: (0, 0) };
        let mut add = |name: String, account_cell: Cell, msg: Cell| {
            run_cells(
                &format!("{name}-v{version}"),
                cfg.clone(),
                account_cell,
                msg,
                &addr,
                &mut rows,
            )
        };
        let account_cell = account.serialize().unwrap();
        for value in [1_000_000_000u128, 0] {
            for (enc, len) in coins_lengths(value) {
                let f = IntFields { value: (value, len), ..minimal };
                add(
                    format!("int-value-{value}-{enc}"),
                    account_cell.clone(),
                    internal_message_cell(&src, &addr, &f),
                );
            }
        }
        for flags in [0u128, 1] {
            for (enc, len) in coins_lengths(flags) {
                let f = IntFields { extra_flags: (flags, len), ..minimal };
                add(
                    format!("int-flags-{flags}-{enc}"),
                    account_cell.clone(),
                    internal_message_cell(&src, &addr, &f),
                );
            }
        }
        for fee in [0u128, 1000] {
            for (enc, len) in coins_lengths(fee) {
                let f = IntFields { fwd_fee: (fee, len), ..minimal };
                add(
                    format!("int-fwdfee-{fee}-{enc}"),
                    account_cell.clone(),
                    internal_message_cell(&src, &addr, &f),
                );
            }
        }
        for fee in [0u128, 1000] {
            for (enc, len) in coins_lengths(fee) {
                add(
                    format!("ext-importfee-{fee}-{enc}"),
                    account_cell.clone(),
                    external_message_cell(&addr, (fee, len)),
                );
            }
        }
        let used = account.storage_info().unwrap().used();
        let (cells_min, bits_min) =
            (minimal_len(used.cells() as u128), minimal_len(used.bits() as u128));
        for (enc, cells_len, bits_len) in [
            ("min", cells_min, bits_min),
            ("cells-lead", cells_min + 1, bits_min),
            ("bits-lead", cells_min, bits_min + 1),
            ("len6", 6, 6),
        ] {
            add(
                format!("account-used-{enc}"),
                account_with_storage_used(&account, cells_len, bits_len),
                internal_message_cell(&src, &addr, &minimal),
            );
        }
    }
    assert_eq!(rows.len(), 3 * 28);
    if let Ok(path) = std::env::var("RTOS_NONMINIMAL_TRANSACTION_EXPORT") {
        std::fs::write(path, rows.join("\n") + "\n").unwrap();
        return;
    }
    let expected: std::collections::HashMap<_, _> = include_str!("data/nonminimal-coins.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let f: Vec<_> = line.split('\t').collect();
            (f[0], (f[1].to_lowercase(), f[2].to_lowercase()))
        })
        .collect();
    assert_eq!(expected.len(), rows.len());
    // Before version 12 the reference credits extra_flags as the legacy IHR
    // fee to the message balance, which the executor does not do; the minimal
    // flags=1 row at version 11 is tracked as a separate executor finding.
    const KNOWN_DIFFERENCES: [&str; 1] = ["int-flags-1-min-v11"];
    for row in &rows {
        let f: Vec<_> = row.split('\t').collect();
        if KNOWN_DIFFERENCES.contains(&f[0]) {
            continue;
        }
        let (th, ah) = &expected[f[0]];
        assert_eq!(
            (f[10].to_lowercase(), f[11].to_lowercase()),
            (th.clone(), ah.clone()),
            "{}",
            f[0]
        );
    }
}
