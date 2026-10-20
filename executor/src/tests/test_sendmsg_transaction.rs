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
    run_cells_with(name, config, account_cell, msg_cell, address, false, rows)
}

/// As `run_cells`; `special` marks the account special for the reference
/// (the executor derives it from the configuration).
fn run_cells_with(
    name: &str,
    config: BlockchainConfig,
    account_cell: Cell,
    msg_cell: Cell,
    address: &MsgAddressInt,
    special: bool,
    rows: &mut Vec<String>,
) {
    let input = format!(
        "{name}\t200\t2000000001\t{}\t{}\t{}\t-\t{}\t{}\t{}",
        boc(config.raw_config().serialize().unwrap()),
        boc(account_cell.clone()),
        boc(msg_cell.clone()),
        u8::from(special),
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
    check_reference_rows(
        &rows,
        include_str!("data/nonminimal-coins.tsv"),
        "RTOS_NONMINIMAL_TRANSACTION_EXPORT",
        &[],
    );
}

/// Compares exported rows (transaction and account roots in columns 10 and 11)
/// with a reference fixture (id, transaction root, account root, ...). When
/// `export_var` is set the rows are written to that path instead. Rows listed
/// in `known` are open findings: they must still differ, so the list cannot go
/// stale silently.
fn check_reference_rows(rows: &[String], fixture: &str, export_var: &str, known: &[&str]) {
    if let Ok(path) = std::env::var(export_var) {
        std::fs::write(path, rows.join("\n") + "\n").unwrap();
        return;
    }
    let expected: std::collections::HashMap<_, _> = fixture
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let f: Vec<_> = line.split('\t').collect();
            (f[0], (f[1].to_lowercase(), f[2].to_lowercase()))
        })
        .collect();
    assert_eq!(expected.len(), rows.len());
    for row in rows {
        let f: Vec<_> = row.split('\t').collect();
        let (th, ah) = expected.get(f[0]).unwrap_or_else(|| panic!("{} not in fixture", f[0]));
        let actual = (f[10].to_lowercase(), f[11].to_lowercase());
        if known.contains(&f[0]) {
            assert_ne!(actual, (th.clone(), ah.clone()), "{} no longer differs", f[0]);
        } else {
            assert_eq!(actual, (th.clone(), ah.clone()), "{}", f[0]);
        }
    }
}

/// `value` as a Coins payload in its minimal encoding.
fn coins_min(builder: &mut BuilderData, value: u128) {
    coins_bits(builder, value, minimal_len(value));
}

struct Inbound {
    value: u128,
    other: rtos_block::ExtraCurrencyCollection,
    extra_flags: u128,
    bounce: bool,
}

impl Inbound {
    fn value(value: u128) -> Self {
        Self { value, other: Default::default(), extra_flags: 0, bounce: false }
    }
}

/// An internal message with minimal encodings and the given value, extra
/// currencies, extra_flags and bounce flag.
fn inbound_cell(src: &MsgAddressInt, dst: &MsgAddressInt, m: &Inbound) -> Cell {
    let mut b = BuilderData::new();
    b.append_bit_zero().unwrap(); // int_msg_info$0
    b.append_bit_one().unwrap(); // ihr_disabled
    if m.bounce {
        b.append_bit_one().unwrap();
    } else {
        b.append_bit_zero().unwrap();
    }
    b.append_bit_zero().unwrap(); // bounced
    src.write_to(&mut b).unwrap();
    dst.write_to(&mut b).unwrap();
    coins_min(&mut b, m.value);
    m.other.write_to(&mut b).unwrap();
    coins_min(&mut b, m.extra_flags);
    coins_min(&mut b, 0); // fwd_fee
    b.append_u64(1000).unwrap(); // created_lt
    b.append_u32(0).unwrap(); // created_at
    b.append_bit_zero().unwrap(); // no init
    b.append_bit_zero().unwrap(); // inline empty body
    b.into_cell().unwrap()
}

/// An active account cell with the given balance, code and data.
fn account_cell(
    addr: &MsgAddressInt,
    cfg: &BlockchainConfig,
    coins: u128,
    other: rtos_block::ExtraCurrencyCollection,
    code: &str,
    data: Cell,
) -> Cell {
    let mut init = StateInit::default();
    init.set_code(rtos_assembler::compile_code_to_cell(code).unwrap());
    init.set_data(data);
    Account::active(
        addr.clone(),
        CurrencyCollection { coins: rtos_block::Coins::try_from(coins).unwrap(), other },
        0,
        100,
        init,
        cfg.size_limits_config().acc_state_cells_for_storage_dict,
    )
    .unwrap()
    .serialize()
    .unwrap()
}

/// Contract code sending the message kept as the first reference of its data.
fn send_code(mode: u8) -> String {
    format!("PUSHROOT CTOS LDREF DROP PUSHINT {mode} SENDRAWMSG")
}

fn data_with_refs(refs: &[Cell]) -> Cell {
    let mut b = BuilderData::new();
    for r in refs {
        b.checked_append_reference(r.clone()).unwrap();
    }
    b.into_cell().unwrap()
}

/// An outbound internal message to `dst` without bounce.
fn outbound_cell(
    src: &MsgAddressInt,
    dst: &MsgAddressInt,
    value: u128,
    other: rtos_block::ExtraCurrencyCollection,
) -> Cell {
    let mut hdr = InternalMessageHeader::with_addresses(
        src.clone(),
        dst.clone(),
        CurrencyCollection { coins: rtos_block::Coins::try_from(value).unwrap(), other },
    );
    hdr.ihr_disabled = true;
    hdr.bounce = false;
    Message::with_int_header(hdr).serialize().unwrap()
}

// Complete transactions for the inbound extra_flags field. From version 12 it
// carries flags and reserved bits refuse the message; before version 12 it is
// the legacy IHR fee, credited with the message value (to the credit phase, the
// gas limit, the stack and c7 values, mode 64 and the bounce), and a bounce
// carries no flags. data/inbound-extra-flags.tsv holds the reference roots.
#[test]
fn inbound_extra_flags_complete_transactions() {
    let src = MsgAddressInt::with_standart(None, 0, [0x11; 32].into()).unwrap();
    let addr = MsgAddressInt::standard(0, [0x62; 32]);
    let max = (1u128 << 120) - 1;
    let mut rows = Vec::new();
    for version in [11u32, 12, 16] {
        let cfg = config(version, false, &addr);
        let none = rtos_block::ExtraCurrencyCollection::default;
        let reply = || data_with_refs(&[outbound_cell(&addr, &src, 0, none())]);
        let contracts = [
            ("accept", "ACCEPT".to_string(), Cell::default(), false, 1_000_000_000),
            ("bounce", "THROW 100".to_string(), Cell::default(), true, 1_000_000_000),
            ("send64", send_code(64), reply(), false, 1_000_000_000),
            ("zerovalue", "PUSHINT 0 NEWC STU 8 ENDC POPROOT".to_string(), Cell::default(), false, 0),
            ("maxvalue", "ACCEPT".to_string(), Cell::default(), false, max),
            ("stack", "DROP DROP DROP NEWC STVARUINT16 ENDC POPROOT".to_string(), Cell::default(), false, 1_000_000_000),
            ("incoming", "INCOMINGVALUE FIRST NEWC STVARUINT16 ENDC POPROOT".to_string(), Cell::default(), false, 1_000_000_000),
            (
                "inmsgparams",
                "PUSHCTR c7 FIRST PUSHINT 17 INDEXVAR PUSHINT 7 INDEXVAR NEWC STVARUINT16 ENDC POPROOT"
                    .to_string(),
                Cell::default(),
                false,
                1_000_000_000,
            ),
        ];
        for (tag, code, data, bounce, value) in contracts {
            let account = account_cell(&addr, &cfg, 10_000_000_000, none(), &code, data);
            for flags in [0u128, 1, 2, 3, 4, 1000, 1 << 100, max] {
                let m = Inbound { extra_flags: flags, bounce, ..Inbound::value(value) };
                run_cells(
                    &format!("a245-{tag}-f{flags}-v{version}"),
                    cfg.clone(),
                    account.clone(),
                    inbound_cell(&src, &addr, &m),
                    &addr,
                    &mut rows,
                );
            }
        }
    }
    assert_eq!(rows.len(), 192);
    check_reference_rows(
        &rows,
        include_str!("data/inbound-extra-flags.tsv"),
        "RTOS_INBOUND_EXTRA_FLAGS_EXPORT",
        &[],
    );
}

// Complete transactions whose credited balance (account balance plus message
// value) exceeds the serialized coins maximum by `over`. The reference keeps
// the wider balance through the transaction and checks it only when the result
// is serialized, so gas fees, outbound values or a bounce can bring it back
// into range. data/credit-overflow.tsv holds the reference roots.
#[test]
fn credit_overflow_complete_transactions() {
    let src = MsgAddressInt::with_standart(None, 0, [0x11; 32].into()).unwrap();
    let addr = MsgAddressInt::standard(0, [0x62; 32]);
    let max = (1u128 << 120) - 1;
    let value = 1u128 << 110;
    let none = rtos_block::ExtraCurrencyCollection::default;
    let mut rows = Vec::new();
    for version in [11u32, 16] {
        let cfg = config(version, false, &addr);
        let reply = |v| data_with_refs(&[outbound_cell(&addr, &src, v, none())]);
        let contracts = [
            ("accept", "ACCEPT".to_string(), Cell::default(), false),
            ("acceptb", "ACCEPT".to_string(), Cell::default(), true),
            ("throw", "THROW 100".to_string(), Cell::default(), false),
            ("bounce", "THROW 100".to_string(), Cell::default(), true),
            ("send128", send_code(128), reply(0), false),
            ("sendfixed", send_code(0), reply(1 << 119), false),
            ("send64", send_code(64), reply(0), false),
            (
                "reserve128",
                format!("PUSHINT {} PUSHINT 0 RAWRESERVE {}", 1u128 << 119, send_code(128)),
                reply(0),
                false,
            ),
            (
                "balance",
                "BALANCE FIRST NEWC STVARUINT32 ENDC POPROOT".to_string(),
                Cell::default(),
                false,
            ),
            (
                "balance16",
                "BALANCE FIRST NEWC STVARUINT16 ENDC POPROOT".to_string(),
                Cell::default(),
                false,
            ),
        ];
        for (tag, code, data, bounce) in contracts {
            for over in [0u128, 1, 1_000_000, 1_000_000_000, 1 << 100] {
                let account =
                    account_cell(&addr, &cfg, max + over - value, none(), &code, data.clone());
                let m = Inbound { bounce, ..Inbound::value(value) };
                run_cells(
                    &format!("a249-{tag}-o{over}-v{version}"),
                    cfg.clone(),
                    account,
                    inbound_cell(&src, &addr, &m),
                    &addr,
                    &mut rows,
                );
            }
        }
    }
    assert_eq!(rows.len(), 100);
    check_reference_rows(
        &rows,
        include_str!("data/credit-overflow.tsv"),
        "RTOS_CREDIT_OVERFLOW_EXPORT",
        &[],
    );
}

/// The basechain config with its gas prices changed by `change`.
fn gas_config(
    version: u32,
    addr: &MsgAddressInt,
    change: impl Fn(&mut rtos_block::GasLimitsPrices),
) -> BlockchainConfig {
    let mut raw = config(version, false, addr).raw_config().clone();
    let mut gas = raw.gas_prices(false).unwrap();
    change(&mut gas);
    raw.set_config(ConfigParamEnum::ConfigParam21(gas)).unwrap();
    BlockchainConfig::with_config(raw).unwrap()
}

// Complete transactions for the compute phase gas fields. The gas bought for a
// balance is not clamped: a gas limit above the VarUInteger 7 maximum
// (2^48 - 1) or an external gas credit above the VarUInteger 3 maximum (65535)
// leaves the transaction unserializable. The gas threshold is rounded up, so
// with a gas price that is not a multiple of 2^16 a value one below it buys
// less than the whole limit. data/gas-width.tsv holds the reference roots.
#[test]
fn gas_width_complete_transactions() {
    let src = MsgAddressInt::with_standart(None, 0, [0x11; 32].into()).unwrap();
    let addr = MsgAddressInt::standard(0, [0x62; 32]);
    let none = rtos_block::ExtraCurrencyCollection::default;
    let base_price = 400u64 << 16;
    let mut rows = Vec::new();
    for version in [11u32, 16] {
        // Internal messages: gas limit width and threshold rounding.
        for (tag, gas_limit, gas_price) in [
            ("gl48m1", (1u64 << 48) - 1, base_price),
            ("gl48", 1 << 48, base_price),
            ("gl50", 1 << 50, base_price),
            ("th", 1_000_000, base_price + 12345),
        ] {
            let cfg = gas_config(version, &addr, |g| {
                g.gas_limit = gas_limit;
                g.gas_price = gas_price;
            });
            let g = cfg.get_gas_config(false).clone();
            let (fp, fl, price) =
                (g.flat_gas_price as u128, g.flat_gas_limit as u128, gas_price as u128);
            let product = price * (gas_limit as u128 - fl);
            let floor = fp + (product >> 16);
            let ceil = fp + product.div_ceil(1 << 16);
            // The least value buying `gas` units below the threshold.
            let buys = |gas: u128| fp + ((gas - fl) * price).div_ceil(1 << 16);
            let values = [
                ("v1e9", 1_000_000_000u128),
                ("buy48m1", buys((1 << 48) - 1)),
                ("buy48", buys(1 << 48)),
                ("floor", floor),
                ("ceilm1", ceil - 1),
                ("ceil", ceil),
                ("v2e110", 1 << 110),
            ];
            for (contract, code) in [("accept", "ACCEPT"), ("noaccept", "NOP")] {
                for (acc_tag, balance) in [("rich", 1u128 << 100), ("poor", 1_000_000_000)] {
                    let account = account_cell(&addr, &cfg, balance, none(), code, Cell::default());
                    for (value_tag, value) in values {
                        run_cells(
                            &format!("a246-{tag}-{contract}-{acc_tag}-{value_tag}-v{version}"),
                            cfg.clone(),
                            account.clone(),
                            inbound_cell(&src, &addr, &Inbound::value(value)),
                            &addr,
                            &mut rows,
                        );
                    }
                }
            }
        }
        // External messages: gas credit width, including 2^32 (which a 32-bit
        // truncation would turn into no credit).
        for credit in [65535u64, 65536, 70000, 1 << 32] {
            let cfg = gas_config(version, &addr, |g| {
                g.gas_limit = (1 << 48) - 1;
                g.gas_price = base_price;
                g.gas_credit = credit;
            });
            for (contract, code) in [("accept", "ACCEPT"), ("noaccept", "NOP")] {
                for (acc_tag, balance) in [("rich", 1u128 << 100), ("poor", 1_000_000_000)] {
                    run_cells(
                        &format!("a246-credit{credit}-{contract}-{acc_tag}-v{version}"),
                        cfg.clone(),
                        account_cell(&addr, &cfg, balance, none(), code, Cell::default()),
                        external_message_cell(&addr, (0, 0)),
                        &addr,
                        &mut rows,
                    );
                }
            }
        }
    }
    assert_eq!(rows.len(), 2 * (4 * 2 * 2 * 7 + 4 * 2 * 2));
    check_reference_rows(&rows, include_str!("data/gas-width.tsv"), "RTOS_GAS_WIDTH_EXPORT", &[]);
}

// Complete transactions bouncing an inbound message with extra currencies.
// With the version-2 extra-currency rules (from version 10) the bounced
// message size leaves the extra-currency dictionary out from version 13, which
// changes its forwarding fee. data/bounce-size.tsv holds the reference roots.
#[test]
fn bounce_size_complete_transactions() {
    let src = MsgAddressInt::with_standart(None, 0, [0x11; 32].into()).unwrap();
    let addr = MsgAddressInt::standard(0, [0x62; 32]);
    let mut rows = Vec::new();
    let extras = |entries: &[(u32, u128)]| {
        let mut other = rtos_block::ExtraCurrencyCollection::default();
        for (key, value) in entries {
            other.set(key, &(*value).into()).unwrap();
        }
        other
    };
    let currencies = [
        ("none", extras(&[])),
        ("one", extras(&[(7, 100)])),
        ("three", extras(&[(7, 100), (9, 1 << 100), (1000, 5)])),
    ];
    for version in [10u32, 12, 13, 16] {
        let cfg = config(version, false, &addr);
        let account = account_cell(
            &addr,
            &cfg,
            10_000_000_000,
            Default::default(),
            "THROW 100",
            Cell::default(),
        );
        for (tag, other) in &currencies {
            for (flags_tag, extra_flags) in [("f0", 0u128), ("f1", 1)] {
                if extra_flags != 0 && version < 12 {
                    continue;
                }
                for value in [1_000_000_000u128, 1_000_000] {
                    let m = Inbound { other: other.clone(), extra_flags, bounce: true, value };
                    run_cells(
                        &format!("a248-{tag}-{flags_tag}-{value}-v{version}"),
                        cfg.clone(),
                        account.clone(),
                        inbound_cell(&src, &addr, &m),
                        &addr,
                        &mut rows,
                    );
                }
            }
        }
    }
    assert_eq!(rows.len(), 3 * 2 + 3 * 3 * 2 * 2);
    check_reference_rows(
        &rows,
        include_str!("data/bounce-size.tsv"),
        "RTOS_BOUNCE_SIZE_EXPORT",
        &[],
    );
}

/// A tick or tock transaction of a special masterchain account, exported in
/// the reference row format (no message; a "-tock-" id marks a tock).
fn run_tick_tock_cells(
    name: &str,
    config: BlockchainConfig,
    account_cell: Cell,
    address: &MsgAddressInt,
    tock: bool,
    rows: &mut Vec<String>,
) {
    let input = format!(
        "{name}\t200\t2000000001\t{}\t{}\t-\t-\t1\t{}\t{}",
        boc(config.raw_config().serialize().unwrap()),
        boc(account_cell.clone()),
        address.workchain_id(),
        hex_bytes(address.address().get_bytestring(0).as_ref())
    );
    let outcome =
        (|| -> rtos_block::Result<(String, String)> {
            let mut account = Account::construct_from_cell(account_cell)?;
            let old = account.hash()?;
            let params = ExecuteParams {
                block_unixtime: 200,
                block_lt: 2_000_000_000,
                last_tr_lt: 2_000_000_001,
                ..Default::default()
            };
            let kind = if tock {
                rtos_block::TransactionTickTock::Tock
            } else {
                rtos_block::TransactionTickTock::Tick
            };
            let mut tx = crate::TickTockTransactionExecutor::new(config, kind)
                .execute_with_params(None, &mut account, params)?;
            tx.write_state_update(&HashUpdate::with_hashes(old, account.hash()?))?;
            Ok((format!("{:x}", tx.hash()?), format!("{:x}", account.hash()?)))
        })();
    let (th, ah) = outcome.unwrap_or_else(|_| ("ERROR".to_string(), "ERROR".to_string()));
    rows.push(format!("{input}\t{th}\t{ah}"));
}

/// An extra-currency dictionary with key 7 holding `leaf` as its raw value.
fn extras_with_leaf(leaf: &BuilderData) -> rtos_block::ExtraCurrencyCollection {
    let mut dict = rtos_block::HashmapE::with_bit_len(32);
    dict.set_builder(SliceData::load_builder(7u32.write_to_new_cell().unwrap()).unwrap(), leaf)
        .unwrap();
    let mut b = BuilderData::new();
    rtos_block::HashmapType::write_hashmap_data(&dict, &mut b).unwrap();
    rtos_block::ExtraCurrencyCollection::construct_from(&mut SliceData::load_builder(b).unwrap())
        .unwrap()
}

/// Encodings of an extra-currency value: minimal, with a leading zero byte,
/// padded to 31 bytes, zero as length 0, zero as one byte, the maximum, and
/// the minimal one followed by a trailing bit in the leaf.
fn extra_value_encodings() -> Vec<(&'static str, rtos_block::ExtraCurrencyCollection)> {
    let leaf = |bytes: &[u8], trailing: bool| {
        let mut b = BuilderData::new();
        b.append_bits(bytes.len(), 5).unwrap();
        b.append_raw(bytes, bytes.len() * 8).unwrap();
        if trailing {
            b.append_bit_one().unwrap();
        }
        extras_with_leaf(&b)
    };
    let mut padded = vec![0u8; 31];
    padded[30] = 100;
    vec![
        ("min100", leaf(&[100], false)),
        ("lead100", leaf(&[0, 100], false)),
        ("len31v100", leaf(&padded, false)),
        ("len0", leaf(&[], false)),
        ("zero1", leaf(&[0], false)),
        ("max31", leaf(&[0xff; 31], false)),
        ("trail", leaf(&[100], true)),
    ]
}

/// The reference reasons a row of `position` may fail with: validation of
/// the account state, the inbound value at serialization, or (for a bounce)
/// packing that value into the bounced message; none for other positions.
fn extra_currency_error_reasons(position: &str) -> &'static [&'static str] {
    match position {
        "acconly" | "getextra" | "send128" | "tick" | "tock" => &["account-invalid"],
        "msgonly" | "send64" => &["serialize"],
        "bounce" => &["serialize", "other:-669"],
        _ => &[],
    }
}

// Complete transactions with an extra-currency value in each encoding at each
// position: the account balance (ordinary and tick/tock), the inbound value,
// a contract-built outbound value (modes 0, +2, +16) and a reserve currency.
// The account and inbound consumers require minimal positive amounts (no
// transaction otherwise); the action list check takes any encoding with
// exact leaves (result 34 and an invalid action list otherwise); the send
// consumer requires minimal positive amounts (result 34 with a valid action
// list, not skippable). Values read by the VM stay lenient.
// data/extra-currency-values.tsv holds the reference roots and reasons.
#[test]
fn extra_currency_values_complete_transactions() {
    let src = MsgAddressInt::with_standart(None, 0, [0x11; 32].into()).unwrap();
    let addr = MsgAddressInt::standard(0, [0x62; 32]);
    let mc_addr = MsgAddressInt::standard(-1, [0x63; 32]);
    let none = rtos_block::ExtraCurrencyCollection::default;
    let mut canonical = rtos_block::ExtraCurrencyCollection::default();
    canonical.set(&7u32, &1000u32.into()).unwrap();
    let mut rows = Vec::new();
    for version in [11u32, 12, 16] {
        let cfg = config(version, false, &addr);
        let mc_cfg = config(version, true, &mc_addr);
        for (enc, extras) in extra_value_encodings() {
            let reply = |other| data_with_refs(&[outbound_cell(&addr, &src, 0, other)]);
            let mut add = |position: &str, account: Cell, inbound: Inbound| {
                run_cells(
                    &format!("a244-{position}-{enc}-v{version}"),
                    cfg.clone(),
                    account,
                    inbound_cell(&src, &addr, &inbound),
                    &addr,
                    &mut rows,
                )
            };
            let plain = || Inbound::value(1_000_000_000);
            let with_extras = || Inbound { other: extras.clone(), ..plain() };
            let rich = |other, code: &str, data| {
                account_cell(&addr, &cfg, 10_000_000_000, other, code, data)
            };
            add("acconly", rich(extras.clone(), "ACCEPT", Cell::default()), plain());
            add("msgonly", rich(none(), "ACCEPT", Cell::default()), with_extras());
            add(
                "bounce",
                rich(none(), "THROW 100", Cell::default()),
                Inbound { bounce: true, ..with_extras() },
            );
            add("send64", rich(none(), &send_code(64), reply(none())), with_extras());
            add(
                "getextra",
                rich(
                    extras.clone(),
                    "PUSHINT 7 GETEXTRABALANCE NEWC STVARUINT32 ENDC POPROOT",
                    Cell::default(),
                ),
                plain(),
            );
            add("send128", rich(extras.clone(), &send_code(128), reply(none())), plain());
            for mode in [0u8, 2, 16] {
                let out = outbound_cell(&addr, &src, 1_000_000, extras.clone());
                add(
                    &format!("sendout{mode}"),
                    rich(canonical.clone(), &send_code(mode), data_with_refs(&[out])),
                    Inbound { bounce: true, ..plain() },
                );
            }
            let dict = data_with_refs(&[extras.root().cloned().unwrap()]);
            add(
                "reservex",
                rich(
                    canonical.clone(),
                    "PUSHINT 1000 PUSHROOT CTOS LDREF DROP PUSHINT 0 RAWRESERVEX",
                    dict,
                ),
                plain(),
            );
            for (position, tock) in [("tick", false), ("tock", true)] {
                let mut init = StateInit::default();
                init.set_code(rtos_assembler::compile_code_to_cell("NOP").unwrap());
                init.set_data(Cell::default());
                init.set_special(rtos_block::TickTock::with_values(true, true));
                let account = Account::active(
                    mc_addr.clone(),
                    CurrencyCollection {
                        coins: rtos_block::Coins::from(10_000_000_000u64),
                        other: extras.clone(),
                    },
                    0,
                    0,
                    init,
                    mc_cfg.size_limits_config().acc_state_cells_for_storage_dict,
                )
                .unwrap()
                .serialize()
                .unwrap();
                run_tick_tock_cells(
                    &format!("a244-{position}-{enc}-v{version}"),
                    mc_cfg.clone(),
                    account,
                    &mc_addr,
                    tock,
                    &mut rows,
                );
            }
        }
        // Mode 128 with zero-valued extras in the suggested message: the
        // value is validated before the whole balance replaces it.
        for (tag, out_extras) in [
            ("zero-one", &[(11111111u32, 50u32), (22222222, 0)][..]),
            ("zero-two", &[(11111111, 0), (22222222, 0), (33333333, 50)][..]),
        ] {
            let mut other = rtos_block::ExtraCurrencyCollection::default();
            for (key, value) in out_extras {
                other.set(key, &(*value).into()).unwrap();
            }
            let mut balance = rtos_block::ExtraCurrencyCollection::default();
            balance.set(&11111111u32, &100u32.into()).unwrap();
            balance.set(&33333333u32, &100u32.into()).unwrap();
            run_cells(
                &format!("a244-sendall-{tag}-v{version}"),
                cfg.clone(),
                account_cell(
                    &addr,
                    &cfg,
                    2_000_000_000,
                    balance,
                    &format!("ACCEPT {}", send_code(128)),
                    data_with_refs(&[outbound_cell(&addr, &src, 1_000_000_000, other)]),
                ),
                inbound_cell(&src, &addr, &Inbound::value(1_000_000_000)),
                &addr,
                &mut rows,
            );
        }
    }
    assert_eq!(rows.len(), 3 * (7 * 12 + 2));
    check_reference_rows(
        &rows,
        include_str!("data/extra-currency-values.tsv"),
        "RTOS_EXTRA_CURRENCY_EXPORT",
        &[],
    );
    if std::env::var_os("RTOS_EXTRA_CURRENCY_EXPORT").is_none() {
        // Every reference refusal is the validation of the position's consumer.
        for line in include_str!("data/extra-currency-values.tsv").lines().skip(1) {
            let f: Vec<_> = line.split('\t').collect();
            let position = f[0].split('-').nth(1).unwrap();
            if f[1] == "error" {
                assert!(extra_currency_error_reasons(position).contains(&f[3]), "{}", f[0]);
            }
        }
    }
}

// Complete transactions with gas configurations at the signed 64-bit
// boundaries of the reference arithmetic (ConfigParam 21 for basechain
// accounts, ConfigParam 20 for a special masterchain account): gas above the
// flat limit of 2^63 - 1, 2^63 and 2^63 + 1, the maximum gas limit, and the
// maximum gas price. Rows cover VM execution with and without ACCEPT, an
// external message (gas credit), a message to an account without code
// (compute skipped) and a special account. data/gas-extreme.tsv holds the
// reference roots.
#[test]
fn gas_extreme_complete_transactions() {
    let src = MsgAddressInt::with_standart(None, 0, [0x11; 32].into()).unwrap();
    let addr = MsgAddressInt::standard(0, [0x62; 32]);
    let mc_addr = MsgAddressInt::standard(-1, [0x63; 32]);
    let none = rtos_block::ExtraCurrencyCollection::default;
    let half = 1u64 << 63;
    let mut rows = Vec::new();
    for version in [11u32, 16] {
        let flat = config(version, false, &addr).raw_config().gas_prices(false).unwrap();
        let variants: [(&str, Box<dyn Fn(&mut rtos_block::GasLimitsPrices)>); 6] = [
            ("m1", Box::new(move |g| g.gas_limit = g.flat_gas_limit + (half - 1))),
            ("half", Box::new(move |g| g.gas_limit = g.flat_gas_limit + half)),
            ("p1", Box::new(move |g| g.gas_limit = g.flat_gas_limit + half + 1)),
            ("max", Box::new(|g| g.gas_limit = u64::MAX)),
            ("pricemax", Box::new(|g| g.gas_price = u64::MAX)),
            ("pricehalf", Box::new(move |g| g.gas_price = half)),
        ];
        assert!(flat.flat_gas_limit < half);
        for (tag, change) in &variants {
            let cfg = gas_config(version, &addr, |g| change(g));
            for (acc_tag, balance) in
                [("rich", 10_000_000_000u128), ("poor", 1_000_000), ("zero", 0)]
            {
                for (contract, code) in [("accept", "ACCEPT"), ("noaccept", "NOP")] {
                    run_cells(
                        &format!("a251-{tag}-{contract}-{acc_tag}-v{version}"),
                        cfg.clone(),
                        account_cell(&addr, &cfg, balance, none(), code, Cell::default()),
                        inbound_cell(&src, &addr, &Inbound::value(1_000_000_000)),
                        &addr,
                        &mut rows,
                    );
                }
                run_cells(
                    &format!("a251-{tag}-external-{acc_tag}-v{version}"),
                    cfg.clone(),
                    account_cell(&addr, &cfg, balance, none(), "ACCEPT", Cell::default()),
                    external_message_cell(&addr, (0, 0)),
                    &addr,
                    &mut rows,
                );
            }
            // No account: the compute phase is skipped.
            run_cells(
                &format!("a251-{tag}-nostate-v{version}"),
                cfg.clone(),
                Account::default().serialize().unwrap(),
                inbound_cell(&src, &addr, &Inbound::value(1_000_000_000)),
                &addr,
                &mut rows,
            );
        }
        // A special masterchain account buys its special gas limit (ConfigParam 20).
        for (tag, special_gas_limit) in [("specialhalf", half), ("specialmax", u64::MAX)] {
            let mut raw = config(version, true, &mc_addr).raw_config().clone();
            let mut gas = raw.gas_prices(true).unwrap();
            gas.special_gas_limit = special_gas_limit;
            raw.set_config(ConfigParamEnum::ConfigParam20(gas)).unwrap();
            let cfg = BlockchainConfig::with_config(raw).unwrap();
            for (contract, code) in [("accept", "ACCEPT"), ("noaccept", "NOP")] {
                let mut init = StateInit::default();
                init.set_code(rtos_assembler::compile_code_to_cell(code).unwrap());
                init.set_data(Cell::default());
                let account = Account::active(
                    mc_addr.clone(),
                    CurrencyCollection::with_coins(10_000_000_000u64),
                    0,
                    0,
                    init,
                    cfg.size_limits_config().acc_state_cells_for_storage_dict,
                )
                .unwrap()
                .serialize()
                .unwrap();
                run_cells_with(
                    &format!("a251-{tag}-{contract}-v{version}"),
                    cfg.clone(),
                    account,
                    inbound_cell(&src, &mc_addr, &Inbound::value(1_000_000_000)),
                    &mc_addr,
                    true,
                    &mut rows,
                );
            }
        }
    }
    assert_eq!(rows.len(), 2 * (6 * (3 * 3 + 1) + 2 * 2));
    check_reference_rows(
        &rows,
        include_str!("data/gas-extreme.tsv"),
        "RTOS_GAS_EXTREME_EXPORT",
        &[],
    );
}
