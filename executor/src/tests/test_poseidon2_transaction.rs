// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use crate::{BlockchainConfig, ExecuteParams, OrdinaryTransactionExecutor, TransactionExecutor};
use rtos_block::{
    Account, BuilderData, Cell, ConfigParam31, ConfigParam8, ConfigParamEnum, CurrencyCollection,
    ExternalInboundMessageHeader, GetRepresentationHash, HashUpdate, InternalMessageHeader,
    Message, MsgAddressInt, Serializable, SliceData, StateInit,
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
    msg: Cell,
    special: bool,
    rows: &mut Vec<String>,
) -> (rtos_block::Transaction, Account) {
    let decoded =
        <Message as rtos_block::Deserializable>::construct_from_cell(msg.clone()).unwrap();
    let address = decoded.dst().unwrap();
    let input = format!(
        "{name}\t200\t2000000001\t{}\t{}\t{}\t-\t{}\t{}\t{}",
        boc(config.raw_config().serialize().unwrap()),
        boc(account.serialize().unwrap()),
        boc(msg.clone()),
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
        .execute_with_params(Some(msg), &mut account, params)
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
    if std::env::var_os("RTOS_POSEIDON_TRANSACTION_EXPORT").is_none() {
        let expected = include_str!("data/poseidon2-transactions.tsv")
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

fn path(depth: usize) -> Cell {
    let mut next = None;
    for node in (0..depth * 2).rev() {
        let mut b = BuilderData::new();
        for lane in 0..3 {
            let mut bytes = [0; 32];
            bytes[30..].copy_from_slice(&((node * 3 + lane + 1) as u16).to_be_bytes());
            b.append_raw(&bytes, 256).unwrap();
        }
        if let Some(child) = next {
            b.checked_append_reference(child).unwrap();
        }
        next = Some(b.into_cell().unwrap());
    }
    next.unwrap()
}
#[test]
fn poseidon2_complete_transactions() {
    let mut rows = Vec::new();
    let mut programs=vec![
        ("perm".to_string(),"ACCEPT PUSHINT 0 PUSHINT 1 PUSHINT 2 PUSHINT 3 PUSHINT 4 PUSHINT 5 PUSHINT 6 PUSHINT 7 POSEIDON2_PERM8 DROP DROP DROP DROP DROP DROP DROP NEWC STU 256 ENDC POPROOT".to_string(),Cell::default()),
        ("hash".into(),"ACCEPT PUSHINT 0 PUSHINT 1 PUSHINT 2 PUSHINT 3 PUSHINT 4 PUSHINT 5 PUSHINT 6 PUSHINT 7 POSEIDON2_HASH7 NEWC STU 256 ENDC POPROOT".into(),Cell::default()),
        ("nan".into(),"ACCEPT PUSHINT 0 PUSHINT 1 PUSHINT 2 PUSHINT 3 PUSHINT 4 PUSHINT 5 PUSHINT 6 PUSHNAN POSEIDON2_HASH7 NEWC STU 256 ENDC POPROOT".into(),Cell::default()),
    ];
    for depth in [1, 2, 12, 64] {
        for invalid in [false, true] {
            programs.push((format!("path{depth}-invalid{invalid}"),format!("ACCEPT DROP LDREF ENDS PUSHINT 17 PUSHINT 29 ROT PUSHINT 0 PUSHINT {depth} POSEIDON2_PATH7 NEWC STU 256 ENDC POPROOT"),path(if invalid {depth+1} else {depth})));
        }
    }
    for version in [15, 16, 17, 19] {
        for (label, wc, special) in
            [("base", 0, false), ("master", -1, false), ("special", -1, true)]
        {
            for external in [false, true] {
                for (case, source, path) in &programs {
                    let name = format!("poseidon-{case}-v{version}-{label}-external{external}");
                    let address =
                        MsgAddressInt::with_standart(None, wc, [0x5e; 32].into()).unwrap();
                    let cfg = config(version, special, &address);
                    let mut state = StateInit::default();
                    state.set_code(rtos_assembler::compile_code_to_cell(source).unwrap());
                    state.set_data(Cell::default());
                    let account = Account::active(
                        address.clone(),
                        CurrencyCollection::with_coins(10_000_000_000u64),
                        0,
                        if special { 0 } else { 100 },
                        state,
                        cfg.size_limits_config().acc_state_cells_for_storage_dict,
                    )
                    .unwrap();
                    let mut msg = if external {
                        Message::with_ext_in_header(ExternalInboundMessageHeader {
                            dst: address.clone(),
                            ..Default::default()
                        })
                    } else {
                        message(address, false)
                    };
                    let mut body = BuilderData::new();
                    body.checked_append_reference(path.clone()).unwrap();
                    msg.set_body(SliceData::load_builder(body).unwrap());
                    run(&name, cfg, account, msg.serialize().unwrap(), special, &mut rows);
                }
            }
        }
    }
    assert_eq!(rows.len(), 264);
    if let Ok(path) = std::env::var("RTOS_POSEIDON_TRANSACTION_EXPORT") {
        std::fs::write(path, rows.join("\n") + "\n").unwrap();
    }
}
