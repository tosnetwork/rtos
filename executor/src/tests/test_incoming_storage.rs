// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use crate::{BlockchainConfig, ExecuteParams, OrdinaryTransactionExecutor, TransactionExecutor};
use rtos_block::{
    Account, BuilderData, Cell, ConfigParam31, ConfigParam8, ConfigParamEnum, CurrencyCollection,
    ExternalInboundMessageHeader, GetRepresentationHash, HashUpdate, IBitstring,
    InternalMessageHeader, Message, MsgAddressInt, Serializable, SliceData, StateInit,
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
    if std::env::var_os("RTOS_INCOMING_STORAGE_EXPORT").is_none() {
        let expected = include_str!("data/incoming-storage.tsv")
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
fn incoming_storage_matches_cpp_transactions() {
    let mut rows = Vec::new();
    for version in [14, 16, 17, 18, 19] {
        for (kind, wc, special) in
            [("base", 0, false), ("master", -1, false), ("special", -1, true)]
        {
            let address = MsgAddressInt::with_standart(None, wc, [0x5a; 32].into()).unwrap();
            for external in [false, true] {
                for body_shape in ["empty", "bits", "chain", "shared"] {
                    for init_present in [false, true] {
                        for body_ref in [false, true] {
                            for (probe, source) in [
                                ("length", "ACCEPT PUSHCTR c7 FIRST TLEN NEWC STU 8 ENDC POPROOT"),
                                ("null", "ACCEPT PUSHCTR c7 FIRST PUSHINT 18 INDEXVAR ISNULL NEWC STI 8 ENDC POPROOT"),
                                ("fields", "ACCEPT PUSHCTR c7 FIRST PUSHINT 18 INDEXVAR UNTUPLE 4 NEWC STU 64 STU 64 STU 256 STU 8 ENDC POPROOT"),
                            ] {
                                let mut state = StateInit::default();
                                state.set_code(rtos_assembler::compile_code_to_cell(source).unwrap());
                                state.set_data(Cell::default());
                                let address = if init_present { MsgAddressInt::with_standart(None,wc,state.hash().unwrap().into()).unwrap() } else { address.clone() };
                                let cfg = config(version, special, &address);
                                let account = Account::active(address.clone(), CurrencyCollection::with_coins(10_000_000_000u64), 0, if special {0} else {100}, state.clone(), cfg.size_limits_config().acc_state_cells_for_storage_dict).unwrap();
                                let mut msg = if external {
                                    Message::with_ext_in_header(ExternalInboundMessageHeader { dst: address.clone(), ..Default::default() })
                                } else { message(address.clone(), false) };
                                let mut body = BuilderData::new();
                                if body_shape != "empty" { body.append_u32(0xdeadbeef).unwrap(); }
                                let mut leaf = BuilderData::new();
                                leaf.append_u8(77).unwrap();
                                let leaf = leaf.into_cell().unwrap();
                                if body_shape == "chain" || body_shape == "shared" { body.checked_append_reference(leaf.clone()).unwrap(); }
                                if body_shape == "shared" {
                                    body.checked_append_reference(leaf.clone()).unwrap();
                                    let mut branch = BuilderData::new();
                                    branch.append_bit_one().unwrap();
                                    branch.checked_append_reference(leaf).unwrap();
                                    body.checked_append_reference(branch.into_cell().unwrap()).unwrap();
                                }
                                msg.set_body(SliceData::load_builder(body).unwrap());
                                if init_present { msg.set_state_init(state); }
                                let (builder, _, _) = msg.serialize_with_params(Some(body_ref), Some(true)).unwrap();
                                let cell = builder.into_cell().unwrap();
                                let name = format!("incoming-v{version}-{kind}-external{external}-{body_shape}-init{init_present}-ref{body_ref}-{probe}");
                                let (tx, account) = run(&name,cfg,account,cell,special,&mut rows);
                                let description = tx.read_description().unwrap();
                                let rtos_block::TransactionDescr::Ordinary(desc) = description else { panic!("ordinary"); };
                                let success = probe == "length" || (version >= 16 && (probe == "null" || (external && !special)));
                                let rtos_block::TrComputePhase::Vm(compute) = desc.compute_ph else { panic!("compute"); };
                                assert_eq!(compute.success,success,"{name}");
                                if probe == "length" {
                                    let data = account.get_data().unwrap();
                                    assert_eq!(SliceData::load_cell(data).unwrap().get_next_byte().unwrap(), if version>=16 {19} else {18},"{name}");
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    assert_eq!(rows.len(), 1440);
    if let Ok(path) = std::env::var("RTOS_INCOMING_STORAGE_EXPORT") {
        std::fs::write(path, rows.join("\n") + "\n").unwrap();
    }
}
