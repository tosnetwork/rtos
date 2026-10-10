// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use crate::{BlockchainConfig, ExecuteParams, OrdinaryTransactionExecutor, TransactionExecutor};
use rtos_block::{
    Account, AccountStorage, BuilderData, Cell, Coins, ConfigParam8, ConfigParamEnum,
    CurrencyCollection, GetRepresentationHash, HashUpdate, HashmapType, InternalMessageHeader,
    Message, MsgAddressInt, Serializable, SizeLimitsConfig, SliceData, StateInit, StorageInfo,
    TrComputePhase, TransactionDescr,
};
mod common;
use common::create_config;

#[test]
fn library_budget_complete_transactions() {
    let export = std::env::var_os("RTOS_LIBRARY_TRANSACTION_EXPORT");
    let mut rows = Vec::new();
    let boc = |c: Cell| {
        rtos_block::write_boc(&c).unwrap().iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    for source in ["account", "message", "global"] {
        for version in [14, 15, 16, 19] {
            for limit in [None, Some(0), Some(1), Some(2)] {
                for shape in ["single", "repeat", "distinct", "initial-library"] {
                    let name = format!("{source}-{shape}-v{version}-limit{limit:?}");
                    let a = rtos_assembler::compile_code_to_cell("PUSHINT 1").unwrap();
                    let b = rtos_assembler::compile_code_to_cell("PUSHINT 2").unwrap();
                    let program = if shape == "repeat" || shape == "distinct" {
                        "DROP LDREF LDREF ENDS CTOS DROP CTOS DROP PUSHINT 77 NEWC STU 8 ENDC POPROOT"
                    } else {
                        "DROP LDREF ENDS CTOS DROP PUSHINT 77 NEWC STU 8 ENDC POPROOT"
                    };
                    let code = rtos_assembler::compile_code_to_cell(program).unwrap();
                    let mut config = create_config("real_boc/config.boc").unwrap();
                    let mut p8 =
                        ConfigParam8 { global_version: config.get_global_version().unwrap() };
                    p8.global_version.version = version;
                    config.set_config(ConfigParamEnum::ConfigParam8(p8)).unwrap();
                    config
                        .set_config(ConfigParamEnum::ConfigParam43(SizeLimitsConfig {
                            max_transaction_library_loads: limit,
                            ..Default::default()
                        }))
                        .unwrap();
                    let config = BlockchainConfig::with_config(config).unwrap();
                    let address = MsgAddressInt::with_standart(None, 0, [0x5a; 32].into()).unwrap();
                    let mut init = StateInit::default();
                    init.set_code(if shape == "initial-library" {
                        code.as_library_cell()
                    } else {
                        code.clone()
                    });
                    init.set_data(Cell::default());
                    let mut library_init = StateInit::default();
                    library_init.set_library_code(a.clone(), false).unwrap();
                    library_init.set_library_code(b.clone(), false).unwrap();
                    if shape == "initial-library" {
                        library_init.set_library_code(code, false).unwrap();
                    }
                    if source == "account" {
                        init.library = library_init.library.clone();
                    }
                    let global_libs = if source == "global" {
                        library_init.library.clone().inner()
                    } else {
                        rtos_block::HashmapE::with_bit_len(256)
                    };
                    let global_boc =
                        global_libs.data().cloned().map(&boc).unwrap_or_else(|| "-".into());
                    let mut account = Account::with_storage(
                        &address,
                        &StorageInfo::with_values(100, Some(Coins::from(7u64))),
                        &AccountStorage::active(
                            0,
                            CurrencyCollection::with_coins(10_000_000_000u64),
                            init,
                        ),
                    );
                    account
                        .calc_storage_stat_dict(
                            config.size_limits_config().acc_state_cells_for_storage_dict,
                        )
                        .unwrap();
                    let mut header = InternalMessageHeader::with_addresses(
                        MsgAddressInt::with_standart(None, 0, [0x11; 32].into()).unwrap(),
                        address,
                        CurrencyCollection::with_coins(1_000_000_000u64),
                    );
                    header.bounce = false;
                    header.created_lt = 1000;
                    let mut message = Message::with_int_header(header);
                    let mut body = BuilderData::new();
                    body.checked_append_reference(a.as_library_cell()).unwrap();
                    if shape == "repeat" || shape == "distinct" {
                        body.checked_append_reference(if shape == "repeat" {
                            a.as_library_cell()
                        } else {
                            b.as_library_cell()
                        })
                        .unwrap();
                    }
                    message.set_body(SliceData::load_builder(body).unwrap());
                    if source == "message" {
                        message.set_state_init(library_init);
                    }
                    let input = format!(
                        "{name}\t200\t2000000001\t{}\t{}\t{}\t{global_boc}",
                        boc(config.raw_config().serialize().unwrap()),
                        boc(account.serialize().unwrap()),
                        boc(message.serialize().unwrap())
                    );
                    let old_hash = account.hash().unwrap();
                    let params = ExecuteParams {
                        block_unixtime: 200,
                        block_lt: 2_000_000_000,
                        last_tr_lt: 2_000_000_001,
                        state_libs: global_libs,
                        ..Default::default()
                    };
                    let mut tx = OrdinaryTransactionExecutor::new(config)
                        .execute_with_params(
                            Some(message.serialize().unwrap()),
                            &mut account,
                            params,
                        )
                        .unwrap();
                    let TransactionDescr::Ordinary(desc) = tx.read_description().unwrap() else {
                        panic!("ordinary expected")
                    };
                    let TrComputePhase::Vm(compute) = desc.compute_ph else {
                        panic!("VM expected")
                    };
                    let needed = if shape == "distinct" { 2 } else { 1 };
                    let success =
                        (source == "global" || version < 15) && limit.is_none_or(|n| n >= needed);
                    assert_eq!(compute.exit_code, if success { 0 } else { 9 }, "{name}");
                    assert_eq!(compute.success, success, "{name}");
                    assert_eq!(desc.aborted, !success, "{name}");
                    tx.write_state_update(&HashUpdate::with_hashes(
                        old_hash,
                        account.hash().unwrap(),
                    ))
                    .unwrap();
                    let tx_hash = format!("{:x}", tx.hash().unwrap());
                    let account_hash = format!("{:x}", account.hash().unwrap());
                    if export.is_none() {
                        let expected = include_str!("data/library-budget-transactions.tsv")
                            .lines()
                            .map(|l| l.split('\t').collect::<Vec<_>>())
                            .find(|f| f[0] == name)
                            .expect("C++ transaction fixture");
                        assert_eq!(tx_hash, expected[1], "{name} transaction root");
                        assert_eq!(account_hash, expected[2], "{name} account root");
                    }
                    rows.push(format!("{input}\t{tx_hash}\t{account_hash}"));
                }
            }
        }
    }
    if let Some(path) = export {
        std::fs::write(path, rows.join("\n") + "\n").unwrap();
    } else {
        assert_eq!(
            include_str!("data/library-budget-transactions.tsv").lines().count(),
            rows.len()
        );
    }
}
