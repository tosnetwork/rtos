// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::*;
use pretty_assertions::assert_eq;
use rtos_block::{Account, ConfigParam8, ConfigParamEnum, HashUpdate, HashmapType, Message};
fn boc(cell: Cell) -> String {
    rtos_block::write_boc(&cell).unwrap().iter().map(|b| format!("{b:02x}")).collect()
}
fn run(
    name: &str,
    config: BlockchainConfig,
    mut account: Account,
    msg: Message,
    libs: HashmapE,
    rows: &mut Vec<String>,
) -> (Transaction, Account) {
    let input = format!(
        "{name}\t{BLOCK_UT}\t{}\t{}\t{}\t{}\t{}\t0\t-1\t{}",
        BLOCK_LT + 1,
        boc(config.raw_config().serialize().unwrap()),
        boc(account.serialize().unwrap()),
        boc(msg.serialize().unwrap()),
        libs.data().map_or_else(|| "-".into(), |c| boc(c.clone())),
        "11".repeat(32)
    );
    let before = account.clone();
    let old = account.hash().unwrap();
    let version = config.global_version();
    let limit = config.size_limits_config().acc_state_cells_for_storage_dict;
    let mut params = execute_params(BLOCK_LT + 1);
    params.state_libs = libs;
    let mut tx = OrdinaryTransactionExecutor::new(config)
        .execute_with_params(Some(msg.serialize().unwrap()), &mut account, params)
        .unwrap();
    account.calc_storage_stat_dict(limit).unwrap();
    if version < 11 {
        account.del_storage_stat();
    }
    tx.write_state_update(&HashUpdate::with_hashes(old, account.hash().unwrap())).unwrap();
    check_account_and_transaction_balances(&before, &account, &msg, Some(&tx));
    let th = tx.hash().unwrap().to_hex_string();
    let ah = account.hash().unwrap().to_hex_string();
    let descr = get_tr_descr(&tx);
    println!("IGNORED_CASE {name} version={version} vm={:?} action={:?} storage={:?} out={} libs={} balance={:?}",descr.compute_ph,descr.action,descr.storage_ph,tx.out_msgs.len().unwrap(),account.libraries().len().unwrap(),account.balance());
    if std::env::var_os("RTOS_IGNORED_EXECUTOR_EXPORT").is_none() {
        let expected = include_str!("data/ignored-executor.tsv")
            .lines()
            .find(|l| l.split('\t').next() == Some(name))
            .expect("fixed reference case");
        assert_eq!(
            format!("{name}\t{th}\t{ah}"),
            expected,
            "{name} complete transaction/account roots"
        );
    }
    rows.push(format!("{input}\t{th}\t{ah}"));
    (tx, account)
}
fn cfg(version: u32) -> BlockchainConfig {
    let mut raw = BLOCKCHAIN_CONFIG.raw_config().clone();
    let mut v = raw.get_global_version().unwrap();
    v.version = version;
    raw.set_config(ConfigParamEnum::ConfigParam8(ConfigParam8 { global_version: v })).unwrap();
    BlockchainConfig::with_config(raw).unwrap()
}
fn libraries(rows: &mut Vec<String>) {
    let code = compile_code_to_cell("ACCEPT PUSHCTR C4 HASHCU PUSHINT 1 CHANGELIB").unwrap();
    let mut versions = vec![BLOCKCHAIN_CONFIG.global_version(), 4, 13, 14, 15, 17];
    versions.sort();
    versions.dedup();
    for version in versions {
        for scope in ["global-only", "missing", "local-public"] {
            let mut libs = HashmapE::with_bit_len(256);
            if scope == "global-only" {
                libs.setref(LIBRARY_CELL.repr_hash().into(), LIBRARY_CELL.clone()).unwrap();
            }
            let mut account = create_test_account(
                1_000_000_000,
                SENDER_ACCOUNT.clone(),
                code.clone(),
                LIBRARY_CELL.clone(),
            );
            if scope == "local-public" {
                account
                    .library_mut()
                    .unwrap()
                    .set(
                        &LIBRARY_CELL.repr_hash().clone(),
                        &SimpleLib::new(LIBRARY_CELL.clone(), true),
                    )
                    .unwrap();
                account.calc_storage_stat_dict(DICT_HASH_MIN_CELLS).unwrap();
            }
            let msg = create_int_msg(
                THIRD_ACCOUNT.clone(),
                SENDER_ACCOUNT.clone(),
                20_000_000,
                false,
                BLOCK_LT - 2,
            );
            let (tx, account) =
                run(&format!("library-{version}-{scope}"), cfg(version), account, msg, libs, rows);
            let descr = get_tr_descr(&tx);
            assert!(matches!(descr.compute_ph,TrComputePhase::Vm(ref vm) if vm.exit_code==0));
            assert_eq!(
                descr.action.unwrap().result_code,
                if version >= 15 {
                    46
                } else if scope == "local-public" {
                    0
                } else {
                    41
                }
            );
            assert_eq!(account.libraries().len().unwrap(), usize::from(scope == "local-public"));
            if version < 15 && scope == "local-public" {
                let (_, mut value) =
                    account.libraries().find_min_max_raw(true, false).unwrap().unwrap();
                assert!(!SimpleLib::construct_from(&mut value).unwrap().is_public_library());
            }
        }
    }
}
fn storage(rows: &mut Vec<String>) {
    for (balance, due, bounce) in [
        (200_000_000, 0, false),
        (200_000_000, 0, true),
        (141782075, 0, false),
        (141782075, 0, true),
        (60000000, 1000, false),
        (60000000, 1000, true),
    ] {
        let code =
            compile_code_to_cell("ACCEPT STORAGEFEES PUSHINT 158514102 CMP THROWIFNOT 62").unwrap();
        let data = create_int_msg(
            SENDER_ACCOUNT.clone(),
            SENDER_ACCOUNT.clone(),
            10_000_000,
            false,
            BLOCK_LT - 2,
        )
        .serialize()
        .unwrap();
        let mut account = create_test_account(balance, SENDER_ACCOUNT.clone(), code, data);
        account.set_due_payment(Some(Coins::from(due)));
        let msg = create_int_msg(
            SENDER_ACCOUNT.clone(),
            SENDER_ACCOUNT.clone(),
            200_000_000,
            bounce,
            BLOCK_LT - 2,
        );
        let (tx, _) = run(
            &format!("storage-{balance}-{due}-{bounce}"),
            BLOCKCHAIN_CONFIG.clone(),
            account,
            msg,
            HashmapE::with_bit_len(256),
            rows,
        );
        let descr = get_tr_descr(&tx);
        let storage = descr.storage_ph.unwrap();
        let collected = storage.storage_fees_collected.as_u128();
        assert!(
            matches!(descr.compute_ph,TrComputePhase::Vm(ref vm) if vm.exit_code==if collected==158514102 {62}else{0})
        );
        assert_eq!(
            collected + storage.storage_fees_due.unwrap_or_default().as_u128(),
            158514102 + u128::from(due)
        );
        assert_eq!(storage.storage_fees_due.is_some(), bounce && balance < 158514102);
    }
}
fn modes(rows: &mut Vec<String>) {
    for (name, balance, income, code) in [
        (
            "mode128-0",
            310000000,
            1230000000,
            r#"
        ACCEPT
        PUSHROOT
        CTOS
        LDREF
        PLDREF
        PUSHINT 128
        SENDRAWMSG
        PUSHINT 1
        SENDRAWMSG
    "#,
        ),
        (
            "mode128-1",
            310000000,
            44404882 + 68259633 - 1,
            r#"
        PUSHINT 10
        PUSHINT 0
        RAWRESERVE

        ACCEPT
        PUSHROOT
        CTOS
        LDREF
        PLDREF
        PUSHINT 128
        SENDRAWMSG
        PUSHINT 1
        SENDRAWMSG
    "#,
        ),
        (
            "mode128-2",
            310000000,
            44404882 + 68259633 - 1,
            r#"
        ACCEPT
        PUSHROOT
        CTOS
        LDREF
        PLDREF
        PUSHINT 130
        SENDRAWMSG
        PUSHINT 1
        SENDRAWMSG
    "#,
        ),
        (
            "mode128-3",
            310000000,
            1230000000,
            r#"
        ACCEPT
        PUSHROOT
        CTOS
        LDREF
        PLDREF
        PUSHINT 128
        SENDRAWMSG
        PUSHINT 128
        SENDRAWMSG
    "#,
        ),
        (
            "mode128-4",
            310000000,
            1230000000,
            r#"
        ACCEPT
        PUSHROOT
        CTOS
        LDREF
        PLDREF
        PUSHINT 128
        SENDRAWMSG
        PUSHINT 130
        SENDRAWMSG
    "#,
        ),
        (
            "mode128-5",
            310000000,
            1230000000,
            r#"
        ACCEPT
        PUSHROOT
        CTOS
        LDREF
        PLDREF
        PUSHINT 128
        SENDRAWMSG
        PUSHINT 1000
        PUSHINT 0
        RAWRESERVE
    "#,
        ),
        (
            "mode128-6",
            310000000,
            1230000000,
            r#"
        ACCEPT
        PUSHROOT
        CTOS
        LDREF
        PLDREF
        PUSHINT 160
        SENDRAWMSG
        PUSHINT 0
        SENDRAWMSG
    "#,
        ),
        (
            "mode128-7",
            310000000,
            1230000000,
            r#"
        ACCEPT
        PUSHROOT
        CTOS
        LDREF
        PLDREF
        PUSHINT 32
        SENDRAWMSG
        PUSHINT 0
        SENDRAWMSG
    "#,
        ),
        (
            "mode128-8",
            3100000000,
            444048082,
            r#"
        PUSHINT 10
        PUSHINT 0
        RAWRESERVE

        ACCEPT
        PUSHROOT
        CTOS
        LDREF
        PLDREF
        PUSHINT 160
        SENDRAWMSG
        PUSHINT 1
        SENDRAWMSG
    "#,
        ),
        (
            "mode128-9",
            3100000000,
            444048082,
            r#"
        ACCEPT
        PUSHROOT
        CTOS
        LDREF
        PLDREF
        PUSHINT 160
        SENDRAWMSG
        PUSHINT 160
        SENDRAWMSG
    "#,
        ),
    ] {
        let account = create_test_account(
            balance,
            SENDER_ACCOUNT.clone(),
            compile_code_to_cell(code).unwrap(),
            create_two_messages_data(),
        );
        let msg = create_int_msg(
            THIRD_ACCOUNT.clone(),
            SENDER_ACCOUNT.clone(),
            income,
            false,
            BLOCK_LT - 2,
        );
        let (tx, account) =
            run(name, BLOCKCHAIN_CONFIG.clone(), account, msg, HashmapE::with_bit_len(256), rows);
        let index: usize = name.rsplit('-').next().unwrap().parse().unwrap();
        let descr = get_tr_descr(&tx);
        assert!(matches!(descr.compute_ph,TrComputePhase::Vm(ref vm) if vm.exit_code==0));
        assert_eq!(
            descr.action.unwrap().result_code,
            if index == 4 || index == 7 { 0 } else { 37 }
        );
        assert_eq!(
            tx.out_msgs.len().unwrap(),
            if index == 4 {
                1
            } else if index == 7 {
                2
            } else {
                0
            }
        );
        assert!(!account.is_none());
    }
}
fn flags(rows: &mut Vec<String>) {
    // Empty balance alone does not activate deletion: mode 32 still needs 128.
    for version in [4, 12, 13, 14, 15, 17] {
        let out = create_int_msg(
            SENDER_ACCOUNT.clone(),
            THIRD_ACCOUNT.clone(),
            1_013_910_000,
            false,
            BLOCK_LT + 1,
        );
        let code = compile_code_to_cell("ACCEPT PUSHCTR C4 PUSHINT 32 SENDRAWMSG").unwrap();
        let mut account = create_test_account(
            1_000_000_000,
            SENDER_ACCOUNT.clone(),
            code,
            out.serialize().unwrap(),
        );
        account.set_last_paid(BLOCK_UT);
        let msg = create_int_msg(
            THIRD_ACCOUNT.clone(),
            SENDER_ACCOUNT.clone(),
            20_000_000,
            false,
            BLOCK_LT - 2,
        );
        let (tx, account) = run(
            &format!("mode32-empty-{version}"),
            cfg(version),
            account,
            msg,
            HashmapE::with_bit_len(256),
            rows,
        );
        assert_eq!(tx.gas_used().unwrap(), 609);
        assert_eq!(tx.out_msgs.len().unwrap(), 1);
        assert!(!account.is_none());
        assert!(account.balance().unwrap().is_zero().unwrap());
    }

    for version in [4, 12, 13, 14, 15, 17] {
        for external in [false, true] {
            for mode in
                [0, 1, 2, 3, 16, 18, 32, 33, 34, 35, 48, 64, 80, 96, 128, 144, 160, 176, 192, 224]
            {
                let out = if external {
                    Message::with_ext_out_header(rtos_block::ExtOutMessageHeader::with_addresses(
                        MsgAddressInt::with_standart(None, -1, SENDER_ACCOUNT.clone()).unwrap(),
                        Default::default(),
                    ))
                } else {
                    create_int_msg(
                        SENDER_ACCOUNT.clone(),
                        THIRD_ACCOUNT.clone(),
                        50_000_000,
                        false,
                        BLOCK_LT + 1,
                    )
                };
                let code =
                    compile_code_to_cell(&format!("ACCEPT PUSHCTR C4 PUSHINT {mode} SENDRAWMSG"))
                        .unwrap();
                let account = create_test_account(
                    1_000_000_000,
                    SENDER_ACCOUNT.clone(),
                    code,
                    out.serialize().unwrap(),
                );
                let msg = create_int_msg(
                    THIRD_ACCOUNT.clone(),
                    SENDER_ACCOUNT.clone(),
                    20_000_000,
                    false,
                    BLOCK_LT - 2,
                );
                let (tx, account) = run(
                    &format!("flags-{version}-{external}-{mode}"),
                    cfg(version),
                    account,
                    msg,
                    HashmapE::with_bit_len(256),
                    rows,
                );
                let rejected = if external { mode & !16 > 3 } else { mode & 192 == 192 };
                let descr = get_tr_descr(&tx);
                assert_eq!(descr.action.unwrap().result_code, if rejected { 34 } else { 0 });
                assert_eq!(tx.out_msgs.len().unwrap(), usize::from(!rejected));
                assert_eq!(account.is_none(), !external && mode & !16 == 160);
            }
        }
    }
}
#[test]
fn ignored_reference_matrix() {
    let mut rows = Vec::new();
    libraries(&mut rows);
    storage(&mut rows);
    modes(&mut rows);
    flags(&mut rows);
    if let Ok(path) = std::env::var("RTOS_IGNORED_EXECUTOR_EXPORT") {
        std::fs::write(path, rows.join("\n") + "\n").unwrap();
    }
}

pub(crate) fn check_libraries() {
    libraries(&mut Vec::new());
}
pub(crate) fn check_storage() {
    storage(&mut Vec::new());
}
pub(crate) fn check_modes() {
    modes(&mut Vec::new());
}
