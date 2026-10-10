// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
// Historical action modes use fixed independent full transaction/account roots.
use crate::{BlockchainConfig, OrdinaryTransactionExecutor, TransactionExecutor};
use rtos_assembler::compile_code_to_cell;
use rtos_block::{
    Account, AddSub, BuilderData, Cell, Coins, ConfigParam8, ConfigParamEnum, CurrencyCollection,
    ExtOutMessageHeader, GetRepresentationHash, HashUpdate, IBitstring, Message, MsgAddressInt,
    Serializable, SliceData, StateInit, StorageUsageCalc, TrBouncePhase, TrComputePhase,
    Transaction,
};
use std::collections::BTreeMap;
mod common;
use common::*;

fn boc(cell: Cell) -> String {
    rtos_block::write_boc(&cell).unwrap().iter().map(|b| format!("{b:02x}")).collect()
}
fn config(version: u32) -> BlockchainConfig {
    let mut raw = BLOCKCHAIN_CONFIG.raw_config().clone();
    let mut global_version = raw.get_global_version().unwrap();
    global_version.version = version;
    raw.set_config(ConfigParamEnum::ConfigParam8(ConfigParam8 { global_version })).unwrap();
    BlockchainConfig::with_config(raw).unwrap()
}
fn outgoing(kind: &str) -> Cell {
    let mut msg = if kind == "external" {
        Message::with_ext_out_header(ExtOutMessageHeader::with_addresses(
            MsgAddressInt::with_standart(None, -1, SENDER_ACCOUNT.clone()).unwrap(),
            Default::default(),
        ))
    } else if kind == "inbound-external" {
        create_test_external_msg()
    } else {
        create_int_msg(
            SENDER_ACCOUNT.clone(),
            THIRD_ACCOUNT.clone(),
            50_000_000u64,
            false,
            BLOCK_LT + 1,
        )
    };
    match kind {
        "malformed" => return Cell::default(),
        "source" | "source-flags" => {
            msg.set_src_address(
                MsgAddressInt::with_standart(None, -1, THIRD_ACCOUNT.clone()).unwrap(),
            );
        }
        "libraries" | "invalid-libraries" => {
            let mut init = StateInit::default();
            init.set_library_code(compile_code_to_cell("NOP").unwrap(), true).unwrap();
            if kind == "invalid-libraries" {
                init.set_library(Cell::default());
            }
            msg.set_state_init(init);
        }
        _ => {}
    }
    if kind.starts_with("library-") {
        let count = if kind.contains("513") {
            513
        } else if kind.contains("512") {
            512
        } else if kind.contains("fork") || kind == "library-two" {
            2
        } else {
            1
        };
        let mut init = StateInit::default();
        for index in 0u32..count {
            let code = BuilderData::with_raw(index.to_be_bytes().to_vec(), 32)
                .unwrap()
                .into_cell()
                .unwrap();
            init.set_library_code(code, true).unwrap();
        }
        if kind.ends_with("bits") || kind.ends_with("refs") {
            let root = init.libraries().root().unwrap();
            assert_eq!(root.references_count(), if kind.contains("fork") { 2 } else { 1 });
            let mut broken = SliceData::load_cell(root.clone()).unwrap().as_builder().unwrap();
            if kind.ends_with("bits") {
                broken.append_bit_zero().unwrap();
            } else {
                broken.checked_append_reference(Cell::default()).unwrap();
            }
            init.set_library(broken.into_cell().unwrap());
        }
        msg.set_state_init(init);
        msg.int_header_mut().unwrap().value.coins = 100_000_000_000u64.into();
        if kind.contains("512") || kind.contains("513") {
            return msg
                .serialize_with_params(Some(false), Some(kind.ends_with("-ref")))
                .unwrap()
                .0
                .into_cell()
                .unwrap();
        }
    }
    if kind == "extra-flags" || kind == "source-flags" {
        msg.int_header_mut().unwrap().extra_flags = 8u64.into();
    }
    if kind == "no-funds" || kind == "no-funds-body" {
        msg.int_header_mut().unwrap().value.coins = 20_000_000_000u64.into();
    }
    if kind == "no-funds-body" {
        let mut body = BuilderData::new();
        body.checked_append_reference(compile_code_to_cell("NOP").unwrap()).unwrap();
        msg.set_body(SliceData::load_cell(body.into_cell().unwrap()).unwrap());
    }
    msg.serialize().unwrap()
}
// Pre-v4 failed action statistics include attempted forwarding fees which were
// rolled back. They are not collected transaction fees. Always verify actual
// balances and the sum of actually collected phase fees, including fines.
fn check_balances(
    version: u32,
    before: &Account,
    after: &Account,
    msg: &Message,
    tx: &Transaction,
) {
    let descr = get_tr_descr(tx);
    let mut left = before.balance().cloned().unwrap_or_default();
    left.add(&msg.get_value().cloned().unwrap_or_default()).unwrap();
    let mut right = after.balance().cloned().unwrap_or_default();
    right.add(tx.total_fees()).unwrap();
    right.coins.add(tx.blackhole_burned()).unwrap();
    tx.iterate_out_msgs(|out| {
        if let Some(h) = out.int_header() {
            right.add(h.value())?;
            right.coins.add(h.fwd_fee())?;
        }
        Ok(true)
    })
    .unwrap();
    assert_eq!(left, right, "actual balance conservation including committed output fees");
    let mut fees = Coins::zero();
    if let Some(action) = descr.action.as_ref() {
        if version >= 4 || action.success {
            fees += action.total_action_fees();
        }
    }
    if let Some(storage) = descr.storage_ph {
        fees += storage.storage_fees_collected;
    }
    if let Some(credit) = descr.credit_ph {
        fees += credit.due_fees_collected.unwrap_or_default();
    }
    if let TrComputePhase::Vm(vm) = descr.compute_ph {
        fees += vm.gas_fees;
    }
    if let Some(TrBouncePhase::Ok(bounce)) = descr.bounce {
        fees += bounce.msg_fees;
    }
    if msg.is_inbound_external() {
        let mut size = StorageUsageCalc::with_limits(0, 0);
        size.append_cell(&msg.serialize().unwrap(), false, &mut 0).unwrap();
        let prices = BLOCKCHAIN_CONFIG.raw_config().fwd_prices(msg.is_masterchain()).unwrap();
        fees += prices.calc_fwd_fee(size.bits(), size.cells());
    }
    assert_eq!(
        *tx.total_fees(),
        CurrencyCollection::from_coins(fees),
        "actual fees equal collected phases; pre-v4 failed action statistics are not charged"
    );
}

struct Matrix {
    expected: BTreeMap<String, String>,
    expected_phases: BTreeMap<String, String>,
    phase_mismatches: Vec<String>,
    inputs: Vec<String>,
    results: Vec<String>,
    mismatches: Vec<String>,
}
impl Matrix {
    fn new() -> Self {
        Self {
            expected: include_str!("data/historical-sendrawmsg.tsv")
                .lines()
                .map(|line| (line.split('\t').next().unwrap().to_owned(), line.to_owned()))
                .collect(),
            expected_phases: include_str!("data/historical-sendrawmsg-phases.tsv")
                .lines()
                .map(|line| (line.split('\t').next().unwrap().to_owned(), line.to_owned()))
                .collect(),
            phase_mismatches: Vec::new(),
            inputs: Vec::new(),
            results: Vec::new(),
            mismatches: Vec::new(),
        }
    }
    fn finish(self) {
        if let Ok(path) = std::env::var("RTOS_HISTORICAL_SENDRAWMSG_EXPORT") {
            use std::io::Write;
            let mut file = std::io::BufWriter::new(std::fs::File::create(&path).unwrap());
            for row in &self.inputs {
                writeln!(file, "{row}").unwrap();
            }
            std::fs::write(format!("{path}.results"), self.results.join("\n") + "\n").unwrap();
        }
        assert!(!self.inputs.is_empty());
        assert!(
            self.phase_mismatches.is_empty(),
            "{} independent fee/action/output mismatches; first {:?}",
            self.phase_mismatches.len(),
            &self.phase_mismatches[..self.phase_mismatches.len().min(30)]
        );
        assert!(
            self.mismatches.is_empty(),
            "{} full transaction/account root mismatches; first cases {:?}",
            self.mismatches.len(),
            &self.mismatches[..self.mismatches.len().min(30)]
        );
    }
    fn run(&mut self, version: u32, kind: &str, inbound: &str, mode: u8, order: &str) {
        let name = format!("send-v{version}-{kind}-{inbound}-m{mode}-{order}");
        let out = outgoing(kind);
        let mut data = BuilderData::new();
        data.checked_append_reference(out).unwrap();
        data.checked_append_reference(outgoing("internal")).unwrap();
        let mut code = String::from("ACCEPT ");
        if order == "before" || order == "around" {
            code.push_str("PUSHCTR C4 CTOS PLDREFIDX 1 PUSHINT 0 SENDRAWMSG ");
        }
        code.push_str(&format!("PUSHCTR C4 CTOS PLDREFIDX 0 PUSHINT {mode} SENDRAWMSG "));
        if order == "after" || order == "around" {
            code.push_str("PUSHCTR C4 CTOS PLDREFIDX 1 PUSHINT 0 SENDRAWMSG ");
        }
        // Both success and failure roots observe whether the new c4 is committed.
        code.push_str("NEWC PUSHINT 119 STUR 8 ENDC POPCTR C4");
        let mut account = create_test_account(
            1_000_000_000u64,
            SENDER_ACCOUNT.clone(),
            compile_code_to_cell(&code).unwrap(),
            data.into_cell().unwrap(),
        );
        if kind.starts_with("library-") {
            account.set_last_paid(BLOCK_UT);
            account.set_balance(CurrencyCollection::with_coins(1_000_000_000_000u64));
            account.calc_storage_stat_dict(rtos_block::DICT_HASH_MIN_CELLS).unwrap();
        }
        let before = account.clone();
        let msg = if inbound == "external" {
            create_test_external_msg()
        } else {
            create_int_msg(
                THIRD_ACCOUNT.clone(),
                SENDER_ACCOUNT.clone(),
                20_000_000u64,
                inbound == "bounce",
                BLOCK_LT - 2,
            )
        };
        let config = config(version);
        let input = if std::env::var_os("RTOS_HISTORICAL_SENDRAWMSG_EXPORT").is_some() {
            format!(
                "{name}\t{BLOCK_UT}\t{}\t{}\t{}\t{}\t-\t0\t-1\t{}",
                BLOCK_LT + 1,
                boc(config.raw_config().serialize().unwrap()),
                boc(account.serialize().unwrap()),
                boc(msg.serialize().unwrap()),
                "11".repeat(32)
            )
        } else {
            name.clone()
        };
        let limit = config.size_limits_config().acc_state_cells_for_storage_dict;
        let old = account.hash().unwrap();
        let mut tx = OrdinaryTransactionExecutor::new(config)
            .execute_with_params(
                Some(msg.serialize().unwrap()),
                &mut account,
                execute_params(BLOCK_LT + 1),
            )
            .unwrap();
        account.calc_storage_stat_dict(limit).unwrap();
        if version < 11 {
            account.del_storage_stat();
        }
        tx.write_state_update(&HashUpdate::with_hashes(old, account.hash().unwrap())).unwrap();
        check_balances(version, &before, &account, &msg, &tx);
        let descr = get_tr_descr(&tx);
        assert!(
            matches!(descr.compute_ph, TrComputePhase::Vm(ref vm) if vm.exit_code==0),
            "{name}: {:?}",
            descr.compute_ph
        );
        let th = tx.hash().unwrap().to_hex_string();
        let ah = account.hash().unwrap().to_hex_string();
        let result = format!("{name}\t{th}\t{ah}");
        if self.expected.get(&name) != Some(&result) {
            self.mismatches.push(name.clone());
        }
        let action = descr.action.as_ref().expect("successful VM has action phase");
        let balance_before = before.balance().map_or(0, |b| b.coins.as_u128());
        let balance_after = account.balance().map_or(0, |b| b.coins.as_u128());
        let balance_delta =
            i128::try_from(balance_after).unwrap() - i128::try_from(balance_before).unwrap();
        let phase = format!(
            "{name}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            tx.total_fees().coins.as_u128(),
            action.total_action_fees().as_u128(),
            tx.out_msgs.len().unwrap(),
            u8::from(action.success),
            u8::from(descr.aborted),
            action.result_code,
            action.skipped_actions,
            action.msgs_created,
            balance_before,
            balance_after,
            balance_delta
        );
        if self.expected_phases.get(&name) != Some(&phase) {
            self.phase_mismatches
                .push(format!("{phase}; expected {:?}", self.expected_phases.get(&name)));
        }

        self.results.push(format!("{result}\ttotal_fees={}\taction_fees={}\tcode={}\targ={:?}\tvalid={}\tsuccess={}\tskipped={}\tout={}\taborted={}\tbounce={:?}",
            tx.total_fees().coins.as_u128(),action.total_action_fees().as_u128(),action.result_code,action.result_arg,action.valid,action.success,action.skipped_actions,
            tx.out_msgs.len().unwrap(),descr.aborted,descr.bounce));
        self.inputs.push(format!("{input}\t{th}\t{ah}"));
    }
}
#[test]
fn historical_sendrawmsg_reference() {
    let mut matrix = Matrix::new();
    for version in [0, 1, 3, 4, 7, 8, 12, 13, 14, 15, 17] {
        for kind in ["internal", "external"] {
            for inbound in ["internal", "bounce", "external"] {
                for mode in 0..=255 {
                    matrix.run(version, kind, inbound, mode, "single");
                }
            }
        }
        for kind in [
            "internal",
            "external",
            "malformed",
            "inbound-external",
            "libraries",
            "source",
            "extra-flags",
            "source-flags",
            "no-funds",
        ] {
            for mode in [
                0, 2, 4, 6, 16, 18, 20, 22, 32, 34, 48, 50, 64, 66, 80, 82, 128, 130, 144, 146,
                160, 162, 192, 194, 208, 210, 255,
            ] {
                for order in ["before", "after", "around"] {
                    matrix.run(version, kind, "bounce", mode, order);
                }
            }
        }
    }
    assert_eq!(matrix.inputs.len(), 24915, "all historical mode combinations ran");
    matrix.finish();
}

#[test]
fn historical_sendrawmsg_priority_probes() {
    let mut matrix = Matrix::new();
    for version in [0, 1, 3, 4, 7, 8, 12, 13, 14, 15, 17] {
        for mode in [
            0, 2, 4, 6, 16, 18, 20, 22, 32, 34, 48, 50, 64, 66, 80, 82, 128, 130, 144, 146, 160,
            162, 192, 194, 208, 210, 255,
        ] {
            for order in ["before", "after", "around"] {
                matrix.run(version, "invalid-libraries", "bounce", mode, order);
            }
        }
    }
    // Single-point reversal controls also reuse complete roots from the broad matrix.
    for (version, kind, mode, order) in [
        (3, "internal", 16, "single"),
        (4, "internal", 16, "single"),
        (7, "malformed", 18, "around"),
        (8, "malformed", 18, "around"),
        (12, "internal", 6, "around"),
        (13, "internal", 6, "around"),
        (12, "source", 18, "around"),
        (13, "source", 18, "around"),
        (14, "libraries", 0, "around"),
        (14, "external", 34, "around"),
        (7, "no-funds", 2, "around"),
        (8, "no-funds", 2, "around"),
        (3, "extra-flags", 0, "around"),
        (12, "extra-flags", 0, "around"),
        (7, "inbound-external", 18, "around"),
        (8, "inbound-external", 18, "around"),
    ] {
        matrix.run(version, kind, "bounce", mode, order);
    }
    assert_eq!(matrix.inputs.len(), 907);
    matrix.finish();
}

#[test]
fn historical_sendrawmsg_library_validation() {
    let mut matrix = Matrix::new();
    for version in [3, 4, 12, 13, 14, 17] {
        for kind in [
            "library-two",
            "library-leaf-bits",
            "library-leaf-refs",
            "library-fork-bits",
            "library-fork-refs",
        ] {
            for mode in [0, 2, 6, 16, 18] {
                for order in ["before", "after"] {
                    matrix.run(version, kind, "bounce", mode, order);
                }
            }
        }
    }
    for version in [12, 13, 14] {
        for kind in
            ["library-512-inline", "library-512-ref", "library-513-inline", "library-513-ref"]
        {
            for mode in [0, 2] {
                matrix.run(version, kind, "bounce", mode, "around");
            }
        }
    }
    assert_eq!(matrix.inputs.len(), 324);
    matrix.finish();
}

#[test]
fn historical_sendrawmsg_fine_activation() {
    let mut matrix = Matrix::new();
    for version in [0, 1, 3, 4, 7, 8, 12, 13, 14, 15, 17] {
        for mode in [0, 2, 16, 18] {
            for order in ["before", "after", "around"] {
                matrix.run(version, "no-funds-body", "bounce", mode, order);
            }
        }
    }
    assert_eq!(matrix.inputs.len(), 132);
    matrix.finish();
}
