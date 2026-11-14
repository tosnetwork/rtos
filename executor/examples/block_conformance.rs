// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Offline block boundary: apply the native update and re-execute every transaction.
#[allow(dead_code)]
#[path = "txn_conformance.rs"]
mod txn;

use anyhow::{anyhow, bail, ensure, Result};
use rtos_block::{
    base64_decode, base64_encode, read_single_root_boc, write_boc, AccountId, Block, BlockError,
    BlockIdExt, Cell, CellType, Deserializable, ExceptionCode, HashmapAugType, HashmapType,
    KeyExtBlkRef, Serializable, ShardAccount, ShardAccounts, ShardStateUnsplit, Transaction,
    TransactionDescr, UInt256, LT_ALIGN,
};
use rtos_vm::{smart_contract_info::SmartContractInfo, stack::StackItem};
use serde_json::{json, Value};
use std::io::{self, BufRead, Read, Write};

pub(crate) struct Original {
    pub(crate) root: Cell,
    pub(crate) bytes: Vec<u8>,
}
fn original(ctx: &Value, name: &str) -> Result<Original> {
    let bytes = base64_decode(ctx[name].as_str().ok_or_else(|| anyhow!("missing BOC {name}"))?)?;
    Ok(Original { root: read_single_root_boc(&bytes)?, bytes })
}
fn hash(cell: &Cell) -> String {
    format!("{:X}", cell.hash(0))
}
fn virtual0(cell: &Cell) -> Cell {
    cell.clone().virtualize(cell.level())
}
fn boc(cell: &Cell) -> Result<Value> {
    Ok(json!(base64_encode(write_boc(cell)?)))
}
fn pruned(error: &anyhow::Error) -> bool {
    matches!(error.downcast_ref::<BlockError>(), Some(BlockError::PrunedCellAccess(_)))
        || matches!(error.downcast_ref::<ExceptionCode>(), Some(ExceptionCode::PrunedCellAccess))
}
fn entry(accounts: &ShardAccounts, key: &AccountId) -> Result<Option<Cell>> {
    accounts
        .get_serialized_as_slice(key.write_to_bitstring()?)?
        .map(|slice| slice.into_cell())
        .transpose()
}
fn absent() -> Result<Cell> {
    ShardAccount::default().serialize()
}

pub(crate) fn apply(
    input: &Original,
    previous: &Cell,
    master: Option<(&Original, &Cell)>,
    why: &mut &'static str,
) -> Result<Value> {
    *why = "malformed_block";
    let block = Block::construct_from_full_cell(input.root.clone())?;
    let info = block.read_info()?;
    let extra = block.read_extra()?;
    if info.after_split() || info.after_merge() {
        *why = "split_merge_unsupported";
        bail!("split/merge needs both predecessor states");
    }
    *why = "state_update_invalid";
    ensure!(
        block.state_update_cell().cell_type() == CellType::MerkleUpdate
            && block.state_update_cell().level() == 0,
        "not a level0 update"
    );
    let update = block.read_state_update()?;
    update.validate()?;
    *why = "prev_state_mismatch";
    ensure!(previous.hash(0) == &update.old_hash, "previous-state hash differs");
    let previous = virtual0(previous);
    *why = "state_update_not_applicable";
    let (applied, _) = update.apply_for(&previous)?;
    *why = "state_update_mismatch";
    ensure!(applied.hash(0) == &update.new_hash, "applied-state hash differs");
    *why = "prev_state_malformed";
    let previous_state = ShardStateUnsplit::construct_from_full_cell(previous)?;

    *why = "malformed_block";
    let master_ref = info.read_master_ref()?;
    let (config_state, current) = if master_ref.is_none() {
        let parent = info.read_prev_ref()?.prev1()?;
        (previous_state.clone(), BlockIdExt::from_ext_blk(parent))
    } else {
        let reference = info.read_master_id()?;
        *why = "master_context_mismatch";
        let (master, state) = master.ok_or_else(|| anyhow!("missing master context"))?;
        ensure!(
            master.root.hash(0) == &reference.root_hash
                && UInt256::calc_file_hash(&master.bytes) == reference.file_hash,
            "masterchain block identity differs"
        );
        let mc = Block::construct_from_full_cell(master.root.clone())?;
        let mi = mc.read_info()?;
        ensure!(
            mi.read_master_ref()?.is_none() && mi.seq_no() == reference.seq_no,
            "masterchain header differs"
        );
        let cell = mc.state_update_cell();
        ensure!(
            cell.cell_type() == CellType::MerkleUpdate
                && cell.references_count() == 2
                && cell.reference(1)?.hash(0) == state.hash(0),
            "masterchain state differs"
        );
        *why = "config_unavailable";
        (
            ShardStateUnsplit::construct_from_full_cell(virtual0(state))
                .map_err(|e| anyhow!("configuration state: {e:#}"))?,
            BlockIdExt::from_ext_blk(reference),
        )
    };
    *why = "config_unavailable";
    // ConfigInfo::unpack_wrapped in the reference converts virtualization
    // errors during extraction to a configuration failure. Later account or
    // history traversal still propagates pruned-cell access normally.
    let custom = (|| -> Result<_> {
        ensure!(
            config_state.shard().is_masterchain() && config_state.seq_no() == current.seq_no(),
            "masterchain state header differs"
        );
        let custom =
            config_state.read_custom()?.ok_or_else(|| anyhow!("missing masterchain extra"))?;
        // ConfigInfo::unpack checks the zero-state record even when the
        // recent/century tuple never looks that far back.
        if config_state.seq_no() != 0 {
            let mut zero = custom
                .prev_blocks
                .get_as_slice(&0)?
                .ok_or_else(|| anyhow!("missing zero-state reference"))?;
            let entry = KeyExtBlkRef::construct_from(&mut zero)?;
            ensure!(
                entry.blk_ref.seq_no == 0 && zero.is_empty_cell(),
                "invalid zero-state reference"
            );
        }
        custom.config.get_global_version()?;
        custom.config.workchains()?;
        custom.config.fundamental_smc_addr()?;
        Ok(custom)
    })()
    .map_err(|e| anyhow!("configuration extraction: {e:#}"))?;
    let history = SmartContractInfo::get_method_prev_blocks_info(&config_state, &current)?;
    ensure!(!matches!(history, StackItem::None), "unavailable previous-block context");
    let config = boc(custom.config.root().ok_or_else(|| anyhow!("missing config root"))?)?;
    let mut context = json!({
        "config":config, "rand_seed":format!("{:x}",extra.rand_seed()),
    });
    if let Some(libs) = config_state.libraries().root() {
        context["libraries"] = boc(libs)?;
    }

    *why = "malformed_block";
    let account_blocks = extra.read_account_blocks()?;
    let mut executed = Vec::new();
    if account_blocks.is_empty() {
        return Ok(json!({"outcome":"accepted", "block_root_hash":hash(&input.root),
            "new_state_hash":hash(&applied), "transactions":executed}));
    }
    *why = "state_update_mismatch";
    let new_state = ShardStateUnsplit::construct_from_full_cell(applied.clone())?;
    *why = "prev_state_malformed";
    let accounts = previous_state.read_accounts()?;
    let new_accounts = new_state.read_accounts()?;
    *why = "malformed_block";
    account_blocks.iterate_with_keys(|key, ab| {
        *why = "account_unavailable";
        let original = entry(&accounts, &key)?.unwrap_or(absent()?);
        *why = "prev_state_malformed";
        ensure!(original.references_count() > 0, "missing account reference");
        let original_account = original.reference(0)?;
        let mut current = original;
        let mut context = context.clone();
        *why = "malformed_block";
        ab.transaction_iterate_full(|_, tx, _| {
            *why = "malformed_block";
            let record = Transaction::construct_from_full_cell(tx.clone())?;
            let expected = record.read_state_update()?;
            let description = record.read_description()?;
            let tock = match description {
                TransactionDescr::Ordinary(_) => None,
                TransactionDescr::TickTock(tt) => Some(tt.tt.is_tock()),
                _ => bail!("unsupported transaction type"),
            };
            *why = "transaction_context_mismatch";
            ensure!(record.account_id() == ab.account_id(), "transaction account differs");
            ensure!(record.now() == info.gen_utime(), "transaction time differs");
            ensure!(record.logical_time() - record.logical_time()%LT_ALIGN == info.start_lt(), "transaction LT differs");
            let old_account = current.reference(0)?;
            ensure!(&expected.old_hash == old_account.hash(0),
                "account old hash differs expected={:X} actual={:X} type={:?} level={} virt={}",
                expected.old_hash, old_account.hash(0), old_account.cell_type(), old_account.level(), old_account.virtualization());
            ensure!(executed.len() < 4096, "too many transactions");
            *why = "execution_refused";
            context["shard_account"] = boc(&current)?;
            context["now"] = json!(record.now());
            context["lt"] = json!(record.logical_time());
            if let Some(tock) = tock {
                context["tick_tock"] = json!(if tock { "tock" } else { "tick" });
                context.as_object_mut().unwrap().remove("message");
            } else {
                let message = record.in_msg_cell().ok_or_else(|| anyhow!("ordinary without message"))?;
                context["message"] = boc(&message)?;
                context.as_object_mut().unwrap().remove("tick_tock");
            }
            let txn::Outcome::Accepted {transaction, shard_account, account_hash} = txn::execute_with_history(&context, Some(history.clone()))? else {
                bail!("transaction execution refused");
            };
            executed.push(json!({"transaction_hash":hash(&transaction), "account_hash":format!("{:X}",account_hash)}));
            *why = "transaction_mismatch";
            ensure!(transaction.hash(0) == tx.hash(0), "re-executed transaction differs");
            *why = "account_hash_mismatch";
            ensure!(expected.new_hash == account_hash, "re-executed account differs");
            current = shard_account;
            Ok(true)
        })?;
        *why = "new_state_mismatch";
        let final_account = current.reference(0)?;
        let final_cs = rtos_block::SliceData::load_cell(final_account.clone())?;
        let target = entry(&new_accounts, &key)?;
        if final_cs.remaining_bits() == 1 && final_cs.remaining_references() == 0
            && final_cs.get_bit(0)? == false {
            ensure!(target.is_none(), "deleted account still present");
        } else {
            let target = target.ok_or_else(|| anyhow!("new account missing"))?;
            if original_account.hash(0) == final_account.hash(0) {
                ensure!(target.reference(0)?.hash(0) == final_account.hash(0), "unchanged account differs");
            } else {
                ensure!(target.hash(0) == current.hash(0), "new ShardAccount differs");
            }
        }
        Ok(true)
    })?;
    Ok(json!({"outcome":"accepted", "block_root_hash":hash(&input.root),
        "new_state_hash":hash(&applied), "transactions":executed}))
}
fn run_block(ctx: &Value) -> Result<Value> {
    let block = original(ctx, "block")?;
    let previous = original(ctx, "prev_state")?;
    ensure!(
        ctx.get("master_block").is_some() == ctx.get("master_state").is_some(),
        "master context must be paired"
    );
    let master = ctx
        .get("master_block")
        .map(|_| -> Result<_> {
            Ok((original(ctx, "master_block")?, original(ctx, "master_state")?))
        })
        .transpose()?;
    let mut why = "malformed_block";
    Ok(match apply(&block, &previous.root, master.as_ref().map(|(b, s)| (b, &s.root)), &mut why) {
        Ok(effect) => effect,
        Err(error) => {
            eprintln!("block {why}: {error:?}");
            json!({"outcome":"rejected", "reason":if pruned(&error) {"pruned_state"} else {why}})
        }
    })
}
fn main() -> Result<()> {
    let harness = std::env::args().nth(1).unwrap_or_default();
    if harness == "--info" {
        println!("{}", json!({"harnesses":["block"],"protocol_version":1}));
        return Ok(());
    }
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut line = String::new();
        let size = input.by_ref().take((16 << 20) + 2).read_line(&mut line)?;
        if size == 0 {
            break;
        }
        let response = (|| -> Result<Value> {
            ensure!(size <= 16 << 20, "context too large");
            ensure!(harness == "block", "unsupported harness");
            run_block(&serde_json::from_str::<Value>(&line)?)
        })()
        .unwrap_or_else(|e| json!({"harness_error":e.to_string()}));
        serde_json::to_writer(&mut output, &response)?;
        writeln!(output)?;
        output.flush()?;
        ensure!(size <= 16 << 20, "context too large");
    }
    Ok(())
}
