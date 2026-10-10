// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use crate::{
    collator_test_bundle::CollatorTestBundle,
    engine_traits::EngineOperations,
    validator::{validator_utils::compute_validator_set_cc, BlockCandidate},
};
use rtos_block::{
    Block, BuilderData, Cell, CellType, Deserializable, HashmapAugType, Result, Serializable,
    ShardStateUnsplit, TransactionDescr, UInt256, ValidatorSet,
};
use std::sync::Arc;
const BUNDLE: &str = "src/tests/static/0.8000000000000000_66163599_2bc2034d_collator_test_bundle";
async fn validate_real(engine: Arc<CollatorTestBundle>, candidate: BlockCandidate) -> Result<()> {
    let info = Block::construct_from_bytes(&candidate.data)?.read_info()?;
    let shard = info.shard().clone();
    let prev = info.read_prev_ids()?;
    let mc_id = if shard.is_masterchain() {
        prev[0].clone()
    } else {
        info.read_master_id()?.master_block_id().1
    };
    let state = engine.load_state(&mc_id).await?;
    let extra = state.shard_state_extra()?;
    let cc = if shard.is_masterchain() {
        extra.validator_info.catchain_seqno
    } else {
        extra.shards.calc_shard_cc_seqno(&shard)?
    };
    let mut derived_cc = 0;
    let nodes = compute_validator_set_cc(&state, &shard, info.seq_no(), cc, &mut derived_cc)?;
    let validators = ValidatorSet::with_cc_seqno(0, 0, 0, derived_cc, nodes)?;
    assert_eq!(validators.catchain_seqno(), 538538);
    assert_eq!(ValidatorSet::calc_subset_hash_short(validators.list(), derived_cc)?, 2445650682);
    let config = state.config_params()?;
    println!("C08_PROTOCOL_VERSION {}", config.get_global_version()?.version);
    let simplex = if shard.is_masterchain() {
        config.get_mc_simplex_config()?.is_some()
    } else {
        config.get_shard_simplex_config()?.is_some()
    };
    super::ValidateQuery::new(
        shard,
        info.min_ref_mc_seqno() - 1,
        prev,
        None,
        candidate,
        validators,
        engine,
        false,
        false,
        simplex,
    )
    .try_validate()
    .await?;
    Ok(())
}

fn candidate(original: &BlockCandidate, block: &Block) -> BlockCandidate {
    let mut c = original.clone();
    c.data = block.write_to_bytes().unwrap();
    c.block_id.root_hash = block.serialize().unwrap().repr_hash().clone();
    c.block_id.file_hash = UInt256::calc_file_hash(&c.data);
    c.collated_file_hash = UInt256::calc_file_hash(&c.collated_data);
    c
}
fn replace(root: &Cell, old: &UInt256, new: &Cell) -> Cell {
    if root.repr_hash() == old {
        return new.clone();
    }
    if root.cell_type() != CellType::Ordinary {
        return root.clone();
    }
    let mut b = BuilderData::from_cell(root).unwrap();
    for i in 0..root.references_count() {
        b.replace_reference_cell(i, replace(&root.reference(i).unwrap(), old, new));
    }
    b.into_cell().unwrap()
}
// Preserve the archived dictionary augmentation while changing only the known
// last-transaction metadata. Recalculating augmentation would need pruned sibling
// account bodies; no balance or account root is changed by this mutation.
fn replace_last_transaction(
    root: &Cell,
    old: &UInt256,
    new: &UInt256,
    lt: u64,
    count: &mut usize,
) -> Cell {
    if root.cell_type() != CellType::Ordinary {
        return root.clone();
    }
    let mut data = root.data().to_vec();
    let bits = root.bit_length();
    let old_bits = old
        .as_slice()
        .iter()
        .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1))
        .chain(lt.to_be_bytes().into_iter().flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1)))
        .collect::<Vec<_>>();
    if bits >= 320
        && (0..320).all(|i| {
            ((data[(bits - 320 + i) / 8] >> (7 - (bits - 320 + i) % 8)) & 1) == old_bits[i]
        })
    {
        *count += 1;
        for i in 0..256 {
            let offset = bits - 320 + i;
            let value = (new.as_slice()[i / 8] >> (7 - i % 8)) & 1;
            data[offset / 8] =
                (data[offset / 8] & !(1 << (7 - offset % 8))) | (value << (7 - offset % 8));
        }
    }
    BuilderData::with_raw_and_refs(
        data,
        bits,
        (0..root.references_count())
            .map(|i| replace_last_transaction(&root.reference(i).unwrap(), old, new, lt, count)),
    )
    .unwrap()
    .into_cell()
    .unwrap()
}
fn update_state(block: &mut Block, f: impl FnOnce(&mut ShardStateUnsplit)) {
    let mut update = block.read_state_update().unwrap();
    let mut state = ShardStateUnsplit::construct_from_cell(update.new.clone()).unwrap();
    f(&mut state);
    update.new = state.serialize().unwrap();
    update.new_hash = update.new.hash(0).clone();
    update.new_depth = update.new.depth(0);
    block.write_state_update(&update).unwrap();
}
#[tokio::test(flavor = "multi_thread")]
async fn candidate_nonempty_full_reference_variants() {
    let bundle = Arc::new(CollatorTestBundle::load(BUNDLE).unwrap());
    let original = bundle.candidate().unwrap().clone();
    assert_eq!(
        original.block_id.root_hash.to_hex_string(),
        "2bc2034d35d9beea3332e4464d587014cd58166bc96813f685f3d894ca28236e"
    );
    let mut block = Block::construct_from_bytes(&original.data).unwrap();
    let mut info = block.read_info().unwrap();
    assert_eq!(info.gen_validator_list_hash_short(), 1099449383);
    info.set_gen_validator_list_hash_short(2445650682);
    block.write_info(&info).unwrap();
    let valid = candidate(&original, &block);
    let roots = rtos_block::read_boc(&valid.collated_data).unwrap().roots;
    let metadata = roots
        .iter()
        .filter_map(|r| rtos_block::ConsensusExtraData::construct_from_cell(r.clone()).ok())
        .collect::<Vec<_>>();
    assert_eq!(metadata.len(), 1);
    assert_eq!(metadata[0].gen_utime_ms / 1000, u64::from(info.gen_utime()));
    let blocks = block.read_extra().unwrap().read_account_blocks().unwrap();
    let mut selected = None;
    let mut count = 0;
    blocks
        .iterate_with_keys(|addr, ab| {
            let mut txs = Vec::new();
            ab.transaction_iterate(|tx| {
                count += 1;
                txs.push(tx);
                Ok(true)
            })?;
            if txs.len() == 1 && matches!(txs[0].read_description()?, TransactionDescr::Ordinary(_))
            {
                selected = Some((addr, ab, txs.remove(0)));
            }
            Ok(true)
        })
        .unwrap();
    assert_eq!(count, 5);
    println!("C08_NONEMPTY transactions={count}");
    let (addr, account_block, tx) = selected.expect("one ordinary transaction account");
    let mut cases = vec![("valid", valid.clone(), true)];
    for (name, time, mask, expected) in [
        ("new-state-load-conflict", false, 1, false),
        ("new-state-load-history", false, 2, false),
        ("new-state-time", true, 0, false),
    ] {
        let mut b = block.clone();
        update_state(&mut b, |s| {
            if time {
                s.set_gen_time(s.gen_time() + 1)
            } else {
                s.set_overload_history(s.overload_history() ^ mask)
            }
        });
        cases.push((name, candidate(&valid, &b), expected));
    }
    let mut current = block.clone();
    update_state(&mut current, |s| {
        s.set_overload_history(s.overload_history() ^ 1);
        s.set_underload_history(s.underload_history() & !1);
    });
    cases.push(("new-state-load-current", candidate(&valid, &current), true));
    let mut bad_account = block.clone();
    let mut extra = bad_account.read_extra().unwrap();
    let mut abs = extra.read_account_blocks().unwrap();
    let mut ab = account_block.clone();
    let mut hu = ab.read_state_update().unwrap();
    hu.new_hash = UInt256::default();
    ab.write_state_update(&hu).unwrap();
    abs.insert(&ab).unwrap();
    extra.write_account_blocks(&abs).unwrap();
    bad_account.write_extra(&extra).unwrap();
    cases.push(("account-new-hash", candidate(&valid, &bad_account), false));
    let mut changed = tx.clone();
    let mut desc = changed.read_description().unwrap();
    if let TransactionDescr::Ordinary(ref mut d) = desc {
        d.compute_ph.get_vmphase_mut().unwrap().exit_code ^= 1;
    }
    changed.write_description(&desc).unwrap();
    let old = tx.serialize().unwrap();
    let new = changed.serialize().unwrap();
    let root = replace(&block.serialize().unwrap(), old.repr_hash(), &new);
    let mut bad_tx = Block::construct_from_cell(root).unwrap();
    update_state(&mut bad_tx, |s| {
        let acc = s.read_accounts().unwrap().account(&addr).unwrap().unwrap();
        assert_eq!(acc.last_trans_hash(), old.repr_hash());
        let mut replacements = 0;
        let root = replace_last_transaction(
            &s.accounts_cell(),
            old.repr_hash(),
            new.repr_hash(),
            acc.last_trans_lt(),
            &mut replacements,
        );
        assert_eq!(replacements, 1);
        s.replace_accounts_cell(root);
    });
    cases.push(("transaction-exit-code", candidate(&valid, &bad_tx), false));
    let mut mismatches = Vec::new();
    for (name, c, expected) in cases {
        if let Ok(dir) = std::env::var("RTOS_NONEMPTY_REFERENCE_EXPORT") {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(std::path::Path::new(&dir).join(format!("{name}.block.boc")), &c.data)
                .unwrap();
            std::fs::write(
                std::path::Path::new(&dir).join(format!("{name}.collated.boc")),
                &c.collated_data,
            )
            .unwrap();
        }
        let result = validate_real(bundle.clone(), c).await;
        println!(
            "C08_NONEMPTY_RESULT {name}\t{}\t{}",
            result.is_ok(),
            result.as_ref().err().map(ToString::to_string).unwrap_or_default()
        );
        if result.is_ok() != expected {
            mismatches.push(name);
        }
    }
    for delta in [0, 15, 16, 29, 30, 31, 32, 60] {
        let mut engine = CollatorTestBundle::load(BUNDLE).unwrap();
        engine.set_test_clock(info.gen_utime() - delta);
        let result = validate_real(Arc::new(engine), valid.clone()).await;
        println!(
            "C08_CLOCK_RESULT {delta}\t{}\t{}",
            result.is_ok(),
            result.as_ref().err().map(ToString::to_string).unwrap_or_default()
        );
        if delta > 30 {
            assert!(matches!(
                result.as_ref().unwrap_err().downcast_ref::<crate::error::NodeError>(),
                Some(crate::error::NodeError::ValidatorSoftReject(_))
            ));
        }
        if result.is_ok() != (delta <= 30) {
            mismatches.push("local-clock");
        }
    }
    assert!(mismatches.is_empty(), "reference acceptance mismatches: {mismatches:?}");
}
