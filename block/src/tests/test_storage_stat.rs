/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::{
    Account, AccountStorageStat, BuilderData, Cell, Deserializable, ExceptionCode, IBitstring,
    MerkleProof, Serializable, StorageStatDict, UInt256, UsageTree, DICT_HASH_MIN_CELLS,
};
use std::collections::HashSet;

fn leaf(tag: u32) -> Cell {
    let mut b = BuilderData::new();
    b.append_u32(tag).unwrap();
    b.into_cell().unwrap()
}

fn node(tag: u32, children: &[Cell]) -> Cell {
    let mut b = BuilderData::new();
    b.append_u32(tag).unwrap();
    for c in children {
        b.checked_append_reference(c.clone()).unwrap();
    }
    b.into_cell().unwrap()
}

#[test]
fn test_storage_stat() {
    let acc_state1 = include_bytes!("data/storage_stat/acc.boc");
    let mut acc1 = Account::construct_from_bytes(acc_state1).unwrap();
    let storage_info1 = acc1.storage_info().unwrap().clone();

    // calc dictionary and check its hash
    let dict_root1 = acc1.calc_storage_stat_dict(DICT_HASH_MIN_CELLS).unwrap().unwrap();
    assert_eq!(dict_root1.repr_hash(), storage_info1.dict_hash().unwrap());
    assert_eq!(storage_info1.used(), acc1.storage_info().unwrap().used());

    // import storage stat dict and check again
    let mut acc1 = Account::construct_from_bytes(acc_state1).unwrap();
    acc1.import_storage_stat_dict(dict_root1.clone()).unwrap();

    let dict_root1 = acc1.calc_storage_stat_dict(DICT_HASH_MIN_CELLS).unwrap().unwrap();
    assert_eq!(dict_root1.repr_hash(), storage_info1.dict_hash().unwrap());
    assert_eq!(storage_info1.used(), acc1.storage_info().unwrap().used());

    // change account state and update dictionary
    let acc_state2 = include_bytes!("data/storage_stat/acc1.boc");
    let mut acc2 = Account::construct_from_bytes(acc_state2).unwrap();
    assert!(acc2.import_storage_stat_dict(dict_root1).is_err());
    let storage_info2 = acc2.storage_info().unwrap();

    *acc1.state_init_mut().unwrap() = acc2.state_init().unwrap().clone();

    let dict_root2 = acc1.calc_storage_stat_dict(DICT_HASH_MIN_CELLS).unwrap().unwrap();
    assert_eq!(dict_root2.repr_hash(), storage_info2.dict_hash().unwrap());
    assert_eq!(storage_info2.used(), acc1.storage_info().unwrap().used());
}

// Full-removal edge case for `replace_roots`: removing all roots empties the dict but leaves
// zero-refcount entries in the cache. The next root change then hits "empty dict + non-empty
// cache" and must NOT clear (the cache is still complete). Verifies the full→empty→full cycle
// gives exactly the same totals and dict as a fresh build over the final roots.
#[test]
fn test_storage_stat_full_removal_then_readd() {
    let shared = leaf(0x5EED);
    let root_a = node(0x0A, &[shared.clone(), leaf(0xAA)]);
    let root_b = node(0x0B, &[shared.clone(), leaf(0xBB)]); // shares `shared` with root_a

    // Reference: a fresh stat built directly over the final roots.
    let mut reference = AccountStorageStat::default();
    reference.replace_roots([root_b.clone()].as_slice().into()).unwrap();
    let ref_dict = reference.calc_dict().unwrap().map(|c| c.repr_hash().clone());
    let (ref_cells, ref_bits) = (reference.total_cells(), reference.total_bits());

    // Edge path: build over root_a, remove everything, then re-add root_b.
    let mut stat = AccountStorageStat::default();
    stat.replace_roots([root_a].as_slice().into()).unwrap();
    assert!(stat.calc_dict().unwrap().is_some(), "dict built for root_a");

    stat.replace_roots([].as_slice().into()).unwrap();
    assert!(stat.calc_dict().unwrap().is_none(), "dict emptied after full removal");
    assert_eq!(stat.total_cells(), 0, "totals zeroed after full removal");
    assert!(!stat.cache.is_empty(), "cache keeps zero-refcount entries — the edge state");

    stat.replace_roots([root_b].as_slice().into()).unwrap();
    let edge_dict = stat.calc_dict().unwrap().map(|c| c.repr_hash().clone());

    assert_eq!(stat.total_cells(), ref_cells, "cells match fresh build");
    assert_eq!(stat.total_bits(), ref_bits, "bits match fresh build");
    assert_eq!(edge_dict, ref_dict, "dict matches fresh build after full→empty→full");
}

// `add_hint` must drop any previously seeded hint, even on its early-return paths (empty `loaded`
// or empty dict). Otherwise a stale hint from a prior call could be applied to the next diff.
#[test]
fn test_add_hint_clears_stale_hint() {
    let parent = node(0x0A, &[node(0x55, &[leaf(0xCC)])]);

    // A non-empty dict is required, otherwise `add_hint` short-circuits before touching the hint.
    let mut full = AccountStorageStat::default();
    full.replace_roots([parent.clone()].as_slice().into()).unwrap();
    let dict = full.calc_dict().unwrap().cloned().unwrap();

    let mut stat = AccountStorageStat::default();
    stat.dict = StorageStatDict::with_hashmap(Some(dict));
    stat.roots = [parent.clone()].as_slice().into();

    let loaded: HashSet<UInt256> = [parent.repr_hash().clone()].into_iter().collect();
    stat.add_hint(&loaded);
    assert!(!stat.hint.is_empty(), "hint is seeded from loaded cells");

    // Second call with nothing loaded must clear the previously seeded hint, not keep it.
    stat.add_hint(&HashSet::new());
    assert!(stat.hint.is_empty(), "empty `loaded` clears the stale hint");
}

// A subtree that is full in the new state but pruned in the old (collated-data) proof — both in the
// stored state and in the storage-stat dict. Without the hint the validator-style incremental diff
// re-counts the shared subtree as new (overcount); `add_hint` marks it pre-existing so totals stay
// correct. Mirrors the real `check_ethalon_bundle` failure at the unit level.
#[test]
fn test_add_hint_treats_pruned_shared_cell_as_preexisting() {
    let gc = leaf(0xCC);
    let shared = node(0x55, &[gc.clone()]); // shared subtree: `shared` + `gc`
    let old_parent = node(0x0A, &[shared.clone()]);
    let new_parent = node(0x0B, &[shared.clone()]); // different root, same shared subtree
    let shared_hash = shared.repr_hash().clone();

    // Full stat over the old state: counts old_parent + shared + gc.
    let mut full = AccountStorageStat::default();
    full.replace_roots([old_parent.clone()].as_slice().into()).unwrap();
    let full_dict = full.calc_dict().unwrap().cloned().unwrap();
    let full_cells = full.total_cells();
    let full_bits = full.total_bits();

    // Retain the changed old-root entry and prove the new root absent; the unchanged
    // `shared` and `gc` entries may remain pruned. Their lookup must fail, not report
    // absence. (`gc` must be pruned too,
    // otherwise it would resolve as a dict hit and the overcount would cancel — the real bug
    // overcounts the *children* of the shared cell, not the shared cell itself.)
    let usage = UsageTree::with_root(full_dict.clone());
    let tracked = StorageStatDict::with_hashmap(Some(usage.root_cell()));
    tracked.get(old_parent.repr_hash()).unwrap();
    assert!(tracked.get(new_parent.repr_hash()).unwrap().is_none());
    let pruned_dict =
        MerkleProof::create_by_usage_tree(&full_dict, &usage).unwrap().proof.virtualize(1);
    let probe = StorageStatDict::with_hashmap(Some(pruned_dict.clone()));
    assert!(probe.get(old_parent.repr_hash()).unwrap().is_some(), "old root entry survives");
    for hash in [&shared_hash, gc.repr_hash()] {
        let error = probe.get(hash).expect_err("shared entries remain unknown in this proof");
        assert_eq!(error.downcast_ref::<ExceptionCode>(), Some(&ExceptionCode::PrunedCellAccess));
    }

    // Prune `shared` out of the old stored state too: old_parent now references a pruned branch.
    let old_parent_pruned =
        MerkleProof::create(&old_parent, |h| *h != shared_hash).unwrap().proof.virtualize(1);
    assert_eq!(
        old_parent_pruned.reference(0).unwrap().references_count(),
        0,
        "shared subtree is pruned in the old state"
    );

    let seed = |stat: &mut AccountStorageStat| {
        stat.dict = StorageStatDict::with_hashmap(Some(pruned_dict.clone()));
        stat.roots = [old_parent_pruned.clone()].as_slice().into();
        stat.total_cells = full_cells;
        stat.total_bits = full_bits;
        stat.dict_updated = false;
    };
    let loaded: HashSet<UInt256> = [old_parent_pruned.repr_hash().clone()].into_iter().collect();

    // Without the hint, the missing old subtree cannot be removed safely.
    let mut without_hint = AccountStorageStat::default();
    seed(&mut without_hint);
    let error = without_hint.replace_roots([new_parent.clone()].as_slice().into()).unwrap_err();
    assert_eq!(error.downcast_ref::<ExceptionCode>(), Some(&ExceptionCode::PrunedCellAccess));

    // With the hint: `shared` is recognised as pre-existing → totals unchanged.
    let mut with_hint = AccountStorageStat::default();
    seed(&mut with_hint);
    with_hint.add_hint(&loaded);
    assert!(with_hint.hint.contains(&shared_hash), "hint marks the shared subtree");
    with_hint.replace_roots([new_parent.clone()].as_slice().into()).unwrap();

    assert_eq!(with_hint.total_cells(), full_cells, "with hint: shared subtree not re-counted");
    assert_eq!(with_hint.total_bits(), full_bits, "hint preserves complete subtree bit count");
    let mut rebuilt = AccountStorageStat::default();
    rebuilt.replace_roots([new_parent.clone()].as_slice().into()).unwrap();
    let expected = rebuilt.calc_dict().unwrap().unwrap().repr_hash().clone();
    assert_eq!(with_hint.calc_dict().unwrap().unwrap().repr_hash(), &expected);
    // Independently reproduced by TOS 5af405d AccountStorageStat with the same
    // forced-pruned leaves: three cells, 96 bits and this committed dictionary.
    assert_eq!(
        expected.to_hex_string(),
        "cded6e98b8c8cc52e4d5c8ce8bacda63bd67f4578c6f98f2d72ea723f9314b38"
    );

    // A hinted cell whose reference count changes needs its actual dictionary
    // entry; the hint proves existence, not a reference count.
    let mut changed_count = AccountStorageStat::default();
    seed(&mut changed_count);
    changed_count.add_hint(&loaded);
    let error = changed_count
        .replace_roots([new_parent.clone(), shared.clone()].as_slice().into())
        .unwrap_err();
    assert_eq!(error.downcast_ref::<ExceptionCode>(), Some(&ExceptionCode::PrunedCellAccess));

    let missing_new_parent = node(12, &[shared.clone()]);
    let error = probe.get(missing_new_parent.repr_hash()).unwrap_err();
    assert_eq!(error.downcast_ref::<ExceptionCode>(), Some(&ExceptionCode::PrunedCellAccess));
    let mut missing_path = AccountStorageStat::default();
    seed(&mut missing_path);
    missing_path.add_hint(&loaded);
    let error = missing_path.replace_roots([missing_new_parent].as_slice().into()).unwrap_err();
    assert_eq!(error.downcast_ref::<ExceptionCode>(), Some(&ExceptionCode::PrunedCellAccess));

    let mut missing_removal_count = AccountStorageStat::default();
    seed(&mut missing_removal_count);
    missing_removal_count.add_hint(&loaded);
    let error = missing_removal_count.remove_cell(&old_parent_pruned).unwrap_err();
    assert_eq!(error.downcast_ref::<ExceptionCode>(), Some(&ExceptionCode::PrunedCellAccess));

    // Providing that entry makes the same nonzero change valid.
    let mut complete = AccountStorageStat::default();
    seed(&mut complete);
    complete.dict = StorageStatDict::with_hashmap(Some(full_dict));
    complete.add_hint(&loaded);
    complete.replace_roots([new_parent.clone(), shared.clone()].as_slice().into()).unwrap();
    let mut rebuilt = AccountStorageStat::default();
    rebuilt.replace_roots([new_parent, shared].as_slice().into()).unwrap();
    assert_eq!(complete.total_cells(), rebuilt.total_cells());
    assert_eq!(complete.total_bits(), rebuilt.total_bits());
    assert_eq!(complete.calc_dict().unwrap(), rebuilt.calc_dict().unwrap());
    assert_eq!(
        complete.calc_dict().unwrap().unwrap().repr_hash().to_hex_string(),
        "ed55b9a98fe55894157039e9c494fb1a84324e6a17b717067037c286fa029be5"
    );
}

#[test]
fn storage_stat_unknown_count_cannot_be_flushed_as_a_deletion() {
    let root = leaf(1);
    let mut stat = AccountStorageStat::default();
    stat.replace_roots([root.clone()].as_slice().into()).unwrap();
    let before = stat.calc_dict().unwrap().cloned();
    let entry = stat.cache.get_mut(root.repr_hash()).unwrap();
    entry.ref_count = None;
    entry.ref_count_diff = 1;
    stat.dict_updated = false;
    let error = stat.calc_dict().unwrap_err();
    assert!(error.to_string().contains("unknown ref_count"));
    assert_eq!(stat.dict.root(), before.as_ref());
}

#[test]
fn storage_stat_hint_preserves_nonzero_merkle_depth() {
    let proof = MerkleProof::create(&leaf(1), |_| true).unwrap().serialize().unwrap();
    let old = node(2, &[proof.clone()]);
    let next = node(3, &[proof.clone()]);
    let mut stat = AccountStorageStat::default();
    stat.replace_roots([old.clone()].as_slice().into()).unwrap();
    stat.calc_dict().unwrap();
    stat.cache.clear();
    stat.add_hint(&[old.repr_hash().clone()].into_iter().collect());
    assert!(stat.hint.contains(old.repr_hash()));
    assert!(!stat.hint.contains(proof.repr_hash()));
    stat.replace_roots([next.clone()].as_slice().into()).unwrap();
    let dict = stat.calc_dict().unwrap().cloned();
    assert_eq!(stat.dict.get(next.repr_hash()).unwrap().unwrap().max_merkle_depth, 1);
    let mut rebuilt = AccountStorageStat::default();
    rebuilt.replace_roots([next].as_slice().into()).unwrap();
    assert_eq!(dict.as_ref(), rebuilt.calc_dict().unwrap());
}

// Independent C++ reference vectors cover every ordered list of up to three roots.
// The graph includes repeated child edges, shared descendants, and roots that are
// themselves descendants of other roots. Compare incremental updates with the
// reference commitment, including when no dictionary has been flushed yet.
#[test]
fn test_storage_root_multiplicity_reference() {
    let shared = leaf(1);
    let a = node(2, &[shared.clone(), shared.clone()]);
    let b = node(3, &[shared.clone(), a.clone()]);
    let c = node(4, &[a.clone(), b.clone(), shared.clone()]);
    let nodes = [shared, a, b, c];
    let mut states: Vec<super::StorageRoots> = vec![Default::default()];
    for n in 1..=3 {
        for k in 0..(1usize << (2 * n)) {
            states.push((0..n).map(|i| nodes[(k >> (2 * i)) & 3].clone()).collect());
        }
    }
    let expected: Vec<_> = include_str!("data/storage_stat/root-multiplicity.tsv")
        .lines()
        .map(|line| {
            let fields: Vec<_> = line.split('\t').collect();
            (
                fields[0].parse::<usize>().unwrap(),
                fields[1].parse::<u64>().unwrap(),
                fields[2].parse::<u64>().unwrap(),
                fields[3].to_ascii_lowercase(),
            )
        })
        .collect();
    assert_eq!(expected.len(), states.len());
    let check = |stat: &mut AccountStorageStat, target: usize, context: &str| {
        let hash = stat
            .calc_dict()
            .unwrap()
            .map(|c| c.repr_hash().to_hex_string())
            .unwrap_or_else(|| "0".repeat(64));
        let (index, cells, bits, expected_hash) = &expected[target];
        assert_eq!(*index, target);
        assert_eq!((stat.total_cells(), stat.total_bits()), (*cells, *bits), "{context}");
        assert_eq!(&hash, expected_hash, "{context}");
    };
    for mode in 0..3 {
        for (from, old) in states.iter().enumerate() {
            for (to, new) in states.iter().enumerate() {
                let mut stat = AccountStorageStat::default();
                stat.replace_roots(old.clone()).unwrap();
                if mode != 0 {
                    stat.calc_dict().unwrap();
                }
                if mode == 2 {
                    // Imported dictionary: only the committed trie has cell counts.
                    stat.cache.clear();
                }
                stat.replace_roots(new.clone()).unwrap();
                check(&mut stat, to, &format!("mode {mode}: {from} -> {to}"));
                // Continue from the updated cache/dictionary, not a fresh instance.
                stat.replace_roots(old.clone()).unwrap();
                check(&mut stat, from, &format!("mode {mode}: {from} -> {to} -> {from}"));
            }
        }
    }
}
