// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::*;
use crate::{
    BuilderData, CellType, IBitstring, Serializable, SigPubKey, UsageTree, ValidatorDescr,
};

fn root(epoch: u32) -> Cell {
    let member = ValidatorDescr::with_params(SigPubKey::from_bytes(&[17; 32]).unwrap(), 1, None);
    ValidatorSet::new(epoch, epoch + 1, 1, vec![member]).unwrap().serialize().unwrap()
}
fn pruned(root: &Cell) -> Cell {
    let mut b = BuilderData::new();
    b.set_type(CellType::PrunedBranch);
    b.append_u8(1).unwrap().append_u8(1).unwrap();
    b.append_raw(root.hash(0).as_slice(), 256).unwrap().append_u16(root.depth(0)).unwrap();
    b.into_cell().unwrap()
}

#[test]
fn cached_hash_resolves_known_pruning_without_changing_the_value() {
    let cache = Mutex::new(Cache::new());
    let full = root(100);
    let partial = pruned(&full).virtualize(1);
    assert_eq!(full.repr_hash(), partial.repr_hash());
    assert!(unpack(partial.clone(), true, &cache).is_err());
    let known = unpack(full.clone(), true, &cache).unwrap();
    let resolved = unpack(partial.clone(), true, &cache).unwrap();
    assert!(Arc::ptr_eq(&known, &resolved));
    assert_eq!(*known, ValidatorSet::construct_from_full_cell(full).unwrap());
    assert!(unpack(partial, false, &cache).is_err());
}

#[test]
fn disabled_cache_does_not_populate_or_refresh_the_shared_state() {
    let cache = Mutex::new(Cache::new());
    let full = root(101);
    unpack(full.clone(), false, &cache).unwrap();
    assert!(cache.lock().unwrap().values.is_empty());
    assert!(unpack(pruned(&full).virtualize(1), true, &cache).is_err());
    for epoch in 0..100 {
        unpack(root(epoch), true, &cache).unwrap();
    }
    let oldest = root(0);
    let original = cache.lock().unwrap().values.get(oldest.repr_hash()).unwrap().clone();
    let uncached = unpack(oldest.clone(), false, &cache).unwrap();
    assert!(!Arc::ptr_eq(&original, &uncached));
    unpack(root(100), true, &cache).unwrap();
    assert!(unpack(pruned(&oldest).virtualize(1), true, &cache).is_err());
}

#[test]
fn hundred_entry_lru_refreshes_hits_and_keeps_outstanding_values_alive() {
    let cache = Mutex::new(Cache::new());
    let roots: Vec<_> = (0..=100).map(root).collect();
    let first = unpack(roots[0].clone(), true, &cache).unwrap();
    for cell in &roots[1..100] {
        unpack(cell.clone(), true, &cache).unwrap();
    }
    assert!(Arc::ptr_eq(&first, &unpack(pruned(&roots[0]).virtualize(1), true, &cache).unwrap()));
    unpack(roots[100].clone(), true, &cache).unwrap();
    assert!(unpack(pruned(&roots[1]).virtualize(1), true, &cache).is_err());
    assert!(unpack(pruned(&roots[0]).virtualize(1), true, &cache).is_ok());
    assert_eq!(cache.lock().unwrap().values.len(), 100);
    assert_eq!(cache.lock().unwrap().newest.len(), 100);
    assert_eq!(first.total_weight(), 1);
}

#[test]
fn usage_roots_bypass_both_lookup_and_insertion() {
    let cache = Mutex::new(Cache::new());
    let public_key = vec![31; 1312];
    let member = ValidatorDescr::with_pq_params(
        UInt256::from([42; 32]),
        crate::PqConsensusKey {
            algorithm_id: 1,
            key_id: crate::derive_consensus_key_id(1, &public_key),
            public_key,
        },
        1,
        UInt256::from([43; 32]),
    );
    let full = ValidatorSet::new(200, 201, 1, vec![member]).unwrap().serialize().unwrap();
    let known = unpack(full.clone(), true, &cache).unwrap();
    let child = full.reference(0).unwrap();
    let tree = UsageTree::with_root(full.clone());
    assert!(!tree.contains(child.repr_hash()));
    let decoded = unpack(tree.root_cell(), true, &cache).unwrap();
    assert!(!Arc::ptr_eq(&known, &decoded));
    assert!(tree.contains(child.repr_hash()));
    let mut cells = vec![full.clone()];
    let mut seen = std::collections::HashSet::new();
    while let Some(cell) = cells.pop() {
        if !seen.insert(cell.repr_hash().clone()) {
            continue;
        }
        assert!(tree.contains(cell.repr_hash()), "cached decoding skipped a proof cell");
        for i in 0..cell.references_count() {
            cells.push(cell.reference(i).unwrap());
        }
    }
    assert!(seen.len() > 10);
    assert!(Arc::ptr_eq(&known, &cache.lock().unwrap().get(full.repr_hash()).unwrap()));
    let missing = UsageTree::with_root(pruned(&full));
    assert!(unpack(missing.root_cell().virtualize(1), true, &cache).is_err());
    let other = root(201);
    let other_tree = UsageTree::with_root(other.clone());
    unpack(other_tree.root_cell(), true, &cache).unwrap();
    assert!(unpack(pruned(&other).virtualize(1), true, &cache).is_err());
}

#[test]
fn lazy_root_load_errors_are_not_hidden_by_cached_hashes() {
    let cache = Mutex::new(Cache::new());
    let full = root(300);
    unpack(full.clone(), true, &cache).unwrap();
    let lazy =
        Cell::lazy_from_pruned(&pruned(&full), Arc::new(|_| Err(error!("test load failure"))), 0)
            .unwrap();
    let error = unpack(lazy, true, &cache).unwrap_err();
    assert!(error.to_string().contains("test load failure"));
}

#[test]
fn usage_tracking_behind_a_lazy_root_is_preserved() {
    let cache = Mutex::new(Cache::new());
    let full = root(301);
    let known = unpack(full.clone(), true, &cache).unwrap();
    let tree = UsageTree::with_root(full.clone());
    let tracked = tree.root_cell();
    let lazy =
        Cell::lazy_from_pruned(&pruned(&full), Arc::new(move |_| Ok(tracked.clone())), 0).unwrap();
    let decoded = unpack(lazy, true, &cache).unwrap();
    assert!(!Arc::ptr_eq(&known, &decoded));
    assert!(tree.contains(full.reference(0).unwrap().repr_hash()));
}
