// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{write_boc, BuilderData, CellLoader, MerkleUpdate};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

struct Budget {
    max: [usize; 3],
    used: [AtomicUsize; 3],
    depth: u16,
}
impl Budget {
    fn new(max: [usize; 3]) -> Self {
        Self { max, used: std::array::from_fn(|_| AtomicUsize::new(0)), depth: 1024 }
    }
    fn charge(&self, kind: usize, n: usize) -> Result<()> {
        let prior = self.used[kind].load(Ordering::SeqCst);
        let next = prior.checked_add(n).ok_or(MerkleApplyLimitExceeded("test overflow"))?;
        if next > self.max[kind] {
            return Err(MerkleApplyLimitExceeded("test quota").into());
        }
        self.used[kind].store(next, Ordering::SeqCst);
        Ok(())
    }
    fn totals(&self) -> [usize; 3] {
        std::array::from_fn(|i| self.used[i].load(Ordering::SeqCst))
    }
}
impl MerkleApplyBudget for Budget {
    fn step(&self) -> Result<()> {
        self.charge(0, 1)
    }
    fn workspace(&self, bytes: usize) -> Result<()> {
        self.charge(1, bytes)
    }
    fn new_cell(&self, bytes: usize) -> Result<()> {
        self.charge(2, bytes)
    }
    fn max_depth(&self) -> u16 {
        self.depth
    }
}
fn cell(tag: u8, refs: &[Cell]) -> Cell {
    let mut builder = BuilderData::with_raw(vec![tag], 8).unwrap();
    for child in refs {
        builder.checked_append_reference(child.clone()).unwrap();
    }
    builder.into_cell().unwrap()
}
fn fixture() -> (Cell, Cell, MerkleUpdate) {
    let shared = cell(1, &[]);
    let old = cell(2, &[cell(3, &[shared.clone()]), shared.clone()]);
    let new = cell(4, &[old.reference(0).unwrap(), cell(5, &[shared])]);
    let update = MerkleUpdate::create(&old, &new).unwrap();
    (old, new, update)
}
const LIMITS: MerkleApplyLimits = MerkleApplyLimits { max_entries: 512, max_depth: 1024 };

#[test]
fn bounded_merkle_apply_matches_pruned_dag_and_exact_quotas() -> Result<()> {
    let (old, expected, update) = fixture();
    let budget = Budget::new([usize::MAX; 3]);
    let (actual, _) = update.apply_for_bounded(&old, &LIMITS, &budget)?;
    assert_eq!(write_boc(&actual)?, write_boc(&expected)?);
    assert_eq!(write_boc(&actual)?, write_boc(&update.apply_for(&old)?.0)?);
    let totals = budget.totals();
    assert!(totals.iter().all(|n| *n > 0));
    update.apply_for_bounded(&old, &LIMITS, &Budget::new(totals))?;
    for category in 0..3 {
        let mut max = totals;
        max[category] -= 1;
        assert!(update.apply_for_bounded(&old, &LIMITS, &Budget::new(max)).is_err());
    }
    Ok(())
}

#[test]
fn bounded_merkle_apply_rejects_loader_before_invocation_and_zero_admission() -> Result<()> {
    let (old, _, update) = fixture();
    let calls = Arc::new(AtomicUsize::new(0));
    let hits = calls.clone();
    let loader: CellLoader = Arc::new(move |_| {
        hits.fetch_add(1, Ordering::SeqCst);
        Err(error!("unexpected ambient loader"))
    });
    let loaded = Cell::with_cell_and_loader(old.clone(), &loader, None)?;
    assert!(update.apply_for_bounded(&loaded, &LIMITS, &Budget::new([usize::MAX; 3])).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let budget = Budget::new([usize::MAX, 0, usize::MAX]);
    assert!(update.apply_for_bounded(&old, &LIMITS, &budget).is_err());
    assert_eq!(budget.totals()[2], 0, "workspace rejection precedes all candidate cell allocation");
    let before = Cell::test_heap_allocations();
    let budget = Budget::new([usize::MAX, usize::MAX, 0]);
    assert!(update.apply_for_bounded(&old, &LIMITS, &budget).is_err());
    assert_eq!(budget.totals()[2], 0);
    assert_eq!(
        Cell::test_heap_allocations(),
        before,
        "zero candidate quota must precede actual cell allocator calls"
    );
    Ok(())
}

#[test]
fn bounded_merkle_apply_depth_identity_and_container_limits() -> Result<()> {
    let mut old = cell(1, &[]);
    for i in 0..128 {
        old = cell(i, &[old]);
    }
    let new = cell(255, &[old.clone(), old.clone()]);
    let update = MerkleUpdate::create(&old, &new)?;
    let budget = Budget::new([usize::MAX; 3]);
    let exact = MerkleApplyLimits { max_entries: 512, max_depth: new.repr_depth() };
    assert_eq!(update.apply_for_bounded(&old, &exact, &budget)?.0, new);
    let short = MerkleApplyLimits { max_depth: exact.max_depth - 1, ..exact };
    assert!(update.apply_for_bounded(&old, &short, &Budget::new([usize::MAX; 3])).is_err());
    let empty = MerkleApplyLimits { max_entries: 0, ..exact };
    assert!(update.apply_for_bounded(&old, &empty, &Budget::new([usize::MAX; 3])).is_err());
    let identity = MerkleUpdate::create(&old, &old)?;
    assert_eq!(
        identity.apply_for_bounded(&old, &LIMITS, &Budget::new([usize::MAX, usize::MAX, 0]))?.0,
        old
    );
    Ok(())
}

#[test]
fn bounded_merkle_apply_cell_allocation_layout_upper_bound() -> Result<()> {
    let mut child = cell(1, &[]);
    for depth in 0..3 {
        child = MerkleUpdate::make_pruned_branch_cell(&child, depth)?.into_cell()?;
    }
    let mut builder = BuilderData::with_raw(vec![0xff; 128], 1023)?;
    for _ in 0..4 {
        builder.checked_append_reference(child.clone())?;
    }
    let maximal = builder.into_cell()?;
    assert_eq!(maximal.level_mask().mask(), 7);
    assert_eq!(maximal.references_count(), 4);
    assert_eq!(maximal.bit_length(), 1023);
    assert!(maximal.alloc_size() <= NEW_CELL_ALLOCATION);
    Ok(())
}

#[test]
fn bounded_merkle_apply_shared_cell_merkle_depth_traversal_order() -> Result<()> {
    use crate::{MerkleProof, Serializable};
    let leaf = cell(9, &[]);
    let pruned = MerkleUpdate::make_pruned_branch_cell(&leaf, 0)?.into_cell()?;
    let shared = cell(10, &[pruned]);
    let proof =
        MerkleProof { hash: shared.hash(0).clone(), depth: shared.depth(0), proof: shared.clone() }
            .serialize()?;
    for refs in [[shared.clone(), proof.clone()], [proof.clone(), shared.clone()]] {
        let old = cell(11, &refs);
        let new = cell(12, &refs);
        let update = MerkleUpdate {
            old_hash: old.repr_hash().clone(),
            new_hash: new.repr_hash().clone(),
            old_depth: old.repr_depth(),
            new_depth: new.repr_depth(),
            old: old.clone(),
            new: new.clone(),
        };
        let ordinary = update.apply_for(&old);
        let bounded = update.apply_for_bounded(&old, &LIMITS, &Budget::new([usize::MAX; 3]));
        let ordinary = ordinary.map_err(|e| error!("ordinary baseline: {e:#}"))?;
        let bounded = bounded.map_err(|e| error!("bounded baseline: {e:#}"))?;
        let reversed = with_reversed_dfs_for_test(|| {
            update.apply_for_bounded(&old, &LIMITS, &Budget::new([usize::MAX; 3]))
        })?;
        assert_eq!(write_boc(&ordinary.0)?, write_boc(&reversed.0)?);
        assert_eq!(write_boc(&ordinary.0)?, write_boc(&bounded.0)?);
        assert_eq!(ordinary.0.repr_depth(), bounded.0.repr_depth());
    }
    Ok(())
}
