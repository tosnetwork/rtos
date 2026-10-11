// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Serialized state-writer path with request admission before graph workspace,
//! cell serialization and logical WriteBatch allocation. Native RocksDB caches
//! and allocator bookkeeping are not included in these byte charges.
use super::*;
use rtos_block::merkle_apply_budget::{
    require_materialized, BudgetMap, BudgetStack, MerkleApplyBudget, MerkleApplyLimitExceeded,
    MerkleApplyLimits,
};

struct Entry {
    cell: Cell,
    existing: bool,
    base: u32,
    inc: u32,
}
const WRITE_CELL_ALLOCATION: usize = 2048;

impl DynamicBocDb {
    pub(crate) fn save_boc_bounded(
        &self,
        root: &Cell,
        limits: MerkleApplyLimits,
        budget: &dyn MerkleApplyBudget,
        add_root_ref: bool,
        observer: Option<&crate::durability::SyncObserver>,
        extra_ops: impl FnOnce(&mut rocksdb::WriteBatch) -> Result<()>,
    ) -> Result<()> {
        require_materialized(root)?;
        let depth_limit = limits.max_depth.min(budget.max_depth());
        if root.repr_depth() > depth_limit {
            return Err(MerkleApplyLimitExceeded("writer graph depth").into());
        }
        let cells_cf = self.cell_db.cells_cf()?;
        let counters_cf = self.counters_cf()?;
        let mut entries = BudgetMap::new(limits.max_entries);
        let mut order = BudgetStack::new(limits.max_entries);
        let mut stack = BudgetStack::new(usize::from(depth_limit) * 4 + 1);
        stack.push((root.clone(), 0u16), budget)?;
        while let Some((cell, depth)) = stack.pop() {
            budget.step()?;
            require_materialized(&cell)?;
            if depth > depth_limit {
                return Err(MerkleApplyLimitExceeded("writer depth").into());
            }
            let hash = cell.repr_hash().clone();
            if entries.get(&hash, budget)?.is_some() {
                continue;
            }
            // Raw storage is pinned by RocksDB; reject oversized/malformed
            // records before any Rust deserialization/copy of those records.
            budget.workspace(WRITE_CELL_ALLOCATION)?;
            let raw = self.cell_db.db().get_pinned_cf(&cells_cf, hash.as_slice())?;
            let counter = self.cell_db.db().get_pinned_cf(&counters_cf, hash.as_slice())?;
            let base = match (&raw, &counter) {
                (None, None) => 0,
                (Some(raw), Some(counter)) if raw.len() <= 1024 && counter.len() == 4 => {
                    let expected = serialize_stored_cell(&cell)?;
                    if raw.as_ref() != expected.as_slice() {
                        fail!(
                            "Existing bounded cell differs from authenticated candidate {hash:x}"
                        );
                    }
                    let value = u32::from_le_bytes(counter[..].try_into().unwrap());
                    if value == 0 || value > MAX_REFCNT {
                        fail!("Invalid existing bounded counter");
                    }
                    value
                }
                _ => fail!("Incomplete existing bounded cell/counter {hash:x}"),
            };
            entries.insert(
                hash.clone(),
                Entry { cell: cell.clone(), existing: base != 0, base, inc: 0 },
                budget,
            )?;
            order.push(hash, budget)?;
            for index in 0..cell.references_count() {
                budget.step()?;
                stack.push(
                    (
                        cell.reference(index)?,
                        depth
                            .checked_add(1)
                            .ok_or(MerkleApplyLimitExceeded("writer depth overflow"))?,
                    ),
                    budget,
                )?;
            }
        }
        let root_exists = entries.get(root.repr_hash(), budget)?.unwrap().existing;
        if !root_exists && !add_root_ref {
            fail!("Existing bounded state index has missing root; reference ownership is unknown");
        }
        if !root_exists || add_root_ref {
            let entry = entries.get_mut(root.repr_hash(), budget)?.unwrap();
            if entry.base >= MAX_REFCNT {
                fail!("Bounded root reference count overflow");
            }
            entry.inc = 1;
        }
        // Count each edge from a newly stored parent exactly once. A previously
        // stored parent already owns all its references; do not increment them.
        while let Some(hash) = order.pop() {
            budget.step()?;
            let entry = entries.get(&hash, budget)?.unwrap();
            let existing = entry.existing;
            let cell = entry.cell.clone();
            if root_exists && !existing {
                fail!("Existing bounded root has missing descendant");
            }
            for i in 0..cell.references_count() {
                budget.step()?;
                let child_hash = cell.reference_repr_hash(i)?;
                let child = entries
                    .get_mut(&child_hash, budget)?
                    .ok_or_else(|| error!("Missing bounded writer child"))?;
                if existing && !child.existing {
                    fail!("Existing bounded parent has missing descendant");
                }
                if !root_exists && !existing {
                    child.inc = child
                        .inc
                        .checked_add(1)
                        .ok_or_else(|| error!("Bounded reference count overflow"))?;
                    if child.base.checked_add(child.inc).is_none_or(|n| n > MAX_REFCNT) {
                        fail!("Bounded reference count overflow");
                    }
                }
            }
        }
        // Admission includes batch header and state-index record before the
        // native batch is created. Per-cell charges above cover its payload.
        budget.workspace(1024)?;
        let mut batch = rocksdb::WriteBatch::default();
        for (hash, entry) in entries.iter() {
            budget.step()?;
            if !root_exists && !entry.existing {
                if entry.inc == 0 {
                    fail!("Unreferenced bounded cell");
                }
                let bytes = serialize_stored_cell(&entry.cell)?;
                if bytes.len() > 1024 {
                    fail!("Oversized serialized bounded cell");
                }
                batch.put_cf(&cells_cf, hash.as_slice(), &bytes);
                batch.put_cf(&counters_cf, hash.as_slice(), entry.inc.to_le_bytes());
            } else if entry.inc > 0 {
                batch.merge_cf(&counters_cf, hash.as_slice(), entry.inc.to_le_bytes());
            }
        }
        extra_ops(&mut batch)?;
        // No mutation before all admission/validation has completed.
        self.cell_db.db().write(batch).map_err(|e| BoundedStateWriteFailure(e.into()))?;
        for (hash, entry) in entries.iter() {
            // No fallible budget operation after commit: invalidation itself
            // cannot allocate or visit any graph. The writer owns all entries.
            if !entry.existing || entry.inc > 0 {
                self.cell_counter_cache.remove(hash);
                self.cell_db.remove_from_cache(hash);
            }
        }
        self.cell_db.db().sync_wal_observed(observer).map_err(BoundedStateWriteFailure)?;
        Ok(())
    }
}
