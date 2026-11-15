// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Append-only archive writer. Admission covers Rust workspace and logical
//! batch payload; native RocksDB caches and allocator overhead are excluded.
use super::*;
use crate::{db::DbKey, dynamic_boc_rc_db::BoundedStateWriteFailure, types::serialize_stored_cell};
use rtos_block::{
    error, fail,
    merkle_apply_budget::{require_materialized, BudgetMap, BudgetStack, MerkleApplyLimitExceeded},
};

pub(super) fn write(
    index: &RocksDbTable<BlockIdExt>,
    boc: &DynamicBocArchiveDb,
    id: &BlockIdExt,
    root: Cell,
    limits: MerkleApplyLimits,
    budget: &dyn MerkleApplyBudget,
    observer: Option<&crate::durability::SyncObserver>,
) -> Result<()> {
    require_materialized(&root)?;
    budget.workspace(DbEntry::SIZE)?;
    let metadata = index.try_get(id)?;
    if let Some(raw) = &metadata {
        if raw.len() != DbEntry::SIZE {
            fail!("Archive bounded index length");
        }
        let entry = DbEntry::deserialize(raw)?;
        if &entry.block_id != id || &entry.cell_id != root.repr_hash() {
            fail!("Archive bounded index identity");
        }
    }
    let depth_limit = limits.max_depth.min(budget.max_depth());
    if root.repr_depth() > depth_limit {
        return Err(MerkleApplyLimitExceeded("archive writer depth").into());
    }
    let cells = boc.cell_db();
    let cf = cells.cells_cf()?;
    let mut entries = BudgetMap::new(limits.max_entries);
    let mut stack = BudgetStack::new(usize::from(depth_limit) * 4 + 1);
    stack.push((root.clone(), 0u16), budget)?;
    while let Some((cell, depth)) = stack.pop() {
        budget.step()?;
        require_materialized(&cell)?;
        if depth > depth_limit {
            return Err(MerkleApplyLimitExceeded("archive writer depth").into());
        }
        let hash = cell.repr_hash().clone();
        if entries.get(&hash, budget)?.is_some() {
            continue;
        }
        budget.workspace(2048)?;
        let raw = cells.db().get_pinned_cf(&cf, hash.as_slice())?;
        let existing = raw.is_some();
        if let Some(raw) = raw {
            if raw.len() > 1024 {
                fail!("Archive bounded cell length");
            }
            if raw.as_ref() != serialize_stored_cell(&cell)?.as_slice() {
                fail!("Archive cell differs from candidate");
            }
        }
        entries.insert(hash, (cell.clone(), existing), budget)?;
        for i in 0..cell.references_count() {
            budget.step()?;
            stack.push(
                (
                    cell.reference(i)?,
                    depth.checked_add(1).ok_or_else(|| error!("Archive writer depth overflow"))?,
                ),
                budget,
            )?;
        }
    }
    let root_exists = entries.get(root.repr_hash(), budget)?.unwrap().1;
    if metadata.is_some() && !root_exists {
        fail!("Archive existing index has missing root");
    }
    for (_, (cell, existing)) in entries.iter() {
        budget.step()?;
        for i in 0..cell.references_count() {
            budget.step()?;
            let child = cell.reference_repr_hash(i)?;
            if *existing && !entries.get(&child, budget)?.unwrap().1 {
                fail!("Archive existing parent has missing child");
            }
        }
    }
    budget.workspace(1024)?;
    let mut batch = rocksdb::WriteBatch::default();
    for (hash, (cell, existing)) in entries.iter() {
        budget.step()?;
        if !existing {
            let raw = serialize_stored_cell(cell)?;
            if raw.len() > 1024 {
                fail!("Archive serialized cell length");
            }
            batch.put_cf(&cf, hash.as_slice(), raw);
        }
    }
    if metadata.is_none() {
        let entry = DbEntry::with_params(id.clone(), root.repr_hash().clone(), UnixTime::now());
        index.put_in_batch(&mut batch, id.key(), &entry.serialize())?;
    }
    cells.db().write(batch).map_err(|e| BoundedStateWriteFailure(e.into()))?;
    cells.db().sync_wal_observed(observer).map_err(BoundedStateWriteFailure)?;
    Ok(())
}
