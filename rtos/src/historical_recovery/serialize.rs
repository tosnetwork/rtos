// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Single-root BOC with explicit pre-allocation accounting. No ordinary writer
//! hash tables, recursion, external cell loaders, or ambient allocation policy.
use crate::history_read_budget::{HistoryReadBudget, ReadKind};
use rtos_block::{
    error, fail,
    merkle_apply_budget::{require_materialized, BudgetMap, BudgetStack, MerkleApplyBudget},
    Cell, Result,
};
use std::sync::Arc;

pub(super) fn serialize(root: &Cell, budget: &Arc<HistoryReadBudget>) -> Result<Vec<u8>> {
    let limit = budget.limits().cells.min(u32::MAX as usize);
    let mut indexes = BudgetMap::new(limit);
    let mut stack = BudgetStack::new(limit.saturating_mul(5));
    let mut order = BudgetStack::new(limit);
    stack.push((root.clone(), false), budget.as_ref())?;
    let mut payload = 0usize;
    while let Some((cell, finish)) = stack.pop() {
        budget.step()?;
        require_materialized(&cell)?;
        if cell.virtualization() != 0 || cell.repr_depth() > budget.limits().depth {
            fail!("Historical serialization requires bounded materialized cells");
        }
        if indexes.get(cell.repr_hash(), budget.as_ref())?.is_some() {
            continue;
        }
        if !finish {
            stack.push((cell.clone(), true), budget.as_ref())?;
            for index in (0..cell.references_count()).rev() {
                stack.push((cell.reference(index)?, false), budget.as_ref())?;
            }
        } else {
            let index = u32::try_from(indexes.len())?;
            indexes.insert(cell.repr_hash().clone(), index, budget.as_ref())?;
            payload = payload
                .checked_add(cell.raw_data()?.len())
                .and_then(|n| n.checked_add(cell.references_count() * 4))
                .ok_or_else(|| error!("Historical BOC length overflow"))?;
            order.push(cell, budget.as_ref())?;
        }
    }
    // Generic BOC, fixed four-byte cell indexes, eight-byte payload length,
    // one root, no absent cells/index/CRC. Raw cell descriptors preserve hashes.
    let length = 30usize.checked_add(payload).ok_or_else(|| error!("Historical BOC overflow"))?;
    let reservation = budget.reserve(ReadKind::State, length)?;
    if reservation.allowance() != length {
        fail!("Historical BOC output exceeds request budget");
    }
    budget.workspace(length)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length)?;
    bytes.extend_from_slice(&0xb5ee9c72u32.to_be_bytes());
    bytes.extend_from_slice(&[4, 8]);
    let count = u32::try_from(indexes.len())?;
    bytes.extend_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&(payload as u64).to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    while let Some(cell) = order.pop() {
        budget.step()?;
        bytes.extend_from_slice(cell.raw_data()?);
        for index in 0..cell.references_count() {
            let child = cell.reference(index)?;
            let reversed = *indexes
                .get(child.repr_hash(), budget.as_ref())?
                .ok_or_else(|| error!("Historical BOC child missing"))?;
            bytes.extend_from_slice(&(count - 1 - reversed).to_be_bytes());
        }
    }
    if bytes.len() != length {
        fail!("Historical BOC serialization length mismatch");
    }
    reservation.finish(&bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history_read_budget::HistoryReadLimits;
    use rtos_block::BuilderData;
    #[test]
    fn historical_bounded_large_snapshot_uses_default_request_budget_twice() -> Result<()> {
        // Match the multipart Engine fixture's real, non-deduplicated graph.
        // This isolates default request accounting; it is not an Engine test.
        let mut level = (0..18_000u32)
            .map(|index| {
                let mut bytes = vec![0x63; 127];
                bytes[..4].copy_from_slice(&index.to_be_bytes());
                BuilderData::with_raw(bytes, 127 * 8)?.into_cell()
            })
            .collect::<Result<Vec<_>>>()?;
        while level.len() > 1 {
            level = level
                .chunks(2)
                .map(|children| {
                    if children.len() == 1 {
                        return Ok(children[0].clone());
                    }
                    let mut parent = BuilderData::new();
                    for child in children {
                        parent.checked_append_reference(child.clone())?;
                    }
                    parent.into_cell()
                })
                .collect::<Result<Vec<_>>>()?;
        }
        let root = level.pop().unwrap();
        let raw = rtos_block::write_boc(&root)?;
        assert!(raw.len() > 2 << 20);
        let budget = HistoryReadBudget::new(HistoryReadLimits::default());
        assert_eq!(budget.limits().steps, 4_000_000);
        assert_eq!(budget.limits().cell_bytes, 128 << 20);
        let first = budget.parse_boc(&raw)?;
        let retained = serialize(&first, &budget)?;
        let second = budget.parse_boc(&retained)?;
        assert_eq!(root.repr_hash(), second.repr_hash());
        assert_eq!(root.repr_depth(), second.repr_depth());
        // A reused owner must eventually refuse; never silently reset quotas.
        let mut refused = false;
        for _ in 0..4 {
            match budget.parse_boc(&retained) {
                Ok(_) => (),
                Err(error) => {
                    assert!(crate::history_read_budget::stops_fallback(&error), "{error:#}");
                    refused = true;
                    break;
                }
            }
        }
        assert!(refused, "repeated physical decoding escaped the cumulative budget");
        assert!(budget.parse_boc(&retained).is_err());
        Ok(())
    }

    #[test]
    fn historical_bounded_serialization_roundtrips_shared_dag() -> Result<()> {
        let leaf = Cell::default();
        let mut parent = BuilderData::new();
        parent.checked_append_reference(leaf.clone())?;
        parent.checked_append_reference(leaf)?;
        let root = parent.into_cell()?;
        let bytes = serialize(&root, &HistoryReadBudget::new(HistoryReadLimits::default()))?;
        let recovered = rtos_block::read_single_root_boc(&bytes)?;
        assert_eq!(root.repr_hash(), recovered.repr_hash());
        assert_eq!(root.repr_depth(), recovered.repr_depth());
        let mut limits = HistoryReadLimits::default();
        limits.cell_bytes = 0;
        assert!(serialize(&root, &HistoryReadBudget::new(limits)).is_err());
        Ok(())
    }
}
