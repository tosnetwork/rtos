// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Thin adapter: all configuration/state derivations spend the caller's request.
use crate::{history_read_budget::HistoryReadBudget, shard_state::ShardStateStuff};
use rtos_block::{
    config_read_budget::{self as cb, ConfigReadBudget},
    error, BlockIdExt, Result, ShardIdent,
};
use std::sync::Arc;

pub(crate) struct ConfigBudget<'a>(pub &'a HistoryReadBudget);
impl ConfigReadBudget for ConfigBudget<'_> {
    fn step(&self) -> Result<()> {
        rtos_block::merkle_apply_budget::MerkleApplyBudget::step(self.0)
    }
    fn workspace(&self, bytes: usize) -> Result<()> {
        rtos_block::merkle_apply_budget::MerkleApplyBudget::workspace(self.0, bytes)
    }
}
pub(crate) fn authenticated_start_parents(
    state: &ShardStateStuff,
    target: &ShardIdent,
    request: &Arc<HistoryReadBudget>,
) -> Result<Vec<BlockIdExt>> {
    let budget = ConfigBudget(request);
    let mut output = cb::vector(&budget, 2)?;
    if target.is_masterchain() {
        output.push(state.block_id().clone());
        return Ok(output);
    }
    parents_for_hashes(state.shard_state_extra()?.shards(), target, &budget)
}
fn parents_for_hashes(
    hashes: &rtos_block::ShardHashes,
    target: &ShardIdent,
    budget: &dyn ConfigReadBudget,
) -> Result<Vec<BlockIdExt>> {
    let mut output = cb::vector(budget, 2)?;
    let mut matches: Option<[Option<BlockIdExt>; 2]> = None;
    let mut merge = false;
    hashes.iterate_workchain_bounded(target.workchain_id(), budget, |ident, descr| {
        let top =
            BlockIdExt::with_params(ident.clone(), descr.seq_no, descr.root_hash, descr.file_hash);
        if descr.before_split {
            let (left, right) = ident.split()?;
            if &left == target || &right == target {
                matches = Some([Some(top), None]);
                merge = false;
            }
        } else if descr.before_merge {
            let parent = ident.merge()?;
            if &parent == target {
                let (_, right) = parent.split()?;
                let entries = matches.get_or_insert_with(|| [None, None]);
                entries[usize::from(right == ident)] = Some(top);
                merge = true;
            }
        } else if &ident == target {
            matches = Some([Some(top), None]);
            merge = false;
        }
        Ok(())
    })?;
    let [left, right] =
        matches.ok_or_else(|| error!("Retired session shard absent from authenticated start"))?;
    output.push(left.ok_or_else(|| error!("Incomplete authenticated merge parents"))?);
    if merge {
        output.push(right.ok_or_else(|| error!("Incomplete authenticated merge parents"))?);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtos_block::{ShardHashes, UInt256};
    #[test]
    fn bounded_config_parents_normal_split_merge_and_holes() {
        let request = HistoryReadBudget::new(Default::default());
        let budget = ConfigBudget(&request);
        let mut hashes = ShardHashes::default();
        hashes.add_workchain(0, 0, UInt256::from([1; 32]), UInt256::from([2; 32])).unwrap();
        let full = ShardIdent::with_workchain_id(0).unwrap();
        let ordinary = parents_for_hashes(&hashes, &full, &budget).unwrap();
        assert_eq!(ordinary.len(), 1);
        hashes
            .update_shard(&full, |mut d| {
                d.before_split = true;
                Ok(d)
            })
            .unwrap();
        let (left, right) = full.split().unwrap();
        assert_eq!(parents_for_hashes(&hashes, &left, &budget).unwrap(), ordinary);
        assert_eq!(parents_for_hashes(&hashes, &right, &budget).unwrap(), ordinary);
        hashes
            .split_shard(&full, |mut d| {
                d.before_split = false;
                d.before_merge = true;
                Ok((d.clone(), d))
            })
            .unwrap();
        let merged = parents_for_hashes(&hashes, &full, &budget).unwrap();
        assert_eq!(
            merged.iter().map(|b| b.shard().clone()).collect::<Vec<_>>(),
            vec![left.clone(), right.clone()]
        );
        hashes
            .update_shard(&right, |mut d| {
                d.before_merge = false;
                Ok(d)
            })
            .unwrap();
        assert!(parents_for_hashes(&hashes, &full, &budget).is_err());
    }
}
