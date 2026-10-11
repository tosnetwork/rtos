// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
impl ShardHashes {
    /// Bounded traversal of one workchain, charging each path (not unique cells).
    /// The DFS stack has at most MAX_SPLIT_DEPTH+1 outstanding right branches.
    pub fn iterate_workchain_bounded<F>(
        &self,
        workchain: i32,
        budget: &dyn crate::config_read_budget::ConfigReadBudget,
        mut visitor: F,
    ) -> Result<()>
    where
        F: FnMut(ShardIdent, ShardDescr) -> Result<()>,
    {
        use crate::config_read_budget as cb;
        cb::lookup(budget, 32)?;
        let Some(InRefValue(tree)) = self.get(&workchain)? else {
            return Ok(());
        };
        let mut stack = cb::vector::<(ShardIdent, SliceData, usize)>(
            budget,
            crate::MAX_SPLIT_DEPTH as usize + 1,
        )?;
        stack.push((ShardIdent::with_workchain_id(workchain)?, tree.get_data(), 0));
        while let Some((ident, mut slice, depth)) = stack.pop() {
            budget.step()?;
            if slice.get_next_bit()? {
                if depth >= crate::MAX_SPLIT_DEPTH as usize {
                    fail!("Shard tree exceeds prefix depth");
                }
                let (left, right) = ident.split()?;
                let left_cell = slice.checked_drain_reference()?;
                let right_cell = slice.checked_drain_reference()?;
                stack.push((right, SliceData::load_cell(right_cell)?, depth + 1));
                stack.push((left, SliceData::load_cell(left_cell)?, depth + 1));
            } else {
                // Coins uses the u128 decoder (types.rs), with a [u8;16]
                // stack buffer. Extra currencies remain dictionary views;
                // their VarUInteger32 values are not decoded here.
                visitor(ident, ShardDescr::construct_from(&mut slice)?)?;
            }
        }
        Ok(())
    }
    pub fn calc_shard_cc_seqno_bounded(
        &self,
        shard: &ShardIdent,
        budget: &dyn crate::config_read_budget::ConfigReadBudget,
    ) -> Result<u32> {
        // Two lookups by fixed 32-bit workchain and <=60-bit shard prefix.
        // find_shard never enumerates subtrees; charge both paths in advance.
        for _ in 0..2 {
            crate::config_read_budget::lookup(budget, 32)?;
            crate::config_read_budget::lookup(budget, crate::MAX_SPLIT_DEPTH as usize)?;
        }
        self.calc_shard_cc_seqno(shard)
    }
}

impl OldMcBlocksInfo {
    pub fn get_next_key_block_bounded(
        &self,
        req_seqno: u32,
        budget: &dyn crate::config_read_budget::ConfigReadBudget,
    ) -> Result<Option<ExtBlkRef>> {
        let found =
            self.traverse_slices_bounded(budget, |key_prefix, key_prefix_len, mut raw| {
                // KeyMaxLt and KeyExtBlkRef consist only of fixed scalars.
                let aug = KeyMaxLt::construct_from(&mut raw)?;
                let value_opt = if key_prefix_len == 32 {
                    Some(KeyExtBlkRef::construct_from(&mut raw)?)
                } else {
                    None
                };
                if !aug.key {
                    // no key blocks in subtree, skip
                    return Ok(TraverseNextStep::Stop);
                }

                let x = Self::build_key_part(key_prefix, key_prefix_len)?;
                let d = 32 - key_prefix_len;
                if d == 0 {
                    return if x >= req_seqno {
                        let value = value_opt.ok_or_else(|| {
                            error!(BlockError::InvalidData(
                                "OldMcBlocksInfo's node with max key length doesn't have value"
                                    .to_string()
                            ))
                        })?;
                        Ok(TraverseNextStep::End(value))
                    } else {
                        Ok(TraverseNextStep::Stop)
                    };
                }
                let y = req_seqno >> (d - 1);
                match y.cmp(&(2 * x + 1)) {
                    std::cmp::Ordering::Greater => {
                        // ((x + 1) << d) <= req_seqno <=> (x+1) <= (req_seqno >> d) = (y >> 1) <=> 2*x+2 <= y <=> y > 2*x+1
                        Ok(TraverseNextStep::Stop) // all nodes in subtree have block.seqno < req_seqno => skip
                    }
                    std::cmp::Ordering::Equal => {
                        Ok(TraverseNextStep::VisitOne) // visit only right ("1")
                    }
                    _ => {
                        Ok(TraverseNextStep::VisitZeroOne) // visit left, then right ("0" then "1")
                    }
                }
            })?;

        if let Some(id) = found {
            if id.blk_ref.seq_no < req_seqno || !id.key {
                fail!("Invalid next key-block index entry");
            }
            Ok(Some(id.blk_ref))
        } else {
            Ok(None)
        }
    }
}
