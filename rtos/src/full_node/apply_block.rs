/*
 * RTOS project modifications (2026-10-10): bound native parent-apply stack and child lifetime.
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::{
    block::BlockStuff,
    engine_traits::EngineOperations,
    shard_state::ShardStateStuff,
    validating_utils::{fmt_block_id_short, UNREGISTERED_CHAIN_MAX_LEN},
};
use rtos_block::{error, fail, BlockIdExt, Result};
use std::{ops::Deref, sync::Arc};
use storage::block_handle_db::BlockHandle;

pub const MAX_RECURSION_DEPTH: u32 = UNREGISTERED_CHAIN_MAX_LEN * 2;

pub async fn apply_block(
    handle: &Arc<BlockHandle>,
    block: &BlockStuff,
    mc_seq_no: u32,
    engine: &Arc<dyn EngineOperations>,
    pre_apply: bool,
    recursion_depth: u32,
) -> Result<()> {
    if handle.id() != block.id() {
        fail!("Block id mismatch in apply block: {} vs {}", handle.id(), block.id())
    }
    log::trace!("apply_block: block: {}", handle.id());

    let prev_ids = block.construct_prev_id()?;
    check_prev_blocks(&prev_ids, engine, mc_seq_no, pre_apply, recursion_depth).await?;

    if !handle.has_state() {
        calc_and_store_state(handle, block, &prev_ids, engine).await?;
    }
    set_prev_ids(handle, &prev_ids, engine.deref())?;
    if !pre_apply {
        set_next_ids(handle, &prev_ids, engine.deref())?;
    }

    Ok(())
}

// Checks is prev block(s) applied and apply if need
async fn check_prev_blocks(
    prev_ids: &(BlockIdExt, Option<BlockIdExt>),
    engine: &Arc<dyn EngineOperations>,
    mc_seq_no: u32,
    pre_apply: bool,
    recursion_depth: u32,
) -> Result<()> {
    // A boxed recursive future still polls every ready ancestor on the same
    // native stack. Poll each parent as a separate task, retaining the existing
    // logical recursion bound in Engine. Dropping this set aborts all children;
    // plain detached JoinHandles would let apply continue after cancellation.
    let mut tasks = tokio::task::JoinSet::new();
    for (index, id) in std::iter::once(&prev_ids.0).chain(prev_ids.1.iter()).enumerate() {
        let engine = engine.clone();
        let id = id.clone();
        tasks.spawn(async move {
            let result = engine
                .download_and_apply_block_internal(&id, mc_seq_no, pre_apply, recursion_depth + 1)
                .await;
            (index, result)
        });
    }
    let mut results = [None, None];
    while let Some(result) = tasks.join_next().await {
        let (index, result) = match result {
            Ok(result) => result,
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(error) => fail!("Parent apply task cancelled: {error}"),
        };
        results[index] = Some(result);
    }
    // Merge parents still run concurrently and both finish before returning.
    // Preserve the original left-before-right error precedence, not completion order.
    for result in results.into_iter().flatten() {
        result?;
    }
    Ok(())
}

// Normal mode - gets prev block(s) state and applies merkle update from block to calculate new state
// Archival mode - just saves state update from block, without applying it
pub async fn calc_and_store_state(
    handle: &Arc<BlockHandle>,
    block: &BlockStuff,
    prev_ids: &(BlockIdExt, Option<BlockIdExt>),
    engine: &Arc<dyn EngineOperations>,
) -> Result<()> {
    let block_descr = fmt_block_id_short(block.id());

    log::debug!("({}): store_state_update: block: {}", block_descr, block.id());

    if engine.is_archival_mode() {
        log::debug!("({}): store_state_update: store_state_update: {}", block_descr, handle.id());
        engine.store_state_update(handle, block.block()?.read_state_update()?.new).await?;
        log::debug!(
            "({}): store_state_update: store_state_update: {} done",
            block_descr,
            handle.id()
        );
    } else {
        let prev_ss_root = match prev_ids {
            (prev1, Some(prev2)) => {
                log::debug!("STATE_PHASE: block={} waiting_for_prev={}", block.id(), prev1);
                let ss1 = engine.clone().wait_state(prev1, None, true).await?;
                log::debug!("STATE_PHASE: block={} waiting_for_prev={}", block.id(), prev2);
                let ss2 = engine.clone().wait_state(prev2, None, true).await?;
                let root = ShardStateStuff::construct_split_root(
                    ss1.root_cell().clone(),
                    ss2.root_cell().clone(),
                )?;
                root
            }
            (prev, None) => {
                log::debug!("STATE_PHASE: block={} waiting_for_prev={}", block.id(), prev);
                let ss = engine.clone().wait_state(prev, None, true).await?;
                ss.root_cell().clone()
            }
        };
        log::debug!("STATE_PHASE: block={} predecessors_ready", block.id());

        let merkle_update = block.block()?.read_state_update()?;
        if merkle_update.old_hash != *prev_ss_root.repr_hash() {
            fail!(
                "Merkle update old_hash mismatch with prev state for block {}: \
                 update.old_hash = {:x}, prev_ss_root.repr_hash = {:x}",
                block.id(),
                merkle_update.old_hash,
                prev_ss_root.repr_hash()
            );
        }
        let block_id = block.id().clone();
        let engine_cloned = engine.clone();

        let block_descr_clone = block_descr.clone();
        let ss = tokio::task::spawn_blocking(move || -> Result<Arc<ShardStateStuff>> {
            log::debug!("STATE_PHASE: block={} merkle_worker_started", block_id);
            let now = std::time::Instant::now();
            let cf = engine_cloned.db_cells_factory()?;
            let mut fast_attempt = true;
            let (ss_root, _metrics) =
                match merkle_update.apply_lazy_unchecked(&cf) {
                    Err(e) => {
                        log::debug!(
                            "Failed the fast attempt of Merkle update applying for block {}: {}. Trying classic approach...",
                            block_id, e
                        );
                        fast_attempt = false;
                        merkle_update.apply_with_factory(&prev_ss_root, &cf).map_err(|e| {
                            error!(
                                "Error applying Merkle update for block {}: {}\
                                prev_ss_root: {:#.2}\
                                merkle_update: {}",
                                block_id, e, prev_ss_root, merkle_update
                            )
                        })?
                    }
                    Ok(r) => r
                };
            let elapsed = now.elapsed();
            log::debug!(
                "({}): TIME: store_state_update: applied Merkle update {}ms   {}",
                block_descr_clone,
                elapsed.as_millis(),
                block_id
            );
            #[cfg(feature = "telemetry")]
            log::debug!(target: "telemetry", "({}): applied Merkle update ({}): \ntime:{}\n{}",
                block_descr_clone,
                if fast_attempt { "fast" } else { "classic" },
                elapsed.as_millis(),
                _metrics);
            metrics::histogram!("rtos_node_db_calc_merkle_update_seconds").record(elapsed);
            ShardStateStuff::from_root_cell(
                block_id.clone(),
                ss_root,
                #[cfg(feature = "telemetry")]
                engine_cloned.engine_telemetry(),
                engine_cloned.engine_allocated(),
            )
        })
        .await??;

        log::debug!("({}): store_state_update: store_state: {}", block_descr, handle.id());
        engine.store_state(handle, ss).await?;
        log::debug!("({}): store_state_update: store_state: {} done", block_descr, handle.id());
    }

    Ok(())
}

// set next block ids for prev blocks
pub fn set_next_ids(
    handle: &Arc<BlockHandle>,
    prev_ids: &(BlockIdExt, Option<BlockIdExt>),
    engine: &dyn EngineOperations,
) -> Result<()> {
    log::trace!("set_next_ids: block: {}", handle.id());
    match prev_ids {
        (prev_id1, Some(prev_id2)) => {
            // After merge
            let prev_handle1 = engine
                .load_block_handle(prev_id1)?
                .ok_or_else(|| error!("Cannot load handle for prev1 block {}", prev_id1))?;
            engine.store_block_next1(&prev_handle1, handle.id())?;
            let prev_handle2 = engine
                .load_block_handle(prev_id2)?
                .ok_or_else(|| error!("Cannot load handle for prev2 block {}", prev_id2))?;
            engine.store_block_next1(&prev_handle2, handle.id())?;
        }
        (prev_id, None) => {
            // if after split and it is second ("1" branch) shard - set next2 for prev block
            let prev_shard = prev_id.shard().clone();
            let shard = handle.id().shard().clone();
            let prev_handle = engine
                .load_block_handle(prev_id)?
                .ok_or_else(|| error!("Cannot load handle for prev block {}", prev_id))?;
            if (prev_shard != shard) && (prev_shard.split()?.1 == shard) {
                engine.store_block_next2(&prev_handle, handle.id())?;
            } else {
                engine.store_block_next1(&prev_handle, handle.id())?;
            }
        }
    }
    Ok(())
}

// Set prev block ids for (pre-)applied block
pub fn set_prev_ids(
    handle: &Arc<BlockHandle>,
    prev_ids: &(BlockIdExt, Option<BlockIdExt>),
    engine: &dyn EngineOperations,
) -> Result<()> {
    log::trace!("set_prev_ids: block: {}", handle.id());
    match prev_ids {
        (prev_id1, Some(prev_id2)) => {
            // After merge
            engine.store_block_prev1(handle, prev_id1)?;
            engine.store_block_prev2(handle, prev_id2)?;
        }
        (prev_id, None) => {
            engine.store_block_prev1(handle, prev_id)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/test_parent_apply_tasks.rs"]
mod tests;
