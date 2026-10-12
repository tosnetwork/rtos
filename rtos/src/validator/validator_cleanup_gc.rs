// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! The durable GC masterchain floor that bounds validator consensus cleanup,
//! and the deletion-gate oracles bound to its pinned state. The floor follows
//! the reference GC block: it trails every frontier, advances one verified
//! successor at a time, and never regresses.
use crate::{engine::Engine, engine_traits::EngineOperations, shard_state::ShardStateStuff};
use consensus_common::validator_cleanup::{
    may_advance_gc, should_adopt_safe_checkpoint, CleanupAncestry, GcAdvanceInputs,
};
use rtos_block::{error, BlockIdExt, HashmapAugType, Result, ShardIdent, UnixTime};
use std::sync::Arc;

/// Candidates examined by the first-run floor search.
const BOOTSTRAP_CANDIDATES: u32 = 64;

/// Whether `checkpoint` is the floor block or a verified ancestor of it on
/// the accepted chain (hash-exact through the floor state's history).
pub(crate) fn ancestor_or_equal(floor: &ShardStateStuff, checkpoint: &BlockIdExt) -> bool {
    if checkpoint == floor.block_id() {
        return true;
    }
    checkpoint.seq_no() < floor.block_id().seq_no()
        && floor.has_prev_block(checkpoint).unwrap_or(false)
}

/// The shard's catchain seqno as of the floor state. Any error, unknown
/// topology or arithmetic overflow yields nothing, which vetoes deletion.
pub(crate) fn shard_catchain_seqno(floor: &ShardStateStuff, shard: &ShardIdent) -> Option<u32> {
    let extra = floor.shard_state_extra().ok()?;
    if shard.is_masterchain() {
        return Some(extra.validator_info.catchain_seqno);
    }
    let shards = extra.shards();
    let left = shards.find_shard(&shard.left_ancestor_mask().ok()?).ok()??;
    if left.shard().is_ancestor_for(shard) {
        return Some(left.descr.next_catchain_seqno);
    }
    if !shard.is_parent_for(left.shard()) {
        return None;
    }
    let right = shards.find_shard(&shard.right_ancestor_mask().ok()?).ok()??;
    if !shard.is_parent_for(right.shard()) {
        return None;
    }
    // A merge takes max + 1; checked, so the sentinel can never be produced.
    left.descr.next_catchain_seqno.max(right.descr.next_catchain_seqno).checked_add(1)
}

async fn advance_inputs(
    engine: &Arc<Engine>,
) -> Result<Option<(GcAdvanceInputs, Arc<ShardStateStuff>)>> {
    let last = engine.load_last_applied_mc_state().await?;
    let extra = last.shard_state_extra()?;
    let seqno = |id: Option<Arc<BlockIdExt>>| id.map(|id| id.seq_no());
    let (Some(rotation), Some(shard_client), Some(pss)) = (
        seqno(engine.load_last_rotation_block_id()?),
        seqno(engine.load_shard_client_mc_block_id()?),
        seqno(engine.load_pss_keeper_mc_block_id()?),
    ) else {
        // An unknown frontier never lets the floor move.
        return Ok(None);
    };
    let last_key = if extra.after_key_block {
        last.block_id().seq_no()
    } else {
        match &extra.last_key_block {
            Some(id) => id.seq_no,
            None => return Ok(None),
        }
    };
    let inputs = GcAdvanceInputs {
        last_rotation_seqno: rotation,
        min_ref_mc_seqno: last.state()?.min_ref_mc_seqno(),
        last_applied_seqno: last.block_id().seq_no(),
        last_key_block_seqno: last_key,
        shard_client_seqno: shard_client,
        pss_keeper_seqno: pss,
        now: UnixTime::now(),
        state_ttl: engine.shard_states_keeper().cleanup_state_ttl(),
    };
    Ok(Some((inputs, last)))
}

/// Bootstraps or advances the floor by at most one step. A floor whose state
/// went missing is left alone: cleanup stays disabled.
pub(crate) async fn maintain_cleanup_floor(engine: &Arc<Engine>) -> Result<()> {
    let keeper = engine.shard_states_keeper();
    let Some((inputs, last)) = advance_inputs(engine).await? else {
        return Ok(());
    };
    if keeper.cleanup_floor_unset() {
        return bootstrap(engine, &inputs, &last);
    }
    let Some((floor_id, floor_state)) = keeper.cleanup_floor() else {
        return Ok(());
    };
    if !may_advance_gc(floor_id.seq_no(), u64::from(floor_state.state()?.gen_time()), &inputs) {
        return Ok(());
    }
    let next = engine.load_block_next1(&floor_id)?;
    let guard = keeper.pin_cleanup_candidate(&next)?;
    let ancestry = |current: &BlockIdExt, candidate: &BlockIdExt| {
        if candidate != guard.state().block_id() {
            return CleanupAncestry::Unknown;
        }
        match guard.state().has_prev_block(current) {
            Ok(true) => CleanupAncestry::Ancestor,
            Ok(false) => CleanupAncestry::NotAncestor,
            Err(_) => CleanupAncestry::Unknown,
        }
    };
    if next.seq_no() != floor_id.seq_no().saturating_add(1)
        || !should_adopt_safe_checkpoint(Some(&floor_id), &next, &ancestry)
    {
        return Err(error!(
            "Cleanup floor successor {next} is not a verified descendant of {floor_id}"
        ));
    }
    keeper.adopt_cleanup_floor(&next, guard)
}

fn bootstrap(engine: &Arc<Engine>, inputs: &GcAdvanceInputs, last: &ShardStateStuff) -> Result<()> {
    let keeper = engine.shard_states_keeper();
    let bound = [
        inputs.last_rotation_seqno,
        inputs.min_ref_mc_seqno,
        inputs.last_applied_seqno.saturating_sub(1024),
        inputs.last_key_block_seqno,
        inputs.shard_client_seqno,
        inputs.pss_keeper_seqno,
    ]
    .into_iter()
    .min()
    .unwrap_or(0);
    let Some(expiry) = inputs.now.checked_sub(inputs.state_ttl) else {
        return Ok(());
    };
    let extra = last.shard_state_extra()?;
    let lowest = bound.saturating_sub(BOOTSTRAP_CANDIDATES);
    for seqno in (lowest..bound).rev() {
        let Some(entry) = extra.prev_blocks.get(&seqno)? else {
            continue;
        };
        let (_, candidate, _) = entry.master_block_id();
        let Ok(guard) = keeper.pin_cleanup_candidate(&candidate) else {
            continue;
        };
        if u64::from(guard.state().state()?.gen_time()) >= expiry {
            continue;
        }
        return keeper.adopt_cleanup_floor(&candidate, guard);
    }
    Ok(())
}
