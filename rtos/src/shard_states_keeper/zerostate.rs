// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Immutable zero-state files remain readable after their dynamic index is GC'd.
use super::*;
use crate::history_read_budget::{HistoryBudgetExceeded, HistoryReadBudget, ReadKind};
use std::io::{Read, Seek, SeekFrom};

pub(super) fn read(
    keeper: &ShardStatesKeeper,
    id: &BlockIdExt,
    budget: Option<&Arc<HistoryReadBudget>>,
) -> Result<Arc<ShardStateStuff>> {
    if id.seq_no() != 0 {
        fail!("Persistent zero-state reader requires sequence zero");
    }
    keeper.check_stop()?;
    let mut input = keeper
        .db
        .load_shard_state_persistent_obj(&PersistentStatePartId::WholeState(id.clone()))
        .map_err(|error| {
            error.context(format!("Persistent zero-state file unavailable for {id}"))
        })?;
    read_input(keeper, id, budget, &mut input).map_err(|error| {
        if budget.is_some() && !crate::history_read_budget::stops_fallback(&error) {
            error.context(storage::bounded_cell::InvalidBoundedState("persistent zero-state file"))
        } else {
            error
        }
    })
}

fn read_input<R: Read + Seek>(
    keeper: &ShardStatesKeeper,
    id: &BlockIdExt,
    budget: Option<&Arc<HistoryReadBudget>>,
    input: &mut R,
) -> Result<Arc<ShardStateStuff>> {
    let length = usize::try_from(input.seek(SeekFrom::End(0))?)?;
    input.seek(SeekFrom::Start(0))?;
    let reservation = if let Some(budget) = budget {
        let reservation = budget.reserve(ReadKind::State, length)?;
        if reservation.allowance() != length {
            return Err(HistoryBudgetExceeded("zero-state file bytes").into());
        }
        rtos_block::merkle_apply_budget::MerkleApplyBudget::workspace(budget.as_ref(), length)?;
        Some(reservation)
    } else {
        // Ordinary boot does not acquire a historical-read capability or its
        // smaller request limits. Authenticate the existing pinned file before
        // allocating a whole-file buffer; the streaming pass has fixed space.
        let mut hash = rtos_block::Sha256::new();
        let mut buffer = [0u8; 64 << 10];
        let mut remaining = length;
        while remaining != 0 {
            keeper.check_stop()?;
            let size = remaining.min(buffer.len());
            input.read_exact(&mut buffer[..size])?;
            hash.update(&buffer[..size]);
            remaining -= size;
        }
        if input.read(&mut [0u8; 1])? != 0 {
            fail!("Zero-state file grew during verification");
        }
        if hash.finalize().as_slice() != id.file_hash().as_slice() {
            fail!("Persistent zero-state file hash differs from pinned identity");
        }
        input.seek(SeekFrom::Start(0))?;
        None
    };
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length)?;
    bytes.resize(length, 0);
    let mut hash = rtos_block::Sha256::new();
    for chunk in bytes.chunks_mut(64 << 10) {
        keeper.check_stop()?;
        input.read_exact(chunk)?;
        hash.update(chunk);
    }
    if input.read(&mut [0u8; 1])? != 0 {
        fail!("Zero-state file grew during read");
    }
    if let Some(reservation) = reservation {
        reservation.finish(&bytes)?;
    }
    // Check again after the second pass: a concurrent rewrite must not turn
    // the initial authentication into authority for different bytes.
    if hash.finalize().as_slice() != id.file_hash().as_slice() {
        fail!("Persistent zero-state file hash differs from pinned identity");
    }
    let root = match budget {
        Some(budget) => budget.parse_boc(&bytes)?,
        None => rtos_block::read_single_root_boc(&bytes)?,
    };
    if root.repr_hash() != id.root_hash() {
        fail!("Persistent zero-state root differs from pinned identity");
    }
    let state = ShardStateStuff::from_root_cell(
        id.clone(),
        root,
        #[cfg(feature = "telemetry")]
        &keeper.telemetry,
        &keeper.allocated,
    )?;
    state.verify_zerostate(id)?;
    Ok(state)
}
