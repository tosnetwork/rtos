// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Transfer finalized delivery to a node-owned durable queue before source retirement.
use crate::{BlockPayloadPtr, BlockSourceInfo, SessionFinality};
use rtos_block::{BlockIdExt, Result, UInt256};
use std::sync::Arc;

/// Source evidence retained until the node confirms a durable draft record.
/// The sink is separately bound to the authenticated session runtime; these
/// fields alone do not establish chain provenance or publication authority.
#[derive(Clone)]
pub struct FinalizedDeliveryDraft {
    pub block_id: BlockIdExt,
    pub source_info: BlockSourceInfo,
    pub data: BlockPayloadPtr,
    pub finality: SessionFinality,
    pub last_mc_finalized_seqno: u32,
    pub candidate_already_sent: bool,
    /// Frozen by source retention; retries must not extend publication lifetime.
    pub created_at_unix_secs: u64,
}

/// Success identifies a durable node record, not an authentication token.
/// Consumers must consult the bound node ledger before acting on this ID.
pub type FinalizedDeliveryCompletion = Box<dyn FnOnce(Result<UInt256>) + Send>;
pub type DurableFinalitySinkPtr = Arc<dyn DurableFinalitySink>;

pub trait DurableFinalitySink: Send + Sync {
    /// Admit a bounded request to a node-owned worker. `Ok(())` means only that
    /// the worker owns the request and will complete it exactly once, even if
    /// its originating session stops. Only completion `Ok(id)` confirms WAL
    /// durability and permits source retirement. An admission error means the
    /// request was not accepted and the completion will not be called.
    ///
    /// The source retains its authenticated certificate and body on either
    /// error path, for retry and recovery; a notification callback is not an ACK.
    fn stage(
        &self,
        draft: FinalizedDeliveryDraft,
        completion: FinalizedDeliveryCompletion,
    ) -> Result<()>;
}
