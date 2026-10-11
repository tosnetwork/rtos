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

/// Separate durable events even when they refer to the same block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalityDeliveryRole {
    Approval,
    Final,
}

/// Lookup coordinates, never a publication capability. The sink must check
/// these against its authenticated runtime and the original durable record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalFinalityRequest {
    pub node_receipt: UInt256,
    pub block_id: BlockIdExt,
    pub role: FinalityDeliveryRole,
    pub local_adnl: UInt256,
    pub local_validator_index: Option<u32>,
    pub source_validator: UInt256,
}

/// Original node-owned evidence, reconstructed by verifying the stored carrier,
/// never by signing again. Source callers must also check their retained digest
/// and original metadata before replacing a full source record with a reference.
#[derive(Clone)]
pub struct CanonicalFinalityRecord {
    pub request: CanonicalFinalityRequest,
    pub data: BlockPayloadPtr,
    pub finality: SessionFinality,
    pub last_mc_finalized_seqno: u32,
    pub candidate_already_sent: bool,
    pub created_at_unix_secs: u64,
}

pub type CanonicalFinalityCompletion =
    Box<dyn FnOnce(Result<CanonicalFinalityRecord>) + Send>;

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

    /// Admit an owned lookup that also durably retains the node's canonical
    /// record for this source binding. Admission is not durability: only a
    /// successful completion proves both the original record and its reference
    /// are retained. Completion runs exactly once after successful admission,
    /// including source shutdown. On admission error it is not called.
    ///
    /// The implementation checks full runtime/network/session/profile domains,
    /// role and origin; a receipt supplied by a caller cannot grant authority.
    /// A retained reference forbids node GC until a separately proven retirement
    /// protocol releases it. Unsupported sinks leave full source ACKs intact.
    fn retain_canonical(
        &self,
        _request: CanonicalFinalityRequest,
        _completion: CanonicalFinalityCompletion,
    ) -> Result<()> {
        rtos_block::fail!("Canonical finality retention is unsupported")
    }
}
