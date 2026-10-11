// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! A full canonical record is authenticated under the real publication owner.
//! A compact close marker alone cannot authorize new historical storage.
use super::*;
use crate::history_read_budget::{HistoryReadBudget, ReadKind};
use rtos_block::merkle_apply_budget::MerkleApplyBudget;

/// Private, non-cloneable authority retaining the authenticated original bytes.
/// This authorizes history storage only, never delivery, custody or signing.
pub(crate) struct NodeHistoryDebt {
    request: CloseFinalityRequest,
    _canonical: CanonicalFinalityRecord,
    _budget: Arc<HistoryReadBudget>,
}
impl NodeHistoryDebt {
    pub(crate) fn request(&self) -> &CloseFinalityRequest { &self.request }
}

struct SourceBudget<'a>(&'a Arc<HistoryReadBudget>);
impl simplex::finality_recovery::SourceHistoryDebtBudget for SourceBudget<'_> {
    fn step(&self) -> Result<()> { self.0.step() }
    fn workspace(&self, bytes: usize) -> Result<()> { self.0.workspace(bytes) }
    fn read_bytes(&self, bytes: usize) -> Result<()> {
        let reservation = self.0.reserve(ReadKind::Metadata, bytes)?;
        if reservation.allowance() != bytes { fail!("Canonical history read budget exhausted"); }
        // The whole admitted amount remains charged; no actual read to refund.
        drop(reservation);
        Ok(())
    }
}

impl PublicationWorker {
    pub(crate) async fn authorize_closing_history_debt(
        &self,
        request: CloseFinalityRequest,
        runtime: Arc<AuthenticatedSessionRuntime>,
        budget: Arc<HistoryReadBudget>,
    ) -> Result<NodeHistoryDebt> {
        budget.step()?;
        let (response, receiver) = oneshot::channel();
        self.admit_draft(Submission::HistoryDebt { request, runtime, budget, response })?;
        // Dropping the observer does not cancel the actor's real blocking work.
        receiver.await.map_err(|e| error!("Node history debt owner: {e}"))?
    }
}

impl State {
    pub(super) async fn history_debt(
        &self,
        store: &Arc<PropagationOutbox>,
        request: CloseFinalityRequest,
        runtime: Arc<AuthenticatedSessionRuntime>,
        budget: Arc<HistoryReadBudget>,
    ) -> Result<NodeHistoryDebt> {
        // Identical runtime/network/local-role checks to normal event closing.
        self.validate_close_runtime(&runtime, &request)?;
        if request.canonical.role != FinalityDeliveryRole::Final
            || !request.canonical.block_id.shard().is_masterchain()
        {
            fail!("Historical node debt requires masterchain Final");
        }
        let limits = self.limits.clone();
        self.write(store, move |store| {
            store.with_history_delivery(&request.canonical.node_receipt, |delivery, entry| {
                budget.step()?;
                // A valid retained full record may still owe propagation.
                // History storage grants no permission to close those effects.
                admit_canonical_workspace(entry, &runtime, &budget)?;
                let canonical = canonical_record_inner(
                    &runtime, &request.canonical, delivery, entry, &limits, Some(&budget),
                )?;
                let (_, digest) = simplex::finality_delivery::canonical_source_identity_bounded(
                    &runtime, &canonical, entry.record.carrier.bytes(), &SourceBudget(&budget),
                )?;
                if request.source_digest != digest
                    || request.created_at_unix_secs != canonical.created_at_unix_secs
                {
                    fail!("Historical node debt changed original source digest or time");
                }
                Ok(NodeHistoryDebt {
                    request: request.clone(), _canonical: canonical, _budget: budget.clone(),
                })
            })
        }).await
    }
}

fn admit_canonical_workspace(
    entry: &UnverifiedRecord,
    runtime: &AuthenticatedSessionRuntime,
    budget: &HistoryReadBudget,
) -> Result<()> {
    let record = &entry.record;
    let mut bytes = record.block_data.len()
        .checked_add(record.carrier.bytes().len())
        .and_then(|n| n.checked_add(record.proof_data.as_ref().map_or(0, Vec::len)))
        .ok_or_else(|| error!("Canonical history payload size overflow"))?;
    // Limits are configurable: a fixed scratch allowance does not cover
    // arbitrary retained effect vectors or their cloned snapshot encoding.
    let effects = record.effects.len().checked_add(entry.pending.len())
        .and_then(|n| n.checked_mul(std::mem::size_of::<PublicationEffect>()))
        .ok_or_else(|| error!("Canonical history effect vector overflow"))?;
    let parents = record.prev.len().checked_mul(std::mem::size_of::<rtos_block::BlockIdExt>())
        .ok_or_else(|| error!("Canonical history parent vector overflow"))?;
    bytes = bytes.checked_add(effects).and_then(|n| n.checked_add(parents))
        .ok_or_else(|| error!("Canonical history container size overflow"))?;
    // validate_pending checks membership with a linear search for each pending
    // effect. Admit that upper bound before invoking the shared validator.
    let membership_steps = record.effects.len().checked_mul(entry.pending.len())
        .ok_or_else(|| error!("Canonical history effect work overflow"))?;
    for _ in 0..membership_steps { budget.step()?; }
    for effect in record.effects.iter().chain(&entry.pending) {
        budget.step()?;
        if let PublicationTarget::Custom(name) = &effect.target {
            bytes = bytes.checked_add(name.len())
                .ok_or_else(|| error!("Canonical history effect size overflow"))?;
        }
    }
    // Reserve before validate_recovery_record clones/encodes the entry and
    // before the shared canonical verifier clones payload/carrier buffers.
    // Sixteen payload lengths cover retained clones, encoding growth and PQ
    // conversion buffers. BOC cells are charged independently by bounded parse;
    // the exact source digest helper charges its own hex/JSON workspace.
    // TL bytes limits do not by themselves cover the vector decoder's initial
    // reservation for up to 1024 declared elements, even in a truncated packet.
    let decode_slots = 1024usize.checked_mul(std::mem::size_of::<
        rtos_api::ton::ton_node::pqblocksignature::PqBlockSignature,
    >()).ok_or_else(|| error!("Canonical signature vector workspace overflow"))?;
    let workspace = bytes.checked_mul(16)
        .and_then(|n| n.checked_add(decode_slots))
        .and_then(|n| n.checked_add(64 << 10))
        .ok_or_else(|| error!("Canonical history workspace overflow"))?;
    budget.workspace(workspace)?;
    // Even a zero-signature carrier reaches the governing member maps. Charge
    // by actual committee size, never infer membership cost from carrier size.
    // Cover the cloned descriptor vector, membership/weight maps (including
    // geometric growth), weight vectors and key-identity scratch buffers.
    let mut members = runtime.committee().len()
        .checked_mul(std::mem::size_of::<rtos_block::ValidatorDescr>())
        .and_then(|n| n.checked_mul(16))
        .ok_or_else(|| error!("Canonical history committee workspace overflow"))?;
    for member in runtime.committee() {
        budget.step()?;
        if let rtos_block::ValidatorKey::Pq(key) = &member.key {
            members = key.public_key.len().checked_mul(4)
                .and_then(|n| members.checked_add(n))
                .ok_or_else(|| error!("Canonical history key workspace overflow"))?;
        }
    }
    budget.workspace(members)?;
    Ok(())
}
