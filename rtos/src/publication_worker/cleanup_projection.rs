// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Node-side projection of one retired authenticated namespace, judged by the
//! publication owner against the source inventory. Selection is by physical
//! namespace; every selected entry is then validated against the
//! re-authenticated runtime, and any mismatch, ambiguity or extra entry is a
//! veto. Nothing here changes state.
use crate::{
    propagation_outbox::{closing::ClosingRecord, Delivery, UnverifiedRecord},
    publication_dependency_leases::LeaseRecord,
    repair_lease_binding::RepairLeaseBinding,
};
use consensus_common::{
    session_runtime::{AuthenticatedSessionRuntime, LocalRole, SessionRecoveryCoordinates},
    simplex_protocol::SimplexProtocol,
};
use rtos_api::WireProfile;
use rtos_block::{BlockIdExt, Result, UInt256};
use simplex::finality_delivery::source_retirement::RetirementItem;
use std::collections::{BTreeMap, BTreeSet};

/// The role half of a physical namespace key; the session (which derives
/// from the shard and catchain seqno) is the other half.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum NamespaceRole {
    Validator,
    Observer(UInt256),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NamespaceSelection {
    pub session: UInt256,
    pub role: NamespaceRole,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CleanupDecision {
    /// Every node obligation of the namespace is Released and exactly covered.
    WouldDelete {
        closes: usize,
    },
    Veto(String),
}

/// The node-side state the projection reads, all from one owner transition.
pub(crate) struct ProjectionInput<'a> {
    pub entries: &'a [UnverifiedRecord],
    pub deliveries: &'a [Delivery],
    pub closing: &'a [ClosingRecord],
    pub leases: &'a [LeaseRecord],
    /// Accepted-but-uncompleted requests of the session, this one excluded.
    pub other_outstanding: usize,
}

/// What every selected node binding must equal: the re-authenticated
/// runtime's identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExpectedIdentity {
    pub session: UInt256,
    pub zerostate: BlockIdExt,
    pub global_id: i32,
    pub recovery_anchor: BlockIdExt,
    pub coordinates: SessionRecoveryCoordinates,
    pub profile: UInt256,
    pub protocol: SimplexProtocol,
    pub carrier_version: u32,
    pub wire_profile: WireProfile,
    pub local_adnl: UInt256,
    pub local_validator_index: Option<u32>,
}

impl ExpectedIdentity {
    pub(crate) fn of(runtime: &AuthenticatedSessionRuntime) -> Result<Self> {
        let recovery = runtime
            .recovery_binding()
            .ok_or_else(|| rtos_block::error!("runtime without recovery binding"))?;
        Ok(Self {
            session: runtime.session_id().clone(),
            zerostate: runtime.pin().zerostate.clone(),
            global_id: runtime.pin().global_id,
            recovery_anchor: recovery.governing_masterchain.clone(),
            coordinates: recovery.coordinates.clone(),
            profile: runtime.profile().clone(),
            protocol: runtime.protocol(),
            carrier_version: runtime.carrier_version(),
            wire_profile: runtime.wire_profile(),
            local_adnl: UInt256::from(*runtime.local_adnl().data()),
            local_validator_index: match runtime.local_role() {
                LocalRole::Validator(index) => Some(index),
                LocalRole::Observer => None,
            },
        })
    }
}

fn binding_role(binding: &RepairLeaseBinding) -> NamespaceRole {
    match binding.canonical.local_validator_index {
        Some(_) => NamespaceRole::Validator,
        None => NamespaceRole::Observer(binding.canonical.local_adnl.clone()),
    }
}

fn binding_selected(binding: &RepairLeaseBinding, selection: &NamespaceSelection) -> bool {
    binding.domain.session_id == selection.session && binding_role(binding) == selection.role
}

/// A selected binding must belong exactly to the re-authenticated runtime.
fn binding_mismatch(binding: &RepairLeaseBinding, expected: &ExpectedIdentity) -> Option<String> {
    let domain = &binding.domain;
    let checks = [
        (domain.zerostate == expected.zerostate, "zerostate"),
        (domain.global_id == expected.global_id, "global id"),
        (domain.source_recovery_anchor == expected.recovery_anchor, "recovery anchor"),
        (domain.source_recovery_coordinates == expected.coordinates, "recovery coordinates"),
        (domain.profile == expected.profile, "profile"),
        (domain.protocol == expected.protocol, "protocol"),
        (domain.carrier_version == expected.carrier_version, "carrier version"),
        (domain.wire_profile == expected.wire_profile, "wire profile"),
        (binding.canonical.local_adnl == expected.local_adnl, "local ADNL"),
        (
            binding.canonical.local_validator_index == expected.local_validator_index,
            "local validator index",
        ),
    ];
    checks
        .iter()
        .find(|(ok, _)| !ok)
        .map(|(_, field)| format!("node binding {} differs from the runtime", field))
}

/// Judges one namespace. WouldDelete requires: no other outstanding request
/// of the session; no retained entry or delivery of the namespace (a release
/// removes them); and an exact bijection between the namespace's Released
/// ClosingRecords, their leases and the source inventory.
pub(crate) fn project_cleanup(
    selection: &NamespaceSelection,
    runtime: &ExpectedIdentity,
    inventory: &[RetirementItem],
    input: &ProjectionInput<'_>,
    budget: &mut ProjectionBudget,
) -> CleanupDecision {
    let veto = |reason: String| CleanupDecision::Veto(reason);
    // Every map or set insertion below is charged before it is made.
    let entry = MAP_ENTRY_OVERHEAD.saturating_add(std::mem::size_of::<RepairLeaseBinding>());
    if input.other_outstanding != 0 {
        return veto(format!("{} outstanding request(s) of the session", input.other_outstanding));
    }
    if runtime.session != selection.session {
        return veto("runtime belongs to another session".into());
    }
    // Retained publication data of the session: each entry must be
    // attributable through a delivery origin, and none may belong here.
    for entry in input.entries.iter().filter(|e| e.record.session_id == selection.session) {
        let mut attributed = false;
        for delivery in input.deliveries.iter().filter(|d| d.record_id == entry.id) {
            let Some(origin) = &delivery.origin else {
                return veto(format!("delivery {:x} has no origin", delivery.delivery_id));
            };
            attributed = true;
            let role = match origin.local_validator_index {
                Some(_) => NamespaceRole::Validator,
                None => NamespaceRole::Observer(origin.local_adnl.clone()),
            };
            if role == selection.role {
                return veto(format!("delivery {:x} is still retained", delivery.delivery_id));
            }
        }
        if !attributed {
            return veto(format!("retained record {} of the session has no delivery", entry.id.0));
        }
    }
    // Released closes of this namespace, keyed by delivery.
    let mut closes: BTreeMap<UInt256, &ClosingRecord> = BTreeMap::new();
    for close in input.closing.iter().filter(|c| binding_selected(&c.binding, selection)) {
        if let Some(reason) = binding_mismatch(&close.binding, runtime) {
            return veto(reason);
        }
        if !close.released {
            return veto(format!("close {:x} is not Released", close.binding.delivery_id));
        }
        if budget.charge(entry).is_err() {
            return veto("projection budget exhausted".into());
        }
        if closes.insert(close.binding.delivery_id.clone(), close).is_some() {
            return veto(format!("two closes for delivery {:x}", close.binding.delivery_id));
        }
    }
    // Leases of this namespace, including orphans without a close.
    let mut leases: BTreeMap<u64, (&LeaseRecord, RepairLeaseBinding)> = BTreeMap::new();
    for lease in input.leases {
        if budget
            .transient(
                lease.binding.len().saturating_add(std::mem::size_of::<RepairLeaseBinding>()),
            )
            .is_err()
        {
            return veto("projection decode workspace exhausted".into());
        }
        let binding = match lease.binding() {
            Ok(binding) => binding,
            Err(error) => return veto(format!("lease {} binding: {error}", lease.generation)),
        };
        if !binding_selected(&binding, selection) {
            continue;
        }
        if let Some(reason) = binding_mismatch(&binding, runtime) {
            return veto(reason);
        }
        if budget.charge(entry).is_err() {
            return veto("projection budget exhausted".into());
        }
        leases.insert(lease.generation, (lease, binding));
    }
    let mut referenced = BTreeSet::new();
    for close in closes.values() {
        let Some((lease, binding)) = leases.get(&close.lease_generation) else {
            return veto(format!("close {:x} has no lease", close.binding.delivery_id));
        };
        if binding != &close.binding
            || lease.dependency_digest != format!("{:x}", close.dependency_digest)
        {
            return veto(format!("lease {} does not match its close", lease.generation));
        }
        if budget.charge(MAP_ENTRY_OVERHEAD).is_err() {
            return veto("projection budget exhausted".into());
        }
        if !referenced.insert(close.lease_generation) {
            return veto(format!("lease {} serves two closes", close.lease_generation));
        }
    }
    if let Some(orphan) = leases.keys().find(|generation| !referenced.contains(generation)) {
        return veto(format!("lease {orphan} has no close"));
    }
    // The source inventory covers exactly the Released closes.
    if inventory.len() != closes.len() {
        return veto(format!(
            "source inventory has {} item(s), the node {} Released close(s)",
            inventory.len(),
            closes.len()
        ));
    }
    let mut seen = BTreeSet::new();
    for item in inventory {
        let Some(close) = closes.get(&item.source_id) else {
            return veto(format!("source item {:x} has no node close", item.source_id));
        };
        if close.offer() != item.offer {
            return veto(format!("source item {:x} offer differs", item.source_id));
        }
        if budget.charge(MAP_ENTRY_OVERHEAD).is_err() {
            return veto("projection budget exhausted".into());
        }
        if !seen.insert(item.source_id.clone()) {
            return veto(format!("source item {:x} appears twice", item.source_id));
        }
    }
    CleanupDecision::WouldDelete { closes: closes.len() }
}

/// Bounds every allocation a projection makes. `items`/`bytes` are the
/// cumulative copy budget (selected data, maps, sets); `transient` bounds the
/// reusable workspace of decoding one record, which unrelated records pass
/// through without consuming the cumulative budget.
#[derive(Clone, Debug)]
pub(crate) struct ProjectionBudget {
    items: usize,
    bytes: usize,
    transient: usize,
}

/// A map or set insertion: the entry plus a conservative node overhead.
const MAP_ENTRY_OVERHEAD: usize = 64;

impl Default for ProjectionBudget {
    fn default() -> Self {
        Self::new(4096, 8 << 20, 64 << 10)
    }
}

impl ProjectionBudget {
    pub(crate) fn new(items: usize, bytes: usize, transient: usize) -> Self {
        Self { items, bytes, transient }
    }
    /// Charges one allocation of `bytes` before it is made.
    pub(crate) fn charge(&mut self, bytes: usize) -> Result<()> {
        let items = self.items.checked_sub(1);
        let left = self.bytes.checked_sub(bytes);
        match (items, left) {
            (Some(items), Some(left)) => {
                self.items = items;
                self.bytes = left;
                Ok(())
            }
            _ => rtos_block::fail!("projection budget exhausted"),
        }
    }
    /// Checks a transient decoding workspace of `bytes`; nothing is consumed.
    pub(crate) fn transient(&self, bytes: usize) -> Result<()> {
        if bytes > self.transient {
            rtos_block::fail!("projection decode workspace exhausted");
        }
        Ok(())
    }
}

/// Conservative in-memory size of a retained entry copy.
fn entry_bytes(entry: &UnverifiedRecord) -> usize {
    let record = &entry.record;
    std::mem::size_of::<UnverifiedRecord>()
        .saturating_add(record.block_data.len())
        .saturating_add(record.proof_data.as_ref().map_or(0, Vec::len))
        .saturating_add(record.carrier.bytes().len())
        .saturating_add(record.prev.len().saturating_mul(std::mem::size_of::<BlockIdExt>()))
        .saturating_add(
            record
                .effects
                .len()
                .saturating_add(entry.pending.len())
                .saturating_mul(std::mem::size_of::<crate::propagation_outbox::PublicationEffect>()),
        )
}

fn lease_bytes(lease: &LeaseRecord) -> usize {
    std::mem::size_of::<LeaseRecord>()
        .saturating_add(lease.binding.len())
        .saturating_add(lease.dependency_digest.len())
        .saturating_add(
            lease
                .dependencies
                .len()
                .saturating_mul(std::mem::size_of::<crate::repair_provenance::Dependency>()),
        )
}

/// The outbox data of one session, copied under the writer lock.
pub(crate) struct OutboxSelection {
    pub entries: Vec<UnverifiedRecord>,
    pub deliveries: Vec<Delivery>,
    pub closing: Vec<ClosingRecord>,
}

/// Copies only `session`'s entries, their deliveries and its closes, charging
/// every copy before it is made.
pub(crate) fn select_outbox(
    session: &UInt256,
    entries: &[UnverifiedRecord],
    deliveries: &[Delivery],
    closing: &[ClosingRecord],
    budget: &mut ProjectionBudget,
) -> Result<OutboxSelection> {
    let mut selection =
        OutboxSelection { entries: Vec::new(), deliveries: Vec::new(), closing: Vec::new() };
    let mut ids = BTreeSet::new();
    for entry in entries.iter().filter(|entry| &entry.record.session_id == session) {
        budget.charge(entry_bytes(entry).saturating_add(MAP_ENTRY_OVERHEAD))?;
        ids.insert(entry.id);
        selection.entries.push(entry.clone());
    }
    for delivery in deliveries.iter().filter(|delivery| ids.contains(&delivery.record_id)) {
        budget.charge(std::mem::size_of::<Delivery>())?;
        selection.deliveries.push(delivery.clone());
    }
    for close in closing.iter().filter(|close| &close.binding.domain.session_id == session) {
        budget.charge(std::mem::size_of::<ClosingRecord>())?;
        selection.closing.push(close.clone());
    }
    Ok(selection)
}

/// Copies only `session`'s lease records. Each binding is decoded in the
/// transient workspace first; only a selected record is charged and copied.
pub(crate) fn select_leases<'a>(
    session: &UInt256,
    records: impl Iterator<Item = &'a LeaseRecord>,
    budget: &mut ProjectionBudget,
) -> Result<Vec<LeaseRecord>> {
    let mut selected = Vec::new();
    for record in records {
        budget.transient(
            record.binding.len().saturating_add(std::mem::size_of::<RepairLeaseBinding>()),
        )?;
        if &record.binding()?.domain.session_id != session {
            continue;
        }
        budget.charge(lease_bytes(record))?;
        selected.push(record.clone());
    }
    Ok(selected)
}

/// The race-free judgement protocol: the session must be quiescent before
/// anything is read; both stores are read with the epoch they were read at;
/// after judging, the session must still be quiescent and both epochs
/// unchanged. Any exhausted epoch, budget or read failure is a veto.
pub(crate) struct JudgeSources<'a> {
    pub outstanding: &'a dyn Fn() -> usize,
    pub read_outbox: &'a dyn Fn(&mut ProjectionBudget) -> Result<(OutboxSelection, Option<u64>)>,
    pub read_leases: &'a dyn Fn(&mut ProjectionBudget) -> Result<(Vec<LeaseRecord>, Option<u64>)>,
    pub outbox_epoch: &'a dyn Fn() -> Result<Option<u64>>,
    pub lease_epoch: &'a dyn Fn() -> Result<Option<u64>>,
}

pub(crate) fn judge_cleanup(
    selection: &NamespaceSelection,
    expected: &ExpectedIdentity,
    inventory: &[RetirementItem],
    sources: &JudgeSources<'_>,
    mut budget: ProjectionBudget,
) -> CleanupDecision {
    let veto = |reason: String| CleanupDecision::Veto(reason);
    let busy = (sources.outstanding)();
    if busy != 0 {
        return veto(format!("{busy} outstanding request(s) of the session"));
    }
    let (outbox, outbox_epoch) = match (sources.read_outbox)(&mut budget) {
        Ok(read) => read,
        Err(error) => return veto(format!("outbox projection: {error}")),
    };
    let (leases, lease_epoch) = match (sources.read_leases)(&mut budget) {
        Ok(read) => read,
        Err(error) => return veto(format!("lease projection: {error}")),
    };
    let (Some(outbox_epoch), Some(lease_epoch)) = (outbox_epoch, lease_epoch) else {
        return veto("store mutation epoch exhausted".into());
    };
    let decision = project_cleanup(
        selection,
        expected,
        inventory,
        &ProjectionInput {
            entries: &outbox.entries,
            deliveries: &outbox.deliveries,
            closing: &outbox.closing,
            leases: &leases,
            other_outstanding: 0,
        },
        &mut budget,
    );
    let busy = (sources.outstanding)();
    let unchanged = matches!((sources.outbox_epoch)(), Ok(Some(epoch)) if epoch == outbox_epoch)
        && matches!((sources.lease_epoch)(), Ok(Some(epoch)) if epoch == lease_epoch);
    if busy != 0 || !unchanged {
        return veto("projection raced a mutation".into());
    }
    decision
}

#[cfg(test)]
#[path = "../tests/test_cleanup_projection.rs"]
mod tests;
