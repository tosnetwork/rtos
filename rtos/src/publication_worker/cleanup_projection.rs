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
pub(crate) fn binding_mismatch(
    binding: &RepairLeaseBinding,
    expected: &ExpectedIdentity,
) -> Option<String> {
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
#[cfg(test)]
pub(crate) fn project_cleanup(
    selection: &NamespaceSelection,
    runtime: &ExpectedIdentity,
    inventory: &[RetirementItem],
    input: &ProjectionInput<'_>,
    budget: &mut ProjectionBudget,
) -> CleanupDecision {
    project_cleanup_inner(selection, runtime, inventory, input, budget).0
}

/// The projection plus, for WouldDelete, the associations of its Released
/// closes, built from the same validated data.
fn project_cleanup_inner(
    selection: &NamespaceSelection,
    runtime: &ExpectedIdentity,
    inventory: &[RetirementItem],
    input: &ProjectionInput<'_>,
    budget: &mut ProjectionBudget,
) -> (CleanupDecision, Vec<consensus_common::validator_cleanup::CleanupAssociation>) {
    let veto = |reason: String| (CleanupDecision::Veto(reason), Vec::new());
    // Every map or set insertion below is charged before it is made.
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
        if budget.charge(map_insert::<UInt256, &ClosingRecord>()).is_err() {
            return veto("projection budget exhausted".into());
        }
        if closes.insert(close.binding.delivery_id.clone(), close).is_some() {
            return veto(format!("two closes for delivery {:x}", close.binding.delivery_id));
        }
    }
    // Leases of this namespace, including orphans without a close.
    let mut leases: BTreeMap<u64, (&LeaseRecord, RepairLeaseBinding)> = BTreeMap::new();
    for lease in input.leases {
        if budget.transient(binding_decode_workspace(&lease.binding)).is_err() {
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
        if budget.charge(map_insert::<u64, (&LeaseRecord, RepairLeaseBinding)>()).is_err() {
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
        if budget.charge(map_insert::<u64, ()>()).is_err() {
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
    // Each source item names its node close the way the node resolves it:
    // by the node receipt in its offer, whose full offer must match.
    let mut seen = BTreeSet::new();
    for item in inventory {
        let node_id = &item.offer.request.canonical.node_receipt;
        let Some(close) = closes.get(node_id) else {
            return veto(format!("source item {:x} has no node close {node_id:x}", item.source_id));
        };
        if close.offer() != item.offer {
            return veto(format!("source item {:x} offer differs", item.source_id));
        }
        if budget.charge(map_insert::<UInt256, ()>()).is_err() {
            return veto("projection budget exhausted".into());
        }
        if !seen.insert(node_id.clone()) {
            return veto(format!("node close {node_id:x} is claimed twice"));
        }
    }
    let mut associations = match reserved::<consensus_common::validator_cleanup::CleanupAssociation>(
        closes.len(),
        0,
        budget,
    ) {
        Ok(associations) => associations,
        Err(_) => return veto("projection budget exhausted".into()),
    };
    for close in closes.values() {
        let encoded = match close.binding.encode() {
            Ok(encoded) => encoded,
            Err(error) => return veto(format!("close binding: {error}")),
        };
        associations.push(consensus_common::validator_cleanup::CleanupAssociation {
            delivery_id: close.binding.delivery_id.clone(),
            close_generation: close.binding.close_generation,
            lease_generation: close.lease_generation,
            dependency_digest: close.dependency_digest.clone(),
            binding_digest: UInt256::calc_file_hash(&encoded),
        });
    }
    (CleanupDecision::WouldDelete { closes: closes.len() }, associations)
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

/// A B-tree map or set insertion may allocate a whole node: charge a full
/// node of `MAP_NODE_ENTRIES` entries plus edges per insertion.
const MAP_NODE_ENTRIES: usize = 12;
const MAP_NODE_OVERHEAD: usize = 256;
fn map_insert<K, V>() -> usize {
    MAP_NODE_ENTRIES
        .saturating_mul(std::mem::size_of::<K>().saturating_add(std::mem::size_of::<V>()))
        .saturating_add(MAP_NODE_OVERHEAD)
}

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

/// Conservative in-memory heap of a retained entry copy (beyond its slot).
fn entry_heap(entry: &UnverifiedRecord) -> usize {
    let record = &entry.record;
    record
        .block_data
        .len()
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

/// Conservative heap of a lease record copy, nested strings included.
fn lease_heap(lease: &LeaseRecord) -> usize {
    let mut heap = lease.binding.len().saturating_add(lease.dependency_digest.len());
    for dependency in &lease.dependencies {
        heap = heap
            .saturating_add(std::mem::size_of::<crate::repair_provenance::Dependency>())
            .saturating_add(dependency.kind.len())
            .saturating_add(dependency.id.len())
            .saturating_add(dependency.digest.len())
            .saturating_add(dependency.root.as_ref().map_or(0, String::len));
    }
    heap
}

/// Workspace of decoding one lease binding: serde's owned strings (at most
/// the encoded length each pass), the parsed intermediate and the result.
fn binding_decode_workspace(encoded: &[u8]) -> usize {
    encoded
        .len()
        .saturating_mul(4)
        .saturating_add(crate::repair_lease_binding::WIRE_STRUCT_BYTES)
        .saturating_add(std::mem::size_of::<RepairLeaseBinding>())
}

/// A vector of exactly `count` elements of `T`, allocated only after its
/// slots plus `heap` were charged.
fn reserved<T>(count: usize, heap: usize, budget: &mut ProjectionBudget) -> Result<Vec<T>> {
    if count == 0 {
        return Ok(Vec::new());
    }
    budget.charge(count.saturating_mul(std::mem::size_of::<T>()).saturating_add(heap))?;
    Ok(Vec::with_capacity(count))
}

/// The outbox data of one session, copied under the writer lock.
pub(crate) struct OutboxSelection {
    pub entries: Vec<UnverifiedRecord>,
    pub deliveries: Vec<Delivery>,
    pub closing: Vec<ClosingRecord>,
}

/// Copies only `session`'s entries, their deliveries and its closes. Each
/// part is counted first and allocated with exactly that capacity after the
/// slots and nested heap were charged.
pub(crate) fn select_outbox(
    session: &UInt256,
    entries: &[UnverifiedRecord],
    deliveries: &[Delivery],
    closing: &[ClosingRecord],
    budget: &mut ProjectionBudget,
) -> Result<OutboxSelection> {
    let selected = |entry: &&UnverifiedRecord| &entry.record.session_id == session;
    let (count, heap) = entries
        .iter()
        .filter(selected)
        .fold((0usize, 0usize), |(n, h), e| (n.saturating_add(1), h.saturating_add(entry_heap(e))));
    let mut chosen = reserved::<UnverifiedRecord>(count, heap, budget)?;
    chosen.extend(entries.iter().filter(selected).cloned());
    let owned = |delivery: &&Delivery| chosen.iter().any(|entry| entry.id == delivery.record_id);
    let count = deliveries.iter().filter(owned).count();
    let mut chosen_deliveries = reserved::<Delivery>(count, 0, budget)?;
    chosen_deliveries.extend(deliveries.iter().filter(owned).cloned());
    let closes = |close: &&ClosingRecord| &close.binding.domain.session_id == session;
    let count = closing.iter().filter(closes).count();
    let mut chosen_closes = reserved::<ClosingRecord>(count, 0, budget)?;
    chosen_closes.extend(closing.iter().filter(closes).cloned());
    Ok(OutboxSelection { entries: chosen, deliveries: chosen_deliveries, closing: chosen_closes })
}

/// Copies only `session`'s lease records. Each binding is decoded in the
/// transient workspace (checked before decoding) to count the selection,
/// the exact vector is charged with its nested heap, then filled.
pub(crate) fn select_leases<'a>(
    session: &UInt256,
    records: impl Iterator<Item = &'a LeaseRecord> + Clone,
    budget: &mut ProjectionBudget,
) -> Result<Vec<LeaseRecord>> {
    let mut count = 0usize;
    let mut heap = 0usize;
    for record in records.clone() {
        budget.transient(binding_decode_workspace(&record.binding))?;
        if &record.binding()?.domain.session_id == session {
            count = count.saturating_add(1);
            heap = heap.saturating_add(lease_heap(record));
        }
    }
    let mut selected = reserved::<LeaseRecord>(count, heap, budget)?;
    for record in records {
        if selected.len() == count {
            break;
        }
        if &record.binding()?.domain.session_id == session {
            selected.push(record.clone());
        }
    }
    Ok(selected)
}

/// Charges and copies the source inventory before it leaves the attempt.
pub(crate) fn copy_inventory(
    inventory: &[RetirementItem],
    budget: &mut ProjectionBudget,
) -> Result<Vec<RetirementItem>> {
    let mut copy = reserved::<RetirementItem>(inventory.len(), 0, budget)?;
    copy.extend_from_slice(inventory);
    Ok(copy)
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

/// A judgement with the associations of its WouldDelete and the (outbox,
/// ledger) epochs both reads and the recheck agreed on.
pub(crate) struct Judgement {
    pub decision: CleanupDecision,
    pub associations: Vec<consensus_common::validator_cleanup::CleanupAssociation>,
    pub epochs: Option<(u64, u64)>,
}

#[cfg(test)]
pub(crate) fn judge_cleanup(
    selection: &NamespaceSelection,
    expected: &ExpectedIdentity,
    inventory: &[RetirementItem],
    sources: &JudgeSources<'_>,
    budget: ProjectionBudget,
) -> CleanupDecision {
    judge_cleanup_detailed(selection, expected, inventory, sources, budget).decision
}

pub(crate) fn judge_cleanup_detailed(
    selection: &NamespaceSelection,
    expected: &ExpectedIdentity,
    inventory: &[RetirementItem],
    sources: &JudgeSources<'_>,
    mut budget: ProjectionBudget,
) -> Judgement {
    let veto = |reason: String| Judgement {
        decision: CleanupDecision::Veto(reason),
        associations: Vec::new(),
        epochs: None,
    };
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
    let (decision, associations) = project_cleanup_inner(
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
    Judgement { decision, associations, epochs: Some((outbox_epoch, lease_epoch)) }
}

#[cfg(test)]
#[path = "../tests/test_cleanup_projection.rs"]
mod tests;
