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
    WouldDelete { closes: usize },
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
) -> CleanupDecision {
    let veto = |reason: String| CleanupDecision::Veto(reason);
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
        if closes.insert(close.binding.delivery_id.clone(), close).is_some() {
            return veto(format!("two closes for delivery {:x}", close.binding.delivery_id));
        }
    }
    // Leases of this namespace, including orphans without a close.
    let mut leases: BTreeMap<u64, (&LeaseRecord, RepairLeaseBinding)> = BTreeMap::new();
    for lease in input.leases {
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
        if !seen.insert(item.source_id.clone()) {
            return veto(format!("source item {:x} appears twice", item.source_id));
        }
    }
    CleanupDecision::WouldDelete { closes: closes.len() }
}

#[cfg(test)]
#[path = "../tests/test_cleanup_projection.rs"]
mod tests;
