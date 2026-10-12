// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{
    propagation_outbox::{
        closing::ClosingRecord, Delivery, PublicationRecord, PublicationStage, RecordId,
        RecoveryOrigin, UnverifiedRecord,
    },
    repair_lease_binding::RepairLeaseDomain,
};
use consensus_common::finality_delivery::{CanonicalFinalityRequest, FinalityDeliveryRole};
use rtos_block::ShardIdent;

fn block(seq: u32) -> BlockIdExt {
    BlockIdExt::with_params(
        ShardIdent::masterchain(),
        seq,
        UInt256::from([seq as u8 + 1; 32]),
        UInt256::from([seq as u8 + 2; 32]),
    )
}
const SESSION: [u8; 32] = [11; 32];
const VALIDATOR_ADNL: [u8; 32] = [9; 32];

fn expected(index: Option<u32>, adnl: [u8; 32]) -> ExpectedIdentity {
    ExpectedIdentity {
        session: UInt256::from(SESSION),
        zerostate: block(0),
        global_id: 7,
        recovery_anchor: block(1),
        coordinates: SessionRecoveryCoordinates {
            shard: ShardIdent::masterchain(),
            catchain_seqno: 5,
            vertical_seqno: 0,
            last_key_block_seqno: 0,
            new_catchain_ids: false,
        },
        profile: UInt256::from([12; 32]),
        protocol: SimplexProtocol::PrivateObserversPlumtree,
        carrier_version: 2,
        wire_profile: WireProfile::T0,
        local_adnl: UInt256::from(adnl),
        local_validator_index: index,
    }
}
fn validator() -> ExpectedIdentity {
    expected(Some(0), VALIDATOR_ADNL)
}
fn validator_selection() -> NamespaceSelection {
    NamespaceSelection { session: UInt256::from(SESSION), role: NamespaceRole::Validator }
}

/// A binding for delivery `id` of the namespace `identity` ran as.
fn binding(id: u8, identity: &ExpectedIdentity) -> RepairLeaseBinding {
    let receipt = UInt256::from([id; 32]);
    RepairLeaseBinding {
        record_id: u64::from(id),
        delivery_id: receipt.clone(),
        canonical: CanonicalFinalityRequest {
            node_receipt: receipt,
            block_id: block(u32::from(id) + 10),
            role: FinalityDeliveryRole::Final,
            local_adnl: identity.local_adnl.clone(),
            local_validator_index: identity.local_validator_index,
            source_validator: UInt256::from([10; 32]),
        },
        domain: RepairLeaseDomain {
            zerostate: identity.zerostate.clone(),
            global_id: identity.global_id,
            history_init: block(0),
            source_recovery_anchor: identity.recovery_anchor.clone(),
            source_recovery_coordinates: identity.coordinates.clone(),
            session_id: identity.session.clone(),
            profile: identity.profile.clone(),
            protocol: identity.protocol,
            carrier_version: identity.carrier_version,
            wire_profile: identity.wire_profile,
        },
        source_digest: UInt256::from([13; 32]),
        canonical_digest: UInt256::from([14; 32]),
        created_at_unix_secs: 100,
        expires_at_unix_secs: 200,
        effects_digest: UInt256::from([15; 32]),
        close_generation: u64::from(id),
    }
}
fn close(id: u8, identity: &ExpectedIdentity, generation: u64, released: bool) -> ClosingRecord {
    ClosingRecord {
        binding: binding(id, identity),
        lease_generation: generation,
        dependency_digest: UInt256::from([0x44; 32]),
        released,
    }
}
fn lease(generation: u64, close: &ClosingRecord) -> LeaseRecord {
    LeaseRecord::for_test(generation, &close.binding, &close.dependency_digest).unwrap()
}
fn item(close: &ClosingRecord) -> RetirementItem {
    RetirementItem { source_id: close.binding.delivery_id.clone(), offer: close.offer() }
}

struct World {
    entries: Vec<UnverifiedRecord>,
    deliveries: Vec<Delivery>,
    closing: Vec<ClosingRecord>,
    leases: Vec<LeaseRecord>,
    outstanding: usize,
}
impl World {
    fn released(ids: &[u8], identity: &ExpectedIdentity) -> (Self, Vec<RetirementItem>) {
        let closing: Vec<_> = ids
            .iter()
            .enumerate()
            .map(|(n, id)| close(*id, identity, n as u64 + 1, true))
            .collect();
        let leases = closing.iter().map(|c| lease(c.lease_generation, c)).collect();
        let items = closing.iter().map(item).collect();
        (Self { entries: vec![], deliveries: vec![], closing, leases, outstanding: 0 }, items)
    }
    fn judge(&self, selection: &NamespaceSelection, identity: &ExpectedIdentity, items: &[RetirementItem]) -> CleanupDecision {
        project_cleanup(
            selection,
            identity,
            items,
            &ProjectionInput {
                entries: &self.entries,
                deliveries: &self.deliveries,
                closing: &self.closing,
                leases: &self.leases,
                other_outstanding: self.outstanding,
            },
        )
    }
}
fn vetoed(decision: CleanupDecision, needle: &str) {
    match decision {
        CleanupDecision::Veto(reason) => assert!(reason.contains(needle), "{reason}"),
        other => panic!("expected a veto containing {needle:?}, got {other:?}"),
    }
}
fn retained(session: [u8; 32], origin: Option<RecoveryOrigin>) -> (UnverifiedRecord, Delivery) {
    let record = PublicationRecord {
        domain: crate::propagation_outbox::OutboxDomain {
            zerostate: block(0),
            global_id: 7,
            wire_profile: WireProfile::T0,
        },
        protocol: SimplexProtocol::PrivateObserversPlumtree,
        profile: UInt256::from([12; 32]),
        session_id: UInt256::from(session),
        block_id: block(30),
        block_data: vec![],
        proof_data: None,
        prev: vec![],
        carrier: crate::propagation_outbox::StoredCarrier::Final(vec![]),
        locally_generated: false,
        created_at_unix_secs: 1,
        expires_at_unix_secs: 2,
        effects: vec![],
    };
    let entry = UnverifiedRecord {
        id: RecordId(77),
        stage: PublicationStage::DraftDurable,
        record,
        pending: vec![],
    };
    let delivery = Delivery {
        delivery_id: UInt256::from([0x77; 32]),
        record_id: RecordId(77),
        last_mc: 0,
        candidate_already_sent: false,
        origin,
    };
    (entry, delivery)
}

#[test]
fn projection_accepts_exact_released_coverage_and_an_empty_namespace() {
    let identity = validator();
    let (world, items) = World::released(&[1, 2], &identity);
    assert_eq!(world.judge(&validator_selection(), &identity, &items), CleanupDecision::WouldDelete { closes: 2 });
    let (empty, none) = World::released(&[], &identity);
    assert_eq!(empty.judge(&validator_selection(), &identity, &none), CleanupDecision::WouldDelete { closes: 0 });
}

#[test]
fn projection_vetoes_every_coverage_gap() {
    let identity = validator();
    let selection = validator_selection();
    // An empty source against a nonempty node, and a node extra.
    let (world, items) = World::released(&[1, 2], &identity);
    vetoed(world.judge(&selection, &identity, &[]), "inventory has 0");
    vetoed(world.judge(&selection, &identity, &items[..1]), "inventory has 1");
    // An unreleased close.
    let (mut world, items) = World::released(&[1], &identity);
    world.closing[0].released = false;
    vetoed(world.judge(&selection, &identity, &items), "not Released");
    // An orphan lease and a missing lease.
    let (mut world, items) = World::released(&[1], &identity);
    let extra = close(9, &identity, 9, true);
    world.leases.push(lease(9, &extra));
    vetoed(world.judge(&selection, &identity, &items), "lease 9 has no close");
    let (mut world, items) = World::released(&[1], &identity);
    world.leases.clear();
    vetoed(world.judge(&selection, &identity, &items), "has no lease");
    // A lease whose digest differs from its close.
    let (mut world, items) = World::released(&[1], &identity);
    world.leases[0].dependency_digest = format!("{:x}", UInt256::from([0x55; 32]));
    vetoed(world.judge(&selection, &identity, &items), "does not match its close");
    // An offer that differs from the node's.
    let (world, mut items) = World::released(&[1], &identity);
    items[0].offer.generation += 1;
    vetoed(world.judge(&selection, &identity, &items), "offer differs");
    // Another outstanding request of the session.
    let (mut world, items) = World::released(&[1], &identity);
    world.outstanding = 1;
    vetoed(world.judge(&selection, &identity, &items), "outstanding");
}

#[test]
fn projection_validates_selected_bindings_and_retained_data() {
    let identity = validator();
    let selection = validator_selection();
    // Same validator directory, a different ADNL: selected, then vetoed.
    let other_adnl = expected(Some(0), [0x99; 32]);
    let (world, items) = World::released(&[1], &other_adnl);
    vetoed(world.judge(&selection, &identity, &items), "local ADNL");
    // A recovery-binding mismatch on the selected namespace.
    let mut drifted = identity.clone();
    drifted.recovery_anchor = block(2);
    let (world, items) = World::released(&[1], &drifted);
    vetoed(world.judge(&selection, &identity, &items), "recovery anchor");
    // Retained data of this namespace, and retained data without an origin.
    let (mut world, items) = World::released(&[1], &identity);
    let origin = RecoveryOrigin {
        carrier_version: 2,
        local_adnl: UInt256::from(VALIDATOR_ADNL),
        source_validator: UInt256::from([10; 32]),
        local_validator_index: Some(0),
    };
    let (entry, delivery) = retained(SESSION, Some(origin));
    world.entries.push(entry);
    world.deliveries.push(delivery);
    vetoed(world.judge(&selection, &identity, &items), "still retained");
    let (mut world, items) = World::released(&[1], &identity);
    let (entry, delivery) = retained(SESSION, None);
    world.entries.push(entry);
    world.deliveries.push(delivery);
    vetoed(world.judge(&selection, &identity, &items), "has no origin");
}

#[test]
fn projection_judges_namespaces_of_one_session_independently() {
    let validator_identity = validator();
    let observer_adnl = [0xab; 32];
    let observer_identity = expected(None, observer_adnl);
    let observer_selection = NamespaceSelection {
        session: UInt256::from(SESSION),
        role: NamespaceRole::Observer(UInt256::from(observer_adnl)),
    };
    // The validator directory has an unreleased close and retained data;
    // the observer directory is fully released.
    let (mut world, observer_items) = World::released(&[1], &observer_identity);
    world.closing.push(close(5, &validator_identity, 50, false));
    let origin = RecoveryOrigin {
        carrier_version: 2,
        local_adnl: UInt256::from(VALIDATOR_ADNL),
        source_validator: UInt256::from([10; 32]),
        local_validator_index: Some(0),
    };
    let (entry, delivery) = retained(SESSION, Some(origin));
    world.entries.push(entry);
    world.deliveries.push(delivery);
    assert_eq!(
        world.judge(&observer_selection, &observer_identity, &observer_items),
        CleanupDecision::WouldDelete { closes: 1 },
        "the other namespace's obligations do not block this one"
    );
    vetoed(world.judge(&validator_selection(), &validator_identity, &[]), "still retained");
    // An observer of another ADNL is not selected for this directory.
    let stranger = expected(None, [0xcd; 32]);
    let (mut world, items) = World::released(&[1], &observer_identity);
    world.closing.push(close(6, &stranger, 60, false));
    assert_eq!(
        world.judge(&observer_selection, &observer_identity, &items),
        CleanupDecision::WouldDelete { closes: 1 }
    );
}
