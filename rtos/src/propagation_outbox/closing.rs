// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Atomic close history. Records are bookkeeping; only worker-verified private
//! custody permits a transition. No history GC is implemented here.
use super::*;
use crate::{
    publication_repair::DurableMcFinalRepairCustody, repair_lease_binding::RepairLeaseBinding,
};
const MAX_CLOSE_RECORDS: usize = 16_384;
const MAX_CLOSE_BYTES: usize = 32 << 20;
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClosingRecord {
    pub binding: RepairLeaseBinding,
    pub lease_generation: u64,
    pub dependency_digest: UInt256,
    pub released: bool,
}

/// Comparison-only upgrade of legacy source coordinates against an existing
/// node close. This returns no source confirmation or storage custody authority.
pub(super) fn restore_legacy_request(
    request: &consensus_common::finality_delivery::CloseFinalityRequest,
    record: &ClosingRecord,
) -> Result<consensus_common::finality_delivery::CloseFinalityRequest> {
    let expected = record.offer().request;
    let mut comparable = expected.clone();
    if request.domain.recovery_binding.is_none() {
        comparable.domain.recovery_binding = None;
    }
    if *request != comparable {
        fail!("Legacy source close conflicts with node evidence");
    }
    Ok(expected)
}

impl ClosingRecord {
    pub(crate) fn offer(&self) -> consensus_common::finality_delivery::CloseOffer {
        use consensus_common::finality_delivery::{
            CloseFinalityRequest, CloseOffer, FinalityCloseDomain,
        };
        let b = &self.binding;
        let d = &b.domain;
        CloseOffer {
            generation: b.close_generation,
            request: CloseFinalityRequest {
                canonical: b.canonical.clone(),
                source_digest: b.source_digest.clone(),
                created_at_unix_secs: b.created_at_unix_secs,
                domain: FinalityCloseDomain {
                    pin: consensus_common::session_runtime::SessionNetworkPin {
                        zerostate: d.zerostate.clone(),
                        global_id: d.global_id,
                    },
                    protocol: d.protocol,
                    carrier_version: d.carrier_version,
                    wire_profile: d.wire_profile,
                    recovery_binding: Some(
                        consensus_common::session_runtime::SessionRecoveryBinding {
                            governing_masterchain: d.source_recovery_anchor.clone(),
                            coordinates: d.source_recovery_coordinates.clone(),
                        },
                    ),
                    profile: d.profile.clone(),
                    session_id: d.session_id.clone(),
                },
            },
        }
    }
}

pub(crate) fn effects_digest(effects: &[PublicationEffect]) -> Result<UInt256> {
    let mut out = Encoder { bytes: Vec::new(), maximum: MAX_CLOSE_BYTES };
    out.append(b"RTOS-close-effects-v1")?;
    out.effects(effects)?;
    Ok(UInt256::calc_file_hash(&out.bytes))
}
/// Fixed v1 event encoding, independent of snapshot versions and allocators.
pub(crate) fn canonical_intent_digest(
    entry: &UnverifiedRecord,
    delivery: &Delivery,
) -> Result<UInt256> {
    let r = &entry.record;
    let mut out = Encoder { bytes: Vec::new(), maximum: 128 << 20 };
    out.append(b"RTOS-close-canonical-v1")?;
    out.u64(entry.id.0)?;
    out.id(&r.domain.zerostate)?;
    out.append(&r.domain.global_id.to_le_bytes())?;
    out.byte(match r.domain.wire_profile {
        WireProfile::Legacy => 0,
        WireProfile::T0 => 1,
    })?;
    out.u32(r.protocol.version())?;
    out.hash(&r.profile)?;
    out.hash(&r.session_id)?;
    out.id(&r.block_id)?;
    out.u32(u32::try_from(r.prev.len())?)?;
    for id in &r.prev {
        out.id(id)?;
    }
    out.byte(u8::from(r.carrier.is_final()))?;
    out.blob(r.carrier.bytes())?;
    out.byte(u8::from(r.locally_generated))?;
    out.u64(r.created_at_unix_secs)?;
    out.u64(r.expires_at_unix_secs)?;
    out.blob(&r.block_data)?;
    out.byte(u8::from(r.proof_data.is_some()))?;
    if let Some(proof) = &r.proof_data {
        out.blob(proof)?;
    }
    out.effects(&r.effects)?;
    out.hash(&delivery.delivery_id)?;
    out.u64(delivery.record_id.0)?;
    out.u32(delivery.last_mc)?;
    out.byte(u8::from(delivery.candidate_already_sent))?;
    let origin = delivery.origin.as_ref().ok_or_else(|| error!("Close requires source origin"))?;
    out.u32(origin.carrier_version)?;
    out.hash(&origin.local_adnl)?;
    out.hash(&origin.source_validator)?;
    out.byte(u8::from(origin.local_validator_index.is_some()))?;
    if let Some(index) = origin.local_validator_index {
        out.u32(index)?;
    }
    Ok(UInt256::calc_file_hash(&out.bytes))
}
fn exact_completed(
    snapshot: &Snapshot,
    delivery: &Delivery,
    entry: &UnverifiedRecord,
) -> Result<()> {
    if entry.stage != PublicationStage::Completed
        || !entry.pending.is_empty()
        || delivery.record_id != entry.id
        || delivery.delivery_id != delivery_id(&entry.record)?
        || !snapshot.deliveries.contains(delivery)
        || !snapshot.entries.contains(entry)
    {
        fail!("Close requires unchanged Completed delivery and empty pending effects");
    }
    Ok(())
}
fn check_binding(
    binding: &RepairLeaseBinding,
    entry: &UnverifiedRecord,
    delivery: &Delivery,
) -> Result<()> {
    binding.validate()?;
    let r = &entry.record;
    let origin = delivery.origin.as_ref().ok_or_else(|| error!("Missing close origin"))?;
    if binding.record_id != entry.id.0
        || binding.delivery_id != delivery.delivery_id
        || binding.canonical.block_id != r.block_id
        || !r.carrier.is_final()
        || binding.domain.zerostate != r.domain.zerostate
        || binding.domain.global_id != r.domain.global_id
        || binding.domain.wire_profile != r.domain.wire_profile
        || binding.domain.protocol != r.protocol
        || binding.domain.profile != r.profile
        || binding.domain.session_id != r.session_id
        || binding.domain.carrier_version != origin.carrier_version
        || binding.canonical.local_adnl != origin.local_adnl
        || binding.canonical.local_validator_index != origin.local_validator_index
        || binding.canonical.source_validator != origin.source_validator
        || binding.created_at_unix_secs != r.created_at_unix_secs
        || binding.expires_at_unix_secs != r.expires_at_unix_secs
        || binding.effects_digest != effects_digest(&r.effects)?
        || binding.canonical_digest != canonical_intent_digest(entry, delivery)?
    {
        fail!("Close binding differs from exact canonical event");
    }
    Ok(())
}
fn custody_record(
    binding: &RepairLeaseBinding,
    custody: &DurableMcFinalRepairCustody,
) -> Result<ClosingRecord> {
    if custody.binding() != binding || custody.lease_generation() == 0 {
        fail!("Close custody differs from exact event binding");
    }
    Ok(ClosingRecord {
        binding: binding.clone(),
        lease_generation: custody.lease_generation(),
        dependency_digest: custody.dependency_digest().clone(),
        released: false,
    })
}
impl PropagationOutbox {
    pub(crate) fn lookup_close(&self, id: &UInt256) -> Result<Option<ClosingRecord>> {
        Ok(self.lock()?.snapshot.closing.iter().find(|c| &c.binding.delivery_id == id).cloned())
    }
    /// A failed/abandoned construction burns this durable generation forever.
    pub(crate) fn reserve_close(
        &self,
        delivery: &Delivery,
        entry: &UnverifiedRecord,
    ) -> Result<u64> {
        let mut state = self.lock()?;
        exact_completed(&state.snapshot, delivery, entry)?;
        if state.snapshot.closing.iter().any(|c| c.binding.delivery_id == delivery.delivery_id) {
            fail!("Delivery already closing");
        }
        if state.snapshot.closing.len() >= MAX_CLOSE_RECORDS {
            fail!("Close history capacity exhausted");
        }
        let mut next = state.snapshot.clone();
        let generation = next.next_close_generation;
        next.next_close_generation =
            generation.checked_add(1).ok_or_else(|| error!("Close generation exhausted"))?;
        self.commit(&mut state, next)?;
        Ok(generation)
    }
    pub(crate) fn begin_close_offer(
        &self,
        binding: &RepairLeaseBinding,
        delivery: &Delivery,
        entry: &UnverifiedRecord,
        custody: &DurableMcFinalRepairCustody,
    ) -> Result<ClosingRecord> {
        let record = custody_record(binding, custody)?;
        self.begin_close_offer_inner(record, delivery, entry)
    }
    fn begin_close_offer_inner(
        &self,
        record: ClosingRecord,
        delivery: &Delivery,
        entry: &UnverifiedRecord,
    ) -> Result<ClosingRecord> {
        let mut state = self.lock()?;
        if let Some(old) = state
            .snapshot
            .closing
            .iter()
            .find(|c| c.binding.delivery_id == record.binding.delivery_id)
        {
            if old == &record {
                return Ok(old.clone());
            }
            fail!("Conflicting or terminal close offer");
        }
        exact_completed(&state.snapshot, delivery, entry)?;
        check_binding(&record.binding, entry, delivery)?;
        if record.binding.close_generation >= state.snapshot.next_close_generation
            || state
                .snapshot
                .closing
                .iter()
                .any(|c| c.binding.close_generation == record.binding.close_generation)
        {
            fail!("Close generation was not reserved or was reused");
        }
        let mut next = state.snapshot.clone();
        next.closing.push(record.clone());
        self.commit(&mut state, next)?;
        Ok(record)
    }
    /// Require both private custody and the opaque source WAL confirmation.
    /// The serialized worker additionally authenticates historical runtime and
    /// ledger ownership; no caller can substitute a network boolean here.
    pub(crate) fn confirm_close(
        &self,
        binding: &RepairLeaseBinding,
        custody: &DurableMcFinalRepairCustody,
        confirmation: &simplex::finality_delivery::DeliveredConfirmation,
    ) -> Result<ClosingRecord> {
        let expected = custody_record(binding, custody)?;
        let offer = expected.offer();
        if confirmation.offer() != &offer
            || confirmation.source_id()
                != &simplex::finality_delivery::close_source_id(&offer.request)?
        {
            fail!("Close requires the exact durable source confirmation");
        }
        self.confirm_close_inner(expected)
    }
    fn confirm_close_inner(&self, expected: ClosingRecord) -> Result<ClosingRecord> {
        let mut state = self.lock()?;
        let index = state
            .snapshot
            .closing
            .iter()
            .position(|c| c.binding.delivery_id == expected.binding.delivery_id)
            .ok_or_else(|| error!("Unknown close offer"))?;
        let old = &state.snapshot.closing[index];
        let mut compare = old.clone();
        compare.released = false;
        if compare != expected {
            fail!("Close confirmation changed binding or custody");
        }
        if old.released {
            return Ok(old.clone());
        }
        let delivery = state
            .snapshot
            .deliveries
            .iter()
            .find(|d| d.delivery_id == expected.binding.delivery_id)
            .ok_or_else(|| error!("Close offer lost canonical delivery"))?;
        let entry = state
            .snapshot
            .entries
            .iter()
            .find(|e| e.id == delivery.record_id)
            .ok_or_else(|| error!("Close offer lost canonical entry"))?;
        exact_completed(&state.snapshot, delivery, entry)?;
        check_binding(&expected.binding, entry, delivery)?;
        let mut next = state.snapshot.clone();
        next.closing[index].released = true;
        next.entries.retain(|e| e.id.0 != expected.binding.record_id);
        next.deliveries.retain(|d| d.delivery_id != expected.binding.delivery_id);
        let result = next.closing[index].clone();
        self.commit(&mut state, next)?;
        Ok(result)
    }
}
pub(super) fn reject_terminal_record(
    snapshot: &Snapshot,
    record: &PublicationRecord,
) -> Result<()> {
    let id = delivery_id(record)?;
    if snapshot.closing.iter().any(|c| c.binding.delivery_id == id) {
        fail!("Event has entered close protocol; canonical revival forbidden");
    }
    Ok(())
}
fn validate_history(snapshot: &Snapshot, domain: &OutboxDomain) -> Result<()> {
    if snapshot.next_close_generation == 0 || snapshot.closing.len() > MAX_CLOSE_RECORDS {
        fail!("Invalid close history capacity/allocator");
    }
    let mut ids = BTreeSet::new();
    let mut generations = BTreeSet::new();
    let mut records = BTreeSet::new();
    let mut bytes = 0usize;
    for c in &snapshot.closing {
        bytes = bytes
            .checked_add(c.binding.encode()?.len() + 45)
            .ok_or_else(|| error!("Close bytes overflow"))?;
        if bytes > MAX_CLOSE_BYTES
            || c.lease_generation == 0
            || c.binding.close_generation >= snapshot.next_close_generation
            || c.binding.record_id == 0
            || c.binding.record_id >= snapshot.next_id
            || c.binding.domain.zerostate != domain.zerostate
            || c.binding.domain.global_id != domain.global_id
            || c.binding.domain.wire_profile != domain.wire_profile
            || c.binding.delivery_id
                != delivery_coordinates(
                    domain,
                    c.binding.domain.protocol,
                    &c.binding.domain.profile,
                    &c.binding.domain.session_id,
                    &c.binding.canonical.block_id,
                    true,
                )?
            || !ids.insert(c.binding.delivery_id.clone())
            || !generations.insert(c.binding.close_generation)
            || !records.insert(c.binding.record_id)
        {
            fail!("Invalid close history binding or quota");
        }
        let entry = snapshot.entries.iter().find(|e| e.id.0 == c.binding.record_id);
        let delivery = snapshot.deliveries.iter().find(|d| d.delivery_id == c.binding.delivery_id);
        if c.released {
            if entry.is_some()
                || delivery.is_some()
                || snapshot
                    .entries
                    .iter()
                    .any(|e| delivery_id(&e.record).is_ok_and(|id| id == c.binding.delivery_id))
            {
                fail!("Released event still has canonical data");
            }
        } else {
            let (Some(e), Some(d)) = (entry, delivery) else {
                fail!("Close offer missing canonical data");
            };
            exact_completed(snapshot, d, e)?;
            check_binding(&c.binding, e, d)?;
        }
    }
    Ok(())
}
pub(super) fn encode_closing(
    snapshot: &Snapshot,
    domain: &OutboxDomain,
    _limits: &Limits,
    out: &mut Encoder,
) -> Result<()> {
    validate_history(snapshot, domain)?;
    out.u64(snapshot.next_close_generation)?;
    out.u32(u32::try_from(snapshot.closing.len())?)?;
    for c in &snapshot.closing {
        out.blob(&c.binding.encode()?)?;
        out.u64(c.lease_generation)?;
        out.hash(&c.dependency_digest)?;
        out.byte(u8::from(c.released))?;
    }
    Ok(())
}
pub(super) fn decode_closing(
    input: &mut Decoder<'_>,
    domain: &OutboxDomain,
    _limits: &Limits,
    next_id: u64,
    entries: &[UnverifiedRecord],
    deliveries: &[Delivery],
) -> Result<(u64, Vec<ClosingRecord>)> {
    let next_close_generation = input.u64()?;
    let count = input.count(MAX_CLOSE_RECORDS)?;
    let mut closing = Vec::new();
    let mut bytes = 0usize;
    for _ in 0..count {
        let raw = input.blob(crate::repair_lease_binding::MAX_REPAIR_BINDING_BYTES)?;
        bytes =
            bytes.checked_add(raw.len() + 45).ok_or_else(|| error!("Close history overflow"))?;
        if bytes > MAX_CLOSE_BYTES {
            fail!("Close history byte quota exhausted");
        }
        closing.push(ClosingRecord {
            binding: RepairLeaseBinding::decode(&raw)?,
            lease_generation: input.u64()?,
            dependency_digest: input.hash()?,
            released: input.boolean()?,
        });
    }
    let snapshot = Snapshot {
        next_close_generation,
        closing,
        next_id,
        entries: entries.to_vec(),
        deliveries: deliveries.to_vec(),
    };
    validate_history(&snapshot, domain)?;
    Ok((next_close_generation, snapshot.closing))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repair_lease_binding::RepairLeaseDomain;
    use consensus_common::finality_delivery::{CanonicalFinalityRequest, FinalityDeliveryRole};
    use std::sync::atomic::{AtomicU8, Ordering};
    #[derive(Default)]
    struct Disk {
        bytes: Mutex<Option<Vec<u8>>>,
        fail: AtomicU8,
    }
    impl SnapshotStore for Disk {
        fn load(&self, maximum: usize) -> Result<Option<Vec<u8>>> {
            let bytes = self.bytes.lock().unwrap().clone();
            if bytes.as_ref().is_some_and(|b| b.len() > maximum) {
                fail!("limit");
            }
            Ok(bytes)
        }
        fn replace_sync(&self, bytes: &[u8]) -> Result<()> {
            let failure = self.fail.load(Ordering::SeqCst);
            if failure == 1 {
                fail!("before");
            }
            *self.bytes.lock().unwrap() = Some(bytes.to_vec());
            if failure == 2 {
                fail!("after");
            }
            Ok(())
        }
    }
    fn id(seq: u32) -> BlockIdExt {
        BlockIdExt::with_params(
            ShardIdent::masterchain(),
            seq,
            UInt256::from([1; 32]),
            UInt256::from([2; 32]),
        )
    }
    fn domain() -> OutboxDomain {
        OutboxDomain { zerostate: id(0), global_id: -1, wire_profile: WireProfile::T0 }
    }
    fn open(disk: Arc<Disk>) -> PropagationOutbox {
        PropagationOutbox::load(
            disk,
            domain(),
            Limits { max_records: 1, ..Limits::default() },
            None,
        )
        .unwrap()
    }
    fn setup(
        store: &PropagationOutbox,
        seq: u32,
    ) -> Result<(Delivery, UnverifiedRecord, ClosingRecord)> {
        let record = PublicationRecord {
            domain: domain(),
            protocol: SimplexProtocol::PrivateObserversPlumtree,
            profile: UInt256::from([3; 32]),
            session_id: UInt256::from([4; 32]),
            block_id: id(seq),
            block_data: vec![1, 2],
            proof_data: None,
            prev: vec![id(seq - 1)],
            carrier: StoredCarrier::Final(vec![9]),
            locally_generated: false,
            created_at_unix_secs: 10,
            expires_at_unix_secs: 20,
            effects: vec![],
        };
        let origin = RecoveryOrigin {
            carrier_version: 2,
            local_adnl: UInt256::from([5; 32]),
            source_validator: UInt256::from([6; 32]),
            local_validator_index: None,
        };
        let receipt = store.stage_draft(record, 4, false, Some(origin.clone()))?;
        let (d, e) = store.delivery(&receipt)?.unwrap();
        store.mark_accepted(e.id)?;
        store.resolve_draft(e.id, vec![])?;
        let (d, e) = store.delivery(&d.delivery_id)?.unwrap();
        let generation = store.reserve_close(&d, &e)?;
        let binding = RepairLeaseBinding {
            record_id: e.id.0,
            delivery_id: receipt.clone(),
            canonical: CanonicalFinalityRequest {
                node_receipt: receipt,
                block_id: e.record.block_id.clone(),
                role: FinalityDeliveryRole::Final,
                local_adnl: origin.local_adnl,
                source_validator: origin.source_validator,
                local_validator_index: None,
            },
            domain: RepairLeaseDomain {
                zerostate: id(0),
                global_id: -1,
                history_init: id(0),
                source_recovery_anchor: id(0),
                source_recovery_coordinates:
                    consensus_common::session_runtime::SessionRecoveryCoordinates {
                        shard: ShardIdent::masterchain(),
                        catchain_seqno: 1,
                        vertical_seqno: 0,
                        last_key_block_seqno: 0,
                        new_catchain_ids: false,
                    },
                protocol: e.record.protocol,
                profile: e.record.profile.clone(),
                session_id: e.record.session_id.clone(),
                carrier_version: 2,
                wire_profile: WireProfile::T0,
            },
            source_digest: UInt256::from([7; 32]),
            canonical_digest: canonical_intent_digest(&e, &d)?,
            created_at_unix_secs: 10,
            expires_at_unix_secs: 20,
            effects_digest: effects_digest(&[])?,
            close_generation: generation,
        };
        Ok((
            d,
            e,
            ClosingRecord {
                binding,
                lease_generation: generation,
                dependency_digest: UInt256::from([8; 32]),
                released: false,
            },
        ))
    }
    #[test]
    fn close_legacy_coordinates_require_exact_original_evidence() -> Result<()> {
        let store = open(Arc::new(Disk::default()));
        let (_, _, record) = setup(&store, 1)?;
        let expected = record.offer().request;
        let mut legacy = expected.clone();
        legacy.domain.recovery_binding = None;
        assert_eq!(restore_legacy_request(&legacy, &record)?, expected);
        for index in 0..7 {
            let mut wrong = legacy.clone();
            match index {
                0 => wrong.source_digest = UInt256::from([91; 32]),
                1 => wrong.created_at_unix_secs += 1,
                2 => wrong.canonical.node_receipt = UInt256::from([92; 32]),
                3 => wrong.canonical.role = FinalityDeliveryRole::Approval,
                4 => wrong.domain.session_id = UInt256::from([93; 32]),
                5 => wrong.canonical.block_id.file_hash = UInt256::from([94; 32]),
                _ => wrong.domain.pin.global_id += 1,
            }
            assert!(restore_legacy_request(&wrong, &record).is_err());
        }
        let mut wrong_anchor = expected.clone();
        wrong_anchor.domain.recovery_binding.as_mut().unwrap().governing_masterchain = id(9);
        assert!(restore_legacy_request(&wrong_anchor, &record).is_err());
        Ok(())
    }

    #[test]
    fn close_atomic_reopen_replay_and_active_quota() -> Result<()> {
        let disk = Arc::new(Disk::default());
        let store = open(disk.clone());
        let (d, e, c) = setup(&store, 1)?;
        store.begin_close_offer_inner(c.clone(), &d, &e)?;
        assert!(store.delivery(&d.delivery_id)?.is_some());
        assert!(store
            .stage_draft(e.record.clone(), d.last_mc, d.candidate_already_sent, d.origin.clone())
            .is_err());
        drop(store);
        let store = open(disk.clone());
        assert_eq!(store.lookup_close(&d.delivery_id)?, Some(c.clone()));
        let terminal = store.confirm_close_inner(c.clone())?;
        assert!(terminal.released);
        assert!(store.delivery(&d.delivery_id)?.is_none());
        assert_eq!(store.confirm_close_inner(c.clone())?, terminal);
        let mut wrong = c.clone();
        wrong.binding.source_digest = UInt256::default();
        assert!(store.confirm_close_inner(wrong).is_err());
        let mut replay = e.record.clone();
        replay.effects.push(PublicationEffect {
            kind: PublicationKind::Block,
            target: PublicationTarget::Public,
        });
        assert!(store.enqueue(replay).is_err());
        drop(store);
        let store = open(disk);
        assert!(store.lookup_close(&d.delivery_id)?.unwrap().released);
        let (d2, e2, c2) = setup(&store, 2)?;
        assert!(e2.id.0 > e.id.0 && c2.binding.close_generation > c.binding.close_generation);
        store.begin_close_offer_inner(c2.clone(), &d2, &e2)?;
        store.confirm_close_inner(c2)?;
        Ok(())
    }
    #[test]
    fn close_uncertain_snapshot_never_exposes_payload_without_tombstone() -> Result<()> {
        for failure in [1, 2] {
            let disk = Arc::new(Disk::default());
            let store = open(disk.clone());
            let (d, e, c) = setup(&store, 1)?;
            store.begin_close_offer_inner(c.clone(), &d, &e)?;
            disk.fail.store(failure, Ordering::SeqCst);
            assert!(store.confirm_close_inner(c.clone()).is_err());
            assert!(store.lookup_close(&d.delivery_id).is_err());
            disk.fail.store(0, Ordering::SeqCst);
            drop(store);
            let store = open(disk);
            let closed = store.lookup_close(&d.delivery_id)?.unwrap();
            assert_eq!(closed.released, failure == 2);
            assert_eq!(store.delivery(&d.delivery_id)?.is_none(), failure == 2);
            assert!(store.confirm_close_inner(c)?.released);
        }
        Ok(())
    }
    #[test]
    fn close_exact_changed_event_and_generation_rejected() -> Result<()> {
        let store = open(Arc::new(Disk::default()));
        let (d, e, c) = setup(&store, 1)?;
        for kind in 0..5 {
            let mut bad = c.clone();
            match kind {
                0 => bad.binding.canonical.local_adnl = UInt256::default(),
                1 => bad.binding.canonical.role = FinalityDeliveryRole::Approval,
                2 => bad.binding.close_generation += 100,
                3 => bad.binding.canonical_digest = UInt256::default(),
                _ => bad.binding.effects_digest = UInt256::default(),
            }
            assert!(store.begin_close_offer_inner(bad, &d, &e).is_err());
        }
        let mut changed = e.clone();
        changed.record.carrier = StoredCarrier::Final(vec![10]);
        assert!(store.begin_close_offer_inner(c.clone(), &d, &changed).is_err());
        store.begin_close_offer_inner(c.clone(), &d, &e)?;
        assert_eq!(store.begin_close_offer_inner(c.clone(), &d, &e)?, c);
        Ok(())
    }
    #[test]
    fn close_real_snapshot_database_reopen_preserves_terminal() -> Result<()> {
        use storage::{
            block_handle_db::NodeStateDb,
            db::rocksdb::{AccessType, RocksDb},
        };
        struct RealDisk(NodeStateDb);
        impl SnapshotStore for RealDisk {
            fn load(&self, maximum: usize) -> Result<Option<Vec<u8>>> {
                let value = self.0.try_get_raw(KEY.as_bytes())?;
                if value.as_ref().is_some_and(|v| v.len() > maximum) {
                    fail!("snapshot limit");
                }
                Ok(value.map(|v| v.to_vec()))
            }
            fn replace_sync(&self, bytes: &[u8]) -> Result<()> {
                self.0.put_raw_sync(KEY.as_bytes(), bytes)
            }
        }
        fn reopen(path: &std::path::Path) -> Result<PropagationOutbox> {
            let db = RocksDb::new(path, "close-test", None, AccessType::ReadWrite)?;
            let disk = Arc::new(RealDisk(NodeStateDb::with_db(db, "snapshot", true)?));
            PropagationOutbox::load(disk, domain(), Limits::default(), None)
        }
        let dir = tempfile::tempdir()?;
        let store = reopen(dir.path())?;
        let (d, e, c) = setup(&store, 1)?;
        store.begin_close_offer_inner(c.clone(), &d, &e)?;
        drop(store);
        let store = reopen(dir.path())?;
        assert_eq!(store.lookup_close(&d.delivery_id)?, Some(c.clone()));
        assert!(store.delivery(&d.delivery_id)?.is_some());
        store.confirm_close_inner(c.clone())?;
        drop(store);
        let store = reopen(dir.path())?;
        assert!(store.lookup_close(&d.delivery_id)?.unwrap().released);
        assert!(store.delivery(&d.delivery_id)?.is_none());
        assert!(store
            .stage_draft(e.record, d.last_mc, d.candidate_already_sent, d.origin)
            .is_err());
        assert_eq!(store.confirm_close_inner(c)?.offer().generation, 1);
        Ok(())
    }
    #[test]
    fn close_reserved_generation_uncertainty_and_schema_three_migration() -> Result<()> {
        let disk = Arc::new(Disk::default());
        let store = open(disk.clone());
        let (d, e, c) = setup(&store, 1)?;
        // Existing schema 3 has the same entry/delivery payload, without v4's
        // empty close allocator/table. Import it and reserve anew, never infer
        // an offer or release from an older Completed tag.
        let mut old = disk.load(1 << 20)?.unwrap();
        old.drain(old.len() - DIGEST_BYTES - 12..old.len() - DIGEST_BYTES);
        old[8..10].copy_from_slice(&3u16.to_le_bytes());
        let n = old.len() - DIGEST_BYTES;
        let hash = UInt256::calc_file_hash(&old[..n]);
        old[n..].copy_from_slice(hash.as_slice());
        *disk.bytes.lock().unwrap() = Some(old);
        drop(store);
        let store = open(disk.clone());
        assert!(store.lookup_close(&d.delivery_id)?.is_none());
        let first = store.reserve_close(&d, &e)?;
        assert_eq!(first, 1);
        disk.fail.store(2, Ordering::SeqCst);
        assert!(store.reserve_close(&d, &e).is_err());
        assert!(store.reserve_close(&d, &e).is_err());
        disk.fail.store(0, Ordering::SeqCst);
        drop(store);
        let store = open(disk);
        assert_eq!(store.reserve_close(&d, &e)?, 3);
        // Supplied stale event changes are independently rejected.
        let mut changed = d.clone();
        changed.last_mc += 1;
        assert!(store.reserve_close(&changed, &e).is_err());
        assert_eq!(c.binding.close_generation, 1);
        Ok(())
    }
    #[test]
    fn close_compact_codec_quota_is_independent_of_active_payload_count() -> Result<()> {
        // Codec-only capacity evidence; actual Engine circulation is separately tested.
        let disk = Arc::new(Disk::default());
        let store = open(disk.clone());
        let (d, e, c) = setup(&store, 1)?;
        store.begin_close_offer_inner(c.clone(), &d, &e)?;
        store.confirm_close_inner(c)?;
        let mut snapshot = store.lock()?.snapshot.clone();
        let base = snapshot.closing[0].clone();
        for n in 2..=1025u32 {
            let mut row = base.clone();
            row.binding.record_id = u64::from(n);
            row.binding.close_generation = u64::from(n);
            row.binding.canonical.block_id = id(n);
            row.binding.delivery_id = delivery_coordinates(
                &domain(),
                row.binding.domain.protocol,
                &row.binding.domain.profile,
                &row.binding.domain.session_id,
                &row.binding.canonical.block_id,
                true,
            )?;
            row.binding.canonical.node_receipt = row.binding.delivery_id.clone();
            snapshot.closing.push(row);
        }
        snapshot.next_id = 1026;
        snapshot.next_close_generation = 1026;
        let limits = Limits { max_records: 1, ..Limits::default() };
        let encoded = encode_snapshot(&snapshot, &domain(), &limits)?;
        let decoded = decode_snapshot(&encoded, &domain(), &limits)?;
        assert_eq!(decoded.closing.len(), 1025);
        assert!(decoded.entries.is_empty());
        let mut bad = decoded.clone();
        bad.closing[0].binding.canonical.block_id = id(2000);
        assert!(encode_snapshot(&bad, &domain(), &limits).is_err());
        let mut bad = decoded;
        bad.closing.resize(MAX_CLOSE_RECORDS + 1, base);
        assert!(encode_snapshot(&bad, &domain(), &limits).is_err());
        Ok(())
    }
    #[test]
    fn close_real_compact_admission_capacity_preserves_snapshot_and_canonical() -> Result<()> {
        use storage::{block_handle_db::NodeStateDb, db::rocksdb::{AccessType, RocksDb}};
        struct CapacityDisk(NodeStateDb);
        impl SnapshotStore for CapacityDisk {
            fn load(&self, maximum: usize) -> Result<Option<Vec<u8>>> {
                let value = self.0.try_get_raw(KEY.as_bytes())?;
                if value.as_ref().is_some_and(|v| v.len() > maximum) { fail!("snapshot limit"); }
                Ok(value.map(|v| v.to_vec()))
            }
            fn replace_sync(&self, bytes: &[u8]) -> Result<()> {
                self.0.put_raw_sync(KEY.as_bytes(), bytes)
            }
        }
        fn reopen(path: &std::path::Path) -> Result<PropagationOutbox> {
            let db = RocksDb::new(path, "compact-capacity", None, AccessType::ReadWrite)?;
            let disk = Arc::new(CapacityDisk(NodeStateDb::with_db(db, "snapshot", true)?));
            PropagationOutbox::load(disk, domain(), Limits::default(), None)
        }
        let dir = tempfile::tempdir()?;
        let store = reopen(dir.path())?;
        let (d1, e1, first) = setup(&store, 1)?;
        let (d2, e2, second) = setup(&store, 2)?;
        let first_size = first.binding.encode()?.len() + 45;
        let second_size = second.binding.encode()?.len() + 45;
        let mut snapshot = store.lock()?.snapshot.clone();
        let mut total = 0usize;
        // Seed codec-valid Released history, not capabilities or authenticated
        // events. The two pending records use the real admission transaction.
        for n in 3..MAX_CLOSE_RECORDS as u32 + 3 {
            let mut row = first.clone();
            row.released = true;
            row.lease_generation = u64::from(n);
            row.binding.record_id = u64::from(n);
            row.binding.close_generation = u64::from(n);
            row.binding.canonical.block_id = id(n);
            row.binding.delivery_id = delivery_coordinates(&domain(), row.binding.domain.protocol,
                &row.binding.domain.profile, &row.binding.domain.session_id,
                &row.binding.canonical.block_id, true)?;
            row.binding.canonical.node_receipt = row.binding.delivery_id.clone();
            let size = row.binding.encode()?.len() + 45;
            if snapshot.closing.len() + 1 >= MAX_CLOSE_RECORDS
                || total + size + first_size > MAX_CLOSE_BYTES { break; }
            total += size;
            snapshot.closing.push(row);
        }
        // Decimal timestamps are legitimate bounded fields. Fill any small
        // remainder caused by differing numeric ID widths, without padding JSON
        // or raising production limits, so exactly one offered row still fits.
        if snapshot.closing.len() + 1 < MAX_CLOSE_RECORDS {
            for row in snapshot.closing.iter_mut().rev() {
                if total + first_size + second_size > MAX_CLOSE_BYTES { break; }
                let original = row.binding.encode()?.len();
                for digits in 3..=19u32 {
                    row.binding.expires_at_unix_secs = 10u64.pow(digits - 1);
                    let extra = row.binding.encode()?.len() - original;
                    if total + extra + first_size + second_size > MAX_CLOSE_BYTES {
                        assert!(total + extra + first_size <= MAX_CLOSE_BYTES);
                        break;
                    }
                }
                total += row.binding.encode()?.len() - original;
            }
        }
        snapshot.next_id = snapshot.closing.len() as u64 + 3;
        snapshot.next_close_generation = snapshot.next_id;
        assert!(snapshot.closing.len() + 1 == MAX_CLOSE_RECORDS
            || total + first_size + second_size > MAX_CLOSE_BYTES);
        let seed = encode_snapshot(&snapshot, &domain(), &Limits::default())?;
        store.store.replace_sync(&seed)?;
        drop(store);
        let store = reopen(dir.path())?;
        store.begin_close_offer_inner(first.clone(), &d1, &e1)?;
        let before = store.store.load(Limits::default().max_snapshot_bytes)?.unwrap();
        let error = store.begin_close_offer_inner(second.clone(), &d2, &e2)
            .unwrap_err().to_string();
        if snapshot.closing.len() + 1 == MAX_CLOSE_RECORDS {
            assert!(error.contains("Invalid close history capacity/allocator"), "{error}");
        } else {
            assert!(error.contains("Invalid close history binding or quota"), "{error}");
        }
        assert_eq!(store.store.load(Limits::default().max_snapshot_bytes)?.unwrap(), before);
        assert!(store.delivery(&d1.delivery_id)?.is_some());
        assert!(store.delivery(&d2.delivery_id)?.is_some());
        assert_eq!(store.lookup_close(&d1.delivery_id)?, Some(first.clone()));
        assert_eq!(store.lookup_close(&d2.delivery_id)?, None);
        eprintln!("compact admission boundary: records={}, bytes={}, rejection={error}",
            snapshot.closing.len() + 1, total + first_size);
        drop(store);
        let store = reopen(dir.path())?;
        assert_eq!(store.store.load(Limits::default().max_snapshot_bytes)?.unwrap(), before);
        assert!(store.delivery(&d1.delivery_id)?.is_some());
        assert!(store.delivery(&d2.delivery_id)?.is_some());
        assert_eq!(store.lookup_close(&d1.delivery_id)?, Some(first));
        assert_eq!(store.lookup_close(&d2.delivery_id)?, None);
        Ok(())
    }

}
