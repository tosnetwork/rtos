// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Atomic close history. Records are bookkeeping; only worker-verified private
//! custody permits a transition. No history GC is implemented here.
use super::*;
use crate::{
    publication_repair::DurableMcFinalRepairCustody, repair_lease_binding::RepairLeaseBinding,
};
const MAX_CLOSE_RECORDS: usize = 16_384;
const MAX_CLOSE_BYTES: usize = 32 << 20;
/// The largest stored close value: its binding plus fixed fields and header.
pub(super) const MAX_CLOSE_VALUE_BYTES: usize =
    crate::repair_lease_binding::MAX_REPAIR_BINDING_BYTES + 256;
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

/// Why a close no longer matches the association recorded at B0, if it
/// does not: it must be Released, bound to the same lease and generations,
/// and its full binding must hash to the recorded digest.
pub(crate) fn association_mismatch(
    close: &ClosingRecord,
    association: &consensus_common::validator_cleanup::CleanupAssociation,
) -> Result<Option<String>> {
    let id = &association.delivery_id;
    let reason = if !close.released {
        Some(format!("close {id:x} is not Released"))
    } else if close.lease_generation != association.lease_generation
        || close.binding.close_generation != association.close_generation
        || close.dependency_digest != association.dependency_digest
    {
        Some(format!("close {id:x} changed its lease or generation"))
    } else if UInt256::calc_file_hash(&close.binding.encode()?) != association.binding_digest {
        Some(format!("close {id:x} binding differs from the journal"))
    } else {
        None
    };
    Ok(reason)
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
        let generation = state.snapshot.next_close_generation;
        let next = generation.checked_add(1).ok_or_else(|| error!("Close generation exhausted"))?;
        let mut batch = Batch::default();
        self.put_meta(&mut batch, state.snapshot.next_id, next)?;
        self.commit(&mut state, batch)?;
        state.snapshot.next_close_generation = next;
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
        let quota = close_quota(&record)?;
        let close_bytes =
            state.close_bytes.checked_add(quota).ok_or_else(|| error!("Close bytes overflow"))?;
        if close_bytes > MAX_CLOSE_BYTES || state.snapshot.closing.len() >= MAX_CLOSE_RECORDS {
            fail!("Close history byte quota exhausted");
        }
        let mut batch = Batch::default();
        self.put_close(&mut batch, &record)?;
        self.commit(&mut state, batch)?;
        state.close_bytes = close_bytes;
        state.snapshot.closing.push(record.clone());
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
        let record_id = entry.id;
        let mut result = state.snapshot.closing[index].clone();
        result.released = true;
        let mut batch = Batch::default();
        self.put_close(&mut batch, &result)?;
        batch.deletes.push(body_key(record_id));
        batch.deletes.push(state_key(record_id));
        self.commit(&mut state, batch)?;
        state.snapshot.closing[index].released = true;
        state.snapshot.entries.retain(|e| e.id != record_id);
        state.snapshot.deliveries.retain(|d| d.delivery_id != expected.binding.delivery_id);
        state.synced.remove(&record_id);
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
pub(super) fn validate_history(snapshot: &Snapshot, domain: &OutboxDomain) -> Result<()> {
    validate_history_with(snapshot, domain, delivery_id)
}

/// The bytes one close counts against the close history quota.
pub(super) fn close_quota(close: &ClosingRecord) -> Result<usize> {
    close.binding.encode()?.len().checked_add(45).ok_or_else(|| error!("Close bytes overflow"))
}
fn validate_history_with(
    snapshot: &Snapshot,
    domain: &OutboxDomain,
    mut live_delivery_id: impl FnMut(&PublicationRecord) -> Result<UInt256>,
) -> Result<()> {
    if snapshot.next_close_generation == 0 || snapshot.closing.len() > MAX_CLOSE_RECORDS {
        fail!("Invalid close history capacity/allocator");
    }
    // Each released record must exclude every live delivery identity, even
    // under a different record ID. Hash the immutable identity once per live
    // entry instead of repeating the same scan for every released record.
    let live_delivery_ids: BTreeSet<_> = if snapshot.closing.iter().any(|c| c.released) {
        snapshot.entries.iter().filter_map(|entry| live_delivery_id(&entry.record).ok()).collect()
    } else {
        BTreeSet::new()
    };
    let mut ids = BTreeSet::new();
    let mut generations = BTreeSet::new();
    let mut records = BTreeSet::new();
    let mut bytes = 0usize;
    for c in &snapshot.closing {
        bytes = bytes.checked_add(close_quota(c)?).ok_or_else(|| error!("Close bytes overflow"))?;
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
                || live_delivery_ids.contains(&c.binding.delivery_id)
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
/// One stored close value, bound to the outbox domain.
pub(super) fn encode_close(domain_digest: &UInt256, c: &ClosingRecord) -> Result<Vec<u8>> {
    let mut out = value_encoder(CLOSE_MAGIC, domain_digest)?;
    out.maximum = MAX_CLOSE_VALUE_BYTES;
    out.blob(&c.binding.encode()?)?;
    out.u64(c.lease_generation)?;
    out.hash(&c.dependency_digest)?;
    out.byte(u8::from(c.released))?;
    Ok(seal(out))
}
pub(super) fn decode_close(bytes: &[u8], domain_digest: &UInt256) -> Result<ClosingRecord> {
    if bytes.len() > MAX_CLOSE_VALUE_BYTES {
        fail!("Outbox close value too large");
    }
    let mut input = open_value(bytes, CLOSE_MAGIC, domain_digest)?;
    let raw = input.blob(crate::repair_lease_binding::MAX_REPAIR_BINDING_BYTES)?;
    let close = ClosingRecord {
        binding: RepairLeaseBinding::decode(&raw)?,
        lease_generation: input.u64()?,
        dependency_digest: input.hash()?,
        released: input.boolean()?,
    };
    input.finish()?;
    Ok(close)
}

/// Seeds synthetic Released bookkeeping for crash tests; bypasses authentication
/// and private custody only while constructing the durable test baseline.
#[cfg(test)]
pub(crate) fn seed_released_pair_for_recovery(
    store: &PropagationOutbox, ids: [BlockIdExt; 3],
) -> Result<(ClosingRecord, ClosingRecord)> {
    let (d, e, c) = tests::setup_with_ids(store, ids[1].clone(), ids[0].clone())?;
    store.begin_close_offer_inner(c.clone(), &d, &e)?;
    let first = store.confirm_close_inner(c)?;
    let (d, e, c) = tests::setup_with_ids(store, ids[2].clone(), ids[1].clone())?;
    store.begin_close_offer_inner(c.clone(), &d, &e)?;
    Ok((first, store.confirm_close_inner(c)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        propagation_outbox::test_stores::{DiskStore, MemoryStore as Disk},
        repair_lease_binding::RepairLeaseDomain,
    };
    use consensus_common::finality_delivery::{CanonicalFinalityRequest, FinalityDeliveryRole};
    use std::sync::atomic::Ordering;
    /// Whether the journal key was written beside the outbox rows.
    fn journal_written(disk: &Disk) -> bool {
        disk.rows.lock().unwrap().contains_key("journal")
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
        setup_with_ids(store, id(seq), id(seq - 1))
    }
    pub(super) fn setup_with_ids(
        store: &PropagationOutbox, block_id: BlockIdExt, previous: BlockIdExt,
    ) -> Result<(Delivery, UnverifiedRecord, ClosingRecord)> {
        let record = PublicationRecord {
            domain: store.domain().clone(),
            protocol: SimplexProtocol::PrivateObserversPlumtree,
            profile: UInt256::from([3; 32]),
            session_id: UInt256::from([4; 32]),
            block_id,
            block_data: vec![1, 2],
            proof_data: None,
            prev: vec![previous],
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
                zerostate: store.domain().zerostate.clone(),
                global_id: store.domain().global_id,
                history_init: store.domain().zerostate.clone(),
                source_recovery_anchor: store.domain().zerostate.clone(),
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
    fn association(
        close: &ClosingRecord,
    ) -> Result<consensus_common::validator_cleanup::CleanupAssociation> {
        Ok(consensus_common::validator_cleanup::CleanupAssociation {
            delivery_id: close.binding.delivery_id.clone(),
            close_generation: close.binding.close_generation,
            lease_generation: close.lease_generation,
            dependency_digest: close.dependency_digest.clone(),
            binding_digest: UInt256::calc_file_hash(&close.binding.encode()?),
        })
    }
    /// Two Released closes; returns them in order.
    fn released_pair(store: &PropagationOutbox) -> Result<(ClosingRecord, ClosingRecord)> {
        let (d, e, c) = setup(store, 1)?;
        store.begin_close_offer_inner(c.clone(), &d, &e)?;
        let first = store.confirm_close_inner(c)?;
        let (d, e, c) = setup(store, 2)?;
        store.begin_close_offer_inner(c.clone(), &d, &e)?;
        let second = store.confirm_close_inner(c)?;
        Ok((first, second))
    }
    #[test]
    fn close_history_hashes_live_ids_once_and_refuses_revival_under_a_new_record_id() -> Result<()> {
        let store = PropagationOutbox::load(Arc::new(Disk::default()), domain(), Limits::default(), None)?;
        let mut revival = None;
        for seq in 1..=8 {
            let (delivery, entry, close) = setup(&store, seq)?;
            if revival.is_none() { revival = Some(entry); }
            let entry = store.delivery(&delivery.delivery_id)?.unwrap().1;
            store.begin_close_offer_inner(close.clone(), &delivery, &entry)?;
            store.confirm_close_inner(close)?;
        }
        for seq in 9..=12 { setup(&store, seq)?; }
        let mut snapshot = store.state.lock().unwrap().snapshot.clone();
        assert_eq!(snapshot.entries.len(), 4);
        assert_eq!(snapshot.closing.iter().filter(|c| c.released).count(), 8);
        let mut hashes = 0usize;
        validate_history_with(&snapshot, &domain(), |record| {
            hashes += 1;
            delivery_id(record)
        })?;
        assert!(hashes <= snapshot.entries.len(), "rehashed live delivery IDs for each released record: {hashes}");
        let mut revived = revival.unwrap();
        revived.id = RecordId(snapshot.next_id);
        snapshot.next_id += 1;
        snapshot.entries.push(revived);
        assert!(validate_history(&snapshot, &domain()).is_err(), "a new record ID cannot revive a released delivery");
        snapshot.entries.pop();
        snapshot.closing.clear();
        let mut hashes = 0usize;
        validate_history_with(&snapshot, &domain(), |record| {
            hashes += 1;
            delivery_id(record)
        })?;
        assert_eq!(hashes, 0, "no released history needs no live ID set");
        Ok(())
    }

    #[test]
    fn cleanup_close_removal_refuses_any_mismatch_changing_nothing() -> Result<()> {
        let disk = Arc::new(Disk::default());
        let store = open(disk.clone());
        let journal = vec![("journal".to_string(), vec![1u8])];
        let (d, e, c) = setup(&store, 1)?;
        store.begin_close_offer_inner(c.clone(), &d, &e)?;
        let unreleased = association(&c)?;
        let refused = store.remove_cleanup_closes(&[unreleased], &journal)?.unwrap_err();
        assert!(refused.contains("not Released"), "{refused}");
        let first = store.confirm_close_inner(c)?;
        let (d, e, c) = setup(&store, 2)?;
        store.begin_close_offer_inner(c.clone(), &d, &e)?;
        let second = store.confirm_close_inner(c)?;
        let (a, b) = (association(&first)?, association(&second)?);
        for kind in 0..5 {
            let mut wrong = b.clone();
            match kind {
                0 => wrong.delivery_id = UInt256::from([99; 32]),
                1 => wrong.lease_generation += 1,
                2 => wrong.close_generation += 1,
                3 => wrong.dependency_digest = UInt256::default(),
                _ => wrong.binding_digest = UInt256::default(),
            }
            let epoch = store.mutation_epoch()?;
            // A mismatch anywhere in the list refuses the whole batch.
            assert!(store.remove_cleanup_closes(&[a.clone(), wrong], &journal)?.is_err());
            assert_eq!(store.mutation_epoch()?, epoch, "nothing was committed");
            assert!(store.lookup_close(&first.binding.delivery_id)?.is_some());
            assert!(store.lookup_close(&second.binding.delivery_id)?.is_some());
        }
        assert!(!journal_written(&disk), "no journal without the removal");
        Ok(())
    }
    #[test]
    fn cleanup_close_removal_is_exact_and_atomic_with_the_journal() -> Result<()> {
        let disk = Arc::new(Disk::default());
        let store = open(disk.clone());
        let journal = vec![("journal".to_string(), vec![1u8])];
        let (first, second) = released_pair(&store)?;
        let epoch = store.mutation_epoch()?.unwrap();
        store.remove_cleanup_closes(&[association(&first)?], &journal)?.unwrap();
        assert_eq!(store.mutation_epoch()?, Some(epoch + 1));
        assert!(store.lookup_close(&first.binding.delivery_id)?.is_none());
        assert_eq!(store.lookup_close(&second.binding.delivery_id)?, Some(second.clone()));
        assert_eq!(disk.rows.lock().unwrap().get("journal"), Some(&journal[0].1));
        drop(store);
        let store = open(disk);
        assert!(store.lookup_close(&first.binding.delivery_id)?.is_none(), "durable");
        assert_eq!(store.lookup_close(&second.binding.delivery_id)?, Some(second));
        Ok(())
    }
    #[test]
    fn cleanup_close_removal_uncertainty_fails_closed_until_reopen() -> Result<()> {
        for failure in [1, 2] {
            let disk = Arc::new(Disk::default());
            let store = open(disk.clone());
            let journal = vec![("journal".to_string(), vec![1u8])];
            let (first, _) = released_pair(&store)?;
            disk.failure.store(failure, Ordering::SeqCst);
            assert!(store.remove_cleanup_closes(&[association(&first)?], &journal).is_err());
            assert!(store.lookup_close(&first.binding.delivery_id).is_err(), "fails closed");
            assert!(store.with_cleanup_lock(|_, _| Ok(())).is_err());
            disk.failure.store(0, Ordering::SeqCst);
            drop(store);
            let store = open(disk.clone());
            let applied = failure == 2;
            assert_eq!(store.lookup_close(&first.binding.delivery_id)?.is_none(), applied);
            assert_eq!(journal_written(&disk), applied, "one batch");
        }
        Ok(())
    }
    /// P5-07.12 phase 1, V5: the close removal and its journal are one synced
    /// batch of the real validator-state DB. On a full disk the store fails
    /// closed, and a cold reopen shows both previous or both intended.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "disk-full harness only"]
    async fn disk_full_close_removal_and_journal_are_all_or_nothing() -> Result<()> {
        use crate::publication_dependency_leases::disk_full_tests::{control, enospc_root, Filler};
        let root = enospc_root().join("outbox");
        std::fs::create_dir_all(&root)?;
        let limits = Limits { max_records: 1, ..Limits::default() };
        let engine =
            crate::test_helper::TestEngine::new_db_dir(root.to_str().unwrap(), None).await?;
        let store = PropagationOutbox::open(engine.db.clone(), domain(), limits.clone())?;
        let (first, second) = released_pair(&store)?;
        let journal_key = "DiskFullJournal".to_string();
        engine.db.rotate_validator_state_wal_for_test()?;
        if control() {
            store
                .remove_cleanup_closes(&[association(&first)?], &[(journal_key.clone(), vec![1])])?
                .unwrap();
            assert!(store.lookup_close(&first.binding.delivery_id)?.is_none());
            assert_eq!(
                engine.db.load_validator_state_key_bounded(&journal_key, 16)?,
                Some(vec![1])
            );
            drop(store);
            engine.db.stop_states_db().await.unwrap();
            eprintln!("ENOSPC-CASE V5 control ok");
            return Ok(());
        }
        let filler = Filler::fill(&root);
        let error = store
            .remove_cleanup_closes(&[association(&first)?], &[(journal_key.clone(), vec![1])])
            .unwrap_err();
        assert!(format!("{error:#}").contains("No space left on device"), "{error:#}");
        // The outbox fails closed in process until it is reopened.
        assert!(store.lookup_close(&first.binding.delivery_id).is_err());
        filler.free();
        drop(store);
        engine.db.stop_states_db().await.unwrap();
        drop(engine);
        let engine =
            crate::test_helper::TestEngine::new_db_dir(root.to_str().unwrap(), None).await?;
        let store = PropagationOutbox::open(engine.db.clone(), domain(), limits)?;
        let close_present = store.lookup_close(&first.binding.delivery_id)?.is_some();
        let journal = engine.db.load_validator_state_key_bounded(&journal_key, 16)?;
        match (close_present, journal) {
            (true, None) => eprintln!("ENOSPC-CASE V5 previous"),
            (false, Some(value)) => {
                assert_eq!(value, vec![1]);
                eprintln!("ENOSPC-CASE V5 intended");
            }
            other => panic!("torn close removal batch: {other:?}"),
        }
        assert_eq!(store.lookup_close(&second.binding.delivery_id)?, Some(second), "untouched");
        drop(store);
        engine.db.stop_states_db().await.unwrap();
        Ok(())
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
            .stage_draft(e.record.as_ref().clone(), d.last_mc, d.candidate_already_sent, d.origin.clone())
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
        let mut replay = e.record.as_ref().clone();
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
            disk.failure.store(failure, Ordering::SeqCst);
            assert!(store.confirm_close_inner(c.clone()).is_err());
            assert!(store.lookup_close(&d.delivery_id).is_err());
            disk.failure.store(0, Ordering::SeqCst);
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
        Arc::make_mut(&mut changed.record).carrier = StoredCarrier::Final(vec![10]);
        assert!(store.begin_close_offer_inner(c.clone(), &d, &changed).is_err());
        store.begin_close_offer_inner(c.clone(), &d, &e)?;
        assert_eq!(store.begin_close_offer_inner(c.clone(), &d, &e)?, c);
        Ok(())
    }
    #[test]
    fn close_real_snapshot_database_reopen_preserves_terminal() -> Result<()> {
        use storage::db::rocksdb::AccessType;
        fn reopen(path: &std::path::Path) -> Result<PropagationOutbox> {
            let disk = DiskStore::open(path, AccessType::ReadWrite)?;
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
            .stage_draft(Arc::unwrap_or_clone(e.record), d.last_mc, d.candidate_already_sent, d.origin)
            .is_err());
        assert_eq!(store.confirm_close_inner(c)?.offer().generation, 1);
        Ok(())
    }
    #[test]
    fn close_reserved_generation_uncertainty_burns_generations() -> Result<()> {
        let disk = Arc::new(Disk::default());
        let store = open(disk.clone());
        let (d, e, c) = setup(&store, 1)?;
        assert_eq!(c.binding.close_generation, 1);
        assert_eq!(store.reserve_close(&d, &e)?, 2);
        disk.failure.store(2, Ordering::SeqCst);
        assert!(store.reserve_close(&d, &e).is_err());
        assert!(store.reserve_close(&d, &e).is_err());
        disk.failure.store(0, Ordering::SeqCst);
        drop(store);
        let store = open(disk);
        assert!(store.lookup_close(&d.delivery_id)?.is_none());
        assert_eq!(store.reserve_close(&d, &e)?, 4, "an uncertain reservation is burnt");
        // Supplied stale event changes are independently rejected.
        let mut changed = d.clone();
        changed.last_mc += 1;
        assert!(store.reserve_close(&changed, &e).is_err());
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
        let rows = encode_snapshot_rows(&snapshot, &domain(), &limits)?;
        let (decoded, _, _) = decode_rows(&rows, &domain(), &limits)?;
        assert_eq!(decoded.closing.len(), 1025);
        assert!(decoded.entries.is_empty());
        let mut bad = decoded.clone();
        bad.closing[0].binding.canonical.block_id = id(2000);
        let rows = encode_snapshot_rows(&bad, &domain(), &limits)?;
        assert!(decode_rows(&rows, &domain(), &limits).is_err());
        let mut bad = decoded;
        bad.closing.resize(MAX_CLOSE_RECORDS + 1, base);
        assert!(validate_history(&bad, &domain()).is_err());
        Ok(())
    }
    #[test]
    fn close_real_compact_admission_capacity_preserves_snapshot_and_canonical() -> Result<()> {
        use storage::db::rocksdb::AccessType;
        fn reopen(path: &std::path::Path) -> Result<PropagationOutbox> {
            let disk = DiskStore::open(path, AccessType::ReadWrite)?;
            PropagationOutbox::load(disk, domain(), Limits::default(), None)
        }
        let rows = |store: &PropagationOutbox| {
            read_rows(store.store.as_ref(), &Limits::default(), usize::MAX)
        };
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
            row.binding.delivery_id = delivery_coordinates(
                &domain(),
                row.binding.domain.protocol,
                &row.binding.domain.profile,
                &row.binding.domain.session_id,
                &row.binding.canonical.block_id,
                true,
            )?;
            row.binding.canonical.node_receipt = row.binding.delivery_id.clone();
            let size = row.binding.encode()?.len() + 45;
            if snapshot.closing.len() + 1 >= MAX_CLOSE_RECORDS
                || total + size + first_size > MAX_CLOSE_BYTES
            {
                break;
            }
            total += size;
            snapshot.closing.push(row);
        }
        // Decimal timestamps are legitimate bounded fields. Fill any small
        // remainder caused by differing numeric ID widths, without padding JSON
        // or raising production limits, so exactly one offered row still fits.
        if snapshot.closing.len() + 1 < MAX_CLOSE_RECORDS {
            for row in snapshot.closing.iter_mut().rev() {
                if total + first_size + second_size > MAX_CLOSE_BYTES {
                    break;
                }
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
        assert!(
            snapshot.closing.len() + 1 == MAX_CLOSE_RECORDS
                || total + first_size + second_size > MAX_CLOSE_BYTES
        );
        let seed = encode_snapshot_rows(&snapshot, &domain(), &Limits::default())?;
        store.store.write_batch(&seed, &[])?;
        drop(store);
        let store = reopen(dir.path())?;
        store.begin_close_offer_inner(first.clone(), &d1, &e1)?;
        let before = rows(&store)?;
        let error =
            store.begin_close_offer_inner(second.clone(), &d2, &e2).unwrap_err().to_string();
        assert!(error.contains("Close history byte quota exhausted"), "{error}");
        assert_eq!(rows(&store)?, before);
        assert!(store.delivery(&d1.delivery_id)?.is_some());
        assert!(store.delivery(&d2.delivery_id)?.is_some());
        assert_eq!(store.lookup_close(&d1.delivery_id)?, Some(first.clone()));
        assert_eq!(store.lookup_close(&d2.delivery_id)?, None);
        eprintln!(
            "compact admission boundary: records={}, bytes={}, rejection={error}",
            snapshot.closing.len() + 1,
            total + first_size
        );
        drop(store);
        let store = reopen(dir.path())?;
        assert_eq!(rows(&store)?, before);
        assert!(store.delivery(&d1.delivery_id)?.is_some());
        assert!(store.delivery(&d2.delivery_id)?.is_some());
        assert_eq!(store.lookup_close(&d1.delivery_id)?, Some(first));
        assert_eq!(store.lookup_close(&d2.delivery_id)?, None);
        Ok(())
    }
}
