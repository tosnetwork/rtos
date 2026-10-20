// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded durable publication intents, not authenticated consensus objects.
//!
//! Recovery must authenticate every record against the Engine's pinned history
//! and complete acceptance before marking it ready or sending. Neither the
//! checksum nor a Ready tag grants that authority. All methods are synchronous;
//! call them on an owned blocking worker, never while holding a network lock.
//!
//! Storage: one validator-state key per object, written in one synced batch per
//! mutation that touches only the objects the mutation changes.
//! - `PropagationOutboxV2/meta`: the identifier allocators;
//! - `PropagationOutboxV2/b/<record>`: a record's immutable body, written once;
//! - `PropagationOutboxV2/s/<record>`: its stage, frozen effects, remaining
//!   effects and delivery identity;
//! - `PropagationOutboxV2/c/<delivery>`: one close history record.
//!
//! Every value carries its kind, the schema, the network domain and its own key
//! identity under a SHA-256 checksum. Loading checks every relationship between
//! the values; the aggregate byte budget is checked before every commit, so an
//! acknowledged state always reopens within the configured limits.
use crate::internal_db::{InternalDb, PropagationOutboxWriterLease};
use consensus_common::simplex_protocol::SimplexProtocol;
use rtos_api::WireProfile;
use rtos_block::{error, fail, BlockIdExt, Result, ShardIdent, UInt256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::{Arc, Mutex},
};

/// The snapshot key of earlier development builds; its presence refuses open.
const LEGACY_KEY: &str = "PropagationOutboxV1";
pub(crate) const KEY_PREFIX: &str = "PropagationOutboxV2/";
const META_KEY: &str = "PropagationOutboxV2/meta";
const BODY_PREFIX: &str = "PropagationOutboxV2/b/";
const STATE_PREFIX: &str = "PropagationOutboxV2/s/";
const CLOSE_PREFIX: &str = "PropagationOutboxV2/c/";
const META_MAGIC: &[u8; 8] = b"RTOSPBXM";
const BODY_MAGIC: &[u8; 8] = b"RTOSPBXB";
const STATE_MAGIC: &[u8; 8] = b"RTOSPBXS";
const CLOSE_MAGIC: &[u8; 8] = b"RTOSPBXC";
pub const SCHEMA_VERSION: u16 = 5;
/// Keys read per page while loading; the writer lease is held throughout.
const LOAD_PAGE_KEYS: usize = 256;
pub(crate) mod closing;
pub(crate) use closing::{canonical_intent_digest, effects_digest, ClosingRecord};
const DIGEST_BYTES: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboxDomain {
    pub zerostate: BlockIdExt,
    pub global_id: i32,
    pub wire_profile: WireProfile,
}

#[derive(Clone, Debug)]
pub struct Limits {
    pub max_records: usize,
    /// The aggregate size of every stored key and value.
    pub max_snapshot_bytes: usize,
    pub max_block_bytes: usize,
    pub max_proof_bytes: usize,
    pub max_carrier_bytes: usize,
    pub max_effects_per_record: usize,
    pub max_custom_target_bytes: usize,
    /// Bounds the declared retry window. Expired unsent records are retained
    /// for the caller's explicit policy; expiry is never a delivery checkpoint.
    pub max_retention_secs: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_records: 1024,
            max_snapshot_bytes: 64 << 20,
            max_block_bytes: 8 << 20,
            max_proof_bytes: 8 << 20,
            max_carrier_bytes: 4 << 20,
            max_effects_per_record: 256,
            max_custom_target_bytes: 1024,
            max_retention_secs: 7 * 24 * 60 * 60,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PublicationKind {
    Candidate,
    Block,
    Finality,
    ShardDescription,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PublicationTarget {
    Public,
    FastSync,
    Custom(String),
    ShardDescription,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PublicationEffect {
    pub kind: PublicationKind,
    pub target: PublicationTarget,
}

/// Bounded serialized network evidence. Bytes are deliberately opaque here:
/// the recovery authenticator must decode them, verify their role matches this
/// tag, and verify the block/session binding. Approval is never a final carrier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoredCarrier {
    Final(Vec<u8>),
    Approval(Vec<u8>),
}
impl StoredCarrier {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Final(bytes) | Self::Approval(bytes) => bytes,
        }
    }
    pub fn is_final(&self) -> bool {
        matches!(self, Self::Final(_))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationRecord {
    pub domain: OutboxDomain,
    pub protocol: SimplexProtocol,
    pub profile: UInt256,
    pub session_id: UInt256,
    pub block_id: BlockIdExt,
    /// Full bytes survive ordinary block/archive GC while retrying.
    pub block_data: Vec<u8>,
    pub proof_data: Option<Vec<u8>>,
    pub prev: Vec<BlockIdExt>,
    pub carrier: StoredCarrier,
    pub locally_generated: bool,
    pub created_at_unix_secs: u64,
    pub expires_at_unix_secs: u64,
    /// Original effects, immutable for this record's lifetime.
    pub effects: Vec<PublicationEffect>,
}
impl PublicationRecord {
    pub fn is_expired(&self, now_unix_secs: u64) -> bool {
        now_unix_secs >= self.expires_at_unix_secs
    }

    fn same_intent(&self, other: &Self) -> bool {
        // A callback replay must not restart retention or resurrect completed
        // effects simply because its caller supplied a new wall-clock time.
        self.domain == other.domain
            && self.protocol == other.protocol
            && self.profile == other.profile
            && self.session_id == other.session_id
            && self.block_id == other.block_id
            && self.block_data == other.block_data
            && self.proof_data == other.proof_data
            && self.prev == other.prev
            && self.carrier == other.carrier
            && self.locally_generated == other.locally_generated
            && self.effects == other.effects
    }
}

/// IDs are monotonically allocated and never reused, including across empty
/// outboxes/restarts. A stale completion cannot erase a later re-enqueue.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationStage {
    Prepared,
    Ready,
    DraftDurable,
    Completed,
    AcceptedDraft,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnverifiedRecord {
    pub id: RecordId,
    pub stage: PublicationStage,
    /// Shared immutable evidence, like the candidate reference retained by a
    /// resolver. A transport checkpoint changes only stage/pending, while old
    /// readers keep the same retained input.
    pub record: Arc<PublicationRecord>,
    pub pending: Vec<PublicationEffect>,
}

/// One page of a prefix scan: the rows read, the last key examined, and whether
/// the prefix range was exhausted.
type ScanPage = (Vec<(String, Vec<u8>)>, String, bool);

/// The keyed storage an outbox writes through. Every write is one synced
/// atomic batch.
trait OutboxStore: Send + Sync {
    fn write_batch(&self, puts: &[(String, Vec<u8>)], deletes: &[String]) -> Result<()>;
    /// At most `max_keys` entries under `prefix` strictly after `after`; a value
    /// larger than `max_value_bytes` is skipped, never copied.
    fn scan(
        &self,
        prefix: &str,
        after: &str,
        max_keys: usize,
        max_value_bytes: usize,
    ) -> Result<ScanPage>;
    fn has_prefix(&self, prefix: &str) -> Result<bool>;
}
impl OutboxStore for InternalDb {
    fn write_batch(&self, puts: &[(String, Vec<u8>)], deletes: &[String]) -> Result<()> {
        self.write_outbox_batch_sync(puts, deletes)
    }
    fn scan(
        &self,
        prefix: &str,
        after: &str,
        max_keys: usize,
        max_value_bytes: usize,
    ) -> Result<ScanPage> {
        self.scan_validator_state_prefix(prefix, after, max_keys, max_value_bytes)
    }
    fn has_prefix(&self, prefix: &str) -> Result<bool> {
        self.validator_state_prefix_has_key_other_than(prefix, "")
    }
}

/// Source claims checked against authenticated history and this node's keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryOrigin {
    pub carrier_version: u32,
    pub local_adnl: UInt256,
    pub source_validator: UInt256,
    pub local_validator_index: Option<u32>,
}

/// Stable delivery identity is bookkeeping, never an authentication receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    pub delivery_id: UInt256,
    pub record_id: RecordId,
    pub last_mc: u32,
    pub candidate_already_sent: bool,
    pub origin: Option<RecoveryOrigin>,
}

#[derive(Clone)]
struct Snapshot {
    next_close_generation: u64,
    closing: Vec<ClosingRecord>,
    next_id: u64,
    entries: Vec<UnverifiedRecord>,
    deliveries: Vec<Delivery>,
}

/// The keys and values one mutation writes, in one synced batch.
#[derive(Default)]
struct Batch {
    puts: Vec<(String, Vec<u8>)>,
    deletes: Vec<String>,
}

struct State {
    snapshot: Snapshot,
    failed: Option<String>,
    /// Records whose body and state this exclusive writer has synced itself.
    /// Loading a record after reopen never grants this process-local receipt.
    synced: HashSet<RecordId>,
    /// Stored size (key plus value) of every key, and their sum.
    sizes: HashMap<String, usize>,
    total_bytes: usize,
    /// The close history's quota bytes, checked before every close commit.
    close_bytes: usize,
    /// Advanced by every write attempt, successful or not; None once
    /// exhausted, which refuses every cleanup projection.
    mutation_epoch: Option<u64>,
}

pub struct PropagationOutbox {
    store: Arc<dyn OutboxStore>,
    domain: OutboxDomain,
    domain_digest: UInt256,
    limits: Limits,
    state: Mutex<State>,
    _writer: Option<PropagationOutboxWriterLease>,
}
impl PropagationOutbox {
    /// Share the returned Arc. A second independent open on the same InternalDb
    /// fails until all owners of this writer have been dropped.
    pub fn open(db: Arc<InternalDb>, domain: OutboxDomain, limits: Limits) -> Result<Arc<Self>> {
        let writer = db.claim_propagation_outbox_writer()?;
        Self::load(db, domain, limits, Some(writer)).map(Arc::new)
    }

    /// Loads under the writer lease the caller holds for the whole read.
    fn load(
        store: Arc<dyn OutboxStore>,
        domain: OutboxDomain,
        limits: Limits,
        writer: Option<PropagationOutboxWriterLease>,
    ) -> Result<Self> {
        validate_domain(&domain)?;
        validate_limits(&limits)?;
        if store.has_prefix(LEGACY_KEY)? {
            fail!(
                "An earlier development propagation outbox format is present; \
                 the node database must be recreated"
            );
        }
        let rows = read_rows(store.as_ref(), &limits, LOAD_PAGE_KEYS)?;
        let domain_digest = domain_digest(&domain)?;
        let state = if rows.is_empty() {
            let snapshot = Snapshot {
                next_close_generation: 1,
                closing: Vec::new(),
                next_id: 1,
                entries: Vec::new(),
                deliveries: Vec::new(),
            };
            // Retain the domain and ID allocator even with no pending work.
            let meta = encode_meta(&domain_digest, &snapshot)?;
            let size = META_KEY.len().saturating_add(meta.len());
            store.write_batch(&[(META_KEY.to_owned(), meta)], &[])?;
            State {
                snapshot,
                failed: None,
                synced: HashSet::new(),
                sizes: HashMap::from([(META_KEY.to_owned(), size)]),
                total_bytes: size,
                close_bytes: 0,
                mutation_epoch: Some(0),
            }
        } else {
            let (snapshot, sizes, total_bytes) = decode_rows(&rows, &domain, &limits)?;
            let mut close_bytes = 0usize;
            for close in &snapshot.closing {
                close_bytes = close_bytes
                    .checked_add(closing::close_quota(close)?)
                    .ok_or_else(|| error!("Close bytes overflow"))?;
            }
            State {
                snapshot,
                failed: None,
                synced: HashSet::new(),
                sizes,
                total_bytes,
                close_bytes,
                mutation_epoch: Some(0),
            }
        };
        Ok(Self { store, domain, domain_digest, limits, state: Mutex::new(state), _writer: writer })
    }

    pub fn domain(&self) -> &OutboxDomain {
        &self.domain
    }

    /// Persist before acknowledging acceptance or attempting any publication.
    /// Exact retries coalesce without restoring already completed effects.
    pub fn enqueue(&self, mut record: PublicationRecord) -> Result<RecordId> {
        record.effects.sort();
        if record.effects.is_empty() {
            fail!("Legacy publication requires effects");
        }
        validate_record(&record, &self.domain, &self.limits)?;
        let mut state = self.lock()?;
        closing::reject_terminal_record(&state.snapshot, &record)?;
        if let Some(entry) =
            state.snapshot.entries.iter().find(|entry| entry.record.same_intent(&record))
        {
            return Ok(entry.id);
        }
        if state.snapshot.entries.len() >= self.limits.max_records {
            fail!("Propagation outbox record capacity exhausted");
        }
        let id = RecordId(state.snapshot.next_id);
        let next_id = id.0.checked_add(1).ok_or_else(|| error!("Outbox ID space exhausted"))?;
        let pending = record.effects.clone();
        let entry =
            UnverifiedRecord { id, stage: PublicationStage::Prepared, record: Arc::new(record), pending };
        let mut batch = Batch::default();
        self.put_body(&mut batch, &entry)?;
        self.put_state(&mut batch, &entry, None)?;
        self.put_meta(&mut batch, next_id, state.snapshot.next_close_generation)?;
        self.commit(&mut state, batch)?;
        state.snapshot.next_id = next_id;
        state.synced.insert(id);
        state.snapshot.entries.push(entry);
        Ok(id)
    }

    /// Only the acceptance owner calls this after persistence/application has
    /// succeeded. On restart, even Ready records require fresh authentication.
    pub fn mark_ready(&self, id: RecordId) -> Result<()> {
        let mut state = self.lock()?;
        let index = entry_index(&state.snapshot, id)
            .ok_or_else(|| error!("Unknown propagation outbox record {}", id.0))?;
        let entry = &state.snapshot.entries[index];
        if matches!(entry.stage, PublicationStage::Ready | PublicationStage::Completed) {
            return Ok(());
        }
        if matches!(entry.stage, PublicationStage::DraftDurable | PublicationStage::AcceptedDraft) {
            fail!("Unresolved draft cannot become Ready");
        }
        let mut next = entry.clone();
        next.stage = if next.pending.is_empty() {
            PublicationStage::Completed
        } else {
            PublicationStage::Ready
        };
        self.replace_entry(&mut state, index, next)
    }

    /// Checkpoint actual acceptance independently of routing availability. A
    /// persisted tag is not a receipt: recovery/query still authenticate and
    /// perform idempotent acceptance before returning an AcceptedSessionBlock.
    pub fn mark_accepted(&self, id: RecordId) -> Result<()> {
        let mut state = self.lock()?;
        let index = entry_index(&state.snapshot, id)
            .ok_or_else(|| error!("Unknown publication acceptance record"))?;
        let mut next = state.snapshot.entries[index].clone();
        next.stage = match next.stage {
            PublicationStage::DraftDurable => PublicationStage::AcceptedDraft,
            PublicationStage::Prepared if next.pending.is_empty() => PublicationStage::Completed,
            PublicationStage::Prepared => PublicationStage::Ready,
            PublicationStage::AcceptedDraft
            | PublicationStage::Ready
            | PublicationStage::Completed => return Ok(()),
        };
        self.replace_entry(&mut state, index, next)
    }

    /// Checkpoint only effects whose transport accepted a send attempt. Failed,
    /// deferred or absent outcomes must not be passed here. No remote delivery
    /// acknowledgement is implied. Duplicate/stale completions are harmless.
    pub fn checkpoint_sent(&self, id: RecordId, sent: &[PublicationEffect]) -> Result<bool> {
        let mut state = self.lock()?;
        let Some(index) = entry_index(&state.snapshot, id) else {
            return Ok(false);
        };
        let entry = &state.snapshot.entries[index];
        if entry.stage == PublicationStage::Completed {
            return Ok(false);
        }
        if entry.stage != PublicationStage::Ready {
            fail!("Cannot checkpoint a Prepared publication");
        }
        if sent.iter().any(|effect| !entry.record.effects.contains(effect)) {
            fail!("Publication checkpoint contains an effect outside the original intent");
        }
        let mut next = entry.clone();
        let before = next.pending.len();
        next.pending.retain(|effect| !sent.contains(effect));
        if before == next.pending.len() {
            return Ok(false);
        }
        if next.pending.is_empty() {
            if delivery_of(&state.snapshot, id).is_some() {
                next.stage = PublicationStage::Completed;
            } else {
                let mut batch = Batch::default();
                batch.deletes.push(body_key(id));
                batch.deletes.push(state_key(id));
                self.commit(&mut state, batch)?;
                state.snapshot.entries.remove(index);
                state.synced.remove(&id);
                return Ok(true);
            }
        }
        self.replace_entry(&mut state, index, next)?;
        Ok(true)
    }

    /// Returns unverified, bounded recovery data, including Prepared/expired
    /// intents. Caller authentication and retention policy cannot be skipped.
    // Completed handoffs deliberately retain full evidence. Safe collection
    // requires a synchronized source ACK plus a retired-session barrier; until
    // that protocol exists this bounded store applies backpressure, never eviction.
    pub fn pending(&self) -> Result<Vec<UnverifiedRecord>> {
        Ok(self.lock()?.snapshot.entries.clone())
    }

    /// Live or historical authentication must precede this call. One transaction
    /// retains all replay evidence before the source is allowed to advance.
    pub fn stage_draft(
        &self,
        mut record: PublicationRecord,
        last_mc: u32,
        candidate_already_sent: bool,
        origin: Option<RecoveryOrigin>,
    ) -> Result<UInt256> {
        record.effects.clear();
        validate_record(&record, &self.domain, &self.limits)?;
        let delivery_id = delivery_id(&record)?;
        let mut state = self.lock()?;
        closing::reject_terminal_record(&state.snapshot, &record)?;
        if let Some(delivery) =
            state.snapshot.deliveries.iter().find(|d| d.delivery_id == delivery_id)
        {
            let existing = state
                .snapshot
                .entries
                .iter()
                .find(|e| e.id == delivery.record_id)
                .ok_or_else(|| error!("Delivery refers to a missing record"))?;
            let mut original = existing.record.as_ref().clone();
            original.effects.clear();
            // Recovery may conservatively demote local routing claims. Preserve
            // the first authenticated intent rather than deriving it again.
            record.locally_generated = original.locally_generated;
            if !original.same_intent(&record) {
                fail!("Delivery identity reused with different evidence");
            }
            return Ok(delivery_id);
        }
        if state.snapshot.entries.len() >= self.limits.max_records {
            fail!("Delivery capacity exhausted; source must retain pending evidence");
        }
        let record_id = RecordId(state.snapshot.next_id);
        let next_id = record_id.0.checked_add(1).ok_or_else(|| error!("Outbox ID exhausted"))?;
        let entry = UnverifiedRecord {
            id: record_id,
            stage: PublicationStage::DraftDurable,
            record: Arc::new(record),
            pending: Vec::new(),
        };
        let delivery = Delivery {
            delivery_id: delivery_id.clone(),
            record_id,
            last_mc,
            candidate_already_sent,
            origin,
        };
        let mut batch = Batch::default();
        self.put_body(&mut batch, &entry)?;
        self.put_state(&mut batch, &entry, Some(&delivery))?;
        self.put_meta(&mut batch, next_id, state.snapshot.next_close_generation)?;
        self.commit(&mut state, batch)?;
        state.snapshot.next_id = next_id;
        state.synced.insert(record_id);
        state.snapshot.entries.push(entry);
        state.snapshot.deliveries.push(delivery);
        Ok(delivery_id)
    }

    /// Runs `f` with the write epoch and the close history while holding the
    /// writer lock, so no outbox write can interleave with what `f` does.
    pub(crate) fn with_cleanup_lock<R>(
        &self,
        f: impl FnOnce(Option<u64>, &[ClosingRecord]) -> Result<R>,
    ) -> Result<R> {
        let state = self.lock()?;
        f(state.mutation_epoch, &state.snapshot.closing)
    }

    /// Removes exactly the closes `associations` name, each still Released
    /// and bound to the recorded lease, generations and binding digest, and
    /// writes `extra` keys in the same synced batch. Refuses, changing
    /// nothing, if any does not match.
    pub(crate) fn remove_cleanup_closes(
        &self,
        associations: &[consensus_common::validator_cleanup::CleanupAssociation],
        extra: &[(String, Vec<u8>)],
    ) -> Result<std::result::Result<(), String>> {
        let mut state = self.lock()?;
        for association in associations {
            let found = state
                .snapshot
                .closing
                .iter()
                .find(|close| close.binding.delivery_id == association.delivery_id);
            let Some(close) = found else {
                return Ok(Err(format!("close {:x} is missing", association.delivery_id)));
            };
            if let Some(reason) = closing::association_mismatch(close, association)? {
                return Ok(Err(reason));
            }
        }
        if let Some((key, _)) = extra.iter().find(|(key, _)| key.starts_with(KEY_PREFIX)) {
            fail!("Cleanup journal key {key} collides with the outbox namespace");
        }
        let mut batch = Batch::default();
        let mut released = 0usize;
        for close in state.snapshot.closing.iter().filter(|close| {
            associations.iter().any(|a| a.delivery_id == close.binding.delivery_id)
        }) {
            batch.deletes.push(close_key(&close.binding.delivery_id));
            released =
                released.checked_add(closing::close_quota(close)?).ok_or_else(|| error!("Close bytes overflow"))?;
        }
        batch.puts.extend(extra.iter().cloned());
        self.commit(&mut state, batch)?;
        state.close_bytes = state.close_bytes.saturating_sub(released);
        state.snapshot.closing.retain(|close| {
            !associations.iter().any(|a| a.delivery_id == close.binding.delivery_id)
        });
        Ok(Ok(()))
    }

    /// The write epoch, read under the writer lock; None once exhausted.
    pub(crate) fn mutation_epoch(&self) -> Result<Option<u64>> {
        Ok(self.lock()?.mutation_epoch)
    }

    /// The retained data of `session`, selected under the writer lock with
    /// every copy charged to `budget`, and the write epoch it was read at.
    pub(crate) fn cleanup_view_for(
        &self,
        session: &UInt256,
        budget: &mut crate::publication_worker::cleanup_projection::ProjectionBudget,
    ) -> Result<(crate::publication_worker::cleanup_projection::OutboxSelection, Option<u64>)> {
        let state = self.lock()?;
        let selection = crate::publication_worker::cleanup_projection::select_outbox(
            session,
            &state.snapshot.entries,
            &state.snapshot.deliveries,
            &state.snapshot.closing,
            budget,
        )?;
        Ok((selection, state.mutation_epoch))
    }

    /// Advances the write epoch as any committed write would.
    #[cfg(test)]
    pub(crate) fn bump_mutation_epoch_for_test(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.mutation_epoch = state.mutation_epoch.and_then(|epoch| epoch.checked_add(1));
        }
    }

    #[cfg(test)]
    pub(crate) fn exhaust_mutation_epoch_for_test(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.mutation_epoch = Some(u64::MAX);
        }
    }

    /// Observe sticky writer health without cloning any retained entries.
    pub(crate) fn check_health(&self) -> Result<()> {
        drop(self.lock()?);
        Ok(())
    }

    pub fn delivery(&self, id: &UInt256) -> Result<Option<(Delivery, UnverifiedRecord)>> {
        let state = self.lock()?;
        let Some(delivery) = state.snapshot.deliveries.iter().find(|d| &d.delivery_id == id) else {
            return Ok(None);
        };
        let entry = state
            .snapshot
            .entries
            .iter()
            .find(|e| e.id == delivery.record_id)
            .ok_or_else(|| error!("Delivery refers to a missing record"))?;
        Ok(Some((delivery.clone(), entry.clone())))
    }

    /// Borrow an actual full delivery under the writer's healthy-state lock.
    /// The consumer must admit its budget before cloning or parsing any payload.
    pub(crate) fn with_history_delivery<T>(
        &self,
        id: &UInt256,
        consume: impl FnOnce(&Delivery, &UnverifiedRecord) -> Result<T>,
    ) -> Result<T> {
        let state = self.lock()?;
        if state.snapshot.closing.iter().any(|closed| &closed.binding.delivery_id == id) {
            fail!("Compacted closing history requires its existing exact custody evidence");
        }
        let delivery = state
            .snapshot
            .deliveries
            .iter()
            .find(|d| &d.delivery_id == id)
            .ok_or_else(|| error!("Historical debt has no retained full delivery"))?;
        let entry = state
            .snapshot
            .entries
            .iter()
            .find(|e| e.id == delivery.record_id)
            .ok_or_else(|| error!("Historical debt has no retained full canonical record"))?;
        consume(delivery, entry)
    }

    /// A delivery mapping is a permanent source reference, including after
    /// Completed. No delivery or canonical evidence may be reclaimed without a
    /// separate source retirement protocol. A source may compact its full ACK
    /// only after this exclusive writer synced the record's body and state
    /// itself. Cold reads need that barrier; repeated requests reuse its
    /// successful result. An uncertain later write poisons this owner just like
    /// admission.
    pub(crate) fn retain_delivery(&self, expected: &Delivery) -> Result<()> {
        let mut state = self.lock()?;
        if state.snapshot.closing.iter().any(|c| c.binding.delivery_id == expected.delivery_id) {
            fail!("Canonical reference has entered close protocol");
        }
        if !state.snapshot.deliveries.iter().any(|delivery| delivery == expected) {
            fail!("Canonical source reference differs from durable delivery");
        }
        if expected.origin.is_none() {
            fail!("Canonical source reference requires a retained origin");
        }
        if state.synced.contains(&expected.record_id) {
            return Ok(());
        }
        let index = entry_index(&state.snapshot, expected.record_id)
            .ok_or_else(|| error!("Delivery refers to a missing record"))?;
        let entry = state.snapshot.entries[index].clone();
        let mut batch = Batch::default();
        self.put_body(&mut batch, &entry)?;
        self.put_state(&mut batch, &entry, Some(expected))?;
        self.commit(&mut state, batch)?;
        state.synced.insert(expected.record_id);
        Ok(())
    }

    pub fn delivery_for_record(&self, id: RecordId) -> Result<Option<Delivery>> {
        Ok(delivery_of(&self.lock()?.snapshot, id).cloned())
    }

    /// Exact targets are frozen once. A replay after configuration changes uses
    /// this original intent, including the empty-effects acceptance obligation.
    pub fn resolve_draft(&self, id: RecordId, mut effects: Vec<PublicationEffect>) -> Result<()> {
        let mut state = self.lock()?;
        let index = entry_index(&state.snapshot, id).ok_or_else(|| error!("Unknown draft"))?;
        let entry = &state.snapshot.entries[index];
        if entry.stage == PublicationStage::DraftDurable {
            fail!("Cannot resolve targets before acceptance");
        }
        if entry.stage != PublicationStage::AcceptedDraft {
            return Ok(());
        }
        effects.sort();
        effects.dedup();
        let mut next = entry.clone();
        Arc::make_mut(&mut next.record).effects = effects.clone();
        next.pending = effects;
        next.stage = if next.pending.is_empty() {
            PublicationStage::Completed
        } else {
            PublicationStage::Ready
        };
        validate_record(&next.record, &self.domain, &self.limits)?;
        self.replace_entry(&mut state, index, next)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>> {
        let state = self.state.lock().map_err(|_| error!("Propagation outbox writer panicked"))?;
        if let Some(error) = &state.failed {
            fail!("Propagation outbox write outcome is uncertain; reopen required: {error}");
        }
        Ok(state)
    }

    /// Write the new state of the entry at `index` and install it.
    fn replace_entry(
        &self,
        state: &mut State,
        index: usize,
        next: UnverifiedRecord,
    ) -> Result<()> {
        let delivery = delivery_of(&state.snapshot, next.id).cloned();
        validate_pending(&next.record, next.stage, &next.pending)?;
        let mut batch = Batch::default();
        self.put_state(&mut batch, &next, delivery.as_ref())?;
        self.commit(state, batch)?;
        state.snapshot.entries[index] = next;
        Ok(())
    }

    fn put_meta(&self, batch: &mut Batch, next_id: u64, next_close_generation: u64) -> Result<()> {
        let mut out = value_encoder(META_MAGIC, &self.domain_digest)?;
        out.u64(next_id)?;
        out.u64(next_close_generation)?;
        batch.puts.push((META_KEY.to_owned(), seal(out)));
        Ok(())
    }

    fn put_body(&self, batch: &mut Batch, entry: &UnverifiedRecord) -> Result<()> {
        validate_record(&entry.record, &self.domain, &self.limits)?;
        batch.puts.push((body_key(entry.id), encode_body(&self.domain_digest, entry, &self.limits)?));
        Ok(())
    }

    fn put_state(
        &self,
        batch: &mut Batch,
        entry: &UnverifiedRecord,
        delivery: Option<&Delivery>,
    ) -> Result<()> {
        batch.puts.push((state_key(entry.id), encode_state(&self.domain_digest, entry, delivery)?));
        Ok(())
    }

    fn put_close(&self, batch: &mut Batch, close: &ClosingRecord) -> Result<()> {
        batch.puts.push((
            close_key(&close.binding.delivery_id),
            closing::encode_close(&self.domain_digest, close)?,
        ));
        Ok(())
    }

    /// Commit one batch. The aggregate byte budget is checked first and a
    /// refusal there writes nothing and does not poison the writer; a write
    /// error does, because its outcome may already be visible.
    fn commit(&self, state: &mut State, batch: Batch) -> Result<()> {
        state.mutation_epoch = state.mutation_epoch.and_then(|epoch| epoch.checked_add(1));
        let mut total = state.total_bytes;
        let mut touched: HashMap<&str, usize> = HashMap::new();
        for key in batch.puts.iter().map(|(key, _)| key).chain(&batch.deletes) {
            if !touched.contains_key(key.as_str()) {
                touched.insert(key.as_str(), state.sizes.get(key).copied().unwrap_or(0));
            }
        }
        for old in touched.values() {
            total = total.checked_sub(*old).ok_or_else(|| error!("Outbox byte accounting"))?;
        }
        let mut sized: HashMap<&str, usize> = HashMap::new();
        for (key, value) in &batch.puts {
            sized.insert(key.as_str(), key.len().saturating_add(value.len()));
        }
        for size in sized.values() {
            total = total.checked_add(*size).ok_or_else(|| error!("Outbox byte overflow"))?;
        }
        if total > self.limits.max_snapshot_bytes {
            fail!("Propagation outbox byte capacity exhausted");
        }
        if let Err(error) = self.store.write_batch(&batch.puts, &batch.deletes) {
            // I/O errors can occur after a write became visible. Do not keep
            // mutating an in-memory state that may no longer match the WAL.
            state.failed = Some(error.to_string());
            return Err(error);
        }
        let sized: Vec<(String, usize)> =
            sized.into_iter().map(|(key, size)| (key.to_owned(), size)).collect();
        for key in &batch.deletes {
            state.sizes.remove(key);
        }
        for (key, size) in sized {
            state.sizes.insert(key, size);
        }
        state.total_bytes = total;
        Ok(())
    }
}

fn entry_index(snapshot: &Snapshot, id: RecordId) -> Option<usize> {
    snapshot.entries.iter().position(|entry| entry.id == id)
}

fn delivery_of(snapshot: &Snapshot, id: RecordId) -> Option<&Delivery> {
    snapshot.deliveries.iter().find(|delivery| delivery.record_id == id)
}

fn body_key(id: RecordId) -> String {
    format!("{BODY_PREFIX}{:016x}", id.0)
}
fn state_key(id: RecordId) -> String {
    format!("{STATE_PREFIX}{:016x}", id.0)
}
fn close_key(delivery_id: &UInt256) -> String {
    format!("{CLOSE_PREFIX}{}", delivery_id.to_hex_string())
}
fn parse_record_key(key: &str, prefix: &str) -> Result<RecordId> {
    let hex = key.strip_prefix(prefix).ok_or_else(|| error!("Outbox key outside its kind"))?;
    if hex.len() != 16 || !hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        fail!("Malformed outbox record key {key}");
    }
    Ok(RecordId(u64::from_str_radix(hex, 16)?))
}

/// Domain-, session-, block- and role-bound identity. Effects and wall clock are
/// deliberately excluded: the first durable handoff freezes their meaning.
pub(crate) fn delivery_id(record: &PublicationRecord) -> Result<UInt256> {
    delivery_coordinates(
        &record.domain,
        record.protocol,
        &record.profile,
        &record.session_id,
        &record.block_id,
        record.carrier.is_final(),
    )
}
fn delivery_coordinates(
    domain: &OutboxDomain,
    protocol: SimplexProtocol,
    profile: &UInt256,
    session_id: &UInt256,
    block_id: &BlockIdExt,
    is_final: bool,
) -> Result<UInt256> {
    let mut out = Encoder { bytes: Vec::new(), maximum: 512 };
    out.append(b"RTOS-finality-delivery-v1")?;
    out.id(&domain.zerostate)?;
    out.append(&domain.global_id.to_le_bytes())?;
    out.byte(wire_byte(domain.wire_profile))?;
    out.byte(u8::try_from(protocol.version())?)?;
    out.hash(profile)?;
    out.hash(session_id)?;
    out.id(block_id)?;
    out.byte(u8::from(is_final))?;
    Ok(UInt256::calc_file_hash(&out.bytes))
}

fn wire_byte(profile: WireProfile) -> u8 {
    match profile {
        WireProfile::Legacy => 0,
        WireProfile::T0 => 1,
    }
}

fn domain_digest(domain: &OutboxDomain) -> Result<UInt256> {
    let mut out = Encoder { bytes: Vec::new(), maximum: 256 };
    out.append(b"RTOS-outbox-domain-v1")?;
    out.id(&domain.zerostate)?;
    out.append(&domain.global_id.to_le_bytes())?;
    out.byte(wire_byte(domain.wire_profile))?;
    Ok(UInt256::calc_file_hash(&out.bytes))
}

fn validate_limits(limits: &Limits) -> Result<()> {
    if limits.max_records == 0
        || limits.max_records > u32::MAX as usize
        || limits.max_snapshot_bytes < 256
        || limits.max_snapshot_bytes > u32::MAX as usize
        || limits.max_block_bytes == 0
        || limits.max_carrier_bytes == 0
        || limits.max_effects_per_record == 0
        || limits.max_retention_secs == 0
        || [
            limits.max_block_bytes,
            limits.max_proof_bytes,
            limits.max_carrier_bytes,
            limits.max_effects_per_record,
            limits.max_custom_target_bytes,
        ]
        .iter()
        .any(|size| *size > limits.max_snapshot_bytes)
    {
        fail!("Invalid propagation outbox limits");
    }
    Ok(())
}
fn validate_domain(domain: &OutboxDomain) -> Result<()> {
    if !domain.zerostate.shard().is_masterchain()
        || domain.zerostate.seq_no() != 0
        || domain.zerostate.root_hash().is_zero()
        || domain.zerostate.file_hash().is_zero()
    {
        fail!("Propagation outbox needs a complete masterchain zerostate pin");
    }
    Ok(())
}
fn validate_record(
    record: &PublicationRecord,
    domain: &OutboxDomain,
    limits: &Limits,
) -> Result<()> {
    if &record.domain != domain {
        fail!("Publication belongs to another network or wire profile");
    }
    if record.block_data.is_empty()
        || record.block_data.len() > limits.max_block_bytes
        || record
            .proof_data
            .as_ref()
            .is_some_and(|p| p.is_empty() || p.len() > limits.max_proof_bytes)
        || record.carrier.bytes().is_empty()
        || record.carrier.bytes().len() > limits.max_carrier_bytes
        || record.prev.is_empty()
        || record.prev.len() > 2
        || record.effects.len() > limits.max_effects_per_record
        || record.expires_at_unix_secs <= record.created_at_unix_secs
        || record.expires_at_unix_secs - record.created_at_unix_secs > limits.max_retention_secs
    {
        fail!("Publication record exceeds its bounds or has an invalid retry window");
    }
    if record.effects.windows(2).any(|pair| pair[0] >= pair[1]) {
        fail!("Publication effects must be unique and ordered");
    }
    for effect in &record.effects {
        if let PublicationTarget::Custom(name) = &effect.target {
            // Empty name is permitted for an explicit custom-overlay category
            // intent; root must checkpoint that category only after all sends.
            if name.len() > limits.max_custom_target_bytes {
                fail!("Custom target name too large");
            }
        }
        if (effect.kind == PublicationKind::ShardDescription)
            != (effect.target == PublicationTarget::ShardDescription)
        {
            fail!("Shard-description publication target mismatch");
        }
        // A shard block accepted with its notarization set as a finalized
        // ancestor broadcasts that set as its finality, as the reference node
        // does; a shard description and any masterchain finality stay final-only.
        if !record.carrier.is_final()
            && (effect.kind == PublicationKind::ShardDescription
                || (effect.kind == PublicationKind::Finality
                    && record.block_id.shard().is_masterchain()))
        {
            fail!("Approval cannot authorize final-only publication effects");
        }
    }
    Ok(())
}

fn validate_pending(
    record: &PublicationRecord,
    stage: PublicationStage,
    pending: &[PublicationEffect],
) -> Result<()> {
    if (matches!(stage, PublicationStage::DraftDurable | PublicationStage::AcceptedDraft)
        && (!pending.is_empty() || !record.effects.is_empty()))
        || (stage == PublicationStage::Completed && !pending.is_empty())
        || (stage == PublicationStage::Ready && pending.is_empty())
        || pending.windows(2).any(|pair| pair[0] >= pair[1])
        || pending.iter().any(|effect| !record.effects.contains(effect))
        || (stage == PublicationStage::Prepared && pending != record.effects)
    {
        fail!("Invalid outbox remaining effects");
    }
    Ok(())
}

/// Revalidate externally assembled recovery data with the storage invariants.
/// Public fields do not prove that an object passed through the bounded decoder.
pub(crate) fn validate_recovery_record(entry: &UnverifiedRecord, limits: &Limits) -> Result<()> {
    validate_limits(limits)?;
    validate_domain(&entry.record.domain)?;
    validate_record(&entry.record, &entry.record.domain, limits)?;
    validate_pending(&entry.record, entry.stage, &entry.pending)?;
    if entry.id.0 == 0 || entry.id.0 == u64::MAX {
        fail!("Invalid outbox record ID");
    }
    let digest = domain_digest(&entry.record.domain)?;
    let size = encode_body(&digest, entry, limits)?
        .len()
        .checked_add(encode_state(&digest, entry, None)?.len())
        .ok_or_else(|| error!("Outbox record size overflow"))?;
    if size > limits.max_snapshot_bytes {
        fail!("Propagation outbox byte capacity exhausted");
    }
    Ok(())
}

struct Encoder {
    bytes: Vec<u8>,
    maximum: usize,
}
impl Encoder {
    fn append(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            fail!("Propagation outbox byte capacity exhausted");
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    fn byte(&mut self, value: u8) -> Result<()> {
        self.append(&[value])
    }
    fn u32(&mut self, value: u32) -> Result<()> {
        self.append(&value.to_le_bytes())
    }
    fn u64(&mut self, value: u64) -> Result<()> {
        self.append(&value.to_le_bytes())
    }
    fn blob(&mut self, bytes: &[u8]) -> Result<()> {
        self.u32(u32::try_from(bytes.len())?)?;
        self.append(bytes)
    }
    fn hash(&mut self, value: &UInt256) -> Result<()> {
        self.append(value.as_slice())
    }
    fn id(&mut self, value: &BlockIdExt) -> Result<()> {
        self.append(&value.shard().workchain_id().to_le_bytes())?;
        self.u64(value.shard().shard_prefix_with_tag())?;
        self.u32(value.seq_no())?;
        self.hash(value.root_hash())?;
        self.hash(value.file_hash())
    }
    fn effect(&mut self, effect: &PublicationEffect) -> Result<()> {
        self.byte(match effect.kind {
            PublicationKind::Candidate => 0,
            PublicationKind::Block => 1,
            PublicationKind::Finality => 2,
            PublicationKind::ShardDescription => 3,
        })?;
        match &effect.target {
            PublicationTarget::Public => self.byte(0),
            PublicationTarget::FastSync => self.byte(1),
            PublicationTarget::Custom(name) => {
                self.byte(2)?;
                self.blob(name.as_bytes())
            }
            PublicationTarget::ShardDescription => self.byte(3),
        }
    }
    fn effects(&mut self, effects: &[PublicationEffect]) -> Result<()> {
        self.u32(u32::try_from(effects.len())?)?;
        for effect in effects {
            self.effect(effect)?;
        }
        Ok(())
    }
}

/// The common head of every stored value: its kind, the schema and the domain.
fn value_encoder(magic: &[u8; 8], domain_digest: &UInt256) -> Result<Encoder> {
    let mut out = Encoder { bytes: Vec::new(), maximum: u32::MAX as usize };
    out.append(magic)?;
    out.append(&SCHEMA_VERSION.to_le_bytes())?;
    out.hash(domain_digest)?;
    Ok(out)
}

/// Append the checksum over everything before it.
fn seal(mut out: Encoder) -> Vec<u8> {
    let digest = UInt256::calc_file_hash(&out.bytes);
    out.bytes.extend_from_slice(digest.as_slice());
    out.bytes
}

fn encode_meta(domain_digest: &UInt256, snapshot: &Snapshot) -> Result<Vec<u8>> {
    let mut out = value_encoder(META_MAGIC, domain_digest)?;
    out.u64(snapshot.next_id)?;
    out.u64(snapshot.next_close_generation)?;
    Ok(seal(out))
}

fn encode_body(domain_digest: &UInt256, entry: &UnverifiedRecord, limits: &Limits) -> Result<Vec<u8>> {
    let record = &entry.record;
    let mut out = value_encoder(BODY_MAGIC, domain_digest)?;
    out.maximum = limits.max_snapshot_bytes;
    out.u64(entry.id.0)?;
    out.byte(match record.protocol {
        SimplexProtocol::Private => 0,
        SimplexProtocol::BlockSync => 1,
        SimplexProtocol::PrivateObserversPlumtree => 2,
    })?;
    out.hash(&record.profile)?;
    out.hash(&record.session_id)?;
    out.id(&record.block_id)?;
    out.byte(u8::try_from(record.prev.len())?)?;
    for prev in &record.prev {
        out.id(prev)?;
    }
    out.byte(u8::from(record.carrier.is_final()))?;
    out.blob(record.carrier.bytes())?;
    out.byte(u8::from(record.locally_generated))?;
    out.u64(record.created_at_unix_secs)?;
    out.u64(record.expires_at_unix_secs)?;
    out.blob(&record.block_data)?;
    out.byte(u8::from(record.proof_data.is_some()))?;
    if let Some(proof) = &record.proof_data {
        out.blob(proof)?;
    }
    Ok(seal(out))
}

fn encode_state(
    domain_digest: &UInt256,
    entry: &UnverifiedRecord,
    delivery: Option<&Delivery>,
) -> Result<Vec<u8>> {
    let mut out = value_encoder(STATE_MAGIC, domain_digest)?;
    out.u64(entry.id.0)?;
    out.byte(match entry.stage {
        PublicationStage::Prepared => 0,
        PublicationStage::Ready => 1,
        PublicationStage::DraftDurable => 2,
        PublicationStage::Completed => 3,
        PublicationStage::AcceptedDraft => 4,
    })?;
    out.effects(&entry.record.effects)?;
    out.effects(&entry.pending)?;
    out.byte(u8::from(delivery.is_some()))?;
    if let Some(delivery) = delivery {
        if delivery.record_id != entry.id {
            fail!("Delivery belongs to another record");
        }
        out.hash(&delivery.delivery_id)?;
        out.u32(delivery.last_mc)?;
        out.byte(u8::from(delivery.candidate_already_sent))?;
        out.byte(u8::from(delivery.origin.is_some()))?;
        if let Some(origin) = &delivery.origin {
            out.u32(origin.carrier_version)?;
            out.hash(&origin.local_adnl)?;
            out.hash(&origin.source_validator)?;
            out.byte(u8::from(origin.local_validator_index.is_some()))?;
            if let Some(index) = origin.local_validator_index {
                out.u32(index)?;
            }
        }
    }
    Ok(seal(out))
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Decoder<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(size).ok_or_else(|| error!("Outbox length overflow"))?;
        let bytes =
            self.bytes.get(self.offset..end).ok_or_else(|| error!("Truncated outbox value"))?;
        self.offset = end;
        Ok(bytes)
    }
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn boolean(&mut self) -> Result<bool> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(error!("Unknown outbox boolean/tag")),
        }
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into()?))
    }
    fn count(&mut self, maximum: usize) -> Result<usize> {
        let value = self.u32()? as usize;
        if value > maximum {
            fail!("Outbox decoded length exceeds configured bound");
        }
        Ok(value)
    }
    fn blob(&mut self, maximum: usize) -> Result<Vec<u8>> {
        let size = self.count(maximum)?;
        Ok(self.take(size)?.to_vec())
    }
    fn hash(&mut self) -> Result<UInt256> {
        Ok(UInt256::from_slice(self.take(32)?))
    }
    fn id(&mut self) -> Result<BlockIdExt> {
        let workchain = i32::from_le_bytes(self.take(4)?.try_into()?);
        let prefix = self.u64()?;
        let shard = ShardIdent::with_tagged_prefix(workchain, prefix)?;
        Ok(BlockIdExt::with_params(shard, self.u32()?, self.hash()?, self.hash()?))
    }
    fn effects(&mut self, limits: &Limits) -> Result<Vec<PublicationEffect>> {
        let count = self.count(limits.max_effects_per_record)?;
        // Do not preallocate from an untrusted count. Each push is preceded by
        // actual, bounded input consumption, including for truncated values.
        let mut effects = Vec::new();
        for _ in 0..count {
            let kind = match self.byte()? {
                0 => PublicationKind::Candidate,
                1 => PublicationKind::Block,
                2 => PublicationKind::Finality,
                3 => PublicationKind::ShardDescription,
                _ => return Err(error!("Unknown outbox publication kind")),
            };
            let target = match self.byte()? {
                0 => PublicationTarget::Public,
                1 => PublicationTarget::FastSync,
                2 => PublicationTarget::Custom(String::from_utf8(
                    self.blob(limits.max_custom_target_bytes)?,
                )?),
                3 => PublicationTarget::ShardDescription,
                _ => return Err(error!("Unknown outbox target")),
            };
            effects.push(PublicationEffect { kind, target });
        }
        Ok(effects)
    }
    fn finish(&self) -> Result<()> {
        if self.offset != self.bytes.len() {
            fail!("Trailing outbox value bytes");
        }
        Ok(())
    }
}

/// Check a value's checksum, kind, schema and domain; returns its payload.
fn open_value<'a>(
    bytes: &'a [u8],
    magic: &[u8; 8],
    domain_digest: &UInt256,
) -> Result<Decoder<'a>> {
    if bytes.len() < DIGEST_BYTES {
        fail!("Outbox value too short");
    }
    let (payload, digest) = bytes.split_at(bytes.len() - DIGEST_BYTES);
    if UInt256::calc_file_hash(payload).as_slice() != digest {
        fail!("Outbox value checksum mismatch");
    }
    let mut input = Decoder { bytes: payload, offset: 0 };
    if input.take(8)? != magic {
        fail!("Outbox value of another kind");
    }
    if u16::from_le_bytes(input.take(2)?.try_into()?) != SCHEMA_VERSION {
        fail!("Unknown outbox schema version");
    }
    if &input.hash()? != domain_digest {
        fail!("Outbox value belongs to another network or wire profile");
    }
    Ok(input)
}

struct DecodedBody {
    record: PublicationRecord,
}

fn decode_body(
    bytes: &[u8],
    id: RecordId,
    domain: &OutboxDomain,
    domain_digest: &UInt256,
    limits: &Limits,
) -> Result<DecodedBody> {
    let mut input = open_value(bytes, BODY_MAGIC, domain_digest)?;
    if input.u64()? != id.0 {
        fail!("Outbox body stored under another record key");
    }
    let protocol = SimplexProtocol::try_from(u32::from(input.byte()?))?;
    let profile = input.hash()?;
    let session_id = input.hash()?;
    let block_id = input.id()?;
    let prev_count = input.byte()?;
    if !(1..=2).contains(&prev_count) {
        fail!("Invalid outbox previous-block count");
    }
    let mut prev = Vec::new();
    for _ in 0..prev_count {
        prev.push(input.id()?);
    }
    let final_ = input.boolean()?;
    let carrier = input.blob(limits.max_carrier_bytes)?;
    let carrier =
        if final_ { StoredCarrier::Final(carrier) } else { StoredCarrier::Approval(carrier) };
    let locally_generated = input.boolean()?;
    let created_at_unix_secs = input.u64()?;
    let expires_at_unix_secs = input.u64()?;
    let block_data = input.blob(limits.max_block_bytes)?;
    let proof_data =
        if input.boolean()? { Some(input.blob(limits.max_proof_bytes)?) } else { None };
    input.finish()?;
    Ok(DecodedBody {
        record: PublicationRecord {
            domain: domain.clone(),
            protocol,
            profile,
            session_id,
            block_id,
            block_data,
            proof_data,
            prev,
            carrier,
            locally_generated,
            created_at_unix_secs,
            expires_at_unix_secs,
            effects: Vec::new(),
        },
    })
}

struct DecodedState {
    stage: PublicationStage,
    effects: Vec<PublicationEffect>,
    pending: Vec<PublicationEffect>,
    delivery: Option<Delivery>,
}

fn decode_state(
    bytes: &[u8],
    id: RecordId,
    domain_digest: &UInt256,
    limits: &Limits,
) -> Result<DecodedState> {
    let mut input = open_value(bytes, STATE_MAGIC, domain_digest)?;
    if input.u64()? != id.0 {
        fail!("Outbox state stored under another record key");
    }
    let stage = match input.byte()? {
        0 => PublicationStage::Prepared,
        1 => PublicationStage::Ready,
        2 => PublicationStage::DraftDurable,
        3 => PublicationStage::Completed,
        4 => PublicationStage::AcceptedDraft,
        _ => return Err(error!("Unknown outbox publication stage")),
    };
    let effects = input.effects(limits)?;
    let pending = input.effects(limits)?;
    let delivery = if input.boolean()? {
        Some(Delivery {
            delivery_id: input.hash()?,
            record_id: id,
            last_mc: input.u32()?,
            candidate_already_sent: input.boolean()?,
            origin: if input.boolean()? {
                Some(RecoveryOrigin {
                    carrier_version: input.u32()?,
                    local_adnl: input.hash()?,
                    source_validator: input.hash()?,
                    local_validator_index: if input.boolean()? {
                        Some(input.u32()?)
                    } else {
                        None
                    },
                })
            } else {
                None
            },
        })
    } else {
        None
    };
    input.finish()?;
    Ok(DecodedState { stage, effects, pending, delivery })
}

fn decode_meta(bytes: &[u8], domain_digest: &UInt256) -> Result<(u64, u64)> {
    let mut input = open_value(bytes, META_MAGIC, domain_digest)?;
    let next_id = input.u64()?;
    let next_close_generation = input.u64()?;
    input.finish()?;
    if next_id == 0 || next_close_generation == 0 {
        fail!("Invalid outbox ID allocator");
    }
    Ok((next_id, next_close_generation))
}

/// Every row under the outbox prefix, read in pages of `page` keys.
fn read_rows(
    store: &dyn OutboxStore,
    limits: &Limits,
    page: usize,
) -> Result<Vec<(String, Vec<u8>)>> {
    let mut rows = Vec::new();
    let mut after = String::new();
    let mut total = 0usize;
    loop {
        let (entries, last, done) =
            store.scan(KEY_PREFIX, &after, page, limits.max_snapshot_bytes)?;
        for (key, value) in entries {
            total = total
                .checked_add(key.len().saturating_add(value.len()))
                .ok_or_else(|| error!("Outbox byte overflow"))?;
            if total > limits.max_snapshot_bytes {
                fail!("Stored propagation outbox exceeds its byte budget");
            }
            rows.push((key, value));
        }
        if done || last.is_empty() {
            return Ok(rows);
        }
        after = last;
    }
}

/// Rebuild and check the whole outbox from its rows: every value bound to its
/// key and domain, bodies paired with states, identities unique and derived,
/// allocators above every stored identifier and the close history consistent.
fn decode_rows(
    rows: &[(String, Vec<u8>)],
    domain: &OutboxDomain,
    limits: &Limits,
) -> Result<(Snapshot, HashMap<String, usize>, usize)> {
    let digest = domain_digest(domain)?;
    let mut meta = None;
    let mut bodies: BTreeMap<RecordId, DecodedBody> = BTreeMap::new();
    let mut states: BTreeMap<RecordId, DecodedState> = BTreeMap::new();
    let mut closes = Vec::new();
    let mut sizes = HashMap::new();
    let mut total = 0usize;
    for (key, value) in rows {
        let size = key.len().saturating_add(value.len());
        total = total.checked_add(size).ok_or_else(|| error!("Outbox byte overflow"))?;
        if total > limits.max_snapshot_bytes {
            fail!("Stored propagation outbox exceeds its byte budget");
        }
        if sizes.insert(key.clone(), size).is_some() {
            fail!("Repeated outbox key {key}");
        }
        if key == META_KEY {
            meta = Some(decode_meta(value, &digest)?);
        } else if key.starts_with(BODY_PREFIX) {
            let id = parse_record_key(key, BODY_PREFIX)?;
            bodies.insert(id, decode_body(value, id, domain, &digest, limits)?);
        } else if key.starts_with(STATE_PREFIX) {
            let id = parse_record_key(key, STATE_PREFIX)?;
            states.insert(id, decode_state(value, id, &digest, limits)?);
        } else if let Some(hex) = key.strip_prefix(CLOSE_PREFIX) {
            let close = closing::decode_close(value, &digest)?;
            if close.binding.delivery_id.to_hex_string() != hex {
                fail!("Outbox close stored under another delivery key");
            }
            closes.push(close);
        } else {
            fail!("Unknown outbox key {key}");
        }
    }
    let (next_id, next_close_generation) =
        meta.ok_or_else(|| error!("Propagation outbox keys exist without their metadata"))?;
    if bodies.len() != states.len() || bodies.keys().ne(states.keys()) {
        fail!("Outbox record body and state do not pair");
    }
    if bodies.len() > limits.max_records {
        fail!("Outbox record capacity exhausted");
    }
    let mut entries = Vec::with_capacity(bodies.len());
    let mut deliveries = Vec::new();
    let mut delivery_ids = BTreeSet::new();
    for ((id, body), (_, state)) in bodies.into_iter().zip(states) {
        if id.0 == 0 || id.0 >= next_id {
            fail!("Outbox record ID above its allocator");
        }
        let mut record = body.record;
        record.effects = state.effects;
        validate_record(&record, domain, limits)?;
        validate_pending(&record, state.stage, &state.pending)?;
        let has_delivery = state.delivery.is_some();
        if let Some(delivery) = state.delivery {
            if delivery.delivery_id != delivery_id(&record)?
                || !delivery_ids.insert(delivery.delivery_id.clone())
            {
                fail!("Invalid duplicate or mismatched delivery identity");
            }
            deliveries.push(delivery);
        }
        if matches!(
            state.stage,
            PublicationStage::DraftDurable
                | PublicationStage::AcceptedDraft
                | PublicationStage::Completed
        ) && !has_delivery
        {
            fail!("Delivery stage without identity");
        }
        // Only a Draft creates an empty Prepared intent, and a Draft always has
        // a retained delivery identity; otherwise mark_accepted would create
        // an identity-less Completed record that cannot reopen.
        if state.stage == PublicationStage::Prepared && record.effects.is_empty() && !has_delivery
        {
            fail!("Empty Prepared publication requires a delivery identity");
        }
        entries.push(UnverifiedRecord {
            id,
            stage: state.stage,
            record: Arc::new(record),
            pending: state.pending,
        });
    }
    closes.sort_by_key(|close| close.binding.close_generation);
    let snapshot = Snapshot { next_close_generation, closing: closes, next_id, entries, deliveries };
    closing::validate_history(&snapshot, domain)?;
    Ok((snapshot, sizes, total))
}

/// Load legacy close coordinates from the existing bounded node ledger only.
/// The caller must authenticate the returned historical coordinates and still
/// execute normal custody/confirmation checks; this read grants no capability.
pub(crate) fn load_legacy_close_request(
    db: &Arc<InternalDb>,
    request: &consensus_common::finality_delivery::CloseFinalityRequest,
) -> Result<consensus_common::finality_delivery::CloseFinalityRequest> {
    let domain = OutboxDomain {
        zerostate: request.domain.pin.zerostate.clone(),
        global_id: request.domain.pin.global_id,
        wire_profile: request.domain.wire_profile,
    };
    let key = close_key(&request.canonical.node_receipt);
    let bytes = db
        .load_validator_state_key_bounded(&key, closing::MAX_CLOSE_VALUE_BYTES)?
        .ok_or_else(|| error!("Legacy source close has no exact node closing record"))?;
    let record = closing::decode_close(&bytes, &domain_digest(&domain)?)?;
    if record.binding.delivery_id != request.canonical.node_receipt {
        fail!("Legacy source close has no exact node closing record");
    }
    closing::restore_legacy_request(request, &record)
}

/// Every row of a whole in-memory outbox, for seeding tests.
#[cfg(test)]
fn encode_snapshot_rows(
    snapshot: &Snapshot,
    domain: &OutboxDomain,
    limits: &Limits,
) -> Result<Vec<(String, Vec<u8>)>> {
    let digest = domain_digest(domain)?;
    let mut rows = vec![(META_KEY.to_owned(), encode_meta(&digest, snapshot)?)];
    for entry in &snapshot.entries {
        let delivery = delivery_of(snapshot, entry.id);
        rows.push((body_key(entry.id), encode_body(&digest, entry, limits)?));
        rows.push((state_key(entry.id), encode_state(&digest, entry, delivery)?));
    }
    for close in &snapshot.closing {
        rows.push((close_key(&close.binding.delivery_id), closing::encode_close(&digest, close)?));
    }
    Ok(rows)
}

/// Every outbox row of `db`, read with one iterator so the rows are one
/// point-in-time view. Never opens a competing outbox writer.
#[cfg(test)]
fn cold_rows(db: &InternalDb, limits: &Limits) -> Result<Vec<(String, Vec<u8>)>> {
    read_rows(db, limits, usize::MAX)
}

/// Test-only observation of the existing durable state. Does not claim a
/// writer, create a database key, or replace any state. Stop/join the actual
/// writer before treating an observed in-progress write as a durability proof.
#[cfg(test)]
pub(crate) fn inspect_delivery(
    db: &Arc<InternalDb>,
    domain: &OutboxDomain,
    limits: &Limits,
    id: &UInt256,
) -> Result<Option<(Delivery, UnverifiedRecord)>> {
    validate_domain(domain)?;
    validate_limits(limits)?;
    let rows = cold_rows(db, limits)?;
    if rows.is_empty() {
        return Ok(None);
    }
    let (snapshot, _, _) = decode_rows(&rows, domain, limits)?;
    let Some(delivery) = snapshot.deliveries.iter().find(|delivery| &delivery.delivery_id == id)
    else {
        return Ok(None);
    };
    let entry = snapshot
        .entries
        .iter()
        .find(|entry| entry.id == delivery.record_id)
        .ok_or_else(|| error!("Delivery refers to a missing record"))?;
    Ok(Some((delivery.clone(), entry.clone())))
}

/// Read-only coherent observation. Never opens a competing outbox writer.
#[cfg(test)]
pub(crate) fn inspect_closure_progress(
    db: &Arc<InternalDb>,
    domain: &OutboxDomain,
) -> Result<(Vec<UnverifiedRecord>, Vec<ClosingRecord>)> {
    let limits = Limits::default();
    let rows = cold_rows(db, &limits)?;
    if rows.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let (snapshot, _, _) = decode_rows(&rows, domain, &limits)?;
    Ok((snapshot.entries, snapshot.closing))
}

/// Every outbox row of `db` as one byte string, for comparing whole durable
/// states; `inspect_exported_rows` decodes it.
#[cfg(test)]
pub(crate) fn export_rows(db: &InternalDb) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for (key, value) in cold_rows(db, &Limits::default())? {
        out.extend_from_slice(&u32::try_from(key.len())?.to_le_bytes());
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(&u32::try_from(value.len())?.to_le_bytes());
        out.extend_from_slice(&value);
    }
    Ok(out)
}

/// The records and closes of rows exported by `export_rows`.
#[cfg(test)]
pub(crate) fn inspect_exported_rows(
    bytes: &[u8],
    domain: &OutboxDomain,
) -> Result<(Vec<UnverifiedRecord>, Vec<ClosingRecord>)> {
    let mut input = Decoder { bytes, offset: 0 };
    let mut rows = Vec::new();
    while input.offset < bytes.len() {
        let key = String::from_utf8(input.blob(1 << 10)?)?;
        let value = input.blob(64 << 20)?;
        rows.push((key, value));
    }
    let (snapshot, _, _) = decode_rows(&rows, domain, &Limits::default())?;
    Ok((snapshot.entries, snapshot.closing))
}

/// The records whose state and the closes one write batch puts, decoded under
/// `domain`. Pure: reads only the batch about to reach the database.
#[cfg(test)]
pub(crate) fn inspect_closure_batch(
    puts: &[(String, Vec<u8>)],
    domain: &OutboxDomain,
) -> Result<(Vec<RecordId>, Vec<ClosingRecord>)> {
    let digest = domain_digest(domain)?;
    let mut records = Vec::new();
    let mut closes = Vec::new();
    for (key, value) in puts {
        if key.starts_with(STATE_PREFIX) {
            let id = parse_record_key(key, STATE_PREFIX)?;
            decode_state(value, id, &digest, &Limits::default())?;
            records.push(id);
        } else if key.starts_with(CLOSE_PREFIX) {
            closes.push(closing::decode_close(value, &digest)?);
        }
    }
    Ok((records, closes))
}

/// Keyed stores for tests: an in-memory map with injected failures and a real
/// RocksDB table.
#[cfg(test)]
pub(crate) mod test_stores {
    use super::*;
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
    use storage::{
        block_handle_db::NodeStateDb,
        db::rocksdb::{AccessType, RocksDb},
    };

    /// `failure`: 1 refuses before the write; 2 applies the batch and then
    /// reports an uncertain error; 3 applies only the first operation of the
    /// batch (a torn batch, which models corruption) and reports an error.
    #[derive(Default)]
    pub(crate) struct MemoryStore {
        pub(crate) rows: Mutex<BTreeMap<String, Vec<u8>>>,
        pub(crate) failure: AtomicU8,
        pub(crate) sync_attempts: AtomicUsize,
        /// Bytes of every put value, summed over all batches.
        pub(crate) written_bytes: AtomicUsize,
    }
    impl MemoryStore {
        pub(crate) fn snapshot(&self) -> BTreeMap<String, Vec<u8>> {
            self.rows.lock().unwrap().clone()
        }
    }
    impl OutboxStore for MemoryStore {
        fn write_batch(&self, puts: &[(String, Vec<u8>)], deletes: &[String]) -> Result<()> {
            self.sync_attempts.fetch_add(1, Ordering::Relaxed);
            let failure = self.failure.load(Ordering::Acquire);
            if failure == 1 {
                fail!("Injected write failure before commit");
            }
            let mut rows = self.rows.lock().unwrap();
            for (index, (key, value)) in puts.iter().enumerate() {
                if failure == 3 && index > 0 {
                    break;
                }
                self.written_bytes.fetch_add(value.len(), Ordering::Relaxed);
                rows.insert(key.clone(), value.clone());
            }
            if failure != 3 || puts.is_empty() {
                for key in deletes {
                    rows.remove(key);
                    if failure == 3 {
                        break;
                    }
                }
            }
            if failure == 2 {
                fail!("Injected uncertain write failure after commit");
            }
            if failure == 3 {
                fail!("Injected torn batch");
            }
            Ok(())
        }
        fn scan(
            &self,
            prefix: &str,
            after: &str,
            max_keys: usize,
            max_value_bytes: usize,
        ) -> Result<ScanPage> {
            let rows = self.rows.lock().unwrap();
            let mut out = Vec::new();
            let mut last = String::new();
            for (key, value) in rows.range(prefix.to_owned()..) {
                if !key.starts_with(prefix) {
                    break;
                }
                if !after.is_empty() && key.as_str() <= after {
                    continue;
                }
                if out.len() == max_keys {
                    return Ok((out, last, false));
                }
                last = key.clone();
                if value.len() <= max_value_bytes {
                    out.push((key.clone(), value.clone()));
                }
            }
            Ok((out, last, true))
        }
        fn has_prefix(&self, prefix: &str) -> Result<bool> {
            Ok(self.rows.lock().unwrap().keys().any(|key| key.starts_with(prefix)))
        }
    }

    pub(crate) struct DiskStore(NodeStateDb);
    impl DiskStore {
        pub(crate) fn open(path: &std::path::Path, access: AccessType) -> Result<Arc<Self>> {
            let db = RocksDb::new(path, "outbox", None, access)?;
            Ok(Arc::new(Self(NodeStateDb::with_db(db, "publication_test", true)?)))
        }
    }
    impl OutboxStore for DiskStore {
        fn write_batch(&self, puts: &[(String, Vec<u8>)], deletes: &[String]) -> Result<()> {
            let puts: Vec<(&[u8], &[u8])> =
                puts.iter().map(|(k, v)| (k.as_bytes(), v.as_slice())).collect();
            let deletes: Vec<&[u8]> = deletes.iter().map(|k| k.as_bytes()).collect();
            self.0.write_batch_sync(&puts, &deletes)
        }
        fn scan(
            &self,
            prefix: &str,
            after: &str,
            max_keys: usize,
            max_value_bytes: usize,
        ) -> Result<ScanPage> {
            let start = if after.is_empty() { prefix } else { after };
            let mut out = Vec::new();
            let mut last = String::new();
            let mut done = true;
            self.0.for_each_from(start.as_bytes(), &mut |key, value| {
                if !key.starts_with(prefix.as_bytes()) {
                    return Ok(false);
                }
                if key == after.as_bytes() {
                    return Ok(true);
                }
                if out.len() == max_keys {
                    done = false;
                    return Ok(false);
                }
                last = String::from_utf8(key.to_vec())?;
                if value.len() <= max_value_bytes {
                    out.push((last.clone(), value.to_vec()));
                }
                Ok(true)
            })?;
            Ok((out, last, done))
        }
        fn has_prefix(&self, prefix: &str) -> Result<bool> {
            let mut found = false;
            self.0.for_each_from(prefix.as_bytes(), &mut |key, _| {
                found = key.starts_with(prefix.as_bytes());
                Ok(false)
            })?;
            Ok(found)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_stores::{DiskStore, MemoryStore};
    use super::*;
    use std::{process::Command, sync::atomic::Ordering};
    use storage::db::rocksdb::AccessType;

    fn block_id(seqno: u32) -> BlockIdExt {
        BlockIdExt::with_params(
            ShardIdent::masterchain(),
            seqno,
            UInt256::from([seqno as u8 + 1; 32]),
            UInt256::from([seqno as u8 + 2; 32]),
        )
    }
    fn domain() -> OutboxDomain {
        OutboxDomain { zerostate: block_id(0), global_id: -239, wire_profile: WireProfile::T0 }
    }
    fn effect(kind: PublicationKind) -> PublicationEffect {
        PublicationEffect { kind, target: PublicationTarget::Public }
    }
    fn record(seqno: u32) -> PublicationRecord {
        PublicationRecord {
            domain: domain(),
            protocol: SimplexProtocol::PrivateObserversPlumtree,
            profile: UInt256::from([11; 32]),
            session_id: UInt256::from([12; 32]),
            block_id: block_id(seqno),
            block_data: vec![1, 2, 3],
            proof_data: Some(vec![4, 5]),
            prev: vec![block_id(seqno - 1)],
            carrier: StoredCarrier::Final(vec![6, 7, 8]),
            locally_generated: false,
            created_at_unix_secs: 100,
            expires_at_unix_secs: 200,
            effects: vec![
                effect(PublicationKind::Candidate),
                effect(PublicationKind::Block),
                effect(PublicationKind::Finality),
            ],
        }
    }
    fn memory(store: Arc<MemoryStore>, limits: Limits) -> PropagationOutbox {
        PropagationOutbox::load(store, domain(), limits, None).unwrap()
    }
    fn reload(store: Arc<MemoryStore>) -> Result<PropagationOutbox> {
        PropagationOutbox::load(store, domain(), Limits::default(), None)
    }

    #[test]
    fn outbox_checkpoints_share_immutable_recovery_evidence() -> Result<()> {
        let disk = Arc::new(MemoryStore::default());
        let store = memory(disk.clone(), Limits::default());
        let mut first = record(1);
        first.block_data = vec![31; 1 << 20];
        first.proof_data = Some(vec![41; 1 << 20]);
        let id = store.enqueue(first.clone())?;
        store.mark_ready(id)?;
        let held = store.pending()?.remove(0);
        let other = store.enqueue(record(2))?;
        store.mark_ready(other)?;
        let before = disk.sync_attempts.load(Ordering::Relaxed);
        assert!(store.checkpoint_sent(id, &[effect(PublicationKind::Candidate)])?);
        let current = store.pending()?.into_iter().find(|entry| entry.id == id).unwrap();
        assert_eq!(held.record.block_data.as_ptr(), current.record.block_data.as_ptr(),
            "a transport checkpoint copied retained block evidence");
        assert_eq!(held.record.proof_data.as_ref().unwrap().as_ptr(),
            current.record.proof_data.as_ref().unwrap().as_ptr(),
            "a transport checkpoint copied retained proof evidence");
        assert_eq!(held.record, current.record);
        assert_eq!(held.pending.len(), 3, "a reader's earlier checkpoint must not change");
        assert_eq!(current.pending.len(), 2);
        assert_eq!(disk.sync_attempts.load(Ordering::Relaxed), before + 1);
        assert!(!store.checkpoint_sent(id, &[effect(PublicationKind::Candidate)])?);
        assert_eq!(disk.sync_attempts.load(Ordering::Relaxed), before + 1);
        let reopened = memory(disk, Limits::default());
        let restored = reopened.pending()?.into_iter().find(|entry| entry.id == id).unwrap();
        assert_eq!(restored, current, "reopen must use the full synced checkpoint");
        Ok(())
    }

    /// A transition writes only the changed record's state, whatever the
    /// number and size of the other records held.
    #[test]
    fn outbox_transition_cost_is_independent_of_retained_records() -> Result<()> {
        let mut costs = Vec::new();
        for held in [1u32, 300] {
            let disk = Arc::new(MemoryStore::default());
            let store = memory(disk.clone(), Limits::default());
            let mut ids = Vec::new();
            for index in 1..=held {
                let mut intent = record(1 + index % 200);
                let seqno = index;
                intent.session_id = UInt256::from_slice(&[seqno.to_le_bytes(); 8].concat());
                intent.block_data = vec![7; 16 << 10];
                ids.push(store.enqueue(intent)?);
            }
            let id = ids[0];
            store.mark_ready(id)?;
            let before = disk.written_bytes.load(Ordering::Relaxed);
            let writes = disk.sync_attempts.load(Ordering::Relaxed);
            assert!(store.checkpoint_sent(id, &[effect(PublicationKind::Candidate)])?);
            assert_eq!(disk.sync_attempts.load(Ordering::Relaxed), writes + 1);
            costs.push(disk.written_bytes.load(Ordering::Relaxed) - before);
        }
        assert_eq!(costs[0], costs[1], "a checkpoint rewrote state it did not change");
        assert!(costs[0] < 1024, "a checkpoint wrote {} bytes", costs[0]);
        Ok(())
    }

    /// Measurement only: wall time and bytes allocated on this thread per
    /// transition, with 1, 100 and 1000 records held (each with a 16 KiB body).
    /// Allocation includes the in-memory test store's copy of each value.
    #[test]
    #[ignore = "measurement; prints the cost of one transition"]
    fn outbox_transition_cpu_and_allocation_measurement() -> Result<()> {
        #[cfg(feature = "jemalloc")]
        fn allocated() -> u64 {
            tikv_jemalloc_ctl::thread::allocatedp::mib()
                .and_then(|mib| mib.read())
                .map(|counter| counter.get())
                .unwrap_or(0)
        }
        #[cfg(not(feature = "jemalloc"))]
        fn allocated() -> u64 {
            0
        }
        for held in [1u32, 100, 1000] {
            let disk = Arc::new(MemoryStore::default());
            let store = memory(disk.clone(), Limits::default());
            let mut ids = Vec::new();
            for index in 1..=held {
                let mut intent = record(1 + index % 200);
                intent.session_id = UInt256::from_slice(&[index.to_le_bytes(); 8].concat());
                intent.block_data = vec![7; 16 << 10];
                ids.push(store.enqueue(intent)?);
            }
            let measured: Vec<RecordId> = ids.iter().take(64).copied().collect();
            let started = std::time::Instant::now();
            let before = allocated();
            for id in &measured {
                store.mark_ready(*id)?;
                store.checkpoint_sent(*id, &[effect(PublicationKind::Candidate)])?;
            }
            let operations = (measured.len() * 2) as u128;
            let elapsed = started.elapsed().as_micros() / operations;
            let bytes = u128::from(allocated().saturating_sub(before)) / operations;
            eprintln!("outbox transition with {held} records held: {elapsed} us, {bytes} bytes allocated");
        }
        Ok(())
    }

    #[test]
    fn outbox_target_freeze_preserves_held_draft_and_syncs_complete_evidence() -> Result<()> {
        for failure in [0, 1, 2] {
            let disk = Arc::new(MemoryStore::default());
            let store = memory(disk.clone(), Limits::default());
            let delivery = store.stage_draft(record(1), 7, false, None)?;
            let (coordinates, _) = store.delivery(&delivery)?.unwrap();
            store.mark_accepted(coordinates.record_id)?;
            let (_, held) = store.delivery(&delivery)?.unwrap();
            assert!(held.record.effects.is_empty());
            let targets = vec![effect(PublicationKind::Block)];
            disk.failure.store(failure, Ordering::Release);
            let result = store.resolve_draft(coordinates.record_id, targets.clone());
            assert_eq!(result.is_ok(), failure == 0);
            assert!(held.record.effects.is_empty(), "target freeze mutated an earlier reader");
            assert!(held.pending.is_empty());
            if failure != 0 {
                assert!(store.pending().is_err(), "uncertain writes must remain sticky");
            }
            disk.failure.store(0, Ordering::Release);
            let reopened = memory(disk, Limits::default());
            let (_, restored) = reopened.delivery(&delivery)?.unwrap();
            assert_eq!(restored.record.block_data, held.record.block_data);
            assert_eq!(restored.record.proof_data, held.record.proof_data);
            assert_eq!(restored.record.carrier, held.record.carrier);
            if failure == 1 {
                assert_eq!(restored, held, "a rejected write must preserve the prior state");
            } else {
                assert_eq!(restored.stage, PublicationStage::Ready);
                assert_eq!(restored.pending, targets);
                assert_eq!(restored.record.effects, targets);
            }
        }
        Ok(())
    }

    #[test]
    fn outbox_mutation_epoch_advances_on_every_write_and_fails_closed_on_exhaustion() -> Result<()>
    {
        let disk = Arc::new(MemoryStore::default());
        let store = memory(disk.clone(), Limits::default());
        let start = store.mutation_epoch()?.unwrap();
        store.enqueue(record(1))?;
        let after_write = store.mutation_epoch()?.unwrap();
        assert!(after_write > start, "a write advances the epoch");
        // A failed write still advances it before the outbox turns sticky.
        disk.failure.store(1, Ordering::Release);
        assert!(store.enqueue(record(2)).is_err());
        assert!(store.mutation_epoch().is_err(), "an uncertain outbox refuses every read");
        // Exhaustion is permanent: no later write wraps the epoch back.
        let store = memory(Arc::new(MemoryStore::default()), Limits::default());
        store.exhaust_mutation_epoch_for_test();
        store.enqueue(record(3))?;
        assert_eq!(store.mutation_epoch()?, None);
        store.enqueue(record(4))?;
        assert_eq!(store.mutation_epoch()?, None);
        Ok(())
    }

    #[test]
    fn outbox_delivery_draft_resolve_complete_reopen_and_roles() -> Result<()> {
        let disk = Arc::new(MemoryStore::default());
        let limits = Limits::default();
        let store = memory(disk.clone(), limits.clone());
        let original = record(1);
        let delivery_id = store.stage_draft(original.clone(), 7, false, None)?;
        let (delivery, entry) = store.delivery(&delivery_id)?.unwrap();
        assert_eq!(entry.stage, PublicationStage::DraftDurable);
        assert!(entry.pending.is_empty());
        assert!(store.mark_ready(delivery.record_id).is_err());
        assert!(store.resolve_draft(delivery.record_id, Vec::new()).is_err());
        store.mark_accepted(delivery.record_id)?;
        assert_eq!(store.delivery(&delivery_id)?.unwrap().1.stage, PublicationStage::AcceptedDraft);
        let exact = vec![effect(PublicationKind::Block)];
        store.resolve_draft(delivery.record_id, exact.clone())?;
        store.resolve_draft(delivery.record_id, vec![effect(PublicationKind::Finality)])?;
        assert_eq!(store.delivery(&delivery_id)?.unwrap().1.record.effects, exact);
        store.mark_ready(delivery.record_id)?;
        assert!(store.checkpoint_sent(delivery.record_id, &exact)?);
        drop(store);
        let store = memory(disk, limits);
        let (_, completed) = store.delivery(&delivery_id)?.unwrap();
        assert_eq!(completed.stage, PublicationStage::Completed);
        assert_eq!(completed.record.block_data, original.block_data);
        let mut replay = original.clone();
        replay.created_at_unix_secs += 1;
        replay.expires_at_unix_secs += 1;
        replay.locally_generated = !replay.locally_generated;
        assert_eq!(store.stage_draft(replay, 500, true, None)?, delivery_id);
        assert_eq!(store.delivery(&delivery_id)?.unwrap().0.last_mc, 7);
        assert_eq!(store.delivery(&delivery_id)?.unwrap().1.stage, PublicationStage::Completed);
        let mut conflict = original.clone();
        conflict.block_data.push(99);
        assert!(store.stage_draft(conflict, 0, false, None).is_err());
        let mut approval = original;
        approval.carrier = StoredCarrier::Approval(vec![1, 2]);
        let approval_id = store.stage_draft(approval, 0, false, None)?;
        assert_ne!(delivery_id, approval_id);
        let id = store.delivery(&approval_id)?.unwrap().0.record_id;
        store.mark_accepted(id)?;
        store.resolve_draft(id, Vec::new())?;
        store.mark_ready(id)?;
        assert_eq!(store.delivery(&approval_id)?.unwrap().1.stage, PublicationStage::Completed);
        Ok(())
    }

    #[test]
    fn outbox_delivery_capacity_and_uncertain_wal_retain_evidence() -> Result<()> {
        let disk = Arc::new(MemoryStore::default());
        let limits = Limits { max_records: 1, ..Limits::default() };
        let store = memory(disk.clone(), limits.clone());
        disk.failure.store(2, Ordering::SeqCst);
        assert!(store.stage_draft(record(1), 0, false, None).is_err());
        assert!(store.pending().is_err());
        assert!(store.check_health().is_err());
        assert!(store
            .with_history_delivery::<()>(&delivery_id(&record(1))?, |_, _| {
                panic!("uncertain WAL must not expose history admission evidence")
            })
            .is_err());
        drop(store);
        disk.failure.store(0, Ordering::SeqCst);
        let store = memory(disk, limits);
        let identity = store.stage_draft(record(1), 0, false, None)?;
        let id = store.delivery(&identity)?.unwrap().0.record_id;
        store.mark_accepted(id)?;
        store.resolve_draft(id, Vec::new())?;
        store.mark_ready(id)?;
        assert!(store.stage_draft(record(2), 0, false, None).is_err());
        assert_eq!(store.delivery(&identity)?.unwrap().1.stage, PublicationStage::Completed);
        Ok(())
    }

    /// A snapshot key of an earlier development format refuses open: the outbox
    /// never starts empty beside old source references.
    #[test]
    fn outbox_earlier_format_refuses_open() {
        let disk = Arc::new(MemoryStore::default());
        disk.rows.lock().unwrap().insert(LEGACY_KEY.to_owned(), vec![1, 2, 3]);
        let error = reload(disk.clone()).err().unwrap();
        assert!(error.to_string().contains("earlier development"), "{error}");
        assert_eq!(disk.rows.lock().unwrap().len(), 1, "open wrote nothing");
    }

    #[test]
    fn outbox_accepted_draft_is_not_an_empty_or_expired_completion() -> Result<()> {
        let disk = Arc::new(MemoryStore::default());
        let store = memory(disk.clone(), Limits::default());
        let original = record(1);
        let identity = store.stage_draft(original.clone(), 7, false, None)?;
        let id = store.delivery(&identity)?.unwrap().0.record_id;
        assert!(original.is_expired(original.expires_at_unix_secs));
        assert!(store.resolve_draft(id, Vec::new()).is_err());
        store.mark_accepted(id)?;
        assert!(store.mark_ready(id).is_err(), "unresolved targets must never appear Ready");
        assert!(store.checkpoint_sent(id, &[]).is_err());
        drop(store);
        let store = memory(disk, Limits::default());
        let (_, entry) = store.delivery(&identity)?.unwrap();
        assert_eq!(entry.stage, PublicationStage::AcceptedDraft);
        assert!(entry.pending.is_empty());
        assert_eq!(entry.record.created_at_unix_secs, original.created_at_unix_secs);
        assert_eq!(entry.record.expires_at_unix_secs, original.expires_at_unix_secs);
        store.mark_accepted(id)?;
        assert_eq!(store.delivery(&identity)?.unwrap().1.stage, PublicationStage::AcceptedDraft);
        store.resolve_draft(id, Vec::new())?;
        assert_eq!(store.delivery(&identity)?.unwrap().1.stage, PublicationStage::Completed);
        Ok(())
    }

    #[test]
    fn outbox_acceptance_checkpoint_uncertainty_is_not_acknowledged() -> Result<()> {
        for failure in [1, 2] {
            let disk = Arc::new(MemoryStore::default());
            let store = memory(disk.clone(), Limits::default());
            let identity = store.stage_draft(record(1), 0, false, None)?;
            let id = store.delivery(&identity)?.unwrap().0.record_id;
            disk.failure.store(failure, Ordering::SeqCst);
            assert!(store.mark_accepted(id).is_err());
            assert!(store.delivery(&identity).is_err());
            drop(store);
            disk.failure.store(0, Ordering::SeqCst);
            let reopened = memory(disk, Limits::default());
            assert_eq!(
                reopened.delivery(&identity)?.unwrap().1.stage,
                if failure == 1 {
                    PublicationStage::DraftDurable
                } else {
                    PublicationStage::AcceptedDraft
                }
            );
            // A caller must authenticate and accept again before this idempotent
            // checkpoint; the recovered stage alone grants no receipt.
            reopened.mark_accepted(id)?;
            assert_eq!(
                reopened.delivery(&identity)?.unwrap().1.stage,
                PublicationStage::AcceptedDraft
            );
        }
        Ok(())
    }

    /// An uncertain batch reopens as the old or the new state; a torn batch,
    /// which models corruption, may be refused. The writer stays poisoned.
    #[test]
    fn outbox_uncertain_batch_reopens_old_or_new_and_torn_batch_is_refused() -> Result<()> {
        // A stage_draft batch carries body, state and meta.
        for failure in [1u8, 2, 3] {
            let disk = Arc::new(MemoryStore::default());
            let store = memory(disk.clone(), Limits::default());
            store.enqueue(record(1))?;
            disk.failure.store(failure, Ordering::SeqCst);
            assert!(store.stage_draft(record(2), 7, false, None).is_err());
            assert!(store.pending().is_err(), "the writer stays poisoned");
            assert!(store.enqueue(record(3)).is_err());
            disk.failure.store(0, Ordering::SeqCst);
            drop(store);
            match failure {
                1 => assert_eq!(reload(disk)?.pending()?.len(), 1, "old state"),
                2 => assert_eq!(reload(disk)?.pending()?.len(), 2, "new state"),
                _ => assert!(reload(disk).is_err(), "a torn batch is refused"),
            }
        }
        // A completion that deletes body and state, torn after the first delete.
        let disk = Arc::new(MemoryStore::default());
        let store = memory(disk.clone(), Limits::default());
        let id = store.enqueue(record(1))?;
        store.mark_ready(id)?;
        disk.failure.store(3, Ordering::SeqCst);
        assert!(store
            .checkpoint_sent(
                id,
                &[
                    effect(PublicationKind::Candidate),
                    effect(PublicationKind::Block),
                    effect(PublicationKind::Finality)
                ]
            )
            .is_err());
        disk.failure.store(0, Ordering::SeqCst);
        drop(store);
        assert!(reload(disk).is_err(), "half a record is refused");
        Ok(())
    }

    #[test]
    fn outbox_relationships_are_checked_at_open() -> Result<()> {
        let baseline = || -> Result<(Arc<MemoryStore>, RecordId)> {
            let disk = Arc::new(MemoryStore::default());
            let store = memory(disk.clone(), Limits::default());
            let id = store.enqueue(record(1))?;
            store.stage_draft(record(2), 7, false, None)?;
            Ok((disk, id))
        };
        let (disk, _) = baseline()?;
        assert!(reload(disk.clone()).is_ok());
        let edit = |change: &dyn Fn(&mut BTreeMap<String, Vec<u8>>)| -> Result<bool> {
            let (disk, _) = baseline()?;
            change(&mut disk.rows.lock().unwrap());
            Ok(reload(disk).is_err())
        };
        let first = RecordId(1);
        // Missing metadata beside records is corruption, not a first open.
        assert!(edit(&|rows| { rows.remove(META_KEY); })?);
        // An orphan body and an orphan state.
        assert!(edit(&|rows| { rows.remove(&state_key(first)); })?);
        assert!(edit(&|rows| { rows.remove(&body_key(first)); })?);
        // A value moved under another record's key.
        assert!(edit(&|rows| {
            let body = rows.remove(&body_key(first)).unwrap();
            let state = rows.remove(&state_key(first)).unwrap();
            rows.insert(body_key(RecordId(5)), body);
            rows.insert(state_key(RecordId(5)), state);
        })?);
        // A record above the allocator.
        assert!(edit(&|rows| {
            let body = rows.remove(&body_key(first)).unwrap();
            rows.insert(body_key(RecordId(9)), body);
        })?);
        // An unknown key in the namespace.
        assert!(edit(&|rows| { rows.insert(format!("{KEY_PREFIX}x"), vec![0]); })?);
        // A body stored as a state, and every truncation of every value.
        assert!(edit(&|rows| {
            let body = rows.get(&body_key(first)).unwrap().clone();
            rows.insert(state_key(first), body);
        })?);
        let (disk, _) = baseline()?;
        let rows = disk.snapshot();
        for (key, value) in &rows {
            for end in 0..value.len() {
                let (disk, _) = baseline()?;
                disk.rows.lock().unwrap().insert(key.clone(), value[..end].to_vec());
                assert!(reload(disk).is_err(), "{key} truncated to {end}");
            }
        }
        // Another domain refuses every value.
        let mut other = domain();
        other.global_id += 1;
        let (disk, _) = baseline()?;
        assert!(PropagationOutbox::load(disk, other, Limits::default(), None).is_err());
        Ok(())
    }

    #[test]
    fn outbox_empty_prepared_requires_identity() -> Result<()> {
        let limits = Limits::default();
        let digest = domain_digest(&domain())?;
        let mut empty = record(1);
        empty.effects.clear();
        let entry = UnverifiedRecord {
            id: RecordId(1),
            stage: PublicationStage::Prepared,
            record: Arc::new(empty.clone()),
            pending: Vec::new(),
        };
        let snapshot = Snapshot {
            next_close_generation: 1,
            closing: Vec::new(),
            next_id: 2,
            entries: Vec::new(),
            deliveries: Vec::new(),
        };
        let rows = |delivery: Option<&Delivery>| -> Result<Arc<MemoryStore>> {
            let disk = Arc::new(MemoryStore::default());
            let mut map = disk.rows.lock().unwrap();
            map.insert(META_KEY.to_owned(), encode_meta(&digest, &snapshot)?);
            map.insert(body_key(entry.id), encode_body(&digest, &entry, &limits)?);
            map.insert(state_key(entry.id), encode_state(&digest, &entry, delivery)?);
            drop(map);
            Ok(disk)
        };
        let error = reload(rows(None)?).err().unwrap();
        assert!(error.to_string().contains("Empty Prepared publication requires"), "{error}");
        let delivery = Delivery {
            delivery_id: delivery_id(&empty)?,
            record_id: RecordId(1),
            last_mc: 7,
            candidate_already_sent: true,
            origin: None,
        };
        let disk = rows(Some(&delivery))?;
        let store = reload(disk.clone())?;
        assert_eq!(store.delivery(&delivery.delivery_id)?.unwrap().1.stage, PublicationStage::Prepared);
        store.mark_accepted(RecordId(1))?;
        drop(store);
        assert_eq!(
            reload(disk)?.delivery(&delivery.delivery_id)?.unwrap().1.stage,
            PublicationStage::Completed
        );
        Ok(())
    }

    #[test]
    fn outbox_reopen_partial_checkpoint_role_and_stale_completion() -> Result<()> {
        let store = Arc::new(MemoryStore::default());
        let outbox = memory(store.clone(), Limits::default());
        let id = outbox.enqueue(record(1))?;
        assert!(outbox.checkpoint_sent(id, &[effect(PublicationKind::Candidate)]).is_err());
        outbox.mark_ready(id)?;
        assert!(outbox.checkpoint_sent(id, &[effect(PublicationKind::Candidate)])?);
        assert_eq!(outbox.enqueue(record(1))?, id);
        let mut replay = record(1);
        replay.created_at_unix_secs += 50;
        replay.expires_at_unix_secs += 50;
        assert_eq!(outbox.enqueue(replay)?, id);
        assert_eq!(outbox.pending()?[0].record.expires_at_unix_secs, 200);
        drop(outbox);
        let reopened = memory(store.clone(), Limits::default());
        let pending = reopened.pending()?;
        assert_eq!(pending[0].stage, PublicationStage::Ready);
        assert_eq!(
            pending[0].pending,
            vec![effect(PublicationKind::Block), effect(PublicationKind::Finality)]
        );
        assert!(reopened.checkpoint_sent(id, &pending[0].pending)?);
        drop(reopened);
        let reopened = memory(store, Limits::default());
        let next = reopened.enqueue(record(1))?;
        assert!(next.0 > id.0);
        assert!(!reopened.checkpoint_sent(id, &[effect(PublicationKind::Finality)])?);
        assert_eq!(reopened.pending()?[0].id, next);

        let mut approval = record(2);
        approval.carrier = StoredCarrier::Approval(vec![9]);
        assert!(reopened.enqueue(approval.clone()).is_err());
        approval.effects = vec![effect(PublicationKind::Block)];
        let approval_id = reopened.enqueue(approval)?;
        assert!(!reopened
            .pending()?
            .iter()
            .find(|p| p.id == approval_id)
            .unwrap()
            .record
            .carrier
            .is_final());
        // A shard block accepted with its notarization set broadcasts that set
        // as its finality; its shard description stays final-only.
        let shard = |seqno| {
            BlockIdExt::with_params(
                ShardIdent::full(0),
                seqno,
                UInt256::from([seqno as u8 + 1; 32]),
                UInt256::from([seqno as u8 + 2; 32]),
            )
        };
        let mut approval = record(3);
        approval.block_id = shard(3);
        approval.prev = vec![shard(2)];
        approval.carrier = StoredCarrier::Approval(vec![9]);
        approval.effects = vec![effect(PublicationKind::Block), effect(PublicationKind::Finality)];
        let approval_id = reopened.enqueue(approval.clone())?;
        let saved = reopened.pending()?.into_iter().find(|p| p.id == approval_id).unwrap();
        assert_eq!(saved.record.effects, approval.effects);
        approval.effects = vec![PublicationEffect {
            kind: PublicationKind::ShardDescription,
            target: PublicationTarget::ShardDescription,
        }];
        approval.block_id = shard(4);
        approval.prev = vec![shard(3)];
        assert!(reopened.enqueue(approval).is_err());
        Ok(())
    }

    #[test]
    fn outbox_capacity_and_expiry_never_discard_unsent_work() -> Result<()> {
        let store = Arc::new(MemoryStore::default());
        let limits = Limits {
            max_records: 1,
            max_block_bytes: 3,
            max_retention_secs: 100,
            ..Limits::default()
        };
        let outbox = memory(store.clone(), limits.clone());
        let mut oversized = record(1);
        oversized.block_data.push(4);
        assert!(outbox.enqueue(oversized).is_err());
        let mut too_long = record(1);
        too_long.expires_at_unix_secs += 1;
        assert!(outbox.enqueue(too_long).is_err());
        outbox.enqueue(record(1))?;
        assert!(outbox.enqueue(record(2)).is_err());
        drop(outbox);
        let recovered = memory(store, limits).pending()?;
        assert_eq!(recovered.len(), 1);
        assert!(recovered[0].record.is_expired(201));
        assert_eq!(recovered[0].pending.len(), 3);
        Ok(())
    }

    /// The aggregate byte budget is checked before a commit: a refusal writes
    /// nothing, does not poison, and every acknowledged state reopens.
    #[test]
    fn outbox_total_byte_capacity_does_not_poison_or_overwrite_previous_state() -> Result<()> {
        let store = Arc::new(MemoryStore::default());
        let limits = Limits {
            max_records: 3,
            max_snapshot_bytes: 1400,
            max_block_bytes: 512,
            max_proof_bytes: 128,
            max_carrier_bytes: 128,
            max_effects_per_record: 8,
            max_custom_target_bytes: 32,
            ..Limits::default()
        };
        let outbox = memory(store.clone(), limits.clone());
        let mut first = record(1);
        first.block_data.resize(512, 0);
        let id = outbox.enqueue(first)?;
        let saved = store.snapshot();
        let mut second = record(2);
        second.block_data.resize(512, 0);
        assert!(outbox.enqueue(second).is_err());
        assert_eq!(store.snapshot(), saved);
        assert_eq!(outbox.pending()?.len(), 1);
        outbox.mark_ready(id)?;
        drop(outbox);
        assert_eq!(memory(store.clone(), limits.clone()).pending()?[0].stage, PublicationStage::Ready);
        let total: usize = store.snapshot().iter().map(|(k, v)| k.len() + v.len()).sum();
        assert!(total <= limits.max_snapshot_bytes);
        Ok(())
    }

    #[test]
    fn outbox_concurrent_sessions_do_not_lose_updates() -> Result<()> {
        let outbox = Arc::new(memory(Arc::new(MemoryStore::default()), Limits::default()));
        let threads: Vec<_> = (1..=8)
            .map(|seqno| {
                let outbox = outbox.clone();
                std::thread::spawn(move || -> Result<_> {
                    let mut intent = record(seqno);
                    intent.session_id = UInt256::from([seqno as u8; 32]);
                    let id = outbox.enqueue(intent)?;
                    outbox.mark_ready(id)?;
                    outbox.checkpoint_sent(id, &[effect(PublicationKind::Block)])?;
                    Ok(id)
                })
            })
            .collect();
        let mut ids = BTreeSet::new();
        for thread in threads {
            assert!(ids.insert(thread.join().unwrap()?));
        }
        let pending = outbox.pending()?;
        assert_eq!(pending.len(), 8);
        assert!(pending.iter().all(|p| p.pending
            == vec![effect(PublicationKind::Candidate), effect(PublicationKind::Finality)]));
        Ok(())
    }

    #[test]
    fn outbox_canonical_reference_reuses_only_current_writer_synced_record() -> Result<()> {
        for failure in [1, 2] {
            let disk = Arc::new(MemoryStore::default());
            let store = memory(disk.clone(), Limits::default());
            let origin = RecoveryOrigin {
                carrier_version: 14,
                local_adnl: UInt256::from([1; 32]),
                source_validator: UInt256::from([2; 32]),
                local_validator_index: Some(0),
            };
            let id = store.stage_draft(record(1), 7, true, Some(origin))?;
            let (delivery, original) = store.delivery(&id)?.unwrap();
            let writes = disk.sync_attempts.load(Ordering::Relaxed);
            let rows = disk.snapshot();
            for _ in 0..8 { store.retain_delivery(&delivery)?; }
            assert_eq!(disk.sync_attempts.load(Ordering::Relaxed), writes,
                "canonical reference must reuse this writer's already synced record");
            assert_eq!(disk.snapshot(), rows);
            let mut forged = delivery.clone();
            forged.last_mc += 1;
            assert!(store.retain_delivery(&forged).is_err());
            drop(store);
            let reopened = memory(disk.clone(), Limits::default());
            reopened.retain_delivery(&delivery)?;
            assert_eq!(disk.sync_attempts.load(Ordering::Relaxed), writes + 1,
                "cold decoding alone must not stand in for a current-writer sync");
            reopened.retain_delivery(&delivery)?;
            assert_eq!(disk.sync_attempts.load(Ordering::Relaxed), writes + 1);
            assert_eq!(reopened.delivery(&id)?.unwrap().1, original);
            disk.failure.store(failure, Ordering::Release);
            assert!(reopened.mark_accepted(delivery.record_id).is_err());
            assert!(reopened.retain_delivery(&delivery).is_err(),
                "an uncertain later write invalidates every prior synchronized reference");
        }
        Ok(())
    }

    #[test]
    fn outbox_canonical_reference_reopen_and_uncertain_sync() -> Result<()> {
        for failure in [0, 1, 2] {
            let disk = Arc::new(MemoryStore::default());
            let store = memory(disk.clone(), Limits::default());
            let origin = RecoveryOrigin {
                carrier_version: 14,
                local_adnl: UInt256::from([1; 32]),
                source_validator: UInt256::from([2; 32]),
                local_validator_index: Some(0),
            };
            let id = store.stage_draft(record(1), 7, true, Some(origin))?;
            let (delivery, original) = store.delivery(&id)?.unwrap();
            store.mark_accepted(delivery.record_id)?;
            store.resolve_draft(delivery.record_id, Vec::new())?;
            assert_eq!(store.delivery(&id)?.unwrap().1.stage, PublicationStage::Completed);
            drop(store);
            let store = memory(disk.clone(), Limits::default());
            let mut other = delivery.clone();
            other.origin.as_mut().unwrap().local_adnl = UInt256::from([9; 32]);
            assert!(store.retain_delivery(&other).is_err());
            disk.failure.store(failure, Ordering::Release);
            assert_eq!(store.retain_delivery(&delivery).is_ok(), failure == 0);
            if failure != 0 {
                assert!(store.delivery(&id).is_err(), "uncertain owner must fail closed");
            }
            drop(store);
            disk.failure.store(0, Ordering::Release);
            let reopened = memory(disk, Limits::default());
            let (restored, entry) = reopened.delivery(&id)?.unwrap();
            assert_eq!(restored, delivery);
            assert_eq!(entry.record.block_data, original.record.block_data);
            assert_eq!(entry.record.carrier, original.record.carrier);
            assert_eq!(entry.record.created_at_unix_secs, original.record.created_at_unix_secs);
            reopened.retain_delivery(&restored)?;
        }
        Ok(())
    }

    #[test]
    fn outbox_write_failures_require_reopen_without_losing_possible_commit() -> Result<()> {
        for failure in [1, 2] {
            let store = Arc::new(MemoryStore::default());
            let outbox = memory(store.clone(), Limits::default());
            let id = outbox.enqueue(record(1))?;
            outbox.mark_ready(id)?;
            store.failure.store(failure, Ordering::Release);
            assert!(outbox.checkpoint_sent(id, &[effect(PublicationKind::Block)]).is_err());
            assert!(outbox.pending().is_err());
            assert!(outbox.enqueue(record(2)).is_err());
            assert!(outbox.mark_ready(id).is_err());
            drop(outbox);
            store.failure.store(0, Ordering::Release);
            let reopened = memory(store, Limits::default());
            let pending = reopened.pending()?;
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[0].pending.contains(&effect(PublicationKind::Block)), failure == 1);
            assert!(pending[0].pending.contains(&effect(PublicationKind::Finality)));
        }
        Ok(())
    }

    /// Loading reads every page while the caller holds the writer lease.
    #[test]
    fn outbox_paginated_load_reads_every_record() -> Result<()> {
        let disk = Arc::new(MemoryStore::default());
        let store = memory(disk.clone(), Limits::default());
        for seqno in 1..=300u32 {
            let mut intent = record(1 + seqno % 200);
            intent.session_id = UInt256::from_slice(&[seqno.to_le_bytes(); 8].concat());
            store.enqueue(intent)?;
        }
        drop(store);
        let rows = read_rows(disk.as_ref(), &Limits::default(), 7)?;
        assert_eq!(rows.len(), 601);
        assert_eq!(reload(disk)?.pending()?.len(), 300);
        Ok(())
    }

    /// Executed by the parent test in a separate OS process. process::exit skips
    /// Rust/RocksDB destructors, so recovery cannot rely on a graceful DB flush.
    #[test]
    fn outbox_crash_child() {
        let Some(path) = std::env::var_os("RTOS_OUTBOX_CRASH_TEST_PATH") else {
            return;
        };
        let disk = DiskStore::open(std::path::Path::new(&path), AccessType::ReadWrite).unwrap();
        let outbox = PropagationOutbox::load(disk, domain(), Limits::default(), None).unwrap();
        if let Ok(stage) = std::env::var("RTOS_OUTBOX_DELIVERY_CRASH_STAGE") {
            let identity = outbox.stage_draft(record(1), 7, true, None).unwrap();
            if stage == "accepted" || stage == "completed" {
                let id = outbox.delivery(&identity).unwrap().unwrap().0.record_id;
                outbox.mark_accepted(id).unwrap();
                if stage == "accepted" {
                    std::process::exit(73);
                }
                outbox.resolve_draft(id, Vec::new()).unwrap();
                outbox.mark_ready(id).unwrap();
            }
            std::process::exit(73);
        }
        let id = outbox.enqueue(record(1)).unwrap();
        outbox.mark_ready(id).unwrap();
        outbox.checkpoint_sent(id, &[effect(PublicationKind::Candidate)]).unwrap();
        std::process::exit(73);
    }

    #[test]
    fn outbox_delivery_real_process_exit_preserves_draft_and_completed_identity() -> Result<()> {
        for (mode, expected) in [
            ("draft", PublicationStage::DraftDurable),
            ("accepted", PublicationStage::AcceptedDraft),
            ("completed", PublicationStage::Completed),
        ] {
            let directory = tempfile::tempdir()?;
            let result = Command::new(std::env::current_exe()?)
                .arg("--exact")
                .arg("propagation_outbox::tests::outbox_crash_child")
                .arg("--test-threads=1")
                .env("RTOS_OUTBOX_CRASH_TEST_PATH", directory.path())
                .env("RTOS_OUTBOX_DELIVERY_CRASH_STAGE", mode)
                .status()?;
            assert_eq!(result.code(), Some(73));
            let disk = DiskStore::open(directory.path(), AccessType::ReadWrite)?;
            let store = PropagationOutbox::load(disk, domain(), Limits::default(), None)?;
            let identity = store.stage_draft(record(1), 900, false, None)?;
            let (delivery, entry) = store.delivery(&identity)?.unwrap();
            assert_eq!(entry.stage, expected);
            assert_eq!(delivery.last_mc, 7);
            assert!(delivery.candidate_already_sent);
            assert_eq!(entry.record.block_data, record(1).block_data);
        }
        Ok(())
    }

    #[test]
    fn outbox_real_wal_recovers_after_process_exit_and_checkpoints() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let result = Command::new(std::env::current_exe()?)
            .arg("--exact")
            .arg("propagation_outbox::tests::outbox_crash_child")
            .arg("--test-threads=1")
            .env("RTOS_OUTBOX_CRASH_TEST_PATH", directory.path())
            .status()?;
        assert_eq!(result.code(), Some(73), "child must exit after its synchronous checkpoint");
        {
            let store = DiskStore::open(directory.path(), AccessType::ReadWrite)?;
            let outbox = PropagationOutbox::load(store, domain(), Limits::default(), None)?;
            let pending = outbox.pending()?;
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[0].stage, PublicationStage::Ready);
            assert_eq!(
                pending[0].pending,
                vec![effect(PublicationKind::Block), effect(PublicationKind::Finality)]
            );
            outbox.checkpoint_sent(pending[0].id, &[effect(PublicationKind::Block)])?;
        }
        {
            let store = DiskStore::open(directory.path(), AccessType::ReadWrite)?;
            let outbox = PropagationOutbox::load(store, domain(), Limits::default(), None)?;
            assert_eq!(outbox.pending()?[0].pending, vec![effect(PublicationKind::Finality)]);
        }
        Ok(())
    }

    #[test]
    fn outbox_real_readonly_write_failure_does_not_acknowledge_checkpoint() -> Result<()> {
        let directory = tempfile::tempdir()?;
        {
            let store = DiskStore::open(directory.path(), AccessType::ReadWrite)?;
            let outbox = PropagationOutbox::load(store, domain(), Limits::default(), None)?;
            let id = outbox.enqueue(record(1))?;
            outbox.mark_ready(id)?;
        }
        {
            let store = DiskStore::open(directory.path(), AccessType::ReadOnly)?;
            let outbox = PropagationOutbox::load(store, domain(), Limits::default(), None)?;
            assert!(outbox
                .checkpoint_sent(RecordId(1), &[effect(PublicationKind::Finality)])
                .is_err());
            assert!(outbox.pending().is_err());
        }
        let store = DiskStore::open(directory.path(), AccessType::ReadWrite)?;
        let outbox = PropagationOutbox::load(store, domain(), Limits::default(), None)?;
        assert!(outbox.pending()?[0].pending.contains(&effect(PublicationKind::Finality)));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn outbox_internal_db_rejects_second_writer_and_releases_failed_open() -> Result<()> {
        use crate::{collator_test_bundle::create_engine_allocated, internal_db::InternalDbConfig};
        use std::sync::atomic::AtomicU8;
        let directory = tempfile::tempdir()?;
        let db = Arc::new(
            InternalDb::with_update(
                InternalDbConfig {
                    db_directory: directory.path().to_str().unwrap().into(),
                    ..Default::default()
                },
                false,
                false,
                false,
                None,
                &|| Ok(()),
                None,
                Arc::new(AtomicU8::new(0)),
                None,
                #[cfg(feature = "telemetry")]
                crate::collator_test_bundle::create_engine_telemetry(),
                create_engine_allocated(),
            )
            .await?,
        );
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
            let outbox = PropagationOutbox::open(db.clone(), domain(), Limits::default())?;
            let id = outbox.enqueue(record(1))?;
            assert!(PropagationOutbox::open(db.clone(), domain(), Limits::default()).is_err());
            drop(outbox);
            let mut wrong = domain();
            wrong.global_id += 1;
            assert!(PropagationOutbox::open(db.clone(), wrong, Limits::default()).is_err());
            let outbox = PropagationOutbox::open(db.clone(), domain(), Limits::default())?;
            assert_eq!(outbox.pending()?[0].id, id);
            Ok(())
        }));
        db.stop_states_db().await.unwrap();
        match result {
            Ok(result) => result,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
}
