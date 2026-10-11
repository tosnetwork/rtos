// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded durable publication intents, not authenticated consensus objects.
//!
//! Recovery must authenticate every record against the Engine's pinned history
//! and complete acceptance before marking it ready or sending. Neither the
//! checksum nor a Ready tag grants that authority. All methods are synchronous;
//! call them on an owned blocking worker, never while holding a network lock.
use crate::internal_db::{InternalDb, PropagationOutboxWriterLease};
use consensus_common::simplex_protocol::SimplexProtocol;
use rtos_api::WireProfile;
use rtos_block::{error, fail, BlockIdExt, Result, ShardIdent, UInt256};
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

const KEY: &str = "PropagationOutboxV1";
const MAGIC: &[u8; 8] = b"RTOSPBOX";
pub const SCHEMA_VERSION: u16 = 1;
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
/// snapshots/restarts. A stale completion cannot erase a later re-enqueue.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecordId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicationStage {
    Prepared,
    Ready,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnverifiedRecord {
    pub id: RecordId,
    pub stage: PublicationStage,
    pub record: PublicationRecord,
    pub pending: Vec<PublicationEffect>,
}

trait SnapshotStore: Send + Sync {
    fn load(&self, maximum: usize) -> Result<Option<Vec<u8>>>;
    fn replace_sync(&self, bytes: &[u8]) -> Result<()>;
}
impl SnapshotStore for InternalDb {
    fn load(&self, maximum: usize) -> Result<Option<Vec<u8>>> {
        self.load_validator_state_raw_bounded(KEY, maximum)
    }
    fn replace_sync(&self, bytes: &[u8]) -> Result<()> {
        self.save_validator_state_raw_sync(KEY, bytes)
    }
}

#[derive(Clone)]
struct Snapshot {
    next_id: u64,
    entries: Vec<UnverifiedRecord>,
}
struct State {
    snapshot: Snapshot,
    failed: Option<String>,
}

pub struct PropagationOutbox {
    store: Arc<dyn SnapshotStore>,
    domain: OutboxDomain,
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

    fn load(
        store: Arc<dyn SnapshotStore>,
        domain: OutboxDomain,
        limits: Limits,
        writer: Option<PropagationOutboxWriterLease>,
    ) -> Result<Self> {
        validate_domain(&domain)?;
        validate_limits(&limits)?;
        let snapshot = match store.load(limits.max_snapshot_bytes)? {
            Some(bytes) => decode_snapshot(&bytes, &domain, &limits)?,
            None => {
                let snapshot = Snapshot { next_id: 1, entries: Vec::new() };
                // Retain the domain and ID allocator even with no pending work.
                store.replace_sync(&encode_snapshot(&snapshot, &domain, &limits)?)?;
                snapshot
            }
        };
        Ok(Self {
            store,
            domain,
            limits,
            state: Mutex::new(State { snapshot, failed: None }),
            _writer: writer,
        })
    }

    pub fn domain(&self) -> &OutboxDomain {
        &self.domain
    }

    /// Persist before acknowledging acceptance or attempting any publication.
    /// Exact retries coalesce without restoring already completed effects.
    pub fn enqueue(&self, mut record: PublicationRecord) -> Result<RecordId> {
        record.effects.sort();
        validate_record(&record, &self.domain, &self.limits)?;
        let mut state = self.lock()?;
        if let Some(entry) =
            state.snapshot.entries.iter().find(|entry| entry.record.same_intent(&record))
        {
            return Ok(entry.id);
        }
        if state.snapshot.entries.len() >= self.limits.max_records {
            fail!("Propagation outbox record capacity exhausted");
        }
        let mut next = state.snapshot.clone();
        let id = RecordId(next.next_id);
        next.next_id =
            next.next_id.checked_add(1).ok_or_else(|| error!("Outbox ID space exhausted"))?;
        let pending = record.effects.clone();
        next.entries.push(UnverifiedRecord {
            id,
            stage: PublicationStage::Prepared,
            record,
            pending,
        });
        self.commit(&mut state, next)?;
        Ok(id)
    }

    /// Only the acceptance owner calls this after persistence/application has
    /// succeeded. On restart, even Ready records require fresh authentication.
    pub fn mark_ready(&self, id: RecordId) -> Result<()> {
        let mut state = self.lock()?;
        let mut next = state.snapshot.clone();
        let entry = next
            .entries
            .iter_mut()
            .find(|entry| entry.id == id)
            .ok_or_else(|| error!("Unknown propagation outbox record {}", id.0))?;
        if entry.stage == PublicationStage::Ready {
            return Ok(());
        }
        entry.stage = PublicationStage::Ready;
        self.commit(&mut state, next)
    }

    /// Checkpoint only effects whose transport accepted a send attempt. Failed,
    /// deferred or absent outcomes must not be passed here. No remote delivery
    /// acknowledgement is implied. Duplicate/stale completions are harmless.
    pub fn checkpoint_sent(&self, id: RecordId, sent: &[PublicationEffect]) -> Result<bool> {
        let mut state = self.lock()?;
        let mut next = state.snapshot.clone();
        let Some(index) = next.entries.iter().position(|entry| entry.id == id) else {
            return Ok(false);
        };
        let entry = &mut next.entries[index];
        if entry.stage != PublicationStage::Ready {
            fail!("Cannot checkpoint a Prepared publication");
        }
        if sent.iter().any(|effect| !entry.record.effects.contains(effect)) {
            fail!("Publication checkpoint contains an effect outside the original intent");
        }
        let before = entry.pending.len();
        entry.pending.retain(|effect| !sent.contains(effect));
        if before == entry.pending.len() {
            return Ok(false);
        }
        if entry.pending.is_empty() {
            next.entries.remove(index);
        }
        self.commit(&mut state, next)?;
        Ok(true)
    }

    /// Returns unverified, bounded recovery data, including Prepared/expired
    /// intents. Caller authentication and retention policy cannot be skipped.
    pub fn pending(&self) -> Result<Vec<UnverifiedRecord>> {
        Ok(self.lock()?.snapshot.entries.clone())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>> {
        let state = self.state.lock().map_err(|_| error!("Propagation outbox writer panicked"))?;
        if let Some(error) = &state.failed {
            fail!("Propagation outbox write outcome is uncertain; reopen required: {error}");
        }
        Ok(state)
    }

    fn commit(&self, state: &mut State, next: Snapshot) -> Result<()> {
        let bytes = encode_snapshot(&next, &self.domain, &self.limits)?;
        if let Err(error) = self.store.replace_sync(&bytes) {
            // I/O errors can occur after a write became visible. Do not keep
            // mutating an in-memory snapshot that may no longer match the WAL.
            state.failed = Some(error.to_string());
            return Err(error);
        }
        state.snapshot = next;
        Ok(())
    }
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
        || record.effects.is_empty()
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
        if !record.carrier.is_final()
            && matches!(effect.kind, PublicationKind::Finality | PublicationKind::ShardDescription)
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
    if pending.is_empty()
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
    let next_id = entry.id.0.checked_add(1).ok_or_else(|| error!("Outbox ID exhausted"))?;
    if entry.id.0 == 0 {
        fail!("Invalid outbox record ID");
    }
    encode_snapshot(
        &Snapshot { next_id, entries: vec![entry.clone()] },
        &entry.record.domain,
        limits,
    )?;
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

fn encode_snapshot(snapshot: &Snapshot, domain: &OutboxDomain, limits: &Limits) -> Result<Vec<u8>> {
    if snapshot.entries.len() > limits.max_records {
        fail!("Outbox record capacity exhausted");
    }
    let mut out = Encoder { bytes: Vec::new(), maximum: limits.max_snapshot_bytes - DIGEST_BYTES };
    out.append(MAGIC)?;
    out.append(&SCHEMA_VERSION.to_le_bytes())?;
    out.byte(match domain.wire_profile {
        WireProfile::Legacy => 0,
        WireProfile::T0 => 1,
    })?;
    out.append(&domain.global_id.to_le_bytes())?;
    out.id(&domain.zerostate)?;
    out.u64(snapshot.next_id)?;
    out.u32(u32::try_from(snapshot.entries.len())?)?;
    for entry in &snapshot.entries {
        let record = &entry.record;
        validate_record(record, domain, limits)?;
        out.u64(entry.id.0)?;
        out.byte(match entry.stage {
            PublicationStage::Prepared => 0,
            PublicationStage::Ready => 1,
        })?;
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
        out.effects(&record.effects)?;
        out.effects(&entry.pending)?;
    }
    let digest = UInt256::calc_file_hash(&out.bytes);
    out.bytes.extend_from_slice(digest.as_slice());
    Ok(out.bytes)
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Decoder<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(size).ok_or_else(|| error!("Outbox length overflow"))?;
        let bytes =
            self.bytes.get(self.offset..end).ok_or_else(|| error!("Truncated outbox snapshot"))?;
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
        // actual, bounded input consumption, including for truncated snapshots.
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
}

fn decode_snapshot(bytes: &[u8], domain: &OutboxDomain, limits: &Limits) -> Result<Snapshot> {
    if bytes.len() > limits.max_snapshot_bytes || bytes.len() < DIGEST_BYTES {
        fail!("Outbox snapshot length invalid");
    }
    let (payload, digest) = bytes.split_at(bytes.len() - DIGEST_BYTES);
    if UInt256::calc_file_hash(payload).as_slice() != digest {
        fail!("Outbox snapshot checksum mismatch");
    }
    let mut input = Decoder { bytes: payload, offset: 0 };
    if input.take(8)? != MAGIC {
        fail!("Unknown outbox snapshot magic");
    }
    if u16::from_le_bytes(input.take(2)?.try_into()?) != SCHEMA_VERSION {
        fail!("Unknown outbox schema version");
    }
    let wire_profile = match input.byte()? {
        0 => WireProfile::Legacy,
        1 => WireProfile::T0,
        _ => return Err(error!("Unknown outbox wire profile")),
    };
    let global_id = i32::from_le_bytes(input.take(4)?.try_into()?);
    let stored_domain = OutboxDomain { wire_profile, global_id, zerostate: input.id()? };
    if &stored_domain != domain {
        fail!("Outbox snapshot belongs to another network or wire profile");
    }
    let next_id = input.u64()?;
    if next_id == 0 {
        fail!("Invalid outbox ID allocator");
    }
    let count = input.count(limits.max_records)?;
    let mut entries = Vec::new();
    let mut ids = BTreeSet::new();
    for _ in 0..count {
        let id = RecordId(input.u64()?);
        if id.0 == 0 || id.0 >= next_id || !ids.insert(id) {
            fail!("Invalid or repeated outbox record ID");
        }
        let stage = match input.byte()? {
            0 => PublicationStage::Prepared,
            1 => PublicationStage::Ready,
            _ => return Err(error!("Unknown outbox publication stage")),
        };
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
        let effects = input.effects(limits)?;
        let pending = input.effects(limits)?;
        let record = PublicationRecord {
            domain: stored_domain.clone(),
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
            effects,
        };
        validate_record(&record, domain, limits)?;
        validate_pending(&record, stage, &pending)?;
        entries.push(UnverifiedRecord { id, stage, record, pending });
    }
    if input.offset != payload.len() {
        fail!("Trailing outbox snapshot bytes");
    }
    Ok(Snapshot { next_id, entries })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        process::Command,
        sync::atomic::{AtomicU8, Ordering},
    };
    use storage::{
        block_handle_db::NodeStateDb,
        db::rocksdb::{AccessType, RocksDb},
    };

    #[derive(Default)]
    struct MemoryStore {
        bytes: Mutex<Option<Vec<u8>>>,
        /// 1 fails before commit; 2 simulates an ambiguous error after commit.
        failure: AtomicU8,
    }
    impl SnapshotStore for MemoryStore {
        fn load(&self, maximum: usize) -> Result<Option<Vec<u8>>> {
            let bytes = self.bytes.lock().unwrap();
            if bytes.as_ref().is_some_and(|bytes| bytes.len() > maximum) {
                fail!("Stored snapshot exceeds read limit");
            }
            Ok(bytes.clone())
        }
        fn replace_sync(&self, bytes: &[u8]) -> Result<()> {
            let failure = self.failure.load(Ordering::Acquire);
            if failure == 1 {
                fail!("Injected write failure before commit");
            }
            *self.bytes.lock().unwrap() = Some(bytes.to_vec());
            if failure == 2 {
                fail!("Injected uncertain write failure after commit");
            }
            Ok(())
        }
    }
    struct DiskStore(NodeStateDb);
    impl DiskStore {
        fn open(path: &std::path::Path, access: AccessType) -> Result<Arc<Self>> {
            let db = RocksDb::new(path, "outbox", None, access)?;
            Ok(Arc::new(Self(NodeStateDb::with_db(db, "publication_test", true)?)))
        }
    }
    impl SnapshotStore for DiskStore {
        fn load(&self, maximum: usize) -> Result<Option<Vec<u8>>> {
            let value = self.0.try_get_raw(KEY.as_bytes())?;
            match value {
                Some(bytes) if bytes.len() > maximum => Err(error!("Snapshot exceeds read limit")),
                Some(bytes) => Ok(Some(bytes.to_vec())),
                None => Ok(None),
            }
        }
        fn replace_sync(&self, bytes: &[u8]) -> Result<()> {
            self.0.put_raw_sync(KEY.as_bytes(), bytes)
        }
    }

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

    #[test]
    fn outbox_total_byte_capacity_does_not_poison_or_overwrite_previous_snapshot() -> Result<()> {
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
        let saved = store.load(limits.max_snapshot_bytes)?;
        let mut second = record(2);
        second.block_data.resize(512, 0);
        assert!(outbox.enqueue(second).is_err());
        assert_eq!(store.load(limits.max_snapshot_bytes)?, saved);
        assert_eq!(outbox.pending()?.len(), 1);
        outbox.mark_ready(id)?;
        drop(outbox);
        assert_eq!(memory(store, limits).pending()?[0].stage, PublicationStage::Ready);
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

    fn checksum(bytes: &mut [u8]) {
        let end = bytes.len() - DIGEST_BYTES;
        let digest = UInt256::calc_file_hash(&bytes[..end]);
        bytes[end..].copy_from_slice(digest.as_slice());
    }

    #[test]
    fn outbox_recovery_rejects_corruption_unknown_domains_and_unbounded_lengths() -> Result<()> {
        let store = Arc::new(MemoryStore::default());
        let outbox = memory(store.clone(), Limits::default());
        outbox.enqueue(record(1))?;
        let bytes = store.load(1 << 20)?.unwrap();
        drop(outbox);
        for length in 0..bytes.len() {
            assert!(decode_snapshot(&bytes[..length], &domain(), &Limits::default()).is_err());
        }
        let mut other = domain();
        other.zerostate.file_hash = UInt256::from([90; 32]);
        assert!(decode_snapshot(&bytes, &other, &Limits::default()).is_err());
        other = domain();
        other.global_id += 1;
        assert!(decode_snapshot(&bytes, &other, &Limits::default()).is_err());
        other = domain();
        other.wire_profile = WireProfile::Legacy;
        assert!(decode_snapshot(&bytes, &other, &Limits::default()).is_err());
        // Repair the checksum to exercise semantic parsing, not only hashing.
        // header: magic(8), schema(2), wire(1), global(4), pin(80), next(8), count(4).
        for (index, value) in [(8, 2), (10, 99), (115, 99), (116, 99)] {
            let mut bad = bytes.clone();
            bad[index] = value;
            checksum(&mut bad);
            assert!(decode_snapshot(&bad, &domain(), &Limits::default()).is_err());
        }
        let mut bad = bytes.clone();
        bad[103..107].copy_from_slice(&u32::MAX.to_le_bytes());
        checksum(&mut bad);
        assert!(decode_snapshot(&bad, &domain(), &Limits::default()).is_err());
        // This fixture's block-data length follows its fixed metadata, one
        // previous ID and a three-byte carrier. Do not allocate its forged size.
        let mut huge_body = bytes.clone();
        huge_body[367..371].copy_from_slice(&u32::MAX.to_le_bytes());
        checksum(&mut huge_body);
        assert!(decode_snapshot(&huge_body, &domain(), &Limits::default()).is_err());
        let mut trailing = bytes[..bytes.len() - DIGEST_BYTES].to_vec();
        trailing.push(0);
        trailing.extend_from_slice(&[0; DIGEST_BYTES]);
        checksum(&mut trailing);
        assert!(decode_snapshot(&trailing, &domain(), &Limits::default()).is_err());
        *store.bytes.lock().unwrap() = Some(bad);
        assert!(PropagationOutbox::load(store, domain(), Limits::default(), None).is_err());
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
        let id = outbox.enqueue(record(1)).unwrap();
        outbox.mark_ready(id).unwrap();
        outbox.checkpoint_sent(id, &[effect(PublicationKind::Candidate)]).unwrap();
        std::process::exit(73);
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
        db.stop_states_db().await;
        match result {
            Ok(result) => result,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
}
