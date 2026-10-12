// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Validator consensus-database cleanup: the pure core.
//!
//! A validator consensus database holds own votes and leader-window recovery
//! state, so deleting one for a session that can still be legally recreated
//! would destroy live consensus state. Deletion authority is therefore bound to
//! a durable record and to a masterchain checkpoint proving the session is
//! permanently retired. This module holds the record, its strict encoding, the
//! canonical directory names it may act on, the deletion gate and the driver
//! state machine. It has no I/O, so every decision is unit-testable.
use crate::session_runtime::{
    SessionNetworkPin, SessionRecoveryBinding, SessionRecoveryCoordinates,
};
use crate::Result;
use rtos_block::{BlockIdExt, ShardIdent, UInt256};
use std::collections::BTreeMap;

/// Physical layout of a consensus namespace under `<root>/consensus`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NamespaceLayout {
    /// Simplex protocols 0 and 1.
    V1,
    /// Simplex protocol 2, validator role.
    V2Validator,
    /// Simplex protocol 2, observer role with its local ADNL id.
    V2Observer(UInt256),
}

/// The namespace name relative to `<root>/consensus`. Every runtime directory
/// is rendered here, so a cleanup record names exactly the real directory.
pub fn namespace_relative_name(
    layout: &NamespaceLayout,
    shard: &ShardIdent,
    catchain_seqno: u32,
    session_id: &UInt256,
) -> String {
    let base = format!(
        "consensus.{}.{:016x}.{}.{}",
        shard.workchain_id(),
        shard.shard_prefix_with_tag(),
        catchain_seqno,
        session_id.to_hex_string()
    );
    match layout {
        NamespaceLayout::V1 => base,
        NamespaceLayout::V2Validator => format!("v2/{base}.validator"),
        NamespaceLayout::V2Observer(adnl) => format!("v2/{base}.observer.{}", adnl.to_hex_string()),
    }
}

/// Shard and catchain seqno recovered from a canonical namespace name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedNamespace {
    pub layout: NamespaceLayout,
    pub shard: ShardIdent,
    pub catchain_seqno: u32,
}

/// Parses a namespace name whose session id is exactly `session_id`. The
/// authority is: parse the fields, then require that re-rendering the
/// canonical name equals the input. That one equality rejects any suffix,
/// separator, non-canonical number and session mismatch.
pub fn parse_canonical_namespace_name(name: &str, session_id: &UInt256) -> Option<ParsedNamespace> {
    let (versioned, rest) = match name.strip_prefix("v2/") {
        Some(rest) => (true, rest),
        None => (false, name),
    };
    let mut fields = rest.splitn(6, '.');
    if fields.next()? != "consensus" {
        return None;
    }
    let workchain: i32 = fields.next()?.parse().ok()?;
    let shard_text = fields.next()?;
    if shard_text.len() != 16 {
        return None;
    }
    let shard_prefix = u64::from_str_radix(shard_text, 16).ok()?;
    let catchain_seqno: u32 = fields.next()?.parse().ok()?;
    // No-wrap invariant: a namespace at the last catchain seqno is never acted on.
    if catchain_seqno == u32::MAX {
        return None;
    }
    let session_text = fields.next()?;
    if session_text != session_id.to_hex_string() {
        return None;
    }
    let layout = match (versioned, fields.next()) {
        (false, None) => NamespaceLayout::V1,
        (true, Some("validator")) => NamespaceLayout::V2Validator,
        (true, Some(observer)) => {
            let adnl = observer.strip_prefix("observer.")?;
            if adnl.len() != 64 {
                return None;
            }
            NamespaceLayout::V2Observer(adnl.parse().ok()?)
        }
        _ => return None,
    };
    let shard = ShardIdent::with_tagged_prefix(workchain, shard_prefix).ok()?;
    if namespace_relative_name(&layout, &shard, catchain_seqno, session_id) != name {
        return None;
    }
    Some(ParsedNamespace { layout, shard, catchain_seqno })
}

/// A cleanup checkpoint must be a fully specified masterchain block.
pub fn is_full_masterchain_checkpoint(block: &BlockIdExt) -> bool {
    block.shard().is_masterchain() && !block.root_hash().is_zero() && !block.file_hash().is_zero()
}

/// One durable cleanup intent: a session, the masterchain checkpoint at which
/// it retired, the exact namespace to reclaim once retirement is proven and,
/// for an authenticated namespace, the identity that re-authenticates it from
/// history after a restart.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingValidatorCleanup {
    pub session_id: UInt256,
    pub retirement_checkpoint: BlockIdExt,
    pub namespace: String,
    pub identity: Option<CleanupIdentity>,
}

/// What a cold cleanup needs to re-authenticate an authenticated namespace:
/// the network pin, the recovery binding and the local ADNL it ran with.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupIdentity {
    pub pin: SessionNetworkPin,
    pub binding: SessionRecoveryBinding,
    pub local_adnl: UInt256,
}

const RECORD_VERSION: u8 = 2;
const BLOCK_ID_BYTES: usize = 4 + 8 + 4 + 32 + 32;
// version(1) + session(32) + checkpoint + namespace length(2)
const FIXED_PREFIX: usize = 1 + 32 + BLOCK_ID_BYTES + 2;
// global id(4) + zerostate + governing block + coordinates (4 + 8 + 4 + 4 + 4 + 1) + ADNL(32)
const IDENTITY_BYTES: usize = 4 + BLOCK_ID_BYTES + BLOCK_ID_BYTES + 25 + 32;
const MAX_NAMESPACE_BYTES: usize = 512;
#[cfg(test)]
pub(crate) const FIXED_PREFIX_FOR_TEST: usize = FIXED_PREFIX;
/// Upper bound for one encoded record.
pub const MAX_RECORD_BYTES: usize = FIXED_PREFIX + MAX_NAMESPACE_BYTES + 1 + IDENTITY_BYTES;

/// Outcome of a cold re-verification of an authenticated namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CleanupVerdict {
    /// Every node obligation is Released and exactly covered by the source.
    WouldDelete {
        closes: usize,
    },
    Veto(String),
}

/// Key prefix for records. Each physical namespace has its own key (the
/// prefix plus its canonical relative name), so retirement and erase are
/// single-key writes and namespaces sharing a session never overwrite each
/// other.
pub const RECORD_KEY_PREFIX: &str = "ValidatorConsensusCleanupV2.";

pub fn record_key(namespace: &str) -> String {
    format!("{RECORD_KEY_PREFIX}{namespace}")
}

/// The key prefixes under which records of `session` can exist: its V1
/// namespace name, and its authenticated namespaces (validator and every
/// observer ADNL), for a bounded per-session scan.
pub fn session_record_prefixes(
    shard: &ShardIdent,
    catchain_seqno: u32,
    session: &UInt256,
) -> [String; 2] {
    let base = namespace_relative_name(&NamespaceLayout::V1, shard, catchain_seqno, session);
    [record_key(&base), record_key(&format!("v2/{base}."))]
}

/// Durable session-level claim to delete the session's candidate table,
/// written with the erase of the session's last namespace record.
pub const CANDIDATE_CLAIM_PREFIX: &str = "ValidatorCandidateCleanupV1.";

pub fn candidate_claim_key(session: &UInt256) -> String {
    format!("{CANDIDATE_CLAIM_PREFIX}{}", session.to_hex_string())
}

/// The session of a claim key, if it is exactly a canonical claim key.
pub fn parse_candidate_claim_key(key: &str) -> Option<UInt256> {
    let hex = key.strip_prefix(CANDIDATE_CLAIM_PREFIX)?;
    let session: UInt256 = hex.parse().ok()?;
    (session.to_hex_string() == hex).then_some(session)
}

/// Builds the record for a retiring group. The name is rendered by the same
/// function as the runtime directory, so a later cleanup acts on the real one.
pub fn make_record(
    session_id: &UInt256,
    layout: &NamespaceLayout,
    shard: &ShardIdent,
    catchain_seqno: u32,
    retirement_checkpoint: &BlockIdExt,
) -> Result<PendingValidatorCleanup> {
    if !is_full_masterchain_checkpoint(retirement_checkpoint) {
        rtos_block::fail!("Cleanup checkpoint must be a full masterchain block");
    }
    let namespace = namespace_relative_name(layout, shard, catchain_seqno, session_id);
    if parse_canonical_namespace_name(&namespace, session_id).is_none() {
        rtos_block::fail!("Cleanup namespace is not canonical");
    }
    if namespace.len() > MAX_NAMESPACE_BYTES {
        rtos_block::fail!("Cleanup namespace exceeds the record bound");
    }
    Ok(PendingValidatorCleanup {
        session_id: session_id.clone(),
        retirement_checkpoint: retirement_checkpoint.clone(),
        namespace,
        identity: None,
    })
}

fn put_block_id(out: &mut Vec<u8>, id: &BlockIdExt) {
    out.extend_from_slice(&id.shard().workchain_id().to_le_bytes());
    out.extend_from_slice(&id.shard().shard_prefix_with_tag().to_le_bytes());
    out.extend_from_slice(&id.seq_no().to_le_bytes());
    out.extend_from_slice(id.root_hash().as_slice());
    out.extend_from_slice(id.file_hash().as_slice());
}

/// A strict little-endian reader: every read is bounds-checked.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(len)?;
        let slice = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn i32(&mut self) -> Option<i32> {
        Some(i32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn hash(&mut self) -> Option<UInt256> {
        Some(UInt256::from_slice(self.take(32)?))
    }
    fn shard(&mut self) -> Option<ShardIdent> {
        let workchain = self.i32()?;
        ShardIdent::with_tagged_prefix(workchain, self.u64()?).ok()
    }
    fn block_id(&mut self) -> Option<BlockIdExt> {
        let shard = self.shard()?;
        let seqno = self.u32()?;
        let root = self.hash()?;
        Some(BlockIdExt::with_params(shard, seqno, root, self.hash()?))
    }
    fn done(&self) -> bool {
        self.at == self.bytes.len()
    }
}

/// Whether `identity` fits `namespace`: only an authenticated layout carries
/// one, its coordinates name the namespace's shard and catchain seqno, and an
/// observer's ADNL is the one in its name.
fn identity_fits(parsed: &ParsedNamespace, identity: Option<&CleanupIdentity>) -> bool {
    match (&parsed.layout, identity) {
        (NamespaceLayout::V1, None) => true,
        (NamespaceLayout::V1, Some(_)) => false,
        (_, None) => true,
        (layout, Some(identity)) => {
            let coordinates = &identity.binding.coordinates;
            coordinates.shard == parsed.shard
                && coordinates.catchain_seqno == parsed.catchain_seqno
                && identity.pin.zerostate.shard().is_masterchain()
                && identity.binding.governing_masterchain.shard().is_masterchain()
                && match layout {
                    NamespaceLayout::V2Observer(adnl) => adnl == &identity.local_adnl,
                    _ => true,
                }
        }
    }
}

impl PendingValidatorCleanup {
    /// Attaches the re-authentication identity of an authenticated namespace.
    pub fn with_identity(mut self, identity: CleanupIdentity) -> Result<Self> {
        let parsed = parse_canonical_namespace_name(&self.namespace, &self.session_id)
            .ok_or_else(|| rtos_block::error!("Cleanup namespace is not canonical"))?;
        if !identity_fits(&parsed, Some(&identity)) {
            rtos_block::fail!("Cleanup identity does not fit its namespace");
        }
        self.identity = Some(identity);
        Ok(self)
    }
}

/// Deterministic little-endian encoding, versioned so an old record is
/// rejected rather than misread.
pub fn encode_record(record: &PendingValidatorCleanup) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAX_RECORD_BYTES);
    out.push(RECORD_VERSION);
    out.extend_from_slice(record.session_id.as_slice());
    put_block_id(&mut out, &record.retirement_checkpoint);
    // Canonical names are far below the cap; `make_record` and decode both
    // enforce it, so the length always fits.
    let name = record.namespace.as_bytes();
    out.extend_from_slice(&(name.len().min(MAX_NAMESPACE_BYTES) as u16).to_le_bytes());
    out.extend_from_slice(&name[..name.len().min(MAX_NAMESPACE_BYTES)]);
    match &record.identity {
        None => out.push(0),
        Some(identity) => {
            out.push(1);
            out.extend_from_slice(&identity.pin.global_id.to_le_bytes());
            put_block_id(&mut out, &identity.pin.zerostate);
            put_block_id(&mut out, &identity.binding.governing_masterchain);
            let coordinates = &identity.binding.coordinates;
            out.extend_from_slice(&coordinates.shard.workchain_id().to_le_bytes());
            out.extend_from_slice(&coordinates.shard.shard_prefix_with_tag().to_le_bytes());
            out.extend_from_slice(&coordinates.catchain_seqno.to_le_bytes());
            out.extend_from_slice(&coordinates.vertical_seqno.to_le_bytes());
            out.extend_from_slice(&coordinates.last_key_block_seqno.to_le_bytes());
            out.push(u8::from(coordinates.new_catchain_ids));
            out.extend_from_slice(identity.local_adnl.as_slice());
        }
    }
    out
}

/// Strict decode. Anything inconsistent yields nothing: a malformed safety
/// record never grants authority to delete (at worst a directory leaks).
pub fn decode_record(value: &[u8]) -> Option<PendingValidatorCleanup> {
    if value.len() < FIXED_PREFIX + 1 || value.len() > MAX_RECORD_BYTES {
        return None;
    }
    let mut reader = Reader { bytes: value, at: 0 };
    if reader.u8()? != RECORD_VERSION {
        return None;
    }
    let session_id = reader.hash()?;
    let checkpoint = reader.block_id()?;
    if !is_full_masterchain_checkpoint(&checkpoint) {
        return None;
    }
    let name_len = usize::from(reader.u16()?);
    if name_len > MAX_NAMESPACE_BYTES {
        return None;
    }
    let namespace = std::str::from_utf8(reader.take(name_len)?).ok()?.to_owned();
    let parsed = parse_canonical_namespace_name(&namespace, &session_id)?;
    let identity = match reader.u8()? {
        0 => None,
        1 => {
            let global_id = reader.i32()?;
            let zerostate = reader.block_id()?;
            let governing_masterchain = reader.block_id()?;
            let shard = reader.shard()?;
            let catchain_seqno = reader.u32()?;
            let vertical_seqno = reader.u32()?;
            let last_key_block_seqno = reader.u32()?;
            let new_catchain_ids = match reader.u8()? {
                0 => false,
                1 => true,
                _ => return None,
            };
            let local_adnl = reader.hash()?;
            Some(CleanupIdentity {
                pin: SessionNetworkPin { global_id, zerostate },
                binding: SessionRecoveryBinding {
                    governing_masterchain,
                    coordinates: SessionRecoveryCoordinates {
                        shard,
                        catchain_seqno,
                        vertical_seqno,
                        last_key_block_seqno,
                        new_catchain_ids,
                    },
                },
                local_adnl,
            })
        }
        _ => return None,
    };
    if !reader.done() || !identity_fits(&parsed, identity.as_ref()) {
        return None;
    }
    Some(PendingValidatorCleanup {
        session_id,
        retirement_checkpoint: checkpoint,
        namespace,
        identity,
    })
}

/// The retirement checkpoint is the GC block or a verified ancestor of it on
/// the accepted chain; false on any uncertainty.
pub type AncestorOfGcFn<'a> = dyn Fn(&BlockIdExt) -> bool + 'a;
/// The shard's catchain seqno as of the GC state; nothing when unknown, which
/// vetoes deletion.
pub type GcShardCatchainSeqnoFn<'a> = dyn Fn(&ShardIdent) -> Option<u32> + 'a;
/// Whether the session currently has a live or pending group.
pub type SessionIsLiveFn<'a> = dyn Fn(&UInt256) -> bool + 'a;
/// Whether the retiring group confirmed its close for the recorded incarnation.
pub type SessionIsClosedFn<'a> = dyn Fn(&UInt256) -> bool + 'a;
/// Local veto over a record that the gate would otherwise allow.
pub type CustodyVetoFn<'a> = dyn Fn(&PendingValidatorCleanup) -> bool + 'a;

/// On-chain obsolescence, bound to the durable GC floor. True only when the
/// retirement checkpoint is the GC block or its ancestor and the namespace's
/// catchain seqno is below the shard's catchain seqno at GC: then the session
/// is in neither the current nor the next set at GC and, since the per-shard
/// catchain seqno never decreases on the accepted chain, cannot recur.
pub fn session_is_onchain_obsolete(
    record: &PendingValidatorCleanup,
    gc_checkpoint: &BlockIdExt,
    ancestor_or_equal_of_gc: &AncestorOfGcFn,
    gc_shard_catchain_seqno: &GcShardCatchainSeqnoFn,
) -> bool {
    if !is_full_masterchain_checkpoint(gc_checkpoint) {
        return false;
    }
    let Some(parsed) = parse_canonical_namespace_name(&record.namespace, &record.session_id) else {
        return false;
    };
    if !(record.retirement_checkpoint == *gc_checkpoint
        || ancestor_or_equal_of_gc(&record.retirement_checkpoint))
    {
        return false;
    }
    // An unknown value and the u32::MAX sentinel both veto deletion.
    match gc_shard_catchain_seqno(&parsed.shard) {
        Some(current) if current != u32::MAX => parsed.catchain_seqno < current,
        _ => false,
    }
}

/// The full deletion gate: a durable record (the caller passes only persisted
/// ones), on-chain obsolescence, not live, and closed for this incarnation.
/// Any uncertain input keeps the namespace.
pub fn cleanup_eligible(
    record: &PendingValidatorCleanup,
    gc_checkpoint: &BlockIdExt,
    ancestor_or_equal_of_gc: &AncestorOfGcFn,
    gc_shard_catchain_seqno: &GcShardCatchainSeqnoFn,
    is_live: &SessionIsLiveFn,
    is_closed: &SessionIsClosedFn,
) -> bool {
    if is_live(&record.session_id) || !is_closed(&record.session_id) {
        return false;
    }
    session_is_onchain_obsolete(
        record,
        gc_checkpoint,
        ancestor_or_equal_of_gc,
        gc_shard_catchain_seqno,
    )
}

/// Ancestry of one checkpoint relative to another on the accepted chain.
/// Unknown is distinct from NotAncestor and always fails closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupAncestry {
    Ancestor,
    NotAncestor,
    Unknown,
}

/// Monotonic adoption of a new GC checkpoint: only a verified strict
/// descendant of the current one, so the floor never regresses.
pub fn should_adopt_safe_checkpoint(
    current: Option<&BlockIdExt>,
    candidate: &BlockIdExt,
    ancestry_of: &dyn Fn(&BlockIdExt, &BlockIdExt) -> CleanupAncestry,
) -> bool {
    if !is_full_masterchain_checkpoint(candidate) {
        return false;
    }
    match current {
        Some(current) if is_full_masterchain_checkpoint(current) => {
            current != candidate && ancestry_of(current, candidate) == CleanupAncestry::Ancestor
        }
        _ => true,
    }
}

/// Durable key of the cleanup GC masterchain floor.
pub const GC_FLOOR_KEY: &str = "ValidatorCleanupGcMcBlockId";
const CHECKPOINT_BYTES: usize = 4 + 8 + 4 + 32 + 32;

/// Encodes a full masterchain checkpoint for the durable GC floor key.
pub fn encode_checkpoint(id: &BlockIdExt) -> Vec<u8> {
    let mut out = Vec::with_capacity(CHECKPOINT_BYTES);
    out.extend_from_slice(&id.shard().workchain_id().to_le_bytes());
    out.extend_from_slice(&id.shard().shard_prefix_with_tag().to_le_bytes());
    out.extend_from_slice(&id.seq_no().to_le_bytes());
    out.extend_from_slice(id.root_hash().as_slice());
    out.extend_from_slice(id.file_hash().as_slice());
    out
}

/// Strict decode of the GC floor; anything but a full masterchain block fails.
pub fn decode_checkpoint(value: &[u8]) -> Option<BlockIdExt> {
    if value.len() != CHECKPOINT_BYTES {
        return None;
    }
    let workchain = i32::from_le_bytes(value.get(0..4)?.try_into().ok()?);
    let shard = u64::from_le_bytes(value.get(4..12)?.try_into().ok()?);
    let seqno = u32::from_le_bytes(value.get(12..16)?.try_into().ok()?);
    let id = BlockIdExt::with_params(
        ShardIdent::with_tagged_prefix(workchain, shard).ok()?,
        seqno,
        UInt256::from_slice(value.get(16..48)?),
        UInt256::from_slice(value.get(48..80)?),
    );
    is_full_masterchain_checkpoint(&id).then_some(id)
}

/// Frontiers the GC floor must stay strictly below before it may advance,
/// as in the reference `try_advance_gc_masterchain_block`.
#[derive(Clone, Debug, Default)]
pub struct GcAdvanceInputs {
    pub last_rotation_seqno: u32,
    pub min_ref_mc_seqno: u32,
    pub last_applied_seqno: u32,
    pub last_key_block_seqno: u32,
    pub shard_client_seqno: u32,
    pub pss_keeper_seqno: u32,
    pub now: u64,
    pub state_ttl: u64,
}

/// Whether the floor at `floor_seqno` with state time `floor_utime` may
/// advance one step. Arithmetic is checked; overflow refuses.
pub fn may_advance_gc(floor_seqno: u32, floor_utime: u64, inputs: &GcAdvanceInputs) -> bool {
    let Some(behind_head) = floor_seqno.checked_add(1024) else {
        return false;
    };
    let Some(expiry) = inputs.now.checked_sub(inputs.state_ttl) else {
        return false;
    };
    inputs.last_applied_seqno > 0
        && floor_seqno < inputs.last_rotation_seqno
        && floor_seqno < inputs.min_ref_mc_seqno
        && behind_head < inputs.last_applied_seqno
        && floor_seqno < inputs.last_key_block_seqno
        && floor_seqno < inputs.shard_client_seqno
        && floor_seqno < inputs.pss_keeper_seqno
        && floor_utime < expiry
}

/// A record reserved for deletion. Both tokens are threaded back through the
/// completion, so a stale or duplicate completion is rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservedDelete {
    pub record: PendingValidatorCleanup,
    pub generation: u64,
    pub attempt_id: u64,
}

/// A request for the next page of durable records strictly after `after_key`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageRequest {
    pub after_key: String,
    pub max_keys: usize,
    pub token: u64,
}

/// One bounded slice of durable records in key order. `last_key` is the last
/// key read (valid or not); `reached_end` is true at the end of the range.
#[derive(Clone, Debug, Default)]
pub struct Page {
    pub records: Vec<PendingValidatorCleanup>,
    pub last_key: String,
    pub reached_end: bool,
}

/// Deletion-gate inputs for one pass, all bound to one durable GC snapshot.
pub struct Oracles<'a> {
    pub gc: BlockIdExt,
    pub ancestor_or_equal_of_gc: &'a AncestorOfGcFn<'a>,
    pub gc_shard_catchain_seqno: &'a GcShardCatchainSeqnoFn<'a>,
    pub is_live: &'a SessionIsLiveFn<'a>,
    /// Extra local veto beside the gate: true keeps the record.
    pub custody_veto: &'a CustodyVetoFn<'a>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PassSummary {
    pub examined: usize,
    pub reserved: usize,
    pub wrapped: bool,
    pub page_failed: bool,
    pub point_failed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InFlightState {
    Deleting,
    Erasing,
}

struct InFlight {
    session: UInt256,
    generation: u64,
    attempt_id: u64,
    state: InFlightState,
}

#[derive(Default)]
struct Pass {
    active: bool,
    token: u64,
    page_examined: bool,
    unverified: usize,
    examined: usize,
    reserved: usize,
    wrapped: bool,
    point_failed: bool,
}

/// Driver of the cleanup. The durable store is the only backlog; in memory
/// there are only open retirements awaiting their close, at most
/// `MAX_IN_FLIGHT` operations, the live sessions' incarnation tokens, the scan
/// cursor and the running pass. Records are per physical namespace: a
/// validator directory and each observer directory of one session are judged
/// and deleted independently, while group creation is deferred per session.
/// Confine it to one owner.
#[derive(Default)]
pub struct ValidatorCleanupManager {
    /// Namespace -> (session, generation) awaiting its close confirmation.
    open_retirements: BTreeMap<String, (UInt256, u64)>,
    /// Namespace deletes from reservation to the acknowledged erase.
    in_flight: BTreeMap<String, InFlight>,
    /// Session-level candidate-table cleanups from dispatch to completion.
    claims_in_flight: BTreeMap<UInt256, u64>,
    live_generation: BTreeMap<UInt256, u64>,
    next_generation: u64,
    next_attempt: u64,
    next_token: u64,
    cursor: String,
    pass: Pass,
    completed_cycles: u64,
}

impl ValidatorCleanupManager {
    pub const PAGE_SIZE: usize = 256;
    pub const DISPATCH_BUDGET: usize = 16;
    pub const MAX_IN_FLIGHT: usize = 64;
    /// The tick period: at most one pass per tick, and the pacing of retries.
    pub const TICK_SECONDS: u64 = 10;

    // u64 counters cannot be exhausted in practice; saturating keeps the type
    // total without wrapping back to an older token.
    fn next(counter: &mut u64) -> u64 {
        *counter = counter.saturating_add(1);
        *counter
    }

    /// A group for `session` is about to be created. The caller must first
    /// check `is_delete_in_flight` and defer creation while it is true. Any
    /// retirement of the session still awaiting its close is superseded.
    pub fn on_group_created(&mut self, session: &UInt256) {
        let generation = Self::next(&mut self.next_generation);
        self.live_generation.insert(session.clone(), generation);
        self.open_retirements.retain(|_, (owner, _)| owner != session);
    }

    /// The current incarnation retired; its durable record was persisted
    /// before the group may close. Returns the generation the close must
    /// report back.
    pub fn on_group_retired(&mut self, record: &PendingValidatorCleanup) -> u64 {
        if let Some(in_flight) = self.in_flight.get(&record.namespace) {
            return in_flight.generation;
        }
        let generation = match self.live_generation.remove(&record.session_id) {
            Some(generation) => generation,
            None => Self::next(&mut self.next_generation),
        };
        self.open_retirements
            .insert(record.namespace.clone(), (record.session_id.clone(), generation));
        generation
    }

    /// The retiring group confirmed close of `namespace` for `generation`; a
    /// stale ack from an older incarnation is ignored.
    pub fn on_close_confirmed(&mut self, namespace: &str, generation: u64) {
        if self.open_retirements.get(namespace).is_some_and(|(_, open)| *open == generation) {
            self.open_retirements.remove(namespace);
        }
    }

    /// True while any namespace of `session`, or its candidate-table cleanup,
    /// is between reservation and its acknowledged completion.
    pub fn is_delete_in_flight(&self, session: &UInt256) -> bool {
        self.claims_in_flight.contains_key(session)
            || self.in_flight.values().any(|entry| &entry.session == session)
    }

    /// True while this exact namespace is between reservation and its
    /// acknowledged erase.
    pub fn is_namespace_in_flight(&self, namespace: &str) -> bool {
        self.in_flight.contains_key(namespace)
    }

    /// Whether `session` still has a retirement awaiting its close, or a
    /// namespace delete in flight other than `except`.
    pub fn session_has_other_holders(&self, session: &UInt256, except: &str) -> bool {
        self.live_generation.contains_key(session)
            || self.open_retirements.values().any(|(owner, _)| owner == session)
            || self
                .in_flight
                .iter()
                .any(|(namespace, entry)| &entry.session == session && namespace != except)
    }

    /// The page to read at this tick, or nothing when a pass is running or
    /// in-flight capacity is exhausted.
    pub fn begin_tick(&mut self) -> Option<PageRequest> {
        if self.pass.active || self.operation_count() >= Self::MAX_IN_FLIGHT {
            return None;
        }
        let token = Self::next(&mut self.next_token);
        self.pass = Pass { active: true, token, ..Pass::default() };
        Some(PageRequest { after_key: self.cursor.clone(), max_keys: Self::PAGE_SIZE, token })
    }

    pub fn is_current_pass(&self, token: u64) -> bool {
        self.pass.active && token == self.pass.token && !self.pass.page_examined
    }

    /// The page read of `token` failed: the pass ends having examined nothing.
    pub fn abort_pass(&mut self, token: u64) -> Option<PassSummary> {
        if !self.is_current_pass(token) {
            return None;
        }
        self.pass = Pass::default();
        Some(PassSummary { page_failed: true, ..PassSummary::default() })
    }

    /// Runs the gate on every record not held in memory or live and returns up
    /// to the dispatch budget of eligible records to confirm by point read.
    pub fn on_page(
        &mut self,
        request: &PageRequest,
        page: &Page,
        oracles: &Oracles,
    ) -> Vec<PendingValidatorCleanup> {
        let mut candidates = Vec::new();
        if !self.is_current_pass(request.token) {
            return candidates;
        }
        let capacity = Self::MAX_IN_FLIGHT.saturating_sub(self.operation_count());
        let room = Self::DISPATCH_BUDGET.min(capacity);
        let closed = |_: &UInt256| true; // open retirements are held below
        let mut stopped = false;
        for record in &page.records {
            let held = self.held_in_memory(record);
            let eligible = !held
                && !(oracles.custody_veto)(record)
                && cleanup_eligible(
                    record,
                    &oracles.gc,
                    oracles.ancestor_or_equal_of_gc,
                    oracles.gc_shard_catchain_seqno,
                    oracles.is_live,
                    &closed,
                );
            if eligible && candidates.len() == room {
                stopped = true;
                break;
            }
            self.cursor = record_key(&record.namespace);
            self.pass.examined = self.pass.examined.saturating_add(1);
            if eligible {
                candidates.push(record.clone());
            }
        }
        if !stopped {
            if !page.last_key.is_empty() && page.last_key > self.cursor {
                self.cursor = page.last_key.clone();
            }
            self.pass.wrapped = page.reached_end;
        }
        self.pass.unverified = candidates.len();
        self.pass.page_examined = true;
        candidates
    }

    /// The point read of one candidate: its durable record now (`Ok(None)` if
    /// gone) or a read error, which is not absence. Reserves the delete only if
    /// the record is unchanged and the namespace is still not held.
    pub fn on_point_read_result(
        &mut self,
        token: u64,
        candidate: &PendingValidatorCleanup,
        current: &std::result::Result<Option<PendingValidatorCleanup>, String>,
        is_live: &SessionIsLiveFn,
    ) -> Option<ReservedDelete> {
        if !self.pass.active
            || token != self.pass.token
            || !self.pass.page_examined
            || self.pass.unverified == 0
        {
            return None;
        }
        self.pass.unverified -= 1;
        let record = match current {
            Err(_) => {
                self.pass.point_failed = true;
                return None;
            }
            Ok(record) => record,
        };
        if record.as_ref() != Some(candidate) {
            return None;
        }
        if self.held_in_memory(candidate)
            || is_live(&candidate.session_id)
            || self.operation_count() >= Self::MAX_IN_FLIGHT
        {
            return None;
        }
        let attempt_id = Self::next(&mut self.next_attempt);
        self.in_flight.insert(
            candidate.namespace.clone(),
            InFlight {
                session: candidate.session_id.clone(),
                generation: 0,
                attempt_id,
                state: InFlightState::Deleting,
            },
        );
        self.pass.reserved = self.pass.reserved.saturating_add(1);
        Some(ReservedDelete { record: candidate.clone(), generation: 0, attempt_id })
    }

    pub fn pass_verified(&self) -> bool {
        self.pass.active && self.pass.page_examined && self.pass.unverified == 0
    }

    /// Finishes the running pass; a pass that reached the end wraps the cursor.
    pub fn end_pass(&mut self) -> PassSummary {
        let summary = PassSummary {
            examined: self.pass.examined,
            reserved: self.pass.reserved,
            wrapped: self.pass.wrapped,
            page_failed: false,
            point_failed: self.pass.point_failed,
        };
        if self.pass.active && self.pass.wrapped {
            self.cursor.clear();
            self.completed_cycles = self.completed_cycles.saturating_add(1);
        }
        self.pass = Pass::default();
        summary
    }

    /// A delete attempt truly finished (never a timeout). On confirmed removal
    /// the entry waits for the durable erase; otherwise the reservation is
    /// released and the still-durable record is seen again later. Returns
    /// whether the erase must now be dispatched.
    pub fn on_delete_completed(
        &mut self,
        namespace: &str,
        generation: u64,
        attempt_id: u64,
        confirmed_gone: bool,
    ) -> bool {
        let matches = self.in_flight.get(namespace).is_some_and(|entry| {
            entry.generation == generation
                && entry.attempt_id == attempt_id
                && entry.state == InFlightState::Deleting
        });
        if !matches {
            return false;
        }
        if confirmed_gone {
            if let Some(entry) = self.in_flight.get_mut(namespace) {
                entry.state = InFlightState::Erasing;
            }
            true
        } else {
            self.in_flight.remove(namespace);
            false
        }
    }

    /// The durable erase for the attempt committed: release the reservation.
    pub fn on_erase_acknowledged(&mut self, namespace: &str, generation: u64, attempt_id: u64) {
        let matches = self.in_flight.get(namespace).is_some_and(|entry| {
            entry.generation == generation
                && entry.attempt_id == attempt_id
                && entry.state == InFlightState::Erasing
        });
        if matches {
            self.in_flight.remove(namespace);
        }
    }

    /// Confirmed deletes whose durable erase has not been acknowledged yet,
    /// as (namespace, session, generation, attempt), for an erase retry.
    pub fn erasing_entries(&self) -> Vec<(String, UInt256, u64, u64)> {
        self.in_flight
            .iter()
            .filter(|(_, entry)| entry.state == InFlightState::Erasing)
            .map(|(namespace, entry)| {
                (namespace.clone(), entry.session.clone(), entry.generation, entry.attempt_id)
            })
            .collect()
    }

    /// Reserves the session-level candidate-table cleanup of `session`; none
    /// while the session is live, has a retirement awaiting its close, or has
    /// any delete in flight.
    pub fn begin_claim(&mut self, session: &UInt256) -> Option<u64> {
        if self.live_generation.contains_key(session)
            || self.open_retirements.values().any(|(owner, _)| owner == session)
            || self.is_delete_in_flight(session)
            || self.operation_count() >= Self::MAX_IN_FLIGHT
        {
            return None;
        }
        let attempt = Self::next(&mut self.next_attempt);
        self.claims_in_flight.insert(session.clone(), attempt);
        Some(attempt)
    }

    /// The claim attempt ended (its table deleted and claim erased, or not);
    /// a stale attempt is ignored.
    pub fn end_claim(&mut self, session: &UInt256, attempt: u64) {
        if self.claims_in_flight.get(session) == Some(&attempt) {
            self.claims_in_flight.remove(session);
        }
    }

    pub fn in_first_scan(&self) -> bool {
        self.completed_cycles == 0
    }
    pub fn completed_cycles(&self) -> u64 {
        self.completed_cycles
    }
    pub fn pass_running(&self) -> bool {
        self.pass.active
    }
    /// Namespace deletes and candidate claims together: the one budget the
    /// `MAX_IN_FLIGHT` cap applies to.
    pub fn operation_count(&self) -> usize {
        self.in_flight.len().saturating_add(self.claims_in_flight.len())
    }
    pub fn in_flight_count(&self) -> usize {
        self.operation_count()
    }
    pub fn open_retirement_count(&self) -> usize {
        self.open_retirements.len()
    }
    pub fn live_session_count(&self) -> usize {
        self.live_generation.len()
    }
    pub fn cursor(&self) -> &str {
        &self.cursor
    }

    fn held_in_memory(&self, record: &PendingValidatorCleanup) -> bool {
        self.in_flight.contains_key(&record.namespace)
            || self.open_retirements.contains_key(&record.namespace)
            || self.live_generation.contains_key(&record.session_id)
    }
}

#[cfg(test)]
#[path = "tests/test_validator_cleanup.rs"]
mod tests;
