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
/// it retired, and the exact namespace to reclaim once retirement is proven.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingValidatorCleanup {
    pub session_id: UInt256,
    pub retirement_checkpoint: BlockIdExt,
    pub namespace: String,
}

const RECORD_VERSION: u8 = 1;
// version(1) + session(32) + workchain(4) + shard(8) + seqno(4) + root(32) + file(32)
const FIXED_PREFIX: usize = 1 + 32 + 4 + 8 + 4 + 32 + 32;
/// Upper bound for one encoded record; the longest layout is an observer name.
pub const MAX_RECORD_BYTES: usize = FIXED_PREFIX + 512;

/// Key prefix for records; each record lives under its own key so retirement
/// and erase are single-key writes. The prefix ends in '.', and the lowercase
/// session hex after it always sorts above '.'.
pub const RECORD_KEY_PREFIX: &str = "ValidatorConsensusCleanupV1.";

pub fn record_key(session_id: &UInt256) -> String {
    format!("{RECORD_KEY_PREFIX}{}", session_id.to_hex_string())
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
    Ok(PendingValidatorCleanup {
        session_id: session_id.clone(),
        retirement_checkpoint: retirement_checkpoint.clone(),
        namespace,
    })
}

/// Deterministic little-endian encoding, versioned so an old record is
/// rejected rather than misread.
pub fn encode_record(record: &PendingValidatorCleanup) -> Vec<u8> {
    let id = &record.retirement_checkpoint;
    let mut out = Vec::with_capacity(FIXED_PREFIX + record.namespace.len());
    out.push(RECORD_VERSION);
    out.extend_from_slice(record.session_id.as_slice());
    out.extend_from_slice(&id.shard().workchain_id().to_le_bytes());
    out.extend_from_slice(&id.shard().shard_prefix_with_tag().to_le_bytes());
    out.extend_from_slice(&id.seq_no().to_le_bytes());
    out.extend_from_slice(id.root_hash().as_slice());
    out.extend_from_slice(id.file_hash().as_slice());
    out.extend_from_slice(record.namespace.as_bytes());
    out
}

/// Strict decode. Anything inconsistent yields nothing: a malformed safety
/// record never grants authority to delete (at worst a directory leaks).
pub fn decode_record(value: &[u8]) -> Option<PendingValidatorCleanup> {
    if value.len() < FIXED_PREFIX || value.len() > MAX_RECORD_BYTES {
        return None;
    }
    if *value.first()? != RECORD_VERSION {
        return None;
    }
    let session_id = UInt256::from_slice(value.get(1..33)?);
    let workchain = i32::from_le_bytes(value.get(33..37)?.try_into().ok()?);
    let shard = u64::from_le_bytes(value.get(37..45)?.try_into().ok()?);
    let seqno = u32::from_le_bytes(value.get(45..49)?.try_into().ok()?);
    let root = UInt256::from_slice(value.get(49..81)?);
    let file = UInt256::from_slice(value.get(81..113)?);
    let namespace = std::str::from_utf8(value.get(FIXED_PREFIX..)?).ok()?.to_owned();
    let checkpoint = BlockIdExt::with_params(
        ShardIdent::with_tagged_prefix(workchain, shard).ok()?,
        seqno,
        root,
        file,
    );
    if !is_full_masterchain_checkpoint(&checkpoint) {
        return None;
    }
    parse_canonical_namespace_name(&namespace, &session_id)?;
    Some(PendingValidatorCleanup { session_id, retirement_checkpoint: checkpoint, namespace })
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
    match gc_shard_catchain_seqno(&parsed.shard) {
        Some(current) => parsed.catchain_seqno < current,
        None => false,
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
/// cursor and the running pass. Confine it to one owner.
#[derive(Default)]
pub struct ValidatorCleanupManager {
    open_retirements: BTreeMap<UInt256, u64>,
    in_flight: BTreeMap<UInt256, InFlight>,
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
    /// check `is_delete_in_flight` and defer creation while it is true. A
    /// retirement still awaiting its close is superseded.
    pub fn on_group_created(&mut self, session: &UInt256) {
        let generation = Self::next(&mut self.next_generation);
        self.live_generation.insert(session.clone(), generation);
        self.open_retirements.remove(session);
    }

    /// The current incarnation retired; its durable record was persisted
    /// before the group may close. Returns the generation the close must
    /// report back.
    pub fn on_group_retired(&mut self, record: &PendingValidatorCleanup) -> u64 {
        let session = &record.session_id;
        if let Some(in_flight) = self.in_flight.get(session) {
            return in_flight.generation;
        }
        let generation = match self.live_generation.remove(session) {
            Some(generation) => generation,
            None => Self::next(&mut self.next_generation),
        };
        self.open_retirements.insert(session.clone(), generation);
        generation
    }

    /// The retiring group confirmed close for `generation`; a stale ack from
    /// an older incarnation is ignored.
    pub fn on_close_confirmed(&mut self, session: &UInt256, generation: u64) {
        if self.open_retirements.get(session) == Some(&generation) {
            self.open_retirements.remove(session);
        }
    }

    /// True from reservation until the durable erase is acknowledged.
    pub fn is_delete_in_flight(&self, session: &UInt256) -> bool {
        self.in_flight.contains_key(session)
    }

    /// The page to read at this tick, or nothing when a pass is running or
    /// in-flight capacity is exhausted.
    pub fn begin_tick(&mut self) -> Option<PageRequest> {
        if self.pass.active || self.in_flight.len() >= Self::MAX_IN_FLIGHT {
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
        let capacity = Self::MAX_IN_FLIGHT.saturating_sub(self.in_flight.len());
        let room = Self::DISPATCH_BUDGET.min(capacity);
        let closed = |_: &UInt256| true; // open retirements are held below
        let mut stopped = false;
        for record in &page.records {
            let held = self.held_in_memory(&record.session_id);
            let eligible = !held
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
            self.cursor = record_key(&record.session_id);
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
    /// the record is unchanged and the session is still not held.
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
        let session = &candidate.session_id;
        if self.held_in_memory(session)
            || is_live(session)
            || self.in_flight.len() >= Self::MAX_IN_FLIGHT
        {
            return None;
        }
        let attempt_id = Self::next(&mut self.next_attempt);
        self.in_flight.insert(
            session.clone(),
            InFlight { generation: 0, attempt_id, state: InFlightState::Deleting },
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
        session: &UInt256,
        generation: u64,
        attempt_id: u64,
        confirmed_gone: bool,
    ) -> bool {
        let matches = self.in_flight.get(session).is_some_and(|entry| {
            entry.generation == generation
                && entry.attempt_id == attempt_id
                && entry.state == InFlightState::Deleting
        });
        if !matches {
            return false;
        }
        if confirmed_gone {
            if let Some(entry) = self.in_flight.get_mut(session) {
                entry.state = InFlightState::Erasing;
            }
            true
        } else {
            self.in_flight.remove(session);
            false
        }
    }

    /// The durable erase for the attempt committed: release the reservation.
    pub fn on_erase_acknowledged(&mut self, session: &UInt256, generation: u64, attempt_id: u64) {
        let matches = self.in_flight.get(session).is_some_and(|entry| {
            entry.generation == generation
                && entry.attempt_id == attempt_id
                && entry.state == InFlightState::Erasing
        });
        if matches {
            self.in_flight.remove(session);
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
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
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

    fn held_in_memory(&self, session: &UInt256) -> bool {
        self.in_flight.contains_key(session)
            || self.open_retirements.contains_key(session)
            || self.live_generation.contains_key(session)
    }
}

#[cfg(test)]
#[path = "tests/test_validator_cleanup.rs"]
mod tests;
