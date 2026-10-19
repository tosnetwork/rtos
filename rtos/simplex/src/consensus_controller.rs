/*
 * RTOS project modifications (2026-10-10): naming and durable own-decision journal integration.
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! # `ConsensusController` entity
//!
//! Per-session consensus finalization controller. Owns the
//! finalization-journal state previously inlined on `SessionProcessor` plus
//! the FSM finalization/certificate event handlers and the recursive
//! parent-chain finalization walk.
//!
//! ## Owned state (the finalization journal)
//!
//! - `finalized_head_seqno` / `finalized_head_slot` / `finalized_head_block_id`
//!   / `finalized_head_before_split` — the locally materialized finalized head
//!   cursor (parent context for empty-block generation + validation shortcuts).
//! - `before_split_by_block_id` — observed `before_split` flags for non-empty
//!   block ids, the empty-block policy source.
//! - `last_consensus_finalized_seqno` — producer-side highest finalized seqno.
//! - `finalized_blocks` — blocks whose finalized state is already materialized
//!   locally (dedup of repeat events / late body arrivals).
//! - `finalized_pending_body` — finalized blocks (FinalCert observed) whose
//!   candidate body has not yet arrived; materialization is deferred.
//! - `finalized_delivery_sent` / `finalized_delivery_sent_seqno` — the
//!   at-most-once finalized-callback dedup (per candidate id and per seqno).
//!
//! Hosts the [`FinalizedEntry`] / [`FinalizedSeqnoRecord`] inner types.
//!
//! ## Finalization pipeline
//!
//! The controller owns the certificate-observed and finalization-driven
//! handlers dispatched by `SessionProcessor::process_simplex_events` (which
//! stays the event pump):
//!
//! - [`ConsensusController::handle_notarization_reached`] /
//!   [`ConsensusController::handle_skip_certificate_reached`] /
//!   [`ConsensusController::handle_finalization_reached`] react to certificate
//!   observation: record milestones, request missing bodies, emit
//!   candidate-observed, and persist+relay the cert (the persist/relay/standstill
//!   IO is the synchronous [`ConsensusBackend::persist_notar_cert_then_relay`] /
//!   `persist_skip_cert_then_relay` / `persist_final_cert_then_relay` effect,
//!   which registers the durability wait on the SXMAIN async-DB registry — the
//!   continuation stays `SessionProcessor`-side).
//! - [`ConsensusController::handle_block_finalized`] records the trigger in
//!   `finalized_pending_body` and kicks the recursive walk.
//! - [`ConsensusController::try_finalize_recursive_chain`] /
//!   [`ConsensusController::try_emit_recursive_finalized_callback`] /
//!   [`ConsensusController::maybe_apply_finalized_state`] are the recursive
//!   parent-chain walk:
//!   they apply local finalized state (persist via
//!   [`ConsensusBackend::persist_finalized_block`], advance the accepted normal
//!   head, update the head cursor) and emit the at-most-once
//!   `on_block_finalized` callback through the owned `callbacks`.
//!
//! ```text
//! process_simplex_events  (pump; stays on SessionProcessor)
//!   ├─ NotarizationReached  ─▶ handle_notarization_reached  ─▶ persist_notar_cert_then_relay
//!   ├─ SkipCertificateReached ▶ handle_skip_certificate_reached ▶ persist_skip_cert_then_relay
//!   ├─ FinalizationReached  ─▶ handle_finalization_reached  ─▶ persist_final_cert_then_relay
//!   └─ BlockFinalized       ─▶ handle_block_finalized
//!                                 │  finalized_pending_body.insert
//!                                 ▼
//!                       retry_pending_recursive_finalization_for
//!                                 ▼
//!                       try_finalize_recursive_chain (walk parents)
//!                                 ├─ maybe_apply_finalized_state ─▶ persist_finalized_block
//!                                 └─ try_emit_recursive_finalized_callback ─▶ notify_block_finalized
//! ```
//!
//! ## Boundary
//!
//! `ConsensusController` owns the finalization-journal state + finalization/cert
//! handlers, the MC applied-top pipeline, vote/certificate **ingress** (`on_vote`
//! / `on_certificate` + `misbehavior_reports`), and the consensus-meaningful
//! **outbound** action (`broadcast_vote_after_persist`: sign, persist, send). It
//! does NOT drive collation or candidate validation, and `SimplexState` stays
//! owned by `SessionProcessor` (the shared kernel, reached via
//! `simplex_state{,_mut}`). The `broadcast_vote` durability-wait shell also stays
//! on `SessionProcessor` because it crosses the `DatabaseController` async-DB
//! registry, re-entering the controller once the prerequisite is durable. The
//! `SessionProcessor`-owned reads (FSM state, candidate book, runtime slot flags)
//! and `&mut self` effects (cert/finalized-block persist+relay, slot reset, peer
//! candidate requests, vote persist + send) are reached through the borrowing
//! [`ConsensusBackend`] seam, built per call by
//! `SessionProcessor::with_consensus_backend`, mirroring `CollationBackend` /
//! `ValidationBackend`.
//!
//! The immutable per-session `Arc<SessionDescription>`, the shared
//! `Arc<SessionCallbacks>`, and the `Arc<SessionTelemetry>` are held directly
//! on the controller (cloned from the same `Arc`s `SessionProcessor` holds), so
//! session id / shard / weights / timing reads, finalized-callback dispatch,
//! and metric recording need no per-call threading.

use crate::{
    block::{CandidateId as BlockCandidateId, RawCandidateId, SlotIndex, ValidatorIndex},
    candidate_book::{CandidateBook, ReceivedCandidate, EMPTY_CHAIN_WARN_DEPTH},
    database::{FinalizedBlockRecord, VoteRecord},
    finality_recovery::ExpectedFinalityOutput,
    misbehavior::{MisbehaviorReport, VoteResult},
    receiver::StandstillCertificateType,
    session_callbacks::SessionCallbacks,
    session_description::SessionDescription,
    session_processor::ROUND_DEBUG_PERIOD,
    session_runtime::SessionRuntime,
    session_telemetry::SessionTelemetry,
    simplex_state::{
        BlockFinalizedEvent, FinalizationReachedEvent, NotarizationReachedEvent, SimplexState,
        SkipCertificateReachedEvent, Vote,
    },
    trace_collector::TraceCollector,
    utils::{extract_vote_and_signature, threshold_66, verify_vote_signature},
    BlockCandidatePriority, BlockHash, BlockPayloadPtr, BlockSourceInfo, PublicKeyHash,
    RawVoteData, SessionId, SIMPLEX_ROUNDLESS,
};
use consensus_common::{check_execution_time, instrument, CandidateObservedFlags};
use rtos_api::ton::consensus::simplex::{
    vote::Vote as TlVote, Certificate, UnsignedVote, Vote as TlVoteBoxed,
};
use rtos_block::{
    sha256_digest, BlockIdExt, BlockSignaturesPure, BlockSignaturesSimplex, BlockSignaturesVariant,
    CryptoSignature, CryptoSignaturePair, Result, UInt256, ValidatorBaseInfo,
};
use std::{
    collections::{HashMap, HashSet},
    sync::{atomic::Ordering, Arc},
    time::{Duration, SystemTime},
};

/// Finalization journal entry.
///
/// Records that a FinalCert was observed for (slot, hash), but local finalized
/// state has not been materialized yet because the candidate body is still
/// missing.
#[derive(Clone)]
pub(crate) struct FinalizedEntry {
    /// The finalization event from `SimplexState`.
    event: BlockFinalizedEvent,
    /// Certificate retention completed for this in-flight finalization. As in
    /// C++ SaveCertificate -> FinalizationObserved, parent resolution retries
    /// must not repeat the already successful persistence phase.
    intent_retained: bool,
    /// Source replay must observe its own node handoff before trusting any
    /// startup callback cache. Keep successful parents through async retries.
    acknowledged_source_candidates: HashSet<RawCandidateId>,
    // Keep this walk's dependencies in its output manifest across retries,
    // including empty candidates materialized while waiting for a child ACK.
    walked_candidates: HashSet<RawCandidateId>,
    /// Complete output plan from a successful dependency resolution in this
    /// process. Reusing a materialized ancestor must retain its full output
    /// suffix, including Approval records still owned by this source.
    resolved_output_plan: Vec<(RawCandidateId, crate::finality_recovery::ExpectedFinalityOutput)>,
    /// Process-local C++ InFlight continuation, rebuilt from evidence after restart.
    continuation: Option<FinalityContinuation>,
    /// Exact preexisting sealed obligations, bound to this retained source.
    /// They only require more work; they never seed accepted receipts.
    sealed_output_requirements: Option<Vec<crate::finality_recovery::ExpectedFinalityOutput>>,
    /// Time when finalization was first observed (for timeout / diagnostics).
    finalized_at: SystemTime,
}

/// Immutable metadata captured only after complete dependency resolution.
#[derive(Clone)]
struct FinalityPlanStep {
    id: RawCandidateId,
    block: BlockIdExt,
    parent: Option<RawCandidateId>,
    is_empty: bool,
    has_final_cert: bool,
    source: Option<UInt256>,
}
#[derive(Clone)]
struct FinalityContinuation {
    steps: Vec<FinalityPlanStep>,
    next: usize,
    outputs: Vec<ExpectedFinalityOutput>,
    trigger_hash_data: Vec<u8>,
    requirements: Option<Vec<ExpectedFinalityOutput>>,
}

/// Value of `finalized_delivery_sent_seqno`: the delivered `BlockIdExt` plus the
/// originating slot. The slot is kept so this map can later be pruned together
/// with the retained candidate metadata; until then, keeping this map
/// session-long is what prevents old retained `received_candidates` from
/// re-emitting callbacks.
#[derive(Debug, Clone)]
struct FinalizedSeqnoRecord {
    is_final: bool,
    slot: SlotIndex,
    block_id: BlockIdExt,
}

/// One synchronous dependency-resolution pass, never an acceptance receipt.
/// C++ InFlight shares the parent operation and its already-derived identity.
#[derive(Default)]
struct FinalityRetryPass {
    pending_ancestors: HashSet<RawCandidateId>,
    outputs: HashMap<(BlockIdExt, bool, UInt256), ExpectedFinalityOutput>,
}
impl FinalityRetryPass {
    fn output(&mut self, block: &BlockIdExt, is_final: bool, source: &UInt256) -> ExpectedFinalityOutput {
        let key = (block.clone(), is_final, source.clone());
        if let Some(output) = self.outputs.get(&key) {
            return output.clone();
        }
        let output = ExpectedFinalityOutput::new(block, is_final, source);
        // This is a memory bound on the optimization, not a legal chain limit.
        // Larger passes continue through the same constructor without caching.
        if self.outputs.len() < 1024 {
            self.outputs.insert(key, output.clone());
        }
        output
    }
}

/// How many attempted, unresolved finalizations the group holds before it stops
/// producing. Nothing is dropped to stay under it: reaching it means conversion is
/// not keeping up, and the response is that the round pauses until it clears.
pub(crate) const DEFAULT_PENDING_FINALIZATIONS_MAX: usize = 16;

/// Environment override for [`DEFAULT_PENDING_FINALIZATIONS_MAX`].
pub(crate) const PENDING_FINALIZATIONS_MAX_ENV: &str = "TOS_SIMPLEX_PENDING_FINALIZATIONS_MAX";

/// Parse the pending-finalization limit override: a positive integer, anything
/// else falls back to the default with a warning.
pub(crate) fn parse_pending_finalizations_max(value: Option<&str>) -> usize {
    let Some(value) = value else {
        return DEFAULT_PENDING_FINALIZATIONS_MAX;
    };
    match value.trim().parse::<usize>() {
        Ok(parsed) if parsed > 0 => parsed,
        _ => {
            log::warn!(
                "Simplex finalization: ignoring invalid {PENDING_FINALIZATIONS_MAX_ENV}={value}"
            );
            DEFAULT_PENDING_FINALIZATIONS_MAX
        }
    }
}

/// Why one candidate's finalization attempt did not finish.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FinalizationFailure {
    /// A dependency that was not ready yet (a body, a notarization certificate,
    /// a node acknowledgement, a store that refused the write for now). A later
    /// attempt can find it gone, so the candidate stays queued.
    Retryable(String),
    /// Retrying cannot mend it (signature-set conversion failure, a parent
    /// cycle). The candidate is kept, never retried, and its dependents fail with it.
    Permanent(String),
    /// The session is stopping. Nothing is retried and nothing is reported.
    Cancelled,
}

/// What has happened to one candidate's finalization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CandidateFinalization {
    /// No attempt is running; one may have failed for a reason that may not recur.
    Idle,
    /// An attempt is running in the current pass.
    InFlight,
    /// The candidate is finalized.
    Finalized,
    /// The conversion failed in a way retrying cannot mend. Kept and counted.
    StalledPermanently(String),
}

#[derive(Clone, Debug)]
struct CandidateFinalizationEntry {
    state: CandidateFinalization,
    attempts: u32,
}

impl CandidateFinalizationEntry {
    /// Held un-converted: stopped for good, or attempted and not finished.
    fn is_pending(&self) -> bool {
        match self.state {
            CandidateFinalization::StalledPermanently(_) => true,
            CandidateFinalization::Idle | CandidateFinalization::InFlight => self.attempts > 0,
            CandidateFinalization::Finalized => false,
        }
    }

    fn is_stalled(&self) -> bool {
        matches!(self.state, CandidateFinalization::StalledPermanently(_))
    }
}

/// The candidates one trigger's finalization attempted in one pass and how each
/// own step ended. A candidate's attempt completes only after its parent's, and
/// a parent's failure is its children's failure, so outcomes are applied
/// ancestor first.
#[derive(Default)]
struct ChainAttempt {
    /// Attempted candidates, trigger first, each parent after its child.
    chain: Vec<RawCandidateId>,
    /// Result of each candidate's own step, when it was reached.
    own: HashMap<RawCandidateId, std::result::Result<(), FinalizationFailure>>,
}

impl ChainAttempt {
    fn succeed(&mut self, id: &RawCandidateId) {
        self.own.entry(id.clone()).or_insert(Ok(()));
    }

    fn fail(&mut self, id: &RawCandidateId, failure: FinalizationFailure) {
        self.own.insert(id.clone(), Err(failure));
    }
}

/// Outcome of handing one finalized block to the node.
enum FinalityHandoff {
    Delivered,
    Pending,
    Permanent(String),
}

/// Session-owned reads/effects the finalization pipeline needs but cannot reach
/// from `&mut ConsensusController` alone.
///
/// This is the controller's borrowing backend view: a drain-scoped handle built
/// fresh from `&mut SessionProcessor` by `session_processor`'s
/// `with_consensus_backend` split-borrow immediately before a handler / walk
/// runs, then dropped (RAII). Because it is rebuilt per call, every read is
/// current — no captured snapshot, no shared mutable handle. The controller's
/// own state lives on `&mut Self`; everything genuinely owned by
/// `SessionProcessor` is reached only through this trait.
///
/// Reads available from handles the controller already holds are NOT duplicated
/// here: session id / shard / weights / timing come from the owned
/// `description`, and counters from the owned `telemetry`. The applied-top floor
/// and accepted-normal-head cursor are now controller-owned state, so what
/// remains are the FSM / candidate-book reads and the
/// `SessionProcessor`-mediated effects below.
///
/// ## Effect timing
///
/// The `persist_*` effects run
/// **synchronously** in the production adapter (the cert/finalized-block
/// persist registers a wait on the SXMAIN async-DB registry exactly as the
/// pre-refactor in-line code did, preserving the persist→relay ordering and the
/// `WaitFor*` semantics). The `request_candidate` and `reset_slot_state` effects
/// are **deferred** — they need `&mut SessionProcessor` machinery the borrowing
/// adapter cannot provide, so they bounce a closure onto SXMAIN (mirroring
/// `CollationBackend::request_parent_candidate` /
/// `ValidationBackend::request_candidate`). `reset_slot_state` re-enters
/// `self.consensus.prune_below`, so it must run after the borrow scope ends;
/// it is ancient-slot GC, so the one-turn deferral is behaviour-neutral.
pub(crate) trait ConsensusBackend {
    /// Borrow the consensus FSM state (notarize-cert lookup, slot-progressed
    /// check) for the recursive walk.
    fn simplex_state(&self) -> &SimplexState;

    /// Mutably borrow the consensus FSM state for vote/certificate ingress:
    /// `SimplexState::on_vote` and `set_{notarize,skip,finalize}_certificate`.
    /// `SimplexState` itself stays owned by `SessionProcessor` (the shared
    /// kernel); the controller reaches it only for the duration of a single
    /// `with_consensus_backend` borrow scope.
    fn simplex_state_mut(&mut self) -> &mut SimplexState;

    /// Borrow the received-candidate book (body/metadata holder) for the walk.
    fn candidate_book(&self) -> &CandidateBook;

    /// Borrow the per-session runtime (per-slot started-at + first-finalized
    /// latency flags read by `maybe_apply_finalized_state`).
    fn runtime(&self) -> &SessionRuntime;

    /// Mutably borrow the runtime to set the per-slot first-candidate-finalized
    /// latency flag, and lower the wake horizon from
    /// [`ConsensusController::set_mc_finalized_block`].
    fn runtime_mut(&mut self) -> &mut SessionRuntime;

    /// Request a missing candidate body/metadata from peers through the shared
    /// `SessionProcessor::request_candidate` throttle map. Bounces a closure
    /// onto SXMAIN (the fetch needs `&mut SessionProcessor`).
    fn request_candidate(&self, slot: SlotIndex, hash: UInt256, delay: Option<Duration>);

    /// FinalCert ancestry can include notarized skipped slots. Resolve their
    /// contents without the ordinary obsolete-vote repair filter.
    fn request_candidate_for_finality(&self, slot: SlotIndex, hash: UInt256, delay: Option<Duration>) {
        self.request_candidate(slot,hash,delay);
    }

    /// Reset per-slot state after a slot is materially finalized (FSM/receiver
    /// GC + precollation cleanup). Bounces onto SXMAIN: the underlying
    /// `SessionProcessor::reset_slot_state` re-enters `self.consensus`
    /// (`cleanup_old_candidates` → `ConsensusController::prune_below`), so it
    /// must run after the controller borrow scope ends.
    fn reset_slot_state(&self, slot: SlotIndex);

    /// Persist the notarization certificate then (after durability) cache the
    /// VoteSignatureSet, relay the full cert, and cache it for standstill.
    /// Synchronous registration on the SXMAIN async-DB registry; the relay
    /// continuation runs `SessionProcessor`-side post-durability.
    fn persist_notar_cert_then_relay(&mut self, event: &NotarizationReachedEvent) {
        self.persist_notar_cert(event, true);
    }

    /// Startup replay saves newly reconstructed certificates without gossip.
    fn persist_notar_cert(&mut self, event: &NotarizationReachedEvent, relay: bool);

    /// Persist the skip certificate then (after durability) relay + cache it
    /// for standstill. See [`Self::persist_notar_cert_then_relay`].
    fn persist_skip_cert_then_relay(&mut self, event: &SkipCertificateReachedEvent) {
        self.persist_skip_cert(event, true);
    }

    fn persist_skip_cert(&mut self, event: &SkipCertificateReachedEvent, relay: bool);

    /// Persist the finalization certificate then (after durability) relay,
    /// cache per-slot + last-final, and update standstill tracking. See
    /// [`Self::persist_notar_cert_then_relay`].
    fn persist_final_cert_then_relay(&mut self, event: &FinalizationReachedEvent) {
        self.persist_final_cert(event, true);
    }

    /// Startup replay shares the save completion without re-gossiping its
    /// historical certificate (C++ suppress_certificate_broadcast_).
    fn persist_final_cert(&mut self, event: &FinalizationReachedEvent, relay: bool);

    /// Persist a finalized-block record for restart recovery. On masterchain
    /// the write is registered with the SXMAIN async-DB registry (logging
    /// continuation); on shardchains it is a fire-and-forget queued write.
    ///
    /// Returns `false` only when the synchronous registration failed
    /// (`save_finalized_block[_async]` returned `Err` immediately) — the caller
    /// then leaves the trigger queued in `finalized_pending_body`.
    fn persist_finalized_block(&mut self, record: FinalizedBlockRecord) -> bool;

    /// Persist an applied incoming vote to the session DB (fire-and-forget).
    /// Mirrors C++ `store_vote_to_db(message.data, source).detach()` after
    /// `handle_vote(...)` returns true: the async write handle is discarded and
    /// only an immediate `Err` is surfaced so [`ConsensusController::on_vote`]
    /// can bump the error counter.
    fn save_incoming_vote(&self, record: &VoteRecord) -> Result<()>;

    /// Notify the receiver's standstill tracker that a certificate of `kind`
    /// was accepted for `slot` (forwards to `Receiver::notify_certificate_accepted`).
    /// Must be called only after the matching `SimplexState::set_*_certificate`
    /// returned `Ok(true)` (newly stored), matching the pre-refactor in-line order.
    fn notify_certificate_accepted(&self, slot: u32, kind: StandstillCertificateType);

    /// Temporarily ban a peer whose certificate failed signature / weight
    /// verification (forwards to `Receiver::ban_source_for_bad_signature`,
    /// C++ `PoolImpl::ban`), so repeated forged traffic cannot starve the
    /// receiver/processor pipeline.
    fn ban_source_for_bad_signature(&self, source_idx: u32);
    fn ban_peer_for_bad_signature(&self, peer: PublicKeyHash);

    /// Broadcast a locally produced, session-signed vote to all validators
    /// (forwards to `Receiver::send_vote`, which serializes the TL vote,
    /// fans it out, and loops it back through the listener for FSM accounting).
    /// Mirrors C++ `pool.cpp::handle(BroadcastVote)` publishing
    /// `OutgoingProtocolMessage`.
    fn send_vote(&self, signed_vote: TlVote);
}

/// Per-session consensus finalization controller.
///
/// Owned by [`SessionProcessor`](crate::session_processor::SessionProcessor) as
/// `self.consensus`; all access goes through the accessor methods declared
/// below — internal fields stay non-`pub` so the boundary is enforceable.
pub(crate) struct ConsensusController {
    /// Callback-delivery aspect, shared with `SessionProcessor` and
    /// `SessionImpl` as `Arc<SessionCallbacks>`. Held directly so the
    /// controller can dispatch `notify_block_finalized` / `notify_candidate_observed`
    /// without routing the call back through `SessionProcessor`.
    callbacks: Arc<SessionCallbacks>,
    /// Immutable per-session configuration handle, the same `Arc` held by
    /// `SessionProcessor` / `SessionRuntime`. Held directly for session id /
    /// shard / weights / source keys / timing reads.
    description: Arc<SessionDescription>,
    /// Per-session telemetry aspect, the same `Arc` held by `SessionProcessor`.
    /// Held directly so finalization paths record milestones / latencies /
    /// counters without threading a `&SessionTelemetry`. Interior-mutable.
    telemetry: Arc<SessionTelemetry>,

    /// Highest finalized non-empty block seqno materialized locally.
    finalized_head_seqno: Option<u32>,
    /// Slot of the latest locally materialized finalized head.
    finalized_head_slot: Option<SlotIndex>,
    /// Last finalized non-empty block id (parent for empty blocks).
    finalized_head_block_id: Option<BlockIdExt>,
    /// Last finalized head block's `before_split` flag (split/merge fallback).
    finalized_head_before_split: bool,
    /// Observed `before_split` values for non-empty block ids (empty-block
    /// policy source).
    before_split_by_block_id: HashMap<BlockIdExt, bool>,
    /// Producer-side highest finalized seqno tracked for this session.
    last_consensus_finalized_seqno: Option<u32>,
    /// Blocks whose finalized state has already been materialized locally
    /// (dedup of repeat finalization events + late body arrivals).
    finalized_blocks: HashSet<RawCandidateId>,
    finalized_final_proofs: HashSet<RawCandidateId>,
    /// Finalized blocks (FinalCert observed) still waiting for candidate body
    /// arrival; materialization is deferred until the body arrives.
    finalized_pending_body: HashMap<RawCandidateId, FinalizedEntry>,
    /// Only cryptographically verified pending source FinalCerts are registered
    /// by SessionProcessor; this changes delivery scheduling, not authority.
    replayed_source_finalizations: HashSet<RawCandidateId>,
    /// Dedup set for finalized delivery: emit at most once per finalized
    /// candidate id.
    finalized_delivery_sent: HashSet<RawCandidateId>,
    /// Seqno-level finalized callback tracking (at most one callback per seqno
    /// for a distinct block; idempotent for the same block id).
    finalized_delivery_sent_seqno: HashMap<u32, FinalizedSeqnoRecord>,
    /// Ancestor Approval handoffs actually accepted by the node in this process.
    /// Never seeded from startup markers, and never substitutes for a trigger's
    /// own FinalCert source handoff. Shared replays join this completed result.
    acknowledged_ancestor_approvals: HashSet<RawCandidateId>,

    /*
        ====================================================================
        Masterchain applied-top tracking

        The validator-manager finalization pipeline. Seeded from
        `initial_block_seqno - 1` and advanced by `set_mc_finalized_block`
        (manager applied-top notifications), restart recovery, and finalized
        non-empty blocks (the recursive walk). Mirrors the C++
        `block-producer.cpp` / `block-validator.cpp` applied-top handling.
        ====================================================================
    */
    /// Last MC-registered applied-top seqno for this shard session.
    ///
    /// The recursive-walk parent-climb floor and the shard callback-emission
    /// gate (`applied_floor`), and the shardchain empty-block lag input
    /// (`CollationController::should_generate_empty_block`). Kept monotonic.
    last_mc_finalized_seqno: Option<u32>,
    /// Seqno fallback for the accepted normal head used by MC validation
    /// ordering. Seeded from `initial_block_seqno - 1`, then advanced by
    /// applied-top notifications, restart recovery, and finalized non-empty
    /// blocks.
    accepted_normal_head_seqno: u32,
    /// Exact accepted normal head when known (mirrors the C++
    /// `last_accepted_block_` semantics closely enough to reject stale
    /// same-seqno forks once an exact `BlockIdExt` has been observed). Read by
    /// validation parent-tip resolution.
    accepted_normal_head_block_id: Option<BlockIdExt>,

    /// Misbehavior proofs collected from vote ingress (`SimplexState::on_vote`
    /// returning [`VoteResult::Misbehavior`]). Write-only accumulator today —
    /// kept for the future ValidatorGroup slashing/reporting hook.
    misbehavior_reports: Vec<MisbehaviorReport>,

    /// Trace collector for recording vote / certificate / finalization
    /// lifecycle events. `None` when stats collection is disabled — every
    /// hot-path call site is guarded with `if let Some(tc) =
    /// &self.trace_collector`. Cheap-to-clone handle cloned from
    /// `SessionProcessor` at construction
    trace_collector: Option<TraceCollector>,

    /*
        Finalization backpressure

        One entry per candidate whose finalization was attempted. Unresolved
        entries are never dropped; finalized ones are released with old slots.
    */
    finalization_status: HashMap<RawCandidateId, CandidateFinalizationEntry>,
    /// Entries that are `is_pending()`, kept equal to a full recount.
    pending_finalizations: usize,
    /// Entries stopped for a reason retrying cannot mend.
    stalled_finalizations: usize,
    /// Whether the group has been told to stop producing.
    backlog_over_limit: bool,
    pending_finalizations_max: usize,
    /// A permanent handoff failure reported by the last emission attempt.
    handoff_failure: Option<(RawCandidateId, String)>,
    /// Every backlog flip, in order (over_limit, pending), for tests.
    #[cfg(test)]
    backlog_transitions: Vec<(bool, usize)>,
    /// Handoff failures to inject, as the C++ state resolver's fault injection
    /// does for its finalization attempts: (retryable, permanent).
    #[cfg(test)]
    injected_handoff_failures: std::cell::Cell<(usize, usize)>,
}

// ======================================================================
// Construction & handles
// ======================================================================
// Build the controller and read its shared session handles.
impl ConsensusController {
    /// Construct a fresh consensus controller.
    ///
    /// `callbacks` / `description` / `telemetry` are cheap-to-clone shared
    /// handles (`Arc`) cloned from `SessionProcessor` at construction.
    ///
    /// `finalized_head_seqno` / `last_consensus_finalized_seqno` /
    /// `last_mc_finalized_seqno` / `accepted_normal_head_seqno` are seeded from
    /// `initial_block_seqno - 1` (the block before session start is treated as
    /// the finalized head + applied top), matching the pre-refactor
    /// `SessionProcessor::new`.
    pub(crate) fn new(
        callbacks: Arc<SessionCallbacks>,
        description: Arc<SessionDescription>,
        telemetry: Arc<SessionTelemetry>,
        finalized_head_seqno: Option<u32>,
        last_consensus_finalized_seqno: Option<u32>,
        last_mc_finalized_seqno: Option<u32>,
        accepted_normal_head_seqno: u32,
        trace_collector: Option<TraceCollector>,
    ) -> Self {
        Self {
            callbacks,
            description,
            telemetry,
            finalized_head_seqno,
            finalized_head_slot: None,
            finalized_head_block_id: None,
            finalized_head_before_split: false,
            before_split_by_block_id: HashMap::new(),
            last_consensus_finalized_seqno,
            finalized_blocks: HashSet::new(),
            finalized_final_proofs: HashSet::new(),
            finalized_pending_body: HashMap::new(),
            replayed_source_finalizations: HashSet::new(),
            finalized_delivery_sent: HashSet::new(),
            finalized_delivery_sent_seqno: HashMap::new(),
            acknowledged_ancestor_approvals: HashSet::new(),
            last_mc_finalized_seqno,
            accepted_normal_head_seqno,
            accepted_normal_head_block_id: None,
            misbehavior_reports: Vec::new(),
            trace_collector,
            finalization_status: HashMap::new(),
            pending_finalizations: 0,
            stalled_finalizations: 0,
            backlog_over_limit: false,
            pending_finalizations_max: parse_pending_finalizations_max(
                std::env::var(PENDING_FINALIZATIONS_MAX_ENV).ok().as_deref(),
            ),
            handoff_failure: None,
            #[cfg(test)]
            backlog_transitions: Vec::new(),
            #[cfg(test)]
            injected_handoff_failures: std::cell::Cell::new((0, 0)),
        }
    }

    /// Session identifier (via the owned description handle).
    #[inline]
    fn session_id(&self) -> &SessionId {
        self.description.get_session_id()
    }

    /// Current session time (real-time or manually overridden for tests/replay),
    /// via the owned description handle.
    #[inline]
    fn now(&self) -> SystemTime {
        self.description.get_time()
    }
}

// ======================================================================
// Finalization journal state
// ======================================================================
// The locally-materialized finalized-head cursor, masterchain applied-top
// cursor, finalized-block/delivery dedup journal, and history pruning.
impl ConsensusController {
    /* Finalized-head cursor */

    /// Highest finalized non-empty block seqno materialized locally.
    pub(crate) fn finalized_head_seqno(&self) -> Option<u32> {
        self.finalized_head_seqno
    }

    /// Slot of the latest locally materialized finalized head.
    pub(crate) fn finalized_head_slot(&self) -> Option<SlotIndex> {
        self.finalized_head_slot
    }

    /// Last finalized non-empty block id (parent for empty blocks).
    pub(crate) fn finalized_head_block_id(&self) -> &Option<BlockIdExt> {
        &self.finalized_head_block_id
    }

    /// Last finalized head block's `before_split` flag.
    pub(crate) fn finalized_head_before_split(&self) -> bool {
        self.finalized_head_before_split
    }

    /// Observed `before_split` values for non-empty block ids.
    pub(crate) fn before_split_by_block_id(&self) -> &HashMap<BlockIdExt, bool> {
        &self.before_split_by_block_id
    }

    /// Producer-side highest finalized seqno tracked for this session.
    pub(crate) fn last_consensus_finalized_seqno(&self) -> Option<u32> {
        self.last_consensus_finalized_seqno
    }

    /// Set the finalized head cursor (recovery republish).
    pub(crate) fn set_finalized_head(&mut self, seqno: u32, slot: SlotIndex, block_id: BlockIdExt) {
        self.finalized_head_seqno = Some(seqno);
        self.finalized_head_slot = Some(slot);
        self.finalized_head_block_id = Some(block_id);
    }

    /// Set the producer-side last-consensus-finalized seqno (set_mc / recovery).
    pub(crate) fn set_last_consensus_finalized_seqno(&mut self, value: Option<u32>) {
        self.last_consensus_finalized_seqno = value;
    }

    /// Record an observed `before_split` flag for a non-empty block id
    /// (`on_candidate_received`).
    pub(crate) fn insert_before_split(&mut self, block_id: BlockIdExt, before_split: bool) {
        self.before_split_by_block_id.insert(block_id, before_split);
    }

    /* Masterchain applied-top cursor */

    /// Last MC-registered applied-top seqno for this shard session.
    pub(crate) fn last_mc_finalized_seqno(&self) -> Option<u32> {
        self.last_mc_finalized_seqno
    }

    /// Set the MC applied-top seqno (restart recovery + tests). The monotonic
    /// max is applied by the caller / [`Self::set_mc_finalized_block`].
    pub(crate) fn set_last_mc_finalized_seqno(&mut self, value: Option<u32>) {
        self.last_mc_finalized_seqno = value;
    }

    /// Seqno of the accepted normal head used by MC validation ordering.
    pub(crate) fn accepted_normal_head_seqno(&self) -> u32 {
        self.accepted_normal_head_seqno
    }

    /// Set the accepted-normal-head seqno fallback (tests).
    #[cfg(test)]
    pub(crate) fn set_accepted_normal_head_seqno(&mut self, value: u32) {
        self.accepted_normal_head_seqno = value;
    }

    /// Exact accepted normal head when known (validation parent-tip seed).
    pub(crate) fn accepted_normal_head_block_id(&self) -> &Option<BlockIdExt> {
        &self.accepted_normal_head_block_id
    }

    /* Finalized-block & delivery journal */

    /// True if `id`'s finalized state has been materialized locally.
    pub(crate) fn is_finalized_block(&self, id: &RawCandidateId) -> bool {
        self.finalized_blocks.contains(id)
    }

    /// Number of finalized triggers still waiting for candidate body arrival.
    pub(crate) fn finalized_pending_body_len(&self) -> usize {
        self.finalized_pending_body.len()
    }

    /// Time a still-pending finalized trigger was first observed (debug dump).
    pub(crate) fn finalized_pending_finalized_at(&self, id: &RawCandidateId) -> Option<SystemTime> {
        self.finalized_pending_body.get(id).map(|entry| entry.finalized_at)
    }

    /// Block id previously delivered at `seqno`, if any (recovery-seed dedup).
    pub(crate) fn finalized_delivery_sent_seqno_block_id(&self, seqno: u32) -> Option<BlockIdExt> {
        self.finalized_delivery_sent_seqno.get(&seqno).map(|record| record.block_id.clone())
    }

    /// Mark a candidate id as having its finalized state materialized locally
    /// (recovery seed).
    pub(crate) fn insert_finalized_block(&mut self, id: RawCandidateId) {
        self.finalized_blocks.insert(id);
    }

    pub(crate) fn register_source_finality_replay(&mut self, id: RawCandidateId) {
        self.replayed_source_finalizations.insert(id);
    }

    /// Mark a candidate id as finalized-callback-delivered (recovery seed).
    pub(crate) fn insert_finalized_delivery_sent(&mut self, id: RawCandidateId) {
        self.finalized_delivery_sent.insert(id);
    }

    /// Record the seqno-level finalized-callback dedup entry (recovery seed).
    pub(crate) fn insert_finalized_delivery_sent_seqno(
        &mut self,
        seqno: u32,
        slot: SlotIndex,
        block_id: BlockIdExt,
    ) {
        self.finalized_delivery_sent_seqno
            .insert(seqno, FinalizedSeqnoRecord { is_final: true, slot, block_id });
    }

    #[cfg(test)]
    pub(crate) fn continuation_cursor_for_test(&self, id: &RawCandidateId) -> Option<usize> {
        self.finalized_pending_body.get(id)?.continuation.as_ref().map(|plan| plan.next)
    }

    /* History pruning */

    /// Prune finalized-journal entries for slots `< up_to_slot`.
    ///
    /// Fan-out target from `SessionProcessor::cleanup_old_candidates`. Prunes
    /// the transient `finalized_pending_body` buffer and the per-id
    /// `finalized_delivery_sent` dedup, then refreshes the pending-body gauge.
    ///
    /// `finalized_delivery_sent_seqno` is intentionally NOT pruned here: while
    /// old `received_candidates` remain retained, dropping the seqno dedup
    /// could let a later recursive parent-chain walk re-emit an
    /// already-delivered finalized callback.
    ///
    /// An unresolved finalization never ages out: pending triggers and every
    /// unresolved or permanently stalled candidate are kept whatever their slot
    /// (C++ never erases them), and [`Self::durable_pending_floor`] keeps their
    /// dependencies from being pruned while any exists. Only finalized status
    /// entries are released with old slots.
    pub(crate) fn prune_below(&mut self, up_to_slot: SlotIndex) {
        self.finalization_status.retain(|id, entry| {
            id.slot >= up_to_slot || entry.state != CandidateFinalization::Finalized
        });
        self.telemetry.finalized_pending_body_gauge.set(self.finalized_pending_body.len() as f64);
        self.finalized_delivery_sent.retain(|id| id.slot >= up_to_slot);
        // C++ keeps an in-flight finalization's completed parent operation;
        // advancing the live slot window cannot turn it back into a body read.
        // Pin only receipts already earned by actual node acceptance, and only
        // while a retained source's complete resolved plan still references
        // them. Once those plans finish, the next prune reclaims the receipts.
        let in_flight_ancestors: HashSet<_> = self.finalized_pending_body.values()
            .flat_map(|entry| entry.resolved_output_plan.iter().map(|(id, _)| id.clone()))
            .collect();
        self.acknowledged_ancestor_approvals.retain(|id|
            id.slot >= up_to_slot || in_flight_ancestors.contains(id));
    }
}

// ======================================================================
// Finalization backpressure
// ======================================================================
// Per-candidate finalization status, the pending/stalled counts, and the
// stop-producing signal published to the FSM when the backlog crosses the limit.
impl ConsensusController {
    /// Attempted, unresolved finalizations held right now (stalled included).
    pub(crate) fn pending_finalizations(&self) -> usize {
        self.pending_finalizations
    }

    /// Finalizations stopped for a reason retrying cannot mend.
    pub(crate) fn stalled_finalizations(&self) -> usize {
        self.stalled_finalizations
    }

    /// Whether the group has been told to stop producing.
    pub(crate) fn backlog_over_limit(&self) -> bool {
        self.backlog_over_limit
    }

    /// Finalization state of one candidate, if it was ever attempted.
    #[cfg(test)]
    pub(crate) fn candidate_finalization(
        &self,
        id: &RawCandidateId,
    ) -> Option<CandidateFinalization> {
        self.finalization_status.get(id).map(|entry| entry.state.clone())
    }

    fn is_permanently_stalled(&self, id: &RawCandidateId) -> bool {
        self.finalization_status.get(id).is_some_and(CandidateFinalizationEntry::is_stalled)
    }

    /// Replace one status entry, keeping the counts equal to a recount.
    fn store_finalization_status(&mut self, id: RawCandidateId, entry: CandidateFinalizationEntry) {
        let (pending, stalled) = (entry.is_pending(), entry.is_stalled());
        if let Some(old) = self.finalization_status.insert(id, entry) {
            if old.is_pending() {
                self.pending_finalizations = self.pending_finalizations.saturating_sub(1);
            }
            if old.is_stalled() {
                self.stalled_finalizations = self.stalled_finalizations.saturating_sub(1);
            }
        }
        if pending {
            self.pending_finalizations = self.pending_finalizations.saturating_add(1);
        }
        if stalled {
            self.stalled_finalizations = self.stalled_finalizations.saturating_add(1);
        }
    }

    /// Start one candidate's finalization attempt within `attempt`.
    ///
    /// Returns the state the candidate had. A finalized candidate is not
    /// attempted again; a permanently stalled one is not retried but is joined
    /// to the chain so its dependents fail with it; one already in flight in
    /// this pass joins that operation.
    fn begin_candidate_attempt(
        &mut self,
        attempt: &mut ChainAttempt,
        id: &RawCandidateId,
    ) -> CandidateFinalization {
        let current = self.finalization_status.get(id).cloned();
        match current.as_ref().map(|entry| &entry.state) {
            Some(CandidateFinalization::Finalized) => return CandidateFinalization::Finalized,
            Some(CandidateFinalization::InFlight) => return CandidateFinalization::InFlight,
            Some(CandidateFinalization::StalledPermanently(reason)) => {
                let reason = reason.clone();
                if !attempt.chain.contains(id) {
                    attempt.chain.push(id.clone());
                }
                attempt.fail(
                    id,
                    FinalizationFailure::Permanent(format!(
                        "slot {} is permanently stalled: {reason}",
                        id.slot
                    )),
                );
                return CandidateFinalization::StalledPermanently(reason);
            }
            Some(CandidateFinalization::Idle) | None => {}
        }
        let attempts = current.map_or(0, |entry| entry.attempts).saturating_add(1);
        self.store_finalization_status(
            id.clone(),
            CandidateFinalizationEntry { state: CandidateFinalization::InFlight, attempts },
        );
        attempt.chain.push(id.clone());
        CandidateFinalization::Idle
    }

    /// Complete one candidate's attempt and recount, as C++ does at the end of
    /// every attempt. Finalized and stalled are terminal.
    fn complete_candidate_attempt(
        &mut self,
        backend: &mut dyn ConsensusBackend,
        id: &RawCandidateId,
        result: std::result::Result<(), FinalizationFailure>,
    ) {
        let Some(entry) = self.finalization_status.get(id).cloned() else {
            return;
        };
        if matches!(
            entry.state,
            CandidateFinalization::Finalized | CandidateFinalization::StalledPermanently(_)
        ) {
            return;
        }
        let state = match result {
            Ok(()) => CandidateFinalization::Finalized,
            Err(FinalizationFailure::Retryable(_)) | Err(FinalizationFailure::Cancelled) => {
                CandidateFinalization::Idle
            }
            Err(FinalizationFailure::Permanent(reason)) => {
                log::error!(
                    "Session {} finalization: the certificate for slot {} cannot be finalized and \
                     retrying will not change that: {reason}. It is kept rather than dropped, and \
                     this group stops producing.",
                    self.session_id().to_hex_string(),
                    id.slot,
                );
                CandidateFinalization::StalledPermanently(reason)
            }
        };
        self.store_finalization_status(
            id.clone(),
            CandidateFinalizationEntry { state, attempts: entry.attempts },
        );
        self.update_finalization_backlog(backend);
    }

    /// Apply a trigger's attempt outcomes ancestor first. A candidate whose own
    /// step was not reached inherits its parent's failure; with no failure on
    /// the way it succeeded when the whole operation completed, and is still
    /// pending otherwise.
    fn finish_chain_attempt(
        &mut self,
        backend: &mut dyn ConsensusBackend,
        attempt: ChainAttempt,
        complete: bool,
    ) {
        let mut inherited: Option<FinalizationFailure> = None;
        for id in attempt.chain.iter().rev() {
            let result = match (&inherited, attempt.own.get(id)) {
                (Some(failure), _) => Err(failure.clone()),
                (None, Some(own)) => own.clone(),
                (None, None) if complete => Ok(()),
                (None, None) => Err(FinalizationFailure::Retryable(
                    "finalization did not complete in this pass".to_string(),
                )),
            };
            if let Err(failure) = &result {
                inherited = Some(failure.clone());
            }
            self.complete_candidate_attempt(backend, id, result);
        }
    }

    /// Tell the group when the backlog crosses the limit or clears.
    ///
    /// One finalization beyond retrying is enough on its own: it is not a queue
    /// that is still moving but a chain that cannot pass this slot.
    fn update_finalization_backlog(&mut self, backend: &mut dyn ConsensusBackend) {
        let over = self.pending_finalizations > self.pending_finalizations_max
            || self.stalled_finalizations > 0;
        if over == self.backlog_over_limit {
            return;
        }
        self.backlog_over_limit = over;
        if over {
            log::error!(
                "Session {} finalization: {} agreed certificates are waiting to be finalized \
                 ({} permanently stalled), over the limit of {}; this group stops producing \
                 until they clear. Nothing is discarded.",
                self.session_id().to_hex_string(),
                self.pending_finalizations,
                self.stalled_finalizations,
                self.pending_finalizations_max,
            );
        } else {
            log::warn!(
                "Session {} finalization: the finalization backlog has cleared; this group \
                 produces again.",
                self.session_id().to_hex_string(),
            );
        }
        backend.simplex_state_mut().set_finality_behind(over);
        #[cfg(test)]
        self.backlog_transitions.push((over, self.pending_finalizations));
    }

    /// The failure a not-ready handoff of `id` stands for.
    fn take_handoff_failure(&mut self, id: &RawCandidateId) -> FinalizationFailure {
        match self.handoff_failure.take() {
            Some((failed, reason)) if &failed == id => FinalizationFailure::Permanent(reason),
            // A handoff refused while the session stops is cancelled, not retried.
            _ if self.callbacks.is_stopping() => FinalizationFailure::Cancelled,
            _ => FinalizationFailure::Retryable(
                "finalized block handoff is not complete".to_string(),
            ),
        }
    }
}

// ======================================================================
// Vote & certificate ingress
// ======================================================================
// SXMAIN entry points for inbound votes / certificates (signature checks,
// persistence, FSM submission, misbehavior reports).
impl ConsensusController {
    /// Handle an incoming vote from the network.
    ///
    /// Verifies the signature, converts the TL vote to an FSM vote, and passes
    /// it to [`SimplexState::on_vote`] via
    /// [`ConsensusBackend::simplex_state_mut`]. The signature is retained by the
    /// FSM for certificate creation and the raw bytes are threaded through for
    /// misbehavior-proof storage.
    ///
    /// Returns `true` iff the vote was newly applied (`VoteResult::Applied`) so
    /// the caller pumps `check_all()`; duplicate / late / misbehavior / rejected
    /// votes return `false` (no pump).
    pub(crate) fn on_vote(
        &mut self,
        backend: &mut dyn ConsensusBackend,
        source_idx: u32,
        tl_vote: TlVoteBoxed,
        raw_vote: RawVoteData,
    ) -> bool {
        //check_execution_time!(30_000); //TODO: LK: restore during performance testing

        let source_idx = ValidatorIndex::new(source_idx);

        // Validate source index
        if !source_idx.is_valid(self.description.get_total_nodes()) {
            log::warn!(
                "Session {} on_vote: invalid source_idx={} (max={})",
                self.session_id().to_hex_string(),
                source_idx,
                self.description.get_total_nodes()
            );
            return false;
        }

        // Fast-path: drop votes that reference already-finalized slots BEFORE signature verification.
        // This avoids wasted crypto verification for late / duplicated votes.
        //
        // C++ parity: `state.slot_at(slot)` returns nullopt for `slot < first_non_finalized_slot_`.
        let (tl_kind, tl_slot, tl_hash_opt) = match tl_vote.vote() {
            UnsignedVote::Consensus_Simplex_NotarizeVote(u) => {
                if *u.id.slot() < 0 {
                    log::warn!(
                        "Session {} on_vote: REJECTED - \
                        negative slot {} in NotarizeVote from source_idx={source_idx}",
                        self.session_id().to_hex_string(),
                        u.id.slot()
                    );
                    return false;
                }
                let slot = SlotIndex::new(*u.id.slot() as u32);
                let hash = UInt256::from_slice(u.id.hash().as_slice());
                ("notarize", slot, Some(hash))
            }
            UnsignedVote::Consensus_Simplex_FinalizeVote(u) => {
                if *u.id.slot() < 0 {
                    log::warn!(
                        "Session {} on_vote: REJECTED - \
                        negative slot {} in FinalizeVote from source_idx={source_idx}",
                        self.session_id().to_hex_string(),
                        u.id.slot()
                    );
                    return false;
                }
                let slot = SlotIndex::new(*u.id.slot() as u32);
                let hash = UInt256::from_slice(u.id.hash().as_slice());
                ("finalize", slot, Some(hash))
            }
            UnsignedVote::Consensus_Simplex_SkipVote(u) => {
                if u.slot < 0 {
                    log::warn!(
                        "Session {} on_vote: REJECTED - \
                        negative slot {} in SkipVote from source_idx={source_idx}",
                        self.session_id().to_hex_string(),
                        u.slot
                    );
                    return false;
                }
                ("skip", SlotIndex::new(u.slot as u32), None)
            }
        };

        let fsm_first_non_finalized_slot = backend.simplex_state().get_first_non_finalized_slot();
        if tl_slot < fsm_first_non_finalized_slot {
            log::trace!(
                "Session {} on_vote: dropping old vote slot={tl_slot} (< \
                first_non_finalized={fsm_first_non_finalized_slot}) kind={tl_kind} from \
                source_idx={source_idx}",
                &self.session_id().to_hex_string()[..8],
            );
            return false;
        }

        // Mirror C++ vote ingress: reject slots at or beyond `first_too_new_slot`.
        if backend.simplex_state().is_vote_slot_too_far_ahead(tl_slot) {
            log::warn!(
                "Session {} on_vote: REJECTED - slot {tl_slot} too far ahead (first_too_new={}) \
                kind={tl_kind} from source_idx={source_idx}",
                &self.session_id().to_hex_string()[..8],
                backend.simplex_state().first_too_new_vote_slot(),
            );
            return false;
        }

        let tl_hash_prefix = tl_hash_opt
            .as_ref()
            .map(|h| hex::encode(&h.as_slice()[..4]))
            .unwrap_or_else(|| "-".to_string());
        log::trace!(
            "Session {} on_vote: source_idx={} kind={} slot={} hash={}",
            self.session_id().to_hex_string(),
            source_idx,
            tl_kind,
            tl_slot,
            tl_hash_prefix.as_str(),
        );

        // Get source's public key for signature verification
        let source_public_key = self.description.get_source_public_key(source_idx);

        // Verify signature
        if !verify_vote_signature(&tl_vote, self.session_id(), source_public_key) {
            log::warn!(
                "Session {} on_vote: invalid signature from source_idx={}",
                self.session_id().to_hex_string(),
                source_idx
            );
            return false;
        }

        // Trace: record the verified incoming vote for other validators (skip our own loopback).
        if let Some(tc) = &self.trace_collector {
            if Some(source_idx) != self.description.local_validator_index() {
                tc.record_vote_received(
                    self.session_id(),
                    source_idx.value() as i32,
                    tl_vote.vote().clone(),
                );
            }
        }

        // Extract FSM vote AND signature from TL (signature stored for certificate creation)
        let (vote, signature) = match extract_vote_and_signature(&tl_vote) {
            Ok(v) => v,
            Err(e) => {
                log::warn!(
                    "Session {} on_vote: failed to extract vote from source_idx={}: {}",
                    self.session_id().to_hex_string(),
                    source_idx,
                    e
                );
                return false;
            }
        };

        // Extract slot for logging before vote is moved
        let vote_slot = match &vote {
            Vote::Notarize(v) => v.slot,
            Vote::Finalize(v) => v.slot,
            Vote::Skip(v) => v.slot,
        };

        log::trace!(
            "Session {} on_vote: verified vote from source_idx={} kind={} slot={} hash={}",
            self.session_id().to_hex_string(),
            source_idx,
            tl_kind,
            vote_slot,
            tl_hash_prefix.as_str(),
        );

        match tl_kind {
            "notarize" => {
                self.telemetry.votes_in_total_counter.increment(1);
                self.telemetry.votes_in_notarize_counter.increment(1);
                self.telemetry.votes_in_notarize_total.fetch_add(1, Ordering::Relaxed);
            }
            "finalize" => {
                self.telemetry.votes_in_total_counter.increment(1);
                self.telemetry.votes_in_finalize_counter.increment(1);
                self.telemetry.votes_in_finalize_total.fetch_add(1, Ordering::Relaxed);
            }
            "skip" => {
                self.telemetry.votes_in_total_counter.increment(1);
                self.telemetry.votes_in_skip_counter.increment(1);
                self.telemetry.votes_in_skip_total.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }

        // Preserve raw bytes for DB persistence (simplex_state.on_vote consumes raw_vote)
        let raw_vote_for_db = raw_vote.clone();

        // Pass to FSM with signature and raw bytes (for certificate creation and misbehavior proofs)
        let result = backend.simplex_state_mut().on_vote(
            self.description.as_ref(),
            source_idx,
            vote,
            signature,
            raw_vote,
        );

        match result {
            VoteResult::Applied => {
                // Vote applied successfully.
                //
                // Persist vote to DB (fire-and-forget), matching C++:
                // `if (handle_vote(...)) store_vote_to_db(message->message.data.clone(), source).detach();`
                let vote_hash = UInt256::from_slice(&sha256_digest(raw_vote_for_db.as_bytes()));
                let record = VoteRecord {
                    vote_hash,
                    data: raw_vote_for_db.to_raw_buffer(),
                    node_idx: source_idx,
                    seqno: 0, // assigned by save_vote_async
                };
                if let Err(e) = backend.save_incoming_vote(&record) {
                    log::error!(
                        "Session {} on_vote: failed to create vote save: {}",
                        &self.session_id().to_hex_string()[..8],
                        e
                    );
                    self.telemetry.increment_error();
                }

                // Proactively request missing candidate when receiving a NotarizeVote
                // for a block we don't have. This handles the case where the candidate
                // broadcast was lost (e.g., due to QUIC congestion stall with C++ ngtcp2).
                // Without this, the node can't vote and NotarizationReached is never triggered,
                // which is the normal trigger for candidate requests.
                if let Some(ref hash) = tl_hash_opt {
                    let candidate_id = RawCandidateId { slot: tl_slot, hash: hash.clone() };
                    if !backend.candidate_book().has_real_body(&candidate_id) {
                        log::debug!(
                            "Session {} on_vote: NotarizeVote for missing candidate \
                            slot={tl_slot} hash={} from source_idx={source_idx}, requesting",
                            &self.session_id().to_hex_string()[..8],
                            &hash.to_hex_string()[..8]
                        );
                        backend.request_candidate(tl_slot, hash.clone(), None);
                    }
                }
            }
            VoteResult::Duplicate => {
                // Duplicate vote, silently ignore
                log::trace!(
                    "Session {} on_vote: duplicate vote from source_idx={} slot={}",
                    self.session_id().to_hex_string(),
                    source_idx,
                    vote_slot
                );
                return false;
            }
            VoteResult::SlotAlreadyFinalized => {
                // Late vote for already-finalized slot - completely normal in distributed systems
                log::trace!(
                    "Session {} on_vote: late vote from source_idx={source_idx} slot={vote_slot} \
                    (slot already finalized)",
                    self.session_id().to_hex_string(),
                );
                return false;
            }
            VoteResult::Misbehavior(proof) => {
                log::warn!(
                    "Session {} on_vote: MISBEHAVIOR from source_idx={}: {}",
                    self.session_id().to_hex_string(),
                    source_idx,
                    proof
                );

                // Collect misbehavior report for potential downstream processing
                let slot = proof.slot();
                let report = MisbehaviorReport { validator_idx: source_idx, slot, proof };
                self.misbehavior_reports.push(report);
                self.telemetry.misbehavior_counter.increment(1);

                // TODO: Callback to ValidatorGroup for slashing/reporting
                return false;
            }
            VoteResult::Rejected(reason) => {
                log::warn!(
                    "Session {} on_vote: FSM rejected vote from source_idx={}: {}",
                    self.session_id().to_hex_string(),
                    source_idx,
                    reason
                );
                return false;
            }
        }

        // Vote applied — caller pumps the main loop.
        true
    }

    /// Handle an incoming certificate from the network.
    ///
    /// C++ nodes broadcast certificates when thresholds are reached. Validates
    /// the source, drops certs for already-finalized slots, verifies the
    /// certificate (`Certificate::from_tl` enforces the strict C++ policy: valid
    /// and unique validator indices, every signature valid, at least 2/3 weight),
    /// then stores it through [`ConsensusBackend::simplex_state_mut`] and relays
    /// via the standstill tracker on first store.
    ///
    /// Returns `true` iff a still-needed certificate passed verification (so
    /// the caller pumps `check_all()`). Duplicates, rejected, late and
    /// invalid-source certificates return `false`.
    ///
    /// Reference: C++ pool.cpp `handle(IncomingProtocolMessage)` →
    /// `handle_foreign_certificate(cert)`: look up the slot, store the cert
    /// (notar/skip/final), update per-validator vote accounting, propagate.
    pub(crate) fn on_certificate(
        &mut self,
        backend: &mut dyn ConsensusBackend,
        source_idx: impl Into<Option<u32>>,
        tl_certificate: Certificate,
    ) -> bool {
        self.on_certificate_from_peer(backend, None, source_idx.into(), tl_certificate)
    }

    pub(crate) fn on_certificate_from_peer(
        &mut self,
        backend: &mut dyn ConsensusBackend,
        peer: Option<PublicKeyHash>,
        source_idx: Option<u32>,
        tl_certificate: Certificate,
    ) -> bool {
        let source_idx = source_idx.map(ValidatorIndex::new);

        // Avoid logging the full TL certificate (includes signature bytes) on the hot path.
        // It is extremely verbose and materially slows down trace-enabled test runs.
        let (tl_slot, tl_kind, tl_hash_opt, tl_sig_count) = match &tl_certificate {
            Certificate::Consensus_Simplex_Certificate(c) => {
                let sig_count = c.signatures.votes().len();
                match &c.vote {
                    UnsignedVote::Consensus_Simplex_NotarizeVote(v) => {
                        if *v.id.slot() < 0 {
                            log::warn!(
                                "Session {} on_certificate: REJECTED - \
                                negative slot {} in NotarizeVote from source_idx={source_idx:?}",
                                self.session_id().to_hex_string(),
                                v.id.slot()
                            );
                            return false;
                        }
                        let slot = SlotIndex::new(*v.id.slot() as u32);
                        let hash = UInt256::from_slice(v.id.hash().as_slice());
                        (slot, "notarize", Some(hash), sig_count)
                    }
                    UnsignedVote::Consensus_Simplex_FinalizeVote(v) => {
                        if *v.id.slot() < 0 {
                            log::warn!(
                                "Session {} on_certificate: REJECTED - \
                                negative slot {} in FinalizeVote from source_idx={source_idx:?}",
                                self.session_id().to_hex_string(),
                                v.id.slot()
                            );
                            return false;
                        }
                        let slot = SlotIndex::new(*v.id.slot() as u32);
                        let hash = UInt256::from_slice(v.id.hash().as_slice());
                        (slot, "finalize", Some(hash), sig_count)
                    }
                    UnsignedVote::Consensus_Simplex_SkipVote(v) => {
                        if v.slot < 0 {
                            log::warn!(
                                "Session {} on_certificate: REJECTED - \
                                negative slot {} in SkipVote from source_idx={source_idx:?}",
                                self.session_id().to_hex_string(),
                                v.slot
                            );
                            return false;
                        }
                        (SlotIndex::new(v.slot as u32), "skip", None, sig_count)
                    }
                }
            }
        };

        let tl_hash_prefix = tl_hash_opt
            .as_ref()
            .map(|h| hex::encode(&h.as_slice()[..4]))
            .unwrap_or_else(|| "-".to_string());
        log::debug!(
            "Session {} on_certificate: source_idx={:?} kind={} slot={} hash={} sigs={}",
            self.session_id().to_hex_string(),
            source_idx,
            tl_kind,
            tl_slot,
            tl_hash_prefix.as_str(),
            tl_sig_count
        );

        // Validate source index - must be a known validator in the session
        if source_idx.is_some_and(|index| !index.is_valid(self.description.get_total_nodes())) {
            log::warn!(
                "Session {} on_certificate: REJECTED - invalid source_idx={:?} (max={})",
                self.session_id().to_hex_string(),
                source_idx,
                self.description.get_total_nodes()
            );
            return false;
        }

        // C++ parity: drop certificates that reference finalized slots BEFORE signature verification.
        // This avoids wasted crypto verification for late / duplicated certificates.
        //
        // Reference: C++ `state.slot_at(slot)` returns nullopt for `slot < first_non_finalized_slot_`,
        // so `handle_foreign_certificate` ignores them (prevents state resurrection / last_final regressions).
        let fsm_first_non_finalized_slot = backend.simplex_state().get_first_non_finalized_slot();
        if tl_slot < fsm_first_non_finalized_slot {
            log::trace!(
                "Session {} on_certificate: dropping old certificate slot={tl_slot} \
                (< first_non_finalized={fsm_first_non_finalized_slot}) kind={tl_kind} \
                from source_idx={source_idx:?}",
                &self.session_id().to_hex_string()[..8],
            );
            return false;
        }

        // Match fixed C++ pool.cpp: the network ingress bound is exclusive
        // and checked before certificate verification, persistence or repair.
        if backend.simplex_state().is_vote_slot_too_far_ahead(tl_slot) {
            log::warn!(
                "Session {} on_certificate: REJECTED - slot {tl_slot} outside ingress window \
                (first_too_new={}) kind={tl_kind} from source_idx={source_idx:?}",
                &self.session_id().to_hex_string()[..8],
                backend.simplex_state().first_too_new_vote_slot(),
            );
            return false;
        }

        // Receiver acceptance notifications cannot recall copies already queued
        // on this actor. Match fixed C++ pool.cpp: CertificateBundle::needs is
        // checked here before Certificate::from_tl, repair or persistence.
        let raw_vote = match &tl_certificate {
            Certificate::Consensus_Simplex_Certificate(c) => {
                crate::utils::tl_unsigned_to_vote(&c.vote)
            }
        };
        let Ok(raw_vote) = raw_vote else {
            return false;
        };
        if !backend.simplex_state().needs_certificate(&raw_vote) {
            return false;
        }

        // Parse and verify the certificate (C++ strict policy)
        // Certificate::from_tl performs comprehensive validation:
        // - Rejects invalid validator indices
        // - Rejects duplicate validator indices
        // - Rejects if any signature is invalid
        // - Rejects if total weight < 2/3 threshold
        let cert = match crate::certificate::Certificate::<Vote>::from_tl(
            &tl_certificate,
            self.description.as_ref(),
            self.session_id(),
        ) {
            Ok(c) => c,
            Err(e) => {
                self.telemetry.cert_verify_fail_counter.increment(1);
                self.telemetry.cert_verify_fails_total.fetch_add(1, Ordering::Relaxed);
                log::warn!(
                    "Session {} on_certificate: REJECTED from source_idx={:?}: {}",
                    self.session_id().to_hex_string(),
                    source_idx,
                    e
                );
                // C++ parity (`pool.cpp`): bad-signature certificates trigger a
                // temporary peer ban so repeated forged traffic cannot starve
                // the receiver/processor pipeline.
                if let Some(peer) = peer {
                    backend.ban_peer_for_bad_signature(peer);
                } else if let Some(index) = source_idx {
                    backend.ban_source_for_bad_signature(index.value());
                }
                return false;
            }
        };

        self.telemetry.certs_in_counter.increment(1);

        log::debug!(
            "Session {} on_certificate: verified certificate with {} valid signatures",
            self.session_id().to_hex_string(),
            cert.signatures.len()
        );

        // Proactively request missing candidate when receiving a certificate
        // for a block we don't have. This handles the case where the candidate
        // broadcast was lost (e.g., due to QUIC congestion stall with C++ ngtcp2).
        if let Some(ref hash) = tl_hash_opt {
            let candidate_id = RawCandidateId { slot: tl_slot, hash: hash.clone() };
            if !backend.candidate_book().has_real_body(&candidate_id) {
                log::debug!(
                    "Session {} on_certificate: {tl_kind} cert for missing candidate \
                    slot={tl_slot} hash={} from source_idx={source_idx:?}, requesting",
                    &self.session_id().to_hex_string()[..8],
                    &hash.to_hex_string()[..8]
                );
                backend.request_candidate(tl_slot, hash.clone(), None);
            }
        }

        // Dispatch based on vote type in certificate
        // If stored (new certificate), relay to other validators and cache for standstill
        match &cert.vote {
            Vote::Notarize(notar_vote) => {
                log::debug!(
                    "Session {} on_certificate: NotarCert slot={} block={} sigs={}",
                    self.session_id().to_hex_string(),
                    notar_vote.slot,
                    &notar_vote.block_hash.to_hex_string()[..8],
                    cert.signatures.len()
                );
                let notar_cert = Arc::new(crate::certificate::Certificate {
                    vote: notar_vote.clone(),
                    signatures: cert.signatures.clone(),
                });
                match backend.simplex_state_mut().set_notarize_certificate(
                    self.description.as_ref(),
                    notar_vote.slot,
                    &notar_vote.block_hash,
                    notar_cert.clone(),
                ) {
                    Ok(true) => {
                        log::debug!(
                            "Session {} on_certificate: stored NotarCert slot={} block={} ({} \
                            sigs)",
                            self.session_id().to_hex_string(),
                            notar_vote.slot,
                            &notar_vote.block_hash.to_hex_string()[..8],
                            cert.signatures.len(),
                        );
                        backend.notify_certificate_accepted(
                            notar_vote.slot.value(),
                            StandstillCertificateType::Notar,
                        );
                    }
                    Ok(false) => {
                        // Already stored for same block - idempotent
                    }
                    Err(e) => {
                        self.telemetry.cert_conflict_counter.increment(1);
                        log::warn!(
                            "Session {} on_certificate: NotarCert conflict slot={} - {}",
                            &self.session_id().to_hex_string()[..8],
                            notar_vote.slot,
                            e
                        );
                    }
                }
            }
            Vote::Finalize(final_vote) => {
                log::debug!(
                    "Session {} on_certificate: FinalCert slot={} block={} sigs={}",
                    self.session_id().to_hex_string(),
                    final_vote.slot,
                    &final_vote.block_hash.to_hex_string()[..8],
                    cert.signatures.len()
                );
                let final_cert = Arc::new(crate::certificate::Certificate {
                    vote: final_vote.clone(),
                    signatures: cert.signatures.clone(),
                });
                match backend.simplex_state_mut().set_finalize_certificate(
                    self.description.as_ref(),
                    final_vote.slot,
                    &final_vote.block_hash,
                    final_cert,
                ) {
                    Ok(true) => {
                        log::debug!(
                            "Session {} on_certificate: stored FinalCert slot={} block={} ({} \
                            sigs)",
                            self.session_id().to_hex_string(),
                            final_vote.slot,
                            &final_vote.block_hash.to_hex_string()[..8],
                            cert.signatures.len(),
                        );
                        backend.notify_certificate_accepted(
                            final_vote.slot.value(),
                            StandstillCertificateType::Final,
                        );
                    }
                    Ok(false) => {
                        // Already stored for same block - idempotent
                    }
                    Err(e) => {
                        self.telemetry.cert_conflict_counter.increment(1);
                        log::warn!(
                            "Session {} on_certificate: FinalCert conflict slot={} - {}",
                            &self.session_id().to_hex_string()[..8],
                            final_vote.slot,
                            e
                        );
                    }
                }
            }
            Vote::Skip(skip_vote) => {
                log::debug!(
                    "Session {} on_certificate: SkipCert slot={} sigs={}",
                    self.session_id().to_hex_string(),
                    skip_vote.slot,
                    cert.signatures.len()
                );
                let skip_cert = Arc::new(crate::certificate::Certificate {
                    vote: skip_vote.clone(),
                    signatures: cert.signatures.clone(),
                });
                match backend.simplex_state_mut().set_skip_certificate(
                    self.description.as_ref(),
                    skip_vote.slot,
                    skip_cert,
                ) {
                    Ok(true) => {
                        log::debug!(
                            "Session {} on_certificate: stored SkipCert slot={} ({} sigs)",
                            self.session_id().to_hex_string(),
                            skip_vote.slot,
                            cert.signatures.len()
                        );
                        backend.notify_certificate_accepted(
                            skip_vote.slot.value(),
                            StandstillCertificateType::Skip,
                        );
                    }
                    Ok(false) => {
                        // Already stored - idempotent
                    }
                    Err(e) => {
                        self.telemetry.cert_conflict_counter.increment(1);
                        log::warn!(
                            "Session {} on_certificate: SkipCert error slot={} - {}",
                            &self.session_id().to_hex_string()[..8],
                            skip_vote.slot,
                            e
                        );
                    }
                }
            }
        }

        // Certificate verified — caller pumps the main loop.
        true
    }
}

// ======================================================================
// Outbound vote
// ======================================================================
// The consensus-meaningful outbound action: sign + persist + send, re-entered
// once the durability prerequisite is satisfied SessionProcessor-side.
impl ConsensusController {
    /// Sign and broadcast a locally produced vote whose durability prerequisite
    /// is confirmed.
    ///
    /// Reached from the `SessionProcessor::broadcast_vote` wait-shell: that shell
    /// owns the votes-out telemetry and the C++ `WaitCandidateInfoStored` gate
    /// (candidate-info before a `NotarizeVote`, notar-cert before a
    /// `FinalizeVote`; `SkipVote` has no prerequisite), and re-enters here the
    /// moment durability is satisfied — inline for the dedup-hit / `SkipVote`
    /// fast path, or from the async-DB registry continuation otherwise. The wait
    /// orchestration stays on `SessionProcessor` because it crosses the
    /// `DatabaseController` registry; the controller owns the consensus-meaningful
    /// outbound action below: sign, persist, send.
    ///
    /// First-notarize-vote latency is sampled here (not in the shell) so the
    /// timestamp reflects the moment the vote is actually sent — the meaningful
    /// end-of-latency point, matching the pre-refactor ordering where the
    /// tracking ran after the (synchronous) wait succeeded.
    ///
    /// Reference: C++ `pool.cpp::handle(BroadcastVote)` → `handle_our_vote(...)`:
    /// sign, persist (db actor), publish `OutgoingProtocolMessage`.
    pub(crate) fn broadcast_vote_after_persist(
        &mut self,
        backend: &mut dyn ConsensusBackend,
        vote: Vote,
    ) {
        // C++ pool.cpp cast_our_vote: finality fell behind while this vote was
        // being prepared. The consensus bookkeeping that produced it stays as it
        // is, but the vote is not journalled, signed, applied or sent.
        if backend.simplex_state().finality_behind() {
            log::debug!(
                "Session {} broadcast_vote: finality is behind, not casting {:?}",
                self.session_id().to_hex_string(),
                vote
            );
            return;
        }

        // Track first notarize vote in this slot (stage 2 latency).
        if let Vote::Notarize(v) = &vote {
            let vote_slot = v.slot;
            if !backend.runtime().first_candidate_notarized(vote_slot) {
                let now = self.now();
                backend.runtime_mut().set_first_candidate_notarized(vote_slot, true, now);
                if let Ok(latency) =
                    now.duration_since(backend.runtime().started_at(vote_slot, now))
                {
                    self.telemetry
                        .first_candidate_notarized_latency_histogram
                        .record(latency.as_millis() as f64);
                    log::trace!(
                        "Session {}: first notarize vote in {:.3}ms",
                        &self.session_id().to_hex_string()[..8],
                        latency.as_secs_f64() * 1000.0
                    );
                }
            }
        }

        // Trace: record our own outbound vote just before signing.
        if let Some(tc) = &self.trace_collector {
            tc.record_voted(self.session_id(), &vote);
        }

        // Sign the vote with the session-scoped signature.
        let signed_vote = match self.description.sign_own_vote(&vote) {
            Ok(v) => v,
            Err(e) => {
                log::error!(
                    "Session {} broadcast_vote: failed to sign vote: {}",
                    self.session_id().to_hex_string(),
                    e
                );
                self.telemetry.increment_error();
                return;
            }
        };

        // Publication is gated by the durable intent and the exact signed bytes
        // the signing journal committed before returning them.

        // The signature becomes observable here. As in the reference node, the
        // vote is first accounted locally, and it is broadcast only if that
        // local accounting applied it: a vote this node itself rejects must not
        // reach a peer, directly or inside a certificate built on it.
        let Some(local_idx) = self.description.local_validator_index() else {
            return;
        };
        let boxed = rtos_api::IntoBoxed::into_boxed(signed_vote.clone());
        let raw_vote: RawVoteData = match self.description.opts().wire_profile.serialize(&boxed) {
            Ok(bytes) => bytes.into(),
            Err(e) => {
                log::error!(
                    "Session {} broadcast_vote: cannot serialize own vote: {}",
                    self.session_id().to_hex_string(),
                    e
                );
                self.telemetry.increment_error();
                return;
            }
        };
        if !self.on_vote(backend, local_idx.value(), boxed, raw_vote) {
            log::warn!(
                "Session {} broadcast_vote: own vote was not applied locally; not broadcasting it",
                self.session_id().to_hex_string()
            );
            return;
        }

        log::trace!(
            "Session {} broadcast_vote: sending signed vote",
            self.session_id().to_hex_string()
        );

        // Send to every other validator; local accounting is already done.
        backend.send_vote(signed_vote);
    }
}

// ======================================================================
// Masterchain applied-top pipeline
// ======================================================================
// Validator-manager finalization: advance the accepted-normal head and apply
// the masterchain finalized block.
impl ConsensusController {
    /// Advance the accepted-normal-head seqno fallback monotonically, clearing a
    /// now-stale exact block id when the seqno moves past it.
    fn advance_accepted_normal_head_seqno(&mut self, seqno: u32) {
        if seqno > self.accepted_normal_head_seqno {
            self.accepted_normal_head_seqno = seqno;
            if self.accepted_normal_head_block_id.as_ref().is_some_and(|b| b.seq_no < seqno) {
                self.accepted_normal_head_block_id = None;
            }
        }
    }

    /// Advance the accepted-normal-head cursor (seqno + exact block id) to
    /// `block_id`. Used by [`Self::set_mc_finalized_block`], the recursive walk
    /// ([`Self::maybe_apply_finalized_state`]), and restart recovery.
    pub(crate) fn advance_accepted_normal_head_block(&mut self, block_id: BlockIdExt) {
        self.advance_accepted_normal_head_seqno(block_id.seq_no);
        match self.accepted_normal_head_block_id.as_ref() {
            Some(current) if current >= &block_id => {}
            _ => self.accepted_normal_head_block_id = Some(block_id),
        }
    }

    /// Update applied-top tracking from a manager notification.
    ///
    /// Called when the manager forwards the current applied top for this session
    /// shard. Mirrors the C++ external notify path:
    /// - `block-producer.cpp::handle(BlockFinalizedInMasterchain)` updates
    ///   `last_mc_finalized_seqno_` and `last_consensus_finalized_seqno_`
    /// - `block-validator.cpp::handle(BlockFinalizedInMasterchain)` advances the
    ///   exact accepted head when `seqno != 0`
    ///
    /// The seqno feeds `should_generate_empty_block()` and the exact block id
    /// seeds the accepted-head cursor when known. The wake horizon is lowered
    /// through the borrowing [`ConsensusBackend::runtime_mut`] so the session
    /// main loop re-evaluates promptly.
    pub(crate) fn set_mc_finalized_block(
        &mut self,
        backend: &mut dyn ConsensusBackend,
        applied_top: BlockIdExt,
    ) {
        self.telemetry.note_mc_applied_top(applied_top.clone());
        let session_shard = self.description.get_shard();
        if applied_top.shard() != session_shard {
            log::trace!(
                "Session {}: ignoring MC finalization update for mismatched shard {} \
                (session shard {})",
                &self.session_id().to_hex_string()[..8],
                applied_top.shard(),
                session_shard
            );
            return;
        }
        let seqno = applied_top.seq_no;
        log::trace!(
            "Session {}: set_applied_top_seqno={} (was {:?})",
            &self.session_id().to_hex_string()[..8],
            seqno,
            self.last_mc_finalized_seqno
        );
        // Keep last_mc_finalized_seqno monotonic, mirroring C++ behavior:
        // last_mc_finalized_seqno_ = std::max(event->block.seqno(), last_mc_finalized_seqno_);
        let prev_mc = self.last_mc_finalized_seqno.unwrap_or(0);
        let updated_mc = seqno.max(prev_mc);
        self.last_mc_finalized_seqno = Some(updated_mc);

        // C++ block-producer.cpp parity:
        // last_consensus_finalized_seqno_ = std::max(last_mc_finalized_seqno_,
        //                                            last_consensus_finalized_seqno_);
        let prev_consensus = self.last_consensus_finalized_seqno.unwrap_or(0);
        self.last_consensus_finalized_seqno = Some(updated_mc.max(prev_consensus));

        // C++ block-validator.cpp ignores seqno 0 on external notify, so only seed
        // the exact accepted head when the applied top is a non-zerostate block.
        if seqno != 0 {
            self.advance_accepted_normal_head_block(applied_top);
        } else {
            self.advance_accepted_normal_head_seqno(seqno);
        }
        let now = self.now();
        backend.runtime_mut().set_next_awake_time(now);
    }
}

// ======================================================================
// FSM finalization / certificate handlers
// ======================================================================
// Certificate-observed + finalization-driven events dispatched by
// SessionProcessor::process_simplex_events (which stays the pump).
impl ConsensusController {
    /// Handle block finalized event.
    ///
    /// Records the trigger in `finalized_pending_body` (kept until recursive
    /// parent-chain materialization succeeds end-to-end) and kicks the
    /// recursive walk. Always processes (never blocks FSM event processing); if
    /// bodies are missing, materialization is deferred until they arrive.
    pub(crate) fn handle_block_finalized(
        &mut self,
        backend: &mut dyn ConsensusBackend,
        event: BlockFinalizedEvent,
    ) {
        check_execution_time!(50_000);
        instrument!();

        let slot = event.slot;
        let block_hash = &event.block_hash;
        let finalized_id = RawCandidateId { slot, hash: block_hash.clone() };

        // INVARIANT CHECK - Certificate must have weight at least two thirds.
        // Reference: C++ pool.cpp - certificate is only created when threshold is reached.
        let certificate = &event.certificate;
        let cert_weight = match certificate.total_weight(&self.description) {
            Ok(weight) => weight,
            Err(error) => {
                log::error!("Invalid finalization certificate membership: {error}");
                return;
            }
        };
        let total_weight = self.description.get_total_weight();
        let threshold = threshold_66(total_weight);
        debug_assert!(
            cert_weight >= threshold,
            "ConsensusController INVARIANT VIOLATION: finalization certificate weight {} \
            is below threshold {} (total={}). This should never happen - FSM only emits \
            BlockFinalized when threshold is reached.",
            cert_weight,
            threshold,
            total_weight
        );
        if cert_weight < threshold {
            log::error!(
                "Session {} handle_block_finalized: INVARIANT VIOLATION: certificate weight {} \
                below threshold {} (total={})",
                &self.session_id().to_hex_string()[..8],
                cert_weight,
                threshold,
                total_weight
            );
            self.telemetry.increment_error();
        }

        // Always keep a pending entry until recursive parent-chain materialization
        // succeeds end-to-end. This provides deterministic retries on late body/cert
        // arrivals and ensures ancestor parity is eventually reached.
        let entry = FinalizedEntry { event: event.clone(), intent_retained: false, acknowledged_source_candidates: HashSet::new(), walked_candidates: HashSet::new(), resolved_output_plan: Vec::new(), continuation: None, sealed_output_requirements: None, finalized_at: self.now() };
        // C++ state-resolver.cpp: a duplicate joins the existing InFlight
        // operation, preserving its original certificate and completed phases.
        self.finalized_pending_body.entry(finalized_id.clone()).or_insert(entry);
        self.telemetry.finalized_pending_body_gauge.set(self.finalized_pending_body.len() as f64);

        log::debug!(
            "Session {} FINALIZED: slot={}, hash={} - recorded in journal, weight={}/{} ({:.0}%)",
            &self.session_id().to_hex_string()[..8],
            slot,
            &block_hash.to_hex_string()[..8],
            cert_weight,
            total_weight,
            100.0 * cert_weight as f64 / total_weight as f64
        );

        // Note: Certificate caching for standstill is handled in handle_finalization_reached()
        // which is triggered by SimplexEvent::FinalizationReached (emitted after BlockFinalized).

        // Attempt recursive parent-chain finalization immediately.
        self.retry_pending_recursive_finalization_for(backend, std::slice::from_ref(&finalized_id));

        // Continue FSM event processing (do NOT push event back to queue)
    }

    /// Handle notarization reached event.
    ///
    /// Records the milestone, proactively requests a missing candidate body,
    /// emits candidate-observed for a present non-empty body, then persists +
    /// relays the notarization certificate (via the synchronous backend
    /// effect). Caching VoteSignatureSet bytes matches the C++ wire format.
    pub(crate) fn handle_notarization_reached(
        &mut self,
        backend: &mut dyn ConsensusBackend,
        event: NotarizationReachedEvent,
    ) {
        check_execution_time!(1_000);

        let now = self.now();
        self.telemetry.record_notarization_milestone(now, event.slot);

        log::trace!(
            "Session {} notarization reached: slot={} block={} sigs={}",
            self.session_id().to_hex_string(),
            event.slot,
            &event.block_hash.to_hex_string()[..8],
            event.certificate.signatures.len()
        );

        let candidate_id = RawCandidateId { slot: event.slot, hash: event.block_hash.clone() };

        // If we learned notarization via foreign votes/cert but the candidate body is missing,
        // proactively request it. Otherwise, the next leader may be unable to collate due to
        // unresolved parent chain, causing timeouts and skip cascades in single-host tests.
        if !backend.candidate_book().has_real_body(&candidate_id) {
            backend.request_candidate(event.slot, event.block_hash.clone(), None);
        }

        // Extract owned candidate fields, releasing the book borrow before the
        // mutable persist effect runs.
        let observed = backend
            .candidate_book()
            .received(&candidate_id)
            .filter(|received| !received.is_empty)
            .map(|received| {
                (
                    received.block_id.clone(),
                    received.data.clone(),
                    received.collated_data.clone(),
                    received.source_idx,
                )
            });
        if let Some((block_id, data, collated_data, source_idx)) = observed {
            let observed_flags = CandidateObservedFlags {
                body_present: true,
                parent_ready: true,
                local_collated: Some(source_idx) == self.description.local_validator_index(),
            };
            self.callbacks.notify_candidate_observed(block_id, data, collated_data, observed_flags);
        }

        backend.persist_notar_cert_then_relay(&event);
    }

    /// Handle skip certificate reached event.
    ///
    /// Persists + broadcasts the skip certificate to all validators (via the
    /// synchronous backend effect). Reference: C++ pool.cpp creates a skip
    /// certificate and broadcasts it.
    pub(crate) fn handle_skip_certificate_reached(
        &mut self,
        backend: &mut dyn ConsensusBackend,
        event: SkipCertificateReachedEvent,
    ) {
        check_execution_time!(1_000);

        log::trace!(
            "Session {} skip certificate reached: slot={} sigs={}",
            self.session_id().to_hex_string(),
            event.slot,
            event.certificate.signatures.len()
        );

        backend.persist_skip_cert_then_relay(&event);
    }

    /// Handle finalization reached event.
    ///
    /// Records the milestone, then persists + relays the finalization
    /// certificate and updates standstill tracking (via the synchronous backend
    /// effect). Reference: C++ parity handle_saved_certificate.
    pub(crate) fn handle_finalization_reached(
        &mut self,
        backend: &mut dyn ConsensusBackend,
        event: FinalizationReachedEvent,
    ) {
        check_execution_time!(1_000);

        let now = self.now();
        self.telemetry.record_final_cert_milestone(now, event.slot);

        log::trace!(
            "Session {} finalization reached: slot={} block={} sigs={}",
            self.session_id().to_hex_string(),
            event.slot,
            &event.block_hash.to_hex_string()[..8],
            event.certificate.signatures.len()
        );

        backend.persist_final_cert_then_relay(&event);
    }
}

// ======================================================================
// Recursive parent-chain finalization walk
// ======================================================================
// Materialize finalized state up the parent chain and emit the at-most-once
// on_block_finalized callback.
impl ConsensusController {
    /* Walk & application */

    /// Retry all triggers currently stored in `finalized_pending_body`.
    ///
    /// Broad "scan everything pending" entrypoint used from periodic / auxiliary
    /// paths (candidate arrivals, notar cert arrivals, etc), reached from
    /// `SessionProcessor::retry_pending_recursive_finalization`. Sorted by
    /// `(slot, hash)` to keep retries deterministic across runs.
    pub(crate) fn retry_pending_recursive_finalization(
        &mut self,
        backend: &mut dyn ConsensusBackend,
    ) {
        // Snapshot current trigger ids from the pending journal.
        let mut pending_ids: Vec<RawCandidateId> =
            self.finalized_pending_body.keys().cloned().collect();
        if pending_ids.is_empty() {
            return;
        }

        // Stable order helps reproducible diagnostics/callback behavior.
        pending_ids.sort_by(|left, right| {
            left.slot
                .value()
                .cmp(&right.slot.value())
                .then_with(|| left.hash.as_slice().cmp(right.hash.as_slice()))
        });

        self.retry_pending_recursive_finalization_for(backend, &pending_ids);
    }

    /// Retry recursive finalization for an explicit set of trigger ids.
    ///
    /// Completed triggers are removed from the pending journal; unresolved ones
    /// remain queued and will be retried when missing data/certs arrive.
    fn retry_pending_recursive_finalization_for(
        &mut self,
        backend: &mut dyn ConsensusBackend,
        pending_ids: &[RawCandidateId],
    ) {
        if pending_ids.is_empty() {
            return;
        }

        // Collect completed triggers first; remove after the pass.
        let mut completed = Vec::new();
        // C++ InFlight attaches children to the same pending parent operation.
        // This set lasts only for this synchronous pass: a completion or timed
        // retry must poll the real handoff again, with its original evidence.
        let mut pass = FinalityRetryPass::default();
        for trigger_id in pending_ids {
            // A stopping session cancels: nothing is attempted, retried or reported.
            if self.callbacks.is_stopping() {
                break;
            }
            // Clone event payload to avoid holding a map borrow across processing.
            let Some(event) =
                self.finalized_pending_body.get(trigger_id).map(|entry| entry.event.clone())
            else {
                continue;
            };
            // Kept, counted and reported, but never retried: retrying cannot mend it.
            if self.is_permanently_stalled(trigger_id) {
                continue;
            }

            let mut attempt = ChainAttempt::default();
            if self.description.authenticated_runtime().is_some()
                && !self.finalized_pending_body.get(trigger_id).unwrap().intent_retained
            {
                if let Err(error) = self.callbacks.retain_finality_intent(
                    backend.runtime().session_start_prev_blocks().to_vec(),
                    &event,
                ) {
                    log::error!("Cannot durably retain finality intent: {error}");
                    // The durable source store retains and retries every refusal.
                    self.begin_candidate_attempt(&mut attempt, trigger_id);
                    attempt.fail(
                        trigger_id,
                        FinalizationFailure::Retryable(format!(
                            "finality intent not retained: {error}"
                        )),
                    );
                    self.finish_chain_attempt(backend, attempt, false);
                    continue;
                }
                self.finalized_pending_body.get_mut(trigger_id).unwrap().intent_retained = true;
            }

            let walked = self.try_finalize_recursive_chain(
                backend,
                trigger_id,
                &event,
                &mut pass,
                &mut attempt,
            );
            let mut done = walked;
            if done && self.description.authenticated_runtime().is_some() {
                if let Err(error) = self.callbacks.resolve_finality_intent(trigger_id) {
                    log::error!("Cannot durably resolve source finality intent: {error}");
                    attempt.fail(
                        trigger_id,
                        FinalizationFailure::Retryable(format!(
                            "finality intent not resolved: {error}"
                        )),
                    );
                    done = false;
                }
            }
            self.finish_chain_attempt(backend, attempt, walked);
            if done {
                completed.push(trigger_id.clone());
            }
        }

        if completed.is_empty() {
            return;
        }

        for trigger_id in completed {
            self.finalized_pending_body.remove(&trigger_id);
            self.replayed_source_finalizations.remove(&trigger_id);
        }
        self.telemetry.finalized_pending_body_gauge.set(self.finalized_pending_body.len() as f64);
    }

    /// Incrementally resolve finalized trigger + parent chain.
    ///
    /// Processing model:
    /// - MC follows its FinalCert context to the first non-empty block.
    /// - WC resolves the dependency stack, then completes parents before children.
    /// - A missing dependency or pending parent handoff keeps WC children queued.
    ///
    /// Return value:
    /// - `true`  => all currently relevant blocks are resolved/emitted/applied.
    /// - `false` => at least one block still waits for requested data/certs.
    ///
    /// C++ parity (`consensus.cpp::finalize_blocks_inner`):
    /// The `FinalCert` context (`maybe_final_cert`) flows through empty candidates
    /// unchanged and is consumed by the first non-empty candidate. On masterchain,
    /// once the cert is consumed the walk stops (null cert + MC → early return).
    fn try_finalize_recursive_chain(
        &mut self,
        backend: &mut dyn ConsensusBackend,
        trigger_id: &RawCandidateId,
        event: &BlockFinalizedEvent,
        pass: &mut FinalityRetryPass,
        attempt: &mut ChainAttempt,
    ) -> bool {
        if self.description.authenticated_runtime().is_some()
            && self.finalized_pending_body.get(trigger_id)
                .is_some_and(|entry| entry.sealed_output_requirements.is_none())
        {
            match self.callbacks.sealed_finality_output_requirements(trigger_id) {
                Ok(required) => self.finalized_pending_body.get_mut(trigger_id).unwrap()
                    .sealed_output_requirements = required,
                Err(error) => {
                    log::error!("Session {} source {}:{} cannot bind sealed output requirements: {error}",
                        self.session_id().to_hex_string(), trigger_id.slot, trigger_id.hash.to_hex_string());
                    self.begin_candidate_attempt(attempt, trigger_id);
                    attempt.fail(
                        trigger_id,
                        FinalizationFailure::Retryable(format!(
                            "sealed output requirements unavailable: {error}"
                        )),
                    );
                    return false;
                }
            }
        }
        if !self.description.get_shard().is_masterchain()
            && self.description.authenticated_runtime().is_some()
        {
            if let Some(result) =
                self.resume_finality_plan(backend, trigger_id, event, pass, attempt)
            {
                return result;
            }
        }
        let required_output_set: Option<HashSet<_>> = self.finalized_pending_body.get(trigger_id)
            .and_then(|entry| entry.sealed_output_requirements.as_ref())
            .map(|outputs| outputs.iter().cloned().collect());
        let mut remaining_required = required_output_set.clone().unwrap_or_default();
        let applied_floor = self.last_mc_finalized_seqno.unwrap_or(0);
        let mut complete = true;
        let mut expected_outputs = Vec::new();
        let mut resolved_output_plan = Vec::new();
        // C++ state-resolver.cpp:927-946 awaits the complete parent operation
        // before publishing a non-empty WC child. Build the dependency stack
        // first; no child callback escapes while a parent is unresolved.
        let workchain = !self.description.get_shard().is_masterchain();
        let mut resolved_workchain = Vec::new();
        let mut visited = HashSet::new();
        let mut depth = 0u32;
        let mut depth_warned = false;
        let mut current_id = trigger_id.clone();

        // C++ parity: `maybe_final_cert` flows through empty candidates and is
        // consumed (dropped to null) by the first non-empty candidate.
        let mut has_final_cert = true;

        // Capture trigger's slot and candidate hash data for FinalCert signature
        // verification context (C++ `maybe_final_candidate->id.slot` /
        // `maybe_final_candidate->hash_data()`).
        let trigger_slot = trigger_id.slot;
        let trigger_candidate_hash_data: Vec<u8> = backend
            .candidate_book()
            .received(trigger_id)
            .map(|r| r.candidate_hash_data_bytes.clone())
            .unwrap_or_default();

        loop {
            depth += 1;
            if depth > EMPTY_CHAIN_WARN_DEPTH && !depth_warned {
                depth_warned = true;
                log::warn!(
                    "Session {} recursive finalization: deep chain depth={} \
                     (warn_threshold={EMPTY_CHAIN_WARN_DEPTH}) trigger=s{}:{}",
                    &self.session_id().to_hex_string()[..8],
                    depth,
                    trigger_id.slot,
                    &trigger_id.hash.to_hex_string()[..8],
                );
            }
            // There is no depth limit: as in C++, a valid chain is walked to its
            // finalized base however long it is. The walk is iterative and the
            // visited set below bounds it by the distinct candidates held.
            if !visited.insert(current_id.clone()) {
                log::error!(
                    "Session {} recursive finalization: parent-cycle detected at s{}:{} \
                     while resolving trigger=s{}:{}",
                    &self.session_id().to_hex_string()[..8],
                    current_id.slot,
                    &current_id.hash.to_hex_string()[..8],
                    trigger_id.slot,
                    &trigger_id.hash.to_hex_string()[..8],
                );
                self.telemetry.increment_error();
                // A candidate id commits to its parent, so a cycle can only come
                // from inconsistent local metadata, which a repaired body
                // replaces. The deepest attempted candidate waits on that repair;
                // the walk is retried rather than dropped or stopped for good.
                if let Some(deepest) = attempt.chain.last().cloned() {
                    attempt.fail(
                        &deepest,
                        FinalizationFailure::Retryable(format!(
                            "parent cycle at slot {}",
                            current_id.slot
                        )),
                    );
                }
                return false;
            }

            // C++ StateResolver::finalization_of checks its persisted marker
            // before ResolveCandidate. A materialized ancestor has already
            // crossed node acceptance; do not require its old body again.
            // Keep the trigger's FinalCert path: a retained source still needs
            // its own handoff even when startup seeded this candidate id.
            if workchain && !has_final_cert && self.finalized_blocks.contains(&current_id) {
                if let Some(entry) = self.finalized_pending_body.get(trigger_id) {
                    // C++ returns the completed parent operation instead of
                    // resolving its old body again. Only a fresh node-accepted
                    // Approval can reuse this walk's previously resolved suffix;
                    // a startup marker alone cannot supply that authority.
                    if self.acknowledged_ancestor_approvals.contains(&current_id) {
                        if let Some(index) = entry.resolved_output_plan.iter()
                            .position(|(id, _)| id == &current_id)
                        {
                            let suffix = &entry.resolved_output_plan[index..];
                            if remaining_required.iter().all(|required|
                                suffix.iter().any(|(_, output)| output == required))
                            {
                                for (_, output) in suffix { remaining_required.remove(output); }
                                expected_outputs.extend(suffix.iter().map(|(_, output)| output.clone()));
                                resolved_output_plan.extend_from_slice(suffix);
                                break;
                            }
                        }
                    }
                    if !entry.walked_candidates.contains(&current_id) && remaining_required.is_empty() {
                        break;
                    }
                } else {
                    break;
                }
            }

            if let Some(entry) = self.finalized_pending_body.get_mut(trigger_id) {
                entry.walked_candidates.insert(current_id.clone());
            }

            // C++ finalize_blocks: a candidate stopped for good answers its
            // dependents with the same refusal, without another attempt.
            if let CandidateFinalization::StalledPermanently(_) =
                self.begin_candidate_attempt(attempt, &current_id)
            {
                return false;
            }

            // Step 1: resolve candidate metadata/body holder.
            let Some(received) = backend.candidate_book().received(&current_id).cloned() else {
                log::debug!(
                    "Session {} recursive finalization: missing candidate metadata for \
                     s{}:{}, requesting body+cert and deferring trigger=s{}:{}",
                    &self.session_id().to_hex_string()[..8],
                    current_id.slot,
                    &current_id.hash.to_hex_string()[..8],
                    trigger_id.slot,
                    &trigger_id.hash.to_hex_string()[..8],
                );
                backend.request_candidate_for_finality(
                    current_id.slot,
                    current_id.hash.clone(),
                    Some(Duration::ZERO),
                );
                attempt.fail(
                    &current_id,
                    FinalizationFailure::Retryable("candidate metadata unavailable".to_string()),
                );
                complete = false;
                break;
            };

            // C++ parity (`consensus.cpp`):
            // if (maybe_final_cert.is_null() && shard.is_masterchain()) { co_return; }
            // On MC, once the final cert is consumed, stop the walk.
            if self.description.get_shard().is_masterchain() && !has_final_cert {
                if !received.is_empty && !self.finalized_delivery_sent.contains(&current_id) {
                    self.finalized_delivery_sent.insert(current_id.clone());
                }
                // C++ finalize_blocks_inner returns success at once here.
                attempt.succeed(&current_id);
                break;
            }

            if !received.is_empty && self.description.authenticated_runtime().is_some() {
                let source = self.build_source_info_for_received(&received);
                let output = pass.output(
                    &received.block_id,
                    has_final_cert,
                    &UInt256::from(*source.source.id().data()),
                );
                remaining_required.remove(&output);
                expected_outputs.push(output.clone());
                resolved_output_plan.push((current_id.clone(), output));
            }
            // Step 2: evaluate local readiness + floor constraints for this block only.
            // C++ parity: cert-carrying walks bypass the floor check because the
            // recursive finalization in C++ has no applied-floor guard.
            // C++ StateResolver awaits each parent FinalizeBlock; an applied
            // top is not this source's durable handoff receipt. Authenticated
            // recovery retains that dependency walk below the applied top.
            let block_below_applied_floor = self.description.authenticated_runtime().is_none()
                && !has_final_cert && received.block_id.seq_no() < applied_floor;
            let body_available = received.has_real_body();

            if workchain {
                if !body_available && !block_below_applied_floor {
                    log::debug!(target: "simplex_resolver",
                        "WC_FINALITY_BODY_PENDING: session={} source_slot={} source_hash={} dependency_slot={} dependency_hash={} hash_data_bytes={} body_bytes={} empty={} required_remaining={}",
                        self.session_id().to_hex_string(), trigger_id.slot.value(), trigger_id.hash.to_hex_string(),
                        current_id.slot.value(), current_id.hash.to_hex_string(),
                        received.candidate_hash_data_bytes.len(), received.data.data().len(), received.is_empty,
                        remaining_required.len());
                    backend.request_candidate_for_finality(
                        current_id.slot,
                        current_id.hash.clone(),
                        Some(Duration::ZERO),
                    );
                    attempt.fail(
                        &current_id,
                        FinalizationFailure::Retryable("candidate body unavailable".to_string()),
                    );
                    return false;
                }
                resolved_workchain.push((current_id.clone(), received.clone(), has_final_cert));
            } else if body_available {
                // Step 3: persist/apply local finalized state before listener callback emission.
                let durable = self.description.authenticated_runtime().is_some();
                if !durable
                    && !self.maybe_apply_finalized_state(backend, &current_id, has_final_cert)
                {
                    attempt.fail(
                        &current_id,
                        FinalizationFailure::Retryable("finalized state not persisted".to_string()),
                    );
                    complete = false;
                    break;
                }

                // Step 4: callback emission policy + signature mode is handled per block.
                let mut step_ready = true;
                self.try_emit_recursive_finalized_callback(
                    backend,
                    &current_id,
                    &received,
                    event,
                    has_final_cert,
                    trigger_slot,
                    &trigger_candidate_hash_data,
                    &mut step_ready,
                );
                if !step_ready {
                    let failure = self.take_handoff_failure(&current_id);
                    attempt.fail(&current_id, failure);
                    complete = false;
                    if durable {
                        break;
                    }
                } else if durable && !complete {
                    break;
                } else if durable
                    && !self.maybe_apply_finalized_state(backend, &current_id, has_final_cert)
                {
                    attempt.fail(
                        &current_id,
                        FinalizationFailure::Retryable("finalized state not persisted".to_string()),
                    );
                    complete = false;
                    break;
                } else {
                    attempt.succeed(&current_id);
                }
            } else if !block_below_applied_floor {
                log::debug!(
                    "Session {} recursive finalization: candidate body missing for s{}:{}, \
                     requesting and deferring trigger=s{}:{}",
                    &self.session_id().to_hex_string()[..8],
                    current_id.slot,
                    &current_id.hash.to_hex_string()[..8],
                    trigger_id.slot,
                    &trigger_id.hash.to_hex_string()[..8],
                );
                backend.request_candidate_for_finality(
                    current_id.slot,
                    current_id.hash.clone(),
                    Some(Duration::ZERO),
                );
                attempt.fail(
                    &current_id,
                    FinalizationFailure::Retryable("candidate body unavailable".to_string()),
                );
                complete = false;
            }

            // Step 5: stop climbing once we reached already-applied floor.
            if block_below_applied_floor {
                if !workchain {
                    attempt.succeed(&current_id);
                }
                if !received.is_empty && !self.finalized_delivery_sent.contains(&current_id) {
                    log::debug!(
                        "Session {} recursive finalization: stopping parent walk below applied-top \
                         floor for block_id={} seqno={} floor={}",
                        &self.session_id().to_hex_string()[..8],
                        received.block_id,
                        received.block_id.seq_no(),
                        applied_floor,
                    );
                    self.finalized_delivery_sent.insert(current_id.clone());
                }
                break;
            }

            // C++ parity: final cert context flows through empty candidates,
            // is consumed by the first non-empty candidate.
            // `if (is_empty) { recurse(parent, maybe_final_cert); }`
            // `else { recurse(parent, {}); }`
            if !received.is_empty {
                has_final_cert = false;
            }

            let Some(parent_id) = received.parent_id else {
                if has_final_cert && self.description.authenticated_runtime().is_some() {
                    attempt.fail(
                        &current_id,
                        FinalizationFailure::Retryable(
                            "final certificate not consumed by a non-empty candidate".to_string(),
                        ),
                    );
                    complete = false;
                }
                break;
            };

            current_id = parent_id;
        }

        // An already materialized parent may shorten new work, but cannot
        // erase any output this exact source had sealed before interruption.
        // Require the full original set before issuing WC callbacks; every
        // member still crosses the normal certificate/node-acceptance path.
        if !remaining_required.is_empty() || required_output_set.as_ref().is_some_and(|required|
            expected_outputs.iter().any(|output| !required.contains(output)))
        {
            log::debug!(
                "Session {} source {}:{} sealed output obligations not fully resolved",
                self.session_id().to_hex_string(),
                trigger_id.slot,
                trigger_id.hash.to_hex_string()
            );
            attempt.fail(
                trigger_id,
                FinalizationFailure::Retryable(
                    "sealed output obligations not resolved".to_string(),
                ),
            );
            return false;
        }
        if workchain {
            if !complete {
                return false;
            }
            if let Some(entry) = self.finalized_pending_body.get_mut(trigger_id) {
                // Cache only a fully resolved plan. This optimization is bounded
                // independently of the legal chain depth; larger plans keep the
                // normal verified walk and output-sealing checks.
                entry.resolved_output_plan = if resolved_output_plan.len() <= 1024 {
                    resolved_output_plan
                } else {
                    Vec::new()
                };
            }
            if self.description.authenticated_runtime().is_some() && resolved_workchain.len() <= 1024 {
                let steps = resolved_workchain.iter().rev().map(|(id, received, has_final_cert)| {
                    FinalityPlanStep {
                        id: id.clone(), block: received.block_id.clone(), parent: received.parent_id.clone(),
                        is_empty: received.is_empty, has_final_cert: *has_final_cert,
                        source: (!received.is_empty).then(||
                            UInt256::from(*self.build_source_info_for_received(received).source.id().data())),
                    }
                }).collect();
                let entry = self.finalized_pending_body.get_mut(trigger_id).expect("registered source");
                entry.continuation = Some(FinalityContinuation {
                    steps, next: 0, outputs: expected_outputs, trigger_hash_data: trigger_candidate_hash_data,
                    requirements: entry.sealed_output_requirements.clone(),
                });
                // Larger plans retain the original complete walk. The bound is
                // only on cached work, never on valid ancestry or output debt.
                return self
                    .resume_finality_plan(backend, trigger_id, event, pass, attempt)
                    .unwrap_or(false);
            }
            // ResolveCandidate/parent failure or a pending node handoff stops
            // this pass. The retained trigger retries the same parent first.
            for (id, received, has_final_cert) in resolved_workchain.into_iter().rev() {
                let durable = self.description.authenticated_runtime().is_some();
                // Approval is the same ancestor operation for every child in
                // this pass. Each FinalCert still crosses its own source path.
                if durable && !has_final_cert && pass.pending_ancestors.contains(&id) {
                    log::debug!(target: "simplex_resolver",
                        "FINALITY_OUTPUT_PENDING: session={} source_slot={} source_hash={} dependency_slot={} dependency_hash={} block_id={} final=false body_bytes={} joined=true",
                        self.session_id().to_hex_string(), trigger_id.slot.value(), trigger_id.hash.to_hex_string(),
                        id.slot.value(), id.hash.to_hex_string(), received.block_id, received.data.data().len());
                    attempt.fail(
                        &id,
                        FinalizationFailure::Retryable(
                            "joined a pending ancestor handoff".to_string(),
                        ),
                    );
                    return false;
                }
                if !durable && !self.maybe_apply_finalized_state(backend, &id, has_final_cert) {
                    attempt.fail(
                        &id,
                        FinalizationFailure::Retryable("finalized state not persisted".to_string()),
                    );
                    return false;
                }
                let mut ready = true;
                self.try_emit_recursive_finalized_callback(
                    backend, &id, &received, event, has_final_cert,
                    trigger_slot, &trigger_candidate_hash_data, &mut ready,
                );
                if !ready {
                    let failure = self.take_handoff_failure(&id);
                    attempt.fail(&id, failure);
                    if durable && !has_final_cert {
                        pass.pending_ancestors.insert(id);
                    }
                    return false;
                }
                if durable && !self.maybe_apply_finalized_state(backend, &id, has_final_cert) {
                    attempt.fail(
                        &id,
                        FinalizationFailure::Retryable("finalized state not persisted".to_string()),
                    );
                    return false;
                }
                attempt.succeed(&id);
            }
        }

        if complete && self.description.authenticated_runtime().is_some() {
            if let Err(error) = self.callbacks.seal_finality_outputs(trigger_id, expected_outputs) {
                log::error!(
                    "Session {} source {}:{} cannot seal complete finality output set: {error}",
                    self.session_id().to_hex_string(),
                    trigger_id.slot,
                    trigger_id.hash.to_hex_string()
                );
                attempt.fail(
                    trigger_id,
                    FinalizationFailure::Retryable(format!(
                        "finality output set not sealed: {error}"
                    )),
                );
                return false;
            }
        }
        complete
    }

    /// Resume the original operation, like a C++ parent coroutine returning
    /// from FinalizeBlock. The cursor is never persisted or seeded by disk tags.
    fn resume_finality_plan(
        &mut self,
        backend: &mut dyn ConsensusBackend,
        trigger_id: &RawCandidateId,
        event: &BlockFinalizedEvent,
        pass: &mut FinalityRetryPass,
        attempt: &mut ChainAttempt,
    ) -> Option<bool> {
        let mut plan = self.finalized_pending_body.get_mut(trigger_id)?.continuation.take()?;
        if self.finalized_pending_body.get(trigger_id)?.sealed_output_requirements != plan.requirements {
            return None; // Newly bound obligations need the complete original resolver.
        }
        let result = self.drive_finality_plan(backend, trigger_id, event, pass, &mut plan, attempt);
        if result.is_some() {
            self.finalized_pending_body.get_mut(trigger_id)?.continuation = Some(plan);
        }
        result
    }

    fn drive_finality_plan(
        &mut self,
        backend: &mut dyn ConsensusBackend,
        trigger_id: &RawCandidateId,
        event: &BlockFinalizedEvent,
        pass: &mut FinalityRetryPass,
        plan: &mut FinalityContinuation,
        attempt: &mut ChainAttempt,
    ) -> Option<bool> {
        // Every step not yet completed is attempted again, child after parent
        // in the chain order (trigger first), as the C++ recursion re-enters
        // each unfinished parent operation.
        let remaining: Vec<RawCandidateId> =
            plan.steps.iter().skip(plan.next).rev().map(|step| step.id.clone()).collect();
        for id in &remaining {
            self.begin_candidate_attempt(attempt, id);
        }
        while let Some(step) = plan.steps.get(plan.next) {
            if self.is_permanently_stalled(&step.id) {
                return Some(false);
            }
            let Some(received) = backend.candidate_book().received(&step.id).cloned() else {
                backend.request_candidate_for_finality(
                    step.id.slot,
                    step.id.hash.clone(),
                    Some(Duration::ZERO),
                );
                attempt.fail(
                    &step.id,
                    FinalizationFailure::Retryable("candidate metadata unavailable".to_string()),
                );
                return Some(false);
            };
            let source = (!received.is_empty).then(||
                UInt256::from(*self.build_source_info_for_received(&received).source.id().data()));
            if received.slot != step.id.slot || received.block_id != step.block
                || received.parent_id != step.parent || received.is_empty != step.is_empty
                || source != step.source
                || (!received.candidate_hash_data_bytes.is_empty()
                    && UInt256::calc_file_hash(&received.candidate_hash_data_bytes) != step.id.hash)
            {
                log::debug!(target: "simplex_resolver",
                    "FINALITY_PLAN_INVALIDATED: session={} source_slot={} dependency_slot={} reason=metadata_changed",
                    self.session_id().to_hex_string(), trigger_id.slot.value(), step.id.slot.value());
                return None;
            }
            if !received.has_real_body() {
                log::debug!(target: "simplex_resolver",
                    "WC_FINALITY_BODY_PENDING: session={} source_slot={} source_hash={} dependency_slot={} dependency_hash={} hash_data_bytes={} body_bytes={} empty={} required_remaining=0 continuation=true",
                    self.session_id().to_hex_string(), trigger_id.slot.value(), trigger_id.hash.to_hex_string(),
                    step.id.slot.value(), step.id.hash.to_hex_string(), received.candidate_hash_data_bytes.len(),
                    received.data.data().len(), received.is_empty);
                backend.request_candidate_for_finality(
                    step.id.slot,
                    step.id.hash.clone(),
                    Some(Duration::ZERO),
                );
                attempt.fail(
                    &step.id,
                    FinalizationFailure::Retryable("candidate body unavailable".to_string()),
                );
                return Some(false);
            }
            if !step.has_final_cert && pass.pending_ancestors.contains(&step.id) {
                log::debug!(target: "simplex_resolver",
                    "FINALITY_OUTPUT_PENDING: session={} source_slot={} source_hash={} dependency_slot={} dependency_hash={} block_id={} final=false body_bytes={} joined=true continuation=true",
                    self.session_id().to_hex_string(), trigger_id.slot.value(), trigger_id.hash.to_hex_string(),
                    step.id.slot.value(), step.id.hash.to_hex_string(), received.block_id, received.data.data().len());
                attempt.fail(
                    &step.id,
                    FinalizationFailure::Retryable("joined a pending ancestor handoff".to_string()),
                );
                return Some(false);
            }
            let mut ready = true;
            self.try_emit_recursive_finalized_callback(
                backend, &step.id, &received, event, step.has_final_cert,
                trigger_id.slot, &plan.trigger_hash_data, &mut ready,
            );
            if !ready {
                let failure = self.take_handoff_failure(&step.id);
                attempt.fail(&step.id, failure);
                if !step.has_final_cert { pass.pending_ancestors.insert(step.id.clone()); }
                return Some(false);
            }
            if !self.maybe_apply_finalized_state(backend, &step.id, step.has_final_cert) {
                attempt.fail(
                    &step.id,
                    FinalizationFailure::Retryable("finalized state not persisted".to_string()),
                );
                return Some(false);
            }
            attempt.succeed(&step.id);
            // The non-empty handoff (or the prior parent for an empty step)
            // and the same materialization gate as the full walk have succeeded.
            // WAL custody or a startup marker cannot advance a non-empty step.
            plan.next += 1;
            log::debug!(target: "simplex_resolver",
                "FINALITY_PLAN_ADVANCED: session={} source_slot={} completed_steps={} total_steps={}",
                self.session_id().to_hex_string(), trigger_id.slot.value(), plan.next, plan.steps.len());
        }
        if let Err(error) = self.callbacks.seal_finality_outputs(trigger_id, plan.outputs.clone()) {
            log::error!(
                "Session {} source {}:{} cannot seal original finality plan: {error}",
                self.session_id().to_hex_string(),
                trigger_id.slot,
                trigger_id.hash.to_hex_string()
            );
            attempt.fail(
                trigger_id,
                FinalizationFailure::Retryable(format!("finality output set not sealed: {error}")),
            );
            return Some(false);
        }
        Some(true)
    }

    /// Attempt to emit `on_block_finalized()` for one block in recursive walk.
    ///
    /// C++ parity (`consensus.cpp::finalize_blocks_inner`):
    /// - Empty candidates never get `BlockFinalized` / `do_finalize_block`.
    /// - Non-empty candidates with `maybe_final_cert` use FinalCert signatures
    ///   and the **trigger** candidate's slot/hash_data for the signature set.
    /// - Non-empty candidates without cert use NotarCert signatures and their own
    ///   slot/hash_data.
    ///
    /// `complete` is set to `false` when dependencies are missing and were requested.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn try_emit_recursive_finalized_callback(
        &mut self,
        backend: &mut dyn ConsensusBackend,
        candidate_id: &RawCandidateId,
        received: &ReceivedCandidate,
        event: &BlockFinalizedEvent,
        has_final_cert: bool,
        trigger_slot: SlotIndex,
        trigger_candidate_hash_data: &[u8],
        complete: &mut bool,
    ) {
        // C++ parity: empty candidates never emit BlockFinalized / do_finalize_block.
        let durable = self.description.authenticated_runtime().is_some();
        let trigger_id = RawCandidateId { slot: event.slot, hash: event.block_hash.clone() };
        let source_replay = durable
            && self.replayed_source_finalizations.contains(&trigger_id)
            && self.finalized_pending_body.get(&trigger_id).is_some_and(|entry|
                !entry.acknowledged_source_candidates.contains(candidate_id))
            && (has_final_cert || !self.acknowledged_ancestor_approvals.contains(candidate_id));
        if source_replay {
            // The startup seed is no completion receipt for this source. Keep
            // the seqno/block conflict guard, but clear the delivered flag until
            // the normal node handoff actually completes.
            self.finalized_delivery_sent.remove(candidate_id);
        }
        if received.is_empty || (self.finalized_delivery_sent.contains(candidate_id) && !source_replay) {
            return;
        }

        // Protocol invariant: at most one finalized callback per seqno for a
        // *distinct* block. Two callbacks for the same `block_id` are idempotent
        // (typically a recursive parent-chain walk re-entering an ancestor whose
        // slot-keyed dedup entry was already pruned by `cleanup_old_slots`) and
        // must NOT panic. Only a different `block_id` at the same seqno is a real
        // protocol breach.
        let seqno = received.block_id.seq_no();
        if let Some(existing) = self.finalized_delivery_sent_seqno.get(&seqno) {
            if existing.block_id == received.block_id
                && !(durable && has_final_cert && !existing.is_final)
                && !source_replay
            {
                log::debug!(
                    "Session {} recursive finalization: idempotent re-entry for \
                     block_id={} seqno={} previous_slot={} current_slot={} (slot dedup pruned)",
                    &self.session_id().to_hex_string()[..8],
                    received.block_id,
                    seqno,
                    existing.slot,
                    candidate_id.slot,
                );
                // Re-insert the candidate_id so subsequent walks short-circuit at
                // the cheaper dedup before reaching here.
                if !durable || existing.is_final {
                    self.finalized_delivery_sent.insert(candidate_id.clone());
                }
                return;
            }
            assert!(
                existing.block_id == received.block_id,
                "Session {} protocol breach: multiple finalized callbacks for seqno={} \
                 existing_block_id={} new_block_id={}",
                &self.session_id().to_hex_string()[..8],
                seqno,
                existing.block_id,
                received.block_id,
            );
        }

        // Apply shard/MC callback emission policy for this block.
        // C++ parity: on MC, emit only when final cert context is present.
        let applied_floor = self.last_mc_finalized_seqno.unwrap_or(0);
        let should_emit = self.should_emit_on_block_finalized_for_block(
            &received.block_id,
            has_final_cert,
            applied_floor,
        );

        if !should_emit {
            if self.description.get_shard().is_masterchain() {
                assert!(
                    !has_final_cert,
                    "Session {} invariant breach: masterchain FinalCert callback unexpectedly suppressed \
                     for block_id={} seqno={}",
                    &self.session_id().to_hex_string()[..8],
                    received.block_id,
                    seqno,
                );
                log::debug!(
                    "Session {} recursive finalization: skip masterchain ancestor callback \
                     without FinalCert context for block_id={} seqno={}",
                    &self.session_id().to_hex_string()[..8],
                    received.block_id,
                    seqno,
                );
            } else {
                log::warn!(
                    "Session {} recursive finalization: skip callback below applied-top \
                     floor for block_id={} seqno={} floor={}",
                    &self.session_id().to_hex_string()[..8],
                    received.block_id,
                    seqno,
                    applied_floor,
                );
            }
            self.finalized_delivery_sent.insert(candidate_id.clone());
            return;
        }

        // C++ parity: FinalCert context → use FinalCert signatures from the trigger
        // event; otherwise use NotarCert from this candidate's slot.
        let signatures = if has_final_cert {
            self.build_finalization_raw_signatures(&event.certificate.signatures)
        } else {
            let Some(notar_cert) = backend
                .simplex_state()
                .get_notarize_certificate(candidate_id.slot, &candidate_id.hash)
            else {
                log::debug!(
                    "Session {} recursive finalization: missing ancestor NotarCert for \
                     s{}:{}, requesting and deferring callback",
                    &self.session_id().to_hex_string()[..8],
                    candidate_id.slot,
                    &candidate_id.hash.to_hex_string()[..8],
                );
                log::debug!(target: "simplex_resolver",
                    "FINALITY_OUTPUT_CERT_PENDING: session={} source_slot={} source_hash={} dependency_slot={} dependency_hash={} reason=missing_notar",
                    self.session_id().to_hex_string(), trigger_id.slot.value(), trigger_id.hash.to_hex_string(),
                    candidate_id.slot.value(), candidate_id.hash.to_hex_string());
                backend.request_candidate_for_finality(
                    candidate_id.slot,
                    candidate_id.hash.clone(),
                    Some(Duration::ZERO),
                );
                *complete = false;
                return;
            };
            self.build_finalization_raw_signatures(&notar_cert.signatures)
        };

        // C++ parity: when using FinalCert, the signature set references the
        // *trigger* candidate's slot/hash_data, not the current ancestor's.
        let (sig_slot, sig_hash_data) = if has_final_cert {
            (trigger_slot, trigger_candidate_hash_data.to_vec())
        } else {
            (received.slot, received.candidate_hash_data_bytes.clone())
        };

        let source_info = self.build_source_info_for_received(received);
        let handoff = self.notify_block_finalized(
            received.block_id.clone(),
            source_info,
            received.root_hash.clone(),
            received.file_hash.clone(),
            received.data.clone(),
            signatures,
            Vec::new(),
            sig_slot,
            sig_hash_data,
            has_final_cert,
        );
        let delivered = match handoff {
            FinalityHandoff::Delivered => true,
            FinalityHandoff::Pending => false,
            FinalityHandoff::Permanent(reason) => {
                // C++ to_signature_set refuses before FinalizeBlock is
                // published; the caller stops this candidate for good.
                self.handoff_failure = Some((candidate_id.clone(), reason));
                false
            }
        };
        if delivered {
            if durable && !has_final_cert {
                self.acknowledged_ancestor_approvals.insert(candidate_id.clone());
            }
            if source_replay {
                self.finalized_pending_body.get_mut(&trigger_id).expect("registered source trigger")
                    .acknowledged_source_candidates.insert(candidate_id.clone());
            }
            let now = self.now();
            self.telemetry.record_self_collation_acceptance(
                candidate_id,
                &received.block_id,
                has_final_cert,
                &self.description,
                now,
            );
            if !durable || has_final_cert {
                self.finalized_delivery_sent.insert(candidate_id.clone());
            }
            let previous = self.finalized_delivery_sent_seqno.insert(
                seqno,
                FinalizedSeqnoRecord {
                    is_final: has_final_cert,
                    slot: candidate_id.slot,
                    block_id: received.block_id.clone(),
                },
            );
            assert!(
                previous.as_ref().is_none_or(|old| durable
                    && old.block_id == received.block_id
                    && (source_replay || (!old.is_final && has_final_cert))),
                "Session {} protocol breach: duplicate finalized callback seqno={} \
                 previous_block_id={} new_block_id={}",
                &self.session_id().to_hex_string()[..8],
                seqno,
                previous.map(|r| r.block_id).unwrap_or_else(|| received.block_id.clone()),
                received.block_id,
            );
        } else {
            log::debug!(target: "simplex_resolver",
                "FINALITY_OUTPUT_PENDING: session={} source_slot={} source_hash={} dependency_slot={} dependency_hash={} block_id={} final={} body_bytes={}",
                self.session_id().to_hex_string(), trigger_id.slot.value(), trigger_id.hash.to_hex_string(),
                candidate_id.slot.value(), candidate_id.hash.to_hex_string(), received.block_id,
                has_final_cert, received.data.data().len());
            *complete = false;
        }
    }

    /// Pending source work must retain its ancestry until node WAL takeover.
    ///
    /// This holds for every session: an unresolved or permanently stalled
    /// finalization never ages out, and neither do the bodies and notarization
    /// certificates its chain still needs.
    pub(crate) fn durable_pending_floor(&self) -> Option<SlotIndex> {
        // A pending trigger may still depend on an older ancestor whose body
        // has not arrived. Keep the whole session history until this closes.
        (!self.finalized_pending_body.is_empty() || self.pending_finalizations > 0)
            .then_some(SlotIndex::new(0))
    }

    /// A materialized row must remain authenticatable after a crash. The
    /// applied MC floor can suppress old body callbacks, but cannot stand in
    /// for the candidate metadata and quorum evidence needed by bootstrap.
    /// Stop at an already materialized ancestor: it passed this same gate (or
    /// authenticated startup replay). Query missing history through the normal
    /// verified candidate resolver and keep the source intent pending.
    pub(crate) fn ensure_recoverable_ancestry(
        &self,
        backend: &mut dyn ConsensusBackend,
        candidate: &RawCandidateId,
    ) -> bool {
        let mut cursor = candidate.clone();
        // Parent slots strictly decrease (checked below), so this terminates
        // without an implementation depth limit.
        loop {
            let Some(received) = backend.candidate_book().received(&cursor) else {
                log::debug!(target: "simplex_resolver",
                    "RECOVERY_ANCESTRY_PENDING: session={} candidate_slot={} candidate_hash={} dependency_slot={} dependency_hash={} reason=missing_metadata",
                    self.session_id().to_hex_string(), candidate.slot.value(), candidate.hash.to_hex_string(),
                    cursor.slot.value(), cursor.hash.to_hex_string());
                backend.request_candidate_for_finality(cursor.slot, cursor.hash, Some(Duration::ZERO));
                return false;
            };
            if received.candidate_hash_data_bytes.is_empty() {
                log::debug!(target: "simplex_resolver",
                    "RECOVERY_ANCESTRY_PENDING: session={} candidate_slot={} candidate_hash={} dependency_slot={} dependency_hash={} reason=missing_hash_data",
                    self.session_id().to_hex_string(), candidate.slot.value(), candidate.hash.to_hex_string(),
                    cursor.slot.value(), cursor.hash.to_hex_string());
                backend.request_candidate_for_finality(cursor.slot, cursor.hash, Some(Duration::ZERO));
                return false;
            }
            let Some(parent) = received.parent_id.clone() else {
                return true;
            };
            if parent.slot >= cursor.slot {
                log::error!("Session {} cannot persist non-decreasing recovery ancestry", self.session_id());
                return false;
            }
            if self.finalized_blocks.contains(&parent) {
                return true;
            }
            if backend.simplex_state().get_notarize_certificate(parent.slot, &parent.hash).is_none() {
                log::debug!(target: "simplex_resolver",
                    "RECOVERY_ANCESTRY_PENDING: session={} candidate_slot={} candidate_hash={} dependency_slot={} dependency_hash={} reason=missing_notar",
                    self.session_id().to_hex_string(), candidate.slot.value(), candidate.hash.to_hex_string(),
                    parent.slot.value(), parent.hash.to_hex_string());
                backend.request_candidate_for_finality(parent.slot, parent.hash, Some(Duration::ZERO));
                return false;
            }
            cursor = parent;
        }
    }

    /// Apply finalized-driven local state once the candidate body is available.
    ///
    /// Updates local finalized/head cursors, persists finalized records for
    /// restart recovery (via [`ConsensusBackend::persist_finalized_block`]), and
    /// clears per-slot runtime once finalization is materially applied.
    ///
    /// Return semantics:
    /// * `true`  — local state applied (and, on MC, persist registered with the
    ///             registry; the actual write completes asynchronously).
    /// * `false` — synchronous persist registration failed; the in-memory state
    ///             was NOT applied and the caller's retry mechanism
    ///             (`finalized_pending_body`) keeps the trigger queued.
    pub(crate) fn maybe_apply_finalized_state(
        &mut self,
        backend: &mut dyn ConsensusBackend,
        finalized_id: &RawCandidateId,
        is_final: bool,
    ) -> bool {
        if self.finalized_blocks.contains(finalized_id)
            && (!self.description.authenticated_runtime().is_some()
                || !is_final
                || self.finalized_final_proofs.contains(finalized_id))
        {
            return true;
        }

        if self.description.authenticated_runtime().is_some()
            && !self.ensure_recoverable_ancestry(backend, finalized_id)
        {
            return false;
        }

        let Some(received) = backend.candidate_book().received(finalized_id).cloned() else {
            return true;
        };

        if received.candidate_hash_data_bytes.is_empty() {
            return true;
        }

        let slot = received.slot;
        let seqno = received.block_id.seq_no();

        let slot_started_at = backend.runtime().started_at(slot, self.now());
        if let Ok(duration) = self.now().duration_since(slot_started_at) {
            self.telemetry.slot_duration_histogram.record(duration.as_millis() as f64);
        }

        if !backend.runtime().first_candidate_finalized(slot) {
            let now = self.now();
            backend.runtime_mut().set_first_candidate_finalized(slot, true, now);
            if let Ok(latency) = now.duration_since(slot_started_at) {
                self.telemetry
                    .first_candidate_finalized_latency_histogram
                    .record(latency.as_millis() as f64);
            }
        }

        let record = FinalizedBlockRecord {
            candidate_id: finalized_id.clone(),
            block_id: received.block_id.clone(),
            parent: received.parent_id.clone(),
            is_final,
        };

        if !backend.persist_finalized_block(record) {
            return false;
        }

        let previous_head_seqno = self.finalized_head_seqno.unwrap_or(0);
        let should_replace_head = match self.finalized_head_slot {
            Some(current_slot) => {
                seqno > previous_head_seqno
                    || (seqno == previous_head_seqno && slot >= current_slot)
            }
            None => true,
        };

        if !received.is_empty {
            if seqno > previous_head_seqno {
                self.finalized_head_seqno = Some(seqno);
            }

            self.advance_accepted_normal_head_block(received.block_id.clone());

            if should_replace_head {
                if let Ok(before_split) =
                    crate::utils::extract_before_split_flag(received.data.data())
                {
                    self.finalized_head_before_split = before_split;
                    self.before_split_by_block_id.insert(received.block_id.clone(), before_split);
                    if before_split {
                        log::info!(
                            "Session {} maybe_apply_finalized_state: block at slot={slot} seqno={seqno} has \
                            before_split=true (next block MUST be empty for split/merge)",
                            &self.session_id().to_hex_string()[..8],
                        );
                    }
                } else {
                    log::trace!(
                        "Session {} maybe_apply_finalized_state: failed to extract before_split flag for \
                        slot={slot}, assuming false",
                        &self.session_id().to_hex_string()[..8],
                    );
                    self.finalized_head_before_split = false;
                }
            }
        }

        if should_replace_head {
            self.finalized_head_slot = Some(slot);
            self.finalized_head_block_id = Some(received.block_id.clone());
        }

        if seqno > self.last_consensus_finalized_seqno.unwrap_or(0) {
            self.last_consensus_finalized_seqno = Some(seqno);
        }

        self.finalized_blocks.insert(finalized_id.clone());
        if is_final {
            self.finalized_final_proofs.insert(finalized_id.clone());
        }

        // Trace: a FinalCert was observed and this block is now accepted/materialized.
        if let Some(tc) = &self.trace_collector {
            let trace_id = BlockCandidateId {
                slot: finalized_id.slot,
                hash: finalized_id.hash.clone(),
                block: received.block_id.clone(),
            };
            let finalize_vote = Vote::Finalize(crate::simplex_state::FinalizeVote {
                slot: finalized_id.slot,
                block_hash: finalized_id.hash.clone(),
            });
            tc.record_cert_observed(self.session_id(), &finalize_vote);
            tc.record_block_accepted(self.session_id(), &trace_id);
        }

        self.telemetry.last_finalized_slot_gauge.set(slot.0 as f64);
        let now = self.now();
        self.telemetry.set_round_debug_at(now + ROUND_DEBUG_PERIOD);
        self.telemetry.set_last_finalization_time(now);

        if backend.simplex_state().is_slot_progressed(&self.description, slot) {
            backend.reset_slot_state(slot);
        } else {
            log::trace!(
                "Session {} maybe_apply_finalized_state: skipping reset_slot_state for \
                non-progressed slot={slot}",
                &self.session_id().to_hex_string()[..8],
            );
        }

        true
    }

    /* Finalized-callback emission helpers */

    /// MC ancestors without FinalCert never emit. Authenticated WC recovery
    /// waits for every parent handoff, including below the applied top; legacy
    /// sessions retain their applied-floor optimization.
    fn should_emit_on_block_finalized_for_block(
        &self,
        block_id: &BlockIdExt,
        has_final_cert: bool,
        applied_floor: u32,
    ) -> bool {
        if self.description.get_shard().is_masterchain() {
            return has_final_cert;
        }
        self.description.authenticated_runtime().is_some() || block_id.seq_no() >= applied_floor
    }

    /// Emit `on_block_finalized` to the listener for finalized-driven acceptance.
    #[allow(clippy::too_many_arguments)]
    fn notify_block_finalized(
        &self,
        block_id: BlockIdExt,
        source_info: BlockSourceInfo,
        root_hash: BlockHash,
        file_hash: BlockHash,
        data: BlockPayloadPtr,
        signatures: Vec<(PublicKeyHash, BlockPayloadPtr)>,
        approve_signatures: Vec<(PublicKeyHash, BlockPayloadPtr)>,
        slot: SlotIndex,
        candidate_hash_data_bytes: Vec<u8>,
        is_final: bool,
    ) -> FinalityHandoff {
        check_execution_time!(20_000);

        #[cfg(test)]
        {
            let (retryable, permanent) = self.injected_handoff_failures.get();
            if retryable > 0 {
                self.injected_handoff_failures.set((retryable - 1, permanent));
                return FinalityHandoff::Pending;
            }
            if permanent > 0 {
                self.injected_handoff_failures.set((retryable, permanent - 1));
                return FinalityHandoff::Permanent(
                    "injected permanent handoff failure".to_string(),
                );
            }
        }

        let signatures_variant = match self.build_simplex_signatures_variant(
            &signatures,
            slot,
            candidate_hash_data_bytes,
            is_final,
        ) {
            Ok(v) => v,
            Err(e) => {
                log::error!(
                    "Session {} notify_block_finalized: failed to build signatures variant: {}",
                    self.session_id().to_hex_string(),
                    e
                );
                self.telemetry.increment_error();
                return FinalityHandoff::Permanent(format!("signature set conversion failed: {e}"));
            }
        };

        if self.description.authenticated_runtime().is_some() {
            let draft = consensus_common::finality_delivery::FinalizedDeliveryDraft {
                block_id,
                source_info,
                data,
                finality: signatures_variant,
                last_mc_finalized_seqno: self.last_mc_finalized_seqno.unwrap_or(0),
                // The node ledger owns candidate publication deduplication.
                candidate_already_sent: false,
                created_at_unix_secs: SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|duration| duration.as_secs())
                    .unwrap_or(0),
            };
            return match self.callbacks.poll_durable_finality(draft) {
                Ok(true) => FinalityHandoff::Delivered,
                Ok(false) => FinalityHandoff::Pending,
                Err(error) => {
                    log::error!(
                        "Session {} finality retained/retry required: {error}",
                        self.session_id()
                    );
                    // The durable source retains every refused handoff and is
                    // polled again; its errors are the retryable class.
                    FinalityHandoff::Pending
                }
            };
        }

        self.callbacks.notify_block_finalized(
            block_id,
            source_info,
            root_hash,
            file_hash,
            data,
            signatures_variant,
            approve_signatures,
        );
        FinalityHandoff::Delivered
    }

    fn build_finalization_raw_signatures(
        &self,
        signatures: &[crate::certificate::VoteSignature],
    ) -> Vec<(PublicKeyHash, BlockPayloadPtr)> {
        signatures
            .iter()
            .map(|s| {
                (
                    self.description.get_source_public_key_hash(s.validator_idx).clone(),
                    consensus_common::ConsensusCommonFactory::create_block_payload(
                        s.signature.clone(),
                    ),
                )
            })
            .collect()
    }

    fn build_source_info_for_received(&self, received: &ReceivedCandidate) -> BlockSourceInfo {
        let source_public_key = self.description.get_source_public_key(received.source_idx).clone();
        BlockSourceInfo {
            source: source_public_key,
            priority: BlockCandidatePriority {
                round: SIMPLEX_ROUNDLESS,
                priority: 0,
                first_block_round: SIMPLEX_ROUNDLESS,
            },
        }
    }

    /// Build `BlockSignaturesVariant::Simplex` from raw signature pairs with context
    /// (session_id, slot, candidate_data, is_final) for accept_block verification.
    ///
    /// # Invariants (checked with assert)
    /// - raw_signatures must not be empty
    /// - candidate_hash_data_bytes must not be empty
    /// - All signatures must have valid format (64 bytes for Ed25519)
    /// - Total weight must meet threshold_66 for finalized blocks
    fn build_simplex_signatures_variant(
        &self,
        raw_signatures: &[(PublicKeyHash, BlockPayloadPtr)],
        slot: SlotIndex,
        candidate_hash_data_bytes: Vec<u8>,
        is_final: bool,
    ) -> Result<consensus_common::SessionFinality> {
        // INVARIANT: Must have at least one signature
        assert!(
            !raw_signatures.is_empty(),
            "build_simplex_signatures_variant: raw_signatures must not be empty for slot={}",
            slot
        );

        // INVARIANT: candidate_hash_data_bytes must not be empty (needed for signature verification)
        assert!(
            !candidate_hash_data_bytes.is_empty(),
            "build_simplex_signatures_variant: candidate_hash_data_bytes must not be empty for slot={}",
            slot
        );

        if self.description.get_source_public_key(ValidatorIndex::from(0usize)).pq_key().is_some() {
            let context = self
                .description
                .pq_context()
                .ok_or_else(|| rtos_block::error!("PQ session context missing"))?;
            let mut weight = 0;
            let mut pairs = Vec::with_capacity(raw_signatures.len());
            let mut seen = std::collections::HashSet::new();
            for (node_id, signature) in raw_signatures {
                if !seen.insert(node_id) {
                    rtos_block::fail!("duplicate PQ finalized signer");
                }
                let index = self.description.get_source_index(node_id)?;
                let identity = self.description.get_source_public_key(index);
                let key =
                    identity.pq_key().ok_or_else(|| rtos_block::error!("mixed PQ finality"))?;
                weight = rtos_block::checked_add_validator_weight(
                    weight,
                    self.description.get_node_weight(index),
                )?;
                pairs.push(rtos_block::PqBlockSignaturePair {
                    validator_id: (*node_id.data()).into(),
                    algorithm_id: key.algorithm_id,
                    signature: signature.data().to_vec(),
                });
            }
            let data = rtos_block::BlockSignaturesSimplexPq {
                validator_info: context.validator_info(),
                sig_count: pairs.len().try_into()?,
                sig_weight: weight,
                signatures: pairs,
                session_id: self.session_id().clone(),
                slot: slot.value() as u32,
                candidate_data: BlockSignaturesSimplex::bytes_to_cell_tree(
                    &candidate_hash_data_bytes,
                )?,
            };
            let candidate: rtos_api::ton::consensus::CandidateHashData =
                rtos_api::Deserializer::new(&mut std::io::Cursor::new(&candidate_hash_data_bytes))
                    .read_boxed()?;
            let verifier = context.for_block(candidate.block().clone())?;
            return if is_final {
                verifier.verify_final(&data)?;
                Ok(consensus_common::SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(
                    data,
                )))
            } else {
                let approval = rtos_api::pq_finality::PqApproval::from_notarization_fields(data)?;
                verifier.verify_approval(&approval)?;
                Ok(consensus_common::SessionFinality::PqApproval(approval))
            };
        }

        let mut pure_signatures = BlockSignaturesPure::new();
        let mut valid_sig_count = 0u32;
        let mut invalid_sig_count = 0u32;

        // Calculate total weight and add signature pairs
        let mut total_weight: u64 = 0;
        let mut seen_signers = std::collections::HashSet::new();
        for (node_id, sig_payload) in raw_signatures {
            if !seen_signers.insert(node_id) {
                rtos_block::fail!("duplicate signer in finalized signature set");
            }
            let src_idx = self.description.get_source_index(node_id)?;
            total_weight = rtos_block::checked_add_validator_weight(
                total_weight,
                self.description.get_node_weight(src_idx),
            )?;

            // Convert raw signature bytes to CryptoSignaturePair
            let sig_bytes = sig_payload.data().to_vec();
            if sig_bytes.len() >= 64 {
                let mut r = [0u8; 32];
                let mut s = [0u8; 32];
                r.copy_from_slice(&sig_bytes[0..32]);
                s.copy_from_slice(&sig_bytes[32..64]);

                pure_signatures.add_sigpair(CryptoSignaturePair {
                    node_id_short: (*node_id.data()).into(),
                    sign: CryptoSignature::with_r_s(&r, &s),
                });
                valid_sig_count += 1;
            } else {
                invalid_sig_count += 1;
                log::warn!(
                    "build_simplex_signatures_variant: invalid signature length {} for node \
                    {node_id} at slot={slot}",
                    sig_bytes.len(),
                );
            }
        }

        // INVARIANT: All signatures must be valid (no invalid signatures)
        assert!(
            invalid_sig_count == 0,
            "build_simplex_signatures_variant: {} invalid signatures found for slot={} (valid={})",
            invalid_sig_count,
            slot,
            valid_sig_count
        );

        // INVARIANT: Must have at least one valid signature added
        assert!(
            valid_sig_count > 0,
            "build_simplex_signatures_variant: no valid signatures added for slot={}",
            slot
        );

        // INVARIANT: For finalized blocks, total weight must meet threshold_66
        let threshold = threshold_66(self.description.get_total_weight());
        assert!(
            total_weight >= threshold,
            "build_simplex_signatures_variant: total_weight {} < threshold {} for slot={} (is_final={})",
            total_weight,
            threshold,
            slot,
            is_final
        );

        pure_signatures.set_weight(total_weight);

        log::trace!(
            "build_simplex_signatures_variant: slot={} sigs={} weight={}/{} ({:.1}%)",
            slot,
            valid_sig_count,
            total_weight,
            self.description.get_total_weight(),
            100.0 * total_weight as f64 / self.description.get_total_weight() as f64
        );

        // Build BlockSignaturesSimplex with full context for signature verification
        let candidate_data =
            BlockSignaturesSimplex::bytes_to_cell_tree(&candidate_hash_data_bytes)?;
        let simplex_signatures = BlockSignaturesSimplex::with_params(
            ValidatorBaseInfo::with_params(0, 0), // Placeholder - will be replaced in accept_block
            pure_signatures,
            self.session_id().clone(),
            slot.value() as u32,
            candidate_data,
            is_final,
        );

        Ok(BlockSignaturesVariant::Simplex(simplex_signatures).into())
    }

    /*
        Receiver ingress (vote / certificate)

        Network-delivered votes and certificates arrive here from
        `SessionProcessor::on_vote` / `on_certificate` (the `ReceiverListener`
        callbacks), each building a `ConsensusBackend` split-borrow and
        delegating. `SimplexState` stays owned by `SessionProcessor` (the shared
        kernel); both methods reach it only through
        `ConsensusBackend::simplex_state{,_mut}` for the borrow scope.

        Both return whether the caller should pump `check_all()` — `true` only
        when the FSM actually advanced (a newly applied vote / a verified
        certificate). Duplicate / late / rejected / misbehaving ingress returns
        `false` so the main loop is not pumped, preserving the pre-refactor
        control flow exactly.
    */
}

// ======================================================================
// Tests
// ======================================================================
// Test-only field seams consolidated under one `#[cfg(test)]` impl so the
// production impls carry no test scaffolding (called from the `#[path]`
// session-processor unit tests; production fields stay private).
#[cfg(test)]
impl ConsensusController {
    pub(crate) fn build_finality_for_test(
        &self,
        signatures: &[(PublicKeyHash, BlockPayloadPtr)],
        slot: SlotIndex,
        data: Vec<u8>,
        is_final: bool,
    ) -> Result<consensus_common::SessionFinality> {
        self.build_simplex_signatures_variant(signatures, slot, data, is_final)
    }
    /* Callback injection */

    /// Re-point the controller at a rebuilt callbacks aspect.
    ///
    /// Test-only seam used by `SessionProcessor::set_listener_for_test`,
    /// mirroring `CollationController` / `ValidationController`.
    pub(crate) fn set_callbacks_for_test(&mut self, callbacks: Arc<SessionCallbacks>) {
        self.callbacks = callbacks;
    }

    /* Finalization-journal field seams */

    pub(crate) fn set_finalized_head_seqno(&mut self, value: Option<u32>) {
        self.finalized_head_seqno = value;
    }

    pub(crate) fn set_finalized_head_slot(&mut self, value: Option<SlotIndex>) {
        self.finalized_head_slot = value;
    }

    pub(crate) fn set_finalized_head_block_id(&mut self, value: Option<BlockIdExt>) {
        self.finalized_head_block_id = value;
    }

    pub(crate) fn set_finalized_head_before_split(&mut self, value: bool) {
        self.finalized_head_before_split = value;
    }

    pub(crate) fn accepted_ancestor_approval_contains_for_test(&self, id: &RawCandidateId) -> bool {
        self.acknowledged_ancestor_approvals.contains(id)
    }

    pub(crate) fn finalized_pending_body_is_empty(&self) -> bool {
        self.finalized_pending_body.is_empty()
    }

    pub(crate) fn finalized_pending_body_contains(&self, id: &RawCandidateId) -> bool {
        self.finalized_pending_body.contains_key(id)
    }

    pub(crate) fn finalized_delivery_sent_contains(&self, id: &RawCandidateId) -> bool {
        self.finalized_delivery_sent.contains(id)
    }

    pub(crate) fn finalized_delivery_sent_seqno_contains(&self, seqno: u32) -> bool {
        self.finalized_delivery_sent_seqno.contains_key(&seqno)
    }

    /// Seed a `finalized_pending_body` entry (FinalCert observed, body pending)
    /// without driving the FSM. Builds the private [`FinalizedEntry`] internally
    /// so the type stays module-private.
    pub(crate) fn insert_pending_body_for_test(
        &mut self,
        id: RawCandidateId,
        event: BlockFinalizedEvent,
        finalized_at: SystemTime,
    ) {
        self.finalized_pending_body.insert(id, FinalizedEntry { event, intent_retained: false, acknowledged_source_candidates: HashSet::new(), walked_candidates: HashSet::new(), resolved_output_plan: Vec::new(), continuation: None, sealed_output_requirements: None, finalized_at });
        self.telemetry.finalized_pending_body_gauge.set(self.finalized_pending_body.len() as f64);
    }

    /* Finalization backpressure seams */

    /// Inject handoff failures for the next emissions: retryable ones first.
    pub(crate) fn inject_handoff_failures_for_test(&mut self, retryable: usize, permanent: usize) {
        self.injected_handoff_failures.set((retryable, permanent));
    }

    /// Inject the pending-finalization limit (no environment change in tests).
    pub(crate) fn set_pending_finalizations_max_for_test(&mut self, max: usize) {
        self.pending_finalizations_max = max;
    }

    pub(crate) fn pending_finalizations_max_for_test(&self) -> usize {
        self.pending_finalizations_max
    }

    /// Every backlog flip so far, in order, as (over_limit, pending).
    pub(crate) fn backlog_transitions_for_test(&self) -> &[(bool, usize)] {
        &self.backlog_transitions
    }

    /// Full recount, to check the incremental counts against.
    pub(crate) fn recount_finalizations_for_test(&self) -> (usize, usize) {
        let pending = self.finalization_status.values().filter(|e| e.is_pending()).count();
        let stalled = self.finalization_status.values().filter(|e| e.is_stalled()).count();
        (pending, stalled)
    }

    pub(crate) fn finalization_attempts_for_test(&self, id: &RawCandidateId) -> u32 {
        self.finalization_status.get(id).map_or(0, |entry| entry.attempts)
    }

    pub(crate) fn finalization_status_len_for_test(&self) -> usize {
        self.finalization_status.len()
    }
}

#[cfg(test)]
mod retry_pass_tests {
    use super::*;

    #[test]
    fn finality_retry_output_cache_preserves_all_inputs_and_overflow() {
        let block = |seq| BlockIdExt::with_params(
            rtos_block::ShardIdent::masterchain(), seq,
            UInt256::from([1; 32]), UInt256::from([2; 32]));
        let source = UInt256::from([3; 32]);
        let other_source = UInt256::from([4; 32]);
        let mut pass = FinalityRetryPass::default();
        let first = pass.output(&block(1), false, &source);
        let before = ExpectedFinalityOutput::construction_count_for_test();
        assert_eq!(pass.output(&block(1), false, &source), first);
        assert_eq!(ExpectedFinalityOutput::construction_count_for_test(), before);
        assert_ne!(pass.output(&block(1), true, &source), first);
        assert_ne!(pass.output(&block(1), false, &other_source), first);
        assert_ne!(pass.output(&block(2), false, &source), first);
        assert_eq!(ExpectedFinalityOutput::construction_count_for_test() - before, 3);
        for seq in 1000..2024 { pass.output(&block(seq), false, &source); }
        assert_eq!(pass.outputs.len(), 1024);
        let before = ExpectedFinalityOutput::construction_count_for_test();
        let uncached = pass.output(&block(9999), true, &other_source);
        assert_eq!(uncached.block_id, block(9999).to_string());
        assert!(uncached.is_final);
        assert_eq!(uncached.source_validator, other_source.to_hex_string());
        assert_eq!(pass.output(&block(9999), true, &other_source), uncached);
        assert_eq!(ExpectedFinalityOutput::construction_count_for_test() - before, 2,
            "overflow must compute the original output rather than discard or alias it");
        assert_eq!(pass.output(&block(1), false, &source), first);
        let before = ExpectedFinalityOutput::construction_count_for_test();
        assert_eq!(FinalityRetryPass::default().output(&block(1), false, &source), first);
        assert_eq!(ExpectedFinalityOutput::construction_count_for_test() - before, 1,
            "a fresh pass must rebuild identity from its actual current inputs");
    }
}
