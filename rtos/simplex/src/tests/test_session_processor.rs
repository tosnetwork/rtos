/*
 * RTOS project modifications (2026-10-10): durable journal and explicit wire profile integration; wait for database completion before asserting effects.
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! Tests for SessionProcessor
//!
//! These tests are included directly from session_processor.rs via #[path] attribute
//! to access private internals without requiring pub(crate) visibility.

use super::*;
use crate::{
    block::ValidatorIndex,
    collation_controller::{CollationResult, LocalChainHead, PrecollatedBlock},
    database::{CandidateInfoRecord, NotarCertRecord},
    receiver::Receiver,
    task_queue::{CallbackTaskQueuePtr, TaskQueuePtr},
    utils::AsyncRequestImpl,
    validation_controller::PendingValidation,
    SessionId, SessionNode, SessionOptions, SIMPLEX_ROUNDLESS,
};
use consensus_common::{
    AsyncCollationRequestPtr, BlockPayloadPtr, BlockSourceInfo, CollationParentHint,
    EnsureCandidateAvailabilityOptions, PublicKey, PublicKeyHash, ResolverPurpose, SessionStats,
    ValidatorBlockCandidateCallback, ValidatorBlockCandidateDecisionCallback,
};
use rtos_api::{
    deserialize_boxed, serialize_boxed,
    ton::{
        consensus::{
            candidatehashdata::{CandidateHashDataEmpty, CandidateHashDataOrdinary},
            candidateid::CandidateId as TlCandidateId,
            candidateparent::CandidateParent as TlCandidateParent,
            simplex::{
                certificate::Certificate, unsignedvote::SkipVote, vote::Vote as TlVote,
                votesignature::VoteSignature, votesignatureset::VoteSignatureSet, CandidateAndCert,
                Certificate as CertificateBoxed, VoteSignature as VoteSignatureBoxed,
            },
            CandidateData, CandidateHashData, CandidateId as CandidateIdBoxed, CandidateParent,
        },
        validator_session::candidate::Candidate as TlCandidate,
    },
    IntoBoxed,
};
use rtos_block::{
    error, sha256_digest, signature::BlockSignaturesVariant, BlockIdExt, BocFlags, BocWriter,
    BuilderData, Ed25519KeyOption, ShardIdent, UInt256, ZeroizingBytes,
};
use std::{
    collections::VecDeque,
    env, fs, mem,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::channel,
        Arc, Mutex,
    },
    time::{Duration, SystemTime},
};

// ============================================================================
// Test Helpers
// ============================================================================

/// Create valid BOC bytes from raw data (for tests that need valid BOC input).
///
/// The compress/decompress pipeline requires valid BOC, so mock data must be
/// wrapped in a cell + serialized as BOC with appropriate flags.
fn make_test_boc(data: &[u8], flags: BocFlags) -> Vec<u8> {
    let mut b = BuilderData::new();
    b.append_raw(data, data.len() * 8).unwrap();
    let cell = b.into_cell().unwrap();
    let mut buf = Vec::new();
    BocWriter::with_flags([cell], flags).unwrap().write(&mut buf).unwrap();
    buf
}

/// Create test validators with equal weights
fn create_test_validators(count: u32) -> Vec<SessionNode> {
    (0..count)
        .map(|_| {
            let public_key =
                Ed25519KeyOption::<ZeroizingBytes>::generate().expect("Failed to generate key");
            let adnl_id = public_key.id().clone();
            SessionNode { public_key, adnl_id, weight: 1 }
        })
        .collect()
}

/// Create test SessionDescription with default options
#[allow(dead_code)]
fn create_test_desc(
    nodes: &[SessionNode],
    local_idx: usize,
) -> Arc<crate::session_description::SessionDescription> {
    create_test_desc_with_opts(nodes, local_idx, &SessionOptions::default())
}

fn create_test_desc_for_shard_with_opts(
    nodes: &[SessionNode],
    local_idx: usize,
    shard: ShardIdent,
    opts: &SessionOptions,
) -> Arc<crate::session_description::SessionDescription> {
    let local_key = nodes[local_idx].public_key.clone();
    Arc::new(
        crate::session_description::SessionDescription::new(
            opts,
            SessionId::default(),
            1, // initial_block_seqno
            nodes,
            local_key,
            &shard,
            SystemTime::now(),
            None, // metrics
        )
        .unwrap(),
    )
}

fn make_start_prev_blocks(shard: &ShardIdent, initial_block_seqno: u32) -> Vec<BlockIdExt> {
    vec![BlockIdExt::with_params(
        shard.clone(),
        initial_block_seqno.saturating_sub(1),
        UInt256::default(),
        UInt256::default(),
    )]
}

// ============================================================================
// Mock Receiver
// ============================================================================

/// Recorded action from SessionProcessor → Receiver
#[derive(Debug, Clone)]
#[allow(dead_code)]
enum ReceiverAction {
    /// send_vote() was called
    SendVote {
        vote: TlVote,
    },
    /// cache_our_vote_for_standstill() was called
    CacheOurVoteForStandstill {
        vote: TlVote,
    },
    /// send_block_broadcast() was called
    SendBlockBroadcast {
        slot: u32,
        candidate_hash: UInt256,
    },
    /// cache_notarization_cert() was called
    CacheNotarizationCert {
        slot: u32,
        block_hash: UInt256,
    },
    /// cache_candidate_bytes() was called (full bytes captured for roundtrip checks)
    CacheCandidateBytes {
        slot: u32,
        block_hash: UInt256,
        candidate_data: Vec<u8>,
    },
    /// send_certificate() was called
    SendCertificate {
        certificate: CertificateBoxed,
    },
    /// cache_standstill_certificate() was called
    CacheStandstillCertificate {
        slot: u32,
        kind: crate::receiver::StandstillCertificateType,
        bytes_len: usize,
    },
    /// cache_last_final_certificate() was called
    CacheLastFinalCertificate {
        slot: u32,
        bytes_len: usize,
    },
    /// cleanup() was called
    Cleanup {
        up_to_slot: u32,
    },
    /// set_ingress_slot_begin() was called
    SetIngressSlotBegin {
        slot: u32,
    },
    /// set_ingress_progress_slot() was called
    SetIngressProgressSlot {
        slot: u32,
    },
    /// cancel_candidate_requests_for_slot() was called
    CancelCandidateRequestsForSlot {
        slot: u32,
    },
    /// set_standstill_slots() was called
    SetStandstillSlots {
        begin: u32,
        end: u32,
    },
    /// request_candidate() was called
    RequestCandidate {
        slot: u32,
        block_hash: UInt256,
    },
    /// notify_certificate_accepted() was called
    NotifyCertificateAccepted {
        slot: u32,
        kind: crate::receiver::StandstillCertificateType,
    },
    /// ban_source_for_bad_signature() was called
    BanSourceForBadSignature {
        source_idx: u32,
    },
    BanPeerForBadSignature {
        peer: consensus_common::PublicKeyHash,
    },
}

/// Mock receiver that records all outbound calls
struct MockReceiver {
    /// Recorded actions (sent votes, broadcasts, etc.)
    actions: Arc<Mutex<VecDeque<ReceiverAction>>>,
    last_standstill_slots: Arc<Mutex<Option<(u32, u32)>>>,
}

impl MockReceiver {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            actions: Arc::new(Mutex::new(VecDeque::new())),
            last_standstill_slots: Arc::new(Mutex::new(None)),
        })
    }

    /// Get all recorded actions (drains the queue)
    fn drain_actions(&self) -> Vec<ReceiverAction> {
        self.actions.lock().unwrap().drain(..).collect()
    }
}

impl Receiver for MockReceiver {
    fn send_vote(&self, vote: TlVote) {
        self.actions.lock().unwrap().push_back(ReceiverAction::SendVote { vote });
    }

    fn cache_our_vote_for_standstill(&self, vote: TlVote) {
        self.actions.lock().unwrap().push_back(ReceiverAction::CacheOurVoteForStandstill { vote });
    }

    fn send_block_broadcast(&self, slot: u32, candidate_hash: UInt256, _candidate: CandidateData) {
        self.actions
            .lock()
            .unwrap()
            .push_back(ReceiverAction::SendBlockBroadcast { slot, candidate_hash });
    }

    fn cache_notarization_cert(&self, slot: u32, block_hash: UInt256, _notar_cert_data: Vec<u8>) {
        self.actions
            .lock()
            .unwrap()
            .push_back(ReceiverAction::CacheNotarizationCert { slot, block_hash });
    }

    fn cache_candidate_bytes(&self, slot: u32, block_hash: UInt256, candidate_data: Vec<u8>) {
        self.actions.lock().unwrap().push_back(ReceiverAction::CacheCandidateBytes {
            slot,
            block_hash,
            candidate_data,
        });
    }

    fn cleanup(&self, up_to_slot: u32) {
        self.actions.lock().unwrap().push_back(ReceiverAction::Cleanup { up_to_slot });
    }

    fn set_ingress_slot_begin(&self, slot: u32) {
        self.actions.lock().unwrap().push_back(ReceiverAction::SetIngressSlotBegin { slot });
    }

    fn set_ingress_progress_slot(&self, slot: u32) {
        self.actions.lock().unwrap().push_back(ReceiverAction::SetIngressProgressSlot { slot });
    }

    fn cancel_candidate_requests_for_slot(&self, slot: u32) {
        self.actions
            .lock()
            .unwrap()
            .push_back(ReceiverAction::CancelCandidateRequestsForSlot { slot });
    }

    fn request_candidate(&self, slot: u32, block_hash: UInt256) {
        self.actions
            .lock()
            .unwrap()
            .push_back(ReceiverAction::RequestCandidate { slot, block_hash });
    }

    fn start(&self) {}

    fn reschedule_standstill(&self) {
        // No-op for tests
    }

    fn set_standstill_slots(&self, begin: u32, end: u32) {
        let mut last = self.last_standstill_slots.lock().unwrap();
        if *last == Some((begin, end)) {
            return;
        }
        *last = Some((begin, end));
        self.actions.lock().unwrap().push_back(ReceiverAction::SetStandstillSlots { begin, end });
    }

    fn send_certificate(&self, certificate: CertificateBoxed) {
        self.actions.lock().unwrap().push_back(ReceiverAction::SendCertificate { certificate });
    }

    fn cache_standstill_certificate(
        &self,
        slot: u32,
        kind: crate::receiver::StandstillCertificateType,
        cert_bytes: Vec<u8>,
    ) {
        self.actions.lock().unwrap().push_back(ReceiverAction::CacheStandstillCertificate {
            slot,
            kind,
            bytes_len: cert_bytes.len(),
        });
    }

    fn cache_last_final_certificate(&self, slot: u32, cert_bytes: Vec<u8>) {
        self.actions.lock().unwrap().push_back(ReceiverAction::CacheLastFinalCertificate {
            slot,
            bytes_len: cert_bytes.len(),
        });
    }

    fn notify_certificate_accepted(
        &self,
        slot: u32,
        kind: crate::receiver::StandstillCertificateType,
    ) {
        self.actions
            .lock()
            .unwrap()
            .push_back(ReceiverAction::NotifyCertificateAccepted { slot, kind });
    }

    fn ban_source_for_bad_signature(&self, source_idx: u32) {
        self.actions
            .lock()
            .unwrap()
            .push_back(ReceiverAction::BanSourceForBadSignature { source_idx });
    }

    fn ban_peer_for_bad_signature(&self, peer: consensus_common::PublicKeyHash) {
        self.actions.lock().unwrap().push_back(ReceiverAction::BanPeerForBadSignature { peer });
    }

    fn stop(&self) {
        // No-op for tests
    }
}

// ============================================================================
// Mock Listener
// ============================================================================

/// Mock listener for testing (no-op implementation)
struct MockListener;

impl consensus_common::SessionListener for MockListener {
    fn on_candidate(
        &self,
        _source_info: BlockSourceInfo,
        _root_hash: UInt256,
        _data: BlockPayloadPtr,
        _collated_data: BlockPayloadPtr,
        _callback: ValidatorBlockCandidateDecisionCallback,
    ) {
    }

    fn on_generate_slot(
        &self,
        _source_info: BlockSourceInfo,
        _request: AsyncCollationRequestPtr,
        _parent: CollationParentHint,
        _callback: ValidatorBlockCandidateCallback,
    ) {
    }

    fn on_block_committed(
        &self,
        _source_info: BlockSourceInfo,
        _root_hash: UInt256,
        _file_hash: UInt256,
        _data: BlockPayloadPtr,
        _signatures: BlockSignaturesVariant,
        _approve_signatures: Vec<(PublicKeyHash, BlockPayloadPtr)>,
        _stats: SessionStats,
    ) {
        panic!(
            "on_block_committed must not be called for Simplex sessions (finalized-driven only)"
        );
    }

    fn on_block_skipped(&self, _round: u32) {}

    fn get_approved_candidate(
        &self,
        _source: PublicKey,
        root_hash: UInt256,
        _file_hash: UInt256,
        _collated_data_hash: UInt256,
        _callback: ValidatorBlockCandidateCallback,
    ) {
        panic!(
            "unexpected legacy get_approved_candidate request in session_processor MockListener \
             (root_hash={}); active simplex tests must not use this callback",
            root_hash.to_hex_string()
        );
    }
}

// ============================================================================
// Recording Listener (for emission model tests)
// ============================================================================

/// Recorded listener event
#[derive(Debug, Clone)]
#[allow(dead_code)]
enum ListenerEvent {
    /// on_block_committed was called
    Committed {
        /// Slot from BlockSignaturesSimplex (meaningful identifier)
        slot: u32,
        root_hash: UInt256,
        is_final: bool,
    },
    /// on_block_skipped was called (not used in SIMPLEX_ROUNDLESS mode)
    Skipped { round: u32 },
    /// on_block_finalized was called (out-of-order delivery)
    Finalized { block_id: BlockIdExt, root_hash: UInt256, is_final: bool },
}

// NOTE: dummy_source_info helper removed - was only used by emission model tests

/// Listener that records all commits and skips for verification
struct RecordingListener {
    events: Arc<Mutex<Vec<ListenerEvent>>>,
    authenticated: Mutex<Vec<consensus_common::CandidateAuthenticationEvidence>>,
}

#[allow(dead_code)]
impl RecordingListener {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            events: Arc::new(Mutex::new(Vec::new())),
            authenticated: Mutex::new(Vec::new()),
        })
    }

    /// Get all recorded events (drains the list)
    fn drain_events(&self) -> Vec<ListenerEvent> {
        mem::take(&mut *self.events.lock().unwrap())
    }

    /// Get count of recorded events
    fn event_count(&self) -> usize {
        self.events.lock().unwrap().len()
    }
}

impl consensus_common::SessionListener for RecordingListener {
    fn on_authenticated_candidate(
        &self,
        evidence: consensus_common::CandidateAuthenticationEvidence,
    ) {
        self.authenticated.lock().unwrap().push(evidence);
    }
    fn on_candidate(
        &self,
        _source_info: BlockSourceInfo,
        _root_hash: UInt256,
        _data: BlockPayloadPtr,
        _collated_data: BlockPayloadPtr,
        _callback: ValidatorBlockCandidateDecisionCallback,
    ) {
        // No-op
    }

    fn on_generate_slot(
        &self,
        _source_info: BlockSourceInfo,
        _request: AsyncCollationRequestPtr,
        _parent: CollationParentHint,
        _callback: ValidatorBlockCandidateCallback,
    ) {
        // No-op
    }

    fn on_block_committed(
        &self,
        _source_info: BlockSourceInfo,
        _root_hash: UInt256,
        _file_hash: UInt256,
        _data: BlockPayloadPtr,
        _signatures: BlockSignaturesVariant,
        _approve_signatures: Vec<(PublicKeyHash, BlockPayloadPtr)>,
        _stats: SessionStats,
    ) {
        panic!(
            "on_block_committed must not be called for Simplex sessions (finalized-driven only)"
        );
    }

    fn on_block_skipped(&self, round: u32) {
        self.events.lock().unwrap().push(ListenerEvent::Skipped { round });
    }

    fn on_block_finalized(
        &self,
        block_id: BlockIdExt,
        _source_info: BlockSourceInfo,
        root_hash: UInt256,
        _file_hash: UInt256,
        _data: BlockPayloadPtr,
        signatures: consensus_common::SessionFinality,
        _approve_signatures: Vec<(PublicKeyHash, BlockPayloadPtr)>,
    ) {
        let consensus_common::SessionFinality::Carrier(signatures) = signatures else {
            panic!("classical test received PQ approval")
        };
        let is_final = match signatures {
            BlockSignaturesVariant::SimplexPq(_) => {
                panic!("classical test harness received PQ signatures")
            }
            BlockSignaturesVariant::Simplex(simplex) => simplex.is_final(),
            BlockSignaturesVariant::Ordinary(_) => true,
        };
        self.events.lock().unwrap().push(ListenerEvent::Finalized {
            block_id,
            root_hash,
            is_final,
        });
    }

    fn get_approved_candidate(
        &self,
        _source: PublicKey,
        root_hash: UInt256,
        _file_hash: UInt256,
        _collated_data_hash: UInt256,
        _callback: ValidatorBlockCandidateCallback,
    ) {
        panic!(
            "unexpected legacy get_approved_candidate request in session_processor \
             RecordingListener (root_hash={}); active simplex tests must not use this callback",
            root_hash.to_hex_string()
        );
    }
}

fn drain_finalized_events(recording: &RecordingListener) -> Vec<(BlockIdExt, bool)> {
    recording
        .drain_events()
        .into_iter()
        .filter_map(|event| match event {
            ListenerEvent::Finalized { block_id, is_final, .. } => Some((block_id, is_final)),
            _ => None,
        })
        .collect()
}

// ============================================================================
// Mock Task Queues
// ============================================================================

/// Simple in-memory task queue for tests
struct TestTaskQueue {
    tasks: Arc<Mutex<VecDeque<TaskPtr>>>,
}

impl TestTaskQueue {
    fn new() -> Arc<Self> {
        Arc::new(Self { tasks: Arc::new(Mutex::new(VecDeque::new())) })
    }
}

impl crate::task_queue::TaskQueue<TaskPtr> for TestTaskQueue {
    fn is_overloaded(&self) -> bool {
        false
    }

    fn is_empty(&self) -> bool {
        self.tasks.lock().unwrap().is_empty()
    }

    fn post_closure(&self, task: TaskPtr) {
        self.tasks.lock().unwrap().push_back(task);
    }

    fn pull_closure(
        &self,
        _timeout: Duration,
        _last_warn_dump_time: &mut SystemTime,
    ) -> Option<TaskPtr> {
        self.tasks.lock().unwrap().pop_front()
    }

    fn flush(&self) {
        self.tasks.lock().unwrap().clear();
    }
}

/// Callback task queue (no-op for simple tests)
struct TestCallbackQueue;

impl crate::task_queue::TaskQueue<crate::task_queue::CallbackTaskPtr> for TestCallbackQueue {
    fn is_overloaded(&self) -> bool {
        false
    }

    fn is_empty(&self) -> bool {
        true
    }

    fn post_closure(&self, _task: crate::task_queue::CallbackTaskPtr) {
        // No-op
    }

    fn pull_closure(
        &self,
        _timeout: Duration,
        _last_warn_dump_time: &mut SystemTime,
    ) -> Option<crate::task_queue::CallbackTaskPtr> {
        None
    }

    fn flush(&self) {}
}

// ============================================================================
// Mock Database
// ============================================================================

const TEST_DB_WATCHDOG: Duration = Duration::from_secs(30);

/// Drive actual storage completions and the actor messages they publish.
/// A storage receipt alone no longer executes finalization inline.
fn drain_processor_storage_and_messages(processor: &mut SessionProcessor) {
    let deadline = std::time::Instant::now() + TEST_DB_WATCHDOG;
    let mut last_warning = SystemTime::now();
    loop {
        processor.process_pending_async_db_results();
        while let Some(task) = processor.task_queue.pull_closure(Duration::ZERO, &mut last_warning)
        {
            assert!(std::time::Instant::now() < deadline, "actor completion drain watchdog");
            task(processor);
        }
        if processor.database.pending_is_empty() && processor.task_queue.is_empty() {
            break;
        }
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .expect("storage completion drain watchdog");
        processor.database.db().sync(Some(remaining)).unwrap();
    }
}

/// Real temporary RocksDB database used by the session tests.
struct MockDb;

impl MockDb {
    fn new() -> crate::database::SimplexDbPtr {
        // Open an independent on-disk database and asynchronous worker.
        let temp_dir = env::temp_dir().join(format!("test_db_{}", rand::random::<u64>()));
        fs::create_dir_all(&temp_dir).unwrap();
        crate::database::SimplexDb::open(&temp_dir, "test").unwrap()
    }
}

// ============================================================================
// Test Fixture
// ============================================================================

struct TestFixture {
    nodes: Vec<SessionNode>,
    description: Arc<crate::session_description::SessionDescription>,
    processor: SessionProcessor,
    receiver: Arc<MockReceiver>,
    #[allow(dead_code)]
    task_queue: Arc<TestTaskQueue>,
}

/// Create test SessionDescription with custom options
fn create_test_desc_with_opts(
    nodes: &[SessionNode],
    local_idx: usize,
    opts: &SessionOptions,
) -> Arc<crate::session_description::SessionDescription> {
    create_test_desc_for_shard_with_opts(nodes, local_idx, ShardIdent::masterchain(), opts)
}

impl TestFixture {
    /// Create a test fixture with N validators (local is validator 0)
    fn new(validator_count: u32) -> Self {
        Self::new_with_opts(validator_count, SessionOptions::default())
    }

    fn new_shard(validator_count: u32) -> Self {
        Self::new_with_shard_and_local_idx(
            validator_count,
            0,
            ShardIdent::with_tagged_prefix(0, 0x8000_0000_0000_0000).unwrap(),
            SessionOptions::default(),
        )
    }

    /// Create a test fixture with N validators, custom options, and local_idx
    fn new_with_local_idx(validator_count: u32, local_idx: usize, opts: SessionOptions) -> Self {
        Self::new_with_shard_and_local_idx(
            validator_count,
            local_idx,
            ShardIdent::masterchain(),
            opts,
        )
    }

    fn new_with_shard_and_local_idx(
        validator_count: u32,
        local_idx: usize,
        shard: ShardIdent,
        opts: SessionOptions,
    ) -> Self {
        let nodes = create_test_validators(validator_count);
        let description = create_test_desc_for_shard_with_opts(&nodes, local_idx, shard, &opts);

        let listener: Arc<dyn consensus_common::SessionListener + Send + Sync> =
            Arc::new(MockListener);
        let listener_weak = Arc::downgrade(&listener);

        let task_queue = TestTaskQueue::new();
        let callback_queue: CallbackTaskQueuePtr = Arc::new(TestCallbackQueue);
        let receiver = MockReceiver::new();
        let db = MockDb::new();

        let stop_flag = Arc::new(AtomicBool::new(false));
        let health_counters = Arc::new(crate::receiver::ReceiverHealthCounters::new());
        let callbacks = Arc::new(crate::session_callbacks::SessionCallbacks::new(
            description.get_session_id().clone(),
            stop_flag.clone(),
            false,
            callback_queue,
            listener_weak,
        ));
        let processor = SessionProcessor::new(
            description.clone(),
            make_start_prev_blocks(description.get_shard(), description.get_initial_block_seqno()),
            task_queue.clone() as TaskQueuePtr,
            receiver.clone() as crate::receiver::ReceiverPtr,
            stop_flag,
            db,
            0,
            health_counters,
            callbacks,
            None,
            0,
        )
        .unwrap();

        Self { nodes, description, processor, receiver, task_queue }
    }

    /// Drain and run any closures the processor posted to the SXMAIN task queue,
    /// against `&mut self.processor`.
    ///
    /// Tests use this to flush deferred backend effects that production would run
    /// on the next main-loop iteration — e.g. the borrowing `ValidationBackend` /
    /// `CollationBackend` cannot call `&mut SessionProcessor` methods like
    /// `request_candidate` synchronously, so they bounce a closure onto this
    /// queue.
    fn run_pending_tasks(&mut self) {
        loop {
            let task = self.task_queue.tasks.lock().unwrap().pop_front();
            match task {
                Some(task) => task(&mut self.processor),
                None => break,
            }
        }
    }

    /// Create a test fixture with N validators and custom session options
    fn new_with_opts(validator_count: u32, opts: SessionOptions) -> Self {
        Self::new_with_shard_and_local_idx(validator_count, 0, ShardIdent::masterchain(), opts)
    }

    /// Advance time by duration
    fn advance_time(&mut self, delta: Duration) {
        self.processor.advance_time(delta);
    }

    /// Get all actions sent to receiver
    fn drain_receiver_actions(&self) -> Vec<ReceiverAction> {
        self.receiver.drain_actions()
    }

    /// Wait for actual FIFO storage completion, then run registry continuations.
    /// The watchdog diagnoses a stalled worker; elapsed time never authorizes a
    /// write. Individual results still flow through the production registry.
    fn drain_pending_async_db_results(&mut self) {
        self.drain_pending_async_db_results_with_watchdog(TEST_DB_WATCHDOG);
    }

    fn drain_pending_async_db_results_with_watchdog(&mut self, watchdog: Duration) {
        let deadline = std::time::Instant::now() + watchdog;
        loop {
            self.processor.process_pending_async_db_results();
            if self.processor.database.pending_is_empty() {
                return;
            }
            let registered: Vec<_> = self
                .processor
                .database
                .pending_iter()
                .map(|entry| (entry.id, entry.op_label))
                .collect();
            let remaining = deadline
                .checked_duration_since(std::time::Instant::now())
                .expect("DB completion drain watchdog expired");
            self.processor.database.db().sync(Some(remaining)).unwrap_or_else(|err| {
                panic!("DB completion barrier failed for {registered:?}: {err}")
            });
            self.processor.process_pending_async_db_results();
            for (id, label) in registered {
                assert!(
                    !self.processor.database.pending_iter().any(|entry| entry.id == id),
                    "storage barrier did not complete registered DB result id={id} label={label}",
                );
            }
            // Continuations may have queued more writes. They require their own
            // completion barrier; a prior barrier says nothing about later work.
        }
    }
}

fn metrics_counter(processor: &SessionProcessor, name: &str) -> u64 {
    processor.get_metrics_receiver().snapshot().counters.get(name).copied().unwrap_or(0)
}

// ============================================================================
// Certificate helpers
// ============================================================================

fn build_skip_certificate_tl(
    session_id: &SessionId,
    nodes: &[SessionNode],
    slot: u32,
    signers: &[usize],
) -> CertificateBoxed {
    let unsigned_vote = SkipVote { slot: slot as i32 }.into_boxed();

    let raw_vote_bytes = crate::utils::serialize_unsigned_vote(&unsigned_vote);
    let to_sign = crate::utils::create_data_to_sign(session_id, &raw_vote_bytes);

    let tl_sigs: Vec<VoteSignatureBoxed> = signers
        .iter()
        .map(|&idx| {
            let sig = nodes[idx].public_key.sign(&to_sign).expect("failed to sign skip vote");
            VoteSignature { who: idx as i32, signature: sig.to_vec().into() }.into_boxed()
        })
        .collect();

    let sig_set = VoteSignatureSet { votes: tl_sigs.into() }.into_boxed();

    Certificate { vote: unsigned_vote, signatures: sig_set }.into_boxed()
}

fn make_test_final_cert(slot: SlotIndex, block_hash: UInt256) -> crate::certificate::FinalCertPtr {
    Arc::new(crate::certificate::Certificate {
        vote: crate::simplex_state::FinalizeVote { slot, block_hash },
        signatures: vec![
            crate::certificate::VoteSignature {
                validator_idx: ValidatorIndex::new(0),
                signature: vec![1u8; 64],
            },
            crate::certificate::VoteSignature {
                validator_idx: ValidatorIndex::new(1),
                signature: vec![2u8; 64],
            },
            crate::certificate::VoteSignature {
                validator_idx: ValidatorIndex::new(2),
                signature: vec![3u8; 64],
            },
        ],
    })
}

fn make_notar_vote_signature_set_bytes(
    session_id: &SessionId,
    nodes: &[SessionNode],
    slot: SlotIndex,
    block_hash: UInt256,
    signers: &[usize],
) -> Vec<u8> {
    let vote = crate::simplex_state::Vote::Notarize(crate::simplex_state::NotarizeVote {
        slot,
        block_hash,
    });
    let unsigned_vote =
        crate::utils::vote_to_tl_unsigned(&vote).expect("failed to build unsigned vote");
    let raw_vote_bytes = crate::utils::serialize_unsigned_vote(&unsigned_vote);
    let to_sign = crate::utils::create_data_to_sign(session_id, &raw_vote_bytes);

    let tl_sigs: Vec<VoteSignatureBoxed> = signers
        .iter()
        .map(|&idx| {
            let sig = nodes[idx].public_key.sign(&to_sign).expect("failed to sign notar vote");
            VoteSignature { who: idx as i32, signature: sig.to_vec().into() }.into_boxed()
        })
        .collect();

    let sig_set = VoteSignatureSet { votes: tl_sigs.into() }.into_boxed();
    serialize_boxed(&sig_set).expect("failed to serialize VoteSignatureSet")
}

// ============================================================================
// Startup recovery helpers (apply_bootstrap state-based tests)
// ============================================================================

fn make_candidate_id(slot: u32, hash_byte: u8) -> RawCandidateId {
    let mut hash = [0u8; 32];
    hash[0] = hash_byte;
    RawCandidateId { slot: SlotIndex::new(slot), hash: UInt256::from(hash) }
}

fn make_block_id(seqno: u32) -> BlockIdExt {
    BlockIdExt {
        shard_id: ShardIdent::masterchain(),
        seq_no: seqno,
        root_hash: UInt256::default(),
        file_hash: UInt256::default(),
    }
}

fn make_candidate_hash_data_with_parent(
    block_id: BlockIdExt,
    collated_file_hash: UInt256,
    parent: Option<RawCandidateId>,
) -> CandidateHashData {
    let parent_tl = match parent {
        None => CandidateParent::Consensus_CandidateWithoutParents,
        Some(parent_id) => {
            let tl_parent_id =
                TlCandidateId { slot: parent_id.slot.value() as i32, hash: parent_id.hash };
            CandidateParent::Consensus_CandidateParent(TlCandidateParent {
                id: CandidateIdBoxed::Consensus_CandidateId(tl_parent_id),
            })
        }
    };

    CandidateHashData::Consensus_CandidateHashDataOrdinary(CandidateHashDataOrdinary {
        block: block_id,
        collated_file_hash: collated_file_hash.into(),
        parent: parent_tl,
    })
}

fn make_candidate_hash_data_empty(
    referenced_block: BlockIdExt,
    parent: RawCandidateId,
) -> CandidateHashData {
    let tl_parent_id = TlCandidateId { slot: parent.slot.value() as i32, hash: parent.hash };

    CandidateHashData::Consensus_CandidateHashDataEmpty(CandidateHashDataEmpty {
        block: referenced_block,
        parent: tl_parent_id,
    })
}

fn make_validator_session_candidate_bytes(
    round: i32,
    root_hash: UInt256,
    data: Vec<u8>,
    collated_data: Vec<u8>,
) -> Vec<u8> {
    let tl_candidate =
        TlCandidate { src: UInt256::default(), round, root_hash, data, collated_data };

    consensus_common::serialize_tl_boxed_object!(&tl_candidate.into_boxed())
}

fn make_vote_record(
    node_idx: ValidatorIndex,
    vote: crate::simplex_state::Vote,
    session_id: &SessionId,
    nodes: &[SessionNode],
) -> crate::database::VoteRecord {
    let signer = &nodes[node_idx.value() as usize].public_key;
    let tl_vote = crate::utils::sign_vote(&vote, session_id, signer).expect("sign_vote failed");
    let serialized = serialize_boxed(&tl_vote).expect("serialize vote failed");
    let vote_hash = UInt256::from_slice(&sha256_digest(&serialized));
    crate::database::VoteRecord { vote_hash, data: serialized.into(), node_idx, seqno: 0 }
}

fn make_final_cert_record(
    session_id: &SessionId,
    nodes: &[SessionNode],
    candidate_id: RawCandidateId,
    signers: &[usize],
) -> crate::database::FinalCertRecord {
    let vote = crate::simplex_state::FinalizeVote {
        slot: candidate_id.slot,
        block_hash: candidate_id.hash.clone(),
    };
    let unsigned_vote =
        crate::utils::vote_to_tl_unsigned(&crate::simplex_state::Vote::Finalize(vote.clone()))
            .expect("build finalize unsigned vote");
    let raw_vote_bytes = crate::utils::serialize_unsigned_vote(&unsigned_vote);
    let to_sign = crate::utils::create_data_to_sign(session_id, &raw_vote_bytes);

    let signatures = signers
        .iter()
        .map(|&idx| {
            let signature = nodes[idx].public_key.sign(&to_sign).expect("sign finalize vote");
            crate::certificate::VoteSignature::new(
                ValidatorIndex::new(idx as u32),
                signature.to_vec(),
            )
        })
        .collect();

    let cert = crate::certificate::Certificate::new(vote, signatures);
    let tl_cert = cert.to_tl().expect("serialize final cert to TL");
    let cert_bytes = serialize_boxed(&tl_cert).expect("serialize final cert");

    crate::database::FinalCertRecord { candidate_id, cert_bytes: cert_bytes.into() }
}

fn make_skip_cert_record(
    session_id: &SessionId,
    nodes: &[SessionNode],
    slot: SlotIndex,
    signers: &[usize],
) -> crate::database::SkipCertRecord {
    let vote = crate::simplex_state::SkipVote { slot };
    let unsigned_vote =
        crate::utils::vote_to_tl_unsigned(&crate::simplex_state::Vote::Skip(vote.clone()))
            .expect("build skip unsigned vote");
    let raw_vote_bytes = crate::utils::serialize_unsigned_vote(&unsigned_vote);
    let to_sign = crate::utils::create_data_to_sign(session_id, &raw_vote_bytes);

    let signatures = signers
        .iter()
        .map(|&idx| {
            let signature = nodes[idx].public_key.sign(&to_sign).expect("sign skip vote");
            crate::certificate::VoteSignature::new(
                ValidatorIndex::new(idx as u32),
                signature.to_vec(),
            )
        })
        .collect();

    let cert = crate::certificate::Certificate::new(vote, signatures);
    let tl_cert = cert.to_tl().expect("serialize skip cert to TL");
    let cert_bytes = serialize_boxed(&tl_cert).expect("serialize skip cert");

    crate::database::SkipCertRecord { slot, cert_bytes: cert_bytes.into() }
}

/// Build an empty bootstrap (all sections empty). Tests populate the sections
/// they exercise; an all-empty bootstrap is treated as a fresh start and
/// `apply_bootstrap` returns early, so recovery tests must set at least one.
fn empty_bootstrap() -> crate::database::Bootstrap {
    crate::database::Bootstrap {
        own_journal: Vec::new(),
        finalized_blocks: vec![],
        candidate_infos: vec![],
        notar_certs: vec![],
        final_certs: vec![],
        skip_certs: vec![],
        votes: vec![],
        pool_state: None,
        candidate_payloads: vec![],
    }
}

/// Run startup recovery against the fixture's real `SessionProcessor`
/// (which implements `StartupRecoveryBackend`) and assert success.
fn run_apply_bootstrap(fixture: &mut TestFixture, bootstrap: crate::database::Bootstrap) {
    let session_id = fixture.description.get_session_id().clone();
    let recovery = crate::startup_recovery::SessionStartupRecoveryProcessor::new(
        session_id,
        fixture.description.clone(),
        bootstrap,
    );
    recovery.apply_bootstrap(&mut fixture.processor).expect("apply_bootstrap failed");
}

// ============================================================================
// Basic Tests
// ============================================================================

#[test]
fn test_session_processor_creation() {
    let fixture = TestFixture::new(4);
    assert_eq!(fixture.description.get_total_nodes(), 4);
    assert_eq!(fixture.description.get_self_idx(), ValidatorIndex::new(0));
}

#[test]
fn test_manual_clock_control() {
    let mut fixture = TestFixture::new_shard(4);

    // Seed manual time to a deterministic value first.
    //
    // Without this, `get_time()` starts as real time and the elapsed duration would
    // include scheduler/overhead jitter between reads.
    let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fixture.processor.set_time(base_time);

    let initial_time = fixture.description.get_time();

    // Advance time by 1 second
    fixture.advance_time(Duration::from_secs(1));

    let new_time = fixture.description.get_time();
    let elapsed = new_time.duration_since(initial_time).unwrap();
    assert_eq!(elapsed, Duration::from_secs(1));

    // Advance time by 5 more seconds
    fixture.advance_time(Duration::from_secs(5));

    let final_time = fixture.description.get_time();
    let total_elapsed = final_time.duration_since(initial_time).unwrap();
    assert_eq!(total_elapsed, Duration::from_secs(6));
}

#[test]
fn test_genesis_collation_expected_seqno_uses_initial_block_seqno() {
    // Regression test for single-host nets:
    // when collation starts with parent=None (first block in epoch), we must use
    // SessionDescription::initial_block_seqno instead of defaulting to 0.
    //
    // Without this, collation fails with:
    // `seqno mismatch: candidate has seqno=1, expected=0 (derived from parent=None)`
    let mut fixture = TestFixture::new_shard(4);

    // initial_block_seqno is set to 1 in create_test_desc()
    assert_eq!(fixture.description.get_initial_block_seqno(), 1);
    // Ensure the expected seqno does NOT depend on finalized_head_seqno when parent=None.
    fixture.processor.consensus.set_finalized_head_seqno(Some(123));

    let slot = SlotIndex::new(132);

    let genesis_block_id =
        BlockIdExt::with_params(ShardIdent::masterchain(), 1, UInt256::rand(), UInt256::rand());

    // Use valid BOC bytes — compress_candidate_data requires valid BOC input
    let block_boc = make_test_boc(&[0xAA], BocFlags::all());
    let collated_boc = make_test_boc(&[0xBB], BocFlags::Crc32);
    let candidate = crate::ValidatorBlockCandidate {
        public_key: fixture.nodes[0].public_key.clone(),
        id: genesis_block_id,
        collated_file_hash: UInt256::from_slice(&sha256_digest(&collated_boc)),
        data: consensus_common::ConsensusCommonFactory::create_block_payload(block_boc),
        collated_data: consensus_common::ConsensusCommonFactory::create_block_payload(collated_boc),
    };

    fixture
        .processor
        .create_normal_block_desc(slot, &candidate, &None)
        .expect("genesis collation must accept initial_block_seqno when parent is None");
}

#[test]
fn test_should_generate_empty_block_uses_committed_head_at_session_start() {
    // Masterchain uses finalized-head gating for empty-block generation (C++ parity:
    // `last_consensus_finalized_seqno_ + 1 < new_seqno`), while shardchains use
    // the MC lag threshold rule. Verify masterchain path.
    let nodes = create_test_validators(4);
    let local_idx = 0;
    let initial_block_seqno = 47;
    let local_key = nodes[local_idx].public_key.clone();
    let shard = ShardIdent::masterchain();
    let opts = SessionOptions::default();
    let description = Arc::new(
        crate::session_description::SessionDescription::new(
            &opts,
            SessionId::default(),
            initial_block_seqno,
            &nodes,
            local_key,
            &shard,
            SystemTime::now(),
            None,
        )
        .unwrap(),
    );

    let listener: Arc<dyn consensus_common::SessionListener + Send + Sync> = Arc::new(MockListener);
    let listener_weak = Arc::downgrade(&listener);

    let task_queue = TestTaskQueue::new();
    let callback_queue: CallbackTaskQueuePtr = Arc::new(TestCallbackQueue);
    let receiver = MockReceiver::new();
    let db = MockDb::new();

    let stop_flag = Arc::new(AtomicBool::new(false));
    let health_counters = Arc::new(crate::receiver::ReceiverHealthCounters::new());
    let callbacks = Arc::new(crate::session_callbacks::SessionCallbacks::new(
        description.get_session_id().clone(),
        stop_flag.clone(),
        false,
        callback_queue,
        listener_weak,
    ));
    let processor = SessionProcessor::new(
        description,
        make_start_prev_blocks(&shard, initial_block_seqno),
        task_queue.clone() as TaskQueuePtr,
        receiver.clone() as crate::receiver::ReceiverPtr,
        stop_flag,
        db,
        0,
        health_counters,
        callbacks,
        None,
        0,
    )
    .unwrap();

    assert_eq!(processor.consensus.finalized_head_seqno(), Some(46));

    // Slot 0 is the initial `first_non_progressed_slot` in fresh state.
    // MC: new_seqno=48, finalized_head=46 -> 46+1=47 < 48 -> empty
    assert!(processor.collation.should_generate_empty_block(
        SlotIndex::new(0),
        48,
        None,
        processor.consensus.finalized_head_before_split(),
        processor.consensus.last_consensus_finalized_seqno(),
        processor.consensus.last_mc_finalized_seqno(),
    ));
    assert!(
        processor.collation.should_generate_empty_block(
            SlotIndex::new(1),
            48,
            None,
            processor.consensus.finalized_head_before_split(),
            processor.consensus.last_consensus_finalized_seqno(),
            processor.consensus.last_mc_finalized_seqno(),
        ),
        "C++ parity: empty-block fallback must also apply to future slots in the same window"
    );
    // MC: new_seqno=47, finalized_head=46 -> 46+1=47 == 47 -> NOT empty
    assert!(!processor.collation.should_generate_empty_block(
        SlotIndex::new(0),
        47,
        None,
        processor.consensus.finalized_head_before_split(),
        processor.consensus.last_consensus_finalized_seqno(),
        processor.consensus.last_mc_finalized_seqno(),
    ));
}

#[test]
fn test_out_of_order_finalized_delivery_emits_immediately_when_body_present() {
    let mut opts = SessionOptions::default();
    opts.use_callback_thread = false;
    let mut fixture = TestFixture::new_with_opts(4, opts);

    let recording = RecordingListener::new();
    let listener: Arc<dyn consensus_common::SessionListener + Send + Sync> = recording.clone();
    fixture.processor.set_listener_for_test(Arc::downgrade(&listener));

    // Set finalized head high so this test isolates finalized-delivery callback.
    fixture.processor.consensus.set_finalized_head_seqno(Some(100));
    fixture.processor.consensus.set_finalized_head_block_id(Some(BlockIdExt::with_params(
        ShardIdent::masterchain(),
        100,
        UInt256::rand(),
        UInt256::rand(),
    )));

    let slot = 103u32;
    let (leader_source, candidate_id, broadcast) =
        make_signed_block_broadcast(&fixture, slot, vec![7u8, 8, 9, 10]);
    fixture.processor.on_candidate_received(leader_source, broadcast, None);

    let received = fixture
        .processor
        .candidate_book()
        .received(&candidate_id)
        .expect("candidate should be present")
        .clone();

    let event = BlockFinalizedEvent {
        slot: candidate_id.slot,
        block_hash: candidate_id.hash.clone(),
        block_id: Some(received.block_id.clone()),
        certificate: make_test_final_cert(candidate_id.slot, candidate_id.hash.clone()),
    };
    fixture.processor.handle_block_finalized(event);

    let events = recording.drain_events();
    assert!(
        events.iter().any(|e| matches!(
            e,
            ListenerEvent::Finalized { block_id, root_hash, .. }
                if block_id == &received.block_id && root_hash == &received.root_hash
        )),
        "out-of-order finalized callback must be emitted when body is already known"
    );
    assert!(
        !events.iter().any(|e| matches!(e, ListenerEvent::Committed { .. })),
        "on_block_committed must be suppressed in out-of-order mode"
    );
    assert!(
        fixture.processor.consensus.finalized_pending_body_is_empty(),
        "no pending-body retention expected when finalized body is already present"
    );
    assert!(
        fixture.processor.requested_candidates().is_empty(),
        "finalized-driven mode must not request missing candidates"
    );
}

#[test]
fn test_out_of_order_finalized_delivery_emits_when_body_arrives_late_and_dedups() {
    let mut opts = SessionOptions::default();
    opts.use_callback_thread = false;
    let mut fixture = TestFixture::new_with_opts(4, opts);

    let recording = RecordingListener::new();
    let listener: Arc<dyn consensus_common::SessionListener + Send + Sync> = recording.clone();
    fixture.processor.set_listener_for_test(Arc::downgrade(&listener));

    // Set finalized head high so this test isolates finalized-delivery callback.
    fixture.processor.consensus.set_finalized_head_seqno(Some(70));
    fixture.processor.consensus.set_finalized_head_block_id(Some(BlockIdExt::with_params(
        ShardIdent::masterchain(),
        70,
        UInt256::rand(),
        UInt256::rand(),
    )));

    let slot = 77u32;
    let block_data = vec![0xA5, 0x5A, 0xCC, 0x33];
    let (leader_source, candidate_id, broadcast) =
        make_signed_block_broadcast(&fixture, slot, block_data.clone());

    // Finalization observed first (before full candidate body is known).
    let root_hash = UInt256::from_slice(&sha256_digest(&block_data));
    let block_id = BlockIdExt {
        shard_id: fixture.processor.runtime.description().get_shard().clone(),
        seq_no: slot,
        root_hash: root_hash.clone(),
        file_hash: root_hash,
    };
    let event = BlockFinalizedEvent {
        slot: candidate_id.slot,
        block_hash: candidate_id.hash.clone(),
        block_id: Some(block_id.clone()),
        certificate: make_test_final_cert(candidate_id.slot, candidate_id.hash.clone()),
    };
    fixture.processor.handle_block_finalized(event.clone());
    // Drain the deferred `request_candidate` bounce onto SXMAIN.
    fixture.run_pending_tasks();

    assert!(
        recording.drain_events().is_empty(),
        "no finalized callback before candidate body is available"
    );
    assert!(
        fixture.processor.requested_candidates().contains_key(&candidate_id),
        "recursive finalization must request missing trigger body/cert immediately"
    );

    // Body arrives later: delayed finalized-delivery path should emit callback now.
    fixture.processor.on_candidate_received(leader_source, broadcast, None);
    let events_after_body = recording.drain_events();
    let finalized_count = events_after_body
        .iter()
        .filter(|e| matches!(e, ListenerEvent::Finalized { block_id: id, .. } if id == &block_id))
        .count();
    assert_eq!(
        finalized_count, 1,
        "exactly one finalized callback expected after late body arrival"
    );
    assert!(
        !events_after_body.iter().any(|e| matches!(e, ListenerEvent::Committed { .. })),
        "on_block_committed must stay suppressed in out-of-order mode"
    );
    assert!(
        fixture.processor.requested_candidates().is_empty(),
        "request bookkeeping must clear once the missing body arrives"
    );

    // Duplicate finalization observation should not re-emit callback.
    fixture.processor.handle_block_finalized(event);
    let events_after_duplicate = recording.drain_events();
    assert!(
        !events_after_duplicate
            .iter()
            .any(|e| matches!(e, ListenerEvent::Finalized { block_id: id, .. } if id == &block_id)),
        "duplicate finalized observation must be deduplicated"
    );
}

#[test]
fn test_out_of_order_mode_does_not_run_commit_chain_recovery_for_missing_body() {
    let mut opts = SessionOptions::default();
    opts.use_callback_thread = false;
    let mut fixture = TestFixture::new_with_opts(4, opts);

    // No candidate body is inserted.
    let slot = SlotIndex::new(55);
    let block_hash = UInt256::rand();
    let block_id =
        BlockIdExt::with_params(ShardIdent::masterchain(), 55, UInt256::rand(), UInt256::rand());
    let finalized_id = RawCandidateId { slot, hash: block_hash.clone() };

    let event = BlockFinalizedEvent {
        slot,
        block_hash: block_hash.clone(),
        block_id: Some(block_id),
        certificate: make_test_final_cert(slot, block_hash),
    };
    fixture.processor.handle_block_finalized(event);
    // Drain the deferred `request_candidate` bounce onto SXMAIN.
    fixture.run_pending_tasks();

    assert!(
        fixture.processor.consensus.finalized_pending_body_contains(&finalized_id),
        "finalization should be buffered until body arrival"
    );
    assert!(
        !fixture.processor.candidate_book().contains_received(&finalized_id),
        "finalized-driven mode must not seed stubs for missing bodies"
    );
    assert!(
        fixture.processor.requested_candidates().contains_key(&finalized_id),
        "missing finalized trigger body must schedule a repair request"
    );

    // Periodic scheduler path should also avoid candidate recovery.
    fixture.processor.check_all();
    assert!(
        fixture.processor.requested_candidates().contains_key(&finalized_id),
        "check_all must keep the pending repair tracked until body arrival"
    );
}

#[test]
fn test_check_all_updates_awake_time() {
    let mut fixture = TestFixture::new(4);

    let before = fixture.processor.get_next_awake_time();

    // Call check_all (should reset awake time)
    fixture.processor.check_all();

    let after = fixture.processor.get_next_awake_time();

    // Awake time should be updated (pushed into future)
    assert!(after >= before);
}

#[test]
fn test_start_arms_timeout_from_current_time_after_cold_delay() {
    let mut fixture = TestFixture::new(4);
    let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fixture.processor.set_time(base_time);

    // Constructor path must not arm startup skip timers.
    assert!(
        fixture.processor.simplex_state.get_next_timeout().is_none(),
        "startup timeout must not be armed before start()"
    );

    // Simulate prolonged cold startup / delayed readiness.
    fixture.processor.advance_time(Duration::from_secs(120));
    let now = fixture.description.get_time();

    fixture.processor.start();

    let timeout = fixture
        .processor
        .simplex_state
        .get_next_timeout()
        .expect("startup timeout must be scheduled after start()");
    let opts = fixture.description.opts();
    let expected = now + opts.first_block_timeout + opts.target_rate;
    assert_eq!(
        timeout, expected,
        "startup timeout must be anchored to start() time, not constructor time \
        (C++ ref: alarm = now + first_block_timeout + target_rate)"
    );
}

#[test]
fn test_receiver_records_no_actions_initially() {
    let fixture = TestFixture::new(4);
    let actions = fixture.drain_receiver_actions();
    assert!(
        actions.iter().all(|a| {
            matches!(a, ReceiverAction::SetIngressSlotBegin { slot: 0 })
                || matches!(a, ReceiverAction::SetIngressProgressSlot { slot: 0 })
                || matches!(a, ReceiverAction::SetStandstillSlots { begin: 0, .. })
        }),
        "Expected only initial ingress/standstill sync actions"
    );
}

#[test]
fn test_check_all_syncs_standstill_slots_when_tracked_interval_changes() {
    let mut fixture = TestFixture::new(4);
    fixture.drain_receiver_actions();

    fixture.processor.check_all();
    let initial_actions = fixture.drain_receiver_actions();
    assert!(
        !initial_actions.iter().any(|a| matches!(a, ReceiverAction::SetStandstillSlots { .. })),
        "unchanged tracked interval should not resync standstill slots"
    );

    fixture.processor.simplex_state.set_first_non_finalized_slot(crate::block::SlotIndex::new(4));
    let (expected_begin, expected_end) =
        fixture.processor.simplex_state.get_tracked_slots_interval();

    fixture.processor.check_all();
    let actions = fixture.drain_receiver_actions();
    assert!(
        actions.iter().any(|a| matches!(
            a,
            ReceiverAction::SetStandstillSlots { begin, end }
                if *begin == expected_begin && *end == expected_end
        )),
        "check_all must resync receiver standstill slots when the FSM tracked interval changes"
    );
}

// ============================================================================
// Certificate relay / standstill cache tests
// ============================================================================

#[test]
fn test_on_certificate_relays_and_caches_skip_certificate_once() {
    let mut fixture = TestFixture::new(4);

    // Build a valid skip certificate (threshold_66 for 4 validators is 3)
    let slot = 0u32;
    let tl_cert =
        build_skip_certificate_tl(&SessionId::default(), &fixture.nodes, slot, &[0, 1, 2]);

    // First application should store + relay + cache
    fixture.processor.on_certificate(1, tl_cert.clone());
    // SXMAIN async-DB-results registry: drain so the skip persist continuation runs
    // (relay + cache happen in the continuation post-migration).
    fixture.drain_pending_async_db_results();

    let actions = fixture.drain_receiver_actions();
    let send_cert_count =
        actions.iter().filter(|a| matches!(a, ReceiverAction::SendCertificate { .. })).count();
    let cache_standstill_count = actions
        .iter()
        .filter(|a| {
            matches!(
                a,
                ReceiverAction::CacheStandstillCertificate {
                    slot: s,
                    kind: crate::receiver::StandstillCertificateType::Skip,
                    ..
                } if *s == slot
            )
        })
        .count();

    // C++ parity (pool.cpp handle_saved_certificate): every newly accepted
    // certificate is relayed once, regardless of origin.
    assert_eq!(send_cert_count, 1, "C++ parity: foreign skip cert must be relayed once");
    assert_eq!(
        cache_standstill_count, 1,
        "expected exactly one cache_standstill_certificate on first apply"
    );

    // Second application should be ignored (already have skip certificate), so no relay/caching
    fixture.processor.on_certificate(1, tl_cert);
    fixture.drain_pending_async_db_results();
    let actions2 = fixture.drain_receiver_actions();
    assert!(
        !actions2.iter().any(|a| matches!(a, ReceiverAction::SendCertificate { .. })),
        "should not relay duplicate skip certificate"
    );
    assert!(
        !actions2.iter().any(|a| matches!(a, ReceiverAction::CacheStandstillCertificate { .. })),
        "should not cache duplicate skip certificate"
    );
}

#[test]
fn test_queued_certificate_duplicates_skip_verification_and_effects_like_cpp() {
    for kind in 0..3 {
        for source in [Some(1u32), None] {
            let mut fixture = TestFixture::new(4);
            let make = |session: &SessionId, kind, slot: u32, hash: UInt256| {
                use rtos_api::ton::consensus::simplex::unsignedvote;
                let id = TlCandidateId { slot: slot as i32, hash }.into_boxed();
                let vote = match kind {
                    0 => unsignedvote::NotarizeVote { id }.into_boxed(),
                    1 => unsignedvote::SkipVote { slot: slot as i32 }.into_boxed(),
                    _ => unsignedvote::FinalizeVote { id }.into_boxed(),
                };
                let preimage = crate::utils::create_data_to_sign(
                    session,
                    &crate::utils::serialize_unsigned_vote(&vote),
                );
                let signatures = (0..3)
                    .map(|index| {
                        VoteSignature {
                            who: index as i32,
                            signature: fixture.nodes[index]
                                .public_key
                                .sign(&preimage)
                                .unwrap()
                                .to_vec(),
                        }
                        .into_boxed()
                    })
                    .collect();
                Certificate {
                    vote,
                    signatures: VoteSignatureSet { votes: signatures }.into_boxed(),
                }
                .into_boxed()
            };
            let hash = UInt256::from([0x51; 32]);
            let valid = make(fixture.description.get_session_id(), kind, 5, hash.clone());
            let other_slot = make(fixture.description.get_session_id(), kind, 6, hash.clone());
            let wrong_context =
                make(&UInt256::from([0x91; 32]), kind, 5, UInt256::from([0x52; 32]));
            let unknown_wrong_context = make(&UInt256::from([0x91; 32]), kind, 6, hash.clone());
            let other_kind_wrong_context =
                make(&UInt256::from([0x91; 32]), 1 - kind.min(1), 5, hash);
            // Call the actor ingress directly: these messages already passed
            // the receiver before its acceptance notification could filter them.
            assert!(fixture.processor.with_consensus_backend(|c, b| c.on_certificate(
                b,
                source,
                valid.clone()
            )));
            fixture.drain_receiver_actions();
            let queued = fixture.task_queue.tasks.lock().unwrap().len();
            let progress = fixture.processor.simplex_state.get_first_non_progressed_slot();
            for duplicate in [valid, wrong_context] {
                assert!(
                    !fixture
                        .processor
                        .with_consensus_backend(|c, b| c.on_certificate(b, source, duplicate)),
                    "a known kind/slot must not verify again or pump the FSM"
                );
            }
            assert_eq!(
                fixture.processor.telemetry.cert_verify_fails_total.load(Ordering::Relaxed),
                0,
                "known-kind ingress must stop before crypto, including another hash/context"
            );
            assert!(fixture.drain_receiver_actions().is_empty());
            assert_eq!(fixture.task_queue.tasks.lock().unwrap().len(), queued);
            assert_eq!(fixture.processor.simplex_state.get_first_non_progressed_slot(), progress);
            assert!(!fixture.processor.with_consensus_backend(|c, b| c.on_certificate(
                b,
                source,
                unknown_wrong_context
            )));
            assert_eq!(
                fixture.processor.telemetry.cert_verify_fails_total.load(Ordering::Relaxed),
                1,
                "a new slot still requires full verification"
            );
            if kind != 2 {
                assert!(!fixture.processor.with_consensus_backend(|c, b| c.on_certificate(
                    b,
                    source,
                    other_kind_wrong_context
                )));
                assert_eq!(
                    fixture.processor.telemetry.cert_verify_fails_total.load(Ordering::Relaxed),
                    2,
                    "another kind in the same live slot still requires verification"
                );
            }
            assert!(
                fixture
                    .processor
                    .with_consensus_backend(|c, b| c.on_certificate(b, source, other_slot)),
                "a valid new slot remains admissible"
            );
        }
    }
}

#[test]
fn test_certificate_ingress_excludes_upper_boundary_before_verification() {
    for source in [Some(1), None] {
        let mut opts = SessionOptions::default();
        opts.slots_per_leader_window = 4;
        opts.max_leader_window_desync = 2;
        let mut fixture = TestFixture::new_with_opts(4, opts);
        fixture.drain_receiver_actions();
        let boundary = fixture.processor.simplex_state.first_too_new_vote_slot().value();
        assert_eq!(boundary, 12);
        let id =
            TlCandidateId { slot: boundary as i32, hash: UInt256::from([42; 32]) }.into_boxed();
        let votes: Vec<rtos_api::ton::consensus::simplex::UnsignedVote> = vec![
            SkipVote { slot: boundary as i32 }.into_boxed(),
            rtos_api::ton::consensus::simplex::unsignedvote::NotarizeVote { id: id.clone() }
                .into_boxed(),
            rtos_api::ton::consensus::simplex::unsignedvote::FinalizeVote { id }.into_boxed(),
        ];
        for vote in votes {
            for session in [SessionId::default(), UInt256::from([77; 32])] {
                let preimage = crate::utils::create_data_to_sign(
                    &session,
                    &crate::utils::serialize_unsigned_vote(&vote),
                );
                let signatures = (0..3)
                    .map(|index| {
                        VoteSignature {
                            who: index as i32,
                            signature: fixture.nodes[index]
                                .public_key
                                .sign(&preimage)
                                .unwrap()
                                .to_vec(),
                        }
                        .into_boxed()
                    })
                    .collect();
                let certificate = Certificate {
                    vote: vote.clone(),
                    signatures: VoteSignatureSet { votes: signatures }.into_boxed(),
                }
                .into_boxed();
                fixture.processor.on_certificate(source, certificate);
            }
        }
        fixture.drain_pending_async_db_results();
        assert!(
            !fixture.processor.simplex_state.has_skip_certificate(SlotIndex::new(boundary)),
            "exclusive ingress boundary cannot be admitted"
        );
        assert!(!fixture
            .processor
            .simplex_state
            .has_finalize_certificate(SlotIndex::new(boundary)));
        assert_eq!(
            fixture
                .processor
                .simplex_state
                .get_notarize_weight(SlotIndex::new(boundary), &UInt256::from([42; 32])),
            0
        );
        assert_eq!(
            fixture.processor.simplex_state.get_first_non_progressed_slot(),
            SlotIndex::new(0)
        );
        assert_eq!(
            fixture.processor.telemetry.cert_verify_fails_total.load(Ordering::Relaxed),
            0,
            "out-of-window certificate must not reach signature verification"
        );
        assert!(
            fixture.drain_receiver_actions().is_empty(),
            "rejected ingress cannot persist, relay, request candidates or ban its source"
        );
    }
}

#[test]
fn test_certificate_ingress_accepts_inside_boundary_and_after_progress() {
    let mut opts = SessionOptions::default();
    opts.slots_per_leader_window = 4;
    opts.max_leader_window_desync = 2;
    let mut fixture = TestFixture::new_with_opts(4, opts);
    fixture.drain_receiver_actions();
    let boundary = fixture.processor.simplex_state.first_too_new_vote_slot().value();
    let at_boundary =
        build_skip_certificate_tl(&SessionId::default(), &fixture.nodes, boundary, &[0, 1, 2]);
    fixture.processor.on_certificate(1, at_boundary.clone());
    assert!(!fixture.processor.simplex_state.has_skip_certificate(SlotIndex::new(boundary)));
    let inside =
        build_skip_certificate_tl(&SessionId::default(), &fixture.nodes, boundary - 1, &[0, 1, 2]);
    fixture.processor.on_certificate(1, inside);
    fixture.drain_pending_async_db_results();
    assert!(fixture.processor.simplex_state.has_skip_certificate(SlotIndex::new(boundary - 1)));
    for slot in 0..4 {
        let cert =
            build_skip_certificate_tl(&SessionId::default(), &fixture.nodes, slot, &[0, 1, 2]);
        fixture.processor.on_certificate(1, cert);
        fixture.drain_pending_async_db_results();
    }
    assert!(fixture.processor.simplex_state.first_too_new_vote_slot().value() > boundary);
    fixture.processor.on_certificate(1, at_boundary);
    fixture.drain_pending_async_db_results();
    assert!(
        fixture.processor.simplex_state.has_skip_certificate(SlotIndex::new(boundary)),
        "the same certificate becomes admissible when real progress opens its window"
    );
}

// ============================================================================
// Bad-signature peer-ban tests
// ============================================================================

/// A certificate that fails `Certificate::from_tl` verification
/// (e.g. signed against the wrong session) must trigger a temporary peer ban for
/// the source via `receiver.ban_source_for_bad_signature(source_idx)`.
///
/// C++ parity: `pool.cpp::handle(IncomingProtocolMessage)` calls `ban(message->source)`
/// when `Certificate::from_tl` reports an error.
#[test]
fn test_on_certificate_bad_signature_triggers_temporary_ban() {
    let mut fixture = TestFixture::new(4);
    fixture.drain_receiver_actions();

    // Sign the skip certificate against a foreign session id so the local
    // SessionProcessor's signature verification fails deterministically.
    let foreign_session_id = SessionId::rand();
    let bad_cert = build_skip_certificate_tl(&foreign_session_id, &fixture.nodes, 0, &[0, 1, 2]);

    let source_idx = 1u32;
    fixture.processor.on_certificate(source_idx, bad_cert);

    let actions = fixture.drain_receiver_actions();

    let ban_count = actions
        .iter()
        .filter(|a| {
            matches!(
                a,
                ReceiverAction::BanSourceForBadSignature { source_idx: s } if *s == source_idx
            )
        })
        .count();
    assert_eq!(
        ban_count, 1,
        "bad-signature certificate must trigger exactly one ban_source_for_bad_signature call \
         for the offending source"
    );

    assert!(
        !actions.iter().any(|a| matches!(a, ReceiverAction::SendCertificate { .. })),
        "rejected certificate must not be relayed"
    );
    assert!(
        !actions.iter().any(|a| matches!(a, ReceiverAction::CacheStandstillCertificate { .. })),
        "rejected certificate must not be cached for standstill"
    );

    assert_eq!(
        metrics_counter(&fixture.processor, "simplex_cert_verify_fail"),
        1,
        "cert_verify_fail counter must increment for invalid certificate"
    );
}

/// Well-signed certificates must NOT result in peer-ban side
/// effects, even if dispatched repeatedly. This guards against false-positive
/// bans during legitimate standstill rebroadcasts.
#[test]
fn test_on_certificate_valid_signature_does_not_ban() {
    let mut fixture = TestFixture::new(4);
    fixture.drain_receiver_actions();

    let slot = 0u32;
    let cert = build_skip_certificate_tl(
        fixture.description.get_session_id(),
        &fixture.nodes,
        slot,
        &[0, 1, 2],
    );

    fixture.processor.on_certificate(1, cert);

    let actions = fixture.drain_receiver_actions();
    assert!(
        !actions.iter().any(|a| matches!(a, ReceiverAction::BanSourceForBadSignature { .. })),
        "validly signed certificate must not trigger a ban"
    );
}

#[test]
fn test_handle_finalization_reached_caches_final_certificate_for_standstill() {
    let mut fixture = TestFixture::new(4);

    let slot = crate::block::SlotIndex::new(7);
    let block_hash = UInt256::rand();

    // Create a finalization certificate with sufficient weight (3 out of 4)
    let signatures = vec![
        crate::certificate::VoteSignature::new(ValidatorIndex::new(0), vec![0]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(1), vec![1]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(2), vec![2]),
    ];
    let vote = crate::simplex_state::FinalizeVote { slot, block_hash: block_hash.clone() };
    let cert = Arc::new(crate::certificate::Certificate { vote, signatures });

    let event = crate::simplex_state::FinalizationReachedEvent {
        slot,
        block_hash: block_hash.clone(),
        certificate: cert,
    };

    fixture.processor.handle_finalization_reached(event);

    // Persist + cache + relay are async (registry continuation); drain before asserting.
    fixture.drain_pending_async_db_results();

    let actions = fixture.drain_receiver_actions();
    assert!(
        actions.iter().any(|a| matches!(
            a,
            ReceiverAction::CacheStandstillCertificate {
                slot: s,
                kind: crate::receiver::StandstillCertificateType::Final,
                ..
            } if *s == slot.value()
        )),
        "expected final cert to be cached in standstill bundle"
    );
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, ReceiverAction::CacheLastFinalCertificate { slot: s, .. } if *s == slot.value())),
        "expected last final certificate to be cached"
    );
}

#[test]
fn test_handle_notarization_reached_persists_before_relay() {
    let mut fixture = TestFixture::new(4);

    let slot = crate::block::SlotIndex::new(9);
    let block_hash = UInt256::rand();
    let candidate_id = RawCandidateId { slot, hash: block_hash.clone() };
    let signatures = vec![
        crate::certificate::VoteSignature::new(ValidatorIndex::new(0), vec![1]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(1), vec![2]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(2), vec![3]),
    ];
    let vote = crate::simplex_state::NotarizeVote { slot, block_hash: block_hash.clone() };
    let cert = Arc::new(crate::certificate::Certificate { vote, signatures });
    let event =
        crate::simplex_state::NotarizationReachedEvent { slot, block_hash, certificate: cert };

    fixture.processor.handle_notarization_reached(event);

    // Drain the SXMAIN async-DB-results registry: storage thread completes the
    // notar persist, registry continuation runs broadcast + cache.
    fixture.drain_pending_async_db_results();

    assert!(
        fixture
            .processor
            .database
            .db()
            .load_notar_cert_by_id(&candidate_id, Duration::from_secs(1))
            .expect("notar cert lookup must succeed")
            .is_some(),
        "notar cert must be persisted in DB after the registry continuation runs"
    );

    let actions = fixture.drain_receiver_actions();
    assert!(
        actions.iter().any(|a| matches!(a, ReceiverAction::SendCertificate { .. })),
        "notar cert should be relayed after successful persistence"
    );
}

#[test]
fn test_handle_finalization_reached_persists_before_relay() {
    let mut fixture = TestFixture::new(4);

    let slot = crate::block::SlotIndex::new(10);
    let block_hash = UInt256::rand();
    let candidate_id = RawCandidateId { slot, hash: block_hash.clone() };
    let signatures = vec![
        crate::certificate::VoteSignature::new(ValidatorIndex::new(0), vec![11]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(1), vec![12]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(2), vec![13]),
    ];
    let vote = crate::simplex_state::FinalizeVote { slot, block_hash: block_hash.clone() };
    let cert = Arc::new(crate::certificate::Certificate { vote, signatures });
    let event =
        crate::simplex_state::FinalizationReachedEvent { slot, block_hash, certificate: cert };

    fixture.processor.handle_finalization_reached(event);

    // Drain the SXMAIN async-DB-results registry: storage thread completes the
    // final persist, registry continuation runs broadcast + cache + standstill update.
    fixture.drain_pending_async_db_results();

    assert!(
        fixture
            .processor
            .database
            .db()
            .load_final_cert_by_id(&candidate_id, Duration::from_secs(1))
            .expect("final cert lookup must succeed")
            .is_some(),
        "final cert must be persisted in DB after the registry continuation runs"
    );

    let actions = fixture.drain_receiver_actions();
    assert!(
        actions.iter().any(|a| matches!(a, ReceiverAction::SendCertificate { .. })),
        "final cert should be relayed after successful persistence"
    );
}

#[test]
fn test_handle_skip_certificate_reached_persists_before_relay() {
    let mut fixture = TestFixture::new(4);

    let slot = crate::block::SlotIndex::new(11);
    let signatures = vec![
        crate::certificate::VoteSignature::new(ValidatorIndex::new(0), vec![21]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(1), vec![22]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(2), vec![23]),
    ];
    let vote = crate::simplex_state::SkipVote { slot };
    let cert = Arc::new(crate::certificate::Certificate { vote, signatures });
    let event = crate::simplex_state::SkipCertificateReachedEvent { slot, certificate: cert };

    fixture.processor.handle_skip_certificate_reached(event);

    // Drain the SXMAIN async-DB-results registry: storage thread completes the
    // skip persist, registry continuation runs broadcast + cache.
    fixture.drain_pending_async_db_results();

    assert!(
        fixture
            .processor
            .database
            .db()
            .load_skip_cert_by_slot(slot, Duration::from_secs(1))
            .expect("skip cert lookup must succeed")
            .is_some(),
        "skip cert must be persisted in DB after the registry continuation runs"
    );

    let actions = fixture.drain_receiver_actions();
    assert!(
        actions.iter().any(|a| matches!(a, ReceiverAction::SendCertificate { .. })),
        "skip cert should be relayed after successful persistence"
    );
}

/// Regression: do not prune the seqno-keyed callback dedup while
/// old `received_candidates` are still retained.
///
/// The original panic happened after `cleanup_old_slots` pruned the slot-keyed
/// `finalized_delivery_sent` entry, while `received_candidates` still kept the
/// old ancestor reachable. If we also prune `finalized_delivery_sent_seqno` here,
/// the next recursive parent-chain walk can emit the same finalized callback a
/// second time. The seqno map must therefore outlive slot-keyed dedup until old
/// received-candidate metadata is pruned under the same invariant.
#[test]
fn test_cleanup_old_slots_keeps_seqno_dedup_while_received_candidates_are_retained() {
    let mut opts = SessionOptions::default();
    opts.use_callback_thread = false;
    let mut fixture = TestFixture::new_with_opts(4, opts);

    let recording = RecordingListener::new();
    let listener: Arc<dyn consensus_common::SessionListener + Send + Sync> = recording.clone();
    fixture.processor.set_listener_for_test(Arc::downgrade(&listener));

    let old_slot = SlotIndex::new(10);
    let old_hash = UInt256::from([0xAA; 32]);
    let old_candidate_id = RawCandidateId { slot: old_slot, hash: old_hash.clone() };
    let old_block_id = BlockIdExt {
        shard_id: ShardIdent::masterchain(),
        seq_no: 100,
        root_hash: UInt256::from([0xAB; 32]),
        file_hash: UInt256::from([0xAC; 32]),
    };
    let received = ReceivedCandidate {
        slot: old_slot,
        source_idx: ValidatorIndex::new(0),
        candidate_hash_data_bytes: vec![1, 2, 3],
        block_id: old_block_id.clone(),
        root_hash: old_block_id.root_hash.clone(),
        file_hash: old_block_id.file_hash.clone(),
        data: consensus_common::ConsensusCommonFactory::create_block_payload(Vec::new()),
        collated_data: consensus_common::ConsensusCommonFactory::create_block_payload(Vec::new()),
        gen_utime_ms: None,
        receive_time: SystemTime::now(),
        is_empty: false,
        parent_id: None,
    };

    fixture.processor.consensus.insert_finalized_delivery_sent(old_candidate_id.clone());
    fixture.processor.consensus.insert_finalized_delivery_sent_seqno(
        old_block_id.seq_no(),
        old_slot,
        old_block_id.clone(),
    );
    fixture
        .processor
        .candidate_book_mut()
        .insert_received(old_candidate_id.clone(), received.clone());

    // cleanup_old_slots(MAX_HISTORY_SLOTS) computes up_to_slot = 1, so slot=0
    // entries would be the only ones cleaned. Using slot=10 above guarantees the
    // "old" entry sits below the cutoff once we bump the cleanup boundary.
    fixture.processor.cleanup_old_slots(SlotIndex::new(MAX_HISTORY_SLOTS + old_slot.value() + 1));

    assert!(
        !fixture.processor.consensus.finalized_delivery_sent_contains(&old_candidate_id),
        "pre-existing slot-keyed dedup pruning must continue to work"
    );
    assert!(
        fixture.processor.candidate_book().contains_received(&old_candidate_id),
        "old received candidates are still retained today; pruning seqno dedup before this \
         metadata is gone would allow duplicate callback emission"
    );
    assert!(
        fixture.processor.consensus.finalized_delivery_sent_seqno_contains(old_block_id.seq_no()),
        "seqno-keyed dedup must remain while old candidate metadata remains reachable"
    );

    let mut complete = true;
    fixture.processor.try_emit_recursive_finalized_callback(
        &old_candidate_id,
        &received,
        &BlockFinalizedEvent {
            slot: old_slot,
            block_hash: old_hash.clone(),
            block_id: Some(old_block_id.clone()),
            certificate: make_test_final_cert(old_slot, old_hash),
        },
        /*has_final_cert=*/ true,
        old_slot,
        &[1, 2, 3],
        &mut complete,
    );

    assert!(complete);
    assert!(
        drain_finalized_events(&recording).is_empty(),
        "idempotent re-entry after slot-keyed cleanup must not emit a second finalized callback"
    );
    assert!(fixture.processor.consensus.finalized_delivery_sent_contains(&old_candidate_id));
}

/// Regression: `try_emit_recursive_finalized_callback` must treat a
/// second emit attempt for the **same** `block_id` at the same seqno as
/// idempotent (no panic, no double-callback) and only assert when a
/// **different** `block_id` would be reported for an already-delivered seqno.
///
/// This protects against the deep recursive parent-chain walk re-entering an
/// already-delivered ancestor whose slot-keyed `finalized_delivery_sent` entry
/// was pruned by `cleanup_old_slots` while the seqno-keyed dedup still remembers
/// the delivered block.
#[test]
fn test_try_emit_recursive_finalized_callback_idempotent_on_same_block_id() {
    let mut fixture = TestFixture::new(4);

    let slot = SlotIndex::new(5);
    let hash = UInt256::from([0xCC; 32]);
    let candidate_id = RawCandidateId { slot, hash: hash.clone() };
    let block_id = BlockIdExt {
        shard_id: ShardIdent::masterchain(),
        seq_no: 42,
        root_hash: UInt256::from([0xDD; 32]),
        file_hash: UInt256::from([0xEE; 32]),
    };

    // Seed the seqno-dedup map as if the callback already fired once.
    fixture.processor.consensus.insert_finalized_delivery_sent_seqno(
        block_id.seq_no(),
        slot,
        block_id.clone(),
    );
    // Simulate that the slot-keyed dedup was pruned by cleanup_old_slots —
    // i.e. `finalized_delivery_sent` does NOT contain this candidate_id.
    assert!(!fixture.processor.consensus.finalized_delivery_sent_contains(&candidate_id));

    let received = ReceivedCandidate {
        slot,
        source_idx: ValidatorIndex::new(0),
        candidate_hash_data_bytes: vec![1, 2, 3],
        block_id: block_id.clone(),
        root_hash: block_id.root_hash.clone(),
        file_hash: block_id.file_hash.clone(),
        data: consensus_common::ConsensusCommonFactory::create_block_payload(Vec::new()),
        collated_data: consensus_common::ConsensusCommonFactory::create_block_payload(Vec::new()),
        gen_utime_ms: None,
        receive_time: SystemTime::now(),
        is_empty: false,
        parent_id: None,
    };

    let dummy_event = BlockFinalizedEvent {
        slot,
        block_hash: hash.clone(),
        block_id: Some(block_id.clone()),
        certificate: Arc::new(crate::certificate::Certificate {
            vote: crate::simplex_state::FinalizeVote { slot, block_hash: hash.clone() },
            signatures: Vec::new(),
        }),
    };

    let mut complete = true;
    // The pre-fix code would unconditionally panic on the seqno-dedup hit.
    // With the fix this must return silently and re-seed the slot-keyed dedup.
    fixture.processor.try_emit_recursive_finalized_callback(
        &candidate_id,
        &received,
        &dummy_event,
        /*has_final_cert=*/ true,
        slot,
        &[1, 2, 3],
        &mut complete,
    );

    assert!(complete, "idempotent re-entry must not flip the `complete` flag back to false");
    assert!(
        fixture.processor.consensus.finalized_delivery_sent_contains(&candidate_id),
        "idempotent path must re-seed the slot-keyed dedup so subsequent walks short-circuit early"
    );
}

#[test]
fn test_update_standstill_after_final_cert_updates_ingress_when_cleanup_is_skipped() {
    let mut fixture = TestFixture::new(4);

    // Regression: for early slots, history cleanup is skipped (up_to_slot == 0).
    fixture.processor.cleanup_old_slots(crate::block::SlotIndex::new(8));
    let cleanup_actions = fixture.drain_receiver_actions();
    assert!(
        !cleanup_actions.iter().any(|a| matches!(a, ReceiverAction::Cleanup { .. })),
        "receiver.cleanup must not run before MAX_HISTORY_SLOTS"
    );

    // Simulate finalized frontier advancement and final-cert hook.
    fixture.processor.simplex_state.set_first_non_finalized_slot(crate::block::SlotIndex::new(9));
    fixture.processor.update_standstill_after_final_cert(crate::block::SlotIndex::new(8));

    let actions = fixture.drain_receiver_actions();
    assert!(
        actions.iter().any(|a| matches!(a, ReceiverAction::SetIngressSlotBegin { slot: 9 })),
        "final-cert path must advance receiver ingress lower bound even when cleanup is skipped"
    );
    assert!(
        actions.iter().any(|a| matches!(a, ReceiverAction::SetIngressProgressSlot { slot: 9 })),
        "final-cert path must advance receiver ingress progress cursor"
    );
}

#[test]
fn test_recovery_set_first_non_finalized_slot_updates_receiver_ingress() {
    let mut fixture = TestFixture::new(4);

    // A persisted finalized block at slot 8 makes recovery set the finalized
    // boundary to slot 9 (max finalized + 1), which must synchronize the
    // receiver ingress cursor to the restored frontier.
    let mut bootstrap = empty_bootstrap();
    bootstrap.finalized_blocks = vec![crate::database::FinalizedBlockRecord {
        candidate_id: make_candidate_id(8, 0x88),
        block_id: make_block_id(108),
        parent: None,
        is_final: true,
    }];
    run_apply_bootstrap(&mut fixture, bootstrap);

    let actions = fixture.drain_receiver_actions();
    assert!(
        actions.iter().any(|a| matches!(a, ReceiverAction::SetIngressSlotBegin { slot: 9 })),
        "recovery must synchronize receiver ingress lower bound with restored frontier"
    );
    assert!(
        actions.iter().any(|a| matches!(a, ReceiverAction::SetIngressProgressSlot { slot: 9 })),
        "recovery must synchronize receiver ingress progress cursor with restored frontier"
    );
    assert_eq!(
        fixture.processor.simplex_state.get_first_non_finalized_slot(),
        crate::block::SlotIndex::new(9),
        "finalized boundary must be max finalized slot + 1"
    );
}

#[test]
fn test_recovery_finalize_parent_chain_sets_base_for_current_frontier() {
    let mut fixture = TestFixture::new(4);

    // Persisted finalized prefix ending at slot 2 (rooted at slot 1). Recovery
    // sets the boundary to slot 3 and step 12 (finalize_parent_chain) must seed
    // available_base for the current first_non_finalized slot from the slot-2
    // finalized record.
    let slot1 = make_candidate_id(1, 0x33);
    let slot2 = make_candidate_id(2, 0x44);
    let mut bootstrap = empty_bootstrap();
    bootstrap.finalized_blocks = vec![
        crate::database::FinalizedBlockRecord {
            candidate_id: slot1.clone(),
            block_id: make_block_id(101),
            parent: None,
            is_final: true,
        },
        crate::database::FinalizedBlockRecord {
            candidate_id: slot2.clone(),
            block_id: make_block_id(102),
            parent: Some(slot1.clone()),
            is_final: true,
        },
    ];
    run_apply_bootstrap(&mut fixture, bootstrap);

    let parent = fixture
        .processor
        .simplex_state
        .get_available_parent(fixture.processor.runtime.description(), SlotIndex::new(3));
    assert_eq!(
        parent,
        Some(crate::block::CandidateParentInfo { slot: slot2.slot, hash: slot2.hash.clone() }),
        "recovery must seed available_base for the current first_non_finalized slot"
    );
}

#[test]
fn test_skip_certificate_syncs_progress_cursor_without_advancing_finalized_frontier() {
    let mut fixture = TestFixture::new(4);
    fixture.drain_receiver_actions();

    let slot = 0u32;
    let tl_cert =
        build_skip_certificate_tl(&SessionId::default(), &fixture.nodes, slot, &[0, 1, 2]);

    fixture.processor.on_certificate(1, tl_cert);

    let actions = fixture.drain_receiver_actions();
    assert!(
        actions.iter().any(|a| matches!(a, ReceiverAction::SetIngressSlotBegin { slot: 0 })),
        "skip progress must keep ingress lower bound at the finalized frontier"
    );
    assert!(
        actions.iter().any(|a| matches!(a, ReceiverAction::SetIngressProgressSlot { slot: 1 })),
        "skip certificate must advance ingress progress cursor to the next slot"
    );
}

#[test]
fn test_skip_certificate_cancels_stale_candidate_request_repairs() {
    let mut fixture = TestFixture::new(4);
    fixture.drain_receiver_actions();

    let slot = crate::block::SlotIndex::new(0);
    let block_hash = UInt256::rand();
    let candidate_id = RawCandidateId { slot, hash: block_hash.clone() };

    fixture.processor.request_candidate(slot, block_hash.clone(), Some(Duration::from_secs(1)));
    assert!(
        fixture.processor.requested_candidates().contains_key(&candidate_id),
        "request should be scheduled before skip"
    );

    let tl_cert =
        build_skip_certificate_tl(&SessionId::default(), &fixture.nodes, slot.value(), &[0, 1, 2]);
    fixture.processor.on_certificate(1, tl_cert);

    assert!(
        !fixture.processor.requested_candidates().contains_key(&candidate_id),
        "skip must cancel scheduled requestCandidate repairs for the skipped slot"
    );

    let actions_after_skip = fixture.drain_receiver_actions();
    assert!(
        actions_after_skip
            .iter()
            .any(|a| matches!(a, ReceiverAction::CancelCandidateRequestsForSlot { slot: 0 })),
        "skip must cancel receiver-side pending requests for the skipped slot"
    );

    fixture.advance_time(Duration::from_secs(2));
    fixture.processor.check_all();

    let actions_after_delay = fixture.drain_receiver_actions();
    assert!(
        !actions_after_delay
            .iter()
            .any(|a| matches!(a, ReceiverAction::RequestCandidate { slot: 0, .. })),
        "cancelled delayed request must not fire after the slot is skipped"
    );
}

#[test]
fn test_handle_notarization_reached_requests_missing_candidate_body() {
    let mut fixture = TestFixture::new(4);

    let slot = crate::block::SlotIndex::new(7);
    let block_hash = UInt256::rand();
    let candidate_id = RawCandidateId { slot, hash: block_hash.clone() };

    // Ensure the candidate body is missing.
    assert!(
        !fixture.processor.candidate_book().contains_received(&candidate_id),
        "test setup: candidate body must be missing"
    );
    assert!(
        !fixture.processor.requested_candidates().contains_key(&candidate_id),
        "test setup: candidate must not be pre-requested"
    );

    // Create a notarization certificate (content doesn't need to be valid for this unit test).
    // threshold_66 for 4 validators is 3.
    let signatures = vec![
        crate::certificate::VoteSignature::new(ValidatorIndex::new(0), vec![0]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(1), vec![1]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(2), vec![2]),
    ];
    let vote = crate::simplex_state::NotarizeVote { slot, block_hash: block_hash.clone() };
    let cert = Arc::new(crate::certificate::Certificate { vote, signatures });

    let event = crate::simplex_state::NotarizationReachedEvent {
        slot,
        block_hash: block_hash.clone(),
        certificate: cert,
    };

    // Act: should schedule requestCandidate for missing body.
    fixture.processor.handle_notarization_reached(event);
    // `request_candidate` is a deferred ConsensusBackend effect bounced
    // onto SXMAIN; drain the queue so the real request runs before asserting.
    fixture.run_pending_tasks();

    assert!(
        fixture.processor.requested_candidates().contains_key(&candidate_id),
        "expected SessionProcessor to schedule requestCandidate for missing notarized block body"
    );
}

// ============================================================================
// Time-based Tests
// ============================================================================

#[test]
fn test_delayed_action_execution() {
    let mut fixture = TestFixture::new(4);

    // Post a delayed action 5 seconds in the future
    let executed = Arc::new(Mutex::new(false));
    let executed_clone = executed.clone();

    let delay = Duration::from_secs(5);
    let expiration_time = fixture.description.get_time() + delay;

    fixture.processor.post_delayed_action(expiration_time, move |_processor| {
        *executed_clone.lock().unwrap() = true;
    });

    // Action should not execute yet
    fixture.processor.check_all();
    assert!(!*executed.lock().unwrap(), "Action executed too early");

    // Advance time by 4 seconds (still not enough)
    fixture.advance_time(Duration::from_secs(4));
    fixture.processor.check_all();
    assert!(!*executed.lock().unwrap(), "Action executed too early");

    // Advance time by 2 more seconds (total 6, past the 5-second mark)
    fixture.advance_time(Duration::from_secs(2));
    fixture.processor.check_all();
    assert!(*executed.lock().unwrap(), "Action should have executed");
}

#[test]
fn test_time_isolation_between_tests() {
    // Each test should have independent time
    let fixture1 = TestFixture::new(4);
    let time1 = fixture1.description.get_time();

    let fixture2 = TestFixture::new(4);
    let time2 = fixture2.description.get_time();

    // Times should be reasonably close (both created around same time).
    // Fixture creation can occasionally be slow on contended CI hosts.
    let diff = time2.duration_since(time1).unwrap_or_else(|_| time1.duration_since(time2).unwrap());
    assert!(
        diff < Duration::from_secs(2),
        "Test fixtures should have similar initial times (diff={:?})",
        diff
    );
}

// ============================================================================
// Batch Finalization Tests
// ============================================================================

/// Notarized parents + finalized descendant (Case A)
///
/// Scenario:
/// - slot 1: notarized (NotarCert), not finalized
/// - slot 2: notarized (NotarCert), not finalized
/// - slot 3: finalized (FinalCert)
/// - parent chain: 1 → 2 → 3 (all non-empty blocks)
///
/// Expected: THREE finalization deliveries emitted in order:
/// - delivery(round=1, is_final=false, sigs=NotarCert/approve)
/// - delivery(round=2, is_final=false, sigs=NotarCert/approve)
/// - delivery(round=3, is_final=true,  sigs=FinalCert/final)
///
/// This verifies C++ `finalize_blocks()` parity:
/// - Parent blocks CAN be finalized (even if body not yet received)
/// - Parent blocks use NotarCert/`create_simplex_approve` signatures
/// - Triggered block uses FinalCert/`create_simplex` signatures
/// - No panic on is_triggered_block=false
/// - Round stream is gapless (round = slot in Option B)
///
#[test]
fn test_batch_finalization_notarized_parents_finalized_descendant() {
    let mut opts = SessionOptions::default();
    opts.use_callback_thread = false;
    let mut fixture = TestFixture::new_with_shard_and_local_idx(
        4,
        0,
        ShardIdent::with_tagged_prefix(0, 0x8000_0000_0000_0000).unwrap(),
        opts,
    );

    let recording = RecordingListener::new();
    let listener: Arc<dyn consensus_common::SessionListener + Send + Sync> = recording.clone();
    fixture.processor.set_listener_for_test(Arc::downgrade(&listener));

    let (leader_1, id_1, bcast_1) = make_signed_block_broadcast(&fixture, 31, vec![1u8, 2, 3]);
    fixture.processor.on_candidate_received(leader_1, bcast_1, None);

    let (leader_2, id_2, bcast_2) =
        make_signed_block_broadcast_with_parent(&fixture, 32, vec![4u8, 5, 6], Some(id_1.clone()));
    fixture.processor.on_candidate_received(leader_2, bcast_2, None);

    let (leader_3, id_3, bcast_3) =
        make_signed_block_broadcast_with_parent(&fixture, 33, vec![7u8, 8, 9], Some(id_2.clone()));
    fixture.processor.on_candidate_received(leader_3, bcast_3, None);

    let block_1 = fixture
        .processor
        .candidate_book()
        .received(&id_1)
        .expect("slot 31 candidate must exist")
        .block_id
        .clone();
    let block_2 = fixture
        .processor
        .candidate_book()
        .received(&id_2)
        .expect("slot 32 candidate must exist")
        .block_id
        .clone();
    let block_3 = fixture
        .processor
        .candidate_book()
        .received(&id_3)
        .expect("slot 33 candidate must exist")
        .block_id
        .clone();

    notarize_slot(&mut fixture, id_1.slot, &id_1.hash);
    notarize_slot(&mut fixture, id_2.slot, &id_2.hash);

    fixture.processor.handle_block_finalized(BlockFinalizedEvent {
        slot: id_3.slot,
        block_hash: id_3.hash.clone(),
        block_id: Some(block_3.clone()),
        certificate: make_test_final_cert(id_3.slot, id_3.hash.clone()),
    });

    let finalized_events: Vec<(BlockIdExt, bool)> = recording
        .drain_events()
        .into_iter()
        .filter_map(|event| match event {
            ListenerEvent::Finalized { block_id, is_final, .. } => Some((block_id, is_final)),
            _ => None,
        })
        .collect();

    assert_eq!(
        finalized_events.len(),
        3,
        "recursive finalization must emit callbacks for both ancestors and trigger",
    );
    assert!(
        finalized_events.iter().any(|(block_id, is_final)| block_id == &block_1 && !is_final),
        "first ancestor must be emitted in NotarCert mode (is_final=false)"
    );
    assert!(
        finalized_events.iter().any(|(block_id, is_final)| block_id == &block_2 && !is_final),
        "second ancestor must be emitted in NotarCert mode (is_final=false)"
    );
    assert!(
        finalized_events.iter().any(|(block_id, is_final)| block_id == &block_3 && *is_final),
        "trigger block must be emitted in FinalCert mode (is_final=true)"
    );

    assert!(fixture.processor.consensus.is_finalized_block(&id_1));
    assert!(fixture.processor.consensus.is_finalized_block(&id_2));
    assert!(fixture.processor.consensus.is_finalized_block(&id_3));
    assert!(
        fixture.processor.consensus.finalized_pending_body_is_empty(),
        "completed recursive chain must not stay in pending journal"
    );
}

// ============================================================================
// SIMPLEX_ROUNDLESS Mode Tests
// ============================================================================

/// Test that SIMPLEX_ROUNDLESS constant is u32::MAX
#[test]
fn test_simplex_roundless_constant_value() {
    assert_eq!(SIMPLEX_ROUNDLESS, u32::MAX, "SIMPLEX_ROUNDLESS should be u32::MAX");
    assert_eq!(SIMPLEX_ROUNDLESS, 0xFFFFFFFF, "SIMPLEX_ROUNDLESS should be 0xFFFFFFFF");
}

// ============================================================================
// Direct Emission Model Tests (SIMPLEX_ROUNDLESS cleanup)
// ============================================================================
//
// These tests verify the simplified direct emission architecture:
// - notify_block_committed() is called directly from commit_single_block()
// - No SlotOutcome buffering (mark/emit pattern removed)
// - Empty blocks don't trigger ValidatorGroup callbacks
// - slots BTreeMap is only used for SlotRuntime (collation/validation state)

/// Test that SlotEntry structure only contains runtime (no outcome field)
///
/// Documents the simplified SlotEntry structure after SIMPLEX_ROUNDLESS cleanup.
#[test]
fn test_slot_entry_structure_simplified() {
    let fixture = TestFixture::new(4);

    // Create a slot entry via slot_runtime_mut (the only way to create entries now)
    let slot = SlotIndex::new(5);

    // Initially no slot entry exists
    assert!(fixture.processor.runtime.slot_entry(slot).is_none());
}

/// Test that slot_entry_mut creates entry with runtime on first access
#[test]
fn test_slot_entry_mut_creates_runtime() {
    let mut fixture = TestFixture::new(4);

    let slot = SlotIndex::new(7);

    // Access runtime (should create entry)
    let now = fixture.processor.now();
    fixture.processor.runtime.slot_runtime_mut(slot, now).pending_generate = true;

    // Verify entry exists with runtime
    let entry = fixture.processor.runtime.slot_entry(slot);
    assert!(entry.is_some(), "Slot entry should exist after slot_runtime_mut");
    assert!(entry.unwrap().runtime.is_some(), "Runtime should be created");
    assert!(
        entry.unwrap().runtime.as_ref().unwrap().pending_generate,
        "pending_generate should be true"
    );
}

/// Test that SlotRuntime can be used independently for collation tracking
#[test]
fn test_slot_runtime_collation_tracking() {
    let mut fixture = TestFixture::new(4);

    let slot = SlotIndex::new(3);

    // Set collation state
    let now = fixture.processor.now();
    fixture.processor.runtime.set_pending_generate(slot, true, now);
    assert!(fixture.processor.runtime.is_pending_generate(slot));

    fixture.processor.runtime.set_generated(slot, true, now);
    assert!(fixture.processor.runtime.is_generated(slot));

    fixture.processor.runtime.set_sent_generated(slot, true, now);
    assert!(fixture.processor.runtime.is_sent_generated(slot));
}

/// Test that slot_started_at tracks when slot processing began
#[test]
fn test_slot_started_at_tracking() {
    let mut fixture = TestFixture::new(4);

    let slot = SlotIndex::new(10);

    // Access slot to create runtime with default start time
    let now = fixture.processor.now();
    fixture.processor.runtime.slot_runtime_mut(slot, now);

    let started_at = fixture.processor.runtime.started_at(slot, now);
    let now = fixture.description.get_time();

    // Started time should be close to now (within 1 second)
    let diff = now.duration_since(started_at).unwrap_or(Duration::ZERO);
    assert!(diff < Duration::from_secs(1), "Slot start time should be close to current time");
}

#[test]
fn test_candidate_decision_fail_drops_late_failure_for_finalized_block() {
    // Regression: in roundless Simplex, validation callbacks can arrive late (after the block is
    // already finalized). In this case we must drop the result and NOT schedule retries / WARN.
    let mut fixture = TestFixture::new(4);

    let slot = SlotIndex::new(5);
    let candidate_id = RawCandidateId { slot, hash: UInt256::rand() };

    // Pretend we've already finalized past this block seqno.
    fixture.processor.consensus.set_finalized_head_seqno(Some(100));

    // Create a non-empty RawCandidate with seqno <= finalized_head_seqno.
    let block_id =
        BlockIdExt::with_params(ShardIdent::masterchain(), 42, UInt256::rand(), UInt256::rand());
    let creator = fixture.nodes[0].public_key.clone();
    let block = crate::block::BlockCandidate {
        id: block_id,
        collated_file_hash: UInt256::rand(),
        data: vec![1, 2, 3],
        collated_data: vec![4, 5, 6],
        creator: creator.into(),
    };
    let raw_candidate = crate::block::RawCandidate::new(
        candidate_id.clone(),
        None,
        ValidatorIndex::new(0),
        block,
        vec![],
    );

    fixture.processor.validation.insert_pending_validation(
        candidate_id.clone(),
        PendingValidation {
            raw_candidate,
            slot,
            receive_time: fixture.description.get_time(),
            source_idx: ValidatorIndex::new(0),
        },
    );
    fixture.processor.validation.insert_pending_approve(candidate_id.clone());
    fixture.processor.validation.insert_validation_attempt(candidate_id.clone(), 0);

    fixture.processor.candidate_decision_fail(slot, candidate_id.clone(), error!("boom"));

    // Must be dropped (no retry scheduling, no rejection bookkeeping).
    assert!(!fixture.processor.validation.pending_validation_contains(&candidate_id));
    assert!(!fixture.processor.validation.pending_approve_contains(&candidate_id));
    assert!(!fixture.processor.validation.validation_attempt_contains(&candidate_id));
    assert!(!fixture.processor.validation.pending_reject_contains(&candidate_id));
    assert!(!fixture.processor.validation.is_rejected(&candidate_id));
}

// ============================================================================
// Optimistic Validation Tests
// ============================================================================

/// Helper: create a non-empty RawCandidate for check_validation tests.
/// The block data is synthetic (not a valid TOS block) — sufficient for
/// testing the gating logic in check_validation which doesn't parse it.
fn make_test_non_empty_candidate(
    candidate_id: RawCandidateId,
    parent_id: Option<RawCandidateId>,
    nodes: &[SessionNode],
) -> crate::block::RawCandidate {
    let block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        candidate_id.slot.value() + 1,
        UInt256::rand(),
        UInt256::rand(),
    );
    let creator = nodes[0].public_key.clone();
    let block = crate::block::BlockCandidate {
        id: block_id,
        collated_file_hash: UInt256::rand(),
        data: vec![1, 2, 3],
        collated_data: vec![4, 5, 6],
        creator: creator.into(),
    };
    crate::block::RawCandidate::new(candidate_id, parent_id, ValidatorIndex::new(0), block, vec![])
}

/// Helper: create an empty RawCandidate with a specific referenced BlockIdExt.
fn make_test_empty_candidate_with_block(
    candidate_id: RawCandidateId,
    parent_id: RawCandidateId,
    referenced_block: BlockIdExt,
) -> crate::block::RawCandidate {
    crate::block::RawCandidate::new_empty(
        candidate_id,
        parent_id,
        ValidatorIndex::new(0),
        referenced_block,
        vec![],
    )
}

/// Helper: insert a minimal ReceivedCandidate into the processor's candidate book.
fn insert_received_candidate(
    processor: &mut SessionProcessor,
    candidate_id: &RawCandidateId,
    block_id: BlockIdExt,
    is_empty: bool,
    parent_id: Option<RawCandidateId>,
) {
    insert_received_candidate_with_gen_utime_ms(
        processor,
        candidate_id,
        block_id,
        is_empty,
        parent_id,
        None,
    );
}

fn insert_received_candidate_with_gen_utime_ms(
    processor: &mut SessionProcessor,
    candidate_id: &RawCandidateId,
    block_id: BlockIdExt,
    is_empty: bool,
    parent_id: Option<RawCandidateId>,
    gen_utime_ms: Option<u64>,
) {
    processor.candidate_book_mut().insert_received(
        candidate_id.clone(),
        ReceivedCandidate {
            slot: candidate_id.slot,
            source_idx: ValidatorIndex::new(0),
            candidate_hash_data_bytes: Vec::new(),
            block_id: block_id.clone(),
            root_hash: block_id.root_hash.clone(),
            file_hash: block_id.file_hash.clone(),
            data: consensus_common::ConsensusCommonFactory::create_block_payload(Vec::new()),
            collated_data: consensus_common::ConsensusCommonFactory::create_block_payload(
                Vec::new(),
            ),
            gen_utime_ms,
            receive_time: SystemTime::now(),
            is_empty,
            parent_id,
        },
    );
}

/// Helper: insert a PendingValidation into the processor.
fn insert_pending_validation(
    processor: &mut SessionProcessor,
    candidate_id: &RawCandidateId,
    raw_candidate: crate::block::RawCandidate,
    time: SystemTime,
) {
    processor.validation.insert_pending_validation(
        candidate_id.clone(),
        PendingValidation {
            raw_candidate,
            slot: candidate_id.slot,
            receive_time: time,
            source_idx: ValidatorIndex::new(0),
        },
    );
}

/// Helper: drive the FSM to notarize a slot by storing a notarization certificate.
fn notarize_slot(fixture: &mut TestFixture, slot: SlotIndex, block_hash: &UInt256) {
    let signatures = vec![
        crate::certificate::VoteSignature::new(ValidatorIndex::new(0), vec![1u8; 64]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(1), vec![2u8; 64]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(2), vec![3u8; 64]),
    ];
    let vote = crate::simplex_state::NotarizeVote { slot, block_hash: block_hash.clone() };
    let cert = Arc::new(crate::certificate::Certificate { vote, signatures });

    fixture
        .processor
        .simplex_state
        .set_notarize_certificate(&fixture.description, slot, block_hash, cert)
        .expect("set_notarize_certificate failed");
}

/// Helper: drive the FSM to skip-cert a slot.
fn skip_slot(fixture: &mut TestFixture, slot: SlotIndex) {
    let signatures = vec![
        crate::certificate::VoteSignature::new(ValidatorIndex::new(0), vec![0]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(1), vec![1]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(2), vec![2]),
    ];
    let vote = crate::simplex_state::SkipVote { slot };
    let cert = Arc::new(crate::certificate::Certificate { vote, signatures });

    fixture
        .processor
        .simplex_state
        .set_skip_certificate(&fixture.description, slot, cert)
        .expect("set_skip_certificate failed");
}

#[test]
fn test_check_validation_forwards_candidate_with_notarized_parent() {
    let mut fixture = TestFixture::new_shard(4);

    let parent_slot = SlotIndex::new(0);
    let parent_hash = UInt256::rand();
    let parent_id = RawCandidateId { slot: parent_slot, hash: parent_hash.clone() };

    let child_slot = SlotIndex::new(1);
    let child_id = RawCandidateId { slot: child_slot, hash: UInt256::rand() };

    let raw_candidate =
        make_test_non_empty_candidate(child_id.clone(), Some(parent_id.clone()), &fixture.nodes);
    let time = fixture.description.get_time();
    insert_pending_validation(&mut fixture.processor, &child_id, raw_candidate, time);

    // Before notarization the candidate must stay blocked by WaitForParent.
    fixture.processor.check_validation();
    assert!(
        !fixture.processor.validation.pending_approve_contains(&child_id),
        "candidate must not be forwarded when parent is not notarized"
    );

    // Notarize the parent slot
    notarize_slot(&mut fixture, parent_slot, &parent_hash);
    assert!(
        fixture.processor.simplex_state.has_notarized_block(parent_slot),
        "parent slot must be notarized after set_notarize_certificate"
    );

    // After notarization: check_validation should forward the candidate
    fixture.processor.check_validation();
    assert!(
        fixture.processor.validation.pending_approve_contains(&child_id),
        "candidate must be forwarded to validation when parent is notarized"
    );
}

#[test]
fn test_check_validation_blocks_candidate_with_non_notarized_parent() {
    let mut fixture = TestFixture::new(4);

    let parent_slot = SlotIndex::new(0);
    let parent_id = RawCandidateId { slot: parent_slot, hash: UInt256::rand() };

    let child_slot = SlotIndex::new(1);
    let child_id = RawCandidateId { slot: child_slot, hash: UInt256::rand() };

    let raw_candidate =
        make_test_non_empty_candidate(child_id.clone(), Some(parent_id.clone()), &fixture.nodes);
    let time = fixture.description.get_time();
    insert_pending_validation(&mut fixture.processor, &child_id, raw_candidate, time);

    // Parent is NOT notarized — candidate must stay in pending_validations.
    fixture.processor.check_validation();
    assert!(
        !fixture.processor.validation.pending_approve_contains(&child_id),
        "candidate must NOT be forwarded when parent slot is not notarized"
    );
    assert!(
        fixture.processor.validation.pending_validation_contains(&child_id),
        "candidate must remain in pending_validations"
    );
}

#[test]
fn test_check_validation_forwards_genesis_candidate_without_parent() {
    let mut fixture = TestFixture::new(4);

    let slot = SlotIndex::new(0);
    let candidate_id = RawCandidateId { slot, hash: UInt256::rand() };

    let raw_candidate = make_test_non_empty_candidate(candidate_id.clone(), None, &fixture.nodes);
    let time = fixture.description.get_time();
    insert_pending_validation(&mut fixture.processor, &candidate_id, raw_candidate, time);

    // Genesis (no parent) should always be forwarded
    fixture.processor.check_validation();
    assert!(
        fixture.processor.validation.pending_approve_contains(&candidate_id),
        "genesis candidate (no parent) must be forwarded unconditionally"
    );
}

#[test]
fn test_check_validation_rejects_genesis_parent_candidate_after_skips_and_finalized_boundary() {
    let mut fixture = TestFixture::new_shard(4);

    let finalized_slot = SlotIndex::new(0);
    let finalized_hash = UInt256::from([0x2a; 32]);

    fixture
        .processor
        .simplex_state
        .set_finalize_certificate(
            &fixture.description,
            finalized_slot,
            &finalized_hash,
            make_test_final_cert(finalized_slot, finalized_hash.clone()),
        )
        .expect("set_finalize_certificate failed");

    let first_nf = fixture.processor.simplex_state.get_first_non_finalized_slot();
    assert!(
        first_nf > finalized_slot,
        "finalized boundary must move forward before checking no-parent post-skip candidate"
    );

    // Gap coverage for slot 3 candidate with implicit finalized-boundary parent.
    skip_slot(&mut fixture, SlotIndex::new(1));
    skip_slot(&mut fixture, SlotIndex::new(2));

    let child_slot = SlotIndex::new(3);
    let child_id = RawCandidateId { slot: child_slot, hash: UInt256::rand() };
    let raw_candidate = make_test_non_empty_candidate(child_id.clone(), None, &fixture.nodes);
    let time = fixture.description.get_time();
    insert_pending_validation(&mut fixture.processor, &child_id, raw_candidate, time);

    fixture.processor.check_validation();
    assert!(
        fixture.processor.validation.is_rejected(&child_id),
        "post-skip candidate with parent_id=None must be rejected by strict C++ WaitForParent parity"
    );
    assert!(
        !fixture.processor.validation.pending_validation_contains(&child_id),
        "rejected post-skip candidate must be removed from pending_validations"
    );
}

#[test]
fn test_check_validation_auto_approves_empty_blocks() {
    let mut fixture = TestFixture::new(4);

    let parent_slot = SlotIndex::new(0);
    let parent_id = RawCandidateId { slot: parent_slot, hash: UInt256::rand() };

    let parent_block_id =
        BlockIdExt::with_params(ShardIdent::masterchain(), 1, UInt256::rand(), UInt256::rand());

    insert_received_candidate(
        &mut fixture.processor,
        &parent_id,
        parent_block_id.clone(),
        false,
        None,
    );

    let child_slot = SlotIndex::new(1);
    let child_id = RawCandidateId { slot: child_slot, hash: UInt256::rand() };

    let raw_candidate = make_test_empty_candidate_with_block(
        child_id.clone(),
        parent_id.clone(),
        parent_block_id.clone(),
    );
    insert_received_candidate(
        &mut fixture.processor,
        &child_id,
        parent_block_id,
        true,
        Some(parent_id.clone()),
    );
    let time = fixture.description.get_time();
    insert_pending_validation(&mut fixture.processor, &child_id, raw_candidate, time);

    // WaitForParent parity: parent must be notarized before candidate is eligible.
    notarize_slot(&mut fixture, parent_slot, &parent_id.hash);

    // Empty blocks with a matching referenced block should be auto-approved.
    // C++ block-validator.cpp accepts when block == event->state->as_normal().
    fixture.processor.check_validation();
    assert!(
        !fixture.processor.validation.pending_validation_contains(&child_id),
        "empty block must be approved when referenced block matches parent normal tip"
    );
}

#[test]
fn test_empty_block_accepted_when_referenced_block_matches_parent() {
    let mut fixture = TestFixture::new(4);

    let parent_slot = SlotIndex::new(0);
    let parent_id = RawCandidateId { slot: parent_slot, hash: UInt256::rand() };

    let parent_block_id =
        BlockIdExt::with_params(ShardIdent::masterchain(), 1, UInt256::rand(), UInt256::rand());

    insert_received_candidate(
        &mut fixture.processor,
        &parent_id,
        parent_block_id.clone(),
        false,
        None,
    );

    let child_slot = SlotIndex::new(1);
    let child_id = RawCandidateId { slot: child_slot, hash: UInt256::rand() };

    let raw_candidate = make_test_empty_candidate_with_block(
        child_id.clone(),
        parent_id.clone(),
        parent_block_id.clone(),
    );
    insert_received_candidate(
        &mut fixture.processor,
        &child_id,
        parent_block_id,
        true,
        Some(parent_id.clone()),
    );
    let time = fixture.description.get_time();
    insert_pending_validation(&mut fixture.processor, &child_id, raw_candidate, time);

    // WaitForParent parity: parent must be notarized before candidate is eligible.
    notarize_slot(&mut fixture, parent_slot, &parent_id.hash);

    fixture.processor.check_validation();
    assert!(
        !fixture.processor.validation.pending_validation_contains(&child_id),
        "empty block must be approved when referenced block matches parent normal tip"
    );
    assert!(
        fixture.processor.validation.approved_contains(&child_id),
        "empty block must appear in approved set after matching reference check"
    );
}

#[test]
fn test_empty_block_rejected_when_referenced_block_differs() {
    let mut fixture = TestFixture::new(4);

    let parent_slot = SlotIndex::new(0);
    let parent_id = RawCandidateId { slot: parent_slot, hash: UInt256::rand() };

    let parent_block_id =
        BlockIdExt::with_params(ShardIdent::masterchain(), 1, UInt256::rand(), UInt256::rand());

    insert_received_candidate(&mut fixture.processor, &parent_id, parent_block_id, false, None);

    let child_slot = SlotIndex::new(1);
    let child_id = RawCandidateId { slot: child_slot, hash: UInt256::rand() };

    let wrong_block_id =
        BlockIdExt::with_params(ShardIdent::masterchain(), 99, UInt256::rand(), UInt256::rand());

    let raw_candidate = make_test_empty_candidate_with_block(
        child_id.clone(),
        parent_id.clone(),
        wrong_block_id.clone(),
    );
    insert_received_candidate(
        &mut fixture.processor,
        &child_id,
        wrong_block_id,
        true,
        Some(parent_id.clone()),
    );
    let time = fixture.description.get_time();
    insert_pending_validation(&mut fixture.processor, &child_id, raw_candidate, time);

    // WaitForParent parity: parent must be notarized before candidate is eligible.
    notarize_slot(&mut fixture, parent_slot, &parent_id.hash);

    // C++ block-validator.cpp rejects empty candidates whose referenced block
    // does not match event->state->as_normal(). Rust must do the same.
    fixture.processor.check_validation();
    assert!(
        fixture.processor.validation.is_rejected(&child_id),
        "empty block must be rejected when referenced block differs from parent normal tip"
    );
    assert!(
        !fixture.processor.validation.approved_contains(&child_id),
        "rejected empty block must not appear in approved set"
    );
}

#[test]
fn test_check_validation_skips_already_approved_candidates() {
    let mut fixture = TestFixture::new(4);

    let slot = SlotIndex::new(0);
    let candidate_id = RawCandidateId { slot, hash: UInt256::rand() };

    let raw_candidate = make_test_non_empty_candidate(candidate_id.clone(), None, &fixture.nodes);
    let time = fixture.description.get_time();
    insert_pending_validation(&mut fixture.processor, &candidate_id, raw_candidate, time);

    // Pre-mark as approved (value is (validity_start_time, signature_payload))
    let dummy_payload = consensus_common::ConsensusCommonFactory::create_block_payload(vec![]);
    fixture.processor.validation.insert_approved(candidate_id.clone(), (time, dummy_payload));

    fixture.processor.check_validation();
    assert!(
        !fixture.processor.validation.pending_approve_contains(&candidate_id),
        "already-approved candidate must not be re-submitted for validation"
    );
}

#[test]
fn test_check_validation_skips_already_rejected_candidates() {
    let mut fixture = TestFixture::new(4);

    let slot = SlotIndex::new(0);
    let candidate_id = RawCandidateId { slot, hash: UInt256::rand() };

    let raw_candidate = make_test_non_empty_candidate(candidate_id.clone(), None, &fixture.nodes);
    let time = fixture.description.get_time();
    insert_pending_validation(&mut fixture.processor, &candidate_id, raw_candidate, time);

    // Pre-mark as rejected
    fixture.processor.validation.insert_rejected(candidate_id.clone());

    fixture.processor.check_validation();
    assert!(
        !fixture.processor.validation.pending_approve_contains(&candidate_id),
        "already-rejected candidate must not be re-submitted for validation"
    );
}

#[test]
fn test_check_validation_skips_pending_approve_candidates() {
    let mut fixture = TestFixture::new(4);

    let slot = SlotIndex::new(0);
    let candidate_id = RawCandidateId { slot, hash: UInt256::rand() };

    let raw_candidate = make_test_non_empty_candidate(candidate_id.clone(), None, &fixture.nodes);
    let time = fixture.description.get_time();
    insert_pending_validation(&mut fixture.processor, &candidate_id, raw_candidate, time);

    // Pre-mark as pending_approve (already being validated)
    fixture.processor.validation.insert_pending_approve(candidate_id.clone());

    // check_validation should not double-insert
    fixture.processor.check_validation();

    // validation_attempt_map should NOT have been updated (try_approve_block not called)
    assert!(
        !fixture.processor.validation.validation_attempt_contains(&candidate_id),
        "candidate already in pending_approve must not be re-submitted"
    );
}

#[test]
fn test_check_validation_chains_notarized_parent_to_descendant() {
    // Validates that a candidate chain A -> B works:
    // - A has no parent (genesis), B has A as parent
    // - Only B's parent slot needs to be notarized for B to pass
    let mut fixture = TestFixture::new_shard(4);

    let slot_a = SlotIndex::new(0);
    let hash_a = UInt256::rand();
    let id_a = RawCandidateId { slot: slot_a, hash: hash_a.clone() };

    let slot_b = SlotIndex::new(1);
    let id_b = RawCandidateId { slot: slot_b, hash: UInt256::rand() };

    // Insert both candidates
    let raw_a = make_test_non_empty_candidate(id_a.clone(), None, &fixture.nodes);
    let raw_b = make_test_non_empty_candidate(id_b.clone(), Some(id_a.clone()), &fixture.nodes);
    let time = fixture.description.get_time();
    insert_pending_validation(&mut fixture.processor, &id_a, raw_a, time);
    insert_pending_validation(&mut fixture.processor, &id_b, raw_b, time);

    // First check_validation:
    // - A (genesis) should pass
    // - B should wait until parent slot A is notarized
    fixture.processor.check_validation();
    assert!(
        fixture.processor.validation.pending_approve_contains(&id_a),
        "genesis candidate A must be forwarded"
    );
    assert!(
        !fixture.processor.validation.pending_approve_contains(&id_b),
        "candidate B must wait until parent slot is notarized"
    );

    // Notarize slot 0 (A's slot)
    notarize_slot(&mut fixture, slot_a, &hash_a);

    // Second check_validation: B should now pass
    fixture.processor.check_validation();
    assert!(
        fixture.processor.validation.pending_approve_contains(&id_b),
        "candidate B must be forwarded after parent slot is notarized"
    );
}

#[test]
fn test_check_validation_wait_for_parent_requires_gap_skip_certificates() {
    let mut fixture = TestFixture::new_shard(4);

    // Candidate at slot 3 references parent at slot 0.
    // Readiness requires:
    // - parent slot 0 notarized
    // - skip certificates for slots 1 and 2
    let parent_slot = SlotIndex::new(0);
    let parent_hash = UInt256::rand();
    let parent_id = RawCandidateId { slot: parent_slot, hash: parent_hash.clone() };

    let child_slot = SlotIndex::new(3);
    let child_id = RawCandidateId { slot: child_slot, hash: UInt256::rand() };
    let raw_candidate =
        make_test_non_empty_candidate(child_id.clone(), Some(parent_id.clone()), &fixture.nodes);
    let time = fixture.description.get_time();
    insert_pending_validation(&mut fixture.processor, &child_id, raw_candidate, time);

    // Parent notarized, but gap skips missing: still blocked.
    notarize_slot(&mut fixture, parent_slot, &parent_hash);
    fixture.processor.check_validation();
    assert!(
        !fixture.processor.validation.pending_approve_contains(&child_id),
        "candidate must be blocked until all intermediate slots are skip-certified"
    );

    // Add skip cert for slot 1 only: still blocked.
    skip_slot(&mut fixture, SlotIndex::new(1));
    fixture.processor.check_validation();
    assert!(
        !fixture.processor.validation.pending_approve_contains(&child_id),
        "candidate must remain blocked when gap skip coverage is partial"
    );

    // Add skip cert for slot 2 -> now eligible.
    skip_slot(&mut fixture, SlotIndex::new(2));
    fixture.processor.check_validation();
    assert!(
        fixture.processor.validation.pending_approve_contains(&child_id),
        "candidate must be forwarded once parent and full skip-gap readiness are satisfied"
    );
}

#[test]
fn test_check_validation_wait_for_parent_rejects_parent_hash_mismatch() {
    let mut fixture = TestFixture::new(4);

    let parent_slot = SlotIndex::new(0);
    let notarized_parent_hash = UInt256::from([0x21; 32]);
    let mismatched_parent_hash = UInt256::from([0x99; 32]);
    let parent_id = RawCandidateId { slot: parent_slot, hash: mismatched_parent_hash };

    let child_slot = SlotIndex::new(1);
    let child_id = RawCandidateId { slot: child_slot, hash: UInt256::rand() };
    let raw_candidate =
        make_test_non_empty_candidate(child_id.clone(), Some(parent_id.clone()), &fixture.nodes);
    let time = fixture.description.get_time();
    insert_pending_validation(&mut fixture.processor, &child_id, raw_candidate, time);

    // Notarize the slot with a different hash than candidate.parent_id.
    notarize_slot(&mut fixture, parent_slot, &notarized_parent_hash);
    fixture.processor.check_validation();

    assert!(
        fixture.processor.validation.is_rejected(&child_id),
        "candidate must be rejected when parent hash mismatches notarized block"
    );
    assert!(
        !fixture.processor.validation.pending_validation_contains(&child_id),
        "rejected candidate must be removed from pending_validations"
    );
}

#[test]
fn test_check_validation_blocks_skipped_frontier_parent_even_with_bridge_head_seqno() {
    let mut fixture = TestFixture::new_shard(4);

    // Simulate bridge-side applied head already at seqno=1 while slot 0 in this
    // session ended with a skip certificate (no notarized block hash for slot 0).
    fixture.processor.consensus.set_accepted_normal_head_seqno(1);
    skip_slot(&mut fixture, SlotIndex::new(0));

    let parent_id = RawCandidateId { slot: SlotIndex::new(0), hash: UInt256::from([0x44; 32]) };
    let child_slot = SlotIndex::new(1);
    let child_id = RawCandidateId { slot: child_slot, hash: UInt256::rand() };
    let raw_candidate =
        make_test_non_empty_candidate(child_id.clone(), Some(parent_id.clone()), &fixture.nodes);
    let time = fixture.description.get_time();
    insert_pending_validation(&mut fixture.processor, &child_id, raw_candidate, time);

    fixture.processor.check_validation();
    assert!(
        !fixture.processor.validation.pending_approve_contains(&child_id),
        "strict C++ parity must not forward skipped-frontier bypass candidates \
         even when seqno matches accepted_normal_head_seqno + 1"
    );
    assert!(
        fixture.processor.validation.pending_validation_contains(&child_id),
        "blocked skipped-frontier candidate must remain pending until parent readiness changes"
    );
}

#[test]
fn test_on_candidate_received_non_empty_does_not_wait_for_unresolved_ancestor_chain() {
    let mut fixture = TestFixture::new(4);

    let grandparent_id =
        RawCandidateId { slot: SlotIndex::new(0), hash: UInt256::from([0x71; 32]) };
    let parent_id = RawCandidateId { slot: SlotIndex::new(1), hash: UInt256::from([0x72; 32]) };
    let parent_block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        10,
        UInt256::from([0x73; 32]),
        UInt256::from([0x74; 32]),
    );
    insert_received_candidate(
        &mut fixture.processor,
        &parent_id,
        parent_block_id,
        false,
        Some(grandparent_id),
    );

    let (leader_source, child_id, broadcast) = make_signed_block_broadcast_with_parent(
        &fixture,
        2,
        vec![0x55, 0x66, 0x77],
        Some(parent_id.clone()),
    );

    fixture.processor.on_candidate_received(leader_source, broadcast, None);

    assert!(
        fixture.processor.validation.pending_validation_contains(&child_id),
        "non-empty candidate must be admitted immediately even if only ancestor metadata is missing"
    );
    assert!(
        fixture.processor.requested_candidates().is_empty(),
        "non-empty admission must not trigger ancestor prefetch requests"
    );

    let received = fixture
        .processor
        .candidate_book()
        .received(&child_id)
        .expect("child candidate must be stored");
    assert!(
        received.parent_id.as_ref() == Some(&parent_id),
        "stored child candidate must preserve the explicit parent link"
    );
}

#[test]
fn test_on_candidate_received_empty_waits_in_pending_validation_and_requests_missing_parent() {
    let mut fixture = TestFixture::new(4);

    let parent_id = RawCandidateId { slot: SlotIndex::new(1), hash: UInt256::from([0x81; 32]) };
    let referenced_block = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        20,
        UInt256::from([0x82; 32]),
        UInt256::from([0x83; 32]),
    );
    let (leader_source, child_id, broadcast) = make_signed_empty_block_broadcast_with_parent(
        &fixture,
        2,
        parent_id.clone(),
        referenced_block,
    );

    fixture.processor.on_candidate_received(leader_source, broadcast, None);

    assert!(
        fixture.processor.validation.pending_validation_contains(&child_id),
        "empty candidate must enter pending_validations immediately after ingress"
    );
    assert!(
        fixture.processor.requested_candidates().is_empty(),
        "ingress must not prefetch parent metadata before WaitForParent is satisfied"
    );

    notarize_slot(&mut fixture, parent_id.slot, &parent_id.hash);
    fixture.processor.check_validation();
    // `ensure_empty_parent_tip_ready` (now on `ValidationController`) requests the
    // missing parent through the borrowing `ValidationBackend`, which bounces the
    // `&mut SessionProcessor` `request_candidate` call onto the task queue; flush
    // it so the request lands, exactly as the SXMAIN loop would next iteration.
    fixture.run_pending_tasks();

    assert!(
        fixture.processor.validation.pending_validation_contains(&child_id),
        "empty candidate must remain pending while parent metadata is still missing"
    );
    assert!(
        fixture.processor.requested_candidates().contains_key(&parent_id),
        "validation path must request the missing parent metadata on demand"
    );
    assert!(
        !fixture.processor.validation.pending_approve_contains(&child_id),
        "empty candidate must not enter pending_approve until the parent normal tip is resolvable"
    );
    assert!(
        !fixture.processor.validation.is_rejected(&child_id),
        "missing parent metadata must defer empty approval instead of rejecting it"
    );
}

#[test]
fn test_ensure_candidate_available_requests_even_if_slot_skipped() {
    let mut fixture = TestFixture::new(4);
    let candidate_id = RawCandidateId { slot: SlotIndex::new(7), hash: UInt256::from([0xAB; 32]) };
    let block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        77,
        UInt256::from([0xBC; 32]),
        UInt256::from([0xCD; 32]),
    );

    insert_received_candidate(&mut fixture.processor, &candidate_id, block_id.clone(), false, None);
    skip_slot(&mut fixture, candidate_id.slot);

    fixture.processor.ensure_candidate_available(
        block_id,
        EnsureCandidateAvailabilityOptions {
            purpose: ResolverPurpose::SimplexCollationParent,
            include_parent_chain: false,
        },
    );

    assert!(
        fixture.processor.requested_candidates().contains_key(&candidate_id),
        "resolver ensure must request body even for skipped slot"
    );

    let requests: Vec<(u32, UInt256)> = fixture
        .receiver
        .drain_actions()
        .into_iter()
        .filter_map(|action| match action {
            ReceiverAction::RequestCandidate { slot, block_hash } => Some((slot, block_hash)),
            _ => None,
        })
        .collect();
    assert!(
        requests
            .iter()
            .any(|(slot, hash)| *slot == candidate_id.slot.value() && *hash == candidate_id.hash),
        "resolver ensure must send receiver.request_candidate for target candidate"
    );
}

#[test]
fn test_ensure_candidate_available_requests_parent_chain_when_enabled() {
    let mut fixture = TestFixture::new(4);
    let root_id = RawCandidateId { slot: SlotIndex::new(3), hash: UInt256::from([0x11; 32]) };
    let parent_id = RawCandidateId { slot: SlotIndex::new(4), hash: UInt256::from([0x22; 32]) };
    let child_id = RawCandidateId { slot: SlotIndex::new(5), hash: UInt256::from([0x33; 32]) };
    let root_block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        31,
        UInt256::from([0x44; 32]),
        UInt256::from([0x45; 32]),
    );
    let parent_block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        32,
        UInt256::from([0x46; 32]),
        UInt256::from([0x47; 32]),
    );
    let child_block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        33,
        UInt256::from([0x48; 32]),
        UInt256::from([0x49; 32]),
    );

    insert_received_candidate(&mut fixture.processor, &root_id, root_block_id, false, None);
    insert_received_candidate(
        &mut fixture.processor,
        &parent_id,
        parent_block_id,
        false,
        Some(root_id.clone()),
    );
    insert_received_candidate(
        &mut fixture.processor,
        &child_id,
        child_block_id.clone(),
        false,
        Some(parent_id.clone()),
    );

    fixture.processor.ensure_candidate_available(
        child_block_id,
        EnsureCandidateAvailabilityOptions {
            purpose: ResolverPurpose::SimplexCollationParent,
            include_parent_chain: true,
        },
    );

    assert!(
        fixture.processor.requested_candidates().contains_key(&child_id),
        "child must be requested"
    );
    assert!(
        fixture.processor.requested_candidates().contains_key(&parent_id),
        "parent must be requested when include_parent_chain=true"
    );
    assert!(
        fixture.processor.requested_candidates().contains_key(&root_id),
        "root ancestor must be requested when metadata chain is available"
    );
}

#[test]
fn test_ensure_candidate_available_requests_immediate_parent_and_stops_on_missing_metadata() {
    let mut fixture = TestFixture::new(4);
    let parent_id = RawCandidateId { slot: SlotIndex::new(8), hash: UInt256::from([0xAA; 32]) };
    let child_id = RawCandidateId { slot: SlotIndex::new(9), hash: UInt256::from([0xBB; 32]) };
    let child_block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        91,
        UInt256::from([0xCC; 32]),
        UInt256::from([0xDD; 32]),
    );

    // Only child metadata is known. Parent metadata is absent by design.
    insert_received_candidate(
        &mut fixture.processor,
        &child_id,
        child_block_id.clone(),
        false,
        Some(parent_id.clone()),
    );

    fixture.processor.ensure_candidate_available(
        child_block_id,
        EnsureCandidateAvailabilityOptions {
            purpose: ResolverPurpose::SimplexCollationParent,
            include_parent_chain: true,
        },
    );

    assert!(
        fixture.processor.requested_candidates().contains_key(&child_id),
        "target candidate must be requested"
    );
    assert!(
        fixture.processor.requested_candidates().contains_key(&parent_id),
        "immediate parent must be requested even when parent metadata is missing"
    );
    assert_eq!(
        fixture.processor.requested_candidates().len(),
        2,
        "traversal must stop after requesting the first missing parent metadata"
    );

    let requests: Vec<(u32, UInt256)> = fixture
        .receiver
        .drain_actions()
        .into_iter()
        .filter_map(|action| match action {
            ReceiverAction::RequestCandidate { slot, block_hash } => Some((slot, block_hash)),
            _ => None,
        })
        .collect();
    assert!(
        requests
            .iter()
            .any(|(slot, hash)| *slot == child_id.slot.value() && *hash == child_id.hash),
        "must request child candidate body"
    );
    assert!(
        requests
            .iter()
            .any(|(slot, hash)| *slot == parent_id.slot.value() && *hash == parent_id.hash),
        "must request immediate parent candidate body"
    );
}

#[test]
fn test_ensure_candidate_available_respects_retry_throttling() {
    let mut fixture = TestFixture::new(4);
    let candidate_id = RawCandidateId { slot: SlotIndex::new(10), hash: UInt256::from([0x01; 32]) };
    let block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        101,
        UInt256::from([0x02; 32]),
        UInt256::from([0x03; 32]),
    );
    let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fixture.processor.set_time(base_time);

    insert_received_candidate(&mut fixture.processor, &candidate_id, block_id.clone(), false, None);

    // First ensure: must request immediately.
    fixture.processor.ensure_candidate_available(
        block_id.clone(),
        EnsureCandidateAvailabilityOptions {
            purpose: ResolverPurpose::SimplexCollationParent,
            include_parent_chain: false,
        },
    );
    let first_requests: Vec<(u32, UInt256)> = fixture
        .receiver
        .drain_actions()
        .into_iter()
        .filter_map(|action| match action {
            ReceiverAction::RequestCandidate { slot, block_hash } => Some((slot, block_hash)),
            _ => None,
        })
        .collect();
    assert_eq!(first_requests.len(), 1, "first ensure must emit one request");

    // Second ensure at the same logical time: throttled, no extra request.
    fixture.processor.ensure_candidate_available(
        block_id.clone(),
        EnsureCandidateAvailabilityOptions {
            purpose: ResolverPurpose::SimplexCollationParent,
            include_parent_chain: false,
        },
    );
    let second_requests: Vec<(u32, UInt256)> = fixture
        .receiver
        .drain_actions()
        .into_iter()
        .filter_map(|action| match action {
            ReceiverAction::RequestCandidate { slot, block_hash } => Some((slot, block_hash)),
            _ => None,
        })
        .collect();
    assert!(second_requests.is_empty(), "second ensure inside retry window must be throttled");

    // Advance beyond retry interval and ensure again: request should be emitted.
    fixture
        .processor
        .set_time(base_time + CANDIDATE_REQUEST_RETRY_INTERVAL + Duration::from_millis(1));
    fixture.processor.ensure_candidate_available(
        block_id,
        EnsureCandidateAvailabilityOptions {
            purpose: ResolverPurpose::SimplexCollationParent,
            include_parent_chain: false,
        },
    );
    let third_requests: Vec<(u32, UInt256)> = fixture
        .receiver
        .drain_actions()
        .into_iter()
        .filter_map(|action| match action {
            ReceiverAction::RequestCandidate { slot, block_hash } => Some((slot, block_hash)),
            _ => None,
        })
        .collect();
    assert_eq!(third_requests.len(), 1, "ensure after retry interval must emit request again");
}

#[test]
fn test_ensure_candidate_available_deferred_retry_on_missing_mapping() {
    let mut fixture = TestFixture::new(4);
    let candidate_id = RawCandidateId { slot: SlotIndex::new(15), hash: UInt256::from([0xDE; 32]) };
    let block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        150,
        UInt256::from([0xEF; 32]),
        UInt256::from([0xF0; 32]),
    );
    let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fixture.processor.set_time(base_time);

    // No mapping exists yet — ensure should schedule a deferred retry.
    fixture.processor.ensure_candidate_available(
        block_id.clone(),
        EnsureCandidateAvailabilityOptions {
            purpose: ResolverPurpose::SimplexCollationParent,
            include_parent_chain: false,
        },
    );
    // The controller schedules its retry through the controller queue, which
    // bounces an immediate task onto the main queue that then arms the runtime
    // delayed action; drain that SXMAIN hop before inspecting the timer.
    fixture.run_pending_tasks();

    assert_eq!(
        fixture.processor.runtime.delayed_actions_count(),
        1,
        "must schedule exactly one deferred retry on missing mapping"
    );

    // No request should have been sent yet.
    let requests: Vec<_> = fixture
        .receiver
        .drain_actions()
        .into_iter()
        .filter_map(|action| match action {
            ReceiverAction::RequestCandidate { slot, block_hash } => Some((slot, block_hash)),
            _ => None,
        })
        .collect();
    assert!(requests.is_empty(), "no request before mapping is available");

    // Now insert the mapping and advance time past the retry delay.
    insert_received_candidate(&mut fixture.processor, &candidate_id, block_id.clone(), false, None);
    fixture
        .processor
        .set_time(base_time + RESOLVER_AVAILABILITY_RETRY_DELAY + Duration::from_millis(1));
    fixture.processor.process_delayed_actions();

    assert!(
        fixture.processor.requested_candidates().contains_key(&candidate_id),
        "deferred retry must request the candidate once mapping becomes available"
    );

    let requests: Vec<_> = fixture
        .receiver
        .drain_actions()
        .into_iter()
        .filter_map(|action| match action {
            ReceiverAction::RequestCandidate { slot, block_hash } => Some((slot, block_hash)),
            _ => None,
        })
        .collect();
    assert_eq!(requests.len(), 1, "deferred retry must emit exactly one request");
    assert_eq!(requests[0].0, candidate_id.slot.value());
    assert_eq!(requests[0].1, candidate_id.hash);
}

#[test]
fn test_ensure_candidate_available_deferred_retry_gives_up_after_max_retries() {
    let mut fixture = TestFixture::new(4);
    let block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        200,
        UInt256::from([0xA1; 32]),
        UInt256::from([0xA2; 32]),
    );
    let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fixture.processor.set_time(base_time);

    // No mapping — fire the initial ensure.
    fixture.processor.ensure_candidate_available(
        block_id.clone(),
        EnsureCandidateAvailabilityOptions {
            purpose: ResolverPurpose::SimplexValidationParent,
            include_parent_chain: false,
        },
    );
    // The retry is scheduled through the controller queue, which bounces an
    // immediate task onto the main queue that arms the runtime delayed action;
    // drain that SXMAIN hop so the timer is observable.
    fixture.run_pending_tasks();

    // Repeatedly advance time and process delayed actions until retries are exhausted.
    for i in 0..RESOLVER_AVAILABILITY_MAX_RETRIES {
        assert_eq!(
            fixture.processor.runtime.delayed_actions_count(),
            1,
            "attempt {}: must have exactly one pending deferred retry",
            i
        );
        let advance = RESOLVER_AVAILABILITY_RETRY_DELAY + Duration::from_millis(1);
        fixture.processor.set_time(base_time + advance * (i + 1));
        fixture.processor.process_delayed_actions();
        // Each still-unresolved retry re-arms the next one through the same
        // controller-queue bounce; flush it before the next count assertion.
        fixture.run_pending_tasks();
    }

    // After max retries, no more deferred actions should be scheduled.
    assert!(
        fixture.processor.runtime.delayed_actions_count() == 0,
        "must not schedule more retries after exhausting max attempts"
    );
}

// ============================================================================
// Health check anomaly tests
// ============================================================================

/// Reset health alert timestamps to a deterministic base time so that
/// cooldown checks work correctly in tests (HealthAlertState is initialized
/// with real SystemTime::now() during SessionProcessor::new).
fn reset_health_alert_time(processor: &mut SessionProcessor, base: SystemTime) {
    let mut s = processor.telemetry.health_alert_state_for_test();
    s.last_progress_warn = base;
    s.last_activity_warn = base;
    s.last_cert_fail_warn = base;
    s.last_skip_ratio_warn = base;
    s.last_standstill_warn = base;
    s.last_finalization_speed_warn = base;
    s.last_finalization_nonzero_at = base;
    s.last_candidate_giveup_warn = base;
    s.prev_votes_in_notarize = 0;
    s.prev_votes_in_finalize = 0;
    s.prev_votes_in_skip = 0;
}

#[test]
fn test_health_check_cert_verify_fail_anomaly() {
    let mut fixture = TestFixture::new(4);

    let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fixture.processor.set_time(base_time);
    reset_health_alert_time(&mut fixture.processor, base_time);

    // Initially no warnings
    fixture.processor.run_health_checks();

    // Simulate cert verify failure
    fixture
        .processor
        .telemetry
        .cert_verify_fails_total
        .store(1, std::sync::atomic::Ordering::Relaxed);

    // Advance past cooldown (default 30s)
    fixture.processor.set_time(base_time + Duration::from_secs(31));
    fixture.processor.run_health_checks();

    assert_eq!(fixture.processor.telemetry.health_alert_state_for_test().prev_cert_verify_fails, 1);
}

#[test]
fn test_health_check_standstill_anomaly() {
    let mut fixture = TestFixture::new(4);

    let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fixture.processor.set_time(base_time);
    reset_health_alert_time(&mut fixture.processor, base_time);

    fixture.processor.run_health_checks();

    fixture
        .processor
        .telemetry
        .receiver_health_counters
        .standstill_triggers
        .store(3, Ordering::Relaxed);

    fixture.processor.set_time(base_time + Duration::from_secs(31));
    fixture.processor.run_health_checks();

    assert_eq!(
        fixture.processor.telemetry.health_alert_state_for_test().prev_standstill_triggers,
        3
    );
}

#[test]
fn test_health_check_candidate_giveup_anomaly() {
    let mut fixture = TestFixture::new(4);

    let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fixture.processor.set_time(base_time);
    reset_health_alert_time(&mut fixture.processor, base_time);

    fixture.processor.run_health_checks();

    fixture
        .processor
        .telemetry
        .receiver_health_counters
        .candidate_giveups
        .store(2, Ordering::Relaxed);

    fixture.processor.set_time(base_time + Duration::from_secs(31));
    fixture.processor.run_health_checks();

    assert_eq!(fixture.processor.telemetry.health_alert_state_for_test().prev_candidate_giveups, 2);
}

#[test]
fn test_health_check_skip_vote_dominance_anomaly() {
    let mut fixture = TestFixture::new(4);

    let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fixture.processor.set_time(base_time);
    reset_health_alert_time(&mut fixture.processor, base_time);

    fixture.processor.run_health_checks();

    // High skip-dominant window (delta-based): should trigger skip ratio anomaly.
    fixture.processor.telemetry.votes_in_skip_total.store(24, std::sync::atomic::Ordering::Relaxed);
    fixture
        .processor
        .telemetry
        .votes_in_notarize_total
        .store(2, std::sync::atomic::Ordering::Relaxed);
    fixture
        .processor
        .telemetry
        .votes_in_finalize_total
        .store(1, std::sync::atomic::Ordering::Relaxed);

    fixture.processor.set_time(base_time + Duration::from_secs(31));
    fixture.processor.run_health_checks();

    assert_eq!(fixture.processor.telemetry.health_alert_state_for_test().prev_votes_in_skip, 24);
    assert_eq!(fixture.processor.telemetry.health_alert_state_for_test().prev_votes_in_notarize, 2);
    assert_eq!(fixture.processor.telemetry.health_alert_state_for_test().prev_votes_in_finalize, 1);
    assert_eq!(
        fixture.processor.telemetry.health_alert_state_for_test().last_skip_ratio_warn,
        base_time + Duration::from_secs(31)
    );
}

#[test]
fn test_health_check_skip_vote_dominance_ignores_sparse_zero_denominator() {
    let mut fixture = TestFixture::new(4);

    let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fixture.processor.set_time(base_time);
    reset_health_alert_time(&mut fixture.processor, base_time);

    fixture.processor.run_health_checks();

    // One stream is absent in the current window, but the overall progress vote
    // stream is still healthy enough that skip traffic is not dominant.
    fixture.processor.telemetry.votes_in_skip_total.store(3, std::sync::atomic::Ordering::Relaxed);
    fixture
        .processor
        .telemetry
        .votes_in_notarize_total
        .store(0, std::sync::atomic::Ordering::Relaxed);
    fixture
        .processor
        .telemetry
        .votes_in_finalize_total
        .store(10, std::sync::atomic::Ordering::Relaxed);

    fixture.processor.set_time(base_time + Duration::from_secs(31));
    fixture.processor.run_health_checks();

    assert_eq!(fixture.processor.telemetry.health_alert_state_for_test().prev_votes_in_skip, 3);
    assert_eq!(fixture.processor.telemetry.health_alert_state_for_test().prev_votes_in_notarize, 0);
    assert_eq!(
        fixture.processor.telemetry.health_alert_state_for_test().prev_votes_in_finalize,
        10
    );
    assert_eq!(
        fixture.processor.telemetry.health_alert_state_for_test().last_skip_ratio_warn,
        base_time
    );
}

#[test]
fn test_health_check_cooldown_prevents_spam() {
    let mut fixture = TestFixture::new(4);

    let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fixture.processor.set_time(base_time);
    reset_health_alert_time(&mut fixture.processor, base_time);

    // First cert verify fail — advance past initial cooldown
    fixture
        .processor
        .telemetry
        .cert_verify_fails_total
        .store(1, std::sync::atomic::Ordering::Relaxed);
    fixture.processor.set_time(base_time + Duration::from_secs(31));
    fixture.processor.run_health_checks();
    assert_eq!(fixture.processor.telemetry.health_alert_state_for_test().prev_cert_verify_fails, 1);

    // More cert verify fails, but within cooldown since last warn at t+31
    fixture
        .processor
        .telemetry
        .cert_verify_fails_total
        .store(5, std::sync::atomic::Ordering::Relaxed);
    fixture.processor.set_time(base_time + Duration::from_secs(35));
    fixture.processor.run_health_checks();
    assert_eq!(fixture.processor.telemetry.health_alert_state_for_test().prev_cert_verify_fails, 1);

    // After cooldown passes (31 + 30 = 61, use 62)
    fixture.processor.set_time(base_time + Duration::from_secs(62));
    fixture.processor.run_health_checks();
    assert_eq!(fixture.processor.telemetry.health_alert_state_for_test().prev_cert_verify_fails, 5);
}

#[test]
fn test_health_check_configurable_cooldown() {
    let nodes = create_test_validators(4);
    let local_key = nodes[0].public_key.clone();
    let shard = ShardIdent::masterchain();

    let mut opts = SessionOptions::default();
    opts.health_alert_cooldown = Duration::from_secs(10);

    let description = Arc::new(
        crate::session_description::SessionDescription::new(
            &opts,
            SessionId::default(),
            1,
            &nodes,
            local_key,
            &shard,
            SystemTime::now(),
            None,
        )
        .unwrap(),
    );

    let listener: Arc<dyn consensus_common::SessionListener + Send + Sync> = Arc::new(MockListener);
    let listener_weak = Arc::downgrade(&listener);
    let task_queue = TestTaskQueue::new();
    let callback_queue: CallbackTaskQueuePtr = Arc::new(TestCallbackQueue);
    let receiver = MockReceiver::new();
    let db = MockDb::new();
    let stop_flag = Arc::new(AtomicBool::new(false));
    let health_counters = Arc::new(crate::receiver::ReceiverHealthCounters::new());

    let callbacks = Arc::new(crate::session_callbacks::SessionCallbacks::new(
        description.get_session_id().clone(),
        stop_flag.clone(),
        false,
        callback_queue,
        listener_weak,
    ));
    let mut processor = SessionProcessor::new(
        description,
        make_start_prev_blocks(&shard, 1),
        task_queue as TaskQueuePtr,
        receiver as crate::receiver::ReceiverPtr,
        stop_flag,
        db,
        0,
        health_counters,
        callbacks,
        None,
        0,
    )
    .unwrap();

    assert_eq!(processor.telemetry.health_alert_state_for_test().cooldown, Duration::from_secs(10));

    let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    processor.set_time(base_time);
    reset_health_alert_time(&mut processor, base_time);

    processor.telemetry.cert_verify_fails_total.store(1, std::sync::atomic::Ordering::Relaxed);

    // After 11s (> 10s cooldown), should trigger
    processor.set_time(base_time + Duration::from_secs(11));
    processor.run_health_checks();
    assert_eq!(processor.telemetry.health_alert_state_for_test().prev_cert_verify_fails, 1);
}

// ============================================================================
// Collation pacing tests
// ============================================================================

#[test]
fn test_update_collation_pacing_sets_earliest_time() {
    let mut fixture = TestFixture::new(4);
    let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fixture.processor.set_time(base_time);

    assert!(fixture.processor.collation.earliest_collation_time().is_none());

    fixture.processor.collation.update_collation_pacing();

    let target_rate = fixture.description.opts().target_rate;
    assert_eq!(
        fixture.processor.collation.earliest_collation_time(),
        Some(base_time + target_rate),
    );
}

#[test]
fn test_update_collation_pacing_advances_on_repeated_calls() {
    let mut fixture = TestFixture::new(4);
    let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fixture.processor.set_time(base_time);

    let target_rate = fixture.description.opts().target_rate;

    fixture.processor.collation.update_collation_pacing();
    assert_eq!(
        fixture.processor.collation.earliest_collation_time(),
        Some(base_time + target_rate)
    );

    // Advance time by half the target_rate and pace again
    fixture.advance_time(target_rate / 2);
    fixture.processor.collation.update_collation_pacing();
    assert_eq!(
        fixture.processor.collation.earliest_collation_time(),
        Some(base_time + target_rate / 2 + target_rate),
    );
}

#[test]
fn test_compute_collation_start_time_caps_parent_delay_to_target_rate() {
    let mut fixture = TestFixture::new(4);
    let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fixture.processor.set_time(base_time);

    let parent_id = RawCandidateId { slot: SlotIndex::new(0), hash: UInt256::rand() };
    let parent_block_id =
        BlockIdExt::with_params(ShardIdent::masterchain(), 1, UInt256::rand(), UInt256::rand());
    let parent_gen_utime_ms =
        base_time.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64 + 500;

    insert_received_candidate_with_gen_utime_ms(
        &mut fixture.processor,
        &parent_id,
        parent_block_id,
        false,
        None,
        Some(parent_gen_utime_ms),
    );

    let parent_info =
        crate::block::CandidateParentInfo { slot: parent_id.slot, hash: parent_id.hash.clone() };
    let start_time = fixture.processor.compute_collation_start_time(Some(&parent_info));

    assert_eq!(
        start_time,
        base_time + fixture.description.opts().target_rate,
        "collation start time should not be delayed by more than one target_rate from now"
    );
}

#[test]
fn test_shard_collation_start_time_matches_cpp_early_dispatch() {
    let mut fixture = TestFixture::new_shard(4);
    let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fixture.processor.set_time(base_time);

    let parent_id = RawCandidateId { slot: SlotIndex::new(0), hash: UInt256::rand() };
    let parent_block_id = BlockIdExt::with_params(
        fixture.description.get_shard().clone(),
        1,
        UInt256::rand(),
        UInt256::rand(),
    );
    let parent_gen_utime_ms =
        base_time.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64;

    insert_received_candidate_with_gen_utime_ms(
        &mut fixture.processor,
        &parent_id,
        parent_block_id,
        false,
        None,
        Some(parent_gen_utime_ms),
    );

    let parent_info =
        crate::block::CandidateParentInfo { slot: parent_id.slot, hash: parent_id.hash.clone() };
    let dispatch_time = fixture.processor.compute_collation_start_time(Some(&parent_info));
    let min_gen_time = fixture.processor.compute_collation_min_gen_time(Some(&parent_info));

    assert_eq!(
        dispatch_time, base_time,
        "shard collation should dispatch at slot_start - target_rate"
    );
    assert_eq!(
        min_gen_time,
        base_time + fixture.description.opts().target_rate,
        "early shard dispatch must preserve the block min generation time"
    );
}

#[test]
fn test_check_collation_blocks_before_earliest_time() {
    let mut fixture = TestFixture::new(4);
    let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fixture.processor.set_time(base_time);

    let gate_time = base_time + Duration::from_millis(500);
    fixture.processor.collation.set_earliest_collation_time(Some(gate_time));

    fixture.processor.reset_next_awake_time();

    fixture.processor.check_collation();

    assert_eq!(
        fixture.processor.get_next_awake_time(),
        base_time + MAX_AWAKE_TIMEOUT,
        "with the temporary 10ms fallback poll, next_awake_time stays at the earlier fallback wake"
    );
}

#[test]
fn test_check_collation_proceeds_after_pacing_expires() {
    let mut fixture = TestFixture::new(4);
    let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fixture.processor.set_time(base_time);

    let gate_time = base_time + Duration::from_millis(500);
    fixture.processor.collation.set_earliest_collation_time(Some(gate_time));

    fixture.advance_time(Duration::from_millis(600));

    fixture.processor.reset_next_awake_time();
    fixture.processor.check_collation();

    assert_ne!(
        fixture.processor.get_next_awake_time(),
        gate_time,
        "check_collation should proceed past pacing gate after time expires"
    );
}

#[test]
fn test_check_collation_pacing_gate_is_idempotent() {
    let mut fixture = TestFixture::new(4);
    let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fixture.processor.set_time(base_time);

    let gate_time = base_time + Duration::from_millis(500);
    fixture.processor.collation.set_earliest_collation_time(Some(gate_time));

    fixture.processor.reset_next_awake_time();
    fixture.processor.check_collation();
    assert_eq!(fixture.processor.get_next_awake_time(), base_time + MAX_AWAKE_TIMEOUT);

    assert_eq!(fixture.processor.collation.earliest_collation_time(), Some(gate_time));

    fixture.processor.reset_next_awake_time();
    fixture.processor.check_collation();
    assert_eq!(fixture.processor.get_next_awake_time(), base_time + MAX_AWAKE_TIMEOUT);
}

#[test]
fn test_collation_starts_metric_tracks_async_generation_requests() {
    let opts = SessionOptions { slots_per_leader_window: 1, ..Default::default() };
    let mut fixture = TestFixture::new_with_opts(4, opts);

    fixture.processor.check_collation();

    assert_eq!(metrics_counter(&fixture.processor, "simplex_collation_starts"), 1);
    assert_eq!(metrics_counter(&fixture.processor, "simplex_collates.total"), 1);
    assert_eq!(metrics_counter(&fixture.processor, "simplex_self_collates.total"), 1);
}

#[test]
fn test_collation_starts_metric_tracks_precollated_fast_path() {
    let opts = SessionOptions { slots_per_leader_window: 1, ..Default::default() };
    let mut fixture = TestFixture::new_with_opts(4, opts);
    let slot = SlotIndex::new(0);
    let request = AsyncRequestImpl::new(11, false, fixture.description.get_time());
    let candidate = make_local_collated_candidate(&fixture, 1, 0x41);

    fixture.processor.collation.insert_precollated(
        slot,
        PrecollatedBlock { request, result: Some(CollationResult::Block(candidate)), parent: None },
    );

    fixture.processor.check_collation();

    assert_eq!(metrics_counter(&fixture.processor, "simplex_collation_starts"), 1);
    assert_eq!(metrics_counter(&fixture.processor, "simplex_collates.total"), 0);
    assert_eq!(metrics_counter(&fixture.processor, "simplex_collates_precollated.success"), 1);
    assert_eq!(metrics_counter(&fixture.processor, "simplex_self_collates.total"), 0);
}

#[test]
fn test_self_collation_acceptance_marks_success_and_records_latency() {
    let mut fixture = TestFixture::new(4);
    let slot = SlotIndex::new(0);
    let candidate_id = RawCandidateId { slot, hash: UInt256::from([0x9a; 32]) };
    let block_id =
        BlockIdExt::with_params(ShardIdent::masterchain(), 1, UInt256::rand(), UInt256::rand());

    let now = fixture.processor.now();
    fixture.processor.telemetry.record_self_collation_start(
        fixture.processor.runtime.description(),
        slot,
        1,
        None,
        None,
        &[],
        now,
    );
    fixture.processor.telemetry.record_self_collation_generated(
        slot,
        "unit_test_generated",
        fixture.processor.runtime.description(),
        now,
    );
    fixture.processor.telemetry.link_self_collation_candidate(
        slot,
        &candidate_id,
        fixture.processor.runtime.description(),
    );
    fixture.advance_time(Duration::from_millis(25));
    let now = fixture.processor.now();
    fixture.processor.telemetry.record_self_collation_acceptance(
        &candidate_id,
        &block_id,
        true,
        fixture.processor.runtime.description(),
        now,
    );

    let snapshot = fixture.processor.get_metrics_receiver().snapshot();
    assert_eq!(snapshot.counters.get("simplex_self_collates.total").copied().unwrap_or(0), 1);
    assert_eq!(snapshot.counters.get("simplex_self_collates.success").copied().unwrap_or(0), 1);
    assert_eq!(snapshot.counters.get("simplex_self_collates.failure").copied().unwrap_or(0), 0);

    let samples =
        snapshot.histograms.get("time:self_collation_accept_latency").cloned().unwrap_or_default();
    assert_eq!(samples.len(), 1, "acceptance latency histogram must have one sample");
    assert!(
        samples[0] >= 25,
        "acceptance latency sample should include advanced time, got {}",
        samples[0]
    );
}

#[test]
fn test_self_collation_retry_counts_total_only_once() {
    let fixture = TestFixture::new(4);
    let slot = SlotIndex::new(0);

    let now = fixture.processor.now();
    fixture.processor.telemetry.record_self_collation_start(
        fixture.processor.runtime.description(),
        slot,
        1,
        None,
        None,
        &[],
        now,
    );
    fixture.processor.telemetry.record_self_collation_start(
        fixture.processor.runtime.description(),
        slot,
        1,
        Some(1),
        None,
        &[],
        now,
    );
    fixture.processor.telemetry.record_self_collation_start(
        fixture.processor.runtime.description(),
        slot,
        1,
        Some(2),
        None,
        &[],
        now,
    );

    assert_eq!(
        metrics_counter(&fixture.processor, "simplex_self_collates.total"),
        1,
        "retries must NOT bump total: the whole slot is one self-collation",
    );
    assert_eq!(metrics_counter(&fixture.processor, "simplex_self_collates.success"), 0);
    assert_eq!(metrics_counter(&fixture.processor, "simplex_self_collates.failure"), 0);
}

#[test]
fn test_self_collation_failure_only_on_terminal_drop() {
    let opts = SessionOptions { slots_per_leader_window: 4, ..Default::default() };
    let mut fixture = TestFixture::new_with_opts(4, opts);
    let slot = SlotIndex::new(0);
    let request_id = 904;

    let now = fixture.processor.now();
    fixture.processor.telemetry.record_self_collation_start(
        fixture.processor.runtime.description(),
        slot,
        1,
        None,
        None,
        &[],
        now,
    );

    fixture.processor.collation.insert_precollated(
        slot,
        PrecollatedBlock {
            request: AsyncRequestImpl::new(request_id, false, now),
            result: None,
            parent: None,
        },
    );

    // A genuine error while the slot is still current schedules a single
    // restart sharing the window-end budget - it is NOT terminal, so the
    // self-collation funnel records no failure (the whole slot is one
    // self-collation, regardless of how many times the real collation restarts).
    fixture.processor.on_collation_failed_impl(slot, request_id, error!("transient error"));
    assert_eq!(metrics_counter(&fixture.processor, "simplex_self_collates.failure"), 0);
    assert_eq!(metrics_counter(&fixture.processor, "simplex_self_collates.total"), 1);

    // The consumed failed request has no further rights. A real retry owns a
    // new request id at this same slot while retaining the slot's one funnel.
    let retry_id = request_id + 1;
    fixture.processor.collation.insert_precollated(
        slot,
        PrecollatedBlock {
            request: AsyncRequestImpl::new(retry_id, false, now),
            result: None,
            parent: None,
        },
    );
    fixture.processor.on_collation_failed_impl(slot, request_id, error!("obsolete callback"));
    assert!(fixture.processor.collation.precollated_contains(slot));

    // Once the slot has progressed past (here: skip-certified by consensus), a
    // failure for it is terminal and marks the self-collation flow as failed.
    skip_slot(&mut fixture, slot);
    fixture.processor.on_collation_failed_impl(slot, retry_id, error!("slot already passed"));

    assert_eq!(metrics_counter(&fixture.processor, "simplex_self_collates.total"), 1);
    assert_eq!(metrics_counter(&fixture.processor, "simplex_self_collates.success"), 0);
    assert_eq!(metrics_counter(&fixture.processor, "simplex_self_collates.failure"), 1);
}

#[test]
fn test_self_collation_ignore_paths_do_not_increment_failure() {
    let fixture = TestFixture::new(4);
    let slot = SlotIndex::new(0);

    let now = fixture.processor.now();
    fixture.processor.telemetry.record_self_collation_start(
        fixture.processor.runtime.description(),
        slot,
        1,
        None,
        None,
        &[],
        now,
    );

    // An "ignore" path (e.g. cancelled callback / pipeline reset) just drops tracking
    // — it must NOT bump success or failure. The ignore metric is auto-derived
    // by `add_compute_result_metric` as `total - success - failure`.
    let now = fixture.processor.now();
    fixture.processor.telemetry.forget_self_collation_tracking(
        slot,
        "callback_cancelled_before_generation_result",
        fixture.processor.runtime.description(),
        now,
    );

    assert_eq!(metrics_counter(&fixture.processor, "simplex_self_collates.total"), 1);
    assert_eq!(metrics_counter(&fixture.processor, "simplex_self_collates.success"), 0);
    assert_eq!(metrics_counter(&fixture.processor, "simplex_self_collates.failure"), 0);
}

// ============================================================================
// Candidate Query Fallback Tests (C++ parity: CandidateResolver DB fallback)
// ============================================================================

#[test]
fn test_candidate_query_fallback_cache_hit() {
    let mut fixture = TestFixture::new(4);
    let slot = SlotIndex::new(5);
    let block_hash = UInt256::rand();
    let candidate_id = RawCandidateId { slot, hash: block_hash.clone() };

    let fake_candidate_bytes = vec![0xCA, 0xFE, 0xBA, 0xBE];
    fixture
        .processor
        .candidate_book_mut()
        .insert_cached_data(candidate_id, fake_candidate_bytes.clone());

    let (tx, rx) = channel();
    let callback: crate::QueryResponseCallback = Box::new(move |result| {
        tx.send(result).unwrap();
    });

    fixture.processor.handle_candidate_query_fallback(slot, block_hash, true, false, callback);

    let result = rx.recv_timeout(Duration::from_secs(2)).expect("callback not called");
    let payload = result.expect("response should be Ok");
    let response_bytes = payload.data();

    assert!(!response_bytes.is_empty(), "response should contain serialized CandidateAndCert");

    let deserialized = deserialize_boxed(response_bytes)
        .expect("should deserialize response")
        .downcast::<CandidateAndCert>()
        .expect("should be CandidateAndCert");

    let inner = match deserialized {
        CandidateAndCert::Consensus_Simplex_CandidateAndCert(inner) => inner,
    };

    assert_eq!(
        &inner.candidate[..],
        &fake_candidate_bytes[..],
        "candidate bytes should match the cached data"
    );
}

#[test]
fn test_candidate_query_fallback_miss_returns_empty() {
    let mut fixture = TestFixture::new(4);
    let slot = SlotIndex::new(99);
    let block_hash = UInt256::rand();

    let (tx, rx) = channel();
    let callback: crate::QueryResponseCallback = Box::new(move |result| {
        tx.send(result).unwrap();
    });

    fixture.processor.handle_candidate_query_fallback(slot, block_hash, true, false, callback);

    let result = rx.recv_timeout(Duration::from_secs(5)).expect("callback not called");
    let payload = result.expect("response should be Ok even for empty");
    let response_bytes = payload.data();

    let deserialized = deserialize_boxed(response_bytes)
        .expect("should deserialize response")
        .downcast::<CandidateAndCert>()
        .expect("should be CandidateAndCert");

    let inner = match deserialized {
        CandidateAndCert::Consensus_Simplex_CandidateAndCert(inner) => inner,
    };

    assert!(inner.candidate.is_empty(), "candidate bytes should be empty when not found");
}

fn make_signed_block_broadcast_with_parent(
    fixture: &TestFixture,
    slot: u32,
    block_data: Vec<u8>,
    parent_id: Option<RawCandidateId>,
) -> (u32, RawCandidateId, CandidateData) {
    let collated_data: Vec<u8> = vec![];
    let root_hash = UInt256::from_slice(&sha256_digest(&block_data));
    let shard = fixture.processor.runtime.description().get_shard().clone();

    let block_id = BlockIdExt {
        shard_id: shard,
        seq_no: slot,
        root_hash: root_hash.clone(),
        file_hash: root_hash,
    };
    let collated_file_hash = UInt256::from_slice(&sha256_digest(&collated_data));
    let data_bytes = block_data;
    let collated_data_bytes = collated_data;

    let candidate_hash = crate::utils::compute_candidate_id_hash_u32(
        slot,
        Some(&block_id),
        Some(&collated_file_hash),
        parent_id.as_ref().map(|p| (p.slot.value(), &p.hash)),
    );

    let session_id = fixture.processor.session_id().clone();
    let leader_idx = fixture.processor.runtime.description().get_leader(SlotIndex::new(slot));
    let leader_key = fixture.processor.runtime.description().get_source_public_key(leader_idx);
    let signature = crate::utils::sign_candidate_u32(
        &session_id,
        slot,
        &candidate_hash,
        leader_key.classical_key().unwrap(),
    )
    .expect("signing failed");

    let candidate_id = RawCandidateId { slot: SlotIndex::new(slot), hash: candidate_hash };
    let block = crate::block::BlockCandidate {
        id: block_id,
        collated_file_hash,
        data: data_bytes,
        collated_data: collated_data_bytes,
        creator: leader_key.clone(),
    };
    let raw_candidate = crate::block::RawCandidate::new(
        candidate_id.clone(),
        parent_id,
        leader_idx,
        block,
        signature,
    );
    let serialized = raw_candidate.serialize(false).expect("serialize RawCandidate");
    let msg = deserialize_boxed(&serialized).expect("deserialize CandidateData");
    let broadcast = msg.downcast::<CandidateData>().expect("downcast CandidateData");

    (leader_idx.value(), candidate_id, broadcast)
}

fn make_signed_block_broadcast(
    fixture: &TestFixture,
    slot: u32,
    block_data: Vec<u8>,
) -> (u32, RawCandidateId, CandidateData) {
    make_signed_block_broadcast_with_parent(fixture, slot, block_data, None)
}

fn make_signed_empty_block_broadcast_with_parent(
    fixture: &TestFixture,
    slot: u32,
    parent_id: RawCandidateId,
    referenced_block: BlockIdExt,
) -> (u32, RawCandidateId, CandidateData) {
    let candidate_hash = crate::utils::compute_candidate_id_hash_empty(
        &referenced_block,
        (parent_id.slot, &parent_id.hash),
    );
    let session_id = fixture.processor.session_id().clone();
    let leader_idx = fixture.processor.runtime.description().get_leader(SlotIndex::new(slot));
    let leader_key = fixture.processor.runtime.description().get_source_public_key(leader_idx);
    let signature = crate::utils::sign_candidate_u32(
        &session_id,
        slot,
        &candidate_hash,
        leader_key.classical_key().unwrap(),
    )
    .expect("signing failed");

    let candidate_id = RawCandidateId { slot: SlotIndex::new(slot), hash: candidate_hash };
    let raw_candidate = crate::block::RawCandidate::new_empty(
        candidate_id.clone(),
        parent_id,
        leader_idx,
        referenced_block,
        signature,
    );
    let serialized = raw_candidate.serialize(false).expect("serialize RawCandidate");
    let msg = deserialize_boxed(&serialized).expect("deserialize CandidateData");
    let broadcast = msg.downcast::<CandidateData>().expect("downcast CandidateData");

    (leader_idx.value(), candidate_id, broadcast)
}

fn make_local_collated_candidate(
    fixture: &TestFixture,
    seqno: u32,
    tag: u8,
) -> Arc<crate::ValidatorBlockCandidate> {
    let block_boc = make_test_boc(&[tag], BocFlags::all());
    let collated_boc = make_test_boc(&[tag.wrapping_add(1)], BocFlags::Crc32);
    let root_hash = UInt256::from_slice(&sha256_digest(&block_boc));
    let block_id = BlockIdExt {
        shard_id: fixture.processor.runtime.description().get_shard().clone(),
        seq_no: seqno,
        root_hash: root_hash.clone(),
        file_hash: root_hash,
    };
    let collated_file_hash = UInt256::from_slice(&sha256_digest(&collated_boc));
    let self_idx = fixture.description.get_self_idx().value() as usize;

    Arc::new(crate::ValidatorBlockCandidate {
        public_key: fixture.nodes[self_idx].public_key.clone(),
        id: block_id,
        collated_file_hash,
        data: consensus_common::ConsensusCommonFactory::create_block_payload(block_boc),
        collated_data: consensus_common::ConsensusCommonFactory::create_block_payload(collated_boc),
    })
}

#[test]
fn test_candidate_data_cache_populated_on_candidate_received() {
    let _ = env_logger::Builder::new().filter_level(log::LevelFilter::Debug).try_init();
    let mut fixture = TestFixture::new(4);

    // Use slot 0 so that validator 0 (local) is the slot leader
    let slot = 0u32;
    let (leader_source, candidate_id, broadcast) =
        make_signed_block_broadcast(&fixture, slot, vec![1u8, 2, 3, 4, 5]);

    assert!(
        !fixture.processor.candidate_book().contains_cached_data(&candidate_id),
        "cache should be empty before on_candidate_received"
    );

    fixture.processor.on_candidate_received(leader_source, broadcast, None);

    assert!(
        fixture.processor.candidate_book().contains_cached_data(&candidate_id),
        "cache should be populated after on_candidate_received"
    );

    assert!(
        fixture.processor.candidate_book().contains_received(&candidate_id),
        "candidate_book should also have the candidate"
    );
}

#[test]
fn test_candidate_ingress_metrics_split_broadcast_and_query() {
    let mut fixture = TestFixture::new(4);

    let (leader_source, _, broadcast) =
        make_signed_block_broadcast(&fixture, 1, vec![1u8, 2, 3, 4, 5]);
    fixture.processor.on_candidate_received(leader_source, broadcast, None);

    assert_eq!(metrics_counter(&fixture.processor, "simplex_candidate_received_broadcast"), 1);
    assert_eq!(metrics_counter(&fixture.processor, "simplex_candidate_received_query"), 0);

    let (_, _, query_candidate) = make_signed_block_broadcast(&fixture, 2, vec![9u8, 8, 7, 6]);
    fixture.processor.on_candidate_received(
        ValidatorIndex::new(3).value(),
        query_candidate,
        Some(Vec::new()),
    );

    assert_eq!(metrics_counter(&fixture.processor, "simplex_candidate_received_broadcast"), 1);
    assert_eq!(metrics_counter(&fixture.processor, "simplex_candidate_received_query"), 1);
}

#[test]
fn test_old_slot_broadcast_is_dropped_without_persistence_side_effects() {
    let mut fixture = TestFixture::new(4);
    fixture.processor.simplex_state.set_first_non_finalized_slot(SlotIndex::new(1));

    let slot = 0u32;
    let (leader_source, candidate_id, broadcast) =
        make_signed_block_broadcast(&fixture, slot, vec![9u8, 8, 7, 6]);

    fixture.processor.on_candidate_received(leader_source, broadcast, None /* broadcast */);

    assert!(
        !fixture.processor.candidate_book().contains_cached_data(&candidate_id),
        "old-slot broadcast must not populate candidate_data_cache"
    );
    assert!(
        !fixture.processor.candidate_book().contains_received(&candidate_id),
        "old-slot broadcast must not populate candidate_book"
    );
    assert!(
        !fixture.processor.candidate_book().contains_seen_broadcast(SlotIndex::new(slot)),
        "old-slot broadcast should be dropped before broadcast dedup state is updated"
    );
}

#[test]
fn test_candidate_precheck_keeps_simple_addition_rule() {
    let mut fixture = TestFixture::new(4);

    let slot = fixture.processor.simplex_state.max_acceptable_slot().value().saturating_add(1);
    let (leader_source, candidate_id, broadcast) =
        make_signed_block_broadcast(&fixture, slot, vec![7u8, 7, 7, 7]);

    fixture.processor.on_candidate_received(leader_source, broadcast, None);

    assert!(
        !fixture.processor.candidate_book().contains_cached_data(&candidate_id),
        "candidate above the simple-addition bound must be dropped before caching"
    );
    assert_eq!(
        metrics_counter(&fixture.processor, "simplex_candidate_precheck_drop_future_slot"),
        1
    );
}

#[test]
fn test_candidate_precheck_progress_gap_uses_progress_cursor() {
    let mut fixture = TestFixture::new(4);
    fixture.drain_receiver_actions();

    let skip_cert = build_skip_certificate_tl(&SessionId::default(), &fixture.nodes, 0, &[0, 1, 2]);
    fixture.processor.on_certificate(1, skip_cert);
    fixture.drain_receiver_actions();

    assert_eq!(fixture.processor.simplex_state.get_first_non_finalized_slot(), SlotIndex::new(0));
    assert_eq!(fixture.processor.simplex_state.get_first_non_progressed_slot(), SlotIndex::new(1));

    let slot = fixture.processor.simplex_state.max_acceptable_slot().value();
    let (leader_source, candidate_id, broadcast) =
        make_signed_block_broadcast(&fixture, slot, vec![8u8, 8, 8, 8]);

    fixture.processor.on_candidate_received(leader_source, broadcast, None);

    assert!(
        fixture.processor.candidate_book().contains_cached_data(&candidate_id),
        "candidate at the progress-anchored boundary should survive precheck even when finalization lags"
    );
}

#[test]
fn test_register_candidate_for_validation_keeps_slot_behind_progress_cursor_until_finalized() {
    let mut fixture = TestFixture::new(4);
    fixture.drain_receiver_actions();

    let skip_cert = build_skip_certificate_tl(&SessionId::default(), &fixture.nodes, 0, &[0, 1, 2]);
    fixture.processor.on_certificate(1, skip_cert);
    fixture.drain_receiver_actions();

    assert_eq!(fixture.processor.simplex_state.get_first_non_finalized_slot(), SlotIndex::new(0));
    assert_eq!(fixture.processor.simplex_state.get_first_non_progressed_slot(), SlotIndex::new(1));

    let slot = SlotIndex::new(0);
    let candidate_id = RawCandidateId { slot, hash: UInt256::rand() };
    let raw_candidate = make_test_non_empty_candidate(candidate_id.clone(), None, &fixture.nodes);
    let receive_time = fixture.description.get_time();

    let now = fixture.processor.now();
    fixture.processor.validation.register_candidate_for_validation(
        raw_candidate,
        slot,
        fixture.description.get_self_idx(),
        receive_time,
        now,
        &fixture.processor.simplex_state,
        &mut fixture.processor.runtime,
    );

    assert!(
        fixture.processor.validation.pending_validation_contains(&candidate_id),
        "candidate behind first_non_progressed_slot must stay eligible until the slot is finalized"
    );
}

#[test]
fn test_conflicting_second_broadcast_same_slot_is_dropped_by_precheck() {
    let mut fixture = TestFixture::new(4);
    let slot = 0u32;

    let (leader_source, first_id, first_broadcast) =
        make_signed_block_broadcast(&fixture, slot, vec![1u8, 1, 1, 1]);
    fixture.processor.on_candidate_received(
        leader_source,
        first_broadcast,
        None, /* broadcast */
    );

    assert!(
        fixture.processor.candidate_book().contains_received(&first_id),
        "first broadcast candidate should be accepted"
    );

    let (_, second_id, second_broadcast) =
        make_signed_block_broadcast(&fixture, slot, vec![2u8, 2, 2, 2]);
    assert_ne!(first_id, second_id, "test setup must create conflicting candidate ids");

    fixture.processor.on_candidate_received(
        leader_source,
        second_broadcast,
        None, /* broadcast */
    );

    assert!(
        !fixture.processor.candidate_book().contains_received(&second_id),
        "conflicting second broadcast for same slot must be dropped"
    );
    assert!(
        !fixture.processor.candidate_book().contains_cached_data(&second_id),
        "conflicting second broadcast must not be persisted in candidate_data_cache"
    );
    assert_eq!(
        fixture.processor.candidate_book().seen_broadcast(SlotIndex::new(slot)).cloned(),
        Some(first_id),
        "slot dedup state should keep first accepted broadcast candidate id"
    );
}

#[test]
fn test_relayed_broadcast_from_non_leader_is_accepted() {
    // Regression: an authentic, leader-signed broadcast candidate that is
    // delivered by a relay / gossip peer (sender != slot leader, no attached notar cert)
    // must be ACCEPTED, not dropped. Dropping it strands any node that missed the leader's
    // direct delivery: it can never notarize the slot, is forced to skip, and a single such
    // node is enough to wedge finalization on a notarized slot (releasenet MC stall).
    //
    // Before the fix this candidate was dropped with precheck_drop_reason=unexpected_sender;
    // after the fix it is accepted and authenticated by the leader-signature check.
    let mut fixture = TestFixture::new(4);
    let slot = 0u32;
    let (leader_source, candidate_id, broadcast) =
        make_signed_block_broadcast(&fixture, slot, vec![3u8, 4, 5, 6]);

    // Deliver the leader-signed broadcast from a peer that is NOT the slot leader,
    // exactly as a relay / gossip hop would (notar_cert = None => broadcast path).
    let relay_sender = (leader_source + 1) % 4;
    assert_ne!(relay_sender, leader_source, "relay sender must differ from the slot leader");

    fixture.processor.on_candidate_received(relay_sender, broadcast, None /* broadcast */);

    assert!(
        fixture.processor.candidate_book().contains_received(&candidate_id),
        "relayed leader-signed broadcast must be accepted into received_candidates"
    );
    assert!(
        fixture.processor.candidate_book().contains_cached_data(&candidate_id),
        "relayed leader-signed broadcast must be persisted in candidate_data_cache"
    );
    assert_eq!(
        fixture.processor.candidate_book().seen_broadcast(SlotIndex::new(slot)).cloned(),
        Some(candidate_id),
        "relayed broadcast must update the slot dedup state"
    );
    assert_eq!(
        metrics_counter(&fixture.processor, "simplex_candidate_relayed_broadcast"),
        1,
        "relayed broadcast observability counter must increment"
    );
}

// ============================================================================
// Protocol Parity Tests (stub body, partial merge, finalized seqno)
// ============================================================================

#[test]
fn test_has_real_candidate_body_returns_false_for_stub() {
    let mut fixture = TestFixture::new(4);
    let slot = SlotIndex::new(10);
    let hash = UInt256::rand();
    let candidate_id = RawCandidateId { slot, hash: hash.clone() };

    // No entry => false
    assert!(!fixture.processor.candidate_book().has_real_body(&candidate_id));

    // Insert a finalized-boundary stub (empty candidate_hash_data_bytes)
    let receive_time = fixture.processor.now();
    fixture.processor.candidate_book_mut().insert_received(
        candidate_id.clone(),
        ReceivedCandidate {
            slot,
            source_idx: ValidatorIndex::new(0),
            candidate_hash_data_bytes: Vec::new(), // stub marker
            block_id: BlockIdExt::default(),
            root_hash: UInt256::default(),
            file_hash: UInt256::default(),
            data: consensus_common::ConsensusCommonFactory::create_block_payload(Vec::new()),
            collated_data: consensus_common::ConsensusCommonFactory::create_block_payload(
                Vec::new(),
            ),
            gen_utime_ms: None,
            receive_time,
            is_empty: false,
            parent_id: None,
        },
    );

    // Stub => false
    assert!(
        !fixture.processor.candidate_book().has_real_body(&candidate_id),
        "finalized-boundary stub must NOT count as real body"
    );

    // Overwrite with real data
    fixture
        .processor
        .candidate_book_mut()
        .received_mut(&candidate_id)
        .unwrap()
        .candidate_hash_data_bytes = vec![1, 2, 3];

    assert!(
        !fixture.processor.candidate_book().has_real_body(&candidate_id),
        "hash metadata alone must not suppress body retrieval"
    );
    fixture.processor.candidate_book_mut().received_mut(&candidate_id).unwrap().data =
        consensus_common::ConsensusCommonFactory::create_block_payload(make_test_boc(
            b"candidate-body",
            BocFlags::Crc32,
        ));
    assert!(
        fixture.processor.candidate_book().has_real_body(&candidate_id),
        "metadata and actual body must count as present"
    );
}

#[test]
fn test_candidate_query_fallback_returns_notar_only_when_body_missing() {
    let mut fixture = TestFixture::new(4);
    let slot = SlotIndex::new(99);
    let block_hash = UInt256::rand();

    let (tx, rx) = channel();
    let callback: crate::QueryResponseCallback = Box::new(move |result| {
        tx.send(result).unwrap();
    });

    // No candidate in cache or DB => should return empty/empty
    fixture.processor.handle_candidate_query_fallback(slot, block_hash, false, true, callback);

    let result = rx.recv().unwrap();
    assert!(result.is_ok(), "should return Ok even when nothing found");
}

#[test]
fn test_initial_mc_tracking_seeds_from_initial_block_seqno() {
    let fixture = TestFixture::new(4);

    assert_eq!(fixture.processor.consensus.last_mc_finalized_seqno(), Some(0));
    assert_eq!(fixture.processor.consensus.last_consensus_finalized_seqno(), Some(0));
    assert_eq!(fixture.processor.consensus.accepted_normal_head_seqno(), 0);
    assert!(
        fixture.processor.consensus.accepted_normal_head_block_id().is_none(),
        "exact accepted head should be unknown until manager/recovery/finalization supplies a block id"
    );
}

#[test]
fn test_set_mc_finalized_block_couples_consensus_finalized_seqno_for_mc_session() {
    let mut fixture = TestFixture::new(4);

    // Initially 0
    assert_eq!(fixture.processor.consensus.last_mc_finalized_seqno(), Some(0));
    assert_eq!(fixture.processor.consensus.last_consensus_finalized_seqno(), Some(0));

    // Set MC-registered top to seqno 42 for this session shard.
    let mc_registered_top =
        BlockIdExt::with_params(ShardIdent::masterchain(), 42, UInt256::rand(), UInt256::rand());
    fixture.processor.set_mc_finalized_block(mc_registered_top.clone());

    // C++ parity: external MC notify updates both the applied-top cursor and the
    // producer-side consensus-finalized seqno used for empty-block policy.
    assert_eq!(fixture.processor.consensus.last_mc_finalized_seqno(), Some(42));
    assert_eq!(
        fixture.processor.consensus.last_consensus_finalized_seqno(),
        Some(42),
        "set_mc_finalized_block must advance last_consensus_finalized_seqno with the applied top"
    );
    assert_eq!(fixture.processor.consensus.accepted_normal_head_seqno(), 42);
    assert_eq!(
        fixture.processor.consensus.accepted_normal_head_block_id().as_ref(),
        Some(&mc_registered_top)
    );

    // Set consensus finalized higher via direct field (simulating a finalization)
    fixture.processor.consensus.set_last_consensus_finalized_seqno(Some(100));

    // Set MC finalized lower => should NOT decrease consensus
    let older_top =
        BlockIdExt::with_params(ShardIdent::masterchain(), 50, UInt256::rand(), UInt256::rand());
    fixture.processor.set_mc_finalized_block(older_top);
    assert_eq!(
        fixture.processor.consensus.last_consensus_finalized_seqno(),
        Some(100),
        "set_mc_finalized_block must not decrease an already advanced consensus-finalized head"
    );

    // Monotonic MC seqno: out-of-order MC event with lower seqno must not regress.
    // C++ parity uses the updated monotonic MC cursor when recomputing
    // last_consensus_finalized_seqno.
    fixture.processor.consensus.set_last_mc_finalized_seqno(Some(200));
    let out_of_order_top =
        BlockIdExt::with_params(ShardIdent::masterchain(), 150, UInt256::rand(), UInt256::rand());
    fixture.processor.set_mc_finalized_block(out_of_order_top);
    assert_eq!(
        fixture.processor.consensus.last_mc_finalized_seqno(),
        Some(200),
        "set_mc_finalized_block must keep last_mc_finalized_seqno monotonic"
    );
    assert_eq!(
        fixture.processor.consensus.last_consensus_finalized_seqno(),
        Some(200),
        "set_mc_finalized_block must recompute last_consensus_finalized_seqno from the monotonic MC cursor"
    );
}

#[test]
fn test_mc_applied_top_disables_empty_block_recovery_for_seqno_2() {
    let mut fixture = TestFixture::new(4);

    // Session starts from zerostate: seqno 1 is the first real block, so seqno 2 is
    // initially "ahead" and triggers empty-block recovery.
    assert_eq!(fixture.processor.consensus.last_consensus_finalized_seqno(), Some(0));
    assert!(
        fixture.processor.collation.should_generate_empty_block(
            SlotIndex::new(1),
            2,
            None,
            fixture.processor.consensus.finalized_head_before_split(),
            fixture.processor.consensus.last_consensus_finalized_seqno(),
            fixture.processor.consensus.last_mc_finalized_seqno(),
        ),
        "with finalized seqno 0, MC seqno 2 must use empty-block recovery"
    );

    // C++ parity: validator-manager reports that MC block 1 is applied, which advances
    // the producer-side finalized cursor through notify_mc_finalized().
    let applied_mc_top =
        BlockIdExt::with_params(ShardIdent::masterchain(), 1, UInt256::rand(), UInt256::rand());
    fixture.processor.set_mc_finalized_block(applied_mc_top.clone());

    assert_eq!(fixture.processor.consensus.last_mc_finalized_seqno(), Some(1));
    assert_eq!(fixture.processor.consensus.accepted_normal_head_seqno(), 1);
    assert_eq!(
        fixture.processor.consensus.accepted_normal_head_block_id().as_ref(),
        Some(&applied_mc_top)
    );
    assert_eq!(
        fixture.processor.consensus.last_consensus_finalized_seqno(),
        Some(1),
        "applied-top updates must promote the producer-side consensus-finalized seqno"
    );
    assert!(
        !fixture.processor.collation.should_generate_empty_block(
            SlotIndex::new(1),
            2,
            None,
            fixture.processor.consensus.finalized_head_before_split(),
            fixture.processor.consensus.last_consensus_finalized_seqno(),
            fixture.processor.consensus.last_mc_finalized_seqno(),
        ),
        "applied-top seqno 1 must suppress empty-block recovery for MC seqno 2 in C++ parity mode"
    );
}

#[test]
fn test_set_mc_finalized_block_zero_seqno_does_not_seed_exact_accepted_head() {
    let mut fixture = TestFixture::new(4);
    assert_eq!(fixture.processor.consensus.accepted_normal_head_seqno(), 0);
    assert!(
        fixture.processor.consensus.accepted_normal_head_block_id().is_none(),
        "exact accepted head starts unknown at zerostate"
    );

    let zerostate_top =
        BlockIdExt::with_params(ShardIdent::masterchain(), 0, UInt256::rand(), UInt256::rand());
    fixture.processor.set_mc_finalized_block(zerostate_top);

    assert_eq!(fixture.processor.consensus.last_mc_finalized_seqno(), Some(0));
    assert_eq!(fixture.processor.consensus.last_consensus_finalized_seqno(), Some(0));
    assert_eq!(fixture.processor.consensus.accepted_normal_head_seqno(), 0);
    assert!(
        fixture.processor.consensus.accepted_normal_head_block_id().is_none(),
        "C++ block-validator parity: external notify with seqno 0 must not seed exact accepted head"
    );
}

#[test]
fn test_set_mc_finalized_block_ignores_mismatched_shard() {
    let mut fixture = TestFixture::new(4);
    assert!(fixture.description.get_shard().is_masterchain());

    fixture.processor.consensus.set_last_mc_finalized_seqno(Some(123));
    fixture.processor.consensus.set_last_consensus_finalized_seqno(Some(123));

    let shard_block = BlockIdExt::with_params(
        ShardIdent::with_tagged_prefix(0, 0x8000_0000_0000_0000).unwrap(),
        777,
        UInt256::rand(),
        UInt256::rand(),
    );
    fixture.processor.set_mc_finalized_block(shard_block);

    assert_eq!(
        fixture.processor.consensus.last_mc_finalized_seqno(),
        Some(123),
        "mismatched shard update must be ignored"
    );
    assert_eq!(
        fixture.processor.consensus.last_consensus_finalized_seqno(),
        Some(123),
        "consensus finalized must not change on mismatched shard update"
    );
}

#[test]
fn test_set_mc_finalized_block_wakes_processor() {
    let mut fixture = TestFixture::new(4);
    let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fixture.processor.set_time(base_time);
    fixture.processor.runtime.force_next_awake_time(base_time + Duration::from_secs(60));

    let mc_registered_top =
        BlockIdExt::with_params(ShardIdent::masterchain(), 42, UInt256::rand(), UInt256::rand());
    fixture.processor.set_mc_finalized_block(mc_registered_top);

    assert_eq!(
        fixture.processor.get_next_awake_time(),
        base_time,
        "MC finalization should wake the FSM immediately"
    );
}

#[test]
fn test_check_validation_does_not_wait_for_mc_applied_head_before_submitting() {
    let mut fixture = TestFixture::new(4);

    let parent_slot = SlotIndex::new(0);
    let child_slot = SlotIndex::new(1);
    let parent_id = RawCandidateId { slot: parent_slot, hash: UInt256::rand() };
    let child_id = RawCandidateId { slot: child_slot, hash: UInt256::rand() };
    let parent_block_id =
        BlockIdExt::with_params(ShardIdent::masterchain(), 1, UInt256::rand(), UInt256::rand());

    insert_received_candidate(
        &mut fixture.processor,
        &parent_id,
        parent_block_id.clone(),
        false,
        None,
    );

    let raw_candidate =
        make_test_non_empty_candidate(child_id.clone(), Some(parent_id.clone()), &fixture.nodes);
    let time = fixture.description.get_time();
    insert_pending_validation(&mut fixture.processor, &child_id, raw_candidate, time);
    notarize_slot(&mut fixture, parent_slot, &parent_id.hash);

    fixture.processor.check_validation();
    assert!(
        fixture.processor.validation.pending_approve_contains(&child_id),
        "candidate should be submitted without a SessionProcessor wait on the accepted MC head"
    );
    assert!(
        !fixture.processor.validation.is_rejected(&child_id),
        "SessionProcessor should not reject while validator-side MC stale protection owns this check"
    );
}

#[test]
fn test_check_all_releases_validation_retry_before_revalidation() {
    let mut fixture = TestFixture::new_shard(4);

    let parent_slot = SlotIndex::new(0);
    let child_slot = SlotIndex::new(1);
    let parent_id = RawCandidateId { slot: parent_slot, hash: UInt256::rand() };
    let child_id = RawCandidateId { slot: child_slot, hash: UInt256::rand() };
    let parent_block_id = BlockIdExt::with_params(
        fixture.description.get_shard().clone(),
        1,
        UInt256::rand(),
        UInt256::rand(),
    );

    insert_received_candidate(&mut fixture.processor, &parent_id, parent_block_id, false, None);

    let raw_candidate =
        make_test_non_empty_candidate(child_id.clone(), Some(parent_id.clone()), &fixture.nodes);
    let time = fixture.description.get_time();
    insert_pending_validation(&mut fixture.processor, &child_id, raw_candidate, time);
    notarize_slot(&mut fixture, parent_slot, &parent_id.hash);

    fixture.processor.validation.insert_pending_approve(child_id.clone());
    let child_id_for_release = child_id.clone();
    fixture.processor.post_delayed_action(time, move |processor| {
        processor.validation.remove_pending_approve(&child_id_for_release);
    });

    fixture.processor.check_all();

    assert!(
        fixture.processor.validation.pending_approve_contains(&child_id),
        "retry gate release should happen before check_validation so the candidate is resubmitted in the same pass"
    );
}

#[test]
fn test_check_validation_waits_for_min_block_interval() {
    let opts =
        SessionOptions { min_block_interval: Duration::from_millis(500), ..Default::default() };
    let mut fixture = TestFixture::new_with_shard_and_local_idx(
        4,
        0,
        ShardIdent::with_tagged_prefix(0, 0x8000_0000_0000_0000).unwrap(),
        opts,
    );
    let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fixture.processor.set_time(base_time);
    fixture.processor.runtime.force_next_awake_time(base_time + Duration::from_secs(60));

    let parent_slot = SlotIndex::new(0);
    let child_slot = SlotIndex::new(1);
    let parent_id = RawCandidateId { slot: parent_slot, hash: UInt256::rand() };
    let child_id = RawCandidateId { slot: child_slot, hash: UInt256::rand() };
    let parent_block_id = BlockIdExt::with_params(
        fixture.description.get_shard().clone(),
        1,
        UInt256::rand(),
        UInt256::rand(),
    );
    let parent_gen_utime_ms =
        base_time.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64;

    insert_received_candidate_with_gen_utime_ms(
        &mut fixture.processor,
        &parent_id,
        parent_block_id,
        false,
        None,
        Some(parent_gen_utime_ms),
    );

    let raw_candidate =
        make_test_non_empty_candidate(child_id.clone(), Some(parent_id.clone()), &fixture.nodes);
    insert_pending_validation(&mut fixture.processor, &child_id, raw_candidate, base_time);
    notarize_slot(&mut fixture, parent_slot, &parent_id.hash);

    fixture.processor.check_validation();

    assert!(
        !fixture.processor.validation.pending_approve_contains(&child_id),
        "candidate should not be submitted before the min_block_interval elapses"
    );
    assert_eq!(
        fixture.processor.get_next_awake_time(),
        base_time + Duration::from_millis(500),
        "validation should arm a wake for the min_block_interval deadline"
    );

    fixture.advance_time(Duration::from_millis(600));
    fixture.processor.runtime.force_next_awake_time(base_time + Duration::from_secs(60));
    fixture.processor.check_validation();

    assert!(
        fixture.processor.validation.pending_approve_contains(&child_id),
        "candidate should be submitted after the min_block_interval elapses"
    );
}

#[test]
fn test_check_validation_does_not_reject_mc_candidate_with_wrong_exact_parent_head() {
    let mut fixture = TestFixture::new(4);

    let parent_slot = SlotIndex::new(0);
    let child_slot = SlotIndex::new(1);
    let parent_id = RawCandidateId { slot: parent_slot, hash: UInt256::rand() };
    let child_id = RawCandidateId { slot: child_slot, hash: UInt256::rand() };
    let accepted_block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        1,
        UInt256::from([0x11; 32]),
        UInt256::from([0x12; 32]),
    );
    let different_parent_block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        1,
        UInt256::from([0x21; 32]),
        UInt256::from([0x22; 32]),
    );

    fixture.processor.set_mc_finalized_block(accepted_block_id);
    insert_received_candidate(
        &mut fixture.processor,
        &parent_id,
        different_parent_block_id,
        false,
        None,
    );

    let raw_candidate =
        make_test_non_empty_candidate(child_id.clone(), Some(parent_id.clone()), &fixture.nodes);
    let time = fixture.description.get_time();
    insert_pending_validation(&mut fixture.processor, &child_id, raw_candidate, time);
    notarize_slot(&mut fixture, parent_slot, &parent_id.hash);

    fixture.processor.check_validation();
    assert!(
        fixture.processor.validation.pending_approve_contains(&child_id),
        "candidate should be submitted without exact-head rejection in SessionProcessor"
    );
    assert!(
        !fixture.processor.validation.is_rejected(&child_id),
        "SessionProcessor should not reject on exact-head mismatch; validator-side MC fork prevention covers this"
    );
}

#[test]
fn test_should_generate_empty_block_uses_parent_before_split_hint() {
    let mut fixture = TestFixture::new_shard(4);

    let parent_id = RawCandidateId { slot: SlotIndex::new(0), hash: UInt256::from([0x41; 32]) };
    let parent_block_id = BlockIdExt::with_params(
        fixture.description.get_shard().clone(),
        101,
        UInt256::from([0x51; 32]),
        UInt256::from([0x52; 32]),
    );
    insert_received_candidate(
        &mut fixture.processor,
        &parent_id,
        parent_block_id.clone(),
        false,
        None,
    );
    fixture.processor.consensus.insert_before_split(parent_block_id.clone(), true);

    let parent_info =
        crate::block::CandidateParentInfo { slot: parent_id.slot, hash: parent_id.hash.clone() };
    let parent_before_split = fixture.processor.resolve_parent_before_split_flag(
        Some(&parent_info),
        std::slice::from_ref(&parent_block_id),
    );
    assert_eq!(
        parent_before_split,
        Some(true),
        "parent-derived before_split must be resolved from current parent state"
    );

    fixture.processor.consensus.set_finalized_head_before_split(false);
    fixture.processor.consensus.set_last_mc_finalized_seqno(Some(100));
    assert!(
        fixture.processor.collation.should_generate_empty_block(
            SlotIndex::new(1),
            101,
            parent_before_split,
            fixture.processor.consensus.finalized_head_before_split(),
            fixture.processor.consensus.last_consensus_finalized_seqno(),
            fixture.processor.consensus.last_mc_finalized_seqno(),
        ),
        "parent before_split=true must force empty generation even when lag gating is false"
    );
}

#[test]
fn test_recovery_seed_received_candidates_preserves_persisted_empty_records() {
    let mut fixture = TestFixture::new(4);

    let c1 = RawCandidateId { slot: SlotIndex::new(1), hash: UInt256::from([0xA1; 32]) };
    let c2 = RawCandidateId { slot: SlotIndex::new(2), hash: UInt256::from([0xA2; 32]) };
    let c3 = RawCandidateId { slot: SlotIndex::new(3), hash: UInt256::from([0xA3; 32]) };
    let b1 = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        10,
        UInt256::from([0xB1; 32]),
        UInt256::from([0xB2; 32]),
    );
    let b2 = b1.clone();
    let b3 = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        11,
        UInt256::from([0xB3; 32]),
        UInt256::from([0xB4; 32]),
    );

    let mut bootstrap = empty_bootstrap();
    bootstrap.finalized_blocks = vec![
        FinalizedBlockRecord {
            candidate_id: c1.clone(),
            block_id: b1.clone(),
            parent: None,
            is_final: true,
        },
        FinalizedBlockRecord {
            candidate_id: c2.clone(),
            block_id: b2,
            parent: Some(c1.clone()),
            is_final: true,
        },
        FinalizedBlockRecord {
            candidate_id: c3.clone(),
            block_id: b3.clone(),
            parent: Some(c2.clone()),
            is_final: true,
        },
    ];
    run_apply_bootstrap(&mut fixture, bootstrap);

    let root = fixture.processor.candidate_book().received(&c1).expect("root record");
    assert!(!root.is_empty);

    let empty = fixture.processor.candidate_book().received(&c2).expect("empty record");
    assert!(empty.is_empty, "persisted empty MC record must remain marked empty on recovery");
    assert_eq!(empty.parent_id.as_ref(), Some(&c1));
    assert_eq!(empty.block_id, b1);

    let child = fixture.processor.candidate_book().received(&c3).expect("child record");
    assert!(!child.is_empty);
    assert_eq!(child.parent_id.as_ref(), Some(&c2));
    assert_eq!(child.block_id, b3);
}

// ============================================================================
// Foreign Certificate Relay Regression Tests (C++ parity)
// ============================================================================

/// Verify that a notarization certificate ingested via set_notarize_certificate
/// (foreign path) triggers relay to peers.
#[test]
fn test_foreign_notarization_cert_is_relayed() {
    let mut fixture = TestFixture::new(4);

    let slot = crate::block::SlotIndex::new(3);
    let block_hash = UInt256::rand();

    let signatures = vec![
        crate::certificate::VoteSignature::new(ValidatorIndex::new(0), vec![10]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(1), vec![11]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(2), vec![12]),
    ];
    let vote = crate::simplex_state::NotarizeVote { slot, block_hash: block_hash.clone() };
    let cert = Arc::new(crate::certificate::Certificate { vote, signatures });

    let event = crate::simplex_state::NotarizationReachedEvent {
        slot,
        block_hash: block_hash.clone(),
        certificate: cert,
    };

    fixture.processor.handle_notarization_reached(event);
    fixture.drain_pending_async_db_results();

    let actions = fixture.drain_receiver_actions();
    assert!(
        actions.iter().any(|a| matches!(a, ReceiverAction::SendCertificate { .. })),
        "foreign notarization cert must be relayed (C++ parity: handle_saved_certificate)"
    );
}

/// Verify that a finalization certificate ingested via set_finalize_certificate
/// (foreign path) triggers relay to peers.
#[test]
fn test_foreign_finalization_cert_is_relayed() {
    let mut fixture = TestFixture::new(4);

    let slot = crate::block::SlotIndex::new(5);
    let block_hash = UInt256::rand();

    let signatures = vec![
        crate::certificate::VoteSignature::new(ValidatorIndex::new(0), vec![20]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(1), vec![21]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(2), vec![22]),
    ];
    let vote = crate::simplex_state::FinalizeVote { slot, block_hash: block_hash.clone() };
    let cert = Arc::new(crate::certificate::Certificate { vote, signatures });

    let event = crate::simplex_state::FinalizationReachedEvent {
        slot,
        block_hash: block_hash.clone(),
        certificate: cert,
    };

    fixture.processor.handle_finalization_reached(event);
    fixture.drain_pending_async_db_results();

    let actions = fixture.drain_receiver_actions();
    assert!(
        actions.iter().any(|a| matches!(a, ReceiverAction::SendCertificate { .. })),
        "foreign finalization cert must be relayed (C++ parity: handle_saved_certificate)"
    );
}

#[test]
fn test_foreign_vote_is_not_rebroadcast() {
    let mut fixture = TestFixture::new(4);

    let slot = crate::block::SlotIndex::new(2);
    let block_hash = UInt256::from([0xAB; 32]);
    let vote = crate::simplex_state::Vote::Notarize(crate::simplex_state::NotarizeVote {
        slot,
        block_hash,
    });
    let tl_vote = crate::utils::sign_vote(
        &vote,
        fixture.description.get_session_id(),
        &fixture.nodes[1].public_key,
    )
    .expect("failed to sign foreign vote");
    let raw_vote: crate::RawVoteData =
        consensus_common::serialize_tl_boxed_object!(&tl_vote).into();

    fixture.processor.on_vote(1, tl_vote, raw_vote);

    let actions = fixture.drain_receiver_actions();
    assert!(
        !actions.iter().any(|a| matches!(a, ReceiverAction::SendVote { .. })),
        "foreign votes must not be re-broadcast"
    );
}

#[test]
fn test_recovery_reconstructed_pq_certificates_survive_repeated_bootstrap_without_relay() {
    use crate::pq_fixture as f;
    for (kind, role) in [("empty", "notarize"), ("empty", "finalize"), ("skip", "skip")] {
        let directory = crate::authenticated_fixture::TestDirectory::new();
        let path = directory.path().join("db");
        let description = f::description(ShardIdent::masterchain(), 0);
        let db = crate::database::SimplexDb::open(&path, "replayed-cert").unwrap();
        // A process can stop after storing the individual votes but before its
        // quorum certificate is saved. Use real fixture PQ signatures.
        for index in 0..2 {
            let vote = f::vote(kind, role, index, f::CONTEXT);
            let data = serialize_boxed(&vote).unwrap();
            db.save_vote_async(&crate::database::VoteRecord {
                vote_hash: UInt256::calc_file_hash(&data),
                data,
                node_idx: ValidatorIndex::new(index as u32),
                seqno: index as i64,
            })
            .unwrap();
        }
        db.sync(Some(Duration::from_secs(10))).unwrap();
        let mut bootstrap = db.load_bootstrap().unwrap();
        assert!(
            bootstrap.notar_certs.is_empty()
                && bootstrap.final_certs.is_empty()
                && bootstrap.skip_certs.is_empty()
        );
        for restart in 0..2 {
            let receiver = MockReceiver::new();
            let mut processor =
                make_pq_processor_with_description_for_test(db.clone(), description.clone());
            processor.receiver = receiver.clone();
            crate::startup_recovery::SessionStartupRecoveryProcessor::new(
                f::session(),
                description.clone(),
                bootstrap,
            )
            .apply_bootstrap(&mut processor)
            .unwrap();
            db.sync(Some(Duration::from_secs(10))).unwrap();
            processor.process_pending_async_db_results();
            assert!(
                !receiver
                    .drain_actions()
                    .iter()
                    .any(|action| matches!(action, ReceiverAction::SendCertificate { .. })),
                "historical certificates must not be relayed on restart {restart}"
            );
            bootstrap = db.load_bootstrap().unwrap();
            let records = match role {
                "notarize" => bootstrap.notar_certs.len(),
                "finalize" => bootstrap.final_certs.len(),
                _ => bootstrap.skip_certs.len(),
            };
            assert_eq!(
                records, 1,
                "reconstructed {role} certificate must be durable on restart {restart}"
            );
            // A second reader independently checks membership, quorum, session
            // and signatures in the newly stored bootstrap.
            crate::startup_recovery::SessionStartupRecoveryProcessor::new(
                f::session(),
                description.clone(),
                bootstrap.clone(),
            )
            .authenticate_pq_input()
            .unwrap();
        }
        db.close(Some(Duration::from_secs(10))).unwrap();
    }
}

#[test]
fn test_recovery_drain_startup_events_drops_certificate_relay_events() {
    let mut fixture = TestFixture::new(4);

    let slot = crate::block::SlotIndex::new(3);
    let block_hash = UInt256::from([0xCD; 32]);
    let signatures = vec![
        crate::certificate::VoteSignature::new(ValidatorIndex::new(0), vec![1]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(1), vec![2]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(2), vec![3]),
    ];
    let vote = crate::simplex_state::NotarizeVote { slot, block_hash: block_hash.clone() };
    let cert = Arc::new(crate::certificate::Certificate { vote, signatures });
    let stored = fixture
        .processor
        .simplex_state
        .set_notarize_certificate(&fixture.description, slot, &block_hash, cert)
        .expect("set_notarize_certificate should succeed");
    assert!(stored, "notar cert should be stored before startup drain");

    // Run startup recovery with a minimal non-empty bootstrap so the drain step
    // preserves the reconstructed certificate save but suppresses its historical
    // NotarizationReached relay event. The finalized block sits at slot 0 so it
    // does not interfere with the notar cert at slot 3.
    let mut bootstrap = empty_bootstrap();
    bootstrap.finalized_blocks = vec![crate::database::FinalizedBlockRecord {
        candidate_id: make_candidate_id(0, 0x01),
        block_id: make_block_id(1),
        parent: None,
        is_final: true,
    }];
    run_apply_bootstrap(&mut fixture, bootstrap);

    // Clear restore-time receiver traffic, then verify the first normal tick does
    // not re-broadcast the drained certificate-relay event.
    fixture.drain_receiver_actions();
    fixture.processor.check_all();
    let actions = fixture.drain_receiver_actions();
    assert!(
        !actions.iter().any(|a| matches!(a, ReceiverAction::SendCertificate { .. })),
        "drained startup certificate events must not be re-broadcast on first normal tick"
    );
}

// ============================================================================
// Startup recovery orchestration (apply_bootstrap) — state-based tests
//
// These exercise the full `SessionStartupRecoveryProcessor::apply_bootstrap`
// pipeline against a real `SessionProcessor` (which implements
// `StartupRecoveryBackend`) and assert on the resulting kernel state +
// drained receiver actions, replacing the former mock-listener ordering tests.
// ============================================================================

#[test]
fn test_apply_bootstrap_restores_state_first_commit_strategy() {
    // 2-validator session where self is validator 1.
    let mut fixture = TestFixture::new_with_local_idx(2, 1, SessionOptions::default());
    let session_id = fixture.description.get_session_id().clone();
    let self_idx = ValidatorIndex::new(1);

    let vote0 = crate::simplex_state::Vote::Notarize(crate::simplex_state::NotarizeVote {
        slot: SlotIndex::new(10),
        block_hash: UInt256::from([0xAA; 32]),
    });
    let vote1 = crate::simplex_state::Vote::Notarize(crate::simplex_state::NotarizeVote {
        slot: SlotIndex::new(11),
        block_hash: UInt256::from([0xBB; 32]),
    });

    let mut bootstrap = empty_bootstrap();
    bootstrap.votes = vec![
        make_vote_record(ValidatorIndex::new(0), vote0, &session_id, &fixture.nodes),
        make_vote_record(self_idx, vote1, &session_id, &fixture.nodes),
    ];
    bootstrap.finalized_blocks = vec![
        FinalizedBlockRecord {
            candidate_id: make_candidate_id(5, 0x55),
            block_id: make_block_id(100),
            parent: None,
            is_final: true,
        },
        FinalizedBlockRecord {
            candidate_id: make_candidate_id(7, 0x77),
            block_id: make_block_id(101),
            parent: None,
            is_final: true,
        },
    ];
    bootstrap.notar_certs = vec![NotarCertRecord {
        candidate_id: make_candidate_id(5, 0x55),
        notar_cert_bytes: vec![1, 2, 3].into(),
    }];
    bootstrap.pool_state =
        Some(PoolStateRecord { first_nonannounced_window: crate::block::WindowIndex::new(2) });

    run_apply_bootstrap(&mut fixture, bootstrap);

    // Finalized boundary = max finalized slot (7) + 1.
    assert_eq!(
        fixture.processor.simplex_state.get_first_non_finalized_slot(),
        SlotIndex::new(8),
        "finalized boundary must be max finalized slot + 1"
    );

    // Both finalized records seeded into received_candidates for restart lookups.
    assert!(fixture.processor.candidate_book().received(&make_candidate_id(5, 0x55)).is_some());
    assert!(fixture.processor.candidate_book().received(&make_candidate_id(7, 0x77)).is_some());

    // Last-finalized notification advanced the finalized head to the newest record.
    assert_eq!(fixture.processor.consensus.finalized_head_seqno(), Some(101));
    assert_eq!(fixture.processor.consensus.finalized_head_slot(), Some(SlotIndex::new(7)));

    let actions = fixture.drain_receiver_actions();
    assert!(
        actions.iter().any(|a| matches!(a, ReceiverAction::CacheNotarizationCert { slot: 5, .. })),
        "notar cert must be restored into the receiver cache"
    );
    assert!(
        actions.iter().any(|a| matches!(a, ReceiverAction::SetIngressSlotBegin { slot: 8 })),
        "receiver ingress lower bound must be synced to the restored frontier"
    );
}

#[test]
fn test_apply_bootstrap_replays_final_certs_repairs_boundary() {
    let mut fixture = TestFixture::new(4);
    let session_id = fixture.description.get_session_id().clone();

    let restored_final = make_candidate_id(736, 0xF7);
    let final_cert =
        make_final_cert_record(&session_id, &fixture.nodes, restored_final.clone(), &[0, 1, 2]);

    let mut bootstrap = empty_bootstrap();
    bootstrap.finalized_blocks = vec![FinalizedBlockRecord {
        candidate_id: make_candidate_id(31, 0x31),
        block_id: make_block_id(143_023),
        parent: None,
        is_final: true,
    }];
    bootstrap.final_certs = vec![final_cert];
    bootstrap.pool_state =
        Some(PoolStateRecord { first_nonannounced_window: crate::block::WindowIndex::new(94) });

    run_apply_bootstrap(&mut fixture, bootstrap);

    // Replaying the persisted FinalCert during recovery repairs the
    // finalized boundary BEYOND the filtered finalized_blocks (slot 31 -> 737),
    // which suppresses restart-skip generation for the already-finalized slot.
    assert_eq!(
        fixture.processor.simplex_state.get_first_non_finalized_slot(),
        SlotIndex::new(737),
        "FinalCert replay must repair the finalized boundary beyond finalized_blocks"
    );
    assert!(
        fixture
            .processor
            .simplex_state
            .get_finalize_certificate(restored_final.slot, &restored_final.hash)
            .is_some(),
        "persisted FinalCert must be seeded into simplex_state during recovery"
    );
}

#[test]
fn test_apply_bootstrap_replays_skip_certs() {
    let mut fixture = TestFixture::new(4);
    let session_id = fixture.description.get_session_id().clone();

    let skip_slot = SlotIndex::new(656);
    let skip_cert = make_skip_cert_record(&session_id, &fixture.nodes, skip_slot, &[0, 1, 2]);

    let mut bootstrap = empty_bootstrap();
    bootstrap.finalized_blocks = vec![FinalizedBlockRecord {
        candidate_id: make_candidate_id(639, 0x63),
        block_id: make_block_id(136_107),
        parent: None,
        is_final: true,
    }];
    bootstrap.skip_certs = vec![skip_cert];
    bootstrap.pool_state =
        Some(PoolStateRecord { first_nonannounced_window: crate::block::WindowIndex::new(83) });

    run_apply_bootstrap(&mut fixture, bootstrap);

    // Persisted SkipCert must be replayed/seeded during recovery (before
    // restart-skip generation) so the skipped-slot progress cursor is restored.
    assert!(
        fixture.processor.simplex_state.has_skip_certificate(skip_slot),
        "persisted SkipCert must be seeded into simplex_state during recovery"
    );
}

#[test]
fn test_apply_bootstrap_seeds_persisted_empty_mc_chain() {
    let mut fixture = TestFixture::new(4);

    let c1 = make_candidate_id(10, 0xA1);
    let c2 = make_candidate_id(11, 0xA2);
    let c3 = make_candidate_id(12, 0xA3);

    let mut bootstrap = empty_bootstrap();
    bootstrap.finalized_blocks = vec![
        FinalizedBlockRecord {
            candidate_id: c1.clone(),
            block_id: make_block_id(100),
            parent: None,
            is_final: true,
        },
        // c2 shares c1's block_id (seqno 100) -> recognized as an empty MC record.
        FinalizedBlockRecord {
            candidate_id: c2.clone(),
            block_id: make_block_id(100),
            parent: Some(c1.clone()),
            is_final: true,
        },
        FinalizedBlockRecord {
            candidate_id: c3.clone(),
            block_id: make_block_id(101),
            parent: Some(c2.clone()),
            is_final: true,
        },
    ];

    run_apply_bootstrap(&mut fixture, bootstrap);

    assert!(fixture.processor.candidate_book().received(&c1).is_some());
    let mid = fixture.processor.candidate_book().received(&c2).expect("middle record");
    assert!(mid.is_empty, "shared-block-id record must be marked empty on recovery");
    assert_eq!(mid.parent_id.as_ref(), Some(&c1));
    assert!(fixture.processor.candidate_book().received(&c3).is_some());

    // Last-finalized notification still targets the newest final record.
    assert_eq!(fixture.processor.consensus.finalized_head_seqno(), Some(101));
    assert_eq!(fixture.processor.consensus.finalized_head_slot(), Some(c3.slot));
}

#[test]
fn test_apply_bootstrap_does_not_generate_skip_votes_when_window_zero() {
    let mut fixture = TestFixture::new(4);

    let mut bootstrap = empty_bootstrap();
    bootstrap.finalized_blocks = vec![FinalizedBlockRecord {
        candidate_id: make_candidate_id(1, 0x11),
        block_id: make_block_id(1),
        parent: None,
        is_final: true,
    }];
    bootstrap.pool_state =
        Some(PoolStateRecord { first_nonannounced_window: crate::block::WindowIndex::new(0) });

    run_apply_bootstrap(&mut fixture, bootstrap);

    assert_eq!(
        fixture.processor.simplex_state.get_first_non_finalized_slot(),
        SlotIndex::new(2),
        "finalized boundary must be max finalized slot + 1"
    );
    assert_eq!(fixture.processor.consensus.finalized_head_seqno(), Some(1));

    // first_nonannounced_window == 0 => no restart skip votes generated, so the
    // first normal tick broadcasts no votes.
    fixture.drain_receiver_actions();
    fixture.processor.check_all();
    let actions = fixture.drain_receiver_actions();
    assert!(
        !actions.iter().any(|a| matches!(a, ReceiverAction::SendVote { .. })),
        "no restart skip votes must be generated when first_nonannounced_window=0"
    );
}

#[test]
fn test_apply_bootstrap_restore_candidate_bytes_roundtrip_empty_and_non_empty() {
    let mut fixture = TestFixture::new(1); // single validator is enough for this test

    let shard = ShardIdent::masterchain();
    let max_size = 1_000_000;

    // Parent candidate id (used by both empty and non-empty for parent linkage).
    let parent_id = RawCandidateId { slot: SlotIndex::new(9), hash: UInt256::from([0xAA; 32]) };

    // Empty block record (CandidateHashDataEmpty).
    let empty_referenced_block = BlockIdExt {
        shard_id: shard.clone(),
        seq_no: 50,
        root_hash: UInt256::from([0x10; 32]),
        file_hash: UInt256::from([0x11; 32]),
    };
    let empty_hash = crate::utils::compute_candidate_id_hash_empty(
        &empty_referenced_block,
        (parent_id.slot, &parent_id.hash),
    );
    let empty_candidate_id = RawCandidateId { slot: SlotIndex::new(10), hash: empty_hash };

    // Non-empty block record (CandidateHashDataOrdinary + real candidate TL bytes).
    let non_empty_round_seqno: i32 = 51;
    let non_empty_root_hash = UInt256::from([0x22; 32]);
    let non_empty_data = make_test_boc(b"block_data_bytes", BocFlags::all());
    let non_empty_collated = make_test_boc(b"collated_data_bytes", BocFlags::Crc32);
    let candidate_payload_bytes = make_validator_session_candidate_bytes(
        non_empty_round_seqno,
        non_empty_root_hash.clone(),
        non_empty_data.clone(),
        non_empty_collated.clone(),
    );

    let non_empty_hash = crate::utils::compute_candidate_id_hash_from_bytes(
        SlotIndex::new(11),
        &candidate_payload_bytes,
        Some((parent_id.slot, &parent_id.hash)),
        &shard,
        max_size,
        0,
    )
    .expect("compute_candidate_id_hash_from_bytes failed");
    let non_empty_candidate_id = RawCandidateId { slot: SlotIndex::new(11), hash: non_empty_hash };

    let non_empty_file_hash = UInt256::from_slice(&sha256_digest(&non_empty_data));
    let non_empty_collated_file_hash = UInt256::from_slice(&sha256_digest(&non_empty_collated));
    let non_empty_block_id = BlockIdExt {
        shard_id: shard.clone(),
        seq_no: non_empty_round_seqno as u32,
        root_hash: non_empty_root_hash.clone(),
        file_hash: non_empty_file_hash.clone(),
    };

    let empty_info = CandidateInfoRecord {
        candidate_id: empty_candidate_id.clone(),
        leader_idx: 0,
        candidate_hash_data: make_candidate_hash_data_empty(
            empty_referenced_block.clone(),
            parent_id.clone(),
        ),
        signature: vec![0xE1; 64].into(),
    };
    let non_empty_info = CandidateInfoRecord {
        candidate_id: non_empty_candidate_id.clone(),
        leader_idx: 0,
        candidate_hash_data: make_candidate_hash_data_with_parent(
            non_empty_block_id.clone(),
            non_empty_collated_file_hash.clone(),
            Some(parent_id.clone()),
        ),
        signature: vec![0xB1; 64].into(),
    };

    let mut bootstrap = empty_bootstrap();
    bootstrap.finalized_blocks = vec![
        FinalizedBlockRecord {
            candidate_id: empty_candidate_id.clone(),
            block_id: empty_referenced_block.clone(),
            parent: Some(parent_id.clone()),
            is_final: true,
        },
        FinalizedBlockRecord {
            candidate_id: non_empty_candidate_id.clone(),
            block_id: non_empty_block_id.clone(),
            parent: Some(empty_candidate_id.clone()),
            is_final: true,
        },
    ];
    bootstrap.candidate_infos = vec![empty_info.clone(), non_empty_info];

    run_apply_bootstrap(&mut fixture, bootstrap);

    // Only the empty candidate is cached; non-empty candidates are resolved via
    // peer overlay, not reconstructed during recovery.
    let actions = fixture.drain_receiver_actions();
    let cached: Vec<(u32, UInt256, Vec<u8>)> = actions
        .iter()
        .filter_map(|a| match a {
            ReceiverAction::CacheCandidateBytes { slot, block_hash, candidate_data } => {
                Some((*slot, block_hash.clone(), candidate_data.clone()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(cached.len(), 1, "only the empty candidate must be cached during recovery");

    let (slot, _hash, bytes) = &cached[0];
    assert_eq!(*slot, empty_candidate_id.slot.value());
    let msg = deserialize_boxed(bytes).expect("deserialize CandidateData");
    let candidate_data = msg.downcast::<CandidateData>().expect("downcast CandidateData");
    match candidate_data {
        CandidateData::Consensus_Empty(empty) => {
            assert_eq!(SlotIndex::new(empty.slot as u32), empty_candidate_id.slot);
            assert_eq!(empty.signature, empty_info.signature);
            assert_eq!(empty.block, empty_referenced_block);
            assert_eq!(SlotIndex::new(*empty.parent.slot() as u32), parent_id.slot);
            assert_eq!(empty.parent.hash(), &parent_id.hash);
        }
        CandidateData::Consensus_Block(_) => {
            panic!("non-empty block should not be cached during startup recovery");
        }
    }
}

#[test]
fn test_apply_bootstrap_restore_candidate_bytes_skips_non_empty_and_keeps_empty() {
    let mut fixture = TestFixture::new(1);

    let shard = ShardIdent::masterchain();
    let parent_id = RawCandidateId { slot: SlotIndex::new(9), hash: UInt256::from([0xAA; 32]) };

    // Empty candidate (valid, reconstructable).
    let empty_block = BlockIdExt {
        shard_id: shard.clone(),
        seq_no: 7,
        root_hash: UInt256::from([0x10; 32]),
        file_hash: UInt256::from([0x11; 32]),
    };
    let empty_hash = crate::utils::compute_candidate_id_hash_empty(
        &empty_block,
        (parent_id.slot, &parent_id.hash),
    );
    let empty_candidate_id = RawCandidateId { slot: SlotIndex::new(10), hash: empty_hash };

    // Non-empty candidate (skipped during recovery).
    let non_empty_candidate_id =
        RawCandidateId { slot: SlotIndex::new(11), hash: UInt256::from([0x22; 32]) };
    let non_empty_block_id = BlockIdExt {
        shard_id: shard.clone(),
        seq_no: 8,
        root_hash: UInt256::from([0x33; 32]),
        file_hash: UInt256::from([0x44; 32]),
    };

    let empty_info = CandidateInfoRecord {
        candidate_id: empty_candidate_id.clone(),
        leader_idx: 0,
        candidate_hash_data: make_candidate_hash_data_empty(empty_block.clone(), parent_id.clone()),
        signature: vec![0xE1; 64].into(),
    };
    let non_empty_info = CandidateInfoRecord {
        candidate_id: non_empty_candidate_id.clone(),
        leader_idx: 0,
        candidate_hash_data: make_candidate_hash_data_with_parent(
            non_empty_block_id.clone(),
            UInt256::from([0x55; 32]),
            Some(parent_id.clone()),
        ),
        signature: vec![0xB1; 64].into(),
    };

    let mut bootstrap = empty_bootstrap();
    bootstrap.finalized_blocks = vec![
        FinalizedBlockRecord {
            candidate_id: empty_candidate_id.clone(),
            block_id: empty_block.clone(),
            parent: Some(parent_id.clone()),
            is_final: true,
        },
        FinalizedBlockRecord {
            candidate_id: non_empty_candidate_id.clone(),
            block_id: non_empty_block_id.clone(),
            parent: Some(empty_candidate_id.clone()),
            is_final: true,
        },
    ];
    bootstrap.candidate_infos = vec![empty_info, non_empty_info];

    run_apply_bootstrap(&mut fixture, bootstrap);

    let actions = fixture.drain_receiver_actions();
    let cached: Vec<(u32, UInt256, Vec<u8>)> = actions
        .iter()
        .filter_map(|a| match a {
            ReceiverAction::CacheCandidateBytes { slot, block_hash, candidate_data } => {
                Some((*slot, block_hash.clone(), candidate_data.clone()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(cached.len(), 1, "empty candidate cached, non-empty skipped (not fetched)");
    assert_eq!(cached[0].0, SlotIndex::new(10).value());

    let msg = deserialize_boxed(&cached[0].2).expect("deserialize CandidateData");
    let candidate_data = msg.downcast::<CandidateData>().expect("downcast CandidateData");
    assert!(
        matches!(candidate_data, CandidateData::Consensus_Empty(_)),
        "expected empty candidate to be reconstructed"
    );
}

// ============================================================================
// Finalized journal cleanup tests
// ============================================================================

/// Verify that `cleanup_old_candidates` never ages out an unresolved finalized-journal
/// entry (C++ keeps every agreed certificate until it is converted) and treats the old
/// entry as no session error.
#[test]
fn test_journal_cleanup_keeps_unresolved_entries() {
    let mut fixture = TestFixture::new(4);

    let old_slot = SlotIndex::new(5);
    let current_slot = SlotIndex::new(20);
    let old_hash = UInt256::rand();
    let current_hash = UInt256::rand();

    let old_id = RawCandidateId { slot: old_slot, hash: old_hash.clone() };
    let current_id = RawCandidateId { slot: current_slot, hash: current_hash.clone() };

    let dummy_cert: crate::certificate::FinalCertPtr = Arc::new(crate::certificate::Certificate {
        vote: crate::simplex_state::FinalizeVote { slot: old_slot, block_hash: old_hash.clone() },
        signatures: Vec::new(),
    });

    let dummy_cert2: crate::certificate::FinalCertPtr = Arc::new(crate::certificate::Certificate {
        vote: crate::simplex_state::FinalizeVote {
            slot: current_slot,
            block_hash: current_hash.clone(),
        },
        signatures: Vec::new(),
    });

    let now = fixture.description.get_time();

    fixture.processor.consensus.insert_pending_body_for_test(
        old_id.clone(),
        BlockFinalizedEvent {
            slot: old_slot,
            block_hash: old_hash,
            block_id: None,
            certificate: dummy_cert,
        },
        now - Duration::from_secs(60),
    );

    fixture.processor.consensus.insert_pending_body_for_test(
        current_id.clone(),
        BlockFinalizedEvent {
            slot: current_slot,
            block_hash: current_hash,
            block_id: None,
            certificate: dummy_cert2,
        },
        now,
    );

    assert_eq!(fixture.processor.consensus.finalized_pending_body_len(), 2);

    let errors_before =
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed);

    // Cleanup slots < 10 — both unresolved entries stay, old_slot(5) included.
    fixture.processor.cleanup_old_candidates(SlotIndex::new(10));

    assert_eq!(fixture.processor.consensus.finalized_pending_body_len(), 2);
    assert!(fixture.processor.consensus.finalized_pending_body_contains(&old_id));
    assert!(fixture.processor.consensus.finalized_pending_body_contains(&current_id));

    let errors_after =
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        errors_after, errors_before,
        "stale finalized-journal entries should be pruned without incrementing error count"
    );
}

#[test]
fn test_cleanup_old_candidates_prunes_candidate_info_store_results() {
    let mut fixture = TestFixture::new(4);

    let (leader_old, old_id, old_broadcast) =
        make_signed_block_broadcast(&fixture, 4, vec![1, 1, 1]);
    fixture.processor.on_candidate_received(leader_old, old_broadcast, None);
    let (leader_new, new_id, new_broadcast) =
        make_signed_block_broadcast(&fixture, 24, vec![2, 2, 2]);
    fixture.processor.on_candidate_received(leader_new, new_broadcast, None);

    assert!(
        fixture.processor.database.contains_candidate_info_store(&old_id),
        "old candidate must exist before cleanup"
    );
    assert!(
        fixture.processor.database.contains_candidate_info_store(&new_id),
        "new candidate must exist before cleanup"
    );

    fixture.processor.cleanup_old_candidates(SlotIndex::new(10));

    assert!(
        !fixture.processor.database.contains_candidate_info_store(&old_id),
        "candidate_info_store_results must prune entries below cleanup slot"
    );
    assert!(
        fixture.processor.database.contains_candidate_info_store(&new_id),
        "candidate_info_store_results must keep entries at/above cleanup slot"
    );
}

// ============================================================================
// on_block_finalized / maybe_apply_finalized_state tests
// ============================================================================

#[test]
fn test_finalized_callback_not_emitted_when_finalized_record_persist_fails() {
    let mut opts = SessionOptions::default();
    opts.use_callback_thread = false;
    let mut fixture = TestFixture::new_with_opts(4, opts);

    let recording = RecordingListener::new();
    let listener: Arc<dyn consensus_common::SessionListener + Send + Sync> = recording.clone();
    fixture.processor.set_listener_for_test(Arc::downgrade(&listener));

    let (leader_source, candidate_id, broadcast) =
        make_signed_block_broadcast(&fixture, 94, vec![0x10, 0x20, 0x30]);
    fixture.processor.on_candidate_received(leader_source, broadcast, None);
    let received = fixture
        .processor
        .candidate_book()
        .received(&candidate_id)
        .expect("candidate must exist")
        .clone();

    fixture.processor.database.db().fail_next_finalized_block_save_for_test();
    fixture.processor.handle_block_finalized(BlockFinalizedEvent {
        slot: candidate_id.slot,
        block_hash: candidate_id.hash.clone(),
        block_id: Some(received.block_id.clone()),
        certificate: make_test_final_cert(candidate_id.slot, candidate_id.hash.clone()),
    });

    let events = recording.drain_events();
    assert!(
        !events.iter().any(|e| matches!(e, ListenerEvent::Finalized { .. })),
        "callback must not be emitted when finalized record persistence fails"
    );
    assert!(
        !fixture.processor.consensus.is_finalized_block(&candidate_id),
        "candidate must not enter finalized_blocks set on persist failure"
    );
    assert!(
        fixture.processor.consensus.finalized_pending_body_contains(&candidate_id),
        "trigger must remain pending for retry after persist failure"
    );
}

/// Finalized-record persist now happens asynchronously through the SXMAIN
/// async-DB-results registry (`maybe_apply_finalized_state` migration). The
/// listener callback fires before the persist completes — matching C++
/// `state-resolver.cpp::do_finalize_blocks`:
///
/// ```text
///   co_await owning_bus().publish<FinalizeBlock>(candidate, sig_set);  // callback
///   ...
///   co_await bus.db->set(std::move(key), td::BufferSlice());           // persist
/// ```
///
/// This test verifies the new ordering invariants:
/// 1. The `on_block_finalized` callback fires (immediately, with the in-memory
///    state already applied).
/// 2. The finalized record is eventually durable in the DB after the SXMAIN
///    registry continuation drains and the storage queue flushes.
#[test]
fn test_finalized_callback_fires_then_record_eventually_persists() {
    struct CallbackTracker {
        db: crate::database::SimplexDbPtr,
        candidate_id: RawCandidateId,
        callback_invoked: Arc<AtomicBool>,
        persisted_visible_during_callback: Arc<AtomicBool>,
    }

    impl consensus_common::SessionListener for CallbackTracker {
        fn on_candidate(
            &self,
            _source_info: BlockSourceInfo,
            _root_hash: UInt256,
            _data: BlockPayloadPtr,
            _collated_data: BlockPayloadPtr,
            _callback: ValidatorBlockCandidateDecisionCallback,
        ) {
        }

        fn on_generate_slot(
            &self,
            _source_info: BlockSourceInfo,
            _request: AsyncCollationRequestPtr,
            _parent: CollationParentHint,
            _callback: ValidatorBlockCandidateCallback,
        ) {
        }

        fn on_block_committed(
            &self,
            _source_info: BlockSourceInfo,
            _root_hash: UInt256,
            _file_hash: UInt256,
            _data: BlockPayloadPtr,
            _signatures: BlockSignaturesVariant,
            _approve_signatures: Vec<(PublicKeyHash, BlockPayloadPtr)>,
            _stats: SessionStats,
        ) {
            panic!(
                "on_block_committed must not be called for Simplex sessions (finalized-driven only)"
            );
        }

        fn on_block_skipped(&self, _round: u32) {}

        fn on_block_finalized(
            &self,
            _block_id: BlockIdExt,
            _source_info: BlockSourceInfo,
            _root_hash: UInt256,
            _file_hash: UInt256,
            _data: BlockPayloadPtr,
            _signatures: consensus_common::SessionFinality,
            _approve_signatures: Vec<(PublicKeyHash, BlockPayloadPtr)>,
        ) {
            self.callback_invoked.store(true, Ordering::Relaxed);
            // Snapshot DB visibility at callback time — informational only.
            // The new ordering does NOT guarantee the record is persisted yet
            // (matches C++ which `co_await`s FinalizeBlock before db->set).
            let has_record = self
                .db
                .load_finalized_blocks()
                .expect("finalized records load must succeed")
                .iter()
                .any(|record| record.candidate_id == self.candidate_id);
            self.persisted_visible_during_callback.store(has_record, Ordering::Relaxed);
        }

        fn get_approved_candidate(
            &self,
            _source: PublicKey,
            root_hash: UInt256,
            _file_hash: UInt256,
            _collated_data_hash: UInt256,
            _callback: ValidatorBlockCandidateCallback,
        ) {
            panic!(
                "unexpected legacy get_approved_candidate request in CallbackTracker (root_hash={})",
                root_hash.to_hex_string()
            );
        }
    }

    let mut opts = SessionOptions::default();
    opts.use_callback_thread = false;
    let mut fixture = TestFixture::new_with_opts(4, opts);

    let (leader_source, candidate_id, broadcast) =
        make_signed_block_broadcast(&fixture, 95, vec![0x44, 0x55, 0x66]);
    fixture.processor.on_candidate_received(leader_source, broadcast, None);
    let received = fixture
        .processor
        .candidate_book()
        .received(&candidate_id)
        .expect("candidate must exist")
        .clone();

    let callback_invoked = Arc::new(AtomicBool::new(false));
    let persisted_visible_during_callback = Arc::new(AtomicBool::new(false));
    let listener: Arc<dyn consensus_common::SessionListener + Send + Sync> =
        Arc::new(CallbackTracker {
            db: fixture.processor.database.db().clone(),
            candidate_id: candidate_id.clone(),
            callback_invoked: callback_invoked.clone(),
            persisted_visible_during_callback: persisted_visible_during_callback.clone(),
        });
    fixture.processor.set_listener_for_test(Arc::downgrade(&listener));

    fixture.processor.handle_block_finalized(BlockFinalizedEvent {
        slot: candidate_id.slot,
        block_hash: candidate_id.hash.clone(),
        block_id: Some(received.block_id.clone()),
        certificate: make_test_final_cert(candidate_id.slot, candidate_id.hash.clone()),
    });

    assert!(
        callback_invoked.load(Ordering::Relaxed),
        "on_block_finalized callback must fire (state applied inline before persist)",
    );
    assert!(
        fixture.processor.consensus.is_finalized_block(&candidate_id),
        "finalized_blocks must contain the candidate after the inline apply",
    );
    let _ = persisted_visible_during_callback.load(Ordering::Relaxed);

    // Drain the SXMAIN async-DB-results registry so the persist continuation
    // runs, then sync the storage queue to flush the actual RocksDB write.
    fixture.drain_pending_async_db_results();
    fixture.processor.database.db().sync(Some(Duration::from_secs(2))).expect("sync must succeed");

    let persisted_visible_after = fixture
        .processor
        .database
        .db()
        .load_finalized_blocks()
        .expect("finalized records load must succeed")
        .iter()
        .any(|record| record.candidate_id == candidate_id);
    assert!(
        persisted_visible_after,
        "finalized record must be visible in DB once registry drains and storage flushes",
    );
}

/// Finalized block with body present must advance `finalized_head_seqno`
/// and `last_consensus_finalized_seqno`.
#[test]
fn test_finalized_with_body_advances_committed_seqno() {
    let mut opts = SessionOptions::default();
    opts.use_callback_thread = false;
    let mut fixture = TestFixture::new_with_opts(4, opts);

    let recording = RecordingListener::new();
    let listener: Arc<dyn consensus_common::SessionListener + Send + Sync> = recording.clone();
    fixture.processor.set_listener_for_test(Arc::downgrade(&listener));

    assert_eq!(fixture.processor.consensus.finalized_head_seqno(), Some(0));
    assert_eq!(fixture.processor.consensus.last_consensus_finalized_seqno(), Some(0));

    let slot = 5u32;
    let (leader_source, candidate_id, broadcast) =
        make_signed_block_broadcast(&fixture, slot, vec![1, 2, 3, 4]);
    fixture.processor.on_candidate_received(leader_source, broadcast, None);

    let received = fixture
        .processor
        .candidate_book()
        .received(&candidate_id)
        .expect("candidate must be present")
        .clone();

    let event = BlockFinalizedEvent {
        slot: candidate_id.slot,
        block_hash: candidate_id.hash.clone(),
        block_id: Some(received.block_id.clone()),
        certificate: make_test_final_cert(candidate_id.slot, candidate_id.hash.clone()),
    };
    fixture.processor.handle_block_finalized(event);

    assert_eq!(
        fixture.processor.consensus.finalized_head_seqno(),
        Some(received.block_id.seq_no()),
        "finalized_head_seqno must advance to finalized block seqno"
    );
    assert_eq!(
        fixture.processor.consensus.last_consensus_finalized_seqno(),
        Some(received.block_id.seq_no()),
        "last_consensus_finalized_seqno must advance to finalized block seqno"
    );
    assert!(
        fixture.processor.consensus.is_finalized_block(&candidate_id),
        "candidate must be in finalized_blocks set"
    );

    let events = recording.drain_events();
    assert!(
        events.iter().any(|e| matches!(e, ListenerEvent::Finalized { .. })),
        "on_block_finalized callback must be emitted"
    );
}

/// Out-of-order finalization: higher seqno finalized first, then lower seqno.
/// Both must advance cursors monotonically (never decrease).
#[test]
fn test_finalized_out_of_order_seqno_advances_monotonically() {
    let mut opts = SessionOptions::default();
    opts.use_callback_thread = false;
    let mut fixture = TestFixture::new_with_opts(4, opts);

    let recording = RecordingListener::new();
    let listener: Arc<dyn consensus_common::SessionListener + Send + Sync> = recording.clone();
    fixture.processor.set_listener_for_test(Arc::downgrade(&listener));

    let slot_high = 10u32;
    let (leader_high, id_high, broadcast_high) =
        make_signed_block_broadcast(&fixture, slot_high, vec![10, 20, 30]);
    fixture.processor.on_candidate_received(leader_high, broadcast_high, None);

    let received_high = fixture.processor.candidate_book().received(&id_high).unwrap().clone();

    let event_high = BlockFinalizedEvent {
        slot: id_high.slot,
        block_hash: id_high.hash.clone(),
        block_id: Some(received_high.block_id.clone()),
        certificate: make_test_final_cert(id_high.slot, id_high.hash.clone()),
    };
    fixture.processor.handle_block_finalized(event_high);

    let seqno_after_high = fixture.processor.consensus.finalized_head_seqno();
    let consensus_after_high = fixture.processor.consensus.last_consensus_finalized_seqno();

    let slot_low = 3u32;
    let (leader_low, id_low, broadcast_low) =
        make_signed_block_broadcast(&fixture, slot_low, vec![40, 50, 60]);
    fixture.processor.on_candidate_received(leader_low, broadcast_low, None);

    let received_low = fixture.processor.candidate_book().received(&id_low).unwrap().clone();

    let event_low = BlockFinalizedEvent {
        slot: id_low.slot,
        block_hash: id_low.hash.clone(),
        block_id: Some(received_low.block_id.clone()),
        certificate: make_test_final_cert(id_low.slot, id_low.hash.clone()),
    };
    fixture.processor.handle_block_finalized(event_low);

    assert!(
        fixture.processor.consensus.finalized_head_seqno() >= seqno_after_high,
        "finalized_head_seqno must not decrease after lower-seqno finalization: \
        before={:?} after={:?}",
        seqno_after_high,
        fixture.processor.consensus.finalized_head_seqno(),
    );
    assert!(
        fixture.processor.consensus.last_consensus_finalized_seqno() >= consensus_after_high,
        "last_consensus_finalized_seqno must not decrease after lower-seqno finalization: \
        before={:?} after={:?}",
        consensus_after_high,
        fixture.processor.consensus.last_consensus_finalized_seqno(),
    );
    assert!(fixture.processor.consensus.is_finalized_block(&id_high));
    assert!(fixture.processor.consensus.is_finalized_block(&id_low));

    let events = recording.drain_events();
    let finalized_count =
        events.iter().filter(|e| matches!(e, ListenerEvent::Finalized { .. })).count();
    assert_eq!(finalized_count, 2, "both blocks must emit on_block_finalized callbacks");
}

/// Duplicate finalization for the same candidate must be deduplicated:
/// second call must not re-emit callback and must not modify cursors.
#[test]
fn test_finalized_duplicate_is_idempotent() {
    let mut opts = SessionOptions::default();
    opts.use_callback_thread = false;
    let mut fixture = TestFixture::new_with_opts(4, opts);

    let recording = RecordingListener::new();
    let listener: Arc<dyn consensus_common::SessionListener + Send + Sync> = recording.clone();
    fixture.processor.set_listener_for_test(Arc::downgrade(&listener));

    let slot = 7u32;
    let (leader_source, candidate_id, broadcast) =
        make_signed_block_broadcast(&fixture, slot, vec![0xDE, 0xAD]);
    fixture.processor.on_candidate_received(leader_source, broadcast, None);

    let received = fixture.processor.candidate_book().received(&candidate_id).unwrap().clone();

    let event = BlockFinalizedEvent {
        slot: candidate_id.slot,
        block_hash: candidate_id.hash.clone(),
        block_id: Some(received.block_id.clone()),
        certificate: make_test_final_cert(candidate_id.slot, candidate_id.hash.clone()),
    };
    fixture.processor.handle_block_finalized(event.clone());

    let seqno_after_first = fixture.processor.consensus.finalized_head_seqno();
    let consensus_after_first = fixture.processor.consensus.last_consensus_finalized_seqno();
    let _ = recording.drain_events();

    fixture.processor.handle_block_finalized(event);

    assert_eq!(fixture.processor.consensus.finalized_head_seqno(), seqno_after_first);
    assert_eq!(fixture.processor.consensus.last_consensus_finalized_seqno(), consensus_after_first);

    let events_after_dup = recording.drain_events();
    assert!(
        !events_after_dup.iter().any(|e| matches!(e, ListenerEvent::Finalized { .. })),
        "duplicate finalization must not re-emit on_block_finalized callback"
    );
}

/// Empty-block finalization must NOT advance `finalized_head_seqno` (empty blocks
/// keep parent seqno), but the candidate must still be recorded in `finalized_blocks`.
#[test]
fn test_finalized_empty_block_does_not_advance_seqno() {
    let mut opts = SessionOptions::default();
    opts.use_callback_thread = false;
    let mut fixture = TestFixture::new_with_opts(4, opts);

    fixture.processor.consensus.set_finalized_head_seqno(Some(50));
    fixture.processor.consensus.set_finalized_head_block_id(Some(BlockIdExt::with_params(
        ShardIdent::masterchain(),
        50,
        UInt256::rand(),
        UInt256::rand(),
    )));

    let slot = SlotIndex::new(22);
    let block_hash = UInt256::rand();
    let candidate_id = RawCandidateId { slot, hash: block_hash.clone() };

    let block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        50, // same seqno as parent — empty block
        UInt256::rand(),
        UInt256::rand(),
    );

    fixture.processor.candidate_book_mut().insert_received(
        candidate_id.clone(),
        ReceivedCandidate {
            slot,
            source_idx: ValidatorIndex::new(0),
            candidate_hash_data_bytes: vec![1, 2, 3],
            block_id: block_id.clone(),
            root_hash: block_id.root_hash.clone(),
            file_hash: block_id.file_hash.clone(),
            data: consensus_common::ConsensusCommonFactory::create_block_payload(vec![0xAA].into()),
            collated_data: consensus_common::ConsensusCommonFactory::create_block_payload(
                vec![0xBB].into(),
            ),
            gen_utime_ms: None,
            receive_time: fixture.description.get_time(),
            is_empty: true,
            parent_id: None,
        },
    );

    let event = BlockFinalizedEvent {
        slot,
        block_hash: block_hash.clone(),
        block_id: Some(block_id),
        certificate: make_test_final_cert(slot, block_hash),
    };
    fixture.processor.handle_block_finalized(event);

    assert_eq!(
        fixture.processor.consensus.finalized_head_seqno(),
        Some(50),
        "finalized_head_seqno must not advance for empty-block finalization"
    );
    assert!(
        fixture.processor.consensus.is_finalized_block(&candidate_id),
        "empty-block candidate must be recorded in finalized_blocks"
    );
}

/// Multiple finalized blocks with bodies arriving in reverse seqno order:
/// `finalized_head_seqno` must reflect the highest seqno seen.
#[test]
fn test_finalized_reverse_order_keeps_highest_seqno() {
    let mut opts = SessionOptions::default();
    opts.use_callback_thread = false;
    let mut fixture = TestFixture::new_with_opts(4, opts);

    let recording = RecordingListener::new();
    let listener: Arc<dyn consensus_common::SessionListener + Send + Sync> = recording.clone();
    fixture.processor.set_listener_for_test(Arc::downgrade(&listener));

    let slots: Vec<u32> = vec![20, 15, 10, 5];
    let mut highest_seqno = 0u32;

    for &slot in &slots {
        let (leader, cid, bcast) =
            make_signed_block_broadcast(&fixture, slot, vec![slot as u8, 0xFF]);
        fixture.processor.on_candidate_received(leader, bcast, None);

        let received = fixture.processor.candidate_book().received(&cid).unwrap().clone();
        let seqno = received.block_id.seq_no();
        if seqno > highest_seqno {
            highest_seqno = seqno;
        }

        let event = BlockFinalizedEvent {
            slot: cid.slot,
            block_hash: cid.hash.clone(),
            block_id: Some(received.block_id.clone()),
            certificate: make_test_final_cert(cid.slot, cid.hash.clone()),
        };
        fixture.processor.handle_block_finalized(event);
    }

    assert_eq!(
        fixture.processor.consensus.finalized_head_seqno(),
        Some(highest_seqno),
        "finalized_head_seqno must be the highest seqno across all out-of-order finalizations"
    );
    assert_eq!(
        fixture.processor.consensus.last_consensus_finalized_seqno(),
        Some(highest_seqno),
        "last_consensus_finalized_seqno must be the highest seqno across all out-of-order finalizations"
    );

    let events = recording.drain_events();
    let finalized_count =
        events.iter().filter(|e| matches!(e, ListenerEvent::Finalized { .. })).count();
    assert_eq!(finalized_count, slots.len(), "all blocks must emit on_block_finalized");
}

/// Verify that `finalized_pending_body` is cleaned up when
/// `maybe_apply_finalized_state` runs (body present at finalization time).
#[test]
fn test_finalized_clears_journal_entry_on_apply() {
    let mut opts = SessionOptions::default();
    opts.use_callback_thread = false;
    let mut fixture = TestFixture::new_with_opts(4, opts);

    let slot = 12u32;
    let (leader_source, candidate_id, broadcast) =
        make_signed_block_broadcast(&fixture, slot, vec![0xCA, 0xFE]);
    fixture.processor.on_candidate_received(leader_source, broadcast, None);

    let received = fixture.processor.candidate_book().received(&candidate_id).unwrap().clone();

    let event = BlockFinalizedEvent {
        slot: candidate_id.slot,
        block_hash: candidate_id.hash.clone(),
        block_id: Some(received.block_id.clone()),
        certificate: make_test_final_cert(candidate_id.slot, candidate_id.hash.clone()),
    };
    fixture.processor.handle_block_finalized(event);

    assert!(
        fixture.processor.consensus.finalized_pending_body_is_empty(),
        "journal must be empty after finalization with body present"
    );
    assert!(
        fixture.processor.consensus.is_finalized_block(&candidate_id),
        "candidate must be in finalized_blocks set"
    );
}

#[test]
fn test_recursive_finalization_defers_until_missing_parent_body_arrives() {
    recursive_parent_body_recovery_case(false);
}

#[test]
fn test_recursive_finalization_repairs_skipped_notarized_parent() {
    recursive_parent_body_recovery_case(true);
}

fn recursive_parent_body_recovery_case(skipped_parent: bool) {
    let mut opts = SessionOptions::default();
    opts.use_callback_thread = false;
    let mut fixture = TestFixture::new_with_shard_and_local_idx(
        4,
        0,
        ShardIdent::with_tagged_prefix(0, 0x8000_0000_0000_0000).unwrap(),
        opts,
    );

    let recording = RecordingListener::new();
    let listener: Arc<dyn consensus_common::SessionListener + Send + Sync> = recording.clone();
    fixture.processor.set_listener_for_test(Arc::downgrade(&listener));

    let (parent_leader, parent_id, parent_broadcast) =
        make_signed_block_broadcast(&fixture, 41, vec![1u8, 2, 3]);
    let (child_leader, child_id, child_broadcast) = make_signed_block_broadcast_with_parent(
        &fixture,
        42,
        vec![4u8, 5, 6],
        Some(parent_id.clone()),
    );

    fixture.processor.on_candidate_received(child_leader, child_broadcast, None);
    let child_block = fixture
        .processor
        .candidate_book()
        .received(&child_id)
        .expect("child body must be present")
        .block_id
        .clone();

    notarize_slot(&mut fixture, parent_id.slot, &parent_id.hash);
    if skipped_parent {
        skip_slot(&mut fixture, parent_id.slot);
        assert!(fixture
            .processor
            .simplex_state
            .has_skip_certificate_for_slot(&fixture.description, parent_id.slot));
        assert!(fixture
            .processor
            .simplex_state
            .get_notarize_certificate(parent_id.slot, &parent_id.hash)
            .is_some());
    }

    fixture.processor.handle_block_finalized(BlockFinalizedEvent {
        slot: child_id.slot,
        block_hash: child_id.hash.clone(),
        block_id: Some(child_block.clone()),
        certificate: make_test_final_cert(child_id.slot, child_id.hash.clone()),
    });
    // Drain the deferred `request_candidate` bounce so the missing-parent
    // repair request reaches the (fake) receiver before we inspect its actions.
    fixture.run_pending_tasks();

    let initial_events = drain_finalized_events(&recording);
    assert!(initial_events.is_empty(), "C++ WC child waits for the parent finalization");
    assert!(
        fixture.processor.consensus.finalized_pending_body_contains(&child_id),
        "trigger must remain in pending journal while parent body is missing"
    );
    assert!(
        fixture.drain_receiver_actions().iter().any(|action| match action {
            ReceiverAction::RequestCandidate { slot, block_hash } => {
                *slot == parent_id.slot.value() && block_hash == &parent_id.hash
            }
            _ => false,
        }),
        "missing parent body must trigger immediate requestCandidate"
    );

    let parent_notar = skipped_parent.then(|| {
        make_notar_vote_signature_set_bytes(
            fixture.processor.session_id(),
            &fixture.nodes,
            parent_id.slot,
            parent_id.hash.clone(),
            &[0, 1, 2],
        )
    });
    fixture.processor.on_candidate_received(parent_leader, parent_broadcast, parent_notar);
    let parent_block = fixture
        .processor
        .candidate_book()
        .received(&parent_id)
        .expect("parent body must be present")
        .block_id
        .clone();

    let finalized_events = drain_finalized_events(&recording);
    assert_eq!(
        finalized_events,
        vec![(parent_block, false), (child_block, true)],
        "C++ WC FinalizeBlock order is parent approval before child final"
    );
    assert!(
        !fixture.processor.consensus.finalized_pending_body_contains(&child_id),
        "pending journal entry must clear after recursive completion"
    );
}

#[test]
fn test_recursive_finalization_defers_until_parent_notar_cert_arrives() {
    let mut opts = SessionOptions::default();
    opts.use_callback_thread = false;
    let mut fixture = TestFixture::new_with_shard_and_local_idx(
        4,
        0,
        ShardIdent::with_tagged_prefix(0, 0x8000_0000_0000_0000).unwrap(),
        opts,
    );

    let recording = RecordingListener::new();
    let listener: Arc<dyn consensus_common::SessionListener + Send + Sync> = recording.clone();
    fixture.processor.set_listener_for_test(Arc::downgrade(&listener));

    let (parent_leader, parent_id, parent_broadcast) =
        make_signed_block_broadcast(&fixture, 51, vec![7u8, 7, 7]);
    fixture.processor.on_candidate_received(parent_leader, parent_broadcast, None);
    let parent_block = fixture
        .processor
        .candidate_book()
        .received(&parent_id)
        .expect("parent body must exist")
        .block_id
        .clone();

    let (child_leader, child_id, child_broadcast) = make_signed_block_broadcast_with_parent(
        &fixture,
        52,
        vec![8u8, 8, 8],
        Some(parent_id.clone()),
    );
    fixture.processor.on_candidate_received(child_leader, child_broadcast, None);
    let child_block = fixture
        .processor
        .candidate_book()
        .received(&child_id)
        .expect("child body must exist")
        .block_id
        .clone();

    fixture.processor.handle_block_finalized(BlockFinalizedEvent {
        slot: child_id.slot,
        block_hash: child_id.hash.clone(),
        block_id: Some(child_block.clone()),
        certificate: make_test_final_cert(child_id.slot, child_id.hash.clone()),
    });
    // Drain the deferred `request_candidate` bounce so the missing-ancestor
    // repair request reaches the (fake) receiver before we inspect its actions.
    fixture.run_pending_tasks();

    let initial_events = drain_finalized_events(&recording);
    assert!(initial_events.is_empty(), "C++ WC child waits for the parent finalization");
    assert!(
        fixture.processor.consensus.finalized_pending_body_contains(&child_id),
        "trigger must stay pending while ancestor NotarCert is missing"
    );
    assert!(
        fixture.drain_receiver_actions().iter().any(|action| match action {
            ReceiverAction::RequestCandidate { slot, block_hash } => {
                *slot == parent_id.slot.value() && block_hash == &parent_id.hash
            }
            _ => false,
        }),
        "missing ancestor NotarCert must trigger requestCandidate"
    );

    let notar_bytes = make_notar_vote_signature_set_bytes(
        fixture.processor.session_id(),
        &fixture.nodes,
        parent_id.slot,
        parent_id.hash.clone(),
        &[0, 1, 2],
    );
    fixture.processor.process_received_notar_cert(parent_id.slot, &parent_id.hash, &notar_bytes);
    // Notar-cert persist + FSM feed + retry_pending_recursive_finalization() now run from
    // the SXMAIN async-DB-results registry continuation; drain so the recursive retry fires
    // before we assert on its observable side-effects.
    fixture.drain_pending_async_db_results();

    let finalized_events = drain_finalized_events(&recording);
    assert_eq!(
        finalized_events,
        vec![(parent_block, false), (child_block, true)],
        "C++ WC FinalizeBlock order is parent approval before child final"
    );
    assert!(
        !fixture.processor.consensus.finalized_pending_body_contains(&child_id),
        "pending journal entry must clear once notar cert arrives and retry runs"
    );
}

#[test]
fn test_recovery_ancestry_requires_parent_evidence_even_below_applied_floor() {
    let mut opts = SessionOptions::default();
    opts.use_callback_thread = false;
    let mut fixture = TestFixture::new_with_shard_and_local_idx(
        4,
        0,
        ShardIdent::with_tagged_prefix(0, 0x8000_0000_0000_0000).unwrap(),
        opts,
    );
    let (parent_leader, parent, parent_data) =
        make_signed_block_broadcast(&fixture, 51, vec![7, 7, 7]);
    let (leader, child, data) =
        make_signed_block_broadcast_with_parent(&fixture, 69, vec![8, 8, 8], Some(parent.clone()));
    fixture.processor.on_candidate_received(leader, data, None);
    fixture.processor.set_mc_finalized_block(BlockIdExt::with_params(
        fixture.description.get_shard().clone(),
        1000,
        UInt256::rand(),
        UInt256::rand(),
    ));
    // Exercise the production materialization gate as well as the resolver.
    // CandidateBook is an already-verified input boundary here; cryptographic
    // rejection is covered by pq_live_recovery_* above.
    let (nodes, keys) = crate::pq_fixture::members();
    let members = nodes.iter().map(|n| n.descriptor.clone().unwrap()).collect();
    let (runtime, key, options) = crate::authenticated_fixture::runtime_with_members_on_shard(
        members,
        keys[0].clone(),
        fixture.description.get_shard().clone(),
    );
    let nodes = runtime
        .committee()
        .iter()
        .map(crate::SimplexSessionNode::from_descriptor)
        .collect::<rtos_block::Result<Vec<_>>>()
        .unwrap();
    let description = Arc::new(
        SessionDescription::new_with_runtime(
            &options,
            runtime.session_id().clone(),
            1,
            &nodes,
            key,
            runtime.shard(),
            SystemTime::now(),
            None,
            Some(&runtime),
        )
        .unwrap()
        .bind_pq_session(runtime.catchain_seqno())
        .unwrap(),
    );
    let db = MockDb::new();
    let mut authenticated = make_pq_processor_with_description_for_test(db.clone(), description);
    authenticated.candidate_book_mut().insert_received(
        child.clone(),
        fixture.processor.candidate_book().received(&child).unwrap().clone(),
    );
    assert!(
        !authenticated
            .with_consensus_backend(|c, b| c.maybe_apply_finalized_state(b, &child, true)),
        "never persist a record whose required recovery ancestry is missing"
    );
    assert!(db.load_finalized_blocks().unwrap().is_empty());
    fixture.run_pending_tasks();
    for _ in 0..1000 {
        assert!(!fixture
            .processor
            .with_consensus_backend(|c, b| c.ensure_recoverable_ancestry(b, &child)));
    }
    assert_eq!(
        fixture.task_queue.tasks.lock().unwrap().len(),
        1,
        "repeated finality-ancestry retries must not enqueue repeated repairs"
    );
    fixture.run_pending_tasks();
    assert!(fixture.drain_receiver_actions().iter().any(|action| matches!(action,
        ReceiverAction::RequestCandidate { slot, block_hash }
            if *slot == parent.slot.value() && block_hash == &parent.hash)));

    fixture.processor.on_candidate_received(parent_leader, parent_data, None);
    assert!(
        !fixture.processor.with_consensus_backend(|c, b| c.ensure_recoverable_ancestry(b, &child)),
        "a signed proposal alone cannot support an ancestor's finality"
    );
    let notar = make_notar_vote_signature_set_bytes(
        fixture.processor.session_id(),
        &fixture.nodes,
        parent.slot,
        parent.hash.clone(),
        &[0, 1, 2],
    );
    fixture.processor.process_received_notar_cert(parent.slot, &parent.hash, &notar);
    fixture.drain_pending_async_db_results();
    assert!(
        fixture.processor.with_consensus_backend(|c, b| c.ensure_recoverable_ancestry(b, &child)),
        "the authenticated parent and its durably ingested NotarCert close the recovery gap"
    );
}

#[test]
fn test_deferred_candidate_repairs_coalesce_across_controllers_and_keep_urgent_delay() {
    let mut fixture = TestFixture::new(4);
    fixture.run_pending_tasks();
    let slot = SlotIndex::new(69);
    let hash = UInt256::rand();
    for _ in 0..1000 {
        fixture.processor.with_consensus_backend(|_, b| {
            b.request_candidate(slot, hash.clone(), Some(Duration::from_secs(5)));
        });
        fixture.processor.with_validation_backend(|_, b| {
            b.request_candidate(slot, hash.clone(), None);
        });
        fixture.processor.with_collation_backend(|_, b| {
            b.request_parent_candidate(slot, hash.clone());
        });
    }
    assert_eq!(
        fixture.task_queue.tasks.lock().unwrap().len(),
        1,
        "throttling after dequeue cannot bound the repair backlog"
    );
    fixture.processor.with_consensus_backend(|_, b| {
        b.request_candidate(slot, hash.clone(), Some(Duration::ZERO));
    });
    let other_hash = UInt256::rand();
    fixture.processor.with_consensus_backend(|_, b| {
        b.request_candidate(slot, other_hash.clone(), Some(Duration::ZERO));
    });
    assert_eq!(
        fixture.task_queue.tasks.lock().unwrap().len(),
        2,
        "different candidate hashes in the same slot remain distinct"
    );
    fixture.run_pending_tasks();
    let requests: Vec<_> = fixture
        .drain_receiver_actions()
        .into_iter()
        .filter_map(|action| match action {
            ReceiverAction::RequestCandidate { slot: s, block_hash } if s == slot.value() => {
                Some(block_hash)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        requests,
        vec![hash.clone(), other_hash],
        "an urgent retry must not inherit the first delayed request"
    );
    assert!(fixture.processor.deferred_candidate_requests.lock().unwrap().is_empty());
    fixture.processor.with_consensus_backend(|_, b| {
        b.request_candidate(slot, hash, Some(Duration::ZERO));
    });
    assert_eq!(
        fixture.task_queue.tasks.lock().unwrap().len(),
        1,
        "dequeued repairs must permit future retries through the normal limiter"
    );
}

#[test]
fn test_deferred_candidate_repair_discard_releases_ticket() {
    let mut fixture = TestFixture::new(4);
    fixture.run_pending_tasks();
    let slot = SlotIndex::new(69);
    let hash = UInt256::rand();
    for _ in 0..2 {
        fixture.processor.with_consensus_backend(|_, b| {
            b.request_candidate(slot, hash.clone(), Some(Duration::ZERO));
        });
        assert_eq!(fixture.task_queue.tasks.lock().unwrap().len(), 1);
        crate::task_queue::TaskQueue::flush(&*fixture.task_queue);
        assert!(
            fixture.processor.deferred_candidate_requests.lock().unwrap().is_empty(),
            "discarding a queued closure must not suppress the next repair"
        );
    }
}

#[test]
fn test_recursive_finalization_traverses_empty_ancestor_without_callback() {
    let mut opts = SessionOptions::default();
    opts.use_callback_thread = false;
    let mut fixture = TestFixture::new_with_shard_and_local_idx(
        4,
        0,
        ShardIdent::with_tagged_prefix(0, 0x8000_0000_0000_0000).unwrap(),
        opts,
    );

    let recording = RecordingListener::new();
    let listener: Arc<dyn consensus_common::SessionListener + Send + Sync> = recording.clone();
    fixture.processor.set_listener_for_test(Arc::downgrade(&listener));

    let (root_leader, root_id, root_broadcast) =
        make_signed_block_broadcast(&fixture, 61, vec![1u8, 9, 1]);
    fixture.processor.on_candidate_received(root_leader, root_broadcast, None);
    let root_block = fixture
        .processor
        .candidate_book()
        .received(&root_id)
        .expect("root must exist")
        .block_id
        .clone();

    let (empty_leader, empty_id, empty_broadcast) = make_signed_empty_block_broadcast_with_parent(
        &fixture,
        62,
        root_id.clone(),
        root_block.clone(),
    );
    fixture.processor.on_candidate_received(empty_leader, empty_broadcast, None);

    let (child_leader, child_id, child_broadcast) = make_signed_block_broadcast_with_parent(
        &fixture,
        63,
        vec![2u8, 9, 2],
        Some(empty_id.clone()),
    );
    fixture.processor.on_candidate_received(child_leader, child_broadcast, None);
    let child_block = fixture
        .processor
        .candidate_book()
        .received(&child_id)
        .expect("child must exist")
        .block_id
        .clone();

    notarize_slot(&mut fixture, root_id.slot, &root_id.hash);

    fixture.processor.handle_block_finalized(BlockFinalizedEvent {
        slot: child_id.slot,
        block_hash: child_id.hash.clone(),
        block_id: Some(child_block.clone()),
        certificate: make_test_final_cert(child_id.slot, child_id.hash.clone()),
    });

    let finalized_events = drain_finalized_events(&recording);
    assert_eq!(finalized_events.len(), 2, "empty ancestors must not emit callbacks");
    assert_eq!(
        finalized_events.iter().filter(|(block_id, _)| block_id == &root_block).count(),
        1,
        "root callback must be emitted once (no duplicate from empty ancestor)"
    );
    assert!(finalized_events
        .iter()
        .any(|(block_id, is_final)| block_id == &root_block && !is_final));
    assert!(finalized_events
        .iter()
        .any(|(block_id, is_final)| block_id == &child_block && *is_final));
    assert!(
        fixture.processor.consensus.is_finalized_block(&empty_id),
        "empty ancestor must still be finalized locally"
    );
}

#[test]
fn test_recursive_finalization_dedups_repeated_trigger_and_cert_retry() {
    let mut opts = SessionOptions::default();
    opts.use_callback_thread = false;
    let mut fixture = TestFixture::new_with_shard_and_local_idx(
        4,
        0,
        ShardIdent::with_tagged_prefix(0, 0x8000_0000_0000_0000).unwrap(),
        opts,
    );

    let recording = RecordingListener::new();
    let listener: Arc<dyn consensus_common::SessionListener + Send + Sync> = recording.clone();
    fixture.processor.set_listener_for_test(Arc::downgrade(&listener));

    let (root_leader, root_id, root_broadcast) =
        make_signed_block_broadcast(&fixture, 71, vec![3u8, 3, 3]);
    fixture.processor.on_candidate_received(root_leader, root_broadcast, None);
    let root_block = fixture
        .processor
        .candidate_book()
        .received(&root_id)
        .expect("root must exist")
        .block_id
        .clone();

    let (child_leader, child_id, child_broadcast) = make_signed_block_broadcast_with_parent(
        &fixture,
        72,
        vec![4u8, 4, 4],
        Some(root_id.clone()),
    );
    fixture.processor.on_candidate_received(child_leader, child_broadcast, None);
    let child_block = fixture
        .processor
        .candidate_book()
        .received(&child_id)
        .expect("child must exist")
        .block_id
        .clone();

    notarize_slot(&mut fixture, root_id.slot, &root_id.hash);

    let child_finalized_event = BlockFinalizedEvent {
        slot: child_id.slot,
        block_hash: child_id.hash.clone(),
        block_id: Some(child_block.clone()),
        certificate: make_test_final_cert(child_id.slot, child_id.hash.clone()),
    };
    fixture.processor.handle_block_finalized(child_finalized_event.clone());

    let first_events = drain_finalized_events(&recording);
    assert_eq!(first_events.len(), 2);
    assert!(first_events.iter().any(|(block_id, is_final)| block_id == &root_block && !is_final));
    assert!(first_events.iter().any(|(block_id, is_final)| block_id == &child_block && *is_final));

    let notar_bytes = make_notar_vote_signature_set_bytes(
        fixture.processor.session_id(),
        &fixture.nodes,
        root_id.slot,
        root_id.hash.clone(),
        &[0, 1, 2],
    );
    fixture.processor.process_received_notar_cert(root_id.slot, &root_id.hash, &notar_bytes);
    fixture.processor.handle_block_finalized(child_finalized_event);

    assert!(
        drain_finalized_events(&recording).is_empty(),
        "retries/duplicate finalization must not re-emit recursive callbacks"
    );
}

#[test]
fn test_recursive_finalization_masterchain_emits_finalcert_only() {
    let mut opts = SessionOptions::default();
    opts.use_callback_thread = false;
    let mut fixture = TestFixture::new_with_opts(4, opts);

    let recording = RecordingListener::new();
    let listener: Arc<dyn consensus_common::SessionListener + Send + Sync> = recording.clone();
    fixture.processor.set_listener_for_test(Arc::downgrade(&listener));

    let (parent_leader, parent_id, parent_broadcast) =
        make_signed_block_broadcast(&fixture, 81, vec![5u8, 5, 1]);
    fixture.processor.on_candidate_received(parent_leader, parent_broadcast, None);

    let (child_leader, child_id, child_broadcast) = make_signed_block_broadcast_with_parent(
        &fixture,
        82,
        vec![5u8, 5, 2],
        Some(parent_id.clone()),
    );
    fixture.processor.on_candidate_received(child_leader, child_broadcast, None);
    let child_block = fixture
        .processor
        .candidate_book()
        .received(&child_id)
        .expect("child must exist")
        .block_id
        .clone();

    notarize_slot(&mut fixture, parent_id.slot, &parent_id.hash);

    fixture.processor.handle_block_finalized(BlockFinalizedEvent {
        slot: child_id.slot,
        block_hash: child_id.hash.clone(),
        block_id: Some(child_block.clone()),
        certificate: make_test_final_cert(child_id.slot, child_id.hash.clone()),
    });

    let finalized_events = drain_finalized_events(&recording);
    assert_eq!(
        finalized_events.len(),
        1,
        "masterchain callbacks must only be emitted for FinalCert blocks",
    );
    assert!(
        finalized_events.iter().any(|(block_id, is_final)| block_id == &child_block && *is_final),
        "masterchain trigger must be emitted with FinalCert signatures",
    );
    assert!(
        !finalized_events.iter().any(|(_, is_final)| !*is_final),
        "masterchain must never emit on_block_finalized with notar-mode signatures",
    );
    // C++ parity: on MC, once the non-empty trigger consumes the FinalCert,
    // the walk stops (null cert + MC → co_return). The parent is NOT processed
    // by this finalization walk — it requires its own separate finalization event.
    assert!(
        !fixture.processor.consensus.is_finalized_block(&parent_id),
        "C++ parity: MC parent must NOT be finalized by child's cert walk \
         (cert consumed by non-empty child, MC walk stops)"
    );
}

#[test]
fn test_recursive_finalization_applied_top_floor_skips_older_ancestor_callbacks() {
    let mut opts = SessionOptions::default();
    opts.use_callback_thread = false;
    let mut fixture = TestFixture::new_with_shard_and_local_idx(
        4,
        0,
        ShardIdent::with_tagged_prefix(0, 0x8000_0000_0000_0000).unwrap(),
        opts,
    );

    let recording = RecordingListener::new();
    let listener: Arc<dyn consensus_common::SessionListener + Send + Sync> = recording.clone();
    fixture.processor.set_listener_for_test(Arc::downgrade(&listener));

    fixture.processor.set_mc_finalized_block(BlockIdExt::with_params(
        fixture.description.get_shard().clone(),
        92,
        UInt256::rand(),
        UInt256::rand(),
    ));

    let (old_leader, old_id, old_broadcast) =
        make_signed_block_broadcast(&fixture, 91, vec![9u8, 1, 9]);
    fixture.processor.on_candidate_received(old_leader, old_broadcast, None);
    let old_block = fixture
        .processor
        .candidate_book()
        .received(&old_id)
        .expect("old ancestor must exist")
        .block_id
        .clone();

    let (mid_leader, mid_id, mid_broadcast) = make_signed_block_broadcast_with_parent(
        &fixture,
        92,
        vec![9u8, 2, 9],
        Some(old_id.clone()),
    );
    fixture.processor.on_candidate_received(mid_leader, mid_broadcast, None);
    let mid_block = fixture
        .processor
        .candidate_book()
        .received(&mid_id)
        .expect("mid ancestor must exist")
        .block_id
        .clone();

    let (trigger_leader, trigger_id, trigger_broadcast) = make_signed_block_broadcast_with_parent(
        &fixture,
        93,
        vec![9u8, 3, 9],
        Some(mid_id.clone()),
    );
    fixture.processor.on_candidate_received(trigger_leader, trigger_broadcast, None);
    let trigger_block = fixture
        .processor
        .candidate_book()
        .received(&trigger_id)
        .expect("trigger must exist")
        .block_id
        .clone();

    notarize_slot(&mut fixture, old_id.slot, &old_id.hash);
    notarize_slot(&mut fixture, mid_id.slot, &mid_id.hash);

    fixture.processor.handle_block_finalized(BlockFinalizedEvent {
        slot: trigger_id.slot,
        block_hash: trigger_id.hash.clone(),
        block_id: Some(trigger_block.clone()),
        certificate: make_test_final_cert(trigger_id.slot, trigger_id.hash.clone()),
    });

    let finalized_events = drain_finalized_events(&recording);
    assert_eq!(finalized_events.len(), 2);
    assert!(
        !finalized_events.iter().any(|(block_id, _)| block_id == &old_block),
        "callbacks below applied-top floor must be suppressed"
    );
    assert!(finalized_events
        .iter()
        .any(|(block_id, is_final)| block_id == &mid_block && !is_final));
    assert!(finalized_events
        .iter()
        .any(|(block_id, is_final)| block_id == &trigger_block && *is_final));
    assert!(
        fixture.processor.consensus.is_finalized_block(&old_id),
        "suppressed ancestor must still be finalized locally"
    );
}

// ============================================================================
// `ensure_candidate_info_stored` — direct-API tests
// ============================================================================
//
// These tests target `ensure_candidate_info_stored` directly to verify the three
// completion paths (Ok inline, Err inline for missing entry, Ok via deferred
// continuation). End-to-end coverage of the per-caller wiring lives further down
// next to `broadcast_vote` / `process_received_notar_cert` / `process_validated_candidates`.

/// Capture the `Result<()>` argument the callback receives, so tests can assert
/// on the outcome after the call returns (inline) or after the registry drains
/// (deferred). `None` means the callback hasn't fired yet.
type EnsureCallbackOutcome = Arc<Mutex<Option<std::result::Result<(), String>>>>;

/// Build an `EnsureCallbackOutcome` and a closure suitable for passing to
/// `ensure_candidate_info_stored`. The closure stores `Ok(())` / `Err(msg)`
/// into the shared cell; `msg` is the `Display`-formatted error so we don't
/// have to clone failure errors.
fn make_ensure_callback() -> (
    EnsureCallbackOutcome,
    impl FnOnce(&mut SessionProcessor, rtos_block::Result<()>) + Send + 'static,
) {
    let outcome: EnsureCallbackOutcome = Arc::new(Mutex::new(None));
    let outcome_for_cb = outcome.clone();
    let cb = move |_processor: &mut SessionProcessor, res: rtos_block::Result<()>| {
        let stored = match res {
            Ok(()) => Ok(()),
            Err(e) => Err(e.to_string()),
        };
        *outcome_for_cb.lock().unwrap() = Some(stored);
    };
    (outcome, cb)
}

/// Missing dedup-map entry → callback fires inline with `Err(...)` and the
/// session error counter is bumped.
#[test]
fn test_ensure_candidate_info_stored_callback_fires_inline_with_err_when_missing() {
    let mut fixture = TestFixture::new(4);
    let candidate_id = RawCandidateId { slot: SlotIndex::new(77), hash: UInt256::rand() };
    let errors_before =
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed);

    let (outcome, cb) = make_ensure_callback();
    fixture.processor.ensure_candidate_info_stored(&candidate_id, true, false, cb);

    let captured = outcome.lock().unwrap().clone().expect("callback must fire inline");
    let err = captured.expect_err("missing candidateInfo entry must surface as Err");
    assert!(
        err.contains("missing candidateInfo store result"),
        "Err must describe the missing prerequisite, got: {err}",
    );

    let errors_after =
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        errors_after > errors_before,
        "missing candidateInfo path must increment error counter (matches abort semantics)",
    );
}

/// Persisted candidateInfo → callback fires inline with `Ok(())` and the DB is
/// queryable. No deferred entry is registered.
#[test]
fn test_ensure_candidate_info_stored_callback_fires_inline_with_ok_when_persisted() {
    let mut fixture = TestFixture::new(4);
    let (leader_source, candidate_id, broadcast) =
        make_signed_block_broadcast(&fixture, 78, vec![1, 2, 3, 4]);
    fixture.processor.on_candidate_received(leader_source, broadcast, None);

    // Wait for the storage thread to flush the candidateInfo write so the dedup-map
    // entry's `is_ready()` is true at the time we call `ensure_*`.
    for _ in 0..200 {
        let res = fixture
            .processor
            .database
            .candidate_info_store_result(&candidate_id)
            .expect("save_candidate_info_async must register a dedup-map entry")
            .clone();
        if res.is_ready() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    let pending_before = fixture.processor.database.pending_count();
    let (outcome, cb) = make_ensure_callback();
    fixture.processor.ensure_candidate_info_stored(&candidate_id, true, false, cb);

    let captured = outcome.lock().unwrap().clone().expect("callback must fire inline");
    captured.expect("inline-Ready callback must surface Ok(())");
    assert_eq!(
        fixture.processor.database.pending_count(),
        pending_before,
        "inline-Ready path must NOT register a deferred entry in the registry",
    );
    assert!(
        fixture
            .processor
            .database
            .db()
            .load_candidate_info_by_id(&candidate_id, Duration::from_secs(1))
            .expect("candidate info lookup must succeed")
            .is_some(),
        "candidateInfo must be present in DB",
    );
}

/// In-flight candidateInfo → callback is deferred via the SXMAIN async-DB-results
/// registry; firing the registry drain only after completing the underlying
/// result actually invokes the callback.
#[test]
fn test_ensure_candidate_info_stored_callback_is_deferred_when_in_flight() {
    let mut fixture = TestFixture::new(4);
    let candidate_id = RawCandidateId { slot: SlotIndex::new(79), hash: UInt256::rand() };
    let pending = ManualAsyncResult::pending();
    fixture.processor.database.insert_candidate_info_store(candidate_id.clone(), pending.clone());

    let (outcome, cb) = make_ensure_callback();
    fixture.processor.ensure_candidate_info_stored(&candidate_id, true, false, cb);

    assert!(
        outcome.lock().unwrap().is_none(),
        "callback must NOT fire while the underlying result is still in flight",
    );
    let pending_entries: Vec<_> =
        fixture.processor.database.pending_iter().map(|e| e.op_label).collect();
    assert!(
        pending_entries.contains(&"ensure_candidate_info_stored:candidate_info"),
        "deferred path must register a registry entry with the candidate_info op label, \
         got entries: {pending_entries:?}",
    );

    // Complete + drain → callback fires with Ok(()).
    pending.complete_ok();
    fixture.processor.process_pending_async_db_results();

    let captured = outcome.lock().unwrap().clone().expect("callback must fire after drain");
    captured.expect("deferred Ok must surface Ok(())");
}

/// Deferred path with a real storage error must surface `Err(...)` to the
/// callback and bump the session error counter from inside the registry
/// continuation (matches the inline-Err semantic).
#[test]
fn test_ensure_candidate_info_stored_callback_surfaces_err_from_deferred_failure() {
    let mut fixture = TestFixture::new(4);
    let candidate_id = RawCandidateId { slot: SlotIndex::new(80), hash: UInt256::rand() };
    let pending = ManualAsyncResult::pending();
    fixture.processor.database.insert_candidate_info_store(candidate_id.clone(), pending.clone());

    let errors_before =
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed);

    let (outcome, cb) = make_ensure_callback();
    fixture.processor.ensure_candidate_info_stored(&candidate_id, true, false, cb);

    pending.complete_err("disk_unavailable");
    fixture.processor.process_pending_async_db_results();

    let captured = outcome.lock().unwrap().clone().expect("callback must fire after drain");
    let err = captured.expect_err("deferred Err must surface Err");
    assert!(
        err.contains("disk_unavailable"),
        "Err message must propagate from the storage layer, got: {err}",
    );
    let errors_after =
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        errors_after > errors_before,
        "deferred-failure path must increment the session error counter from the continuation",
    );
}

/// `wait_candidate_info=false && wait_notar_cert=false` → callback fires inline
/// with `Ok(())` and nothing is registered. Lets callers (e.g., a future wrapper
/// for `SkipVote`) avoid a special case in their own code.
#[test]
fn test_ensure_candidate_info_stored_callback_fires_inline_with_ok_when_no_wait_requested() {
    let mut fixture = TestFixture::new(4);
    let candidate_id = RawCandidateId { slot: SlotIndex::new(81), hash: UInt256::rand() };
    let pending_before = fixture.processor.database.pending_count();

    let (outcome, cb) = make_ensure_callback();
    fixture.processor.ensure_candidate_info_stored(&candidate_id, false, false, cb);

    let captured = outcome.lock().unwrap().clone().expect("callback must fire inline");
    captured.expect("no-wait path must surface Ok(())");
    assert_eq!(
        fixture.processor.database.pending_count(),
        pending_before,
        "no-wait path must NOT register a deferred entry",
    );
}

#[test]
fn test_broadcast_vote_aborts_when_candidate_info_is_missing() {
    let mut fixture = TestFixture::new(4);
    let slot = SlotIndex::new(90);
    let vote = crate::simplex_state::Vote::Notarize(crate::simplex_state::NotarizeVote {
        slot,
        block_hash: UInt256::rand(),
    });
    let persist_fail_before = metrics_counter(&fixture.processor, "simplex_votes_out_persist_fail");

    fixture.processor.broadcast_vote(vote);

    let actions = fixture.drain_receiver_actions();
    assert!(
        !actions.iter().any(|a| matches!(a, ReceiverAction::SendVote { .. })),
        "notarize vote must not be sent when candidateInfo durability check fails"
    );
    assert_eq!(
        metrics_counter(&fixture.processor, "simplex_votes_out_persist_fail"),
        persist_fail_before + 1,
        "aborted vote must bump persist-failure counter"
    );
}

#[test]
fn test_broadcast_finalize_vote_aborts_when_notar_cert_is_missing() {
    let mut fixture = TestFixture::new(4);
    let slot = SlotIndex::new(91);
    let vote = crate::simplex_state::Vote::Finalize(crate::simplex_state::FinalizeVote {
        slot,
        block_hash: UInt256::rand(),
    });
    let persist_fail_before = metrics_counter(&fixture.processor, "simplex_votes_out_persist_fail");

    fixture.processor.broadcast_vote(vote);

    let actions = fixture.drain_receiver_actions();
    assert!(
        !actions.iter().any(|a| matches!(a, ReceiverAction::SendVote { .. })),
        "finalize vote must not be sent when notar-cert durability check fails"
    );
    assert_eq!(
        metrics_counter(&fixture.processor, "simplex_votes_out_persist_fail"),
        persist_fail_before + 1,
        "aborted vote must bump persist-failure counter"
    );
}

#[test]
fn test_broadcast_skip_vote_bypasses_durability_wait() {
    let h = crate::signing_coordinator::tests::Harness::custody(rtos_api::WireProfile::Legacy);
    h.description.install_coordinator(h.coordinator.clone()).unwrap();
    let mut processor =
        make_pq_processor_with_description_for_test(h.db.clone(), h.description.clone());
    let receiver = MockReceiver::new();
    processor.receiver = receiver.clone();
    let slot = SlotIndex::new(0);
    let vote = crate::simplex_state::Vote::Skip(crate::simplex_state::SkipVote { slot });
    let persist_fail_before = metrics_counter(&processor, "simplex_votes_out_persist_fail");

    processor.broadcast_vote(vote);

    let actions = receiver.drain_actions();
    assert!(
        actions.iter().any(|a| matches!(a, ReceiverAction::SendVote { .. })),
        "skip vote must still be sent without candidate/notar durability waits"
    );
    assert!(
        processor.database.pending_iter().all(|entry| !entry.op_label.starts_with("ensure_")),
        "skip vote registers no durability wait"
    );
    assert_eq!(
        metrics_counter(&processor, "simplex_votes_out_persist_fail"),
        persist_fail_before,
        "skip vote path must not increment persist-failure counter"
    );
    assert_eq!(h.signature_count(), 1);
}

/// A classical (non-post-quantum) session never signs an own vote: there is no
/// classical or network-key fallback, so nothing is persisted, applied or sent.
#[test]
fn test_classical_session_refuses_to_sign_or_send_an_own_vote() {
    let mut fixture = TestFixture::new(4);
    let slot = SlotIndex::new(123);
    let vote = crate::simplex_state::Vote::Skip(crate::simplex_state::SkipVote { slot });

    let pending_before = fixture.processor.database.pending_count();
    let errors_before =
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed);

    fixture.processor.broadcast_vote(vote);

    let actions = fixture.drain_receiver_actions();
    assert!(
        !actions.iter().any(|a| matches!(a, ReceiverAction::SendVote { .. })),
        "a classical session must not publish an own vote",
    );
    assert_eq!(
        fixture.processor.database.pending_count(),
        pending_before,
        "no own-vote write is registered for a vote that was never signed",
    );
    assert_eq!(
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed),
        errors_before + 1,
        "the refused signature is counted as an error",
    );
}

#[test]
fn test_process_validated_candidates_skips_candidate_when_candidate_info_missing() {
    let mut fixture = TestFixture::new(4);
    let slot = SlotIndex::new(0);

    let (leader_source, candidate_id, broadcast) =
        make_signed_block_broadcast(&fixture, slot.value(), vec![5, 6, 7, 8]);
    fixture.processor.on_candidate_received(leader_source, broadcast, None);

    let now = fixture.description.get_time();
    fixture.processor.candidate_decision_ok_internal(candidate_id.clone(), slot, now);
    fixture.processor.database.remove_candidate_info_store(&candidate_id);

    fixture.processor.process_validated_candidates();
    fixture.processor.simplex_state.check_all(&fixture.description);

    let mut has_notarize = false;
    while let Some(event) = fixture.processor.simplex_state.pull_event() {
        if let crate::simplex_state::SimplexEvent::BroadcastVote(
            crate::simplex_state::Vote::Notarize(v),
        ) = event
        {
            if v.slot == slot {
                has_notarize = true;
            }
        }
    }

    assert!(
        !has_notarize,
        "candidate must not be fed into FSM when candidateInfo durability check fails"
    );
}

#[test]
fn test_process_received_notar_cert_aborts_when_persist_fails() {
    let mut fixture = TestFixture::new(4);

    let (leader_source, candidate_id, broadcast) =
        make_signed_block_broadcast(&fixture, 93, vec![9, 3, 9, 3]);
    fixture.processor.on_candidate_received(leader_source, broadcast, None);

    fixture.processor.database.db().fail_next_notar_cert_save_for_test();

    let notar_bytes = make_notar_vote_signature_set_bytes(
        fixture.processor.session_id(),
        &fixture.nodes,
        candidate_id.slot,
        candidate_id.hash.clone(),
        &[0, 1, 2],
    );
    fixture.processor.process_received_notar_cert(
        candidate_id.slot,
        &candidate_id.hash,
        &notar_bytes,
    );

    assert!(
        fixture
            .processor
            .simplex_state
            .get_notarize_certificate(candidate_id.slot, &candidate_id.hash)
            .is_none(),
        "FSM must not accept notar cert when DB persist failed"
    );
    assert!(
        fixture
            .processor
            .database
            .db()
            .load_notar_certs_async()
            .wait_timeout(TEST_DB_WATCHDOG)
            .expect("DB certificate scan watchdog expired")
            .expect("notar cert scan must succeed")
            .is_empty(),
        "failed persist must not leave notar cert in DB"
    );
}

/// Verify that the correct processing order (validated candidates BEFORE
/// FSM timeouts) allows a candidate to be notarized even when the clock
/// has advanced past the skip timeout.
///
/// Without Fix A (processing-order), calling `simplex_state.check_all()`
/// first would fire the `first_block_timeout` and skip-vote the slot
/// before the already-validated candidate is fed to the FSM.
#[test]
fn test_process_validated_candidates_before_fsm_timeout() {
    let mut fixture = TestFixture::new(4);

    let slot = SlotIndex::new(0);
    let (leader_source, candidate_id, broadcast) =
        make_signed_block_broadcast(&fixture, slot.value(), vec![0xAA, 0xBB, 0xCC]);
    fixture.processor.on_candidate_received(leader_source, broadcast, None);

    let time = fixture.description.get_time();
    fixture.processor.candidate_decision_ok_internal(candidate_id.clone(), slot, time);
    assert!(
        !fixture.processor.validation.validated_is_empty(),
        "candidate must be in the validated_candidates queue"
    );

    // Advance time past first_block_timeout + target_rate (defaults: 3s + 1s = 4s).
    fixture.advance_time(Duration::from_secs(5));

    // --- Correct order (Fix A): feed candidates, THEN run FSM timeouts ---
    fixture.processor.process_validated_candidates();
    // `process_validated_candidates()` routes the FSM feed through
    // `ensure_candidate_info_stored()`: while the candidateInfo persist is still
    // in flight on the background storage thread, the feed is deferred to the
    // SXMAIN async-DB-results registry instead of running inline. Drain the
    // registry so the candidate is fed to the FSM *before* the timeout is
    // evaluated below; without this the feed races the storage write and the
    // slot is skip-voted first (the flaky failure this test guards against).
    fixture.drain_pending_async_db_results();
    fixture.processor.simplex_state.check_all(&fixture.description);

    // Collect FSM events produced by the two calls above.
    let mut has_notarize = false;
    while let Some(event) = fixture.processor.simplex_state.pull_event() {
        if let crate::simplex_state::SimplexEvent::BroadcastVote(
            crate::simplex_state::Vote::Notarize(ref v),
        ) = event
        {
            if v.slot == slot {
                has_notarize = true;
            }
        }
    }

    // The critical invariant: the candidate was notarized because
    // process_validated_candidates() ran before simplex_state.check_all().
    assert!(
        has_notarize,
        "slot 0 must be notarized (candidate was fed to FSM before timeout evaluation)"
    );
    // In C++ mode a skip vote may follow
    // the notarize vote after the timeout fires -- that is harmless and
    // expected.  The key property is that the notarize vote was emitted.
}

/// Verify that the `log::warn!` for "drop because block is already
/// finalized" only fires when `cand_seqno <= finalized_seqno`, i.e. the
/// candidate is actually dropped.  When `cand_seqno > finalized_seqno`
/// the candidate must proceed to `validated_candidates`.
#[test]
fn test_candidate_decision_ok_does_not_drop_when_cand_seqno_greater_than_finalized() {
    let mut fixture = TestFixture::new(4);

    let slot = SlotIndex::new(0);
    let candidate_hash = UInt256::rand();
    let candidate_id = RawCandidateId { slot, hash: candidate_hash.clone() };

    let raw_candidate = make_test_non_empty_candidate(candidate_id.clone(), None, &fixture.nodes);
    let time = fixture.description.get_time();
    insert_pending_validation(&mut fixture.processor, &candidate_id, raw_candidate, time);

    // Set finalized_head_seqno to a value BELOW the candidate's seqno.
    // make_test_non_empty_candidate uses slot.value()+1 as seq_no, so for
    // slot 0 the candidate seqno = 1.  Setting finalized_head to 0 means
    // cand_seqno (1) > finalized_seqno (0) → candidate must NOT be dropped.
    fixture.processor.consensus.set_finalized_head_seqno(Some(0));

    // Call the public wrapper which contains the guard.
    let validity_start = time;
    fixture.processor.candidate_decision_ok(slot, candidate_id.clone(), validity_start, time);

    // The candidate must have been pushed to validated_candidates (not dropped).
    assert!(
        !fixture.processor.validation.validated_is_empty(),
        "candidate with cand_seqno > committed_seqno must NOT be dropped"
    );
    // And it must have been removed from pending_validations (consumed, not leaked).
    assert!(
        !fixture.processor.validation.pending_validation_contains(&candidate_id),
        "pending_validations entry must be consumed"
    );
}

#[test]
fn test_generated_candidate_validation_missed_metric_increments_on_final_rejection() {
    let mut fixture = TestFixture::new(4);

    let slot = SlotIndex::new(0);
    let candidate_id = RawCandidateId { slot, hash: UInt256::rand() };
    let raw_candidate = make_test_non_empty_candidate(candidate_id.clone(), None, &fixture.nodes);
    let time = fixture.description.get_time();
    insert_pending_validation(&mut fixture.processor, &candidate_id, raw_candidate, time);

    let now = fixture.processor.now();
    fixture.processor.telemetry.record_self_collation_start(
        fixture.processor.runtime.description(),
        slot,
        1,
        None,
        None,
        &[],
        now,
    );
    fixture.processor.telemetry.record_self_collation_generated(
        slot,
        "unit_test_generated",
        fixture.processor.runtime.description(),
        now,
    );
    fixture.processor.telemetry.link_self_collation_candidate(
        slot,
        &candidate_id,
        fixture.processor.runtime.description(),
    );
    fixture.processor.track_generated_candidate_for_validation(candidate_id.clone());
    fixture.processor.mark_generated_candidate_validation_started(&candidate_id);
    fixture.processor.candidate_decision_fail(
        slot,
        candidate_id.clone(),
        error!("validator rejected"),
    );

    assert_eq!(
        metrics_counter(&fixture.processor, "simplex_generated_candidate_validation_missed"),
        1
    );
    assert_eq!(metrics_counter(&fixture.processor, "simplex_self_collates.total"), 1);
    assert_eq!(metrics_counter(&fixture.processor, "simplex_self_collates.success"), 0);
    assert_eq!(metrics_counter(&fixture.processor, "simplex_self_collates.failure"), 1);
    assert!(
        !fixture.processor.telemetry.waiting_validation_contains(&candidate_id),
        "tracking entry must be removed after the miss is recorded"
    );
    assert!(
        fixture.processor.validation.is_rejected(&candidate_id),
        "final rejection should still mark the candidate as rejected"
    );
}

// ============================================================================
// Candidate Chaining Tests (C++ parity)
// ============================================================================

/// Test that local_chain_head and generated_parent_cache start empty.
#[test]
fn test_local_chain_head_initial_state() {
    let fixture = TestFixture::new(4);
    assert!(fixture.processor.collation.local_chain_head().is_none());
    assert!(fixture.processor.collation.generated_parent_cache_is_empty());
}

/// Test that invalidate_local_chain_head clears both the chain head and cache.
#[test]
fn test_invalidate_local_chain_head_clears_state() {
    let mut fixture = TestFixture::new(4);

    let hash = UInt256::from([0xAA; 32]);
    let block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        1,
        UInt256::from([0xBB; 32]),
        UInt256::from([0xCC; 32]),
    );
    let parent_info =
        crate::block::CandidateParentInfo { slot: SlotIndex::new(0), hash: hash.clone() };
    let raw_id = RawCandidateId { slot: SlotIndex::new(0), hash: hash.clone() };

    fixture.processor.collation.set_local_chain_head(Some(LocalChainHead {
        window: WindowIndex::new(0),
        slot: SlotIndex::new(0),
        parent_info,
        gen_utime_ms: None,
    }));
    fixture.processor.collation.insert_generated_parent(raw_id.clone(), block_id);

    assert!(fixture.processor.collation.local_chain_head().is_some());
    assert!(!fixture.processor.collation.generated_parent_cache_is_empty());

    fixture.processor.collation.invalidate_local_chain_head();

    assert!(fixture.processor.collation.local_chain_head().is_none());
    assert!(fixture.processor.collation.generated_parent_cache_is_empty());
}

/// Test that resolve_parent_block_id finds parents in generated_parent_cache
/// even before the async on_candidate_received self-loop populates received_candidates.
#[test]
fn test_resolve_parent_from_generated_cache() {
    let mut fixture = TestFixture::new(4);

    let hash = UInt256::from([0xDD; 32]);
    let block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        1,
        UInt256::from([0xEE; 32]),
        UInt256::from([0xFF; 32]),
    );
    let parent_info =
        crate::block::CandidateParentInfo { slot: SlotIndex::new(5), hash: hash.clone() };
    let raw_id = RawCandidateId { slot: SlotIndex::new(5), hash: hash.clone() };

    // Not in candidate_book yet
    assert!(fixture
        .processor
        .with_collation_backend(|c, b| c.resolve_parent_block_id(&parent_info, b))
        .is_none());

    // Seed the generated_parent_cache (as generated_block would)
    fixture.processor.collation.insert_generated_parent(raw_id, block_id.clone());

    // Now resolvable
    let resolved =
        fixture.processor.with_collation_backend(|c, b| c.resolve_parent_block_id(&parent_info, b));
    assert_eq!(resolved, Some(block_id));
}

/// Test that reset_precollations clears the local chain head.
#[test]
fn test_reset_precollations_clears_chain_head() {
    let mut fixture = TestFixture::new(4);

    let hash = UInt256::from([0x11; 32]);
    let parent_info =
        crate::block::CandidateParentInfo { slot: SlotIndex::new(0), hash: hash.clone() };

    fixture.processor.collation.set_local_chain_head(Some(LocalChainHead {
        window: WindowIndex::new(0),
        slot: SlotIndex::new(0),
        parent_info,
        gen_utime_ms: None,
    }));

    fixture.processor.reset_precollations();

    assert!(fixture.processor.collation.local_chain_head().is_none());
    assert!(fixture.processor.collation.generated_parent_cache_is_empty());
}

/// Test that multi-slot window options produce correct precollation depth.
#[test]
fn test_slots_per_leader_window_precollation_depth() {
    // Single-slot window: no precollation
    let opts1 = SessionOptions { slots_per_leader_window: 1, ..Default::default() };
    assert_eq!(opts1.slots_per_leader_window.saturating_sub(1), 0);

    // 4-slot window: up to 3 precollated
    let opts4 = SessionOptions { slots_per_leader_window: 4, ..Default::default() };
    assert_eq!(opts4.slots_per_leader_window.saturating_sub(1), 3);

    // 8-slot window: up to 7 precollated
    let opts8 = SessionOptions { slots_per_leader_window: 8, ..Default::default() };
    assert_eq!(opts8.slots_per_leader_window.saturating_sub(1), 7);
}

/// Test that creating a SessionProcessor with multi-slot window succeeds.
#[test]
fn test_multi_slot_window_session_creation() {
    let opts = SessionOptions { slots_per_leader_window: 4, ..Default::default() };
    let fixture = TestFixture::new_with_opts(4, opts);
    assert_eq!(fixture.description.opts().slots_per_leader_window, 4);
    assert!(fixture.processor.collation.local_chain_head().is_none());
}

#[test]
fn test_on_collation_complete_publishes_future_slot_in_current_window() {
    // C++ parity: for multi-slot windows, candidates generated for future slots in
    // the same active leader window are published immediately.
    let opts = SessionOptions { slots_per_leader_window: 4, ..Default::default() };
    let mut fixture = TestFixture::new_with_opts(4, opts);

    let slot = SlotIndex::new(1);
    assert_eq!(
        fixture.processor.simplex_state.get_first_non_progressed_slot(),
        SlotIndex::new(0),
        "precondition: progress cursor starts at slot 0"
    );
    assert_eq!(
        fixture.description.get_window_idx(slot),
        fixture.processor.simplex_state.get_current_leader_window_idx(),
        "precondition: slot 1 is in current leader window"
    );

    let request_id = 77;
    let request = AsyncRequestImpl::new(request_id, false, fixture.description.get_time());
    fixture
        .processor
        .collation
        .insert_precollated(slot, PrecollatedBlock { request, result: None, parent: None });

    let block_id =
        BlockIdExt::with_params(ShardIdent::masterchain(), 1, UInt256::rand(), UInt256::rand());
    let block_boc = make_test_boc(&[0x31], BocFlags::all());
    let collated_boc = make_test_boc(&[0x32], BocFlags::Crc32);
    let candidate = crate::ValidatorBlockCandidate {
        public_key: fixture.nodes[0].public_key.clone(),
        id: block_id,
        collated_file_hash: UInt256::from_slice(&sha256_digest(&collated_boc)),
        data: consensus_common::ConsensusCommonFactory::create_block_payload(block_boc),
        collated_data: consensus_common::ConsensusCommonFactory::create_block_payload(collated_boc),
    };

    fixture.processor.on_collation_complete(
        slot,
        request_id,
        CollationResult::Block(Arc::new(candidate)),
    );

    let actions = fixture.drain_receiver_actions();
    assert!(
        actions.iter().any(
            |a| matches!(a, ReceiverAction::SendBlockBroadcast { slot: s, .. } if *s == slot.value())
        ),
        "future in-window candidate must be broadcast immediately (C++ parity)"
    );
    assert!(
        fixture.processor.runtime.is_generated(slot),
        "future in-window slot must be marked generated after immediate publish"
    );
}

#[test]
fn test_on_collation_complete_publishes_future_empty_slot_in_current_window() {
    // C++ parity: future in-window slots may resolve to empty blocks, not just collated blocks.
    let opts = SessionOptions { slots_per_leader_window: 4, ..Default::default() };
    let mut fixture = TestFixture::new_with_opts(4, opts);

    let slot = SlotIndex::new(1);
    let request_id = 78;
    let request = AsyncRequestImpl::new(request_id, false, fixture.description.get_time());
    let parent_hash = UInt256::from([0x41; 32]);
    let parent_block_id =
        BlockIdExt::with_params(ShardIdent::masterchain(), 1, UInt256::rand(), UInt256::rand());

    fixture.processor.collation.insert_precollated(
        slot,
        PrecollatedBlock {
            request,
            result: None,
            parent: Some(crate::block::CandidateParentInfo {
                slot: SlotIndex::new(0),
                hash: parent_hash,
            }),
        },
    );

    fixture.processor.on_collation_complete(
        slot,
        request_id,
        CollationResult::Empty { parent_block_id: parent_block_id.clone() },
    );

    let actions = fixture.drain_receiver_actions();
    assert!(
        actions.iter().any(
            |a| matches!(a, ReceiverAction::SendBlockBroadcast { slot: s, .. } if *s == slot.value())
        ),
        "future in-window empty block must be broadcast immediately (C++ parity)"
    );
    assert!(
        fixture.processor.runtime.is_generated(slot),
        "future in-window empty slot must be marked generated after immediate publish"
    );
}

#[test]
fn test_on_collation_complete_publishes_late_same_window_slot_cpp_parity() {
    // C++ parity: if the leader window is still current, a collation result may
    // still be published even after Rust's first_non_progressed_slot advanced
    // inside the same window (for example, after a local timeout-skip).
    let opts = SessionOptions { slots_per_leader_window: 4, ..Default::default() };
    let mut fixture = TestFixture::new_with_opts(4, opts);
    fixture.drain_receiver_actions();

    let slot = SlotIndex::new(0);
    let request_id = 79;
    let request = AsyncRequestImpl::new(request_id, false, fixture.description.get_time());
    fixture
        .processor
        .collation
        .insert_precollated(slot, PrecollatedBlock { request, result: None, parent: None });

    assert_eq!(
        fixture.processor.simplex_state.get_first_non_progressed_slot(),
        SlotIndex::new(0),
        "precondition: progress cursor starts at slot 0"
    );
    assert_eq!(
        fixture.processor.simplex_state.get_current_leader_window_idx(),
        fixture.description.get_window_idx(slot),
        "precondition: slot 0 is in the current leader window"
    );

    // Advance progress inside the same 4-slot leader window by skip-certing slot 0.
    skip_slot(&mut fixture, slot);
    assert_eq!(
        fixture.processor.simplex_state.get_first_non_progressed_slot(),
        SlotIndex::new(1),
        "precondition: progress cursor advanced to slot 1"
    );
    assert_eq!(
        fixture.processor.simplex_state.get_current_leader_window_idx(),
        fixture.description.get_window_idx(slot),
        "precondition: window 0 must still be current after slot 0 skip"
    );

    // A second callback/generation has already advanced within this same
    // leader window. Publishing the older result must not schedule slot1 after
    // slot3, as observed on an actual interrupted-node restart.
    skip_slot(&mut fixture, SlotIndex::new(1));
    skip_slot(&mut fixture, SlotIndex::new(2));
    fixture.processor.check_collation();
    assert!(fixture.processor.collation.precollated_contains(SlotIndex::new(3)));

    let block_id =
        BlockIdExt::with_params(ShardIdent::masterchain(), 1, UInt256::rand(), UInt256::rand());
    let block_boc = make_test_boc(&[0x41], BocFlags::all());
    let collated_boc = make_test_boc(&[0x42], BocFlags::Crc32);
    let candidate = crate::ValidatorBlockCandidate {
        public_key: fixture.nodes[0].public_key.clone(),
        id: block_id,
        collated_file_hash: UInt256::from_slice(&sha256_digest(&collated_boc)),
        data: consensus_common::ConsensusCommonFactory::create_block_payload(block_boc),
        collated_data: consensus_common::ConsensusCommonFactory::create_block_payload(collated_boc),
    };

    fixture.processor.on_collation_complete(
        slot,
        request_id,
        CollationResult::Block(Arc::new(candidate)),
    );

    let actions = fixture.drain_receiver_actions();
    assert!(
        actions.iter().any(
            |a| matches!(a, ReceiverAction::SendBlockBroadcast { slot: s, .. } if *s == slot.value())
        ),
        "late same-window candidate must still be broadcast (C++ parity)"
    );
    assert!(
        fixture.processor.runtime.is_generated(slot),
        "late same-window slot must still be marked generated"
    );
}

#[test]
fn test_check_collation_cancels_stale_window_precollations_without_local_chain_head() {
    // C++ parity: block-producer.cpp cancels old-window collation requests on
    // every new OurLeaderWindowStarted, even if no local chain head was ever set.
    // Rust check_collation() must detect stale-window precollated_blocks entries
    // and reset the pipeline even when local_chain_head is None.
    let opts = SessionOptions { slots_per_leader_window: 4, ..Default::default() };
    let mut fixture = TestFixture::new_with_opts(4, opts);
    fixture.drain_receiver_actions();

    // Manually insert a precollated entry for slot 0 (window 0).
    let request_id = 90;
    let request = AsyncRequestImpl::new(request_id, false, fixture.description.get_time());
    fixture.processor.collation.insert_precollated(
        SlotIndex::new(0),
        PrecollatedBlock { request, result: None, parent: None },
    );

    assert!(
        fixture.processor.collation.local_chain_head().is_none(),
        "precondition: no local chain head"
    );
    assert!(!fixture.processor.collation.precollated_is_empty(), "precondition: has stale entry");

    // Advance the FSM to window 1 by skip-certing all of window 0.
    for s in 0..4u32 {
        skip_slot(&mut fixture, SlotIndex::new(s));
    }
    fixture.drain_receiver_actions();

    assert_eq!(
        fixture.processor.simplex_state.get_current_leader_window_idx(),
        WindowIndex::new(1),
        "precondition: FSM advanced to window 1"
    );

    // check_collation must detect the stale window-0 entry and reset.
    fixture.processor.check_collation();

    assert!(
        fixture.processor.collation.precollated_is_empty(),
        "stale window-0 precollated entries must be cleared even without local_chain_head"
    );
}

#[test]
fn test_handle_slot_skipped_preserves_same_window_precollation() {
    // C++ parity: per-slot skip events must NOT destroy same-window precollation
    // entries. The locked parent and async request are needed for late same-window
    // callbacks.
    let opts = SessionOptions { slots_per_leader_window: 4, ..Default::default() };
    let mut fixture = TestFixture::new_with_opts(4, opts);
    fixture.drain_receiver_actions();

    let slot = SlotIndex::new(0);
    let request_id = 91;
    let request = AsyncRequestImpl::new(request_id, false, fixture.description.get_time());
    fixture
        .processor
        .collation
        .insert_precollated(slot, PrecollatedBlock { request, result: None, parent: None });

    // Skip slot 0 (still same window 0).
    skip_slot(&mut fixture, slot);

    assert!(
        fixture.processor.collation.precollated_contains(slot),
        "same-window precollation must be preserved after per-slot skip"
    );
}

// ============================================================================
// C++ in-window collation parity tests
// ============================================================================

#[test]
fn test_precollate_same_window_slot_uses_local_chain_head_before_parent_notarization() {
    let opts = SessionOptions { slots_per_leader_window: 4, ..Default::default() };
    let probe = TestFixture::new_with_opts(4, opts.clone());
    let local_idx = probe.description.get_leader(SlotIndex::new(1)).value() as usize;
    let mut fixture = TestFixture::new_with_local_idx(4, local_idx, opts);

    let parent_hash = UInt256::from([0xB1; 32]);
    let block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        1,
        UInt256::from([0xB2; 32]),
        UInt256::from([0xB3; 32]),
    );

    fixture.processor.collation.set_local_chain_head(Some(LocalChainHead {
        window: WindowIndex::new(0),
        slot: SlotIndex::new(0),
        parent_info: crate::block::CandidateParentInfo {
            slot: SlotIndex::new(0),
            hash: parent_hash.clone(),
        },
        gen_utime_ms: None,
    }));
    fixture.processor.collation.insert_generated_parent(
        RawCandidateId { slot: SlotIndex::new(0), hash: parent_hash.clone() },
        block_id.clone(),
    );
    fixture.processor.consensus.set_last_consensus_finalized_seqno(Some(block_id.seq_no));

    assert!(
        !fixture.processor.simplex_state.has_notarized_block(SlotIndex::new(0)),
        "precondition: slot 0 is not notarized yet"
    );

    fixture.processor.precollate_block(SlotIndex::new(1));

    let precollated = fixture
        .processor
        .collation
        .precollated(SlotIndex::new(1))
        .expect("same-window child slot must be precollated immediately");
    let parent = precollated.parent.as_ref().expect("precollated slot must capture parent");
    assert_eq!(parent.slot, SlotIndex::new(0));
    assert_eq!(parent.hash, parent_hash);
}

#[test]
fn test_precollate_first_slot_in_new_window_uses_fsm_available_base() {
    let opts = SessionOptions { slots_per_leader_window: 2, ..Default::default() };
    let probe = TestFixture::new_with_opts(4, opts.clone());
    let local_idx = probe.description.get_leader(SlotIndex::new(2)).value() as usize;
    let mut fixture = TestFixture::new_with_local_idx(4, local_idx, opts);

    let stale_hash = UInt256::from([0xC0; 32]);
    fixture.processor.collation.set_local_chain_head(Some(LocalChainHead {
        window: WindowIndex::new(0),
        slot: SlotIndex::new(1),
        parent_info: crate::block::CandidateParentInfo {
            slot: SlotIndex::new(1),
            hash: stale_hash.clone(),
        },
        gen_utime_ms: None,
    }));

    let fsm_parent_id = RawCandidateId { slot: SlotIndex::new(1), hash: UInt256::from([0xC3; 32]) };
    let fsm_parent_block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        11,
        UInt256::from([0xC4; 32]),
        UInt256::from([0xC5; 32]),
    );
    insert_received_candidate(
        &mut fixture.processor,
        &fsm_parent_id,
        fsm_parent_block_id.clone(),
        false,
        Some(RawCandidateId { slot: SlotIndex::new(0), hash: UInt256::from([0xC6; 32]) }),
    );

    fixture.processor.simplex_state.on_block_notarized_for_test(
        &fixture.description,
        SlotIndex::new(0),
        UInt256::from([0xC7; 32]),
    );
    fixture.processor.simplex_state.on_block_notarized_for_test(
        &fixture.description,
        SlotIndex::new(1),
        fsm_parent_id.hash.clone(),
    );
    fixture
        .processor
        .consensus
        .set_last_consensus_finalized_seqno(Some(fsm_parent_block_id.seq_no));

    assert_eq!(
        fixture.processor.simplex_state.get_current_leader_window_idx(),
        fixture.description.get_window_idx(SlotIndex::new(2)),
        "precondition: slot 2 is now the first slot of the current leader window"
    );

    fixture.processor.precollate_block(SlotIndex::new(2));

    let precollated = fixture
        .processor
        .collation
        .precollated(SlotIndex::new(2))
        .expect("first slot in the new window must use the FSM base");
    let parent = precollated.parent.as_ref().expect("new-window slot must capture parent");
    assert_eq!(parent.slot, fsm_parent_id.slot);
    assert_eq!(parent.hash, fsm_parent_id.hash);
    assert_ne!(
        parent.hash, stale_hash,
        "new-window collation must ignore the stale local_chain_head and use FSM available_base"
    );
}

#[test]
fn test_check_collation_resets_stale_local_chain_head_on_window_change() {
    let opts = SessionOptions { slots_per_leader_window: 2, ..Default::default() };
    let probe = TestFixture::new_with_opts(4, opts.clone());
    let local_idx = probe.description.get_leader(SlotIndex::new(2)).value() as usize;
    let mut fixture = TestFixture::new_with_local_idx(4, local_idx, opts);

    let stale_raw_id = RawCandidateId { slot: SlotIndex::new(1), hash: UInt256::from([0xD0; 32]) };
    let stale_block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        51,
        UInt256::from([0xD1; 32]),
        UInt256::from([0xD2; 32]),
    );
    fixture.processor.collation.set_local_chain_head(Some(LocalChainHead {
        window: WindowIndex::new(0),
        slot: stale_raw_id.slot,
        parent_info: crate::block::CandidateParentInfo {
            slot: stale_raw_id.slot,
            hash: stale_raw_id.hash.clone(),
        },
        gen_utime_ms: None,
    }));
    fixture.processor.collation.insert_generated_parent(stale_raw_id.clone(), stale_block_id);

    let fsm_parent_id = RawCandidateId { slot: SlotIndex::new(1), hash: UInt256::from([0xD3; 32]) };
    let fsm_parent_block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        12,
        UInt256::from([0xD4; 32]),
        UInt256::from([0xD5; 32]),
    );
    insert_received_candidate(
        &mut fixture.processor,
        &fsm_parent_id,
        fsm_parent_block_id.clone(),
        false,
        Some(RawCandidateId { slot: SlotIndex::new(0), hash: UInt256::from([0xD6; 32]) }),
    );

    fixture.processor.simplex_state.on_block_notarized_for_test(
        &fixture.description,
        SlotIndex::new(0),
        UInt256::from([0xD7; 32]),
    );
    fixture.processor.simplex_state.on_block_notarized_for_test(
        &fixture.description,
        SlotIndex::new(1),
        fsm_parent_id.hash.clone(),
    );
    fixture
        .processor
        .consensus
        .set_last_consensus_finalized_seqno(Some(fsm_parent_block_id.seq_no));

    fixture.processor.check_collation();

    assert!(
        fixture.processor.collation.local_chain_head().is_none(),
        "window change must invalidate the stale local chain head"
    );
    let precollated = fixture
        .processor
        .collation
        .precollated(SlotIndex::new(2))
        .expect("after clearing stale local state, collation must fall back to the FSM base");
    let parent = precollated.parent.as_ref().expect("precollated slot must capture parent");
    assert_eq!(parent.slot, fsm_parent_id.slot);
    assert_eq!(parent.hash, fsm_parent_id.hash);
    assert!(
        fixture.processor.collation.generated_parent_cache_is_empty(),
        "reset_precollations must also clear the old generated_parent_cache"
    );
}

/// End-to-end session processor test: first leader absent, timeout fires,
/// skip certificate arrives, window advances, second leader (us) collates.
///
/// Uses time simulation via set_time/advance_time and injects skip certificates
/// from other validators to drive the full timeout → skip → collation pipeline.
#[test]
fn test_second_leader_collates_after_timeout_skip() {
    // 4 validators, 1 slot per window → window 0 = slot 0 (leader v0), window 1 = slot 1 (leader v1).
    // We are v1 (second leader).
    let opts = SessionOptions {
        slots_per_leader_window: 1,
        first_block_timeout: Duration::from_secs(3),
        target_rate: Duration::from_millis(500),
        ..Default::default()
    };
    let mut fixture = TestFixture::new_with_local_idx(4, 1, opts.clone());

    assert_eq!(
        fixture.description.get_self_idx(),
        ValidatorIndex::new(1),
        "precondition: we must be validator 1"
    );
    assert_eq!(
        fixture.description.get_leader(SlotIndex::new(0)),
        ValidatorIndex::new(0),
        "precondition: v0 leads window 0"
    );
    assert_eq!(
        fixture.description.get_leader(SlotIndex::new(1)),
        ValidatorIndex::new(1),
        "precondition: v1 leads window 1"
    );

    // Set deterministic base time and start the session (arms timeouts).
    let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fixture.processor.set_time(base_time);
    fixture.processor.start();
    fixture.drain_receiver_actions(); // clear startup actions

    // Advance time past first_block_timeout + target_rate to trigger timeout for slot 0.
    // C++ timeout fires at: base + first_block_timeout + target_rate = 3.5s
    fixture.advance_time(opts.first_block_timeout + opts.target_rate + Duration::from_millis(1));

    // check_all: processes timeout → our node decides to skip slot 0. This
    // classical fixture has no post-quantum signer, so no own vote is sent.
    fixture.processor.check_all();

    let actions_after_timeout = fixture.drain_receiver_actions();
    assert!(
        !actions_after_timeout.iter().any(|a| matches!(a, ReceiverAction::SendVote { .. })),
        "a classical session never signs or sends its skip vote"
    );

    // Inject skip certificate from other validators for slot 0 (quorum = 3 of 4).
    let skip_cert = build_skip_certificate_tl(
        fixture.description.get_session_id(),
        &fixture.nodes,
        0,
        &[1, 2, 3],
    );
    fixture.processor.on_certificate(2, skip_cert);

    // check_all: processes skip cert → window advances to 1 → check_collation sees
    // we are leader for slot 1 → invoke_collation creates a collation request.
    fixture.processor.check_all();

    // The second leader must have initiated collation for slot 1.
    let slot1 = SlotIndex::new(1);
    assert!(
        fixture.processor.collation.precollated_contains(slot1)
            || fixture.processor.runtime.is_pending_generate(slot1),
        "second leader (v1) must initiate collation for slot 1 after window 0 skip. \
        precollated_blocks={:?}, pending_generate={}",
        fixture.processor.collation.precollated_slots(),
        fixture.processor.runtime.is_pending_generate(slot1),
    );
}

/// Late-join scenario: node receives only a finalization certificate for a far slot
/// (no candidate body), then receives a child candidate whose parent is that
/// bodyless-but-finalized block. The node must not stall and must start validation.
///
/// Real-network flow:
/// 1. Node joins late, receives FinalCert for slot 50 (no body)
/// 2. FSM advances first_non_finalized_slot past slot 50
/// 3. The finalization is recorded in finalized_pending_body (body missing)
/// 4. Skip certificates are injected for intermediate slots (51..54)
/// 5. A new candidate for slot 55 arrives with parent = slot 50 block
/// 6. is_wait_for_parent_ready passes: parent matches get_last_finalize_certificate()
/// 7. check_validation proceeds — candidate enters validation pipeline
#[test]
fn test_late_join_finalization_cert_without_body_then_child_validates() {
    let mut fixture = TestFixture::new_shard(4);

    let far_slot = SlotIndex::new(50);
    let far_block_hash = UInt256::rand();

    // 1. Inject finalization certificate for slot 50 into the FSM (simulating
    //    a late-join node receiving a FinalCert from the network without the body).
    let signatures = vec![
        crate::certificate::VoteSignature::new(ValidatorIndex::new(0), vec![10]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(1), vec![11]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(2), vec![12]),
    ];
    let finalize_vote =
        crate::simplex_state::FinalizeVote { slot: far_slot, block_hash: far_block_hash.clone() };
    let final_cert = Arc::new(crate::certificate::Certificate { vote: finalize_vote, signatures });

    fixture
        .processor
        .simplex_state
        .set_finalize_certificate(
            &fixture.description,
            far_slot,
            &far_block_hash,
            final_cert.clone(),
        )
        .expect("set_finalize_certificate failed");

    // Verify FSM advanced past slot 50.
    let first_nf = fixture.processor.simplex_state.get_first_non_finalized_slot();
    assert!(
        first_nf > far_slot,
        "first_non_finalized_slot must advance past the finalized slot: got {first_nf}, expected > {far_slot}"
    );

    // Process events emitted by set_finalize_certificate (BlockFinalized + FinalizationReached).
    fixture.processor.check_all();
    drain_processor_storage_and_messages(&mut fixture.processor);

    // The finalization should be in finalized_pending_body since no body exists.
    let far_id = RawCandidateId { slot: far_slot, hash: far_block_hash.clone() };
    assert!(
        fixture.processor.consensus.finalized_pending_body_contains(&far_id),
        "finalization for bodyless slot 50 must be recorded in finalized_pending_body"
    );

    // finalized_head_seqno must NOT advance (no body to materialize).
    let head_before = fixture.processor.consensus.finalized_head_seqno();

    // 2. Inject skip certificates for the gap slots 51..55 (exclusive).
    for gap in 51..55u32 {
        skip_slot(&mut fixture, SlotIndex::new(gap));
    }

    // 3. Create and insert a child candidate for slot 55, parented on slot 50.
    let child_slot = SlotIndex::new(55);
    let child_hash = UInt256::rand();
    let child_id = RawCandidateId { slot: child_slot, hash: child_hash.clone() };
    let parent_id = RawCandidateId { slot: far_slot, hash: far_block_hash.clone() };

    let raw_candidate =
        make_test_non_empty_candidate(child_id.clone(), Some(parent_id.clone()), &fixture.nodes);
    let time = fixture.description.get_time();
    insert_pending_validation(&mut fixture.processor, &child_id, raw_candidate, time);

    // 4. Drive validation: check_validation should find the child candidate eligible
    //    because its parent matches the last finalize certificate and gaps are skip-covered.
    fixture.processor.check_validation();

    assert!(
        fixture.processor.validation.pending_approve_contains(&child_id),
        "child candidate at slot 55 must enter validation pipeline (not stall). \
        The parent at slot 50 has a finalization certificate even though the body is missing."
    );

    // finalized_head_seqno must remain unchanged (parent body still missing).
    assert_eq!(
        fixture.processor.consensus.finalized_head_seqno(),
        head_before,
        "finalized_head_seqno must NOT advance when the parent body is still missing"
    );

    // finalized_pending_body must still contain the slot 50 entry.
    assert!(
        fixture.processor.consensus.finalized_pending_body_contains(&far_id),
        "finalized_pending_body must retain slot 50 entry until body arrives"
    );
}

// ============================================================================
// MC empty-final-trigger parity (C++ consensus.cpp::finalize_blocks_inner)
// ============================================================================

/// C++ parity: when the FinalCert trigger is an empty MC candidate, the first
/// non-empty ancestor in the parent chain must receive `on_block_finalized()`
/// with FinalCert semantics, and the walk must stop after that block.
///
/// This is the confirmed root cause of the simnet mid-session stall where
/// MC 45865 was locally finalized but never delivered to `ValidatorGroup`.
#[test]
fn test_mc_empty_final_trigger_emits_callback_for_non_empty_ancestor_cpp_parity() {
    let mut opts = SessionOptions::default();
    opts.use_callback_thread = false;
    let mut fixture = TestFixture::new_with_opts(4, opts);

    let recording = RecordingListener::new();
    let listener: Arc<dyn consensus_common::SessionListener + Send + Sync> = recording.clone();
    fixture.processor.set_listener_for_test(Arc::downgrade(&listener));

    // Build chain: parent(non-empty, slot 90) → empty(slot 91, FinalCert trigger)
    let (parent_leader, parent_id, parent_broadcast) =
        make_signed_block_broadcast(&fixture, 90, vec![0xAA, 0xBB, 0xCC]);
    fixture.processor.on_candidate_received(parent_leader, parent_broadcast, None);
    let parent_block = fixture
        .processor
        .candidate_book()
        .received(&parent_id)
        .expect("parent must exist")
        .block_id
        .clone();

    let (empty_leader, empty_id, empty_broadcast) = make_signed_empty_block_broadcast_with_parent(
        &fixture,
        91,
        parent_id.clone(),
        parent_block.clone(),
    );
    fixture.processor.on_candidate_received(empty_leader, empty_broadcast, None);

    // Notarize parent so recursive finalization can find its cert.
    notarize_slot(&mut fixture, parent_id.slot, &parent_id.hash);

    // FinalCert arrives on the empty trigger (slot 91).
    fixture.processor.handle_block_finalized(BlockFinalizedEvent {
        slot: empty_id.slot,
        block_hash: empty_id.hash.clone(),
        block_id: None,
        certificate: make_test_final_cert(empty_id.slot, empty_id.hash.clone()),
    });

    let finalized_events = drain_finalized_events(&recording);

    // C++ parity: exactly one callback — the non-empty ancestor with FinalCert
    // semantics (is_final=true). The empty trigger itself must not emit.
    assert_eq!(
        finalized_events.len(),
        1,
        "MC empty-final-trigger must emit exactly one callback for the non-empty ancestor \
         (got {} callbacks: {:?})",
        finalized_events.len(),
        finalized_events,
    );
    assert_eq!(
        finalized_events[0].0, parent_block,
        "callback must be for the non-empty ancestor block"
    );
    assert!(finalized_events[0].1, "callback must carry FinalCert semantics (is_final=true)");

    // Both empty trigger and parent must be locally finalized.
    assert!(
        fixture.processor.consensus.is_finalized_block(&empty_id),
        "empty trigger must be locally finalized"
    );
    assert!(
        fixture.processor.consensus.is_finalized_block(&parent_id),
        "non-empty parent must be locally finalized"
    );
}

/// C++ parity: when multiple empty blocks chain back to a non-empty MC ancestor,
/// the FinalCert context must flow through all empties and deliver the callback
/// exactly once for the non-empty ancestor.
#[test]
fn test_mc_deep_empty_chain_delivers_finalcert_to_first_non_empty_ancestor() {
    let mut opts = SessionOptions::default();
    opts.use_callback_thread = false;
    let mut fixture = TestFixture::new_with_opts(4, opts);

    let recording = RecordingListener::new();
    let listener: Arc<dyn consensus_common::SessionListener + Send + Sync> = recording.clone();
    fixture.processor.set_listener_for_test(Arc::downgrade(&listener));

    // Chain: root(non-empty, s100) → empty1(s101) → empty2(s102, FinalCert trigger)
    let (root_leader, root_id, root_broadcast) =
        make_signed_block_broadcast(&fixture, 100, vec![0xDD, 0xEE]);
    fixture.processor.on_candidate_received(root_leader, root_broadcast, None);
    let root_block = fixture
        .processor
        .candidate_book()
        .received(&root_id)
        .expect("root must exist")
        .block_id
        .clone();

    let (e1_leader, e1_id, e1_broadcast) = make_signed_empty_block_broadcast_with_parent(
        &fixture,
        101,
        root_id.clone(),
        root_block.clone(),
    );
    fixture.processor.on_candidate_received(e1_leader, e1_broadcast, None);
    let e1_block = fixture
        .processor
        .candidate_book()
        .received(&e1_id)
        .expect("e1 must exist")
        .block_id
        .clone();

    let (e2_leader, e2_id, e2_broadcast) = make_signed_empty_block_broadcast_with_parent(
        &fixture,
        102,
        e1_id.clone(),
        e1_block.clone(),
    );
    fixture.processor.on_candidate_received(e2_leader, e2_broadcast, None);

    notarize_slot(&mut fixture, root_id.slot, &root_id.hash);

    fixture.processor.handle_block_finalized(BlockFinalizedEvent {
        slot: e2_id.slot,
        block_hash: e2_id.hash.clone(),
        block_id: None,
        certificate: make_test_final_cert(e2_id.slot, e2_id.hash.clone()),
    });

    let finalized_events = drain_finalized_events(&recording);
    assert_eq!(
        finalized_events.len(),
        1,
        "deep empty chain must produce exactly one callback for the root ancestor"
    );
    assert_eq!(finalized_events[0].0, root_block);
    assert!(finalized_events[0].1, "must carry FinalCert semantics");

    assert!(fixture.processor.consensus.is_finalized_block(&e2_id));
    assert!(fixture.processor.consensus.is_finalized_block(&e1_id));
    assert!(fixture.processor.consensus.is_finalized_block(&root_id));
}

/// C++ parity: on MC, the recursive walk must stop after the first non-empty
/// block that consumed the FinalCert context. No further ancestors should
/// receive callbacks (matching `maybe_final_cert.is_null() && MC → return`).
#[test]
fn test_mc_walk_stops_after_cert_consumed_by_non_empty_block() {
    let mut opts = SessionOptions::default();
    opts.use_callback_thread = false;
    let mut fixture = TestFixture::new_with_opts(4, opts);

    let recording = RecordingListener::new();
    let listener: Arc<dyn consensus_common::SessionListener + Send + Sync> = recording.clone();
    fixture.processor.set_listener_for_test(Arc::downgrade(&listener));

    // Chain: grandparent(non-empty, s110) → parent(non-empty, s111) → empty(s112, trigger)
    let (gp_leader, gp_id, gp_broadcast) =
        make_signed_block_broadcast(&fixture, 110, vec![0x11, 0x22]);
    fixture.processor.on_candidate_received(gp_leader, gp_broadcast, None);

    let (parent_leader, parent_id, parent_broadcast) = make_signed_block_broadcast_with_parent(
        &fixture,
        111,
        vec![0x33, 0x44],
        Some(gp_id.clone()),
    );
    fixture.processor.on_candidate_received(parent_leader, parent_broadcast, None);
    let parent_block = fixture
        .processor
        .candidate_book()
        .received(&parent_id)
        .expect("parent must exist")
        .block_id
        .clone();

    let (empty_leader, empty_id, empty_broadcast) = make_signed_empty_block_broadcast_with_parent(
        &fixture,
        112,
        parent_id.clone(),
        parent_block.clone(),
    );
    fixture.processor.on_candidate_received(empty_leader, empty_broadcast, None);

    notarize_slot(&mut fixture, gp_id.slot, &gp_id.hash);
    notarize_slot(&mut fixture, parent_id.slot, &parent_id.hash);

    fixture.processor.handle_block_finalized(BlockFinalizedEvent {
        slot: empty_id.slot,
        block_hash: empty_id.hash.clone(),
        block_id: None,
        certificate: make_test_final_cert(empty_id.slot, empty_id.hash.clone()),
    });

    let finalized_events = drain_finalized_events(&recording);

    // C++ parity: only parent (first non-empty after empty trigger) gets callback.
    // Grandparent does NOT get a callback because on MC, once the cert is consumed
    // by a non-empty block, the walk stops (null cert + MC → early return).
    assert_eq!(
        finalized_events.len(),
        1,
        "MC walk must stop after cert is consumed: only parent should get callback, \
         grandparent must NOT (got {} callbacks)",
        finalized_events.len(),
    );
    assert_eq!(finalized_events[0].0, parent_block);
    assert!(finalized_events[0].1, "must carry FinalCert semantics");

    // Empty trigger and parent must be locally finalized.
    assert!(fixture.processor.consensus.is_finalized_block(&empty_id));
    assert!(fixture.processor.consensus.is_finalized_block(&parent_id));
    // Grandparent should NOT be locally finalized by this walk (MC stops early).
    assert!(
        !fixture.processor.consensus.is_finalized_block(&gp_id),
        "grandparent must NOT be finalized by the MC empty-cert walk (cert consumed)"
    );
}

// ============================================================================
// Standstill parity: certificate acceptance feedback
// =====================================================================

// ============================================================================
// Pending async DB results registry
// ============================================================================
//
// Cover `post_async_db_result()` / `process_pending_async_db_results()` and
// the `pending_async_db_results` field on `SessionProcessor`. The registry
// lets callers register an in-flight `*_async()` DB result with a one-shot
// continuation that is invoked on completion (or timeout) from `check_all()`,
// without blocking SXMAIN on `wait()`.

/// Deterministic `StorageAsyncResult<()>` test stub. Starts pending; tests
/// flip it to Ok / Err via `complete_*()` to exercise the registry.
struct ManualAsyncResult {
    state: Mutex<Option<rtos_block::Result<()>>>,
}

impl ManualAsyncResult {
    fn pending() -> Arc<Self> {
        Arc::new(Self { state: Mutex::new(None) })
    }

    fn complete_ok(self: &Arc<Self>) {
        *self.state.lock().unwrap() = Some(Ok(()));
    }

    fn complete_err(self: &Arc<Self>, msg: &str) {
        *self.state.lock().unwrap() = Some(Err(error!("{}", msg)));
    }

    /// Inject the typed [`StorageResultAlreadyTaken`] sentinel — the same
    /// value that `StorageAsyncResultImpl::{try_get, wait_timeout}` emit when
    /// the inner result was consumed by a prior caller. Used by the
    /// "redundant FSM re-emit" regression tests so they exercise the real
    /// `downcast_ref` detection path used by the cert callbacks instead of
    /// stringly comparing error messages.
    fn complete_taken_sentinel(self: &Arc<Self>) {
        *self.state.lock().unwrap() = Some(Err(consensus_common::StorageResultAlreadyTaken.into()));
    }
}

impl consensus_common::StorageAsyncResult<()> for ManualAsyncResult {
    fn is_ready(&self) -> bool {
        self.state.lock().unwrap().is_some()
    }

    fn try_get(&self) -> Option<rtos_block::Result<()>> {
        self.state.lock().unwrap().take()
    }

    fn wait_timeout(&self, _: Duration) -> Option<rtos_block::Result<()>> {
        self.try_get()
    }
}

/// Ready-then-Ok callback fires once and removes the entry.
#[test]
fn test_post_async_db_result_invokes_ok_callback_when_ready() {
    let mut fixture = TestFixture::new(4);
    let result = ManualAsyncResult::pending();

    let outcome = Arc::new(Mutex::new(None::<bool>));
    let outcome_cb = outcome.clone();

    fixture.processor.post_async_db_result(
        "test_ok",
        result.clone(),
        Duration::from_secs(60),
        move |_processor, res| {
            *outcome_cb.lock().unwrap() = Some(res.is_ok());
        },
    );

    assert_eq!(fixture.processor.database.pending_count(), 1);

    // Drain while pending: callback must NOT fire.
    fixture.processor.process_pending_async_db_results();
    assert!(outcome.lock().unwrap().is_none(), "callback must not fire while pending");
    assert_eq!(fixture.processor.database.pending_count(), 1);

    // Complete and re-drain: callback fires with Ok and entry is removed.
    result.complete_ok();
    fixture.processor.process_pending_async_db_results();
    assert_eq!(*outcome.lock().unwrap(), Some(true), "callback must observe Ok");
    assert_eq!(fixture.processor.database.pending_count(), 0);
}

/// Storage Err propagates verbatim to the continuation.
#[test]
fn test_post_async_db_result_propagates_storage_error() {
    let mut fixture = TestFixture::new(4);
    let result = ManualAsyncResult::pending();

    let captured = Arc::new(Mutex::new(None::<String>));
    let captured_cb = captured.clone();

    fixture.processor.post_async_db_result(
        "test_err",
        result.clone(),
        Duration::from_secs(60),
        move |_processor, res| match res {
            Ok(()) => panic!("expected error from storage layer"),
            Err(e) => *captured_cb.lock().unwrap() = Some(e.to_string()),
        },
    );

    result.complete_err("disk_full");
    fixture.processor.process_pending_async_db_results();

    let msg = captured.lock().unwrap().clone().expect("callback must fire");
    assert!(msg.contains("disk_full"), "error message must reach the continuation: {msg}");
    assert_eq!(fixture.processor.database.pending_count(), 0);
}

/// Deadline elapsed while still pending: continuation receives `Err(...timed out...)`
/// and the timeout counter increments.
#[test]
fn test_post_async_db_result_times_out_when_deadline_passes() {
    let mut fixture = TestFixture::new(4);
    let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fixture.processor.set_time(base_time);

    let result = ManualAsyncResult::pending();
    let outcome = Arc::new(Mutex::new(None::<String>));
    let outcome_cb = outcome.clone();

    fixture.processor.post_async_db_result(
        "test_timeout",
        result.clone(),
        Duration::from_millis(500),
        move |_processor, res| match res {
            Ok(()) => panic!("expected timeout error"),
            Err(e) => *outcome_cb.lock().unwrap() = Some(e.to_string()),
        },
    );

    let timeouts_before = metrics_counter(&fixture.processor, "simplex_async_db_timeout_total");

    // Within deadline: callback must NOT fire.
    fixture.advance_time(Duration::from_millis(100));
    fixture.processor.process_pending_async_db_results();
    assert!(outcome.lock().unwrap().is_none(), "callback must not fire before deadline");

    // Past deadline (> 500ms total): callback fires with Err timeout.
    fixture.advance_time(Duration::from_millis(500));
    fixture.processor.process_pending_async_db_results();
    let msg = outcome.lock().unwrap().clone().expect("callback must fire on timeout");
    assert!(msg.contains("test_timeout"), "label must appear in timeout error: {msg}");
    assert!(msg.contains("timed out"), "timeout error must mention 'timed out': {msg}");
    assert_eq!(fixture.processor.database.pending_count(), 0);
    assert_eq!(
        metrics_counter(&fixture.processor, "simplex_async_db_timeout_total"),
        timeouts_before + 1,
        "timeout counter must increment exactly once"
    );
}

/// Pending entry causes `next_awake_time` to be advanced to `now + ASYNC_DB_POLL_DELAY`.
#[test]
fn test_post_async_db_result_pending_schedules_next_awake() {
    let mut fixture = TestFixture::new(4);
    let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fixture.processor.set_time(base_time);

    let result = ManualAsyncResult::pending();
    fixture.processor.post_async_db_result(
        "test_awake",
        result,
        Duration::from_secs(60),
        |_processor, _res| {},
    );

    fixture.processor.reset_next_awake_time();
    let before = fixture.processor.get_next_awake_time();
    fixture.processor.process_pending_async_db_results();
    let after = fixture.processor.get_next_awake_time();
    assert!(
        after <= base_time + Duration::from_millis(5),
        "pending entry must schedule wake at <= now + ASYNC_DB_POLL_DELAY (5ms); got after={:?} before={:?}",
        after,
        before,
    );
}

/// Continuations may register new pending entries; ready ones are drained by
/// the same loop pass (matching `process_delayed_actions()` semantics). Pending
/// continuation registrations stay in the queue for the next `check_all()` pass.
#[test]
fn test_pending_async_db_results_drains_chained_ready_continuations_in_one_pass() {
    let mut fixture = TestFixture::new(4);
    let outer = ManualAsyncResult::pending();
    let ready_inner = ManualAsyncResult::pending();
    ready_inner.complete_ok();
    let pending_inner = ManualAsyncResult::pending();

    let ready_inner_cb = ready_inner.clone();
    let pending_inner_cb = pending_inner.clone();
    let ready_called = Arc::new(AtomicBool::new(false));
    let pending_called = Arc::new(AtomicBool::new(false));
    let ready_called_for_cb = ready_called.clone();
    let pending_called_for_cb = pending_called.clone();

    fixture.processor.post_async_db_result(
        "test_outer",
        outer.clone(),
        Duration::from_secs(60),
        move |processor, _res| {
            let ready_cb = ready_called_for_cb.clone();
            processor.post_async_db_result(
                "test_inner_ready",
                ready_inner_cb,
                Duration::from_secs(60),
                move |_p, _r| {
                    ready_cb.store(true, Ordering::SeqCst);
                },
            );
            let pending_cb = pending_called_for_cb.clone();
            processor.post_async_db_result(
                "test_inner_pending",
                pending_inner_cb,
                Duration::from_secs(60),
                move |_p, _r| {
                    pending_cb.store(true, Ordering::SeqCst);
                },
            );
        },
    );

    outer.complete_ok();
    fixture.processor.process_pending_async_db_results();
    assert!(
        ready_called.load(Ordering::SeqCst),
        "ready continuation registered inside callback must drain in same pass"
    );
    assert!(!pending_called.load(Ordering::SeqCst), "pending continuation must wait");
    assert_eq!(
        fixture.processor.database.pending_count(),
        1,
        "only the still-pending continuation entry must remain queued",
    );

    pending_inner.complete_ok();
    fixture.processor.process_pending_async_db_results();
    assert!(pending_called.load(Ordering::SeqCst), "pending continuation must fire on next pass");
    assert_eq!(fixture.processor.database.pending_count(), 0);
}

// ----------------------------------------------------------------------------
// `maybe_store_pool_state` migration to the async-DB-results registry.
// ----------------------------------------------------------------------------

/// When the FSM has not crossed the next leader window yet, `maybe_store_pool_state`
/// must be a no-op: no DB write scheduled, no registry entry, cursor unchanged.
#[test]
fn test_maybe_store_pool_state_is_noop_when_window_not_advanced() {
    let mut fixture = TestFixture::new(4);
    let initial_window = WindowIndex::new(5);
    fixture.processor.database.set_first_nonannounced_window(initial_window);
    assert_eq!(
        fixture.processor.simplex_state.get_current_leader_window_idx(),
        WindowIndex::new(0)
    );

    fixture.processor.maybe_store_pool_state();

    assert_eq!(
        fixture.processor.database.first_nonannounced_window(),
        initial_window,
        "first_nonannounced_window must not move when current window is behind it",
    );
    assert_eq!(
        fixture.processor.database.pending_count(),
        0,
        "no-op call must not register a pending DB result",
    );
}

/// When the FSM is at-or-past the announced cursor, `maybe_store_pool_state` must:
/// - advance the in-memory cursor synchronously (matches C++ ordering); and
/// - register a `PendingAsyncDbEntry` for the durability wait without blocking SXMAIN.
///
/// Draining the registry once the write completes must remove the entry without
/// incrementing the error counter.
#[test]
fn test_maybe_store_pool_state_advances_cursor_and_registers_pending_write() {
    let mut fixture = TestFixture::new(4);
    let errors_before =
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(fixture.processor.database.first_nonannounced_window(), WindowIndex::new(0));
    assert_eq!(
        fixture.processor.simplex_state.get_current_leader_window_idx(),
        WindowIndex::new(0)
    );
    assert_eq!(fixture.processor.database.pending_count(), 0);

    fixture.processor.maybe_store_pool_state();

    assert_eq!(
        fixture.processor.database.first_nonannounced_window(),
        WindowIndex::new(1),
        "in-memory cursor must advance to current_window + 1 synchronously",
    );
    assert_eq!(
        fixture.processor.database.pending_count(),
        1,
        "the durability wait must be registered, not blocked on inline",
    );
    assert_eq!(
        fixture.processor.database.pending_iter().next().expect("entry must exist").op_label,
        "maybe_store_pool_state",
        "registered entry must carry the op label for diagnostics",
    );

    // A subsequent call before the write completes must still be a no-op
    // (cursor already advanced, so the guard kicks in).
    fixture.processor.maybe_store_pool_state();
    assert_eq!(
        fixture.processor.database.pending_count(),
        1,
        "second call must not enqueue a duplicate write while the first is in flight",
    );

    // Drain the registry — the real RocksDB write completes within the bench
    // ManualAsyncResult-equivalent latency window. Allow a few polls for the
    // background storage thread to flush.
    for _ in 0..200 {
        fixture.processor.process_pending_async_db_results();
        if fixture.processor.database.pending_is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    assert_eq!(
        fixture.processor.database.pending_count(),
        0,
        "registry must drain after the storage thread confirms the write",
    );
    assert_eq!(
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed),
        errors_before,
        "successful pool_state persist must not bump the error counter",
    );
}

// ============================================================================
// `SessionProcessor::stop()` shutdown drain + db.sync() parity
// ============================================================================
//
// C++ parity: `validator/consensus/bridge.cpp::destroy_inner()` publishes
// `StopRequested` and then `co_await`s `bus_->db->close()`, forcing the db
// actor to drain its queued `co_await db->set(...)` tasks before the bus is
// torn down. The Rust equivalent is `SessionProcessor::stop()` which:
//   1) drains `pending_async_db_results` so any registered continuation runs
//      on SXMAIN (`drain_pending_async_db_results_for_shutdown`),
//   2) calls `db.sync(SHUTDOWN_DB_SYNC_TIMEOUT)` to flush the storage queue.

/// `stop()` must not regress when there is nothing in-flight: empty registry,
/// zero error increments, db.sync() succeeds quickly.
#[test]
fn test_stop_completes_with_empty_registry_and_no_errors() {
    let mut fixture = TestFixture::new(4);
    assert_eq!(fixture.processor.database.pending_count(), 0);
    let errors_before =
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed);

    fixture.processor.stop(false);

    assert_eq!(
        fixture.processor.database.pending_count(),
        0,
        "no entries to drain on a fresh processor",
    );
    assert_eq!(
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed),
        errors_before,
        "successful stop must not bump the error counter",
    );
}

/// When async-DB-result entries are still in flight at shutdown, `stop()` must
/// drain them on SXMAIN so registered continuations fire (matches C++
/// `co_await bus_->db->close()` semantics where queued `db->set(...)` tasks
/// complete with Ok or `cancelled` before the bus is dropped).
#[test]
fn test_stop_drains_pending_async_db_results_with_real_db() {
    let mut fixture = TestFixture::new(4);
    let errors_before =
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed);

    // Register a real RocksDB-backed write through the registry and confirm it sits
    // in the queue (not blocked on inline) before we tear the session down.
    fixture.processor.maybe_store_pool_state();
    assert_eq!(
        fixture.processor.database.pending_count(),
        1,
        "pool_state write must be queued in the registry",
    );

    fixture.processor.stop(false);

    assert_eq!(
        fixture.processor.database.pending_count(),
        0,
        "stop() must drain pending_async_db_results before returning",
    );
    assert_eq!(
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed),
        errors_before,
        "drained Ok continuation must not bump the error counter",
    );
}

/// Continuations chained by another continuation (callback inside callback) must
/// also drain — matches the in-pass chained-drain semantics of
/// `process_pending_async_db_results()` and the actor framework's drain-on-close
/// guarantee in C++.
#[test]
fn test_stop_drains_chained_continuations() {
    let mut fixture = TestFixture::new(4);
    let outer = ManualAsyncResult::pending();
    let chained = ManualAsyncResult::pending();
    chained.complete_ok();
    let chained_inner_cb = chained.clone();
    let chained_called = Arc::new(AtomicBool::new(false));
    let chained_called_for_cb = chained_called.clone();

    fixture.processor.post_async_db_result(
        "test_outer_for_stop",
        outer.clone(),
        Duration::from_secs(60),
        move |processor, _res| {
            let cb_marker = chained_called_for_cb.clone();
            processor.post_async_db_result(
                "test_chained_for_stop",
                chained_inner_cb,
                Duration::from_secs(60),
                move |_p, _r| {
                    cb_marker.store(true, Ordering::SeqCst);
                },
            );
        },
    );

    // Outer becomes ready right before stop() is called. The drain loop must
    // run the outer continuation (which schedules the chained one) and then
    // run the chained continuation in the same shutdown pass.
    outer.complete_ok();

    fixture.processor.stop(false);

    assert!(
        chained_called.load(Ordering::SeqCst),
        "chained continuation registered inside another continuation must drain on stop()",
    );
    assert_eq!(
        fixture.processor.database.pending_count(),
        0,
        "registry must be empty after stop()",
    );
}

// ============================================================================
// Cert handlers cluster: async-DB-results registry migration
// ============================================================================
//
// `handle_notarization_reached`, `handle_skip_certificate_reached`,
// `handle_finalization_reached` previously blocked SXMAIN on `result.wait()`
// to enforce wait-for-store-before-relay. They now register the persist
// in `pending_async_db_results` and run the broadcast / cache / standstill
// work from the registry continuation.
//
// C++ parity (`pool.cpp::handle_prospective_certificate`):
//   co_await owning_bus().publish<SaveCertificate>(cert);
//   handle_saved_certificate(*slot, cert);  // broadcast + cache
// The persist still gates the broadcast — same as before this migration, just
// non-blocking on SXMAIN.

/// `handle_notarization_reached` must register a `pending_async_db_results` entry,
/// defer the broadcast/cache to the continuation, and not bump the error counter
/// on the happy path.
#[test]
fn test_handle_notarization_reached_registers_async_persist_and_defers_relay() {
    let mut fixture = TestFixture::new(4);
    let errors_before =
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed);

    let slot = crate::block::SlotIndex::new(20);
    let block_hash = UInt256::rand();
    let signatures = vec![
        crate::certificate::VoteSignature::new(ValidatorIndex::new(0), vec![1]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(1), vec![2]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(2), vec![3]),
    ];
    let vote = crate::simplex_state::NotarizeVote { slot, block_hash: block_hash.clone() };
    let cert = Arc::new(crate::certificate::Certificate { vote, signatures });
    let event =
        crate::simplex_state::NotarizationReachedEvent { slot, block_hash, certificate: cert };

    fixture.drain_receiver_actions();
    fixture.processor.handle_notarization_reached(event);

    let pending_entries: Vec<_> =
        fixture.processor.database.pending_iter().map(|e| e.op_label).collect();
    assert!(
        pending_entries.contains(&"handle_notarization_reached"),
        "notarization persist must be registered in the SXMAIN async-DB-results registry, \
         got entries: {pending_entries:?}",
    );

    let actions_before_drain = fixture.drain_receiver_actions();
    assert!(
        !actions_before_drain.iter().any(|a| matches!(a, ReceiverAction::SendCertificate { .. })),
        "broadcast must be deferred to the registry continuation (not synchronous), got actions: \
         {actions_before_drain:?}",
    );

    fixture.drain_pending_async_db_results();

    let actions = fixture.drain_receiver_actions();
    assert!(
        actions.iter().any(|a| matches!(a, ReceiverAction::SendCertificate { .. })),
        "notar cert must be relayed once the registry continuation runs",
    );
    assert!(
        actions.iter().any(|a| matches!(
            a,
            ReceiverAction::CacheStandstillCertificate {
                kind: crate::receiver::StandstillCertificateType::Notar,
                ..
            }
        )),
        "notar cert standstill cache must be populated by the continuation",
    );
    assert!(
        actions.iter().any(|a| matches!(a, ReceiverAction::CacheNotarizationCert { .. })),
        "VoteSignatureSet cache must be populated by the continuation",
    );
    assert_eq!(
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed),
        errors_before,
        "successful notar persist must not bump the error counter",
    );
}

/// Same parity check for `handle_skip_certificate_reached`.
#[test]
fn test_handle_skip_certificate_reached_registers_async_persist_and_defers_relay() {
    let mut fixture = TestFixture::new(4);
    let errors_before =
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed);

    let slot = crate::block::SlotIndex::new(21);
    let signatures = vec![
        crate::certificate::VoteSignature::new(ValidatorIndex::new(0), vec![21]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(1), vec![22]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(2), vec![23]),
    ];
    let vote = crate::simplex_state::SkipVote { slot };
    let cert = Arc::new(crate::certificate::Certificate { vote, signatures });
    let event = crate::simplex_state::SkipCertificateReachedEvent { slot, certificate: cert };

    fixture.drain_receiver_actions();
    fixture.processor.handle_skip_certificate_reached(event);

    let pending_entries: Vec<_> =
        fixture.processor.database.pending_iter().map(|e| e.op_label).collect();
    assert!(
        pending_entries.contains(&"handle_skip_certificate_reached"),
        "skip cert persist must be registered in the SXMAIN async-DB-results registry, \
         got entries: {pending_entries:?}",
    );

    let actions_before_drain = fixture.drain_receiver_actions();
    assert!(
        !actions_before_drain.iter().any(|a| matches!(a, ReceiverAction::SendCertificate { .. })),
        "broadcast must be deferred to the registry continuation (not synchronous)",
    );

    fixture.drain_pending_async_db_results();

    let actions = fixture.drain_receiver_actions();
    assert!(
        actions.iter().any(|a| matches!(a, ReceiverAction::SendCertificate { .. })),
        "skip cert must be relayed once the registry continuation runs",
    );
    assert!(
        actions.iter().any(|a| matches!(
            a,
            ReceiverAction::CacheStandstillCertificate {
                kind: crate::receiver::StandstillCertificateType::Skip,
                ..
            }
        )),
        "skip cert standstill cache must be populated by the continuation",
    );
    assert_eq!(
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed),
        errors_before,
        "successful skip persist must not bump the error counter",
    );
}

/// Same parity check for `handle_finalization_reached`, which additionally caches
/// the last-final cert and runs `update_standstill_after_final_cert` from the
/// continuation.
#[test]
fn test_handle_finalization_reached_registers_async_persist_and_defers_relay() {
    let mut fixture = TestFixture::new(4);
    let errors_before =
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed);

    let slot = crate::block::SlotIndex::new(22);
    let block_hash = UInt256::rand();
    let signatures = vec![
        crate::certificate::VoteSignature::new(ValidatorIndex::new(0), vec![31]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(1), vec![32]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(2), vec![33]),
    ];
    let vote = crate::simplex_state::FinalizeVote { slot, block_hash: block_hash.clone() };
    let cert = Arc::new(crate::certificate::Certificate { vote, signatures });
    let event =
        crate::simplex_state::FinalizationReachedEvent { slot, block_hash, certificate: cert };

    fixture.drain_receiver_actions();
    fixture.processor.handle_finalization_reached(event);

    let pending_entries: Vec<_> =
        fixture.processor.database.pending_iter().map(|e| e.op_label).collect();
    assert!(
        pending_entries.contains(&"handle_finalization_reached"),
        "final cert persist must be registered in the SXMAIN async-DB-results registry, \
         got entries: {pending_entries:?}",
    );

    let actions_before_drain = fixture.drain_receiver_actions();
    assert!(
        !actions_before_drain.iter().any(|a| matches!(a, ReceiverAction::SendCertificate { .. })),
        "broadcast must be deferred to the registry continuation (not synchronous)",
    );
    assert!(
        !actions_before_drain
            .iter()
            .any(|a| matches!(a, ReceiverAction::CacheLastFinalCertificate { .. })),
        "last-final cache must be deferred to the registry continuation",
    );

    fixture.drain_pending_async_db_results();

    let actions = fixture.drain_receiver_actions();
    assert!(
        actions.iter().any(|a| matches!(a, ReceiverAction::SendCertificate { .. })),
        "final cert must be relayed once the registry continuation runs",
    );
    assert!(
        actions.iter().any(|a| matches!(
            a,
            ReceiverAction::CacheStandstillCertificate {
                kind: crate::receiver::StandstillCertificateType::Final,
                ..
            }
        )),
        "final cert standstill cache must be populated by the continuation",
    );
    assert!(
        actions.iter().any(|a| matches!(a, ReceiverAction::CacheLastFinalCertificate { .. })),
        "last-final cache must be populated by the continuation \
         (matches C++ pool.cpp::handle_typed_saved_certificate(FinalCertRef))",
    );
    assert_eq!(
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed),
        errors_before,
        "successful final persist must not bump the error counter",
    );
}

// ----------------------------------------------------------------------------
// Redundant-FSM-re-emit classification for cert handlers
// ----------------------------------------------------------------------------
//
// `handle_notarization_reached` / `handle_skip_certificate_reached` /
// `handle_finalization_reached` all keep per-slot dedup maps
// (`notar_cert_store_results`, `skip_cert_store_results`,
// `final_cert_store_results`) so a single in-flight
// `StorageAsyncResultPtr<()>` is reused across FSM re-emissions for the same
// slot. Once the first registry continuation observed the storage outcome,
// `consensus_common::StorageAsyncResultImpl::try_get()` transitions to
// `AsyncResultState::Taken` and any subsequent poll returns
// `Some(Err("StorageAsyncResult: result already taken"))`.
//
// That sentinel must be classified as a benign redundant wake:
//   * NO `increment_error()` — the first callback reported the real outcome;
//   * NO side-effects (broadcast / standstill cache / last-final cache) —
//     the first callback already executed them; replaying them would
//     double-count `certs_relayed_counter` and spam peers on every FSM re-emit.
//
// Regression for the 5x5 single-host mixed soak (Apr 25 2026, merged HEAD
// 84d0b07eb) which showed ~200-290 spurious
// "handle_notarization_reached: failed to store notar cert ... result already
// taken" ERROR lines per Rust node over ~6 minutes and a matching bump in
// `simplex_session_errors_total`.

/// `handle_notarization_reached` must treat the "result already taken"
/// sentinel as a benign redundant wake: no error-counter bump, no duplicate
/// relay or cache updates.
#[test]
fn test_handle_notarization_reached_treats_result_already_taken_as_ok() {
    let mut fixture = TestFixture::new(4);
    let errors_before =
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed);

    let slot = crate::block::SlotIndex::new(120);
    let block_hash = UInt256::rand();
    let candidate_id = RawCandidateId { slot, hash: block_hash.clone() };

    // Simulate the real dedup-map state after the first callback already
    // consumed the persist outcome: inject the typed
    // `consensus_common::StorageResultAlreadyTaken` sentinel — the same value
    // `StorageAsyncResultImpl::{try_get, wait_timeout}` emit in production.
    // This exercises the real `downcast_ref` detection path used by the
    // cert callbacks (no string matching).
    let taken = ManualAsyncResult::pending();
    taken.complete_taken_sentinel();
    fixture.processor.database.insert_notar_cert_store(candidate_id.clone(), taken);

    let signatures = vec![
        crate::certificate::VoteSignature::new(ValidatorIndex::new(0), vec![1]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(1), vec![2]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(2), vec![3]),
    ];
    let vote = crate::simplex_state::NotarizeVote { slot, block_hash: block_hash.clone() };
    let cert = Arc::new(crate::certificate::Certificate { vote, signatures });
    let event =
        crate::simplex_state::NotarizationReachedEvent { slot, block_hash, certificate: cert };

    fixture.drain_receiver_actions();
    fixture.processor.handle_notarization_reached(event);
    fixture.drain_pending_async_db_results();

    assert_eq!(
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed),
        errors_before,
        "redundant FSM re-emit (result already taken) must NOT bump the error counter",
    );
    let actions = fixture.drain_receiver_actions();
    assert!(
        !actions.iter().any(|a| matches!(a, ReceiverAction::SendCertificate { .. })),
        "redundant emit must NOT re-broadcast the notar cert, got actions: {actions:?}",
    );
    assert!(
        !actions.iter().any(|a| matches!(a, ReceiverAction::CacheNotarizationCert { .. })),
        "redundant emit must NOT re-populate the VoteSignatureSet cache, got actions: \
         {actions:?}",
    );
    assert!(
        !actions.iter().any(|a| matches!(
            a,
            ReceiverAction::CacheStandstillCertificate {
                kind: crate::receiver::StandstillCertificateType::Notar,
                ..
            }
        )),
        "redundant emit must NOT re-populate the standstill cache, got actions: {actions:?}",
    );
}

/// Same regression for `handle_skip_certificate_reached`.
#[test]
fn test_handle_skip_certificate_reached_treats_result_already_taken_as_ok() {
    let mut fixture = TestFixture::new(4);
    let errors_before =
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed);

    let slot = crate::block::SlotIndex::new(121);

    let taken = ManualAsyncResult::pending();
    taken.complete_taken_sentinel();
    fixture.processor.database.insert_skip_cert_store(slot, taken);

    let signatures = vec![
        crate::certificate::VoteSignature::new(ValidatorIndex::new(0), vec![21]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(1), vec![22]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(2), vec![23]),
    ];
    let vote = crate::simplex_state::SkipVote { slot };
    let cert = Arc::new(crate::certificate::Certificate { vote, signatures });
    let event = crate::simplex_state::SkipCertificateReachedEvent { slot, certificate: cert };

    fixture.drain_receiver_actions();
    fixture.processor.handle_skip_certificate_reached(event);
    fixture.drain_pending_async_db_results();

    assert_eq!(
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed),
        errors_before,
        "redundant FSM re-emit (result already taken) must NOT bump the error counter",
    );
    let actions = fixture.drain_receiver_actions();
    assert!(
        !actions.iter().any(|a| matches!(a, ReceiverAction::SendCertificate { .. })),
        "redundant emit must NOT re-broadcast the skip cert, got actions: {actions:?}",
    );
    assert!(
        !actions.iter().any(|a| matches!(
            a,
            ReceiverAction::CacheStandstillCertificate {
                kind: crate::receiver::StandstillCertificateType::Skip,
                ..
            }
        )),
        "redundant emit must NOT re-populate the standstill cache, got actions: {actions:?}",
    );
}

/// Same regression for `handle_finalization_reached` — also verifies the
/// last-final cache + `update_standstill_after_final_cert` side-effects are
/// suppressed on the redundant wake.
#[test]
fn test_handle_finalization_reached_treats_result_already_taken_as_ok() {
    let mut fixture = TestFixture::new(4);
    let errors_before =
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed);

    let slot = crate::block::SlotIndex::new(122);
    let block_hash = UInt256::rand();
    let candidate_id = RawCandidateId { slot, hash: block_hash.clone() };

    let taken = ManualAsyncResult::pending();
    taken.complete_taken_sentinel();
    fixture.processor.database.insert_final_cert_store(candidate_id.clone(), taken);

    let signatures = vec![
        crate::certificate::VoteSignature::new(ValidatorIndex::new(0), vec![31]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(1), vec![32]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(2), vec![33]),
    ];
    let vote = crate::simplex_state::FinalizeVote { slot, block_hash: block_hash.clone() };
    let cert = Arc::new(crate::certificate::Certificate { vote, signatures });
    let event =
        crate::simplex_state::FinalizationReachedEvent { slot, block_hash, certificate: cert };

    fixture.drain_receiver_actions();
    fixture.processor.handle_finalization_reached(event);
    fixture.drain_pending_async_db_results();

    assert_eq!(
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed),
        errors_before,
        "redundant FSM re-emit (result already taken) must NOT bump the error counter",
    );
    let actions = fixture.drain_receiver_actions();
    assert!(
        !actions.iter().any(|a| matches!(a, ReceiverAction::SendCertificate { .. })),
        "redundant emit must NOT re-broadcast the final cert, got actions: {actions:?}",
    );
    assert!(
        !actions.iter().any(|a| matches!(
            a,
            ReceiverAction::CacheStandstillCertificate {
                kind: crate::receiver::StandstillCertificateType::Final,
                ..
            }
        )),
        "redundant emit must NOT re-populate the standstill cache, got actions: {actions:?}",
    );
    assert!(
        !actions.iter().any(|a| matches!(a, ReceiverAction::CacheLastFinalCertificate { .. })),
        "redundant emit must NOT re-populate the last-final cache, got actions: {actions:?}",
    );
}

// ============================================================================
// `ensure_candidate_info_stored` migration to async-DB-results registry
// ============================================================================
//
// `process_received_notar_cert`, `process_validated_candidates`, and
// `broadcast_vote` previously blocked SXMAIN on `wait_candidate_info_stored`
// (which itself called `result.wait()`). They now use the callback-style
// `ensure_candidate_info_stored(...)` and defer their post-persist work to the
// SXMAIN async-DB-results registry continuation when a wait is still in flight.
// Either way, the same caller callback runs (Ok branch on success, Err branch
// on failure) — eliminating the inline-vs-deferred branching pattern callers
// had with the previous status-enum API.
//
// C++ parity: `consensus.cpp::try_notarize` `co_await`s `store_candidate`
// before publishing the vote; `candidate-resolver.cpp::store_candidate`
// `co_await`s the db actor. Persist-before-FSM/relay invariant preserved.

/// `broadcast_vote` (Notarize variant) must defer the network send to the
/// registry continuation when candidateInfo persist is still pending.
#[test]
fn test_broadcast_vote_defers_send_when_candidate_info_pending() {
    let h = crate::signing_coordinator::tests::Harness::custody(rtos_api::WireProfile::Legacy);
    h.description.install_coordinator(h.coordinator.clone()).unwrap();
    let mut processor =
        make_pq_processor_with_description_for_test(h.db.clone(), h.description.clone());
    let receiver = MockReceiver::new();
    processor.receiver = receiver.clone();
    let slot = SlotIndex::new(0);
    let block_hash = UInt256::rand();
    let candidate_id = RawCandidateId { slot, hash: block_hash.clone() };

    // Inject a manually-controlled pending result into the dedup map so the poll
    // returns Pending instead of Ready/NotFound.
    let pending = ManualAsyncResult::pending();
    processor.database.insert_candidate_info_store(candidate_id.clone(), pending.clone());

    let vote = crate::simplex_state::Vote::Notarize(crate::simplex_state::NotarizeVote {
        slot,
        block_hash,
    });

    receiver.drain_actions();
    processor.broadcast_vote(vote);

    let pending_entries: Vec<_> = processor.database.pending_iter().map(|e| e.op_label).collect();
    assert!(
        pending_entries.contains(&"ensure_candidate_info_stored:candidate_info"),
        "broadcast_vote(Notarize) must register a pending continuation when candidateInfo \
         is in flight, got entries: {pending_entries:?}",
    );

    let actions_before = receiver.drain_actions();
    assert!(
        !actions_before.iter().any(|a| matches!(a, ReceiverAction::SendVote { .. })),
        "vote send must be deferred to the continuation while persist is pending",
    );
    assert_eq!(h.signature_count(), 0, "nothing is signed before candidateInfo is durable");

    // Complete the persist; drain registry; verify vote is now sent.
    pending.complete_ok();
    processor.process_pending_async_db_results();

    let actions_after = receiver.drain_actions();
    assert!(
        actions_after.iter().any(|a| matches!(a, ReceiverAction::SendVote { .. })),
        "vote must be sent once the persist continuation runs",
    );
    assert_eq!(h.signature_count(), 1);
}

/// `broadcast_vote` (Notarize variant) must abort with a persist-fail bump when
/// the candidateInfo persist completes with a real error.
#[test]
fn test_broadcast_vote_aborts_when_pending_persist_completes_with_error() {
    let mut fixture = TestFixture::new(4);
    let slot = SlotIndex::new(81);
    let block_hash = UInt256::rand();
    let candidate_id = RawCandidateId { slot, hash: block_hash.clone() };

    let pending = ManualAsyncResult::pending();
    fixture.processor.database.insert_candidate_info_store(candidate_id.clone(), pending.clone());

    let vote = crate::simplex_state::Vote::Notarize(crate::simplex_state::NotarizeVote {
        slot,
        block_hash,
    });
    let persist_fail_before = metrics_counter(&fixture.processor, "simplex_votes_out_persist_fail");

    fixture.drain_receiver_actions();
    fixture.processor.broadcast_vote(vote);

    pending.complete_err("disk_unavailable");
    fixture.processor.process_pending_async_db_results();

    let actions_after = fixture.drain_receiver_actions();
    assert!(
        !actions_after.iter().any(|a| matches!(a, ReceiverAction::SendVote { .. })),
        "vote must NOT be sent when the deferred persist completes with an error",
    );
    assert_eq!(
        metrics_counter(&fixture.processor, "simplex_votes_out_persist_fail"),
        persist_fail_before + 1,
        "persist-fail counter must bump from the continuation's failure path",
    );
}

/// `process_validated_candidates` must defer the FSM feed to the registry
/// continuation when candidateInfo persist is still pending.
#[test]
fn test_process_validated_candidates_defers_feed_when_candidate_info_pending() {
    let mut fixture = TestFixture::new(4);
    let slot = SlotIndex::new(0);

    let (leader_source, candidate_id, broadcast) =
        make_signed_block_broadcast(&fixture, slot.value(), vec![5, 6, 7, 8]);
    fixture.processor.on_candidate_received(leader_source, broadcast, None);

    // Force the candidateInfo dedup-map entry to be Pending by overwriting the
    // real RocksDB-backed one with our ManualAsyncResult.
    let pending = ManualAsyncResult::pending();
    fixture.processor.database.insert_candidate_info_store(candidate_id.clone(), pending.clone());

    let now = fixture.description.get_time();
    fixture.processor.candidate_decision_ok_internal(candidate_id.clone(), slot, now);

    fixture.processor.process_validated_candidates();

    // FSM feed must be deferred — no Notarize vote has been emitted yet.
    let mut has_notarize_before = false;
    fixture.processor.simplex_state.check_all(&fixture.description);
    while let Some(event) = fixture.processor.simplex_state.pull_event() {
        if let crate::simplex_state::SimplexEvent::BroadcastVote(
            crate::simplex_state::Vote::Notarize(v),
        ) = event
        {
            if v.slot == slot {
                has_notarize_before = true;
            }
        }
    }
    assert!(
        !has_notarize_before,
        "FSM must not emit Notarize for this slot while candidateInfo persist is pending",
    );

    // Complete the persist; drain registry; verify the FSM is fed.
    pending.complete_ok();
    fixture.processor.process_pending_async_db_results();
    fixture.processor.simplex_state.check_all(&fixture.description);

    let mut has_notarize_after = false;
    while let Some(event) = fixture.processor.simplex_state.pull_event() {
        if let crate::simplex_state::SimplexEvent::BroadcastVote(
            crate::simplex_state::Vote::Notarize(v),
        ) = event
        {
            if v.slot == slot {
                has_notarize_after = true;
            }
        }
    }
    assert!(
        has_notarize_after,
        "FSM must emit Notarize for this slot once the deferred candidate is fed by the \
         registry continuation",
    );
}

/// `process_received_notar_cert` must defer the FSM feed and the
/// `retry_pending_recursive_finalization()` call to the registry continuation
/// when the notar-cert persist is still pending.
#[test]
fn test_process_received_notar_cert_defers_fsm_feed_when_persist_pending() {
    let mut fixture = TestFixture::new(4);
    let slot = SlotIndex::new(85);
    let block_hash = UInt256::rand();
    let candidate_id = RawCandidateId { slot, hash: block_hash.clone() };

    // Build a valid notar VoteSignatureSet payload + inject a pending dedup-map entry
    // for the notar-cert wait so the poll returns Pending.
    let notar_bytes = make_notar_vote_signature_set_bytes(
        fixture.processor.session_id(),
        &fixture.nodes,
        slot,
        block_hash.clone(),
        &[0, 1, 2],
    );
    let pending = ManualAsyncResult::pending();
    fixture.processor.database.insert_notar_cert_store(candidate_id.clone(), pending.clone());

    fixture.processor.process_received_notar_cert(slot, &block_hash, &notar_bytes);

    let pending_entries: Vec<_> =
        fixture.processor.database.pending_iter().map(|e| e.op_label).collect();
    assert!(
        pending_entries.contains(&"ensure_candidate_info_stored:notar_cert"),
        "process_received_notar_cert must register a pending continuation when notar-cert \
         persist is in flight, got entries: {pending_entries:?}",
    );

    // FSM feed deferred → no notar-cert recorded yet for this (slot, hash).
    assert!(
        fixture.processor.simplex_state.get_notarize_certificate(slot, &block_hash).is_none(),
        "FSM must not have the notar cert recorded while persist is pending",
    );

    pending.complete_ok();
    fixture.processor.process_pending_async_db_results();

    assert!(
        fixture.processor.simplex_state.get_notarize_certificate(slot, &block_hash).is_some(),
        "FSM must record the notar cert once the deferred continuation runs",
    );
}

// ============================================================================
// `maybe_apply_finalized_state` migration to async-DB-results registry
// ============================================================================
//
// Pre-migration the masterchain branch blocked SXMAIN on
// `save_finalized_block_async().wait()` to gate the local apply on durability.
// It now hands the in-flight write to the SXMAIN async-DB-results registry via
// `post_async_db_result(...)` and applies the local state immediately —
// matching C++ `state-resolver.cpp::do_finalize_blocks` where `co_await
// FinalizeBlock` (callback) runs before `co_await db->set(...)` (persist).
//
// Sync-Err registration (`save_finalized_block_async()` returns Err
// synchronously) still returns `false` and leaves in-memory state untouched —
// see `test_finalized_callback_not_emitted_when_finalized_record_persist_fails`
// for that path.

/// Masterchain `maybe_apply_finalized_state` must register an async-DB-results
/// entry, apply local state inline, and return `true` so the recursive walk
/// continues. The persist outcome is reported from the registry continuation.
#[test]
fn test_maybe_apply_finalized_state_registers_async_persist_on_masterchain() {
    let mut fixture = TestFixture::new(4);
    assert!(
        fixture.description.get_shard().is_masterchain(),
        "TestFixture must run on masterchain to exercise the async persist path",
    );

    let (_leader, candidate_id, broadcast) =
        make_signed_block_broadcast(&fixture, 200, vec![0xaa, 0xbb, 0xcc]);
    fixture.processor.on_candidate_received(_leader, broadcast, None);

    let pending_before = fixture.processor.database.pending_count();
    let errors_before =
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed);

    let applied = fixture.processor.maybe_apply_finalized_state(&candidate_id, true);
    assert!(applied, "successful registration must return true");

    let pending_entries: Vec<_> =
        fixture.processor.database.pending_iter().map(|e| e.op_label).collect();
    assert!(
        pending_entries.contains(&"maybe_apply_finalized_state"),
        "MC persist must be registered in the SXMAIN async-DB-results registry, \
         got entries: {pending_entries:?}",
    );
    assert_eq!(
        fixture.processor.database.pending_count(),
        pending_before + 1,
        "exactly one new registry entry must be added per call",
    );
    assert!(
        fixture.processor.consensus.is_finalized_block(&candidate_id),
        "in-memory state must be applied inline (matches C++ callback-before-persist)",
    );
    assert_eq!(
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed),
        errors_before,
        "happy-path registration must not bump the error counter",
    );

    fixture.drain_pending_async_db_results();
    fixture.processor.database.db().sync(Some(Duration::from_secs(2))).expect("sync must succeed");

    assert!(
        fixture
            .processor
            .database
            .db()
            .load_finalized_blocks()
            .expect("finalized records load must succeed")
            .iter()
            .any(|record| record.candidate_id == candidate_id),
        "finalized record must be durable in DB after registry drain + db.sync",
    );
    assert_eq!(
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed),
        errors_before,
        "successful async persist must not bump the error counter from the continuation",
    );
}

/// Async persist failure (continuation observes `Err`) must bump the session
/// error counter. The in-memory state was already applied inline; the
/// `finalized_blocks` dedup keeps the candidate from being retried.
#[test]
fn test_maybe_apply_finalized_state_async_persist_failure_increments_error_counter() {
    let mut fixture = TestFixture::new(4);
    let candidate_id = RawCandidateId { slot: SlotIndex::new(201), hash: UInt256::rand() };

    // Pre-seed a `candidate_book` entry the function expects (slot/seqno
    // bookkeeping) — minimal real candidate is enough; the test doesn't exercise
    // the FSM, only the registry plumbing.
    let (_leader, real_id, broadcast) =
        make_signed_block_broadcast(&fixture, 201, vec![0x11, 0x22, 0x33]);
    fixture.processor.on_candidate_received(_leader, broadcast, None);

    let errors_before =
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed);

    let applied = fixture.processor.maybe_apply_finalized_state(&real_id, true);
    assert!(applied, "registration must succeed (synchronous step)");
    assert!(
        fixture.processor.consensus.is_finalized_block(&real_id),
        "in-memory state is applied inline regardless of eventual persist outcome",
    );

    // Swap the registered registry entry's `result` with a manually-failed one
    // to simulate the storage thread reporting Err for this write — without
    // having to inject a deterministic disk failure into RocksDB.
    let real_entry_idx = fixture
        .processor
        .database
        .pending_iter()
        .position(|e| e.op_label == "maybe_apply_finalized_state")
        .expect("the MC persist must be registered before we can simulate its failure");
    let failed = ManualAsyncResult::pending();
    failed.complete_err("simulated_disk_failure");
    fixture
        .processor
        .database
        .pending_iter_mut()
        .nth(real_entry_idx)
        .expect("entry must exist after position lookup")
        .result = failed.clone();

    fixture.processor.process_pending_async_db_results();

    assert_eq!(
        fixture
            .processor
            .database
            .pending_iter()
            .filter(|e| e.op_label == "maybe_apply_finalized_state")
            .count(),
        0,
        "async-Err path must remove the entry from the registry",
    );
    let errors_after =
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        errors_after > errors_before,
        "async persist failure must bump the session error counter from the continuation \
         (matches `increment_error()` in the Ok/Err match arm)",
    );
    assert!(
        fixture.processor.consensus.is_finalized_block(&real_id),
        "in-memory state must NOT be rolled back on async-Err (matches the migration design)",
    );

    // Silence unused-variable warning on `candidate_id` — used here as a guard
    // against accidental reuse of the same id across the two test cases above.
    let _ = candidate_id;
}

// Snapshot builders for `SessionTelemetry`
//
// Each builder produces a neutral, owned snapshot that the telemetry aspect
// will consume read-only in later commits. Tests assert that the builders
// project the right `SessionProcessor` private state into snapshot fields.
// ============================================================================

#[test]
fn build_health_check_snapshot_projects_dynamic_state() {
    let mut fixture = TestFixture::new(3);
    fixture.processor.runtime.force_active_weight(2);
    fixture.processor.consensus.set_finalized_head_slot(Some(SlotIndex(11)));

    let snapshot = fixture.processor.build_health_check_snapshot();

    assert_eq!(snapshot.active_weight, 2);
    assert_eq!(snapshot.finalized_head_slot, Some(SlotIndex(11)));
    // No peer activity yet — every peer (except self) is "never seen".
    let other_peers = fixture.processor.runtime.description().get_total_nodes() - 1;
    assert_eq!(snapshot.peers_never_seen, other_peers);
    // First-non-finalized/first-non-progressed default to slot 0 at session
    // start (no FSM activity).
    assert_eq!(snapshot.first_non_finalized, SlotIndex(0));
    assert_eq!(snapshot.first_non_progressed, SlotIndex(0));
}

#[test]
fn build_consensus_state_snapshot_carries_trigger_and_counts() {
    let fixture = TestFixture::new(3);

    let snapshot = fixture.processor.build_consensus_state_snapshot("check_all");

    assert_eq!(snapshot.trigger, "check_all");
    assert_eq!(snapshot.pending_validations_count, 0);
    assert_eq!(snapshot.validated_count, 0);
    assert!(!snapshot.generated);
    assert!(!snapshot.pending_generate);
}

#[test]
fn build_validation_inventory_snapshot_returns_empty_buckets_for_clean_session() {
    let fixture = TestFixture::new(3);
    let snapshot = fixture.processor.build_validation_inventory_snapshot(SystemTime::now());

    assert_eq!(snapshot.totals.received_total, 0);
    assert!(snapshot.received.is_empty());
    assert!(snapshot.validated.is_empty());
    assert!(snapshot.notarized.is_empty());
    assert!(snapshot.finalized.is_empty());
}

#[test]
fn build_dump_status_snapshot_uses_processor_clock() {
    let mut fixture = TestFixture::new(3);
    let base_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    fixture.processor.set_time(base_time);
    fixture.processor.runtime.force_active_weight(3);
    fixture.processor.consensus.set_finalized_head_seqno(Some(42));

    let snapshot = fixture.processor.build_dump_status_snapshot();

    assert_eq!(snapshot.observed_at, base_time);
    assert_eq!(snapshot.active_weight, 3);
    assert_eq!(snapshot.finalized_head_seqno, Some(42));
}

#[test]
fn build_full_dump_snapshot_includes_all_scalar_heads() {
    let mut fixture = TestFixture::new(3);
    fixture.processor.consensus.set_finalized_head_seqno(Some(99));
    fixture.processor.consensus.set_last_consensus_finalized_seqno(Some(98));
    fixture.processor.consensus.set_accepted_normal_head_seqno(100);
    fixture.processor.consensus.set_last_mc_finalized_seqno(Some(50));

    let now = SystemTime::now();
    let snapshot = fixture.processor.build_full_dump_snapshot(now, /* is_stalled */ false);

    assert_eq!(snapshot.last_consensus_finalized_seqno, Some(98));
    assert_eq!(snapshot.accepted_normal_head_seqno, 100);
    assert_eq!(snapshot.last_mc_finalized_seqno, Some(50));
    assert_eq!(snapshot.pending_validations_count, 0);
    assert_eq!(snapshot.approved_count, 0);
    assert_eq!(snapshot.rejected_count, 0);
    assert_eq!(snapshot.precollated_count, 0);
    assert_eq!(snapshot.generated_waiting_validation_count, 0);
    // No stall ⇒ no standstill dump output.
    assert!(snapshot.standstill_diagnostic_dump.is_none());
}

#[test]
fn build_full_dump_snapshot_skips_standstill_dump_when_not_stalled() {
    let fixture = TestFixture::new(3);
    let snapshot =
        fixture.processor.build_full_dump_snapshot(SystemTime::now(), /* is_stalled */ false);
    assert!(snapshot.standstill_diagnostic_dump.is_none());
}

// ============================================================================
// `SessionProcessor::stop()` — close()/destroy_db wiring
// ============================================================================
//
// These tests assert the shutdown contract the migrated session paths rely on:
//
// * `stop(false)` flips `db.is_closed()` so any post-stop continuation that
//   tries to enqueue a write fails fast with `DB_CLOSED_ERROR` (C++ parity:
//   `bus_->db->close()` sets `key_value_ = {}` in `KeyValueAsync::close()`).
// * `stop(true)` additionally calls `db.mark_for_destroy()` so the on-disk
//   DB is removed when the last `Arc<SimplexDb>` drops (C++ parity:
//   `td::RocksDb::destroy(db_path() + "/db/") + td::rmrf(db_path())`).
// * `stop()` is idempotent — calling it a second time short-circuits with no
//   new error-counter bumps.

#[test]
fn test_stop_flips_db_is_closed_gate() {
    let mut fixture = TestFixture::new(4);
    assert!(
        !fixture.processor.database.db().is_closed(),
        "pre-condition: db must be open at fixture creation"
    );

    fixture.processor.stop(false);

    assert!(
        fixture.processor.database.db().is_closed(),
        "stop() must flip db.is_closed() so late continuations fail fast",
    );
}

#[test]
fn test_stop_without_destroy_does_not_mark_for_destroy() {
    let mut fixture = TestFixture::new(4);
    let db_path = fixture.processor.database.db().get_path().to_path_buf();
    assert!(db_path.exists(), "DB directory must exist at fixture creation");

    // Keep a clone so we can observe the path after SessionProcessor is consumed.
    let db_clone = fixture.processor.database.db().clone();
    fixture.processor.stop(false);

    // Drop the SessionProcessor's Arc reference (simulates session tear-down).
    drop(fixture);
    // One Arc remains (db_clone) — path must still exist (no mark_for_destroy()).
    assert!(db_path.exists(), "stop(destroy_db=false) must NOT remove the DB directory",);
    drop(db_clone);

    // After the last Arc drops, the DB thread's Drop still runs. Give that
    // teardown a brief window; because mark_for_destroy was NOT called it must
    // not remove the directory. A short fixed wait is enough to catch an
    // erroneous async removal without padding the suite with a multi-second
    // sleep.
    std::thread::sleep(Duration::from_millis(200));
    assert!(db_path.exists(), "DB directory must persist across drop when destroy_db=false",);

    // Cleanup so we don't leak temp DBs.
    let _ = std::fs::remove_dir_all(&db_path);
}

#[test]
fn test_stop_with_destroy_db_removes_directory() {
    let mut fixture = TestFixture::new(4);
    let db_path = fixture.processor.database.db().get_path().to_path_buf();
    assert!(db_path.exists(), "pre-condition: DB directory must exist");

    fixture.processor.stop(true);

    // Drop the session processor — the DB thread runs its cleanup on the
    // mark_for_destroy path.
    drop(fixture);

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if !db_path.exists() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "DB directory {} must be removed after stop(destroy_db=true)+drop",
                db_path.display()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn test_stop_is_idempotent_and_does_not_double_increment_errors() {
    let mut fixture = TestFixture::new(4);
    let errors_before =
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed);

    fixture.processor.stop(false);
    let errors_after_first =
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        errors_after_first, errors_before,
        "first stop() on a quiescent processor must not bump the error counter",
    );

    // Second stop() must not panic and must short-circuit. `db.close()` is
    // idempotent: the second call short-circuits to Ok(()) (it does NOT return
    // DB_CLOSED_ERROR), so a clean double-stop should not record a new storage
    // error. Assert the counter moved by AT MOST 1 to lock that contract while
    // tolerating a single incidental teardown bump.
    fixture.processor.stop(false);
    let errors_after_second =
        fixture.processor.telemetry.session_errors_count.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        errors_after_second <= errors_after_first + 1,
        "double-stop must increment the error counter by at most 1 (observed {} -> {})",
        errors_after_first,
        errors_after_second,
    );
    assert!(
        fixture.processor.database.db().is_closed(),
        "db must remain closed across double-stop",
    );
}

#[test]
fn pq_live_controller_retains_full_signatures_and_role() {
    use crate::pq_fixture as f;
    let fixture = TestFixture::new(2);
    for version in [0, 1] {
        for kind in ["empty", "ordinary", "shard_empty", "shard_ordinary"] {
            let description = f::description(f::block_id(kind).shard().clone(), version);
            assert!(description
                .get_legacy_signing_key()
                .unwrap_err()
                .to_string()
                .contains("Disabled"));
            let controller = crate::consensus_controller::ConsensusController::new(
                fixture.processor.callbacks.clone(),
                description.clone(),
                fixture.processor.telemetry.clone(),
                None,
                None,
                None,
                41,
                None,
            );
            for (role, is_final) in [("finalize", true), ("notarize", false)] {
                let signatures: Vec<_> = (0..2)
                    .map(|i| {
                        (
                            description.get_source_public_key_hash(ValidatorIndex::new(i)).clone(),
                            consensus_common::ConsensusCommonFactory::create_block_payload(
                                f::bytes(&f::row(kind, role, i as usize, f::CONTEXT), "signature"),
                            ),
                        )
                    })
                    .collect();
                let data = f::bytes(&f::row(kind, role, 0, f::CONTEXT), "candidate");
                let result = controller.build_finality_for_test(
                    &signatures,
                    SlotIndex::new(99),
                    data.clone(),
                    is_final,
                );
                if !is_final && f::block_id(kind).shard().is_masterchain() {
                    assert!(result.is_err());
                    continue;
                }
                match result.unwrap() {
                    consensus_common::SessionFinality::Carrier(
                        BlockSignaturesVariant::SimplexPq(carrier),
                    ) => {
                        assert!(is_final);
                        assert_eq!(carrier.signatures[0].signature.len(), 2420);
                        assert_eq!(carrier.sig_weight, 3);
                        description
                            .pq_context()
                            .unwrap()
                            .for_block(f::block_id(kind))
                            .unwrap()
                            .verify_final(&carrier)
                            .unwrap();
                    }
                    consensus_common::SessionFinality::PqApproval(approval) => {
                        assert!(!is_final);
                        description
                            .pq_context()
                            .unwrap()
                            .for_block(f::block_id(kind))
                            .unwrap()
                            .verify_approval(&approval)
                            .unwrap();
                    }
                    _ => panic!("PQ finality downgraded"),
                }
                assert!(controller
                    .build_finality_for_test(
                        &signatures,
                        SlotIndex::new(99),
                        data.clone(),
                        !is_final
                    )
                    .is_err());
                assert!(controller
                    .build_finality_for_test(
                        &signatures[..1],
                        SlotIndex::new(99),
                        data.clone(),
                        is_final
                    )
                    .is_err());
                assert!(controller
                    .build_finality_for_test(
                        &[signatures[0].clone(), signatures[0].clone()],
                        SlotIndex::new(99),
                        data,
                        is_final
                    )
                    .is_err());
            }
        }
    }
    assert!(SessionOptions { proto_version: 2, ..Default::default() }.validate().is_err());
}

fn make_pq_processor_for_test(db: crate::database::SimplexDbPtr) -> SessionProcessor {
    make_pq_processor_with_description_for_test(
        db,
        crate::pq_fixture::description(ShardIdent::masterchain(), 0),
    )
}
fn make_pq_processor_with_description_for_test(
    db: crate::database::SimplexDbPtr,
    description: Arc<SessionDescription>,
) -> SessionProcessor {
    let listener: Arc<dyn consensus_common::SessionListener + Send + Sync> = Arc::new(MockListener);
    let stop = Arc::new(AtomicBool::new(false));
    let callbacks = Arc::new(crate::session_callbacks::SessionCallbacks::new(
        description.get_session_id().clone(),
        stop.clone(),
        false,
        Arc::new(TestCallbackQueue),
        Arc::downgrade(&listener),
    ));
    SessionProcessor::new(
        description.clone(),
        make_start_prev_blocks(description.get_shard(), description.get_initial_block_seqno()),
        TestTaskQueue::new(),
        MockReceiver::new(),
        stop,
        db,
        0,
        Arc::new(crate::receiver::ReceiverHealthCounters::new()),
        callbacks,
        None,
        7,
    )
    .unwrap()
}
#[test]
fn pq_live_processor_candidate_persistence_and_authenticated_recovery() {
    use crate::pq_fixture as f;
    let path =
        std::env::temp_dir().join(format!("rtos-pq-processor-{}", UInt256::rand().to_hex_string()));
    let db = crate::database::SimplexDb::open(&path, "pq-test").unwrap();
    let candidate = rtos_api::ton::consensus::candidatedata::Empty {
        slot: 99,
        parent: TlCandidateId { slot: 98, hash: UInt256::from([5; 32]) }.into_boxed(),
        block: f::block_id("empty"),
        signature: f::bytes(&f::row("empty", "candidate", 1, f::CONTEXT), "signature"),
    }
    .into_boxed();
    let expected = serialize_boxed(&candidate).unwrap();
    let mut processor = make_pq_processor_for_test(db.clone());
    processor.on_candidate_received(1, candidate, None);
    db.sync(Some(Duration::from_secs(10))).unwrap();
    let id =
        crate::block::RawCandidateId { slot: SlotIndex::new(99), hash: f::candidate_hash("empty") };
    assert_eq!(
        db.load_candidate_payload_by_id(&id, Duration::from_secs(10)).unwrap().unwrap(),
        expected
    );
    let metadata = db.load_candidate_info_by_id(&id, Duration::from_secs(10)).unwrap().unwrap();
    assert_eq!(metadata.signature.len(), 2420);
    assert_eq!(metadata.leader_idx, 1);
    drop(processor);
    db.close(Some(Duration::from_secs(10))).unwrap();
    drop(db);
    let db = crate::database::SimplexDb::open(&path, "pq-test").unwrap();
    let bootstrap = db.load_bootstrap().unwrap();
    assert_eq!(bootstrap.candidate_payloads.len(), 1);
    let mut restored = make_pq_processor_for_test(db.clone());
    let description = f::description(ShardIdent::masterchain(), 0);
    crate::startup_recovery::SessionStartupRecoveryProcessor::new(
        f::session(),
        description.clone(),
        bootstrap.clone(),
    )
    .apply_bootstrap(&mut restored)
    .unwrap();
    assert!(
        !restored.runtime.is_generated(SlotIndex::new(99)),
        "restored peer candidate must not fence our local production slot"
    );
    for alteration in 0..3 {
        let mut bad = bootstrap.clone();
        match alteration {
            0 => bad.candidate_infos[0].signature[0] ^= 1,
            1 => bad.candidate_infos[0].leader_idx = 0,
            _ => bad.candidate_payloads[0].0.hash = UInt256::from([33; 32]),
        }
        let mut target = make_pq_processor_for_test(db.clone());
        assert!(crate::startup_recovery::SessionStartupRecoveryProcessor::new(
            f::session(),
            description.clone(),
            bad
        )
        .apply_bootstrap(&mut target)
        .is_err());
        assert!(
            !target.runtime.is_generated(SlotIndex::new(99)),
            "unauthenticated payload or metadata cannot set a local production fence"
        );
    }
    drop(restored);
    db.close(Some(Duration::from_secs(10))).unwrap();
    drop(db);
    std::fs::remove_dir_all(path).unwrap();
}
#[test]
fn pq_live_recovery_rejects_vote_context_and_member_before_application() {
    use crate::pq_fixture as f;
    for (index, context) in [(0, f::CONTEXT), (0, "TOS-AUTH-ML-DSA-44-v1"), (2, f::CONTEXT)] {
        let vote = f::vote("empty", "notarize", 0, context);
        let data = serialize_boxed(&vote).unwrap();
        let mut bootstrap = crate::database::Bootstrap::default();
        bootstrap.votes.push(crate::database::VoteRecord {
            vote_hash: UInt256::calc_file_hash(&data),
            data,
            node_idx: ValidatorIndex::new(index),
            seqno: 0,
        });
        let db = MockDb::new();
        let mut target = make_pq_processor_for_test(db);
        let result = crate::startup_recovery::SessionStartupRecoveryProcessor::new(
            f::session(),
            f::description(ShardIdent::masterchain(), 0),
            bootstrap,
        )
        .apply_bootstrap(&mut target);
        assert_eq!(result.is_ok(), index == 0 && context == f::CONTEXT, "{result:?}");
    }
}

#[test]
fn pq_live_recovery_requires_finality_before_any_state_mutation() {
    use crate::{
        database::{
            Bootstrap, CandidateInfoRecord, FinalCertRecord, FinalizedBlockRecord, NotarCertRecord,
            SkipCertRecord,
        },
        pq_fixture as f,
    };
    let id = crate::block::RawCandidateId {
        slot: SlotIndex::new(99),
        hash: f::candidate_hash("ordinary"),
    };
    let data = f::bytes(&f::row("ordinary", "candidate", 1, f::CONTEXT), "candidate");
    let candidate_hash_data = rtos_api::deserialize_typed(&data).unwrap();
    let info = CandidateInfoRecord {
        candidate_id: id.clone(),
        leader_idx: 1,
        candidate_hash_data,
        signature: f::bytes(&f::row("ordinary", "candidate", 1, f::CONTEXT), "signature"),
    };
    let parent = match &info.candidate_hash_data {
        rtos_api::ton::consensus::CandidateHashData::Consensus_CandidateHashDataOrdinary(data) => {
            match &data.parent {
                rtos_api::ton::consensus::CandidateParent::Consensus_CandidateParent(parent) => {
                    Some(crate::block::RawCandidateId {
                        slot: SlotIndex::new(*parent.id.slot() as u32),
                        hash: parent.id.hash().clone(),
                    })
                }
                _ => None,
            }
        }
        _ => unreachable!(),
    };
    let mut valid = Bootstrap::default();
    valid.candidate_infos.push(info);
    valid.finalized_blocks.push(FinalizedBlockRecord {
        candidate_id: id.clone(),
        block_id: f::block_id("ordinary"),
        parent,
        is_final: true,
    });
    let certificate = |role: &str, context: &str| {
        serialize_boxed(
            &rtos_api::ton::consensus::simplex::certificate::Certificate {
                vote: f::vote("ordinary", role, 0, context).vote().clone(),
                signatures: f::signatures("ordinary", role, context),
            }
            .into_boxed(),
        )
        .unwrap()
    };
    valid.final_certs.push(FinalCertRecord {
        candidate_id: id.clone(),
        cert_bytes: certificate("finalize", f::CONTEXT),
    });
    for alteration in 0..6 {
        let mut bootstrap = valid.clone();
        match alteration {
            0 => {}
            1 => bootstrap.final_certs.clear(),
            2 => bootstrap.final_certs[0].cert_bytes = certificate("notarize", f::CONTEXT),
            3 => {
                bootstrap.final_certs[0].cert_bytes =
                    certificate("finalize", "TOS-AUTH-ML-DSA-44-v1")
            }
            4 => bootstrap
                .skip_certs
                .push(SkipCertRecord { slot: SlotIndex::new(99), cert_bytes: vec![0] }),
            _ => bootstrap
                .notar_certs
                .push(NotarCertRecord { candidate_id: id.clone(), notar_cert_bytes: vec![0] }),
        }
        let mut target = make_pq_processor_for_test(MockDb::new());
        let before = target.simplex_state.get_first_non_finalized_slot();
        let result = crate::startup_recovery::SessionStartupRecoveryProcessor::new(
            f::session(),
            f::description(ShardIdent::masterchain(), 0),
            bootstrap,
        )
        .apply_bootstrap(&mut target);
        assert_eq!(result.is_ok(), alteration == 0, "alteration {alteration}: {result:?}");
        if alteration != 0 {
            assert_eq!(target.simplex_state.get_first_non_finalized_slot(), before);
            assert!(crate::startup_recovery::StartupRecoveryBackend::candidate_book(&target)
                .received(&id)
                .is_none());
        }
    }
}

#[test]
fn pq_live_session_stops_on_invalid_recovery_record() {
    use crate::pq_fixture as f;
    let path =
        std::env::temp_dir().join(format!("rtos-pq-startup-{}", UInt256::rand().to_hex_string()));
    let db = crate::database::SimplexDb::open(&path, &f::session().to_hex_string()).unwrap();
    let data = serialize_boxed(&f::vote("empty", "notarize", 0, "TOS-AUTH-ML-DSA-44-v1")).unwrap();
    db.save_vote_async(&crate::database::VoteRecord {
        vote_hash: UInt256::calc_file_hash(&data),
        data,
        node_idx: ValidatorIndex::new(0),
        seqno: 0,
    })
    .unwrap()
    .wait()
    .unwrap();
    db.close(Some(Duration::from_secs(10))).unwrap();
    drop(db);
    let listener = RecordingListener::new();
    let dyn_listener: Arc<dyn consensus_common::SessionListener + Send + Sync> = listener.clone();
    let (nodes, keys) = f::members();
    let session = crate::SessionFactory::create_session(
        &SessionOptions {
            wait_for_db_init: true,
            use_callback_thread: false,
            ..Default::default()
        },
        &f::session(),
        &ShardIdent::masterchain(),
        nodes,
        &keys[0],
        path.to_str().unwrap().to_owned(),
        crate::SessionFactory::create_in_process_overlay_manager(1),
        Arc::downgrade(&dyn_listener),
        None,
        7,
    );
    assert!(session.is_err(), "invalid PQ recovery must fail before overlay registration");
    assert_eq!(listener.event_count(), 0);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let db = loop {
        match crate::database::SimplexDb::open(&path, &f::session().to_hex_string()) {
            Ok(db) => break db,
            Err(error) if std::time::Instant::now() < deadline => {
                let _ = error;
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("stopped session retained DB: {error}"),
        }
    };
    let bootstrap = db.load_bootstrap().unwrap();
    assert_eq!(bootstrap.votes.len(), 1, "failed recovery must not sign/persist additional votes");
    assert!(bootstrap.finalized_blocks.is_empty());
    assert!(bootstrap.candidate_infos.is_empty());
    db.close(Some(Duration::from_secs(10))).unwrap();
    drop(db);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn pq_live_recovery_authenticates_finalized_parent_chains_and_role_flags() {
    use crate::{
        database::{
            Bootstrap, CandidateInfoRecord, FinalCertRecord, FinalizedBlockRecord, NotarCertRecord,
        },
        pq_fixture as f,
    };
    use rtos_api::ton::consensus::simplex::{
        certificate::Certificate, unsignedvote::FinalizeVote, votesignature::VoteSignature,
        votesignatureset::VoteSignatureSet,
    };
    let data: serde_json::Value =
        serde_json::from_str(include_str!("../../../../tl/rtos_api/tests/data/live-pq-chain.json"))
            .unwrap();
    let row = |kind: &str, role: &str, index: usize| {
        data["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["kind"] == kind && r["role"] == role && r["index"] == index)
            .unwrap()
    };
    let info = |kind: &str, slot: u32| {
        let r = row(kind, "candidate", (slot % 2) as usize);
        let bytes = f::bytes(r, "candidate");
        CandidateInfoRecord {
            candidate_id: crate::block::RawCandidateId {
                slot: SlotIndex::new(slot),
                hash: UInt256::calc_file_hash(&bytes),
            },
            leader_idx: slot % 2,
            candidate_hash_data: rtos_api::deserialize_typed(&bytes).unwrap(),
            signature: f::bytes(r, "signature"),
        }
    };
    let signatures = |kind: &str, role: &str, count: usize| {
        VoteSignatureSet {
            votes: (0..count)
                .map(|i| {
                    VoteSignature {
                        who: i as i32,
                        signature: f::bytes(row(kind, role, i), "signature"),
                    }
                    .into_boxed()
                })
                .collect(),
        }
        .into_boxed()
    };
    for kind in ["empty", "ordinary"] {
        let parent = info("parent", 98);
        let child = info(kind, 99);
        let mut valid = Bootstrap::default();
        valid.candidate_infos = vec![parent.clone(), child.clone()];
        valid.finalized_blocks = vec![
            FinalizedBlockRecord {
                candidate_id: parent.candidate_id.clone(),
                block_id: parent.candidate_hash_data.block().clone(),
                parent: None,
                is_final: kind == "empty",
            },
            FinalizedBlockRecord {
                candidate_id: child.candidate_id.clone(),
                block_id: child.candidate_hash_data.block().clone(),
                parent: Some(parent.candidate_id.clone()),
                is_final: true,
            },
        ];
        valid.notar_certs.push(NotarCertRecord {
            candidate_id: parent.candidate_id.clone(),
            notar_cert_bytes: serialize_boxed(&signatures("parent", "notarize", 2)).unwrap(),
        });
        let final_cert = |proof_kind: &str, id: &crate::block::RawCandidateId, count| {
            serialize_boxed(
                &Certificate {
                    vote: FinalizeVote {
                        id: TlCandidateId { slot: 99, hash: id.hash.clone() }.into_boxed(),
                    }
                    .into_boxed(),
                    signatures: signatures(proof_kind, "finalize", count),
                }
                .into_boxed(),
            )
            .unwrap()
        };
        valid.final_certs.push(FinalCertRecord {
            candidate_id: child.candidate_id.clone(),
            cert_bytes: final_cert(kind, &child.candidate_id, 2),
        });
        for alteration in 0..13 {
            let mut bootstrap = valid.clone();
            match alteration {
                0 => {}
                1 => bootstrap.final_certs.clear(),
                2 => bootstrap.notar_certs.clear(),
                3 => bootstrap.final_certs[0].cert_bytes = final_cert(kind, &child.candidate_id, 1),
                4 => bootstrap.finalized_blocks[0].is_final = true,
                5 => bootstrap.final_certs[0].cert_bytes.push(0),
                6 => {
                    bootstrap.finalized_blocks.remove(0);
                }
                7 => {
                    bootstrap.finalized_blocks.remove(0);
                    bootstrap.candidate_infos.remove(0);
                }
                8 => {
                    bootstrap.finalized_blocks.remove(0);
                    bootstrap.notar_certs.clear();
                }
                10..=12 => {
                    bootstrap.finalized_blocks.remove(0);
                    bootstrap.notar_certs.clear();
                    // Reconstruct a missing ancestor NotarCert from the real
                    // stored PQ votes; duplicate low-weight votes cannot add weight.
                    for index in if alteration == 11 { vec![0, 0] } else { vec![0, 1] } {
                        let signed = TlVote {
                            vote: rtos_api::ton::consensus::simplex::unsignedvote::NotarizeVote {
                                id: TlCandidateId {
                                    slot: 98,
                                    hash: parent.candidate_id.hash.clone(),
                                }
                                .into_boxed(),
                            }
                            .into_boxed(),
                            signature: f::bytes(row("parent", "notarize", index), "signature"),
                        }
                        .into_boxed();
                        let mut data = serialize_boxed(&signed).unwrap();
                        if alteration == 12 {
                            *data.last_mut().unwrap() ^= 1;
                        }
                        bootstrap.votes.push(crate::database::VoteRecord {
                            vote_hash: UInt256::calc_file_hash(&data),
                            data,
                            node_idx: ValidatorIndex::new(index as u32),
                            seqno: index as i64,
                        });
                    }
                }
                _ => {
                    let sibling_kind = if kind == "empty" { "ordinary" } else { "empty" };
                    let sibling = info(sibling_kind, 99);
                    bootstrap.finalized_blocks.push(FinalizedBlockRecord {
                        candidate_id: sibling.candidate_id.clone(),
                        block_id: sibling.candidate_hash_data.block().clone(),
                        parent: Some(parent.candidate_id.clone()),
                        is_final: true,
                    });
                    bootstrap.final_certs.push(FinalCertRecord {
                        candidate_id: sibling.candidate_id.clone(),
                        cert_bytes: final_cert(sibling_kind, &sibling.candidate_id, 2),
                    });
                    bootstrap.candidate_infos.push(sibling);
                }
            }
            let description = f::description(parent.candidate_hash_data.block().shard().clone(), 0);
            let mut target =
                make_pq_processor_with_description_for_test(MockDb::new(), description.clone());
            let before = target.simplex_state.get_first_non_finalized_slot();
            let result = crate::startup_recovery::SessionStartupRecoveryProcessor::new(
                f::session(),
                description,
                bootstrap,
            )
            .apply_bootstrap(&mut target);
            let succeeds = alteration == 0
                || alteration == 6
                || alteration == 10
                || (alteration == 4 && kind == "empty");
            assert_eq!(result.is_ok(), succeeds, "{kind}/{alteration}: {result:?}");
            let expected = match alteration {
                7 => Some("finalized ancestor metadata missing"),
                8 => Some("finalized ancestor lacks authenticated finality"),
                9 => Some("disconnected finalized chain"),
                _ => None,
            };
            if let Some(expected) = expected {
                assert!(result.as_ref().unwrap_err().to_string().contains(expected), "{result:?}");
            }
            if !succeeds {
                assert_eq!(target.simplex_state.get_first_non_finalized_slot(), before);
            }
        }
    }
}

/// A failed PQ bootstrap must never even attempt network registration. Returning
/// an error also bounds a regression: the test cannot leave a live session behind.
struct RejectBootstrapOverlay(std::sync::atomic::AtomicUsize);
impl consensus_common::ConsensusOverlayManager for RejectBootstrapOverlay {
    fn start_overlay(
        &self,
        _key: &consensus_common::PrivateKey,
        _id: &Arc<adnl::PrivateOverlayShortId>,
        _nodes: &[consensus_common::ConsensusNode],
        _listener: consensus_common::ConsensusOverlayListenerPtr,
        _replay: consensus_common::ConsensusOverlayLogReplayListenerPtr,
        _transport: consensus_common::OverlayTransportType,
        _sync: Option<consensus_common::BlockSyncOverlayParams>,
    ) -> rtos_block::Result<consensus_common::ConsensusOverlayPtr> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(rtos_block::error!("unexpected overlay registration after corrupt PQ bootstrap"))
    }
    fn stop_overlay(
        &self,
        _id: &Arc<adnl::PrivateOverlayShortId>,
        _overlay: &consensus_common::ConsensusOverlayPtr,
    ) {
    }
}

#[test]
fn pq_live_session_rejects_raw_corruption_before_overlay_or_replay() {
    use crate::pq_fixture as f;
    use consensus_common::{AsyncKeyValueStorageOptions, ConsensusCommonFactory};
    use rtos_api::ton::consensus::{
        candidateparent::CandidateParent,
        simplex::{
            certificate::Certificate,
            db::{self, key},
        },
    };
    let candidate_id = || TlCandidateId { slot: 99, hash: f::candidate_hash("empty") };
    let vote = serialize_boxed(&f::vote("empty", "notarize", 0, f::CONTEXT)).unwrap();
    let certificate = Certificate {
        vote: f::vote("empty", "finalize", 0, f::CONTEXT).vote().clone(),
        signatures: f::signatures("empty", "finalize", f::CONTEXT),
    };
    let cert_bytes = serialize_boxed(&certificate.clone().into_boxed()).unwrap();
    let vote_key = |data: &[u8]| {
        serialize_boxed(&key::vote::Vote { vote_hash: UInt256::calc_file_hash(data) }.into_boxed())
            .unwrap()
    };
    let finalized_key = serialize_boxed(
        &key::finalizedblock::FinalizedBlock { candidateId: candidate_id() }.into_boxed(),
    )
    .unwrap();
    let finalized = |parent| {
        serialize_boxed(
            &db::finalizedblock::FinalizedBlock {
                block_id: f::block_id("empty"),
                parent,
                is_final: rtos_api::ton::Bool::BoolTrue,
            }
            .into_boxed(),
        )
        .unwrap()
    };
    let info_row = f::row("empty", "candidate", 1, f::CONTEXT);
    let info = rtos_api::deserialize_typed(&f::bytes(&info_row, "candidate")).unwrap();
    let payload = serialize_boxed(
        &rtos_api::ton::consensus::candidatedata::Empty {
            slot: 99,
            parent: TlCandidateId { slot: 98, hash: UInt256::from([5; 32]) }.into_boxed(),
            block: f::block_id("empty"),
            signature: f::bytes(&info_row, "signature"),
        }
        .into_boxed(),
    )
    .unwrap();
    let templates = vec![
        (
            "vote",
            vote_key(&vote),
            serialize_boxed(&db::vote::Vote { data: vote, node_idx: 0, seqno: 0 }.into_boxed())
                .unwrap(),
        ),
        (
            "certificate",
            vote_key(&cert_bytes),
            serialize_boxed(&db::vote::Cert { cert: certificate }.into_boxed()).unwrap(),
        ),
        (
            "candidate_info",
            serialize_boxed(
                &key::candidate_resolver::candidateinfo::CandidateInfo {
                    candidateId: candidate_id(),
                }
                .into_boxed(),
            )
            .unwrap(),
            serialize_boxed(
                &db::candidate_resolver::candidateinfo::CandidateInfo {
                    leader_id: 1,
                    candidate_hash_data: info,
                    signature: f::bytes(&info_row, "signature"),
                }
                .into_boxed(),
            )
            .unwrap(),
        ),
        (
            "finalized",
            finalized_key.clone(),
            finalized(rtos_api::ton::consensus::CandidateParent::Consensus_CandidateWithoutParents),
        ),
        (
            "pool",
            serialize_boxed(&key::PoolState::default()).unwrap(),
            serialize_boxed(
                &db::poolstate::PoolState { first_nonannounced_window: 0 }.into_boxed(),
            )
            .unwrap(),
        ),
        (
            "payload",
            serialize_boxed(
                &key::candidate::Candidate { candidateId: candidate_id() }.into_boxed(),
            )
            .unwrap(),
            payload,
        ),
    ];
    let mut cases = Vec::new();
    cases.push(("valid_vote".into(), templates[0].1.clone(), templates[0].2.clone()));
    cases.push(("valid_payload".into(), templates[5].1.clone(), templates[5].2.clone()));
    for (name, key, value) in &templates[..2] {
        let mut wrong_key = key.clone();
        *wrong_key.last_mut().unwrap() ^= 1;
        cases.push((format!("{name}/wrong_key_hash"), wrong_key, value.clone()));
    }
    for (name, key, value) in templates {
        for mutation in ["truncated_key", "key_suffix", "truncated_value", "value_suffix"] {
            let (mut key, mut value) = (key.clone(), value.clone());
            match mutation {
                "truncated_key" => key.truncate(4),
                "key_suffix" => key.push(0x99),
                "truncated_value" => value.truncate(1),
                _ => value.push(0x99),
            }
            // The pool singleton has no key body; a four-byte key is valid.
            if name == "pool" && mutation == "truncated_key" {
                continue;
            }
            cases.push((format!("{name}/{mutation}"), key, value));
        }
    }
    cases.push((
        "filtered_finalized_parent".into(),
        finalized_key,
        finalized(
            CandidateParent {
                id: TlCandidateId { slot: 98, hash: UInt256::from([5; 32]) }.into_boxed(),
            }
            .into_boxed(),
        ),
    ));
    cases.push(("unknown_key".into(), vec![0x42; 4], vec![0]));
    cases.push(("short_key".into(), vec![0x42], vec![0]));
    for version in [0, 1] {
        for (name, key, value) in &cases {
            let path = std::env::temp_dir()
                .join(format!("rtos-pq-strict-{}", UInt256::rand().to_hex_string()));
            let open_storage = || {
                ConsensusCommonFactory::create_async_key_value_storage(
                    &path,
                    &f::session().to_hex_string(),
                    AsyncKeyValueStorageOptions { use_callback_thread: false },
                )
            };
            let storage = open_storage().unwrap();
            storage.set(key.clone(), value.clone(), None).wait().unwrap();
            storage.sync(Some(Duration::from_secs(10))).unwrap();
            let before = storage.get_by_prefix(Vec::new(), None).wait().unwrap();
            storage.close(Some(Duration::from_secs(10))).unwrap();
            drop(storage);
            let listener = RecordingListener::new();
            let dyn_listener: Arc<dyn consensus_common::SessionListener + Send + Sync> =
                listener.clone();
            let overlay = Arc::new(RejectBootstrapOverlay(std::sync::atomic::AtomicUsize::new(0)));
            let (nodes, keys) = f::members();
            let result = crate::SessionFactory::create_session(
                &SessionOptions {
                    wait_for_db_init: true,
                    use_callback_thread: false,
                    proto_version: version,
                    ..Default::default()
                },
                &f::session(),
                &ShardIdent::masterchain(),
                nodes,
                &keys[0],
                path.to_str().unwrap().to_owned(),
                overlay.clone(),
                Arc::downgrade(&dyn_listener),
                None,
                7,
            );
            assert!(result.is_err(), "v{version} {name}: corrupt bootstrap started");
            assert_eq!(
                overlay.0.load(std::sync::atomic::Ordering::SeqCst),
                usize::from(name.starts_with("valid_")),
                "v{version} {name}: unexpected overlay registration count"
            );
            assert_eq!(listener.event_count(), 0, "v{version} {name}: listener called");
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let storage = loop {
                match open_storage() {
                    Ok(storage) => break storage,
                    Err(_) if std::time::Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(20))
                    }
                    Err(e) => panic!("v{version} {name}: stopped session retained database: {e}"),
                }
            };
            assert_eq!(
                storage.get_by_prefix(Vec::new(), None).wait().unwrap(),
                before,
                "v{version} {name}: failed recovery changed database"
            );
            storage.close(Some(Duration::from_secs(10))).unwrap();
            drop(storage);
            std::fs::remove_dir_all(path).unwrap();
        }
    }
}

#[test]
fn own_journal_real_vote_controller_and_recovery() {
    use crate::signing_coordinator::tests::{vote, Harness};
    for stage in [
        None,
        Some("before_intent"),
        Some("after_intent"),
        Some("before_sign"),
        Some("after_sign"),
        Some("before_signed"),
        Some("after_signed"),
    ] {
        let h = Harness::new();
        h.description.install_coordinator(h.coordinator.clone()).unwrap();
        *h.coordinator.fail_at.lock().unwrap() = stage;
        let mut processor =
            make_pq_processor_with_description_for_test(h.db.clone(), h.description.clone());
        let receiver = MockReceiver::new();
        processor.receiver = receiver.clone();
        processor.with_consensus_backend(|controller, backend| {
            controller.broadcast_vote_after_persist(backend, vote("notarize"))
        });
        let sent: Vec<_> = receiver
            .drain_actions()
            .into_iter()
            .filter_map(|a| match a {
                ReceiverAction::SendVote { vote } => {
                    Some(serialize_boxed(&vote.into_boxed()).unwrap())
                }
                _ => None,
            })
            .collect();
        assert_eq!(sent.len(), usize::from(stage.is_none()), "{stage:?}");
        if stage.is_none() {
            let durable =
                h.db.storage
                    .get_by_prefix(crate::signing_coordinator::PREFIX.to_vec(), None)
                    .wait()
                    .unwrap();
            h.coordinator.verify_bootstrap(&durable).unwrap();
            processor.with_consensus_backend(|controller, backend| {
                controller.broadcast_vote_after_persist(backend, vote("notarize"))
            });
            let again: Vec<_> = receiver
                .drain_actions()
                .into_iter()
                .filter_map(|a| match a {
                    ReceiverAction::SendVote { vote } => {
                        Some(serialize_boxed(&vote.into_boxed()).unwrap())
                    }
                    _ => None,
                })
                .collect();
            // The vote was applied locally on its first cast; a repeated cast
            // releases the committed bytes but local accounting reports a
            // duplicate, so nothing is published again and nothing is signed.
            assert!(again.is_empty(), "an already applied own vote is not published again");
            assert_eq!(sent.len(), 1);
            assert_eq!(h.calls.load(Ordering::SeqCst), 1);
        }
    }
    // Intent-only startup resumes the exact old decision and enters the actual
    // recovery FSM/cache path without an initial broadcast.
    for intent_only in [false, true] {
        let mut h = Harness::new();
        if intent_only {
            *h.coordinator.fail_at.lock().unwrap() = Some("after_intent");
        }
        let result = h.coordinator.vote(&vote("notarize"));
        assert_eq!(result.is_err(), intent_only);
        h = h.reopen();
        h.description.install_coordinator(h.coordinator.clone()).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let bootstrap =
            h.db.load_pq_bootstrap_cancellable(&cancel, Duration::from_millis(10)).unwrap();
        let mut target =
            make_pq_processor_with_description_for_test(h.db.clone(), h.description.clone());
        let receiver = MockReceiver::new();
        target.receiver = receiver.clone();
        crate::startup_recovery::SessionStartupRecoveryProcessor::new(
            crate::pq_fixture::session(),
            h.description.clone(),
            bootstrap,
        )
        .apply_bootstrap(&mut target)
        .unwrap();
        let actions = receiver.drain_actions();
        assert!(
            !actions.iter().any(|a| matches!(
                a,
                ReceiverAction::SendVote { .. } | ReceiverAction::SendBlockBroadcast { .. }
            )),
            "recovery must not initially publish"
        );
        let cached: Vec<_> = actions
            .iter()
            .filter_map(|a| match a {
                ReceiverAction::CacheOurVoteForStandstill { vote } => {
                    Some(serialize_boxed(&vote.clone().into_boxed()).unwrap())
                }
                _ => None,
            })
            .collect();
        let exact = serialize_boxed(&crate::pq_fixture::vote(
            "empty",
            "notarize",
            1,
            crate::pq_fixture::CONTEXT,
        ))
        .unwrap();
        assert_eq!(
            cached,
            vec![exact],
            "recover the exact durable vote into the actual standstill cache"
        );
        assert_eq!(h.calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn own_journal_real_candidate_recovery_uses_durable_carrier() {
    use crate::signing_coordinator::tests::{empty, full, Harness};
    for profile in [rtos_api::WireProfile::Legacy, rtos_api::WireProfile::T0] {
        for candidate in [empty(), full()] {
            for intent_only in [false, true] {
                let h = Harness::new_with_profile(profile);
                if intent_only {
                    *h.coordinator.fail_at.lock().unwrap() = Some("after_intent");
                }
                let signed = h.coordinator.candidate(candidate.clone());
                assert_eq!(signed.is_err(), intent_only);
                let h = h.reopen();
                h.description.install_coordinator(h.coordinator.clone()).unwrap();
                let cancel = Arc::new(AtomicBool::new(false));
                let bootstrap =
                    h.db.load_pq_bootstrap_cancellable(&cancel, Duration::from_millis(10)).unwrap();
                assert!(
                    bootstrap.candidate_infos.is_empty() && bootstrap.candidate_payloads.is_empty(),
                    "journal must be sufficient without peer caches"
                );
                let mut target = make_pq_processor_with_description_for_test(
                    h.db.clone(),
                    h.description.clone(),
                );
                let receiver = MockReceiver::new();
                target.receiver = receiver.clone();
                crate::startup_recovery::SessionStartupRecoveryProcessor::new(
                    crate::pq_fixture::session(),
                    h.description.clone(),
                    bootstrap,
                )
                .apply_bootstrap(&mut target)
                .unwrap();
                let actions = receiver.drain_actions();
                assert!(
                    !actions.iter().any(|a| matches!(
                        a,
                        ReceiverAction::SendVote { .. } | ReceiverAction::SendBlockBroadcast { .. }
                    )),
                    "startup must not publish a recovered candidate"
                );
                let restored = h.coordinator.candidate(candidate.clone()).unwrap();
                let empty = matches!(candidate, CandidateData::Consensus_Empty(_));
                let hash = if empty {
                    crate::pq_fixture::candidate_hash("empty")
                } else {
                    // Fixed canonical full-candidate ID covered by the public signature fixture.
                    UInt256::from_slice(
                        &hex::decode(
                            "e159212aac1dbb99e8c9d5c143881582bb50bc6acfad45e48e023c17b24101a5",
                        )
                        .unwrap(),
                    )
                };
                let cached: Vec<_> = actions
                    .iter()
                    .filter_map(|a| match a {
                        ReceiverAction::CacheCandidateBytes {
                            slot,
                            block_hash,
                            candidate_data,
                        } => Some((*slot, block_hash.clone(), candidate_data.clone())),
                        _ => None,
                    })
                    .collect();
                assert_eq!(
                    cached,
                    vec![(99, hash.clone(), profile.serialize(&restored).unwrap())],
                    "actual receiver must restore exact durable carrier bytes"
                );
                let id =
                    crate::block::RawCandidateId { slot: SlotIndex::new(99), hash: hash.clone() };
                let received = target
                    .candidate
                    .book()
                    .received(&id)
                    .expect("actual candidate book must receive recovered metadata");
                assert_eq!(UInt256::calc_file_hash(&received.candidate_hash_data_bytes), hash);
                assert_eq!(received.source_idx, ValidatorIndex::new(1));
                assert_eq!(received.is_empty, empty);
                assert_eq!(received.block_id.seq_no, 42);
                assert_eq!(
                    received.block_id.root_hash,
                    crate::pq_fixture::block_id("empty").root_hash
                );
                let parent = if empty {
                    Some(crate::block::RawCandidateId {
                        slot: SlotIndex::new(98),
                        hash: UInt256::from([5; 32]),
                    })
                } else {
                    None
                };
                assert_eq!(received.parent_id, parent);
                if let Ok(original) = signed {
                    assert_eq!(
                        profile.serialize(&original).unwrap(),
                        profile.serialize(&restored).unwrap()
                    );
                }
                assert_eq!(h.calls.load(Ordering::SeqCst), 1);
            }
        }
    }
}

/// Hold the real DB worker inside a callback. Simplex disables the separate
/// callback thread, so subsequent storage operations remain queued until release.
struct TestDbWorkerGate {
    release: Option<std::sync::mpsc::Sender<()>>,
    expired: Arc<AtomicBool>,
}

impl TestDbWorkerGate {
    fn hold(fixture: &TestFixture) -> Self {
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let expired = Arc::new(AtomicBool::new(false));
        let worker_expired = expired.clone();
        fixture.processor.database.db().storage.get(
            b"test-worker-gate".to_vec(),
            Some(Box::new(move |result| {
                let _ = entered_tx.send(result.is_ok());
                if release_rx.recv_timeout(TEST_DB_WATCHDOG).is_err() {
                    worker_expired.store(true, Ordering::SeqCst);
                }
            })),
        );
        assert!(entered_rx
            .recv_timeout(TEST_DB_WATCHDOG)
            .expect("DB worker must enter the callback"));
        Self { release: Some(release_tx), expired }
    }
    fn release(mut self) {
        assert!(!self.expired.load(Ordering::SeqCst), "DB worker gate watchdog expired");
        self.release.take().unwrap().send(()).expect("DB worker must still await release");
    }
}

impl Drop for TestDbWorkerGate {
    fn drop(&mut self) {
        // Release on assertion unwind too, before the fixture drops and joins DB.
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

fn queued_notar_event(slot: SlotIndex) -> crate::simplex_state::NotarizationReachedEvent {
    let block_hash = UInt256::rand();
    let signatures = (0..3)
        .map(|i| crate::certificate::VoteSignature::new(ValidatorIndex::new(i), vec![i as u8]))
        .collect();
    let vote = crate::simplex_state::NotarizeVote { slot, block_hash: block_hash.clone() };
    let certificate = Arc::new(crate::certificate::Certificate { vote, signatures });
    crate::simplex_state::NotarizationReachedEvent { slot, block_hash, certificate }
}

#[test]
fn test_real_db_worker_completion_gates_notar_relay() {
    let mut fixture = TestFixture::new(4);
    fixture.processor.set_time(fixture.processor.now());
    let gate = TestDbWorkerGate::hold(&fixture);
    fixture.processor.handle_notarization_reached(queued_notar_event(SlotIndex::new(230)));
    fixture.processor.process_pending_async_db_results();
    assert_eq!(fixture.processor.database.pending_count(), 1);
    assert!(fixture
        .drain_receiver_actions()
        .iter()
        .all(|a| !matches!(a, ReceiverAction::SendCertificate { .. })));
    gate.release();
    fixture.drain_pending_async_db_results();
    assert_eq!(
        fixture
            .drain_receiver_actions()
            .iter()
            .filter(|a| matches!(a, ReceiverAction::SendCertificate { .. }))
            .count(),
        1
    );
    assert!(!fixture
        .processor
        .database
        .db()
        .load_notar_certs_async()
        .wait_timeout(TEST_DB_WATCHDOG)
        .expect("DB read watchdog expired")
        .unwrap()
        .is_empty());
    fixture.processor.process_pending_async_db_results();
    assert!(fixture.drain_receiver_actions().is_empty());
}

#[test]
fn test_real_db_worker_late_completion_does_not_bypass_deadline() {
    let mut fixture = TestFixture::new(4);
    fixture.processor.set_time(fixture.processor.now());
    let gate = TestDbWorkerGate::hold(&fixture);
    let errors_before = fixture.processor.telemetry.session_errors_count.load(Ordering::Relaxed);
    fixture.processor.handle_notarization_reached(queued_notar_event(SlotIndex::new(231)));
    fixture.processor.process_pending_async_db_results();
    assert_eq!(fixture.processor.database.pending_count(), 1);
    fixture.advance_time(DEFAULT_ASYNC_DB_WRITE_TIMEOUT + Duration::from_secs(1));
    fixture.processor.process_pending_async_db_results();
    assert!(fixture.processor.database.pending_is_empty());
    assert_eq!(
        fixture.processor.telemetry.session_errors_count.load(Ordering::Relaxed),
        errors_before + 1
    );
    assert!(fixture
        .drain_receiver_actions()
        .iter()
        .all(|a| !matches!(a, ReceiverAction::SendCertificate { .. })));
    gate.release();
    fixture.processor.database.db().sync(Some(TEST_DB_WATCHDOG)).unwrap();
    // A timeout does not cancel an already queued write. Its eventual durability
    // must not revive the expired continuation or authorize a late relay.
    assert!(!fixture
        .processor
        .database
        .db()
        .load_notar_certs_async()
        .wait_timeout(TEST_DB_WATCHDOG)
        .expect("DB read watchdog expired")
        .unwrap()
        .is_empty());
    fixture.processor.process_pending_async_db_results();
    assert!(fixture
        .drain_receiver_actions()
        .iter()
        .all(|a| !matches!(a, ReceiverAction::SendCertificate { .. })));
}

#[test]
#[should_panic(expected = "storage barrier did not complete registered DB result")]
fn test_db_completion_drain_rejects_uncompleted_manual_result() {
    let mut fixture = TestFixture::new(4);
    fixture.processor.post_async_db_result(
        "uncompleted_manual_result",
        ManualAsyncResult::pending(),
        DEFAULT_ASYNC_DB_WRITE_TIMEOUT,
        |_, _| panic!("uncompleted manual result must not run its continuation"),
    );
    fixture.drain_pending_async_db_results();
}

#[test]
fn test_db_completion_drain_waits_for_chained_real_writes() {
    let mut fixture = TestFixture::new(4);
    let completed = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let count = completed.clone();
    let result =
        fixture.processor.database.db().storage.set(b"test-first-write".to_vec(), vec![1], None);
    fixture.processor.post_async_db_result(
        "first_real_write",
        result,
        DEFAULT_ASYNC_DB_WRITE_TIMEOUT,
        move |processor, result| {
            result.unwrap();
            count.fetch_add(1, Ordering::Relaxed);
            let next =
                processor.database.db().storage.set(b"test-second-write".to_vec(), vec![2], None);
            processor.post_async_db_result(
                "second_real_write",
                next,
                DEFAULT_ASYNC_DB_WRITE_TIMEOUT,
                move |_, result| {
                    result.unwrap();
                    count.fetch_add(1, Ordering::Relaxed);
                },
            );
        },
    );
    fixture.drain_pending_async_db_results();
    assert_eq!(completed.load(Ordering::Relaxed), 2);
    assert!(fixture.processor.database.pending_is_empty());
}

#[test]
fn test_db_completion_drain_preserves_real_storage_error() {
    let mut fixture = TestFixture::new(4);
    fixture.processor.database.db().close(Some(TEST_DB_WATCHDOG)).unwrap();
    let result =
        fixture.processor.database.db().storage.set(b"closed-db-write".to_vec(), vec![1], None);
    let failed = Arc::new(AtomicBool::new(false));
    let observed = failed.clone();
    fixture.processor.post_async_db_result(
        "closed_db_write",
        result,
        DEFAULT_ASYNC_DB_WRITE_TIMEOUT,
        move |_, result| {
            assert!(result.unwrap_err().to_string().contains("closed"));
            observed.store(true, Ordering::SeqCst);
        },
    );
    fixture.drain_pending_async_db_results();
    assert!(failed.load(Ordering::SeqCst));
    assert!(fixture.processor.database.pending_is_empty());
}

#[test]
fn test_db_completion_watchdog_reports_blocked_worker_without_relay() {
    let mut fixture = TestFixture::new(4);
    fixture.processor.set_time(fixture.processor.now());
    let gate = TestDbWorkerGate::hold(&fixture);
    fixture.processor.handle_notarization_reached(queued_notar_event(SlotIndex::new(232)));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fixture.drain_pending_async_db_results_with_watchdog(Duration::from_millis(100));
    }));
    let panic = outcome.expect_err("a blocked DB worker must trip the diagnostic watchdog");
    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .unwrap_or("");
    assert!(message.contains("DB completion barrier failed"), "unexpected panic: {message}");
    assert_eq!(fixture.processor.database.pending_count(), 1);
    assert!(fixture
        .drain_receiver_actions()
        .iter()
        .all(|a| !matches!(a, ReceiverAction::SendCertificate { .. })));
    // The diagnostic did not complete or discard the production result. Releasing
    // the worker makes it observable and permits the original continuation once.
    gate.release();
    fixture.drain_pending_async_db_results();
    assert_eq!(
        fixture
            .drain_receiver_actions()
            .iter()
            .filter(|a| matches!(a, ReceiverAction::SendCertificate { .. }))
            .count(),
        1
    );
}

#[test]
fn custody_real_vote_controller_and_recovery() {
    use crate::signing_coordinator::tests::{vote, Harness};
    for role in ["notarize", "finalize", "skip"] {
        for stage in [
            None,
            Some("before_intent"),
            Some("after_intent"),
            Some("before_sign"),
            Some("after_sign"),
            Some("before_signed"),
            Some("after_signed"),
        ] {
            let h = Harness::custody(rtos_api::WireProfile::T0);
            h.description.install_coordinator(h.coordinator.clone()).unwrap();
            *h.coordinator.fail_at.lock().unwrap() = stage;
            let mut processor =
                make_pq_processor_with_description_for_test(h.db.clone(), h.description.clone());
            let receiver = MockReceiver::new();
            processor.receiver = receiver.clone();
            processor.with_consensus_backend(|controller, backend| {
                controller.broadcast_vote_after_persist(backend, vote(role))
            });
            let sent: Vec<_> = receiver
                .drain_actions()
                .into_iter()
                .filter_map(|a| match a {
                    ReceiverAction::SendVote { vote } => {
                        Some(serialize_boxed(&vote.into_boxed()).unwrap())
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(sent.len(), usize::from(stage.is_none()), "{stage:?}");
            if stage.is_none() {
                let durable =
                    h.db.storage
                        .get_by_prefix(crate::signing_coordinator::PREFIX.to_vec(), None)
                        .wait()
                        .unwrap();
                h.coordinator.verify_bootstrap(&durable).unwrap();
                processor.with_consensus_backend(|controller, backend| {
                    controller.broadcast_vote_after_persist(backend, vote(role))
                });
                let again: Vec<_> = receiver
                    .drain_actions()
                    .into_iter()
                    .filter_map(|a| match a {
                        ReceiverAction::SendVote { vote } => {
                            Some(serialize_boxed(&vote.into_boxed()).unwrap())
                        }
                        _ => None,
                    })
                    .collect();
                assert!(again.is_empty(), "an already applied own vote is not published again");
                assert_eq!(sent.len(), 1);
                assert_eq!(h.signature_count(), 1);
            }
        }
        // Intent-only startup resumes the exact old decision and enters the actual
        // recovery FSM/cache path without an initial broadcast.
        for intent_only in [false, true] {
            let mut h = Harness::custody(rtos_api::WireProfile::T0);
            if intent_only {
                *h.coordinator.fail_at.lock().unwrap() = Some("after_intent");
            }
            let result = h.coordinator.vote(&vote(role));
            assert_eq!(result.is_err(), intent_only);
            h = h.reopen();
            h.description.install_coordinator(h.coordinator.clone()).unwrap();
            let cancel = Arc::new(AtomicBool::new(false));
            let bootstrap =
                h.db.load_pq_bootstrap_cancellable(&cancel, Duration::from_millis(10)).unwrap();
            let mut target =
                make_pq_processor_with_description_for_test(h.db.clone(), h.description.clone());
            let receiver = MockReceiver::new();
            target.receiver = receiver.clone();
            crate::startup_recovery::SessionStartupRecoveryProcessor::new(
                crate::pq_fixture::session(),
                h.description.clone(),
                bootstrap,
            )
            .apply_bootstrap(&mut target)
            .unwrap();
            let actions = receiver.drain_actions();
            assert!(
                !actions.iter().any(|a| matches!(
                    a,
                    ReceiverAction::SendVote { .. } | ReceiverAction::SendBlockBroadcast { .. }
                )),
                "recovery must not initially publish"
            );
            let cached: Vec<_> = actions
                .iter()
                .filter_map(|a| match a {
                    ReceiverAction::CacheOurVoteForStandstill { vote } => {
                        Some(serialize_boxed(&vote.clone().into_boxed()).unwrap())
                    }
                    _ => None,
                })
                .collect();
            let exact =
                serialize_boxed(&h.coordinator.vote(&vote(role)).unwrap().into_boxed()).unwrap();
            assert_eq!(
                cached,
                vec![exact],
                "recover the exact durable vote into the actual standstill cache"
            );
            assert_eq!(h.signature_count(), 1);
        }
    }
}

#[test]
fn custody_real_candidate_recovery_uses_durable_carrier() {
    use crate::signing_coordinator::tests::{empty, full, Harness};
    for profile in [rtos_api::WireProfile::Legacy, rtos_api::WireProfile::T0] {
        for candidate in [empty(), full()] {
            for intent_only in [false, true] {
                let h = Harness::custody(profile);
                if intent_only {
                    *h.coordinator.fail_at.lock().unwrap() = Some("after_intent");
                }
                let signed = h.coordinator.candidate(candidate.clone());
                assert_eq!(signed.is_err(), intent_only);
                let h = h.reopen();
                h.description.install_coordinator(h.coordinator.clone()).unwrap();
                let cancel = Arc::new(AtomicBool::new(false));
                let bootstrap =
                    h.db.load_pq_bootstrap_cancellable(&cancel, Duration::from_millis(10)).unwrap();
                assert!(
                    bootstrap.candidate_infos.is_empty() && bootstrap.candidate_payloads.is_empty(),
                    "journal must be sufficient without peer caches"
                );
                let mut target = make_pq_processor_with_description_for_test(
                    h.db.clone(),
                    h.description.clone(),
                );
                let receiver = MockReceiver::new();
                target.receiver = receiver.clone();
                crate::startup_recovery::SessionStartupRecoveryProcessor::new(
                    crate::pq_fixture::session(),
                    h.description.clone(),
                    bootstrap,
                )
                .apply_bootstrap(&mut target)
                .unwrap();
                assert!(
                    target.runtime.is_generated(SlotIndex::new(99)),
                    "restored durable own candidate must fence re-collation of its slot"
                );
                assert!(
                    !target.runtime.is_sent_generated(SlotIndex::new(99)),
                    "recovery must not manufacture evidence of network publication"
                );
                let actions = receiver.drain_actions();
                assert!(
                    !actions.iter().any(|a| matches!(
                        a,
                        ReceiverAction::SendVote { .. } | ReceiverAction::SendBlockBroadcast { .. }
                    )),
                    "startup must not publish a recovered candidate"
                );
                let restored = h.coordinator.candidate(candidate.clone()).unwrap();
                let empty = matches!(candidate, CandidateData::Consensus_Empty(_));
                let hash = if empty {
                    crate::pq_fixture::candidate_hash("empty")
                } else {
                    // Fixed canonical full-candidate ID covered by the public signature fixture.
                    UInt256::from_slice(
                        &hex::decode(
                            "e159212aac1dbb99e8c9d5c143881582bb50bc6acfad45e48e023c17b24101a5",
                        )
                        .unwrap(),
                    )
                };
                let cached: Vec<_> = actions
                    .iter()
                    .filter_map(|a| match a {
                        ReceiverAction::CacheCandidateBytes {
                            slot,
                            block_hash,
                            candidate_data,
                        } => Some((*slot, block_hash.clone(), candidate_data.clone())),
                        _ => None,
                    })
                    .collect();
                assert_eq!(
                    cached,
                    vec![(99, hash.clone(), profile.serialize(&restored).unwrap())],
                    "actual receiver must restore exact durable carrier bytes"
                );
                let id =
                    crate::block::RawCandidateId { slot: SlotIndex::new(99), hash: hash.clone() };
                let received = target
                    .candidate
                    .book()
                    .received(&id)
                    .expect("actual candidate book must receive recovered metadata");
                assert_eq!(UInt256::calc_file_hash(&received.candidate_hash_data_bytes), hash);
                assert_eq!(received.source_idx, ValidatorIndex::new(1));
                assert_eq!(received.is_empty, empty);
                assert_eq!(received.block_id.seq_no, 42);
                assert_eq!(
                    received.block_id.root_hash,
                    crate::pq_fixture::block_id("empty").root_hash
                );
                let parent = if empty {
                    Some(crate::block::RawCandidateId {
                        slot: SlotIndex::new(98),
                        hash: UInt256::from([5; 32]),
                    })
                } else {
                    None
                };
                assert_eq!(received.parent_id, parent);
                if let Ok(original) = signed {
                    assert_eq!(
                        profile.serialize(&original).unwrap(),
                        profile.serialize(&restored).unwrap()
                    );
                }
                assert_eq!(h.signature_count(), 1);
            }
        }
    }
}

#[test]
fn custody_retired_backend_stops_real_vote_publication() {
    use crate::signing_coordinator::tests::{vote, Harness};
    let h = Harness::custody_with_key(rtos_api::WireProfile::T0, [0xa7; 32], 4_000_000_000);
    h.description.install_coordinator(h.coordinator.clone()).unwrap();
    let mut processor =
        make_pq_processor_with_description_for_test(h.db.clone(), h.description.clone());
    let receiver = MockReceiver::new();
    processor.receiver = receiver.clone();
    // Custody observes its own actual deadline after capability installation.
    // The coordinator's wall clock remains valid; the real backend must refuse.
    assert!(h.store.as_ref().unwrap().expired_at(4_000_000_000));
    for role in ["notarize", "finalize", "skip"] {
        processor.with_consensus_backend(|controller, backend| {
            controller.broadcast_vote_after_persist(backend, vote(role));
        });
    }
    assert!(receiver
        .drain_actions()
        .iter()
        .all(|action| !matches!(action, ReceiverAction::SendVote { .. })));
    assert_eq!(h.signature_count(), 0);
    assert!(h.store.as_ref().unwrap().signatures_refused_after_expiry() > 0);
    assert!(
        h.coordinator.vote(&vote("notarize")).is_err(),
        "backend failure must poison subsequent signing"
    );
}

#[test]
fn authenticated_observer_processor_accepts_only_valid_pq_quorum_without_signing() {
    let directory = crate::authenticated_fixture::TestDirectory::new();
    let stores: Vec<_> = [0xa1, 0xa2]
        .into_iter()
        .map(|seed| rtos_pq_consensus::ConsensusKeyStore::from_seed(&[seed; 32], 0).unwrap())
        .collect();
    let (_, keys) = crate::pq_fixture::members();
    let members = stores
        .iter()
        .enumerate()
        .map(|(index, store)| {
            rtos_block::ValidatorDescr::with_pq_params(
                UInt256::from([index as u8 + 1; 32]),
                store.consensus_key().clone(),
                index as u64 + 1,
                UInt256::from(*keys[index].id().data()),
            )
        })
        .collect();
    let observer = Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[0x71; 32]).unwrap();
    let (runtime, transport, options) =
        crate::authenticated_fixture::runtime_with_members(members, observer);
    let nodes = runtime
        .committee()
        .iter()
        .map(crate::SimplexSessionNode::from_descriptor)
        .collect::<Result<Vec<_>>>()
        .unwrap();
    let description = Arc::new(
        SessionDescription::new_with_runtime(
            &options,
            runtime.session_id().clone(),
            1,
            &nodes,
            transport,
            runtime.shard(),
            SystemTime::now(),
            None,
            Some(&runtime),
        )
        .unwrap()
        .bind_pq_session(runtime.catchain_seqno())
        .unwrap(),
    );
    assert!(description.local_validator_index().is_none());
    let db =
        crate::database::SimplexDb::open(directory.path().join("db"), "observer-cert").unwrap();
    let receiver = MockReceiver::new();
    let mut processor = make_pq_processor_with_description_for_test(db.clone(), description);
    processor.receiver = receiver.clone();
    let make_certificate_at = |slot: u32, session: &SessionId, signers: &[usize], corrupt: bool| {
        let vote = SkipVote { slot: slot as i32 }.into_boxed();
        let preimage = crate::utils::create_data_to_sign(
            session,
            &crate::utils::serialize_unsigned_vote(&vote),
        );
        let signatures = signers
            .iter()
            .map(|&index| {
                let mut signature = stores[index].sign_consensus(&preimage).unwrap().bytes.to_vec();
                if corrupt {
                    signature[0] ^= 1;
                }
                VoteSignature { who: index as i32, signature }.into_boxed()
            })
            .collect();
        Certificate { vote, signatures: VoteSignatureSet { votes: signatures }.into_boxed() }
            .into_boxed()
    };
    let make_certificate = |session: &SessionId, signers: &[usize], corrupt: bool| {
        make_certificate_at(0, session, signers, corrupt)
    };
    let boundary = processor.simplex_state.first_too_new_vote_slot().value();
    let boundary_cert = make_certificate_at(boundary, runtime.session_id(), &[0, 1], false);
    let invalid = [
        make_certificate(runtime.session_id(), &[0], false), // weight 1 < quorum 2
        make_certificate(runtime.session_id(), &[0, 0], false), // duplicate cannot add weight
        make_certificate(&UInt256::from([0xff; 32]), &[0, 1], false),
        make_certificate(runtime.session_id(), &[0, 1], true),
    ];
    let valid = make_certificate(runtime.session_id(), &[0, 1], false);
    let queued_duplicate = make_certificate(&UInt256::from([0xff; 32]), &[0, 1], false);
    let calls: Vec<_> = stores.iter().map(|store| store.consensus_signatures_produced()).collect();
    receiver.drain_actions();
    processor.on_certificate(None::<u32>, boundary_cert);
    assert!(!processor.simplex_state.has_skip_certificate(SlotIndex::new(boundary)));
    assert!(db
        .load_skip_cert_by_slot(SlotIndex::new(boundary), Duration::from_secs(5))
        .unwrap()
        .is_none());
    assert!(receiver.drain_actions().is_empty());
    assert_eq!(processor.telemetry.cert_verify_fails_total.load(Ordering::Relaxed), 0);
    for certificate in invalid {
        // None is a transport observer, not a forged committee index zero.
        processor.on_certificate(None::<u32>, certificate);
        assert!(!processor.simplex_state.has_skip_certificate(SlotIndex::new(0)));
        assert!(db
            .load_skip_cert_by_slot(SlotIndex::new(0), Duration::from_secs(5))
            .unwrap()
            .is_none());
        assert!(!receiver.drain_actions().iter().any(|action| matches!(
            action,
            ReceiverAction::SendVote { .. } | ReceiverAction::SendCertificate { .. }
        )));
    }
    processor.on_certificate(None::<u32>, valid.clone());
    let drain = |processor: &mut SessionProcessor| {
        for _ in 0..16 {
            db.sync(Some(Duration::from_secs(5))).unwrap();
            processor.process_pending_async_db_results();
            if processor.database.pending_is_empty() {
                return;
            }
        }
        panic!("certificate continuations did not drain after actual storage barriers");
    };
    drain(&mut processor);
    assert!(processor.simplex_state.has_skip_certificate(SlotIndex::new(0)));
    assert!(db
        .load_skip_cert_by_slot(SlotIndex::new(0), Duration::from_secs(5))
        .unwrap()
        .is_some());
    let actions = receiver.drain_actions();
    assert_eq!(
        actions
            .iter()
            .filter(|action| matches!(action, ReceiverAction::SendCertificate { .. }))
            .count(),
        1
    );
    assert!(!actions.iter().any(|action| matches!(
        action,
        ReceiverAction::SendVote { .. } | ReceiverAction::CacheOurVoteForStandstill { .. }
    )));
    let verify_failures = processor.telemetry.cert_verify_fails_total.load(Ordering::Relaxed);
    processor.on_certificate(None::<u32>, queued_duplicate);
    assert_eq!(
        processor.telemetry.cert_verify_fails_total.load(Ordering::Relaxed),
        verify_failures,
        "queued known-kind PQ certificate must stop before repeated verification"
    );
    assert!(receiver.drain_actions().is_empty());
    processor.on_certificate(None::<u32>, valid);
    drain(&mut processor);
    assert!(!receiver.drain_actions().iter().any(|action| matches!(
        action,
        ReceiverAction::SendVote { .. } | ReceiverAction::SendCertificate { .. }
    )));
    assert_eq!(
        calls,
        stores.iter().map(|store| store.consensus_signatures_produced()).collect::<Vec<_>>()
    );
    drop(processor);
    db.close(None).unwrap();
}

#[test]
fn authenticated_observer_nonempty_query_emits_leader_evidence_after_pq_verification() {
    use rtos_block::Serializable;
    let directory = crate::authenticated_fixture::TestDirectory::new();
    let store = rtos_pq_consensus::ConsensusKeyStore::from_seed(&[0xa3; 32], 0).unwrap();
    let (mut nodes, _) = crate::pq_fixture::members();
    nodes[1] = crate::SimplexSessionNode::from_descriptor(
        &crate::signing_coordinator::tests::custody_descriptor(&store),
    )
    .unwrap();
    let observer = Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[0x71; 32]).unwrap();
    let (runtime, transport, options) = crate::authenticated_fixture::runtime_with_members(
        nodes.iter().map(|node| node.descriptor.clone().unwrap()).collect(),
        observer,
    );
    let nodes = runtime
        .committee()
        .iter()
        .map(crate::SimplexSessionNode::from_descriptor)
        .collect::<rtos_block::Result<Vec<_>>>()
        .unwrap();
    let description = Arc::new(
        SessionDescription::new_with_runtime(
            &options,
            runtime.session_id().clone(),
            1,
            &nodes,
            transport,
            runtime.shard(),
            SystemTime::now(),
            None,
            Some(&runtime),
        )
        .unwrap()
        .bind_pq_session(runtime.catchain_seqno())
        .unwrap(),
    );
    let db =
        crate::database::SimplexDb::open(directory.path().join("db"), "observer-body").unwrap();
    let receiver = MockReceiver::new();
    let mut processor = make_pq_processor_with_description_for_test(db.clone(), description);
    processor.receiver = receiver.clone();
    let listener = RecordingListener::new();
    let listener_dyn: Arc<dyn consensus_common::SessionListener + Send + Sync> = listener.clone();
    processor.callbacks = Arc::new(crate::session_callbacks::SessionCallbacks::new(
        runtime.session_id().clone(),
        Arc::new(AtomicBool::new(false)),
        false,
        Arc::new(TestCallbackQueue),
        Arc::downgrade(&listener_dyn),
    ));
    let mut block = rtos_block::Block::default();
    block.set_global_id(runtime.pin().global_id);
    let mut info = rtos_block::BlockInfo::default();
    info.set_seq_no(1).unwrap();
    info.set_shard(runtime.shard().clone());
    block.write_info(&info).unwrap();
    let cell = block.serialize().unwrap();
    let data = rtos_block::write_boc(&cell).unwrap();
    let collated = make_test_boc(b"authenticated-observer", BocFlags::Crc32);
    let slot = SlotIndex::new(options.slots_per_leader_window);
    let bytes = make_validator_session_candidate_bytes(
        1,
        cell.repr_hash().clone(),
        data.clone(),
        collated.clone(),
    );
    let hash = crate::utils::compute_candidate_id_hash_from_bytes(
        slot,
        &bytes,
        None,
        runtime.shard(),
        1 << 20,
        options.proto_version,
    )
    .unwrap();
    let signature = store
        .sign_consensus(&crate::utils::create_data_to_sign(
            runtime.session_id(),
            &crate::utils::create_candidate_id_to_sign(slot, &hash),
        ))
        .unwrap()
        .bytes
        .to_vec();
    let candidate = rtos_api::ton::consensus::candidatedata::Block {
        slot: slot.value() as i32,
        parent: rtos_api::ton::consensus::CandidateParent::Consensus_CandidateWithoutParents,
        candidate: bytes,
        signature,
    }
    .into_boxed();
    let vote = rtos_api::ton::consensus::simplex::unsignedvote::NotarizeVote {
        id: TlCandidateId { slot: slot.value() as i32, hash: hash.clone() }.into_boxed(),
    }
    .into_boxed();
    let cert = Certificate {
        signatures: VoteSignatureSet {
            votes: vec![VoteSignature {
                who: 1,
                signature: store
                    .sign_consensus(&crate::utils::create_data_to_sign(
                        runtime.session_id(),
                        &crate::utils::serialize_unsigned_vote(&vote),
                    ))
                    .unwrap()
                    .bytes
                    .to_vec(),
            }
            .into_boxed()],
        }
        .into_boxed(),
        vote,
    }
    .into_boxed();
    let certificate = options.wire_profile.serialize(&cert).unwrap();
    let mut bad = candidate.clone();
    let CandidateData::Consensus_Block(ref mut value) = bad else { unreachable!() };
    value.signature[0] ^= 1;
    // Query relay comes from member zero; the scheduled author is member one.
    processor.on_candidate_received(0, bad, Some(certificate.clone()));
    assert!(listener.authenticated.lock().unwrap().is_empty());
    processor.on_candidate_received(0, candidate, Some(certificate));
    let evidence = listener.authenticated.lock().unwrap();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].creator_index, 1);
    assert_eq!(evidence[0].creator_adnl, nodes[1].adnl_id);
    assert_eq!(evidence[0].data.data().as_slice(), data.as_slice());
    assert_eq!(evidence[0].collated_data.data().as_slice(), collated.as_slice());
    assert_eq!(evidence[0].block_id.root_hash(), cell.repr_hash());
    assert_eq!(evidence[0].session_id, *runtime.session_id());
    drop(evidence);
    db.sync(Some(Duration::from_secs(5))).unwrap();
    processor.process_pending_async_db_results();
    assert!(!receiver
        .drain_actions()
        .iter()
        .any(|action| matches!(action, ReceiverAction::SendVote { .. })));
    drop(processor);
    db.close(None).unwrap();
}

#[test]
fn source_finality_controller_waits_for_wal_before_persist_sent_and_gc() {
    source_finality_controller_case(false, false, false, None);
}
#[test]
fn source_finality_controller_approval_upgrades_to_final_after_separate_wal_ack() {
    source_finality_controller_case(true, false, false, None);
}
#[test]
fn source_finality_retained_final_certificate_cannot_be_skipped_by_later_applied_floor() {
    source_finality_controller_case(false, true, false, Some(CertificateGateCase::ReplaySuccess));
}
#[test]
fn source_finality_controller_failed_certificate_save_retries_before_wal_handoff() {
    source_finality_controller_case(false, false, true, None);
}
#[derive(Clone, Copy)]
enum CertificateGateCase {
    LiveSuccess,
    LiveFailure,
    ReplaySuccess,
    ReplayFailure,
    ReplaySeededCandidate,
    ReplaySeededSeqno,
    ReplaySeededBoth,
}
#[test]
fn source_finality_authenticated_replay_requires_own_ack_despite_startup_delivery_seed() {
    for case in [
        CertificateGateCase::ReplaySeededCandidate,
        CertificateGateCase::ReplaySeededSeqno,
        CertificateGateCase::ReplaySeededBoth,
    ] {
        source_finality_controller_case(false, false, false, Some(case));
    }
}
#[test]
fn source_finality_cpp_save_certificate_gates_live_and_replay_before_materialization() {
    for case in [
        CertificateGateCase::LiveSuccess,
        CertificateGateCase::LiveFailure,
        CertificateGateCase::ReplaySuccess,
        CertificateGateCase::ReplayFailure,
    ] {
        source_finality_controller_case(false, false, false, Some(case));
    }
}
fn source_finality_controller_case(
    upgrade: bool,
    high_floor: bool,
    fail_retain: bool,
    gate: Option<CertificateGateCase>,
) {
    use crate::finality_delivery::tests::{fixture, fixture_role, HeldSink};
    let temp = crate::authenticated_fixture::TestDirectory::new();
    let (runtime, draft) = if upgrade || high_floor {
        fixture_role(true, ShardIdent::with_tagged_prefix(0, 0x8000000000000000).unwrap())
    } else {
        fixture()
    };
    let namespace = runtime.runtime_directory(temp.path().to_str().unwrap()).unwrap();
    let nodes = runtime
        .committee()
        .iter()
        .map(crate::SimplexSessionNode::from_descriptor)
        .collect::<rtos_block::Result<Vec<_>>>()
        .unwrap();
    let key = Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[0x71; 32]).unwrap();
    let options = SessionOptions {
        protocol: runtime.protocol(),
        proto_version: runtime.carrier_version(),
        wire_profile: runtime.wire_profile(),
        slots_per_leader_window: runtime.slots_per_leader_window(),
        ..Default::default()
    };
    let description = Arc::new(
        SessionDescription::new_with_runtime(
            &options,
            runtime.session_id().clone(),
            1,
            &nodes,
            key,
            runtime.shard(),
            SystemTime::now(),
            None,
            Some(&runtime),
        )
        .unwrap()
        .bind_pq_session(runtime.catchain_seqno())
        .unwrap(),
    );
    let db = crate::database::SimplexDb::open(&namespace, "source-ack").unwrap();
    let mut processor =
        make_pq_processor_with_description_for_test(db.clone(), description.clone());
    let receiver = MockReceiver::new();
    processor.receiver = receiver.clone();
    let listener = RecordingListener::new();
    let listener_dyn: Arc<dyn consensus_common::SessionListener + Send + Sync> = listener.clone();
    let sink = Arc::new(HeldSink::default());
    let callbacks = Arc::new(
        crate::session_callbacks::SessionCallbacks::new(
            runtime.session_id().clone(),
            Arc::new(AtomicBool::new(false)),
            false,
            Arc::new(TestCallbackQueue),
            Arc::downgrade(&listener_dyn),
        )
        .with_delivery_sink(Some(sink.clone())),
    );
    callbacks.initialize_delivery(runtime.clone(), std::path::Path::new(&namespace)).unwrap();
    callbacks.bind_delivery_start(runtime.pin().zerostate.clone()).unwrap();
    processor.consensus.set_callbacks_for_test(callbacks.clone());
    processor.callbacks = callbacks;
    let consensus_common::SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(proof)) =
        &draft.finality
    else {
        unreachable!()
    };
    let wire =
        rtos_api::pq_finality::PqNetworkSignatureSet::from_final_fields(proof).unwrap().to_node();
    let candidate_bytes = rtos_api::serialize_boxed(&wire.candidate).unwrap();
    let candidate_id = RawCandidateId {
        slot: SlotIndex::new(proof.slot),
        hash: UInt256::calc_file_hash(&candidate_bytes),
    };
    processor.candidate_book_mut().insert_received(
        candidate_id.clone(),
        ReceivedCandidate {
            slot: candidate_id.slot,
            source_idx: ValidatorIndex::new(0),
            candidate_hash_data_bytes: candidate_bytes,
            block_id: draft.block_id.clone(),
            root_hash: draft.block_id.root_hash().clone(),
            file_hash: draft.block_id.file_hash().clone(),
            data: draft.data.clone(),
            collated_data: consensus_common::ConsensusCommonFactory::create_block_payload(
                Vec::new(),
            ),
            gen_utime_ms: None,
            receive_time: SystemTime::now(),
            is_empty: false,
            parent_id: None,
        },
    );
    let certificate = Arc::new(crate::certificate::Certificate {
        vote: crate::simplex_state::FinalizeVote {
            slot: candidate_id.slot,
            block_hash: candidate_id.hash.clone(),
        },
        signatures: proof
            .signatures
            .iter()
            .enumerate()
            .map(|(index, signature)| crate::certificate::VoteSignature {
                validator_idx: ValidatorIndex::new(index as u32),
                signature: signature.signature.clone(),
            })
            .collect(),
    });
    let event = BlockFinalizedEvent {
        slot: candidate_id.slot,
        block_hash: candidate_id.hash.clone(),
        block_id: Some(draft.block_id.clone()),
        certificate,
    };
    if upgrade {
        let (_, approval) = fixture_role(false, runtime.shard().clone());
        let consensus_common::SessionFinality::PqApproval(proof) = approval.finality else {
            unreachable!()
        };
        let wire =
            rtos_api::pq_finality::PqNetworkSignatureSet::from_approval(&proof).unwrap().to_node();
        let cert = Arc::new(crate::certificate::Certificate {
            vote: crate::simplex_state::NotarizeVote {
                slot: candidate_id.slot,
                block_hash: candidate_id.hash.clone(),
            },
            signatures: wire
                .signatures
                .iter()
                .enumerate()
                .map(|(index, signature)| crate::certificate::VoteSignature {
                    validator_idx: ValidatorIndex::new(index as u32),
                    signature: signature.signature.clone(),
                })
                .collect(),
        });
        processor
            .simplex_state
            .set_notarize_certificate(&description, candidate_id.slot, &candidate_id.hash, cert)
            .unwrap();
        let received = processor.candidate_book().received(&candidate_id).unwrap().clone();
        let mut complete = true;
        processor.try_emit_recursive_finalized_callback(
            &candidate_id,
            &received,
            &event,
            false,
            candidate_id.slot,
            &received.candidate_hash_data_bytes,
            &mut complete,
        );
        assert!(!complete);
        let (staged, complete_stage) = sink.0.lock().unwrap().pop().unwrap();
        assert!(matches!(staged.finality, consensus_common::SessionFinality::PqApproval(_)));
        complete_stage(Ok(UInt256::from([6; 32])));
        complete = true;
        processor.try_emit_recursive_finalized_callback(
            &candidate_id,
            &received,
            &event,
            false,
            candidate_id.slot,
            &received.candidate_hash_data_bytes,
            &mut complete,
        );
        assert!(complete);
        assert!(
            !processor.consensus.finalized_delivery_sent_contains(&candidate_id),
            "Approval cannot suppress Final"
        );
        processor.with_consensus_backend(|controller, backend| {
            assert!(controller.maybe_apply_finalized_state(backend, &candidate_id, false))
        });
        db.sync(Some(Duration::from_secs(5))).unwrap();
        assert!(!db.load_finalized_blocks().unwrap()[0].is_final);
    }
    let blocked_intents = std::path::Path::new(&namespace).join("finality-intents");
    if fail_retain {
        std::fs::write(&blocked_intents, b"fixture obstruction before certificate retention")
            .unwrap();
    }
    if high_floor {
        let mut later = draft.block_id.clone();
        later.seq_no += 100;
        processor.set_mc_finalized_block(later);
    }
    let pending_certificate = gate.map(|_| ManualAsyncResult::pending());
    if let Some(result) = &pending_certificate {
        processor.database.insert_final_cert_store(candidate_id.clone(), result.clone());
    }
    if matches!(
        gate,
        Some(CertificateGateCase::ReplaySeededCandidate | CertificateGateCase::ReplaySeededBoth)
    ) {
        processor.consensus.insert_finalized_delivery_sent(candidate_id.clone());
    }
    if matches!(
        gate,
        Some(CertificateGateCase::ReplaySeededSeqno | CertificateGateCase::ReplaySeededBoth)
    ) {
        processor.consensus.insert_finalized_delivery_sent_seqno(
            draft.block_id.seq_no(),
            candidate_id.slot,
            draft.block_id.clone(),
        );
    }
    let replay = high_floor
        || matches!(
            gate,
            Some(
                CertificateGateCase::ReplaySuccess
                    | CertificateGateCase::ReplayFailure
                    | CertificateGateCase::ReplaySeededCandidate
                    | CertificateGateCase::ReplaySeededSeqno
                    | CertificateGateCase::ReplaySeededBoth
            )
        );
    if replay {
        processor
            .simplex_state
            .set_first_non_finalized_slot(SlotIndex::new(candidate_id.slot.value() + 100));
        processor.replay_finality_intent(event.certificate.to_tl().unwrap()).unwrap();
    } else if gate.is_some() {
        processor.simplex_state.push_event_front(SimplexEvent::BlockFinalized(event.clone()));
        processor.process_simplex_events();
    } else {
        processor.handle_block_finalized(event.clone());
    }
    if let Some(result) = pending_certificate {
        assert!(sink.0.lock().unwrap().is_empty(), "SaveCertificate pending: no node WAL handoff");
        assert!(!processor.consensus.finalized_pending_body_contains(&candidate_id));
        assert_eq!(processor.pending_finality_materialization_count(), 1);
        assert!(
            db.load_finalized_blocks().unwrap().is_empty(),
            "SaveCertificate pending: no finalized marker"
        );
        assert!(db.load_final_certs().unwrap().is_empty());
        if matches!(gate, Some(CertificateGateCase::LiveSuccess)) {
            let notar_vote = Vote::Notarize(crate::simplex_state::NotarizeVote {
                slot: candidate_id.slot,
                block_hash: candidate_id.hash.clone(),
            });
            let signed = crate::utils::create_data_to_sign(
                runtime.session_id(),
                &crate::utils::serialize_unsigned_vote(
                    &crate::utils::vote_to_tl_unsigned(&notar_vote).unwrap(),
                ),
            );
            let signatures = [0xa9, 0xaa]
                .iter()
                .enumerate()
                .map(|(index, seed)| {
                    let store =
                        rtos_pq_consensus::ConsensusKeyStore::from_seed(&[*seed; 32], 0).unwrap();
                    crate::certificate::VoteSignature {
                        validator_idx: ValidatorIndex::new(index as u32),
                        signature: store.sign_consensus(&signed).unwrap().bytes.to_vec(),
                    }
                })
                .collect();
            let notar_cert = Arc::new(crate::certificate::Certificate {
                vote: crate::simplex_state::NotarizeVote {
                    slot: candidate_id.slot,
                    block_hash: candidate_id.hash.clone(),
                },
                signatures,
            });
            crate::certificate::Certificate::<Vote>::from_tl(
                &notar_cert.to_tl().unwrap(),
                &description,
                runtime.session_id(),
            )
            .unwrap();
            processor.handle_notarization_reached(NotarizationReachedEvent {
                slot: candidate_id.slot,
                block_hash: candidate_id.hash.clone(),
                certificate: notar_cert,
            });
            db.sync(Some(TEST_DB_WATCHDOG)).unwrap();
            processor.process_pending_async_db_results();
            let mut last_warning = SystemTime::now();
            while let Some(task) =
                processor.task_queue.pull_closure(Duration::ZERO, &mut last_warning)
            {
                task(&mut processor);
            }
            assert!(db.load_notar_certs().unwrap().iter().any(|c| c.candidate_id == candidate_id));
            assert!(
                sink.0.lock().unwrap().is_empty(),
                "NotarCert completion cannot release a pending FinalCert"
            );
            assert!(db.load_finalized_blocks().unwrap().is_empty());
        }
        let failed = matches!(
            gate,
            Some(CertificateGateCase::LiveFailure | CertificateGateCase::ReplayFailure)
        );
        if failed {
            result.complete_err("injected certificate storage failure");
            drain_processor_storage_and_messages(&mut processor);
            assert!(sink.0.lock().unwrap().is_empty(), "failed save cannot publish finalization");
            assert!(db.load_finalized_blocks().unwrap().is_empty());
            assert!(processor.pending_saved_finalizations.contains_key(&candidate_id));
            if replay {
                processor.replay_finality_intent(event.certificate.to_tl().unwrap()).unwrap();
            } else {
                processor.simplex_state.push_event_front(SimplexEvent::FinalizationReached(
                    FinalizationReachedEvent {
                        slot: event.slot,
                        block_hash: event.block_hash.clone(),
                        certificate: event.certificate.clone(),
                    },
                ));
                processor
                    .simplex_state
                    .push_event_front(SimplexEvent::BlockFinalized(event.clone()));
                processor.process_simplex_events();
            }
        } else {
            // Release the completion only after the real storage worker saved
            // the exact certificate; the pending receipt itself proves nothing.
            db.save_final_cert_async(&candidate_id, &event.certificate).unwrap().wait().unwrap();
            result.complete_ok();
            processor.process_pending_async_db_results();
            assert_eq!(
                processor.pending_finality_materialization_count(),
                1,
                "saved-but-not-yet-dispatched finalization is still in flight"
            );
            assert!(sink.0.lock().unwrap().is_empty());
        }
        drain_processor_storage_and_messages(&mut processor);
        assert!(db.load_final_certs().unwrap().iter().any(|c| c.candidate_id == candidate_id));
        assert!(!processor.pending_saved_finalizations.contains_key(&candidate_id));
        assert_eq!(
            sink.0.lock().unwrap().len(),
            1,
            "duplicate completion must not repeat WAL handoff"
        );
        if matches!(
            gate,
            Some(
                CertificateGateCase::ReplaySeededCandidate
                    | CertificateGateCase::ReplaySeededSeqno
                    | CertificateGateCase::ReplaySeededBoth
            )
        ) {
            processor.consensus.prune_below(SlotIndex::new(candidate_id.slot.value() + 100));
            assert!(
                processor.consensus.finalized_pending_body_contains(&candidate_id),
                "slot cleanup cannot discard an authenticated source handoff before its own ACK"
            );
            processor.with_consensus_backend(|controller, backend| {
                controller.retry_pending_recursive_finalization(backend)
            });
            assert_eq!(
                sink.0.lock().unwrap().len(),
                1,
                "old-slot retries must join the same node handoff"
            );
        }
        let final_broadcasts = receiver.drain_actions().into_iter().filter(|action| matches!(action,
            ReceiverAction::SendCertificate { certificate }
                if matches!(certificate.vote(), rtos_api::ton::consensus::simplex::UnsignedVote::Consensus_Simplex_FinalizeVote(_))
        )).count();
        assert_eq!(
            final_broadcasts,
            usize::from(!replay),
            "live completion relays once; C++ startup replay suppresses certificate broadcasts"
        );
    }
    if fail_retain {
        assert!(
            sink.0.lock().unwrap().is_empty(),
            "failed retention cannot authorize node handoff"
        );
        assert_eq!(processor.callbacks.finality_retention_attempts(), 1);
        assert!(processor.consensus.finalized_pending_body_contains(&candidate_id));
        // Unrelated actor callbacks must not each restart the same blocked
        // certificate conversion. The periodic fallback keeps its own horizon.
        processor.set_time(SystemTime::now());
        processor.check_all();
        assert_eq!(processor.callbacks.finality_retention_attempts(), 2);
        for _ in 0..16 {
            processor.check_all();
        }
        assert_eq!(
            processor.callbacks.finality_retention_attempts(),
            2,
            "unrelated wakeups must join pending finalization between periodic retries"
        );
        processor.advance_time(Duration::from_millis(250));
        processor.check_all();
        assert_eq!(
            processor.callbacks.finality_retention_attempts(),
            3,
            "the original retry horizon must still retry failed certificate retention"
        );
        std::fs::remove_file(&blocked_intents).unwrap();
        processor.with_consensus_backend(|c, b| c.retry_pending_recursive_finalization(b));
    }
    for _ in 0..3 {
        processor.with_consensus_backend(|c, b| c.retry_pending_recursive_finalization(b));
    }
    // C++ attaches a duplicate to its existing InFlight finalization. It does
    // not redo a successful SaveCertificate phase while the node WAL is held.
    processor.handle_block_finalized(event);
    assert_eq!(
        processor.callbacks.finality_retention_attempts(),
        if fail_retain { 4 } else { 1 },
        "parent/WAL retries must reuse the completed C++ certificate-save phase"
    );
    assert_eq!(sink.0.lock().unwrap().len(), 1);
    assert_eq!(processor.consensus.is_finalized_block(&candidate_id), upgrade);
    assert!(!processor.consensus.finalized_delivery_sent_contains(&candidate_id));
    db.sync(Some(Duration::from_secs(5))).unwrap();
    assert!(
        db.load_finalized_blocks().unwrap().iter().all(|record| !record.is_final),
        "source Final must wait for its own node WAL"
    );
    processor.cleanup_old_slots(SlotIndex::new(1000));
    assert!(
        processor.candidate_book().received(&candidate_id).is_some(),
        "held finality must retain body ancestry"
    );
    let (_, complete) = sink.0.lock().unwrap().pop().unwrap();
    processor.set_time(processor.now());
    let now = processor.now(); // The fixture stores timestamps at microsecond precision.
    processor.next_finality_retry = now + Duration::from_millis(250);
    complete(Ok(UInt256::from([7; 32])));
    assert!(!processor.consensus.finalized_delivery_sent_contains(&candidate_id));
    processor.on_finality_delivery_ready();
    assert_eq!(
        processor.now(),
        now,
        "completed delivery must resume without advancing the fallback clock"
    );
    assert!(processor.consensus.is_finalized_block(&candidate_id));
    assert!(processor.consensus.finalized_delivery_sent_contains(&candidate_id));
    db.sync(Some(Duration::from_secs(5))).unwrap();
    processor.process_pending_async_db_results();
    let finalized = db.load_finalized_blocks().unwrap();
    assert_eq!(finalized.len(), 1);
    assert!(finalized[0].is_final, "Final must upgrade earlier Approval persistence");
    processor.with_consensus_backend(|controller, backend| {
        controller.retry_pending_recursive_finalization(backend)
    });
    assert!(sink.0.lock().unwrap().is_empty(), "duplicate retry must not stage again");
    drop(processor);
    db.close(None).unwrap();
    if gate.is_some() {
        drop(db);
        let reopened = crate::database::SimplexDb::open(&namespace, "source-ack").unwrap();
        assert!(reopened
            .load_final_certs()
            .unwrap()
            .iter()
            .any(|c| c.candidate_id == candidate_id));
        assert!(
            reopened
                .load_finalized_blocks()
                .unwrap()
                .iter()
                .any(|b| b.candidate_id == candidate_id && b.is_final),
            "cold read must retain both the certificate and its later materialized marker"
        );
        reopened.close(None).unwrap();
    }
}

#[test]
fn source_finality_main_worker_release_keeps_only_accepted_node_work_owned() {
    use crate::finality_delivery::tests::{fixture, HeldSink};
    let temp = crate::authenticated_fixture::TestDirectory::new();
    let (runtime, draft) = fixture();
    let namespace = runtime.runtime_directory(temp.path().to_str().unwrap()).unwrap();
    let listener = RecordingListener::new();
    let listener_dyn: Arc<dyn consensus_common::SessionListener + Send + Sync> = listener.clone();
    let sink = Arc::new(HeldSink::default());
    let callbacks = Arc::new(
        crate::session_callbacks::SessionCallbacks::new(
            runtime.session_id().clone(),
            Arc::new(AtomicBool::new(false)),
            false,
            Arc::new(TestCallbackQueue),
            Arc::downgrade(&listener_dyn),
        )
        .with_delivery_sink(Some(sink.clone())),
    );
    let main_worker = callbacks.delivery_lifetime();
    callbacks.initialize_delivery(runtime.clone(), std::path::Path::new(&namespace)).unwrap();
    callbacks.bind_delivery_start(runtime.pin().zerostate.clone()).unwrap();
    let old_handle = Arc::new(callbacks.with_listener(Arc::downgrade(&listener_dyn)));
    assert!(!callbacks.poll_durable_finality(draft).unwrap());
    drop(main_worker);
    assert!(!callbacks.source_namespace_drained());
    assert!(!old_handle.source_namespace_drained());
    assert!(
        callbacks.initialize_delivery(runtime.clone(), std::path::Path::new(&namespace)).is_err(),
        "accepted node work must retain source lock after main worker joins"
    );
    assert!(crate::finality_delivery::scan_pending_finality(temp.path()).unwrap().is_empty());
    let (_, complete) = sink.0.lock().unwrap().pop().unwrap();
    complete(Err(rtos_block::error!("Node WAL failed after source stop")));
    assert!(callbacks.source_namespace_drained());
    assert!(old_handle.source_namespace_drained());
    let recoverable = crate::finality_delivery::scan_pending_finality(temp.path()).unwrap();
    assert_eq!(recoverable.len(), 1);
    drop(recoverable);
    let next_worker = callbacks.delivery_lifetime();
    callbacks.initialize_delivery(runtime, std::path::Path::new(&namespace)).unwrap();
    assert!(!callbacks.source_namespace_drained());
    drop(next_worker);
    assert!(callbacks.source_namespace_drained());
    // Both old source/listener handles remain alive; neither retains the lock.
    assert_eq!(crate::finality_delivery::scan_pending_finality(temp.path()).unwrap().len(), 1);
    drop(old_handle);
}

/// Exercises the real controller walk with two nonempty ancestors separated by
/// empties. The PQ votes are real; candidate-book rehydration is explicit fixture
/// input, while source intent/ACK/output files are reopened from disk.
#[test]
fn source_finality_controller_empty_trigger_seals_all_roles_after_cold_retry() {
    source_finality_empty_trigger_cold_retry_case(
        false,
        false,
        false,
        false,
        false,
        PresealedColdPlan::None,
    );
}

#[test]
fn source_finality_controller_cold_retry_keeps_ancestor_handoff_below_applied_floor() {
    source_finality_empty_trigger_cold_retry_case(
        true,
        false,
        false,
        false,
        false,
        PresealedColdPlan::None,
    );
}

#[test]
fn source_finality_controller_replay_stops_at_materialized_parent_without_its_body() {
    source_finality_empty_trigger_cold_retry_case(
        true,
        true,
        false,
        false,
        false,
        PresealedColdPlan::None,
    );
}

#[test]
fn source_finality_replayed_children_share_only_fresh_accepted_ancestor_approval() {
    source_finality_empty_trigger_cold_retry_case(
        false,
        false,
        true,
        false,
        false,
        PresealedColdPlan::None,
    );
}

#[test]
fn source_finality_replay_reuses_materialized_ancestry_without_truncating_outputs() {
    source_finality_empty_trigger_cold_retry_case(
        false,
        false,
        true,
        true,
        false,
        PresealedColdPlan::None,
    );
}

#[test]
fn source_finality_replay_pruning_keeps_inflight_accepted_ancestor_receipts() {
    source_finality_empty_trigger_cold_retry_case(
        false,
        false,
        true,
        true,
        true,
        PresealedColdPlan::None,
    );
}

#[test]
fn source_finality_cold_replay_preserves_presealed_outputs_after_parent_materialization() {
    source_finality_empty_trigger_cold_retry_case(
        false,
        false,
        false,
        false,
        false,
        PresealedColdPlan::Exact,
    );
}

#[test]
fn source_finality_cold_replay_does_not_accept_changed_sealed_output_role() {
    source_finality_empty_trigger_cold_retry_case(
        false,
        false,
        false,
        false,
        false,
        PresealedColdPlan::ChangedParentRole,
    );
}

#[test]
fn source_finality_long_empty_plan_keeps_uncached_full_walk() {
    source_finality_empty_trigger_cold_retry_case(
        false,
        false,
        false,
        false,
        false,
        PresealedColdPlan::LongUncachedChain,
    );
}

enum PresealedColdPlan {
    None,
    Exact,
    ChangedParentRole,
    LongUncachedChain,
}

fn source_finality_empty_trigger_cold_retry_case(
    high_floor: bool,
    materialized_parent: bool,
    shared_approvals: bool,
    reuse_materialized_plan: bool,
    prune_after_acceptance: bool,
    presealed_case: PresealedColdPlan,
) {
    let long_uncached_chain = matches!(presealed_case, PresealedColdPlan::LongUncachedChain);
    let presealed_cold_plan =
        matches!(presealed_case, PresealedColdPlan::Exact | PresealedColdPlan::ChangedParentRole);
    use crate::finality_delivery::tests::{fixture_role, HeldSink};
    use rtos_block::Serializable;
    let temp = crate::authenticated_fixture::TestDirectory::new();
    let (runtime, _) =
        fixture_role(true, ShardIdent::with_tagged_prefix(0, 0x8000000000000000).unwrap());
    assert!(runtime.recovery_binding().is_some());
    let namespace = runtime.runtime_directory(temp.path().to_str().unwrap()).unwrap();
    let nodes = runtime
        .committee()
        .iter()
        .map(crate::SimplexSessionNode::from_descriptor)
        .collect::<Result<Vec<_>>>()
        .unwrap();
    let options = SessionOptions {
        protocol: runtime.protocol(),
        proto_version: runtime.carrier_version(),
        wire_profile: runtime.wire_profile(),
        slots_per_leader_window: runtime.slots_per_leader_window(),
        ..Default::default()
    };
    let transport = Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[0x71; 32]).unwrap();
    let description = Arc::new(
        SessionDescription::new_with_runtime(
            &options,
            runtime.session_id().clone(),
            1,
            &nodes,
            transport,
            runtime.shard(),
            SystemTime::now(),
            None,
            Some(&runtime),
        )
        .unwrap()
        .bind_pq_session(runtime.catchain_seqno())
        .unwrap(),
    );
    let stores: Vec<_> = [0xa9, 0xaa]
        .iter()
        .map(|seed| rtos_pq_consensus::ConsensusKeyStore::from_seed(&[*seed; 32], 0).unwrap())
        .collect();
    let mut chain: Vec<(RawCandidateId, ReceivedCandidate)> = Vec::new();
    let layout = if long_uncached_chain {
        std::iter::once((0, false)).chain((1..=1024).map(|slot| (slot, true))).collect()
    } else if shared_approvals {
        vec![(0, false), (1, true), (2, false), (3, true), (4, false)]
    } else {
        vec![(0, false), (1, true), (2, false), (3, true)]
    };
    for (slot, empty) in layout {
        let parent = chain.last().map(|(id, _)| id.clone());
        let (block_id, data) = if empty {
            let previous = &chain.last().unwrap().1;
            (previous.block_id.clone(), previous.data.clone())
        } else {
            let mut block = rtos_block::Block::default();
            block.set_global_id(runtime.pin().global_id);
            let mut info = rtos_block::BlockInfo::default();
            info.set_seq_no(slot + 1).unwrap();
            info.set_shard(runtime.shard().clone());
            block.write_info(&info).unwrap();
            let cell = block.serialize().unwrap();
            let bytes = rtos_block::write_boc(&cell).unwrap();
            (
                BlockIdExt::with_params(
                    runtime.shard().clone(),
                    slot + 1,
                    cell.repr_hash().clone(),
                    UInt256::calc_file_hash(&bytes),
                ),
                consensus_common::ConsensusCommonFactory::create_block_payload(bytes),
            )
        };
        let hash_data = if empty {
            make_candidate_hash_data_empty(block_id.clone(), parent.clone().unwrap())
        } else {
            make_candidate_hash_data_with_parent(
                block_id.clone(),
                UInt256::default(),
                parent.clone(),
            )
        };
        let bytes = rtos_api::serialize_boxed(&hash_data).unwrap();
        let id =
            RawCandidateId { slot: SlotIndex::new(slot), hash: UInt256::calc_file_hash(&bytes) };
        chain.push((
            id.clone(),
            ReceivedCandidate {
                slot: id.slot,
                source_idx: ValidatorIndex::new(0),
                candidate_hash_data_bytes: bytes,
                root_hash: block_id.root_hash().clone(),
                file_hash: block_id.file_hash().clone(),
                block_id,
                data,
                collated_data: consensus_common::ConsensusCommonFactory::create_block_payload(
                    Vec::new(),
                ),
                gen_utime_ms: None,
                receive_time: SystemTime::now(),
                is_empty: empty,
                parent_id: parent,
            },
        ));
    }
    let sign = |id: &RawCandidateId, final_vote: bool| {
        let boxed =
            TlCandidateId { slot: id.slot.value() as i32, hash: id.hash.clone() }.into_boxed();
        let vote = if final_vote {
            rtos_api::ton::consensus::simplex::unsignedvote::FinalizeVote { id: boxed }.into_boxed()
        } else {
            rtos_api::ton::consensus::simplex::unsignedvote::NotarizeVote { id: boxed }.into_boxed()
        };
        let bytes = crate::utils::create_data_to_sign(
            runtime.session_id(),
            &crate::utils::serialize_unsigned_vote(&vote),
        );
        stores
            .iter()
            .enumerate()
            .map(|(i, s)| crate::certificate::VoteSignature {
                validator_idx: ValidatorIndex::new(i as u32),
                signature: s.sign_consensus(&bytes).unwrap().bytes.to_vec(),
            })
            .collect::<Vec<_>>()
    };
    let trigger = chain[if long_uncached_chain { chain.len() - 1 } else { 3 }].0.clone();
    let event = BlockFinalizedEvent {
        slot: trigger.slot,
        block_hash: trigger.hash.clone(),
        block_id: None,
        certificate: Arc::new(crate::certificate::Certificate {
            vote: crate::simplex_state::FinalizeVote {
                slot: trigger.slot,
                block_hash: trigger.hash.clone(),
            },
            signatures: sign(&trigger, true),
        }),
    };
    let second_event = shared_approvals.then(|| {
        let id = &chain[4].0;
        BlockFinalizedEvent {
            slot: id.slot,
            block_hash: id.hash.clone(),
            block_id: None,
            certificate: Arc::new(crate::certificate::Certificate {
                vote: crate::simplex_state::FinalizeVote {
                    slot: id.slot,
                    block_hash: id.hash.clone(),
                },
                signatures: sign(id, true),
            }),
        }
    });
    let listener = RecordingListener::new();
    let listener_dyn: Arc<dyn consensus_common::SessionListener + Send + Sync> = listener.clone();
    let make_processor = |sink: Arc<HeldSink>| {
        let db = crate::database::SimplexDb::open(&namespace, "sealed-cold").unwrap();
        let mut processor =
            make_pq_processor_with_description_for_test(db.clone(), description.clone());
        let callbacks = Arc::new(
            crate::session_callbacks::SessionCallbacks::new(
                runtime.session_id().clone(),
                Arc::new(AtomicBool::new(false)),
                false,
                Arc::new(TestCallbackQueue),
                Arc::downgrade(&listener_dyn),
            )
            .with_delivery_sink(Some(sink)),
        );
        callbacks.initialize_delivery(runtime.clone(), std::path::Path::new(&namespace)).unwrap();
        callbacks.bind_delivery_start(runtime.pin().zerostate.clone()).unwrap();
        processor.consensus.set_callbacks_for_test(callbacks.clone());
        processor.callbacks = callbacks;
        for (index, (id, received)) in chain.iter().enumerate() {
            if materialized_parent && index == 0 {
                processor.consensus.insert_finalized_block(id.clone());
            } else {
                processor.candidate_book_mut().insert_received(id.clone(), received.clone());
            }
        }
        // Rehydrate every ancestor's quorum evidence, including empty nodes.
        // Body-callback suppression never replaces recovery authentication.
        for (id, _) in chain.iter().take(if shared_approvals { 4 } else { 3 }) {
            processor
                .simplex_state
                .set_notarize_certificate(
                    &description,
                    id.slot,
                    &id.hash,
                    Arc::new(crate::certificate::Certificate {
                        vote: crate::simplex_state::NotarizeVote {
                            slot: id.slot,
                            block_hash: id.hash.clone(),
                        },
                        signatures: sign(id, false),
                    }),
                )
                .unwrap();
        }
        if high_floor {
            processor.set_mc_finalized_block(BlockIdExt::with_params(
                runtime.shard().clone(),
                1000,
                UInt256::rand(),
                UInt256::rand(),
            ));
        }
        (db, processor)
    };
    let map = std::path::Path::new(&namespace).join("finality-intents/outputs-v1").join(format!(
        "{}-{}.outputs",
        trigger.slot.value(),
        trigger.hash.to_hex_string()
    ));
    let sink = Arc::new(HeldSink::default());
    let (db, mut processor) = make_processor(sink.clone());
    processor.handle_block_finalized(event.clone());
    if let Some(second) = &second_event {
        processor.handle_block_finalized(second.clone());
    }
    if long_uncached_chain {
        assert_eq!(chain.len(), 1025);
        assert_eq!(
            processor.consensus.continuation_cursor_for_test(&trigger),
            None,
            "oversized valid plans must use the full resolver rather than a partial continuation"
        );
        assert!(!map.exists());
        assert!(!processor.consensus.is_finalized_block(&chain[0].0));
        let staged = std::mem::take(&mut *sink.0.lock().unwrap());
        assert_eq!(staged.len(), 1, "the long empty chain still owes its original Final handoff");
        assert_eq!(staged[0].0.block_id, chain[0].1.block_id);
        assert!(matches!(staged[0].0.finality, consensus_common::SessionFinality::Carrier(_)));
        for (_, done) in staged {
            done(Ok(UInt256::from([0x35; 32])));
        }
        for _ in 0..8 {
            processor.with_consensus_backend(|c, b| c.retry_pending_recursive_finalization(b));
            if map.exists() {
                break;
            }
        }
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&map).unwrap()).unwrap();
        let outputs = value["outputs"].as_array().unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0]["block_id"], chain[0].1.block_id.to_string());
        assert_eq!(outputs[0]["is_final"], true);
        assert!(processor.consensus.finalized_pending_body_is_empty());
        drop(processor);
        db.close(None).unwrap();
        return;
    }
    if materialized_parent {
        let staged = std::mem::take(&mut *sink.0.lock().unwrap());
        assert_eq!(
            staged.len(),
            1,
            "C++ persisted parent marker must terminate recovery before a pruned body lookup"
        );
        assert_eq!(staged[0].0.block_id, chain[2].1.block_id);
        assert!(matches!(staged[0].0.finality, consensus_common::SessionFinality::Carrier(_)));
        for (_, done) in staged {
            done(Ok(UInt256::from([3; 32])));
        }
        for _ in 0..8 {
            processor.with_consensus_backend(|c, b| c.retry_pending_recursive_finalization(b));
            if map.exists() {
                break;
            }
        }
        assert!(map.exists(), "current source still needs its own node handoff before closure");
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&map).unwrap()).unwrap();
        assert_eq!(value["outputs"].as_array().unwrap().len(), 1);
        drop(processor);
        db.close(None).unwrap();
        return;
    }
    assert!(!map.exists(), "a held node handoff cannot seal a complete walk");
    let pending_path = std::path::Path::new(&namespace).join("finality-intents").join(format!(
        "{}-{}.json",
        trigger.slot.value(),
        trigger.hash.to_hex_string()
    ));
    let completed_path = pending_path
        .parent()
        .unwrap()
        .join("completed-v1")
        .join(pending_path.with_extension("complete").file_name().unwrap());
    let presealed_bytes = if presealed_cold_plan {
        // The existing IO fault leaves the exact crash window: the full plan
        // and completion proof are durable, but the source intent is not yet
        // unlinked. A completed ancestor must not shrink that source's plan.
        processor.callbacks.fail_intent_resolution_once_for_test();
        let mut warm_handoffs = 0;
        for _ in 0..16 {
            for (_, done) in std::mem::take(&mut *sink.0.lock().unwrap()) {
                warm_handoffs += 1;
                done(Ok(UInt256::from([0x28; 32])));
            }
            processor.with_consensus_backend(|c, b| c.retry_pending_recursive_finalization(b));
            if map.exists() && completed_path.exists() {
                break;
            }
        }
        assert_eq!(warm_handoffs, 2, "both original roles must cross the warm node sink");
        assert!(pending_path.exists() && completed_path.exists());
        assert!(processor.consensus.is_finalized_block(&chain[0].0));
        let mut bytes = std::fs::read(&map).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["outputs"].as_array().unwrap().len(), 2);
        if matches!(presealed_case, PresealedColdPlan::ChangedParentRole) {
            let parent = value["outputs"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|output| output["block_id"] == chain[0].1.block_id.to_string())
                .unwrap();
            parent["is_final"] = serde_json::json!(true);
            bytes = serde_json::to_vec(&value).unwrap();
            std::fs::write(&map, &bytes).unwrap();
        }
        Some(bytes)
    } else {
        // Resolve only Final. Approval is a separate debt and must keep the map absent.
        let staged = std::mem::take(&mut *sink.0.lock().unwrap());
        assert_eq!(staged.len(), 1, "C++ WC parent must be the sole pending handoff");
        assert_eq!(
            staged[0].0.block_id, chain[0].1.block_id,
            "C++ WC parent must precede child final"
        );
        assert!(matches!(staged[0].0.finality, consensus_common::SessionFinality::PqApproval(_)));
        for (draft, done) in staged {
            if matches!(draft.finality, consensus_common::SessionFinality::PqApproval(_)) {
                done(Err(rtos_block::error!("held approval before restart")));
            } else {
                done(Ok(UInt256::from([1; 32])));
            }
        }
        processor.with_consensus_backend(|c, b| c.retry_pending_recursive_finalization(b));
        assert!(!map.exists(), "Final ACK must not fill an ancestor Approval hole");
        for (_, done) in std::mem::take(&mut *sink.0.lock().unwrap()) {
            done(Err(rtos_block::error!("restart with source debt")));
        }
        None
    };
    drop(processor);
    db.close(None).unwrap();
    drop(db);
    let sink = Arc::new(HeldSink::default());
    *sink.1.lock().unwrap() = Some(Vec::new());
    let (db, mut processor) = make_processor(sink.clone());
    if presealed_cold_plan {
        processor.consensus.insert_finalized_block(chain[0].0.clone());
    }
    if shared_approvals {
        // A startup delivery seed is deliberately insufficient: both replays
        // must first obtain this boot's real ancestor node acceptance.
        processor.consensus.insert_finalized_delivery_sent(chain[0].0.clone());
        processor.consensus.insert_finalized_delivery_sent_seqno(
            chain[0].1.block_id.seq_no(),
            chain[0].0.slot,
            chain[0].1.block_id.clone(),
        );
    }
    let retained = processor.callbacks.pending_finality_intents().unwrap();
    assert_eq!(
        retained.len(),
        if shared_approvals { 2 } else { 1 },
        "cold replay comes from the durable source certificate"
    );
    for wire in &retained {
        processor
            .replay_finality_intent(runtime.wire_profile().deserialize_typed(wire).unwrap())
            .unwrap();
    }
    drain_processor_storage_and_messages(&mut processor);
    assert_eq!(
        processor.callbacks.finality_retention_attempts(),
        if shared_approvals { 2 } else { 1 },
        "cold recovery must establish persistence again instead of inheriting a warm phase"
    );
    if matches!(presealed_case, PresealedColdPlan::ChangedParentRole) {
        for _ in 0..4 {
            processor.with_consensus_backend(|c, b| c.retry_pending_recursive_finalization(b));
        }
        assert!(
            sink.0.lock().unwrap().is_empty(),
            "a declared role cannot manufacture a node handoff"
        );
        assert!(
            sink.1.lock().unwrap().as_ref().unwrap().is_empty(),
            "a declared role cannot seed this boot's node acceptance"
        );
        assert!(pending_path.exists(), "inconsistent original debt must remain pending");
        assert_eq!(std::fs::read(&map).unwrap(), presealed_bytes.unwrap());
        drop(processor);
        db.close(None).unwrap();
        return;
    }
    if shared_approvals {
        // Both authenticated source intents wait on this same held parent WAL.
        // C++ attaches the second finalization to the existing InFlight work.
        for _ in 0..3 {
            let before = processor.callbacks.finality_poll_attempts();
            let built_before =
                crate::finality_recovery::ExpectedFinalityOutput::construction_count_for_test();
            let reads_before = CandidateBook::received_lookup_count_for_test();
            processor.with_consensus_backend(|c, b| c.retry_pending_recursive_finalization(b));
            assert_eq!(
                CandidateBook::received_lookup_count_for_test() - reads_before,
                2,
                "two in-flight sources must read only their actual current waiting candidates"
            );
            assert!(crate::finality_recovery::ExpectedFinalityOutput::construction_count_for_test() - built_before <= 4,
                "an exact output identity must not be rebuilt for a shared or already resolved plan");
            assert_eq!(
                processor.callbacks.finality_poll_attempts() - before,
                1,
                "one recovery pass must poll a shared pending ancestor only once"
            );
        }
        for id in [&trigger, &chain[4].0] {
            assert_eq!(
                processor.consensus.continuation_cursor_for_test(id),
                Some(0),
                "a held WAL cannot advance a source continuation"
            );
        }
        let data = processor.candidate_book().received(&chain[0].0).unwrap().data.clone();
        processor.candidate_book_mut().received_mut(&chain[0].0).unwrap().data =
            consensus_common::ConsensusCommonFactory::create_block_payload(Vec::new());
        let before = processor.callbacks.finality_poll_attempts();
        processor.with_consensus_backend(|c, b| c.retry_pending_recursive_finalization(b));
        assert_eq!(
            processor.callbacks.finality_poll_attempts(),
            before,
            "missing pending body must request repair before polling the node"
        );
        for id in [&trigger, &chain[4].0] {
            assert_eq!(processor.consensus.continuation_cursor_for_test(id), Some(0));
        }
        processor.candidate_book_mut().received_mut(&chain[0].0).unwrap().data = data;
        // A changed dependency edge cannot reuse a previously resolved plan.
        processor.candidate_book_mut().received_mut(&chain[0].0).unwrap().parent_id =
            Some(chain[4].0.clone());
        processor.with_consensus_backend(|c, b| c.retry_pending_recursive_finalization(b));
        for id in [&trigger, &chain[4].0] {
            assert_eq!(
                processor.consensus.continuation_cursor_for_test(id),
                None,
                "changed live metadata must invalidate the cached plan before any child handoff"
            );
        }
        assert_eq!(processor.callbacks.finality_poll_attempts(), before);
        processor.candidate_book_mut().received_mut(&chain[0].0).unwrap().parent_id = None;
        processor.with_consensus_backend(|c, b| c.retry_pending_recursive_finalization(b));
        for id in [&trigger, &chain[4].0] {
            assert_eq!(processor.consensus.continuation_cursor_for_test(id), Some(0));
        }
        assert!(processor.consensus.finalized_pending_body_contains(&trigger));
        assert!(processor.consensus.finalized_pending_body_contains(&chain[4].0));
        assert!(
            !processor.consensus.is_finalized_block(&chain[0].0),
            "joining an in-flight ancestor must not grant acceptance"
        );
    }
    let second_map = second_event.as_ref().map(|e| {
        std::path::Path::new(&namespace).join("finality-intents/outputs-v1").join(format!(
            "{}-{}.outputs",
            e.slot.value(),
            e.block_hash.to_hex_string()
        ))
    });
    let mut final_slots = std::collections::BTreeSet::new();
    let mut parent_accepted = false;
    let mut rejected_parent_acceptance = false;
    let mut ancestor_body_evicted = false;
    for _ in 0..16 {
        if reuse_materialized_plan
            && !ancestor_body_evicted
            && processor.consensus.is_finalized_block(&chain[0].0)
        {
            assert!(
                parent_accepted,
                "only actual fresh node acceptance can make ancestry reusable"
            );
            processor.candidate_book_mut().received_mut(&chain[0].0).unwrap().data =
                consensus_common::ConsensusCommonFactory::create_block_payload(Vec::new());
            ancestor_body_evicted = true;
            if prune_after_acceptance {
                // This source has a real, freshly accepted parent and an
                // already resolved output plan. Slot cleanup may advance while
                // its child handoff is still in flight, as during catch-up.
                processor.consensus.prune_below(SlotIndex::new(1000));
                assert!(
                    processor.consensus.accepted_ancestor_approval_contains_for_test(&chain[0].0),
                    "retained sources must keep their actual accepted ancestor receipt"
                );
            }
        }
        for (draft, done) in std::mem::take(&mut *sink.0.lock().unwrap()) {
            if matches!(draft.finality, consensus_common::SessionFinality::Carrier(_)) {
                assert!(parent_accepted, "child final cannot precede parent node acceptance");
                let consensus_common::SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(
                    proof,
                )) = &draft.finality
                else {
                    unreachable!()
                };
                final_slots.insert(proof.slot);
            }
            done(Ok(UInt256::from([2; 32])));
        }
        processor.with_consensus_backend(|c, b| c.retry_pending_recursive_finalization(b));
        let acceptance = std::mem::take(sink.1.lock().unwrap().as_mut().unwrap());
        for (request, done) in acceptance {
            for _ in 0..3 {
                processor.with_consensus_backend(|c, b| c.retry_pending_recursive_finalization(b));
            }
            if request.block_id == chain[0].1.block_id {
                assert!(
                    !parent_accepted,
                    "replayed children must join one fresh accepted ancestor approval"
                );
                assert!(
                    sink.0.lock().unwrap().is_empty(),
                    "WAL custody does not release the WC child"
                );
                if !presealed_cold_plan {
                    assert!(
                        !processor.consensus.is_finalized_block(&chain[0].0),
                        "WAL custody cannot materialize the parent before node acceptance"
                    );
                }
                if !rejected_parent_acceptance {
                    done(Err(rtos_block::error!("injected parent node acceptance failure")));
                    if shared_approvals {
                        for id in [&trigger, &chain[4].0] {
                            assert_eq!(
                                processor.consensus.continuation_cursor_for_test(id),
                                Some(0),
                                "failed node acceptance must preserve the exact waiting position"
                            );
                        }
                    }
                    rejected_parent_acceptance = true;
                    std::thread::sleep(Duration::from_millis(270));
                    continue;
                }
                parent_accepted = true;
            }
            done(Ok(()));
        }
        if map.exists()
            && second_map.as_ref().is_none_or(|p| p.exists())
            && (!presealed_cold_plan || !pending_path.exists())
        {
            break;
        }
    }
    assert!(parent_accepted, "presealed obligations still require this boot's node acceptance");
    if let Some(original) = presealed_bytes {
        assert_eq!(
            std::fs::read(&map).unwrap(),
            original,
            "cold replay must preserve the exact original full output set"
        );
        assert!(!pending_path.exists(), "normal replay must finish the original intent");
    }
    if reuse_materialized_plan {
        assert!(ancestor_body_evicted, "regression must remove the already accepted ancestor body");
        assert!(
            map.exists(),
            "accepted ancestor reuse must finish the retained source with its complete output set"
        );
    }
    if prune_after_acceptance {
        processor.with_consensus_backend(|c, b| c.retry_pending_recursive_finalization(b));
        assert!(
            processor.consensus.finalized_pending_body_is_empty(),
            "all retained source plans must have finished before testing reclamation"
        );
        processor.consensus.prune_below(SlotIndex::new(1000));
        assert!(
            !processor.consensus.accepted_ancestor_approval_contains_for_test(&chain[0].0),
            "unreferenced old receipts must be reclaimed after source completion"
        );
    }
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&map).unwrap()).unwrap();
    assert_eq!(
        processor.callbacks.finality_retention_attempts(),
        if shared_approvals { 2 } else { 1 },
        "cold-recovery retries reuse only their own successful certificate-save phase"
    );
    let outputs = value["outputs"].as_array().unwrap();
    assert_eq!(outputs.len(), 2, "empty nodes produce no output; both nonempty ancestors do");
    for (index, role) in [(0, false), (2, true)] {
        assert!(
            outputs
                .iter()
                .any(|v| v["block_id"] == chain[index].1.block_id.to_string()
                    && v["is_final"] == role)
        );
    }
    assert_eq!(value["released"], false, "sealed handoff is not Delivered confirmation");
    if let Some(second_map) = second_map {
        assert!(second_map.exists(), "both original triggers must seal their complete output sets");
        let second: serde_json::Value =
            serde_json::from_slice(&std::fs::read(second_map).unwrap()).unwrap();
        let second_outputs = second["outputs"].as_array().unwrap();
        assert_eq!(
            second_outputs.len(),
            3,
            "the later child retains both ancestor approvals and its own Final"
        );
        for (index, role) in [(0, false), (2, false), (4, true)] {
            assert!(second_outputs
                .iter()
                .any(|v| v["block_id"] == chain[index].1.block_id.to_string()
                    && v["is_final"] == role));
        }
        assert_eq!(
            final_slots,
            std::collections::BTreeSet::from([3, 4]),
            "each FinalCert context still needs its separate original source handoff"
        );
    }
    drop(processor);
    db.close(None).unwrap();
}

#[test]
fn test_transport_certificate_rejection_bans_observer_peer_without_validator_index() {
    let mut fixture = TestFixture::new(4);
    fixture.drain_receiver_actions();
    let peer = rtos_block::KeyId::from_data([0x71; 32]);
    let cert = build_skip_certificate_tl(&SessionId::rand(), &fixture.nodes, 0, &[0, 1, 2]);
    fixture.processor.on_transport_certificate(peer.clone(), None, cert);
    let actions = fixture.drain_receiver_actions();
    assert_eq!(
        actions
            .iter()
            .filter(|action| matches!(action,
        ReceiverAction::BanPeerForBadSignature { peer: actual } if actual == &peer))
            .count(),
        1
    );
    assert!(!actions
        .iter()
        .any(|action| matches!(action, ReceiverAction::BanSourceForBadSignature { .. })));
    assert!(!fixture.processor.simplex_state.has_skip_certificate(SlotIndex::new(0)));
}

#[test]
fn test_transport_certificate_valid_observer_forwarding_is_accepted_without_ban() {
    let mut fixture = TestFixture::new(4);
    fixture.drain_receiver_actions();
    let peer = rtos_block::KeyId::from_data([0x71; 32]);
    let cert = build_skip_certificate_tl(&SessionId::default(), &fixture.nodes, 0, &[0, 1, 2]);
    fixture.processor.on_transport_certificate(peer, None, cert);
    fixture.drain_pending_async_db_results();
    assert!(fixture.processor.simplex_state.has_skip_certificate(SlotIndex::new(0)));
    assert!(!fixture.drain_receiver_actions().iter().any(|action| matches!(
        action,
        ReceiverAction::BanPeerForBadSignature { .. }
            | ReceiverAction::BanSourceForBadSignature { .. }
    )));
}

#[test]
fn test_transport_certificate_rejection_attributes_ban_to_transport_peer() {
    let mut fixture = TestFixture::new(4);
    fixture.drain_receiver_actions();
    let peer = rtos_block::KeyId::from_data([0x72; 32]);
    let cert = build_skip_certificate_tl(&SessionId::rand(), &fixture.nodes, 0, &[0, 1, 2]);
    fixture.processor.on_transport_certificate(peer.clone(), Some(1), cert);
    let actions = fixture.drain_receiver_actions();
    assert_eq!(
        actions
            .iter()
            .filter(|action| matches!(action,
        ReceiverAction::BanPeerForBadSignature { peer: actual } if actual == &peer))
            .count(),
        1
    );
    assert!(!actions
        .iter()
        .any(|action| matches!(action, ReceiverAction::BanSourceForBadSignature { .. })));
}

#[test]
fn test_transport_certificate_outside_ingress_window_does_not_ban() {
    let mut fixture = TestFixture::new(4);
    fixture.drain_receiver_actions();
    let slot = fixture.processor.simplex_state.first_too_new_vote_slot().value();
    let peer = rtos_block::KeyId::from_data([0x71; 32]);
    let cert = build_skip_certificate_tl(&SessionId::rand(), &fixture.nodes, slot, &[0, 1, 2]);
    fixture.processor.on_transport_certificate(peer, None, cert);
    assert!(!fixture.drain_receiver_actions().iter().any(|action| matches!(
        action,
        ReceiverAction::BanPeerForBadSignature { .. }
            | ReceiverAction::BanSourceForBadSignature { .. }
    )));
}

#[test]
fn test_candidate_query_fallback_reads_cold_disk_body_and_notar() {
    let mut fixture = TestFixture::new(4);
    let (_leader, id, candidate) = make_signed_block_broadcast(&fixture, 9, vec![7, 9, 11]);
    let wire = fixture.description.opts().wire_profile.serialize(&candidate).unwrap();
    let vote = crate::simplex_state::NotarizeVote { slot: id.slot, block_hash: id.hash.clone() };
    let signed_vote = crate::simplex_state::Vote::Notarize(vote.clone());
    let bytes = crate::utils::create_data_to_sign(
        fixture.processor.session_id(),
        &crate::utils::serialize_unsigned_vote(
            &crate::utils::vote_to_tl_unsigned(&signed_vote).unwrap(),
        ),
    );
    let cert = crate::certificate::Certificate {
        vote,
        signatures: [0, 1, 2]
            .iter()
            .map(|&i| crate::certificate::VoteSignature {
                validator_idx: ValidatorIndex::new(i as u32),
                signature: fixture.nodes[i].public_key.sign(&bytes).unwrap().to_vec(),
            })
            .collect(),
    };
    let db = fixture.processor.database.db().clone();
    db.save_candidate_payload_async(&id, &wire).unwrap().wait().unwrap();
    db.save_notar_cert_async(&id, &cert).unwrap().wait().unwrap();
    assert!(!fixture.processor.candidate_book().contains_received(&id));
    assert!(fixture.processor.candidate_book().cached_data(&id).is_none());
    assert!(fixture.processor.simplex_state.get_notarize_certificate(id.slot, &id.hash).is_none());
    let (tx, rx) = channel();
    fixture.processor.handle_candidate_query_fallback(
        id.slot,
        id.hash.clone(),
        true,
        true,
        Box::new(move |result| tx.send(result).unwrap()),
    );
    let result = rx.recv_timeout(Duration::from_secs(5)).unwrap().unwrap();
    let response = fixture
        .description
        .opts()
        .wire_profile
        .deserialize_typed::<CandidateAndCert>(result.data())
        .unwrap();
    assert_eq!(response.candidate(), &wire);
    assert_eq!(
        response.notar(),
        &rtos_api::serialize_boxed(&cert.to_tl_vote_signature_set()).unwrap()
    );
    assert!(
        !fixture.processor.candidate_book().contains_received(&id),
        "serving disk bytes alone does not approve or finalize a candidate"
    );
}

#[test]
fn test_deferred_finality_repair_cannot_be_downgraded_by_ordinary_requests() {
    for finality_first in [false, true] {
        let mut fixture = TestFixture::new(4);
        fixture.run_pending_tasks();
        fixture.drain_receiver_actions();
        let slot = SlotIndex::new(69);
        let hash = UInt256::rand();
        skip_slot(&mut fixture, slot);
        for _ in 0..1000 {
            if finality_first {
                fixture.processor.with_consensus_backend(|_, b| {
                    b.request_candidate_for_finality(slot, hash.clone(), Some(Duration::ZERO))
                });
            }
            fixture.processor.with_validation_backend(|_, b| {
                b.request_candidate(slot, hash.clone(), Some(Duration::from_secs(5)))
            });
            if !finality_first {
                fixture.processor.with_consensus_backend(|_, b| {
                    b.request_candidate_for_finality(slot, hash.clone(), Some(Duration::ZERO))
                });
            }
        }
        assert_eq!(
            fixture.task_queue.tasks.lock().unwrap().len(),
            1,
            "one candidate keeps one owned queued repair"
        );
        fixture.run_pending_tasks();
        let rows: Vec<_> = fixture
            .drain_receiver_actions()
            .into_iter()
            .filter_map(|action| match action {
                ReceiverAction::RequestCandidate { slot: s, block_hash } if s == slot.value() => {
                    Some(block_hash)
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            rows,
            vec![hash],
            "ordinary delay/skip policy cannot downgrade the finality dependency"
        );
        assert!(fixture.processor.deferred_candidate_requests.lock().unwrap().is_empty());
    }
}

#[test]
fn test_query_repair_restores_absent_body_despite_retained_validation_decision() {
    for rejected in [false, true] {
        let mut fixture = TestFixture::new(4);
        let (leader, id, candidate) = make_signed_block_broadcast(&fixture, 9, vec![1, 3, 5, 7]);
        if rejected {
            fixture.processor.validation.insert_rejected(id.clone());
        } else {
            fixture.processor.validation.insert_approved(
                id.clone(),
                (
                    SystemTime::now(),
                    consensus_common::ConsensusCommonFactory::create_block_payload(Vec::new()),
                ),
            );
        }
        assert!(!fixture.processor.candidate_book().contains_received(&id));
        let notar = make_notar_vote_signature_set_bytes(
            fixture.processor.session_id(),
            &fixture.nodes,
            id.slot,
            id.hash.clone(),
            &[0, 1, 2],
        );
        fixture.processor.on_candidate_received(leader, candidate, Some(notar));
        assert!(
            fixture.processor.candidate_book().has_real_body(&id),
            "a retained validation decision is not the missing candidate body"
        );
        if rejected {
            assert!(
                fixture.processor.validation.is_rejected(&id),
                "data repair does not approve a rejected candidate"
            );
        } else {
            assert!(fixture.processor.validation.approved_contains(&id));
        }
    }
}

/// An own vote is published only after local accounting applied it, as the
/// reference applies an own vote before broadcasting it. A vote local state
/// rejects is still signed and journalled (the decision was made), but it never
/// reaches a peer, directly or through a certificate.
#[test]
fn own_vote_rejected_locally_is_never_published() {
    let h = crate::signing_coordinator::tests::Harness::custody(rtos_api::WireProfile::Legacy);
    h.description.install_coordinator(h.coordinator.clone()).unwrap();
    let mut processor =
        make_pq_processor_with_description_for_test(h.db.clone(), h.description.clone());
    let receiver = MockReceiver::new();
    processor.receiver = receiver.clone();
    let published = |actions: &[ReceiverAction]| {
        actions
            .iter()
            .filter(|a| {
                matches!(
                    a,
                    ReceiverAction::SendVote { .. } | ReceiverAction::SendCertificate { .. }
                )
            })
            .count()
    };

    let too_far = processor.simplex_state.first_too_new_vote_slot();
    let rejected =
        crate::simplex_state::Vote::Skip(crate::simplex_state::SkipVote { slot: too_far });
    processor.with_consensus_backend(|controller, backend| {
        controller.broadcast_vote_after_persist(backend, rejected)
    });
    assert_eq!(h.signature_count(), 1, "the decision is signed and journalled first");
    assert_eq!(published(&receiver.drain_actions()), 0, "a locally rejected vote must not be sent");

    let accepted = crate::simplex_state::Vote::Skip(crate::simplex_state::SkipVote {
        slot: SlotIndex::new(0),
    });
    processor.with_consensus_backend(|controller, backend| {
        controller.broadcast_vote_after_persist(backend, accepted)
    });
    assert_eq!(h.signature_count(), 2);
    let actions = receiver.drain_actions();
    assert_eq!(published(&actions), 1, "an applied own vote is sent exactly once");
    assert!(actions.iter().any(|a| matches!(a, ReceiverAction::SendVote { .. })));
}

// ============================================================================
// Finalization backpressure
// ============================================================================
//
// Every finalization attempt is tracked per candidate. An attempted candidate
// that has not finished, or that stopped for a reason retrying cannot mend,
// counts as pending; over the limit (or with any permanent stall) the group is
// told to stop producing, and told again when the backlog clears.

/// Workchain fixture with a recording listener and synchronous callbacks.
fn backlog_fixture(
) -> (TestFixture, Arc<RecordingListener>, Arc<dyn consensus_common::SessionListener + Send + Sync>)
{
    let mut opts = SessionOptions::default();
    opts.use_callback_thread = false;
    let mut fixture = TestFixture::new_with_shard_and_local_idx(
        4,
        0,
        ShardIdent::with_tagged_prefix(0, 0x8000_0000_0000_0000).unwrap(),
        opts,
    );
    let recording = RecordingListener::new();
    let listener: Arc<dyn consensus_common::SessionListener + Send + Sync> = recording.clone();
    fixture.processor.set_listener_for_test(Arc::downgrade(&listener));
    (fixture, recording, listener)
}

fn backlog_id(slot: u32) -> RawCandidateId {
    let mut hash = [0x5Au8; 32];
    hash[..4].copy_from_slice(&slot.to_le_bytes());
    RawCandidateId { slot: SlotIndex::new(slot), hash: UInt256::from(hash) }
}

/// Seed a received candidate (one seqno per slot) and, optionally, its
/// notarization certificate.
fn seed_backlog_node(
    fixture: &mut TestFixture,
    slot: u32,
    parent: Option<u32>,
    is_empty: bool,
    notarize: bool,
) -> RawCandidateId {
    let id = backlog_id(slot);
    let shard = fixture.description.get_shard().clone();
    let mut root = [0x11u8; 32];
    root[..4].copy_from_slice(&slot.to_le_bytes());
    let block_id = BlockIdExt::with_params(shard, slot, UInt256::from(root), UInt256::from(root));
    let received = crate::candidate_book::ReceivedCandidate {
        slot: id.slot,
        source_idx: ValidatorIndex::new(0),
        candidate_hash_data_bytes: vec![0xAB, slot as u8],
        block_id,
        root_hash: UInt256::from(root),
        file_hash: UInt256::from(root),
        data: consensus_common::ConsensusCommonFactory::create_block_payload(if is_empty {
            vec![]
        } else {
            vec![1u8, slot as u8]
        }),
        collated_data: consensus_common::ConsensusCommonFactory::create_block_payload(vec![]),
        gen_utime_ms: None,
        receive_time: SystemTime::now(),
        is_empty,
        parent_id: parent.map(backlog_id),
    };
    fixture.processor.candidate_book_mut().insert_received(id.clone(), received);
    if notarize {
        notarize_slot(fixture, id.slot, &id.hash);
    }
    id
}

fn finalize_backlog_trigger(fixture: &mut TestFixture, id: &RawCandidateId) {
    let block_id = fixture.processor.candidate_book().received(id).map(|r| r.block_id.clone());
    fixture.processor.handle_block_finalized(BlockFinalizedEvent {
        slot: id.slot,
        block_hash: id.hash.clone(),
        block_id,
        certificate: make_test_final_cert(id.slot, id.hash.clone()),
    });
}

fn retry_backlog(fixture: &mut TestFixture) {
    fixture.processor.with_consensus_backend(|consensus, backend| {
        consensus.retry_pending_recursive_finalization(backend)
    });
}

fn assert_backlog_counts_match_recount(fixture: &TestFixture) {
    let consensus = &fixture.processor.consensus;
    assert_eq!(
        consensus.recount_finalizations_for_test(),
        (consensus.pending_finalizations(), consensus.stalled_finalizations()),
        "incremental backlog counts must equal a full recount"
    );
}

/// A chain of `children` candidates above a root whose body has not arrived:
/// finalizing the top attempts every candidate down to the missing root.
fn seed_chain_over_missing_root(
    fixture: &mut TestFixture,
    root: u32,
    children: u32,
) -> RawCandidateId {
    let root_id = backlog_id(root);
    notarize_slot(fixture, root_id.slot, &root_id.hash);
    let mut top = root_id;
    for slot in root + 1..=root + children {
        top = seed_backlog_node(fixture, slot, Some(slot - 1), false, true);
    }
    top
}

fn is_stalled(state: Option<crate::consensus_controller::CandidateFinalization>) -> bool {
    matches!(state, Some(crate::consensus_controller::CandidateFinalization::StalledPermanently(_)))
}

#[test]
fn test_finalization_backlog_default_limit_and_override_parsing() {
    use crate::consensus_controller::parse_pending_finalizations_max as parse;
    assert_eq!(crate::consensus_controller::DEFAULT_PENDING_FINALIZATIONS_MAX, 16);
    assert_eq!(parse(None), 16);
    assert_eq!(parse(Some("3")), 3);
    assert_eq!(parse(Some("0")), 16, "zero is not a usable limit");
    assert_eq!(parse(Some("-1")), 16);
    assert_eq!(parse(Some("abc")), 16);
}

#[test]
fn test_finalization_backlog_sixteen_pending_keeps_producing() {
    let (mut fixture, _recording, _listener) = backlog_fixture();
    fixture.processor.consensus.set_pending_finalizations_max_for_test(16);
    let top = seed_chain_over_missing_root(&mut fixture, 40, 15);

    finalize_backlog_trigger(&mut fixture, &top);

    let consensus = &fixture.processor.consensus;
    assert_eq!(consensus.pending_finalizations(), 16, "15 children + the missing root");
    assert!(!consensus.backlog_over_limit(), "16 is not over the limit of 16");
    assert!(!fixture.processor.simplex_state.finality_behind());
    assert!(consensus.backlog_transitions_for_test().is_empty());
    assert_backlog_counts_match_recount(&fixture);
}

#[test]
fn test_finalization_backlog_seventeenth_stops_and_clears_at_root_completion() {
    let (mut fixture, recording, _listener) = backlog_fixture();
    fixture.processor.consensus.set_pending_finalizations_max_for_test(16);
    let top = seed_chain_over_missing_root(&mut fixture, 40, 16);

    finalize_backlog_trigger(&mut fixture, &top);

    assert_eq!(fixture.processor.consensus.pending_finalizations(), 17);
    assert!(fixture.processor.consensus.backlog_over_limit());
    assert!(fixture.processor.simplex_state.finality_behind(), "the FSM is told to stop");
    assert_eq!(fixture.processor.consensus.backlog_transitions_for_test(), &[(true, 17)]);
    assert_eq!(
        fixture.processor.consensus.candidate_finalization(&backlog_id(40)),
        Some(crate::consensus_controller::CandidateFinalization::Idle),
        "the missing root was attempted and is retried"
    );
    assert!(drain_finalized_events(&recording).is_empty());
    assert_backlog_counts_match_recount(&fixture);

    // The root arrives. Completions are applied ancestor first, so the backlog
    // clears exactly when the root's own attempt completes (17 -> 16).
    seed_backlog_node(&mut fixture, 40, None, false, true);
    retry_backlog(&mut fixture);

    let consensus = &fixture.processor.consensus;
    assert_eq!(consensus.backlog_transitions_for_test(), &[(true, 17), (false, 16)]);
    assert_eq!(consensus.pending_finalizations(), 0);
    assert!(!consensus.backlog_over_limit());
    assert!(!fixture.processor.simplex_state.finality_behind(), "the FSM produces again");
    assert!(!consensus.finalized_pending_body_contains(&top));
    for slot in 40..=56 {
        assert_eq!(
            consensus.candidate_finalization(&backlog_id(slot)),
            Some(crate::consensus_controller::CandidateFinalization::Finalized),
            "slot {slot}"
        );
    }
    assert_eq!(drain_finalized_events(&recording).len(), 17);
    assert_backlog_counts_match_recount(&fixture);
}

/// The backlog crossing logs one bounded snapshot of the held certificates,
/// lowest slot first, and nothing more while it stays over the limit.
#[test]
fn test_finalization_backlog_transition_logs_one_bounded_snapshot() {
    let (mut fixture, _recording, _listener) = backlog_fixture();
    fixture.processor.consensus.set_pending_finalizations_max_for_test(2);
    let top = seed_chain_over_missing_root(&mut fixture, 40, 40);

    finalize_backlog_trigger(&mut fixture, &top);
    retry_backlog(&mut fixture);
    retry_backlog(&mut fixture);

    let consensus = &fixture.processor.consensus;
    assert!(consensus.backlog_over_limit());
    let snapshots = consensus.backlog_snapshots_for_test();
    assert_eq!(snapshots.len(), 1, "only the transition is reported, not every attempt");
    let lines = &snapshots[0];
    assert_eq!(lines.len(), 33, "32 candidates and the count of the rest");
    assert_eq!(lines[32], "9 further held certificates not listed");
    let root = backlog_id(40);
    assert!(
        lines[0].starts_with(&format!(
            "candidate=s40:{} parent=none stage=idle trigger=false attempts=1 last_failure=",
            &root.hash.to_hex_string()[..8]
        )),
        "{}",
        lines[0]
    );
    assert!(!lines[0].ends_with("last_failure=none"), "{}", lines[0]);
    assert!(
        lines[1].contains(&format!("parent=s40:{}", &root.hash.to_hex_string()[..8])),
        "{}",
        lines[1]
    );
    for line in lines.iter().take(32) {
        assert!(line.len() < 512, "bounded line: {line}");
    }
}

#[test]
fn test_finalization_backlog_overlapping_triggers_count_shared_ancestors_once() {
    let (mut fixture, _recording, _listener) = backlog_fixture();
    fixture.processor.consensus.set_pending_finalizations_max_for_test(2);
    notarize_slot(&mut fixture, backlog_id(40).slot, &backlog_id(40).hash);
    let a = seed_backlog_node(&mut fixture, 41, Some(40), false, true);
    let b = seed_backlog_node(&mut fixture, 42, Some(41), false, true);

    finalize_backlog_trigger(&mut fixture, &a);
    assert_eq!(fixture.processor.consensus.pending_finalizations(), 2, "a + missing root");
    assert!(!fixture.processor.consensus.backlog_over_limit());

    finalize_backlog_trigger(&mut fixture, &b);
    let consensus = &fixture.processor.consensus;
    assert_eq!(consensus.pending_finalizations(), 3, "b, a and the root, each once");
    assert!(consensus.backlog_over_limit());
    assert!(consensus.finalization_attempts_for_test(&backlog_id(40)) >= 2);
    assert_eq!(consensus.finalization_attempts_for_test(&b), 1);
    assert_backlog_counts_match_recount(&fixture);
}

#[test]
fn test_finalization_backlog_partial_parent_completion() {
    let (mut fixture, recording, _listener) = backlog_fixture();
    let root = seed_backlog_node(&mut fixture, 40, None, false, true);
    // The middle candidate has no notarization certificate yet.
    let middle = seed_backlog_node(&mut fixture, 41, Some(40), false, false);
    let top = seed_backlog_node(&mut fixture, 42, Some(41), false, true);

    finalize_backlog_trigger(&mut fixture, &top);

    use crate::consensus_controller::CandidateFinalization;
    let consensus = &fixture.processor.consensus;
    assert_eq!(consensus.candidate_finalization(&root), Some(CandidateFinalization::Finalized));
    assert_eq!(consensus.candidate_finalization(&middle), Some(CandidateFinalization::Idle));
    assert_eq!(consensus.candidate_finalization(&top), Some(CandidateFinalization::Idle));
    assert_eq!(consensus.pending_finalizations(), 2, "a finished parent no longer counts");
    assert_eq!(drain_finalized_events(&recording).len(), 1, "only the root was handed off");
    assert_backlog_counts_match_recount(&fixture);

    notarize_slot(&mut fixture, middle.slot, &middle.hash);
    retry_backlog(&mut fixture);
    assert_eq!(fixture.processor.consensus.pending_finalizations(), 0);
    assert_eq!(fixture.processor.consensus.finalization_attempts_for_test(&middle), 2);
}

#[test]
fn test_finalization_backlog_retryable_handoff_failure_is_retried() {
    let (mut fixture, recording, _listener) = backlog_fixture();
    let only = seed_backlog_node(&mut fixture, 40, None, false, true);
    fixture.processor.consensus.inject_handoff_failures_for_test(1, 0);

    finalize_backlog_trigger(&mut fixture, &only);
    use crate::consensus_controller::CandidateFinalization;
    assert_eq!(
        fixture.processor.consensus.candidate_finalization(&only),
        Some(CandidateFinalization::Idle)
    );
    assert_eq!(fixture.processor.consensus.pending_finalizations(), 1);
    assert_eq!(fixture.processor.consensus.stalled_finalizations(), 0);
    assert!(drain_finalized_events(&recording).is_empty());

    retry_backlog(&mut fixture);
    assert_eq!(
        fixture.processor.consensus.candidate_finalization(&only),
        Some(CandidateFinalization::Finalized)
    );
    assert_eq!(fixture.processor.consensus.finalization_attempts_for_test(&only), 2);
    assert_eq!(fixture.processor.consensus.pending_finalizations(), 0);
    assert_eq!(drain_finalized_events(&recording).len(), 1);
}

#[test]
fn test_finalization_backlog_permanent_stall_propagates_and_is_never_retried() {
    let (mut fixture, recording, _listener) = backlog_fixture();
    let root = seed_backlog_node(&mut fixture, 40, None, false, true);
    let child = seed_backlog_node(&mut fixture, 41, Some(40), false, true);
    fixture.processor.consensus.inject_handoff_failures_for_test(0, 1);

    finalize_backlog_trigger(&mut fixture, &child);

    let consensus = &fixture.processor.consensus;
    assert!(is_stalled(consensus.candidate_finalization(&root)), "the failure is the root's");
    assert!(is_stalled(consensus.candidate_finalization(&child)), "and its dependents'");
    assert_eq!(consensus.stalled_finalizations(), 2);
    assert_eq!(consensus.pending_finalizations(), 2);
    assert!(consensus.backlog_over_limit(), "one stall is enough, whatever the limit");
    assert!(fixture.processor.simplex_state.finality_behind());
    assert!(consensus.finalized_pending_body_contains(&child), "kept, not dropped");
    assert!(drain_finalized_events(&recording).is_empty());
    let root_attempts = consensus.finalization_attempts_for_test(&root);

    // A second trigger on top of the stalled chain fails with it, without
    // another attempt on the stalled ancestors.
    let grandchild = seed_backlog_node(&mut fixture, 42, Some(41), false, true);
    finalize_backlog_trigger(&mut fixture, &grandchild);
    retry_backlog(&mut fixture);
    retry_backlog(&mut fixture);
    let consensus = &fixture.processor.consensus;
    assert!(is_stalled(consensus.candidate_finalization(&grandchild)));
    assert_eq!(consensus.finalization_attempts_for_test(&root), root_attempts);
    assert_eq!(consensus.finalization_attempts_for_test(&child), 1, "never retried");
    assert_eq!(consensus.finalization_attempts_for_test(&grandchild), 1);
    assert_eq!(consensus.stalled_finalizations(), 3);
    assert!(drain_finalized_events(&recording).is_empty());
    assert_backlog_counts_match_recount(&fixture);
}

#[test]
fn test_finalization_backlog_parent_cycle_is_kept_and_retried_until_repaired() {
    let (mut fixture, recording, _listener) = backlog_fixture();
    // Inconsistent local metadata: 41 names 42 as its parent and 42 names 41.
    let a = seed_backlog_node(&mut fixture, 41, Some(42), false, true);
    let b = seed_backlog_node(&mut fixture, 42, Some(41), false, true);

    finalize_backlog_trigger(&mut fixture, &b);

    use crate::consensus_controller::CandidateFinalization;
    let consensus = &fixture.processor.consensus;
    assert_eq!(consensus.candidate_finalization(&a), Some(CandidateFinalization::Idle));
    assert_eq!(consensus.candidate_finalization(&b), Some(CandidateFinalization::Idle));
    assert_eq!(consensus.pending_finalizations(), 2);
    assert_eq!(consensus.stalled_finalizations(), 0);
    assert!(consensus.finalized_pending_body_contains(&b), "a non-custody session keeps it too");

    // The repaired body names the real parent: the same trigger completes.
    seed_backlog_node(&mut fixture, 41, None, false, true);
    retry_backlog(&mut fixture);
    assert_eq!(fixture.processor.consensus.pending_finalizations(), 0);
    assert_eq!(drain_finalized_events(&recording).len(), 2);
}

#[test]
fn test_finalization_backlog_survives_pruning_and_eviction() {
    let (mut fixture, _recording, _listener) = backlog_fixture();
    let done = seed_backlog_node(&mut fixture, 40, None, false, true);
    finalize_backlog_trigger(&mut fixture, &done);
    let missing = backlog_id(50);
    notarize_slot(&mut fixture, missing.slot, &missing.hash);
    let waiting = seed_backlog_node(&mut fixture, 51, Some(50), false, true);
    finalize_backlog_trigger(&mut fixture, &waiting);
    assert_eq!(fixture.processor.consensus.pending_finalizations(), 2);
    assert_eq!(
        fixture.processor.consensus.durable_pending_floor(),
        Some(SlotIndex::new(0)),
        "an unresolved finalization pins the history for every session"
    );

    // A prune far above every slot releases only finalized entries.
    fixture.processor.consensus.prune_below(SlotIndex::new(10_000));
    let consensus = &fixture.processor.consensus;
    assert_eq!(consensus.candidate_finalization(&done), None, "finalized entry evicted");
    assert_eq!(consensus.pending_finalizations(), 2, "eviction changes no pending count");
    assert!(consensus.finalized_pending_body_contains(&waiting), "unresolved trigger kept");
    assert_eq!(consensus.finalization_status_len_for_test(), 2);
    assert_backlog_counts_match_recount(&fixture);
}

#[test]
fn test_finalization_backlog_chain_longer_than_former_depth_limit_progresses() {
    let mut opts = SessionOptions::default();
    opts.use_callback_thread = false;
    let mut fixture = TestFixture::new_with_opts(4, opts);
    let recording = RecordingListener::new();
    let listener: Arc<dyn consensus_common::SessionListener + Send + Sync> = recording.clone();
    fixture.processor.set_listener_for_test(Arc::downgrade(&listener));

    // A non-empty root under a run of empty candidates longer than the former
    // 100_000-candidate walk limit. The final certificate flows through the
    // empty run to the root, as in C++.
    let depth = 100_010u32;
    let root = seed_backlog_node(&mut fixture, 1, None, false, false);
    let mut top = root.clone();
    for slot in 2..=depth + 1 {
        top = seed_backlog_node(&mut fixture, slot, Some(slot - 1), true, false);
    }
    finalize_backlog_trigger(&mut fixture, &top);

    let consensus = &fixture.processor.consensus;
    assert!(!consensus.finalized_pending_body_contains(&top), "the deep chain completed");
    assert_eq!(consensus.pending_finalizations(), 0);
    assert_eq!(consensus.stalled_finalizations(), 0);
    let root_block = fixture.processor.candidate_book().received(&root).unwrap().block_id.clone();
    assert_eq!(drain_finalized_events(&recording), vec![(root_block, true)]);
}

#[test]
fn test_finality_behind_drops_own_vote_before_journal() {
    let h = crate::signing_coordinator::tests::Harness::custody(rtos_api::WireProfile::Legacy);
    h.description.install_coordinator(h.coordinator.clone()).unwrap();
    let mut processor =
        make_pq_processor_with_description_for_test(h.db.clone(), h.description.clone());
    let receiver = MockReceiver::new();
    processor.receiver = receiver.clone();
    let vote = crate::simplex_state::Vote::Skip(crate::simplex_state::SkipVote {
        slot: SlotIndex::new(0),
    });

    processor.simplex_state.set_finality_behind(processor.runtime.description(), true);
    processor.broadcast_vote(vote.clone());
    assert!(
        !receiver.drain_actions().iter().any(|a| matches!(a, ReceiverAction::SendVote { .. })),
        "a vote reaching the pool while finality is behind is not sent"
    );
    assert_eq!(h.signature_count(), 0, "nor signed or journalled");

    processor.simplex_state.set_finality_behind(processor.runtime.description(), false);
    processor.broadcast_vote(vote);
    assert!(receiver.drain_actions().iter().any(|a| matches!(a, ReceiverAction::SendVote { .. })));
    assert_eq!(h.signature_count(), 1);
}

#[test]
fn test_finality_behind_at_parent_ready_abandons_notarization_after_validation() {
    // C++ try_notarize checks may_vote right after WaitForParent; a backlog
    // present then gives the vote up even if it clears while validation runs.
    // Validation itself is not suppressed.
    for behind_at_parent_ready in [false, true] {
        let mut fixture = TestFixture::new(4);
        let id = RawCandidateId { slot: SlotIndex::new(0), hash: UInt256::rand() };
        let block = crate::block::BlockCandidate {
            id: BlockIdExt::with_params(
                ShardIdent::masterchain(),
                1,
                UInt256::rand(),
                UInt256::rand(),
            ),
            collated_file_hash: UInt256::rand(),
            data: vec![1, 2, 3],
            collated_data: vec![4, 5, 6],
            creator: fixture.nodes[0].public_key.clone().into(),
        };
        let raw = crate::block::RawCandidate::new(
            id.clone(),
            None,
            ValidatorIndex::new(0),
            block.clone(),
            vec![],
        );
        let time = fixture.description.get_time();
        insert_pending_validation(&mut fixture.processor, &id, raw, time);

        fixture
            .processor
            .simplex_state
            .set_finality_behind(fixture.processor.runtime.description(), behind_at_parent_ready);
        fixture.processor.check_validation();
        assert!(
            fixture.processor.validation.pending_approve_contains(&id),
            "validation proceeds whatever the backlog"
        );

        // The backlog clears before validation and storage complete.
        fixture
            .processor
            .simplex_state
            .set_finality_behind(fixture.processor.runtime.description(), false);
        while fixture.processor.simplex_state.pull_event().is_some() {}
        let candidate = crate::block::Candidate::new(
            crate::block::CandidateId {
                slot: id.slot,
                hash: id.hash.clone(),
                block: block.id.clone(),
            },
            None,
            ValidatorIndex::new(0),
            Some(block),
            vec![],
        );
        fixture.processor.feed_validated_candidate_to_fsm(candidate);
        let mut notar_votes = 0;
        while let Some(event) = fixture.processor.simplex_state.pull_event() {
            if matches!(
                event,
                crate::simplex_state::SimplexEvent::BroadcastVote(
                    crate::simplex_state::Vote::Notarize(_)
                )
            ) {
                notar_votes += 1;
            }
        }
        assert_eq!(notar_votes, usize::from(!behind_at_parent_ready));
        assert_eq!(
            fixture
                .processor
                .simplex_state
                .is_notarization_abandoned(&fixture.description, id.slot),
            behind_at_parent_ready
        );
    }
}

/// C++ pool.cpp handle_prospective_certificate: a certificate is broadcast only
/// after SaveCertificate succeeded. A certificate that could not be stored is
/// not relayed.
#[test]
fn test_handle_notarization_reached_does_not_relay_when_persist_fails() {
    let mut fixture = TestFixture::new(4);
    let slot = crate::block::SlotIndex::new(9);
    let block_hash = UInt256::rand();
    let signatures = vec![
        crate::certificate::VoteSignature::new(ValidatorIndex::new(0), vec![1]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(1), vec![2]),
        crate::certificate::VoteSignature::new(ValidatorIndex::new(2), vec![3]),
    ];
    let vote = crate::simplex_state::NotarizeVote { slot, block_hash: block_hash.clone() };
    let cert = Arc::new(crate::certificate::Certificate { vote, signatures });
    let event =
        crate::simplex_state::NotarizationReachedEvent { slot, block_hash, certificate: cert };

    fixture.processor.database.db().fail_next_notar_cert_save_for_test();
    fixture.processor.handle_notarization_reached(event);
    fixture.drain_pending_async_db_results();

    let actions = fixture.drain_receiver_actions();
    assert!(
        !actions.iter().any(|a| matches!(a, ReceiverAction::SendCertificate { .. })),
        "a certificate that was not stored must not be relayed"
    );
}

/*
    ========================================================================
    Votes refused before their intent while finality is behind (C++ Pool
    VoteCastOutcome, tos d590082e43)

    The C++ reference harness observes each vote at request, committed
    intent, committed signed record and verified broadcast, and requires each
    stage exactly once per recovered vote (memo evidence
    2026-10-20-a142-rust/cpp-runs-isolated). Here the same stages are the
    signing journal records, the signer calls and the receiver's sends.
    ========================================================================
*/

/// A signing-journal harness whose session has the C++ harness timing: four
/// slots per window, first block 0.3 s, target rate 0.4 s.
fn a142_harness() -> rtos_block::Result<crate::signing_coordinator::tests::Harness> {
    use crate::{
        pq_fixture as f,
        signing_coordinator::tests::{binding, custody_backend, custody_descriptor, Harness},
    };
    use std::os::unix::fs::PermissionsExt;
    // A real, public test key in custody: every vote is signed and verified for real.
    let root = std::env::temp_dir().join(format!("rtos-a142-{}", UInt256::rand()));
    std::fs::create_dir(&root)?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    let seed_path = root.join("public-test.seed");
    std::fs::write(&seed_path, [0x91u8; 32])?;
    std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600))?;
    let now_secs = SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() as u32;
    let custody = rtos_pq_consensus::PqConsensusCustody::load(
        UInt256::from([2; 32]),
        &[rtos_pq_consensus::ConfiguredKey { key_file: seed_path, valid_from: 0, expire_at: 0 }],
        now_secs,
    )?;
    let store = custody
        .held_keys(&UInt256::from([2; 32]))
        .values()
        .next()
        .map(|held| held.store.clone())
        .ok_or_else(|| error!("the test custody holds no key"))?;
    let (mut nodes, keys) = f::members();
    nodes[1] = crate::SimplexSessionNode::from_descriptor(&custody_descriptor(&store))?;
    let opts = SessionOptions {
        slots_per_leader_window: 4,
        first_block_timeout: Duration::from_millis(300),
        target_rate: Duration::from_millis(400),
        first_block_timeout_multiplier: 1.2,
        ..Default::default()
    };
    let description = Arc::new(
        SessionDescription::new(
            &opts,
            f::session(),
            42,
            &nodes,
            keys[1].clone(),
            &ShardIdent::masterchain(),
            SystemTime::now(),
            None,
        )?
        .bind_pq_session(7)?,
    );
    let db = crate::database::SimplexDb::open(root.join("db"), "own-signing")?;
    let mut journal_binding = binding(&description);
    journal_binding.expire_at = Some(u64::from(store.expire_at()));
    journal_binding.slots_per_window = 4;
    let coordinator = Arc::new(crate::signing_coordinator::SigningCoordinator::open(
        db.clone(),
        journal_binding,
        description.get_source_public_key(description.get_self_idx()).clone(),
        &root,
        true,
        custody_backend(&description, store.clone()),
    )?);
    description.install_coordinator(coordinator.clone())?;
    Ok(Harness {
        root,
        db,
        description,
        coordinator,
        calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        store: Some(store),
    })
}

fn a142_processor(
    h: &crate::signing_coordinator::tests::Harness,
) -> (SessionProcessor, Arc<MockReceiver>) {
    let mut processor =
        make_pq_processor_with_description_for_test(h.db.clone(), h.description.clone());
    let receiver = MockReceiver::new();
    processor.receiver = receiver.clone();
    (processor, receiver)
}

/// The votes the receiver was asked to send, in order.
fn sent_votes(receiver: &MockReceiver) -> rtos_block::Result<Vec<crate::simplex_state::Vote>> {
    let mut votes = Vec::new();
    for action in receiver.drain_actions() {
        if let ReceiverAction::SendVote { vote } = action {
            votes.push(crate::utils::extract_vote(&vote.into_boxed())?);
        }
    }
    Ok(votes)
}

/// The number of records in this node's signing journal (intents and signed votes).
fn journal_records(h: &crate::signing_coordinator::tests::Harness) -> rtos_block::Result<usize> {
    Ok(h.db.storage.get_by_prefix(crate::signing_coordinator::PREFIX.to_vec(), None).wait()?.len())
}

fn signer_calls(h: &crate::signing_coordinator::tests::Harness) -> usize {
    h.signature_count()
}

fn set_behind(processor: &mut SessionProcessor, behind: bool) {
    processor.simplex_state.set_finality_behind(processor.runtime.description(), behind);
}

fn skip_vote(slot: u32) -> crate::simplex_state::Vote {
    crate::simplex_state::Vote::Skip(crate::simplex_state::SkipVote { slot: SlotIndex::new(slot) })
}

/// bootstrap-suppressed and race-refused-then-clear: the startup skips are
/// requested while finality is fine, reach the gate after the backlog went
/// over and are refused before any intent: nothing is journalled, signed or
/// sent. The clear requests each exact vote again, and each is journalled,
/// signed and sent exactly once (C++: request, intent, signed and outgoing
/// once each for skips 0-3). Later toggles cast nothing more.
#[test]
fn test_refused_skips_are_journalled_signed_and_sent_once_after_the_clear() -> rtos_block::Result<()>
{
    let h = a142_harness()?;
    let (mut processor, receiver) = a142_processor(&h);
    let journal_before = journal_records(&h)?;
    assert_eq!(processor.simplex_state.generate_restart_skip_votes(WindowIndex::new(1), 4), 4);
    set_behind(&mut processor, true);
    processor.process_simplex_events();

    assert_eq!(sent_votes(&receiver)?, Vec::new(), "a refused skip is not sent");
    assert_eq!(signer_calls(&h), 0, "nor signed");
    assert_eq!(journal_records(&h)?, journal_before, "nor journalled");
    assert_eq!(processor.simplex_state.recovery_state().suppressed_votes, 4);

    set_behind(&mut processor, false);
    processor.process_simplex_events();
    let expected: Vec<_> = (0..4).map(skip_vote).collect();
    assert_eq!(sent_votes(&receiver)?, expected, "each exact vote once, in slot order");
    assert_eq!(signer_calls(&h), 4, "each signed once");
    assert!(journal_records(&h)? > journal_before, "and journalled");
    let journalled = journal_records(&h)?;

    set_behind(&mut processor, true);
    set_behind(&mut processor, false);
    processor.process_simplex_events();
    assert_eq!(sent_votes(&receiver)?, Vec::new(), "repeated toggles cast nothing more");
    assert_eq!(signer_calls(&h), 4);
    assert_eq!(journal_records(&h)?, journalled);
    Ok(())
}

/// The gate's outcome is machine-identifiable, and only skip and final votes
/// are kept: a refused notarize vote is reported but neither kept nor asked for
/// again. A vote past the gate is Submitted.
#[test]
fn test_vote_cast_outcome_and_kept_kinds() -> rtos_block::Result<()> {
    use crate::{
        consensus_controller::VoteCastOutcome,
        simplex_state::{NotarizeVote, Vote},
    };
    let h = a142_harness()?;
    let (mut processor, receiver) = a142_processor(&h);
    let desc = h.description.clone();
    processor.simplex_state.mark_slot_voted_on_restart(&desc, &skip_vote(1));
    let notarize = Vote::Notarize(NotarizeVote {
        slot: SlotIndex::new(2),
        block_hash: UInt256::from([7; 32]),
    });

    set_behind(&mut processor, true);
    let outcomes: Vec<_> = [notarize.clone(), skip_vote(1)]
        .into_iter()
        .map(|vote| {
            processor.with_consensus_backend(|controller, backend| {
                controller.broadcast_vote_after_persist(backend, vote)
            })
        })
        .collect();
    assert_eq!(
        outcomes,
        vec![
            VoteCastOutcome::SuppressedBeforeIntentFinalityBehind,
            VoteCastOutcome::SuppressedBeforeIntentFinalityBehind
        ]
    );
    assert_eq!(processor.simplex_state.recovery_state().suppressed_votes, 1, "only the skip");

    set_behind(&mut processor, false);
    processor.process_simplex_events();
    assert_eq!(sent_votes(&receiver)?, vec![skip_vote(1)], "the notarize vote is not resent");

    let outcome = processor.with_consensus_backend(|controller, backend| {
        controller.broadcast_vote_after_persist(backend, notarize)
    });
    assert_eq!(outcome, VoteCastOutcome::Submitted);
    Ok(())
}

/// Journal and signing failures happen at or after the intent boundary: they
/// stay Submitted, nothing is kept, and no backlog transition casts the vote
/// again.
#[test]
fn test_journal_failures_stay_submitted_and_are_never_retried() -> rtos_block::Result<()> {
    use crate::consensus_controller::VoteCastOutcome;
    for stage in [
        "before_intent",
        "after_intent",
        "before_sign",
        "after_sign",
        "before_signed",
        "after_signed",
    ] {
        let h = a142_harness()?;
        let (mut processor, receiver) = a142_processor(&h);
        let desc = h.description.clone();
        processor.simplex_state.mark_slot_voted_on_restart(&desc, &skip_vote(1));
        if let Ok(mut fail_at) = h.coordinator.fail_at.lock() {
            *fail_at = Some(stage);
        }
        let outcome = processor.with_consensus_backend(|controller, backend| {
            controller.broadcast_vote_after_persist(backend, skip_vote(1))
        });
        assert_eq!(outcome, VoteCastOutcome::Submitted, "{stage}");
        assert_eq!(processor.simplex_state.recovery_state().suppressed_votes, 0, "{stage}");
        if let Ok(mut fail_at) = h.coordinator.fail_at.lock() {
            *fail_at = None;
        }
        let calls = signer_calls(&h);
        set_behind(&mut processor, true);
        set_behind(&mut processor, false);
        processor.process_simplex_events();
        assert_eq!(sent_votes(&receiver)?, Vec::new(), "{stage}: not cast again");
        assert_eq!(signer_calls(&h), calls, "{stage}: not signed again");
    }
    Ok(())
}

/// race-final-after-clear, in the Rust shape: a final vote waits for its
/// notarization certificate to be durable; the backlog goes over before that
/// wait completes, so the vote reaches the gate behind and is refused. After
/// the clear the exact vote is requested again, signed and sent once
/// (C++: notarize once, final once, no skip).
#[test]
fn test_final_refused_after_its_durability_wait_is_cast_once_after_the_clear(
) -> rtos_block::Result<()> {
    use crate::simplex_state::{FinalizeVote, Vote};
    let h = a142_harness()?;
    let (mut processor, receiver) = a142_processor(&h);
    let desc = h.description.clone();
    let hash = UInt256::from([0x61; 32]);
    let final_vote =
        Vote::Finalize(FinalizeVote { slot: SlotIndex::new(0), block_hash: hash.clone() });
    processor.simplex_state.mark_slot_voted_on_restart(&desc, &final_vote);
    let id = RawCandidateId { slot: SlotIndex::new(0), hash };
    let pending = ManualAsyncResult::pending();
    processor.database.insert_notar_cert_store(id, pending.clone());

    processor.broadcast_vote(final_vote.clone());
    assert_eq!(processor.database.pending_count(), 1, "the final vote waits for durability");
    set_behind(&mut processor, true);
    pending.complete_ok();
    processor.process_pending_async_db_results();
    assert_eq!(sent_votes(&receiver)?, Vec::new());
    assert_eq!(signer_calls(&h), 0);
    assert_eq!(processor.simplex_state.recovery_state().suppressed_votes, 1);
    // A consumed storage result reports itself as taken, as the real one does.
    pending.complete_taken_sentinel();

    set_behind(&mut processor, false);
    processor.process_simplex_events();
    processor.process_pending_async_db_results();
    assert_eq!(sent_votes(&receiver)?, vec![final_vote], "the exact final vote once");
    assert_eq!(signer_calls(&h), 1);
    Ok(())
}

/// shutdown-pending and shutdown-suppressed: the group stops with a refused
/// skip kept, a final vote whose durability wait completes only during the
/// stop, and deferred skips of an expired timeout. The stop delivers the
/// pending callback, which is refused behind the backlog; a backlog clear
/// after the stop requests the kept and deferred votes, and none of them is
/// journalled, signed or sent (C++: nothing is cast by a stopped group).
#[test]
fn test_stopped_group_casts_nothing_it_kept_or_deferred() -> rtos_block::Result<()> {
    use crate::simplex_state::{FinalizeVote, Vote};
    let h = a142_harness()?;
    let (mut processor, receiver) = a142_processor(&h);
    let desc = h.description.clone();
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    desc.set_time(t0);
    processor.simplex_state.reset_timeouts_on_start(&desc);
    let hash = UInt256::from([0x62; 32]);
    let final_vote =
        Vote::Finalize(FinalizeVote { slot: SlotIndex::new(0), block_hash: hash.clone() });
    processor.simplex_state.mark_slot_voted_on_restart(&desc, &final_vote);
    processor.simplex_state.mark_slot_voted_on_restart(&desc, &skip_vote(1));
    let pending = ManualAsyncResult::pending();
    processor
        .database
        .insert_notar_cert_store(RawCandidateId { slot: SlotIndex::new(0), hash }, pending.clone());
    processor.broadcast_vote(final_vote);

    set_behind(&mut processor, true);
    processor.broadcast_vote(skip_vote(1));
    desc.set_time(t0 + Duration::from_millis(800));
    processor.simplex_state.check_all(&desc);
    processor.process_simplex_events();
    let kept = processor.simplex_state.recovery_state();
    assert_eq!((kept.suppressed_votes, kept.deferred_skip_slots), (1, 4), "{kept:?}");

    pending.complete_ok();
    processor.stop(false);
    assert_eq!(processor.simplex_state.recovery_state().suppressed_votes, 2, "refused in stop");

    set_behind(&mut processor, false);
    processor.process_simplex_events();
    processor.process_pending_async_db_results();
    assert_eq!(sent_votes(&receiver)?, Vec::new(), "nothing is sent by a stopped group");
    assert_eq!(signer_calls(&h), 0, "nor signed");
    Ok(())
}

/// The real backlog producer: the clear at the root's completion hands the
/// refused vote back to the FSM queue and wakes the main loop at once.
#[test]
fn test_backlog_clear_requeues_refused_votes_and_wakes_the_main_loop() {
    let (mut fixture, _recording, _listener) = backlog_fixture();
    fixture.processor.consensus.set_pending_finalizations_max_for_test(16);
    let top = seed_chain_over_missing_root(&mut fixture, 40, 16);
    finalize_backlog_trigger(&mut fixture, &top);
    assert!(fixture.processor.simplex_state.finality_behind());

    let desc = fixture.description.clone();
    let slot = fixture.processor.simplex_state.get_first_non_progressed_slot();
    let vote = crate::simplex_state::Vote::Skip(crate::simplex_state::SkipVote { slot });
    fixture.processor.simplex_state.mark_slot_voted_on_restart(&desc, &vote);
    while fixture.processor.simplex_state.pull_event().is_some() {}
    fixture.processor.broadcast_vote(vote.clone());
    assert_eq!(fixture.processor.simplex_state.recovery_state().suppressed_votes, 1);

    seed_backlog_node(&mut fixture, 40, None, false, true);
    fixture.processor.reset_next_awake_time();
    retry_backlog(&mut fixture);
    assert!(!fixture.processor.simplex_state.finality_behind());
    let mut requeued = Vec::new();
    while let Some(event) = fixture.processor.simplex_state.pull_event() {
        if let SimplexEvent::BroadcastVote(v) = event {
            requeued.push(v);
        }
    }
    assert!(requeued.contains(&vote), "the refused vote is requested again: {requeued:?}");
    assert!(
        fixture.processor.runtime.get_next_awake_time() <= fixture.processor.now(),
        "the main loop wakes to drain it"
    );
}
