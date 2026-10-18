// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! One bounded publication actor. Accepted blocking writes retain their real join
//! independently of the caller's response future. Idle loops never own Engine.
pub(crate) mod cleanup_projection;
pub(crate) mod cleanup_steps;
mod closing;
mod history_debt;
pub(crate) use history_debt::NodeHistoryDebt;

use crate::{
    engine::Engine,
    engine_traits::EngineOperations,
    propagation_outbox::{
        Limits, OutboxDomain, PropagationOutbox, PublicationEffect, PublicationKind,
        PublicationRecord, PublicationStage, PublicationTarget, RecordId, RecoveryOrigin,
        UnverifiedRecord,
    },
    propagation_outbox_auth::authenticate_publication,
    types::owned_tasks::OwnedTasks,
    validator::{
        accept_block::{accept_authenticated_publication, AcceptedSessionBlock},
        propagation::{
            PropagationDestination, PropagationEvent, PropagationKind, PropagationPlan,
            PropagationStatus, PropagationTarget,
        },
    },
};
use consensus_common::{
    finality_delivery::{
        CanonicalFinalityCompletion, CanonicalFinalityRecord, CanonicalFinalityRequest,
        CloseFinalityRequest, CloseOffer, DurableFinalitySink, DurableFinalitySinkPtr,
        FinalityCloseCompletion, FinalityCloseDomain, FinalityDeliveryRole,
        FinalityTerminalCompletion, FinalityTerminalLookup, FinalizedDeliveryCompletion,
        FinalizedDeliveryDraft,
    },
    session_runtime::{AuthenticatedSessionRuntime, LocalRole},
    simplex_protocol::SimplexProtocol,
    SessionFinality,
};
use futures::FutureExt;
use rtos_api::{pq_finality::PqNetworkSignatureSet, IntoBoxed};
use rtos_block::{error, fail, BlockSignaturesVariant, Result, UInt256};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, Weak,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio_util::sync::CancellationToken;

const QUEUE_CAPACITY: usize = 32;
const RETRY_INTERVAL: Duration = Duration::from_secs(1);
const HISTORY_TIMEOUT: Duration = Duration::from_secs(60);
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
struct LegacySubmission {
    record: PublicationRecord,
    response: Responder<Result<AcceptedSessionBlock>>,
}

/// Accepted-but-uncompleted requests per session. A request counts from
/// before it is enqueued until its callback or response has been delivered.
pub(crate) struct OutstandingRequests(Mutex<OutstandingState>);
#[derive(Default)]
struct OutstandingState {
    counts: std::collections::HashMap<UInt256, usize>,
    /// A broken invariant (an extra release): no session is ever quiescent
    /// again in this process.
    poisoned: bool,
}
impl OutstandingRequests {
    fn lock(&self) -> std::sync::MutexGuard<'_, OutstandingState> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }
    /// Counts one request of `session`; a count that cannot grow refuses it.
    fn begin(self: &Arc<Self>, session: &UInt256) -> Result<Outstanding> {
        let mut state = self.lock();
        let count = state.counts.entry(session.clone()).or_insert(0);
        *count = count
            .checked_add(1)
            .ok_or_else(|| error!("Outstanding publication requests exhausted"))?;
        Ok(Outstanding { map: self.clone(), session: session.clone() })
    }
    /// Requests of `session` still outstanding; `usize::MAX` once poisoned.
    pub(crate) fn count(&self, session: &UInt256) -> usize {
        let state = self.lock();
        if state.poisoned {
            return usize::MAX;
        }
        state.counts.get(session).copied().unwrap_or(0)
    }
    #[cfg(test)]
    fn set_for_test(&self, session: &UInt256, count: usize) {
        self.lock().counts.insert(session.clone(), count);
    }
}
impl Default for OutstandingRequests {
    fn default() -> Self {
        Self(Mutex::new(OutstandingState::default()))
    }
}
/// One outstanding request; dropping it ends the count.
pub(crate) struct Outstanding {
    map: Arc<OutstandingRequests>,
    session: UInt256,
}
impl Drop for Outstanding {
    fn drop(&mut self) {
        let mut state = self.map.lock();
        match state.counts.get_mut(&self.session) {
            Some(count) if *count > 0 => {
                *count -= 1;
                if *count == 0 {
                    state.counts.remove(&self.session);
                }
            }
            _ => {
                if !state.poisoned {
                    log::error!(
                        "Outstanding publication request count underflow; cleanup projections refused"
                    );
                }
                state.poisoned = true;
            }
        }
    }
}
/// A oneshot response that ends its request's outstanding count only after
/// the value was handed over.
struct Responder<T> {
    sender: oneshot::Sender<T>,
    outstanding: Option<Outstanding>,
}
impl<T> Responder<T> {
    fn new(sender: oneshot::Sender<T>) -> Self {
        Self { sender, outstanding: None }
    }
    fn send(self, value: T) -> std::result::Result<(), T> {
        let Self { sender, outstanding } = self;
        let sent = sender.send(value);
        drop(outstanding);
        sent
    }
}
/// Wraps a callback so the request stays outstanding until it has run,
/// including while it unwinds.
fn hold<T: 'static>(callback: &mut Option<Box<dyn FnOnce(Result<T>) + Send>>, token: Outstanding) {
    if let Some(inner) = callback.take() {
        *callback = Some(Box::new(move |result| {
            let _token = token;
            inner(result);
        }));
    }
}
// The callback guard also completes rejected queued requests during an actor panic.
struct Completion(Option<FinalizedDeliveryCompletion>);
impl Completion {
    fn finish(mut self, result: Result<UInt256>) {
        if let Some(callback) = self.0.take() {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| callback(result)));
        }
    }
}
impl Drop for Completion {
    fn drop(&mut self) {
        if let Some(callback) = self.0.take() {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                callback(Err(error!("Publication owner stopped before Draft WAL")))
            }));
        }
    }
}
struct CanonicalCompletion(Option<CanonicalFinalityCompletion>);
impl CanonicalCompletion {
    fn finish(mut self, result: Result<CanonicalFinalityRecord>) {
        if let Some(callback) = self.0.take() {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| callback(result)));
        }
    }
}
impl Drop for CanonicalCompletion {
    fn drop(&mut self) {
        if let Some(callback) = self.0.take() {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                callback(Err(error!("Publication owner stopped before canonical retention")))
            }));
        }
    }
}
/// Accepted closing callbacks retain the actor's real IO owner. Admission
/// rejection disarms this guard, as with the existing source draft callback.
struct ClosingCompletion<T>(Option<Box<dyn FnOnce(Result<T>) + Send>>);
impl<T> ClosingCompletion<T> {
    fn finish(mut self, result: Result<T>) {
        if let Some(callback) = self.0.take() {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| callback(result)));
        }
    }
}
impl<T> Drop for ClosingCompletion<T> {
    fn drop(&mut self) {
        if let Some(callback) = self.0.take() {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                callback(Err(error!("Publication close owner stopped before durable completion")))
            }));
        }
    }
}
enum Submission {
    #[cfg(test)]
    RetryBackground { response: oneshot::Sender<Result<()>> },
    Acceptance {
        request: CanonicalFinalityRequest,
        runtime: Arc<AuthenticatedSessionRuntime>,
        queued_at: std::time::Instant,
        completion: ClosingCompletion<()>,
    },
    HistoryDebt {
        request: CloseFinalityRequest,
        runtime: Arc<AuthenticatedSessionRuntime>,
        budget: Arc<crate::history_read_budget::HistoryReadBudget>,
        response: Responder<Result<NodeHistoryDebt>>,
    },
    Terminal {
        request: CloseFinalityRequest,
        runtime: Arc<AuthenticatedSessionRuntime>,
        completion: ClosingCompletion<FinalityTerminalLookup>,
    },
    OfferClose {
        request: CloseFinalityRequest,
        runtime: Arc<AuthenticatedSessionRuntime>,
        completion: ClosingCompletion<CloseOffer>,
    },
    SourceDelivered {
        confirmation: simplex::finality_delivery::DeliveredConfirmation,
        runtime: Arc<AuthenticatedSessionRuntime>,
        completion: ClosingCompletion<()>,
    },
    Canonical {
        request: CanonicalFinalityRequest,
        runtime: Arc<AuthenticatedSessionRuntime>,
        completion: CanonicalCompletion,
    },
    Legacy(LegacySubmission),
    Draft {
        record: PublicationRecord,
        last_mc: u32,
        candidate_already_sent: bool,
        completion: Completion,
        origin: RecoveryOrigin,
        historical: bool,
    },
    Query {
        id: UInt256,
        response: oneshot::Sender<Result<AcceptedSessionBlock>>,
    },
    /// One journaled deletion step, run as one owner transition.
    /// `ownership` is the attempt's reservation share, dropped only once the
    /// transition has returned (or the submission was rejected).
    Cleanup {
        step: cleanup_steps::CleanupStep,
        ownership: Arc<dyn std::any::Any + Send + Sync>,
        response: oneshot::Sender<Result<cleanup_steps::CleanupStepOutcome>>,
    },
}

enum WorkerTurn {
    Stop,
    Command(Option<Submission>),
    Retry,
}

async fn next_worker_turn(
    stop: &CancellationToken,
    tick: &mut tokio::time::Interval,
    receiver: &mut mpsc::Receiver<Submission>,
    wake: &Notify,
) -> WorkerTurn {
    // Keep the mailbox FIFO moving before taking another eager repair turn.
    // The original periodic retry still wins when due, including under a busy
    // mailbox, so cold/expired/Completed repair and sends cannot starve.
    tokio::select! {
        biased;
        _ = stop.cancelled() => WorkerTurn::Stop,
        _ = tick.tick() => WorkerTurn::Retry,
        command = receiver.recv() => WorkerTurn::Command(command),
        _ = wake.notified() => WorkerTurn::Retry,
    }
}

impl Submission {
    fn reject(self) {
        match self {
            #[cfg(test)]
            Self::RetryBackground { response } => {
                let _ = response.send(Err(error!("Publication retry test shutdown")));
            }
            Self::HistoryDebt { response, .. } => {
                let _ = response.send(Err(error!("Publication history admission shutdown")));
            }
            Self::Terminal { completion, .. } => {
                completion.finish(Err(error!("Publication closing shutdown")))
            }
            Self::OfferClose { completion, .. } => {
                completion.finish(Err(error!("Publication closing shutdown")))
            }
            Self::SourceDelivered { completion, .. } => {
                completion.finish(Err(error!("Publication closing shutdown")))
            }
            Self::Acceptance { completion, .. } => {
                completion.finish(Err(error!("Publication acceptance shutdown")))
            }
            Self::Canonical { completion, .. } => {
                completion.finish(Err(error!("Publication retention shutdown")))
            }
            Self::Legacy(request) => {
                let _ = request
                    .response
                    .send(Err(error!("Publication shutdown before durable admission")));
            }
            Self::Draft { completion, .. } => {
                completion.finish(Err(error!("Publication shutdown before durable admission")))
            }
            Self::Query { response, .. } => {
                let _ = response.send(Err(error!("Publication query shutdown")));
            }
            Self::Cleanup { response, .. } => {
                let _ = response.send(Err(error!("Publication cleanup step shutdown")));
            }
        }
    }
    /// Counts this request as outstanding for its session before it is
    /// enqueued. The count ends when its callback or response is delivered,
    /// or when a rejected request is dropped.
    fn track(&mut self, outstanding: &Arc<OutstandingRequests>) -> Result<()> {
        match self {
            Self::Terminal { runtime, completion, .. } => {
                hold(&mut completion.0, outstanding.begin(runtime.session_id())?)
            }
            Self::OfferClose { runtime, completion, .. } => {
                hold(&mut completion.0, outstanding.begin(runtime.session_id())?)
            }
            Self::SourceDelivered { runtime, completion, .. } => {
                hold(&mut completion.0, outstanding.begin(runtime.session_id())?)
            }
            Self::Acceptance { runtime, completion, .. } => {
                hold(&mut completion.0, outstanding.begin(runtime.session_id())?)
            }
            Self::Canonical { runtime, completion, .. } => {
                hold(&mut completion.0, outstanding.begin(runtime.session_id())?)
            }
            Self::Draft { record, completion, .. } => {
                hold(&mut completion.0, outstanding.begin(&record.session_id)?)
            }
            Self::HistoryDebt { runtime, response, .. } => {
                response.outstanding = Some(outstanding.begin(runtime.session_id())?)
            }
            Self::Legacy(request) => {
                request.response.outstanding = Some(outstanding.begin(&request.record.session_id)?)
            }
            #[cfg(test)]
            Self::RetryBackground { .. } => {}
            Self::Query { .. } | Self::Cleanup { .. } => {}
        }
        Ok(())
    }
    /// A request that was not admitted: its callback must not run.
    fn disarm(self) {
        match self {
            Self::Terminal { mut completion, .. } => {
                completion.0.take();
            }
            Self::OfferClose { mut completion, .. } => {
                completion.0.take();
            }
            Self::SourceDelivered { mut completion, .. } => {
                completion.0.take();
            }
            Self::Draft { mut completion, .. } => {
                completion.0.take();
            }
            Self::Acceptance { mut completion, .. } => {
                completion.0.take();
            }
            Self::Canonical { mut completion, .. } => {
                completion.0.take();
            }
            _ => {}
        }
    }
}
struct SessionSink {
    worker: Arc<PublicationWorker>,
    runtime: Arc<AuthenticatedSessionRuntime>,
    historical: bool,
}
impl DurableFinalitySink for SessionSink {
    fn await_accepted(
        &self,
        request: CanonicalFinalityRequest,
        completion: Box<dyn FnOnce(Result<()>) + Send>,
    ) -> Result<()> {
        self.worker.admit_draft(Submission::Acceptance {
            request, runtime: self.runtime.clone(), queued_at: std::time::Instant::now(),
            completion: ClosingCompletion(Some(completion)),
        })
    }
    fn lookup_terminal(
        &self,
        request: CloseFinalityRequest,
        completion: FinalityTerminalCompletion,
    ) -> Result<()> {
        self.worker.admit_draft(Submission::Terminal {
            request,
            runtime: self.runtime.clone(),
            completion: ClosingCompletion(Some(completion)),
        })
    }
    fn offer_close(
        &self,
        request: CloseFinalityRequest,
        completion: FinalityCloseCompletion,
    ) -> Result<()> {
        self.worker.admit_draft(Submission::OfferClose {
            request,
            runtime: self.runtime.clone(),
            completion: ClosingCompletion(Some(completion)),
        })
    }

    fn retain_canonical(
        &self,
        request: CanonicalFinalityRequest,
        completion: CanonicalFinalityCompletion,
    ) -> Result<()> {
        self.worker.admit_draft(Submission::Canonical {
            request,
            runtime: self.runtime.clone(),
            completion: CanonicalCompletion(Some(completion)),
        })
    }
    fn stage(
        &self,
        draft: FinalizedDeliveryDraft,
        completion: FinalizedDeliveryCompletion,
    ) -> Result<()> {
        let record = live_record(&self.runtime, &draft, &self.worker.state.limits)?;
        let request = Submission::Draft {
            record,
            last_mc: draft.last_mc_finalized_seqno,
            candidate_already_sent: draft.candidate_already_sent,
            completion: Completion(Some(completion)),
            origin: RecoveryOrigin {
                carrier_version: self.runtime.carrier_version(),
                local_adnl: UInt256::from(*self.runtime.local_adnl().data()),
                source_validator: UInt256::from(*draft.source_info.source.id().data()),
                local_validator_index: match self.runtime.local_role() {
                    LocalRole::Validator(index) => Some(index),
                    LocalRole::Observer => None,
                },
            },
            historical: self.historical,
        };
        // On admission failure the source owns retry and completion must not run.
        self.worker.admit_draft(request)
    }
}
#[derive(Clone)]
struct WorkerActivity {
    phase: &'static str,
    record: Option<(u64, String)>,
    since: std::time::Instant,
}
impl Default for WorkerActivity {
    fn default() -> Self {
        Self { phase: "idle", record: None, since: std::time::Instant::now() }
    }
}
/// A lexical activity scope: nested WAL work restores the owning accept phase.
/// No mutex guard is held across an await or while a source callback runs.
struct ActivityScope<'a> {
    activity: &'a Mutex<WorkerActivity>,
    previous: Option<WorkerActivity>,
}
impl ActivityScope<'_> {
    fn phase(&self, phase: &'static str) {
        let mut current = self.activity.lock().unwrap_or_else(|p| p.into_inner());
        current.phase = phase;
        current.since = std::time::Instant::now();
    }
}
impl Drop for ActivityScope<'_> {
    fn drop(&mut self) {
        *self.activity.lock().unwrap_or_else(|p| p.into_inner()) = self.previous.take().unwrap();
    }
}
// C++ state-resolver keeps completed typed resolution results. Keep the
// corresponding receipt process-local, bounded, and separate from disk stage
// flags: an Accepted/Completed flag alone never constructs a verified receipt.
#[derive(Default)]
struct AcceptanceCache {
    entries: std::collections::BTreeMap<u64, CachedAcceptance>,
    order: std::collections::VecDeque<u64>,
    payload_bytes: usize,
}
struct CachedAcceptance {
    record: Arc<PublicationRecord>,
    accepted: AcceptedSessionBlock,
    payload_bytes: usize,
}
impl AcceptanceCache {
    fn get(
        &mut self,
        entry: &UnverifiedRecord,
        engine: &dyn EngineOperations,
    ) -> Result<Option<AcceptedSessionBlock>> {
        if !matches!(
            entry.stage,
            PublicationStage::AcceptedDraft | PublicationStage::Ready | PublicationStage::Completed
        ) {
            return Ok(None);
        }
        let Some(cached) = self.entries.get(&entry.id.0) else { return Ok(None) };
        // Full immutable content/role/domain binding, including effects. A
        // changed plan takes the normal acceptance path unless this actor has
        // updated the cache after its own authenticated, durable resolution.
        if cached.record != entry.record {
            return Ok(None);
        }
        let receipt = cached.accepted.current_receipt(engine)?;
        if receipt.is_some() {
            self.order.retain(|id| *id != entry.id.0);
            self.order.push_back(entry.id.0);
        }
        Ok(receipt)
    }
    fn insert(
        &mut self,
        id: RecordId,
        record: Arc<PublicationRecord>,
        accepted: &AcceptedSessionBlock,
        limits: &Limits,
    ) {
        self.remove(id.0);
        let payload_bytes = record
            .block_data
            .len()
            .saturating_add(record.proof_data.as_ref().map_or(0, Vec::len))
            .saturating_add(record.carrier.bytes().len().saturating_mul(2))
            .saturating_add(accepted.block().data().len())
            .saturating_add(accepted.proof().data().len())
            .saturating_add(
                record
                    .effects
                    .iter()
                    .map(|effect| match &effect.target {
                        PublicationTarget::Custom(name) => name.len(),
                        _ => 0,
                    })
                    .sum::<usize>(),
            );
        if limits.max_records == 0 || payload_bytes > limits.max_snapshot_bytes {
            return;
        }
        while self.entries.len() >= limits.max_records
            || self.payload_bytes.saturating_add(payload_bytes) > limits.max_snapshot_bytes
        {
            let Some(oldest) = self.order.front().copied() else { break };
            self.remove(oldest);
        }
        self.entries
            .insert(id.0, CachedAcceptance { record, accepted: accepted.clone(), payload_bytes });
        self.order.push_back(id.0);
        self.payload_bytes += payload_bytes;
    }
    fn resolved_routing(
        &mut self,
        before: &UnverifiedRecord,
        effects: Vec<PublicationEffect>,
        limits: &Limits,
    ) {
        if before.stage != PublicationStage::AcceptedDraft {
            return;
        }
        let Some(cached) = self.entries.get(&before.id.0) else { return };
        if cached.record != before.record {
            return;
        }
        let accepted = cached.accepted.clone();
        let mut record = before.record.clone();
        Arc::make_mut(&mut record).effects = effects;
        self.insert(before.id, record, &accepted, limits);
    }
    fn remove(&mut self, id: u64) {
        if let Some(old) = self.entries.remove(&id) {
            self.payload_bytes -= old.payload_bytes;
        }
        self.order.retain(|old| *old != id);
    }
}
struct State {
    activity: Mutex<WorkerActivity>,
    engine: Weak<Engine>,
    io: Arc<OwnedTasks>,
    enabled: AtomicBool,
    fatal: AtomicBool,
    stop: CancellationToken,
    wake: Notify,
    limits: Limits,
    ready: tokio::sync::watch::Sender<Option<std::result::Result<(), String>>>,
    cursor: Mutex<(u64, std::collections::BTreeMap<u64, usize>)>,
    acceptance_turn: AtomicBool,
    acceptance_verified: Mutex<std::collections::BTreeSet<u64>>,
    accepted_receipts: Mutex<AcceptanceCache>,
    #[cfg(test)]
    acceptance_request_runs: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    actual_acceptance_runs: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    background_acceptance_runs: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    background_routing_turns: std::sync::atomic::AtomicUsize,
    acceptance_cursor: Mutex<u64>,
    acceptance_retry: Mutex<std::collections::BTreeMap<u64, tokio::time::Instant>>,
    retry_after: Mutex<std::collections::BTreeMap<(u64, PublicationEffect), tokio::time::Instant>>,
    outstanding: Arc<OutstandingRequests>,
    #[cfg(test)]
    cleanup_commit_hook:
        Mutex<Option<Arc<dyn Fn(&crate::propagation_outbox::PropagationOutbox) + Send + Sync>>>,
}
pub(crate) struct PublicationWorker {
    sender: Mutex<Option<mpsc::Sender<Submission>>>,
    tasks: Arc<OwnedTasks>,
    state: Arc<State>,
}
impl PublicationWorker {
    pub(crate) fn start(engine: &Arc<Engine>, domain: OutboxDomain) -> Result<Arc<Self>> {
        let (sender, receiver) = mpsc::channel(QUEUE_CAPACITY);
        let state = Arc::new(State {
            activity: Mutex::new(WorkerActivity::default()),
            engine: Arc::downgrade(engine),
            io: Arc::new(OwnedTasks::default()),
            enabled: AtomicBool::new(false),
            fatal: AtomicBool::new(false),
            stop: CancellationToken::new(),
            wake: Notify::new(),
            limits: Limits::default(),
            ready: tokio::sync::watch::channel(None).0,
            cursor: Mutex::new(Default::default()),
            acceptance_turn: AtomicBool::new(true),
            acceptance_verified: Mutex::new(Default::default()),
            accepted_receipts: Mutex::new(Default::default()),
            #[cfg(test)]
            acceptance_request_runs: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            actual_acceptance_runs: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            background_acceptance_runs: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            background_routing_turns: std::sync::atomic::AtomicUsize::new(0),
            acceptance_cursor: Mutex::new(0),
            acceptance_retry: Mutex::new(Default::default()),
            retry_after: Mutex::new(Default::default()),
            outstanding: Default::default(),
            #[cfg(test)]
            cleanup_commit_hook: Mutex::new(None),
        });
        let tasks = Arc::new(OwnedTasks::default());
        let result = Arc::new(Self {
            sender: Mutex::new(Some(sender)),
            tasks: tasks.clone(),
            state: state.clone(),
        });
        let db = engine.db().clone();
        tasks.spawn("publication actor", async move {
            let task = async {
                let limits = state.limits.clone();
                let opened =
                    state.blocking(move || PropagationOutbox::open(db, domain, limits)).await;
                match opened {
                    Ok(store) => {
                        state.ready.send_replace(Some(Ok(())));
                        state.clone().run(store, receiver).await;
                    }
                    Err(error) => {
                        state.ready.send_replace(Some(Err(error.to_string())));
                        state.fatal(format!("Publication outbox open: {error}"));
                    }
                }
            };
            if std::panic::AssertUnwindSafe(task).catch_unwind().await.is_err() {
                state.ready.send_replace(Some(Err("Publication actor panicked".into())));
                state.fatal("Publication actor panicked".into());
            }
        })?;
        Ok(result)
    }
    pub(crate) async fn ready(&self) -> Result<()> {
        let mut receiver = self.state.ready.subscribe();
        loop {
            if let Some(result) = receiver.borrow().clone() {
                return result.map_err(|message| error!("Publication startup: {message}"));
            }
            receiver
                .changed()
                .await
                .map_err(|error| error!("Publication startup owner: {error}"))?;
        }
    }
    pub(crate) fn enable(&self) {
        self.state.enabled.store(true, Ordering::Release);
        self.state.wake.notify_one();
    }
    pub(crate) async fn submit(&self, record: PublicationRecord) -> Result<AcceptedSessionBlock> {
        let probe = UnverifiedRecord {
            id: RecordId(1),
            stage: PublicationStage::Prepared,
            pending: record.effects.clone(),
            record: Arc::new(record),
        };
        crate::propagation_outbox::validate_recovery_record(&probe, &self.state.limits)?;
        validate_plan(&probe)?;
        let record = Arc::unwrap_or_clone(probe.record);
        let (response, result) = oneshot::channel();
        {
            let sender =
                self.sender.lock().map_err(|_| error!("Publication submission lock poisoned"))?;
            if self.state.fatal.load(Ordering::Acquire) || self.state.stop.is_cancelled() {
                fail!("Publication worker is stopped or failed");
            }
            let mut request =
                Submission::Legacy(LegacySubmission { record, response: Responder::new(response) });
            request.track(&self.state.outstanding)?;
            sender
                .as_ref()
                .ok_or_else(|| error!("Publication admission closed"))?
                .try_send(request)
                .map_err(|error| error!("Publication queue admission: {error}"))?;
        }
        result.await.map_err(|error| error!("Publication actor completion: {error}"))?
    }
    pub(crate) fn sink(
        self: &Arc<Self>,
        runtime: Arc<AuthenticatedSessionRuntime>,
    ) -> DurableFinalitySinkPtr {
        Arc::new(SessionSink { worker: self.clone(), runtime, historical: false })
    }
    /// Only the historical authenticator can create this receipt. Each draft is
    /// independently authenticated again before WAL custody; current routing or
    /// local secret availability cannot erase a retired session's delivery debt.
    pub(crate) fn historical_sink(
        self: &Arc<Self>,
        authenticated: &crate::validator::retired_session_auth::AuthenticatedRetiredSession,
    ) -> Result<DurableFinalitySinkPtr> {
        let runtime = authenticated.runtime().clone();
        let engine = self.state.engine.upgrade().ok_or_else(|| error!("Engine unavailable"))?;
        if &runtime.pin().zerostate != engine.zerostate_id()
            || runtime.wire_profile() != engine.validator_network().wire_profile()
        {
            fail!("Historical sink belongs to another Engine domain");
        }
        Ok(Arc::new(SessionSink { worker: self.clone(), runtime, historical: true }))
    }

    fn admit_draft(&self, mut request: Submission) -> Result<()> {
        if let Err(error) = request.track(&self.state.outstanding) {
            request.disarm();
            return Err(error);
        }
        let sender = (|| {
            let sender = self.sender.lock().map_err(|_| error!("Publication admission poisoned"))?;
            if self.state.fatal.load(Ordering::Acquire) {
                fail!("Publication admission failed");
            }
            if self.state.stop.is_cancelled() {
                fail!("Publication admission stopping");
            }
            sender.as_ref().cloned().ok_or_else(|| error!("Publication admission closed"))
        })();
        let (rejected, reason) = match sender {
            Ok(sender) => match sender.try_send(request) {
                Ok(()) => return Ok(()),
                Err(mpsc::error::TrySendError::Full(request)) => (request, "Publication draft queue full".to_owned()),
                Err(mpsc::error::TrySendError::Closed(request)) => (request, "Publication draft channel closed".to_owned()),
            },
            Err(error) => (request, error.to_string()),
        };
        rejected.disarm();
        fail!("{reason}; {}; retain source evidence", self.state.activity_description())
    }
    pub(crate) async fn recover_draft(
        &self,
        record: PublicationRecord,
        last_mc: u32,
        candidate_already_sent: bool,
        origin: RecoveryOrigin,
    ) -> Result<UInt256> {
        let probe = UnverifiedRecord {
            id: RecordId(1),
            stage: PublicationStage::DraftDurable,
            record: Arc::new(record.clone()),
            pending: Vec::new(),
        };
        crate::propagation_outbox::validate_recovery_record(&probe, &self.state.limits)?;
        let (sender, receiver) = oneshot::channel();
        self.admit_draft(Submission::Draft {
            record,
            last_mc,
            candidate_already_sent,
            completion: Completion(Some(Box::new(move |result| {
                let _ = sender.send(result);
            }))),
            origin,
            historical: true,
        })?;
        receiver.await.map_err(|e| error!("Recovery draft owner: {e}"))?
    }
    pub(crate) async fn query(&self, id: UInt256) -> Result<AcceptedSessionBlock> {
        let (response, result) = oneshot::channel();
        {
            let sender =
                self.sender.lock().map_err(|_| error!("Publication query admission poisoned"))?;
            if self.state.stop.is_cancelled() {
                fail!("Publication owner stopped");
            }
            sender
                .as_ref()
                .ok_or_else(|| error!("Publication owner stopped"))?
                .try_send(Submission::Query { id, response })
                .map_err(|_| error!("Publication query queue full"))?;
        }
        result.await.map_err(|e| error!("Publication query owner: {e}"))?
    }
    #[cfg(test)]
    pub(crate) fn outstanding_for_test(&self, session: &UInt256) -> usize {
        self.state.outstanding.count(session)
    }
    /// Runs one journaled deletion step in the owner's transition.
    pub(crate) async fn cleanup_step(
        &self,
        step: cleanup_steps::CleanupStep,
        ownership: Arc<dyn std::any::Any + Send + Sync>,
    ) -> Result<cleanup_steps::CleanupStepOutcome> {
        let (response, result) = oneshot::channel();
        {
            let sender =
                self.sender.lock().map_err(|_| error!("Publication cleanup admission poisoned"))?;
            if self.state.stop.is_cancelled() || self.state.fatal.load(Ordering::Acquire) {
                fail!("Publication owner stopped");
            }
            sender
                .as_ref()
                .ok_or_else(|| error!("Publication owner stopped"))?
                .try_send(Submission::Cleanup { step, ownership, response })
                .map_err(|_| error!("Publication cleanup queue full"))?;
        }
        result.await.map_err(|e| error!("Publication cleanup owner: {e}"))?
    }
    #[cfg(test)]
    pub(crate) fn test_acceptance_request_runs(&self) -> usize {
        self.state.acceptance_request_runs.load(Ordering::Relaxed)
    }
    #[cfg(test)]
    pub(crate) fn test_actual_acceptance_runs(&self) -> usize {
        self.state.actual_acceptance_runs.load(Ordering::Relaxed)
    }
    #[cfg(test)]
    pub(crate) fn test_background_runs(&self) -> (usize, usize) {
        (self.state.background_acceptance_runs.load(Ordering::Relaxed),
         self.state.background_routing_turns.load(Ordering::Relaxed))
    }
    #[cfg(test)]
    pub(crate) async fn test_retry_background(&self) -> Result<()> {
        let (response, result) = oneshot::channel();
        self.admit_draft(Submission::RetryBackground { response })?;
        result.await.map_err(|error| error!("Publication retry test: {error}"))?
    }
    #[cfg(test)]
    pub(crate) fn set_cleanup_commit_hook(
        &self,
        hook: Option<Arc<dyn Fn(&crate::propagation_outbox::PropagationOutbox) + Send + Sync>>,
    ) {
        *self.state.cleanup_commit_hook.lock().unwrap() = hook;
    }
    pub(crate) fn stop(&self) {
        self.sender.lock().unwrap_or_else(|p| p.into_inner()).take();
        self.state.stop.cancel();
        self.state.wake.notify_one();
    }
    pub(crate) async fn wait(&self) -> Result<()> {
        self.stop();
        // The actor stops creating I/O only after all admitted submissions finish.
        let actor = self.tasks.wait().await;
        let io = self.state.io.wait().await;
        actor?;
        io?;
        if self.state.fatal.load(Ordering::Acquire) {
            fail!("Publication worker failed");
        }
        Ok(())
    }
}
impl State {
    fn activity_scope(&self, phase: &'static str, record: Option<(u64, String)>) -> ActivityScope<'_> {
        let mut current = self.activity.lock().unwrap_or_else(|p| p.into_inner());
        let next = WorkerActivity { phase, record: record.or_else(|| current.record.clone()), since: std::time::Instant::now() };
        let previous = Some(std::mem::replace(&mut *current, next));
        ActivityScope { activity: &self.activity, previous }
    }
    fn activity_description(&self) -> String {
        let current = self.activity.lock().unwrap_or_else(|p| p.into_inner());
        let (record, block) = current.record.as_ref().map(|(id, block)| (id.to_string(), block.as_str())).unwrap_or_else(|| ("none".to_owned(), "none"));
        format!("worker_phase={} phase_ms={} record={} block={}", current.phase, current.since.elapsed().as_millis(), record, block)
    }
    fn fatal(&self, message: String) {
        self.fatal.store(true, Ordering::Release);
        self.io.record_error(message);
        self.stop.cancel();
        if let Some(engine) = self.engine.upgrade() {
            engine.stopper().set_stop();
        }
    }
    async fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let (sent, received) = oneshot::channel();
        self.io.spawn_handle("publication WAL operation", || {
            tokio::task::spawn_blocking(move || {
                let _ = sent.send(work());
            })
        })?;
        match received.await {
            Ok(result) => result,
            Err(error) => {
                self.fatal(format!("Publication blocking worker panicked: {error}"));
                Err(error!("Publication blocking completion: {error}"))
            }
        }
    }
    async fn write<T: Send + 'static>(
        &self,
        store: &Arc<PropagationOutbox>,
        work: impl FnOnce(&PropagationOutbox) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let _activity = self.activity_scope("wal_io", None);
        let store = store.clone();
        let result = self
            .blocking(move || {
                let result = work(&store);
                // Capacity/validation rejection is recoverable. An uncertain disk
                // result poisons the store and must stop all further transactions.
                let poisoned = result.is_err() && store.check_health().is_err();
                Ok((result, poisoned))
            })
            .await?;
        if result.1 {
            self.fatal("Publication WAL state uncertain; reopen required".into());
        }
        result.0
    }
    async fn snapshot(&self, store: &Arc<PropagationOutbox>) -> Result<Vec<UnverifiedRecord>> {
        let store = store.clone();
        let result = self.blocking(move || store.pending()).await;
        if let Err(error) = &result {
            self.fatal(format!("Publication snapshot unavailable: {error}"));
        }
        result
    }
    async fn run(
        self: Arc<Self>,
        store: Arc<PropagationOutbox>,
        mut receiver: mpsc::Receiver<Submission>,
    ) {
        let mut tick = tokio::time::interval(RETRY_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            if self.engine.strong_count() == 0 {
                break;
            }
            let command = match next_worker_turn(&self.stop, &mut tick, &mut receiver, &self.wake).await {
                WorkerTurn::Stop => { receiver.close(); None },
                WorkerTurn::Command(command) => command,
                WorkerTurn::Retry => { self.recover(&store, &mut receiver).await; continue; },
            };
            if let Some(command) = command {
                #[cfg(test)]
                let command = match command {
                    Submission::RetryBackground { response } => {
                        // Drive the next eligible turn without wall-clock sleeps.
                        // All IO still runs on the real publication actor.
                        self.acceptance_retry.lock().unwrap().clear();
                        self.recover(&store, &mut receiver).await;
                        let _ = response.send(Ok(()));
                        continue;
                    }
                    command => command,
                };
                self.submit_one(&store, command).await;
            } else {
                // These requests have not started a WAL transaction. Active
                // transactions have already drained before reaching this branch.
                while let Some(command) = receiver.recv().await {
                    command.reject();
                }
                break;
            }
            if self.engine.strong_count() == 0 {
                break;
            }
        }
    }
    async fn submit_one(&self, store: &Arc<PropagationOutbox>, command: Submission) {
        // Cancellation and a ready mailbox can win the actor select in either
        // order. A queued request has not started its transaction and must not
        // resume acceptance after an earlier uncertain WAL result stopped us.
        // Already executing operations still finish before reaching this seam.
        if self.stop.is_cancelled() || self.fatal.load(Ordering::Acquire) {
            command.reject();
            return;
        }
        let phase = match &command {
            #[cfg(test)]
            Submission::RetryBackground { .. } => "test_retry_background",
            Submission::Acceptance { .. } => "accept_request",
            Submission::HistoryDebt { .. } => "history_debt",
            Submission::Terminal { .. } => "terminal_lookup",
            Submission::OfferClose { .. } => "offer_close",
            Submission::SourceDelivered { .. } => "source_delivered",
            Submission::Canonical { .. } => "canonical_retention",
            Submission::Legacy(_) => "legacy_submission",
            Submission::Draft { .. } => "draft_retention",
            Submission::Query { .. } => "accept_query",
            Submission::Cleanup { .. } => "cleanup",
        };
        let _activity = self.activity_scope(phase, None);
        let command_started = std::time::Instant::now();
        match command {
            #[cfg(test)]
            Submission::RetryBackground { response } => {
                let _ = response.send(Err(error!("Nested publication retry test refused")));
            }
            Submission::HistoryDebt { request, runtime, budget, response } => {
                let result = self.history_debt(store, request, runtime, budget).await;
                let _ = response.send(result);
            }
            Submission::Terminal { request, runtime, completion } => {
                completion.finish(self.lookup_terminal(store, &runtime, &request).await);
            }
            Submission::OfferClose { request, runtime, completion } => {
                completion.finish(self.offer_close(store, &runtime, request).await);
            }
            Submission::SourceDelivered { confirmation, runtime, completion } => {
                completion.finish(self.confirm_delivered(store, &runtime, confirmation).await);
            }
            Submission::Acceptance { request, runtime, queued_at, completion } => {
                let started = std::time::Instant::now();
                log::debug!(target: "simplex_resolver",
                    "NODE_ACCEPT_BEGIN: session={} node_receipt={} block_id={} role={:?} queue_ms={}",
                    runtime.session_id().to_hex_string(), request.node_receipt.to_hex_string(),
                    request.block_id, request.role, queued_at.elapsed().as_millis());
                let result = async {
                    if self.stop.is_cancelled() {
                        fail!("Publication shutdown before acceptance");
                    }
                    let id = request.node_receipt.clone();
                    let (delivery, entry) = self.write(store, move |store| store.delivery(&id))
                        .await?.ok_or_else(|| error!("Unknown acceptance delivery"))?;
                    log::debug!(target: "simplex_resolver",
                        "NODE_ACCEPT_LOOKUP: session={} node_receipt={} record={} elapsed_ms={}",
                        runtime.session_id().to_hex_string(), request.node_receipt.to_hex_string(),
                        entry.id.0, started.elapsed().as_millis());
                    // Bind role, block, session, network and origin before using
                    // the same authenticated accept operation as normal Query.
                    canonical_record(&runtime, &request, &delivery, &entry, &self.limits)?;
                    log::debug!(target: "simplex_resolver",
                        "NODE_ACCEPT_BOUND: session={} node_receipt={} record={} elapsed_ms={}",
                        runtime.session_id().to_hex_string(), request.node_receipt.to_hex_string(),
                        entry.id.0, started.elapsed().as_millis());
                    // A persisted stage is not acceptance authority after restart.
                    // Reuse only a completed acceptance verified by this worker,
                    // after binding the full source request above.
                    if self.acceptance_verified_in_process(&entry) {
                        return Ok(());
                    }
                    let engine = self.engine.upgrade().ok_or_else(|| error!("Publication Engine gone"))?;
                    #[cfg(test)]
                    self.acceptance_request_runs.fetch_add(1, Ordering::Relaxed);
                    self.accept(store, engine, entry).await?;
                    Ok(())
                }.await;
                log::debug!(target: "simplex_resolver",
                    "NODE_ACCEPT_END: session={} node_receipt={} elapsed_ms={} error={:?}",
                    runtime.session_id().to_hex_string(), request.node_receipt.to_hex_string(),
                    started.elapsed().as_millis(), result.as_ref().err().map(ToString::to_string));
                completion.finish(result);
            }
            Submission::Canonical { request, runtime, completion } => {
                let result = async {
                    if self.stop.is_cancelled() {
                        fail!("Publication shutdown before canonical retention");
                    }
                    let id = request.node_receipt.clone();
                    let (delivery, entry) = self
                        .write(store, move |store| store.delivery(&id))
                        .await?
                        .ok_or_else(|| error!("Unknown canonical delivery"))?;
                    let canonical =
                        canonical_record(&runtime, &request, &delivery, &entry, &self.limits)?;
                    self.write(store, move |store| store.retain_delivery(&delivery)).await?;
                    Ok(canonical)
                }
                .await;
                completion.finish(result);
            }
            Submission::Legacy(command) => self.submit_legacy(store, command).await,
            Submission::Draft {
                mut record,
                last_mc,
                candidate_already_sent,
                completion,
                historical,
                origin,
            } => {
                let result = async {
                    if self.stop.is_cancelled() {
                        fail!("Publication shutdown before Draft WAL");
                    }
                    let probe = UnverifiedRecord {
                        id: RecordId(1),
                        stage: PublicationStage::DraftDurable,
                        record: Arc::new(record.clone()),
                        pending: Vec::new(),
                    };
                    crate::propagation_outbox::validate_recovery_record(&probe, &self.limits)?;
                    if historical {
                        let engine =
                            self.engine.upgrade().ok_or_else(|| error!("Engine unavailable"))?;
                        let authenticated = tokio::time::timeout(
                            HISTORY_TIMEOUT,
                            authenticate_publication(
                                &engine.masterchain_proof_verifier,
                                engine.as_ref(),
                                probe,
                                &self.limits,
                            ),
                        )
                        .await
                        .map_err(|_| error!("Recovery history timeout"))??;
                        // Reconstruct the original role claim from history, never
                        // from today's (possibly retired) local key configuration.
                        record.locally_generated =
                            historical_origin(&authenticated, &origin)?.locally_generated;
                    }
                    self.write(store, move |store| {
                        store.stage_draft(record, last_mc, candidate_already_sent, Some(origin))
                    })
                    .await
                }
                .await;
                completion.finish(result);
                self.wake.notify_one();
            }
            Submission::Cleanup { step, ownership, response } => {
                let outcome = self.cleanup_step(store, step);
                drop(ownership);
                let _ = response.send(outcome);
            }
            Submission::Query { id, response } => {
                // Caller cancellation only drops this response; acceptance and IO remain actor-owned.
                let result = async {
                    let query = id.clone();
                    let (_, entry) = self
                        .write(store, move |store| store.delivery(&query))
                        .await?
                        .ok_or_else(|| error!("Unknown durable delivery ID"))?;
                    let engine =
                        self.engine.upgrade().ok_or_else(|| error!("Engine unavailable"))?;
                    self.accept(store, engine, entry).await
                }
                .await;
                let _ = response.send(result);
                self.wake.notify_one();
            }
        }
        log::debug!("Publication command phase={} elapsed_ms={}", phase, command_started.elapsed().as_millis());
    }
    async fn submit_legacy(&self, store: &Arc<PropagationOutbox>, command: LegacySubmission) {
        let result = async {
            if self.fatal.load(Ordering::Acquire) || self.stop.is_cancelled() {
                fail!("Publication worker stopped before durable admission");
            }
            let engine = self.engine.upgrade().ok_or_else(|| error!("Publication Engine gone"))?;
            let probe = UnverifiedRecord {
                id: RecordId(1),
                stage: PublicationStage::Prepared,
                pending: command.record.effects.clone(),
                record: Arc::new(command.record.clone()),
            };
            validate_plan(&probe)?;
            // Authentication happens before durable admission; bogus metadata or
            // signatures cannot fill the bounded durable queue.
            tokio::time::timeout(
                HISTORY_TIMEOUT,
                authenticate_publication(
                    &engine.masterchain_proof_verifier,
                    engine.as_ref(),
                    probe,
                    &self.limits,
                ),
            )
            .await
            .map_err(|_| error!("Publication history authentication timed out"))??;
            let record = command.record;
            let id = self.write(store, move |store| store.enqueue(record)).await?;
            let entry = self
                .snapshot(store)
                .await?
                .into_iter()
                .find(|entry| entry.id == id)
                .ok_or_else(|| error!("Durable publication disappeared before acceptance"))?;
            self.accept(store, engine, entry).await
        }
        .await;
        let _ = command.response.send(result);
        self.wake.notify_one();
    }
    async fn resolve_draft(
        &self,
        store: &Arc<PropagationOutbox>,
        engine: &Arc<Engine>,
        entry: UnverifiedRecord,
    ) -> Result<bool> {
        if entry.stage == PublicationStage::DraftDurable {
            fail!("Routing resolution requires actual acceptance first");
        }
        if entry.stage != PublicationStage::AcceptedDraft {
            return Ok(true);
        }
        // Authenticate disk evidence before allowing its metadata to resolve destinations.
        let authenticated = tokio::time::timeout(
            HISTORY_TIMEOUT,
            authenticate_publication(
                &engine.masterchain_proof_verifier,
                engine.as_ref(),
                entry.clone(),
                &self.limits,
            ),
        )
        .await
        .map_err(|_| error!("Draft history timeout"))??;
        let id = entry.id;
        let delivery = self
            .write(store, move |store| store.delivery_for_record(id))
            .await?
            .ok_or_else(|| error!("Draft delivery metadata missing"))?;
        let origin =
            delivery.origin.as_ref().ok_or_else(|| error!("Draft recovery origin absent"))?;
        let claims = historical_origin(&authenticated, origin)?;
        validate_creator_claim(&authenticated, &claims)?;
        if !routing_available(engine.as_ref(), &claims)? {
            metrics::counter!("rtos_publication_routing_blocked_total").increment(1);
            return Ok(false);
        }
        let plan = PropagationPlan::for_event(
            entry.record.protocol,
            PropagationEvent::Finalized,
            &entry.record.block_id,
            true,
            entry.record.locally_generated,
            entry.record.carrier.is_final(),
            delivery.last_mc,
            delivery.candidate_already_sent,
        );
        let destinations = tokio::time::timeout(
            SEND_TIMEOUT,
            engine.resolve_propagation_targets(&entry.record.block_id, &plan),
        )
        .await
        .map_err(|_| error!("Draft destination resolution timeout"))??;
        let mut effects = Vec::new();
        for destination in destinations {
            plan.for_destination(&destination)?;
            effects.push(effect_from_destination(destination)?);
        }
        effects.sort();
        effects.dedup();
        let resolved_effects = effects.clone();
        self.write(store, move |store| store.resolve_draft(id, effects)).await?;
        // Destination resolution changes only routing metadata, after actual
        // acceptance and a successful WAL commit. Retain that same opaque
        // result rather than accepting the block again for its resolved plan.
        // Cache misses, eviction and cold starts still use normal acceptance.
        self.accepted_receipts.lock().unwrap()
            .resolved_routing(&entry, resolved_effects, &self.limits);
        Ok(true)
    }
    fn acceptance_verified_in_process(&self, entry: &UnverifiedRecord) -> bool {
        matches!(entry.stage,
            PublicationStage::AcceptedDraft | PublicationStage::Ready | PublicationStage::Completed)
            && self.acceptance_verified.lock().unwrap().contains(&entry.id.0)
    }

    async fn accept(
        &self,
        store: &Arc<PropagationOutbox>,
        engine: Arc<Engine>,
        entry: UnverifiedRecord,
    ) -> Result<AcceptedSessionBlock> {
        let activity = self.activity_scope("accept_history", Some((entry.id.0, entry.record.block_id.to_string())));
        let started = std::time::Instant::now();
        let trace_record = entry.id.0;
        let trace_phase = |phase: &str| {
            log::debug!(target: "simplex_resolver",
                "NODE_ACCEPT_PHASE: record={} phase={} elapsed_ms={}",
                trace_record, phase, started.elapsed().as_millis());
        };
        trace_phase("history_begin");
        validate_plan(&entry)?;
        let publication = tokio::time::timeout(
            HISTORY_TIMEOUT,
            authenticate_publication(
                &engine.masterchain_proof_verifier,
                engine.as_ref(),
                entry,
                &self.limits,
            ),
        )
        .await
        .map_err(|_| error!("Publication history authentication timed out"))??;
        trace_phase("history_done");
        let id = publication.entry().id;
        if let Some(delivery) =
            self.write(store, move |store| store.delivery_for_record(id)).await?
        {
            let origin = delivery
                .origin
                .as_ref()
                .ok_or_else(|| error!("Delivery recovery origin absent"))?;
            let claims = historical_origin(&publication, origin)?;
            validate_creator_claim(&publication, &claims)?;
        }
        trace_phase("origin_done");
        // Authentication and creator/origin binding above still run on every
        // request, including cache hits. A new worker starts with no receipts.
        let record = publication.entry().record.clone();
        if let Some(receipt) = self.accepted_receipts.lock().unwrap()
            .get(publication.entry(), engine.as_ref())?
        {
            trace_phase("cached_receipt");
            return Ok(receipt);
        }
        activity.phase("accept_block");
        trace_phase("block_begin");
        // Deliberately not cancelable: this phase can write state/proof data.
        #[cfg(test)]
        self.actual_acceptance_runs.fetch_add(1, Ordering::Relaxed);
        let (entry, accepted) =
            accept_authenticated_publication(publication, engine.clone()).await?;
        trace_phase("block_done");
        let id = entry.id;
        let needs_verification = !self.acceptance_verified.lock().unwrap().contains(&id.0);
        if needs_verification {
            activity.phase("accept_durability");
            let durability = engine.clone().ensure_publication_acceptance_durable(&accepted);
            #[cfg(all(target_os = "linux", feature = "isolated-consensus-signing"))]
            let durability = crate::publication_io_test_control::acceptance_scope(&entry, durability).await;
            #[cfg(not(all(target_os = "linux", feature = "isolated-consensus-signing")))]
            let durability = durability.await;
            if let Err(error) = durability {
                if error
                    .downcast_ref::<crate::internal_db::PublicationDurabilityFailure>()
                    .is_some()
                {
                    self.fatal(error.to_string());
                    #[cfg(all(target_os = "linux", feature = "isolated-consensus-signing"))]
                    crate::publication_io_test_control::after_fatal(&entry, store.as_ref(), &accepted, &error)?;
                }
                return Err(error);
            }
            // Private-v2 suppresses legacy shard-description broadcasts, but
            // finalized WC data must still enter the local MC collator's pool.
            // Do this only after the block/proof/state durability barrier; a
            // failure keeps the handoff retryable and cannot admit an approval.
            if accepted.is_final()
                && !accepted.block().id().shard().is_masterchain()
                && entry.record.protocol == SimplexProtocol::PrivateObserversPlumtree
            {
                activity.phase("accept_shard_description");
                accepted.register_shard_description(engine.clone(), entry.record.locally_generated).await?;
            }
        }
        trace_phase("durability_done");
        self.write(store, move |store| store.mark_accepted(id)).await?;
        trace_phase("wal_done");
        self.acceptance_verified.lock().unwrap().insert(id.0);
        self.accepted_receipts.lock().unwrap().insert(id, record, &accepted, &self.limits);
        Ok(accepted)
    }
    async fn routing_ready(
        &self,
        store: &Arc<PropagationOutbox>,
        engine: &Arc<Engine>,
        entry: &UnverifiedRecord,
    ) -> Result<bool> {
        let id = entry.id;
        let Some(delivery) = self.write(store, move |store| store.delivery_for_record(id)).await?
        else {
            // Version-1 legacy submissions have no handoff origin. Keep their
            // historical authentication/plan contract; do not invent an origin.
            return Ok(true);
        };
        let publication = tokio::time::timeout(
            HISTORY_TIMEOUT,
            authenticate_publication(
                &engine.masterchain_proof_verifier,
                engine.as_ref(),
                entry.clone(),
                &self.limits,
            ),
        )
        .await
        .map_err(|_| error!("Publication routing history timeout"))??;
        let origin = delivery.origin.as_ref().ok_or_else(|| error!("Delivery origin absent"))?;
        let claims = historical_origin(&publication, origin)?;
        validate_creator_claim(&publication, &claims)?;
        routing_available(engine.as_ref(), &claims)
    }
    async fn send_while_serving(
        &self,
        store: &Arc<PropagationOutbox>,
        receiver: &mut mpsc::Receiver<Submission>,
        engine: &Arc<Engine>,
        accepted: &AcceptedSessionBlock,
        plan: &PropagationPlan,
    ) -> Option<crate::validator::propagation::PropagationOutcome> {
        let sending = tokio::time::timeout(
            SEND_TIMEOUT,
            engine.propagate_accepted_session_block(accepted, plan),
        );
        tokio::pin!(sending);
        loop {
            tokio::select! {
                _ = self.stop.cancelled() => return None,
                result = &mut sending => {
                    if result.is_err() { metrics::counter!("rtos_publication_send_timeouts_total").increment(1); }
                    return result.ok();
                },
                command = receiver.recv() => match command {
                    Some(command) => self.submit_one(store, command).await,
                    None => return None,
                },
            }
        }
    }
    fn select_retry(
        &self,
        entries: &[UnverifiedRecord],
        now_unix_secs: u64,
        now: tokio::time::Instant,
    ) -> Option<(UnverifiedRecord, PublicationEffect)> {
        if entries.is_empty() {
            return None;
        }
        // Round-robin eligible effects. Success advances immediately; failure
        // has a separate minimum one-second backoff for each exact target.
        {
            let mut cursor = self.cursor.lock().unwrap();
            let mut retry = self.retry_after.lock().unwrap();
            cursor.1.retain(|id, _| entries.iter().any(|entry| entry.id.0 == *id));
            retry.retain(|(id, effect), _| {
                entries.iter().any(|entry| entry.id.0 == *id && entry.pending.contains(effect))
            });
            let start = entries.iter().position(|entry| entry.id.0 > cursor.0).unwrap_or(0);
            let mut selected = None;
            for index in 0..entries.len() {
                let entry = &entries[(start + index) % entries.len()];
                // Expired intents stay durable, but cannot delay live work.
                if entry.stage != PublicationStage::Ready || entry.record.is_expired(now_unix_secs)
                {
                    continue;
                }
                let offset = *cursor.1.get(&entry.id.0).unwrap_or(&0);
                for step in 0..entry.pending.len() {
                    let index = (offset + step) % entry.pending.len();
                    let effect = &entry.pending[index];
                    if retry.get(&(entry.id.0, effect.clone())).is_some_and(|at| *at > now) {
                        continue;
                    }
                    cursor.0 = entry.id.0;
                    cursor.1.insert(entry.id.0, index + 1);
                    retry.insert((entry.id.0, effect.clone()), now + RETRY_INTERVAL);
                    selected = Some((entry.clone(), effect.clone()));
                    break;
                }
                if selected.is_some() {
                    break;
                }
            }
            selected
        }
    }
    fn select_acceptance(
        &self,
        entries: &[UnverifiedRecord],
        now: tokio::time::Instant,
    ) -> Option<UnverifiedRecord> {
        if entries.is_empty() {
            return None;
        }
        let enabled = self.enabled.load(Ordering::Acquire);
        let mut verified = self.acceptance_verified.lock().unwrap();
        verified.retain(|id| entries.iter().any(|entry| entry.id.0 == *id));
        // Persisted stages from an older process are not proof that all required
        // artifacts survived. Expiry/disabled routing never bypass this pass.
        let eligible = |entry: &UnverifiedRecord| {
            !verified.contains(&entry.id.0)
                || matches!(
                    entry.stage,
                    PublicationStage::DraftDurable | PublicationStage::Prepared
                )
                || (enabled && entry.stage == PublicationStage::AcceptedDraft)
        };
        let mut retry = self.acceptance_retry.lock().unwrap();
        retry.retain(|id, _| entries.iter().any(|entry| entry.id.0 == *id && eligible(entry)));
        let mut cursor = self.acceptance_cursor.lock().unwrap();
        let start = entries.iter().position(|entry| entry.id.0 > *cursor).unwrap_or(0);
        let entry = (0..entries.len())
            .map(|offset| &entries[(start + offset) % entries.len()])
            .find(|entry| {
                eligible(entry) && !retry.get(&entry.id.0).is_some_and(|deadline| *deadline > now)
            })
            .cloned();
        if let Some(entry) = &entry {
            *cursor = entry.id.0;
            retry.insert(entry.id.0, now + RETRY_INTERVAL);
        }
        entry
    }
    async fn recover(
        &self,
        store: &Arc<PropagationOutbox>,
        receiver: &mut mpsc::Receiver<Submission>,
    ) {
        let _activity = self.activity_scope("retry_snapshot", None);
        if self.stop.is_cancelled() {
            return;
        }
        let entries = match self.snapshot(store).await {
            Ok(entries) => entries,
            Err(_) => return,
        };
        if entries.is_empty() {
            return;
        }
        let now = tokio::time::Instant::now();
        let now_unix_secs =
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let has_send_work = self.enabled.load(Ordering::Acquire)
            && entries.iter().any(|entry| {
                entry.stage == PublicationStage::Ready && !entry.record.is_expired(now_unix_secs)
            });
        // One slow historical debt cannot consume every scheduling turn while
        // already-accepted records have effects ready to send.
        let acceptance_turn = self.acceptance_turn.swap(true, Ordering::AcqRel);
        let selected = if acceptance_turn || !has_send_work {
            self.select_acceptance(&entries, now)
        } else {
            None
        };
        if let Some(entry) = selected {
            self.acceptance_turn.store(false, Ordering::Release);
            let retry_id = entry.id.0;
            if let Some(engine) = self.engine.upgrade() {
                let result = async {
                    let id = entry.id;
                    // Actual acceptance precedes routing and never depends on a
                    // retired local key or publication expiry.
                    #[cfg(test)]
                    self.background_routing_turns.fetch_add(1, Ordering::Relaxed);
                    // Routing can stay unavailable after acceptance completed.
                    // C++ reuses completed finalization instead of re-entering
                    // block acceptance for every routing retry. Persisted tags
                    // alone never authorize this shortcut after a cold start.
                    if !self.acceptance_verified_in_process(&entry) {
                        #[cfg(test)]
                        self.background_acceptance_runs.fetch_add(1, Ordering::Relaxed);
                        self.accept(store, engine.clone(), entry).await?;
                    }
                    if self.enabled.load(Ordering::Acquire) {
                        let entry = self
                            .snapshot(store)
                            .await?
                            .into_iter()
                            .find(|entry| entry.id == id)
                            .ok_or_else(|| error!("Accepted draft disappeared"))?;
                        if !self.resolve_draft(store, &engine, entry).await? {
                            self.acceptance_retry.lock().unwrap().insert(retry_id, tokio::time::Instant::now() + RETRY_INTERVAL);
                            log::debug!("Accepted publication {retry_id} waits for original routing authority");
                        }
                    }
                    Ok::<_, anyhow::Error>(())
                }
                .await;
                if let Err(error) = result {
                    self.acceptance_retry
                        .lock()
                        .unwrap()
                        .insert(retry_id, tokio::time::Instant::now() + RETRY_INTERVAL);
                    log::warn!("Durable delivery acceptance or routing retry deferred: {error}");
                }
                self.wake.notify_one();
            }
            return;
        }
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }
        let now_unix_secs =
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let selected = self.select_retry(&entries, now_unix_secs, tokio::time::Instant::now());
        let Some((entry, effect)) = selected else {
            return;
        };
        drop(entries);
        {
            if self.stop.is_cancelled() {
                return;
            }
            let Some(engine) = self.engine.upgrade() else { return };
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            if entry.record.is_expired(now) {
                metrics::counter!("rtos_publication_expired_pending_total").increment(1);
                return; // Never acknowledge or discard unsent expired work.
            }
            let accepted = match self.accept(store, engine.clone(), entry.clone()).await {
                Ok(accepted) => accepted,
                Err(error) => {
                    metrics::counter!("rtos_publication_retry_errors_total").increment(1);
                    log::warn!("Publication {} recovery deferred: {error}", entry.id.0);
                    self.retry_after.lock().unwrap().insert(
                        (entry.id.0, effect.clone()),
                        tokio::time::Instant::now() + RETRY_INTERVAL,
                    );
                    self.wake.notify_one();
                    return;
                }
            };
            match self.routing_ready(store, &engine, &entry).await {
                Ok(true) => {}
                Ok(false) => {
                    metrics::counter!("rtos_publication_routing_blocked_total").increment(1);
                    self.retry_after.lock().unwrap().insert(
                        (entry.id.0, effect.clone()),
                        tokio::time::Instant::now() + RETRY_INTERVAL,
                    );
                    self.wake.notify_one();
                    return;
                }
                Err(error) => {
                    log::warn!("Publication routing deferred: {error}");
                    self.retry_after.lock().unwrap().insert(
                        (entry.id.0, effect.clone()),
                        tokio::time::Instant::now() + RETRY_INTERVAL,
                    );
                    self.wake.notify_one();
                    return;
                }
            }
            let plan = match validate_plan(&entry) {
                Ok(plan) => plan,
                Err(_) => return,
            };
            {
                if self.stop.is_cancelled() {
                    return;
                }
                let destination = destination(&effect);
                let exact = match plan.for_destination(&destination) {
                    Ok(plan) => plan,
                    Err(_) => return,
                };
                let Some(outcome) =
                    self.send_while_serving(store, receiver, &engine, &accepted, &exact).await
                else {
                    self.retry_after.lock().unwrap().insert(
                        (entry.id.0, effect.clone()),
                        tokio::time::Instant::now() + RETRY_INTERVAL,
                    );
                    self.wake.notify_one();
                    return;
                };
                let sent = outcome.receipts.iter().any(|receipt| {
                    receipt.kind == destination.kind
                        && receipt.target == destination.target
                        && receipt.status == PropagationStatus::Sent
                });
                self.retry_after.lock().unwrap().insert(
                    (entry.id.0, effect.clone()),
                    tokio::time::Instant::now() + RETRY_INTERVAL,
                );
                self.wake.notify_one();
                if sent {
                    let id = entry.id;
                    if let Err(error) =
                        self.write(store, move |store| store.checkpoint_sent(id, &[effect])).await
                    {
                        log::error!("Publication checkpoint failed: {error}");
                        if self.fatal.load(Ordering::Acquire) {
                            return;
                        }
                    }
                } else {
                    metrics::counter!("rtos_publication_pending_send_attempts_total").increment(1);
                    log::debug!(
                        "Publication {} target {:?} remains pending: {:?}",
                        entry.id.0,
                        destination,
                        outcome.receipts
                    );
                }
            }
        }
    }
}

/// Historical consistency of a stored local-role claim is not proof that this
/// node currently possesses (or ever possessed) the claimed transport key.
struct OriginClaims {
    local_adnl: Arc<rtos_block::KeyId>,
    local_validator: Option<UInt256>,
    locally_generated: bool,
}
fn historical_origin(
    publication: &crate::propagation_outbox_auth::AuthenticatedPublication,
    origin: &RecoveryOrigin,
) -> Result<OriginClaims> {
    if origin.carrier_version != publication.context().carrier_version() {
        fail!("Recovery carrier envelope version differs from history");
    }
    let creator = publication.block().block()?.read_extra()?.created_by().clone();
    let committee = publication.context().committee();
    if creator != origin.source_validator
        || !committee.iter().any(|v| v.validator_id().ok().as_ref() == Some(&creator))
    {
        fail!("Recovery creator is not bound to body and governing committee");
    }
    let transport = rtos_block::KeyId::from_data(*origin.local_adnl.as_array());
    let local_id = if let Some(index) = origin.local_validator_index {
        let member = committee
            .get(index as usize)
            .ok_or_else(|| error!("Recovery local validator index out of range"))?;
        if member.adnl_addr()? != transport {
            fail!("Recovery local index and historical ADNL differ");
        }
        Some(member.validator_id()?)
    } else {
        if committee.iter().any(|member| member.adnl_addr().ok().as_ref() == Some(&transport)) {
            fail!("Recovery observer role conflicts with historical validator transport");
        }
        None
    };
    Ok(OriginClaims {
        local_adnl: transport,
        locally_generated: local_id.as_ref() == Some(&creator),
        local_validator: local_id,
    })
}
fn validate_creator_claim(
    publication: &crate::propagation_outbox_auth::AuthenticatedPublication,
    claims: &OriginClaims,
) -> Result<()> {
    if publication.entry().record.locally_generated != claims.locally_generated {
        fail!("Recovery creator routing claim differs from historical role claim");
    }
    Ok(())
}
fn routing_available(engine: &dyn EngineOperations, claims: &OriginClaims) -> Result<bool> {
    if engine.adnl_key_by_id(&claims.local_adnl).is_none() {
        return Ok(false);
    }
    match &claims.local_validator {
        Some(id) => Ok(engine.consensus_transport_bindings()?.iter().any(|binding| {
            &binding.validator_id == id && binding.adnl_key_id == claims.local_adnl
        })),
        None => Ok(true),
    }
}

fn effect_from_destination(destination: PropagationDestination) -> Result<PublicationEffect> {
    Ok(PublicationEffect {
        kind: match destination.kind {
            PropagationKind::Candidate => PublicationKind::Candidate,
            PropagationKind::Block => PublicationKind::Block,
            PropagationKind::Finality => PublicationKind::Finality,
            PropagationKind::ShardDescription => PublicationKind::ShardDescription,
        },
        target: match destination.target {
            PropagationTarget::Public => PublicationTarget::Public,
            PropagationTarget::FastSync => PublicationTarget::FastSync,
            PropagationTarget::Custom(name) if !name.is_empty() => PublicationTarget::Custom(name),
            PropagationTarget::Custom(_) => fail!("Exact custom name required"),
            PropagationTarget::ShardDescription => PublicationTarget::ShardDescription,
        },
    })
}
/// Reconstruct only the original evidence under this sink's authenticated
/// runtime. A delivery ID and disk fields alone never grant authority.
/// Cold-read verification only: no writer, retention transaction or capability.
#[cfg(test)]
pub(crate) fn inspect_canonical_record(
    db: &Arc<crate::internal_db::InternalDb>,
    domain: &crate::propagation_outbox::OutboxDomain,
    runtime: &AuthenticatedSessionRuntime,
    request: &CanonicalFinalityRequest,
) -> Result<CanonicalFinalityRecord> {
    let limits = Limits::default();
    let (delivery, entry) =
        crate::propagation_outbox::inspect_delivery(db, domain, &limits, &request.node_receipt)?
            .ok_or_else(|| error!("Cold canonical delivery missing"))?;
    canonical_record(runtime, request, &delivery, &entry, &limits)
}

fn canonical_record(
    runtime: &AuthenticatedSessionRuntime,
    request: &CanonicalFinalityRequest,
    delivery: &crate::propagation_outbox::Delivery,
    entry: &UnverifiedRecord,
    limits: &Limits,
) -> Result<CanonicalFinalityRecord> {
    canonical_record_inner(runtime, request, delivery, entry, limits, None)
}

fn canonical_record_inner(
    runtime: &AuthenticatedSessionRuntime,
    request: &CanonicalFinalityRequest,
    delivery: &crate::propagation_outbox::Delivery,
    entry: &UnverifiedRecord,
    limits: &Limits,
    budget: Option<&crate::history_read_budget::HistoryReadBudget>,
) -> Result<CanonicalFinalityRecord> {
    crate::propagation_outbox::validate_recovery_record(entry, limits)?;
    let record = &entry.record;
    let expected_index = match runtime.local_role() {
        LocalRole::Validator(index) => Some(index),
        LocalRole::Observer => None,
    };
    let origin =
        delivery.origin.as_ref().ok_or_else(|| error!("Missing canonical source origin"))?;
    if request.node_receipt != delivery.delivery_id
        || delivery.record_id != entry.id
        || request.node_receipt != crate::propagation_outbox::delivery_id(record)?
        || request.block_id != record.block_id
        || (request.role == FinalityDeliveryRole::Final) != record.carrier.is_final()
        || request.local_adnl != UInt256::from(*runtime.local_adnl().data())
        || request.local_validator_index != expected_index
        || request.local_adnl != origin.local_adnl
        || request.local_validator_index != origin.local_validator_index
        || request.source_validator != origin.source_validator
        || origin.carrier_version != runtime.carrier_version()
        || record.domain.zerostate != runtime.pin().zerostate
        || record.domain.global_id != runtime.pin().global_id
        || record.domain.wire_profile != runtime.wire_profile()
        || record.protocol != runtime.protocol()
        || &record.profile != runtime.profile()
        || &record.session_id != runtime.session_id()
    {
        fail!("Canonical delivery differs from authenticated source binding");
    }
    let data = Arc::new(record.block_data.clone());
    let block = if let Some(budget) = budget {
        crate::block::BlockStuff::deserialize_block_bounded(record.block_id.clone(), data, budget)?
    } else {
        crate::block::BlockStuff::deserialize_block_checked(record.block_id.clone(), data)?
    };
    block.verify_expected_id(&record.block_id)?;
    let creator = block.block()?.read_extra()?.created_by().clone();
    if creator != request.source_validator
        || !runtime
            .committee()
            .iter()
            .any(|member| member.validator_id().ok().as_ref() == Some(&creator))
        || block.block()?.global_id() != runtime.pin().global_id
    {
        fail!("Canonical body creator differs from authenticated source");
    }
    let (_, previous) =
        crate::block::construct_and_check_prev_stuff(block.root_cell(), block.id(), false)?;
    if previous.prev != record.prev {
        fail!("Canonical body ancestry differs from retained record");
    }
    let wire: rtos_api::ton::ton_node::SignatureSet = if budget.is_some() {
        runtime
            .wire_profile()
            .deserialize_value_bounded(record.carrier.bytes(), record.carrier.bytes().len())?
    } else {
        runtime.wire_profile().deserialize_typed(record.carrier.bytes())?
    };
    if runtime.wire_profile().serialize(&wire)? != record.carrier.bytes() {
        fail!("Noncanonical retained signature carrier");
    }
    let rtos_api::ton::ton_node::SignatureSet::TonNode_SignatureSet_SimplexPq(fields) = wire else {
        fail!("Canonical retention requires a PQ carrier");
    };
    let context =
        runtime.pq_context().ok_or_else(|| error!("Canonical retention needs PQ runtime"))?;
    let verifier = match budget {
        Some(budget) => context.for_block_bounded(
            record.block_id.clone(),
            &crate::bounded_session_derivation::ConfigBudget(budget),
        )?,
        None => context.for_block(record.block_id.clone())?,
    };
    let network = match budget {
        Some(budget) => PqNetworkSignatureSet::from_node_bounded(
            fields,
            &crate::bounded_session_derivation::ConfigBudget(budget),
        )?,
        None => PqNetworkSignatureSet::from_node(fields)?,
    };
    let verified = match budget {
        Some(budget) => verifier.verify_network_bounded(
            &network,
            &crate::bounded_session_derivation::ConfigBudget(budget),
        )?,
        None => verifier.verify_network(&network)?,
    };
    if verified.is_final() != record.carrier.is_final() {
        fail!("Canonical carrier role mismatch");
    }
    let finality = if verified.is_final() {
        SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(verified.into_final()?.0))
    } else {
        SessionFinality::PqApproval(verified.into_approval()?.0)
    };
    Ok(CanonicalFinalityRecord {
        request: request.clone(),
        data: consensus_common::ConsensusCommonFactory::create_block_payload(
            record.block_data.clone().into(),
        ),
        finality,
        last_mc_finalized_seqno: delivery.last_mc,
        candidate_already_sent: delivery.candidate_already_sent,
        created_at_unix_secs: record.created_at_unix_secs,
    })
}

fn live_record(
    runtime: &AuthenticatedSessionRuntime,
    draft: &FinalizedDeliveryDraft,
    limits: &Limits,
) -> Result<PublicationRecord> {
    use crate::block::{construct_and_check_prev_stuff, BlockStuff};
    if draft.data.data().is_empty() || draft.data.data().len() > limits.max_block_bytes {
        fail!("Delivery body limit exceeded");
    }
    let block = BlockStuff::deserialize_block_checked(
        draft.block_id.clone(),
        Arc::new(draft.data.data().to_vec()),
    )?;
    block.verify_expected_id(&draft.block_id)?;
    if block.block()?.global_id() != runtime.pin().global_id {
        fail!("Delivery global ID mismatch");
    }
    let (_, header) = construct_and_check_prev_stuff(block.root_cell(), &draft.block_id, false)?;
    let verifier = runtime
        .pq_context()
        .ok_or_else(|| error!("Delivery needs PQ runtime"))?
        .for_block(draft.block_id.clone())?;
    let (network, final_) = match &draft.finality {
        SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(carrier)) => {
            verifier.verify_final(carrier)?;
            (PqNetworkSignatureSet::from_final_fields(carrier)?, true)
        }
        SessionFinality::PqApproval(carrier) => {
            verifier.verify_approval(carrier)?;
            (PqNetworkSignatureSet::from_approval(carrier)?, false)
        }
        _ => fail!("Delivery requires PQ Final or Approval"),
    };
    let creator = block.block()?.read_extra()?.created_by().clone();
    if creator != draft.source_info.source.block_creator()? {
        fail!("Delivery source differs from authenticated body creator");
    }
    let source = runtime
        .committee()
        .iter()
        .position(|member| member.validator_id().ok().as_ref() == Some(&creator))
        .ok_or_else(|| error!("Delivery creator is outside authenticated committee"))?;
    let locally_generated =
        matches!(runtime.local_role(), LocalRole::Validator(index) if index as usize == source);
    let bytes = runtime.wire_profile().serialize(&network.to_node().into_boxed())?;
    let now = draft.created_at_unix_secs;
    Ok(PublicationRecord {
        domain: OutboxDomain {
            zerostate: runtime.pin().zerostate.clone(),
            global_id: runtime.pin().global_id,
            wire_profile: runtime.wire_profile(),
        },
        protocol: runtime.protocol(),
        profile: runtime.profile().clone(),
        session_id: runtime.session_id().clone(),
        block_id: draft.block_id.clone(),
        block_data: draft.data.data().to_vec(),
        proof_data: None,
        prev: header.prev,
        carrier: if final_ {
            crate::propagation_outbox::StoredCarrier::Final(bytes)
        } else {
            crate::propagation_outbox::StoredCarrier::Approval(bytes)
        },
        locally_generated,
        created_at_unix_secs: now,
        expires_at_unix_secs: now
            .checked_add(limits.max_retention_secs)
            .ok_or_else(|| error!("Delivery expiry overflow"))?,
        effects: Vec::new(),
    })
}

fn destination(effect: &PublicationEffect) -> PropagationDestination {
    PropagationDestination {
        kind: match effect.kind {
            PublicationKind::Candidate => PropagationKind::Candidate,
            PublicationKind::Block => PropagationKind::Block,
            PublicationKind::Finality => PropagationKind::Finality,
            PublicationKind::ShardDescription => PropagationKind::ShardDescription,
        },
        target: match &effect.target {
            PublicationTarget::Public => PropagationTarget::Public,
            PublicationTarget::FastSync => PropagationTarget::FastSync,
            PublicationTarget::Custom(name) => PropagationTarget::Custom(name.clone()),
            PublicationTarget::ShardDescription => PropagationTarget::ShardDescription,
        },
    }
}
fn validate_plan(entry: &UnverifiedRecord) -> Result<PropagationPlan> {
    // The saved exact intent fixes recency and dedup at original admission.
    // A retry does not silently turn a previously selected candidate into no work.
    let plan = PropagationPlan::for_event(
        entry.record.protocol,
        PropagationEvent::Finalized,
        &entry.record.block_id,
        true,
        entry.record.locally_generated,
        entry.record.carrier.is_final(),
        0,
        false,
    );
    for effect in &entry.record.effects {
        if matches!(&effect.target, PublicationTarget::Custom(name) if name.is_empty()) {
            fail!("Durable publication needs an exact custom overlay name");
        }
        plan.for_destination(&destination(effect))?;
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn state() -> Arc<State> {
        Arc::new(State {
            activity: Mutex::new(WorkerActivity::default()),
            engine: Weak::new(),
            io: Arc::new(OwnedTasks::default()),
            enabled: AtomicBool::new(false),
            fatal: AtomicBool::new(false),
            stop: CancellationToken::new(),
            wake: Notify::new(),
            limits: Limits::default(),
            ready: tokio::sync::watch::channel(None).0,
            cursor: Mutex::new(Default::default()),
            acceptance_turn: AtomicBool::new(true),
            acceptance_verified: Mutex::new(Default::default()),
            accepted_receipts: Mutex::new(Default::default()),
            #[cfg(test)]
            acceptance_request_runs: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            actual_acceptance_runs: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            background_acceptance_runs: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            background_routing_turns: std::sync::atomic::AtomicUsize::new(0),
            acceptance_cursor: Mutex::new(0),
            acceptance_retry: Mutex::new(Default::default()),
            retry_after: Mutex::new(Default::default()),
            outstanding: Default::default(),
            #[cfg(test)]
            cleanup_commit_hook: Mutex::new(None),
        })
    }
    fn scheduling_entry(id: u64, expires: u64) -> UnverifiedRecord {
        // Only scheduling coordinates are relevant; this is not an authentication fixture.
        let effect =
            PublicationEffect { kind: PublicationKind::Block, target: PublicationTarget::Public };
        UnverifiedRecord {
            id: RecordId(id),
            stage: PublicationStage::Ready,
            pending: vec![effect.clone()],
            record: Arc::new(PublicationRecord {
                domain: OutboxDomain {
                    zerostate: Default::default(),
                    global_id: 0,
                    wire_profile: rtos_api::WireProfile::T0,
                },
                protocol:
                    consensus_common::simplex_protocol::SimplexProtocol::PrivateObserversPlumtree,
                profile: Default::default(),
                session_id: Default::default(),
                block_id: Default::default(),
                block_data: vec![],
                proof_data: None,
                prev: vec![],
                carrier: crate::propagation_outbox::StoredCarrier::Final(vec![]),
                locally_generated: false,
                created_at_unix_secs: 1,
                expires_at_unix_secs: expires,
                effects: vec![effect],
            }),
        }
    }
    #[test]
    fn publication_worker_completion_is_exactly_once_on_drop_and_success() {
        use std::sync::atomic::AtomicUsize;
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        drop(Completion(Some(Box::new(move |result| {
            assert!(result.is_err());
            counter.fetch_add(1, Ordering::SeqCst);
        }))));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let counter = calls.clone();
        Completion(Some(Box::new(move |result| {
            assert_eq!(result.unwrap(), UInt256::from([7; 32]));
            counter.fetch_add(1, Ordering::SeqCst);
        })))
        .finish(Ok(UInt256::from([7; 32])));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn publication_worker_queued_commands_precede_eager_maintenance() {
        let stop = CancellationToken::new();
        let wake = Notify::new();
        let (sender, mut receiver) = mpsc::channel(QUEUE_CAPACITY);
        let mut tick = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(60), RETRY_INTERVAL);
        for index in 0..QUEUE_CAPACITY {
            let (response, _) = oneshot::channel();
            sender.try_send(Submission::Query {
                id: UInt256::from([index as u8; 32]), response,
            }).unwrap();
        }
        for index in 0..QUEUE_CAPACITY {
            wake.notify_one();
            match next_worker_turn(&stop, &mut tick, &mut receiver, &wake).await {
                WorkerTurn::Command(Some(Submission::Query { id, .. })) => {
                    assert_eq!(id, UInt256::from([index as u8; 32]));
                }
                _ => panic!("eager maintenance overtook queued command {index}"),
            }
        }
        assert!(matches!(next_worker_turn(&stop, &mut tick, &mut receiver, &wake).await,
            WorkerTurn::Retry), "idle maintenance notification must remain available");
    }

    #[tokio::test]
    async fn publication_worker_due_maintenance_and_stop_precede_busy_mailbox() {
        let stop = CancellationToken::new();
        let wake = Notify::new();
        let (sender, mut receiver) = mpsc::channel(QUEUE_CAPACITY);
        let (response, _) = oneshot::channel();
        sender.try_send(Submission::Query { id: UInt256::default(), response }).unwrap();
        let mut tick = tokio::time::interval_at(
            tokio::time::Instant::now() - RETRY_INTERVAL, RETRY_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        assert!(matches!(next_worker_turn(&stop, &mut tick, &mut receiver, &wake).await,
            WorkerTurn::Retry), "the original due retry must not starve behind commands");
        assert_eq!(receiver.len(), 1);
        wake.notify_one();
        stop.cancel();
        assert!(matches!(next_worker_turn(&stop, &mut tick, &mut receiver, &wake).await,
            WorkerTurn::Stop), "shutdown must retain the queued request for rejection");
        assert_eq!(receiver.len(), 1);
    }
    #[test]
    fn publication_worker_canonical_completion_survives_owner_and_callback_failure() {
        use std::sync::atomic::AtomicUsize;
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        drop(CanonicalCompletion(Some(Box::new(move |result| {
            counter.fetch_add(1, Ordering::SeqCst);
            assert!(result.is_err());
            panic!("source callback failed after recording completion");
        }))));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let counter = calls.clone();
        CanonicalCompletion(Some(Box::new(move |result| {
            counter.fetch_add(1, Ordering::SeqCst);
            assert!(result.is_err());
            panic!("source callback failed after explicit completion");
        })))
        .finish(Err(error!("canonical write failed")));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn publication_worker_closing_completion_drains_on_unwind_and_callback_panic() {
        use std::sync::atomic::AtomicUsize;
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let result = std::panic::catch_unwind(move || {
            let _completion = ClosingCompletion::<()>(Some(Box::new(move |result| {
                counter.fetch_add(1, Ordering::SeqCst);
                assert!(result.is_err());
                panic!("source callback panicked during actor unwind");
            })));
            panic!("actor failed with accepted closing request");
        });
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let counter = calls.clone();
        ClosingCompletion(Some(Box::new(move |result: Result<()>| {
            counter.fetch_add(1, Ordering::SeqCst);
            assert!(result.is_ok());
            panic!("source callback panicked after successful close");
        })))
        .finish(Ok(()));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn outstanding_request_spans_its_callback_and_rolls_back_on_rejection() {
        let session = UInt256::from([0x31; 32]);
        let map: Arc<OutstandingRequests> = Default::default();
        // A held request counts; its callback still sees it outstanding.
        let observed = Arc::new(Mutex::new(None));
        let (seen, probe) = (observed.clone(), map.clone());
        let probe_session = session.clone();
        let mut callback: Option<Box<dyn FnOnce(Result<()>) + Send>> = Some(Box::new(move |_| {
            *seen.lock().unwrap() = Some(probe.count(&probe_session));
        }));
        hold(&mut callback, map.begin(&session).unwrap());
        assert_eq!(map.count(&session), 1);
        ClosingCompletion(callback).finish(Ok(()));
        assert_eq!(*observed.lock().unwrap(), Some(1), "outstanding through the callback");
        assert_eq!(map.count(&session), 0);
        // A panicking callback still ends the count after unwinding.
        let mut callback: Option<Box<dyn FnOnce(Result<()>) + Send>> =
            Some(Box::new(|_| panic!("callback panicked")));
        hold(&mut callback, map.begin(&session).unwrap());
        ClosingCompletion(callback).finish(Ok(()));
        assert_eq!(map.count(&session), 0);
        // A completion dropped by the owner runs its callback, then ends.
        let mut callback: Option<Box<dyn FnOnce(Result<()>) + Send>> = Some(Box::new(|_| {}));
        hold(&mut callback, map.begin(&session).unwrap());
        drop(ClosingCompletion(callback));
        assert_eq!(map.count(&session), 0);
        // A oneshot response ends the count after the value is handed over,
        // and an unsent dropped response ends it too.
        let (sender, mut receiver) = oneshot::channel::<u8>();
        let mut responder = Responder::new(sender);
        responder.outstanding = Some(map.begin(&session).unwrap());
        assert_eq!(map.count(&session), 1);
        responder.send(7).unwrap();
        assert_eq!(receiver.try_recv().unwrap(), 7);
        assert_eq!(map.count(&session), 0);
        let (sender, _receiver) = oneshot::channel::<u8>();
        let mut responder = Responder::new(sender);
        responder.outstanding = Some(map.begin(&session).unwrap());
        drop(responder);
        assert_eq!(map.count(&session), 0);
        // Counts are per session and never underflow.
        let other = UInt256::from([0x32; 32]);
        let first = map.begin(&session).unwrap();
        let second = map.begin(&other).unwrap();
        assert_eq!((map.count(&session), map.count(&other)), (1, 1));
        drop(first);
        drop(second);
        assert_eq!((map.count(&session), map.count(&other)), (0, 0));
    }

    #[test]
    fn outstanding_counts_refuse_overflow_and_poison_on_underflow() {
        use std::sync::atomic::AtomicUsize;
        let worker = PublicationWorker {
            sender: Mutex::new(None),
            tasks: Arc::new(OwnedTasks::default()),
            state: state(),
        };
        let record = Arc::unwrap_or_clone(scheduling_entry(1, 200).record);
        let session = record.session_id.clone();
        // One below the maximum still admits; at the maximum admission is
        // refused before anything is enqueued and the callback never runs.
        worker.state.outstanding.set_for_test(&session, usize::MAX - 1);
        let last = worker.state.outstanding.begin(&session).unwrap();
        assert_eq!(worker.outstanding_for_test(&session), usize::MAX);
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let request = Submission::Draft {
            record: record.clone(),
            last_mc: 0,
            candidate_already_sent: false,
            historical: false,
            origin: RecoveryOrigin {
                carrier_version: 1,
                local_adnl: UInt256::default(),
                source_validator: UInt256::default(),
                local_validator_index: None,
            },
            completion: Completion(Some(Box::new(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
            }))),
        };
        let refused = worker.admit_draft(request).unwrap_err().to_string();
        assert!(refused.contains("exhausted"), "{refused}");
        assert_eq!(calls.load(Ordering::SeqCst), 0, "a refused admission never completes");
        assert_eq!(worker.outstanding_for_test(&session), usize::MAX);
        drop(last);
        worker.state.outstanding.set_for_test(&session, 0);
        // An extra release is a broken invariant: no session is ever
        // quiescent again.
        let token = worker.state.outstanding.begin(&session).unwrap();
        worker.state.outstanding.set_for_test(&session, 0);
        drop(token);
        assert_eq!(worker.outstanding_for_test(&session), usize::MAX);
        assert_eq!(worker.outstanding_for_test(&UInt256::from([0x77; 32])), usize::MAX);
    }

    #[test]
    fn publication_worker_rejected_draft_rolls_back_its_outstanding_count() {
        let worker = PublicationWorker {
            sender: Mutex::new(None),
            tasks: Arc::new(OwnedTasks::default()),
            state: state(),
        };
        let record = Arc::unwrap_or_clone(scheduling_entry(1, 200).record);
        let session = record.session_id.clone();
        let request = Submission::Draft {
            record,
            last_mc: 0,
            candidate_already_sent: false,
            historical: false,
            origin: RecoveryOrigin {
                carrier_version: 1,
                local_adnl: UInt256::default(),
                source_validator: UInt256::default(),
                local_validator_index: None,
            },
            completion: Completion(Some(Box::new(|_| {}))),
        };
        assert!(worker.admit_draft(request).is_err());
        assert_eq!(worker.outstanding_for_test(&session), 0);
    }

    #[test]
    fn publication_worker_rejected_draft_does_not_complete() {
        use std::sync::atomic::AtomicUsize;
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let worker = PublicationWorker {
            sender: Mutex::new(None),
            tasks: Arc::new(OwnedTasks::default()),
            state: state(),
        };
        let request = Submission::Draft {
            record: Arc::unwrap_or_clone(scheduling_entry(1, 200).record),
            last_mc: 0,
            candidate_already_sent: false,
            historical: false,
            origin: RecoveryOrigin {
                carrier_version: 1,
                local_adnl: UInt256::default(),
                source_validator: UInt256::default(),
                local_validator_index: None,
            },
            completion: Completion(Some(Box::new(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
            }))),
        };
        assert!(worker.admit_draft(request).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn publication_worker_disabled_accepts_expired_debt_but_does_not_resolve_routing() {
        let state = state();
        let now = tokio::time::Instant::now();
        let mut draft = scheduling_entry(1, 1);
        draft.stage = PublicationStage::DraftDurable;
        Arc::make_mut(&mut draft.record).effects.clear();
        draft.pending.clear();
        let mut prepared = scheduling_entry(2, 1);
        prepared.stage = PublicationStage::Prepared;
        let mut accepted = draft.clone();
        accepted.id = RecordId(3);
        accepted.stage = PublicationStage::AcceptedDraft;
        let mut completed = accepted.clone();
        completed.id = RecordId(4);
        completed.stage = PublicationStage::Completed;
        let entries = vec![draft, prepared, accepted, completed];
        assert_eq!(state.select_acceptance(&entries, now).unwrap().id, RecordId(1));
        assert_eq!(state.select_acceptance(&entries, now).unwrap().id, RecordId(2));
        assert_eq!(state.select_acceptance(&entries, now).unwrap().id, RecordId(3));
        assert_eq!(state.select_acceptance(&entries, now).unwrap().id, RecordId(4));
        assert!(state.select_retry(&entries, 100, now).is_none());
        state.acceptance_verified.lock().unwrap().extend([3, 4]);
        assert!(state.select_acceptance(&entries, now + RETRY_INTERVAL).is_some());
        // A successful per-process verification removes Completed repair debt,
        // but an AcceptedDraft still needs routing when explicitly enabled.
        state.enabled.store(true, Ordering::Release);
        state.acceptance_cursor.lock().unwrap().clone_from(&2);
        assert_eq!(
            state.select_acceptance(&entries, now + RETRY_INTERVAL).unwrap().id,
            RecordId(3)
        );
    }

    #[test]
    fn publication_worker_blocked_routing_does_not_hide_other_acceptance_or_sends() {
        let state = state();
        state.enabled.store(true, Ordering::Release);
        let now = tokio::time::Instant::now();
        let mut blocked = scheduling_entry(1, 200);
        blocked.stage = PublicationStage::AcceptedDraft;
        Arc::make_mut(&mut blocked.record).effects.clear();
        blocked.pending.clear();
        let mut draft = blocked.clone();
        draft.id = RecordId(2);
        draft.stage = PublicationStage::DraftDurable;
        let ready = scheduling_entry(3, 200);
        let entries = vec![blocked, draft, ready];
        state.acceptance_verified.lock().unwrap().insert(3);
        state.acceptance_retry.lock().unwrap().insert(1, now + RETRY_INTERVAL);
        assert_eq!(state.select_acceptance(&entries, now).unwrap().id, RecordId(2));
        assert_eq!(state.select_retry(&entries, 100, now).unwrap().0.id, RecordId(3));
        assert_eq!(
            state.select_acceptance(&entries, now + RETRY_INTERVAL).unwrap().id,
            RecordId(1)
        );
    }

    #[test]
    fn publication_worker_revalidates_completed_and_expired_ready_once_per_process() {
        let worker = state();
        let now = tokio::time::Instant::now();
        let mut completed = scheduling_entry(1, 1);
        completed.stage = PublicationStage::Completed;
        completed.pending.clear();
        let expired = scheduling_entry(2, 1);
        let entries = vec![completed, expired];
        assert!(!worker.enabled.load(Ordering::Acquire));
        assert_eq!(worker.select_acceptance(&entries, now).unwrap().id, RecordId(1));
        worker.acceptance_verified.lock().unwrap().insert(1);
        assert_eq!(worker.select_acceptance(&entries, now).unwrap().id, RecordId(2));
        worker.acceptance_verified.lock().unwrap().insert(2);
        assert!(worker.select_acceptance(&entries, now + RETRY_INTERVAL).is_none());
        assert!(worker.select_retry(&entries, 100, now).is_none());
        // A new process must not inherit this in-memory durability evidence.
        assert_eq!(state().select_acceptance(&entries, now).unwrap().id, RecordId(1));
    }

    #[test]
    fn publication_worker_live_effect_is_not_delayed_by_expired_records() {
        let state = state();
        let mut entries: Vec<_> = (1..=1023).map(|id| scheduling_entry(id, 100)).collect();
        entries.push(scheduling_entry(1024, 200));
        let now = tokio::time::Instant::now();
        let selected = state.select_retry(&entries, 100, now).unwrap();
        assert_eq!(selected.0.id, RecordId(1024));
        assert_eq!(entries.len(), 1024, "expired records must remain durable");
        assert!(state.select_retry(&entries, 100, now).is_none(), "live target must obey backoff");
        assert_eq!(
            state.select_retry(&entries, 100, now + RETRY_INTERVAL).unwrap().0.id,
            RecordId(1024)
        );
        assert!(state.select_retry(&entries, 200, now + RETRY_INTERVAL).is_none());
    }
    #[test]
    fn publication_worker_failure_backoff_does_not_block_other_exact_targets() {
        let state = state();
        let mut first = scheduling_entry(1, 200);
        let second_effect = PublicationEffect {
            kind: PublicationKind::Finality,
            target: PublicationTarget::Public,
        };
        first.pending.push(second_effect.clone());
        Arc::make_mut(&mut first.record).effects.push(second_effect.clone());
        let entries = vec![first, scheduling_entry(2, 200)];
        let now = tokio::time::Instant::now();
        assert_eq!(state.select_retry(&entries, 100, now).unwrap().0.id, RecordId(1));
        assert_eq!(state.select_retry(&entries, 100, now).unwrap().0.id, RecordId(2));
        assert_eq!(state.select_retry(&entries, 100, now).unwrap().1, second_effect);
        assert!(state.select_retry(&entries, 100, now).is_none());
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn publication_worker_cancelled_waiter_retains_real_blocking_write() {
        let state = state();
        let (entered, observing) = oneshot::channel();
        let (release, held) = std::sync::mpsc::channel();
        let wrote = Arc::new(AtomicBool::new(false));
        let wrote_worker = wrote.clone();
        let worker = state.clone();
        let waiter = tokio::spawn(async move {
            worker
                .blocking(move || {
                    let _ = entered.send(());
                    held.recv_timeout(Duration::from_secs(10)).unwrap();
                    wrote_worker.store(true, Ordering::Release);
                    Ok(())
                })
                .await
        });
        observing.await.unwrap();
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert!(tokio::time::timeout(Duration::from_millis(20), state.io.wait()).await.is_err());
        assert!(!wrote.load(Ordering::Acquire));
        release.send(()).unwrap();
        state.io.wait().await.unwrap();
        assert!(wrote.load(Ordering::Acquire));
        state.io.wait().await.unwrap();
    }
    #[tokio::test]
    async fn publication_worker_blocking_panic_is_sticky_failure() {
        let state = state();
        assert!(state
            .blocking::<()>(|| panic!("controlled publication disk panic"))
            .await
            .is_err());
        assert!(state.fatal.load(Ordering::Acquire));
        assert!(state.stop.is_cancelled());
        assert!(state.io.wait().await.is_err());
        assert!(state.io.wait().await.is_err());
    }
}
