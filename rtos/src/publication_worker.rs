// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! One bounded publication actor. Accepted blocking writes retain their real join
//! independently of the caller's response future. Idle loops never own Engine.
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
        DurableFinalitySink, DurableFinalitySinkPtr, FinalizedDeliveryCompletion,
        FinalizedDeliveryDraft,
    },
    session_runtime::{AuthenticatedSessionRuntime, LocalRole},
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
    response: oneshot::Sender<Result<AcceptedSessionBlock>>,
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
enum Submission {
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
}
impl Submission {
    fn reject(self) {
        match self {
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
        }
    }
}
struct SessionSink {
    worker: Arc<PublicationWorker>,
    runtime: Arc<AuthenticatedSessionRuntime>,
}
impl DurableFinalitySink for SessionSink {
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
            historical: false,
        };
        // On admission failure the source owns retry and completion must not run.
        self.worker.admit_draft(request)
    }
}
struct State {
    engine: Weak<Engine>,
    io: Arc<OwnedTasks>,
    enabled: AtomicBool,
    fatal: AtomicBool,
    stop: CancellationToken,
    wake: Notify,
    limits: Limits,
    ready: tokio::sync::watch::Sender<Option<std::result::Result<(), String>>>,
    cursor: Mutex<(u64, std::collections::BTreeMap<u64, usize>)>,
    acceptance_cursor: Mutex<u64>,
    acceptance_retry: Mutex<std::collections::BTreeMap<u64, tokio::time::Instant>>,
    retry_after: Mutex<std::collections::BTreeMap<(u64, PublicationEffect), tokio::time::Instant>>,
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
            engine: Arc::downgrade(engine),
            io: Arc::new(OwnedTasks::default()),
            enabled: AtomicBool::new(false),
            fatal: AtomicBool::new(false),
            stop: CancellationToken::new(),
            wake: Notify::new(),
            limits: Limits::default(),
            ready: tokio::sync::watch::channel(None).0,
            cursor: Mutex::new(Default::default()),
            acceptance_cursor: Mutex::new(0),
            acceptance_retry: Mutex::new(Default::default()),
            retry_after: Mutex::new(Default::default()),
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
            record,
        };
        crate::propagation_outbox::validate_recovery_record(&probe, &self.state.limits)?;
        validate_plan(&probe)?;
        let record = probe.record;
        let (response, result) = oneshot::channel();
        {
            let sender =
                self.sender.lock().map_err(|_| error!("Publication submission lock poisoned"))?;
            if self.state.fatal.load(Ordering::Acquire) || self.state.stop.is_cancelled() {
                fail!("Publication worker is stopped or failed");
            }
            sender
                .as_ref()
                .ok_or_else(|| error!("Publication admission closed"))?
                .try_send(Submission::Legacy(LegacySubmission { record, response }))
                .map_err(|error| error!("Publication queue admission: {error}"))?;
        }
        result.await.map_err(|error| error!("Publication actor completion: {error}"))?
    }
    pub(crate) fn sink(
        self: &Arc<Self>,
        runtime: Arc<AuthenticatedSessionRuntime>,
    ) -> DurableFinalitySinkPtr {
        Arc::new(SessionSink { worker: self.clone(), runtime })
    }
    fn admit_draft(&self, request: Submission) -> Result<()> {
        let result = (|| {
            let sender =
                self.sender.lock().map_err(|_| error!("Publication admission poisoned"))?;
            if self.state.stop.is_cancelled() || self.state.fatal.load(Ordering::Acquire) {
                fail!("Publication admission closed");
            }
            Ok(sender.as_ref().ok_or_else(|| error!("Publication admission closed"))?.clone())
        })();
        let rejected = match result {
            Ok(sender) => match sender.try_send(request) {
                Ok(()) => return Ok(()),
                Err(error) => error.into_inner(),
            },
            Err(_) => request,
        };
        if let Submission::Draft { mut completion, .. } = rejected {
            completion.0.take();
        }
        fail!("Publication draft queue full or closed; retain source evidence")
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
            record: record.clone(),
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
        let store = store.clone();
        let result = self
            .blocking(move || {
                let result = work(&store);
                // Capacity/validation rejection is recoverable. An uncertain disk
                // result poisons the store and must stop all further transactions.
                let poisoned = result.is_err() && store.pending().is_err();
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
            let command = tokio::select! {
                _ = self.stop.cancelled() => { receiver.close(); None },
                command = receiver.recv() => command,
                _ = tick.tick() => { self.recover(&store, &mut receiver).await; continue; },
                _ = self.wake.notified() => { self.recover(&store, &mut receiver).await; continue; },
            };
            if let Some(command) = command {
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
        match command {
            Submission::Legacy(command) => self.submit_legacy(store, command).await,
            Submission::Draft {
                record,
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
                        record: record.clone(),
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
                        validate_origin(&authenticated, engine.as_ref(), &origin)?;
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
                    let entry = self.resolve_draft(store, &engine, entry).await?;
                    self.accept(store, engine, entry).await
                }
                .await;
                let _ = response.send(result);
                self.wake.notify_one();
            }
        }
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
                record: command.record.clone(),
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
    ) -> Result<UnverifiedRecord> {
        if entry.stage != PublicationStage::DraftDurable {
            return Ok(entry);
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
        validate_origin(&authenticated, engine.as_ref(), origin)?;
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
        self.write(store, move |store| store.resolve_draft(id, effects)).await?;
        self.snapshot(store)
            .await?
            .into_iter()
            .find(|e| e.id == id)
            .ok_or_else(|| error!("Resolved draft disappeared"))
    }
    async fn accept(
        &self,
        store: &Arc<PropagationOutbox>,
        engine: Arc<Engine>,
        entry: UnverifiedRecord,
    ) -> Result<AcceptedSessionBlock> {
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
        let id = publication.entry().id;
        if let Some(delivery) =
            self.write(store, move |store| store.delivery_for_record(id)).await?
        {
            let origin = delivery
                .origin
                .as_ref()
                .ok_or_else(|| error!("Delivery recovery origin absent"))?;
            validate_origin(&publication, engine.as_ref(), origin)?;
        }
        // Deliberately not cancelable: this phase can write state/proof data.
        let (entry, accepted) = accept_authenticated_publication(publication, engine).await?;
        let id = entry.id;
        self.write(store, move |store| store.mark_ready(id)).await?;
        Ok(accepted)
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
    async fn recover(
        &self,
        store: &Arc<PropagationOutbox>,
        receiver: &mut mpsc::Receiver<Submission>,
    ) {
        if !self.enabled.load(Ordering::Acquire) || self.stop.is_cancelled() {
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
        let selected = {
            let mut retry = self.acceptance_retry.lock().unwrap();
            retry.retain(|id, _| {
                entries.iter().any(|e| {
                    e.id.0 == *id
                        && matches!(
                            e.stage,
                            PublicationStage::DraftDurable | PublicationStage::Prepared
                        )
                })
            });
            let mut cursor = self.acceptance_cursor.lock().unwrap();
            let start = entries.iter().position(|e| e.id.0 > *cursor).unwrap_or(0);
            let entry = (0..entries.len())
                .map(|offset| &entries[(start + offset) % entries.len()])
                .find(|e| {
                    matches!(e.stage, PublicationStage::DraftDurable | PublicationStage::Prepared)
                        && !retry.get(&e.id.0).is_some_and(|deadline| *deadline > now)
                })
                .cloned();
            if let Some(entry) = &entry {
                *cursor = entry.id.0;
                retry.insert(entry.id.0, now + RETRY_INTERVAL);
            }
            entry
        };
        if let Some(entry) = selected {
            let retry_id = entry.id.0;
            if let Some(engine) = self.engine.upgrade() {
                let result = async {
                    let entry = self.resolve_draft(store, &engine, entry).await?;
                    self.accept(store, engine, entry).await
                }
                .await;
                if let Err(error) = result {
                    self.acceptance_retry
                        .lock()
                        .unwrap()
                        .insert(retry_id, tokio::time::Instant::now() + RETRY_INTERVAL);
                    log::warn!("Durable delivery acceptance deferred: {error}");
                }
                self.wake.notify_one();
            }
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

fn validate_origin(
    publication: &crate::propagation_outbox_auth::AuthenticatedPublication,
    engine: &Engine,
    origin: &RecoveryOrigin,
) -> Result<()> {
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
    if engine.adnl_key_by_id(&transport).is_none() {
        fail!("Recovery local transport key unavailable");
    }
    let local_id = if let Some(index) = origin.local_validator_index {
        let member = committee
            .get(index as usize)
            .ok_or_else(|| error!("Recovery local validator index out of range"))?;
        let id = member.validator_id()?;
        if member.adnl_addr()? != transport
            || !engine
                .consensus_transport_bindings()?
                .iter()
                .any(|binding| binding.validator_id == id && binding.adnl_key_id == transport)
        {
            fail!("Recovery local validator transport binding is not authenticated");
        }
        Some(id)
    } else {
        if committee.iter().any(|member| member.adnl_addr().ok().as_ref() == Some(&transport)) {
            fail!("Recovery observer role conflicts with historical validator transport");
        }
        None
    };
    if publication.entry().record.locally_generated != (local_id.as_ref() == Some(&creator)) {
        fail!("Recovery creator routing claim differs from authenticated local role");
    }
    Ok(())
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
            engine: Weak::new(),
            io: Arc::new(OwnedTasks::default()),
            enabled: AtomicBool::new(false),
            fatal: AtomicBool::new(false),
            stop: CancellationToken::new(),
            wake: Notify::new(),
            limits: Limits::default(),
            ready: tokio::sync::watch::channel(None).0,
            cursor: Mutex::new(Default::default()),
            acceptance_cursor: Mutex::new(0),
            acceptance_retry: Mutex::new(Default::default()),
            retry_after: Mutex::new(Default::default()),
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
            record: PublicationRecord {
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
            },
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
            record: scheduling_entry(1, 200).record,
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
        first.record.effects.push(second_effect.clone());
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
