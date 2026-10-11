// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! One bounded publication actor. Accepted blocking writes retain their real join
//! independently of the caller's response future. Idle loops never own Engine.
use crate::{
    engine::Engine,
    engine_traits::EngineOperations,
    propagation_outbox::{
        Limits, OutboxDomain, PropagationOutbox, PublicationEffect, PublicationKind,
        PublicationRecord, PublicationStage, PublicationTarget, RecordId, UnverifiedRecord,
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
use futures::FutureExt;
use rtos_block::{error, fail, Result};
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
struct Submission {
    record: PublicationRecord,
    response: oneshot::Sender<Result<AcceptedSessionBlock>>,
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
                .try_send(Submission { record, response })
                .map_err(|error| error!("Publication queue admission: {error}"))?;
        }
        result.await.map_err(|error| error!("Publication actor completion: {error}"))?
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
                    let _ = command
                        .response
                        .send(Err(error!("Publication shutdown before durable admission")));
                }
                break;
            }
            if self.engine.strong_count() == 0 {
                break;
            }
        }
    }
    async fn submit_one(&self, store: &Arc<PropagationOutbox>, command: Submission) {
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
        // Round-robin eligible effects. Success advances immediately; failure
        // has a separate minimum one-second backoff for each exact target.
        let selected = {
            let mut cursor = self.cursor.lock().unwrap();
            let mut retry = self.retry_after.lock().unwrap();
            cursor.1.retain(|id, _| entries.iter().any(|entry| entry.id.0 == *id));
            retry.retain(|(id, effect), _| {
                entries.iter().any(|entry| entry.id.0 == *id && entry.pending.contains(effect))
            });
            let start = entries.iter().position(|entry| entry.id.0 > cursor.0).unwrap_or(0);
            let now = tokio::time::Instant::now();
            let mut selected = None;
            for index in 0..entries.len() {
                let entry = &entries[(start + index) % entries.len()];
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
        };
        let Some((entry, effect)) = selected else {
            return;
        };
        drop(entries);
        for entry in [entry] {
            if self.stop.is_cancelled() {
                return;
            }
            let Some(engine) = self.engine.upgrade() else { return };
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            if entry.record.is_expired(now) {
                metrics::counter!("rtos_publication_expired_pending_total").increment(1);
                continue; // Never acknowledge or discard unsent expired work.
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
                    continue;
                }
            };
            let plan = match validate_plan(&entry) {
                Ok(plan) => plan,
                Err(_) => continue,
            };
            for effect in [effect] {
                if self.stop.is_cancelled() {
                    return;
                }
                let destination = destination(&effect);
                let exact = match plan.for_destination(&destination) {
                    Ok(plan) => plan,
                    Err(_) => continue,
                };
                let Some(outcome) =
                    self.send_while_serving(store, receiver, &engine, &accepted, &exact).await
                else {
                    self.retry_after.lock().unwrap().insert(
                        (entry.id.0, effect.clone()),
                        tokio::time::Instant::now() + RETRY_INTERVAL,
                    );
                    self.wake.notify_one();
                    continue;
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
            retry_after: Mutex::new(Default::default()),
        })
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
