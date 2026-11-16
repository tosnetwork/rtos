/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 * RTOS project modifications (2026-10-11): owned RLDP sender lifecycle.
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! RLDP sender owners. Cancellation requests drain; they never detach active work.
use super::TARGET;
use crate::adnl::tasks::AdnlTasks;
use futures::FutureExt;
use rtos_block::{error, Result};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};
use tokio::sync::{oneshot, Semaphore};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug)]
pub(super) enum SendCancelled {
    CallerDropped,
    Deadline,
    OwnerClosed,
    PeerEvicted,
    SiblingFailed,
}
impl std::fmt::Display for SendCancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RLDP send cancelled: {self:?}")
    }
}
impl std::error::Error for SendCancelled {}

pub(super) struct SendControl {
    pub(super) protocol_deadline: Option<std::time::Instant>,
    token: CancellationToken,
    reason: Mutex<Option<SendCancelled>>,
    parts: tokio_util::task::TaskTracker,
    failure: Mutex<Option<Result<bool>>>,
    #[cfg(test)]
    pub test_after_start: Mutex<Option<Arc<dyn Fn(u32) -> Result<Option<bool>> + Send + Sync>>>,
    #[cfg(test)]
    pub test_after_fec: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    #[cfg(test)]
    pub test_deadline: Mutex<Option<std::time::Duration>>,
    #[cfg(test)]
    pub test_bbr_error: std::sync::atomic::AtomicBool,
}
impl SendControl {
    pub fn new() -> Arc<Self> {
        Self::with_protocol_deadline(None)
    }
    pub fn with_protocol_deadline(protocol_deadline: Option<std::time::Instant>) -> Arc<Self> {
        Arc::new(Self {
            protocol_deadline,
            token: CancellationToken::new(),
            reason: Mutex::new(None),
            parts: tokio_util::task::TaskTracker::new(),
            failure: Mutex::new(None),
            #[cfg(test)]
            test_after_start: Mutex::new(None),
            #[cfg(test)]
            test_after_fec: Mutex::new(None),
            #[cfg(test)]
            test_deadline: Mutex::new(None),
            #[cfg(test)]
            test_bbr_error: std::sync::atomic::AtomicBool::new(false),
        })
    }
    pub fn deadline(&self) -> std::time::Duration {
        let remaining = self
            .protocol_deadline
            .map(|deadline| deadline.saturating_duration_since(std::time::Instant::now()));
        #[cfg(test)]
        if let Some(deadline) = *self.test_deadline.lock().unwrap() {
            return remaining.map_or(deadline, |remaining| remaining.min(deadline));
        }
        remaining.unwrap_or_else(|| {
            std::time::Duration::from_millis(super::RldpNode::TIMEOUT_OUTBOUND_HARD_MS)
        })
    }
    pub fn cancel(&self, reason: SendCancelled) {
        let mut previous = self.reason.lock().unwrap();
        if previous.is_none() {
            *previous = Some(reason);
        }
        self.token.cancel();
    }
    pub async fn cancelled(&self) {
        self.token.cancelled().await;
    }
    pub fn check(&self) -> Result<()> {
        if self.protocol_deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            self.cancel(SendCancelled::Deadline);
        }
        if let Some(reason) = *self.reason.lock().unwrap() {
            return Err(reason.into());
        }
        Ok(())
    }
    pub(super) fn record_failure(&self, result: &mut Result<bool>) {
        if matches!(result, Ok(true)) {
            return;
        }
        let mut first = self.failure.lock().unwrap();
        if first.is_none() {
            *first = Some(match result {
                Ok(false) => Ok(false),
                _ => std::mem::replace(result, Err(SendCancelled::SiblingFailed.into())),
            });
        }
        self.cancel(SendCancelled::SiblingFailed);
    }
    pub fn take_failure(&self) -> Option<Result<bool>> {
        self.failure.lock().unwrap().take()
    }

    pub async fn drain(&self) {
        self.parts.close();
        self.parts.wait().await;
    }
    pub fn guard(self: &Arc<Self>) -> CancelOnDrop {
        CancelOnDrop(self.clone())
    }
}
pub(super) struct CancelOnDrop(Arc<SendControl>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel(SendCancelled::CallerDropped);
    }
}

type Work = Pin<Box<dyn Future<Output = Result<bool>> + Send>>;
struct Job {
    work: Work,
    control: Arc<SendControl>,
    done: oneshot::Sender<Result<bool>>,
}
struct Core {
    queue: lockfree::queue::Queue<Job>,
    sem: Semaphore,
}

pub(super) struct SendWorkerPool {
    core: Arc<Core>,
    owner: Arc<AdnlTasks>,
    admission: Arc<Mutex<bool>>,
    started: std::sync::OnceLock<()>,
    pub(super) workers: usize,
    fec_slots: std::sync::OnceLock<Arc<Semaphore>>,
}
impl SendWorkerPool {
    pub fn new(owner: Arc<AdnlTasks>) -> Self {
        Self {
            core: Arc::new(Core { queue: lockfree::queue::Queue::new(), sem: Semaphore::new(0) }),
            owner,
            admission: Arc::new(Mutex::new(true)),
            started: std::sync::OnceLock::new(),
            workers: num_cpus::get().clamp(1, 8),
            fec_slots: std::sync::OnceLock::new(),
        }
    }
    pub(super) fn fec_slots(&self) -> Arc<Semaphore> {
        self.fec_slots.get_or_init(|| Arc::new(Semaphore::new(self.workers))).clone()
    }

    // Like native connection actors, an ACK wait yields without occupying a
    // scarce compute worker. The real blocking FEC work has a separate limit.
    pub(super) fn submit_v2(
        &self,
        control: Arc<SendControl>,
        work: impl Future<Output = Result<bool>> + Send + 'static,
    ) -> Result<oneshot::Receiver<Result<bool>>> {
        let open = self.admission.lock().unwrap();
        if !*open || self.owner.is_closed() {
            return Err(SendCancelled::OwnerClosed.into());
        }
        let owner_token = self.owner.enter()?;
        let token = control.parts.token();
        let (done, result) = oneshot::channel();
        let job = Job {
            control,
            done,
            work: Box::pin(async move {
                let _token = token;
                work.await
            }),
        };
        self.owner.spawn_admitted(
            "RLDP V2 part",
            owner_token,
            Self::run_job(job, self.owner.clone()),
        );
        Ok(result)
    }

    async fn run_job(job: Job, owner: Arc<AdnlTasks>) {
        if owner.is_closed() {
            job.control.cancel(SendCancelled::OwnerClosed);
        }
        let mut panicked = false;
        let mut result = match job.control.check() {
            Err(error) => Err(error),
            Ok(()) => match std::panic::AssertUnwindSafe(job.work).catch_unwind().await {
                Ok(result) => result,
                Err(_) => {
                    panicked = true;
                    Err(error!("RLDP part panicked"))
                }
            },
        };
        if result.as_ref().err().is_some_and(|e| e.downcast_ref::<FecTaskFailed>().is_some()) {
            panicked = true;
        }
        job.control.record_failure(&mut result);
        if panicked {
            owner.failed("RLDP sender worker panicked".into());
        }
        let _ = job.done.send(result);
    }

    pub fn submit(
        &self,
        control: Arc<SendControl>,
        work: impl Future<Output = Result<bool>> + Send + 'static,
    ) -> Result<oneshot::Receiver<Result<bool>>> {
        let mut open = self.admission.lock().unwrap();
        if !*open || self.owner.is_closed() {
            *open = false;
            return Err(SendCancelled::OwnerClosed.into());
        }
        // One startup lease spans registration of every worker, so shutdown
        // cannot observe a partially registered pool as drained.
        let startup = self.owner.enter()?;
        self.started.get_or_init(|| {
            for _ in 0..self.workers {
                let core = self.core.clone();
                let owner = self.owner.clone();
                let admission = self.admission.clone();
                self.owner.spawn_admitted("RLDP send pool", startup.clone(), async move {
                    loop {
                        let stopping = tokio::select! {
                            biased;
                            _ = owner.cancelled() => true,
                            permit = core.sem.acquire() => match permit { Ok(p) => { p.forget(); false }, Err(_) => true },
                        };
                        if stopping {
                            let mut open = admission.lock().unwrap();
                            *open = false;
                            core.sem.close();
                            while let Some(job) = core.queue.pop() {
                                job.control.cancel(SendCancelled::OwnerClosed);
                                let _ = job.done.send(Err(SendCancelled::OwnerClosed.into()));
                            }
                            break;
                        }
                        if let Some(job) = core.queue.pop() {
                            Self::run_job(job, owner.clone()).await;
                        }
                    }
                });
            }
        });
        let (done, result) = oneshot::channel();
        let token = control.parts.token();
        let tracked = async move {
            let _token = token;
            work.await
        };
        self.core.queue.push(Job { work: Box::pin(tracked), control, done });
        self.core.sem.add_permits(1);
        drop(startup);
        Ok(result)
    }
}
impl Drop for SendWorkerPool {
    fn drop(&mut self) {
        *self.admission.lock().unwrap() = false;
        self.core.sem.close();
    }
}

#[derive(Debug)]
struct FecTaskFailed(tokio::task::JoinError);
impl std::fmt::Display for FecTaskFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RLDP FEC worker failed: {}", self.0)
    }
}
impl std::error::Error for FecTaskFailed {}

pub(super) async fn supervise(
    control: Arc<SendControl>,
    owner: Arc<AdnlTasks>,
    deadline: std::time::Duration,
    work: impl Future<Output = Result<bool>>,
) -> Result<bool> {
    let work = std::panic::AssertUnwindSafe(work).catch_unwind();
    tokio::pin!(work);
    let result = tokio::select! {
        result = &mut work => result,
        _ = owner.cancelled() => { control.cancel(SendCancelled::OwnerClosed); work.await },
        _ = tokio::time::sleep(deadline) => { control.cancel(SendCancelled::Deadline); work.await },
    };
    match result {
        Ok(result) => result,
        Err(_) => {
            control.cancel(SendCancelled::SiblingFailed);
            owner.failed("RLDP transfer panicked".into());
            Err(error!("RLDP transfer panicked"))
        }
    }
}

// A permit remains with the actual blocking owner until its JoinHandle ends.
// Cancellation can reject queued work, but never releases a running FEC slot.
pub(super) async fn fec_limited<T, R, F>(
    state: T,
    control: Arc<SendControl>,
    owner: Arc<AdnlTasks>,
    capacity: Arc<Semaphore>,
    work: F,
) -> Result<(T, R)>
where
    T: Send + 'static,
    R: Send + 'static,
    F: FnOnce(&mut T) -> Result<R> + Send + 'static,
{
    let permit = tokio::select! {
        biased;
        _ = control.cancelled() => { control.check()?; unreachable!() },
        _ = owner.cancelled() => return Err(SendCancelled::OwnerClosed.into()),
        permit = capacity.acquire_owned() => permit?,
    };
    let ((state, _permit), result) =
        fec((state, permit), control, owner, move |(state, _)| work(state)).await?;
    Ok((state, result))
}

// Called only by retained send owners. There is intentionally no timeout/select
// around the real handle: running encoder work cannot be forcibly cancelled.
pub(super) async fn fec<T, R, F>(
    mut state: T,
    control: Arc<SendControl>,
    owner: Arc<AdnlTasks>,
    work: F,
) -> Result<(T, R)>
where
    T: Send + 'static,
    R: Send + 'static,
    F: FnOnce(&mut T) -> Result<R> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        // Cancellation may arrive while Tokio's blocking queue is occupied.
        // An admitted async part does not authorize starting queued FEC later.
        if owner.is_closed() {
            control.cancel(SendCancelled::OwnerClosed);
        }
        control.check()?;
        let result = work(&mut state)?;
        #[cfg(test)]
        {
            let hook = control.test_after_fec.lock().unwrap().clone();
            if let Some(hook) = hook {
                hook();
            }
        }
        Ok((state, result))
    })
    .await
    .map_err(|e| {
        log::error!(target: TARGET, "RLDP FEC worker failed: {e}");
        error!("RLDP FEC task failed").context(FecTaskFailed(e))
    })?
}

pub(super) struct SendRegistration {
    pub peer: Option<(std::sync::Weak<super::RldpPeer>, CancellationToken)>,
    pub transfers: Arc<lockfree::map::Map<super::TransferId, super::RldpTransfer>>,
    pub send: super::TransferId,
    pub receive: Option<super::TransferId>,
    pub owner: Arc<AdnlTasks>,
    pub bounded_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
}
fn with_live_peer(
    peer: &Option<(std::sync::Weak<super::RldpPeer>, CancellationToken)>,
    action: impl FnOnce(Option<&mut std::collections::HashSet<super::TransferId>>),
) {
    if let Some((weak, closed)) = peer {
        if let Some(peer) = weak.upgrade() {
            let mut ids = peer.registrations.lock().unwrap();
            if !closed.is_cancelled() {
                action(Some(&mut ids));
            }
        }
    } else {
        action(None);
    }
}
impl Drop for SendRegistration {
    fn drop(&mut self) {
        with_live_peer(&self.peer, |_| {
            self.transfers.insert(self.send, super::RldpTransfer::Done);
            if let Some(id) = self.receive {
                self.transfers.insert(id, super::RldpTransfer::Done);
            }
        });
        let transfers = self.transfers.clone();
        let send = self.send;
        let receive = self.receive;
        let owner = self.owner.clone();
        let peer = self.peer.clone();
        let expiry = async move {
            tokio::select! {
                _ = owner.cancelled() => {},
                _ = async {
                    if let Some((_, closed)) = &peer { closed.cancelled().await; }
                    else { std::future::pending::<()>().await; }
                } => {},
                _ = tokio::time::sleep(std::time::Duration::from_millis(super::RldpNode::TIMEOUT_MAX_MS * 2)) => {},
            }
            with_live_peer(&peer, |ids| {
                transfers.remove(&send);
                if let Some(id) = receive {
                    transfers.remove(&id);
                }
                if let Some(ids) = ids {
                    ids.remove(&send);
                    if let Some(id) = receive {
                        ids.remove(&id);
                    }
                }
            });
        };
        if self.owner.spawn_or_return("RLDP transfer expiry", expiry).is_err() {
            with_live_peer(&self.peer, |ids| {
                self.transfers.remove(&send);
                if let Some(id) = receive {
                    self.transfers.remove(&id);
                }
                if let Some(ids) = ids {
                    ids.remove(&send);
                    if let Some(id) = receive {
                        ids.remove(&id);
                    }
                }
            });
        }
    }
}

#[cfg(test)]
#[path = "owned_send_tests.rs"]
mod tests;
