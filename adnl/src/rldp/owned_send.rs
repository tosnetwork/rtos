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
    SiblingFailed,
}
impl std::fmt::Display for SendCancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RLDP send cancelled: {self:?}")
    }
}
impl std::error::Error for SendCancelled {}

pub(super) struct SendControl {
    token: CancellationToken,
    reason: Mutex<Option<SendCancelled>>,
    parts: tokio_util::task::TaskTracker,
}
impl SendControl {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            token: CancellationToken::new(),
            reason: Mutex::new(None),
            parts: tokio_util::task::TaskTracker::new(),
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
        if let Some(reason) = *self.reason.lock().unwrap() {
            return Err(reason.into());
        }
        Ok(())
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
}
impl SendWorkerPool {
    pub fn new(owner: Arc<AdnlTasks>) -> Self {
        Self {
            core: Arc::new(Core { queue: lockfree::queue::Queue::new(), sem: Semaphore::new(0) }),
            owner,
            admission: Arc::new(Mutex::new(true)),
            started: std::sync::OnceLock::new(),
        }
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
            for _ in 0..num_cpus::get().clamp(1, 8) {
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
                            if owner.is_closed() { job.control.cancel(SendCancelled::OwnerClosed); }
                            let result = match job.control.check() {
                                Err(error) => Err(error),
                                Ok(()) => match std::panic::AssertUnwindSafe(job.work).catch_unwind().await {
                                    Ok(result) => result,
                                    Err(_) => {
                                        job.control.cancel(SendCancelled::SiblingFailed);
                                        owner.failed("RLDP part panicked".into());
                                        Err(error!("RLDP part panicked"))
                                    }
                                },
                            };
                            if result.as_ref().err().is_some_and(|e| e.downcast_ref::<FecTaskFailed>().is_some()) {
                                owner.failed("RLDP FEC task panicked".into());
                            }
                            let _ = job.done.send(result);
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

// Called only by retained send owners. There is intentionally no timeout/select
// around the real handle: running encoder work cannot be forcibly cancelled.
pub(super) async fn fec<T, R, F>(mut state: T, work: F) -> Result<(T, R)>
where
    T: Send + 'static,
    R: Send + 'static,
    F: FnOnce(&mut T) -> Result<R> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let result = work(&mut state)?;
        Ok((state, result))
    })
    .await
    .map_err(|e| {
        log::error!(target: TARGET, "RLDP FEC worker failed: {e}");
        error!("RLDP FEC task failed").context(FecTaskFailed(e))
    })?
}

pub(super) struct SendRegistration {
    pub transfers: Arc<lockfree::map::Map<super::TransferId, super::RldpTransfer>>,
    pub send: super::TransferId,
    pub receive: Option<super::TransferId>,
    pub owner: Arc<AdnlTasks>,
    pub bounded_permit: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
}
impl Drop for SendRegistration {
    fn drop(&mut self) {
        self.transfers.insert(self.send, super::RldpTransfer::Done);
        if let Some(id) = self.receive {
            self.transfers.insert(id, super::RldpTransfer::Done);
        }
        let transfers = self.transfers.clone();
        let send = self.send;
        let receive = self.receive;
        let owner = self.owner.clone();
        let permit = self.bounded_permit.clone();
        let expiry = async move {
            let _permit = permit;
            tokio::select! {
                _ = owner.cancelled() => {},
                _ = tokio::time::sleep(std::time::Duration::from_millis(super::RldpNode::TIMEOUT_MAX_MS * 2)) => {},
            }
            transfers.remove(&send);
            if let Some(id) = receive {
                transfers.remove(&id);
            }
        };
        if self.owner.spawn_or_return("RLDP transfer expiry", expiry).is_err() {
            self.transfers.remove(&self.send);
            if let Some(id) = self.receive {
                self.transfers.remove(&id);
            }
        }
    }
}
