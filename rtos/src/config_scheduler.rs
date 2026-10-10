// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later

use super::{Answer, Task};
use adnl::common::Wait;
use rtos_block::{fail, Result};
use std::{
    future::Future,
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
};
use tokio::{runtime::Handle, sync::mpsc::UnboundedReceiver, task::JoinHandle};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub(super) struct Admission {
    pub open: bool,
    pub started: bool,
}

/// Closing admission does not cancel accepted configuration writes or callbacks.
/// Independent supervisors retain real task handles even if shutdown waiters drop.
pub(super) struct ConfigScheduler {
    pub admission: Mutex<Admission>,
    pub cancellation: CancellationToken,
    pub callbacks: TaskTracker,
    worker: TaskTracker,
    errors: Mutex<Vec<String>>,
}

impl Default for ConfigScheduler {
    fn default() -> Self {
        Self {
            admission: Mutex::new(Admission { open: true, started: false }),
            cancellation: CancellationToken::new(),
            callbacks: TaskTracker::new(),
            worker: TaskTracker::new(),
            errors: Mutex::new(Vec::new()),
        }
    }
}

impl ConfigScheduler {
    pub fn stop(&self) {
        let mut admission = self.admission.lock().unwrap();
        admission.open = false;
        self.cancellation.cancel();
        self.worker.close();
    }

    pub fn own_worker(self: &Arc<Self>, runtime: &Handle, worker: JoinHandle<()>) {
        let owner = self.clone();
        let token = self.worker.token();
        runtime.spawn(async move {
            let _token = token;
            if let Err(error) = worker.await {
                owner.errors.lock().unwrap().push(format!("configuration scheduler: {error}"));
                owner.stop();
            }
        });
    }

    pub fn spawn_callback(
        self: &Arc<Self>,
        runtime: &Handle,
        future: impl Future<Output = ()> + Send + 'static,
    ) {
        // Only the admitted scheduler creates callbacks. Closing public admission
        // does not prevent callbacks required by an already accepted write.
        let worker = runtime.spawn(future);
        let owner = self.clone();
        let token = self.callbacks.token();
        runtime.spawn(async move {
            let _token = token;
            if let Err(error) = worker.await {
                owner.errors.lock().unwrap().push(format!("configuration subscriber: {error}"));
                owner.stop();
            }
        });
    }

    pub async fn stop_and_wait(&self) -> Result<()> {
        self.stop();
        self.worker.wait().await;
        // Also join callbacks after a scheduler panic, which skips its normal
        // drain loop. Their key queries fail when the inbox is dropped.
        self.callbacks.close();
        self.callbacks.wait().await;
        let errors = self.errors.lock().unwrap();
        if !errors.is_empty() {
            fail!("Configuration task failures: {}", errors.join("; "));
        }
        Ok(())
    }
}

/// A panicked actor must wake the current request and every queued caller.
pub(super) struct PendingAnswer(Option<Arc<Wait<Answer>>>);
impl PendingAnswer {
    pub fn new(wait: Arc<Wait<Answer>>) -> Self {
        Self(Some(wait))
    }
    pub fn respond(&mut self, answer: Answer) {
        self.0.take().unwrap().respond(Some(answer));
    }
}
impl Drop for PendingAnswer {
    fn drop(&mut self) {
        if let Some(wait) = self.0.take() {
            wait.respond(None);
        }
    }
}

pub(super) struct ConfigInbox(pub UnboundedReceiver<(Arc<Wait<Answer>>, Task)>);
impl Deref for ConfigInbox {
    type Target = UnboundedReceiver<(Arc<Wait<Answer>>, Task)>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for ConfigInbox {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for ConfigInbox {
    fn drop(&mut self) {
        self.0.close();
        while let Ok((wait, _)) = self.0.try_recv() {
            wait.respond(None);
        }
    }
}
