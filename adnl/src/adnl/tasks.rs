// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later

use rtos_block::{error, Result};
use std::{
    future::Future,
    sync::{Arc, Mutex},
    thread,
};
use tokio_util::{
    sync::CancellationToken,
    task::{TaskTracker, TaskTrackerToken},
};

/// Owns actual async task and OS-thread joins. Closing admission and acquiring a
/// tracker token are serialized; cancelling a caller waiting for stop cannot
/// detach a worker or discard its terminal error.
pub(crate) struct AdnlTasks {
    open: Mutex<bool>,
    runtime: tokio::runtime::Handle,
    workers: TaskTracker,
    cancellation: CancellationToken,
    stopped: CancellationToken,
    errors: Mutex<Vec<String>>,
    cleanup: Mutex<Vec<Box<dyn FnOnce() + Send>>>,
    wake: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}
impl AdnlTasks {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            open: Mutex::new(true),
            runtime: tokio::runtime::Handle::current(),
            workers: TaskTracker::new(),
            cancellation: CancellationToken::new(),
            stopped: CancellationToken::new(),
            errors: Mutex::new(Vec::new()),
            wake: Mutex::new(None),
            cleanup: Mutex::new(Vec::new()),
        })
    }
    pub fn on_stopped(&self, cleanup: impl FnOnce() + Send + 'static) {
        self.cleanup.lock().unwrap().push(Box::new(cleanup));
    }
    pub fn set_wake(&self, wake: impl Fn() + Send + Sync + 'static) {
        *self.wake.lock().unwrap() = Some(Box::new(wake));
    }
    pub fn enter(&self) -> Result<TaskTrackerToken> {
        let open = self.open.lock().unwrap();
        if !*open {
            return Err(error!("ADNL task admission closed"));
        }
        Ok(self.workers.token())
    }
    pub fn spawn_or_return<F>(
        self: &Arc<Self>,
        name: &'static str,
        future: F,
    ) -> std::result::Result<(), F>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let open = self.open.lock().unwrap();
        if !*open {
            return Err(future);
        }
        let token = self.workers.token();
        let worker = self.runtime.spawn(future);
        let owner = self.clone();
        self.runtime.spawn(async move {
            let _token = token;
            if let Err(error) = worker.await {
                owner.failed(format!("{name}: {error}"));
            }
        });
        Ok(())
    }
    pub fn spawn(
        self: &Arc<Self>,
        name: &'static str,
        future: impl Future<Output = ()> + Send + 'static,
    ) -> bool {
        self.spawn_or_return(name, future).is_ok()
    }
    pub fn spawn_cancelable(
        self: &Arc<Self>,
        name: &'static str,
        future: impl Future<Output = ()> + Send + 'static,
    ) -> bool {
        let cancel = self.cancellation.clone();
        self.spawn(name, async move {
            tokio::select! { biased; _ = cancel.cancelled() => {}, _ = future => {} }
        })
    }
    pub fn thread(
        self: &Arc<Self>,
        name: String,
        worker: impl FnOnce() + Send + 'static,
    ) -> Result<()> {
        let open = self.open.lock().unwrap();
        if !*open {
            return Err(error!("ADNL thread admission closed"));
        }
        let token = self.workers.token();
        let handle = thread::Builder::new().name(name.clone()).spawn(worker)?;
        let owner = self.clone();
        // Joining is blocking, so never occupy an async executor thread. This
        // supervisor cannot be cancelled by an individual stop waiter.
        self.runtime.spawn_blocking(move || {
            let _token = token;
            if handle.join().is_err() {
                owner.failed(format!("{name}: thread panicked"));
            }
        });
        Ok(())
    }
    fn failed(self: &Arc<Self>, error: String) {
        self.errors.lock().unwrap().push(error);
        self.close();
    }
    pub fn close(self: &Arc<Self>) {
        let mut open = self.open.lock().unwrap();
        if *open {
            *open = false;
            if let Some(wake) = self.wake.lock().unwrap().as_ref() {
                wake();
            }
            self.cancellation.cancel();
            self.workers.close();
            let owner = self.clone();
            self.runtime.spawn(async move {
                owner.workers.wait().await;
                for cleanup in owner.cleanup.lock().unwrap().drain(..) {
                    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(cleanup)).is_err() {
                        owner.errors.lock().unwrap().push("ADNL resource cleanup panicked".into());
                    }
                }
                owner.stopped.cancel();
            });
        }
    }
    pub fn is_closed(&self) -> bool {
        self.cancellation.is_cancelled()
    }
    pub async fn cancelled(&self) {
        self.cancellation.cancelled().await;
    }
    pub async fn wait(self: &Arc<Self>) -> Result<()> {
        self.close();
        self.stopped.cancelled().await;
        let errors = self.errors.lock().unwrap();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(error!("ADNL worker failures: {}", errors.join("; ")))
        }
    }
}
