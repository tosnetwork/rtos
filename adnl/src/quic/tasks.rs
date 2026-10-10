// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later

use rtos_block::{fail, Result};
use std::{
    future::Future,
    sync::{Arc, Mutex},
};
use tokio::runtime::Handle;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

#[derive(Default)]
pub(super) struct ShutdownCompletion {
    result: Mutex<Option<std::result::Result<(), String>>>,
    changed: tokio::sync::Notify,
}

impl ShutdownCompletion {
    pub fn finish(&self, result: std::result::Result<(), String>) {
        *self.result.lock().unwrap() = Some(result);
        self.changed.notify_waiters();
    }

    pub async fn wait(&self) -> Result<()> {
        loop {
            let changed = self.changed.notified();
            if let Some(result) = self.result.lock().unwrap().clone() {
                return result.map_err(anyhow::Error::msg);
            }
            changed.await;
        }
    }
}

/// Admission and actual worker joins share one lifetime. Supervisors are never
/// cancelled by transport shutdown: they observe the real worker's terminal state.
pub(super) struct QuicTasks {
    open: Mutex<bool>,
    runtime: Handle,
    cancellation: CancellationToken,
    workers: TaskTracker,
    errors: Mutex<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn quic_owned_waiter_cancellation_preserves_accepted_worker() {
        let owner = QuicTasks::new(Handle::current(), CancellationToken::new());
        let (release, held) = oneshot::channel();
        let (finished, completion) = oneshot::channel();
        assert!(owner.spawn("held subscriber", async move {
            held.await.unwrap();
            finished.send(()).unwrap();
        }));
        owner.close();
        assert!(!owner.spawn("late", async { panic!("closed admission") }));
        let mut wait = Box::pin(owner.wait());
        assert!(tokio::time::timeout(std::time::Duration::from_millis(20), &mut wait)
            .await
            .is_err());
        drop(wait);
        release.send(()).unwrap();
        owner.wait().await.unwrap();
        completion.await.unwrap();
        owner.wait().await.unwrap();
    }

    #[tokio::test]
    async fn quic_owned_worker_panic_is_sticky_and_closes_admission() {
        let owner = QuicTasks::new(Handle::current(), CancellationToken::new());
        assert!(owner.spawn("controlled failure", async { panic!("injected QUIC worker failure") }));
        let first = owner.wait().await.unwrap_err().to_string();
        assert!(first.contains("controlled failure"));
        assert_eq!(owner.wait().await.unwrap_err().to_string(), first);
        assert!(!owner.spawn("late", async {}));
    }

    #[tokio::test]
    async fn quic_owned_enqueue_racing_shutdown_cannot_register_late_sender() {
        let owner = QuicTasks::new(Handle::current(), CancellationToken::new());
        let (queued, queue_observed) = std::sync::mpsc::channel();
        let (release, held) = std::sync::mpsc::channel();
        let enqueuer = owner.clone();
        let worker = std::thread::spawn(move || {
            enqueuer
                .admit(|| {
                    queued.send(()).unwrap();
                    held.recv().unwrap();
                })
                .unwrap();
        });
        queue_observed.recv().unwrap();
        let closer = owner.clone();
        let stop = std::thread::spawn(move || closer.close());
        release.send(()).unwrap();
        worker.join().unwrap();
        stop.join().unwrap();
        assert!(!owner.spawn("sender after close", async { panic!("late sender polled") }));
        assert!(owner.admit(|| panic!("late queue mutation")).is_none());
        owner.wait().await.unwrap();
    }
}

impl QuicTasks {
    pub fn new(runtime: Handle, cancellation: CancellationToken) -> Arc<Self> {
        Arc::new(Self {
            open: Mutex::new(true),
            runtime,
            cancellation,
            workers: TaskTracker::new(),
            errors: Mutex::new(Vec::new()),
        })
    }

    pub fn spawn(
        self: &Arc<Self>,
        name: &'static str,
        future: impl Future<Output = ()> + Send + 'static,
    ) -> bool {
        let open = self.open.lock().unwrap();
        if !*open || self.cancellation.is_cancelled() {
            return false;
        }
        let tracked = self.workers.token();
        let worker = self.runtime.spawn(future);
        let owner = self.clone();
        self.runtime.spawn(async move {
            let _tracked = tracked;
            if let Err(error) = worker.await {
                owner.errors.lock().unwrap().push(format!("{name}: {error}"));
                owner.close();
            }
        });
        true
    }

    /// Perform a synchronous enqueue under the same gate as worker admission.
    /// The closure must not spawn through this owner or await another task.
    pub fn admit<T>(&self, operation: impl FnOnce() -> T) -> Option<T> {
        let open = self.open.lock().unwrap();
        if !*open || self.cancellation.is_cancelled() {
            return None;
        }
        Some(operation())
    }

    pub fn spawn_cancelable(
        self: &Arc<Self>,
        name: &'static str,
        future: impl Future<Output = ()> + Send + 'static,
    ) -> bool {
        let cancellation = self.cancellation.clone();
        self.spawn(name, async move {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => {},
                _ = future => {},
            }
        })
    }

    pub fn close(&self) {
        let mut open = self.open.lock().unwrap();
        *open = false;
        self.cancellation.cancel();
        self.workers.close();
    }

    pub async fn wait(&self) -> Result<()> {
        self.close();
        self.workers.wait().await;
        let errors = self.errors.lock().unwrap();
        if !errors.is_empty() {
            fail!("QUIC worker failures: {}", errors.join("; "));
        }
        Ok(())
    }
}
