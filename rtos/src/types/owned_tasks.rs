// Copyright (C) 2026 RTOS contributors.
// Licensed under the GNU General Public License v3.0.

use rtos_block::{fail, Result};
use std::{
    future::Future,
    sync::{Arc, Mutex},
};
use tokio::task::{AbortHandle, JoinHandle};
use tokio_util::{
    sync::CancellationToken,
    task::{TaskTracker, TaskTrackerToken},
};

/// Owns task completion, including tasks cancelled or panicked outside the owner.
/// The admission lock covers both creating a worker and registering its join.
/// Cancellation never aborts the join supervisor itself.
pub(crate) struct OwnedTasks {
    open: Mutex<bool>,
    tracker: TaskTracker,
    errors: Arc<Mutex<Vec<String>>>,
    cancellation: CancellationToken,
    parent: Option<Arc<OwnedTasks>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn owned_tasks_waits_for_real_worker_after_cancelled_waiter() {
        let owner = Arc::new(OwnedTasks::new(CancellationToken::new()));
        let (release, held) = tokio::sync::oneshot::channel();
        owner
            .spawn("held storage operation", async move {
                held.await.unwrap();
            })
            .unwrap();
        let waiting_owner = owner.clone();
        let waiter = tokio::spawn(async move { waiting_owner.wait().await });
        tokio::task::yield_now().await;
        waiter.abort();
        let _ = waiter.await;
        assert!(tokio::time::timeout(Duration::from_millis(20), owner.wait()).await.is_err());
        assert!(owner.spawn("late work", async {}).is_err());
        release.send(()).unwrap();
        owner.wait().await.unwrap();
        owner.wait().await.unwrap();
    }

    #[tokio::test]
    async fn owned_tasks_reports_external_abort_and_child_join_before_parent_drain() {
        let owner = Arc::new(OwnedTasks::new(CancellationToken::new()));
        let child = OwnedTasks::child(owner.clone(), owner.cancellation().child_token());
        let abort = child.spawn("aborted child", std::future::pending()).unwrap();
        abort.abort();
        assert!(child.wait().await.unwrap_err().to_string().contains("aborted child"));
        assert!(owner.wait().await.unwrap_err().to_string().contains("aborted child"));
        assert!(child.spawn("late child", async {}).is_err());
    }
}

impl OwnedTasks {
    pub fn new(cancellation: CancellationToken) -> Self {
        Self {
            open: Mutex::new(true),
            tracker: TaskTracker::new(),
            errors: Arc::default(),
            cancellation,
            parent: None,
        }
    }

    pub fn child(parent: Arc<Self>, cancellation: CancellationToken) -> Self {
        Self { errors: parent.errors.clone(), parent: Some(parent), ..Self::new(cancellation) }
    }

    pub fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }

    /// An admitted asynchronous operation also blocks drain until its future is
    /// completed or dropped. Callers must register resources before any await.
    pub fn enter(&self) -> Result<TaskTrackerToken> {
        let open = self.open.lock().unwrap();
        if !*open || self.cancellation.is_cancelled() {
            fail!("Task owner is stopping");
        }
        Ok(self.tracker.token())
    }

    pub fn spawn_handle(
        &self,
        name: &'static str,
        start: impl FnOnce() -> JoinHandle<()>,
    ) -> Result<AbortHandle> {
        self.spawn_result(name, || Ok(start()))
    }

    pub fn spawn_result(
        &self,
        name: &'static str,
        start: impl FnOnce() -> Result<JoinHandle<()>>,
    ) -> Result<AbortHandle> {
        let open = self.open.lock().unwrap();
        if !*open || self.cancellation.is_cancelled() {
            fail!("Task owner is stopping: {name}");
        }
        let parent = self.parent.as_ref().map(|owner| owner.enter()).transpose()?;
        let handle = start()?;
        let abort = handle.abort_handle();
        let errors = self.errors.clone();
        self.tracker.spawn(async move {
            let _parent = parent;
            if let Err(error) = handle.await {
                errors.lock().unwrap().push(format!("{name}: {error}"));
            }
        });
        Ok(abort)
    }

    pub fn spawn(
        &self,
        name: &'static str,
        future: impl Future<Output = ()> + Send + 'static,
    ) -> Result<AbortHandle> {
        self.spawn_handle(name, || tokio::spawn(future))
    }

    /// Only for cancellation-safe work, such as network waits. A worker doing
    /// storage operations must select cancellation at its own safe boundaries.
    pub fn spawn_cancelable(
        &self,
        name: &'static str,
        future: impl Future<Output = ()> + Send + 'static,
    ) -> Result<AbortHandle> {
        let cancellation = self.cancellation.clone();
        self.spawn(name, async move {
            tokio::select! { biased; _ = cancellation.cancelled() => {}, _ = future => {} }
        })
    }

    pub fn stop(&self) {
        let mut open = self.open.lock().unwrap();
        *open = false;
        self.cancellation.cancel();
        self.tracker.close();
    }

    pub fn record_error(&self, error: String) {
        let mut errors = self.errors.lock().unwrap();
        if !errors.contains(&error) {
            errors.push(error);
        }
    }

    pub async fn wait(&self) -> Result<()> {
        self.stop();
        self.tracker.wait().await;
        let errors = self.errors.lock().unwrap();
        if !errors.is_empty() {
            fail!("Owned worker failures: {}", errors.join("; "));
        }
        Ok(())
    }
}
