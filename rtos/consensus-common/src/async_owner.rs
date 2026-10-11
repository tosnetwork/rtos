// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later

use rtos_block::{error, Result};
use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use tokio::{
    runtime::{Handle, RuntimeFlavor},
    sync::{watch, Notify},
    task::JoinHandle,
};

/// Owns actual worker joins. The finalizer outlives individual stop waiters.
pub(crate) struct AsyncOwner {
    runtime: Handle,
    handles: Mutex<Option<Vec<(&'static str, JoinHandle<()>)>>>,
    stop: watch::Sender<bool>,
    stopped: AtomicBool,
    notify: Notify,
    errors: Mutex<Vec<String>>,
}
impl AsyncOwner {
    pub fn new(runtime: Handle) -> Arc<Self> {
        let (stop, _) = watch::channel(false);
        Arc::new(Self {
            runtime,
            handles: Mutex::new(Some(Vec::new())),
            stop,
            stopped: AtomicBool::new(false),
            notify: Notify::new(),
            errors: Mutex::new(Vec::new()),
        })
    }
    pub fn spawn(
        self: &Arc<Self>,
        name: &'static str,
        future: impl Future<Output = ()> + Send + 'static,
    ) -> bool {
        let mut handles = self.handles.lock().unwrap();
        let Some(handles) = handles.as_mut() else {
            return false;
        };
        use futures::FutureExt;
        // Observe actual completed joins on each admission; do not retain one
        // task allocation per request for the entire session lifetime.
        let mut index = 0;
        while index < handles.len() {
            match (&mut handles[index].1).now_or_never() {
                Some(result) => {
                    let (name, _) = handles.swap_remove(index);
                    if let Err(error) = result {
                        self.errors.lock().unwrap().push(format!("{name}: {error}"));
                    }
                }
                None => index += 1,
            }
        }
        // Panic requests sibling cancellation immediately, not only when stop is called.
        let owner = self.clone();
        handles.push((
            name,
            self.runtime.spawn(async move {
                use futures::FutureExt;
                if let Err(panic) = std::panic::AssertUnwindSafe(future).catch_unwind().await {
                    owner.errors.lock().unwrap().push(format!("{name}: panicked"));
                    owner.close();
                    std::panic::resume_unwind(panic);
                }
            }),
        ));
        true
    }
    pub fn background(
        self: &Arc<Self>,
        name: &'static str,
        future: impl Future<Output = ()> + Send + 'static,
    ) -> bool {
        let mut stop = self.stop.subscribe();
        self.spawn(name, async move {
            if *stop.borrow() {
                return;
            }
            tokio::select! { biased; _ = stop.changed() => {}, _ = future => {} }
        })
    }
    pub fn close(self: &Arc<Self>) {
        let mut handles = self.handles.lock().unwrap();
        let Some(handles) = handles.take() else {
            return;
        };
        self.stop.send_replace(true);
        let owner = self.clone();
        self.runtime.spawn(async move {
            for (name, handle) in handles {
                if let Err(err) = handle.await {
                    owner.errors.lock().unwrap().push(format!("{name}: {err}"));
                }
            }
            owner.stopped.store(true, Ordering::Release);
            owner.notify.notify_waiters();
        });
    }
    pub fn drained(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }
    pub async fn wait(self: &Arc<Self>) -> Result<()> {
        self.close();
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.drained() {
                break;
            }
            notified.await;
        }
        let errors = self.errors.lock().unwrap();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(error!("Overlay worker failures: {}", errors.join("; ")))
        }
    }
    pub fn wait_sync(self: &Arc<Self>) -> Result<()> {
        self.close();
        match Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::CurrentThread => Err(error!(
                "Synchronous overlay drain requires an OS thread or multi-thread runtime"
            )),
            Ok(_) => tokio::task::block_in_place(|| futures::executor::block_on(self.wait())),
            Err(_) => futures::executor::block_on(self.wait()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn overlay_owned_cancelled_waiter_retains_actual_join() {
        let owner = AsyncOwner::new(Handle::current());
        let (release, held) = oneshot::channel();
        let resource = Arc::new(());
        let weak = Arc::downgrade(&resource);
        assert!(owner.spawn("held", async move {
            let _resource = resource;
            held.await.unwrap();
        }));
        let waiter_owner = owner.clone();
        let waiter = tokio::spawn(async move { waiter_owner.wait().await });
        tokio::task::yield_now().await;
        waiter.abort();
        let _ = waiter.await;
        owner.close();
        assert!(!owner.drained());
        assert!(weak.upgrade().is_some());
        assert!(!owner.spawn("late", async {}));
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), owner.wait())
            .await
            .unwrap()
            .unwrap();
        owner.wait().await.unwrap();
        assert!(owner.drained());
        assert!(weak.upgrade().is_none());
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn overlay_owned_panic_is_sticky_and_joins_held_sibling() {
        let owner = AsyncOwner::new(Handle::current());
        let (release, held) = oneshot::channel();
        owner.spawn("held sibling", async move {
            held.await.unwrap();
        });
        owner.spawn("panic source", async {
            panic!("injected worker panic");
        });
        owner.close();
        assert!(!owner.drained());
        release.send(()).unwrap();
        let first = owner.wait().await.unwrap_err().to_string();
        assert!(first.contains("panic source"));
        assert_eq!(first, owner.wait().await.unwrap_err().to_string());
        assert!(owner.drained());
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn overlay_owned_completed_workers_are_reaped_during_admission() {
        let owner = AsyncOwner::new(Handle::current());
        for _ in 0..2000 {
            let (tx, rx) = oneshot::channel();
            assert!(owner.spawn("short request", async move {
                tx.send(()).unwrap();
            }));
            rx.await.unwrap();
            // Actual completion may follow the response. Observe the handle
            // rather than assuming the response means its destructor finished.
            loop {
                if owner.handles.lock().unwrap().as_ref().unwrap().last().unwrap().1.is_finished() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        }
        assert!(owner.handles.lock().unwrap().as_ref().unwrap().len() <= 2);
        owner.wait().await.unwrap();
    }
    #[tokio::test]
    async fn overlay_owned_sync_bridge_refuses_current_thread_runtime() {
        let owner = AsyncOwner::new(Handle::current());
        owner.background("idle", std::future::pending());
        assert!(owner.wait_sync().is_err());
        assert!(!owner.drained());
        owner.wait().await.unwrap();
    }
}
