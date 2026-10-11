// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later

use rtos_block::{error, Result};
use std::{future::Future, sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}};
use tokio::{runtime::{Handle, RuntimeFlavor}, sync::{watch, Notify}, task::JoinHandle};

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
        Arc::new(Self { runtime, handles: Mutex::new(Some(Vec::new())), stop,
            stopped: AtomicBool::new(false), notify: Notify::new(), errors: Mutex::new(Vec::new()) })
    }
    pub fn spawn(self: &Arc<Self>, name: &'static str, future: impl Future<Output=()> + Send + 'static) -> bool {
        let mut handles = self.handles.lock().unwrap();
        let Some(handles) = handles.as_mut() else { return false; };
        // Panic requests sibling cancellation immediately, not only when stop is called.
        let owner = self.clone();
        handles.push((name, self.runtime.spawn(async move {
            use futures::FutureExt;
            if let Err(panic) = std::panic::AssertUnwindSafe(future).catch_unwind().await {
                owner.errors.lock().unwrap().push(format!("{name}: panicked"));
                owner.close();
                std::panic::resume_unwind(panic);
            }
        })));
        true
    }
    pub fn background(self: &Arc<Self>, name: &'static str, future: impl Future<Output=()> + Send + 'static) -> bool {
        let mut stop = self.stop.subscribe();
        self.spawn(name, async move {
            if *stop.borrow() { return; }
            tokio::select! { biased; _ = stop.changed() => {}, _ = future => {} }
        })
    }
    pub fn close(self: &Arc<Self>) {
        let mut handles = self.handles.lock().unwrap();
        let Some(handles) = handles.take() else { return; };
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
    pub fn drained(&self) -> bool { self.stopped.load(Ordering::Acquire) }
    pub async fn wait(self: &Arc<Self>) -> Result<()> {
        self.close();
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.drained() { break; }
            notified.await;
        }
        let errors = self.errors.lock().unwrap();
        if errors.is_empty() { Ok(()) } else { Err(error!("Overlay worker failures: {}", errors.join("; "))) }
    }
    pub fn wait_sync(self: &Arc<Self>) -> Result<()> {
        self.close();
        match Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::CurrentThread => {
                Err(error!("Synchronous overlay drain requires an OS thread or multi-thread runtime"))
            }
            Ok(_) => tokio::task::block_in_place(|| futures::executor::block_on(self.wait())),
            Err(_) => futures::executor::block_on(self.wait()),
        }
    }
}
