// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Per-Engine observations around actual owned work; no capability construction.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
static HOOKS: LazyLock<Mutex<std::collections::HashMap<usize, Arc<Hook>>>> =
    LazyLock::new(|| Mutex::new(Default::default()));
struct Hook {
    gate: Mutex<Option<(tokio::sync::oneshot::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
    fail_sync: AtomicBool,
    syncs: AtomicUsize,
    completed: tokio::sync::Notify,
}
pub(crate) struct Control {
    key: usize,
    hook: Arc<Hook>,
    pub entered: Option<tokio::sync::oneshot::Receiver<()>>,
    release: Option<std::sync::mpsc::Sender<()>>,
}
impl Control {
    pub(crate) fn release(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
    pub(crate) fn syncs(&self) -> usize {
        self.hook.syncs.load(Ordering::SeqCst)
    }
    pub(crate) async fn completed(&self) {
        self.hook.completed.notified().await;
    }
}
impl Drop for Control {
    fn drop(&mut self) {
        self.release();
        HOOKS.lock().unwrap().remove(&self.key);
    }
}
pub(crate) fn install(engine: &Engine, pause: bool, fail_sync: bool) -> Control {
    let key = engine as *const Engine as usize;
    let (sent, received) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let hook = Arc::new(Hook {
        gate: Mutex::new(pause.then_some((sent, wait))),
        fail_sync: AtomicBool::new(fail_sync),
        syncs: AtomicUsize::new(0),
        completed: Default::default(),
    });
    assert!(HOOKS.lock().unwrap().insert(key, hook.clone()).is_none());
    Control { key, hook, entered: pause.then_some(received), release: pause.then_some(release) }
}
fn get(engine: &Engine) -> Option<Arc<Hook>> {
    HOOKS.lock().unwrap().get(&(engine as *const Engine as usize)).cloned()
}
pub(super) fn before_commit(engine: &Engine) -> Result<()> {
    if let Some(hook) = get(engine) {
        if let Some((entered, release)) = hook.gate.lock().unwrap().take() {
            let _ = entered.send(());
            release
                .recv()
                .map_err(|_| error!("Historical commit test gate released without completion"))?;
        }
    }
    Ok(())
}
pub(super) fn after_sync(engine: &Engine) -> Result<()> {
    if let Some(hook) = get(engine) {
        hook.syncs.fetch_add(1, Ordering::SeqCst);
        if hook.fail_sync.swap(false, Ordering::SeqCst) {
            // Actual file/directory barriers already completed. Model their
            // caller observing an uncertain outcome; this is not a syscall EIO.
            return Err(std::io::Error::from_raw_os_error(5).into());
        }
    }
    Ok(())
}
pub(super) fn completed(engine: &Engine) {
    if let Some(hook) = get(engine) {
        hook.completed.notify_one();
    }
}

pub(crate) fn available_requests() -> usize {
    REQUESTS.available_permits()
}
