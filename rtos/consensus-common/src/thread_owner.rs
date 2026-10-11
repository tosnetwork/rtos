// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Retained OS thread handles. Completion means join, including thread-local destructors.
use rtos_block::{error, Result};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Condvar, Mutex,
};
use std::thread::{Builder, JoinHandle, ThreadId};

#[derive(Default)]
struct State {
    threads: Vec<(String, JoinHandle<()>)>,
    ids: Vec<ThreadId>,
    joining: bool,
    result: Option<std::result::Result<(), String>>,
}

/// Synchronous ownership used by legacy consensus workers. Callers may run
/// `join` in a retained blocking task; cancelling its observer cannot detach it.
pub struct ThreadOwner {
    stop: Arc<AtomicBool>,
    state: Mutex<State>,
    changed: Condvar,
}
impl ThreadOwner {
    pub fn new(stop: Arc<AtomicBool>) -> Self {
        Self { stop, state: Mutex::new(State::default()), changed: Condvar::new() }
    }
    pub fn spawn(
        &self,
        builder: Builder,
        name: String,
        stopped: Arc<AtomicBool>,
        task: impl FnOnce() + Send + 'static,
    ) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if state.joining || state.result.is_some() || self.stop.load(Ordering::Acquire) {
            return Err(error!("{name}: thread admission closed"));
        }
        let stop = self.stop.clone();
        let handle = builder.spawn(move || {
            struct Exit {
                stop: Arc<AtomicBool>,
                stopped: Arc<AtomicBool>,
            }
            impl Drop for Exit {
                fn drop(&mut self) {
                    if std::thread::panicking() {
                        self.stop.store(true, Ordering::Release);
                    }
                    self.stopped.store(true, Ordering::Release);
                }
            }
            let _exit = Exit { stop, stopped };
            task();
        })?;
        state.ids.push(handle.thread().id());
        state.threads.push((name, handle));
        Ok(())
    }
    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Release);
    }
    pub fn join(&self) -> Result<()> {
        self.request_stop();
        let mut state = self.state.lock().unwrap();
        // Never certify a self-join, and do not deadlock behind another waiter
        // which is joining this very worker.
        if state.ids.contains(&std::thread::current().id()) {
            return Err(error!("consensus worker cannot join its own owner"));
        }
        loop {
            if let Some(result) = &state.result {
                return result.clone().map_err(|error| error!("{error}"));
            }
            if !state.joining {
                break;
            }
            state = self.changed.wait(state).unwrap();
        }
        state.joining = true;
        let threads = std::mem::take(&mut state.threads);
        drop(state);
        let mut errors = Vec::new();
        for (name, thread) in threads {
            if let Err(payload) = thread.join() {
                let message = payload
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| payload.downcast_ref::<&str>().copied())
                    .unwrap_or("non-string panic");
                errors.push(format!("{name}: {message}"));
            }
        }
        let result = if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) };
        let mut state = self.state.lock().unwrap();
        state.result = Some(result.clone());
        self.changed.notify_all();
        result.map_err(|error| error!("{error}"))
    }
}
impl Drop for ThreadOwner {
    fn drop(&mut self) {
        if let Err(error) = self.join() {
            log::error!("Consensus thread cleanup: {error}");
        }
    }
}
