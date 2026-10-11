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
    #[cfg(test)]
    reaped: Arc<(Mutex<bool>, Condvar)>,
}
impl ThreadOwner {
    pub fn new(stop: Arc<AtomicBool>) -> Self {
        Self {
            stop,
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
            #[cfg(test)]
            reaped: Default::default(),
        }
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
    pub fn is_joined(&self) -> bool {
        self.state.lock().unwrap().result.is_some()
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
        let state = self.state.get_mut().unwrap();
        if state.result.is_none() && state.ids.contains(&std::thread::current().id()) {
            self.stop.store(true, Ordering::Release);
            // A final owner reference can be released by one of its own
            // callbacks. Transfer every handle before returning from Drop;
            // the reaper joins this thread only after this callback exits.
            let slot = Arc::new(Mutex::new(std::mem::take(&mut state.threads)));
            let transferred = slot.clone();
            #[cfg(test)]
            let reaped = self.reaped.clone();
            if let Err(error) =
                Builder::new().name("consensus-thread-reaper".into()).spawn(move || {
                    for (name, worker) in transferred.lock().unwrap().drain(..) {
                        if let Err(error) = worker.join() {
                            log::error!("Consensus reaper joined failed worker {name}: {error:?}");
                        }
                    }
                    #[cfg(test)]
                    {
                        *reaped.0.lock().unwrap() = true;
                        reaped.1.notify_all();
                    }
                })
            {
                // OS resource exhaustion is not proof of shutdown. Retain the
                // handles instead of silently dropping them as detached work.
                log::error!("Cannot start consensus reaper; retained unjoined handles: {error}");
                std::mem::forget(slot);
            }
            return;
        }
        if let Err(error) = self.join() {
            log::error!("Consensus thread cleanup: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, sync::mpsc, time::Duration};

    struct HeldExit(mpsc::Sender<()>, mpsc::Receiver<()>);
    impl Drop for HeldExit {
        fn drop(&mut self) {
            self.0.send(()).unwrap();
            self.1.recv().unwrap();
        }
    }
    thread_local! { static EXIT: RefCell<Option<HeldExit>> = const { RefCell::new(None) }; }

    #[test]
    fn thread_owner_waits_for_actual_tls_destructor_after_body_finished() {
        let owner = Arc::new(ThreadOwner::new(Arc::new(AtomicBool::new(false))));
        let stopped = Arc::new(AtomicBool::new(false));
        let (entered, ready) = mpsc::channel();
        let (release, held) = mpsc::channel();
        owner
            .spawn(Builder::new(), "TLS worker".into(), stopped.clone(), move || {
                EXIT.with(|slot| *slot.borrow_mut() = Some(HeldExit(entered, held)));
            })
            .unwrap();
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(stopped.load(Ordering::Acquire), "body exit flag must precede held TLS drop");
        let other = owner.clone();
        let (finished, completion) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            finished.send(other.join()).unwrap();
        });
        assert!(completion.recv_timeout(Duration::from_millis(30)).is_err());
        release.send(()).unwrap();
        completion.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
        waiter.join().unwrap();
        owner.join().unwrap();
    }

    #[test]
    fn thread_owner_joins_held_sibling_after_panic_and_retains_all_errors() {
        let stop = Arc::new(AtomicBool::new(false));
        let owner = Arc::new(ThreadOwner::new(stop.clone()));
        let (release, held) = mpsc::channel();
        owner
            .spawn(Builder::new(), "held sibling".into(), Default::default(), move || {
                held.recv().unwrap();
                panic!("second failure");
            })
            .unwrap();
        owner
            .spawn(Builder::new(), "first worker".into(), Default::default(), || {
                panic!("first failure");
            })
            .unwrap();
        let (finished, completion) = mpsc::channel();
        let other = owner.clone();
        let waiter = std::thread::spawn(move || {
            finished.send(other.join()).unwrap();
        });
        assert!(completion.recv_timeout(Duration::from_millis(30)).is_err());
        release.send(()).unwrap();
        let error =
            completion.recv_timeout(Duration::from_secs(2)).unwrap().unwrap_err().to_string();
        assert!(error.contains("first failure") && error.contains("second failure"));
        waiter.join().unwrap();
        assert_eq!(owner.join().unwrap_err().to_string(), error);
        assert!(stop.load(Ordering::Acquire));
        assert!(owner.spawn(Builder::new(), "late".into(), Default::default(), || {}).is_err());
    }
    #[test]
    fn thread_owner_last_reference_on_worker_is_reaped_after_tls_exit() {
        let owner = Arc::new(ThreadOwner::new(Arc::new(AtomicBool::new(false))));
        let reaped = owner.reaped.clone();
        let last = owner.clone();
        let (begin, start) = mpsc::channel();
        let (entered, ready) = mpsc::channel();
        let (release, held) = mpsc::channel();
        owner
            .spawn(Builder::new(), "self-drop worker".into(), Default::default(), move || {
                start.recv().unwrap();
                EXIT.with(|slot| *slot.borrow_mut() = Some(HeldExit(entered, held)));
                drop(last);
            })
            .unwrap();
        drop(owner);
        begin.send(()).unwrap();
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        let (done, _) = reaped
            .1
            .wait_timeout_while(reaped.0.lock().unwrap(), Duration::from_millis(30), |done| !*done)
            .unwrap();
        assert!(!*done, "reaper must wait for real TLS destruction");
        drop(done);
        release.send(()).unwrap();
        let (done, _) = reaped
            .1
            .wait_timeout_while(reaped.0.lock().unwrap(), Duration::from_secs(2), |done| !*done)
            .unwrap();
        assert!(*done, "self-drop owner never joined its worker");
    }
}
