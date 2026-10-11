// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::owned_tasks::OwnedTasks;
use crate::engine::Stopper;
use rtos_block::{error, fail, Result};
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;

/// Service bits are retired only after the complete accepted service graph joins.
/// Returned handles observe completion; dropping them never detaches ownership.
pub(crate) struct ServiceTasks {
    tasks: OwnedTasks,
    stopper: Arc<Stopper>,
    completions: Arc<Mutex<Vec<(u32, std::result::Result<(), String>)>>>,
}
impl ServiceTasks {
    pub fn new(stopper: Arc<Stopper>) -> Self {
        Self { tasks: Default::default(), stopper, completions: Default::default() }
    }
    pub fn stop(&self) {
        self.tasks.stop();
    }
    pub fn register(
        &self,
        name: &'static str,
        mask: u32,
        start: Box<dyn FnOnce() -> JoinHandle<()> + Send>,
    ) -> Result<JoinHandle<()>> {
        let stopper = self.stopper.clone();
        let completions = self.completions.clone();
        let (sent, received) = tokio::sync::oneshot::channel();
        self.tasks.spawn_result(name, || {
            if stopper.check_stop() {
                fail!("Service admission stopped: {name}");
            }
            stopper.acquire_stop(mask);
            let worker = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(start)) {
                Ok(worker) => worker,
                Err(_) => {
                    let message = format!("{name}: service start panicked");
                    stopper.report_service_failure(mask, message.clone());
                    return Err(error!("{message}"));
                }
            };
            Ok(tokio::spawn(async move {
                let result = worker.await.map_err(|error| format!("{name}: {error}"));
                if let Err(error) = &result {
                    // Stop immediately, but do not exempt a service bit while
                    // accepted descendants might still be writing.
                    stopper.report_service_failure(0, error.clone());
                }
                // Successful transient children need no permanent completion
                // record; the tracker already retains their real join.
                if mask != 0 || result.is_err() {
                    completions.lock().unwrap().push((mask, result.clone()));
                }
                let _ = sent.send(result);
            }))
        })?;
        Ok(tokio::spawn(async move {
            if let Err(error) = received.await.expect("service join supervisor lost") {
                panic!("observed service failure: {error}");
            }
        }))
    }
    pub async fn wait(&self) -> Result<()> {
        let joined = self.tasks.wait().await;
        let completed = self.completions.lock().unwrap().clone();
        let failed = completed
            .iter()
            .filter_map(|(mask, result)| result.as_ref().err().map(|_| *mask))
            .fold(0, |a, b| a | b);
        for (mask, result) in completed {
            match result {
                Ok(()) if mask & failed == 0 => self.stopper.release_stop(mask),
                Ok(()) => {}
                Err(error) => self.stopper.report_service_failure(mask, error),
            }
        }
        joined
    }
}

/// Keep typed task results while the Engine retains the actual worker handle.
pub(crate) fn spawn_owned<T: Send + 'static>(
    engine: &dyn crate::engine_traits::EngineOperations,
    name: &'static str,
    future: impl std::future::Future<Output = T> + Send + 'static,
) -> Result<JoinHandle<T>> {
    let (sent, received) = tokio::sync::oneshot::channel();
    let completion = engine.register_service_task(
        name,
        0,
        Box::new(move || {
            tokio::spawn(async move {
                let result = future.await;
                let _ = sent.send(result);
            })
        }),
    )?;
    Ok(tokio::spawn(async move {
        completion.await.expect("owned service failed");
        received.await.expect("owned service result lost")
    }))
}
