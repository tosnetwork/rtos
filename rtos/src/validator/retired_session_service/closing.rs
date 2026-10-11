// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Closing replay after the full certificate/canonical payload has been retired.
use super::super::retired_session_auth::authenticate_closing_runtime;
use super::*;
use consensus_common::finality_delivery::FinalityDeliveryRole;
use simplex::finality_delivery::scan_finality_closures_namespace_report;

const CLOSE_BATCH: usize = 16;

pub(super) struct ActiveClosure {
    pub namespace: PathBuf,
    job: tokio::task::JoinHandle<Result<usize>>,
}

impl RetiredSessionService {
    pub(super) fn admit_closure(
        &self,
        engine: &Arc<Engine>,
        namespace: &std::path::Path,
        active: &mut Vec<ActiveClosure>,
    ) {
        let cursors = self.close_cursors.clone();
        let engine = engine.clone();
        let path = namespace.to_owned();
        // The actor retains the join through shutdown. Neither authentication
        // timeout nor caller cancellation may detach admitted source callbacks.
        active.push(ActiveClosure {
            namespace: path.clone(),
            job: tokio::spawn(async move { replay_namespace(engine, path, cursors).await }),
        });
    }

    pub(super) fn poll_closures(&self, engine: &Engine, active: &mut Vec<ActiveClosure>) {
        let mut index = 0;
        while index < active.len() {
            if !active[index].job.is_finished() {
                index += 1;
                continue;
            }
            let owner = active.swap_remove(index);
            match owner.job.now_or_never().expect("finished closure job") {
                Ok(Ok(completed)) => {
                    self.status.lock().unwrap_or_else(|e| e.into_inner()).completed +=
                        completed as u64;
                }
                Ok(Err(error)) => self.deferred(&owner.namespace, &error),
                Err(error) => {
                    // RecoveryReservation never auto-releases on unwind. An
                    // unproven source drain must prevent future admission.
                    engine.stopper().set_stop();
                    engine.stopper().report_service_failure(
                        0,
                        format!("source closing recovery join failed: {error}"),
                    );
                }
            }
        }
    }
}

async fn replay_namespace(
    engine: Arc<Engine>,
    namespace: PathBuf,
    cursors: Arc<Mutex<std::collections::BTreeMap<PathBuf, rtos_block::UInt256>>>,
) -> Result<usize> {
    let after = {
        let cursors = cursors.lock().map_err(|_| error!("Closing cursor poisoned"))?;
        if !cursors.contains_key(&namespace) && cursors.len() >= 16_384 {
            fail!("Closing namespace cursor capacity exhausted");
        }
        cursors.get(&namespace).cloned()
    };
    let path = namespace.clone();
    let batch = tokio::task::spawn_blocking(move || {
        scan_finality_closures_namespace_report(&path, after.as_ref(), CLOSE_BATCH)
    })
    .await
    .map_err(|e| error!("Source closing scan join: {e}"))??;
    if let Some(last) = batch.next_cursor {
        cursors
            .lock()
            .map_err(|_| error!("Closing cursor poisoned"))?
            .insert(namespace.clone(), last);
    }
    let mut candidates = Vec::new();
    let mut first_error = None;
    for (id, locator) in batch.items {
        let (locator, request) = match locator.and_then(|locator| {
            let request = locator.request()?;
            Ok((locator, request))
        }) {
            Ok(value) => value,
            Err(error) => {
                log::warn!(target: "validator", "Source closing {} item {id}: {error}", namespace.display());
                first_error.get_or_insert(error);
                continue;
            }
        };
        // Legacy references without an authenticated recovery binding still
        // need the full historical session recovery path.
        if request.domain.recovery_binding.is_some()
            && request.canonical.role == FinalityDeliveryRole::Final
            && request.canonical.block_id.shard().is_masterchain()
        {
            candidates.push((id, locator));
        }
    }
    if candidates.is_empty() || engine.check_stop() {
        return first_error.map_or(Ok(0), Err);
    }
    let worker = engine.ensure_publication_worker().await?;
    let mut lease = None;
    let mut completions = Vec::new();
    let admission = std::panic::AssertUnwindSafe(async {
        for (_, locator) in candidates {
            if engine.check_stop() {
                drop(locator);
                continue;
            }
            let authentication = async {
                let request = locator.request()?;
                tokio::time::timeout(
                    AUTH_TIMEOUT,
                    authenticate_closing_runtime(engine.as_ref(), &request, &namespace),
                )
                .await
                .map_err(|_| error!("Source closing history temporarily unavailable"))?
            }
            .await;
            let runtime = match authentication {
                Ok(runtime) => runtime,
                Err(error) => {
                    first_error.get_or_insert(error);
                    continue;
                }
            };
            if lease.is_none() {
                match engine.finality_recovery_registry().reserve(&runtime) {
                    Ok(Some(reservation)) => lease = Some(reservation),
                    Ok(None) => break,
                    Err(error) => {
                        first_error.get_or_insert(error);
                        break;
                    }
                }
            }
            let (sender, receiver) = tokio::sync::oneshot::channel();
            // Retain the receiver before calling external admission code: it may panic
            // after handing off its source owner.
            completions.push(receiver);
            let result = locator.resume(
                runtime.clone(),
                worker.sink(runtime.clone()),
                worker.delivered_sink(runtime),
                Box::new(move |result| {
                    let _ = sender.send(result);
                }),
            );
            match result {
                Ok(()) => {}
                Err(error) => {
                    completions.pop();
                    first_error.get_or_insert(error);
                }
            }
        }
    })
    .catch_unwind()
    .await;
    if admission.is_err() {
        engine.stopper().set_stop();
        engine.stopper().report_service_failure(
            0,
            "Source closing admission panicked; draining callbacks".into(),
        );
        first_error.get_or_insert_with(|| error!("Source closing admission panicked"));
    }
    let mut completed = 0;
    let mut lost_completion = false;
    // Never timeout an admitted callback. The source guarantees its store
    // owner is dropped before completion, including node rejection paths.
    for completion in completions {
        match completion.await {
            Ok(Ok(())) => completed += 1,
            Ok(Err(error)) => {
                first_error.get_or_insert(error);
            }
            Err(error) => {
                // A dropped callback is not a certified source drain. Keep
                // the reservation occupied and fail the Engine closed.
                engine.stopper().set_stop();
                lost_completion = true;
                first_error
                    .get_or_insert_with(|| error!("Source closing completion lost: {error}"));
            }
        }
    }
    if lost_completion {
        engine
            .stopper()
            .report_service_failure(0, "Source closing callback lost its drain proof".into());
    }
    if !lost_completion && admission.is_ok() {
        if let Some(lease) = lease {
            lease.release();
        }
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    Ok(completed)
}
