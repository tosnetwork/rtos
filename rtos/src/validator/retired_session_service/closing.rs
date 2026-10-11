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
            job: tokio::spawn(async move {
                replay_namespace(
                    engine,
                    path,
                    cursors,
                    #[cfg(test)]
                    None,
                )
                .await
            }),
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
    #[cfg(test)] test_gate: Option<Arc<ClosureAdmissionGate>>,
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
            #[cfg(test)]
            if let Some(gate) = &test_gate {
                if !completions.is_empty() {
                    gate.entered.notified().await;
                    gate.panicking.store(true, std::sync::atomic::Ordering::Release);
                    panic!("injected subsequent source admission panic");
                }
            }
            let sink = worker.sink(runtime.clone());
            #[cfg(test)]
            let sink = if let Some(gate) = &test_gate {
                Arc::new(HeldTerminalSink { delegate: sink, gate: gate.clone() })
                    as consensus_common::finality_delivery::DurableFinalitySinkPtr
            } else {
                sink
            };
            let (sender, receiver) = tokio::sync::oneshot::channel();
            // Retain the receiver before calling external admission code: it may panic
            // after handing off its source owner.
            completions.push(receiver);
            let result = locator.resume(
                runtime.clone(),
                sink,
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

// Per-job test admission interposition. The delegate still authenticates and
// executes the real node lookup; only its actual source continuation is held.
#[cfg(test)]
#[derive(Default)]
struct ClosureAdmissionGate {
    held: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    entered: tokio::sync::Notify,
    panicking: std::sync::atomic::AtomicBool,
    lookup_ok: std::sync::atomic::AtomicBool,
}
#[cfg(test)]
impl ClosureAdmissionGate {
    fn release(&self) {
        let callback = self.held.lock().unwrap().take();
        if let Some(callback) = callback {
            callback();
        }
    }
}
#[cfg(test)]
struct HeldTerminalSink {
    delegate: consensus_common::finality_delivery::DurableFinalitySinkPtr,
    gate: Arc<ClosureAdmissionGate>,
}
#[cfg(test)]
impl consensus_common::finality_delivery::DurableFinalitySink for HeldTerminalSink {
    fn stage(
        &self,
        draft: consensus_common::finality_delivery::FinalizedDeliveryDraft,
        completion: consensus_common::finality_delivery::FinalizedDeliveryCompletion,
    ) -> Result<()> {
        self.delegate.stage(draft, completion)
    }
    fn lookup_terminal(
        &self,
        request: consensus_common::finality_delivery::CloseFinalityRequest,
        completion: consensus_common::finality_delivery::FinalityTerminalCompletion,
    ) -> Result<()> {
        let gate = self.gate.clone();
        self.delegate.lookup_terminal(
            request,
            Box::new(move |result| {
                gate.lookup_ok.store(result.is_ok(), std::sync::atomic::Ordering::Release);
                *gate.held.lock().unwrap() = Some(Box::new(move || completion(result)));
                gate.entered.notify_one();
            }),
        )
    }
    fn offer_close(
        &self,
        request: consensus_common::finality_delivery::CloseFinalityRequest,
        completion: consensus_common::finality_delivery::FinalityCloseCompletion,
    ) -> Result<()> {
        self.delegate.offer_close(request, completion)
    }
}

/// Called by an actual Engine/source fixture after its two live handoffs have
/// produced synced references and the live source owner has been dropped.
#[cfg(test)]
pub(crate) async fn test_admission_panic_drains_real_source(
    engine: Arc<Engine>,
    namespace: PathBuf,
    runtime: Arc<consensus_common::session_runtime::AuthenticatedSessionRuntime>,
) {
    use std::sync::atomic::Ordering;
    let service = RetiredSessionService {
        status: Mutex::new(Default::default()),
        initialized: tokio::sync::watch::channel(false).0,
        close_cursors: Arc::new(Mutex::new(Default::default())),
    };
    let gate = Arc::new(ClosureAdmissionGate::default());
    struct Release(Arc<ClosureAdmissionGate>);
    impl Drop for Release {
        fn drop(&mut self) {
            self.0.release();
        }
    }
    let release = Release(gate.clone());
    let task_engine = engine.clone();
    let task_path = namespace.clone();
    let cursors = service.close_cursors.clone();
    let task_gate = gate.clone();
    let mut active = vec![ActiveClosure {
        namespace: namespace.clone(),
        job: tokio::spawn(async move {
            replay_namespace(task_engine, task_path, cursors, Some(task_gate)).await
        }),
    }];
    let result = std::panic::AssertUnwindSafe(async {
        tokio::time::timeout(Duration::from_secs(10), async {
            while !gate.panicking.load(Ordering::Acquire) || !engine.check_stop() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("second admission must panic after actual first lookup");
        assert!(gate.lookup_ok.load(Ordering::Acquire), "real Engine lookup must succeed");
        service.poll_closures(&engine, &mut active);
        assert_eq!(active.len(), 1, "held source completion must retain actual job");
        assert_eq!(service.snapshot().deferred, 0, "job must not report terminal before drain");
        assert!(engine.finality_recovery_registry().owns(&runtime));
        assert!(engine.finality_recovery_registry().reserve_normal(&runtime).unwrap().is_none());
        assert!(
            simplex::finality_delivery::scan_finality_closures_namespace(&namespace)
                .unwrap()
                .is_empty(),
            "real source file lock must still be held"
        );
        gate.release();
    })
    .catch_unwind()
    .await;
    // Release on every failure, then collect the real join before propagating it.
    drop(release);
    tokio::time::timeout(Duration::from_secs(20), async {
        while !active.is_empty() {
            service.poll_closures(&engine, &mut active);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("admitted source work must reach a terminal join after gate release");
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    assert_eq!(service.snapshot().deferred, 1, "panic remains a reported failure");
    assert!(
        engine.finality_recovery_registry().owns(&runtime),
        "panic reservation remains fail-closed"
    );
    let locators =
        simplex::finality_delivery::scan_finality_closures_namespace(&namespace).unwrap();
    assert!(!locators.is_empty(), "terminal job must have dropped every source store lock owner");
    drop(locators);
}
