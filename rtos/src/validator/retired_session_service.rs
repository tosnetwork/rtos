// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Engine-owned replay of authenticated historical certificate debts.
use super::{
    consensus_overlay::ConsensusOverlayManagerImpl, finality_recovery_owner::RecoveryReservation,
    retired_session_auth::authenticate_retired_session,
};
use crate::{engine::Engine, engine_traits::EngineOperations};
use consensus_common::{
    AsyncCollationRequestPtr, BlockHash, BlockPayloadPtr, BlockSourceInfo, CollationParentHint,
    PublicKey, PublicKeyHash, SessionListener, SessionStats, ValidatorBlockCandidateCallback,
    ValidatorBlockCandidateDecisionCallback,
};
use futures::FutureExt;
use rtos_block::{error, fail, BlockSignaturesVariant, Result};
use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

const MAX_ACTIVE: usize = 8;
const SCAN_BATCH: usize = 64;
const RETRY: Duration = Duration::from_secs(1);
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);
const REPLAY_SLICE: Duration = Duration::from_secs(30);

#[derive(Clone, Default, Debug)]
pub(crate) struct RecoveryServiceSnapshot {
    pub active: usize,
    pub completed: u64,
    pub passes: u64,
    pub deferred: u64,
}

pub(crate) struct RetiredSessionService {
    status: Mutex<RecoveryServiceSnapshot>,
    initialized: tokio::sync::watch::Sender<bool>,
}

impl RetiredSessionService {
    pub(crate) fn start(engine: Arc<Engine>) -> Result<Arc<Self>> {
        let service = Arc::new(Self {
            status: Mutex::new(Default::default()),
            initialized: tokio::sync::watch::channel(false).0,
        });
        let owner = service.clone();
        let task_engine = engine.clone();
        // ServiceTasks owns the actual join even if the startup caller goes away.
        engine.register_service_task(
            "retired consensus recovery",
            Engine::MASK_SERVICE_RETIRED_RECOVERY,
            Box::new(move || {
                tokio::spawn(async move {
                    owner.run(task_engine).await;
                })
            }),
        )?;
        Ok(service)
    }

    pub(crate) fn snapshot(&self) -> RecoveryServiceSnapshot {
        self.status.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub(crate) async fn wait_initial_scan(&self) -> Result<()> {
        let mut ready = self.initialized.subscribe();
        while !*ready.borrow_and_update() {
            ready.changed().await.map_err(|e| error!("Retired recovery startup: {e}"))?;
        }
        Ok(())
    }

    fn deferred(&self, path: &std::path::Path, error: &dyn std::fmt::Display) {
        self.status.lock().unwrap_or_else(|e| e.into_inner()).deferred += 1;
        log::warn!(target: "validator", "Retired recovery {} deferred: {error}", path.display());
    }

    async fn run(self: Arc<Self>, engine: Arc<Engine>) {
        let mut active = Vec::new();
        let result =
            std::panic::AssertUnwindSafe(self.run_inner(&engine, &mut active)).catch_unwind().await;
        self.initialized.send_replace(true);
        if !matches!(result, Ok(Ok(()))) {
            // Stop all admission, but do not declare this service drained yet.
            engine.stopper().set_stop();
        }
        // Keep every session and its namespace lease until the real blocking
        // shutdown certifies drain. Caller cancellation cannot detach this work.
        while let Some(mut owner) = active.pop() {
            loop {
                if self.retire(&engine, &mut owner).await {
                    break;
                }
                tokio::time::sleep(RETRY).await;
            }
        }
        self.status.lock().unwrap_or_else(|e| e.into_inner()).active = 0;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                engine.stopper().report_service_failure(0, format!("retired recovery: {error}"))
            }
            Err(_) => engine.stopper().report_service_failure(
                0,
                "retired recovery actor panicked after owned drain".into(),
            ),
        }
    }

    async fn run_inner(
        &self,
        engine: &Arc<Engine>,
        active: &mut Vec<ActiveRecovery>,
    ) -> Result<()> {
        let directory = PathBuf::from(engine.db_root_dir()?).join("catchains/consensus/v2");
        let mut cursor = None;
        loop {
            if engine.check_stop() {
                return Ok(());
            }
            let mut index = 0;
            while index < active.len() {
                let owner = &mut active[index];
                let done = owner.session.as_ref().is_some_and(|s| s.finality_recovery_complete());
                let failed = owner.failure.is_some()
                    || owner.session.as_ref().is_some_and(|s| s.is_panicked());
                if done || failed || owner.started.elapsed() >= REPLAY_SLICE {
                    if self.retire(engine, owner).await {
                        if done {
                            self.status.lock().unwrap_or_else(|e| e.into_inner()).completed += 1;
                        }
                        active.swap_remove(index);
                        continue;
                    }
                }
                index += 1;
            }
            self.status.lock().unwrap_or_else(|e| e.into_inner()).active = active.len();
            let root = directory.clone();
            let after = cursor.clone();
            // This join belongs to the actor; no timeout abandons blocking IO.
            let entries = tokio::task::spawn_blocking(move || namespace_batch(root, after))
                .await
                .map_err(|e| error!("Recovery directory scan join: {e}"))?;
            match entries {
                Err(error) => self.deferred(&directory, &error),
                Ok(entries) => {
                    let first_pass_deadline = tokio::time::Instant::now() + AUTH_TIMEOUT;
                    for path in entries {
                        if engine.check_stop() || active.len() >= MAX_ACTIVE {
                            break;
                        }
                        cursor = Some(path.clone());
                        if active.iter().any(|owner| owner.namespace == path) {
                            continue;
                        }
                        if let Err(error) = self.admit(engine, &path, active).await {
                            self.deferred(&path, &error);
                        }
                        // Initial boot makes a bounded attempt, then permits the
                        // normal manager. Later passes keep retrying fairly.
                        if tokio::time::Instant::now() >= first_pass_deadline {
                            break;
                        }
                    }
                }
            }
            {
                let mut status = self.status.lock().unwrap_or_else(|e| e.into_inner());
                status.passes += 1;
                status.active = active.len();
            }
            self.initialized.send_replace(true);
            tokio::time::sleep(RETRY).await;
        }
    }

    async fn admit(
        &self,
        engine: &Arc<Engine>,
        namespace: &std::path::Path,
        active: &mut Vec<ActiveRecovery>,
    ) -> Result<()> {
        let path = namespace.to_owned();
        let record = tokio::task::spawn_blocking(move || {
            simplex::finality_recovery::scan_finality_recovery_namespace(&path)
        })
        .await
        .map_err(|e| error!("Retired source scan join: {e}"))??;
        let Some(record) = record else {
            return Ok(());
        };
        let authenticated = tokio::time::timeout(
            AUTH_TIMEOUT,
            authenticate_retired_session(engine.as_ref(), &record),
        )
        .await
        .map_err(|_| error!("Retired history is temporarily unavailable"))??;
        let runtime = authenticated.runtime().clone();
        let Some(key) = engine.adnl_key_by_id(runtime.local_adnl()) else {
            fail!("Historical transport key unavailable; source remains retained");
        };
        let sink = engine.ensure_publication_worker().await?.historical_sink(&authenticated)?;
        let db_root = PathBuf::from(engine.db_root_dir()?).join("catchains");
        let db_root =
            db_root.to_str().ok_or_else(|| error!("Recovery DB path is not UTF-8"))?.to_owned();
        let Some(lease) = engine.finality_recovery_registry().reserve(&runtime)? else {
            return Ok(());
        };
        let listener: Arc<dyn SessionListener + Send + Sync> = Arc::new(RecoveryListener);
        let overlay = Arc::new(ConsensusOverlayManagerImpl::new(
            engine.validator_network(),
            runtime.session_id().clone(),
            None,
        ));
        let weak_listener = Arc::downgrade(&listener);
        // Install the lease owner before awaiting construction. Panic cleanup
        // keeps this vector reachable through run_inner's outer catch_unwind.
        active.push(ActiveRecovery {
            namespace: namespace.to_owned(),
            lease: Some(lease),
            session: None,
            failure: None,
            listener,
            started: tokio::time::Instant::now(),
        });
        let result = tokio::task::spawn_blocking(move || {
            simplex::SessionFactory::create_finality_recovery_session_checked(
                authenticated.options(),
                runtime,
                &key,
                &db_root,
                authenticated.record(),
                overlay,
                weak_listener,
                sink,
            )
        })
        .await;
        let owner = active.last_mut().expect("admitted recovery owner");
        match result {
            Ok(Ok(session)) => owner.session = Some(session),
            Ok(Err(failure)) => {
                self.deferred(namespace, &failure);
                owner.failure = Some(failure);
            }
            Err(error) => {
                // Checked constructors must capture any post-allocation panic
                // with an owned cleanup receipt. An unexpected join failure has
                // no such proof: keep the lease and make shutdown wait.
                engine.stopper().set_stop();
                self.deferred(namespace, &error);
                fail!("Retired constructor lost cleanup receipt: {error}");
            }
        }
        Ok(())
    }

    async fn retire(&self, engine: &Arc<Engine>, owner: &mut ActiveRecovery) -> bool {
        let drained = if let Some(session) = &owner.session {
            let session = session.clone();
            match tokio::task::spawn_blocking(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    session.stop_checked()
                }));
                (session.threads_drained(), outcome)
            })
            .await
            {
                Ok((drained, outcome)) => {
                    if !matches!(outcome, Ok(Ok(()))) {
                        self.deferred(&owner.namespace, &"checked session shutdown failed");
                        if drained {
                            engine.stopper().report_service_failure(
                                0,
                                "retired session joined with failure".into(),
                            );
                        }
                    }
                    drained
                }
                Err(error) => {
                    self.deferred(&owner.namespace, &error);
                    false
                }
            }
        } else if let Some(failure) = owner.failure.take() {
            // The failure itself owns any partly constructed session. Never
            // drop the only cleanup handle while a blocking retry is running.
            let retained = Arc::new(Mutex::new(failure));
            let work = retained.clone();
            let result = tokio::task::spawn_blocking(move || {
                work.lock().unwrap_or_else(|e| e.into_inner()).retry_cleanup()
            })
            .await;
            let failure = Arc::try_unwrap(retained)
                .ok()
                .expect("joined recovery cleanup")
                .into_inner()
                .unwrap_or_else(|e| e.into_inner());
            let drained = result.is_ok_and(|done| done);
            owner.failure = Some(failure);
            drained
        } else {
            false
        };
        if drained {
            owner.session.take();
            owner.failure.take();
            if let Some(lease) = owner.lease.take() {
                lease.release();
            }
        }
        drained
    }
}

struct ActiveRecovery {
    namespace: PathBuf,
    lease: Option<RecoveryReservation>,
    session: Option<simplex::SessionPtr>,
    failure: Option<simplex::SessionCreationFailure>,
    // Simplex only retains a Weak callback; keep this through checked join.
    #[allow(dead_code)]
    listener: Arc<dyn SessionListener + Send + Sync>,
    started: tokio::time::Instant,
}

/// Bounded lexicographic round-robin enumeration. Directory entries and retired
/// records remain untrusted; a malformed namespace cannot stop unrelated replay.
fn namespace_batch(root: PathBuf, after: Option<PathBuf>) -> Result<Vec<PathBuf>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut next = BTreeSet::new();
    let mut beginning = BTreeSet::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let path = entry.path();
        beginning.insert(path.clone());
        if beginning.len() > SCAN_BATCH {
            beginning.pop_last();
        }
        if after.as_ref().is_none_or(|last| &path > last) {
            next.insert(path);
            if next.len() > SCAN_BATCH {
                next.pop_last();
            }
        }
    }
    if next.is_empty() {
        next = beginning;
    }
    Ok(next.into_iter().collect())
}

struct RecoveryListener;
impl SessionListener for RecoveryListener {
    fn on_candidate(
        &self,
        _: BlockSourceInfo,
        _: BlockHash,
        _: BlockPayloadPtr,
        _: BlockPayloadPtr,
        callback: ValidatorBlockCandidateDecisionCallback,
    ) {
        callback(Err(error!("Historical recovery cannot approve candidates")));
    }
    fn on_generate_slot(
        &self,
        _: BlockSourceInfo,
        _: AsyncCollationRequestPtr,
        _: CollationParentHint,
        callback: ValidatorBlockCandidateCallback,
    ) {
        callback(Err(error!("Historical recovery cannot collate")));
    }
    fn on_block_committed(
        &self,
        _: BlockSourceInfo,
        _: BlockHash,
        _: BlockHash,
        _: BlockPayloadPtr,
        _: BlockSignaturesVariant,
        _: Vec<(PublicKeyHash, BlockPayloadPtr)>,
        _: SessionStats,
    ) {
    }
    fn on_block_skipped(&self, _: u32) {}
    fn get_approved_candidate(
        &self,
        _: PublicKey,
        _: BlockHash,
        _: BlockHash,
        _: BlockHash,
        callback: ValidatorBlockCandidateCallback,
    ) {
        callback(Err(error!("Historical recovery has no legacy candidate authority")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retired_recovery_scan_round_robin_is_bounded_and_wraps() -> Result<()> {
        let root = tempfile::tempdir()?;
        for index in 0..(SCAN_BATCH * 2 + 3) {
            std::fs::create_dir(root.path().join(format!("session-{index:04}")))?;
        }
        // Regular files (including a corrupt unrelated record) are not sessions.
        std::fs::write(root.path().join("not-a-namespace"), b"bad")?;
        let first = namespace_batch(root.path().to_owned(), None)?;
        assert_eq!(first.len(), SCAN_BATCH);
        let second = namespace_batch(root.path().to_owned(), first.last().cloned())?;
        assert_eq!(second.len(), SCAN_BATCH);
        assert!(first.iter().all(|path| !second.contains(path)));
        let final_batch = namespace_batch(root.path().to_owned(), second.last().cloned())?;
        assert_eq!(final_batch.len(), 3);
        assert_eq!(namespace_batch(root.path().to_owned(), final_batch.last().cloned())?, first);
        assert!(namespace_batch(root.path().join("missing"), None)?.is_empty());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn retired_recovery_scan_does_not_follow_namespace_symlinks() -> Result<()> {
        let root = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        std::os::unix::fs::symlink(outside.path(), root.path().join("foreign"))?;
        assert!(namespace_batch(root.path().to_owned(), None)?.is_empty());
        Ok(())
    }
}
