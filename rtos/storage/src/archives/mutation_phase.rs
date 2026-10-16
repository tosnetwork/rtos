// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! One admitted native mutation phase; completion is not whole-operation commit.
use super::*;
struct Status { alive: bool, started: bool, completed: bool }
struct Shared { status: Mutex<Status>, domain: Arc<ArchiveDomain>, epoch: u64 }
pub(crate) struct MutationPhase { shared: Arc<Shared> }
pub(crate) struct MutationJob { shared: Arc<Shared>, custody: Option<NativeCustody>, started: bool }
impl ArchiveOperation {
    pub(crate) fn mutation_phase(&self) -> (MutationPhase, MutationJob) {
        let shared = Arc::new(Shared { status: Mutex::new(Status { alive: true, started: false, completed: false }),
            domain: self.custody.domain.clone(), epoch: self.epoch });
        (MutationPhase { shared: shared.clone() }, MutationJob { shared, custody: Some(self.child()), started: false })
    }
}
impl MutationPhase {
    pub(crate) fn check_completion(&self) -> Result<()> {
        let domain = self.shared.domain.lock()?;
        ArchiveDomain::check_epoch(&domain, self.shared.epoch)?;
        if domain.phase == Phase::RecoveryRequired {
            return Err(ArchiveContextError::RecoveryRequired(domain.epoch).into());
        }
        Ok(())
    }
    pub(crate) fn complete(self) {
        self.shared.status.lock().unwrap_or_else(|e| e.into_inner()).completed = true;
    }
}
impl Drop for MutationPhase {
    fn drop(&mut self) {
        let mut status = self.shared.status.lock().unwrap_or_else(|e| e.into_inner());
        status.alive = false;
        if status.started && !status.completed { self.shared.domain.latch_failure(); }
    }
}
impl MutationJob {
    /// Call immediately before the first canonical write, after pure preflight.
    pub(crate) fn start(&mut self) -> Result<()> {
        let mut status = self.shared.status.lock().map_err(|_| ArchiveContextError::Poisoned)?;
        let domain = self.shared.domain.lock()?;
        ArchiveDomain::check_epoch(&domain, self.shared.epoch)?;
        if domain.phase == Phase::RecoveryRequired {
            return Err(ArchiveContextError::RecoveryRequired(domain.epoch).into());
        }
        if !status.alive { return Err(ArchiveContextError::RecoveryCancelled.into()); }
        status.started = true; self.started = true;
        Ok(())
    }
    pub(crate) fn handoff<T: Send + 'static>(mut self, value: T) -> NativeHandoff<T> {
        self.custody.take().expect("native mutation custody").handoff(value)
    }
}
impl Drop for MutationJob {
    fn drop(&mut self) {
        if self.started && self.custody.is_some() { self.shared.domain.latch_failure(); }
    }
}
