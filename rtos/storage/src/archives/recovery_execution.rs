// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Exclusive recovery execution lane, separate from old-view IO tickets.
//! Retains providers and actual jobs, including registered idle-writer close
//! receipts. Protection reservations and durable root completion remain separate.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

struct ExecutionState {
    domain: Arc<ArchiveDomain>,
    epoch: u64,
    owners: Arc<ArchiveIoOwners>,
    providers: Vec<Arc<RocksDb>>,
    effects_started: AtomicBool,
    owner_alive: AtomicBool,
    busy: AtomicBool,
    packages_retired: AtomicBool,
    completed: AtomicBool,
    rebuilding: AtomicBool,
}
impl Drop for ExecutionState {
    fn drop(&mut self) {
        if self.effects_started.load(Ordering::Acquire) && !self.completed.load(Ordering::Acquire) {
            self.domain.latch_failure();
        }
        // Last native job/handoff has released its reference before this drop.
        // Release native provider pins before making the logical claim available.
        self.providers.clear();
        let mut state = self.domain.state.lock().unwrap_or_else(|error| error.into_inner());
        state.recovery_claimed = false;
        // Never reopen admission implicitly, even for cancellation before IO.
    }
}

pub(crate) struct RecoveryExecution {
    state: Arc<ExecutionState>,
}
impl ArchiveDomain {
    /// Acquire the logical claim before closing/draining the old epoch. No old
    /// IO ticket is held by this owner, so it cannot itself prevent the drain.
    pub(crate) fn begin_recovery(
        self: &Arc<Self>,
        epoch: u64,
        participants: &[ArchiveProvider],
    ) -> Result<RecoveryExecution> {
        let mut state = self.lock()?;
        Self::check_epoch(&state, epoch)?;
        if state.phase == Phase::RecoveryRequired {
            return Err(ArchiveContextError::RecoveryRequired(epoch).into());
        }
        if state.recovery_claimed {
            return Err(ArchiveContextError::RecoveryBusy.into());
        }
        if participants.is_empty() {
            return Err(ArchiveContextError::InvalidRecoveryProviders.into());
        }
        for (index, provider) in participants.iter().enumerate() {
            if !Arc::ptr_eq(&provider.domain, self) {
                return Err(ArchiveContextError::BindingConflict.into());
            }
            if participants[..index]
                .iter()
                .any(|earlier| Arc::ptr_eq(&earlier.provider, &provider.provider))
            {
                return Err(ArchiveContextError::InvalidRecoveryProviders.into());
            }
        }
        let providers = participants.iter().map(|p| p.provider.clone()).collect();
        state.recovery_claimed = true;
        state.phase = Phase::Closing;
        state.owners.close();
        Ok(RecoveryExecution {
            state: Arc::new(ExecutionState {
                domain: self.clone(),
                epoch,
                owners: state.owners.clone(),
                providers,
                effects_started: AtomicBool::new(false),
                owner_alive: AtomicBool::new(true),
                busy: AtomicBool::new(false),
                packages_retired: AtomicBool::new(false),
                completed: AtomicBool::new(false),
                rebuilding: AtomicBool::new(false),
            }),
        })
    }
}
static NEXT_RETIREMENT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
#[derive(Debug)]
pub(crate) struct PackageRetirement {
    pub(crate) identity: u64,
    pub(crate) packages: usize,
    pub(crate) closed_files: usize,
}
impl RecoveryExecution {
    pub(crate) async fn wait_for_old_io(&self) -> Result<()> {
        self.state.owners.wait().await;
        self.check_drained()
    }
    fn check_drained(&self) -> Result<()> {
        let state = self.state.domain.lock()?;
        ArchiveDomain::check_epoch(&state, self.state.epoch)?;
        if state.phase == Phase::RecoveryRequired {
            return Err(ArchiveContextError::RecoveryRequired(state.epoch).into());
        }
        if state.phase != Phase::Closing || state.owners.outstanding() != 0 {
            return Err(ArchiveContextError::NotDrained.into());
        }
        Ok(())
    }
    /// Capture idle packages only after all admitted constructors and IO have
    /// really drained. No package lock is taken under the registry mutex.
    /// This is resource discovery, not proof that descriptors have closed.
    pub(in crate::archives) fn snapshot_packages(
        &self,
    ) -> Result<Vec<Arc<super::super::package::PackageState>>> {
        let mut state = self.state.domain.lock()?;
        ArchiveDomain::check_epoch(&state, self.state.epoch)?;
        if state.phase == Phase::RecoveryRequired {
            return Err(ArchiveContextError::RecoveryRequired(state.epoch).into());
        }
        if state.phase != Phase::Closing || state.owners.outstanding() != 0 {
            return Err(ArchiveContextError::NotDrained.into());
        }
        let packages: Vec<_> = state.packages.iter().filter_map(std::sync::Weak::upgrade).collect();
        state.packages.retain(|package| package.strong_count() != 0);
        // Releasing a rejected snapshot may close the final idle file. Never
        // let that destruction happen while holding the registry/domain lock.
        drop(state);
        if packages.iter().any(|package| {
            !self
                .state
                .providers
                .iter()
                .any(|provider| Arc::ptr_eq(provider, package.view().binding().db()))
        }) {
            return Err(ArchiveContextError::InvalidRecoveryProviders.into());
        }
        Ok(packages)
    }

    /// Close idle descriptors under this execution's unique claim. The returned
    /// receipt must be consumed before any following recovery phase is allowed.
    pub(crate) fn retire_packages(
        &self,
    ) -> Result<tokio::task::JoinHandle<Result<RecoveryReceipt<PackageRetirement>>>> {
        let packages = self.snapshot_packages()?;
        self.spawn_phase_kind(true, move || {
            let identity = NEXT_RETIREMENT
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |id| id.checked_add(1))
                .map_err(|_| anyhow::anyhow!("Package retirement identity exhausted"))?;
            let mut report =
                PackageRetirement { identity, packages: packages.len(), closed_files: 0 };
            for package in packages {
                report.closed_files += usize::from(package.retire_native()?);
            }
            Ok(report)
        })
    }

    /// Recovery mutations require this execution's consumed close receipt.
    /// Phase-specific protection and manifest preconditions remain mandatory.
    pub(crate) fn spawn_recovery_phase<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<tokio::task::JoinHandle<Result<RecoveryReceipt<T>>>> {
        self.check_drained()?;
        if !self.state.packages_retired.load(Ordering::Acquire) {
            return Err(ArchiveContextError::RetirementRequired.into());
        }
        self.spawn_phase(work)
    }

    // The raw scheduler is private: external recovery code cannot bypass the
    // retirement gate. Its unit tests exercise the scheduling primitive itself.
    fn spawn_phase<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<tokio::task::JoinHandle<Result<RecoveryReceipt<T>>>> {
        self.spawn_phase_kind(false, work)
    }
    fn spawn_phase_kind<T: Send + 'static>(
        &self,
        retirement: bool,
        work: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<tokio::task::JoinHandle<Result<RecoveryReceipt<T>>>> {
        self.check_drained()?;
        self.state
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ArchiveContextError::RecoveryBusy)?;
        let mut job =
            RecoveryJob { state: self.state.clone(), started: false, consumed: false, retirement };
        Ok(tokio::task::spawn_blocking(move || {
            {
                let state = job.state.domain.lock()?;
                ArchiveDomain::check_epoch(&state, job.state.epoch)?;
                if state.phase == Phase::RecoveryRequired {
                    return Err(ArchiveContextError::RecoveryRequired(state.epoch).into());
                }
                if state.phase != Phase::Closing || state.owners.outstanding() != 0 {
                    return Err(ArchiveContextError::NotDrained.into());
                }
                if !job.state.owner_alive.load(Ordering::Acquire) {
                    return Err(ArchiveContextError::RecoveryCancelled.into());
                }
                // Ordered against owner cancellation and failure latching; mark before invoking code
                // that can perform IO. Consuming a phase never resets this bit.
                job.started = true;
                job.state.effects_started.store(true, Ordering::Release);
            }
            let value = work()?;
            Ok(RecoveryReceipt { value: Some(value), job: Some(job) })
        }))
    }
    // No completion/publication API yet: full durable root cleanup and actual
    // resource receipts must be integrated before any owner can certify success.
}

impl Drop for RecoveryExecution {
    fn drop(&mut self) {
        // This mutex is also held by the native phase when it checks owner
        // liveness and records its first possible effect. Exactly one wins:
        // cancellation first prevents queued work; native start first requires
        // recovery while the real job continues to retain all provider pins.
        let mut state = self.state.domain.state.lock().unwrap_or_else(|error| error.into_inner());
        self.state.owner_alive.store(false, Ordering::Release);
        if self.state.effects_started.load(Ordering::Acquire)
            && !self.state.completed.load(Ordering::Acquire)
        {
            state.phase = Phase::RecoveryRequired;
            state.owners.close();
        }
    }
}

struct RecoveryJob {
    state: Arc<ExecutionState>,
    started: bool,
    consumed: bool,
    retirement: bool,
}
impl Drop for RecoveryJob {
    fn drop(&mut self) {
        if self.started && !self.consumed {
            self.state.domain.latch_failure();
        }
        self.state.busy.store(false, Ordering::Release);
    }
}
#[must_use = "unconsumed recovery phase results retain the claim and require recovery"]
pub(crate) struct RecoveryReceipt<T> {
    value: Option<T>,
    job: Option<RecoveryJob>,
}
impl<T> RecoveryReceipt<T> {
    pub(crate) fn consume(mut self, finish: impl FnOnce(&mut T) -> Result<()>) -> Result<()> {
        {
            let job = self.job.as_ref().expect("recovery phase job");
            let state = job.state.domain.lock()?;
            ArchiveDomain::check_epoch(&state, job.state.epoch)?;
            if state.phase == Phase::RecoveryRequired {
                return Err(ArchiveContextError::RecoveryRequired(state.epoch).into());
            }
        }
        finish(self.value.as_mut().expect("recovery phase payload"))?;
        // Payload/resource destruction also precedes phase acknowledgement.
        drop(self.value.take());
        let job = self.job.as_mut().expect("recovery phase job");
        let state = job.state.domain.lock()?;
        ArchiveDomain::check_epoch(&state, job.state.epoch)?;
        if state.phase == Phase::RecoveryRequired {
            return Err(ArchiveContextError::RecoveryRequired(state.epoch).into());
        }
        if !job.state.owner_alive.load(Ordering::Acquire) {
            return Err(ArchiveContextError::RecoveryCancelled.into());
        }
        if job.retirement {
            job.state.packages_retired.store(true, Ordering::Release);
        }
        job.consumed = true;
        Ok(())
    }
}
impl<T> Drop for RecoveryReceipt<T> {
    fn drop(&mut self) {
        if self.job.as_ref().is_some_and(|job| !job.consumed) {
            self.job.as_ref().expect("recovery job").state.domain.latch_failure();
        }
        drop(self.value.take());
        drop(self.job.take());
    }
}

#[cfg(test)]
#[path = "../tests/test_recovery_execution.rs"]
mod tests;

#[cfg(target_os = "linux")]
impl RecoveryExecution {
    /// Root-last completion grants one exclusive constructor ticket for a new
    /// generation. Ordinary admission remains closed until its maps are ready.
    pub(in crate::archives) fn begin_rebuild(
        &self,
        completion: super::super::recovery_worker::RecoveryCompletion,
        binding: &ArchiveProvider,
    ) -> Result<ArchiveOperation> {
        self.check_drained()?;
        if self.state.busy.load(Ordering::Acquire)
            || !self.state.packages_retired.load(Ordering::Acquire)
            || !completion.matches(&self.state.providers)
            || !Arc::ptr_eq(binding.domain(), &self.state.domain)
            || !self.state.providers.iter().any(|db| Arc::ptr_eq(db, binding.db()))
        {
            return Err(ArchiveContextError::NotDrained.into());
        }
        let mut state = self.state.domain.lock()?;
        ArchiveDomain::check_epoch(&state, self.state.epoch)?;
        let epoch = state.epoch.checked_add(1).ok_or(ArchiveContextError::EpochOverflow)?;
        let owners = Arc::new(ArchiveIoOwners::default());
        let ticket = owners.enter()?;
        state.epoch = epoch;
        state.owners = owners;
        self.state.rebuilding.store(true, Ordering::Release);
        Ok(ArchiveOperation {
            epoch,
            custody: NativeCustody {
                domain: self.state.domain.clone(),
                provider: Some(binding.db().clone()),
                ticket: Some(ticket),
            },
        })
    }
    pub(in crate::archives) fn publish(self, install: impl FnOnce()) -> Result<()> {
        let mut state = self.state.domain.lock()?;
        let epoch = self.state.epoch.checked_add(1).ok_or(ArchiveContextError::EpochOverflow)?;
        ArchiveDomain::check_epoch(&state, epoch)?;
        if !self.state.rebuilding.load(Ordering::Acquire)
            || self.state.busy.load(Ordering::Acquire)
            || state.phase != Phase::Closing
            || state.owners.outstanding() != 0
        {
            return Err(ArchiveContextError::NotDrained.into());
        }
        install();
        self.state.completed.store(true, Ordering::Release);
        state.phase = Phase::Open;
        Ok(())
    }
}
