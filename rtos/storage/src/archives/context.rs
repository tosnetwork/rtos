// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Archive context primitives. Canonical IO migration is not yet integrated.
use super::io_owners::{ArchiveIoOwners, ArchiveIoTicket};
use crate::db::rocksdb::RocksDb;
use rtos_block::Result;
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ArchiveContextError {
    #[error("Archive view epoch {expected} is stale; current epoch is {current}")]
    Stale { expected: u64, current: u64 },
    #[error("Archive admission is closed at epoch {0}")]
    Closed(u64),
    #[error("Archive context requires recovery at epoch {0}")]
    RecoveryRequired(u64),
    #[error("Archive context state is poisoned")]
    Poisoned,
    #[error("Native provider is already bound to another archive domain")]
    BindingConflict,
    #[error("Only a writable native provider can bind an archive domain")]
    ReadOnlyProvider,
    #[error("Archive context transition requires a closed, drained epoch")]
    NotDrained,
    #[error("Archive epoch overflow")]
    EpochOverflow,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Open,
    Closing,
    RecoveryRequired,
}
struct State {
    epoch: u64,
    phase: Phase,
    owners: Arc<ArchiveIoOwners>,
}
pub struct ArchiveDomain {
    state: Mutex<State>,
}
impl Default for ArchiveDomain {
    fn default() -> Self {
        Self { state: Mutex::new(State { epoch: 0, phase: Phase::Open, owners: Arc::default() }) }
    }
}
impl ArchiveDomain {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    fn lock(&self) -> Result<MutexGuard<'_, State>> {
        self.state.lock().map_err(|_| ArchiveContextError::Poisoned.into())
    }
    fn check_epoch(state: &State, expected: u64) -> Result<()> {
        if state.epoch != expected {
            return Err(ArchiveContextError::Stale { expected, current: state.epoch }.into());
        }
        Ok(())
    }
    fn check_open(state: &State) -> Result<()> {
        match state.phase {
            Phase::Open => Ok(()),
            Phase::Closing => Err(ArchiveContextError::Closed(state.epoch).into()),
            Phase::RecoveryRequired => {
                Err(ArchiveContextError::RecoveryRequired(state.epoch).into())
            }
        }
    }
    pub fn close(self: &Arc<Self>, expected_epoch: u64) -> Result<ClosedArchive> {
        let mut state = self.lock()?;
        Self::check_epoch(&state, expected_epoch)?;
        if state.phase == Phase::Open {
            state.phase = Phase::Closing;
        }
        state.owners.close();
        Ok(ClosedArchive { domain: self.clone(), epoch: state.epoch, owners: state.owners.clone() })
    }
    fn latch_failure(&self) {
        // Drop must close admission even if a prior panic poisoned the mutex.
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.phase = Phase::RecoveryRequired;
        state.owners.close();
    }
    pub fn recovery_required(&self) -> bool {
        self.state.lock().map_or(true, |state| state.phase == Phase::RecoveryRequired)
    }
    pub fn outstanding(&self) -> usize {
        self.state.lock().unwrap_or_else(|error| error.into_inner()).owners.outstanding()
    }
    // No production publication API: durable recovery and idle-writer retirement
    // have not been implemented. Tests only exercise immutable epoch identities.
    #[cfg(test)]
    fn publish_next_epoch(&self, expected: u64) -> Result<()> {
        let mut state = self.lock()?;
        Self::check_epoch(&state, expected)?;
        if state.phase == Phase::RecoveryRequired {
            return Err(ArchiveContextError::RecoveryRequired(state.epoch).into());
        }
        if state.phase != Phase::Closing || state.owners.outstanding() != 0 {
            return Err(ArchiveContextError::NotDrained.into());
        }
        state.epoch = state.epoch.checked_add(1).ok_or(ArchiveContextError::EpochOverflow)?;
        state.owners = Arc::default();
        state.phase = Phase::Open;
        Ok(())
    }
}

#[derive(Clone)]
pub struct ArchiveProvider {
    provider: Arc<RocksDb>,
    domain: Arc<ArchiveDomain>,
}
impl ArchiveProvider {
    pub(crate) fn bound(provider: Arc<RocksDb>, domain: Arc<ArchiveDomain>) -> Self {
        Self { provider, domain }
    }
    pub fn view(&self) -> Result<ArchiveView> {
        let state = self.domain.lock()?;
        ArchiveDomain::check_open(&state)?;
        Ok(ArchiveView { binding: self.clone(), epoch: state.epoch })
    }
}
#[derive(Clone)]
pub struct ArchiveView {
    binding: ArchiveProvider,
    epoch: u64,
}
impl ArchiveView {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn enter(&self) -> Result<ArchiveOperation> {
        let state = self.binding.domain.lock()?;
        ArchiveDomain::check_epoch(&state, self.epoch)?;
        ArchiveDomain::check_open(&state)?;
        // Registration and admission closure share the domain mutex.
        let ticket = state.owners.enter()?;
        Ok(ArchiveOperation {
            epoch: self.epoch,
            custody: NativeCustody {
                domain: self.binding.domain.clone(),
                provider: Some(self.binding.provider.clone()),
                ticket: Some(ticket),
            },
        })
    }
}
pub struct ArchiveOperation {
    epoch: u64,
    custody: NativeCustody,
}
impl ArchiveOperation {
    /// Inherit the admitted epoch while retaining the destination native DB.
    /// Closing forbids new roots, but does not revoke an existing operation.
    pub fn inherit(&self, destination: &ArchiveProvider) -> Result<Self> {
        if !Arc::ptr_eq(&self.custody.domain, &destination.domain) {
            return Err(ArchiveContextError::BindingConflict.into());
        }
        let state = self.custody.domain.lock()?;
        ArchiveDomain::check_epoch(&state, self.epoch)?;
        if state.phase == Phase::RecoveryRequired {
            return Err(ArchiveContextError::RecoveryRequired(self.epoch).into());
        }
        Ok(Self {
            epoch: self.epoch,
            custody: NativeCustody {
                domain: self.custody.domain.clone(),
                provider: Some(destination.provider.clone()),
                ticket: self.custody.ticket.clone(),
            },
        })
    }

    /// Capture this operation's binding without obtaining fresh root admission.
    pub fn view(&self) -> ArchiveView {
        ArchiveView {
            binding: ArchiveProvider::bound(
                self.custody.provider.as_ref().expect("operation retains provider").clone(),
                self.custody.domain.clone(),
            ),
            epoch: self.epoch,
        }
    }

    /// Call inside the native job immediately before opening its read file.
    /// The mutex orders read start against failure latching. A read that wins
    /// may finish after a later latch, retaining custody through file close.
    pub fn start_read(self) -> Result<NativeCustody> {
        {
            let state = self.custody.domain.lock()?;
            ArchiveDomain::check_epoch(&state, self.epoch)?;
            if state.phase == Phase::RecoveryRequired {
                return Err(ArchiveContextError::RecoveryRequired(self.epoch).into());
            }
        }
        Ok(self.custody)
    }

    pub fn child(&self) -> NativeCustody {
        NativeCustody {
            domain: self.custody.domain.clone(),
            provider: self.custody.provider.clone(),
            ticket: self.custody.ticket.clone(),
        }
    }
}

pub struct ClosedArchive {
    domain: Arc<ArchiveDomain>,
    epoch: u64,
    owners: Arc<ArchiveIoOwners>,
}
impl ClosedArchive {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub async fn wait(&self) {
        self.owners.wait().await;
    }
    pub fn recovery_required(&self) -> bool {
        self.domain.recovery_required()
    }
}

/// Owns one inherited ticket through actual work. Plain read cancellation does
/// not latch failure; mutation completion must use the handoff below.
pub struct NativeCustody {
    domain: Arc<ArchiveDomain>,
    provider: Option<Arc<RocksDb>>,
    ticket: Option<ArchiveIoTicket>,
}
impl NativeCustody {
    /// The result remains an owner after the native closure returns. This is
    /// specifically a mutation-to-metadata handoff, not a plain read result.
    pub fn handoff<T: Send + 'static>(self, value: T) -> NativeHandoff<T> {
        NativeHandoff { value: Some(value), custody: Some(self), consumed: false }
    }
}
impl Drop for NativeCustody {
    fn drop(&mut self) {
        drop(self.provider.take());
        drop(self.ticket.take());
    }
}

#[must_use = "dropping an unconsumed mutation handoff requires recovery"]
pub struct NativeHandoff<T: Send + 'static> {
    value: Option<T>,
    custody: Option<NativeCustody>,
    consumed: bool,
}
impl<T: Send + 'static> NativeHandoff<T> {
    /// No owned payload escapes. Success completes this phase only, not later
    /// WAL/loose-file work or the whole archive operation.
    pub fn consume(mut self, callback: impl FnOnce(&mut T) -> Result<()>) -> Result<()> {
        callback(self.value.as_mut().expect("handoff payload is present"))?;
        self.consumed = true;
        Ok(())
    }
}
impl<T: Send + 'static> Drop for NativeHandoff<T> {
    fn drop(&mut self) {
        if !self.consumed {
            if let Some(custody) = &self.custody {
                custody.domain.latch_failure();
            }
        }
        // Result destruction, including a writer guard, precedes the provider
        // and ticket. A panic/error can never acknowledge successful metadata.
        drop(self.value.take());
        drop(self.custody.take());
    }
}

#[cfg(test)]
#[path = "../tests/test_archive_context.rs"]
mod tests;
