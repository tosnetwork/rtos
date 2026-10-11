// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Node owner of a source retirement preparation. It keeps the engine's
//! namespace lease from session teardown onwards, so no recovery or normal
//! session can be admitted between the stop and a later retirement step.
use super::finality_recovery_owner::RecoveryReservation;
use simplex::finality_delivery::source_retirement::{
    PendingRetirementScan, RetirementRefusal, SourceRetirementPreparation,
};

/// Result of preparing a stopped group's namespace for retirement. Dropping
/// either variant without `abandon` keeps the engine lease registered: the
/// namespace then stays closed to new sessions until the process restarts.
pub enum RetirementOutcome {
    Prepared(RetirementPreparationOwner),
    Refused(RetirementRefusalOwner),
}

/// A preparation together with the lease that protects its namespace. It
/// exists only after a drained teardown, so abandoning it may release.
pub struct RetirementPreparationOwner {
    source: Option<SourceRetirementPreparation>,
    reservation: Option<RecoveryReservation>,
}

/// A refusal that still owns whatever it was given: the lease and, when the
/// node refused reconciliation, the scan with its namespace locks. The
/// namespace itself is unchanged.
pub struct RetirementRefusalOwner {
    refusal: RetirementRefusal,
    scan: Option<PendingRetirementScan>,
    reservation: Option<RecoveryReservation>,
    drained: bool,
}

impl RetirementOutcome {
    pub(crate) fn prepared(
        source: SourceRetirementPreparation,
        reservation: RecoveryReservation,
    ) -> Self {
        Self::Prepared(RetirementPreparationOwner {
            source: Some(source),
            reservation: Some(reservation),
        })
    }
    /// `drained` certifies that the session's workers and storage are gone;
    /// without it the lease can never be released through this outcome.
    pub(crate) fn refused(
        refusal: RetirementRefusal,
        scan: Option<PendingRetirementScan>,
        reservation: Option<RecoveryReservation>,
        drained: bool,
    ) -> Self {
        Self::Refused(RetirementRefusalOwner { refusal, scan, reservation, drained })
    }
}

impl RetirementPreparationOwner {
    pub fn preparation(&self) -> Option<&SourceRetirementPreparation> {
        self.source.as_ref()
    }
    /// Gives the namespace back: source locks drop first, then the lease.
    pub fn abandon(mut self) {
        drop(self.source.take());
        if let Some(reservation) = self.reservation.take() {
            reservation.release();
        }
    }
}

impl RetirementRefusalOwner {
    pub fn refusal(&self) -> &RetirementRefusal {
        &self.refusal
    }
    /// True when the engine lease is still held by this refusal.
    pub fn holds_reservation(&self) -> bool {
        self.reservation.is_some()
    }
    /// True when the refused scan, and with it the namespace locks, is held.
    pub fn holds_scan(&self) -> bool {
        self.scan.is_some()
    }
    /// True when teardown proved the session's workers and storage are gone.
    pub fn drained(&self) -> bool {
        self.drained
    }
    /// Releases the scan, then the lease, making the namespace admissible
    /// again. An undrained namespace is never released here: the refusal is
    /// handed back unchanged and keeps the namespace closed.
    pub fn abandon(mut self) -> std::result::Result<(), Box<Self>> {
        if !self.drained {
            return Err(Box::new(self));
        }
        drop(self.scan.take());
        if let Some(reservation) = self.reservation.take() {
            reservation.release();
        }
        Ok(())
    }
}
