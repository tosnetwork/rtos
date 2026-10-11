// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Node owner of a source retirement preparation. It keeps the engine's
//! namespace lease from session teardown onwards, so no recovery or normal
//! session can be admitted between the stop and a later retirement step.
use super::finality_recovery_owner::RecoveryReservation;
use simplex::finality_delivery::source_retirement::{
    RetirementRefusal, SourceRetirementPreparation,
};

/// Result of preparing a stopped group's namespace for retirement. Dropping
/// either variant without `abandon` keeps the engine lease registered: the
/// namespace then stays closed to new sessions until the process restarts.
pub enum RetirementOutcome {
    Prepared(RetirementPreparationOwner),
    Refused(RetirementRefusalOwner),
}

/// A preparation together with the lease that protects its namespace.
pub struct RetirementPreparationOwner {
    source: Option<SourceRetirementPreparation>,
    reservation: Option<RecoveryReservation>,
}

/// A refusal that still owns the namespace lease; the namespace is unchanged.
pub struct RetirementRefusalOwner {
    refusal: RetirementRefusal,
    reservation: Option<RecoveryReservation>,
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
    pub(crate) fn refused(
        refusal: RetirementRefusal,
        reservation: Option<RecoveryReservation>,
    ) -> Self {
        Self::Refused(RetirementRefusalOwner { refusal, reservation })
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
    /// Releases the lease; the refused namespace becomes admissible again.
    pub fn abandon(mut self) {
        if let Some(reservation) = self.reservation.take() {
            reservation.release();
        }
    }
}
