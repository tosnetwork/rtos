// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! The journaled deletion steps of a retired authenticated namespace that
//! must run as publication-owner transitions: the B0 commit (judged and
//! durably journaled with no outbox or lease mutation in between), the
//! resume verification, the B2 close removal together with the Releasing
//! journal, and the B3 lease release at zero references.
use super::{cleanup_projection, State};
use crate::{propagation_outbox::PropagationOutbox, publication_dependency_leases::LeaseRelease};
use consensus_common::validator_cleanup::{
    encode_record, record_key, CleanupAssociation, CleanupJournal, PendingValidatorCleanup,
};
use rtos_block::{error, Result};
use std::sync::Arc;

pub(crate) enum CleanupStep {
    /// B0: judge, and only on WouldDelete durably journal `intended` (in
    /// Deleting, its associations filled from the judgement).
    Commit {
        selection: cleanup_projection::NamespaceSelection,
        expected: cleanup_projection::ExpectedIdentity,
        inventory: Vec<simplex::finality_delivery::source_retirement::RetirementItem>,
        budget: cleanup_projection::ProjectionBudget,
        /// The record the attempt read; B0 writes only over exactly it.
        durable: PendingValidatorCleanup,
        intended: PendingValidatorCleanup,
    },
    /// Resume: every journaled close is still present, Released and bound
    /// exactly as recorded, and its binding belongs to the runtime.
    Verify { expected: cleanup_projection::ExpectedIdentity, associations: Vec<CleanupAssociation> },
    /// B2: remove the journaled closes and write `intended` (Releasing) in
    /// one synced batch, only over exactly `durable` (Deleted, same token).
    ReleaseCloses { durable: PendingValidatorCleanup, intended: PendingValidatorCleanup },
    /// B3: release one journaled lease once no close references it and its
    /// binding still belongs to the runtime.
    ReleaseLease { expected: cleanup_projection::ExpectedIdentity, association: CleanupAssociation },
}

#[derive(Debug)]
pub(crate) enum CleanupStepOutcome {
    /// B0 journaled; carries the durable record.
    Committed(PendingValidatorCleanup),
    /// Refused with nothing written.
    Vetoed(String),
    Verified,
    ClosesReleased,
    Lease(LeaseRelease),
    /// A close still references the lease: nothing changed.
    Referenced,
    /// A write's outcome is unknown; carries the intended durable record.
    Uncertain(PendingValidatorCleanup, String),
}

/// Why the durable record is not exactly `expected`, if it is not.
fn durable_differs(
    engine: &crate::engine::Engine,
    expected: &PendingValidatorCleanup,
) -> Result<Option<String>> {
    use crate::engine_traits::EngineOperations;
    Ok(match engine.load_validator_cleanup_record(&expected.namespace)? {
        Some(durable) if &durable == expected => None,
        _ => Some("durable cleanup journal changed under the attempt".into()),
    })
}

impl State {
    pub(super) fn cleanup_step(
        &self,
        store: &Arc<PropagationOutbox>,
        step: CleanupStep,
    ) -> Result<CleanupStepOutcome> {
        let engine = self.engine.upgrade().ok_or_else(|| error!("Engine unavailable"))?;
        let leases = engine.db().repair_leases().clone();
        match step {
            CleanupStep::Commit { selection, expected, inventory, budget, durable, intended } => {
                if durable.journal != CleanupJournal::Pending
                    || durable.namespace != intended.namespace
                {
                    return Ok(CleanupStepOutcome::Vetoed("B0 must start from Pending".into()));
                }
                if let Some(reason) = durable_differs(&engine, &durable)? {
                    return Ok(CleanupStepOutcome::Vetoed(reason));
                }
                let session = selection.session.clone();
                let sources = cleanup_projection::JudgeSources {
                    outstanding: &|| self.outstanding.count(&session),
                    read_outbox: &|budget| store.cleanup_view_for(&session, budget),
                    read_leases: &|budget| leases.records_for(&session, budget),
                    outbox_epoch: &|| store.mutation_epoch(),
                    lease_epoch: &|| leases.mutation_epoch(),
                };
                let judgement = cleanup_projection::judge_cleanup_detailed(
                    &selection, &expected, &inventory, &sources, budget,
                );
                let (cleanup_projection::CleanupDecision::WouldDelete { .. }, Some(epochs)) =
                    (&judgement.decision, judgement.epochs)
                else {
                    let reason = match judgement.decision {
                        cleanup_projection::CleanupDecision::Veto(reason) => reason,
                        cleanup_projection::CleanupDecision::WouldDelete { .. } => {
                            "judgement without validated epochs".into()
                        }
                    };
                    return Ok(CleanupStepOutcome::Vetoed(reason));
                };
                let CleanupJournal::Deleting(mut payload) = intended.journal.clone() else {
                    return Ok(CleanupStepOutcome::Vetoed("B0 must journal Deleting".into()));
                };
                payload.associations = judgement.associations;
                let intended = PendingValidatorCleanup {
                    journal: CleanupJournal::Deleting(payload),
                    ..intended
                };
                // Refused before anything is written, never truncated.
                let encoded = match encode_record(&intended) {
                    Ok(encoded) => encoded,
                    Err(error) => return Ok(CleanupStepOutcome::Vetoed(error.to_string())),
                };
                #[cfg(test)]
                if let Some(hook) = self.cleanup_commit_hook.lock().unwrap().clone() {
                    hook(store);
                }
                // Under both store locks (outbox, then ledger: the only
                // order): still quiescent and unmutated, then the synced
                // journal write. Nothing can interleave until it completes.
                store.with_cleanup_lock(|outbox_epoch, _| {
                    leases.with_cleanup_lock(|lease_epoch| {
                        if self.outstanding.count(&session) != 0
                            || outbox_epoch != Some(epochs.0)
                            || lease_epoch != Some(epochs.1)
                        {
                            return Ok(CleanupStepOutcome::Vetoed(
                                "projection raced a mutation before B0".into(),
                            ));
                        }
                        let put = (record_key(&intended.namespace), encoded);
                        #[cfg(test)]
                        if let Some(applied) =
                            crate::validator::validator_cleanup_gc::take_write_fault(
                                &intended.namespace,
                                crate::validator::validator_cleanup_gc::CleanupPoint::AfterB0,
                            )
                        {
                            if applied {
                                engine.db().write_validator_state_batch_sync(&[put], &[])?;
                            }
                            return Ok(CleanupStepOutcome::Uncertain(
                                intended.clone(),
                                "injected journal write fault".into(),
                            ));
                        }
                        Ok(match engine.db().write_validator_state_batch_sync(&[put], &[]) {
                            Ok(()) => CleanupStepOutcome::Committed(intended.clone()),
                            Err(error) => {
                                CleanupStepOutcome::Uncertain(intended.clone(), error.to_string())
                            }
                        })
                    })
                })
            }
            CleanupStep::Verify { expected, associations } => {
                store.with_cleanup_lock(|_, closing| {
                    for association in &associations {
                        let Some(close) = closing
                            .iter()
                            .find(|close| close.binding.delivery_id == association.delivery_id)
                        else {
                            return Ok(CleanupStepOutcome::Vetoed(format!(
                                "close {:x} is missing",
                                association.delivery_id
                            )));
                        };
                        if let Some(reason) =
                            crate::propagation_outbox::closing::association_mismatch(
                                close,
                                association,
                            )?
                        {
                            return Ok(CleanupStepOutcome::Vetoed(reason));
                        }
                        if let Some(reason) =
                            cleanup_projection::binding_mismatch(&close.binding, &expected)
                        {
                            return Ok(CleanupStepOutcome::Vetoed(reason));
                        }
                    }
                    Ok(CleanupStepOutcome::Verified)
                })
            }
            CleanupStep::ReleaseCloses { durable, intended } => {
                let CleanupJournal::Releasing(payload) = &intended.journal else {
                    return Ok(CleanupStepOutcome::Vetoed("B2 must journal Releasing".into()));
                };
                // Only from exactly the Deleted journal of the same attempt.
                let same_record = PendingValidatorCleanup {
                    journal: durable.journal.clone(),
                    ..intended.clone()
                };
                if durable.journal != CleanupJournal::Deleted(payload.clone())
                    || same_record != durable
                {
                    return Ok(CleanupStepOutcome::Vetoed(
                        "B2 must follow the attempt's own Deleted journal".into(),
                    ));
                }
                if let Some(reason) = durable_differs(&engine, &durable)? {
                    return Ok(CleanupStepOutcome::Vetoed(reason));
                }
                let put = match encode_record(&intended) {
                    Ok(encoded) => (record_key(&intended.namespace), encoded),
                    Err(error) => return Ok(CleanupStepOutcome::Vetoed(error.to_string())),
                };
                match store.remove_cleanup_closes(&payload.associations, &[put]) {
                    Ok(Ok(())) => Ok(CleanupStepOutcome::ClosesReleased),
                    Ok(Err(reason)) => Ok(CleanupStepOutcome::Vetoed(reason)),
                    Err(error) => Ok(CleanupStepOutcome::Uncertain(intended, error.to_string())),
                }
            }
            CleanupStep::ReleaseLease { expected, association } => {
                // Under the outbox lock (then the ledger's, the only order),
                // so no close can come to reference the lease in between; the
                // binding check and the release are one ledger operation.
                store.with_cleanup_lock(|_, closing| {
                    if closing
                        .iter()
                        .any(|close| close.lease_generation == association.lease_generation)
                    {
                        return Ok(CleanupStepOutcome::Referenced);
                    }
                    Ok(CleanupStepOutcome::Lease(leases.release_checked(
                        association.lease_generation,
                        &association.binding_digest,
                        &association.dependency_digest,
                        |binding| cleanup_projection::binding_mismatch(binding, &expected),
                    )?))
                })
            }
        }
    }
}
