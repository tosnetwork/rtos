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
        intended: PendingValidatorCleanup,
    },
    /// Resume: every journaled close is still present, Released and bound
    /// exactly as recorded, and its binding belongs to the runtime.
    Verify { expected: cleanup_projection::ExpectedIdentity, associations: Vec<CleanupAssociation> },
    /// B2: remove the journaled closes and write `intended` (Releasing) in
    /// one synced batch.
    ReleaseCloses { intended: PendingValidatorCleanup },
    /// B3: release one journaled lease once no close references it.
    ReleaseLease { association: CleanupAssociation },
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

impl State {
    pub(super) fn cleanup_step(
        &self,
        store: &Arc<PropagationOutbox>,
        step: CleanupStep,
    ) -> Result<CleanupStepOutcome> {
        let engine = self.engine.upgrade().ok_or_else(|| error!("Engine unavailable"))?;
        let leases = engine.db().repair_leases().clone();
        match step {
            CleanupStep::Commit { selection, expected, inventory, budget, intended } => {
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
                        let put = (record_key(&intended.namespace), encode_record(&intended));
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
            CleanupStep::ReleaseCloses { intended } => {
                let CleanupJournal::Releasing(payload) = &intended.journal else {
                    return Ok(CleanupStepOutcome::Vetoed("B2 must journal Releasing".into()));
                };
                let put = (record_key(&intended.namespace), encode_record(&intended));
                match store.remove_cleanup_closes(&payload.associations, &[put]) {
                    Ok(Ok(())) => Ok(CleanupStepOutcome::ClosesReleased),
                    Ok(Err(reason)) => Ok(CleanupStepOutcome::Vetoed(reason)),
                    Err(error) => Ok(CleanupStepOutcome::Uncertain(intended, error.to_string())),
                }
            }
            CleanupStep::ReleaseLease { association } => {
                // Under the outbox lock (then the ledger's, the only order),
                // so no close can come to reference the lease in between.
                store.with_cleanup_lock(|_, closing| {
                    if closing
                        .iter()
                        .any(|close| close.lease_generation == association.lease_generation)
                    {
                        return Ok(CleanupStepOutcome::Referenced);
                    }
                    Ok(CleanupStepOutcome::Lease(leases.release_for(
                        association.lease_generation,
                        &association.binding_digest,
                        &association.dependency_digest,
                    )?))
                })
            }
        }
    }
}
