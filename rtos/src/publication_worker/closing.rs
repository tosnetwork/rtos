// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Exact event closure. Public offers are coordinates; only an authenticated
//! source store completion and private durable custody may release a payload.
use super::*;
use crate::{
    propagation_outbox::{canonical_intent_digest, effects_digest, ClosingRecord, Delivery},
    publication_repair::{
        obtain_durable_mc_custody, reopen_durable_mc_custody, DurableMcFinalRepairCustody,
        McFinalRepairRequest,
    },
    repair_lease_binding::{RepairLeaseBinding, RepairLeaseDomain},
};

impl PublicationWorker {
    /// The normal/historical factory supplies its authenticated runtime. The
    /// public lookup request cannot manufacture the source's private token.
    pub(crate) fn delivered_sink(
        self: &Arc<Self>,
        runtime: Arc<AuthenticatedSessionRuntime>,
    ) -> simplex::finality_delivery::DeliveredCompletionSink {
        let worker = self.clone();
        Arc::new(move |confirmation, completion| {
            worker.admit_draft(Submission::SourceDelivered {
                confirmation,
                runtime: runtime.clone(),
                completion: ClosingCompletion(Some(completion)),
            })
        })
    }
}

impl State {
    fn validate_close_runtime(
        &self,
        runtime: &AuthenticatedSessionRuntime,
        request: &CloseFinalityRequest,
    ) -> Result<Arc<Engine>> {
        if self.stop.is_cancelled() || self.fatal.load(Ordering::Acquire) {
            fail!("Publication closing owner stopped or failed");
        }
        let engine = self.engine.upgrade().ok_or_else(|| error!("Publication Engine gone"))?;
        let local_index = match runtime.local_role() {
            LocalRole::Validator(index) => Some(index),
            LocalRole::Observer => None,
        };
        if request.domain != FinalityCloseDomain::from_runtime(runtime)
            || request.canonical.local_adnl != UInt256::from(*runtime.local_adnl().data())
            || request.canonical.local_validator_index != local_index
            || runtime.pin().zerostate != *engine.zerostate_id()
            || runtime.wire_profile() != engine.validator_network().wire_profile()
        {
            fail!("Closing request differs from authenticated source runtime");
        }
        Ok(engine)
    }

    async fn current_close(
        &self,
        store: &Arc<PropagationOutbox>,
        engine: Arc<Engine>,
        request: &CloseFinalityRequest,
    ) -> Result<Option<(ClosingRecord, DurableMcFinalRepairCustody)>> {
        let id = request.canonical.node_receipt.clone();
        let Some(closed) = self.write(store, move |store| store.lookup_close(&id)).await? else {
            return Ok(None);
        };
        if closed.offer().request != *request {
            fail!("Closing generation belongs to different canonical source evidence");
        }
        // A decoded tombstone/Completed flag is not a new custody capability.
        let custody = reopen_durable_mc_custody(
            engine,
            closed.lease_generation,
            closed.binding.clone(),
            closed.dependency_digest.clone(),
        )
        .await?;
        Ok(Some((closed, custody)))
    }

    async fn original_source(
        &self,
        store: &Arc<PropagationOutbox>,
        runtime: &AuthenticatedSessionRuntime,
        request: &CloseFinalityRequest,
    ) -> Result<(Delivery, UnverifiedRecord)> {
        let id = request.canonical.node_receipt.clone();
        let (delivery, entry) = self
            .write(store, move |store| store.delivery(&id))
            .await?
            .ok_or_else(|| error!("Unknown retained finality delivery"))?;
        let canonical =
            canonical_record(runtime, &request.canonical, &delivery, &entry, &self.limits)?;
        let (_, original_digest) =
            simplex::finality_delivery::canonical_source_identity(runtime, &canonical)?;
        if request.source_digest != original_digest
            || request.created_at_unix_secs != canonical.created_at_unix_secs
        {
            fail!("Closing request changed original source digest or time");
        }
        Ok((delivery, entry))
    }

    async fn lookup_terminal(
        &self,
        store: &Arc<PropagationOutbox>,
        runtime: &AuthenticatedSessionRuntime,
        request: &CloseFinalityRequest,
    ) -> Result<FinalityTerminalLookup> {
        let engine = self.validate_close_runtime(runtime, request)?;
        if let Some((closed, _custody)) = self.current_close(store, engine, request).await? {
            return Ok(if closed.released {
                FinalityTerminalLookup::Released(closed.offer())
            } else {
                FinalityTerminalLookup::CloseOffered(closed.offer())
            });
        }
        self.original_source(store, runtime, request).await?;
        Ok(FinalityTerminalLookup::Retained)
    }

    async fn offer_close(
        &self,
        store: &Arc<PropagationOutbox>,
        runtime: &AuthenticatedSessionRuntime,
        request: CloseFinalityRequest,
    ) -> Result<CloseOffer> {
        let engine = self.validate_close_runtime(runtime, &request)?;
        if let Some((closed, _custody)) =
            self.current_close(store, engine.clone(), &request).await?
        {
            return Ok(closed.offer());
        }
        if request.canonical.role != FinalityDeliveryRole::Final
            || !request.canonical.block_id.shard().is_masterchain()
        {
            fail!("Persistent repair closing currently requires masterchain Final");
        }
        let (delivery, entry) = self.original_source(store, runtime, &request).await?;
        if entry.stage != PublicationStage::Completed || !entry.pending.is_empty() {
            fail!("Delivery still has acceptance or propagation obligations");
        }
        let recovery = runtime
            .recovery_binding()
            .ok_or_else(|| error!("Closing source lacks authenticated runtime recovery binding"))?;
        let expected_delivery = delivery.clone();
        let expected_entry = entry.clone();
        let close_generation = self
            .write(store, move |store| store.reserve_close(&expected_delivery, &expected_entry))
            .await?;
        let binding = RepairLeaseBinding {
            record_id: entry.id.0,
            delivery_id: delivery.delivery_id.clone(),
            canonical: request.canonical.clone(),
            domain: RepairLeaseDomain {
                zerostate: runtime.pin().zerostate.clone(),
                global_id: runtime.pin().global_id,
                history_init: engine.init_mc_block_id().clone(),
                source_recovery_anchor: recovery.governing_masterchain.clone(),
                source_recovery_coordinates: recovery.coordinates.clone(),
                session_id: runtime.session_id().clone(),
                profile: runtime.profile().clone(),
                protocol: runtime.protocol(),
                carrier_version: runtime.carrier_version(),
                wire_profile: runtime.wire_profile(),
            },
            source_digest: request.source_digest.clone(),
            canonical_digest: canonical_intent_digest(&entry, &delivery)?,
            created_at_unix_secs: entry.record.created_at_unix_secs,
            expires_at_unix_secs: entry.record.expires_at_unix_secs,
            effects_digest: effects_digest(&entry.record.effects)?,
            close_generation,
        };
        let repair = McFinalRepairRequest {
            pin: runtime.pin().clone(),
            history_init: engine.init_mc_block_id().clone(),
            block_id: request.canonical.block_id.clone(),
            session_id: runtime.session_id().clone(),
            profile: runtime.profile().clone(),
            protocol: runtime.protocol(),
            carrier_version: runtime.carrier_version(),
            wire_profile: runtime.wire_profile(),
        };
        let custody = obtain_durable_mc_custody(engine, repair, binding.clone()).await?;
        // The actual storage owner rechecks the entire event after all awaits.
        self.write(store, move |store| {
            store
                .begin_close_offer(&binding, &delivery, &entry, &custody)
                .map(|record| record.offer())
        })
        .await
    }

    async fn confirm_delivered(
        &self,
        store: &Arc<PropagationOutbox>,
        runtime: &AuthenticatedSessionRuntime,
        confirmation: simplex::finality_delivery::DeliveredConfirmation,
    ) -> Result<()> {
        let offer = confirmation.offer();
        let engine = self.validate_close_runtime(runtime, &offer.request)?;
        if confirmation.source_id() != &simplex::finality_delivery::close_source_id(&offer.request)?
        {
            fail!("Delivered owner belongs to another source identity");
        }
        let (closed, custody) = self
            .current_close(store, engine, &offer.request)
            .await?
            .ok_or_else(|| error!("Delivered confirmation has no durable close offer"))?;
        if closed.offer() != *offer {
            fail!("Delivered confirmation refers to a stale close generation");
        }
        self.write(store, move |store| {
            // Keep the opaque completion and custody alive through the real WAL.
            store.confirm_close(&closed.binding, &custody, &confirmation).map(|_| ())
        })
        .await
    }
}
