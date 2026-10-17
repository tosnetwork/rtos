// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Recover retained source deliveries before opening new consensus sessions.
use crate::{
    block::{construct_and_check_prev_stuff, BlockStuff},
    engine_traits::EngineOperations,
    propagation_outbox::{Limits, OutboxDomain, PublicationRecord, RecoveryOrigin, StoredCarrier},
};
use rtos_block::{error, fail, Result};
use std::{path::PathBuf, sync::Arc};

/// Source files are untrusted. The node reauthenticates governing history and
/// evidence before its WAL receipt permits the source copy to be removed.
/// Retired sessions participate even when this node no longer runs a validator.
pub(crate) async fn recover_retained_finality(engine: Arc<dyn EngineOperations>) -> Result<()> {
    let root = PathBuf::from(engine.db_root_dir()?).join("catchains");
    loop {
        if engine.check_stop() {
            fail!("Retained finality recovery stopped before admission");
        }
        let scan_root = root.clone();
        let pending = owned_source_io(engine.as_ref(), "scan retained finality", move || {
            simplex::finality_delivery::scan_pending_finality_for_bootstrap(&scan_root)
        })
        .await?;
        for namespace in &pending.deferred_certificate_replay {
            log::warn!("Retained source namespace {} requires checked certificate replay before interrupted retention can complete", namespace.display());
        }
        if pending.ready.is_empty() {
            return Ok(());
        }
        for source in pending.ready {
            if engine.check_stop() {
                fail!("Retained finality recovery stopped before admission");
            }
            let retained = source.record();
            let block = BlockStuff::deserialize_block_checked(
                retained.block_id.clone(),
                Arc::new(retained.data.clone()),
            )?;
            block.verify_expected_id(&retained.block_id)?;
            let (_, previous) =
                construct_and_check_prev_stuff(block.root_cell(), &retained.block_id, false)?;
            let record = PublicationRecord {
                domain: OutboxDomain {
                    zerostate: retained.pin.zerostate.clone(),
                    global_id: retained.pin.global_id,
                    wire_profile: retained.wire_profile,
                },
                protocol: retained.protocol,
                profile: retained.profile.clone(),
                session_id: retained.session_id.clone(),
                block_id: retained.block_id.clone(),
                block_data: retained.data.clone(),
                proof_data: None,
                prev: previous.prev,
                carrier: if retained.is_final {
                    StoredCarrier::Final(retained.signature_set.clone())
                } else {
                    StoredCarrier::Approval(retained.signature_set.clone())
                },
                // The node derives this claim from authenticated historical
                // membership and the body creator before its first WAL stage.
                // Current key availability only gates routing, not recovery.
                locally_generated: false,
                created_at_unix_secs: retained.created_at_unix_secs,
                expires_at_unix_secs: retained
                    .created_at_unix_secs
                    .checked_add(Limits::default().max_retention_secs)
                    .ok_or_else(|| error!("Retained finality retention overflow"))?,
                // The node freezes exact destinations after historical authentication.
                effects: Vec::new(),
            };
            let origin = RecoveryOrigin {
                carrier_version: retained.carrier_version,
                local_adnl: retained.local_adnl.clone(),
                source_validator: retained.source_validator.clone(),
                local_validator_index: retained.local_validator_index,
            };
            let receipt = engine
                .clone()
                .recover_finality_delivery(
                    record,
                    retained.last_mc_finalized_seqno,
                    retained.candidate_already_sent,
                    origin,
                )
                .await?;
            // Never remove the only source copy after mere queue admission.
            owned_source_io(engine.as_ref(), "ack retained finality", move || {
                source.acknowledge(receipt)
            })
            .await?;
        }
        // The scanner is bounded; drain another batch before admitting new sessions.
    }
}

/// Engine owns the actual blocking join even if this result waiter is dropped.
async fn owned_source_io<T: Send + 'static>(
    engine: &dyn EngineOperations,
    name: &'static str,
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let (sent, received) = tokio::sync::oneshot::channel();
    engine.register_service_task(
        name,
        0,
        Box::new(move || {
            tokio::task::spawn_blocking(move || {
                let _ = sent.send(work());
            })
        }),
    )?;
    received.await.map_err(|error| error!("Retained finality worker completion: {error}"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    struct IoEngine(crate::types::service_tasks::ServiceTasks);
    #[async_trait::async_trait]
    impl EngineOperations for IoEngine {
        fn register_service_task(
            &self,
            name: &'static str,
            mask: u32,
            start: Box<dyn FnOnce() -> tokio::task::JoinHandle<()> + Send>,
        ) -> Result<tokio::task::JoinHandle<()>> {
            self.0.register(name, mask, start)
        }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn retained_finality_cancelled_waiter_keeps_source_io_owned() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;
        let engine = Arc::new(IoEngine(crate::types::service_tasks::ServiceTasks::new(Arc::new(
            crate::engine::Stopper::default(),
        ))));
        let completed = Arc::new(AtomicBool::new(false));
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker_engine = engine.clone();
        let worker_completed = completed.clone();
        let waiter = tokio::spawn(async move {
            owned_source_io(worker_engine.as_ref(), "held source acknowledgement", move || {
                let _ = entered_tx.send(());
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                worker_completed.store(true, Ordering::Release);
                Ok(())
            })
            .await
        });
        entered_rx.await.unwrap();
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        let drained_early = tokio::time::timeout(Duration::from_millis(20), engine.0.wait()).await;
        release_tx.send(()).unwrap();
        engine.0.wait().await.unwrap();
        assert!(drained_early.is_err(), "source IO outlived its Engine drain barrier");
        assert!(completed.load(Ordering::Acquire));
    }
}
