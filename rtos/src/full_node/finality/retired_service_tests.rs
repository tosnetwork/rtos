// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Actual Engine historical sink tests; private-network service replay follows separately.
use super::*;
use crate::{
    propagation_outbox::{Limits, PropagationOutbox, PublicationStage},
    validator::{
        accept_block::AcceptancePhase, retired_session_auth::authenticate_retired_session,
    },
};
use consensus_common::{
    finality_delivery::{DurableFinalitySinkPtr, FinalizedDeliveryDraft},
    session_runtime::LocalRole,
    BlockCandidatePriority, BlockSourceInfo, ConsensusCommonFactory, SessionFinality,
    ValidatorIdentity,
};

fn locator(fixture: &SpoolFixture) -> simplex::finality_recovery::SessionRecoveryRecord {
    let runtime = &fixture.runtime;
    let root = std::path::PathBuf::from(fixture.engine.db_root_dir().unwrap()).join("catchains");
    simplex::finality_recovery::SessionRecoveryRecord {
        pin: runtime.pin().clone(),
        binding: runtime.recovery_binding().unwrap().clone(),
        protocol: runtime.protocol(),
        carrier_version: runtime.carrier_version(),
        wire_profile: runtime.wire_profile(),
        profile: runtime.profile().clone(),
        session_id: runtime.session_id().clone(),
        local_adnl: UInt256::from(*runtime.local_adnl().data()),
        local_validator_index: match runtime.local_role() {
            LocalRole::Validator(index) => Some(index),
            LocalRole::Observer => None,
        },
        prev_blocks: vec![fixture.block.construct_prev_id().unwrap().0],
        start_masterchain: runtime.recovery_binding().unwrap().governing_masterchain.clone(),
        namespace: runtime.runtime_directory(root.to_str().unwrap()).unwrap().into(),
    }
}
fn draft(fixture: &SpoolFixture, final_role: bool) -> FinalizedDeliveryDraft {
    let mut row = fixture.row.clone();
    if !final_role {
        row["signatures"] = row["approval_signatures"].clone();
    }
    let mut carrier = fixture_carrier(&row);
    carrier.slot = row["slot"].as_u64().unwrap() as u32;
    FinalizedDeliveryDraft {
        block_id: fixture.block.id().clone(),
        source_info: BlockSourceInfo {
            source: ValidatorIdentity::from_descriptor(&fixture.runtime.committee()[0]).unwrap(),
            priority: BlockCandidatePriority { round: 99, first_block_round: 0, priority: 0 },
        },
        data: ConsensusCommonFactory::create_block_payload(fixture.block.data().to_vec()),
        finality: if final_role {
            SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(carrier))
        } else {
            SessionFinality::PqApproval(
                rtos_api::pq_finality::PqApproval::from_notarization_fields(carrier).unwrap(),
            )
        },
        last_mc_finalized_seqno: 0,
        candidate_already_sent: false,
        created_at_unix_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    }
}
async fn stage(sink: &DurableFinalitySinkPtr, draft: FinalizedDeliveryDraft) -> Result<UInt256> {
    let (sent, received) = tokio::sync::oneshot::channel();
    sink.stage(
        draft,
        Box::new(move |result| {
            let _ = sent.send(result);
        }),
    )?;
    tokio::time::timeout(Duration::from_secs(20), received)
        .await
        .map_err(|_| rtos_block::error!("Historical sink WAL completion timeout"))?
        .map_err(|error| rtos_block::error!("Historical sink completion dropped: {error}"))?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retired_service_historical_sink_accepts_without_key_and_reauthenticates_each_block() {
    for row in 0..2 {
        for final_role in [false, true] {
            let fixture = SpoolFixture::new_for_transport(row, 0x60).await;
            let recovery = locator(&fixture);
            let valid = draft(&fixture, final_role);
            let mut wrong_creator = valid.clone();
            wrong_creator.source_info.source =
                ValidatorIdentity::from_descriptor(&fixture.runtime.committee()[1]).unwrap();
            let mut wrong_body = valid.clone();
            let mut bytes = fixture.block.data().to_vec();
            bytes[0] ^= 1;
            wrong_body.data = ConsensusCommonFactory::create_block_payload(bytes);
            let mut bad_carrier = fixture_carrier(&fixture.row);
            bad_carrier.slot = fixture.row["slot"].as_u64().unwrap() as u32;
            if !final_role {
                let mut approval = fixture.row.clone();
                approval["signatures"] = approval["approval_signatures"].clone();
                bad_carrier = fixture_carrier(&approval);
                bad_carrier.slot = fixture.row["slot"].as_u64().unwrap() as u32;
            }
            bad_carrier.signatures[0].signature[0] ^= 1;
            let mut wrong_signature = valid.clone();
            wrong_signature.finality = if final_role {
                SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(bad_carrier))
            } else {
                SessionFinality::PqApproval(
                    rtos_api::pq_finality::PqApproval::from_notarization_fields(bad_carrier)
                        .unwrap(),
                )
            };
            let SpoolFixture { dir, engine, runtime, block, state_root, .. } = fixture;
            engine.clone().wait_stop().await.unwrap();
            drop(engine);
            let path = dir.path().join("config.json");
            let mut config: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            config["validator_key_ring"] = serde_json::json!({});
            config["consensus_transport_bindings"] = serde_json::json!([]);
            std::fs::write(path, serde_json::to_vec(&config).unwrap()).unwrap();
            let reopened = open_engine(dir.path()).await;
            let result = std::panic::AssertUnwindSafe(async {
                assert!(reopened.adnl_key_by_id(runtime.local_adnl()).is_none());
                let authenticated =
                    authenticate_retired_session(reopened.as_ref(), &recovery).await.unwrap();
                let sink = reopened
                    .ensure_publication_worker()
                    .await
                    .unwrap()
                    .historical_sink(&authenticated)
                    .unwrap();
                for rejected in [wrong_creator, wrong_body, wrong_signature] {
                    assert!(
                        stage(&sink, rejected).await.is_err(),
                        "session receipt bypassed per-block authentication"
                    );
                }
                assert!(reopened.load_block_handle(block.id()).unwrap().is_none());
                let id = stage(&sink, valid.clone()).await.unwrap();
                assert_eq!(stage(&sink, valid).await.unwrap(), id);
                let accepted = tokio::time::timeout(
                    Duration::from_secs(20),
                    reopened.clone().await_publication(id.clone()),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(accepted.block(), &block);
                assert_eq!(accepted.is_final(), final_role);
                assert_eq!(accepted.phase(), AcceptancePhase::Preapplied);
                assert_eq!(
                    reopened.load_state(block.id()).await.unwrap().root_cell().repr_hash(),
                    &state_root
                );
                id
            })
            .catch_unwind()
            .await;
            reopened.clone().wait_stop().await.unwrap();
            drop(reopened);
            let id = result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
            let reopened = open_engine(dir.path()).await;
            let result = std::panic::AssertUnwindSafe(async {
                let domain = crate::propagation_outbox::OutboxDomain {
                    zerostate: recovery.pin.zerostate,
                    global_id: recovery.pin.global_id,
                    wire_profile: recovery.wire_profile,
                };
                let ledger =
                    PropagationOutbox::open(reopened.db().clone(), domain, Limits::default())
                        .unwrap();
                assert_eq!(
                    ledger.pending().unwrap().len(),
                    1,
                    "rejected/duplicate evidence created durable debt"
                );
                let (delivery, entry) = ledger.delivery(&id).unwrap().unwrap();
                assert_eq!(entry.stage, PublicationStage::AcceptedDraft);
                assert!(entry.pending.is_empty() && entry.record.effects.is_empty());
                assert!(!entry.record.locally_generated, "target60 must not impersonate creator61");
                assert_eq!(delivery.origin.unwrap().local_adnl, recovery.local_adnl);
                assert_eq!(entry.record.block_data, block.data());
                assert_eq!(
                    reopened.load_state(block.id()).await.unwrap().root_cell().repr_hash(),
                    &state_root
                );
                assert!(!reopened.load_block_handle(block.id()).unwrap().unwrap().is_applied());
            })
            .catch_unwind()
            .await;
            reopened.clone().wait_stop().await.unwrap();
            drop(reopened);
            result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        }
    }
}

#[path = "publication_history_tests.rs"]
mod publication_history_tests;
