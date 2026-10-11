// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Normal applied-config transport and authenticated acceptance, with real DBs.
use super::*;
use crate::validator::{
    accept_block::{accept_pq_session_block, AcceptancePhase},
    propagation::{
        PropagationDestination, PropagationEvent, PropagationKind, PropagationPlan,
        PropagationStatus, PropagationTarget,
    },
};
use consensus_common::{simplex_protocol::SimplexProtocol, SessionFinality};
use futures::FutureExt;
use rtos_api::pq_finality::{PqSessionContext, PqVerificationContext};

async fn governing_session(pair: &Pair) -> PqSessionContext {
    // The session identity and ordered committee come from the actual applied
    // bootstrap state; neither is trusted from the received certificate.
    let state = pair.provider.load_state(&pair.anchor).await.unwrap();
    let config = state.config_params().unwrap();
    let verifier = PqVerificationContext::from_governing_config(
        -239,
        config,
        pair.shard.id().clone(),
        0,
        0,
        7,
    )
    .unwrap();
    let (committee, _) = config
        .validator_set()
        .unwrap()
        .calc_subset(
            &config.catchain_config().unwrap(),
            pair.shard.id().shard().shard_prefix_with_tag(),
            pair.shard.id().shard().workchain_id(),
            7,
        )
        .unwrap();
    PqSessionContext::from_authenticated_session_members(
        verifier.expected_session_id().clone(),
        pair.shard.id().shard().clone(),
        7,
        committee,
    )
    .unwrap()
}

fn sent(
    outcome: &crate::validator::propagation::PropagationOutcome,
    kind: PropagationKind,
) -> bool {
    outcome.receipts.iter().any(|r| {
        r.kind == kind
            && r.target == PropagationTarget::Public
            && matches!(r.status, PropagationStatus::Sent)
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn propagation_authenticated_normal_finality_applies_by_mc_and_reopens() {
    let pair = Pair::with_propagation_profile("included", false, true).await;
    let mut services = None;
    let result = std::panic::AssertUnwindSafe(async {
        let client = pair.receiver.overlay_client(pair.shard.id().shard()).await.unwrap();
        let prefix = WireProfile::T0
            .serialize(
                &rtos_api::ton::overlay::message::Message {
                    overlay: UInt256::from(*client.overlay_client().id().data()),
                }
                .into_boxed(),
            )
            .unwrap();
        let sender = pair
            .provider
            .network()
            .context()
            .stack
            .adnl
            .key_by_tag(NodeNetwork::TAG_OVERLAY_KEY)
            .unwrap();
        pair.receiver.network().test_broadcast_faults.configure(
            *sender.id().data(),
            prefix.clone(),
            0,
        );
        let receiver_transport = pair.receiver.network().context().stack.adnl
            .key_by_tag(NodeNetwork::TAG_OVERLAY_KEY).unwrap();
        pair.provider.network().test_broadcast_faults.capture_repair_replies(*receiver_transport.id().data());
        let context = governing_session(&pair).await;
        let previous = pair.shard.construct_prev_id().unwrap().0;
        let mut bad = pair.shard_carrier.clone();
        bad.signatures[0].signature[0] ^= 1;
        assert!(accept_pq_session_block(
            pair.shard.id().clone(),
            Some(pair.shard.data().to_vec()),
            vec![previous.clone()],
            SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(bad)),
            context.clone(),
            pair.provider.clone(),
        )
        .await
        .is_err());
        assert!(!pair.provider.load_block_handle(pair.shard.id()).unwrap().unwrap().has_state());
        assert!(pair.receiver.load_block_handle(pair.shard.id()).unwrap().is_none());

        let accepted = accept_pq_session_block(
            pair.shard.id().clone(),
            Some(pair.shard.data().to_vec()),
            vec![previous.clone()],
            SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(pair.shard_carrier.clone())),
            context.clone(),
            pair.provider.clone(),
        )
        .await
        .unwrap();
        assert_eq!(accepted.phase(), AcceptancePhase::Preapplied);
        assert!(!pair.provider.load_block_handle(pair.shard.id()).unwrap().unwrap().is_applied());
        // A non-creator finalizes: public delivery must be independent finality,
        // not a public block send masquerading as finality recovery.
        let plan = PropagationPlan::for_event(
            SimplexProtocol::PrivateObserversPlumtree,
            PropagationEvent::Finalized,
            pair.shard.id(),
            true,
            false,
            true,
            0,
            false,
        );
        assert!(!plan.block_targets.public);
        // A durable exact target that disappeared cannot silently fan out or
        // become acknowledged as delivered by another current overlay.
        let missing = PropagationDestination {
            kind: PropagationKind::Finality,
            target: PropagationTarget::Custom("removed-overlay".into()),
        };
        let deferred = pair
            .provider
            .propagate_accepted_session_block(&accepted, &plan.for_destination(&missing).unwrap())
            .await;
        assert_eq!(deferred.receipts.len(), 1, "{deferred:?}");
        assert_eq!(deferred.receipts[0].target, missing.target);
        assert!(matches!(deferred.receipts[0].status, PropagationStatus::Deferred(_)));
        assert!(deferred.needs_retry());
        let plan = plan
            .for_destination(&PropagationDestination {
                kind: PropagationKind::Finality,
                target: PropagationTarget::Public,
            })
            .unwrap();
        let outcome = pair.provider.propagate_accepted_session_block(&accepted, &plan).await;
        assert!(sent(&outcome, PropagationKind::Finality), "{outcome:?}");
        assert!(!outcome.needs_retry(), "{outcome:?}");
        let (expected_wire, expected_id) = pair.finality_wire();
        // New neighbours learn via IHAVE and request the retained carrier. That
        // Simple response travels on a query stream, not try_consume_custom.
        let carrier_wire = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                for wire in pair.provider.network().test_broadcast_faults.repair_replies() {
                    if let Ok(rtos_api::ton::overlay::Broadcast::Overlay_BroadcastPlumtreeSimple(carrier)) =
                        WireProfile::T0.deserialize_typed::<rtos_api::ton::overlay::Broadcast>(&wire) {
                        if carrier.broadcast_id.as_array() == &expected_id { return wire; }
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await.unwrap_or_else(|error| panic!(
            "normal repair carrier missing: {error}; expected={expected_id:?}; inbound={:?}; replies={}",
            pair.receiver.network().test_broadcast_faults.receipts(),
            pair.provider.network().test_broadcast_faults.repair_replies().len()));
        let carrier: rtos_api::ton::overlay::Broadcast = WireProfile::T0.deserialize_typed(&carrier_wire).unwrap();
        let rtos_api::ton::overlay::Broadcast::Overlay_BroadcastPlumtreeSimple(carrier) = carrier
        else {
            panic!("finality must use simple Plumtree");
        };
        assert_eq!(carrier.data, expected_wire);
        if let Ok(directory) = std::env::var("RTOS_V2_PROPAGATION_EVIDENCE_DIR") {
            let directory = std::path::PathBuf::from(directory);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join("normal.finality"), &carrier.data).unwrap();
            std::fs::write(directory.join("normal.plumtree"), &carrier_wire)
                .unwrap();
            std::fs::write(directory.join("normal.transport-id"), expected_id).unwrap();
        }
        pair.wait_preapplied().await;
        let receiver_handle = pair.receiver.load_block_handle(pair.shard.id()).unwrap().unwrap();
        assert!(!receiver_handle.is_applied());
        assert_eq!(
            pair.receiver.load_state(pair.shard.id()).await.unwrap().root_cell().repr_hash(),
            &pair.shard_state_root
        );

        services = Some(pair.apply_by_normal_clients().await);
        let applied = pair.receiver.load_block_handle(pair.shard.id()).unwrap().unwrap();
        assert!(applied.is_applied());
        assert_eq!(applied.masterchain_ref_seq_no(), 1);
        // An applied observer can reconstruct authenticated acceptance, but its
        // lack of an authorized origination signer must remain a publication
        // failure; it cannot masquerade as a validator for reverse sends.
        let retry = accept_pq_session_block(
            pair.shard.id().clone(),
            None,
            vec![previous],
            SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(pair.shard_carrier.clone())),
            context,
            pair.receiver.clone(),
        )
        .await
        .unwrap();
        assert!(retry.already_present());
        assert_eq!(retry.phase(), AcceptancePhase::Applied);
        let observer_outcome = pair.receiver.propagate_accepted_session_block(&retry, &plan).await;
        assert!(!sent(&observer_outcome, PropagationKind::Finality), "{observer_outcome:?}");
        assert!(observer_outcome.needs_retry(), "{observer_outcome:?}");
        // The authorized provider can retry the retained carrier. This is a
        // same-direction idempotent resend, not bidirectional role interoperability.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let retry_outcome = pair.provider.propagate_accepted_session_block(&accepted, &plan).await;
        assert!(sent(&retry_outcome, PropagationKind::Finality), "{retry_outcome:?}");
        assert!(!retry_outcome.needs_retry(), "{retry_outcome:?}");
    })
    .catch_unwind()
    .await;
    // A failed assertion must still release actual overlay and DB ownership.
    pair.receiver.clone().wait_stop().await.unwrap();
    pair.provider.clone().wait_stop().await.unwrap();
    if let Some((master, shards)) = services {
        master.await.unwrap();
        shards.await.unwrap();
    }
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
    let id = pair.shard.id().clone();
    let expected_root = pair.shard_state_root.clone();
    let dir = pair._dir.path().join("receiver");
    // Both owning Engines must be dropped before reacquiring the real DB lock.
    let Pair { _dir: keep_dir, receiver, provider, .. } = pair;
    drop(receiver);
    drop(provider);
    let reopened = open_engine(&dir).await;
    let handle = reopened.load_block_handle(&id).unwrap().unwrap();
    assert!(handle.is_applied());
    assert_eq!(handle.masterchain_ref_seq_no(), 1);
    assert_eq!(reopened.load_state(&id).await.unwrap().root_cell().repr_hash(), &expected_root);
    reopened.clone().wait_stop().await.unwrap();
    drop(reopened);
    drop(keep_dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn propagation_authenticated_approval_uses_block_fec_without_finality() {
    let pair = Pair::with_propagation_profile("included", false, true).await;
    let result = std::panic::AssertUnwindSafe(async {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("testdata/v2-propagation-recovery.json")).unwrap();
        let mut row = fixture["rows"][0].clone();
        row["signatures"] = row["approval_signatures"].clone();
        let carrier = fixture_carrier(&row);
        let approval =
            rtos_api::pq_finality::PqApproval::from_notarization_fields(carrier).unwrap();
        let context = governing_session(&pair).await;
        let accepted = accept_pq_session_block(
            pair.shard.id().clone(),
            Some(pair.shard.data().to_vec()),
            vec![pair.shard.construct_prev_id().unwrap().0],
            SessionFinality::PqApproval(approval),
            context,
            pair.provider.clone(),
        )
        .await
        .unwrap();
        assert!(!accepted.is_final());
        assert!(accepted.final_network_signatures().is_err());
        let plan = PropagationPlan::for_event(
            SimplexProtocol::PrivateObserversPlumtree,
            PropagationEvent::Finalized,
            pair.shard.id(),
            true,
            true,
            false,
            0,
            false,
        );
        assert!(plan.block_targets.public);
        assert_eq!(plan.finality_targets, crate::validator::propagation::TargetSet::NONE);
        let destinations =
            pair.provider.resolve_propagation_targets(pair.shard.id(), &plan).await.unwrap();
        let public = destinations
            .iter()
            .find(|destination| {
                destination.kind == PropagationKind::Block
                    && destination.target == PropagationTarget::Public
            })
            .expect("normal resolver must freeze the public block destination");
        let plan = plan.for_destination(public).unwrap();
        let outcome = pair.provider.propagate_accepted_session_block(&accepted, &plan).await;
        assert!(sent(&outcome, PropagationKind::Block), "{outcome:?}");
        assert!(!outcome.receipts.iter().any(|r| r.kind == PropagationKind::Finality));
        assert!(!outcome.needs_retry(), "{outcome:?}");
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if pair
                    .receiver
                    .load_block_handle(pair.shard.id())
                    .unwrap()
                    .is_some_and(|h| h.has_state())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("authenticated approval block must arrive through normal public FEC");
        let handle = pair.receiver.load_block_handle(pair.shard.id()).unwrap().unwrap();
        assert!(!handle.is_applied(), "notarization cannot imply MC inclusion");
        assert_eq!(
            pair.receiver.load_state(pair.shard.id()).await.unwrap().root_cell().repr_hash(),
            &pair.shard_state_root
        );
    })
    .catch_unwind()
    .await;
    pair.receiver.clone().wait_stop().await.unwrap();
    pair.provider.clone().wait_stop().await.unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn propagation_authenticated_finalize_candidate_fallback_keeps_partial_delivery_retryable() {
    let pair = Pair::with_propagation_profile("included", false, true).await;
    let result = std::panic::AssertUnwindSafe(async {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("testdata/v2-propagation-recovery.json")).unwrap();
        let mut row = fixture["rows"][0].clone();
        row["signatures"] = row["approval_signatures"].clone();
        let carrier = fixture_carrier(&row);
        let approval =
            rtos_api::pq_finality::PqApproval::from_notarization_fields(carrier).unwrap();
        let context = governing_session(&pair).await;
        let accepted = accept_pq_session_block(
            pair.shard.id().clone(),
            Some(pair.shard.data().to_vec()),
            vec![pair.shard.construct_prev_id().unwrap().0],
            SessionFinality::PqApproval(approval),
            context,
            pair.provider.clone(),
        )
        .await
        .unwrap();
        assert!(!accepted.is_final());
        assert!(accepted.final_network_signatures().is_err());

        let plan = PropagationPlan::for_event(
            SimplexProtocol::PrivateObserversPlumtree,
            PropagationEvent::Finalized,
            pair.shard.id(),
            true,
            false,
            false,
            0,
            false,
        );
        let outcome = pair.provider.propagate_accepted_session_block(&accepted, &plan).await;
        assert!(sent(&outcome, PropagationKind::Candidate), "{outcome:?}");
        assert!(outcome.needs_retry(), "the fast overlay has no observer peers: {outcome:?}");
        assert!(!sent(&outcome, PropagationKind::Block));
        assert!(!sent(&outcome, PropagationKind::Finality));
        tokio::time::timeout(Duration::from_secs(15), async {
            while pair.receiver.try_get_cached_block_candidate(pair.shard.id()).is_none() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("finalize fallback must reach the real public candidate consumer");
        let receive_plan = PropagationPlan::for_event(
            SimplexProtocol::PrivateObserversPlumtree,
            PropagationEvent::CandidateReceived,
            pair.shard.id(),
            true,
            false,
            false,
            0,
            false,
        );
        let duplicate = pair
            .provider
            .relay_validated_candidate(&accepted.candidate_relay().unwrap(), &receive_plan)
            .await;
        assert!(
            duplicate.needs_retry(),
            "unacknowledged fast destination must remain retryable: {duplicate:?}"
        );
        assert!(
            !duplicate.receipts.iter().any(|r| matches!(&r.status,
            PropagationStatus::Skipped(reason) if reason == "Candidate already relayed")),
            "partial publication must not poison the shared receive/finalize cache: {duplicate:?}"
        );
        assert!(!pair
            .receiver
            .load_block_handle(pair.shard.id())
            .unwrap()
            .is_some_and(|h| h.is_applied()));
    })
    .catch_unwind()
    .await;
    pair.receiver.clone().wait_stop().await.unwrap();
    pair.provider.clone().wait_stop().await.unwrap();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_recovery_replays_prepared_and_ready_acceptance() {
    use crate::{
        block_proof::MasterchainProofVerifier,
        propagation_outbox::{
            Limits, OutboxDomain, PublicationEffect, PublicationKind, PublicationRecord,
            PublicationStage, PublicationTarget, RecordId, StoredCarrier, UnverifiedRecord,
        },
        propagation_outbox_auth::authenticate_publication,
        validator::accept_block::accept_authenticated_publication,
    };
    struct WrongCheckpoint {
        zero: BlockIdExt,
        init: BlockIdExt,
    }
    #[async_trait::async_trait]
    impl EngineOperations for WrongCheckpoint {
        fn zerostate_id(&self) -> Result<&BlockIdExt> {
            Ok(&self.zero)
        }
        fn init_mc_block_id(&self) -> &BlockIdExt {
            &self.init
        }
        fn load_block_handle(
            &self,
            _: &BlockIdExt,
        ) -> Result<Option<Arc<storage::block_handle_db::BlockHandle>>> {
            panic!("foreign checkpoint reached storage");
        }
    }
    for final_role in [false, true] {
        let pair = Pair::with_propagation_profile("included", false, true).await;
        let result = std::panic::AssertUnwindSafe(async {
            let fixture: serde_json::Value =
                serde_json::from_str(include_str!("testdata/v2-propagation-recovery.json"))
                    .unwrap();
            let mut row = fixture["rows"][0].clone();
            if !final_role {
                row["signatures"] = row["approval_signatures"].clone();
            }
            let carrier = fixture_carrier(&row);
            let network = if final_role {
                rtos_api::pq_finality::PqNetworkSignatureSet::from_final_fields(&carrier).unwrap()
            } else {
                let approval =
                    rtos_api::pq_finality::PqApproval::from_notarization_fields(carrier).unwrap();
                rtos_api::pq_finality::PqNetworkSignatureSet::from_approval(&approval).unwrap()
            };
            let bytes = WireProfile::T0.serialize(&network.to_node().into_boxed()).unwrap();
            let history = MasterchainProofVerifier::default();
            let context = history
                .pq_publication_context(
                    pair.provider.as_ref(),
                    pair.shard.id(),
                    pair.shard.block().unwrap(),
                )
                .await
                .unwrap();
            let effect = PublicationEffect {
                kind: PublicationKind::Block,
                target: PublicationTarget::Public,
            };
            let mut entry = UnverifiedRecord {
                id: RecordId(1),
                stage: PublicationStage::Prepared,
                record: PublicationRecord {
                    domain: OutboxDomain {
                        zerostate: context.zerostate().clone(),
                        global_id: context.global_id(),
                        wire_profile: WireProfile::T0,
                    },
                    protocol: context.protocol(),
                    profile: context.profile().clone(),
                    session_id: context.verifier().expected_session_id().clone(),
                    block_id: pair.shard.id().clone(),
                    block_data: pair.shard.data().to_vec(),
                    proof_data: None,
                    prev: vec![pair.shard.construct_prev_id().unwrap().0],
                    carrier: if final_role {
                        StoredCarrier::Final(bytes)
                    } else {
                        StoredCarrier::Approval(bytes)
                    },
                    locally_generated: false,
                    created_at_unix_secs: 100,
                    expires_at_unix_secs: 200,
                    effects: vec![effect.clone()],
                },
                pending: vec![effect],
            };
            let mut wrong_init = context.history_init().clone();
            wrong_init.file_hash = UInt256::from([0xAB; 32]);
            let foreign =
                Arc::new(WrongCheckpoint { zero: context.zerostate().clone(), init: wrong_init });
            let receipt = authenticate_publication(
                &history,
                pair.provider.as_ref(),
                entry.clone(),
                &Limits::default(),
            )
            .await
            .unwrap();
            let failure = accept_authenticated_publication(receipt, foreign).await;
            assert!(
                matches!(failure, Err(error) if error.to_string().contains("another Engine domain"))
            );
            for stage in [PublicationStage::Prepared, PublicationStage::Ready] {
                entry.stage = stage;
                let receipt = authenticate_publication(
                    &history,
                    pair.provider.as_ref(),
                    entry.clone(),
                    &Limits::default(),
                )
                .await
                .unwrap();
                let (retained, accepted) =
                    accept_authenticated_publication(receipt, pair.provider.clone()).await.unwrap();
                assert_eq!(retained, entry);
                assert_eq!(accepted.block(), &pair.shard);
                assert_eq!(accepted.is_final(), final_role);
                assert_eq!(accepted.phase(), AcceptancePhase::Preapplied);
                let handle = pair.provider.load_block_handle(pair.shard.id()).unwrap().unwrap();
                assert!(handle.has_state());
                assert!(!handle.is_applied());
                assert_eq!(
                    pair.provider
                        .load_state(pair.shard.id())
                        .await
                        .unwrap()
                        .root_cell()
                        .repr_hash(),
                    &pair.shard_state_root
                );
            }
            // Exercise the actual Engine admission and owned worker. Publication
            // stays disabled so every selected target must survive shutdown.
            let mut record = entry.record;
            record.created_at_unix_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            record.expires_at_unix_secs =
                record.created_at_unix_secs + Limits::default().max_retention_secs;
            record.effects = vec![PublicationEffect {
                kind: if final_role {
                    PublicationKind::Finality
                } else {
                    PublicationKind::Candidate
                },
                target: PublicationTarget::Public,
            }];
            let accepted = pair.provider.clone().submit_publication(record.clone()).await.unwrap();
            assert_eq!(accepted.block(), &pair.shard);
            assert_eq!(accepted.is_final(), final_role);
            assert_eq!(accepted.phase(), AcceptancePhase::Preapplied);
            record
        })
        .catch_unwind()
        .await;
        pair.receiver.clone().wait_stop().await.unwrap();
        pair.provider.clone().wait_stop().await.unwrap();
        let record = result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        let dir = pair._dir.path().join("provider");
        let Pair { _dir: keep_dir, receiver, provider, .. } = pair;
        drop(receiver);
        drop(provider);
        let reopened = open_engine(&dir).await;
        let outbox = crate::propagation_outbox::PropagationOutbox::open(
            reopened.db().clone(),
            record.domain.clone(),
            Limits::default(),
        )
        .unwrap();
        let pending = outbox.pending().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].stage, PublicationStage::Ready);
        assert_eq!(pending[0].record, record);
        assert_eq!(pending[0].pending, record.effects);
        drop(outbox);
        reopened.clone().wait_stop().await.unwrap();
        drop(reopened);
        drop(keep_dir);
    }
}

fn spool_draft(
    runtime: &consensus_common::session_runtime::AuthenticatedSessionRuntime,
    block: &BlockStuff,
    row: &serde_json::Value,
    final_role: bool,
) -> consensus_common::finality_delivery::FinalizedDeliveryDraft {
    use consensus_common::{
        BlockCandidatePriority, BlockSourceInfo, ConsensusCommonFactory, ValidatorIdentity,
    };
    let mut row = row.clone();
    if !final_role {
        row["signatures"] = row["approval_signatures"].clone();
    }
    let mut carrier = fixture_carrier(&row);
    carrier.slot = row["slot"].as_u64().unwrap() as u32;
    let finality = if final_role {
        SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(carrier))
    } else {
        SessionFinality::PqApproval(
            rtos_api::pq_finality::PqApproval::from_notarization_fields(carrier).unwrap(),
        )
    };
    consensus_common::finality_delivery::FinalizedDeliveryDraft {
        block_id: block.id().clone(),
        source_info: BlockSourceInfo {
            source: ValidatorIdentity::from_descriptor(&runtime.committee()[0]).unwrap(),
            priority: BlockCandidatePriority { round: 99, first_block_round: 0, priority: 0 },
        },
        data: ConsensusCommonFactory::create_block_payload(block.data().to_vec()),
        finality,
        last_mc_finalized_seqno: 0,
        candidate_already_sent: false,
        created_at_unix_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    }
}

async fn stage_spool(
    sink: &consensus_common::finality_delivery::DurableFinalitySinkPtr,
    draft: consensus_common::finality_delivery::FinalizedDeliveryDraft,
) -> Result<UInt256> {
    let (sent, received) = tokio::sync::oneshot::channel();
    sink.stage(
        draft,
        Box::new(move |result| {
            let _ = sent.send(result);
        }),
    )?;
    tokio::time::timeout(Duration::from_secs(15), received)
        .await
        .map_err(|_| rtos_block::error!("durable completion timeout"))?
        .map_err(|error| rtos_block::error!("durable completion dropped: {error}"))?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_durable_sink_wal_receipt_reopens_and_accepts_creator_bound_drafts() {
    use crate::propagation_outbox::{Limits, OutboxDomain, PropagationOutbox, PublicationStage};
    use consensus_common::{ConsensusCommonFactory, ValidatorIdentity};
    let all: serde_json::Value =
        serde_json::from_str(include_str!("testdata/v2-publication-spool.json")).unwrap();
    let mut stable_ids = Vec::new();
    for row_index in 0..2 {
        for final_role in [false, true] {
            let SpoolFixture { dir, engine, runtime, block, row, state_root } =
                SpoolFixture::new(row_index).await;
            let domain = OutboxDomain {
                zerostate: runtime.pin().zerostate.clone(),
                global_id: runtime.pin().global_id,
                wire_profile: runtime.wire_profile(),
            };
            let draft = spool_draft(&runtime, &block, &row, final_role);
            let result = std::panic::AssertUnwindSafe(async {
                let sink = engine.clone().durable_finality_sink(runtime.clone()).await.unwrap();
                assert!(engine.load_block_handle(block.id()).unwrap().is_none());
                let mut wrong_creator = draft.clone();
                wrong_creator.source_info.source =
                    ValidatorIdentity::from_descriptor(&runtime.committee()[1]).unwrap();
                let mut wrong_body = draft.clone();
                let mut data = block.data().to_vec();
                let last = data.len() - 1;
                data[last] ^= 1;
                wrong_body.data = ConsensusCommonFactory::create_block_payload(data);
                for rejected in [wrong_creator, wrong_body] {
                    let (sent, received) = tokio::sync::oneshot::channel();
                    assert!(sink
                        .stage(
                            rejected,
                            Box::new(move |value| {
                                let _ = sent.send(value);
                            })
                        )
                        .is_err());
                    assert!(
                        received.await.is_err(),
                        "rejected admission must not invoke WAL completion"
                    );
                }
                assert!(
                    engine.load_block_handle(block.id()).unwrap().is_none(),
                    "rejected evidence touched block storage"
                );
                let id = stage_spool(&sink, draft.clone()).await.unwrap();
                assert_eq!(
                    stage_spool(&sink, draft.clone()).await.unwrap(),
                    id,
                    "exact retry changed durable identity"
                );
                // A different valid certificate for the same body/role has the
                // same delivery identity, but must not replace its first evidence.
                let alternative =
                    spool_draft(&runtime, &block, &all["rows"][1 - row_index], final_role);
                let collision = stage_spool(&sink, alternative).await.unwrap_err();
                assert!(collision.to_string().contains("different evidence"), "{collision}");
                id
            })
            .catch_unwind()
            .await;
            engine.clone().wait_stop().await.unwrap();
            drop(engine);
            let id = result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
            stable_ids.push(id.clone());

            // Inspect only after closing the actual Engine: an independent
            // live writer would violate the outbox's single-writer contract.
            let reopened = open_engine(dir.path()).await;
            let result = std::panic::AssertUnwindSafe(async {
                {
                    let ledger = PropagationOutbox::open(
                        reopened.db().clone(),
                        domain.clone(),
                        Limits::default(),
                    )
                    .unwrap();
                    let (delivery, stored) = ledger
                        .delivery(&id)
                        .unwrap()
                        .expect("WAL receipt lost across real DB reopen");
                    assert_eq!(
                        ledger.pending().unwrap().len(),
                        1,
                        "rejected or duplicate draft created another record"
                    );
                    assert_eq!(
                        delivery.origin.as_ref().unwrap().source_validator,
                        block.block().unwrap().read_extra().unwrap().created_by().clone()
                    );
                    assert_eq!(delivery.origin.as_ref().unwrap().local_validator_index, Some(0));
                    assert_eq!(stored.record.block_data, block.data());
                    assert_eq!(stored.record.carrier.is_final(), final_role);
                    assert!(
                        stored.record.locally_generated,
                        "empty trigger leader replaced original creator"
                    );
                }
                reopened.set_test_chain_time(Some(1002));
                reopened.initialize_test_full_node_overlays().await.unwrap();
                reopened
                    .overlays_router()
                    .unwrap()
                    .refresh_fast_sync_from_applied_state()
                    .await
                    .unwrap();
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
                let handle = reopened.load_block_handle(block.id()).unwrap().unwrap();
                assert!(handle.has_state());
                assert!(!handle.is_applied(), "durable acceptance cannot fake MC inclusion");
                assert_eq!(
                    reopened.load_state(block.id()).await.unwrap().root_cell().repr_hash(),
                    &state_root
                );
                let sink = reopened.clone().durable_finality_sink(runtime.clone()).await.unwrap();
                assert_eq!(
                    stage_spool(&sink, draft.clone()).await.unwrap(),
                    id,
                    "reopen retry changed ID"
                );
            })
            .catch_unwind()
            .await;
            reopened.clone().wait_stop().await.unwrap();
            drop(reopened);
            result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));

            let reopened = open_engine(dir.path()).await;
            let result = std::panic::AssertUnwindSafe(async {
                let ledger =
                    PropagationOutbox::open(reopened.db().clone(), domain, Limits::default())
                        .unwrap();
                let (_, stored) = ledger.delivery(&id).unwrap().unwrap();
                assert_eq!(ledger.pending().unwrap().len(), 1);
                assert_eq!(stored.stage, PublicationStage::AcceptedDraft);
                assert!(stored.pending.is_empty(), "disabled publication cannot resolve targets");
                assert!(
                    stored.record.effects.is_empty(),
                    "empty unresolved intent is not Completed"
                );
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
            drop(dir);
        }
    }
    assert_ne!(stable_ids[0], stable_ids[1], "Approval and Final must have different IDs");
    assert_eq!(stable_ids[0], stable_ids[2], "empty trigger must refer to the same body/role ID");
    assert_eq!(stable_ids[1], stable_ids[3]);
}

fn remove_spool_transport(dir: &std::path::Path) -> serde_json::Value {
    let path = dir.join("config.json");
    let original: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut retired = original.clone();
    retired["consensus_transport_bindings"] = serde_json::json!([]);
    retired["validator_key_ring"] = serde_json::json!({});
    std::fs::write(path, serde_json::to_vec(&retired).unwrap()).unwrap();
    original
}
fn restore_spool_transport(dir: &std::path::Path, original: &serde_json::Value) {
    let path = dir.join("config.json");
    let mut config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    config["consensus_transport_bindings"] = original["consensus_transport_bindings"].clone();
    config["validator_key_ring"] = original["validator_key_ring"].clone();
    std::fs::write(path, serde_json::to_vec(&config).unwrap()).unwrap();
}
fn spool_domain(
    runtime: &consensus_common::session_runtime::AuthenticatedSessionRuntime,
) -> crate::propagation_outbox::OutboxDomain {
    crate::propagation_outbox::OutboxDomain {
        zerostate: runtime.pin().zerostate.clone(),
        global_id: runtime.pin().global_id,
        wire_profile: runtime.wire_profile(),
    }
}
fn inspect_spool(
    engine: &Arc<Engine>,
    domain: &crate::propagation_outbox::OutboxDomain,
    id: &UInt256,
) -> crate::propagation_outbox::UnverifiedRecord {
    crate::propagation_outbox::inspect_delivery(
        engine.db(),
        domain,
        &crate::propagation_outbox::Limits::default(),
        id,
    )
    .unwrap()
    .expect("persisted delivery disappeared")
    .1
}
async fn initialize_spool_router(engine: &Arc<Engine>) {
    engine.set_test_chain_time(Some(1002));
    engine.initialize_test_full_node_overlays().await.unwrap();
    engine.overlays_router().unwrap().refresh_fast_sync_from_applied_state().await.unwrap();
}
async fn assert_spool_acceptance(
    engine: &Arc<Engine>,
    id: &UInt256,
    block: &BlockStuff,
    state_root: &UInt256,
    final_role: bool,
) {
    let accepted =
        tokio::time::timeout(Duration::from_secs(20), engine.clone().await_publication(id.clone()))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(accepted.block(), block);
    assert_eq!(accepted.is_final(), final_role);
    assert_eq!(accepted.phase(), AcceptancePhase::Preapplied);
    assert_eq!(engine.load_state(block.id()).await.unwrap().root_cell().repr_hash(), state_root);
    assert!(!engine.load_block_handle(block.id()).unwrap().unwrap().is_applied());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_retired_transport_accepts_and_restored_authority_resumes_frozen_routes() {
    use crate::propagation_outbox::PublicationStage;
    for row_index in 0..2 {
        for final_role in [false, true] {
            let SpoolFixture { dir, engine, runtime, block, row, state_root } =
                SpoolFixture::new(row_index).await;
            let domain = spool_domain(&runtime);
            let result = std::panic::AssertUnwindSafe(async {
                let sink = engine.clone().durable_finality_sink(runtime.clone()).await.unwrap();
                stage_spool(&sink, spool_draft(&runtime, &block, &row, final_role)).await.unwrap()
            })
            .catch_unwind()
            .await;
            engine.clone().wait_stop().await.unwrap();
            drop(engine);
            let id = result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
            let original = remove_spool_transport(dir.path());
            let retired = open_engine(dir.path()).await;
            let result = std::panic::AssertUnwindSafe(async {
                assert!(retired.adnl_key_by_id(runtime.local_adnl()).is_none());
                assert!(retired.consensus_transport_bindings().unwrap().is_empty());
                initialize_spool_router(&retired).await;
                assert_spool_acceptance(&retired, &id, &block, &state_root, final_role).await;
                let accepted = inspect_spool(&retired, &domain, &id);
                assert_eq!(accepted.stage, PublicationStage::AcceptedDraft);
                assert!(accepted.pending.is_empty() && accepted.record.effects.is_empty());
                retired.enable_publication_worker().await.unwrap();
                // Observe more than one retry interval: absent authority must
                // not reinterpret this original validator intent as an observer.
                let until = tokio::time::Instant::now() + Duration::from_millis(1200);
                while tokio::time::Instant::now() < until {
                    assert_eq!(inspect_spool(&retired, &domain, &id), accepted);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                accepted
            })
            .catch_unwind()
            .await;
            retired.clone().wait_stop().await.unwrap();
            drop(retired);
            let blocked = result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));

            restore_spool_transport(dir.path(), &original);
            let restored = open_engine(dir.path()).await;
            let result = std::panic::AssertUnwindSafe(async {
                assert!(restored.adnl_key_by_id(runtime.local_adnl()).is_some());
                assert_eq!(
                    inspect_spool(&restored, &domain, &id),
                    blocked,
                    "blocked intent changed across actual DB reopen"
                );
                initialize_spool_router(&restored).await;
                restored.enable_publication_worker().await.unwrap();
                let ready = tokio::time::timeout(Duration::from_secs(15), async {
                    loop {
                        let entry = inspect_spool(&restored, &domain, &id);
                        if entry.stage == PublicationStage::Ready {
                            break entry;
                        }
                        assert_ne!(
                            entry.stage,
                            PublicationStage::Completed,
                            "unresolved/failed transport cannot complete"
                        );
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                })
                .await
                .expect("restored real authority did not resolve original routing intent");
                assert!(!ready.record.effects.is_empty());
                assert!(
                    !ready.pending.is_empty(),
                    "isolated fast/public Plumtree has no outbound neighbours"
                );
                assert_eq!(ready.record.created_at_unix_secs, blocked.record.created_at_unix_secs);
                assert_eq!(ready.record.block_data, blocked.record.block_data);
                assert_eq!(ready.record.carrier, blocked.record.carrier);
                assert_spool_acceptance(&restored, &id, &block, &state_root, final_role).await;
            })
            .catch_unwind()
            .await;
            restored.clone().wait_stop().await.unwrap();
            drop(restored);
            result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));

            // Revoke authority again after destinations have been frozen. The
            // next normal router has no fast identity, but cannot rewrite them.
            remove_spool_transport(dir.path());
            let retired = open_engine(dir.path()).await;
            let result = std::panic::AssertUnwindSafe(async {
                assert!(retired.adnl_key_by_id(runtime.local_adnl()).is_none());
                let frozen = inspect_spool(&retired, &domain, &id);
                assert_eq!(frozen.stage, PublicationStage::Ready);
                assert!(!frozen.pending.is_empty());
                initialize_spool_router(&retired).await;
                retired.enable_publication_worker().await.unwrap();
                assert_spool_acceptance(&retired, &id, &block, &state_root, final_role).await;
                let until = tokio::time::Instant::now() + Duration::from_millis(1200);
                while tokio::time::Instant::now() < until {
                    assert_eq!(
                        inspect_spool(&retired, &domain, &id),
                        frozen,
                        "authority loss rewrote frozen targets or acknowledged a send"
                    );
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .catch_unwind()
            .await;
            retired.clone().wait_stop().await.unwrap();
            drop(retired);
            result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        }
    }
}

fn spool_pending_record(
    runtime: &consensus_common::session_runtime::AuthenticatedSessionRuntime,
    draft: &consensus_common::finality_delivery::FinalizedDeliveryDraft,
) -> simplex::finality_delivery::PendingFinalityRecord {
    let signatures = match &draft.finality {
        SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(value)) => {
            rtos_api::pq_finality::PqNetworkSignatureSet::from_final_fields(value).unwrap()
        }
        SessionFinality::PqApproval(value) => {
            rtos_api::pq_finality::PqNetworkSignatureSet::from_approval(value).unwrap()
        }
        _ => unreachable!(),
    };
    simplex::finality_delivery::PendingFinalityRecord {
        pin: runtime.pin().clone(),
        protocol: runtime.protocol(),
        carrier_version: runtime.carrier_version(),
        wire_profile: runtime.wire_profile(),
        profile: runtime.profile().clone(),
        session_id: runtime.session_id().clone(),
        block_id: draft.block_id.clone(),
        local_adnl: UInt256::from(*runtime.local_adnl().data()),
        local_validator_index: Some(0),
        source_validator: UInt256::from(*draft.source_info.source.id().data()),
        data: draft.data.data().to_vec(),
        signature_set: runtime
            .wire_profile()
            .serialize(&signatures.to_node().into_boxed())
            .unwrap(),
        is_final: signatures.is_final(),
        last_mc_finalized_seqno: draft.last_mc_finalized_seqno,
        candidate_already_sent: draft.candidate_already_sent,
        created_at_unix_secs: draft.created_at_unix_secs,
    }
}
fn spool_recovery_record(
    source: &simplex::finality_delivery::PendingFinalityRecord,
) -> crate::propagation_outbox::PublicationRecord {
    use crate::propagation_outbox::{Limits, OutboxDomain, PublicationRecord, StoredCarrier};
    let block = BlockStuff::deserialize_block_checked(
        source.block_id.clone(),
        Arc::new(source.data.clone()),
    )
    .unwrap();
    PublicationRecord {
        domain: OutboxDomain {
            zerostate: source.pin.zerostate.clone(),
            global_id: source.pin.global_id,
            wire_profile: source.wire_profile,
        },
        protocol: source.protocol,
        profile: source.profile.clone(),
        session_id: source.session_id.clone(),
        block_id: source.block_id.clone(),
        block_data: source.data.clone(),
        proof_data: None,
        prev: vec![block.construct_prev_id().unwrap().0],
        carrier: if source.is_final {
            StoredCarrier::Final(source.signature_set.clone())
        } else {
            StoredCarrier::Approval(source.signature_set.clone())
        },
        locally_generated: true,
        created_at_unix_secs: source.created_at_unix_secs,
        expires_at_unix_secs: source.created_at_unix_secs + Limits::default().max_retention_secs,
        effects: Vec::new(),
    }
}
fn spool_origin(
    source: &simplex::finality_delivery::PendingFinalityRecord,
) -> crate::propagation_outbox::RecoveryOrigin {
    crate::propagation_outbox::RecoveryOrigin {
        carrier_version: source.carrier_version,
        local_adnl: source.local_adnl.clone(),
        source_validator: source.source_validator.clone(),
        local_validator_index: source.local_validator_index,
    }
}

#[test]
fn publication_source_only_crash_child() {
    let Ok(root) = std::env::var("RTOS_SPOOL_CRASH_ROOT") else { return };
    let row_index: usize = std::env::var("RTOS_SPOOL_CRASH_ROW").unwrap().parse().unwrap();
    let final_role = std::env::var("RTOS_SPOOL_CRASH_FINAL").unwrap() == "1";
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("testdata/v2-publication-spool.json")).unwrap();
    let row = &fixture["rows"][row_index];
    let block = fixture_block(row);
    let bytes = decode(&fixture["state_boc"]);
    let cell = read_single_root_boc(&bytes).unwrap();
    let anchor = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        0,
        cell.repr_hash().clone(),
        UInt256::calc_file_hash(&bytes),
    );
    let config = ConfigParams::construct_from_cell(
        read_single_root_boc(&decode(&fixture["config_boc"])).unwrap(),
    )
    .unwrap();
    let (committee, _) = config
        .validator_set()
        .unwrap()
        .calc_subset(&config.catchain_config().unwrap(), SHARD_FULL, 0, 7)
        .unwrap();
    let transport = Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[0x61; 32]).unwrap();
    let runtime =
        consensus_common::session_runtime::AuthenticatedSessionRuntime::from_authenticated_config(
            consensus_common::session_runtime::SessionNetworkPin {
                global_id: -239,
                zerostate: anchor,
            },
            &config,
            rtos_api::session_identity::SessionCoordinates {
                shard: block.id().shard(),
                catchain_seqno: 7,
                vertical_seqno: 0,
                last_key_block_seqno: 0,
                new_catchain_ids: false,
            },
            committee,
            transport.id().clone(),
        )
        .unwrap();
    let record = spool_pending_record(&runtime, &spool_draft(&runtime, &block, row, final_role));
    let namespace = std::path::PathBuf::from(runtime.runtime_directory(&root).unwrap());
    std::fs::create_dir_all(&namespace).unwrap();
    simplex::finality_delivery::retain_pending_finality(&namespace, &record).unwrap();
    // Abrupt process exit: no node sink/ledger ever received this source record.
    std::process::exit(73);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_source_only_crash_recovers_without_retired_key_and_rejects_bad_history() {
    use crate::propagation_outbox::{Limits, PublicationStage, StoredCarrier};
    for row_index in 0..2 {
        for final_role in [false, true] {
            let SpoolFixture { dir, engine, runtime, block, state_root, .. } =
                SpoolFixture::new(row_index).await;
            let source_root =
                std::path::PathBuf::from(engine.db_root_dir().unwrap()).join("catchains");
            engine.clone().wait_stop().await.unwrap();
            drop(engine);
            let original = remove_spool_transport(dir.path());
            let output=std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact","full_node::finality::persistence_tests::inclusion_tests::propagation_tests::publication_source_only_crash_child","--nocapture"])
                .env("RTOS_SPOOL_CRASH_ROOT",&source_root)
                .env("RTOS_SPOOL_CRASH_ROW",row_index.to_string())
                .env("RTOS_SPOOL_CRASH_FINAL",if final_role {"1"} else {"0"}).output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(73),
                "child failed before durable source retention: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let source = {
                let pending =
                    simplex::finality_delivery::scan_pending_finality(&source_root).unwrap();
                assert_eq!(pending.len(), 1);
                pending[0].record().clone()
            }; // Release source-store lock before the production scanner opens it.
            let record = spool_recovery_record(&source);
            let domain = record.domain.clone();
            let id = crate::propagation_outbox::delivery_id(&record).unwrap();
            let retired = open_engine(dir.path()).await;
            let result = std::panic::AssertUnwindSafe(async {
                assert!(retired.adnl_key_by_id(runtime.local_adnl()).is_none());
                assert!(retired.consensus_transport_bindings().unwrap().is_empty());
                assert!(
                    crate::propagation_outbox::inspect_delivery(
                        retired.db(),
                        &domain,
                        &Limits::default(),
                        &id
                    )
                    .unwrap()
                    .is_none(),
                    "child must not create node WAL"
                );
                crate::validator::recover_retained_finality(retired.clone()).await.unwrap();
                assert!(
                    simplex::finality_delivery::scan_pending_finality(&source_root)
                        .unwrap()
                        .is_empty(),
                    "source must ACK only after node WAL"
                );
                let durable = inspect_spool(&retired, &domain, &id);
                assert_eq!(durable.record.block_data, record.block_data);
                assert_eq!(durable.record.carrier, record.carrier);
                assert_eq!(durable.record.created_at_unix_secs, source.created_at_unix_secs);
                assert_spool_acceptance(&retired, &id, &block, &state_root, final_role).await;
                let accepted = inspect_spool(&retired, &domain, &id);
                assert_eq!(accepted.stage, PublicationStage::AcceptedDraft);
                assert!(accepted.pending.is_empty() && accepted.record.effects.is_empty());
                if row_index == 1 && final_role {
                    // All records remain canonical/bounded; historical evidence,
                    // not absence of a current key, must reject these mutations.
                    let origin = spool_origin(&source);
                    let mut negatives = Vec::new();
                    let mut bad = origin.clone();
                    bad.source_validator = runtime.committee()[1].validator_id().unwrap();
                    negatives.push((record.clone(), bad));
                    let mut bad = origin.clone();
                    bad.local_validator_index = Some(1);
                    negatives.push((record.clone(), bad));
                    let mut bad = origin.clone();
                    bad.carrier_version += 1;
                    negatives.push((record.clone(), bad));
                    let mut bad = record.clone();
                    bad.domain.zerostate.file_hash = UInt256::from([91; 32]);
                    negatives.push((bad, origin.clone()));
                    let mut bad = record.clone();
                    bad.profile = UInt256::from([92; 32]);
                    negatives.push((bad, origin.clone()));
                    let mut bad = record.clone();
                    bad.session_id = UInt256::from([93; 32]);
                    negatives.push((bad, origin.clone()));
                    let mut bad = record.clone();
                    bad.carrier = StoredCarrier::Approval(source.signature_set.clone());
                    negatives.push((bad, origin.clone()));
                    let mut bad = record.clone();
                    bad.block_data[0] ^= 1;
                    negatives.push((bad, origin.clone()));
                    for (bad, origin) in &negatives {
                        assert!(retired
                            .clone()
                            .recover_finality_delivery(bad.clone(), 0, false, origin.clone())
                            .await
                            .is_err());
                    }
                    assert_eq!(inspect_spool(&retired, &domain, &id), accepted);
                    negatives
                } else {
                    Vec::new()
                }
            })
            .catch_unwind()
            .await;
            retired.clone().wait_stop().await.unwrap();
            drop(retired);
            let negatives = result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
            // An additional real DB reopen preserves the accepted but unresolved
            // evidence. Key restoration cannot turn corrupt history into valid input.
            if !negatives.is_empty() {
                restore_spool_transport(dir.path(), &original);
            }
            let reopened = open_engine(dir.path()).await;
            let result = std::panic::AssertUnwindSafe(async {
                let retained = inspect_spool(&reopened, &domain, &id);
                assert_eq!(retained.stage, PublicationStage::AcceptedDraft);
                assert_eq!(retained.record.block_data, record.block_data);
                assert_eq!(retained.record.carrier, record.carrier);
                assert_eq!(retained.record.created_at_unix_secs, source.created_at_unix_secs);
                assert!(retained.pending.is_empty() && retained.record.effects.is_empty());
                for (bad, origin) in negatives {
                    assert!(reopened
                        .clone()
                        .recover_finality_delivery(bad, 0, false, origin)
                        .await
                        .is_err());
                }
                assert_spool_acceptance(&reopened, &id, &block, &state_root, final_role).await;
            })
            .catch_unwind()
            .await;
            reopened.clone().wait_stop().await.unwrap();
            drop(reopened);
            result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_reopen_repairs_lost_artifacts_for_completed_and_expired_ready() {
    use crate::propagation_outbox::{
        Limits, PropagationOutbox, PublicationEffect, PublicationKind, PublicationStage,
        PublicationTarget,
    };
    use storage::archives::package_entry_id::{GetFileName, PackageEntryId};
    for final_role in [false, true] {
        for completed in [false, true] {
            for lose_proof in [false, true] {
                let SpoolFixture { dir, engine, runtime, block, row, state_root } =
                    SpoolFixture::new(1).await;
                let domain = spool_domain(&runtime);
                let mut draft = spool_draft(&runtime, &block, &row, final_role);
                // Retention expiry governs sends, not durable acceptance repair.
                draft.created_at_unix_secs -= Limits::default().max_retention_secs + 5;
                let result = std::panic::AssertUnwindSafe(async {
                    let sink = engine.clone().durable_finality_sink(runtime.clone()).await.unwrap();
                    let id = stage_spool(&sink, draft).await.unwrap();
                    let accepted = engine.clone().await_publication(id.clone()).await.unwrap();
                    assert_eq!(accepted.phase(), AcceptancePhase::Preapplied);
                    assert_eq!(accepted.is_final(), final_role);
                    let proof = accepted.proof();
                    (
                        id,
                        proof.is_link(),
                        proof.data().to_vec(),
                        std::path::PathBuf::from(engine.db_root_dir().unwrap())
                            .join("archive/unapplied"),
                    )
                })
                .catch_unwind()
                .await;
                engine.clone().wait_stop().await.unwrap();
                drop(engine);
                let (id, is_link, proof_bytes, unapplied) =
                    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));

                // Set up a persisted stage through the real ledger API while no
                // owner exists. Completed here is a test input, NOT evidence of
                // real network delivery. Only artifact repair is under test.
                let setup = open_engine(dir.path()).await;
                let result = std::panic::AssertUnwindSafe(async {
                    let ledger = PropagationOutbox::open(
                        setup.db().clone(),
                        domain.clone(),
                        Limits::default(),
                    )
                    .unwrap();
                    let (delivery, stored) = ledger.delivery(&id).unwrap().unwrap();
                    assert_eq!(stored.stage, PublicationStage::AcceptedDraft);
                    let effects = vec![PublicationEffect {
                        kind: PublicationKind::Candidate,
                        target: PublicationTarget::Public,
                    }];
                    ledger.resolve_draft(delivery.record_id, effects.clone()).unwrap();
                    if completed {
                        assert!(ledger.checkpoint_sent(delivery.record_id, &effects).unwrap());
                    }
                    let stored = ledger.delivery(&id).unwrap().unwrap().1;
                    assert_eq!(
                        stored.stage,
                        if completed {
                            PublicationStage::Completed
                        } else {
                            PublicationStage::Ready
                        }
                    );
                    assert!(
                        stored.record.expires_at_unix_secs
                            < std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs()
                    );
                    stored
                })
                .catch_unwind()
                .await;
                setup.clone().wait_stop().await.unwrap();
                drop(setup);
                let before = result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));

                let body_path = unapplied.join(PackageEntryId::Block(block.id()).filename_short());
                let proof_path = unapplied.join(
                    if is_link {
                        PackageEntryId::ProofLink(block.id())
                    } else {
                        PackageEntryId::Proof(block.id())
                    }
                    .filename_short(),
                );
                assert_eq!(std::fs::read(&body_path).unwrap(), block.data());
                assert_eq!(std::fs::read(&proof_path).unwrap(), proof_bytes);
                let lost_path = if lose_proof { &proof_path } else { &body_path };
                // Explicit missing-file simulation after clean stop. This is
                // not a claim about hardware power-loss or fsync crash ordering.
                std::fs::rename(lost_path, dir.path().join("simulated-lost-artifact")).unwrap();

                let reopened = open_engine(dir.path()).await;
                let result = std::panic::AssertUnwindSafe(async {
                    let handle = reopened.load_block_handle(block.id()).unwrap().unwrap();
                    assert!(handle.has_data() && handle.has_state());
                    assert!(if is_link { handle.has_proof_link() } else { handle.has_proof() });
                    assert!(!handle.is_applied());
                    assert_eq!(inspect_spool(&reopened, &domain, &id), before);
                    if lose_proof {
                        assert!(reopened
                            .db()
                            .load_block_proof_raw(&handle, is_link)
                            .await
                            .is_err());
                    } else {
                        assert!(reopened.db().load_block_data_raw(&handle).await.is_err());
                    }
                    // No query and no enable: startup's background acceptance
                    // pass must revisit Completed and expired Ready on its own.
                    reopened.ensure_publication_worker().await.unwrap();
                    tokio::time::timeout(Duration::from_secs(20), async {
                        loop {
                            let body = reopened.db().load_block_data_raw(&handle).await;
                            let proof = reopened.db().load_block_proof_raw(&handle, is_link).await;
                            if body.as_ref().is_ok_and(|data| data == block.data())
                                && proof.as_ref().is_ok_and(|data| data == &proof_bytes)
                            {
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                    })
                    .await
                    .expect("disabled startup did not repair expired/completed physical artifacts");
                    let repaired = reopened.db().load_block_proof(&handle, is_link).await.unwrap();
                    if is_link {
                        repaired.check_proof_link().unwrap();
                    } else {
                        repaired.check_proof_as_link().unwrap();
                    }
                    assert_eq!(reopened.db().load_block_data(&handle).await.unwrap(), block);
                    assert_eq!(
                        inspect_spool(&reopened, &domain, &id),
                        before,
                        "artifact repair changed delivery identity, stage or frozen effects"
                    );
                    assert_eq!(
                        reopened.load_state(block.id()).await.unwrap().root_cell().repr_hash(),
                        &state_root
                    );
                })
                .catch_unwind()
                .await;
                // Join the actual actor and all storage writers before the
                // second DB reopen is treated as a durability observation.
                reopened.clone().wait_stop().await.unwrap();
                drop(reopened);
                result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));

                let reopened = open_engine(dir.path()).await;
                let result = std::panic::AssertUnwindSafe(async {
                    let handle = reopened.load_block_handle(block.id()).unwrap().unwrap();
                    assert_eq!(reopened.db().load_block_data(&handle).await.unwrap(), block);
                    assert_eq!(
                        reopened.db().load_block_proof_raw(&handle, is_link).await.unwrap(),
                        proof_bytes
                    );
                    assert_eq!(inspect_spool(&reopened, &domain, &id), before);
                    assert!(!handle.is_applied());
                    assert_eq!(
                        reopened.load_state(block.id()).await.unwrap().root_cell().repr_hash(),
                        &state_root
                    );
                })
                .catch_unwind()
                .await;
                reopened.clone().wait_stop().await.unwrap();
                drop(reopened);
                result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
            }
        }
    }
}

#[path = "propagation_durability_tests.rs"]
mod durability_tests;
