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
                assert_eq!(stored.stage, PublicationStage::Ready);
                assert!(
                    !stored.pending.is_empty(),
                    "publication remained disabled; no target was sent"
                );
                assert_eq!(stored.pending, stored.record.effects);
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
