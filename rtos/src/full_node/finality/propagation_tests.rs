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
        let received = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let receipts = pair.receiver.network().test_broadcast_faults.receipts();
                if receipts.iter().any(|r| r.simple_id == Some(expected_id)) {
                    break receipts;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|error| {
            panic!(
                "normal finality carrier missing: {error}; expected={expected_id:?}; actual={:?}",
                pair.receiver.network().test_broadcast_faults.receipts()
            )
        });
        let receipt = received
            .iter()
            .find(|r| r.simple_id == Some(expected_id) && !r.dropped && r.error.is_none())
            .expect("normal sender must emit the T0 certificate-bound simple transport ID");
        let carrier: rtos_api::ton::overlay::Broadcast =
            WireProfile::T0.deserialize_typed(&receipt.wire[prefix.len()..]).unwrap();
        let rtos_api::ton::overlay::Broadcast::Overlay_BroadcastPlumtreeSimple(carrier) = carrier
        else {
            panic!("finality must use simple Plumtree");
        };
        assert_eq!(carrier.data, expected_wire);
        if let Ok(directory) = std::env::var("RTOS_V2_PROPAGATION_EVIDENCE_DIR") {
            let directory = std::path::PathBuf::from(directory);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join("normal.finality"), &carrier.data).unwrap();
            std::fs::write(directory.join("normal.plumtree"), &receipt.wire[prefix.len()..])
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
        // Real already-applied acceptance rebuilds a verified carrier and sends
        // through the opposite node's normal router without rewriting its state.
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
        let retry_outcome = pair.receiver.propagate_accepted_session_block(&retry, &plan).await;
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
async fn propagation_authenticated_finalize_candidate_fallback_shares_receive_dedup() {
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
        assert!(!outcome.needs_retry(), "{outcome:?}");
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
        assert!(!duplicate.attempted(), "{duplicate:?}");
        assert!(duplicate
            .receipts
            .iter()
            .any(|r| matches!(r.status, PropagationStatus::Skipped(_))));
        assert!(!duplicate.needs_retry());
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
        })
        .catch_unwind()
        .await;
        pair.receiver.clone().wait_stop().await.unwrap();
        pair.provider.clone().wait_stop().await.unwrap();
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }
}
