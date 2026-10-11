// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Normal applied-config transport and authenticated acceptance, with real DBs.
use super::*;
use crate::validator::{
    accept_block::{accept_pq_session_block, AcceptancePhase},
    propagation::{
        PropagationEvent, PropagationKind, PropagationPlan, PropagationStatus, PropagationTarget,
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
        let outcome = pair.provider.propagate_accepted_session_block(&accepted, &plan).await;
        assert!(sent(&outcome, PropagationKind::Finality), "{outcome:?}");
        assert!(!outcome.needs_retry(), "{outcome:?}");
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
