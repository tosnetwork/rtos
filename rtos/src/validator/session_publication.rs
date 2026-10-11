// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Freeze exact publication effects before durable acceptance of a v2 callback.
use super::propagation::{PropagationEvent, PropagationKind, PropagationPlan, PropagationTarget};
use crate::{
    block::{construct_and_check_prev_stuff, BlockStuff},
    engine_traits::EngineOperations,
    propagation_outbox::{
        Limits, OutboxDomain, PublicationEffect, PublicationKind, PublicationRecord,
        PublicationTarget, StoredCarrier,
    },
};
use consensus_common::{
    session_runtime::{AuthenticatedSessionRuntime, LocalRole},
    SessionFinality,
};
use rtos_api::{pq_finality::PqNetworkSignatureSet, IntoBoxed};
use rtos_block::{error, fail, BlockIdExt, BlockSignaturesVariant, Result};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

#[allow(clippy::too_many_arguments)]
pub(super) async fn prepare_publication(
    runtime: &AuthenticatedSessionRuntime,
    id: BlockIdExt,
    data: &[u8],
    prev: &[BlockIdExt],
    finality: &SessionFinality,
    engine: &Arc<dyn EngineOperations>,
    locally_generated: bool,
    last_mc: u32,
    candidate_already_sent: bool,
) -> Result<Option<PublicationRecord>> {
    let limits = Limits::default();
    if data.is_empty() || data.len() > limits.max_block_bytes {
        fail!("Publication block exceeds its durable limit");
    }
    let block = BlockStuff::deserialize_block_checked(id.clone(), Arc::new(data.to_vec()))?;
    block.verify_expected_id(&id)?;
    let (_, actual) = construct_and_check_prev_stuff(block.root_cell(), &id, false)?;
    if actual.prev != prev
        || block.block()?.global_id() != runtime.pin().global_id
        || &runtime.pin().zerostate != engine.zerostate_id()?
    {
        fail!("Publication body or pin differs from the authenticated session");
    }
    let verifier = runtime
        .pq_context()
        .ok_or_else(|| error!("Publication needs a PQ session"))?
        .for_block(id.clone())?;
    let (network, slot, is_final) = match finality {
        SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(carrier)) => {
            verifier.verify_final(carrier)?;
            (PqNetworkSignatureSet::from_final_fields(carrier)?, carrier.slot, true)
        }
        SessionFinality::PqApproval(approval) => {
            verifier.verify_approval(approval)?;
            (PqNetworkSignatureSet::from_approval(approval)?, approval.slot(), false)
        }
        _ => fail!("Publication requires PQ quorum evidence"),
    };
    if locally_generated {
        let leader =
            (slot / runtime.slots_per_leader_window()) as usize % runtime.committee().len();
        if !matches!(runtime.local_role(), LocalRole::Validator(index) if index as usize == leader)
        {
            fail!("Publication creator does not match the authenticated leader");
        }
    }
    let plan = PropagationPlan::for_event(
        runtime.protocol(),
        PropagationEvent::Finalized,
        &id,
        true,
        locally_generated,
        is_final,
        last_mc,
        candidate_already_sent,
    );
    let destinations = engine.resolve_propagation_targets(&id, &plan).await?;
    let mut effects = Vec::with_capacity(destinations.len());
    for destination in destinations {
        plan.for_destination(&destination)?;
        let kind = match destination.kind {
            PropagationKind::Candidate => PublicationKind::Candidate,
            PropagationKind::Block => PublicationKind::Block,
            PropagationKind::Finality => PublicationKind::Finality,
            PropagationKind::ShardDescription => PublicationKind::ShardDescription,
        };
        let target = match destination.target {
            PropagationTarget::Public => PublicationTarget::Public,
            PropagationTarget::FastSync => PublicationTarget::FastSync,
            PropagationTarget::Custom(name) if !name.is_empty() => PublicationTarget::Custom(name),
            PropagationTarget::Custom(_) => {
                fail!("Durable publication requires a named custom target")
            }
            PropagationTarget::ShardDescription => PublicationTarget::ShardDescription,
        };
        effects.push(PublicationEffect { kind, target });
    }
    effects.sort();
    effects.dedup();
    if effects.is_empty() {
        return Ok(None);
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let bytes = runtime.wire_profile().serialize(&network.to_node().into_boxed())?;
    Ok(Some(PublicationRecord {
        domain: OutboxDomain {
            zerostate: runtime.pin().zerostate.clone(),
            global_id: runtime.pin().global_id,
            wire_profile: runtime.wire_profile(),
        },
        protocol: runtime.protocol(),
        profile: runtime.profile().clone(),
        session_id: runtime.session_id().clone(),
        block_id: id,
        block_data: data.to_vec(),
        proof_data: None,
        prev: prev.to_vec(),
        carrier: if is_final {
            StoredCarrier::Final(bytes)
        } else {
            StoredCarrier::Approval(bytes)
        },
        locally_generated,
        created_at_unix_secs: now,
        expires_at_unix_secs: now
            .checked_add(limits.max_retention_secs)
            .ok_or_else(|| error!("Publication retention deadline overflow"))?,
        effects,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus_common::session_runtime::SessionNetworkPin;
    use rtos_api::session_identity::SessionCoordinates;
    use rtos_block::*;
    struct Resolver(BlockIdExt);
    #[async_trait::async_trait]
    impl EngineOperations for Resolver {
        fn zerostate_id(&self) -> Result<&BlockIdExt> {
            Ok(&self.0)
        }
        async fn resolve_propagation_targets(
            &self,
            _: &BlockIdExt,
            plan: &PropagationPlan,
        ) -> Result<Vec<super::super::propagation::PropagationDestination>> {
            use super::super::propagation::PropagationDestination;
            let mut targets = Vec::new();
            for kind in
                [PropagationKind::Candidate, PropagationKind::Block, PropagationKind::Finality]
            {
                if plan.targets_for(kind).public {
                    targets
                        .push(PropagationDestination { kind, target: PropagationTarget::Public });
                }
            }
            Ok(targets)
        }
    }
    #[tokio::test]
    async fn session_publication_freezes_authenticated_effects_and_rejects_wrong_body() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../full_node/finality/testdata/v2-propagation-recovery.json"
        ))
        .unwrap();
        let bytes = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
        let config = ConfigParams::construct_from_cell(
            read_single_root_boc(&bytes(&fixture["config_boc"])).unwrap(),
        );
        let config = config.unwrap();
        let zero_data = bytes(&fixture["state_boc"]);
        let zero = BlockIdExt::with_params(
            ShardIdent::masterchain(),
            0,
            read_single_root_boc(&zero_data).unwrap().repr_hash().clone(),
            UInt256::calc_file_hash(&zero_data),
        );
        let row = &fixture["rows"][0];
        let candidate_bytes = bytes(&row["candidate"]);
        let candidate: rtos_api::ton::consensus::CandidateHashData =
            rtos_api::WireProfile::T0.deserialize_typed(&candidate_bytes).unwrap();
        let id = candidate.block().clone();
        let data = bytes(&row["block_boc"]);
        let block =
            BlockStuff::deserialize_block_checked(id.clone(), Arc::new(data.clone())).unwrap();
        let (committee, _) = config
            .validator_set()
            .unwrap()
            .calc_subset(
                &config.catchain_config().unwrap(),
                id.shard().shard_prefix_with_tag(),
                id.shard().workchain_id(),
                7,
            )
            .unwrap();
        let local = committee[0].adnl_addr().unwrap();
        let runtime = AuthenticatedSessionRuntime::from_authenticated_config(
            SessionNetworkPin {
                global_id: block.block().unwrap().global_id(),
                zerostate: zero.clone(),
            },
            &config,
            SessionCoordinates {
                shard: id.shard(),
                catchain_seqno: 7,
                vertical_seqno: 0,
                last_key_block_seqno: 0,
                new_catchain_ids: false,
            },
            committee,
            local,
        )
        .unwrap();
        let engine: Arc<dyn EngineOperations> = Arc::new(Resolver(zero));
        let prev = vec![block.construct_prev_id().unwrap().0];
        let mut carrier = BlockSignaturesSimplexPq {
            validator_info: runtime.pq_context().unwrap().validator_info(),
            sig_count: row["signatures"].as_array().unwrap().len() as u32,
            sig_weight: row["weight"].as_u64().unwrap(),
            session_id: runtime.session_id().clone(),
            slot: 99,
            candidate_data: BlockSignaturesSimplex::bytes_to_cell_tree(&candidate_bytes).unwrap(),
            signatures: row["signatures"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| {
                    let mut id = [0; 32];
                    id[..4]
                        .copy_from_slice(&(s["index"].as_u64().unwrap() as u32 + 1).to_le_bytes());
                    PqBlockSignaturePair {
                        validator_id: id.into(),
                        algorithm_id: 1,
                        signature: bytes(&s["signature"]),
                    }
                })
                .collect(),
        };
        let finality = SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(carrier.clone()));
        let intent = prepare_publication(
            &runtime,
            id.clone(),
            &data,
            &prev,
            &finality,
            &engine,
            false,
            0,
            true,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            intent.effects,
            vec![PublicationEffect {
                kind: PublicationKind::Finality,
                target: PublicationTarget::Public
            }]
        );
        assert_eq!(intent.block_data, data);
        assert_eq!(intent.session_id, runtime.session_id().clone());
        assert!(intent.carrier.is_final());
        let mut wrong = data.clone();
        wrong[0] ^= 1;
        assert!(prepare_publication(
            &runtime,
            id.clone(),
            &wrong,
            &prev,
            &finality,
            &engine,
            false,
            0,
            false
        )
        .await
        .is_err());
        carrier.signatures[0].signature[0] ^= 1;
        assert!(prepare_publication(
            &runtime,
            id,
            &data,
            &prev,
            &SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(carrier)),
            &engine,
            false,
            0,
            false
        )
        .await
        .is_err());
    }
}
