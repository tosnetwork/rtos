// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Recheck author and body bindings before granting public candidate relay authority.
//! Transport admission remains the receiver's responsibility; a relay need not be the author.
use crate::block::BlockStuff;
use consensus_common::{
    session_runtime::AuthenticatedSessionRuntime, simplex_protocol::SimplexProtocol,
    CandidateAuthenticationEvidence, ValidatorIdentity,
};
use rtos_api::{ton::consensus::CandidateHashData, IntoBoxed};
use rtos_block::{fail, Result, UInt256};
use std::{io::Cursor, sync::Arc};

pub(super) fn verify_candidate_for_relay(
    runtime: &AuthenticatedSessionRuntime,
    evidence: &CandidateAuthenticationEvidence,
    max_block_size: usize,
    max_collated_size: usize,
) -> Result<BlockStuff> {
    if runtime.protocol() != SimplexProtocol::PrivateObserversPlumtree
        || runtime.wire_profile() != rtos_api::WireProfile::T0
        || runtime.session_id() != &evidence.session_id
        || runtime.shard() != evidence.block_id.shard()
        || evidence.slot > i32::MAX as u32
    {
        fail!("Candidate relay runtime or session mismatch");
    }
    // Ordinary hash data is fixed-width apart from its optional parent. Bound
    // it before TL allocation, independently of the block payload limits.
    if evidence.candidate_hash_data.len() > 256
        || evidence.data.data().len() > max_block_size
        || evidence.collated_data.data().len() > max_collated_size
    {
        fail!("Candidate relay evidence exceeds session limits");
    }
    let count = runtime.committee().len();
    let slots = runtime.slots_per_leader_window();
    if count == 0 || slots == 0 {
        fail!("Candidate relay has no authenticated leader schedule");
    }
    let leader = (evidence.slot / slots) as usize % count;
    let descriptor = &runtime.committee()[leader];
    if evidence.creator_index as usize != leader
        || descriptor.adnl_addr()?.data() != evidence.creator_adnl.data()
    {
        fail!("Candidate relay author differs from scheduled leader");
    }
    let identity = ValidatorIdentity::from_descriptor(descriptor)?;
    let mut input = Cursor::new(evidence.candidate_hash_data.as_slice());
    let decoded = rtos_api::Deserializer::new(&mut input).read_boxed::<CandidateHashData>()?;
    if input.position() as usize != evidence.candidate_hash_data.len()
        || rtos_api::serialize_boxed(&decoded)? != evidence.candidate_hash_data
    {
        fail!("Candidate relay hash data is not canonical");
    }
    let CandidateHashData::Consensus_CandidateHashDataOrdinary(ordinary) = &decoded else {
        fail!("Empty candidates cannot authorize block relay");
    };
    if ordinary.block != evidence.block_id
        || ordinary.collated_file_hash != UInt256::calc_file_hash(evidence.collated_data.data())
    {
        fail!("Candidate relay body commitment mismatch");
    }
    if let Some(parent) = ordinary.parent.id() {
        if *parent.slot() < 0 || *parent.slot() as u32 >= evidence.slot {
            fail!("Candidate relay parent slot is not earlier than the candidate");
        }
    }
    let id = rtos_api::ton::consensus::candidateid::CandidateId {
        slot: evidence.slot as i32,
        hash: UInt256::calc_file_hash(&evidence.candidate_hash_data),
    }
    .into_boxed();
    let preimage =
        simplex::utils::create_data_to_sign(runtime.session_id(), &rtos_api::serialize_boxed(&id)?);
    identity.verify_simplex(&preimage, &evidence.signature)?;
    let block = BlockStuff::deserialize_block_checked(
        evidence.block_id.clone(),
        Arc::new(evidence.data.data().to_vec()),
    )?;
    block.verify_expected_id(&evidence.block_id)?;
    if block.block()?.global_id() != runtime.pin().global_id {
        fail!("Candidate relay block belongs to a different network");
    }
    Ok(block)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use consensus_common::{session_runtime::SessionNetworkPin, ConsensusCommonFactory};
    use rtos_api::session_identity::SessionCoordinates;
    use rtos_block::{BlockIdExt, ConfigParams, Deserializable, KeyId, ShardIdent, ValidatorSet};

    pub(in crate::validator) fn fixture(
    ) -> (AuthenticatedSessionRuntime, CandidateAuthenticationEvidence) {
        let json: serde_json::Value = serde_json::from_str(include_str!(
            "../full_node/finality/testdata/v2-propagation-recovery.json"
        ))
        .unwrap();
        let bytes = |value: &serde_json::Value| hex::decode(value.as_str().unwrap()).unwrap();
        let row = &json["rows"][0];
        let config = ConfigParams::construct_from_bytes(&bytes(&json["config_boc"])).unwrap();
        let candidate = bytes(&row["candidate"]);
        let parsed: CandidateHashData =
            rtos_api::WireProfile::T0.deserialize_typed(&candidate).unwrap();
        let block_id = parsed.block().clone();
        let (committee, _) = config
            .validator_set()
            .unwrap()
            .calc_subset(
                &config.catchain_config().unwrap(),
                block_id.shard().shard_prefix_with_tag(),
                0,
                7,
            )
            .unwrap();
        // Match the group's ValidatorSet representation. Prefix weights are
        // internal lookup metadata and do not change the signed committee.
        let committee = ValidatorSet::new(0, 100000, committee.len() as u16, committee)
            .unwrap()
            .list()
            .to_vec();
        // This is an explicitly trusted isolated test configuration, not a test
        // of governing-chain authentication or network peer admission.
        let runtime = AuthenticatedSessionRuntime::from_authenticated_config(
            SessionNetworkPin {
                global_id: -239,
                zerostate: BlockIdExt::with_params(
                    ShardIdent::masterchain(),
                    0,
                    UInt256::from([21; 32]),
                    UInt256::from([22; 32]),
                ),
            },
            &config,
            SessionCoordinates {
                shard: block_id.shard(),
                catchain_seqno: 7,
                vertical_seqno: 0,
                last_key_block_seqno: 0,
                new_catchain_ids: false,
            },
            committee.clone(),
            committee[0].adnl_addr().unwrap(),
        )
        .unwrap();
        assert_eq!(hex::encode(runtime.session_id().as_slice()), row["session"].as_str().unwrap());
        let leader = (99 / runtime.slots_per_leader_window()) as usize % committee.len();
        let identity = committee[leader].validator_id().unwrap();
        let signer_index = u32::from_le_bytes(identity.as_slice()[..4].try_into().unwrap()) - 1;
        let signature = row["candidate_signatures"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["index"].as_u64() == Some(signer_index as u64))
            .unwrap();
        let evidence = CandidateAuthenticationEvidence {
            session_id: runtime.session_id().clone(),
            slot: 99,
            creator_index: leader as u32,
            creator_adnl: committee[leader].adnl_addr().unwrap(),
            candidate_hash_data: candidate,
            signature: bytes(&signature["signature"]),
            block_id,
            data: ConsensusCommonFactory::create_block_payload(bytes(&row["block_boc"])),
            collated_data: ConsensusCommonFactory::create_block_payload(vec![]),
        };
        (runtime, evidence)
    }

    #[test]
    fn candidate_relay_authentication_accepts_real_pq_author_and_binds_bodies() {
        let (runtime, evidence) = fixture();
        let size = evidence.data.data().len();
        let block = verify_candidate_for_relay(&runtime, &evidence, size, 0).unwrap();
        assert_eq!(block.id(), &evidence.block_id);
        let mut changed = evidence.clone();
        let mut body = changed.data.data().to_vec();
        body[0] ^= 1;
        changed.data = ConsensusCommonFactory::create_block_payload(body);
        assert!(verify_candidate_for_relay(&runtime, &changed, size, 0).is_err());
        changed = evidence.clone();
        changed.collated_data = ConsensusCommonFactory::create_block_payload(vec![1]);
        assert!(verify_candidate_for_relay(&runtime, &changed, size, 1).is_err());
        assert!(verify_candidate_for_relay(&runtime, &evidence, size - 1, 0).is_err());
    }

    #[test]
    fn candidate_relay_authentication_rejects_wrong_author_session_and_signature() {
        let (runtime, evidence) = fixture();
        let size = evidence.data.data().len();
        verify_candidate_for_relay(&runtime, &evidence, size, 0).unwrap();
        let mut changed = evidence.clone();
        changed.creator_index = (changed.creator_index + 1) % runtime.committee().len() as u32;
        assert!(verify_candidate_for_relay(&runtime, &changed, size, 0).is_err());
        changed = evidence.clone();
        changed.creator_adnl = KeyId::from_data([0xff; 32]);
        assert!(verify_candidate_for_relay(&runtime, &changed, size, 0).is_err());
        changed = evidence.clone();
        changed.session_id = UInt256::from([0xff; 32]);
        assert!(verify_candidate_for_relay(&runtime, &changed, size, 0).is_err());
        changed = evidence.clone();
        changed.signature[0] ^= 1;
        assert!(verify_candidate_for_relay(&runtime, &changed, size, 0).is_err());
        changed = evidence.clone();
        changed.slot = i32::MAX as u32 + 1;
        assert!(verify_candidate_for_relay(&runtime, &changed, size, 0).is_err());
    }

    #[test]
    fn candidate_relay_authentication_rejects_noncanonical_and_inverted_parent() {
        let (runtime, evidence) = fixture();
        let size = evidence.data.data().len();
        let mut changed = evidence.clone();
        changed.candidate_hash_data.push(0);
        assert!(verify_candidate_for_relay(&runtime, &changed, size, 0).is_err());
        changed.candidate_hash_data.resize(257, 0);
        assert!(verify_candidate_for_relay(&runtime, &changed, size, 0).is_err());
        let mut parsed: CandidateHashData =
            rtos_api::WireProfile::T0.deserialize_typed(&evidence.candidate_hash_data).unwrap();
        let CandidateHashData::Consensus_CandidateHashDataOrdinary(ref mut ordinary) = parsed
        else {
            unreachable!()
        };
        ordinary.parent = rtos_api::ton::consensus::candidateparent::CandidateParent {
            id: rtos_api::ton::consensus::candidateid::CandidateId {
                slot: 99,
                hash: UInt256::from([98; 32]),
            }
            .into_boxed(),
        }
        .into_boxed();
        changed = evidence.clone();
        changed.candidate_hash_data = rtos_api::serialize_boxed(&parsed).unwrap();
        assert!(verify_candidate_for_relay(&runtime, &changed, size, 0)
            .err()
            .expect("inverted parent must fail")
            .to_string()
            .contains("parent slot"));
    }
}
