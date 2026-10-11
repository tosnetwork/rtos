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
