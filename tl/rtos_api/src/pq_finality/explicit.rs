// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Verification against caller-supplied membership and session. These raw
//! coordinates and successful numeric weights grant no chain admission token.
use super::{build_simplex_vote_data, verify_all_signatures};
use rtos_block::{
    checked_add_validator_weight, checked_validator_weight_sum, derive_consensus_key_id, error,
    fail, quorum_weight_reached, PqBlockSignaturePair, Result, UInt256, ValidatorBaseInfo,
    ValidatorDescr, ValidatorKey, ValidatorSet, MLDSA44_PUBLIC_KEY_BYTES, PQ_SIGNATURE_MAX_SIGNERS,
};
use std::collections::{HashMap, HashSet};

#[derive(Debug)]
pub struct FinalityRefusal(pub &'static str);
impl std::fmt::Display for FinalityRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for FinalityRefusal {}
fn refused(reason: &'static str) -> anyhow::Error {
    FinalityRefusal(reason).into()
}

/// Raw wire identity, independent of the admitted ShardIdent profile.
#[derive(Clone, Debug)]
pub struct ExplicitFinalityBlock {
    pub workchain: i32,
    pub shard: u64,
    pub seqno: u32,
    pub root_hash: UInt256,
    pub file_hash: UInt256,
}

/// Immutable decoded evidence. Construction checks shape, not signatures or
/// the caller's authority to supply the governing context.
pub struct ExplicitPqSignatureSet {
    validator_info: ValidatorBaseInfo,
    session_id: UInt256,
    slot: u32,
    candidate: Vec<u8>,
    signatures: Vec<PqBlockSignaturePair>,
    is_final: bool,
}
impl ExplicitPqSignatureSet {
    pub fn new(
        validator_info: ValidatorBaseInfo,
        session_id: UInt256,
        slot: u32,
        candidate: Vec<u8>,
        signatures: Vec<PqBlockSignaturePair>,
        is_final: bool,
    ) -> Result<Self> {
        // The explicit C++ boundary parses the candidate before constructing
        // and validating its signature set.
        rtos_block::validate_candidate_tl(&candidate)
            .map_err(|_| refused("candidate_malformed"))?;
        if signatures.len() > PQ_SIGNATURE_MAX_SIGNERS as usize {
            return Err(refused("too_many_signers"));
        }
        let mut ids = HashSet::new();
        for pair in &signatures {
            pair.validate()?;
            if !ids.insert(pair.validator_id.clone()) {
                return Err(refused("duplicate_signer"));
            }
        }
        Ok(Self { validator_info, session_id, slot, candidate, signatures, is_final })
    }
}

pub struct ExplicitPqFinalityContext {
    validators: Vec<ValidatorDescr>,
    catchain_seqno: u32,
    subset_hash: u32,
    total_weight: u64,
    block: ExplicitFinalityBlock,
    expected_session: UInt256,
}
impl ExplicitPqFinalityContext {
    pub fn new(
        validators: Vec<ValidatorDescr>,
        catchain_seqno: u32,
        block: ExplicitFinalityBlock,
        expected_session: UInt256,
    ) -> Result<Self> {
        Self::with_member_limit(validators, catchain_seqno, block, expected_session, 1024)
    }
    fn with_member_limit(
        validators: Vec<ValidatorDescr>,
        catchain_seqno: u32,
        block: ExplicitFinalityBlock,
        expected_session: UInt256,
        max_members: usize,
    ) -> Result<Self> {
        if validators.is_empty() || validators.len() > max_members || block.shard == 0 {
            fail!("explicit context requires 1..{} validators and a nonzero shard", max_members);
        }
        let mut ids = HashSet::new();
        let mut keys = HashSet::new();
        for member in &validators {
            if matches!(&member.key, ValidatorKey::Pq(key) if key.algorithm_id == 0) {
                fail!("explicit PQ algorithm must be positive");
            }
            if !ids.insert(member.validator_id()?) || !keys.insert(member.consensus_key_id()?) {
                fail!("explicit context has duplicate validator or key identity");
            }
        }
        let total_weight = checked_validator_weight_sum(validators.iter().map(|v| v.weight))?;
        let subset_hash = ValidatorSet::calc_subset_hash_short(&validators, catchain_seqno)?;
        Ok(Self { validators, catchain_seqno, subset_hash, total_weight, block, expected_session })
    }
    pub fn total_weight(&self) -> u64 {
        self.total_weight
    }

    /// Mirror the explicit finality boundary: carrier compatibility, set/role/
    /// session identity, candidate identity, signer membership, every signature,
    /// quorum, then an optional final-proof claimed weight. No chain authority.
    pub fn verify(
        &self,
        set: &ExplicitPqSignatureSet,
        expected_final: bool,
        claimed_weight: Option<u64>,
    ) -> Result<u64> {
        if self.validators.iter().any(|v| !matches!(v.key, ValidatorKey::Pq(_))) {
            return Err(refused("carrier_mismatch"));
        }
        if set.validator_info.catchain_seqno != self.catchain_seqno {
            return Err(refused("catchain_seqno_mismatch"));
        }
        if set.validator_info.validator_list_hash_short != self.subset_hash {
            return Err(refused("validator_set_hash_mismatch"));
        }
        if set.is_final != expected_final {
            return Err(refused("role_mismatch"));
        }
        if set.session_id != self.expected_session {
            return Err(refused("session_mismatch"));
        }
        let vote = build_simplex_vote_data(&set.session_id, set.slot, &set.candidate, set.is_final)
            .map_err(|_| refused("candidate_malformed"))?;
        let block = &self.block;
        if (vote.workchain, vote.shard, vote.seqno) != (block.workchain, block.shard, block.seqno)
            || vote.root_hash != block.root_hash
            || vote.file_hash != block.file_hash
        {
            return Err(refused("block_mismatch"));
        }
        let mut members = HashMap::new();
        for member in &self.validators {
            let ValidatorKey::Pq(key) = &member.key else {
                return Err(error!("PQ member required"));
            };
            members.insert(member.validator_id()?, (key, member.weight));
        }
        let mut weight = 0;
        for signature in &set.signatures {
            let Some((key, member_weight)) = members.get(&signature.validator_id) else {
                return Err(refused("unknown_signer"));
            };
            if key.algorithm_id != signature.algorithm_id {
                return Err(refused("algorithm_mismatch"));
            }
            if key.public_key.len() != MLDSA44_PUBLIC_KEY_BYTES {
                return Err(refused("malformed_public_key"));
            }
            if derive_consensus_key_id(key.algorithm_id, &key.public_key) != key.key_id {
                return Err(refused("key_id_mismatch"));
            }
            weight = checked_add_validator_weight(weight, *member_weight)
                .map_err(|_| refused("weight_overflow"))?;
        }
        let keys = members.into_iter().map(|(id, (key, _))| (id, key)).collect();
        verify_all_signatures(&vote.data_to_sign, &set.signatures, &keys).map_err(|e| {
            match e.downcast_ref::<rtos_pq_crypto::VerifyError>() {
                Some(rtos_pq_crypto::VerifyError::Backend(_)) => refused("backend_failure"),
                Some(_) => refused("malformed_signature"),
                None => refused("invalid_signature"),
            }
        })?;
        if !quorum_weight_reached(weight, self.total_weight) {
            return Err(refused("insufficient_weight"));
        }
        if expected_final && claimed_weight.is_some_and(|claim| claim != weight) {
            return Err(refused("claimed_weight_mismatch"));
        }
        Ok(weight)
    }
}
