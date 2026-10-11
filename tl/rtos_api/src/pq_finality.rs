// RTOS modifications (2026-10-10): owned consumer readiness and authenticated finality recovery.
// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! PQ final signatures bound to an explicitly supplied governing configuration.
//! The caller must authenticate that configuration and its place in chain history.
//! This module never obtains authority from the signature carrier or a peer's RPC.
use crate::{
    session_identity::{derive_session_from_config, SessionCoordinates},
    IntoBoxed,
};
use rtos_block::{
    checked_validator_weight_sum, error, fail, has_quorum, BlockIdExt, BlockSignaturesSimplexPq,
    ConfigParamEnum, ConfigParams, PqBlockValidatorWeight, Result, Serializable, UInt256,
    ValidatorDescr, ValidatorKey,
};
use std::{collections::HashMap, io::Cursor};

mod network;
pub use network::{PqNetworkSignatureSet, VerifiedPqNetworkSignatures};

/// Immutable expected context, derived from the caller's governing configuration.
/// Construction validates protocol consistency, not the origin of the config.
#[derive(Clone, Debug)]
pub struct PqVerificationContext {
    block_id: BlockIdExt,
    session_id: UInt256,
    catchain_seqno: u32,
    subset_hash: u32,
    total_weight: u64,
    validators: Vec<ValidatorDescr>,
}

/// Immutable membership and session identity supplied by the authenticated session
/// manager. This validates consistency; it does not authenticate its caller.
#[derive(Clone, Debug)]
pub struct PqSessionContext {
    shard: rtos_block::ShardIdent,
    session_id: UInt256,
    catchain_seqno: u32,
    subset_hash: u32,
    validators: Vec<ValidatorDescr>,
    total_weight: u64,
}
impl PqSessionContext {
    /// `session_id` and `validators` must be the manager's authenticated, frozen
    /// governing-session snapshot, never values extracted from a peer carrier.
    pub fn from_authenticated_session_members(
        session_id: UInt256,
        shard: rtos_block::ShardIdent,
        catchain_seqno: u32,
        validators: Vec<ValidatorDescr>,
    ) -> Result<Self> {
        rtos_block::validate_validator_list(&validators)?;
        if validators.iter().any(|v| !matches!(v.key, ValidatorKey::Pq(_))) {
            fail!("PQ session requires an entirely PQ governing subset");
        }
        let subset_hash =
            rtos_block::ValidatorSet::calc_subset_hash_short(&validators, catchain_seqno)?;
        let total_weight = checked_validator_weight_sum(validators.iter().map(|v| v.weight))?;
        Ok(Self { session_id, shard, catchain_seqno, subset_hash, validators, total_weight })
    }
    pub fn from_authenticated_session_members_bounded(
        session_id: UInt256, shard: rtos_block::ShardIdent, catchain_seqno: u32,
        validators: Vec<ValidatorDescr>, budget: &dyn rtos_block::config_read_budget::ConfigReadBudget,
    ) -> Result<Self> {
        let total_weight = rtos_block::validators::validate_validator_list_bounded(&validators, budget)?;
        for v in &validators {
            budget.step()?;
            if !matches!(v.key, ValidatorKey::Pq(_)) { fail!("PQ session requires an entirely PQ governing subset"); }
        }
        budget.workspace(12 + validators.len() * 104)?;
        rtos_block::config_read_budget::steps(budget, validators.len())?;
        let subset_hash = rtos_block::ValidatorSet::calc_subset_hash_short(&validators, catchain_seqno)?;
        Ok(Self { session_id, shard, catchain_seqno, subset_hash, validators, total_weight })
    }
    pub fn for_block(&self, block_id: BlockIdExt) -> Result<PqVerificationContext> {
        if block_id.shard() != &self.shard {
            fail!("PQ block shard differs from authenticated session shard");
        }
        Ok(PqVerificationContext {
            block_id,
            session_id: self.session_id.clone(),
            catchain_seqno: self.catchain_seqno,
            subset_hash: self.subset_hash,
            total_weight: self.total_weight,
            validators: self.validators.clone(),
        })
    }
    pub fn validator_info(&self) -> rtos_block::ValidatorBaseInfo {
        rtos_block::ValidatorBaseInfo::with_params(self.subset_hash, self.catchain_seqno)
    }
}

/// Live-only notarization quorum. This type intentionally has no on-chain serialization
/// or conversion into the final-only on-chain #13 signature carrier.
#[derive(Clone, Debug)]
pub struct PqApproval {
    data: BlockSignaturesSimplexPq,
}
impl PqApproval {
    /// The field layout shares resource bounds with #13; its signature role is
    /// always Notarize, independently of how these untrusted bytes were obtained.
    pub fn from_notarization_fields(data: BlockSignaturesSimplexPq) -> Result<Self> {
        data.serialize()?;
        Ok(Self { data })
    }
    pub fn session_id(&self) -> &UInt256 {
        &self.data.session_id
    }
    pub fn slot(&self) -> u32 {
        self.data.slot
    }
}

#[derive(Debug)]
pub struct VerifiedPqApproval {
    block_id: BlockIdExt,
    session_id: UInt256,
    slot: u32,
    weight: u64,
}
impl VerifiedPqApproval {
    pub fn block_id(&self) -> &BlockIdExt {
        &self.block_id
    }
    pub fn session_id(&self) -> &UInt256 {
        &self.session_id
    }
    pub fn slot(&self) -> u32 {
        self.slot
    }
    pub fn weight(&self) -> u64 {
        self.weight
    }
}

/// A verified final signature quorum under a particular supplied context.
/// This is not, by itself, an authenticated chain or a fully validated block.
#[derive(Debug)]
pub struct VerifiedPqSignatures {
    block_id: BlockIdExt,
    session_id: UInt256,
    slot: u32,
    weight: u64,
}

impl VerifiedPqSignatures {
    pub fn block_id(&self) -> &BlockIdExt {
        &self.block_id
    }
    pub fn session_id(&self) -> &UInt256 {
        &self.session_id
    }
    pub fn slot(&self) -> u32 {
        self.slot
    }
    pub fn weight(&self) -> u64 {
        self.weight
    }
}

impl PqVerificationContext {
    /// The intrinsic global ID and config must belong to the same authenticated
    /// governing state/key block. Target coordinates must come from the target
    /// block header, whose root is subsequently covered by the certificate.
    pub fn from_governing_config(
        global_id: i32,
        config: &ConfigParams,
        block_id: BlockIdExt,
        vertical_seqno: u32,
        previous_key_block_seqno: u32,
        catchain_seqno: u32,
    ) -> Result<Self> {
        Self::from_governing_validator_set(
            global_id,
            config,
            config.validator_set()?,
            block_id,
            vertical_seqno,
            previous_key_block_seqno,
            catchain_seqno,
        )
    }

    /// The caller must independently authorize next-set use (e.g. the trusted
    /// top-shard-descriptor validation mode). The carrier cannot enable it.
    pub fn from_governing_next_validator_set(
        global_id: i32,
        config: &ConfigParams,
        block_id: BlockIdExt,
        vertical_seqno: u32,
        previous_key_block_seqno: u32,
        catchain_seqno: u32,
    ) -> Result<Self> {
        Self::from_governing_validator_set(
            global_id,
            config,
            config.next_validator_set()?,
            block_id,
            vertical_seqno,
            previous_key_block_seqno,
            catchain_seqno,
        )
    }

    fn from_governing_validator_set(
        global_id: i32,
        config: &ConfigParams,
        set: rtos_block::ValidatorSet,
        block_id: BlockIdExt,
        vertical_seqno: u32,
        previous_key_block_seqno: u32,
        catchain_seqno: u32,
    ) -> Result<Self> {
        match config.config(19)? {
            Some(ConfigParamEnum::ConfigParam19(id)) if id == global_id as u32 => {}
            _ => fail!("PQ governing global_id disagrees with missing or mismatched Param19"),
        }
        rtos_block::validate_validator_list(set.list())?;
        let (validators, subset_hash) = set.calc_subset(
            &config.catchain_config()?,
            block_id.shard().shard_prefix_with_tag(),
            block_id.shard().workchain_id(),
            catchain_seqno,
        )?;
        if validators.iter().any(|v| !matches!(v.key, ValidatorKey::Pq(_))) {
            fail!("PQ finality requires an entirely PQ governing subset");
        }
        let identity = derive_session_from_config(
            global_id,
            config,
            SessionCoordinates {
                shard: block_id.shard(),
                catchain_seqno,
                vertical_seqno,
                last_key_block_seqno: previous_key_block_seqno,
                new_catchain_ids: false,
            },
            &validators,
        )?;
        let total_weight = checked_validator_weight_sum(validators.iter().map(|v| v.weight))?;
        Ok(Self {
            block_id,
            session_id: identity.session_id,
            catchain_seqno,
            subset_hash,
            total_weight,
            validators,
        })
    }

    pub fn expected_session_id(&self) -> &UInt256 {
        &self.session_id
    }
    pub fn subset_hash(&self) -> u32 {
        self.subset_hash
    }

    /// Verify a persisted #13 carrier, which can only represent final votes.
    /// All supplied signers are checked, including weight beyond the threshold.
    pub fn verify_final(&self, carrier: &BlockSignaturesSimplexPq) -> Result<VerifiedPqSignatures> {
        let weight = self.verify_role(carrier, true)?;
        Ok(VerifiedPqSignatures {
            block_id: self.block_id.clone(),
            session_id: self.session_id.clone(),
            slot: carrier.slot,
            weight,
        })
    }

    pub fn verify_approval(&self, approval: &PqApproval) -> Result<VerifiedPqApproval> {
        if self.block_id.shard().is_masterchain() {
            fail!("masterchain requires final votes");
        }
        let weight = self.verify_role(&approval.data, false)?;
        Ok(VerifiedPqApproval {
            block_id: self.block_id.clone(),
            session_id: self.session_id.clone(),
            slot: approval.data.slot,
            weight,
        })
    }

    fn verify_role(&self, carrier: &BlockSignaturesSimplexPq, is_final: bool) -> Result<u64> {
        // Public carrier fields may have been built manually, bypassing decoding.
        // Serialization enforces all structural/resource limits in that case too.
        carrier.serialize()?;
        if carrier.validator_info.catchain_seqno != self.catchain_seqno {
            fail!("PQ catchain seqno mismatch");
        }
        if carrier.validator_info.validator_list_hash_short != self.subset_hash {
            fail!("PQ validator subset hash mismatch");
        }
        if carrier.session_id != self.session_id {
            fail!("PQ carried session differs from governing expected session");
        }
        let message = vote_preimage(&self.block_id, carrier, is_final)?;
        let mut members = HashMap::new();
        let mut weights = Vec::with_capacity(self.validators.len());
        for member in &self.validators {
            let ValidatorKey::Pq(key) = &member.key else { fail!("PQ member required") };
            let id = member.validator_id()?;
            weights.push(PqBlockValidatorWeight {
                validator_id: id.clone(),
                algorithm_id: key.algorithm_id,
                weight: member.weight,
            });
            members.insert(id, key);
        }
        let weight = carrier.check_structural_membership_and_weight(&weights)?;
        for signature in &carrier.signatures {
            let key =
                members.get(&signature.validator_id).ok_or_else(|| error!("PQ unknown signer"))?;
            if !rtos_pq_crypto::verify_simplex(&message, &signature.signature, &key.public_key)? {
                fail!("PQ invalid final signature from {}", signature.validator_id);
            }
        }
        if !has_quorum(weight, self.total_weight) {
            fail!("PQ insufficient verified weight: {weight} of {}", self.total_weight);
        }
        Ok(weight)
    }
}

/// Canonical final-vote preimage. Candidate bytes are bounded and strictly
/// decoded; their complete embedded block ID must equal the expected target.
pub fn final_vote_preimage(
    block_id: &BlockIdExt,
    carrier: &BlockSignaturesSimplexPq,
) -> Result<Vec<u8>> {
    vote_preimage(block_id, carrier, true)
}

pub fn approval_vote_preimage(block_id: &BlockIdExt, approval: &PqApproval) -> Result<Vec<u8>> {
    vote_preimage(block_id, &approval.data, false)
}

fn vote_preimage(
    block_id: &BlockIdExt,
    carrier: &BlockSignaturesSimplexPq,
    is_final: bool,
) -> Result<Vec<u8>> {
    use crate::ton::consensus::{
        candidateid::CandidateId,
        datatosign::DataToSign,
        simplex::unsignedvote::{FinalizeVote, NotarizeVote},
    };
    let bytes = carrier.candidate_bytes()?;
    let mut input = Cursor::new(bytes.as_slice());
    let candidate = crate::Deserializer::new(&mut input)
        .read_boxed::<crate::ton::consensus::CandidateHashData>()?;
    if input.position() as usize != bytes.len() {
        fail!("PQ candidate trailing TL data");
    }
    if candidate.block() != block_id {
        fail!("PQ candidate block id mismatch");
    }
    let canonical = crate::serialize_boxed(&candidate)?;
    if canonical != bytes {
        fail!("PQ candidate encoding is not canonical");
    }
    let id = CandidateId { slot: carrier.slot as i32, hash: UInt256::calc_file_hash(&canonical) }
        .into_boxed();
    let vote = if is_final {
        crate::serialize_boxed(&FinalizeVote { id }.into_boxed())?
    } else {
        crate::serialize_boxed(&NotarizeVote { id }.into_boxed())?
    };
    crate::serialize_boxed(
        &DataToSign { session_id: carrier.session_id.clone(), data: vote }.into_boxed(),
    )
}
