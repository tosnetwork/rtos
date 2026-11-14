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
    checked_validator_weight_sum,
    config_read_budget::{self as cb, ConfigReadBudget},
    error, fail, has_quorum, BlockIdExt, BlockSignaturesSimplexPq, ConfigParamEnum, ConfigParams,
    PqBlockValidatorWeight, Result, Serializable, UInt256, ValidatorDescr, ValidatorKey,
};
use std::{collections::HashMap, io::Cursor};

/// Count and admit each TL write before an exact output allocation. Preserve
/// the original budget error (including its typed cause) across the IO adapter.
fn serialize_budgeted<T: crate::BoxedSerialize>(
    value: &T,
    budget: &dyn ConfigReadBudget,
) -> Result<Vec<u8>> {
    struct Count<'a> {
        budget: &'a dyn ConfigReadBudget,
        length: usize,
        writes: usize,
        error: Option<anyhow::Error>,
    }
    impl std::io::Write for Count<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if let Err(error) = self.budget.step() {
                self.error = Some(error);
                return Err(std::io::Error::other("TL budget refused"));
            }
            self.length = self
                .length
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("TL length overflow"))?;
            self.writes += 1;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count { budget, length: 0, writes: 0, error: None };
    let counted = crate::Serializer::new(&mut count).write_boxed(value);
    if let Some(error) = count.error {
        return Err(error);
    }
    counted?;
    cb::steps(budget, count.writes)?;
    let mut output = cb::vector(budget, count.length)?;
    crate::Serializer::new(&mut output).write_boxed(value)?;
    Ok(output)
}

mod network;
pub use network::{PqNetworkSignatureSet, VerifiedPqNetworkSignatures};
mod explicit;
pub use explicit::{
    ExplicitFinalityBlock, ExplicitPqFinalityContext, ExplicitPqSignatureSet, FinalityRefusal,
};

// Shared by admitted on-chain finality and explicit verification contexts.
// All signers are checked, including signatures after a sufficient quorum.
fn verify_all_signatures(
    message: &[u8],
    signatures: &[rtos_block::PqBlockSignaturePair],
    members: &HashMap<UInt256, &rtos_block::PqConsensusKey>,
) -> Result<()> {
    for signature in signatures {
        let key =
            members.get(&signature.validator_id).ok_or_else(|| error!("PQ unknown signer"))?;
        if !rtos_pq_crypto::verify_simplex(message, &signature.signature, &key.public_key)? {
            fail!("PQ invalid final signature from {}", signature.validator_id);
        }
    }
    Ok(())
}

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
        session_id: UInt256,
        shard: rtos_block::ShardIdent,
        catchain_seqno: u32,
        validators: Vec<ValidatorDescr>,
        budget: &dyn rtos_block::config_read_budget::ConfigReadBudget,
    ) -> Result<Self> {
        let total_weight =
            rtos_block::validators::validate_validator_list_bounded(&validators, budget)?;
        for v in &validators {
            budget.step()?;
            if !matches!(v.key, ValidatorKey::Pq(_)) {
                fail!("PQ session requires an entirely PQ governing subset");
            }
        }
        budget.workspace(12 + validators.len() * 104)?;
        rtos_block::config_read_budget::steps(budget, validators.len())?;
        let subset_hash =
            rtos_block::ValidatorSet::calc_subset_hash_short(&validators, catchain_seqno)?;
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
    pub fn for_block_bounded(
        &self,
        block_id: BlockIdExt,
        budget: &dyn ConfigReadBudget,
    ) -> Result<PqVerificationContext> {
        if block_id.shard() != &self.shard {
            fail!("PQ block shard differs from authenticated session shard");
        }
        let mut validators = cb::vector(budget, self.validators.len())?;
        for validator in &self.validators {
            validators.push(validator.clone_bounded(budget)?);
        }
        Ok(PqVerificationContext {
            block_id,
            session_id: self.session_id.clone(),
            catchain_seqno: self.catchain_seqno,
            subset_hash: self.subset_hash,
            total_weight: self.total_weight,
            validators,
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

    /// Same governing inputs as the ordinary path; unused previous/next sets
    /// are not decoded. The caller retains ownership of this cumulative budget.
    pub fn from_governing_config_bounded(
        global_id: i32,
        config: &ConfigParams,
        block_id: BlockIdExt,
        vertical_seqno: u32,
        previous_key_block_seqno: u32,
        catchain_seqno: u32,
        budget: &dyn ConfigReadBudget,
    ) -> Result<Self> {
        let decoded =
            config.governing_session_config_bounded(block_id.shard().is_masterchain(), budget)?;
        cb::lookup(budget, 32)?;
        match config.config(19)? {
            Some(ConfigParamEnum::ConfigParam19(id)) if id == global_id as u32 => {}
            _ => fail!("PQ governing global_id disagrees with missing or mismatched Param19"),
        }
        rtos_block::validators::validate_validator_list_bounded(decoded.current.list(), budget)?;
        let (validators, subset_hash) = decoded.current.calc_subset_bounded(
            &decoded.catchain,
            block_id.shard().shard_prefix_with_tag(),
            block_id.shard().workchain_id(),
            catchain_seqno,
            budget,
        )?;
        for validator in &validators {
            budget.step()?;
            if !matches!(validator.key, ValidatorKey::Pq(_)) {
                fail!("PQ finality requires an entirely PQ governing subset");
            }
        }
        let identity = crate::session_identity::derive_session_from_decoded_bounded(
            global_id,
            &decoded,
            SessionCoordinates {
                shard: block_id.shard(),
                catchain_seqno,
                vertical_seqno,
                last_key_block_seqno: previous_key_block_seqno,
                new_catchain_ids: false,
            },
            &validators,
            budget,
        )?;
        cb::steps(budget, validators.len())?;
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

    pub fn verify_final_bounded(
        &self,
        carrier: &BlockSignaturesSimplexPq,
        budget: &dyn ConfigReadBudget,
    ) -> Result<VerifiedPqSignatures> {
        let weight = self.verify_role_bounded(carrier, true, budget)?;
        Ok(VerifiedPqSignatures {
            block_id: self.block_id.clone(),
            session_id: self.session_id.clone(),
            slot: carrier.slot,
            weight,
        })
    }

    fn verify_role_bounded(
        &self,
        carrier: &BlockSignaturesSimplexPq,
        is_final: bool,
        budget: &dyn ConfigReadBudget,
    ) -> Result<u64> {
        carrier.validate_structure_bounded(budget)?;
        if carrier.validator_info.catchain_seqno != self.catchain_seqno {
            fail!("PQ catchain seqno mismatch");
        }
        if carrier.validator_info.validator_list_hash_short != self.subset_hash {
            fail!("PQ validator subset hash mismatch");
        }
        if carrier.session_id != self.session_id {
            fail!("PQ carried session differs from governing expected session");
        }
        let message = vote_preimage_with_budget(&self.block_id, carrier, is_final, Some(budget))?;
        let mut members = cb::vector(budget, self.validators.len())?;
        let mut weights = cb::vector(budget, self.validators.len())?;
        for member in &self.validators {
            budget.step()?;
            let ValidatorKey::Pq(key) = &member.key else { fail!("PQ member required") };
            let id = member.validator_id_bounded(budget)?;
            weights.push(PqBlockValidatorWeight {
                validator_id: id.clone(),
                algorithm_id: key.algorithm_id,
                weight: member.weight,
            });
            members.push((id, key));
        }
        let weight = carrier.check_structural_membership_and_weight_bounded(&weights, budget)?;
        for signature in &carrier.signatures {
            let mut found = None;
            for (id, key) in &members {
                budget.step()?;
                if id == &signature.validator_id {
                    found = Some(*key);
                    break;
                }
            }
            let key = found.ok_or_else(|| error!("PQ unknown signer"))?;
            // One admission per complete fixed-parameter ML-DSA-44 verification.
            // The backend borrows exact-width key/signature slices and has no
            // input-sized Rust allocations. Every supplied signer is verified.
            budget.step()?;
            if !rtos_pq_crypto::verify_simplex(&message, &signature.signature, &key.public_key)? {
                fail!("PQ invalid final signature from {}", signature.validator_id);
            }
        }
        if !has_quorum(weight, self.total_weight) {
            fail!("PQ insufficient verified weight: {weight} of {}", self.total_weight);
        }
        Ok(weight)
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
        verify_all_signatures(&message, &carrier.signatures, &members)?;
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
    vote_preimage_with_budget(block_id, carrier, is_final, None)
}
/// Explicit candidate wire data. Raw block coordinates carry no chain authority.
pub struct SimplexVoteData {
    pub workchain: i32,
    pub shard: u64,
    pub seqno: u32,
    pub root_hash: UInt256,
    pub file_hash: UInt256,
    pub candidate_hash: UInt256,
    pub data_to_sign: Vec<u8>,
}

/// Build the native Simplex signing preimage from canonical TL candidate bytes.
/// This structural primitive neither checks membership nor admits a shard.
pub fn build_simplex_vote_data(
    session_id: &UInt256,
    slot: u32,
    candidate: &[u8],
    is_final: bool,
) -> Result<SimplexVoteData> {
    rtos_block::signature::validate_candidate_tl(candidate)?;
    let mut input = candidate;
    let mut de = crate::Deserializer::new(&mut input);
    let _tag = de.read_bare::<i32>()?;
    let workchain = de.read_bare::<i32>()?;
    let shard = de.read_bare::<i64>()? as u64;
    let seqno = de.read_bare::<i32>()? as u32;
    let root_hash = de.read_bare::<UInt256>()?;
    let file_hash = de.read_bare::<UInt256>()?;
    let candidate_hash = UInt256::calc_file_hash(candidate);
    let data_to_sign = encode_vote_preimage(session_id, slot, &candidate_hash, is_final, None)?;
    Ok(SimplexVoteData {
        workchain,
        shard,
        seqno,
        root_hash,
        file_hash,
        candidate_hash,
        data_to_sign,
    })
}

/// Bind structural signing data to a supplied raw block identity. This does not
/// authenticate the block or admit its coordinates as a governing shard.
pub fn build_simplex_vote_data_for_block(
    session_id: &UInt256,
    slot: u32,
    candidate: &[u8],
    is_final: bool,
    block: &ExplicitFinalityBlock,
) -> Result<SimplexVoteData> {
    let vote = build_simplex_vote_data(session_id, slot, candidate, is_final)
        .map_err(|_| FinalityRefusal("candidate_malformed"))?;
    if (vote.workchain, vote.shard, vote.seqno) != (block.workchain, block.shard, block.seqno)
        || vote.root_hash != block.root_hash
        || vote.file_hash != block.file_hash
    {
        return Err(FinalityRefusal("block_mismatch").into());
    }
    Ok(vote)
}

fn vote_preimage_with_budget(
    block_id: &BlockIdExt,
    carrier: &BlockSignaturesSimplexPq,
    is_final: bool,
    budget: Option<&dyn ConfigReadBudget>,
) -> Result<Vec<u8>> {
    let bytes = match budget {
        Some(budget) => carrier.candidate_bytes_bounded(budget)?,
        None => carrier.candidate_bytes()?,
    };
    let mut input = Cursor::new(bytes.as_slice());
    let candidate = crate::Deserializer::new(&mut input)
        .read_boxed::<crate::ton::consensus::CandidateHashData>()?;
    if input.position() as usize != bytes.len() {
        fail!("PQ candidate trailing TL data");
    }
    if candidate.block() != block_id {
        fail!("PQ candidate block id mismatch");
    }
    let encode_candidate = |budget: Option<&dyn ConfigReadBudget>| match budget {
        Some(budget) => serialize_budgeted(&candidate, budget),
        None => crate::serialize_boxed(&candidate),
    };
    let canonical = encode_candidate(budget)?;
    if canonical != bytes {
        fail!("PQ candidate encoding is not canonical");
    }
    encode_vote_preimage(
        &carrier.session_id,
        carrier.slot,
        &UInt256::calc_file_hash(&canonical),
        is_final,
        budget,
    )
}

fn encode_vote_preimage(
    session_id: &UInt256,
    slot: u32,
    candidate_hash: &UInt256,
    is_final: bool,
    budget: Option<&dyn ConfigReadBudget>,
) -> Result<Vec<u8>> {
    use crate::ton::consensus::{
        candidateid::CandidateId,
        datatosign::DataToSign,
        simplex::unsignedvote::{FinalizeVote, NotarizeVote},
    };
    let id = CandidateId { slot: slot as i32, hash: candidate_hash.clone() }.into_boxed();
    let vote = if is_final {
        let vote = FinalizeVote { id }.into_boxed();
        match budget {
            Some(budget) => serialize_budgeted(&vote, budget)?,
            None => crate::serialize_boxed(&vote)?,
        }
    } else {
        let vote = NotarizeVote { id }.into_boxed();
        match budget {
            Some(budget) => serialize_budgeted(&vote, budget)?,
            None => crate::serialize_boxed(&vote)?,
        }
    };
    let data = DataToSign { session_id: session_id.clone(), data: vote }.into_boxed();
    match budget {
        Some(budget) => serialize_budgeted(&data, budget),
        None => crate::serialize_boxed(&data),
    }
}
