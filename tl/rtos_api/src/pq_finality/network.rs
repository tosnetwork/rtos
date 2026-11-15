// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Unverified network evidence has no persisted weight or final-proof authority.
//! Only an independently constructed governing context can grant either role.
use super::*;
use crate::{ton, WireProfile};
use rtos_block::{
    BlockSignaturesSimplex, PqBlockSignaturePair, ValidatorBaseInfo, MLDSA44_ALGORITHM_ID,
    PQ_SIGNATURE_BYTES, PQ_SIGNATURE_MAX_SIGNERS,
};
use std::collections::HashSet;

#[derive(Clone, Debug)]
pub struct PqNetworkSignatureSet {
    is_final: bool,
    validator_info: ValidatorBaseInfo,
    signatures: Vec<PqBlockSignaturePair>,
    session_id: UInt256,
    slot: u32,
    candidate: ton::consensus::CandidateHashData,
}

impl PqNetworkSignatureSet {
    fn checked_pair(
        validator_id: UInt256,
        algorithm_id: i32,
        signature: Vec<u8>,
    ) -> Result<PqBlockSignaturePair> {
        let algorithm_id =
            u16::try_from(algorithm_id).map_err(|_| error!("PQ network algorithm out of range"))?;
        if algorithm_id != MLDSA44_ALGORITHM_ID {
            fail!("PQ network unsupported algorithm");
        }
        if signature.len() != PQ_SIGNATURE_BYTES {
            fail!("PQ network signature length");
        }
        Ok(PqBlockSignaturePair { validator_id, algorithm_id, signature })
    }

    pub fn from_node(value: ton::ton_node::signature_set::signatureset::SimplexPq) -> Result<Self> {
        if value.signatures.len() > PQ_SIGNATURE_MAX_SIGNERS as usize {
            fail!("PQ network signer count exceeds maximum");
        }
        let mut signatures = Vec::with_capacity(value.signatures.len());
        for pair in value.signatures {
            signatures.push(Self::checked_pair(
                pair.validator_id,
                pair.algorithm_id,
                pair.signature,
            )?);
        }
        let result = Self {
            is_final: matches!(value.final_, ton::Bool::BoolTrue),
            validator_info: ValidatorBaseInfo::with_params(
                value.validator_set_hash as u32,
                value.cc_seqno as u32,
            ),
            signatures,
            session_id: value.session_id,
            slot: value.slot as u32,
            candidate: value.candidate,
        };
        result.validate_structure()?;
        Ok(result)
    }

    pub fn from_node_bounded(
        value: ton::ton_node::signature_set::signatureset::SimplexPq,
        budget: &dyn ConfigReadBudget,
    ) -> Result<Self> {
        if value.signatures.len() > PQ_SIGNATURE_MAX_SIGNERS as usize {
            fail!("PQ network signer count exceeds maximum");
        }
        let mut signatures = cb::vector(budget, value.signatures.len())?;
        for pair in value.signatures {
            budget.step()?;
            signatures.push(Self::checked_pair(
                pair.validator_id,
                pair.algorithm_id,
                pair.signature,
            )?);
        }
        let result = Self {
            is_final: matches!(value.final_, ton::Bool::BoolTrue),
            validator_info: ValidatorBaseInfo::with_params(
                value.validator_set_hash as u32,
                value.cc_seqno as u32,
            ),
            signatures,
            session_id: value.session_id,
            slot: value.slot as u32,
            candidate: value.candidate,
        };
        result.validate_structure_bounded(budget)?;
        Ok(result)
    }

    fn validate_structure_bounded(&self, budget: &dyn ConfigReadBudget) -> Result<()> {
        if self.signatures.len() > PQ_SIGNATURE_MAX_SIGNERS as usize {
            fail!("PQ network signer count exceeds maximum");
        }
        for (index, pair) in self.signatures.iter().enumerate() {
            budget.step()?;
            if pair.algorithm_id != MLDSA44_ALGORITHM_ID {
                fail!("PQ network unsupported algorithm");
            }
            if pair.signature.len() != PQ_SIGNATURE_BYTES {
                fail!("PQ network signature length");
            }
            for previous in &self.signatures[..index] {
                budget.step()?;
                if previous.validator_id == pair.validator_id {
                    fail!("PQ network duplicate validator identity");
                }
            }
        }
        if serialize_budgeted(&self.candidate, budget)?.len() > 1024 {
            fail!("PQ network candidate exceeds maximum");
        }
        Ok(())
    }

    pub fn from_lite(
        value: ton::lite_server::signature_set::signatureset::SimplexPq,
    ) -> Result<Self> {
        if value.signatures.len() > PQ_SIGNATURE_MAX_SIGNERS as usize {
            fail!("PQ network signer count exceeds maximum");
        }
        let signatures = value
            .signatures
            .into_iter()
            .map(|pair| Self::checked_pair(pair.validator_id, pair.algorithm_id, pair.signature))
            .collect::<Result<Vec<_>>>()?;
        Self::validate_signatures(&signatures)?;
        if value.candidate.len() > 1024 {
            fail!("PQ network candidate exceeds maximum");
        }
        let candidate = WireProfile::T0.deserialize_typed(&value.candidate)?;
        let result = Self {
            is_final: true,
            validator_info: ValidatorBaseInfo::with_params(
                value.validator_set_hash as u32,
                value.cc_seqno as u32,
            ),
            signatures,
            session_id: value.session_id,
            slot: value.slot as u32,
            candidate,
        };
        result.validate_structure()?;
        Ok(result)
    }

    /// Prepare outgoing final fields; this is structural validation, not authentication.
    pub fn from_final_fields(value: &BlockSignaturesSimplexPq) -> Result<Self> {
        value.serialize()?;
        let result = Self {
            is_final: true,
            validator_info: value.validator_info.clone(),
            signatures: value.signatures.clone(),
            session_id: value.session_id.clone(),
            slot: value.slot,
            candidate: WireProfile::T0.deserialize_typed(&value.candidate_bytes()?)?,
        };
        result.validate_structure()?;
        Ok(result)
    }

    pub fn from_approval(value: &PqApproval) -> Result<Self> {
        let mut result = Self::from_final_fields(&value.data)?;
        result.is_final = false;
        Ok(result)
    }

    fn validate_structure(&self) -> Result<()> {
        Self::validate_signatures(&self.signatures)?;
        if WireProfile::T0.serialize(&self.candidate)?.len() > 1024 {
            fail!("PQ network candidate exceeds maximum");
        }
        Ok(())
    }

    fn validate_signatures(signatures: &[PqBlockSignaturePair]) -> Result<()> {
        if signatures.len() > PQ_SIGNATURE_MAX_SIGNERS as usize {
            fail!("PQ network signer count exceeds maximum");
        }
        let mut ids = HashSet::new();
        for pair in signatures {
            if pair.algorithm_id != MLDSA44_ALGORITHM_ID {
                fail!("PQ network unsupported algorithm");
            }
            if pair.signature.len() != PQ_SIGNATURE_BYTES {
                fail!("PQ network signature length");
            }
            if !ids.insert(&pair.validator_id) {
                fail!("PQ network duplicate validator identity");
            }
        }
        Ok(())
    }

    pub fn to_node(&self) -> ton::ton_node::signature_set::signatureset::SimplexPq {
        ton::ton_node::signature_set::signatureset::SimplexPq {
            final_: if self.is_final { ton::Bool::BoolTrue } else { ton::Bool::BoolFalse },
            cc_seqno: self.validator_info.catchain_seqno as i32,
            validator_set_hash: self.validator_info.validator_list_hash_short as i32,
            signatures: self
                .signatures
                .iter()
                .map(|pair| ton::ton_node::pqblocksignature::PqBlockSignature {
                    validator_id: pair.validator_id.clone(),
                    algorithm_id: i32::from(pair.algorithm_id),
                    signature: pair.signature.clone(),
                })
                .collect(),
            session_id: self.session_id.clone(),
            slot: self.slot as i32,
            candidate: self.candidate.clone(),
        }
    }

    pub fn to_lite(&self) -> Result<ton::lite_server::signature_set::signatureset::SimplexPq> {
        if !self.is_final {
            fail!("PQ approval cannot become a final-only LiteServer proof carrier");
        }
        Ok(ton::lite_server::signature_set::signatureset::SimplexPq {
            cc_seqno: self.validator_info.catchain_seqno as i32,
            validator_set_hash: self.validator_info.validator_list_hash_short as i32,
            signatures: self
                .signatures
                .iter()
                .map(|pair| ton::lite_server::pqsignature::PqSignature {
                    validator_id: pair.validator_id.clone(),
                    algorithm_id: i32::from(pair.algorithm_id),
                    signature: pair.signature.clone(),
                })
                .collect(),
            session_id: self.session_id.clone(),
            slot: self.slot as i32,
            candidate: WireProfile::T0.serialize(&self.candidate)?,
        })
    }

    pub fn is_final(&self) -> bool {
        self.is_final
    }
    pub fn validator_info(&self) -> &ValidatorBaseInfo {
        &self.validator_info
    }
    pub fn block_id(&self) -> &BlockIdExt {
        self.candidate.block()
    }
    pub fn session_id(&self) -> &UInt256 {
        &self.session_id
    }
    pub fn slot(&self) -> u32 {
        self.slot
    }
}

#[derive(Debug)]
enum VerifiedNetworkRole {
    Final(BlockSignaturesSimplexPq, VerifiedPqSignatures),
    Approval(PqApproval, VerifiedPqApproval),
}

/// Private association prevents pairing a verified token with different unverified fields.
#[derive(Debug)]
pub struct VerifiedPqNetworkSignatures {
    evidence: VerifiedNetworkRole,
}
impl VerifiedPqNetworkSignatures {
    pub fn is_final(&self) -> bool {
        matches!(self.evidence, VerifiedNetworkRole::Final(..))
    }
    pub fn into_final(self) -> Result<(BlockSignaturesSimplexPq, VerifiedPqSignatures)> {
        match self.evidence {
            VerifiedNetworkRole::Final(carrier, verified) => Ok((carrier, verified)),
            VerifiedNetworkRole::Approval(..) => fail!("PQ approval has no final proof authority"),
        }
    }
    pub fn into_approval(self) -> Result<(PqApproval, VerifiedPqApproval)> {
        match self.evidence {
            VerifiedNetworkRole::Approval(carrier, verified) => Ok((carrier, verified)),
            VerifiedNetworkRole::Final(..) => fail!("PQ final evidence is not a notarization"),
        }
    }
}

impl PqVerificationContext {
    pub fn verify_network(
        &self,
        input: &PqNetworkSignatureSet,
    ) -> Result<VerifiedPqNetworkSignatures> {
        input.validate_structure()?;
        let members: HashMap<_, _> = self
            .validators
            .iter()
            .map(|member| Ok((member.validator_id()?, member)))
            .collect::<Result<_>>()?;
        let weights = input
            .signatures
            .iter()
            .map(|pair| {
                members
                    .get(&pair.validator_id)
                    .map(|member| member.weight)
                    .ok_or_else(|| error!("PQ network signer is not in governing context"))
            })
            .collect::<Result<Vec<_>>>()?;
        let weight = checked_validator_weight_sum(weights)?;
        // Weight comes only from this governing context, never from wire metadata.
        let carrier = BlockSignaturesSimplexPq {
            validator_info: input.validator_info.clone(),
            sig_count: input.signatures.len() as u32,
            sig_weight: weight,
            signatures: input.signatures.clone(),
            session_id: input.session_id.clone(),
            slot: input.slot,
            candidate_data: BlockSignaturesSimplex::bytes_to_cell_tree(
                &WireProfile::T0.serialize(&input.candidate)?,
            )?,
        };
        let evidence = if input.is_final {
            let verified = self.verify_final(&carrier)?;
            VerifiedNetworkRole::Final(carrier, verified)
        } else {
            let approval = PqApproval::from_notarization_fields(carrier)?;
            let verified = self.verify_approval(&approval)?;
            VerifiedNetworkRole::Approval(approval, verified)
        };
        Ok(VerifiedPqNetworkSignatures { evidence })
    }
}

impl PqVerificationContext {
    pub fn verify_network_bounded(
        &self,
        input: &PqNetworkSignatureSet,
        budget: &dyn ConfigReadBudget,
    ) -> Result<VerifiedPqNetworkSignatures> {
        input.validate_structure_bounded(budget)?;
        let mut members = cb::vector(budget, self.validators.len())?;
        for member in &self.validators {
            budget.step()?;
            members.push((member.validator_id_bounded(budget)?, member.weight));
        }
        let mut weight = 0;
        for pair in &input.signatures {
            let mut found = None;
            for (id, value) in &members {
                budget.step()?;
                if id == &pair.validator_id {
                    found = Some(*value);
                    break;
                }
            }
            weight = rtos_block::checked_add_validator_weight(
                weight,
                found.ok_or_else(|| error!("PQ network signer is not in governing context"))?,
            )?;
        }
        let mut signatures = cb::vector(budget, input.signatures.len())?;
        for signature in &input.signatures {
            budget.step()?;
            budget.workspace(signature.signature.len())?;
            signatures.push(signature.clone());
        }
        let candidate = serialize_budgeted(&input.candidate, budget)?;
        let carrier = BlockSignaturesSimplexPq {
            validator_info: input.validator_info.clone(),
            sig_count: signatures.len() as u32,
            sig_weight: weight,
            signatures,
            session_id: input.session_id.clone(),
            slot: input.slot,
            candidate_data: BlockSignaturesSimplex::bytes_to_cell_tree_bounded(&candidate, budget)?,
        };
        let evidence = if input.is_final {
            let verified = self.verify_final_bounded(&carrier, budget)?;
            VerifiedNetworkRole::Final(carrier, verified)
        } else {
            if self.block_id.shard().is_masterchain() {
                fail!("masterchain requires final votes");
            }
            // Same structural/role verification as the ordinary approval path.
            let weight = self.verify_role_bounded(&carrier, false, budget)?;
            let verified = VerifiedPqApproval {
                block_id: self.block_id.clone(),
                session_id: self.session_id.clone(),
                slot: carrier.slot,
                weight,
            };
            VerifiedNetworkRole::Approval(PqApproval { data: carrier }, verified)
        };
        Ok(VerifiedPqNetworkSignatures { evidence })
    }
}
