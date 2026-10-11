// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Historical authentication of recovery data. No acceptance, publication or storage writes.
//! The existing history resolver may download missing governing proofs. Its owner
//! must supply normal timeout/cancellation/drain handling; missing history is retriable.
//! Candidate effects here are post-certificate replay. Pre-quorum CandidateReceived
//! needs independent leader/candidate/collated evidence and is not represented.
use crate::{
    block::{construct_and_check_prev_stuff, BlockStuff},
    block_proof::{MasterchainProofVerifier, PqPublicationContext},
    engine_traits::EngineOperations,
    propagation_outbox::{validate_recovery_record, Limits, UnverifiedRecord},
};
use rtos_api::{
    pq_finality::{PqNetworkSignatureSet, VerifiedPqNetworkSignatures},
    ton::ton_node::SignatureSet,
    WireProfile,
};
use rtos_block::{fail, Result};
use std::sync::Arc;

/// Constructible only after authenticating history, block bytes and carrier.
/// This receipt proves neither execution validity nor masterchain inclusion.
/// Private immutable fields keep the verified objects bound to each other.
pub(crate) struct AuthenticatedPublication {
    entry: UnverifiedRecord,
    block: BlockStuff,
    context: PqPublicationContext,
    carrier: VerifiedPqNetworkSignatures,
}
impl AuthenticatedPublication {
    pub(crate) fn entry(&self) -> &UnverifiedRecord {
        &self.entry
    }
    pub(crate) fn block(&self) -> &BlockStuff {
        &self.block
    }
    pub(crate) fn context(&self) -> &PqPublicationContext {
        &self.context
    }
    /// Consumes the receipt. Changing the returned data does not create another
    /// authenticated publication; acceptance must preserve/recheck its binding.
    pub(crate) fn into_parts(
        self,
    ) -> (UnverifiedRecord, BlockStuff, PqPublicationContext, VerifiedPqNetworkSignatures) {
        (self.entry, self.block, self.context, self.carrier)
    }
}

pub(crate) async fn authenticate_publication<E: EngineOperations + ?Sized>(
    history: &MasterchainProofVerifier,
    engine: &E,
    entry: UnverifiedRecord,
    limits: &Limits,
) -> Result<AuthenticatedPublication> {
    validate_recovery_record(&entry, limits)?;
    let record = &entry.record;
    if record.domain.zerostate != *engine.zerostate_id()?
        || record.domain.wire_profile != WireProfile::T0
        || record.domain.wire_profile != engine.validator_network().wire_profile()
    {
        fail!("Publication network pin or wire profile differs from this Engine");
    }
    let block = BlockStuff::deserialize_block_checked(
        record.block_id.clone(),
        Arc::new(record.block_data.clone()),
    )?;
    block.verify_expected_id(&record.block_id)?;
    if block.block()?.global_id() != record.domain.global_id {
        fail!("Publication block global ID differs from its record");
    }
    let (_, previous) = construct_and_check_prev_stuff(block.root_cell(), block.id(), false)?;
    if previous.prev != record.prev {
        fail!("Publication previous blocks differ from its authenticated body");
    }
    // Neither proof_data nor Prepared/Ready nor routing metadata grants authority.
    // This walks the same pinned history as normal masterchain proof verification.
    let context = history.pq_publication_context(engine, block.id(), block.block()?).await?;
    if context.zerostate() != &record.domain.zerostate
        || context.global_id() != record.domain.global_id
        || context.protocol() != record.protocol
        || context.profile() != &record.profile
        || context.verifier().expected_session_id() != &record.session_id
    {
        fail!("Publication policy differs from authenticated governing history");
    }
    let encoded = record.carrier.bytes();
    let wire: SignatureSet = WireProfile::T0.deserialize_typed(encoded)?;
    if WireProfile::T0.serialize(&wire)? != encoded {
        fail!("Noncanonical publication signature carrier");
    }
    let SignatureSet::TonNode_SignatureSet_SimplexPq(fields) = wire else {
        fail!("Publication recovery requires a PQ network carrier");
    };
    let carrier = context.verifier().verify_network(&PqNetworkSignatureSet::from_node(fields)?)?;
    if carrier.is_final() != record.carrier.is_final() {
        fail!("Publication carrier role differs from its stored tag");
    }
    Ok(AuthenticatedPublication { entry, block, context, carrier })
}

#[cfg(test)]
#[path = "tests/test_propagation_outbox_auth.rs"]
mod tests;
