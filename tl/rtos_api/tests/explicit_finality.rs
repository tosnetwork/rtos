// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
#[path = "common/pq_finality.rs"]
mod fixture;
use rtos_api::pq_finality::*;
use rtos_block::*;

fn context(validators: Vec<ValidatorDescr>, block: &BlockIdExt) -> ExplicitPqFinalityContext {
    ExplicitPqFinalityContext::new(
        validators,
        7,
        ExplicitFinalityBlock {
            workchain: block.shard().workchain_id(),
            shard: block.shard().shard_prefix_with_tag(),
            seqno: block.seq_no(),
            root_hash: block.root_hash.clone(),
            file_hash: block.file_hash.clone(),
        },
        fixture::context(&fixture::config()).expected_session_id().clone(),
    )
    .unwrap()
}
fn evidence(carrier: &BlockSignaturesSimplexPq) -> ExplicitPqSignatureSet {
    ExplicitPqSignatureSet::new(
        carrier.validator_info.clone(),
        carrier.session_id.clone(),
        carrier.slot,
        carrier.candidate_bytes().unwrap(),
        carrier.signatures.clone(),
        true,
    )
    .unwrap()
}
fn reason(error: anyhow::Error) -> &'static str {
    error.downcast_ref::<FinalityRefusal>().unwrap().0
}

#[test]
fn final_claim_is_checked_after_every_signature() {
    let ctx =
        context(fixture::config().validator_set().unwrap().list().to_vec(), &fixture::block_id());
    let mut carrier = fixture::signed(&[1], "finalize", "TOS-CONSENSUS-SIMPLEX-v1");
    assert_eq!(ctx.verify(&evidence(&carrier), true, None).unwrap(), 2);
    assert_eq!(
        reason(ctx.verify(&evidence(&carrier), true, Some(0)).unwrap_err()),
        "claimed_weight_mismatch"
    );
    carrier.signatures[0].signature[0] ^= 1;
    assert_eq!(
        reason(ctx.verify(&evidence(&carrier), true, Some(0)).unwrap_err()),
        "invalid_signature"
    );
    let mut carrier = fixture::signed(&[1, 0], "finalize", "TOS-CONSENSUS-SIMPLEX-v1");
    carrier.signatures[1].signature[0] ^= 1;
    assert_eq!(
        reason(ctx.verify(&evidence(&carrier), true, None).unwrap_err()),
        "invalid_signature"
    );
}

#[test]
fn only_signed_keys_are_verified_at_the_explicit_boundary() {
    let mut validators = fixture::config().validator_set().unwrap().list().to_vec();
    let ValidatorKey::Pq(key) = &mut validators[0].key else { unreachable!() };
    key.key_id = UInt256::default();
    // This supplied set is unsuitable for production admission, but its
    // unsigned key does not change the message signed by member1.
    assert!(PqSessionContext::from_authenticated_session_members(
        UInt256::default(),
        ShardIdent::masterchain(),
        7,
        validators.clone(),
    )
    .is_err());
    let mut carrier = fixture::signed(&[1], "finalize", "TOS-CONSENSUS-SIMPLEX-v1");
    carrier.validator_info.validator_list_hash_short =
        ValidatorSet::calc_subset_hash_short(&validators, 7).unwrap();
    let ctx = context(validators, &fixture::block_id());
    assert_eq!(ctx.verify(&evidence(&carrier), true, None).unwrap(), 2);
}

#[test]
fn raw_coordinates_do_not_admit_a_governing_set() {
    let validators = fixture::config().validator_set().unwrap().list().to_vec();
    assert!(ShardIdent::with_tagged_prefix(-1, 1).is_err());
    let hash = ValidatorSet::calc_subset_hash_short(&validators, 7).unwrap();
    let mut carrier = fixture::unsigned(&fixture::context(&fixture::config()));
    let mut candidate = carrier.candidate_bytes().unwrap();
    candidate[8..16].copy_from_slice(&1u64.to_le_bytes());
    carrier.candidate_data = BlockSignaturesSimplex::bytes_to_cell_tree(&candidate).unwrap();
    carrier.validator_info.validator_list_hash_short = hash;
    let id = fixture::block_id();
    let ctx = ExplicitPqFinalityContext::new(
        validators,
        7,
        ExplicitFinalityBlock {
            workchain: -1,
            shard: 1,
            seqno: id.seq_no(),
            root_hash: id.root_hash,
            file_hash: id.file_hash,
        },
        carrier.session_id.clone(),
    )
    .unwrap();
    assert_eq!(
        reason(ctx.verify(&evidence(&carrier), true, Some(0)).unwrap_err()),
        "insufficient_weight"
    );
}
