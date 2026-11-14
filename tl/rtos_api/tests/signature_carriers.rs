// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
#[path = "common/pq_finality.rs"]
mod fixture;
use rtos_api::pq_finality::*;
use rtos_block::*;

#[test]
fn expected_signing_block_checks_all_raw_fields_and_candidate_first() {
    let carrier = fixture::unsigned(&fixture::context(&fixture::config()));
    let candidate = carrier.candidate_bytes().unwrap();
    let id = fixture::block_id();
    let block = ExplicitFinalityBlock {
        workchain: -1,
        shard: 1u64 << 63,
        seqno: id.seq_no(),
        root_hash: id.root_hash,
        file_hash: id.file_hash,
    };
    for field in 0..5 {
        let mut different = block.clone();
        match field {
            0 => different.workchain += 1,
            1 => different.shard ^= 1,
            2 => different.seqno += 1,
            3 => different.root_hash = UInt256::default(),
            _ => different.file_hash = UInt256::default(),
        }
        let error = build_simplex_vote_data_for_block(
            &carrier.session_id,
            carrier.slot,
            &candidate,
            true,
            &different,
        )
        .err()
        .unwrap();
        assert_eq!(error.downcast_ref::<FinalityRefusal>().unwrap().0, "block_mismatch");
        let error = build_simplex_vote_data_for_block(
            &carrier.session_id,
            carrier.slot,
            &[],
            true,
            &different,
        )
        .err()
        .unwrap();
        assert_eq!(error.downcast_ref::<FinalityRefusal>().unwrap().0, "candidate_malformed");
    }
    let mut raw = candidate;
    raw[8..16].copy_from_slice(&1u64.to_le_bytes());
    let mut raw_block = block;
    raw_block.shard = 1;
    assert!(ShardIdent::with_tagged_prefix(-1, 1).is_err());
    assert!(build_simplex_vote_data_for_block(
        &carrier.session_id,
        u32::MAX,
        &raw,
        false,
        &raw_block
    )
    .is_ok());
}

#[test]
fn descriptor_fetch_checks_context_then_signed_key_before_claimed_weight() {
    let validators = fixture::config().validator_set().unwrap().list().to_vec();
    let mut carrier = fixture::signed(&[1], "finalize", "TOS-CONSENSUS-SIMPLEX-v1");
    // Structural parsing never claims cryptographic verification.
    carrier.signatures[0].signature[0] ^= 1;
    let encode = |v: &BlockSignaturesSimplexPq| write_boc(&v.serialize().unwrap()).unwrap();
    assert!(BlockSignaturesSimplexPq::construct_from_pq_boc_with_validator_set(
        &encode(&carrier),
        &validators,
        7
    )
    .is_ok());
    assert_eq!(
        BlockSignaturesSimplexPq::construct_from_pq_boc_with_validator_set(
            &encode(&carrier),
            &validators,
            8
        )
        .unwrap_err()
        .to_string(),
        "catchain seqno mismatch"
    );
    let mut wrong = carrier.clone();
    wrong.validator_info.validator_list_hash_short ^= 1;
    assert_eq!(
        BlockSignaturesSimplexPq::construct_from_pq_boc_with_validator_set(
            &encode(&wrong),
            &validators,
            7
        )
        .unwrap_err()
        .to_string(),
        "validator set hash mismatch"
    );
    let mut members = validators.clone();
    let ValidatorKey::Pq(unsigned) = &mut members[0].key else { unreachable!() };
    unsigned.public_key.clear();
    unsigned.key_id = UInt256::default();
    carrier.validator_info.validator_list_hash_short =
        ValidatorSet::calc_subset_hash_short(&members, 7).unwrap();
    assert!(
        BlockSignaturesSimplexPq::construct_from_pq_boc_with_validator_set(
            &encode(&carrier),
            &members,
            7
        )
        .is_ok(),
        "unused public key is opaque"
    );
    let ValidatorKey::Pq(signed) = &mut members[1].key else { unreachable!() };
    signed.key_id = UInt256::from([98; 32]);
    carrier.sig_weight = 0;
    carrier.validator_info.validator_list_hash_short =
        ValidatorSet::calc_subset_hash_short(&members, 7).unwrap();
    assert_eq!(
        BlockSignaturesSimplexPq::construct_from_pq_boc_with_validator_set(
            &encode(&carrier),
            &members,
            7
        )
        .unwrap_err()
        .to_string(),
        "validator key_id mismatch"
    );
    let ValidatorKey::Pq(signed) = &mut members[1].key else { unreachable!() };
    signed.public_key.clear();
    assert_eq!(
        BlockSignaturesSimplexPq::construct_from_pq_boc_with_validator_set(
            &encode(&carrier),
            &members,
            7
        )
        .unwrap_err()
        .to_string(),
        "malformed validator public key"
    );
}

#[test]
fn pq_profile_refuses_wrong_tag_before_malformed_body() {
    let validators = fixture::config().validator_set().unwrap().list().to_vec();
    for tag in [0x11, 0x12] {
        let root = BuilderData::with_raw(vec![tag], 8).unwrap().into_cell().unwrap();
        let error = BlockSignaturesSimplexPq::construct_from_pq_boc_with_validator_set(
            &write_boc(&root).unwrap(),
            &validators,
            7,
        )
        .unwrap_err();
        assert_eq!(
            pq_block_signature_reason_code(&error),
            Some(PqBlockSignatureReasonCode::UnsupportedCarrier)
        );
    }
}
