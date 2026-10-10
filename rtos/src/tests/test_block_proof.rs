/*
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::{block::BlockStuff, block_proof::BlockProofStuff};

#[path = "../../../tl/rtos_api/tests/common/pq_finality.rs"]
mod pq_fixture;

#[test]
fn test_check_master_blocks_proof() {
    let name = "src/tests/static/test_master_block_proof/key_block__3082181";
    let key_block = BlockStuff::read_block_from_file(name).unwrap();

    let bytes =
        std::fs::read("src/tests/static/test_master_block_proof/key_proof__3082181").unwrap();
    let key_block_proof = BlockProofStuff::deserialize(key_block.id(), bytes, false).unwrap();

    for seqno in 3082182..=3082200 {
        let name = format!("src/tests/static/test_master_block_proof/block__{}", seqno);
        let block = BlockStuff::read_block_from_file(&name).unwrap();

        let name = format!("src/tests/static/test_master_block_proof/proof__{}", seqno);
        let bytes = std::fs::read(&name).unwrap();
        let block_proof = BlockProofStuff::deserialize(block.id(), bytes, false).unwrap();

        block_proof.check_with_prev_key_block_proof(&key_block_proof).unwrap();
    }
}

#[test]
fn test_check_master_blocks_proof_shuffle() {
    let name = "src/tests/static/test_master_block_proof_shuffle/key_block__3236530";
    let key_block = BlockStuff::read_block_from_file(name).unwrap();

    let bytes =
        std::fs::read("src/tests/static/test_master_block_proof_shuffle/key_proof__3236530")
            .unwrap();
    let key_block_proof = BlockProofStuff::deserialize(key_block.id(), bytes, false).unwrap();

    for seqno in 3236531..=3236550 {
        let name = format!("src/tests/static/test_master_block_proof_shuffle/block__{}", seqno);
        let block = BlockStuff::read_block_from_file(&name).unwrap();

        let bytes = std::fs::read(format!(
            "src/tests/static/test_master_block_proof_shuffle/proof__{}",
            seqno
        ))
        .unwrap();
        let block_proof = BlockProofStuff::deserialize(block.id(), bytes, false).unwrap();

        block_proof.check_with_prev_key_block_proof(&key_block_proof).unwrap();
    }
}

#[test]
fn test_proof_signature_quorum_weighted_boundary() {
    use crate::validator::validator_utils::ValidatorSubsetInfo;
    use rtos_block::{
        Block, BlockIdExt, BlockProof, BlockSignatures, BlockSignaturesPure, Cell, CryptoSignature,
        CryptoSignaturePair, Ed25519KeyOption, ShardIdent, SigPubKey, UInt256, ValidatorBaseInfo,
        ValidatorDescr, ZeroizingBytes,
    };
    let keys: Vec<_> =
        (0..3).map(|_| Ed25519KeyOption::<ZeroizingBytes>::generate().unwrap()).collect();
    let validators: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            ValidatorDescr::with_params(
                SigPubKey::from_bytes(key.pub_key().unwrap()).unwrap(),
                (i + 1) as u64,
                None,
            )
        })
        .collect();
    let subset = ValidatorSubsetInfo { validators, short_hash: 42 };
    let id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        1,
        UInt256::from([1; 32]),
        UInt256::from([2; 32]),
    );
    let data = Block::build_data_for_sign(&id.root_hash, &id.file_hash);
    for (signers, accepted) in [(vec![0, 2], true), (vec![0, 1], false), (vec![0, 0, 2], false)] {
        let mut signatures = BlockSignaturesPure::default();
        let mut weight = 0;
        for i in signers {
            signatures.add_sigpair(CryptoSignaturePair {
                node_id_short: subset.validators[i].compute_node_id_short().unwrap(),
                sign: CryptoSignature::from_bytes(&keys[i].sign(&data).unwrap()).unwrap(),
            });
            weight += subset.validators[i].weight;
        }
        signatures.set_weight(weight);
        let proof = BlockProof::with_ordinary_signatures(
            id.clone(),
            Cell::default(),
            Some(BlockSignatures::with_params(ValidatorBaseInfo::with_params(42, 0), signatures)),
        );
        let proof = BlockProofStuff::new(proof, false).unwrap();
        assert_eq!(
            proof.check_signatures(&subset).is_ok(),
            accepted,
            "signed weight {weight} of 6"
        );
    }
}

#[test]
fn test_pq_proof_requires_authenticated_finality_context() {
    use crate::validator::validator_utils::ValidatorSubsetInfo;
    use rtos_block::{BlockProof, BlockSignaturesVariant, Cell, Deserializable};

    // Structurally valid reference payload; its patterned signature is not a
    // cryptographic certificate. Decoding must not authorize a node proof.
    let row = include_str!("../../../block/tests/data/pq-block-signature-vectors.txt")
        .lines()
        .find(|line| line.starts_with("valid-1\t"))
        .unwrap();
    let fields: Vec<_> = row.split('\t').collect();
    let signatures =
        BlockSignaturesVariant::construct_from_bytes(&hex::decode(fields[4]).unwrap()).unwrap();
    let subset = ValidatorSubsetInfo {
        validators: vec![],
        short_hash: signatures.validator_info().validator_list_hash_short,
    };
    let proof = BlockProofStuff::new(
        BlockProof::with_params(
            rtos_block::BlockIdExt::with_params(
                rtos_block::ShardIdent::masterchain(),
                1,
                Default::default(),
                Default::default(),
            ),
            Cell::default(),
            Some(signatures.clone()),
        ),
        false,
    )
    .unwrap();
    let error = proof.check_signatures(&subset).unwrap_err();
    assert!(error.to_string().contains("no CryptoSignature view"), "{error}");
    let error = crate::validating_utils::build_checked_data(&signatures, proof.id()).unwrap_err();
    assert!(error.to_string().contains("trusted governing session context"), "{error}");
}

#[test]
fn test_pq_proof_verifies_with_governing_state_and_key_block() {
    use rtos_block::*;
    let config = pq_fixture::config();
    let mut state = ShardStateUnsplit::default();
    state.set_global_id(-239);
    state.set_shard(ShardIdent::masterchain());
    state.set_seq_no(10);
    let mut state_extra = McStateExtra::default();
    state_extra.config = config.clone();
    state_extra.after_key_block = true;
    state.write_custom(Some(&state_extra)).unwrap();
    let state_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        10,
        UInt256::default(),
        UInt256::default(),
    );
    let master = crate::shard_state::ShardStateStuff::from_state(
        state_id,
        state,
        #[cfg(feature = "telemetry")]
        &crate::collator_test_bundle::create_engine_telemetry(),
        &crate::collator_test_bundle::create_engine_allocated(),
    )
    .unwrap();

    // The test explicitly supplies this synthetic governing key block as its
    // trusted input. This does not exercise authentication from a network anchor.
    let mut info = BlockInfo::default();
    info.set_seq_no(10).unwrap();
    info.set_shard(ShardIdent::masterchain());
    info.set_key_block(true);
    info.set_gen_utime(900);
    let mut extra = BlockExtra::default();
    let mut custom = McBlockExtra::default();
    custom.set_config(config);
    extra.write_custom(&custom).unwrap();
    let key = Block::with_params(-239, info, ValueFlow::default(), MerkleUpdate::default(), extra)
        .unwrap();
    let key_root = key.serialize().unwrap();
    let key_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        10,
        key_root.repr_hash().clone(),
        UInt256::calc_file_hash(&write_boc(&key_root).unwrap()),
    );
    let key_proof = BlockProofStuff::new(
        BlockProof::with_params(
            key_id,
            MerkleProof::create(&key_root, |_| true).unwrap().serialize().unwrap(),
            None,
        ),
        false,
    )
    .unwrap();
    let root = pq_fixture::target_block().serialize().unwrap();
    let merkle = MerkleProof::create(&root, |_| true).unwrap().serialize().unwrap();
    for mutation in 0..4 {
        let mut carrier = pq_fixture::signed(&[1], "finalize", "TOS-CONSENSUS-SIMPLEX-v1");
        match mutation {
            1 => carrier.signatures[0].signature[0] ^= 1,
            2 => carrier.session_id = UInt256::default(),
            3 => carrier = pq_fixture::signed(&[1], "notarize", "TOS-CONSENSUS-SIMPLEX-v1"),
            _ => {}
        }
        let proof = BlockProofStuff::new(
            BlockProof::with_params(
                pq_fixture::block_id(),
                merkle.clone(),
                Some(BlockSignaturesVariant::SimplexPq(carrier)),
            ),
            false,
        )
        .unwrap();
        let state_result = proof.check_with_master_state(&master);
        let key_result = proof.check_with_prev_key_block_proof(&key_proof);
        assert_eq!(
            state_result.is_ok(),
            mutation == 0,
            "state mutation {mutation}: {state_result:?}"
        );
        assert_eq!(key_result.is_ok(), mutation == 0, "key mutation {mutation}: {key_result:?}");
    }
}

#[test]
fn test_pq_proof_refuses_later_governing_epoch_even_with_same_keys() {
    use rtos_block::*;
    let mut state = ShardStateUnsplit::default();
    state.set_global_id(-239);
    state.set_shard(ShardIdent::masterchain());
    state.set_seq_no(11);
    let mut extra = McStateExtra::default();
    extra.config = pq_fixture::config();
    extra.after_key_block = true;
    state.write_custom(Some(&extra)).unwrap();
    let master = crate::shard_state::ShardStateStuff::from_state(
        BlockIdExt::with_params(
            ShardIdent::masterchain(),
            11,
            UInt256::default(),
            UInt256::default(),
        ),
        state,
        #[cfg(feature = "telemetry")]
        &crate::collator_test_bundle::create_engine_telemetry(),
        &crate::collator_test_bundle::create_engine_allocated(),
    )
    .unwrap();
    let root = pq_fixture::target_block().serialize().unwrap();
    let carrier = pq_fixture::signed(&[1], "finalize", "TOS-CONSENSUS-SIMPLEX-v1");
    let proof = BlockProofStuff::new(
        BlockProof::with_params(
            pq_fixture::block_id(),
            MerkleProof::create(&root, |_| true).unwrap().serialize().unwrap(),
            Some(BlockSignaturesVariant::SimplexPq(carrier)),
        ),
        false,
    )
    .unwrap();
    assert!(proof
        .check_with_master_state(&master)
        .unwrap_err()
        .to_string()
        .contains("different key-block epoch"));
}
