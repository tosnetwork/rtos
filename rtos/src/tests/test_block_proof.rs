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
fn test_reject_legacy_master_blocks_proof() {
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

        // Historical fixtures use the old validator-set commitment. Target
        // V2 must reject it; block's legacy subset tests separately verify the
        // original member selection and cryptographic signatures.
        assert!(block_proof
            .check_with_prev_key_block_proof(&key_block_proof)
            .unwrap_err()
            .to_string()
            .contains("Bad validator set hash"));
    }
}

#[test]
fn test_reject_legacy_master_blocks_proof_shuffle() {
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

        // Historical fixtures use the old validator-set commitment. Target
        // V2 must reject it; block's legacy subset tests separately verify the
        // original member selection and cryptographic signatures.
        assert!(block_proof
            .check_with_prev_key_block_proof(&key_block_proof)
            .unwrap_err()
            .to_string()
            .contains("Bad validator set hash"));
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

#[tokio::test]
async fn test_pq_proof_verifies_with_governing_state_and_key_block() {
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
    key_proof.check_trusted_checkpoint(key_proof.id()).unwrap();
    let handles = crate::collator_test_bundle::create_block_handle_storage(None).unwrap();
    let cached_handle = handles
        .create_handle(pq_fixture::block_id(), storage::types::BlockMeta::default(), None)
        .unwrap()
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
        let engine = CachedProofEngine { handle: cached_handle.clone(), proof: proof.clone() };
        let history =
            super::BootstrapAuthority::from_checkpoint(key_proof.id(), key_proof.clone()).unwrap();
        let cached =
            crate::boot::download_and_check_key_block_proof(&engine, proof.id(), &history).await;
        // This fixture is an ordinary block: even its valid final certificate
        // must not promote it to a governing key-block authority.
        assert!(cached.unwrap_err().to_string().contains("replacement download reached"));
        let boot_result = history.authenticate_block(proof.id(), proof.clone());
        assert_eq!(boot_result.is_ok(), mutation == 0, "boot mutation {mutation}: {boot_result:?}");
        let mut different_id = proof.id().clone();
        different_id.file_hash = UInt256::default();
        assert!(history
            .authenticate_block(&different_id, proof.clone())
            .unwrap_err()
            .to_string()
            .contains("requested block identity"));
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

struct CachedProofEngine {
    handle: std::sync::Arc<storage::block_handle_db::BlockHandle>,
    proof: BlockProofStuff,
}

#[async_trait::async_trait]
impl crate::engine_traits::EngineOperations for CachedProofEngine {
    fn load_block_handle(
        &self,
        _: &rtos_block::BlockIdExt,
    ) -> rtos_block::Result<Option<std::sync::Arc<storage::block_handle_db::BlockHandle>>> {
        Ok(Some(self.handle.clone()))
    }
    async fn load_block_proof(
        &self,
        _: &std::sync::Arc<storage::block_handle_db::BlockHandle>,
        _: bool,
    ) -> rtos_block::Result<BlockProofStuff> {
        Ok(self.proof.clone())
    }
    fn check_stop(&self) -> bool {
        false
    }
    async fn download_block_proof(
        &self,
        _: &rtos_block::BlockIdExt,
        _: bool,
        _: bool,
    ) -> rtos_block::Result<BlockProofStuff> {
        rtos_block::fail!("replacement download reached")
    }
}

#[tokio::test]
async fn test_cold_boot_checkpoint_checks_cached_contents_against_local_pin() {
    use rtos_block::*;
    for mutation in 0..5 {
        let handles = crate::collator_test_bundle::create_block_handle_storage(None).unwrap();
        let mut info = BlockInfo::default();
        info.set_seq_no(10).unwrap();
        info.set_shard(ShardIdent::masterchain());
        info.set_key_block(mutation != 2);
        info.set_gen_utime(900);
        let mut custom = McBlockExtra::default();
        custom.set_config(pq_fixture::config());
        let mut extra = BlockExtra::default();
        extra.write_custom(&custom).unwrap();
        let block = Block::with_params(
            if mutation == 3 { 0 } else { -239 },
            info,
            ValueFlow::default(),
            MerkleUpdate::default(),
            extra,
        )
        .unwrap();
        let root = block.serialize().unwrap();
        let id = BlockIdExt::with_params(
            ShardIdent::masterchain(),
            10,
            root.repr_hash().clone(),
            UInt256::calc_file_hash(&write_boc(&root).unwrap()),
        );
        let proof = BlockProofStuff::new(
            BlockProof::with_params(
                id.clone(),
                if mutation == 4 {
                    Cell::default()
                } else {
                    MerkleProof::create(&root, |_| true).unwrap().serialize().unwrap()
                },
                None,
            ),
            true,
        )
        .unwrap();
        let mut pin = id.clone();
        if mutation == 1 {
            pin.file_hash = UInt256::from([77; 32]);
        }
        // The handle claims a key block even for the non-key counterexample.
        // Its cache flags must never replace validation of actual proof content.
        let meta = storage::types::BlockMeta::for_import(900, 0, 0, true, true, false);
        let handle = handles.create_handle(pin.clone(), meta, None).unwrap().unwrap();
        let engine = CheckpointCacheEngine { pin, handle, proof };
        let result = crate::boot::run_cold(&engine).await;
        if mutation == 0 {
            let (_, zero, proof) = result.unwrap();
            assert!(zero.is_none());
            assert_eq!(proof.unwrap().id(), &id);
        } else {
            assert!(result.is_err(), "checkpoint mutation {mutation} accepted");
        }
    }
}

struct CheckpointCacheEngine {
    pin: rtos_block::BlockIdExt,
    handle: std::sync::Arc<storage::block_handle_db::BlockHandle>,
    proof: BlockProofStuff,
}
#[async_trait::async_trait]
impl crate::engine_traits::EngineOperations for CheckpointCacheEngine {
    fn init_mc_block_id(&self) -> &rtos_block::BlockIdExt {
        &self.pin
    }
    fn get_last_fork_masterchain_seqno(&self) -> u32 {
        0
    }
    fn load_block_handle(
        &self,
        _: &rtos_block::BlockIdExt,
    ) -> rtos_block::Result<Option<std::sync::Arc<storage::block_handle_db::BlockHandle>>> {
        Ok(Some(self.handle.clone()))
    }
    async fn load_block_proof(
        &self,
        _: &std::sync::Arc<storage::block_handle_db::BlockHandle>,
        _: bool,
    ) -> rtos_block::Result<BlockProofStuff> {
        Ok(self.proof.clone())
    }
}

fn bootstrap_fixture_proof(
    row: &serde_json::Value,
    signed: bool,
    corrupt: bool,
) -> BlockProofStuff {
    use rtos_block::*;
    let bytes = hex::decode(row["block_boc"].as_str().unwrap()).unwrap();
    let root = read_single_root_boc(&bytes).unwrap();
    let block = Block::construct_from_cell(root.clone()).unwrap();
    let info = block.read_info().unwrap();
    let id = BlockIdExt::with_params(
        info.shard().clone(),
        info.seq_no(),
        root.repr_hash().clone(),
        UInt256::calc_file_hash(&bytes),
    );
    let signatures = signed.then(|| {
        let mut signature = hex::decode(row["signature"].as_str().unwrap()).unwrap();
        if corrupt {
            signature[0] ^= 1;
        }
        BlockSignaturesVariant::SimplexPq(BlockSignaturesSimplexPq {
            validator_info: ValidatorBaseInfo::with_params(
                row["subset_hash"].as_u64().unwrap() as u32,
                7,
            ),
            session_id: UInt256::from_slice(
                &hex::decode(row["session"].as_str().unwrap()).unwrap(),
            ),
            slot: row["slot"].as_u64().unwrap() as u32,
            candidate_data: BlockSignaturesSimplex::bytes_to_cell_tree(
                &hex::decode(row["candidate"].as_str().unwrap()).unwrap(),
            )
            .unwrap(),
            sig_count: 1,
            sig_weight: 2,
            signatures: vec![PqBlockSignaturePair {
                validator_id: UInt256::from([2; 32]),
                algorithm_id: 1,
                signature,
            }],
        })
    });
    BlockProofStuff::new(
        BlockProof::with_params(
            id,
            MerkleProof::create(&root, |_| true).unwrap().serialize().unwrap(),
            signatures,
        ),
        !signed,
    )
    .unwrap()
}

#[tokio::test]
async fn test_bootstrap_authority_authenticates_successive_key_blocks() {
    use super::BootstrapAuthority;
    let data: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tl/rtos_api/tests/data/bootstrap-history.json"
    ))
    .unwrap();
    let row = |name: &str| {
        data["cases"].as_array().unwrap().iter().find(|row| row["name"] == name).unwrap()
    };
    let anchor =
        bootstrap_fixture_proof(&serde_json::json!({"block_boc":data["anchor_boc"]}), false, false);
    let history = BootstrapAuthority::from_checkpoint(anchor.id(), anchor.clone()).unwrap();
    let first = bootstrap_fixture_proof(row("first"), true, false);
    let second = bootstrap_fixture_proof(row("second"), true, false);
    let next = history.advance_key_block(first.id(), first.clone()).unwrap();
    assert_eq!(next.id(), first.id());
    assert_eq!(next.anchor(), anchor.id());
    let last = next.advance_key_block(second.id(), second.clone()).unwrap();
    assert_eq!(last.id(), second.id());
    assert_eq!(last.anchor(), anchor.id());
    assert!(
        history.advance_key_block(second.id(), second.clone()).is_err(),
        "skipped governing epoch accepted"
    );
    assert!(next.advance_key_block(first.id(), first.clone()).is_err(), "replay accepted");
    let corrupt = bootstrap_fixture_proof(row("first"), true, true);
    assert!(
        history.advance_key_block(corrupt.id(), corrupt.clone()).is_err(),
        "corrupt signature accepted"
    );
    assert_eq!(history.id(), anchor.id());
    let bad_config = bootstrap_fixture_proof(row("bad-next-config"), true, false);
    history.authenticate_block(bad_config.id(), bad_config.clone()).unwrap();
    assert!(
        history.advance_key_block(bad_config.id(), bad_config.clone()).is_err(),
        "invalid governing configuration promoted"
    );

    // Exercise the real cached-proof consumer, including a valid key-block hit.
    let handles = crate::collator_test_bundle::create_block_handle_storage(None).unwrap();
    let meta = storage::types::BlockMeta::for_import(942, 0, 0, true, true, false);
    let handle = handles.create_handle(first.id().clone(), meta, None).unwrap().unwrap();
    let engine = CachedProofEngine { handle: handle.clone(), proof: first.clone() };
    let (_, cached) =
        crate::boot::download_and_check_key_block_proof(&engine, first.id(), &history)
            .await
            .unwrap();
    assert_eq!(cached.id(), first.id());
    assert_eq!(cached.anchor(), anchor.id());
    let engine = CachedProofEngine { handle, proof: corrupt };
    assert!(crate::boot::download_and_check_key_block_proof(&engine, first.id(), &history)
        .await
        .unwrap_err()
        .to_string()
        .contains("replacement download reached"));
}

#[test]
fn test_bootstrap_authority_starts_from_pinned_zerostate() {
    use super::BootstrapAuthority;
    use rtos_block::*;
    let data: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tl/rtos_api/tests/data/bootstrap-history.json"
    ))
    .unwrap();
    let row = data["cases"].as_array().unwrap().iter().find(|r| r["name"] == "from-zero").unwrap();
    for wrong_global in [false, true] {
        let mut state = ShardStateUnsplit::default();
        state.set_global_id(if wrong_global { 0 } else { -239 });
        state.set_shard(ShardIdent::masterchain());
        let mut custom = McStateExtra::default();
        custom.config = pq_fixture::config();
        state.write_custom(Some(&custom)).unwrap();
        let root = state.serialize().unwrap();
        let bytes = write_boc(&root).unwrap();
        let pin = BlockIdExt::with_params(
            ShardIdent::masterchain(),
            0,
            root.repr_hash().clone(),
            UInt256::calc_file_hash(&bytes),
        );
        let zero = crate::shard_state::ShardStateStuff::deserialize_zerostate(
            pin.clone(),
            &bytes,
            #[cfg(feature = "telemetry")]
            &crate::collator_test_bundle::create_engine_telemetry(),
            &crate::collator_test_bundle::create_engine_allocated(),
        )
        .unwrap();
        let result = BootstrapAuthority::from_zerostate(&pin, zero.clone());
        if wrong_global {
            assert!(result.is_err());
            continue;
        }
        let history = result.unwrap();
        let proof = bootstrap_fixture_proof(row, true, false);
        let next = history.advance_key_block(proof.id(), proof.clone()).unwrap();
        assert_eq!(next.id(), proof.id());
        assert_eq!(next.anchor(), &pin);
        let mut wrong_pin = pin;
        wrong_pin.file_hash = UInt256::from([77; 32]);
        assert!(BootstrapAuthority::from_zerostate(&wrong_pin, zero).is_err());
    }
}
