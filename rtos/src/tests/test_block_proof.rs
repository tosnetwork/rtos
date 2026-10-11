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

#[tokio::test]
async fn test_warm_recovery_authenticates_history_before_saving_cursor() {
    use rtos_block::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let chain: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tl/rtos_api/tests/data/bootstrap-history.json"
    ))
    .unwrap();
    let row: serde_json::Value =
        serde_json::from_str(include_str!("../../../tl/rtos_api/tests/data/warm-history.json"))
            .unwrap();
    for mutation in 0..13 {
        let anchor = bootstrap_fixture_proof(
            &serde_json::json!({"block_boc":chain["anchor_boc"]}),
            false,
            false,
        );
        let first = bootstrap_fixture_proof(&chain["cases"][1], true, mutation == 1);
        let second = bootstrap_fixture_proof(&chain["cases"][2], true, false);
        let mut target = bootstrap_fixture_proof(&row, true, mutation == 2);
        if mutation == 12 {
            let (block, root) = target.virtualize_block().unwrap();
            let excluded = block.read_state_update().unwrap().new_hash;
            let proof = MerkleProof::create(&root, |hash| hash != &excluded).unwrap();
            target = BlockProofStuff::new(
                BlockProof::with_params(
                    target.id().clone(),
                    proof.serialize().unwrap(),
                    target.proof.signatures.clone(),
                ),
                false,
            )
            .unwrap();
        }
        let target_id = target.id().clone();
        let mut state = ShardStateUnsplit::construct_from_bytes(
            &hex::decode(row["state_boc"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        if mutation == 3 {
            state.set_gen_time(999);
        }
        if mutation == 4 || mutation == 11 {
            let mut custom = state.read_custom().unwrap().unwrap();
            if mutation == 4 {
                custom.prev_blocks.del(&42).unwrap();
            } else {
                custom
                    .prev_blocks
                    .set(
                        &42,
                        &KeyExtBlkRef { key: true, blk_ref: ExtBlkRef::fake(0, 0) },
                        &KeyMaxLt { key: true, max_end_lt: 0 },
                    )
                    .unwrap();
            }
            state.write_custom(Some(&custom)).unwrap();
        }
        if mutation == 9 {
            state.set_seq_no(45);
        }
        let state = crate::shard_state::ShardStateStuff::from_state(
            target_id.clone(),
            state,
            #[cfg(feature = "telemetry")]
            &crate::collator_test_bundle::create_engine_telemetry(),
            &crate::collator_test_bundle::create_engine_allocated(),
        )
        .unwrap();
        let handles = crate::collator_test_bundle::create_block_handle_storage(None).unwrap();
        let pin = anchor.id().clone();
        let mut entries = Vec::new();
        for proof in [anchor, first, second, target] {
            let handle = handles
                .create_handle(proof.id().clone(), storage::types::BlockMeta::default(), None)
                .unwrap()
                .unwrap();
            handle.set_block_applied();
            entries.push((handle, proof));
        }
        let mut start = target_id.clone();
        let mut next = None;
        let mut previous = None;
        // Follow an applied successor after a crash left the saved cursor behind.
        if mutation == 0 || mutation == 6 {
            start = entries[2].0.id().clone();
            entries[2].0.set_next1();
            next = Some(if mutation == 6 { start.clone() } else { target_id.clone() });
        }
        // Backtrack over an interrupted application; reject a cyclic pointer.
        if mutation == 7 || mutation == 8 {
            start.seq_no = 45;
            start.root_hash = UInt256::from([99; 32]);
            start.file_hash = UInt256::from([98; 32]);
            let handle = handles
                .create_handle(start.clone(), storage::types::BlockMeta::default(), None)
                .unwrap()
                .unwrap();
            handle.set_state();
            handle.set_prev1();
            entries.push((handle, BlockProofStuff::fake(&start).unwrap()));
            previous = Some(if mutation == 8 { start.clone() } else { target_id.clone() });
        }
        if mutation == 5 {
            entries[0].1 = entries[1].1.clone();
        }
        if mutation == 10 {
            entries.remove(1);
        }
        let engine = RecoveryProofEngine {
            workers: Default::default(),
            pin,
            state,
            entries,
            next,
            previous,
            saves: AtomicUsize::new(0),
            stores: AtomicUsize::new(0),
            proof_reads: AtomicUsize::new(0),
            verifier: Default::default(),
        };
        let result = crate::boot::recover_warm_boot_position(&engine, &start).await;
        if mutation == 0 || mutation == 7 || mutation == 12 {
            assert_eq!(result.unwrap(), target_id, "mutation {mutation}");
            assert_eq!(engine.saves.load(Ordering::SeqCst), 1);
        } else {
            let error = result
                .expect_err(&format!("invalid recovery mutation {mutation} accepted"))
                .to_string();
            if mutation == 3 {
                assert!(error.contains("Snapshot root differs"), "{error}");
            }
            if mutation == 11 {
                assert!(error.contains("Invalid next key-block index entry"), "{error}");
            }
            println!("recovery mutation {mutation} rejected before cursor write: {error}");
            assert_eq!(
                engine.saves.load(Ordering::SeqCst),
                0,
                "unverified cursor persisted for mutation {mutation}"
            );
        }
    }
}

struct RecoveryProofEngine {
    workers: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    pin: rtos_block::BlockIdExt,
    state: std::sync::Arc<crate::shard_state::ShardStateStuff>,
    entries: Vec<(std::sync::Arc<storage::block_handle_db::BlockHandle>, BlockProofStuff)>,
    next: Option<rtos_block::BlockIdExt>,
    previous: Option<rtos_block::BlockIdExt>,
    saves: std::sync::atomic::AtomicUsize,
    stores: std::sync::atomic::AtomicUsize,
    proof_reads: std::sync::atomic::AtomicUsize,
    verifier: super::MasterchainProofVerifier,
}

#[async_trait::async_trait]
impl crate::engine_traits::EngineOperations for RecoveryProofEngine {
    fn register_service_task(
        &self,
        _name: &'static str,
        _mask: u32,
        start: Box<dyn FnOnce() -> tokio::task::JoinHandle<()> + Send>,
    ) -> rtos_block::Result<tokio::task::JoinHandle<()>> {
        // Retain the real worker independently of its observing handle. The
        // proof-only fixture joins these workers before recovering its mock Arc.
        // Shutdown behavior itself is covered by the real Engine archive tests.
        let worker = start();
        let (sent, received) = tokio::sync::oneshot::channel();
        self.workers.lock().unwrap().push(tokio::spawn(async move {
            let result = worker.await;
            let succeeded = result.is_ok();
            let _ = sent.send(result);
            assert!(succeeded, "proof fixture service worker failed");
        }));
        Ok(tokio::spawn(async move { received.await.unwrap().unwrap() }))
    }

    async fn store_block(
        &self,
        block: &BlockStuff,
    ) -> rtos_block::Result<crate::internal_db::BlockResult> {
        self.stores.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let handle = self.entries.iter().find(|(h, _)| h.id() == block.id()).unwrap().0.clone();
        Ok(crate::internal_db::BlockResult::with_status(
            handle,
            crate::internal_db::DataStatus::Updated,
        ))
    }
    async fn store_block_proof(
        &self,
        id: &rtos_block::BlockIdExt,
        _: Option<std::sync::Arc<storage::block_handle_db::BlockHandle>>,
        _: &BlockProofStuff,
    ) -> rtos_block::Result<crate::internal_db::BlockResult> {
        self.stores.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let handle = self.entries.iter().find(|(h, _)| h.id() == id).unwrap().0.clone();
        Ok(crate::internal_db::BlockResult::with_status(
            handle,
            crate::internal_db::DataStatus::Updated,
        ))
    }

    async fn check_masterchain_proof(&self, proof: &BlockProofStuff) -> rtos_block::Result<()> {
        self.verifier.verify(self, proof).await.map(|_| ())
    }
    async fn load_last_applied_mc_state_bounded(&self,
        budget: std::sync::Arc<crate::history_read_budget::HistoryReadBudget>,
    ) -> rtos_block::Result<std::sync::Arc<crate::shard_state::ShardStateStuff>> {
        // This adapter already owns the parsed fixture; production uses detached DB reads.
        budget.graph(self.state.root_cell())?;
        Ok(self.state.clone())
    }
    async fn load_last_applied_mc_state(
        &self,
    ) -> rtos_block::Result<std::sync::Arc<crate::shard_state::ShardStateStuff>> {
        Ok(self.state.clone())
    }

    fn zerostate_id(&self) -> rtos_block::Result<&rtos_block::BlockIdExt> {
        Ok(&self.pin)
    }
    async fn load_mc_zero_state(
        &self,
    ) -> rtos_block::Result<std::sync::Arc<crate::shard_state::ShardStateStuff>> {
        Ok(self.state.clone())
    }

    fn init_mc_block_id(&self) -> &rtos_block::BlockIdExt {
        &self.pin
    }
    fn check_stop(&self) -> bool {
        false
    }
    fn load_block_handle(
        &self,
        id: &rtos_block::BlockIdExt,
    ) -> rtos_block::Result<Option<std::sync::Arc<storage::block_handle_db::BlockHandle>>> {
        Ok(self.entries.iter().find(|(h, _)| h.id() == id).map(|(h, _)| h.clone()))
    }
    async fn load_block_proof(
        &self,
        handle: &std::sync::Arc<storage::block_handle_db::BlockHandle>,
        _: bool,
    ) -> rtos_block::Result<BlockProofStuff> {
        self.proof_reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.entries
            .iter()
            .find(|(h, _)| h.id() == handle.id())
            .map(|(_, p)| p.clone())
            .ok_or_else(|| rtos_block::error!("missing recovery proof"))
    }
    async fn load_block_proof_bounded(
        &self, handle: &std::sync::Arc<storage::block_handle_db::BlockHandle>, _: bool,
        budget: std::sync::Arc<crate::history_read_budget::HistoryReadBudget>,
    ) -> rtos_block::Result<BlockProofStuff> {
        self.proof_reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let proof = &self.entries.iter().find(|(h, _)| h.id() == handle.id())
            .ok_or_else(|| rtos_block::error!("missing recovery proof"))?.1;
        // Fixture objects are already parsed; account actual objects before clone.
        budget.proof(proof)?;
        Ok(proof.clone())
    }
    async fn download_block_proof(
        &self,
        id: &rtos_block::BlockIdExt,
        _: bool,
        key_block: bool,
    ) -> rtos_block::Result<BlockProofStuff> {
        if [10, 42, 43].contains(&id.seq_no) {
            assert!(key_block, "historical key proof requested through ordinary archive");
        }
        rtos_block::fail!("missing recovery proof download reached")
    }
    async fn load_state(
        &self,
        _: &rtos_block::BlockIdExt,
    ) -> rtos_block::Result<std::sync::Arc<crate::shard_state::ShardStateStuff>> {
        Ok(self.state.clone())
    }
    fn load_block_next1(
        &self,
        _: &rtos_block::BlockIdExt,
    ) -> rtos_block::Result<rtos_block::BlockIdExt> {
        Ok(self.next.clone().unwrap())
    }
    fn load_block_prev1(
        &self,
        _: &rtos_block::BlockIdExt,
    ) -> rtos_block::Result<rtos_block::BlockIdExt> {
        Ok(self.previous.clone().unwrap())
    }
    fn save_last_applied_mc_block_id(&self, id: &rtos_block::BlockIdExt) -> rtos_block::Result<()> {
        assert_eq!(id, self.state.block_id());
        self.saves.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn test_warm_recovery_accepts_pinned_states_only_with_matching_roots() {
    use rtos_block::*;
    for zerostate in [false, true] {
        for corrupt in [false, true] {
            let mut state = ShardStateUnsplit::default();
            state.set_global_id(-239);
            state.set_shard(ShardIdent::masterchain());
            if !zerostate {
                state.set_seq_no(10);
            }
            let mut custom = McStateExtra::default();
            custom.config = pq_fixture::config();
            state.write_custom(Some(&custom)).unwrap();
            let root = state.serialize().unwrap();
            let (pin, proof) = if zerostate {
                let pin = BlockIdExt::with_params(
                    ShardIdent::masterchain(),
                    0,
                    root.repr_hash().clone(),
                    UInt256::calc_file_hash(&write_boc(&root).unwrap()),
                );
                (pin.clone(), BlockProofStuff::fake(&pin).unwrap())
            } else {
                let mut info = BlockInfo::default();
                info.set_seq_no(10).unwrap();
                info.set_shard(ShardIdent::masterchain());
                info.set_key_block(true);
                info.set_gen_utime(900);
                let mut extra = BlockExtra::default();
                let mut mc = McBlockExtra::default();
                mc.set_config(custom.config);
                extra.write_custom(&mc).unwrap();
                let block = Block::with_params(
                    -239,
                    info,
                    ValueFlow::default(),
                    MerkleUpdate::create(&Cell::default(), &root).unwrap(),
                    extra,
                )
                .unwrap();
                let root = block.serialize().unwrap();
                let pin = BlockIdExt::with_params(
                    ShardIdent::masterchain(),
                    10,
                    root.repr_hash().clone(),
                    UInt256::calc_file_hash(&write_boc(&root).unwrap()),
                );
                let proof = BlockProofStuff::new(
                    BlockProof::with_params(
                        pin.clone(),
                        MerkleProof::create(&root, |_| true).unwrap().serialize().unwrap(),
                        None,
                    ),
                    true,
                )
                .unwrap();
                (pin, proof)
            };
            if corrupt {
                state.set_gen_time(777);
            }
            let state = crate::shard_state::ShardStateStuff::from_state(
                pin.clone(),
                state,
                #[cfg(feature = "telemetry")]
                &crate::collator_test_bundle::create_engine_telemetry(),
                &crate::collator_test_bundle::create_engine_allocated(),
            )
            .unwrap();
            let handles = crate::collator_test_bundle::create_block_handle_storage(None).unwrap();
            let handle = handles
                .create_handle(pin.clone(), storage::types::BlockMeta::default(), None)
                .unwrap()
                .unwrap();
            handle.set_block_applied();
            let engine = RecoveryProofEngine {
                workers: Default::default(),
                pin: pin.clone(),
                state,
                entries: vec![(handle, proof)],
                next: None,
                previous: None,
                saves: std::sync::atomic::AtomicUsize::new(0),
                stores: std::sync::atomic::AtomicUsize::new(0),
                proof_reads: std::sync::atomic::AtomicUsize::new(0),
                verifier: Default::default(),
            };
            let result = crate::boot::recover_warm_boot_position(&engine, &pin).await;
            assert_eq!(result.is_ok(), !corrupt, "zero={zerostate} corrupt={corrupt}: {result:?}");
            assert_eq!(
                engine.saves.load(std::sync::atomic::Ordering::SeqCst),
                usize::from(!corrupt)
            );
        }
    }
}

#[tokio::test]
async fn test_live_proof_history_cache_never_caches_incoming_certificates() {
    use rtos_block::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let chain: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tl/rtos_api/tests/data/bootstrap-history.json"
    ))
    .unwrap();
    let row: serde_json::Value =
        serde_json::from_str(include_str!("../../../tl/rtos_api/tests/data/warm-history.json"))
            .unwrap();
    let anchor = bootstrap_fixture_proof(
        &serde_json::json!({"block_boc":chain["anchor_boc"]}),
        false,
        false,
    );
    let first = bootstrap_fixture_proof(&chain["cases"][1], true, false);
    let second = bootstrap_fixture_proof(&chain["cases"][2], true, false);
    let target = bootstrap_fixture_proof(&row, true, false);
    let state = ShardStateUnsplit::construct_from_bytes(
        &hex::decode(row["state_boc"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let state = crate::shard_state::ShardStateStuff::from_state(
        target.id().clone(),
        state,
        #[cfg(feature = "telemetry")]
        &crate::collator_test_bundle::create_engine_telemetry(),
        &crate::collator_test_bundle::create_engine_allocated(),
    )
    .unwrap();
    let pin = anchor.id().clone();
    let handles = crate::collator_test_bundle::create_block_handle_storage(None).unwrap();
    let entries = [anchor, first.clone(), second.clone(), target.clone()]
        .into_iter()
        .map(|proof| {
            let handle = handles
                .create_handle(proof.id().clone(), storage::types::BlockMeta::default(), None)
                .unwrap()
                .unwrap();
            handle.set_block_applied();
            handle.set_data();
            handle.set_proof();
            (handle, proof)
        })
        .collect();
    let engine = RecoveryProofEngine {
        workers: Default::default(),
        pin,
        state,
        entries,
        next: None,
        previous: None,
        saves: AtomicUsize::new(0),
        stores: AtomicUsize::new(0),
        proof_reads: AtomicUsize::new(0),
        verifier: Default::default(),
    };
    {
        use crate::history_read_budget::{HistoryReadBudget, HistoryReadLimits, HistoryBudgetExceeded};
        let bytes = engine.entries.iter().map(|(_, p)| p.data().len()).sum();
        let exact = HistoryReadLimits { proof_count: 4, proof_bytes: bytes, ..Default::default() };
        let verifier = super::MasterchainProofVerifier::default();
        verifier.verify_bounded(&engine, &target, HistoryReadBudget::new(exact.clone())).await.unwrap();
        // A warm authority cache must still charge its actual retained proof.
        let error = verifier.verify_bounded(&engine, &target, HistoryReadBudget::new(
            HistoryReadLimits { proof_count: 0, ..exact.clone() })).await.err().expect("budget exceeded");
        assert!(error.downcast_ref::<HistoryBudgetExceeded>().is_some());
        let error = super::MasterchainProofVerifier::default().verify_bounded(&engine, &target,
            HistoryReadBudget::new(HistoryReadLimits { proof_bytes: bytes - 1, ..exact })).await.err().expect("budget exceeded");
        assert!(error.downcast_ref::<HistoryBudgetExceeded>().is_some());
        engine.proof_reads.store(0, Ordering::SeqCst);
    }
    let block = BlockStuff::deserialize_block_checked(
        target.id().clone(),
        Arc::new(hex::decode(row["block_boc"].as_str().unwrap()).unwrap()),
    )
    .unwrap();
    super::check_block_proof_pair(&engine, target.id(), &block, &target).await.unwrap();
    assert_eq!(engine.proof_reads.load(Ordering::SeqCst), 3, "anchor plus two key proofs");
    target.check_proof(&engine).await.unwrap();
    assert_eq!(
        engine.proof_reads.load(Ordering::SeqCst),
        3,
        "verified governing authority should be reused"
    );
    let engine_arc = Arc::new(engine);
    let consumer_engine: Arc<dyn crate::engine_traits::EngineOperations> = engine_arc.clone();
    crate::sync::save_test_block(
        &consumer_engine,
        target.id(),
        Arc::new(block.clone()),
        Arc::new(target.clone()),
    )
    .await
    .unwrap();
    assert_eq!(engine_arc.stores.load(Ordering::SeqCst), 2);
    engine_arc.stores.store(0, Ordering::SeqCst);
    for bad in [
        bootstrap_fixture_proof(&row, true, true),
        first.clone(),
        BlockProofStuff::new(target.proof.clone(), true).unwrap(),
    ] {
        assert!(
            crate::sync::save_test_block(
                &consumer_engine,
                target.id(),
                Arc::new(block.clone()),
                Arc::new(bad)
            )
            .await
            .is_err(),
            "archive accepted invalid proof"
        );
        assert_eq!(engine_arc.stores.load(Ordering::SeqCst), 0, "archive stored unverified input");
    }
    drop(consumer_engine);
    let workers = std::mem::take(&mut *engine_arc.workers.lock().unwrap());
    for worker in workers {
        worker.await.unwrap();
    }
    let mut engine =
        Arc::try_unwrap(engine_arc).unwrap_or_else(|_| panic!("archive consumer retained engine"));
    let corrupt = bootstrap_fixture_proof(&row, true, true);
    assert!(
        corrupt.check_proof(&engine).await.is_err(),
        "cached block ID bypassed incoming signature verification"
    );
    assert_eq!(engine.proof_reads.load(Ordering::SeqCst), 3);
    let link = BlockProofStuff::new(target.proof.clone(), true).unwrap();
    assert!(link.check_proof(&engine).await.is_err(), "masterchain link accepted as finality");
    assert!(
        super::check_block_proof_pair(&engine, target.id(), &block, &first).await.is_err(),
        "unrelated valid proof accepted with block"
    );
    let mut wrong_id = target.id().clone();
    wrong_id.file_hash = UInt256::from([55; 32]);
    assert!(super::check_block_proof_pair(&engine, &wrong_id, &block, &target).await.is_err());

    // Reusing an immutable authenticated authority does not reread corrupted DB
    // objects. A fresh verifier must authenticate that DB object from the pin.
    engine.entries[2].1 = bootstrap_fixture_proof(&chain["cases"][2], true, true);
    target.check_proof(&engine).await.unwrap();
    engine.verifier = Default::default();
    assert!(
        target.check_proof(&engine).await.is_err(),
        "parsed cached history promoted without verification"
    );
    engine.entries[2].1 = second;
    target.check_proof(&engine).await.unwrap();
    // The current state's ID may itself be the governing key block, which is
    // absent from its prev_blocks dictionary. Its raw config is never authority.
    let original_hint = engine.state.clone();
    let mut hint = original_hint.state().unwrap().clone();
    hint.set_seq_no(43);
    let mut custom = hint.read_custom().unwrap().unwrap();
    custom.prev_blocks.del(&43).unwrap();
    custom.config.set_config(ConfigParamEnum::ConfigParam19(0)).unwrap();
    hint.write_custom(Some(&custom)).unwrap();
    engine.state = crate::shard_state::ShardStateStuff::from_state(
        engine.entries[2].0.id().clone(),
        hint,
        #[cfg(feature = "telemetry")]
        &crate::collator_test_bundle::create_engine_telemetry(),
        &crate::collator_test_bundle::create_engine_allocated(),
    )
    .unwrap();
    engine.verifier = Default::default();
    target.check_proof(&engine).await.unwrap();
    engine.state = original_hint;
    let original_pin = engine.pin.clone();
    engine.pin.file_hash = UInt256::from([77; 32]);
    assert!(
        target.check_proof(&engine).await.is_err(),
        "wrong local pin reused another pin's cached authority"
    );
    engine.pin = original_pin;
    let before = engine.proof_reads.load(Ordering::SeqCst);
    engine.pin = first.id().clone();
    target.check_proof(&engine).await.unwrap();
    assert_eq!(
        engine.proof_reads.load(Ordering::SeqCst) - before,
        2,
        "a new pin must not reuse old-pin authorities"
    );

    // is_applied/has_data/has_proof are all set, yet a bad stored certificate is
    // rejected by the actual applied-cache validation helper.
    super::check_applied_masterchain(&engine, target.id()).await.unwrap();
    engine.entries[3].1 = corrupt;
    assert!(
        super::check_applied_masterchain(&engine, target.id()).await.is_err(),
        "applied flag bypassed finality"
    );
    engine.entries[3].1 = target.clone();
    let mut altered = engine.state.state().unwrap().clone();
    let mut custom = altered.read_custom().unwrap().unwrap();
    let mut reference = custom.prev_blocks.get(&43).unwrap().unwrap();
    reference.blk_ref.root_hash = UInt256::from([66; 32]);
    custom.prev_blocks.set(&43, &reference, &KeyMaxLt { key: true, max_end_lt: 0 }).unwrap();
    altered.write_custom(Some(&custom)).unwrap();
    engine.state = crate::shard_state::ShardStateStuff::from_state(
        target.id().clone(),
        altered,
        #[cfg(feature = "telemetry")]
        &crate::collator_test_bundle::create_engine_telemetry(),
        &crate::collator_test_bundle::create_engine_allocated(),
    )
    .unwrap();
    assert!(
        target.check_proof(&engine).await.is_err(),
        "same-height substituted history reused cached authority"
    );
}

struct MonitorProofEngine {
    pin: rtos_block::BlockIdExt,
    zero: Option<std::sync::Arc<crate::shard_state::ShardStateStuff>>,
    proofs: Vec<BlockProofStuff>,
    advertised: Vec<rtos_block::BlockIdExt>,
    stored: parking_lot::Mutex<Vec<rtos_block::BlockIdExt>>,
    handles: storage::block_handle_db::BlockHandleStorage,
    fail_store: bool,
    stopped: bool,
}

#[async_trait::async_trait]
impl crate::engine_traits::EngineOperations for MonitorProofEngine {
    fn zerostate_id(&self) -> rtos_block::Result<&rtos_block::BlockIdExt> {
        Ok(self.zero.as_ref().unwrap().block_id())
    }
    async fn load_mc_zero_state(
        &self,
    ) -> rtos_block::Result<std::sync::Arc<crate::shard_state::ShardStateStuff>> {
        Ok(self.zero.as_ref().unwrap().clone())
    }

    fn init_mc_block_id(&self) -> &rtos_block::BlockIdExt {
        &self.pin
    }
    fn check_stop(&self) -> bool {
        self.stopped
    }
    fn load_block_handle(
        &self,
        _: &rtos_block::BlockIdExt,
    ) -> rtos_block::Result<Option<std::sync::Arc<storage::block_handle_db::BlockHandle>>> {
        Ok(None)
    }
    async fn download_next_key_blocks_ids(
        &self,
        id: &rtos_block::BlockIdExt,
    ) -> rtos_block::Result<Vec<rtos_block::BlockIdExt>> {
        Ok(self.advertised.iter().filter(|next| next.seq_no > id.seq_no).cloned().collect())
    }
    async fn download_block_proof(
        &self,
        id: &rtos_block::BlockIdExt,
        link: bool,
        key: bool,
    ) -> rtos_block::Result<BlockProofStuff> {
        assert!(key);
        assert_eq!(link, id == &self.pin);
        self.proofs
            .iter()
            .find(|proof| proof.id().seq_no == id.seq_no)
            .cloned()
            .ok_or_else(|| rtos_block::error!("Missing monitor fixture"))
    }
    async fn store_block_proof(
        &self,
        id: &rtos_block::BlockIdExt,
        _: Option<std::sync::Arc<storage::block_handle_db::BlockHandle>>,
        proof: &BlockProofStuff,
    ) -> rtos_block::Result<crate::internal_db::BlockResult> {
        assert_eq!(id, proof.id());
        if self.fail_store {
            rtos_block::fail!("Injected monitor storage failure");
        }
        self.stored.lock().push(id.clone());
        let handle = self
            .handles
            .create_handle(id.clone(), storage::types::BlockMeta::default(), None)?
            .unwrap();
        Ok(crate::internal_db::BlockResult::with_status(
            handle,
            crate::internal_db::DataStatus::Updated,
        ))
    }
}

fn monitor_fixture() -> (MonitorProofEngine, serde_json::Value) {
    let data: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tl/rtos_api/tests/data/bootstrap-history.json"
    ))
    .unwrap();
    let anchor =
        bootstrap_fixture_proof(&serde_json::json!({"block_boc":data["anchor_boc"]}), false, false);
    let first = bootstrap_fixture_proof(&data["cases"][1], true, false);
    let second = bootstrap_fixture_proof(&data["cases"][2], true, false);
    (
        MonitorProofEngine {
            pin: anchor.id().clone(),
            zero: None,
            advertised: vec![first.id().clone(), second.id().clone()],
            proofs: vec![anchor, first, second],
            stored: Default::default(),
            handles: crate::collator_test_bundle::create_block_handle_storage(None).unwrap(),
            fail_store: false,
            stopped: false,
        },
        data,
    )
}

#[tokio::test]
async fn test_monitor_history_authenticates_before_storage_and_resumes() {
    use crate::network::full_node_overlays::advance_monitor_history;
    let (mut engine, data) = monitor_fixture();
    let mut history = None;
    engine.proofs[2] = bootstrap_fixture_proof(&data["cases"][2], true, true);
    assert!(advance_monitor_history(&engine, &mut history).await.is_err());
    assert_eq!(history.as_ref().unwrap().id(), engine.proofs[1].id());
    assert_eq!(*engine.stored.lock(), vec![engine.proofs[1].id().clone()]);
    engine.proofs[2] = bootstrap_fixture_proof(&data["cases"][2], true, false);
    advance_monitor_history(&engine, &mut history).await.unwrap();
    assert_eq!(history.as_ref().unwrap().id(), engine.proofs[2].id());
    assert_eq!(history.as_ref().unwrap().anchor(), &engine.pin);
    assert_eq!(engine.stored.lock().len(), 2);
    advance_monitor_history(&engine, &mut history).await.unwrap();
    assert_eq!(engine.stored.lock().len(), 2);
    engine.pin.file_hash = rtos_block::UInt256::from([77; 32]);
    assert!(advance_monitor_history(&engine, &mut history).await.is_err());
    assert!(history.is_none(), "Changed pin must discard previous authority");
    assert_eq!(engine.stored.lock().len(), 2);
}

#[tokio::test]
async fn test_monitor_history_rejects_untrusted_successors_before_storage() {
    use crate::network::full_node_overlays::advance_monitor_history;
    for mutation in 0..8 {
        let (mut engine, data) = monitor_fixture();
        match mutation {
            0 => engine.proofs[1] = bootstrap_fixture_proof(&data["cases"][1], true, true),
            1 => engine.proofs[1] = bootstrap_fixture_proof(&data["cases"][1], false, false),
            2 => {
                engine.proofs[1] = bootstrap_fixture_proof(&data["cases"][3], true, false);
                engine.advertised[0] = engine.proofs[1].id().clone();
            }
            3 => engine.advertised[0].file_hash = rtos_block::UInt256::from([77; 32]),
            4 => {
                engine.advertised.remove(0);
            }
            5 => engine.advertised = vec![engine.advertised[0].clone(); 6],
            6 => engine.fail_store = true,
            7 => engine.stopped = true,
            _ => unreachable!(),
        }
        let mut history = None;
        let result = advance_monitor_history(&engine, &mut history).await;
        assert!(result.is_err(), "monitor mutation {mutation} accepted");
        assert!(engine.stored.lock().is_empty(), "monitor mutation {mutation} reached storage");
        assert_eq!(history.as_ref().unwrap().id(), &engine.pin);
    }
}

#[tokio::test]
async fn test_monitor_history_starts_from_complete_zerostate_pin() {
    use crate::network::full_node_overlays::advance_monitor_history;
    use rtos_block::*;
    let data: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tl/rtos_api/tests/data/archive-authority.json"
    ))
    .unwrap();
    let bytes = hex::decode(data["zerostate"].as_str().unwrap()).unwrap();
    let root = read_single_root_boc(&bytes).unwrap();
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
    let (mut engine, _) = monitor_fixture();
    engine.pin = pin;
    engine.zero = Some(zero);
    engine.proofs = [0, 2]
        .into_iter()
        .map(|i| bootstrap_fixture_proof(&data["cases"][i], true, false))
        .collect();
    engine.advertised = engine.proofs.iter().map(|p| p.id().clone()).collect();
    let mut history = None;
    advance_monitor_history(&engine, &mut history).await.unwrap();
    assert_eq!(history.as_ref().unwrap().id(), engine.proofs[1].id());
    assert_eq!(history.as_ref().unwrap().anchor(), &engine.pin);
    assert_eq!(engine.stored.lock().len(), 2);
    engine.pin.file_hash = UInt256::from([88; 32]);
    assert!(advance_monitor_history(&engine, &mut history).await.is_err());
    assert!(history.is_none());
    assert_eq!(engine.stored.lock().len(), 2);
}

#[tokio::test]
async fn test_monitor_history_rejects_foreign_cached_authority() {
    let (mut engine, _) = monitor_fixture();
    let mut history = Some(
        super::BootstrapAuthority::from_checkpoint(&engine.pin, engine.proofs[0].clone()).unwrap(),
    );
    engine.pin.file_hash = rtos_block::UInt256::from([99; 32]);
    engine.advertised.clear();
    assert!(crate::network::full_node_overlays::advance_monitor_history(&engine, &mut history)
        .await
        .is_err());
    assert!(history.is_none());
    assert!(engine.stored.lock().is_empty());
}

#[tokio::test]
async fn historical_broadcast_context_authenticates_old_epoch_after_rotation() {
    use rtos_block::*;
    use std::sync::atomic::AtomicUsize;
    let chain: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tl/rtos_api/tests/data/bootstrap-history.json"
    ))
    .unwrap();
    let warm: serde_json::Value =
        serde_json::from_str(include_str!("../../../tl/rtos_api/tests/data/warm-history.json"))
            .unwrap();
    let anchor = bootstrap_fixture_proof(
        &serde_json::json!({"block_boc": chain["anchor_boc"]}),
        false,
        false,
    );
    let first = bootstrap_fixture_proof(&chain["cases"][1], true, false);
    let second = bootstrap_fixture_proof(&chain["cases"][2], true, false);
    let latest = bootstrap_fixture_proof(&warm, true, false);
    let state = ShardStateUnsplit::construct_from_bytes(
        &hex::decode(warm["state_boc"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let state = crate::shard_state::ShardStateStuff::from_state(
        latest.id().clone(),
        state,
        #[cfg(feature = "telemetry")]
        &crate::collator_test_bundle::create_engine_telemetry(),
        &crate::collator_test_bundle::create_engine_allocated(),
    )
    .unwrap();
    let handles = crate::collator_test_bundle::create_block_handle_storage(None).unwrap();
    let entries = [anchor.clone(), first.clone(), second.clone()]
        .into_iter()
        .map(|proof| {
            let handle = handles
                .create_handle(proof.id().clone(), storage::types::BlockMeta::default(), None)
                .unwrap()
                .unwrap();
            handle.set_data();
            handle.set_proof();
            handle.set_block_applied();
            (handle, proof)
        })
        .collect();
    let mut engine = RecoveryProofEngine {
        workers: Default::default(),
        pin: anchor.id().clone(),
        state,
        entries,
        next: None,
        previous: None,
        saves: AtomicUsize::new(0),
        stores: AtomicUsize::new(0),
        proof_reads: AtomicUsize::new(0),
        verifier: Default::default(),
    };
    // The history fixture predates broadcast header binding. Use a separately
    // signed block whose header catchain/subset match its certificate.
    let broadcast: serde_json::Value = serde_json::from_str(include_str!(
        "../full_node/finality/testdata/historical-broadcast.json"
    ))
    .unwrap();
    let second = bootstrap_fixture_proof(&broadcast, true, false);
    let block = second.virtualize_block().unwrap().0;
    assert!(
        crate::full_node::shard_client::pq_broadcast_context(&engine.state, second.id(), &block)
            .is_err(),
        "fixture must require historical rather than current governing config"
    );
    let context = crate::full_node::shard_client::resolve_pq_broadcast_context(
        &engine,
        &engine.state,
        second.id(),
        &block,
    )
    .await
    .unwrap();
    let BlockSignaturesVariant::SimplexPq(carrier) = second.clone().drain_signatures().unwrap()
    else {
        panic!("PQ fixture required")
    };
    let network =
        rtos_api::pq_finality::PqNetworkSignatureSet::from_final_fields(&carrier).unwrap();
    context.verify_network(&network).unwrap();
    let mut corrupt = carrier.clone();
    corrupt.signatures[0].signature[0] ^= 1;
    assert!(context
        .verify_network(
            &rtos_api::pq_finality::PqNetworkSignatureSet::from_final_fields(&corrupt).unwrap()
        )
        .is_err());
    // Current state's lookup coordinates alone cannot grant historical authority.
    // Even an applied/data/proof-marked old key block must authenticate from pin.
    engine.entries[1].1 = bootstrap_fixture_proof(&chain["cases"][1], true, true);
    assert!(crate::full_node::shard_client::resolve_pq_broadcast_context(
        &engine,
        &engine.state,
        second.id(),
        &block
    )
    .await
    .is_err());
    engine.entries[1].1 = first;
    for epoch in [engine.pin.seq_no() - 1, u32::MAX] {
        let mut altered = block.clone();
        let mut header = altered.read_info().unwrap();
        header.set_prev_key_block_seqno(epoch);
        altered.write_info(&header).unwrap();
        assert!(
            crate::full_node::shard_client::resolve_pq_broadcast_context(
                &engine,
                &engine.state,
                second.id(),
                &altered
            )
            .await
            .is_err(),
            "forged epoch must not resolve trusted authority"
        );
    }
    let mut foreign = block.clone();
    foreign.set_global_id(block.global_id().wrapping_add(1));
    assert!(crate::full_node::shard_client::resolve_pq_broadcast_context(
        &engine,
        &engine.state,
        second.id(),
        &foreign
    )
    .await
    .is_err());
    engine.pin.file_hash = UInt256::from([55; 32]);
    assert!(crate::full_node::shard_client::resolve_pq_broadcast_context(
        &engine,
        &engine.state,
        second.id(),
        &block
    )
    .await
    .is_err());
    assert_eq!(engine.stores.load(std::sync::atomic::Ordering::SeqCst), 0);
}
