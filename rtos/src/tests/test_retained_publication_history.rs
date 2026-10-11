// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::engine_traits::{EngineAlloc, EngineOperations};
use rtos_block::*;

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

struct CapsuleEngine {
    directory: tempfile::TempDir,
    pin: BlockIdExt,
    zero: BlockIdExt,
    allocated: Arc<EngineAlloc>,
    #[cfg(feature = "telemetry")]
    telemetry: Arc<crate::engine_traits::EngineTelemetry>,
}
#[async_trait::async_trait]
impl EngineOperations for CapsuleEngine {
    fn db_root_dir(&self) -> Result<&str> {
        Ok(self.directory.path().to_str().unwrap())
    }
    fn init_mc_block_id(&self) -> &BlockIdExt {
        &self.pin
    }
    fn zerostate_id(&self) -> Result<&BlockIdExt> {
        Ok(&self.zero)
    }
    fn engine_allocated(&self) -> &Arc<EngineAlloc> {
        &self.allocated
    }
    #[cfg(feature = "telemetry")]
    fn engine_telemetry(&self) -> &Arc<crate::engine_traits::EngineTelemetry> {
        &self.telemetry
    }
    fn check_stop(&self) -> bool {
        false
    }
    fn register_service_task(
        &self,
        _: &'static str,
        _: u32,
        start: Box<dyn FnOnce() -> tokio::task::JoinHandle<()> + Send>,
    ) -> Result<tokio::task::JoinHandle<()>> {
        Ok(start())
    }
    fn load_block_handle(
        &self,
        _: &BlockIdExt,
    ) -> Result<Option<Arc<storage::block_handle_db::BlockHandle>>> {
        Ok(None)
    }
    async fn download_block_proof(
        &self,
        _: &BlockIdExt,
        _: bool,
        _: bool,
    ) -> Result<BlockProofStuff> {
        fail!("ordinary historical proof unavailable")
    }
    async fn load_last_applied_mc_state(&self) -> Result<Arc<ShardStateStuff>> {
        fail!("ordinary historical index unavailable")
    }
}

#[tokio::test]
async fn retained_publication_nonzero_epoch_cold_cache_and_revocation() {
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
    let state = hex::decode(warm["state_boc"].as_str().unwrap()).unwrap();
    let global_id = ShardStateUnsplit::construct_from_bytes(&state).unwrap().global_id();
    // A checkpoint pin and network zerostate are independent local inputs.
    let network: serde_json::Value =
        serde_json::from_str(include_str!("../validator/tests/data/manager-history.json")).unwrap();
    let zero: BlockIdExt = network["zero"].as_str().unwrap().parse().unwrap();
    assert_eq!(zero.seq_no, 0);
    let mut engine = CapsuleEngine {
        directory: tempfile::tempdir().unwrap(),
        pin: anchor.id().clone(),
        zero,
        allocated: crate::collator_test_bundle::create_engine_allocated(),
        #[cfg(feature = "telemetry")]
        telemetry: crate::collator_test_bundle::create_engine_telemetry(),
    };
    let path = root(&engine).unwrap();
    let domain = Domain::from_engine(&engine).unwrap();
    Store::open(path.clone(), Limits::default())
        .unwrap()
        .commit(
            domain.clone(),
            latest.id().clone(),
            global_id,
            state,
            vec![anchor, first, second, latest.clone()],
        )
        .unwrap();
    let broadcast: serde_json::Value = serde_json::from_str(include_str!(
        "../full_node/finality/testdata/historical-broadcast.json"
    ))
    .unwrap();
    let target = bootstrap_fixture_proof(&broadcast, true, false);
    let block = target.virtualize_block().unwrap().0;
    assert!(block.read_info().unwrap().prev_key_block_seqno() > engine.pin.seq_no);
    // Every call starts with an empty authority cache. No ordinary state/proof
    // loader can supply the missing history. This is a verifier boundary test,
    // not an Engine WAL/GC or power-loss test.
    let context = crate::block_proof::MasterchainProofVerifier::default()
        .pq_broadcast_context(&engine, target.id(), &block)
        .await
        .unwrap();
    let BlockSignaturesVariant::SimplexPq(carrier) = target.clone().drain_signatures().unwrap()
    else {
        panic!("PQ required")
    };
    context
        .verify_network(
            &rtos_api::pq_finality::PqNetworkSignatureSet::from_final_fields(&carrier).unwrap(),
        )
        .unwrap();
    let manifest = path.join(format!("{}.json", anchor_name(&domain, latest.id())));
    let bytes = std::fs::read(&manifest).unwrap();
    std::fs::remove_file(&manifest).unwrap();
    assert!(crate::block_proof::MasterchainProofVerifier::default()
        .pq_broadcast_context(&engine, target.id(), &block)
        .await
        .is_err());
    std::fs::write(&manifest, &bytes).unwrap();
    // The same exact manifest restores the cold verification path.
    crate::block_proof::MasterchainProofVerifier::default()
        .pq_broadcast_context(&engine, target.id(), &block)
        .await
        .unwrap();
    // Checkpoint lookup permits its pinned link; successors never accept links.
    assert!(crate::boot::load_history_proof(&engine, &engine.pin, true, true).await.is_ok());
    assert!(crate::boot::load_history_proof(&engine, &engine.pin, false, true).await.is_err());
    let original_zero = engine.zero.clone();
    engine.zero.file_hash = UInt256::from([98; 32]);
    assert!(crate::block_proof::MasterchainProofVerifier::default()
        .pq_broadcast_context(&engine, target.id(), &block)
        .await
        .is_err());
    engine.zero = original_zero;
    engine.pin.file_hash = UInt256::from([99; 32]);
    assert!(crate::block_proof::MasterchainProofVerifier::default()
        .pq_broadcast_context(&engine, target.id(), &block)
        .await
        .is_err());
}

#[test]
fn retained_publication_lookup_rejects_conflicting_full_ids() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().to_owned(), Limits::default()).unwrap();
    let id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        42,
        UInt256::from([1; 32]),
        UInt256::from([2; 32]),
    );
    let domain = Domain { zero: id.to_string(), init: id.to_string() };
    store.commit(domain.clone(), id.clone(), -239, vec![1], vec![]).unwrap();
    let mut conflicting = id.clone();
    conflicting.file_hash = UInt256::from([3; 32]);
    store.commit(domain.clone(), conflicting, -239, vec![2], vec![]).unwrap();
    assert!(store.manifests(&domain).is_err());
}
