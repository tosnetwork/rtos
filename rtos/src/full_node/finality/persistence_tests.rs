// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{
    block::BlockStuff,
    config::TonNodeConfig,
    engine::{Engine, EngineFlags, Stopper},
    network::node_network::NodeNetwork,
};
use rtos_api::{pq_finality::PqNetworkSignatureSet, WireProfile};
use rtos_block::*;

async fn open_engine(dir: &std::path::Path) -> Arc<Engine> {
    let config =
        TonNodeConfig::from_file(dir.to_str().unwrap(), "config.json", None, "config.json", None)
            .await
            .unwrap();
    Engine::new(
        config,
        EngineFlags { initial_sync_disabled: true, force_check_db: false, truncate_db: None },
        Arc::new(Stopper::new()),
    )
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_engine_finality_recovery_persists_applies_and_reopens() {
    let _ = env_logger::builder().is_test(true).try_init();
    // Public deterministic test keys only; reproducer is archived with C2a evidence.
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("testdata/recovery.json")).unwrap();
    let bytes = |value: &serde_json::Value| hex::decode(value.as_str().unwrap()).unwrap();
    let state_id = |data: &[u8]| {
        let root = read_single_root_boc(data).unwrap();
        let state = ShardStateUnsplit::construct_from_cell(root.clone()).unwrap();
        BlockIdExt::with_params(
            state.shard().clone(),
            state.seq_no(),
            root.repr_hash().clone(),
            UInt256::calc_file_hash(data),
        )
    };
    let mc_bytes = bytes(&fixture["state_boc"]);
    let prev_bytes = bytes(&fixture["prev_state_boc"]);
    let next_bytes = bytes(&fixture["next_state_boc"]);
    let mc_id = state_id(&mc_bytes);
    let prev_id = state_id(&prev_bytes);
    let row = &fixture["rows"][0];
    let candidate_bytes = bytes(&row["candidate"]);
    let candidate: rtos_api::ton::consensus::CandidateHashData =
        WireProfile::T0.deserialize_typed(&candidate_bytes).unwrap();
    let id = candidate.block().clone();
    let block =
        BlockStuff::deserialize_block_checked(id.clone(), Arc::new(bytes(&row["block_boc"])))
            .unwrap();
    let carrier = BlockSignaturesSimplexPq {
        validator_info: ValidatorBaseInfo::with_params(
            row["subset_hash"].as_u64().unwrap() as u32,
            7,
        ),
        sig_count: 3,
        sig_weight: 3,
        slot: 99,
        session_id: UInt256::from_slice(&bytes(&row["session"])),
        candidate_data: BlockSignaturesSimplex::bytes_to_cell_tree(&candidate_bytes).unwrap(),
        signatures: row["signatures"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| {
                let mut identity = [0; 32];
                identity[..4]
                    .copy_from_slice(&(item["index"].as_u64().unwrap() as u32 + 1).to_le_bytes());
                PqBlockSignaturePair {
                    validator_id: identity.into(),
                    algorithm_id: 1,
                    signature: bytes(&item["signature"]),
                }
            })
            .collect(),
    };
    let evidence = NetworkSignatureSet::PostQuantum(
        PqNetworkSignatureSet::from_final_fields(&carrier).unwrap(),
    );
    let temporary = tempfile::tempdir().unwrap();
    let directory = std::env::var_os("RTOS_RECOVERY_DIRECTORY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| temporary.path().to_path_buf());
    let dir = directory.as_path();
    let (adnl, _) = adnl::node::AdnlNodeConfig::with_ip_address_and_private_key_tags(
        "127.0.0.1:0",
        vec![NodeNetwork::TAG_DHT_KEY, NodeNetwork::TAG_OVERLAY_KEY],
    )
    .unwrap();
    let anchor = serde_json::json!({"workchain":-1,"shard":mc_id.shard().shard_prefix_with_tag() as i64,"seqno":0,"root_hash":base64_encode(mc_id.root_hash.as_slice()),"file_hash":base64_encode(mc_id.file_hash.as_slice())});
    std::fs::write(dir.join("global.json"),serde_json::to_vec(&serde_json::json!({"@type":"config.global","dht":{"@type":"dht.config.global","k":6,"a":3,"static_nodes":{"@type":"dht.nodes","nodes":[]}},"validator":{"@type":"validator.config.global","zero_state":anchor,"hardforks":[]}})).unwrap()).unwrap();
    std::fs::write(dir.join("config.json"),serde_json::to_vec(&serde_json::json!({
        "ton_global_config_name":"global.json","boot_from_zerostate":true,"internal_db_path":dir.join("db"),"restore_db":false,"sync_by_archives":false,"adnl_node":adnl,
        "validator_keys":[],"validator_key_ring":{},"json_rpc_server":null,"control_server":null,"lite_server":null,
        "test_bundles_config":{"collator":{"path":""},"validator":{"path":""}}
    })).unwrap()).unwrap();

    let phase = std::env::var("RTOS_RECOVERY_PHASE").ok();
    if phase.is_none() {
        for phase in ["write", "reopen"] {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["full_node::finality::persistence_tests::real_engine_finality_recovery_persists_applies_and_reopens", "--exact", "--include-ignored", "--nocapture"])
                .env("RTOS_RECOVERY_DIRECTORY", dir).env("RTOS_RECOVERY_PHASE", phase)
                .spawn().unwrap();
            let start = Instant::now();
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                if start.elapsed() > Duration::from_secs(30) {
                    child.kill().unwrap();
                    let _ = child.wait();
                    panic!("recovery {phase} child timed out");
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            };
            assert!(status.success(), "recovery {phase} child failed");
        }
        return;
    }
    let engine = open_engine(dir).await;
    if phase.as_deref() == Some("reopen") {
        let handle = engine.load_block_handle(&id).unwrap().unwrap();
        assert!(handle.has_state());
        assert!(handle.has_proof_link());
        assert!(!handle.is_applied());
        assert_eq!(
            engine.load_state(&id).await.unwrap().root_cell().repr_hash(),
            read_single_root_boc(&next_bytes).unwrap().repr_hash()
        );
        assert_eq!(engine.load_block(&handle).await.unwrap().data(), block.data());
        let proof_bytes = std::fs::read(dir.join("expected-proof.bin")).unwrap();
        assert_eq!(engine.load_block_proof(&handle, true).await.unwrap().data(), proof_bytes);
        let ops: Arc<dyn EngineOperations> = engine.clone();
        recover(&ops, &id, &evidence).await.unwrap();
        let mut bad = carrier;
        bad.signatures[0].signature[0] ^= 1;
        recover(
            &ops,
            &id,
            &NetworkSignatureSet::PostQuantum(
                PqNetworkSignatureSet::from_final_fields(&bad).unwrap(),
            ),
        )
        .await
        .unwrap();
        assert_eq!(engine.load_block_proof(&handle, true).await.unwrap().data(), proof_bytes);
        drop(ops);
        drop(handle);
        engine.clone().wait_stop().await;
        return;
    }
    assert_eq!(phase.as_deref(), Some("write"));
    for (id, data) in [(&mc_id, &mc_bytes), (&prev_id, &prev_bytes)] {
        let state = ShardStateStuff::from_root_cell(
            id.clone(),
            read_single_root_boc(data).unwrap(),
            #[cfg(feature = "telemetry")]
            engine.engine_telemetry(),
            engine.engine_allocated(),
        )
        .unwrap();
        engine.store_zerostate(state, data).await.unwrap();
    }
    engine.save_last_applied_mc_block_id(&mc_id).unwrap();
    engine.save_shard_client_mc_block_id(&mc_id).unwrap();
    // The real candidate-cache download path reconstructs and checks its proof.
    // Leave data committed without proof/state, as after a failed storage step.
    engine.cache_block_candidate(&id, block.data().to_vec()).unwrap();
    let partial = engine.store_block(&block).await.unwrap().to_any();
    assert!(partial.has_data());
    assert!(!partial.has_state());
    let ops: Arc<dyn EngineOperations> = engine.clone();
    recover(&ops, &id, &evidence).await.unwrap();
    let handle = engine.load_block_handle(&id).unwrap().unwrap();
    assert!(handle.has_data());
    assert!(handle.has_proof_link());
    assert!(handle.has_state());
    assert!(
        !handle.is_applied(),
        "shard finality only authorizes pre-apply before masterchain inclusion"
    );
    assert_eq!(
        engine.load_state(&id).await.unwrap().root_cell().repr_hash(),
        read_single_root_boc(&next_bytes).unwrap().repr_hash()
    );
    assert_eq!(engine.load_block(&handle).await.unwrap().data(), block.data());
    let proof_bytes = engine.load_block_proof(&handle, true).await.unwrap().data().to_vec();
    std::fs::write(dir.join("expected-proof.bin"), &proof_bytes).unwrap();
    drop(ops);
    drop(partial);
    drop(handle);
    engine.clone().wait_stop().await;
}
