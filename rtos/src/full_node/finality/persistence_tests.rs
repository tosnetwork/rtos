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
    run_engine_recovery(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_engine_finality_downloads_over_network_without_candidate_cache() {
    run_engine_recovery(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_engine_monitoring_covers_zero_and_maximum_split() {
    let dir = tempfile::tempdir().unwrap();
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("testdata/recovery.json")).unwrap();
    let data = hex::decode(fixture["state_boc"].as_str().unwrap()).unwrap();
    let mc_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        0,
        read_single_root_boc(&data).unwrap().repr_hash().clone(),
        UInt256::calc_file_hash(&data),
    );
    write_recovery_config(dir.path(), &mc_id, true);
    let engine = open_engine(dir.path()).await;
    let root = ShardIdent::with_prefix_len(0, 0, 0).unwrap();
    for depth in [0, Engine::MAX_MONITOR_MIN_SPLIT] {
        let last = (1u64 << depth) - 1;
        engine.set_test_monitoring(depth, 1u64 << last);
        assert!(engine.need_monitor(&root).unwrap());
        for index in 0..=last {
            let prefix = if depth == 0 { 0 } else { index << (64 - depth) };
            let shard = ShardIdent::with_prefix_len(depth, 0, prefix).unwrap();
            assert_eq!(engine.need_monitor(&shard).unwrap(), index == last);
        }
        engine.set_test_monitoring(depth, 0);
        assert!(!engine.need_monitor(&root).unwrap());
        assert!(engine.need_monitor(&ShardIdent::masterchain()).unwrap());
        assert!(!engine.need_monitor(&ShardIdent::with_prefix_len(0, 1, 0).unwrap()).unwrap());
    }
    engine.wait_stop().await.unwrap();
}

async fn run_engine_recovery(network_repair: bool) {
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
    write_recovery_config(dir, &mc_id, network_repair);

    let phase = if network_repair {
        Some("network".to_owned())
    } else {
        std::env::var("RTOS_RECOVERY_PHASE").ok()
    };
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
        engine.clone().wait_stop().await.unwrap();
        return;
    }
    assert!(matches!(phase.as_deref(), Some("write" | "network")));
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
    let mut provider = None;
    let partial = if network_repair {
        let provider_dir = dir.join("provider");
        write_recovery_config(&provider_dir, &mc_id, true);
        let peer_engine = open_engine(&provider_dir).await;
        let stored = peer_engine.store_block(&block).await.unwrap().to_any();
        let proof = crate::validator::accept_block::create_new_proof_link(&block).unwrap();
        peer_engine.store_block_proof(&id, Some(stored), &proof).await.unwrap();
        engine.initialize_test_full_node_overlays().await.unwrap();
        peer_engine.initialize_test_full_node_overlays().await.unwrap();
        for (local, remote) in [(&engine, &peer_engine), (&peer_engine, &engine)] {
            let local_adnl = &local.network().context().stack.adnl;
            let remote_adnl = &remote.network().context().stack.adnl;
            let local_key = local_adnl.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY).unwrap();
            let remote_key = remote_adnl.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY).unwrap();
            let peer = local_adnl
                .add_peer(local_key.id(), remote_adnl.ip_address_adnl(), None, &remote_key)
                .unwrap()
                .unwrap();
            assert!(local
                .overlay_client(id.shard())
                .await
                .unwrap()
                .overlay_client()
                .neighbours()
                .add(peer)
                .unwrap());
        }
        assert!(engine.load_block_handle(&id).unwrap().is_none());
        assert!(engine.try_get_cached_block_candidate(&id).is_none());
        assert_eq!(peer_engine.overlays_router().unwrap().test_block_download_queries(), 0);
        provider = Some(peer_engine);
        None
    } else {
        // Leave data committed without proof/state, as after a failed storage step.
        engine.cache_block_candidate(&id, block.data().to_vec()).unwrap();
        let partial = engine.store_block(&block).await.unwrap().to_any();
        assert!(partial.has_data());
        assert!(!partial.has_state());
        Some(partial)
    };
    let ops: Arc<dyn EngineOperations> = engine.clone();
    if network_repair {
        use rtos_api::IntoBoxed;
        let NetworkSignatureSet::PostQuantum(signatures) = &evidence else { unreachable!() };
        let carrier = BlockFinalityBroadcast {
            id: id.clone(),
            signature_set: signatures.to_node().into_boxed(),
        };
        let bytes = WireProfile::T0.serialize(&carrier.into_boxed()).unwrap();
        let parsed: rtos_api::ton::ton_node::Broadcast =
            WireProfile::T0.deserialize_typed(&bytes).unwrap();
        let rtos_api::ton::ton_node::Broadcast::TonNode_BlockFinalityBroadcast(carrier) = parsed
        else {
            unreachable!()
        };
        let sender = provider
            .as_ref()
            .unwrap()
            .network()
            .context()
            .stack
            .adnl
            .key_by_tag(NodeNetwork::TAG_OVERLAY_KEY)
            .unwrap()
            .id()
            .clone();
        engine
            .clone()
            .process_block_finality_broadcast(carrier, sender, bytes.len())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if engine.load_block_handle(&id).unwrap().is_some_and(|handle| handle.has_state())
                    && engine.pending_finality.lock().workers == 0
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    } else {
        recover(&ops, &id, &evidence).await.unwrap();
    }
    if network_repair {
        assert!(
            engine.try_get_cached_block_candidate(&id).is_none(),
            "network repair must not insert a candidate-cache shortcut"
        );
        assert!(
            provider.as_ref().unwrap().overlays_router().unwrap().test_block_download_queries() > 0,
            "provider must receive a real DownloadBlockFull network query"
        );
    }
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
    engine.clone().wait_stop().await.unwrap();
    let receiver_weak = Arc::downgrade(&engine);
    drop(engine);
    assert!(receiver_weak.upgrade().is_none(), "recovery retained receiver Engine");
    if let Some(provider) = provider {
        provider.clone().wait_stop().await.unwrap();
        let provider_weak = Arc::downgrade(&provider);
        drop(provider);
        assert!(provider_weak.upgrade().is_none(), "network query retained provider Engine");
        let reopened_provider = open_engine(&dir.join("provider")).await;
        reopened_provider.wait_stop().await.unwrap();
    }
    // Reopen the exact database in this process/runtime after real network
    // ingress, recovery workers, storage/apply and all owned tasks have joined.
    let reopened_receiver = open_engine(dir).await;
    reopened_receiver.wait_stop().await.unwrap();
}

fn write_recovery_config(dir: &std::path::Path, mc_id: &BlockIdExt, network: bool) {
    std::fs::create_dir_all(dir).unwrap();
    let address = if network {
        // Select a local ephemeral port instead of reserving shared fixed ports.
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().to_string()
    } else {
        "127.0.0.1:0".to_owned()
    };
    let (adnl, _) = adnl::node::AdnlNodeConfig::with_ip_address_and_private_key_tags(
        &address,
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
}
