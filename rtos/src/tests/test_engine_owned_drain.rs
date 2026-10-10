// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::network::overlay_client::OverlayInitGate;
use std::{path::Path, time::Duration};

fn config(dir: &Path) {
    let address =
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().to_string();
    let (adnl, _) = adnl::node::AdnlNodeConfig::with_ip_address_and_private_key_tags(
        &address,
        vec![NodeNetwork::TAG_DHT_KEY, NodeNetwork::TAG_OVERLAY_KEY],
    )
    .unwrap();
    let data = include_bytes!("static/zerostate.boc");
    let root = rtos_block::read_single_root_boc(data).unwrap();
    let anchor = serde_json::json!({"workchain":-1,"shard":i64::MIN,"seqno":0,"root_hash":rtos_block::base64_encode(root.repr_hash().as_slice()),"file_hash":rtos_block::base64_encode(UInt256::calc_file_hash(data).as_slice())});
    std::fs::write(dir.join("global.json"),serde_json::to_vec(&serde_json::json!({"@type":"config.global","dht":{"@type":"dht.config.global","k":6,"a":3,"static_nodes":{"@type":"dht.nodes","nodes":[]}},"validator":{"@type":"validator.config.global","zero_state":anchor,"hardforks":[]}})).unwrap()).unwrap();
    std::fs::write(dir.join("config.json"),serde_json::to_vec(&serde_json::json!({
        "ton_global_config_name":"global.json","boot_from_zerostate":true,"internal_db_path":dir.join("db"),"restore_db":false,"sync_by_archives":false,"adnl_node":adnl,
        "validator_keys":[],"validator_key_ring":{},"json_rpc_server":null,"control_server":null,"lite_server":null,
        "test_bundles_config":{"collator":{"path":""},"validator":{"path":""}}
    })).unwrap()).unwrap();
}

async fn open(dir: &Path) -> Arc<Engine> {
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

async fn seed_queue(engine: &Arc<Engine>) {
    let bytes = include_bytes!("static/zerostate.boc");
    let id = engine.zerostate_id().unwrap().clone();
    let state = ShardStateStuff::deserialize_zerostate(
        id.clone(),
        bytes,
        #[cfg(feature = "telemetry")]
        engine.engine_telemetry(),
        engine.engine_allocated(),
    )
    .unwrap();
    engine.store_zerostate(state, bytes).await.unwrap();
    engine.save_last_applied_mc_block_id(&id).unwrap();
    engine.save_shard_client_mc_block_id(&id).unwrap();
    engine.initialize_queue_manager().await.unwrap();
}

async fn stopped(engine: Arc<Engine>) {
    tokio::time::timeout(Duration::from_secs(15), engine.wait_stop())
        .await
        .expect("Engine shutdown watchdog")
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn engine_owned_drain_two_real_engines_wait_for_listener_then_reopen_databases() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    config(first.path());
    config(second.path());
    let a = open(first.path()).await;
    let b = open(second.path()).await;
    seed_queue(&a).await;
    seed_queue(&b).await;
    a.initialize_full_node_overlays(DhtSearchPolicy::default()).await.unwrap();
    b.initialize_full_node_overlays(DhtSearchPolicy::default()).await.unwrap();
    let client = a.overlay_client(&ShardIdent::MASTERCHAIN).await.unwrap();
    let release = client.hold_listener_exit();
    let client_weak = Arc::downgrade(&client);
    drop(client);
    let stopping = tokio::spawn(stopped(a.clone()));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!stopping.is_finished(), "Engine certified stop before actual listener exit");
    assert!(a.overlays_router().is_err(), "stop must close normal request admission");
    assert!(a.initialize_full_node_overlays(DhtSearchPolicy::default()).await.is_err());
    release.send(()).unwrap();
    stopping.await.unwrap();
    stopped(b.clone()).await;
    assert!(client_weak.upgrade().is_none(), "listener/client ownership leaked");
    let weak_a = Arc::downgrade(&a);
    let weak_b = Arc::downgrade(&b);
    drop(a);
    drop(b);
    assert!(weak_a.upgrade().is_none(), "first Engine retained after joined shutdown");
    assert!(weak_b.upgrade().is_none(), "second Engine retained after joined shutdown");
    // Same process and runtime: real storage locks must have been released.
    let reopened_a = open(first.path()).await;
    let reopened_b = open(second.path()).await;
    stopped(reopened_a).await;
    stopped(reopened_b).await;
}

async fn partial_initialization(cancel: bool) {
    let dir = tempfile::tempdir().unwrap();
    config(dir.path());
    let engine = open(dir.path()).await;
    let gate = Arc::new(OverlayInitGate {
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Semaphore::new(0),
        fail: true,
    });
    *engine.overlay_init_test_gate.lock().unwrap() = Some(gate.clone());
    let starting_engine = engine.clone();
    let starting = tokio::spawn(async move {
        starting_engine.initialize_full_node_overlays(DhtSearchPolicy::default()).await
    });
    tokio::time::timeout(Duration::from_secs(10), gate.entered.notified()).await.unwrap();
    let router = engine
        .owned_services
        .lock()
        .unwrap()
        .router
        .clone()
        .expect("owner registered before constructor await");
    assert!(engine.overlays_router().is_err(), "partial owner must not be externally ready");
    // The sibling is a real initialized overlay with its real workers running.
    let mc = router.overlay_client(&ShardIdent::MASTERCHAIN).await.unwrap();
    let client_weak = Arc::downgrade(&mc);
    drop(mc);
    if cancel {
        starting.abort();
        match starting.await {
            Err(error) => assert!(error.is_cancelled()),
            Ok(_) => panic!("constructor unexpectedly completed"),
        }
    } else {
        gate.release.add_permits(1);
        assert!(starting.await.unwrap().is_err());
    }
    stopped(engine.clone()).await;
    assert!(client_weak.upgrade().is_none());
    drop(router);
    let weak = Arc::downgrade(&engine);
    drop(engine);
    assert!(weak.upgrade().is_none(), "partial initialization retained Engine");
    stopped(open(dir.path()).await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn engine_owned_drain_partial_constructor_failure_joins_successful_sibling() {
    partial_initialization(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn engine_owned_drain_cancelled_constructor_joins_successful_sibling() {
    partial_initialization(true).await;
}
