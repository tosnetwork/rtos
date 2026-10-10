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
    let id = engine.zerostate_id().clone();
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
    let auxiliary = a.overlays_router().unwrap().hold_test_auxiliary_listeners().await.unwrap();
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
    for release in auxiliary {
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(
            !stopping.is_finished(),
            "Engine returned before all real fast/custom listeners joined"
        );
        release.send(()).unwrap();
    }
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
    let overlay = engine.network.context().stack.overlay.clone();
    let profile = overlay.wire_profile();
    let file_hash = engine.zerostate_id().file_hash();
    let base_id = adnl::OverlayUtils::calc_overlay_short_id_with_profile(
        0,
        i64::MIN,
        file_hash.as_slice(),
        profile,
    )
    .unwrap();
    assert!(overlay.get_query_prefix(&base_id).is_ok(), "base overlay was never registered");
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
    assert!(overlay.get_query_prefix(&base_id).is_err(), "partial protocol registration leaked");
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

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn engine_owned_drain_top_shard_writer_flushes_accepted_work_and_reports_failures() {
    struct Writer {
        entered: tokio::sync::Notify,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
        writes: std::sync::atomic::AtomicUsize,
        errors: std::sync::Mutex<Vec<String>>,
    }
    #[async_trait::async_trait]
    impl EngineOperations for Writer {
        fn remove_top_shard_block(
            &self,
            _: &crate::types::top_block_descr::TopBlockDescrId,
        ) -> Result<()> {
            let index = self.writes.fetch_add(1, Ordering::SeqCst);
            if index == 0 {
                self.entered.notify_one();
                self.release.lock().unwrap().recv().unwrap();
            }
            if index != 1 {
                fail!("controlled persistence failure {index}");
            }
            Ok(())
        }
        fn report_service_failure(&self, mask: u32, error: String) {
            assert_eq!(mask, 0);
            self.errors.lock().unwrap().push(error);
        }
    }
    let (release, held) = std::sync::mpsc::channel();
    let writer = Arc::new(Writer {
        entered: tokio::sync::Notify::new(),
        release: std::sync::Mutex::new(held),
        writes: Default::default(),
        errors: Default::default(),
    });
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    for _ in 0..3 {
        sender.send(crate::shard_blocks::StoreAction::Remove(Default::default())).unwrap();
    }
    let owner = Arc::new(crate::types::owned_tasks::OwnedTasks::new(
        tokio_util::sync::CancellationToken::new(),
    ));
    owner
        .spawn_handle("actual top shard writer", || {
            save_top_shard_blocks_worker(writer.clone(), receiver, owner.cancellation().clone())
        })
        .unwrap();
    writer.entered.notified().await;
    let stopping_owner = owner.clone();
    let stopping = tokio::spawn(async move { stopping_owner.wait().await });
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert!(!stopping.is_finished(), "storage writer was not actually joined");
    release.send(()).unwrap();
    stopping.await.unwrap().unwrap();
    assert_eq!(
        writer.writes.load(Ordering::SeqCst),
        3,
        "accepted writes were dropped at cancellation"
    );
    assert_eq!(writer.errors.lock().unwrap().len(), 2, "storage failures were lost");
    assert!(sender.send(crate::shard_blocks::StoreAction::Remove(Default::default())).is_err());
    assert_eq!(Arc::strong_count(&writer), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn engine_owned_drain_cancelled_waiter_retains_server_and_sticky_failure() {
    struct HeldServer {
        started: tokio::sync::oneshot::Sender<()>,
        gate: tokio::sync::Mutex<tokio::sync::oneshot::Receiver<()>>,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }
    #[async_trait::async_trait]
    impl Stoppable for HeldServer {
        fn name(&self) -> &'static str {
            "controlled held server"
        }
        async fn shutdown(self: Box<Self>) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.started.send(()).unwrap();
            self.gate.into_inner().await.unwrap();
            panic!("controlled terminal server failure");
        }
    }
    let dir = tempfile::tempdir().unwrap();
    config(dir.path());
    let engine = open(dir.path()).await;
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (started, entered) = tokio::sync::oneshot::channel();
    let (release, gate) = tokio::sync::oneshot::channel();
    engine.servers.push(Box::new(HeldServer {
        started,
        gate: tokio::sync::Mutex::new(gate),
        calls: calls.clone(),
    }));
    let first = tokio::spawn(engine.clone().wait_stop());
    tokio::time::timeout(Duration::from_secs(10), entered).await.unwrap().unwrap();
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    assert!(tokio::time::timeout(Duration::from_millis(30), engine.clone().wait_stop())
        .await
        .is_err());
    release.send(()).unwrap();
    for _ in 0..2 {
        let error = tokio::time::timeout(Duration::from_secs(15), engine.clone().wait_stop())
            .await
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("controlled held server shutdown panicked"));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let weak = Arc::downgrade(&engine);
    drop(engine);
    assert!(weak.upgrade().is_none());
    stopped(open(dir.path()).await).await;
}

async fn server_construction_race(cancel_startup: bool) {
    struct SocketServer {
        stop: tokio::sync::oneshot::Sender<()>,
        worker: tokio::task::JoinHandle<()>,
        exits: Arc<std::sync::atomic::AtomicUsize>,
    }
    #[async_trait::async_trait]
    impl Stoppable for SocketServer {
        fn name(&self) -> &'static str {
            "held socket server"
        }
        async fn shutdown(self: Box<Self>) {
            self.stop.send(()).unwrap();
            self.worker.await.unwrap();
            self.exits.fetch_add(1, Ordering::SeqCst);
        }
    }
    let dir = tempfile::tempdir().unwrap();
    config(dir.path());
    let engine = open(dir.path()).await;
    let (entered, address) = tokio::sync::oneshot::channel();
    let (release, held) = tokio::sync::oneshot::channel();
    let exits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let worker_exits = exits.clone();
    let starting_engine = engine.clone();
    let starting = tokio::spawn(async move {
        starting_engine
            .start_owned_server("held constructor", async move {
                let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let address = socket.local_addr().unwrap();
                let (stop, wait) = tokio::sync::oneshot::channel();
                let worker = tokio::spawn(async move {
                    wait.await.unwrap();
                    drop(socket);
                });
                entered.send(address).unwrap();
                held.await.unwrap();
                Ok(Box::new(SocketServer { stop, worker, exits: worker_exits })
                    as Box<dyn Stoppable>)
            })
            .await
    });
    let address = tokio::time::timeout(Duration::from_secs(5), address).await.unwrap().unwrap();
    assert!(std::net::TcpListener::bind(address).is_err());
    if cancel_startup {
        starting.abort();
    } else {
        engine.start_shutdown().unwrap();
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(30), engine.clone().wait_stop()).await.is_err(),
        "shutdown forgot a constructor that already owns a live socket worker"
    );
    assert_eq!(exits.load(Ordering::SeqCst), 0);
    assert!(engine.start_owned_server("late constructor", async { unreachable!() }).await.is_err());
    release.send(()).unwrap();
    let result = starting.await;
    if cancel_startup {
        assert!(result.unwrap_err().is_cancelled());
    } else {
        assert!(result.unwrap().is_err(), "stopped constructor became externally ready");
    }
    stopped(engine.clone()).await;
    assert_eq!(exits.load(Ordering::SeqCst), 1);
    drop(std::net::TcpListener::bind(address).expect("server socket leaked"));
    let weak = Arc::downgrade(&engine);
    drop(engine);
    assert!(weak.upgrade().is_none());
    stopped(open(dir.path()).await).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn engine_owned_drain_cancelled_server_constructor_waiter_preserves_live_worker() {
    server_construction_race(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn engine_owned_drain_concurrent_server_constructor_and_stop_closes_admission() {
    server_construction_race(false).await;
}
