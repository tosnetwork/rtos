/*
 * RTOS project modifications (2026-10-10): isolated configuration test output.
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use super::*;

fn make_test_config_handler() -> NodeConfigHandler {
    let (sender, _reader) = tokio::sync::mpsc::unbounded_channel();
    NodeConfigHandler {
        scheduler: Arc::default(),
        runtime_handle: tokio::runtime::Handle::current(),
        sender,
        key_ring: Arc::new(lockfree::map::Map::new()),
        validator_keys: Arc::new(ValidatorKeys::new()),
    }
}

#[tokio::test]
async fn test_custom_overlays_serde() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let output = dir.path().join("custom_overlays.json");
    let path = output.to_str().expect("temporary path must be UTF-8");
    for _ in 0..100 {
        let mut overlays = Vec::new();
        for _ in 0..rand::random::<u32>() % 5 {
            let mut nodes = Vec::new();
            for _ in 0..rand::random::<u32>() % 12 {
                let adnl_id = UInt256::rand();
                let msg_sender = rand::random::<bool>();
                let msg_sender_priority = rand::random::<u32>();
                let block_sender = rand::random::<bool>();
                nodes.push(CustomOverlayNode {
                    adnl_id,
                    msg_sender: msg_sender.into(),
                    msg_sender_priority: msg_sender_priority as i32,
                    block_sender: block_sender.into(),
                });
            }
            let mut sender_shards = Vec::new();
            for _ in 0..(rand::random::<u32>() % 2) + 1 {
                let workchain = rand::random::<i32>();
                let shard = (rand::random::<u64>() & 0xFFFF_0000_0000_0000) | 0x0000_1000_0000_0000;
                sender_shards
                    .push(ton::ton_node::shardid::ShardId { workchain, shard: shard as i64 });
            }
            let name = format!("overlay_{}", UInt256::rand().to_hex_string());
            let skip_public_msg_send = rand::random::<bool>();
            let use_quic = rand::random::<bool>();
            let overlay = CustomOverlay {
                name,
                nodes,
                sender_shards,
                skip_public_msg_send: skip_public_msg_send.into(),
                use_quic: use_quic.into(),
            };
            overlays.push(overlay);
        }
        let coc = CustomOverlaysConfigBoxed::Engine_Validator_CustomOverlaysConfig(
            CustomOverlaysConfig { overlays },
        );

        TonNodeConfig::save_custom_overlays_json(&coc, path).await?;
        let loaded_coc = TonNodeConfig::load_custom_overlays_json(path)?;
        let _ = std::fs::remove_file(path);
        assert_eq!(format!("{:?}", coc), format!("{:?}", loaded_coc));
    }
    Ok(())
}

#[tokio::test]
async fn test_get_actual_validator_key_ids_uses_validator_key_order() -> Result<()> {
    let config_handler = make_test_config_handler();

    let key_a = Ed25519KeyOption::<ZeroizingBytes>::generate()?;
    let key_b = Ed25519KeyOption::<ZeroizingBytes>::generate()?;
    let key_c = Ed25519KeyOption::<ZeroizingBytes>::generate()?;

    // Intentionally add keys in election order that differs from validator key order.
    config_handler.validator_keys.add(ValidatorKeysJson {
        expire_at: i32::MAX,
        election_id: 30,
        validator_key_id: base64_encode(key_b.id().data()),
        validator_adnl_key_id: None,
    })?;
    config_handler.validator_keys.add(ValidatorKeysJson {
        expire_at: i32::MAX,
        election_id: 10,
        validator_key_id: base64_encode(key_c.id().data()),
        validator_adnl_key_id: None,
    })?;
    config_handler.validator_keys.add(ValidatorKeysJson {
        expire_at: i32::MAX,
        election_id: 20,
        validator_key_id: base64_encode(key_a.id().data()),
        validator_adnl_key_id: None,
    })?;
    // Duplicate key in another election is still one local validator key.
    config_handler.validator_keys.add(ValidatorKeysJson {
        expire_at: i32::MAX,
        election_id: 40,
        validator_key_id: base64_encode(key_b.id().data()),
        validator_adnl_key_id: None,
    })?;

    let mut expected = vec![*key_a.id().data(), *key_b.id().data(), *key_c.id().data()];
    expected.sort_unstable();
    expected.dedup();

    let actual = config_handler.get_actual_validator_key_ids()?;
    let actual: Vec<[u8; 32]> = actual.iter().map(|key_id| *key_id.data()).collect();

    assert_eq!(actual, expected);
    Ok(())
}

#[test]
fn test_network_zerostate_requires_complete_masterchain_anchor() {
    let good = serde_json::json!({"validator": {"zero_state": {
        "workchain": -1, "shard": i64::MIN, "seqno": 0,
        "root_hash": "01".repeat(32), "file_hash": "02".repeat(32)
    }}});
    let parse = |value| -> Result<BlockIdExt> {
        serde_json::from_value::<TonNodeGlobalConfigJson>(value)?.zero_state()
    };
    let id = parse(good.clone()).unwrap();
    assert!(id.shard().is_masterchain_ext());
    assert_eq!(id.seq_no, 0);
    for (field, value) in [
        ("workchain", serde_json::json!(0)),
        ("shard", serde_json::json!(0x4000000000000000i64)),
        ("seqno", serde_json::json!(1)),
        ("seqno", serde_json::json!(-1)),
        ("seqno", serde_json::json!(u64::from(u32::MAX) + 1)),
        ("root_hash", serde_json::json!("00".repeat(32))),
        ("file_hash", serde_json::json!("00".repeat(32))),
        ("file_hash", serde_json::Value::Null),
        ("root_hash", serde_json::Value::Null),
    ] {
        let mut value_json = good.clone();
        value_json["validator"]["zero_state"][field] = value;
        assert!(parse(value_json).is_err(), "invalid {field}");
    }
}

#[test]
fn test_initial_checkpoint_is_an_explicit_complete_local_pin() {
    let zero = serde_json::json!({
        "workchain": -1, "shard": i64::MIN, "seqno": 0,
        "root_hash": "01".repeat(32), "file_hash": "02".repeat(32)
    });
    let mut init = zero.clone();
    init["seqno"] = serde_json::json!(10);
    let parse = |init| -> Result<Option<BlockIdExt>> {
        serde_json::from_value::<TonNodeGlobalConfigJson>(
            serde_json::json!({"validator": {"zero_state": zero, "init_block": init}}),
        )?
        .init_block()
    };
    assert_eq!(parse(init.clone()).unwrap().unwrap().seq_no, 10);
    assert_eq!(parse(zero.clone()).unwrap().unwrap().seq_no, 0);
    let mut maximum = init.clone();
    maximum["seqno"] = serde_json::json!(u32::MAX);
    assert_eq!(parse(maximum).unwrap().unwrap().seq_no, u32::MAX);
    for (field, value) in [
        ("workchain", serde_json::json!(0)),
        ("shard", serde_json::json!(0x4000000000000000i64)),
        ("seqno", serde_json::json!(-1)),
        ("seqno", serde_json::json!(u64::from(u32::MAX) + 1)),
        ("root_hash", serde_json::json!("00".repeat(32))),
        ("file_hash", serde_json::Value::Null),
    ] {
        let mut bad = init.clone();
        bad[field] = value;
        assert!(parse(bad).is_err());
    }
    let mut other_zero = zero.clone();
    other_zero["file_hash"] = serde_json::json!("03".repeat(32));
    assert!(parse(other_zero).is_err());
}

fn scheduler_test_config() -> TonNodeConfig {
    serde_json::from_value(serde_json::json!({
        "validator_keys": [], "validator_key_ring": {}
    }))
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_scheduler_stop_releases_actor_and_rejects_new_writes() {
    let (handler, context) =
        NodeConfigHandler::create(scheduler_test_config(), tokio::runtime::Handle::current())
            .unwrap();
    handler.clone().start_sheduler(context, vec![]).unwrap();
    handler.show_custom_overlays().await.unwrap();
    handler.stop_and_wait().await.unwrap();
    assert!(handler.show_custom_overlays().await.is_err());
    assert!(handler.get_key_raw([7; 32]).await.is_none());
    handler.stop_and_wait().await.unwrap();
    let weak = Arc::downgrade(&handler);
    drop(handler);
    assert!(weak.upgrade().is_none(), "scheduler retained its own sender");
}

struct HeldConfigSubscriber {
    handler: Arc<NodeConfigHandler>,
    entered: tokio::sync::Notify,
    release: tokio::sync::Semaphore,
    completed: atomic::AtomicBool,
    panic: bool,
}

#[async_trait::async_trait]
impl NodeConfigSubscriber for HeldConfigSubscriber {
    async fn event(&self, _: ConfigEvent) -> Result<bool> {
        self.entered.notify_one();
        self.release.acquire().await.unwrap().forget();
        if self.panic {
            panic!("controlled configuration subscriber failure");
        }
        // This uses the real GetKey request queue after public admission closed.
        assert!(self.handler.get_key_raw([7; 32]).await.is_none());
        self.completed.store(true, atomic::Ordering::Release);
        Ok(true)
    }
}

fn scheduler_subscriber_config() -> TonNodeConfig {
    let mut config = scheduler_test_config();
    config.validator_keys = Some(vec![ValidatorKeysJson {
        expire_at: i32::MAX,
        election_id: 1001,
        validator_key_id: base64_encode([8; 32]),
        validator_adnl_key_id: Some(base64_encode([7; 32])),
    }]);
    config
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_scheduler_drain_serves_accepted_callback_lookup_after_cancelled_waiter() {
    let (handler, context) =
        NodeConfigHandler::create(scheduler_subscriber_config(), tokio::runtime::Handle::current())
            .unwrap();
    let subscriber = Arc::new(HeldConfigSubscriber {
        handler: handler.clone(),
        entered: Default::default(),
        release: tokio::sync::Semaphore::new(0),
        completed: atomic::AtomicBool::new(false),
        panic: false,
    });
    handler.clone().start_sheduler(context, vec![subscriber.clone()]).unwrap();
    subscriber.entered.notified().await;
    let waiter_handler = handler.clone();
    let waiter = tokio::spawn(async move { waiter_handler.stop_and_wait().await });
    tokio::task::yield_now().await;
    waiter.abort();
    let _ = waiter.await;
    assert!(tokio::time::timeout(Duration::from_millis(30), handler.stop_and_wait())
        .await
        .is_err());
    assert!(handler.show_custom_overlays().await.is_err());
    subscriber.release.add_permits(1);
    tokio::time::timeout(Duration::from_secs(3), handler.stop_and_wait()).await.unwrap().unwrap();
    assert!(subscriber.completed.load(atomic::Ordering::Acquire));
    let weak_handler = Arc::downgrade(&handler);
    let weak_subscriber = Arc::downgrade(&subscriber);
    drop(subscriber);
    drop(handler);
    assert!(weak_subscriber.upgrade().is_none());
    assert!(weak_handler.upgrade().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_scheduler_subscriber_panic_is_sticky_after_real_join() {
    let (handler, context) =
        NodeConfigHandler::create(scheduler_subscriber_config(), tokio::runtime::Handle::current())
            .unwrap();
    let subscriber = Arc::new(HeldConfigSubscriber {
        handler: handler.clone(),
        entered: Default::default(),
        release: tokio::sync::Semaphore::new(1),
        completed: atomic::AtomicBool::new(false),
        panic: true,
    });
    handler.clone().start_sheduler(context, vec![subscriber.clone()]).unwrap();
    subscriber.entered.notified().await;
    for _ in 0..2 {
        let error = tokio::time::timeout(Duration::from_secs(3), handler.stop_and_wait())
            .await
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("configuration subscriber"));
    }
    let weak = Arc::downgrade(&handler);
    drop(subscriber);
    drop(handler);
    assert!(weak.upgrade().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_scheduler_partial_load_failure_drains_started_callbacks() {
    let mut config = scheduler_subscriber_config();
    config.validator_keys.as_mut().unwrap().push(ValidatorKeysJson {
        expire_at: i32::MAX,
        election_id: 1002,
        validator_key_id: base64_encode([9; 32]),
        validator_adnl_key_id: Some("invalid base64!".into()),
    });
    let (handler, context) =
        NodeConfigHandler::create(config, tokio::runtime::Handle::current()).unwrap();
    let subscriber = Arc::new(HeldConfigSubscriber {
        handler: handler.clone(),
        entered: Default::default(),
        release: tokio::sync::Semaphore::new(0),
        completed: atomic::AtomicBool::new(false),
        panic: false,
    });
    assert!(handler.clone().start_sheduler(context, vec![subscriber.clone()]).is_err());
    subscriber.entered.notified().await;
    assert!(handler.show_custom_overlays().await.is_err());
    subscriber.release.add_permits(1);
    tokio::time::timeout(Duration::from_secs(3), handler.stop_and_wait()).await.unwrap().unwrap();
    assert!(subscriber.completed.load(atomic::Ordering::Acquire));
    let weak = Arc::downgrade(&handler);
    drop(subscriber);
    drop(handler);
    assert!(weak.upgrade().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_scheduler_commits_accepted_write_before_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = scheduler_test_config();
    config.custom_overlays_file_name = dir.path().join("overlays.json").to_str().unwrap().into();
    let (handler, context) =
        NodeConfigHandler::create(config, tokio::runtime::Handle::current()).unwrap();
    handler.clone().start_sheduler(context, vec![]).unwrap();
    let overlay = CustomOverlay {
        name: "accepted-before-stop".into(),
        nodes: vec![],
        sender_shards: vec![],
        skip_public_msg_send: false.into(),
        use_quic: false.into(),
    };
    let (wait, mut reader) = Wait::new();
    wait.request();
    handler.send_task((wait.clone(), Task::AddCustomOverlay(overlay))).unwrap();
    handler.stop_and_wait().await.unwrap();
    assert!(matches!(
        wait.wait(&mut reader, true).await,
        Some(Some(Answer::CustomOverlays(Ok(_))))
    ));
    let stored = std::fs::read_to_string(dir.path().join("overlays.json")).unwrap();
    assert!(stored.contains("accepted-before-stop"));
}

#[tokio::test]
async fn config_scheduler_stop_before_start_rejects_lookups_without_waiting() {
    let (handler, context) =
        NodeConfigHandler::create(scheduler_test_config(), tokio::runtime::Handle::current())
            .unwrap();
    handler.stop_and_wait().await.unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(1), handler.get_key_raw([7; 32]))
        .await
        .unwrap()
        .is_none());
    assert!(handler.clone().start_sheduler(context, vec![]).is_err());
}

#[tokio::test]
async fn config_scheduler_dropped_inbox_and_current_answer_wake_callers() {
    let (sent, received) = tokio::sync::mpsc::unbounded_channel();
    let (queued, mut queued_answer) = Wait::new();
    queued.request();
    assert!(sent.send((queued.clone(), Task::GetKey([7; 32]))).is_ok());
    drop(scheduler::ConfigInbox(received));
    assert!(matches!(queued.wait(&mut queued_answer, true).await, Some(None)));
    let (current, mut current_answer) = Wait::new();
    current.request();
    drop(PendingAnswer::new(current.clone()));
    assert!(matches!(current.wait(&mut current_answer, true).await, Some(None)));
}
