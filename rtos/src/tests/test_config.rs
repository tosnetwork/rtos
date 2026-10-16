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
        validator_transport_changed: tokio::sync::Notify::new(),
        validator_transport_revision: std::sync::Mutex::new(0),
        runtime_handle: tokio::runtime::Handle::current(),
        sender,
        key_ring: Arc::new(lockfree::map::Map::new()),
        validator_keys: Arc::new(ValidatorKeys::new()),
        consensus_transport_bindings: Vec::new(),
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
    events: std::sync::Mutex<Vec<u8>>,
}

#[async_trait::async_trait]
impl NodeConfigSubscriber for HeldConfigSubscriber {
    async fn event(&self, event: ConfigEvent) -> Result<bool> {
        self.entered.notify_one();
        self.release.acquire().await.unwrap().forget();
        if self.panic {
            panic!("controlled configuration subscriber failure");
        }
        // This uses the real GetKey request queue after public admission closed.
        let (key_id, kind) = match event {
            ConfigEvent::AddValidatorAdnlKey(id, _) => (id, 1),
            ConfigEvent::RemoveValidatorAdnlKey(id, _) => (id, 2),
        };
        let key = self
            .handler
            .get_key_raw(*key_id.data())
            .await
            .expect("accepted callback lookup must still be served during shutdown");
        assert_eq!(key.id(), &key_id);
        self.events.lock().unwrap().push(kind);
        self.completed.store(true, atomic::Ordering::Release);
        Ok(true)
    }
}

fn scheduler_subscriber_config() -> TonNodeConfig {
    let mut config = scheduler_test_config();
    // Public deterministic test key, never a node/operator secret.
    let (json, key) =
        Ed25519KeyOption::<ZeroizingBytes>::from_private_key_with_json(&[71; 32]).unwrap();
    config.validator_key_ring = Some(HashMap::from([(base64_encode(key.id().data()), json)]));
    config.validator_keys = Some(vec![ValidatorKeysJson {
        expire_at: i32::MAX,
        election_id: 1001,
        validator_key_id: base64_encode([8; 32]),
        validator_adnl_key_id: Some(base64_encode(key.id().data())),
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
        events: Default::default(),
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
        events: Default::default(),
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
        events: Default::default(),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_scheduler_removal_callback_is_ordered_and_can_reenter_lookup_during_stop() {
    let config = scheduler_subscriber_config();
    let key_id = KeyId::from_data(
        base64_decode(
            config.validator_keys.as_ref().unwrap()[0].validator_adnl_key_id.as_ref().unwrap(),
        )
        .unwrap()
        .try_into()
        .unwrap(),
    );
    let (handler, context) =
        NodeConfigHandler::create(config, tokio::runtime::Handle::current()).unwrap();
    let subscriber = Arc::new(HeldConfigSubscriber {
        handler: handler.clone(),
        entered: Default::default(),
        release: tokio::sync::Semaphore::new(0),
        completed: atomic::AtomicBool::new(false),
        panic: false,
        events: Default::default(),
    });
    handler.clone().start_sheduler(context, vec![subscriber.clone()]).unwrap();
    subscriber.entered.notified().await;
    // This is the same dispatch method used by actual validator-key retirement.
    handler.dispatch_config_event(
        subscriber.clone(),
        ConfigEvent::RemoveValidatorAdnlKey(key_id.clone(), 1001),
    );
    handler.stop();
    for _ in 0..16 {
        assert!(
            tokio::time::timeout(Duration::from_millis(100), handler.get_key_raw(*key_id.data()))
                .await
                .unwrap()
                .is_none(),
            "external reads must not prolong shutdown"
        );
    }
    assert!(subscriber.events.lock().unwrap().is_empty());
    subscriber.release.add_permits(2);
    tokio::time::timeout(Duration::from_secs(3), handler.stop_and_wait()).await.unwrap().unwrap();
    assert_eq!(*subscriber.events.lock().unwrap(), vec![1, 2]);
    let weak = Arc::downgrade(&handler);
    drop(subscriber);
    drop(handler);
    assert!(weak.upgrade().is_none());
}

struct RotationConfigSubscriber {
    handler: Arc<NodeConfigHandler>,
    retained_key: Arc<KeyId>,
    events: std::sync::Mutex<Vec<(u8, i32)>>,
}

#[async_trait::async_trait]
impl NodeConfigSubscriber for RotationConfigSubscriber {
    async fn event(&self, event: ConfigEvent) -> Result<bool> {
        let key = self
            .handler
            .get_key_raw(*self.retained_key.data())
            .await
            .expect("rotation callback must reenter the real actor and read the retained key");
        assert_eq!(key.id(), &self.retained_key);
        let entry = match event {
            ConfigEvent::AddValidatorAdnlKey(_, election) => (1, election),
            ConfigEvent::RemoveValidatorAdnlKey(_, election) => (2, election),
        };
        self.events.lock().unwrap().push(entry);
        Ok(true)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_scheduler_fourth_election_retires_old_key_without_callback_deadlock() {
    // All identities below are public deterministic test seeds. This test uses
    // only its temporary JSON config and the ordinary non-vault key backend.
    assert!(get_vault().is_none(), "isolated configuration fixture requires no global vault");
    let dir = tempfile::tempdir().unwrap();
    let mut config = scheduler_test_config();
    config.configs_dir = dir.path().to_str().unwrap().into();
    config.file_name = "config.json".into();
    let mut validator_ids = vec![];
    let mut adnl_ids = vec![];
    for index in 0..4u8 {
        let (validator_json, validator) =
            Ed25519KeyOption::<ZeroizingBytes>::from_private_key_with_json(&[101 + index; 32])
                .unwrap();
        let (adnl_json, adnl) =
            Ed25519KeyOption::<ZeroizingBytes>::from_private_key_with_json(&[111 + index; 32])
                .unwrap();
        let ring = config.validator_key_ring.as_mut().unwrap();
        ring.insert(base64_encode(validator.id().data()), validator_json);
        ring.insert(base64_encode(adnl.id().data()), adnl_json);
        if index < 3 {
            config.validator_keys.as_mut().unwrap().push(ValidatorKeysJson {
                expire_at: i32::MAX,
                election_id: 1001 + i32::from(index),
                validator_key_id: base64_encode(validator.id().data()),
                validator_adnl_key_id: Some(base64_encode(adnl.id().data())),
            });
        }
        validator_ids.push(validator.id().clone());
        adnl_ids.push(adnl.id().clone());
    }
    let (handler, context) =
        NodeConfigHandler::create(config, tokio::runtime::Handle::current()).unwrap();
    let subscriber = Arc::new(RotationConfigSubscriber {
        handler: handler.clone(),
        retained_key: adnl_ids[3].clone(),
        events: Default::default(),
    });
    handler.clone().start_sheduler(context, vec![subscriber.clone()]).unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        handler.add_validator_key(validator_ids[3].data(), 1004, i32::MAX).await.unwrap();
        // This public command invokes actual revision_validator_keys at four
        // registrations and emits Remove for the oldest, unshared ADNL key.
        handler.add_validator_adnl_key(validator_ids[3].data(), adnl_ids[3].data()).await.unwrap();
    })
    .await
    .expect("the fourth registration must not wait on its own GetKey queue");
    assert!(handler.find(adnl_ids[0].data()).is_err());
    assert!(handler.find(validator_ids[0].data()).is_err());
    assert!(handler.sign_data(adnl_ids[0].data(), b"retired key").is_err());
    assert!(handler.sign_data(validator_ids[0].data(), b"retired key").is_err());
    assert!(handler.get_key_raw(*adnl_ids[0].data()).await.is_none());
    assert!(handler.get_key_raw(*validator_ids[0].data()).await.is_none());
    assert!(handler.get_key_raw(*adnl_ids[3].data()).await.is_some());
    tokio::time::timeout(Duration::from_secs(3), handler.stop_and_wait()).await.unwrap().unwrap();
    assert_eq!(
        *subscriber.events.lock().unwrap(),
        vec![(1, 1001), (1, 1002), (1, 1003), (1, 1004), (2, 1001)]
    );
    let saved: TonNodeConfig =
        serde_json::from_slice(&std::fs::read(dir.path().join("config.json")).unwrap()).unwrap();
    let saved_keys = saved.validator_keys.unwrap();
    assert_eq!(saved_keys.len(), 3);
    assert!(!saved_keys.iter().any(|entry| entry.election_id == 1001));
    assert!(saved_keys.iter().any(|entry| entry.election_id == 1004));
    let saved_ring = saved.validator_key_ring.unwrap();
    assert!(!saved_ring.contains_key(&base64_encode(adnl_ids[0].data())));
    assert!(!saved_ring.contains_key(&base64_encode(validator_ids[0].data())));
    assert!(saved_ring.contains_key(&base64_encode(adnl_ids[3].data())));
    let weak = Arc::downgrade(&handler);
    drop(subscriber);
    drop(handler);
    assert!(weak.upgrade().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_scheduler_rotation_keeps_shared_key_until_last_role_is_retired() {
    assert!(get_vault().is_none(), "isolated fixture requires no global vault");
    let dir = tempfile::tempdir().unwrap();
    let mut config = scheduler_test_config();
    config.configs_dir = dir.path().to_str().unwrap().into();
    config.file_name = "config.json".into();
    let mut validators = Vec::new();
    let mut transports = Vec::new();
    for index in 0..6u8 {
        let (json, key) =
            Ed25519KeyOption::<ZeroizingBytes>::from_private_key_with_json(&[151 + index; 32])
                .unwrap();
        config.validator_key_ring.as_mut().unwrap().insert(base64_encode(key.id().data()), json);
        validators.push(key.id().clone());
        let (json, key) =
            Ed25519KeyOption::<ZeroizingBytes>::from_private_key_with_json(&[161 + index; 32])
                .unwrap();
        config.validator_key_ring.as_mut().unwrap().insert(base64_encode(key.id().data()), json);
        transports.push(key.id().clone());
    }
    // The same private key is used by two validator registrations and two ADNL
    // bindings. After election 1002 retires, it remains needed only as ADNL.
    for (index, validator, adnl) in [
        (0, &validators[0], &validators[0]),
        (1, &validators[0], &transports[1]),
        (2, &validators[2], &validators[0]),
    ] {
        config.validator_keys.as_mut().unwrap().push(ValidatorKeysJson {
            expire_at: i32::MAX,
            election_id: 1001 + index,
            validator_key_id: base64_encode(validator.data()),
            validator_adnl_key_id: Some(base64_encode(adnl.data())),
        });
    }
    let (handler, context) =
        NodeConfigHandler::create(config, tokio::runtime::Handle::current()).unwrap();
    let subscriber = Arc::new(RotationConfigSubscriber {
        handler: handler.clone(),
        retained_key: transports[5].clone(),
        events: Default::default(),
    });
    handler.clone().start_sheduler(context, vec![subscriber.clone()]).unwrap();
    for index in 3..6 {
        tokio::time::timeout(Duration::from_secs(3), async {
            handler
                .add_validator_key(validators[index].data(), 1001 + index as i32, i32::MAX)
                .await
                .unwrap();
            handler
                .add_validator_adnl_key(validators[index].data(), transports[index].data())
                .await
                .unwrap();
        })
        .await
        .unwrap();
        let saved: TonNodeConfig =
            serde_json::from_slice(&std::fs::read(dir.path().join("config.json")).unwrap())
                .unwrap();
        assert_eq!(saved.validator_keys.as_ref().unwrap().len(), 3);
        let retained = index < 5;
        assert_eq!(
            saved
                .validator_key_ring
                .as_ref()
                .unwrap()
                .contains_key(&base64_encode(validators[0].data())),
            retained
        );
        assert_eq!(handler.get_key_raw(*validators[0].data()).await.is_some(), retained);
        assert_eq!(handler.find(validators[0].data()).is_ok(), retained);
        if retained {
            let signature =
                handler.sign_data(validators[0].data(), b"shared transport key").unwrap();
            handler
                .find(validators[0].data())
                .unwrap()
                .verify(b"shared transport key", &signature)
                .unwrap();
        } else {
            assert!(handler.sign_data(validators[0].data(), b"retired shared key").is_err());
        }
        if index >= 4 {
            assert!(handler.find(transports[1].data()).is_err());
            assert!(handler.get_key_raw(*transports[1].data()).await.is_none());
        }
    }
    handler.stop_and_wait().await.unwrap();
    assert_eq!(
        *subscriber.events.lock().unwrap(),
        vec![
            (1, 1001),
            (1, 1002),
            (1, 1003),
            (1, 1004),
            (1, 1005),
            (2, 1002),
            (1, 1006),
            (2, 1003),
        ]
    );
    let weak = Arc::downgrade(&handler);
    drop(subscriber);
    drop(handler);
    assert!(weak.upgrade().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_scheduler_vault_rotation_retains_shared_private_key() {
    const CHILD: &str = "RTOS_CONFIG_VAULT_ROTATION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        // The vault factory is process-global. Only the child sees this public
        // fixture's encrypted file, without altering concurrent tests' backend.
        let dir = tempfile::tempdir().unwrap();
        let url = format!(
            "file://{}?master_key={}",
            dir.path().join("vault.json").display(),
            "42".repeat(32)
        );
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "config::tests::config_scheduler_vault_rotation_retains_shared_private_key",
                "--exact",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("VAULT_URL", url)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "vault rotation child timed out: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("vault rotation child completed"));
        return;
    }
    let vault = get_vault().expect("child must use the real encrypted file vault");
    let mut config = scheduler_test_config();
    let mut keys = Vec::new();
    for seed in [181u8, 182] {
        let (json, key) = get_key_option_factory().from_private_key_with_json(&[seed; 32]).unwrap();
        let id = base64_encode(key.id().data());
        SecretsVaultConfig::save_private_key(&id, &json, &key).await.unwrap();
        config.validator_key_ring.as_mut().unwrap().insert(id, json);
        keys.push(key);
    }
    let shared = base64_encode(keys[0].id().data());
    let other = base64_encode(keys[1].id().data());
    let private_id = make_secret_id!(SecretsVaultConfig::SID_PRIVATE_KEYS, &shared);
    let metadata_id = make_secret_id!(SecretsVaultConfig::SID_VALIDATOR_KEYS, &shared);
    for (election_id, validator) in [(1001, &shared), (1002, &shared), (1003, &other)] {
        let registration = ValidatorKeysJson {
            expire_at: i32::MAX,
            election_id,
            validator_key_id: validator.clone(),
            validator_adnl_key_id: Some(shared.clone()),
        };
        SecretsVaultConfig::save_validator_key(&registration).await.unwrap();
        config.validator_keys.as_mut().unwrap().push(registration);
    }
    for election in 1001..=1003 {
        let id = if election == 1003 { &other } else { &shared };
        assert!(config.remove_validator_key(id.clone(), election).await.unwrap());
        let retired = config.remove_key_from_key_ring(&shared).await.unwrap();
        assert_eq!(retired, election == 1003);
        vault.flush().await.unwrap();
        // A second backend instance reads the actual persisted file after every
        // transition, including the interval with only an ADNL role remaining.
        let reopened = secrets_vault::vault_builder::SecretVaultBuilder::from_url(
            &std::env::var("VAULT_URL").unwrap(),
            BlockCryptoFactory {}.new_crypto().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(reopened.exists(&private_id).await.unwrap(), election < 1003);
        assert_eq!(reopened.exists(&metadata_id).await.unwrap(), election < 1002);
        if election < 1003 {
            let restored = reopened.load(&private_id).await.unwrap();
            let Secret::Blob { blob } = restored else { panic!("expected stored private key") };
            let data = blob.data();
            let locked = data.lock().unwrap();
            assert_eq!(&locked[..32], &[181u8; 32]);
        }
    }
    // Idempotent cleanup tolerates records already absent in the real backend.
    assert!(config.remove_key_from_key_ring(&shared).await.unwrap());
    println!("vault rotation child completed");
}

// This isolated child hook induces a real file-backend write failure.
pub(super) fn block_retirement_vault_write(namespace: &str) {
    if std::env::var("RTOS_RETIREMENT_FAIL_NAMESPACE").ok().as_deref() == Some(namespace) {
        if let Some(path) = std::env::var_os("RTOS_RETIREMENT_BLOCK_PATH") {
            std::fs::create_dir_all(path).unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn config_scheduler_vault_failure_retries_retirement() {
    const CHILD: &str = "RTOS_RETIREMENT_FAILURE_CHILD";
    let Ok(namespace) = std::env::var(CHILD) else {
        let mut failures = Vec::new();
        for namespace in
            [SecretsVaultConfig::SID_VALIDATOR_KEYS, SecretsVaultConfig::SID_PRIVATE_KEYS]
        {
            let dir = tempfile::tempdir().unwrap();
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "config::tests::config_scheduler_vault_failure_retries_retirement",
                    "--exact",
                    "--nocapture",
                ])
                .env(CHILD, namespace)
                .env(
                    "VAULT_URL",
                    format!(
                        "file://{}?master_key={}",
                        dir.path().join("vault.json").display(),
                        "43".repeat(32)
                    ),
                )
                .env("RTOS_RETIREMENT_BLOCK_PATH", dir.path().join("vault.tmp"))
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            while child.try_wait().unwrap().is_none() {
                if std::time::Instant::now() >= deadline {
                    child.kill().unwrap();
                    panic!("retirement child timed out: {:?}", child.wait_with_output().unwrap());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let output = child.wait_with_output().unwrap();
            eprintln!(
                "{namespace}: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            if !output.status.success()
                || !String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed")
                || !String::from_utf8_lossy(&output.stderr)
                    .contains(&format!("ACTUAL_VAULT_WRITE_FAILED {namespace}:"))
                || !String::from_utf8_lossy(&output.stdout)
                    .contains(&format!("RETIREMENT_CHILD_COMPLETED {namespace}"))
            {
                failures.push(namespace);
            }
        }
        assert!(failures.is_empty(), "failed cuts: {failures:?}");
        return;
    };
    let vault = get_vault().expect("actual file vault");
    let dir = tempfile::tempdir().unwrap();
    let mut config = scheduler_test_config();
    config.configs_dir = dir.path().to_str().unwrap().into();
    config.file_name = "config.json".into();
    let mut keys = Vec::new();
    for seed in 191u8..196 {
        let (_, key) = config
            .import_private_key(PrivateKey::Pk_Ed25519(Ed25519Private {
                key: UInt256::with_array([seed; 32]),
            }))
            .unwrap();
        let id = base64_encode(key.id().data());
        let json = &config.validator_key_ring.as_ref().unwrap()[&id];
        SecretsVaultConfig::save_private_key(&id, json, &key).await.unwrap();
        keys.push(key);
    }
    // Key 0 retires. Key 1 keeps a role in another election.
    for (index, adnl) in [(0, 1), (1, 1), (2, 2)] {
        let entry = ValidatorKeysJson {
            expire_at: i32::MAX,
            election_id: 1001 + index as i32,
            validator_key_id: base64_encode(keys[index].id().data()),
            validator_adnl_key_id: Some(base64_encode(keys[adnl].id().data())),
        };
        SecretsVaultConfig::save_validator_key(&entry).await.unwrap();
        config.validator_keys.as_mut().unwrap().push(entry);
    }
    let (handler, context) =
        NodeConfigHandler::create(config, tokio::runtime::Handle::current()).unwrap();
    handler.clone().start_sheduler(context, vec![]).unwrap();
    handler.add_validator_key(keys[3].id().data(), 1004, i32::MAX).await.unwrap();
    assert!(handler.find(keys[0].id().data()).is_ok());
    assert!(handler.get_key_raw(*keys[0].id().data()).await.is_some());
    assert!(handler.sign_data(keys[0].id().data(), b"before retirement").is_ok());
    std::env::set_var("RTOS_RETIREMENT_FAIL_NAMESPACE", &namespace);
    let result = handler.add_validator_adnl_key(keys[3].id().data(), keys[4].id().data()).await;
    assert!(result.is_err(), "real file write must fail at {namespace}");
    eprintln!("ACTUAL_VAULT_WRITE_FAILED {namespace}: {}", result.unwrap_err());
    assert!(
        handler.find(keys[0].id().data()).is_err(),
        "pending retirement must deny new runtime lookup"
    );
    assert!(handler.sign_data(keys[0].id().data(), b"pending").is_err());
    assert!(handler.get_key_raw(*keys[0].id().data()).await.is_none());
    assert!(handler.find(keys[1].id().data()).is_ok());
    assert!(handler.get_key_raw(*keys[1].id().data()).await.is_some());
    assert!(handler.sign_data(keys[1].id().data(), b"retained").is_ok());
    std::env::remove_var("RTOS_RETIREMENT_FAIL_NAMESPACE");
    std::fs::remove_dir(std::env::var_os("RTOS_RETIREMENT_BLOCK_PATH").unwrap()).unwrap();
    for _ in 0..2 {
        handler.add_validator_adnl_key(keys[3].id().data(), keys[4].id().data()).await.unwrap();
        assert!(handler.find(keys[0].id().data()).is_err());
        assert!(handler.sign_data(keys[0].id().data(), b"retired").is_err());
        assert!(handler.get_key_raw(*keys[0].id().data()).await.is_none());
        let saved: TonNodeConfig =
            serde_json::from_slice(&std::fs::read(dir.path().join("config.json")).unwrap())
                .unwrap();
        assert_eq!(saved.validator_keys.as_ref().unwrap().len(), 3);
        assert!(saved.validator_keys.as_ref().unwrap().iter().all(|k| k.election_id != 1001));
        assert!(!saved
            .validator_key_ring
            .as_ref()
            .unwrap()
            .contains_key(&base64_encode(keys[0].id().data())));
        let reopened = secrets_vault::vault_builder::SecretVaultBuilder::from_url(
            &std::env::var("VAULT_URL").unwrap(),
            BlockCryptoFactory {}.new_crypto().unwrap(),
        )
        .await
        .unwrap();
        for namespace in
            [SecretsVaultConfig::SID_PRIVATE_KEYS, SecretsVaultConfig::SID_VALIDATOR_KEYS]
        {
            assert!(!reopened
                .exists(&make_secret_id!(namespace, base64_encode(keys[0].id().data())))
                .await
                .unwrap());
            assert!(reopened
                .exists(&make_secret_id!(namespace, base64_encode(keys[1].id().data())))
                .await
                .unwrap());
        }
    }
    handler.stop_and_wait().await.unwrap();
    // No unrelated store/flush may mask NOT_FOUND compensation on retry.
    let id = base64_encode(keys[0].id().data());
    let record = make_secret_id!(&namespace, &id);
    if namespace == SecretsVaultConfig::SID_PRIVATE_KEYS {
        let (json, _) = get_key_option_factory().from_private_key_with_json(&[191; 32]).unwrap();
        SecretsVaultConfig::save_private_key(&id, &json, &keys[0]).await.unwrap();
    } else {
        SecretsVaultConfig::save_validator_key(&ValidatorKeysJson {
            expire_at: i32::MAX,
            election_id: 1001,
            validator_key_id: id.clone(),
            validator_adnl_key_id: None,
        })
        .await
        .unwrap();
    }
    std::env::set_var("RTOS_RETIREMENT_FAIL_NAMESPACE", &namespace);
    let delete = || async {
        if namespace == SecretsVaultConfig::SID_PRIVATE_KEYS {
            SecretsVaultConfig::on_drop(&id).await
        } else {
            SecretsVaultConfig::drop_validator_metadata(&id).await
        }
    };
    assert!(delete().await.is_err());
    assert!(
        !vault.exists(&record).await.unwrap(),
        "file backend already removed the memory record"
    );
    let reopen = || async {
        secrets_vault::vault_builder::SecretVaultBuilder::from_url(
            &std::env::var("VAULT_URL").unwrap(),
            BlockCryptoFactory {}.new_crypto().unwrap(),
        )
        .await
        .unwrap()
    };
    assert!(reopen().await.exists(&record).await.unwrap(), "failed write still exists on disk");
    std::env::remove_var("RTOS_RETIREMENT_FAIL_NAMESPACE");
    std::fs::remove_dir(std::env::var_os("RTOS_RETIREMENT_BLOCK_PATH").unwrap()).unwrap();
    delete().await.unwrap();
    assert!(
        !reopen().await.exists(&record).await.unwrap(),
        "NOT_FOUND retry must persist deletion"
    );
    // Retirement prevents new acquisition, not use of an Arc returned earlier.
    assert!(keys[0].sign(b"previously acquired capability").is_ok());
    drop(vault);
    println!("RETIREMENT_CHILD_COMPLETED {namespace}");
}

#[tokio::test]
async fn explicit_consensus_transport_has_no_validator_signing_identity() -> Result<()> {
    let (json, key) = Ed25519KeyOption::<ZeroizingBytes>::from_private_key_with_json(&[91; 32])?;
    let mut config = scheduler_test_config();
    config.validator_key_ring = Some(HashMap::from([(base64_encode(key.id().data()), json)]));
    config.consensus_transport_bindings = vec![ConsensusTransportBindingJson {
        validator_id: base64_encode([92; 32]), adnl_key_id: base64_encode(key.id().data()),
    }];
    let (handler, context) = NodeConfigHandler::create(config, tokio::runtime::Handle::current())?;
    handler.clone().start_sheduler(context, vec![])?;
    let result = async {
        anyhow::ensure!(!handler.get_validator_status());
        anyhow::ensure!(handler.get_actual_validator_keys()?.is_empty());
        let bindings = handler.consensus_transport_bindings()?;
        anyhow::ensure!(bindings.len() == 1 && bindings[0].validator_id == UInt256::from([92; 32]));
        anyhow::ensure!(handler.consensus_transport_key(key.id()).await?.id() == key.id());
        anyhow::ensure!(handler.get_validator_key(key.id()).await.is_none());
        anyhow::ensure!(handler.consensus_transport_key(&KeyId::from_data([93; 32])).await.is_err());
        Ok::<_, anyhow::Error>(())
    }.await;
    handler.stop_and_wait().await?;
    result
}

#[tokio::test]
async fn explicit_consensus_transport_rejects_duplicate_missing_and_wrong_keys() -> Result<()> {
    let binding = ConsensusTransportBindingJson { validator_id: base64_encode([92; 32]), adnl_key_id: base64_encode([93; 32]) };
    for same_stable in [true, false] {
        let mut config = scheduler_test_config();
        let mut other = binding.clone();
        if same_stable { other.adnl_key_id = base64_encode([94; 32]); }
        else { other.validator_id = base64_encode([94; 32]); }
        config.consensus_transport_bindings = vec![binding.clone(), other];
        anyhow::ensure!(NodeConfigHandler::create(config, tokio::runtime::Handle::current()).is_err());
    }
    for wrong_key in [false, true] {
        let mut config = scheduler_test_config();
        config.consensus_transport_bindings = vec![binding.clone()];
        if wrong_key {
            let (json, _) = Ed25519KeyOption::<ZeroizingBytes>::from_private_key_with_json(&[91; 32])?;
            config.validator_key_ring = Some(HashMap::from([(binding.adnl_key_id.clone(), json)]));
        }
        let (handler, context) = NodeConfigHandler::create(config, tokio::runtime::Handle::current())?;
        anyhow::ensure!(handler.clone().start_sheduler(context, vec![]).is_err());
        handler.stop_and_wait().await?;
    }
    Ok(())
}

#[test]
fn durable_config_replacement_preserves_old_file_on_failure() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("config.json");
    write_config_durable(&path, br#"{"version":1}"#)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))?;
    }
    write_config_durable(&path, br#"{"version":2}"#)?;
    assert_eq!(std::fs::read(&path)?, br#"{"version":2}"#);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path)?.permissions().mode() & 0o777, 0o640);
        let link = dir.path().join("linked.json");
        std::os::unix::fs::symlink(&path, &link)?;
        write_config_durable(&link, br#"{"version":3}"#)?;
        assert!(std::fs::symlink_metadata(&link)?.file_type().is_symlink());
        assert_eq!(std::fs::read(&path)?, br#"{"version":3}"#);
    }
    // Native rename refusal must leave the existing directory and its data intact.
    let blocked = dir.path().join("directory.json");
    std::fs::create_dir(&blocked)?;
    std::fs::write(blocked.join("sentinel"), b"retained")?;
    assert!(write_config_durable(&blocked, br#"{"version":4}"#).is_err());
    assert_eq!(std::fs::read(blocked.join("sentinel"))?, b"retained");
    assert!(std::fs::read_dir(dir.path())?.all(|entry| !entry.unwrap().file_name().to_string_lossy().ends_with(".tmp")));
    Ok(())
}
