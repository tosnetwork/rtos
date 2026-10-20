/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! getTime, setVerbosity, the private-key exports, getConfig and getStats
//! against the reference engine (evidence: control-surface/oracle getters,
//! export, framing). Data files under tests/data/control-surface come from
//! the reference engine's control port.

use super::{
    key_tests::{ask, ask_object, Node},
    *,
};
use rtos_api::{
    deserialize_boxed,
    ton::{
        engine::validator::{
            ExportedPrivateKeys as ExportedPrivateKeysBoxed, JsonConfig as JsonConfigBoxed,
            KeyHash as KeyHashBoxed, Stats as StatsBoxed, Time as TimeBoxed,
        },
        pub_::publickey::{Aes, Ed25519},
        rpc::engine::validator::{
            ExportAllPrivateKeys, ExportPrivateKey, GenerateKeyPair, GetConfig, GetStats, GetTime,
            SetVerbosity,
        },
    },
};
use rtos_block::{ShardIdent, UInt256};
use std::sync::Mutex;

const DATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/tests/data/control-surface/");

fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

#[tokio::test(flavor = "multi_thread")]
async fn get_time_answers_the_unix_time() {
    let node = Node::start(true).await;
    let before = unix_now();
    let answer = ask_object(&node, 1, GetTime::default()).await.unwrap();
    let time = i64::from(answer.downcast::<TimeBoxed>().unwrap().only().time);
    assert!(before <= time && time <= unix_now() + 1);
    assert_eq!(ask(&node, 2, GetTime::default()).await, Ok(Some((602, "not authorized".into()))));
    node.server.shutdown().await;
    node.handler.stop_and_wait().await.unwrap();
}

struct Recording(Mutex<Vec<log::LevelFilter>>);

impl VerbosityControl for Recording {
    fn set_level(&self, level: log::LevelFilter) -> Result<()> {
        self.0.lock().unwrap().push(level);
        Ok(())
    }
}

static LEVELS: std::sync::OnceLock<Arc<Recording>> = std::sync::OnceLock::new();

struct Shared(Arc<Recording>);

impl VerbosityControl for Shared {
    fn set_level(&self, level: log::LevelFilter) -> Result<()> {
        self.0.set_level(level)
    }
}

#[test]
fn verbosity_maps_onto_log_levels_as_the_reference_levels() {
    use log::LevelFilter::*;
    let expected = [Error, Warn, Info, Debug, Trace, Trace, Trace, Trace, Trace, Trace, Trace];
    for (verbosity, level) in expected.iter().enumerate() {
        assert_eq!(verbosity_level(verbosity as i32), *level, "{verbosity}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn set_verbosity_checks_its_range_and_reaches_the_logging_backend() {
    let recording = LEVELS.get_or_init(|| Arc::new(Recording(Mutex::new(Vec::new())))).clone();
    // The process has one control; it may already be installed by this test.
    let _ = install_verbosity_control(Box::new(Shared(recording.clone())));
    let node = Node::start(true).await;
    let ask_level = |verbosity| SetVerbosity { verbosity };
    for bad in [11, -1, i32::MIN] {
        assert_eq!(
            ask(&node, 1, ask_level(bad)).await,
            Ok(Some((602, "verbosity should be in range [0..10]".into())))
        );
    }
    assert_eq!(ask(&node, 2, ask_level(3)).await, Ok(Some((602, "not authorized".into()))));
    assert!(recording.0.lock().unwrap().is_empty(), "a refused request changes nothing");
    assert_eq!(ask(&node, 1, ask_level(3)).await, Ok(None));
    assert_eq!(ask(&node, 1, ask_level(0)).await, Ok(None));
    assert_eq!(
        *recording.0.lock().unwrap(),
        vec![log::LevelFilter::Debug, log::LevelFilter::Error]
    );
    node.server.shutdown().await;
    node.handler.stop_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn the_single_key_export_is_not_implemented_as_in_the_reference() {
    let node = Node::start(true).await;
    let query = || ExportPrivateKey { key_hash: UInt256::with_array([7; 32]) };
    assert_eq!(ask(&node, 4, query()).await, Ok(Some((651, "not implemented".into()))));
    assert_eq!(ask(&node, 2, query()).await, Ok(Some((602, "not authorized".into()))));
    node.server.shutdown().await;
    node.handler.stop_and_wait().await.unwrap();
}

/// The keys of an exported payload: a size and a serialized private key
/// each, then 32 bytes of padding, as the reference console reads it.
fn exported_keys(payload: &[u8]) -> Vec<rtos_api::ton::PrivateKey> {
    assert!(payload.len() >= 32, "data is too small");
    let mut rest = &payload[..payload.len() - 32];
    let mut keys = Vec::new();
    while !rest.is_empty() {
        let size = u32::from_le_bytes(rest[..4].try_into().unwrap()) as usize;
        let key = deserialize_boxed(&rest[4..4 + size]).unwrap();
        keys.push(key.downcast::<rtos_api::ton::PrivateKey>().unwrap());
        rest = &rest[4 + size..];
    }
    keys
}

fn ed25519_secret(key: &rtos_api::ton::PrivateKey) -> [u8; 32] {
    match key {
        rtos_api::ton::PrivateKey::Pk_Ed25519(key) => key.key.clone().inner(),
        other => panic!("not an Ed25519 key: {other:?}"),
    }
}

fn client_key() -> Arc<dyn KeyOption> {
    get_key_option_factory().from_private_key(&[0x42; 32]).unwrap()
}

#[test]
fn the_reference_engines_export_decrypts_here() {
    let hex = std::fs::read_to_string(format!("{DATA}cpp-exported-private-keys.hex")).unwrap();
    let reply = deserialize_boxed(&hex::decode(hex.trim()).unwrap()).unwrap();
    let reply = reply.downcast::<ExportedPrivateKeysBoxed>().unwrap().only();
    let payload = decrypt_with(&client_key(), &reply.encrypted_data).unwrap();
    let keys = exported_keys(&payload);
    // The reference node exported its Ed25519 keys and an AES key it held.
    assert!(keys.iter().any(|key| matches!(key, rtos_api::ton::PrivateKey::Pk_Ed25519(_))));
    assert!(keys.iter().any(|key| matches!(key, rtos_api::ton::PrivateKey::Pk_Aes(_))));
    let mut tampered = reply.encrypted_data.to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(decrypt_with(&client_key(), &tampered).is_err(), "sha256 mismatch after decryption");
}

#[tokio::test(flavor = "multi_thread")]
async fn every_private_key_is_exported_encrypted_to_the_client() {
    let node = Node::start(true).await;
    let generated = ask_object(&node, 1, GenerateKeyPair::default()).await.unwrap();
    let generated = generated.downcast::<KeyHashBoxed>().unwrap().only().key_hash.inner();
    let aes = ExportAllPrivateKeys {
        encryption_key: PublicKey::Pub_Aes(Aes { key: UInt256::with_array([1; 32]) }),
    };
    assert_eq!(ask(&node, 4, aes).await, Ok(Some((621, "encryption key is not Ed25519".into()))));
    let public: [u8; 32] = client_key().pub_key().unwrap().try_into().unwrap();
    let query = || ExportAllPrivateKeys {
        encryption_key: PublicKey::Pub_Ed25519(Ed25519 { key: UInt256::with_array(public) }),
    };
    assert_eq!(ask(&node, 2, query()).await, Ok(Some((602, "not authorized".into()))));
    let reply = ask_object(&node, 4, query()).await.unwrap();
    let reply = reply.downcast::<ExportedPrivateKeysBoxed>().unwrap().only();
    if let Ok(path) = std::env::var("RTOS_EXPORT_FIXTURE_OUT") {
        // For the reference decryptor: the reply as the console receives it.
        std::fs::write(path, hex::encode(&reply.encrypted_data)).unwrap();
    }
    let ids: Vec<[u8; 32]> =
        exported_keys(&decrypt_with(&client_key(), &reply.encrypted_data).unwrap())
            .iter()
            .map(|key| {
                *get_key_option_factory()
                    .from_private_key(&ed25519_secret(key))
                    .unwrap()
                    .id()
                    .data()
            })
            .collect();
    assert!(ids.contains(&generated), "the generated key is exported");
    let saved = node.saved();
    let own = saved["adnl_node"]["keys"].as_array().unwrap().len();
    // The key ring, the node's identities and the control and lite servers.
    assert_eq!(ids.len(), 1 + own + 2);
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted);
    node.server.shutdown().await;
    node.handler.stop_and_wait().await.unwrap();
}

/// A JSON document from serde values, in the reference encoder's form.
fn to_td(value: &serde_json::Value) -> TdJson {
    match value {
        serde_json::Value::Bool(value) => TdJson::Bool(*value),
        serde_json::Value::Number(number) => TdJson::Int(number.as_i64().unwrap()),
        serde_json::Value::String(text) => TdJson::Str(text.clone()),
        serde_json::Value::Array(items) => TdJson::Arr(items.iter().map(to_td).collect()),
        serde_json::Value::Object(fields) => TdJson::Obj(
            fields
                .iter()
                .map(|(name, value)| {
                    let name: &'static str = Box::leak(name.clone().into_boxed_str());
                    (name, to_td(value))
                })
                .collect(),
        ),
        serde_json::Value::Null => panic!("no null in the configuration"),
    }
}

#[test]
fn the_json_layout_is_the_reference_encoders() {
    let reference = std::fs::read_to_string(format!("{DATA}cpp-getconfig.json")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&reference).unwrap();
    assert_eq!(to_td(&value).encode_pretty(), reference, "byte for byte");
    assert_eq!(TdJson::Arr(vec![]).encode_pretty(), "[\n]\n");
    assert_eq!(TdJson::Str("a\"b\\c\n".into()).encode_pretty(), "\"a\\\"b\\\\c\\n\"\n");
}

/// The field names each typed object carries, in order.
fn field_orders(value: &serde_json::Value, out: &mut Vec<(String, Vec<String>)>) {
    match value {
        serde_json::Value::Object(fields) => {
            if let Some(serde_json::Value::String(name)) = fields.get("@type") {
                out.push((name.clone(), fields.keys().cloned().collect()));
            }
            fields.values().for_each(|value| field_orders(value, out));
        }
        serde_json::Value::Array(items) => items.iter().for_each(|value| field_orders(value, out)),
        _ => (),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn get_config_projects_the_node_in_the_reference_schema() {
    let node = Node::start(true).await;
    let k1 = ask_object(&node, 1, GenerateKeyPair::default()).await.unwrap();
    let k1 = k1.downcast::<KeyHashBoxed>().unwrap().only().key_hash.inner();
    let k2 = ask_object(&node, 1, GenerateKeyPair::default()).await.unwrap();
    let k2 = k2.downcast::<KeyHashBoxed>().unwrap().only().key_hash.inner();
    let h = UInt256::with_array;
    use rtos_api::ton::rpc::engine::validator::{
        AddAdnlId, AddValidatorAdnlAddress, AddValidatorPermanentKey, AddValidatorTempKey,
    };
    assert_eq!(ask(&node, 2, AddAdnlId { key_hash: h(k1), category: 3 }).await, Ok(None));
    let perm = AddValidatorPermanentKey { key_hash: h(k2), election_date: 1000, ttl: -16 };
    assert_eq!(ask(&node, 2, perm).await, Ok(None));
    let temp =
        AddValidatorTempKey { permanent_key_hash: h(k2), key_hash: h(k2), ttl: 2_100_000_000 };
    assert_eq!(ask(&node, 2, temp).await, Ok(None));
    let addr =
        AddValidatorAdnlAddress { permanent_key_hash: h(k2), key_hash: h(k1), ttl: 2_100_000_000 };
    assert_eq!(ask(&node, 2, addr).await, Ok(None));
    assert_eq!(ask(&node, 2, GetConfig::default()).await, Ok(Some((602, "not authorized".into()))));
    let answer = ask_object(&node, 1, GetConfig::default()).await.unwrap();
    let data = answer.downcast::<JsonConfigBoxed>().unwrap().only().data;
    let json: serde_json::Value = serde_json::from_str(&data).unwrap();
    assert_eq!(to_td(&json).encode_pretty(), data, "the reference layout");
    // Every object type the reference engine wrote has its fields in its order.
    let reference: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(format!("{DATA}cpp-getconfig.json")).unwrap(),
    )
    .unwrap();
    let (mut ours, mut theirs) = (Vec::new(), Vec::new());
    field_orders(&json, &mut ours);
    field_orders(&reference, &mut theirs);
    for (name, fields) in &theirs {
        for (our_name, our_fields) in &ours {
            if our_name == name {
                assert_eq!(our_fields, fields, "{name}");
            }
        }
    }
    let top: Vec<&String> = json.as_object().unwrap().keys().collect();
    let reference_top: Vec<&String> = reference.as_object().unwrap().keys().collect();
    assert_eq!(top, reference_top);
    // The node's own content.
    let adnl = json["adnl"].as_array().unwrap();
    assert!(adnl.iter().any(|entry| entry["id"] == base64_encode(k1) && entry["category"] == 3));
    let ids: Vec<Vec<u8>> = adnl
        .iter()
        .map(|entry| rtos_block::base64_decode(entry["id"].as_str().unwrap()).unwrap())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted, "ordered by id, as the reference maps order them");
    let validator = &json["validators"][0];
    assert_eq!(validator["id"], base64_encode(k2));
    assert_eq!(validator["election_date"], 1000);
    assert_eq!(validator["expire_at"], -16, "the wire bits, signed");
    assert_eq!(validator["temp_keys"][0]["key"], base64_encode(k2));
    assert_eq!(validator["adnl_addrs"][0]["id"], base64_encode(k1));
    assert_eq!(json["dht"].as_array().unwrap().len(), 1);
    assert_eq!(json["gc"]["ids"], serde_json::json!([]));
    let control = &json["control"][0];
    assert_eq!(control["@type"], "engine.controlInterface");
    assert_eq!(json["liteservers"][0]["@type"], "engine.liteServer");
    assert!(json.get("fullnodeconfig").is_none() && json.get("extraconfig").is_none());
    node.server.shutdown().await;
    node.handler.stop_and_wait().await.unwrap();
}

struct StateEngine(
    Arc<crate::shard_state::ShardStateStuff>,
    Arc<crate::engine_traits::EngineAlloc>,
);

#[async_trait::async_trait]
impl EngineOperations for StateEngine {
    fn engine_allocated(&self) -> &Arc<crate::engine_traits::EngineAlloc> {
        &self.1
    }
    #[cfg(feature = "telemetry")]
    fn engine_telemetry(&self) -> &Arc<crate::engine_traits::EngineTelemetry> {
        Box::leak(Box::new(crate::collator_test_bundle::create_engine_telemetry()))
    }
    fn load_last_applied_mc_block_id(&self) -> Result<Option<Arc<BlockIdExt>>> {
        Ok(Some(Arc::new(self.0.block_id().clone())))
    }
    async fn load_last_applied_mc_state(&self) -> Result<Arc<crate::shard_state::ShardStateStuff>> {
        Ok(self.0.clone())
    }
    fn load_shard_client_mc_block_id(&self) -> Result<Option<Arc<BlockIdExt>>> {
        Ok(Some(Arc::new(self.0.block_id().clone())))
    }
    // No block handles: the block time falls back to the state's time.
    fn load_block_handle(
        &self,
        _id: &BlockIdExt,
    ) -> Result<Option<Arc<storage::block_handle_db::BlockHandle>>> {
        Ok(None)
    }
}

#[test]
fn block_ids_print_as_the_reference_prints_them() {
    let id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        0,
        UInt256::from_slice(
            &hex::decode("A920CB5933CA2658E25767CBC962FA0C0A73E103F14113A669B5A2DEC5E4D017")
                .unwrap(),
        ),
        UInt256::from_slice(
            &hex::decode("C584D48546047C770D5EEAFF830F746A2DA193EA3B145E793B95089E11E36AEB")
                .unwrap(),
        ),
    );
    // As the reference engine's getStats printed this block.
    assert_eq!(
        block_id_to_str(&id),
        "(-1,8000000000000000,0):A920CB5933CA2658E25767CBC962FA0C0A73E103F14113A669B5A2DEC5E4D017:C584D48546047C770D5EEAFF830F746A2DA193EA3B145E793B95089E11E36AEB"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn get_stats_reports_the_masterchain_under_the_reference_names() {
    let state = crate::test_helper::gen_master_state(
        Default::default(),
        #[cfg(feature = "telemetry")]
        None,
        None,
    );
    let engine = StateEngine(state.clone(), crate::collator_test_bundle::create_engine_allocated());
    let node = Node::start_with_engine(Arc::new(engine)).await;
    let answer = ask_object(&node, 1, GetStats::default()).await.unwrap();
    let stats = answer.downcast::<StatsBoxed>().unwrap().only().stats;
    let stats: Vec<(String, String)> =
        stats.into_iter().map(|stat| (stat.key, stat.value)).collect();
    let id = state.block_id();
    let mut expected = vec![
        ("masterchainblock".to_string(), block_id_to_str(id)),
        ("masterchainblocktime".to_string(), state.state().unwrap().gen_time().to_string()),
    ];
    // A generated state may carry no key block reference.
    if let Ok(key_block) = state.last_keyblock_id() {
        expected.push(("keymasterchainblock".to_string(), block_id_to_str(&key_block)));
    }
    expected.push(("shardclientmasterchainseqno".to_string(), id.seq_no().to_string()));
    expected.push(("stateserializerenabled".to_string(), "true".to_string()));
    assert_eq!(stats[1..], expected[..]);
    assert_eq!(stats[0].0, "unixtime");
    node.server.shutdown().await;
    node.handler.stop_and_wait().await.unwrap();
}

#[test]
fn control_clients_are_listed_as_the_reference_configuration_reads_them() {
    let id = |byte: u8| base64_encode([byte; 32]);
    let view = crate::config::ControlConfigView {
        ip_address: Some("127.0.0.1:47931".into()),
        adnl: vec![],
        dht: vec![],
        fullnode: None,
        validators: vec![],
        lite_server: None,
        control_server: Some(crate::config::ServerView {
            id: id(9),
            port: 47932,
            clients: vec![(id(3), 5), (id(1), 7), (id(3), 0), (id(2), 3), (id(2), 4)],
        }),
        ext_messages_broadcast_disabled: true,
        state_serializer_enabled: false,
        pq_consensus: None,
    };
    let json: serde_json::Value =
        serde_json::from_str(&config_json(&view).unwrap().encode_pretty()).unwrap();
    // A later entry replaces an earlier one, zero removes it; ordered by id.
    assert_eq!(
        json["control"][0]["allowed"],
        serde_json::json!([
            { "@type": "engine.controlProcess", "id": id(1), "permissions": 7 },
            { "@type": "engine.controlProcess", "id": id(2), "permissions": 4 },
        ])
    );
    assert_eq!(json["addrs"][0]["ip"], 2130706433, "as the reference engine wrote 127.0.0.1");
    assert_eq!(json["fullnode"], base64_encode([0; 32]));
    assert_eq!(
        json["fullnodeconfig"],
        serde_json::json!({
            "@type": "engine.validator.fullNodeConfig", "ext_messages_broadcast_disabled": true
        })
    );
    assert_eq!(json["extraconfig"]["state_serializer_enabled"], false);
    assert!(json["extraconfig"].get("pq_consensus").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn get_stats_before_start_is_not_ready() {
    let node = Node::start(false).await;
    assert_eq!(
        ask(&node, 1, GetStats::default()).await,
        Ok(Some((651, "validator manager not started".into())))
    );
    assert_eq!(ask(&node, 2, GetStats::default()).await, Ok(Some((602, "not authorized".into()))));
    node.server.shutdown().await;
    node.handler.stop_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn get_stats_reports_the_reference_names_it_has() {
    let node = Node::start(true).await;
    let answer = ask_object(&node, 1, GetStats::default()).await.unwrap();
    let stats = answer.downcast::<StatsBoxed>().unwrap().only().stats;
    let names: Vec<&str> = stats.iter().map(|stat| stat.key.as_str()).collect();
    // A node without a masterchain state reports the time and the serializer.
    assert_eq!(names, vec!["unixtime", "stateserializerenabled"]);
    assert_eq!(stats[1].value, "true");
    node.server.shutdown().await;
    node.handler.stop_and_wait().await.unwrap();
}

/// An engine that records the custom overlays it is given.
struct OverlayEngine {
    allocated: Arc<crate::engine_traits::EngineAlloc>,
    #[cfg(feature = "telemetry")]
    telemetry: Arc<crate::engine_traits::EngineTelemetry>,
    given: Mutex<Vec<Vec<String>>>,
}

#[async_trait::async_trait]
impl EngineOperations for OverlayEngine {
    fn engine_allocated(&self) -> &Arc<crate::engine_traits::EngineAlloc> {
        &self.allocated
    }
    #[cfg(feature = "telemetry")]
    fn engine_telemetry(&self) -> &Arc<crate::engine_traits::EngineTelemetry> {
        &self.telemetry
    }
    async fn update_custom_overlays(
        &self,
        configs: Option<&[rtos_api::ton::engine::validator::customoverlay::CustomOverlay]>,
    ) -> Result<()> {
        let names = configs.unwrap_or_default().iter().map(|c| c.name.clone()).collect();
        self.given.lock().unwrap().push(names);
        Ok(())
    }
}

/// The reference engine's answer to a recorded console command.
fn reference_failure(command: &str) -> (i32, String) {
    let table = std::fs::read_to_string(format!("{DATA}cpp-console.tsv")).unwrap();
    let row = table.lines().find(|line| line.split('\t').next() == Some(command)).unwrap();
    let output = row.split('\t').nth(2).unwrap();
    let inner = output.split_once("[Error : ").unwrap().1;
    let inner = inner.strip_suffix("]\\n").unwrap();
    let (code, message) = inner.split_once(" : ").unwrap();
    (code.parse().unwrap(), message.to_string())
}

fn overlay(
    name: &str,
    nodes: usize,
) -> rtos_api::ton::engine::validator::customoverlay::CustomOverlay {
    rtos_api::ton::engine::validator::customoverlay::CustomOverlay {
        name: name.to_string(),
        nodes: (0..nodes)
            .map(|i| rtos_api::ton::engine::validator::customoverlaynode::CustomOverlayNode {
                adnl_id: UInt256::from([i as u8 + 1; 32]),
                ..Default::default()
            })
            .collect::<Vec<_>>()
            .into(),
        ..Default::default()
    }
}

/// Custom overlays are added and removed as the reference engine adds and
/// removes them: an empty node list, a name in use and an unknown name are
/// refused with the reference messages, before start every request is not
/// ready, and the engine gets each new list.
#[tokio::test(flavor = "multi_thread")]
async fn custom_overlays_change_as_in_the_reference_engine() {
    use rtos_api::ton::rpc::engine::validator::{
        AddCustomOverlay, DelCustomOverlay, ShowCustomOverlays,
    };
    let engine = Arc::new(OverlayEngine {
        allocated: crate::collator_test_bundle::create_engine_allocated(),
        #[cfg(feature = "telemetry")]
        telemetry: crate::collator_test_bundle::create_engine_telemetry(),
        given: Mutex::new(Vec::new()),
    });
    let node = Node::start_with_engine(engine.clone()).await;
    let empty = AddCustomOverlay { overlay: overlay("ov2", 0) };
    assert_eq!(
        ask(&node, 15, empty).await,
        Ok(Some(reference_failure("add-custom-overlay cases/console2/ov2.json")))
    );
    assert_eq!(ask(&node, 15, AddCustomOverlay { overlay: overlay("ov1", 2) }).await, Ok(None));
    assert_eq!(
        ask(&node, 15, AddCustomOverlay { overlay: overlay("ov1", 1) }).await,
        Ok(Some((0, "duplicate custom overlay name \"ov1\"".to_string())))
    );
    assert_eq!(
        ask(&node, 15, DelCustomOverlay { name: "nosuch".to_string() }).await,
        Ok(Some(reference_failure("del-custom-overlay nosuch")))
    );
    let shown = ask_object(&node, 15, ShowCustomOverlays::default()).await.unwrap();
    let shown =
        shown.downcast::<rtos_api::ton::engine::validator::CustomOverlaysConfig>().unwrap().only();
    assert_eq!(shown.overlays.iter().map(|o| o.name.as_str()).collect::<Vec<_>>(), ["ov1"]);
    assert_eq!(ask(&node, 15, DelCustomOverlay { name: "ov1".to_string() }).await, Ok(None));
    assert_eq!(*engine.given.lock().unwrap(), vec![vec!["ov1".to_string()], vec![]]);
    node.server.shutdown().await;
    node.handler.stop_and_wait().await.unwrap();

    let node = Node::start(false).await;
    let not_started = Ok(Some((651, "not started".to_string())));
    assert_eq!(ask(&node, 15, AddCustomOverlay { overlay: overlay("ov1", 1) }).await, not_started);
    assert_eq!(ask(&node, 15, DelCustomOverlay { name: "ov1".to_string() }).await, not_started);
    assert_eq!(ask(&node, 15, ShowCustomOverlays::default()).await, not_started);
    node.server.shutdown().await;
    node.handler.stop_and_wait().await.unwrap();
}
