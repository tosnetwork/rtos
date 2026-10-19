/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Key commands of the control interface against the reference engine's
//! replies. Every expected code and message below was observed on the
//! reference validator engine's control port, in the same order of commands
//! (evidence: control-surface/oracle keyops). Only the text after "key not in
//! db" depends on how a key ring stores keys and is not compared.

use super::*;
use crate::config::{ConfigEvent, NodeConfigSubscriber, TonNodeConfig};
use adnl::client::{AdnlClient, AdnlClientConfig};
use rtos_api::{
    serialize_boxed,
    ton::{
        engine::validator::{ControlQueryError as ControlQueryErrorBoxed, KeyHash as KeyHashBoxed},
        rpc::engine::validator::{
            AddAdnlId, AddValidatorAdnlAddress, AddValidatorPermanentKey, AddValidatorTempKey,
            DelAdnlId, DelValidatorAdnlAddress, DelValidatorPermanentKey, DelValidatorTempKey,
            ExportPublicKey, GenerateKeyPair, Sign,
        },
    },
    AnyBoxedSerialize,
};
use rtos_block::{base64_encode, UInt256};
use secrets_vault::vault_block::get_key_option_factory;
use std::sync::Mutex;

const SERVER_KEY: &str =
    r#"{"type_id":1209251014,"pvt_key":"cJIxGZviebMQWL726DRejqVzRTSXPv/1sO/ab6XOZXk="}"#;
const SERVER_PUB: &str =
    r#"{"type_id":1209251014,"pub_key":"cujCRU4rQbSw48yHVHxQtRPhUlbo+BuZggFTQSu04Y8="}"#;

struct StartedEngine;

#[async_trait::async_trait]
impl EngineOperations for StartedEngine {
    fn load_last_applied_mc_block_id(&self) -> Result<Option<Arc<rtos_block::BlockIdExt>>> {
        Ok(None)
    }
    fn load_shard_client_mc_block_id(&self) -> Result<Option<Arc<rtos_block::BlockIdExt>>> {
        Ok(None)
    }
}

#[derive(Default)]
pub(super) struct Recorder {
    events: Mutex<Vec<(bool, [u8; 32], i32)>>,
}

#[async_trait::async_trait]
impl NodeConfigSubscriber for Recorder {
    async fn event(&self, event: ConfigEvent) -> Result<bool> {
        let entry = match event {
            ConfigEvent::AddValidatorAdnlKey(id, election) => (true, *id.data(), election),
            ConfigEvent::RemoveValidatorAdnlKey(id, election) => (false, *id.data(), election),
        };
        self.events.lock().unwrap().push(entry);
        Ok(true)
    }
}

struct Client {
    private: serde_json::Value,
    public: serde_json::Value,
}

fn client() -> Client {
    let (private, key) = get_key_option_factory().generate_with_json().unwrap();
    Client {
        private: serde_json::to_value(private).unwrap(),
        public: serde_json::json!({
            "type_id": 1209251014,
            "pub_key": base64_encode(key.pub_key().unwrap()),
        }),
    }
}

pub(super) struct Node {
    pub(super) dir: tempfile::TempDir,
    pub(super) handler: Arc<NodeConfigHandler>,
    pub(super) recorder: Arc<Recorder>,
    pub(super) server: ControlServer,
    clients: Vec<(u32, Client)>,
}

impl Node {
    pub(super) async fn start(started: bool) -> Self {
        Self::start_with(started, serde_json::json!({})).await
    }

    /// A node whose configuration is created from a default configuration
    /// with `extra` fields.
    pub(super) async fn start_with(started: bool, extra: serde_json::Value) -> Self {
        let source = if started {
            DataSource::Engine(Arc::new(StartedEngine))
        } else {
            DataSource::Status(Arc::new(NotStarted))
        };
        Self::start_with_source(source, extra).await
    }

    /// A started node backed by `engine`.
    pub(super) async fn start_with_engine(engine: Arc<dyn EngineOperations>) -> Self {
        Self::start_with_source(DataSource::Engine(engine), serde_json::json!({})).await
    }

    async fn start_with_source(source: DataSource, extra: serde_json::Value) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let configs = dir.path().to_str().unwrap().to_string();
        // The control and lite server sections are only configuration here;
        // the server under test is started separately below.
        let mut default = serde_json::json!({
            "ip_address": "127.0.0.1:47931",
            "control_server_port": 47932,
            "lite_server_port": 47933,
        });
        for (name, value) in extra.as_object().unwrap() {
            default[name] = value.clone();
        }
        std::fs::write(dir.path().join("default_config.json"), default.to_string()).unwrap();
        let config =
            TonNodeConfig::from_file(&configs, "config.json", None, "default_config.json", None)
                .await
                .unwrap();
        let (handler, context) =
            NodeConfigHandler::create(config, tokio::runtime::Handle::current()).unwrap();
        let recorder = Arc::new(Recorder::default());
        handler.clone().start_sheduler(context, vec![recorder.clone()]).unwrap();
        let clients: Vec<(u32, Client)> =
            [1, 2, 4, 15].into_iter().map(|bits| (bits, client())).collect();
        let listed: Vec<serde_json::Value> = clients
            .iter()
            .map(|(bits, client)| {
                let mut entry = client.public.clone();
                entry["permissions"] = (*bits).into();
                entry
            })
            .collect();
        let json = serde_json::json!({
            "address": "127.0.0.1:0",
            "server_key": serde_json::from_str::<serde_json::Value>(SERVER_KEY).unwrap(),
            "clients": { "list": listed },
        });
        let server = ControlServer::with_params(
            AdnlServerConfig::from_json_with_permissions(&json.to_string()).unwrap(),
            source,
            handler.clone(),
            handler.clone(),
            None,
        )
        .await
        .unwrap();
        Self { dir, handler, recorder, server, clients }
    }

    pub(super) async fn connect(&self, bits: u32) -> AdnlClient {
        let (_, client) = self.clients.iter().find(|(b, _)| *b == bits).unwrap();
        let json = serde_json::json!({
            "server_address": self.server.local_addr().to_string(),
            "server_key": serde_json::from_str::<serde_json::Value>(SERVER_PUB).unwrap(),
            "client_key": client.private,
        });
        let (_, config) = AdnlClientConfig::from_json(&json.to_string()).unwrap();
        AdnlClient::connect(&config).await.unwrap()
    }

    pub(super) fn saved(&self) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(self.dir.path().join("config.json")).unwrap())
            .unwrap()
    }

    fn events(&self) -> Vec<(bool, [u8; 32], i32)> {
        self.recorder.events.lock().unwrap().clone()
    }
}

struct NotStarted;
impl StatusReporter for NotStarted {
    fn get_report(&self) -> u32 {
        0
    }
}

/// The reply to one control query on a fresh connection: `Ok(None)` for
/// success, `Ok(Some((code, message)))` for a control error, `Err` when the
/// server closed the connection without a reply.
pub(super) async fn ask<Q: AnyBoxedSerialize>(
    node: &Node,
    bits: u32,
    query: Q,
) -> std::result::Result<Option<(i32, String)>, String> {
    let answer = ask_object(node, bits, query).await?;
    Ok(answer.downcast::<ControlQueryErrorBoxed>().ok().map(|error| {
        let error = error.only();
        (error.code, error.message)
    }))
}

pub(super) async fn ask_object<Q: AnyBoxedSerialize>(
    node: &Node,
    bits: u32,
    query: Q,
) -> std::result::Result<TLObject, String> {
    let mut client = node.connect(bits).await;
    let data = serialize_boxed(&query.into_tl_object()).unwrap();
    let wrapped = ControlQuery { data: data.into() }.into_tl_object().into();
    let answer = client.query(&wrapped).await.map_err(|error| error.to_string());
    if answer.is_ok() {
        client.shutdown().await.unwrap();
    }
    answer
}

fn refused(code: i32, message: &str) -> std::result::Result<Option<(i32, String)>, String> {
    Ok(Some((code, message.to_string())))
}

fn ok() -> std::result::Result<Option<(i32, String)>, String> {
    Ok(None)
}

fn assert_key_not_found(reply: std::result::Result<Option<(i32, String)>, String>, prefix: &str) {
    let (code, message) = reply.unwrap().expect("a refusal");
    assert_eq!(code, 2);
    assert!(message.starts_with(&format!("{prefix}key not in db: ")), "{message}");
}

async fn generate(node: &Node) -> [u8; 32] {
    let answer = ask_object(node, 1, GenerateKeyPair::default()).await.unwrap();
    answer.downcast::<KeyHashBoxed>().unwrap().only().key_hash.inner()
}

fn h(bytes: [u8; 32]) -> UInt256 {
    UInt256::with_array(bytes)
}

fn b64(bytes: [u8; 32]) -> String {
    base64_encode(bytes)
}

fn perm(key: [u8; 32], date: i32, expire: i32) -> AddValidatorPermanentKey {
    AddValidatorPermanentKey { key_hash: h(key), election_date: date, ttl: expire }
}

fn temp(perm: [u8; 32], key: [u8; 32], expire: i32) -> AddValidatorTempKey {
    AddValidatorTempKey { permanent_key_hash: h(perm), key_hash: h(key), ttl: expire }
}

fn addr(perm: [u8; 32], key: [u8; 32], expire: i32) -> AddValidatorAdnlAddress {
    AddValidatorAdnlAddress { permanent_key_hash: h(perm), key_hash: h(key), ttl: expire }
}

fn validator<'a>(saved: &'a serde_json::Value, id: &str) -> Option<&'a serde_json::Value> {
    saved["validator_keys"].as_array()?.iter().find(|key| key["validator_key_id"] == id)
}

#[tokio::test(flavor = "multi_thread")]
async fn key_commands_follow_the_reference_replies_and_effects() {
    let node = Node::start(true).await;
    let full = node.saved()["adnl_node"]["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["tag"] == 2)
        .map(|key| {
            let option: rtos_block::KeyOptionJson =
                serde_json::from_value(key["data"].clone()).unwrap();
            *get_key_option_factory().from_private_key_json(&option).unwrap().id().data()
        })
        .unwrap();
    let k1 = generate(&node).await;
    let k2 = generate(&node).await;
    let k3 = generate(&node).await;
    let k4 = generate(&node).await;
    let unknown = [0x33; 32];

    // addAdnlId: permission, category narrowing (no reply), key lookup, bound.
    let add = |key: [u8; 32], category: i32| AddAdnlId { key_hash: h(key), category };
    assert_eq!(ask(&node, 1, add(k1, 0)).await, refused(602, "not authorized"));
    assert!(ask(&node, 2, add(unknown, 256)).await.is_err(), "closed without a reply");
    assert!(ask(&node, 2, add(k1, -1)).await.is_err(), "closed without a reply");
    assert_key_not_found(ask(&node, 2, add(unknown, 251)).await, "failed to get public key: ");
    assert_eq!(
        ask(&node, 2, add(k1, 251)).await,
        refused(621, "failed to add adnl node: bad category value")
    );
    assert_eq!(ask(&node, 2, add(k1, 250)).await, ok());
    assert_eq!(ask(&node, 2, add(k1, 0)).await, ok());
    let written = node.saved();
    assert_eq!(ask(&node, 2, add(k1, 0)).await, ok());
    assert_eq!(node.saved(), written, "an unchanged id is not written again");
    assert_eq!(written["adnl_ids"], serde_json::json!([{ "id": b64(k1), "category": 0 }]));

    // Permanent keys.
    assert_key_not_found(
        ask(&node, 2, perm(unknown, 1000, 2000000000)).await,
        "failed to get public key: ",
    );
    assert_eq!(ask(&node, 1, perm(k2, 1000, 2000000000)).await, refused(602, "not authorized"));
    assert_eq!(ask(&node, 2, perm(k2, 1000, 2000000000)).await, ok());
    assert_eq!(ask(&node, 2, perm(k2, 1000, 2000000000)).await, ok());
    assert_eq!(ask(&node, 2, perm(k2, 1000, 2000000001)).await, ok());
    assert_eq!(
        ask(&node, 2, perm(k2, 1001, 2000000001)).await,
        refused(621, "failed to add validator permanent key: election date changed")
    );
    assert_eq!(
        ask(&node, 2, perm(k3, 1000, 2000000001)).await,
        refused(621, "failed to add validator permanent key: duplicate election date")
    );
    assert_eq!(ask(&node, 2, perm(k3, 1002, -16)).await, ok());
    assert_eq!(ask(&node, 2, perm(k3, 1002, 5)).await, ok());
    let saved = node.saved();
    // The wire value is the absolute expiry, kept as given.
    assert_eq!(validator(&saved, &b64(k2)).unwrap()["expire_at"], 2000000001);
    assert_eq!(validator(&saved, &b64(k2)).unwrap()["election_id"], 1000);
    assert_eq!(validator(&saved, &b64(k3)).unwrap()["expire_at"], 5);

    // Temporary keys.
    assert_eq!(
        ask(&node, 2, temp(unknown, k4, 2000000000)).await,
        refused(651, "failed to add validator temp key: unknown permanent validator key")
    );
    assert_key_not_found(
        ask(&node, 2, temp(k2, unknown, 2000000000)).await,
        "failed to get public key: ",
    );
    assert_key_not_found(
        ask(&node, 2, temp(unknown, unknown, 2000000000)).await,
        "failed to get public key: ",
    );
    assert_eq!(ask(&node, 2, temp(k2, k4, 2000000000)).await, ok());
    assert_eq!(ask(&node, 2, temp(k2, k4, 2000000000)).await, ok());
    assert_eq!(ask(&node, 2, temp(k2, k4, 2000000005)).await, ok());
    assert_eq!(ask(&node, 1, temp(k2, k4, 2000000000)).await, refused(602, "not authorized"));
    assert_eq!(
        node.saved()["validator_temp_keys"],
        serde_json::json!([{ "validator_key_id": b64(k2), "key_id": b64(k4), "expire_at": 2000000005u32 }])
    );

    // Validator ADNL addresses, and the runtime binding they drive.
    assert_eq!(
        ask(&node, 2, addr(k2, k3, 2000000000)).await,
        refused(
            651,
            "failed to add validator adnl address: to-be-added validator adnl address not in adnl nodes list"
        )
    );
    assert_eq!(
        ask(&node, 2, addr(unknown, k1, 2000000000)).await,
        refused(651, "failed to add validator adnl address: unknown permanent validator key")
    );
    assert_key_not_found(
        ask(&node, 2, addr(k2, unknown, 2000000000)).await,
        "failed to get public key: ",
    );
    assert!(node.events().is_empty());
    assert_eq!(ask(&node, 2, addr(k2, k1, 2000000000)).await, ok());
    node.handler.wait_test_subscribers().await.unwrap();
    assert_eq!(node.events(), vec![(true, k1, 1000)]);
    assert_eq!(ask(&node, 2, addr(k2, k1, 2000000000)).await, ok());
    assert_eq!(ask(&node, 2, addr(k2, k1, 5)).await, ok());
    node.handler.wait_test_subscribers().await.unwrap();
    assert_eq!(
        node.events(),
        vec![(true, k1, 1000), (false, k1, 1000)],
        "an expired address is unbound"
    );
    assert_eq!(ask(&node, 2, addr(k2, k1, 2000000000)).await, ok());
    node.handler.wait_test_subscribers().await.unwrap();
    assert_eq!(node.events().len(), 3);
    let bound = node.handler.get_actual_validator_keys().unwrap();
    let bound = bound.iter().find(|key| key.validator_key_id == b64(k2)).unwrap();
    assert_eq!(bound.validator_adnl_key_id.as_deref(), Some(b64(k1).as_str()));

    // Deletion.
    let del_adnl = |key: [u8; 32]| DelAdnlId { key_hash: h(key) };
    assert_eq!(
        ask(&node, 2, del_adnl(k1)).await,
        refused(602, "failed to del adnl node: adnl addr still in use")
    );
    assert_eq!(
        ask(&node, 2, del_adnl(full)).await,
        refused(602, "failed to del adnl node: adnl addr still in use")
    );
    assert_eq!(ask(&node, 2, del_adnl(unknown)).await, ok());
    assert_eq!(ask(&node, 1, del_adnl(unknown)).await, refused(602, "not authorized"));
    let del_temp = |perm: [u8; 32], key: [u8; 32]| DelValidatorTempKey {
        permanent_key_hash: h(perm),
        key_hash: h(key),
    };
    assert_eq!(
        ask(&node, 2, del_temp(unknown, k4)).await,
        refused(651, "failed to del validator temp key: unknown permanent validator key")
    );
    assert_eq!(ask(&node, 2, del_temp(k2, unknown)).await, ok());
    assert_eq!(ask(&node, 2, del_temp(k2, k4)).await, ok());
    assert_eq!(ask(&node, 2, del_temp(k2, k4)).await, ok());
    // An unreferenced key leaves the key ring.
    assert!(node.handler.find(&k4).is_err());
    let del_addr = |perm: [u8; 32], key: [u8; 32]| DelValidatorAdnlAddress {
        permanent_key_hash: h(perm),
        key_hash: h(key),
    };
    assert_eq!(
        ask(&node, 2, del_addr(unknown, k1)).await,
        refused(651, "failed to del validator adnl addr: unknown permanent validator key")
    );
    assert_eq!(ask(&node, 2, del_addr(k2, unknown)).await, ok());
    assert_eq!(ask(&node, 2, del_addr(k2, k1)).await, ok());
    node.handler.wait_test_subscribers().await.unwrap();
    assert_eq!(node.events().last(), Some(&(false, k1, 1000)));
    assert!(node.handler.find(&k1).is_ok(), "still listed as an ADNL id");
    assert_eq!(ask(&node, 2, del_adnl(k1)).await, ok());
    assert_eq!(ask(&node, 2, del_adnl(k1)).await, ok());
    assert!(node.handler.find(&k1).is_err());
    assert_eq!(ask(&node, 2, temp(k2, k3, 2000000000)).await, ok());
    let del_perm = |key: [u8; 32]| DelValidatorPermanentKey { key_hash: h(key) };
    assert_eq!(ask(&node, 2, del_perm(unknown)).await, ok());
    assert_eq!(ask(&node, 1, del_perm(k2)).await, refused(602, "not authorized"));
    assert_eq!(ask(&node, 2, del_perm(k2)).await, ok());
    assert_eq!(ask(&node, 2, del_perm(k2)).await, ok());
    assert_eq!(
        ask(&node, 2, del_temp(k2, k3)).await,
        refused(651, "failed to del validator temp key: unknown permanent validator key")
    );
    assert!(node.handler.find(&k2).is_err());
    assert!(node.handler.find(&k3).is_ok(), "k3 is still a permanent key");
    assert!(node
        .handler
        .get_actual_validator_keys()
        .unwrap()
        .iter()
        .all(|key| key.validator_key_id != b64(k2)));
    let saved = node.saved();
    assert!(validator(&saved, &b64(k2)).is_none());
    assert!(saved.get("validator_temp_keys").is_none());
    assert!(saved.get("validator_adnl_addresses").is_none());
    assert!(saved.get("adnl_ids").is_none());

    // Unknown keys for the plain key queries.
    let (code, message) =
        ask(&node, 1, ExportPublicKey { key_hash: h(unknown) }).await.unwrap().unwrap();
    assert_eq!(code, 2);
    assert!(message.starts_with("key not in db: "), "{message}");
    let sign = Sign { key_hash: h(unknown), data: b"abc".to_vec().into() };
    let (code, message) = ask(&node, 4, sign).await.unwrap().unwrap();
    assert_eq!(code, 2);
    assert!(message.starts_with("key not in db: "), "{message}");
    node.server.shutdown().await;
    node.handler.stop_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn key_commands_persist_across_a_restart() {
    let node = Node::start(true).await;
    let k1 = generate(&node).await;
    let k2 = generate(&node).await;
    let k3 = generate(&node).await;
    assert_eq!(ask(&node, 2, AddAdnlId { key_hash: h(k1), category: 3 }).await, ok());
    assert_eq!(ask(&node, 2, perm(k2, 1700, 2100000000)).await, ok());
    assert_eq!(ask(&node, 2, temp(k2, k3, 2100000000)).await, ok());
    assert_eq!(ask(&node, 2, addr(k2, k1, 2100000000)).await, ok());
    node.server.shutdown().await;
    node.handler.stop_and_wait().await.unwrap();
    let configs = node.dir.path().to_str().unwrap().to_string();
    let reloaded =
        TonNodeConfig::from_file(&configs, "config.json", None, "default_config.json", None)
            .await
            .unwrap();
    let (handler, context) =
        NodeConfigHandler::create(reloaded, tokio::runtime::Handle::current()).unwrap();
    let recorder = Arc::new(Recorder::default());
    handler.clone().start_sheduler(context, vec![recorder.clone()]).unwrap();
    handler.wait_test_subscribers().await.unwrap();
    assert_eq!(*recorder.events.lock().unwrap(), vec![(true, k1, 1700)], "the binding is restored");
    let keys = handler.get_actual_validator_keys().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].validator_adnl_key_id.as_deref(), Some(b64(k1).as_str()));
    assert!(handler.find(&k3).is_ok());
    let view = handler.control_view().await.unwrap();
    assert!(view.adnl.iter().any(|entry| entry.id == b64(k1) && entry.category == 3));
    let (_, temps, addrs) = &view.validators[0];
    assert_eq!(temps[0].key_id, b64(k3));
    assert_eq!(addrs[0].key_id, b64(k1));
    handler.stop_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_write_reports_the_errno_with_the_change_in_force() {
    use std::os::unix::fs::PermissionsExt;
    let node = Node::start(true).await;
    let k1 = generate(&node).await;
    let before = node.saved();
    let mode = std::fs::metadata(node.dir.path()).unwrap().permissions();
    std::fs::set_permissions(node.dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    let reply = ask(&node, 2, AddAdnlId { key_hash: h(k1), category: 0 }).await.unwrap();
    std::fs::set_permissions(node.dir.path(), mode).unwrap();
    let (code, message) = reply.expect("the write fails");
    assert_eq!(code, libc::EACCES);
    assert!(message.starts_with("failed to add adnl node: "), "{message}");
    assert_eq!(node.saved(), before, "nothing was written");
    // As in the reference engine, the change stays in memory: repeating the
    // command finds nothing to change and writes nothing.
    assert_eq!(ask(&node, 2, AddAdnlId { key_hash: h(k1), category: 0 }).await, ok());
    assert_eq!(node.saved(), before);
    let view = node.handler.control_view().await.unwrap();
    assert!(view.adnl.iter().any(|entry| entry.id == b64(k1)));
    node.server.shutdown().await;
    node.handler.stop_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn key_commands_before_start_are_not_ready_and_change_nothing() {
    let node = Node::start(false).await;
    let k1 = generate(&node).await;
    let before = node.saved();
    for reply in [
        ask(&node, 2, AddAdnlId { key_hash: h(k1), category: 0 }).await,
        ask(&node, 2, AddAdnlId { key_hash: h(k1), category: 300 }).await,
        ask(&node, 2, perm(k1, 1000, 2000000000)).await,
        ask(&node, 2, temp(k1, k1, 2000000000)).await,
        ask(&node, 2, addr(k1, k1, 2000000000)).await,
        ask(&node, 2, DelAdnlId { key_hash: h(k1) }).await,
        ask(&node, 2, DelValidatorPermanentKey { key_hash: h(k1) }).await,
        ask(&node, 2, DelValidatorTempKey { permanent_key_hash: h(k1), key_hash: h(k1) }).await,
        ask(&node, 2, DelValidatorAdnlAddress { permanent_key_hash: h(k1), key_hash: h(k1) }).await,
    ] {
        assert_eq!(reply, refused(651, "not started"));
    }
    // The permission check comes first.
    assert_eq!(ask(&node, 1, perm(k1, 1000, 2000000000)).await, refused(602, "not authorized"));
    assert_eq!(node.saved(), before);
    node.server.shutdown().await;
    node.handler.stop_and_wait().await.unwrap();
}
