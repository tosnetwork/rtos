/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Control-plane authorization against the reference engine's model: a
//! client the server does not list is refused before its query is decoded,
//! a listed client needs the bits each query requires, and unserved queries
//! are refused as unsupported.

use super::*;
use adnl::{
    client::{AdnlClient, AdnlClientConfig},
    common::Answer,
};
use rtos_api::{
    serialize_boxed,
    ton::{
        engine::validator::{
            ControlQueryError as ControlQueryErrorBoxed, KeyHash as KeyHashBoxed,
            Signature as SignatureBoxed,
        },
        rpc::engine::validator::{AddDhtId, ControlQuery, GetTime},
    },
    AnyBoxedSerialize,
};
use rtos_block::{base64_encode, KeyOption};
use secrets_vault::vault_block::get_key_option_factory;
use std::sync::atomic::{AtomicUsize, Ordering};

const SERVER_KEY: &str =
    r#"{"type_id":1209251014,"pvt_key":"cJIxGZviebMQWL726DRejqVzRTSXPv/1sO/ab6XOZXk="}"#;
const SERVER_PUB: &str =
    r#"{"type_id":1209251014,"pub_key":"cujCRU4rQbSw48yHVHxQtRPhUlbo+BuZggFTQSu04Y8="}"#;

/// A key ring that counts what it is asked to do.
struct CountingKeyRing {
    key: Arc<dyn KeyOption>,
    generated: AtomicUsize,
    imported: AtomicUsize,
    signed: AtomicUsize,
}

impl CountingKeyRing {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            key: get_key_option_factory().generate().unwrap(),
            generated: AtomicUsize::new(0),
            imported: AtomicUsize::new(0),
            signed: AtomicUsize::new(0),
        })
    }
    fn key_hash(&self) -> [u8; 32] {
        *self.key.id().data()
    }
    fn untouched(&self) -> bool {
        self.generated.load(Ordering::SeqCst) == 0
            && self.imported.load(Ordering::SeqCst) == 0
            && self.signed.load(Ordering::SeqCst) == 0
    }
}

#[async_trait::async_trait]
impl KeyRing for CountingKeyRing {
    async fn generate(&self, _key_type: i32) -> Result<[u8; 32]> {
        self.generated.fetch_add(1, Ordering::SeqCst);
        Ok(self.key_hash())
    }
    async fn import_private_key(&self, _key: PrivateKey) -> Result<[u8; 32]> {
        self.imported.fetch_add(1, Ordering::SeqCst);
        Ok(self.key_hash())
    }
    fn find(&self, key_hash: &[u8; 32]) -> Result<Arc<dyn KeyOption>> {
        if key_hash != &self.key_hash() {
            fail!("unknown key")
        }
        Ok(self.key.clone())
    }
    fn sign_data(&self, key_hash: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
        let key = self.find(key_hash)?;
        self.signed.fetch_add(1, Ordering::SeqCst);
        key.sign(data)
    }
}

struct Status;
impl StatusReporter for Status {
    fn get_report(&self) -> u32 {
        0
    }
}

struct Client {
    private: serde_json::Value,
    public: serde_json::Value,
    id: [u8; 32],
}

fn client() -> Client {
    let (private, key) = get_key_option_factory().generate_with_json().unwrap();
    Client {
        private: serde_json::to_value(private).unwrap(),
        public: serde_json::json!({
            "type_id": 1209251014,
            "pub_key": base64_encode(key.pub_key().unwrap()),
        }),
        id: *key.id().data(),
    }
}

fn listed(client: &Client, permissions: Option<serde_json::Value>) -> serde_json::Value {
    let mut entry = client.public.clone();
    if let Some(permissions) = permissions {
        entry["permissions"] = permissions;
    }
    entry
}

fn server_config(clients: serde_json::Value) -> AdnlServerConfig {
    let json = serde_json::json!({
        "address": "127.0.0.1:0",
        "server_key": serde_json::from_str::<serde_json::Value>(SERVER_KEY).unwrap(),
        "clients": clients,
    });
    AdnlServerConfig::from_json_with_permissions(&json.to_string()).unwrap()
}

fn node_config() -> Arc<NodeConfigHandler> {
    let config: crate::config::TonNodeConfig = serde_json::from_str("{}").unwrap();
    let (handler, _context) =
        NodeConfigHandler::create(config, tokio::runtime::Handle::current()).unwrap();
    handler
}

async fn start(clients: serde_json::Value, key_ring: Arc<CountingKeyRing>) -> ControlServer {
    ControlServer::with_params(
        server_config(clients),
        DataSource::Status(Arc::new(Status)),
        key_ring,
        node_config(),
        None,
    )
    .await
    .unwrap()
}

async fn connect(server: &ControlServer, client: &Client) -> AdnlClient {
    let json = serde_json::json!({
        "server_address": server.local_addr().to_string(),
        "server_key": serde_json::from_str::<serde_json::Value>(SERVER_PUB).unwrap(),
        "client_key": client.private,
    });
    let (_, config) = AdnlClientConfig::from_json(&json.to_string()).unwrap();
    AdnlClient::connect(&config).await.unwrap()
}

/// Sends a control query and returns the reply object.
async fn ask<Q: AnyBoxedSerialize>(client: &mut AdnlClient, query: Q) -> TLObject {
    let data = serialize_boxed(&query.into_tl_object()).unwrap();
    ask_raw(client, data).await
}

async fn ask_raw(client: &mut AdnlClient, data: Vec<u8>) -> TLObject {
    let wrapped = ControlQuery { data: data.into() }.into_tl_object().into();
    client.query(&wrapped).await.unwrap()
}

fn refusal(answer: TLObject) -> Option<(i32, String)> {
    answer.downcast::<ControlQueryErrorBoxed>().ok().map(|error| {
        let error = error.only();
        (error.code, error.message)
    })
}

fn forbidden() -> Option<(i32, String)> {
    Some((602, "forbidden".to_string()))
}

fn not_authorized() -> Option<(i32, String)> {
    Some((602, "not authorized".to_string()))
}

fn sign(key_ring: &CountingKeyRing) -> Sign {
    Sign { key_hash: UInt256::with_array(key_ring.key_hash()), data: b"payload".to_vec().into() }
}

#[test]
fn served_queries_require_the_reference_bits() {
    let expected: Vec<(TLObject, u32)> = vec![
        (GenerateKeyPair::default().into_tl_object(), VEP_DEFAULT),
        (ImportPrivateKey::default().into_tl_object(), VEP_DEFAULT),
        (ExportPublicKey::default().into_tl_object(), VEP_DEFAULT),
        (Sign::default().into_tl_object(), VEP_UNSAFE),
        (AddValidatorPermanentKey::default().into_tl_object(), VEP_MODIFY),
        (AddValidatorTempKey::default().into_tl_object(), VEP_MODIFY),
        (AddValidatorAdnlAddress::default().into_tl_object(), VEP_MODIFY),
        (AddAdnlId::default().into_tl_object(), VEP_MODIFY),
        (GetStats::default().into_tl_object(), VEP_DEFAULT),
        (GetConfig::default().into_tl_object(), VEP_DEFAULT),
        (AddCustomOverlay::default().into_tl_object(), VEP_MODIFY),
        (DelCustomOverlay::default().into_tl_object(), VEP_MODIFY),
        (ShowCustomOverlays::default().into_tl_object(), VEP_DEFAULT),
        (SignShardOverlayCertificate::default().into_tl_object(), VEP_MODIFY),
        (ImportShardOverlayCertificate::default().into_tl_object(), VEP_MODIFY),
        (SetExtMessagesBroadcastDisabled::default().into_tl_object(), VEP_MODIFY),
    ];
    for (query, bits) in expected {
        assert_eq!(required_permission(&query), Some(bits), "{query:?}");
    }
    for (query, bits) in [
        (GetTime::default().into_tl_object(), VEP_DEFAULT),
        (SetVerbosity::default().into_tl_object(), VEP_DEFAULT),
        (ExportPrivateKey::default().into_tl_object(), VEP_UNSAFE),
        (ExportAllPrivateKeys::default().into_tl_object(), VEP_UNSAFE),
        (DelAdnlId::default().into_tl_object(), VEP_MODIFY),
        (DelValidatorPermanentKey::default().into_tl_object(), VEP_MODIFY),
        (DelValidatorTempKey::default().into_tl_object(), VEP_MODIFY),
        (DelValidatorAdnlAddress::default().into_tl_object(), VEP_MODIFY),
    ] {
        assert_eq!(required_permission(&query), Some(bits), "{query:?}");
    }
    assert_eq!(required_permission(&AddDhtId::default().into_tl_object()), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unlisted_client_is_forbidden_on_a_reused_connection() {
    let key_ring = CountingKeyRing::new();
    let listed_client = client();
    let stranger = client();
    let server = start(
        serde_json::json!({ "list": [listed(&listed_client, Some(7.into()))] }),
        key_ring.clone(),
    )
    .await;
    let mut connection = connect(&server, &stranger).await;
    assert_eq!(refusal(ask(&mut connection, GetStats::default()).await), forbidden());
    assert_eq!(refusal(ask(&mut connection, sign(&key_ring)).await), forbidden());
    assert_eq!(refusal(ask(&mut connection, GenerateKeyPair::default()).await), forbidden());
    // Unparsable and unsupported payloads are refused the same way.
    assert_eq!(refusal(ask_raw(&mut connection, vec![1, 2, 3]).await), forbidden());
    assert_eq!(refusal(ask(&mut connection, GetTime::default()).await), forbidden());
    assert!(key_ring.untouched(), "a refused client must not reach the key ring");
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn undecodable_bytes_are_authorized_before_decoding() {
    let key_ring = CountingKeyRing::new();
    let member = client();
    let stranger = client();
    let subscriber = ControlQuerySubscriber::new(
        DataSource::Status(Arc::new(Status)),
        key_ring.clone(),
        node_config(),
        None,
        Arc::new([(member.id, VEP_DEFAULT)].into_iter().collect()),
    )
    .unwrap();
    let local = KeyId::from_data([9; 32]);
    let garbage = [0xff_u8; 7];
    let reply = |result: Option<QueryResult>| match result {
        Some(QueryResult::Consumed(QueryAnswer::Ready(Some(Answer::Object(object))))) => {
            refusal(object.object)
        }
        _ => panic!("no ready reply"),
    };
    let stranger_peers = AdnlPeers::with_keys(local.clone(), KeyId::from_data(stranger.id));
    assert_eq!(
        reply(subscriber.consume_raw(&garbage, &stranger_peers).await.unwrap()),
        forbidden()
    );
    let member_peers = AdnlPeers::with_keys(local, KeyId::from_data(member.id));
    let (code, message) =
        reply(subscriber.consume_raw(&garbage, &member_peers).await.unwrap()).unwrap();
    assert_eq!(code, 0);
    assert!(message.starts_with("failed to parse validator query: "), "{message}");
}

#[tokio::test(flavor = "multi_thread")]
async fn clients_without_permissions_are_forbidden() {
    let key_ring = CountingKeyRing::new();
    let absent = client();
    let zero = client();
    let server = start(
        serde_json::json!({ "list": [listed(&absent, None), listed(&zero, Some(0.into()))] }),
        key_ring.clone(),
    )
    .await;
    for who in [&absent, &zero] {
        let mut connection = connect(&server, who).await;
        assert_eq!(refusal(ask(&mut connection, GetStats::default()).await), forbidden());
    }
    server.shutdown().await;
    let server = start(serde_json::json!("any"), key_ring.clone()).await;
    let mut connection = connect(&server, &absent).await;
    assert_eq!(refusal(ask(&mut connection, GetStats::default()).await), forbidden());
    assert!(key_ring.untouched());
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn default_bits_run_default_queries_only() {
    let key_ring = CountingKeyRing::new();
    let operator = client();
    let server =
        start(serde_json::json!({ "list": [listed(&operator, Some(1.into()))] }), key_ring.clone())
            .await;
    let mut connection = connect(&server, &operator).await;
    assert_eq!(refusal(ask(&mut connection, sign(&key_ring)).await), not_authorized());
    assert_eq!(refusal(ask(&mut connection, AddAdnlId::default()).await), not_authorized());
    assert_eq!(refusal(ask(&mut connection, AddCustomOverlay::default()).await), not_authorized());
    assert_eq!(key_ring.signed.load(Ordering::SeqCst), 0, "a refused Sign must not sign");
    let hash = ask(&mut connection, GenerateKeyPair::default())
        .await
        .downcast::<KeyHashBoxed>()
        .expect("GenerateKeyPair runs");
    assert_eq!(hash.only().key_hash, UInt256::with_array(key_ring.key_hash()));
    assert_eq!(key_ring.generated.load(Ordering::SeqCst), 1);
    let exported = ask(
        &mut connection,
        ExportPublicKey { key_hash: UInt256::with_array(key_ring.key_hash()) },
    )
    .await;
    match exported.downcast::<PublicKey>() {
        Ok(PublicKey::Pub_Ed25519(key)) => {
            assert_eq!(&key.key.as_slice()[..], key_ring.key.pub_key().unwrap())
        }
        other => panic!("ExportPublicKey did not run: {other:?}"),
    }
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn modify_bits_run_modify_and_entry_only_queries() {
    let key_ring = CountingKeyRing::new();
    let operator = client();
    let server =
        start(serde_json::json!({ "list": [listed(&operator, Some(2.into()))] }), key_ring.clone())
            .await;
    let mut connection = connect(&server, &operator).await;
    assert_eq!(refusal(ask(&mut connection, GetStats::default()).await), not_authorized());
    assert_eq!(refusal(ask(&mut connection, GenerateKeyPair::default()).await), not_authorized());
    assert!(key_ring.untouched());
    // The handler runs and refuses: a status-only server is not started.
    let reply = ask(&mut connection, AddValidatorTempKey::default()).await;
    assert_eq!(refusal(reply), Some((651, "not started".to_string())));
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unsafe_bits_sign_and_signed_values_are_bit_sets() {
    for bits in [serde_json::json!(7), serde_json::json!(-1), serde_json::json!("4")] {
        let key_ring = CountingKeyRing::new();
        let operator = client();
        let server = start(
            serde_json::json!({ "list": [listed(&operator, Some(bits.clone()))] }),
            key_ring.clone(),
        )
        .await;
        let mut connection = connect(&server, &operator).await;
        let signature = ask(&mut connection, sign(&key_ring))
            .await
            .downcast::<SignatureBoxed>()
            .unwrap_or_else(|answer| panic!("Sign did not run with {bits}: {answer:?}"));
        key_ring.key.verify(b"payload", &signature.only().signature).unwrap();
        assert_eq!(key_ring.signed.load(Ordering::SeqCst), 1);
        server.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_known_unserved_function_is_unsupported() {
    let key_ring = CountingKeyRing::new();
    let operator = client();
    let server =
        start(serde_json::json!({ "list": [listed(&operator, Some(1.into()))] }), key_ring.clone())
            .await;
    let mut connection = connect(&server, &operator).await;
    assert_eq!(
        refusal(ask(&mut connection, AddDhtId::default()).await),
        Some((621, "query not supported".to_string()))
    );
    // An unknown constructor is a parse error, not an unsupported query.
    let (code, message) =
        refusal(ask_raw(&mut connection, 0x0bad_c0de_u32.to_le_bytes().to_vec()).await).unwrap();
    assert_eq!(code, 0);
    assert!(message.starts_with("failed to parse validator query: "), "{message}");
    // The connection stays usable.
    assert!(ask(&mut connection, GenerateKeyPair::default())
        .await
        .downcast::<KeyHashBoxed>()
        .is_ok());
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_entries_apply_in_order() {
    let key_ring = CountingKeyRing::new();
    let replaced = client();
    let removed = client();
    let server = start(
        serde_json::json!({ "list": [
            listed(&replaced, Some(1.into())),
            listed(&removed, Some(7.into())),
            listed(&replaced, Some(4.into())),
            listed(&removed, Some(0.into())),
        ]}),
        key_ring.clone(),
    )
    .await;
    let mut connection = connect(&server, &replaced).await;
    assert!(ask(&mut connection, sign(&key_ring)).await.downcast::<SignatureBoxed>().is_ok());
    assert_eq!(refusal(ask(&mut connection, GenerateKeyPair::default()).await), not_authorized());
    let mut connection = connect(&server, &removed).await;
    assert_eq!(refusal(ask(&mut connection, GetStats::default()).await), forbidden());
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn each_server_authorizes_from_its_own_table() {
    let key_ring = CountingKeyRing::new();
    let operator = client();
    let first =
        start(serde_json::json!({ "list": [listed(&operator, Some(7.into()))] }), key_ring.clone())
            .await;
    let second = start(serde_json::json!({ "list": [] }), key_ring.clone()).await;
    let mut connection = connect(&first, &operator).await;
    assert!(ask(&mut connection, GenerateKeyPair::default())
        .await
        .downcast::<KeyHashBoxed>()
        .is_ok());
    let mut connection = connect(&second, &operator).await;
    assert_eq!(refusal(ask(&mut connection, GenerateKeyPair::default()).await), forbidden());
    first.shutdown().await;
    second.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn certificate_and_broadcast_queries_need_modify_then_a_serving_full_node() {
    let key_ring = CountingKeyRing::new();
    let reader = client();
    let operator = client();
    let server = start(
        serde_json::json!({ "list": [
            listed(&reader, Some(1.into())),
            listed(&operator, Some(2.into())),
        ]}),
        key_ring.clone(),
    )
    .await;
    let mut connection = connect(&server, &reader).await;
    assert_eq!(
        refusal(ask(&mut connection, SignShardOverlayCertificate::default()).await),
        not_authorized()
    );
    assert_eq!(
        refusal(ask(&mut connection, ImportShardOverlayCertificate::default()).await),
        not_authorized()
    );
    assert_eq!(
        refusal(ask(&mut connection, SetExtMessagesBroadcastDisabled::default()).await),
        not_authorized()
    );
    // Without a serving full node each is refused as not ready, with the
    // reference code rather than the generic handler failure.
    let not_started = Some((651, "not started".to_string()));
    let mut connection = connect(&server, &operator).await;
    assert_eq!(
        refusal(ask(&mut connection, SignShardOverlayCertificate::default()).await),
        not_started
    );
    assert_eq!(
        refusal(ask(&mut connection, ImportShardOverlayCertificate::default()).await),
        not_started
    );
    assert_eq!(
        refusal(ask(&mut connection, SetExtMessagesBroadcastDisabled::default()).await),
        not_started
    );
    server.shutdown().await;
}
