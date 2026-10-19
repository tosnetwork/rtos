/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::{
    collator_test_bundle::CollatorTestBundle,
    config::{KeyCommand, KeyCommandError, KeyRing, NodeConfigHandler},
    engine::Engine,
    engine_traits::{EngineOperations, Stoppable},
    network::{
        node_network::NodeNetwork,
        shard_overlay_certificates::{error_code, ShardCertificateEndpoint, WireShard},
    },
    shard_states_keeper::PinnedShardStateGuard,
    validating_utils::{supported_capabilities, supported_version},
};
use adnl::{
    common::{AdnlPeers, QueryAnswer, QueryResult, Subscriber},
    server::{AdnlServer, AdnlServerConfig, ClientPermissions},
};
use rtos_api::{
    deserialize_boxed,
    ton::{
        self,
        accountaddress::AccountAddress,
        engine::validator::{
            controlqueryerror::ControlQueryError,
            customoverlay::CustomOverlay,
            exportedprivatekeys::ExportedPrivateKeys,
            jsonconfig::JsonConfig,
            keyhash::KeyHash,
            onestat::OneStat,
            signature::Signature,
            stats::Stats,
            time::Time,
            //ControlQueryError as ControlQueryErrorBoxed,
            Success,
        },
        lite_server::configinfo::ConfigInfo,
        raw::{
            appliedshardsinfo::AppliedShardsInfo, shardaccountmeta::ShardAccountMeta,
            shardaccountstate::ShardAccountState, AppliedShardsInfo as AppliedShardsInfoBoxed,
            ShardAccountMeta as ShardAccountMetaBoxed, ShardAccountState as ShardAccountStateBoxed,
        },
        rpc::{
            engine::validator::{
                AddAdnlId, AddCustomOverlay, AddValidatorAdnlAddress, AddValidatorPermanentKey,
                AddValidatorTempKey, ControlQuery, DelAdnlId, DelCustomOverlay,
                DelValidatorAdnlAddress, DelValidatorPermanentKey, DelValidatorTempKey,
                ExportAllPrivateKeys, ExportPrivateKey, ExportPublicKey, GenerateKeyPair,
                GetBundle, GetConfig, GetFutureBundle, GetSelectedStats, GetStats, GetTime,
                ImportPrivateKey, ImportShardOverlayCertificate, SetExtMessagesBroadcastDisabled,
                SetVerbosity, ShowCustomOverlays, Sign, SignShardOverlayCertificate,
            },
            lite_server::{
                GetBlock, GetConfigAll, GetConfigParams, Query as LiteServerQuery, SendMessage,
            },
            raw::{
                GetAccountByBlock, GetAccountMetaByBlock, GetAppliedShardsInfo,
                GetShardAccountMeta, GetShardAccountState,
            },
        },
        PrivateKey, PublicKey,
    },
    IntoBoxed, TLObject,
};
use rtos_block::{
    base64_encode, error, fail, sha256_digest, AccountId, BlockIdExt, KeyId, KeyOption,
    MerkleProof, MsgAddressInt, Result, Serializable, ShardAccount, ShardIdent, UInt256,
    ED25519_KEY_TYPE,
};
use rtos_block_json::serialize_config_param;
use secrets_vault::vault_block::get_key_option_factory;
use std::sync::Arc;

/// Permission bits of a control client, as the reference engine defines them.
pub(crate) const VEP_DEFAULT: u32 = 1;
pub(crate) const VEP_MODIFY: u32 = 2;
pub(crate) const VEP_UNSAFE: u32 = 4;

/// Reference engine error codes used in control replies.
const ERROR_CODE_ERROR: i32 = 602;
const ERROR_CODE_PROTOVIOLATION: i32 = 621;
const ERROR_CODE_NOTREADY: i32 = 651;

/// The permission bits a served control query needs. Zero means that being a
/// listed client is enough, as for lite-server queries on the control port.
/// `None` is a query this server does not serve.
pub(crate) fn required_permission(query: &TLObject) -> Option<u32> {
    macro_rules! table {
        ($($ty:ty => $bits:expr),* $(,)?) => {
            $(if query.is::<$ty>() { return Some($bits); })*
        };
    }
    table!(
        GetTime => VEP_DEFAULT,
        SetVerbosity => VEP_DEFAULT,
        ExportPrivateKey => VEP_UNSAFE,
        ExportAllPrivateKeys => VEP_UNSAFE,
        GenerateKeyPair => VEP_DEFAULT,
        ImportPrivateKey => VEP_DEFAULT,
        ExportPublicKey => VEP_DEFAULT,
        Sign => VEP_UNSAFE,
        AddValidatorPermanentKey => VEP_MODIFY,
        AddValidatorTempKey => VEP_MODIFY,
        AddValidatorAdnlAddress => VEP_MODIFY,
        AddAdnlId => VEP_MODIFY,
        DelAdnlId => VEP_MODIFY,
        DelValidatorPermanentKey => VEP_MODIFY,
        DelValidatorTempKey => VEP_MODIFY,
        DelValidatorAdnlAddress => VEP_MODIFY,
        GetStats => VEP_DEFAULT,
        GetConfig => VEP_DEFAULT,
        AddCustomOverlay => VEP_MODIFY,
        DelCustomOverlay => VEP_MODIFY,
        ShowCustomOverlays => VEP_DEFAULT,
        GetBlock => 0,
        GetConfigAll => 0,
        GetConfigParams => 0,
        SendMessage => 0,
        GetShardAccountState => VEP_DEFAULT,
        GetShardAccountMeta => VEP_DEFAULT,
        GetAccountByBlock => VEP_DEFAULT,
        GetAccountMetaByBlock => VEP_DEFAULT,
        GetAppliedShardsInfo => VEP_DEFAULT,
        GetSelectedStats => VEP_DEFAULT,
        GetBundle => VEP_MODIFY,
        GetFutureBundle => VEP_MODIFY,
        SignShardOverlayCertificate => VEP_MODIFY,
        ImportShardOverlayCertificate => VEP_MODIFY,
        SetExtMessagesBroadcastDisabled => VEP_MODIFY,
    );
    None
}

fn control_error(code: i32, message: impl Into<String>) -> Result<QueryResult> {
    QueryResult::consume_boxed(
        ControlQueryError { code, message: message.into() }.into_boxed(),
        #[cfg(feature = "telemetry")]
        None,
    )
}

/// The errno the reference key ring reports for a key it does not hold.
const ERROR_CODE_KEY_NOT_FOUND: i32 = 2;

/// Why a key lookup failed, after the reference key ring's "key not in db".
fn key_not_found(key_hash: &[u8; 32]) -> String {
    format!("no key {} in the key ring", hex::encode_upper(key_hash))
}

/// The reply code of a failed command: the code it carries, the errno of an
/// operating-system error, else 0.
fn reply_code(error: &rtos_block::Error) -> i32 {
    if let Some(error) = error.downcast_ref::<KeyCommandError>() {
        return error.code;
    }
    error_code(error)
}

/// The reference engine answers some malformed queries with no reply and
/// closes the connection; a handler returns this error to do the same.
#[derive(Debug, thiserror::Error)]
#[error("query refused without a reply")]
struct CloseConnection;

/// A signed wire field read as the unsigned value it encodes.
fn wire_unsigned(value: i32) -> u32 {
    u32::from_ne_bytes(value.to_ne_bytes())
}

/// The constructor of `pk.ed25519`, the serialized form of an exported key.
const PRIVATE_KEY_ED25519: u32 = 0x4968_2317;

/// The reference engine's default outgoing port, which this node does not
/// configure separately.
const DEFAULT_OUT_PORT: i64 = 3278;

/// A block id as the reference engine prints it.
fn block_id_to_str(id: &BlockIdExt) -> String {
    format!(
        "({},{:016x},{}):{}:{}",
        id.shard().workchain_id(),
        id.shard().shard_prefix_with_tag(),
        id.seq_no(),
        hex::encode_upper(id.root_hash.as_slice()),
        hex::encode_upper(id.file_hash.as_slice())
    )
}

/// Encrypts `data` to an Ed25519 public key as the reference engine's
/// Ed25519 encryptor does: an ephemeral public key, the SHA-256 of the data,
/// then the data under AES-CTR keyed from the shared secret and the digest.
pub fn encrypt_for(public: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let ephemeral = get_key_option_factory().generate()?;
    let shared = ephemeral.shared_secret(public)?;
    let secret: [u8; 32] =
        shared.lock()?.as_ref().try_into().map_err(|_| error!("shared secret is not 32 bytes"))?;
    let digest = sha256_digest(data);
    let mut body = data.to_vec();
    adnl::common::AdnlCryptoUtils::build_cipher_secure(&secret, &digest).apply_keystream(&mut body);
    let mut out = Vec::with_capacity(64 + body.len());
    out.extend_from_slice(ephemeral.pub_key()?);
    out.extend_from_slice(&digest);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decrypts what [`encrypt_for`] produced, with the recipient's key. The
/// console decrypts an exported key set with it, through the library.
#[allow(dead_code)]
pub fn decrypt_with(key: &Arc<dyn KeyOption>, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 64 {
        fail!("message is too short");
    }
    let shared = key.shared_secret(&data[..32])?;
    let secret: [u8; 32] =
        shared.lock()?.as_ref().try_into().map_err(|_| error!("shared secret is not 32 bytes"))?;
    let digest: [u8; 32] = data[32..64].try_into().map_err(|_| error!("bad digest"))?;
    let mut body = data[64..].to_vec();
    adnl::common::AdnlCryptoUtils::build_cipher_secure(&secret, &digest).apply_keystream(&mut body);
    if sha256_digest(&body) != digest {
        fail!("sha256 mismatch after decryption");
    }
    Ok(body)
}

fn obj(fields: Vec<(&'static str, TdJson)>) -> TdJson {
    TdJson::Obj(fields)
}

fn typed(name: &str, mut fields: Vec<(&'static str, TdJson)>) -> TdJson {
    fields.insert(0, ("@type", TdJson::Str(name.to_string())));
    obj(fields)
}

fn int(value: impl Into<i64>) -> TdJson {
    TdJson::Int(value.into())
}

fn text(value: impl Into<String>) -> TdJson {
    TdJson::Str(value.into())
}

/// The id bytes a base64 key id stands for, for ordering as the reference
/// engine's maps order them.
fn id_bytes(id: &str) -> Vec<u8> {
    rtos_block::base64_decode(id).unwrap_or_default()
}

/// A signed 32-bit field holding an unsigned value, as the reference engine
/// writes it.
fn signed(value: u32) -> i64 {
    i64::from(i32::from_ne_bytes(value.to_ne_bytes()))
}

/// The configuration in the reference engine's `engine.validator.config`
/// schema. Lists the node has no counterpart for are empty.
fn config_json(view: &crate::config::ControlConfigView) -> Result<TdJson> {
    let mut addrs = Vec::new();
    if let Some(address) = &view.ip_address {
        let address: std::net::SocketAddrV4 =
            address.parse().map_err(|e| error!("bad ADNL address {address}: {e}"))?;
        addrs.push(typed(
            "engine.addr",
            vec![
                ("ip", int(signed(u32::from(*address.ip())))),
                ("port", int(address.port())),
                ("categories", TdJson::Arr(vec![int(0)])),
                ("priority_categories", TdJson::Arr(vec![])),
            ],
        ));
    }
    let mut adnl = view.adnl.clone();
    adnl.sort_by_key(|entry| id_bytes(&entry.id));
    let adnl = adnl
        .iter()
        .map(|entry| {
            typed("engine.adnl", vec![("id", text(&entry.id)), ("category", int(entry.category))])
        })
        .collect();
    let mut dht = view.dht.clone();
    dht.sort_by_key(|id| id_bytes(id));
    let dht = dht.iter().map(|id| typed("engine.dht", vec![("id", text(id))])).collect();
    let mut validators = view.validators.clone();
    validators.sort_by_key(|(key, _, _)| id_bytes(&key.validator_key_id));
    let validators = validators
        .iter()
        .map(|(key, temps, addresses)| {
            let mut temps = temps.clone();
            temps.sort_by_key(|entry| id_bytes(&entry.key_id));
            let mut addresses = addresses.clone();
            // An address bound before the address list existed is listed too.
            if let Some(bound) = &key.validator_adnl_key_id {
                if !addresses.iter().any(|entry| &entry.key_id == bound) {
                    addresses.push(crate::config::ValidatorBoundKeyJson {
                        validator_key_id: key.validator_key_id.clone(),
                        key_id: bound.clone(),
                        expire_at: u32::from_ne_bytes(key.expire_at.to_ne_bytes()),
                    });
                }
            }
            addresses.sort_by_key(|entry| id_bytes(&entry.key_id));
            typed(
                "engine.validator",
                vec![
                    ("id", text(&key.validator_key_id)),
                    (
                        "temp_keys",
                        TdJson::Arr(
                            temps
                                .iter()
                                .map(|entry| {
                                    typed(
                                        "engine.validatorTempKey",
                                        vec![
                                            ("key", text(&entry.key_id)),
                                            ("expire_at", int(signed(entry.expire_at))),
                                        ],
                                    )
                                })
                                .collect(),
                        ),
                    ),
                    (
                        "adnl_addrs",
                        TdJson::Arr(
                            addresses
                                .iter()
                                .map(|entry| {
                                    typed(
                                        "engine.validatorAdnlAddress",
                                        vec![
                                            ("id", text(&entry.key_id)),
                                            ("expire_at", int(signed(entry.expire_at))),
                                        ],
                                    )
                                })
                                .collect(),
                        ),
                    ),
                    ("election_date", int(key.election_id)),
                    ("expire_at", int(key.expire_at)),
                ],
            )
        })
        .collect();
    let mut fields = vec![
        ("out_port", int(DEFAULT_OUT_PORT)),
        ("addrs", TdJson::Arr(addrs)),
        ("adnl", TdJson::Arr(adnl)),
        ("dht", TdJson::Arr(dht)),
        ("validators", TdJson::Arr(validators)),
        ("collators", TdJson::Arr(vec![])),
        ("fullnode", text(view.fullnode.clone().unwrap_or_else(|| base64_encode([0u8; 32])))),
        ("fullnodeslaves", TdJson::Arr(vec![])),
        ("fullnodemasters", TdJson::Arr(vec![])),
    ];
    if view.ext_messages_broadcast_disabled {
        fields.push((
            "fullnodeconfig",
            typed(
                "engine.validator.fullNodeConfig",
                vec![("ext_messages_broadcast_disabled", TdJson::Bool(true))],
            ),
        ));
    }
    if !view.state_serializer_enabled || view.pq_consensus.is_some() {
        let mut extra = vec![
            ("state_serializer_enabled", TdJson::Bool(view.state_serializer_enabled)),
            ("fast_sync_member_certificates", TdJson::Arr(vec![])),
            ("fast_sync_overlay_clients", TdJson::Arr(vec![])),
        ];
        if let Some(pq) = &view.pq_consensus {
            let json = pq.to_json();
            let keys = json["keys"]
                .as_array()
                .map(|keys| {
                    keys.iter()
                        .map(|key| {
                            typed(
                                "engine.validator.pqConsensusKey",
                                vec![
                                    (
                                        "consensus_key_file",
                                        text(key["consensus_key_file"].as_str().unwrap_or("")),
                                    ),
                                    ("valid_from", int(key["valid_from"].as_i64().unwrap_or(0))),
                                    ("expire_at", int(key["expire_at"].as_i64().unwrap_or(0))),
                                ],
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            extra.push((
                "pq_consensus",
                typed(
                    "engine.validator.pqConsensus",
                    vec![
                        ("validator_id", text(json["validator_id"].as_str().unwrap_or(""))),
                        (
                            "consensus_key_file",
                            text(json["consensus_key_file"].as_str().unwrap_or("")),
                        ),
                        ("keys", TdJson::Arr(keys)),
                    ],
                ),
            ));
        }
        fields.push(("extraconfig", typed("engine.validator.extraConfig", extra)));
    }
    let liteservers = view
        .lite_server
        .iter()
        .map(|server| {
            typed("engine.liteServer", vec![("id", text(&server.id)), ("port", int(server.port))])
        })
        .collect();
    fields.push(("liteservers", TdJson::Arr(liteservers)));
    let control = view
        .control_server
        .iter()
        .map(|server| {
            // As the reference configuration reads them: a later entry for a
            // client replaces an earlier one, and zero permissions remove it.
            let mut listed = std::collections::BTreeMap::new();
            for (id, bits) in &server.clients {
                if *bits == 0 {
                    listed.remove(&id_bytes(id));
                } else {
                    listed.insert(id_bytes(id), (id.clone(), *bits));
                }
            }
            let clients: Vec<_> = listed.into_values().collect();
            typed(
                "engine.controlInterface",
                vec![
                    ("id", text(&server.id)),
                    ("port", int(server.port)),
                    (
                        "allowed",
                        TdJson::Arr(
                            clients
                                .iter()
                                .map(|(id, bits)| {
                                    typed(
                                        "engine.controlProcess",
                                        vec![("id", text(id)), ("permissions", int(*bits))],
                                    )
                                })
                                .collect(),
                        ),
                    ),
                ],
            )
        })
        .collect();
    fields.push(("control", TdJson::Arr(control)));
    fields.push(("shards_to_monitor", TdJson::Arr(vec![])));
    fields.push(("gc", typed("engine.gc", vec![("ids", TdJson::Arr(vec![]))])));
    Ok(typed("engine.validator.config", fields))
}

/// A JSON value written the way the reference engine's JSON builder writes
/// it: fields in schema order, three-space indentation, `" : "` between a
/// name and its value, an empty array as `[` and `]` on separate lines.
#[derive(Debug, Clone, PartialEq)]
pub enum TdJson {
    Int(i64),
    Bool(bool),
    Str(String),
    Arr(Vec<TdJson>),
    Obj(Vec<(&'static str, TdJson)>),
}

impl TdJson {
    /// The pretty form with its final newline.
    pub fn encode_pretty(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, 0);
        out.push('\n');
        out
    }

    fn newline(out: &mut String, depth: usize) {
        out.push('\n');
        for _ in 0..depth {
            out.push_str("   ");
        }
    }

    fn write(&self, out: &mut String, depth: usize) {
        match self {
            TdJson::Int(value) => out.push_str(&value.to_string()),
            TdJson::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
            TdJson::Str(value) => Self::write_string(out, value),
            TdJson::Arr(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    Self::newline(out, depth + 1);
                    item.write(out, depth + 1);
                }
                Self::newline(out, depth);
                out.push(']');
            }
            TdJson::Obj(fields) => {
                out.push('{');
                for (index, (name, value)) in fields.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    Self::newline(out, depth + 1);
                    Self::write_string(out, name);
                    out.push_str(" : ");
                    value.write(out, depth + 1);
                }
                Self::newline(out, depth);
                out.push('}');
            }
        }
    }

    fn write_string(out: &mut String, value: &str) {
        out.push('"');
        for ch in value.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\u{8}' => out.push_str("\\b"),
                '\u{c}' => out.push_str("\\f"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
                ch => out.push(ch),
            }
        }
        out.push('"');
    }
}

/// How the running node changes its log level when an operator asks.
pub trait VerbosityControl: Send + Sync {
    fn set_level(&self, level: log::LevelFilter) -> Result<()>;
}

static VERBOSITY_CONTROL: std::sync::OnceLock<Box<dyn VerbosityControl>> =
    std::sync::OnceLock::new();

/// Installs the logging backend's control; there is one per process.
pub fn install_verbosity_control(control: Box<dyn VerbosityControl>) -> Result<()> {
    VERBOSITY_CONTROL.set(control).map_err(|_| error!("a verbosity control is already installed"))
}

/// The level of the reference engine's verbosity `v`, which is the level
/// ERROR raised by `v`: 0 logs errors only, 1 warnings, 2 information,
/// 3 debug, and 4 to 10 everything.
pub fn verbosity_level(verbosity: i32) -> log::LevelFilter {
    match verbosity {
        i32::MIN..=0 => log::LevelFilter::Error,
        1 => log::LevelFilter::Warn,
        2 => log::LevelFilter::Info,
        3 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    }
}

/// Applies a level through the installed control, else to the log facade.
pub fn apply_verbosity(level: log::LevelFilter) -> Result<()> {
    match VERBOSITY_CONTROL.get() {
        Some(control) => control.set_level(level),
        None => {
            log::set_max_level(level);
            Ok(())
        }
    }
}

fn into_answer(result: QueryResult) -> Result<Option<QueryAnswer>> {
    match result {
        QueryResult::Consumed(answer) => Ok(Some(answer)),
        QueryResult::Rejected(query) => fail!("Control query was not answered: {query:?}"),
        QueryResult::RejectedBundle(_) => fail!("Control query bundle was not answered"),
    }
}

pub struct ControlServer {
    adnl: AdnlServer,
}

impl ControlServer {
    pub async fn with_params(
        config: AdnlServerConfig,
        data_source: DataSource,
        key_ring: Arc<dyn KeyRing>,
        node_config: Arc<NodeConfigHandler>,
        network: Option<&NodeNetwork>,
    ) -> Result<Self> {
        // Any key may connect; each query is authorized from this server's
        // own client table.
        let permissions = config
            .client_permissions()
            .ok_or_else(|| error!("Control server must authorize each query"))?;
        if permissions.is_empty() {
            log::warn!("Control server lists no permitted client: every query is forbidden");
        }
        let ret = Self {
            adnl: AdnlServer::listen(
                config,
                vec![Arc::new(ControlQuerySubscriber::new(
                    data_source,
                    key_ring,
                    node_config,
                    network,
                    permissions,
                )?)],
                #[cfg(feature = "telemetry")]
                "ControlServer",
            )
            .await?,
        };
        Ok(ret)
    }
    #[cfg(test)]
    pub(crate) fn local_addr(&self) -> std::net::SocketAddr {
        self.adnl.local_addr()
    }

    pub async fn shutdown(self) {
        self.adnl.shutdown().await
    }
}

#[async_trait::async_trait]
impl Stoppable for ControlServer {
    fn name(&self) -> &'static str {
        "controlserver"
    }
    async fn shutdown(self: Box<Self>) {
        (*self).shutdown().await;
    }
}

pub trait StatusReporter: Send + Sync {
    fn get_report(&self) -> u32;
}

pub enum DataSource {
    Engine(Arc<dyn EngineOperations>),
    Status(Arc<dyn StatusReporter>),
}

struct ControlQuerySubscriber {
    data_source: DataSource,
    key_ring: Arc<dyn KeyRing>,
    config: Arc<NodeConfigHandler>,
    public_overlay_adnl_id: Option<Arc<KeyId>>,
    certificates: Option<Arc<ShardCertificateEndpoint>>,
    permissions: Arc<ClientPermissions>,
}

impl ControlQuerySubscriber {
    fn new(
        data_source: DataSource,
        key_ring: Arc<dyn KeyRing>,
        config: Arc<NodeConfigHandler>,
        network: Option<&NodeNetwork>,
        permissions: Arc<ClientPermissions>,
    ) -> Result<Self> {
        let key_id = if let Some(network) = network {
            Some(network.get_key_id_by_tag(NodeNetwork::TAG_OVERLAY_KEY)?)
        } else {
            None
        };
        let certificates = network.map(|network| network.shard_certificate_endpoint().clone());
        let ret = Self {
            data_source,
            key_ring,
            config,
            public_overlay_adnl_id: key_id,
            certificates,
            permissions,
        };
        Ok(ret)
    }

    fn engine(&self) -> Result<&Arc<dyn EngineOperations>> {
        match self.data_source {
            DataSource::Engine(ref engine) => Ok(engine),
            _ => fail!("`engine is not set`"),
        }
    }

    async fn get_all_config_params(&self) -> Result<ConfigInfo> {
        let engine = self.engine()?;
        let mc_state = engine.load_last_applied_mc_state().await?;
        let block_id = mc_state.block_id();
        let config_params = mc_state.config_params()?;
        let config_info = ConfigInfo {
            mode: 0,
            id: block_id.clone(),
            state_proof: vec![],
            config_proof: config_params.write_to_bytes()?,
        };
        Ok(config_info)
    }

    async fn get_config_params(&self, param_number: u32) -> Result<ConfigInfo> {
        let engine = self.engine()?;
        let mc_state = engine.load_last_applied_mc_state().await?;
        let config_params = mc_state.config_params()?;
        let config_param = serialize_config_param(config_params, param_number)?;
        let config_info = ConfigInfo {
            mode: 0,
            id: mc_state.block_id().clone(),
            state_proof: vec![],
            config_proof: config_param.into_bytes(),
        };
        Ok(config_info)
    }

    async fn get_account_state(&self, address: AccountAddress) -> Result<ShardAccountStateBoxed> {
        let address: MsgAddressInt = address.account_address.parse()?;
        Self::convert_account_state(self.find_account(&address).await?)
    }

    async fn get_account_by_block(
        &self,
        account_id: UInt256,
        block_root_hash: UInt256,
    ) -> Result<ShardAccountStateBoxed> {
        Self::convert_account_state(
            self.find_account_by_block(&account_id.into(), &block_root_hash).await?,
        )
    }

    async fn get_account_meta(&self, address: AccountAddress) -> Result<ShardAccountMetaBoxed> {
        let address: MsgAddressInt = address.account_address.parse()?;
        Self::convert_account_meta(self.find_account(&address).await?)
    }

    async fn get_account_meta_by_block(
        &self,
        account_id: UInt256,
        block_root_hash: UInt256,
    ) -> Result<ShardAccountMetaBoxed> {
        Self::convert_account_meta(
            self.find_account_by_block(&account_id.into(), &block_root_hash).await?,
        )
    }

    async fn find_account(
        &self,
        addr: &MsgAddressInt,
    ) -> Result<Option<(ShardAccount, PinnedShardStateGuard)>> {
        let engine = self.engine()?;
        let state = if addr.is_masterchain() {
            let mc_block_id = engine
                .load_last_applied_mc_block_id()?
                .ok_or_else(|| error!("Cannot load last_applied_mc_block_id!"))?;
            engine.load_and_pin_state(&mc_block_id).await?
        } else {
            let mc_block_id = engine.load_shard_client_mc_block_id()?;
            let mc_block_id =
                mc_block_id.ok_or_else(|| error!("Cannot load shard_client_mc_block_id!"))?;
            let mc_state = engine.load_and_pin_state(&mc_block_id).await?;
            let mut shard_state = None;
            for id in mc_state.state().top_blocks(addr.workchain_id())? {
                if id.shard().contains_account(addr.address())? {
                    shard_state = engine.load_and_pin_state(&id).await.ok();
                    break;
                }
            }
            shard_state.ok_or_else(|| error!("Cannot find actual shard for account {}", addr))?
        };
        Ok(state.state().shard_account(&addr.address())?.map(|acc| (acc, state)))
    }

    async fn find_account_by_block(
        &self,
        account_id: &AccountId,
        block_root_hash: &UInt256,
    ) -> Result<Option<(ShardAccount, PinnedShardStateGuard)>> {
        let engine = self.engine()?;
        let block_id = engine.find_full_block_id(block_root_hash)?.ok_or_else(|| {
            error!("Cannot find full block id by root hash {:x}", block_root_hash)
        })?;
        let shard_state = engine.load_and_pin_state(&block_id).await?;
        Ok(shard_state.state().shard_account(account_id)?.map(|acc| (acc, shard_state)))
    }

    fn convert_account_state(
        shard_account: Option<(ShardAccount, PinnedShardStateGuard)>,
    ) -> Result<ShardAccountStateBoxed> {
        Ok(match shard_account {
            Some((account, _state_guard)) => {
                let shard_account = account.write_to_bytes()?;
                ShardAccountStateBoxed::Raw_ShardAccountState(ShardAccountState { shard_account })
            }
            None => ShardAccountStateBoxed::Raw_ShardAccountNone,
        })
    }

    fn convert_account_meta(
        shard_account: Option<(ShardAccount, PinnedShardStateGuard)>,
    ) -> Result<ShardAccountMetaBoxed> {
        Ok(match shard_account {
            Some((shard_account, _state_guard)) => {
                let account = shard_account.read_account()?;
                let code = account.get_code().map(|cell| cell.repr_hash().clone());
                let data = account.get_data().map(|cell| cell.repr_hash().clone());
                let libs = account.libraries().root().map(|cell| cell.repr_hash().clone());

                let cell = shard_account.account_cell();
                let proof = MerkleProof::create(&cell, |hash| {
                    Some(hash) != code.as_ref()
                        && Some(hash) != data.as_ref()
                        && Some(hash) != libs.as_ref()
                })
                .unwrap();
                ShardAccountMetaBoxed::Raw_ShardAccountMeta(ShardAccountMeta {
                    shard_account_meta: proof.write_to_bytes()?,
                })
            }
            None => ShardAccountMetaBoxed::Raw_ShardAccountMetaNone,
        })
    }

    async fn get_applied_shards_info(&self) -> Result<AppliedShardsInfoBoxed> {
        let engine = self.engine()?;
        let mc_block_id = engine
            .load_last_applied_mc_block_id()?
            .ok_or_else(|| error!("Cannot load load_last_applied_mc_block_id"))?;
        let shards_mc_block_id = engine
            .load_shard_client_mc_block_id()?
            .ok_or_else(|| error!("Cannot load shard_client_mc_block_id"))?;
        let mut applied_blocks = engine.load_state(&shards_mc_block_id).await?.top_blocks_all()?;
        applied_blocks.push(mc_block_id.as_ref().clone());
        Ok(AppliedShardsInfoBoxed::Raw_AppliedShardsInfo(AppliedShardsInfo {
            shards: applied_blocks,
        }))
    }

    fn convert_sync_status(&self, sync_status: u32) -> String {
        match sync_status {
            Engine::SYNC_STATUS_START_BOOT => "start_boot".to_string(),
            Engine::SYNC_STATUS_LOAD_STATES => "load_states".to_string(),
            Engine::SYNC_STATUS_FINISH_BOOT => "finish_boot".to_string(),
            Engine::SYNC_STATUS_SYNC_ARCHIVES => "synchronization_by_archives".to_string(),
            Engine::SYNC_STATUS_SYNC_BLOCKS => "synchronization_by_blocks".to_string(),
            Engine::SYNC_STATUS_FINISH_SYNC => "synchronization_finished".to_string(),
            Engine::SYNC_STATUS_CHECKING_DB => "checking_db".to_string(),
            Engine::SYNC_STATUS_DB_BROKEN => "db_broken".to_string(),
            _ => "no_set_status".to_string(),
        }
    }

    fn block_id_to_json(block_id: &BlockIdExt) -> String {
        serde_json::json!({
            "shard":  block_id.shard().to_string(),
            "seq_no": block_id.seq_no(),
            "rh":     format!("{:x}", block_id.root_hash),
            "fh":     format!("{:x}", block_id.file_hash)
        })
        .to_string()
    }

    fn add_stats(stats: &mut Vec<OneStat>, key: impl ToString, value: impl ToString) {
        stats.push(OneStat { key: key.to_string(), value: value.to_string() })
    }

    fn statistics_to_json(
        map: &lockfree::map::Map<ShardIdent, u64>,
        now: i64,
        new_format: bool,
    ) -> String {
        let mut json_map = serde_json::Map::new();
        for item in map.iter() {
            let value = if new_format {
                match *item.val() {
                    0 => -1,
                    value => now - value as i64,
                }
                .into()
            } else {
                match *item.val() {
                    0 => "never".to_string(),
                    value => format!("{} sec ago", now - value as i64),
                }
                .into()
            };
            json_map.insert(item.key().to_string(), value);
        }
        format!("{:#}", serde_json::Value::from(json_map))
    }

    fn get_shards_time_diff(engine: &Arc<dyn EngineOperations>, now: u32) -> Result<u32> {
        let shard_client_mc_block_id = engine
            .load_shard_client_mc_block_id()?
            .ok_or_else(|| error!("Cannot load shard_mc_block_id"))?;
        let shard_client_mc_block_handle = engine
            .load_block_handle(&shard_client_mc_block_id)?
            .ok_or_else(|| error!("Cannot load handle for block {}", &shard_client_mc_block_id))?;
        Ok(now - shard_client_mc_block_handle.gen_utime())
    }

    async fn get_selected_stats(&self, filter: Option<&str>) -> Result<Stats> {
        let mut stats = Vec::new();
        let new_format = filter.is_some();

        // sync status
        let sync_status = match &self.data_source {
            DataSource::Engine(engine) => engine.get_sync_status(),
            DataSource::Status(status) => status.get_report(),
        };
        let sync_status = format!("\"{}\"", self.convert_sync_status(sync_status));
        Self::add_stats(
            &mut stats,
            if new_format { "node_status" } else { "sync_status" },
            sync_status,
        );
        if let DataSource::Status(_) = &self.data_source {
            return Ok(Stats { stats });
        }

        let engine = self.engine()?;
        let now = engine.now();

        let mc_block_id = if let Some(id) = engine.load_last_applied_mc_block_id()? {
            id
        } else {
            Self::add_stats(&mut stats, "masterchainblock", "\"not set\"");
            return Ok(Stats { stats });
        };

        let mc_block_handle = engine
            .load_block_handle(&mc_block_id)?
            .ok_or_else(|| error!("Cannot load handle for block {}", &mc_block_id))?;

        // masterchainblocktime
        Self::add_stats(&mut stats, "masterchainblocktime", mc_block_handle.gen_utime());

        // masterchainblocknumber
        Self::add_stats(&mut stats, "masterchainblocknumber", mc_block_handle.id().seq_no());

        Self::add_stats(&mut stats, "node_version", format!("\"{}\"", env!("CARGO_PKG_VERSION")));
        let public_overlay_adnl_id = self
            .public_overlay_adnl_id
            .as_ref()
            .ok_or_else(|| error!("Public overlay key id didn`t set!"))?;
        Self::add_stats(
            &mut stats,
            "public_overlay_key_id",
            format!("\"{}\"", &public_overlay_adnl_id),
        );

        if new_format {
            Self::add_stats(&mut stats, "supported_block", supported_version());
            Self::add_stats(&mut stats, "supported_capabilities", supported_capabilities());
        }

        // timediff
        let diff = now - mc_block_handle.gen_utime();
        Self::add_stats(&mut stats, "timediff", diff);

        // shards timediff
        match Self::get_shards_time_diff(engine, now) {
            Err(_) => Self::add_stats(&mut stats, "shards_timediff", "\"unknown\""),
            Ok(shards_timediff) => Self::add_stats(&mut stats, "shards_timediff", shards_timediff),
        };

        let mc_state = engine.load_last_applied_mc_state().await.ok();

        // global network ID
        if new_format {
            if let Some(mc_state) = &mc_state {
                Self::add_stats(&mut stats, "global_id", mc_state.state()?.global_id())
            } else {
                Self::add_stats(&mut stats, "global_id", "\"unknown\"")
            }
        }

        // in_current_vset_p34
        let adnl_ids = self.config.get_actual_validator_adnl_key_ids()?;
        if let Some(mc_state) = &mc_state {
            let current = mc_state.config_params()?.validator_set()?.list().iter().any(|val| {
                let Ok(adnl_id) = val.adnl_addr() else {
                    return false;
                };
                let is_validator = adnl_ids.contains(&adnl_id);
                if is_validator {
                    Self::add_stats(
                        &mut stats,
                        "current_vset_p34_adnl_id",
                        format!("\"{}\"", &adnl_id),
                    );
                }
                is_validator
            });
            Self::add_stats(&mut stats, "in_current_vset_p34", current)
        } else {
            Self::add_stats(&mut stats, "in_current_vset_p34", "\"unknown\"")
        }

        // in_next_vset_p36
        if let Some(mc_state) = &mc_state {
            let next = mc_state.config_params()?.next_validator_set()?.list().iter().any(|val| {
                let Ok(adnl_id) = val.adnl_addr() else {
                    return false;
                };
                let is_validator = adnl_ids.contains(&adnl_id);
                if is_validator {
                    Self::add_stats(
                        &mut stats,
                        "next_vset_p36_adnl_id",
                        format!("\"{}\"", &adnl_id),
                    );
                }
                is_validator
            });
            Self::add_stats(&mut stats, "in_next_vset_p36", next)
        } else {
            Self::add_stats(&mut stats, "in_next_vset_p36", "\"unknown\"")
        }

        let value = match engine.load_last_applied_mc_block_id() {
            Ok(Some(block_id)) => Self::block_id_to_json(&block_id),
            Ok(None) => "\"no last applied masterchain block{}\"".to_string(),
            Err(err) => format!("\"{}\"", err),
        };
        Self::add_stats(&mut stats, "last_applied_masterchain_block_id", value);

        let value = Self::statistics_to_json(engine.last_validation_time(), now as i64, new_format);
        if new_format {
            Self::add_stats(&mut stats, "last_validation_ago_sec", value)
        } else {
            Self::add_stats(&mut stats, "validation_stats", value)
        }

        let value = Self::statistics_to_json(engine.last_collation_time(), now as i64, new_format);
        if new_format {
            Self::add_stats(&mut stats, "last_collation_ago_sec", value)
        } else {
            Self::add_stats(&mut stats, "collation_stats", value)
        }

        // tps_10
        if let Ok(tps) = engine.calc_tps(10) {
            Self::add_stats(&mut stats, "tps_10", tps);
        }

        // tps_300
        if let Ok(tps) = engine.calc_tps(300) {
            Self::add_stats(&mut stats, "tps_300", tps);
        }

        Self::add_stats(
            &mut stats,
            "validation_status",
            format!("\"{:?}\"", engine.validation_status()),
        );

        Ok(Stats { stats })
    }

    /// The configuration as the reference engine reports it: its schema,
    /// field order and JSON layout, every list ordered by id.
    async fn get_validator_config(&self) -> Result<JsonConfig> {
        let view = self.config.control_view().await?;
        Ok(JsonConfig { data: config_json(&view)?.encode_pretty() })
    }

    /// The reference engine's statistics that this node keeps, under the
    /// same names and formats; statistics of components this node does not
    /// have are not reported.
    async fn get_stats(&self) -> Result<QueryResult> {
        let DataSource::Engine(engine) = &self.data_source else {
            return control_error(ERROR_CODE_NOTREADY, "validator manager not started");
        };
        let mut stats = Vec::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);
        Self::add_stats(&mut stats, "unixtime", now);
        if let Some(mc_block_id) = engine.load_last_applied_mc_block_id()? {
            Self::add_stats(&mut stats, "masterchainblock", block_id_to_str(&mc_block_id));
            let state = engine.load_last_applied_mc_state().await?;
            Self::add_stats(&mut stats, "masterchainblocktime", state.state()?.gen_time());
            // A state without a key block reference reports none.
            if let Ok(key_block) = state.last_keyblock_id() {
                Self::add_stats(&mut stats, "keymasterchainblock", block_id_to_str(&key_block));
            }
        }
        if let Some(shard_client) = engine.load_shard_client_mc_block_id()? {
            Self::add_stats(&mut stats, "shardclientmasterchainseqno", shard_client.seq_no());
        }
        let view = self.config.control_view().await?;
        Self::add_stats(&mut stats, "stateserializerenabled", view.state_serializer_enabled);
        QueryResult::consume_boxed(
            Stats { stats }.into_boxed(),
            #[cfg(feature = "telemetry")]
            None,
        )
    }

    /// Every private key of the node, encrypted to the client's key as the
    /// reference engine encrypts them.
    async fn export_all_private_keys(&self, encryption_key: &PublicKey) -> Result<QueryResult> {
        let PublicKey::Pub_Ed25519(key) = encryption_key else {
            return control_error(ERROR_CODE_PROTOVIOLATION, "encryption key is not Ed25519");
        };
        let keys = self.config.exportable_private_keys().await?;
        let mut plain = Vec::new();
        for key in &keys {
            // The size, then the key as a serialized private key.
            plain.extend_from_slice(&36u32.to_le_bytes());
            plain.extend_from_slice(&PRIVATE_KEY_ED25519.to_le_bytes());
            plain.extend_from_slice(&key.secret);
        }
        let mut tail = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut tail);
        plain.extend_from_slice(&tail);
        let encrypted = encrypt_for(key.key.as_slice(), &plain);
        plain.iter_mut().for_each(|byte| *byte = 0);
        QueryResult::consume_boxed(
            ExportedPrivateKeys { encrypted_data: encrypted? }.into_boxed(),
            #[cfg(feature = "telemetry")]
            None,
        )
    }

    pub async fn add_custom_overlay(&self, overlay: CustomOverlay) -> Result<Success> {
        let config = self.config.add_custom_overlay(overlay).await?;
        self.engine()?.update_custom_overlays(Some(&config.overlays()[..])).await?;
        Ok(Success::Engine_Validator_Success)
    }

    pub async fn del_custom_overlay(&self, name: String) -> Result<Success> {
        let config = self.config.del_custom_overlay(name).await?;
        self.engine()?.update_custom_overlays(Some(&config.overlays()[..])).await?;
        Ok(Success::Engine_Validator_Success)
    }

    async fn process_generate_keypair(&self, key_type: i32) -> Result<KeyHash> {
        let ret =
            KeyHash { key_hash: UInt256::with_array(self.key_ring.generate(key_type).await?) };
        Ok(ret)
    }

    async fn process_import_private_key(&self, key: PrivateKey) -> Result<KeyHash> {
        let ret =
            KeyHash { key_hash: UInt256::with_array(self.key_ring.import_private_key(key).await?) };
        Ok(ret)
    }

    fn export_public_key(&self, key_hash: &[u8; 32]) -> Result<PublicKey> {
        let private = self.key_ring.find(key_hash)?;
        (&private).try_into()
    }

    fn process_sign_data(&self, key_hash: &[u8; 32], data: &[u8]) -> Result<Signature> {
        let sign = self.key_ring.sign_data(key_hash, data)?;
        Ok(Signature { signature: sign })
    }

    fn started(&self) -> bool {
        matches!(self.data_source, DataSource::Engine(_))
    }

    /// The key-ring lookup that precedes a key command: a key this node does
    /// not hold is refused as the reference key ring refuses it.
    async fn check_key(&self, key_hash: &[u8; 32]) -> std::result::Result<(), (i32, String)> {
        if self.key_ring.find(key_hash).is_ok() {
            return Ok(());
        }
        let id = base64_encode(key_hash);
        let own = self.config.get_adnl_keys().await.unwrap_or_default();
        if own.iter().any(|(key, _)| key == &id) {
            return Ok(());
        }
        Err((ERROR_CODE_KEY_NOT_FOUND, format!("key not in db: {}", key_not_found(key_hash))))
    }

    /// A key command after the permission and readiness checks: the key
    /// lookup when the command names one, then the configuration change.
    async fn run_key_command(
        &self,
        checked_key: Option<&[u8; 32]>,
        command: KeyCommand,
        failure_prefix: &str,
    ) -> Result<QueryResult> {
        if !self.started() {
            return control_error(ERROR_CODE_NOTREADY, "not started");
        }
        if let Some(key) = checked_key {
            if let Err((code, message)) = self.check_key(key).await {
                return control_error(code, format!("failed to get public key: {message}"));
            }
        }
        match self.config.key_command(command).await {
            Ok(()) => QueryResult::consume_boxed(
                Success::Engine_Validator_Success,
                #[cfg(feature = "telemetry")]
                None,
            ),
            Err(error) => control_error(reply_code(&error), format!("{failure_prefix}{error}")),
        }
    }

    async fn prepare_bundle(&self, block_id: BlockIdExt) -> Result<Success> {
        if let DataSource::Engine(ref engine) = self.data_source {
            let handle = engine
                .load_block_handle(&block_id)?
                .ok_or_else(|| error!("Cannot load handle for block {}", block_id))?;
            let block = engine.load_block(&handle).await?;
            let bundle = CollatorTestBundle::build_with_ethalon(engine, block).await?;
            tokio::task::spawn_blocking(move || {
                bundle.save("target/bundles").ok();
            });
        }
        Ok(Success::Engine_Validator_Success)
    }

    async fn prepare_future_bundle(&self, prev_block_ids: Vec<BlockIdExt>) -> Result<Success> {
        if let DataSource::Engine(ref engine) = self.data_source {
            let bundle = CollatorTestBundle::build_for_collating_block(
                engine,
                prev_block_ids,
                None,
                Vec::new(),
            )
            .await?;
            tokio::task::spawn_blocking(move || {
                bundle.save("target/bundles").ok();
            });
        }
        Ok(Success::Engine_Validator_Success)
    }

    /// The full node, when it serves requests. The key ring the reference
    /// engine also waits for exists before this server does, so only the
    /// full node can be not ready.
    fn certificate_router(
        &self,
    ) -> Option<Arc<crate::network::full_node_overlays::FullNodeOverlaysRouter>> {
        if !matches!(self.data_source, DataSource::Engine(_)) {
            return None;
        }
        self.certificates.as_ref()?.serving_router().ok()
    }

    /// Integer fields keep the wire bit patterns: the unsigned size is the
    /// signed wire value reinterpreted, as the reference engine does.
    fn sign_shard_overlay_certificate(
        &self,
        query: SignShardOverlayCertificate,
    ) -> Result<QueryResult> {
        let Some(router) = self.certificate_router() else {
            return control_error(ERROR_CODE_NOTREADY, "not started");
        };
        let subject = KeyId::from_data(query.signed_key.key_hash().clone().inner());
        match router.sign_shard_overlay_certificate_wire(
            WireShard { workchain: query.workchain, shard: query.shard },
            &subject,
            query.expire_at,
            query.max_size as u32,
        ) {
            Ok(certificate) => QueryResult::consume_boxed(
                certificate,
                #[cfg(feature = "telemetry")]
                None,
            ),
            Err(error) => {
                control_error(error_code(&error), format!("failed to import cert: {error}"))
            }
        }
    }

    fn import_shard_overlay_certificate(
        &self,
        query: ImportShardOverlayCertificate,
    ) -> Result<QueryResult> {
        let Some(router) = self.certificate_router() else {
            return control_error(ERROR_CODE_NOTREADY, "not started");
        };
        let signed_key = KeyId::from_data(query.signed_key.key_hash().clone().inner());
        match router.import_shard_overlay_certificate_wire(
            WireShard { workchain: query.workchain, shard: query.shard },
            &signed_key,
            &query.cert,
        ) {
            Ok(()) => QueryResult::consume_boxed(
                Success::Engine_Validator_Success,
                #[cfg(feature = "telemetry")]
                None,
            ),
            Err(error) => {
                control_error(error_code(&error), format!("failed to import cert: {error}"))
            }
        }
    }

    async fn set_ext_messages_broadcast_disabled(&self, disabled: bool) -> Result<QueryResult> {
        if self.certificate_router().is_none() {
            return control_error(ERROR_CODE_NOTREADY, "not started");
        }
        match self.config.set_ext_messages_broadcast_disabled(disabled).await {
            Ok(()) => QueryResult::consume_boxed(
                Success::Engine_Validator_Success,
                #[cfg(feature = "telemetry")]
                None,
            ),
            Err(error) => control_error(error_code(&error), error.to_string()),
        }
    }

    async fn redirect_external_message(&self, message_data: &[u8]) -> Result<Success> {
        let engine = self.engine()?;
        engine.redirect_external_message(message_data).await?;
        Ok(Success::Engine_Validator_Success)
    }

    /// Answers a query from a listed client, in the reference engine's order:
    /// an unserved query is refused as unsupported, then the permission bits
    /// are checked, and only then the handler runs.
    async fn dispatch(&self, query: TLObject, permissions: u32) -> Result<QueryResult> {
        log::debug!("query (control server): {:?}", query);
        let Some(required) = required_permission(&query) else {
            log::warn!("Unsupported ControlQuery (control server): {:?}", query);
            return control_error(ERROR_CODE_PROTOVIOLATION, "query not supported");
        };
        if permissions & required != required {
            return control_error(ERROR_CODE_ERROR, "not authorized");
        }
        let query = match query.downcast::<GetTime>() {
            Ok(_) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|elapsed| elapsed.as_secs())
                    .unwrap_or(0);
                let time = i32::try_from(now).unwrap_or(i32::MAX);
                return QueryResult::consume_boxed(
                    Time { time }.into_boxed(),
                    #[cfg(feature = "telemetry")]
                    None,
                );
            }
            Err(query) => query,
        };
        let query = match query.downcast::<SetVerbosity>() {
            Ok(query) => {
                if !(0..=10).contains(&query.verbosity) {
                    return control_error(ERROR_CODE_ERROR, "verbosity should be in range [0..10]");
                }
                if let Err(error) = apply_verbosity(verbosity_level(query.verbosity)) {
                    return control_error(reply_code(&error), error.to_string());
                }
                return QueryResult::consume_boxed(
                    Success::Engine_Validator_Success,
                    #[cfg(feature = "telemetry")]
                    None,
                );
            }
            Err(query) => query,
        };
        let query = match query.downcast::<ExportPrivateKey>() {
            // The reference engine has no single-key export.
            Ok(_) => return control_error(ERROR_CODE_NOTREADY, "not implemented"),
            Err(query) => query,
        };
        let query = match query.downcast::<ExportAllPrivateKeys>() {
            Ok(query) => return self.export_all_private_keys(&query.encryption_key).await,
            Err(query) => query,
        };
        let query = match query.downcast::<GetShardAccountState>() {
            Ok(account) => {
                let answer = self.get_account_state(account.account_address).await?;
                return QueryResult::consume_boxed(
                    answer,
                    #[cfg(feature = "telemetry")]
                    None,
                );
            }
            Err(query) => query,
        };
        let query = match query.downcast::<GetShardAccountMeta>() {
            Ok(account) => {
                let answer = self.get_account_meta(account.account_address).await?;
                return QueryResult::consume_boxed(
                    answer,
                    #[cfg(feature = "telemetry")]
                    None,
                );
            }
            Err(query) => query,
        };
        let query = match query.downcast::<GetAccountByBlock>() {
            Ok(account) => {
                let answer =
                    self.get_account_by_block(account.account_id, account.block_root_hash).await?;
                return QueryResult::consume_boxed(
                    answer,
                    #[cfg(feature = "telemetry")]
                    None,
                );
            }
            Err(query) => query,
        };
        let query = match query.downcast::<GetAccountMetaByBlock>() {
            Ok(account) => {
                let answer = self
                    .get_account_meta_by_block(account.account_id, account.block_root_hash)
                    .await?;
                return QueryResult::consume_boxed(
                    answer,
                    #[cfg(feature = "telemetry")]
                    None,
                );
            }
            Err(query) => query,
        };
        let query = match query.downcast::<GetAppliedShardsInfo>() {
            Ok(_) => {
                let answer = self.get_applied_shards_info().await?;
                return QueryResult::consume_boxed(
                    answer,
                    #[cfg(feature = "telemetry")]
                    None,
                );
            }
            Err(query) => query,
        };
        let query = match query.downcast::<GenerateKeyPair>() {
            Ok(_params) => {
                return QueryResult::consume(
                    self.process_generate_keypair(ED25519_KEY_TYPE).await?,
                    #[cfg(feature = "telemetry")]
                    None,
                )
            }
            Err(query) => query,
        };
        let query = match query.downcast::<ImportPrivateKey>() {
            Ok(query) => {
                return QueryResult::consume(
                    self.process_import_private_key(query.key).await?,
                    #[cfg(feature = "telemetry")]
                    None,
                )
            }
            Err(query) => query,
        };
        let query = match query.downcast::<ExportPublicKey>() {
            Ok(query) => {
                if let Err((code, message)) = self.check_key(query.key_hash.as_slice()).await {
                    return control_error(code, message);
                }
                return QueryResult::consume_boxed(
                    self.export_public_key(query.key_hash.as_slice())?,
                    #[cfg(feature = "telemetry")]
                    None,
                );
            }
            Err(query) => query,
        };
        let query = match query.downcast::<Sign>() {
            Ok(query) => {
                if self.key_ring.find(query.key_hash.as_slice()).is_err() {
                    let message =
                        format!("key not in db: {}", key_not_found(query.key_hash.as_slice()));
                    return control_error(ERROR_CODE_KEY_NOT_FOUND, message);
                }
                return QueryResult::consume(
                    self.process_sign_data(query.key_hash.as_slice(), &query.data)?,
                    #[cfg(feature = "telemetry")]
                    None,
                );
            }
            Err(query) => query,
        };
        let query = match query.downcast::<AddAdnlId>() {
            Ok(query) => {
                if !self.started() {
                    return control_error(ERROR_CODE_NOTREADY, "not started");
                }
                // A category outside 0..=255 fails before the key lookup; the
                // reference engine then drops the reply and the connection.
                let Ok(category) = u8::try_from(query.category) else {
                    return Err(CloseConnection.into());
                };
                let key = query.key_hash.inner();
                return self
                    .run_key_command(
                        Some(&key),
                        KeyCommand::AddAdnlId { id: base64_encode(key), category },
                        "failed to add adnl node: ",
                    )
                    .await;
            }
            Err(query) => query,
        };
        let query = match query.downcast::<DelAdnlId>() {
            Ok(query) => {
                let id = base64_encode(query.key_hash.inner());
                return self
                    .run_key_command(
                        None,
                        KeyCommand::DelAdnlId { id },
                        "failed to del adnl node: ",
                    )
                    .await;
            }
            Err(query) => query,
        };
        let query = match query.downcast::<AddValidatorPermanentKey>() {
            Ok(query) => {
                let key = query.key_hash.inner();
                let command = KeyCommand::AddPermanentKey {
                    validator: base64_encode(key),
                    election_date: query.election_date,
                    expire_at: wire_unsigned(query.ttl),
                };
                return self
                    .run_key_command(Some(&key), command, "failed to add validator permanent key: ")
                    .await;
            }
            Err(query) => query,
        };
        let query = match query.downcast::<AddValidatorTempKey>() {
            Ok(query) => {
                let key = query.key_hash.inner();
                let command = KeyCommand::AddTempKey {
                    validator: base64_encode(query.permanent_key_hash.inner()),
                    key: base64_encode(key),
                    expire_at: wire_unsigned(query.ttl),
                };
                return self
                    .run_key_command(Some(&key), command, "failed to add validator temp key: ")
                    .await;
            }
            Err(query) => query,
        };
        let query = match query.downcast::<AddValidatorAdnlAddress>() {
            Ok(query) => {
                let key = query.key_hash.inner();
                let command = KeyCommand::AddAdnlAddress {
                    validator: base64_encode(query.permanent_key_hash.inner()),
                    adnl: base64_encode(key),
                    expire_at: wire_unsigned(query.ttl),
                };
                return self
                    .run_key_command(Some(&key), command, "failed to add validator adnl address: ")
                    .await;
            }
            Err(query) => query,
        };
        let query = match query.downcast::<DelValidatorPermanentKey>() {
            Ok(query) => {
                let command = KeyCommand::DelPermanentKey {
                    validator: base64_encode(query.key_hash.inner()),
                };
                return self
                    .run_key_command(None, command, "failed to del validator permanent key: ")
                    .await;
            }
            Err(query) => query,
        };
        let query = match query.downcast::<DelValidatorTempKey>() {
            Ok(query) => {
                let command = KeyCommand::DelTempKey {
                    validator: base64_encode(query.permanent_key_hash.inner()),
                    key: base64_encode(query.key_hash.inner()),
                };
                return self
                    .run_key_command(None, command, "failed to del validator temp key: ")
                    .await;
            }
            Err(query) => query,
        };
        let query = match query.downcast::<DelValidatorAdnlAddress>() {
            Ok(query) => {
                let command = KeyCommand::DelAdnlAddress {
                    validator: base64_encode(query.permanent_key_hash.inner()),
                    adnl: base64_encode(query.key_hash.inner()),
                };
                return self
                    .run_key_command(None, command, "failed to del validator adnl addr: ")
                    .await;
            }
            Err(query) => query,
        };
        let query = match query.downcast::<GetBundle>() {
            Ok(query) => {
                return QueryResult::consume_boxed(
                    self.prepare_bundle(query.block_id.clone()).await?,
                    #[cfg(feature = "telemetry")]
                    None,
                )
            }
            Err(query) => query,
        };
        let query = match query.downcast::<GetFutureBundle>() {
            Ok(query) => {
                let prev_block_ids = query.prev_block_ids.to_vec();
                return QueryResult::consume_boxed(
                    self.prepare_future_bundle(prev_block_ids).await?,
                    #[cfg(feature = "telemetry")]
                    None,
                );
            }
            Err(query) => query,
        };
        let query = match query.downcast::<SendMessage>() {
            Ok(query) => {
                let message_data = query.body;
                return QueryResult::consume_boxed(
                    self.redirect_external_message(&message_data).await?,
                    #[cfg(feature = "telemetry")]
                    None,
                );
            }
            Err(query) => query,
        };
        let query = match query.downcast::<GetConfigParams>() {
            Ok(query) => {
                let param_number =
                    query.param_list.first().ok_or_else(|| error!("Invalid param_number"))?;
                let answer = self.get_config_params(*param_number as u32).await?;

                return QueryResult::consume_boxed(
                    answer.into_boxed(),
                    #[cfg(feature = "telemetry")]
                    None,
                );
            }
            Err(query) => query,
        };
        let query = match query.downcast::<GetBlock>() {
            Ok(GetBlock { id }) => {
                let engine = self.engine()?;
                let (full_id, data) = engine
                    .lookup_block_by_seqno(&id.shard().into(), id.seq_no)
                    .await?
                    .ok_or_else(|| error!("Block not found: {:?}", id))?;
                let answer = ton::lite_server::blockdata::BlockData { id: full_id, data };
                return QueryResult::consume_boxed(
                    answer.into_boxed(),
                    #[cfg(feature = "telemetry")]
                    None,
                );
            }
            Err(query) => query,
        };
        let query = match query.downcast::<GetConfigAll>() {
            Ok(_) => {
                let answer = self.get_all_config_params().await?;
                return QueryResult::consume_boxed(
                    answer.into_boxed(),
                    #[cfg(feature = "telemetry")]
                    None,
                );
            }
            Err(query) => query,
        };
        let query = match query.downcast::<GetStats>() {
            Ok(_) => return self.get_stats().await,
            Err(query) => query,
        };
        let query = match query.downcast::<GetSelectedStats>() {
            Ok(get_stats) => {
                let answer = self.get_selected_stats(Some(&get_stats.filter)).await?;
                return QueryResult::consume_boxed(
                    answer.into_boxed(),
                    #[cfg(feature = "telemetry")]
                    None,
                );
            }
            Err(query) => query,
        };

        let query = match query.downcast::<GetConfig>() {
            Ok(_) => {
                let answer = self.get_validator_config().await?;
                return QueryResult::consume_boxed(
                    answer.into_boxed(),
                    #[cfg(feature = "telemetry")]
                    None,
                );
            }
            Err(query) => query,
        };

        let query = match query.downcast::<AddCustomOverlay>() {
            Ok(params) => {
                return QueryResult::consume_boxed(
                    self.add_custom_overlay(params.overlay).await?,
                    #[cfg(feature = "telemetry")]
                    None,
                );
            }
            Err(query) => query,
        };

        let query = match query.downcast::<DelCustomOverlay>() {
            Ok(params) => {
                return QueryResult::consume_boxed(
                    self.del_custom_overlay(params.name).await?,
                    #[cfg(feature = "telemetry")]
                    None,
                );
            }
            Err(query) => query,
        };

        let query = match query.downcast::<SignShardOverlayCertificate>() {
            Ok(query) => return self.sign_shard_overlay_certificate(query),
            Err(query) => query,
        };

        let query = match query.downcast::<ImportShardOverlayCertificate>() {
            Ok(query) => return self.import_shard_overlay_certificate(query),
            Err(query) => query,
        };

        let query = match query.downcast::<SetExtMessagesBroadcastDisabled>() {
            Ok(query) => {
                return self.set_ext_messages_broadcast_disabled((&query.disabled).into()).await
            }
            Err(query) => query,
        };

        let query = match query.downcast::<ShowCustomOverlays>() {
            Ok(_) => {
                return QueryResult::consume_boxed(
                    self.config.show_custom_overlays().await?,
                    #[cfg(feature = "telemetry")]
                    None,
                );
            }
            Err(query) => query,
        };

        log::warn!("Unsupported ControlQuery (control server): {:?}", query);
        control_error(ERROR_CODE_PROTOVIOLATION, "query not supported")
    }

    /// Authorizes the client before the query body is decoded: a client this
    /// server does not list is refused whatever it sent, and the connection
    /// stays open.
    async fn consume_raw(&self, bytes: &[u8], peers: &AdnlPeers) -> Result<Option<QueryResult>> {
        let Some(permissions) = self.permissions.get(peers.other().data()).copied() else {
            return control_error(ERROR_CODE_ERROR, "forbidden").map(Some);
        };
        let object = match deserialize_boxed(bytes) {
            Ok(object) => object,
            Err(error) => {
                return control_error(0, format!("failed to parse validator query: {error}"))
                    .map(Some)
            }
        };
        if object.is::<LiteServerQuery>() {
            // The lite-server path of the control port is not served here.
            return Ok(None);
        }
        let query = match object.downcast::<ControlQuery>() {
            Ok(query) => query,
            Err(object) => {
                return control_error(
                    0,
                    format!("failed to parse validator query: not a control query {object:?}"),
                )
                .map(Some)
            }
        };
        let query = match deserialize_boxed(&query.data[..]) {
            Ok(query) => query,
            Err(error) => {
                return control_error(0, format!("failed to parse validator query: {error}"))
                    .map(Some)
            }
        };
        let result = match self.dispatch(query, permissions).await {
            Ok(result) => result,
            Err(err) if err.downcast_ref::<CloseConnection>().is_some() => return Err(err),
            Err(err) => QueryResult::consume_boxed(
                ControlQueryError { code: -1, message: err.to_string() }.into_boxed(),
                #[cfg(feature = "telemetry")]
                None,
            )?,
        };
        Ok(Some(result))
    }
}

#[async_trait::async_trait]
impl Subscriber for ControlQuerySubscriber {
    async fn try_consume_raw_query(
        &self,
        bytes: &[u8],
        peers: &AdnlPeers,
    ) -> Result<Option<QueryAnswer>> {
        let now = std::time::Instant::now();
        let result = match self.consume_raw(bytes, peers).await? {
            Some(result) => into_answer(result),
            None => Ok(None),
        };
        log::trace!("Control server operation {} TIME", now.elapsed().as_millis());
        result
    }
}

#[cfg(test)]
#[path = "../tests/test_control.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/test_control_permissions.rs"]
mod permissions_tests;

#[cfg(test)]
#[path = "../tests/test_control_keys.rs"]
mod key_tests;

#[cfg(test)]
#[path = "../tests/test_control_pq_section.rs"]
mod pq_section_tests;

#[cfg(test)]
#[path = "../tests/test_control_handlers.rs"]
mod handler_tests;
