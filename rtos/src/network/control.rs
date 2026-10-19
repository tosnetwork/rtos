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
    config::{KeyCommand, KeyCommandError, KeyRing, NodeConfigHandler},
    engine_traits::{EngineOperations, Stoppable},
    network::{
        liteserver::LiteServerQuerySubscriber,
        node_network::NodeNetwork,
        shard_overlay_certificates::{error_code, ShardCertificateEndpoint, WireShard},
    },
};
use adnl::{
    common::{AdnlPeers, QueryAnswer, QueryResult, Subscriber},
    server::{AdnlServer, AdnlServerConfig, ClientPermissions},
};
use rtos_api::{
    deserialize_boxed,
    ton::{
        engine::validator::{
            controlqueryerror::ControlQueryError, customoverlay::CustomOverlay,
            exportedprivatekeys::ExportedPrivateKeys, jsonconfig::JsonConfig, keyhash::KeyHash,
            onestat::OneStat, signature::Signature, stats::Stats, time::Time, Success,
        },
        rpc::engine::validator::{
            AddAdnlId, AddCustomOverlay, AddValidatorAdnlAddress, AddValidatorPermanentKey,
            AddValidatorTempKey, DelAdnlId, DelCustomOverlay, DelValidatorAdnlAddress,
            DelValidatorPermanentKey, DelValidatorTempKey, ExportAllPrivateKeys, ExportPrivateKey,
            ExportPublicKey, GenerateKeyPair, GetConfig, GetStats, GetTime, ImportPrivateKey,
            ImportShardOverlayCertificate, SetExtMessagesBroadcastDisabled, SetVerbosity,
            ShowCustomOverlays, Sign, SignShardOverlayCertificate,
        },
        PrivateKey, PublicKey,
    },
    IntoBoxed, TLObject,
};
use rtos_block::{
    base64_encode, error, fail, sha256_digest, BlockIdExt, KeyId, KeyOption, Result, UInt256,
    ED25519_KEY_TYPE,
};
use secrets_vault::vault_block::get_key_option_factory;
use std::sync::Arc;

/// Permission bits of a control client, as the reference engine defines them.
pub(crate) const VEP_DEFAULT: u32 = 1;
pub(crate) const VEP_MODIFY: u32 = 2;
pub(crate) const VEP_UNSAFE: u32 = 4;

/// Limits of the lite-server path of the control port: the lite server's
/// defaults.
const CONTROL_LITE_FAST_QUERIES: u64 = 256;
const CONTROL_LITE_SLOW_QUERIES: u64 = 16;
const CONTROL_LITE_ACCOUNT_CACHE_MB: u64 = 256;

/// Reference engine error codes used in control replies.
const ERROR_CODE_ERROR: i32 = 602;
const ERROR_CODE_PROTOVIOLATION: i32 = 621;
const ERROR_CODE_NOTREADY: i32 = 651;

/// The permission bits a served control query needs; `None` is a query this
/// server does not serve. A lite-server query on the control port needs only
/// that its client is listed.
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

/// The constructor ids of every function of the reference engine's schema,
/// sorted; a control query naming any other constructor fails to parse.
const REFERENCE_FUNCTIONS: [u32; 170] = [
    0x00c1a022, 0x01457726, 0x03806c81, 0x093ddd78, 0x0a7a545b, 0x0b02248f, 0x0b94a40a, 0x0bbfa683,
    0x11b7d099, 0x128333c0, 0x15807ac7, 0x15c29fb1, 0x15cd0649, 0x1621ef14, 0x1661fe60, 0x174ac8fa,
    0x1ac30a58, 0x1ae2e498, 0x1aea1a28, 0x1db3216d, 0x1faaa1bf, 0x222cbc61, 0x2335fb5a, 0x26bcbb98,
    0x281f5acc, 0x293a74f2, 0x2ba1e7ea, 0x2bc35b22, 0x2d35f2a0, 0x2fc05215, 0x315bb84f, 0x333d79db,
    0x348bf3fc, 0x34934212, 0x352f8a56, 0x3946614c, 0x3b3fe208, 0x3baeb69b, 0x3c82c0cf, 0x3f64895b,
    0x4174b4e2, 0x421c283a, 0x42db9f96, 0x4397d69b, 0x44f3f211, 0x48ee64ab, 0x4c42def9, 0x4d082b9a,
    0x4d3135d2, 0x4f95e21f, 0x52d5c311, 0x5431bf77, 0x543fba6c, 0x54590a3b, 0x55086f12, 0x55e184bd,
    0x565ffcb0, 0x5973e88c, 0x599b5d80, 0x59ad2225, 0x5ae0f750, 0x5c973c56, 0x5c9a4066, 0x5daac511,
    0x604f2d1c, 0x6074ab78, 0x61b191e1, 0x6234a8b9, 0x680449ad, 0x68061fa0, 0x68a0ecd0, 0x690cb481,
    0x6ce2ce6b, 0x6d0c9297, 0x6e80ea19, 0x6f5ecfa6, 0x6ffb5781, 0x731d3bf4, 0x735d2df1, 0x747a5d9d,
    0x7578cc7d, 0x769fc0e8, 0x7949426c, 0x7a9c09d5, 0x7bd0590d, 0x7d530769, 0x7db1e7e5, 0x7def77c7,
    0x7fff7bfa, 0x8060d7f9, 0x807ae660, 0x812857f5, 0x84fd5b3e, 0x87ad0787, 0x87fd94eb, 0x8a9109da,
    0x8d336f32, 0x8d7aa279, 0x8dacb78c, 0x8f123202, 0x90745d0c, 0x91c4962a, 0x92150578, 0x92767f31,
    0x92cd9671, 0x939fdee3, 0x93fa5a3e, 0x94271ee8, 0x94ffc3e9, 0x9aae907f, 0x9c50ff1f, 0x9d99bc2b,
    0xa0e6e0d1, 0xa40b09fe, 0xa476bdc0, 0xa97948ed, 0xad2a7842, 0xae4b6011, 0xb083ff2a, 0xb1825e82,
    0xb535689e, 0xb659165e, 0xb942153b, 0xbe2fbd72, 0xbe7b2522, 0xbec6c985, 0xc13d3142, 0xc4461b53,
    0xc6f4b24e, 0xc81fde27, 0xcbeb3f18, 0xcc728048, 0xccfd8443, 0xcd5653f2, 0xcf280039, 0xd06cced8,
    0xd1e420ca, 0xd4b8bb5f, 0xd4bcd72a, 0xd7252362, 0xd72dd1ee, 0xd7cfcf0b, 0xdacba682, 0xdb721f89,
    0xdbb8eac6, 0xdc44a7f3, 0xde2d22c9, 0xe0d59ac5, 0xe0fd3df5, 0xe140bed1, 0xe57f583d, 0xe65241fc,
    0xe9abff94, 0xea42f8ef, 0xea6b89b5, 0xeb25607b, 0xed8554ab, 0xee07d861, 0xf08a0f47, 0xf3acb726,
    0xf50c1e8c, 0xf677ab10, 0xf6fd33f5, 0xf708435a, 0xf7e24955, 0xf7e28640, 0xf9c3b1c6, 0xfcd8acce,
    0xfdbcbff1, 0xff8f0f47,
];

/// The control-port framing as the reference engine reads it: a lite-server
/// query is told apart first, then the control query envelope and its
/// function are parsed with the reference parser's rules, positions and
/// messages, before this server decodes the function itself.
mod frame {
    use super::REFERENCE_FUNCTIONS;
    use rtos_api::{
        ton::rpc::engine::validator::{
            AddAdnlId, AddCustomOverlay, AddValidatorAdnlAddress, AddValidatorPermanentKey,
            AddValidatorTempKey, ControlQuery, DelAdnlId, DelCustomOverlay,
            DelValidatorAdnlAddress, DelValidatorPermanentKey, DelValidatorTempKey,
            ExportAllPrivateKeys, ExportPrivateKey, ExportPublicKey, GenerateKeyPair, GetConfig,
            GetStats, GetTime, ImportPrivateKey, ImportShardOverlayCertificate,
            SetExtMessagesBroadcastDisabled, SetVerbosity, ShowCustomOverlays, Sign,
            SignShardOverlayCertificate,
        },
        Constructor,
    };

    const LITE_SERVER_QUERY: u32 = 0x798c_06df;
    const BOOL_TRUE: u32 = 0x9972_75b5;
    const BOOL_FALSE: u32 = 0xbc79_9737;
    const KEY_HASH: u32 = 0xc2c6_a54e;

    /// A field as the reference parser reads it.
    pub(super) enum Field {
        Int,
        Long,
        Int256,
        Bytes,
        Bool,
        /// A boxed type with one constructor.
        Exact(u32, &'static [Field]),
        /// A boxed type with several constructors.
        OneOf(&'static [(u32, &'static [Field])]),
        /// A bare vector of bare elements.
        Vector(&'static [Field]),
    }

    use Field::*;

    const PUBLIC_KEY: &[(u32, &[Field])] = &[
        (0xb61f_450a, &[Bytes]),
        (0x4813_b4c6, &[Int256]),
        (0x2dbc_add4, &[Int256]),
        (0x34ba_45cb, &[Bytes]),
    ];
    const PRIVATE_KEY: &[(u32, &[Field])] = &[
        (0xb1db_9b30, &[Bytes]),
        (0x4968_2317, &[Int256]),
        (0xa5e8_5137, &[Int256]),
        (0x37a5_f65b, &[Bytes]),
    ];
    const OVERLAY_CERTIFICATE: &[(u32, &[Field])] = &[
        (0xe09e_d731, &[OneOf(PUBLIC_KEY), Int, Int, Bytes]),
        (0xb43f_9c83, &[OneOf(PUBLIC_KEY), Int, Int, Int, Bytes]),
        (0x32da_bccf, &[]),
    ];
    const CUSTOM_OVERLAY: &[Field] =
        &[Bytes, Vector(&[Int256, Bool, Int, Bool]), Vector(&[Int, Long]), Bool, Bool];

    /// The fields of every function this server serves; any other function
    /// of the reference schema is refused as unsupported without decoding.
    pub(super) fn served_fields(constructor: u32) -> Option<&'static [Field]> {
        let table: &[(u32, &'static [Field])] = &[
            (GetTime::constructor_const(), &[]),
            (ImportPrivateKey::constructor_const(), &[OneOf(PRIVATE_KEY)]),
            (ExportPrivateKey::constructor_const(), &[Int256]),
            (ExportPublicKey::constructor_const(), &[Int256]),
            (GenerateKeyPair::constructor_const(), &[]),
            (AddAdnlId::constructor_const(), &[Int256, Int]),
            (AddValidatorPermanentKey::constructor_const(), &[Int256, Int, Int]),
            (AddValidatorTempKey::constructor_const(), &[Int256, Int256, Int]),
            (AddValidatorAdnlAddress::constructor_const(), &[Int256, Int256, Int]),
            (DelAdnlId::constructor_const(), &[Int256]),
            (DelValidatorPermanentKey::constructor_const(), &[Int256]),
            (DelValidatorTempKey::constructor_const(), &[Int256, Int256]),
            (DelValidatorAdnlAddress::constructor_const(), &[Int256, Int256]),
            (GetConfig::constructor_const(), &[]),
            (Sign::constructor_const(), &[Int256, Bytes]),
            (ExportAllPrivateKeys::constructor_const(), &[OneOf(PUBLIC_KEY)]),
            (SetVerbosity::constructor_const(), &[Int]),
            (GetStats::constructor_const(), &[]),
            (
                SignShardOverlayCertificate::constructor_const(),
                &[Int, Long, Exact(KEY_HASH, &[Int256]), Int, Int],
            ),
            (
                ImportShardOverlayCertificate::constructor_const(),
                &[Int, Long, Exact(KEY_HASH, &[Int256]), OneOf(OVERLAY_CERTIFICATE)],
            ),
            (SetExtMessagesBroadcastDisabled::constructor_const(), &[Bool]),
            (AddCustomOverlay::constructor_const(), CUSTOM_OVERLAY),
            (DelCustomOverlay::constructor_const(), &[Bytes]),
            (ShowCustomOverlays::constructor_const(), &[]),
        ];
        table.iter().find(|(id, _)| *id == constructor).map(|(_, fields)| *fields)
    }

    /// The reference parser: a read past the end fails at the position the
    /// successful reads reached, and the first failure is the one reported.
    struct Parser<'a> {
        data: &'a [u8],
        pos: usize,
        error: Option<(String, usize)>,
    }

    impl<'a> Parser<'a> {
        fn new(data: &'a [u8]) -> Self {
            Self { data, pos: 0, error: None }
        }

        fn fail(&mut self, message: &str) {
            if self.error.is_none() {
                self.error = Some((message.to_string(), self.pos));
            }
        }

        /// Takes `len` bytes, or fails as the reference length check fails.
        fn take(&mut self, len: usize) -> Option<&'a [u8]> {
            if self.error.is_some() {
                return None;
            }
            match self.pos.checked_add(len).filter(|end| *end <= self.data.len()) {
                Some(end) => {
                    let bytes = &self.data[self.pos..end];
                    self.pos = end;
                    Some(bytes)
                }
                None => {
                    self.fail("Not enough data to read");
                    None
                }
            }
        }

        fn int(&mut self) -> Option<u32> {
            self.take(4).map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        }

        /// A string: the reference parser reads the length word, then the
        /// rest rounded as it rounds it.
        fn bytes(&mut self) -> Option<&'a [u8]> {
            let start = self.pos;
            let head = self.take(4)?;
            let (len, begin, aligned) = match head[0] {
                len @ 0..=253 => {
                    let len = usize::from(len);
                    (len, start + 1, (len >> 2) << 2)
                }
                254 => {
                    let len = usize::from(head[1])
                        | usize::from(head[2]) << 8
                        | usize::from(head[3]) << 16;
                    (len, start + 4, len.checked_add(3)? >> 2 << 2)
                }
                _ => {
                    let more = self.take(4)?;
                    let mut len: u64 = 0;
                    for (shift, byte) in head[1..].iter().chain(more.iter()).enumerate() {
                        len |= u64::from(*byte) << (8 * shift);
                    }
                    let Some(len) = usize::try_from(len).ok().filter(|len| *len <= usize::MAX - 3)
                    else {
                        self.fail("Too big string found");
                        return None;
                    };
                    (len, start + 8, (len + 3) >> 2 << 2)
                }
            };
            self.take(aligned)?;
            self.data.get(begin..begin.checked_add(len)?)
        }

        fn fields(&mut self, fields: &[Field]) {
            for field in fields {
                if self.error.is_some() {
                    return;
                }
                self.field(field);
            }
        }

        fn field(&mut self, field: &Field) {
            match field {
                Int => {
                    self.int();
                }
                Long => {
                    self.take(8);
                }
                Int256 => {
                    self.take(32);
                }
                Bytes => {
                    self.bytes();
                }
                Bool => {
                    if let Some(value) = self.int() {
                        if value != BOOL_TRUE && value != BOOL_FALSE {
                            self.fail("Bool expected");
                        }
                    }
                }
                Exact(id, fields) => {
                    if let Some(value) = self.int() {
                        if value != *id {
                            self.fail("Wrong constructor found");
                            return;
                        }
                        self.fields(fields);
                    }
                }
                OneOf(constructors) => {
                    if let Some(value) = self.int() {
                        match constructors.iter().find(|(id, _)| *id == value) {
                            Some((_, fields)) => self.fields(fields),
                            None => self.fail(&format!("Unknown constructor found 0x{value:08x}")),
                        }
                    }
                }
                Vector(element) => {
                    if let Some(count) = self.int() {
                        let left = self.data.len().saturating_sub(self.pos);
                        if left < count as usize {
                            self.fail("Wrong vector length");
                            return;
                        }
                        for _ in 0..count {
                            self.fields(element);
                            if self.error.is_some() {
                                return;
                            }
                        }
                    }
                }
            }
        }

        fn end(&mut self) {
            if self.error.is_none() && self.pos != self.data.len() {
                self.fail("Too much data to fetch");
            }
        }

        fn result(&self) -> Result<(), String> {
            match &self.error {
                Some((message, pos)) => Err(format!("{message} at {pos}")),
                None => Ok(()),
            }
        }
    }

    /// What the bytes of a control-port query are.
    pub(super) enum Frame<'a> {
        /// A lite-server query, for the lite-server path.
        Lite,
        /// A function this server serves, already checked as the reference
        /// parser checks it; its bytes are to be decoded.
        Served(&'a [u8]),
        /// A function of the reference schema this server does not serve.
        Unserved,
    }

    /// Reads a control-port query; a failure is the reference parser's
    /// message with its position.
    pub(super) fn read(bytes: &[u8]) -> Result<Frame<'_>, String> {
        let mut lite = Parser::new(bytes);
        if lite.int() == Some(LITE_SERVER_QUERY) {
            lite.bytes();
            lite.end();
            if lite.result().is_ok() {
                return Ok(Frame::Lite);
            }
        }
        let mut outer = Parser::new(bytes);
        let mut data: &[u8] = &[];
        if let Some(value) = outer.int() {
            if value != ControlQuery::constructor_const() {
                outer.fail("Wrong constructor found");
            } else if let Some(inner) = outer.bytes() {
                data = inner;
            }
        }
        outer.end();
        outer.result()?;
        let mut inner = Parser::new(data);
        let Some(constructor) = inner.int() else {
            inner.result()?;
            return Err("Not enough data to read at 0".to_string());
        };
        if REFERENCE_FUNCTIONS.binary_search(&constructor).is_err() {
            inner.fail(&format!("Unknown constructor found 0x{constructor:08x}"));
            inner.result()?;
        }
        let Some(fields) = served_fields(constructor) else {
            return Ok(Frame::Unserved);
        };
        inner.fields(fields);
        inner.end();
        inner.result()?;
        Ok(Frame::Served(data))
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
        // The control subscriber comes first, so that a client it does not
        // list never reaches the lite-server path.
        let lite = match &data_source {
            DataSource::Engine(engine) => {
                Some(Arc::new(LiteServerQuerySubscriber::new_with_profile(
                    rtos_api::WireProfile::T0,
                    tokio::runtime::Handle::current(),
                    engine.clone(),
                    CONTROL_LITE_FAST_QUERIES,
                    CONTROL_LITE_SLOW_QUERIES,
                    CONTROL_LITE_ACCOUNT_CACHE_MB,
                )?) as Arc<dyn Subscriber>)
            }
            DataSource::Status(_) => None,
        };
        let mut subscribers: Vec<Arc<dyn Subscriber>> = vec![Arc::new(
            ControlQuerySubscriber::new(data_source, key_ring, node_config, network, permissions)?,
        )];
        subscribers.extend(lite);
        let ret = Self {
            adnl: AdnlServer::listen(
                config,
                subscribers,
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

/// The engine's start-up status. Before the engine has started the reference
/// engine answers every engine query with "not started", so the control port
/// holds the status but does not read it.
pub trait StatusReporter: Send + Sync {
    #[allow(dead_code)]
    fn get_report(&self) -> u32;
}

/// What the control port serves from.
pub enum DataSource {
    Engine(Arc<dyn EngineOperations>),
    Status(#[allow(dead_code)] Arc<dyn StatusReporter>),
}

struct ControlQuerySubscriber {
    data_source: DataSource,
    key_ring: Arc<dyn KeyRing>,
    config: Arc<NodeConfigHandler>,
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
        let certificates = network.map(|network| network.shard_certificate_endpoint().clone());
        let ret = Self { data_source, key_ring, config, certificates, permissions };
        Ok(ret)
    }

    fn engine(&self) -> Result<&Arc<dyn EngineOperations>> {
        match self.data_source {
            DataSource::Engine(ref engine) => Ok(engine),
            _ => fail!("`engine is not set`"),
        }
    }

    fn add_stats(stats: &mut Vec<OneStat>, key: impl ToString, value: impl ToString) {
        stats.push(OneStat { key: key.to_string(), value: value.to_string() })
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
            // The reference engine reports the block handle's time.
            let time = match engine.load_block_handle(&mc_block_id)? {
                Some(handle) => handle.gen_utime(),
                None => state.state()?.gen_time(),
            };
            Self::add_stats(&mut stats, "masterchainblocktime", time);
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
        let query = match query.downcast::<GetStats>() {
            Ok(_) => return self.get_stats().await,
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
        let data = match frame::read(bytes) {
            // The lite-server path; before the engine starts nothing answers
            // it and the connection closes, as with the reference engine.
            Ok(frame::Frame::Lite) => return Ok(None),
            Ok(frame::Frame::Unserved) => {
                return control_error(ERROR_CODE_PROTOVIOLATION, "query not supported").map(Some)
            }
            Ok(frame::Frame::Served(data)) => data,
            Err(error) => {
                return control_error(0, format!("failed to parse validator query: {error}"))
                    .map(Some)
            }
        };
        let query = match deserialize_boxed(data) {
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
                ControlQueryError { code: reply_code(&err), message: err.to_string() }.into_boxed(),
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

#[cfg(test)]
#[path = "../tests/test_control_framing.rs"]
mod framing_tests;
