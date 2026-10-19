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
// Publish a complete configuration only after its contents are durable. The
// temporary file lives beside the destination so replacement stays atomic.
fn write_config_durable(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    // Keep configured symlinks pointing at the same target when replacing it.
    let path = match std::fs::canonicalize(path) {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => path.to_owned(),
        Err(error) => return Err(error.into()),
    };
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let name = path.file_name().ok_or_else(|| error!("Configuration path has no filename"))?;
    let permissions = match std::fs::metadata(&path) {
        Ok(metadata) => Some(metadata.permissions()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let (temporary, mut file) = loop {
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut temporary_name = name.to_os_string();
        temporary_name.push(format!(".{}.{}.tmp", std::process::id(), sequence));
        let temporary = parent.join(temporary_name);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
        match options.open(&temporary) {
            Ok(file) => break (temporary, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    };
    let result = (|| -> Result<()> {
        file.write_all(bytes)?;
        if let Some(permissions) = permissions { file.set_permissions(permissions)?; }
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, &path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    // Never remove the published destination after an uncertain directory sync.
    if result.is_err() { let _ = std::fs::remove_file(&temporary); }
    result
}

use crate::network::{
    liteserver::{LiteServerConfig, LiteServerConfigJson},
    node_network::NodeNetwork,
    shard_overlay_certificates::ShardOverlayCertificatePolicy,
};
use adnl::{
    client::AdnlClientConfigJson,
    common::{add_unbound_object_to_map_with_update, Wait},
    node::{AdnlNodeConfig, AdnlNodeConfigJson},
    server::{AdnlServerConfig, AdnlServerConfigJson},
};
use rtos_api::{
    ton::{
        self,
        adnl::{address::address::Udp, addresslist::AddressList as AdnlAddressList},
        dht::node::Node as DhtNodeConfig,
        engine::validator::{
            customoverlay::CustomOverlay, customoverlaynode::CustomOverlayNode,
            customoverlaysconfig::CustomOverlaysConfig,
            CustomOverlaysConfig as CustomOverlaysConfigBoxed,
        },
        pk::privatekey::Ed25519 as Ed25519Private,
        pub_::publickey::Ed25519,
        PrivateKey,
    },
    IntoBoxed,
};
use rtos_block::{
    base64_decode, base64_encode, error, fail, BlockIdExt, Ed25519KeyOption, KeyId, KeyOption,
    KeyOptionJson, MsgAddressInt, Result, SecretBytes, ShardIdent, UInt256, ZeroizingBytes,
};
use rtos_block_json::PathMap;
use secrets_vault::{
    crypto::factory::CryptoFactory,
    errors::error::VaultError,
    make_secret_id,
    memory::protected_memory::ProtectedMemory,
    types::{
        algorithm::Algorithm as SecretAlgorithm,
        metadata::Metadata as SecretMetadata,
        secret::{Secret, SecretInMemoryFactory},
        secret_id::SecretId,
        store_mode::StoreMode as SecretStoreMode,
    },
    vault::SecretVault,
    vault_block::{get_key_option_factory, get_vault, BlockCryptoFactory},
};
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    fmt::{Display, Formatter},
    fs::File,
    io::BufReader,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        atomic::{self, AtomicI32},
        Arc,
    },
    time::Duration,
};
use storage::{archives::epoch::ArchivalModeConfig, shardstate_db_async::CellsDbConfig};

#[macro_export]
macro_rules! key_option_public_key {
    ($key: expr) => {
        format!(
            "{{
            \"type_id\": 1209251014,
            \"pub_key\": \"{}\"
            }}",
            $key
        )
        .as_str()
    };
}

async fn try_n_times<F, Fut, T, E>(
    attempts: usize,
    retry_delay: Duration,
    mut f: F,
) -> std::result::Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<T, E>>,
{
    let mut last_err;
    let mut i = 0;
    loop {
        match f().await {
            Ok(val) => return Ok(val),
            Err(e) => last_err = e,
        }
        i += 1;
        if i >= attempts {
            return Err(last_err);
        }
        tokio::time::sleep(retry_delay).await;
    }
}

#[async_trait::async_trait]
pub trait KeyRing: Sync + Send {
    async fn generate(&self, key_type: i32) -> Result<[u8; 32]>;
    async fn import_private_key(&self, key: PrivateKey) -> Result<[u8; 32]>;
    // find private key in KeyRing by public key hash
    fn find(&self, key_hash: &[u8; 32]) -> Result<Arc<dyn KeyOption>>;
    fn sign_data(&self, key_hash: &[u8; 32], data: &[u8]) -> Result<Vec<u8>>;
}

#[derive(serde::Deserialize, serde::Serialize, Clone, Debug)]
pub struct CellsGcConfig {
    pub gc_interval_sec: u32,
    pub cells_lifetime_sec: u64,
}

impl Default for CellsGcConfig {
    fn default() -> Self {
        CellsGcConfig { gc_interval_sec: 900, cells_lifetime_sec: 1800 }
    }
}

#[derive(serde::Deserialize, serde::Serialize, Clone, Debug)]
#[serde(default, deny_unknown_fields)]
pub struct CollatorConfig {
    pub cutoff_timeout_ms: u32,
    pub stop_timeout_ms: u32,
    pub clean_timeout_percentage_points: u32,
    pub optimistic_clean_percentage_points: u32,
    pub max_secondary_clean_timeout_percentage_points: u32,
    pub max_collate_threads: u32,
    pub retry_if_empty: bool,
    pub finalize_empty_after_ms: u32,
    pub empty_collation_sleep_ms: u32,
    pub external_messages_timeout_percentage_points: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_messages_maximum_queue_length: Option<u32>, // None - unlimited
    pub dispatch_phase_2_max_total: usize,
    pub dispatch_phase_3_max_total: usize,
    pub dispatch_phase_2_max_per_initiator: usize,
    pub dispatch_phase_3_max_per_initiator: usize,
    pub defer_messages_after: usize,
    pub defer_out_queue_size_limit: usize,
    #[serde(deserialize_with = "from_str_vec", serialize_with = "to_str_vec")]
    pub priority_list: Vec<MsgAddressInt>,
    #[serde(deserialize_with = "from_str_vec", serialize_with = "to_str_vec")]
    pub whitelist: Vec<MsgAddressInt>,
}

fn from_str_vec<'de, D, T>(deserializer: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: FromStr,
    <T as FromStr>::Err: std::fmt::Display,
{
    let s: Vec<String> = serde::Deserialize::deserialize(deserializer)?;
    let mut result = Vec::with_capacity(s.len());
    for item in s {
        result.push(item.parse().map_err(serde::de::Error::custom)?);
    }
    Ok(result)
}

fn to_str_vec<T, S>(items: &Vec<T>, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: ToString,
{
    let s: Vec<String> = items.iter().map(|item| item.to_string()).collect();
    serde::Serialize::serialize(&s, serializer)
}

impl Default for CollatorConfig {
    fn default() -> Self {
        Self {
            cutoff_timeout_ms: 1000,
            stop_timeout_ms: 1500,
            clean_timeout_percentage_points: 150, // 0.150 = 15% = 150ms
            optimistic_clean_percentage_points: 1000, // 1.000 = 100% = 150ms
            max_secondary_clean_timeout_percentage_points: 350, // 0.350 = 35% = 350ms
            max_collate_threads: 10,
            retry_if_empty: false,
            finalize_empty_after_ms: 800,
            empty_collation_sleep_ms: 100,
            external_messages_timeout_percentage_points: 100, // 0.1 = 10% = 100ms
            external_messages_maximum_queue_length: Some(25600),
            dispatch_phase_2_max_total: 150,
            dispatch_phase_3_max_total: 150,
            dispatch_phase_2_max_per_initiator: 20,
            dispatch_phase_3_max_per_initiator: 0,
            defer_messages_after: 10,
            defer_out_queue_size_limit: 2048,
            priority_list: Vec::new(),
            whitelist: Vec::new(),
        }
    }
}

#[derive(serde::Deserialize, serde::Serialize, Clone, Debug, Copy, Default)]
pub enum ShardStatesCacheMode {
    Off, // States saved sinchronously and not cached.
    #[default]
    Moderate, // States saved asiynchronously.
}
impl ShardStatesCacheMode {
    pub fn _is_enabled(&self) -> bool {
        matches!(self, ShardStatesCacheMode::Moderate)
    }
    pub fn is_disabled(&self) -> bool {
        matches!(self, ShardStatesCacheMode::Off)
    }
}

pub struct SecretsVaultConfig {}

impl SecretsVaultConfig {
    const KEY_ADNL_KEY_ID: &str = "adnl_key_id";
    const KEY_ELECTION_ID: &str = "election_id";
    const KEY_EXPIRE_AT: &str = "expire_at";
    const KEY_TYPE: &str = "type";
    const KEY_VALIDATOR_KEY_ID: &str = "validator_key_id";
    const SID_PRIVATE_KEYS: &str = "private_keys";
    const SID_VALIDATOR_KEYS: &str = "validator_keys";
    const TYPE_ADNL_BOOTSTRAP_KEY: &str = "adnl_bootstrap_key";
    const TYPE_ADNL_SERVER_KEY: &str = "adnl_server_key"; // Control/lite server
    const TYPE_PRIVATE_KEY: &str = "private_key";
    const TYPE_VALIDATOR_KEY: &str = "validator_key";

    async fn drop_validator_metadata(key_id: &str) -> Result<()> {
        let Some(vault) = get_vault() else {
            return Ok(());
        };
        #[cfg(test)]
        tests::block_retirement_vault_write(Self::SID_VALIDATOR_KEYS);
        let id = make_secret_id!(Self::SID_VALIDATOR_KEYS, key_id);
        match vault.delete(&id).await {
            Err(error)
                if error
                    .downcast_ref::<VaultError>()
                    .is_some_and(|error| error.code() == VaultError::NOT_FOUND) =>
            {
                Ok(())
            }
            result => result,
        }?;
        // The file backend may have removed its in-memory entry before a failed
        // write. NOT_FOUND on retry is not proof that disk deletion completed.
        vault.flush().await
    }

    async fn on_drop(key_id: &str) -> Result<()> {
        async fn delete(vault: &SecretVault, sid: &str, key_id: &str) -> Option<anyhow::Error> {
            #[cfg(test)]
            tests::block_retirement_vault_write(sid);
            let secret_id = make_secret_id!(sid, key_id);
            vault.delete(&secret_id).await.err().filter(|e| {
                if let Some(e) = e.downcast_ref::<VaultError>() {
                    e.code() != VaultError::NOT_FOUND
                } else {
                    true
                }
            })
        }

        let Some(vault) = get_vault() else {
            return Ok(());
        };
        log::info!("Drop key from the vault: {key_id}");
        let err1 = delete(&vault, Self::SID_PRIVATE_KEYS, key_id).await;
        let err2 = delete(&vault, Self::SID_VALIDATOR_KEYS, key_id).await;
        match (err1, err2) {
            (Some(err1), Some(err2)) => fail!("{err1}, {err2}"),
            (Some(err), None) | (None, Some(err)) => fail!("{err}"),
            (None, None) => vault.flush().await,
        }
    }

    pub async fn on_load(config: &mut TonNodeConfig) -> Result<()> {
        let Some(vault) = get_vault() else {
            return Ok(());
        };

        // Create/Load secrets vault
        log::info!("Load keys from the vault");
        let metadata_list = vault.list_metadata().await?;

        // Read private keys
        for metadata in &metadata_list {
            let secret_id = metadata.secret_id.as_ref().ok_or_else(|| error!("Empty secret id"))?;
            let secret: Secret = vault.load(secret_id).await?;
            let Secret::Blob { blob } = secret else {
                continue;
            };
            if metadata.get_tag_str(Self::KEY_TYPE)? != Self::TYPE_PRIVATE_KEY {
                continue;
            }
            let key = {
                let private_key = blob.data();
                let private_key_lock = private_key.lock()?;
                let private_key_data: &[u8] = &private_key_lock
                    .get(..32)
                    .ok_or_else(|| error!("Wrong private key length"))?;
                UInt256::with_array(private_key_data.try_into()?)
            };
            let private_key_in = PrivateKey::Pk_Ed25519(Ed25519Private { key });
            config.import_private_key(private_key_in)?;
            log::info!("Read key {} from the vault", secret_id);
        }

        // Read elections metadata
        for metadata in &metadata_list {
            let secret_id = metadata.secret_id.as_ref().ok_or_else(|| error!("Empty secret id"))?;
            let secret: Secret = vault.load(secret_id).await?;
            let Secret::Blob { blob: _ } = secret else {
                continue;
            };
            if metadata.get_tag_str(Self::KEY_TYPE)? != Self::TYPE_VALIDATOR_KEY {
                continue;
            }

            let validator_key_id = metadata.get_tag_blob_b64(Self::KEY_VALIDATOR_KEY_ID)?;
            let validator_key_id = validator_key_id.as_slice();
            let election_id = metadata.get_tag_i32(Self::KEY_ELECTION_ID)?;
            let expire_at = metadata.get_tag_i32(Self::KEY_EXPIRE_AT)?;
            config.add_validator_key(validator_key_id.try_into()?, election_id, expire_at)?;
            log::info!("Read metadata for key {} from the vault", base64_encode(validator_key_id));

            if !metadata.tags.contains_key(Self::KEY_ADNL_KEY_ID) {
                continue;
            }
            let adnl_key_id = metadata.get_tag_blob_b64(Self::KEY_ADNL_KEY_ID)?;
            let adnl_key_id = adnl_key_id.as_slice();
            config.add_validator_adnl_key(validator_key_id.try_into()?, adnl_key_id.try_into()?)?;
            log::info!("Read metadata for ADNL key {} from the vault", base64_encode(adnl_key_id));
        }

        Ok(())
    }

    pub async fn save_private_key(
        key_id_b64: &str,
        key_config: &KeyOptionJson,
        key: &Arc<dyn KeyOption>,
    ) -> Result<()> {
        if key_config.vault.is_none() {
            return Ok(());
        }
        let Some(vault) = get_vault() else {
            return Ok(());
        };

        let secret = {
            let crypto = BlockCryptoFactory {}.new_crypto()?;

            log::info!("Write key {key_id_b64} to the vault");
            let key_pvt = ProtectedMemory::from_slice(key.pvt_key()?.lock()?.as_ref())?;
            let secret_id = make_secret_id!(Self::SID_PRIVATE_KEYS, key_id_b64);
            let metadata = SecretMetadata::new(Some(&secret_id), SecretAlgorithm::None, true)
                .with_tag(Self::KEY_TYPE, Self::TYPE_PRIVATE_KEY);

            SecretInMemoryFactory::new_ed25519_pvtkey_protected(key_pvt, metadata, crypto)?
        };

        vault.store(&secret, SecretStoreMode::CreateOrReplace).await
    }

    async fn save_adnl_keys(
        keys: &[Arc<dyn KeyOption>],
        type_tag: &'static str,
        log_label: &'static str,
    ) -> Result<()> {
        let mut snapshots = Vec::with_capacity(keys.len());
        for key in keys {
            let key_id_b64 = base64_encode(key.id().data());
            let pvt = ProtectedMemory::from_slice(key.pvt_key()?.lock()?.as_ref())?;
            snapshots.push((key_id_b64, pvt));
        }

        let Some(vault) = get_vault() else {
            return Ok(());
        };

        for (key_id_b64, pvt) in snapshots {
            log::info!("Write {log_label} {key_id_b64} to the vault");
            let secret_id = make_secret_id!(key_id_b64);
            let metadata = SecretMetadata::new(Some(&secret_id), SecretAlgorithm::None, true)
                .with_tag(Self::KEY_TYPE, type_tag);
            let crypto = BlockCryptoFactory {}.new_crypto()?;
            let secret =
                SecretInMemoryFactory::new_ed25519_pvtkey_protected(pvt, metadata, crypto)?;
            vault.store(&secret, SecretStoreMode::CreateOrReplace).await?;
        }
        Ok(())
    }

    pub async fn save_adnl_bootstrap_keys(adnl: &AdnlNodeConfig, tags: &[usize]) -> Result<()> {
        let keys: Vec<Arc<dyn KeyOption>> =
            tags.iter().map(|&t| adnl.key_by_tag(t)).collect::<Result<_>>()?;
        Self::save_adnl_keys(&keys, Self::TYPE_ADNL_BOOTSTRAP_KEY, "ADNL bootstrap key").await
    }

    pub async fn save_adnl_server_key(key: &Arc<dyn KeyOption>) -> Result<()> {
        Self::save_adnl_keys(
            std::slice::from_ref(key),
            Self::TYPE_ADNL_SERVER_KEY,
            "ADNL server key",
        )
        .await
    }

    pub async fn save_validator_key(key: &ValidatorKeysJson) -> Result<()> {
        let Some(vault) = get_vault() else {
            return Ok(());
        };

        let secret = {
            let crypto = BlockCryptoFactory {}.new_crypto()?;

            log::info!("Write metadata for key {} to the vault", &key.validator_key_id);
            let secret_id: SecretId =
                make_secret_id!(Self::SID_VALIDATOR_KEYS, &key.validator_key_id);
            let mut metadata = SecretMetadata::new(Some(&secret_id), SecretAlgorithm::None, true)
                .with_tag(Self::KEY_TYPE, Self::TYPE_VALIDATOR_KEY)
                .with_tag(Self::KEY_ELECTION_ID, key.election_id.to_string())
                .with_tag(Self::KEY_EXPIRE_AT, key.expire_at.to_string())
                .with_tag(Self::KEY_VALIDATOR_KEY_ID, &key.validator_key_id);
            if let Some(adnl_key_id) = &key.validator_adnl_key_id {
                log::info!("Write metadata for ADNL key {adnl_key_id} to the vault");
                metadata = metadata.with_tag(Self::KEY_ADNL_KEY_ID, adnl_key_id);
            }

            SecretInMemoryFactory::new_raw(b"".as_slice(), metadata, crypto)?
        };

        vault.store(&secret, SecretStoreMode::CreateOrReplace).await
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct TonNodeConfig {
    log_config_name: Option<String>,
    ton_global_config_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    boot_from_zerostate: Option<bool>,
    internal_db_path: Option<String>,
    validation_countdown_mode: Option<String>,
    unsafe_catchain_patches_path: Option<String>,
    #[serde(skip_serializing)]
    ip_address: Option<String>,
    /// Explicit QUIC address (ip:port). If absent, derived as same_ip:adnl_port+1000.
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_address_quic: Option<String>,
    adnl_node: Option<AdnlNodeConfigJson>,
    json_rpc_server: Option<JsonRpcServerConfigJson>,
    metrics: Option<MetricsConfigJson>,
    #[serde(skip_serializing_if = "NodeExtensions::is_default")]
    #[serde(default)]
    extensions: NodeExtensions,
    validator_keys: Option<Vec<ValidatorKeysJson>>,
    /// ADNL ids added by the operator.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    adnl_ids: Vec<AdnlIdJson>,
    /// Temporary keys of permanent validator keys.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    validator_temp_keys: Vec<ValidatorBoundKeyJson>,
    /// ADNL addresses of permanent validator keys. The address a validator
    /// entry is bound to at run time is one of its unexpired addresses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    validator_adnl_addresses: Vec<ValidatorBoundKeyJson>,
    /// Explicit local transport ownership only; never a consensus signing key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    consensus_transport_bindings: Vec<ConsensusTransportBindingJson>,
    /// The post-quantum consensus section exactly as written, a null one
    /// included. Every write of the configuration carries it unchanged; only
    /// the consensus key loader decodes and checks it.
    #[serde(
        default,
        rename = "pq_consensus",
        deserialize_with = "keep_section",
        skip_serializing_if = "Option::is_none"
    )]
    pq_consensus: Option<serde_json::Value>,
    #[serde(skip_serializing)]
    control_server_port: Option<u16>,
    control_server: Option<AdnlServerConfigJson>,
    #[serde(skip_serializing)]
    lite_server_port: Option<u16>,
    lite_server: Option<LiteServerConfigJson>,
    default_rldp_roundtrip_ms: Option<u32>,
    #[serde(default)]
    test_bundles_config: CollatorTestBundlesGeneralConfig,
    gc: Option<GC>,
    validator_key_ring: Option<HashMap<String, KeyOptionJson>>,
    #[serde(skip)]
    configs_dir: String,
    #[serde(skip)]
    port: Option<u16>,
    #[serde(skip)]
    file_name: String,
    #[serde(skip)]
    custom_overlays_file_name: String,
    #[serde(default)]
    restore_db: bool,
    #[serde(default)]
    cells_db_config: CellsDbConfig,
    #[serde(default)]
    collator_config: CollatorConfig,
    #[serde(default)]
    collator_config_mc: Option<CollatorConfig>,
    #[serde(default)]
    skip_saving_persistent_states: bool,
    #[serde(default)]
    states_cache_mode: ShardStatesCacheMode,
    #[serde(default)]
    sync_by_archives: bool,
    #[serde(default)]
    accelerated_consensus_disabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_logs_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    archival_mode: Option<ArchivalModeConfig>,
    #[serde(skip)]
    custom_overlays: CustomOverlaysConfigBoxed,
    #[serde(default)]
    pss_downloading_threads: usize,
    #[serde(default = "TonNodeConfig::default_pss_cells_cache_max_count")]
    pss_cells_cache_max_count: usize,
    #[serde(default = "TonNodeConfig::default_pss_prev_part_max_size")]
    pss_prev_part_max_size: usize,
    /// Neither broadcast nor rebroadcast external messages; set at run time
    /// by the control query and kept here.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    ext_messages_broadcast_disabled: bool,
    /// From the `--auto-sign` and `--accept-certs-from` options of this run;
    /// never written to the file.
    #[serde(skip)]
    shard_overlay_certificate_policy: ShardOverlayCertificatePolicy,
}

pub struct TonNodeGlobalConfig(TonNodeGlobalConfigJson);

#[derive(Default, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct NodeExtensions {
    pub disable_broadcast_retransmit: bool,
    pub adnl_compression: bool,
    pub broadcast_hops: Option<u8>,
}

impl NodeExtensions {
    fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

/// Local, operator-configured binding. Both identifiers are base64-encoded 32 bytes.
/// Governing state must independently authenticate the stable identity/ADNL pair.
#[derive(serde::Deserialize, serde::Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ConsensusTransportBindingJson {
    pub validator_id: String,
    pub adnl_key_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusTransportBinding {
    pub validator_id: UInt256,
    pub adnl_key_id: Arc<KeyId>,
}

#[derive(serde::Deserialize, serde::Serialize, Clone, Debug)]
pub struct ValidatorKeysJson {
    #[serde(default)]
    pub expire_at: i32,
    pub election_id: i32,
    pub validator_key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_adnl_key_id: Option<String>,
}

/// A present section is kept as written, `null` included; an absent one
/// stays absent.
fn keep_section<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<serde_json::Value>, D::Error> {
    <serde_json::Value as serde::Deserialize>::deserialize(deserializer).map(Some)
}

/// An ADNL id added by the operator, with its address category. The node's
/// own overlay and DHT identities are members without an entry, in category 0.
#[derive(serde::Deserialize, serde::Serialize, Clone, Debug, PartialEq, Eq)]
pub struct AdnlIdJson {
    pub id: String,
    pub category: u8,
}

/// A temporary key or an ADNL address bound to a permanent validator key.
/// The expiry is the unsigned reading of the wire value.
#[derive(serde::Deserialize, serde::Serialize, Clone, Debug, PartialEq, Eq)]
pub struct ValidatorBoundKeyJson {
    pub validator_key_id: String,
    pub key_id: String,
    pub expire_at: u32,
}

/// Reply codes of the reference engine for key commands.
pub const KEY_COMMAND_ERROR: i32 = 602;
pub const KEY_COMMAND_PROTOVIOLATION: i32 = 621;
pub const KEY_COMMAND_NOTREADY: i32 = 651;
/// The highest ADNL address category the reference engine accepts.
pub const MAX_ADNL_CATEGORY: u8 = 250;

/// A refused key command with the code the reference engine replies with.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct KeyCommandError {
    pub code: i32,
    pub message: String,
}

fn key_command_error(code: i32, message: &str) -> rtos_block::Error {
    KeyCommandError { code, message: message.to_string() }.into()
}

/// A key command of the control interface, with the reference engine's
/// configuration semantics.
#[derive(Debug, Clone)]
pub enum KeyCommand {
    AddAdnlId { id: String, category: u8 },
    DelAdnlId { id: String },
    AddPermanentKey { validator: String, election_date: i32, expire_at: u32 },
    AddTempKey { validator: String, key: String, expire_at: u32 },
    AddAdnlAddress { validator: String, adnl: String, expire_at: u32 },
    DelPermanentKey { validator: String },
    DelTempKey { validator: String, key: String },
    DelAdnlAddress { validator: String, adnl: String },
}

/// The parts of the configuration a key command changes.
struct KeyState {
    validator_keys: Option<Vec<ValidatorKeysJson>>,
    adnl_ids: Vec<AdnlIdJson>,
    validator_temp_keys: Vec<ValidatorBoundKeyJson>,
    validator_adnl_addresses: Vec<ValidatorBoundKeyJson>,
    validator_key_ring: Option<HashMap<String, KeyOptionJson>>,
}

/// What a key command changed, for the runtime effects that follow it.
#[derive(Debug, Default)]
struct KeyChange {
    changed: bool,
    updated: Option<ValidatorKeysJson>,
    removed: Option<ValidatorKeysJson>,
    bound: Vec<(String, i32)>,
    unbound: Vec<(String, i32)>,
    released: Vec<String>,
}

#[cfg(test)]
#[derive(Clone)]
pub struct TestEmulatorConsensusConfig {
    pub validator_keys: Vec<Arc<dyn KeyOption>>,
    pub slot_interval_min_ms: u64,
    pub slot_interval_max_ms: u64,
    pub slot_interval_reliability: f64,
}

#[cfg(test)]
impl TestEmulatorConsensusConfig {
    pub fn fixed_local(validator_keys: Vec<Arc<dyn KeyOption>>) -> Self {
        Self {
            validator_keys,
            slot_interval_min_ms: Self::default_slot_interval_min_ms(),
            slot_interval_max_ms: Self::default_slot_interval_max_ms(),
            slot_interval_reliability: 0.0,
        }
    }

    fn default_slot_interval_min_ms() -> u64 {
        100
    }

    fn default_slot_interval_max_ms() -> u64 {
        100
    }
}

#[cfg(test)]
#[derive(serde::Deserialize, serde::Serialize, Clone)]
struct TestEmulatorConsensusConfigJson {
    pub validator_keys: Vec<KeyOptionJson>,
    #[serde(default = "TestEmulatorConsensusConfig::default_slot_interval_min_ms")]
    pub slot_interval_min_ms: u64,
    #[serde(default = "TestEmulatorConsensusConfig::default_slot_interval_max_ms")]
    pub slot_interval_max_ms: u64,
    #[serde(default)]
    pub slot_interval_reliability: f64,
}

#[cfg(test)]
impl TryFrom<TestEmulatorConsensusConfigJson> for TestEmulatorConsensusConfig {
    type Error = rtos_block::Error;

    fn try_from(config: TestEmulatorConsensusConfigJson) -> Result<Self> {
        // `slot_interval_reliability` is applied as the slot tick's
        // `EmulatorDelaySpec::skip_probability`. `EmulatorParams::validate()`
        // forbids a non-zero skip there because a dropped slot tick would
        // permanently stall slot generation, so reject it here at the config
        // boundary instead of failing later during emulator setup.
        if config.slot_interval_reliability != 0.0 {
            fail!(
                "TestEmulatorConsensusConfig: slot_interval_reliability ({}) must be 0.0 \
                 (it sets the slot tick skip probability, and a skipped tick would \
                 permanently stall slot generation)",
                config.slot_interval_reliability,
            );
        }
        Ok(Self {
            validator_keys: config
                .validator_keys
                .iter()
                .map(Ed25519KeyOption::<ZeroizingBytes>::from_private_key_json)
                .collect::<Result<Vec<_>>>()?,
            slot_interval_min_ms: config.slot_interval_min_ms,
            slot_interval_max_ms: config.slot_interval_max_ms,
            slot_interval_reliability: config.slot_interval_reliability,
        })
    }
}

#[derive(serde::Deserialize, serde::Serialize, Default, Debug, Clone)]
pub struct GC {
    enable_for_archives: bool,
    archives_life_time_hours: Option<u32>, // Hours
    enable_for_shard_state_persistent: bool,
    #[serde(default)]
    cells_gc_config: CellsGcConfig,
}

#[derive(Debug, Default, serde::Deserialize, serde::Serialize, Clone)]
#[serde(default)]
pub struct CollatorTestBundlesConfig {
    build_for_unknown_errors: bool,
    known_errors: Vec<String>,
    build_for_errors: bool,
    errors: Vec<String>,
    #[serde(default)]
    build_all: bool,
    path: String,
}

impl CollatorTestBundlesConfig {
    pub fn is_enable(&self) -> bool {
        self.build_all
            || self.build_for_unknown_errors
            || (self.build_for_errors && !self.errors.is_empty())
    }

    pub fn build_all(&self) -> bool {
        self.build_all
    }

    pub fn need_to_build_for(&self, error: &str) -> bool {
        self.build_for_unknown_errors && self.known_errors.iter().all(|e| !error.contains(e))
            || self.build_for_errors && self.errors.iter().any(|e| error.contains(e))
    }

    pub fn path(&self) -> &str {
        &self.path
    }
}

#[derive(Debug, Default, serde::Deserialize, serde::Serialize, Clone)]
#[serde(default)]
pub struct CollatorTestBundlesGeneralConfig {
    pub collator: CollatorTestBundlesConfig,
    pub validator: CollatorTestBundlesConfig,
}

const LOCAL_HOST: &str = "127.0.0.1";

impl TonNodeConfig {
    pub const DEFAULT_DB_ROOT: &'static str = "node_db";
    pub const CUSTOM_OVERLAYS_CONFIG_NAME: &'static str = "custom-overlays.json";
    /// Permission bits of the console client a created configuration lists.
    pub const BOOTSTRAP_CONTROL_PERMISSIONS: i32 = 0x7fffffff;

    pub fn boot_from_zerostate(&self) -> bool {
        self.boot_from_zerostate.unwrap_or(false)
    }

    // The node binary uses `load_or_create`; tests and tools use this.
    #[allow(dead_code)]
    pub async fn from_file(
        configs_dir: &str,
        json_file_name: &str,
        adnl_config: Option<AdnlNodeConfigJson>,
        default_config_name: &str,
        client_console_key: Option<String>,
    ) -> Result<Self> {
        let (config, _) = Self::load_or_create(
            configs_dir,
            json_file_name,
            adnl_config,
            default_config_name,
            client_console_key,
        )
        .await?;
        Ok(config)
    }

    /// Loads the node configuration, or creates it from the default
    /// configuration when it does not exist yet. The flag is true only when
    /// this call wrote a new configuration file.
    pub async fn load_or_create(
        configs_dir: &str,
        json_file_name: &str,
        adnl_config: Option<AdnlNodeConfigJson>,
        default_config_name: &str,
        client_console_key: Option<String>,
    ) -> Result<(Self, bool)> {
        let config_file_path = TonNodeConfig::build_path(configs_dir, json_file_name);
        let config_file = File::open(config_file_path.clone());
        let mut created = false;

        let mut config_json = match config_file {
            Ok(file) => {
                let reader = BufReader::new(file);
                let config: TonNodeConfig = serde_json::from_reader(reader)?;
                if client_console_key.is_some() {
                    println!("Can't generate console_config.json: delete config.json before");
                }
                config
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // generate new config from default_config
                let path = TonNodeConfig::build_path(configs_dir, default_config_name);
                let default_config_file =
                    File::open(&path).map_err(|err| error!("Can't open {:?}: {}", path, err))?;

                let reader = BufReader::new(default_config_file);
                let mut config: TonNodeConfig = serde_json::from_reader(reader)?;
                // Set ADNL config
                config.adnl_node = if let Some(adnl_config) = adnl_config {
                    Some(adnl_config)
                } else {
                    let ip_address = if let Some(ip_address) = &config.ip_address {
                        ip_address
                    } else {
                        fail!("IP address is not set in default config")
                    };
                    let adnl_tags = vec![NodeNetwork::TAG_DHT_KEY, NodeNetwork::TAG_OVERLAY_KEY];
                    let (adnl_config, adnl_node) =
                        AdnlNodeConfig::with_ip_address_and_private_key_tags(
                            ip_address,
                            adnl_tags.clone(),
                        )?;
                    SecretsVaultConfig::save_adnl_bootstrap_keys(&adnl_node, &adnl_tags).await?;
                    Some(adnl_config)
                };
                config.create_and_save_console_configs(configs_dir, client_console_key).await?;
                config.create_and_save_lite_configs(configs_dir).await?;
                config.ip_address = None;
                write_config_durable(&config_file_path, &serde_json::to_vec_pretty(&config)?)?;
                created = true;
                config
            }
            Err(error) => return Err(error.into()),
        };

        let custom_overlays_config_path =
            TonNodeConfig::build_path(configs_dir, Self::CUSTOM_OVERLAYS_CONFIG_NAME);
        config_json.custom_overlays_file_name =
            custom_overlays_config_path.to_string_lossy().to_string();
        if Path::exists(&custom_overlays_config_path) {
            config_json.custom_overlays =
                Self::load_custom_overlays_json(&config_json.custom_overlays_file_name)?;
        } else {
            config_json.custom_overlays = CustomOverlaysConfigBoxed::default();
        }

        config_json.configs_dir = configs_dir.to_string();
        config_json.file_name = json_file_name.to_string();
        Ok((config_json, created))
    }

    pub fn adnl_node(&self) -> Result<AdnlNodeConfig> {
        let adnl_node =
            self.adnl_node.as_ref().ok_or_else(|| error!("ADNL node is not configured!"))?;

        let mut ret = AdnlNodeConfig::from_json_config(adnl_node)?;
        if let Some(port) = self.port {
            ret.set_port(port)
        }
        if let Some(quic_addr) = self.quic_address() {
            ret.set_ip_address_quic(quic_addr);
        }
        Ok(ret)
    }

    pub fn json_rpc_server(&self) -> Result<Option<JsonRpcServerConfig>> {
        match &self.json_rpc_server {
            Some(r) => Ok(Some(JsonRpcServerConfig::from_json_config(r)?)),
            None => Ok(None),
        }
    }

    pub fn metrics(&self) -> Result<Option<MetricsConfig>> {
        match &self.metrics {
            Some(m) => Ok(Some(MetricsConfig::from_json_config(m)?)),
            None => Ok(None),
        }
    }

    pub fn control_server(&self) -> Result<Option<AdnlServerConfig>> {
        self.control_server
            .as_ref()
            .map(AdnlServerConfig::from_json_config_with_permissions)
            .transpose()
    }

    pub fn lite_server(&self) -> Result<Option<LiteServerConfig>> {
        self.lite_server.as_ref().map(LiteServerConfig::from_json_config).transpose()
    }

    /// The configured log configuration file; an empty name means none.
    pub fn log_config_path(&self) -> Option<PathBuf> {
        match &self.log_config_name {
            Some(log_config_name) if !log_config_name.is_empty() => {
                Some(self.build_config_path(log_config_name))
            }
            _ => None,
        }
    }

    pub fn unsafe_catchain_patches_files(&self) -> Vec<String> {
        let mut result = Vec::new();
        if let Some(catchain_patches) = &self.unsafe_catchain_patches_path {
            let log_path = self.build_config_path(catchain_patches);
            if let Ok(dir) = std::fs::read_dir(log_path) {
                for filename in dir.into_iter().flatten() {
                    if let Some(path_str) = filename.path().to_str() {
                        if path_str.ends_with(".json") {
                            result.push(path_str.to_string());
                        }
                    }
                }
            }
        }
        result
    }

    pub fn validation_countdown_mode(&self) -> Option<String> {
        self.validation_countdown_mode.clone()
    }

    pub fn gc_archives_life_time_hours(&self) -> Option<u32> {
        // GC disabled in archival mode
        if self.archival_mode.is_some() {
            return None;
        }
        if let Some(gc) = &self.gc {
            if gc.enable_for_archives {
                return gc.archives_life_time_hours.or(Some(0));
            }
        }
        None
    }

    pub fn archival_mode(&self) -> Option<&ArchivalModeConfig> {
        self.archival_mode.as_ref()
    }

    pub fn internal_db_path(&self) -> &str {
        self.internal_db_path.as_deref().unwrap_or(Self::DEFAULT_DB_ROOT)
    }

    pub fn cells_gc_config(&self) -> CellsGcConfig {
        match &self.gc {
            Some(conf) => conf.cells_gc_config.clone(),
            None => CellsGcConfig::default(),
        }
    }

    pub fn enable_shard_state_persistent_gc(&self) -> bool {
        self.gc.as_ref().map(|c| c.enable_for_shard_state_persistent).unwrap_or(false)
    }

    #[cfg(test)]
    pub fn set_internal_db_path(&mut self, path: String) {
        self.internal_db_path.replace(path);
    }

    pub fn default_rldp_roundtrip(&self) -> Option<u32> {
        self.default_rldp_roundtrip_ms
    }

    pub fn test_bundles_config(&self) -> &CollatorTestBundlesGeneralConfig {
        &self.test_bundles_config
    }

    pub fn extensions(&self) -> &NodeExtensions {
        &self.extensions
    }
    #[cfg(test)]
    pub fn ext_messages_broadcast_disabled(&self) -> bool {
        self.ext_messages_broadcast_disabled
    }
    pub fn set_shard_overlay_certificate_policy(&mut self, policy: ShardOverlayCertificatePolicy) {
        self.shard_overlay_certificate_policy = policy;
    }
    pub fn restore_db(&self) -> bool {
        self.restore_db
    }
    pub fn skip_saving_persistent_states(&self) -> bool {
        self.skip_saving_persistent_states
    }
    pub fn states_cache_mode(&self) -> ShardStatesCacheMode {
        self.states_cache_mode
    }
    pub fn sync_by_archives(&self) -> bool {
        self.sync_by_archives
    }
    pub fn cells_db_config(&self) -> &CellsDbConfig {
        &self.cells_db_config
    }

    pub fn is_accelerated_consensus_disabled(&self) -> bool {
        self.accelerated_consensus_disabled
    }

    pub fn session_logs_file(&self) -> Option<String> {
        self.session_logs_file.clone()
    }

    pub fn quic_address(&self) -> Option<SocketAddr> {
        self.ip_address_quic.as_ref().and_then(|s| match s.parse::<SocketAddr>() {
            Ok(addr) => {
                if !addr.ip().is_ipv4() {
                    log::warn!(
                        "ip_address_quic \"{s}\" is not an IPv4 address. \
                         ADNL/TL address lists only support IPv4, so this QUIC address \
                         cannot be advertised. QUIC address will not be used, \
                         node will fall back to derived port."
                    );
                    None
                } else {
                    Some(addr)
                }
            }
            Err(e) => {
                log::warn!(
                    "Failed to parse ip_address_quic \"{s}\": {e}. \
                     QUIC address will not be used, node will fall back to derived port."
                );
                None
            }
        })
    }

    #[cfg(test)]
    pub fn set_port(&mut self, port: u16) {
        self.port.replace(port);
    }

    pub fn collator_config(&self) -> &CollatorConfig {
        &self.collator_config
    }

    pub fn collator_config_mc(&self) -> &CollatorConfig {
        &self.collator_config_mc.as_ref().unwrap_or(&self.collator_config)
    }

    pub fn custom_overlays_config(&self) -> &[CustomOverlay] {
        self.custom_overlays.overlays()
    }

    pub fn pss_downloading_threads(&self) -> usize {
        self.pss_downloading_threads
    }

    const fn default_pss_cells_cache_max_count() -> usize {
        100_000_000
    }

    const fn default_pss_prev_part_max_size() -> usize {
        10 * 1024 * 1024 * 1024
    }

    pub fn pss_cells_cache_max_count(&self) -> usize {
        self.pss_cells_cache_max_count
    }

    pub fn pss_prev_part_max_size(&self) -> usize {
        self.pss_prev_part_max_size
    }

    pub fn load_global_config(&self) -> Result<TonNodeGlobalConfig> {
        let name = self
            .ton_global_config_name
            .as_ref()
            .ok_or_else(|| error!("global config information not found in config.json!"))?;
        let global_config_path = self.build_config_path(name);
        TonNodeGlobalConfig::from_json_file(global_config_path)
    }

    async fn create_and_save_configs(
        &mut self,
        configs_dir: &str,
        port: Option<u16>,
        client_config_name: &str,
        client_pub_keys: Option<Vec<String>>,
        client_permissions: Option<i32>,
    ) -> Result<Option<AdnlServerConfigJson>> {
        let server_address = if let Some(port) = port {
            format!("{}:{}", LOCAL_HOST, port)
        } else {
            println!(
                "Can`t generate {client_config_name}: \
                default config doesn`t contain server port"
            );
            return Ok(None);
        };

        let (server_private_key, server_key) = get_key_option_factory().generate_with_json()?;
        SecretsVaultConfig::save_adnl_server_key(&server_key).await?;

        // generate and save client console template
        let client_config_file_path = TonNodeConfig::build_path(configs_dir, client_config_name);
        let client_config = AdnlClientConfigJson::with_params(
            &server_address,
            serde_json::from_str(key_option_public_key!(base64_encode(server_key.pub_key()?)))?,
            None,
            None,
        );
        write_config_durable(&client_config_file_path, &serde_json::to_vec_pretty(&client_config)?)
            .map_err(|err| error!("Can`t create {client_config_name}: {}", err))?;

        // generate and save server config
        let client_keys = if let Some(client_pub_keys) = client_pub_keys {
            let mut keys = Vec::new();
            for client_pub_key in client_pub_keys {
                keys.push(serde_json::from_str(client_pub_key.as_str())?);
            }
            Some(keys)
        } else {
            None
        };

        let server_config = match (client_permissions, client_keys) {
            (Some(permissions), Some(keys)) => AdnlServerConfigJson::with_client_permissions(
                server_address,
                server_private_key,
                keys.into_iter().map(|key| (key, permissions)).collect(),
                None,
            ),
            (_, client_keys) => AdnlServerConfigJson::with_params(
                server_address,
                server_private_key,
                client_keys,
                None,
            ),
        };
        Ok(Some(server_config))
    }

    async fn create_and_save_console_configs(
        &mut self,
        configs_dir: &str,
        client_pub_key: Option<String>,
    ) -> Result<()> {
        self.control_server = self
            .create_and_save_configs(
                configs_dir,
                self.control_server_port.clone(),
                "console_config.json",
                Some(client_pub_key.map(|key| vec![key]).unwrap_or(vec![])),
                // The bootstrap console client gets every permission.
                Some(Self::BOOTSTRAP_CONTROL_PERMISSIONS),
            )
            .await?;
        self.control_server_port = None;
        Ok(())
    }

    async fn create_and_save_lite_configs(&mut self, configs_dir: &str) -> Result<()> {
        self.lite_server = self
            .create_and_save_configs(
                configs_dir,
                self.lite_server_port.clone(),
                "lite_client_config.json",
                None,
                None,
            )
            .await?
            .map(|adnl| LiteServerConfigJson::from_server_config(adnl));
        self.lite_server_port = None;
        Ok(())
    }

    #[allow(dead_code)]
    fn get_validator_key_info(&self, validator_key_id: &str) -> Result<Option<ValidatorKeysJson>> {
        if let Some(validator_keys) = &self.validator_keys {
            for key_json in validator_keys {
                if key_json.validator_key_id == validator_key_id {
                    return Ok(Some(key_json.clone()));
                }
            }
        }
        Ok(None)
    }

    fn get_validator_key_info_by_election_id(
        &self,
        election_id: &i32,
    ) -> Result<Option<ValidatorKeysJson>> {
        if let Some(validator_keys) = &self.validator_keys {
            for key_json in validator_keys {
                if key_json.election_id == *election_id {
                    return Ok(Some(key_json.clone()));
                }
            }
        }
        Ok(None)
    }

    fn update_validator_key_info(
        &mut self,
        updated_info: ValidatorKeysJson,
    ) -> Result<ValidatorKeysJson> {
        if let Some(validator_keys) = &mut self.validator_keys {
            for keys_info in validator_keys.iter_mut() {
                if keys_info.election_id == updated_info.election_id {
                    keys_info.expire_at = updated_info.expire_at;
                    keys_info.validator_key_id = updated_info.validator_key_id;
                    keys_info.validator_adnl_key_id = updated_info.validator_adnl_key_id;
                    return Ok(keys_info.clone());
                }
            }
        }
        fail!("Validator keys information was not found!");
    }

    pub fn build_config_path(&self, file_name: &str) -> PathBuf {
        Self::build_path(&self.configs_dir, file_name)
    }

    fn build_path(directory_name: &str, file_name: &str) -> PathBuf {
        let path = Path::new(directory_name);
        path.join(file_name)
    }

    async fn save_to_file(&self, file_name: &str) -> Result<()> {
        let config_file_path = self.build_config_path(file_name);
        // A write never drops or changes the post-quantum consensus section
        // the file holds; such a write is refused.
        match std::fs::read(&config_file_path) {
            Ok(bytes) => {
                let on_disk: serde_json::Value = serde_json::from_slice(&bytes)?;
                let section = crate::pq_consensus_config::CONFIG_FIELD;
                if on_disk.get(section) != self.pq_consensus.as_ref() {
                    fail!(
                        "refusing to write {}: the write would drop or change its {section} \
                         section",
                        config_file_path.display()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        write_config_durable(&config_file_path, &serde_json::to_vec_pretty(&self)?)?;
        Ok(())
    }

    async fn save_custom_overlays_json(conf: &CustomOverlaysConfigBoxed, path: &str) -> Result<()> {
        let mut list = Vec::new();
        for overlay in conf.overlays() {
            let mut nodes = Vec::new();
            for node in &overlay.nodes {
                let mut map = serde_json::Map::new();
                map.insert(
                    "adnl_id".to_string(),
                    serde_json::Value::String(base64_encode(&node.adnl_id.as_slice())),
                );
                map.insert(
                    "msg_sender".to_string(),
                    serde_json::Value::Bool((&node.msg_sender).into()),
                );
                map.insert(
                    "msg_sender_priority".to_string(),
                    serde_json::Value::Number(node.msg_sender_priority.into()),
                );
                map.insert(
                    "block_sender".to_string(),
                    serde_json::Value::Bool((&node.block_sender).into()),
                );
                nodes.push(serde_json::Value::Object(map));
            }
            let mut shards = Vec::new();
            for shard in &overlay.sender_shards {
                let mut map = serde_json::Map::new();
                map.insert(
                    "workchain".to_string(),
                    serde_json::Value::Number(shard.workchain.into()),
                );
                map.insert("shard".to_string(), serde_json::Value::Number(shard.shard.into()));
                shards.push(serde_json::Value::Object(map));
            }
            let mut map = serde_json::Map::new();
            map.insert("name".to_string(), serde_json::Value::String(overlay.name.clone()));
            map.insert("nodes".to_string(), serde_json::Value::Array(nodes));
            map.insert("sender_shards".to_string(), serde_json::Value::Array(shards));
            map.insert(
                "skip_public_msg_send".to_string(),
                serde_json::Value::Bool((&overlay.skip_public_msg_send).into()),
            );
            map.insert("use_quic".to_string(), serde_json::Value::Bool((&overlay.use_quic).into()));
            list.push(serde_json::Value::Object(map));
        }
        let mut map = serde_json::Map::new();
        map.insert("overlays".to_string(), serde_json::Value::Array(list));
        write_config_durable(Path::new(path), &serde_json::to_vec_pretty(&map)?)?;
        Ok(())
    }

    fn load_custom_overlays_json(path: &str) -> Result<CustomOverlaysConfigBoxed> {
        let file = File::open(path).map_err(|err| error!("Can't open {:?}: {}", path, err))?;
        let reader = BufReader::new(file);
        let json_value: serde_json::Value = serde_json::from_reader(reader)?;
        Self::parse_custom_overlays_json(json_value)
    }

    pub fn parse_custom_overlay_json(json_value: &serde_json::Value) -> Result<CustomOverlay> {
        let mut nodes = Vec::new();
        let overlay_json = PathMap::new(
            json_value.as_object().ok_or_else(|| error!("Invalid custom overlay format"))?,
        );
        let nodes_json = overlay_json.get_obj_vec("nodes")?;
        for node_json in nodes_json {
            let adnl_id_b64 = node_json.get_str("adnl_id")?;
            let adnl_id = base64_decode(&adnl_id_b64)?;
            if adnl_id.len() != 32 {
                fail!(
                    "Invalid adnl_id length {} (expected 32) in custom overlay node",
                    adnl_id.len()
                );
            }
            let msg_sender = node_json.get_bool("msg_sender")?;
            let msg_sender_priority = node_json.get_num32("msg_sender_priority")?;
            let block_sender = node_json.get_bool("block_sender")?;
            nodes.push(CustomOverlayNode {
                adnl_id: UInt256::from_raw(adnl_id, 256),
                msg_sender: msg_sender.into(),
                msg_sender_priority: msg_sender_priority as i32,
                block_sender: block_sender.into(),
            });
        }
        let mut sender_shards = Vec::new();
        let sender_shards_json = overlay_json.get_obj_vec("sender_shards")?;
        for shard_json in sender_shards_json {
            let workchain = shard_json.get_num32("workchain")? as i32;
            let shard = shard_json.get_num64("shard")? as i64;
            sender_shards.push(ton::ton_node::shardid::ShardId { workchain, shard });
        }
        let name = overlay_json.get_str("name")?.to_string();
        let skip_public_msg_send = overlay_json.get_bool("skip_public_msg_send")?;
        // Optional: absent => false, but a present non-boolean is a config error.
        let use_quic = match overlay_json.get_item("use_quic") {
            Ok(value) => value
                .as_bool()
                .ok_or_else(|| error!("custom overlay `use_quic` must be boolean"))?,
            Err(_) => false,
        };
        let overlay = CustomOverlay {
            name,
            nodes,
            sender_shards,
            skip_public_msg_send: skip_public_msg_send.into(),
            use_quic: use_quic.into(),
        };
        Ok(overlay)
    }

    fn parse_custom_overlays_json(
        json_value: serde_json::Value,
    ) -> Result<CustomOverlaysConfigBoxed> {
        let map = json_value
            .as_object()
            .ok_or_else(|| error!("Invalid custom overlays config format"))?;
        let map = PathMap::new(map);
        let overlays_json = map.get_vec("overlays")?;
        let mut overlays = Vec::new();
        for overlay_json in overlays_json {
            overlays.push(Self::parse_custom_overlay_json(overlay_json)?);
        }
        Ok(CustomOverlaysConfig { overlays }.into_boxed())
    }

    fn generate_and_save_keys(&mut self, _key_type: i32) -> Result<([u8; 32], Arc<dyn KeyOption>)> {
        let (mut private, public) = get_key_option_factory().generate_with_json()?;
        let key_id = public.id().data();
        let key_id_b64 = base64_encode(key_id);
        log::info!("generate_and_save_keys: generate new key (id: {key_id_b64})");
        if let Some(name) = &mut private.vault {
            *name = make_secret_id!(SecretsVaultConfig::SID_PRIVATE_KEYS, &key_id_b64).to_string();
        }
        let key_ring = self.validator_key_ring.get_or_insert_default();
        key_ring.insert(key_id_b64, private);
        Ok((*key_id, public))
    }

    fn import_private_key(
        &mut self,
        pvt_key: PrivateKey,
    ) -> Result<([u8; 32], Arc<dyn KeyOption>)> {
        match pvt_key {
            PrivateKey::Pk_Ed25519(pvt_key) => {
                let (mut private, public) =
                    get_key_option_factory().from_private_key_with_json(pvt_key.key.as_array())?;
                let key_id = public.id().data();
                let key_id_b64 = base64_encode(key_id);
                log::info!("import_private_key: import private key key (id: {key_id_b64})");
                if let Some(name) = &mut private.vault {
                    *name = make_secret_id!(SecretsVaultConfig::SID_PRIVATE_KEYS, &key_id_b64)
                        .to_string();
                }
                let key_ring = self.validator_key_ring.get_or_insert_with(HashMap::new);
                key_ring.insert(key_id_b64, private);
                Ok((*key_id, public))
            }
            _ => fail!("Unsupported key type"),
        }
    }

    fn is_correct_election_id(&self, _election_id: i32) -> bool {
        // Temporary change
        // When importing keys from a C++ node, it is acceptable to import them in any chronological order
        /*
        if let Some(validator_keys) = &self.validator_keys {
            for key_json in validator_keys {
                if key_json.election_id > election_id {
                    return false;
                }
            }
        }
        */
        true
    }

    fn add_validator_key(
        &mut self,
        key_id: &[u8; 32],
        election_id: i32,
        expire_at: i32,
    ) -> Result<ValidatorKeysJson> {
        let new_key_id_b64 = base64_encode(key_id);
        let key_info = ValidatorKeysJson {
            expire_at,
            election_id,
            validator_key_id: new_key_id_b64.clone(),
            validator_adnl_key_id: None,
        };

        if !self.is_correct_election_id(election_id) {
            fail!("Invalid arg: bad election_id!");
        }
        let added_key_info = self.get_validator_key_info_by_election_id(&election_id)?;
        match &mut self.validator_keys {
            Some(validator_keys) => match added_key_info {
                Some(existing) => {
                    if existing.validator_key_id != new_key_id_b64 {
                        log::warn!(
                            "add_validator_key: OVERWRITING validator key for election_id={}: \
                             old_key={} -> new_key={} (adnl_key will be cleared)",
                            election_id,
                            existing.validator_key_id,
                            new_key_id_b64,
                        );
                    }
                    self.update_validator_key_info(key_info.clone())?;
                }
                None => {
                    validator_keys.push(key_info.clone());
                }
            },
            None => {
                let keys = vec![key_info.clone()];
                self.validator_keys = Some(keys);
            }
        }
        Ok(key_info)
    }

    fn add_validator_adnl_key(
        &mut self,
        validator_key_id: &[u8; 32],
        adnl_key_id: &[u8; 32],
    ) -> Result<ValidatorKeysJson> {
        let key_id_b64 = base64_encode(validator_key_id);
        let new_adnl_b64 = base64_encode(adnl_key_id);

        let matching: Vec<ValidatorKeysJson> = self
            .validator_keys
            .as_ref()
            .map(|keys| keys.iter().filter(|k| k.validator_key_id == key_id_b64).cloned().collect())
            .unwrap_or_default();

        if matching.is_empty() {
            fail!("Validator key have not been added!")
        }

        let mut last_updated = None;
        for entry in &matching {
            if let Some(existing_adnl) = &entry.validator_adnl_key_id {
                if *existing_adnl != new_adnl_b64 {
                    log::warn!(
                        "add_validator_adnl_key: OVERWRITING adnl key for election_id={}: \
                         old_adnl={} -> new_adnl={} (validator_key={})",
                        entry.election_id,
                        existing_adnl,
                        new_adnl_b64,
                        key_id_b64,
                    );
                }
            }
            let mut updated = entry.clone();
            updated.validator_adnl_key_id = Some(new_adnl_b64.clone());
            last_updated = Some(self.update_validator_key_info(updated)?);
        }
        if matching.len() > 1 {
            log::info!(
                "add_validator_adnl_key: updated adnl binding for {} elections sharing \
                 validator_key={}",
                matching.len(),
                key_id_b64,
            );
        }
        Ok(last_updated.unwrap())
    }

    #[cfg(test)]
    async fn remove_validator_key(
        &mut self,
        validator_key_id: String,
        election_id: i32,
    ) -> Result<bool> {
        if let Some(validator_keys) = self.validator_keys.as_mut() {
            let pos = validator_keys.iter().position(|item| {
                (item.validator_key_id == validator_key_id) && (item.election_id == election_id)
            });
            if let Some(pos) = pos {
                // A key may span elections. The vault record describes the
                // remaining registration; pruning an older one must not erase it.
                if !validator_keys
                    .iter()
                    .enumerate()
                    .any(|(index, key)| index != pos && key.validator_key_id == validator_key_id)
                {
                    SecretsVaultConfig::drop_validator_metadata(&validator_key_id).await?;
                }
                validator_keys.swap_remove(pos);
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[cfg(test)]
    async fn remove_key_from_key_ring(&mut self, key_id: &str) -> Result<bool> {
        // Retain private material until neither role in any remaining election
        // references it. A validator key may also be used as an ADNL identity.
        if self.validator_keys.as_ref().is_some_and(|keys| {
            keys.iter().any(|key| {
                key.validator_key_id == key_id
                    || key.validator_adnl_key_id.as_deref() == Some(key_id)
            })
        }) {
            return Ok(false);
        }
        SecretsVaultConfig::on_drop(key_id).await?;
        if let Some(key_ring) = self.validator_key_ring.as_mut() {
            key_ring.remove(key_id);
        }
        Ok(true)
    }

    /// The node's own ADNL identities (full-node overlay and DHT).
    fn node_adnl_ids(&self) -> Vec<String> {
        self.node_identities_tagged().into_iter().map(|(id, _)| id).collect()
    }

    /// The category of a member of the ADNL id list, `None` for a non-member.
    fn adnl_category(&self, id: &str) -> Option<u8> {
        if let Some(entry) = self.adnl_ids.iter().find(|entry| entry.id == id) {
            return Some(entry.category);
        }
        self.node_adnl_ids().iter().any(|own| own == id).then_some(0)
    }

    fn validator_entry(&self, validator: &str) -> Option<&ValidatorKeysJson> {
        self.validator_keys.as_ref()?.iter().find(|key| key.validator_key_id == validator)
    }

    fn require_validator(&self, validator: &str) -> Result<()> {
        if self.validator_entry(validator).is_none() {
            return Err(key_command_error(KEY_COMMAND_NOTREADY, "unknown permanent validator key"));
        }
        Ok(())
    }

    /// Whether any configured role still refers to `id`.
    fn key_referenced(&self, id: &str) -> bool {
        let as_validator = self.validator_keys.as_ref().is_some_and(|keys| {
            keys.iter().any(|key| {
                key.validator_key_id == id || key.validator_adnl_key_id.as_deref() == Some(id)
            })
        });
        let bound = self
            .validator_temp_keys
            .iter()
            .chain(self.validator_adnl_addresses.iter())
            .any(|entry| entry.key_id == id);
        let transport = self
            .consensus_transport_bindings
            .iter()
            .any(|binding| binding.adnl_key_id == id || binding.validator_id == id);
        as_validator
            || bound
            || transport
            || self.adnl_ids.iter().any(|entry| entry.id == id)
            || self.node_adnl_ids().iter().any(|own| own == id)
    }

    /// Selects the ADNL address the runtime binds `validator` to: the current
    /// one while it stays an unexpired listed address, else the most recently
    /// added unexpired one.
    fn rebind_validator(&mut self, validator: &str, now: u32, change: &mut KeyChange) {
        let active: Vec<String> = self
            .validator_adnl_addresses
            .iter()
            .filter(|entry| {
                entry.validator_key_id == validator
                    && entry.expire_at > now
                    && self.adnl_category(&entry.key_id).is_some()
            })
            .map(|entry| entry.key_id.clone())
            .collect();
        let Some(entry) = self
            .validator_keys
            .as_mut()
            .and_then(|keys| keys.iter_mut().find(|key| key.validator_key_id == validator))
        else {
            return;
        };
        let current = entry.validator_adnl_key_id.clone();
        let selected = match &current {
            Some(current) if active.contains(current) => Some(current.clone()),
            _ => active.last().cloned(),
        };
        if selected == current {
            return;
        }
        entry.validator_adnl_key_id = selected.clone();
        let election = entry.election_id;
        change.updated = Some(entry.clone());
        if let Some(old) = current {
            change.unbound.push((old, election));
        }
        if let Some(new) = selected {
            change.bound.push((new, election));
        }
    }

    /// Applies one key command to the configuration as the reference engine
    /// does: every refusal happens before any change.
    fn apply_key_command(&mut self, command: KeyCommand, now: u32) -> Result<KeyChange> {
        let mut change = KeyChange::default();
        match command {
            KeyCommand::AddAdnlId { id, category } => {
                if category > MAX_ADNL_CATEGORY {
                    return Err(key_command_error(
                        KEY_COMMAND_PROTOVIOLATION,
                        "bad category value",
                    ));
                }
                if let Some(entry) = self.adnl_ids.iter_mut().find(|entry| entry.id == id) {
                    if entry.category != category {
                        entry.category = category;
                        change.changed = true;
                    }
                } else if self.adnl_category(&id) != Some(category) {
                    self.adnl_ids.push(AdnlIdJson { id, category });
                    change.changed = true;
                }
            }
            KeyCommand::DelAdnlId { id } => {
                if self.adnl_category(&id).is_none() {
                    return Ok(change);
                }
                let in_use = self.node_adnl_ids().contains(&id)
                    || self.validator_adnl_addresses.iter().any(|entry| entry.key_id == id)
                    || self.validator_keys.as_ref().is_some_and(|keys| {
                        keys.iter().any(|key| key.validator_adnl_key_id.as_deref() == Some(&id))
                    });
                if in_use {
                    return Err(key_command_error(KEY_COMMAND_ERROR, "adnl addr still in use"));
                }
                self.adnl_ids.retain(|entry| entry.id != id);
                change.changed = true;
                change.released.push(id);
            }
            KeyCommand::AddPermanentKey { validator, election_date, expire_at } => {
                let keys = self.validator_keys.get_or_insert_with(Vec::new);
                if keys.iter().any(|key| {
                    key.election_id == election_date && key.validator_key_id != validator
                }) {
                    return Err(key_command_error(
                        KEY_COMMAND_PROTOVIOLATION,
                        "duplicate election date",
                    ));
                }
                // The expiry keeps its wire bit pattern.
                let expire_bits = i32::from_ne_bytes(expire_at.to_ne_bytes());
                if let Some(key) = keys.iter_mut().find(|key| key.validator_key_id == validator) {
                    if key.election_id != election_date {
                        return Err(key_command_error(
                            KEY_COMMAND_PROTOVIOLATION,
                            "election date changed",
                        ));
                    }
                    if key.expire_at != expire_bits {
                        key.expire_at = expire_bits;
                        change.changed = true;
                        change.updated = Some(key.clone());
                    }
                } else {
                    let key = ValidatorKeysJson {
                        expire_at: expire_bits,
                        election_id: election_date,
                        validator_key_id: validator,
                        validator_adnl_key_id: None,
                    };
                    keys.push(key.clone());
                    change.changed = true;
                    change.updated = Some(key);
                }
            }
            KeyCommand::AddTempKey { validator, key, expire_at } => {
                self.require_validator(&validator)?;
                change.changed =
                    Self::upsert_bound(&mut self.validator_temp_keys, validator, key, expire_at);
            }
            KeyCommand::AddAdnlAddress { validator, adnl, expire_at } => {
                if self.adnl_category(&adnl).is_none() {
                    return Err(key_command_error(
                        KEY_COMMAND_NOTREADY,
                        "to-be-added validator adnl address not in adnl nodes list",
                    ));
                }
                self.require_validator(&validator)?;
                change.changed = Self::upsert_bound(
                    &mut self.validator_adnl_addresses,
                    validator.clone(),
                    adnl,
                    expire_at,
                );
                if change.changed {
                    self.rebind_validator(&validator, now, &mut change);
                }
            }
            KeyCommand::DelPermanentKey { validator } => {
                let Some(keys) = self.validator_keys.as_mut() else {
                    return Ok(change);
                };
                let Some(position) = keys.iter().position(|key| key.validator_key_id == validator)
                else {
                    return Ok(change);
                };
                let removed = keys.remove(position);
                if let Some(adnl) = &removed.validator_adnl_key_id {
                    change.unbound.push((adnl.clone(), removed.election_id));
                    change.released.push(adnl.clone());
                }
                for list in [&mut self.validator_temp_keys, &mut self.validator_adnl_addresses] {
                    list.retain(|entry| {
                        if entry.validator_key_id == validator {
                            change.released.push(entry.key_id.clone());
                            false
                        } else {
                            true
                        }
                    });
                }
                change.released.push(validator);
                change.removed = Some(removed);
                change.changed = true;
            }
            KeyCommand::DelTempKey { validator, key } => {
                self.require_validator(&validator)?;
                let before = self.validator_temp_keys.len();
                self.validator_temp_keys
                    .retain(|entry| !(entry.validator_key_id == validator && entry.key_id == key));
                if self.validator_temp_keys.len() != before {
                    change.changed = true;
                    change.released.push(key);
                }
            }
            KeyCommand::DelAdnlAddress { validator, adnl } => {
                self.require_validator(&validator)?;
                let before = self.validator_adnl_addresses.len();
                self.validator_adnl_addresses
                    .retain(|entry| !(entry.validator_key_id == validator && entry.key_id == adnl));
                if self.validator_adnl_addresses.len() != before {
                    change.changed = true;
                    change.released.push(adnl);
                    self.rebind_validator(&validator, now, &mut change);
                }
            }
        }
        Ok(change)
    }

    fn key_state(&self) -> KeyState {
        KeyState {
            validator_keys: self.validator_keys.clone(),
            adnl_ids: self.adnl_ids.clone(),
            validator_temp_keys: self.validator_temp_keys.clone(),
            validator_adnl_addresses: self.validator_adnl_addresses.clone(),
            validator_key_ring: self.validator_key_ring.clone(),
        }
    }

    fn restore_key_state(&mut self, state: KeyState) {
        self.validator_keys = state.validator_keys;
        self.adnl_ids = state.adnl_ids;
        self.validator_temp_keys = state.validator_temp_keys;
        self.validator_adnl_addresses = state.validator_adnl_addresses;
        self.validator_key_ring = state.validator_key_ring;
    }

    /// Inserts or updates a bound key; whether anything changed.
    fn upsert_bound(
        list: &mut Vec<ValidatorBoundKeyJson>,
        validator_key_id: String,
        key_id: String,
        expire_at: u32,
    ) -> bool {
        if let Some(entry) = list
            .iter_mut()
            .find(|entry| entry.validator_key_id == validator_key_id && entry.key_id == key_id)
        {
            if entry.expire_at == expire_at {
                return false;
            }
            entry.expire_at = expire_at;
            return true;
        }
        list.push(ValidatorBoundKeyJson { validator_key_id, key_id, expire_at });
        true
    }

    /// Keys the configuration no longer refers to after a command; they leave
    /// the key ring, as the reference engine collects them.
    fn collect_released(&mut self, released: &[String]) -> Vec<String> {
        let mut collected = Vec::new();
        for id in released {
            if collected.contains(id) || self.key_referenced(id) {
                continue;
            }
            if let Some(ring) = self.validator_key_ring.as_mut() {
                ring.remove(id);
            }
            collected.push(id.clone());
        }
        collected
    }

    /// The validator keys with their temporary keys and ADNL addresses, for
    /// the configuration projection of the control interface.
    pub(crate) fn validator_key_view(
        &self,
    ) -> Vec<(ValidatorKeysJson, Vec<ValidatorBoundKeyJson>, Vec<ValidatorBoundKeyJson>)> {
        let Some(keys) = &self.validator_keys else {
            return Vec::new();
        };
        keys.iter()
            .map(|key| {
                let pick = |list: &[ValidatorBoundKeyJson]| {
                    list.iter()
                        .filter(|entry| entry.validator_key_id == key.validator_key_id)
                        .cloned()
                        .collect::<Vec<_>>()
                };
                (key.clone(), pick(&self.validator_temp_keys), pick(&self.validator_adnl_addresses))
            })
            .collect()
    }

    /// The ADNL id list with categories: the node's own identities first,
    /// then the operator's entries.
    pub(crate) fn adnl_id_view(&self) -> Vec<AdnlIdJson> {
        let mut result: Vec<AdnlIdJson> = Vec::new();
        for id in self.node_adnl_ids() {
            if !result.iter().any(|entry| entry.id == id) {
                result.push(AdnlIdJson { category: self.adnl_category(&id).unwrap_or(0), id });
            }
        }
        for entry in &self.adnl_ids {
            if !result.iter().any(|known| known.id == entry.id) {
                result.push(entry.clone());
            }
        }
        result
    }

    /// Every private key the node holds, by key id: the key ring, the node's
    /// ADNL identities and the control and lite server keys.
    fn private_keys(&self) -> Result<Vec<ExportedKey>> {
        let mut options: Vec<KeyOptionJson> = Vec::new();
        if let Some(ring) = &self.validator_key_ring {
            options.extend(ring.values().cloned());
        }
        if let Some(node) = &self.adnl_node {
            let node = serde_json::to_value(node)?;
            for key in node.get("keys").and_then(|keys| keys.as_array()).into_iter().flatten() {
                if let Some(data) = key.get("data") {
                    options.push(serde_json::from_value(data.clone())?);
                }
            }
        }
        for server in [
            self.control_server.as_ref().map(serde_json::to_value).transpose()?,
            self.lite_server.as_ref().map(serde_json::to_value).transpose()?,
        ]
        .into_iter()
        .flatten()
        {
            if let Some(key) = server.get("server_key") {
                options.push(serde_json::from_value(key.clone())?);
            }
        }
        let mut keys: Vec<ExportedKey> = Vec::new();
        for option in &options {
            let key = get_key_option_factory().from_private_key_json(option)?;
            let id = *key.id().data();
            if keys.iter().any(|known| known.id == id) {
                continue;
            }
            let secret = key.pvt_key()?.lock()?.as_ref().to_vec();
            keys.push(ExportedKey { id, secret });
        }
        keys.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(keys)
    }

    /// The server key id, port and listed clients of a server section.
    fn server_view(value: serde_json::Value) -> Result<ServerView> {
        let key: KeyOptionJson = serde_json::from_value(
            value.get("server_key").cloned().ok_or_else(|| error!("server without a key"))?,
        )?;
        let id = base64_encode(get_key_option_factory().from_private_key_json(&key)?.id().data());
        let address: SocketAddr = value
            .get("address")
            .and_then(|address| address.as_str())
            .ok_or_else(|| error!("server without an address"))?
            .parse()?;
        let mut clients = Vec::new();
        if let Some(list) = value.get("clients").and_then(|clients| clients.get("list")) {
            for client in list.as_array().into_iter().flatten() {
                let key: KeyOptionJson = serde_json::from_value(client.clone())?;
                let id =
                    base64_encode(get_key_option_factory().from_public_key_json(&key)?.id().data());
                let permissions = match client.get("permissions") {
                    Some(serde_json::Value::Number(number)) => number.as_i64(),
                    Some(serde_json::Value::String(text)) => text.parse::<i64>().ok(),
                    _ => Some(0),
                }
                .and_then(|bits| i32::try_from(bits).ok())
                .ok_or_else(|| error!("client permissions are not a 32-bit integer"))?;
                clients.push((id, permissions));
            }
        }
        Ok(ServerView { id, port: address.port(), clients })
    }

    /// Everything the configuration projection of the control interface
    /// reads, taken in one step.
    fn control_view(&self) -> Result<ControlConfigView> {
        let node = self.node_identities_tagged();
        let pq_consensus = match &self.pq_consensus {
            Some(section) => {
                let at = format!("$.{}", crate::pq_consensus_config::CONFIG_FIELD);
                crate::pq_consensus_config::PqConsensusConfig::from_json(section, &at).map_err(
                    |refused| error!("post-quantum consensus configuration refused: {refused}"),
                )?
            }
            None => None,
        };
        Ok(ControlConfigView {
            ip_address: self
                .adnl_node
                .as_ref()
                .and_then(|node| serde_json::to_value(node).ok())
                .and_then(|node| {
                    node.get("ip_address").and_then(|ip| ip.as_str()).map(String::from)
                }),
            adnl: self.adnl_id_view(),
            dht: node
                .iter()
                .filter(|(_, tag)| *tag == NodeNetwork::TAG_DHT_KEY)
                .map(|(id, _)| id.clone())
                .collect(),
            fullnode: node
                .iter()
                .find(|(_, tag)| *tag == NodeNetwork::TAG_OVERLAY_KEY)
                .map(|(id, _)| id.clone()),
            validators: self.validator_key_view(),
            lite_server: self
                .lite_server
                .as_ref()
                .map(|lite| {
                    serde_json::to_value(lite).map_err(Into::into).and_then(Self::server_view)
                })
                .transpose()?,
            control_server: self
                .control_server
                .as_ref()
                .map(|server| {
                    serde_json::to_value(server).map_err(Into::into).and_then(Self::server_view)
                })
                .transpose()?,
            ext_messages_broadcast_disabled: self.ext_messages_broadcast_disabled,
            state_serializer_enabled: !self.skip_saving_persistent_states,
            pq_consensus,
        })
    }

    fn node_identities_tagged(&self) -> Vec<(String, usize)> {
        let mut result = Vec::new();
        if let Some(adnl_config) = &self.adnl_node {
            for tag in [NodeNetwork::TAG_OVERLAY_KEY, NodeNetwork::TAG_DHT_KEY] {
                if let Ok(key) = adnl_config.key_by_tag(tag, true) {
                    result.push((base64_encode(key.id().data()), tag));
                }
            }
        }
        result
    }
}

/// A private key for an encrypted export; the key material is cleared when
/// it is dropped and never printed.
pub struct ExportedKey {
    pub id: [u8; 32],
    pub secret: Vec<u8>,
}

impl std::fmt::Debug for ExportedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ExportedKey({})", base64_encode(self.id))
    }
}

impl Drop for ExportedKey {
    fn drop(&mut self) {
        self.secret.iter_mut().for_each(|byte| *byte = 0);
    }
}

/// A control or lite server as the configuration projection lists it.
#[derive(Debug, Clone)]
pub struct ServerView {
    pub id: String,
    pub port: u16,
    pub clients: Vec<(String, i32)>,
}

/// The configuration as the control interface projects it.
#[derive(Debug)]
pub struct ControlConfigView {
    pub ip_address: Option<String>,
    pub adnl: Vec<AdnlIdJson>,
    pub dht: Vec<String>,
    pub fullnode: Option<String>,
    pub validators:
        Vec<(ValidatorKeysJson, Vec<ValidatorBoundKeyJson>, Vec<ValidatorBoundKeyJson>)>,
    pub lite_server: Option<ServerView>,
    pub control_server: Option<ServerView>,
    pub ext_messages_broadcast_disabled: bool,
    pub state_serializer_enabled: bool,
    pub pq_consensus: Option<crate::pq_consensus_config::PqConsensusConfig>,
}

pub enum ConfigEvent {
    AddValidatorAdnlKey(Arc<KeyId>, i32),
    RemoveValidatorAdnlKey(Arc<KeyId>, i32),
}

#[async_trait::async_trait]
pub trait NodeConfigSubscriber: Send + Sync {
    async fn event(&self, sender: ConfigEvent) -> Result<bool>;
}

#[derive(Debug)]
enum Task {
    Generate(i32),
    ImportPrivateKey(PrivateKey),
    #[cfg(test)]
    AddValidatorKey([u8; 32], i32, i32),
    #[cfg(test)]
    AddValidatorAdnlKey([u8; 32], [u8; 32]),
    GetKey([u8; 32]),
    ExportAdnlKeys,
    AddCustomOverlay(CustomOverlay),
    DelCustomOverlay(String),
    GetCustomOverlays,
    SetExtMessagesBroadcastDisabled(bool),
    KeyCommand(KeyCommand),
    ControlView,
    PrivateKeys,
}

#[derive(Debug)]
enum Answer {
    Generate(Result<[u8; 32]>),
    ImportPrivateKey(Result<[u8; 32]>),
    GetKey(Option<Arc<dyn KeyOption>>),
    Result(Result<()>),
    AdnlKeys(Vec<(String, usize)>),
    CustomOverlays(Result<CustomOverlaysConfigBoxed>),
    ControlView(Box<ControlConfigView>),
    PrivateKeys(Result<Vec<ExportedKey>>),
}

impl ExtMessagesSetting {
    async fn save(&self, config: &TonNodeConfig, name: &str) -> Result<()> {
        #[cfg(test)]
        if self.fail_next_save.swap(false, atomic::Ordering::SeqCst) {
            return Err(std::io::Error::from_raw_os_error(libc::EIO).into());
        }
        config.save_to_file(name).await
    }
}

#[path = "config_scheduler.rs"]
mod scheduler;
use scheduler::{ConfigScheduler, PendingAnswer};

pub struct NodeConfigHandlerContext {
    reader: tokio::sync::mpsc::UnboundedReceiver<(Arc<Wait<Answer>>, Task)>,
    config: TonNodeConfig,
}

pub struct NodeConfigHandler {
    scheduler: Arc<ConfigScheduler>,
    validator_transport_changed: tokio::sync::Notify,
    validator_transport_revision: std::sync::Mutex<u64>,
    runtime_handle: tokio::runtime::Handle,
    sender: tokio::sync::mpsc::UnboundedSender<(Arc<Wait<Answer>>, Task)>,
    key_ring: Arc<lockfree::map::Map<String, Arc<dyn KeyOption>>>,
    validator_keys: Arc<ValidatorKeys>,
    consensus_transport_bindings: Vec<ConsensusTransportBinding>,
    shard_overlay_certificate_policy: ShardOverlayCertificatePolicy,
    ext_messages: Arc<ExtMessagesSetting>,
}

/// The live external-message broadcast setting. Only the configuration
/// actor changes it, in the same step as the configuration it persists.
#[derive(Default)]
struct ExtMessagesSetting {
    live: Arc<atomic::AtomicBool>,
    #[cfg(test)]
    fail_next_save: atomic::AtomicBool,
}

impl NodeConfigHandler {
    fn send_task(&self, task: (Arc<Wait<Answer>>, Task)) -> Result<()> {
        let gate = self.scheduler.admission.lock().unwrap();
        // Accepted subscribers may need a key lookup while writes are draining.
        // The scheduler closes the receiver after their actual completion.
        if !gate.open
            && (!gate.started || !scheduler::in_callback() || !matches!(&task.1, Task::GetKey(_)))
        {
            fail!("Configuration scheduler is stopping");
        }
        self.sender.send(task).map_err(|_| error!("Configuration scheduler is closed"))
    }

    fn dispatch_config_event(&self, subscriber: Arc<dyn NodeConfigSubscriber>, event: ConfigEvent) {
        self.scheduler.spawn_callback(&self.runtime_handle, async move {
            if let Err(error) = subscriber.event(event).await {
                log::warn!("Configuration subscriber event failed: {error}");
            }
        });
    }

    pub(crate) fn stop(&self) {
        self.scheduler.stop();
    }

    pub(crate) async fn stop_and_wait(&self) -> Result<()> {
        self.scheduler.stop_and_wait().await
    }

    pub fn create(
        config: TonNodeConfig,
        runtime_handle: tokio::runtime::Handle,
    ) -> Result<(Arc<Self>, NodeConfigHandlerContext)> {
        let mut stable_ids = std::collections::HashSet::new();
        let mut transport_ids = std::collections::HashSet::new();
        let mut bindings = Vec::new();
        for binding in &config.consensus_transport_bindings {
            let stable: [u8; 32] = base64_decode(&binding.validator_id)?.as_slice().try_into()?;
            let transport: [u8; 32] = base64_decode(&binding.adnl_key_id)?.as_slice().try_into()?;
            if !stable_ids.insert(stable) || !transport_ids.insert(transport) {
                fail!("Duplicate consensus transport identity or ADNL binding");
            }
            bindings.push(ConsensusTransportBinding {
                validator_id: UInt256::from(stable),
                adnl_key_id: KeyId::from_data(transport),
            });
        }
        let (sender, reader) = tokio::sync::mpsc::unbounded_channel();
        let config_handler = Arc::new(NodeConfigHandler {
            scheduler: Arc::default(),
            validator_transport_changed: tokio::sync::Notify::new(),
            validator_transport_revision: std::sync::Mutex::new(0),
            runtime_handle,
            sender,
            key_ring: Arc::new(lockfree::map::Map::new()),
            validator_keys: Arc::new(ValidatorKeys::new()),
            consensus_transport_bindings: bindings,
            shard_overlay_certificate_policy: config.shard_overlay_certificate_policy.clone(),
            ext_messages: Arc::new(ExtMessagesSetting {
                live: Arc::new(atomic::AtomicBool::new(config.ext_messages_broadcast_disabled)),
                #[cfg(test)]
                fail_next_save: atomic::AtomicBool::new(false),
            }),
        });

        Ok((config_handler, NodeConfigHandlerContext { reader, config }))
    }

    pub(crate) async fn validator_transport_changed(&self) {
        self.validator_transport_changed.notified().await;
    }

    pub(crate) fn notify_validator_transport_changed(&self) {
        if let Err(error) = self.update_validator_transport(|| Ok(())) {
            log::error!("Cannot publish transport configuration revision: {error}");
        }
    }

    fn update_validator_transport(&self, update: impl FnOnce() -> Result<()>) -> Result<()> {
        let mut revision = self
            .validator_transport_revision
            .lock()
            .map_err(|_| error!("Transport configuration revision lock poisoned"))?;
        *revision = revision
            .checked_add(1)
            .ok_or_else(|| error!("Transport configuration revision exhausted"))?;
        let result = update();
        drop(revision);
        self.validator_transport_changed.notify_one();
        result
    }

    /// A test barrier after callbacks scheduled by commands already acknowledged.
    /// This preserves actor admission and the real ordered subscriber path.
    #[cfg(test)]
    pub(crate) async fn wait_test_subscribers(&self) -> Result<()> {
        let (sent, received) = tokio::sync::oneshot::channel();
        {
            let admission = self.scheduler.admission.lock().unwrap();
            if !admission.open {
                fail!("Configuration scheduler stopped before subscriber barrier");
            }
            self.scheduler.spawn_callback(&self.runtime_handle, async move {
                let _ = sent.send(());
            });
        }
        received.await.map_err(|error| error!("Subscriber barrier: {error}"))
    }

    pub(crate) fn validator_transport_revision(&self) -> Result<u64> {
        self.validator_transport_revision
            .lock()
            .map(|revision| *revision)
            .map_err(|_| error!("Transport configuration revision lock poisoned"))
    }

    // Publication is synchronous while registration writers are excluded. The
    // caller must keep this bounded and must not await a keyring query.
    pub(crate) fn with_validator_transport_revision<T>(
        &self,
        expected: u64,
        publish: impl FnOnce() -> T,
    ) -> Result<Option<T>> {
        let revision = self
            .validator_transport_revision
            .lock()
            .map_err(|_| error!("Transport configuration revision lock poisoned"))?;
        if *revision != expected {
            return Ok(None);
        }
        Ok(Some(publish()))
    }

    pub fn consensus_transport_bindings(&self) -> Result<Vec<ConsensusTransportBinding>> {
        Ok(self.consensus_transport_bindings.clone())
    }

    /// Only explicit local transport bindings can access this path. This grants
    /// no consensus authority; callers must check the authenticated governing set.
    pub async fn consensus_transport_key(&self, id: &Arc<KeyId>) -> Result<Arc<dyn KeyOption>> {
        if !self.consensus_transport_bindings.iter().any(|binding| &binding.adnl_key_id == id) {
            fail!("ADNL key is not an explicitly configured consensus transport");
        }
        let key = self
            .get_key_raw(*id.data())
            .await
            .ok_or_else(|| error!("Configured consensus transport private key is unavailable"))?;
        if key.id() != id {
            fail!("Configured consensus transport key identity mismatch");
        }
        Ok(key)
    }

    pub fn get_validator_status(&self) -> bool {
        !self.validator_keys.is_empty()
    }

    #[cfg(test)]
    pub async fn add_validator_key(
        &self,
        key_hash: &[u8; 32],
        election_date: ton::int,
        expire_at: ton::int,
    ) -> Result<()> {
        let (wait, mut queue_reader) = Wait::new();
        let task = Task::AddValidatorKey(*key_hash, election_date, expire_at);
        let pushed_task = (wait.clone(), task);
        wait.request();
        if let Err(e) = self.send_task(pushed_task) {
            fail!("Error add_validator_key: {}", e);
        }
        match wait.wait(&mut queue_reader, true).await {
            Some(None) => fail!("Answer was not set!"),
            Some(Some(Answer::Result(result))) => result,
            Some(Some(_)) => fail!("Bad answer (AddValidatorKey)!"),
            None => fail!("Waiting returned an internal error!"),
        }
    }

    #[cfg(test)]
    pub async fn add_validator_adnl_key(
        &self,
        validator_key_hash: &[u8; 32],
        validator_adnl_key_hash: &[u8; 32],
    ) -> Result<()> {
        let (wait, mut queue_reader) = Wait::new();
        let pushed_task = (
            wait.clone(),
            Task::AddValidatorAdnlKey(*validator_key_hash, *validator_adnl_key_hash),
        );
        wait.request();
        if let Err(e) = self.send_task(pushed_task) {
            fail!("Error add_validator_adnl_key: {}", e);
        }
        match wait.wait(&mut queue_reader, true).await {
            Some(None) => fail!("Answer was not set!"),
            Some(Some(Answer::Result(result))) => result,
            Some(Some(_)) => fail!("Bad answer (AddValidatorAdnlKey)!"),
            None => fail!("Waiting returned an internal error!"),
        }
    }

    // Unused
    ///// returns validator's public key
    //    pub fn get_current_validator_key(&self, vset: &ValidatorSet) -> Option<[u8; 32]> {
    //        // search by adnl_id in validator_keys first
    //        for id_key in self.validator_keys.values.iter() {
    //            if let Some(adnl_id) = id_key.1.validator_adnl_key_id.as_ref() {
    //                match UInt256::from_str(adnl_id) {
    //                    Ok(adnl_id) => {
    //                        let pub_key_opt = vset.list().iter().find_map(|descr| {
    //                            if descr.adnl_addr.as_ref() == Some(&adnl_id) {
    //                                Some(descr.public_key.key_bytes().clone())
    //                            } else {
    //                                None
    //                            }
    //                        });
    //                        if let Some(pub_key) = pub_key_opt.as_ref() {
    //                            log::info!("get_current_validator_key returns pub_key {}", hex::encode(pub_key));
    //                            return pub_key_opt
    //                        }
    //                    }
    //                    Err(err) => log::warn!("adnl_id error: {}", err)
    //                }
    //            }
    //        }
    //        // then search by key_id from vset in keyring
    //        for descr in vset.list().iter() {
    //            let key_id = base64_encode(descr.compute_node_id_short().as_slice());
    //            let pub_key_found = self.key_ring.iter().position(|k_v| k_v.0 == key_id).is_some();
    //            if pub_key_found {
    //                log::info!("get_current_validator_key returns pub_key {}", hex::encode(descr.public_key.key_bytes()));
    //                return Some(descr.public_key.key_bytes().clone())
    //            }
    //        }
    //        log::warn!("get_current_validator_key key not found");
    //        None
    //    }

    // Unused
    //    pub fn workchain_id(&self) -> Option<i32> {
    //        self.workchain_id
    //    }

    pub fn get_actual_validator_adnl_key_ids(&self) -> Result<Vec<Arc<KeyId>>> {
        self.get_actual_key_ids(|| self.validator_keys.get_validator_adnl_key_ids())
    }

    pub fn get_actual_validator_key_ids(&self) -> Result<Vec<Arc<KeyId>>> {
        self.get_actual_key_ids_sorted(|| self.validator_keys.get_validator_key_ids())
    }

    pub fn get_actual_validator_keys(&self) -> Result<Vec<ValidatorKeysJson>> {
        let mut result = Vec::new();
        for validator_key_id in self.validator_keys.get_validator_key_ids().into_iter() {
            let Some(key) = self.validator_keys.get(&validator_key_id) else {
                log::warn!("Validator key id {validator_key_id} not found in validator_keys");
                continue;
            };
            result.push(key);
        }
        Ok(result)
    }

    pub async fn add_custom_overlay(
        &self,
        overlay: CustomOverlay,
    ) -> Result<CustomOverlaysConfigBoxed> {
        let (wait, mut queue_reader) = Wait::new();
        let pushed_task = (wait.clone(), Task::AddCustomOverlay(overlay));
        wait.request();
        if let Err(e) = self.send_task(pushed_task) {
            fail!("Error add_custom_overlay: {}", e);
        }
        match wait.wait(&mut queue_reader, true).await {
            Some(None) => fail!("Answer was not set!"),
            Some(Some(Answer::CustomOverlays(r))) => r,
            Some(Some(_)) => fail!("Bad answer (Result needed)!"),
            None => fail!("Waiting returned an internal error!"),
        }
    }

    pub async fn del_custom_overlay(&self, name: String) -> Result<CustomOverlaysConfigBoxed> {
        let (wait, mut queue_reader) = Wait::new();
        let pushed_task = (wait.clone(), Task::DelCustomOverlay(name));
        wait.request();
        if let Err(e) = self.send_task(pushed_task) {
            fail!("Error del_custom_overlay: {}", e);
        }
        match wait.wait(&mut queue_reader, true).await {
            Some(None) => fail!("Answer was not set!"),
            Some(Some(Answer::CustomOverlays(r))) => r,
            Some(Some(_)) => fail!("Bad answer (Result needed)!"),
            None => fail!("Waiting returned an internal error!"),
        }
    }

    /// The startup policy of shard overlay certificate pushes.
    pub fn shard_overlay_certificate_policy(&self) -> &ShardOverlayCertificatePolicy {
        &self.shard_overlay_certificate_policy
    }

    /// The live external-message broadcast setting the full node reads.
    pub fn ext_messages_broadcast_disabled_flag(&self) -> Arc<atomic::AtomicBool> {
        self.ext_messages.live.clone()
    }

    /// Change the external-message broadcast setting: an unchanged value
    /// succeeds without a write; otherwise the configuration and the live
    /// setting change first and the file is written after, so a failed write
    /// is reported with the change already in force.
    pub async fn set_ext_messages_broadcast_disabled(&self, disabled: bool) -> Result<()> {
        let (wait, mut queue_reader) = Wait::new();
        let pushed_task = (wait.clone(), Task::SetExtMessagesBroadcastDisabled(disabled));
        wait.request();
        if let Err(e) = self.send_task(pushed_task) {
            fail!("Error set_ext_messages_broadcast_disabled: {}", e);
        }
        match wait.wait(&mut queue_reader, true).await {
            Some(None) => fail!("Answer was not set!"),
            Some(Some(Answer::Result(result))) => result,
            Some(Some(_)) => fail!("Bad answer (SetExtMessagesBroadcastDisabled)!"),
            None => fail!("Waiting returned an internal error!"),
        }
    }

    #[cfg(test)]
    pub(crate) fn fail_next_ext_messages_save(&self) {
        self.ext_messages.fail_next_save.store(true, atomic::Ordering::SeqCst);
    }

    pub async fn show_custom_overlays(&self) -> Result<CustomOverlaysConfigBoxed> {
        let (wait, mut queue_reader) = Wait::new();
        let pushed_task = (wait.clone(), Task::GetCustomOverlays);
        wait.request();
        if let Err(e) = self.send_task(pushed_task) {
            fail!("Error show_custom_overlays: {}", e);
        }
        match wait.wait(&mut queue_reader, true).await {
            Some(None) => fail!("Answer was not set!"),
            Some(Some(Answer::CustomOverlays(r))) => r,
            Some(Some(_)) => fail!("Bad answer (Result needed)!"),
            None => fail!("Waiting returned an internal error!"),
        }
    }

    pub async fn get_adnl_keys(&self) -> Result<Vec<(String, usize)>> {
        let (wait, mut queue_reader) = Wait::new();
        let pushed_task = (wait.clone(), Task::ExportAdnlKeys);
        wait.request();
        if let Err(e) = self.send_task(pushed_task) {
            log::warn!("Error get_adnl_keys {e}");
            return Ok(vec![]);
        }
        match wait.wait(&mut queue_reader, true).await {
            Some(Some(Answer::AdnlKeys(keys))) => Ok(keys),
            _ => Ok(vec![]),
        }
    }

    pub async fn get_validator_key(
        &self,
        key_id: &Arc<KeyId>,
    ) -> Option<(Arc<dyn KeyOption>, i32)> {
        match self.validator_keys.get(&base64_encode(key_id.data())) {
            Some(key) => {
                //       let result = if let Some(key) = self.key_ring.get(&key_id) {
                //           Some(key.(val(), key_election_id))

                if let Some(key_opt) = self.get_key_raw(*key_id.data()).await {
                    Some((key_opt, key.election_id))
                } else {
                    None
                }
            }
            None => None,
        }
    }

    async fn get_key_raw(&self, key_hash: [u8; 32]) -> Option<Arc<dyn KeyOption>> {
        let (wait, mut queue_reader) = Wait::new();
        let pushed_task = (wait.clone(), Task::GetKey(key_hash));
        wait.request();
        if let Err(e) = self.send_task(pushed_task) {
            log::warn!("Error get_key_raw {}", e);
            return None;
        }
        match wait.wait(&mut queue_reader, true).await {
            Some(Some(Answer::GetKey(key))) => key,
            _ => None,
        }
    }

    fn get_actual_key_ids(&self, src: impl Fn() -> Vec<String>) -> Result<Vec<Arc<KeyId>>> {
        let mut result = Vec::new();
        for key_id in src().iter() {
            let id = base64_decode(key_id)?;
            result.push(KeyId::from_data(id[..].try_into()?));
        }
        Ok(result)
    }

    fn get_actual_key_ids_sorted(&self, src: impl Fn() -> Vec<String>) -> Result<Vec<Arc<KeyId>>> {
        let mut ids = Vec::new();
        for key_id in src().iter() {
            let id = base64_decode(key_id)?;
            let key_bytes: [u8; 32] = id[..].try_into()?;
            ids.push((key_bytes, KeyId::from_data(key_bytes)));
        }

        ids.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        ids.dedup_by(|(left, _), (right, _)| left == right);

        Ok(ids.into_iter().map(|(_, key_id)| key_id).collect())
    }

    // generates a new key and saves it to config
    // returns public key hash as key_id
    async fn generate_and_save(
        key_ring: &Arc<lockfree::map::Map<String, Arc<dyn KeyOption>>>,
        key_type: i32,
        config: &mut TonNodeConfig,
        config_name: &str,
    ) -> Result<[u8; 32]> {
        log::info!("start generate key (type: {})", key_type);
        let (key_id, key_opt) = config.generate_and_save_keys(key_type)?;
        config.save_to_file(config_name).await?;

        let id = base64_encode(key_id);
        let key_config = config.validator_key_ring.as_ref().and_then(|r| r.get(&id)).cloned();
        if let Some(key_config) = key_config {
            try_n_times(3, Duration::from_millis(150), || {
                SecretsVaultConfig::save_private_key(&id, &key_config, &key_opt)
            })
            .await?;
        }

        log::info!("finish generate key (type: {key_type}), key_id: {id}");
        key_ring.insert(id, key_opt.clone());
        Ok(key_id)
    }

    async fn import_private_key(
        key_ring: &Arc<lockfree::map::Map<String, Arc<dyn KeyOption>>>,
        key: PrivateKey,
        config: &mut TonNodeConfig,
        config_name: &str,
    ) -> Result<[u8; 32]> {
        log::info!("start import private key");
        let (key_id, public_key) = config.import_private_key(key)?;
        config.save_to_file(config_name).await?;

        let id = base64_encode(key_id);
        let key_config = config.validator_key_ring.as_ref().and_then(|r| r.get(&id)).cloned();
        if let Some(key_config) = key_config {
            try_n_times(3, Duration::from_millis(150), || {
                SecretsVaultConfig::save_private_key(&id, &key_config, &public_key)
            })
            .await?;
        }

        key_ring.insert(id, public_key.clone());
        log::info!("finish import private key, key_id: {}", base64_encode(key_id));
        Ok(key_id)
    }

    #[cfg(test)]
    async fn add_validator_adnl_key_and_save(
        self: Arc<Self>,
        validator_keys: &Arc<ValidatorKeys>,
        config: &mut TonNodeConfig,
        validator_key_hash: &[u8; 32],
        validator_adnl_key_hash: &[u8; 32],
        subscribers: &[Arc<dyn NodeConfigSubscriber>],
    ) -> Result<()> {
        let key = config.add_validator_adnl_key(validator_key_hash, validator_adnl_key_hash)?;
        let election_id = key.election_id;
        self.update_validator_transport(|| validator_keys.add(key.clone()))?;
        try_n_times(3, Duration::from_millis(150), || SecretsVaultConfig::save_validator_key(&key))
            .await?;
        let adnl_key_id = KeyId::from_data(*validator_adnl_key_hash);

        for subscriber in subscribers.iter() {
            self.dispatch_config_event(
                subscriber.clone(),
                ConfigEvent::AddValidatorAdnlKey(adnl_key_id.clone(), election_id),
            );
        }

        config.save_to_file(&config.file_name).await?;
        Ok(())
    }

    /// Runs one key command in the configuration actor. The configuration
    /// changes first, then the runtime follows it (validator key map, vault,
    /// ADNL bindings, key ring), and the file is written last: a failed write
    /// is reported with the change already in force, as the reference engine
    /// reports a failed configuration write.
    async fn apply_key_command_and_save(
        &self,
        validator_keys: &Arc<ValidatorKeys>,
        key_ring: &Arc<lockfree::map::Map<String, Arc<dyn KeyOption>>>,
        config: &mut TonNodeConfig,
        command: KeyCommand,
        subscribers: &[Arc<dyn NodeConfigSubscriber>],
    ) -> Result<()> {
        let now = u32::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| error!("system clock before the epoch: {e}"))?
                .as_secs(),
        )
        .map_err(|_| error!("system clock beyond the 32-bit Unix time range"))?;
        let before = config.key_state();
        let change = config.apply_key_command(command, now)?;
        if !change.changed {
            return Ok(());
        }
        let collected = config.collect_released(&change.released);
        // The vault records go first: when one of them cannot be written the
        // configuration is put back, so that repeating the command repeats
        // the whole change instead of leaving a record the next start reloads.
        let durable = async {
            if let Some(removed) = &change.removed {
                SecretsVaultConfig::drop_validator_metadata(&removed.validator_key_id).await?;
            }
            if let Some(updated) = &change.updated {
                try_n_times(3, Duration::from_millis(150), || {
                    SecretsVaultConfig::save_validator_key(updated)
                })
                .await?;
            }
            for id in &collected {
                SecretsVaultConfig::on_drop(id).await?;
            }
            Ok::<(), rtos_block::Error>(())
        };
        if let Err(error) = durable.await {
            config.restore_key_state(before);
            return Err(error);
        }
        if let Some(removed) = &change.removed {
            self.update_validator_transport(|| validator_keys.remove(removed).map(|_| ()))?;
        }
        if let Some(updated) = &change.updated {
            self.update_validator_transport(|| validator_keys.add(updated.clone()))?;
        }
        let event_key = |adnl: &str| -> Result<Arc<KeyId>> {
            let bytes = base64_decode(adnl)?;
            Ok(KeyId::from_data(
                bytes[..].try_into().map_err(|e| error!("Invalid ADNL key Id {adnl}: {e}"))?,
            ))
        };
        for (adnl, election) in &change.unbound {
            // The transport of a key bound by another validator entry stays.
            let still_bound = config.validator_keys.as_ref().is_some_and(|keys| {
                keys.iter().any(|key| key.validator_adnl_key_id.as_deref() == Some(adnl.as_str()))
            });
            if still_bound {
                continue;
            }
            let id = event_key(adnl)?;
            for subscriber in subscribers {
                self.dispatch_config_event(
                    subscriber.clone(),
                    ConfigEvent::RemoveValidatorAdnlKey(id.clone(), *election),
                );
            }
        }
        for (adnl, election) in &change.bound {
            let id = event_key(adnl)?;
            for subscriber in subscribers {
                self.dispatch_config_event(
                    subscriber.clone(),
                    ConfigEvent::AddValidatorAdnlKey(id.clone(), *election),
                );
            }
        }
        for id in &collected {
            key_ring.remove(id);
        }
        config.save_to_file(&config.file_name).await
    }

    /// Runs a key command of the control interface.
    pub async fn key_command(&self, command: KeyCommand) -> Result<()> {
        let (wait, mut queue_reader) = Wait::new();
        let pushed_task = (wait.clone(), Task::KeyCommand(command));
        wait.request();
        self.send_task(pushed_task)?;
        match wait.wait(&mut queue_reader, true).await {
            Some(None) => fail!("Answer was not set!"),
            Some(Some(Answer::Result(result))) => result,
            Some(Some(_)) => fail!("Bad answer (KeyCommand)!"),
            None => fail!("Waiting returned an internal error!"),
        }
    }

    /// Every private key the node holds, by key id, for an encrypted export.
    pub async fn exportable_private_keys(&self) -> Result<Vec<ExportedKey>> {
        let (wait, mut queue_reader) = Wait::new();
        let pushed_task = (wait.clone(), Task::PrivateKeys);
        wait.request();
        self.send_task(pushed_task)?;
        match wait.wait(&mut queue_reader, true).await {
            Some(None) => fail!("Answer was not set!"),
            Some(Some(Answer::PrivateKeys(keys))) => keys,
            Some(Some(_)) => fail!("Bad answer (PrivateKeys)!"),
            None => fail!("Waiting returned an internal error!"),
        }
    }

    /// The configuration as the control interface projects it.
    pub async fn control_view(&self) -> Result<ControlConfigView> {
        let (wait, mut queue_reader) = Wait::new();
        let pushed_task = (wait.clone(), Task::ControlView);
        wait.request();
        self.send_task(pushed_task)?;
        match wait.wait(&mut queue_reader, true).await {
            Some(None) => fail!("Answer was not set!"),
            Some(Some(Answer::ControlView(view))) => Ok(*view),
            Some(Some(Answer::Result(Err(error)))) => Err(error),
            Some(Some(_)) => fail!("Bad answer (ControlView)!"),
            None => fail!("Waiting returned an internal error!"),
        }
    }

    #[cfg(test)]
    async fn add_validator_key_and_save(
        &self,
        validator_keys: Arc<ValidatorKeys>,
        config: &mut TonNodeConfig,
        key_id: &[u8; 32],
        election_id: i32,
        expire_at: i32,
    ) -> Result<()> {
        let key = config.add_validator_key(key_id, election_id, expire_at)?;
        self.update_validator_transport(|| validator_keys.add(key.clone()))?;
        config.save_to_file(&config.file_name).await?;
        try_n_times(3, Duration::from_millis(150), || SecretsVaultConfig::save_validator_key(&key))
            .await?;
        Ok(())
    }

    async fn add_custom_overlay_and_save(
        config: &mut TonNodeConfig,
        overlay: CustomOverlay,
    ) -> Result<CustomOverlaysConfigBoxed> {
        let CustomOverlaysConfigBoxed::Engine_Validator_CustomOverlaysConfig(conf) =
            &mut config.custom_overlays;
        conf.overlays.push(overlay);
        TonNodeConfig::save_custom_overlays_json(
            &config.custom_overlays,
            &config.custom_overlays_file_name,
        )
        .await?;
        Ok(config.custom_overlays.clone())
    }

    async fn del_custom_overlay_and_save(
        config: &mut TonNodeConfig,
        name: String,
    ) -> Result<CustomOverlaysConfigBoxed> {
        let CustomOverlaysConfigBoxed::Engine_Validator_CustomOverlaysConfig(conf) =
            &mut config.custom_overlays;
        conf.overlays.retain(|overlay| overlay.name != name);
        TonNodeConfig::save_custom_overlays_json(
            &config.custom_overlays,
            &config.custom_overlays_file_name,
        )
        .await?;
        Ok(config.custom_overlays.clone())
    }

    fn get_key(config: &TonNodeConfig, key_id: [u8; 32]) -> Option<Arc<dyn KeyOption>> {
        if let Some(validator_key_ring) = &config.validator_key_ring {
            if let Some(key_config) = validator_key_ring.get(&base64_encode(key_id)) {
                match get_key_option_factory().from_private_key_json(key_config) {
                    Ok(key) => return Some(key),
                    Err(e) => {
                        log::error!(
                            "get_key {}: from_private_key_json failed: {e}",
                            base64_encode(key_id),
                        );
                        return None;
                    }
                }
            }
        }
        None
    }

    fn export_adnl_keys(actual_config: &TonNodeConfig) -> Vec<(String, usize)> {
        let mut result = Vec::new();
        if let Some(adnl_config) = &actual_config.adnl_node {
            if let Ok(overlay_key) = adnl_config.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY, true) {
                result.push((base64_encode(overlay_key.id().data()), NodeNetwork::TAG_OVERLAY_KEY));
            }
            if let Ok(dht_key) = adnl_config.key_by_tag(NodeNetwork::TAG_DHT_KEY, true) {
                result.push((base64_encode(dht_key.id().data()), NodeNetwork::TAG_DHT_KEY));
            }
        }
        result
    }

    fn load_config(
        &self,
        config: &TonNodeConfig,
        subscribers: &[Arc<dyn NodeConfigSubscriber>],
    ) -> Result<()> {
        // load key ring
        if let Some(key_ring) = &config.validator_key_ring {
            for (key_id, key) in key_ring.iter() {
                if let Err(e) = self.add_key_to_dynamic_key_ring(key_id.to_string(), key) {
                    log::warn!("fail added key from key ring: {}", e);
                }
            }
        }

        // Explicit transport-only identities must resolve to their actual local
        // private key. A malformed/missing key is a configuration error, not an
        // invitation to substitute the ordinary fullnode overlay key.
        for binding in &self.consensus_transport_bindings {
            let key = Self::get_key(config, *binding.adnl_key_id.data()).ok_or_else(|| {
                error!("Configured consensus transport private key is unavailable")
            })?;
            if key.id() != &binding.adnl_key_id {
                fail!("Configured consensus transport key identity mismatch");
            }
        }

        // load validator keys
        if let Some(validator_keys) = &config.validator_keys {
            for key in validator_keys.iter() {
                if let Err(e) =
                    self.update_validator_transport(|| self.validator_keys.add(key.clone()))
                {
                    log::warn!("fail added key to validator keys map: {}", e);
                }
                if let Some(validator_adnl_key_id) = &key.validator_adnl_key_id {
                    let adnl_key_id = base64_decode(validator_adnl_key_id)?;
                    let adnl_key_id = KeyId::from_data(adnl_key_id[..].try_into()?);
                    let election_id = key.election_id;
                    for subscriber in subscribers {
                        self.dispatch_config_event(
                            subscriber.clone(),
                            ConfigEvent::AddValidatorAdnlKey(adnl_key_id.clone(), election_id),
                        );
                    }
                }
            }
        }
        Ok(())
    }

    fn add_key_to_dynamic_key_ring(
        &self,
        key_id: String,
        key_config: &KeyOptionJson,
    ) -> Result<()> {
        let key_option = match get_key_option_factory().from_private_key_json(key_config) {
            Ok(k) => k,
            Err(e) => fail!("Failed to load key (key_id: {}): {}", key_id, e),
        };

        if let Some(key) = self.key_ring.insert(key_option.id().to_string(), key_option) {
            log::warn!("Added key was already in key ring collection (id: {})", key.key());
        }

        Ok(())
    }

    pub fn start_sheduler(
        self: Arc<Self>,
        config_handler_context: NodeConfigHandlerContext,
        subscribers: Vec<Arc<dyn NodeConfigSubscriber>>,
    ) -> Result<()> {
        let name = config_handler_context.config.file_name.clone();
        let mut actual_config = config_handler_context.config;
        let mut reader = scheduler::ConfigInbox(config_handler_context.reader);
        let key_ring = self.key_ring.clone();
        let validator_keys = self.validator_keys.clone();
        let ext_messages = self.ext_messages.clone();
        let scheduler = self.scheduler.clone();
        let mut admission = scheduler.admission.lock().unwrap();
        if !admission.open || admission.started {
            fail!("Configuration scheduler is stopped or already started");
        }
        admission.started = true;
        let loaded = self.load_config(&actual_config, &subscribers);
        let scheduler_worker = scheduler.clone();
        let runtime = self.runtime_handle.clone();
        let worker = runtime.spawn(async move {
            let mut draining = false;
            loop {
                let task = if draining {
                    match reader.try_recv() {
                        Ok(task) => Some(task),
                        Err(_) => {
                            // No external writes can enter after stop. Existing
                            // callbacks may still ask this actor for their key.
                            scheduler_worker.callbacks.close();
                            tokio::select! {
                                biased;
                                _ = scheduler_worker.callbacks.wait() => None,
                                task = reader.recv() => task,
                            }
                        }
                    }
                } else {
                    tokio::select! {
                        biased;
                        _ = scheduler_worker.cancellation.cancelled() => {
                            draining = true;
                            continue;
                        },
                        task = reader.recv() => task,
                    }
                };
                let Some(task) = task else { break };
                let mut response = PendingAnswer::new(task.0);
                let answer = match task.1 {
                    Task::Generate(key_type) => {
                        let result = NodeConfigHandler::generate_and_save(
                            &key_ring,
                            key_type,
                            &mut actual_config,
                            &name,
                        )
                        .await;
                        Answer::Generate(result)
                    }
                    Task::ImportPrivateKey(ref key) => {
                        let result = NodeConfigHandler::import_private_key(
                            &key_ring,
                            key.clone(),
                            &mut actual_config,
                            &name,
                        )
                        .await;
                        self.notify_validator_transport_changed();
                        Answer::ImportPrivateKey(result)
                    }
                    #[cfg(test)]
                    Task::AddValidatorAdnlKey(key, adnl_key) => {
                        let result = NodeConfigHandler::add_validator_adnl_key_and_save(
                            self.clone(),
                            &validator_keys,
                            &mut actual_config,
                            &key,
                            &adnl_key,
                            &subscribers,
                        )
                        .await;
                        self.notify_validator_transport_changed();
                        Answer::Result(result)
                    }
                    #[cfg(test)]
                    Task::AddValidatorKey(key, election_id, expire_at) => {
                        let result = self
                            .add_validator_key_and_save(
                                validator_keys.clone(),
                                &mut actual_config,
                                &key,
                                election_id,
                                expire_at,
                            )
                            .await;
                        self.notify_validator_transport_changed();
                        Answer::Result(result)
                    }
                    Task::KeyCommand(command) => {
                        let result = self
                            .apply_key_command_and_save(
                                &validator_keys,
                                &key_ring,
                                &mut actual_config,
                                command,
                                &subscribers,
                            )
                            .await;
                        self.notify_validator_transport_changed();
                        Answer::Result(result)
                    }
                    Task::PrivateKeys => Answer::PrivateKeys(actual_config.private_keys()),
                    Task::ControlView => match actual_config.control_view() {
                        Ok(view) => Answer::ControlView(Box::new(view)),
                        Err(error) => Answer::Result(Err(error)),
                    },
                    Task::GetKey(key_data) => {
                        let result = NodeConfigHandler::get_key(&actual_config, key_data);
                        Answer::GetKey(result)
                    }
                    Task::ExportAdnlKeys => {
                        let keys = NodeConfigHandler::export_adnl_keys(&actual_config);
                        Answer::AdnlKeys(keys)
                    }
                    Task::AddCustomOverlay(overlay) => {
                        let result = NodeConfigHandler::add_custom_overlay_and_save(
                            &mut actual_config,
                            overlay,
                        )
                        .await;
                        Answer::CustomOverlays(result)
                    }
                    Task::DelCustomOverlay(name) => {
                        let result = NodeConfigHandler::del_custom_overlay_and_save(
                            &mut actual_config,
                            name,
                        )
                        .await;
                        Answer::CustomOverlays(result)
                    }
                    Task::GetCustomOverlays => {
                        Answer::CustomOverlays(Ok(actual_config.custom_overlays.clone()))
                    }
                    Task::SetExtMessagesBroadcastDisabled(disabled) => {
                        let result = if actual_config.ext_messages_broadcast_disabled == disabled {
                            Ok(())
                        } else {
                            actual_config.ext_messages_broadcast_disabled = disabled;
                            ext_messages.live.store(disabled, atomic::Ordering::Release);
                            ext_messages.save(&actual_config, &name).await
                        };
                        Answer::Result(result)
                    }
                };
                response.respond(answer);
            }
            reader.close();
            while let Ok((wait, _)) = reader.try_recv() {
                wait.respond(None);
            }
        });
        scheduler.own_worker(&runtime, worker);
        drop(admission);
        if loaded.is_err() {
            scheduler.stop();
        }
        loaded
    }
}

#[async_trait::async_trait]
impl KeyRing for NodeConfigHandler {
    async fn generate(&self, key_type: i32) -> Result<[u8; 32]> {
        log::info!("request generate key (key_type: {})", key_type);
        let (wait, mut queue_reader) = Wait::new();
        let pushed_task = (wait.clone(), Task::Generate(key_type));
        wait.request();
        if let Err(e) = self.send_task(pushed_task) {
            fail!("Error generate: {}", e);
        }
        match wait.wait(&mut queue_reader, true).await {
            Some(None) => fail!("Answer was not set!"),
            Some(Some(Answer::Generate(result))) => result,
            Some(Some(_)) => fail!("Bad answer (Generate)!"),
            None => fail!("Waiting returned an internal error!"),
        }
    }

    async fn import_private_key(&self, key: PrivateKey) -> Result<[u8; 32]> {
        log::info!("request import private key");
        let (wait, mut queue_reader) = Wait::new();
        let pushed_task = (wait.clone(), Task::ImportPrivateKey(key));
        wait.request();
        if let Err(e) = self.send_task(pushed_task) {
            fail!("Error generate: {}", e);
        }
        match wait.wait(&mut queue_reader, true).await {
            Some(None) => fail!("Answer was not set!"),
            Some(Some(Answer::ImportPrivateKey(result))) => result,
            Some(Some(_)) => fail!("Bad answer (ImportPrivateKey)!"),
            None => fail!("Waiting returned an internal error!"),
        }
    }

    fn sign_data(&self, key_hash: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
        let private = self.find(key_hash)?;
        Ok(private.sign(data)?.to_vec())
    }

    // find private key in KeyRing by public key hash
    fn find(&self, key_id: &[u8; 32]) -> Result<Arc<dyn KeyOption>> {
        let id = base64_encode(key_id);
        match self.key_ring.get(&id) {
            Some(key) => Ok(key.val().clone()),
            None => fail!("key not found for hash: {}", &id),
        }
    }
}

impl TonNodeGlobalConfig {
    /// Constructor from json file
    pub fn from_json_file(json_file: impl AsRef<Path>) -> Result<Self> {
        let rtos_node_global_cfg_json = TonNodeGlobalConfigJson::from_json_file(json_file)?;
        Ok(TonNodeGlobalConfig(rtos_node_global_cfg_json))
    }
    /*
        pub fn from_json(json : &str) -> Result<Self> {
            let rtos_node_global_cfg_json = TonNodeGlobalConfigJson::from_json(&json)?;
            Ok(TonNodeGlobalConfig(rtos_node_global_cfg_json))
        }
    */

    pub fn zero_state(&self) -> Result<BlockIdExt> {
        self.0.zero_state()
    }

    pub fn init_block(&self) -> Result<Option<BlockIdExt>> {
        self.0.init_block()
    }

    pub fn hardforks(&self) -> Result<Vec<BlockIdExt>> {
        self.0.hardforks()
    }

    pub fn dht_nodes(&self) -> Result<Vec<DhtNodeConfig>> {
        self.0.get_dht_nodes_configs()
    }

    // Unused
    //    pub fn dht_param_a(&self) -> Result<i32> {
    //        self.0.dht.a.ok_or_else(|| error!("Dht param a is not set!"))
    //    }

    // Unused
    //    pub fn dht_param_k(&self) -> Result<i32> {
    //        self.0.dht.k.ok_or_else(|| error!("Dht param k is not set!"))
    //    }
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub struct TonNodeGlobalConfigJson {
    #[serde(alias = "@type")]
    type_node: String,
    dht: DhtGlobalConfig,
    validator: Validator,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
struct DhtGlobalConfig {
    #[serde(alias = "@type")]
    type_dht: Option<String>,
    k: Option<i32>,
    a: Option<i32>,
    static_nodes: DhtNodes,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
struct DhtNodes {
    #[serde(alias = "@type")]
    type_dht: Option<String>,
    nodes: Vec<DhtNode>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
struct DhtNode {
    #[serde(alias = "@type")]
    type_node: Option<String>,
    id: IdDhtNode,
    addr_list: AddressList,
    version: Option<i32>,
    signature: Option<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
struct IdDhtNode {
    #[serde(alias = "@type")]
    type_node: Option<String>,
    key: Option<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
struct AddressList {
    #[serde(alias = "@type")]
    type_node: Option<String>,
    addrs: Vec<Address>,
    version: Option<i32>,
    reinit_date: Option<i32>,
    priority: Option<i32>,
    expire_at: Option<i32>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub struct Address {
    #[serde(alias = "@type")]
    type_node: Option<String>,
    ip: Option<i64>,
    port: Option<u16>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
struct Validator {
    #[serde(alias = "@type")]
    type_node: Option<String>,
    zero_state: ConfigBlockId,
    init_block: Option<ConfigBlockId>,
    hardforks: Vec<ConfigBlockId>,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
struct ConfigBlockId {
    workchain: Option<i32>,
    shard: Option<i64>,
    seqno: Option<u32>,
    root_hash: Option<String>,
    file_hash: Option<String>,
}

pub const PUB_ED25519: &str = "pub.ed25519";

impl IdDhtNode {
    pub fn convert_key(&self) -> Result<Arc<dyn KeyOption>> {
        let type_id = self.type_node.as_ref().ok_or_else(|| error!("Type_node is not set!"))?;

        if !type_id.eq(PUB_ED25519) {
            fail!("unknown type_node!")
        };

        let key = if let Some(key) = &self.key {
            base64_decode(key)?
        } else {
            fail!("No public key!");
        };

        let pub_key = key[..32].try_into()?;
        Ok(Ed25519KeyOption::<ZeroizingBytes>::from_public_key(pub_key))
    }
}

impl TonNodeGlobalConfigJson {
    /// Constructs new configuration from JSON data
    pub fn from_json_file(json_file: impl AsRef<Path>) -> Result<Self> {
        let file = File::open(json_file.as_ref())
            .map_err(|err| error!("cannot open file {:?} : {}", json_file.as_ref(), err))?;
        let reader = BufReader::new(file);
        Ok(serde_json::from_reader(reader)?)
    }
    /*
        pub fn from_json(json: &str) -> Result<Self> {
            let json_config: TonNodeGlobalConfigJson = serde_json::from_str(json)?;
            Ok(json_config)
        }
    */

    pub fn get_dht_nodes_configs(&self) -> Result<Vec<DhtNodeConfig>> {
        let mut result = Vec::new();
        for dht_node in self.dht.static_nodes.nodes.iter() {
            let key = dht_node.id.convert_key()?;
            let mut addrs = Vec::new();
            for addr in dht_node.addr_list.addrs.iter() {
                let ip = if let Some(ip) = addr.ip {
                    ip
                } else {
                    continue;
                };
                let port = if let Some(port) = addr.port { port } else { continue };
                let addr = Udp { ip: ip as i32, port: port as i32 }.into_boxed();
                addrs.push(addr);
            }
            let version =
                if let Some(version) = dht_node.addr_list.version { version } else { continue };
            let reinit_date = if let Some(reinit_date) = dht_node.addr_list.reinit_date {
                reinit_date
            } else {
                continue;
            };
            let priority =
                if let Some(priority) = dht_node.addr_list.priority { priority } else { continue };
            let expire_at = if let Some(expire_at) = dht_node.addr_list.expire_at {
                expire_at
            } else {
                continue;
            };
            let addr_list = AdnlAddressList { addrs, version, reinit_date, priority, expire_at };
            let version = if let Some(version) = dht_node.version { version } else { continue };
            let signature =
                if let Some(signature) = &dht_node.signature { signature } else { continue };
            let node = DhtNodeConfig {
                id: Ed25519 { key: UInt256::with_array(key.pub_key()?.try_into()?) }.into_boxed(),
                addr_list,
                version,
                signature: base64_decode(signature)?,
            };
            result.push(node) //convert_to_dht_node_cfg()?);
        }
        Ok(result)
    }

    fn parse_block_id(&self, block_id: &ConfigBlockId) -> Result<BlockIdExt> {
        let workchain_id =
            block_id.workchain.ok_or_else(|| error!("Unknown workchain id (of zero_state)!"))?;

        let seqno =
            block_id.seqno.ok_or_else(|| error!("Unknown workchain seqno (of zero_state)!"))?;

        let shard =
            block_id.shard.ok_or_else(|| error!("Unknown workchain shard (of zero_state)!"))?;

        let root_hash = block_id
            .root_hash
            .as_ref()
            .ok_or_else(|| error!("Unknown workchain root_hash (of zero_state)!"))?
            .parse()?;

        let file_hash = block_id
            .file_hash
            .as_ref()
            .ok_or_else(|| error!("Unknown workchain file_hash (of zero_state)!"))?
            .parse()?;

        Ok(BlockIdExt {
            shard_id: ShardIdent::with_tagged_prefix(workchain_id, shard as u64)?,
            seq_no: seqno,
            root_hash,
            file_hash,
        })
    }

    pub fn zero_state(&self) -> Result<BlockIdExt> {
        let id = self
            .parse_block_id(&self.validator.zero_state)
            .map_err(|err| error!("zero state parse error: {}", err))?;
        if !id.shard().is_masterchain_ext() || id.seq_no != 0 {
            fail!("Network zerostate must be masterchain sequence zero");
        }
        if id.root_hash == UInt256::default() || id.file_hash == UInt256::default() {
            fail!("Network zerostate requires explicit nonzero root and file hashes");
        }
        Ok(id)
    }

    pub fn init_block(&self) -> Result<Option<BlockIdExt>> {
        match self.validator.init_block {
            Some(ref init_block) => match self.parse_block_id(init_block) {
                Ok(block_id) => {
                    if !block_id.shard().is_masterchain_ext()
                        || block_id.root_hash == UInt256::default()
                        || block_id.file_hash == UInt256::default()
                    {
                        fail!("Initial checkpoint requires a complete masterchain block identity");
                    }
                    if block_id.seq_no == 0 && block_id != self.zero_state()? {
                        fail!("Initial sequence-zero checkpoint differs from network zerostate");
                    }
                    Ok(Some(block_id))
                }
                Err(err) => fail!("init block parse error: {}", err),
            },
            None => Ok(None),
        }
    }

    fn hardforks(&self) -> Result<Vec<BlockIdExt>> {
        log::info!("hardforks count {}", self.validator.hardforks.len());
        self.validator.hardforks.iter().try_fold(Vec::new(), |mut vec, block_id| {
            match self.parse_block_id(block_id) {
                Ok(block_id) => {
                    vec.push(block_id);
                    Ok(vec)
                }
                Err(err) => fail!("hardforks parse error: {}", err),
            }
        })
    }
}

#[derive(Clone)]
pub struct ValidatorManagerConfig {
    pub update_interval: Duration,
    pub unsafe_resync_catchains: HashSet<u32>,
    /// Maps catchain_seqno to block_seqno and unsafe rotation id
    pub unsafe_catchain_rotates: HashMap<u32, (u32, u32)>,
    pub no_countdown_for_zerostate: bool,
    pub accelerated_consensus_disabled: bool,
    /// Checkpoint-bound deletion of retired validator consensus namespaces.
    /// A start-up choice: when off no cleanup tick runs and durable records
    /// accumulate until a later start with cleanup on reclaims them.
    pub consensus_cleanup_enabled: bool,
    /// Period of the cleanup tick: at most one pass per tick.
    pub consensus_cleanup_tick: Duration,
    #[cfg(test)]
    pub test_emulator_consensus: Option<TestEmulatorConsensusConfig>,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct UnsafeCatchainRotation {
    catchain_seqno: u32,
    block_seqno: u32,
    unsafe_rotation_id: u32,
}

#[derive(Default, serde::Deserialize, serde::Serialize)]
struct ValidatorManagerConfigImpl {
    #[serde(default)]
    unsafe_resync_catchains: Vec<u32>,
    #[serde(default)]
    unsafe_catchain_rotates: Vec<UnsafeCatchainRotation>,
    #[serde(default)]
    disable_validator_consensus_cleanup: bool,
    #[cfg(test)]
    #[serde(default)]
    test_emulator_consensus: Option<TestEmulatorConsensusConfigJson>,
}

impl Display for ValidatorManagerConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "validation countdown mode: {}; update interval: {} ms; resync: [{}]; rotates: [{}]",
            if self.no_countdown_for_zerostate { "except-zerostate" } else { "always" },
            self.update_interval.as_millis(),
            self.unsafe_resync_catchains.iter().map(|n| format!("{} ", n)).collect::<String>(),
            self.unsafe_catchain_rotates
                .iter()
                .map(|(cc, (blk, uid))| format!("({},{})=>{} ", cc, blk, uid))
                .collect::<String>()
        )
    }
}

impl ValidatorManagerConfig {
    pub fn read_configs(
        config_files: Vec<String>,
        validation_countdown_mode: Option<String>,
        accelerated_consensus_disabled: bool,
    ) -> ValidatorManagerConfig {
        log::debug!(target: "validator", "Reading validator manager config files: {}",
            config_files.iter().map(|x| format!("{}; ",x)).collect::<String>());

        let mut validator_config = ValidatorManagerConfig::default();
        match validation_countdown_mode {
            Some(x) if x == "always" => validator_config.no_countdown_for_zerostate = false,
            Some(x) if x == "except-zerostate" => {
                validator_config.no_countdown_for_zerostate = true
            }
            Some(x) => log::error!(
                "Incorrect option: validation_countdown_mode must be either 'always' or 'except-zerostate', '{}' found",
                x
            ),
            None => (),
        }

        validator_config.accelerated_consensus_disabled = accelerated_consensus_disabled;

        'iterate_configs: for one_config in config_files.into_iter() {
            if let Ok(config_file) = std::fs::File::open(one_config.clone()) {
                let reader = std::io::BufReader::new(config_file);
                let config: ValidatorManagerConfigImpl = match serde_json::from_reader(reader) {
                    Err(e) => {
                        log::warn!(
                            "Not ValidatorManagerConfig, but expected to be: {}, error: {}",
                            one_config,
                            e
                        );
                        continue 'iterate_configs;
                    }
                    Ok(cfg) => cfg,
                };

                if config.disable_validator_consensus_cleanup {
                    validator_config.consensus_cleanup_enabled = false;
                }

                for resync in config.unsafe_resync_catchains.into_iter() {
                    validator_config.unsafe_resync_catchains.insert(resync);
                }

                for rotate in config.unsafe_catchain_rotates.into_iter() {
                    validator_config.unsafe_catchain_rotates.insert(
                        rotate.catchain_seqno,
                        (rotate.block_seqno, rotate.unsafe_rotation_id),
                    );
                }

                #[cfg(test)]
                if let Some(emulator_config) = config.test_emulator_consensus {
                    match TestEmulatorConsensusConfig::try_from(emulator_config) {
                        Ok(emulator_config) => {
                            validator_config.test_emulator_consensus = Some(emulator_config);
                        }
                        Err(e) => {
                            log::warn!("Invalid test_emulator_consensus in {}: {}", one_config, e);
                        }
                    }
                }
            }
        }

        log::info!(target: "validator", "Validator manager config has been read: {}", validator_config);

        validator_config
    }

    pub fn check_unsafe_catchain_rotation(
        &self,
        block_seqno_opt: Option<u32>,
        catchain_seqno: u32,
    ) -> Option<u32> {
        if let Some(blk) = block_seqno_opt {
            match self.unsafe_catchain_rotates.get(&catchain_seqno) {
                Some((required_block_seqno, rotation_id)) if *required_block_seqno <= blk => {
                    Some(*rotation_id)
                }
                _ => None,
            }
        } else {
            None
        }
    }
}

impl Default for ValidatorManagerConfig {
    fn default() -> Self {
        ValidatorManagerConfig {
            update_interval: Duration::from_secs(3),
            unsafe_resync_catchains: HashSet::new(),
            unsafe_catchain_rotates: HashMap::new(),
            no_countdown_for_zerostate: false,
            accelerated_consensus_disabled: false,
            consensus_cleanup_enabled: true,
            consensus_cleanup_tick: Duration::from_secs(
                consensus_common::validator_cleanup::ValidatorCleanupManager::TICK_SECONDS,
            ),
            #[cfg(test)]
            test_emulator_consensus: None,
        }
    }
}

struct ValidatorKeys {
    values: lockfree::map::Map<i32, ValidatorKeysJson>, // election_id, keys_info
    index: lockfree::map::Map<i32, i32>,                // current_election_id, next_election_id
    first: AtomicI32,
}

impl ValidatorKeys {
    fn new() -> Self {
        ValidatorKeys {
            values: lockfree::map::Map::new(),
            index: lockfree::map::Map::new(),
            first: AtomicI32::new(0),
        }
    }

    fn is_empty(&self) -> bool {
        self.first.load(atomic::Ordering::Relaxed) == 0
    }

    fn add(&self, key: ValidatorKeysJson) -> Result<()> {
        // inserted in sorted order
        let mut first = false;

        add_unbound_object_to_map_with_update(&self.values, key.election_id, |old| {
            if let Some(existing) = old {
                if existing.validator_key_id != key.validator_key_id {
                    log::warn!(
                        "ValidatorKeys: replacing validator key for election_id={}: \
                         old_key={} -> new_key={}",
                        key.election_id,
                        existing.validator_key_id,
                        key.validator_key_id,
                    );
                }
                if existing.validator_adnl_key_id != key.validator_adnl_key_id {
                    log::warn!(
                        "ValidatorKeys: adnl key changed for election_id={}: \
                         old_adnl={:?} -> new_adnl={:?}",
                        key.election_id,
                        existing.validator_adnl_key_id,
                        key.validator_adnl_key_id,
                    );
                }
            }
            if self
                .first
                .compare_exchange(
                    0,
                    key.election_id,
                    atomic::Ordering::Relaxed,
                    atomic::Ordering::Relaxed,
                )
                .is_ok()
            {
                first = true;
            }
            Ok(Some(key.clone()))
        })?;

        if first {
            return Ok(());
        }

        let mut current = self.first.load(atomic::Ordering::Relaxed);
        match current.cmp(&key.election_id) {
            std::cmp::Ordering::Greater => {
                add_unbound_object_to_map_with_update(&self.index, key.election_id, |_| {
                    if let Err(prev) = self.first.fetch_update(
                        atomic::Ordering::Relaxed,
                        atomic::Ordering::Relaxed,
                        |x| {
                            if x > key.election_id {
                                Some(key.election_id)
                            } else {
                                None
                            }
                        },
                    ) {
                        let old = self
                            .index
                            .insert(prev, key.election_id)
                            .ok_or_else(|| error!("validator keys collections was broken!"))?;
                        Ok(Some(*old.val()))
                    } else {
                        Ok(Some(current))
                    }
                })?;
                return Ok(());
            }
            std::cmp::Ordering::Equal => {
                return Ok(());
            }
            std::cmp::Ordering::Less => (),
        }

        loop {
            if let Some(item) = &self.index.get(&current) {
                match item.val().cmp(&key.election_id) {
                    std::cmp::Ordering::Greater => {
                        add_unbound_object_to_map_with_update(&self.index, *item.key(), |_| {
                            self.index.insert(key.election_id, *item.val());
                            Ok(Some(key.election_id))
                        })?;
                        break;
                    }
                    std::cmp::Ordering::Equal => {
                        break;
                    }
                    std::cmp::Ordering::Less => {
                        current = *item.val();
                    }
                }
            } else {
                self.index.insert(current, key.election_id);
                break;
            };
        }

        Ok(())
    }

    fn remove(&self, key: &ValidatorKeysJson) -> Result<bool> {
        let mut current = self.first.load(atomic::Ordering::Relaxed);

        if current == key.election_id {
            if let Some(item) = &self.index.get(&current) {
                self.first.store(*item.val(), atomic::Ordering::Relaxed);
            } else {
                self.first.store(0, atomic::Ordering::Relaxed);
            }
            return Ok(true);
        }

        while let Some(item) = &self.index.get(&current) {
            if item.val() == &key.election_id {
                if let Some(removed_item) = &self.index.get(item.val()) {
                    self.index.insert(*item.key(), *removed_item.val());
                } else {
                    // remove last element
                    self.index.remove(item.key());
                }
                return Ok(true);
            } else {
                current = *item.val();
            }
        }
        Ok(false)
    }

    fn get(&self, id_key: &str) -> Option<ValidatorKeysJson> {
        let mut current = self.first.load(atomic::Ordering::Relaxed);
        loop {
            if let Some(result) = self.get_try(id_key, current) {
                return Some(result);
            }
            match self.index.get(&current) {
                Some(next) => current = *next.val(),
                None => return None,
            }
        }
    }

    fn get_try(&self, id_key: &str, index: i32) -> Option<ValidatorKeysJson> {
        let mut result = None;
        if let Some(key) = self.values.get(&index) {
            if key.val().validator_key_id == id_key {
                result = Some(key.val().clone());
            } else if let Some(adnl_key) = &key.val().validator_adnl_key_id {
                if adnl_key == id_key {
                    result = Some(key.val().clone());
                }
            }
        }
        result
    }

    fn get_validator_adnl_key_ids(&self) -> Vec<String> {
        let mut adnl_ids = Vec::new();
        let mut current = self.first.load(atomic::Ordering::Relaxed);
        loop {
            if let Some(validator_info) = self.values.get(&current) {
                if let Some(adnl_key) = &validator_info.val().validator_adnl_key_id {
                    adnl_ids.push(adnl_key.clone());
                } else {
                    adnl_ids.push(validator_info.val().validator_key_id.clone());
                }
            }
            match self.index.get(&current) {
                Some(next) => current = *next.val(),
                None => return adnl_ids,
            }
        }
    }

    fn get_validator_key_ids(&self) -> Vec<String> {
        let mut key_ids = Vec::new();
        let mut current = self.first.load(atomic::Ordering::Relaxed);
        loop {
            if let Some(validator_info) = self.values.get(&current) {
                key_ids.push(validator_info.val().validator_key_id.clone());
            }
            match self.index.get(&current) {
                Some(next) => current = *next.val(),
                None => return key_ids,
            }
        }
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct JsonRpcServerConfigJson {
    pub address: String,
}
#[derive(Debug)]
pub struct JsonRpcServerConfig {
    pub address: SocketAddr,
}
impl JsonRpcServerConfig {
    /// Construct from JSON config structure
    pub fn from_json_config(json: &JsonRpcServerConfigJson) -> Result<Self> {
        Ok(Self { address: json.address.parse()? })
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct MetricsConfigJson {
    pub address: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub histogram_buckets: HashMap<String, Vec<f64>>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub global_labels: HashMap<String, String>,
}

const DEFAULT_TIME_BUCKETS: &[f64] = &[
    0.000001, 0.0001, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 60.0,
    120.0, 300.0, 600.0, 3600.0,
];

#[derive(Debug)]
pub struct MetricsConfig {
    pub address: SocketAddr,
    pub histogram_buckets: HashMap<String, Vec<f64>>,
    pub global_labels: HashMap<String, String>,
}
impl MetricsConfig {
    pub fn from_json_config(json: &MetricsConfigJson) -> Result<Self> {
        let mut histogram_buckets = json.histogram_buckets.clone();
        if !histogram_buckets.contains_key("seconds") {
            histogram_buckets.insert("seconds".to_string(), DEFAULT_TIME_BUCKETS.to_vec());
        }
        Ok(Self {
            address: json.address.parse()?,
            histogram_buckets,
            global_labels: json.global_labels.clone(),
        })
    }
}

#[cfg(test)]
#[path = "tests/test_config.rs"]
mod tests;
