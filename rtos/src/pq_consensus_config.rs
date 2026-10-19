// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! The post-quantum consensus key part of the node configuration and the
//! custody the node loads from it at startup.
//!
//! The section is checked as written before it is decoded, so a misspelt or
//! missing window field can never default to a wider window that the next
//! rewrite of the configuration would make permanent. One key that is valid
//! for every election and never expires is stated as `consensus_key_file` with
//! `keys` empty or absent; every other set of keys is stated in `keys` alone
//! with `consensus_key_file` empty. Both at once, or neither, is refused.
//!
//! The validator identity is decoded from base64, as the reference node's
//! configuration decoder reads an int256. Hex and controller-address forms are
//! inputs of the offline operator tool only, never of this configuration.
//!
//! Every refusal here is a startup error: a node whose operator configured
//! consensus keys must not come up quietly as an observer.

use rtos_block::{base64_decode, base64_encode, error, fail, Result, UInt256};
use rtos_pq_consensus::{
    load_consensus_key, plan_key_load, validate_schedule, ConfiguredKey, ConsensusKeyStore,
    KeyWindow, PqConsensusCustody,
};
use serde_json::{Map, Value};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

/// The field of the node configuration that holds the section.
pub const CONFIG_FIELD: &str = "pq_consensus";
/// The node configuration file the engine reads the section from.
pub const NODE_CONFIG_FILE_NAME: &str = "config.json";
/// The largest window bound a configuration can state: it reads back the same
/// as a signed 32-bit TL integer.
pub const MAX_CONSENSUS_KEY_TIME: u32 = 0x7fff_ffff;

const BINDING_TYPE: &str = "engine.validator.pqConsensus";
const KEY_TYPE: &str = "engine.validator.pqConsensusKey";

/// The custody clock: system time in whole seconds, read at each decision
/// point. A clock before the epoch reads as 0.
pub fn pq_custody_now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u32::try_from(elapsed.as_secs()).unwrap_or(u32::MAX))
        .unwrap_or(0)
}

/// The section as configured, after single-key normalization: a single
/// `consensus_key_file` is the one key valid from 0 that never expires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqConsensusConfig {
    pub validator_id: UInt256,
    pub keys: Vec<ConfiguredKey>,
}

fn field<'a>(object: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
    object.get(name)
}

fn only_fields(object: &Map<String, Value>, at: &str, allowed: &[&str]) -> Option<String> {
    object
        .keys()
        .find(|name| !allowed.contains(&name.as_str()))
        .map(|name| format!("{at}.{name} is not a field of the consensus key configuration"))
}

fn type_is(object: &Map<String, Value>, at: &str, expected: &str) -> Option<String> {
    match field(object, "@type") {
        None => None,
        Some(Value::String(name)) if name == expected => None,
        Some(_) => Some(format!("{at} is not a {expected}")),
    }
}

/// The digits a window bound is written with: a JSON number as written, or a
/// decimal string. A number that is not a plain non-negative integer is
/// rendered with a sign, point or exponent and is refused by the digit check.
fn window_digits(value: &Value) -> Option<String> {
    match value {
        Value::Number(number) => Some(number.to_string()),
        Value::String(text) => Some(text.clone()),
        _ => None,
    }
}

fn window(object: &Map<String, Value>, at: &str, name: &str) -> Option<String> {
    let here = format!("{at}.{name}");
    let Some(value) = field(object, name) else {
        return Some(format!(
            "{here} is missing; a consensus key's window is stated, never defaulted"
        ));
    };
    let Some(digits) = window_digits(value) else {
        return Some(format!("{here} is not a number"));
    };
    if parse_window(&digits).is_none() {
        return Some(format!("{here} is not a unix time between 0 and 2147483647"));
    }
    None
}

fn parse_window(digits: &str) -> Option<u32> {
    if digits.is_empty() || digits.len() > 10 || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut parsed: u64 = 0;
    for c in digits.bytes() {
        parsed = parsed.checked_mul(10)?.checked_add(u64::from(c - b'0'))?;
    }
    u32::try_from(parsed).ok().filter(|value| *value <= MAX_CONSENSUS_KEY_TIME)
}

/// Why the section at `at` is refused as written, or nothing. A null or absent
/// section is no section and is not checked here.
pub fn check_pq_consensus_json(section: &Value, at: &str) -> Option<String> {
    let Value::Object(binding) = section else {
        return Some(format!("{at} is not an object"));
    };
    if let Some(refused) =
        only_fields(binding, at, &["@type", "validator_id", "consensus_key_file", "keys"])
    {
        return Some(refused);
    }
    if let Some(refused) = type_is(binding, at, BINDING_TYPE) {
        return Some(refused);
    }
    if field(binding, "validator_id").is_none() {
        return Some(format!("{at}.validator_id is missing"));
    }
    let mut single = false;
    if let Some(file) = field(binding, "consensus_key_file") {
        let Value::String(file) = file else {
            return Some(format!("{at}.consensus_key_file is not a string"));
        };
        single = !file.is_empty();
    }
    let mut listed: usize = 0;
    if let Some(keys) = field(binding, "keys") {
        let Value::Array(keys) = keys else {
            return Some(format!("{at}.keys is not a list"));
        };
        for entry in keys {
            let here = format!("{at}.keys[{listed}]");
            listed = listed.saturating_add(1);
            let Value::Object(key) = entry else {
                return Some(format!("{here} is not an object"));
            };
            if let Some(refused) =
                only_fields(key, &here, &["@type", "consensus_key_file", "valid_from", "expire_at"])
            {
                return Some(refused);
            }
            if let Some(refused) = type_is(key, &here, KEY_TYPE) {
                return Some(refused);
            }
            match field(key, "consensus_key_file") {
                Some(Value::String(file)) if !file.is_empty() => {}
                _ => return Some(format!("{here}.consensus_key_file is missing or empty")),
            }
            if let Some(refused) = window(key, &here, "valid_from") {
                return Some(refused);
            }
            if let Some(refused) = window(key, &here, "expire_at") {
                return Some(refused);
            }
        }
    }
    if single && listed != 0 {
        return Some(format!(
            "{at} states both a single consensus_key_file and keys; several keys are stated in keys alone"
        ));
    }
    if !single && listed == 0 {
        return Some(format!("{at} names no consensus key"));
    }
    None
}

fn decode_validator_id(value: &Value, at: &str) -> std::result::Result<UInt256, String> {
    let Value::String(text) = value else {
        return Err(format!("{at}.validator_id: expected a base64 string"));
    };
    let bytes = base64_decode(text).map_err(|e| format!("{at}.validator_id: {e}"))?;
    let bytes: [u8; 32] =
        bytes.try_into().map_err(|_| format!("{at}.validator_id: wrong length for UInt"))?;
    Ok(UInt256::from(bytes))
}

fn decoded_window(key: &Map<String, Value>, name: &str) -> std::result::Result<u32, String> {
    // Already checked by `check_pq_consensus_json`; decoded again, never defaulted.
    key.get(name)
        .and_then(window_digits)
        .as_deref()
        .and_then(parse_window)
        .ok_or_else(|| format!("{name} is not a unix time between 0 and 2147483647"))
}

impl PqConsensusConfig {
    /// Decode the section at `at`, checked as written first. A null section is
    /// no section.
    pub fn from_json(section: &Value, at: &str) -> std::result::Result<Option<Self>, String> {
        if section.is_null() {
            return Ok(None);
        }
        if let Some(refused) = check_pq_consensus_json(section, at) {
            return Err(refused);
        }
        let Value::Object(binding) = section else {
            return Err(format!("{at} is not an object"));
        };
        let validator_id = decode_validator_id(
            binding.get("validator_id").ok_or_else(|| format!("{at}.validator_id is missing"))?,
            at,
        )?;
        let mut keys = Vec::new();
        if let Some(Value::String(file)) = binding.get("consensus_key_file") {
            if !file.is_empty() {
                keys.push(ConfiguredKey {
                    key_file: PathBuf::from(file),
                    valid_from: 0,
                    expire_at: 0,
                });
            }
        }
        if let Some(Value::Array(listed)) = binding.get("keys") {
            for entry in listed {
                let Value::Object(key) = entry else {
                    return Err(format!("{at}.keys entry is not an object"));
                };
                let Some(Value::String(file)) = key.get("consensus_key_file") else {
                    return Err(format!("{at}.keys entry names no consensus_key_file"));
                };
                keys.push(ConfiguredKey {
                    key_file: PathBuf::from(file),
                    valid_from: decoded_window(key, "valid_from")?,
                    expire_at: decoded_window(key, "expire_at")?,
                });
            }
        }
        Ok(Some(Self { validator_id, keys }))
    }

    /// The section as the reference node writes it back: one key valid for
    /// every election and never expiring as the single `consensus_key_file`,
    /// anything else in `keys` alone with the single file empty, so a reader
    /// that predates `keys` refuses to start rather than take one of several
    /// keys for the whole configuration.
    pub fn to_json(&self) -> Value {
        let mut primary = String::new();
        let mut keys = Vec::new();
        match self.keys.as_slice() {
            [only] if only.valid_from == 0 && only.expire_at == 0 => {
                primary = only.key_file.to_string_lossy().into_owned();
            }
            listed => {
                for key in listed {
                    keys.push(serde_json::json!({
                        "@type": KEY_TYPE,
                        "consensus_key_file": key.key_file.to_string_lossy(),
                        "valid_from": key.valid_from,
                        "expire_at": key.expire_at,
                    }));
                }
            }
        }
        serde_json::json!({
            "@type": BINDING_TYPE,
            "validator_id": base64_encode(self.validator_id.as_slice()),
            "consensus_key_file": primary,
            "keys": keys,
        })
    }
}

impl serde::Serialize for PqConsensusConfig {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        self.to_json().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for PqConsensusConfig {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let section = Value::deserialize(deserializer)?;
        let at = format!("$.{CONFIG_FIELD}");
        match Self::from_json(&section, &at) {
            Ok(Some(config)) => Ok(config),
            Ok(None) => Err(serde::de::Error::custom(format!("{at} is null"))),
            Err(refused) => Err(serde::de::Error::custom(format!(
                "post-quantum consensus configuration refused: {refused}"
            ))),
        }
    }
}

/// Parse the section from the whole node configuration as written. An absent
/// or null section is no section.
pub fn parse_pq_consensus(config_json: &Value) -> Result<Option<PqConsensusConfig>> {
    let Value::Object(root) = config_json else {
        fail!(
            "post-quantum consensus configuration refused: the configuration is not a JSON object"
        )
    };
    let Some(section) = root.get(CONFIG_FIELD) else {
        return Ok(None);
    };
    PqConsensusConfig::from_json(section, &format!("$.{CONFIG_FIELD}"))
        .map_err(|refused| error!("post-quantum consensus configuration refused: {refused}"))
}

/// The custody one node holds, shared by the engine, the validator manager and
/// every group that looks up a signer.
///
/// Linearization points: every read decision (a membership lookup, an
/// observer selection, an exact signer lookup) takes the read lock once, with
/// the clock value its caller read for that decision, so it sees custody
/// either entirely before or entirely after any change. Every change takes the
/// write lock once: an installation is visible to the next read decision, and
/// a removal checks its refusal against the caller's fresh set snapshot and
/// removes in the same critical section, so no lookup can observe a removal
/// that its own check would have refused.
pub struct PqCustodyShared {
    validator_id: UInt256,
    custody: RwLock<PqConsensusCustody>,
}

impl PqCustodyShared {
    pub fn new(validator_id: UInt256, custody: PqConsensusCustody) -> Self {
        Self { validator_id, custody: RwLock::new(custody) }
    }
    /// The validator identity custody was configured for.
    pub fn validator_id(&self) -> &UInt256 {
        &self.validator_id
    }
    /// One read decision over custody.
    pub fn read<R>(&self, decide: impl FnOnce(&PqConsensusCustody) -> R) -> R {
        let custody = self.custody.read().unwrap_or_else(|poisoned| poisoned.into_inner());
        decide(&custody)
    }
    pub fn is_empty(&self) -> bool {
        self.read(PqConsensusCustody::is_empty)
    }
    pub fn usable_key_ids(&self, now: u32) -> Vec<[u8; 32]> {
        self.read(|custody| custody.usable_key_ids(&self.validator_id, now))
    }
    /// Hold another key of the configured validator.
    pub fn install(
        &self,
        store: Arc<ConsensusKeyStore>,
        valid_from: u32,
        expire_at: u32,
    ) -> std::result::Result<(), rtos_pq_consensus::Error> {
        let mut custody = self.custody.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        custody.install(self.validator_id.clone(), store, valid_from, expire_at)
    }
    /// Remove a held key unless custody refuses it against `sets`, the caller's
    /// fresh previous, current and next validator sets, at `now`. The check
    /// and the removal are one change.
    pub fn remove_key_checked(
        &self,
        key_id: &[u8; 32],
        now: u32,
        sets: &[&[rtos_block::ValidatorDescr]],
    ) -> std::result::Result<(), &'static str> {
        let mut custody = self.custody.write().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(refusal) = custody.removal_refusal(&self.validator_id, key_id, now, sets) {
            return Err(refusal);
        }
        if !custody.remove_key(&self.validator_id, key_id) {
            return Err("no such held consensus key");
        }
        Ok(())
    }
}

/// The custody loaded at startup, and the identity each loaded file derived.
/// A key that had expired before startup is not loaded and has no entry.
pub struct LoadedPqConsensus {
    pub config: PqConsensusConfig,
    pub custody: Arc<PqCustodyShared>,
    pub key_ids_by_file: BTreeMap<PathBuf, [u8; 32]>,
}

fn identity_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Load the configured custody in the reference node's startup order: refuse a
/// zero validator, plan the load before reading any seed (warning about each
/// expired key that is not loaded), load every unexpired seed with its window
/// end as its signing deadline, check the schedule over the identities the
/// seeds derive, install every loaded key, then record the windows of the keys
/// that were not loaded. Any refusal is returned with its reason.
pub fn load_pq_consensus_config(config: PqConsensusConfig, now: u32) -> Result<LoadedPqConsensus> {
    if config.validator_id.is_zero() {
        fail!("post-quantum consensus custody names no validator: validator_id is zero")
    }
    let plan = plan_key_load(&config.keys, now)
        .map_err(|e| error!("post-quantum consensus custody refused: {e}"))?;
    for (index, key) in config.keys.iter().enumerate() {
        if !plan.contains(&index) {
            log::warn!(
                "post-quantum consensus key {} expired at {} and is not loaded; remove it from the configuration",
                key.key_file.display(),
                key.expire_at
            );
        }
    }
    let mut loaded = Vec::with_capacity(plan.len());
    let mut schedule = Vec::with_capacity(plan.len());
    let mut key_ids_by_file = BTreeMap::new();
    for &index in &plan {
        let key = config.keys.get(index).ok_or_else(|| {
            error!("post-quantum consensus custody refused: load plan out of range")
        })?;
        let store =
            Arc::new(load_consensus_key(&key.key_file, key.expire_at).map_err(|e| {
                error!("post-quantum consensus key {}: {e}", key.key_file.display())
            })?);
        let key_id = *store.consensus_key().key_id.as_array();
        schedule.push(KeyWindow {
            key_id: Some(key_id),
            valid_from: key.valid_from,
            expire_at: key.expire_at,
        });
        log::warn!(
            "post-quantum consensus custody: validator_id {} key_id {} valid_from {} expire_at {}",
            identity_hex(config.validator_id.as_slice()),
            identity_hex(&key_id),
            key.valid_from,
            key.expire_at
        );
        key_ids_by_file.insert(key.key_file.clone(), key_id);
        loaded.push((store, key.valid_from, key.expire_at));
    }
    validate_schedule(&schedule)
        .map_err(|e| error!("post-quantum consensus custody refused: {e}"))?;
    let mut custody = PqConsensusCustody::default();
    for (store, valid_from, expire_at) in loaded {
        custody
            .install(config.validator_id.clone(), store, valid_from, expire_at)
            .map_err(|e| error!("post-quantum consensus custody refused: {e}"))?;
    }
    for (index, key) in config.keys.iter().enumerate() {
        if !plan.contains(&index) {
            custody
                .record_unloaded(config.validator_id.clone(), key.valid_from, key.expire_at)
                .map_err(|e| error!("post-quantum consensus custody refused: {e}"))?;
        }
    }
    let custody = Arc::new(PqCustodyShared::new(config.validator_id.clone(), custody));
    Ok(LoadedPqConsensus { config, custody, key_ids_by_file })
}

/// Parse and load the custody of the whole node configuration as written, or
/// nothing when no section is configured.
pub fn load_pq_consensus(config_json: &Value, now: u32) -> Result<Option<LoadedPqConsensus>> {
    match parse_pq_consensus(config_json)? {
        Some(config) => load_pq_consensus_config(config, now).map(Some),
        None => Ok(None),
    }
}

/// Read the node configuration file in `configs_dir` as written and load its
/// custody. A configuration without a directory or file has no section.
pub fn load_pq_consensus_from_dir(
    configs_dir: &Path,
    now: u32,
) -> Result<Option<LoadedPqConsensus>> {
    if configs_dir.as_os_str().is_empty() {
        return Ok(None);
    }
    let path = configs_dir.join(NODE_CONFIG_FILE_NAME);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => fail!("cannot read {}: {error}", path.display()),
    };
    let config_json: Value = serde_json::from_slice(&bytes)
        .map_err(|e| error!("cannot parse {}: {e}", path.display()))?;
    load_pq_consensus(&config_json, now)
}

#[cfg(test)]
#[path = "tests/test_pq_consensus_config.rs"]
mod tests;
