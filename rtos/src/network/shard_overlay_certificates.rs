// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Outbound broadcast sources of the public shard overlays.
//!
//! Every shard overlay sends as a per-shard ephemeral Ed25519 key that lives
//! as long as the node, across overlay recreation. A node holding a
//! validator transport root signs a certificate for that key, so its
//! broadcasts are trusted by peers enforcing the shard rules; a node may also
//! import a certificate for its full-node ADNL key and then send as that key.
//! The shard rules authorize the previous, current and next validator
//! transport roots of the applied masterchain state.
//!
//! Operators reach these sources through the control queries that sign and
//! import certificates, and through certificates pushed over ADNL by an
//! issuer started with `--auto-sign`; a receiver accepts pushes only from the
//! senders named by `--accept-certs-from`.

use crate::network::full_node_overlays::FullNodeOverlaysRouter;
use adnl::{
    common::{AdnlPeers, Subscriber},
    BroadcastCheckResult, OverlayCertificate, OverlayPrivacyRules, OverlayShortId,
    CERTIFICATE_FLAG_ALLOW_FEC, CERTIFICATE_FLAG_TRUSTED, MAX_FEC_BROADCAST_SIZE,
};
use rtos_api::{
    deserialize_boxed,
    ton::{
        engine::validator::keyhash::KeyHash, overlay::Certificate as CertificateTl,
        rpc::engine::validator::ImportShardOverlayCertificate,
    },
    Constructor, IntoBoxed,
};
use rtos_block::{
    error, fail, ConfigParamEnum, ConfigParams, Ed25519KeyOption, KeyId, KeyOption, Result,
    ShardHashes, ShardIdent, UInt256, WorkchainDescr, BASE_WORKCHAIN_ID, MASTERCHAIN_ID,
    SHARD_FULL,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, Weak,
    },
    time::Duration,
};

/// Lifetime of a self-issued certificate.
pub const SELF_CERTIFICATE_LIFETIME_SEC: i32 = 3600;
/// How often a node with signing authority re-signs its certificates.
pub const SELF_CERTIFICATE_REFRESH: Duration = Duration::from_secs(30);
/// A pushed certificate must stay valid at least this long after import.
pub const PUSHED_CERTIFICATE_MIN_LIFETIME_SEC: i32 = 60;
/// How often an issuer pushes certificates to its `--auto-sign` targets.
pub const ISSUE_INTERVAL: Duration = Duration::from_secs(60);
/// Lifetime of a pushed certificate.
pub const ISSUED_CERTIFICATE_LIFETIME_SEC: i32 = 3600;
const ED25519_SIGNATURE_SIZE: usize = 64;

/// Generic error code of control replies.
pub const ERROR_CODE_ERROR: i32 = 602;

/// A failed certificate command with the code its control reply carries:
/// 602 for an unknown shard, 0 for every check without a code of its own.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct CertificateCommandError {
    pub code: i32,
    pub message: String,
}

fn command_error(code: i32, message: impl Into<String>) -> rtos_block::Error {
    CertificateCommandError { code, message: message.into() }.into()
}

/// The control-reply code of an error: its own code when it carries one, the
/// errno of an operating-system error, else 0.
pub fn error_code(error: &rtos_block::Error) -> i32 {
    if let Some(error) = error.downcast_ref::<CertificateCommandError>() {
        return error.code;
    }
    for cause in error.chain() {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            if let Some(errno) = io.raw_os_error() {
                return errno;
            }
        }
    }
    0
}

/// A shard as control and push messages name it: the workchain and the
/// tagged shard prefix reinterpreted as a signed 64-bit integer. It is
/// resolved only against registered shards, so any value is accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireShard {
    pub workchain: i32,
    pub shard: i64,
}

impl WireShard {
    fn names(&self, shard: &ShardIdent) -> bool {
        shard.workchain_id() == self.workchain && shard.shard_prefix_with_tag() as i64 == self.shard
    }
}

impl From<&ShardIdent> for WireShard {
    fn from(shard: &ShardIdent) -> Self {
        Self { workchain: shard.workchain_id(), shard: shard.shard_prefix_with_tag() as i64 }
    }
}

impl std::fmt::Display for WireShard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({},{:016x})", self.workchain, self.shard as u64)
    }
}

/// A 32-byte ADNL id in hex, as `--auto-sign` and `--accept-certs-from` take
/// it; the zero id is refused.
pub fn parse_adnl_id_hex(value: &str) -> Result<Arc<KeyId>> {
    let bytes = hex::decode(value).map_err(|e| error!("bad ADNL hex: {e}"))?;
    let bytes: [u8; 32] =
        bytes.try_into().map_err(|_| error!("bad ADNL id size: expected 32 bytes"))?;
    if bytes == [0; 32] {
        fail!("zero ADNL id");
    }
    Ok(KeyId::from_data(bytes))
}

/// Startup policy of certificate pushes. Repeated options accumulate as
/// sets, and accepting from `*` stays in force once given. It is never
/// written to the configuration file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShardOverlayCertificatePolicy {
    auto_sign: Vec<Arc<KeyId>>,
    accept_from: HashSet<Arc<KeyId>>,
    accept_from_any: bool,
}

impl ShardOverlayCertificatePolicy {
    /// One `--auto-sign` value: a target this node pushes certificates to.
    pub fn add_auto_sign(&mut self, value: &str) -> Result<()> {
        let id = parse_adnl_id_hex(value)?;
        if let Err(at) = self.auto_sign.binary_search_by(|known| known.data().cmp(id.data())) {
            self.auto_sign.insert(at, id);
        }
        Ok(())
    }

    /// One `--accept-certs-from` value: a sender id, or `*` for any sender.
    pub fn add_accept_certs_from(&mut self, value: &str) -> Result<()> {
        if value == "*" {
            self.accept_from_any = true;
        } else {
            self.accept_from.insert(parse_adnl_id_hex(value)?);
        }
        Ok(())
    }

    /// Push targets in id order.
    pub fn auto_sign(&self) -> &[Arc<KeyId>] {
        &self.auto_sign
    }

    pub fn accepts_from_any(&self) -> bool {
        self.accept_from_any
    }

    pub fn accepted_senders(&self) -> &HashSet<Arc<KeyId>> {
        &self.accept_from
    }

    /// Whether pushes are received at all.
    pub fn receives(&self) -> bool {
        self.accept_from_any || !self.accept_from.is_empty()
    }

    /// Whether `sender` may deliver a certificate. It says nothing of the
    /// certificate's issuer, which is checked separately.
    pub fn accepts(&self, sender: &Arc<KeyId>) -> bool {
        self.accept_from_any || self.accept_from.contains(sender)
    }
}

/// The shards an issuer signs for: the masterchain; every shard of the
/// state cut to the basechain's monitor split depth, with its ancestors;
/// and every active workchain enabled by `utime` without shards. The
/// basechain depth cuts every workchain, as the reference engine does.
/// Ordered by workchain and then unsigned shard prefix.
pub fn overlay_certificate_shards(
    shards: &ShardHashes,
    config: &ConfigParams,
    utime: u32,
) -> Result<Vec<ShardIdent>> {
    let workchains = match config.config(12)? {
        Some(ConfigParamEnum::ConfigParam12(param)) => Some(param.workchains),
        _ => None,
    };
    let monitor_min_split = match &workchains {
        Some(workchains) => {
            workchains.get(&BASE_WORKCHAIN_ID)?.map(|wc| wc.monitor_min_split()).unwrap_or(0)
        }
        None => 0,
    };
    let mut all: BTreeSet<(i32, u64)> = BTreeSet::new();
    all.insert((MASTERCHAIN_ID, SHARD_FULL));
    let mut present = HashSet::new();
    shards.iterate_shards(|ident, _| {
        present.insert(ident.workchain_id());
        let mut shard = ident;
        while shard.prefix_len() > monitor_min_split {
            shard = shard.merge()?;
        }
        loop {
            all.insert((shard.workchain_id(), shard.shard_prefix_with_tag()));
            if shard.prefix_len() == 0 {
                break;
            }
            shard = shard.merge()?;
        }
        Ok(true)
    })?;
    if let Some(workchains) = workchains {
        workchains.iterate_with_keys(|id: i32, descr: WorkchainDescr| {
            if !present.contains(&id) && descr.active() && descr.enabled_since <= utime {
                all.insert((id, SHARD_FULL));
            }
            Ok(true)
        })?;
    }
    all.into_iter().map(|(wc, shard)| ShardIdent::with_tagged_prefix(wc, shard)).collect()
}

/// One certificate of an issuer scan, or why it could not be signed.
pub struct IssuedCertificate {
    pub target: Arc<KeyId>,
    pub shard: ShardIdent,
    pub message: Result<ImportShardOverlayCertificate>,
}

/// Rules of a shard overlay before any applied validator set is known: all
/// FEC broadcasts are refused, simple ones need the application check.
pub fn startup_rules() -> OverlayPrivacyRules {
    OverlayPrivacyRules::with_max_unauthorized_size(MAX_FEC_BROADCAST_SIZE)
}

/// Rules of a shard overlay for the given validator transport roots.
pub fn authority_rules(roots: &[Arc<KeyId>]) -> OverlayPrivacyRules {
    OverlayPrivacyRules::new(
        MAX_FEC_BROADCAST_SIZE,
        CERTIFICATE_FLAG_ALLOW_FEC,
        roots.iter().map(|root| (*root.data(), MAX_FEC_BROADCAST_SIZE)).collect::<BTreeMap<_, _>>(),
    )
}

/// The certificate signer: the first canonical root this node holds.
pub fn select_signer(
    roots: &[Arc<KeyId>],
    local_transport_ids: &HashSet<Arc<KeyId>>,
) -> Option<Arc<KeyId>> {
    let mut sorted: Vec<_> = roots.to_vec();
    sorted.sort_by(|left, right| left.data().cmp(right.data()));
    sorted.dedup();
    sorted.into_iter().find(|root| local_transport_ids.contains(root))
}

/// What one overlay must hold: its rules and the certificates of its sources.
#[derive(Clone, Debug)]
pub struct OverlayInstall {
    pub overlay_id: Arc<OverlayShortId>,
    // None leaves the overlay's rules unchanged
    pub rules: Option<OverlayPrivacyRules>,
    pub certificates: Vec<(Arc<KeyId>, Option<OverlayCertificate>)>,
}

struct ShardSource {
    overlay_id: Option<Arc<OverlayShortId>>,
    local_key: Arc<dyn KeyOption>,
    local_cert: Option<OverlayCertificate>,
    adnl_key: Option<Arc<KeyId>>,
    adnl_cert: Option<OverlayCertificate>,
}

impl ShardSource {
    fn install(&self, rules: &OverlayPrivacyRules) -> Option<OverlayInstall> {
        let overlay_id = self.overlay_id.clone()?;
        let mut certificates = vec![(self.local_key.id().clone(), self.local_cert.clone())];
        if let Some(adnl_key) = &self.adnl_key {
            if adnl_key != self.local_key.id() {
                certificates.push((adnl_key.clone(), self.adnl_cert.clone()));
            }
        }
        Some(OverlayInstall { overlay_id, rules: Some(rules.clone()), certificates })
    }
}

struct State {
    rules: OverlayPrivacyRules,
    // The validator transport roots the rules were built from.
    roots: Vec<Arc<KeyId>>,
    signer: Option<Arc<dyn KeyOption>>,
    shards: HashMap<ShardIdent, ShardSource>,
}

pub struct ShardOverlayCertificates {
    state: Mutex<State>,
    // Set once the full node serves requests, cleared when it stops.
    serving: AtomicBool,
    issuer_started: AtomicBool,
}

impl Default for ShardOverlayCertificates {
    fn default() -> Self {
        Self::new()
    }
}

impl ShardOverlayCertificates {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                rules: startup_rules(),
                roots: Vec::new(),
                signer: None,
                shards: HashMap::new(),
            }),
            serving: AtomicBool::new(false),
            issuer_started: AtomicBool::new(false),
        }
    }

    fn state(&self) -> Result<std::sync::MutexGuard<'_, State>> {
        self.state.lock().map_err(|_| error!("Shard overlay certificate state poisoned"))
    }

    pub(crate) fn set_serving(&self, serving: bool) {
        self.serving.store(serving, Ordering::Release);
    }

    pub(crate) fn is_serving(&self) -> bool {
        self.serving.load(Ordering::Acquire)
    }

    /// True for the one caller that starts the issuer.
    pub(crate) fn claim_issuer(&self) -> bool {
        !self.issuer_started.swap(true, Ordering::AcqRel)
    }

    pub(crate) fn release_issuer(&self) {
        self.issuer_started.store(false, Ordering::Release);
    }

    /// Current rules; new overlays are created with them.
    pub fn rules(&self) -> Result<OverlayPrivacyRules> {
        Ok(self.state()?.rules.clone())
    }

    #[cfg(test)]
    pub fn signer_id(&self) -> Result<Option<Arc<KeyId>>> {
        Ok(self.state()?.signer.as_ref().map(|signer| signer.id().clone()))
    }

    fn sign_local(
        signer: &Arc<dyn KeyOption>,
        overlay_id: &OverlayShortId,
        source: &ShardSource,
        now: i32,
    ) -> Result<OverlayCertificate> {
        OverlayCertificate::sign(
            signer,
            overlay_id.data(),
            source.local_key.id().data(),
            now.saturating_add(SELF_CERTIFICATE_LIFETIME_SEC),
            MAX_FEC_BROADCAST_SIZE,
            CERTIFICATE_FLAG_TRUSTED | CERTIFICATE_FLAG_ALLOW_FEC,
        )
    }

    /// A (re)created overlay of `shard`: keeps the shard's ephemeral key and
    /// certificates, signing one when a signer exists and none is held.
    pub fn register_overlay(
        &self,
        shard: &ShardIdent,
        overlay_id: &Arc<OverlayShortId>,
        adnl_key: &Arc<KeyId>,
        now: i32,
    ) -> Result<OverlayInstall> {
        let mut state = self.state()?;
        let State { rules, signer, shards, .. } = &mut *state;
        if !shards.contains_key(shard) {
            let local_key = Ed25519KeyOption::<rtos_block::ZeroizingBytes>::generate()?;
            shards.insert(
                shard.clone(),
                ShardSource {
                    overlay_id: None,
                    local_key,
                    local_cert: None,
                    adnl_key: None,
                    adnl_cert: None,
                },
            );
        }
        let source = shards.get_mut(shard).ok_or_else(|| error!("Shard source vanished"))?;
        if source.overlay_id.as_ref() != Some(overlay_id) {
            // A certificate binds one overlay identity.
            source.local_cert = None;
            source.adnl_cert = None;
        }
        source.overlay_id = Some(overlay_id.clone());
        if source.adnl_key.as_ref() != Some(adnl_key) {
            source.adnl_cert = None;
            source.adnl_key = Some(adnl_key.clone());
        }
        if source.local_cert.is_none() {
            if let Some(signer) = signer {
                source.local_cert = Some(Self::sign_local(signer, overlay_id, source, now)?);
            }
        }
        source.install(rules).ok_or_else(|| error!("Shard overlay is not registered"))
    }

    /// Replace the rules by the applied state's authority. A new signer
    /// re-signs every shard certificate; losing the signer keeps the held
    /// certificates until they expire. Empty roots install rules that
    /// authorize nobody: stale authority is never kept.
    pub fn update_authority(
        &self,
        roots: &[Arc<KeyId>],
        signer: Option<Arc<dyn KeyOption>>,
        now: i32,
    ) -> Result<Vec<OverlayInstall>> {
        let mut state = self.state()?;
        let State { rules, roots: current_roots, signer: current, shards } = &mut *state;
        *rules = authority_rules(roots);
        *current_roots = roots.to_vec();
        let resign = match (&signer, current.as_ref()) {
            (Some(new), Some(old)) => new.id() != old.id(),
            (Some(_), None) => true,
            (None, _) => false,
        };
        *current = signer;
        if resign {
            if let Some(signer) = current.as_ref() {
                for source in shards.values_mut() {
                    if let Some(overlay_id) = source.overlay_id.clone() {
                        source.local_cert =
                            Some(Self::sign_local(signer, &overlay_id, source, now)?);
                    }
                }
            }
        }
        Ok(shards.values().filter_map(|source| source.install(rules)).collect())
    }

    /// Periodic re-signing while this node holds signing authority.
    pub fn refresh(&self, now: i32) -> Result<Vec<OverlayInstall>> {
        let mut state = self.state()?;
        let State { rules, signer, shards, .. } = &mut *state;
        let Some(signer) = signer.as_ref() else {
            return Ok(Vec::new());
        };
        let mut installs = Vec::new();
        for source in shards.values_mut() {
            if let Some(overlay_id) = source.overlay_id.clone() {
                source.local_cert = Some(Self::sign_local(signer, &overlay_id, source, now)?);
                installs.extend(source.install(rules));
            }
        }
        Ok(installs)
    }

    /// The key a shard broadcast is sent as: the full-node ADNL key when it
    /// holds a certificate valid for this payload, else the ephemeral key.
    pub fn choose_outbound_source(
        &self,
        shard: &ShardIdent,
        adnl_key: &Arc<dyn KeyOption>,
        size: usize,
        is_fec: bool,
        now: i32,
    ) -> Result<Arc<dyn KeyOption>> {
        let state = self.state()?;
        let source = state
            .shards
            .get(shard)
            .ok_or_else(|| error!("No outbound source for shard {shard}"))?;
        let size = u32::try_from(size).map_err(|_| error!("Broadcast is too large"))?;
        if adnl_key.id() != source.local_key.id() && source.adnl_key.as_ref() == Some(adnl_key.id())
        {
            if let (Some(cert), Some(overlay_id)) = (&source.adnl_cert, &source.overlay_id) {
                let valid =
                    cert.check(adnl_key.id().data(), overlay_id.data(), now, size, is_fec, false)
                        == BroadcastCheckResult::Allowed
                        && state.rules.is_authorized_key(cert.issuer_hash());
                if valid {
                    return Ok(adnl_key.clone());
                }
            }
        }
        Ok(source.local_key.clone())
    }

    fn shard_source(
        shards: &mut HashMap<ShardIdent, ShardSource>,
        shard: WireShard,
    ) -> Result<&mut ShardSource> {
        shards
            .iter_mut()
            .find(|(ident, source)| shard.names(ident) && source.overlay_id.is_some())
            .map(|(_, source)| source)
            .ok_or_else(|| command_error(ERROR_CODE_ERROR, "shard not found"))
    }

    /// Console import, in the reference order: the shard must exist, then
    /// the certificate must be non-empty with a 64-byte signature, allow a
    /// 16 MiB FEC broadcast by `signed_key` at `now`, and come from an
    /// authorized issuer. It is attached to whichever local source it names.
    pub fn import_certificate_wire(
        &self,
        shard: WireShard,
        signed_key: &Arc<KeyId>,
        certificate: &CertificateTl,
        now: i32,
    ) -> Result<OverlayInstall> {
        let mut state = self.state()?;
        let State { rules, shards, .. } = &mut *state;
        let source = Self::shard_source(shards, shard)?;
        let certificate = OverlayCertificate::from_tl(certificate)
            .map_err(|e| command_error(0, format!("Invalid certificate: {e}")))?
            .ok_or_else(|| command_error(0, "empty certificate"))?;
        if certificate.signature().len() != ED25519_SIGNATURE_SIZE {
            return Err(command_error(
                0,
                format!("bad certificate signature size: {}", certificate.signature().len()),
            ));
        }
        let overlay_id =
            source.overlay_id.clone().ok_or_else(|| error!("Shard overlay is not registered"))?;
        let verdict = certificate.check(
            signed_key.data(),
            overlay_id.data(),
            now,
            MAX_FEC_BROADCAST_SIZE,
            true,
            false,
        );
        if verdict != BroadcastCheckResult::Allowed {
            return Err(command_error(0, "certificate is not valid for this shard overlay"));
        }
        if !rules.is_authorized_key(certificate.issuer_hash()) {
            return Err(command_error(
                0,
                format!(
                    "certificate issuer is not authorized for this shard overlay: {}",
                    hex::encode(certificate.issuer_hash())
                ),
            ));
        }
        if signed_key == source.local_key.id() {
            source.local_cert = Some(certificate.clone());
        }
        if source.adnl_key.as_ref() == Some(signed_key) {
            source.adnl_cert = Some(certificate.clone());
        }
        Ok(OverlayInstall {
            overlay_id,
            rules: None,
            certificates: vec![(signed_key.clone(), Some(certificate))],
        })
    }

    #[cfg(test)]
    pub fn import_certificate(
        &self,
        shard: &ShardIdent,
        signed_key: &Arc<KeyId>,
        certificate: &CertificateTl,
        now: i32,
    ) -> Result<OverlayInstall> {
        self.import_certificate_wire(shard.into(), signed_key, certificate, now)
    }

    /// Push import: only from a sender the policy accepts, only for the
    /// full-node ADNL key, with at least a minute left at the fractional
    /// time `now`, from a validator transport root of the applied sets
    /// (also for a sender accepted through `*`); then the console checks at
    /// `now` truncated to whole seconds.
    #[allow(clippy::too_many_arguments)]
    pub fn import_pushed_certificate(
        &self,
        shard: WireShard,
        sender: &Arc<KeyId>,
        policy: &ShardOverlayCertificatePolicy,
        full_node_key: &Arc<KeyId>,
        signed_key: &Arc<KeyId>,
        certificate: &CertificateTl,
        now: f64,
    ) -> Result<OverlayInstall> {
        if !policy.accepts(sender) {
            fail!("certificate source is not configured: {sender}");
        }
        if signed_key != full_node_key {
            fail!("certificate is for unexpected key {signed_key}, expected {full_node_key}");
        }
        let parsed =
            OverlayCertificate::from_tl(certificate)?.ok_or_else(|| error!("empty certificate"))?;
        if parsed.signature().len() != ED25519_SIGNATURE_SIZE {
            fail!("bad certificate signature size: {}", parsed.signature().len());
        }
        if f64::from(parsed.expire_at()) < now + f64::from(PUSHED_CERTIFICATE_MIN_LIFETIME_SEC) {
            fail!("certificate expires too soon");
        }
        let issuer_is_root =
            self.state()?.roots.iter().any(|root| root.data() == parsed.issuer_hash());
        if !issuer_is_root {
            fail!("certificate issuer is not a validator: {}", hex::encode(parsed.issuer_hash()));
        }
        self.import_certificate_wire(shard, signed_key, certificate, now as i32)
    }

    /// The full-node ADNL identity changed: its certificates no longer apply.
    pub fn reset_adnl_source_certificates(&self) -> Result<Vec<OverlayInstall>> {
        let mut state = self.state()?;
        let mut installs = Vec::new();
        for source in state.shards.values_mut() {
            if let (Some(adnl_key), Some(overlay_id)) = (&source.adnl_key, &source.overlay_id) {
                if source.adnl_cert.take().is_some() {
                    installs.push(OverlayInstall {
                        overlay_id: overlay_id.clone(),
                        rules: None,
                        certificates: vec![(adnl_key.clone(), None)],
                    });
                }
            }
        }
        Ok(installs)
    }

    fn sign_with(
        signer: &Arc<dyn KeyOption>,
        overlay_id: &OverlayShortId,
        subject: &Arc<KeyId>,
        expire_at: i32,
        max_size: u32,
    ) -> Result<CertificateTl> {
        OverlayCertificate::sign_for_console(
            signer,
            overlay_id.data(),
            subject.data(),
            expire_at,
            max_size,
        )
        .map_err(|e| command_error(0, format!("failed to create certificate: failed to sign: {e}")))
    }

    /// Console signing for `subject` in `shard`: the shard must exist, then
    /// this node must hold signing authority. The reply is the version-1
    /// wire form exactly as the peer implementation produces it.
    pub fn sign_overlay_certificate_wire(
        &self,
        shard: WireShard,
        subject: &Arc<KeyId>,
        expire_at: i32,
        max_size: u32,
    ) -> Result<CertificateTl> {
        let mut state = self.state()?;
        let signer = state.signer.clone();
        let source = Self::shard_source(&mut state.shards, shard)?;
        let overlay_id =
            source.overlay_id.clone().ok_or_else(|| error!("Shard overlay is not registered"))?;
        let signer =
            signer.ok_or_else(|| command_error(0, "Node has no key with signing authority"))?;
        Self::sign_with(&signer, &overlay_id, subject, expire_at, max_size)
    }

    #[cfg(test)]
    pub fn sign_overlay_certificate(
        &self,
        shard: &ShardIdent,
        subject: &Arc<KeyId>,
        expire_at: i32,
        max_size: u32,
    ) -> Result<CertificateTl> {
        self.sign_overlay_certificate_wire(shard.into(), subject, expire_at, max_size)
    }

    /// One issuer scan: a certificate by `signer` for every target and
    /// shard, each pair failing on its own (a shard without an overlay fails
    /// only its pairs). All share one expiry.
    pub fn issue_shard_overlay_certificates(
        &self,
        signer: &Arc<dyn KeyOption>,
        targets: &[Arc<KeyId>],
        shards: &[ShardIdent],
        expire_at: i32,
    ) -> Result<Vec<IssuedCertificate>> {
        let mut state = self.state()?;
        let mut issued = Vec::new();
        for target in targets {
            for shard in shards {
                let message = Self::shard_source(&mut state.shards, shard.into())
                    .and_then(|source| {
                        source.overlay_id.clone().ok_or_else(|| error!("shard not found"))
                    })
                    .and_then(|overlay_id| {
                        Self::sign_with(
                            signer,
                            &overlay_id,
                            target,
                            expire_at,
                            MAX_FEC_BROADCAST_SIZE,
                        )
                    })
                    .map(|cert| ImportShardOverlayCertificate {
                        workchain: shard.workchain_id(),
                        shard: shard.shard_prefix_with_tag() as i64,
                        signed_key: KeyHash { key_hash: UInt256::from_slice(target.data()) }
                            .into_boxed(),
                        cert,
                    });
                issued.push(IssuedCertificate {
                    target: target.clone(),
                    shard: shard.clone(),
                    message,
                });
            }
        }
        Ok(issued)
    }

    #[cfg(test)]
    pub(crate) fn local_key(&self, shard: &ShardIdent) -> Option<Arc<dyn KeyOption>> {
        self.state().ok()?.shards.get(shard).map(|source| source.local_key.clone())
    }

    #[cfg(test)]
    pub(crate) fn local_certificate(&self, shard: &ShardIdent) -> Option<OverlayCertificate> {
        self.state().ok()?.shards.get(shard).and_then(|source| source.local_cert.clone())
    }

    #[cfg(test)]
    pub(crate) fn adnl_certificate(&self, shard: &ShardIdent) -> Option<OverlayCertificate> {
        self.state().ok()?.shards.get(shard).and_then(|source| source.adnl_cert.clone())
    }
}

/// The ADNL receiver of pushed certificates on the full-node identity, and
/// the route of certificate control queries to the full node. It is created
/// with the network; the full node binds itself once it exists, and every
/// request also checks that the full node is serving.
pub struct ShardCertificateEndpoint {
    policy: ShardOverlayCertificatePolicy,
    full_node_key: Arc<KeyId>,
    router: Mutex<Weak<FullNodeOverlaysRouter>>,
}

/// Wire constructor of a pushed certificate.
pub fn push_constructor() -> u32 {
    ImportShardOverlayCertificate::constructor_const()
}

impl ShardCertificateEndpoint {
    pub fn new(policy: ShardOverlayCertificatePolicy, full_node_key: Arc<KeyId>) -> Self {
        Self { policy, full_node_key, router: Mutex::new(Weak::new()) }
    }

    pub fn policy(&self) -> &ShardOverlayCertificatePolicy {
        &self.policy
    }

    /// Route to `router`. A second live full node on the same network is
    /// refused; a stopped one may be replaced.
    pub(crate) fn bind(&self, router: &Arc<FullNodeOverlaysRouter>) -> Result<()> {
        let mut bound =
            self.router.lock().map_err(|_| error!("Certificate endpoint state poisoned"))?;
        if let Some(current) = bound.upgrade() {
            if !Arc::ptr_eq(&current, router) {
                fail!("Shard certificate endpoint is already bound to another full node");
            }
        }
        *bound = Arc::downgrade(router);
        Ok(())
    }

    /// The bound full node, if it is serving.
    pub(crate) fn serving_router(&self) -> Result<Arc<FullNodeOverlaysRouter>> {
        let router = self
            .router
            .lock()
            .map_err(|_| error!("Certificate endpoint state poisoned"))?
            .upgrade()
            .ok_or_else(|| error!("full node is not started"))?;
        if !router.certificate_service_ready() {
            fail!("full node is not started");
        }
        Ok(router)
    }

    async fn receive(&self, data: &[u8], peers: &AdnlPeers) {
        let sender = peers.other();
        if !self.policy.accepts(sender) {
            log::debug!(
                "shard overlay cert ignored from unconfigured source={sender} dst={}",
                peers.local()
            );
            return;
        }
        let message = match deserialize_boxed(data).and_then(|object| {
            object
                .downcast::<ImportShardOverlayCertificate>()
                .map_err(|object| error!("unexpected object {object:?}"))
        }) {
            Ok(message) => message,
            Err(e) => {
                log::warn!(
                    "shard overlay cert receive failed from={sender} dst={} error={e}",
                    peers.local()
                );
                return;
            }
        };
        let shard = WireShard { workchain: message.workchain, shard: message.shard };
        if matches!(message.cert, CertificateTl::Overlay_EmptyCertificate) {
            log::warn!(
                "shard overlay cert receive ignored empty certificate from={sender} dst={} \
                shard={shard}",
                peers.local()
            );
            return;
        }
        let signed_key = KeyId::from_data(message.signed_key.key_hash().clone().inner());
        let result = self.serving_router().and_then(|router| {
            router.import_pushed_shard_overlay_certificate(
                shard,
                sender,
                &self.policy,
                &signed_key,
                &message.cert,
            )
        });
        match result {
            Ok(()) => log::info!(
                "shard overlay cert imported from={sender} dst={} shard={shard} \
                signed_key={signed_key}",
                peers.local()
            ),
            Err(e) => log::warn!(
                "shard overlay cert import failed from={sender} dst={} shard={shard} \
                signed_key={signed_key} error={e}",
                peers.local()
            ),
        }
    }
}

#[async_trait::async_trait]
impl Subscriber for ShardCertificateEndpoint {
    async fn try_consume_custom(&self, data: &[u8], peers: &AdnlPeers) -> Result<bool> {
        let is_push = data.len() >= 4
            && u32::from_le_bytes([data[0], data[1], data[2], data[3]]) == push_constructor();
        // Unsubscribed, as the reference engine is, when no sender is
        // accepted or the message is not for the full-node identity.
        if !is_push || !self.policy.receives() || peers.local() != &self.full_node_key {
            return Ok(false);
        }
        self.receive(data, peers).await;
        Ok(true)
    }
}

#[cfg(test)]
#[path = "tests/test_shard_overlay_certificates.rs"]
mod tests;
