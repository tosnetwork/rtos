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

use adnl::{
    BroadcastCheckResult, OverlayCertificate, OverlayPrivacyRules, OverlayShortId,
    CERTIFICATE_FLAG_ALLOW_FEC, CERTIFICATE_FLAG_TRUSTED, MAX_FEC_BROADCAST_SIZE,
};
use rtos_api::{
    ton::{
        engine::validator::keyhash::KeyHash, overlay::Certificate as CertificateTl,
        rpc::engine::validator::ImportShardOverlayCertificate,
    },
    IntoBoxed,
};
use rtos_block::{error, fail, Ed25519KeyOption, KeyId, KeyOption, Result, ShardIdent, UInt256};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};

/// Lifetime of a self-issued certificate.
pub const SELF_CERTIFICATE_LIFETIME_SEC: i32 = 3600;
/// How often a node with signing authority re-signs its certificates.
pub const SELF_CERTIFICATE_REFRESH: Duration = Duration::from_secs(30);
/// A pushed certificate must stay valid at least this long after import.
pub const PUSHED_CERTIFICATE_MIN_LIFETIME_SEC: i32 = 60;
const ED25519_SIGNATURE_SIZE: usize = 64;

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
    signer: Option<Arc<dyn KeyOption>>,
    shards: HashMap<ShardIdent, ShardSource>,
}

pub struct ShardOverlayCertificates {
    state: Mutex<State>,
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
                signer: None,
                shards: HashMap::new(),
            }),
        }
    }

    fn state(&self) -> Result<std::sync::MutexGuard<'_, State>> {
        self.state.lock().map_err(|_| error!("Shard overlay certificate state poisoned"))
    }

    /// Current rules; new overlays are created with them.
    pub fn rules(&self) -> Result<OverlayPrivacyRules> {
        Ok(self.state()?.rules.clone())
    }

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
        let State { rules, signer, shards } = &mut *state;
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
        let State { rules, signer: current, shards } = &mut *state;
        *rules = authority_rules(roots);
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
        let State { rules, signer, shards } = &mut *state;
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

    /// Console import: the certificate must be a 64-byte signature allowing
    /// a 16 MiB FEC broadcast by `signed_key` now, from an authorized
    /// issuer. It is attached to whichever local source it names.
    pub fn import_certificate(
        &self,
        shard: &ShardIdent,
        signed_key: &Arc<KeyId>,
        certificate: &CertificateTl,
        now: i32,
    ) -> Result<OverlayInstall> {
        let certificate =
            OverlayCertificate::from_tl(certificate)?.ok_or_else(|| error!("empty certificate"))?;
        if certificate.signature().len() != ED25519_SIGNATURE_SIZE {
            fail!("bad certificate signature size: {}", certificate.signature().len());
        }
        let mut state = self.state()?;
        let State { rules, shards, .. } = &mut *state;
        let source =
            shards.get_mut(shard).ok_or_else(|| error!("No shard overlay for shard {shard}"))?;
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
            fail!("certificate is not valid for this shard overlay");
        }
        if !rules.is_authorized_key(certificate.issuer_hash()) {
            fail!(
                "certificate issuer is not authorized for this shard overlay: {}",
                hex::encode(certificate.issuer_hash())
            );
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

    /// Push import: only from a configured source (or any, when allowed),
    /// only for the full-node ADNL key, with at least a minute left, from a
    /// validator transport root of the applied sets; then the console checks.
    #[allow(clippy::too_many_arguments)]
    pub fn import_pushed_certificate(
        &self,
        shard: &ShardIdent,
        sender: &Arc<KeyId>,
        accept_from: &HashSet<Arc<KeyId>>,
        accept_from_any: bool,
        full_node_key: &Arc<KeyId>,
        signed_key: &Arc<KeyId>,
        certificate: &CertificateTl,
        roots: &[Arc<KeyId>],
        now: i32,
    ) -> Result<OverlayInstall> {
        if !accept_from_any && !accept_from.contains(sender) {
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
        if i64::from(parsed.expire_at())
            < i64::from(now) + i64::from(PUSHED_CERTIFICATE_MIN_LIFETIME_SEC)
        {
            fail!("certificate expires too soon");
        }
        if !roots.iter().any(|root| root.data() == parsed.issuer_hash()) {
            fail!("certificate issuer is not a validator: {}", hex::encode(parsed.issuer_hash()));
        }
        self.import_certificate(shard, signed_key, certificate, now)
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

    /// Console signing for `subject` in `shard`, replying with the version-1
    /// wire form exactly as the peer implementation does.
    pub fn sign_overlay_certificate(
        &self,
        shard: &ShardIdent,
        subject: &Arc<KeyId>,
        expire_at: i32,
        max_size: u32,
    ) -> Result<CertificateTl> {
        let state = self.state()?;
        let signer = state
            .signer
            .as_ref()
            .ok_or_else(|| error!("Node has no key with signing authority"))?;
        let overlay_id = state
            .shards
            .get(shard)
            .and_then(|source| source.overlay_id.as_ref())
            .ok_or_else(|| error!("No shard overlay for shard {shard}"))?;
        OverlayCertificate::sign_for_console(
            signer,
            overlay_id.data(),
            subject.data(),
            expire_at,
            max_size,
        )
    }

    /// Issuer loop step: certificates for every target and shard, as the
    /// messages a pushing issuer sends to each target.
    pub fn issue_shard_overlay_certificates(
        &self,
        targets: &[Arc<KeyId>],
        shards: &[ShardIdent],
        now: i32,
    ) -> Result<Vec<(Arc<KeyId>, ImportShardOverlayCertificate)>> {
        let expire_at = now.saturating_add(SELF_CERTIFICATE_LIFETIME_SEC);
        let mut messages = Vec::new();
        for target in targets {
            for shard in shards {
                let cert = self.sign_overlay_certificate(
                    shard,
                    target,
                    expire_at,
                    MAX_FEC_BROADCAST_SIZE,
                )?;
                messages.push((
                    target.clone(),
                    ImportShardOverlayCertificate {
                        workchain: shard.workchain_id(),
                        shard: shard.shard_prefix_with_tag() as i64,
                        signed_key: KeyHash { key_hash: UInt256::from_slice(target.data()) }
                            .into_boxed(),
                        cert,
                    },
                ));
            }
        }
        Ok(messages)
    }

    #[cfg(test)]
    pub(crate) fn local_key(&self, shard: &ShardIdent) -> Option<Arc<dyn KeyOption>> {
        self.state().ok()?.shards.get(shard).map(|source| source.local_key.clone())
    }

    #[cfg(test)]
    pub(crate) fn local_certificate(&self, shard: &ShardIdent) -> Option<OverlayCertificate> {
        self.state().ok()?.shards.get(shard).and_then(|source| source.local_cert.clone())
    }
}

#[cfg(test)]
#[path = "tests/test_shard_overlay_certificates.rs"]
mod tests;
