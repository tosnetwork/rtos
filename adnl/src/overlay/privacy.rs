/*
 * RTOS project additions (2026-10-19): overlay broadcast authorization.
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Overlay broadcast authorization shared by every broadcast protocol:
//! privacy rules, source certificates and the source eligibility verdict,
//! including the per-issuer certificate check limiter and the short
//! signature rejection applied to a peer that relayed a bad signature.

use rtos_api::{
    serialize_boxed,
    ton::{
        overlay::{
            certificate::{Certificate as CertificateV1Tl, CertificateV2 as CertificateV2Tl},
            certificateid::{CertificateId, CertificateIdV2},
            Certificate as CertificateTl,
        },
        PublicKey,
    },
    IntoBoxed,
};
use rtos_block::{error, fail, sha256_digest, KeyId, KeyOption, Result, UInt256};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};

/// Largest payload sent as one simple broadcast; larger payloads use FEC.
pub const MAX_SIMPLE_BROADCAST_SIZE: u32 = 768;
/// Largest payload any public broadcast may carry.
pub const MAX_FEC_BROADCAST_SIZE: u32 = 16 << 20;
/// Certificate and rule flag: FEC broadcasts are permitted.
pub const CERTIFICATE_FLAG_ALLOW_FEC: u32 = 1;
/// Certificate and rule flag: the source needs no application check.
pub const CERTIFICATE_FLAG_TRUSTED: u32 = 2;
/// Broadcast flag: the broadcast identity omits the source.
pub const BROADCAST_FLAG_ANY_SENDER: u32 = 1;
/// Broadcast flag: every FEC part of one broadcast goes to one neighbour set.
pub const BROADCAST_FLAG_FIXED_NEIGHBOURS: u32 = 2;

/// How long a peer that relayed a bad signature is refused.
pub(crate) const SIGNATURE_REJECTION: Duration = Duration::from_secs(5);
const CERTIFICATE_CHECK_WINDOW: Duration = Duration::from_secs(60);
const CERTIFICATE_CHECK_LIMIT: usize = 60;
const CERTIFICATE_CACHE_SIZE: usize = 100;

/// Ordered so that `min`/`max` compose verdicts the way the rules do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BroadcastCheckResult {
    Forbidden = 1,
    NeedCheck = 2,
    Allowed = 3,
}

/// Who may broadcast, and how much, in one overlay.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OverlayPrivacyRules {
    max_unauthorized_size: u32,
    flags: u32,
    authorized_keys: BTreeMap<[u8; 32], u32>,
}

impl OverlayPrivacyRules {
    /// Rules with no authorized key and no flags: unauthorized sources may
    /// send simple broadcasts up to `size` after an application check.
    pub fn with_max_unauthorized_size(size: u32) -> Self {
        Self { max_unauthorized_size: size, flags: 0, authorized_keys: BTreeMap::new() }
    }

    pub fn new(
        max_unauthorized_size: u32,
        flags: u32,
        authorized_keys: BTreeMap<[u8; 32], u32>,
    ) -> Self {
        Self { max_unauthorized_size, flags, authorized_keys }
    }

    pub fn check_rules(
        &self,
        source: &[u8; 32],
        size: u32,
        is_fec: bool,
        is_any_sender: bool,
    ) -> BroadcastCheckResult {
        match self.authorized_keys.get(source) {
            Some(cap) => {
                if *cap >= size {
                    BroadcastCheckResult::Allowed
                } else {
                    BroadcastCheckResult::Forbidden
                }
            }
            None => {
                if is_any_sender
                    || size > self.max_unauthorized_size
                    || (is_fec && (self.flags & CERTIFICATE_FLAG_ALLOW_FEC) == 0)
                {
                    BroadcastCheckResult::Forbidden
                } else if (self.flags & CERTIFICATE_FLAG_TRUSTED) != 0 {
                    BroadcastCheckResult::Allowed
                } else {
                    BroadcastCheckResult::NeedCheck
                }
            }
        }
    }

    pub fn is_authorized_key(&self, key: &[u8; 32]) -> bool {
        self.authorized_keys.contains_key(key)
    }

    pub fn authorized_keys(&self) -> &BTreeMap<[u8; 32], u32> {
        &self.authorized_keys
    }

    pub fn flags(&self) -> u32 {
        self.flags
    }

    pub fn max_broadcast_size(&self) -> u32 {
        self.authorized_keys.values().copied().fold(self.max_unauthorized_size, u32::max)
    }

    pub fn max_unauthorized_size(&self) -> u32 {
        self.max_unauthorized_size
    }
}

/// A broadcast source certificate: `issuer` vouches that `node` may send
/// broadcasts of up to `max_size` bytes in one overlay until `expire_at`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OverlayCertificate {
    issuer: PublicKey,
    issuer_hash: [u8; 32],
    expire_at: i32,
    max_size: u32,
    flags: u32,
    signature: Vec<u8>,
}

impl OverlayCertificate {
    pub fn from_wire(bytes: &[u8]) -> Result<Option<Self>> {
        let tl = crate::adnl::wire::decode(bytes, |s| crate::packet::Refusal(s).into())?;
        Self::from_tl(&tl)
    }

    /// The flags a version-1 certificate implies, and the flags for which the
    /// version-1 preimage and serialization are used.
    pub fn default_flags(max_size: u32) -> u32 {
        (if max_size > MAX_SIMPLE_BROADCAST_SIZE { CERTIFICATE_FLAG_ALLOW_FEC } else { 0 })
            | CERTIFICATE_FLAG_TRUSTED
    }

    pub fn new(
        issuer: PublicKey,
        expire_at: i32,
        max_size: u32,
        flags: u32,
        signature: Vec<u8>,
    ) -> Result<Self> {
        let issuer_hash = sha256_digest(serialize_boxed(&issuer)?);
        Ok(Self { issuer, issuer_hash, expire_at, max_size, flags, signature })
    }

    /// Parse a wire certificate. The empty certificate is `None`; integer
    /// fields are reinterpreted as unsigned exactly as the wire peer does.
    pub fn from_tl(tl: &CertificateTl) -> Result<Option<Self>> {
        match tl {
            CertificateTl::Overlay_EmptyCertificate => Ok(None),
            CertificateTl::Overlay_Certificate(cert) => {
                let max_size = cert.max_size as u32;
                Ok(Some(Self::new(
                    cert.issued_by.clone(),
                    cert.expire_at,
                    max_size,
                    Self::default_flags(max_size),
                    cert.signature.to_vec(),
                )?))
            }
            CertificateTl::Overlay_CertificateV2(cert) => Ok(Some(Self::new(
                cert.issued_by.clone(),
                cert.expire_at,
                cert.max_size as u32,
                cert.flags as u32,
                cert.signature.to_vec(),
            )?)),
        }
    }

    /// Wire form: version 1 exactly when the flags are the default ones.
    pub fn to_tl(&self) -> CertificateTl {
        if self.flags == Self::default_flags(self.max_size) {
            CertificateV1Tl {
                issued_by: self.issuer.clone(),
                expire_at: self.expire_at,
                max_size: self.max_size as i32,
                signature: self.signature.clone(),
            }
            .into_boxed()
        } else {
            CertificateV2Tl {
                issued_by: self.issuer.clone(),
                expire_at: self.expire_at,
                max_size: self.max_size as i32,
                flags: self.flags as i32,
                signature: self.signature.clone(),
            }
            .into_boxed()
        }
    }

    /// Hash of the normalized wire form; the signature cache key.
    pub fn tl_hash(&self) -> Result<[u8; 32]> {
        Ok(sha256_digest(serialize_boxed(&self.to_tl())?))
    }

    /// The signed preimage binding the certificate to an overlay and a node.
    pub fn to_sign(&self, overlay: &[u8; 32], node: &[u8; 32]) -> Result<Vec<u8>> {
        if self.flags == Self::default_flags(self.max_size) {
            serialize_boxed(
                &CertificateId {
                    overlay_id: UInt256::with_array(*overlay),
                    node: UInt256::with_array(*node),
                    expire_at: self.expire_at,
                    max_size: self.max_size as i32,
                }
                .into_boxed(),
            )
        } else {
            serialize_boxed(
                &CertificateIdV2 {
                    overlay_id: UInt256::with_array(*overlay),
                    node: UInt256::with_array(*node),
                    expire_at: self.expire_at,
                    max_size: self.max_size as i32,
                    flags: self.flags as i32,
                }
                .into_boxed(),
            )
        }
    }

    /// Verdict for `node` sending `size` bytes at `unix_time`.
    pub fn check(
        &self,
        node: &[u8; 32],
        overlay: &[u8; 32],
        unix_time: i32,
        size: u32,
        is_fec: bool,
        skip_signature: bool,
    ) -> BroadcastCheckResult {
        if size > self.max_size
            || unix_time > self.expire_at
            || (is_fec && (self.flags & CERTIFICATE_FLAG_ALLOW_FEC) == 0)
        {
            return BroadcastCheckResult::Forbidden;
        }
        if !skip_signature && self.verify_signature(overlay, node).is_err() {
            return BroadcastCheckResult::Forbidden;
        }
        if (self.flags & CERTIFICATE_FLAG_TRUSTED) != 0 {
            BroadcastCheckResult::Allowed
        } else {
            BroadcastCheckResult::NeedCheck
        }
    }

    /// Issue a certificate signed by `issuer`.
    pub fn sign(
        issuer: &Arc<dyn KeyOption>,
        overlay: &[u8; 32],
        subject: &[u8; 32],
        expire_at: i32,
        max_size: u32,
        flags: u32,
    ) -> Result<Self> {
        let mut cert =
            Self::new(PublicKey::try_from(issuer)?, expire_at, max_size, flags, Vec::new())?;
        if &cert.issuer_hash != issuer.id().data() {
            fail!("Certificate issuer identity does not match its signing key");
        }
        cert.signature = issuer.sign(&cert.to_sign(overlay, subject)?)?;
        Ok(cert)
    }

    /// Certificate as the console signing command returns it: flags
    /// `Trusted | AllowFec` select the preimage, but the reply is always the
    /// version-1 wire form. At `max_size <= 768` the preimage is version 2
    /// while the reply implies default flags, so such a reply does not verify
    /// at any receiver; this mirrors the peer implementation unchanged.
    pub fn sign_for_console(
        issuer: &Arc<dyn KeyOption>,
        overlay: &[u8; 32],
        subject: &[u8; 32],
        expire_at: i32,
        max_size: u32,
    ) -> Result<CertificateTl> {
        let cert = Self::sign(
            issuer,
            overlay,
            subject,
            expire_at,
            max_size,
            CERTIFICATE_FLAG_TRUSTED | CERTIFICATE_FLAG_ALLOW_FEC,
        )?;
        Ok(CertificateV1Tl {
            issued_by: cert.issuer,
            expire_at,
            max_size: max_size as i32,
            signature: cert.signature,
        }
        .into_boxed())
    }

    pub fn issuer(&self) -> &PublicKey {
        &self.issuer
    }

    pub fn issuer_hash(&self) -> &[u8; 32] {
        &self.issuer_hash
    }

    pub fn expire_at(&self) -> i32 {
        self.expire_at
    }

    pub fn max_size(&self) -> u32 {
        self.max_size
    }

    pub fn flags(&self) -> u32 {
        self.flags
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    fn verify_signature(&self, overlay: &[u8; 32], node: &[u8; 32]) -> Result<()> {
        crate::wire_keys::NetworkPublicKey::from_wire(&serialize_boxed(&self.issuer)?)?
            .verify(&self.to_sign(overlay, node)?, &self.signature)
    }
}

/// A sliding window admitting at most `limit` events per `duration`.
struct RateLimiterWindow {
    duration: Duration,
    limit: usize,
    entries: VecDeque<Instant>,
}

impl RateLimiterWindow {
    fn new(duration: Duration, limit: usize) -> Self {
        Self { duration, limit, entries: VecDeque::new() }
    }

    fn gc(&mut self, now: Instant) {
        while let Some(oldest) = self.entries.back() {
            if now.saturating_duration_since(*oldest) > self.duration {
                self.entries.pop_back();
            } else {
                break;
            }
        }
    }

    fn check(&mut self, now: Instant) -> bool {
        if self.limit == 0 {
            return false;
        }
        self.gc(now);
        self.entries.len() < self.limit
    }

    fn insert(&mut self, now: Instant) {
        self.gc(now);
        self.entries.push_front(now);
    }
}

/// A recency-ordered set of bounded size; lookups do not refresh recency.
struct LruSet<K: PartialEq> {
    capacity: usize,
    entries: VecDeque<K>,
}

impl<K: PartialEq> LruSet<K> {
    fn new(capacity: usize) -> Self {
        Self { capacity, entries: VecDeque::new() }
    }

    fn contains(&self, key: &K) -> bool {
        self.entries.contains(key)
    }

    fn put(&mut self, key: K) {
        if let Some(position) = self.entries.iter().position(|entry| entry == &key) {
            self.entries.remove(position);
        }
        self.entries.push_front(key);
        while self.entries.len() > self.capacity && self.entries.len() > 1 {
            self.entries.pop_back();
        }
    }
}

struct AuthorizedKeyLimiter {
    certificate_checks: RateLimiterWindow,
    // (overlay, source, certificate hash). A verifier serves one overlay; the
    // overlay is part of the key so a shared verifier cannot reuse a check.
    checked_certificates: LruSet<([u8; 32], [u8; 32], [u8; 32])>,
}

impl AuthorizedKeyLimiter {
    fn new() -> Self {
        Self {
            certificate_checks: RateLimiterWindow::new(
                CERTIFICATE_CHECK_WINDOW,
                CERTIFICATE_CHECK_LIMIT,
            ),
            checked_certificates: LruSet::new(CERTIFICATE_CACHE_SIZE),
        }
    }
}

/// Per-overlay verifier state: the issuer limiters and the peers whose
/// signatures are temporarily refused.
#[derive(Default)]
pub(crate) struct BroadcastVerifier {
    limiters: Mutex<HashMap<[u8; 32], AuthorizedKeyLimiter>>,
    rejected: Mutex<HashMap<Arc<KeyId>, Instant>>,
}

impl BroadcastVerifier {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn check_source_eligible_at(
        &self,
        rules: &OverlayPrivacyRules,
        fixed_member_list: bool,
        overlay: &[u8; 32],
        source: &[u8; 32],
        cert: Option<&OverlayCertificate>,
        size: u32,
        is_fec: bool,
        is_any_sender: bool,
        message_from: Option<&Arc<KeyId>>,
        unix_time: i32,
        now: Instant,
    ) -> BroadcastCheckResult {
        if size == 0 {
            return BroadcastCheckResult::Forbidden;
        }
        let r = rules.check_rules(source, size, is_fec, is_any_sender);
        let Some(cert) = cert else {
            return r;
        };
        if r == BroadcastCheckResult::Allowed || fixed_member_list {
            return r;
        }
        if !rules.is_authorized_key(cert.issuer_hash()) {
            return r;
        }
        let Ok(cert_hash) = cert.tl_hash() else {
            return r;
        };
        let cache_key = (*overlay, *source, cert_hash);
        let mut r2 = cert.check(source, overlay, unix_time, size, is_fec, true);
        if r2 != BroadcastCheckResult::Forbidden {
            let mut limiters = match self.limiters.lock() {
                Ok(limiters) => limiters,
                Err(_) => return r,
            };
            let limiter =
                limiters.entry(*cert.issuer_hash()).or_insert_with(AuthorizedKeyLimiter::new);
            if !limiter.checked_certificates.contains(&cache_key) {
                if !limiter.certificate_checks.check(now) {
                    log::debug!(
                        target: super::TARGET,
                        "Dropping certificate from {}: rate limit exceeded",
                        hex::encode(cert.issuer_hash())
                    );
                    r2 = BroadcastCheckResult::Forbidden;
                } else {
                    let verified = self.check_signature_with_peer_at(message_from, now, || {
                        cert.verify_signature(overlay, source)
                    });
                    match verified {
                        Ok(()) => {
                            limiter.certificate_checks.insert(now);
                            limiter.checked_certificates.put(cache_key);
                        }
                        Err(e) => {
                            log::debug!(
                                target: super::TARGET,
                                "Dropping certificate from {}: {e}",
                                hex::encode(cert.issuer_hash())
                            );
                            r2 = BroadcastCheckResult::Forbidden;
                        }
                    }
                }
            }
        }
        let r2 = r2.min(rules.check_rules(cert.issuer_hash(), size, is_fec, is_any_sender));
        r.max(r2)
    }

    /// Verify a signature relayed by `message_from`. A bad signature refuses
    /// that peer's signatures for a short time; locally checked data
    /// (`message_from = None`) never bans anyone.
    pub(crate) fn check_signature_from_peer(
        &self,
        key: &Arc<dyn KeyOption>,
        message: &[u8],
        signature: &[u8],
        message_from: Option<&Arc<KeyId>>,
    ) -> Result<()> {
        self.check_signature_from_peer_at(key, message, signature, message_from, Instant::now())
    }

    pub(crate) fn check_signature_from_peer_at(
        &self,
        key: &Arc<dyn KeyOption>,
        message: &[u8],
        signature: &[u8],
        message_from: Option<&Arc<KeyId>>,
        now: Instant,
    ) -> Result<()> {
        self.check_signature_with_peer_at(message_from, now, || key.verify(message, signature))
    }

    fn check_signature_with_peer_at(
        &self,
        message_from: Option<&Arc<KeyId>>,
        now: Instant,
        verify: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        if let Some(peer) = message_from {
            if self.is_peer_banned_at(peer, now) {
                fail!("Peer {peer} is temporarily banned");
            }
        }
        let result = verify();
        if result.is_err() {
            if let Some(peer) = message_from {
                let mut rejected =
                    self.rejected.lock().map_err(|_| error!("Signature ban lock poisoned"))?;
                rejected.retain(|_, until| *until > now);
                rejected.insert(peer.clone(), now + SIGNATURE_REJECTION);
                log::warn!(
                    target: super::TARGET,
                    "Ban signatures from peer {peer} for {} s",
                    SIGNATURE_REJECTION.as_secs()
                );
            }
        }
        result
    }

    pub(crate) fn is_peer_banned(&self, peer: &Arc<KeyId>) -> bool {
        self.is_peer_banned_at(peer, Instant::now())
    }

    pub(crate) fn is_peer_banned_at(&self, peer: &Arc<KeyId>, now: Instant) -> bool {
        match self.rejected.lock() {
            Ok(rejected) => rejected.get(peer).is_some_and(|until| *until > now),
            // A poisoned table refuses rather than admits.
            Err(_) => true,
        }
    }

    #[cfg(test)]
    pub(crate) fn clear_rejections_for_test(&self) {
        self.rejected.lock().unwrap().clear();
    }

    /// Drop limiters of issuers the rules no longer authorize.
    pub(crate) fn retain_authorized(&self, rules: &OverlayPrivacyRules) {
        if let Ok(mut limiters) = self.limiters.lock() {
            limiters.retain(|key, _| rules.is_authorized_key(key));
        }
    }
}

/// Application approval for a public-overlay broadcast whose source verdict
/// is `NeedCheck`. `Ok` approves the broadcast; an error refuses it.
#[async_trait::async_trait]
pub trait PublicBroadcastCheck: Send + Sync {
    async fn check_broadcast(&self, source: &Arc<KeyId>, data: &[u8]) -> Result<()>;
}

/// Outstanding application checks per overlay; further checks are refused.
pub(crate) const MAX_PENDING_APPLICATION_CHECKS: usize = 256;

/// Receive policy of a public overlay with explicit privacy rules.
pub(crate) struct PublicBroadcastPolicy {
    rules: RwLock<Arc<OverlayPrivacyRules>>,
    check: RwLock<Option<Arc<dyn PublicBroadcastCheck>>>,
    pending: Arc<tokio::sync::Semaphore>,
}

impl PublicBroadcastPolicy {
    pub(crate) fn new(rules: OverlayPrivacyRules) -> Self {
        Self {
            rules: RwLock::new(Arc::new(rules)),
            check: RwLock::new(None),
            pending: Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_APPLICATION_CHECKS)),
        }
    }

    pub(crate) fn rules(&self) -> Arc<OverlayPrivacyRules> {
        match self.rules.read() {
            Ok(rules) => rules.clone(),
            // A poisoned lock admits nobody: no key is authorized and no
            // unauthorized size is accepted.
            Err(_) => Arc::new(OverlayPrivacyRules::default()),
        }
    }

    pub(crate) fn set_rules(&self, rules: OverlayPrivacyRules) -> Result<()> {
        *self.rules.write().map_err(|_| error!("Overlay privacy rules lock poisoned"))? =
            Arc::new(rules);
        Ok(())
    }

    pub(crate) fn set_check(&self, check: Option<Arc<dyn PublicBroadcastCheck>>) -> Result<()> {
        *self.check.write().map_err(|_| error!("Overlay broadcast check lock poisoned"))? = check;
        Ok(())
    }

    /// Run the application check. A missing check, or one more outstanding
    /// check than the bound, refuses the broadcast.
    pub(crate) async fn check(&self, source: &Arc<KeyId>, data: &[u8]) -> Result<()> {
        let check = self
            .check
            .read()
            .map_err(|_| error!("Overlay broadcast check lock poisoned"))?
            .clone()
            .ok_or_else(|| error!("No application check installed for this overlay"))?;
        let _permit = self
            .pending
            .clone()
            .try_acquire_owned()
            .map_err(|_| error!("Too many outstanding application checks"))?;
        check.check_broadcast(source, data).await
    }

    #[cfg(test)]
    pub(crate) fn outstanding_checks(&self) -> usize {
        MAX_PENDING_APPLICATION_CHECKS - self.pending.available_permits()
    }
}

#[cfg(test)]
#[path = "privacy_tests.rs"]
mod tests;
