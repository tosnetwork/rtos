// RTOS modifications (2026-10-10): owned consumer readiness and authenticated finality recovery.
/*
 * RTOS project additions (2026-10-10): authenticated Plumtree overlay transport.
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

use crate::rldp::{RaptorqDecoder, RaptorqEncoder};
use rtos_api::{
    serialize_boxed,
    ton::{
        fec::type_::RaptorQ,
        overlay::{
            broadcast::{
                BroadcastPlumtreeFec, BroadcastPlumtreeIHave, BroadcastPlumtreePrune,
                BroadcastPlumtreeSimple, BroadcastPlumtreeUseful,
            },
            broadcast_plumtree_fec::{id::Id as FecId, tosign::ToSign as FecToSign},
            broadcast_plumtree_simple::tosign::ToSign as SimpleToSign,
            certificateid::{CertificateId, CertificateIdV2},
            Broadcast, Certificate,
        },
        rpc::overlay::RepairPlumtreePart,
        PublicKey,
    },
    IntoBoxed,
};
use rtos_block::{error, fail, sha256_digest, KeyId, KeyOption, Result, UInt256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Instant,
};

/// Repair replies carry exactly one supported broadcast, without the legacy
/// hop postfix used by other overlay protocols.
pub(crate) fn decode_repair_response(bytes: &[u8]) -> Result<Broadcast> {
    let (object, consumed) = rtos_api::deserialize_boxed_with_suffix(bytes)?;
    if consumed != bytes.len() {
        fail!("Trailing bytes in Plumtree repair response");
    }
    let message =
        object.downcast::<Broadcast>().map_err(|_| error!("Bad Plumtree repair response type"))?;
    if !matches!(
        message,
        Broadcast::Overlay_BroadcastPlumtreeSimple(_)
            | Broadcast::Overlay_BroadcastPlumtreeFec(_)
            | Broadcast::Overlay_BroadcastNotFound
    ) {
        fail!("Unexpected Plumtree repair carrier");
    }
    Ok(message)
}

pub const MAX_PLUMTREE_PAYLOAD: usize = 16 << 20;
const K: usize = 30;
const PARTS: usize = 45;
const LIFETIME: f64 = 20.0;
const MAX_MISSING: usize = 1024;
const MAX_QUERIES: usize = 512;
const MAX_TARGETS: usize = 5;
const MAX_CERT: usize = 256;

/// Explicit transport authority. These keys are classical transport key IDs,
/// never stable consensus identities or PQ signing keys. Installing this policy
/// does not admit Simplex protocol v2 or grant consensus signing authority.
#[derive(Clone, Debug)]
pub struct PlumtreeConfig {
    pub authorized_keys: BTreeMap<[u8; 32], usize>,
    pub max_untrusted_size: usize,
    pub untrusted_flags: u32,
    pub fixed_members: bool,
    pub original_sender: bool,
    pub eager_limit: usize,
    /// A hard local memory admission limit, including retained carrier bytes.
    pub max_retained_bytes: usize,
    pub max_broadcasts: usize,
}

impl PlumtreeConfig {
    pub fn validate(&self) -> Result<()> {
        if self.eager_limit > 4
            || self.max_retained_bytes < MAX_PLUMTREE_PAYLOAD
            || self.max_broadcasts == 0
            || self.max_broadcasts > 1024
            || self.max_untrusted_size > MAX_PLUMTREE_PAYLOAD
            || self.untrusted_flags & !3 != 0
            || self
                .authorized_keys
                .iter()
                .any(|(key, cap)| *key == [0; 32] || *cap == 0 || *cap > MAX_PLUMTREE_PAYLOAD)
        {
            fail!("Invalid Plumtree transport policy");
        }
        Ok(())
    }

    fn directly_allowed(&self, key: &[u8; 32], size: usize, any_sender: bool) -> bool {
        match self.authorized_keys.get(key) {
            Some(cap) => size <= *cap,
            None => !any_sender && size <= self.max_untrusted_size && self.untrusted_flags & 3 == 3,
        }
    }

    fn authorize(
        &self,
        overlay: &[u8; 32],
        key: &Arc<dyn KeyOption>,
        cert: &Certificate,
        size: usize,
        any_sender: bool,
        now: f64,
    ) -> Result<()> {
        if size == 0 || size > MAX_PLUMTREE_PAYLOAD {
            fail!("Invalid Plumtree admission size");
        }
        if self.directly_allowed(key.id().data(), size, any_sender) {
            return Ok(());
        }
        if self.fixed_members {
            fail!("Plumtree source is not authorized");
        }
        let (issuer, expiry, max_size, flags, signature) = match cert {
            Certificate::Overlay_Certificate(c) => (
                &c.issued_by,
                c.expire_at,
                c.max_size,
                2 | if c.max_size > 768 { 1 } else { 0 },
                &c.signature,
            ),
            Certificate::Overlay_CertificateV2(c) => {
                (&c.issued_by, c.expire_at, c.max_size, c.flags as u32, &c.signature)
            }
            Certificate::Overlay_EmptyCertificate => fail!("Missing Plumtree source certificate"),
        };
        let issuer: Arc<dyn KeyOption> = issuer.try_into()?;
        // All Plumtree carriers, including simple, require AllowFec + Trusted.
        if (expiry as f64) < now.floor()
            || max_size <= 0
            || size > max_size as usize
            || flags & 3 != 3
            || !self.authorized_keys.get(issuer.id().data()).is_some_and(|cap| size <= *cap)
        {
            fail!("Ineligible Plumtree source certificate");
        }
        let default_flags = 2 | if max_size > 768 { 1 } else { 0 };
        let preimage = if flags == default_flags {
            serialize_boxed(
                &CertificateId {
                    overlay_id: UInt256::with_array(*overlay),
                    node: UInt256::with_array(*key.id().data()),
                    expire_at: expiry,
                    max_size,
                }
                .into_boxed(),
            )?
        } else {
            serialize_boxed(
                &CertificateIdV2 {
                    overlay_id: UInt256::with_array(*overlay),
                    node: UInt256::with_array(*key.id().data()),
                    expire_at: expiry,
                    max_size,
                    flags: flags as i32,
                }
                .into_boxed(),
            )?
        };
        issuer.verify(&preimage, signature)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct PartKey {
    pub id: [u8; 32],
    pub part: i32,
    pub tree: i32,
}
impl PartKey {
    fn checked(id: &UInt256, part: i32, tree: i32) -> Result<Self> {
        if *id.as_slice() == [0; 32]
            || tree < 0
            || tree > PARTS as i32
            || (tree == 0 && part != 0)
            || (tree != 0 && (part < 0 || part >= PARTS as i32 || tree != part + 1))
        {
            fail!("Invalid Plumtree part/tree identity");
        }
        Ok(Self { id: *id.as_array(), part, tree })
    }
    fn query(&self, now: f64) -> RepairPlumtreePart {
        RepairPlumtreePart {
            broadcast_id: self.id.into(),
            timestamp: now.into(),
            part_index: self.part,
            tree_index: self.tree,
        }
    }
    fn preimage(&self, timestamp: f64, size: usize, hash: [u8; 32]) -> Result<Vec<u8>> {
        if self.tree == 0 {
            serialize_boxed(
                &SimpleToSign {
                    id: self.id.into(),
                    timestamp: timestamp.into(),
                    tree_index: self.tree,
                    data_size: size as i32,
                    data_hash: hash.into(),
                }
                .into_boxed(),
            )
        } else {
            serialize_boxed(
                &FecToSign {
                    id: self.id.into(),
                    timestamp: timestamp.into(),
                    part_index: self.part,
                    tree_index: self.tree,
                    data_size: size as i32,
                    data_hash: hash.into(),
                }
                .into_boxed(),
            )
        }
    }
}

fn check_time(timestamp: f64, now: f64) -> Result<()> {
    if !now.is_finite()
        || !timestamp.is_finite()
        || timestamp < now - LIFETIME
        || timestamp > now + LIFETIME
    {
        fail!("Expired or invalid Plumtree timestamp");
    }
    Ok(())
}
fn fec_id(flags: i32, hash: UInt256, size: i32, part_size: usize) -> Result<UInt256> {
    Ok(sha256_digest(serialize_boxed(
        &FecId { flags, full_data_hash: hash, full_data_size: size, part_size: part_size as i32 }
            .into_boxed(),
    )?)
    .into())
}

#[derive(Clone)]
struct Auth {
    src: PublicKey,
    cert: Certificate,
    timestamp: f64,
    size: usize,
    hash: [u8; 32],
    signature: Vec<u8>,
}
impl Auth {
    fn verify(
        &self,
        key: PartKey,
        policy: &PlumtreeConfig,
        overlay: &[u8; 32],
        admission_size: usize,
        any_sender: bool,
        now: f64,
    ) -> Result<Arc<KeyId>> {
        check_time(self.timestamp, now)?;
        // Bounds precede public-key work and retained allocation.
        if self.signature.len() != 64 || serialize_boxed(&self.cert)?.len() > MAX_CERT {
            fail!("Invalid Plumtree authentication size");
        }
        if !matches!(self.src, PublicKey::Pub_Ed25519(_)) {
            fail!("Plumtree needs a transport Ed25519 key");
        }
        let src: Arc<dyn KeyOption> = (&self.src).try_into()?;
        policy.authorize(overlay, &src, &self.cert, admission_size, any_sender, now)?;
        src.verify(&key.preimage(self.timestamp, self.size, self.hash)?, &self.signature)?;
        Ok(src.id().clone())
    }
    fn ihave(&self, key: PartKey, now: f64) -> Broadcast {
        BroadcastPlumtreeIHave {
            broadcast_id: key.id.into(),
            timestamp: now.into(),
            part_index: key.part,
            tree_index: key.tree,
            src: self.src.clone(),
            certificate: self.cert.clone(),
            payload_timestamp: self.timestamp.into(),
            data_size: self.size as i32,
            data_hash: self.hash.into(),
            signature: self.signature.clone().into(),
        }
        .into_boxed()
    }
}

struct Part {
    auth: Auth,
    wire: Broadcast,
    advertised: BTreeSet<[u8; 32]>,
    sent: BTreeSet<[u8; 32]>,
    full_sends: usize,
}
struct BroadcastState {
    first_seen: Instant,
    source: Arc<KeyId>,
    flags: i32,
    full_hash: Option<[u8; 32]>,
    full_size: usize,
    decoder: Option<RaptorqDecoder>,
    delivered: bool,
    decode_failed: bool,
    bytes: usize,
    parts: BTreeMap<i32, Part>,
}
#[derive(Default)]
struct Slot {
    eager: BTreeMap<[u8; 32], (Instant, usize)>,
    pending: BTreeMap<[u8; 32], Instant>,
}
struct Missing {
    created: Instant,
    due: Instant,
    targets: BTreeMap<[u8; 32], Auth>,
    tried: BTreeSet<[u8; 32]>,
    active: BTreeSet<[u8; 32]>,
}

pub(crate) enum Action {
    Send { peer: [u8; 32], message: Broadcast },
    Query { peer: [u8; 32], key: PartKey, query: RepairPlumtreePart, answer_limit: usize },
    Deliver { source: Arc<KeyId>, data: Vec<u8> },
}

/// Serialized by the owning overlay. No network or consumer callbacks occur
/// under this state lock; actions are executed after releasing it.
pub(crate) struct Engine {
    policy: PlumtreeConfig,
    overlay: [u8; 32],
    states: BTreeMap<[u8; 32], BroadcastState>,
    missing: BTreeMap<PartKey, Missing>,
    slots: Vec<Slot>,
    retained: usize,
    outstanding: BTreeMap<(PartKey, [u8; 32]), usize>,
}
impl Engine {
    pub fn new(policy: PlumtreeConfig, overlay: [u8; 32]) -> Result<Self> {
        policy.validate()?;
        Ok(Self {
            policy,
            overlay,
            states: BTreeMap::new(),
            missing: BTreeMap::new(),
            slots: (0..=PARTS).map(|_| Slot::default()).collect(),
            retained: 0,
            outstanding: BTreeMap::new(),
        })
    }
    pub fn accepts(message: &Broadcast) -> bool {
        matches!(
            message,
            Broadcast::Overlay_BroadcastPlumtreeSimple(_)
                | Broadcast::Overlay_BroadcastPlumtreeFec(_)
                | Broadcast::Overlay_BroadcastPlumtreeIHave(_)
                | Broadcast::Overlay_BroadcastPlumtreePrune(_)
                | Broadcast::Overlay_BroadcastPlumtreeUseful(_)
        )
    }
    fn control(key: PartKey, peer: [u8; 32], now: f64, useful: bool) -> Action {
        let message = if useful {
            BroadcastPlumtreeUseful {
                broadcast_id: key.id.into(),
                timestamp: now.into(),
                part_index: key.part,
                tree_index: key.tree,
            }
            .into_boxed()
        } else {
            BroadcastPlumtreePrune {
                broadcast_id: key.id.into(),
                timestamp: now.into(),
                part_index: key.part,
                tree_index: key.tree,
            }
            .into_boxed()
        };
        Action::Send { peer, message }
    }
    fn gc(&mut self, mono: Instant) {
        self.states.retain(|_, state| {
            if mono.duration_since(state.first_seen).as_secs_f64() > LIFETIME {
                self.retained -= state.bytes;
                false
            } else {
                true
            }
        });
        self.missing.retain(|_, m| {
            !m.active.is_empty() || mono.duration_since(m.created).as_secs_f64() <= LIFETIME
        });
        for slot in &mut self.slots {
            slot.pending.retain(|_, since| mono.duration_since(*since).as_secs() < 5);
            slot.eager.retain(|_, (since, sent)| {
                mono.duration_since(*since).as_secs() <= 30 || *sent <= 50
            });
        }
    }
    fn promote(&mut self, tree: i32, peer: [u8; 32], mono: Instant, force: bool) {
        let slot = &mut self.slots[tree as usize];
        slot.pending.remove(&peer);
        if self.policy.eager_limit == 0 {
            return;
        }
        if !slot.eager.contains_key(&peer) && slot.eager.len() >= self.policy.eager_limit {
            if !force {
                return;
            }
            if let Some(old) = slot.eager.keys().next().copied() {
                slot.eager.remove(&old);
            }
        }
        slot.eager.insert(peer, (mono, 0));
    }
    fn part(&self, key: PartKey) -> Option<&Part> {
        self.states.get(&key.id).and_then(|s| s.parts.get(&key.part)).filter(|p| {
            (p.auth.size > 0)
                && (matches!(p.wire, Broadcast::Overlay_BroadcastPlumtreeSimple(_))
                    == (key.tree == 0))
        })
    }
    fn reserve_send(&mut self, key: PartKey, peer: [u8; 32], mono: Instant) -> Option<Broadcast> {
        let slot = &mut self.slots[key.tree as usize];
        let part = self.states.get_mut(&key.id)?.parts.get_mut(&key.part)?;
        if part.sent.contains(&peer)
            || part.full_sends >= self.policy.eager_limit
            || (!slot.eager.contains_key(&peer)
                && !slot.pending.contains_key(&peer)
                && slot.eager.len() + slot.pending.len() >= self.policy.eager_limit)
        {
            return None;
        }
        part.sent.insert(peer);
        part.full_sends += 1;
        if let Some((_, sent)) = slot.eager.get_mut(&peer) {
            *sent += 1;
        } else {
            slot.pending.insert(peer, mono);
        }
        Some(part.wire.clone())
    }
    fn forward(
        &mut self,
        key: PartKey,
        from: Option<[u8; 32]>,
        neighbours: &[[u8; 32]],
        now: f64,
        mono: Instant,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        let eager: Vec<_> = self.slots[key.tree as usize].eager.keys().copied().collect();
        for peer in eager.into_iter().filter(|p| Some(*p) != from && neighbours.contains(p)) {
            if let Some(message) = self.reserve_send(key, peer, mono) {
                actions.push(Action::Send { peer, message });
            }
        }
        let slot = &self.slots[key.tree as usize];
        let Some(part) = self.states.get_mut(&key.id).and_then(|s| s.parts.get_mut(&key.part))
        else {
            return actions;
        };
        for peer in neighbours.iter().take(5).copied().filter(|p| Some(*p) != from) {
            if slot.eager.contains_key(&peer)
                || part.sent.contains(&peer)
                || part.advertised.contains(&peer)
                || part.full_sends >= self.policy.eager_limit
                || (!slot.pending.contains_key(&peer)
                    && slot.eager.len() + slot.pending.len() >= self.policy.eager_limit)
            {
                continue;
            }
            part.advertised.insert(peer);
            actions.push(Action::Send { peer, message: part.auth.ihave(key, now) });
        }
        actions
    }
    pub fn tick(&mut self, now: f64, mono: Instant) -> Vec<Action> {
        self.gc(mono);
        let mut actions = Vec::new();
        let mut response_budget =
            self.policy.max_retained_bytes.saturating_sub(self.outstanding.values().sum());
        for (key, missing) in &mut self.missing {
            if missing.due > mono || self.outstanding.len() >= MAX_QUERIES {
                continue;
            }
            // One request at a time for each part; completion schedules fallback.
            if !missing.active.is_empty() {
                continue;
            }
            if let Some(peer) = missing
                .targets
                .iter()
                .find(|(p, auth)| {
                    !missing.tried.contains(*p)
                        && auth
                            .verify(*key, &self.policy, &self.overlay, auth.size, false, now)
                            .is_ok()
                })
                .map(|(p, _)| *p)
            {
                missing.tried.insert(peer);
                missing.active.insert(peer);
                let answer_limit = missing.targets[&peer].size + 4096;
                if answer_limit > response_budget {
                    missing.tried.remove(&peer);
                    missing.active.remove(&peer);
                    continue;
                }
                response_budget -= answer_limit;
                self.outstanding.insert((*key, peer), answer_limit);
                actions.push(Action::Query {
                    peer,
                    key: *key,
                    query: key.query(now),
                    answer_limit,
                });
            }
        }
        actions
    }
    pub fn repair_query(
        &mut self,
        peer: [u8; 32],
        query: RepairPlumtreePart,
        now: f64,
        mono: Instant,
    ) -> Result<Broadcast> {
        self.gc(mono);
        check_time(*query.timestamp, now)?;
        let key = PartKey::checked(&query.broadcast_id, query.part_index, query.tree_index)?;
        let part = self.part(key).ok_or_else(|| error!("Unknown Plumtree repair part"))?;
        if peer == [0; 32] || !part.advertised.contains(&peer) || part.sent.contains(&peer) {
            fail!("Unsolicited or repeated Plumtree repair query: part={} tree={} advertised={} sent={}", key.part, key.tree, part.advertised.contains(&peer), part.sent.contains(&peer));
        }
        Ok(self.reserve_send(key, peer, mono).unwrap_or(Broadcast::Overlay_BroadcastNotFound))
    }
    pub fn receive(
        &mut self,
        peer: [u8; 32],
        message: Broadcast,
        expected: Option<PartKey>,
        neighbours: &[[u8; 32]],
        now: f64,
        mono: Instant,
    ) -> Result<Vec<Action>> {
        self.gc(mono);
        if peer == [0; 32] {
            fail!("Missing Plumtree immediate sender");
        }
        if let Some(key) = expected {
            if self.outstanding.remove(&(key, peer)).is_none() {
                fail!("Unsolicited repair response");
            }
            let Some(missing) = self.missing.get_mut(&key) else {
                return Ok(Vec::new());
            };
            if !missing.active.remove(&peer) {
                fail!("Repair response belongs to a removed peer");
            }
            missing.due = mono;
            if matches!(message, Broadcast::Overlay_BroadcastNotFound) {
                return Ok(self.tick(now, mono));
            }
        }
        match message {
            Broadcast::Overlay_BroadcastPlumtreeIHave(m) if expected.is_none() => {
                check_time(*m.timestamp, now)?;
                let key = PartKey::checked(&m.broadcast_id, m.part_index, m.tree_index)?;
                if self.policy.original_sender || self.part(key).is_some() {
                    return Ok(Vec::new());
                }
                let max_size = if key.tree == 0 {
                    MAX_PLUMTREE_PAYLOAD
                } else {
                    MAX_PLUMTREE_PAYLOAD.div_ceil(K)
                };
                if m.data_size <= 0 || m.data_size as usize > max_size {
                    fail!("Invalid Plumtree IHAVE size");
                }
                if let Some(missing) = self.missing.get(&key) {
                    if missing.targets.contains_key(&peer) || missing.targets.len() >= MAX_TARGETS {
                        return Ok(Vec::new());
                    }
                } else if self.missing.len() >= MAX_MISSING {
                    fail!("Plumtree repair queue is full");
                }
                let auth = Auth {
                    src: m.src,
                    cert: m.certificate,
                    timestamp: *m.payload_timestamp,
                    size: m.data_size as usize,
                    hash: *m.data_hash.as_array(),
                    signature: m.signature.to_vec(),
                };
                auth.verify(key, &self.policy, &self.overlay, auth.size, false, now)?;
                let eager_empty = self.slots[key.tree as usize].eager.is_empty();
                let missing = self.missing.entry(key).or_insert_with(|| Missing {
                    created: mono,
                    due: mono + std::time::Duration::from_millis(if eager_empty { 0 } else { 200 }),
                    targets: BTreeMap::new(),
                    tried: BTreeSet::new(),
                    active: BTreeSet::new(),
                });
                missing.targets.insert(peer, auth);
                Ok(self.tick(now, mono))
            }
            Broadcast::Overlay_BroadcastPlumtreePrune(m) if expected.is_none() => {
                check_time(*m.timestamp, now)?;
                let key = PartKey::checked(&m.broadcast_id, m.part_index, m.tree_index)?;
                if self.part(key).is_some_and(|p| p.sent.contains(&peer)) {
                    self.slots[key.tree as usize].eager.remove(&peer);
                    self.slots[key.tree as usize].pending.remove(&peer);
                }
                Ok(Vec::new())
            }
            Broadcast::Overlay_BroadcastPlumtreeUseful(m) if expected.is_none() => {
                check_time(*m.timestamp, now)?;
                let key = PartKey::checked(&m.broadcast_id, m.part_index, m.tree_index)?;
                if self.part(key).is_some_and(|p| p.sent.contains(&peer)) {
                    let pending = self.slots[key.tree as usize].pending.contains_key(&peer);
                    if pending || self.slots[key.tree as usize].eager.contains_key(&peer) {
                        self.promote(key.tree, peer, mono, false);
                    }
                }
                Ok(Vec::new())
            }
            message @ (Broadcast::Overlay_BroadcastPlumtreeSimple(_)
            | Broadcast::Overlay_BroadcastPlumtreeFec(_)) => {
                self.receive_payload(peer, message, expected, neighbours, now, mono)
            }
            _ => fail!("Unexpected Plumtree carrier"),
        }
    }
    pub fn remove_peer(&mut self, peer: [u8; 32]) {
        for slot in &mut self.slots {
            slot.eager.remove(&peer);
            slot.pending.remove(&peer);
        }
        for missing in self.missing.values_mut() {
            missing.targets.remove(&peer);
            missing.active.remove(&peer);
        }
        for state in self.states.values_mut() {
            for part in state.parts.values_mut() {
                part.advertised.remove(&peer);
                part.sent.remove(&peer);
            }
        }
        // Keep outstanding queries charged until their completion/deadline. A
        // removed peer cannot return a valid response through the active set.
    }

    pub fn query_failed(&mut self, key: PartKey, peer: [u8; 32], mono: Instant) {
        self.outstanding.remove(&(key, peer));
        if let Some(missing) = self.missing.get_mut(&key) {
            missing.active.remove(&peer);
            missing.due = mono;
        }
    }
    fn receive_payload(
        &mut self,
        peer: [u8; 32],
        message: Broadcast,
        expected: Option<PartKey>,
        neighbours: &[[u8; 32]],
        now: f64,
        mono: Instant,
    ) -> Result<Vec<Action>> {
        let (key, flags, full_size, full_hash, data, auth) = match &message {
            Broadcast::Overlay_BroadcastPlumtreeSimple(m) => {
                if m.tree_index != 0 {
                    fail!("Simple Plumtree payload must use tree zero");
                }
                let key = PartKey::checked(&m.broadcast_id, 0, m.tree_index)?;
                (
                    key,
                    m.flags,
                    m.data.len(),
                    None,
                    m.data.to_vec(),
                    Auth {
                        src: m.src.clone(),
                        cert: m.certificate.clone(),
                        timestamp: *m.timestamp,
                        size: m.data.len(),
                        hash: sha256_digest(&m.data),
                        signature: m.signature.to_vec(),
                    },
                )
            }
            Broadcast::Overlay_BroadcastPlumtreeFec(m) => {
                if m.full_data_size <= 0
                    || m.full_data_size as usize > MAX_PLUMTREE_PAYLOAD
                    || m.tree_index == 0
                    || m.data.len() != (m.full_data_size as usize).div_ceil(K)
                {
                    fail!("Invalid Plumtree FEC dimensions");
                }
                let id = fec_id(m.flags, m.full_data_hash.clone(), m.full_data_size, m.data.len())?;
                let key = PartKey::checked(&id, m.part_index, m.tree_index)?;
                (
                    key,
                    m.flags,
                    m.full_data_size as usize,
                    Some(*m.full_data_hash.as_array()),
                    m.data.to_vec(),
                    Auth {
                        src: m.src.clone(),
                        cert: m.certificate.clone(),
                        timestamp: *m.timestamp,
                        size: m.data.len(),
                        hash: sha256_digest(&m.data),
                        signature: m.signature.to_vec(),
                    },
                )
            }
            _ => unreachable!(),
        };
        check_time(auth.timestamp, now)?;
        if full_size == 0 || full_size > MAX_PLUMTREE_PAYLOAD {
            fail!("Invalid Plumtree payload size");
        }
        if expected.is_some_and(|expected| expected != key) {
            fail!("Plumtree repair identity mismatch");
        }
        if self.policy.original_sender
            || (expected.is_none() && !self.slots[key.tree as usize].eager.contains_key(&peer))
        {
            self.slots[key.tree as usize].eager.remove(&peer);
            return Ok(vec![Self::control(key, peer, now, false)]);
        }
        if self.part(key).is_some() {
            self.slots[key.tree as usize].eager.remove(&peer);
            return Ok(vec![Self::control(key, peer, now, false)]);
        }
        let source =
            auth.verify(key, &self.policy, &self.overlay, full_size, flags & 1 != 0, now)?;
        let wire_size = serialize_boxed(&message)?.len();
        // Account decoder input/output reservation as well as every retained TL carrier.
        let reserve = wire_size + if self.states.contains_key(&key.id) { 0 } else { full_size * 3 };
        if reserve > self.policy.max_retained_bytes.saturating_sub(self.retained)
            || (!self.states.contains_key(&key.id)
                && self.states.len() >= self.policy.max_broadcasts)
        {
            fail!("Plumtree retained state limit exceeded");
        }
        if let Some(state) = self.states.get(&key.id) {
            if state.flags != flags || state.full_hash != full_hash || state.full_size != full_size
            {
                fail!("Plumtree broadcast commitment collision");
            }
        }
        let decoder = if full_hash.is_some() && !self.states.contains_key(&key.id) {
            Some(RaptorqDecoder::with_params(RaptorQ {
                data_size: full_size as i32,
                symbol_size: auth.size as i32,
                symbols_count: K as i32,
            })?)
        } else {
            None
        };
        let state = self.states.entry(key.id).or_insert_with(|| BroadcastState {
            first_seen: mono,
            source,
            flags,
            full_hash,
            full_size,
            decoder,
            delivered: false,
            decode_failed: false,
            bytes: 0,
            parts: BTreeMap::new(),
        });
        state.bytes += reserve;
        self.retained += reserve;
        state.parts.insert(
            key.part,
            Part {
                auth,
                wire: message,
                advertised: BTreeSet::new(),
                sent: BTreeSet::new(),
                full_sends: 0,
            },
        );
        let delivery = if !state.delivered && !state.decode_failed {
            match state.decoder.as_mut() {
                Some(decoder) => decoder.decode(key.part as u32, &data),
                None => Some(data),
            }
        } else {
            None
        };
        let delivery = if let Some(data) = delivery {
            if data.len() != state.full_size
                || state.full_hash.is_some_and(|hash| hash != sha256_digest(&data))
            {
                state.decode_failed = true;
                None
            } else {
                state.delivered = true;
                Some(Action::Deliver { source: state.source.clone(), data })
            }
        } else {
            None
        };
        self.missing.remove(&key);
        self.promote(key.tree, peer, mono, true);
        let mut actions = vec![Self::control(key, peer, now, true)];
        actions.extend(self.forward(key, Some(peer), neighbours, now, mono));
        if let Some(delivery) = delivery {
            actions.push(delivery);
        }
        Ok(actions)
    }
}

impl Engine {
    pub fn publish(
        &mut self,
        signer: &Arc<dyn KeyOption>,
        certificate: Certificate,
        flags: i32,
        simple_id: Option<[u8; 32]>,
        data: &[u8],
        neighbours: &[[u8; 32]],
        now: f64,
        mono: Instant,
    ) -> Result<Vec<Action>> {
        self.gc(mono);
        check_time(now, now)?;
        if data.is_empty() || data.len() > MAX_PLUMTREE_PAYLOAD {
            fail!("Invalid Plumtree send size");
        }
        self.policy.authorize(
            &self.overlay,
            signer,
            &certificate,
            data.len(),
            flags & 1 != 0,
            now,
        )?;
        if serialize_boxed(&certificate)?.len() > MAX_CERT {
            fail!("Oversized Plumtree certificate");
        }
        let full_hash = sha256_digest(data);
        let id = match simple_id {
            Some(id) => {
                PartKey::checked(&id.into(), 0, 0)?;
                id
            }
            None => *fec_id(flags, full_hash.into(), data.len() as i32, data.len().div_ceil(K))?
                .as_array(),
        };
        if self.states.contains_key(&id) {
            fail!("Plumtree broadcast identity is already retained");
        }
        if self.states.len() >= self.policy.max_broadcasts {
            fail!("Plumtree broadcast limit exceeded");
        }
        // Reserve the worst-case retained carrier and decoder budget before signing.
        let count = if simple_id.is_some() { 1 } else { PARTS };
        let estimate = data.len() * 3
            + count * (data.len().div_ceil(if simple_id.is_some() { 1 } else { K }) + 512);
        if estimate > self.policy.max_retained_bytes.saturating_sub(self.retained) {
            fail!("Plumtree send retention budget exceeded");
        }
        let src: PublicKey = signer.try_into()?;
        if !matches!(src, PublicKey::Pub_Ed25519(_)) {
            fail!("Plumtree sender requires a transport Ed25519 key");
        }
        let mut state = BroadcastState {
            first_seen: mono,
            source: signer.id().clone(),
            flags,
            full_hash: if simple_id.is_some() { None } else { Some(full_hash) },
            full_size: data.len(),
            decoder: None,
            delivered: true,
            decode_failed: false,
            bytes: data.len() * 3,
            parts: BTreeMap::new(),
        };
        let mut encoder = if simple_id.is_none() {
            Some(RaptorqEncoder::with_data(data, Some(data.len().div_ceil(K) as u32)))
        } else {
            None
        };
        for index in 0..count {
            let mut seqno = index as u32;
            let payload = if let Some(encoder) = &mut encoder {
                encoder.encode(&mut seqno)?
            } else {
                data.to_vec()
            };
            // Encoding IDs are part of the signed identity, never inferred from loop position.
            if seqno >= PARTS as u32 || state.parts.contains_key(&(seqno as i32)) {
                fail!("Unexpected Plumtree FEC encoding ID");
            }
            let key = PartKey {
                id,
                part: seqno as i32,
                tree: if simple_id.is_some() { 0 } else { seqno as i32 + 1 },
            };
            let hash = sha256_digest(&payload);
            let signature = signer.sign(&key.preimage(now, payload.len(), hash)?)?;
            let auth = Auth {
                src: src.clone(),
                cert: certificate.clone(),
                timestamp: now.into(),
                size: payload.len(),
                hash,
                signature,
            };
            let wire = if simple_id.is_some() {
                BroadcastPlumtreeSimple {
                    flags,
                    timestamp: now.into(),
                    src: src.clone(),
                    certificate: certificate.clone(),
                    broadcast_id: id.into(),
                    tree_index: 0,
                    data: payload.into(),
                    signature: auth.signature.clone().into(),
                }
                .into_boxed()
            } else {
                BroadcastPlumtreeFec {
                    flags,
                    timestamp: now.into(),
                    src: src.clone(),
                    certificate: certificate.clone(),
                    full_data_hash: full_hash.into(),
                    full_data_size: data.len() as i32,
                    part_index: key.part,
                    tree_index: key.tree,
                    data: payload.into(),
                    signature: auth.signature.clone().into(),
                }
                .into_boxed()
            };
            state.bytes += serialize_boxed(&wire)?.len();
            state.parts.insert(
                key.part,
                Part {
                    auth,
                    wire,
                    advertised: BTreeSet::new(),
                    sent: BTreeSet::new(),
                    full_sends: 0,
                },
            );
        }
        self.retained += state.bytes;
        let keys: Vec<_> = state
            .parts
            .keys()
            .map(|index| PartKey {
                id,
                part: *index,
                tree: if simple_id.is_some() { 0 } else { *index + 1 },
            })
            .collect();
        self.states.insert(id, state);
        let mut actions =
            vec![Action::Deliver { source: signer.id().clone(), data: data.to_vec() }];
        for key in keys {
            actions.extend(self.forward(key, None, neighbours, now, mono));
        }
        Ok(actions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtos_api::deserialize_boxed;
    use rtos_block::{Ed25519KeyOption, ZeroizingBytes};
    use std::collections::VecDeque;

    fn key(seed: u8) -> Arc<dyn KeyOption> {
        Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[seed; 32]).unwrap()
    }
    fn policy(signer: &Arc<dyn KeyOption>) -> PlumtreeConfig {
        PlumtreeConfig {
            authorized_keys: BTreeMap::from([(*signer.id().data(), MAX_PLUMTREE_PAYLOAD)]),
            max_untrusted_size: 0,
            untrusted_flags: 0,
            fixed_members: true,
            original_sender: false,
            eager_limit: 4,
            max_retained_bytes: MAX_PLUMTREE_PAYLOAD * 8,
            max_broadcasts: 16,
        }
    }
    #[test]
    fn repair_response_requires_single_exact_carrier() {
        let bytes = serialize_boxed(&Broadcast::Overlay_BroadcastNotFound).unwrap();
        assert!(matches!(
            decode_repair_response(&bytes).unwrap(),
            Broadcast::Overlay_BroadcastNotFound
        ));
        for suffix in [vec![0], bytes.clone()] {
            let mut appended = bytes.clone();
            appended.extend_from_slice(&suffix);
            assert!(decode_repair_response(&appended).is_err());
        }
        let message = BroadcastPlumtreePrune {
            broadcast_id: [1; 32].into(),
            timestamp: 1.0.into(),
            part_index: 0,
            tree_index: 0,
        }
        .into_boxed();
        assert!(decode_repair_response(&serialize_boxed(&message).unwrap()).is_err());
    }

    #[test]
    fn maximum_envelope_field_accounting() {
        use rtos_api::ton::{
            overlay::certificate::CertificateV2,
            quic::{answer::Answer, request::Message},
        };
        let signer = key(31);
        let src: PublicKey = (&signer).try_into().unwrap();
        let certificate = CertificateV2 {
            issued_by: src.clone(),
            expire_at: i32::MAX,
            max_size: MAX_PLUMTREE_PAYLOAD as i32,
            flags: 3,
            signature: vec![0; 200].into(),
        }
        .into_boxed();
        assert_eq!(serialize_boxed(&src).unwrap().len(), 36);
        assert_eq!(serialize_boxed(&certificate).unwrap().len(), MAX_CERT);
        let simple = BroadcastPlumtreeSimple {
            flags: 0,
            timestamp: 1.0.into(),
            src: src.clone(),
            certificate: certificate.clone(),
            broadcast_id: [1; 32].into(),
            tree_index: 0,
            data: vec![0; MAX_PLUMTREE_PAYLOAD].into(),
            signature: vec![0; 64].into(),
        }
        .into_boxed();
        let simple_bytes = serialize_boxed(&simple).unwrap();
        // Constructor, flags, timestamp, Ed25519 key, certificate, ID,
        // tree, 8-byte large TL length, 64-byte signature with TL framing.
        let simple_overhead = 4 + 4 + 8 + 36 + 256 + 32 + 4 + 8 + 68;
        assert_eq!(simple_bytes.len(), MAX_PLUMTREE_PAYLOAD + simple_overhead);
        let mut with_prefix = vec![0; 160]; // Maximum configured certified overlay prefix.
        with_prefix.extend_from_slice(&simple_bytes);
        let wire = serialize_boxed(&Message { data: with_prefix.into() }.into_boxed()).unwrap();
        assert_eq!(wire.len(), MAX_PLUMTREE_PAYLOAD + 592);
        assert!(wire.len() < rtos_api::MAX_QUIC_ENVELOPE_BYTES);
        let part_size = MAX_PLUMTREE_PAYLOAD.div_ceil(K);
        let fec = BroadcastPlumtreeFec {
            flags: 0,
            timestamp: 1.0.into(),
            src: src.clone(),
            certificate: certificate.clone(),
            full_data_hash: [2; 32].into(),
            full_data_size: MAX_PLUMTREE_PAYLOAD as i32,
            part_index: 44,
            tree_index: 45,
            data: vec![0; part_size].into(),
            signature: vec![0; 64].into(),
        }
        .into_boxed();
        let fec_bytes = serialize_boxed(&fec).unwrap();
        // FEC includes two additional ints; its smaller TL bytes use 4-byte
        // lengths and up to 3 bytes padding. Repair answers have no overlay prefix.
        assert_eq!(part_size, 559241);
        assert_eq!(fec_bytes.len(), part_size + 427);
        let answer = serialize_boxed(&Answer { data: fec_bytes.into() }.into_boxed()).unwrap();
        assert_eq!(answer.len(), 559676);
        assert!(answer.len() <= part_size + 4096);
        let auth = Auth {
            src,
            cert: certificate,
            timestamp: 1.0.into(),
            size: part_size,
            hash: [2; 32],
            signature: vec![0; 64],
        };
        let part = PartKey { id: [1; 32], part: 44, tree: 45 };
        assert_eq!(serialize_boxed(&auth.ihave(part, 1.0)).unwrap().len(), 456);
        assert_eq!(serialize_boxed(&part.query(1.0)).unwrap().len(), 52);
    }

    #[test]
    fn authenticated_repair_batch_budget_is_released_on_completion() {
        let signer = key(32);
        let cfg = policy(&signer);
        let mut receiving = cfg.clone();
        receiving.max_retained_bytes = MAX_PLUMTREE_PAYLOAD;
        let mut receiver = Engine::new(receiving, [9; 32]).unwrap();
        let mono = Instant::now();
        let now = 1700000000.0;
        for id in 1..=16 {
            let mut sender = Engine::new(cfg.clone(), [9; 32]).unwrap();
            let actions = sender
                .publish(
                    &signer,
                    Certificate::Overlay_EmptyCertificate,
                    0,
                    Some([id; 32]),
                    &vec![0; 1 << 20],
                    &[[2; 32]],
                    now,
                    mono,
                )
                .unwrap();
            let ihave = actions
                .into_iter()
                .find_map(|action| match action {
                    Action::Send { message, .. } => Some(message),
                    _ => None,
                })
                .unwrap();
            receiver.receive([1; 32], ihave, None, &[], now, mono).unwrap();
            assert!(receiver.outstanding.values().sum::<usize>() <= MAX_PLUMTREE_PAYLOAD);
        }
        assert_eq!(receiver.missing.len(), 16);
        assert_eq!(receiver.outstanding.len(), 15);
        assert_eq!(receiver.outstanding.values().sum::<usize>(), 15 * ((1 << 20) + 4096));
        let (part, peer) = *receiver.outstanding.keys().next().unwrap();
        receiver.query_failed(part, peer, mono);
        assert_eq!(receiver.outstanding.len(), 14);
        let actions = receiver.tick(now, mono);
        assert_eq!(actions.iter().filter(|a| matches!(a, Action::Query { .. })).count(), 1);
        assert_eq!(receiver.outstanding.len(), 15);
        assert!(receiver.outstanding.values().sum::<usize>() <= MAX_PLUMTREE_PAYLOAD);
    }

    fn roundtrip(message: Broadcast) -> Broadcast {
        deserialize_boxed(&serialize_boxed(&message).unwrap())
            .unwrap()
            .downcast::<Broadcast>()
            .unwrap()
    }
    fn pump(
        engines: &mut [Engine; 2],
        initial: Vec<Action>,
        now: f64,
        mono: Instant,
    ) -> Vec<(usize, Vec<u8>)> {
        let mut work: VecDeque<_> = initial.into_iter().map(|a| (0usize, a)).collect();
        let mut delivered = Vec::new();
        let ids = [[1; 32], [2; 32]];
        let mut steps = 0;
        while let Some((src, action)) = work.pop_front() {
            steps += 1;
            assert!(steps < 1000);
            match action {
                Action::Deliver { data, .. } => delivered.push((src, data)),
                Action::Send { peer, message } => {
                    let dst = ids.iter().position(|id| *id == peer).unwrap();
                    let next = engines[dst]
                        .receive(ids[src], roundtrip(message), None, &[ids[src]], now, mono)
                        .unwrap();
                    work.extend(next.into_iter().map(|a| (dst, a)));
                }
                Action::Query { peer, key, query, .. } => {
                    let dst = ids.iter().position(|id| *id == peer).unwrap();
                    let wire = engines[dst].repair_query(ids[src], query, now, mono).unwrap();
                    let next = engines[src]
                        .receive(ids[dst], roundtrip(wire), Some(key), &[ids[dst]], now, mono)
                        .unwrap();
                    work.extend(next.into_iter().map(|a| (src, a)));
                }
            }
        }
        delivered
    }

    #[test]
    fn simple_and_fec_repair_deliver_exact_bytes() {
        let signer = key(42);
        for size in [1, 29, 30, 31, 23040, 65537] {
            for simple in [true, false] {
                let data: Vec<u8> = (0..size).map(|i| (i * 19) as u8).collect();
                let mut engines = [
                    Engine::new(policy(&signer), [9; 32]).unwrap(),
                    Engine::new(policy(&signer), [9; 32]).unwrap(),
                ];
                let now = 1700000000.25;
                let mono = Instant::now();
                let actions = engines[0]
                    .publish(
                        &signer,
                        Certificate::Overlay_EmptyCertificate,
                        0,
                        simple.then_some([3; 32]),
                        &data,
                        &[[2; 32]],
                        now,
                        mono,
                    )
                    .unwrap();
                assert!(actions.iter().any(|a| matches!(
                    a,
                    Action::Send { message: Broadcast::Overlay_BroadcastPlumtreeIHave(_), .. }
                )));
                let delivered = pump(&mut engines, actions, now, mono);
                assert_eq!(delivered, vec![(0, data.clone()), (1, data)]);
                assert!(engines.iter().all(|engine| engine.outstanding.is_empty()));
            }
        }
    }

    #[test]
    fn ihave_signature_binding_and_repair_origin_fail_closed() {
        let signer = key(42);
        let wrong = key(43);
        let mut sender = Engine::new(policy(&signer), [9; 32]).unwrap();
        let mut receiver = Engine::new(policy(&signer), [9; 32]).unwrap();
        let mono = Instant::now();
        let now = 1700000000.25;
        let actions = sender
            .publish(
                &signer,
                Certificate::Overlay_EmptyCertificate,
                0,
                Some([3; 32]),
                b"exact payload",
                &[[2; 32]],
                now,
                mono,
            )
            .unwrap();
        let ihave = actions
            .into_iter()
            .find_map(|a| match a {
                Action::Send { message: Broadcast::Overlay_BroadcastPlumtreeIHave(m), .. } => {
                    Some(m)
                }
                _ => None,
            })
            .unwrap();
        for mutation in 0..7 {
            let mut bad = ihave.clone();
            match mutation {
                0 => bad.signature[0] ^= 1,
                1 => bad.data_hash = [88; 32].into(),
                2 => bad.broadcast_id = [89; 32].into(),
                3 => bad.payload_timestamp = (now - 21.0).into(),
                4 => bad.timestamp = f64::NAN.into(),
                5 => bad.src = (&wrong).try_into().unwrap(),
                _ => bad.part_index = 1,
            }
            assert!(
                receiver.receive([1; 32], bad.into_boxed(), None, &[], now, mono).is_err(),
                "mutation {mutation}"
            );
            assert!(receiver.missing.is_empty());
            assert!(receiver.outstanding.is_empty());
        }
        let actions =
            receiver.receive([1; 32], ihave.clone().into_boxed(), None, &[], now, mono).unwrap();
        let (part, query) = actions
            .into_iter()
            .find_map(|a| match a {
                Action::Query { key, query, .. } => Some((key, query)),
                _ => None,
            })
            .unwrap();
        let payload = sender.repair_query([2; 32], query, now, mono).unwrap();
        assert!(receiver.receive([77; 32], payload.clone(), Some(part), &[], now, mono).is_err());
        assert_eq!(receiver.outstanding.len(), 1);
        let mut bad = payload.clone();
        if let Broadcast::Overlay_BroadcastPlumtreeSimple(m) = &mut bad {
            m.broadcast_id = [4; 32].into();
            // Keep the substituted response genuinely authenticated, so this
            // probes request identity rather than failing earlier at signature verification.
            let other = PartKey { id: [4; 32], part: 0, tree: 0 };
            m.signature = signer
                .sign(&other.preimage(now, m.data.len(), sha256_digest(&m.data)).unwrap())
                .unwrap()
                .into();
        }
        assert!(receiver.receive([1; 32], bad, Some(part), &[], now, mono).is_err());
        assert!(receiver.states.is_empty());
        assert!(receiver.outstanding.is_empty());
        assert!(receiver.receive([1; 32], payload.clone(), Some(part), &[], now, mono).is_err());
        let actions = receiver.receive([1; 32], payload, None, &[], now, mono).unwrap();
        assert!(matches!(
            &actions[..],
            [Action::Send { message: Broadcast::Overlay_BroadcastPlumtreePrune(_), .. }]
        ));
        assert!(receiver.states.is_empty());
    }

    #[test]
    fn certificate_overlay_expiry_and_trust_are_transport_bound() {
        use rtos_api::ton::overlay::certificate::CertificateV2;
        let issuer = key(42);
        let signer = key(43);
        let now = 1700000000.25;
        let overlay = [9; 32];
        let expiry = now as i32 + 3;
        let max_size = 1000;
        let preimage = serialize_boxed(
            &CertificateId {
                overlay_id: overlay.into(),
                node: (*signer.id().data()).into(),
                expire_at: expiry,
                max_size,
            }
            .into_boxed(),
        )
        .unwrap();
        let cert = CertificateV2 {
            issued_by: (&issuer).try_into().unwrap(),
            expire_at: expiry,
            max_size,
            flags: 3,
            signature: issuer.sign(&preimage).unwrap().into(),
        }
        .into_boxed();
        let mut cfg = policy(&issuer);
        cfg.fixed_members = false;
        cfg.authorize(&overlay, &signer, &cert, 100, false, now).unwrap();
        assert!(cfg.authorize(&[8; 32], &signer, &cert, 100, false, now).is_err());
        assert!(cfg.authorize(&overlay, &signer, &cert, 1001, false, now).is_err());
        assert!(cfg.authorize(&overlay, &signer, &cert, 100, false, now + 4.0).is_err());
        let mut no_trust = cert.clone();
        if let Certificate::Overlay_CertificateV2(c) = &mut no_trust {
            c.flags = 1;
        }
        assert!(cfg.authorize(&overlay, &signer, &no_trust, 100, false, now).is_err());
        cfg.fixed_members = true;
        assert!(cfg.authorize(&overlay, &signer, &cert, 100, false, now).is_err());
    }
}

#[cfg(test)]
mod transport_tests {
    use super::{
        super::{OverlayNode, OverlayParams, OverlayShortId, OverlayUtils},
        *,
    };
    use crate::{
        common::{AdnlPeers, QueryResult, Subscriber},
        node::{AdnlNode, AdnlNodeConfig, IpAddress},
        QuicNode, QuicRateLimitConfig,
    };
    use rtos_api::TLObject;
    use std::{
        net::{SocketAddr, UdpSocket},
        time::Duration,
    };
    use tokio_util::sync::CancellationToken;

    struct ObservedOverlay {
        overlay: Arc<OverlayNode>,
        reports: tokio::sync::mpsc::UnboundedSender<([u8; 32], bool)>,
    }
    #[async_trait::async_trait]
    impl Subscriber for ObservedOverlay {
        async fn try_consume_custom(&self, bytes: &[u8], peers: &AdnlPeers) -> Result<bool> {
            let result = self.overlay.try_consume_custom(bytes, peers).await;
            self.reports.send((sha256_digest(bytes), result.is_ok())).unwrap();
            result
        }
        async fn try_consume_query_bundle(
            &self,
            objects: Vec<TLObject>,
            peers: &AdnlPeers,
        ) -> Result<QueryResult> {
            let result = self.overlay.try_consume_query_bundle(objects, peers).await;
            result
        }
    }
    struct Endpoint {
        overlay: Arc<OverlayNode>,
        key: Arc<dyn KeyOption>,
        quic: Arc<QuicNode>,
        addr: SocketAddr,
        token: CancellationToken,
        reports: tokio::sync::mpsc::UnboundedReceiver<([u8; 32], bool)>,
        subscriptions: std::sync::Mutex<Vec<super::super::BroadcastSubscription>>,
    }
    impl Drop for Endpoint {
        fn drop(&mut self) {
            self.token.cancel();
        }
    }
    async fn endpoint(seed: u8) -> Endpoint {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        drop(socket);
        let (_, cfg) = AdnlNodeConfig::from_ip_address_and_private_keys(
            &addr.to_string(),
            vec![([seed; 32], 0)],
        )
        .unwrap();
        let key = cfg.key_by_tag(0).unwrap().clone();
        let adnl = AdnlNode::with_config(
            cfg,
            #[cfg(feature = "dump")]
            None,
        )
        .await
        .unwrap();
        let overlay = OverlayNode::with_params(adnl, &[55; 32], 0).unwrap();
        let token = CancellationToken::new();
        let (tx, reports) = tokio::sync::mpsc::unbounded_channel();
        let quic = QuicNode::new(
            vec![Arc::new(ObservedOverlay { overlay: overlay.clone(), reports: tx })],
            token.clone(),
            tokio::runtime::Handle::current(),
            Some(QuicRateLimitConfig::disabled()),
        );
        quic.add_key(&[seed; 32], key.id(), addr).unwrap();
        overlay.set_quic(quic.clone()).unwrap();
        Endpoint { overlay, key, quic, addr, token, reports, subscriptions: Default::default() }
    }
    fn config(key: &Arc<dyn KeyOption>) -> PlumtreeConfig {
        PlumtreeConfig {
            authorized_keys: BTreeMap::from([(*key.id().data(), MAX_PLUMTREE_PAYLOAD)]),
            max_untrusted_size: 0,
            untrusted_flags: 0,
            fixed_members: true,
            original_sender: false,
            eager_limit: 4,
            max_retained_bytes: MAX_PLUMTREE_PAYLOAD * 8,
            max_broadcasts: 16,
        }
    }
    async fn consumed(endpoint: &mut Endpoint, bytes: &[u8]) -> bool {
        let hash = sha256_digest(bytes);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let (id, accepted) = endpoint.reports.recv().await.unwrap();
                if hash == id {
                    break accepted;
                }
            }
        })
        .await
        .expect("actual overlay processing report")
    }
    async fn pair() -> (Endpoint, Endpoint, Arc<OverlayShortId>) {
        let a = endpoint(91).await;
        let b = endpoint(92).await;
        let id = OverlayShortId::from_data([93; 32]);
        for (local, remote) in [(&a, &b), (&b, &a)] {
            local.quic.add_peer_key(remote.key.id().clone(), remote.addr).unwrap();
            let ip = IpAddress::from_versioned_string(&remote.addr.to_string(), None).unwrap();
            local.overlay.adnl.add_peer(local.key.id(), &ip, Some(&ip), &remote.key).unwrap();
            local
                .overlay
                .add_private_overlay(
                    OverlayParams::with_id_only(&id),
                    &local.key,
                    &[remote.key.id().clone()],
                    true,
                    None,
                )
                .unwrap();
            assert!(local
                .overlay
                .configure_plumtree(&id, config(&a.key), &tokio::runtime::Handle::current())
                .is_err());
            local
                .subscriptions
                .lock()
                .unwrap()
                .push(local.overlay.subscribe_broadcast(&id).unwrap());
            local
                .overlay
                .configure_plumtree(&id, config(&a.key), &tokio::runtime::Handle::current())
                .unwrap();
            assert_eq!(
                local.overlay.get_overlay(&id, "test").unwrap().plumtree_neighbours().len(),
                1
            );
        }
        (a, b, id)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn owned_consumer_isolated_across_real_overlay_recreation() {
        let (a, b, id) = pair().await;
        let mut old = b.subscriptions.lock().unwrap().pop().unwrap();
        b.overlay.delete_private_overlay(&id).unwrap();
        assert!(old.recv().await.unwrap().is_none());
        b.overlay
            .add_private_overlay(
                OverlayParams::with_id_only(&id),
                &b.key,
                &[a.key.id().clone()],
                true,
                None,
            )
            .unwrap();
        let mut new = b.overlay.subscribe_broadcast(&id).unwrap();
        assert!(b.overlay.subscribe_broadcast(&id).is_err());
        b.overlay
            .configure_plumtree(&id, config(&a.key), &tokio::runtime::Handle::current())
            .unwrap();
        // Dropping an old generation cannot close or unsubscribe the replacement.
        drop(old);
        let send = a.overlay.broadcast_plumtree(
            &id,
            &a.key,
            Certificate::Overlay_EmptyCertificate,
            0,
            Some([109; 32]),
            b"new generation payload",
        );
        let (received, sent) =
            tokio::time::timeout(Duration::from_secs(15), async { tokio::join!(new.recv(), send) })
                .await
                .unwrap();
        sent.unwrap();
        assert_eq!(received.unwrap().unwrap().data, b"new generation payload");
        drop(new);
        assert!(!b
            .overlay
            .get_overlay(&id, "closed consumer")
            .unwrap()
            .received_rawbytes
            .has_subscription());
        assert!(
            b.overlay.subscribe_broadcast(&id).is_err(),
            "closed generation cannot be silently reactivated"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn actual_overlay_quic_simple_fec_and_rejection_boundary() {
        let (a, mut b, id) = pair().await;
        for (simple, data) in [
            (true, b"finality carrier".to_vec()),
            (false, (0..70000).map(|i| (i * 37) as u8).collect()),
        ] {
            let send = a.overlay.broadcast_plumtree(
                &id,
                &a.key,
                Certificate::Overlay_EmptyCertificate,
                0,
                simple.then_some([94; 32]),
                &data,
            );
            let (recv_a, recv_b, sent) = tokio::time::timeout(Duration::from_secs(20), async {
                tokio::join!(biased; a.overlay.wait_for_broadcast(&id), b.overlay.wait_for_broadcast(&id), send)
            }).await.expect("Plumtree QUIC delivery");
            sent.unwrap();
            for delivered in [recv_a, recv_b] {
                let delivered = delivered.unwrap().unwrap();
                assert_eq!(delivered.data, data);
                assert_eq!(delivered.recv_from, *a.key.id());
            }
        }
        // Eager state now exists. A correctly addressed, source-authorized carrier
        // with a damaged signature must reach and fail the real dispatcher.
        let local_overlay = a.overlay.get_overlay(&id, "test").unwrap();
        let mut forged = local_overlay
            .plumtree_engine()
            .unwrap()
            .states
            .get(&[94; 32])
            .unwrap()
            .parts
            .get(&0)
            .unwrap()
            .wire
            .clone();
        if let Broadcast::Overlay_BroadcastPlumtreeSimple(m) = &mut forged {
            m.broadcast_id = [95; 32].into();
            m.signature[0] ^= 1;
        }
        let mut bytes = OverlayUtils::calc_message_prefix(&id).unwrap();
        rtos_api::serialize_boxed_append(&mut bytes, &forged).unwrap();
        let peers = AdnlPeers::with_keys(a.key.id().clone(), b.key.id().clone());
        a.quic.message(bytes.clone(), Some(&a.overlay.adnl), &peers).await.unwrap();
        assert!(!consumed(&mut b, &bytes).await);
        let received_overlay = b.overlay.get_overlay(&id, "test").unwrap();
        assert!(!received_overlay.plumtree_engine().unwrap().states.contains_key(&[95; 32]));
        // Legacy one-byte hop postfixes are not a Plumtree wire extension.
        let mut trailing = OverlayUtils::calc_message_prefix(&id).unwrap();
        let valid =
            local_overlay.plumtree_engine().unwrap().states[&[94; 32]].parts[&0].wire.clone();
        rtos_api::serialize_boxed_append(&mut trailing, &valid).unwrap();
        trailing.push(1);
        a.quic.message(trailing.clone(), Some(&a.overlay.adnl), &peers).await.unwrap();
        assert!(!consumed(&mut b, &trailing).await);
        // An unknown overlay namespace is rejected after actual QUIC receipt.
        let mut wrong_namespace =
            OverlayUtils::calc_message_prefix(&OverlayShortId::from_data([96; 32])).unwrap();
        rtos_api::serialize_boxed_append(&mut wrong_namespace, &forged).unwrap();
        a.quic.message(wrong_namespace.clone(), Some(&a.overlay.adnl), &peers).await.unwrap();
        assert!(!consumed(&mut b, &wrong_namespace).await);
        assert_eq!(received_overlay.plumtree_engine().unwrap().states.len(), 2);
        // V1 node signatures retain their original domain despite V2 flags.
        let signed = local_overlay.get_signed_node(&a.key, false).unwrap();
        if let super::super::OverlayNodeInfo::V1(node) = signed {
            OverlayUtils::verify_node(&id, &node).unwrap();
        } else {
            panic!("V1 expected");
        }
    }
    struct EchoConsumer(std::sync::atomic::AtomicUsize);
    #[async_trait::async_trait]
    impl Subscriber for EchoConsumer {
        async fn try_consume_query(&self, object: TLObject, _: &AdnlPeers) -> Result<QueryResult> {
            use rtos_api::ton::{ton_node::Data, TestObject};
            let object = match object.downcast::<TestObject>() {
                Ok(TestObject::TestVectorBytes(value)) => {
                    self.0.fetch_add(1, std::sync::atomic::Ordering::Release);
                    return QueryResult::consume(
                        rtos_api::ton::adnl::pong::Pong {
                            value: value.value.iter().map(|v| v.len() as i64).sum(),
                        },
                        #[cfg(feature = "telemetry")]
                        None,
                    );
                }
                Ok(_) => fail!("Unsupported fixture object"),
                Err(object) => object,
            };
            match object.downcast::<Data>() {
                Ok(value) => {
                    self.0.fetch_add(1, std::sync::atomic::Ordering::Release);
                    QueryResult::consume_boxed(
                        value,
                        #[cfg(feature = "telemetry")]
                        None,
                    )
                }
                Err(object) => Ok(QueryResult::Rejected(object)),
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn public_overlay_role_advertisements_and_real_delivery() {
        use super::super::{Nodes, OverlayNodeInfo};
        let a = endpoint(101).await;
        let b = endpoint(102).await;
        let id = OverlayShortId::from_data([103; 32]);
        for endpoint in [&a, &b] {
            endpoint.overlay.add_local_workchain_overlay(OverlayParams::with_id_only(&id)).unwrap();
            let overlay = endpoint.overlay.get_overlay(&id, "public fixture").unwrap();
            assert!(!overlay.use_v2_peer_advertisements());
            let OverlayNodeInfo::V2(disabled) =
                endpoint.overlay.get_signed_node(&id, true).unwrap()
            else {
                unreachable!()
            };
            assert_eq!(disabled.flags, 2);
            OverlayUtils::verify_node(&id, &disabled).unwrap();
            let mut cfg = config(&a.key);
            cfg.fixed_members = false;
            cfg.original_sender = endpoint.key.id() == a.key.id();
            endpoint
                .subscriptions
                .lock()
                .unwrap()
                .push(endpoint.overlay.subscribe_broadcast(&id).unwrap());
            endpoint
                .overlay
                .configure_plumtree(&id, cfg, &tokio::runtime::Handle::current())
                .unwrap();
            assert!(overlay.use_v2_peer_advertisements());
            assert!(matches!(
                overlay
                    .prepare_random_peers(&endpoint.key, overlay.use_v2_peer_advertisements())
                    .unwrap(),
                Nodes::V2(_)
            ));
        }
        for (local, remote) in [(&a, &b), (&b, &a)] {
            local.quic.add_peer_key(remote.key.id().clone(), remote.addr).unwrap();
            let ip = IpAddress::from_versioned_string(&remote.addr.to_string(), None).unwrap();
            let node = remote.overlay.get_signed_node(&id, true).unwrap();
            let OverlayNodeInfo::V2(n) = &node else { unreachable!() };
            assert_eq!(n.flags, if remote.key.id() == a.key.id() { 2 } else { 0 });
            assert!(local.overlay.add_public_peer(&ip, &node, &id).unwrap().is_some());
        }
        let sender = a.overlay.get_overlay(&id, "sender").unwrap();
        let receiver = b.overlay.get_overlay(&id, "receiver").unwrap();
        assert_eq!(sender.plumtree_neighbours(), vec![*b.key.id().data()]);
        assert!(receiver.plumtree_neighbours().is_empty(), "original source is not a relay target");
        let send = a.overlay.broadcast_plumtree(
            &id,
            &a.key,
            Certificate::Overlay_EmptyCertificate,
            0,
            Some([104; 32]),
            b"public role-bound transport",
        );
        let (left, right, sent) = tokio::time::timeout(Duration::from_secs(15), async {
            tokio::join!(biased; a.overlay.wait_for_broadcast(&id), b.overlay.wait_for_broadcast(&id), send)
        }).await.unwrap();
        sent.unwrap();
        assert_eq!(left.unwrap().unwrap().data, b"public role-bound transport");
        assert_eq!(right.unwrap().unwrap().data, b"public role-bound transport");
        let OverlayNodeInfo::V2(mut node) = b.overlay.get_signed_node(&id, true).unwrap() else {
            unreachable!()
        };
        let ip = IpAddress::from_versioned_string(&b.addr.to_string(), None).unwrap();
        for flags in [1, 2, 4, 0] {
            node.version += 1;
            node.flags = flags;
            let signed = OverlayUtils::get_node_to_sign(&b.key, &node.overlay, flags, node.version);
            node.signature = b.key.sign(&serialize_boxed(&signed).unwrap()).unwrap().into();
            let info: OverlayNodeInfo<super::super::NodeV1, super::super::NodeV2> =
                OverlayNodeInfo::V2(node.clone());
            a.overlay.add_public_peer(&ip, &info, &id).unwrap().unwrap();
            assert_eq!(sender.plumtree_neighbours().len(), usize::from(flags == 0));
        }
        a.overlay.delete_public_peer(b.key.id(), &id).unwrap();
        assert!(sender.plumtree_neighbours().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn actual_maximum_payload_and_wire_and_answer_limits() {
        use rtos_api::{
            deserialize_boxed, serialize_boxed_append,
            ton::{
                overlay::certificate::CertificateV2, quic::request::Query as QuicQuery,
                testobject::TestVectorBytes,
            },
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (a, b, id) = pair().await;
        // Directly authorized origins may attach an ignored certificate. This
        // is exactly the maximum retained certificate size (256 bytes).
        let certificate = CertificateV2 {
            issued_by: (&a.key).try_into().unwrap(),
            expire_at: i32::MAX,
            max_size: MAX_PLUMTREE_PAYLOAD as i32,
            flags: 3,
            signature: vec![0; 200].into(),
        }
        .into_boxed();
        assert_eq!(serialize_boxed(&certificate).unwrap().len(), 256);
        let data = vec![17; MAX_PLUMTREE_PAYLOAD];
        let send = a.overlay.broadcast_plumtree(&id, &a.key, certificate, 0, Some([97; 32]), &data);
        let (left, right, sent) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(biased; a.overlay.wait_for_broadcast(&id), b.overlay.wait_for_broadcast(&id), send)
        }).await.expect("maximum lawful payload traverses real QUIC repair");
        sent.unwrap();
        assert_eq!(left.unwrap().unwrap().data, data);
        assert_eq!(right.unwrap().unwrap().data, data);
        let over = vec![0; MAX_PLUMTREE_PAYLOAD + 1];
        assert!(a
            .overlay
            .broadcast_plumtree(
                &id,
                &a.key,
                Certificate::Overlay_EmptyCertificate,
                0,
                Some([98; 32]),
                &over
            )
            .await
            .is_err());

        let consumer = Arc::new(EchoConsumer(AtomicUsize::new(0)));
        b.overlay.add_consumer(&id, consumer.clone()).unwrap();
        let peers = AdnlPeers::with_keys(a.key.id().clone(), b.key.id().clone());
        let prefix = b.overlay.get_overlay(&id, "fixture").unwrap().query_prefix.clone();
        let request = |last: usize| {
            let mut bytes = prefix.clone();
            serialize_boxed_append(
                &mut bytes,
                &TestVectorBytes {
                    value: vec![vec![0; 8 << 20], vec![1; 8 << 20], vec![2; last]].into(),
                }
                .into_boxed(),
            )
            .unwrap();
            bytes
        };
        let base =
            serialize_boxed(&QuicQuery { data: request(0).into() }.into_boxed()).unwrap().len();
        let extra = rtos_api::MAX_QUIC_ENVELOPE_BYTES - base;
        let bytes = request(extra);
        let wire = serialize_boxed(&QuicQuery { data: bytes.clone().into() }.into_boxed()).unwrap();
        assert_eq!(wire.len(), rtos_api::MAX_QUIC_ENVELOPE_BYTES);
        assert!(deserialize_boxed(&wire).is_err(), "ordinary TL field budget stays at 16 MiB");
        assert!(rtos_api::deserialize_quic_envelope(&wire).is_ok());
        assert!(a
            .quic
            .query(bytes, Some(&a.overlay.adnl), &peers, Some(5000))
            .await
            .unwrap()
            .is_some());
        let processed = consumer.0.load(Ordering::Acquire);
        assert_eq!(processed, 1);
        let oversized = request(extra + 4);
        let wire =
            serialize_boxed(&QuicQuery { data: oversized.clone().into() }.into_boxed()).unwrap();
        assert_eq!(wire.len(), rtos_api::MAX_QUIC_ENVELOPE_BYTES + 4);
        assert!(rtos_api::deserialize_quic_envelope(&wire).is_err());
        let rejected = tokio::time::timeout(
            Duration::from_secs(15),
            a.quic.query(oversized, Some(&a.overlay.adnl), &peers, Some(5000)),
        )
        .await
        .unwrap();
        assert!(!matches!(rejected, Ok(Some(_))), "oversized request must have no answer");
        assert_eq!(consumer.0.load(Ordering::Acquire), processed);

        let mut echo = prefix;
        serialize_boxed_append(
            &mut echo,
            &rtos_api::ton::ton_node::data::Data { data: vec![3; 8192].into() }.into_boxed(),
        )
        .unwrap();
        assert!(a
            .quic
            .query_with_answer_limit(echo.clone(), Some(&a.overlay.adnl), &peers, Some(5000), 12288)
            .await
            .unwrap()
            .is_some());
        assert!(a
            .quic
            .query_with_answer_limit(echo, Some(&a.overlay.adnl), &peers, Some(5000), 1024)
            .await
            .is_err());
        assert!(
            consumer.0.load(Ordering::Acquire) > processed + 1,
            "oversized response came from the actual consumer"
        );

        let old = a.overlay.get_overlay(&id, "fixture").unwrap();
        a.overlay.delete_private_overlay(&id).unwrap();
        assert!(old.plumtree_engine().is_err());
        assert!(old
            .execute_plumtree(vec![Action::Deliver { source: a.key.id().clone(), data: vec![1] }])
            .await
            .is_err());
    }
}

#[cfg(test)]
mod reference_interop {
    use super::*;
    use rtos_api::deserialize_boxed;
    use rtos_block::{Ed25519KeyOption, ZeroizingBytes};
    use std::{fs, path::PathBuf, process::Command};

    /// The external runner is built from the pinned reference source in a
    /// separate directory. It invokes its real actor receiver, producer,
    /// keyring and repair handler; no reference libraries enter this crate.
    #[test]
    #[ignore = "requires the isolated pinned-reference actor runner"]
    fn fixed_reference_actor_bidirectional_carriers() {
        let runner = std::env::var("RTOS_PLUMTREE_CPP_RUNNER").expect("reference runner path");
        let dir = PathBuf::from(
            std::env::var("RTOS_PLUMTREE_INTEROP_DIR").expect("isolated output directory"),
        );
        fs::create_dir_all(&dir).unwrap();
        let signer = Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[42; 32]).unwrap();
        let wrong = Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[43; 32]).unwrap();
        let policy = PlumtreeConfig {
            authorized_keys: BTreeMap::from([(*signer.id().data(), MAX_PLUMTREE_PAYLOAD)]),
            max_untrusted_size: 0,
            untrusted_flags: 0,
            fixed_members: true,
            original_sender: false,
            eager_limit: 4,
            max_retained_bytes: MAX_PLUMTREE_PAYLOAD * 8,
            max_broadcasts: 16,
        };
        let mut sender = Engine::new(policy.clone(), [9; 32]).unwrap();
        let now = super::super::plumtree_now();
        let mono = Instant::now();
        let rust_simple = b"Rust simple carrier".to_vec();
        let rust_fec: Vec<u8> = (0..65537).map(|i| (i * 37) as u8).collect();
        sender
            .publish(
                &signer,
                Certificate::Overlay_EmptyCertificate,
                0,
                Some([3; 32]),
                &rust_simple,
                &[],
                now,
                mono,
            )
            .unwrap();
        sender
            .publish(
                &signer,
                Certificate::Overlay_EmptyCertificate,
                0,
                None,
                &rust_fec,
                &[],
                now,
                mono,
            )
            .unwrap();
        let simple_key = PartKey { id: [3; 32], part: 0, tree: 0 };
        let simple = sender.part(simple_key).unwrap().wire.clone();
        let fec_id = *sender.states.keys().find(|id| **id != [3; 32]).unwrap();
        let fec_key = PartKey { id: fec_id, part: 0, tree: 1 };
        let fec = sender.part(fec_key).unwrap().wire.clone();
        let mut manifest = String::new();
        let mut emit = |name: &str, key: PartKey, carrier: Broadcast, accepted: bool| {
            fs::write(dir.join(name), serialize_boxed(&carrier).unwrap()).unwrap();
            manifest.push_str(&format!(
                "{name} {} {} {} {}\n",
                hex::encode(key.id),
                key.part,
                key.tree,
                u8::from(accepted)
            ));
        };
        let mut bad = simple.clone();
        if let Broadcast::Overlay_BroadcastPlumtreeSimple(m) = &mut bad {
            m.signature[0] ^= 1;
        }
        emit("rust-bad-signature.tl", simple_key, bad, false);
        let mut bad = simple.clone();
        if let Broadcast::Overlay_BroadcastPlumtreeSimple(m) = &mut bad {
            m.broadcast_id = [4; 32].into();
            let other = PartKey { id: [4; 32], part: 0, tree: 0 };
            m.signature = signer
                .sign(&other.preimage(now, m.data.len(), sha256_digest(&m.data)).unwrap())
                .unwrap()
                .into();
        }
        emit("rust-wrong-request.tl", simple_key, bad, false);
        let mut bad = simple.clone();
        if let Broadcast::Overlay_BroadcastPlumtreeSimple(m) = &mut bad {
            m.src = (&wrong).try_into().unwrap();
            m.signature = wrong
                .sign(&simple_key.preimage(now, m.data.len(), sha256_digest(&m.data)).unwrap())
                .unwrap()
                .into();
        }
        emit("rust-unauthorized-origin.tl", simple_key, bad, false);
        let mut bad = fec.clone();
        if let Broadcast::Overlay_BroadcastPlumtreeFec(m) = &mut bad {
            m.data[0] ^= 1;
        }
        emit("rust-bad-symbol.tl", fec_key, bad, false);
        let mut bad = fec.clone();
        if let Broadcast::Overlay_BroadcastPlumtreeFec(m) = &mut bad {
            m.tree_index = 2;
        }
        emit("rust-wrong-tree.tl", fec_key, bad, false);
        emit("rust-simple.tl", simple_key, simple, true);
        for part in 0..PARTS as i32 {
            let key = PartKey { id: fec_id, part, tree: part + 1 };
            emit(&format!("rust-fec-{part}.tl"), key, sender.part(key).unwrap().wire.clone(), true);
        }
        let mut trailing = serialize_boxed(&sender.part(simple_key).unwrap().wire).unwrap();
        trailing.push(1);
        fs::write(dir.join("rust-trailing.tl"), trailing).unwrap();
        manifest.push_str(&format!("rust-trailing.tl {} 0 0 0\n", hex::encode(simple_key.id)));
        fs::write(dir.join("rust-cases.txt"), manifest).unwrap();
        let output = Command::new(runner).env("RTOS_PLUMTREE_INTEROP_DIR", &dir).output().unwrap();
        fs::write(dir.join("reference.stdout"), &output.stdout).unwrap();
        fs::write(dir.join("reference.stderr"), &output.stderr).unwrap();
        assert!(
            output.status.success(),
            "reference actor failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read_to_string(dir.join("cpp-receipts.txt")).unwrap().lines().count(), 52);
        let cpp_simple = b"reference simple carrier".to_vec();
        let cpp_fec: Vec<u8> = (0..65539).map(|i| (i * 41) as u8).collect();
        let hashes: BTreeSet<_> = fs::read_to_string(dir.join("cpp-deliveries.txt"))
            .unwrap()
            .lines()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        assert_eq!(
            hashes,
            [&rust_simple, &rust_fec, &cpp_simple, &cpp_fec]
                .into_iter()
                .map(|data| hex::encode(sha256_digest(data)))
                .collect()
        );
        let mut receiver = Engine::new(policy, [9; 32]).unwrap();
        let mut delivered = Vec::new();
        for tree in 0..=PARTS as i32 {
            let ihave =
                deserialize_boxed(&fs::read(dir.join(format!("cpp-{tree}-ihave.tl"))).unwrap())
                    .unwrap()
                    .downcast::<Broadcast>()
                    .unwrap();
            let payload = decode_repair_response(
                &fs::read(dir.join(format!("cpp-{tree}-payload.tl"))).unwrap(),
            )
            .unwrap();
            let now = super::super::plumtree_now();
            let query = receiver.receive([2; 32], ihave, None, &[], now, Instant::now()).unwrap();
            let key = query
                .into_iter()
                .find_map(|a| match a {
                    Action::Query { key, .. } => Some(key),
                    _ => None,
                })
                .expect("authenticated reference IHAVE triggers real repair");
            let actions =
                receiver.receive([2; 32], payload, Some(key), &[], now, Instant::now()).unwrap();
            for action in actions {
                if let Action::Deliver { data, .. } = action {
                    delivered.push(data);
                }
            }
        }
        assert_eq!(delivered, vec![cpp_simple, cpp_fec]);
        assert!(receiver.outstanding.is_empty());
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    use rtos_block::{Ed25519KeyOption, ZeroizingBytes};
    use std::{collections::VecDeque, time::Duration};

    fn setup() -> (Arc<dyn KeyOption>, PlumtreeConfig) {
        let key = Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[42; 32]).unwrap();
        let config = PlumtreeConfig {
            authorized_keys: BTreeMap::from([(*key.id().data(), MAX_PLUMTREE_PAYLOAD)]),
            max_untrusted_size: 0,
            untrusted_flags: 0,
            fixed_members: true,
            original_sender: false,
            eager_limit: 4,
            max_retained_bytes: MAX_PLUMTREE_PAYLOAD * 8,
            max_broadcasts: 16,
        };
        (key, config)
    }
    #[test]
    fn removed_peer_late_response_and_state_expiry_are_bounded() {
        let (signer, cfg) = setup();
        let mono = Instant::now();
        let now = 1700000000.0;
        let mut sender = Engine::new(cfg.clone(), [9; 32]).unwrap();
        let mut receiver = Engine::new(cfg, [9; 32]).unwrap();
        let sent = sender
            .publish(
                &signer,
                Certificate::Overlay_EmptyCertificate,
                0,
                Some([3; 32]),
                b"durable reference",
                &[[2; 32]],
                now,
                mono,
            )
            .unwrap();
        let ihave = sent
            .into_iter()
            .find_map(|a| match a {
                Action::Send { message, .. } => Some(message),
                _ => None,
            })
            .unwrap();
        let requested = receiver.receive([1; 32], ihave, None, &[], now, mono).unwrap();
        let (key, query) = requested
            .into_iter()
            .find_map(|a| match a {
                Action::Query { key, query, .. } => Some((key, query)),
                _ => None,
            })
            .unwrap();
        let payload = sender.repair_query([2; 32], query, now, mono).unwrap();
        receiver.remove_peer([1; 32]);
        assert_eq!(
            receiver.outstanding.len(),
            1,
            "removed queries remain charged until completion"
        );
        assert!(receiver.receive([1; 32], payload, Some(key), &[], now, mono).is_err());
        assert!(receiver.outstanding.is_empty());
        assert!(receiver.states.is_empty());
        receiver.query_failed(key, [1; 32], mono); // Duplicate completion cannot underflow.
        assert!(sender.retained > 0);
        sender.tick(now + 21.0, mono + Duration::from_secs(21));
        assert_eq!(sender.retained, 0);
        assert!(sender.states.is_empty());
    }

    #[test]
    fn corrupted_decoded_commitment_never_reaches_consumer() {
        let (signer, cfg) = setup();
        let now = 1700000000.0;
        let mono = Instant::now();
        let mut sender = Engine::new(cfg.clone(), [9; 32]).unwrap();
        let data: Vec<u8> = (0..3000).map(|n| n as u8).collect();
        sender
            .publish(&signer, Certificate::Overlay_EmptyCertificate, 0, None, &data, &[], now, mono)
            .unwrap();
        let state = sender.states.values().next().unwrap();
        let mut receiver = Engine::new(cfg, [9; 32]).unwrap();
        let mut delivered = 0;
        for part in state.parts.values() {
            let Broadcast::Overlay_BroadcastPlumtreeFec(mut payload) = part.wire.clone() else {
                unreachable!();
            };
            payload.full_data_hash = [88; 32].into();
            let id = fec_id(
                0,
                payload.full_data_hash.clone(),
                payload.full_data_size,
                payload.data.len(),
            )
            .unwrap();
            let key = PartKey::checked(&id, payload.part_index, payload.tree_index).unwrap();
            let hash = sha256_digest(&payload.data);
            payload.signature =
                signer.sign(&key.preimage(now, payload.data.len(), hash).unwrap()).unwrap().into();
            let auth = Auth {
                src: payload.src.clone(),
                cert: payload.certificate.clone(),
                timestamp: now,
                size: payload.data.len(),
                hash,
                signature: payload.signature.to_vec(),
            };
            let query =
                receiver.receive([1; 32], auth.ihave(key, now), None, &[], now, mono).unwrap();
            assert!(query.iter().any(|a| matches!(a, Action::Query { .. })));
            let actions =
                receiver.receive([1; 32], payload.into_boxed(), Some(key), &[], now, mono).unwrap();
            delivered +=
                actions.into_iter().filter(|a| matches!(a, Action::Deliver { .. })).count();
        }
        assert_eq!(delivered, 0);
        assert!(receiver.states.values().all(|state| state.decode_failed && !state.delivered));
    }

    #[test]
    fn five_node_multihop_with_lost_advertisement_and_repair_response() {
        let (signer, cfg) = setup();
        let mono = Instant::now();
        let now = 1700000000.0;
        let ids = [[1; 32], [2; 32], [3; 32], [4; 32], [5; 32]];
        let neighbours = [
            vec![ids[1], ids[2]],
            vec![ids[0], ids[2], ids[3]],
            vec![ids[0], ids[1], ids[4]],
            vec![ids[1], ids[4]],
            vec![ids[2], ids[3]],
        ];
        for simple in [true, false] {
            let mut engines: Vec<_> = (0..5)
                .map(|index| {
                    let mut cfg = cfg.clone();
                    cfg.original_sender = index == 0;
                    if index == 0 {
                        cfg.eager_limit = 1;
                    }
                    Engine::new(cfg, [9; 32]).unwrap()
                })
                .collect();
            let data: Vec<u8> = (0..3000).map(|n| (n * 11) as u8).collect();
            let initial = engines[0]
                .publish(
                    &signer,
                    Certificate::Overlay_EmptyCertificate,
                    0,
                    simple.then_some([3; 32]),
                    &data,
                    &neighbours[0],
                    now,
                    mono,
                )
                .unwrap();
            let mut queue: VecDeque<_> = initial.into_iter().map(|action| (0, action)).collect();
            let mut deliveries = [0usize; 5];
            let mut lost_ihave = false;
            let mut lost_response = simple;
            for round in 0..100 {
                let clock = now + round as f64 * 0.05;
                let instant = mono + Duration::from_millis(round * 50);
                while let Some((from, action)) = queue.pop_front() {
                    match action {
                        Action::Deliver { source, data: received } => {
                            assert_eq!(received, data);
                            assert_eq!(source, *signer.id());
                            deliveries[from] += 1;
                        }
                        Action::Send { peer, message } => {
                            let to = ids.iter().position(|id| *id == peer).unwrap();
                            if !lost_ihave
                                && matches!(message, Broadcast::Overlay_BroadcastPlumtreeIHave(_))
                            {
                                lost_ihave = true;
                                continue;
                            }
                            let next = engines[to]
                                .receive(ids[from], message, None, &neighbours[to], clock, instant)
                                .unwrap();
                            queue.extend(next.into_iter().map(|action| (to, action)));
                        }
                        Action::Query { peer, key, query, .. } => {
                            let to = ids.iter().position(|id| *id == peer).unwrap();
                            let response =
                                engines[to].repair_query(ids[from], query, clock, instant).unwrap();
                            if !lost_response && key.tree > 0 {
                                lost_response = true;
                                engines[from].query_failed(key, peer, instant);
                                continue;
                            }
                            let next = engines[from]
                                .receive(
                                    peer,
                                    response,
                                    Some(key),
                                    &neighbours[from],
                                    clock,
                                    instant,
                                )
                                .unwrap();
                            queue.extend(next.into_iter().map(|action| (from, action)));
                        }
                    }
                }
                for index in 0..5 {
                    queue.extend(
                        engines[index].tick(clock, instant).into_iter().map(|a| (index, a)),
                    );
                }
                if deliveries == [1; 5] {
                    break;
                }
            }
            assert!(lost_ihave && lost_response);
            assert_eq!(deliveries, [1; 5], "simple={simple}");
            assert!(engines
                .iter()
                .all(|engine| engine.retained <= engine.policy.max_retained_bytes));
        }
    }
}
