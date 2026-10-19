use crate::types::owned_tasks::OwnedTasks;
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
use adnl::{
    common::{spawn_cancelable, Query, Wait},
    node::AddressCache,
    OverlayNode, OverlayShortId,
};
use rand::Rng;
use rtos_api::{
    ton::{rpc::ton_node::GetCapabilities, ton_node::Capabilities},
    AnyBoxedSerialize,
};
use rtos_block::{error, fail, KeyId, Result};
use std::{
    cmp::min,
    fmt::{Display, Formatter},
    sync::{
        atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

#[derive(Debug)]
pub struct Neighbour {
    id: Arc<KeyId>,
    last_ping: AtomicU64,
    proto_version_major: AtomicI32,
    proto_version_minor: AtomicI32,
    roundtrip_adnl: AtomicU64,
    roundtrip_rldp: AtomicU64,
    all_attempts: AtomicU64,
    fail_attempts: AtomicU64,
    // One counter for every query outcome, whatever its transport: a failure
    // adds one, a success takes one off down to zero.
    unreliability: AtomicU32,
}

pub struct Neighbours {
    peers: Arc<NeighboursCache>,
    reserve: ReserveNeighbours,
    ///< Replaced peers saved stats
    all_peers: lockfree::set::Set<Arc<KeyId>>,
    overlay_id: Arc<OverlayShortId>,
    overlay: Arc<OverlayNode>,
    fail_attempts: AtomicU64,
    all_attempts: AtomicU64,
    start: Instant,
    cancellation_token: tokio_util::sync::CancellationToken,
    tasks: Arc<OwnedTasks>,
}

pub const PROTOCOL_VERSION_MAJOR: i32 = 3;
pub const PROTOCOL_VERSION_MINOR: i32 = 2;
/// A full neighbour list drops its most unreliable member for a new peer
/// only when that member's unreliability is above this.
pub const BETTER_REPLACE_UNRELIABILITY: u32 = 5;
/// Neighbours whose relative unreliability is above this are never chosen.
pub const FAIL_UNRELIABILITY: u32 = 10;

pub const UPDATE_FLAG_SUCCESS: u8 = 0x01;
pub const UPDATE_FLAG_IS_RLDP: u8 = 0x02;
pub const UPDATE_FLAG_IS_REGISTER: u8 = 0x04;
pub const UPDATE_FLAG_IS_REG_IN_COMMON_STAT: u8 = 0x08;

impl Display for Neighbour {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} unr {}, version {}.{}, rt ADNL {}, rt RLDP {}, peer stat: {:.4}",
            self.id(),
            self.unreliability(),
            self.proto_version_major.load(Ordering::Relaxed),
            self.proto_version_minor.load(Ordering::Relaxed),
            self.roundtrip_adnl.load(Ordering::Relaxed),
            self.roundtrip_rldp.load(Ordering::Relaxed),
            self.fail_attempts.load(Ordering::Relaxed) as f64
                / self.all_attempts.load(Ordering::Relaxed) as f64,
        )
    }
}

impl Neighbour {
    pub(crate) fn new(id: Arc<KeyId>, default_rldp_roundtrip: u32) -> Self {
        Self {
            id,
            last_ping: AtomicU64::new(0),
            proto_version_major: AtomicI32::new(0),
            proto_version_minor: AtomicI32::new(0),
            roundtrip_adnl: AtomicU64::new(0),
            roundtrip_rldp: AtomicU64::new(default_rldp_roundtrip as u64),
            all_attempts: AtomicU64::new(0),
            fail_attempts: AtomicU64::new(0),
            unreliability: AtomicU32::new(0),
        }
    }

    pub fn unreliability(&self) -> u32 {
        self.unreliability.load(Ordering::Relaxed)
    }

    /// The protocol version the neighbour advertised, as unsigned numbers;
    /// 0.0 until its capabilities are known.
    pub fn version(&self) -> (u32, u32) {
        (
            self.proto_version_major.load(Ordering::Relaxed) as u32,
            self.proto_version_minor.load(Ordering::Relaxed) as u32,
        )
    }

    pub fn is_good(&self) -> bool {
        self.unreliability() <= BETTER_REPLACE_UNRELIABILITY
    }

    #[cfg(test)]
    pub(crate) fn set_test_state(&self, unreliability: u32, major: i32, minor: i32) {
        self.unreliability.store(unreliability, Ordering::Relaxed);
        self.proto_version_major.store(major, Ordering::Relaxed);
        self.proto_version_minor.store(minor, Ordering::Relaxed);
    }

    pub fn update_proto_version(&self, q: &Capabilities) {
        self.proto_version_major.store(*q.version_major(), Ordering::Relaxed);
        self.proto_version_minor.store(*q.version_minor(), Ordering::Relaxed);
    }

    pub fn id(&self) -> &Arc<KeyId> {
        &self.id
    }

    pub fn query_success(&self, roundtrip: u64, is_rldp: bool) {
        let _ = self
            .unreliability
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| Some(old.saturating_sub(1)));
        if is_rldp {
            self.update_roundtrip_rldp(roundtrip)
        } else {
            self.update_roundtrip_adnl(roundtrip)
        }
    }

    pub fn query_failed(&self, roundtrip: u64, is_rldp: bool) {
        let _ = self
            .unreliability
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| Some(old.saturating_add(1)));
        let labels = [("neighbour", self.id.to_string())];
        metrics::counter!("rtos_node_network_neighbour_failures_total", &labels).increment(1);
        if is_rldp {
            self.update_roundtrip_rldp(roundtrip)
        } else {
            self.update_roundtrip_adnl(roundtrip)
        }
    }

    pub fn roundtrip_adnl(&self) -> Option<u64> {
        Self::roundtrip(&self.roundtrip_adnl)
    }

    pub fn roundtrip_rldp(&self) -> Option<u64> {
        Self::roundtrip(&self.roundtrip_rldp)
    }

    pub fn update_roundtrip_adnl(&self, roundtrip: u64) {
        Self::set_roundtrip(&self.roundtrip_adnl, roundtrip)
    }

    pub fn update_roundtrip_rldp(&self, roundtrip: u64) {
        Self::set_roundtrip(&self.roundtrip_rldp, roundtrip)
    }

    fn last_ping(&self) -> u64 {
        self.last_ping.load(Ordering::Relaxed)
    }

    fn roundtrip(storage: &AtomicU64) -> Option<u64> {
        let roundtrip = storage.load(Ordering::Relaxed);
        if roundtrip == 0 {
            None
        } else {
            Some(roundtrip)
        }
    }

    fn set_last_ping(&self, elapsed: u64) {
        self.last_ping.store(elapsed, Ordering::Relaxed)
    }

    fn set_roundtrip(storage: &AtomicU64, roundtrip: u64) {
        let roundtrip_old = storage.load(Ordering::Relaxed);
        let roundtrip = if roundtrip_old > 0 { (roundtrip_old + roundtrip) / 2 } else { roundtrip };
        //    log::trace!("roundtrip new value: {}", roundtrip);
        storage.store(roundtrip, Ordering::Relaxed);
    }
}

pub const MAX_NEIGHBOURS: usize = 16;

/// Whether a neighbour advertises at least the required version.
fn is_eligible(neighbour: &Neighbour, required: (u32, u32)) -> bool {
    let (major, minor) = neighbour.version();
    major > required.0 || (major == required.0 && minor >= required.1)
}

/// Selection weight of a neighbour whose unreliability is `unreliability`
/// when the least unreliable eligible neighbour has `min_unreliability`:
/// 2^(FAIL_UNRELIABILITY - u), where u is the difference plus 4 for an older
/// major version and 2 for an older minor one; none above the cutoff.
pub(crate) fn selection_weight(
    unreliability: u32,
    min_unreliability: u32,
    (major, minor): (u32, u32),
) -> Option<u32> {
    let mut unr = unreliability.saturating_sub(min_unreliability);
    if major < PROTOCOL_VERSION_MAJOR as u32 {
        unr = unr.saturating_add(4);
    } else if major == PROTOCOL_VERSION_MAJOR as u32 && minor < PROTOCOL_VERSION_MINOR as u32 {
        unr = unr.saturating_add(2);
    }
    if unr <= FAIL_UNRELIABILITY {
        Some(1u32 << (FAIL_UNRELIABILITY - unr))
    } else {
        None
    }
}

/// Weighted random choice among the neighbours advertising at least
/// `required`; `None` when none of them is eligible and within the cutoff.
pub(crate) fn choose_from(
    neighbours: &[Arc<Neighbour>],
    required: (u32, u32),
    rng: &mut impl Rng,
) -> Option<Arc<Neighbour>> {
    let min_unreliability =
        neighbours.iter().filter(|n| is_eligible(n, required)).map(|n| n.unreliability()).min()?;
    let mut best = None;
    let mut sum = 0u64;
    for neighbour in neighbours.iter().filter(|n| is_eligible(n, required)) {
        if let Some(weight) =
            selection_weight(neighbour.unreliability(), min_unreliability, neighbour.version())
        {
            sum = sum.saturating_add(weight as u64);
            if rng.gen_range(0..sum) < weight as u64 {
                best = Some(neighbour.clone());
            }
        }
    }
    best
}

/// The neighbour a full list gives up for a new peer: its most unreliable
/// member when that one is above BETTER_REPLACE_UNRELIABILITY (`true`), a
/// uniformly random member otherwise (`false`); `None` for an empty list.
pub(crate) fn replacement_victim(
    neighbours: &[Arc<Neighbour>],
    rng: &mut impl Rng,
) -> Option<(Arc<Neighbour>, bool)> {
    let mut worst = None;
    let mut random = None;
    let mut max_unreliability = 0;
    for (count, neighbour) in neighbours.iter().enumerate() {
        let unreliability = neighbour.unreliability();
        if unreliability > max_unreliability {
            max_unreliability = unreliability;
            worst = Some(neighbour.clone());
        }
        if rng.gen_range(0..=count) == 0 {
            random = Some(neighbour.clone());
        }
    }
    if max_unreliability > BETTER_REPLACE_UNRELIABILITY {
        worst.map(|n| (n, true))
    } else {
        random.map(|n| (n, false))
    }
}
const PING_DELAY_MS: u64 = 1000; // Neighbour ping recommended minimum delay
const RESERVE_PING_DELAY_MS: u64 = 30000; // Reserved neighbour ping recommended minimum delay

impl Neighbours {
    const DEFAULT_RLDP_ROUNDTRIP_MS: u32 = 2000;
    const MAX_PINGS: usize = 6;
    const TIMEOUT_PING_MAX_MS: u64 = 1000;
    const TIMEOUT_RELOAD_MAX_SEC: u64 = 30;
    const TIMEOUT_RELOAD_MIN_SEC: u64 = 10;

    const TIMEOUT_PING_MAX: Duration = Duration::from_millis(Self::TIMEOUT_PING_MAX_MS);
    const TIMEOUT_PING_MIN: Duration = Duration::from_millis(10);

    pub(crate) fn new(
        start_peers: &[Arc<KeyId>],
        overlay: &Arc<OverlayNode>,
        overlay_id: Arc<OverlayShortId>,
        default_rldp_roundtrip: &Option<u32>,
        cancellation_token: tokio_util::sync::CancellationToken,
        tasks: Arc<OwnedTasks>,
    ) -> Result<Self> {
        let default_rldp_roundtrip =
            default_rldp_roundtrip.unwrap_or(Self::DEFAULT_RLDP_ROUNDTRIP_MS);
        let ret = Neighbours {
            peers: Arc::new(NeighboursCache::new(start_peers, default_rldp_roundtrip)?),
            reserve: ReserveNeighbours::new(),
            all_peers: lockfree::set::Set::new(),
            overlay: overlay.clone(),
            overlay_id,
            fail_attempts: AtomicU64::new(0),
            all_attempts: AtomicU64::new(0),
            start: Instant::now(),
            cancellation_token,
            tasks,
        };
        Ok(ret)
    }

    pub fn count(&self) -> usize {
        self.peers.count()
    }

    pub fn new_neighbour(&self, peer: Arc<KeyId>) -> Arc<Neighbour> {
        Arc::new(Neighbour::new(peer, self.peers.default_rldp_roundtrip))
    }

    pub fn add(&self, peer: Arc<KeyId>) -> Result<bool> {
        if self.count() >= MAX_NEIGHBOURS {
            return Ok(false);
        }
        let reserve_peer = self.reserve.find_in_reserve(&peer);
        self.reserve.on_active_added(&reserve_peer);
        self.peers.insert_ex(peer, false, reserve_peer)
    }

    pub fn contains(&self, peer: &Arc<KeyId>) -> bool {
        self.peers.contains(peer)
    }

    pub fn contains_overlay_peer(&self, id: &Arc<KeyId>) -> bool {
        self.all_peers.contains(id)
    }

    pub fn add_overlay_peer(&self, id: Arc<KeyId>) -> bool {
        self.all_peers.insert(id).is_ok()
    }

    pub fn remove_overlay_peer(&self, id: &Arc<KeyId>) {
        self.all_peers.remove(id);
    }

    pub fn all_peers(&self) -> &lockfree::set::Set<Arc<KeyId>> {
        &self.all_peers
    }

    pub fn peer(&self, peer: &Arc<KeyId>) -> Option<Arc<Neighbour>> {
        self.peers.get(peer)
    }

    pub fn get_peers_iter(&self) -> NeighboursCacheIterator {
        NeighboursCacheIterator::new(self.peers.clone())
    }

    pub fn rotate_neighbours(&self, id: &Arc<OverlayShortId>) -> Result<()> {
        log::trace!("rotate_neighbours");

        let overlay_peers = AddressCache::with_limit((MAX_NEIGHBOURS * 2 + 1) as u32);
        self.overlay.get_cached_random_peers(&overlay_peers, id, (MAX_NEIGHBOURS * 2) as u32)?;

        log::trace!("{id} got {} cached random peers from overlay", overlay_peers.count());

        log::trace!("neighbours reserve before: {}", self.reserve.descr());
        let mut ex = false;
        let mut rng = rand::thread_rng();

        let (mut iter, mut current) = overlay_peers.first();
        while let Some(elem) = current {
            if self.contains(&elem) {
                current = overlay_peers.next(&mut iter);
                continue;
            }
            let count = self.peers.count();
            let reserve_peer = self.reserve.find_in_reserve(&elem);
            // If peer exists in reserve and it is known to be bad unreliability, skipping
            if reserve_peer.as_ref().map_or(false, |v| !v.is_good()) {
                current = overlay_peers.next(&mut iter);
                continue;
            }

            if count == MAX_NEIGHBOURS {
                let peers: Vec<_> = self.get_peers_iter().collect();
                let (deleted_peer, is_bad) = replacement_victim(&peers, &mut rng)
                    .ok_or_else(|| error!("Internal error: deleted peer is not set!"))?;
                if !is_bad {
                    ex = true;
                }
                log::trace!(
                    "deleted_peer: {} unr: {} is_bad: {is_bad}",
                    deleted_peer.id(),
                    deleted_peer.unreliability(),
                );
                if is_bad {
                    self.reserve.on_active_replaced(&reserve_peer, deleted_peer.clone());
                }
                self.peers.replace(deleted_peer.id(), elem.clone(), reserve_peer, is_bad)?;
            } else {
                self.peers.insert(elem.clone(), reserve_peer)?;
            }

            if ex {
                break;
            }
            current = overlay_peers.next(&mut iter);
        }
        log::trace!("neighbours reserve after: {}", self.reserve.descr());
        log::trace!("/rotate_neighbours");
        Ok(())
    }

    pub fn start_rotation_worker(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        spawn_cancelable(self.cancellation_token.clone(), async move {
            loop {
                let sleep_time = rand::thread_rng()
                    .gen_range(Self::TIMEOUT_RELOAD_MIN_SEC..Self::TIMEOUT_RELOAD_MAX_SEC);
                tokio::time::sleep(Duration::from_secs(sleep_time)).await;
                if let Err(e) = self.rotate_neighbours(&self.overlay_id) {
                    log::warn!("reload neighbours err: {:?}", e);
                }
            }
        })
    }

    pub fn start_ping_worker(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        spawn_cancelable(self.cancellation_token.clone(), async move {
            self.ping_worker().await;
        })
    }

    #[cfg(feature = "telemetry")]
    pub fn log_neighbors_stat(&self) {
        log::debug!(
            target: "telemetry",
            "Neighbours: overlay {} count {}",
            self.overlay_id, self.peers.count()
        );
        let node_stat = self.fail_attempts.load(Ordering::Relaxed) as f64
            / self.all_attempts.load(Ordering::Relaxed) as f64;
        for neighbour in self.get_peers_iter() {
            log::debug!(
                target: "telemetry",
                "Neighbour {}, node stat: {:.4}",
                neighbour, node_stat
            )
        }
    }

    pub fn choose_neighbour(&self) -> Result<Option<Arc<Neighbour>>> {
        self.choose_neighbour_with_version(0, 0)
    }

    /// A weighted random neighbour among those advertising at least
    /// `major`.`minor`.
    pub fn choose_neighbour_with_version(
        &self,
        major: u32,
        minor: u32,
    ) -> Result<Option<Arc<Neighbour>>> {
        let peers: Vec<_> = self.get_peers_iter().collect();
        for neighbour in &peers {
            let labels = [("neighbour", neighbour.id().to_string())];
            metrics::gauge!("rtos_node_network_neighbour_unreliability", &labels)
                .set(neighbour.unreliability() as f64);
        }
        let best = choose_from(&peers, (major, minor), &mut rand::thread_rng());
        if let Some(best) = &best {
            log::trace!("Selected neighbour {} for overlay {}", best, self.overlay_id);
        } else {
            log::trace!("Selected neighbour None for overlay {}", self.overlay_id);
        }
        Ok(best)
    }

    pub fn update_neighbour_stats(
        &self,
        neighbour: &Arc<Neighbour>,
        roundtrip: u64,
        update_flag: u8,
    ) {
        if (update_flag & UPDATE_FLAG_SUCCESS) != 0 {
            neighbour.query_success(roundtrip, (update_flag & UPDATE_FLAG_IS_RLDP) != 0);
        } else {
            neighbour.query_failed(roundtrip, (update_flag & UPDATE_FLAG_IS_RLDP) != 0);
        }
        if (update_flag & UPDATE_FLAG_IS_REGISTER) != 0 {
            neighbour.all_attempts.fetch_add(1, Ordering::Relaxed);
            if (update_flag & UPDATE_FLAG_IS_REG_IN_COMMON_STAT) != 0 {
                self.all_attempts.fetch_add(1, Ordering::Relaxed);
            }
            if (update_flag & UPDATE_FLAG_SUCCESS) == 0 {
                neighbour.fail_attempts.fetch_add(1, Ordering::Relaxed);
                if (update_flag & UPDATE_FLAG_IS_REG_IN_COMMON_STAT) != 0 {
                    self.fail_attempts.fetch_add(1, Ordering::Relaxed);
                }
            }
        };
        log::trace!("Update stats for neighbour {} for overlay {}", neighbour, self.overlay_id);
    }

    pub fn got_neighbour_capabilities(
        &self,
        peer: &Arc<Neighbour>,
        _roundtrip: u64,
        capabilities: &Capabilities,
    ) {
        peer.update_proto_version(capabilities);
    }

    async fn ping_worker(self: &Arc<Self>) {
        let (wait, mut queue_reader) = Wait::new();
        loop {
            let peers = self.peers.count();
            let max_count = min(peers, Self::MAX_PINGS);
            if max_count == 0 {
                log::trace!("No peers in overlay {}", self.overlay_id);
                tokio::time::sleep(Self::TIMEOUT_PING_MAX).await;
                continue;
            }
            log::trace!("neighbours: overlay {} count {}", self.overlay_id, peers);

            // Ping active list with priority and reserve nodes otherwise
            let mut ping_reserve = false;
            let (mut next_ping, mut ping_idx) = self.peers.next_for_ping(&self.start);
            next_ping = next_ping.or_else(|| {
                ping_reserve = true;
                let (rv, idx) = self.reserve.next_for_ping(&self.start);
                ping_idx = idx;
                rv
            });
            let peer = match next_ping {
                Some(peer) => peer,
                None => {
                    log::trace!("next_for_ping: None");
                    tokio::time::sleep(Self::TIMEOUT_PING_MIN).await;
                    continue;
                }
            };
            let last = self.start.elapsed().as_millis() as u64 - peer.last_ping();
            if last < Self::TIMEOUT_PING_MAX_MS {
                tokio::time::sleep(Duration::from_millis(Self::TIMEOUT_PING_MAX_MS - last)).await;
            } else {
                tokio::time::sleep(Self::TIMEOUT_PING_MIN).await;
            }
            let self_cloned = self.clone();
            let wait_cloned = wait.clone();
            let mut count = wait.request();
            peer.set_last_ping(self.start.elapsed().as_millis() as u64);
            if self
                .tasks
                .spawn_cancelable("neighbour capability ping", async move {
                    if let Err(e) = self_cloned.update_capabilities(peer, ping_reserve).await {
                        log::debug!("{}; ping_idx #{}", e, ping_idx)
                    }
                    wait_cloned.respond(Some(()));
                })
                .is_err()
            {
                return;
            }
            while count >= max_count {
                wait.wait(&mut queue_reader, false).await;
                count -= 1;
            }
        }
    }

    async fn update_capabilities(
        self: Arc<Self>,
        peer: Arc<Neighbour>,
        ping_reserve: bool,
    ) -> Result<()> {
        let now = Instant::now();
        peer.set_last_ping(self.start.elapsed().as_millis() as u64);
        let query = GetCapabilities.into_tl_object().into();
        let answer = self
            .overlay
            .query(&peer.id, &query, &self.overlay_id, Some(Self::TIMEOUT_PING_MAX_MS))
            .await;
        let roundtrip = now.elapsed().as_millis() as u64;
        let common = if !ping_reserve { UPDATE_FLAG_IS_REG_IN_COMMON_STAT } else { 0u8 };
        let status = if !ping_reserve { "active" } else { "reserve" };
        // A missing, failed or unparsable answer counts as a failed ping.
        let caps = match answer {
            Ok(Some(answer)) => Query::parse::<_, Capabilities>(answer, &query.object),
            Ok(None) => Err(error!("no answer")),
            Err(e) => Err(e),
        };
        match caps {
            Ok(caps) => {
                log::trace!(
                    "Got capabilities from {} {} {}: {:?}",
                    status,
                    peer.id,
                    self.overlay_id,
                    caps
                );
                self.update_neighbour_stats(&peer, roundtrip, common | UPDATE_FLAG_SUCCESS);
                self.got_neighbour_capabilities(&peer, roundtrip, &caps);
                Ok(())
            }
            Err(e) => {
                self.update_neighbour_stats(&peer, roundtrip, common);
                fail!(
                    "Capabilities were not received from {} {} (unr {}) {}: {e}",
                    status,
                    peer.id,
                    peer.unreliability(),
                    self.overlay_id
                )
            }
        }
    }
}

struct NeighboursCache {
    count: AtomicU32,
    next: AtomicU32,
    indices: lockfree::map::Map<u32, Arc<KeyId>>,
    values: lockfree::map::Map<Arc<KeyId>, Arc<Neighbour>>,
    default_rldp_roundtrip: u32,
}

impl NeighboursCache {
    fn new(start_peers: &[Arc<KeyId>], default_rldp_roundtrip: u32) -> Result<Self> {
        let instance = NeighboursCache {
            count: AtomicU32::new(0),
            next: AtomicU32::new(0),
            indices: lockfree::map::Map::new(),
            values: lockfree::map::Map::new(),
            default_rldp_roundtrip,
        };

        let mut index = 0;
        for peer in start_peers.iter() {
            if index < MAX_NEIGHBOURS {
                instance.insert(peer.clone(), None)?;
                index += 1;
            }
        }

        Ok(instance)
    }

    fn contains(&self, peer: &Arc<KeyId>) -> bool {
        self.values.get(peer).is_some()
    }

    fn insert(
        &self,
        peer: Arc<KeyId>,
        existing_in_reserve: Option<Arc<Neighbour>>,
    ) -> Result<bool> {
        let status = self.insert_ex(peer, false, existing_in_reserve)?;
        Ok(status)
    }

    fn count(&self) -> usize {
        self.count.load(Ordering::Relaxed) as usize
    }

    fn get(&self, peer: &Arc<KeyId>) -> Option<Arc<Neighbour>> {
        self.values.get_cloned(peer)
    }

    fn next_for_ping(&self, start: &Instant) -> (Option<Arc<Neighbour>>, u64) {
        let mut next = self.next.load(Ordering::Relaxed);
        let count = self.count.load(Ordering::Relaxed);
        let started_from = next;
        let mut ret: Option<Arc<Neighbour>> = None;
        let mut ping_idx: u64 = 0;
        loop {
            let key_id = if let Some(key_id) = self.indices.get(&next) {
                key_id
            } else {
                return (None, 0);
            };
            if let Some(neighbour) = self.values.get(key_id.val()) {
                let cur_idx: u64 = next.into();
                next = if next >= count - 1 {
                    0 // ping cyclically
                } else {
                    next + 1
                };
                self.next.store(next, Ordering::Relaxed);
                let neighbour = neighbour.val();
                if start.elapsed().as_millis() as u64 - neighbour.last_ping() < PING_DELAY_MS {
                    // Pinged recently
                    if next == started_from {
                        break;
                    } else {
                        continue;
                    }
                }
                ret.replace(neighbour.clone());
                ping_idx = cur_idx;
            } else {
                // Value has been updated. Repeat step
                continue;
            }
            break;
        }
        (ret, ping_idx)
    }

    fn insert_ex(
        &self,
        peer: Arc<KeyId>,
        silent_insert: bool,
        existing_in_reserve: Option<Arc<Neighbour>>,
    ) -> Result<bool> {
        let count = self.count.load(Ordering::Relaxed);
        if !silent_insert && (count >= MAX_NEIGHBOURS as u32) {
            fail!("NeighboursCache overflow!");
        }

        let mut is_overflow = false;
        let mut index = 0;
        let insertion =
            self.values.insert_with(peer.clone(), |_key, prev_gen_val, updated_pair| {
                if updated_pair.is_some() {
                    lockfree::map::Preview::Discard
                } else if prev_gen_val.is_some() {
                    lockfree::map::Preview::Keep
                } else {
                    if !silent_insert {
                        index = self.count.fetch_add(1, Ordering::Relaxed);
                        if index >= MAX_NEIGHBOURS as u32 {
                            self.count.fetch_sub(1, Ordering::Relaxed);
                            is_overflow = true;
                        }
                    }

                    if is_overflow {
                        lockfree::map::Preview::Discard
                    } else {
                        lockfree::map::Preview::New(existing_in_reserve.clone().unwrap_or_else(
                            || Arc::new(Neighbour::new(peer.clone(), self.default_rldp_roundtrip)),
                        ))
                    }
                }
            });

        if is_overflow {
            fail!("NeighboursCache overflow!");
        }

        let status = match insertion {
            lockfree::map::Insertion::Created => true,
            lockfree::map::Insertion::Failed(_) => false,
            lockfree::map::Insertion::Updated(_) => {
                fail!("neighbours: unreachable Insertion::Updated")
            }
        };

        if status && !silent_insert {
            self.indices.insert(index, peer);
        }

        Ok(status)
    }

    pub fn replace(
        &self,
        old: &Arc<KeyId>,
        new: Arc<KeyId>,
        existing_in_reserve: Option<Arc<Neighbour>>,
        bad_peer: bool,
    ) -> Result<bool> {
        let new_unr = existing_in_reserve.as_ref().map_or(0, |v| v.unreliability());
        log::debug!(
            "started replace (old: {}, new: {}) {}, new_unr: {}",
            &old,
            &new,
            if bad_peer { "as a bad peer" } else { "for rotation" },
            new_unr
        );
        let index = if let Some(index) = self.get_index(old) {
            index
        } else {
            fail!("replaced neighbour not found!")
        };
        log::debug!("replace func use index: {} (old: {}, new: {})", &index, &old, &new);
        let status_insert = self.insert_ex(new.clone(), true, existing_in_reserve)?;

        if status_insert {
            self.indices.insert(index, new);
            self.values.remove(old);
        }
        log::debug!("finish replace (old: {})", &old);
        Ok(status_insert)
    }

    fn get_index(&self, peer: &Arc<KeyId>) -> Option<u32> {
        for index in self.indices.iter() {
            if index.1.cmp(peer) == std::cmp::Ordering::Equal {
                return Some(index.0);
            }
        }
        None
    }
}

pub struct NeighboursCacheIterator {
    current: i32,
    parent: Arc<NeighboursCache>,
}

impl NeighboursCacheIterator {
    fn new(parent: Arc<NeighboursCache>) -> Self {
        NeighboursCacheIterator { current: -1, parent }
    }
}

impl Iterator for NeighboursCacheIterator {
    type Item = Arc<Neighbour>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut result = None;

        let current = self.current + 1;
        for _ in 0..5 {
            let key_id = if let Some(key_id) = &self.parent.indices.get(&(current as u32)) {
                key_id.val().clone()
            } else {
                return None;
            };

            if let Some(neighbour) = &self.parent.values.get(&key_id) {
                self.current = current;
                result = Some(neighbour.val().clone());
                break;
            } else {
                // Value has been updated. Repeat step
                continue;
            }
        }

        result
    }
}

/// Neighbours, replaced in main active list, are stored in reserve list
struct ReserveNeighbours {
    last_ping: AtomicU64,
    reserve: lockfree::map::Map<Arc<KeyId>, Arc<Neighbour>>,
}

impl ReserveNeighbours {
    pub(crate) fn new() -> Self {
        ReserveNeighbours { last_ping: AtomicU64::new(0), reserve: lockfree::map::Map::new() }
    }

    /// Save peer stat in reserve when peer is replaced in active list.
    /// Remove its replacement from reserve (if it was in reserve ('reserve_peer'))
    pub fn on_active_replaced(&self, reserve_peer: &Option<Arc<Neighbour>>, peer: Arc<Neighbour>) {
        if reserve_peer.is_some() {
            log::trace!("reserve del: {}", &reserve_peer.as_ref().unwrap().id());
            self.reserve.remove(reserve_peer.as_ref().unwrap().id());
        }
        log::trace!("reserve ins: {}, unr {}", &peer.id(), peer.unreliability());
        self.reserve.insert(peer.id().clone(), peer);
    }

    pub fn on_active_added(&self, reserve_peer: &Option<Arc<Neighbour>>) {
        if reserve_peer.is_some() {
            log::trace!("reserve del2: {}", &reserve_peer.as_ref().unwrap().id());
            self.reserve.remove(reserve_peer.as_ref().unwrap().id());
        }
    }

    fn last_ping(&self) -> u64 {
        self.last_ping.load(Ordering::Relaxed)
    }

    fn set_last_ping(&self, elapsed: u64) {
        self.last_ping.store(elapsed, Ordering::Relaxed)
    }

    /// Description
    pub fn descr(&self) -> String {
        let mut rv: String = String::new();
        for guard in self.reserve.iter() {
            rv.push_str(&format!("{}: unr {}; ", guard.key(), guard.val().unreliability()));
        }
        rv
    }

    /// Get next (bad) peer from reserve list, not ping'ed in last PING_DELAY_MS
    pub fn next_for_ping(&self, start: &Instant) -> (Option<Arc<Neighbour>>, u64) {
        let mut rv: Option<Arc<Neighbour>> = None;
        let mut idx: u64 = 0;
        let now = start.elapsed().as_millis() as u64;
        if now - self.last_ping() > RESERVE_PING_DELAY_MS {
            self.set_last_ping(now);
            let mut cur_idx: u64 = 0;
            for neighbour in self.reserve.iter() {
                cur_idx += 1;
                let neighbour = neighbour.val();
                if neighbour.is_good() {
                    continue;
                }
                if rv.as_ref().is_some() && rv.as_ref().unwrap().last_ping() < neighbour.last_ping()
                {
                    continue;
                }
                rv.replace(neighbour.clone());
                idx = cur_idx;
            }
        }
        (rv, if idx > 0 { idx - 1 } else { 0 })
    }

    /// Find old peer stats by its KeyId if this peer already was in active list and was replaced
    pub fn find_in_reserve(&self, peer_id: &Arc<KeyId>) -> Option<Arc<Neighbour>> {
        if let Some(neighbour) = self.reserve.get(peer_id) {
            return Some(neighbour.val().clone());
        }
        None
    }
}
