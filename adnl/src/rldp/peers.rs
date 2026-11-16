// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Native RLDP2 connection admission, expiration and retirement ownership.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, Weak};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

type Key = (Arc<KeyId>, Arc<KeyId>);
struct Entry {
    peer: Arc<RldpPeer>,
    expires: Instant,
}
#[derive(Default)]
struct State {
    v1: BTreeMap<Key, Arc<RldpPeer>>,
    v2: BTreeMap<Key, Entry>,
    retiring: BTreeMap<Key, CancellationToken>,
    order: BTreeMap<Arc<KeyId>, BTreeSet<(Instant, Arc<KeyId>)>>,
}
impl State {
    fn refresh(&mut self, key: &Key, expires: Instant) -> Option<Arc<RldpPeer>> {
        let entry = self.v2.get_mut(key)?;
        if expires > entry.expires {
            let order = self.order.get_mut(&key.0).unwrap();
            order.remove(&(entry.expires, key.1.clone()));
            order.insert((expires, key.1.clone()));
            entry.expires = expires;
        }
        Some(entry.peer.clone())
    }
    fn remove(&mut self, key: &Key) -> Option<Arc<RldpPeer>> {
        let entry = self.v2.remove(key)?;
        self.retiring.insert(key.clone(), entry.peer.drained.clone());
        let order = self.order.get_mut(&key.0).unwrap();
        order.remove(&(entry.expires, key.1.clone()));
        if order.is_empty() {
            self.order.remove(&key.0);
        }
        Some(entry.peer)
    }
    fn oldest(&self, min_share: usize) -> Option<(Key, Instant)> {
        let mut best = None;
        for (local, order) in &self.order {
            if order.len() < min_share {
                continue;
            }
            if let Some((expires, remote)) = order.first() {
                if best.as_ref().is_none_or(|(_, old)| expires < old) {
                    best = Some(((local.clone(), remote.clone()), *expires));
                }
            }
        }
        best
    }
    fn victim(&self, local: &Arc<KeyId>) -> Option<Key> {
        let share = (PeerTable::MAX_CONNECTIONS / self.order.len().max(1)).max(1);
        if let Some(mine) = self.order.get(local).filter(|order| order.len() >= share) {
            return mine.first().map(|(_, remote)| (local.clone(), remote.clone()));
        }
        self.oldest(share).or_else(|| self.oldest(0)).map(|(key, _)| key)
    }
}

pub(super) struct PeerTable {
    state: Mutex<State>,
    admission: tokio::sync::Mutex<()>,
    capacity: Arc<Semaphore>,
    wake: Arc<Notify>,
    adnl: Arc<AdnlNode>,
    pool: Arc<SendWorkerPool>,
    transfers: Arc<lockfree::map::Map<TransferId, RldpTransfer>>,
    counter: Arc<AtomicU64>,
    min_timeout_ms: u64,
    pub(super) evicted: AtomicU64,
}
impl PeerTable {
    pub(super) const MAX_CONNECTIONS: usize = 4096;
    const IDLE: Duration = Duration::from_secs(120);
    pub(super) fn new(
        adnl: Arc<AdnlNode>,
        pool: Arc<SendWorkerPool>,
        transfers: Arc<lockfree::map::Map<TransferId, RldpTransfer>>,
        counter: Arc<AtomicU64>,
        min_timeout_ms: u64,
    ) -> Result<Arc<Self>> {
        let ret = Arc::new(Self {
            state: Mutex::new(State::default()),
            admission: tokio::sync::Mutex::new(()),
            capacity: Arc::new(Semaphore::new(Self::MAX_CONNECTIONS)),
            wake: Arc::new(Notify::new()),
            adnl,
            pool,
            transfers,
            counter,
            min_timeout_ms,
            evicted: AtomicU64::new(0),
        });
        let weak = Arc::downgrade(&ret);
        let wake = ret.wake.clone();
        let owner = ret.adnl.tasks().clone();
        let lifetime = owner.clone();
        let token = owner.enter()?;
        owner.spawn_admitted("RLDP connection expiration", token, async move {
            loop {
                let next = match weak.upgrade() {
                    Some(table) => table.expire(Instant::now()),
                    None => break,
                };
                tokio::select! {
                    biased;
                    _ = lifetime.cancelled() => {
                        if let Some(table) = weak.upgrade() { table.close(); }
                        break;
                    }
                    _ = wake.notified() => {},
                    _ = async {
                        match next {
                            Some(at) => tokio::time::sleep_until(at).await,
                            None => std::future::pending::<()>().await,
                        }
                    } => {},
                }
            }
        });
        Ok(ret)
    }
    pub(super) fn expire(&self, now: Instant) -> Option<Instant> {
        let mut state = self.state.lock().unwrap();
        state.retiring.retain(|_, drained| !drained.is_cancelled());
        while let Some((key, at)) = state.oldest(0) {
            if at > now {
                return Some(at);
            }
            if let Some(peer) = state.remove(&key) {
                peer.close(&self.transfers);
            }
        }
        None
    }
    fn close(&self) {
        let mut state = self.state.lock().unwrap();
        for peer in state.v1.values() {
            peer.close(&self.transfers);
        }
        for entry in state.v2.values() {
            entry.peer.close(&self.transfers);
        }
        state.v1.clear();
        state.v2.clear();
        state.order.clear();
        state.retiring.clear();
    }
    pub(super) async fn get(
        &self,
        local: &Arc<KeyId>,
        remote: &Arc<KeyId>,
        v2: bool,
        deadline: Option<Instant>,
    ) -> Result<Arc<RldpPeer>> {
        if self.adnl.tasks().is_closed() {
            return Err(SendCancelled::OwnerClosed.into());
        }
        let key = (local.clone(), remote.clone());
        let expires = deadline.unwrap_or_else(Instant::now) + Self::IDLE;
        {
            let mut state = self.state.lock().unwrap();
            if !v2 {
                if let Some(peer) = state.v1.get(&key) {
                    return Ok(peer.clone());
                }
                let peer = self.create(None)?;
                state.v1.insert(key, peer.clone());
                return Ok(peer);
            }
            if let Some(peer) = state.refresh(&key, expires) {
                return Ok(peer);
            }
        }
        // Serialize new admission, but existing connections can still refresh
        // and progress while an evicted connection joins actual blocking work.
        let _admission = loop {
            let admission = tokio::select! {
                _ = self.adnl.tasks().cancelled() => return Err(SendCancelled::OwnerClosed.into()),
                guard = self.admission.lock() => guard,
            };
            let retiring = {
                let mut state = self.state.lock().unwrap();
                if let Some(peer) = state.refresh(&key, expires) {
                    return Ok(peer);
                }
                let retiring =
                    state.retiring.get(&key).filter(|done| !done.is_cancelled()).cloned();
                if retiring.is_none() && state.v2.len() >= Self::MAX_CONNECTIONS {
                    let victim =
                        state.victim(local).ok_or_else(|| error!("RLDP connection order drift"))?;
                    let peer = state.remove(&victim).unwrap();
                    peer.close(&self.transfers);
                    self.evicted.fetch_add(1, Ordering::Relaxed);
                }
                retiring
            };
            if let Some(retiring) = retiring {
                // Reopening the same identity cannot race an old generation's
                // real join and ID cleanup, even if other slots are free.
                drop(admission);
                tokio::select! {
                    _ = self.adnl.tasks().cancelled() => return Err(SendCancelled::OwnerClosed.into()),
                    _ = retiring.cancelled() => {},
                }
                continue;
            }
            break admission;
        };
        let permit = tokio::select! {
            _ = self.adnl.tasks().cancelled() => return Err(SendCancelled::OwnerClosed.into()),
            permit = self.capacity.clone().acquire_owned() => permit?,
        };
        let peer = self.create(Some(permit))?;
        let expires = deadline.unwrap_or_else(Instant::now) + Self::IDLE;
        {
            let mut state = self.state.lock().unwrap();
            if self.adnl.tasks().is_closed() {
                peer.close(&self.transfers);
                return Err(SendCancelled::OwnerClosed.into());
            }
            state.order.entry(local.clone()).or_default().insert((expires, remote.clone()));
            state.v2.insert(key, Entry { peer: peer.clone(), expires });
        }
        self.wake.notify_one();
        Ok(peer)
    }
    fn create(&self, permit: Option<OwnedSemaphorePermit>) -> Result<Arc<RldpPeer>> {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let peer = Arc::new(RldpPeer {
            outbound_semaphore: Arc::new(Semaphore::new(RldpNode::MAX_OUTBOUNDS_PER_PEER as usize)),
            transfer_slots: Arc::new(Semaphore::new(256)),
            tx,
            closed: CancellationToken::new(),
            drained: CancellationToken::new(),
            registrations: Arc::new(Mutex::new(HashSet::new())),
            completed: Mutex::new(std::collections::VecDeque::new()),
            stats: StatsV2::new(StatsConfigV2::default(), self.min_timeout_ms)?,
            #[cfg(test)]
            idle: Arc::new(Notify::new()),
            counter: self.counter.clone().into(),
        });
        let weak: Weak<RldpPeer> = Arc::downgrade(&peer);
        let closed = peer.closed.clone();
        let drained = peer.drained.clone();
        let wake = self.wake.clone();
        let registrations = peer.registrations.clone();
        #[cfg(test)]
        let idle = peer.idle.clone();
        let transfers = self.transfers.clone();
        let pool = self.pool.clone();
        let min_timeout_ms = self.min_timeout_ms;
        let owner = self.adnl.tasks().clone();
        let lifetime = owner.clone();
        let token = owner.enter()?;
        owner.spawn_admitted("RLDP peer sender", token, async move {
            let _permit = permit;
            let mut tasks = futures::stream::FuturesUnordered::new();
            loop {
                #[cfg(test)]
                idle.notify_one();
                tokio::select! {
                    biased;
                    _ = lifetime.cancelled() => { closed.cancel(); break; },
                    _ = closed.cancelled() => break,
                    job = rx.recv() => match job {
                        Some(job) => {
                            if let Some(peer) = weak.upgrade() {
                                tasks.push(job.run(peer, &transfers, &pool, min_timeout_ms));
                            } else {
                                job.ctx.control.cancel(SendCancelled::PeerEvicted);
                                let _ = job.done.send(Err(SendCancelled::PeerEvicted.into()));
                            }
                        }
                        None => break,
                    },
                    _ = tasks.next(), if !tasks.is_empty() => {},
                }
            }
            rx.close();
            while let Ok(job) = rx.try_recv() {
                job.ctx.control.cancel(SendCancelled::PeerEvicted);
                let _ = job.done.send(Err(SendCancelled::PeerEvicted.into()));
            }
            while tasks.next().await.is_some() {}
            let mut ids = registrations.lock().unwrap();
            for id in ids.drain() {
                transfers.remove(&id);
            }
            if let Some(peer) = weak.upgrade() {
                peer.completed.lock().unwrap().clear();
            }
            drop(ids);
            drained.cancel();
            wake.notify_one();
        });
        Ok(peer)
    }
}
impl Drop for PeerTable {
    fn drop(&mut self) {
        self.close();
        self.wake.notify_one();
    }
}
impl RldpPeer {
    pub(super) fn finish_inbound(
        &self,
        transfers: &lockfree::map::Map<TransferId, RldpTransfer>,
        id: TransferId,
        finished: &CancellationToken,
        now: Instant,
    ) {
        let mut ids = self.registrations.lock().unwrap();
        if finished.is_cancelled() {
            return;
        }
        // Old expiry and registration drops must not touch this ID again,
        // including after the completed-ID cache evicts it and it is reused.
        finished.cancel();
        if self.closed.is_cancelled() {
            return;
        }
        transfers.insert(id, RldpTransfer::Done);
        ids.insert(id);
        let mut completed = self.completed.lock().unwrap();
        completed.push_back((id, now + Duration::from_secs(20)));
        // Native trims only on completion: retain a minimum128 entries, expire
        // older entries after20s, and bound the cache unconditionally at2048.
        while completed.len() > 2048
            || (completed.len() > 128 && completed.front().is_some_and(|(_, at)| *at <= now))
        {
            let (old, _) = completed.pop_front().unwrap();
            if transfers.get(&old).is_some_and(|entry| matches!(entry.val(), RldpTransfer::Done)) {
                transfers.remove(&old);
                ids.remove(&old);
            }
        }
    }
    fn close(&self, _transfers: &lockfree::map::Map<TransferId, RldpTransfer>) {
        let _ids = self.registrations.lock().unwrap();
        self.closed.cancel();
    }
    pub(super) fn insert_transfer(
        &self,
        transfers: &lockfree::map::Map<TransferId, RldpTransfer>,
        id: TransferId,
        value: RldpTransfer,
    ) -> Result<()> {
        self.insert_transfer_with(transfers, id, || Ok((value, ())))
    }
    pub(super) fn insert_transfer_with<T>(
        &self,
        transfers: &lockfree::map::Map<TransferId, RldpTransfer>,
        id: TransferId,
        create: impl FnOnce() -> Result<(RldpTransfer, T)>,
    ) -> Result<T> {
        let mut ids = self.registrations.lock().unwrap();
        if self.closed.is_cancelled() {
            return Err(SendCancelled::PeerEvicted.into());
        }
        let (value, result) = create()?;
        transfers.insert(id, value);
        ids.insert(id);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn connection_victim_policy_matches_pinned_native() {
        let context = include_str!("../../../ci/conformance/rldp2_connection_policy_context.tsv");
        let expected = include_str!("../../../ci/conformance/rldp2_connection_policy_effects.tsv");
        let meta: serde_json::Value = serde_json::from_str(include_str!(
            "../../../ci/conformance/rldp2_connection_policy_metadata.json"
        ))
        .unwrap();
        assert_eq!(
            meta["reference_commit"],
            include_str!("../../../ci/conformance/REFERENCE").trim()
        );
        for (key, bytes) in [
            ("cases_sha256", context.as_bytes()),
            ("effects_sha256", expected.as_bytes()),
            (
                "probe_source_sha256",
                include_bytes!("../../../ci/conformance/rldp2_connection_policy_reference.cpp")
                    .as_slice(),
            ),
            (
                "runner_source_sha256",
                include_bytes!("../../../ci/conformance/rldp2_runtime_reference.py").as_slice(),
            ),
        ] {
            assert_eq!(meta[key], hex::encode(rtos_block::sha256_digest(bytes)), "{key}");
        }
        let identity = |value: u32| {
            let mut bytes = [0; 32];
            bytes[28..].copy_from_slice(&value.to_be_bytes());
            KeyId::from_data(bytes)
        };
        let now = Instant::now();
        let mut actual = String::new();
        for line in context.lines() {
            let v: Vec<u32> = line.split_whitespace().map(|v| v.parse().unwrap()).collect();
            assert_eq!(v.len(), 7);
            assert_eq!(v[1] + v[2], 4096);
            let mut state = State::default();
            for (local, count, expiry) in [(1, v[1], v[3]), (2, v[2], v[4])] {
                for peer in 0..count {
                    state
                        .order
                        .entry(identity(local))
                        .or_default()
                        .insert((now + Duration::from_secs(expiry as u64), identity(peer)));
                }
            }
            if v[6] != 0 {
                let order = state.order.get_mut(&identity(1)).unwrap();
                assert!(order.remove(&(now + Duration::from_secs(v[3] as u64), identity(0))));
                order.insert((now + Duration::from_secs(30), identity(0)));
            }
            let (local, remote) = state.victim(&identity(v[5])).unwrap();
            let local = u32::from_be_bytes(local.data()[28..].try_into().unwrap());
            let remote = u32::from_be_bytes(remote.data()[28..].try_into().unwrap());
            actual.push_str(&format!("{} {local} {remote}\n", v[0]));
        }
        assert_eq!(actual, expected);
    }
}
