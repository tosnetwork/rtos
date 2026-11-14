// Copyright 2017-2020 Telegram Systems LLP
// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Admission before unauthenticated ADNL decryption, following TOS1181.
//! Tickets own concurrency credit; completing work never refunds rate debt.
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::{Arc, Mutex, MutexGuard, OnceLock},
    time::Instant,
};

pub const MAX_PREAUTH_SOURCES: usize = 4096;

/// Charge IPv4 addresses or IPv6 /64s, independently of the source port.
/// Mapped IPv6 stays in the IPv6 family, as in td::IPAddress.
pub fn preauth_source(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V4(mut address) => {
            address.set_port(0);
            SocketAddr::V4(address)
        }
        SocketAddr::V6(address) => {
            let mut bytes = address.ip().octets();
            bytes[8..].fill(0);
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(bytes), 0, 0, 0))
        }
    }
}

/// Seconds on the process's monotonic clock. Explicit `_at` methods use this
/// same unit and permit deterministic clock-driven callers and tests.
pub fn monotonic_now() -> f64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_secs_f64()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigError(pub &'static str);
impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ConfigError {}

/// A burst of `capacity` units, replenishing one unit every `period` seconds.
pub struct RateLimiter {
    period: f64,
    emission_interval: f64,
    ready_at: f64,
}
impl RateLimiter {
    pub fn new(capacity: u32, period: f64) -> Result<Self, ConfigError> {
        if capacity == 0 || !period.is_finite() || period <= 0.0 {
            return Err(ConfigError("positive capacity and finite positive period required"));
        }
        let emission_interval = (capacity - 1) as f64 * period;
        if !emission_interval.is_finite() {
            return Err(ConfigError("rate interval overflows"));
        }
        Ok(Self { period, emission_interval, ready_at: -emission_interval })
    }
    pub fn take(&mut self) -> bool {
        self.take_at(monotonic_now())
    }
    pub fn take_at(&mut self, now: f64) -> bool {
        if !valid_time(now) {
            return false;
        }
        let minimum = now - self.emission_interval;
        if self.ready_at < minimum {
            self.ready_at = minimum;
        }
        if self.ready_at > now {
            return false;
        }
        self.ready_at += self.period;
        true
    }
    pub fn can_take(&self) -> bool {
        self.can_take_at(monotonic_now())
    }
    pub fn can_take_at(&self, now: f64) -> bool {
        valid_time(now) && self.ready_at.max(now - self.emission_interval) <= now
    }
    pub fn is_full(&self) -> bool {
        self.is_full_at(monotonic_now())
    }
    pub fn is_full_at(&self, now: f64) -> bool {
        valid_time(now) && self.ready_at < now - self.emission_interval
    }
    pub fn ready_at(&self) -> f64 {
        self.ready_at_at(monotonic_now())
    }
    pub fn ready_at_at(&self, now: f64) -> f64 {
        self.ready_at.max(now)
    }
    pub fn period(&self) -> f64 {
        self.period
    }
}

struct BudgetState {
    work: RateLimiter,
    in_flight: usize,
}
/// Shared across local identities/actor threads when used as the process pool.
pub struct DecryptBudget {
    state: Mutex<BudgetState>,
    limit: usize,
}
impl DecryptBudget {
    pub fn new(burst: u32, period: f64, in_flight_limit: usize) -> Result<Arc<Self>, ConfigError> {
        Ok(Arc::new(Self {
            state: Mutex::new(BudgetState { work: RateLimiter::new(burst, period)?, in_flight: 0 }),
            limit: in_flight_limit,
        }))
    }
    pub fn process_default() -> Arc<Self> {
        static PROCESS: OnceLock<Arc<DecryptBudget>> = OnceLock::new();
        PROCESS.get_or_init(|| Self::new(4096, 1.0 / 4096.0, 512).unwrap()).clone()
    }
    /// A fresh pool for one local ADNL identity, unlike the shared process pool.
    pub fn local_default() -> Arc<Self> {
        Self::new(256, 1.0 / 512.0, 64).unwrap()
    }
    pub fn in_flight(&self) -> usize {
        lock(&self.state).in_flight
    }
    fn acquire_with_clock(&self, clock: &mut impl FnMut() -> f64) -> bool {
        let mut state = lock(&self.state);
        // A full concurrency pool does not spend an additional rate token.
        if state.in_flight >= self.limit || !state.work.take_at(clock()) {
            return false;
        }
        state.in_flight += 1;
        true
    }
    fn release(&self) {
        let mut state = lock(&self.state);
        state.in_flight = state.in_flight.checked_sub(1).expect("owned decrypt budget underflow");
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    SourceLimit,
    RateLimited,
    ProcessBudget,
    LocalBudget,
    InvalidTime,
}
impl AdmissionError {
    pub fn code(self) -> &'static str {
        match self {
            Self::SourceLimit => "source_limit",
            Self::RateLimited => "rate_limited",
            Self::ProcessBudget => "process_budget",
            Self::LocalBudget => "local_budget",
            Self::InvalidTime => "invalid_time",
        }
    }
}
impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for AdmissionError {}

pub struct Source<Extra> {
    pub rate_limiter: RateLimiter,
    pub extra: Extra,
    in_flight: u64,
    idle: Option<IdleLinks>,
}
impl<Extra> Source<Extra> {
    pub fn in_flight(&self) -> u64 {
        self.in_flight
    }
}
#[derive(Clone, Copy)]
struct IdleLinks {
    previous: Option<IpAddr>,
    next: Option<IpAddr>,
}
struct GateState<Extra> {
    sources: BTreeMap<IpAddr, Source<Extra>>,
    idle_first: Option<IpAddr>,
    idle_last: Option<IpAddr>,
}
struct GateInner<Extra> {
    state: Mutex<GateState<Extra>>,
    max_sources: usize,
    burst: u32,
    period: f64,
}

/// Bounded per-source admission. An alive ticket pins its source entry even
/// if the gate handle is dropped. Idle entries are evicted least recently used.
pub struct PreauthGate<Extra: Default> {
    inner: Arc<GateInner<Extra>>,
}
impl<Extra: Default> PreauthGate<Extra> {
    pub fn new(max_sources: usize, burst: u32, period: f64) -> Result<Self, ConfigError> {
        if max_sources == 0 {
            return Err(ConfigError("positive source limit required"));
        }
        RateLimiter::new(burst, period)?;
        Ok(Self {
            inner: Arc::new(GateInner {
                state: Mutex::new(GateState {
                    sources: BTreeMap::new(),
                    idle_first: None,
                    idle_last: None,
                }),
                max_sources,
                burst,
                period,
            }),
        })
    }
    pub fn for_local_id() -> Self {
        Self::new(MAX_PREAUTH_SOURCES, 75, 0.33).unwrap()
    }
    pub fn len(&self) -> usize {
        lock(&self.inner.state).sources.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn contains(&self, address: SocketAddr) -> bool {
        lock(&self.inner.state).sources.contains_key(&preauth_source(address).ip())
    }
    /// Read diagnostics under the gate lock; the callback must not reenter it.
    pub fn for_each(&self, mut function: impl FnMut(SocketAddr, &Source<Extra>)) {
        let state = lock(&self.inner.state);
        for (&key, source) in &state.sources {
            function(SocketAddr::new(key, 0), source);
        }
    }
    pub fn admit(
        &self,
        address: SocketAddr,
        process: Arc<DecryptBudget>,
        local: Arc<DecryptBudget>,
    ) -> Result<Ticket<Extra>, AdmissionError> {
        self.admit_with_clock(address, process, local, &mut monotonic_now)
    }
    pub fn admit_at(
        &self,
        address: SocketAddr,
        process: Arc<DecryptBudget>,
        local: Arc<DecryptBudget>,
        now: f64,
    ) -> Result<Ticket<Extra>, AdmissionError> {
        if !valid_time(now) {
            return Err(AdmissionError::InvalidTime);
        }
        self.admit_with_clock(address, process, local, &mut || now)
    }
    fn admit_with_clock(
        &self,
        address: SocketAddr,
        process: Arc<DecryptBudget>,
        local: Arc<DecryptBudget>,
        clock: &mut impl FnMut() -> f64,
    ) -> Result<Ticket<Extra>, AdmissionError> {
        let key = preauth_source(address).ip();
        let mut state = lock(&self.inner.state);
        if !state.sources.contains_key(&key) {
            if state.sources.len() >= self.inner.max_sources {
                let old = state.idle_first.ok_or(AdmissionError::SourceLimit)?;
                unlink_idle(&mut state, old);
                state.sources.remove(&old);
            }
            state.sources.insert(
                key,
                Source {
                    rate_limiter: RateLimiter::new(self.inner.burst, self.inner.period).unwrap(),
                    extra: Extra::default(),
                    in_flight: 0,
                    idle: None,
                },
            );
            push_idle(&mut state, key);
        } else if state.sources[&key].in_flight == 0 {
            unlink_idle(&mut state, key);
            push_idle(&mut state, key);
        }
        let source = state.sources.get_mut(&key).unwrap();
        if !source.rate_limiter.take_at(clock()) {
            return Err(AdmissionError::RateLimited);
        }
        if !process.acquire_with_clock(clock) {
            return Err(AdmissionError::ProcessBudget);
        }
        if !local.acquire_with_clock(clock) {
            process.release();
            return Err(AdmissionError::LocalBudget);
        }
        let was_idle = source.in_flight == 0;
        source.in_flight += 1;
        if was_idle {
            unlink_idle(&mut state, key);
        }
        Ok(Ticket { gate: self.inner.clone(), key, process, local })
    }
    /// The predicate runs under the gate lock and must not reenter the gate.
    pub fn erase_idle_if(&self, mut predicate: impl FnMut(&Source<Extra>) -> bool) {
        let mut state = lock(&self.inner.state);
        let mut next = state.idle_first;
        while let Some(key) = next {
            next = state.sources[&key].idle.unwrap().next;
            if predicate(&state.sources[&key]) {
                unlink_idle(&mut state, key);
                state.sources.remove(&key);
            }
        }
    }
}

/// Non-cloneable ownership of both decrypt pools and one live source entry.
pub struct Ticket<Extra: Default> {
    gate: Arc<GateInner<Extra>>,
    key: IpAddr,
    process: Arc<DecryptBudget>,
    local: Arc<DecryptBudget>,
}
impl<Extra: Default> Ticket<Extra> {
    pub fn source(&self) -> SocketAddr {
        SocketAddr::new(self.key, 0)
    }
    /// Access per-source state only while holding admission. The closure runs
    /// under the gate lock and must not reenter this gate.
    pub fn with_source<R>(&self, function: impl FnOnce(&mut Source<Extra>) -> R) -> R {
        let mut state = lock(&self.gate.state);
        function(state.sources.get_mut(&self.key).expect("ticket source remains pinned"))
    }
}
impl<Extra: Default> Drop for Ticket<Extra> {
    fn drop(&mut self) {
        self.local.release();
        self.process.release();
        let mut state = lock(&self.gate.state);
        let source = state.sources.get_mut(&self.key).expect("ticket source remains pinned");
        source.in_flight = source.in_flight.checked_sub(1).expect("owned source budget underflow");
        if source.in_flight == 0 {
            push_idle(&mut state, self.key);
        }
    }
}

fn valid_time(now: f64) -> bool {
    now.is_finite() && now >= 0.0
}
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A user callback may panic while holding the gate. Accounting is private;
    // recover the state so ticket unwinding can still release its credits.
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
fn unlink_idle<Extra>(state: &mut GateState<Extra>, key: IpAddr) {
    let links =
        state.sources.get_mut(&key).unwrap().idle.take().expect("idle source has one LRU entry");
    if let Some(previous) = links.previous {
        state.sources.get_mut(&previous).unwrap().idle.as_mut().unwrap().next = links.next;
    } else {
        state.idle_first = links.next;
    }
    if let Some(next) = links.next {
        state.sources.get_mut(&next).unwrap().idle.as_mut().unwrap().previous = links.previous;
    } else {
        state.idle_last = links.previous;
    }
}
fn push_idle<Extra>(state: &mut GateState<Extra>, key: IpAddr) {
    let previous = state.idle_last;
    if let Some(previous) = previous {
        state.sources.get_mut(&previous).unwrap().idle.as_mut().unwrap().next = Some(key);
    } else {
        state.idle_first = Some(key);
    }
    state.idle_last = Some(key);
    let source = state.sources.get_mut(&key).unwrap();
    assert!(source.idle.is_none(), "source has no duplicate LRU entry");
    source.idle = Some(IdleLinks { previous, next: None });
}
