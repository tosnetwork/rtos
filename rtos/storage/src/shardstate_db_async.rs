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
#[cfg(feature = "telemetry")]
use crate::StorageTelemetry;
use crate::{
    cell_db::CellByHashStorageAdapter,
    db::{
        rocksdb::{RocksDb, RocksDbTable},
        DbKey,
    },
    dynamic_boc_rc_db::{AsyncCellsStorageAdapter, DynamicBocDb},
    error::StorageError,
    traits::Serializable,
    StorageAlloc, TARGET,
};
use rtos_block::{
    error, fail, BlockIdExt, Cell, CellsFactory, CellsStorage, Result, UInt256, UnixTime,
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        atomic::{AtomicU32, AtomicU8, Ordering},
        Arc,
    },
    time::Duration,
};

/// The order in which states were stored, as the state GC sees it. States
/// are collected oldest first, and collection stops at the oldest state the
/// policy keeps, so a later state is never collected before an earlier one.
pub trait StateInsertionOrder: Send + Sync {
    /// Whether `id` lies before the oldest stored state the policy keeps,
    /// as of the last collection pass. A state that is not stored counts as
    /// collected.
    fn in_collectable_prefix(&self, id: &BlockIdExt) -> bool;
}

pub trait AllowStateGcResolver: Send + Sync {
    fn allow_state_gc(&self, block_id: &BlockIdExt, save_utime: u64, gc_utime: u64)
        -> Result<bool>;

    /// Whether the collection policy alone lets `block_id` go, before read
    /// pins and repair custody are considered. Collection stops at the
    /// oldest stored state for which this is false.
    fn state_gc_eligible(&self, block_id: &BlockIdExt) -> Result<bool> {
        self.allow_state_gc(block_id, 0, u64::MAX)
    }

    /// Gives the resolver the store order the collection follows.
    fn attach_insertion_order(&self, _order: Arc<dyn StateInsertionOrder>) {}

    /// Captures the progress that will authorize the next GC cycle and
    /// returns its ticket, or `None` when this resolver has no such gate.
    fn stage_gc_progress(&self) -> Option<u64> {
        None
    }

    /// Makes the progress staged under `ticket` the one deletion decisions
    /// use. The GC worker calls this only after a barrier, issued after the
    /// staging, has made every write that progress depends on durable.
    fn commit_gc_progress(&self, _ticket: u64) {}

    /// From now on, deletion decisions use committed progress only.
    fn require_durable_progress(&self) {}
}

/// Barrier the state GC runs between staging and committing its progress.
pub type GcProgressBarrier =
    Arc<dyn Fn() -> futures::future::BoxFuture<'static, Result<()>> + Send + Sync>;

/// Store order of the indexed states: a sequence number per state, assigned
/// when its index entry is first written and removed with it.
#[derive(Default)]
struct InsertionOrderMap {
    by_seq: BTreeMap<u64, BlockIdExt>,
    by_id: HashMap<BlockIdExt, u64>,
    next_seq: u64,
    /// Sequence number of the oldest state the last pass kept by policy;
    /// every older state is collectable. Zero before the first pass.
    collectable_end: u64,
}

pub(crate) struct InsertionOrder(parking_lot::RwLock<InsertionOrderMap>);

impl InsertionOrder {
    fn seq_key(seq: u64) -> [u8; 8] {
        seq.to_be_bytes()
    }

    fn insert(&self, seq: u64, id: BlockIdExt) -> Result<()> {
        let mut map = self.0.write();
        map.next_seq = map
            .next_seq
            .max(seq.checked_add(1).ok_or_else(|| error!("State store order sequence exhausted"))?);
        if let Some(old) = map.by_id.insert(id.clone(), seq) {
            map.by_seq.remove(&old);
        }
        map.by_seq.insert(seq, id);
        Ok(())
    }

    fn remove(&self, id: &BlockIdExt) -> Option<u64> {
        let mut map = self.0.write();
        let seq = map.by_id.remove(id)?;
        map.by_seq.remove(&seq);
        Some(seq)
    }

    fn reserve(&self) -> Result<u64> {
        let map = self.0.read();
        Ok(map.next_seq)
    }

    fn seq_of(&self, id: &BlockIdExt) -> Option<u64> {
        self.0.read().by_id.get(id).copied()
    }

    fn snapshot(&self) -> Vec<(u64, BlockIdExt)> {
        self.0.read().by_seq.iter().map(|(seq, id)| (*seq, id.clone())).collect()
    }

    fn set_collectable_end(&self, end: u64) {
        self.0.write().collectable_end = end;
    }
}

impl StateInsertionOrder for InsertionOrder {
    fn in_collectable_prefix(&self, id: &BlockIdExt) -> bool {
        let map = self.0.read();
        match map.by_id.get(id) {
            Some(seq) => *seq < map.collectable_end,
            None => true,
        }
    }
}

pub(crate) struct DbEntry {
    // Because key in db is not a full BlockIdExt it's need to store it here to use while GC.
    pub block_id: BlockIdExt,
    pub cell_id: UInt256,
    pub save_utime: u64,
}

impl DbEntry {
    pub fn with_params(block_id: BlockIdExt, cell_id: UInt256, save_utime: u64) -> Self {
        Self { block_id, cell_id, save_utime }
    }
}

impl Serializable for DbEntry {
    const SIZE: usize = BlockIdExt::SIZE + 40;
    type Bytes = [u8; Self::SIZE];
    fn serialize(&self) -> Self::Bytes {
        let mut ret = [0u8; Self::SIZE];
        ret[..BlockIdExt::SIZE].copy_from_slice(&self.block_id.serialize());
        ret[BlockIdExt::SIZE..BlockIdExt::SIZE + 32].copy_from_slice(self.cell_id.key());
        ret[BlockIdExt::SIZE + 32..].copy_from_slice(&self.save_utime.serialize());
        ret
    }
    fn deserialize_checked(data: &[u8]) -> Result<Self> {
        let block_id = BlockIdExt::deserialize_checked(data)?;
        let cell_id = UInt256::from(&data[BlockIdExt::SIZE..BlockIdExt::SIZE + 32]);
        let save_utime = u64::deserialize_checked(&data[BlockIdExt::SIZE + 32..])?;
        let ret = Self { block_id, cell_id, save_utime };
        Ok(ret)
    }
}

pub enum Job {
    PutState(Cell, BlockIdExt),
    DeleteState(BlockIdExt),
}

#[async_trait::async_trait]
pub trait Callback: Sync + Send {
    /// Invoked only on successful apply; failures are retried, stop skips it.
    async fn invoke(&self, job: Job);
}

pub struct SsNotificationCallback(tokio::sync::Notify);

#[async_trait::async_trait]
impl Callback for SsNotificationCallback {
    async fn invoke(&self, _job: Job) {
        self.0.notify_one();
    }
}

impl SsNotificationCallback {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(tokio::sync::Notify::new()))
    }
    pub async fn wait(&self) {
        self.0.notified().await;
    }
}

impl Job {
    pub fn block_id(&self) -> &BlockIdExt {
        match self {
            Job::PutState(_cell, id) => id,
            Job::DeleteState(id) => id,
        }
    }
}

#[derive(serde::Deserialize, serde::Serialize, Clone, Debug)]
pub struct CellsDbConfig {
    #[serde(deserialize_with = "CellsDbConfig::deserialize_states_db_queue_len")]
    pub states_db_queue_len: u32,
    #[serde(default, skip_serializing, rename = "prefill_cells_counters")]
    _prefill_cells_counters: Option<bool>,
    pub cells_cache_size_bytes: u64,
    pub counters_cache_size_bytes: u64,
    #[serde(default = "CellsDbConfig::default_cells_lru_cache_capacity")]
    pub cells_lru_cache_capacity: usize,
    #[serde(default = "CellsDbConfig::default_counters_lru_cache_capacity")]
    pub counters_lru_cache_capacity: usize,
}

impl CellsDbConfig {
    fn default_cells_lru_cache_capacity() -> usize {
        5_000_000
    }
    fn default_counters_lru_cache_capacity() -> usize {
        5_000_000
    }
    fn deserialize_states_db_queue_len<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> std::result::Result<u32, D::Error> {
        let v = <u32 as serde::Deserialize>::deserialize(d)?;
        if v < Self::min_states_db_queue_len() {
            return Err(serde::de::Error::custom(format!(
                "states_db_queue_len must be >= {}, got {v}",
                Self::min_states_db_queue_len()
            )));
        }
        Ok(v)
    }
    fn min_states_db_queue_len() -> u32 {
        100
    }
}

impl Default for CellsDbConfig {
    fn default() -> Self {
        Self {
            states_db_queue_len: 1000,
            _prefill_cells_counters: None,
            cells_cache_size_bytes: 2_000_000_000,
            counters_cache_size_bytes: 1_000_000_000,
            cells_lru_cache_capacity: Self::default_cells_lru_cache_capacity(),
            counters_lru_cache_capacity: Self::default_counters_lru_cache_capacity(),
        }
    }
}

enum StateCommand {
    BoundedPut {
        id: BlockIdExt,
        root: Cell,
        limits: rtos_block::merkle_apply_budget::MerkleApplyLimits,
        budget: Arc<dyn rtos_block::merkle_apply_budget::MerkleApplyBudget>,
        reply: tokio::sync::oneshot::Sender<Result<()>>,
        observer: crate::durability::SyncObservation,
    },
    Work(Job, Option<Arc<dyn Callback>>),
    Barrier(tokio::sync::oneshot::Sender<Result<()>>, crate::durability::SyncObservation),
}

#[cfg(any(test, feature = "integration-test-support"))]
#[derive(Default)]
struct TestGcBatchProgress {
    started: u64,
    completed: u64,
    watched: Option<BlockIdExt>,
    watched_epoch: Option<u64>,
}

type StateTaskJoin =
    futures::future::Shared<futures::future::BoxFuture<'static, std::result::Result<(), Arc<str>>>>;
#[derive(Default)]
struct StateTaskOwners {
    closed: bool,
    worker: Option<StateTaskJoin>,
    gc: Option<StateTaskJoin>,
}
fn state_task_join(task: tokio::task::JoinHandle<()>) -> StateTaskJoin {
    use futures::FutureExt;
    task.map(|result| result.map_err(|error| Arc::<str>::from(error.to_string()))).boxed().shared()
}

pub struct ShardStateDb {
    shardstate_db: Arc<RocksDbTable<BlockIdExt>>,
    order_db: Arc<RocksDbTable<Vec<u8>>>,
    order: Arc<InsertionOrder>,
    dynamic_boc_db: Arc<DynamicBocDb>,
    storer: tokio::sync::mpsc::UnboundedSender<StateCommand>,
    write_failure: tokio::sync::watch::Sender<Option<String>>,
    #[cfg(test)]
    late_index_gate: std::sync::Mutex<Option<crate::durability::LateIndexGate>>,
    #[cfg(test)]
    ordinary_index_attempts: std::sync::atomic::AtomicUsize,
    bounded_read_gate: std::sync::RwLock<()>,
    in_queue: AtomicU32,
    stop: Arc<AtomicU8>,
    task_owners: std::sync::Mutex<StateTaskOwners>,
    config: CellsDbConfig,
    gc_resolver: tokio::sync::OnceCell<Arc<dyn AllowStateGcResolver>>,
    #[cfg(any(test, feature = "integration-test-support"))]
    test_gc_batches: std::sync::Mutex<TestGcBatchProgress>,
    #[cfg(feature = "telemetry")]
    telemetry: Arc<StorageTelemetry>,
}

impl ShardStateDb {
    const MASK_GC: u8 = 0x01;
    const MASK_WORKER: u8 = 0x02;
    pub(crate) const MASK_STOPPED: u8 = 0x80;
    const GC_QUEUE_POLL_INTERVAL_MS: u64 = 10_000;
    const PUT_QUEUE_POLL_INTERVAL_MS: u64 = 100;
    const ORDER_CF_SUFFIX: &'static str = "_order";

    /// Reads the persisted store order. An indexed state without an order
    /// record is appended after the recorded ones, oldest save time first;
    /// an order record without an indexed state is dropped.
    fn load_insertion_order(
        shardstate_db: &RocksDbTable<BlockIdExt>,
        order_db: &RocksDbTable<Vec<u8>>,
    ) -> Result<InsertionOrder> {
        let order = InsertionOrder(parking_lot::RwLock::new(InsertionOrderMap::default()));
        let mut stale = Vec::new();
        order_db.for_each(&mut |key, value| {
            let seq = <[u8; 8]>::try_from(key)
                .map(u64::from_be_bytes)
                .map_err(|_| error!("Malformed state store order key"))?;
            let id = BlockIdExt::deserialize(value)?;
            if shardstate_db.contains(&id)? {
                order.insert(seq, id)?;
            } else {
                stale.push(key.to_vec());
            }
            Ok(true)
        })?;
        for key in stale {
            order_db.delete_raw(&key)?;
        }
        let mut missing = Vec::new();
        shardstate_db.for_each(&mut |_key, value| {
            let entry = DbEntry::deserialize(value)?;
            if order.seq_of(&entry.block_id).is_none() {
                missing.push((entry.save_utime, entry.block_id));
            }
            Ok(true)
        })?;
        missing.sort_by(|(a_time, a_id), (b_time, b_id)| {
            (
                a_time,
                a_id.seq_no(),
                a_id.shard().workchain_id(),
                a_id.shard().shard_prefix_with_tag(),
            )
                .cmp(&(
                    b_time,
                    b_id.seq_no(),
                    b_id.shard().workchain_id(),
                    b_id.shard().shard_prefix_with_tag(),
                ))
        });
        for (_, id) in missing {
            let seq = order.reserve()?;
            order_db.put_raw(&InsertionOrder::seq_key(seq), &id.serialize())?;
            order.insert(seq, id)?;
        }
        Ok(order)
    }

    /// The store order the state GC follows.
    pub fn insertion_order(&self) -> Arc<dyn StateInsertionOrder> {
        self.order.clone()
    }

    /// Indexed states oldest first, as stored.
    pub fn states_in_store_order(&self) -> Vec<BlockIdExt> {
        self.order.snapshot().into_iter().map(|(_, id)| id).collect()
    }

    /// One collection pass: the states in store order up to the oldest one
    /// the policy keeps. That boundary is published to readers before the
    /// candidates are returned.
    fn collectable_prefix(&self, gc_resolver: &dyn AllowStateGcResolver) -> Vec<BlockIdExt> {
        let entries = self.order.snapshot();
        let mut end = entries.last().map_or(0, |(seq, _)| seq.saturating_add(1));
        let mut prefix = Vec::new();
        for (seq, id) in entries {
            match gc_resolver.state_gc_eligible(&id) {
                Ok(true) => prefix.push(id),
                Ok(false) => {
                    end = seq;
                    break;
                }
                Err(e) => {
                    log::warn!(target: TARGET, "ShardStateDb GC: eligibility of {id}: {e}");
                    end = seq;
                    break;
                }
            }
        }
        self.order.set_collectable_end(end);
        prefix
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: Arc<RocksDb>,
        shardstate_db_cf: &str,
        cell_db_cf: &str,
        counters_cf_name: &str,
        config: CellsDbConfig,
        #[cfg(feature = "telemetry")] telemetry: Arc<StorageTelemetry>,
        allocated: Arc<StorageAlloc>,
    ) -> Result<Arc<Self>> {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();

        let dynamic_boc_db = DynamicBocDb::with_db(
            db.clone(),
            cell_db_cf,
            counters_cf_name,
            &config,
            #[cfg(feature = "telemetry")]
            telemetry.clone(),
            allocated.clone(),
        )?;

        let shardstate_db = Arc::new(RocksDbTable::with_db(db.clone(), shardstate_db_cf, true)?);
        let order_db = Arc::new(RocksDbTable::with_db(
            db.clone(),
            format!("{shardstate_db_cf}{}", Self::ORDER_CF_SUFFIX),
            true,
        )?);
        let order = Arc::new(Self::load_insertion_order(&shardstate_db, &order_db)?);
        let ss_db = Arc::new(Self {
            shardstate_db,
            order_db,
            order,
            dynamic_boc_db: Arc::new(dynamic_boc_db),
            storer: sender,
            bounded_read_gate: std::sync::RwLock::new(()),
            write_failure: tokio::sync::watch::channel(None).0,
            #[cfg(test)]
            late_index_gate: std::sync::Mutex::new(None),
            #[cfg(test)]
            ordinary_index_attempts: std::sync::atomic::AtomicUsize::new(0),
            in_queue: AtomicU32::new(0),
            stop: Arc::new(AtomicU8::new(0)),
            task_owners: Default::default(),
            config,
            gc_resolver: tokio::sync::OnceCell::new(),
            #[cfg(any(test, feature = "integration-test-support"))]
            test_gc_batches: Default::default(),
            #[cfg(feature = "telemetry")]
            telemetry,
        });

        let worker = tokio::spawn({
            let ss_db = ss_db.clone();
            async move {
                ss_db.worker(receiver).await;
            }
        });

        ss_db.task_owners.lock().unwrap().worker = Some(state_task_join(worker));
        Ok(ss_db)
    }

    pub fn start_gc(
        self: Arc<Self>,
        gc_resolver: Arc<dyn AllowStateGcResolver>,
        run_interval_adjustable_sec: Arc<AtomicU32>,
    ) {
        self.start_gc_with_progress_barrier(gc_resolver, run_interval_adjustable_sec, None)
    }

    /// Starts the state GC. With `progress_barrier`, every collection cycle
    /// first stages the resolver's progress, runs the barrier and commits the
    /// staged progress only if the barrier succeeded; deletion decisions use
    /// committed progress only. A failed barrier skips the cycle.
    pub fn start_gc_with_progress_barrier(
        self: Arc<Self>,
        gc_resolver: Arc<dyn AllowStateGcResolver>,
        run_interval_adjustable_sec: Arc<AtomicU32>,
        progress_barrier: Option<GcProgressBarrier>,
    ) {
        // Register the actual owner under the same lock that closes admission.
        // A stop concurrent with start_gc either joins it or prevents its spawn.
        let owner = self.clone();
        let mut tasks = owner.task_owners.lock().unwrap();
        if tasks.closed {
            return;
        }
        if progress_barrier.is_some() {
            gc_resolver.require_durable_progress();
        }
        gc_resolver.attach_insertion_order(self.order.clone());
        if self.gc_resolver.set(gc_resolver.clone()).is_err() {
            log::error!(target: TARGET, "INTERNAL ERROR: Attempt to set GC resolver twice");
            return;
        }
        self.stop.fetch_or(Self::MASK_GC, Ordering::Relaxed);
        let gc = tokio::spawn(async move {
            fn check_and_stop(stop: &AtomicU8) -> bool {
                if (stop.load(Ordering::Relaxed) & ShardStateDb::MASK_STOPPED) != 0 {
                    stop.fetch_and(!ShardStateDb::MASK_GC, Ordering::Relaxed);
                    log::warn!(target: TARGET, "ShardStateDb GC: stopped");
                    true
                } else {
                    false
                }
            }

            async fn sleep_nicely(stop: &AtomicU8, mut sleep_for_ms: u64) -> bool {
                const TIMEOUT_STEP: u64 = 1000;
                loop {
                    let interval =
                        if sleep_for_ms > TIMEOUT_STEP { TIMEOUT_STEP } else { sleep_for_ms };
                    tokio::time::sleep(Duration::from_millis(interval)).await;
                    if check_and_stop(stop) {
                        return false;
                    }
                    if sleep_for_ms <= TIMEOUT_STEP {
                        return true;
                    }
                    sleep_for_ms -= TIMEOUT_STEP;
                }
            }

            async fn wait_queue(in_queue: &AtomicU32, stop: &AtomicU8, max_queue_len: u32) -> bool {
                loop {
                    let in_queue = in_queue.load(Ordering::Relaxed);
                    metrics::gauge!("rtos_node_db_shardstate_queue_size").set(in_queue as f64);
                    if in_queue >= max_queue_len / 2 {
                        log::warn!(
                            target: TARGET,
                            "ShardStateDb GC: queue is half full (length: {}), waiting...",
                            in_queue
                        );
                        if !sleep_nicely(stop, ShardStateDb::GC_QUEUE_POLL_INTERVAL_MS).await {
                            return false;
                        }
                    } else {
                        return true;
                    }
                }
            }

            log::debug!(target: TARGET, "ShardStateDb GC: started worker");

            let mut to_delete: Vec<BlockIdExt> = vec![];
            loop {
                let run_gc_interval = run_interval_adjustable_sec.load(Ordering::Relaxed) as u64;
                if to_delete.is_empty() {
                    log::debug!(target: TARGET, "ShardStateDb GC: waiting for {run_gc_interval}sec...");
                    if !sleep_nicely(&self.stop, run_gc_interval * 1000).await {
                        return;
                    }
                } else {
                    #[cfg(any(test, feature = "integration-test-support"))]
                    let batch_epoch = {
                        let mut progress = self.test_gc_batches.lock().unwrap();
                        progress.started += 1;
                        let epoch = progress.started;
                        if progress.watched.as_ref().is_some_and(|id| to_delete.contains(id)) {
                            progress.watched_epoch = Some(epoch);
                        }
                        epoch
                    };
                    while let Some(id) = to_delete.pop() {
                        if !wait_queue(&self.in_queue, &self.stop, self.config.states_db_queue_len)
                            .await
                        {
                            return;
                        }
                        let in_queue = self.in_queue.fetch_add(1, Ordering::Relaxed) + 1;
                        metrics::gauge!("rtos_node_db_shardstate_queue_size").set(in_queue as f64);

                        let now = std::time::Instant::now();
                        let callback = SsNotificationCallback::new();
                        if self
                            .storer
                            .send(StateCommand::Work(
                                Job::DeleteState(id.clone()),
                                Some(callback.clone()),
                            ))
                            .is_err()
                        {
                            log::error!(
                                target: TARGET,
                                "Can't send state to delete from db, id {}",
                                id
                            );
                        } else {
                            #[cfg(feature = "telemetry")]
                            self.telemetry
                                .shardstates_queue
                                .update(std::cmp::max(0, in_queue) as u64);
                            log::trace!(target: TARGET, "ShardStateDb GC: in_queue {}", in_queue);

                            loop {
                                let result = tokio::time::timeout(
                                    Duration::from_millis(1000),
                                    callback.wait(),
                                )
                                .await;
                                if let Err(tokio::time::error::Elapsed { .. }) = result {
                                    if check_and_stop(&self.stop) {
                                        return;
                                    }
                                } else {
                                    break;
                                }
                            }

                            let elapsed = now.elapsed();
                            metrics::histogram!("rtos_node_db_shardstate_gc_seconds")
                                .record(elapsed);
                            // Like the reference collector, the next state goes
                            // as soon as this one is done.
                            if check_and_stop(&self.stop) {
                                return;
                            }
                        }
                    }
                    // All IDs in this exact batch have completed their actual worker
                    // callbacks. Publish only here, never after an individual commit.
                    #[cfg(any(test, feature = "integration-test-support"))]
                    {
                        self.test_gc_batches.lock().unwrap().completed = batch_epoch;
                    }
                }

                if let Some(barrier) = &progress_barrier {
                    // Deletion may rely only on progress whose prerequisite
                    // writes were durable before this cycle selects anything.
                    let ticket = gc_resolver.stage_gc_progress();
                    match barrier().await {
                        Ok(()) => {
                            if let Some(ticket) = ticket {
                                gc_resolver.commit_gc_progress(ticket);
                            }
                        }
                        Err(e) => {
                            log::warn!(
                                target: TARGET,
                                "ShardStateDb GC: progress barrier failed, skipping cycle: {e}"
                            );
                            continue;
                        }
                    }
                }

                log::debug!(target: TARGET, "ShardStateDb GC: collecting states to delete");

                // States go oldest stored first, and the pass stops at the
                // oldest one the policy keeps: a later state is never
                // collected while an earlier one is kept.
                let prefix = self.collectable_prefix(gc_resolver.as_ref());
                let mut kept = 0;
                for id in prefix {
                    if check_and_stop(&self.stop) {
                        return;
                    }
                    let save_utime = match self.shardstate_db.try_get(&id) {
                        Ok(Some(value)) => match DbEntry::deserialize(&value) {
                            Ok(entry) => entry.save_utime,
                            Err(e) => {
                                log::warn!(target: TARGET, "ShardStateDb GC: index of {id}: {e}");
                                kept += 1;
                                continue;
                            }
                        },
                        Ok(None) => continue,
                        Err(e) => {
                            log::warn!(target: TARGET, "ShardStateDb GC: index of {id}: {e}");
                            kept += 1;
                            continue;
                        }
                    };
                    match gc_resolver.allow_state_gc(&id, save_utime, UnixTime::now()) {
                        Ok(true) => {
                            log::debug!(target: TARGET, "ShardStateDb GC: delete  id {}", id);
                            to_delete.push(id);
                        }
                        Ok(false) => {
                            // Held by a reader or repair custody: retried on a
                            // later pass, the order of the rest is unchanged.
                            kept += 1;
                            log::debug!(target: TARGET, "ShardStateDb GC: keep  id {}", id);
                        }
                        Err(e) => {
                            kept += 1;
                            log::warn!(
                                target: TARGET,
                                "ShardStateDb  allow_state_gc  id {}  error {}",
                                id, e
                            )
                        }
                    }
                }

                if check_and_stop(&self.stop) {
                    return;
                }

                log::info!(
                    target: TARGET,
                    "ShardStateDb GC: collected {} states to delete, kept {}",
                    to_delete.len(), kept
                );

                // Deleted from the end of the vector: oldest stored first.
                to_delete.reverse();
            }
        });
        tasks.gc = Some(state_task_join(gc));
    }

    pub async fn stop(&self) -> Result<()> {
        let (worker, gc) = {
            let mut tasks = self.task_owners.lock().unwrap();
            tasks.closed = true;
            self.stop.fetch_or(Self::MASK_STOPPED, Ordering::Relaxed);
            (tasks.worker.clone(), tasks.gc.clone())
        };
        // Shared joins survive cancellation of any individual stop waiter and
        // retain failures for subsequent callers. Join completion proves the
        // task's captured DB ownership has actually been released.
        let mut failures = Vec::new();
        for task in [worker, gc].into_iter().flatten() {
            if let Err(error) = task.await {
                failures.push(error.to_string());
            }
        }
        self.stop.store(Self::MASK_STOPPED, Ordering::Relaxed);
        if failures.is_empty() {
            Ok(())
        } else {
            Err(error!("State storage tasks failed: {}", failures.join("; ")))
        }
    }

    #[cfg(test)]
    pub(crate) async fn test_worker_completion(&self) -> std::result::Result<(), Arc<str>> {
        let worker = self.task_owners.lock().unwrap().worker.clone().unwrap();
        worker.await
    }

    pub fn is_gc_run(&self) -> bool {
        self.stop.load(Ordering::Relaxed) & Self::MASK_GC != 0
    }

    pub fn shardstate_db(&self) -> Arc<RocksDbTable<BlockIdExt>> {
        Arc::clone(&self.shardstate_db)
    }

    #[cfg(test)]
    pub fn enum_shardstate_db(&self) -> Result<()> {
        self.shardstate_db.for_each(&mut |_key, val| {
            let db_entry = DbEntry::deserialize(val)?;
            println!("{}", db_entry.block_id);
            Ok(true)
        })?;
        Ok(())
    }

    pub async fn sync_pending(&self) -> Result<()> {
        self.sync_pending_observed(None).await
    }
    pub async fn sync_pending_observed(
        &self,
        observer: crate::durability::SyncObservation,
    ) -> Result<()> {
        let mut failure = self.write_failure.subscribe();
        if let Some(error) = failure.borrow().as_ref() {
            fail!("State writer has a failed operation: {error}");
        }
        let (send, receive) = tokio::sync::oneshot::channel();
        self.storer
            .send(StateCommand::Barrier(send, observer))
            .map_err(|_| error!("State writer stopped"))?;
        tokio::select! {
            result = receive => result.map_err(|_| error!("State writer failed during durability barrier"))?,
            _ = failure.changed() => Err(error!("State writer failed before durability barrier: {:?}", *failure.borrow())),
        }
    }

    /// Execute a reservation only while the physical state index is absent.
    /// The same gate excludes actual deletion and both state writer paths.
    pub fn with_absent_state<T>(
        &self,
        id: &BlockIdExt,
        reserve: impl FnOnce() -> Result<T>,
    ) -> Result<Option<T>> {
        let _gate =
            self.bounded_read_gate.write().map_err(|_| error!("State write gate poisoned"))?;
        if let Some(reason) = self.write_failure.borrow().as_ref() {
            fail!("State writer failed: {reason}");
        }
        if self.shardstate_db.contains(id)? {
            Ok(None)
        } else {
            reserve().map(Some)
        }
    }

    /// Admit and enqueue one bounded state save. The command owns its budget
    /// until the actual serialized writer and WAL sync finish, even if this
    /// observation future is dropped. Budget failures are never retried through
    /// the ordinary writer.
    pub async fn put_bounded(
        &self,
        id: &BlockIdExt,
        root: Cell,
        limits: rtos_block::merkle_apply_budget::MerkleApplyLimits,
        budget: Arc<dyn rtos_block::merkle_apply_budget::MerkleApplyBudget>,
    ) -> Result<()> {
        self.put_bounded_observed(id, root, limits, budget, None).await
    }

    pub async fn put_bounded_observed(
        &self,
        id: &BlockIdExt,
        root: Cell,
        limits: rtos_block::merkle_apply_budget::MerkleApplyLimits,
        budget: Arc<dyn rtos_block::merkle_apply_budget::MerkleApplyBudget>,
        observer: crate::durability::SyncObservation,
    ) -> Result<()> {
        budget.workspace(1024)?;
        while self.in_queue.load(Ordering::Relaxed) >= self.config.states_db_queue_len {
            if self.stop.load(Ordering::Relaxed) & Self::MASK_STOPPED != 0 {
                fail!("Stopped");
            }
            tokio::time::sleep(Duration::from_millis(Self::PUT_QUEUE_POLL_INTERVAL_MS)).await;
        }
        if self.stop.load(Ordering::Relaxed) & Self::MASK_STOPPED != 0 {
            fail!("Stopped");
        }
        let (reply, receiver) = tokio::sync::oneshot::channel();
        self.in_queue.fetch_add(1, Ordering::Relaxed);
        if self
            .storer
            .send(StateCommand::BoundedPut {
                id: id.clone(),
                root,
                limits,
                budget,
                reply,
                observer,
            })
            .is_err()
        {
            self.in_queue.fetch_sub(1, Ordering::Relaxed);
            fail!("Bounded state writer stopped");
        }
        receiver.await.map_err(|e| error!("Bounded state writer failed: {e}"))?
    }

    pub async fn put(
        &self,
        id: &BlockIdExt,
        state_root: Cell,
        callback: Option<Arc<dyn Callback>>,
    ) -> Result<()> {
        let root_id = state_root.repr_hash().clone();
        log::debug!(
            target: TARGET,
            "ShardStateDb::put  id {}  root_cell_id {:x}",
            id, root_id
        );
        let mut attempt = 0usize;
        loop {
            let in_queue = self.in_queue.load(Ordering::Relaxed);
            if in_queue >= self.config.states_db_queue_len {
                if attempt % 10 == 0 {
                    log::warn!(
                        target: TARGET,
                        "ShardStateDb::put id {id}  root_cell_id {root_id:x} \
                        waiting for queue (current queue length: {in_queue})"
                    );
                }
                tokio::time::sleep(Duration::from_millis(Self::PUT_QUEUE_POLL_INTERVAL_MS)).await;
                attempt += 1;

                if self.stop.load(Ordering::Relaxed) & Self::MASK_STOPPED != 0 {
                    fail!("Stopped");
                }
            } else {
                break;
            }
        }

        let in_queue = self.in_queue.fetch_add(1, Ordering::Relaxed) + 1;

        self.storer
            .send(StateCommand::Work(Job::PutState(state_root, id.clone()), callback))
            .map_err(|_| {
                error!("Can't send state to put into db, id {}, root {:x}", id, root_id)
            })?;

        metrics::gauge!("rtos_node_db_shardstate_queue_size").set(in_queue as f64);
        #[cfg(feature = "telemetry")]
        self.telemetry.shardstates_queue.update(std::cmp::max(0, in_queue) as u64);
        log::trace!("ShardStateDb put: in_queue {}", in_queue);

        Ok(())
    }

    /// Arm before making the watched state eligible for GC. A batch already
    /// in progress cannot satisfy this observation retroactively.
    #[cfg(any(test, feature = "integration-test-support"))]
    pub fn test_watch_gc_batch(&self, id: &BlockIdExt) {
        let mut progress = self.test_gc_batches.lock().unwrap();
        progress.watched = Some(id.clone());
        progress.watched_epoch = None;
    }

    #[cfg(any(test, feature = "integration-test-support"))]
    pub fn test_watched_gc_batch_completed(&self) -> bool {
        let progress = self.test_gc_batches.lock().unwrap();
        progress.watched_epoch.is_some_and(|epoch| progress.completed >= epoch)
    }

    /// Physical record presence, independent of logical GC eligibility.
    pub fn contains_state_record(&self, id: &BlockIdExt) -> Result<bool> {
        self.shardstate_db.contains(id)
    }

    pub fn get(&self, id: &BlockIdExt) -> Result<Cell> {
        let data = match self.shardstate_db.get(id) {
            Ok(data) => data,
            Err(e) => {
                if let Some(gc_resolver) = self.gc_resolver.get() {
                    if gc_resolver.allow_state_gc(id, 0, 0)? {
                        fail!(StorageError::StateIsAllowedToGc(id.clone()))
                    }
                }
                return Err(e);
            }
        };
        let db_entry = DbEntry::deserialize(&data)?;

        log::debug!(
            target: TARGET,
            "ShardStateDb::get  id {}  cell_id {:x}",
            id, db_entry.cell_id
        );

        if let Some(gc_resolver) = self.gc_resolver.get() {
            let utime_now = UnixTime::now();
            if gc_resolver.allow_state_gc(&db_entry.block_id, db_entry.save_utime, utime_now)? {
                fail!(StorageError::StateIsAllowedToGc(db_entry.block_id))
            }
        }

        let root_cell = self.dynamic_boc_db.load_cell(&db_entry.cell_id)?;
        Ok(root_cell)
    }

    pub fn get_detached<T>(
        &self,
        id: &BlockIdExt,
        budget: &dyn crate::bounded_cell::CellReadBudget,
        pin: impl FnOnce(u64) -> Result<T>,
    ) -> Result<(Cell, T)> {
        let _gate = self
            .bounded_read_gate
            .read()
            .map_err(|_| rtos_block::error!("State read gate poisoned"))?;
        budget.metadata(DbEntry::SIZE)?;
        let data = self.shardstate_db.get(id)?;
        if data.len() != DbEntry::SIZE {
            return Err(crate::bounded_cell::InvalidBoundedState("index length").into());
        }
        let entry = DbEntry::deserialize(&data)?;
        if &entry.block_id != id {
            return Err(crate::bounded_cell::InvalidBoundedState("index identity").into());
        }
        if let Some(gc) = self.gc_resolver.get() {
            if gc.allow_state_gc(id, entry.save_utime, UnixTime::now())? {
                fail!(StorageError::StateIsAllowedToGc(id.clone()));
            }
        }
        let lease = pin(entry.save_utime)?;
        let root = self.dynamic_boc_db.cell_db().load_detached(&entry.cell_id, budget)?;
        Ok((root, lease))
    }

    pub fn get_cell(&self, id: &UInt256) -> Result<Cell> {
        log::trace!(target: TARGET, "ShardStateDb::get_cell  id {:x}", id);
        self.dynamic_boc_db.load_cell(id)
    }

    pub fn create_hashed_cell_storage(
        &self,
        root: Option<&Cell>,
        max_inmemory_cells: usize,
    ) -> Result<impl CellsStorage> {
        CellByHashStorageAdapter::new(
            self.dynamic_boc_db.cell_db().clone(),
            root,
            max_inmemory_cells,
        )
    }

    pub fn create_fast_cell_storage(
        &self,
        index: Vec<(UInt256, u16)>,
    ) -> Result<AsyncCellsStorageAdapter> {
        AsyncCellsStorageAdapter::new(self.dynamic_boc_db.clone(), index)
    }

    pub fn cells_factory(&self) -> Result<Arc<dyn CellsFactory>> {
        Ok(self.dynamic_boc_db.cells_factory())
    }

    pub fn enumerate_ids(
        &self,
        callback: &mut dyn FnMut(&BlockIdExt) -> Result<bool>,
    ) -> Result<()> {
        self.shardstate_db.for_each(&mut |_key, value| {
            let entry = DbEntry::deserialize(value)?;
            callback(&entry.block_id)
        })?;
        Ok(())
    }

    async fn worker(
        self: Arc<Self>,
        mut receiver: tokio::sync::mpsc::UnboundedReceiver<StateCommand>,
    ) {
        self.stop.fetch_or(Self::MASK_WORKER, Ordering::Relaxed);

        let check_stop = || {
            if self.stop.load(Ordering::Relaxed) & Self::MASK_STOPPED != 0 {
                self.stop.fetch_and(!ShardStateDb::MASK_WORKER, Ordering::Relaxed);
                true
            } else {
                false
            }
        };

        loop {
            if check_stop() {
                return;
            }
            if let Ok(Some(command)) =
                tokio::time::timeout(Duration::from_millis(500), receiver.recv()).await
            {
                let (mut job, callback) = match command {
                    StateCommand::BoundedPut { id, root, limits, budget, reply, observer } => {
                        self.in_queue.fetch_sub(1, Ordering::Relaxed);
                        let result = tokio::task::block_in_place(|| {
                            let _gate = self
                                .bounded_read_gate
                                .write()
                                .map_err(|_| error!("State write gate poisoned"))?;
                            rtos_block::merkle_apply_budget::require_materialized(&root)?;
                            if let Some(prior) = self.write_failure.borrow().as_ref() {
                                fail!("Earlier state write failed: {prior}");
                            }
                            budget.workspace(DbEntry::SIZE)?;
                            let existing_index = self.shardstate_db.try_get(&id)?;
                            if let Some(existing) = &existing_index {
                                if existing.len() != DbEntry::SIZE {
                                    fail!("Bounded state index length mismatch");
                                }
                                let entry = DbEntry::deserialize(existing)?;
                                if entry.block_id != id {
                                    fail!("Bounded state index block identity mismatch");
                                }
                                if entry.cell_id != *root.repr_hash() {
                                    fail!("Bounded state index root mismatch");
                                }
                            }
                            let entry = DbEntry::with_params(
                                id.clone(),
                                root.repr_hash().clone(),
                                UnixTime::now(),
                            );
                            let new_seq = match &existing_index {
                                Some(_) => None,
                                None => Some(self.order.reserve()?),
                            };
                            let result = self.dynamic_boc_db.save_boc_bounded(
                                &root,
                                limits,
                                budget.as_ref(),
                                existing_index.is_none(),
                                observer.as_deref(),
                                |batch| {
                                    self.shardstate_db.put_in_batch(
                                        batch,
                                        id.key(),
                                        &entry.serialize(),
                                    )?;
                                    if let Some(seq) = new_seq {
                                        self.order_db.put_in_batch(
                                            batch,
                                            &InsertionOrder::seq_key(seq),
                                            &id.serialize(),
                                        )?;
                                    }
                                    Ok(())
                                },
                            );
                            if let (Ok(_), Some(seq)) = (&result, new_seq) {
                                self.order.insert(seq, id.clone())?;
                            }
                            if let Err(error) = &result {
                                if error
                                .downcast_ref::<crate::dynamic_boc_rc_db::BoundedStateWriteFailure>(
                                )
                                .is_some()
                            {
                                self.write_failure.send_replace(Some(error.to_string()));
                            }
                            }
                            result
                        });
                        // Per-request rejection is terminal for this command,
                        // not a permanent ordinary-writer retry loop.
                        let _ = reply.send(result);
                        continue;
                    }
                    StateCommand::Work(job, callback) => (job, callback),
                    StateCommand::Barrier(reply, observer) => {
                        // The state index and cells share this physical DB (new()).
                        let result = match self.write_failure.borrow().as_ref() {
                            Some(error) => Err(error!("Earlier state write failed: {error}")),
                            None => self.shardstate_db.sync_wal_observed(observer.as_deref()),
                        };
                        if let Err(error) = &result {
                            self.write_failure.send_replace(Some(error.to_string()));
                        }
                        let _ = reply.send(result);
                        continue;
                    }
                };
                let in_queue = self.in_queue.fetch_sub(1, Ordering::Relaxed) - 1;
                metrics::gauge!("rtos_node_db_shardstate_queue_size").set(in_queue as f64);
                #[cfg(feature = "telemetry")]
                self.telemetry.shardstates_queue.update(std::cmp::max(0, in_queue) as u64);
                log::debug!("ShardStateDb worker: in_queue {}", in_queue);

                loop {
                    match &mut job {
                        Job::PutState(cell, id) => {
                            match self.clone().put_internal(id, cell.clone()) {
                                Err(e) => {
                                    self.write_failure.send_replace(Some(e.to_string()));
                                    if check_stop() {
                                        return;
                                    }
                                    log::error!(
                                        target: TARGET, "CRITICAL! ShardStateDb::put_internal  {}", e
                                    );
                                    tokio::time::sleep(Duration::from_secs(1)).await;
                                    continue;
                                }
                                Ok(saved_root) => {
                                    *cell = saved_root;
                                }
                            }
                        }
                        Job::DeleteState(id) => {
                            if let Err(e) = self.clone().delete_internal(id) {
                                self.write_failure.send_replace(Some(e.to_string()));
                                if check_stop() {
                                    return;
                                }
                                log::error!(
                                    target: TARGET, "CRITICAL! ShardStateDb::delete_internal  {}", e
                                );
                                tokio::time::sleep(Duration::from_secs(1)).await;
                                continue;
                            }
                        }
                    }
                    break;
                }
                if let Some(callback) = callback {
                    let _ = callback.invoke(job).await;
                }
            }
        }
    }

    fn put_internal(self: Arc<Self>, id: &BlockIdExt, state_root: Cell) -> Result<Cell> {
        let _gate =
            self.bounded_read_gate.write().map_err(|_| error!("State write gate poisoned"))?;
        let cell_id = state_root.repr_hash().clone();

        log::trace!(
            target: TARGET,
            "ShardStateDb::put_internal  id {}  root_cell_id {:x}",
            id, cell_id
        );

        if self.shardstate_db.contains(id)? {
            log::warn!(
                target: TARGET,
                "ShardStateDb::put_internal  ALREADY EXISTS  id {}  root_cell_id {:x}",
                id, cell_id
            );
            return self.dynamic_boc_db.load_cell(&cell_id);
        }

        let ss_db = self.clone();
        let saved_root = tokio::task::block_in_place(|| {
            let check_stop = || {
                if ss_db.stop.load(Ordering::Relaxed) & Self::MASK_STOPPED != 0 {
                    fail!("Stopped")
                } else {
                    Ok(())
                }
            };
            ss_db.dynamic_boc_db.save_boc(state_root, &check_stop)
        })?;

        #[cfg(test)]
        {
            let gate = self.late_index_gate.lock().unwrap().take();
            if let Some(gate) = gate {
                gate()?;
            }
        }
        let save_utime = UnixTime::now();
        let db_entry = DbEntry::with_params(id.clone(), cell_id.clone(), save_utime);
        let seq = self.order.reserve()?;
        let index_result = (|| {
            let mut batch = rocksdb::WriteBatch::default();
            self.shardstate_db.put_in_batch(&mut batch, id.key(), &db_entry.serialize())?;
            self.order_db.put_in_batch(
                &mut batch,
                &InsertionOrder::seq_key(seq),
                &id.serialize(),
            )?;
            self.shardstate_db.physical_db().write_batch(batch)
        })();
        if index_result.is_ok() {
            self.order.insert(seq, id.clone())?;
        }
        #[cfg(test)]
        self.ordinary_index_attempts.fetch_add(1, Ordering::SeqCst);
        index_result?;

        log::trace!(
            target: TARGET,
            "ShardStateDb::put_internal DONE  id {}  root_cell_id {:x}",
            id, cell_id
        );

        Ok(saved_root)
    }

    fn delete_internal(self: Arc<Self>, id: &BlockIdExt) -> Result<()> {
        log::trace!(target: TARGET, "ShardStateDb::delete_internal  id {}", id);
        let protection = self.dynamic_boc_db.cell_db().db().repair_protection();
        let Some(_deletion) = protection.try_deletion() else {
            return Ok(());
        };
        if protection.state(id) {
            return Ok(());
        }

        let _gate = self
            .bounded_read_gate
            .write()
            .map_err(|_| rtos_block::error!("State read gate poisoned"))?;
        let db_entry = DbEntry::deserialize(&self.shardstate_db.get(id)?)?;
        // Eligibility may have changed after the asynchronous GC selection.
        if let Some(gc) = self.gc_resolver.get() {
            if !gc.allow_state_gc(id, db_entry.save_utime, UnixTime::now())? {
                return Ok(());
            }
        }

        let ss_db = self.clone();
        let shardstate_db = self.shardstate_db.clone();
        let id_for_batch = id.clone();
        tokio::task::block_in_place(|| {
            let check_stop = || {
                if ss_db.stop.load(Ordering::Relaxed) & Self::MASK_STOPPED != 0 {
                    fail!("Stopped")
                } else {
                    Ok(())
                }
            };
            ss_db.dynamic_boc_db.delete_boc(&db_entry.cell_id, &check_stop, |batch| {
                shardstate_db.add_delete_to_batch(batch, &id_for_batch)?;
                if let Some(seq) = ss_db.order.seq_of(&id_for_batch) {
                    ss_db.order_db.add_raw_to_batch(batch, &InsertionOrder::seq_key(seq), None)?;
                }
                Ok(())
            })
        })?;
        self.order.remove(id);

        log::trace!(target: TARGET, "ShardStateDb::delete_internal  DONE  id {}", id);
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/test_bounded_state_writer.rs"]
mod bounded_writer_tests;

#[cfg(test)]
mod bounded_read_tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    struct Policy(AtomicBool);
    impl AllowStateGcResolver for Policy {
        fn allow_state_gc(&self, _: &BlockIdExt, _: u64, _: u64) -> Result<bool> {
            Ok(self.0.load(Ordering::SeqCst))
        }
    }
    struct Budget;
    impl crate::bounded_cell::CellReadBudget for Budget {
        fn admit_cell(&self, _: &UInt256, _: usize, _: usize) -> Result<()> {
            Ok(())
        }
        fn complete_cell(&self, _: &Cell) -> Result<()> {
            Ok(())
        }
        fn step(&self) -> Result<()> {
            Ok(())
        }
        fn metadata(&self, _: usize) -> Result<()> {
            Ok(())
        }
        fn max_depth(&self) -> u16 {
            4096
        }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn bounded_state_queued_delete_rechecks_pin_and_rejects_bad_index() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let db = RocksDb::new(
            dir.path().to_str().unwrap(),
            "bounded_gc",
            None,
            crate::db::rocksdb::AccessType::ReadWrite,
        )?;
        let states = ShardStateDb::new(
            db,
            "states",
            "cells",
            "counters",
            CellsDbConfig::default(),
            #[cfg(feature = "telemetry")]
            Arc::new(crate::StorageTelemetry::default()),
            Arc::new(crate::StorageAlloc::default()),
        )?;
        let root = Cell::default();
        let id = BlockIdExt::with_params(
            rtos_block::ShardIdent::masterchain(),
            1,
            root.repr_hash().clone(),
            UInt256::default(),
        );
        states.clone().put_internal(&id, root.clone())?;
        let policy = Arc::new(Policy(AtomicBool::new(false)));
        assert!(states.gc_resolver.set(policy.clone()).is_ok());
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let read_states = states.clone();
        let read_id = id.clone();
        let reader = tokio::task::spawn_blocking(move || {
            read_states.get_detached(&read_id, &Budget, |_| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
        });
        entered_rx.await.unwrap();
        // Represents a GC decision already queued before the reader pinned.
        let delete_states = states.clone();
        let delete_id = id.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let mut deletion = tokio::task::spawn_blocking(move || {
            started_tx.send(()).unwrap();
            delete_states.delete_internal(&delete_id)
        });
        started_rx.await.unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(50), &mut deletion).await.is_err());
        release_tx.send(()).unwrap();
        assert_eq!(reader.await.unwrap()?.0, root);
        deletion.await.unwrap()?;
        assert!(states.get(&id).is_ok(), "queued deletion must recheck the current pin policy");
        policy.0.store(true, Ordering::SeqCst);
        states.clone().delete_internal(&id)?;
        assert!(states.get(&id).is_err(), "released policy permits actual deletion");
        states.shardstate_db.put(&id, &[0u8])?;
        let error = states.get_detached(&id, &Budget, |_| Ok(())).err().unwrap();
        assert!(error.downcast_ref::<crate::bounded_cell::InvalidBoundedState>().is_some());
        let mut other = id.clone();
        other.seq_no += 1;
        states
            .shardstate_db
            .put(&id, &DbEntry::with_params(other, root.repr_hash().clone(), 0).serialize())?;
        let error = states.get_detached(&id, &Budget, |_| Ok(())).err().unwrap();
        assert!(error.downcast_ref::<crate::bounded_cell::InvalidBoundedState>().is_some());
        states.stop().await.unwrap();
        Ok(())
    }
}

#[cfg(test)]
mod insertion_order_tests {
    use super::*;
    use std::sync::{atomic::AtomicBool, OnceLock};

    /// States below `threshold` are eligible; like the node resolver, one is
    /// gone only once it lies in the collectable prefix.
    struct Below {
        threshold: AtomicU32,
        order: OnceLock<Arc<dyn StateInsertionOrder>>,
        pinned: AtomicBool,
    }
    impl Below {
        fn new(threshold: u32) -> Arc<Self> {
            Arc::new(Self {
                threshold: AtomicU32::new(threshold),
                order: OnceLock::new(),
                pinned: AtomicBool::new(false),
            })
        }
    }
    impl AllowStateGcResolver for Below {
        fn allow_state_gc(&self, id: &BlockIdExt, _: u64, _: u64) -> Result<bool> {
            Ok(self.state_gc_eligible(id)?
                && !(self.pinned.load(Ordering::SeqCst) && id.seq_no() == 1)
                && self.order.get().is_none_or(|order| order.in_collectable_prefix(id)))
        }
        fn state_gc_eligible(&self, id: &BlockIdExt) -> Result<bool> {
            Ok(id.seq_no() < self.threshold.load(Ordering::SeqCst))
        }
        fn attach_insertion_order(&self, order: Arc<dyn StateInsertionOrder>) {
            let _ = self.order.set(order);
        }
    }

    /// Stops the states and waits until the database itself is released, so
    /// a reopen sees what was written.
    async fn close(states: Arc<ShardStateDb>) -> Result<()> {
        let db = states.shardstate_db.physical_db().clone();
        states.stop().await?;
        drop(states);
        tokio::time::timeout(Duration::from_secs(10), async {
            while Arc::strong_count(&db) > 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .map_err(|_| error!("state database not released"))?;
        Ok(())
    }

    fn open(dir: &std::path::Path) -> Result<Arc<ShardStateDb>> {
        let db = crate::db::node::open_node_db(
            dir,
            &CellsDbConfig::default(),
            crate::db::rocksdb::AccessType::ReadWrite,
        )?;
        ShardStateDb::new(
            db,
            "order_states",
            crate::db::node::CELLS_CF_NAME,
            crate::db::node::CELLSCOUNTERS_CF_NAME,
            CellsDbConfig::default(),
            #[cfg(feature = "telemetry")]
            Arc::new(crate::StorageTelemetry::default()),
            Arc::new(crate::StorageAlloc::default()),
        )
    }

    fn state(seq_no: u32) -> Result<(BlockIdExt, Cell)> {
        let root = rtos_block::BuilderData::with_raw(vec![seq_no as u8, 0x5a], 16)?.into_cell()?;
        let id = BlockIdExt::with_params(
            rtos_block::ShardIdent::masterchain(),
            seq_no,
            root.repr_hash().clone(),
            UInt256::from([seq_no as u8; 32]),
        );
        Ok((id, root))
    }

    /// The pass stops at the oldest kept state: a later eligible state stays
    /// stored and readable, and the store order survives a reopen.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn collection_follows_store_order_and_stops_at_the_oldest_kept_state() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (a, b, c) = (state(1)?, state(5)?, state(2)?);
        {
            let states = open(dir.path())?;
            for (id, root) in [&a, &b, &c] {
                states.clone().put_internal(id, root.clone())?;
            }
            assert_eq!(states.states_in_store_order(), vec![a.0.clone(), b.0.clone(), c.0.clone()]);
            let policy = Below::new(3);
            policy.attach_insertion_order(states.insertion_order());
            assert!(states.gc_resolver.set(policy.clone()).is_ok());
            // Before any pass nothing is collectable: every state reads.
            assert!(states.get(&c.0).is_ok());
            assert_eq!(states.collectable_prefix(policy.as_ref()), vec![a.0.clone()]);
            // C is eligible but behind the kept B: it stays readable.
            assert!(!policy.allow_state_gc(&c.0, 0, 0)?);
            assert!(states.get(&c.0).is_ok());
            assert!(policy.allow_state_gc(&a.0, 0, 0)?);
            states.clone().delete_internal(&a.0)?;
            assert!(!states.contains_state_record(&a.0)?);
            assert_eq!(states.states_in_store_order(), vec![b.0.clone(), c.0.clone()]);
            states.shardstate_db.sync_wal()?;
            close(states).await?;
        }
        // Reopened: the order of the remaining states is the stored one.
        let states = open(dir.path())?;
        assert!(states.contains_state_record(&b.0)?, "index survives the reopen");
        assert_eq!(states.states_in_store_order(), vec![b.0.clone(), c.0.clone()]);
        let policy = Below::new(10);
        policy.attach_insertion_order(states.insertion_order());
        assert_eq!(states.collectable_prefix(policy.as_ref()), vec![b.0.clone(), c.0.clone()]);
        states.stop().await?;
        Ok(())
    }

    /// The running collector deletes oldest first, never past a kept state,
    /// and retries a pinned one without reordering the rest.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn running_collector_deletes_only_the_collectable_prefix() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let states = open(dir.path())?;
        let (a, b, c) = (state(1)?, state(5)?, state(2)?);
        for (id, root) in [&a, &b, &c] {
            states.clone().put_internal(id, root.clone())?;
        }
        let policy = Below::new(3);
        policy.pinned.store(true, Ordering::SeqCst);
        states.clone().start_gc(policy.clone(), Arc::new(AtomicU32::new(1)));
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(states.contains_state_record(&a.0)?, "a pinned state waits");
        policy.pinned.store(false, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(!states.contains_state_record(&a.0)?);
        assert!(states.contains_state_record(&b.0)?);
        assert!(states.contains_state_record(&c.0)?, "never collected past a kept state");
        policy.threshold.store(10, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(!states.contains_state_record(&b.0)?);
        assert!(!states.contains_state_record(&c.0)?);
        states.stop().await?;
        Ok(())
    }

    /// An indexed state without an order record (written before the order
    /// existed) is appended by save time; a stale order record is dropped.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn order_is_reconciled_with_the_index_on_open() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (a, b) = (state(7)?, state(3)?);
        {
            let states = open(dir.path())?;
            states.clone().put_internal(&a.0, a.1.clone())?;
            states.clone().put_internal(&b.0, b.1.clone())?;
            // Lose the order record of A, and leave one for an unknown state.
            let seq = states.order.seq_of(&a.0).unwrap();
            states.order_db.delete_raw(&InsertionOrder::seq_key(seq))?;
            let ghost = state(9)?.0;
            states.order_db.put_raw(&InsertionOrder::seq_key(1000), &ghost.serialize())?;
            states.shardstate_db.sync_wal()?;
            close(states).await?;
        }
        let states = open(dir.path())?;
        assert_eq!(states.states_in_store_order(), vec![b.0.clone(), a.0.clone()]);
        assert!(states.order_db.try_get_raw(&InsertionOrder::seq_key(1000))?.is_none());
        states.stop().await?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/test_disk_full_shardstate.rs"]
mod disk_full_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "tests/test_late_index_eio_ref.rs"]
mod late_index_eio_tests;
