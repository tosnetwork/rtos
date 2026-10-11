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
    sync::{
        atomic::{AtomicU32, AtomicU8, Ordering},
        Arc,
    },
    time::Duration,
};

pub trait AllowStateGcResolver: Send + Sync {
    fn allow_state_gc(&self, block_id: &BlockIdExt, save_utime: u64, gc_utime: u64)
        -> Result<bool>;
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

pub struct ShardStateDb {
    shardstate_db: Arc<RocksDbTable<BlockIdExt>>,
    dynamic_boc_db: Arc<DynamicBocDb>,
    storer: tokio::sync::mpsc::UnboundedSender<StateCommand>,
    write_failure: tokio::sync::watch::Sender<Option<String>>,
    bounded_read_gate: std::sync::RwLock<()>,
    in_queue: AtomicU32,
    stop: Arc<AtomicU8>,
    config: CellsDbConfig,
    gc_resolver: tokio::sync::OnceCell<Arc<dyn AllowStateGcResolver>>,
    #[cfg(feature = "telemetry")]
    telemetry: Arc<StorageTelemetry>,
}

impl ShardStateDb {
    const MASK_GC: u8 = 0x01;
    const MASK_WORKER: u8 = 0x02;
    pub(crate) const MASK_STOPPED: u8 = 0x80;
    const GC_QUEUE_POLL_INTERVAL_MS: u64 = 10_000;
    const PUT_QUEUE_POLL_INTERVAL_MS: u64 = 100;

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

        let ss_db = Arc::new(Self {
            shardstate_db: Arc::new(RocksDbTable::with_db(db.clone(), shardstate_db_cf, true)?),
            dynamic_boc_db: Arc::new(dynamic_boc_db),
            storer: sender,
            bounded_read_gate: std::sync::RwLock::new(()),
            write_failure: tokio::sync::watch::channel(None).0,
            in_queue: AtomicU32::new(0),
            stop: Arc::new(AtomicU8::new(0)),
            config,
            gc_resolver: tokio::sync::OnceCell::new(),
            #[cfg(feature = "telemetry")]
            telemetry,
        });

        tokio::spawn({
            let ss_db = ss_db.clone();
            async move {
                ss_db.worker(receiver).await;
            }
        });

        Ok(ss_db)
    }

    pub fn start_gc(
        self: Arc<Self>,
        gc_resolver: Arc<dyn AllowStateGcResolver>,
        run_interval_adjustable_sec: Arc<AtomicU32>,
    ) {
        if self.gc_resolver.set(gc_resolver.clone()).is_err() {
            log::error!(target: TARGET, "INTERNAL ERROR: Attempt to set GC resolver twice");
        }
        self.stop.fetch_or(Self::MASK_GC, Ordering::Relaxed);
        tokio::spawn(async move {
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
                    let interval_ms = (run_gc_interval * 1000) / (to_delete.len() + 1) as u64;
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
                            let elapsed = elapsed.as_millis() as u64;
                            if elapsed > interval_ms {
                                log::debug!(
                                    target: TARGET,
                                    "ShardStateDb GC: deleting state {} was slower then given \
                                    interval, TIME {} ms, slot {} ms",
                                    id, elapsed, interval_ms,
                                );
                                if check_and_stop(&self.stop) {
                                    return;
                                }
                            } else if !sleep_nicely(&self.stop, interval_ms - elapsed).await {
                                return;
                            }
                        }
                    }
                }

                log::debug!(target: TARGET, "ShardStateDb GC: collecting states to delete");

                let mut kept = 0;
                self.shardstate_db
                    .for_each(&mut |_key, value| {
                        if check_and_stop(&self.stop) {
                            return Ok(false);
                        }
                        let entry = DbEntry::deserialize(value)?;
                        let time = UnixTime::now();
                        match gc_resolver.allow_state_gc(&entry.block_id, entry.save_utime, time) {
                            Ok(true) => {
                                log::debug!(
                                target: TARGET, "ShardStateDb GC: delete  id {}", entry.block_id);
                                to_delete.push(entry.block_id);
                            }
                            Ok(false) => {
                                kept += 1;
                                log::debug!(
                                target: TARGET, "ShardStateDb GC: keep  id {}", entry.block_id);
                            }
                            Err(e) => log::warn!(
                                target: TARGET,
                                "ShardStateDb  allow_state_gc  id {}  root_cell_id {:x}  error {}",
                                entry.block_id, entry.cell_id, e
                            ),
                        }
                        Ok(true)
                    })
                    .expect("Can't return error");

                if check_and_stop(&self.stop) {
                    return;
                }

                log::info!(
                    target: TARGET,
                    "ShardStateDb GC: collected {} states to delete, kept {}",
                    to_delete.len(), kept
                );

                // Sort ids by decreasing seqno. This way differences between
                // states will be smaller, so each delete operation will be faster
                // (last in the vector - the earliest state - will be deleted first)
                to_delete.sort_by_key(|b| std::cmp::Reverse(b.seq_no()));
            }
        });
    }

    pub async fn stop(&self) {
        self.stop.fetch_or(Self::MASK_STOPPED, Ordering::Relaxed);
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if !self.is_run() {
                tokio::time::sleep(Duration::from_secs(1)).await;
                break;
            }
        }
    }

    pub fn is_gc_run(&self) -> bool {
        self.stop.load(Ordering::Relaxed) & Self::MASK_GC != 0
    }

    fn is_run(&self) -> bool {
        (self.stop.load(Ordering::Relaxed) & !Self::MASK_STOPPED) != 0
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
                                    )
                                },
                            );
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

        let save_utime = UnixTime::now();
        let db_entry = DbEntry::with_params(id.clone(), cell_id.clone(), save_utime);
        self.shardstate_db.put(id, &db_entry.serialize())?;

        log::trace!(
            target: TARGET,
            "ShardStateDb::put_internal DONE  id {}  root_cell_id {:x}",
            id, cell_id
        );

        Ok(saved_root)
    }

    fn delete_internal(self: Arc<Self>, id: &BlockIdExt) -> Result<()> {
        log::trace!(target: TARGET, "ShardStateDb::delete_internal  id {}", id);

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
                shardstate_db.add_delete_to_batch(batch, &id_for_batch)
            })
        })?;

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
        states.stop().await;
        Ok(())
    }
}
