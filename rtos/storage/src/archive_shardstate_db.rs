/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
#[cfg(feature = "telemetry")]
use crate::StorageTelemetry;
use crate::{
    cell_db::CellByHashStorageAdapter,
    db::rocksdb::{RocksDb, RocksDbTable},
    dynamic_boc_archive_db::DynamicBocArchiveDb,
    shardstate_db_async::{CellsDbConfig, DbEntry},
    traits::Serializable,
    StorageAlloc, TARGET,
};
use rtos_block::merkle_apply_budget::{MerkleApplyBudget, MerkleApplyLimits};
use rtos_block::{BlockIdExt, Cell, CellsFactory, CellsStorage, Result, UInt256, UnixTime};
use std::sync::{Arc, Mutex};

pub struct ArchiveShardStateDb {
    index: Arc<RocksDbTable<BlockIdExt>>,
    boc_db: Arc<DynamicBocArchiveDb>,
    write_gate: Arc<Mutex<Option<String>>>,
}

impl ArchiveShardStateDb {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        db: Arc<RocksDb>,
        index_cf: &str,
        cells_cf: &str,
        config: &CellsDbConfig,
        #[cfg(feature = "telemetry")] telemetry: Arc<StorageTelemetry>,
        allocated: Arc<StorageAlloc>,
    ) -> Result<Self> {
        let boc_db = Arc::new(DynamicBocArchiveDb::with_db(
            db.clone(),
            cells_cf,
            config,
            #[cfg(feature = "telemetry")]
            telemetry,
            allocated,
        )?);
        let index = Arc::new(RocksDbTable::with_db(db, index_cf, true)?);
        Ok(Self { index, boc_db, write_gate: Arc::new(Mutex::new(None)) })
    }

    pub fn contains_state_record(&self, id: &BlockIdExt) -> Result<bool> {
        self.index.contains(id)
    }

    /// The reservation is registered before any ordinary or bounded writer can
    /// create this index. Archive states are append-only and have no GC.
    pub fn with_absent_state<T>(
        &self,
        id: &BlockIdExt,
        reserve: impl FnOnce() -> Result<T>,
    ) -> Result<Option<T>> {
        let _gate = self
            .write_gate
            .lock()
            .map_err(|_| rtos_block::error!("Archive write gate poisoned"))?;
        if let Some(reason) = _gate.as_ref() {
            rtos_block::fail!("Archive writer failed: {reason}");
        }
        if self.index.contains(id)? {
            Ok(None)
        } else {
            reserve().map(Some)
        }
    }

    pub async fn put_bounded(
        &self,
        id: &BlockIdExt,
        root: Cell,
        limits: MerkleApplyLimits,
        budget: Arc<dyn MerkleApplyBudget>,
    ) -> Result<()> {
        self.put_bounded_observed(id, root, limits, budget, None).await
    }

    /// The blocking writer owns the budget through the actual WAL boundary,
    /// even when the future observing its result is cancelled.
    pub async fn put_bounded_observed(
        &self,
        id: &BlockIdExt,
        root: Cell,
        limits: MerkleApplyLimits,
        budget: Arc<dyn MerkleApplyBudget>,
        observer: crate::durability::SyncObservation,
    ) -> Result<()> {
        budget.workspace(1024)?;
        let id = id.clone();
        let index = self.index.clone();
        let boc = self.boc_db.clone();
        let gate = self.write_gate.clone();
        tokio::task::spawn_blocking(move || {
            let mut failed =
                gate.lock().map_err(|_| rtos_block::error!("Archive write gate poisoned"))?;
            if let Some(reason) = failed.as_ref() {
                rtos_block::fail!("Archive writer failed: {reason}");
            }
            let result = bounded_writer::write(
                &index,
                &boc,
                &id,
                root,
                limits,
                budget.as_ref(),
                observer.as_deref(),
            );
            if let Err(error) = &result {
                if error
                    .downcast_ref::<crate::dynamic_boc_rc_db::BoundedStateWriteFailure>()
                    .is_some()
                {
                    *failed = Some(error.to_string());
                }
            }
            result
        })
        .await
        .map_err(|e| rtos_block::error!("Archive bounded writer task: {e}"))?
    }

    pub fn put(&self, id: &BlockIdExt, state_root: Cell) -> Result<Cell> {
        let gate = self
            .write_gate
            .lock()
            .map_err(|_| rtos_block::error!("Archive write gate poisoned"))?;
        if let Some(reason) = gate.as_ref() {
            rtos_block::fail!("Archive writer failed: {reason}");
        }
        let cell_id = state_root.repr_hash().clone();
        log::debug!(
            target: TARGET,
            "ArchiveShardStateDb::put  id {}  root_cell_id {:x}", id, cell_id
        );

        if self.index.contains(id)? {
            log::debug!(
                target: TARGET,
                "ArchiveShardStateDb::put  ALREADY EXISTS  id {}", id
            );
            let data = self.index.get(id)?;
            let db_entry = DbEntry::deserialize(&data)?;
            return self.boc_db.cell_db().load_cell(&db_entry.cell_id);
        }

        let saved = self.boc_db.save_boc(state_root, &|| Ok(()))?;
        let save_utime = UnixTime::now();
        let db_entry = DbEntry::with_params(id.clone(), cell_id, save_utime);
        self.index.put(id, &db_entry.serialize())?;
        Ok(saved)
    }

    pub fn put_update(&self, id: &BlockIdExt, state_root: Cell) -> Result<()> {
        let gate = self
            .write_gate
            .lock()
            .map_err(|_| rtos_block::error!("Archive write gate poisoned"))?;
        if let Some(reason) = gate.as_ref() {
            rtos_block::fail!("Archive writer failed: {reason}");
        }
        let state_root = state_root.virtualize(1);
        let cell_id = state_root.repr_hash().clone();
        log::debug!(
            target: TARGET,
            "ArchiveShardStateDb::put_update  id {}  root_cell_id {:x}", id, cell_id
        );

        if self.index.contains(id)? {
            log::info!(
                target: TARGET,
                "ArchiveShardStateDb::put_update  ALREADY EXISTS  id {}", id
            );
            return Ok(());
        }

        self.boc_db.save_update(state_root)?;
        let save_utime = UnixTime::now();
        let db_entry = DbEntry::with_params(id.clone(), cell_id, save_utime);
        self.index.put(id, &db_entry.serialize())?;
        Ok(())
    }

    /// Cells and index are constructed from the same physical DB.
    pub fn sync_wal(&self) -> Result<()> {
        self.sync_wal_observed(None)
    }
    pub fn sync_wal_observed(
        &self,
        observer: Option<&crate::durability::SyncObserver>,
    ) -> Result<()> {
        let mut failed = self
            .write_gate
            .lock()
            .map_err(|_| rtos_block::error!("Archive write gate poisoned"))?;
        if let Some(reason) = failed.as_ref() {
            rtos_block::fail!("Archive writer failed: {reason}");
        }
        let result = self.index.sync_wal_observed(observer);
        if let Err(error) = &result {
            *failed = Some(error.to_string());
        }
        result
    }

    pub fn get(&self, id: &BlockIdExt) -> Result<Cell> {
        let data = self.index.get(id)?;
        let db_entry = DbEntry::deserialize(&data)?;
        log::debug!(
            target: TARGET,
            "ArchiveShardStateDb::get  id {}  cell_id {:x}", id, db_entry.cell_id
        );
        self.boc_db.cell_db().load_cell(&db_entry.cell_id)
    }

    pub fn get_detached<T>(
        &self,
        id: &BlockIdExt,
        budget: &dyn crate::bounded_cell::CellReadBudget,
        pin: impl FnOnce(u64) -> Result<T>,
    ) -> Result<(Cell, T)> {
        budget.metadata(DbEntry::SIZE)?;
        let data = self.index.get(id)?;
        if data.len() != DbEntry::SIZE {
            return Err(crate::bounded_cell::InvalidBoundedState("archive index length").into());
        }
        let entry = DbEntry::deserialize(&data)?;
        if &entry.block_id != id {
            return Err(crate::bounded_cell::InvalidBoundedState("archive index identity").into());
        }
        let lease = pin(entry.save_utime)?;
        let root = self.boc_db.cell_db().load_detached(&entry.cell_id, budget)?;
        Ok((root, lease))
    }

    pub fn get_cell(&self, id: &UInt256) -> Result<Cell> {
        self.boc_db.cell_db().load_cell(id)
    }

    pub fn contains(&self, id: &BlockIdExt) -> Result<bool> {
        self.index.contains(id)
    }

    pub fn cells_factory(&self) -> Arc<dyn CellsFactory> {
        self.boc_db.cell_db().clone() as Arc<dyn CellsFactory>
    }

    pub fn rocksdb_memory_usage(&self) -> crate::RocksDbMemoryUsage {
        self.boc_db.cell_db().db().memory_usage()
    }

    pub fn create_hashed_cell_storage(
        &self,
        root: Option<&Cell>,
        max_inmemory_cells: usize,
    ) -> Result<impl CellsStorage> {
        CellByHashStorageAdapter::new(self.boc_db.cell_db().clone(), root, max_inmemory_cells)
    }
}

#[path = "bounded_archive_writer.rs"]
mod bounded_writer;

#[cfg(test)]
#[path = "tests/test_bounded_archive_writer.rs"]
mod bounded_writer_tests;

#[cfg(test)]
#[path = "tests/test_disk_full_archive_state.rs"]
mod disk_full_tests;
