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
use super::truncation_selection::TruncationSelection;
#[cfg(feature = "telemetry")]
use crate::StorageTelemetry;
use crate::{
    archives::{
        archive_manager::{ArchiveManager, ImportEntry},
        block_index_db::{BlockIndexDb, LookupResult, RepackOffsets},
        get_mc_seq_no,
        package::Package,
        package_entry::PackageEntry,
        package_entry_id::{GetFileName, PackageEntryId},
        package_entry_meta_db::{PackageEntryInfo, PackageEntryMeta, PackageEntryMetaDb},
        package_id::{PackageId, PackageType},
        package_info::PackageInfo,
        package_offsets_db::PackageOffsetsDb,
        package_status_db::PackageStatusDb,
        package_status_key::PackageStatusKey,
        ARCHIVE_PACKAGE_SIZE, KEY_ARCHIVE_PACKAGE_SIZE,
    },
    block_handle_db::BlockHandle,
    db::rocksdb::RocksDb,
    traits::Serializable,
    StorageAlloc, TARGET,
};
use adnl::common::add_unbound_object_to_map;
use rtos_block::{
    error, fail, AccountIdPrefixFull, BlockIdExt, Result, ShardIdent, BASE_WORKCHAIN_ID,
};
use std::{
    borrow::Borrow,
    fs::create_dir_all,
    hash::Hash,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, OnceLock,
    },
};

const DEFAULT_PKG_VERSION: u32 = 1;

#[derive(Clone, Copy)]
enum PackageOpenMode { RecoverOrCreate, PreserveExisting }

enum ChosenPackage {
    Info(Arc<PackageInfo>),
    Slot(PackageEntryInfo),
}

/*
    Archive slice is a set of files (packages) starting from some base MC block.
    Each package may store data related upto ARCHIVE_PACKAGE_SIZE MC blocks.
    There are several storing modes:
    - storing of MC and shard blocks data together in one package
    - storing of MC and shard blocks in separated packages;
      depending on min_split config parameter, there could be 1 or more packages for shard blocks
    First package has index 0, subsequent packages will get incremented index.
    MC package is indexed first, shard package indexes follow it
*/

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MetadataCut { EntryMeta, NonSlicedStatus, Offset, BlockIndex }
#[cfg(test)]
type MetadataGate = Arc<dyn Fn(u64, u64) -> Result<()> + Send + Sync>;

use super::context::{ArchiveContextError, ArchiveOperation, ArchiveProvider, ArchiveView};

pub struct ArchiveSlice {
    view: ArchiveView,
    archive_id: u32,
    db_root_path: Arc<PathBuf>,
    finalized: bool,
    package_count: AtomicU32,

    // packet index in slice
    // packet number in slice -> shard and number of first block of shard in packet
    package_index: lockfree::map::Map<u32, PackageEntryInfo>,

    // shard and number of the first block of the shard in the packet -> packet
    package_store: lockfree::map::Map<PackageEntryInfo, OnceLock<Arc<PackageInfo>>>,

    package_type: PackageType,
    shard_separated: bool,
    shard_split_depth: u8,
    sliced_mode: bool,
    slice_size: u32,

    // package index in slice -> package meta info
    entry_db: PackageEntryMetaDb,

    block_index_db: BlockIndexDb,

    // record type + block id -> offset in package
    offsets_db: PackageOffsetsDb,
    package_status_db: PackageStatusDb,
    #[cfg(feature = "telemetry")]
    telemetry: Arc<StorageTelemetry>,
    #[cfg(test)]
    metadata_gate: std::sync::Mutex<Option<(MetadataCut, MetadataGate)>>,
    #[cfg(test)]
    before_package_open: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
    allocated: Arc<StorageAlloc>,
}

impl ArchiveSlice {
    pub async fn new_empty(
        binding: ArchiveProvider,
        parent: &ArchiveOperation,
        db_root_path: Arc<PathBuf>,
        archive_id: u32,
        package_type: PackageType,
        shard_split_depth: u8,
        #[cfg(feature = "telemetry")] telemetry: Arc<StorageTelemetry>,
        allocated: Arc<StorageAlloc>,
    ) -> Result<Self> {
        let operation = parent.inherit(&binding)?;
        let db = binding.db().clone();
        super::recovery_guard::ensure_slice_clear(
            db.db(), &db_root_path, archive_id, matches!(package_type, PackageType::KeyBlocks),
        )?;
        let mut ret = Self::create(
            operation.view(),
            db,
            db_root_path,
            archive_id,
            package_type,
            false,
            true,
            shard_split_depth,
            #[cfg(feature = "telemetry")]
            telemetry,
            allocated,
        )
        .await?;
        let mut transaction = ret.package_status_db.begin_transaction()?;
        let (check_status, check_index) = if ret.sliced_mode {
            ret.shard_separated = true;
            transaction.put(&PackageStatusKey::SlicedMode, &true.serialize())?;
            transaction.put(&PackageStatusKey::TotalSlices, &1u32.serialize())?;
            transaction.put(&PackageStatusKey::SliceSize, &ret.slice_size.serialize())?;
            transaction
                .put(&PackageStatusKey::ShardSplitDepth, &ret.shard_split_depth.serialize())?;
            let meta = PackageEntryMeta::with_data(
                0,
                DEFAULT_PKG_VERSION,
                Some(&ret.get_base_entry_info()),
            );
            ret.entry_db.put_value(&0.into(), &meta)?;
            (4, 1)
        } else {
            transaction.put(&PackageStatusKey::SlicedMode, &false.serialize())?;
            transaction.put(&PackageStatusKey::NonSlicedSize, &0u64.serialize())?;
            (2, 0)
        };
        transaction.commit()?;
        if check_status != ret.package_status_db.len()? {
            fail!(
                "Package status DB in archive {archive_id} contains {} entries \
                but only {check_status} expected",
                ret.package_status_db.len()?
            )
        }
        if check_index != ret.entry_db.len()? {
            fail!(
                "Entry DB in archive {archive_id} contains {} entries \
                but only {check_index} expected",
                ret.entry_db.len()?
            )
        }
        let entry = ret.get_base_entry_info();
        ret.open_package(&operation, entry, None, 0, DEFAULT_PKG_VERSION, PackageOpenMode::RecoverOrCreate).await?;
        Ok(ret)
    }

    /// Create a new archive slice for importing existing .pack files.
    /// Unlike `new_empty()`, this does not create an initial package file.
    /// Packages are registered later via `import_package_entries()`.
    pub async fn new_for_import(
        binding: ArchiveProvider,
        parent: &ArchiveOperation,
        db_root_path: Arc<PathBuf>,
        archive_id: u32,
        package_type: PackageType,
        shard_split_depth: u8,
        #[cfg(feature = "telemetry")] telemetry: Arc<StorageTelemetry>,
        allocated: Arc<StorageAlloc>,
    ) -> Result<Self> {
        let operation = parent.inherit(&binding)?;
        let db = binding.db().clone();
        super::recovery_guard::ensure_slice_clear(
            db.db(), &db_root_path, archive_id, matches!(package_type, PackageType::KeyBlocks),
        )?;
        let mut ret = Self::create(
            operation.view(),
            db,
            db_root_path,
            archive_id,
            package_type,
            true, // finalized: prevents truncation when opening packages
            true, // create_if_not_exist
            shard_split_depth,
            #[cfg(feature = "telemetry")]
            telemetry,
            allocated,
        )
        .await?;
        let mut transaction = ret.package_status_db.begin_transaction()?;
        if ret.sliced_mode {
            ret.shard_separated = true;
            transaction.put(&PackageStatusKey::SlicedMode, &true.serialize())?;
            transaction.put(&PackageStatusKey::TotalSlices, &0u32.serialize())?;
            transaction.put(&PackageStatusKey::SliceSize, &ret.slice_size.serialize())?;
            transaction
                .put(&PackageStatusKey::ShardSplitDepth, &ret.shard_split_depth.serialize())?;
        } else {
            transaction.put(&PackageStatusKey::SlicedMode, &false.serialize())?;
            transaction.put(&PackageStatusKey::NonSlicedSize, &0u64.serialize())?;
        }
        transaction.commit()?;
        Ok(ret)
    }

    pub async fn import_package_entries(
        &self,
        package_archive_id: u32,
        shard: &ShardIdent,
        file_size: u64,
        entries: &[ImportEntry],
    ) -> Result<()> {
        let entry = PackageEntryInfo { seqno: package_archive_id, shard: shard.clone() };

        if let Some(pi) = self.get_package_by_entry(&entry).await {
            // The package already exists — it could be partially written by the node. Refresh the persisted size to match.
            let info = if self.shard_separated { Some(pi.entry()) } else { None };
            self.entry_db.put_value(
                &pi.index().into(),
                &PackageEntryMeta::with_data(file_size, pi.version(), info),
            )?;
        } else {
            self.add_package(entry, file_size).await?;
        }

        if !self.sliced_mode {
            let pi = self.get_package_by_entry(&self.get_base_entry_info()).await
                .ok_or_else(|| error!("Imported non-sliced package is missing"))?;
            self.entry_db.put_value(&u32::MAX.into(),
                &PackageEntryMeta::with_data(file_size, pi.version(), None))?;
            self.package_status_db.put_value(&PackageStatusKey::NonSlicedSize, &file_size)?;
        }

        for import_entry in entries {
            let offset_key = (&import_entry.entry_id).into();
            self.offsets_db.put_value(&offset_key, &import_entry.offset)?;
            if let (PackageEntryId::Block(_), Some(bm)) =
                (&import_entry.entry_id, &import_entry.block_meta)
            {
                self.block_index_db.put_raw(
                    &bm.shard,
                    bm.seq_no,
                    bm.end_lt,
                    bm.gen_utime,
                    bm.mc_ref_seq_no,
                    u32::try_from(import_entry.offset).map_err(|_| {
                        error!("entry offset {} exceeds u32 range", import_entry.offset)
                    })?,
                )?;
            }
        }

        Ok(())
    }

    pub fn db_root_path(&self) -> &Path {
        self.db_root_path.as_path()
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn with_data(
        protection: Arc<crate::repair_protection::RepairProtection>,
        binding: ArchiveProvider,
        parent: &ArchiveOperation,
        db_root_path: Arc<PathBuf>,
        archive_id: u32,
        package_type: PackageType,
        finalized: bool,
        cleanup_if_broken: bool,
        #[cfg(feature = "telemetry")] telemetry: Arc<StorageTelemetry>,
        allocated: Arc<StorageAlloc>,
    ) -> Result<Self> {
        let operation = parent.inherit(&binding)?;
        let db = binding.db().clone();
        let _startup = protection.deletion().await;
        super::recovery_guard::ensure_slice_clear(
            db.db(), &db_root_path, archive_id, matches!(package_type, PackageType::KeyBlocks),
        )?;
        let mode = if protection.archive_range(archive_id, None) {
            PackageOpenMode::PreserveExisting
        } else {
            PackageOpenMode::RecoverOrCreate
        };
        let mut ret = Self::create(
            operation.view(),
            db,
            db_root_path,
            archive_id,
            package_type,
            finalized,
            false,
            0,
            #[cfg(feature = "telemetry")]
            telemetry,
            allocated,
        )
        .await?;
        ret.sliced_mode = ret
            .package_status_db
            .try_get_value::<bool>(&PackageStatusKey::SlicedMode)?
            .ok_or_else(|| error!("Cannot read archive {archive_id} sliced_mode"))?;
        if ret.sliced_mode {
            let total_slices =
                ret.package_status_db.get_value::<u32>(&PackageStatusKey::TotalSlices)?;
            ret.slice_size =
                ret.package_status_db.get_value::<u32>(&PackageStatusKey::SliceSize)?;
            let mut entry_info =
                Some(PackageEntryInfo { seqno: 0, shard: ShardIdent::masterchain() });
            if let Some(shard_split_depth) =
                ret.package_status_db.try_get_value::<u8>(&PackageStatusKey::ShardSplitDepth)?
            {
                entry_info = None;
                ret.shard_separated = true;
                ret.shard_split_depth = shard_split_depth;
            }
            if ret.slice_size == 0 {
                fail!("Zero slice size in archive {archive_id}")
            }
            log::debug!(
                target: TARGET,
                "Read archive {archive_id} for the sliced mode. \
                Total slices: {total_slices}, slice size: {}",
                ret.slice_size
            );
            for i in 0..total_slices {
                let meta = ret.entry_db.get_value(&i.into())?;
                log::debug!(target: TARGET, "Read slice #{i} metadata: {meta:?}");
                let entry = if let Some(entry) = &mut entry_info {
                    entry.seqno = archive_id + i * ret.slice_size;
                    entry.clone()
                } else if let Some(entry) = meta.get_info()? {
                    entry
                } else {
                    fail!("No entry info for slice #{i}")
                };
                match ret.open_package(&operation, entry, None, meta.entry_size(), meta.version(), mode).await {
                    Ok(_) => (),
                    Err(e) => {
                        if e.is::<ArchiveContextError>() { return Err(e); }
                        if cleanup_if_broken && matches!(mode, PackageOpenMode::RecoverOrCreate) {
                            match ret.destroy_broken().await {
                                Ok(_) => (),
                                Err(e) => log::error!(
                                    target: TARGET,
                                    "Can't destroy broken slice #{i} of archive {archive_id}: {e}"
                                ),
                            }
                        }
                        fail!("Can't read archive {archive_id} slice #{i}: {e}. Stopped reading")
                    }
                }
            }
        } else {
            let size = ret.package_status_db.get_value::<u64>(&PackageStatusKey::NonSlicedSize)?;
            // Live append persists the end under the non-sliced sentinel; imports
            // historically used index zero. Never infer a committed end from the file.
            let meta = match ret.entry_db.try_get_value(&u32::MAX.into())? {
                Some(meta) => Some(meta),
                None => ret.entry_db.try_get_value(&0.into())?,
            };
            let (size, version) = if matches!(mode, PackageOpenMode::PreserveExisting) {
                match meta {
                    Some(meta) => {
                        // A legacy explicit truncation left only this status updated.
                        // Without an ordering marker, disagreement is not repairable here.
                        if size != 0 && size != meta.entry_size() {
                            fail!("Protected non-sliced package has ambiguous durable length metadata")
                        }
                        (meta.entry_size(), meta.version())
                    },
                    None => (size, 0),
                }
            } else {
                // Legacy explicit truncation updates only NonSlicedSize; keep
                // that committed boundary, but never discard a stored version
                // that enables recovery of an unacknowledged package tail.
                (size, meta.map_or(0, |meta| meta.version()))
            };
            let entry = ret.get_base_entry_info();
            ret.open_package(&operation, entry, None, size, version, mode).await?;
        }
        Ok(ret)
    }

    pub async fn destroy(&mut self) -> Result<()> {
        let mut to_drop = 0;
        while self.package_count.load(Ordering::Relaxed) > 0 {
            self.withdraw_package(to_drop)?.package().remove().await?;
            self.package_count.fetch_sub(1, Ordering::Relaxed);
            to_drop += 1;
        }
        self.destroy_dbs()?;
        Ok(())
    }

    pub async fn destroy_broken(&mut self) -> Result<()> {
        let operation = self.view.enter()?;
        if self.sliced_mode {
            let mut count =
                self.package_status_db.get_value::<u32>(&PackageStatusKey::TotalSlices)?;
            let mut index = 0;
            let mut shards = vec![ShardIdent::masterchain()];
            if self.shard_separated {
                for shard in 0..1 << self.shard_split_depth {
                    let shard = ShardIdent::with_prefix_len(
                        self.shard_split_depth,
                        BASE_WORKCHAIN_ID,
                        if self.shard_split_depth == 0 { 0 }
                        else { (shard as u64) << (64 - self.shard_split_depth) },
                    )?;
                    shards.push(shard)
                }
            }
            while count > 0 {
                let seq_no = self.archive_id + self.slice_size * index;
                index += 1;
                let package_id = PackageId::with_values(seq_no, self.package_type);
                for shard in shards.iter() {
                    if count == 0 {
                        break;
                    }
                    let path = package_id.full_path(self.db_root_path.as_path(), shard)?;
                    match Package::remove_by_path(&self.view, &operation, &path).await {
                        Ok(_) => {
                            log::info!(
                                target: TARGET,
                                "destroy_packages: removed package {seq_no} {shard}"
                            );
                            count -= 1;
                        }
                        Err(e) => {
                            // Preserve remaining packages and tables once a
                            // deletion fails; retrying indefinitely cannot heal
                            // the now-failed archive domain.
                            return Err(e.context(format!("Cannot remove package {seq_no} {shard}")));
                        }
                    }
                }
            }
        } else {
            let size = self.package_status_db.get_value::<u64>(&PackageStatusKey::NonSlicedSize)?;
            let entry = self.get_base_entry_info();
            self.new_package(entry, Some(0), size, 0).await?;
        }
        self.destroy_dbs()
    }

    pub fn package_type(&self) -> PackageType {
        self.package_type
    }

    pub fn archive_id(&self) -> u32 {
        self.archive_id
    }

    pub fn finalized(&self) -> bool {
        self.finalized
    }

    pub async fn get_archive_id(&self, mc_seq_no: u32, shard: &ShardIdent) -> Option<u64> {
        if !self.sliced_mode {
            return Some(self.archive_id as u64);
        }
        match self.choose_package(mc_seq_no, shard).await {
            Err(e) => {
                log::warn!(target: TARGET, "get_archive_id: {e}");
                None
            }
            Ok(ChosenPackage::Info(info)) => {
                let archive_id = if self.shard_separated {
                    let seq_no = self.archive_id + self.slice_size * info.index();
                    ((seq_no as u64) << 32) | (self.archive_id as u64)
                } else {
                    ((info.index() as u64) << 32) | (self.archive_id as u64)
                };
                log::debug!(
                    target: TARGET,
                    "get_archive_id: {shard} {mc_seq_no} -> {archive_id:x}"
                );
                Some(archive_id)
            }
            Ok(ChosenPackage::Slot(_)) => None,
        }
    }

    async fn add_package(&self, entry: PackageEntryInfo, size: u64) -> Result<()> {
        let try_add_package = async |package_count, entry: &PackageEntryInfo| {
            if self
                .new_package(entry.clone(), Some(package_count), size, DEFAULT_PKG_VERSION)
                .await?
            {
                let info = if self.shard_separated { Some(entry) } else { None };
                self.entry_db.put_value(
                    &package_count.into(),
                    &PackageEntryMeta::with_data(size, DEFAULT_PKG_VERSION, info),
                )?;
                self.package_status_db
                    .put_value(&PackageStatusKey::TotalSlices, &(package_count + 1))?;
                Ok(true)
            } else {
                Ok(false)
            }
        };
        loop {
            const BUSY: u32 = 0x80000000;
            let package_count = self.package_count.fetch_or(BUSY, Ordering::Relaxed);
            if (package_count & BUSY) != 0 {
                tokio::task::yield_now().await;
                continue;
            }
            let result = try_add_package(package_count, &entry).await;
            let new_count = match &result {
                Err(_) | Ok(false) => package_count,
                Ok(true) => package_count + 1,
            };
            if self
                .package_count
                .compare_exchange(
                    package_count | BUSY,
                    new_count,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_err()
                && result.is_ok()
            {
                tokio::task::yield_now().await;
                continue;
            }
            if let Err(e) = result {
                break Err(e);
            } else {
                break Ok(());
            }
        }
    }

    #[cfg(test)]
    fn observe_metadata_cut(&self, stage: MetadataCut, offset: u64, size: u64) -> Result<()> {
        let gate = {
            let mut gate = self.metadata_gate.lock().unwrap();
            if gate.as_ref().is_some_and(|(selected, _)| *selected == stage) {
                gate.take().map(|(_, gate)| gate)
            } else { None }
        };
        if let Some(gate) = gate { gate(offset, size)?; }
        Ok(())
    }

    pub async fn add_file<B: Borrow<BlockIdExt> + Hash>(
        &self,
        block_handle: &BlockHandle,
        entry_id: &PackageEntryId<B>,
        data: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let offset_key = entry_id.into();
        if self.offsets_db.contains(&offset_key)? {
            // afrer DB's truncation it is possible to have some remains in offsets_db
            log::warn!(
                target: TARGET,
                "Entry {entry_id} was already presented in offsets_db, it will be rewritten"
            )
        }
        let mc_seq_no = get_mc_seq_no(block_handle);
        let package_info = loop {
            match self.choose_package(mc_seq_no, block_handle.id().shard()).await? {
                ChosenPackage::Info(info) => break info,
                ChosenPackage::Slot(entry) => {
                    if !(entry.seqno - self.archive_id).is_multiple_of(self.slice_size) {
                        fail!(
                            "Blocks must not be skipped! archive Id {}, mc_seq_no {mc_seq_no}, \
                            seqno {}, expected seqno {}",
                            self.archive_id,
                            entry.seqno,
                            mc_seq_no - (mc_seq_no - self.archive_id) / self.slice_size
                        )
                    }
                    self.add_package(entry, 0).await?;
                }
            }
        };
        let entry = PackageEntry::with_data(entry_id.filename(), data);
        let after_append = |offset: u64, size: u64, indexed_offset: Option<u32>| {
            let info = if self.shard_separated { Some(package_info.entry()) } else { None };
            let index = if self.sliced_mode { Some(package_info.index()) } else { None };
            let meta = PackageEntryMeta::with_data(size, package_info.version(), info);
            log::debug!(
                target: TARGET,
                "Writing package entry metadata {}: {meta:?}, offset: {offset}",
                index.map(|index| format!(" for slice #{index}")).unwrap_or("".to_string())
            );
            #[cfg(test)]
            self.observe_metadata_cut(MetadataCut::EntryMeta, offset, size)?;
            self.entry_db.put_value(&index.unwrap_or(u32::MAX).into(), &meta)?;
            if !self.sliced_mode {
                #[cfg(test)]
                self.observe_metadata_cut(MetadataCut::NonSlicedStatus, offset, size)?;
                self.package_status_db.put_value(&PackageStatusKey::NonSlicedSize, &size)?;
            }
            #[cfg(test)]
            self.observe_metadata_cut(MetadataCut::Offset, offset, size)?;
            self.offsets_db.put_value(&offset_key, &offset)?;
            if let Some(indexed_offset) = indexed_offset {
                #[cfg(test)]
                self.observe_metadata_cut(MetadataCut::BlockIndex, offset, size)?;
                self.block_index_db.put(block_handle, indexed_offset)?;
            }
            Ok(())
        };
        let entry = if matches!(entry_id, PackageEntryId::Block(_)) {
            package_info.package().append_indexed_entry(entry, |offset, size| {
                after_append(u64::from(offset), size, Some(offset))
            }).await?
        } else {
            package_info.package().append_entry(entry, |offset, size| {
                after_append(offset, size, None)
            }).await?
        };
        // Relocation may delete the loose copy immediately after this returns.
        // Commit package directory entries and the provider's index WAL first.
        self.sync_block_package(block_handle, None).await?;
        Ok(entry.take_data())
    }

    pub async fn sync_block_package(
        &self,
        handle: &BlockHandle,
        observer: crate::durability::SyncObservation,
    ) -> Result<()> {
        let package = match self.choose_package(get_mc_seq_no(handle), handle.id().shard()).await? {
            ChosenPackage::Info(info) => info,
            ChosenPackage::Slot(_) => fail!("Required archive package is absent"),
        };
        package.package().sync_durable(observer.clone()).await?;
        // These tables belong to this archive's actual provider DB (which can
        // differ from the node DB in archival epoch mode).
        self.entry_db.sync_wal_observed(observer.as_deref())?;
        self.offsets_db.sync_wal_observed(observer.as_deref())?;
        self.package_status_db.sync_wal_observed(observer.as_deref())?;
        Ok(())
    }

    pub async fn get_file<B: Borrow<BlockIdExt> + Hash>(
        &self,
        block_handle: &BlockHandle,
        entry_id: &PackageEntryId<B>,
    ) -> Result<Option<PackageEntry>> {
        let mc_seq_no = get_mc_seq_no(block_handle);
        let shard = block_handle.id().shard();
        self.get_file_raw(mc_seq_no, &shard, entry_id).await
    }

    async fn get_file_raw<B: Borrow<BlockIdExt> + Hash>(
        &self,
        mc_seq_no: u32,
        shard: &ShardIdent,
        entry_id: &PackageEntryId<B>,
    ) -> Result<Option<PackageEntry>> {
        let offset_key = entry_id.into();
        let offset = match self.offsets_db.try_get_value(&offset_key)? {
            Some(offset) => offset,
            None => {
                log::warn!(
                    target: TARGET,
                    "Inconsistent archive: offsets_db missing entry {entry_id} \
                     (slice archive_id={}, shard={shard}, mc_seq_no={mc_seq_no})",
                    self.archive_id,
                );
                return Ok(None);
            }
        };
        let package_info = match self.choose_package(mc_seq_no, shard).await? {
            ChosenPackage::Info(info) => info,
            ChosenPackage::Slot(_) => {
                fail!(
                    "mc_seq_no {mc_seq_no} is too big to get file {entry_id} from archive {}",
                    self.archive_id
                );
            }
        };
        log::debug!(
            target: TARGET,
            "Reading package entry: {}, offset: {offset}",
            package_info.package().get_path()
        );
        let entry = package_info.package().read_entry(offset).await?;
        if entry.data().is_empty() {
            fail!("Read entry ({}) is corrupted! It can't have zero length!", entry_id);
        }
        Ok(Some(entry))
    }

    #[cfg(any(test, feature = "integration-test-support"))]
    pub(super) fn test_remove_entry_offset<B: Borrow<BlockIdExt> + Hash>(&self, entry: &PackageEntryId<B>) -> Result<()> {
        let key = entry.into();
        if !self.offsets_db.contains(&key)? { fail!("Fault fixture archive entry was absent"); }
        self.offsets_db.delete(&key)
    }

    pub async fn get_file_bounded<B: Borrow<BlockIdExt> + Hash>(
        &self,
        handle: &BlockHandle,
        entry_id: &PackageEntryId<B>,
        limits: super::bounded_read::ArchiveReadLimits,
    ) -> Result<Option<PackageEntry>> {
        let operation = self.view.enter()?;
        self.get_file_bounded_in(&operation, handle, entry_id, limits).await
    }

    pub(super) async fn get_file_bounded_in<B: Borrow<BlockIdExt> + Hash>(
        &self, parent: &ArchiveOperation, handle: &BlockHandle,
        entry_id: &PackageEntryId<B>, limits: super::bounded_read::ArchiveReadLimits,
    ) -> Result<Option<PackageEntry>> {
        let operation = self.view.inherit(parent)?;
        self.get_file_raw_bounded(&operation, get_mc_seq_no(handle), handle.id().shard(), entry_id, limits).await
    }

    async fn get_file_raw_bounded<B: Borrow<BlockIdExt> + Hash>(
        &self,
        operation: &ArchiveOperation,
        mc_seq_no: u32,
        shard: &ShardIdent,
        entry_id: &PackageEntryId<B>,
        limits: super::bounded_read::ArchiveReadLimits,
    ) -> Result<Option<PackageEntry>> {
        let offset_key = entry_id.into();
        let offset = match self.offsets_db.try_get_value(&offset_key)? {
            Some(offset) => offset,
            None => {
                log::warn!(
                    target: TARGET,
                    "Inconsistent archive: offsets_db missing entry {entry_id} \
                     (slice archive_id={}, shard={shard}, mc_seq_no={mc_seq_no})",
                    self.archive_id,
                );
                return Ok(None);
            }
        };
        let package_info = match self.choose_package(mc_seq_no, shard).await? {
            ChosenPackage::Info(info) => info,
            ChosenPackage::Slot(_) => {
                fail!(
                    "mc_seq_no {mc_seq_no} is too big to get file {entry_id} from archive {}",
                    self.archive_id
                );
            }
        };
        log::debug!(
            target: TARGET,
            "Reading package entry: {}, offset: {offset}",
            package_info.package().get_path()
        );
        let entry = package_info.package().read_entry_bounded_in(operation, offset, limits).await?;
        if entry.filename() != entry_id.filename() { fail!("Archive entry filename mismatch"); }
        if entry.data().is_empty() {
            fail!("Read entry ({}) is corrupted! It can't have zero length!", entry_id);
        }
        Ok(Some(entry))
    }

    pub async fn get_slice(&self, archive_id: u64, offset: u64, limit: u32) -> Result<Vec<u8>> {
        let operation = self.view.enter()?;
        self.get_slice_in(&operation, archive_id, offset, limit).await
    }

    pub(super) async fn get_slice_in(&self, parent: &ArchiveOperation, archive_id: u64, offset: u64, limit: u32) -> Result<Vec<u8>> {
        let operation = self.view.inherit(parent)?;
        super::bounded_read::check_length("range", u64::from(limit), super::bounded_read::ARCHIVE_RANGE_MAX_BYTES)?;
        if archive_id as u32 != self.archive_id {
            fail!(
                "Bad archive ID (archive_id = {}, expected {})!",
                archive_id as u32,
                self.archive_id
            )
        }
        let index = if self.shard_separated {
            ((archive_id >> 32) as u32).checked_sub(self.archive_id)
                .and_then(|relative| relative.checked_div(self.slice_size))
                .ok_or_else(|| error!("Invalid archive slice index"))?
        } else {
            (archive_id >> 32) as u32
        };
        let Some(package_info) = self.get_package_by_index(index).await else {
            fail!("index {index} is not found in archive")
        };
        package_info.package().read_range_in(&operation, offset, limit).await
    }

    pub async fn get_block_by_lookup_result(
        &self,
        lookup_result: LookupResult,
    ) -> Result<Option<(BlockIdExt, Vec<u8>)>> {
        let LookupResult { shard, mc_ref, offset } = lookup_result;
        let package_info = match self.choose_package(mc_ref, &shard).await? {
            ChosenPackage::Info(info) => info,
            ChosenPackage::Slot(_) => {
                log::warn!(
                    "mc_seq_no {mc_ref} is too big to get archive file {}, 
                    will get from block index",
                    self.archive_id
                );
                return Ok(None);
            }
        };
        log::trace!(
            target: TARGET,
            "Reading package entry: {}, offset: {offset}",
            package_info.package().get_path()
        );
        let entry = package_info.package().read_entry(offset as u64).await?;
        if entry.data().is_empty() {
            log::warn!(
                "Read entry ({} {} {}) is corrupted! It can't have zero length!",
                shard,
                mc_ref,
                offset
            );
            return Ok(None);
        }
        let entry_id = PackageEntryId::<BlockIdExt>::from_filename(entry.filename())?;
        let PackageEntryId::Block(block_id) = entry_id else {
            log::warn!(
                "Read entry ({} {} {}) has not a 'block' filename: {}",
                shard,
                mc_ref,
                offset,
                entry.filename()
            );
            return Ok(None);
        };
        Ok(Some((block_id.clone(), entry.take_data())))
    }

    pub async fn lookup_block_by_seqno(
        &self,
        prefix: &AccountIdPrefixFull,
        seqno: u32,
    ) -> Result<Option<(BlockIdExt, Vec<u8>)>> {
        let Some(lr) = self.block_index_db.lookup_by_seqno(prefix, seqno)? else {
            return Ok(None);
        };
        self.get_block_by_lookup_result(lr).await
    }

    pub async fn lookup_proof_by_seqno(
        &self,
        prefix: &AccountIdPrefixFull,
        seqno: u32,
    ) -> Result<Option<(BlockIdExt, Vec<u8>)>> {
        let Some(lr) = self.block_index_db.lookup_by_seqno(prefix, seqno)? else {
            return Ok(None);
        };
        let mc_seq_no = lr.mc_ref;
        let Some((block_id, _)) = self.get_block_by_lookup_result(lr).await? else {
            return Ok(None);
        };

        // Masterchain blocks store proofs under `Proof`, shard blocks under `ProofLink`.
        let entry_id = if block_id.shard().is_masterchain() {
            PackageEntryId::Proof(block_id.clone())
        } else {
            PackageEntryId::ProofLink(block_id.clone())
        };

        self.get_file_raw(mc_seq_no, block_id.shard(), &entry_id)
            .await
            .map(|opt_entry| opt_entry.map(|entry| (block_id, entry.take_data())))
    }

    pub async fn lookup_block_by_lt(
        &self,
        prefix: &AccountIdPrefixFull,
        lt: u64,
    ) -> Result<Option<(BlockIdExt, Vec<u8>)>> {
        let Some(lr) = self.block_index_db.lookup_by_lt(prefix, lt)? else {
            return Ok(None);
        };
        self.get_block_by_lookup_result(lr).await
    }

    pub async fn lookup_blocks_by_utime<'a>(
        &self,
        prefix: &AccountIdPrefixFull,
        utime: u32,
        mut f: Box<dyn FnMut(BlockIdExt, Vec<u8>) -> Result<bool> + Send + 'a>,
    ) -> Result<()> {
        let mut found = vec![];
        self.block_index_db.lookup_by_utime(prefix, utime, &mut |lr| {
            found.push(lr);
            Ok(true)
        })?;
        for lr in found {
            if let Some((block_id, data)) = self.get_block_by_lookup_result(lr).await? {
                if !f(block_id, data)? {
                    break;
                }
            }
        }
        Ok(())
    }

    /// truncs slice starting from master block_id
    pub async fn trunc(&mut self, selection: Arc<TruncationSelection>) -> Result<()> {
        let block_id = selection.cutoff();
        log::info!(
            target: TARGET,
            "truncating by mc_seq_no: {}, sliced_mode: {}",
            block_id.seq_no(), self.sliced_mode
        );

        let offset =
            match self.offsets_db.try_get_value(&(&PackageEntryId::Proof(block_id)).into())? {
                Some(offset) => offset,
                None => return Ok(()),
            };

        let (mc_seqno, mc_index) =
            match self.choose_package(block_id.seq_no(), &ShardIdent::masterchain()).await {
                Err(e) => fail!("Slice is corrupted, sliced mode {}: {e}", self.sliced_mode),
                Ok(ChosenPackage::Info(ref info)) => (info.entry().seqno, info.index()),
                Ok(ChosenPackage::Slot(ref entry)) => {
                    fail!(
                        "Slice is corrupted, sliced mode true: no index for mc_seq_no {}",
                        entry.seqno
                    );
                }
            };

        // Find all related packages
        let upto = if !self.sliced_mode || !self.shard_separated {
            mc_index + 1
        } else {
            let mut count = 0;
            let mut total = 0;
            for shard in 0..(1 << self.shard_split_depth) {
                let prefix = if self.shard_split_depth == 0 {
                    0
                } else {
                    (shard as u64) << (64 - self.shard_split_depth)
                };
                let shard =
                    ShardIdent::with_prefix_len(self.shard_split_depth, BASE_WORKCHAIN_ID, prefix)?;
                let entry = PackageEntryInfo { seqno: mc_seqno, shard };
                if let Some(package_info) = self.get_package_by_entry(&entry).await {
                    let index = package_info.index();
                    if index <= mc_index {
                        fail!(
                            "Slice is corrupted, sliced mode {}: \
                            shard {} index {index} < MC index {mc_index}",
                            self.sliced_mode,
                            entry.shard
                        )
                    }
                    count += 1;
                    total += index - mc_index;
                }
            }
            if total != count * (count + 1) / 2 {
                fail!(
                    "Slice is corrupted, sliced mode {}: shard indexes are sparsed",
                    self.sliced_mode
                )
            }
            mc_index + count + 1
        };

        // Remove tail packages
        let mut to_drop = upto;
        while self.package_count.load(Ordering::Relaxed) > upto {
            self.withdraw_package(to_drop)
                .map_err(|e| error!("Slice is corrupted: {e}, cannot drop"))?
                .destroy()
                .await?;
            self.package_count.fetch_sub(1, Ordering::Relaxed);
            to_drop += 1;
        }

        // Truncate last package(s)

        if !self.sliced_mode {
            let package_info = self
                .withdraw_package(0)
                .map_err(|e| error!("Slice is corrupted: {e}, cannot truncate, non-sliced mode"))?;
            package_info.package().truncate(offset).await?;
            self.entry_db.put_value(&u32::MAX.into(),
                &PackageEntryMeta::with_data(offset, package_info.version(), None))?;
            self.package_status_db.put_value(&PackageStatusKey::NonSlicedSize, &offset)?;
            let entry = package_info.entry().clone();
            self.package_store.insert(entry.clone(), OnceLock::from(Arc::new(package_info)));
            self.package_index.insert(0, entry);
            return Ok(());
        }

        // Delete unneeded entries from package by repack.
        // 1) read all items from package and write it (with condition) into "new" package
        //      write new offsets and indexes into correspond dbs by the way
        // 2) rename new package
        // while old package is not deleted repack might be replay many times
        // (it doesn't use offsets db), but read form package will fail
        // (offsets db points new package)

        // TotalSlices is written after the loop because the effective count may be less than
        // upto if all entries in the boundary package(s) are deleted.
        let mut effective_total = mc_index;

        for i in mc_index..upto {
            let mut package_info = self
                .withdraw_package(i)
                .map_err(|e| error!("Slice is corrupted: {e}, cannot truncate"))?;
            let old_package = package_info.package();
            let new_name = old_package.get_path() + ".new";
            log::trace!(target: TARGET, "repack package {}", old_package.get_path());
            let _ = tokio::fs::remove_file(&new_name).await;
            let new_package = Package::open(self.view.clone(), &self.view.enter()?, new_name.into(), false, true).await?;
            let mut old_reader = old_package.open_reader().await?;

            let mut any_kept = false;
            let mut source_offset = 0u64;
            let mut index_offsets = RepackOffsets::new();
            while let Some(entry) = old_reader.next().await? {
                let entry_id = PackageEntryId::from_filename(entry.filename())?;
                let block_offset = if matches!(&entry_id, PackageEntryId::Block(_)) {
                    Some(source_offset)
                } else {
                    None
                };
                source_offset = source_offset.checked_add(entry.serialized_size()?)
                    .ok_or_else(|| error!("Archive source offset overflow"))?;
                let id = match &entry_id {
                    PackageEntryId::Block(id) => id,
                    PackageEntryId::Proof(id) => id,
                    PackageEntryId::ProofLink(id) => id,
                    _ => fail!("Unsupported entry: {entry_id:?}"),
                };
                if selection.should_delete(id) {
                    log::trace!(target: TARGET, "repack package: delete {entry_id}");
                    if let Some(offset) = block_offset {
                        index_offsets.insert((id.shard().clone(), offset), None);
                    }
                    if let Err(e) = self.offsets_db.delete(&(&entry_id).into()) {
                        log::warn!(
                            target: TARGET,
                            "Can't delete {entry_id} from offsets db (slice: {}): {e}",
                            self.archive_id
                        )
                    }
                } else {
                    log::trace!(target: TARGET, "repack package: repack {entry_id}");
                    let mut after_append = |offset: u64, size: u64| {
                        let info = if self.shard_separated {
                            Some(package_info.entry())
                        } else {
                            None
                        };
                        let meta =
                            PackageEntryMeta::with_data(size, package_info.version(), info);
                        let index = package_info.index();
                        log::debug!(
                            target: TARGET,
                            "Writing package entry metadata for slice \
                            #{index}: {meta:?}, offset: {offset}"
                        );
                        self.entry_db.put_value(&index.into(), &meta)?;
                        self.offsets_db.put_value(&(&entry_id).into(), &offset)?;
                        if let Some(old) = block_offset {
                            index_offsets.insert((id.shard().clone(), old), Some(offset));
                        }
                        Ok(())
                    };
                    if block_offset.is_some() {
                        new_package.append_indexed_entry(entry, |offset, size| {
                            after_append(u64::from(offset), size)
                        }).await?;
                    } else {
                        new_package.append_entry(entry, after_append).await?;
                    }
                    any_kept = true;
                }
            }
            if any_kept {
                effective_total = i + 1;
            } else {
                log::debug!(
                    target: TARGET,
                    "All entries deleted from package #{i} in slice {}: \
                    not counting it towards TotalSlices",
                    self.archive_id
                );
                if let Err(e) = self.entry_db.delete(&i.into()) {
                    log::warn!(
                        target: TARGET,
                        "Can't delete #{i} from entry_db (slice: {}): {e}",
                        self.archive_id
                    );
                }
            }

            let index_batch = self.block_index_db.prepare_repack_offsets(
                &index_offsets,
                |shard, mc_ref| {
                    Ok(self.package_entry_info(mc_ref, shard)? == *package_info.entry())
                },
            )?;
            tokio::fs::rename(new_package.get_path(), old_package.get_path()).await?;
            crate::archives::package::sync_file_and_parents(old_package.path()).await?;
            self.block_index_db.commit_repack_offsets(index_batch)?;
            let name = old_package.get_path().into();
            *package_info.package_mut() = Package::open(self.view.clone(), &self.view.enter()?, name, false, true).await?;
            log::trace!(
                target: TARGET,
                "package repacked {}",
                package_info.package().path().display()
            );
            let entry = package_info.entry().clone();
            self.package_store.insert(entry.clone(), OnceLock::from(Arc::new(package_info)));
            self.package_index.insert(i, entry);
        }

        self.package_status_db
            .put_value(&PackageStatusKey::TotalSlices, &(effective_total as u32))?;

        Ok(())
    }

    async fn choose_package(&self, mc_seq_no: u32, shard: &ShardIdent) -> Result<ChosenPackage> {
        let entry_info = self.package_entry_info(mc_seq_no, shard)?;
        let ret = match self.get_package_by_entry(&entry_info).await {
            Some(info) => ChosenPackage::Info(info),
            None => ChosenPackage::Slot(entry_info),
        };
        Ok(ret)
    }

    fn package_entry_info(&self, mc_seq_no: u32, shard: &ShardIdent) -> Result<PackageEntryInfo> {
        let entry_info = if !self.sliced_mode || (self.package_type == PackageType::KeyBlocks) {
            self.get_base_entry_info()
        } else if let Some(seqno) = mc_seq_no.checked_sub(self.archive_id) {
            PackageEntryInfo {
                seqno: mc_seq_no - seqno % self.slice_size,
                shard: if !self.shard_separated || shard.is_masterchain() {
                    ShardIdent::masterchain()
                } else {
                    shard.relative_with_len(self.shard_split_depth)?
                },
            }
        } else {
            fail!("Wrong mc_seq_no {mc_seq_no} < {}", self.archive_id)
        };
        Ok(entry_info)
    }

    #[allow(clippy::too_many_arguments)]
    async fn create(
        view: ArchiveView,
        db: Arc<RocksDb>,
        db_root_path: Arc<PathBuf>,
        archive_id: u32,
        package_type: PackageType,
        finalized: bool,
        create_if_not_exist: bool,
        mut shard_split_depth: u8,
        #[cfg(feature = "telemetry")] telemetry: Arc<StorageTelemetry>,
        allocated: Arc<StorageAlloc>,
    ) -> Result<Self> {
        let packages_path = db_root_path.join(ArchiveManager::ARCHIVE_DIR).join("packages");
        tokio::fs::create_dir_all(&packages_path).await.map_err(|e| {
            error!("Cannot create archive packages directory {}: {e}", packages_path.display())
        })?;
        let (prefix, slice_size, sliced_mode) = if package_type == PackageType::KeyBlocks {
            shard_split_depth = 0;
            ("key_", KEY_ARCHIVE_PACKAGE_SIZE, false)
        } else {
            ("", ARCHIVE_PACKAGE_SIZE, true)
        };
        let ret = Self {
            view,
            archive_id,
            db_root_path,
            finalized,
            package_count: AtomicU32::new(0),
            package_index: lockfree::map::Map::new(),
            package_store: lockfree::map::Map::new(),
            package_type,
            shard_separated: false,
            shard_split_depth,
            sliced_mode,
            slice_size,
            entry_db: PackageEntryMetaDb::with_db(
                db.clone(),
                format!("entry_meta_{prefix}db_{archive_id}"),
                create_if_not_exist,
            )?,
            block_index_db: BlockIndexDb::with_db(
                db.clone(),
                format!("block_index_{prefix}db_{archive_id}"),
                create_if_not_exist,
            )?,
            offsets_db: PackageOffsetsDb::with_db(
                db.clone(),
                format!("offsets_{prefix}db_{archive_id}"),
                create_if_not_exist,
            )?,
            package_status_db: PackageStatusDb::with_db(
                db,
                format!("status_{prefix}db_{archive_id}"),
                create_if_not_exist,
            )?,
            #[cfg(feature = "telemetry")]
            telemetry,
            #[cfg(test)]
            metadata_gate: std::sync::Mutex::new(None),
            #[cfg(test)]
            before_package_open: std::sync::Mutex::new(None),
            allocated,
        };
        Ok(ret)
    }

    fn destroy_dbs(&mut self) -> Result<()> {
        if !self.entry_db.destroy()? {
            fail!("entry_db of slice {} was not destroyed", self.archive_id);
        }
        if !self.offsets_db.destroy()? {
            fail!("offsets_db of slice {} was not destroyed", self.archive_id);
        }
        if !self.package_status_db.destroy()? {
            fail!("package_status_db of slice {} was not destroyed", self.archive_id);
        }
        if self.block_index_db.destroy().is_err() {
            fail!("block_index_db of slice {} was not destroyed", self.archive_id);
        }
        Ok(())
    }

    fn get_base_entry_info(&self) -> PackageEntryInfo {
        PackageEntryInfo { seqno: self.archive_id, shard: ShardIdent::masterchain() }
    }

    async fn get_package_by_index(&self, index: u32) -> Option<Arc<PackageInfo>> {
        loop {
            let Some(entry) = self.package_index.get(&index) else {
                break None;
            };
            if let Some(package_info) = self.get_package_by_entry(entry.val()).await {
                break Some(package_info);
            }
        }
    }

    async fn get_package_by_entry(&self, entry: &PackageEntryInfo) -> Option<Arc<PackageInfo>> {
        loop {
            let Some(package_info) = self.package_store.get(entry) else {
                break None;
            };
            if let Some(package_info) = package_info.val().get() {
                break Some(package_info.clone());
            }
            tokio::task::yield_now().await;
        }
    }

    async fn new_package(
        &self,
        entry: PackageEntryInfo,
        index: Option<u32>,
        size: u64,
        version: u32,
    ) -> Result<bool> {
        let operation = self.view.enter()?;
        self.open_package(&operation, entry, index, size, version, PackageOpenMode::RecoverOrCreate).await
    }

    async fn open_package(
        &self, parent: &ArchiveOperation, entry: PackageEntryInfo, index: Option<u32>, size: u64,
        version: u32, mode: PackageOpenMode,
    ) -> Result<bool> {
        let operation = self.view.inherit(parent)?;
        let package_str = format!("{} {}", entry.seqno, entry.shard);
        log::debug!(
            target: TARGET,
            "Adding package {package_str}, size: {size} bytes, version: {version}"
        );
        let package_id = PackageId::with_values(entry.seqno, self.package_type);
        let path = package_id.full_path(self.db_root_path.as_path(), &entry.shard)?;
        let Some(parent) = path.parent() else {
            fail!("Cannot create parent directory for {}", path.display())
        };
        if matches!(mode, PackageOpenMode::RecoverOrCreate) {
            create_dir_all(parent)
                .map_err(|e| error!("Cannot create directory {} : {e}", parent.display()))?;
        }
        if add_unbound_object_to_map(&self.package_store, entry.clone(), || Ok(OnceLock::new()))? {
            let create_package = async || {
                #[cfg(test)]
                {
                    let gate = self.before_package_open.lock().unwrap().take();
                    if let Some(gate) = gate { gate(); }
                }
                if matches!(mode, PackageOpenMode::PreserveExisting) {
                    return Package::open_existing_exact(self.view.clone(), &operation, path.clone(), self.finalized, size).await;
                }
                let package = match Package::open(self.view.clone(), &operation, path.clone(), self.finalized, true).await {
                    Ok(p) => p,
                    Err(e) if e.is::<ArchiveContextError>() => return Err(e),
                    Err(e) => match tokio::fs::remove_file(path.as_path()).await {
                        Ok(_) => fail!(
                            "Failed to open or create archive {}: {e}. \
                            Archive file was cleaned up",
                            path.display()
                        ),
                        Err(e2) => fail!(
                            "Failed to open or create archive {}: {e}. \
                            Error cleaning archive file: {e2}",
                            path.display()
                        ),
                    },
                };
                if !self.finalized && (version >= DEFAULT_PKG_VERSION) {
                    package.truncate(size).await?;
                }
                Ok(package)
            };
            let package = match create_package().await {
                Ok(package) => package,
                Err(e) => {
                    self.package_store.remove(&entry);
                    return Err(e);
                }
            };
            let index = index.unwrap_or_else(|| self.package_count.fetch_add(1, Ordering::Relaxed));
            let pi = PackageInfo::with_data(
                entry.clone(),
                index,
                package_id,
                package,
                version,
                #[cfg(feature = "telemetry")]
                &self.telemetry,
                &self.allocated,
            );
            let Some(package_info) = self.package_store.get(&entry) else {
                fail!("Cannot initialize package info for {package_str}");
            };
            if package_info.val().set(Arc::new(pi)).is_err() {
                fail!("Cannot set package info for {package_str}");
            }
            self.package_index.insert(index, entry);
            log::info!(
                target: TARGET,
                "Added package {package_str}, index {index}, size: {size} bytes, version: {version}"
            );
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn withdraw_package(&self, index: u32) -> Result<PackageInfo> {
        let Some(entry) = self.package_index.remove(&index) else {
            fail!("No index entry for package with index {index}");
        };
        let Some(package_info) = self.package_store.remove(entry.val()) else {
            fail!("No package info for package with index {index}");
        };
        let (_, package_info) =
            lockfree::map::Removed::<_, _>::try_into(package_info).map_err(|_| {
                error!("Cannot extract info out of store for package with index {index}")
            })?;
        let Some(package_info) = package_info.into_inner() else {
            fail!("Cannot extract info out of cell for package with index {index}");
        };
        Arc::try_unwrap(package_info)
            .map_err(|_| error!("Cannot get mutable info for package with index {index}"))
    }
}

#[cfg(test)]
#[path = "../tests/test_archive_slice.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/test_disk_full_archive.rs"]
mod disk_full_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "../tests/test_sst_archive.rs"]
mod sst_disk_full_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "../tests/test_archive_metadata_eio.rs"]
mod metadata_eio_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "../tests/test_archive_package_io_eio.rs"]
mod package_io_eio_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "../tests/test_archive_repack_readers.rs"]
mod repack_reader_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "../tests/test_archive_repack_rename.rs"]
mod repack_rename_tests;
