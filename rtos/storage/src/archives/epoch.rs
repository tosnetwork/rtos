/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use super::{context::{ArchiveOperation, ArchiveProvider, ArchiveView},
    recovery_participant::{Anchor, Identity, Provider}};
use crate::{
    archives::ARCHIVE_SLICE_SIZE,
    db::rocksdb::{AccessType, RocksDb},
    TARGET,
};
use rtos_block::{error, fail, Result};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

const EPOCH_META_FILENAME: &str = "epoch_meta.json";

/// Persisted metadata for an epoch directory
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub(crate) struct EpochMeta {
    pub mc_seq_no_start: u32,
    pub mc_seq_no_end: u32,
}

async fn read_epoch_meta(epoch_path: &Path) -> Result<EpochMeta> {
    let meta_path = epoch_path.join(EPOCH_META_FILENAME);
    let data = tokio::fs::read_to_string(&meta_path)
        .await
        .map_err(|e| error!("Cannot read {}: {}", meta_path.display(), e))?;
    serde_json::from_str(&data).map_err(|e| error!("Cannot parse {}: {}", meta_path.display(), e))
}

pub(crate) async fn write_epoch_meta(epoch_path: &Path, meta: &EpochMeta) -> Result<()> {
    let meta_path = epoch_path.join(EPOCH_META_FILENAME);
    let data = serde_json::to_string_pretty(meta)
        .map_err(|e| error!("Cannot serialize epoch meta: {}", e))?;
    tokio::fs::write(&meta_path, data.as_bytes())
        .await
        .map_err(|e| error!("Cannot write {}: {}", meta_path.display(), e))
}

/// Configuration for a single existing epoch directory
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct EpochEntry {
    pub path: PathBuf,
}

/// Archival mode configuration.
/// When present, archives are split into epochs and GC is disabled.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ArchivalModeConfig {
    /// Number of MC blocks per epoch. Must be a positive multiple of ARCHIVE_SLICE_SIZE (20_000).
    pub epoch_size: u32,
    /// Path where new epoch directories will be created
    pub new_epochs_path: PathBuf,
    /// List of existing epoch directories, ordered by ascending MC seq_no.
    #[serde(default)]
    pub existing_epochs: Vec<EpochEntry>,
}

/// Read-only configuration/discovery result. No native DB has been opened yet.
pub(crate) struct ExistingEpoch {
    pub path: PathBuf,
    pub meta: EpochMeta,
    pub explicit: bool,
}

/// Discover every configured epoch before opening any provider. Recovery callers
/// request complete enumeration, which also refuses unrecognized directories.
/// Native identity, physical-alias and owned-open checks follow this path scan.
pub(crate) async fn scan_existing(config: &ArchivalModeConfig, complete: bool) -> Result<Vec<ExistingEpoch>> {
    if config.epoch_size == 0 || config.epoch_size % ARCHIVE_SLICE_SIZE != 0 {
        fail!("epoch_size must be a positive multiple of ARCHIVE_SLICE_SIZE ({})", ARCHIVE_SLICE_SIZE);
    }
    let mut selected = std::collections::BTreeMap::<u32, ExistingEpoch>::new();
    async fn inspect(path: &Path, size: u32, explicit: bool) -> Result<ExistingEpoch> {
        // Reject symlinks in every component rather than canonicalizing through
        // them. This is inspection, not an owned open against external renames.
        let absolute = if path.is_absolute() { path.to_path_buf() } else { std::env::current_dir()?.join(path) };
        let mut prefix = PathBuf::new();
        for component in absolute.components() {
            if matches!(component, std::path::Component::ParentDir) { fail!("Parent traversal in epoch path"); }
            prefix.push(component.as_os_str());
            let meta = tokio::fs::symlink_metadata(&prefix).await?;
            if meta.file_type().is_symlink() || !meta.is_dir() { fail!("Invalid epoch directory component"); }
        }
        let meta_path = absolute.join(EPOCH_META_FILENAME);
        let file = tokio::fs::symlink_metadata(&meta_path).await?;
        if !file.is_file() || file.file_type().is_symlink() { fail!("Invalid epoch metadata file"); }
        let meta = read_epoch_meta(&absolute).await?;
        EpochRouter::validate_epoch_meta(&meta, size, &absolute)?;
        Ok(ExistingEpoch { path: tokio::fs::canonicalize(absolute).await?, meta, explicit })
    }
    fn insert(selected: &mut std::collections::BTreeMap<u32, ExistingEpoch>, value: ExistingEpoch) -> Result<()> {
        if let Some(old) = selected.get(&value.meta.mc_seq_no_start) {
            if old.path != value.path || old.meta.mc_seq_no_end != value.meta.mc_seq_no_end {
                fail!("Conflicting epoch providers for range starting {}", value.meta.mc_seq_no_start);
            }
            // One physical path configured explicitly and found by discovery is
            // one provider; keep its stable explicit anchor, not vector position.
            return Ok(());
        }
        selected.insert(value.meta.mc_seq_no_start, value);
        Ok(())
    }
    for entry in &config.existing_epochs {
        insert(&mut selected, inspect(&entry.path, config.epoch_size, true).await?)?;
    }
    // Absence is read-only: normal construction may create this directory later.
    // A pending recovery still has to match its recorded provider inventory.
    let mut prefix = PathBuf::new();
    let absolute = if config.new_epochs_path.is_absolute() { config.new_epochs_path.clone() }
        else { std::env::current_dir()?.join(&config.new_epochs_path) };
    if absolute.components().any(|component| matches!(component, std::path::Component::ParentDir)) {
        fail!("Parent traversal in discovery path");
    }
    for component in absolute.components() {
        prefix.push(component.as_os_str());
        match tokio::fs::symlink_metadata(&prefix).await {
            Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {},
            Ok(_) => fail!("Invalid discovery directory component"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(selected.into_values().collect()),
            Err(error) => return Err(error.into()),
        }
    }
    let mut entries = tokio::fs::read_dir(&absolute).await?;
    while let Some(entry) = entries.next_entry().await? {
        let file_type = entry.file_type().await?;
        if file_type.is_symlink() { fail!("Symlink in epoch discovery directory"); }
        if !file_type.is_dir() {
            if complete { fail!("Unrecognized file in epoch discovery directory"); }
            continue;
        }
        let path = entry.path();
        match tokio::fs::symlink_metadata(path.join(EPOCH_META_FILENAME)).await {
            Ok(_) => insert(&mut selected, inspect(&path, config.epoch_size, false).await?)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !complete => {},
            Err(error) => return Err(error.into()),
        }
    }
    Ok(selected.into_values().collect())
}

/// Runtime state for a single epoch
pub struct Epoch {
    recovery: Provider,
    binding: ArchiveProvider,
    mc_seq_no_start: u32,
    mc_seq_no_end: u32,
    path: Arc<PathBuf>,
    db: Arc<RocksDb>,
}

impl Epoch {
    pub(crate) fn recovery_provider(&self) -> &Provider { &self.recovery }

    pub fn binding(&self) -> &ArchiveProvider { &self.binding }

    pub fn mc_seq_no_start(&self) -> u32 {
        self.mc_seq_no_start
    }

    pub fn mc_seq_no_end(&self) -> u32 {
        self.mc_seq_no_end
    }

    pub fn path(&self) -> &Arc<PathBuf> {
        &self.path
    }

    pub fn db(&self) -> &Arc<RocksDb> {
        &self.db
    }
}

/// Routes mc_seq_no to the appropriate epoch's RocksDb and filesystem path.
///
/// All epochs must have the same size (`epoch_size`), which allows O(1) arithmetic lookup
/// without any map search.
pub struct EpochRouter {
    view: ArchiveView,
    epochs: lockfree::map::Map<u32, Arc<Epoch>>,
    epoch_size: u32,
    new_epochs_path: PathBuf,
    creation_mutex: tokio::sync::Mutex<()>,
}

impl EpochRouter {
    pub async fn new(config: &ArchivalModeConfig, startup: &ArchiveOperation) -> Result<Self> {
        let startup = startup.view().inherit(startup)?;
        let view = startup.view();
        let existing = scan_existing(config, false).await?;
        let epochs = lockfree::map::Map::new();
        let mut identities = std::collections::HashSet::new();
        identities.insert(Identity::native(&view.binding().db().db().get_db_identity()?)?);
        for entry in existing {
            let db = RocksDb::new(&entry.path, "archive_db", None, AccessType::ReadWrite)?;
            let native = db.db().get_db_identity()?;
            let recovery = Provider::epoch(&entry.path,
                if entry.explicit { &entry.path } else { &config.new_epochs_path },
                if entry.explicit { Anchor::ExplicitEpoch } else { Anchor::Discovery },
                (entry.meta.mc_seq_no_start, entry.meta.mc_seq_no_end), &native)?;
            if !identities.insert(recovery.database) {
                fail!("Duplicate native identity among archive providers");
            }
            let binding = db.bind_archive_domain(view.binding().domain().clone())?;
            epochs.insert(entry.meta.mc_seq_no_start, Arc::new(Epoch {
                recovery, binding, mc_seq_no_start: entry.meta.mc_seq_no_start,
                mc_seq_no_end: entry.meta.mc_seq_no_end,
                path: Arc::new(entry.path), db,
            }));
        }
        tokio::fs::create_dir_all(&config.new_epochs_path).await.map_err(|e| {
            error!("Cannot create new_epochs_path {}: {}", config.new_epochs_path.display(), e)
        })?;

        Ok(Self {
            view,
            epochs,
            epoch_size: config.epoch_size,
            new_epochs_path: config.new_epochs_path.clone(),
            creation_mutex: tokio::sync::Mutex::new(()),
        })
    }

    pub fn view(&self) -> &ArchiveView { &self.view }

    pub(crate) fn rebuilt(&self, startup: &ArchiveOperation) -> Result<Self> {
        let operation = startup.inherit(self.view.binding())?;
        let epochs = lockfree::map::Map::new();
        for entry in self.epochs.iter() { epochs.insert(*entry.key(), entry.val().clone()); }
        Ok(Self { view: operation.view(), epochs, epoch_size: self.epoch_size,
            new_epochs_path: self.new_epochs_path.clone(), creation_mutex: tokio::sync::Mutex::new(()) })
    }

    /// The coordinator calls this only after closing and draining admission.
    /// Keep the actual open owners, including epochs with no affected packages.
    pub(crate) fn recovery_epochs(&self) -> Vec<Arc<Epoch>> {
        self.epochs.iter().map(|entry| entry.val().clone()).collect()
    }

    pub fn resolve(&self, mc_seq_no: u32) -> Option<Arc<Epoch>> {
        let start = (mc_seq_no / self.epoch_size) * self.epoch_size;
        self.epochs.get(&start).map(|g| Arc::clone(g.val()))
    }

    /// Resolve the epoch for a given mc_seq_no, creating a new one if needed.
    pub async fn resolve_or_create(&self, mc_seq_no: u32) -> Result<Arc<Epoch>> {
        let operation = self.view.enter()?;
        self.resolve_or_create_in(&operation, mc_seq_no).await
    }

    pub async fn resolve_or_create_in(&self, parent: &ArchiveOperation, mc_seq_no: u32) -> Result<Arc<Epoch>> {
        let operation = self.view.inherit(parent)?;
        if let Some(epoch) = self.resolve(mc_seq_no) {
            return Ok(epoch);
        }

        // Serialize creation to prevent concurrent RocksDb::new() on the same path
        let _creation_guard = self.creation_mutex.lock().await;

        // Double-check after acquiring the mutex — another caller may have created the epoch
        if let Some(epoch) = self.resolve(mc_seq_no) {
            return Ok(epoch);
        }

        // Recheck after waiting for another creator, before any new path effect.
        let _before_create = self.view.inherit(&operation)?;
        let epoch_index = mc_seq_no / self.epoch_size;
        let start = epoch_index * self.epoch_size;
        let end = start.checked_add(self.epoch_size - 1)
            .ok_or_else(|| error!("Epoch range exceeds u32 sequence space"))?;

        let epoch_dir = self.new_epochs_path.join(format!("epoch_{}", epoch_index));
        tokio::fs::create_dir_all(&epoch_dir)
            .await
            .map_err(|e| error!("Cannot create epoch directory {}: {}", epoch_dir.display(), e))?;

        let meta = EpochMeta { mc_seq_no_start: start, mc_seq_no_end: end };
        write_epoch_meta(&epoch_dir, &meta).await?;

        let db = RocksDb::new(&epoch_dir, "archive_db", None, AccessType::ReadWrite)?;
        let recovery = Provider::epoch(&epoch_dir, &self.new_epochs_path, Anchor::Discovery,
            (start, end), &db.db().get_db_identity()?)?;
        if recovery.database == Identity::native(&self.view.binding().db().db().get_db_identity()?)?
            || self.epochs.iter().any(|entry| entry.val().recovery.database == recovery.database) {
            fail!("Duplicate native identity among archive providers");
        }
        let binding = db.bind_archive_domain(self.view.binding().domain().clone())?;

        log::info!(
            target: TARGET,
            "Created new epoch {}: mc_seq_no [{}, {}], path: {}",
            epoch_index, start, end, epoch_dir.display()
        );

        let epoch = Arc::new(Epoch {
            recovery, binding,
            mc_seq_no_start: start,
            mc_seq_no_end: end,
            path: Arc::new(epoch_dir),
            db,
        });
        self.epochs.insert(start, Arc::clone(&epoch));

        Ok(epoch)
    }

    /// Returns summed approximate RocksDB memory usage across all epochs.
    pub fn memory_usage(&self) -> crate::RocksDbMemoryUsage {
        let mut total = crate::RocksDbMemoryUsage::default();
        for guard in self.epochs.iter() {
            total += guard.val().db().memory_usage();
        }
        total
    }

    pub fn epoch_size(&self) -> u32 {
        self.epoch_size
    }

    fn validate_epoch_meta(meta: &EpochMeta, epoch_size: u32, path: &Path) -> Result<()> {
        if meta.mc_seq_no_start % epoch_size != 0 {
            fail!(
                "Epoch at {} has mc_seq_no_start={} which is not aligned to epoch_size={}",
                path.display(),
                meta.mc_seq_no_start,
                epoch_size
            );
        }
        let expected_end = meta.mc_seq_no_start.checked_add(epoch_size - 1)
            .ok_or_else(|| error!("Epoch range exceeds u32 sequence space"))?;
        if meta.mc_seq_no_end != expected_end {
            fail!(
                "Epoch at {} has mc_seq_no_end={} but expected {} for epoch_size={}",
                path.display(),
                meta.mc_seq_no_end,
                expected_end,
                epoch_size
            );
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/test_epoch.rs"]
mod tests;
