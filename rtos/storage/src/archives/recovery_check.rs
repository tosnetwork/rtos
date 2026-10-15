// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Offline, non-repairing inventory for archive recovery/downgrade prechecks.
use super::{
    epoch::{ArchivalModeConfig, EpochMeta},
    package_index_db::PackageIndexEntry,
    ARCHIVE_SLICE_SIZE,
};
use crate::{
    db::node::{CELLSCOUNTERS_CF_NAME, CELLS_CF_NAME},
    dynamic_boc_rc_db::DynamicBocDb,
    shardstate_db_async::CellsDbConfig,
};
use rocksdb::{ColumnFamilyDescriptor, DBWithThreadMode, IteratorMode, MultiThreaded, Options};
use rtos_block::{error, fail, Result};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

type NativeDb = DBWithThreadMode<MultiThreaded>;

#[derive(Clone)]
pub struct CheckConfig {
    pub node_root: PathBuf,
    pub working_directory: PathBuf,
    pub archival_mode: Option<ArchivalModeConfig>,
}
#[derive(Debug, Serialize)]
pub struct ProviderReport {
    pub root: PathBuf,
    pub database: PathBuf,
    pub families: usize,
    pub archive_status_families: usize,
    pub epoch_range: Option<(u32, u32)>,
}
#[derive(Debug, Serialize)]
pub struct CheckReport {
    pub providers: Vec<ProviderReport>,
    pub live_archives: usize,
    pub scope: &'static str,
}

// Drop native DB before releasing the independent, read-only LOCK descriptor.
struct OpenProvider {
    db: NativeDb,
    _caches: Vec<rocksdb::Cache>,
    _lock: std::sync::Arc<File>,
    root: PathBuf,
    database: PathBuf,
    families: BTreeSet<String>,
    range: Option<(u32, u32)>,
    directory_identity: (u64, u64),
    lock_identity: (u64, u64),
    initial_inventory: Inventory,
}
static INSPECTION_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Resolve an inspection input without following symlinks in any path component.
pub fn resolve_checked(base: &Path, path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() { path.to_path_buf() } else { base.join(path) };
    let mut prefix = PathBuf::new();
    for component in absolute.components() {
        prefix.push(component.as_os_str());
        if fs::symlink_metadata(&prefix)?.file_type().is_symlink() {
            fail!("Symlink in inspection path: {}", prefix.display());
        }
    }
    Ok(fs::canonicalize(absolute)?)
}
fn file_identity(metadata: &fs::Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

fn shared_lock(file: &File, database: &Path) -> Result<()> {
    // SAFETY: flock is a native Linux structure, and fcntl receives its valid pointer.
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = libc::F_RDLCK as _;
    lock.l_whence = libc::SEEK_SET as _;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &lock) } == -1 {
        return Err(error!(
            "Database is not offline: {}: {}",
            database.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}
#[derive(Default)]
struct ProviderLocks {
    held: BTreeMap<(u64, u64), std::sync::Arc<File>>,
    // If a pathname changes to an already-held inode during open, keep the new
    // descriptor until every provider DB has dropped. Closing it early would
    // release this process's existing POSIX lock on that inode.
    deferred: Vec<File>,
}
impl ProviderLocks {
    fn acquire(&mut self, database: &Path) -> Result<std::sync::Arc<File>> {
        let path = database.join("LOCK");
        let before = fs::symlink_metadata(&path)?;
        if !before.is_file() || before.file_type().is_symlink() {
            fail!("Invalid database LOCK file");
        }
        let expected = file_identity(&before);
        if self.held.contains_key(&expected) {
            fail!("Provider LOCK inode alias refused before open");
        }
        self.deferred
            .push(fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&path)?);
        let file = self.deferred.last().ok_or_else(|| error!("Missing inspection descriptor"))?;
        let opened = file.metadata()?;
        let actual = file_identity(&opened);
        if self.held.contains_key(&actual) {
            fail!("Provider LOCK changed to an already-held inode");
        }
        if !opened.is_file() || actual != expected {
            fail!("Provider LOCK changed during open");
        }
        shared_lock(file, database)?;
        let file = std::sync::Arc::new(
            self.deferred.pop().ok_or_else(|| error!("Missing inspection descriptor"))?,
        );
        self.held.insert(actual, file.clone());
        Ok(file)
    }
}
impl OpenProvider {
    #[cfg(test)]
    fn open(root: PathBuf, name: &str, range: Option<(u32, u32)>) -> Result<Self> {
        Self::open_with_locks(root, name, range, &mut ProviderLocks::default())
    }
    fn open_with_locks(
        root: PathBuf,
        name: &str,
        range: Option<(u32, u32)>,
        locks: &mut ProviderLocks,
    ) -> Result<Self> {
        let database = resolve_checked(&root, Path::new(name))?;
        let directory = fs::symlink_metadata(&database)?;
        if !directory.is_dir() {
            fail!("Provider is not a directory");
        }
        let directory_identity = file_identity(&directory);
        let lock = locks.acquire(&database)?;
        let lock_identity = file_identity(&lock.metadata()?);
        let initial_inventory = inventory(&database, false)?;
        let mut options = Options::default();
        options.create_if_missing(false);
        options.create_missing_column_families(false);
        options.set_wal_recovery_mode(rocksdb::DBRecoveryMode::AbsoluteConsistency);
        let families: BTreeSet<_> = NativeDb::list_cf(&options, &database)?.into_iter().collect();
        let mut config = CellsDbConfig::default();
        config.cells_cache_size_bytes = 8 * 1024 * 1024;
        config.counters_cache_size_bytes = 8 * 1024 * 1024;
        let mut caches = Vec::new();
        let descriptors: Vec<_> = families
            .iter()
            .map(|name| {
                let cf_options = match name.as_str() {
                    CELLS_CF_NAME => {
                        let (o, c) = DynamicBocDb::build_cells_cf_options(&config);
                        caches.push(c);
                        o
                    }
                    CELLSCOUNTERS_CF_NAME => {
                        let (o, c) = DynamicBocDb::build_counters_cf_options(&config);
                        caches.push(c);
                        o
                    }
                    _ => Options::default(),
                };
                ColumnFamilyDescriptor::new(name, cf_options)
            })
            .collect();
        let db = NativeDb::open_cf_descriptors_read_only(&options, &database, descriptors, false)?;
        let provider = Self {
            db,
            _caches: caches,
            _lock: lock,
            root,
            database,
            families,
            range,
            directory_identity,
            lock_identity,
            initial_inventory,
        };
        provider.verify_identity()?;
        if inventory(&provider.database, false)? != provider.initial_inventory {
            fail!("Provider changed during native read-only open");
        }
        Ok(provider)
    }
    fn verify_identity(&self) -> Result<()> {
        let current = resolve_checked(&self.root, &self.database)?;
        let directory = fs::symlink_metadata(&current)?;
        let lock = fs::symlink_metadata(self.database.join("LOCK"))?;
        if current != self.database
            || !directory.is_dir()
            || !lock.is_file()
            || lock.file_type().is_symlink()
            || file_identity(&directory) != self.directory_identity
            || file_identity(&lock) != self.lock_identity
            || file_identity(&self._lock.metadata()?) != self.lock_identity
        {
            fail!("Database or LOCK path identity changed during inspection");
        }
        Ok(())
    }
    fn statuses(&self) -> Result<usize> {
        let mut count = 0;
        for name in &self.families {
            let parsed = name
                .strip_prefix("status_key_db_")
                .map(|s| (true, s))
                .or_else(|| name.strip_prefix("status_db_").map(|s| (false, s)));
            let Some((key, id)) = parsed else { continue };
            let id: u32 = id.parse().map_err(|_| error!("Invalid archive CF identity {name}"))?;
            if let Some((start, end)) = self.range {
                if key || id < start || id > end {
                    fail!("Archive CF outside provider range: {name}");
                }
            }
            self.require_families(id, key)?;
            let cf = self.db.cf_handle(name).ok_or_else(|| error!("Missing CF {name}"))?;
            for row in self.db.iterator_cf(&cf, IteratorMode::Start) {
                let (key, _) = row?;
                if !super::recovery_guard::known_status_key(key.as_ref())
                {
                    fail!(
                        "Pending or unsupported archive status in {} / {}",
                        self.database.display(),
                        name
                    );
                }
            }
            count += 1;
        }
        // Missing status must not hide another orphan archive family.
        for name in &self.families {
            for kind in ["entry_meta", "offsets", "block_index"] {
                for (prefix, key) in
                    [(format!("{kind}_key_db_"), true), (format!("{kind}_db_"), false)]
                {
                    if let Some(id) = name.strip_prefix(&prefix) {
                        self.require_families(id.parse()?, key)?;
                    }
                }
            }
        }
        Ok(count)
    }
    fn require_families(&self, id: u32, key: bool) -> Result<()> {
        for kind in ["entry_meta", "offsets", "block_index", "status"] {
            let name = format!("{kind}_{}db_{id}", if key { "key_" } else { "" });
            if !self.families.contains(&name) {
                fail!("Missing archive CF {} in {}", name, self.database.display());
            }
        }
        Ok(())
    }
}

fn entry_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
fn epochs(config: &ArchivalModeConfig, working: &Path) -> Result<Vec<(PathBuf, (u32, u32))>> {
    if config.epoch_size == 0 || config.epoch_size % ARCHIVE_SLICE_SIZE != 0 {
        fail!("Invalid epoch_size");
    }
    let parent = resolve_checked(working, &config.new_epochs_path)?;
    let mut paths = BTreeSet::new();
    for entry in &config.existing_epochs {
        paths.insert(resolve_checked(working, &entry.path)?);
    }
    for entry in fs::read_dir(&parent)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            fail!("Symlink in epoch discovery: {}", entry.path().display());
        }
        let candidate = entry.file_name().to_string_lossy().starts_with("epoch_")
            || entry_exists(&entry.path().join("epoch_meta.json"))?
            || entry_exists(&entry.path().join("archive_db"))?;
        if candidate {
            if !kind.is_dir() {
                fail!("Invalid epoch candidate: {}", entry.path().display());
            }
            paths.insert(fs::canonicalize(entry.path())?);
        }
    }
    let mut ranges = BTreeMap::new();
    for path in paths {
        let meta: EpochMeta = serde_json::from_reader(
            fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path.join("epoch_meta.json"))?,
        )?;
        let end = meta
            .mc_seq_no_start
            .checked_add(config.epoch_size - 1)
            .ok_or_else(|| error!("Epoch range overflow"))?;
        if meta.mc_seq_no_start % config.epoch_size != 0 || meta.mc_seq_no_end != end {
            fail!("Invalid epoch range: {}", path.display());
        }
        if ranges.insert(meta.mc_seq_no_start, (path, (meta.mc_seq_no_start, end))).is_some() {
            fail!("Conflicting duplicate epoch range");
        }
    }
    Ok(ranges.into_values().collect())
}

type Inventory = BTreeMap<PathBuf, (u64, u64, u64, i64, i64)>;
fn inventory(root: &Path, reject_staging: bool) -> Result<Inventory> {
    let mut result = Inventory::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            fail!("Symlink in inspected provider: {}", path.display());
        }
        if reject_staging {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if name.ends_with(".pack.new") || name.starts_with(".repack-") {
                fail!("Unresolved archive staging: {}", path.display());
            }
        }
        result.insert(
            path.clone(),
            (
                metadata.dev(),
                metadata.ino(),
                metadata.len(),
                metadata.mtime(),
                metadata.mtime_nsec(),
            ),
        );
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)? {
                pending.push(entry?.path());
            }
        } else if !metadata.is_file() {
            fail!("Unsupported provider entry: {}", path.display());
        }
    }
    Ok(result)
}

fn package_inventory(root: &Path) -> Result<Option<Inventory>> {
    let archive = root.join("archive");
    if !entry_exists(&archive)? {
        return Ok(None);
    }
    let archive = resolve_checked(root, &archive)?;
    if !fs::symlink_metadata(&archive)?.is_dir() {
        fail!("Archive path is not a directory");
    }
    let packages = archive.join("packages");
    if !entry_exists(&packages)? {
        return Ok(None);
    }
    let packages = resolve_checked(root, &packages)?;
    if !fs::symlink_metadata(&packages)?.is_dir() {
        fail!("Package path is not a directory");
    }
    Ok(Some(inventory(&packages, true)?))
}
pub fn inspect(config: &CheckConfig) -> Result<CheckReport> {
    inspect_with_completion(config, || {})
}
fn inspect_with_completion(config: &CheckConfig, complete: impl FnOnce()) -> Result<CheckReport> {
    // POSIX locks belong to the process: a second LOCK close could release an
    // earlier lock. Serialize all provider lifetimes, including error cleanup.
    let _serial =
        INSPECTION_SERIAL.lock().map_err(|_| error!("Inspection coordinator poisoned"))?;
    let working = resolve_checked(&std::env::current_dir()?, &config.working_directory)?;
    if !working.is_dir() {
        fail!("Node working directory is not a directory");
    }
    let main_root = resolve_checked(&working, &config.node_root)?;
    // Declared before providers so every DB drops before any registry LOCK fd.
    let mut locks = ProviderLocks::default();
    let mut providers = vec![OpenProvider::open_with_locks(main_root, "db", None, &mut locks)?];
    let epoch_inventory = match &config.archival_mode {
        Some(c) => epochs(c, &working)?,
        None => vec![],
    };
    let mut physical = BTreeSet::new();
    physical.insert(fs::canonicalize(&providers[0].database)?);
    for (path, range) in &epoch_inventory {
        let database = fs::canonicalize(path.join("archive_db"))?;
        if !physical.insert(database) {
            fail!("Database path is used by multiple providers");
        }
        providers.push(OpenProvider::open_with_locks(
            path.clone(),
            "archive_db",
            Some(*range),
            &mut locks,
        )?);
    }
    let package_before: Vec<_> =
        providers.iter().map(|p| package_inventory(&p.root)).collect::<Result<_>>()?;
    let mut live = 0;
    for (name, key) in [("files", false), ("key_files", true)] {
        let cf = providers[0]
            .db
            .cf_handle(name)
            .ok_or_else(|| error!("Missing main archive index {name}"))?;
        for row in providers[0].db.iterator_cf(&cf, IteratorMode::Start) {
            let (raw, value) = row?;
            let id = u32::from_le_bytes(
                raw.as_ref().try_into().map_err(|_| error!("Invalid archive index key"))?,
            );
            let entry: PackageIndexEntry = serde_cbor::from_slice(&value)?;
            if entry.deleted() {
                continue;
            }
            let provider_index = if key || config.archival_mode.is_none() {
                0
            } else {
                providers
                    .iter()
                    .position(|p| p.range.is_some_and(|(start, end)| id >= start && id <= end))
                    .ok_or_else(|| error!("Live archive {id} has no epoch provider"))?
            };
            let provider = &providers[provider_index];
            provider.require_families(id, key)?;
            if package_before[provider_index].is_none() {
                fail!("Live archive {id} has no package root");
            }
            live += 1;
        }
    }
    let mut reports = Vec::new();
    for (i, p) in providers.iter().enumerate() {
        let count = p.statuses()?;
        p.verify_identity()?;
        if inventory(&p.database, false)? != p.initial_inventory {
            fail!("Provider changed during offline check");
        }
        if package_inventory(&p.root)? != package_before[i] {
            fail!("Package inventory changed during offline check");
        }
        reports.push(ProviderReport {
            root: p.root.clone(),
            database: p.database.clone(),
            families: p.families.len(),
            archive_status_families: count,
            epoch_range: p.range,
        });
    }
    if let Some(c) = &config.archival_mode {
        if epochs(c, &working)? != epoch_inventory {
            fail!("Epoch inventory changed during offline check");
        }
    }
    complete();
    for provider in &providers {
        provider.verify_identity()?;
    }
    Ok(CheckReport{providers:reports,live_archives:live,scope:"Offline advisory-lock precheck only; no recovery, integrity or old-binary enforcement claim"})
}

#[cfg(test)]
#[path = "../tests/test_archive_recovery_check.rs"]
mod tests;
