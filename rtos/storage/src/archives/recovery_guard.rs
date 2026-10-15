// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Preserve unresolved archive inputs before legacy startup cleanup.
use rocksdb::{DBWithThreadMode, IteratorMode, MultiThreaded};
use rtos_block::{error, fail, Result};
use std::{fs, path::Path};

#[derive(Debug, thiserror::Error)]
#[error("Archive recovery required: {0}")]
pub struct ArchiveRecoveryRequired(#[source] anyhow::Error);

pub(crate) fn known_status_key(key: &[u8]) -> bool {
    [b"ShardSplitDepth".as_slice(), b"SlicedMode", b"SliceSize", b"NonSlicedSize", b"TotalSlices"]
        .contains(&key)
}

type NativeDb = DBWithThreadMode<MultiThreaded>;

fn statuses(db: &NativeDb, names: impl IntoIterator<Item = String>) -> Result<()> {
    for name in names {
        let Some(id) =
            name.strip_prefix("status_db_").or_else(|| name.strip_prefix("status_key_db_"))
        else {
            continue;
        };
        let _: u32 = id.parse().map_err(|_| error!("Invalid archive status identity {name}"))?;
        let cf =
            db.cf_handle(&name).ok_or_else(|| error!("Missing archive status family {name}"))?;
        for row in db.iterator_cf(&cf, IteratorMode::Start) {
            let (key, _) = row?;
            if !known_status_key(&key) {
                fail!("Pending or unsupported archive status in {name}");
            }
        }
    }
    Ok(())
}

fn checked_exists(path: &Path) -> Result<bool> {
    let mut prefix = std::path::PathBuf::new();
    for component in path.components() {
        prefix.push(component.as_os_str());
        match fs::symlink_metadata(&prefix) {
            Ok(meta) if meta.file_type().is_symlink() => {
                fail!("Symlink in archive path: {}", prefix.display())
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(true)
}

fn packages(root: &Path) -> Result<()> {
    let archive = root.join("archive");
    if !checked_exists(&archive)? {
        return Ok(());
    }
    if !fs::symlink_metadata(&archive)?.is_dir() {
        fail!("Archive path is not a directory");
    }
    let packages = archive.join("packages");
    if !checked_exists(&packages)? {
        return Ok(());
    }
    if !fs::symlink_metadata(&packages)?.is_dir() {
        fail!("Package path is not a directory");
    }
    // Keep directory iterators, not a collection of every package pathname.
    let mut pending = vec![fs::read_dir(packages)?];
    while let Some(entries) = pending.last_mut() {
        let Some(entry) = entries.next() else {
            pending.pop();
            continue;
        };
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".pack.new") || name.starts_with(".repack-") {
            fail!("Unresolved archive staging: {}", entry.path().display());
        }
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            fail!("Symlink in archive packages: {}", entry.path().display());
        }
        if kind.is_dir() {
            pending.push(fs::read_dir(entry.path())?);
        } else if !kind.is_file() {
            fail!("Unsupported archive entry: {}", entry.path().display());
        }
    }
    Ok(())
}

pub(crate) fn ensure_provider_clear(db: &NativeDb, root: &Path, names: &[String]) -> Result<()> {
    (|| {
        statuses(db, names.iter().cloned())?;
        packages(root)
    })()
    .map_err(|e| ArchiveRecoveryRequired(e).into())
}

pub(crate) fn ensure_open_provider_clear(db: &NativeDb, root: &Path) -> Result<()> {
    (|| {
        let names = NativeDb::list_cf(&rocksdb::Options::default(), db.path())?;
        statuses(db, names)?;
        packages(root)
    })()
    .map_err(|e| ArchiveRecoveryRequired(e).into())
}

pub(crate) fn ensure_slice_clear(db: &NativeDb, root: &Path, id: u32, key: bool) -> Result<()> {
    let name = format!("status_{}db_{id}", if key { "key_" } else { "" });
    (|| {
        if db.cf_handle(&name).is_some() {
            statuses(db, [name])?;
        }
        packages(root)
    })()
    .map_err(|e| ArchiveRecoveryRequired(e).into())
}

#[cfg(test)]
#[path = "../tests/test_archive_recovery_guard.rs"]
mod tests;
