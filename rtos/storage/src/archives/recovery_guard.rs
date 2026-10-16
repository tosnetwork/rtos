// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Preserve unresolved archive inputs before legacy startup cleanup.
use rocksdb::{DBWithThreadMode, IteratorMode, MultiThreaded};
use rtos_block::{error, fail, Result};
use std::{fs, path::Path};

#[derive(Debug, thiserror::Error)]
#[error("Archive recovery required: {0}")]
pub struct ArchiveRecoveryRequired(#[source] pub(crate) anyhow::Error);

pub(crate) fn known_status_key(key: &[u8]) -> bool {
    [b"ShardSplitDepth".as_slice(), b"SlicedMode", b"SliceSize", b"NonSlicedSize", b"TotalSlices"]
        .contains(&key)
}

type NativeDb = DBWithThreadMode<MultiThreaded>;

/// Ordinary startup/inspection must not interpret pending root work as an
/// absent slice. The exclusive recovery bootstrap uses a separate authority.
pub(crate) fn ensure_root_controls_clear(db: &NativeDb) -> Result<()> {
    use super::recovery_root::{RootHeader, PARTICIPANT_KEY, ROOT_KEY};
    if let Some(bytes) = db.get_pinned(ROOT_KEY)? {
        let _header = RootHeader::decode(&bytes)?;
        fail!("Pending archive root recovery");
    }
    if let Some(bytes) = db.get_pinned(PARTICIPANT_KEY)? {
        // A backlink without independently checked root authority never
        // authorizes cleanup, including unknown future participant formats.
        let _backlink = super::recovery_participant::Backlink::decode(&bytes)?;
        fail!("Pending archive recovery participant");
    }
    let root = db.path().parent().ok_or_else(|| error!("Missing archive provider root"))?;
    orphan_controls(root).map_err(|error| ArchiveRecoveryRequired(error).into())
}

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

/// With neither root nor backlink, no operation directory has cleanup authority.
/// Even an empty operation directory is preserved: it may precede Building.
/// An empty shared recovery directory is harmless after root-last cleanup.
fn orphan_controls(root: &Path) -> Result<()> {
    // Ordinary provider aliases remain compatible when no root work exists.
    // Resolve the provider root, then reject aliases in the control area itself.
    let archive = fs::canonicalize(root)?.join("archive");
    if !checked_exists(&archive)? { return Ok(()); }
    if !fs::symlink_metadata(&archive)?.is_dir() { fail!("Archive path is not a directory"); }
    let controls = archive.join("recovery");
    if !checked_exists(&controls)? { return Ok(()); }
    if !fs::symlink_metadata(&controls)?.is_dir() { fail!("Recovery control path is not a directory"); }
    if let Some(entry) = fs::read_dir(&controls)?.next() {
        let entry = entry?;
        fail!("Orphan archive recovery artifact: {}", entry.path().display());
    }
    Ok(())
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
        ensure_root_controls_clear(db)?;
        statuses(db, names.iter().cloned())?;
        packages(root)
    })()
    .map_err(|e| ArchiveRecoveryRequired(e).into())
}

pub(crate) fn ensure_open_provider_clear(db: &NativeDb, root: &Path) -> Result<()> {
    (|| {
        ensure_root_controls_clear(db)?;
        let names = NativeDb::list_cf(&rocksdb::Options::default(), db.path())?;
        statuses(db, names)?;
        packages(root)
    })()
    .map_err(|e| ArchiveRecoveryRequired(e).into())
}

pub(crate) fn ensure_slice_clear(db: &NativeDb, root: &Path, id: u32, key: bool) -> Result<()> {
    let name = format!("status_{}db_{id}", if key { "key_" } else { "" });
    (|| {
        ensure_root_controls_clear(db)?;
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
