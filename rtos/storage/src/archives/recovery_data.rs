// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Canonical package and archive-CF inventory. Caller retains all providers and
//! closed admission throughout. This digest is not permission to clear controls.
use super::{package_id::PackageId, recovery_providers::RecoveryProviders, recovery_root::Inventory};
use rtos_block::{error, fail, Result, Sha256, ShardIdent};
use std::{collections::BinaryHeap, ffi::OsString, fs, io::Read,
    os::{fd::IntoRawFd, unix::{fs::{MetadataExt, OpenOptionsExt}}}, path::{Path, PathBuf}};

struct Digest { hash: Sha256, count: u64 }
impl Digest {
    fn record(&mut self, tag: u8, provider: [u8;32], parts: &[&[u8]]) -> Result<()> {
        self.count = self.count.checked_add(1).ok_or_else(|| error!("Archive data inventory overflow"))?;
        self.hash.update([tag]); self.hash.update(provider);
        for part in parts {
            self.hash.update(u64::try_from(part.len())?.to_le_bytes()); self.hash.update(part);
        }
        Ok(())
    }
}

/// Bounded batches of directory names, independent of the number of files.
/// Rescans once per 512 entries; callers must not mutate the tree during a scan.
fn sorted_entries(path: &Path, mut visit: impl FnMut(PathBuf) -> Result<()>) -> Result<()> {
    let mut last: Option<OsString> = None;
    loop {
        let mut names = BinaryHeap::new();
        for entry in fs::read_dir(path)? {
            let name = entry?.file_name();
            if last.as_ref().is_some_and(|last| &name <= last) { continue; }
            names.push(name);
            if names.len() > 512 { names.pop(); }
        }
        if names.is_empty() { break; }
        for name in names.into_sorted_vec() {
            visit(path.join(&name))?;
            last = Some(name);
        }
    }
    Ok(())
}
fn directory(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => Ok(true),
        Ok(_) => fail!("Invalid archive inventory directory {}", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
fn identity(meta: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (meta.dev(), meta.ino(), meta.len(), meta.mtime(), meta.mtime_nsec(), meta.ctime(), meta.ctime_nsec())
}
fn file_digest(path: &Path) -> Result<(u64, [u8;32])> {
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() || before.file_type().is_symlink() { fail!("Invalid canonical package file"); }
    let mut file = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path)?;
    let outcome = (|| {
        if identity(&file.metadata()?) != identity(&before) { fail!("Package changed during inventory open"); }
        let mut hash = Sha256::new(); let mut bytes = 0u64; let mut buffer = [0u8; 65536];
        loop {
            let n = file.read(&mut buffer)?; if n == 0 { break; }
            bytes = bytes.checked_add(n as u64).ok_or_else(|| error!("Package size overflow"))?;
            hash.update(&buffer[..n]);
        }
        if bytes != before.len() || identity(&file.metadata()?) != identity(&before)
            || identity(&fs::symlink_metadata(path)?) != identity(&before) {
            fail!("Package changed during inventory read");
        }
        Ok((bytes, hash.finalize()))
    })();
    let fd = file.into_raw_fd();
    // SAFETY: this unique descriptor is consumed exactly once, with no EINTR
    // retry. Any close error refuses publication of the inventory result.
    let closed = unsafe { libc::close(fd) };
    if closed != 0 { return Err(std::io::Error::last_os_error().into()); }
    outcome
}
fn package_identity(root: &Path, path: &Path) -> Result<(bool, u32)> {
    let name = path.file_name().and_then(|name| name.to_str()).ok_or_else(|| error!("Invalid package name"))?;
    let name = name.strip_suffix(".pack").ok_or_else(|| error!("Unknown archive package entry"))?;
    let (key, tail) = if let Some(tail) = name.strip_prefix("key.archive.") { (true, tail) }
        else { (false, name.strip_prefix("archive.").ok_or_else(|| error!("Unknown archive package entry"))?) };
    let (id, shard) = match tail.split_once('.') {
        Some((id, shard)) if !key => (id.parse::<u32>()?, shard.parse::<ShardIdent>()?),
        Some(_) => fail!("Key package cannot have shard suffix"),
        None => (tail.parse::<u32>()?, ShardIdent::masterchain()),
    };
    let package = if key { PackageId::for_key_block(id) } else { PackageId::for_block(id) };
    if package.full_path(root, &shard)? != path { fail!("Noncanonical package path"); }
    Ok((key, id))
}
fn routed(roles: u8, range: Option<(u32,u32)>, key: bool, id: u32) -> Result<()> {
    if (key && roles & 2 == 0) || (!key && roles & 4 == 0)
        || range.is_some_and(|(start,end)| key || id < start || id > end) {
        fail!("Archive data outside provider routing");
    }
    Ok(())
}

pub(crate) fn inventory(providers: &RecoveryProviders) -> Result<Inventory> {
    let mut digest = Digest { hash: Sha256::new(), count: 0 };
    for participant in &providers.participants {
        let descriptor = &participant.descriptor;
        let provider = descriptor.digest()?;
        let db = participant.database.db();
        let mut names = rocksdb::DB::list_cf(&rocksdb::Options::default(), db.path())?;
        names.sort();
        for name in &names {
            let mut archive = None;
            for kind in ["block_index", "entry_meta", "offsets", "status"] {
                for key in [false, true] {
                    let prefix = format!("{kind}_{}db_", if key { "key_" } else { "" });
                    if let Some(number) = name.strip_prefix(&prefix) {
                        let id = number.parse::<u32>()?;
                        if format!("{prefix}{id}") != *name { fail!("Noncanonical archive CF name"); }
                        archive = Some((kind, key, id));
                    }
                }
            }
            let Some((kind, key, id)) = archive else {
                if ["block_index_", "entry_meta_", "offsets_", "status_"].iter().any(|prefix| name.starts_with(prefix)) {
                    fail!("Unrecognized archive metadata family");
                }
                continue;
            };
            routed(descriptor.roles, descriptor.range, key, id)?;
            for required in ["block_index", "entry_meta", "offsets", "status"] {
                let required = format!("{required}_{}db_{id}", if key { "key_" } else { "" });
                if names.binary_search(&required).is_err() { fail!("Incomplete archive metadata family set"); }
            }
            digest.record(1, provider, &[name.as_bytes()])?; // Empty CF presence is significant.
            let cf = db.cf_handle(name).ok_or_else(|| error!("Missing archive metadata CF"))?;
            let mut rows = db.raw_iterator_cf(&cf); rows.seek_to_first();
            while rows.valid() {
                let key = rows.key().ok_or_else(|| error!("Missing archive row key"))?;
                let value = rows.value().ok_or_else(|| error!("Missing archive row value"))?;
                if kind == "status" && !super::recovery_guard::known_status_key(key) {
                    fail!("Unresolved archive metadata control record");
                }
                digest.record(2, provider, &[name.as_bytes(), key, value])?;
                rows.next();
            }
            rows.status()?;
        }
        let root = db.path().parent().ok_or_else(|| error!("Missing archive provider root"))?;
        let archive = root.join("archive");
        if !directory(&archive)? { continue; }
        let packages = archive.join("packages");
        if !directory(&packages)? { continue; }
        sorted_entries(&packages, |bucket| {
            if !directory(&bucket)? { fail!("Package bucket disappeared"); }
            let name = bucket.file_name().and_then(|n| n.to_str()).ok_or_else(|| error!("Invalid package bucket"))?;
            let (key, index, width) = if let Some(id) = name.strip_prefix("arch") {
                (false, id.parse::<u32>()?, super::ARCHIVE_SIZE)
            } else if let Some(id) = name.strip_prefix("key") {
                (true, id.parse::<u32>()?, super::KEY_ARCHIVE_SIZE)
            } else { fail!("Unknown package bucket"); };
            let canonical = if key { format!("key{index:03}") } else { format!("arch{index:04}") };
            if canonical != name || index > u32::MAX / width { fail!("Noncanonical package bucket"); }
            if (key && descriptor.roles & 2 == 0) || (!key && descriptor.roles & 4 == 0) {
                fail!("Package bucket outside provider routing");
            }
            let low = u64::from(index) * u64::from(width);
            let high = (low + u64::from(width) - 1).min(u64::from(u32::MAX));
            if descriptor.range.is_some_and(|(start,end)| key || high < u64::from(start) || low > u64::from(end)) {
                fail!("Package bucket outside epoch range");
            }
            sorted_entries(&bucket, |path| {
                let (key, id) = package_identity(root, &path)?;
                routed(descriptor.roles, descriptor.range, key, id)?;
                let relative = path.strip_prefix(root)?.as_os_str().as_encoded_bytes();
                let (length, hash) = file_digest(&path)?;
                digest.record(3, provider, &[relative, &length.to_le_bytes(), &hash])
            })
        })?;
    }
    Ok(Inventory { count: digest.count, digest: digest.hash.finalize() })
}
#[cfg(test)]
#[path = "../tests/test_recovery_data.rs"]
mod tests;
