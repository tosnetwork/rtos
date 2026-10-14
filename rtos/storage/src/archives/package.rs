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
use crate::{
    archives::package_entry::{PackageEntry, PKG_ENTRY_HEADER_SIZE},
    TARGET,
};
use rtos_block::{error, fail, Result};
use std::{
    io::SeekFrom,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

#[derive(Debug)]
pub struct Package {
    path: PathBuf,
    read_only: bool,
    size: AtomicU64,
    // A partial tail or uncertain metadata requires fresh-owner recovery.
    write_healthy: AtomicBool,
    write_mutex: tokio::sync::Mutex<Option<tokio::fs::File>>,
}

pub(crate) const PKG_HEADER_SIZE: usize = 4;
const PKG_HEADER_MAGIC: u32 = 0xAE8F_DD01;

async fn read_header<R: tokio::io::AsyncReadExt + Unpin>(reader: &mut R) -> Result<()> {
    let mut buf = [0; PKG_HEADER_SIZE];
    if reader.read_exact(&mut buf).await? != PKG_HEADER_SIZE {
        fail!("Package file read failed")
    }
    if u32::from_le_bytes(buf) != PKG_HEADER_MAGIC {
        fail!("Package file header mismatch")
    }

    Ok(())
}

impl Package {
    pub async fn open(path: PathBuf, read_only: bool, create: bool) -> Result<Self> {
        let (file, size) = if read_only {
            let size = tokio::fs::metadata(&path).await?.len();
            if size < PKG_HEADER_SIZE as u64 {
                fail!("Package file is too short")
            }
            (None, size)
        } else {
            let mut file = Self::open_file_ext(read_only, create, path.as_path()).await?;
            let mut size = file.metadata().await?.len();

            file.seek(SeekFrom::Start(0)).await?;
            if size < PKG_HEADER_SIZE as u64 {
                if !create {
                    fail!("Package file is too short")
                }
                file.write_all(&PKG_HEADER_MAGIC.to_le_bytes()).await?;
                file.flush().await?;
                size = PKG_HEADER_SIZE as u64;
            } else {
                read_header(&mut file).await?;
                file.seek(SeekFrom::End(0)).await?;
            }
            (Some(file), size)
        };

        Ok(Self {
            path,
            read_only,
            size: AtomicU64::new(size),
            write_healthy: AtomicBool::new(true),
            write_mutex: tokio::sync::Mutex::new(file),
        })
    }

    /// Validate a leased existing package without any repair or creation. Use
    /// the same descriptor for validation and later append access.
    pub(crate) async fn open_existing_exact(path: PathBuf, read_only: bool, logical_size: u64) -> Result<Self> {
        let mut file = tokio::fs::OpenOptions::new().read(true).write(!read_only).open(&path).await
            .map_err(|error| error!("Protected package open failed for {}: {error}", path.display()))?;
        let expected = logical_size.checked_add(PKG_HEADER_SIZE as u64)
            .ok_or_else(|| error!("Protected package size overflow"))?;
        let size = file.metadata().await?.len();
        if size != expected || size < PKG_HEADER_SIZE as u64 {
            fail!("Protected package physical length differs from durable metadata");
        }
        read_header(&mut file).await?;
        file.seek(SeekFrom::End(0)).await?;
        Ok(Self {
            path, read_only, size: AtomicU64::new(size),
            write_healthy: AtomicBool::new(true),
            write_mutex: tokio::sync::Mutex::new(if read_only { None } else { Some(file) }),
        })
    }

    pub fn size(&self) -> u64 {
        self.size.load(Ordering::SeqCst) - PKG_HEADER_SIZE as u64
    }

    pub async fn remove(&self) -> Result<()> {
        debug_assert!(!self.read_only);
        let mut file = self.write_mutex.lock().await;
        if file.take().is_none() {
            Ok(())
        } else {
            Self::remove_by_path(self.path()).await
        }
    }

    pub async fn remove_by_path(path: &Path) -> Result<()> {
        if path.try_exists()? {
            tokio::fs::remove_file(path)
                .await
                .map_err(|err| error!("destroy package error {}", err))?;
        }
        Ok(())
    }

    /// File and directory entries are separate durability obligations.
    pub async fn sync_durable(
        &self,
        observer: Option<&crate::durability::SyncObserver>,
    ) -> Result<()> {
        let _guard = self.write_mutex.lock().await;
        sync_file_and_parents_observed(self.path(), observer).await
    }

    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    /// Complete pending package IO and observe the actual Linux fd close result.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) async fn close_for_sst_test(&self) -> Result<()> {
        use std::os::fd::{AsRawFd, IntoRawFd};
        let mut guard = self.write_mutex.lock().await;
        let Some(mut file) = guard.take() else {
            fail!("SST package fd already closed or read-only: {}", self.path.display());
        };
        file.flush().await?;
        let file = file.into_std().await;
        eprintln!("SST-PACK-CLOSE fd={} path={}", file.as_raw_fd(), self.path.display());
        tokio::task::spawn_blocking(move || {
            unsafe extern "C" {
                fn close(fd: std::ffi::c_int) -> std::ffi::c_int;
            }
            let fd = file.into_raw_fd();
            // SAFETY: exclusive File ownership was transferred above; close the
            // fd once, never retry EINTR (Linux may already have released it).
            if unsafe { close(fd) } == -1 {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(())
        })
        .await
        .map_err(|e| error!("SST package close owner failed: {e}"))?
    }

    pub fn get_path(&self) -> String {
        self.path.display().to_string()
    }

    pub async fn truncate(&self, size: u64) -> Result<()> {
        let new_size = (PKG_HEADER_SIZE as u64)
            .checked_add(size)
            .ok_or_else(|| error!("Package truncate size overflow"))?;
        let mut guard = self.write_mutex.lock().await;
        if !self.write_healthy.load(Ordering::SeqCst) {
            fail!("Package write state is uncertain; reopen before mutation");
        }
        let Some(file) = &mut *guard else {
            fail!(
                "Cannot truncate package file {}, because it was not opened",
                self.path().display()
            );
        };
        self.write_healthy.store(false, Ordering::SeqCst);
        let old_raw = self.size.load(Ordering::SeqCst);
        let old_file_len = file.metadata().await?.len();
        log::warn!(target: TARGET, "Truncating package {}: raw_size {old_raw} -> {new_size}, file_len {old_file_len} -> {new_size}", self.path.display());
        file.set_len(new_size).await?;
        // ftruncate does not move the cursor; publish only after both complete.
        file.seek(SeekFrom::Start(new_size)).await?;
        self.size.store(new_size, Ordering::SeqCst);
        self.write_healthy.store(true, Ordering::SeqCst);
        Ok(())
    }

    pub async fn read_entry(&self, offset: u64) -> Result<PackageEntry> {
        let mut file = self.open_file().await?;
        let required_size = offset + PKG_ENTRY_HEADER_SIZE as u64;
        // Fast path: use cached atomic size for bounds check.
        let mut actual_size = self.size();
        if actual_size <= required_size {
            // Slow path: cached size may be stale when another thread just finished
            // appending; confirm with actual file metadata before returning EOF.
            actual_size = file.metadata().await?.len().saturating_sub(PKG_HEADER_SIZE as u64);
            if actual_size <= required_size {
                fail!(
                    "Unexpected end of file when reading package {} entry with offset {offset}",
                    self.path.display()
                );
            } else {
                log::warn!(
                    target: TARGET,
                    "Not actualized package {} size {actual_size} \
                    when reading entry with offset {offset}",
                    self.path.display()
                )
            }
        }
        file.seek(SeekFrom::Start(PKG_HEADER_SIZE as u64 + offset)).await?;
        PackageEntry::read_from(&mut file)
            .await
            .map_err(|e| {
                error!("Package::read_entry {} at offset {offset}: {e}", self.path.display())
            })?
            .ok_or_else(|| {
                error!(
                    "Package::read_entry {} at offset {offset}: Unexpected end of file",
                    self.path.display()
                )
            })
    }

    pub async fn read_entry_bounded(
        &self,
        offset: u64,
        limits: super::bounded_read::ArchiveReadLimits,
    ) -> Result<PackageEntry> {
        let mut file = tokio::fs::OpenOptions::new().read(true).write(!self.read_only)
            .open(&self.path).await
            .map_err(super::bounded_read::ArchiveReadNotStarted::from_open)?;
        read_header(&mut file).await?;
        let start = offset.checked_add(PKG_HEADER_SIZE as u64)
            .ok_or_else(|| error!("Archive entry offset overflow"))?;
        let end = start.checked_add(PKG_ENTRY_HEADER_SIZE as u64)
            .ok_or_else(|| error!("Archive entry header offset overflow"))?;
        if end > file.metadata().await?.len() { fail!("Truncated archive entry header"); }
        file.seek(SeekFrom::Start(start)).await?;
        // Preserve typed limit errors; formatting them into strings loses the
        // upper resolver's ability to forbid fallback after budget exhaustion.
        PackageEntry::read_from_bounded(&mut file, limits).await
    }

    pub async fn append_entry(
        &self,
        entry: &PackageEntry,
        after_append: impl FnOnce(u64, u64) -> Result<()>,
    ) -> Result<()> {
        debug_assert!(entry.filename().len() <= u16::MAX as usize);
        debug_assert!(entry.data().len() <= u32::MAX as usize);
        let mut guard = self.write_mutex.lock().await;
        if !self.write_healthy.load(Ordering::SeqCst) {
            fail!("Package write state is uncertain; reopen before mutation");
        }
        let Some(file) = &mut *guard else {
            fail!(
                "Cannot append entry to package file {}, because it was not opened",
                self.path().display()
            );
        };
        // Neither an error nor an abandoned future may reset this admission.
        self.write_healthy.store(false, Ordering::SeqCst);
        let actual_before = file.metadata().await?.len();
        let raw_size = self.size.load(Ordering::SeqCst);
        let entry_offset = raw_size - PKG_HEADER_SIZE as u64;
        if raw_size != actual_before {
            fail!("Package {} physical/logical length mismatch before append: {actual_before} != {raw_size}", self.path.display());
        }
        let entry_size = entry.write_to(file).await?;
        // Pack data must be durable before the offset gets committed.
        file.sync_data().await?;
        let total_size = raw_size
            .checked_add(entry_size)
            .ok_or_else(|| error!("Package append size overflow"))?;
        let actual_after = file.metadata().await?.len();
        if total_size != actual_after {
            fail!("Package {} physical/logical length mismatch after append: {actual_after} != {total_size}", self.path.display());
        }
        self.size.store(total_size, Ordering::SeqCst);
        let result = after_append(entry_offset, total_size - PKG_HEADER_SIZE as u64);
        if result.is_ok() {
            self.write_healthy.store(true, Ordering::SeqCst);
        }
        result
    }

    pub async fn open_file(&self) -> Result<tokio::fs::File> {
        Self::open_file_ext(self.read_only, false, self.path.as_path()).await
    }

    async fn open_file_ext(
        read_only: bool,
        create: bool,
        path: impl AsRef<Path>,
    ) -> Result<tokio::fs::File> {
        Ok(tokio::fs::OpenOptions::new()
            .read(true)
            .write(!read_only || create)
            .create(create)
            .open(&path)
            .await?)
    }
}

pub struct PackageReader<R: tokio::io::AsyncReadExt + Unpin> {
    reader: tokio::io::BufReader<R>,
}

impl<R: tokio::io::AsyncReadExt + Unpin> PackageReader<R> {
    pub async fn next(&mut self) -> Result<Option<PackageEntry>> {
        PackageEntry::read_from(&mut self.reader).await
    }
}

pub async fn read_package_from_file(
    path: impl AsRef<Path>,
) -> Result<PackageReader<tokio::fs::File>> {
    read_package_from(
        tokio::fs::OpenOptions::new().read(true).write(false).create(false).open(path).await?,
    )
    .await
}

pub async fn read_package_from<R: tokio::io::AsyncReadExt + Unpin>(
    reader: R,
) -> Result<PackageReader<R>> {
    let mut reader = tokio::io::BufReader::with_capacity(1 << 19, reader);
    read_header(&mut reader).await?;
    Ok(PackageReader::<R> { reader })
}

#[cfg(test)]
#[path = "../tests/test_package.rs"]
mod tests;

/// Called by an owned storage operation. Synchronize the directory chain as
/// archive packages may have created more than one new ancestor directory.
pub(crate) async fn sync_file_and_parents(path: &Path) -> Result<()> {
    sync_file_and_parents_observed(path, None).await
}
pub(crate) async fn sync_file_and_parents_observed(
    path: &Path,
    observer: Option<&crate::durability::SyncObserver>,
) -> Result<()> {
    let file = tokio::fs::OpenOptions::new().read(true).write(true).open(path).await?;
    crate::durability::before(observer, crate::durability::SyncPoint::File, path)?;
    file.sync_all().await?;
    let mut parent = path.parent();
    while let Some(directory) = parent {
        if directory.as_os_str().is_empty() {
            break;
        }
        let file = tokio::fs::File::open(directory).await?;
        crate::durability::before(observer, crate::durability::SyncPoint::Directory, directory)?;
        file.sync_all().await?;
        parent = directory.parent();
    }
    Ok(())
}

#[cfg(test)]
mod bounded_tests {
    use super::*;
    use crate::archives::bounded_read::{ArchiveReadLimitExceeded, ArchiveReadLimits};
    #[tokio::test]
    async fn bounded_archive_real_package_limit_offset_and_truncation() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("archive.pack");
        // Real fixed package/entry headers followed by an exact-sized payload.
        let mut data = 0xAE8F_DD01u32.to_le_bytes().to_vec();
        data.extend_from_slice(&0x1E8Bu16.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(b"xabcd");
        std::fs::write(&path, &data)?;
        let package = Package::open(path.clone(), true, false).await?;
        let limits = ArchiveReadLimits { data_bytes: 4, filename_bytes: 1 };
        let entry = package.read_entry_bounded(0, limits).await?;
        assert_eq!(entry.filename(), "x"); assert_eq!(entry.data(), b"abcd");
        let error = package.read_entry_bounded(0, ArchiveReadLimits { data_bytes: 3, ..limits }).await.err().unwrap();
        assert!(error.downcast_ref::<ArchiveReadLimitExceeded>().is_some());
        assert!(package.read_entry_bounded(u64::MAX, limits).await.is_err());
        std::fs::write(&path, &data[..data.len()-1])?;
        assert!(package.read_entry_bounded(0, limits).await.is_err());
        // Malicious advertised size rejected even though the file has no body.
        data.truncate(12); data[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        std::fs::write(&path, data)?;
        let error = package.read_entry_bounded(0, limits).await.err().unwrap();
        assert!(error.downcast_ref::<ArchiveReadLimitExceeded>().is_some());
        Ok(())
    }
}

#[cfg(test)]
mod protected_open_tests {
    use super::*;
    #[tokio::test]
    async fn protected_package_exact_open_checks_readonly_magic_and_allows_valid_append() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("protected.pack");
        let package = Package::open(path.clone(), false, true).await?;
        let entry = PackageEntry::with_data("first".into(), b"first".to_vec());
        package.append_entry(&entry, |_, _| Ok(())).await?;
        let size = package.size();
        drop(package);
        let original = std::fs::read(&path)?;
        let mut damaged = original.clone();
        damaged[0] ^= 0xff;
        std::fs::write(&path, &damaged)?;
        assert!(Package::open_existing_exact(path.clone(), true, size).await.is_err());
        assert_eq!(std::fs::read(&path)?, damaged);
        std::fs::write(&path, &original)?;
        let package = Package::open_existing_exact(path.clone(), false, size).await?;
        package.append_entry(&entry, |_, _| Ok(())).await?;
        let appended = package.size();
        assert!(appended > size);
        drop(package);
        assert!(Package::open_existing_exact(path.clone(), true, appended).await.is_ok());
        Ok(())
    }
}

#[cfg(test)]
mod write_health_tests {
    use super::*;

    #[tokio::test]
    async fn metadata_error_fences_append_and_truncate_until_fresh_owner_recovery() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("write-health.pack");
        let package = Package::open(path.clone(), false, true).await?;
        let seed = PackageEntry::with_data("seed".into(), b"acknowledged bytes".to_vec());
        package.append_entry(&seed, |_, _| Ok(())).await?;
        let committed_end = package.size();
        let original = std::fs::read(&path)?;
        let target = PackageEntry::with_data("target".into(), b"uncommitted metadata".to_vec());
        let error = package
            .append_entry(&target, |_, _| Err(error!("metadata commit refused")))
            .await
            .expect_err("metadata callback failure must propagate");
        assert!(error.to_string().contains("metadata commit refused"));
        let uncertain = std::fs::read(&path)?;
        assert!(uncertain.starts_with(&original));
        assert!(uncertain.len() > original.len());
        let read = package.read_entry(0).await?;
        assert_eq!(read.filename(), seed.filename());
        assert_eq!(read.data(), seed.data());
        let calls = AtomicU64::new(0);
        let error = package
            .append_entry(&target, |_, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await
            .expect_err("unhealthy append must be refused");
        assert!(error.to_string().contains("write state is uncertain"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let error =
            package.truncate(committed_end).await.expect_err("unhealthy truncate must be refused");
        assert!(error.to_string().contains("write state is uncertain"));
        assert_eq!(std::fs::read(&path)?, uncertain, "refusal must not repair or mutate bytes");
        drop(package);
        assert!(Package::open_existing_exact(path.clone(), false, committed_end).await.is_err());
        assert_eq!(
            std::fs::read(&path)?,
            uncertain,
            "protected reopen must preserve uncertain history"
        );
        // This models only the explicitly unprotected durable-end recovery policy.
        let recovered = Package::open(path.clone(), false, false).await?;
        recovered.truncate(committed_end).await?;
        assert_eq!(std::fs::read(&path)?, original);
        recovered.append_entry(&target, |_, _| Ok(())).await?;
        let entry = recovered.read_entry(committed_end).await?;
        assert_eq!(entry.filename(), target.filename());
        assert_eq!(entry.data(), target.data());
        Ok(())
    }

    #[tokio::test]
    async fn prewrite_length_mismatch_is_refused_and_latches_write_health() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("length-mismatch.pack");
        let package = Package::open(path.clone(), false, true).await?;
        let seed = PackageEntry::with_data("seed".into(), b"seed".to_vec());
        package.append_entry(&seed, |_, _| Ok(())).await?;
        use std::io::Write;
        std::fs::OpenOptions::new().append(true).open(&path)?.write_all(b"foreign tail")?;
        let before = std::fs::read(&path)?;
        let error = package
            .append_entry(&seed, |_, _| panic!("mismatch must precede metadata"))
            .await
            .expect_err("length mismatch must fail closed");
        assert!(error.to_string().contains("length mismatch before append"));
        assert_eq!(std::fs::read(&path)?, before);
        assert!(package
            .truncate(0)
            .await
            .unwrap_err()
            .to_string()
            .contains("write state is uncertain"));
        Ok(())
    }
}
