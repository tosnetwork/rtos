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
use super::context::{ArchiveOperation, ArchiveView};
use crate::archives::package_entry::PackageEntry;
use rtos_block::{error, fail, Result};
use std::{
    io::SeekFrom,
    path::{Path, PathBuf},
    sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}},
};

#[derive(Debug)]
pub struct Package {
    state: Arc<PackageState>,
}

/// One identity for cached length/health, captured view and actual writer. Native
/// migration can retain this state independently of the caller's Package handle.
#[derive(Debug)]
pub(super) struct PackageState {
    // Writer ownership is released before the captured provider/view.
    write_mutex: Arc<tokio::sync::Mutex<Option<std::fs::File>>>,
    path: PathBuf,
    read_only: bool,
    size: AtomicU64,
    // A partial tail or uncertain metadata requires fresh-owner recovery.
    write_healthy: AtomicBool,
    retired: AtomicBool,
    #[cfg(test)]
    fail_retirement_close: AtomicBool,
    #[cfg(test)]
    retirement_probe: std::sync::Mutex<Option<AppendProbe>>,
    view: ArchiveView,
    #[cfg(test)]
    append_probe: std::sync::Mutex<Option<AppendProbe>>,
}
impl PackageState {
    pub(super) fn view(&self) -> &ArchiveView { &self.view }
}
#[cfg(test)]
#[derive(Debug)]
struct AppendProbe {
    started: std::sync::mpsc::SyncSender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

/// A transferable writer guard always pins the shared state and its provider.
/// Declaration order releases serialization before the final state reference.
struct PackageWriter {
    guard: tokio::sync::OwnedMutexGuard<Option<std::fs::File>>,
    _state: Arc<PackageState>,
}
impl std::ops::Deref for PackageWriter {
    type Target = Option<std::fs::File>;
    fn deref(&self) -> &Self::Target { &self.guard }
}
impl std::ops::DerefMut for PackageWriter {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.guard }
}

pub(crate) const PKG_HEADER_SIZE: usize = 4;
pub(super) const PKG_HEADER_MAGIC: u32 = 0xAE8F_DD01;

struct AppendLayout {
    entry_offset: u64,
    total_size: u64,
    logical_size: u64,
}

impl AppendLayout {
    fn checked(raw_size: u64, entry_size: u64) -> Result<Self> {
        let entry_offset = raw_size.checked_sub(PKG_HEADER_SIZE as u64)
            .ok_or_else(|| error!("Package length is smaller than its header"))?;
        let total_size = raw_size.checked_add(entry_size)
            .ok_or_else(|| error!("Package append size overflow"))?;
        let logical_size = total_size.checked_sub(PKG_HEADER_SIZE as u64)
            .ok_or_else(|| error!("Package logical size underflow"))?;
        Ok(Self { entry_offset, total_size, logical_size })
    }
}

fn block_index_offset(offset: u64) -> Result<u32> {
    u32::try_from(offset).map_err(|_| error!("Package BlockIndex offset exceeds u32"))
}

#[cfg(test)]
#[path = "../tests/test_package_preflight.rs"]
mod preflight_tests;

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

fn read_header_sync(reader: &mut impl std::io::Read) -> Result<()> {
    let mut bytes = [0; PKG_HEADER_SIZE];
    reader.read_exact(&mut bytes)?;
    if u32::from_le_bytes(bytes) != PKG_HEADER_MAGIC { fail!("Package file header mismatch"); }
    Ok(())
}

impl Package {
    fn ensure_active(&self) -> Result<()> {
        if self.state.retired.load(Ordering::Acquire) {
            return Err(super::context::ArchiveContextError::Retired(self.state.view.epoch()).into());
        }
        Ok(())
    }
    fn enter_operation(&self) -> Result<ArchiveOperation> {
        self.ensure_active()?;
        self.state.view.enter()
    }
    fn inherit_operation(&self, parent: &ArchiveOperation) -> Result<ArchiveOperation> {
        self.ensure_active()?;
        self.state.view.inherit(parent)
    }

    async fn lock_writer(&self) -> PackageWriter {
        let state = self.state.clone();
        let guard = state.write_mutex.clone().lock_owned().await;
        PackageWriter { guard, _state: state }
    }

    fn from_opened(view: ArchiveView, parent: &ArchiveOperation, path: PathBuf, read_only: bool, file: Option<std::fs::File>, size: u64) -> Result<Self> {
        let state = Arc::new(PackageState {
            view, path, read_only, size: AtomicU64::new(size), write_healthy: AtomicBool::new(true), retired: AtomicBool::new(false),
            #[cfg(test)]
            fail_retirement_close: AtomicBool::new(false),
            #[cfg(test)]
            retirement_probe: std::sync::Mutex::new(None),
            write_mutex: Arc::new(tokio::sync::Mutex::new(file)),
            #[cfg(test)]
            append_probe: std::sync::Mutex::new(None),
        });
        state.view.register_package(parent, &state)?;
        Ok(Self { state })
    }

    pub async fn open(view: ArchiveView, parent: &ArchiveOperation, path: PathBuf, read_only: bool, create: bool) -> Result<Self> {
        if read_only || !create {
            return Self::open_native_existing(view, parent, path, read_only, None).await;
        }
        let operation = view.inherit(parent)?;
        let (phase, mut job) = operation.mutation_phase();
        let native_path = path.clone();
        let handoff = tokio::task::spawn_blocking(move || {
            // O_CREAT may create the file, so cancellation must be ordered before
            // the open itself, not merely before a later header write.
            job.start()?;
            let mut file = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&native_path)?;
            let mut size = file.metadata()?.len();
            std::io::Seek::seek(&mut file, SeekFrom::Start(0))?;
            if size < PKG_HEADER_SIZE as u64 {
                std::io::Write::write_all(&mut file, &PKG_HEADER_MAGIC.to_le_bytes())?;
                std::io::Write::flush(&mut file)?;
                size = PKG_HEADER_SIZE as u64;
            } else {
                read_header_sync(&mut file)?;
                std::io::Seek::seek(&mut file, SeekFrom::End(0))?;
            }
            Ok::<_, anyhow::Error>(job.handoff((Some(file), size)))
        }).await.map_err(|e| error!("Native package create task failed: {e}"))??;
        phase.check_completion()?;
        let mut package = None;
        handoff.consume(|opened| {
            package = Some(Self::from_opened(view, &operation, path, false, opened.0.take(), opened.1)?);
            Ok(())
        })?;
        phase.complete();
        Ok(package.expect("registered native package"))
    }

    /// Validate a leased existing package without any repair or creation. Use
    /// the same native descriptor for validation and subsequent append access.
    pub(crate) async fn open_existing_exact(view: ArchiveView, parent: &ArchiveOperation, path: PathBuf, read_only: bool, logical_size: u64) -> Result<Self> {
        let expected = logical_size.checked_add(PKG_HEADER_SIZE as u64)
            .ok_or_else(|| error!("Protected package size overflow"))?;
        Self::open_native_existing(view, parent, path, read_only, Some(expected)).await
    }

    async fn open_native_existing(
        view: ArchiveView, parent: &ArchiveOperation, path: PathBuf,
        read_only: bool, expected: Option<u64>,
    ) -> Result<Self> {
        let operation = view.inherit(parent)?;
        let native_path = path.clone();
        let acquisition = tokio::task::spawn_blocking(move || {
            let custody = operation.start_read()?;
            // Preserve ordinary read-only open semantics: the legacy path only
            // inspects length; protected exact opens also validate the header.
            if read_only && expected.is_none() {
                let size = std::fs::metadata(&native_path)?.len();
                if size < PKG_HEADER_SIZE as u64 { fail!("Package file is too short"); }
                return Ok::<_, anyhow::Error>(custody.acquisition((None, size)));
            }
            let mut file = std::fs::OpenOptions::new().read(true).write(!read_only).open(&native_path)
                .map_err(|error| error!("Existing package open failed for {}: {error}", native_path.display()))?;
            let size = file.metadata()?.len();
            if expected.is_some_and(|expected| expected != size) || size < PKG_HEADER_SIZE as u64 {
                fail!("Package physical length differs from durable metadata or header minimum");
            }
            read_header_sync(&mut file)?;
            std::io::Seek::seek(&mut file, SeekFrom::End(0))?;
            let file = if read_only { drop(file); None } else { Some(file) };
            Ok(custody.acquisition((file, size)))
        }).await.map_err(|e| error!("Native package existing-open task failed: {e}"))??;
        // Recheck the epoch and failure state after native acquisition, before
        // publishing a writer. The acquisition still owns its resource here.
        let _registration = view.inherit(parent)?;
        let mut package = None;
        acquisition.consume(|opened| {
            package = Some(Self::from_opened(view, &_registration, path, read_only, opened.0.take(), opened.1)?);
            Ok(())
        })?;
        Ok(package.expect("registered existing native package"))
    }

    pub fn size(&self) -> u64 {
        self.state.size.load(Ordering::SeqCst) - PKG_HEADER_SIZE as u64
    }

    pub async fn remove(&self) -> Result<()> {
        if self.state.read_only { fail!("Cannot remove a read-only package"); }
        let operation = self.enter_operation()?;
        let mut guard = self.lock_writer().await;
        if guard.is_none() { return Ok(()); }
        let (phase, mut job) = operation.mutation_phase();
        let handoff = tokio::task::spawn_blocking(move || {
            // Keep the live writer intact when cancellation wins before start.
            job.start()?;
            drop(guard.take());
            remove_file_native(&guard._state.path)?;
            Ok::<_, anyhow::Error>(job.handoff(guard))
        }).await.map_err(|e| error!("Native package remove task failed: {e}"))??;
        phase.check_completion()?;
        handoff.consume(|_| Ok(()))?;
        phase.complete();
        Ok(())
    }

    pub(crate) async fn remove_by_path(
        view: &ArchiveView, parent: &ArchiveOperation, path: &Path,
    ) -> Result<()> {
        let operation = view.inherit(parent)?;
        let (phase, mut job) = operation.mutation_phase();
        let path = path.to_path_buf();
        let handoff = tokio::task::spawn_blocking(move || {
            job.start()?;
            remove_file_native(&path)?;
            Ok::<_, anyhow::Error>(job.handoff(()))
        }).await.map_err(|e| error!("Native package path remove task failed: {e}"))??;
        phase.check_completion()?;
        handoff.consume(|_| Ok(()))?;
        phase.complete();
        Ok(())
    }

    /// File and directory entries are separate durability obligations.
    pub async fn sync_durable(
        &self,
        observer: crate::durability::SyncObservation,
    ) -> Result<()> {
        let operation = self.enter_operation()?;
        let guard = self.lock_writer().await;
        let (phase, mut job) = operation.mutation_phase();
        let handoff = tokio::task::spawn_blocking(move || {
            job.start()?;
            sync_file_and_parents_native(&guard._state.path, observer.as_deref())?;
            Ok::<_, anyhow::Error>(job.handoff(guard))
        }).await.map_err(|e| error!("Native package sync task failed: {e}"))??;
        phase.check_completion()?;
        handoff.consume(|_| Ok(()))?;
        phase.complete();
        Ok(())
    }

    pub fn path(&self) -> &Path {
        self.state.path.as_path()
    }

    /// Borrow the actual writer identity; does not clone or transfer its fd.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) async fn writer_fd_for_io_test(&self) -> Result<std::ffi::c_int> {
        use std::os::fd::AsRawFd;
        let guard = self.lock_writer().await;
        let file = guard.as_ref().ok_or_else(|| error!("Package writer is closed"))?;
        Ok(file.as_raw_fd())
    }

    /// Complete pending package IO and observe the actual Linux fd close result.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) async fn close_for_sst_test(&self) -> Result<()> {
        use std::os::fd::{AsRawFd, IntoRawFd};
        let mut guard = self.lock_writer().await;
        let Some(mut file) = guard.take() else {
            fail!("SST package fd already closed or read-only: {}", self.state.path.display());
        };
        std::io::Write::flush(&mut file)?;
        eprintln!("SST-PACK-CLOSE fd={} path={}", file.as_raw_fd(), self.state.path.display());
        tokio::task::spawn_blocking(move || {
            let _guard = guard;
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
        self.state.path.display().to_string()
    }

    pub async fn truncate(&self, size: u64) -> Result<()> {
        let new_size = (PKG_HEADER_SIZE as u64).checked_add(size)
            .ok_or_else(|| error!("Package truncate size overflow"))?;
        let operation = self.enter_operation()?;
        let guard = self.lock_writer().await;
        if !self.state.write_healthy.load(Ordering::SeqCst) {
            fail!("Package write state is uncertain; reopen before mutation");
        }
        let (phase, mut job) = operation.mutation_phase();
        let state = self.state.clone();
        let handoff = tokio::task::spawn_blocking(move || {
            let mut guard = guard;
            let file = guard.as_mut().ok_or_else(|| error!("Package writer is closed"))?;
            let _old_file_len = file.metadata()?.len();
            job.start()?;
            state.write_healthy.store(false, Ordering::SeqCst);
            file.set_len(new_size)?;
            std::io::Seek::seek(file, SeekFrom::Start(new_size))?;
            state.size.store(new_size, Ordering::SeqCst);
            Ok::<_, anyhow::Error>(job.handoff(guard))
        }).await.map_err(|e| error!("Native package truncate task failed: {e}"))??;
        phase.check_completion()?;
        handoff.consume(|_| { self.state.write_healthy.store(true, Ordering::SeqCst); Ok(()) })?;
        phase.complete();
        Ok(())
    }

    pub async fn read_entry(&self, offset: u64) -> Result<PackageEntry> {
        self.read_entry_bounded(offset, wire_read_limits()).await
    }

    pub(super) async fn open_reader(&self) -> Result<super::native_read::NativePackageReader> {
        let operation = self.enter_operation()?;
        super::native_read::NativePackageReader::open(operation, self.state.path.clone(), wire_read_limits()).await
    }

    pub async fn read_entry_bounded(
        &self,
        offset: u64,
        limits: super::bounded_read::ArchiveReadLimits,
    ) -> Result<PackageEntry> {
        let operation = self.enter_operation()?;
        self.read_entry_bounded_in(&operation, offset, limits).await
    }

    pub(super) async fn read_entry_bounded_in(
        &self, parent: &ArchiveOperation, offset: u64,
        limits: super::bounded_read::ArchiveReadLimits,
    ) -> Result<PackageEntry> {
        let operation = self.inherit_operation(parent)?;
        super::native_read::read_entry(operation, self.state.path.clone(), offset, limits).await
    }

    pub(super) async fn read_range_in(
        &self, parent: &ArchiveOperation, offset: u64, limit: u32,
    ) -> Result<Vec<u8>> {
        let operation = self.inherit_operation(parent)?;
        super::native_read::read_range(operation, self.state.path.clone(), offset, limit).await
    }

    pub async fn append_entry(
        &self,
        entry: PackageEntry,
        after_append: impl FnOnce(u64, u64) -> Result<()>,
    ) -> Result<PackageEntry> {
        self.append_entry_checked(entry, Ok, after_append).await
    }

    pub(super) async fn append_indexed_entry(
        &self,
        entry: PackageEntry,
        after_append: impl FnOnce(u32, u64) -> Result<()>,
    ) -> Result<PackageEntry> {
        self.append_entry_checked(entry, block_index_offset, after_append).await
    }

    async fn append_entry_checked<O: Send + 'static>(
        &self, entry: PackageEntry,
        checked_offset: impl FnOnce(u64) -> Result<O> + Send + 'static,
        after_append: impl FnOnce(O, u64) -> Result<()>,
    ) -> Result<PackageEntry> {
        let entry_size = entry.serialized_size()?;
        let operation = self.enter_operation()?;
        let guard = self.lock_writer().await;
        if !self.state.write_healthy.load(Ordering::SeqCst) {
            fail!("Package write state is uncertain; reopen before mutation");
        }
        let (phase, mut job) = operation.mutation_phase();
        let state = self.state.clone();
        let handoff = tokio::task::spawn_blocking(move || {
            let mut guard = guard;
            let file = guard.as_mut().ok_or_else(|| error!("Package writer is closed"))?;
            state.write_healthy.store(false, Ordering::SeqCst);
            let raw_size = state.size.load(Ordering::SeqCst);
            if raw_size < PKG_HEADER_SIZE as u64 { fail!("Package length is smaller than its header"); }
            let actual_before = file.metadata()?.len();
            if raw_size != actual_before { fail!("Package physical/logical length mismatch before append"); }
            let cursor = std::io::Seek::stream_position(file)?;
            if cursor != raw_size { fail!("Package writer cursor mismatch before append"); }
            let prepared = AppendLayout::checked(raw_size, entry_size)
                .and_then(|layout| Ok((checked_offset(layout.entry_offset)?, layout)));
            let (offset, layout) = match prepared {
                Ok(value) => value,
                Err(error) => { state.write_healthy.store(true, Ordering::SeqCst); return Err(error); }
            };
            if let Err(error) = job.start() {
                // Pure preflight succeeded and no canonical byte was touched.
                state.write_healthy.store(true, Ordering::SeqCst);
                return Err(error);
            }
            #[cfg(test)]
            if let Some(probe) = state.append_probe.lock().unwrap().take() {
                probe.started.send(())?;
                probe.release.recv_timeout(std::time::Duration::from_secs(10))?;
            }
            let written = entry.write_to_sync(file)?;
            if written != entry_size { fail!("Package entry encoded size changed during append"); }
            file.sync_data()?;
            if file.metadata()?.len() != layout.total_size { fail!("Package physical/logical length mismatch after append"); }
            state.size.store(layout.total_size, Ordering::SeqCst);
            Ok::<_, anyhow::Error>(job.handoff((Some(entry), Some(offset), layout.logical_size, guard)))
        }).await.map_err(|e| error!("Native package append task failed: {e}"))??;
        let mut entry = None;
        phase.check_completion()?;
        handoff.consume(|payload| {
            after_append(payload.1.take().expect("checked append offset"), payload.2)?;
            self.state.write_healthy.store(true, Ordering::SeqCst);
            entry = payload.0.take();
            Ok(())
        })?;
        phase.complete();
        Ok(entry.expect("consumed package entry"))
    }

}

// Preserve the legacy API's full wire-format range. Callers requiring a
// resource budget must continue using read_entry_bounded with explicit limits.
fn wire_read_limits() -> super::bounded_read::ArchiveReadLimits {
    super::bounded_read::ArchiveReadLimits { data_bytes: u32::MAX as usize, filename_bytes: u16::MAX as usize }
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
pub(super) fn package_fixture_context() -> Result<(tempfile::TempDir, ArchiveView, ArchiveOperation)> {
    let dir = tempfile::tempdir()?;
    let db = crate::db::rocksdb::RocksDb::new(dir.path(), "provider", None, crate::db::rocksdb::AccessType::ReadWrite)?;
    let view = db.bind_archive_domain(super::context::ArchiveDomain::new())?.view()?;
    let operation = view.enter()?;
    Ok((dir, view, operation))
}

#[cfg(test)]
#[path = "../tests/test_package.rs"]
mod tests;

// Missing files are already removed. Other errors must reach the mutation
// owner; a failed existence probe must never turn into apparent success.
fn remove_file_native(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Called by an owned storage operation. Synchronize the directory chain as
/// archive packages may have created more than one new ancestor directory.
pub(crate) async fn sync_file_and_parents(path: &Path) -> Result<()> {
    sync_file_and_parents_observed(path, None).await
}
pub(crate) async fn sync_file_and_parents_observed(
    path: &Path,
    observer: crate::durability::SyncObservation,
) -> Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || sync_file_and_parents_native(&path, observer.as_deref()))
        .await.map_err(|e| error!("Native file sync task failed: {e}"))?
}

fn sync_file_and_parents_native(
    path: &Path,
    observer: Option<&crate::durability::SyncObserver>,
) -> Result<()> {
    let file = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
    crate::durability::before(observer, crate::durability::SyncPoint::File, path)?;
    file.sync_all()?;
    let mut parent = path.parent();
    while let Some(directory) = parent {
        if directory.as_os_str().is_empty() {
            break;
        }
        let file = std::fs::File::open(directory)?;
        crate::durability::before(observer, crate::durability::SyncPoint::Directory, directory)?;
        file.sync_all()?;
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
        let (_context_dir, view, operation) = package_fixture_context()?;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("archive.pack");
        // Real fixed package/entry headers followed by an exact-sized payload.
        let mut data = 0xAE8F_DD01u32.to_le_bytes().to_vec();
        data.extend_from_slice(&0x1E8Bu16.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(b"xabcd");
        std::fs::write(&path, &data)?;
        let package = Package::open(view.clone(), &operation, path.clone(), true, false).await?;
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
        let (_context_dir, view, operation) = package_fixture_context()?;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("protected.pack");
        let package = Package::open(view.clone(), &operation, path.clone(), false, true).await?;
        let entry = PackageEntry::with_data("first".into(), b"first".to_vec());
        let entry = package.append_entry(entry, |_, _| Ok(())).await?;
        let size = package.size();
        drop(package);
        let original = std::fs::read(&path)?;
        let mut damaged = original.clone();
        damaged[0] ^= 0xff;
        std::fs::write(&path, &damaged)?;
        assert!(Package::open_existing_exact(view.clone(), &operation, path.clone(), true, size).await.is_err());
        assert_eq!(std::fs::read(&path)?, damaged);
        std::fs::write(&path, &original)?;
        let package = Package::open_existing_exact(view.clone(), &operation, path.clone(), false, size).await?;
        package.append_entry(entry, |_, _| Ok(())).await?;
        let appended = package.size();
        assert!(appended > size);
        drop(package);
        assert!(Package::open_existing_exact(view.clone(), &operation, path.clone(), true, appended).await.is_ok());
        Ok(())
    }
}

#[cfg(test)]
mod write_health_tests {
    use super::*;

    #[tokio::test]
    async fn metadata_error_fences_append_and_truncate_until_fresh_owner_recovery() -> Result<()> {
        let (_context_dir, view, operation) = package_fixture_context()?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("write-health.pack");
        let package = Package::open(view.clone(), &operation, path.clone(), false, true).await?;
        let seed = PackageEntry::with_data("seed".into(), b"acknowledged bytes".to_vec());
        let seed = package.append_entry(seed, |_, _| Ok(())).await?;
        let committed_end = package.size();
        let original = std::fs::read(&path)?;
        let target = || PackageEntry::with_data("target".into(), b"uncommitted metadata".to_vec());
        let error = package
            .append_entry(target(), |_, _| Err(error!("metadata commit refused")))
            .await
            .err().expect("metadata callback failure must propagate");
        assert!(error.to_string().contains("metadata commit refused"));
        let uncertain = std::fs::read(&path)?;
        assert!(uncertain.starts_with(&original));
        assert!(uncertain.len() > original.len());
        let error = package.read_entry(0).await.err().expect("failed domain must refuse new reads");
        assert!(error.is::<crate::archives::context::ArchiveContextError>());
        let calls = AtomicU64::new(0);
        let error = package
            .append_entry(target(), |_, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await
            .err().expect("unhealthy append must be refused");
        assert!(error.is::<crate::archives::context::ArchiveContextError>());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let error =
            package.truncate(committed_end).await.expect_err("unhealthy truncate must be refused");
        assert!(error.is::<crate::archives::context::ArchiveContextError>());
        assert_eq!(std::fs::read(&path)?, uncertain, "refusal must not repair or mutate bytes");
        drop(package);
        assert!(Package::open_existing_exact(view.clone(), &operation, path.clone(), false, committed_end).await.is_err());
        assert_eq!(
            std::fs::read(&path)?,
            uncertain,
            "protected reopen must preserve uncertain history"
        );
        assert!(view.binding().domain().recovery_required());
        drop(operation); drop(view);
        // Reopen the actual provider with a fresh domain; the failed in-process
        // domain cannot be bypassed by merely constructing another Package.
        let db = crate::db::rocksdb::RocksDb::new(_context_dir.path(), "provider", None, crate::db::rocksdb::AccessType::ReadWrite)?;
        let view = db.bind_archive_domain(super::super::context::ArchiveDomain::new())?.view()?;
        let operation = view.enter()?;
        assert!(Package::open_existing_exact(view.clone(), &operation, path.clone(), false, committed_end).await.is_err());
        // This models only the explicitly unprotected durable-end recovery policy.
        let recovered = Package::open(view.clone(), &operation, path.clone(), false, false).await?;
        recovered.truncate(committed_end).await?;
        assert_eq!(std::fs::read(&path)?, original);
        let read = recovered.read_entry(0).await?;
        assert_eq!(read.filename(), seed.filename());
        assert_eq!(read.data(), seed.data());
        let target = recovered.append_entry(target(), |_, _| Ok(())).await?;
        let entry = recovered.read_entry(committed_end).await?;
        assert_eq!(entry.filename(), target.filename());
        assert_eq!(entry.data(), target.data());
        Ok(())
    }

    #[tokio::test]
    async fn prewrite_length_mismatch_is_refused_and_latches_write_health() -> Result<()> {
        let (_context_dir, view, operation) = package_fixture_context()?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("length-mismatch.pack");
        let package = Package::open(view.clone(), &operation, path.clone(), false, true).await?;
        let seed = PackageEntry::with_data("seed".into(), b"seed".to_vec());
        let seed = package.append_entry(seed, |_, _| Ok(())).await?;
        use std::io::Write;
        std::fs::OpenOptions::new().append(true).open(&path)?.write_all(b"foreign tail")?;
        let before = std::fs::read(&path)?;
        let error = package
            .append_entry(seed, |_, _| panic!("mismatch must precede metadata"))
            .await
            .err().expect("length mismatch must fail closed");
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

#[cfg(test)]
mod consuming_tests {
    use super::*;
    use std::time::Duration;

    async fn check_owned_append(indexed: bool) -> Result<()> {
        let (_context_dir, view, operation) = package_fixture_context()?;
        let directory = tempfile::tempdir()?;
        let package = Package::open(
            view, &operation, directory.path().join("owned.pack"), false, true,
        ).await?;
        let entry = PackageEntry::with_data("owned".into(), b"owned payload".to_vec());
        let data_pointer = entry.data().as_ptr();
        let name_pointer = entry.filename().as_ptr();
        let encoded_size = entry.serialized_size()?;
        let calls = AtomicU64::new(0);
        let callback = |offset: u64, size: u64| {
            assert!(package.state.write_mutex.try_lock().is_err(), "metadata callback lost writer guard");
            assert_eq!(offset, 0);
            assert_eq!(size, encoded_size);
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        };
        let entry = if indexed {
            package.append_indexed_entry(entry, |offset, size| callback(u64::from(offset), size)).await?
        } else {
            package.append_entry(entry, callback).await?
        };
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(entry.data().as_ptr(), data_pointer, "append replaced owned payload allocation");
        assert_eq!(entry.filename().as_ptr(), name_pointer);
        assert_eq!(entry.data(), b"owned payload");
        assert_eq!(entry.filename(), "owned");
        assert!(package.state.write_mutex.try_lock().is_ok(), "append returned while writer guard remained locked");
        tokio::time::timeout(Duration::from_secs(5), package.sync_durable(None)).await??;
        let next = package.size();
        let entry = tokio::time::timeout(Duration::from_secs(5), async {
            if indexed {
                package.append_indexed_entry(entry, |offset, _| {
                    assert_eq!(u64::from(offset), next);
                    Ok(())
                }).await
            } else {
                package.append_entry(entry, |offset, _| {
                    assert_eq!(offset, next);
                    Ok(())
                }).await
            }
        }).await??;
        assert_eq!(entry.data().as_ptr(), data_pointer, "append replaced owned payload allocation");
        tokio::time::timeout(Duration::from_secs(5), package.sync_durable(None)).await??;
        for offset in [0, next] {
            let stored = package.read_entry(offset).await?;
            assert_eq!(stored.filename(), entry.filename());
            assert_eq!(stored.data(), entry.data());
        }
        Ok(())
    }

    #[tokio::test]
    async fn ordinary_append_returns_owned_buffer_after_unlock() -> Result<()> {
        check_owned_append(false).await
    }

    #[tokio::test]
    async fn indexed_append_returns_owned_buffer_after_unlock() -> Result<()> {
        check_owned_append(true).await
    }
}

#[cfg(test)]
mod state_ownership_tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn shared_state_and_owned_writer_outlive_dropped_package_handle() -> Result<()> {
        let (_context_dir, view, operation) = package_fixture_context()?;
        let dir = tempfile::tempdir()?;
        let package = Package::open(view.clone(), &operation, dir.path().join("owned.pack"), false, true).await?;
        let state = package.state.clone();
        let weak_state = Arc::downgrade(&state);
        let weak_provider = Arc::downgrade(view.binding().db());
        let mut guard = package.lock_writer().await;
        let worker_state = weak_state.clone();
        drop(state);
        fn assert_send<T: Send>(_: &T) {}
        assert_send(&guard);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let observer = tokio::spawn(async move {
            let _ = started_tx.send(());
            release_rx.await.unwrap();
            let state = worker_state.upgrade().expect("writer guard must pin shared package state");
            assert!(state.write_mutex.try_lock().is_err());
            assert_eq!(guard.as_mut().unwrap().metadata().unwrap().len(), PKG_HEADER_SIZE as u64);
            drop(guard);
            assert!(state.write_mutex.try_lock().is_ok());
            drop(state);
            let _ = done_tx.send(());
        });
        started_rx.await?;
        drop(package); drop(operation); drop(view); drop(observer);
        assert!(weak_state.upgrade().is_some()); assert!(weak_provider.upgrade().is_some());
        release_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(10), done_rx).await??;
        assert!(weak_state.upgrade().is_none()); assert!(weak_provider.upgrade().is_none());
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/test_package_native_writer.rs"]
mod native_writer_tests;

#[path = "package_retirement.rs"]
mod retirement;
pub(super) fn retirement_restart_required() -> bool { retirement::restart_required() }
