// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Native read owners for the canonical IO migration. Callers supply inherited
//! authority for the provider that owns the path; no new root is admitted here.
use super::{
    bounded_read::{
        check_length, ArchiveReadLimits, ArchiveReadNotStarted, ARCHIVE_RANGE_MAX_BYTES,
    },
    context::{ArchiveOperation, NativeCustody},
    package::{PKG_HEADER_MAGIC, PKG_HEADER_SIZE},
    package_entry::{PackageEntry, PKG_ENTRY_HEADER_SIZE},
};
use rtos_block::{error, fail, Result};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::PathBuf,
};

/// Field destruction order is intentional: close the actual descriptor before
/// releasing the provider and then its operation ticket, including on unwind.
struct OwnedReader {
    file: File,
    _custody: NativeCustody,
}

async fn read_owned<T: Send + 'static>(
    operation: ArchiveOperation,
    path: PathBuf,
    read: impl FnOnce(&mut File) -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(move || {
        // This check runs in the actual native owner, not its async observer.
        let custody = operation.start_read()?;
        let file = File::open(path).map_err(ArchiveReadNotStarted::from_open)?;
        let mut owner = OwnedReader { file, _custody: custody };
        read(&mut owner.file)
    })
    .await
    .map_err(|error| error!("Archive native read owner failed: {error}"))?
}

pub(super) async fn read_entry(
    operation: ArchiveOperation,
    path: PathBuf,
    offset: u64,
    limits: ArchiveReadLimits,
) -> Result<PackageEntry> {
    read_owned(operation, path, move |file| {
        let mut header = [0; PKG_HEADER_SIZE];
        file.read_exact(&mut header)?;
        if u32::from_le_bytes(header) != PKG_HEADER_MAGIC {
            fail!("Package file header mismatch");
        }
        let start = offset
            .checked_add(PKG_HEADER_SIZE as u64)
            .ok_or_else(|| error!("Archive entry offset overflow"))?;
        let end = start
            .checked_add(PKG_ENTRY_HEADER_SIZE as u64)
            .ok_or_else(|| error!("Archive entry header offset overflow"))?;
        if end > file.metadata()?.len() {
            fail!("Truncated archive entry header");
        }
        file.seek(SeekFrom::Start(start))?;
        PackageEntry::read_from_bounded_sync(file, limits)
    })
    .await
}

pub(super) async fn read_range(
    operation: ArchiveOperation,
    path: PathBuf,
    offset: u64,
    limit: u32,
) -> Result<Vec<u8>> {
    let capacity = check_length("range", u64::from(limit), ARCHIVE_RANGE_MAX_BYTES)?;
    offset.checked_add(u64::from(limit)).ok_or_else(|| error!("Archive range offset overflow"))?;
    read_owned(operation, path, move |file| {
        file.seek(SeekFrom::Start(offset))?;
        let mut bytes = vec![0; capacity];
        let mut count = 0;
        while count < capacity {
            let read = match file.read(&mut bytes[count..]) {
                Ok(read) => read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            if read == 0 {
                break;
            }
            count += read;
        }
        bytes.truncate(count);
        Ok(bytes)
    })
    .await
}

pub(super) async fn read_loose(
    operation: ArchiveOperation,
    path: PathBuf,
    limits: ArchiveReadLimits,
) -> Result<Vec<u8>> {
    read_owned(operation, path, move |file| {
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            fail!("Archive entry is not a regular file");
        }
        read_loose_opened(file, metadata.len(), limits)
    })
    .await
}

fn read_loose_opened(file: &mut File, expected: u64, limits: ArchiveReadLimits) -> Result<Vec<u8>> {
    let size = check_length("data", expected, limits.data_bytes)?;
    if size == 0 {
        fail!("Archive entry is empty");
    }
    let capacity = size.checked_add(1).ok_or_else(|| error!("Archive read size overflow"))?;
    let mut bytes = vec![0; capacity];
    let mut count = 0;
    while count < capacity {
        let read = match file.read(&mut bytes[count..]) {
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        if read == 0 {
            break;
        }
        count += read;
    }
    check_length("data", count as u64, limits.data_bytes)?;
    if count != size || file.metadata()?.len() != expected {
        fail!("Archive file changed length during bounded read");
    }
    bytes.truncate(size);
    Ok(bytes)
}

#[cfg(test)]
#[path = "../tests/test_archive_native_read.rs"]
mod tests;
