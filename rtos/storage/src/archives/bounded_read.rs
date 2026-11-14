// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Explicit per-object limits; callers own cumulative request accounting.
#[cfg(test)]
use rtos_block::fail;
use rtos_block::Result;
#[cfg(test)]
use tokio::io::AsyncReadExt;

/// Shared storage/network cap for a single archive range response.
pub const ARCHIVE_RANGE_MAX_BYTES: usize = 1 << 21;

#[derive(Clone, Copy, Debug)]
pub struct ArchiveReadLimits {
    pub data_bytes: usize,
    pub filename_bytes: usize,
}
#[derive(Debug)]
pub struct ArchiveReadLimitExceeded {
    pub resource: &'static str,
    pub requested: u64,
    pub limit: usize,
}
impl std::fmt::Display for ArchiveReadLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Archive {} read limit exceeded: {} > {}",
            self.resource, self.requested, self.limit
        )
    }
}
impl std::error::Error for ArchiveReadLimitExceeded {}

/// Issued only by an open operation before any archive payload read.
#[derive(Debug)]
pub struct ArchiveReadNotStarted(std::io::Error);
impl ArchiveReadNotStarted {
    pub(super) fn from_open(error: std::io::Error) -> Self {
        Self(error)
    }
    pub fn is_not_found(&self) -> bool {
        self.0.kind() == std::io::ErrorKind::NotFound
    }
}
impl std::fmt::Display for ArchiveReadNotStarted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for ArchiveReadNotStarted {}

/// A bounded artifact lookup proved absence before opening its payload.
/// Only archive routing can mint this evidence; corrupt package contents and
/// arbitrary storage errors must never acquire missing-artifact semantics.
#[derive(Debug)]
pub struct ArchiveArtifactMissing(&'static str);
impl ArchiveArtifactMissing {
    pub(super) fn new(location: &'static str) -> Self {
        Self(location)
    }
}
impl std::fmt::Display for ArchiveArtifactMissing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Bounded archive artifact absent: {}", self.0)
    }
}
impl std::error::Error for ArchiveArtifactMissing {}

pub fn check_length(resource: &'static str, requested: u64, limit: usize) -> Result<usize> {
    if requested > limit as u64 {
        return Err(ArchiveReadLimitExceeded { resource, requested, limit }.into());
    }
    Ok(usize::try_from(requested)?)
}

#[cfg(test)]
pub(super) async fn read_loose(
    path: &std::path::Path,
    limits: ArchiveReadLimits,
) -> Result<Vec<u8>> {
    let mut file = tokio::fs::File::open(path).await.map_err(ArchiveReadNotStarted::from_open)?;
    let metadata = file.metadata().await?;
    if !metadata.is_file() {
        fail!("Archive entry is not a regular file");
    }
    read_opened(&mut file, metadata.len(), limits).await
}

#[cfg(test)]
async fn read_opened(
    file: &mut tokio::fs::File,
    expected: u64,
    limits: ArchiveReadLimits,
) -> Result<Vec<u8>> {
    let size = check_length("data", expected, limits.data_bytes)?;
    if size == 0 {
        fail!("Archive entry is empty");
    }
    // Read no more than the metadata size plus one sentinel byte, even if the
    // same opened file grows. No unrestricted read_to_end or second path open.
    let capacity =
        size.checked_add(1).ok_or_else(|| rtos_block::error!("Archive read size overflow"))?;
    let mut bytes = vec![0; capacity];
    let mut read = 0;
    while read < capacity {
        let count = file.read(&mut bytes[read..]).await?;
        if count == 0 {
            break;
        }
        read += count;
    }
    if read > limits.data_bytes {
        return Err(ArchiveReadLimitExceeded {
            resource: "data",
            requested: read as u64,
            limit: limits.data_bytes,
        }
        .into());
    }
    if read != size || file.metadata().await?.len() != expected {
        fail!("Archive file changed length during bounded read");
    }
    bytes.truncate(size);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn bounded_archive_loose_exact_limit_and_oversize() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("body");
        std::fs::write(&path, b"abcd")?;
        let limits = ArchiveReadLimits { data_bytes: 4, filename_bytes: 32 };
        assert_eq!(read_loose(&path, limits).await?, b"abcd");
        let error =
            read_loose(&path, ArchiveReadLimits { data_bytes: 3, ..limits }).await.unwrap_err();
        assert!(error.downcast_ref::<ArchiveReadLimitExceeded>().is_some());
        Ok(())
    }
    #[tokio::test]
    async fn bounded_archive_loose_same_fd_growth_truncation_and_replacement() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("body");
        let limits = ArchiveReadLimits { data_bytes: 4, filename_bytes: 32 };
        for new_data in [b"abcde".as_slice(), b"ab".as_slice()] {
            std::fs::write(&path, b"abcd")?;
            let mut file = tokio::fs::File::open(&path).await?;
            let size = file.metadata().await?.len();
            std::fs::write(&path, new_data)?;
            assert!(read_opened(&mut file, size, limits).await.is_err());
        }
        std::fs::write(&path, b"abcd")?;
        let mut file = tokio::fs::File::open(&path).await?;
        let size = file.metadata().await?.len();
        std::fs::rename(&path, dir.path().join("old"))?;
        std::fs::write(&path, vec![0; 100])?;
        assert_eq!(read_opened(&mut file, size, limits).await?, b"abcd");
        Ok(())
    }
}
