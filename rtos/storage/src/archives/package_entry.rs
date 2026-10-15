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
use crate::{traits::Serializable, TARGET};
use rtos_block::{error, fail, Result};

pub(crate) const PKG_ENTRY_HEADER_SIZE: usize = 8;
const PKG_ENTRY_HEADER_MAGIC: u16 = 0x1E8B;

#[derive(Debug)]
struct PackageEntryHeader {
    filename_size: u16,
    data_size: u32,
}

struct PackageEntryLayout {
    header: PackageEntryHeader,
    size: u64,
}

impl PackageEntryLayout {
    fn checked(filename_size: u64, data_size: u64) -> Result<Self> {
        let header = PackageEntryHeader {
            filename_size: u16::try_from(filename_size)
                .map_err(|_| error!("Package entry filename exceeds u16 length"))?,
            data_size: u32::try_from(data_size)
                .map_err(|_| error!("Package entry data exceeds u32 length"))?,
        };
        let size = (PKG_ENTRY_HEADER_SIZE as u64)
            .checked_add(filename_size)
            .and_then(|size| size.checked_add(data_size))
            .ok_or_else(|| error!("Package entry encoded size overflow"))?;
        Ok(Self { header, size })
    }
}

impl Serializable for PackageEntryHeader {
    const SIZE: usize = PKG_ENTRY_HEADER_SIZE;
    type Bytes = [u8; Self::SIZE];
    fn serialize(&self) -> Self::Bytes {
        let mut ret = [0u8; Self::SIZE];
        ret[..2].copy_from_slice(&PKG_ENTRY_HEADER_MAGIC.serialize());
        ret[2..4].copy_from_slice(&self.filename_size.serialize());
        ret[4..].copy_from_slice(&self.data_size.serialize());
        ret
    }
    fn deserialize_checked(data: &[u8]) -> Result<Self> {
        let magic = u16::deserialize(data)?;
        if magic != PKG_ENTRY_HEADER_MAGIC {
            fail!("Bad entry magic: 0x{magic:X}")
        }
        let filename_size = u16::deserialize(&data[2..])?;
        let data_size = u32::deserialize(&data[4..])?;
        let ret = Self { filename_size, data_size };
        Ok(ret)
    }
}

pub struct PackageEntry {
    filename: String,
    data: Vec<u8>,
}

impl PackageEntry {
    pub const fn with_data(filename: String, data: Vec<u8>) -> Self {
        Self { filename, data }
    }

    pub(super) async fn read_from<R: tokio::io::AsyncReadExt + Unpin>(
        reader: &mut R,
    ) -> Result<Option<Self>> {
        let mut buf = [0; PKG_ENTRY_HEADER_SIZE];
        match reader.read_exact(&mut buf).await {
            Ok(count) => assert_eq!(count, buf.len()),
            Err(error) => {
                return if error.kind() == tokio::io::ErrorKind::UnexpectedEof {
                    Ok(None)
                } else {
                    Err(error.into())
                }
            }
        }
        let entry_header = PackageEntryHeader::deserialize(&buf)?;
        let mut buf = vec![0; entry_header.filename_size as usize];
        reader.read_exact(&mut buf).await?;
        let filename = String::from_utf8(buf)?;
        log::trace!(
            target: TARGET,
            "Reading package entry: {filename}, size: {}",
            entry_header.data_size
        );
        let mut data = vec![0; entry_header.data_size as usize];
        reader.read_exact(&mut data).await?;
        Ok(Some(Self::with_data(filename, data)))
    }

    #[cfg(test)]
    pub(super) async fn read_from_bounded<R: tokio::io::AsyncReadExt + Unpin>(
        reader: &mut R,
        limits: super::bounded_read::ArchiveReadLimits,
    ) -> Result<Self> {
        let mut header = [0; PKG_ENTRY_HEADER_SIZE];
        reader.read_exact(&mut header).await?;
        let header = PackageEntryHeader::deserialize(&header)?;
        // Both lengths are checked before either attacker-sized allocation.
        let filename_size = super::bounded_read::check_length("filename", u64::from(header.filename_size), limits.filename_bytes)?;
        let data_size = super::bounded_read::check_length("data", u64::from(header.data_size), limits.data_bytes)?;
        let mut filename = vec![0; filename_size];
        reader.read_exact(&mut filename).await?;
        let filename = String::from_utf8(filename)?;
        let mut data = vec![0; data_size];
        reader.read_exact(&mut data).await?;
        Ok(Self::with_data(filename, data))
    }

    /// Native counterpart of bounded decoding, used by owned blocking readers.
    pub(super) fn read_from_bounded_sync<R: std::io::Read>(
        reader: &mut R,
        limits: super::bounded_read::ArchiveReadLimits,
    ) -> Result<Self> {
        let mut header = [0; PKG_ENTRY_HEADER_SIZE];
        reader.read_exact(&mut header)?;
        let header = PackageEntryHeader::deserialize(&header)?;
        // Validate both advertised lengths before allocating either payload.
        let filename_size = super::bounded_read::check_length(
            "filename", u64::from(header.filename_size), limits.filename_bytes,
        )?;
        let data_size = super::bounded_read::check_length(
            "data", u64::from(header.data_size), limits.data_bytes,
        )?;
        let mut filename = vec![0; filename_size];
        reader.read_exact(&mut filename)?;
        let filename = String::from_utf8(filename)?;
        let mut data = vec![0; data_size];
        reader.read_exact(&mut data)?;
        Ok(Self::with_data(filename, data))
    }

    pub(super) async fn write_to<W: tokio::io::AsyncWriteExt + Unpin>(
        &self,
        writer: &mut W,
    ) -> Result<u64> {
        let layout = self.layout()?;
        writer.write_all(&layout.header.serialize()).await?;
        writer.write_all(self.filename.as_bytes()).await?;
        writer.write_all(&self.data).await?;
        writer.flush().await?;
        Ok(layout.size)
    }

    pub fn filename(&self) -> &str {
        self.filename.as_str()
    }

    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }

    pub fn take_data(self) -> Vec<u8> {
        self.data
    }

    /// Returns the serialized size of this entry (header + filename + data).
    pub fn serialized_size(&self) -> Result<u64> {
        Ok(self.layout()?.size)
    }

    fn layout(&self) -> Result<PackageEntryLayout> {
        PackageEntryLayout::checked(
            u64::try_from(self.filename.len())?,
            u64::try_from(self.data.len())?,
        )
    }
}

#[cfg(test)]
mod bounded_tests {
    use super::*;
    use crate::archives::bounded_read::{ArchiveReadLimitExceeded, ArchiveReadLimits};
    #[tokio::test]
    async fn bounded_archive_header_rejects_before_payload_read() -> Result<()> {
        let limits = ArchiveReadLimits { data_bytes: 4, filename_bytes: 8 };
        for (filename_size, data_size) in [(1, u32::MAX), (u16::MAX, 1)] {
            // Header only: a payload read would fail with EOF rather than the
            // typed limit. No attacker-sized payload exists in this fixture.
            let header = PackageEntryHeader { filename_size, data_size }.serialize();
            let mut input = header.as_slice();
            let error = PackageEntry::read_from_bounded(&mut input, limits).await.err().unwrap();
            assert!(error.downcast_ref::<ArchiveReadLimitExceeded>().is_some());
            assert!(input.is_empty());
        }
        let header = PackageEntryHeader { filename_size: 1, data_size: 4 }.serialize();
        for length in 0..header.len() {
            assert!(PackageEntry::read_from_bounded(&mut &header[..length], limits).await.is_err());
        }
        let mut invalid = header; invalid[0] ^= 1;
        assert!(PackageEntry::read_from_bounded(&mut invalid.as_slice(), limits).await.is_err());
        Ok(())
    }
}

#[cfg(test)]
mod encoding_tests {
    use super::*;
    use std::{pin::Pin, task::{Context, Poll}};

    #[test]
    fn checked_encoding_lengths_preserve_wire_limits() -> Result<()> {
        let layout = PackageEntryLayout::checked(u16::MAX.into(), u32::MAX.into())?;
        assert_eq!(layout.header.filename_size, u16::MAX);
        assert_eq!(layout.header.data_size, u32::MAX);
        assert_eq!(layout.size, 8 + u64::from(u16::MAX) + u64::from(u32::MAX));
        assert!(PackageEntryLayout::checked(u64::from(u16::MAX) + 1, 0).is_err());
        assert!(PackageEntryLayout::checked(0, u64::from(u32::MAX) + 1).is_err());
        assert!(PackageEntryLayout::checked(u64::MAX, u64::MAX).is_err());
        // UTF-8 byte length, not the character count, controls the wire field.
        let entry = PackageEntry::with_data("é".repeat(32768), vec![]);
        assert!(entry.serialized_size().is_err());
        Ok(())
    }

    #[derive(Default)]
    struct CountingWriter { writes: usize, flushes: usize }
    impl tokio::io::AsyncWrite for CountingWriter {
        fn poll_write(mut self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<std::io::Result<usize>> {
            self.writes += 1;
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.flushes += 1;
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn invalid_encoding_never_calls_writer() {
        let entry = PackageEntry::with_data("x".repeat(usize::from(u16::MAX) + 1), vec![1]);
        let mut writer = CountingWriter::default();
        assert!(entry.write_to(&mut writer).await.is_err());
        assert_eq!((writer.writes, writer.flushes), (0, 0));
    }
}
