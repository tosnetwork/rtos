// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::archives::bounded_read::{ArchiveReadLimits, ArchiveReadLimitExceeded};
use std::io::{self, Cursor, Read, Write};

fn limits() -> ArchiveReadLimits { ArchiveReadLimits { data_bytes: 16 * 1024 * 1024, filename_bytes: u16::MAX as usize } }

#[tokio::test]
async fn native_encoding_matches_async_wire_and_preserves_original_body() -> Result<()> {
    for (name, body) in [(String::new(), vec![]), ("块-é".into(), vec![1,2,3]),
        ("x".repeat(u16::MAX as usize), vec![5; 8 * 1024 * 1024 + 3])] {
        let entry = PackageEntry::with_data(name, body);
        let original = entry.data().as_ptr();
        let mut native = Vec::new(); let size = entry.write_to_sync(&mut native)?;
        let mut asynchronous = Vec::new();
        assert_eq!(entry.write_to(&mut asynchronous).await?, size);
        assert_eq!(native, asynchronous); assert_eq!(size, entry.serialized_size()?);
        assert_eq!(entry.data().as_ptr(), original);
        let mut input = native.as_slice();
        let decoded = PackageEntry::read_next_bounded_sync(&mut input, limits())?.unwrap();
        assert_eq!(decoded.filename(), entry.filename()); assert_eq!(decoded.data(), entry.data());
        assert!(PackageEntry::read_next_bounded_sync(&mut input, limits())?.is_none());
    }
    Ok(())
}

#[test]
fn native_sequential_scan_rejects_every_partial_header_and_body() -> Result<()> {
    let entry = PackageEntry::with_data("block".into(), vec![3; 19]);
    let mut bytes = Vec::new(); entry.write_to_sync(&mut bytes)?;
    assert!(PackageEntry::read_next_bounded_sync(&mut io::empty(), limits())?.is_none());
    for end in 1..bytes.len() {
        assert!(PackageEntry::read_next_bounded_sync(&mut &bytes[..end], limits()).is_err(), "partial entry at {end}");
    }
    let mut input = Cursor::new([bytes.clone(), bytes.clone()].concat());
    for _ in 0..2 { assert_eq!(PackageEntry::read_next_bounded_sync(&mut input, limits())?.unwrap().data(), entry.data()); }
    assert!(PackageEntry::read_next_bounded_sync(&mut input, limits())?.is_none());
    let mut bad = bytes.clone(); bad[0] ^= 1;
    assert!(PackageEntry::read_next_bounded_sync(&mut &bad[..], limits()).is_err());
    bad = bytes; bad[PKG_ENTRY_HEADER_SIZE] = 255;
    assert!(PackageEntry::read_next_bounded_sync(&mut &bad[..], limits()).is_err());
    Ok(())
}

#[test]
fn native_limits_precede_payload_reads_and_io_errors_remain_errors() -> Result<()> {
    let limits = ArchiveReadLimits { filename_bytes: 8, data_bytes: 4 };
    for (filename_size, data_size) in [(9, 1), (1, 5)] {
        let header = PackageEntryHeader { filename_size, data_size }.serialize();
        let error = PackageEntry::read_next_bounded_sync(&mut header.as_slice(), limits).err().unwrap();
        assert!(error.is::<ArchiveReadLimitExceeded>());
    }
    struct Broken(io::ErrorKind);
    impl Read for Broken { fn read(&mut self, _: &mut [u8]) -> io::Result<usize> { Err(io::Error::new(self.0, "native read error")) } }
    for kind in [io::ErrorKind::Other, io::ErrorKind::UnexpectedEof] {
        assert!(PackageEntry::read_next_bounded_sync(&mut Broken(kind), limits).is_err());
    }
    struct InterruptedOnce<R> { reader: R, interrupted: bool }
    impl<R: Read> Read for InterruptedOnce<R> {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted { self.interrupted = true; return Err(io::ErrorKind::Interrupted.into()); }
            self.reader.read(output)
        }
    }
    let entry = PackageEntry::with_data("ok".into(), vec![1]); let mut bytes = Vec::new();
    entry.write_to_sync(&mut bytes)?;
    let mut input = InterruptedOnce { reader: bytes.as_slice(), interrupted: false };
    assert_eq!(PackageEntry::read_next_bounded_sync(&mut input, limits)?.unwrap().data(), &[1]);
    Ok(())
}

#[derive(Default)]
struct FaultWriter { remaining: usize, writes: usize, flushes: usize, fail_flush: bool }
impl Write for FaultWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.remaining == 0 { return Err(io::Error::other("native short write")); }
        let n = bytes.len().min(self.remaining).min(3); self.remaining -= n; Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if self.fail_flush { Err(io::Error::other("native flush error")) } else { Ok(()) }
    }
}
#[test]
fn native_write_rejects_bad_lengths_before_io_and_propagates_partial_failures() -> Result<()> {
    let invalid = PackageEntry::with_data("x".repeat(u16::MAX as usize + 1), vec![1]);
    let mut writer = FaultWriter::default();
    assert!(invalid.write_to_sync(&mut writer).is_err());
    assert_eq!((writer.writes, writer.flushes), (0,0));
    let entry = PackageEntry::with_data("entry".into(), vec![3;19]);
    let size = entry.serialized_size()? as usize;
    for end in 0..size {
        let mut writer = FaultWriter { remaining: end, ..Default::default() };
        assert!(entry.write_to_sync(&mut writer).is_err()); assert_eq!(writer.flushes, 0);
    }
    let mut writer = FaultWriter { remaining: size, fail_flush: true, ..Default::default() };
    assert!(entry.write_to_sync(&mut writer).is_err()); assert_eq!(writer.flushes, 1);
    let mut writer = FaultWriter { remaining: size, ..Default::default() };
    assert_eq!(entry.write_to_sync(&mut writer)?, size as u64);
    assert_eq!(writer.remaining, 0); assert_eq!(writer.flushes, 1);
    Ok(())
}

#[tokio::test]
async fn owned_native_phase_encodes_and_syncs_real_file_then_scans_after_reopen() -> Result<()> {
    use crate::{archives::context::ArchiveDomain, db::rocksdb::{RocksDb, AccessType}};
    let dir = tempfile::tempdir()?;
    let db = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite)?;
    let domain = ArchiveDomain::new(); let provider = db.bind_archive_domain(domain.clone())?;
    let execution = domain.begin_recovery(0, &[provider])?;
    execution.wait_for_old_io().await?;
    let path = dir.path().join("native-entries"); let output = path.clone();
    let entry = PackageEntry::with_data("retained-entry".into(), vec![7; 1024 * 1024 + 1]);
    let pointer = entry.data().as_ptr() as usize;
    execution.retire_packages()?.await??.consume(|_| Ok(()))?;
    execution.spawn_recovery_phase(move || {
        let mut file = std::fs::File::create(output)?;
        entry.write_to_sync(&mut file)?; entry.write_to_sync(&mut file)?; file.sync_all()?;
        Ok(entry)
    })?.await??.consume(|entry| { assert_eq!(entry.data().as_ptr() as usize, pointer); Ok(()) })?;
    let mut file = std::fs::File::open(path)?;
    for _ in 0..2 {
        let entry = PackageEntry::read_next_bounded_sync(&mut file, limits())?.unwrap();
        assert_eq!(entry.filename(), "retained-entry"); assert_eq!(entry.data(), vec![7;1024*1024+1]);
    }
    assert!(PackageEntry::read_next_bounded_sync(&mut file, limits())?.is_none());
    // This fixture verifies owned native codec IO; it is not a durable recovery
    // completion or an explicit close receipt for the canonical Package writer.
    drop(execution); assert!(domain.recovery_required());
    Ok(())
}
