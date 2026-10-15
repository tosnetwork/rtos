// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::archives::bounded_read::ArchiveReadLimits;

#[test]
fn append_layout_checks_total_cursor_and_index_boundaries() -> Result<()> {
    assert!(AppendLayout::checked(3, 8).is_err());
    assert!(AppendLayout::checked(u64::MAX, 1).is_err());
    let layout = AppendLayout::checked(4, 8)?;
    assert_eq!((layout.entry_offset, layout.total_size, layout.logical_size), (0, 12, 8));
    let layout = AppendLayout::checked(u64::from(u32::MAX) + 4, 16)?;
    assert_eq!(block_index_offset(layout.entry_offset)?, u32::MAX);
    assert!(layout.logical_size > u64::from(u32::MAX));
    assert!(block_index_offset(u64::from(u32::MAX) + 1).is_err());
    Ok(())
}

#[tokio::test]
async fn invalid_append_preserves_file_then_maximum_filename_roundtrips() -> Result<()> {
    let (directory, view, operation) = package_fixture_context()?;
    let path = directory.path().join("preflight.pack");
    let package = Package::open(view, &operation, path.clone(), false, true).await?;
    let before = std::fs::read(&path)?;
    let mut callbacks = 0;
    let invalid = PackageEntry::with_data("x".repeat(usize::from(u16::MAX) + 1), vec![1]);
    assert!(package.append_entry(invalid, |_, _| { callbacks += 1; Ok(()) }).await.is_err());
    assert_eq!(callbacks, 0);
    assert_eq!(package.size(), 0);
    assert_eq!(std::fs::read(&path)?, before);
    assert!(package.write_healthy.load(Ordering::SeqCst));
    let valid = PackageEntry::with_data("x".repeat(usize::from(u16::MAX)), vec![7, 8]);
    let encoded_size = valid.serialized_size()?;
    let valid = package.append_entry(valid, |offset, size| {
        callbacks += 1;
        assert_eq!(offset, 0);
        assert_eq!(size, encoded_size);
        Ok(())
    }).await?;
    let read = package.read_entry_bounded(0, ArchiveReadLimits {
        filename_bytes: usize::from(u16::MAX), data_bytes: 2,
    }).await?;
    assert_eq!(read.filename(), valid.filename());
    assert_eq!(read.data(), valid.data());
    assert_eq!(callbacks, 1);
    Ok(())
}

#[tokio::test]
async fn damaged_length_and_cursor_latch_before_append() -> Result<()> {
    for bad_length in [true, false] {
        let (directory, view, operation) = package_fixture_context()?;
        let path = directory.path().join("damaged.pack");
        let package = Package::open(view, &operation, path.clone(), false, true).await?;
        if bad_length {
            package.size.store(3, Ordering::SeqCst);
        } else {
            package.write_mutex.lock().await.as_mut().unwrap().seek(SeekFrom::Start(0)).await?;
        }
        let before = std::fs::read(&path)?;
        let entry = PackageEntry::with_data("entry".into(), vec![1]);
        let error = package.append_entry(entry, |_, _| panic!("damaged writer reached metadata"))
            .await.err().expect("damaged writer must be refused");
        assert!(error.to_string().contains(if bad_length { "smaller than its header" } else { "cursor mismatch" }));
        assert!(!package.write_healthy.load(Ordering::SeqCst));
        assert_eq!(std::fs::read(&path)?, before);
        assert!(package.truncate(0).await.unwrap_err().to_string().contains("write state is uncertain"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn sparse_indexed_append_checks_start_before_effects() -> Result<()> {
    use std::{io::Write, os::unix::fs::{FileExt, MetadataExt}};
    for offset in [u64::from(u32::MAX), u64::from(u32::MAX) + 1] {
        let (directory, view, operation) = package_fixture_context()?;
        let path = directory.path().join("sparse.pack");
        let raw_size = offset + PKG_HEADER_SIZE as u64;
        let mut seed = std::fs::File::create(&path)?;
        seed.write_all(&PKG_HEADER_MAGIC.to_le_bytes())?;
        seed.set_len(raw_size)?;
        seed.sync_all()?;
        drop(seed);
        let before = std::fs::metadata(&path)?;
        assert!(before.blocks() * 512 < 1024 * 1024,
            "sparse fixture unsupported: indexed offset boundary remains unverified");
        let package = Package::open(view, &operation, path.clone(), false, false).await?;
        let make_entry = || PackageEntry::with_data("block".into(), vec![1, 2, 3]);
        let entry = make_entry();
        let encoded_size = entry.serialized_size()?;
        let mut callbacks = 0;
        let result = package.append_indexed_entry(entry, |actual, size| {
            callbacks += 1;
            assert_eq!(u64::from(actual), offset);
            assert_eq!(size, offset + encoded_size);
            Ok(())
        }).await;
        let entry = if offset == u64::from(u32::MAX) {
            let entry = result?;
            assert_eq!(callbacks, 1);
            assert_eq!(std::fs::metadata(&path)?.len(), raw_size + entry.serialized_size()?);
            entry
        } else {
            assert!(result.err().expect("oversized Block offset must fail").to_string().contains("BlockIndex offset exceeds u32"));
            assert_eq!(callbacks, 0);
            let after = std::fs::metadata(&path)?;
            assert_eq!((after.len(), after.blocks()), (before.len(), before.blocks()));
            assert_eq!(package.size(), offset);
            let file = std::fs::File::open(&path)?;
            let mut header = [0; 4]; file.read_exact_at(&mut header, 0)?;
            assert_eq!(header, PKG_HEADER_MAGIC.to_le_bytes());
            let mut tail = [1; 8]; file.read_exact_at(&mut tail, raw_size - 8)?;
            assert_eq!(tail, [0; 8]);
            // A wide non-Block entry remains legal at this offset after refusal.
            package.append_entry(make_entry(), |actual, _| { assert_eq!(actual, offset); Ok(()) }).await?
        };
        let read = package.read_entry_bounded(offset, ArchiveReadLimits { filename_bytes: 5, data_bytes: 3 }).await?;
        assert_eq!(read.filename(), entry.filename());
        assert_eq!(read.data(), entry.data());
        drop(package);
        std::fs::remove_file(path)?;
    }
    Ok(())
}
