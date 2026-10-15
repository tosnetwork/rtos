// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{
    archives::{
        bounded_read::ArchiveReadLimitExceeded,
        context::{ArchiveContextError, ArchiveDomain, ArchiveView},
    },
    db::rocksdb::{AccessType, RocksDb},
};
use std::{sync::Arc, time::Duration};

fn fixture() -> (tempfile::TempDir, Arc<RocksDb>, Arc<ArchiveDomain>, ArchiveView) {
    let dir = tempfile::tempdir().unwrap();
    let db = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite).unwrap();
    let domain = ArchiveDomain::new();
    let view = db.bind_archive_domain(domain.clone()).unwrap().view().unwrap();
    (dir, db, domain, view)
}
fn package_bytes() -> Vec<u8> {
    let mut bytes = PKG_HEADER_MAGIC.to_le_bytes().to_vec();
    bytes.extend_from_slice(&0x1E8Bu16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&4u32.to_le_bytes());
    bytes.extend_from_slice(b"xabcd");
    bytes
}
const LIMITS: ArchiveReadLimits = ArchiveReadLimits { filename_bytes: 1, data_bytes: 4 };

#[tokio::test]
async fn native_entry_preserves_wire_format_and_rejects_bounds_before_payload_read() {
    let (dir, _db, domain, view) = fixture();
    let path = dir.path().join("archive.pack");
    let bytes = package_bytes();
    std::fs::write(&path, &bytes).unwrap();
    let entry = read_entry(view.enter().unwrap(), path.clone(), 0, LIMITS).await.unwrap();
    assert_eq!(entry.filename(), "x");
    assert_eq!(entry.data(), b"abcd");
    for limits in [
        ArchiveReadLimits { filename_bytes: 0, ..LIMITS },
        ArchiveReadLimits { data_bytes: 3, ..LIMITS },
    ] {
        let error = read_entry(view.enter().unwrap(), path.clone(), 0, limits).await.err().unwrap();
        assert!(error.is::<ArchiveReadLimitExceeded>());
    }
    for offset in [u64::MAX, u64::MAX - PKG_HEADER_SIZE as u64, bytes.len() as u64] {
        assert!(read_entry(view.enter().unwrap(), path.clone(), offset, LIMITS).await.is_err());
    }
    // Truncated payload and corrupt package/entry headers are never open-only failures.
    let mut bad_package_magic = bytes.clone();
    bad_package_magic[0] ^= 1;
    let mut bad_entry_magic = bytes.clone();
    bad_entry_magic[4] ^= 1;
    for invalid in [bytes[..bytes.len() - 1].to_vec(), bad_package_magic, bad_entry_magic] {
        std::fs::write(&path, invalid).unwrap();
        let error = read_entry(view.enter().unwrap(), path.clone(), 0, LIMITS).await.err().unwrap();
        assert!(!error.is::<ArchiveReadNotStarted>());
    }
    let mut oversized = bytes[..12].to_vec();
    oversized[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    std::fs::write(&path, oversized).unwrap();
    let error = read_entry(view.enter().unwrap(), path, 0, LIMITS).await.err().unwrap();
    assert!(
        error.is::<ArchiveReadLimitExceeded>(),
        "header bounds must precede missing filename/body reads"
    );
    assert_eq!(domain.outstanding(), 0);
}

#[tokio::test]
async fn native_range_enforces_cap_overflow_and_exact_output() {
    let (dir, _db, domain, view) = fixture();
    let path = dir.path().join("range.pack");
    let bytes = vec![37; ARCHIVE_RANGE_MAX_BYTES + 2];
    std::fs::write(&path, &bytes).unwrap();
    let full = read_range(view.enter().unwrap(), path.clone(), 1, ARCHIVE_RANGE_MAX_BYTES as u32)
        .await
        .unwrap();
    assert_eq!(full, bytes[1..=ARCHIVE_RANGE_MAX_BYTES]);
    assert_eq!(
        read_range(view.enter().unwrap(), path.clone(), bytes.len() as u64 - 1, 20).await.unwrap(),
        vec![37]
    );
    assert!(read_range(view.enter().unwrap(), path.clone(), 0, 0).await.unwrap().is_empty());
    assert!(read_range(view.enter().unwrap(), path.clone(), bytes.len() as u64 + 1, 10)
        .await
        .unwrap()
        .is_empty());
    let absent = dir.path().join("absent");
    let error = read_range(view.enter().unwrap(), absent, 0, ARCHIVE_RANGE_MAX_BYTES as u32 + 1)
        .await
        .unwrap_err();
    assert!(error.is::<ArchiveReadLimitExceeded>(), "range cap must precede open");
    assert!(read_range(view.enter().unwrap(), path, u64::MAX, 1).await.is_err());
    assert_eq!(domain.outstanding(), 0);
}

#[tokio::test]
async fn native_loose_preserves_bounds_and_open_only_errors() {
    let (dir, _db, domain, view) = fixture();
    let path = dir.path().join("body");
    std::fs::write(&path, b"abcd").unwrap();
    assert_eq!(read_loose(view.enter().unwrap(), path.clone(), LIMITS).await.unwrap(), b"abcd");
    let error = read_loose(
        view.enter().unwrap(),
        path.clone(),
        ArchiveReadLimits { data_bytes: 3, ..LIMITS },
    )
    .await
    .unwrap_err();
    assert!(error.is::<ArchiveReadLimitExceeded>());
    std::fs::write(&path, b"").unwrap();
    assert!(read_loose(view.enter().unwrap(), path.clone(), LIMITS).await.is_err());
    std::fs::remove_file(&path).unwrap();
    let error = read_loose(view.enter().unwrap(), path, LIMITS).await.unwrap_err();
    assert!(error.downcast_ref::<ArchiveReadNotStarted>().unwrap().is_not_found());
    assert_eq!(domain.outstanding(), 0);
}

#[test]
fn native_loose_same_fd_growth_truncation_and_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("body");
    for bytes in [b"abcde".as_slice(), b"ab".as_slice()] {
        std::fs::write(&path, b"abcd").unwrap();
        let mut file = File::open(&path).unwrap();
        let expected = file.metadata().unwrap().len();
        std::fs::write(&path, bytes).unwrap();
        assert!(read_loose_opened(&mut file, expected, LIMITS).is_err());
    }
    std::fs::write(&path, b"abcd").unwrap();
    let mut file = File::open(&path).unwrap();
    let expected = file.metadata().unwrap().len();
    std::fs::rename(&path, dir.path().join("old")).unwrap();
    std::fs::write(&path, vec![0; 100]).unwrap();
    assert_eq!(read_loose_opened(&mut file, expected, LIMITS).unwrap(), b"abcd");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_native_read_observer_retains_provider_and_actual_file_owner() {
    let (dir, db, domain, view) = fixture();
    let path = dir.path().join("body");
    std::fs::write(&path, b"abcd").unwrap();
    let weak = Arc::downgrade(&db);
    let operation = view.enter().unwrap();
    let (entered_send, entered_receive) = tokio::sync::oneshot::channel();
    let (release_send, release_receive) = std::sync::mpsc::channel();
    let (read_send, read_receive) = tokio::sync::oneshot::channel();
    let observer = tokio::spawn(read_owned(operation, path, move |file| {
        let _ = entered_send.send(());
        release_receive.recv_timeout(Duration::from_secs(20)).unwrap();
        let mut bytes = [0; 4];
        file.read_exact(&mut bytes)?;
        let _ = read_send.send(bytes);
        Ok(())
    }));
    tokio::time::timeout(Duration::from_secs(20), entered_receive).await.unwrap().unwrap();
    observer.abort();
    let cancelled = observer.await.unwrap_err().is_cancelled();
    drop(view);
    drop(db);
    let closed = domain.close(0).unwrap();
    let pinned = weak.upgrade().is_some();
    let outstanding = domain.outstanding();
    let mut wait = Box::pin(closed.wait());
    let pending = futures::poll!(&mut wait).is_pending();
    drop(wait);
    // Unconditionally release the native owner before asserting observations.
    release_send.send(()).unwrap();
    let bytes = tokio::time::timeout(Duration::from_secs(20), read_receive).await.unwrap().unwrap();
    tokio::time::timeout(Duration::from_secs(20), closed.wait()).await.unwrap();
    assert!(cancelled && pinned && pending);
    assert_eq!(outstanding, 1);
    assert_eq!(bytes, *b"abcd");
    assert!(weak.upgrade().is_none());
    assert!(!closed.recovery_required(), "read-only observer cancellation latched recovery");
}

#[test]
fn queued_native_read_checks_recovery_in_actual_blocking_owner() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let (dir, _db, domain, view) = fixture();
        let (entered_send, entered_receive) = tokio::sync::oneshot::channel();
        let (release_send, release_receive) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            let _ = entered_send.send(());
            release_receive.recv_timeout(Duration::from_secs(20)).unwrap();
        });
        tokio::time::timeout(Duration::from_secs(20), entered_receive).await.unwrap().unwrap();
        let parent = view.enter().unwrap();
        let mut read =
            Box::pin(read_loose(view.enter().unwrap(), dir.path().join("absent"), LIMITS));
        let pending = futures::poll!(&mut read).is_pending();
        // Existing failure handoff is the production latch, not a test-only setter.
        drop(parent.child().handoff(()));
        drop(parent);
        release_send.send(()).unwrap();
        blocker.await.unwrap();
        let error = read.await.unwrap_err();
        assert!(pending);
        assert_eq!(
            error.downcast_ref::<ArchiveContextError>(),
            Some(&ArchiveContextError::RecoveryRequired(0))
        );
        assert!(!error.is::<ArchiveReadNotStarted>(), "context refusal became an open-only error");
        assert_eq!(domain.outstanding(), 0);
    });
}

#[tokio::test]
async fn native_read_panic_releases_owner_without_mutation_latch() {
    let (dir, _db, domain, view) = fixture();
    let path = dir.path().join("body");
    std::fs::write(&path, b"abcd").unwrap();
    let result: Result<()> =
        read_owned(view.enter().unwrap(), path, |_| panic!("controlled native reader panic")).await;
    assert!(result.is_err());
    assert_eq!(domain.outstanding(), 0);
    assert!(!domain.recovery_required());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn started_native_read_finishes_after_recovery_latch() {
    let (dir, db, domain, view) = fixture();
    let path = dir.path().join("body");
    std::fs::write(&path, b"abcd").unwrap();
    let parent = view.enter().unwrap();
    let (entered_send, entered_receive) = tokio::sync::oneshot::channel();
    let (release_send, release_receive) = std::sync::mpsc::channel();
    let observer = tokio::spawn(read_owned(view.enter().unwrap(), path, move |file| {
        let _ = entered_send.send(());
        release_receive.recv_timeout(Duration::from_secs(20)).unwrap();
        let mut bytes = [0; 4];
        file.read_exact(&mut bytes)?;
        Ok(bytes)
    }));
    tokio::time::timeout(Duration::from_secs(20), entered_receive).await.unwrap().unwrap();
    drop(parent.child().handoff(()));
    drop(parent);
    let failed = domain.recovery_required();
    let retained = domain.outstanding();
    drop(view);
    let weak = Arc::downgrade(&db);
    drop(db);
    let pinned = weak.upgrade().is_some();
    release_send.send(()).unwrap();
    let result =
        tokio::time::timeout(Duration::from_secs(20), observer).await.unwrap().unwrap().unwrap();
    assert!(failed && pinned);
    assert_eq!(retained, 1);
    assert_eq!(result, *b"abcd");
    assert_eq!(domain.outstanding(), 0);
    assert!(weak.upgrade().is_none());
}
