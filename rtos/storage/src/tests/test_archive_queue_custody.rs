// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{
    archives::io_owners::ArchiveIoOwners,
    db::rocksdb::{AccessType, RocksDb},
    tests::utils::create_block_handle_storage,
};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

struct HeldCallback {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    completed: AtomicBool,
    panic_after_release: bool,
}
#[async_trait::async_trait]
impl Callback for HeldCallback {
    async fn invoke(&self, _job: StoreJob, ok: bool) {
        assert!(ok, "actual queued write failed");
        self.entered.notify_one();
        self.release.notified().await;
        if self.panic_after_release {
            panic!("controlled queue callback panic");
        }
        self.completed.store(true, Ordering::SeqCst);
    }
}
async fn entered(callback: &HeldCallback) {
    tokio::time::timeout(Duration::from_secs(20), callback.entered.notified())
        .await
        .expect("callback did not enter");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn work_ticket_covers_actual_write_and_callback_after_parent_drop() {
    let dir = tempfile::tempdir().unwrap();
    let db = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite).unwrap();
    let (storage, handle_db) = create_block_handle_storage(db);
    let handle =
        storage.create_handle(BlockIdExt::default(), BlockMeta::default(), None).unwrap().unwrap();
    storage.sync_pending().await.unwrap();
    handle.set_archived();
    let owners = ArchiveIoOwners::default();
    let parent = owners.enter().unwrap();
    let callback = Arc::new(HeldCallback {
        entered: Default::default(),
        release: Default::default(),
        completed: AtomicBool::new(false),
        panic_after_release: false,
    });
    storage
        .save_handle_with_archive_custody(&handle, Some(callback.clone()), parent.clone())
        .unwrap();
    entered(&callback).await;
    let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_eq!(
            handle_db.try_get_raw(handle.id().root_hash().as_slice()).unwrap().unwrap().as_ref(),
            handle.serialize().as_slice()
        );
        drop(parent);
        owners.close();
        assert_eq!(owners.outstanding(), 1, "queued Work lost its custody ticket");
    }));
    callback.release.notify_one();
    tokio::time::timeout(Duration::from_secs(20), owners.wait()).await.unwrap();
    storage.sync_pending().await.unwrap();
    assert!(callback.completed.load(Ordering::SeqCst));
    run.unwrap_or_else(|p| std::panic::resume_unwind(p));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn barrier_ticket_survives_cancelled_waiter_at_real_wal_boundary() {
    for fail in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let db = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite).unwrap();
        let (storage, _) = create_block_handle_storage(db);
        let storage = Arc::new(storage);
        let handle = storage
            .create_handle(BlockIdExt::default(), BlockMeta::default(), None)
            .unwrap()
            .unwrap();
        storage.sync_pending().await.unwrap();
        handle.set_archived();
        storage.save_handle(&handle, None).unwrap();
        let owners = ArchiveIoOwners::default();
        let ticket = owners.enter().unwrap();
        let (entered_send, entered_receive) = std::sync::mpsc::channel();
        let (release_send, release_receive) = std::sync::mpsc::channel();
        let release_receive = std::sync::Mutex::new(release_receive);
        let visits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls = visits.clone();
        let observer: crate::durability::SyncObservation = Some(Arc::new(move |point, _path| {
            assert_eq!(point, crate::durability::SyncPoint::Wal);
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                entered_send.send(()).unwrap();
                release_receive.lock().unwrap().recv_timeout(Duration::from_secs(20)).unwrap();
            }
            if fail {
                return Err(error!("controlled WAL boundary refusal"));
            }
            Ok(())
        }));
        let caller_storage = storage.clone();
        let caller = tokio::spawn(async move {
            caller_storage.sync_pending_observed_with_archive_custody(observer, ticket).await
        });
        entered_receive.recv_timeout(Duration::from_secs(20)).unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owners.close();
            assert_eq!(owners.outstanding(), 1, "queued Barrier lost its custody ticket");
        }));
        release_send.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(20), owners.wait()).await.unwrap();
        assert_eq!(storage.sync_pending().await.is_err(), fail);
        assert_eq!(visits.load(Ordering::SeqCst), if fail { 1 } else { 3 });
        run.unwrap_or_else(|p| std::panic::resume_unwind(p));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn callback_panic_drops_actual_work_and_queued_barrier_custody() {
    let dir = tempfile::tempdir().unwrap();
    let db = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite).unwrap();
    let (storage, _) = create_block_handle_storage(db);
    let handle =
        storage.create_handle(BlockIdExt::default(), BlockMeta::default(), None).unwrap().unwrap();
    storage.sync_pending().await.unwrap();
    let owners = ArchiveIoOwners::default();
    let parent = owners.enter().unwrap();
    let callback = Arc::new(HeldCallback {
        entered: Default::default(),
        release: Default::default(),
        completed: AtomicBool::new(false),
        panic_after_release: true,
    });
    storage
        .save_handle_with_archive_custody(&handle, Some(callback.clone()), parent.clone())
        .unwrap();
    entered(&callback).await;
    let mut barrier =
        Box::pin(storage.sync_pending_observed_with_archive_custody(None, parent.clone()));
    assert!(futures::poll!(&mut barrier).is_pending());
    drop(parent);
    owners.close();
    let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_eq!(owners.outstanding(), 2, "queued panic path lost custody")
    }));
    callback.release.notify_one();
    assert!(tokio::time::timeout(Duration::from_secs(20), barrier).await.unwrap().is_err());
    tokio::time::timeout(Duration::from_secs(20), owners.wait()).await.unwrap();
    assert_eq!(owners.outstanding(), 0);
    assert!(storage
        .save_handle_with_archive_custody(
            &handle,
            None,
            ArchiveIoOwners::default().enter().unwrap()
        )
        .is_err());
    run.unwrap_or_else(|p| std::panic::resume_unwind(p));
}

#[tokio::test]
async fn no_cache_and_enqueue_failure_release_supplied_ticket() {
    let dir = tempfile::tempdir().unwrap();
    let db = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite).unwrap();
    let (mut storage, handle_db) = create_block_handle_storage(db);
    let handle =
        storage.create_handle(BlockIdExt::default(), BlockMeta::default(), None).unwrap().unwrap();
    storage.sync_pending().await.unwrap();
    let owners = ArchiveIoOwners::default();
    storage.set_no_cache();
    handle.set_archived();
    storage.save_handle_with_archive_custody(&handle, None, owners.enter().unwrap()).unwrap();
    assert_eq!(owners.outstanding(), 0);
    assert_eq!(
        handle_db.try_get_raw(handle.id().root_hash().as_slice()).unwrap().unwrap().as_ref(),
        handle.serialize().as_slice()
    );
    storage.no_cache = false;
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    drop(receiver);
    storage.storer = sender;
    assert!(storage
        .save_handle_with_archive_custody(&handle, None, owners.enter().unwrap())
        .is_err());
    assert_eq!(owners.outstanding(), 0);
    assert!(storage
        .sync_pending_observed_with_archive_custody(None, owners.enter().unwrap())
        .await
        .is_err());
    owners.wait().await;
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the explicitly armed private WAL sync harness"]
async fn barrier_native_wal_failure_retains_custody_after_cancel() {
    let db_path = std::path::PathBuf::from(std::env::var_os("RTOS_QUEUE_DB").unwrap());
    let arm = std::path::PathBuf::from(std::env::var_os("RTOS_QUEUE_ARM").unwrap());
    let case = std::env::var("RTOS_QUEUE_CASE").unwrap();
    assert!(matches!(case.as_str(), "fault" | "control" | "wrong-path" | "no-arm"));
    assert!(!arm.exists());
    assert!(!db_path.exists());
    let db = RocksDb::new(
        db_path.parent().unwrap(),
        db_path.file_name().unwrap().to_str().unwrap(),
        None,
        AccessType::ReadWrite,
    )
    .unwrap();
    let (storage, handle_db) = create_block_handle_storage(db);
    let storage = Arc::new(storage);
    let handle =
        storage.create_handle(BlockIdExt::default(), BlockMeta::default(), None).unwrap().unwrap();
    storage.sync_pending().await.unwrap();
    handle.set_archived();
    let callback = Arc::new(HeldCallback {
        entered: Default::default(),
        release: Default::default(),
        completed: AtomicBool::new(false),
        panic_after_release: false,
    });
    storage.save_handle(&handle, Some(callback.clone())).unwrap();
    entered(&callback).await;
    callback.release.notify_one();
    assert_eq!(
        handle_db.try_get_raw(handle.id().root_hash().as_slice()).unwrap().unwrap().as_ref(),
        handle.serialize().as_slice()
    );
    let owners = ArchiveIoOwners::default();
    let ticket = owners.enter().unwrap();
    let (entered_send, entered_receive) = std::sync::mpsc::channel();
    let (release_send, release_receive) = std::sync::mpsc::channel();
    let release_receive = std::sync::Mutex::new(release_receive);
    let visits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls = visits.clone();
    let observer: crate::durability::SyncObservation = Some(Arc::new(move |point, path| {
        assert_eq!(point, crate::durability::SyncPoint::Wal);
        assert_eq!(path, db_path.as_path());
        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
            entered_send.send(()).unwrap();
            release_receive.lock().unwrap().recv_timeout(Duration::from_secs(30)).unwrap();
        }
        // All failures in this test come from the actual native sync call.
        Ok(())
    }));
    let caller_storage = storage.clone();
    let caller = tokio::spawn(async move {
        caller_storage.sync_pending_observed_with_archive_custody(observer, ticket).await
    });
    entered_receive.recv_timeout(Duration::from_secs(30)).unwrap();
    caller.abort();
    let cancelled = caller.await.unwrap_err().is_cancelled();
    let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert!(cancelled);
        owners.close();
        assert_eq!(
            owners.outstanding(),
            1,
            "native Barrier lost custody after observer cancellation"
        );
        assert!(callback.completed.load(Ordering::SeqCst));
        if case != "no-arm" {
            std::fs::write(&arm, b"private WAL sync test").unwrap();
        }
    }));
    eprintln!("QUEUE_BARRIER_RELEASE");
    release_send.send(()).unwrap();
    let drained = tokio::time::timeout(Duration::from_secs(30), owners.wait()).await;
    if arm.exists() {
        std::fs::remove_file(&arm).unwrap();
    }
    eprintln!("QUEUE_BARRIER_DRAINED");
    drained.unwrap();
    let sticky = storage.sync_pending().await;
    assert_eq!(owners.outstanding(), 0);
    run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    assert_eq!(sticky.is_err(), case == "fault", "native WAL failure must remain sticky");
    assert_eq!(visits.load(Ordering::SeqCst), if case == "fault" { 1 } else { 3 });
}

async fn verify_writer_close_releases_provider(panic_after_release: bool) {
    let dir = tempfile::tempdir().unwrap();
    let db = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite).unwrap();
    let provider = Arc::downgrade(&db);
    let (storage, handle_db) = create_block_handle_storage(db);
    let handle = storage
        .create_handle(BlockIdExt::default(), BlockMeta::default(), None)
        .unwrap()
        .unwrap();
    storage.sync_pending().await.unwrap();
    let callback = Arc::new(HeldCallback {
        entered: Default::default(),
        release: Default::default(),
        completed: AtomicBool::new(false),
        panic_after_release,
    });
    handle.set_archived();
    storage.save_handle(&handle, Some(callback.clone())).unwrap();
    entered(&callback).await;
    drop(handle_db);
    let mut closing = Box::pin(storage.close_and_wait());
    std::future::poll_fn(|cx| {
        assert!(
            std::future::Future::poll(closing.as_mut(), cx).is_pending(),
            "close returned before the actual writer callback exited"
        );
        std::task::Poll::Ready(())
    })
    .await;
    assert!(provider.upgrade().is_some());
    assert!(RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite).is_err());
    callback.release.notify_one();
    let closed = tokio::time::timeout(Duration::from_secs(20), closing).await.unwrap();
    assert_eq!(closed.is_err(), panic_after_release);
    if panic_after_release {
        let diagnostic = format!("{:#}", closed.unwrap_err());
        assert!(diagnostic.contains("Handle writer failed during durability barrier"));
        assert!(diagnostic.contains("Handle writer failed while closing"));
    }
    assert!(provider.upgrade().is_none(), "joined writer retained its provider");
    let reopened = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite).unwrap();
    let stored = BlockHandleDb::with_db(reopened, "block_handles", false).unwrap();
    assert_eq!(
        stored.try_get_raw(handle.id().root_hash().as_slice()).unwrap().unwrap().as_ref(),
        handle.serialize().as_slice()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_joins_actual_writer_before_provider_reopen() {
    verify_writer_close_releases_provider(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_reports_writer_panic_after_provider_release() {
    verify_writer_close_releases_provider(true).await;
}

async fn verify_close_at_actual_writer_exit(cancel_observer: bool) {
    let dir = tempfile::tempdir().unwrap();
    let db = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite).unwrap();
    let provider = Arc::downgrade(&db);
    let (storage, handle_db) = create_block_handle_storage(db);
    let completion = storage.writer_completion_for_test();
    let (mut entered, release) = storage.hold_writer_exit_for_test();
    drop(handle_db);
    let mut closing = Box::pin(storage.close_and_wait());
    let mut early = None;
    let arrival = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            tokio::select! {
                result = &mut closing, if early.is_none() => early = Some(result),
                arrived = &mut entered => break arrived,
            }
        }
    })
    .await;
    let arrived = matches!(arrival, Ok(Ok(())));
    let pending = if arrived && early.is_none() {
        std::future::poll_fn(|cx| {
            let pending = match std::future::Future::poll(closing.as_mut(), cx) {
                std::task::Poll::Pending => true,
                std::task::Poll::Ready(result) => {
                    early = Some(result);
                    false
                }
            };
            std::task::Poll::Ready(pending)
        })
        .await
    } else {
        false
    };
    let closing = if cancel_observer {
        drop(closing);
        None
    } else {
        Some(closing)
    };
    let held = provider.upgrade().is_some();
    let excluded = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite).is_err();
    // Release and join independently before propagating any observation failure.
    let released = release.send(()).is_ok();
    let completed = tokio::time::timeout(Duration::from_secs(20), completion).await;
    let gone = provider.upgrade().is_none();
    let closed = if let Some(closing) = closing {
        match early {
            Some(result) => Some(Ok(result)),
            None => Some(tokio::time::timeout(Duration::from_secs(20), closing).await),
        }
    } else {
        None
    };
    assert!(arrived, "actual writer did not reach post-drain exit hook");
    assert!(released);
    assert!(matches!(completed, Ok(Ok(()))), "independent writer join failed");
    assert!(gone, "actual joined writer retained its provider");
    assert!(pending, "close returned before actual writer exit");
    assert!(held && excluded, "writer exit boundary lost provider exclusion");
    if let Some(closed) = closed {
        closed.unwrap().unwrap();
    }
    RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_waits_at_actual_post_drain_writer_exit() {
    verify_close_at_actual_writer_exit(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_close_observer_retains_writer_until_actual_exit() {
    verify_close_at_actual_writer_exit(true).await;
}
