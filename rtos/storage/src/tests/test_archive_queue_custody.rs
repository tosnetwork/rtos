// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{
    archives::io_owners::ArchiveIoOwners,
    db::rocksdb::{AccessType, RocksDb},
    tests::utils::create_block_handle_storage,
};
use std::time::Duration;

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
