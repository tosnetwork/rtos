// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::db::rocksdb::AccessType;
use std::{fs::File, io::Write, sync::Weak, time::Duration};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

fn fixture() -> (tempfile::TempDir, Arc<RocksDb>, Arc<ArchiveDomain>, ArchiveView) {
    let dir = tempfile::tempdir().unwrap();
    let db = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite).unwrap();
    let domain = ArchiveDomain::new();
    let view = db.bind_archive_domain(domain.clone()).unwrap().view().unwrap();
    (dir, db, domain, view)
}
fn assert_send<T: Send>() {}

type DropObservations = Arc<Mutex<Vec<(usize, bool, bool)>>>;
struct Payload {
    writer: OwnedMutexGuard<Option<File>>,
    domain: Arc<ArchiveDomain>,
    provider: Weak<RocksDb>,
    dropped: DropObservations,
}
impl Drop for Payload {
    fn drop(&mut self) {
        // Close the operation-owned test file before the custody ticket drops.
        drop(self.writer.take());
        self.dropped.lock().unwrap().push((
            self.domain.outstanding(),
            self.domain.recovery_required(),
            self.provider.upgrade().is_some(),
        ));
    }
}
async fn payload(
    domain: Arc<ArchiveDomain>,
    db: &Arc<RocksDb>,
    observations: DropObservations,
) -> Payload {
    let writer = Arc::new(AsyncMutex::new(Some(tempfile::tempfile().unwrap()))).lock_owned().await;
    Payload { writer, domain, provider: Arc::downgrade(db), dropped: observations }
}
fn native_write(mut value: Payload, custody: NativeCustody) -> NativeHandoff<Payload> {
    value.writer.as_mut().unwrap().write_all(b"owned archive context fixture").unwrap();
    value.writer.as_ref().unwrap().sync_data().unwrap();
    custody.handoff(value)
}

#[test]
fn provider_binding_uses_actual_once_lock_winner() {
    let dir = tempfile::tempdir().unwrap();
    let db = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite).unwrap();
    let domains = [ArchiveDomain::new(), ArchiveDomain::new()];
    let ready = Arc::new(std::sync::Barrier::new(3));
    let workers: Vec<_> = domains
        .iter()
        .map(|domain| {
            let domain = domain.clone();
            let db = db.clone();
            let ready = ready.clone();
            std::thread::spawn(move || {
                ready.wait();
                db.bind_archive_domain(domain)
            })
        })
        .collect();
    ready.wait();
    let results: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    let winner = results.iter().position(|r| r.is_ok()).unwrap();
    assert!(db.bind_archive_domain(domains[winner].clone()).is_ok());
    let error = db.bind_archive_domain(domains[1 - winner].clone()).err().unwrap();
    assert_eq!(
        error.downcast_ref::<ArchiveContextError>(),
        Some(&ArchiveContextError::BindingConflict)
    );
    let view = results[winner].as_ref().unwrap().view().unwrap();
    domains[winner].close(view.epoch()).unwrap();
    assert!(view.enter().is_err());
    assert_eq!(domains[1 - winner].outstanding(), 0);
}

#[test]
fn provider_modes_and_native_alias_lock_are_respected() {
    let (dir, db, domain, _view) = fixture();
    let readonly = RocksDb::new(dir.path(), "db", None, AccessType::ReadOnly).unwrap();
    let error = readonly.bind_archive_domain(domain).err().unwrap();
    assert_eq!(
        error.downcast_ref::<ArchiveContextError>(),
        Some(&ArchiveContextError::ReadOnlyProvider)
    );
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(dir.path().join("db"), dir.path().join("alias")).unwrap();
        assert!(
            RocksDb::new(dir.path(), "alias", None, AccessType::ReadWrite).is_err(),
            "native writable alias unexpectedly obtained a second provider"
        );
    }
    drop(readonly);
    drop(db);
}

#[tokio::test]
async fn shared_epoch_providers_drain_inherited_children_after_close() {
    let (dir, db, domain, view) = fixture();
    let epoch_db = RocksDb::new(dir.path(), "epoch", None, AccessType::ReadWrite).unwrap();
    let epoch_view = epoch_db.bind_archive_domain(domain.clone()).unwrap().view().unwrap();
    let parent = view.enter().unwrap();
    let other = epoch_view.enter().unwrap();
    let closed = domain.close(view.epoch()).unwrap();
    let child = parent.child();
    assert_eq!(domain.outstanding(), 3);
    assert!(view.enter().is_err());
    assert!(epoch_view.enter().is_err());
    assert!(domain.publish_next_epoch(0).is_err());
    drop(parent);
    drop(other);
    assert_eq!(domain.outstanding(), 1);
    let mut wait = Box::pin(closed.wait());
    assert!(futures::poll!(&mut wait).is_pending());
    drop(wait);
    let repeated = domain.close(0).unwrap();
    let mut wait = Box::pin(repeated.wait());
    assert!(futures::poll!(&mut wait).is_pending());
    drop(wait);
    drop(child);
    closed.wait().await;
    repeated.wait().await;
    assert_eq!(domain.outstanding(), 0);
    drop(db);
}

#[tokio::test]
async fn immutable_views_refuse_stale_epochs_and_preserve_typed_errors() {
    let (_dir, db, domain, old) = fixture();
    let closed = domain.close(0).unwrap();
    closed.wait().await;
    let error = old.enter().err().unwrap().context("archive caller context");
    assert_eq!(error.downcast_ref::<ArchiveContextError>(), Some(&ArchiveContextError::Closed(0)));
    assert!(domain.publish_next_epoch(1).is_err());
    domain.publish_next_epoch(0).unwrap();
    let error = old.enter().err().expect("stale archive view unexpectedly regained admission");
    assert_eq!(
        error.downcast_ref::<ArchiveContextError>(),
        Some(&ArchiveContextError::Stale { expected: 0, current: 1 })
    );
    let current = db.bind_archive_domain(domain.clone()).unwrap().view().unwrap();
    assert_eq!(current.epoch(), 1);
    let current_operation = current.enter().unwrap();
    let error = old.inherit(&current_operation).err().expect("stale target view inherited current authority");
    assert_eq!(error.downcast_ref::<ArchiveContextError>(), Some(&ArchiveContextError::Stale { expected: 0, current: 1 }));
    drop(current_operation);
    assert!(current.enter().is_ok());
    assert!(domain.close(0).is_err());
    assert!(domain.publish_next_epoch(1).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn completed_native_result_retains_ticket_provider_and_owned_guard() {
    assert_send::<OwnedMutexGuard<Option<File>>>();
    assert_send::<NativeHandoff<Payload>>();
    let (_dir, db, domain, view) = fixture();
    let weak = Arc::downgrade(&db);
    let parent = view.enter().unwrap();
    let native = parent.child();
    let observations = DropObservations::default();
    let value = payload(domain.clone(), &db, observations.clone()).await;
    let result = tokio::task::spawn_blocking(move || native_write(value, native)).await.unwrap();
    drop(parent);
    drop(view);
    drop(db);
    let closed = domain.close(0).unwrap();
    assert!(weak.upgrade().is_some());
    assert_eq!(domain.outstanding(), 1, "completed native result lost its custody ticket");
    let mut wait = Box::pin(closed.wait());
    assert!(futures::poll!(&mut wait).is_pending());
    drop(wait);
    let inspected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        result
            .consume(|value| {
                assert_eq!(value.writer.as_ref().unwrap().metadata().unwrap().len(), 29);
                assert_eq!(domain.outstanding(), 1, "metadata callback lost native result custody");
                Ok(())
            })
            .unwrap();
    }));
    closed.wait().await;
    inspected.unwrap_or_else(|p| std::panic::resume_unwind(p));
    assert_eq!(*observations.lock().unwrap(), vec![(1, false, true)]);
    assert!(weak.upgrade().is_none());
    assert!(!closed.recovery_required());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unconsumed_error_and_panic_handoffs_latch_before_payload_drop() {
    for mode in ["unconsumed", "error", "panic"] {
        let (_dir, db, domain, view) = fixture();
        let parent = view.enter().unwrap();
        let native = parent.child();
        let observations = DropObservations::default();
        let value = payload(domain.clone(), &db, observations.clone()).await;
        let result =
            tokio::task::spawn_blocking(move || native_write(value, native)).await.unwrap();
        drop(parent);
        drop(view);
        drop(db);
        let closed = domain.close(0).unwrap();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match mode {
            "unconsumed" => {
                drop(result);
                Ok(())
            }
            "error" => result.consume(|_| Err(rtos_block::error!("controlled metadata error"))),
            _ => result.consume(|_| panic!("controlled metadata callback panic")),
        }));
        closed.wait().await;
        assert_eq!(outcome.is_err(), mode == "panic");
        if let Ok(result) = outcome {
            assert_eq!(result.is_err(), mode == "error");
        }
        assert!(closed.recovery_required(), "failed native handoff did not latch recovery");
        assert_eq!(
            *observations.lock().unwrap(),
            vec![(1, true, true)],
            "native payload dropped before failure latch or after custody release"
        );
        assert_eq!(domain.outstanding(), 0);
        assert!(domain.publish_next_epoch(0).is_err());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_observer_does_not_release_held_native_owner() {
    let (_dir, db, domain, view) = fixture();
    let parent = view.enter().unwrap();
    let native = parent.child();
    let observations = DropObservations::default();
    let value = payload(domain.clone(), &db, observations.clone()).await;
    let (entered_send, entered_receive) = tokio::sync::oneshot::channel();
    let (release_send, release_receive) = std::sync::mpsc::channel();
    let blocking = tokio::task::spawn_blocking(move || {
        entered_send.send(()).unwrap();
        release_receive.recv_timeout(Duration::from_secs(20)).unwrap();
        native_write(value, native)
    });
    let observer = tokio::spawn(async move { blocking.await });
    tokio::time::timeout(Duration::from_secs(20), entered_receive).await.unwrap().unwrap();
    observer.abort();
    let cancelled = observer.await.err().expect("observer must be cancelled").is_cancelled();
    drop(parent);
    drop(view);
    drop(db);
    let closed = domain.close(0).unwrap();
    let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert!(cancelled);
        assert_eq!(domain.outstanding(), 1, "cancelled observer released the actual native owner");
    }));
    let mut wait = Box::pin(closed.wait());
    let pending = futures::poll!(&mut wait).is_pending();
    drop(wait);
    release_send.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(20), closed.wait()).await.unwrap();
    checked.unwrap_or_else(|p| std::panic::resume_unwind(p));
    assert!(pending);
    assert!(closed.recovery_required());
    assert_eq!(*observations.lock().unwrap(), vec![(1, true, true)]);
    assert_eq!(domain.outstanding(), 0);
}


#[tokio::test]
async fn checked_inheritance_pins_destination_after_closing() {
    let (dir, db, domain, view) = fixture();
    let epoch_db = RocksDb::new(dir.path(), "inherited-epoch", None, AccessType::ReadWrite).unwrap();
    let destination = epoch_db.bind_archive_domain(domain.clone()).unwrap();
    let weak = Arc::downgrade(&epoch_db);
    let parent = view.enter().unwrap();
    let closed = domain.close(0).unwrap();
    let inherited = parent.inherit(&destination).unwrap();
    assert_eq!(inherited.view().epoch(), 0);
    assert!(inherited.view().enter().is_err(), "inherited view reopened root admission");
    let native = inherited.start_read().unwrap();
    drop(destination);
    drop(epoch_db);
    drop(parent);
    drop(view);
    drop(db);
    assert!(weak.upgrade().is_some(), "inherited owner lost destination provider");
    assert_eq!(domain.outstanding(), 1);
    let mut wait = Box::pin(closed.wait());
    assert!(futures::poll!(&mut wait).is_pending());
    drop(wait);
    drop(native);
    closed.wait().await;
    assert!(weak.upgrade().is_none());
}

#[test]
fn checked_inheritance_rejects_other_domain_and_failure_before_read_start() {
    let (_dir, db, domain, view) = fixture();
    let (_other_dir, other_db, other_domain, _other_view) = fixture();
    let parent = view.enter().unwrap();
    let destination = db.bind_archive_domain(domain.clone()).unwrap();
    let other = other_db.bind_archive_domain(other_domain.clone()).unwrap();
    let error = parent.inherit(&other).err().expect("cross-domain inheritance admitted");
    assert_eq!(error.downcast_ref::<ArchiveContextError>(), Some(&ArchiveContextError::BindingConflict));
    assert_eq!(other_domain.outstanding(), 0);
    let queued = parent.inherit(&destination).unwrap();
    let started = parent.inherit(&destination).unwrap().start_read().unwrap();
    domain.latch_failure();
    let error = queued.start_read().err().expect("read started after recovery latch");
    assert_eq!(error.downcast_ref::<ArchiveContextError>(), Some(&ArchiveContextError::RecoveryRequired(0)));
    let error = parent.inherit(&destination).err().expect("inheritance ignored recovery latch");
    assert_eq!(error.downcast_ref::<ArchiveContextError>(), Some(&ArchiveContextError::RecoveryRequired(0)));
    assert_eq!(domain.outstanding(), 2, "started read custody was revoked by failure");
    drop(parent);
    assert_eq!(domain.outstanding(), 1);
    drop(started);
    assert_eq!(domain.outstanding(), 0);
}


#[tokio::test]
async fn cached_package_and_slice_views_refuse_stale_read_authority() {
    use crate::archives::{
        archive_slice::ArchiveSlice, bounded_read::ArchiveReadLimits, package::Package,
        package_id::PackageType,
    };
    let (dir, db, domain, view) = fixture();
    let parent = view.enter().unwrap();
    let path = dir.path().join("direct.pack");
    let package = Package::open(view.clone(), &parent, path.clone(), false, true).await.unwrap();
    let original = std::fs::read(&path).unwrap();
    let slice = ArchiveSlice::new_empty(
        view.binding().clone(),
        &parent,
        Arc::new(dir.path().to_path_buf()),
        0,
        PackageType::Blocks,
        0,
        #[cfg(feature = "telemetry")]
        Arc::new(crate::StorageTelemetry::default()),
        Arc::new(crate::StorageAlloc::default()),
    )
    .await
    .unwrap();
    drop(parent);
    let closed = domain.close(0).unwrap();
    closed.wait().await;
    // Test-only publisher exercises immutable views, not production retirement.
    domain.publish_next_epoch(0).unwrap();
    let current = db.bind_archive_domain(domain.clone()).unwrap().view().unwrap().enter().unwrap();
    let expected = ArchiveContextError::Stale { expected: 0, current: 1 };
    let error = package
        .read_entry_bounded(0, ArchiveReadLimits { data_bytes: 4, filename_bytes: 4 })
        .await
        .err()
        .unwrap();
    assert_eq!(error.downcast_ref::<ArchiveContextError>(), Some(&expected));
    let error = package.read_range_in(&current, 0, 4).await.unwrap_err();
    assert_eq!(error.downcast_ref::<ArchiveContextError>(), Some(&expected));
    let error = slice.get_slice(0, 0, 4).await.unwrap_err();
    assert_eq!(error.downcast_ref::<ArchiveContextError>(), Some(&expected));
    let error = Package::open(view, &current, path.clone(), false, true).await.unwrap_err();
    assert_eq!(error.downcast_ref::<ArchiveContextError>(), Some(&expected));
    assert_eq!(std::fs::read(&path).unwrap(), original);
}
