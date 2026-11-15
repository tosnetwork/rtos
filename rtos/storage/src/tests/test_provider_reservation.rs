// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::db::rocksdb::{destroy_rocks_db, AccessType, RocksDb};
use std::{sync::Arc, time::Duration};

fn writable(path: &Path) -> rtos_block::Result<Arc<RocksDb>> {
    RocksDb::new(
        path.parent().unwrap(),
        path.file_name().unwrap().to_str().unwrap(),
        None,
        AccessType::ReadWrite,
    )
}
fn busy<T>(result: rtos_block::Result<T>) -> bool {
    result.err().is_some_and(|error| {
        matches!(error.downcast_ref::<ReservationError>(), Some(ReservationError::Busy(_)))
    })
}

#[cfg(unix)]
#[test]
fn simultaneous_alias_opens_have_one_owner_and_reopen_after_close() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("db");
    let alias = dir.path().join("alias");
    fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    let start = Arc::new(std::sync::Barrier::new(3));
    let handles: Vec<_> = [real.clone(), alias.clone()]
        .into_iter()
        .map(|path| {
            let start = start.clone();
            std::thread::spawn(move || {
                start.wait();
                writable(&path)
            })
        })
        .collect();
    start.wait();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let winners = results.iter().filter(|r| r.is_ok()).count();
    let losers_busy = results
        .iter()
        .filter_map(|r| r.as_ref().err())
        .all(|e| matches!(e.downcast_ref::<ReservationError>(), Some(ReservationError::Busy(_))));
    if let Some(owner) = results.iter().find_map(|r| r.as_ref().ok()) {
        owner.db().put(b"kept", b"value").unwrap();
        owner.sync_wal().unwrap();
    }
    drop(results);
    assert_eq!(winners, 1, "simultaneous writable aliases escaped exclusion");
    assert!(losers_busy);
    let reopened = writable(&alias).unwrap();
    assert_eq!(reopened.db().get(b"kept").unwrap(), Some(b"value".to_vec()));
}

#[test]
fn failed_native_open_releases_identity_for_repaired_retry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let db = writable(&path).unwrap();
    db.db().put(b"kept", b"value").unwrap();
    db.sync_wal().unwrap();
    drop(db);
    let current = path.join("CURRENT");
    let original = fs::read(&current).unwrap();
    fs::write(&current, b"not-a-manifest\n").unwrap();
    let failed = writable(&path);
    fs::write(&current, original).unwrap();
    let error = failed.err().expect("malformed CURRENT must fail in native open");
    assert!(
        error.downcast_ref::<rocksdb::Error>().is_some(),
        "failure was not from native open: {error}"
    );
    let reopened = writable(&path).unwrap();
    assert_eq!(reopened.db().get(b"kept").unwrap(), Some(b"value".to_vec()));
}

#[test]
fn static_destroy_refuses_live_provider_and_instance_destroy_releases_afterward() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let db = writable(&path).unwrap();
    db.db().put(b"kept", b"value").unwrap();
    db.sync_wal().unwrap();
    assert!(
        busy(RocksDb::destroy_db(&path)),
        "static destroy bypassed a live provider reservation"
    );
    assert_eq!(db.db().get(b"kept").unwrap(), Some(b"value".to_vec()));
    let mut db = Arc::try_unwrap(db).ok().unwrap();
    assert!(db.destroy().unwrap());
    let db = Arc::new(db);
    assert!(db.bind_archive_domain(crate::archives::context::ArchiveDomain::new()).is_err());
    drop(db);
    let reopened = writable(&path).unwrap();
    assert_eq!(reopened.db().get(b"kept").unwrap(), None);
}

#[test]
fn instance_destroy_preserves_native_owner_when_nested_provider_is_active() {
    let dir = tempfile::tempdir().unwrap();
    let parent_path = dir.path().join("db");
    let parent = writable(&parent_path).unwrap();
    parent.db().put(b"kept", b"value").unwrap();
    let child = writable(&parent_path.join("child")).unwrap();
    let mut parent = Arc::try_unwrap(parent).ok().unwrap();
    assert!(busy(parent.destroy()), "parent destruction ignored a live nested provider");
    assert_eq!(parent.db().get(b"kept").unwrap(), Some(b"value".to_vec()));
    drop(child);
    assert!(parent.destroy().unwrap());
}

#[test]
fn open_parent_then_destroy_child_conflicts_before_creation() {
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("parent");
    let child = parent.join("child");
    let held = PathIntent::reserve(normalize(&parent).unwrap(), Intent::Open).unwrap();
    let error = ProviderReservation::destroy(&child)
        .err()
        .expect("child destroy bypassed parent Open intent");
    assert!(matches!(error, ReservationError::Busy(_)));
    assert!(!parent.exists());
    drop(held);
}

#[test]
fn destroy_child_then_open_parent_conflicts_before_creation() {
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("parent");
    let child = parent.join("child");
    let held = PathIntent::reserve(normalize(&child).unwrap(), Intent::Destroy).unwrap();
    let error = ProviderReservation::open(&parent)
        .err()
        .expect("parent Open bypassed child Destroy intent");
    assert!(matches!(error, ReservationError::Busy(_)));
    assert!(!parent.exists());
    drop(held);
}

#[cfg(unix)]
#[test]
fn replacement_path_and_renamed_original_inode_both_remain_reserved() {
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join("db");
    let renamed = dir.path().join("old");
    let held = ProviderReservation::open(&original).unwrap();
    fs::rename(&original, &renamed).unwrap();
    fs::create_dir(&original).unwrap();
    fs::write(original.join("replacement"), b"preserve me").unwrap();
    assert!(busy(writable(&original)), "same reserved path accepted a replacement inode");
    assert!(busy(writable(&renamed)), "renamed original inode escaped physical exclusion");
    assert!(matches!(held.verify(), Err(ReservationError::IdentityChanged(_))));
    assert!(held.remove_directory_if_present().is_err());
    assert_eq!(fs::read(original.join("replacement")).unwrap(), b"preserve me");
    drop(held);
    let new = writable(&original).unwrap();
    drop(new);
    let old = writable(&renamed).unwrap();
    drop(old);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_cleanup_observer_retains_actual_destructive_owner() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    drop(writable(&path).unwrap());
    let (entered_send, entered_receive) = tokio::sync::oneshot::channel();
    let (release_send, release_receive) = std::sync::mpsc::channel();
    let (finished_send, finished_receive) = tokio::sync::oneshot::channel();
    CLEANUP_GATES.get_or_init(Default::default).lock().unwrap().insert(
        fs::canonicalize(&path).unwrap(),
        CleanupGate { entered: entered_send, release: release_receive, finished: finished_send },
    );
    let root = dir.path().to_str().unwrap().to_owned();
    let observer = tokio::spawn(async move { destroy_rocks_db(&root, "db").await });
    tokio::time::timeout(Duration::from_secs(20), entered_receive).await.unwrap().unwrap();
    observer.abort();
    let cancelled = observer.await.unwrap_err().is_cancelled();
    let assertions = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert!(cancelled);
        assert!(busy(writable(&path)), "cancelled cleanup observer released live exclusion");
        assert!(busy(writable(&path.join("child"))), "destructive owner allowed a nested provider");
        assert!(!path.join("child").exists());
    }));
    release_send.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(20), finished_receive).await.unwrap().unwrap();
    assertions.unwrap_or_else(|p| std::panic::resume_unwind(p));
    assert!(!path.exists());
    assert!(dir.path().exists(), "cleanup removed an ancestor directory");
    drop(writable(&path).unwrap());
}

#[tokio::test]
async fn missing_cleanup_preserves_empty_parent_and_creates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    assert!(!RocksDb::destroy_db(dir.path().join("missing")).unwrap());
    destroy_rocks_db(dir.path().to_str().unwrap(), "missing").await.unwrap();
    assert!(dir.path().exists());
    assert!(!dir.path().join("missing").exists());
}

#[test]
fn existing_reservation_and_native_open_never_create_missing_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing/db");
    assert!(ProviderReservation::open_existing(&missing).is_err());
    assert!(!dir.path().join("missing").exists());
    let empty = dir.path().join("empty");
    fs::create_dir(&empty).unwrap();
    let owner = ProviderReservation::open_existing(&empty).unwrap();
    assert!(RocksDb::open_existing_for_recovery(owner, None).is_err());
    assert_eq!(fs::read_dir(&empty).unwrap().count(), 0);
    // Failure releases the reservation without leaving a fabricated DB.
    ProviderReservation::open_existing(&empty).unwrap().verify_existing().unwrap();
    let ordinary = ProviderReservation::open(&empty).unwrap();
    assert!(RocksDb::open_existing_for_recovery(ordinary, None).is_err());
    assert_eq!(fs::read_dir(&empty).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn existing_reservation_rejects_symlinks_and_retains_exclusion() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    drop(writable(&path).unwrap());
    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    assert!(ProviderReservation::open_existing(&alias).is_err());
    let owner = ProviderReservation::open_existing(&path).unwrap();
    assert!(busy(writable(&path)));
    assert!(ProviderReservation::open_existing(&path).is_err());
    let db = RocksDb::open_existing_for_recovery(owner, None).unwrap();
    let retained = db.clone();
    drop(db);
    assert!(busy(writable(&path)));
    drop(retained);
    let owner = ProviderReservation::open_existing(&path).unwrap();
    owner.verify_existing().unwrap();
    fs::rename(&path, dir.path().join("moved")).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(owner.verify_existing().is_err());
}

#[test]
fn existing_recovery_open_preserves_legacy_families_and_pending_controls() {
    use crate::{
        archives::recovery_root::{PARTICIPANT_KEY, ROOT_KEY},
        db::rocksdb::{LAST_UNNEEDED_KEY_BLOCK, NODE_STATE_DB_NAME},
        traits::Serializable,
    };
    use rtos_block::{BlockIdExt, ShardIdent};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let mut options = rocksdb::Options::default();
    options.create_if_missing(true);
    options.create_missing_column_families(true);
    let mut names: Vec<_> = (0..100).map(|n| format!("untouched_{n}")).collect();
    names.extend([NODE_STATE_DB_NAME.to_string(), "status_db_0".to_string()]);
    let native =
        rocksdb::DBWithThreadMode::<rocksdb::MultiThreaded>::open_cf(&options, &path, &names)
            .unwrap();
    let cutoff =
        BlockIdExt::with_params(ShardIdent::masterchain(), 100, [1; 32].into(), [2; 32].into());
    native
        .put_cf(
            &native.cf_handle(NODE_STATE_DB_NAME).unwrap(),
            LAST_UNNEEDED_KEY_BLOCK,
            cutoff.serialize(),
        )
        .unwrap();
    // Clean status row permits normal legacy cleanup, so preservation here
    // proves the existing-only policy independently of pending-root refusal.
    native.put_cf(&native.cf_handle("status_db_0").unwrap(), b"SlicedMode", b"original").unwrap();
    native.flush_wal(true).unwrap();
    let identity = native.get_db_identity().unwrap();
    drop(native);
    let owner = ProviderReservation::open_existing(&path).unwrap();
    let mut cf_options = std::collections::HashMap::new();
    cf_options.insert("must_not_create".to_string(), rocksdb::Options::default());
    let db = RocksDb::open_existing_for_recovery(owner, cf_options).unwrap();
    assert_eq!(db.db().get_db_identity().unwrap(), identity);
    assert!(db.db().cf_handle("must_not_create").is_none());
    assert_eq!(
        db.db()
            .get_cf(&db.db().cf_handle("status_db_0").unwrap(), b"SlicedMode")
            .unwrap()
            .as_deref(),
        Some(b"original".as_slice())
    );
    db.db().put(ROOT_KEY, b"future-root-format").unwrap();
    db.db().put(PARTICIPANT_KEY, b"future-participant-format").unwrap();
    db.sync_wal().unwrap();
    drop(db);
    let owner = ProviderReservation::open_existing(&path).unwrap();
    let db = RocksDb::open_existing_for_recovery(owner, None).unwrap();
    assert_eq!(db.db().get(ROOT_KEY).unwrap().as_deref(), Some(b"future-root-format".as_slice()));
    assert_eq!(
        db.db().get(PARTICIPANT_KEY).unwrap().as_deref(),
        Some(b"future-participant-format".as_slice())
    );
    assert!(db.db().cf_handle("status_db_0").is_some());
    assert!(crate::archives::recovery_guard::ensure_root_controls_clear(db.db()).is_err());
}

#[cfg(unix)]
#[test]
fn bootstrap_alias_owner_detects_retargeting_and_cannot_be_used_as_strict_owner() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("first");
    let second = dir.path().join("second");
    fs::create_dir(&first).unwrap();
    fs::create_dir(&second).unwrap();
    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink(&first, &alias).unwrap();
    let mut owner = ProviderReservation::inspect_existing(&alias).unwrap().into_owner();
    owner.verify().unwrap();
    assert!(owner.verify_existing().is_err());
    assert!(owner.require_strict_path().is_err());
    fs::remove_file(&alias).unwrap();
    std::os::unix::fs::symlink(&second, &alias).unwrap();
    assert!(owner.verify().is_err());
    assert!(ProviderReservation::open_existing(&first).is_err());
    drop(owner);
    ProviderReservation::open_existing(&first).unwrap();
    let missing = dir.path().join("missing");
    assert!(ProviderReservation::inspect_existing(&missing).is_err());
    assert!(!missing.exists());
}
