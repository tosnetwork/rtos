// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::super::epoch::EpochEntry;
use super::*;
use std::{
    process::{Command, Stdio},
    time::{Duration, Instant},
};
const CHILD: &str = "archives::recovery_check::tests::native_child";
fn observed(config: &CheckConfig) -> Result<CheckReport> {
    eprintln!("RECOVERY_CHECK_BEGIN root={}", config.node_root.display());
    let result = inspect(config);
    eprintln!("RECOVERY_CHECK_END ok={}", result.is_ok());
    result
}
fn fixture(root: &Path, name: &str, main: bool) {
    fs::create_dir_all(root).unwrap();
    let mut options = Options::default();
    options.create_if_missing(true);
    options.create_missing_column_families(true);
    let names = if main { vec!["files", "key_files"] } else { vec!["default"] };
    let db = NativeDb::open_cf(&options, root.join(name), names).unwrap();
    drop(db);
}
fn config(root: &Path) -> CheckConfig {
    CheckConfig {
        node_root: root.to_path_buf(),
        working_directory: root.to_path_buf(),
        archival_mode: None,
    }
}
fn archive(root: &Path, name: &str, id: u32, key: bool, pending: bool, index: bool) {
    let mut options = Options::default();
    options.create_missing_column_families(true);
    let families = NativeDb::list_cf(&options, root.join(name)).unwrap();
    let db = NativeDb::open_cf(&options, root.join(name), families).unwrap();
    for kind in ["entry_meta", "offsets", "block_index", "status"] {
        let name = format!("{kind}_{}db_{id}", if key { "key_" } else { "" });
        db.create_cf(&name, &Options::default()).unwrap();
    }
    let name = format!("status_{}db_{id}", if key { "key_" } else { "" });
    db.put_cf(&db.cf_handle(&name).unwrap(), b"SlicedMode", [1]).unwrap();
    if pending {
        db.put_cf(&db.cf_handle(&name).unwrap(), b"RepackRecovery", b"pending").unwrap();
    }
    if index {
        db.put_cf(
            &db.cf_handle(if key { "key_files" } else { "files" }).unwrap(),
            id.to_le_bytes(),
            serde_cbor::to_vec(&PackageIndexEntry::new()).unwrap(),
        )
        .unwrap();
    }
    fs::create_dir_all(root.join("archive/packages/arch0000")).unwrap();
    drop(db);
}
fn bytes(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    inventory(root, false)
        .unwrap()
        .into_keys()
        .filter(|p| p.is_file())
        .map(|p| {
            let b = fs::read(&p).unwrap();
            (p, b)
        })
        .collect()
}
#[test]
fn single_clear_and_pending_are_read_only() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fixture(root, "db", true);
    archive(root, "db", 0, false, false, true);
    let before = bytes(root);
    assert_eq!(observed(&config(root)).unwrap().live_archives, 1);
    assert_eq!(bytes(root), before);
    let options = Options::default();
    let families = NativeDb::list_cf(&options, root.join("db")).unwrap();
    let db = NativeDb::open_cf(&options, root.join("db"), families).unwrap();
    db.put_cf(&db.cf_handle("status_db_0").unwrap(), b"UnknownRecoveryVersion", b"x").unwrap();
    drop(db);
    let before = bytes(root);
    assert!(observed(&config(root)).unwrap_err().to_string().contains("Pending or unsupported"));
    assert_eq!(bytes(root), before);
}
#[test]
fn orphan_marker_and_legacy_staging_refuse() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fixture(root, "db", true);
    archive(root, "db", 0, false, true, false);
    assert!(observed(&config(root)).is_err());
    let other = tempfile::tempdir().unwrap();
    fixture(other.path(), "db", true);
    let path = other.path().join("archive/packages/arch0000");
    fs::create_dir_all(&path).unwrap();
    for name in ["archive.00000.pack.new", ".repack-fixture"] {
        let marker = path.join(name);
        fs::write(&marker, b"preserve").unwrap();
        let before = bytes(other.path());
        assert!(observed(&config(other.path()))
            .unwrap_err()
            .to_string()
            .contains("Unresolved archive staging"));
        assert_eq!(bytes(other.path()), before);
        fs::remove_file(marker).unwrap();
    }
}
fn epoch_setup(root: &Path) -> CheckConfig {
    fixture(root, "db", true);
    let epochs = root.join("epochs");
    fs::create_dir(&epochs).unwrap();
    let epoch = epochs.join("epoch_0");
    fixture(&epoch, "archive_db", false);
    fs::write(epoch.join("epoch_meta.json"), br#"{"mc_seq_no_start":0,"mc_seq_no_end":19999}"#)
        .unwrap();
    CheckConfig {
        node_root: root.to_path_buf(),
        working_directory: root.to_path_buf(),
        archival_mode: Some(ArchivalModeConfig {
            epoch_size: 20000,
            new_epochs_path: PathBuf::from("epochs"),
            existing_epochs: vec![],
        }),
    }
}
#[test]
fn epoch_routes_key_archives_to_main_and_checks_all_providers() {
    for pending in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let cfg = epoch_setup(dir.path());
        archive(dir.path(), "db", 0, true, pending, true);
        let epoch = dir.path().join("epochs/epoch_0");
        archive(&epoch, "archive_db", 0, false, false, false);
        let before = bytes(dir.path());
        let result = observed(&cfg);
        assert_eq!(result.is_ok(), !pending);
        assert_eq!(before, bytes(dir.path()));
    }
    let dir = tempfile::tempdir().unwrap();
    let cfg = epoch_setup(dir.path());
    archive(&dir.path().join("epochs/epoch_0"), "archive_db", 0, false, true, false);
    assert!(observed(&cfg).unwrap_err().to_string().contains("Pending or unsupported"));
}
#[test]
fn epoch_inventory_refuses_missing_duplicate_and_malformed_candidates() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = epoch_setup(dir.path());
    assert_eq!(observed(&cfg).unwrap().providers.len(), 2);
    cfg.archival_mode
        .as_mut()
        .unwrap()
        .existing_epochs
        .push(EpochEntry { path: PathBuf::from("epochs/epoch_0") });
    assert_eq!(observed(&cfg).unwrap().providers.len(), 2);
    let duplicate = dir.path().join("epochs/epoch_duplicate");
    fixture(&duplicate, "archive_db", false);
    fs::copy(dir.path().join("epochs/epoch_0/epoch_meta.json"), duplicate.join("epoch_meta.json"))
        .unwrap();
    assert!(observed(&cfg).unwrap_err().to_string().contains("duplicate"));
    fs::remove_dir_all(&duplicate).unwrap();
    fs::create_dir(&duplicate).unwrap();
    assert!(observed(&cfg).is_err());
    fs::write(duplicate.join("epoch_meta.json"), b"invalid").unwrap();
    assert!(observed(&cfg).is_err());
    fs::remove_dir_all(&duplicate).unwrap();
    cfg.archival_mode.as_mut().unwrap().new_epochs_path = PathBuf::from("missing");
    assert!(observed(&cfg).is_err());
}
#[test]
fn missing_live_target_and_corrupt_database_refuse() {
    let dir = tempfile::tempdir().unwrap();
    fixture(dir.path(), "db", true);
    let db = NativeDb::open_cf(&Options::default(), dir.path().join("db"), ["files", "key_files"])
        .unwrap();
    db.put_cf(
        &db.cf_handle("files").unwrap(),
        10u32.to_le_bytes(),
        serde_cbor::to_vec(&PackageIndexEntry::new()).unwrap(),
    )
    .unwrap();
    drop(db);
    assert!(observed(&config(dir.path())).unwrap_err().to_string().contains("Missing archive CF"));
    let other = tempfile::tempdir().unwrap();
    fs::create_dir(other.path().join("db")).unwrap();
    fs::write(other.path().join("db/LOCK"), b"").unwrap();
    assert!(observed(&config(other.path())).is_err());
}
fn child(root: &Path, mode: &str) -> std::process::Child {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--ignored", "--exact", CHILD, "--nocapture"])
        .env("RTOS_RECOVERY_CHECK_CHILD_ROOT", root)
        .env("RTOS_RECOVERY_CHECK_CHILD_MODE", mode)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if mode == "check-refused" && unsafe { libc::geteuid() } == 0 {
        use std::os::unix::process::CommandExt;
        command.uid(65534);
    }
    command.spawn().unwrap()
}

fn wait(mut process: std::process::Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = process.try_wait().unwrap() {
            return status;
        }
        if Instant::now() > deadline {
            process.kill().unwrap();
            process.wait().unwrap();
            panic!("native check child timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
#[test]
fn native_writer_lock_conflicts_in_both_directions() {
    let dir = tempfile::tempdir().unwrap();
    fixture(dir.path(), "db", true);
    let process = child(dir.path(), "hold-writer");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !dir.path().join("writer-ready").exists() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(observed(&config(dir.path())).unwrap_err().to_string().contains("not offline"));
    fs::write(dir.path().join("writer-release"), b"x").unwrap();
    assert!(wait(process).success());
    let provider = OpenProvider::open(dir.path().to_path_buf(), "db", None).unwrap();
    provider.statuses().unwrap();
    assert!(
        !wait(child(dir.path(), "try-writer")).success(),
        "readonly DB open released independent LOCK"
    );
    drop(provider);
    assert!(wait(child(dir.path(), "try-writer")).success());
}
#[test]
fn unflushed_counter_merge_and_pending_marker_survive_readonly_replay() {
    for pending in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            wait(child(dir.path(), if pending { "wal-pending" } else { "wal-clear" })).success()
        );
        assert!(!fs::read_dir(dir.path().join("db")).unwrap().any(|e| e
            .unwrap()
            .path()
            .extension()
            .is_some_and(|s| s == "sst")));
        let before = bytes(dir.path());
        let provider = OpenProvider::open(dir.path().to_path_buf(), "db", None).unwrap();
        assert_eq!(
            provider
                .db
                .get_cf(&provider.db.cf_handle(CELLSCOUNTERS_CF_NAME).unwrap(), b"counter")
                .unwrap()
                .unwrap(),
            9u32.to_le_bytes()
        );
        assert_eq!(provider.statuses().is_err(), pending);
        drop(provider);
        assert_eq!(observed(&config(dir.path())).is_err(), pending);
        assert_eq!(bytes(dir.path()), before);
    }
}
#[test]
#[ignore = "isolated native writer/WAL fixture"]
fn native_child() {
    let root = PathBuf::from(std::env::var_os("RTOS_RECOVERY_CHECK_CHILD_ROOT").unwrap());
    let mode = std::env::var("RTOS_RECOVERY_CHECK_CHILD_MODE").unwrap();
    if mode == "check-refused" {
        assert!(observed(&config(&root)).is_err());
        return;
    }
    if mode.starts_with("wal-") {
        let mut options = Options::default();
        options.create_if_missing(true);
        options.create_missing_column_families(true);
        let config = CellsDbConfig::default();
        let (counter, cache) = DynamicBocDb::build_counters_cf_options(&config);
        let names = [
            "files",
            "key_files",
            "entry_meta_db_0",
            "offsets_db_0",
            "block_index_db_0",
            "status_db_0",
        ];
        let mut descriptors: Vec<_> =
            names.into_iter().map(|n| ColumnFamilyDescriptor::new(n, Options::default())).collect();
        descriptors.push(ColumnFamilyDescriptor::new(CELLSCOUNTERS_CF_NAME, counter));
        let db = NativeDb::open_cf_descriptors(&options, root.join("db"), descriptors).unwrap();
        db.put_cf(&db.cf_handle(CELLSCOUNTERS_CF_NAME).unwrap(), b"counter", 7u32.to_le_bytes())
            .unwrap();
        db.merge_cf(&db.cf_handle(CELLSCOUNTERS_CF_NAME).unwrap(), b"counter", 2u32.to_le_bytes())
            .unwrap();
        db.put_cf(&db.cf_handle("status_db_0").unwrap(), b"SlicedMode", [1]).unwrap();
        if mode == "wal-pending" {
            db.put_cf(&db.cf_handle("status_db_0").unwrap(), b"RepackRecovery", b"pending")
                .unwrap();
        }
        db.flush_wal(true).unwrap();
        std::hint::black_box(cache);
        std::process::exit(0);
    }
    let families = NativeDb::list_cf(&Options::default(), root.join("db")).unwrap();
    let db = match NativeDb::open_cf(&Options::default(), root.join("db"), families) {
        Ok(db) => db,
        Err(_) => std::process::exit(7),
    };
    if mode == "hold-writer" {
        fs::write(root.join("writer-ready"), b"x").unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while !root.join("writer-release").exists() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    drop(db);
}

#[test]
fn many_families_do_not_trigger_legacy_cleanup() {
    use crate::db::rocksdb::{LAST_UNNEEDED_KEY_BLOCK, NODE_STATE_DB_NAME};
    use crate::traits::Serializable;
    for pending in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        fixture(root, "db", true);
        archive(root, "db", 0, false, pending, true);
        let options = Options::default();
        let families = NativeDb::list_cf(&options, root.join("db")).unwrap();
        let db = NativeDb::open_cf(&options, root.join("db"), families).unwrap();
        db.create_cf(NODE_STATE_DB_NAME, &options).unwrap();
        for index in 0..101 {
            db.create_cf(&format!("padding_{index}"), &options).unwrap();
        }
        let boundary = rtos_block::BlockIdExt::with_params(
            rtos_block::ShardIdent::masterchain(),
            100,
            rtos_block::UInt256::default(),
            rtos_block::UInt256::default(),
        );
        db.put_cf(
            &db.cf_handle(NODE_STATE_DB_NAME).unwrap(),
            LAST_UNNEEDED_KEY_BLOCK.as_bytes(),
            boundary.serialize(),
        )
        .unwrap();
        drop(db);
        let families = NativeDb::list_cf(&options, root.join("db")).unwrap();
        assert!(
            families.len() > 100
                && !families.iter().any(|name| name == "repair_dependency_leases_v1")
        );
        let before = bytes(root);
        assert_eq!(observed(&config(root)).is_err(), pending);
        assert_eq!(bytes(root), before);
        assert_eq!(NativeDb::list_cf(&options, root.join("db")).unwrap(), families);
    }
}

#[test]
fn lock_and_database_path_replacement_are_detected() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    fixture(root, "db", true);
    let provider = OpenProvider::open(root.to_path_buf(), "db", None).unwrap();
    fs::rename(root.join("db/LOCK"), root.join("db/LOCK.old")).unwrap();
    fs::write(root.join("db/LOCK"), b"").unwrap();
    assert!(provider.verify_identity().unwrap_err().to_string().contains("identity changed"));
    drop(provider);
    let provider = OpenProvider::open(root.to_path_buf(), "db", None).unwrap();
    fs::rename(root.join("db"), root.join("db.old")).unwrap();
    fixture(root, "db", true);
    assert!(provider.verify_identity().unwrap_err().to_string().contains("identity changed"));
    drop(provider);
}

#[test]
fn symlinked_inputs_and_unrecognized_epoch_directories_refuse() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let cfg = epoch_setup(root);
    symlink(root, root.join("alias")).unwrap();
    let mut linked = cfg.clone();
    linked.node_root = root.join("alias");
    assert!(observed(&linked).unwrap_err().to_string().contains("Symlink"));
    fs::remove_file(root.join("alias")).unwrap();
    let metadata = root.join("epochs/epoch_0/epoch_meta.json");
    fs::rename(&metadata, root.join("metadata.json")).unwrap();
    symlink(root.join("metadata.json"), &metadata).unwrap();
    assert!(observed(&cfg).is_err());
    fs::remove_file(&metadata).unwrap();
    fs::rename(root.join("metadata.json"), &metadata).unwrap();
    fixture(&root.join("epochs/custom-directory"), "archive_db", false);
    assert!(observed(&cfg).is_err());
    fs::remove_dir_all(root.join("epochs/custom-directory")).unwrap();
    assert_eq!(observed(&cfg).unwrap().providers.len(), 2);
    let invalid = root.join("epochs/dangling-directory");
    fs::create_dir(&invalid).unwrap();
    symlink(root.join("absent-meta"), invalid.join("epoch_meta.json")).unwrap();
    assert!(observed(&cfg).is_err());
}

#[test]
fn inaccessible_provider_refuses_without_modification() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    fixture(root, "db", true);
    let before = bytes(root);
    let permissions = fs::metadata(root.join("db")).unwrap().permissions();
    fs::set_permissions(root.join("db"), fs::Permissions::from_mode(0o000)).unwrap();
    let status = wait(child(root, "check-refused"));
    fs::set_permissions(root.join("db"), permissions).unwrap();
    assert!(status.success());
    assert_eq!(bytes(root), before);
}

#[test]
fn concurrent_inspections_keep_all_provider_lifetimes_serialized() {
    use std::sync::mpsc;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    fixture(root, "db", true);
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let first_config = config(root);
    let first = std::thread::spawn(move || {
        inspect_with_completion(&first_config, || {
            ready_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(20)).unwrap();
        })
    });
    ready_rx.recv_timeout(Duration::from_secs(20)).unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    let second_config = config(root);
    let second = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        let result = inspect(&second_config);
        finished_tx.send(result.is_ok()).unwrap();
        result
    });
    started_rx.recv_timeout(Duration::from_secs(20)).unwrap();
    assert!(matches!(
        finished_rx.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    // A real independent native writer must still see the first inspection's lock.
    assert!(!wait(child(root, "try-writer")).success());
    release_tx.send(()).unwrap();
    first.join().unwrap().unwrap();
    assert!(finished_rx.recv_timeout(Duration::from_secs(20)).unwrap());
    second.join().unwrap().unwrap();
    assert!(wait(child(root, "try-writer")).success());
}
