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
    Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", CHILD, "--nocapture"])
        .env("RTOS_RECOVERY_CHECK_CHILD_ROOT", root)
        .env("RTOS_RECOVERY_CHECK_CHILD_MODE", mode)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
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
