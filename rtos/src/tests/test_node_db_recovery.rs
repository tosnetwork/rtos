// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Actual WAL recovery through both node DB consumers after an unclean process exit.
use super::*;
#[cfg(feature = "telemetry")]
use crate::collator_test_bundle::create_engine_telemetry;
use crate::{
    archive_import::{run_import, ImportConfig},
    collator_test_bundle::create_engine_allocated,
    network_db::DbNetworkBinding,
};
use rtos_block::{read_single_root_boc, BuilderData};
use std::{
    fs,
    process::{Child, Command, Stdio},
    time::Instant,
};
use storage::db::node::open_node_db;

const CHILD_TEST: &str = "internal_db::node_db_recovery_tests::node_db_counter_wal_writer";
const ROOT_ENV: &str = "RTOS_COUNTER_WAL_FIXTURE";
const STATE_TABLE: &str = "recovery_states";
const SENTINEL_TABLE: &str = "recovery_wal_tail";
const SENTINEL_KEY: &[u8] = b"after-counter-merge";
const SENTINEL_VALUE: &[u8] = b"must-survive-the-entire-wal";

fn small_config() -> CellsDbConfig {
    let mut config = CellsDbConfig::default();
    config.cells_cache_size_bytes = 1 << 20;
    config.counters_cache_size_bytes = 1 << 20;
    config.cells_lru_cache_capacity = 128;
    config.counters_lru_cache_capacity = 128;
    config
}

fn anchor(root: &Path) -> Result<BlockIdExt> {
    let data = fs::read(root.join("mc-zero.boc"))?;
    let cell = read_single_root_boc(&data)?;
    Ok(BlockIdExt::with_params(
        ShardIdent::masterchain(),
        0,
        cell.repr_hash().clone(),
        UInt256::calc_file_hash(&data),
    ))
}

fn prepare(root: &Path) -> Result<()> {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("static/archive-mc-wc.json"))?;
    fs::write(root.join("mc-zero.boc"), hex::decode(fixture["zerostate"].as_str().unwrap())?)?;
    fs::write(root.join("wc-zero.boc"), hex::decode(fixture["wc_zerostate"].as_str().unwrap())?)?;
    let id = anchor(root)?;
    let mut global: serde_json::Value = serde_json::from_str(include_str!("config/mainnet.json"))?;
    global["validator"] = serde_json::json!({"zero_state": {
        "workchain": -1, "shard": i64::MIN, "seqno": 0,
        "root_hash": id.root_hash.as_base64(false), "file_hash": id.file_hash.as_base64(false)
    }});
    fs::write(root.join("global.json"), serde_json::to_vec(&global)?)?;
    fs::create_dir(root.join("archives"))?;
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
struct Row {
    family: String,
    key: String,
    value: String,
}

fn snapshot(db: &Arc<RocksDb>) -> Result<Vec<Row>> {
    let mut rows = Vec::new();
    for family in [CELLS_CF_NAME, CELLSCOUNTERS_CF_NAME, STATE_TABLE, SENTINEL_TABLE] {
        let table = db.clone().table::<UInt256>(family, false)?;
        table.for_each(&mut |key, value| {
            rows.push(Row {
                family: family.into(),
                key: hex::encode(key),
                value: hex::encode(value),
            });
            Ok(true)
        })?;
    }
    rows.sort_by(|a, b| (&a.family, &a.key).cmp(&(&b.family, &b.key)));
    Ok(rows)
}

fn verify(db: &Arc<RocksDb>, root: &Path) -> Result<()> {
    let expected: Vec<Row> = serde_json::from_slice(&fs::read(root.join("manifest.json"))?)?;
    assert_eq!(
        snapshot(db)?,
        expected,
        "cold recovery must preserve every cell/counter/state and the post-Merge sentinel"
    );
    let sentinel = db.clone().table::<UInt256>(SENTINEL_TABLE, false)?;
    assert_eq!(sentinel.try_get_raw(SENTINEL_KEY)?.unwrap().as_ref(), SENTINEL_VALUE);
    Ok(())
}

/// Invoked only by the parent tests, then killed while the DB is still open.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn node_db_counter_wal_writer() -> Result<()> {
    let Some(root) = std::env::var_os(ROOT_ENV) else { return Ok(()) };
    let root = PathBuf::from(root);
    let node_root = root.join("node_db");
    let _binding = DbNetworkBinding::acquire(&node_root, &anchor(&root)?)?;
    let db = open_node_db(&node_root, &small_config(), AccessType::ReadWrite)?;
    let states = ShardStateDb::new(
        db.clone(),
        STATE_TABLE,
        CELLS_CF_NAME,
        CELLSCOUNTERS_CF_NAME,
        small_config(),
        #[cfg(feature = "telemetry")]
        Arc::new(StorageTelemetry::default()),
        Arc::new(StorageAlloc::default()),
    )?;
    let sentinel = db.clone().table::<UInt256>(SENTINEL_TABLE, true)?;
    // Two independent root references to one child produce a real counter Merge.
    let child = BuilderData::with_raw(vec![0x31], 8)?.into_cell()?;
    for seq in [1, 2] {
        let mut builder = BuilderData::with_raw(vec![seq as u8], 8)?;
        builder.checked_append_reference(child.clone())?;
        let cell = builder.into_cell()?;
        let id = BlockIdExt::with_params(
            ShardIdent::masterchain(),
            seq,
            cell.repr_hash().clone(),
            UInt256::default(),
        );
        states.put(&id, cell, None).await?;
        states.sync_pending().await?;
    }
    sentinel.put_raw(SENTINEL_KEY, SENTINEL_VALUE)?;
    db.sync_wal()?;
    let counters = db.clone().table::<UInt256>(CELLSCOUNTERS_CF_NAME, false)?;
    assert_eq!(
        counters.try_get_raw(child.repr_hash().as_slice())?.unwrap().as_ref(),
        &2u32.to_le_bytes()
    );
    assert!(db.db().live_files()?.is_empty(), "fixture must recover cells from WAL, not SST files");
    let manifest = snapshot(&db)?;
    assert_eq!(manifest.iter().filter(|row| row.family == CELLS_CF_NAME).count(), 3);
    assert_eq!(manifest.iter().filter(|row| row.family == CELLSCOUNTERS_CF_NAME).count(), 3);
    fs::write(root.join("manifest.json"), serde_json::to_vec(&manifest)?)?;
    fs::write(root.join("ready"), b"wal-synced")?;
    // Keep all owners alive. No destructor/normal shutdown may flush this fixture.
    loop {
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn crash_writer(root: &Path) -> Result<()> {
    prepare(root)?;
    let log = fs::File::create(root.join("writer.log"))?;
    let mut child = KillOnDrop(
        Command::new(std::env::current_exe()?)
            .args(["--ignored", "--exact", CHILD_TEST, "--nocapture"])
            .env(ROOT_ENV, root)
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while !root.join("ready").exists() {
        assert!(
            child.0.try_wait()?.is_none(),
            "WAL writer failed: {}",
            fs::read_to_string(root.join("writer.log"))?
        );
        assert!(Instant::now() < deadline, "WAL writer did not become ready");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    child.0.kill()?;
    let status = child.0.wait()?;
    assert!(!status.success(), "writer must end without normal DB destruction");
    Ok(())
}

async fn release(db: Arc<RocksDb>) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        while Arc::strong_count(&db) > 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    drop(db);
    Ok(())
}

fn verify_second_open(root: &Path) -> Result<()> {
    let db = open_node_db(root.join("node_db"), &small_config(), AccessType::ReadWrite)?;
    verify(&db, root)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_db_counter_wal_import_preserves_existing_dynamic_cells() -> Result<()> {
    let dir = tempfile::tempdir()?;
    crash_writer(dir.path()).await?;
    let root = dir.path();
    let db = run_import(ImportConfig {
        archives_path: root.join("archives"),
        epochs_path: root.join("epochs"),
        epoch_size: 20_000,
        node_db_path: root.join("node_db"),
        mc_zerostate_path: root.join("mc-zero.boc"),
        wc_zerostate_paths: vec![root.join("wc-zero.boc")],
        global_config_path: root.join("global.json"),
        skip_validation: false,
        move_files: false,
    })
    .await?;
    verify(&db, root)?;
    release(db).await?;
    verify_second_open(root)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_db_counter_wal_archival_mode_preserves_existing_dynamic_cells() -> Result<()> {
    let dir = tempfile::tempdir()?;
    crash_writer(dir.path()).await?;
    let root = dir.path();
    let db = InternalDb::with_update(
        InternalDbConfig {
            db_directory: root.join("node_db").to_string_lossy().into_owned(),
            cells_db_config: small_config(),
            archival_mode: Some(ArchivalModeConfig {
                epoch_size: 20_000,
                new_epochs_path: root.join("epochs"),
                existing_epochs: vec![],
            }),
            ..Default::default()
        },
        false,
        false,
        false,
        None,
        &|| Ok(()),
        None,
        Arc::new(AtomicU8::new(0)),
        None,
        #[cfg(feature = "telemetry")]
        create_engine_telemetry(),
        create_engine_allocated(),
    )
    .await?;
    verify(&db.recovery_node_db, root)?;
    let physical = db.recovery_node_db.clone();
    db.stop_states_db().await.unwrap();
    drop(db);
    release(physical).await?;
    verify_second_open(root)
}

/// Negative control uses its own crash fixture: the destructive legacy open
/// cannot affect either production-path positive control.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_db_counter_wal_legacy_open_negative_control() -> Result<()> {
    let dir = tempfile::tempdir()?;
    crash_writer(dir.path()).await?;
    let root = dir.path();
    let expected: Vec<Row> = serde_json::from_slice(&fs::read(root.join("manifest.json"))?)?;
    let legacy = RocksDb::new(
        root.join("node_db"),
        storage::db::rocksdb::NODE_DB_NAME,
        None,
        AccessType::ReadWrite,
    );
    match legacy {
        Ok(db) => {
            let actual = snapshot(&db);
            assert!(
                !matches!(&actual, Ok(rows) if rows == &expected),
                "negative control did not expose the legacy recovery defect"
            );
            println!("legacy WAL recovery snapshot: {actual:?}");
            drop(db);
        }
        Err(error) => println!("legacy WAL recovery open error: {error:#}"),
    }
    // Require the actual missing-operator diagnosis, not an unrelated failure
    // or merely a deliberately absent row. Closing the owner flushes its LOG.
    let log = fs::read_to_string(
        root.join("node_db").join(storage::db::rocksdb::NODE_DB_NAME).join("LOG"),
    )?;
    let diagnosis: Vec<_> = log
        .lines()
        .filter(|line| {
            line.contains("Merge requires") || line.contains("merge_operator != nullptr")
        })
        .collect();
    assert!(
        !diagnosis.is_empty(),
        "legacy opener must report missing counter merge operator in RocksDB LOG"
    );
    for line in diagnosis {
        println!("legacy RocksDB recovery: {line}");
    }
    Ok(())
}

fn pending_archive_root_bytes(db: &RocksDb) -> Result<Vec<u8>> {
    // Independent fixed-format fixture, including the checksum over all flags.
    let identity = db.db().get_db_identity()?;
    let mut bytes = vec![0u8; 316];
    bytes[..8].copy_from_slice(b"RTOSATR1");
    bytes[8..12].copy_from_slice(&[1, 0, 1, 2]);
    bytes[12..28].fill(4);
    bytes[28..36].copy_from_slice(&(identity.len() as u64).to_le_bytes());
    bytes[36..68].copy_from_slice(&rtos_block::sha256_digest(identity));
    bytes[68..76].copy_from_slice(&100u64.to_le_bytes());
    bytes[76..84].copy_from_slice(&1u64.to_le_bytes());
    bytes[84..116].fill(8);
    let checksum = rtos_block::sha256_digest(&bytes[..284]);
    bytes[284..].copy_from_slice(&checksum);
    Ok(bytes)
}

#[tokio::test]
async fn pending_archive_root_precedes_ledger_creation_and_other_node_services() -> Result<()> {
    for ledger in ["missing", "corrupt", "valid"] {
        let dir = tempfile::tempdir()?;
        let db = open_node_db(dir.path(), &small_config(), AccessType::ReadWrite)?;
        let root = pending_archive_root_bytes(&db)?;
        if ledger != "missing" {
            db.db().create_cf(
                "repair_dependency_leases_v1",
                &storage::sst_native_test::Options::default(),
            )?;
            let cf = db.db().cf_handle("repair_dependency_leases_v1").unwrap();
            db.db().put_cf(
                &cf,
                b"next",
                if ledger == "corrupt" { b"bad".as_slice() } else { &[0; 8] },
            )?;
        }
        db.db().put(b"ArchiveTruncationRootV1", &root)?;
        db.sync_wal()?;
        drop(db);
        let outcome = InternalDb::construct(
            InternalDbConfig {
                db_directory: dir.path().to_string_lossy().into_owned(),
                cells_db_config: small_config(),
                ..Default::default()
            },
            false,
            Arc::new(AtomicU8::new(0)),
            None,
            #[cfg(feature = "telemetry")]
            create_engine_telemetry(),
            create_engine_allocated(),
        )
        .await;
        let error = outcome.err().expect("pending root started ordinary services");
        let message = format!("{error:#}");
        match ledger {
            "missing" => assert!(message.contains("ledger presence"), "{message}"),
            "corrupt" => assert!(message.contains("generation length"), "{message}"),
            // Building is now supported before staging, but this fixture has
            // no selection sidecar. Its absence must preserve the pending root.
            _ => assert!(
                error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound),
                "{message}"
            ),
        }
        assert!(!dir.path().join("catchains").exists());
        assert!(!dir.path().join("archive").exists());
        let db = open_node_db(dir.path(), &small_config(), AccessType::ReadWrite)?;
        assert_eq!(db.db().get(b"ArchiveTruncationRootV1")?.as_deref(), Some(root.as_slice()));
        assert_eq!(db.db().cf_handle("repair_dependency_leases_v1").is_some(), ledger != "missing");
    }
    Ok(())
}

#[tokio::test]
async fn pending_archive_bootstrap_rebuilds_real_lease_protection_on_same_provider() -> Result<()> {
    use crate::{
        history_read_budget::HistoryReadBudget,
        publication_dependency_leases::{sst_fixture_for_test, DependencyLeases},
    };
    use storage::db::node::open_node_db_for_bootstrap;
    let dir = tempfile::tempdir()?;
    let db = open_node_db(dir.path(), &small_config(), AccessType::ReadWrite)?;
    let leases = DependencyLeases::open(db.clone(), true)?;
    let (binding, dependencies, id) = sst_fixture_for_test();
    leases.begin(&binding, dependencies, &HistoryReadBudget::new(Default::default()))?;
    let root = pending_archive_root_bytes(&db)?;
    db.db().put(b"ArchiveTruncationRootV1", &root)?;
    db.sync_wal()?;
    drop(leases);
    drop(db);
    let mut bootstrap =
        open_node_db_for_bootstrap(dir.path(), &small_config(), AccessType::ReadWrite)?;
    assert!(bootstrap.requires_recovery());
    let db = bootstrap.database().clone();
    assert!(!db.repair_protection().state(&id));
    let leases = DependencyLeases::open(db.clone(), false)?;
    assert!(Arc::ptr_eq(leases.protection(), db.repair_protection()));
    assert!(leases.protection().state(&id));
    bootstrap.inspect_recovery_providers(None, leases.protection()).await?;
    assert!(bootstrap.finish().is_err());
    assert_eq!(db.db().get(b"ArchiveTruncationRootV1")?.as_deref(), Some(root.as_slice()));
    Ok(())
}

const CLEANED_CHILD: &str =
    "internal_db::node_db_recovery_tests::node_cleaned_recovery_crash_writer";
const CLEANED_ENV: &str = "RTOS_CLEANED_RECOVERY_FIXTURE";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "child process fixture"]
async fn node_cleaned_recovery_crash_writer() -> Result<()> {
    use crate::publication_dependency_leases::DependencyLeases;
    let root = std::path::PathBuf::from(std::env::var(CLEANED_ENV)?);
    let db = open_node_db(&root, &small_config(), AccessType::ReadWrite)?;
    let _leases = DependencyLeases::open(db.clone(), true)?;
    let states = ShardStateDb::new(
        db.clone(),
        STATE_TABLE,
        CELLS_CF_NAME,
        CELLSCOUNTERS_CF_NAME,
        small_config(),
        #[cfg(feature = "telemetry")]
        Arc::new(StorageTelemetry::default()),
        Arc::new(StorageAlloc::default()),
    )?;
    let sentinel = db.clone().table::<UInt256>(SENTINEL_TABLE, true)?;
    // Two independent root references to one child produce a real counter Merge.
    let child = BuilderData::with_raw(vec![0x31], 8)?.into_cell()?;
    for seq in [1, 2] {
        let mut builder = BuilderData::with_raw(vec![seq as u8], 8)?;
        builder.checked_append_reference(child.clone())?;
        let cell = builder.into_cell()?;
        let id = BlockIdExt::with_params(
            ShardIdent::masterchain(),
            seq,
            cell.repr_hash().clone(),
            UInt256::default(),
        );
        states.put(&id, cell, None).await?;
        states.sync_pending().await?;
    }
    sentinel.put_raw(SENTINEL_KEY, SENTINEL_VALUE)?;
    db.sync_wal()?;
    let counters = db.clone().table::<UInt256>(CELLSCOUNTERS_CF_NAME, false)?;
    assert_eq!(
        counters.try_get_raw(child.repr_hash().as_slice())?.unwrap().as_ref(),
        &2u32.to_le_bytes()
    );
    assert!(db.db().live_files()?.is_empty(), "fixture must recover cells from WAL, not SST files");
    let manifest = snapshot(&db)?;
    assert_eq!(manifest.iter().filter(|row| row.family == CELLS_CF_NAME).count(), 3);
    assert_eq!(manifest.iter().filter(|row| row.family == CELLSCOUNTERS_CF_NAME).count(), 3);
    fs::write(root.join("manifest.json"), serde_json::to_vec(&manifest)?)?;
    for name in ["files", "key_files"] {
        db.db().create_cf(name, &Default::default())?;
    }
    // Independent wire fixture for the final durable state, with sidecars
    // already removed by a prior cleanup attempt. No archive rows are present.
    let mut header = pending_archive_root_bytes(&db)?;
    header[10] = 4;
    header[11] = 3; // Cleaned, node policy, aborted Building.
    let identity = db.db().get_db_identity()?;
    let absolute = fs::canonicalize(&root)?;
    let raw = absolute.as_os_str().as_encoded_bytes();
    let mut anchor = b"RTOS archive recovery anchor v1".to_vec();
    anchor.push(1);
    anchor.extend_from_slice(&(raw.len() as u64).to_le_bytes());
    anchor.extend_from_slice(raw);
    let mut descriptor = vec![0u8; 93];
    descriptor[..4].copy_from_slice(&[1, 0, 7, 1]);
    descriptor[4..36].copy_from_slice(&rtos_block::sha256_digest(anchor));
    descriptor[36..44].copy_from_slice(&(identity.len() as u64).to_le_bytes());
    descriptor[44..76].copy_from_slice(&rtos_block::sha256_digest(identity));
    let mut providers = 93u64.to_le_bytes().to_vec();
    providers.extend_from_slice(&rtos_block::sha256_digest(descriptor));
    header[164..172].copy_from_slice(&1u64.to_le_bytes());
    header[172..204].copy_from_slice(&rtos_block::sha256_digest(providers));
    let empty = rtos_block::sha256_digest([]);
    header[212..244].copy_from_slice(&empty);
    header[252..284].copy_from_slice(&empty);
    let checksum = rtos_block::sha256_digest(&header[..284]);
    header[284..].copy_from_slice(&checksum);
    let controls = root.join("archive/recovery").join(hex::encode([4u8; 16]));
    fs::create_dir_all(&controls)?;
    for directory in [
        &controls,
        controls.parent().unwrap(),
        controls.parent().unwrap().parent().unwrap(),
        root.as_path(),
    ] {
        fs::File::open(directory)?.sync_all()?;
    }
    db.db().put(b"recovery-sentinel", b"acknowledged-before-interruption")?;
    db.db().put(b"ArchiveTruncationRootV1", header)?;
    db.sync_wal()?;
    fs::write(root.join("child-ready"), b"ready")?;
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_node_restart_finishes_cleaned_recovery_and_preserves_data() -> Result<()> {
    let dir = tempfile::tempdir()?;
    crash_cleaned_writer(dir.path()).await?;
    let db = InternalDb::with_update(
        InternalDbConfig {
            db_directory: dir.path().to_string_lossy().into_owned(),
            cells_db_config: small_config(),
            ..Default::default()
        },
        false,
        false,
        false,
        None,
        &|| Ok(()),
        None,
        Arc::new(AtomicU8::new(0)),
        None,
        #[cfg(feature = "telemetry")]
        create_engine_telemetry(),
        create_engine_allocated(),
    )
    .await?;
    let physical = db.recovery_node_db.clone();
    verify(&physical, dir.path())?;
    assert!(physical.db().get(b"ArchiveTruncationRootV1")?.is_none());
    assert!(physical.db().get(b"ArchiveTruncationParticipantV1")?.is_none());
    assert_eq!(
        physical.db().get(b"recovery-sentinel")?.as_deref(),
        Some(b"acknowledged-before-interruption".as_slice())
    );
    assert!(!dir.path().join("archive/recovery").join(hex::encode([4u8; 16])).exists());
    db.stop_states_db().await?;
    drop(db);
    release(physical).await?;
    let reopened = open_node_db(dir.path(), &small_config(), AccessType::ReadWrite)?;
    verify(&reopened, dir.path())?;
    assert!(reopened.db().get(b"ArchiveTruncationRootV1")?.is_none());
    assert_eq!(
        reopened.db().get(b"recovery-sentinel")?.as_deref(),
        Some(b"acknowledged-before-interruption".as_slice())
    );
    Ok(())
}

async fn crash_cleaned_writer(root: &Path) -> Result<()> {
    let mut child = KillOnDrop(
        Command::new(std::env::current_exe()?)
            .args(["--exact", CLEANED_CHILD, "--ignored", "--nocapture"])
            .env(CLEANED_ENV, root)
            .stdout(Stdio::null())
            .stderr(Stdio::from(fs::File::create(root.join("child.log"))?))
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while !root.join("child-ready").exists() {
        if let Some(status) = child.0.try_wait()? {
            fail!(
                "Recovery fixture exited {status}: {}",
                fs::read_to_string(root.join("child.log"))?
            );
        }
        if Instant::now() >= deadline {
            child.0.kill()?;
            child.0.wait()?;
            fail!("Recovery fixture readiness timeout");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    child.0.kill()?;
    assert!(!child.0.wait()?.success());
    Ok(())
}

/// Runs the actual node executable, not another test function. The binary must
/// be built from the same source revision and supplied explicitly by the runner.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires RTOS_NODE_RECOVERY_BINARY built from this revision"]
async fn node_executable_restarts_after_cleaned_recovery_with_consistent_data() -> Result<()> {
    let binary = fs::canonicalize(std::env::var("RTOS_NODE_RECOVERY_BINARY")?)?;
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    prepare(root)?;
    // The archive-import fixture omits the genesis key-block marker used by
    // the node's overlay startup. Match the node zerostate template and repin
    // the resulting bytes before creating any network-bound database.
    use rtos_block::{Deserializable, HashmapType, Serializable, ShardStateUnsplit};
    let mut genesis =
        ShardStateUnsplit::construct_from_bytes(&fs::read(root.join("mc-zero.boc"))?)?;
    let mut extra = genesis.read_custom()?.expect("masterchain genesis extra");
    extra.after_key_block = true;
    let template = ShardStateUnsplit::construct_from_bytes(include_bytes!("static/zerostate.boc"))?;
    let template = template.read_custom()?.expect("node genesis configuration");
    template.config.config_params.iterate_slices(|key, value| {
        if extra.config.config_params.get(key.clone())?.is_none() {
            extra.config.config_params.set(key, &value)?;
        }
        Ok(true)
    })?;
    genesis.write_custom(Some(&extra))?;
    fs::write(root.join("mc-zero.boc"), rtos_block::write_boc(&genesis.serialize()?)?)?;
    let pin = anchor(root)?;
    let mut global: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("global.json"))?)?;
    global["validator"]["zero_state"]["root_hash"] =
        serde_json::json!(pin.root_hash.as_base64(false));
    global["validator"]["zero_state"]["file_hash"] =
        serde_json::json!(pin.file_hash.as_base64(false));
    fs::write(root.join("global.json"), serde_json::to_vec(&global)?)?;
    let node_root = root.join("node_db");
    fs::create_dir(&node_root)?;
    drop(DbNetworkBinding::acquire(&node_root, &anchor(root)?)?);
    crash_cleaned_writer(&node_root).await?;

    // Keep the process entirely on the local fixture network, without remote
    // bootstrap peers, public servers, validator signing keys or external RPC.
    let mut global: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("global.json"))?)?;
    global["dht"]["static_nodes"]["nodes"] = serde_json::json!([]);
    global["liteservers"] = serde_json::json!([]);
    fs::write(root.join("global.json"), serde_json::to_vec(&global)?)?;
    let zero = root.join("zero");
    fs::create_dir(&zero)?;
    for name in ["mc-zero.boc", "wc-zero.boc"] {
        let bytes = fs::read(root.join(name))?;
        fs::write(
            zero.join(format!("{}.boc", hex::encode(rtos_block::sha256_digest(&bytes)))),
            bytes,
        )?;
    }
    fs::write(
        root.join("default_config.json"),
        serde_json::to_vec(&serde_json::json!({
            "log_config_name": "node-log.yml",
            "ton_global_config_name": "global.json",
            "internal_db_path": node_root,
            "ip_address": "127.0.0.1:0",
            "ip_address_quic": "127.0.0.1:0",
            "boot_from_zerostate": true,
            "restore_db": true,
            "workchain": 0,
            "cells_db_config": small_config()
        }))?,
    )?;
    fs::write(root.join("node-log.yml"),
        "appenders:\n  console:\n    kind: console\n    encoder:\n      pattern: '{m}{n}'\nroot:\n  level: info\n  appenders: [console]\n".replace("\\n", "\n"))?;

    for attempt in 0..2 {
        let log_path = root.join(format!("node-{attempt}.log"));
        let log = fs::File::create(&log_path)?;
        let mut node = KillOnDrop(
            Command::new(&binary)
                .env("TOKIO_WORKER_THREADS", "2")
                .arg("--configs")
                .arg(root)
                .arg("--zerostate")
                .arg(&zero)
                .arg("--initial-sync-disabled")
                .current_dir(root)
                .stdout(Stdio::from(log.try_clone()?))
                .stderr(Stdio::from(log))
                .spawn()?,
        );
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let output = fs::read_to_string(&log_path)?;
            if let Some(status) = node.0.try_wait()? {
                fail!("Actual node exited before boot, attempt {attempt}, {status}: {output}");
            }
            if output.contains("Node services started.") {
                break;
            }
            if Instant::now() >= deadline {
                fail!("Actual node boot timeout, attempt {attempt}: {output}");
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        node.0.kill()?;
        assert!(!node.0.wait()?.success());
        eprintln!("Actual node attempt {attempt}: services started, then SIGKILL");
    }
    // No inspection opens the DB between the two node processes: the second
    // node itself must replay the WAL and handle its unclean-shutdown beacon.
    let db = open_node_db(&node_root, &small_config(), AccessType::ReadWrite)?;
    let expected: Vec<Row> = serde_json::from_slice(&fs::read(node_root.join("manifest.json"))?)?;
    let actual = snapshot(&db)?;
    eprintln!("Checking {} acknowledged rows after two node process restarts", expected.len());
    for row in expected {
        assert!(actual.contains(&row), "acknowledged row changed after node restarts: {row:?}");
    }
    // Additional rows are legitimate: the actual node persists its configured
    // masterchain and workchain zerostates during its first full boot.
    assert!(db.db().get(b"ArchiveTruncationRootV1")?.is_none());
    assert!(db.db().get(b"ArchiveTruncationParticipantV1")?.is_none());
    assert_eq!(
        db.db().get(b"recovery-sentinel")?.as_deref(),
        Some(b"acknowledged-before-interruption".as_slice())
    );
    assert!(!node_root.join("archive/recovery").join(hex::encode([4u8; 16])).exists());
    drop(db);
    let db = InternalDb::with_update(
        InternalDbConfig {
            db_directory: node_root.to_string_lossy().into_owned(),
            cells_db_config: small_config(),
            ..Default::default()
        },
        false,
        false,
        false,
        None,
        &|| Ok(()),
        None,
        Arc::new(AtomicU8::new(0)),
        None,
        #[cfg(feature = "telemetry")]
        create_engine_telemetry(),
        create_engine_allocated(),
    )
    .await?;
    let id = anchor(root)?;
    assert_eq!(db.load_full_node_state(LAST_APPLIED_MC_BLOCK)?.as_deref(), Some(&id));
    assert_eq!(db.load_full_node_state(SHARD_CLIENT_MC_BLOCK)?.as_deref(), Some(&id));
    assert!(db.load_block_handle(&id)?.expect("applied zerostate handle").is_applied());
    db.load_shard_state_dynamic(&id)?.verify_zerostate(&id)?;
    eprintln!(
        "Recovered node head, applied handle and zerostate root match the independent fixture"
    );
    // Negative control follows the successful restarts: contradictory durable
    // progress must refuse startup, preserve data and retain the restore marker.
    let mut conflicting = id.clone();
    conflicting.seq_no = 1;
    db.save_full_node_state(SHARD_CLIENT_MC_BLOCK, &conflicting)?;
    let physical = db.recovery_node_db.clone();
    physical.sync_wal()?;
    db.stop_states_db().await?;
    drop(db);
    release(physical).await?;
    let log_path = root.join("conflicting-progress.log");
    let log = fs::File::create(&log_path)?;
    let mut node = KillOnDrop(
        Command::new(&binary)
            .env("TOKIO_WORKER_THREADS", "2")
            .arg("--configs")
            .arg(root)
            .arg("--zerostate")
            .arg(&zero)
            .arg("--initial-sync-disabled")
            .current_dir(root)
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = node.0.try_wait()? {
            assert!(!status.success());
            break;
        }
        if Instant::now() >= deadline {
            fail!("Conflicting checkpoint was not rejected: {}", fs::read_to_string(&log_path)?);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let output = fs::read_to_string(log_path)?;
    assert!(output.contains("Genesis checkpoint conflicts with ShardsClientMcBlockId"), "{output}");
    assert!(!output.contains("Node services started."));
    assert!(node_root.join("ton_node.restoring").exists());
    let db = open_node_db(&node_root, &small_config(), AccessType::ReadWrite)?;
    assert_eq!(snapshot(&db)?, actual, "rejected restart changed state rows");
    eprintln!(
        "Conflicting progress rejected by actual node; state rows and recovery marker preserved"
    );
    Ok(())
}
