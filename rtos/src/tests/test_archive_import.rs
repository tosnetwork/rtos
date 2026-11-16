/*
 * RTOS project modifications (2026-10-10): protocol-consistent authenticated cross-chain archive fixtures.
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
#[cfg(feature = "telemetry")]
use crate::collator_test_bundle::create_engine_telemetry;
use crate::{
    archive_import::{run_import, ImportConfig},
    block::{BlockIdExtExtention, BlockStuff},
    collator_test_bundle::create_engine_allocated,
    internal_db::{
        InternalDb, InternalDbConfig, ARCHIVES_GC_BLOCK, LAST_APPLIED_MC_BLOCK,
        PSS_KEEPER_MC_BLOCK, SHARD_CLIENT_MC_BLOCK,
    },
    test_helper::init_test_log,
};
use rtos_block::{
    read_single_root_boc, write_boc, AccountIdPrefixFull, BlockIdExt, Result, SHARD_FULL,
};
use std::{
    path::{Path, PathBuf},
    sync::{atomic::AtomicU8, Arc},
};
use storage::{archives::epoch::ArchivalModeConfig, db::rocksdb::RocksDb};

#[path = "test_archive_import_fixture.rs"]
mod authenticated_fixture;
use authenticated_fixture::Fixture;

async fn wait_for_db_release(db: Arc<RocksDb>) {
    while Arc::strong_count(&db) > 1 {
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    drop(db);
}

const ARCHIVES_PATH: &str = "src/tests/static/archives";
const MC_ZEROSTATE_PATH: &str =
    "src/tests/static/5E994FCF4D425C0A6CE6A792594B7173205F740A39CD56F537DEFD28B48A0F6E.boc";
const WC_ZEROSTATE_PATH: &str =
    "src/tests/static/EE0BEDFE4B32761FB35E9E1D8818EA720CAD1A0E7B4D2ED673C488E72E910342.boc";
const GLOBAL_CONFIG_PATH: &str = "src/tests/config/mainnet.json";

/// Copy archive files to a temporary directory, restoring colons in filenames
/// (files are stored with underscores to avoid issues on Windows).
fn prepare_archives(dest: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(ARCHIVES_PATH)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        let restored_name = name.replace("_", ":");
        std::fs::copy(entry.path(), dest.join(restored_name))?;
    }
    Ok(())
}

fn import_config(dir: &Path, archives_path: PathBuf) -> ImportConfig {
    ImportConfig {
        archives_path,
        epochs_path: dir.join("epochs"),
        epoch_size: 20_000,
        node_db_path: dir.join("node_db"),
        mc_zerostate_path: PathBuf::from(MC_ZEROSTATE_PATH),
        wc_zerostate_paths: vec![PathBuf::from(WC_ZEROSTATE_PATH)],
        global_config_path: PathBuf::from(GLOBAL_CONFIG_PATH),
        skip_validation: false,
        move_files: false,
    }
}

async fn open_db(dir: &Path) -> Result<InternalDb> {
    let db_dir = dir.join("node_db");
    let epochs_path = dir.join("epochs");
    InternalDb::with_update(
        InternalDbConfig {
            db_directory: db_dir.to_string_lossy().to_string(),
            archival_mode: if dir.join("dynamic-state-fixture").exists() {
                None
            } else {
                Some(ArchivalModeConfig {
                    epoch_size: 20_000,
                    new_epochs_path: epochs_path,
                    existing_epochs: vec![],
                })
            },
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
    .await
}

async fn check_imported_block(
    db: &InternalDb,
    block_id: &BlockIdExt,
) -> Result<Option<BlockStuff>> {
    let handle =
        db.load_block_handle(block_id)?.expect("Block handle must exist for imported block");
    assert!(handle.has_state(), "Imported block must have state");
    assert!(handle.has_saved_state(), "Imported block must have saved state");
    assert!(handle.is_applied(), "Imported block must be applied");

    let mut block_stuff = None;
    if block_id.seq_no() > 0 {
        assert!(handle.has_data(), "Imported block must have data");
        assert!(handle.has_prev1(), "Imported block must have prev1");
        if block_id.is_masterchain() {
            assert!(handle.has_proof(), "Imported MC block must have proof");
        } else {
            assert!(handle.has_proof_link(), "Imported shard block must have proof link");
        }

        let prev1 = db.load_block_prev1(&block_id)?;
        assert_eq!(prev1.seq_no(), block_id.seq_no() - 1);
        let prev_handle = db.load_block_handle(&prev1)?.expect("Prev block handle must exist");
        assert!(prev_handle.has_next1(), "Imported block must have next1");
        let next1 = db.load_block_next1(prev_handle.id())?;
        assert_eq!(&next1, block_id);

        block_stuff = Some(db.load_block_data(&handle).await?);
        let _ = db.load_block_proof(&handle, !block_id.is_masterchain()).await?;
    }

    let loaded_state = db.load_shard_state_dynamic(block_id)?;
    let boc = write_boc(loaded_state.root_cell())?;
    let deserialized_state = read_single_root_boc(&boc)?;
    assert_eq!(loaded_state.root_cell().repr_hash(), deserialized_state.repr_hash());
    if block_id.seq_no() > 0 {
        assert_eq!(
            *deserialized_state.repr_hash(),
            block_stuff.as_ref().unwrap().block()?.read_state_update()?.new_hash
        );
    } else {
        assert_eq!(deserialized_state.repr_hash(), block_id.root_hash());
    }

    Ok(block_stuff)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_import_and_verify() -> Result<()> {
    init_test_log();
    let fixture = Fixture::new();
    let dir = tempfile::tempdir()?;
    let archives = dir.path().join("archives");
    fixture.prepare(dir.path(), &archives).await?;
    let node_db = run_import(fixture.config(dir.path(), archives)).await?;
    wait_for_db_release(node_db).await;
    let db = open_db(dir.path()).await?;
    fixture.assert_imported(&db, 4).await?;
    db.stop_states_db().await.unwrap();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_import_resume() -> Result<()> {
    init_test_log();
    let fixture = Fixture::new();
    let dir = tempfile::tempdir()?;
    let all_archives = dir.path().join("archives");
    fixture.prepare(dir.path(), &all_archives).await?;
    let partial = dir.path().join("partial");
    std::fs::create_dir(&partial)?;
    for entry in std::fs::read_dir(&all_archives)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with("archive.00001.") {
            std::fs::copy(entry.path(), partial.join(entry.file_name()))?;
        }
    }
    assert_eq!(std::fs::read_dir(&partial)?.count(), 2, "first MC and WC packages");
    let mut first = fixture.config(dir.path(), partial.clone());
    first.move_files = true;
    let node_db = run_import(first).await?;
    wait_for_db_release(node_db).await;
    assert_eq!(
        std::fs::read_dir(&partial)?.count(),
        0,
        "successful move import consumes both chains"
    );
    let db = open_db(dir.path()).await?;
    fixture.assert_imported(&db, 2).await?;
    db.stop_states_db().await.unwrap();
    drop(db);
    for entry in std::fs::read_dir(&all_archives)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with("archive.00003.") {
            std::fs::copy(entry.path(), partial.join(entry.file_name()))?;
        }
    }
    assert_eq!(std::fs::read_dir(&partial)?.count(), 2, "second MC and WC packages");
    let node_db = run_import(fixture.config(dir.path(), partial)).await?;
    wait_for_db_release(node_db).await;
    let db = open_db(dir.path()).await?;
    fixture.assert_imported(&db, 4).await?;
    db.stop_states_db().await.unwrap();
    Ok(())
}

/// Archive indexes can be ahead of the shard client. Rewinding the client to
/// group one's tip must re-import both chains of group one, not skip to group two.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_import_resume_respects_shard_client() -> Result<()> {
    init_test_log();
    let fixture = Fixture::new();
    let dir = tempfile::tempdir()?;
    let archives = dir.path().join("archives");
    fixture.prepare(dir.path(), &archives).await?;
    let node_db = run_import(fixture.config(dir.path(), archives.clone())).await?;
    wait_for_db_release(node_db).await;
    {
        let db = open_db(dir.path()).await?;
        fixture.assert_imported(&db, 4).await?;
        db.save_full_node_state(SHARD_CLIENT_MC_BLOCK, &fixture.id(2, false))?;
        db.stop_states_db().await.unwrap();
    }
    let mut second = fixture.config(dir.path(), archives.clone());
    second.move_files = true;
    let node_db = run_import(second).await?;
    wait_for_db_release(node_db).await;
    let leftover: Vec<_> = std::fs::read_dir(&archives)?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .filter(|name| name.starts_with("archive.00001."))
        .collect();
    assert!(
        leftover.is_empty(),
        "shard-client resume must consume group one's MC and WC packages: {leftover:?}"
    );
    let db = open_db(dir.path()).await?;
    fixture.assert_imported(&db, 4).await?;
    db.stop_states_db().await.unwrap();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_import_rejects_skip_validation() -> Result<()> {
    init_test_log();
    let dir = tempfile::tempdir().unwrap();
    let archives = dir.path().join("archives");
    prepare_archives(&archives).unwrap();
    let mut config = import_config(dir.path(), archives);
    config.skip_validation = true;

    let error = run_import(config).await.err().expect("skip-validation must be rejected");
    assert!(error.to_string().contains("--skip-validation is unsupported"));
    assert!(!dir.path().join("node_db").exists(), "rejected import must not create a database");
    assert!(!dir.path().join("epochs").exists(), "rejected import must not move archives");
    Ok(())
}

#[path = "test_node_nonzero_recovery.rs"]
mod node_process_recovery;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persistent_gc_keeps_mc_and_wc_zero_files_but_expires_regular_snapshots() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let fixture = Fixture::node_recovery();
    let archives = dir.path().join("archives");
    fixture.prepare(dir.path(), &archives).await?;
    let physical = run_import(fixture.config(dir.path(), archives)).await?;
    tokio::time::timeout(std::time::Duration::from_secs(60), wait_for_db_release(physical)).await?;
    let db = open_db(dir.path()).await?;
    fixture.assert_imported(&db, 4).await?;
    let old = fixture.id(1, false);
    let handle = db.load_block_handle(&old)?.expect("imported MC1");
    let bytes = rtos_block::write_boc(db.load_shard_state_dynamic(&old)?.root_cell())?;
    db.store_shard_state_persistent_raw(&handle, &bytes, None).await?;
    let files = storage::db::filedb::FileDb::with_path(
        dir.path().join("node_db").join(crate::internal_db::SHARD_STATE_PERSISTENT_DB_NAME),
    );
    assert!(files.contains(&old).await?);
    let result = db.shard_state_persistent_gc(|_| (0, true), &fixture.id(0, false)).await;
    let checked = fixture.assert_imported(&db, 4).await;
    let expired = !files.contains(&old).await?;
    db.stop_states_db().await?;
    result?;
    checked?;
    assert!(expired, "ordinary expired snapshots must still be collected");
    Ok(())
}
