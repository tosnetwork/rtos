// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Ordering and durability checks of the node database's write paths.
use super::*;
use crate::collator_test_bundle::create_engine_allocated;
#[cfg(feature = "telemetry")]
use crate::collator_test_bundle::create_engine_telemetry;
use std::sync::atomic::AtomicU8;
use storage::block_handle_db::{Callback, StoreJob};

async fn open_db(dir: &std::path::Path) -> Result<InternalDb> {
    open_db_with(dir, None).await
}

async fn open_db_with(
    dir: &std::path::Path,
    archival_mode: Option<storage::archives::epoch::ArchivalModeConfig>,
) -> Result<InternalDb> {
    InternalDb::with_update(
        InternalDbConfig {
            db_directory: dir.to_str().ok_or_else(|| error!("non UTF-8 path"))?.to_owned(),
            archival_mode,
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

fn mc(seq_no: u32) -> BlockIdExt {
    let mut hash = [0u8; 32];
    hash[..4].copy_from_slice(&seq_no.to_be_bytes());
    hash[31] = 0x3c;
    BlockIdExt::with_params(
        ShardIdent::masterchain(),
        seq_no,
        UInt256::from(hash),
        UInt256::default(),
    )
}

struct HeldWriter {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl Callback for HeldWriter {
    async fn invoke(&self, _job: StoreJob, _ok: bool) {
        self.entered.notify_one();
        self.release.notified().await;
    }
}

/// Holds the ordered handle writer inside a callback until released.
async fn hold_writer(db: &InternalDb) -> Result<Arc<HeldWriter>> {
    let held = Arc::new(HeldWriter { entered: Default::default(), release: Default::default() });
    let handle = db.create_test_block_handle(&mc(1_000_000))?;
    db.block_handle_storage.save_handle(&handle, Some(held.clone()))?;
    held.entered.notified().await;
    Ok(held)
}

/// Restore lowers LAST_ROTATION synchronously; an older value still queued
/// in the writer must not overwrite it afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restored_rotation_is_not_overwritten_by_older_queued_value() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = open_db(dir.path()).await?;
    let held = hold_writer(&db).await?;
    db.save_validator_state(LAST_ROTATION_MC_BLOCK, &mc(100))?;
    db.save_validator_state_sync(LAST_ROTATION_MC_BLOCK, &mc(7))?;
    held.release.notify_one();
    db.block_handle_storage.sync_pending().await?;
    assert_eq!(db.load_validator_state(LAST_ROTATION_MC_BLOCK)?.map(|id| id.seq_no()), Some(7));
    let raw = db.load_validator_state_raw(LAST_ROTATION_MC_BLOCK)?.unwrap_or_default();
    assert_eq!(BlockIdExt::deserialize(&raw)?.seq_no(), 7);
    db.stop_states_db().await?;
    Ok(())
}

/// The archive GC's deletion authority is made durable before deletion, and
/// it waits for every earlier queued pointer first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn archive_gc_waits_for_durable_authority_before_deleting() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = Arc::new(open_db(dir.path()).await?);
    let held = hold_writer(&db).await?;
    db.save_full_node_state(ARCHIVES_GC_BLOCK, &mc(40))?;
    let gc_db = db.clone();
    let mut gc = tokio::spawn(async move { gc_db.archive_gc(&mc(30)).await });
    let finished_while_held =
        tokio::time::timeout(std::time::Duration::from_millis(500), &mut gc).await.is_ok();
    let stored = |key: &str| -> Result<bool> {
        Ok(db.full_node_state_db.try_get_raw(key.as_bytes())?.is_some())
    };
    let authority_while_held = stored(LAST_UNNEEDED_KEY_BLOCK)?;
    held.release.notify_one();
    gc.await.map_err(|e| error!("{e}"))??;
    assert!(!finished_while_held, "archive GC ran while earlier pointers were not durable");
    assert!(!authority_while_held);
    assert!(stored(ARCHIVES_GC_BLOCK)? && stored(LAST_UNNEEDED_KEY_BLOCK)?);
    db.stop_states_db().await?;
    Ok(())
}

/// After a failed write the archive GC refuses before destructive work.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn archive_gc_refuses_after_a_failed_write() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = open_db(dir.path()).await?;
    db.recovery_node_db.drop_table(storage::block_handle_db::BLOCK_HANDLE_DB_NAME)?;
    let handle = db.create_test_block_handle(&mc(5));
    assert!(handle.is_ok(), "admission succeeds; the commit fails");
    assert!(db.archive_gc(&mc(30)).await.is_err());
    assert!(db.full_node_state_db.try_get_raw(LAST_UNNEEDED_KEY_BLOCK.as_bytes())?.is_none());
    let _ = db.stop_states_db().await;
    Ok(())
}

/// A durable applied flag is in the database when the call returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_applied_flag_is_stored_on_return() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = open_db(dir.path()).await?;
    let handle = db.create_test_block_handle(&mc(9))?;
    let held = hold_writer(&db).await?;
    let applied = {
        let db = &db;
        let handle = handle.clone();
        async move { db.store_block_applied_durable(&handle).await }
    };
    tokio::pin!(applied);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(300), &mut applied).await.is_err(),
        "durable applied flag acknowledged while the writer was held"
    );
    held.release.notify_one();
    assert!(applied.await?);
    // Read the stored record, not the cached handle.
    let node_db = db.recovery_node_db.clone();
    let mut reader = BlockHandleStorage::with_dbs(
        Arc::new(BlockHandleDb::with_db(node_db.clone(), BLOCK_HANDLE_DB_NAME, false)?),
        Arc::new(NodeStateDb::with_db(
            node_db.clone(),
            storage::db::rocksdb::NODE_STATE_DB_NAME,
            false,
        )?),
        Arc::new(NodeStateDb::with_db(db.catchain_db.clone(), VALIDATOR_STATE_DB_NAME, false)?),
        #[cfg(feature = "telemetry")]
        db.telemetry.storage.clone(),
        db.allocated.storage.clone(),
    );
    reader.set_no_cache();
    let stored = reader.load_handle_by_id(&mc(9))?;
    assert!(stored.is_some_and(|handle| handle.is_applied()));
    db.stop_states_db().await?;
    Ok(())
}

/// Archival mode: the saved-state notification fires only after the separate
/// archival state database was synchronized and the saved flag is durable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn archival_state_is_durable_before_it_is_reported_saved() -> Result<()> {
    struct Observed {
        states: Arc<storage::archive_shardstate_db::ArchiveShardStateDb>,
        synced_at_report: std::sync::Mutex<Option<Option<u64>>>,
        reported: tokio::sync::Notify,
    }
    #[async_trait::async_trait]
    impl storage::shardstate_db_async::Callback for Observed {
        async fn invoke(&self, _job: storage::shardstate_db_async::Job) {
            *self.synced_at_report.lock().unwrap() = Some(self.states.wal_synced_count());
            self.reported.notify_one();
        }
    }
    let dir = tempfile::tempdir()?;
    let db = open_db_with(
        &dir.path().join("node_db"),
        Some(storage::archives::epoch::ArchivalModeConfig {
            epoch_size: 20_000,
            new_epochs_path: dir.path().join("epochs"),
            existing_epochs: vec![],
        }),
    )
    .await?;
    let StateDb::Archive(states) = &db.state_db else { fail!("archival state DB expected") };
    let block = crate::block::BlockStuff::read_block_from_file("src/tests/static/b571525")?;
    let state = crate::shard_state::ShardStateStuff::read_from_file(
        block.id().clone(),
        "src/tests/static/ss571525",
        #[cfg(feature = "telemetry")]
        &db.telemetry,
        &db.allocated,
    )?;
    let handle = db
        .store_block_data(&block, None)
        .await?
        .to_updated()
        .ok_or_else(|| error!("block data not stored"))?;
    let observed = Arc::new(Observed {
        states: states.clone(),
        synced_at_report: Default::default(),
        reported: Default::default(),
    });
    let synced_before = states.wal_synced_count().unwrap_or_default();
    let held = hold_writer(&db).await?;
    let store = {
        let db = &db;
        let handle = handle.clone();
        let state = state.clone();
        let callback = observed.clone() as Arc<dyn storage::shardstate_db_async::Callback>;
        async move { db.store_shard_state_dynamic(&handle, &state, None, Some(callback), false).await }
    };
    tokio::pin!(store);
    let reported_while_held =
        tokio::time::timeout(std::time::Duration::from_millis(500), &mut store).await.is_ok()
            || observed.synced_at_report.lock().unwrap().is_some();
    held.release.notify_one();
    store.await?;
    assert!(!reported_while_held, "state reported saved before its flag was durable");
    let synced_at_report = observed.synced_at_report.lock().unwrap().flatten().unwrap_or_default();
    assert!(
        synced_at_report > synced_before,
        "archival state DB was not synchronized before the state was reported saved"
    );
    assert!(handle.has_saved_state());
    db.stop_states_db().await?;
    Ok(())
}

/// Recovery declares completion only after its metadata is durable: when the
/// final barrier fails, the recovery beacon stays, and the next start repeats
/// recovery and completes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupted_recovery_keeps_its_beacon_and_is_repeated() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("node_db");
    let beacon = root.join("ton_node.restoring");
    {
        let db = open_db(&root).await?;
        std::fs::write(root.join("ton_node.running"), b"")?;
        // Poison the ordered writer: its next commit fails.
        db.recovery_node_db.drop_table(storage::block_handle_db::BLOCK_HANDLE_DB_NAME)?;
        db.create_test_block_handle(&mc(3))?;
        let interrupted = restore::check_db(&db, 0, true, false, &|| Ok(()), None).await;
        assert!(interrupted.is_err(), "recovery completed over a failed metadata barrier");
        assert!(beacon.exists(), "recovery beacon removed before its metadata was durable");
        let _ = db.stop_states_db().await;
    }
    let db = open_db(&root).await?;
    assert!(beacon.exists(), "recovery beacon lost across restart");
    restore::check_db(&db, 0, true, false, &|| Ok(()), None).await?;
    assert!(!beacon.exists(), "repeated recovery did not complete");
    db.stop_states_db().await?;
    Ok(())
}
