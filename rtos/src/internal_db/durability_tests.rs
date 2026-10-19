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
    let early = tokio::time::timeout(std::time::Duration::from_millis(500), &mut gc).await;
    let finished_while_held = early.is_ok();
    let stored = |key: &str| -> Result<bool> {
        Ok(db.full_node_state_db.try_get_raw(key.as_bytes())?.is_some())
    };
    let authority_while_held = stored(LAST_UNNEEDED_KEY_BLOCK)?;
    held.release.notify_one();
    match early {
        Ok(joined) => joined.map_err(|e| error!("{e}"))??,
        Err(_) => gc.await.map_err(|e| error!("{e}"))??,
    }
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

/// Reads the stored handle record, bypassing every in-memory cache.
fn stored_handle(db: &InternalDb, id: &BlockIdExt) -> Result<Option<Arc<BlockHandle>>> {
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
    reader.load_handle_by_id(id)
}

/// A durable applied flag is in the database when the call returns, even
/// while the ordered writer is held in a callback.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_applied_flag_is_stored_on_return() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = open_db(dir.path()).await?;
    let handle = db.create_test_block_handle(&mc(9))?;
    db.block_handle_storage.sync_pending().await?;
    let held = hold_writer(&db).await?;
    let applied = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        db.store_block_applied_durable(&handle),
    )
    .await;
    let stored = stored_handle(&db, &mc(9))?;
    held.release.notify_one();
    assert!(applied.map_err(|_| error!("durable applied write did not return"))??);
    assert!(stored.is_some_and(|handle| handle.is_applied()), "applied flag not stored on return");
    db.stop_states_db().await?;
    Ok(())
}

/// A notification that reports a state saved, with what was stored when it
/// fired.
struct ReportProbe {
    db: Arc<InternalDb>,
    id: BlockIdExt,
    archival_syncs: std::sync::Mutex<Option<Option<u64>>>,
    stored_saved: std::sync::Mutex<Option<bool>>,
    reported: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl storage::shardstate_db_async::Callback for ReportProbe {
    async fn invoke(&self, _job: storage::shardstate_db_async::Job) {
        if let StateDb::Archive(states) = &self.db.state_db {
            *self.archival_syncs.lock().unwrap() = Some(states.wal_synced_count());
        }
        let saved = stored_handle(&self.db, &self.id)
            .ok()
            .flatten()
            .is_some_and(|handle| handle.has_saved_state());
        *self.stored_saved.lock().unwrap() = Some(saved);
        self.reported.notify_one();
    }
}

/// Stores the fixture state with a report probe while the ordered writer is
/// held, and returns the probe after the report.
async fn report_saved_state(db: Arc<InternalDb>) -> Result<Arc<ReportProbe>> {
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
    db.block_handle_storage.sync_pending().await?;
    let probe = Arc::new(ReportProbe {
        db: db.clone(),
        id: block.id().clone(),
        archival_syncs: Default::default(),
        stored_saved: Default::default(),
        reported: Default::default(),
    });
    let held = hold_writer(&db).await?;
    let reported = probe.reported.notified();
    db.store_shard_state_dynamic(
        &handle,
        &state,
        None,
        Some(probe.clone() as Arc<dyn storage::shardstate_db_async::Callback>),
        false,
    )
    .await?;
    let result = tokio::time::timeout(std::time::Duration::from_secs(20), reported).await;
    held.release.notify_one();
    result.map_err(|_| error!("saved state never reported"))?;
    Ok(probe)
}

/// Archival mode: when the state is reported saved, the separate archival
/// state database has been synchronized and the saved flag is stored.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn archival_state_is_durable_before_it_is_reported_saved() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = Arc::new(
        open_db_with(
            &dir.path().join("node_db"),
            Some(storage::archives::epoch::ArchivalModeConfig {
                epoch_size: 20_000,
                new_epochs_path: dir.path().join("epochs"),
                existing_epochs: vec![],
            }),
        )
        .await?,
    );
    let StateDb::Archive(states) = &db.state_db else { fail!("archival state DB expected") };
    let synced_before = states.wal_synced_count().unwrap_or_default();
    let probe = report_saved_state(db.clone()).await?;
    let synced_at_report = probe.archival_syncs.lock().unwrap().flatten().unwrap_or_default();
    assert!(
        synced_at_report > synced_before,
        "archival state DB was not synchronized before the state was reported saved"
    );
    assert_eq!(*probe.stored_saved.lock().unwrap(), Some(true), "saved flag not stored at report");
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

/// Dynamic mode: when the state is reported saved, the saved flag is stored;
/// its synchronized write also covers the state written before it on the
/// same WAL. The report does not wait for a writer callback.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dynamic_state_is_reported_saved_only_after_durable_flag() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = Arc::new(open_db(dir.path()).await?);
    let probe = report_saved_state(db.clone()).await?;
    assert_eq!(*probe.stored_saved.lock().unwrap(), Some(true), "saved flag not stored at report");
    db.stop_states_db().await?;
    Ok(())
}
