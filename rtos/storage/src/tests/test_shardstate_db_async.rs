/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
#[cfg(feature = "telemetry")]
use crate::StorageTelemetry;
use crate::{
    db::rocksdb::{destroy_rocks_db, AccessType, RocksDb},
    shardstate_db_async::{AllowStateGcResolver, CellsDbConfig, ShardStateDb},
    tests::utils::init_test_log,
    StorageAlloc,
};
use rtos_block::{read_single_root_boc, BlockIdExt, Cell, Result, ShardIdent, UInt256};
use std::{
    fs::read,
    path::Path,
    sync::{atomic::AtomicU32, Arc},
    time::Duration,
};

const DB_PATH: &str = "../../target/test";

fn ss_from_file(index: u32) -> Cell {
    let path = format!("src/tests/testdata/{}", index);
    let orig_bytes =
        read(Path::new(&path)).unwrap_or_else(|_| panic!("Error reading file {}", path));

    read_single_root_boc(orig_bytes).expect("Error deserializing shard-state")
}

struct MockedResolver;

impl AllowStateGcResolver for MockedResolver {
    fn allow_state_gc(
        &self,
        block_id: &BlockIdExt,
        _saved_at: u64,
        _gc_utime: u64,
    ) -> Result<bool> {
        Ok(block_id.seq_no() > 2_467_100)
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_shardstate_db_async() -> Result<()> {
    init_test_log();

    const DB_NAME: &str = "test_shardstate_db_async";

    destroy_rocks_db(DB_PATH, DB_NAME).await.unwrap();

    let db = RocksDb::new(DB_PATH, DB_NAME, None, AccessType::ReadWrite)?;
    let ss_db = ShardStateDb::new(
        db.clone(),
        "shardstate_db",
        "cells",
        "counters",
        CellsDbConfig::default(),
        #[cfg(feature = "telemetry")]
        Arc::new(StorageTelemetry::default()),
        Arc::new(StorageAlloc::default()),
    )?;

    ss_db.clone().start_gc(Arc::new(MockedResolver), Arc::new(AtomicU32::new(1)));

    let range = 2_467_080..2_467_119;
    for i in range.clone() {
        let root_cell = ss_from_file(i);
        let block_id_ext = BlockIdExt::with_params(
            ShardIdent::with_tagged_prefix(-1, 0x8000_0000_0000_0000)?,
            i,
            root_cell.repr_hash().clone(),
            UInt256::default(),
        );
        ss_db.put(&block_id_ext, root_cell.clone(), None).await?;
    }

    tokio::time::sleep(Duration::from_secs(5)).await;

    for i in range {
        let root_cell = ss_from_file(i);
        let block_id_ext = BlockIdExt::with_params(
            ShardIdent::with_tagged_prefix(-1, 0x8000_0000_0000_0000)?,
            i,
            root_cell.repr_hash().clone(),
            UInt256::default(),
        );
        let res = ss_db.get(&block_id_ext);

        if block_id_ext.seq_no() > 2_467_100 {
            if res.is_ok() {
                panic!("Should be error");
            }
        } else {
            let loaded_root_cell = res.unwrap();
            assert_eq!(root_cell, loaded_root_cell);
        }
    }

    ss_db.stop().await.unwrap();

    drop(ss_db);
    drop(db);
    destroy_rocks_db(DB_PATH, DB_NAME).await.unwrap();
    Ok(())
}

struct StateDurabilityPause {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
#[async_trait::async_trait]
impl crate::shardstate_db_async::Callback for StateDurabilityPause {
    async fn invoke(&self, _job: crate::shardstate_db_async::Job) {
        self.entered.notify_one();
        self.release.notified().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn publication_durability_state_barrier_waits_for_actual_completion() -> Result<()> {
    let path = std::env::temp_dir().join(format!("rtos-state-barrier-{}", std::process::id()));
    let db = RocksDb::new(&path, "db", None, AccessType::ReadWrite)?;
    let store = ShardStateDb::new(
        db.clone(),
        "states",
        "cells",
        "counters",
        CellsDbConfig::default(),
        #[cfg(feature = "telemetry")]
        Arc::new(StorageTelemetry::default()),
        Arc::new(StorageAlloc::default()),
    )?;
    let pause =
        Arc::new(StateDurabilityPause { entered: Default::default(), release: Default::default() });
    let id = BlockIdExt::default();
    store.put(&id, Cell::default(), Some(pause.clone())).await?;
    pause.entered.notified().await;
    let copy = store.clone();
    let mut barrier = tokio::spawn(async move { copy.sync_pending().await });
    assert!(tokio::time::timeout(Duration::from_millis(20), &mut barrier).await.is_err());
    pause.release.notify_one();
    barrier.await.unwrap()?;
    assert_eq!(store.get(&id)?.repr_hash(), Cell::default().repr_hash());
    store.stop().await.unwrap();
    drop(store);
    drop(db);
    destroy_rocks_db(path.to_str().expect("UTF-8 temporary test path"), "db").await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn publication_durability_state_failure_cannot_ack_a_barrier() -> Result<()> {
    let path = std::env::temp_dir().join(format!("rtos-state-failure-{}", std::process::id()));
    let db = RocksDb::new(&path, "db", None, AccessType::ReadWrite)?;
    let store = ShardStateDb::new(
        db.clone(),
        "states",
        "cells",
        "counters",
        CellsDbConfig::default(),
        #[cfg(feature = "telemetry")]
        Arc::new(StorageTelemetry::default()),
        Arc::new(StorageAlloc::default()),
    )?;
    db.drop_table("states")?;
    store.put(&BlockIdExt::default(), Cell::default(), None).await?;
    assert!(tokio::time::timeout(Duration::from_secs(5), store.sync_pending()).await?.is_err());
    assert!(store.sync_pending().await.is_err());
    store.stop().await.unwrap();
    drop(store);
    drop(db);
    destroy_rocks_db(path.to_str().expect("UTF-8 temporary test path"), "db").await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn state_owner_immediate_stop_joins_unpolled_worker_and_reopens_db() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite)?;
    let states = ShardStateDb::new(db.clone(), "states", "cells", "counters",
        CellsDbConfig::default(),
        #[cfg(feature = "telemetry")]
        Arc::new(StorageTelemetry::default()), Arc::new(StorageAlloc::default()))?;
    // No yield since spawn: current-thread worker has not set MASK_WORKER yet.
    states.stop().await?;
    states.clone().start_gc(Arc::new(MockedResolver), Arc::new(AtomicU32::new(0)));
    assert!(!states.is_gc_run(), "closed storage cannot admit a new GC owner");
    drop(states);
    drop(db);
    let reopened = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite)?;
    drop(reopened);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn state_owner_cancelled_stop_retains_join_until_callback_finishes() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite)?;
    let states = ShardStateDb::new(db.clone(), "states", "cells", "counters",
        CellsDbConfig::default(),
        #[cfg(feature = "telemetry")]
        Arc::new(StorageTelemetry::default()), Arc::new(StorageAlloc::default()))?;
    let pause = Arc::new(StateDurabilityPause { entered: Default::default(), release: Default::default() });
    states.put(&BlockIdExt::default(), Cell::default(), Some(pause.clone())).await?;
    pause.entered.notified().await;
    let owner = states.clone();
    let mut stop = tokio::spawn(async move { owner.stop().await });
    let (waiting, cancelled) = match tokio::time::timeout(Duration::from_millis(20), &mut stop).await {
        Ok(result) => (false, result),
        Err(_) => { stop.abort(); (true, stop.await) },
    };
    pause.release.notify_one();
    let drained = states.stop().await;
    let weak = Arc::downgrade(&db);
    drop(states);
    drop(db);
    assert!(waiting, "stop must wait for actual callback completion");
    assert!(cancelled.unwrap_err().is_cancelled());
    drained?;
    assert!(weak.upgrade().is_none(), "joined task must drop its actual DB ownership");
    Ok(())
}

struct PanickingStateCallback;
#[async_trait::async_trait]
impl crate::shardstate_db_async::Callback for PanickingStateCallback {
    async fn invoke(&self, _: crate::shardstate_db_async::Job) {
        panic!("injected actual state worker panic");
    }
}
#[tokio::test(flavor = "multi_thread")]
async fn state_owner_worker_panic_is_retained_by_every_stop_waiter() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite)?;
    let states = ShardStateDb::new(db.clone(), "states", "cells", "counters",
        CellsDbConfig::default(),
        #[cfg(feature = "telemetry")]
        Arc::new(StorageTelemetry::default()), Arc::new(StorageAlloc::default()))?;
    states.put(&BlockIdExt::default(), Cell::default(), Some(Arc::new(PanickingStateCallback))).await?;
    // Observe actual task termination before setting the stop flag; otherwise
    // normal stop could reject queued work before this callback runs.
    let worker = states.test_worker_completion().await;
    let first = states.stop().await;
    let second = states.stop().await;
    let weak = Arc::downgrade(&db);
    drop(states);
    drop(db);
    assert!(worker.is_err());
    assert!(first.unwrap_err().to_string().contains("injected actual state worker panic"));
    assert!(second.is_err());
    assert!(weak.upgrade().is_none());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn state_owner_gc_admission_racing_stop_has_no_unjoined_db_owner() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite)?;
    let states = ShardStateDb::new(db.clone(), "states", "cells", "counters",
        CellsDbConfig::default(),
        #[cfg(feature = "telemetry")]
        Arc::new(StorageTelemetry::default()), Arc::new(StorageAlloc::default()))?;
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let admission_owner = states.clone();
    let start = barrier.clone();
    let admission = tokio::spawn(async move {
        start.wait().await;
        admission_owner.start_gc(Arc::new(MockedResolver), Arc::new(AtomicU32::new(0)));
    });
    barrier.wait().await;
    let stopped = states.stop().await;
    let admitted = admission.await;
    drop(states);
    drop(db);
    admitted.unwrap();
    stopped?;
    // Either admission won and was joined, or shutdown closed it before spawn.
    let reopened = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite)?;
    drop(reopened);
    Ok(())
}

/// Resolver whose deletion boundary moves only through staged, committed
/// progress, like the node's durable-progress gate.
struct GatedResolver {
    live: AtomicU32,
    committed: AtomicU32,
    staged: std::sync::Mutex<Option<(u64, u32)>>,
    tickets: std::sync::atomic::AtomicU64,
}

impl AllowStateGcResolver for GatedResolver {
    fn allow_state_gc(
        &self,
        block_id: &BlockIdExt,
        _saved_at: u64,
        _gc_utime: u64,
    ) -> Result<bool> {
        Ok(block_id.seq_no() < self.committed.load(std::sync::atomic::Ordering::SeqCst))
    }
    fn stage_gc_progress(&self) -> Option<u64> {
        use std::sync::atomic::Ordering;
        let ticket = self.tickets.fetch_add(1, Ordering::SeqCst) + 1;
        *self.staged.lock().unwrap() = Some((ticket, self.live.load(Ordering::SeqCst)));
        Some(ticket)
    }
    fn commit_gc_progress(&self, ticket: u64) {
        let staged = self.staged.lock().unwrap().take();
        if let Some((staged_ticket, value)) = staged {
            if staged_ticket == ticket {
                self.committed.store(value, std::sync::atomic::Ordering::SeqCst);
            }
        }
    }
}

struct HeldHandleWrite {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
#[async_trait::async_trait]
impl crate::block_handle_db::Callback for HeldHandleWrite {
    async fn invoke(&self, _job: crate::block_handle_db::StoreJob, _ok: bool) {
        self.entered.notify_one();
        self.release.notified().await;
    }
}

/// Returns whether the oldest state was still present while the pointer
/// write that justified its deletion was held in the handle writer, and
/// whether it was deleted after the writer was released.
async fn gc_while_pointer_write_is_held(with_barrier: bool) -> Result<(bool, bool)> {
    use std::sync::atomic::{AtomicU64, Ordering};
    let dir = tempfile::tempdir()?;
    let db = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite)?;
    let states = ShardStateDb::new(
        db.clone(),
        "states",
        "cells",
        "counters",
        CellsDbConfig::default(),
        #[cfg(feature = "telemetry")]
        Arc::new(StorageTelemetry::default()),
        Arc::new(StorageAlloc::default()),
    )?;
    let shard = ShardIdent::with_tagged_prefix(-1, 0x8000_0000_0000_0000)?;
    let mut ids = Vec::new();
    for seq_no in 2_467_080..2_467_084u32 {
        let root = ss_from_file(seq_no);
        let id = BlockIdExt::with_params(
            shard.clone(),
            seq_no,
            root.repr_hash().clone(),
            UInt256::default(),
        );
        states.put(&id, root, None).await?;
        ids.push(id);
    }
    states.sync_pending().await?;
    let (handles, _) = crate::tests::utils::create_block_handle_storage(db.clone());
    let handles = Arc::new(handles);
    let hold =
        Arc::new(HeldHandleWrite { entered: Default::default(), release: Default::default() });
    let blocker = handles
        .create_handle(BlockIdExt::default(), crate::types::BlockMeta::default(), None)?
        .ok_or_else(|| rtos_block::error!("blocker handle exists"))?;
    handles.save_handle(&blocker, Some(hold.clone()))?;
    hold.entered.notified().await;
    // The pointer that makes the two oldest states unnecessary is queued, not
    // durable; the resolver's live progress already reflects it.
    handles.save_full_node_state("ShardClient".to_owned(), &ids[2])?;
    let resolver = Arc::new(GatedResolver {
        live: AtomicU32::new(ids[2].seq_no()),
        committed: AtomicU32::new(0),
        staged: Default::default(),
        tickets: AtomicU64::new(0),
    });
    if with_barrier {
        let barrier_handles = handles.clone();
        let barrier: crate::shardstate_db_async::GcProgressBarrier = Arc::new(move || {
            let handles = barrier_handles.clone();
            Box::pin(async move { handles.sync_pending().await })
        });
        states.clone().start_gc_with_progress_barrier(
            resolver.clone(),
            Arc::new(AtomicU32::new(1)),
            Some(barrier),
        );
    } else {
        // Control: progress committed without any barrier.
        resolver.committed.store(resolver.live.load(Ordering::SeqCst), Ordering::SeqCst);
        states.clone().start_gc(resolver.clone(), Arc::new(AtomicU32::new(1)));
    }
    tokio::time::sleep(Duration::from_millis(3500)).await;
    let present_while_held = states.get(&ids[0]).is_ok();
    hold.release.notify_one();
    let mut deleted_after = false;
    for _ in 0..60 {
        if states.get(&ids[0]).is_err() {
            deleted_after = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    if with_barrier && deleted_after {
        // Deletion followed the durable pointer.
        let pointer =
            crate::block_handle_db::NodeStateDb::with_db(db.clone(), "full_node_states", false)?;
        assert!(pointer.try_get_raw(b"ShardClient")?.is_some());
    }
    assert!(states.get(&ids[3]).is_ok(), "state above the boundary was deleted");
    states.stop().await?;
    Ok((present_while_held, deleted_after))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn state_gc_waits_for_durable_progress_pointer() -> Result<()> {
    let (present_while_held, deleted_after) = gc_while_pointer_write_is_held(true).await?;
    assert!(present_while_held, "state deleted while its authorizing pointer was not durable");
    assert!(deleted_after, "state not deleted after the pointer became durable");
    Ok(())
}

/// Control for the test above: without the barrier the same fixture deletes
/// while the pointer write is still held, so the test can see the race.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn state_gc_without_progress_barrier_deletes_before_pointer_is_durable() -> Result<()> {
    let (present_while_held, _) = gc_while_pointer_write_is_held(false).await?;
    assert!(!present_while_held, "control fixture did not exercise the race");
    Ok(())
}
