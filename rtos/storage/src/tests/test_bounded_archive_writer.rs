// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::db::node::{open_node_db, CELLS_CF_NAME};
use rtos_block::{
    error, fail, merkle_apply_budget::MerkleApplyLimitExceeded, write_boc, BuilderData, ShardIdent,
};
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
struct Budget {
    max: usize,
    used: AtomicUsize,
    gate: Mutex<Option<(tokio::sync::oneshot::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
}
impl Budget {
    fn new(max: usize) -> Arc<Self> {
        Arc::new(Self { max, used: AtomicUsize::new(0), gate: Mutex::new(None) })
    }
}
impl MerkleApplyBudget for Budget {
    fn step(&self) -> Result<()> {
        Ok(())
    }
    fn workspace(&self, bytes: usize) -> Result<()> {
        if bytes == 2048 {
            if let Some((entered, release)) = self.gate.lock().unwrap().take() {
                let _ = entered.send(());
                release.recv().map_err(|e| error!("writer gate: {e}"))?;
            }
        }
        let old = self.used.fetch_add(bytes, Ordering::SeqCst);
        if old.checked_add(bytes).is_none_or(|n| n > self.max) {
            return Err(MerkleApplyLimitExceeded("writer test allocation").into());
        }
        Ok(())
    }
    fn new_cell(&self, _: usize) -> Result<()> {
        fail!("writer must not rebuild graph cells")
    }
    fn max_depth(&self) -> u16 {
        128
    }
}
const LIMITS: MerkleApplyLimits = MerkleApplyLimits { max_entries: 64, max_depth: 128 };
fn config() -> CellsDbConfig {
    let mut config = CellsDbConfig::default();
    config.cells_lru_cache_capacity = 64;
    config.counters_lru_cache_capacity = 64;
    config.cells_cache_size_bytes = 1 << 20;
    config.counters_cache_size_bytes = 1 << 20;
    config
}
fn open(path: &std::path::Path) -> Result<(Arc<RocksDb>, Arc<ArchiveShardStateDb>)> {
    let db = open_node_db(path, &config(), crate::db::rocksdb::AccessType::ReadWrite)?;
    let states = Arc::new(ArchiveShardStateDb::new(
        db.clone(),
        "bounded_archive_states",
        CELLS_CF_NAME,
        &config(),
        #[cfg(feature = "telemetry")]
        Arc::new(StorageTelemetry::default()),
        Arc::new(StorageAlloc::default()),
    )?);
    Ok((db, states))
}
fn fixture() -> (Cell, Cell, BlockIdExt, BlockIdExt) {
    let child = BuilderData::with_raw(vec![7], 8).unwrap().into_cell().unwrap();
    let mut builder = BuilderData::with_raw(vec![8], 8).unwrap();
    builder.checked_append_reference(child.clone()).unwrap();
    builder.checked_append_reference(child.clone()).unwrap();
    let root = builder.into_cell().unwrap();
    let id = |seq| {
        BlockIdExt::with_params(
            ShardIdent::masterchain(),
            seq,
            UInt256::from([seq as u8; 32]),
            UInt256::default(),
        )
    };
    let first = id(1);
    let second = id(2);
    (root, child, first, second)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_state_archive_admission_idempotency_and_cold_read() -> Result<()> {
    let (root, _, first, second) = fixture();
    let dir = tempfile::tempdir()?;
    let (db, states) = open(dir.path())?;
    assert_eq!(states.with_absent_state(&first, || Ok(7))?, Some(7));
    assert!(states.put_bounded(&first, root.clone(), LIMITS, Budget::new(0)).await.is_err());
    assert!(!states.contains_state_record(&first)?);
    assert!(db.clone().table::<UInt256>(CELLS_CF_NAME, false)?.is_empty()?);
    states.put_bounded(&first, root.clone(), LIMITS, Budget::new(usize::MAX)).await?;
    assert_eq!(
        states
            .with_absent_state(&first, || -> Result<()> { panic!("existing must not reserve") })?,
        None
    );
    states.put_bounded(&first, root.clone(), LIMITS, Budget::new(usize::MAX)).await?;
    states.put_bounded(&second, root.clone(), LIMITS, Budget::new(usize::MAX)).await?;
    drop(states);
    drop(db);
    let (_db, states) = open(dir.path())?;
    assert_eq!(write_boc(&states.get(&first)?)?, write_boc(&root)?);
    assert_eq!(write_boc(&states.get(&second)?)?, write_boc(&root)?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_state_archive_corruption_and_missing_index_root_reject() -> Result<()> {
    for missing in [false, true] {
        let dir = tempfile::tempdir()?;
        let (db, states) = open(dir.path())?;
        let (root, _, first, second) = fixture();
        states.put_bounded(&first, root.clone(), LIMITS, Budget::new(usize::MAX)).await?;
        let cells = db.clone().table::<UInt256>(CELLS_CF_NAME, false)?;
        let mut corrupt = cells.get(root.repr_hash())?.to_vec();
        if missing {
            cells.delete(root.repr_hash())?;
        } else {
            corrupt[2] ^= 1;
            cells.put(root.repr_hash(), &corrupt)?;
        }
        let target = if missing { &first } else { &second };
        assert!(states
            .put_bounded(target, root.clone(), LIMITS, Budget::new(usize::MAX))
            .await
            .is_err());
        assert!(!states.contains_state_record(&second)?);
        if missing {
            assert!(cells.try_get(root.repr_hash())?.is_none());
        } else {
            assert_eq!(cells.get(root.repr_hash())?.as_ref(), corrupt.as_slice());
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_state_archive_cancelled_observer_retains_writer_through_wal() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (_db, states) = open(dir.path())?;
    let (root, _, first, _) = fixture();
    let budget = Budget::new(usize::MAX);
    let weak = Arc::downgrade(&budget);
    let (entered, observed) = tokio::sync::oneshot::channel();
    let (release, gate) = std::sync::mpsc::channel();
    let gate = Mutex::new(Some((entered, gate)));
    let hook: Arc<crate::durability::SyncObserver> = Arc::new(move |point, _| {
        assert_eq!(point, crate::durability::SyncPoint::Wal);
        let (entered, release) = gate.lock().unwrap().take().unwrap();
        let _ = entered.send(());
        release.recv().map_err(|e| error!("WAL pause: {e}"))?;
        Ok(())
    });
    let owned = states.clone();
    let target = first.clone();
    let candidate = root.clone();
    let observer = tokio::spawn(async move {
        owned.put_bounded_observed(&target, candidate, LIMITS, budget, Some(hook)).await
    });
    tokio::time::timeout(Duration::from_secs(10), observed).await??;
    observer.abort();
    assert!(observer.await.unwrap_err().is_cancelled());
    assert!(weak.upgrade().is_some(), "blocking writer retains admission at actual WAL");
    release.send(()).unwrap();
    let barrier = states.clone();
    tokio::task::spawn_blocking(move || barrier.sync_wal()).await??;
    assert_eq!(write_boc(&states.get(&first)?)?, write_boc(&root)?);
    tokio::time::timeout(Duration::from_secs(10), async {
        while weak.upgrade().is_some() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_state_archive_wal_poison_all_writers_and_cold_retry() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (db, states) = open(dir.path())?;
    let (root, _, first, second) = fixture();
    let hook: Arc<crate::durability::SyncObserver> =
        Arc::new(|_, _| fail!("actual archive WAL fault"));
    let error = states
        .put_bounded_observed(&first, root.clone(), LIMITS, Budget::new(usize::MAX), Some(hook))
        .await
        .unwrap_err();
    assert!(error.downcast_ref::<crate::dynamic_boc_rc_db::BoundedStateWriteFailure>().is_some());
    assert!(states.sync_wal().is_err());
    assert!(states.put(&second, root.clone()).is_err());
    assert!(states.put_update(&second, root.clone()).is_err());
    assert!(states.with_absent_state(&second, || Ok(())).is_err());
    assert!(states
        .put_bounded(&second, root.clone(), LIMITS, Budget::new(usize::MAX))
        .await
        .is_err());
    drop(states);
    drop(db);
    // Clean reopen/idempotency, not a power-loss assertion.
    let (_db, states) = open(dir.path())?;
    states.put_bounded(&first, root.clone(), LIMITS, Budget::new(usize::MAX)).await?;
    assert_eq!(write_boc(&states.get(&first)?)?, write_boc(&root)?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_state_archive_absence_reservation_excludes_real_writer() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (_db, states) = open(dir.path())?;
    let (root, _, first, _) = fixture();
    let (entered, observed) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let owner = states.clone();
    let id = first.clone();
    let reservation = std::thread::spawn(move || {
        owner.with_absent_state(&id, || {
            assert!(owner.write_gate.try_lock().is_err());
            let _ = entered.send(());
            wait.recv()?;
            assert!(!owner.contains_state_record(&id)?);
            Ok(())
        })
    });
    tokio::time::timeout(Duration::from_secs(10), observed).await??;
    let owner = states.clone();
    let id = first.clone();
    let mut writer =
        tokio::spawn(
            async move { owner.put_bounded(&id, root, LIMITS, Budget::new(usize::MAX)).await },
        );
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut writer).await.is_err());
    release.send(())?;
    assert_eq!(reservation.join().unwrap()?, Some(()));
    writer.await??;
    assert!(states.contains_state_record(&first)?);
    Ok(())
}
