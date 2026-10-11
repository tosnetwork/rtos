// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::db::node::{open_node_db, CELLSCOUNTERS_CF_NAME, CELLS_CF_NAME};
use rtos_block::{
    merkle_apply_budget::{MerkleApplyBudget, MerkleApplyLimitExceeded, MerkleApplyLimits},
    write_boc, BuilderData, ShardIdent,
};
use std::sync::{atomic::AtomicUsize, Mutex};

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
fn open(path: &std::path::Path) -> Result<(Arc<RocksDb>, Arc<ShardStateDb>)> {
    let db = open_node_db(path, &config(), crate::db::rocksdb::AccessType::ReadWrite)?;
    let states = ShardStateDb::new(
        db.clone(),
        "bounded_states",
        CELLS_CF_NAME,
        CELLSCOUNTERS_CF_NAME,
        config(),
        #[cfg(feature = "telemetry")]
        Arc::new(StorageTelemetry::default()),
        Arc::new(StorageAlloc::default()),
    )?;
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
fn count(db: &Arc<RocksDb>, cell: &Cell) -> Result<Option<u32>> {
    let table = db.clone().table::<UInt256>(CELLSCOUNTERS_CF_NAME, false)?;
    let value = table
        .try_get_raw(cell.repr_hash().as_slice())?
        .map(|raw| u32::from_le_bytes(raw[..].try_into().unwrap()));
    Ok(value)
}
async fn close(db: Arc<RocksDb>, states: Arc<ShardStateDb>) -> Result<()> {
    states.stop().await.unwrap();
    drop(states);
    tokio::time::timeout(Duration::from_secs(10), async {
        while Arc::strong_count(&db) > 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    drop(db);
    Ok(())
}
async fn delete(states: &ShardStateDb, id: &BlockIdExt) -> Result<()> {
    states.in_queue.fetch_add(1, Ordering::Relaxed);
    states
        .storer
        .send(StateCommand::Work(Job::DeleteState(id.clone()), None))
        .map_err(|e| error!("delete queue: {e}"))?;
    states.sync_pending().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_state_writer_idempotent_shared_root_and_real_delete_reopen() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (db, states) = open(dir.path())?;
    let (root, child, first, second) = fixture();
    states.put_bounded(&first, root.clone(), LIMITS, Budget::new(usize::MAX)).await?;
    states.put_bounded(&first, root.clone(), LIMITS, Budget::new(usize::MAX)).await?;
    assert_eq!(count(&db, &root)?, Some(1));
    assert_eq!(count(&db, &child)?, Some(2));
    states.put_bounded(&second, root.clone(), LIMITS, Budget::new(usize::MAX)).await?;
    assert_eq!(count(&db, &root)?, Some(2));
    assert_eq!(count(&db, &child)?, Some(2));
    delete(&states, &first).await?;
    close(db, states).await?;
    let (db, states) = open(dir.path())?;
    assert!(!states.contains_state_record(&first)?);
    assert_eq!(write_boc(&states.get(&second)?)?, write_boc(&root)?);
    assert_eq!(count(&db, &root)?, Some(1));
    assert_eq!(count(&db, &child)?, Some(2));
    delete(&states, &second).await?;
    close(db, states).await?;
    let (db, states) = open(dir.path())?;
    assert!(!states.contains_state_record(&second)?);
    assert_eq!(count(&db, &root)?, None);
    assert_eq!(count(&db, &child)?, None);
    close(db, states).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_state_writer_admission_exact_and_reject_before_mutation() -> Result<()> {
    let (root, _, first, _) = fixture();
    let measured = Budget::new(usize::MAX);
    let dir = tempfile::tempdir()?;
    let (db, states) = open(dir.path())?;
    states.put_bounded(&first, root.clone(), LIMITS, measured.clone()).await?;
    let exact = measured.used.load(Ordering::SeqCst);
    close(db, states).await?;
    for limit in [0, exact - 1, exact] {
        let dir = tempfile::tempdir()?;
        let (db, states) = open(dir.path())?;
        let result = states.put_bounded(&first, root.clone(), LIMITS, Budget::new(limit)).await;
        if limit == exact {
            result?;
            assert_eq!(write_boc(&states.get(&first)?)?, write_boc(&root)?);
        } else {
            assert!(result.is_err());
            assert!(!states.contains_state_record(&first)?);
            assert!(db.clone().table::<UInt256>(CELLS_CF_NAME, false)?.is_empty()?);
            assert!(db.clone().table::<UInt256>(CELLSCOUNTERS_CF_NAME, false)?.is_empty()?);
            // A quota rejection does not poison the ordinary queue or retry.
            states.put_bounded(&first, root.clone(), LIMITS, Budget::new(exact)).await?;
        }
        close(db, states).await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_state_writer_rejects_corrupt_existing_payload_without_mutation() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (db, states) = open(dir.path())?;
    let (root, _, first, second) = fixture();
    states.put_bounded(&first, root.clone(), LIMITS, Budget::new(usize::MAX)).await?;
    let table = db.clone().table::<UInt256>(CELLS_CF_NAME, false)?;
    let mut corrupt = table.get(&root.repr_hash())?.to_vec();
    corrupt[2] ^= 1;
    table.put_raw(root.repr_hash().as_slice(), &corrupt)?;
    assert!(states
        .put_bounded(&second, root.clone(), LIMITS, Budget::new(usize::MAX))
        .await
        .is_err());
    assert_eq!(table.get(&root.repr_hash())?.as_ref(), corrupt.as_slice());
    assert_eq!(count(&db, &root)?, Some(1));
    assert!(!states.contains_state_record(&second)?);
    drop(table);
    close(db, states).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_state_writer_cancelled_observer_retains_actual_budget_owner() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (db, states) = open(dir.path())?;
    let (root, _, first, _) = fixture();
    let budget = Budget::new(usize::MAX);
    let weak = Arc::downgrade(&budget);
    let (entered, observed) = tokio::sync::oneshot::channel();
    let (release, gate) = std::sync::mpsc::channel();
    *budget.gate.lock().unwrap() = Some((entered, gate));
    let owned = states.clone();
    let target = first.clone();
    let candidate = root.clone();
    let observer =
        tokio::spawn(async move { owned.put_bounded(&target, candidate, LIMITS, budget).await });
    tokio::time::timeout(Duration::from_secs(10), observed).await??;
    observer.abort();
    assert!(observer.await.unwrap_err().is_cancelled());
    assert!(weak.upgrade().is_some(), "actual writer still owns request admission");
    release.send(()).unwrap();
    states.sync_pending().await?;
    assert_eq!(write_boc(&states.get(&first)?)?, write_boc(&root)?);
    tokio::time::timeout(Duration::from_secs(10), async {
        while weak.upgrade().is_some() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    close(db, states).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_state_writer_existing_index_missing_root_does_not_guess_refcounts() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (db, states) = open(dir.path())?;
    let (root, child, first, _) = fixture();
    states.put_bounded(&first, root.clone(), LIMITS, Budget::new(usize::MAX)).await?;
    let cells = db.clone().table::<UInt256>(CELLS_CF_NAME, false)?;
    let counters = db.clone().table::<UInt256>(CELLSCOUNTERS_CF_NAME, false)?;
    cells.delete_raw(root.repr_hash().as_slice())?;
    counters.delete_raw(root.repr_hash().as_slice())?;
    assert!(states
        .put_bounded(&first, root.clone(), LIMITS, Budget::new(usize::MAX))
        .await
        .is_err());
    assert!(states.contains_state_record(&first)?);
    assert_eq!(count(&db, &root)?, None);
    assert_eq!(count(&db, &child)?, Some(2), "failed repair cannot count old root edges twice");
    assert!(cells.try_get_raw(root.repr_hash().as_slice())?.is_none());
    drop(cells);
    drop(counters);
    close(db, states).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_state_writer_wal_failure_poison_and_reopen_idempotency() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (db, states) = open(dir.path())?;
    let (root, child, first, _) = fixture();
    let observer: Arc<crate::durability::SyncObserver> = Arc::new(|point, _| {
        assert_eq!(point, crate::durability::SyncPoint::Wal);
        fail!("injected actual bounded writer WAL failure")
    });
    let error = states
        .put_bounded_observed(&first, root.clone(), LIMITS, Budget::new(usize::MAX), Some(observer))
        .await
        .unwrap_err();
    assert!(error.downcast_ref::<crate::dynamic_boc_rc_db::BoundedStateWriteFailure>().is_some());
    assert!(states.sync_pending().await.is_err(), "uncertain write must never acknowledge barrier");
    assert!(states
        .put_bounded(&first, root.clone(), LIMITS, Budget::new(usize::MAX))
        .await
        .is_err());
    close(db, states).await?;
    // This clean close is a retry/idempotency check, not a power-loss claim.
    let (db, states) = open(dir.path())?;
    states.put_bounded(&first, root.clone(), LIMITS, Budget::new(usize::MAX)).await?;
    assert_eq!(write_boc(&states.get(&first)?)?, write_boc(&root)?);
    assert_eq!(count(&db, &root)?, Some(1));
    assert_eq!(count(&db, &child)?, Some(2));
    close(db, states).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_state_writer_absence_reservation_excludes_real_writer() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (db, states) = open(dir.path())?;
    let (root, _, first, _) = fixture();
    let (entered, observed) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let owner = states.clone();
    let id = first.clone();
    let reservation = std::thread::spawn(move || {
        owner.with_absent_state(&id, || {
            assert!(owner.bounded_read_gate.try_write().is_err());
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
    assert_eq!(
        states
            .with_absent_state(&first, || -> Result<()> { panic!("existing must not reserve") })?,
        None
    );
    close(db, states).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persistent_repair_custody_preselected_delete_rechecks_at_actual_transaction() -> Result<()>
{
    let dir = tempfile::tempdir()?;
    let (db, states) = open(dir.path())?;
    let (root, child, first, second) = fixture();
    states.put_bounded(&first, root.clone(), LIMITS, Budget::new(usize::MAX)).await?;
    let budget = Budget::new(usize::MAX);
    let (entered, observed) = tokio::sync::oneshot::channel();
    let (release, gate) = std::sync::mpsc::channel();
    *budget.gate.lock().unwrap() = Some((entered, gate));
    let writer = {
        let owner = states.clone();
        let id = second.clone();
        let cell = root.clone();
        tokio::spawn(async move { owner.put_bounded(&id, cell, LIMITS, budget).await })
    };
    tokio::time::timeout(Duration::from_secs(10), observed).await??;
    // A decision and queue admission happened before registration. Only the
    // actual delete consumer can prevent this old work item from deleting.
    states.in_queue.fetch_add(1, Ordering::Relaxed);
    states.storer.send(StateCommand::Work(Job::DeleteState(first.clone()), None)).unwrap();
    let authentication = db.repair_protection().authentication().await?;
    db.repair_protection().protect([first.clone()], []);
    drop(authentication);
    release.send(())?;
    writer.await??;
    states.sync_pending().await?;
    assert!(states.contains_state_record(&first)?);
    assert_eq!(write_boc(&states.get(&first)?)?, write_boc(&root)?);
    assert_eq!(count(&db, &root)?, Some(2));
    assert_eq!(count(&db, &child)?, Some(2));
    delete(&states, &second).await?;
    assert!(!states.contains_state_record(&second)?, "unleased control is actually deleted");
    assert_eq!(count(&db, &root)?, Some(1));
    close(db, states).await
}
