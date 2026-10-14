// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Real refcounted state WAL failures: typed bounded result and ordinary callback.
use super::*;
use crate::{
    db::node::{open_node_db, CELLSCOUNTERS_CF_NAME, CELLS_CF_NAME},
    tests::disk_full_state_support as support,
};
use rtos_block::write_boc;
use std::{path::Path, sync::atomic::AtomicUsize};
const TIMEOUT: Duration = Duration::from_secs(10);
fn open(path: &Path) -> (Arc<RocksDb>, Arc<ShardStateDb>) {
    let db =
        open_node_db(path, &support::config(), crate::db::rocksdb::AccessType::ReadWrite).unwrap();
    let states = ShardStateDb::new(
        db.clone(),
        "state_index",
        CELLS_CF_NAME,
        CELLSCOUNTERS_CF_NAME,
        support::config(),
        #[cfg(feature = "telemetry")]
        Arc::new(StorageTelemetry::default()),
        Arc::new(StorageAlloc::default()),
    )
    .unwrap();
    (db, states)
}
async fn close(db: Arc<RocksDb>, states: Arc<ShardStateDb>) {
    tokio::time::timeout(TIMEOUT, states.stop()).await.expect("state stop timed out").unwrap();
    drop(states);
    tokio::time::timeout(TIMEOUT, async {
        while Arc::strong_count(&db) != 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("state physical owner did not drain");
    drop(db);
}
async fn bounded(states: &ShardStateDb, seq: u8) -> Result<()> {
    let (id, root) = support::graph(seq);
    tokio::time::timeout(
        TIMEOUT,
        states.put_bounded(&id, root, support::LIMITS, support::Budget::new()),
    )
    .await
    .expect("bounded state reply timed out")
}
struct Receipt {
    count: AtomicUsize,
    notify: tokio::sync::Notify,
}
impl Receipt {
    fn new() -> Arc<Self> {
        Arc::new(Self { count: AtomicUsize::new(0), notify: tokio::sync::Notify::new() })
    }
    async fn success(&self) {
        tokio::time::timeout(TIMEOUT, async {
            while self.count.load(Ordering::SeqCst) == 0 {
                self.notify.notified().await;
            }
        })
        .await
        .expect("ordinary success callback timed out");
        assert_eq!(self.count.load(Ordering::SeqCst), 1);
    }
}
#[async_trait::async_trait]
impl Callback for Receipt {
    async fn invoke(&self, _: Job) {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.notify.notify_one();
    }
}
async fn ordinary(states: &ShardStateDb, seq: u8, receipt: Arc<Receipt>) {
    let (id, root) = support::graph(seq);
    tokio::time::timeout(TIMEOUT, states.put(&id, root, Some(receipt)))
        .await
        .expect("ordinary admission timed out")
        .unwrap();
}
fn inspect(db: &Arc<RocksDb>, states: &ShardStateDb, seed: &[u8]) -> [bool; 3] {
    let mut present = [false; 3];
    for seq in 1..=3 {
        let (id, root) = support::graph(seq);
        let stored = states.shardstate_db.try_get(&id).unwrap();
        if let Some(bytes) = stored {
            support::check_index(&bytes, &id, &root);
            if seq == 1 {
                assert_eq!(bytes.as_ref(), seed, "acknowledged index changed");
            }
            let read = states.get(&id).unwrap();
            assert_eq!(write_boc(&read).unwrap(), write_boc(&root).unwrap());
            support::check_cell(db, &root);
            present[usize::from(seq - 1)] = true;
        } else {
            assert!(support::raw_cell(db, &root).is_none(), "orphan target root after WAL failure");
        }
    }
    assert!(present[0], "acknowledged state lost");
    support::check_cell(db, &support::child());
    support::check_counts(db, &present);
    present
}
async fn exercise(ordinary_mode: bool, live: bool) {
    let kind = if ordinary_mode { "ordinary" } else { "bounded" };
    let mode = if live { "live" } else { "cold" };
    let case = format!("state-{kind}-{mode}");
    let path = support::root(&case);
    std::fs::create_dir_all(&path).unwrap();
    let control = support::control();
    let (db, states) = open(&path);
    if ordinary_mode {
        let receipt = Receipt::new();
        ordinary(&states, 1, receipt.clone()).await;
        receipt.success().await;
    } else {
        bounded(&states, 1).await.unwrap();
    }
    tokio::time::timeout(TIMEOUT, states.sync_pending()).await.unwrap().unwrap();
    let seed = states.shardstate_db.get(&support::graph(1).0).unwrap().to_vec();
    inspect(&db, &states, &seed);
    support::flush(&db);
    let filler = if control { None } else { Some(support::fill(&path)) };
    let failed_callback = Receipt::new();
    if ordinary_mode {
        let mut failure = states.write_failure.subscribe();
        ordinary(&states, 2, failed_callback.clone()).await; // Admission is not acknowledgement.
        if control {
            failed_callback.success().await;
        } else {
            let reason = tokio::time::timeout(TIMEOUT, async {
                loop {
                    if let Some(reason) = failure.borrow().clone() {
                        break reason;
                    }
                    failure.changed().await.unwrap();
                }
            })
            .await
            .expect("actual state failure watch timed out");
            assert!(reason.contains("No space left") || reason.contains("ENOSPC"), "{reason}");
            assert_eq!(
                failed_callback.count.load(Ordering::SeqCst),
                0,
                "failed state invoked success callback"
            );
        }
    } else {
        let result = bounded(&states, 2).await;
        assert_eq!(result.is_ok(), control, "state acknowledgement: {result:?}");
        if let Err(error) = result {
            support::check_enospc(&error);
        }
    }
    if let Some(filler) = filler {
        std::fs::remove_file(filler).unwrap();
    }
    let barrier = tokio::time::timeout(TIMEOUT, states.sync_pending())
        .await
        .expect("failure barrier timed out");
    assert_eq!(barrier.is_ok(), control, "state failure barrier: {barrier:?}");
    if live {
        let probe = bounded(&states, 3).await;
        assert_eq!(probe.is_ok(), control, "independent state probe: {probe:?}");
    }
    close(db, states).await;
    assert_eq!(
        failed_callback.count.load(Ordering::SeqCst),
        if ordinary_mode && control { 1 } else { 0 },
        "failed state invoked success callback during stop"
    );
    let (db, states) = open(&path);
    let present = inspect(&db, &states, &seed); // Before ANY target retry.
    if control {
        assert!(present[1]);
    }
    assert_eq!(present[2], live && control);
    if ordinary_mode {
        let receipt = Receipt::new();
        ordinary(&states, 2, receipt.clone()).await;
        receipt.success().await;
    } else {
        bounded(&states, 2).await.unwrap();
    }
    tokio::time::timeout(TIMEOUT, states.sync_pending()).await.unwrap().unwrap();
    let expected = inspect(&db, &states, &seed);
    assert!(expected[1]);
    // Idempotent save must not inflate references to an already indexed root.
    bounded(&states, 2).await.unwrap();
    assert_eq!(inspect(&db, &states, &seed), expected);
    close(db, states).await;
    let (db, states) = open(&path);
    assert_eq!(inspect(&db, &states, &seed), expected);
    close(db, states).await;
    eprintln!("ENOSPC-CASE {case} {} ok", if control { "control" } else { "fault" });
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated ENOSPC tmpfs and syscall trace"]
async fn disk_full_state_bounded_live() {
    exercise(false, true).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated ENOSPC tmpfs and syscall trace"]
async fn disk_full_state_bounded_cold() {
    exercise(false, false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated ENOSPC tmpfs and syscall trace"]
async fn disk_full_state_ordinary_cold() {
    exercise(true, false).await;
}
