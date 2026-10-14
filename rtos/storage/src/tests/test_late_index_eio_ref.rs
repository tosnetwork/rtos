// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{
    db::node::{open_node_db, CELLSCOUNTERS_CF_NAME, CELLS_CF_NAME},
    tests::{disk_full_state_support as support, late_index_eio_support as late},
};
use late::TIMEOUT;
use std::{path::Path, sync::atomic::AtomicUsize};
const CF: &str = "late_index_ref_state";
fn open(path: &Path) -> (Arc<RocksDb>, Arc<ShardStateDb>) {
    let db =
        open_node_db(path, &support::config(), crate::db::rocksdb::AccessType::ReadWrite).unwrap();
    let states = ShardStateDb::new(
        db.clone(),
        CF,
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
    tokio::time::timeout(TIMEOUT, states.stop())
        .await
        .expect("stop timeout; cold forbidden")
        .unwrap();
    drop(states);
    late::close_db(db).await;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated native WAL-body EIO harness"]
async fn ordinary_late_index_eio() {
    let path = late::root().join("db");
    let control = late::control();
    let (db, states) = open(&path);
    for seq in 0..2 {
        let receipt = Receipt::new();
        ordinary(&states, seq, receipt.clone()).await;
        receipt.success().await;
    }
    states.sync_pending().await.unwrap();
    let seeds = late::indices(&db, CF);
    let gates = Arc::new(AtomicUsize::new(0));
    *states.late_index_gate.lock().unwrap() =
        Some(late::gate(db.clone(), CF, seeds.clone(), gates.clone()));
    let mut failure = states.write_failure.subscribe();
    let receipt = Receipt::new();
    ordinary(&states, 2, receipt.clone()).await;
    if control {
        receipt.success().await;
        states.sync_pending().await.unwrap();
    } else {
        tokio::time::timeout(TIMEOUT, async {
            while failure.borrow().is_none() {
                failure.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        late::check_eio(failure.borrow().as_ref().unwrap());
        assert_eq!(receipt.count.load(Ordering::SeqCst), 0);
        assert!(states.sync_pending().await.is_err());
        assert!(states.with_absent_state(&support::graph(3).0, || Ok(())).is_err());
        tokio::time::sleep(Duration::from_millis(1200)).await;
    }
    assert_eq!(gates.load(Ordering::SeqCst), 1);
    late::inspect(&db, CF, &seeds, control, true);
    tokio::time::timeout(TIMEOUT, states.stop()).await.unwrap().unwrap();
    assert_eq!(receipt.count.load(Ordering::SeqCst), usize::from(control));
    late::disarm();
    drop(states);
    late::close_db(db).await;
    let (db, states) = open(&path);
    late::inspect(&db, CF, &seeds, control, true);
    assert_eq!(states.get(&support::graph(2).0).is_ok(), control);
    for seq in 0..2 {
        late::check_boc(states.get(&support::graph(seq).0).unwrap(), seq);
    }
    let retry = Receipt::new();
    ordinary(&states, 2, retry.clone()).await;
    retry.success().await;
    states.sync_pending().await.unwrap();
    late::inspect(&db, CF, &seeds, true, true);
    let index = states.shardstate_db.get(&support::graph(2).0).unwrap().to_vec();
    close(db, states).await;
    let (db, states) = open(&path);
    late::inspect(&db, CF, &seeds, true, true);
    assert_eq!(states.shardstate_db.get(&support::graph(2).0).unwrap().as_ref(), index);
    for seq in 0..=2 {
        late::check_boc(states.get(&support::graph(seq).0).unwrap(), seq);
    }
    close(db, states).await;
    eprintln!("LATE-INDEX COMPLETE producer=ref control={control}");
}
