// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Shared actual late-index gate/readers. Requires native WAL interposition.
use super::disk_full_state_support as support;
use crate::{
    db::{
        node::{CELLSCOUNTERS_CF_NAME, CELLS_CF_NAME},
        rocksdb::RocksDb,
    },
    types::serialize_stored_cell,
};
use rtos_block::{write_boc, BlockIdExt, UInt256};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
pub const TIMEOUT: Duration = Duration::from_secs(20);
pub fn root() -> PathBuf {
    PathBuf::from(std::env::var_os("RTOS_LATE_INDEX_ROOT").expect("run late-index harness"))
}
pub fn control() -> bool {
    std::env::var("RTOS_LATE_INDEX_CONTROL").as_deref() == Ok("1")
}
pub fn arm() -> PathBuf {
    PathBuf::from(std::env::var_os("RTOS_LATE_INDEX_ARM").unwrap())
}
pub fn disarm() {
    if std::env::var("RTOS_LATE_INDEX_NO_ARM").as_deref() != Ok("1") {
        std::fs::remove_file(arm()).unwrap();
    }
}
pub fn check_eio(error: &str) {
    assert!(
        error.contains("Input/output error") || error.contains("IO error") || error.contains("EIO"),
        "expected native EIO: {error}"
    );
}
pub fn indices(db: &Arc<RocksDb>, cf: &str) -> [Vec<u8>; 2] {
    let table = db.clone().table::<BlockIdExt>(cf, false).unwrap();
    [0, 1].map(|seq| table.get(&support::graph(seq).0).unwrap().to_vec())
}
pub fn gate(
    db: Arc<RocksDb>,
    cf: &'static str,
    seeds: [Vec<u8>; 2],
    count: Arc<AtomicUsize>,
) -> crate::durability::LateIndexGate {
    Arc::new(move || {
        assert_eq!(indices(&db, cf), seeds);
        assert!(db
            .clone()
            .table::<BlockIdExt>(cf, false)?
            .try_get(&support::graph(2).0)?
            .is_none());
        for seq in 0..=2 {
            assert_eq!(
                support::raw_cell(&db, &support::graph(seq).1).unwrap(),
                serialize_stored_cell(&support::graph(seq).1).unwrap().to_vec()
            );
        }
        support::check_cell(&db, &support::child());
        db.sync_wal()?;
        eprintln!("LATE-INDEX CELLS_SYNCED cf={cf} index_absent=true");
        if std::env::var("RTOS_LATE_INDEX_NO_ARM").as_deref() != Ok("1") {
            std::fs::write(arm(), b"post-cells")?;
        }
        count.fetch_add(1, Ordering::SeqCst);
        eprintln!("LATE-INDEX ARMED cf={cf}");
        Ok(())
    })
}
pub fn inspect(db: &Arc<RocksDb>, cf: &str, seeds: &[Vec<u8>; 2], indexed: bool, counters: bool) {
    let table = db.clone().table::<BlockIdExt>(cf, false).unwrap();
    assert_eq!(&indices(db, cf), seeds, "old ACKed index changed");
    for seq in 0..=2 {
        let (id, root) = support::graph(seq);
        let raw = table.try_get(&id).unwrap();
        assert_eq!(raw.is_some(), seq < 2 || indexed, "late-index publication differs");
        if let Some(raw) = raw {
            support::check_index(&raw, &id, &root);
        }
        assert_eq!(
            support::raw_cell(db, &root).unwrap(),
            serialize_stored_cell(&root).unwrap().to_vec(),
            "complete orphan/ACK root missing"
        );
    }
    support::check_cell(db, &support::child());
    if counters {
        let table = db.clone().table::<UInt256>(CELLSCOUNTERS_CF_NAME, false).unwrap();
        for seq in 0..=2 {
            assert_eq!(
                table.get(support::graph(seq).1.repr_hash()).unwrap().as_ref(),
                1u32.to_le_bytes()
            );
        }
        assert_eq!(table.get(support::child().repr_hash()).unwrap().as_ref(), 6u32.to_le_bytes());
    }
    assert_eq!(db.clone().table::<UInt256>(CELLS_CF_NAME, false).unwrap().len().unwrap(), 4);
}
pub fn check_boc(actual: rtos_block::Cell, seq: u8) {
    assert_eq!(write_boc(&actual).unwrap(), write_boc(&support::graph(seq).1).unwrap());
}
pub async fn joined<T: Send + 'static>(task: impl FnOnce() -> T + Send + 'static) -> T {
    let mut owner = tokio::task::spawn_blocking(task);
    tokio::time::timeout(TIMEOUT, &mut owner)
        .await
        .expect("late-index owner timed out; cold forbidden")
        .unwrap()
}
pub async fn close_db(db: Arc<RocksDb>) {
    tokio::time::timeout(TIMEOUT, async {
        while Arc::strong_count(&db) != 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("late-index DB owners remain; cold forbidden");
    joined(move || {
        db.db().cancel_all_background_work(true);
        drop(db);
    })
    .await;
    eprintln!("LATE-INDEX NATIVE_CLOSE_COMPLETE");
}
