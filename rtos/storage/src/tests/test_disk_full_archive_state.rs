// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{
    db::node::{open_node_db, CELLS_CF_NAME},
    tests::disk_full_state_support as support,
};
use rtos_block::write_boc;
use std::{path::Path, time::Duration};
const TIMEOUT: Duration = Duration::from_secs(10);
fn open(path: &Path) -> (Arc<RocksDb>, Arc<ArchiveShardStateDb>) {
    let db =
        open_node_db(path, &support::config(), crate::db::rocksdb::AccessType::ReadWrite).unwrap();
    let states = Arc::new(
        ArchiveShardStateDb::new(
            db.clone(),
            "archive_state_index",
            CELLS_CF_NAME,
            &support::config(),
            #[cfg(feature = "telemetry")]
            Arc::new(StorageTelemetry::default()),
            Arc::new(StorageAlloc::default()),
        )
        .unwrap(),
    );
    (db, states)
}
async fn put(states: &ArchiveShardStateDb, seq: u8) -> Result<()> {
    let (id, root) = support::graph(seq);
    tokio::time::timeout(
        TIMEOUT,
        states.put_bounded(&id, root, support::LIMITS, support::Budget::new()),
    )
    .await
    .expect("archive state write timed out")
}
async fn close(db: Arc<RocksDb>, states: Arc<ArchiveShardStateDb>) {
    drop(states);
    tokio::time::timeout(TIMEOUT, async {
        while Arc::strong_count(&db) != 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("archive state physical owner did not drain");
    drop(db);
}
fn inspect(db: &Arc<RocksDb>, states: &ArchiveShardStateDb, seed: &[u8]) -> [bool; 3] {
    let mut present = [false; 3];
    for seq in 1..=3 {
        let (id, root) = support::graph(seq);
        if let Some(bytes) = states.index.try_get(&id).unwrap() {
            support::check_index(&bytes, &id, &root);
            if seq == 1 {
                assert_eq!(bytes.as_ref(), seed, "acknowledged archive index changed");
            }
            assert_eq!(write_boc(&states.get(&id).unwrap()).unwrap(), write_boc(&root).unwrap());
            support::check_cell(db, &root);
            present[usize::from(seq - 1)] = true;
        } else {
            assert!(
                support::raw_cell(db, &root).is_none(),
                "orphan archive target after WAL failure"
            );
        }
    }
    assert!(present[0]);
    support::check_cell(db, &support::child());
    present
}
async fn exercise(live: bool) {
    let case = format!("state-archive-{}", if live { "live" } else { "cold" });
    let path = support::root(&case);
    std::fs::create_dir_all(&path).unwrap();
    let control = support::control();
    let (db, states) = open(&path);
    put(&states, 1).await.unwrap();
    states.sync_wal().unwrap();
    let seed = states.index.get(&support::graph(1).0).unwrap().to_vec();
    inspect(&db, &states, &seed);
    support::flush(&db);
    let filler = if control { None } else { Some(support::fill(&path)) };
    let result = put(&states, 2).await;
    assert_eq!(result.is_ok(), control, "archive state acknowledgement: {result:?}");
    if let Err(error) = result {
        support::check_enospc(&error);
    }
    if let Some(filler) = filler {
        std::fs::remove_file(filler).unwrap();
    }
    let barrier = states.sync_wal();
    assert_eq!(barrier.is_ok(), control, "archive state failure barrier: {barrier:?}");
    if live {
        let probe = put(&states, 3).await;
        assert_eq!(probe.is_ok(), control, "bounded archive state probe: {probe:?}");
        let (id, root) = support::graph(3);
        let probe = states.put(&id, root);
        assert_eq!(probe.is_ok(), control, "ordinary archive state probe: {probe:?}");
    }
    close(db, states).await;
    let (db, states) = open(&path);
    let present = inspect(&db, &states, &seed); // First cold check is before retry.
    if control {
        assert!(present[1]);
    }
    assert_eq!(present[2], live && control);
    put(&states, 2).await.unwrap();
    states.sync_wal().unwrap();
    let expected = inspect(&db, &states, &seed);
    assert!(expected[1]);
    put(&states, 2).await.unwrap();
    assert_eq!(inspect(&db, &states, &seed), expected);
    close(db, states).await;
    let (db, states) = open(&path);
    assert_eq!(inspect(&db, &states, &seed), expected);
    close(db, states).await;
    eprintln!("ENOSPC-CASE {case} {} ok", if control { "control" } else { "fault" });
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated ENOSPC tmpfs and syscall trace"]
async fn disk_full_archive_state_live() {
    exercise(true).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated ENOSPC tmpfs and syscall trace"]
async fn disk_full_archive_state_cold() {
    exercise(false).await;
}
