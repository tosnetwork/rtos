// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{
    db::node::{open_node_db, CELLS_CF_NAME},
    tests::disk_full_state_support as support,
    types::serialize_stored_cell,
};
use rtos_block::{write_boc, MerkleUpdate};
use std::{path::Path, time::Duration};

const TIMEOUT: Duration = Duration::from_secs(10);

fn open(path: &Path) -> (Arc<RocksDb>, Arc<ArchiveShardStateDb>) {
    let db =
        open_node_db(path, &support::config(), crate::db::rocksdb::AccessType::ReadWrite).unwrap();
    let states = Arc::new(
        ArchiveShardStateDb::new(
            db.clone(),
            "ordinary_archive_state_index",
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

fn input(seq: u8, update: bool) -> Cell {
    let root = support::graph(seq).1;
    if !update {
        return root;
    }
    let old = support::graph(if seq == 1 { 0 } else { 1 }).1;
    let update = MerkleUpdate::create(&old, &root).unwrap();
    assert_eq!(&update.new_hash, root.repr_hash());
    let virtualized = update.new.clone().virtualize(1);
    assert_eq!(virtualized.repr_hash(), root.repr_hash(), "update target hash");
    for i in 0..2 {
        assert!(update.new.reference(i).unwrap().is_pruned(), "fixture must prune shared child");
        let child = virtualized.reference(i).unwrap();
        assert!(child.is_pruned());
        assert_eq!(child.level(), 0, "update import must skip unchanged pruned cell");
        assert_eq!(child.repr_hash(), support::child().repr_hash());
    }
    update.new
}

async fn joined<T: Send + 'static>(operation: impl FnOnce() -> T + Send + 'static) -> T {
    let mut writer = tokio::task::spawn_blocking(operation);
    // A timeout fails this test before filler release or reopen. Only an actual
    // joined writer result authorizes the subsequent ownership/DB steps.
    tokio::time::timeout(TIMEOUT, &mut writer)
        .await
        .expect("ordinary archive owner timed out; no reopen authorized")
        .expect("ordinary archive owner panicked")
}

async fn produce(
    states: Arc<ArchiveShardStateDb>,
    seq: u8,
    root: Cell,
    update: bool,
) -> Result<()> {
    let (id, expected) = support::graph(seq);
    joined(move || {
        if update {
            states.put_update(&id, root)
        } else {
            let saved = states.put(&id, root)?;
            assert_eq!(saved.repr_hash(), expected.repr_hash(), "ordinary returned wrong root");
            Ok(())
        }
    })
    .await
}

async fn barrier(states: Arc<ArchiveShardStateDb>) -> Result<()> {
    joined(move || states.sync_wal()).await
}

async fn close(db: Arc<RocksDb>, states: Arc<ArchiveShardStateDb>) {
    drop(states);
    tokio::time::timeout(TIMEOUT, async {
        while Arc::strong_count(&db) != 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("ordinary archive physical DB owner did not drain");
    drop(db);
}

fn seed_indices(states: &ArchiveShardStateDb) -> [Vec<u8>; 2] {
    [0, 1].map(|seq| states.index.get(&support::graph(seq).0).unwrap().to_vec())
}

fn inspect(db: &Arc<RocksDb>, states: &ArchiveShardStateDb, seeds: &[Vec<u8>; 2]) -> [bool; 4] {
    let mut present = [false; 4];
    for seq in 0..=3 {
        let (id, root) = support::graph(seq);
        let raw = support::raw_cell(db, &root);
        if let Some(raw) = &raw {
            assert_eq!(raw, &serialize_stored_cell(&root).unwrap().to_vec(), "raw root bytes");
        }
        if let Some(bytes) = states.index.try_get(&id).unwrap() {
            support::check_index(&bytes, &id, &root);
            if seq < 2 {
                assert_eq!(bytes.as_ref(), seeds[seq as usize], "acknowledged seed index changed");
            }
            assert_eq!(write_boc(&states.get(&id).unwrap()).unwrap(), write_boc(&root).unwrap());
            assert!(raw.is_some(), "index published without its complete root cell");
            present[seq as usize] = true;
        } else {
            assert!(seq >= 2, "acknowledged seed index missing");
            assert!(states.get(&id).is_err(), "unindexed target unexpectedly readable");
            // A valid unindexed cell is retained and inspected, not deleted or
            // confused with a damaged cell at a later separate index failure.
            if raw.is_some() {
                eprintln!("ORDINARY-OBS valid-unindexed-root seq={seq}");
            }
        }
    }
    support::check_cell(db, &support::child());
    present
}

async fn exercise(update: bool, live: bool) {
    let case = format!(
        "state-ordinary-{}-{}",
        if update { "update" } else { "put" },
        if live { "live" } else { "cold" }
    );
    let path = support::root(&case);
    std::fs::create_dir_all(&path).unwrap();
    let control = support::control();
    // Setup correctness is asserted before pressure; no parsing/setup error
    // can stand in for the target WAL failure.
    let inputs = [input(1, update), input(2, update), input(3, update)];
    let (db, states) = open(&path);
    produce(states.clone(), 0, support::graph(0).1, false).await.unwrap();
    produce(states.clone(), 1, inputs[0].clone(), update).await.unwrap();
    barrier(states.clone()).await.unwrap();
    let seeds = seed_indices(&states);
    assert_eq!(inspect(&db, &states, &seeds), [true, true, false, false]);
    support::flush(&db);
    let filler = if control { None } else { Some(support::fill(&path)) };
    let result = produce(states.clone(), 2, inputs[1].clone(), update).await;
    eprintln!("ORDINARY-OBS target-producer={result:?}");
    assert_eq!(result.is_ok(), control, "ordinary producer acknowledgement: {result:?}");
    if let Err(error) = result {
        support::check_enospc(&error);
    }
    if let Some(filler) = filler {
        std::fs::remove_file(filler).unwrap();
    }
    inspect(&db, &states, &seeds);
    let mut probe_ok = false;
    if live {
        let probe = produce(states.clone(), 3, inputs[2].clone(), update).await;
        eprintln!("ORDINARY-OBS live-probe={probe:?}");
        probe_ok = probe.is_ok();
        if control {
            assert!(probe_ok);
        }
    }
    let sync = barrier(states.clone()).await;
    eprintln!("ORDINARY-OBS durability-barrier={sync:?}");
    let synced = sync.is_ok();
    if control {
        assert!(synced);
    }
    close(db, states).await;
    let (db, states) = open(&path);
    let cold = inspect(&db, &states, &seeds); // No target retry before cold observation.
    if control {
        assert!(cold[2]);
    }
    if synced && probe_ok {
        assert!(cold[3], "synced successful probe disappeared");
    }
    if !live {
        assert!(!cold[3]);
    }
    produce(states.clone(), 2, inputs[1].clone(), update).await.unwrap();
    barrier(states.clone()).await.unwrap();
    let expected = inspect(&db, &states, &seeds);
    assert!(expected[2]);
    let target_index = states.index.get(&support::graph(2).0).unwrap().to_vec();
    let target_bytes = support::raw_cell(&db, &support::graph(2).1).unwrap();
    produce(states.clone(), 2, inputs[1].clone(), update).await.unwrap();
    barrier(states.clone()).await.unwrap();
    assert_eq!(states.index.get(&support::graph(2).0).unwrap().as_ref(), target_index);
    assert_eq!(support::raw_cell(&db, &support::graph(2).1).unwrap(), target_bytes);
    close(db, states).await;
    let (db, states) = open(&path);
    assert_eq!(inspect(&db, &states, &seeds), expected);
    assert_eq!(states.index.get(&support::graph(2).0).unwrap().as_ref(), target_index);
    assert_eq!(support::raw_cell(&db, &support::graph(2).1).unwrap(), target_bytes);
    close(db, states).await;
    eprintln!("ENOSPC-CASE {case} {} ok", if control { "control" } else { "fault" });
}

macro_rules! case {
    ($name:ident, $update:literal, $live:literal) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[ignore = "requires isolated ENOSPC tmpfs and syscall trace"]
        async fn $name() {
            exercise($update, $live).await;
        }
    };
}
case!(disk_full_archive_put_live, false, true);
case!(disk_full_archive_put_cold, false, false);
case!(disk_full_archive_update_live, true, true);
case!(disk_full_archive_update_cold, true, false);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pruned_update_fixture_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let (db, states) = open(dir.path());
    produce(states.clone(), 0, support::graph(0).1, false).await.unwrap();
    produce(states.clone(), 1, input(1, true), true).await.unwrap();
    barrier(states.clone()).await.unwrap();
    let seeds = seed_indices(&states);
    produce(states.clone(), 2, input(2, true), true).await.unwrap();
    barrier(states.clone()).await.unwrap();
    assert_eq!(inspect(&db, &states, &seeds), [true, true, true, false]);
    close(db, states).await;
    let (db, states) = open(dir.path());
    assert_eq!(inspect(&db, &states, &seeds), [true, true, true, false]);
    close(db, states).await;
}
