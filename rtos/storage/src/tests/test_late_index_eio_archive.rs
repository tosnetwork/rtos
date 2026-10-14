// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{
    db::node::{open_node_db, CELLS_CF_NAME},
    tests::{disk_full_state_support as support, late_index_eio_support as late},
};
use rtos_block::MerkleUpdate;
use std::{
    path::Path,
    sync::atomic::{AtomicUsize, Ordering},
};
const CF: &str = "late_index_archive_state";
fn open(path: &Path) -> (Arc<RocksDb>, Arc<ArchiveShardStateDb>) {
    let db =
        open_node_db(path, &support::config(), crate::db::rocksdb::AccessType::ReadWrite).unwrap();
    let states = Arc::new(
        ArchiveShardStateDb::new(
            db.clone(),
            CF,
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

async fn produce(states: Arc<ArchiveShardStateDb>, seq: u8, update: bool) -> Result<()> {
    late::joined(move || {
        let (id, root) = support::graph(seq);
        if update {
            states.put_update(&id, input(seq, true))
        } else {
            let saved = states.put(&id, root.clone())?;
            assert_eq!(saved.repr_hash(), root.repr_hash());
            Ok(())
        }
    })
    .await
}
async fn close(db: Arc<RocksDb>, states: Arc<ArchiveShardStateDb>) {
    drop(states);
    late::close_db(db).await;
}
async fn exercise(update: bool) {
    let path = late::root().join("db");
    let control = late::control();
    let (db, states) = open(&path);
    for seq in 0..2 {
        produce(states.clone(), seq, false).await.unwrap();
    }
    late::joined({
        let states = states.clone();
        move || states.sync_wal()
    })
    .await
    .unwrap();
    eprintln!("LATE-INDEX SEEDS_SYNCED");
    let seeds = late::indices(&db, CF);
    let gates = Arc::new(AtomicUsize::new(0));
    *states.late_index_gate.lock().unwrap() =
        Some(late::gate(db.clone(), CF, seeds.clone(), gates.clone()));
    let result = produce(states.clone(), 2, update).await;
    eprintln!("LATE-INDEX ARCHIVE_RESULT update={update} result={result:?}");
    assert_eq!(result.is_ok(), control, "late-index archive producer acknowledgement differs");
    if let Err(error) = result {
        late::check_eio(&error.to_string());
    }
    late::inspect(&db, CF, &seeds, control, false);
    assert_eq!(states.get(&support::graph(2).0).is_ok(), control);
    for seq in 0..2 {
        late::check_boc(states.get(&support::graph(seq).0).unwrap(), seq);
    }
    if !control {
        let retry = produce(states.clone(), 2, update).await;
        assert!(retry.is_err());
        late::check_eio(&retry.unwrap_err().to_string());
        late::inspect(&db, CF, &seeds, false, false);
    }
    assert_eq!(gates.load(Ordering::SeqCst), 1);
    let sync = late::joined({
        let states = states.clone();
        move || states.sync_wal()
    })
    .await;
    eprintln!(
        "LATE-INDEX ARCHIVE_SYNC result={sync:?} gate={:?}",
        states.write_gate.lock().unwrap()
    );
    if control {
        sync.unwrap();
    }
    late::disarm();
    close(db, states).await;
    let (db, states) = open(&path);
    late::inspect(&db, CF, &seeds, control, false);
    assert_eq!(states.get(&support::graph(2).0).is_ok(), control);
    produce(states.clone(), 2, update).await.unwrap();
    late::joined({
        let states = states.clone();
        move || states.sync_wal()
    })
    .await
    .unwrap();
    late::inspect(&db, CF, &seeds, true, false);
    let index = states.index.get(&support::graph(2).0).unwrap().to_vec();
    close(db, states).await;
    let (db, states) = open(&path);
    late::inspect(&db, CF, &seeds, true, false);
    assert_eq!(states.index.get(&support::graph(2).0).unwrap().as_ref(), index);
    for seq in 0..=2 {
        late::check_boc(states.get(&support::graph(seq).0).unwrap(), seq);
    }
    close(db, states).await;
    eprintln!("LATE-INDEX COMPLETE producer=archive update={update} control={control}");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated native WAL-body EIO harness"]
async fn ordinary_put_late_index_eio() {
    exercise(false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires isolated native WAL-body EIO harness"]
async fn pruned_update_late_index_eio() {
    exercise(true).await;
}
