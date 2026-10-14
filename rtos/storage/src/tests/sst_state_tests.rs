// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
#[cfg(feature = "telemetry")]
use crate::StorageTelemetry;
use crate::{
    archive_shardstate_db::ArchiveShardStateDb,
    db::{
        node::{open_node_db, CELLSCOUNTERS_CF_NAME, CELLS_CF_NAME},
        rocksdb::{AccessType, RocksDb},
    },
    shardstate_db_async::ShardStateDb,
    tests::disk_full_state_support as support,
    types::serialize_stored_cell,
    StorageAlloc,
};
use rtos_block::{write_boc, BlockIdExt, BuilderData, Cell, Result, ShardIdent, UInt256};
use std::{path::Path, sync::Arc, time::Duration};

const TIMEOUT: Duration = Duration::from_secs(10);
const INDEX: &str = "sst_state_index";
enum Store {
    Ref(Arc<ShardStateDb>),
    Archive(Arc<ArchiveShardStateDb>),
}

fn materialized(byte: u8) -> Cell {
    let mut root = BuilderData::with_raw(vec![byte], 8).unwrap();
    root.checked_append_reference(support::child()).unwrap();
    root.checked_append_reference(support::child()).unwrap();
    root.into_cell().unwrap()
}
fn graph(seq: u8) -> (BlockIdExt, Cell) {
    let seed = materialized(8);
    let root = if seq == 1 {
        seed
    } else {
        let child = support::child();
        let a = seed.repr_hash().as_slice();
        let b = child.repr_hash().as_slice();
        let (low, high) = if a < b { (a, b) } else { (b, a) };
        (0..=255)
            .filter(|n| *n != 8)
            .map(materialized)
            .find(|cell| {
                let key = cell.repr_hash().as_slice();
                key > low && key < high
            })
            .expect("public target must overlap seeded SST key range")
    };
    let id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        seq as u32,
        root.repr_hash().clone(),
        UInt256::from([seq; 32]),
    );
    (id, root)
}
async fn joined<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let mut owner = tokio::task::spawn_blocking(f);
    tokio::time::timeout(TIMEOUT, &mut owner)
        .await
        .expect("SST native owner timed out; no reopen authorized")
        .unwrap()
}
fn open(path: &Path, archive: bool) -> Result<(Arc<RocksDb>, Store)> {
    let config = support::config();
    let db = open_node_db(path, &config, AccessType::ReadWrite)?;
    let store = if archive {
        Store::Archive(Arc::new(ArchiveShardStateDb::new(
            db.clone(),
            INDEX,
            CELLS_CF_NAME,
            &config,
            #[cfg(feature = "telemetry")]
            Arc::new(StorageTelemetry::default()),
            Arc::new(StorageAlloc::default()),
        )?))
    } else {
        Store::Ref(ShardStateDb::new(
            db.clone(),
            INDEX,
            CELLS_CF_NAME,
            CELLSCOUNTERS_CF_NAME,
            config,
            #[cfg(feature = "telemetry")]
            Arc::new(StorageTelemetry::default()),
            Arc::new(StorageAlloc::default()),
        )?)
    };
    let raw = db.db();
    for name in rocksdb::DB::list_cf(&rocksdb::Options::default(), db.path())? {
        let options = [("disable_auto_compactions", "true"), ("write_buffer_size", "16777216")];
        if name == "default" {
            raw.set_options(&options)?;
        } else {
            let cf = raw.cf_handle(&name).expect("existing named CF must be opened");
            raw.set_options_cf(&cf, &options)?;
        }
    }
    Ok((db, store))
}
async fn put(store: &Store, seq: u8) -> Result<()> {
    let (id, root) = graph(seq);
    match store {
        Store::Ref(s) => s.put_bounded(&id, root, support::LIMITS, support::Budget::new()).await,
        Store::Archive(s) => {
            s.put_bounded(&id, root, support::LIMITS, support::Budget::new()).await
        }
    }
}
async fn sync(store: &Store) -> Result<()> {
    match store {
        Store::Ref(s) => tokio::time::timeout(TIMEOUT, s.sync_pending()).await.unwrap(),
        Store::Archive(s) => {
            let s = s.clone();
            joined(move || s.sync_wal()).await
        }
    }
}
async fn close(db: Arc<RocksDb>, store: Store) {
    if let Store::Ref(s) = &store {
        let stopped =
            tokio::time::timeout(TIMEOUT, s.stop()).await.expect("state owners did not stop");
        eprintln!("SST-OBS state-stop={stopped:?}");
    }
    drop(store);
    tokio::time::timeout(TIMEOUT, async {
        while Arc::strong_count(&db) != 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("physical SST DB ownership did not drain");
    joined(move || {
        db.db().cancel_all_background_work(true);
        drop(db);
    })
    .await;
}
fn compact(db: &RocksDb, force: bool) {
    let raw = db.db();
    let cf = raw.cf_handle(CELLS_CF_NAME).unwrap();
    let mut options = rocksdb::CompactOptions::default();
    options.set_exclusive_manual_compaction(true);
    options.set_change_level(true);
    options.set_target_level(6);
    options.set_bottommost_level_compaction(if force {
        rocksdb::BottommostLevelCompaction::Force
    } else {
        rocksdb::BottommostLevelCompaction::Skip
    });
    raw.compact_range_cf_opt::<&[u8], &[u8]>(&cf, None, None, &options);
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct Input {
    name: String,
    level: i32,
    size: usize,
    start: Vec<u8>,
    end: Vec<u8>,
    hash: String,
}
fn files(db: &RocksDb) -> Vec<Input> {
    let mut files: Vec<_> = db
        .db()
        .live_files()
        .unwrap()
        .into_iter()
        .filter(|f| f.column_family_name == CELLS_CF_NAME)
        .map(|f| {
            let hash = format!(
                "{:x}",
                UInt256::calc_file_hash(
                    &std::fs::read(db.path().join(f.name.trim_start_matches('/'))).unwrap()
                )
            );
            Input {
                name: f.name,
                level: f.level,
                size: f.size,
                start: f.start_key.unwrap(),
                end: f.end_key.unwrap(),
                hash,
            }
        })
        .collect();
    files.sort_by(|a, b| a.name.cmp(&b.name));
    files
}
fn inspect(db: &Arc<RocksDb>, store: &Store) -> Vec<Vec<u8>> {
    let index = db.clone().table::<BlockIdExt>(INDEX, false).unwrap();
    let mut bytes = Vec::new();
    for seq in [1, 2] {
        let (id, root) = graph(seq);
        let data = index.get(&id).expect("acknowledged index missing");
        support::check_index(&data, &id, &root);
        bytes.push(data.to_vec());
        let loaded = match store {
            Store::Ref(s) => s.get(&id),
            Store::Archive(s) => s.get(&id),
        }
        .expect("acknowledged root no longer readable");
        assert_eq!(
            write_boc(&loaded).unwrap(),
            write_boc(&root).unwrap(),
            "acknowledged BOC changed"
        );
        let cell = support::raw_cell(db, &root).expect("acknowledged raw root missing");
        assert_eq!(cell, serialize_stored_cell(&root).unwrap().to_vec());
        bytes.push(cell);
    }
    support::check_cell(db, &support::child());
    bytes.push(support::raw_cell(db, &support::child()).unwrap());
    if let Store::Ref(_) = store {
        let counters = db.clone().table::<UInt256>(CELLSCOUNTERS_CF_NAME, false).unwrap();
        for (cell, count) in [(graph(1).1, 1u32), (graph(2).1, 1), (support::child(), 4)] {
            let raw = counters.get(cell.repr_hash()).unwrap();
            assert_eq!(raw.as_ref(), count.to_le_bytes());
            bytes.push(raw.to_vec());
        }
    }
    bytes
}
async fn flush(db: Arc<RocksDb>) -> Result<()> {
    joined(move || db.clone().table::<UInt256>(CELLS_CF_NAME, false)?.flush_family()).await
}
async fn exercise(archive: bool, compaction: bool) {
    let case = format!(
        "state-sst-{}-{}",
        if archive { "archive" } else { "refcount" },
        if compaction { "compact" } else { "flush" }
    );
    let path = support::root(&case);
    std::fs::create_dir_all(&path).unwrap();
    let control = support::control();
    let (db, store) = open(&path, archive).expect("SST setup DB open");
    put(&store, 1).await.unwrap();
    sync(&store).await.unwrap();
    support::flush(&db);
    let setup = db.clone();
    joined(move || compact(&setup, false)).await;
    let seed = files(&db);
    assert_eq!(seed.len(), 1, "seed cells SST count");
    assert_eq!(seed[0].level, 6, "seed bottommost level");
    put(&store, 2).await.unwrap();
    sync(&store).await.unwrap();
    let acknowledged = inspect(&db, &store);
    assert_eq!(files(&db), seed, "target cells unexpectedly auto-flushed");
    if compaction {
        flush(db.clone()).await.unwrap();
    }
    let before = files(&db);
    assert_eq!(before.len(), if compaction { 2 } else { 1 });
    if compaction {
        let target = before.iter().find(|f| f.level == 0).expect("target L0 SST");
        assert!(
            target.start > seed[0].start && target.end < seed[0].end,
            "target SST must overlap seed range"
        );
    }
    for f in &before {
        eprintln!(
            "SST-INPUT name={} cf={} level={} size={} range={:?}/{:?} sha256={}",
            f.name, CELLS_CF_NAME, f.level, f.size, f.start, f.end, f.hash
        );
    }
    let filler = if control { None } else { Some(support::fill(&path)) };
    if compaction {
        let owner = db.clone();
        joined(move || compact(&owner, true)).await;
        eprintln!("SST-OBS compact-return=unit");
    } else {
        let result = flush(db.clone()).await;
        eprintln!("SST-OBS flush-result={result:?}");
        assert_eq!(result.is_ok(), control, "SST flush acknowledgement: {result:?}");
        if let Err(error) = result {
            support::check_enospc(&error);
        }
    }
    let after = files(&db);
    if control {
        let fresh: Vec<_> =
            after.iter().filter(|f| !before.iter().any(|old| old.name == f.name)).collect();
        assert!(!fresh.is_empty(), "SST positive operation did not register fresh rewrite");
        for f in fresh {
            eprintln!(
                "SST-OUTPUT name={} cf={} level={} sha256={}",
                f.name, CELLS_CF_NAME, f.level, f.hash
            );
        }
    } else {
        assert_eq!(after, before, "failed SST operation changed registered acknowledged inputs");
    }
    for name in [
        "rocksdb.background-errors",
        "rocksdb.num-running-flushes",
        "rocksdb.num-running-compactions",
    ] {
        eprintln!("SST-OBS {name}={:?}", db.db().property_int_value(name));
    }
    assert_eq!(inspect(&db, &store), acknowledged, "live acknowledged content changed");
    if let Some(filler) = filler {
        std::fs::remove_file(filler).unwrap();
    }
    eprintln!("SST-OBS post-error-barrier={:?}", sync(&store).await);
    close(db, store).await;
    let (db, store) = open(&path, archive).expect("acknowledged SST inputs no longer recoverable");
    assert_eq!(inspect(&db, &store), acknowledged, "cold acknowledged content changed");
    if compaction {
        let owner = db.clone();
        joined(move || compact(&owner, true)).await;
    } else {
        flush(db.clone()).await.unwrap();
    }
    sync(&store).await.unwrap();
    assert_eq!(inspect(&db, &store), acknowledged);
    close(db, store).await;
    let (db, store) = open(&path, archive).expect("second acknowledged SST recovery failed");
    assert_eq!(inspect(&db, &store), acknowledged);
    close(db, store).await;
    eprintln!("ENOSPC-CASE {case} {} ok", if control { "control" } else { "fault" });
}
macro_rules! case {
    ($name:ident,$archive:literal,$compact:literal) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[ignore = "requires isolated SST ENOSPC and syscall trace"]
        async fn $name() {
            exercise($archive, $compact).await;
        }
    };
}
case!(disk_full_sst_refcount_flush, false, false);
case!(disk_full_sst_archive_flush, true, false);
case!(disk_full_sst_refcount_compact, false, true);
case!(disk_full_sst_archive_compact, true, true);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn acknowledged_graph_and_native_close_roundtrip() {
    for archive in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (db, store) = open(dir.path(), archive).unwrap();
        put(&store, 1).await.unwrap();
        put(&store, 2).await.unwrap();
        sync(&store).await.unwrap();
        let before = inspect(&db, &store);
        close(db, store).await;
        let (db, store) = open(dir.path(), archive).unwrap();
        assert_eq!(inspect(&db, &store), before);
        close(db, store).await;
    }
}
