// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Actual storage-component producers/consumers; no blockchain authentication.
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
use std::{collections::BTreeMap, path::Path, sync::Arc, time::Duration};

const TIMEOUT: Duration = Duration::from_secs(30);
const INDEX: &str = "sst_metadata_index";
#[derive(Clone, Copy)]
enum Target {
    Counter,
    RefIndex,
    ArchiveIndex,
}
impl Target {
    fn cf(self) -> &'static str {
        match self {
            Self::Counter => CELLSCOUNTERS_CF_NAME,
            _ => INDEX,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::RefIndex => "ref-index",
            Self::ArchiveIndex => "archive-index",
        }
    }
}
enum Store {
    Ref(Arc<ShardStateDb>),
    Archive(Arc<ArchiveShardStateDb>),
}

fn graphs() -> [(BlockIdExt, Cell); 4] {
    let mut roots: Vec<_> = (0..=255)
        .map(|byte| {
            let mut root = BuilderData::with_raw(vec![byte], 8).unwrap();
            root.checked_append_reference(support::child()).unwrap();
            root.checked_append_reference(support::child()).unwrap();
            root.into_cell().unwrap()
        })
        .collect();
    roots.sort_by(|a, b| a.repr_hash().as_slice().cmp(b.repr_hash().as_slice()));
    assert!(roots.windows(2).all(|p| p[0].repr_hash() != p[1].repr_hash()));
    std::array::from_fn(|n| {
        let root = roots[[0, 128, 255, 129][n]].clone();
        let seq = n as u32 + 1;
        (
            BlockIdExt::with_params(
                ShardIdent::masterchain(),
                seq,
                root.repr_hash().clone(),
                UInt256::from([seq as u8; 32]),
            ),
            root,
        )
    })
}
async fn joined<T: Send + 'static>(task: impl FnOnce() -> T + Send + 'static) -> T {
    let mut owner = tokio::task::spawn_blocking(task);
    tokio::time::timeout(TIMEOUT, &mut owner)
        .await
        .expect("metadata SST owner timed out; cold reopen forbidden")
        .unwrap()
}
fn open(path: &Path, target: Target) -> Result<(Arc<RocksDb>, Store)> {
    let config = support::config();
    let db = open_node_db(path, &config, AccessType::ReadWrite)?;
    let store = match target {
        Target::ArchiveIndex => Store::Archive(Arc::new(ArchiveShardStateDb::new(
            db.clone(),
            INDEX,
            CELLS_CF_NAME,
            &config,
            #[cfg(feature = "telemetry")]
            Arc::new(StorageTelemetry::default()),
            Arc::new(StorageAlloc::default()),
        )?)),
        _ => Store::Ref(ShardStateDb::new(
            db.clone(),
            INDEX,
            CELLS_CF_NAME,
            CELLSCOUNTERS_CF_NAME,
            config,
            #[cfg(feature = "telemetry")]
            Arc::new(StorageTelemetry::default()),
            Arc::new(StorageAlloc::default()),
        )?),
    };
    for name in rocksdb::DB::list_cf(&rocksdb::Options::default(), db.path())? {
        let options = [("disable_auto_compactions", "true"), ("write_buffer_size", "16777216")];
        if name == "default" {
            db.db().set_options(&options)?;
        } else {
            db.db().set_options_cf(&db.db().cf_handle(&name).unwrap(), &options)?;
        }
    }
    Ok((db, store))
}
async fn put(store: &Store, graph: &(BlockIdExt, Cell)) -> Result<()> {
    match store {
        Store::Ref(s) => {
            s.put_bounded(&graph.0, graph.1.clone(), support::LIMITS, support::Budget::new()).await
        }
        Store::Archive(s) => {
            s.put_bounded(&graph.0, graph.1.clone(), support::LIMITS, support::Budget::new()).await
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
        let result = tokio::time::timeout(TIMEOUT, s.stop())
            .await
            .expect("metadata producer owners timed out; cold reopen forbidden");
        eprintln!("SST-OBS metadata-stop={result:?}");
        result.expect("metadata producer teardown failed; cold reopen forbidden");
    }
    drop(store);
    tokio::time::timeout(TIMEOUT, async {
        while Arc::strong_count(&db) != 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("metadata DB owners remain; cold reopen forbidden");
    eprintln!("SST-OBS metadata-db-owners=1");
    joined(move || {
        db.db().cancel_all_background_work(true);
        drop(db);
    })
    .await;
    eprintln!("SST-OBS metadata-native-close=complete");
}
fn compact(db: &RocksDb, cf: &str, force: bool) {
    let family = db.db().cf_handle(cf).unwrap();
    let mut options = rocksdb::CompactOptions::default();
    options.set_exclusive_manual_compaction(true);
    options.set_change_level(true);
    options.set_target_level(6);
    options.set_bottommost_level_compaction(if force {
        rocksdb::BottommostLevelCompaction::Force
    } else {
        rocksdb::BottommostLevelCompaction::Skip
    });
    db.db().compact_range_cf_opt::<&[u8], &[u8]>(&family, None, None, &options);
}
async fn flush(db: Arc<RocksDb>, cf: &'static str) -> Result<()> {
    joined(move || db.table::<String>(cf, false)?.flush_family()).await
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Input {
    name: String,
    level: i32,
    size: usize,
    start: Vec<u8>,
    end: Vec<u8>,
    hash: UInt256,
}
fn files(db: &RocksDb, cf: &str) -> Vec<Input> {
    let mut files: Vec<_> = db
        .db()
        .live_files()
        .unwrap()
        .into_iter()
        .filter(|f| f.column_family_name == cf)
        .map(|f| Input {
            hash: UInt256::calc_file_hash(
                &std::fs::read(db.path().join(f.name.trim_start_matches('/'))).unwrap(),
            ),
            name: f.name,
            level: f.level,
            size: f.size,
            start: f.start_key.unwrap(),
            end: f.end_key.unwrap(),
        })
        .collect();
    files.sort_by(|a, b| a.name.cmp(&b.name));
    files
}
type Rows = BTreeMap<Vec<u8>, Vec<u8>>;
fn rows(db: &Arc<RocksDb>, cf: &str) -> Rows {
    let mut rows = Rows::new();
    db.clone()
        .table::<String>(cf, false)
        .unwrap()
        .for_each(&mut |key, value| {
            assert!(rows.insert(key.to_vec(), value.to_vec()).is_none());
            Ok(true)
        })
        .unwrap();
    rows
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Dataset {
    cells: Rows,
    index: Rows,
    counters: Option<Rows>,
}
fn inspect(db: &Arc<RocksDb>, store: &Store, graphs: &[(BlockIdExt, Cell)]) -> Dataset {
    let index = db.clone().table::<BlockIdExt>(INDEX, false).unwrap();
    for (id, root) in graphs {
        let data = index.get(id).expect("acknowledged metadata index missing");
        support::check_index(&data, id, root);
        let loaded = match store {
            Store::Ref(s) => s.get(id),
            Store::Archive(s) => s.get(id),
        }
        .expect("acknowledged metadata root unreadable");
        assert_eq!(
            write_boc(&loaded).unwrap(),
            write_boc(root).unwrap(),
            "acknowledged BOC changed"
        );
        assert_eq!(
            support::raw_cell(db, root).unwrap(),
            serialize_stored_cell(root).unwrap().to_vec()
        );
    }
    support::check_cell(db, &support::child());
    let counters = if let Store::Ref(_) = store {
        let counters = db.clone().table::<UInt256>(CELLSCOUNTERS_CF_NAME, false).unwrap();
        for (_, root) in graphs {
            assert_eq!(counters.get(root.repr_hash()).unwrap().as_ref(), 1u32.to_le_bytes());
        }
        assert_eq!(
            counters.get(support::child().repr_hash()).unwrap().as_ref(),
            (2 * graphs.len() as u32).to_le_bytes()
        );
        let rows = rows(db, CELLSCOUNTERS_CF_NAME);
        assert_eq!(rows.len(), graphs.len() + 1);
        Some(rows)
    } else {
        None
    };
    let index = rows(db, INDEX);
    assert_eq!(index.len(), graphs.len());
    let cells = rows(db, CELLS_CF_NAME);
    assert_eq!(cells.len(), graphs.len() + 1);
    Dataset { cells, index, counters }
}
fn preserve_immutable(old: &Dataset, new: &Dataset) {
    for (name, before, after) in
        [("cells", &old.cells, &new.cells), ("index", &old.index, &new.index)]
    {
        for (key, value) in before {
            assert_eq!(
                after.get(key),
                Some(value),
                "old acknowledged {name} changed during recovery"
            );
        }
    }
    if let (Some(old), Some(new)) = (&old.counters, &new.counters) {
        for (key, value) in old {
            if key.as_slice() != support::child().repr_hash().as_slice() {
                assert_eq!(new.get(key), Some(value));
            }
        }
    }
}
fn output(db: &RocksDb, cf: &str, before: &[Input], rewrite: bool) {
    let after = files(db, cf);
    let fresh: Vec<_> =
        after.iter().filter(|f| !before.iter().any(|old| old.name == f.name)).collect();
    assert!(!fresh.is_empty(), "metadata positive maintenance did not register fresh output");
    for file in fresh {
        if rewrite {
            assert_eq!(file.level, 6);
        }
        eprintln!(
            "SST-OUTPUT name={} cf={} level={} size={} sha256={:x}",
            file.name, cf, file.level, file.size, file.hash
        );
    }
}
async fn maintenance(
    db: &Arc<RocksDb>,
    cf: &'static str,
    rewrite: bool,
    fault: bool,
    before: &[Input],
) {
    if rewrite {
        let owner = db.clone();
        joined(move || compact(&owner, cf, true)).await;
        eprintln!("SST-OBS compact-return=unit cf={cf}");
    } else {
        let result = flush(db.clone(), cf).await;
        eprintln!("SST-OBS flush-result={result:?} cf={cf}");
        if fault {
            support::check_enospc(&result.expect_err("metadata flush falsely acknowledged"));
        } else {
            result.unwrap();
        }
    }
    for name in [
        "rocksdb.background-errors",
        "rocksdb.num-running-flushes",
        "rocksdb.num-running-compactions",
    ] {
        eprintln!("SST-OBS {name}={:?}", db.db().property_int_value(name).unwrap());
    }
    eprintln!("SST-OBS independent-sync={:?}", db.sync_wal());
    if fault {
        assert_eq!(files(db, cf), before, "failed metadata maintenance changed ACKed inputs");
    } else {
        output(db, cf, before, rewrite);
    }
}
async fn exercise(path: &Path, target: Target, rewrite: bool, fault: bool) {
    std::fs::create_dir_all(path).unwrap();
    let graphs = graphs();
    let cf = target.cf();
    let (db, store) = open(path, target).expect("metadata setup open");
    put(&store, &graphs[0]).await.unwrap();
    put(&store, &graphs[2]).await.unwrap();
    sync(&store).await.unwrap();
    flush(db.clone(), cf).await.unwrap();
    let owner = db.clone();
    joined(move || compact(&owner, cf, false)).await;
    let seed = files(&db, cf);
    assert_eq!(seed.len(), 1);
    assert_eq!(seed[0].level, 6);
    put(&store, &graphs[1]).await.unwrap();
    sync(&store).await.unwrap();
    let three = inspect(&db, &store, &graphs[..3]);
    assert_eq!(files(&db, cf), seed, "metadata target automatically flushed");
    if rewrite {
        flush(db.clone(), cf).await.unwrap();
    }
    let before = files(&db, cf);
    assert_eq!(before.len(), if rewrite { 2 } else { 1 });
    if rewrite {
        let l0 = before.iter().find(|f| f.level == 0).unwrap();
        assert!(
            l0.start <= seed[0].end && seed[0].start <= l0.end,
            "metadata SST ranges do not overlap"
        );
        if !matches!(target, Target::Counter) {
            assert!(l0.start > seed[0].start && l0.end < seed[0].end);
        }
    }
    for file in &before {
        eprintln!(
            "SST-INPUT name={} cf={} level={} size={} range={:?}/{:?} sha256={:x}",
            file.name, cf, file.level, file.size, file.start, file.end, file.hash
        );
    }
    let filler = fault.then(|| support::fill(path));
    maintenance(&db, cf, rewrite, fault, &before).await;
    assert_eq!(inspect(&db, &store, &graphs[..3]), three, "live acknowledged metadata changed");
    if let Some(filler) = filler {
        std::fs::remove_file(filler).unwrap();
    }
    eprintln!("SST-OBS post-error-producer-sync={:?}", sync(&store).await);
    close(db, store).await;
    let (db, store) = open(path, target).expect("acknowledged metadata SST cold open failed");
    assert_eq!(
        inspect(&db, &store, &graphs[..3]),
        three,
        "first cold before retry changed metadata"
    );
    put(&store, &graphs[3]).await.unwrap();
    sync(&store).await.unwrap();
    let four = inspect(&db, &store, &graphs);
    preserve_immutable(&three, &four);
    if rewrite {
        flush(db.clone(), cf).await.unwrap();
    }
    let before = files(&db, cf);
    maintenance(&db, cf, rewrite, false, &before).await;
    assert_eq!(inspect(&db, &store, &graphs), four);
    close(db, store).await;
    let (db, store) = open(path, target).expect("second metadata SST cold open failed");
    assert_eq!(inspect(&db, &store, &graphs), four, "four-state metadata snapshot changed");
    preserve_immutable(&three, &four);
    close(db, store).await;
}
macro_rules! case {
    ($name:ident,$target:ident,$rewrite:literal) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[ignore = "isolated named-CF SST disk-full harness only"]
        async fn $name() {
            let target = Target::$target;
            let case = format!(
                "metadata-sst-{}-{}",
                target.name(),
                if $rewrite { "compact" } else { "flush" }
            );
            exercise(&support::root(&case), target, $rewrite, !support::control()).await;
        }
    };
}
case!(disk_full_metadata_counter_flush, Counter, false);
case!(disk_full_metadata_counter_compact, Counter, true);
case!(disk_full_metadata_ref_index_flush, RefIndex, false);
case!(disk_full_metadata_ref_index_compact, RefIndex, true);
case!(disk_full_metadata_archive_index_flush, ArchiveIndex, false);
case!(disk_full_metadata_archive_index_compact, ArchiveIndex, true);
macro_rules! roundtrip {
    ($name:ident,$target:ident) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() {
            let path = tempfile::tempdir().unwrap();
            exercise(path.path(), Target::$target, true, false).await;
        }
    };
}
roundtrip!(metadata_counter_merge_and_owned_close_roundtrip, Counter);
roundtrip!(metadata_ref_index_enclosing_range_roundtrip, RefIndex);
roundtrip!(metadata_archive_index_enclosing_range_roundtrip, ArchiveIndex);
