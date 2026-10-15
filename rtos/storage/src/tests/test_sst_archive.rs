// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Real ArchiveSlice component and provider; no block authentication/epoch GC claim.
use super::*;
use crate::{
    archives::package::PKG_HEADER_SIZE,
    db::rocksdb::AccessType,
    tests::{disk_full_state_support as support, utils::create_block_handle_storage},
    types::BlockMeta,
};
use rtos_block::{AccountIdPrefixFull, UInt256};
use std::{collections::BTreeMap, time::Duration};

const TIMEOUT: Duration = Duration::from_secs(30);
#[derive(Clone, Copy)]
enum Kind {
    Entry,
    Index,
    Offset,
    Status,
}
impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Entry => "entry",
            Self::Index => "index",
            Self::Offset => "offset",
            Self::Status => "status",
        }
    }
    fn cf(self, key: bool) -> &'static str {
        match (self, key) {
            (Self::Entry, false) => "entry_meta_db_0",
            (Self::Entry, true) => "entry_meta_key_db_0",
            (Self::Index, false) => "block_index_db_0",
            (Self::Index, true) => "block_index_key_db_0",
            (Self::Offset, false) => "offsets_db_0",
            (Self::Offset, true) => "offsets_key_db_0",
            (Self::Status, false) => "status_db_0",
            (Self::Status, true) => "status_key_db_0",
        }
    }
}
async fn joined<T: Send + 'static>(task: impl FnOnce() -> T + Send + 'static) -> T {
    let mut owner = tokio::task::spawn_blocking(task);
    tokio::time::timeout(TIMEOUT, &mut owner)
        .await
        .expect("archive SST owner timed out; no cold reopen")
        .unwrap()
}
fn configure(db: &RocksDb) -> Result<()> {
    for name in rocksdb::DB::list_cf(&rocksdb::Options::default(), db.path())? {
        let options = [("disable_auto_compactions", "true"), ("write_buffer_size", "16777216")];
        if name == "default" {
            db.db().set_options(&options)?;
        } else {
            db.db().set_options_cf(&db.db().cf_handle(&name).unwrap(), &options)?;
        }
    }
    Ok(())
}
async fn sole(db: &Arc<RocksDb>) {
    tokio::time::timeout(TIMEOUT, async {
        while Arc::strong_count(db) != 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("archive DB owners remain; no cold reopen");
}
fn ids() -> [BlockIdExt; 5] {
    [1, ARCHIVE_PACKAGE_SIZE + 1, 2, 2 * ARCHIVE_PACKAGE_SIZE + 1, 3 * ARCHIVE_PACKAGE_SIZE + 1]
        .map(|seq| {
            BlockIdExt::with_params(
                ShardIdent::masterchain(),
                seq,
                UInt256::from([seq as u8; 32]),
                UInt256::from([seq.wrapping_add(10) as u8; 32]),
            )
        })
}
fn payload(handle: &BlockHandle) -> Vec<u8> {
    format!("public archive block {}", handle.id().seq_no()).into_bytes()
}
async fn open(
    path: &Path,
    key: bool,
) -> (Arc<RocksDb>, Arc<RocksDb>, ArchiveSlice, Vec<Arc<BlockHandle>>) {
    let provider = RocksDb::new(path, "archive_provider", None, AccessType::ReadWrite).unwrap();
    provider.bind_archive_domain(crate::archives::context::ArchiveDomain::new()).unwrap();
    let handles_db = RocksDb::new(path, "handle_db", None, AccessType::ReadWrite).unwrap();
    let (storage, table) = create_block_handle_storage(handles_db.clone());
    let mut handles = Vec::new();
    for id in ids() {
        let flags = if key { crate::block_handle_db::FLAG_KEY_BLOCK } else { 0 };
        let handle = storage
            .create_handle(
                id.clone(),
                BlockMeta::with_data(flags, id.seq_no(), u64::from(id.seq_no()), 0, 0),
                None,
            )
            .unwrap()
            .or_else(|| storage.load_handle_by_id(&id).unwrap())
            .unwrap();
        assert_eq!(handle.id(), &id);
        assert_eq!(handle.end_lt(), u64::from(id.seq_no()));
        storage.save_handle(&handle, None).unwrap();
        handles.push(handle);
    }
    storage.sync_pending().await.unwrap();
    drop(table);
    drop(storage);
    sole(&handles_db).await;
    let pack_root = Arc::new(path.join("pack_root"));
    std::fs::create_dir_all(pack_root.as_path()).unwrap();
    let mode = if key { PackageType::KeyBlocks } else { PackageType::Blocks };
    let existed = provider.db().cf_handle(Kind::Status.cf(key)).is_some();
    let slice = if existed {
        ArchiveSlice::with_data(
            provider.repair_protection().clone(),
            provider.test_archive_provider().unwrap(),
        &provider.test_archive_provider().unwrap().view().unwrap().enter().unwrap(),
            pack_root,
            0,
            mode,
            false,
            false,
            #[cfg(feature = "telemetry")]
            Arc::new(StorageTelemetry::default()),
            Arc::new(StorageAlloc::default()),
        )
        .await
    } else {
        ArchiveSlice::new_empty(
            provider.test_archive_provider().unwrap(),
        &provider.test_archive_provider().unwrap().view().unwrap().enter().unwrap(),
            pack_root,
            0,
            mode,
            0,
            #[cfg(feature = "telemetry")]
            Arc::new(StorageTelemetry::default()),
            Arc::new(StorageAlloc::default()),
        )
        .await
    }
    .expect("acknowledged archive provider cold open failed");
    configure(&provider).unwrap();
    configure(&handles_db).unwrap();
    (provider, handles_db, slice, handles)
}
async fn put(slice: &ArchiveSlice, handle: &BlockHandle) {
    let bytes = payload(handle);
    assert_eq!(
        slice.add_file(handle, &PackageEntryId::Block(handle.id()), bytes.clone()).await.unwrap(),
        bytes
    );
}
async fn infos(slice: &ArchiveSlice, handles: &[Arc<BlockHandle>]) -> Vec<Arc<PackageInfo>> {
    let mut infos = BTreeMap::new();
    for handle in handles {
        let ChosenPackage::Info(info) =
            slice.choose_package(handle.id().seq_no(), handle.id().shard()).await.unwrap()
        else {
            panic!("ACKed archive package absent");
        };
        infos.entry(info.index()).or_insert(info);
    }
    infos.into_values().collect()
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
    tables: BTreeMap<String, Rows>,
    packs: BTreeMap<PathBuf, Vec<u8>>,
}
async fn inspect(
    db: &Arc<RocksDb>,
    slice: &ArchiveSlice,
    handles: &[Arc<BlockHandle>],
    key: bool,
) -> Dataset {
    let prefix = AccountIdPrefixFull { workchain_id: -1, prefix: 0 };
    for handle in handles {
        let entry = PackageEntryId::Block(handle.id());
        let bytes = payload(handle);
        let found =
            slice.get_file(handle, &entry).await.unwrap().expect("ACKed archive entry missing");
        assert_eq!(found.filename(), entry.filename());
        assert_eq!(found.data(), bytes);
        for result in [
            slice.lookup_block_by_seqno(&prefix, handle.id().seq_no()).await,
            slice.lookup_block_by_lt(&prefix, handle.end_lt()).await,
        ] {
            let (id, found) = result.unwrap().expect("ACKed archive block lookup missing");
            assert_eq!(&id, handle.id());
            assert_eq!(found, bytes);
        }
        let mut found = Vec::new();
        slice
            .lookup_blocks_by_utime(
                &prefix,
                handle.gen_utime(),
                Box::new(|id, bytes| {
                    found.push((id, bytes));
                    Ok(true)
                }),
            )
            .await
            .unwrap();
        assert_eq!(found, vec![(handle.id().clone(), bytes)]);
    }
    let packages = infos(slice, handles).await;
    assert_eq!(
        packages.len(),
        if key {
            1
        } else if handles.len() == 2 {
            2
        } else {
            handles.len() - 1
        }
    );
    assert_eq!(slice.sliced_mode, !key);
    assert_eq!(
        slice.package_status_db.get_value::<bool>(&PackageStatusKey::SlicedMode).unwrap(),
        !key
    );
    if key {
        assert_eq!(
            slice.package_status_db.get_value::<u64>(&PackageStatusKey::NonSlicedSize).unwrap(),
            packages[0].package().size()
        );
    } else {
        assert_eq!(
            slice.package_status_db.get_value::<u32>(&PackageStatusKey::TotalSlices).unwrap(),
            packages.len() as u32
        );
        assert_eq!(
            slice.package_status_db.get_value::<u32>(&PackageStatusKey::SliceSize).unwrap(),
            ARCHIVE_PACKAGE_SIZE
        );
        assert_eq!(
            slice.package_status_db.get_value::<u8>(&PackageStatusKey::ShardSplitDepth).unwrap(),
            0
        );
    }
    let mut packs = BTreeMap::new();
    for info in packages {
        let meta = slice
            .entry_db
            .get_value(&if key { u32::MAX.into() } else { info.index().into() })
            .unwrap();
        assert_eq!(meta.entry_size(), info.package().size());
        assert_eq!(meta.version(), DEFAULT_PKG_VERSION);
        assert!(
            meta.get_info().unwrap() == if key { None } else { Some(info.entry().clone()) },
            "archive metadata package identity changed"
        );
        let bytes = std::fs::read(info.package().path()).unwrap();
        assert_eq!(bytes.len() as u64, info.package().size() + PKG_HEADER_SIZE as u64);
        packs.insert(info.package().path().to_path_buf(), bytes);
    }
    let tables: BTreeMap<_, _> = [Kind::Entry, Kind::Index, Kind::Offset, Kind::Status]
        .into_iter()
        .map(|kind| (kind.cf(key).to_owned(), rows(db, kind.cf(key))))
        .collect();
    assert_eq!(tables[Kind::Entry.cf(key)].len(), packs.len());
    assert_eq!(tables[Kind::Index.cf(key)].len(), 3 * handles.len());
    assert_eq!(tables[Kind::Offset.cf(key)].len(), handles.len());
    assert_eq!(tables[Kind::Status.cf(key)].len(), if key { 2 } else { 4 });
    Dataset { tables, packs }
}
fn prefixes(old: &Dataset, new: &Dataset) {
    for (path, bytes) in &old.packs {
        assert!(new.packs[path].starts_with(bytes), "ACKed archive pack prefix changed");
    }
}
async fn close(
    provider: Arc<RocksDb>,
    handles_db: Arc<RocksDb>,
    slice: ArchiveSlice,
    handles: Vec<Arc<BlockHandle>>,
    acknowledged: usize,
) {
    for handle in &handles[..acknowledged] {
        slice.sync_block_package(handle, None).await.unwrap();
    }
    let packages = infos(&slice, &handles[..acknowledged]).await;
    drop(slice);
    drop(handles);
    tokio::time::timeout(TIMEOUT, async {
        while packages.iter().any(|info| Arc::strong_count(info) != 1) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("archive package owners remain; no cold reopen");
    for info in &packages {
        tokio::time::timeout(TIMEOUT, info.package().close_for_sst_test())
            .await
            .expect("archive package close timed out; no cold reopen")
            .unwrap();
    }
    drop(packages);
    sole(&provider).await;
    sole(&handles_db).await;
    eprintln!("SST-OBS archive-provider-owners=1 handle-db-owners=1");
    joined(move || {
        provider.db().cancel_all_background_work(true);
        handles_db.db().cancel_all_background_work(true);
        drop(provider);
        drop(handles_db);
    })
    .await;
    eprintln!("SST-OBS archive-native-close=complete");
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
            support::check_enospc(&result.expect_err("archive SST flush falsely acknowledged"));
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
    eprintln!("SST-OBS independent-provider-sync={:?}", db.sync_wal());
    let after = files(db, cf);
    if fault {
        assert_eq!(after, before, "failed archive SST changed registered ACK input");
    } else {
        let fresh: Vec<_> =
            after.iter().filter(|f| !before.iter().any(|old| old.name == f.name)).collect();
        assert!(!fresh.is_empty(), "archive positive maintenance missing fresh registered output");
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
}
async fn exercise(path: &Path, key: bool, kind: Kind, rewrite: bool, fault: bool) {
    std::fs::create_dir_all(path).unwrap();
    let cf = kind.cf(key);
    let (db, handles_db, slice, handles) = open(path, key).await;
    put(&slice, &handles[0]).await;
    put(&slice, &handles[1]).await;
    let seed_data = inspect(&db, &slice, &handles[..2], key).await;
    flush(db.clone(), cf).await.unwrap();
    let owner = db.clone();
    joined(move || compact(&owner, cf, false)).await;
    let seed = files(&db, cf);
    assert_eq!(seed.len(), 1);
    assert_eq!(seed[0].level, 6);
    put(&slice, &handles[0]).await;
    put(&slice, &handles[2]).await;
    put(&slice, &handles[3]).await;
    let four = inspect(&db, &slice, &handles[..4], key).await;
    prefixes(&seed_data, &four);
    assert_eq!(files(&db, cf), seed, "archive target auto-flushed");
    if rewrite {
        flush(db.clone(), cf).await.unwrap();
    }
    let before = files(&db, cf);
    assert_eq!(before.len(), if rewrite { 2 } else { 1 });
    if rewrite {
        let l0 = before.iter().find(|f| f.level == 0).unwrap();
        assert!(
            l0.start <= seed[0].end && seed[0].start <= l0.end,
            "archive target inputs do not overlap"
        );
    }
    for file in &before {
        eprintln!(
            "SST-INPUT name={} cf={} level={} size={} range={:?}/{:?} sha256={:x}",
            file.name, cf, file.level, file.size, file.start, file.end, file.hash
        );
    }
    let filler = fault.then(|| support::fill(path));
    maintenance(&db, cf, rewrite, fault, &before).await;
    assert_eq!(
        inspect(&db, &slice, &handles[..4], key).await,
        four,
        "live archive ACK dataset changed"
    );
    if let Some(filler) = filler {
        std::fs::remove_file(filler).unwrap();
    }
    close(db, handles_db, slice, handles, 4).await;
    let (db, handles_db, slice, handles) = open(path, key).await;
    assert_eq!(
        inspect(&db, &slice, &handles[..4], key).await,
        four,
        "first cold before retry archive ACK changed"
    );
    put(&slice, &handles[4]).await;
    let five = inspect(&db, &slice, &handles, key).await;
    prefixes(&four, &five);
    if rewrite {
        flush(db.clone(), cf).await.unwrap();
    }
    let before = files(&db, cf);
    maintenance(&db, cf, rewrite, false, &before).await;
    assert_eq!(inspect(&db, &slice, &handles, key).await, five);
    close(db, handles_db, slice, handles, 5).await;
    let (db, handles_db, slice, handles) = open(path, key).await;
    assert_eq!(inspect(&db, &slice, &handles, key).await, five, "second cold archive ACK changed");
    close(db, handles_db, slice, handles, 5).await;
}
macro_rules! case {
    ($name:ident,$key:literal,$kind:ident,$rewrite:literal) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[ignore = "isolated archive provider SST disk-full harness only"]
        async fn $name() {
            let kind = Kind::$kind;
            let case = format!(
                "archive-sst-{}-{}-{}",
                if $key { "keys" } else { "blocks" },
                kind.name(),
                if $rewrite { "compact" } else { "flush" }
            );
            exercise(&support::root(&case), $key, kind, $rewrite, !support::control()).await;
        }
    };
}
case!(disk_full_archive_blocks_entry_flush, false, Entry, false);
case!(disk_full_archive_blocks_entry_compact, false, Entry, true);
case!(disk_full_archive_blocks_index_flush, false, Index, false);
case!(disk_full_archive_blocks_index_compact, false, Index, true);
case!(disk_full_archive_blocks_offset_flush, false, Offset, false);
case!(disk_full_archive_blocks_offset_compact, false, Offset, true);
case!(disk_full_archive_blocks_status_flush, false, Status, false);
case!(disk_full_archive_blocks_status_compact, false, Status, true);
case!(disk_full_archive_keys_entry_flush, true, Entry, false);
case!(disk_full_archive_keys_entry_compact, true, Entry, true);
case!(disk_full_archive_keys_index_flush, true, Index, false);
case!(disk_full_archive_keys_index_compact, true, Index, true);
case!(disk_full_archive_keys_offset_flush, true, Offset, false);
case!(disk_full_archive_keys_offset_compact, true, Offset, true);
case!(disk_full_archive_keys_status_flush, true, Status, false);
case!(disk_full_archive_keys_status_compact, true, Status, true);
macro_rules! normal {
    ($name:ident,$key:literal,$kind:ident) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() {
            let path = tempfile::tempdir().unwrap();
            exercise(path.path(), $key, Kind::$kind, true, false).await;
        }
    };
}
normal!(archive_blocks_entry_roundtrip, false, Entry);
normal!(archive_blocks_index_roundtrip, false, Index);
normal!(archive_blocks_offset_roundtrip, false, Offset);
normal!(archive_blocks_status_roundtrip, false, Status);
normal!(archive_keys_entry_roundtrip, true, Entry);
normal!(archive_keys_index_roundtrip, true, Index);
normal!(archive_keys_offset_roundtrip, true, Offset);
normal!(archive_keys_status_roundtrip, true, Status);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn archive_key_cold_version_and_unacknowledged_tail_recovery() {
    use std::io::Write;
    let path = tempfile::tempdir().unwrap();
    let (db, handles_db, slice, handles) = open(path.path(), true).await;
    put(&slice, &handles[0]).await;
    put(&slice, &handles[1]).await;
    let acknowledged = inspect(&db, &slice, &handles[..2], true).await;
    let package = acknowledged.packs.keys().next().unwrap().clone();
    close(db, handles_db, slice, handles, 2).await;
    let mut file = std::fs::OpenOptions::new().append(true).open(&package).unwrap();
    file.write_all(b"private unacknowledged package tail").unwrap();
    file.sync_all().unwrap();
    drop(file);
    let (db, handles_db, slice, handles) = open(path.path(), true).await;
    assert_eq!(
        inspect(&db, &slice, &handles[..2], true).await,
        acknowledged,
        "unprotected cold recovery retained an unACKed tail"
    );
    assert_eq!(infos(&slice, &handles[..1]).await[0].version(), DEFAULT_PKG_VERSION);
    put(&slice, &handles[4]).await;
    let meta = slice.entry_db.get_value(&u32::MAX.into()).unwrap();
    assert_eq!(meta.version(), DEFAULT_PKG_VERSION, "cold append downgraded package version");
    close(db, handles_db, slice, handles, 2).await;
    let (db, handles_db, slice, handles) = open(path.path(), true).await;
    assert_eq!(infos(&slice, &handles[..1]).await[0].version(), DEFAULT_PKG_VERSION);
    let found = slice
        .get_file(&handles[4], &PackageEntryId::Block(handles[4].id()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.data(), payload(&handles[4]));
    close(db, handles_db, slice, handles, 2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn archive_key_legacy_status_truncation_keeps_committed_boundary() {
    let path = tempfile::tempdir().unwrap();
    let (db, handles_db, slice, handles) = open(path.path(), true).await;
    put(&slice, &handles[0]).await;
    let first = inspect(&db, &slice, &handles[..1], true).await;
    let package = first.packs.keys().next().unwrap().clone();
    let size = first.packs[&package].len() as u64 - PKG_HEADER_SIZE as u64;
    put(&slice, &handles[1]).await;
    close(db, handles_db, slice, handles, 2).await;
    let db = RocksDb::new(path.path(), "archive_provider", None, AccessType::ReadWrite).unwrap();
    db.bind_archive_domain(crate::archives::context::ArchiveDomain::new()).unwrap();
    let status = PackageStatusDb::with_db(db.clone(), Kind::Status.cf(true), false).unwrap();
    status.put_value(&PackageStatusKey::NonSlicedSize, &size).unwrap();
    db.sync_wal().unwrap();
    drop(status);
    sole(&db).await;
    joined(move || {
        db.db().cancel_all_background_work(true);
        drop(db);
    })
    .await;
    let (db, handles_db, slice, handles) = open(path.path(), true).await;
    assert_eq!(
        std::fs::read(&package).unwrap(),
        first.packs[&package],
        "status-only committed truncation lost its boundary"
    );
    assert_eq!(infos(&slice, &handles[..1]).await[0].version(), DEFAULT_PKG_VERSION);
    let found = slice
        .get_file(&handles[0], &PackageEntryId::Block(handles[0].id()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.data(), payload(&handles[0]));
    // The legacy truncation leaves stale second-entry indices; do not claim their cleanup.
    close(db, handles_db, slice, handles, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn archive_key_protected_length_mismatch_refuses_without_file_mutation() {
    let path = tempfile::tempdir().unwrap();
    let (db, handles_db, slice, handles) = open(path.path(), true).await;
    put(&slice, &handles[0]).await;
    let first = inspect(&db, &slice, &handles[..1], true).await;
    let size = first.packs.values().next().unwrap().len() as u64 - PKG_HEADER_SIZE as u64;
    put(&slice, &handles[1]).await;
    let acknowledged = inspect(&db, &slice, &handles[..2], true).await;
    let packages = infos(&slice, &handles[..2]).await;
    let protected = handles[0].id().clone();
    drop(slice);
    drop(handles);
    assert!(packages.iter().all(|p| Arc::strong_count(p) == 1));
    for info in &packages {
        info.package().close_for_sst_test().await.unwrap();
    }
    drop(packages);
    sole(&db).await;
    sole(&handles_db).await;
    let status = PackageStatusDb::with_db(db.clone(), Kind::Status.cf(true), false).unwrap();
    status.put_value(&PackageStatusKey::NonSlicedSize, &size).unwrap();
    db.sync_wal().unwrap();
    drop(status);
    db.repair_protection()
        .register(
            77,
            crate::repair_protection::LeaseProtection {
                artifacts: vec![protected],
                ..Default::default()
            },
        )
        .unwrap();
    let result = ArchiveSlice::with_data(
        db.repair_protection().clone(),
        db.test_archive_provider().unwrap(),
        &db.test_archive_provider().unwrap().view().unwrap().enter().unwrap(),
        Arc::new(path.path().join("pack_root")),
        0,
        PackageType::KeyBlocks,
        false,
        false,
        #[cfg(feature = "telemetry")]
        Arc::new(StorageTelemetry::default()),
        Arc::new(StorageAlloc::default()),
    )
    .await;
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("protected ambiguous package accepted"),
    };
    assert!(error.to_string().contains("ambiguous durable length metadata"));
    for (package, bytes) in acknowledged.packs {
        assert_eq!(std::fs::read(package).unwrap(), bytes);
    }
    sole(&db).await;
    joined(move || {
        db.db().cancel_all_background_work(true);
        handles_db.db().cancel_all_background_work(true);
        drop(db);
        drop(handles_db);
    })
    .await;
}
