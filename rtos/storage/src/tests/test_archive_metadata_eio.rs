// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Actual package-body success followed by sequential provider metadata EIO.
use super::*;
use crate::{
    archives::{block_index_db::BlocksIndexKey, package::PKG_HEADER_SIZE},
    db::rocksdb::AccessType,
    repair_protection::LeaseProtection,
    tests::{late_index_eio_support as late, utils::create_block_handle_storage},
    types::BlockMeta,
};
use rtos_block::UInt256;
use std::{collections::BTreeMap, sync::atomic::AtomicUsize, time::Duration};

pub(super) type Rows = BTreeMap<Vec<u8>, Vec<u8>>;
fn stage() -> MetadataCut {
    match std::env::var("RTOS_ARCHIVE_META_STAGE").unwrap().as_str() {
        "entry" => MetadataCut::EntryMeta,
        "status" => MetadataCut::NonSlicedStatus,
        "offset" => MetadataCut::Offset,
        "index" => MetadataCut::BlockIndex,
        _ => panic!("invalid archive metadata stage"),
    }
}
pub(super) fn cf(kind: &str, key: bool) -> String {
    format!("{kind}_{}db_0", if key { "key_" } else { "" })
}
pub(super) fn rows(db: &Arc<RocksDb>, name: &str) -> Rows {
    let mut result = Rows::new();
    db.clone()
        .table::<String>(name, false)
        .unwrap()
        .for_each(&mut |key, value| {
            assert!(result.insert(key.to_vec(), value.to_vec()).is_none());
            Ok(true)
        })
        .unwrap();
    result
}
pub(super) fn old_rows(db: &Arc<RocksDb>, key: bool, old: &[Rows; 2]) {
    for (kind, old) in ["offsets", "block_index"].into_iter().zip(old) {
        let current = rows(db, &cf(kind, key));
        for (id, value) in old {
            assert_eq!(current.get(id), Some(value), "old ACK row changed");
        }
    }
}
pub(super) fn payload(handle: &BlockHandle) -> Vec<u8> {
    format!("actual metadata EIO block {}", handle.id().seq_no()).into_bytes()
}
pub(super) async fn native(
    path: &Path,
    key: bool,
) -> (Arc<RocksDb>, Arc<RocksDb>, Vec<Arc<BlockHandle>>) {
    let provider = RocksDb::new(path, "archive_provider", None, AccessType::ReadWrite).unwrap();
    provider.bind_archive_domain(crate::archives::context::ArchiveDomain::new()).unwrap();
    let handles_db = RocksDb::new(path, "handle_db", None, AccessType::ReadWrite).unwrap();
    let (storage, table) = create_block_handle_storage(handles_db.clone());
    let mut handles = Vec::new();
    for seq in [10u32, 12, 11] {
        let id = BlockIdExt::with_params(
            ShardIdent::masterchain(),
            seq,
            UInt256::from([seq as u8; 32]),
            UInt256::from([seq as u8 + 3; 32]),
        );
        let flags = if key { crate::block_handle_db::FLAG_KEY_BLOCK } else { 0 };
        let handle = storage
            .create_handle(id.clone(), BlockMeta::with_data(flags, seq, u64::from(seq), 0, 0), None)
            .unwrap()
            .or_else(|| storage.load_handle_by_id(&id).unwrap())
            .unwrap();
        assert_eq!(handle.id(), &id);
        storage.save_handle(&handle, None).unwrap();
        handles.push(handle);
    }
    tokio::time::timeout(late::TIMEOUT, storage.sync_pending()).await.unwrap().unwrap();
    drop(storage);
    drop(table);
    (provider, handles_db, handles)
}
pub(super) fn protect(db: &Arc<RocksDb>, id: &BlockIdExt) {
    db.repair_protection()
        .register(77, LeaseProtection { artifacts: vec![id.clone()], ..Default::default() })
        .unwrap();
}
pub(super) async fn open(
    db: &Arc<RocksDb>,
    path: &Path,
    key: bool,
    protected: Option<&BlockIdExt>,
) -> Result<ArchiveSlice> {
    if let Some(id) = protected {
        protect(db, id);
    }
    let root = Arc::new(path.join("pack_root"));
    let mode = if key { PackageType::KeyBlocks } else { PackageType::Blocks };
    if db.db().cf_handle(&cf("status", key)).is_none() {
        ArchiveSlice::new_empty(
            db.test_archive_provider().unwrap(),
            &db.test_archive_provider().unwrap().view().unwrap().enter().unwrap(),
            root,
            0,
            mode,
            0,
            #[cfg(feature = "telemetry")]
            Arc::new(StorageTelemetry::default()),
            Arc::new(StorageAlloc::default()),
        )
        .await
    } else {
        ArchiveSlice::with_data(
            db.repair_protection().clone(),
            db.test_archive_provider().unwrap(),
            &db.test_archive_provider().unwrap().view().unwrap().enter().unwrap(),
            root,
            0,
            mode,
            false,
            false,
            #[cfg(feature = "telemetry")]
            Arc::new(StorageTelemetry::default()),
            Arc::new(StorageAlloc::default()),
        )
        .await
    }
}
pub(super) async fn produce(slice: &ArchiveSlice, handle: &BlockHandle) -> Result<Vec<u8>> {
    tokio::time::timeout(
        late::TIMEOUT,
        slice.add_file(handle, &PackageEntryId::Block(handle.id()), payload(handle)),
    )
    .await
    .expect("archive add_file owner timed out; no cold reopen")
}
pub(super) async fn package(slice: &ArchiveSlice, handle: &BlockHandle) -> Arc<PackageInfo> {
    let ChosenPackage::Info(info) =
        slice.choose_package(handle.id().seq_no(), handle.id().shard()).await.unwrap()
    else {
        panic!("seed package missing")
    };
    info
}
pub(super) async fn reads(slice: &ArchiveSlice, handles: &[Arc<BlockHandle>]) {
    let prefix = AccountIdPrefixFull { workchain_id: -1, prefix: 0 };
    for handle in handles {
        let entry = PackageEntryId::Block(handle.id());
        let found =
            slice.get_file(handle, &entry).await.unwrap().expect("ACKed archive entry missing");
        assert_eq!(found.filename(), entry.filename());
        assert_eq!(found.data(), payload(handle));
        for result in [
            slice.lookup_block_by_seqno(&prefix, handle.id().seq_no()).await,
            slice.lookup_block_by_lt(&prefix, handle.end_lt()).await,
        ] {
            let (id, bytes) = result.unwrap().expect("ACKed archive lookup missing");
            assert_eq!(&id, handle.id());
            assert_eq!(bytes, payload(handle));
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
        assert_eq!(found, vec![(handle.id().clone(), payload(handle))]);
    }
}
pub(super) fn target_rows(
    db: &Arc<RocksDb>,
    key: bool,
    handle: &BlockHandle,
    offset: bool,
    index: bool,
) {
    let offsets = PackageOffsetsDb::with_db(db.clone(), &cf("offsets", key), false).unwrap();
    assert_eq!(offsets.contains(&(&PackageEntryId::Block(handle.id())).into()).unwrap(), offset);
    let lookup = rows(db, &cf("block_index", key));
    for name in [
        BlocksIndexKey::key_with_seqno(handle.id().shard(), handle.id().seq_no()),
        BlocksIndexKey::key_with_lt(handle.id().shard(), handle.end_lt()),
        BlocksIndexKey::key_with_utime(
            handle.id().shard(),
            handle.gen_utime(),
            handle.id().seq_no(),
        ),
    ] {
        assert_eq!(
            lookup.contains_key(name.as_bytes()),
            index,
            "target lookup triplet publication differs"
        );
    }
}
async fn close(
    db: Arc<RocksDb>,
    handles_db: Arc<RocksDb>,
    slice: Option<ArchiveSlice>,
    handles: Vec<Arc<BlockHandle>>,
) {
    if let Some(slice) = slice {
        let info = package(&slice, &handles[0]).await;
        drop(slice);
        drop(handles);
        tokio::time::timeout(late::TIMEOUT, async {
            while Arc::strong_count(&info) != 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("archive package owners remain; cold forbidden");
        tokio::time::timeout(late::TIMEOUT, info.package().close_for_sst_test())
            .await
            .unwrap()
            .unwrap();
        drop(info);
    } else {
        drop(handles);
    }
    late::close_db(db).await;
    late::close_db(handles_db).await;
    eprintln!("ARCHIVE-META NATIVE_ALL_CLOSED");
}
pub(super) fn snapshot(db: &Arc<RocksDb>, key: bool, path: &Path) -> (Vec<Rows>, Vec<u8>) {
    (
        ["entry_meta", "status", "offsets", "block_index"]
            .map(|kind| rows(db, &cf(kind, key)))
            .into(),
        std::fs::read(path).unwrap(),
    )
}
async fn exercise(key: bool) {
    let path = late::root();
    let stage = stage();
    let control = late::control();
    let protected = std::env::var("RTOS_ARCHIVE_META_PROTECTED").as_deref() == Ok("1");
    assert!(key || stage != MetadataCut::NonSlicedStatus, "Blocks has no status syscall at append");
    let (db, handles_db, handles) = native(&path, key).await;
    let slice = open(&db, &path, key, None).await.unwrap();
    for handle in &handles[..2] {
        assert_eq!(produce(&slice, handle).await.unwrap(), payload(handle));
    }
    reads(&slice, &handles[..2]).await;
    let info = package(&slice, &handles[0]).await;
    let pack_path = info.package().path().to_path_buf();
    let prefix = std::fs::read(&pack_path).unwrap();
    let old_size = prefix.len() as u64 - PKG_HEADER_SIZE as u64;
    drop(info);
    let old = [rows(&db, &cf("offsets", key)), rows(&db, &cf("block_index", key))];
    assert_eq!(old[0].len(), 2);
    assert_eq!(old[1].len(), 6);
    let mut complete = prefix.clone();
    PackageEntry::with_data(
        PackageEntryId::Block(handles[2].id()).filename(),
        payload(&handles[2]),
    )
    .write_to(&mut complete)
    .await
    .unwrap();
    let new_size = complete.len() as u64 - PKG_HEADER_SIZE as u64;
    if protected {
        protect(&db, handles[0].id());
    }
    eprintln!("ARCHIVE-META SEEDS_SYNCED pack={} old_size={old_size}", pack_path.display());
    let observed = Arc::new(AtomicUsize::new(0));
    let gate: MetadataGate = {
        let db = db.clone();
        let old = old.clone();
        let file = pack_path.clone();
        let observed = observed.clone();
        let complete = complete.clone();
        let target = handles[2].clone();
        Arc::new(move |offset, size| {
            assert_eq!(offset, old_size);
            assert_eq!(size, new_size);
            assert_eq!(
                std::fs::read(&file).unwrap(),
                complete,
                "real durable target body incomplete"
            );
            old_rows(&db, key, &old);
            let entry = PackageEntryMetaDb::with_db(db.clone(), &cf("entry_meta", key), false)?;
            let meta = entry.get_value(&if key { u32::MAX.into() } else { 0u32.into() })?;
            assert_eq!(
                meta.entry_size(),
                if stage == MetadataCut::EntryMeta { old_size } else { new_size }
            );
            assert_eq!(meta.version(), DEFAULT_PKG_VERSION);
            if key {
                let status = PackageStatusDb::with_db(db.clone(), &cf("status", key), false)?;
                assert_eq!(
                    status.get_value::<u64>(&PackageStatusKey::NonSlicedSize)?,
                    if matches!(stage, MetadataCut::Offset | MetadataCut::BlockIndex) {
                        new_size
                    } else {
                        old_size
                    }
                );
            }
            target_rows(&db, key, &target, stage == MetadataCut::BlockIndex, false);
            db.sync_wal()?;
            eprintln!("ARCHIVE-META PREFIX_SYNCED stage={stage:?} size={size}");
            if std::env::var("RTOS_LATE_INDEX_NO_ARM").as_deref() == Ok("1") {
                eprintln!("ARCHIVE-META ARM_SKIPPED");
            } else {
                std::fs::write(late::arm(), b"post-package-prefix")?;
                eprintln!("ARCHIVE-META ARMED stage={stage:?}");
            }
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    };
    *slice.metadata_gate.lock().unwrap() = Some((stage, gate));
    let result = produce(&slice, &handles[2]).await;
    eprintln!("ARCHIVE-META TARGET_RESULT stage={stage:?} result={result:?}");
    assert_eq!(result.is_ok(), control, "archive metadata acknowledgement differs");
    if let Err(error) = result {
        late::check_eio(&error.to_string());
    }
    assert_eq!(observed.load(Ordering::SeqCst), 1);
    old_rows(&db, key, &old);
    reads(&slice, &handles[..2]).await;
    let offset = control || stage == MetadataCut::BlockIndex;
    target_rows(&db, key, &handles[2], offset, control);
    if !control {
        let retry = produce(&slice, &handles[2]).await;
        assert!(retry.is_err(), "uncertain live package accepted retry");
        assert!(retry.unwrap_err().to_string().contains("uncertain"));
        assert_eq!(std::fs::read(&pack_path).unwrap(), complete);
        assert_eq!(observed.load(Ordering::SeqCst), 1);
    }
    late::disarm();
    close(db, handles_db, Some(slice), handles).await;
    let (db, handles_db, handles) = native(&path, key).await;
    let before_cold = std::fs::read(&pack_path).unwrap();
    let opened = open(&db, &path, key, protected.then(|| handles[0].id())).await;
    let refusal = !control
        && protected
        && matches!(stage, MetadataCut::EntryMeta | MetadataCut::NonSlicedStatus);
    if refusal {
        let error = match opened {
            Err(error) => error,
            Ok(_) => panic!("protected uncertain archive accepted"),
        };
        assert!(error.to_string().contains(if stage == MetadataCut::NonSlicedStatus {
            "ambiguous durable length metadata"
        } else {
            "physical length differs from durable metadata"
        }));
        assert_eq!(std::fs::read(&pack_path).unwrap(), before_cold);
        old_rows(&db, key, &old);
        target_rows(&db, key, &handles[2], offset, false);
        close(db, handles_db, None, handles).await;
        eprintln!("ARCHIVE-META COMPLETE outcome=protected-refusal key={key} stage={stage:?}");
        return;
    }
    let slice = opened.expect("coherent archive cold consumer failed");
    old_rows(&db, key, &old);
    reads(&slice, &handles[..2]).await;
    target_rows(&db, key, &handles[2], offset, control);
    assert_eq!(
        slice
            .get_file(&handles[2], &PackageEntryId::Block(handles[2].id()))
            .await
            .unwrap()
            .is_some(),
        offset
    );
    let cold_bytes = std::fs::read(&pack_path).unwrap();
    assert!(cold_bytes.starts_with(&prefix));
    if !control && matches!(stage, MetadataCut::EntryMeta | MetadataCut::NonSlicedStatus) {
        assert_eq!(cold_bytes, prefix, "unprotected old committed end not restored");
    }
    assert_eq!(produce(&slice, &handles[2]).await.unwrap(), payload(&handles[2]));
    reads(&slice, &handles).await;
    target_rows(&db, key, &handles[2], true, true);
    let final_data = snapshot(&db, key, &pack_path);
    assert!(final_data.1.starts_with(&prefix));
    close(db, handles_db, Some(slice), handles).await;
    let (db, handles_db, handles) = native(&path, key).await;
    let slice = open(&db, &path, key, protected.then(|| handles[0].id())).await.unwrap();
    reads(&slice, &handles).await;
    old_rows(&db, key, &old);
    assert_eq!(snapshot(&db, key, &pack_path), final_data);
    close(db, handles_db, Some(slice), handles).await;
    eprintln!("ARCHIVE-META COMPLETE outcome=recovered key={key} stage={stage:?} protected={protected} control={control}");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires private native archive metadata WAL EIO harness"]
async fn blocks_body_metadata_eio() {
    exercise(false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires private native archive metadata WAL EIO harness"]
async fn keyblocks_body_metadata_eio() {
    exercise(true).await;
}
