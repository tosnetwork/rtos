// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Archive package/index ENOSPC at actual add_file cut points.
//! Separate live probes from untouched failure-state cold reopen fixtures.
use super::*;
use crate::{db::rocksdb::AccessType, tests::utils::create_block_handle_storage, types::BlockMeta};
use std::{io::Write, ops::Deref};

fn fill(path: &Path) -> PathBuf {
    let path = path.join("enospc-filler");
    let mut file = std::fs::File::create(&path).unwrap();
    for size in [65536, 4096] {
        loop {
            match file.write_all(&vec![0; size]) {
                Ok(()) => (),
                Err(error) => {
                    assert_eq!(error.raw_os_error(), Some(28));
                    break;
                }
            }
        }
    }
    path
}
fn id(seqno: u32) -> BlockIdExt {
    BlockIdExt::with_params(
        ShardIdent::masterchain(),
        seqno,
        rtos_block::UInt256::from([seqno as u8; 32]),
        rtos_block::UInt256::from([seqno as u8 + 10; 32]),
    )
}
fn make_handles(db: &Arc<RocksDb>) -> Vec<Arc<BlockHandle>> {
    let (storage, _) = create_block_handle_storage(db.clone());
    (1..=5)
        .map(|seqno| {
            storage
                .create_handle(
                    id(seqno),
                    BlockMeta::with_data(0, seqno, u64::from(seqno), 0, 0),
                    None,
                )
                .unwrap()
                .unwrap()
        })
        .collect()
}
fn flush(db: &Arc<RocksDb>) {
    let names = rocksdb::DB::list_cf(&rocksdb::Options::default(), db.path()).unwrap();
    let raw = db.as_ref().deref();
    for name in names {
        if name == "default" {
            raw.flush().unwrap();
        } else {
            raw.flush_cf(&raw.cf_handle(&name).expect("named provider CF must be open")).unwrap();
        }
    }
    db.sync_wal().unwrap();
}
async fn reopen(db: &Arc<RocksDb>, root: Arc<PathBuf>) -> ArchiveSlice {
    ArchiveSlice::with_data(
        db.repair_protection().clone(),
        db.clone(),
        root,
        0,
        PackageType::Blocks,
        false,
        false,
        #[cfg(feature = "telemetry")]
        Arc::new(StorageTelemetry::default()),
        Arc::new(StorageAlloc::default()),
    )
    .await
    .unwrap()
}
async fn assert_entry(slice: &ArchiveSlice, handle: &BlockHandle, data: &[u8]) {
    let entry = PackageEntryId::Block(handle.id());
    let found =
        slice.get_file(handle, &entry).await.unwrap().expect("acknowledged indexed entry missing");
    assert_eq!(found.filename(), entry.filename(), "stale offset names a different entry");
    assert_eq!(found.data(), data, "stale offset or incomplete indexed bytes");
    let prefix = rtos_block::AccountIdPrefixFull { workchain_id: -1, prefix: 0 };
    let (indexed_id, indexed_bytes) = slice
        .lookup_block_by_seqno(&prefix, handle.id().seq_no())
        .await
        .unwrap()
        .expect("acknowledged block-index entry missing");
    assert_eq!(&indexed_id, handle.id());
    assert_eq!(indexed_bytes, data);
}
async fn exercise(cut: &str, live: bool) {
    let mount =
        PathBuf::from(std::env::var_os("RTOS_ENOSPC_ROOT").expect("run inside tmpfs harness"));
    let mode = if live { "live" } else { "cold" };
    let case = format!("archive-{cut}-{mode}");
    let directory = mount.join(&case);
    let root = Arc::new(directory.join("db"));
    std::fs::create_dir_all(&directory).unwrap();
    let control = std::env::var("RTOS_ENOSPC_CONTROL").as_deref() == Ok("1");
    let db = RocksDb::new(&directory, "db", None, AccessType::ReadWrite).unwrap();
    let handles = make_handles(&db);
    let slice = ArchiveSlice::new_empty(
        db.clone(),
        root.clone(),
        0,
        PackageType::Blocks,
        0,
        #[cfg(feature = "telemetry")]
        Arc::new(StorageTelemetry::default()),
        Arc::new(StorageAlloc::default()),
    )
    .await
    .unwrap();
    let seed = b"acknowledged archive block";
    slice
        .add_file(&handles[0], &PackageEntryId::Block(handles[0].id()), seed.to_vec())
        .await
        .unwrap();
    let package =
        PackageId::for_block(0).full_path(root.as_path(), &ShardIdent::masterchain()).unwrap();
    let original = std::fs::read(&package).unwrap();
    let target = if cut == "body" { vec![0x5a; 65536] } else { b"new indexed block".to_vec() };
    if cut == "index" {
        let entry = PackageEntry::with_data(
            PackageEntryId::Block(handles[1].id()).filename(),
            target.clone(),
        );
        assert!(
            original.len() as u64 + entry.serialized_size() <= 4096,
            "index cut must fit package writes inside the allocated first page"
        );
    }
    flush(&db);
    let filler = if control { None } else { Some(fill(&directory)) };
    let result =
        slice.add_file(&handles[1], &PackageEntryId::Block(handles[1].id()), target.clone()).await;
    assert_eq!(result.is_ok(), control, "archive acknowledgement: {result:?}");
    if let Err(error) = result {
        let error = format!("{error:#}");
        assert!(error.contains("No space left") || error.contains("ENOSPC"), "{error}");
    }
    if let Some(filler) = filler {
        std::fs::remove_file(filler).unwrap();
    }
    assert_entry(&slice, &handles[0], seed).await;
    assert!(
        std::fs::read(&package).unwrap().starts_with(&original),
        "acknowledged pack prefix changed"
    );
    if live {
        // Drain any one-shot Tokio error too: refusal of only the first retry
        // does not prove that the damaged instance cannot acknowledge corruption.
        for handle in &handles[2..] {
            let bytes = format!("independent probe {}", handle.id().seq_no()).into_bytes();
            let result =
                slice.add_file(handle, &PackageEntryId::Block(handle.id()), bytes.clone()).await;
            if control {
                assert!(result.is_ok(), "live positive control: {result:?}");
            }
            if result.is_ok() {
                assert_entry(&slice, handle, &bytes).await;
            }
            assert_entry(&slice, &handles[0], seed).await;
        }
    }
    // The cold-only fixture has performed NO append since the failed target.
    drop(slice);
    drop(handles);
    drop(db);
    let db = RocksDb::new(&directory, "db", None, AccessType::ReadWrite).unwrap();
    let handles = make_handles(&db);
    let slice = reopen(&db, root.clone()).await;
    assert_entry(&slice, &handles[0], seed).await;
    let recovered =
        slice.get_file(&handles[1], &PackageEntryId::Block(handles[1].id())).await.unwrap();
    if let Some(entry) = &recovered {
        assert_eq!(entry.filename(), PackageEntryId::Block(handles[1].id()).filename());
        assert_eq!(entry.data(), target);
    }
    if control {
        assert!(recovered.is_some());
    }
    if !control && !live {
        assert_eq!(
            std::fs::read(&package).unwrap(),
            original,
            "unprotected recovery must discard only its uncommitted tail"
        );
    }
    slice
        .add_file(&handles[1], &PackageEntryId::Block(handles[1].id()), target.clone())
        .await
        .unwrap();
    assert_entry(&slice, &handles[1], &target).await;
    drop(slice);
    drop(handles);
    drop(db);
    let db = RocksDb::new(&directory, "db", None, AccessType::ReadWrite).unwrap();
    let handles = make_handles(&db);
    let slice = reopen(&db, root).await;
    assert_entry(&slice, &handles[0], seed).await;
    assert_entry(&slice, &handles[1], &target).await;
    eprintln!("ENOSPC-CASE {case} {} ok", if control { "control" } else { "fault" });
}
#[tokio::test]
#[ignore = "requires isolated ENOSPC tmpfs and syscall trace"]
async fn disk_full_archive_body_live() {
    exercise("body", true).await;
}
#[tokio::test]
#[ignore = "requires isolated ENOSPC tmpfs and syscall trace"]
async fn disk_full_archive_body_cold() {
    exercise("body", false).await;
}
#[tokio::test]
#[ignore = "requires isolated ENOSPC tmpfs and syscall trace"]
async fn disk_full_archive_index_live() {
    exercise("index", true).await;
}
#[tokio::test]
#[ignore = "requires isolated ENOSPC tmpfs and syscall trace"]
async fn disk_full_archive_index_cold() {
    exercise("index", false).await;
}
