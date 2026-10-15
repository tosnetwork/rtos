// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Separate native-fault producer and cold-reader processes; see memo harness.
use super::metadata_eio_tests as base;
use super::*;
use crate::{
    db::rocksdb::AccessType,
    tests::{late_index_eio_support as late, utils::create_block_handle_storage},
    types::BlockMeta,
};
use rtos_block::UInt256;
use serde_json::json;

fn root() -> PathBuf {
    PathBuf::from(std::env::var_os("RTOS_RENAME_ROOT").expect("native harness required"))
}
fn id(seq: u32) -> BlockIdExt {
    BlockIdExt::with_params(
        ShardIdent::masterchain(),
        seq,
        UInt256::from([seq as u8; 32]),
        UInt256::from([seq as u8 + 3; 32]),
    )
}
fn save(root: &Path, name: &str, value: serde_json::Value) {
    std::fs::write(root.join(name), serde_json::to_vec_pretty(&value).unwrap()).unwrap();
}
fn snapshot(root: &Path, phase: &str, db: &Arc<RocksDb>, pack: &Path) {
    let rows: Vec<_> = ["entry_meta", "status", "offsets", "block_index"]
        .into_iter()
        .map(|kind| (kind, base::rows(db, &base::cf(kind, false)).into_iter().collect::<Vec<_>>()))
        .collect();
    save(root, &format!("{phase}-rows.json"), json!(rows));
    for (label, path) in
        [("old", pack.to_path_buf()), ("new", PathBuf::from(format!("{}.new", pack.display())))]
    {
        match std::fs::read(&path) {
            Ok(bytes) => std::fs::write(root.join(format!("{phase}-{label}.bin")), bytes).unwrap(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::write(root.join(format!("{phase}-{label}.absent")), b"").unwrap();
            }
            Err(error) => panic!("snapshot failed: {error}"),
        }
    }
}
async fn read(slice: &ArchiveSlice, handle: &BlockHandle) -> [bool; 4] {
    let expected = Some((handle.id().clone(), base::payload(handle)));
    let prefix = AccountIdPrefixFull { workchain_id: -1, prefix: 0 };
    let file = slice
        .get_file(handle, &PackageEntryId::Block(handle.id()))
        .await
        .map(|entry| entry.map(|entry| (entry.filename().to_string(), entry.data().to_vec())));
    let seq = slice.lookup_block_by_seqno(&prefix, handle.id().seq_no()).await;
    let lt = slice.lookup_block_by_lt(&prefix, handle.end_lt()).await;
    let mut rows = Vec::new();
    let time = slice
        .lookup_blocks_by_utime(
            &prefix,
            handle.gen_utime(),
            Box::new(|id, bytes| {
                rows.push((id, bytes));
                Ok(true)
            }),
        )
        .await;
    eprintln!(
        "RENAME READ id={} file={file:?} seq={seq:?} lt={lt:?} time={time:?} rows={rows:?}",
        handle.id()
    );
    [
        file.as_ref().ok()
            == Some(&Some((PackageEntryId::Block(handle.id()).filename(), base::payload(handle)))),
        seq.as_ref().ok() == Some(&expected),
        lt.as_ref().ok() == Some(&expected),
        time.is_ok() && rows == vec![expected.unwrap()],
    ]
}

#[tokio::test]
#[ignore = "requires isolated native rename harness"]
async fn producer() {
    let root = root();
    let multiple = std::env::var("RTOS_RENAME_LAYOUT").as_deref() == Ok("multiple");
    let mode = std::env::var("RTOS_RENAME_MODE").unwrap();
    let (db, handles_db, mut handles) = base::native(&root, false).await;
    if multiple {
        let (storage, table) = create_block_handle_storage(handles_db.clone());
        let handle = storage
            .create_handle(id(9), BlockMeta::with_data(0, 9, 9, 0, 0), None)
            .unwrap()
            .unwrap();
        storage.save_handle(&handle, None).unwrap();
        storage.sync_pending().await.unwrap();
        handles.push(handle);
        drop(storage);
        drop(table);
    }
    let mut slice = base::open(&db, &root, false, None).await.unwrap();
    for index in [1, 0, 2] {
        assert_eq!(
            base::produce(&slice, &handles[index]).await.unwrap(),
            base::payload(&handles[index])
        );
        if multiple && index == 0 {
            slice
                .add_file(
                    &handles[0],
                    &PackageEntryId::Proof(handles[0].id()),
                    b"retained proof10".to_vec(),
                )
                .await
                .unwrap();
        }
    }
    if multiple {
        assert_eq!(base::produce(&slice, &handles[3]).await.unwrap(), base::payload(&handles[3]));
    }
    slice
        .add_file(
            &handles[2],
            &PackageEntryId::Proof(handles[2].id()),
            b"actual cut proof11".to_vec(),
        )
        .await
        .unwrap();
    db.sync_wal().unwrap();
    handles_db.sync_wal().unwrap();
    let retained: Vec<_> = handles.iter().filter(|h| h.id().seq_no() < 11).collect();
    for handle in &retained {
        assert!(read(&slice, handle).await.into_iter().all(|ok| ok));
    }
    let pack = {
        let info = base::package(&slice, &handles[0]).await;
        info.package().path().to_path_buf()
    };
    std::fs::write(root.join("package-path"), pack.as_os_str().as_encoded_bytes()).unwrap();
    snapshot(&root, "seed", &db, &pack);
    let target = if mode == "wrong-path" {
        format!("{}.wrong", pack.display())
    } else {
        pack.display().to_string()
    };
    std::fs::write(root.join("rename-paths"), format!("{}.new\n{target}\n", pack.display()))
        .unwrap();
    if mode != "missing-arm" {
        std::fs::write(root.join("armed"), b"seed-synced").unwrap();
    }
    eprintln!("RENAME SEEDS_SYNCED pack={}", pack.display());
    let result = slice.trunc(handles[2].id(), &|id| id.seq_no() >= 11).await;
    let api_ok = result.is_ok();
    let api_error = result.err().map(|error| error.to_string());
    let indexed = slice.package_index.get(&0).is_some();
    snapshot(&root, "after-trunc", &db, &pack);
    let mut live = Vec::new();
    for handle in &retained {
        live.push((handle.id().seq_no(), read(&slice, handle).await));
    }
    save(
        &root,
        "producer.json",
        json!({"api_ok":api_ok,"api_error":api_error,
        "package_index_present":indexed,"live":live,"layout":if multiple {"multiple"} else {"single"}}),
    );
    drop(retained);
    drop(slice);
    drop(handles);
    late::close_db(db).await;
    late::close_db(handles_db).await;
    eprintln!("RENAME PRODUCER_DB_JOINED; package closure verified by parent process/trace");
    assert_eq!(api_ok, mode != "fault", "actual rename API result differs");
    if mode == "fault" {
        late::check_eio(api_error.as_deref().unwrap());
    } else {
        assert!(
            live.iter().all(|(_, row)| row.iter().all(|ok| *ok)),
            "control live retained data differs"
        );
    }
}

#[tokio::test]
#[ignore = "requires producer terminal receipt before cold child"]
async fn cold() {
    let root = root();
    let phase = std::env::var("RTOS_RENAME_PHASE").unwrap();
    let multiple = std::env::var("RTOS_RENAME_LAYOUT").as_deref() == Ok("multiple");
    let pack = PathBuf::from(std::fs::read_to_string(root.join("package-path")).unwrap());
    let db = RocksDb::new(&root, "archive_provider", None, AccessType::ReadWrite).unwrap();
    db.bind_archive_domain(crate::archives::context::ArchiveDomain::new()).unwrap();
    let handles_db = RocksDb::new(&root, "handle_db", None, AccessType::ReadWrite).unwrap();
    let (storage, table) = create_block_handle_storage(handles_db.clone());
    let mut handles = Vec::new();
    for seq in if multiple { vec![10, 9] } else { vec![10] } {
        let handle = storage.load_handle_by_id(&id(seq)).unwrap().expect("seeded handle missing");
        assert_eq!(handle.id(), &id(seq));
        handles.push(handle);
    }
    drop(storage);
    drop(table);
    snapshot(&root, &format!("{phase}-before"), &db, &pack);
    let opened = base::open(&db, &root, false, None).await;
    let mut reads = Vec::new();
    let open_error = match opened {
        Ok(slice) => {
            snapshot(&root, &format!("{phase}-opened"), &db, &pack);
            for handle in &handles {
                reads.push((handle.id().seq_no(), read(&slice, handle).await));
            }
            let info = base::package(&slice, &handles[0]).await;
            drop(slice);
            tokio::time::timeout(late::TIMEOUT, async {
                while Arc::strong_count(&info) != 1 {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("cold package owners remain");
            info.package().close_for_sst_test().await.unwrap();
            drop(info);
            None
        }
        Err(error) => Some(error.to_string()),
    };
    snapshot(&root, &format!("{phase}-after"), &db, &pack);
    save(&root, &format!("{phase}.json"), json!({"open_error":open_error,"reads":reads}));
    drop(handles);
    late::close_db(db).await;
    late::close_db(handles_db).await;
    eprintln!("RENAME COLD_ALL_OWNERS_CLOSED phase={phase}");
    assert!(open_error.is_none(), "cold constructor failed (not retained-reader red)");
    assert_eq!(reads.len(), if multiple { 2 } else { 1 });
    assert!(
        reads.iter().all(|(_, row)| row.iter().all(|ok| *ok)),
        "RENAME_RETAINED_IDENTITY_PAYLOAD_CHANGED"
    );
}
