// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Actual sliced repack: retained offsets and all public lookup consumers.
use super::metadata_eio_tests as base;
use super::*;
use crate::{db::rocksdb::AccessType, tests::late_index_eio_support as late};

async fn observations(slice: &ArchiveSlice, handle: &BlockHandle, phase: &str) -> [bool; 4] {
    let expected = Some((handle.id().clone(), base::payload(handle)));
    let prefix = AccountIdPrefixFull { workchain_id: -1, prefix: 0 };
    let file = slice
        .get_file(handle, &PackageEntryId::Block(handle.id()))
        .await
        .map(|entry| entry.map(|entry| (entry.filename().to_string(), entry.data().to_vec())));
    let seq = slice.lookup_block_by_seqno(&prefix, handle.id().seq_no()).await;
    let lt = slice.lookup_block_by_lt(&prefix, handle.end_lt()).await;
    let mut time_rows = Vec::new();
    let time = slice
        .lookup_blocks_by_utime(
            &prefix,
            handle.gen_utime(),
            Box::new(|id, bytes| {
                time_rows.push((id, bytes));
                Ok(true)
            }),
        )
        .await;
    eprintln!("REPACK READ phase={phase} file={file:?} seq={seq:?} lt={lt:?} time={time:?} rows={time_rows:?}");
    [
        file.as_ref().ok()
            == Some(&Some((PackageEntryId::Block(handle.id()).filename(), base::payload(handle)))),
        seq.as_ref().ok() == Some(&expected),
        lt.as_ref().ok() == Some(&expected),
        time.is_ok() && time_rows == vec![expected.unwrap()],
    ]
}

async fn close(
    slice: ArchiveSlice,
    db: Arc<RocksDb>,
    handles_db: Arc<RocksDb>,
    handles: Vec<Arc<BlockHandle>>,
) {
    let info = base::package(&slice, &handles[0]).await;
    drop(slice);
    drop(handles);
    tokio::time::timeout(late::TIMEOUT, async {
        while Arc::strong_count(&info) != 1 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("repack package owners remain; cold forbidden");
    tokio::time::timeout(late::TIMEOUT, info.package().close_for_sst_test())
        .await
        .expect("repack native close timed out; cold forbidden")
        .expect("repack native close failed; cold forbidden");
    drop(info);
    late::close_db(db).await;
    late::close_db(handles_db).await;
    eprintln!("REPACK ALL_OWNERS_CLOSED");
}

async fn exercise(shifted: bool, proof: bool, reader: usize) {
    let path = tempfile::tempdir().unwrap();
    eprintln!("REPACK ROOT {}", path.path().display());
    let (db, handles_db, handles) = base::native(path.path(), false).await;
    let mut slice = base::open(&db, path.path(), false, None).await.unwrap();
    let order = if shifted { [1, 0, 2] } else { [0, 1, 2] };
    for index in order {
        assert_eq!(
            base::produce(&slice, &handles[index]).await.unwrap(),
            base::payload(&handles[index])
        );
    }
    let proof_id = PackageEntryId::Proof(handles[2].id());
    if proof {
        assert_eq!(
            slice
                .add_file(&handles[2], &proof_id, b"actual cut proof fixture".to_vec())
                .await
                .unwrap(),
            b"actual cut proof fixture"
        );
    }
    db.sync_wal().unwrap();
    handles_db.sync_wal().unwrap();
    base::reads(&slice, &handles).await;
    let pack = {
        let info = base::package(&slice, &handles[0]).await;
        info.package().path().to_path_buf()
    };
    let before = base::snapshot(&db, false, &pack);
    let old_offset =
        slice.offsets_db.get_value(&(&PackageEntryId::Block(handles[0].id())).into()).unwrap();
    assert_eq!(old_offset > 0, shifted);
    eprintln!(
        "REPACK BEFORE pack={} old_offset={old_offset} shifted={shifted} proof={proof}",
        pack.display()
    );
    slice.trunc(handles[2].id(), &|id| id.seq_no() >= 11).await.unwrap();
    db.sync_wal().unwrap();
    assert!(!PathBuf::from(format!("{}.new", pack.display())).exists());
    if proof {
        assert_ne!(base::snapshot(&db, false, &pack), before);
        assert_eq!(
            slice.offsets_db.get_value(&(&PackageEntryId::Block(handles[0].id())).into()).unwrap(),
            0
        );
        for id in [
            PackageEntryId::Block(handles[1].id()),
            PackageEntryId::Block(handles[2].id()),
            proof_id,
        ] {
            assert!(!slice.offsets_db.contains(&(&id).into()).unwrap());
        }
    } else {
        assert_eq!(base::snapshot(&db, false, &pack), before, "missing Proof must be a no-op");
    }
    let live = observations(&slice, &handles[0], "live").await;
    let retained = handles[0].clone();
    close(slice, db, handles_db, handles).await;

    let db = RocksDb::new(path.path(), "archive_provider", None, AccessType::ReadWrite).unwrap();
    let handles_db = RocksDb::new(path.path(), "handle_db", None, AccessType::ReadWrite).unwrap();
    let slice = base::open(&db, path.path(), false, None).await.unwrap();
    let cold = observations(&slice, &retained, "cold").await;
    close(slice, db, handles_db, vec![retained]).await;
    eprintln!("REPACK OUTCOME reader={reader} live={live:?} cold={cold:?}");
    assert!(live[0] && cold[0], "retained get_file changed after successful repack");
    if reader == 0 {
        assert!(
            live.into_iter().all(|ok| ok) && cold.into_iter().all(|ok| ok),
            "control retained readers differ"
        );
    } else {
        assert!(
            live[reader] && cold[reader],
            "retained lookup reader={reader} changed after successful repack"
        );
    }
}

#[tokio::test]
async fn shifted_retained_seq() {
    exercise(true, true, 1).await;
}
#[tokio::test]
async fn shifted_retained_lt() {
    exercise(true, true, 2).await;
}
#[tokio::test]
async fn shifted_retained_time() {
    exercise(true, true, 3).await;
}
#[tokio::test]
async fn missing_proof_control() {
    exercise(true, false, 0).await;
}
#[tokio::test]
async fn ordered_layout_control() {
    exercise(false, true, 0).await;
}
