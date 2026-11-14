// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Actual sliced repack: retained offsets and all public lookup consumers.
use super::{metadata_eio_tests as base, *};
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
    slice
        .trunc(Arc::new(TruncationSelection::new(handles[2].id().clone(), Vec::new()).unwrap()))
        .await
        .unwrap();
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
    db.bind_archive_domain(crate::archives::context::ArchiveDomain::new()).unwrap();
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

#[tokio::test]
async fn multiple_retained_shifts_with_interleaved_proofs() {
    use crate::{tests::utils::create_block_handle_storage, types::BlockMeta};
    use rtos_block::UInt256;
    let path = tempfile::tempdir().unwrap();
    let (db, handles_db, mut handles) = base::native(path.path(), false).await;
    let (storage, table) = create_block_handle_storage(handles_db.clone());
    for seq in [8u32, 9] {
        let id = BlockIdExt::with_params(
            ShardIdent::masterchain(),
            seq,
            UInt256::from([seq as u8; 32]),
            UInt256::from([seq as u8 + 3; 32]),
        );
        let handle = storage
            .create_handle(id, BlockMeta::with_data(0, seq, u64::from(seq), 0, 0), None)
            .unwrap()
            .unwrap();
        storage.save_handle(&handle, None).unwrap();
        handles.push(handle);
    }
    tokio::time::timeout(late::TIMEOUT, storage.sync_pending()).await.unwrap().unwrap();
    drop(storage);
    drop(table);
    let mut slice = base::open(&db, path.path(), false, None).await.unwrap();
    for (index, block) in
        [(1, true), (0, false), (0, true), (2, false), (3, true), (2, true), (4, false), (4, true)]
    {
        let handle = &handles[index];
        let id = if block {
            PackageEntryId::Block(handle.id())
        } else {
            PackageEntryId::Proof(handle.id())
        };
        let data = if block {
            base::payload(handle)
        } else {
            format!("proof {}", handle.id().seq_no()).into_bytes()
        };
        assert_eq!(slice.add_file(handle, &id, data.clone()).await.unwrap(), data);
    }
    base::reads(&slice, &handles).await;
    let mut offsets = Vec::new();
    for index in [0, 3, 4] {
        offsets.push(
            slice
                .offsets_db
                .get_value(&(&PackageEntryId::Block(handles[index].id())).into())
                .unwrap(),
        );
    }
    slice
        .trunc(Arc::new(TruncationSelection::new(handles[2].id().clone(), Vec::new()).unwrap()))
        .await
        .unwrap();
    let mut shifts = Vec::new();
    let mut live = Vec::new();
    for (position, index) in [0, 3, 4].into_iter().enumerate() {
        let offset = slice
            .offsets_db
            .get_value(&(&PackageEntryId::Block(handles[index].id())).into())
            .unwrap();
        assert!(offset > 0, "retained Proof precedes each retained Block");
        shifts.push(offsets[position].checked_sub(offset).unwrap());
        live.push(observations(&slice, &handles[index], "multi-live").await);
    }
    assert!(shifts[0] > 0 && shifts[0] < shifts[1] && shifts[1] < shifts[2]);
    let prefix = AccountIdPrefixFull { workchain_id: -1, prefix: 0 };
    let deleted_live = [
        slice.lookup_block_by_seqno(&prefix, 11).await.unwrap().is_none(),
        slice.lookup_block_by_seqno(&prefix, 12).await.unwrap().is_none(),
    ];
    let retained = vec![handles[0].clone(), handles[3].clone(), handles[4].clone()];
    close(slice, db, handles_db, handles).await;
    let db = RocksDb::new(path.path(), "archive_provider", None, AccessType::ReadWrite).unwrap();
    db.bind_archive_domain(crate::archives::context::ArchiveDomain::new()).unwrap();
    let handles_db = RocksDb::new(path.path(), "handle_db", None, AccessType::ReadWrite).unwrap();
    let slice = base::open(&db, path.path(), false, None).await.unwrap();
    let mut cold = Vec::new();
    for handle in &retained {
        cold.push(observations(&slice, handle, "multi-cold").await);
    }
    let deleted_cold = [
        slice.lookup_block_by_seqno(&prefix, 11).await.unwrap().is_none(),
        slice.lookup_block_by_seqno(&prefix, 12).await.unwrap().is_none(),
    ];
    close(slice, db, handles_db, retained).await;
    assert!(live.into_iter().chain(cold).flatten().all(|ok| ok));
    assert!(deleted_live.into_iter().chain(deleted_cold).all(|absent| absent));
}

#[tokio::test]
async fn repack_index_isolates_package_and_shard_aliases() {
    let path = tempfile::tempdir().unwrap();
    let db = RocksDb::new(path.path(), "index", None, AccessType::ReadWrite).unwrap();
    let index = BlockIndexDb::with_db(db.clone(), base::cf("block_index", false), true).unwrap();
    let master = ShardIdent::masterchain();
    let shard = ShardIdent::with_tagged_prefix(0, 0x8000000000000000).unwrap();
    for (seq, offset) in [(9u32, 500u32), (10, 196), (12, 0), (110, 196)] {
        index.put_raw(&master, seq, seq.into(), seq, seq, offset).unwrap();
    }
    index.put_raw(&shard, 10, 10, 10, 10, 196).unwrap();
    let offsets = RepackOffsets::from([
        ((master.clone(), 500), Some(170)),
        ((master.clone(), 196), Some(0)),
        ((master.clone(), 0), None),
    ]);
    let batch = index
        .prepare_repack_offsets(
            &offsets,
            |shard, mc_ref| Ok(shard.is_masterchain() && mc_ref < 100),
        )
        .unwrap();
    index.commit_repack_offsets(batch).unwrap();
    for (shard, seq, expected) in
        [(&master, 9u32, 170u32), (&master, 10, 0), (&master, 110, 196), (&shard, 10, 196)]
    {
        let prefix = AccountIdPrefixFull { workchain_id: shard.workchain_id(), prefix: 0 };
        assert_eq!(index.lookup_by_seqno(&prefix, seq).unwrap().unwrap().offset, expected);
        assert_eq!(index.lookup_by_lt(&prefix, seq.into()).unwrap().unwrap().offset, expected);
        let mut found = Vec::new();
        index
            .lookup_by_utime(&prefix, seq, &mut |entry| {
                found.push((entry.mc_ref, entry.offset));
                Ok(true)
            })
            .unwrap();
        assert_eq!(found, vec![(seq, expected)]);
    }
    let rows = base::rows(&db, &base::cf("block_index", false));
    use crate::archives::block_index_db::BlocksIndexKey;
    for key in [
        BlocksIndexKey::key_with_seqno(&master, 12),
        BlocksIndexKey::key_with_lt(&master, 12),
        BlocksIndexKey::key_with_utime(&master, 12, 12),
    ] {
        assert!(!rows.contains_key(key.as_bytes()));
    }
    drop(index);
    late::close_db(db).await;
}

#[tokio::test]
async fn repack_index_rejects_unmapped_and_overflow_without_mutation() {
    let path = tempfile::tempdir().unwrap();
    let db = RocksDb::new(path.path(), "index", None, AccessType::ReadWrite).unwrap();
    let index = BlockIndexDb::with_db(db.clone(), base::cf("block_index", false), true).unwrap();
    let shard = ShardIdent::masterchain();
    index.put_raw(&shard, 10, 10, 10, 10, 196).unwrap();
    index.put_raw(&shard, 11, 11, 11, 11, 400).unwrap();
    let before = base::rows(&db, &base::cf("block_index", false));
    let missing = RepackOffsets::from([((shard.clone(), 196), Some(0))]);
    let error = index.prepare_repack_offsets(&missing, |_, _| Ok(true)).err().unwrap();
    assert!(error.to_string().contains("absent from source package"));
    assert_eq!(base::rows(&db, &base::cf("block_index", false)), before);
    for (old, new) in [(u64::from(u32::MAX) + 1, Some(0)), (196, Some(u64::from(u32::MAX) + 1))] {
        let offsets = RepackOffsets::from([((shard.clone(), old), new)]);
        assert!(index.prepare_repack_offsets(&offsets, |_, _| Ok(true)).is_err());
        assert_eq!(base::rows(&db, &base::cf("block_index", false)), before);
    }
    drop(index);
    late::close_db(db).await;
}
