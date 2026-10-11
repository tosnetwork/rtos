/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::{
    block_handle_db::FLAG_KEY_BLOCK,
    db::rocksdb::{destroy_rocks_db, AccessType, RocksDb},
    tests::utils::create_block_handle_storage,
    types::BlockMeta,
};
use rtos_block::{BlockIdExt, ShardIdent, UInt256};

const DB_PATH: &str = "../../target/test";

#[allow(clippy::bool_assert_comparison)]
#[tokio::test]
async fn test_block_handle_specific_flags() {
    const DB_NAME: &str = "test_block_handle_specific_flags";

    let db = RocksDb::new(DB_PATH, DB_NAME, None, AccessType::ReadWrite).unwrap();
    let (block_handle_storage, _) = create_block_handle_storage(db);
    let handle = block_handle_storage
        .create_handle(BlockIdExt::default(), BlockMeta::default(), None)
        .unwrap()
        .unwrap();

    //    assert_eq!(handle.flags(), 0);
    //    assert_eq!(handle.fetched(), false);

    assert_eq!(handle.has_data(), false);
    assert_eq!(handle.set_data(), true);
    assert_eq!(handle.has_data(), true);
    assert_eq!(handle.set_data(), false);

    assert_eq!(handle.has_proof(), false);
    assert_eq!(handle.set_proof(), true);
    assert_eq!(handle.has_proof(), true);
    assert_eq!(handle.set_proof(), false);

    assert_eq!(handle.has_proof_link(), false);
    assert_eq!(handle.set_proof_link(), true);
    assert_eq!(handle.has_proof_link(), true);
    assert_eq!(handle.set_proof_link(), false);

    /*
        assert_eq!(handle.processed_in_ext_db(), false);
        assert_eq!(handle.set_processed_in_ext_db(), false);
        assert_eq!(handle.processed_in_ext_db(), true);
    */

    assert_eq!(handle.has_state(), false);
    assert_eq!(handle.set_state(), true);
    assert_eq!(handle.has_state(), true);
    assert_eq!(handle.set_state(), false);

    assert_eq!(handle.has_persistent_state(), false);
    assert_eq!(handle.set_persistent_state(), true);
    assert_eq!(handle.has_persistent_state(), true);
    assert_eq!(handle.set_persistent_state(), false);

    assert_eq!(handle.has_next1(), false);
    assert_eq!(handle.set_next1(), true);
    assert_eq!(handle.has_next1(), true);
    assert_eq!(handle.set_next1(), false);

    assert_eq!(handle.has_next2(), false);
    assert_eq!(handle.set_next2(), true);
    assert_eq!(handle.has_next2(), true);
    assert_eq!(handle.set_next2(), false);

    assert_eq!(handle.has_prev1(), false);
    assert_eq!(handle.set_prev1(), true);
    assert_eq!(handle.has_prev1(), true);
    assert_eq!(handle.set_prev1(), false);

    assert_eq!(handle.has_prev2(), false);
    assert_eq!(handle.set_prev2(), true);
    assert_eq!(handle.has_prev2(), true);
    assert_eq!(handle.set_prev2(), false);

    assert_eq!(handle.is_applied(), false);
    assert_eq!(handle.set_block_applied(), true);
    assert_eq!(handle.is_applied(), true);
    assert_eq!(handle.set_block_applied(), false);

    assert_eq!(handle.is_archived(), false);
    assert_eq!(handle.set_archived(), true);
    assert_eq!(handle.is_archived(), true);
    assert_eq!(handle.set_archived(), false);
}

#[tokio::test]
async fn test_handle_db() {
    const DB_NAME: &str = "test_handle_db";

    let db = RocksDb::new(DB_PATH, DB_NAME, None, AccessType::ReadWrite).unwrap();
    let (block_handle_storage, _) = create_block_handle_storage(db.clone());

    for mc_seq_no in 0..20_u32 {
        let block_id = BlockIdExt::with_params(
            ShardIdent::masterchain(),
            mc_seq_no,
            UInt256::from_le_bytes(&mc_seq_no.to_le_bytes()),
            UInt256::default(),
        );
        let flags = if mc_seq_no % 13 == 0 { FLAG_KEY_BLOCK } else { 0 };
        let meta = BlockMeta::with_data(flags, 0, 0, 0, 0);
        let handle =
            block_handle_storage.create_handle(block_id.clone(), meta, None).unwrap().unwrap();
        handle.set_data();
        //tokio::task::yield_now().await;
        handle.set_archived();
        block_handle_storage.save_handle(&handle, None).unwrap();
        if mc_seq_no % 13 == 0 {
            assert!(handle.is_key_block().unwrap());
        }
        assert!(handle.has_data());
        assert!(handle.is_archived());
    }

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    for mc_seq_no in 0..20 {
        let block_id = BlockIdExt::with_params(
            ShardIdent::masterchain(),
            mc_seq_no,
            UInt256::from_le_bytes(&mc_seq_no.to_le_bytes()),
            UInt256::default(),
        );
        let handle = block_handle_storage.load_handle_by_id(&block_id).unwrap().unwrap();
        if mc_seq_no % 13 == 0 {
            assert!(handle.is_key_block().unwrap());
        }
        assert!(handle.has_data());
        assert!(handle.is_archived());
    }

    drop(block_handle_storage);
    drop(db);
    destroy_rocks_db(DB_PATH, DB_NAME).await.unwrap();
}

struct DurabilityPause {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
#[async_trait::async_trait]
impl crate::block_handle_db::Callback for DurabilityPause {
    async fn invoke(&self, _job: crate::block_handle_db::StoreJob, ok: bool) {
        assert!(ok);
        self.entered.notify_one();
        self.release.notified().await;
    }
}

#[tokio::test]
async fn publication_durability_handle_barrier_waits_for_queued_work() {
    use std::sync::Arc;
    let path = std::env::temp_dir().join(format!("rtos-handle-barrier-{}", std::process::id()));
    let db = RocksDb::new(&path, "db", None, AccessType::ReadWrite).unwrap();
    let (storage, table) = create_block_handle_storage(db.clone());
    let storage = Arc::new(storage);
    let handle =
        storage.create_handle(BlockIdExt::default(), BlockMeta::default(), None).unwrap().unwrap();
    let paused =
        Arc::new(DurabilityPause { entered: Default::default(), release: Default::default() });
    storage.save_handle(&handle, Some(paused.clone())).unwrap();
    paused.entered.notified().await;
    handle.set_data();
    storage.save_handle(&handle, None).unwrap();
    let copy = storage.clone();
    let mut barrier = tokio::spawn(async move { copy.sync_pending().await });
    assert!(tokio::time::timeout(std::time::Duration::from_millis(20), &mut barrier)
        .await
        .is_err());
    paused.release.notify_one();
    barrier.await.unwrap().unwrap();
    assert!(table.len().unwrap() > 0);
    drop(table);
    drop(handle);
    drop(storage);
    drop(db);
    destroy_rocks_db(path.to_str().expect("UTF-8 temporary test path"), "db").await.unwrap();
    std::fs::remove_dir_all(path).unwrap();
}

#[tokio::test]
async fn publication_durability_handle_write_failure_is_sticky() {
    let path = std::env::temp_dir().join(format!("rtos-handle-failure-{}", std::process::id()));
    let db = RocksDb::new(&path, "db", None, AccessType::ReadWrite).unwrap();
    let (storage, table) = create_block_handle_storage(db.clone());
    let handle =
        storage.create_handle(BlockIdExt::default(), BlockMeta::default(), None).unwrap().unwrap();
    storage.sync_pending().await.unwrap();
    db.drop_table("block_handles").unwrap();
    storage.save_handle(&handle, None).unwrap(); // actual queue admission succeeds
    assert!(storage.sync_pending().await.is_err()); // actual physical write fails
    assert!(storage.sync_pending().await.is_err());
    drop(table);
    drop(handle);
    drop(storage);
    drop(db);
    destroy_rocks_db(path.to_str().expect("UTF-8 temporary test path"), "db").await.unwrap();
    std::fs::remove_dir_all(path).unwrap();
}
