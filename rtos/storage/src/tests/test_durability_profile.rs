// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Synthetic replay of one applied block's handle-writer traffic, for
//! counting synchronizations (run under `strace -c`) and timing them.
//!
//! Per block it issues the ordinary apply path's handle and pointer writes in
//! the bursts they occur in: handle creation, data flag, proof flag, state
//! flag, saved-state flag, prev1 plus next1 on the parent, masterchain
//! reference, archived flag followed by the archive barrier, applied flag,
//! then the last-applied and shard-client pointers. Between bursts it lets the
//! writer drain, as the IO between those steps does on a node. It uses only
//! APIs that existed before the durability change, so the same file measures
//! the previous writer.
use crate::{
    db::rocksdb::{AccessType, RocksDb},
    tests::utils::create_block_handle_storage,
    types::BlockMeta,
};
use rtos_block::{BlockIdExt, ShardIdent, UInt256};
use std::time::{Duration, Instant};

fn id(index: u32) -> BlockIdExt {
    let mut hash = [0u8; 32];
    hash[..4].copy_from_slice(&index.to_be_bytes());
    hash[31] = 0xa5;
    BlockIdExt::with_params(
        ShardIdent::masterchain(),
        index,
        UInt256::from(hash),
        UInt256::default(),
    )
}

async fn drain() {
    tokio::time::sleep(Duration::from_millis(1)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement; run explicitly with RTOS_PROFILE_BLOCKS and strace"]
async fn durability_profile_block_replay() {
    let blocks: u32 =
        std::env::var("RTOS_PROFILE_BLOCKS").ok().and_then(|v| v.parse().ok()).unwrap_or(100);
    let dir =
        std::env::var_os("RTOS_PROFILE_DIR").map(std::path::PathBuf::from).unwrap_or_else(|| {
            std::env::temp_dir().join(format!("rtos-profile-{}", std::process::id()))
        });
    let db = RocksDb::new(&dir, "db", None, AccessType::ReadWrite).unwrap();
    let (storage, _) = create_block_handle_storage(db.clone());
    storage.sync_pending().await.unwrap();
    let start = Instant::now();
    let mut barrier_time = Duration::ZERO;
    let mut parent = storage.create_handle(id(0), BlockMeta::default(), None).unwrap().unwrap();
    for index in 1..=blocks {
        let handle = storage.create_handle(id(index), BlockMeta::default(), None).unwrap().unwrap();
        drain().await;
        handle.set_data();
        storage.save_handle(&handle, None).unwrap();
        drain().await;
        handle.set_proof();
        storage.save_handle(&handle, None).unwrap();
        drain().await;
        handle.set_state();
        storage.save_handle(&handle, None).unwrap();
        drain().await;
        handle.set_state_saved();
        storage.save_handle(&handle, None).unwrap();
        drain().await;
        handle.set_prev1();
        storage.save_handle(&handle, None).unwrap();
        parent.set_next1();
        storage.save_handle(&parent, None).unwrap();
        drain().await;
        handle.set_masterchain_ref_seq_no(index).unwrap();
        storage.save_handle(&handle, None).unwrap();
        drain().await;
        handle.set_archived();
        storage.save_handle(&handle, None).unwrap();
        let barrier = Instant::now();
        storage.sync_pending().await.unwrap();
        barrier_time += barrier.elapsed();
        handle.set_block_applied();
        storage.save_handle(&handle, None).unwrap();
        storage.save_full_node_state("LastMcBlockId".to_owned(), handle.id()).unwrap();
        storage.save_full_node_state("ShardsClientMcBlockId".to_owned(), handle.id()).unwrap();
        drain().await;
        parent = handle;
    }
    storage.sync_pending().await.unwrap();
    let elapsed = start.elapsed();
    eprintln!(
        "DURABILITY_PROFILE blocks={blocks} total_ms={} per_block_ms={:.3} archive_barrier_ms_per_block={:.3} wal_synced={:?}",
        elapsed.as_millis(),
        elapsed.as_secs_f64() * 1000.0 / f64::from(blocks.max(1)),
        barrier_time.as_secs_f64() * 1000.0 / f64::from(blocks.max(1)),
        db.db().property_value("rocksdb.options-statistics").ok().flatten().and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("rocksdb.wal.synced COUNT : ").map(str::to_owned))
        }),
    );
    drop(storage);
    drop(db);
    let _ = std::fs::remove_dir_all(&dir);
}
