// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Actual post-construction failures. Successful exclusive DB reopening, not a
//! stopper reference count alone, proves the self-owned state worker released IO.
use super::*;
use crate::{
    config::TonNodeConfig,
    engine::{EngineFlags, Stopper},
};
use storage::traits::Serializable as StorageSerializable;

async fn failed_startup(mode: u8) {
    let Fixture { dir, engine, parent, target, .. } = fixture(true).await;
    let root = PathBuf::from(engine.db_root_dir().unwrap());
    close(engine).await;
    let db = open_cells_for_fault_injection(&root);
    let versions =
        db.clone().table::<String>(storage::db::rocksdb::NODE_STATE_DB_NAME, false).unwrap();
    let key = crate::internal_db::DB_VERSION.to_owned();
    let original = versions.get(&key).unwrap().to_vec();
    if mode == 0 {
        versions
            .put_raw_sync(
                key.as_bytes(),
                &<u32 as StorageSerializable>::serialize(
                    &(crate::internal_db::CURRENT_DB_VERSION + 100),
                ),
            )
            .unwrap();
    }
    drop(versions);
    drop(db);
    // A directory at the actual marker makes File::write deterministically fail
    // even as root. No global fault switch or worker mock is involved.
    let beacon = root.join("ton_node.restoring");
    if mode == 2 {
        std::fs::create_dir(&beacon).unwrap();
    }
    let config = TonNodeConfig::from_file(
        dir.path().to_str().unwrap(),
        "config.json",
        None,
        "config.json",
        None,
    )
    .await
    .unwrap();
    let stopper = Arc::new(Stopper::new());
    let opened = Engine::new(
        config,
        EngineFlags {
            initial_sync_disabled: true,
            force_check_db: mode == 2,
            truncate_db: if mode == 1 { Some(u32::MAX) } else { None },
        },
        stopper.clone(),
    )
    .await;
    let error = match opened {
        Ok(engine) => {
            close(engine).await;
            None
        }
        Err(error) => Some(error),
    };
    let drained = tokio::time::timeout(Duration::from_secs(20), async {
        while Arc::strong_count(&stopper) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    // This fails on the original leaked self-owned worker even when the
    // construction stopper count has already reached one. No sleep/retry hides it.
    let db = open_cells_for_fault_injection(&root);
    let versions =
        db.clone().table::<String>(storage::db::rocksdb::NODE_STATE_DB_NAME, false).unwrap();
    versions.put_raw_sync(key.as_bytes(), &original).unwrap();
    drop(versions);
    drop(db);
    if mode == 2 {
        std::fs::remove_dir(&beacon).unwrap();
    }
    drained.expect("failed startup owner must finish rollback");
    let error = error.expect("controlled real startup failure must not return an Engine");
    match mode {
        0 => assert!(format!("{error:#}").contains("Wrong database version"), "{error:#}"),
        1 => assert!(format!("{error:#}").contains("4294967295"), "{error:#}"),
        2 => assert!(
            error.chain().any(|cause| cause.downcast_ref::<std::io::Error>().is_some()),
            "expected actual restoring marker IO failure: {error:#}"
        ),
        _ => unreachable!(),
    }
    // Exercise complete normal construction on the same DB/network config after
    // restoring only the fault, then cold read both physical state DAGs/artifacts.
    let engine = open_engine(dir.path()).await;
    let checked = std::panic::AssertUnwindSafe(async {
        for id in [parent.id(), target.id()] {
            assert!(engine.db().test_contains_dynamic_state_record(id).unwrap());
            let state = engine.load_state(id).await.unwrap();
            assert!(!write_boc(state.root_cell()).unwrap().is_empty());
            let handle = engine.load_block_handle(id).unwrap().unwrap();
            assert_eq!(engine.load_block(&handle).await.unwrap().id(), id);
            engine.load_block_proof(&handle, false).await.unwrap();
        }
    })
    .catch_unwind()
    .await;
    close(engine).await;
    checked.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_startup_owner_unsupported_version_releases_actual_db() {
    failed_startup(0).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_startup_owner_missing_truncate_block_releases_actual_db() {
    failed_startup(1).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_startup_owner_restoring_marker_error_releases_actual_db() {
    failed_startup(2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn engine_truncation_completes_at_the_floor_and_refuses_below_it() {
    use consensus_common::validator_cleanup::{encode_checkpoint, GC_FLOOR_KEY};
    for floor_above_head in [true, false] {
        let Fixture { dir, engine, parent, target, .. } = fixture(false).await;
        // The floor is persisted and restored (and pinned) by a reopened keeper.
        let floor = if floor_above_head { target.id().clone() } else { parent.id().clone() };
        engine
            .db()
            .write_validator_state_batch_sync(
                &[(GC_FLOOR_KEY.to_owned(), encode_checkpoint(&floor))],
                &[],
            )
            .unwrap();
        close(engine).await;
        let engine = open_engine(dir.path()).await;
        let run = std::panic::AssertUnwindSafe(async {
            assert_eq!(engine.validator_cleanup_floor().map(|(id, _)| id), Some(floor.clone()));
            let floor_key =
                || engine.db().load_validator_state_key_bounded(GC_FLOOR_KEY, 256).unwrap();
            let heads = || {
                (
                    engine.load_last_applied_mc_block_id().unwrap(),
                    engine.load_shard_client_mc_block_id().unwrap(),
                    engine.load_pss_keeper_mc_block_id().unwrap(),
                    engine.load_last_rotation_block_id().unwrap(),
                    engine.load_archives_gc_mc_block_id().unwrap(),
                )
            };
            let (key_before, heads_before) = (floor_key(), heads());
            assert_eq!(heads_before.0.as_deref(), Some(target.id()));
            crate::engine::TRUNCATION_HELD_AFTER_HEAD_REWRITES
                .store(false, std::sync::atomic::Ordering::SeqCst);
            crate::engine::TRUNCATION_LOADED_PREVIOUS_STATE
                .store(false, std::sync::atomic::Ordering::SeqCst);
            let result = engine.truncate_database(target.id().seq_no()).await;
            assert_eq!(floor_key(), key_before, "the floor key is never touched");
            assert_eq!(engine.validator_cleanup_floor().map(|(id, _)| id), Some(floor.clone()));
            if floor_above_head {
                let error = result.unwrap_err().to_string();
                assert!(error.contains("below the cleanup floor"), "{error}");
                assert!(
                    !crate::engine::TRUNCATION_LOADED_PREVIOUS_STATE
                        .load(std::sync::atomic::Ordering::SeqCst),
                    "refused before any state work"
                );
                assert_eq!(heads(), heads_before, "every head key unchanged");
                assert!(engine.load_block_handle(target.id()).unwrap().is_some());
            } else {
                result.unwrap();
                assert_eq!(
                    engine.load_last_applied_mc_block_id().unwrap().as_deref(),
                    Some(parent.id())
                );
                assert!(
                    crate::engine::TRUNCATION_HELD_AFTER_HEAD_REWRITES
                        .load(std::sync::atomic::Ordering::SeqCst),
                    "the guard is held through the head rewrites"
                );
            }
            let keeper = engine.shard_states_keeper();
            assert!(!keeper.truncation_active(), "the guard is released at the end");
            drop(keeper.begin_truncation(floor.seq_no()).unwrap());
        })
        .catch_unwind()
        .await;
        close(engine).await;
        run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    }
}
