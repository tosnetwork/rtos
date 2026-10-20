// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Startup checks of the persisted GC floor after an unclean stop: they run
//! whether or not the database is repaired, and before any repair.
use super::*;
use crate::collator_test_bundle::create_engine_allocated;
#[cfg(feature = "telemetry")]
use crate::collator_test_bundle::create_engine_telemetry;
use consensus_common::validator_cleanup::{encode_checkpoint, GC_FLOOR_KEY};
use std::sync::atomic::AtomicU8;

async fn open_db(dir: &std::path::Path) -> Result<InternalDb> {
    InternalDb::with_update(
        InternalDbConfig {
            db_directory: dir.to_str().ok_or_else(|| error!("non UTF-8 path"))?.to_owned(),
            ..Default::default()
        },
        false,
        false,
        false,
        None,
        &|| Ok(()),
        None,
        Arc::new(AtomicU8::new(0)),
        None,
        #[cfg(feature = "telemetry")]
        create_engine_telemetry(),
        create_engine_allocated(),
    )
    .await
}

fn floor_id() -> BlockIdExt {
    BlockIdExt::with_params(
        rtos_block::ShardIdent::masterchain(),
        42,
        UInt256::from([1; 32]),
        UInt256::from([2; 32]),
    )
}

fn persist_floor(db: &InternalDb, value: Vec<u8>) -> Result<()> {
    db.write_validator_state_batch_sync(&[(GC_FLOOR_KEY.to_owned(), value)], &[])
}

/// After an unclean stop without repair, a floor whose handle or state is
/// gone stops the node instead of starting it on a database that may "work
/// incorrectly"; without a floor, or after a clean stop, it starts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unrepaired_unclean_start_refuses_a_floor_without_state() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("node_db");
    let db = open_db(&root).await?;
    let running = root.join("ton_node.running");

    std::fs::write(&running, b"")?;
    restore::check_db(&db, 0, false, false, &|| Ok(()), None).await?;
    assert!(running.exists(), "the run is marked as running again");

    persist_floor(&db, encode_checkpoint(&floor_id()))?;
    std::fs::write(&running, b"")?;
    let error = restore::check_db(&db, 0, false, false, &|| Ok(()), None).await.unwrap_err();
    assert!(format!("{error:#}").contains("has no block handle"), "{error:#}");

    db.create_test_block_handle(&floor_id())?;
    std::fs::write(&running, b"")?;
    let error = restore::check_db(&db, 0, false, false, &|| Ok(()), None).await.unwrap_err();
    assert!(format!("{error:#}").contains("has no saved state"), "{error:#}");
    db.stop_states_db().await?;
    Ok(())
}

/// The checks run before the repair pass: a malformed floor refuses the
/// start before the restore beacon is set, so the repair never runs over it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn repair_does_not_run_over_a_malformed_floor() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("node_db");
    let db = open_db(&root).await?;
    persist_floor(&db, vec![0xff; 7])?;
    std::fs::write(root.join("ton_node.running"), b"")?;
    let error = restore::check_db(&db, 0, true, false, &|| Ok(()), None).await.unwrap_err();
    assert!(format!("{error:#}").contains("malformed"), "{error:#}");
    assert!(!root.join("ton_node.restoring").exists(), "repair started over a refused floor");
    db.stop_states_db().await?;
    Ok(())
}

/// An interrupted repair left the database in an unknown state: without
/// repair enabled the node does not start on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupted_repair_is_not_skipped() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("node_db");
    let db = open_db(&root).await?;
    std::fs::write(root.join("ton_node.restoring"), b"")?;
    let error = restore::check_db(&db, 0, false, false, &|| Ok(()), None).await.unwrap_err();
    assert!(format!("{error:#}").contains("interrupted database restore"), "{error:#}");
    db.stop_states_db().await?;
    Ok(())
}
