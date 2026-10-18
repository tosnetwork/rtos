// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use futures::FutureExt;

async fn exercise_checked_cursor_gap(force: bool, damaged_head: bool) -> Result<()> {
    for retained in [2, 3, 0] {
        let dir = tempfile::tempdir()?;
        let root = dir.path();
        let fixture = Fixture::node_recovery();
        let archives = root.join("archives");
        fixture.prepare(root, &archives).await?;
        let physical = run_import(fixture.config(root, archives)).await?;
        tokio::time::timeout(Duration::from_secs(60), wait_for_db_release(physical)).await?;
        let db = open_db(root).await?;
        fixture.assert_imported(&db, 4).await?;
        let _lease = truncation_recovery::prepare(&db, &fixture, retained, false).await?;
        let recorded_head = if damaged_head {
            rtos_block::BlockIdExt::with_params(
                rtos_block::ShardIdent::masterchain(),
                5,
                rtos_block::UInt256::from([0x95; 32]),
                rtos_block::UInt256::from([0x96; 32]),
            )
        } else {
            fixture.id(4, false)
        };
        db.save_full_node_state(LAST_APPLIED_MC_BLOCK, &recorded_head)?;
        let before = package_inventory(root)?;
        fs::write(root.join("node_db/ton_node.running"), b"")?;
        let checked = std::panic::AssertUnwindSafe(async {
            let result =
                crate::internal_db::restore::check_db(&db, 0, true, force, &|| Ok(()), None).await;
            if force || damaged_head {
                let error = result.expect_err("forced truncation must retain the custody veto");
                if retained != 0 {
                    assert!(
                        error
                            .to_string()
                            .contains("Archive truncation conflicts with repair custody"),
                        "{error}"
                    );
                }
                assert!(root.join("node_db/ton_node.restoring").exists());
            } else {
                result.expect(
                    "healthy checked MC and lagging shard cursor must recover independently",
                );
                assert!(!root.join("node_db/ton_node.restoring").exists());
            }
            assert_eq!(
                db.load_full_node_state(LAST_APPLIED_MC_BLOCK)?.as_deref(),
                Some(&recorded_head)
            );
            assert_eq!(
                db.load_full_node_state(SHARD_CLIENT_MC_BLOCK)?.as_deref(),
                Some(&fixture.id(retained, false))
            );
            for key in [PSS_KEEPER_MC_BLOCK, ARCHIVES_GC_BLOCK] {
                assert_eq!(db.load_full_node_state(key)?.as_deref(), Some(&fixture.id(4, false)));
            }
            assert_eq!(package_inventory(root)?, before, "protected archives must remain exact");
            fixture.assert_history(&db, 4).await?;
            Ok::<_, anyhow::Error>(())
        })
        .catch_unwind()
        .await;
        db.stop_states_db().await?;
        checked.unwrap_or_else(|panic| std::panic::resume_unwind(panic))?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_restore_keeps_checked_mc_ahead_of_shard_client() -> Result<()> {
    exercise_checked_cursor_gap(false, false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forced_restore_still_refuses_truncation_of_repair_custody() -> Result<()> {
    exercise_checked_cursor_gap(true, false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn damaged_head_restore_still_refuses_truncation_of_repair_custody() -> Result<()> {
    exercise_checked_cursor_gap(false, true).await
}
