// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Validator-state batches under a full disk (P5-07.12 phase 1, V1/V2).
//! Each batch is atomic: after a failed synced write and a cold reopen,
//! every key of the batch is either all previous or all intended. The
//! callers' contracts (retained ownership, latched pruning) have their own
//! tests; these prove the durable batch itself.
use crate::{
    internal_db::{InternalDb, DESTROYED_VALIDATOR_SESSIONS},
    publication_dependency_leases::disk_full_tests::{enospc_root, Filler},
    test_helper::TestEngine,
    validator::validator_cleanup_gc::{erase_record, persist_retirement},
};
use consensus_common::validator_cleanup::{
    candidate_claim_key, encode_record, make_record, record_key, NamespaceLayout,
};
use rtos_block::{BlockIdExt, Result, ShardIdent, UInt256};
use std::collections::HashSet;

fn record(byte: u8) -> consensus_common::validator_cleanup::PendingValidatorCleanup {
    let checkpoint = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        9,
        UInt256::from([1; 32]),
        UInt256::from([2; 32]),
    );
    make_record(
        &UInt256::from([byte; 32]),
        &NamespaceLayout::V1,
        &ShardIdent::masterchain(),
        5,
        &checkpoint,
    )
    .unwrap()
}

fn read(db: &InternalDb, key: &str) -> Option<Vec<u8>> {
    db.load_validator_state_key_bounded(key, 1 << 20).unwrap()
}

/// Opens a fresh engine DB under the harness root, runs `before`, rotates
/// the validator-state WAL, fills the disk, runs `failing` (which must fail
/// with ENOSPC), frees the disk, cold-reopens and runs `after`.
async fn on_full_disk(
    case: &str,
    before: impl FnOnce(&InternalDb),
    failing: impl FnOnce(&InternalDb) -> Result<()>,
    after: impl FnOnce(&InternalDb),
) -> Result<()> {
    let root = enospc_root().join(case);
    std::fs::create_dir_all(&root)?;
    let engine = TestEngine::new_db_dir(root.to_str().unwrap(), None).await?;
    before(&engine.db);
    engine.db.rotate_validator_state_wal_for_test()?;
    let filler = Filler::fill(&root);
    let error = failing(&engine.db).unwrap_err();
    assert!(format!("{error:#}").contains("No space left on device"), "{error:#}");
    filler.free();
    engine.db.stop_states_db().await.unwrap();
    drop(engine);
    let engine = TestEngine::new_db_dir(root.to_str().unwrap(), None).await?;
    after(&engine.db);
    engine.db.stop_states_db().await.unwrap();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "disk-full harness only"]
async fn disk_full_erase_with_claim_is_all_or_nothing() -> Result<()> {
    let gone = record(7);
    let session = gone.session_id.clone();
    on_full_disk(
        "erase",
        |db| {
            db.write_validator_state_batch_sync(
                &[(record_key(&gone.namespace), encode_record(&gone).unwrap())],
                &[],
            )
            .unwrap()
        },
        |db| erase_record(db, &gone.namespace, Some(&session)),
        |db| {
            let record_present = read(db, &record_key(&gone.namespace)).is_some();
            let claim = read(db, &candidate_claim_key(&session));
            match (record_present, claim) {
                (true, None) => eprintln!("ENOSPC-CASE V1 previous"),
                (false, Some(value)) => {
                    assert_eq!(value, gone.namespace.as_bytes(), "a complete claim");
                    eprintln!("ENOSPC-CASE V1 intended");
                }
                other => panic!("torn erase batch: {other:?}"),
            }
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "disk-full harness only"]
async fn disk_full_fence_with_records_is_all_or_nothing() -> Result<()> {
    let (a, b) = (UInt256::from([1; 32]), UInt256::from([2; 32]));
    let previous = HashSet::from([a.clone()]);
    let intended = HashSet::from([a.clone(), b.clone()]);
    let new_record = record(9);
    on_full_disk(
        "fence",
        |db| persist_retirement(db, &previous, &[]).unwrap(),
        |db| persist_retirement(db, &intended, std::slice::from_ref(&new_record)),
        |db| {
            let fence: HashSet<UInt256> =
                crate::engine_operations::deserialize_destroyed_session_ids(
                    &read(db, DESTROYED_VALIDATOR_SESSIONS).expect("a fence"),
                )
                .unwrap()
                .into_iter()
                .collect();
            let record_present = read(db, &record_key(&new_record.namespace)).is_some();
            if fence == previous {
                assert!(!record_present, "torn: previous fence with the new record");
                eprintln!("ENOSPC-CASE V2 previous");
            } else {
                assert_eq!(fence, intended, "the fence is previous or intended");
                assert!(record_present, "torn: intended fence without its record");
                eprintln!("ENOSPC-CASE V2 intended");
            }
        },
    )
    .await
}
