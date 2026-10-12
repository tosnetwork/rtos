// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Validator-state writes under a full disk (P5-07.12 phase 1, V1/V2/V6/V7).
//! Each write is one synced batch: after a failed write and a cold reopen,
//! every key of the batch holds exactly its previous bytes or exactly its
//! intended bytes, never a mix. The callers' contracts (retained ownership,
//! latched pruning) have their own tests; these prove the durable batch. In
//! control mode the same write runs with ample space and must succeed.
use crate::{
    internal_db::{InternalDb, DESTROYED_VALIDATOR_SESSIONS},
    publication_dependency_leases::disk_full_tests::{control, enospc_root, Filler},
    test_helper::TestEngine,
    validator::validator_cleanup_gc::{erase_record, persist_retirement, write_journal},
};
use consensus_common::validator_cleanup::{
    candidate_claim_key, encode_record, make_record, record_key, CleanupJournal, JournalPayload,
    NamespaceLayout, PendingValidatorCleanup,
};
use rtos_block::{BlockIdExt, Result, ShardIdent, UInt256};
use std::collections::HashSet;

fn record(byte: u8) -> PendingValidatorCleanup {
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

fn fence_bytes(fence: &HashSet<UInt256>) -> Option<Vec<u8>> {
    (!fence.is_empty()).then(|| crate::engine_operations::serialize_destroyed_session_ids(fence))
}

/// Opens a fresh engine DB under the harness root and runs `before`. In
/// control mode `write` must then succeed with ample space. Otherwise the
/// validator-state WAL is rotated, the disk filled, `write` must fail with
/// ENOSPC, the disk is freed, and `after` checks a cold reopen.
async fn on_full_disk(
    case: &str,
    before: impl FnOnce(&InternalDb),
    write: impl FnOnce(&InternalDb) -> Result<()>,
    after: impl FnOnce(&InternalDb),
) -> Result<()> {
    let root = enospc_root().join(case);
    std::fs::create_dir_all(&root)?;
    let engine = TestEngine::new_db_dir(root.to_str().unwrap(), None).await?;
    before(&engine.db);
    engine.db.rotate_validator_state_wal_for_test()?;
    if control() {
        write(&engine.db)?;
        engine.db.stop_states_db().await.unwrap();
        eprintln!("ENOSPC-CASE {case} control ok");
        return Ok(());
    }
    let filler = Filler::fill(&root);
    let error = write(&engine.db).unwrap_err();
    assert!(format!("{error:#}").contains("No space left on device"), "{error:#}");
    filler.free();
    engine.db.stop_states_db().await.unwrap();
    drop(engine);
    let engine = TestEngine::new_db_dir(root.to_str().unwrap(), None).await?;
    after(&engine.db);
    engine.db.stop_states_db().await.unwrap();
    Ok(())
}

/// The keys' bytes after reopen are exactly all `previous` or all `intended`.
fn all_previous_or_all_intended(
    case: &str,
    db: &InternalDb,
    keys: &[String],
    previous: &[Option<Vec<u8>>],
    intended: &[Option<Vec<u8>>],
) {
    let actual: Vec<Option<Vec<u8>>> = keys.iter().map(|key| read(db, key)).collect();
    if actual == previous {
        eprintln!("ENOSPC-CASE {case} previous");
    } else if actual == intended {
        eprintln!("ENOSPC-CASE {case} intended");
    } else {
        panic!("torn or corrupt batch in {case}: {actual:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "disk-full harness only"]
async fn disk_full_erase_with_claim_is_all_or_nothing() -> Result<()> {
    let gone = record(7);
    let session = gone.session_id.clone();
    let keys = [record_key(&gone.namespace), candidate_claim_key(&session)];
    let previous = [Some(encode_record(&gone).unwrap()), None];
    let intended = [None, Some(gone.namespace.as_bytes().to_vec())];
    on_full_disk(
        "erase",
        |db| {
            db.write_validator_state_batch_sync(
                &[(keys[0].clone(), previous[0].clone().unwrap())],
                &[],
            )
            .unwrap()
        },
        |db| erase_record(db, &gone.namespace, Some(&session)),
        |db| all_previous_or_all_intended("V1", db, &keys, &previous, &intended),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "disk-full harness only"]
async fn disk_full_fence_with_records_is_all_or_nothing() -> Result<()> {
    let (a, b) = (UInt256::from([1; 32]), UInt256::from([2; 32]));
    let before = HashSet::from([a.clone()]);
    let after = HashSet::from([a, b]);
    let new_record = record(9);
    let keys = [DESTROYED_VALIDATOR_SESSIONS.to_owned(), record_key(&new_record.namespace)];
    let previous = [fence_bytes(&before), None];
    let intended = [fence_bytes(&after), Some(encode_record(&new_record).unwrap())];
    on_full_disk(
        "fence",
        |db| persist_retirement(db, &before, &[]).unwrap(),
        |db| persist_retirement(db, &after, std::slice::from_ref(&new_record)),
        |db| all_previous_or_all_intended("V2", db, &keys, &previous, &intended),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "disk-full harness only"]
async fn disk_full_fence_pruning_is_previous_or_intended() -> Result<()> {
    let (a, b) = (UInt256::from([1; 32]), UInt256::from([2; 32]));
    let before = HashSet::from([a.clone(), b]);
    // Pruning as the init-block rotation does: the remaining fence, no records.
    let remaining = HashSet::from([a]);
    let keys = [DESTROYED_VALIDATOR_SESSIONS.to_owned()];
    let previous = [fence_bytes(&before)];
    let intended = [fence_bytes(&remaining)];
    on_full_disk(
        "prune",
        |db| persist_retirement(db, &before, &[]).unwrap(),
        |db| persist_retirement(db, &remaining, &[]),
        |db| all_previous_or_all_intended("V7", db, &keys, &previous, &intended),
    )
    .await?;
    // Pruning to an empty fence deletes the key in the same way.
    if !control() {
        let keys = [DESTROYED_VALIDATOR_SESSIONS.to_owned()];
        let previous = [fence_bytes(&remaining)];
        let intended = [None];
        on_full_disk(
            "prune-empty",
            |db| persist_retirement(db, &remaining, &[]).unwrap(),
            |db| persist_retirement(db, &HashSet::new(), &[]),
            |db| all_previous_or_all_intended("V7-empty", db, &keys, &previous, &intended),
        )
        .await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "disk-full harness only"]
async fn disk_full_deleted_journal_write_is_previous_or_intended() -> Result<()> {
    // An authenticated record whose B1′ journal write (Deleting → Deleted)
    // hits a full disk, through the executor's own journal writer.
    let checkpoint = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        9,
        UInt256::from([1; 32]),
        UInt256::from([2; 32]),
    );
    let pin = consensus_common::session_runtime::SessionNetworkPin {
        global_id: -239,
        zerostate: checkpoint.clone(),
    };
    let binding = consensus_common::session_runtime::SessionRecoveryBinding {
        governing_masterchain: checkpoint.clone(),
        coordinates: consensus_common::session_runtime::SessionRecoveryCoordinates {
            shard: ShardIdent::masterchain(),
            catchain_seqno: 5,
            vertical_seqno: 0,
            last_key_block_seqno: 0,
            new_catchain_ids: false,
        },
    };
    let base = make_record(
        &UInt256::from([3; 32]),
        &NamespaceLayout::V2Validator,
        &ShardIdent::masterchain(),
        5,
        &checkpoint,
    )?
    .with_identity(consensus_common::validator_cleanup::CleanupIdentity {
        pin,
        binding,
        local_adnl: UInt256::from([4; 32]),
    })?;
    let payload = JournalPayload {
        attempt: (1 << 32) | 1,
        generation: 1,
        manifest_digest: UInt256::from([5; 32]),
        inventory_digest: UInt256::from([6; 32]),
        associations: Vec::new(),
    };
    let deleting = PendingValidatorCleanup {
        journal: CleanupJournal::Deleting(payload.clone()),
        ..base.clone()
    };
    let deleted = PendingValidatorCleanup { journal: CleanupJournal::Deleted(payload), ..base };
    let keys = [record_key(&deleting.namespace)];
    let previous = [Some(encode_record(&deleting)?)];
    let intended = [Some(encode_record(&deleted)?)];
    on_full_disk(
        "journal",
        |db| {
            db.write_validator_state_batch_sync(
                &[(keys[0].clone(), previous[0].clone().unwrap())],
                &[],
            )
            .unwrap()
        },
        // The writer reports an unsuccessful write as Ok(Err): Uncertain.
        |db| match write_journal(db, &deleting, &deleted)? {
            Ok(()) => Ok(()),
            Err(reason) => rtos_block::fail!("{reason}"),
        },
        |db| all_previous_or_all_intended("V6", db, &keys, &previous, &intended),
    )
    .await
}
