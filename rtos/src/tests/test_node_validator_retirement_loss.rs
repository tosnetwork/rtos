// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Synced validator-state mutations followed by executable recovery.
use super::*;
use consensus_common::validator_cleanup::{candidate_claim_key, encode_record, make_record, record_key, CleanupIdentity, CleanupJournal, JournalPayload, NamespaceLayout, PendingValidatorCleanup};
use crate::{internal_db::DESTROYED_VALIDATOR_SESSIONS, validator::validator_cleanup_gc::{erase_record, next_cleanup_incarnation, persist_retirement, write_journal}};
use std::collections::HashSet;

#[derive(Clone, Copy)]
pub(super) enum BatchKind { Retirement, Claim, Incarnation, Journal }
impl BatchKind {
    pub(super) fn name(self) -> &'static str {
        match self { Self::Retirement => "retirement", Self::Claim => "claim", Self::Incarnation => "incarnation", Self::Journal => "journal" }
    }
}

fn fixture(id: &rtos_block::BlockIdExt) -> Result<(HashSet<UInt256>, PendingValidatorCleanup)> {
    let session = UInt256::from([0x22; 32]);
    let fence = HashSet::from([UInt256::from([0x11; 32]), session.clone()]);
    let record = make_record(&session, &NamespaceLayout::V1, &rtos_block::ShardIdent::masterchain(), 5, id)?;
    Ok((fence, record))
}
// Identity and digests are synthetic journal metadata, not authentication evidence.
fn journal_pair(id: &rtos_block::BlockIdExt) -> Result<(PendingValidatorCleanup, PendingValidatorCleanup)> {
    use consensus_common::session_runtime::{SessionNetworkPin, SessionRecoveryBinding, SessionRecoveryCoordinates};
    let base = make_record(&UInt256::from([0x22; 32]), &NamespaceLayout::V2Validator,
        &rtos_block::ShardIdent::masterchain(), 5, id)?.with_identity(CleanupIdentity {
        pin: SessionNetworkPin { global_id: -239, zerostate: id.clone() },
        binding: SessionRecoveryBinding { governing_masterchain: id.clone(), coordinates: SessionRecoveryCoordinates {
            shard: rtos_block::ShardIdent::masterchain(), catchain_seqno: 5,
            vertical_seqno: 0, last_key_block_seqno: 0, new_catchain_ids: false,
        } },
        local_adnl: UInt256::from([4; 32]),
    })?;
    let payload = JournalPayload { attempt: (1 << 32) | 1, generation: 1,
        manifest_digest: UInt256::from([5; 32]), inventory_digest: UInt256::from([6; 32]),
        associations: Vec::new() };
    Ok((PendingValidatorCleanup { journal: CleanupJournal::Deleting(payload.clone()), ..base.clone() },
        PendingValidatorCleanup { journal: CleanupJournal::Deleted(payload), ..base }))
}
fn intended(id: &rtos_block::BlockIdExt, kind: BatchKind) -> Result<Vec<Option<Vec<u8>>>> {
    let (fence, record) = fixture(id)?;
    let fence = Some(crate::engine_operations::serialize_destroyed_session_ids(&fence));
    Ok(match kind {
        BatchKind::Retirement => vec![fence, Some(encode_record(&record)?)],
        BatchKind::Claim => vec![None, Some(record.namespace.into_bytes()), fence],
        BatchKind::Incarnation => vec![Some(2u64.to_le_bytes().to_vec())],
        BatchKind::Journal => vec![Some(encode_record(&journal_pair(id)?.1)?), fence],
    })
}
fn previous(id: &rtos_block::BlockIdExt, kind: BatchKind) -> Result<Vec<Option<Vec<u8>>>> {
    Ok(match kind {
        BatchKind::Incarnation => vec![Some(1u64.to_le_bytes().to_vec())],
        BatchKind::Journal => vec![Some(encode_record(&journal_pair(id)?.0)?),
            Some(crate::engine_operations::serialize_destroyed_session_ids(&fixture(id)?.0))],
        BatchKind::Retirement => vec![Some(crate::engine_operations::serialize_destroyed_session_ids(
            &HashSet::from([UInt256::from([0x11; 32])]))), None],
        BatchKind::Claim => {
            let (fence, record) = fixture(id)?;
            vec![Some(encode_record(&record)?), None,
                Some(crate::engine_operations::serialize_destroyed_session_ids(&fence))]
        }
    })
}
fn read(db: &InternalDb, id: &rtos_block::BlockIdExt, kind: BatchKind) -> Result<Vec<Option<Vec<u8>>>> {
    let (_, record) = fixture(id)?;
    let keys = match kind {
        BatchKind::Journal => vec![record_key(&journal_pair(id)?.0.namespace), DESTROYED_VALIDATOR_SESSIONS.to_owned()],
        BatchKind::Incarnation => vec!["ValidatorCleanupIncarnationV1".to_owned()],
        BatchKind::Retirement => vec![DESTROYED_VALIDATOR_SESSIONS.to_owned(), record_key(&record.namespace)],
        BatchKind::Claim => vec![record_key(&record.namespace), candidate_claim_key(&record.session_id),
            DESTROYED_VALIDATOR_SESSIONS.to_owned()],
    };
    keys.iter().map(|key| db.load_validator_state_key_bounded(key, 1 << 20)).collect()
}
fn encoded(rows: &[Option<Vec<u8>>]) -> Vec<Option<String>> {
    rows.iter().map(|bytes| bytes.as_ref().map(hex::encode)).collect()
}

#[tokio::test]
#[ignore = "internal child; requires owned validator batch fixture"]
async fn batch_child() -> Result<()> {
    let root = PathBuf::from(std::env::var("RTOS_TEST_VALIDATOR_CHILD_ROOT")?);
    let id: rtos_block::BlockIdExt = fs::read_to_string(root.join("retirement-input.txt"))?.parse()?;
    let kind = match std::env::var("RTOS_TEST_VALIDATOR_BATCH")?.as_str() {
        "retirement" => BatchKind::Retirement, "claim" => BatchKind::Claim,
        "incarnation" => BatchKind::Incarnation, "journal" => BatchKind::Journal,
        _ => rtos_block::fail!("Unknown validator batch"),
    };
    let db = open_db(&root).await?;
    let (fence, record) = fixture(&id)?;
    match kind {
        BatchKind::Incarnation => assert_eq!(next_cleanup_incarnation(&db)?, 1),
        BatchKind::Journal => persist_retirement(&db, &fence, &[journal_pair(&id)?.0])?,
        BatchKind::Retirement => persist_retirement(&db, &HashSet::from([UInt256::from([0x11; 32])]), &[])?,
        BatchKind::Claim => persist_retirement(&db, &fence, std::slice::from_ref(&record))?,
    }
    assert_eq!(read(&db, &id, kind)?, previous(&id, kind)?);
    if let Ok(arm) = std::env::var("RTOS_TEST_ROOT_WAL_ARM") {
        fs::write(arm, b"validator mutation armed after durable baseline\n")?;
    }
    match kind {
        BatchKind::Retirement => persist_retirement(&db, &fence, &[record])?,
        BatchKind::Claim => erase_record(&db, &record.namespace, Some(&record.session_id))?,
        BatchKind::Incarnation => assert_eq!(next_cleanup_incarnation(&db)?, 2),
        BatchKind::Journal => {
            let (previous, next) = journal_pair(&id)?;
            if let Err(reason) = write_journal(&db, &previous, &next)? {
                rtos_block::fail!("Journal write was not acknowledged: {reason}");
            }
        }
    }
    assert_eq!(read(&db, &id, kind)?, intended(&id, kind)?);
    let omitted = std::env::var("RTOS_TEST_OMIT_MANIFEST_SYNC_FILE").as_deref() == Ok("validator-wal");
    if omitted {
        let proof = fs::read_to_string(std::env::var("RTOS_TEST_OMIT_MANIFEST_SYNC_MARKER")?)?;
        assert_eq!(proof.lines().count(), 1);
        assert!(proof.contains(&format!("{}/node_db/catchains/", root.display())));
    }
    let ack = root.join(format!("validator-{}-ack.json", kind.name()));
    fs::write(&ack, serde_json::to_vec(&serde_json::json!({
        "checkpoint": id.to_string(), "kind": kind.name(), "previous": encoded(&previous(&id, kind)?),
        "expected": encoded(&intended(&id, kind)?), "sync_omission_before_ack": omitted,
    }))?)?;
    fs::File::open(&ack)?.sync_all()?;
    loop { tokio::time::sleep(Duration::from_secs(1)).await; }
}

pub(super) async fn write_and_interrupt(root: &Path, id: &rtos_block::BlockIdExt, kind: BatchKind) -> Result<()> {
    fs::write(root.join("retirement-input.txt"), id.to_string())?;
    cache_loss::sync_fixture(root)?;
    let path = root.join(format!("validator-{}-child.log", kind.name()));
    let log = fs::File::create(&path)?;
    let mut child = Process(Command::new(std::env::current_exe()?)
        .args(["--exact", "--ignored", "--nocapture", "--test-threads=1",
            "archive_import::tests::node_process_recovery::truncation_recovery::validator_retirement_loss::batch_child"])
        .env("RTOS_TEST_VALIDATOR_CHILD_ROOT", root)
        .env("RTOS_TEST_VALIDATOR_BATCH", kind.name())
        .stdout(Stdio::from(log.try_clone()?)).stderr(Stdio::from(log)).spawn()?);
    let ack = root.join(format!("validator-{}-ack.json", kind.name()));
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(bytes) = fs::read(&ack) {
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                assert_eq!(value["checkpoint"], id.to_string());
                assert_eq!(value["kind"], kind.name());
                assert_eq!(value["expected"], serde_json::json!(encoded(&intended(id, kind)?)));
                assert_eq!(value["previous"], serde_json::json!(encoded(&previous(id, kind)?)));
                assert_eq!(value["sync_omission_before_ack"],
                    std::env::var("RTOS_TEST_OMIT_MANIFEST_SYNC_FILE").as_deref() == Ok("validator-wal"));
                break;
            }
        }
        if let Some(status) = child.0.try_wait()? {
            keep_evidence(root, &path)?;
            rtos_block::fail!("Validator batch child exited before acknowledgement: {status}");
        }
        if Instant::now() >= deadline {
            keep_evidence(root, &path)?;
            rtos_block::fail!("Validator batch acknowledgement timeout");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(child.0.try_wait()?.is_none());
    child.0.kill()?;
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(child.0.wait()?.signal(), Some(9));
    keep_evidence(root, &path)?;
    keep_evidence(root, &ack)?;
    let loss = match std::env::var("RTOS_TEST_CACHE_LOSS_ENABLED")?.as_str() {
        "1" => true, "0" => false,
        _ => rtos_block::fail!("Invalid cache-loss mode"),
    };
    if loss { cache_loss::clear(root).await?; }
    eprintln!("Acknowledged validator {} batch writer killed without native close; cache-loss={loss}", kind.name());
    Ok(())
}

pub(super) fn verify(root: &Path, db: &InternalDb, id: &rtos_block::BlockIdExt, phase: &str, kind: BatchKind) -> Result<()> {
    let actual = read(db, id, kind)?;
    let expected = intended(id, kind)?;
    let report = root.join(format!("validator-{}-{phase}.json", kind.name()));
    fs::write(&report, serde_json::to_vec(&serde_json::json!({
        "previous": encoded(&previous(id, kind)?), "expected": encoded(&expected), "actual": encoded(&actual),
    }))?)?;
    keep_evidence(root, &report)?;
    assert_eq!(actual, expected, "Acknowledged validator {} batch lost after actual node restart", kind.name());
    if matches!(kind, BatchKind::Journal) && phase == "two-boots" {
        let (previous, next) = journal_pair(id)?;
        assert!(write_journal(db, &previous, &next).is_err(), "Stale journal writer was accepted after recovery");
        assert_eq!(read(db, id, kind)?, expected, "Stale journal writer changed durable state");
        eprintln!("Recovered Deleted journal refuses stale Deleting writer without changing bytes");
    }
    if matches!(kind, BatchKind::Incarnation) && phase == "two-boots" {
        let next = next_cleanup_incarnation(db)?;
        let report = root.join("validator-incarnation-next.json");
        fs::write(&report, serde_json::to_vec(&serde_json::json!({
            "acknowledged_before_crash": 2, "next_after_recovery": next,
        }))?)?;
        keep_evidence(root, &report)?;
        assert_eq!(next, 3, "Recovery reused an acknowledged cleanup incarnation");
        assert_eq!(read(db, id, kind)?, vec![Some(3u64.to_le_bytes().to_vec())]);
        eprintln!("Next cleanup incarnation advances beyond acknowledged pre-crash value");
    }
    eprintln!("Validator {} batch preserved together after {phase}", kind.name());
    Ok(())
}
