// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Synced validator retirement batch followed by executable recovery.
use super::*;
use consensus_common::validator_cleanup::{encode_record, make_record, record_key, NamespaceLayout, PendingValidatorCleanup};
use crate::{internal_db::DESTROYED_VALIDATOR_SESSIONS, validator::validator_cleanup_gc::persist_retirement};
use std::collections::HashSet;

fn fixture(id: &rtos_block::BlockIdExt) -> Result<(HashSet<UInt256>, PendingValidatorCleanup)> {
    let session = UInt256::from([0x22; 32]);
    let fence = HashSet::from([UInt256::from([0x11; 32]), session.clone()]);
    let record = make_record(&session, &NamespaceLayout::V1, &rtos_block::ShardIdent::masterchain(), 5, id)?;
    Ok((fence, record))
}
fn intended(id: &rtos_block::BlockIdExt) -> Result<Vec<Option<Vec<u8>>>> {
    let (fence, record) = fixture(id)?;
    Ok(vec![Some(crate::engine_operations::serialize_destroyed_session_ids(&fence)), Some(encode_record(&record)?)])
}
fn previous() -> Vec<Option<Vec<u8>>> {
    vec![Some(crate::engine_operations::serialize_destroyed_session_ids(&HashSet::from([UInt256::from([0x11; 32])]))), None]
}
fn read(db: &InternalDb, id: &rtos_block::BlockIdExt) -> Result<Vec<Option<Vec<u8>>>> {
    let (_, record) = fixture(id)?;
    Ok(vec![db.load_validator_state_key_bounded(DESTROYED_VALIDATOR_SESSIONS, 1 << 20)?,
        db.load_validator_state_key_bounded(&record_key(&record.namespace), 1 << 20)?])
}
fn encoded(rows: &[Option<Vec<u8>>]) -> Vec<Option<String>> {
    rows.iter().map(|bytes| bytes.as_ref().map(hex::encode)).collect()
}

#[tokio::test]
#[ignore = "internal child; requires owned validator retirement fixture"]
async fn retirement_child() -> Result<()> {
    let root = PathBuf::from(std::env::var("RTOS_TEST_VALIDATOR_CHILD_ROOT")?);
    let id: rtos_block::BlockIdExt = fs::read_to_string(root.join("retirement-input.txt"))?.parse()?;
    let db = open_db(&root).await?;
    persist_retirement(&db, &HashSet::from([UInt256::from([0x11; 32])]), &[])?;
    assert_eq!(read(&db, &id)?, previous());
    if let Ok(arm) = std::env::var("RTOS_TEST_ROOT_WAL_ARM") {
        fs::write(arm, b"retirement armed after durable previous fence\n")?;
    }
    let (fence, record) = fixture(&id)?;
    persist_retirement(&db, &fence, &[record])?;
    assert_eq!(read(&db, &id)?, intended(&id)?);
    let omitted = std::env::var("RTOS_TEST_OMIT_MANIFEST_SYNC_FILE").as_deref() == Ok("validator-wal");
    if omitted {
        let proof = fs::read_to_string(std::env::var("RTOS_TEST_OMIT_MANIFEST_SYNC_MARKER")?)?;
        assert_eq!(proof.lines().count(), 1);
        assert!(proof.contains(&format!("{}/node_db/catchains/", root.display())));
    }
    let ack = root.join("validator-retirement-ack.json");
    fs::write(&ack, serde_json::to_vec(&serde_json::json!({
        "checkpoint": id.to_string(), "previous": encoded(&previous()),
        "expected": encoded(&intended(&id)?), "sync_omission_before_ack": omitted,
    }))?)?;
    fs::File::open(&ack)?.sync_all()?;
    loop { tokio::time::sleep(Duration::from_secs(1)).await; }
}

pub(super) async fn write_and_interrupt(root: &Path, id: &rtos_block::BlockIdExt) -> Result<()> {
    fs::write(root.join("retirement-input.txt"), id.to_string())?;
    cache_loss::sync_fixture(root)?;
    let path = root.join("validator-retirement-child.log");
    let log = fs::File::create(&path)?;
    let mut child = Process(Command::new(std::env::current_exe()?)
        .args(["--exact", "--ignored", "--nocapture", "--test-threads=1",
            "archive_import::tests::node_process_recovery::truncation_recovery::validator_retirement_loss::retirement_child"])
        .env("RTOS_TEST_VALIDATOR_CHILD_ROOT", root)
        .stdout(Stdio::from(log.try_clone()?)).stderr(Stdio::from(log)).spawn()?);
    let ack = root.join("validator-retirement-ack.json");
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(bytes) = fs::read(&ack) {
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                assert_eq!(value["checkpoint"], id.to_string());
                assert_eq!(value["expected"], serde_json::json!(encoded(&intended(id)?)));
                assert_eq!(value["previous"], serde_json::json!(encoded(&previous())));
                assert_eq!(value["sync_omission_before_ack"],
                    std::env::var("RTOS_TEST_OMIT_MANIFEST_SYNC_FILE").as_deref() == Ok("validator-wal"));
                break;
            }
        }
        if let Some(status) = child.0.try_wait()? {
            keep_evidence(root, &path)?;
            rtos_block::fail!("Retirement child exited before acknowledgement: {status}");
        }
        if Instant::now() >= deadline {
            keep_evidence(root, &path)?;
            rtos_block::fail!("Retirement acknowledgement timeout");
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
    eprintln!("Acknowledged validator retirement batch writer killed without native close; cache-loss={loss}");
    Ok(())
}

pub(super) fn verify(root: &Path, db: &InternalDb, id: &rtos_block::BlockIdExt, phase: &str) -> Result<()> {
    let actual = read(db, id)?;
    let expected = intended(id)?;
    let report = root.join(format!("validator-retirement-{phase}.json"));
    fs::write(&report, serde_json::to_vec(&serde_json::json!({
        "previous": encoded(&previous()), "expected": encoded(&expected), "actual": encoded(&actual),
    }))?)?;
    keep_evidence(root, &report)?;
    assert_eq!(actual, expected, "Acknowledged validator retirement batch lost after actual node restart");
    eprintln!("Validator retirement fence and record preserved together after {phase}");
    Ok(())
}
