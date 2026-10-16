// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Validator cleanup-floor durability connected to executable recovery.
use super::*;
use consensus_common::validator_cleanup::{encode_checkpoint, GC_FLOOR_KEY};
use std::sync::Arc;

#[tokio::test]
#[ignore = "internal child; requires owned validator-floor fixture"]
async fn floor_child() -> Result<()> {
    let root = PathBuf::from(std::env::var("RTOS_TEST_VALIDATOR_CHILD_ROOT")?);
    let id: rtos_block::BlockIdExt = fs::read_to_string(root.join("floor-input.txt"))?.parse()?;
    let db = Arc::new(open_db(&root).await?);
    let keeper = crate::shard_states_keeper::ShardStatesKeeper::new(
        db.clone(), false, true, 0, 0, crate::config::ShardStatesCacheMode::Moderate,
        3600, Arc::new(crate::engine::Stopper::new()), 100,
        #[cfg(feature = "telemetry")]
        crate::collator_test_bundle::create_engine_telemetry(),
        crate::collator_test_bundle::create_engine_allocated(),
    )?;
    let guard = keeper.pin_cleanup_candidate(&id)?;
    if let Ok(arm) = std::env::var("RTOS_TEST_ROOT_WAL_ARM") {
        fs::write(arm, b"validator floor armed after native open and physical pin\n")?;
    }
    keeper.adopt_cleanup_floor(&id, guard, keeper.cleanup_floor_epoch())?;
    let (floor, state) = keeper.cleanup_floor().expect("acknowledged floor not pinned");
    assert_eq!(floor, id);
    assert_eq!(state.block_id(), &id);
    let bytes = db.load_validator_state_key_bounded(GC_FLOOR_KEY, 256)?.unwrap();
    assert_eq!(bytes, encode_checkpoint(&id));
    let omitted = std::env::var("RTOS_TEST_OMIT_MANIFEST_SYNC_FILE").as_deref() == Ok("validator-wal");
    if omitted {
        let proof = fs::read_to_string(std::env::var("RTOS_TEST_OMIT_MANIFEST_SYNC_MARKER")?)?;
        assert_eq!(proof.lines().count(), 1);
        assert!(proof.contains(&format!("{}/node_db/catchains/", root.display())), "wrong validator WAL owner");
    }
    let ack = root.join("validator-floor-ack.json");
    fs::write(&ack, serde_json::to_vec(&serde_json::json!({
        "id": id.to_string(), "bytes": hex::encode(bytes), "pinned": true,
        "sync_omission_before_ack": omitted,
    }))?)?;
    fs::File::open(&ack)?.sync_all()?;
    loop { tokio::time::sleep(Duration::from_secs(1)).await; }
}

pub(super) async fn write_and_interrupt(root: &Path, id: &rtos_block::BlockIdExt) -> Result<()> {
    fs::write(root.join("floor-input.txt"), id.to_string())?;
    cache_loss::sync_fixture(root)?;
    let path = root.join("validator-floor-child.log");
    let log = fs::File::create(&path)?;
    let mut child = Process(Command::new(std::env::current_exe()?)
        .args(["--exact", "--ignored", "--nocapture", "--test-threads=1",
            "archive_import::tests::node_process_recovery::truncation_recovery::validator_cache_loss::floor_child"])
        .env("RTOS_TEST_VALIDATOR_CHILD_ROOT", root)
        .stdout(Stdio::from(log.try_clone()?)).stderr(Stdio::from(log)).spawn()?);
    let ack = root.join("validator-floor-ack.json");
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(bytes) = fs::read(&ack) {
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                assert_eq!(value["id"], id.to_string());
                assert_eq!(value["bytes"], hex::encode(encode_checkpoint(id)));
                assert_eq!(value["pinned"], true);
                assert_eq!(value["sync_omission_before_ack"],
                    std::env::var("RTOS_TEST_OMIT_MANIFEST_SYNC_FILE").as_deref() == Ok("validator-wal"));
                break;
            }
        }
        if let Some(status) = child.0.try_wait()? {
            keep_evidence(root, &path)?;
            rtos_block::fail!("Validator floor child exited before acknowledgement: {status}");
        }
        if Instant::now() >= deadline {
            keep_evidence(root, &path)?;
            rtos_block::fail!("Validator floor acknowledgement timeout");
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
    eprintln!("Acknowledged validator floor writer killed with physical pin and native owner alive; cache-loss={loss}");
    Ok(())
}

pub(super) fn verify(root: &Path, db: &InternalDb, id: &rtos_block::BlockIdExt, phase: &str) -> Result<()> {
    let actual = db.load_validator_state_key_bounded(GC_FLOOR_KEY, 256)?;
    let expected = encode_checkpoint(id);
    let report = root.join(format!("validator-floor-{phase}.json"));
    fs::write(&report, serde_json::to_vec(&serde_json::json!({
        "expected": hex::encode(&expected), "actual": actual.as_ref().map(hex::encode),
        "id": id.to_string(),
    }))?)?;
    keep_evidence(root, &report)?;
    assert_eq!(actual, Some(expected), "Acknowledged validator cleanup floor lost after actual node restart");
    assert!(db.check_truncation_above_cleanup_floor(id.seq_no() - 1).is_err());
    db.check_truncation_above_cleanup_floor(id.seq_no())?;
    eprintln!("Validator cleanup floor bytes and truncation boundary preserved after {phase}");
    Ok(())
}
