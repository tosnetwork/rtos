// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Atomic outbox close removal plus journal update across executable recovery.
use super::*;
use crate::propagation_outbox::{inspect_exported_rows, Limits, OutboxDomain, PropagationOutbox};
use consensus_common::validator_cleanup::{decode_record, encode_record, record_key, CleanupAssociation, CleanupJournal};
use std::sync::Arc;

fn domain(db: &InternalDb) -> Result<OutboxDomain> {
    let fixture = Fixture::node_recovery();
    Ok(OutboxDomain { zerostate: fixture.id(0, false),
        global_id: db.load_shard_state_dynamic(&fixture.id(3, false))?.state()?.global_id(),
        wire_profile: rtos_api::WireProfile::T0 })
}
fn rows(db: &InternalDb) -> Result<Vec<String>> {
    let (_, record) = validator_retirement_loss::journal_pair(&Fixture::node_recovery().id(3, false))?;
    let key = record_key(&record.namespace);
    let journal = db
        .load_validator_state_key_bounded(&key, 64 << 20)?
        .map(hex::encode)
        .ok_or_else(|| rtos_block::error!("Missing outbox cleanup row {key}"))?;
    Ok(vec![hex::encode(crate::propagation_outbox::export_rows(db)?), journal])
}
fn receipt(root: &Path) -> Result<serde_json::Value> {
    Ok(serde_json::from_slice(&fs::read(root.join("validator-outbox-ack.json"))?)?)
}
fn check_pair(db: &InternalDb, previous: &[String], expected: &[String]) -> Result<()> {
    assert_eq!(previous.len(), 2); assert_eq!(expected.len(), 2);
    let domain = domain(db)?;
    let (entries, before) = inspect_exported_rows(&hex::decode(&previous[0])?, &domain)?;
    let (after_entries, after) = inspect_exported_rows(&hex::decode(&expected[0])?, &domain)?;
    assert!(entries.is_empty() && after_entries.is_empty());
    assert_eq!(before.len(), 2); assert_eq!(after.len(), 1);
    assert!(before.iter().all(|c| c.released));
    assert_eq!(after[0], before[1], "Unrelated Released close changed");
    let old = decode_record(&hex::decode(&previous[1])?).unwrap();
    let new = decode_record(&hex::decode(&expected[1])?).unwrap();
    let CleanupJournal::Deleted(payload) = &old.journal else { panic!("Expected Deleted baseline") };
    assert_eq!(payload.associations.len(), 1);
    let association = &payload.associations[0];
    assert_eq!(association.delivery_id, before[0].binding.delivery_id);
    assert_eq!(association.close_generation, before[0].binding.close_generation);
    assert_eq!(association.lease_generation, before[0].lease_generation);
    assert_eq!(association.dependency_digest, before[0].dependency_digest);
    assert_eq!(association.binding_digest, UInt256::calc_file_hash(&before[0].binding.encode()?));
    let mut intended = old.clone(); intended.journal = CleanupJournal::Releasing(payload.clone());
    assert_eq!(new, intended, "Close removal changed other journal fields");
    Ok(())
}

#[tokio::test]
#[ignore = "internal child; requires owned outbox fixture"]
async fn outbox_child() -> Result<()> {
    let root = PathBuf::from(std::env::var("RTOS_TEST_OUTBOX_CHILD_ROOT")?);
    let db = Arc::new(open_db(&root).await?);
    let fixture = Fixture::node_recovery();
    let domain = domain(&db)?;
    let store = PropagationOutbox::open(db.clone(), domain.clone(), Limits::default())?;
    // Baseline bookkeeping is synthetic; no live finality confirmation is claimed.
    let (first, second) = crate::propagation_outbox::closing::seed_released_pair_for_recovery(
        &store, [fixture.id(1, false), fixture.id(2, false), fixture.id(3, false)])?;
    let association = CleanupAssociation { delivery_id: first.binding.delivery_id.clone(),
        close_generation: first.binding.close_generation, lease_generation: first.lease_generation,
        dependency_digest: first.dependency_digest.clone(),
        binding_digest: UInt256::calc_file_hash(&first.binding.encode()?) };
    let (_, mut deleted) = validator_retirement_loss::journal_pair(&fixture.id(3, false))?;
    let identity = deleted.identity.as_mut().unwrap();
    identity.pin.zerostate = domain.zerostate; identity.pin.global_id = domain.global_id;
    let CleanupJournal::Deleted(payload) = &mut deleted.journal else { unreachable!() };
    payload.associations = vec![association.clone()];
    let mut releasing = deleted.clone();
    releasing.journal = CleanupJournal::Releasing(deleted.journal.payload().unwrap().clone());
    db.write_validator_state_batch_sync(&[(record_key(&deleted.namespace), encode_record(&deleted)?)], &[])?;
    let previous = rows(&db)?;
    if let Ok(arm) = std::env::var("RTOS_TEST_ROOT_WAL_ARM") { fs::write(arm, b"outbox armed after baseline sync\n")?; }
    if let Err(reason) = store.remove_cleanup_closes(&[association],
        &[(record_key(&releasing.namespace), encode_record(&releasing)?)])? {
        rtos_block::fail!("Close removal was not acknowledged: {reason}");
    }
    assert!(store.lookup_close(&first.binding.delivery_id)?.is_none());
    assert_eq!(store.lookup_close(&second.binding.delivery_id)?, Some(second));
    let expected = rows(&db)?;
    check_pair(&db, &previous, &expected)?;
    let omitted = std::env::var("RTOS_TEST_OMIT_MANIFEST_SYNC_FILE").as_deref() == Ok("validator-wal");
    if omitted {
        let proof = fs::read_to_string(std::env::var("RTOS_TEST_OMIT_MANIFEST_SYNC_MARKER")?)?;
        assert_eq!(proof.lines().count(), 1);
        assert!(proof.contains(&format!("{}/node_db/catchains/", root.display())));
    }
    let ack = root.join("validator-outbox-ack.json");
    fs::write(&ack, serde_json::to_vec(&serde_json::json!({
        "previous": previous, "expected": expected, "sync_omission_before_ack": omitted,
    }))?)?;
    fs::File::open(&ack)?.sync_all()?;
    loop { tokio::time::sleep(Duration::from_secs(1)).await; }
}

pub(super) async fn write_and_interrupt(root: &Path) -> Result<()> {
    cache_loss::sync_fixture(root)?;
    let path = root.join("validator-outbox-child.log");
    let log = fs::File::create(&path)?;
    let mut child = Process(Command::new(std::env::current_exe()?)
        .args(["--exact", "--ignored", "--nocapture", "--test-threads=1",
            "archive_import::tests::node_process_recovery::truncation_recovery::outbox_cache_loss::outbox_child"])
        .env("RTOS_TEST_OUTBOX_CHILD_ROOT", root)
        .stdout(Stdio::from(log.try_clone()?)).stderr(Stdio::from(log)).spawn()?);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(ack) = receipt(root) {
            let previous: Vec<String> = serde_json::from_value(ack["previous"].clone())?;
            let expected: Vec<String> = serde_json::from_value(ack["expected"].clone())?;
            assert_eq!(previous.len(), 2); assert_eq!(expected.len(), 2);
            assert_ne!(previous[0], expected[0]); assert_ne!(previous[1], expected[1]);
            assert_eq!(ack["sync_omission_before_ack"],
                std::env::var("RTOS_TEST_OMIT_MANIFEST_SYNC_FILE").as_deref() == Ok("validator-wal"));
            break;
        }
        if let Some(status) = child.0.try_wait()? {
            keep_evidence(root, &path)?;
            rtos_block::fail!("Outbox child exited before acknowledgement: {status}");
        }
        if Instant::now() >= deadline { keep_evidence(root, &path)?; rtos_block::fail!("Outbox acknowledgement timeout"); }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(child.0.try_wait()?.is_none()); child.0.kill()?;
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(child.0.wait()?.signal(), Some(9));
    keep_evidence(root, &path)?; keep_evidence(root, &root.join("validator-outbox-ack.json"))?;
    let loss = match std::env::var("RTOS_TEST_CACHE_LOSS_ENABLED")?.as_str() {
        "1" => true, "0" => false, _ => rtos_block::fail!("Invalid cache-loss mode"),
    };
    if loss { cache_loss::clear(root).await?; }
    eprintln!("Acknowledged validator outbox batch writer killed without native close; cache-loss={loss}");
    Ok(())
}

pub(super) fn verify(root: &Path, db: &InternalDb, phase: &str) -> Result<()> {
    let ack = receipt(root)?;
    let previous: Vec<String> = serde_json::from_value(ack["previous"].clone())?;
    let expected: Vec<String> = serde_json::from_value(ack["expected"].clone())?;
    check_pair(db, &previous, &expected)?;
    let actual = rows(db)?;
    let path = root.join(format!("validator-outbox-{phase}.json"));
    fs::write(&path, serde_json::to_vec(&serde_json::json!({
        "previous": previous, "expected": expected, "actual": actual,
    }))?)?; keep_evidence(root, &path)?;
    assert_eq!(actual, expected, "Acknowledged validator outbox batch lost after actual node restart");
    eprintln!("Validator outbox batch preserved together after {phase}");
    Ok(())
}
