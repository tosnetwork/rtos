// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! A real history state restored through the native writer and publication barrier.
use super::*;
use crate::{
    collator_test_bundle::create_engine_allocated, internal_db::SHARDSTATE_DB_NAME,
    shard_state::ShardStateStuff,
};
use std::sync::Arc;
use storage::{
    db::node::{CELLSCOUNTERS_CF_NAME, CELLS_CF_NAME},
    shardstate_db_async::{AllowStateGcResolver, SsNotificationCallback},
};

// Preserve the authenticated importer output separately, then populate the
// ordinary node through native APIs. The executable opens the same dynamic
// mode; it cannot silently fall back to the archival copy of the state.
pub(crate) async fn prepare_dynamic(root: &Path, fixture: &Fixture) -> Result<()> {
    let source = open_db(root).await?;
    fixture.assert_imported(&source, 4).await?;
    let mut history = Vec::new();
    for seq in 0..=4 {
        for wc in if seq == 0 { vec![false, true] } else { fixture.chains() } {
            let id = fixture.id(seq, wc);
            let handle = source.load_block_handle(&id)?.unwrap();
            let state = source.load_shard_state_dynamic(&id)?;
            history.push((
                id,
                handle.gen_utime(),
                if seq > 0 { Some(source.load_block_data(&handle).await?) } else { None },
                if seq > 0 { Some(source.load_block_proof(&handle, wc).await?) } else { None },
                rtos_block::write_boc(state.root_cell())?,
            ));
        }
    }
    let mut cursors = Vec::new();
    for key in [
        LAST_APPLIED_MC_BLOCK,
        ARCHIVES_GC_BLOCK,
        PSS_KEEPER_MC_BLOCK,
        SHARD_CLIENT_MC_BLOCK,
        crate::internal_db::INITIAL_MC_BLOCK,
        crate::internal_db::LAST_UNNEEDED_KEY_BLOCK,
    ] {
        if let Some(id) = source.load_full_node_state(key)? {
            cursors.push((key, (*id).clone()));
        }
    }
    let (physical, _) = source.sst_databases_for_test();
    source.stop_states_db().await?;
    drop(source);
    tokio::time::timeout(Duration::from_secs(30), wait_for_db_release(physical)).await?;
    let saved = root.join("authenticated-archive-source");
    fs::create_dir(&saved)?;
    fs::rename(root.join("node_db"), saved.join("node_db"))?;
    fs::rename(root.join("epochs"), saved.join("epochs"))?;
    fs::create_dir(root.join("epochs"))?;
    fs::write(root.join("dynamic-state-fixture"), b"native dynamic history\n")?;
    let _network_binding =
        crate::network_db::DbNetworkBinding::acquire(&root.join("node_db"), &fixture.id(0, false))?;
    let db = open_db(root).await?;
    assert!(!db.is_archival_mode());
    for (id, utime, block, proof, bytes) in history {
        let handle = if let Some(block) = &block {
            db.store_block_data(block, None).await?.to_any()
        } else {
            db.create_or_load_block_handle(&id, None, Some(utime), None)?.to_any()
        };
        if let Some(proof) = proof {
            db.store_block_proof(&id, Some(handle.clone()), &proof, None).await?;
        }
        let state = ShardStateStuff::from_root_cell(
            id.clone(),
            rtos_block::read_single_root_boc(&bytes)?,
            #[cfg(feature = "telemetry")]
            &crate::collator_test_bundle::create_engine_telemetry(),
            &create_engine_allocated(),
        )?;
        let callback = SsNotificationCallback::new();
        db.store_shard_state_dynamic(&handle, &state, None, Some(callback.clone()), true).await?;
        tokio::time::timeout(Duration::from_secs(30), callback.wait()).await?;
        if id.seq_no > 0 {
            let prev = fixture.id(id.seq_no - 1, !id.is_masterchain());
            db.store_block_prev1(&handle, &prev, None)?;
            db.store_block_next1(&db.load_block_handle(&prev)?.unwrap(), &id, None)?;
            db.assign_mc_ref_seq_no(&handle, id.seq_no, None)?;
        }
        db.store_block_applied(&handle, None)?;
        if id.seq_no > 0 {
            db.archive_block(&id, None).await?;
        }
        db.sync_publication_metadata(&handle).await?;
    }
    for (key, id) in cursors {
        db.save_full_node_state(key, &id)?;
    }
    db.sync_publication_state().await?;
    fixture.assert_imported(&db, 4).await?;
    let (physical, _) = db.sst_databases_for_test();
    db.stop_states_db().await?;
    drop(db);
    tokio::time::timeout(Duration::from_secs(30), wait_for_db_release(physical)).await?;
    Ok(())
}

struct OnlyTarget(rtos_block::BlockIdExt);
impl AllowStateGcResolver for OnlyTarget {
    fn allow_state_gc(&self, id: &rtos_block::BlockIdExt, _: u64, _: u64) -> Result<bool> {
        Ok(id == &self.0)
    }
}
fn rows(db: &InternalDb) -> Result<BTreeMap<String, String>> {
    let (physical, _) = db.sst_databases_for_test();
    let mut rows = BTreeMap::new();
    for family in [CELLS_CF_NAME, CELLSCOUNTERS_CF_NAME, SHARDSTATE_DB_NAME] {
        physical.clone().table::<UInt256>(family, false)?.for_each(&mut |key, value| {
            rows.insert(format!("{family}/{}", hex::encode(key)), hex::encode(value));
            Ok(true)
        })?;
    }
    Ok(rows)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "internal child; requires owned history fixture"]
async fn state_child() -> Result<()> {
    let root = PathBuf::from(std::env::var("RTOS_TEST_STATE_CHILD_ROOT")?);
    let unconfirmed = std::env::var("RTOS_TEST_STATE_SYNC_FAILURE").as_deref() == Ok("1");
    let id = Fixture::node_recovery().id(3, false);
    let db = open_db(&root).await?;
    let bytes = rtos_block::write_boc(db.load_shard_state_dynamic(&id)?.root_cell())?;
    let original = rows(&db)?;
    // Establish an absent-state baseline through the real GC owner. Only the
    // eligibility policy is synthetic; no raw cell/counter rows are removed.
    db.test_watch_state_gc_batch(&id);
    db.adjust_states_gc_interval(1);
    db.start_states_gc(Arc::new(OnlyTarget(id.clone())));
    tokio::time::timeout(Duration::from_secs(30), async {
        while db.test_contains_dynamic_state_record(&id).unwrap()
            || !db.test_watched_state_gc_batch_completed()
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    db.sync_publication_state().await?;
    let absent = rows(&db)?;
    assert_ne!(original, absent, "GC must physically change the target state graph");
    db.stop_states_db().await?;
    drop(db);
    // Reopen without the fixture GC policy before restoring the actual MC3 state.
    let db = open_db(&root).await?;
    assert!(!db.test_contains_dynamic_state_record(&id)?);
    assert_eq!(rows(&db)?, absent);
    cache_loss::sync_fixture(&root)?;
    let state = ShardStateStuff::from_root_cell(
        id.clone(),
        rtos_block::read_single_root_boc(&bytes)?,
        #[cfg(feature = "telemetry")]
        &crate::collator_test_bundle::create_engine_telemetry(),
        &create_engine_allocated(),
    )?;
    if let Ok(arm) = std::env::var("RTOS_TEST_ROOT_WAL_ARM") {
        fs::write(arm, b"state WAL armed after durable GC baseline\n")?;
    }
    let callback = SsNotificationCallback::new();
    let handle = db.load_block_handle(&id)?.unwrap();
    let (_, queued) =
        db.store_shard_state_dynamic(&handle, &state, None, Some(callback.clone()), true).await?;
    assert!(queued);
    tokio::time::timeout(Duration::from_secs(30), callback.wait()).await?;
    // Completion of put alone is not the publication durability contract.
    let sync = db.sync_publication_state().await;
    if unconfirmed {
        let proof = fs::read_to_string(root.join("state-sync-fault.reached"))?;
        assert_eq!(proof.lines().count(), 1);
        assert!(proof.starts_with(&format!("state WAL sync EIO: {}/node_db/db/", root.display())));
        assert!(proof.trim_end().ends_with(".log"));
        let error = sync.expect_err("State publication acknowledged a failed WAL sync");
        assert!(format!("{error:#}").contains("Input/output error"));
    } else {
        sync?;
    }
    if std::env::var("RTOS_TEST_OMIT_MANIFEST_SYNC_FILE").as_deref() == Ok("state-wal") {
        let marker = fs::read_to_string(std::env::var("RTOS_TEST_OMIT_MANIFEST_SYNC_MARKER")?)?;
        assert_eq!(
            marker.lines().count(),
            1,
            "exact WAL omission must precede state acknowledgement"
        );
        assert!(
            marker.contains(&format!("{}/node_db/db/", root.display()))
                && marker.trim_end().ends_with(".log")
        );
    }
    assert_eq!(rtos_block::write_boc(db.load_shard_state_dynamic(&id)?.root_cell())?, bytes);
    let restored = rows(&db)?;
    // State index timestamps may change; physical cells and counters must return
    // exactly to the original graph, including references shared with other states.
    for family in [CELLS_CF_NAME, CELLSCOUNTERS_CF_NAME] {
        let prefix = format!("{family}/");
        assert_eq!(
            original.iter().filter(|(k, _)| k.starts_with(&prefix)).collect::<Vec<_>>(),
            restored.iter().filter(|(k, _)| k.starts_with(&prefix)).collect::<Vec<_>>()
        );
    }
    let ack = root.join(if unconfirmed { "state-refusal.json" } else { "state-ack.json" });
    fs::write(
        &ack,
        serde_json::to_vec(&serde_json::json!({"bytes":hex::encode(bytes),
        "rows":restored,"state_barrier_completed":!unconfirmed,"publication_acknowledged":!unconfirmed,"gc_baseline_rows":absent.len()}))?,
    )?;
    fs::File::open(ack)?.sync_all()?;
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

pub(super) async fn write_and_interrupt(root: &Path) -> Result<()> {
    write_and_interrupt_inner(root, false).await
}
pub(super) async fn refuse_and_interrupt(root: &Path) -> Result<()> {
    write_and_interrupt_inner(root, true).await
}
async fn write_and_interrupt_inner(root: &Path, unconfirmed: bool) -> Result<()> {
    let log_path = root.join("state-child.log");
    let log = fs::File::create(&log_path)?;
    let mut command = Command::new(std::env::current_exe()?);
    if unconfirmed {
        let source = root.join("state-sync-fault.c");
        let library = root.join("state-sync-fault.so");
        fs::write(&source, include_str!("state_sync_fault.c"))?;
        let result = Command::new("cc")
            .args(["-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror"])
            .arg(&source)
            .arg("-o")
            .arg(&library)
            .output()?;
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
        command
            .env("LD_PRELOAD", library)
            .env("RTOS_TEST_STATE_SYNC_FAILURE", "1")
            .env("RTOS_TEST_STATE_FAULT_PREFIX", format!("{}/node_db/db/", root.display()))
            .env("RTOS_TEST_ROOT_WAL_ARM", root.join("state-sync-fault.arm"))
            .env("RTOS_TEST_STATE_FAULT_MARKER", root.join("state-sync-fault.reached"));
    }
    let mut child = Process(command
        .args(["--exact", "--ignored", "--nocapture", "--test-threads=1",
            "archive_import::tests::node_process_recovery::truncation_recovery::state_cache_loss::state_child"])
        .env("RTOS_TEST_STATE_CHILD_ROOT", root)
        .stdout(Stdio::from(log.try_clone()?)).stderr(Stdio::from(log)).spawn()?);
    let ack = root.join(if unconfirmed { "state-refusal.json" } else { "state-ack.json" });
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if let Ok(bytes) = fs::read(&ack) {
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                assert_eq!(value["state_barrier_completed"], !unconfirmed);
                break;
            }
        }
        if let Some(status) = child.0.try_wait()? {
            keep_evidence(root, &log_path)?;
            rtos_block::fail!("State writer exited before publication barrier: {status}");
        }
        if Instant::now() >= deadline {
            keep_evidence(root, &log_path)?;
            rtos_block::fail!("State writer timeout");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(child.0.try_wait()?.is_none());
    child.0.kill()?;
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(child.0.wait()?.signal(), Some(9));
    keep_evidence(root, &log_path)?;
    keep_evidence(root, &ack)?;
    if unconfirmed {
        assert!(!root.join("state-ack.json").exists());
        for name in ["state-sync-fault.c", "state-sync-fault.so", "state-sync-fault.reached"] {
            keep_evidence(root, &root.join(name))?;
        }
    }
    let loss = match std::env::var("RTOS_TEST_CACHE_LOSS_ENABLED")?.as_str() {
        "1" => true,
        "0" => false,
        _ => rtos_block::fail!("Invalid cache-loss mode"),
    };
    if loss {
        cache_loss::clear(root).await?;
    }
    if unconfirmed {
        eprintln!("Unconfirmed state writer killed after WAL sync refusal; cache-loss={loss}");
    } else {
        eprintln!(
            "Acknowledged state publication writer killed without native close; cache-loss={loss}"
        );
    }
    Ok(())
}

pub(super) fn verify(root: &Path, db: &InternalDb, phase: &str) -> Result<()> {
    verify_inner(root, db, phase, false)
}
pub(super) fn verify_reconstructed(root: &Path, db: &InternalDb, phase: &str) -> Result<()> {
    verify_inner(root, db, phase, true)
}
fn verify_inner(root: &Path, db: &InternalDb, phase: &str, unconfirmed: bool) -> Result<()> {
    let receipt = if unconfirmed { "state-refusal.json" } else { "state-ack.json" };
    let ack: serde_json::Value = serde_json::from_slice(&fs::read(root.join(receipt))?)?;
    let mut expected: BTreeMap<String, String> = serde_json::from_value(ack["rows"].clone())?;
    let mut actual = rows(db)?;
    if unconfirmed {
        use storage::db::DbKey;
        assert_eq!(ack["publication_acknowledged"], false);
        // A genuine re-save has a new save timestamp. Every other index byte,
        // every cell, and every shared-reference counter must remain exact.
        let id = Fixture::node_recovery().id(3, false);
        let key = format!("{SHARDSTATE_DB_NAME}/{}", hex::encode(id.key()));
        for snapshot in [&mut actual, &mut expected] {
            let row = snapshot.get_mut(&key).expect("reconstructed MC3 index missing");
            assert!(row.len() >= 16);
            row.truncate(row.len() - 16);
        }
    }
    assert_eq!(actual, expected, "Cells, counters or state index changed after restart");
    let id = Fixture::node_recovery().id(3, false);
    let state = db.load_shard_state_dynamic(&id)?;
    assert_eq!(
        rtos_block::write_boc(state.root_cell())?,
        hex::decode(ack["bytes"].as_str().unwrap())?
    );
    let report = root.join(format!("state-{phase}.json"));
    fs::write(
        &report,
        serde_json::to_vec(&serde_json::json!({"rows":expected.len(),
        "state_root":format!("{:x}",state.root_cell().repr_hash()),"exact_rows":!unconfirmed,"exact_rows_except_target_timestamp":unconfirmed,"exact_boc":true}))?,
    )?;
    keep_evidence(root, &report)?;
    eprintln!("State publication graph, counters and index preserved after {phase}");
    Ok(())
}

pub(super) fn generated_config(root: &Path) -> Result<Vec<u8>> {
    let bytes = fs::read(root.join("config.json"))?;
    serde_json::from_slice::<serde_json::Value>(&bytes)?;
    assert!(!bytes.is_empty());
    Ok(bytes)
}

pub(super) fn verify_generated_config(root: &Path, expected: &[u8]) -> Result<()> {
    let actual = fs::read(root.join("config.json"))?;
    let report = root.join("state-generated-config.json");
    fs::write(
        &report,
        serde_json::to_vec(&serde_json::json!({
            "bytes_before": expected.len(), "bytes_after": actual.len(),
            "sha256_before": hex::encode(rtos_block::sha256_digest(expected)),
            "sha256_after": hex::encode(rtos_block::sha256_digest(&actual)),
        }))?,
    )?;
    keep_evidence(root, &report)?;
    assert!(actual == expected, "Generated node configuration lost after recovery interruption");
    Ok(())
}
