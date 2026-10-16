// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Persistent snapshot producers followed by actual executable recovery.
use super::*;
use std::sync::Arc;
use storage::{db::DbKey, types::{PersistentStatePartId, PersistentStatePartKey}};

pub(super) fn part(mode: &str) -> PersistentStatePartId {
    let id = Fixture::node_recovery().id(3, false);
    if mode == "head" { PersistentStatePartId::Head(id) } else { PersistentStatePartId::WholeState(id) }
}
pub(super) fn path(root: &Path, mode: &str) -> PathBuf {
    let key = PersistentStatePartKey::from(&part(mode));
    let name = hex::encode(key.key());
    root.join("node_db/shard_state_persistent_db").join(&name[..4]).join(&name[4..])
}
pub(super) fn ack_path(root: &Path, mode: &str) -> PathBuf { root.join(format!("persistent-{mode}-ack.json")) }

#[tokio::test]
#[ignore = "internal child; requires owned persistent snapshot fixture"]
async fn persistent_child() -> Result<()> {
    let root = PathBuf::from(std::env::var("RTOS_TEST_PERSISTENT_CHILD_ROOT")?);
    let mode = std::env::var("RTOS_TEST_PERSISTENT_MODE")?;
    let db = open_db(&root).await?;
    let id = Fixture::node_recovery().id(3, false);
    let handle = db.load_block_handle(&id)?.unwrap();
    assert!(!handle.has_persistent_state()); assert!(!path(&root, &mode).try_exists()?);
    let state = db.load_shard_state_dynamic(&id)?;
    match mode.as_str() {
        "fast" => db.store_shard_state_persistent_part_fast(&handle, &part(&mode), state.root_cell().clone(), Arc::new(|| false)).await?,
        "head" | "whole" => db.store_shard_state_persistent_part(&handle, &part(&mode), state.root_cell().clone(), None, Arc::new(|| false)).await?,
        "raw" => db.store_shard_state_persistent_raw(&handle, &rtos_block::write_boc(state.root_cell())?, None).await?,
        _ => rtos_block::fail!("Unknown persistent producer"),
    }
    // Drain metadata only. Never sync the snapshot on behalf of its producer.
    db.sync_publication_metadata(&handle).await?;
    let bytes = fs::read(path(&root, &mode))?;
    assert!(!bytes.is_empty());
    assert_eq!(rtos_block::read_single_root_boc(&bytes)?.repr_hash(), state.root_cell().repr_hash());
    assert!(handle.has_persistent_state());
    let ack = ack_path(&root, &mode);
    fs::write(&ack, serde_json::to_vec(&serde_json::json!({"mode": mode,
        "bytes": hex::encode(bytes), "state_root": format!("{:x}", state.root_cell().repr_hash()),
        "persistent_flag": true, "metadata_synced": true,
    }))?)?; fs::File::open(&ack)?.sync_all()?;
    loop { tokio::time::sleep(Duration::from_secs(1)).await; }
}

pub(super) async fn write_and_interrupt(root: &Path, mode: &str) -> Result<()> {
    cache_loss::sync_fixture(root)?;
    let log_path = root.join(format!("persistent-{mode}-child.log"));
    let log = fs::File::create(&log_path)?;
    let mut child = Process(Command::new(std::env::current_exe()?)
        .args(["--exact", "--ignored", "--nocapture", "--test-threads=1",
            "archive_import::tests::node_process_recovery::truncation_recovery::persistent_cache_loss::persistent_child"])
        .env("RTOS_TEST_PERSISTENT_CHILD_ROOT", root).env("RTOS_TEST_PERSISTENT_MODE", mode)
        .stdout(Stdio::from(log.try_clone()?)).stderr(Stdio::from(log)).spawn()?);
    let deadline = Instant::now() + Duration::from_secs(60);
    let ack = ack_path(root, mode);
    let expected = loop {
        if let Ok(bytes) = fs::read(&ack) {
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                assert_eq!(value["mode"], mode); assert_eq!(value["metadata_synced"], true);
                break hex::decode(value["bytes"].as_str().unwrap())?;
            }
        }
        if let Some(status) = child.0.try_wait()? {
            keep_evidence(root, &log_path)?;
            rtos_block::fail!("Persistent producer exited before acknowledgement: {status}");
        }
        if Instant::now() >= deadline { keep_evidence(root, &log_path)?; rtos_block::fail!("Persistent acknowledgement timeout"); }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(fs::read(path(root, mode))?, expected);
    assert!(child.0.try_wait()?.is_none()); child.0.kill()?;
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(child.0.wait()?.signal(), Some(9));
    keep_evidence(root, &log_path)?; keep_evidence(root, &ack)?;
    let loss = match std::env::var("RTOS_TEST_CACHE_LOSS_ENABLED")?.as_str() {
        "1" => true, "0" => false, _ => rtos_block::fail!("Invalid cache-loss mode"),
    };
    if loss { cache_loss::clear(root).await?; }
    let actual = fs::read(path(root, mode))?;
    let report = root.join(format!("persistent-{mode}-cache-loss.json"));
    fs::write(&report, serde_json::to_vec(&serde_json::json!({"mode":mode,"cache_loss":loss,
        "path":path(root,mode).strip_prefix(root)?, "bytes_before":expected.len(), "bytes_after":actual.len(),
        "sha256_before":hex::encode(rtos_block::sha256_digest(&expected)),
        "sha256_after":hex::encode(rtos_block::sha256_digest(&actual)),
    }))?)?; keep_evidence(root, &report)?;
    eprintln!("Acknowledged persistent {mode} writer killed without native close; cache-loss={loss}");
    Ok(())
}

pub(super) async fn verify(root: &Path, db: &InternalDb, mode: &str, phase: &str) -> Result<()> {
    let ack: serde_json::Value = serde_json::from_slice(&fs::read(ack_path(root, mode))?)?;
    let expected = hex::decode(ack["bytes"].as_str().unwrap())?;
    let actual = fs::read(path(root, mode))?;
    let handle = db.load_block_handle(&Fixture::node_recovery().id(3, false))?.unwrap();
    let report = root.join(format!("persistent-{mode}-{phase}.json"));
    fs::write(&report, serde_json::to_vec(&serde_json::json!({"bytes_expected":expected.len(),
        "bytes_actual":actual.len(), "sha256_expected":hex::encode(rtos_block::sha256_digest(&expected)),
        "sha256_actual":hex::encode(rtos_block::sha256_digest(&actual)),"persistent_flag":handle.has_persistent_state(),
    }))?)?; keep_evidence(root, &report)?;
    assert_eq!(actual, expected, "Acknowledged persistent snapshot lost after actual node restart");
    assert!(handle.has_persistent_state(), "Published persistent snapshot flag lost");
    assert_eq!(format!("{:x}",rtos_block::read_single_root_boc(&actual)?.repr_hash()),ack["state_root"].as_str().unwrap());
    assert_eq!(db.load_shard_state_persistent_size(&part(mode)).await?,actual.len() as u64);
    assert_eq!(db.load_shard_state_persistent_slice(&part(mode),0,actual.len() as u64).await?,actual);
    eprintln!("Persistent {mode} snapshot bytes, root, metadata and reads preserved after {phase}");
    Ok(())
}
