// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Exact native sync EIO, interruption and retry across actual node recovery.
use super::*;
use std::sync::Arc;
use super::persistent_cache_loss::{part, path, ack_path};

async fn store(db: &InternalDb, mode: &str) -> Result<()> {
    let id = Fixture::node_recovery().id(3, false);
    let handle = db.load_block_handle(&id)?.unwrap();
    let state = db.load_shard_state_dynamic(&id)?;
    match mode {
        "fast" => db.store_shard_state_persistent_part_fast(&handle, &part(mode), state.root_cell().clone(), Arc::new(|| false)).await,
        "head" | "whole" => db.store_shard_state_persistent_part(&handle, &part(mode), state.root_cell().clone(), None, Arc::new(|| false)).await,
        "raw" => db.store_shard_state_persistent_raw(&handle, &rtos_block::write_boc(state.root_cell())?, None).await,
        _ => rtos_block::fail!("Unknown persistent producer"),
    }
}
fn snapshot(root: &Path, mode: &str) -> Result<Option<String>> {
    let path = path(root, mode);
    Ok(if path.try_exists()? { Some(hex::encode(fs::read(path)?)) } else { None })
}
fn failure_path(root: &Path) -> PathBuf { root.join("persistent-failure.json") }

#[tokio::test]
#[ignore = "internal child; requires owned persistent failure fixture"]
async fn failure_child() -> Result<()> {
    let root=PathBuf::from(std::env::var("RTOS_TEST_PERSISTENT_CHILD_ROOT")?);
    let mode=std::env::var("RTOS_TEST_PERSISTENT_MODE")?;
    let phase=std::env::var("RTOS_TEST_PERSISTENT_PHASE")?;
    let db=open_db(&root).await?;
    let id=Fixture::node_recovery().id(3,false);
    let handle=db.load_block_handle(&id)?.unwrap();
    assert!(!handle.has_persistent_state()); assert!(snapshot(&root,&mode)?.is_none());
    let result=store(&db,&mode).await;
    let proof=fs::read_to_string(std::env::var("RTOS_TEST_PERSISTENT_MARKER")?)?;
    assert_eq!(proof.lines().count(),1);
    let expected_target=path(&root,&mode);
    if phase=="file" { assert!(proof.starts_with(&format!("file sync EIO: {}.",expected_target.display()))); }
    else { assert_eq!(proof,format!("directory sync EIO: {}\n",expected_target.parent().unwrap().display())); }
    let error=result.expect_err("Persistent producer acknowledged failed native sync");
    assert!(format!("{error:#}").contains("Input/output error"));
    assert!(!handle.has_persistent_state(),"Failed sync published persistent flag");
    let actual=snapshot(&root,&mode)?;
    if phase=="file" { assert!(actual.is_none(),"File published before successful contents sync"); }
    else {
        let bytes=hex::decode(actual.as_ref().unwrap())?;
        assert_eq!(rtos_block::read_single_root_boc(&bytes)?.repr_hash(),db.load_shard_state_dynamic(&id)?.root_cell().repr_hash());
    }
    fs::write(failure_path(&root),serde_json::to_vec(&serde_json::json!({
        "mode":mode,"phase":phase,"acknowledged":false,"persistent_flag":false,
        "snapshot":actual,"error":format!("{error:#}"),"sync_proof":proof,
    }))?)?; fs::File::open(failure_path(&root))?.sync_all()?;
    loop { tokio::time::sleep(Duration::from_secs(1)).await; }
}

pub(super) async fn write_and_interrupt(root: &Path, mode: &str, phase: &str) -> Result<()> {
    cache_loss::sync_fixture(root)?;
    let source=root.join("persistent-sync-fault.c");let library=root.join("persistent-sync-fault.so");
    fs::write(&source,include_str!("persistent_sync_fault.c"))?;
    let compile=Command::new("cc").args(["-shared","-fPIC","-O2","-Wall","-Wextra","-Werror"])
        .arg(&source).arg("-o").arg(&library).output()?;
    assert!(compile.status.success(),"{}",String::from_utf8_lossy(&compile.stderr));
    let marker=root.join("persistent-sync-fault.reached");
    let log_path=root.join("persistent-failure-child.log");let log=fs::File::create(&log_path)?;
    let mut child=Process(Command::new(std::env::current_exe()?)
        .args(["--exact","--ignored","--nocapture","--test-threads=1",
            "archive_import::tests::node_process_recovery::truncation_recovery::persistent_failure::failure_child"])
        .env("LD_PRELOAD",&library).env("RTOS_TEST_PERSISTENT_CHILD_ROOT",root)
        .env("RTOS_TEST_PERSISTENT_MODE",mode).env("RTOS_TEST_PERSISTENT_PHASE",phase)
        .env("RTOS_TEST_PERSISTENT_TARGET",path(root,mode)).env("RTOS_TEST_PERSISTENT_MARKER",&marker)
        .stdout(Stdio::from(log.try_clone()?)).stderr(Stdio::from(log)).spawn()?);
    let deadline=Instant::now()+Duration::from_secs(60);
    loop {
        if fs::read(failure_path(root)).ok().and_then(|b|serde_json::from_slice::<serde_json::Value>(&b).ok()).is_some() { break; }
        if let Some(status)=child.0.try_wait()? {
            keep_evidence(root,&source)?;keep_evidence(root,&log_path)?;
            if marker.try_exists()? { keep_evidence(root,&marker)?; }
            rtos_block::fail!("Persistent failure child exited before refusal receipt: {status}");
        }
        if Instant::now()>=deadline { keep_evidence(root,&log_path)?;rtos_block::fail!("Persistent refusal receipt timeout"); }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(child.0.try_wait()?.is_none());child.0.kill()?;
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(child.0.wait()?.signal(),Some(9));
    for p in [&source,&library,&log_path,&marker,&failure_path(root)] { keep_evidence(root,p)?; }
    let loss=match std::env::var("RTOS_TEST_CACHE_LOSS_ENABLED")?.as_str() {"1"=>true,"0"=>false,_=>rtos_block::fail!("Invalid cache-loss mode")};
    if loss { cache_loss::clear(root).await?; }
    eprintln!("Failed persistent {mode}-{phase} writer killed without native close; cache-loss={loss}");
    Ok(())
}

pub(super) async fn verify_and_retry(root: &Path, db: &InternalDb, mode: &str, phase: &str) -> Result<()> {
    let failed:serde_json::Value=serde_json::from_slice(&fs::read(failure_path(root))?)?;
    assert_eq!(failed["acknowledged"],false); assert_eq!(failed["mode"],mode);assert_eq!(failed["phase"],phase);
    let id=Fixture::node_recovery().id(3,false);let handle=db.load_block_handle(&id)?.unwrap();
    assert!(!handle.has_persistent_state(),"Failed sync became published after actual startup");
    let actual=snapshot(root,mode)?;
    assert_eq!(serde_json::json!(actual),failed["snapshot"],"Unacknowledged snapshot changed after restart");
    let report=root.join("persistent-failure-guarded-startup.json");
    fs::write(&report,serde_json::to_vec(&serde_json::json!({"mode":mode,"phase":phase,"persistent_flag":false,"snapshot":actual}))?)?;
    keep_evidence(root,&report)?;
    store(db,mode).await?;db.sync_publication_metadata(&handle).await?;
    let bytes=fs::read(path(root,mode))?;let state=db.load_shard_state_dynamic(&id)?;
    assert!(handle.has_persistent_state());
    assert_eq!(rtos_block::read_single_root_boc(&bytes)?.repr_hash(),state.root_cell().repr_hash());
    let ack=ack_path(root,mode);
    fs::write(&ack,serde_json::to_vec(&serde_json::json!({"mode":mode,"bytes":hex::encode(bytes),
        "state_root":format!("{:x}",state.root_cell().repr_hash()),"persistent_flag":true,"metadata_synced":true}))?)?;
    fs::File::open(&ack)?.sync_all()?;keep_evidence(root,&ack)?;
    persistent_cache_loss::verify(root,db,mode,"retry").await?;
    eprintln!("Persistent {mode}-{phase} EIO refused publication; cold retry acknowledged");
    Ok(())
}
