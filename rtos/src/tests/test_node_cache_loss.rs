// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! LazyFS file-data-loss qualification and synchronous cut acknowledgement.
use super::*;
use std::io::Write;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::unix::pipe};

pub(super) fn sync_fixture(path: &Path) -> Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() { sync_fixture(&entry.path())?; }
        else if kind.is_file() { fs::File::open(entry.path())?.sync_all()?; }
        else { rtos_block::fail!("Unexpected fixture entry before cache-loss baseline"); }
    }
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

fn selection_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(root.join("node_db/archive/recovery"))? {
        let entry = entry?;
        assert!(entry.file_type()?.is_dir());
        let path = entry.path().join("selection.v1");
        if path.try_exists()? { paths.push(path); }
    }
    Ok(paths)
}

pub(super) async fn clear(root: &Path) -> Result<()> {
    let mut ready = Vec::new();
    let mut stages = 0;
    truncation_recovery::find_ready_staging(root, &mut ready, &mut stages)?;
    let mut manifests: Vec<_> = ready.into_iter().map(|path| ("ready", path)).collect();
    manifests.extend(selection_paths(root)?.into_iter().map(|path| ("selection", path)));
    let mut manifest_before = Vec::new();
    for (_, path) in &manifests {
        let bytes = fs::read(path)?;
        keep_evidence(root, path)?;
        manifest_before.push((bytes.len(), hex::encode(rtos_block::sha256_digest(&bytes))));
    }
    let control = root.join("cache-loss-control");
    let old = b"old durable data";
    let new = b"new volatile txt";
    {
        let mut file = fs::File::create(&control)?;
        file.write_all(old)?;
        file.sync_all()?;
    }
    fs::File::open(root)?.sync_all()?;
    {
        let mut file = fs::OpenOptions::new().write(true).open(&control)?;
        file.write_all(new)?;
    }
    assert_eq!(fs::read(&control)?, new, "unsynced control was not visible before cut");
    let mut completed = pipe::OpenOptions::new().read_write(true)
        .open_receiver(std::env::var("RTOS_TEST_LAZYFS_COMPLETED")?)?;
    let mut command = pipe::OpenOptions::new()
        .open_sender(std::env::var("RTOS_TEST_LAZYFS_COMMAND")?)?;
    command.write_all(b"lazyfs::clear-cache\n").await?;
    drop(command);
    let acknowledgement = tokio::time::timeout(Duration::from_secs(20), async {
        let mut acknowledgement = Vec::new();
        loop {
            let mut bytes = [0u8; 256];
            let count = completed.read(&mut bytes).await?;
            if count == 0 { rtos_block::fail!("Cache-loss completion pipe closed"); }
            acknowledgement.extend_from_slice(&bytes[..count]);
            assert!(acknowledgement.len() <= 4096, "unexpected cache-loss acknowledgement");
            if std::str::from_utf8(&acknowledgement)?.contains("finished::clear-cache") {
                return Ok::<_, rtos_block::Error>(acknowledgement);
            }
        }
    }).await??;
    assert_eq!(fs::read(&control)?, old, "cache loss did not discard unsynced overwrite");
    let mut ready_files = Vec::new();
    let mut selection_files = Vec::new();
    for ((kind, path), (length, digest)) in manifests.iter().zip(manifest_before) {
        let bytes = fs::read(path)?;
        let files = if *kind == "ready" { &mut ready_files } else { &mut selection_files };
        files.push(serde_json::json!({
            "path": path.strip_prefix(root)?, "bytes_before": length,
            "sha256_before": digest, "bytes_after": bytes.len(),
            "sha256_after": hex::encode(rtos_block::sha256_digest(&bytes)),
        }));
    }
    let report = root.join("cache-loss.json");
    fs::write(&report, serde_json::to_vec(&serde_json::json!({
        "acknowledgement": std::str::from_utf8(&acknowledgement)?,
        "unsynced_overwrite_discarded": true,
        "ready_files": ready_files,
        "selection_files": selection_files,
        "scope": "LazyFS file-data cache loss; directory metadata loss unproven"
    }))?)?;
    keep_evidence(root, &report)?;
    eprintln!("LazyFS discarded unsynced file data after actual node interruption; independent overwrite control reverted to durable bytes");
    Ok(())
}

pub(super) async fn unfinished_ready(root: &Path) -> Result<()> {
    let mut ready = Vec::new();
    let mut stages = 0;
    truncation_recovery::find_ready_staging(root, &mut ready, &mut stages)?;
    assert_eq!(ready.len(), 1);
    assert!(stages > 0, "Ready cut must follow durable replacement staging");
    let before = fs::read(&ready[0])?;
    assert!(before.len() > 28 && &before[..8] == b"RTOSAMF1");
    keep_evidence(root, &ready[0])?;
    let loss = match std::env::var("RTOS_TEST_CACHE_LOSS_ENABLED")?.as_str() {
        "1" => true,
        "0" => false,
        _ => rtos_block::fail!("Invalid cache-loss test mode"),
    };
    if loss { clear(root).await?; }
    let after = fs::read(&ready[0])?;
    if loss { assert!(after.is_empty(), "unsynced Ready bytes survived cache loss"); }
    else { assert_eq!(after, before, "no-loss control changed Ready bytes"); }
    let mut remaining = Vec::new();
    let mut remaining_stages = 0;
    truncation_recovery::find_ready_staging(root, &mut remaining, &mut remaining_stages)?;
    assert_eq!(remaining, ready);
    assert_eq!(remaining_stages, stages, "durable staged files disappeared");
    let report = root.join("ready-cache-loss.json");
    fs::write(&report, serde_json::to_vec(&serde_json::json!({
        "cache_loss": loss, "ready_bytes_before": before.len(),
        "ready_bytes_after": after.len(), "durable_stage_count": stages
    }))?)?;
    keep_evidence(root, &report)?;
    eprintln!("Unfinished Ready cache-loss={loss}: {} bytes before, {} bytes after; durable stages present", before.len(), after.len());
    Ok(())
}

pub(super) async fn unfinished_selection(root: &Path) -> Result<PathBuf> {
    let mut ready = Vec::new();
    let mut stages = 0;
    truncation_recovery::find_ready_staging(root, &mut ready, &mut stages)?;
    assert!(ready.is_empty(), "Ready exists before Selection completion");
    assert_eq!(stages, 0, "stages exist before Selection completion");
    let mut selections = selection_paths(root)?;
    assert_eq!(selections.len(), 1);
    let selection = selections.remove(0);
    let before = fs::read(&selection)?;
    assert!(before.len() > 28 && &before[..8] == b"RTOSAMF1");
    keep_evidence(root, &selection)?;
    let loss = match std::env::var("RTOS_TEST_CACHE_LOSS_ENABLED")?.as_str() {
        "1" => true,
        "0" => false,
        _ => rtos_block::fail!("Invalid cache-loss test mode"),
    };
    if loss { clear(root).await?; }
    let after = fs::read(&selection)?;
    if loss { assert!(after.is_empty(), "unsynced Selection bytes survived cache loss"); }
    else { assert_eq!(after, before, "no-loss control changed Selection bytes"); }
    let report = root.join("selection-cache-loss.json");
    fs::write(&report, serde_json::to_vec(&serde_json::json!({
        "cache_loss": loss, "selection_bytes_before": before.len(),
        "selection_bytes_after": after.len(), "ready_count": ready.len(), "stage_count": stages,
        "sha256_before": hex::encode(rtos_block::sha256_digest(&before)),
        "sha256_after": hex::encode(rtos_block::sha256_digest(&after)),
    }))?)?;
    keep_evidence(root, &report)?;
    eprintln!("Unfinished Selection cache-loss={loss}: {} bytes before, {} bytes after; no Ready or stages", before.len(), after.len());
    Ok(selection)
}

// Observe staging without opening native databases between interruption and restart.
pub(super) async fn staged_packages(root: &Path) -> Result<()> {
    fn collect(path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() { collect(&entry.path(), files)?; }
            else if entry.file_name().to_string_lossy().starts_with("stage-")
                && entry.file_name().to_string_lossy().ends_with(".pack") {
                assert!(entry.file_type()?.is_file());
                files.push(entry.path());
            }
        }
        Ok(())
    }
    let mut stages = Vec::new();
    collect(root, &mut stages)?;
    stages.sort();
    assert!(!stages.is_empty(), "published Ready must own replacement packages");
    let mut before = Vec::new();
    for path in &stages {
        let bytes = fs::read(path)?;
        assert!(!bytes.is_empty(), "empty staged package before cache loss");
        before.push((bytes.len(), rtos_block::sha256_digest(&bytes)));
        keep_evidence(root, path)?;
    }
    let loss = match std::env::var("RTOS_TEST_CACHE_LOSS_ENABLED")?.as_str() {
        "1" => true,
        "0" => false,
        _ => rtos_block::fail!("Invalid cache-loss test mode"),
    };
    if loss { clear(root).await?; }
    let mut reports = Vec::new();
    for (path, (length, digest)) in stages.iter().zip(before) {
        let bytes = fs::read(path)?;
        let after = rtos_block::sha256_digest(&bytes);
        reports.push(serde_json::json!({
            "path": path.strip_prefix(root)?, "bytes_before": length,
            "bytes_after": bytes.len(), "sha256_before": hex::encode(digest),
            "sha256_after": hex::encode(after),
        }));
        assert_eq!(bytes.len(), length, "staged package length changed");
        assert_eq!(after, digest, "staged package contents changed");
    }
    let report = root.join("stages-cache-loss.json");
    fs::write(&report, serde_json::to_vec(&serde_json::json!({
        "cache_loss": loss, "stage_files": reports,
    }))?)?;
    keep_evidence(root, &report)?;
    eprintln!("Published Ready staging cache-loss={loss}: {} replacement packages preserved byte-exactly", stages.len());
    Ok(())
}
