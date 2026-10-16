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

pub(super) async fn clear(root: &Path) -> Result<()> {
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
    let report = root.join("cache-loss.json");
    fs::write(&report, serde_json::to_vec(&serde_json::json!({
        "acknowledgement": std::str::from_utf8(&acknowledgement)?,
        "unsynced_overwrite_discarded": true,
        "scope": "LazyFS file-data cache loss; directory metadata loss unproven"
    }))?)?;
    keep_evidence(root, &report)?;
    eprintln!("LazyFS discarded unsynced file data after actual node interruption; independent overwrite control reverted to durable bytes");
    Ok(())
}
