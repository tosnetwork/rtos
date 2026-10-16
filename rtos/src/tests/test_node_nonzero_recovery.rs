// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Actual executable restart with authenticated nonzero MC and WC history.
use super::*;
use std::{
    collections::BTreeMap,
    fs,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn package_inventory(root: &Path) -> Result<BTreeMap<PathBuf, [u8; 32]>> {
    fn visit(root: &Path, dir: &Path, rows: &mut BTreeMap<PathBuf, [u8; 32]>) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                visit(root, &entry.path(), rows)?;
            } else if entry.path().extension().is_some_and(|ext| ext == "pack") {
                rows.insert(
                    entry.path().strip_prefix(root)?.to_owned(),
                    rtos_block::sha256_digest(fs::read(entry.path())?),
                );
            }
        }
        Ok(())
    }
    let mut rows = BTreeMap::new();
    for directory in [root.join("node_db"), root.join("epochs")] {
        visit(root, &directory, &mut rows)?;
    }
    Ok(rows)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires RTOS_NODE_RECOVERY_BINARY built from this revision"]
async fn actual_node_restarts_with_nonzero_authenticated_history() -> Result<()> {
    let binary = fs::canonicalize(std::env::var("RTOS_NODE_RECOVERY_BINARY")?)?;
    let dir = tempfile::tempdir()?;
    let root = dir.path();
    let fixture = Fixture::node_recovery();
    let archives = root.join("archives");
    fixture.prepare(root, &archives).await?;
    let physical = run_import(fixture.config(root, archives)).await?;
    tokio::time::timeout(Duration::from_secs(60), wait_for_db_release(physical)).await?;
    let db = open_db(root).await?;
    fixture.assert_imported(&db, 4).await?;
    let (physical, catchain) = db.sst_databases_for_test();
    drop(catchain);
    db.stop_states_db().await?;
    drop(db);
    tokio::time::timeout(Duration::from_secs(30), wait_for_db_release(physical)).await?;
    interrupt_cleaned_writer(root).await?;
    let before = package_inventory(root)?;
    assert!(!before.is_empty(), "node fixture must contain canonical archive packages");

    let global_path = root.join("authenticated-global.json");
    let mut global: serde_json::Value = serde_json::from_slice(&fs::read(&global_path)?)?;
    global["dht"]["static_nodes"]["nodes"] = serde_json::json!([]);
    global["liteservers"] = serde_json::json!([]);
    fs::write(&global_path, serde_json::to_vec(&global)?)?;
    let zero = root.join("zero");
    fs::create_dir(&zero)?;
    for (wc, name) in [(false, "authenticated-mc-zero.boc"), (true, "authenticated-wc-zero.boc")] {
        fs::copy(
            root.join(name),
            zero.join(format!("{}.boc", fixture.id(0, wc).file_hash.as_hex_string())),
        )?;
    }
    let adnl = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let quic = std::net::UdpSocket::bind("127.0.0.1:0")?;
    fs::write(
        root.join("default_config.json"),
        serde_json::to_vec(&serde_json::json!({
            "log_config_name": "node-log.yml",
            "ton_global_config_name": "authenticated-global.json",
            "internal_db_path": root.join("node_db"),
            "ip_address": adnl.local_addr()?.to_string(),
            "ip_address_quic": quic.local_addr()?.to_string(),
            "boot_from_zerostate": true,
            "restore_db": true,
            "archival_mode": {"epoch_size": 20000, "new_epochs_path": root.join("epochs"), "existing_epochs": []}
        }))?,
    )?;
    drop((adnl, quic));
    fs::write(root.join("node-log.yml"), "appenders:\n  console:\n    kind: console\n    encoder:\n      pattern: '{m}{n}'\nroot:\n  level: info\n  appenders: [console]\n")?;
    for attempt in 0..2 {
        let path = root.join(format!("node-{attempt}.log"));
        let log = fs::File::create(&path)?;
        let mut node = Process(
            Command::new(&binary)
                .env("TOKIO_WORKER_THREADS", "2")
                .arg("--configs")
                .arg(root)
                .arg("--zerostate")
                .arg(&zero)
                .arg("--initial-sync-disabled")
                .current_dir(root)
                .stdout(Stdio::from(log.try_clone()?))
                .stderr(Stdio::from(log))
                .spawn()?,
        );
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let output = fs::read_to_string(&path)?;
            if let Some(status) = node.0.try_wait()? {
                rtos_block::fail!("Node attempt {attempt} exited {status}: {output}");
            }
            if output.contains("Node services started.") {
                break;
            }
            if Instant::now() >= deadline {
                rtos_block::fail!("Node attempt {attempt} startup timeout: {output}");
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        node.0.kill()?;
        assert!(!node.0.wait()?.success());
        eprintln!(
            "Nonzero node attempt {attempt}: services started at imported height 4, then SIGKILL"
        );
        // The next actual process must itself open and recover the database.
    }
    assert_eq!(package_inventory(root)?, before, "restart changed canonical package bytes");
    let db = open_db(root).await?;
    fixture.assert_imported(&db, 4).await?;
    let (physical, catchain) = db.sst_databases_for_test();
    assert!(physical.db().get(b"ArchiveTruncationRootV1")?.is_none());
    assert!(physical.db().get(b"ArchiveTruncationParticipantV1")?.is_none());
    drop((physical, catchain));
    for provider in std::iter::once(root.join("node_db"))
        .chain(fs::read_dir(root.join("epochs"))?.map(|entry| entry.unwrap().path()))
    {
        assert!(!provider.join("archive/recovery").join(hex::encode([0x35u8; 16])).exists());
    }
    db.stop_states_db().await?;
    eprintln!("All MC/WC blocks, proofs, state roots, indexes and four progress cursors remain consistent through height 4");
    Ok(())
}

#[path = "test_node_recovery_root_fixture.rs"]
mod pending_root;

#[test]
#[ignore = "child process fixture"]
fn nonzero_cleaned_crash_writer() -> Result<()> {
    pending_root::write_and_hold(Path::new(&std::env::var("RTOS_NONZERO_CLEANED_FIXTURE")?))
}

async fn interrupt_cleaned_writer(root: &Path) -> Result<()> {
    let log_path = root.join("cleaned-writer.log");
    let log = fs::File::create(&log_path)?;
    let mut writer = Process(
        Command::new(std::env::current_exe()?)
            .args([
                "--ignored",
                "--exact",
                "archive_import::tests::node_process_recovery::nonzero_cleaned_crash_writer",
                "--nocapture",
            ])
            .env("RTOS_NONZERO_CLEANED_FIXTURE", root)
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while !root.join("cleaned-ready").exists() {
        if let Some(status) = writer.0.try_wait()? {
            rtos_block::fail!("Cleaned writer {status}: {}", fs::read_to_string(&log_path)?);
        }
        if Instant::now() >= deadline {
            rtos_block::fail!("Cleaned writer timeout: {}", fs::read_to_string(&log_path)?);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    writer.0.kill()?;
    assert!(!writer.0.wait()?.success());
    Ok(())
}
