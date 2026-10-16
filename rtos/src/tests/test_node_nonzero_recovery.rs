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
        if directory == root.join("node_db") {
            let packages = directory.join("archive/packages");
            if packages.try_exists()? {
                visit(root, &packages, &mut rows)?;
            }
        } else {
            for entry in fs::read_dir(directory)? {
                let packages = entry?.path().join("archive/packages");
                if packages.try_exists()? {
                    visit(root, &packages, &mut rows)?;
                }
            }
        }
    }
    Ok(rows)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires RTOS_NODE_RECOVERY_BINARY built from this revision"]
async fn actual_node_restarts_with_nonzero_authenticated_history() -> Result<()> {
    exercise_nonzero_recovery(false, None).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires gdb and RTOS_NODE_RECOVERY_BINARY with current debug symbols"]
async fn actual_node_resumes_after_interrupting_recovery() -> Result<()> {
    exercise_nonzero_recovery(true, None).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires RTOS_NODE_RECOVERY_BINARY built from this revision"]
async fn actual_node_aborts_unstaged_building_with_nonzero_history() -> Result<()> {
    exercise_nonzero_recovery(true, Some("valid")).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires gdb and RTOS_NODE_RECOVERY_BINARY built from this revision"]
async fn actual_node_aborts_declared_building_stages_after_interruption() -> Result<()> {
    exercise_nonzero_recovery(true, Some("staged")).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires RTOS_NODE_RECOVERY_BINARY built from this revision"]
async fn actual_node_preserves_building_with_unverified_inputs() -> Result<()> {
    for case in ["bad-data", "unexpected-stage", "staged-bad-data", "staged-unknown"] {
        exercise_nonzero_recovery(false, Some(case)).await?;
    }
    Ok(())
}

async fn exercise_nonzero_recovery(interrupt_recovery: bool, building: Option<&str>) -> Result<()> {
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
    interrupt_cleaned_writer(root, building).await?;
    let before = package_inventory(root)?;
    let controls_before = recovery_file_inventory(root)?;
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
    if building.is_some_and(|case| !matches!(case, "valid" | "staged")) {
        let path = root.join("building-refused.log");
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
            if let Some(status) = node.0.try_wait()? {
                assert!(!status.success());
                break;
            }
            if Instant::now() >= deadline {
                rtos_block::fail!("Building rejection timeout: {}", fs::read_to_string(&path)?);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        keep_evidence(root, &path)?;
        let output = fs::read_to_string(&path)?;
        let expected = if building.is_some_and(|case| case.ends_with("bad-data")) {
            "Building original archive data changed"
        } else if building == Some("staged-unknown") {
            "Undeclared Building stage file"
        } else {
            "Unrecognized remaining recovery artifact"
        };
        assert!(output.contains(expected), "{output}");
        assert!(!output.contains("Node services started."));
        assert_eq!(package_inventory(root)?, before);
        assert_eq!(
            recovery_file_inventory(root)?,
            controls_before,
            "rejected recovery changed control/stage files"
        );
        let bootstrap = storage::db::node::open_node_db_for_bootstrap(
            root.join("node_db"),
            &Default::default(),
            storage::db::rocksdb::AccessType::ReadWrite,
        )?;
        assert!(bootstrap.requires_recovery());
        assert_eq!(
            bootstrap.database().db().get(b"ArchiveTruncationRootV1")?.unwrap(),
            fs::read(root.join("expected-root.bin"))?
        );
        assert_eq!(
            bootstrap.database().db().get(b"ArchiveTruncationParticipantV1")?.unwrap(),
            fs::read(root.join("expected-backlink.bin"))?
        );
        assert_eq!(
            fs::read(
                root.join("node_db/archive/recovery")
                    .join(hex::encode([0x35u8; 16]))
                    .join("selection.v1")
            )?,
            fs::read(root.join("expected-selection.bin"))?
        );
        if building == Some("unexpected-stage") {
            assert_eq!(
                fs::read(
                    root.join("node_db/archive/recovery")
                        .join(hex::encode([0x35u8; 16]))
                        .join("stage.pack")
                )?,
                b"preserve"
            );
        }
        eprintln!("Actual node rejected Building {building:?}; packages, root, backlink, selection and any unknown stage unchanged");
        return Ok(());
    }
    if interrupt_recovery {
        if building == Some("staged") {
            interrupt_actual_recovery(
                &binary,
                root,
                &zero,
                "stage-after-unlink",
                "sync_close(directory)?; // Stage removal durable before advancing Building.",
            )
            .await?;
            assert_eq!(package_inventory(root)?, before);
            let controls = recovery_file_inventory(root)?;
            assert_eq!(
                controls
                    .keys()
                    .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with("stage-"))
                    .count(),
                1,
                "cut must remove exactly the first of two present declared stages"
            );
        }
        if building.is_some() {
            interrupt_actual_recovery(
                &binary,
                root,
                &zero,
                "building-before-cleaned",
                "main.database.db().put(ROOT_KEY, cleaned.encode()?)?;",
            )
            .await?;
            assert_eq!(package_inventory(root)?, before);
        }
        for (cut, statement) in [
            ("backlink-before-sync", "participant.database.sync_wal()?;"),
            ("root-before-delete", "main.database.db().delete(ROOT_KEY)?;"),
        ] {
            interrupt_actual_recovery(&binary, root, &zero, cut, statement).await?;
            assert_eq!(package_inventory(root)?, before, "interrupted recovery changed packages");
        }
    }
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
        keep_evidence(root, &path)?;
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

async fn interrupt_cleaned_writer(root: &Path, building: Option<&str>) -> Result<()> {
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
            .env("RTOS_NONZERO_BUILDING_FIXTURE", building.unwrap_or("0"))
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

// Debugger-owned cuts leave the production executable and recovery logic unchanged.
// Every child has a private process group so a timeout also kills the inferior.
struct Debugger(Process, bool);
impl Drop for Debugger {
    fn drop(&mut self) {
        if !self.1 {
            return;
        }
        let _ = Command::new("kill")
            .args(["-KILL", "--", &format!("-{}", self.0 .0.id())])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

async fn interrupt_actual_recovery(
    binary: &Path,
    root: &Path,
    zero: &Path,
    cut: &str,
    statement: &str,
) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let source = include_str!("../../storage/src/archives/recovery_worker.rs");
    let matches: Vec<_> =
        source.lines().enumerate().filter(|(_, line)| line.trim() == statement).collect();
    assert_eq!(matches.len(), 1, "crash cut must identify one production statement");
    let line = matches[0].0 + 1;
    let function = if cut == "stage-after-unlink" {
        "recovery_worker::clean_stage"
    } else {
        "recovery_worker::recover_cleaned"
    };
    let marker = root.join(format!("cut-{cut}.reached"));
    let script = root.join(format!("cut-{cut}.gdb"));
    fs::write(
        &script,
        format!(
            r#"set pagination off
set confirm off
set breakpoint pending off
set debuginfod enabled off
break recovery_worker.rs:{line}
run
python
import gdb
frame = gdb.newest_frame()
assert frame is not None and '{function}' in frame.name(), 'wrong recovery frame'
assert frame.find_sal().line == {line}, 'wrong recovery statement'
assert gdb.selected_inferior().pid > 0, 'missing actual node'
with open({marker:?}, 'w') as output:
    output.write('actual recovery stopped at line {line} before {statement}\n')
end
kill
python
assert gdb.selected_inferior().pid == 0, 'node did not terminate'
end
quit
"#,
            marker = marker.to_string_lossy()
        ),
    )?;
    let path = root.join(format!("cut-{cut}.log"));
    let log = fs::File::create(&path)?;
    let mut debugger = Debugger(
        Process(
            Command::new("gdb")
                .args(["--batch", "-nx", "-x"])
                .arg(&script)
                .arg("--args")
                .arg(binary)
                .arg("--configs")
                .arg(root)
                .arg("--zerostate")
                .arg(zero)
                .arg("--initial-sync-disabled")
                .env("TOKIO_WORKER_THREADS", "2")
                .current_dir(root)
                .process_group(0)
                .stdout(Stdio::from(log.try_clone()?))
                .stderr(Stdio::from(log))
                .spawn()?,
        ),
        true,
    );
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(status) = debugger.0 .0.try_wait()? {
            let output = fs::read_to_string(&path)?;
            keep_evidence(root, &path)?;
            keep_evidence(root, &script)?;
            assert!(status.success(), "debugger failed at {cut}: {output}");
            assert!(marker.is_file(), "recovery cut not reached: {output}");
            assert!(output.contains("killed"), "node was not killed: {output}");
            assert!(!output.contains("Node services started."), "cut happened after startup");
            debugger.1 = false;
            eprintln!(
                "Actual node recovery interrupted at {cut}: {}",
                fs::read_to_string(&marker)?.trim()
            );
            break;
        }
        if Instant::now() >= deadline {
            rtos_block::fail!("Recovery cut {cut} timeout: {}", fs::read_to_string(&path)?);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}

fn recovery_file_inventory(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>> {
    let mut files = BTreeMap::new();
    let providers = std::iter::once(root.join("node_db"))
        .chain(fs::read_dir(root.join("epochs"))?.map(|entry| entry.unwrap().path()));
    for provider in providers {
        let directory = provider.join("archive/recovery").join(hex::encode([0x35u8; 16]));
        if !directory.try_exists()? {
            continue;
        }
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            files.insert(path.strip_prefix(root)?.to_owned(), fs::read(path)?);
        }
    }
    Ok(files)
}

fn keep_evidence(root: &Path, path: &Path) -> Result<()> {
    if let Some(evidence) = std::env::var_os("RTOS_NODE_RECOVERY_EVIDENCE_DIR") {
        let evidence = PathBuf::from(evidence).join(root.file_name().expect("fixture root"));
        fs::create_dir_all(&evidence)?;
        fs::copy(path, evidence.join(path.file_name().expect("evidence filename")))?;
    }
    Ok(())
}
