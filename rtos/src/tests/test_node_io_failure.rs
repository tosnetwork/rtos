// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Scoped syscall error simulation, not physical disk exhaustion or power loss.
use super::*;

pub(super) async fn selection_enospc(binary: &Path, root: &Path, zero: &Path) -> Result<()> {
    let source = root.join("selection-enospc.c");
    let library = root.join("selection-enospc.so");
    let marker = root.join("selection-enospc.reached");
    fs::write(&source, include_str!("node_selection_enospc.c"))?;
    let compile = Command::new("cc").args(["-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(&source).arg("-o").arg(&library).output()?;
    assert!(compile.status.success(), "fault shim compile: {}", String::from_utf8_lossy(&compile.stderr));
    let path = root.join("selection-enospc.log");
    let log = fs::File::create(&path)?;
    let mut node = Process(Command::new(binary)
        .env("TOKIO_WORKER_THREADS", "2")
        .env("LD_PRELOAD", &library)
        .env("RTOS_TEST_SELECTION_PREFIX", format!("{}/", root.join("node_db/archive/recovery").display()))
        .env("RTOS_TEST_SELECTION_FAULT_MARKER", &marker)
        .arg("--configs").arg(root).arg("--zerostate").arg(zero)
        .arg("--initial-sync-disabled").current_dir(root)
        .stdout(Stdio::from(log.try_clone()?)).stderr(Stdio::from(log)).spawn()?);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = node.0.try_wait()? {
            assert!(!status.success(), "faulted node unexpectedly succeeded");
            break;
        }
        if Instant::now() >= deadline {
            keep_evidence(root, &path)?;
            rtos_block::fail!("ENOSPC node did not stop: {}", fs::read_to_string(&path)?);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    keep_evidence(root, &path)?;
    keep_evidence(root, &source)?;
    assert_eq!(fs::read_to_string(&marker)?, "write selection.v1 after 28-byte header: ENOSPC\n");
    keep_evidence(root, &marker)?;
    let output = fs::read_to_string(&path)?;
    assert!(output.contains("No space left on device"), "{output}");
    assert!(!output.contains("Node services started."), "{output}");
    assert!(!output.contains("Database was truncated at"), "{output}");
    let controls = root.join("node_db/archive/recovery");
    let operations = fs::read_dir(&controls)?.collect::<std::io::Result<Vec<_>>>()?;
    assert_eq!(operations.len(), 1);
    let selection = operations[0].path().join("selection.v1");
    let bytes = fs::read(&selection)?;
    assert_eq!(bytes.len(), 28, "fault must stop the first body write");
    assert_eq!(&bytes[..8], b"RTOSAMF1");
    keep_evidence(root, &selection)?;
    eprintln!("Actual node refused startup after scoped Selection write ENOSPC; complete header retained for automatic recovery");
    Ok(())
}
