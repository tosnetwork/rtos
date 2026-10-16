// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Scoped syscall error simulation, not physical disk exhaustion or power loss.
use super::*;

pub(super) async fn selection_fault(binary: &Path, root: &Path, zero: &Path, mode: &str) -> Result<()> {
    let (proof, error) = match mode {
        "selection-enospc" => ("write selection.v1 after 28-byte header: ENOSPC\n", "No space left on device"),
        "selection-sync-eio" => ("fsync selection.v1 after complete manifest: EIO\n", "Input/output error"),
        _ => rtos_block::fail!("Unknown Selection fault mode"),
    };
    let source = root.join("selection-fault.c");
    let library = root.join("selection-fault.so");
    let marker = root.join(format!("{mode}.reached"));
    fs::write(&source, include_str!("node_selection_fault.c"))?;
    let compile = Command::new("cc").args(["-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(&source).arg("-o").arg(&library).output()?;
    assert!(compile.status.success(), "fault shim compile: {}", String::from_utf8_lossy(&compile.stderr));
    let path = root.join(format!("{mode}.log"));
    let log = fs::File::create(&path)?;
    let mut node = Process(Command::new(binary)
        .env("TOKIO_WORKER_THREADS", "2")
        .env("LD_PRELOAD", &library)
        .env("RTOS_TEST_SELECTION_PREFIX", format!("{}/", root.join("node_db/archive/recovery").display()))
        .env("RTOS_TEST_SELECTION_FAULT_MARKER", &marker)
        .env("RTOS_TEST_SELECTION_FAULT_MODE", mode)
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
            rtos_block::fail!("Faulted node did not stop: {}", fs::read_to_string(&path)?);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    keep_evidence(root, &path)?;
    keep_evidence(root, &source)?;
    assert_eq!(fs::read_to_string(&marker)?, proof);
    keep_evidence(root, &marker)?;
    let output = fs::read_to_string(&path)?;
    assert!(output.contains(error), "{output}");
    assert!(!output.contains("Node services started."), "{output}");
    assert!(!output.contains("Database was truncated at"), "{output}");
    let controls = root.join("node_db/archive/recovery");
    let operations = fs::read_dir(&controls)?.collect::<std::io::Result<Vec<_>>>()?;
    assert_eq!(operations.len(), 1);
    let selection = operations[0].path().join("selection.v1");
    let bytes = fs::read(&selection)?;
    if mode == "selection-enospc" {
        assert_eq!(bytes.len(), 28, "fault must stop the first body write");
    } else {
        // Independently verify complete framing, record count and body hash.
        let mut position = 28usize;
        let mut records = 0u64;
        while bytes.get(position).copied() != Some(0) {
            assert!(bytes.len().saturating_sub(position) >= 9, "short record header");
            let length = u64::from_le_bytes(bytes[position + 1..position + 9].try_into()?);
            position = position.checked_add(9).and_then(|n| n.checked_add(usize::try_from(length).ok()?))
                .ok_or_else(|| rtos_block::error!("Selection framing overflow"))?;
            assert!(position <= bytes.len(), "short record payload");
            records += 1;
        }
        assert!(records > 0);
        assert_eq!(bytes.len() - position, 41, "incomplete manifest trailer");
        assert_eq!(u64::from_le_bytes(bytes[position + 1..position + 9].try_into()?), records);
        assert_eq!(&bytes[position + 9..], &rtos_block::sha256_digest(&bytes[..position + 1]));
    }
    assert_eq!(&bytes[..8], b"RTOSAMF1");
    keep_evidence(root, &selection)?;
    eprintln!("Actual node refused startup after scoped {mode}; Selection retained for automatic recovery");
    Ok(())
}
