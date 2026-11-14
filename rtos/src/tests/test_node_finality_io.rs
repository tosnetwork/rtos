// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Exact source acknowledgement file failures in the production startup path.
use super::*;

pub(super) async fn refuse(binary: &Path, root: &Path, zero: &Path, mode: &str) -> Result<()> {
    assert!(matches!(mode, "write-enospc" | "sync-eio"));
    let sources = finality_recovery::source_inventory(root)?;
    let pending: Vec<_> =
        sources.keys().filter(|p| p.extension().is_some_and(|e| e == "json")).collect();
    assert_eq!(pending.len(), 1);
    let pending = root.join(pending[0]);
    let original = fs::read(&pending)?;
    let target = pending.with_extension("ack.tmp");
    assert!(!target.exists());
    use std::os::unix::process::CommandExt;
    let source = root.join("source-io-fault.c");
    let library = root.join("source-io-fault.so");
    let arm = root.join("source-io.arm");
    let proof = root.join("source-io.reached");
    let exit = root.join("source-io.exit");
    fs::write(&source, include_str!("finality_source_fault.c"))?;
    let built = Command::new("cc")
        .args(["-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(&source)
        .arg("-o")
        .arg(&library)
        .output()?;
    assert!(built.status.success(), "{}", String::from_utf8_lossy(&built.stderr));
    let code = include_str!("../validator/session_publication.rs");
    let lines: Vec<_> = code
        .lines()
        .enumerate()
        .filter(|(_, line)| line.trim() == "source.acknowledge(receipt)")
        .collect();
    assert_eq!(lines.len(), 1, "source acknowledgement must identify one production statement");
    let line = lines[0].0 + 1;
    let script = root.join("source-io.gdb");
    fs::write(
        &script,
        format!(
            r#"set pagination off
set confirm off
set breakpoint pending off
set debuginfod enabled off
set environment LD_PRELOAD {library}
python
exits = []
gdb.events.exited.connect(lambda event: exits.append(event.exit_code))
end
break session_publication.rs:{line}
run
python
frame = gdb.newest_frame()
assert frame is not None and 'session_publication::recover_retained_finality' in frame.name(), 'wrong source acknowledgement frame'
assert frame.find_sal().line == {line}, 'wrong source acknowledgement statement'
assert gdb.selected_inferior().pid > 0, 'missing actual node'
with open({arm:?}, 'x') as output:
    output.write('armed at verified source acknowledgement\n')
print('Exact actual-node source acknowledgement armed')
end
delete breakpoints
continue
python
assert gdb.selected_inferior().pid == 0, 'failed startup node still alive'
assert len(exits) == 1 and isinstance(exits[0], int) and exits[0] > 0, 'startup did not return an error exit'
with open({exit:?}, 'x') as output:
    output.write(str(exits[0]))
end
quit
"#,
            library = library.display(),
            arm = arm.to_string_lossy(),
            exit = exit.to_string_lossy()
        ),
    )?;
    let path = root.join("source-io.log");
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
                .args(forced_cursor_fixture_args(root))
                .env("TOKIO_WORKER_THREADS", "2")
                .env("RTOS_TEST_SOURCE_FAULT_FILE", &target)
                .env("RTOS_TEST_SOURCE_FAULT_MODE", mode)
                .env("RTOS_TEST_SOURCE_FAULT_ARM", &arm)
                .env("RTOS_TEST_SOURCE_FAULT_MARKER", &proof)
                .current_dir(root)
                .process_group(0)
                .stdout(Stdio::from(log.try_clone()?))
                .stderr(Stdio::from(log))
                .spawn()?,
        ),
        true,
    );
    let deadline = Instant::now() + Duration::from_secs(90);
    let status = loop {
        if let Some(status) = debugger.0 .0.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            keep_evidence(root, &path)?;
            rtos_block::fail!(
                "Source acknowledgement error did not terminate the node: {}",
                fs::read_to_string(&path)?
            );
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    for artifact in [&source, &library, &script, &path] {
        keep_evidence(root, artifact)?;
    }
    assert!(status.success(), "{}", fs::read_to_string(&path)?);
    let code: u32 = fs::read_to_string(&exit)?.parse()?;
    assert!(code > 0);
    debugger.1 = false;
    let marker = fs::read_to_string(&proof)?;
    assert_eq!(marker.lines().count(), 1);
    assert_eq!(marker.trim_end(), format!("source {mode}: {}", target.display()));
    for artifact in [&arm, &proof, &exit] {
        keep_evidence(root, artifact)?;
    }
    let output = fs::read_to_string(&path)?;
    assert!(output.contains("Exact actual-node source acknowledgement armed"));
    assert!(output.contains(if mode == "sync-eio" {
        "Input/output error"
    } else {
        "No space left on device"
    }));
    assert!(!output.contains("Node services started."), "source IO failure was ignored");
    assert_eq!(fs::read(&pending)?, original, "failed source ACK changed retained finality");
    assert!(!pending.with_extension("acked").exists(), "failed source ACK was published");
    let temporary_bytes = fs::metadata(&target)?.len();
    assert_eq!(temporary_bytes > 0, mode == "sync-eio");
    let report = root.join("source-io-refusal.json");
    fs::write(
        &report,
        serde_json::to_vec(&serde_json::json!({"node_exit":code,
        "native_hits":1,"services_started":false,"source_line":line,"mode":mode,
        "source_acknowledged":false,"source_preserved":true,"temporary_bytes":temporary_bytes}))?,
    )?;
    keep_evidence(root, &report)?;
    eprintln!("Actual node refused startup after source {mode}");
    Ok(())
}
