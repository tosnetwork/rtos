// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Exact native WAL failure at the actual executable's startup state barrier.
use super::*;

pub(super) async fn refuse(
    binary: &Path,
    root: &Path,
    zero: &Path,
    unconfirmed: bool,
) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let source = root.join("startup-sync-fault.c");
    let library = root.join("startup-sync-fault.so");
    let arm = root.join("startup-sync.arm");
    let proof = root.join("startup-sync.reached");
    let exit = root.join("startup-sync.exit");
    fs::write(&source, include_str!("state_sync_fault.c"))?;
    let built = Command::new("cc")
        .args(["-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(&source)
        .arg("-o")
        .arg(&library)
        .output()?;
    assert!(built.status.success(), "{}", String::from_utf8_lossy(&built.stderr));
    let code = include_str!("../shard_states_keeper.rs");
    let lines: Vec<_> = code
        .lines()
        .enumerate()
        .filter(|(_, line)| line.trim() == "self.db.sync_publication_state().await?;")
        .collect();
    assert_eq!(lines.len(), 1, "startup barrier must identify one production statement");
    let line = lines[0].0 + 1;
    let script = root.join("startup-sync.gdb");
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
break shard_states_keeper.rs:{line}
run
python
frame = gdb.newest_frame()
assert frame is not None and 'shard_states_keeper' in frame.name() and 'start' in frame.name(), 'wrong startup barrier frame'
assert frame.find_sal().line == {line}, 'wrong startup barrier statement'
assert gdb.selected_inferior().pid > 0, 'missing actual node'
with open({arm:?}, 'x') as output:
    output.write('armed at verified startup state barrier\n')
print('Exact actual-node startup state barrier armed')
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
    let path = root.join("startup-sync.log");
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
                .env("RTOS_TEST_STATE_FAULT_PREFIX", format!("{}/node_db/db/", root.display()))
                .env("RTOS_TEST_ROOT_WAL_ARM", &arm)
                .env("RTOS_TEST_STATE_FAULT_MARKER", &proof)
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
                "Startup barrier error did not terminate the node: {}",
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
    assert!(marker.starts_with(&format!("state WAL sync EIO: {}/node_db/db/", root.display())));
    assert!(marker.trim_end().ends_with(".log"));
    for artifact in [&arm, &proof, &exit] {
        keep_evidence(root, artifact)?;
    }
    let output = fs::read_to_string(&path)?;
    assert!(output.contains("Exact actual-node startup state barrier armed"));
    assert!(output.contains("Input/output error"));
    assert!(!output.contains("Node services started."), "startup barrier error was ignored");
    let reconstructed =
        unconfirmed && std::env::var("RTOS_TEST_CACHE_LOSS_ENABLED")?.as_str() == "1";
    if reconstructed {
        assert!(
            output.contains(&format!(
                "Can't load state for {} from DB, but handle.has_saved_state() == true",
                Fixture::node_recovery().id(3, false)
            )),
            "Startup barrier failure did not follow actual missing-state recovery"
        );
    }
    let report = root.join("startup-sync-refusal.json");
    fs::write(
        &report,
        serde_json::to_vec(&serde_json::json!({"node_exit":code,
        "native_hits":1,"services_started":false,"source_line":line,"state_reconstructed_before_fault":reconstructed}))?,
    )?;
    keep_evidence(root, &report)?;
    eprintln!("Actual node refused services after exact startup state WAL sync EIO");
    Ok(())
}
