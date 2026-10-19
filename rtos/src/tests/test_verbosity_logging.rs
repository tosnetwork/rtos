/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! setVerbosity reaches what the node actually writes: the level change goes
//! through the logging backend, for a log configuration file and for the
//! default configuration. Each case runs in a child process, since logging
//! is set up once per process.

use super::*;

const CHILD: &str = "RTOS_VERBOSITY_CHILD";
const TEST: &str = "verbosity_logging_tests::verbosity_changes_what_the_node_writes";

fn run_child(scenario: &str) {
    match scenario.split_once(':') {
        Some(("file", path)) => init_logging(Some(std::path::Path::new(path))).unwrap(),
        _ => init_logging(None).unwrap(),
    }
    log::debug!("marker debug-before");
    network::control::apply_verbosity(network::control::verbosity_level(3)).unwrap();
    log::debug!("marker debug-after");
    network::control::apply_verbosity(network::control::verbosity_level(0)).unwrap();
    log::warn!("marker warn-quiet");
    log::error!("marker error-loud");
    log::logger().flush();
}

fn child(scenario: &str) -> String {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([TEST, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD, scenario)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn assert_levels(written: &str) {
    assert!(!written.contains("marker debug-before"), "{written}");
    assert!(written.contains("marker debug-after"), "{written}");
    assert!(!written.contains("marker warn-quiet"), "{written}");
    assert!(written.contains("marker error-loud"), "{written}");
}

#[test]
fn verbosity_changes_what_the_node_writes() {
    if let Ok(scenario) = std::env::var(CHILD) {
        return run_child(&scenario);
    }
    // The default configuration, on the standard output.
    assert_levels(&child("default"));
    // A log configuration file with a file appender at the info level.
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("node.log");
    let config = dir.path().join("log_cfg.yml");
    std::fs::write(
        &config,
        format!(
            "appenders:\n  file:\n    kind: file\n    path: \"{}\"\n    encoder:\n      pattern: \"{{m}}{{n}}\"\nroot:\n  level: info\n  appenders:\n    - file\n",
            log.display()
        ),
    )
    .unwrap();
    child(&format!("file:{}", config.display()));
    assert_levels(&std::fs::read_to_string(&log).unwrap());
}
