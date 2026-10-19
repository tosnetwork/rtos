/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Process-level exit statuses of the node binary: 2 for a refused option,
//! configuration or configuration lock, 1 for a failure after the
//! configuration was accepted, 0 for version, a created configuration and
//! `--process-conf-and-exit`, and termination by the stop signal itself.

use std::{
    fs,
    os::unix::{io::AsRawFd, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

const NODE: &str = env!("CARGO_BIN_EXE_rtos");
const GLOBAL_SAMPLE: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/configs/ton-global.config-sample.json");

fn run(dir: &Path, args: &[&str]) -> (ExitStatus, String) {
    let output = Command::new(NODE)
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::null())
        .output()
        .expect("node binary runs");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status, text)
}

fn run_configs(dir: &Path, extra: &[&str]) -> (ExitStatus, String) {
    let mut args = vec!["--configs", dir.to_str().unwrap()];
    args.extend_from_slice(extra);
    run(dir, &args)
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A default configuration the node turns into config.json on its first run.
fn write_default(dir: &Path, db: &str, global: bool) {
    let mut value = serde_json::json!({
        "ip_address": format!("127.0.0.1:{}", free_udp_port()),
        "internal_db_path": db,
    });
    if global {
        fs::copy(GLOBAL_SAMPLE, dir.join("global.json")).unwrap();
        value["ton_global_config_name"] = "global.json".into();
    }
    fs::write(dir.join("default_config.json"), value.to_string()).unwrap();
}

fn generate(dir: &Path) {
    let (status, text) = run_configs(dir, &[]);
    assert_eq!(status.code(), Some(0), "{text}");
    assert!(dir.join("config.json").exists());
}

/// Holds an fcntl write lock on the whole file, as the node does.
struct RecordLock(fs::File);

impl RecordLock {
    fn take(path: &Path) -> Self {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .unwrap();
        // SAFETY: flock is a plain C structure; zeroed is a valid initial value.
        let mut lock: libc::flock = unsafe { std::mem::zeroed() };
        lock.l_type = libc::F_WRLCK as _;
        lock.l_whence = libc::SEEK_SET as _;
        // SAFETY: the descriptor is open and the structure outlives the call.
        assert_eq!(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &lock) }, 0);
        Self(file)
    }
}

#[test]
fn options_exit_like_the_reference_engine() {
    let dir = tempfile::tempdir().unwrap();
    let (status, _) = run(dir.path(), &["--no-such-option"]);
    assert_eq!(status.code(), Some(2));
    let (status, text) = run(dir.path(), &["-h"]);
    assert_eq!(status.code(), Some(2), "help exits 2: {text}");
    let (status, _) = run(dir.path(), &["-V"]);
    assert_eq!(status.code(), Some(0));
    let (status, _) = run_configs(dir.path(), &["--truncate-db", "x"]);
    assert_eq!(status.code(), Some(2));
}

#[test]
fn missing_or_malformed_configuration_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    let (status, text) = run_configs(dir.path(), &[]);
    assert_eq!(status.code(), Some(2), "no config.json and no default: {text}");

    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("config.json"), "{").unwrap();
    let (status, text) = run_configs(dir.path(), &[]);
    assert_eq!(status.code(), Some(2), "malformed config.json: {text}");
}

#[test]
fn processing_a_valid_configuration_exits_0() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("config.json"), "{}").unwrap();
    let (status, text) = run_configs(dir.path(), &["--process-conf-and-exit"]);
    assert_eq!(status.code(), Some(0), "{text}");
}

#[test]
fn creating_the_configuration_exits_0_without_starting_the_engine() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("db");
    write_default(dir.path(), db.to_str().unwrap(), false);
    let (status, text) = run_configs(dir.path(), &[]);
    assert_eq!(status.code(), Some(0), "{text}");
    assert!(text.contains("created config file"), "{text}");
    assert!(!text.contains("Engine::run"), "the engine must not start: {text}");
    assert!(dir.path().join("config.json").exists());
    assert!(!db.exists(), "the engine must not open its database");
    // The next run reads the file it created instead of creating it again.
    let (status, text) = run_configs(dir.path(), &["--process-conf-and-exit"]);
    assert_eq!(status.code(), Some(0), "{text}");
    assert!(!text.contains("created config file"), "{text}");
}

#[test]
fn a_created_configuration_grants_the_console_client_every_permission() {
    let dir = tempfile::tempdir().unwrap();
    let mut value = serde_json::json!({
        "ip_address": format!("127.0.0.1:{}", free_udp_port()),
        "internal_db_path": dir.path().join("db"),
        "control_server_port": free_udp_port(),
    });
    value["log_config_name"] = serde_json::Value::Null;
    fs::write(dir.path().join("default_config.json"), value.to_string()).unwrap();
    let console =
        r#"{"type_id":1209251014,"pub_key":"RYokIiD5AFkzfTBgC6NhtAGFKm0+gwhN4suTzaW0Sjw="}"#;
    let (status, text) = run_configs(dir.path(), &["--ckey", console]);
    assert_eq!(status.code(), Some(0), "{text}");
    let config: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.path().join("config.json")).unwrap()).unwrap();
    let client = &config["control_server"]["clients"]["list"][0];
    assert_eq!(client["pub_key"], "RYokIiD5AFkzfTBgC6NhtAGFKm0+gwhN4suTzaW0Sjw=");
    assert_eq!(client["permissions"], 0x7fffffff);
}

#[test]
fn a_held_configuration_lock_exits_2_and_its_release_admits_the_node() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("config.json"), "{}").unwrap();
    let lock = RecordLock::take(&dir.path().join("config.json.lock"));
    let (status, text) = run_configs(dir.path(), &["--process-conf-and-exit"]);
    assert_eq!(status.code(), Some(2), "{text}");
    assert!(text.contains("config.json.lock"), "{text}");
    // The lock is taken before anything is generated.
    fs::remove_file(dir.path().join("config.json")).unwrap();
    write_default(dir.path(), dir.path().join("db").to_str().unwrap(), false);
    let (status, _) = run_configs(dir.path(), &[]);
    assert_eq!(status.code(), Some(2));
    assert!(!dir.path().join("config.json").exists(), "nothing is generated under a held lock");
    drop(lock);
    let (status, text) = run_configs(dir.path(), &[]);
    assert_eq!(status.code(), Some(0), "{text}");
}

#[test]
fn an_unusable_log_configuration_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("config.json"), r#"{"log_config_name":"missing-log.yml"}"#).unwrap();
    let (status, text) = run_configs(dir.path(), &[]);
    assert_eq!(status.code(), Some(2), "{text}");
}

#[test]
fn an_unloadable_global_configuration_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    write_default(dir.path(), dir.path().join("db").to_str().unwrap(), false);
    generate(dir.path());
    let (status, text) = run_configs(dir.path(), &[]);
    assert_eq!(status.code(), Some(2), "{text}");
    assert!(text.contains("Configuration refused"), "{text}");
}

#[test]
fn an_engine_start_failure_exits_1() {
    let dir = tempfile::tempdir().unwrap();
    write_default(dir.path(), "/proc/rtos-exit-code-test-db", true);
    generate(dir.path());
    let (status, text) = run_configs(dir.path(), &[]);
    assert_eq!(status.code(), Some(1), "{text}");
    assert!(text.contains("Can't start node's Engine"), "{text}");
}

fn stopped_by(signal: i32) {
    let dir = tempfile::tempdir().unwrap();
    write_default(dir.path(), dir.path().join("db").to_str().unwrap(), true);
    generate(dir.path());
    let log: PathBuf = dir.path().join("node.log");
    let mut child = Command::new(NODE)
        .args(["--configs", dir.path().to_str().unwrap()])
        .current_dir(dir.path())
        .stdin(Stdio::null())
        .stdout(fs::File::create(&log).unwrap())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // The stop signals are installed before the engine starts.
    let deadline = Instant::now() + Duration::from_secs(60);
    while !fs::read_to_string(&log).unwrap_or_default().contains("Engine::run") {
        assert!(child.try_wait().unwrap().is_none(), "node exited before the engine started");
        assert!(Instant::now() < deadline, "engine never started");
        std::thread::sleep(Duration::from_millis(50));
    }
    // SAFETY: plain kill(2) on the child's pid.
    assert_eq!(unsafe { libc::kill(child.id() as i32, signal) }, 0);
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            child.kill().ok();
            panic!("node did not stop after signal {signal}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let text = fs::read_to_string(&log).unwrap_or_default();
    assert_eq!(status.signal(), Some(signal), "status {status:?}: {text}");
    assert_eq!(status.code(), None);
    assert!(text.contains("starting node's safe stopping"), "cleanup ran first: {text}");
}

#[test]
fn sigterm_terminates_by_sigterm() {
    stopped_by(libc::SIGTERM);
}

#[test]
fn sigint_terminates_by_sigint() {
    stopped_by(libc::SIGINT);
}
