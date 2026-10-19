/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! `--shutdown-at` against the reference engine run as a process (evidence:
//! control-surface/oracle shutdown-parse and shutdown-run): option parsing,
//! a time in the past, repeated values, and the end itself, which comes at
//! the deadline with status 0 whatever the rest of the process is doing.

use super::*;
use std::time::{Duration, Instant};

const CHILD: &str = "RTOS_SCHEDULED_SHUTDOWN_CHILD";

/// Values the reference parser refuses and accepts, with its message.
#[test]
fn shutdown_times_parse_as_the_reference_parser_reads_them() {
    for value in ["abc", "-1", "4294967296", "", " 5", "+5", "5x", "0x10"] {
        assert_eq!(
            scheduled_shutdown::parse(value),
            Err(format!("Can't parse \"{value}\" as number")),
            "{value:?}"
        );
    }
    assert_eq!(scheduled_shutdown::parse("4294967295"), Ok(u32::MAX));
    assert_eq!(scheduled_shutdown::parse("0"), Ok(0));
    assert_eq!(scheduled_shutdown::parse("0007"), Ok(7));
}

#[test]
fn the_option_repeats_and_a_bad_value_refuses_the_command_line() {
    let matches = build_command()
        .try_get_matches_from(["rtos", "--shutdown-at", "5", "--shutdown-at", "6"])
        .unwrap();
    assert_eq!(scheduled_shutdown::parse_all(&matches), Ok(vec![5, 6]));
    let matches = build_command()
        .try_get_matches_from(["rtos", "--shutdown-at", "5", "--shutdown-at", "x"])
        .unwrap();
    assert_eq!(
        scheduled_shutdown::parse_all(&matches),
        Err("Can't parse \"x\" as number".to_string())
    );
    let matches = build_command().try_get_matches_from(["rtos"]).unwrap();
    assert_eq!(scheduled_shutdown::parse_all(&matches), Ok(vec![]));
}

#[test]
fn a_time_in_the_past_schedules_nothing() {
    let lines = scheduled_shutdown::schedule_all(&[5]).unwrap();
    assert_eq!(
        lines,
        vec![(log::Level::Debug, "Scheduled shutdown is in past (5.000000)".to_string())]
    );
}

/// Runs this test binary again as a child that runs `scenario`, and returns
/// its exit status, how long it ran, and its output.
fn child(scenario: &str, test: &str) -> (std::process::ExitStatus, Duration, String) {
    let started = Instant::now();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([test, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD, scenario)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status, started.elapsed(), text)
}

fn unix_now() -> u32 {
    u32::try_from(
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
    )
    .unwrap()
}

/// The child: arm the timers from the command line it is given, then get
/// stuck the way a shutdown can: a lock held forever, a reader blocked on a
/// pipe nobody writes, and a writer blocked on a full pipe nobody reads.
fn run_child(scenario: &str) {
    init_logger::<std::path::PathBuf>(None);
    let mut args = vec!["rtos".to_string()];
    for value in scenario.split(',') {
        args.push("--shutdown-at".to_string());
        args.push(value.to_string());
    }
    let matches = build_command().try_get_matches_from(args).unwrap();
    let lines = scheduled_shutdown::schedule_all(&scheduled_shutdown::parse_all(&matches).unwrap())
        .unwrap();
    scheduled_shutdown::log_lines(&lines);
    let held = Arc::new(std::sync::Mutex::new(()));
    let guard = held.lock().unwrap();
    let mut fds = [0; 2];
    // SAFETY: plain pipe creation into a two-element array.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let (read_end, write_end) = (fds[0], fds[1]);
    std::thread::spawn(move || {
        let mut byte = [0u8; 1];
        // SAFETY: a blocking read into a valid buffer on a valid descriptor.
        unsafe { libc::read(read_end, byte.as_mut_ptr().cast(), 1) };
    });
    std::thread::spawn(move || {
        let chunk = [0u8; 65536];
        loop {
            // SAFETY: a blocking write from a valid buffer; nobody reads.
            unsafe { libc::write(write_end, chunk.as_ptr().cast(), chunk.len()) };
        }
    });
    let waiter = held.clone();
    std::thread::spawn(move || drop(waiter.lock()));
    // A past-only scenario ends by itself, with a status of its own.
    if scenario.split(',').all(|value| value.parse::<u32>().unwrap() < unix_now()) {
        std::thread::sleep(Duration::from_secs(2));
        std::process::exit(7);
    }
    loop {
        std::thread::sleep(Duration::from_secs(60));
        let _ = &guard;
    }
}

#[test]
fn the_deadline_ends_a_stalled_process_with_status_zero() {
    if let Ok(scenario) = std::env::var(CHILD) {
        return run_child(&scenario);
    }
    let test = "scheduled_shutdown_tests::the_deadline_ends_a_stalled_process_with_status_zero";
    // Two values: the earlier one ends the process.
    let first = unix_now() + 3;
    let (status, elapsed, output) = child(&format!("{},{}", first + 30, first), test);
    assert_eq!(status.code(), Some(0), "{output}");
    assert!(unix_now() >= first, "ended before the deadline: {output}");
    assert!(elapsed < Duration::from_secs(20), "ran {elapsed:?}: {output}");
    assert!(output.contains(&format!("Schedule shutdown for {first}.000000 (in ")), "{output}");
    assert!(
        output.contains(&format!("Schedule shutdown for {}.000000 (in ", first + 30)),
        "{output}"
    );
    assert!(output.contains("Shutting down as scheduled"), "{output}");
    // A time in the past arms nothing: the child ends by its own status.
    let (status, _, output) = child("5", test);
    assert_eq!(status.code(), Some(7), "{output}");
    assert!(!output.contains("Shutting down as scheduled"), "{output}");
}
