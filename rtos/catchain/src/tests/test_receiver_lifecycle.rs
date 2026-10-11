// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::lifecycle_support::*;
use std::sync::mpsc;

fn actual_receiver_db(panic: bool) {
    let (path, key, nodes) = fixture();
    let listener = receiver_listener();
    let create = || {
        ReceiverWrapper::create(
            SessionId::default(),
            Options::default(),
            Arc::downgrade(&listener),
            nodes.clone(),
            key.clone(),
            path.to_string_lossy().into(),
            "owned".into(),
            false,
            CatchainFactory::create_dummy_overlay_manager(),
        )
        .unwrap()
    };
    let receiver = create();
    let (entered, ready) = mpsc::channel();
    let (release, held) = mpsc::channel();
    receiver.task_queues.post_database_closure(Box::new(move || {
        entered.send(()).unwrap();
        held.recv().unwrap();
        assert!(!panic, "actual receiver DB panic");
    }));
    ready.recv_timeout(Duration::from_secs(10)).unwrap();
    let stopping = receiver.clone();
    let (finished, completion) = mpsc::channel();
    let waiter = std::thread::spawn(move || finished.send(stopping.stop_checked()).unwrap());
    assert!(completion.recv_timeout(Duration::from_millis(30)).is_err());
    assert!(!receiver.threads_drained());
    release.send(()).unwrap();
    let result = completion.recv_timeout(Duration::from_secs(10)).unwrap();
    waiter.join().unwrap();
    assert!(receiver.threads_drained());
    if panic {
        let error = result.unwrap_err().to_string();
        assert!(error.contains("actual receiver DB panic"));
        assert_eq!(receiver.stop_checked().unwrap_err().to_string(), error);
    } else {
        result.unwrap();
    }
    drop(receiver);
    let reopened = create();
    reopened.stop_checked().unwrap();
    drop(reopened);
    std::fs::remove_dir_all(path).unwrap();
}
#[test]
fn receiver_owned_shutdown_waits_for_actual_db_worker_and_reopens() {
    actual_receiver_db(false);
}
#[test]
fn receiver_owned_shutdown_reports_db_panic_and_joins_processing_sibling() {
    actual_receiver_db(true);
}
