// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::lifecycle_support::*;
use std::sync::mpsc;
fn actual_main(panic: bool) {
    let (path, key, nodes) = fixture();
    let listener = catchain_listener();
    let create = || {
        CatchainImpl::create(
            &Options::default(),
            &SessionId::default(),
            nodes.clone(),
            &key,
            path.to_string_lossy().into(),
            "owned".into(),
            false,
            CatchainFactory::create_dummy_overlay_manager(),
            Arc::downgrade(&listener),
        )
        .unwrap()
    };
    let catchain = create();
    let (entered, ready) = mpsc::channel();
    let (release, held) = mpsc::channel();
    catchain.task_queues.post_main_queue_closure(move |_| {
        entered.send(()).unwrap();
        held.recv().unwrap();
        assert!(!panic, "actual Catchain main panic");
    });
    ready.recv_timeout(Duration::from_secs(10)).unwrap();
    let waiting = catchain.clone();
    let (finished, completion) = mpsc::channel();
    let waiter = std::thread::spawn(move || finished.send(waiting.stop_checked()).unwrap());
    assert!(completion.recv_timeout(Duration::from_millis(30)).is_err());
    assert!(!catchain.threads_drained());
    release.send(()).unwrap();
    let result = completion.recv_timeout(Duration::from_secs(10)).unwrap();
    waiter.join().unwrap();
    assert!(catchain.threads_drained());
    if panic {
        let error = result.unwrap_err().to_string();
        assert!(error.contains("actual Catchain main panic"));
        assert_eq!(catchain.stop_checked().unwrap_err().to_string(), error);
    } else {
        result.unwrap();
    }
    drop(catchain);
    let reopened = create();
    reopened.stop_checked().unwrap();
    drop(reopened);
    std::fs::remove_dir_all(path).unwrap();
}
#[test]
fn catchain_owned_shutdown_joins_actual_main_and_reopens_database() {
    actual_main(false);
}
#[test]
fn catchain_owned_shutdown_keeps_main_panic_and_joins_receiver() {
    actual_main(true);
}
