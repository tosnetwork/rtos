/*
 * RTOS project modifications (2026-10-11): atomic pair concurrency regressions.
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
use super::AtomicPair;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc, Arc,
};

#[test]
fn atomic_pair_delayed_update_cannot_regress_timestamp() {
    let pair = Arc::new(AtomicPair::new(10, 100));
    let (ready_tx, ready_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let old_pair = pair.clone();
    let old = std::thread::spawn(move || {
        let calls = AtomicUsize::new(0);
        let accepted = old_pair.update_before_lock(
            20,
            200,
            |previous, proposed| {
                calls.fetch_add(1, Ordering::Relaxed);
                previous <= proposed
            },
            || {
                ready_tx.send(()).unwrap();
                resume_rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
            },
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        accepted
    });
    ready_rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
    assert!(pair.update(30, 300, |previous, proposed| previous <= proposed));
    resume_tx.send(()).unwrap();
    let accepted = old.join().unwrap();
    let final_pair = pair.get();
    assert_eq!((accepted, final_pair), (false, (30, 300)));
}

#[test]
fn atomic_pair_checker_panic_releases_lock_without_publication() {
    let pair = AtomicPair::new(10, 100);
    let result = std::panic::catch_unwind(|| {
        pair.update(20, 200, |previous, proposed| {
            assert_eq!((previous, proposed), (10, 20));
            assert_ne!(pair.atomic2.load(Ordering::Relaxed) & AtomicPair::LOCK_BIT, 0);
            panic!("checker rejection by panic");
        });
    });
    assert!(result.is_err());
    // Inspect before calling get so a leaked lock fails instead of hanging.
    assert_eq!(pair.atomic2.load(Ordering::Acquire), 100);
    assert_eq!(pair.get(), (10, 100));
    assert!(!pair.update(20, 200, |_, _| false));
    assert_eq!(pair.get(), (10, 100));
    assert!(pair.update(30, 300, |_, _| true));
    assert_eq!(pair.get(), (30, 300));
}

#[test]
fn atomic_pair_concurrent_readers_observe_complete_pairs() {
    let pair = Arc::new(AtomicPair::new(0, 0));
    std::thread::scope(|scope| {
        for writer in 0..2 {
            let pair = &pair;
            scope.spawn(move || {
                for index in 1..=10_000 {
                    let value = index * 2 + writer;
                    pair.update(value, value * 7, |old, new| old <= new);
                }
            });
        }
        for _ in 0..2 {
            let pair = &pair;
            scope.spawn(move || {
                for _ in 0..10_000 {
                    let (first, second) = pair.get();
                    assert_eq!(second, first * 7);
                }
            });
        }
    });
    assert_eq!(pair.get(), (20_001, 140_007));
}
