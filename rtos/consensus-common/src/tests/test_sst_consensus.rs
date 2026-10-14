// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{sst_test_support as support, TestSstAction};
use std::sync::atomic::AtomicUsize;

fn open(path: &std::path::Path, threaded: bool, label: &str) -> AsyncKeyValueStoragePtr {
    let storage = RocksDbAsyncKeyValueStorage::open(
        path,
        "session",
        AsyncKeyValueStorageOptions { use_callback_thread: threaded },
    )
    .expect(label);
    support::native(&storage, TestSstAction::Configure).unwrap();
    storage
}
fn put(storage: &AsyncKeyValueStoragePtr, key: &[u8], value: &[u8], count: &Arc<AtomicUsize>) {
    let called = count.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    support::wait(storage.set(
        key.to_vec(),
        value.to_vec(),
        Some(Box::new(move |result| {
            assert!(result.is_ok(), "actual setup write callback failed");
            called.fetch_add(1, Ordering::SeqCst);
            tx.send(()).unwrap();
        })),
    ))
    .unwrap();
    rx.recv_timeout(support::TIMEOUT).expect("actual write callback did not finish");
}
fn set1(storage: &AsyncKeyValueStoragePtr, count: &Arc<AtomicUsize>) {
    put(storage, b"keep", b"acknowledged keep", count);
    put(storage, b"cursor", b"1", count);
    storage.sync(Some(support::TIMEOUT)).unwrap();
}
fn set2(storage: &AsyncKeyValueStoragePtr, count: &Arc<AtomicUsize>) {
    put(storage, b"target", b"acknowledged target", count);
    put(storage, b"cursor", b"2", count);
    storage.sync(Some(support::TIMEOUT)).unwrap();
}
fn exercise(compact: bool, threaded: bool) {
    let case = format!(
        "consensus-sst-{}-{}",
        if compact { "compact" } else { "flush" },
        if threaded { "threaded" } else { "inline" }
    );
    let path = support::root(&case);
    std::fs::create_dir_all(&path).unwrap();
    let control = support::control();
    let storage = open(&path, threaded, "shared SST setup DB open failed");
    let count = Arc::new(AtomicUsize::new(0));
    set1(&storage, &count);
    let seed = support::seed(&storage);
    set2(&storage, &count);
    let expected = support::raw(&storage);
    assert_eq!(
        expected,
        vec![
            (b"cursor".to_vec(), b"2".to_vec()),
            (b"keep".to_vec(), b"acknowledged keep".to_vec()),
            (b"target".to_vec(), b"acknowledged target".to_vec())
        ]
    );
    assert_eq!(count.load(Ordering::SeqCst), 4);
    let before = support::inputs(&storage, &seed, compact);
    let filler = if control { None } else { Some(support::fill(&path)) };
    support::run(&storage, &before, compact, control);
    assert_eq!(support::raw(&storage), expected, "live acknowledged shared data changed");
    assert_eq!(count.load(Ordering::SeqCst), 4, "SST IO fabricated a write callback");
    if let Some(filler) = filler {
        std::fs::remove_file(filler).unwrap();
    }
    eprintln!("SST-OBS shared-post-error-sync={:?}", storage.sync(Some(support::TIMEOUT)));
    support::close(storage);
    assert_eq!(count.load(Ordering::SeqCst), 4, "teardown fabricated callback");
    let storage = open(&path, threaded, "acknowledged shared SST open failed");
    assert_eq!(support::raw(&storage), expected, "cold acknowledged shared data changed");
    support::retry(&storage, compact);
    support::close(storage);
    let storage = open(&path, threaded, "acknowledged shared SST open failed");
    assert_eq!(support::raw(&storage), expected, "second acknowledged shared data changed");
    support::close(storage);
    eprintln!("ENOSPC-CASE {case} {} ok", if control { "control" } else { "fault" });
}
macro_rules! case {
    ($name:ident,$compact:literal,$threaded:literal) => {
        #[test]
        #[ignore = "private SST ENOSPC namespace and trace required"]
        fn $name() {
            exercise($compact, $threaded);
        }
    };
}
case!(disk_full_shared_sst_flush_threaded, false, true);
case!(disk_full_shared_sst_flush_inline, false, false);
case!(disk_full_shared_sst_compact_threaded, true, true);
case!(disk_full_shared_sst_compact_inline, true, false);
#[test]
fn queued_sst_shared_callback_and_teardown_roundtrip() {
    for threaded in [false, true] {
        let path = std::env::temp_dir()
            .join(format!("rtos-shared-sst-fixture-{}-{threaded}", std::process::id()));
        assert!(!path.exists(), "fixture directory collision");
        let storage = open(&path, threaded, "acknowledged shared SST open failed");
        let count = Arc::new(AtomicUsize::new(0));
        set1(&storage, &count);
        set2(&storage, &count);
        let before = support::raw(&storage);
        support::close(storage);
        assert_eq!(count.load(Ordering::SeqCst), 4);
        let storage = open(&path, threaded, "acknowledged shared SST open failed");
        assert_eq!(support::raw(&storage), before);
        support::close(storage);
        std::fs::remove_dir_all(&path).unwrap();
    }
}
