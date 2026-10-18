/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! Unit tests for RocksDB-based async key-value storage.
//! RTOS additions (2026-10-10): durable acknowledgement and abrupt-exit probes.

use crate::{AsyncKeyValueStorageOptions, ConsensusCommonFactory};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Creates a unique test database path inside target directory.
fn create_test_db_path(test_name: &str) -> PathBuf {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
    let random: u32 = rand::random();

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/test_dbs")
        .join(format!("{}_{:016x}_{:08x}", test_name, timestamp, random));

    std::fs::create_dir_all(&path).unwrap();
    path
}

fn create_test_options() -> AsyncKeyValueStorageOptions {
    AsyncKeyValueStorageOptions { use_callback_thread: true }
}

fn create_test_options_no_callback_thread() -> AsyncKeyValueStorageOptions {
    AsyncKeyValueStorageOptions { use_callback_thread: false }
}

/// The child exits without Drop/close after acknowledgement. This exercises
/// actual WAL recovery, but process exit alone does not emulate power loss.
/// External syscall fault tests reuse this entry point with a fresh test DB.
#[test]
#[cfg(unix)]
fn test_wal_acknowledgements_and_abrupt_exit() {
    const TEST: &str = "async_key_value_storage::tests::test_wal_acknowledgements_and_abrupt_exit";
    if let Some(path) = std::env::var_os("RTOS_WAL_PROBE_DB") {
        let mode = std::env::var("RTOS_WAL_PROBE_MODE").unwrap();
        let storage = ConsensusCommonFactory::create_async_key_value_storage(
            PathBuf::from(path),
            "wal-probe",
            create_test_options(),
        )
        .unwrap();
        let timeout = Duration::from_secs(10);
        storage
            .set(b"keep".to_vec(), b"durable".to_vec(), None)
            .wait_timeout(timeout)
            .expect("initial write timed out")
            .unwrap();
        storage
            .set(b"erase".to_vec(), b"old".to_vec(), None)
            .wait_timeout(timeout)
            .expect("initial write timed out")
            .unwrap();
        if mode != "normal" {
            // Only the external fault harness supplies this path. Arming after
            // open/seed avoids mistaking a DB initialization error for an
            // acknowledgement or explicit WAL synchronization failure.
            let arm = std::env::var_os("RTOS_WAL_FAIL_ARM").expect("fault arm path");
            std::fs::write(arm, b"armed").unwrap();
        }
        eprintln!("WAL_PROBE_OPERATION {mode}");
        match mode.as_str() {
            "normal" | "set" | "erase" => {
                let (tx, rx) = std::sync::mpsc::channel();
                let callback = Some(Box::new(move |result: crate::Result<()>| {
                    tx.send(result.is_ok()).unwrap();
                }) as crate::StorageWriteCallback);
                let pending = if mode == "set" {
                    storage.set(b"new".to_vec(), b"value".to_vec(), callback)
                } else {
                    storage.erase(b"erase".to_vec(), callback)
                };
                let acknowledged = pending.wait_timeout(timeout).expect("write timed out");
                let callback_ok = rx.recv_timeout(timeout).expect("missing callback");
                assert_eq!(acknowledged.is_ok(), mode == "normal", "{acknowledged:?}");
                assert_eq!(callback_ok, mode == "normal");
            }
            "sync" => assert!(storage.sync(Some(timeout)).is_err()),
            "close" => {
                assert!(storage.close(Some(timeout)).is_err());
                assert!(storage.is_closed());
                assert!(storage.close(Some(timeout)).is_err());
                assert!(storage.set(b"late".to_vec(), vec![], None).wait().is_err());
            }
            _ => panic!("unknown WAL probe mode"),
        }
        if mode == "normal" {
            storage.sync(Some(timeout)).unwrap();
        }
        eprintln!("WAL_PROBE_ACKNOWLEDGED {mode}");
        // _exit skips both Rust drops and C atexit handlers. Calling exit while
        // RocksDB worker threads remain live can race native global teardown;
        // that would test shutdown cleanup instead of abrupt WAL recovery.
        unsafe extern "C" {
            fn _exit(status: std::ffi::c_int) -> !;
        }
        unsafe { _exit(77) }
    }

    let path = create_test_db_path("wal_abrupt_exit");
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", TEST, "--nocapture"])
        .env("RTOS_WAL_PROBE_DB", &path)
        .env("RTOS_WAL_PROBE_MODE", "normal")
        .output()
        .unwrap();
    assert_eq!(child.status.code(), Some(77), "{child:?}");
    assert!(String::from_utf8_lossy(&child.stderr).contains("WAL_PROBE_ACKNOWLEDGED normal"));
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "wal-probe",
        create_test_options(),
    )
    .unwrap();
    assert_eq!(storage.get(b"keep".to_vec(), None).wait().unwrap(), Some(b"durable".to_vec()));
    assert_eq!(storage.get(b"erase".to_vec(), None).wait().unwrap(), None);
    storage.mark_for_destroy();
}

// ============================================================================
// Basic Operations Tests
// ============================================================================

#[test]
fn test_basic_set_and_get() {
    let path = create_test_db_path("test_basic_set_and_get");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "test1",
        create_test_options(),
    )
    .unwrap();

    // Set value
    let set_result = storage.set(b"key1".to_vec(), b"value1".to_vec(), None);
    set_result.wait_timeout(Duration::from_secs(5)).expect("timeout").unwrap();

    // Get value
    let get_result = storage.get(b"key1".to_vec(), None);
    let value = get_result.wait_timeout(Duration::from_secs(5)).expect("timeout").unwrap();

    assert_eq!(value, Some(b"value1".to_vec()));

    storage.mark_for_destroy();
}

#[test]
fn test_get_nonexistent_key() {
    let path = create_test_db_path("test_get_nonexistent_key");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "test2",
        create_test_options(),
    )
    .unwrap();

    let get_result = storage.get(b"nonexistent".to_vec(), None);
    let value = get_result.wait_timeout(Duration::from_secs(5)).expect("timeout").unwrap();

    assert_eq!(value, None);

    storage.mark_for_destroy();
}

#[test]
fn test_erase() {
    let path = create_test_db_path("test_erase");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "test4",
        create_test_options(),
    )
    .unwrap();

    // Set then erase
    storage
        .set(b"key1".to_vec(), b"value1".to_vec(), None)
        .wait_timeout(Duration::from_secs(5))
        .expect("timeout")
        .unwrap();

    storage
        .erase(b"key1".to_vec(), None)
        .wait_timeout(Duration::from_secs(5))
        .expect("timeout")
        .unwrap();

    // Key should be gone
    let value = storage
        .get(b"key1".to_vec(), None)
        .wait_timeout(Duration::from_secs(5))
        .expect("timeout")
        .unwrap();
    assert_eq!(value, None);

    storage.mark_for_destroy();
}

#[test]
fn test_contains() {
    let path = create_test_db_path("test_contains");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "test_contains",
        create_test_options(),
    )
    .unwrap();

    // Key doesn't exist
    let exists = storage
        .contains(b"key1".to_vec(), None)
        .wait_timeout(Duration::from_secs(5))
        .expect("timeout")
        .unwrap();
    assert!(!exists);

    // Set value
    storage
        .set(b"key1".to_vec(), b"value1".to_vec(), None)
        .wait_timeout(Duration::from_secs(5))
        .expect("timeout")
        .unwrap();

    // Key exists now
    let exists = storage
        .contains(b"key1".to_vec(), None)
        .wait_timeout(Duration::from_secs(5))
        .expect("timeout")
        .unwrap();
    assert!(exists);

    // Erase and check again
    storage
        .erase(b"key1".to_vec(), None)
        .wait_timeout(Duration::from_secs(5))
        .expect("timeout")
        .unwrap();

    let exists = storage
        .contains(b"key1".to_vec(), None)
        .wait_timeout(Duration::from_secs(5))
        .expect("timeout")
        .unwrap();
    assert!(!exists);

    storage.mark_for_destroy();
}

#[test]
fn test_overwrite() {
    let path = create_test_db_path("test_overwrite");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "test5",
        create_test_options(),
    )
    .unwrap();

    // Set initial value
    storage
        .set(b"key1".to_vec(), b"value1".to_vec(), None)
        .wait_timeout(Duration::from_secs(5))
        .expect("timeout")
        .unwrap();

    // Overwrite
    storage
        .set(b"key1".to_vec(), b"value2".to_vec(), None)
        .wait_timeout(Duration::from_secs(5))
        .expect("timeout")
        .unwrap();

    // Verify new value
    let value = storage
        .get(b"key1".to_vec(), None)
        .wait_timeout(Duration::from_secs(5))
        .expect("timeout")
        .unwrap();
    assert_eq!(value, Some(b"value2".to_vec()));

    storage.mark_for_destroy();
}

// ============================================================================
// Prefix Scan Tests
// ============================================================================

#[test]
fn test_prefix_scan() {
    let path = create_test_db_path("test_prefix_scan");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "test6",
        create_test_options(),
    )
    .unwrap();

    // Set multiple keys with same prefix
    storage
        .set(b"prefix_a".to_vec(), b"value_a".to_vec(), None)
        .wait_timeout(Duration::from_secs(5))
        .expect("timeout")
        .unwrap();
    storage
        .set(b"prefix_b".to_vec(), b"value_b".to_vec(), None)
        .wait_timeout(Duration::from_secs(5))
        .expect("timeout")
        .unwrap();
    storage
        .set(b"prefix_c".to_vec(), b"value_c".to_vec(), None)
        .wait_timeout(Duration::from_secs(5))
        .expect("timeout")
        .unwrap();
    storage
        .set(b"other_key".to_vec(), b"other_value".to_vec(), None)
        .wait_timeout(Duration::from_secs(5))
        .expect("timeout")
        .unwrap();

    // Scan by prefix
    let results = storage
        .get_by_prefix(b"prefix_".to_vec(), None)
        .wait_timeout(Duration::from_secs(5))
        .expect("timeout")
        .unwrap();

    assert_eq!(results.len(), 3);

    storage.mark_for_destroy();
}

#[test]
fn test_prefix_scan_u32() {
    let path = create_test_db_path("test_prefix_scan_u32");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "test7",
        create_test_options(),
    )
    .unwrap();

    // Create keys with u32 TL-style prefix
    let prefix1: u32 = 0x12345678;
    let prefix2: u32 = 0x87654321;

    let mut key1 = prefix1.to_le_bytes().to_vec();
    key1.extend_from_slice(b"_suffix1");
    let mut key2 = prefix1.to_le_bytes().to_vec();
    key2.extend_from_slice(b"_suffix2");
    let mut key3 = prefix2.to_le_bytes().to_vec();
    key3.extend_from_slice(b"_other");

    storage
        .set(key1, b"value1".to_vec(), None)
        .wait_timeout(Duration::from_secs(5))
        .expect("timeout")
        .unwrap();
    storage
        .set(key2, b"value2".to_vec(), None)
        .wait_timeout(Duration::from_secs(5))
        .expect("timeout")
        .unwrap();
    storage
        .set(key3, b"value3".to_vec(), None)
        .wait_timeout(Duration::from_secs(5))
        .expect("timeout")
        .unwrap();

    // Scan by u32 prefix
    let results = storage
        .get_by_prefix_u32(prefix1, None)
        .wait_timeout(Duration::from_secs(5))
        .expect("timeout")
        .unwrap();

    assert_eq!(results.len(), 2);

    storage.mark_for_destroy();
}

// ============================================================================
// Callback Tests
// ============================================================================

#[test]
fn test_set_with_callback() {
    let path = create_test_db_path("test_set_with_callback");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "test8",
        create_test_options(),
    )
    .unwrap();

    let callback_called = Arc::new(AtomicBool::new(false));
    let callback_called_clone = callback_called.clone();

    let _ = storage.set(
        b"key1".to_vec(),
        b"value1".to_vec(),
        Some(Box::new(move |result| {
            assert!(result.is_ok());
            callback_called_clone.store(true, Ordering::SeqCst);
        })),
    );

    // Wait for callback
    let start = std::time::Instant::now();
    while !callback_called.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(10));
    }

    assert!(callback_called.load(Ordering::SeqCst));

    storage.mark_for_destroy();
}

#[test]
fn test_get_with_callback() {
    let path = create_test_db_path("test_get_with_callback");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "test9",
        create_test_options(),
    )
    .unwrap();

    // Set first
    storage
        .set(b"key1".to_vec(), b"value1".to_vec(), None)
        .wait_timeout(Duration::from_secs(5))
        .expect("timeout")
        .unwrap();

    let callback_called = Arc::new(AtomicBool::new(false));
    let callback_called_clone = callback_called.clone();

    let _ = storage.get(
        b"key1".to_vec(),
        Some(Box::new(move |result| {
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), Some(b"value1".to_vec()));
            callback_called_clone.store(true, Ordering::SeqCst);
        })),
    );

    // Wait for callback
    let start = std::time::Instant::now();
    while !callback_called.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(10));
    }

    assert!(callback_called.load(Ordering::SeqCst));

    storage.mark_for_destroy();
}

#[test]
fn test_erase_with_callback() {
    let path = create_test_db_path("test_erase_with_callback");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "test10",
        create_test_options(),
    )
    .unwrap();

    // Set first
    storage
        .set(b"key1".to_vec(), b"value1".to_vec(), None)
        .wait_timeout(Duration::from_secs(5))
        .expect("timeout")
        .unwrap();

    let callback_called = Arc::new(AtomicBool::new(false));
    let callback_called_clone = callback_called.clone();

    let _ = storage.erase(
        b"key1".to_vec(),
        Some(Box::new(move |result| {
            assert!(result.is_ok());
            callback_called_clone.store(true, Ordering::SeqCst);
        })),
    );

    // Wait for callback
    let start = std::time::Instant::now();
    while !callback_called.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(10));
    }

    assert!(callback_called.load(Ordering::SeqCst));

    storage.mark_for_destroy();
}

// ============================================================================
// Async Result Tests
// ============================================================================

#[test]
fn test_async_result_is_ready() {
    let path = create_test_db_path("test_async_result_is_ready");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "test11",
        create_test_options(),
    )
    .unwrap();

    let result = storage.set(b"key1".to_vec(), b"value1".to_vec(), None);

    // Wait a bit for the operation to complete
    std::thread::sleep(Duration::from_millis(100));

    // Should be ready
    assert!(result.is_ready());

    storage.mark_for_destroy();
}

#[test]
fn test_async_result_try_get() {
    let path = create_test_db_path("test_async_result_try_get");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "test12",
        create_test_options(),
    )
    .unwrap();

    storage
        .set(b"key1".to_vec(), b"value1".to_vec(), None)
        .wait_timeout(Duration::from_secs(5))
        .expect("timeout")
        .unwrap();

    let result = storage.get(b"key1".to_vec(), None);

    // Wait for result
    result.wait_timeout(Duration::from_secs(5)).expect("timeout").unwrap();

    // try_get must surface the typed `StorageResultAlreadyTaken` sentinel —
    // consumers detect this via `downcast_ref` rather than string matching,
    // so any future change to the wrapping must keep the type alive.
    let try_result = result.try_get();
    assert!(try_result.is_some(), "second try_get must return Some(Err)");
    let err = try_result.unwrap().expect_err("second try_get must be Err");
    assert!(
        err.downcast_ref::<crate::StorageResultAlreadyTaken>().is_some(),
        "Err must downcast to StorageResultAlreadyTaken (got: {err})",
    );
    // Display impl is part of the public contract — log scrapers and humans
    // continue to see the legacy text.
    assert_eq!(err.to_string(), "StorageAsyncResult: result already taken");

    // Same contract on `wait_timeout` after `try_get` already drained the
    // result — it must also surface the typed sentinel.
    let wait_result = result
        .wait_timeout(Duration::from_millis(50))
        .expect("wait_timeout on Taken state must return Some, not None");
    let wait_err = wait_result.expect_err("wait_timeout on Taken must be Err");
    assert!(
        wait_err.downcast_ref::<crate::StorageResultAlreadyTaken>().is_some(),
        "wait_timeout Err must also downcast to StorageResultAlreadyTaken (got: {wait_err})",
    );

    storage.mark_for_destroy();
}

// ============================================================================
// Sync Tests
// ============================================================================

#[test]
fn test_sync() {
    let path = create_test_db_path("test_sync");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "test14",
        create_test_options(),
    )
    .unwrap();

    // Queue several writes
    for i in 0..10 {
        let _ =
            storage.set(format!("key{}", i).into_bytes(), format!("value{}", i).into_bytes(), None);
    }

    // Sync should wait for all ops to complete
    storage.sync(Some(Duration::from_secs(5))).unwrap();

    // All values should be readable
    for i in 0..10 {
        let value = storage
            .get(format!("key{}", i).into_bytes(), None)
            .wait_timeout(Duration::from_secs(1))
            .expect("timeout")
            .unwrap();
        assert_eq!(value, Some(format!("value{}", i).into_bytes()));
    }

    storage.mark_for_destroy();
}

#[test]
fn test_sync_with_timeout() {
    let path = create_test_db_path("test_sync_with_timeout");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "test15",
        create_test_options(),
    )
    .unwrap();

    // Sync with timeout should complete
    let result = storage.sync(Some(Duration::from_secs(1)));
    assert!(result.is_ok());

    storage.mark_for_destroy();
}

// ============================================================================
// Lifecycle Tests
// ============================================================================

#[test]
fn test_storage_path() {
    let path = create_test_db_path("test_storage_path");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "test16",
        create_test_options(),
    )
    .unwrap();

    assert_eq!(storage.get_path(), path.as_path());

    storage.mark_for_destroy();
}

#[test]
fn test_storage_id() {
    let path = create_test_db_path("test_storage_id");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "my_storage_id",
        create_test_options(),
    )
    .unwrap();

    assert_eq!(storage.get_storage_id(), "my_storage_id");

    storage.mark_for_destroy();
}

#[test]
fn test_pending_count() {
    let path = create_test_db_path("test_pending_count");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "test17",
        create_test_options(),
    )
    .unwrap();

    // Initially zero
    assert_eq!(storage.pending_count(), 0);

    // Queue some operations (don't wait)
    for i in 0..5 {
        let _ = storage.set(format!("key{}", i).into_bytes(), b"value".to_vec(), None);
    }

    // Sync to clear pending
    storage.sync(Some(Duration::from_secs(5))).unwrap();

    // Should be zero again
    assert_eq!(storage.pending_count(), 0);

    storage.mark_for_destroy();
}

#[test]
fn test_mark_for_destroy() {
    let path = create_test_db_path("test_mark_for_destroy");
    let path_clone = path.clone();

    {
        let storage = ConsensusCommonFactory::create_async_key_value_storage(
            &path,
            "test19",
            create_test_options(),
        )
        .unwrap();

        storage
            .set(b"key1".to_vec(), b"value1".to_vec(), None)
            .wait_timeout(Duration::from_secs(5))
            .expect("timeout")
            .unwrap();

        storage.mark_for_destroy();
    } // Storage dropped here

    // Wait a bit for cleanup
    std::thread::sleep(Duration::from_millis(500));

    // Path should be deleted
    assert!(!path_clone.exists());
}

// ============================================================================
// No Callback Thread Tests
// ============================================================================

#[test]
fn test_no_callback_thread() {
    let path = create_test_db_path("test_no_callback_thread");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "test20",
        create_test_options_no_callback_thread(),
    )
    .unwrap();

    let callback_called = Arc::new(AtomicBool::new(false));
    let callback_called_clone = callback_called.clone();

    // Callback should still work (executed in DB thread)
    let _ = storage.set(
        b"key1".to_vec(),
        b"value1".to_vec(),
        Some(Box::new(move |result| {
            assert!(result.is_ok());
            callback_called_clone.store(true, Ordering::SeqCst);
        })),
    );

    // Wait for callback
    let start = std::time::Instant::now();
    while !callback_called.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(10));
    }

    assert!(callback_called.load(Ordering::SeqCst));

    storage.mark_for_destroy();
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

#[test]
fn test_concurrent_writes() {
    let path = create_test_db_path("test_concurrent_writes");
    let storage = Arc::new(
        ConsensusCommonFactory::create_async_key_value_storage(
            &path,
            "test21",
            create_test_options(),
        )
        .unwrap(),
    );

    let num_threads = 4;
    let writes_per_thread = 25;
    let counter = Arc::new(AtomicU32::new(0));

    let mut handles = vec![];

    for t in 0..num_threads {
        let storage_clone = storage.clone();
        let counter_clone = counter.clone();

        let handle = std::thread::spawn(move || {
            for i in 0..writes_per_thread {
                let key = format!("thread{}_key{}", t, i).into_bytes();
                let value = format!("value{}", i).into_bytes();

                storage_clone
                    .set(key, value, None)
                    .wait_timeout(Duration::from_secs(10))
                    .expect("timeout")
                    .unwrap();

                counter_clone.fetch_add(1, Ordering::SeqCst);
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    assert_eq!(counter.load(Ordering::SeqCst), num_threads * writes_per_thread);

    // Verify all values
    storage.sync(Some(Duration::from_secs(10))).unwrap();

    for t in 0..num_threads {
        for i in 0..writes_per_thread {
            let key = format!("thread{}_key{}", t, i).into_bytes();
            let value = storage
                .get(key, None)
                .wait_timeout(Duration::from_secs(5))
                .expect("timeout")
                .unwrap();
            assert!(value.is_some());
        }
    }

    storage.mark_for_destroy();
}

#[test]
fn test_concurrent_reads_and_writes() {
    let path = create_test_db_path("test_concurrent_reads_and_writes");
    let storage = Arc::new(
        ConsensusCommonFactory::create_async_key_value_storage(
            &path,
            "test22",
            create_test_options(),
        )
        .unwrap(),
    );

    // Pre-populate
    for i in 0..50 {
        storage
            .set(format!("key{}", i).into_bytes(), format!("value{}", i).into_bytes(), None)
            .wait_timeout(Duration::from_secs(5))
            .expect("timeout")
            .unwrap();
    }

    let read_count = Arc::new(AtomicU32::new(0));
    let write_count = Arc::new(AtomicU32::new(0));

    let mut handles = vec![];

    // Readers
    for _ in 0..2 {
        let storage_clone = storage.clone();
        let read_count_clone = read_count.clone();

        let handle = std::thread::spawn(move || {
            for i in 0..50 {
                let key = format!("key{}", i).into_bytes();
                let _ = storage_clone
                    .get(key, None)
                    .wait_timeout(Duration::from_secs(5))
                    .expect("timeout");
                read_count_clone.fetch_add(1, Ordering::SeqCst);
            }
        });

        handles.push(handle);
    }

    // Writers
    for t in 0..2 {
        let storage_clone = storage.clone();
        let write_count_clone = write_count.clone();

        let handle = std::thread::spawn(move || {
            for i in 0..25 {
                let key = format!("new_key_{}_{}", t, i).into_bytes();
                let value = format!("new_value{}", i).into_bytes();
                storage_clone
                    .set(key, value, None)
                    .wait_timeout(Duration::from_secs(5))
                    .expect("timeout")
                    .unwrap();
                write_count_clone.fetch_add(1, Ordering::SeqCst);
            }
        });

        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    assert_eq!(read_count.load(Ordering::SeqCst), 100);
    assert_eq!(write_count.load(Ordering::SeqCst), 50);

    storage.mark_for_destroy();
}

// ============================================================================
// Sync Waits for Callbacks Test
// ============================================================================

#[test]
fn test_sync_waits_for_callbacks() {
    let path = create_test_db_path("test_sync_waits_for_callbacks");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "test23",
        create_test_options(),
    )
    .unwrap();

    let callback_executed = Arc::new(AtomicBool::new(false));
    let callback_executed_clone = callback_executed.clone();

    // Post a write with a callback that takes time
    let _ = storage.set(
        b"key1".to_vec(),
        b"value1".to_vec(),
        Some(Box::new(move |_result| {
            // Simulate slow callback
            std::thread::sleep(Duration::from_millis(100));
            callback_executed_clone.store(true, Ordering::SeqCst);
        })),
    );

    // Sync should wait for callback to complete
    storage.sync(Some(Duration::from_secs(5))).unwrap();

    // Callback should have executed
    assert!(callback_executed.load(Ordering::SeqCst));

    storage.mark_for_destroy();
}

// ============================================================================
// Close / Destroy Regression Tests (CONSENSUS-DB-CLEANUP-1, TN-1035)
// ============================================================================
//
// Covers the `close()` / `is_closed()` / `mark_for_destroy()` contract that
// `SessionProcessor::stop()` relies on for C++ parity with
// `validator/consensus/bridge.cpp::destroy_inner()`:
//
// 1. `close()` drains queued ops BEFORE flipping the gate, so a write posted
//    "just before" shutdown still lands on disk.
// 2. Post-close writes fail fast with `DB_CLOSED_ERROR` and never reach
//    rocksdb.
// 3. `close()` is idempotent.
// 4. `close()` is a superset of `sync()` — no double-sync required.
// 5. `close() + mark_for_destroy()` removes the on-disk DB when the storage
//    is finally dropped.
// 6. Dropping without `close()` still drains via the safety-net path in
//    `RocksDbAsyncKeyValueStorage::Drop`, so no data loss on panic.

fn read_back(storage: &crate::AsyncKeyValueStoragePtr, key: &[u8]) -> Option<Vec<u8>> {
    storage
        .get(key.to_vec(), None)
        .wait_timeout(Duration::from_secs(5))
        .expect("get timeout")
        .expect("get err")
}

#[test]
fn test_close_drains_pending_writes() {
    let path = create_test_db_path("test_close_drains_pending_writes");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "close_drain",
        create_test_options(),
    )
    .unwrap();

    // Fire many writes fire-and-forget; close() must drain them all.
    for i in 0..100u32 {
        let _ =
            storage.set(format!("k{:04}", i).into_bytes(), format!("v{:04}", i).into_bytes(), None);
    }

    assert!(!storage.is_closed(), "is_closed must be false before close()");
    storage.close(Some(Duration::from_secs(5))).expect("close must drain");
    assert!(storage.is_closed(), "is_closed must be true after close()");

    // Reopen from the same path to confirm every write landed. `RocksDb::new`
    // appends `storage_id` as a sub-directory, so reopen with the SAME
    // storage_id — otherwise we'd be pointing at an empty sibling dir.
    drop(storage);
    let reopened = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "close_drain",
        create_test_options(),
    )
    .unwrap();

    for i in 0..100u32 {
        let got = read_back(&reopened, format!("k{:04}", i).as_bytes());
        assert_eq!(got, Some(format!("v{:04}", i).into_bytes()), "missing write i={}", i);
    }

    reopened.mark_for_destroy();
}

#[test]
fn test_close_rejects_new_ops_with_db_closed_error() {
    let path = create_test_db_path("test_close_rejects_new_ops");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "close_reject",
        create_test_options(),
    )
    .unwrap();

    storage
        .set(b"pre".to_vec(), b"ok".to_vec(), None)
        .wait_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap();
    storage.close(Some(Duration::from_secs(5))).unwrap();

    let set_err = storage
        .set(b"post".to_vec(), b"late".to_vec(), None)
        .wait_timeout(Duration::from_secs(1))
        .expect("set result must be immediately ready")
        .expect_err("set after close must be Err");
    assert!(
        set_err.to_string().contains("db is closed"),
        "expected DB_CLOSED_ERROR, got: {}",
        set_err
    );

    let get_err = storage
        .get(b"pre".to_vec(), None)
        .wait_timeout(Duration::from_secs(1))
        .expect("get result must be immediately ready")
        .expect_err("get after close must be Err");
    assert!(
        get_err.to_string().contains("db is closed"),
        "expected DB_CLOSED_ERROR, got: {}",
        get_err
    );

    let erase_err = storage
        .erase(b"pre".to_vec(), None)
        .wait_timeout(Duration::from_secs(1))
        .expect("erase result must be immediately ready")
        .expect_err("erase after close must be Err");
    assert!(
        erase_err.to_string().contains("db is closed"),
        "expected DB_CLOSED_ERROR, got: {}",
        erase_err
    );

    let sync_err =
        storage.sync(Some(Duration::from_secs(1))).expect_err("sync after close must be Err");
    assert!(
        sync_err.to_string().contains("db is closed"),
        "expected DB_CLOSED_ERROR, got: {}",
        sync_err
    );

    storage.mark_for_destroy();
}

#[test]
fn test_close_is_idempotent() {
    let path = create_test_db_path("test_close_is_idempotent");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "close_idempotent",
        create_test_options(),
    )
    .unwrap();

    storage.close(Some(Duration::from_secs(5))).expect("first close must succeed");
    storage.close(Some(Duration::from_secs(5))).expect("second close must short-circuit Ok");
    storage.close(None).expect("third close must short-circuit Ok");

    assert!(storage.is_closed());

    storage.mark_for_destroy();
}

#[test]
fn test_close_does_not_acknowledge_pending_barrier() {
    let path = create_test_db_path("close_pending");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "close_pending",
        create_test_options(),
    )
    .unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    storage
        .set(
            b"key".to_vec(),
            b"value".to_vec(),
            Some(Box::new(move |result| {
                result.unwrap();
                entered_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            })),
        )
        .wait()
        .unwrap();
    entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let closing = storage.clone();
    let close = std::thread::spawn(move || closing.close(Some(Duration::from_secs(10))));
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !storage.is_closed() {
        assert!(std::time::Instant::now() < deadline, "close never closed admission");
        std::thread::sleep(Duration::from_millis(1));
    }
    let repeated = storage.close(Some(Duration::from_secs(1)));
    release_tx.send(()).unwrap();
    close.join().unwrap().unwrap();
    assert!(repeated.is_err(), "pending close was incorrectly acknowledged");
    storage.close(Some(Duration::from_secs(5))).unwrap();
    storage.mark_for_destroy();
}

#[test]
fn test_close_rejects_pending_callback_results_without_blocking() {
    // If `set()` callback variant is posted after close(), both the
    // StorageAsyncResult and the on_complete callback must receive the
    // DB_CLOSED_ERROR without reaching the DB thread.
    let path = create_test_db_path("test_close_rejects_callbacks");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "close_cb_reject",
        create_test_options(),
    )
    .unwrap();

    storage.close(Some(Duration::from_secs(5))).unwrap();

    let cb_err = Arc::new(AtomicBool::new(false));
    let cb_err_clone = cb_err.clone();
    let async_result = storage.set(
        b"x".to_vec(),
        b"y".to_vec(),
        Some(Box::new(move |result| {
            if let Err(e) = result {
                if e.to_string().contains("db is closed") {
                    cb_err_clone.store(true, Ordering::SeqCst);
                }
            }
        })),
    );

    let err = async_result
        .wait_timeout(Duration::from_millis(100))
        .expect("async result must be immediate")
        .expect_err("must be Err");
    assert!(err.to_string().contains("db is closed"));
    assert!(
        cb_err.load(Ordering::SeqCst),
        "on_complete callback must have fired with DB_CLOSED_ERROR"
    );

    storage.mark_for_destroy();
}

#[test]
fn test_close_plus_destroy_removes_db_directory() {
    let path = create_test_db_path("test_close_destroy");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "close_destroy",
        create_test_options(),
    )
    .unwrap();

    storage
        .set(b"k".to_vec(), b"v".to_vec(), None)
        .wait_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap();
    storage.close(Some(Duration::from_secs(5))).unwrap();
    storage.mark_for_destroy();

    // Dropping the last Arc triggers the DB thread cleanup path:
    // drop(db) + remove_dir_all(&path) — the directory must vanish.
    drop(storage);

    // The DB thread removes the directory asynchronously after stop_internal
    // unwinds. Poll up to 5s for the directory to disappear.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if !path.exists() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!("DB directory {} must be removed after mark_for_destroy()+drop", path.display());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn test_drop_without_close_runs_safety_net_drain() {
    // If a caller forgets to close() (e.g. a panic unwinds the session),
    // Drop must still drain pending writes so the next open() sees them.
    let path = create_test_db_path("test_drop_safety_net");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "safety_net",
        create_test_options(),
    )
    .unwrap();

    for i in 0..50u32 {
        let _ =
            storage.set(format!("k{:04}", i).into_bytes(), format!("v{:04}", i).into_bytes(), None);
    }

    // Intentionally skip close() and drop immediately. Drop's safety-net
    // drain (`sync_internal(STOP_WAIT_TIMEOUT)`) must finish every write.
    drop(storage);

    // `RocksDb::new` uses `{path}/{storage_id}` — reopen with the SAME id.
    let reopened = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "safety_net",
        create_test_options(),
    )
    .unwrap();
    for i in 0..50u32 {
        let got = read_back(&reopened, format!("k{:04}", i).as_bytes());
        assert_eq!(got, Some(format!("v{:04}", i).into_bytes()), "missing i={}", i);
    }
    reopened.mark_for_destroy();
}

#[test]
fn test_close_no_callback_thread_variant() {
    // Exercise the `use_callback_thread = false` branch so the `close()`
    // short-circuit for "no callback queue" is covered.
    let path = create_test_db_path("test_close_no_callback_thread");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "close_no_cb",
        create_test_options_no_callback_thread(),
    )
    .unwrap();

    storage
        .set(b"k".to_vec(), b"v".to_vec(), None)
        .wait_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap();
    storage.close(Some(Duration::from_secs(5))).unwrap();
    assert!(storage.is_closed());

    let err = storage
        .set(b"post".to_vec(), b"late".to_vec(), None)
        .wait_timeout(Duration::from_secs(1))
        .expect("immediate")
        .expect_err("must be Err");
    assert!(err.to_string().contains("db is closed"));

    storage.mark_for_destroy();
}

#[test]
fn test_teardown_receipt_requires_last_reference_and_clean_join() {
    let path = create_test_db_path("teardown_receipt_clean");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "teardown_clean",
        create_test_options(),
    )
    .unwrap();
    let receipt = storage.teardown_receipt().expect("RocksDB storage certifies teardown");
    assert_eq!(receipt.path(), path.as_path());
    assert_eq!(receipt.storage_id(), "teardown_clean");
    assert!(receipt.same_instance(&storage.teardown_receipt().unwrap()));
    assert!(receipt.check().is_err(), "a live instance has no teardown outcome");
    let held = storage.clone();
    storage.close(Some(Duration::from_secs(5))).unwrap();
    assert!(receipt.check().is_err(), "a successful close is not a teardown");
    storage.mark_for_destroy();
    drop(storage);
    assert!(
        receipt.check().unwrap_err().to_string().contains("has not been torn down"),
        "another strong reference keeps the instance alive"
    );
    drop(held);
    receipt.check().unwrap();

    let other_path = create_test_db_path("teardown_receipt_other");
    let other = ConsensusCommonFactory::create_async_key_value_storage(
        &other_path,
        "teardown_other",
        create_test_options(),
    )
    .unwrap();
    assert!(!receipt.same_instance(&other.teardown_receipt().unwrap()));
    other.mark_for_destroy();
}

#[test]
fn test_teardown_receipt_is_invalidated_by_a_reopened_instance() {
    let path = create_test_db_path("teardown_receipt_reopen");
    let open = || {
        ConsensusCommonFactory::create_async_key_value_storage(
            &path,
            "teardown_reopen",
            create_test_options(),
        )
        .unwrap()
    };
    let first = open();
    let receipt = first.teardown_receipt().unwrap();
    drop(first);
    receipt.check().unwrap();
    let second = open();
    let error = receipt.check().unwrap_err().to_string();
    assert!(error.contains("reopened by a newer instance"), "{error}");
    let newer = second.teardown_receipt().unwrap();
    assert!(!receipt.same_instance(&newer));
    drop(second);
    newer.check().unwrap();
    assert!(receipt.check().is_err(), "an older receipt stays invalid after the newer drops");
    // An aliased path to the same directory shares the generation.
    let alias = path.join(".");
    let third = ConsensusCommonFactory::create_async_key_value_storage(
        &alias,
        "teardown_reopen",
        create_test_options(),
    )
    .unwrap();
    assert!(newer.check().is_err(), "an alias reopen invalidates the receipt");
    third.mark_for_destroy();
}

#[test]
fn test_storage_registration_fails_closed_and_rolls_back() {
    use std::os::unix::fs::PermissionsExt;
    let open = |path: &std::path::Path| {
        ConsensusCommonFactory::create_async_key_value_storage(
            path,
            "registration",
            create_test_options(),
        )
    };
    // A parent that is a regular file, or a symlinked database child, is
    // refused before anything is registered or started.
    let root = create_test_db_path("registration_refusals");
    let file_parent = root.join("file-parent");
    std::fs::write(&file_parent, b"x").unwrap();
    assert!(open(&file_parent).is_err());
    let real = root.join("real-db");
    std::fs::create_dir_all(&real).unwrap();
    let linked = root.join("linked-parent");
    std::fs::create_dir_all(&linked).unwrap();
    std::os::unix::fs::symlink(&real, linked.join("registration")).unwrap();
    assert!(open(&linked).is_err(), "a symlinked database child is refused");

    // A failed concurrent open at RocksDB's own lock rolls back its live count
    // but advances the generation: the live first instance stays unsatisfied
    // and its receipt never revives.
    let path = create_test_db_path("registration_interleaved");
    let first = open(&path).unwrap();
    let receipt = first.teardown_receipt().unwrap();
    assert!(open(&path).is_err(), "RocksDB admits one instance per directory");
    first.set(b"k".to_vec(), b"v".to_vec(), None).wait().unwrap();
    assert!(receipt.check().is_err(), "the first instance is still live");
    drop(first);
    let error = receipt.check().unwrap_err().to_string();
    assert!(error.contains("reopened by a newer instance"), "{error}");

    // A database init failure rolls back too: a later valid open and its
    // receipt behave normally.
    let database = path.join("registration");
    std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o000)).unwrap();
    let failed = open(&path);
    std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(failed.is_err(), "an unreadable database fails to initialize");
    let reopened = open(&path).unwrap();
    let newer = reopened.teardown_receipt().unwrap();
    reopened.mark_for_destroy();
    drop(reopened);
    newer.check().unwrap();
}

#[test]
fn test_teardown_receipt_rejects_detached_worker_thread() {
    let path = create_test_db_path("teardown_receipt_wedged");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path,
        "teardown_wedged",
        create_test_options(),
    )
    .unwrap();
    let receipt = storage.teardown_receipt().unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    storage
        .set(
            b"key".to_vec(),
            b"value".to_vec(),
            Some(Box::new(move |result| {
                result.unwrap();
                entered_tx.send(()).unwrap();
                // Hold the callback thread past the bounded stop wait.
                let _ = release_rx.recv_timeout(Duration::from_secs(120));
            })),
        )
        .wait()
        .unwrap();
    entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    storage.mark_for_destroy();
    drop(storage);
    let error = receipt.check().unwrap_err().to_string();
    assert!(error.contains("detached after stop timeout"), "{error}");
    release_tx.send(()).unwrap();
}

#[test]
fn test_cleanup_reservation_excludes_openers_and_needs_a_clean_idle_directory() {
    let path = create_test_db_path("cleanup_reservation");
    let open = || {
        ConsensusCommonFactory::create_async_key_value_storage(
            &path,
            "reserved",
            create_test_options(),
        )
    };
    // Never opened here: reservable, and no opener gets in while it is held.
    let reservation = crate::reserve_storage_cleanup(&path, "reserved").unwrap().unwrap();
    assert!(crate::reserve_storage_cleanup(&path, "reserved").unwrap().is_none());
    let refused = open().err().expect("open must be refused while reserved").to_string();
    assert!(refused.contains("reserved for cleanup"), "{refused}");
    drop(reservation);
    // A live instance is never reservable; its clean teardown makes it so.
    let storage = open().unwrap();
    assert!(crate::reserve_storage_cleanup(&path, "reserved").unwrap().is_none());
    drop(storage);
    let reservation = crate::reserve_storage_cleanup(&path, "reserved").unwrap().unwrap();
    assert!(reservation.key().ends_with("reserved"));
    drop(reservation);
    open().unwrap().mark_for_destroy();
}

#[test]
fn test_unclean_teardown_taints_the_directory_beyond_pruning() {
    let path = create_test_db_path("cleanup_taint");
    let (slot, _) = crate::register_storage_instance(&path, "tainted").unwrap();
    assert!(crate::reserve_storage_cleanup(&path, "tainted").unwrap().is_none());
    crate::release_storage_instance(&slot, false);
    assert!(crate::reserve_storage_cleanup(&path, "tainted").unwrap().is_none());
    // Dropping the last slot reference lets the registry prune it; the taint
    // survives, so the directory stays unreservable.
    drop(slot);
    let (other, _) = crate::register_storage_instance(&path, "unrelated").unwrap();
    crate::release_storage_instance(&other, true);
    drop(other);
    assert!(crate::reserve_storage_cleanup(&path, "tainted").unwrap().is_none());
    assert!(crate::reserve_storage_cleanup(&path, "unrelated").unwrap().is_some());
}

#[test]
fn test_taint_is_sticky_per_key_and_overflow_disables_reservations() {
    let mut taint = crate::StorageTaint { keys: Default::default(), overflowed: false };
    let key = PathBuf::from("/a/one");
    assert!(!taint.record(key.clone(), 2));
    assert!(!taint.record(key.clone(), 2), "a repeated failure adds nothing");
    assert_eq!(taint.keys.len(), 1);
    assert!(!taint.record(PathBuf::from("/a/two"), 2));
    assert!(taint.record(PathBuf::from("/a/three"), 2), "the first overflow reports");
    assert!(taint.overflowed);
    assert!(!taint.record(PathBuf::from("/a/four"), 2), "overflow reports once");
    assert_eq!(taint.keys.len(), 2, "taint is never evicted");
}

#[test]
fn test_cleanup_reservation_never_creates_a_missing_directory() {
    let root = create_test_db_path("cleanup_missing");
    let parent = root.join("gone").join("namespace");
    let reservation = crate::reserve_storage_cleanup(&parent, "sid").unwrap().unwrap();
    assert!(!root.join("gone").exists());
    // A later registration builds the same key, so it is excluded.
    let refused = crate::register_storage_instance(&parent, "sid").err().unwrap().to_string();
    assert!(refused.contains("reserved for cleanup"), "{refused}");
    drop(reservation);
    let (slot, _) = crate::register_storage_instance(&parent, "sid").unwrap();
    crate::release_storage_instance(&slot, true);
}

#[test]
fn test_unclean_release_publishes_its_taint_before_any_reservation_can_run() {
    let path = create_test_db_path("cleanup_taint_gap");
    let (unclean, _) = crate::register_storage_instance(&path, "gap").unwrap();
    let (clean, _) = crate::register_storage_instance(&path, "gap").unwrap();
    let key = std::fs::canonicalize(&path).unwrap().join("gap");
    let (result_tx, result_rx) = std::sync::mpsc::channel();
    let result_rx = Arc::new(std::sync::Mutex::new(result_rx));
    let racer: Arc<std::sync::Mutex<Option<std::thread::JoinHandle<()>>>> = Default::default();
    let held_in_gap = Arc::new(AtomicBool::new(false));
    let (racer_slot, racer_path, held, gap_rx) =
        (racer.clone(), path.clone(), held_in_gap.clone(), result_rx.clone());
    let hook: crate::ReleaseHook = Box::new(move || {
        // Inside the unclean release, slot updated, taint not yet recorded:
        // the other instance's clean release and a reservation must wait.
        let handle = std::thread::spawn(move || {
            crate::release_storage_instance(&clean, true);
            let reserved = crate::reserve_storage_cleanup(&racer_path, "gap").unwrap().is_some();
            result_tx.send(reserved).unwrap();
        });
        *racer_slot.lock().unwrap() = Some(handle);
        let raced = gap_rx.lock().unwrap().recv_timeout(Duration::from_millis(200)).is_ok();
        held.store(!raced, Ordering::SeqCst);
        false
    });
    *crate::RELEASE_HOOK.lock().unwrap() = Some((key, hook));
    crate::release_storage_instance(&unclean, false);
    racer.lock().unwrap().take().expect("the hook ran").join().unwrap();
    assert!(
        held_in_gap.load(Ordering::SeqCst),
        "the racing release and reservation were held while the unclean release ran"
    );
    assert!(!result_rx.lock().unwrap().recv().unwrap(), "no reservation after an unclean release");
}

#[test]
fn test_clean_release_never_clears_an_earlier_unclean_one() {
    let path = create_test_db_path("cleanup_sticky");
    let (unclean, _) = crate::register_storage_instance(&path, "sticky").unwrap();
    let (clean, _) = crate::register_storage_instance(&path, "sticky").unwrap();
    let key = std::fs::canonicalize(&path).unwrap().join("sticky");
    // Skip the taint record: the slot flag alone must refuse.
    *crate::RELEASE_HOOK.lock().unwrap() = Some((key, Box::new(|| true)));
    crate::release_storage_instance(&unclean, false);
    crate::release_storage_instance(&clean, true);
    assert!(crate::reserve_storage_cleanup(&path, "sticky").unwrap().is_none());
}

/// C++ KeyValueActor schedules one durable commit behind queued mutations.
/// Check actual WAL syscalls and recovery, rather than a mocked batch counter.
#[test]
#[cfg(target_os = "linux")]
fn test_queued_writes_share_durable_commit_and_survive_abrupt_exit() {
    use std::{io::Write, process::Command};
    const TEST: &str = "async_key_value_storage::tests::test_queued_writes_share_durable_commit_and_survive_abrupt_exit";
    const COUNT: usize = 8;
    if let Some(path) = std::env::var_os("RTOS_GROUP_COMMIT_PROBE_DB") {
        let storage = ConsensusCommonFactory::create_async_key_value_storage(
            PathBuf::from(path), "group-commit", create_test_options_no_callback_thread(),
        ).unwrap();
        let timeout = Duration::from_secs(10);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        storage.set(b"gate".to_vec(), b"durable".to_vec(), Some(Box::new(move |result| {
            result.unwrap();
            entered_tx.send(()).unwrap();
            release_rx.recv_timeout(timeout).unwrap();
        }))).wait_timeout(timeout).unwrap().unwrap();
        entered_rx.recv_timeout(timeout).unwrap();
        let (callback_tx, callback_rx) = std::sync::mpsc::channel();
        let pending: Vec<_> = (0..COUNT).map(|i| {
            let tx = callback_tx.clone();
            storage.set(format!("queued-{i}").into_bytes(), vec![i as u8; 1024],
                Some(Box::new(move |result| { tx.send(result.is_ok()).unwrap(); })))
        }).collect();
        let fault = std::env::var("RTOS_GROUP_COMMIT_FAULT").as_deref() == Ok("eio");
        if fault {
            std::fs::write(std::env::var_os("RTOS_WAL_FAIL_ARM").unwrap(), b"armed").unwrap();
        }
        std::io::stderr().write_all(b"GROUP_COMMIT_BEGIN\n").unwrap();
        release_tx.send(()).unwrap();
        for result in pending {
            assert_eq!(result.wait_timeout(timeout).unwrap().is_ok(), !fault);
        }
        for _ in 0..COUNT { assert_eq!(callback_rx.recv_timeout(timeout).unwrap(), !fault); }
        std::io::stderr().write_all(if fault {
            b"GROUP_COMMIT_REJECTED\n"
        } else {
            b"GROUP_COMMIT_ACKNOWLEDGED\n"
        }).unwrap();
        unsafe extern "C" { fn _exit(status: std::ffi::c_int) -> !; }
        unsafe { _exit(77) }
    }
    let path = std::fs::canonicalize(create_test_db_path("queued_group_commit")).unwrap();
    let trace = path.with_extension("strace");
    let output = Command::new("strace")
        .args(["-f", "-yy", "-e", "trace=write,writev,pwrite64,fdatasync,fsync", "-o"])
        .arg(&trace).arg(std::env::current_exe().unwrap())
        .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
        .env("RTOS_GROUP_COMMIT_PROBE_DB", &path).output().unwrap();
    assert_eq!(output.status.code(), Some(77), "{}", String::from_utf8_lossy(&output.stderr));
    let raw = std::fs::read_to_string(&trace).unwrap();
    let begin = raw.find("GROUP_COMMIT_BEGIN").unwrap();
    let end = raw.find("GROUP_COMMIT_ACKNOWLEDGED").unwrap();
    assert!(begin < end);
    let syncs = raw[begin..end].lines().filter(|line| {
        (line.contains("fdatasync(") || line.contains("fsync("))
            && line.contains(path.to_str().unwrap()) && line.contains(".log>")
    }).count();
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path, "group-commit", create_test_options_no_callback_thread(),
    ).unwrap();
    for i in 0..COUNT {
        assert_eq!(storage.get(format!("queued-{i}").into_bytes(), None).wait().unwrap(),
            Some(vec![i as u8; 1024]), "acknowledged data lost at abrupt exit");
    }
    storage.close(Some(Duration::from_secs(10))).unwrap();
    storage.mark_for_destroy();
    eprintln!("GROUP_COMMIT_TRACE {} WAL_SYNCS={syncs} RECOVERED={COUNT}", trace.display());
    assert_eq!(syncs, 1, "queued writes must share a durable WAL commit, as C++ does");
}

#[test]
fn test_queued_mutations_preserve_read_barriers_and_tombstone_order() {
    let path = create_test_db_path("queued_read_barriers");
    let storage = ConsensusCommonFactory::create_async_key_value_storage(
        &path, "barriers", create_test_options_no_callback_thread(),
    ).unwrap();
    let timeout = Duration::from_secs(10);
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    storage.set(b"gate".to_vec(), vec![], Some(Box::new(move |result| {
        result.unwrap();
        entered_tx.send(()).unwrap();
        release_rx.recv_timeout(timeout).unwrap();
    }))).wait_timeout(timeout).unwrap().unwrap();
    entered_rx.recv_timeout(timeout).unwrap();
    let first = storage.set(b"key".to_vec(), b"first".to_vec(), None);
    let before = storage.get(b"key".to_vec(), None);
    let second = storage.set(b"key".to_vec(), b"second".to_vec(), None);
    let erased = storage.erase(b"key".to_vec(), None);
    let after = storage.get(b"key".to_vec(), None);
    release_tx.send(()).unwrap();
    first.wait_timeout(timeout).unwrap().unwrap();
    assert_eq!(before.wait_timeout(timeout).unwrap().unwrap(), Some(b"first".to_vec()));
    second.wait_timeout(timeout).unwrap().unwrap();
    erased.wait_timeout(timeout).unwrap().unwrap();
    assert_eq!(after.wait_timeout(timeout).unwrap().unwrap(), None);
    storage.close(Some(timeout)).unwrap();
    drop(storage);
    let reopened = ConsensusCommonFactory::create_async_key_value_storage(
        &path, "barriers", create_test_options_no_callback_thread(),
    ).unwrap();
    assert_eq!(reopened.get(b"key".to_vec(), None).wait_timeout(timeout).unwrap().unwrap(), None);
    reopened.close(Some(timeout)).unwrap();
    reopened.mark_for_destroy();
}
