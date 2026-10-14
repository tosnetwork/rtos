// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Physical SST fixtures for real owning-queue tests, not authenticated consensus.
use crate::{
    AsyncKeyValueStoragePtr, Result, StorageAsyncResultPtr, TestSstAction, TestSstSnapshot,
};
use rtos_block::UInt256;
use std::{
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
pub const TIMEOUT: Duration = Duration::from_secs(10);

pub fn wait<T: Clone + Send + Sync + 'static>(result: StorageAsyncResultPtr<T>) -> Result<T> {
    result
        .wait_timeout(TIMEOUT)
        .expect("actual SST queue completion timed out; no reopen authorized")
}
pub fn native(storage: &AsyncKeyValueStoragePtr, action: TestSstAction) -> Result<TestSstSnapshot> {
    wait(storage.sst_for_test(action))
}
pub fn raw(storage: &AsyncKeyValueStoragePtr) -> Vec<(Vec<u8>, Vec<u8>)> {
    wait(storage.get_by_prefix(Vec::new(), None)).unwrap()
}
pub fn root(case: &str) -> PathBuf {
    PathBuf::from(std::env::var_os("RTOS_ENOSPC_ROOT").expect("private SST harness required"))
        .join(case)
}
pub fn control() -> bool {
    std::env::var("RTOS_ENOSPC_CONTROL").as_deref() == Ok("1")
}
pub fn fill(path: &Path) -> PathBuf {
    let path = path.join("enospc-filler");
    let mut file = std::fs::File::create(&path).unwrap();
    for size in [65536, 4096] {
        loop {
            match file.write_all(&vec![0; size]) {
                Ok(()) => (),
                Err(e) => {
                    assert_eq!(e.raw_os_error(), Some(28));
                    break;
                }
            }
        }
    }
    path
}
pub fn seed(storage: &AsyncKeyValueStoragePtr) -> TestSstSnapshot {
    storage.sync(Some(TIMEOUT)).unwrap();
    native(storage, TestSstAction::Flush).unwrap();
    let seed = native(storage, TestSstAction::Compact { force: false }).unwrap();
    assert_eq!(seed.files.len(), 1, "seed default SST count");
    assert_eq!(seed.files[0].cf, "default");
    assert_eq!(seed.files[0].level, 6, "seed bottommost SST");
    seed
}
pub fn inputs(
    storage: &AsyncKeyValueStoragePtr,
    seed: &TestSstSnapshot,
    compact: bool,
) -> TestSstSnapshot {
    storage.sync(Some(TIMEOUT)).unwrap();
    let unflushed = native(storage, TestSstAction::Inspect).unwrap();
    assert_eq!(unflushed.files, seed.files, "target unexpectedly auto-flushed");
    if compact {
        native(storage, TestSstAction::Flush).unwrap();
    }
    let before = native(storage, TestSstAction::Inspect).unwrap();
    assert_eq!(before.files.len(), if compact { 2 } else { 1 });
    if compact {
        let target = before.files.iter().find(|f| f.level == 0).expect("target L0 SST");
        assert!(
            target.start <= seed.files[0].end && target.end >= seed.files[0].start,
            "actual SST key ranges must overlap"
        );
    }
    for f in &before.files {
        let bytes =
            std::fs::read(before.physical_path.join(f.name.trim_start_matches('/'))).unwrap();
        eprintln!(
            "SST-INPUT name={} cf={} level={} size={} range={:?}/{:?} sha256={:x}",
            f.name,
            f.cf,
            f.level,
            f.size,
            f.start,
            f.end,
            UInt256::calc_file_hash(&bytes)
        );
    }
    before
}
pub fn run(
    storage: &AsyncKeyValueStoragePtr,
    before: &TestSstSnapshot,
    compact: bool,
    control: bool,
) {
    let result = native(
        storage,
        if compact { TestSstAction::Compact { force: true } } else { TestSstAction::Flush },
    );
    eprintln!("SST-OBS queued-native-result={result:?}");
    if compact {
        assert!(
            result.as_ref().unwrap().compact_returned_unit,
            "compact completion is only a unit marker"
        );
    } else {
        assert_eq!(result.is_ok(), control, "queued SST flush propagation: {result:?}");
        if let Err(e) = &result {
            let s = format!("{e:#}");
            assert!(s.contains("No space left") || s.contains("ENOSPC"), "{s}");
        }
    }
    let after = native(storage, TestSstAction::Inspect).unwrap();
    if control {
        let fresh: Vec<_> = after
            .files
            .iter()
            .filter(|f| !before.files.iter().any(|old| old.name == f.name))
            .collect();
        assert!(!fresh.is_empty(), "queued SST positive operation did not register rewrite");
        for f in fresh {
            let bytes =
                std::fs::read(after.physical_path.join(f.name.trim_start_matches('/'))).unwrap();
            eprintln!(
                "SST-OUTPUT name={} cf={} level={} sha256={:x}",
                f.name,
                f.cf,
                f.level,
                UInt256::calc_file_hash(&bytes)
            );
        }
    } else {
        assert_eq!(after.files, before.files, "failed queued SST changed registered inputs");
    }
    eprintln!(
        "SST-OBS background_errors={:?} running_flushes={:?} running_compactions={:?}",
        after.background_errors, after.running_flushes, after.running_compactions
    );
}
pub fn retry(storage: &AsyncKeyValueStoragePtr, compact: bool) {
    native(
        storage,
        if compact { TestSstAction::Compact { force: true } } else { TestSstAction::Flush },
    )
    .unwrap();
    storage.sync(Some(TIMEOUT)).unwrap();
}
pub fn close(storage: AsyncKeyValueStoragePtr) {
    let receipt = storage.teardown_receipt().expect("actual teardown receipt required");
    storage.close(Some(TIMEOUT)).expect("actual SST storage close failed");
    assert!(
        wait(storage.sst_for_test(TestSstAction::Inspect)).is_err(),
        "SST test hook must respect closed gate"
    );
    drop(storage);
    receipt.check().expect("actual DB/callback/native teardown did not complete");
    eprintln!("SST-OBS teardown-receipt=clean");
}
