// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Real ENOSPC on the production consensus WAL; run with the tmpfs harness.
//! Reopen is not a power-loss simulation. Controls use the identical operations.
use crate::{
    AsyncKeyValueStorageOptions, AsyncKeyValueStoragePtr, ConsensusCommonFactory,
    StorageAsyncResultPtr, StorageWriteCallback,
};
use std::{io::Write, path::Path, sync::mpsc, time::Duration};

const TIMEOUT: Duration = Duration::from_secs(10);

fn wait<T: Clone + Send + Sync + 'static>(result: StorageAsyncResultPtr<T>) -> crate::Result<T> {
    result.wait_timeout(TIMEOUT).expect("consensus operation timed out")
}

fn open(path: &Path, callbacks: bool) -> AsyncKeyValueStoragePtr {
    ConsensusCommonFactory::create_async_key_value_storage(
        path,
        "session",
        AsyncKeyValueStorageOptions { use_callback_thread: callbacks },
    )
    .unwrap()
}

fn fill(path: &Path) -> std::path::PathBuf {
    let filler = path.join("enospc-filler");
    let mut file = std::fs::File::create(&filler).unwrap();
    for size in [65536, 4096] {
        let chunk = vec![0; size];
        loop {
            match file.write_all(&chunk) {
                Ok(()) => (),
                Err(error) => {
                    assert_eq!(error.raw_os_error(), Some(28), "unexpected filler failure");
                    break;
                }
            }
        }
    }
    filler
}

fn exercise(erase: bool, callbacks: bool) {
    let operation = if erase { "erase" } else { "set" };
    let delivery = if callbacks { "callbacks" } else { "inline" };
    let case = format!("consensus-{operation}-{delivery}");
    let root = std::path::PathBuf::from(
        std::env::var_os("RTOS_ENOSPC_ROOT").expect("run inside the disk-full harness"),
    );
    let path = root.join(&case);
    std::fs::create_dir_all(&path).unwrap();
    let control = std::env::var("RTOS_ENOSPC_CONTROL").as_deref() == Ok("1");
    let storage = open(&path, callbacks);
    let keep = b"acknowledged certificate bytes".to_vec();
    // Force both a put and a tombstone beyond any already allocated WAL page.
    let target = vec![b't'; 65536];
    let previous = b"acknowledged signed vote bytes".to_vec();
    let intended = vec![0x5a; 65536];
    wait(storage.set(b"keep".to_vec(), keep.clone(), None)).unwrap();
    if erase {
        wait(storage.set(target.clone(), previous.clone(), None)).unwrap();
    }
    storage.flush_for_disk_full_test().unwrap();
    let filler = if control { None } else { Some(fill(&path)) };
    let (tx, rx) = mpsc::channel();
    let callback: StorageWriteCallback = Box::new(move |result| {
        tx.send(result.map_err(|error| format!("{error:#}"))).unwrap();
    });
    let result = if erase {
        wait(storage.erase(target.clone(), Some(callback)))
    } else {
        wait(storage.set(target.clone(), intended.clone(), Some(callback)))
    };
    let callback = rx.recv_timeout(TIMEOUT).expect("missing consensus callback");
    assert_eq!(result.is_ok(), control, "target acknowledgement: {result:?}");
    assert_eq!(callback.is_ok(), control, "target callback: {callback:?}");
    if !control {
        let error = format!("{:#}", result.unwrap_err());
        assert!(error.contains("No space left") || error.contains("ENOSPC"), "{error}");
    }
    if let Some(filler) = filler {
        std::fs::remove_file(filler).unwrap();
    }
    // Independent probe: never repair the failed target before inspecting it.
    let probe = wait(storage.set(b"probe".to_vec(), b"after freeing space".to_vec(), None));
    assert_eq!(probe.is_ok(), control, "latched RocksDB write error: {probe:?}");
    drop(storage);

    let storage = open(&path, callbacks);
    assert_eq!(wait(storage.get(b"keep".to_vec(), None)).unwrap(), Some(keep.clone()));
    let recovered = wait(storage.get(target.clone(), None)).unwrap();
    if erase {
        if control {
            assert_eq!(recovered, None);
        } else {
            assert!(recovered == Some(previous) || recovered.is_none(), "torn erase recovery");
        }
    } else if control {
        assert_eq!(recovered, Some(intended.clone()));
    } else {
        assert!(recovered.is_none() || recovered == Some(intended.clone()), "torn set recovery");
    }
    assert_eq!(
        wait(storage.get(b"probe".to_vec(), None)).unwrap(),
        if control { Some(b"after freeing space".to_vec()) } else { None },
    );
    let retry = if erase {
        storage.erase(target.clone(), None)
    } else {
        storage.set(target.clone(), intended.clone(), None)
    };
    wait(retry).unwrap();
    storage.close(Some(TIMEOUT)).unwrap();
    drop(storage);
    let storage = open(&path, callbacks);
    assert_eq!(wait(storage.get(b"keep".to_vec(), None)).unwrap(), Some(keep));
    assert_eq!(wait(storage.get(target, None)).unwrap(), if erase { None } else { Some(intended) },);
    storage.close(Some(TIMEOUT)).unwrap();
    drop(storage);
    eprintln!("ENOSPC-CASE {case} {} ok", if control { "control" } else { "fault" });
}

#[test]
#[ignore = "requires isolated ENOSPC tmpfs and syscall trace"]
fn disk_full_consensus_set_callbacks() {
    exercise(false, true);
}

#[test]
#[ignore = "requires isolated ENOSPC tmpfs and syscall trace"]
fn disk_full_consensus_set_inline() {
    exercise(false, false);
}

#[test]
#[ignore = "requires isolated ENOSPC tmpfs and syscall trace"]
fn disk_full_consensus_erase_callbacks() {
    exercise(true, true);
}

#[test]
#[ignore = "requires isolated ENOSPC tmpfs and syscall trace"]
fn disk_full_consensus_erase_inline() {
    exercise(true, false);
}
