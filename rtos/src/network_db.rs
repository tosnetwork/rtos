// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Local database ownership by a complete, explicitly configured network anchor.
//! This is not a chain proof, snapshot authenticator, or validator signing fence.
use rtos_block::{error, fail, BlockIdExt, Result, UInt256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

const LOCK: &str = "rtos-network.lock";
const BINDING: &str = "rtos-network.bin";
const MAGIC: &[u8] = b"RTOS-NETWORK-DB-v1\n";

/// Held for the engine lifetime. The OS releases the advisory lock on exit.
/// It serializes participating RTOS starts, not unrelated database utilities.
pub(crate) struct DbNetworkBinding {
    _lock: File,
}

impl DbNetworkBinding {
    /// Must finish before any network startup, database creation, upgrade,
    /// truncation or recovery. An unbound nonempty directory is never adopted.
    pub(crate) fn acquire(directory: &Path, anchor: &BlockIdExt) -> Result<Self> {
        if !anchor.shard().is_masterchain_ext()
            || anchor.seq_no != 0
            || anchor.root_hash == UInt256::default()
            || anchor.file_hash == UInt256::default()
        {
            fail!("Database binding requires a complete masterchain zerostate anchor");
        }
        let mut expected = MAGIC.to_vec();
        expected.extend_from_slice(&anchor.shard().workchain_id().to_le_bytes());
        expected.extend_from_slice(&anchor.shard().shard_prefix_with_tag().to_le_bytes());
        expected.extend_from_slice(&anchor.seq_no.to_le_bytes());
        expected.extend_from_slice(anchor.root_hash.as_slice());
        expected.extend_from_slice(anchor.file_hash.as_slice());

        fs::create_dir_all(directory)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join(LOCK))?;
        lock.try_lock().map_err(|e| {
            error!("Database network binding is already in use or cannot be locked: {e}")
        })?;
        let binding_path = directory.join(BINDING);
        let binding = match OpenOptions::new().read(true).write(true).open(&binding_path) {
            Ok(mut file) => {
                // Bound reads also reject unknown versions, truncation and trailing data.
                let mut actual = Vec::new();
                Read::by_ref(&mut file).take(expected.len() as u64 + 1).read_to_end(&mut actual)?;
                if actual != expected {
                    fail!("Database network binding mismatch or invalid record; refusing to open database");
                }
                file
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                for entry in fs::read_dir(directory)? {
                    if entry?.file_name() != LOCK {
                        fail!("Existing database directory has no network binding; use a fresh directory or an authenticated migration");
                    }
                }
                let mut file =
                    OpenOptions::new().write(true).create_new(true).open(&binding_path)?;
                // A crash during this small write leaves a record that is either
                // exact or rejected. No database writes have started at this point.
                file.write_all(&expected)?;
                file
            }
            Err(e) => return Err(e.into()),
        };
        // Also sync a matching record after restart: its prior writer may have
        // exited between write and fsync. Never open the DB before both barriers.
        binding.sync_all()?;
        File::open(directory)?.sync_all()?;
        Ok(Self { _lock: lock })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtos_block::ShardIdent;
    fn anchor() -> BlockIdExt {
        BlockIdExt::with_params(
            ShardIdent::masterchain(),
            0,
            UInt256::from([1; 32]),
            UInt256::from([2; 32]),
        )
    }

    #[test]
    fn persists_anchor_and_rejects_other_network_before_modifying_data() {
        let dir = tempfile::tempdir().unwrap();
        let id = anchor();
        let guard = DbNetworkBinding::acquire(dir.path(), &id).unwrap();
        assert!(DbNetworkBinding::acquire(dir.path(), &id).is_err());
        fs::write(dir.path().join("existing-data"), b"unchanged").unwrap();
        let record = fs::read(dir.path().join(BINDING)).unwrap();
        drop(guard);
        for change_root in [false, true] {
            let mut other = id.clone();
            if change_root {
                other.root_hash = UInt256::from([3; 32]);
            } else {
                other.file_hash = UInt256::from([4; 32]);
            }
            assert!(DbNetworkBinding::acquire(dir.path(), &other)
                .err()
                .unwrap()
                .to_string()
                .contains("mismatch"));
            assert_eq!(fs::read(dir.path().join(BINDING)).unwrap(), record);
            assert_eq!(fs::read(dir.path().join("existing-data")).unwrap(), b"unchanged");
        }
        DbNetworkBinding::acquire(dir.path(), &id).unwrap();
    }

    #[test]
    fn refuses_unbound_existing_or_incomplete_records_without_repair() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("old-db"), b"legacy").unwrap();
        assert!(DbNetworkBinding::acquire(dir.path(), &anchor()).is_err());
        assert!(!dir.path().join(BINDING).exists());
        assert_eq!(fs::read(dir.path().join("old-db")).unwrap(), b"legacy");
        for contents in [vec![], b"RTOS-NETWORK-DB-v2\n".to_vec(), vec![0; 200]] {
            let dir = tempfile::tempdir().unwrap();
            fs::write(dir.path().join(BINDING), &contents).unwrap();
            assert!(DbNetworkBinding::acquire(dir.path(), &anchor()).is_err());
            assert_eq!(fs::read(dir.path().join(BINDING)).unwrap(), contents);
        }
    }

    #[test]
    fn invalid_anchor_does_not_create_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-created");
        for mutation in 0..4 {
            let mut id = anchor();
            match mutation {
                0 => id.seq_no = 1,
                1 => id.shard_id = ShardIdent::full(0),
                2 => id.root_hash = UInt256::default(),
                _ => id.file_hash = UInt256::default(),
            }
            assert!(DbNetworkBinding::acquire(&path, &id).is_err());
            assert!(!path.exists());
        }
    }
    #[test]
    fn lock_is_released_after_process_death_without_losing_binding() {
        use std::{
            process::{Child, Command, Stdio},
            time::{Duration, Instant},
        };
        struct KillOnDrop(Child);
        impl Drop for KillOnDrop {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("db");
        let ready = dir.path().join("ready");
        let mut child = KillOnDrop(
            Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", "network_db::tests::process_lock_child"])
                .env("RTOS_DB_BINDING_CHILD_ROOT", &root)
                .env("RTOS_DB_BINDING_CHILD_READY", &ready)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() {
            assert!(Instant::now() < deadline, "child did not acquire binding");
            assert!(child.0.try_wait().unwrap().is_none(), "child exited prematurely");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(DbNetworkBinding::acquire(&root, &anchor()).is_err());
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        DbNetworkBinding::acquire(&root, &anchor()).unwrap();
        let mut different = anchor();
        different.file_hash = UInt256::from([5; 32]);
        assert!(DbNetworkBinding::acquire(&root, &different).is_err());
    }

    #[test]
    #[ignore = "helper launched by lock_is_released_after_process_death_without_losing_binding"]
    fn process_lock_child() {
        let root = std::env::var_os("RTOS_DB_BINDING_CHILD_ROOT").unwrap();
        let ready = std::env::var_os("RTOS_DB_BINDING_CHILD_READY").unwrap();
        let _binding = DbNetworkBinding::acquire(Path::new(&root), &anchor()).unwrap();
        fs::write(ready, b"bound").unwrap();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
}
