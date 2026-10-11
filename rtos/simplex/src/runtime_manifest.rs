// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Durable role/transport manifest. It never provisions a signing capability.
use consensus_common::session_runtime::{AuthenticatedSessionRuntime, LocalRole};
use rtos_block::{error, fail, Result};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

pub(crate) struct RuntimeManifest {
    _locked: File,
}
impl RuntimeManifest {
    fn bytes(runtime: &AuthenticatedSessionRuntime) -> Result<Vec<u8>> {
        let (role, index) = match runtime.local_role() {
            LocalRole::Validator(index) => ("validator", Some(index)),
            LocalRole::Observer => ("observer", None),
        };
        let pin = runtime.pin();
        Ok(serde_json::to_vec(&serde_json::json!({
            "schema": 1,
            "role": role,
            "validator_index": index,
            "local_adnl": hex::encode(runtime.local_adnl().data()),
            "global_id": pin.global_id,
            "zerostate": pin.zerostate.to_string(),
            "profile": runtime.profile().to_hex_string(),
            "session": runtime.session_id().to_hex_string(),
            "shard_workchain": runtime.shard().workchain_id(),
            "shard_prefix": runtime.shard().shard_prefix_with_tag(),
            "catchain_seqno": runtime.catchain_seqno(),
            "simplex_protocol": runtime.protocol().version(),
            "carrier_version": runtime.carrier_version(),
            "wire_profile": runtime.wire_profile() as u8,
            "slots_per_window": runtime.slots_per_leader_window(),
            "committee": runtime.committee_digest()?.to_hex_string(),
        }))?)
    }
    /// Only a newly created observer directory may be initialized here. A
    /// validator directory requires separate explicit trusted provisioning.
    /// Existing directories with missing or malformed manifests never fall back
    /// to a fresh database. The held file lock spans the actual session worker.
    pub fn open(runtime: &AuthenticatedSessionRuntime, directory: &Path) -> Result<Self> {
        let expected = Self::bytes(runtime)?;
        let fresh = if directory.exists() {
            false
        } else {
            if runtime.local_role() != LocalRole::Observer {
                fail!("Validator runtime requires explicitly provisioned durable namespace");
            }
            if let Some(parent) = directory.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::create_dir(directory)?;
            true
        };
        let path = directory.join("session-runtime.json");
        let mut file = OpenOptions::new().read(true).write(true).create_new(fresh).open(&path)?;
        file.try_lock().map_err(|e| error!("Session runtime namespace already owned: {e}"))?;
        if fresh {
            file.write_all(&expected)?;
            file.sync_all()?;
            File::open(directory)?.sync_all()?;
            if let Some(parent) = directory.parent() {
                File::open(parent)?.sync_all()?;
            }
        } else {
            // A surviving manifest must not silently recreate a deleted/partial DB.
            // Even an interrupted first creation fails closed and requires explicit repair.
            if !directory.join(runtime.session_id().to_hex_string()).join("CURRENT").is_file() {
                fail!("Durable runtime database is missing; implicit empty recovery is forbidden");
            }
            let mut bytes = Vec::new();
            (&mut file).take((1 << 20) + 1).read_to_end(&mut bytes)?;
            if bytes != expected {
                fail!("Durable session runtime binding mismatch");
            }
        }
        Ok(Self { _locked: file })
    }
    #[cfg(test)]
    pub(crate) fn provision_test_validator(
        runtime: &AuthenticatedSessionRuntime,
        directory: &Path,
    ) -> Result<()> {
        if !matches!(runtime.local_role(), LocalRole::Validator(_)) {
            fail!("Test provisioning requires validator role");
        }
        std::fs::create_dir_all(directory)?;
        let database = crate::database::SimplexDb::open(directory, &runtime.session_id().to_hex_string())?;
        database.close(None)?;
        drop(database);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join("session-runtime.json"))?;
        file.write_all(&Self::bytes(runtime)?)?;
        file.sync_all()?;
        File::open(directory)?.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticated_fixture::runtime;

    #[test]
    fn authenticated_manifest_reopen_lock_and_domain_rejection() {
        let temp = crate::authenticated_fixture::TestDirectory::new();
        let directory = temp.path().join("observer");
        let (observer, _, _) = runtime(false);
        let first = RuntimeManifest::open(&observer, &directory).unwrap();
        assert!(RuntimeManifest::open(&observer, &directory).is_err());
        let database = crate::database::SimplexDb::open(&directory, &observer.session_id().to_hex_string()).unwrap();
        database.close(None).unwrap();
        drop(database);
        drop(first);
        let reopened = RuntimeManifest::open(&observer, &directory).unwrap();
        drop(reopened);
        let (validator, _, _) = runtime(true);
        let before = std::fs::read(directory.join("session-runtime.json")).unwrap();
        assert!(RuntimeManifest::open(&validator, &directory).is_err());
        assert_eq!(std::fs::read(directory.join("session-runtime.json")).unwrap(), before);
        let mut corrupt: serde_json::Value = serde_json::from_slice(&before).unwrap();
        for field in
            ["schema", "global_id", "simplex_protocol", "carrier_version", "slots_per_window"]
        {
            let original = corrupt[field].clone();
            corrupt[field] = serde_json::json!(991);
            let bytes = serde_json::to_vec(&corrupt).unwrap();
            std::fs::write(directory.join("session-runtime.json"), &bytes).unwrap();
            assert!(RuntimeManifest::open(&observer, &directory).is_err(), "{field}");
            assert_eq!(std::fs::read(directory.join("session-runtime.json")).unwrap(), bytes);
            corrupt[field] = original;
        }
        std::fs::remove_file(directory.join("session-runtime.json")).unwrap();
        assert!(RuntimeManifest::open(&observer, &directory).is_err());
    }

    #[test]
    fn authenticated_manifest_validator_never_implicitly_provisions() {
        let temp = crate::authenticated_fixture::TestDirectory::new();
        let directory = temp.path().join("validator");
        let (validator, _, _) = runtime(true);
        assert!(RuntimeManifest::open(&validator, &directory).is_err());
        assert!(!directory.exists());
        RuntimeManifest::provision_test_validator(&validator, &directory).unwrap();
        drop(RuntimeManifest::open(&validator, &directory).unwrap());
        let (observer, _, _) = runtime(false);
        assert!(RuntimeManifest::open(&observer, &directory).is_err());
        assert_ne!(
            validator.runtime_directory("root").unwrap(),
            observer.runtime_directory("root").unwrap()
        );
    }
}

#[cfg(test)]
#[test]
fn authenticated_manifest_missing_database_never_becomes_empty_recovery() {
    let temp = crate::authenticated_fixture::TestDirectory::new();
    let directory = temp.path().join("observer");
    let (runtime, _, _) = crate::authenticated_fixture::runtime(false);
    drop(RuntimeManifest::open(&runtime, &directory).unwrap());
    assert!(RuntimeManifest::open(&runtime, &directory).is_err());
    assert!(!directory.join(runtime.session_id().to_hex_string()).exists());
}
