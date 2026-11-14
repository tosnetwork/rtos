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
    /// Locks an existing namespace for retirement preparation without ever
    /// provisioning: a missing or symlinked manifest or database is refused.
    /// Returns the digest of the exact manifest bytes that were verified.
    pub(crate) fn open_existing(
        runtime: &AuthenticatedSessionRuntime,
        directory: &Path,
        charge: &mut crate::finality_delivery::source_retirement::Charge,
    ) -> crate::finality_delivery::source_retirement::Refusal<(Self, rtos_block::UInt256)> {
        use crate::finality_delivery::source_retirement::{
            existing_directory, failed, manifest_workspace, Bucket, RetirementRefusal,
            MANIFEST_WORKSPACE,
        };
        const MAX_MANIFEST_BYTES: u64 = 1 << 20;
        charge.workspace("manifest", manifest_workspace(runtime.committee().len())?)?;
        let expected = Self::bytes(runtime).map_err(failed)?;
        if expected.len() > MANIFEST_WORKSPACE {
            return Err(RetirementRefusal::Manifest("manifest exceeds its workspace bound".into()));
        }
        let path = directory.join("session-runtime.json");
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_file() => {}
            Ok(_) => return Err(RetirementRefusal::UnknownArtifact(path)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(RetirementRefusal::Missing(path))
            }
            Err(e) => return Err(failed(e)),
        }
        let mut file = File::open(&path).map_err(failed)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Err(RetirementRefusal::Busy),
            Err(e) => return Err(failed(e)),
        }
        let database = directory.join(runtime.session_id().to_hex_string());
        existing_directory(&database)?;
        let current = database.join("CURRENT");
        match std::fs::symlink_metadata(&current) {
            Ok(m) if m.file_type().is_file() => {}
            Ok(_) => return Err(RetirementRefusal::UnknownArtifact(current)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(RetirementRefusal::Missing(current))
            }
            Err(e) => return Err(failed(e)),
        }
        let length = file.metadata().map_err(failed)?.len();
        if length > MAX_MANIFEST_BYTES {
            return Err(RetirementRefusal::Manifest("manifest oversized".into()));
        }
        charge.read(Bucket::Manifest, usize::try_from(length).map_err(failed)?)?;
        let mut bytes = Vec::new();
        (&mut file).take(MAX_MANIFEST_BYTES + 1).read_to_end(&mut bytes).map_err(failed)?;
        if bytes != expected {
            return Err(RetirementRefusal::Manifest("runtime binding mismatch".into()));
        }
        Ok((Self { _locked: file }, rtos_block::UInt256::calc_file_hash(&bytes)))
    }
    /// The namespace of a validator that signs with its custody signer, as the
    /// reference node opens its consensus database: an existing namespace is
    /// verified exactly as `open` does; a missing one is created first, with
    /// its empty database and manifest durable before the session uses it.
    pub fn open_or_provision_validator(
        runtime: &AuthenticatedSessionRuntime,
        directory: &Path,
    ) -> Result<Self> {
        if !matches!(runtime.local_role(), LocalRole::Validator(_)) {
            fail!("Validator namespace provisioning requires validator role");
        }
        match std::fs::symlink_metadata(directory) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Self::provision_validator(runtime, directory)?;
            }
            Err(error) => return Err(error.into()),
        }
        Self::open(runtime, directory)
    }
    #[cfg(any(test, feature = "integration-test-support"))]
    pub(crate) fn provision_test_validator(
        runtime: &AuthenticatedSessionRuntime,
        directory: &Path,
    ) -> Result<()> {
        Self::provision_validator(runtime, directory)
    }
    fn provision_validator(runtime: &AuthenticatedSessionRuntime, directory: &Path) -> Result<()> {
        if !matches!(runtime.local_role(), LocalRole::Validator(_)) {
            fail!("Validator namespace provisioning requires validator role");
        }
        // Explicit fixture provisioning never repairs or completes an existing
        // namespace. Atomic create_dir rejects existing files, directories and
        // symlinks before any database or manifest write.
        if let Some(parent) = directory.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::create_dir(directory)?;
        let database =
            crate::database::SimplexDb::open(directory, &runtime.session_id().to_hex_string())?;
        database.close(None)?;
        drop(database);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join("session-runtime.json"))?;
        file.write_all(&Self::bytes(runtime)?)?;
        file.sync_all()?;
        File::open(directory)?.sync_all()?;
        if let Some(parent) = directory.parent() {
            File::open(parent)?.sync_all()?;
        }
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
        let database =
            crate::database::SimplexDb::open(&directory, &observer.session_id().to_hex_string())
                .unwrap();
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
    fn authenticated_manifest_provisioning_rejects_existing_namespace_unchanged() {
        let temp = crate::authenticated_fixture::TestDirectory::new();
        let directory = temp.path().join("existing-validator");
        let (validator, _, _) = runtime(true);
        std::fs::create_dir(&directory).unwrap();
        let sentinel = directory.join("retained-source");
        std::fs::write(&sentinel, b"original debt").unwrap();
        let error = RuntimeManifest::provision_test_validator(&validator, &directory).unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"original debt");
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
        assert!(!directory.join("session-runtime.json").exists());
        assert!(!directory.join(validator.session_id().to_hex_string()).exists());
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

    /// A custody-signed validator creates a missing namespace on first use and
    /// afterwards reopens exactly that namespace; an existing namespace is
    /// verified, never recreated, and a manifest of another binding is refused.
    #[test]
    fn authenticated_manifest_custody_validator_creates_its_namespace_once() {
        let temp = crate::authenticated_fixture::TestDirectory::new();
        let directory = temp.path().join("custody-validator");
        let (validator, _, _) = runtime(true);
        let first = RuntimeManifest::open_or_provision_validator(&validator, &directory).unwrap();
        let manifest = std::fs::read(directory.join("session-runtime.json")).unwrap();
        assert!(directory.join(validator.session_id().to_hex_string()).join("CURRENT").is_file());
        // The held lock spans the session.
        assert!(RuntimeManifest::open_or_provision_validator(&validator, &directory).is_err());
        drop(first);
        drop(RuntimeManifest::open_or_provision_validator(&validator, &directory).unwrap());
        assert_eq!(std::fs::read(directory.join("session-runtime.json")).unwrap(), manifest);
        let (observer, _, _) = runtime(false);
        assert!(RuntimeManifest::open_or_provision_validator(&observer, &directory).is_err());
        assert!(RuntimeManifest::open(&observer, &directory).is_err());
        // A namespace whose database is gone is not silently recreated.
        std::fs::remove_dir_all(directory.join(validator.session_id().to_hex_string())).unwrap();
        assert!(RuntimeManifest::open_or_provision_validator(&validator, &directory).is_err());
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
