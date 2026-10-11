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
