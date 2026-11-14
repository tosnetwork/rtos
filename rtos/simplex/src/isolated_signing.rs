// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Explicitly provisioned signing for isolated executable builds.
//! Provisioning is offline; a live session can only recover the exact journal.
use consensus_common::session_runtime::{AuthenticatedSessionRuntime, LocalRole};
use rtos_block::{error, fail, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

pub const PROFILE_FILE: &str = "isolated-signing.json";
mod schedule;
pub use schedule::{provision_schedule, SCHEDULE_FILE};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    schema: u32,
    network: String,
    global_id: i32,
    session: String,
    profile: String,
    committee: String,
    local_adnl: String,
    validator: String,
    database: PathBuf,
    owner_root: PathBuf,
    key_file: PathBuf,
    generation: u64,
    expire_at: u32,
}
impl Profile {
    fn expected(
        runtime: &AuthenticatedSessionRuntime,
        namespace: &Path,
        owner_root: &Path,
        key_file: &Path,
        generation: u64,
        expire_at: u32,
    ) -> Result<Self> {
        let LocalRole::Validator(index) = runtime.local_role() else {
            fail!("Isolated signer requires authenticated validator role");
        };
        if generation == 0 || expire_at == 0 {
            fail!("Isolated signer requires explicit generation and expiry");
        }
        let member = runtime
            .committee()
            .get(index as usize)
            .ok_or_else(|| error!("Isolated signer committee index is invalid"))?;
        Ok(Self {
            schema: 1,
            network: runtime.pin().zerostate.to_string(),
            global_id: runtime.pin().global_id,
            session: runtime.session_id().to_hex_string(),
            profile: runtime.profile().to_hex_string(),
            committee: runtime.committee_digest()?.to_hex_string(),
            local_adnl: hex::encode(runtime.local_adnl().data()),
            validator: member.validator_id()?.to_hex_string(),
            database: namespace.join(runtime.session_id().to_hex_string()).canonicalize()?,
            owner_root: owner_root.canonicalize()?,
            key_file: key_file.canonicalize()?,
            generation,
            expire_at,
        })
    }
    fn signer(
        &self,
        runtime: &AuthenticatedSessionRuntime,
        namespace: &Path,
        initialize: bool,
    ) -> Result<crate::signing_coordinator::TestSessionSigner> {
        let expected = Self::expected(
            runtime,
            namespace,
            &self.owner_root,
            &self.key_file,
            self.generation,
            self.expire_at,
        )?;
        if serde_json::to_vec(self)? != serde_json::to_vec(&expected)? {
            fail!("Isolated signer profile differs from authenticated session or database");
        }
        let store =
            Arc::new(rtos_pq_consensus::load_consensus_key(&self.key_file, self.expire_at)?);
        let LocalRole::Validator(index) = runtime.local_role() else { unreachable!() };
        let member = &runtime.committee()[index as usize];
        if member.pq_key().ok_or_else(|| error!("Isolated signer requires a PQ descriptor"))?
            != store.consensus_key()
            || store.expired_now()
        {
            fail!("Isolated custody key differs from authenticated descriptor or has expired");
        }
        Ok(crate::signing_coordinator::TestSessionSigner {
            store,
            owner_root: self.owner_root.clone(),
            generation: self.generation,
            initialize,
        })
    }
}

/// Explicit one-time preparation of a fresh isolated validator namespace.
/// Existing or incomplete namespaces are refused. No caller gets signing
/// authority if provisioning fails between ownership, journal and profile sync.
pub fn provision(
    runtime: &AuthenticatedSessionRuntime,
    namespace: &Path,
    owner_root: &Path,
    key_file: &Path,
    generation: u64,
    expire_at: u32,
) -> Result<()> {
    if runtime.protocol()
        != consensus_common::simplex_protocol::SimplexProtocol::PrivateObserversPlumtree
        || runtime.wire_profile() != rtos_api::WireProfile::T0
        || generation == 0
        || expire_at == 0
    {
        fail!(
            "Isolated provisioning requires explicit T0 protocol2 identity, generation and expiry"
        );
    }
    let LocalRole::Validator(index) = runtime.local_role() else {
        fail!("Isolated provisioning requires a validator");
    };
    let store = rtos_pq_consensus::load_consensus_key(key_file, expire_at)?;
    if runtime.committee()[index as usize]
        .pq_key()
        .ok_or_else(|| error!("Isolated provisioning requires PQ custody"))?
        != store.consensus_key()
        || store.expired_now()
    {
        fail!("Isolated provisioning key is unavailable for this descriptor");
    }
    if !owner_root.is_dir() {
        fail!("Isolated ownership directory must be provisioned explicitly");
    }
    crate::runtime_manifest::RuntimeManifest::provision_test_validator(runtime, namespace)?;
    let profile =
        Profile::expected(runtime, namespace, owner_root, key_file, generation, expire_at)?;
    let signer = profile.signer(runtime, namespace, true)?;
    let db = crate::database::SimplexDb::open(namespace, &runtime.session_id().to_hex_string())?;
    let opened = signer.open(runtime, db.clone());
    match opened {
        Ok(coordinator) => drop(coordinator),
        Err(error) => {
            let _ = db.close(None);
            return Err(error);
        }
    }
    db.close(None)?;
    drop(db);
    let mut file =
        OpenOptions::new().write(true).create_new(true).open(namespace.join(PROFILE_FILE))?;
    file.write_all(&serde_json::to_vec(&profile)?)?;
    file.sync_all()?;
    File::open(namespace)?.sync_all()?;
    Ok(())
}

pub(crate) fn recover(
    runtime: &AuthenticatedSessionRuntime,
    namespace: &Path,
) -> Result<crate::signing_coordinator::TestSessionSigner> {
    let file = File::open(namespace.join(PROFILE_FILE))?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > 16_384 {
        fail!("Invalid isolated signing profile");
    }
    let mut bytes = Vec::new();
    file.take(16_385).read_to_end(&mut bytes)?;
    if bytes.len() > 16_384 {
        fail!("Isolated signing profile grew beyond limit");
    }
    let profile: Profile = serde_json::from_slice(&bytes)?;
    profile.signer(runtime, namespace, false)
}

impl crate::SessionFactory {
    #[allow(clippy::too_many_arguments)]
    pub fn create_isolated_authenticated_session_checked(
        options: &crate::SessionOptions,
        runtime: Arc<AuthenticatedSessionRuntime>,
        local_transport_key: &consensus_common::PrivateKey,
        db_path: String,
        overlay_manager: consensus_common::ConsensusOverlayManagerPtr,
        listener: crate::SessionListenerPtr,
        trace_collector: Option<crate::TraceCollector>,
        delivery_sink: Option<consensus_common::finality_delivery::DurableFinalitySinkPtr>,
        delivered: Option<crate::finality_delivery::DeliveredCompletionSink>,
    ) -> std::result::Result<crate::SessionPtr, crate::SessionCreationFailure> {
        let prepare = || -> Result<_> {
            options.validate_authenticated(&runtime)?;
            if runtime.local_adnl() != local_transport_key.id() || delivery_sink.is_none() {
                fail!("Isolated session requires matching transport and durable delivery sink");
            }
            let signer = schedule::recover_or_provision(&runtime, Path::new(&db_path))?;
            let nodes = runtime
                .committee()
                .iter()
                .map(crate::SimplexSessionNode::from_descriptor)
                .collect::<Result<Vec<_>>>()?;
            Ok((signer, nodes))
        };
        let (signer, nodes) = prepare().map_err(crate::SessionCreationFailure::before_worker)?;
        let mut checked = options.clone();
        checked.wait_for_db_init = true;
        match delivered {
            Some(delivered) => crate::session::SessionImpl::create_with_profile_delivered_checked(
                &checked,
                runtime.session_id(),
                runtime.shard(),
                nodes,
                local_transport_key,
                db_path,
                overlay_manager,
                listener,
                trace_collector,
                runtime.catchain_seqno(),
                Some(runtime.clone()),
                delivery_sink,
                Some(delivered),
                false,
                Some(crate::signing_coordinator::OwnSigner::Isolated(signer)),
            ),
            None => crate::session::SessionImpl::create_with_profile_checked(
                &checked,
                runtime.session_id(),
                runtime.shard(),
                nodes,
                local_transport_key,
                db_path,
                overlay_manager,
                listener,
                trace_collector,
                runtime.catchain_seqno(),
                Some(runtime.clone()),
                delivery_sink,
                false,
                Some(crate::signing_coordinator::OwnSigner::Isolated(signer)),
            ),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn isolated_profile_requires_exact_provisioned_identity() {
        let directory = crate::authenticated_fixture::TestDirectory::new();
        let root = directory.path();
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = root.join("public-test-seed");
        std::fs::write(&key, [0xa0; 32]).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let owner = root.join("owner");
        std::fs::create_dir(&owner).unwrap();
        let (runtime, _, _) = crate::authenticated_fixture::runtime(true);
        let namespace = PathBuf::from(runtime.runtime_directory(root.to_str().unwrap()).unwrap());
        assert!(recover(&runtime, &namespace).is_err());
        provision(&runtime, &namespace, &owner, &key, 1, u32::MAX).unwrap();
        assert!(provision(&runtime, &namespace, &owner, &key, 1, u32::MAX).is_err());
        assert!(!recover(&runtime, &namespace).unwrap().initialize);
        let path = namespace.join(PROFILE_FILE);
        let original = std::fs::read(&path).unwrap();
        let profile: serde_json::Value = serde_json::from_slice(&original).unwrap();
        for (field, value) in [
            ("schema", serde_json::json!(2)),
            ("network", serde_json::json!("wrong-network")),
            ("global_id", serde_json::json!(0)),
            ("session", serde_json::json!("00")),
            ("profile", serde_json::json!("00")),
            ("committee", serde_json::json!("00")),
            ("local_adnl", serde_json::json!("00")),
            ("validator", serde_json::json!("00")),
            ("database", serde_json::json!(root)),
            ("generation", serde_json::json!(0)),
            ("expire_at", serde_json::json!(1)),
            ("unknown", serde_json::json!(true)),
        ] {
            let mut changed = profile.clone();
            changed[field] = value;
            std::fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
            assert!(recover(&runtime, &namespace).is_err(), "accepted changed {field}");
        }
        std::fs::write(&path, original).unwrap();
        std::fs::write(&key, [0xa1; 32]).unwrap();
        assert!(recover(&runtime, &namespace).is_err());
    }
}
