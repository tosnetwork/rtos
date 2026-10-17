//! Finite, offline-authorized successor sessions for isolated fixture builds.
use super::{recover, provision, PROFILE_FILE};
use consensus_common::session_runtime::{AuthenticatedSessionRuntime, LocalRole};
use rtos_block::{error, fail, Result};
use serde::{Deserialize, Serialize};
use std::{fs::{self, File, OpenOptions}, io::{Read, Write}, path::{Path, PathBuf}};

pub const SCHEDULE_FILE: &str = "isolated-signing-schedule.json";
const MAX_BYTES: u64 = 65_536;

fn check_expiry(expire_at: u32) -> Result<()> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    if expire_at == 0 || expire_at == u32::MAX || u64::from(expire_at) <= now {
        fail!("Isolated successor schedule requires a future finite expiry");
    }
    Ok(())
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Entry {
    workchain: i32,
    shard: u64,
    catchain: u32,
    profile: String,
    committee: String,
}
impl Entry {
    fn from_runtime(runtime: &AuthenticatedSessionRuntime) -> Result<Self> {
        Ok(Self { workchain: runtime.shard().workchain_id(),
            shard: runtime.shard().shard_prefix_with_tag(), catchain: runtime.catchain_seqno(),
            profile: runtime.profile().to_hex_string(), committee: runtime.committee_digest()?.to_hex_string() })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Schedule {
    schema: u32,
    network: String,
    global_id: i32,
    local_adnl: String,
    validator: String,
    database_parent: PathBuf,
    owner_root: PathBuf,
    key_file: PathBuf,
    expire_at: u32,
    entries: Vec<Entry>,
}

/// The trusted offline preparer supplies only Genesis-committed successor
/// committees. The actual future key-block height is intentionally not guessed.
/// This policy grants no authority outside those exact profiles, committees,
/// shard/catchain coordinates, local identity, database and finite expiry.
pub fn provision_schedule(runtimes: &[AuthenticatedSessionRuntime], database_root: &Path,
    owner_root: &Path, key_file: &Path, expire_at: u32) -> Result<()> {
    if runtimes.is_empty() || runtimes.len() > 32 || expire_at == 0 || expire_at == u32::MAX {
        fail!("Isolated successor schedule needs bounded entries and finite expiry");
    }
    check_expiry(expire_at)?;
    let first = &runtimes[0];
    let LocalRole::Validator(index) = first.local_role() else { fail!("Successor schedule requires validator role"); };
    let validator = first.committee()[index as usize].validator_id()?;
    let database_root = database_root.to_str().ok_or_else(|| error!("Invalid database root"))?;
    let namespace = PathBuf::from(first.runtime_directory(database_root)?);
    let parent = namespace.parent().ok_or_else(|| error!("Missing namespace parent"))?;
    fs::create_dir_all(parent)?;
    let parent = parent.canonicalize()?;
    let custody = rtos_pq_consensus::load_consensus_key(key_file, expire_at)?;
    if custody.expired_now() { fail!("Isolated successor schedule has expired"); }
    let mut entries = Vec::new();
    for runtime in runtimes {
        let LocalRole::Validator(index) = runtime.local_role() else { fail!("Successor schedule requires validator role"); };
        if runtime.pin() != first.pin() || runtime.local_adnl() != first.local_adnl()
            || runtime.committee()[index as usize].validator_id()? != validator
            || runtime.committee()[index as usize].pq_key() != Some(custody.consensus_key())
            || PathBuf::from(runtime.runtime_directory(database_root)?).parent() != Some(parent.as_path()) {
            fail!("Isolated successor schedule has inconsistent trusted identities");
        }
        let entry = Entry::from_runtime(runtime)?;
        if entries.contains(&entry) { fail!("Duplicate isolated successor schedule entry"); }
        entries.push(entry);
    }
    let policy = Schedule { schema: 1, network: first.pin().zerostate.to_string(), global_id: first.pin().global_id,
        local_adnl: hex::encode(first.local_adnl().data()), validator: validator.to_hex_string(),
        database_parent: parent.clone(), owner_root: owner_root.canonicalize()?,
        key_file: key_file.canonicalize()?, expire_at, entries };
    let bytes = serde_json::to_vec(&policy)?;
    if bytes.len() as u64 > MAX_BYTES { fail!("Isolated successor schedule exceeds size bound"); }
    let mut options = OpenOptions::new(); options.write(true).create_new(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
    let mut file = options.open(parent.join(SCHEDULE_FILE))?;
    file.write_all(&bytes)?; file.sync_all()?; File::open(parent)?.sync_all()?;
    Ok(())
}

pub(super) fn recover_or_provision(runtime: &AuthenticatedSessionRuntime, namespace: &Path)
    -> Result<crate::signing_coordinator::TestSessionSigner> {
    match fs::symlink_metadata(namespace.join(PROFILE_FILE)) {
        Ok(_) => return recover(runtime, namespace),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(error) => return Err(error.into()),
    }
    // Never repair or replace a partial/used namespace, even with a valid plan.
    match fs::symlink_metadata(namespace) {
        Ok(_) => fail!("Existing namespace lacks its explicitly provisioned isolated profile"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(error) => return Err(error.into()),
    }
    let parent = namespace.parent().ok_or_else(|| error!("Missing isolated namespace parent"))?;
    let path = parent.join(SCHEDULE_FILE);
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_BYTES { fail!("Invalid isolated successor schedule file"); }
    let mut file = File::open(path)?;
    // Serialize new namespace/journal creation across all scheduled shards.
    file.try_lock().map_err(|error| error!("Isolated schedule provisioning is already owned: {error}"))?;
    let mut bytes = Vec::new(); (&mut file).take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES { fail!("Isolated successor schedule grew beyond size bound"); }
    let policy: Schedule = serde_json::from_slice(&bytes)?;
    let LocalRole::Validator(index) = runtime.local_role() else { fail!("Isolated schedule cannot authorize observer signing"); };
    let binding = runtime.recovery_binding().ok_or_else(|| error!("Successor schedule needs an authenticated governing anchor"))?;
    if binding.coordinates.last_key_block_seqno == 0
        || binding.governing_masterchain.seq_no() < binding.coordinates.last_key_block_seqno {
        fail!("Successor schedule requires an authenticated non-Genesis key epoch");
    }
    if policy.schema != 1 || policy.entries.is_empty() || policy.entries.len() > 32
        || policy.expire_at == 0 || policy.expire_at == u32::MAX
        || policy.network != runtime.pin().zerostate.to_string() || policy.global_id != runtime.pin().global_id
        || policy.local_adnl != hex::encode(runtime.local_adnl().data())
        || policy.validator != runtime.committee()[index as usize].validator_id()?.to_hex_string()
        || policy.database_parent != parent.canonicalize()?
        || !policy.entries.contains(&Entry::from_runtime(runtime)?) {
        fail!("Authenticated runtime is outside the explicit isolated successor schedule");
    }
    // Reject an expired policy before loading custody: malformed policy data
    // must not retire a valid process-wide key handle as a side effect.
    check_expiry(policy.expire_at)?;
    let custody = rtos_pq_consensus::load_consensus_key(&policy.key_file, policy.expire_at)?;
    if custody.expired_now() || runtime.committee()[index as usize].pq_key() != Some(custody.consensus_key()) {
        fail!("Scheduled successor custody key is unavailable or expired");
    }
    let owner = policy.owner_root.join(format!("rotation-{}", runtime.session_id().to_hex_string()));
    fs::create_dir(&owner)?;
    #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; fs::set_permissions(&owner, fs::Permissions::from_mode(0o700))?; }
    provision(runtime, namespace, &owner, &policy.key_file, 1, policy.expire_at)?;
    recover(runtime, namespace)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{os::unix::fs::PermissionsExt, time::{SystemTime, UNIX_EPOCH}};
    use rtos_block::ShardIdent;

    #[test]
    fn isolated_successor_schedule_binds_key_epoch_and_refuses_changed_authority() {
        let directory = crate::authenticated_fixture::TestDirectory::new();
        let root = directory.path();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        let key = root.join("key");fs::write(&key, [0xc7; 32]).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let owner = root.join("owner");fs::create_dir(&owner).unwrap();
        let (base, transport, _) = crate::authenticated_fixture::runtime(true);
        let expiry = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32 + 600;
        let custody = rtos_pq_consensus::ConsensusKeyStore::from_seed(&[0xc7; 32], expiry).unwrap();
        let mut members = base.committee().to_vec();
        members[0].key = rtos_block::ValidatorKey::Pq(custody.consensus_key().clone());
        let (initial, _, _) = crate::authenticated_fixture::runtime_with_members_at_key(
            members.clone(), transport.clone(), ShardIdent::masterchain(), 0, true);
        let (successor, _, _) = crate::authenticated_fixture::runtime_with_members_at_key(
            members, transport, ShardIdent::masterchain(), 5, true);
        assert_ne!(initial.session_id(), successor.session_id());
        assert_eq!(initial.committee_digest().unwrap(), successor.committee_digest().unwrap());
        provision_schedule(&[(*initial).clone()], root, &owner, &key, expiry).unwrap();
        assert!(provision_schedule(&[(*initial).clone()], root, &owner, &key, expiry).is_err());
        let ns = PathBuf::from(successor.runtime_directory(root.to_str().unwrap()).unwrap());
        let path = ns.parent().unwrap().join(SCHEDULE_FILE);
        let original = fs::read(&path).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        for (field, changed) in [
            ("schema", serde_json::json!(2)), ("network", serde_json::json!("other")),
            ("global_id", serde_json::json!(0)), ("local_adnl", serde_json::json!("other")),
            ("validator", serde_json::json!("other")), ("database_parent", serde_json::json!(root)),
            ("entries", serde_json::json!([])), ("expire_at", serde_json::json!(0)),
            ("expire_at", serde_json::json!(1)), ("expire_at", serde_json::json!(u32::MAX)),
            ("unknown", serde_json::json!(true)),
        ] {
            let mut altered = value.clone();altered[field] = changed;
            fs::write(&path, serde_json::to_vec(&altered).unwrap()).unwrap();
            assert!(recover_or_provision(&successor, &ns).is_err(), "accepted changed {field}");
            assert!(!ns.exists());assert_eq!(fs::read_dir(&owner).unwrap().count(), 0);
        }
        for field in ["workchain", "shard", "catchain", "profile", "committee"] {
            let mut altered = value.clone();
            altered["entries"][0][field] = match field {
                "workchain" => serde_json::json!(0), "shard" => serde_json::json!(1),
                "catchain" => serde_json::json!(8), _ => serde_json::json!("other"),
            };
            fs::write(&path, serde_json::to_vec(&altered).unwrap()).unwrap();
            assert!(recover_or_provision(&successor, &ns).is_err());assert!(!ns.exists());
        }
        fs::write(&path, &original).unwrap();
        let initial_ns = PathBuf::from(initial.runtime_directory(root.to_str().unwrap()).unwrap());
        assert!(recover_or_provision(&initial, &initial_ns).is_err());assert!(!initial_ns.exists());
        fs::create_dir(&ns).unwrap();
        assert!(recover_or_provision(&successor, &ns).is_err());
        assert_eq!(fs::read_dir(&ns).unwrap().count(), 0);fs::remove_dir(&ns).unwrap();
        fs::write(&key, [0xc8; 32]).unwrap();
        assert!(recover_or_provision(&successor, &ns).is_err());assert!(!ns.exists());
        fs::write(&key, [0xc7; 32]).unwrap();
        assert!(!recover_or_provision(&successor, &ns).unwrap().initialize);
        assert!(!recover_or_provision(&successor, &ns).unwrap().initialize);
        let profile = ns.join(PROFILE_FILE);let bytes = fs::read(&profile).unwrap();
        fs::write(&profile, b"{}").unwrap();
        assert!(recover_or_provision(&successor, &ns).is_err());
        assert_eq!(fs::read(&profile).unwrap(), b"{}");fs::write(profile, bytes).unwrap();
    }
}
