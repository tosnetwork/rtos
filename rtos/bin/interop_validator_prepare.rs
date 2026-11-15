// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Offline preparation of a fresh mixed-network validator using public test seeds.
//!
//! The validator is configured as a production node is: its consensus seed in
//! a private key file and the node configuration's `pq_consensus` section,
//! which the node loads into custody at startup. No isolated signing profile
//! is provisioned.
use clap::Parser;
use consensus_common::session_runtime::{
    AuthenticatedSessionRuntime, LocalRole, SessionNetworkPin,
};
use rtos::{
    config::{TonNodeConfig, TonNodeGlobalConfig},
    network::node_network::NodeNetwork,
};
use rtos_block::{
    error, fail, read_single_root_boc, Deserializable, Ed25519KeyOption, ShardIdent,
    ShardStateUnsplit, UInt256, ZeroizingBytes,
};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    configs: PathBuf,
    #[arg(long)]
    zerostate: PathBuf,
    #[arg(long)]
    global_config: PathBuf,
    #[arg(long)]
    member: u8,
    /// Also provision only the exact successor set committed in Genesis.
    #[arg(long)]
    include_genesis_successor: bool,
    /// A finite consensus key window end for this public test member: the
    /// configured key's `expire_at`.
    #[arg(long)]
    signer_expire_at: Option<u32>,
}

/// The configured window end of the key: 0 (never) unless an explicit future
/// deadline a node configuration can state is given.
fn signer_expiry(explicit: Option<u32>, now: u64) -> anyhow::Result<u32> {
    match explicit {
        None => Ok(0),
        Some(value)
            if value != 0
                && u64::from(value) > now
                && value <= rtos::pq_consensus_config::MAX_CONSENSUS_KEY_TIME =>
        {
            Ok(value)
        }
        _ => fail!(
            "Explicit fixture signer expiry must be finite, in the future and at most 2147483647"
        ),
    }
}

#[cfg(test)]
mod expiry_tests {
    use super::*;
    #[test]
    fn explicit_custody_deadline_cannot_be_expired_or_unbounded() {
        assert_eq!(signer_expiry(None, 100).unwrap(), 0);
        assert_eq!(signer_expiry(Some(101), 100).unwrap(), 101);
        assert_eq!(signer_expiry(Some(0x7fff_ffff), 100).unwrap(), 0x7fff_ffff);
        for deadline in [0, 1, 99, 100, 0x8000_0000, u32::MAX] {
            assert!(signer_expiry(Some(deadline), 100).is_err());
        }
        assert!(signer_expiry(Some(0x7fff_fffe), 0x7fff_ffff).is_err());
    }
}

fn public_seed(label: &str, member: u8) -> UInt256 {
    UInt256::calc_file_hash(format!("n6-validator-{label}-{member}").as_bytes())
}

fn create_private_directory(path: &std::path::Path) -> anyhow::Result<()> {
    fs::create_dir(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let expire_at = signer_expiry(
        args.signer_expire_at,
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
    )?;
    let root = args.configs.canonicalize()?;
    // Do not provision a running, previously used, or partially prepared node.
    for name in ["config.json", "node_db", "consensus-keys", "validator-prepared.json"] {
        if fs::symlink_metadata(root.join(name)).is_ok() {
            fail!("Fresh interop configuration required: {name} already exists");
        }
    }
    let global = TonNodeGlobalConfig::from_json_file(&args.global_config)?;
    let zero = global.zero_state()?;
    if !zero.shard().is_masterchain() || zero.seq_no() != 0 || !global.hardforks()?.is_empty() {
        fail!("Interop preparation requires a masterchain Genesis without hardforks");
    }
    let bytes = fs::read(&args.zerostate)?;
    let cell = read_single_root_boc(&bytes)?;
    if UInt256::calc_file_hash(&bytes) != zero.file_hash || cell.repr_hash() != zero.root_hash() {
        fail!("Genesis body differs from the supplied global configuration");
    }
    let state = ShardStateUnsplit::construct_from_cell(cell)?;
    if state.seq_no() != 0 || state.shard() != zero.shard() || state.vert_seq_no() != 0 {
        fail!("Genesis header differs from the pinned identity");
    }
    let extra =
        state.read_custom()?.ok_or_else(|| error!("Missing Genesis masterchain configuration"))?;
    let config = &extra.config;
    let transport_seed = public_seed("transport", args.member);
    let (transport_json, transport) =
        Ed25519KeyOption::<ZeroizingBytes>::from_private_key_with_json(transport_seed.as_slice())?;
    let stable_id = public_seed("id", args.member);
    let key_seqno = extra.last_key_block.as_ref().map_or(0, |block| block.seq_no);
    if config.next_validator_set_present()? && !args.include_genesis_successor {
        fail!("Interop Genesis preparation requires one initial validator set");
    }
    if args.include_genesis_successor && !config.next_validator_set_present()? {
        fail!("Explicit Genesis successor required for rotation preparation");
    }
    let mut sets = vec![("initial", config.validator_set()?, 0_u32, 1_u32)];
    if args.include_genesis_successor {
        sets.push(("successor", config.next_validator_set()?, 1, 2));
    }
    let mut shards = vec![(ShardIdent::masterchain(), extra.validator_info.catchain_seqno)];
    extra.shards().iterate_shards(|shard, _| {
        let cc = extra.shards().calc_shard_cc_seqno(&shard)?;
        shards.push((shard, cc));
        Ok(true)
    })?;
    // Genesis can describe an enabled workchain before its first shard entry
    // appears. That first full-shard session starts with catchain sequence zero.
    config.workchains()?.iterate_with_keys(|workchain: i32, descr| {
        if descr.active() && !shards.iter().any(|(shard, _)| shard.workchain_id() == workchain) {
            shards.push((ShardIdent::with_workchain_id(workchain)?, 0));
        }
        Ok(true)
    })?;
    let mut runtimes = Vec::new();
    for (shard, current_cc) in shards {
        // A bounded explicit schedule, never a live wildcard signer. A separate
        // successor must already be committed by the authenticated Genesis.
        for (phase, set, first, last) in &sets {
            for offset in *first..=*last {
                let cc = current_cc
                    .checked_add(offset)
                    .ok_or_else(|| error!("Catchain sequence overflow"))?;
                let (committee, _) = set.calc_subset(
                    &config.catchain_config()?,
                    shard.shard_prefix_with_tag(),
                    shard.workchain_id(),
                    cc,
                )?;
                let runtime = AuthenticatedSessionRuntime::from_authenticated_config(
                    SessionNetworkPin { global_id: state.global_id(), zerostate: zero.clone() },
                    config,
                    rtos_api::session_identity::SessionCoordinates {
                        shard: &shard,
                        catchain_seqno: cc,
                        vertical_seqno: 0,
                        last_key_block_seqno: key_seqno,
                        new_catchain_ids: false,
                    },
                    committee,
                    transport.id().clone(),
                )?
                .bind_recovery_anchor(zero.clone())?;
                if let LocalRole::Validator(index) = runtime.local_role() {
                    if runtime.committee()[index as usize].validator_id()? != stable_id {
                        fail!("Public test transport belongs to an unexpected validator");
                    }
                    if !runtimes.iter().any(
                        |(_, existing): &(&str, AuthenticatedSessionRuntime)| {
                            existing.session_id() == runtime.session_id()
                        },
                    ) {
                        runtimes.push((*phase, runtime));
                    }
                }
            }
        }
    }
    if !runtimes.iter().any(|(_, runtime)| runtime.shard().is_masterchain()) {
        fail!("Public test member is absent from the explicitly scheduled masterchain committees");
    }
    // Bind the fresh database before creating any session namespaces. Hold the
    // same production network lock throughout offline provisioning.
    let _network_binding = rtos::DbNetworkBinding::acquire(&root.join("node_db"), &zero)?;
    let custody = root.join("consensus-keys");
    create_private_directory(&custody)?;
    let key_file = custody.join("public-test-seed");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&key_file)?;
    file.write_all(public_seed("seed", args.member).as_slice())?;
    file.sync_all()?;
    // The node loads exactly this binding into custody at startup; refuse to
    // write one it would refuse.
    let pq_consensus = rtos::pq_consensus_config::PqConsensusConfig {
        validator_id: stable_id.clone(),
        keys: vec![rtos_pq_consensus::ConfiguredKey {
            key_file: key_file.clone(),
            valid_from: 0,
            expire_at,
        }],
    };
    let loaded = rtos::pq_consensus_config::load_pq_consensus_config(
        pq_consensus.clone(),
        u32::try_from(
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
        )
        .unwrap_or(u32::MAX),
    )?;
    let key_id = loaded
        .key_ids_by_file
        .get(&key_file)
        .copied()
        .ok_or_else(|| error!("The prepared consensus key was not loaded"))?;
    let mut sessions = Vec::new();
    for (phase, runtime) in runtimes {
        let LocalRole::Validator(index) = runtime.local_role() else {
            fail!("Prepared session admits this member as observer");
        };
        if runtime.committee()[index as usize].pq_key().map(|key| *key.key_id.as_array())
            != Some(key_id)
        {
            fail!("A scheduled committee records another consensus key for this member");
        }
        let namespace = PathBuf::from(
            runtime.runtime_directory(
                root.join("node_db/catchains")
                    .to_str()
                    .ok_or_else(|| error!("Invalid configuration path"))?,
            )?,
        );
        sessions.push(serde_json::json!({"shard":runtime.shard().to_string(),
            "committee_phase":phase,"expire_at":expire_at,
            "masterchain":runtime.shard().is_masterchain(),
            "catchain_seqno":runtime.catchain_seqno(),
            "session":runtime.session_id().to_hex_string(), "namespace":namespace,
            "carrier_version":runtime.carrier_version(),
            "simplex_protocol":runtime.protocol().version(),
            "committee":runtime.committee().iter().map(|member| Ok(serde_json::json!({
                "validator_id":member.validator_id()?.to_hex_string(),"weight":member.weight
            }))).collect::<anyhow::Result<Vec<_>>>()?}));
    }
    let directory = root.to_str().ok_or_else(|| error!("Invalid configuration path"))?;
    drop(
        TonNodeConfig::from_file(directory, "config.json", None, "default_config.json", None)
            .await?,
    );
    let config_path = root.join("config.json");
    let mut node: serde_json::Value = serde_json::from_slice(&fs::read(&config_path)?)?;
    let keys =
        node["adnl_node"]["keys"].as_array_mut().ok_or_else(|| error!("Missing ADNL keys"))?;
    let overlay = keys
        .iter_mut()
        .find(|key| key["tag"] == NodeNetwork::TAG_OVERLAY_KEY)
        .ok_or_else(|| error!("Missing overlay transport"))?;
    overlay["data"] = serde_json::to_value(&transport_json)?;
    node["validator_key_ring"][rtos_block::base64_encode(transport.id().data())] =
        serde_json::to_value(&transport_json)?;
    node[rtos::pq_consensus_config::CONFIG_FIELD] = pq_consensus.to_json();
    // Transport routing of recovered local publications still reads this
    // binding; it confers no consensus membership, signer or transport identity.
    node["consensus_transport_bindings"] = serde_json::json!([{
        "validator_id":rtos_block::base64_encode(stable_id.as_slice()),
        "adnl_key_id":rtos_block::base64_encode(transport.id().data())}]);
    fs::write(config_path, serde_json::to_vec_pretty(&node)?)?;
    fs::write(
        root.join("validator-prepared.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "public_test_member":args.member,"validator_id":stable_id.to_hex_string(),
            "local_adnl":hex::encode(transport.id().data()),"zerostate":zero.to_string(),
            "sessions":sessions,"signer_expire_at":expire_at,
            "consensus_key_file":key_file,"consensus_key_id":hex::encode(key_id),
            "active_voting_qualified":false
        }))?,
    )?;
    Ok(())
}
