// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Offline public-test keys for the local CI network. Never use these seeds
//! outside disposable test networks. Uses the same identities as interop fixtures.
use clap::Parser;
use rtos::{network::node_network::NodeNetwork, pq_consensus_config::PqConsensusConfig};
use rtos_block::{base64_encode, error, Ed25519KeyOption, UInt256, ZeroizingBytes};
use rtos_pq_consensus::{ConfiguredKey, ConsensusKeyStore};
use std::{fs, io::Write, path::PathBuf};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    member: u8,
    #[arg(long)]
    custody: PathBuf,
    #[arg(long)]
    descriptor: PathBuf,
}

fn public_seed(label: &str, member: u8) -> UInt256 {
    UInt256::calc_file_hash(format!("n6-validator-{label}-{member}").as_bytes())
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mut node: serde_json::Value = serde_json::from_slice(&fs::read(&args.config)?)?;
    let validator_id = public_seed("id", args.member);
    let seed = public_seed("seed", args.member);
    let store = ConsensusKeyStore::from_seed(seed.as_slice(), 0)?;
    let key = store.consensus_key();
    let (transport_json, transport) =
        Ed25519KeyOption::<ZeroizingBytes>::from_private_key_with_json(
            public_seed("transport", args.member).as_slice(),
        )?;
    let overlay = node["adnl_node"]["keys"]
        .as_array_mut()
        .and_then(|keys| keys.iter_mut().find(|key| key["tag"] == NodeNetwork::TAG_OVERLAY_KEY))
        .ok_or_else(|| error!("Missing generated overlay key"))?;
    overlay["data"] = serde_json::to_value(&transport_json)?;
    fs::create_dir(&args.custody)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&args.custody, fs::Permissions::from_mode(0o700))?;
    }
    let key_file = args.custody.canonicalize()?.join("public-test-seed");
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&key_file)?;
    file.write_all(seed.as_slice())?;
    file.sync_all()?;
    let config = PqConsensusConfig {
        validator_id: validator_id.clone(),
        keys: vec![ConfiguredKey { key_file, valid_from: 0, expire_at: 0 }],
    };
    rtos::pq_consensus_config::load_pq_consensus_config(config.clone(), 0)?;
    node["pq_consensus"] = config.to_json();
    node["validator_key_ring"][base64_encode(transport.id().data())] =
        serde_json::to_value(&transport_json)?;
    node["consensus_transport_bindings"] = serde_json::json!([{
        "validator_id": base64_encode(validator_id.as_slice()),
        "adnl_key_id": base64_encode(transport.id().data())
    }]);
    fs::write(&args.config, serde_json::to_vec_pretty(&node)?)?;
    fs::write(
        &args.descriptor,
        serde_json::to_vec_pretty(&serde_json::json!({
            "key_type": "pq", "validator_id": validator_id.to_hex_string(),
            "algorithm_id": key.algorithm_id, "key_id": key.key_id.to_hex_string(),
            "public_key": hex::encode(&key.public_key),
            "adnl_addr": hex::encode(transport.id().data()), "weight": "10"
        }))?,
    )?;
    Ok(())
}
