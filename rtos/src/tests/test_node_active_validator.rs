// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! The actual node manager must advance consensus before and after interruption.
use super::*;
use crate::{config::TonNodeConfig, network::node_network::NodeNetwork};
use consensus_common::session_runtime::{AuthenticatedSessionRuntime, SessionNetworkPin};
use rtos_block::{Ed25519KeyOption, ZeroizingBytes};

pub(super) async fn run(binary: &Path, root: &Path, zero: &Path, fixture: &Fixture) -> Result<()> {
    let runtime = provision(root, fixture, 0xa1, 0x61).await?;
    let local_id = runtime.committee()[0].validator_id()?;
    let mut previous = 4;
    for attempt in 0..2 {
        let path = root.join(format!("active-node-{attempt}.log"));
        let log = fs::File::create(&path)?;
        let mut node = Process(Command::new(binary).env("TOKIO_WORKER_THREADS", "2")
            .arg("--configs").arg(root).arg("--zerostate").arg(zero).arg("--initial-sync-disabled").args(forced_cursor_fixture_args(root))
            .current_dir(root).stdout(Stdio::from(log.try_clone()?)).stderr(Stdio::from(log)).spawn()?);
        let deadline = Instant::now() + Duration::from_secs(100);
        let advanced = loop {
            let output = fs::read_to_string(&path)?;
            keep_evidence(root, &path)?;
            if let Some(status) = node.0.try_wait()? { rtos_block::fail!("Active validator attempt {attempt} exited {status}; see retained log"); }
            let head = output.lines().filter_map(|line| line.strip_prefix("Processing masterblock "))
                .filter_map(|value| value.parse::<u32>().ok()).max().unwrap_or(0);
            if output.contains("Node services started.") && head > previous { break head; }
            if Instant::now() >= deadline { rtos_block::fail!("Active validator did not advance beyond MC{previous}; see retained log"); }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        node.0.kill()?; assert!(!node.0.wait()?.success()); keep_evidence(root, &path)?;
        eprintln!("Actual validator attempt {attempt}: MC{previous} -> MC{advanced}, then SIGKILL");
        previous = advanced;
    }
    let db = open_db(root).await?;
    let head = db.load_full_node_state(LAST_APPLIED_MC_BLOCK)?.unwrap();
    assert!(head.seq_no() >= previous && previous > 5);
    let handle = db.load_block_handle(&head)?.unwrap();
    let block = db.load_block_data(&handle).await?;
    let state = db.load_shard_state_dynamic(&head)?;
    assert_eq!(state.root_cell().repr_hash(), &block.block()?.read_state_update()?.new_hash);
    let proof = db.load_block_proof(&handle, false).await?;
    assert_eq!(proof.id(), head.as_ref());
    fixture.assert_history(&db, 4).await?;
    let governing = db.load_shard_state_dynamic(&fixture.id(4, false))?;
    let mut current = (*head).clone();
    let mut verified_blocks = 0;
    while current.seq_no() > 4 {
        let handle = db.load_block_handle(&current)?.ok_or_else(|| rtos_block::error!("Missing recovered block handle"))?;
        assert!(handle.is_applied());
        let block = db.load_block_data(&handle).await?;
        let state = db.load_shard_state_dynamic(&current)?;
        assert_eq!(state.root_cell().repr_hash(), &block.block()?.read_state_update()?.new_hash);
        let proof = db.load_block_proof(&handle, false).await?;
        proof.check_with_master_state(&governing)?;
        let parent = db.load_block_prev1(&current)?;
        assert_eq!(parent.seq_no() + 1, current.seq_no());
        assert_eq!(db.load_block_next1(&parent)?, current);
        current = parent;
        verified_blocks += 1;
    }
    assert_eq!(current, fixture.id(4, false));
    for key in [ARCHIVES_GC_BLOCK, PSS_KEEPER_MC_BLOCK, SHARD_CLIENT_MC_BLOCK] {
        let cursor = db.load_full_node_state(key)?.ok_or_else(|| rtos_block::error!("Missing progress cursor {key}"))?;
        assert!(cursor.seq_no() <= head.seq_no(), "Progress cursor {key} exceeds applied head");
    }
    let report = root.join("active-validator-recovery.json");
    fs::write(&report, serde_json::to_vec_pretty(&serde_json::json!({
        "initial_height":4,"final_height":head.seq_no(),"complete_boots":2,
        "native_reopen_between_boots":false,"pq_verified_blocks":verified_blocks,"imported_history_preserved":true,"parent_links_consistent":true,"progress_cursors_bounded":true,"state_root":state.root_cell().repr_hash().to_hex_string(),
        "public_test_validator":local_id.to_hex_string(),"session":runtime.session_id().to_hex_string(),
    }))?)?;
    keep_evidence(root, &report)?;
    db.stop_states_db().await?;
    Ok(())
}

pub(super) async fn provision(root: &Path, fixture: &Fixture, custody_seed: u8, transport_seed: u8)
    -> Result<AuthenticatedSessionRuntime> {
    provision_with_expiry(root, fixture, custody_seed, transport_seed, u32::MAX).await
}

pub(super) async fn provision_with_expiry(root: &Path, fixture: &Fixture, custody_seed: u8,
    transport_seed: u8, expire_at: u32) -> Result<AuthenticatedSessionRuntime> {
    // Public deterministic test identities; no configured/production keys are read.
    let custody = root.join("isolated-custody"); fs::create_dir(&custody)?;
    let key_file = custody.join("public-test-seed");
    fs::write(&key_file, [custody_seed; 32])?;
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&custody, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600))?;
    }
    let owner = root.join("isolated-owner"); fs::create_dir(&owner)?;
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&owner, fs::Permissions::from_mode(0o700))?;
    }
    let db = open_db(root).await?;
    let state = db.load_shard_state_dynamic(&fixture.id(4, false))?;
    let config = state.config_params()?;
    let extra = state.shard_state_extra()?;
    let cc = extra.validator_info.catchain_seqno;
    let key_seqno = extra.last_key_block.as_ref().unwrap().seq_no;
    let (committee, _) = config.validator_set()?.calc_subset(&config.catchain_config()?, rtos_block::SHARD_FULL, -1, cc)?;
    let (transport_json, transport) = Ed25519KeyOption::<ZeroizingBytes>::from_private_key_with_json(&[transport_seed; 32])?;
    let runtime = AuthenticatedSessionRuntime::from_authenticated_config(
        SessionNetworkPin { global_id: state.state()?.global_id(), zerostate: fixture.id(0, false) },
        config, rtos_api::session_identity::SessionCoordinates { shard: fixture.id(4, false).shard(),
            catchain_seqno: cc, vertical_seqno: 0, last_key_block_seqno: key_seqno, new_catchain_ids: false },
        committee, transport.id().clone(),
    )?.bind_recovery_anchor(fixture.id(4, false))?;
    let namespace = PathBuf::from(runtime.runtime_directory(root.join("node_db/catchains").to_str().unwrap())?);
    simplex::isolated_signing::provision(&runtime, &namespace, &owner, &key_file, 1, expire_at)?;
    let (physical, _) = db.sst_databases_for_test();
    drop(state); db.stop_states_db().await?; drop(db);
    tokio::time::timeout(Duration::from_secs(30), wait_for_db_release(physical)).await?;
    let generated = TonNodeConfig::from_file(root.to_str().unwrap(), "config.json", None, "default_config.json", None).await?;
    drop(generated);
    let mut node_config: serde_json::Value = serde_json::from_slice(&fs::read(root.join("config.json"))?)?;
    for key in node_config["adnl_node"]["keys"].as_array_mut().unwrap() {
        if key["tag"] == NodeNetwork::TAG_OVERLAY_KEY { key["data"] = serde_json::to_value(&transport_json)?; }
    }
    let local_id = runtime.committee()[match runtime.local_role() { consensus_common::session_runtime::LocalRole::Validator(i) => i as usize, _ => unreachable!() }].validator_id()?;
    node_config["validator_key_ring"][rtos_block::base64_encode(transport.id().data())] = serde_json::to_value(&transport_json)?;
    node_config["consensus_transport_bindings"] = serde_json::json!([{
        "validator_id":rtos_block::base64_encode(local_id.as_slice()),
        "adnl_key_id":rtos_block::base64_encode(transport.id().data()),
    }]);
    fs::write(root.join("config.json"), serde_json::to_vec(&node_config)?)?;
    Ok(runtime)
}
