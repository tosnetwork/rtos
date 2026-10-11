// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Manager/group fixtures use generated governing states and real ADNL ownership.
//! The Engine adapter supplies deterministic state; it is not a full Engine test.
use super::*;
use consensus_common::session_runtime::{AuthenticatedSessionRuntime, LocalRole, SessionNetworkPin};

fn configure(bootstrap: &mut EmulatorNetworkBootstrap, observer: &PrivateKey) -> Result<()> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!("../../../../tl/rtos_api/tests/data/live-pq.json"))?;
    let members: Vec<_> = (0..2).map(|index| {
        let row = fixture["rows"].as_array().unwrap().iter().find(|row|
            row["index"] == index && row["context"] == "TOS-CONSENSUS-SIMPLEX-v1").unwrap();
        let public_key = hex::decode(row["public_key"].as_str().unwrap()).unwrap();
        ValidatorDescr::with_pq_params(UInt256::from([index as u8 + 1; 32]), rtos_block::PqConsensusKey {
            algorithm_id: 1, key_id: rtos_block::derive_consensus_key_id(1, &public_key), public_key,
        }, 1, UInt256::from(*bootstrap.validators[index].adnl_key.id().data()))
    }).collect();
    bootstrap.validator_set = ValidatorSet::with_cc_seqno(0, u32::MAX, 2, 0, members.clone())?;
    bootstrap.config_params.set_config(ConfigParamEnum::ConfigParam34(ConfigParam34 {
        cur_validators: bootstrap.validator_set.clone(),
    }))?;
    let mut previous = members[0].clone();
    previous.adnl_addr = Some(UInt256::from(*observer.id().data()));
    bootstrap.config_params.set_config(ConfigParamEnum::ConfigParam32(rtos_block::ConfigParam32 {
        prev_validators: ValidatorSet::with_cc_seqno(0, u32::MAX, 1, 0, vec![previous])?,
    }))?;
    let v2 = SimplexConfig { protocol_version: 2, ..Default::default() };
    bootstrap.config_params.set_config(ConfigParamEnum::ConfigParam30(NewConsensusConfigAll {
        mc: Some(v2.clone()), shard: Some(v2),
    }))?;
    let mut catchain = bootstrap.config_params.catchain_config()?;
    catchain.shard_validators_num = 2;
    bootstrap.config_params.set_config(ConfigParamEnum::ConfigParam28(catchain))?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_manager_creates_transport_only_observer_and_retires_real_groups() -> Result<()> {
    run_authenticated_manager_observer_lifecycle(false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_manager_retries_transient_sink_initialization_on_same_group() -> Result<()> {
    run_authenticated_manager_observer_lifecycle(true).await
}

async fn run_authenticated_manager_observer_lifecycle(fail_initial_sink: bool) -> Result<()> {
    use adnl::{node::AdnlNode, DhtNode, OverlayNode, RldpNode, NetworkStack};
    let observer: PrivateKey = Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[0x71; 32])?;
    let mut bootstrap = EmulatorNetworkBootstrap::build(2)?;
    configure(&mut bootstrap, &observer)?;
    let (_, config) = AdnlNodeConfig::from_ip_address_and_private_keys("127.0.0.1:0", vec![([0x71; 32], 0)])?;
    let adnl = AdnlNode::with_config(config).await?;
    // Possession of another governing member's transport key does not authorize
    // selecting it without an explicit local stable-identity binding.
    adnl.add_key(bootstrap.validators[0].adnl_key.clone(), 1)?;
    let dht = DhtNode::with_adnl_node(adnl.clone(), 0)?;
    let overlay = OverlayNode::with_params_and_profile(adnl.clone(), &[22; 32], 0, rtos_api::WireProfile::T0)?;
    let rldp = RldpNode::with_params(adnl.clone(), vec![overlay.clone()], None)?;
    overlay.set_rldp(rldp.clone())?;
    let stack = Arc::new(NetworkStack { adnl: adnl.clone(), dht, overlay, rldp, quic: None });
    adnl.start_over_udp(vec![stack.overlay.clone(), stack.dht.clone(), stack.rldp.clone()]).await?;
    let actual = consensus_common::ConsensusCommonFactory::create_adnl_overlay_manager(
        tokio::runtime::Handle::current(), stack, None, false)?;
    let (private_json, _) = Ed25519KeyOption::<ZeroizingBytes>::from_private_key_with_json(&[0x71; 32])?;
    let local_config = serde_json::from_value(serde_json::json!({
        "validator_keys": [],
        "validator_key_ring": { base64_encode(observer.id().data()): private_json },
        "consensus_transport_bindings": [{
            "validator_id": base64_encode([1; 32]),
            "adnl_key_id": base64_encode(observer.id().data()),
        }],
    }))?;
    let (handler, context) = crate::config::NodeConfigHandler::create(local_config, tokio::runtime::Handle::current())?;
    handler.clone().start_sheduler(context, vec![])?;
    let mut engine = BootstrapTestEngine::new_with_local_keys(&bootstrap, Vec::new()).await?;
    engine.transport_config = Some(handler.clone());
    let network = Arc::get_mut(&mut engine.validator_network).unwrap();
    network.authenticated = Some(actual);
    network.transport_keys.push(bootstrap.validators[0].adnl_key.clone());
    network.transport_keys.push(handler.consensus_transport_key(observer.id()).await?);
    let engine = Arc::new(engine);
    let mut manager = ValidatorManagerImpl::create(engine.clone(), tokio::runtime::Handle::current(), ValidatorManagerConfig::default());
    let result = async {
        anyhow::ensure!(!engine.get_validator_status(), "no legacy signing eligibility permitted");
        let mut wrong_binding = bootstrap.config_params.clone();
        let mut wrong_previous = wrong_binding.prev_validator_set()?.list().to_vec();
        wrong_previous[0].adnl_addr = Some(UInt256::from([97; 32]));
        wrong_binding.set_config(ConfigParamEnum::ConfigParam32(rtos_block::ConfigParam32 {
            prev_validators: ValidatorSet::with_cc_seqno(0, u32::MAX, 1, 0, wrong_previous)?,
        }))?;
        anyhow::ensure!(manager.authenticated_transport_key(&wrong_binding, &[]).is_err(),
            "configured stable identity was accepted with wrong governing ADNL");
        let state = engine.build_masterchain_state(&bootstrap, 0)?;
        engine.install_masterchain_state(state.clone(), None)?;
        let failed_group = if fail_initial_sink {
            engine.fail_finality_sink_once.store(true, Ordering::SeqCst);
            let error = manager.update_shards(state.clone()).await.err()
                .ok_or_else(|| error!("Expected sink initialization failure"))?;
            anyhow::ensure!(error.to_string().contains("Injected transient finality sink"));
            let (id, group) = manager.current_sessions.iter().next()
                .ok_or_else(|| error!("Partially started group ownership was lost"))?;
            anyhow::ensure!(!group.is_start_pending().await, "failed sink left a permanently pending start");
            anyhow::ensure!(!group.snapshot().await.has_engine, "failed admission created consensus engine");
            Some((id.clone(), group.clone()))
        } else { None };
        manager.update_shards(state.clone()).await?;
        if let Some((id, original)) = failed_group {
            let retried = manager.current_sessions.get(&id).ok_or_else(|| error!("Failed group was lost during retry"))?;
            anyhow::ensure!(Arc::ptr_eq(&original, retried), "Retry replaced the group instead of releasing its reservation");
        }
        anyhow::ensure!(manager.validator_list_status.curr.is_none(), "fixture must have no PQ signing identity");
        anyhow::ensure!(manager.current_sessions.len() == 2, "expected MC + shard actual observer groups");
        anyhow::ensure!(manager.owned_current_shards == 0, "observer incorrectly marked validator");
        anyhow::ensure!(manager.block_sync_observers.is_empty(), "v2 must not use v1 block-sync topology");
        for group in manager.current_sessions.values() {
            let runtime = group.authenticated_runtime().ok_or_else(|| error!("runtime missing"))?;
            anyhow::ensure!(runtime.local_role() == LocalRole::Observer);
            anyhow::ensure!(runtime.local_adnl() == observer.id());
        }
        wait_for_manager_sessions(&manager).await?;
        for group in manager.current_sessions.values() {
            anyhow::ensure!(group.snapshot().await.has_engine, "Observer never created a real session");
        }
        anyhow::ensure!(engine.validation_status() == ValidationStatus::Disabled);
        let first = manager.current_sessions.clone();
        let previous = bootstrap.config_params.prev_validator_set()?;
        let mut extra = bootstrap.validator_set.list()[1].clone();
        extra.adnl_addr = Some(UInt256::from([81; 32]));
        let mut previous_members = previous.list().to_vec();
        previous_members.push(extra);
        bootstrap.config_params.set_config(ConfigParamEnum::ConfigParam32(rtos_block::ConfigParam32 {
            prev_validators: ValidatorSet::with_cc_seqno(0, u32::MAX, 2, 0, previous_members)?,
        }))?;
        let next = engine.build_masterchain_state(&bootstrap, 1)?;
        engine.install_masterchain_state(next.clone(), Some(state.block_id().clone()))?;
        manager.update_shards(next.clone()).await?;
        wait_for_manager_sessions(&manager).await?;
        for (id, old) in first {
            let replacement = manager.current_sessions.get(&id).ok_or_else(|| error!("same-session replacement missing"))?;
            anyhow::ensure!(!Arc::ptr_eq(&old, replacement), "changed members reused old group");
            anyhow::ensure!(old.teardown_drained(), "old generation was not actually drained");
            anyhow::ensure!(replacement.snapshot().await.has_engine);
            anyhow::ensure!(replacement.authenticated_runtime().unwrap().members().contains(&rtos_block::KeyId::from_data([81; 32])));
        }
        let unchanged = manager.current_sessions.clone();
        manager.update_shards(next).await?;
        for (id, original) in unchanged {
            let retained = manager.current_sessions.get(&id).ok_or_else(|| error!("unchanged admission disappeared"))?;
            anyhow::ensure!(Arc::ptr_eq(&original, retained), "unchanged admission was recreated");
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    let ids = manager.current_sessions.keys().chain(manager.future_sessions.keys()).cloned().collect();
    let stopped = manager.stop_and_remove_sessions(&ids, false).await;
    drop(manager);
    // Drive the outer production spawn entry with the real configuration
    // handler's false validator status. Only explicit transport eligibility can
    // get through its initial wait and create these additional real sessions.
    let spawned = if result.is_ok() && stopped.is_ok() {
        let baseline = engine.validator_network.authenticated_created.load(Ordering::SeqCst);
        let mut manager_config = ValidatorManagerConfig::default();
        manager_config.update_interval = Duration::from_millis(20);
        match spawn_validator_manager(engine.clone(), tokio::runtime::Handle::current(), manager_config) {
            Ok(task) => {
                let started = tokio::time::timeout(Duration::from_secs(5), async {
                    while engine.validator_network.authenticated_created.load(Ordering::SeqCst) < baseline + 2 {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }).await;
                engine.stop.store(true, Ordering::SeqCst);
                let joined = task.await;
                started.map_err(|_| error!("outer manager did not create configured observer sessions"))
                    .and_then(|_| joined.map_err(|error| error!("manager task failed: {error}")))
            }
            Err(error) => Err(error),
        }
    } else { Ok(()) };
    let drained = adnl.stop_checked().await;
    let scheduler_stopped = handler.stop_and_wait().await;
    stopped?;
    drained?;
    scheduler_stopped?;
    result?;
    spawned
}

#[test]
fn authenticated_registry_identity_changes_with_pq_and_transport_rotation() -> Result<()> {
    let observer = Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[0x71; 32])?;
    let mut bootstrap = EmulatorNetworkBootstrap::build(2)?;
    let classical = bootstrap.validator_set.list().to_vec();
    let mut expected = rtos_block::Sha256::new();
    for member in &classical { expected.update(member.compute_node_id_short()?.as_slice()); }
    assert_eq!(compute_validator_list_id(&classical, None)?.unwrap(), UInt256::from(<[u8; 32]>::from(expected.finalize())));
    configure(&mut bootstrap, &observer)?;
    let members = bootstrap.validator_set.list().to_vec();
    let original = compute_validator_list_id(&members, None)?;
    let mut rotated = members.clone();
    rotated[0].adnl_addr = Some(UInt256::from([44; 32]));
    assert_ne!(compute_validator_list_id(&rotated, None)?, original);
    rotated = members.clone();
    rotated[0].key = members[1].key.clone();
    rotated[1].key = members[0].key.clone();
    assert_ne!(compute_validator_list_id(&rotated, None)?, original);
    rotated = members.clone();
    rotated.swap(0, 1);
    assert_ne!(compute_validator_list_id(&rotated, None)?, original);
    Ok(())
}

#[tokio::test]
async fn authenticated_group_rejects_anchor_schedule_and_rebinding() -> Result<()> {
    let key = Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[0x71; 32])?;
    let mut bootstrap = EmulatorNetworkBootstrap::build(2)?;
    configure(&mut bootstrap, &key)?;
    let engine = Arc::new(BootstrapTestEngine::new_with_local_keys(&bootstrap, Vec::new()).await?);
    let state = engine.build_masterchain_state(&bootstrap, 0)?;
    let shard = ShardIdent::masterchain();
    let (info, id) = derive_governing_session_info(&state, &shard, bootstrap.validator_set.list(), 0, 0, 0)?;
    let make_runtime = |zerostate: BlockIdExt| -> Result<Arc<AuthenticatedSessionRuntime>> {
        Ok(Arc::new(AuthenticatedSessionRuntime::from_authenticated_config(
            SessionNetworkPin { global_id: state.state()?.global_id(), zerostate },
            state.config_params()?, rtos_api::session_identity::SessionCoordinates {
                shard: &shard, catchain_seqno: 0, vertical_seqno: 0, last_key_block_seqno: 0, new_catchain_ids: false },
            bootstrap.validator_set.list().to_vec(), key.id().clone())?))
    };
    let runtime = make_runtime(bootstrap.zerostate_id.clone())?;
    let options = SimplexSessionOptions { protocol: runtime.protocol(), proto_version: runtime.carrier_version(),
        wire_profile: runtime.wire_profile(), slots_per_leader_window: runtime.slots_per_leader_window(), ..Default::default() };
    let group = |options| ValidatorGroup::new(info.clone(), key.clone(), id.clone(),
        UInt256::from([1; 32]), bootstrap.validator_set.clone(), 0, ConsensusOptions::Simplex(options), engine.clone(), false, None);
    let attached = group(options.clone()).with_authenticated_runtime(runtime.clone())?;
    assert_eq!(attached.authenticated_runtime().unwrap().local_role(), LocalRole::Observer);
    assert!(attached.with_authenticated_runtime(runtime.clone()).is_err());
    let mut bad_slots = options.clone();
    bad_slots.slots_per_leader_window += 1;
    assert!(group(bad_slots).with_authenticated_runtime(runtime.clone()).is_err());
    for root in [true, false] {
        let mut zero = bootstrap.zerostate_id.clone();
        if root { zero.root_hash = UInt256::from([31; 32]); }
        else { zero.file_hash = UInt256::from([32; 32]); }
        let wrong = make_runtime(zero)?;
        assert_eq!(wrong.session_id(), runtime.session_id(), "anchor is independent from session hash");
        assert!(group(options.clone()).with_authenticated_runtime(wrong).is_err());
    }
    Ok(())
}
