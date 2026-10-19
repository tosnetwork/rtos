// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Manager/group fixtures use generated governing states and real ADNL ownership.
//! The Engine adapter supplies deterministic state; it is not a full Engine test.
use super::*;
use rtos_block::HashmapAugType;
use consensus_common::session_runtime::{AuthenticatedSessionRuntime, LocalRole, SessionNetworkPin};

fn configure(bootstrap: &mut EmulatorNetworkBootstrap, observer: &PrivateKey) -> Result<()> {
    // Public fixture transport seeds make the independently signed history
    // reproducible. This does not install any PQ signing capability in the node.
    for (index, validator) in bootstrap.validators.iter_mut().enumerate() {
        let (json, key) = Ed25519KeyOption::<ZeroizingBytes>::from_private_key_with_json(&[0x60 + index as u8; 32])?;
        validator.adnl_key_json = json;
        validator.validator_descr.adnl_addr = Some(UInt256::from(*key.id().data()));
        validator.adnl_key = key;
    }
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
    // The signed manager history pins the genesis built with a 2400 ms target rate.
    let v2 = SimplexConfig {
        protocol_version: 2,
        noncritical_params: rtos_block::NoncriticalParams { target_rate_ms: 2400, ..Default::default() },
        ..Default::default()
    };
    bootstrap.config_params.set_config(ConfigParamEnum::ConfigParam30(NewConsensusConfigAll {
        mc: Some(v2.clone()), shard: Some(v2),
    }))?;
    let mut catchain = bootstrap.config_params.catchain_config()?;
    catchain.shard_validators_num = 2;
    bootstrap.config_params.set_config(ConfigParamEnum::ConfigParam28(catchain))?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "admits its observer through a transport binding of a committee member's identity; membership and observers now follow custody and the reference observer selection, which excludes committee members, and the signed manager history cannot be re-signed for a custody fixture"]
async fn authenticated_manager_creates_transport_only_observer_and_retires_real_groups() -> Result<()> {
    run_authenticated_manager_observer_lifecycle(false, None, false, None).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "admits its observer through a transport binding of a committee member's identity; membership and observers now follow custody and the reference observer selection, which excludes committee members, and the signed manager history cannot be re-signed for a custody fixture"]
async fn authenticated_manager_retries_transient_sink_initialization_on_same_group() -> Result<()> {
    run_authenticated_manager_observer_lifecycle(true, None, false, None).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "admits its observer through a transport binding of a committee member's identity; membership and observers now follow custody and the reference observer selection, which excludes committee members, and the signed manager history cannot be re-signed for a custody fixture"]
async fn authenticated_manager_retries_normal_loser_after_recovery_admission_on_same_state() -> Result<()> {
    run_authenticated_manager_observer_lifecycle(false, Some(0), false, None).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "admits its observer through a transport binding of a committee member's identity; membership and observers now follow custody and the reference observer selection, which excludes committee members, and the signed manager history cannot be re-signed for a custody fixture"]
async fn authenticated_manager_retries_existing_future_after_recovery_admission_on_same_state() -> Result<()> {
    run_authenticated_manager_observer_lifecycle(false, Some(1), false, None).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "admits its observer through a transport binding of a committee member's identity; membership and observers now follow custody and the reference observer selection, which excludes committee members, and the signed manager history cannot be re-signed for a custody fixture"]
async fn authenticated_manager_retries_idle_future_without_namespace_notification() -> Result<()> {
    run_authenticated_manager_observer_lifecycle(false, None, true, None).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "admits its observer through a transport binding of a committee member's identity; membership and observers now follow custody and the reference observer selection, which excludes committee members, and the signed manager history cannot be re-signed for a custody fixture"]
async fn authenticated_manager_current_busy_preserves_group_in_real_invocation() -> Result<()> {
    run_authenticated_manager_observer_lifecycle(false, None, false, Some(true)).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "admits its observer through a transport binding of a committee member's identity; membership and observers now follow custody and the reference observer selection, which excludes committee members, and the signed manager history cannot be re-signed for a custody fixture"]
async fn authenticated_manager_current_authentication_error_exits_real_invocation() -> Result<()> {
    run_authenticated_manager_observer_lifecycle(false, None, false, Some(false)).await
}

/// Direct fixture updates must obey the invocation's same typed-only policy.
/// Fault assertions below intentionally call update_shards directly instead.
async fn update_with_history_retry(
    manager: &mut ValidatorManagerImpl,
    state: Arc<ShardStateStuff>,
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let generation = manager.engine.finality_recovery_generation();
            match manager.update_shards(state.clone()).await {
                Ok(()) => return Ok(()),
                Err(error) if crate::retired_history::is_retryable(&error) => {
                    eprintln!("manager fixture: typed preparation defer: {error}");
                    let handle = manager.engine.load_block_handle(state.block_id())?
                        .ok_or_else(|| error!("fixture retry MC handle absent"))?;
                    let next = manager.wait_next_mc_or_materialization_retry(&handle, generation)
                        .await?.ok_or_else(|| error!("fixture manager stopped during history retry"))?;
                    anyhow::ensure!(next.id() == state.block_id(), "fixture received unexpected MC during retry");
                }
                Err(error) => return Err(error),
            }
        }
    }).await.map_err(|error| error!("fixture typed history retry deadline: {error}"))?
}

async fn run_authenticated_manager_observer_lifecycle(fail_initial_sink: bool, admission_race: Option<u32>, idle_retry: bool, current_retry: Option<bool>) -> Result<()> {
    use adnl::{node::AdnlNode, DhtNode, OverlayNode, RldpNode, NetworkStack};
    let _ = env_logger::builder().is_test(true).try_init();
    eprintln!("manager lifecycle: begin admission_race={admission_race:?}");
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
    // This fixture replaces the bootstrap configuration before creating its
    // manager state. Pin that actual genesis BOC, not the earlier bootstrap
    // genesis with different configuration, and keep later key references aligned.
    let state = engine.build_masterchain_state(&bootstrap, 0)?;
    bootstrap.zerostate_id = state.block_id().clone();
    engine.init_mc_block_id = state.block_id().clone();
    let engine = Arc::new(engine);
    let mut manager = ValidatorManagerImpl::create(engine.clone(), tokio::runtime::Handle::current(), ValidatorManagerConfig::default());
    let result = async {
        anyhow::ensure!(!engine.get_validator_status(), "no legacy signing eligibility permitted");
        engine.install_masterchain_state(state.clone(), None)?;
        if let Some(retryable) = current_retry {
            engine.fail_current_history_busy_once.store(true, Ordering::SeqCst);
            let error = manager.update_shards(state.clone()).await.expect_err("controlled current busy");
            anyhow::ensure!(crate::retired_history::is_retryable(&error));
            let original = manager.current_sessions.values().find(|g| {
                g.authenticated_runtime().is_some_and(|r| r.shard().is_masterchain())
            }).ok_or_else(|| error!("failed current group ownership missing"))?.clone();
            anyhow::ensure!(!original.snapshot().await.has_engine);
            anyhow::ensure!(!original.is_start_pending().await);
            let baseline = engine.validator_network.authenticated_created.load(Ordering::SeqCst);
            let mut existing = 0;
            for group in manager.current_sessions.values().chain(manager.future_sessions.values()) {
                if group.snapshot().await.has_engine { existing += 1; }
            }
            if retryable {
                engine.fail_current_history_busy_once.store(true, Ordering::SeqCst);
                let completion = async {
                    let result = tokio::time::timeout(Duration::from_secs(8), async {
                        while engine.validator_network.authenticated_created.load(Ordering::SeqCst) < baseline + 4 - existing {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }).await;
                    engine.stop.store(true, Ordering::SeqCst);
                    result.map_err(|e| error!("current busy invocation did not recover: {e}"))
                };
                let (invoked, completed) = tokio::join!(manager.invoke(), completion);
                invoked?;
                completed?;
                anyhow::ensure!(original.snapshot().await.has_engine);
                let runtime = original.authenticated_runtime().unwrap();
                anyhow::ensure!(engine.namespace_registry.reserve(runtime)?.is_none());
            } else {
                engine.fail_current_history_auth.store(true, Ordering::SeqCst);
                let error = tokio::time::timeout(Duration::from_secs(3), manager.invoke()).await
                    .map_err(|e| error!("permanent authentication rejection was retried: {e}"))?
                    .expect_err("authentication failure must leave invocation");
                anyhow::ensure!(error.to_string().contains("permanent historical authentication"));
                anyhow::ensure!(!crate::retired_history::is_retryable(&error));
                anyhow::ensure!(!original.snapshot().await.has_engine);
                anyhow::ensure!(!original.is_start_pending().await);
            }
            let runtime = original.authenticated_runtime().unwrap();
            anyhow::ensure!(Arc::ptr_eq(&original, manager.current_sessions.get(runtime.session_id()).unwrap()),
                "invocation replaced original group instead of retaining ownership");
            return Ok(());
        }
        engine.fail_future_history_until_released.store(idle_retry, Ordering::SeqCst);
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
        if let Some(target_seqno) = admission_race {
            let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            *engine.normal_admission_gate.lock().unwrap() = Some((target_seqno, entered_tx, release_rx));
            let race_done = tokio::sync::Notify::new();
            let race = async {
                let runtime = tokio::time::timeout(Duration::from_secs(10), entered_rx).await
                    .map_err(|e| error!("manager phase=await-normal-admission-gate target_cc={target_seqno}: {e}"))?
                    .map_err(|e| error!("manager phase=normal-admission-gate-channel target_cc={target_seqno}: {e}"))?;
                eprintln!("manager lifecycle: gate entered target_cc={target_seqno}");
                // Normal manager already selected its group. Recovery now wins
                // actual atomic admission before the normal factory can start.
                let token = engine.namespace_registry.reserve(&runtime)?.ok_or_else(|| error!("recovery lost gated race"))?;
                release_tx.send(()).map_err(|e| error!("release normal gate: {e}"))?;
                race_done.notify_one();
                Ok::<_, anyhow::Error>((runtime, token))
            };
            let updates = async {
                update_with_history_retry(&mut manager, state.clone()).await?;
                let handle = engine.load_block_handle(state.block_id())?.unwrap();
                loop {
                    let generation = engine.namespace_registry.generation();
                    tokio::select! {
                        _ = race_done.notified() => return Ok::<_, anyhow::Error>(()),
                        next = manager.wait_next_mc_or_materialization_retry(&handle, generation) => {
                            anyhow::ensure!(next?.is_some(), "manager stopped before admission gate");
                        }
                    }
                    update_with_history_retry(&mut manager, state.clone()).await?;
                }
            };
            let (updated, race) = tokio::join!(tokio::time::timeout(Duration::from_secs(12), updates), race);
            let updated = updated.map_err(|e| error!("manager production retry helper timeout: {e}"))?;
            eprintln!("manager lifecycle: initial update result={updated:?}; race_ok={}", race.is_ok());
            updated?;
            let (runtime, token) = race?;
            let groups = if target_seqno == 0 { &manager.current_sessions } else { &manager.future_sessions };
            let loser = groups.get(runtime.session_id()).ok_or_else(|| error!("normal loser group disappeared"))?.clone();
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while loser.is_start_pending().await && std::time::Instant::now() < deadline { tokio::time::sleep(Duration::from_millis(10)).await; }
            let did_create = loser.snapshot().await.has_engine;
            let generation = engine.namespace_registry.generation();
            token.release();
            engine.namespace_registry.wait_changed(generation).await?;
            anyhow::ensure!(!did_create, "normal loser created a competing session");
            update_with_history_retry(&mut manager, state.clone()).await?;
            let groups = if target_seqno == 0 { &manager.current_sessions } else { &manager.future_sessions };
            anyhow::ensure!(Arc::ptr_eq(&loser, groups.get(runtime.session_id()).unwrap()), "same-state retry replaced loser group");
            // Existing future groups must warm up again on this same MC state;
            // the original is_new gate leaves this exact Arc permanently idle.
            tokio::time::timeout(Duration::from_secs(5), async {
                let handle = engine.load_block_handle(state.block_id())?.unwrap();
                while !loser.snapshot().await.has_engine {
                    let generation = engine.namespace_registry.generation();
                    tokio::select! {
                        _ = async {
                            while !loser.snapshot().await.has_engine {
                                tokio::time::sleep(Duration::from_millis(10)).await;
                            }
                        } => break,
                        next = manager.wait_next_mc_or_materialization_retry(&handle, generation) => { next?; }
                    }
                    update_with_history_retry(&mut manager, state.clone()).await?;
                }
                Ok::<_, anyhow::Error>(())
            }).await.map_err(|e| error!("same-state warm retry: {e}"))??;
            anyhow::ensure!(Arc::ptr_eq(&loser, manager.current_sessions.get(runtime.session_id())
                .or_else(|| manager.future_sessions.get(runtime.session_id())).unwrap()), "warm retry replaced original Arc");
            anyhow::ensure!(engine.namespace_registry.reserve(&runtime)?.is_none(),
                "recovery competed with the live normal session");
        } else {
            update_with_history_retry(&mut manager, state.clone()).await?;
        }
        if idle_retry {
            let handle = engine.load_block_handle(state.block_id())?.unwrap();
            let target = manager.future_sessions.values().find(|g| {
                g.authenticated_runtime().is_some_and(|r| r.shard().is_masterchain() && r.catchain_seqno() == 1)
            }).ok_or_else(|| error!("idle target future absent"))?.clone();
            // Let every unrelated namespace settle before sampling the generation.
            tokio::time::timeout(Duration::from_secs(8), async {
                loop {
                    let mut ready = 0;
                    for group in manager.current_sessions.values().chain(manager.future_sessions.values()) {
                        if !Arc::ptr_eq(group, &target) && group.snapshot().await.has_engine { ready += 1; }
                    }
                    if ready == 3 && engine.future_history_failure_seen.load(Ordering::SeqCst) { break; }
                    let generation = engine.namespace_registry.generation();
                    manager.wait_next_mc_or_materialization_retry(&handle, generation).await?;
                    update_with_history_retry(&mut manager, state.clone()).await?;
                }
                Ok::<_, anyhow::Error>(())
            }).await.map_err(|e| error!("idle fixture settle: {e}"))??;
            anyhow::ensure!(!target.snapshot().await.has_engine, "held failure unexpectedly materialized target");
            let generation = engine.namespace_registry.generation();
            // Pure fault release: no registry mutation, wakeup or new MC input.
            engine.fail_future_history_until_released.store(false, Ordering::SeqCst);
            let next = tokio::time::timeout(Duration::from_secs(3),
                manager.wait_next_mc_or_materialization_retry(&handle, generation))
                .await.map_err(|e| error!("idle materialization timer did not retry: {e}"))??
                .ok_or_else(|| error!("idle manager unexpectedly stopped"))?;
            anyhow::ensure!(next.id() == handle.id(), "idle retry changed MC");
            anyhow::ensure!(engine.namespace_registry.generation() == generation,
                "namespace notification masked idle timer evidence");
            update_with_history_retry(&mut manager, state.clone()).await?;
            tokio::time::timeout(Duration::from_secs(5), async {
                while !target.snapshot().await.has_engine { tokio::time::sleep(Duration::from_millis(10)).await; }
            }).await.map_err(|e| error!("idle future failed materialization after timer: {e}"))?;
            let runtime = target.authenticated_runtime().unwrap();
            anyhow::ensure!(Arc::ptr_eq(&target, manager.future_sessions.get(runtime.session_id()).unwrap()));
            anyhow::ensure!(engine.namespace_registry.reserve(runtime)?.is_none(), "idle retry lost namespace ownership");
        }
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
            let recovery = runtime.recovery_binding()
                .ok_or_else(|| error!("Manager omitted authenticated recovery anchor"))?;
            anyhow::ensure!(&recovery.governing_masterchain == state.block_id(),
                "Recovery anchor must name the actual config source state");
            anyhow::ensure!(&recovery.coordinates.shard == runtime.shard());
            anyhow::ensure!(recovery.coordinates.catchain_seqno == runtime.catchain_seqno());
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
        let next = install_signed_manager_successor(engine.as_ref(), &bootstrap, &state)?;
        engine.install_masterchain_state(next.clone(), Some(state.block_id().clone()))?;
        update_with_history_retry(&mut manager, next.clone()).await?;
        wait_for_manager_sessions(&manager).await?;
        for (id, old) in first {
            let replacement = manager.current_sessions.get(&id).ok_or_else(|| error!("same-session replacement missing"))?;
            anyhow::ensure!(!Arc::ptr_eq(&old, replacement), "changed members reused old group");
            anyhow::ensure!(old.teardown_drained(), "old generation was not actually drained");
            anyhow::ensure!(replacement.snapshot().await.has_engine);
            anyhow::ensure!(replacement.authenticated_runtime().unwrap().members().contains(&rtos_block::KeyId::from_data([81; 32])));
        }
        let unchanged = manager.current_sessions.clone();
        update_with_history_retry(&mut manager, next).await?;
        for (id, original) in unchanged {
            let retained = manager.current_sessions.get(&id).ok_or_else(|| error!("unchanged admission disappeared"))?;
            anyhow::ensure!(Arc::ptr_eq(&original, retained), "unchanged admission was recreated");
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    let ids = manager.current_sessions.keys().chain(manager.future_sessions.keys()).cloned().collect();
    let stopped = manager.stop_and_remove_sessions(&ids).await;
    drop(manager);
    // Drive the outer production spawn entry with the real configuration
    // handler's false validator status. Only explicit transport eligibility can
    // get through its initial wait and create these additional real sessions.
    let spawned = if result.is_ok() && stopped.is_ok() && current_retry.is_none() {
        let baseline = engine.validator_network.authenticated_created.load(Ordering::SeqCst);
        engine.fail_future_history_once.store(true, Ordering::SeqCst);
        let mut manager_config = ValidatorManagerConfig::default();
        manager_config.update_interval = Duration::from_millis(20);
        match spawn_validator_manager(engine.clone(), tokio::runtime::Handle::current(), manager_config) {
            Ok(task) => {
                let started = tokio::time::timeout(Duration::from_secs(5), async {
                    while engine.validator_network.authenticated_created.load(Ordering::SeqCst) < baseline + 4 {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }).await;
                let injected = engine.future_history_failure_seen.load(Ordering::SeqCst);
                engine.stop.store(true, Ordering::SeqCst);
                let joined = task.await;
                started.map_err(|_| error!("outer manager did not retry future materialization without a new MC"))
                    .and_then(|_| if injected { Ok(()) } else { Err(error!("outer manager missed controlled future preparation failure")) })
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

/// Install a real block/state commitment and its independent quorum signature.
/// The normal lifecycle test still derives its changed state locally; a fixture
/// generated for another configuration or predecessor cannot satisfy this check.
fn install_signed_manager_successor(engine: &BootstrapTestEngine, bootstrap: &EmulatorNetworkBootstrap,
    previous: &Arc<ShardStateStuff>) -> Result<Arc<ShardStateStuff>> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!("data/manager-history.json"))?;
    anyhow::ensure!(fixture["zero"] == previous.block_id().to_string(), "signed fixture genesis differs");
    let expected = engine.build_masterchain_state(bootstrap, 1)?;
    let mut expected = expected.state()?.clone();
    expected.set_gen_lt(2);
    let mut extra = expected.read_custom()?.unwrap();
    extra.prev_blocks.set(&0, &rtos_block::KeyExtBlkRef { key: true, blk_ref: ext_blk_ref(previous.block_id()) },
        &rtos_block::KeyMaxLt { key: true, max_end_lt: 0 })?;
    expected.write_custom(Some(&extra))?;
    let bytes = hex::decode(fixture["block_boc"].as_str().ok_or_else(|| error!("Missing block fixture"))?)?;
    let root = rtos_block::read_single_root_boc(&bytes)?;
    let id = BlockIdExt::with_params(ShardIdent::masterchain(), 1, root.repr_hash().clone(), UInt256::calc_file_hash(&bytes));
    let block = BlockStuff::deserialize_block_checked(id.clone(), Arc::new(bytes))?;
    let state = ShardStateStuff::deserialize_state(id.clone(), &hex::decode(fixture["state_boc"].as_str().unwrap())?,
        #[cfg(feature = "telemetry")] &engine.telemetry, &engine.allocated)?;
    anyhow::ensure!(expected.serialize()?.repr_hash() == state.root_cell().repr_hash(), "signed successor differs from requested admission change");
    let update = block.block()?.read_state_update()?;
    anyhow::ensure!(&update.old_hash == previous.root_cell().repr_hash() && &update.new_hash == state.root_cell().repr_hash(), "state update commitments differ");
    let proof = crate::block_proof::BlockProofStuff::deserialize(&id,
        hex::decode(fixture["proof_boc"].as_str().unwrap())?, false)?;
    engine.blocks.write().unwrap().insert(id.clone(), block);
    engine.historical_proofs.write().unwrap().insert(id, proof);
    Ok(state)
}

#[tokio::test]
async fn replaced_observer_admission_records_only_an_orphaned_namespace() -> Result<()> {
    use consensus_common::validator_cleanup::{parse_canonical_namespace_name, NamespaceLayout};
    let key_a = Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[0x71; 32])?;
    let key_b = Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[0x72; 32])?;
    let mut bootstrap = EmulatorNetworkBootstrap::build(2)?;
    configure(&mut bootstrap, &key_a)?;
    let engine = Arc::new(BootstrapTestEngine::new_with_local_keys(&bootstrap, Vec::new()).await?);
    let state = engine.build_masterchain_state(&bootstrap, 0)?;
    engine.install_masterchain_state(state.clone(), None)?;
    let shard = ShardIdent::masterchain();
    let (info, id) =
        derive_governing_session_info(&state, &shard, bootstrap.validator_set.list(), 0, 0, 0)?;
    let runtime = |key: &PrivateKey| -> Result<Arc<AuthenticatedSessionRuntime>> {
        Ok(Arc::new(
            AuthenticatedSessionRuntime::from_authenticated_config(
                SessionNetworkPin {
                    global_id: state.state()?.global_id(),
                    zerostate: bootstrap.zerostate_id.clone(),
                },
                state.config_params()?,
                rtos_api::session_identity::SessionCoordinates {
                    shard: &shard,
                    catchain_seqno: 0,
                    vertical_seqno: 0,
                    last_key_block_seqno: 0,
                    new_catchain_ids: false,
                },
                bootstrap.validator_set.list().to_vec(),
                key.id().clone(),
            )?
            .bind_recovery_anchor(bootstrap.zerostate_id.clone())?,
        ))
    };
    let group = |key: &PrivateKey, runtime: Arc<AuthenticatedSessionRuntime>| -> Result<Arc<ValidatorGroup>> {
        let options = SimplexSessionOptions {
            protocol: runtime.protocol(),
            proto_version: runtime.carrier_version(),
            wire_profile: runtime.wire_profile(),
            slots_per_leader_window: runtime.slots_per_leader_window(),
            ..Default::default()
        };
        Ok(Arc::new(
            ValidatorGroup::new(
                info.clone(),
                key.clone(),
                id.clone(),
                UInt256::from([1; 32]),
                bootstrap.validator_set.clone(),
                0,
                ConsensusOptions::Simplex(options),
                engine.clone(),
                false,
                None,
            )
            .with_authenticated_runtime(runtime)?,
        ))
    };
    let (runtime_a, runtime_b) = (runtime(&key_a)?, runtime(&key_b)?);
    assert_eq!(runtime_a.session_id(), runtime_b.session_id(), "one session");
    assert_eq!(runtime_a.local_role(), LocalRole::Observer);
    let mut manager = ValidatorManagerImpl::create(
        engine.clone(),
        tokio::runtime::Handle::current(),
        ValidatorManagerConfig::default(),
    );
    let fence = manager.destroyed_sessions.clone();
    // The same ADNL keeps its namespace: nothing is recorded.
    let same = runtime(&key_a)?;
    manager.retire_replaced_admission(id.clone(), group(&key_a, runtime_a.clone())?, &same);
    assert!(manager.pending_cleanup_records.is_empty());
    assert!(manager.retiring_groups.iter().all(|(_, _, generation)| generation.is_none()));
    // Another ADNL orphans the old observer namespace: one record, no fence.
    manager.retire_replaced_admission(id.clone(), group(&key_a, runtime_a.clone())?, &runtime_b);
    assert_eq!(manager.pending_cleanup_records.len(), 1);
    let record = manager.pending_cleanup_records[0].clone();
    assert_eq!(&record.session_id, &id);
    let adnl_a = UInt256::from(*runtime_a.local_adnl().data());
    assert_eq!(
        parse_canonical_namespace_name(&record.namespace, &id).map(|parsed| parsed.layout),
        Some(NamespaceLayout::V2Observer(adnl_a.clone()))
    );
    assert_eq!(record.identity.as_ref().map(|identity| &identity.local_adnl), Some(&adnl_a));
    assert_eq!(manager.destroyed_sessions, fence, "the session stays live: no fence");
    assert!(manager
        .retiring_groups
        .iter()
        .any(|(_, _, generation)| generation.as_ref().is_some_and(|(ns, _)| ns == &record.namespace)));
    Ok(())
}
