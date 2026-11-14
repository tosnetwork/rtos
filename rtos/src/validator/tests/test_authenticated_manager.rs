// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Manager/group fixtures use generated governing states and real ADNL ownership.
//! The Engine adapter supplies deterministic state; it is not a full Engine test.
use super::*;
use consensus_common::session_runtime::{
    AuthenticatedSessionRuntime, LocalRole, SessionNetworkPin,
};
use rtos_block::HashmapAugType;

fn configure(bootstrap: &mut EmulatorNetworkBootstrap, observer: &PrivateKey) -> Result<()> {
    // Public fixture transport seeds make the independently signed history
    // reproducible. This does not install any PQ signing capability in the node.
    for (index, validator) in bootstrap.validators.iter_mut().enumerate() {
        let (json, key) = Ed25519KeyOption::<ZeroizingBytes>::from_private_key_with_json(
            &[0x60 + index as u8; 32],
        )?;
        validator.adnl_key_json = json;
        validator.validator_descr.adnl_addr = Some(UInt256::from(*key.id().data()));
        validator.adnl_key = key;
    }
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../../tl/rtos_api/tests/data/live-pq.json"))?;
    let members: Vec<_> = (0..2)
        .map(|index| {
            let row = fixture["rows"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["index"] == index && row["context"] == "TOS-CONSENSUS-SIMPLEX-v1")
                .unwrap();
            let public_key = hex::decode(row["public_key"].as_str().unwrap()).unwrap();
            ValidatorDescr::with_pq_params(
                UInt256::from([index as u8 + 1; 32]),
                rtos_block::PqConsensusKey {
                    algorithm_id: 1,
                    key_id: rtos_block::derive_consensus_key_id(1, &public_key),
                    public_key,
                },
                1,
                UInt256::from(*bootstrap.validators[index].adnl_key.id().data()),
            )
        })
        .collect();
    bootstrap.validator_set = ValidatorSet::with_cc_seqno(0, u32::MAX, 2, 0, members.clone())?;
    bootstrap.config_params.set_config(ConfigParamEnum::ConfigParam34(ConfigParam34 {
        cur_validators: bootstrap.validator_set.clone(),
    }))?;
    let mut previous = members[0].clone();
    previous.adnl_addr = Some(UInt256::from(*observer.id().data()));
    bootstrap.config_params.set_config(ConfigParamEnum::ConfigParam32(
        rtos_block::ConfigParam32 {
            prev_validators: ValidatorSet::with_cc_seqno(0, u32::MAX, 1, 0, vec![previous])?,
        },
    ))?;
    // The signed manager history pins the genesis built with a 2400 ms target rate.
    let v2 = SimplexConfig {
        protocol_version: 2,
        noncritical_params: rtos_block::NoncriticalParams {
            target_rate_ms: 2400,
            ..Default::default()
        },
        ..Default::default()
    };
    bootstrap.config_params.set_config(ConfigParamEnum::ConfigParam30(NewConsensusConfigAll {
        mc: Some(v2.clone()),
        shard: Some(v2),
    }))?;
    let mut catchain = bootstrap.config_params.catchain_config()?;
    catchain.shard_validators_num = 2;
    bootstrap.config_params.set_config(ConfigParamEnum::ConfigParam28(catchain))?;
    Ok(())
}

/// The role the lifecycle fixture admits this node for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FixtureRole {
    /// It custodies a previous-set descriptor outside the committee, so the
    /// reference observer selection admits it as an observer of the current
    /// sessions; observers exist for current sessions only.
    Observer,
    /// It custodies committee member 0, so it validates the current and the
    /// future sessions with that member's custody signer.
    Validator,
}

/// One custody-backed lifecycle fixture: a two-member post-quantum committee
/// whose consensus keys this test holds (it signs the successor block), and
/// one previous-set descriptor outside the committee.
struct CustodyLifecycle {
    committee: Vec<Arc<rtos_pq_consensus::ConsensusKeyStore>>,
    outside: Arc<rtos_pq_consensus::ConsensusKeyStore>,
    outside_id: UInt256,
    outside_transport: PrivateKey,
}

impl CustodyLifecycle {
    /// Every test case uses seeds of its own: a retired key stays retired for
    /// the rest of the process.
    fn new(seed: u8) -> Result<Self> {
        let store = |byte: u8| -> Result<Arc<rtos_pq_consensus::ConsensusKeyStore>> {
            Ok(Arc::new(rtos_pq_consensus::ConsensusKeyStore::from_seed(&[byte; 32], 0)?))
        };
        Ok(Self {
            committee: vec![store(seed)?, store(seed.wrapping_add(1))?],
            outside: store(seed.wrapping_add(2))?,
            outside_id: UInt256::from([seed.wrapping_add(2); 32]),
            outside_transport: Ed25519KeyOption::<ZeroizingBytes>::from_private_key(
                &[seed.wrapping_add(3); 32],
            )?,
        })
    }

    fn member_id(index: usize) -> UInt256 {
        UInt256::from([index as u8 + 1; 32])
    }

    fn configure(&self, bootstrap: &mut EmulatorNetworkBootstrap) -> Result<()> {
        let members: Vec<_> = self
            .committee
            .iter()
            .enumerate()
            .map(|(index, store)| {
                ValidatorDescr::with_pq_params(
                    Self::member_id(index),
                    store.consensus_key().clone(),
                    1,
                    UInt256::from(*bootstrap.validators[index].adnl_key.id().data()),
                )
            })
            .collect();
        bootstrap.validator_set = ValidatorSet::with_cc_seqno(0, u32::MAX, 2, 0, members)?;
        bootstrap.config_params.set_config(ConfigParamEnum::ConfigParam34(ConfigParam34 {
            cur_validators: bootstrap.validator_set.clone(),
        }))?;
        let outside = ValidatorDescr::with_pq_params(
            self.outside_id.clone(),
            self.outside.consensus_key().clone(),
            1,
            UInt256::from(*self.outside_transport.id().data()),
        );
        bootstrap.config_params.set_config(ConfigParamEnum::ConfigParam32(
            rtos_block::ConfigParam32 {
                prev_validators: ValidatorSet::with_cc_seqno(0, u32::MAX, 1, 0, vec![outside])?,
            },
        ))?;
        let v2 = SimplexConfig {
            protocol_version: 2,
            noncritical_params: rtos_block::NoncriticalParams {
                target_rate_ms: 2400,
                ..Default::default()
            },
            ..Default::default()
        };
        bootstrap.config_params.set_config(ConfigParamEnum::ConfigParam30(
            NewConsensusConfigAll { mc: Some(v2.clone()), shard: Some(v2) },
        ))?;
        let mut catchain = bootstrap.config_params.catchain_config()?;
        catchain.shard_validators_num = 2;
        bootstrap.config_params.set_config(ConfigParamEnum::ConfigParam28(catchain))?;
        Ok(())
    }

    fn custody(
        &self,
        role: FixtureRole,
    ) -> Result<Arc<crate::pq_consensus_config::PqCustodyShared>> {
        let (validator, store) = match role {
            FixtureRole::Observer => (self.outside_id.clone(), self.outside.clone()),
            FixtureRole::Validator => (Self::member_id(0), self.committee[0].clone()),
        };
        let mut custody = rtos_pq_consensus::PqConsensusCustody::default();
        custody.install(validator.clone(), store, 0, 0)?;
        Ok(Arc::new(crate::pq_consensus_config::PqCustodyShared::new(validator, custody)))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_manager_creates_transport_only_observer_and_retires_real_groups(
) -> Result<()> {
    run_authenticated_manager_observer_lifecycle(
        0x80,
        FixtureRole::Observer,
        false,
        None,
        false,
        None,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_manager_retries_transient_sink_initialization_on_same_group() -> Result<()> {
    run_authenticated_manager_observer_lifecycle(
        0x84,
        FixtureRole::Observer,
        true,
        None,
        false,
        None,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_manager_retries_normal_loser_after_recovery_admission_on_same_state(
) -> Result<()> {
    run_authenticated_manager_observer_lifecycle(
        0x88,
        FixtureRole::Observer,
        false,
        Some(0),
        false,
        None,
    )
    .await
}

/// Future groups exist only for a session this node is a member of, as in
/// the reference manager; the future recovery race runs as a validator.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_manager_retries_existing_future_after_recovery_admission_on_same_state(
) -> Result<()> {
    run_authenticated_manager_observer_lifecycle(
        0x8c,
        FixtureRole::Validator,
        false,
        Some(1),
        false,
        None,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_manager_retries_idle_future_without_namespace_notification() -> Result<()> {
    run_authenticated_manager_observer_lifecycle(
        0x90,
        FixtureRole::Validator,
        false,
        None,
        true,
        None,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_manager_current_busy_preserves_group_in_real_invocation() -> Result<()> {
    run_authenticated_manager_observer_lifecycle(
        0x94,
        FixtureRole::Observer,
        false,
        None,
        false,
        Some(true),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_manager_current_authentication_error_exits_real_invocation() -> Result<()> {
    run_authenticated_manager_observer_lifecycle(
        0x98,
        FixtureRole::Observer,
        false,
        None,
        false,
        Some(false),
    )
    .await
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
                    let handle = manager
                        .engine
                        .load_block_handle(state.block_id())?
                        .ok_or_else(|| error!("fixture retry MC handle absent"))?;
                    let next = manager
                        .wait_next_mc_or_materialization_retry(&handle, generation)
                        .await?
                        .ok_or_else(|| error!("fixture manager stopped during history retry"))?;
                    anyhow::ensure!(
                        next.id() == state.block_id(),
                        "fixture received unexpected MC during retry"
                    );
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await
    .map_err(|error| error!("fixture typed history retry deadline: {error}"))?
}

/// Every live group of the manager: its current, future and observer groups.
fn live_groups(manager: &ValidatorManagerImpl) -> Vec<Arc<ValidatorGroup>> {
    manager
        .current_sessions
        .values()
        .chain(manager.future_sessions.values())
        .chain(manager.observer_groups.values())
        .cloned()
        .collect()
}

/// The groups of current sessions: observer groups for an observer, current
/// validator groups for a validator.
fn current_groups(
    manager: &ValidatorManagerImpl,
    role: FixtureRole,
) -> HashMap<UInt256, Arc<ValidatorGroup>> {
    match role {
        FixtureRole::Validator => manager.current_sessions.clone(),
        FixtureRole::Observer => manager
            .observer_groups
            .iter()
            .map(|((session, _), group)| (session.clone(), group.clone()))
            .collect(),
    }
}

/// The current or future group of `session`, of either role.
fn group_of(manager: &ValidatorManagerImpl, session: &UInt256) -> Option<Arc<ValidatorGroup>> {
    manager
        .current_sessions
        .get(session)
        .or_else(|| manager.future_sessions.get(session))
        .cloned()
        .or_else(|| {
            manager
                .observer_groups
                .iter()
                .find(|((id, _), _)| id == session)
                .map(|(_, group)| group.clone())
        })
}

async fn run_authenticated_manager_observer_lifecycle(
    seed: u8,
    role: FixtureRole,
    fail_initial_sink: bool,
    admission_race: Option<u32>,
    idle_retry: bool,
    current_retry: Option<bool>,
) -> Result<()> {
    use adnl::{node::AdnlNode, DhtNode, NetworkStack, OverlayNode, RldpNode};
    let _ = env_logger::builder().is_test(true).try_init();
    eprintln!("manager lifecycle: begin role={role:?} admission_race={admission_race:?}");
    let fixture = CustodyLifecycle::new(seed)?;
    let mut bootstrap = EmulatorNetworkBootstrap::build(2)?;
    fixture.configure(&mut bootstrap)?;
    // The node's ADNL identity is its own transport key: the outside
    // descriptor's for an observer, committee member 0's for a validator.
    let local_transport = match role {
        FixtureRole::Observer => fixture.outside_transport.clone(),
        FixtureRole::Validator => bootstrap.validators[0].adnl_key.clone(),
    };
    let (_, config) =
        AdnlNodeConfig::from_ip_address_and_private_keys("127.0.0.1:0", vec![([seed; 32], 0)])?;
    let adnl = AdnlNode::with_config(config).await?;
    adnl.add_key(local_transport.clone(), 1)?;
    // Possession of another governing member's transport key confers nothing.
    if role == FixtureRole::Observer {
        adnl.add_key(bootstrap.validators[0].adnl_key.clone(), 2)?;
    }
    let dht = DhtNode::with_adnl_node(adnl.clone(), 0)?;
    let overlay = OverlayNode::with_params_and_profile(
        adnl.clone(),
        &[22; 32],
        0,
        rtos_api::WireProfile::T0,
    )?;
    let rldp = RldpNode::with_params(adnl.clone(), vec![overlay.clone()], None)?;
    overlay.set_rldp(rldp.clone())?;
    let stack = Arc::new(NetworkStack { adnl: adnl.clone(), dht, overlay, rldp, quic: None });
    adnl.start_over_udp(vec![stack.overlay.clone(), stack.dht.clone(), stack.rldp.clone()]).await?;
    let actual = consensus_common::ConsensusCommonFactory::create_adnl_overlay_manager(
        tokio::runtime::Handle::current(),
        stack,
        None,
        false,
    )?;
    let local_config = serde_json::from_value(serde_json::json!({
        "validator_keys": [],
        "validator_key_ring": {},
    }))?;
    let (handler, context) =
        crate::config::NodeConfigHandler::create(local_config, tokio::runtime::Handle::current())?;
    handler.clone().start_sheduler(context, vec![])?;
    let mut engine = BootstrapTestEngine::new_with_local_keys(&bootstrap, Vec::new()).await?;
    engine.transport_config = Some(handler.clone());
    engine.custody = Some(fixture.custody(role)?);
    let network = Arc::get_mut(&mut engine.validator_network).unwrap();
    network.authenticated = Some(actual);
    network.transport_keys.push(local_transport.clone());
    if role == FixtureRole::Observer {
        network.transport_keys.push(bootstrap.validators[0].adnl_key.clone());
    }
    let state = engine.build_masterchain_state(&bootstrap, 0)?;
    bootstrap.zerostate_id = state.block_id().clone();
    engine.init_mc_block_id = state.block_id().clone();
    let engine = Arc::new(engine);
    let mut manager = ValidatorManagerImpl::create(
        engine.clone(),
        tokio::runtime::Handle::current(),
        ValidatorManagerConfig::default(),
    );
    // Sessions a full start materializes: two current groups, and for a
    // validator two future groups as well.
    let session_count = match role {
        FixtureRole::Observer => 2,
        FixtureRole::Validator => 4,
    };
    let result = async {
        anyhow::ensure!(!engine.get_validator_status(), "no legacy signing eligibility permitted");
        engine.install_masterchain_state(state.clone(), None)?;
        if let Some(retryable) = current_retry {
            engine.fail_current_history_busy_once.store(true, Ordering::SeqCst);
            let error = manager.update_shards(state.clone()).await.expect_err("controlled current busy");
            anyhow::ensure!(crate::retired_history::is_retryable(&error));
            let original = current_groups(&manager, role).into_values().find(|g| {
                g.authenticated_runtime().is_some_and(|r| r.shard().is_masterchain())
            }).ok_or_else(|| error!("failed current group ownership missing"))?;
            anyhow::ensure!(!original.snapshot().await.has_engine);
            anyhow::ensure!(!original.is_start_pending().await);
            if retryable {
                engine.fail_current_history_busy_once.store(true, Ordering::SeqCst);
                let completion = async {
                    let result = tokio::time::timeout(Duration::from_secs(8), async {
                        while !original.snapshot().await.has_engine {
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
            anyhow::ensure!(group_of(&manager, runtime.session_id()).is_some_and(|g| Arc::ptr_eq(&original, &g)),
                "invocation replaced original group instead of retaining ownership");
            return Ok(());
        }
        engine.fail_future_history_until_released.store(idle_retry, Ordering::SeqCst);
        let failed_group = if fail_initial_sink {
            engine.fail_finality_sink_once.store(true, Ordering::SeqCst);
            let error = manager.update_shards(state.clone()).await.err()
                .ok_or_else(|| error!("Expected sink initialization failure"))?;
            anyhow::ensure!(error.to_string().contains("Injected transient finality sink"));
            let failed = live_groups(&manager);
            let mut stopped = None;
            for group in failed {
                if !group.snapshot().await.has_engine {
                    stopped = Some(group);
                }
            }
            let group = stopped.ok_or_else(|| error!("Partially started group ownership was lost"))?;
            anyhow::ensure!(!group.is_start_pending().await, "failed sink left a permanently pending start");
            let id = group.authenticated_runtime().unwrap().session_id().clone();
            Some((id, group))
        } else { None };
        if let Some(target_seqno) = admission_race {
            let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            *engine.normal_admission_gate.lock().unwrap() = Some((target_seqno, entered_tx, release_rx));
            // The gate blocks the thread of the admission it holds; the race
            // runs on a task of its own so that admission cannot starve it.
            let race_done = Arc::new(tokio::sync::Notify::new());
            let (race_engine, race_notify) = (engine.clone(), race_done.clone());
            let race = tokio::spawn(async move {
                let engine = race_engine;
                let runtime = tokio::time::timeout(Duration::from_secs(10), entered_rx).await
                    .map_err(|e| error!("manager phase=await-normal-admission-gate target_cc={target_seqno}: {e}"))?
                    .map_err(|e| error!("manager phase=normal-admission-gate-channel target_cc={target_seqno}: {e}"))?;
                eprintln!("manager lifecycle: gate entered target_cc={target_seqno}");
                // Normal manager already selected its group. Recovery now wins
                // actual atomic admission before the normal factory can start.
                let token = engine.namespace_registry.reserve(&runtime)?.ok_or_else(|| error!("recovery lost gated race"))?;
                release_tx.send(()).map_err(|e| error!("release normal gate: {e}"))?;
                race_notify.notify_one();
                Ok::<_, anyhow::Error>((runtime, token))
            });
            let race = async { race.await.map_err(|e| error!("recovery race task: {e}"))? };
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
            let loser = group_of(&manager, runtime.session_id()).ok_or_else(|| error!("normal loser group disappeared"))?;
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while loser.is_start_pending().await && std::time::Instant::now() < deadline { tokio::time::sleep(Duration::from_millis(10)).await; }
            let did_create = loser.snapshot().await.has_engine;
            let generation = engine.namespace_registry.generation();
            token.release();
            engine.namespace_registry.wait_changed(generation).await?;
            anyhow::ensure!(!did_create, "normal loser created a competing session");
            update_with_history_retry(&mut manager, state.clone()).await?;
            anyhow::ensure!(group_of(&manager, runtime.session_id()).is_some_and(|g| Arc::ptr_eq(&loser, &g)), "same-state retry replaced loser group");
            // Existing groups must warm up again on this same MC state;
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
            anyhow::ensure!(group_of(&manager, runtime.session_id()).is_some_and(|g| Arc::ptr_eq(&loser, &g)), "warm retry replaced original Arc");
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
                    for group in live_groups(&manager) {
                        if !Arc::ptr_eq(&group, &target) && group.snapshot().await.has_engine { ready += 1; }
                    }
                    if ready == session_count - 1 && engine.future_history_failure_seen.load(Ordering::SeqCst) { break; }
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
            let retried = group_of(&manager, &id).ok_or_else(|| error!("Failed group was lost during retry"))?;
            anyhow::ensure!(Arc::ptr_eq(&original, &retried), "Retry replaced the group instead of releasing its reservation");
        }
        let current = current_groups(&manager, role);
        anyhow::ensure!(current.len() == 2, "expected MC + shard actual groups");
        anyhow::ensure!(manager.block_sync_observers.is_empty(), "v2 must not use v1 block-sync topology");
        match role {
            FixtureRole::Observer => {
                anyhow::ensure!(manager.validator_list_status.curr.is_none(), "fixture must have no PQ signing identity");
                anyhow::ensure!(manager.owned_current_shards == 0, "observer incorrectly marked validator");
                anyhow::ensure!(manager.current_sessions.is_empty() && manager.future_sessions.is_empty(),
                    "an observer got a validator group");
            }
            FixtureRole::Validator => {
                anyhow::ensure!(manager.observer_groups.is_empty(), "a committee member observed its own session");
                anyhow::ensure!(manager.future_sessions.len() == 2, "expected MC + shard future groups");
            }
        }
        for group in current.values() {
            let runtime = group.authenticated_runtime().ok_or_else(|| error!("runtime missing"))?;
            match role {
                FixtureRole::Observer => {
                    anyhow::ensure!(runtime.local_role() == LocalRole::Observer);
                    anyhow::ensure!(runtime.local_adnl() == fixture.outside_transport.id());
                    anyhow::ensure!(group.consensus_signer().is_none(), "an observer has a signer");
                }
                FixtureRole::Validator => {
                    anyhow::ensure!(runtime.local_role() == LocalRole::Validator(0));
                    anyhow::ensure!(group.consensus_signer().is_some(), "a validator lacks its signer");
                }
            }
            let recovery = runtime.recovery_binding()
                .ok_or_else(|| error!("Manager omitted authenticated recovery anchor"))?;
            anyhow::ensure!(&recovery.governing_masterchain == state.block_id(),
                "Recovery anchor must name the actual config source state");
            anyhow::ensure!(&recovery.coordinates.shard == runtime.shard());
            anyhow::ensure!(recovery.coordinates.catchain_seqno == runtime.catchain_seqno());
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let mut ready = true;
                for group in live_groups(&manager) {
                    ready &= group.snapshot().await.has_engine;
                }
                if ready { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.map_err(|e| error!("groups never created real sessions: {e}"))?;
        if role == FixtureRole::Observer {
            anyhow::ensure!(engine.validation_status() == ValidationStatus::Disabled);
        }
        let first = current_groups(&manager, role);
        // A changed previous total set changes every runtime's members: the
        // groups are replaced and the old generations drained.
        let previous = bootstrap.config_params.prev_validator_set()?;
        let mut extra = bootstrap.validator_set.list()[1].clone();
        extra.adnl_addr = Some(UInt256::from([81; 32]));
        let mut previous_members = previous.list().to_vec();
        previous_members.push(extra);
        bootstrap.config_params.set_config(ConfigParamEnum::ConfigParam32(rtos_block::ConfigParam32 {
            prev_validators: ValidatorSet::with_cc_seqno(0, u32::MAX, 2, 0, previous_members)?,
        }))?;
        let next = sign_manager_successor(engine.as_ref(), &bootstrap, &state, &fixture.committee)?;
        engine.install_masterchain_state(next.clone(), Some(state.block_id().clone()))?;
        update_with_history_retry(&mut manager, next.clone()).await?;
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let mut ready = true;
                for group in live_groups(&manager) {
                    ready &= group.snapshot().await.has_engine;
                }
                if ready { break; }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.map_err(|e| error!("replacement groups never created real sessions: {e}"))?;
        let replaced = current_groups(&manager, role);
        for (id, old) in first {
            let replacement = replaced.get(&id).ok_or_else(|| error!("same-session replacement missing"))?;
            anyhow::ensure!(!Arc::ptr_eq(&old, replacement), "changed members reused old group");
            anyhow::ensure!(old.teardown_drained(), "old generation was not actually drained");
            anyhow::ensure!(replacement.snapshot().await.has_engine);
            anyhow::ensure!(replacement.authenticated_runtime().unwrap().members().contains(&rtos_block::KeyId::from_data([81; 32])));
        }
        let unchanged = current_groups(&manager, role);
        update_with_history_retry(&mut manager, next).await?;
        let retained_groups = current_groups(&manager, role);
        for (id, original) in unchanged {
            let retained = retained_groups.get(&id).ok_or_else(|| error!("unchanged admission disappeared"))?;
            anyhow::ensure!(Arc::ptr_eq(&original, retained), "unchanged admission was recreated");
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    // The namespaces of the live groups and their manifests: a restarted
    // manager reopens exactly these, never a fresh one.
    let mut manifests = Vec::new();
    for group in live_groups(&manager) {
        if let Some(runtime) = group.authenticated_runtime() {
            let namespace = std::path::PathBuf::from(
                runtime.runtime_directory(&format!("{}/catchains", engine.db_root))?,
            );
            let manifest = std::fs::read(namespace.join("session-runtime.json")).ok();
            manifests.push((namespace, manifest));
        }
    }
    let ids =
        manager.current_sessions.keys().chain(manager.future_sessions.keys()).cloned().collect();
    let stopped = manager.stop_and_remove_sessions(&ids).await;
    let stopped = match stopped {
        Ok(()) => manager.stop_validation().await,
        Err(error) => Err(error),
    };
    drop(manager);
    // Drive the outer production spawn entry with the real configuration
    // handler: custody alone makes it run and create these real sessions.
    let spawned = if result.is_ok() && stopped.is_ok() && current_retry.is_none() {
        let baseline = engine.validator_network.authenticated_created.load(Ordering::SeqCst);
        engine.fail_future_history_once.store(role == FixtureRole::Validator, Ordering::SeqCst);
        let mut manager_config = ValidatorManagerConfig::default();
        manager_config.update_interval = Duration::from_millis(20);
        match spawn_validator_manager(
            engine.clone(),
            tokio::runtime::Handle::current(),
            manager_config,
        ) {
            Ok(task) => {
                let started = tokio::time::timeout(Duration::from_secs(5), async {
                    while engine.validator_network.authenticated_created.load(Ordering::SeqCst)
                        < baseline + session_count
                    {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await;
                let injected = role == FixtureRole::Observer
                    || engine.future_history_failure_seen.load(Ordering::SeqCst);
                engine.stop.store(true, Ordering::SeqCst);
                let joined = task.await;
                let reopened = (|| {
                    for (namespace, manifest) in &manifests {
                        let manifest = manifest
                            .as_ref()
                            .ok_or_else(|| error!("{} had no manifest", namespace.display()))?;
                        anyhow::ensure!(
                            std::fs::read(namespace.join("session-runtime.json")).ok().as_ref()
                                == Some(manifest),
                            "{} was not reopened as the same namespace",
                            namespace.display()
                        );
                    }
                    anyhow::ensure!(!manifests.is_empty(), "no namespace was created");
                    Ok(())
                })();
                started
                    .map_err(|_| {
                        error!("outer manager did not retry materialization without a new MC")
                    })
                    .and_then(|_| {
                        if injected {
                            Ok(())
                        } else {
                            Err(error!(
                                "outer manager missed controlled future preparation failure"
                            ))
                        }
                    })
                    .and_then(|_| joined.map_err(|error| error!("manager task failed: {error}")))
                    .and(reopened)
            }
            Err(error) => Err(error),
        }
    } else {
        Ok(())
    };
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
    for member in &classical {
        expected.update(member.compute_node_id_short()?.as_slice());
    }
    assert_eq!(
        compute_validator_list_id(&classical, None)?.unwrap(),
        UInt256::from(<[u8; 32]>::from(expected.finalize()))
    );
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
    let (info, id) =
        derive_governing_session_info(&state, &shard, bootstrap.validator_set.list(), 0, 0, 0)?;
    let make_runtime = |zerostate: BlockIdExt| -> Result<Arc<AuthenticatedSessionRuntime>> {
        Ok(Arc::new(AuthenticatedSessionRuntime::from_authenticated_config(
            SessionNetworkPin { global_id: state.state()?.global_id(), zerostate },
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
        )?))
    };
    let runtime = make_runtime(bootstrap.zerostate_id.clone())?;
    let options = SimplexSessionOptions {
        protocol: runtime.protocol(),
        proto_version: runtime.carrier_version(),
        wire_profile: runtime.wire_profile(),
        slots_per_leader_window: runtime.slots_per_leader_window(),
        ..Default::default()
    };
    let group = |options| {
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
    };
    let attached = group(options.clone()).with_authenticated_runtime(runtime.clone())?;
    assert_eq!(attached.authenticated_runtime().unwrap().local_role(), LocalRole::Observer);
    assert!(attached.with_authenticated_runtime(runtime.clone()).is_err());
    let mut bad_slots = options.clone();
    bad_slots.slots_per_leader_window += 1;
    assert!(group(bad_slots).with_authenticated_runtime(runtime.clone()).is_err());
    for root in [true, false] {
        let mut zero = bootstrap.zerostate_id.clone();
        if root {
            zero.root_hash = UInt256::from([31; 32]);
        } else {
            zero.file_hash = UInt256::from([32; 32]);
        }
        let wrong = make_runtime(zero)?;
        assert_eq!(
            wrong.session_id(),
            runtime.session_id(),
            "anchor is independent from session hash"
        );
        assert!(group(options.clone()).with_authenticated_runtime(wrong).is_err());
    }
    Ok(())
}

/// Install a real masterchain successor of `previous`: the state the changed
/// `bootstrap` configuration builds, a block whose Merkle update commits
/// `previous` to it, and a finality proof signed by the committee's custody
/// keys and checked against the governing configuration before use.
fn sign_manager_successor(
    engine: &BootstrapTestEngine,
    bootstrap: &EmulatorNetworkBootstrap,
    previous: &Arc<ShardStateStuff>,
    committee: &[Arc<rtos_pq_consensus::ConsensusKeyStore>],
) -> Result<Arc<ShardStateStuff>> {
    use rtos_block::{
        BlkPrevInfo, Block, BlockExtra, BlockInfo, BlockProof, BlockSignaturesSimplex,
        BlockSignaturesSimplexPq, BlockSignaturesVariant, BocFlags, BocWriter, McBlockExtra,
        MerkleProof, MerkleUpdate, PqBlockSignaturePair, ValidatorBaseInfo, ValueFlow,
    };
    let expected = engine.build_masterchain_state(bootstrap, 1)?;
    let mut state = expected.state()?.clone();
    state.set_gen_lt(2);
    let mut extra =
        state.read_custom()?.ok_or_else(|| error!("successor has no masterchain extra"))?;
    extra.prev_blocks.set(
        &0,
        &rtos_block::KeyExtBlkRef { key: true, blk_ref: ext_blk_ref(previous.block_id()) },
        &rtos_block::KeyMaxLt { key: true, max_end_lt: 0 },
    )?;
    state.write_custom(Some(&extra))?;
    let next_root = state.serialize()?;
    let update = MerkleUpdate::create(previous.root_cell(), &next_root)?;
    let previous_config = previous.config_params()?;
    let placeholder = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        1,
        UInt256::default(),
        UInt256::default(),
    );
    let context = rtos_api::pq_finality::PqVerificationContext::from_governing_config(
        0,
        previous_config,
        placeholder,
        0,
        0,
        0,
    )?;
    let mut info = BlockInfo::default();
    info.set_seq_no(1)?;
    info.set_shard(ShardIdent::masterchain());
    info.set_gen_utime(1);
    info.set_start_lt(1);
    info.set_end_lt(2);
    info.set_gen_catchain_seqno(0);
    info.set_prev_key_block_seqno(0);
    info.set_gen_validator_list_hash_short(context.subset_hash());
    info.set_prev_stuff(false, &BlkPrevInfo::Block { prev: ext_blk_ref(previous.block_id()) })?;
    let mut custom = McBlockExtra::default();
    *custom.shards_mut() = extra.shards().clone();
    let mut block_extra = BlockExtra::default();
    block_extra.write_custom(&custom)?;
    let block = Block::with_params(0, info, ValueFlow::default(), update, block_extra)?;
    let root = block.serialize()?;
    let bytes = BocWriter::with_flags([root.clone()], BocFlags::all())?.write_to_vec()?;
    let id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        1,
        root.repr_hash().clone(),
        UInt256::calc_file_hash(&bytes),
    );
    let context = rtos_api::pq_finality::PqVerificationContext::from_governing_config(
        0,
        previous_config,
        id.clone(),
        0,
        0,
        0,
    )?;
    // consensus.candidateHashDataOrdinary of this block with an empty collated hash.
    let mut candidate = 0x3f6431f8u32.to_le_bytes().to_vec();
    candidate.extend((-1i32).to_le_bytes());
    candidate.extend(rtos_block::SHARD_FULL.to_le_bytes());
    candidate.extend(1u32.to_le_bytes());
    candidate.extend(id.root_hash.as_slice());
    candidate.extend(id.file_hash.as_slice());
    candidate.extend(UInt256::calc_file_hash(&[]).as_slice());
    let parent = rtos_api::ton::consensus::candidateparent::CandidateParent {
        id: rtos_api::IntoBoxed::into_boxed(rtos_api::ton::consensus::candidateid::CandidateId {
            slot: 98,
            hash: UInt256::from([98; 32]),
        }),
    };
    candidate
        .extend(rtos_api::WireProfile::T0.serialize(&rtos_api::IntoBoxed::into_boxed(parent))?);
    let mut carrier = BlockSignaturesSimplexPq {
        validator_info: ValidatorBaseInfo::with_params(context.subset_hash(), 0),
        session_id: context.expected_session_id().clone(),
        slot: 99,
        candidate_data: BlockSignaturesSimplex::bytes_to_cell_tree(&candidate)?,
        sig_count: 2,
        sig_weight: 2,
        signatures: vec![],
    };
    let message = rtos_api::pq_finality::final_vote_preimage(&id, &carrier)?;
    for (index, store) in committee.iter().enumerate() {
        carrier.signatures.push(PqBlockSignaturePair {
            validator_id: CustodyLifecycle::member_id(index),
            algorithm_id: 1,
            signature: store.sign_consensus(&message)?.bytes.to_vec(),
        });
    }
    context.verify_final(&carrier)?;
    let proof = BlockProof::with_params(
        id.clone(),
        MerkleProof::create(&root, |_| true)?.serialize()?,
        Some(BlockSignaturesVariant::SimplexPq(carrier)),
    );
    let proof =
        crate::block_proof::BlockProofStuff::deserialize(&id, proof.write_to_bytes()?, false)?;
    let state = ShardStateStuff::deserialize_state(
        id.clone(),
        &rtos_block::write_boc(&next_root)?,
        #[cfg(feature = "telemetry")]
        &engine.telemetry,
        &engine.allocated,
    )?;
    let block = BlockStuff::deserialize_block_checked(id.clone(), Arc::new(bytes))?;
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
    let group = |key: &PrivateKey,
                 runtime: Arc<AuthenticatedSessionRuntime>|
     -> Result<Arc<ValidatorGroup>> {
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
    assert!(manager.retiring_groups.iter().any(|(_, _, generation)| generation
        .as_ref()
        .is_some_and(|(ns, _)| ns == &record.namespace)));
    Ok(())
}
