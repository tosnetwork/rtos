// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Local membership, group admission and observer selection follow consensus
//! key custody, as in the reference node: a transport key, a transport binding
//! or another held key never makes this node a member or chooses its signer.
//! Every case uses seeds of its own: a retired key stays retired for the rest
//! of the process.
use super::*;
use crate::pq_consensus_config::PqCustodyShared;
use consensus_common::session_runtime::LocalRole;
use rtos_pq_consensus::{ConsensusKeyStore, PqConsensusCustody};

struct Member {
    validator_id: UInt256,
    store: Arc<ConsensusKeyStore>,
    transport: PrivateKey,
    transport_json: KeyOptionJson,
}

impl Member {
    fn new(seed: u8, expire_at: u32) -> Result<Self> {
        let store = Arc::new(ConsensusKeyStore::from_seed(&[seed; 32], expire_at)?);
        let (transport_json, transport) =
            Ed25519KeyOption::<ZeroizingBytes>::from_private_key_with_json(&[seed ^ 0x5a; 32])?;
        Ok(Self { validator_id: UInt256::from([seed; 32]), store, transport, transport_json })
    }
    fn descriptor(&self) -> ValidatorDescr {
        ValidatorDescr::with_pq_params(
            self.validator_id.clone(),
            self.store.consensus_key().clone(),
            1,
            UInt256::from(*self.transport.id().data()),
        )
    }
}

fn custody_of(validator: &Member, held: &[(Arc<ConsensusKeyStore>, u32)]) -> Arc<PqCustodyShared> {
    let mut custody = PqConsensusCustody::default();
    for (valid_from, (store, expire_at)) in held.iter().enumerate() {
        custody
            .install(validator.validator_id.clone(), store.clone(), valid_from as u32, *expire_at)
            .unwrap();
    }
    Arc::new(PqCustodyShared::new(validator.validator_id.clone(), custody))
}

/// A two-member post-quantum committee under Simplex `protocol`, with
/// `previous` as the previous total set.
fn configure(
    bootstrap: &mut EmulatorNetworkBootstrap,
    members: &[&Member],
    previous: &[ValidatorDescr],
    protocol: u8,
) -> Result<()> {
    let set: Vec<_> = members.iter().map(|member| member.descriptor()).collect();
    bootstrap.validator_set = ValidatorSet::with_cc_seqno(0, u32::MAX, 2, 0, set)?;
    bootstrap.config_params.set_config(ConfigParamEnum::ConfigParam34(ConfigParam34 {
        cur_validators: bootstrap.validator_set.clone(),
    }))?;
    if !previous.is_empty() {
        bootstrap.config_params.set_config(ConfigParamEnum::ConfigParam32(
            rtos_block::ConfigParam32 {
                prev_validators: ValidatorSet::with_cc_seqno(0, u32::MAX, 1, 0, previous.to_vec())?,
            },
        ))?;
    }
    // The emulator fixtures pin the 2400 ms target rate their genesis was built with.
    let simplex = SimplexConfig {
        protocol_version: protocol,
        noncritical_params: rtos_block::NoncriticalParams {
            target_rate_ms: 2400,
            ..Default::default()
        },
        ..Default::default()
    };
    bootstrap.config_params.set_config(ConfigParamEnum::ConfigParam30(NewConsensusConfigAll {
        mc: Some(simplex.clone()),
        shard: Some(simplex),
    }))?;
    let mut catchain = bootstrap.config_params.catchain_config()?;
    catchain.shard_validators_num = 2;
    bootstrap.config_params.set_config(ConfigParamEnum::ConfigParam28(catchain))?;
    Ok(())
}

struct Fixture {
    bootstrap: EmulatorNetworkBootstrap,
    engine: Arc<BootstrapTestEngine>,
    state: Arc<ShardStateStuff>,
}

async fn build_fixture(
    members: &[&Member],
    previous: &[ValidatorDescr],
    protocol: u8,
    custody: Option<Arc<PqCustodyShared>>,
    transports: &[&Member],
) -> Result<Fixture> {
    let mut bootstrap = EmulatorNetworkBootstrap::build(2)?;
    configure(&mut bootstrap, members, previous, protocol)?;
    let mut engine = BootstrapTestEngine::new_with_local_keys(&bootstrap, Vec::new()).await?;
    engine.custody = custody;
    let network = Arc::get_mut(&mut engine.validator_network).unwrap();
    for member in transports {
        network.transport_keys.push(member.transport.clone());
    }
    let state = engine.build_masterchain_state(&bootstrap, 0)?;
    bootstrap.zerostate_id = state.block_id().clone();
    engine.init_mc_block_id = state.block_id().clone();
    let engine = Arc::new(engine);
    engine.install_masterchain_state(state.clone(), None)?;
    Ok(Fixture { bootstrap, engine, state })
}

fn manager_of(fixture: &Fixture) -> ValidatorManagerImpl {
    ValidatorManagerImpl::create(
        fixture.engine.clone(),
        tokio::runtime::Handle::current(),
        ValidatorManagerConfig::default(),
    )
}

/// One manager pass. Starting a created group's session may fail in this
/// adapter; group selection and admission, which these cases check, happen
/// before any start.
async fn update(manager: &mut ValidatorManagerImpl, state: &Arc<ShardStateStuff>) {
    if let Err(error) =
        tokio::time::timeout(Duration::from_secs(20), manager.update_shards(state.clone()))
            .await
            .expect("manager update deadline")
    {
        eprintln!("custody manager fixture: update_shards: {error}");
    }
}

async fn teardown(mut manager: ValidatorManagerImpl) -> Result<()> {
    let ids: HashSet<_> =
        manager.current_sessions.keys().chain(manager.future_sessions.keys()).cloned().collect();
    tokio::time::timeout(Duration::from_secs(20), manager.stop_and_remove_sessions(&ids))
        .await
        .map_err(|e| error!("custody manager teardown: {e}"))?
}

fn masterchain_committee(fixture: &Fixture) -> Result<Vec<ValidatorDescr>> {
    let catchain = fixture.bootstrap.config_params.catchain_config()?;
    Ok(fixture.bootstrap.validator_set.calc_subset(&catchain, SHARD_FULL, MASTERCHAIN_ID, 0)?.0)
}

fn simplex_options(protocol: u8) -> ConsensusOptions {
    let protocol =
        consensus_common::simplex_protocol::SimplexProtocol::try_from(u32::from(protocol)).unwrap();
    ConsensusOptions::Simplex(SimplexSessionOptions { protocol, ..Default::default() })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn custody_member_of_protocols_0_and_1_gets_a_group_with_its_exact_signer() -> Result<()> {
    for (protocol, seed) in [(0u8, 0x40u8), (1, 0x44)] {
        let ours = Member::new(seed, 0)?;
        let theirs = Member::new(seed + 1, 0)?;
        // Holding the other member's transport key confers nothing.
        let fixture = build_fixture(
            &[&ours, &theirs],
            &[],
            protocol,
            Some(custody_of(&ours, &[(ours.store.clone(), 0)])),
            &[&ours, &theirs],
        )
        .await?;
        let mut manager = manager_of(&fixture);
        update(&mut manager, &fixture.state).await;
        let masterchain = manager
            .current_sessions
            .values()
            .find(|group| group.shard().is_masterchain())
            .cloned()
            .ok_or_else(|| error!("protocol {protocol}: no masterchain group"))?;
        let mut groups = 0;
        for group in manager.current_sessions.values().chain(manager.future_sessions.values()) {
            groups += 1;
            let runtime = group.authenticated_runtime().ok_or_else(|| error!("no runtime"))?;
            let LocalRole::Validator(index) = runtime.local_role() else {
                fail!("protocol {protocol}: a member group was admitted as observer");
            };
            let member = &runtime.committee()[index as usize];
            anyhow::ensure!(member.validator_id()? == ours.validator_id, "protocol {protocol}");
            anyhow::ensure!(runtime.local_adnl() == ours.transport.id());
            let signer = group.consensus_signer().ok_or_else(|| error!("group has no signer"))?;
            anyhow::ensure!(signer.validator() == &ours.validator_id);
            anyhow::ensure!(
                Arc::ptr_eq(signer.store(), &ours.store),
                "signer is not the custody store"
            );
            anyhow::ensure!(signer.descriptor().pq_key() == Some(ours.store.consensus_key()));
        }
        anyhow::ensure!(groups >= 2, "protocol {protocol}: expected current and future groups");
        anyhow::ensure!(masterchain.consensus_signer().is_some());
        anyhow::ensure!(manager.owned_current_shards >= 1, "protocol {protocol}");
        teardown(manager).await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transport_key_and_binding_without_custody_get_no_group() -> Result<()> {
    for (protocol, seed) in [(1u8, 0x48u8), (2, 0x4a)] {
        let ours = Member::new(seed, 0)?;
        let theirs = Member::new(seed + 1, 0)?;
        let mut fixture = build_fixture(&[&ours, &theirs], &[], protocol, None, &[&ours]).await?;
        // A transport binding of our committee identity to its descriptor's
        // transport key, whose private key is loaded: still no membership.
        let local_config = serde_json::from_value(serde_json::json!({
            "validator_keys": [],
            "validator_key_ring": { base64_encode(ours.transport.id().data()): ours.transport_json },
            "consensus_transport_bindings": [{
                "validator_id": base64_encode(ours.validator_id.as_slice()),
                "adnl_key_id": base64_encode(ours.transport.id().data()),
            }],
        }))?;
        let (handler, context) = crate::config::NodeConfigHandler::create(
            local_config,
            tokio::runtime::Handle::current(),
        )?;
        handler.clone().start_sheduler(context, vec![])?;
        Arc::get_mut(&mut fixture.engine).unwrap().transport_config = Some(handler.clone());
        anyhow::ensure!(!fixture.engine.consensus_transport_bindings()?.is_empty());
        let mut manager = manager_of(&fixture);
        anyhow::ensure!(manager
            .local_validator_id(fixture.bootstrap.validator_set.list())
            .is_none());
        update(&mut manager, &fixture.state).await;
        anyhow::ensure!(manager.current_sessions.is_empty(), "protocol {protocol}: a group exists");
        anyhow::ensure!(manager.future_sessions.is_empty(), "protocol {protocol}: a future exists");
        anyhow::ensure!(manager.owned_current_shards == 0);
        teardown(manager).await?;
        handler.stop_and_wait().await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_rotated_away_from_the_set_gets_no_group() -> Result<()> {
    let ours = Member::new(0x4c, 0)?;
    let theirs = Member::new(0x4d, 0)?;
    // Custody still holds an older key of our identity; the set lists another.
    let older = Arc::new(ConsensusKeyStore::from_seed(&[0x4e; 32], 0)?);
    let fixture =
        build_fixture(&[&ours, &theirs], &[], 1, Some(custody_of(&ours, &[(older, 0)])), &[&ours])
            .await?;
    let mut manager = manager_of(&fixture);
    anyhow::ensure!(manager.local_validator_id(fixture.bootstrap.validator_set.list()).is_none());
    update(&mut manager, &fixture.state).await;
    anyhow::ensure!(manager.current_sessions.is_empty() && manager.future_sessions.is_empty());
    teardown(manager).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expiry_after_selection_refuses_creation_without_a_fence() -> Result<()> {
    // Expiry between the caller's selection and the creation-time recheck.
    let ours = Member::new(0x50, 1000)?;
    let theirs = Member::new(0x51, 0)?;
    let fixture = build_fixture(
        &[&ours, &theirs],
        &[],
        1,
        Some(custody_of(&ours, &[(ours.store.clone(), 1000)])),
        &[&ours],
    )
    .await?;
    let committee = masterchain_committee(&fixture)?;
    let shard = ShardIdent::masterchain();
    let manager = manager_of(&fixture);
    fixture.engine.clock_script.lock().unwrap().extend([999, 1000]);
    let selected = manager.local_validator_id(&committee).expect("selected before its deadline");
    anyhow::ensure!(selected == ours.validator_id);
    anyhow::ensure!(manager
        .admit_validator_group(&shard, &committee, &selected, &simplex_options(1))
        .is_none());
    anyhow::ensure!(manager.destroyed_sessions.is_empty(), "a creation refusal fenced the session");
    // The next update decides again from custody, which no longer holds the key.
    let mut manager = manager;
    let reads = fixture.engine.clock_reads.load(Ordering::SeqCst);
    update(&mut manager, &fixture.state).await;
    anyhow::ensure!(fixture.engine.clock_reads.load(Ordering::SeqCst) > reads, "no retry");
    anyhow::ensure!(manager.current_sessions.is_empty() && manager.destroyed_sessions.is_empty());

    // Expiry between the recheck and the exact signer lookup.
    let ours = Member::new(0x52, 1000)?;
    let theirs = Member::new(0x53, 0)?;
    let fixture = build_fixture(
        &[&ours, &theirs],
        &[],
        1,
        Some(custody_of(&ours, &[(ours.store.clone(), 1000)])),
        &[&ours],
    )
    .await?;
    let committee = masterchain_committee(&fixture)?;
    let manager = manager_of(&fixture);
    fixture.engine.clock_script.lock().unwrap().extend([999, 999, 1000]);
    let selected = manager.local_validator_id(&committee).expect("selected before its deadline");
    anyhow::ensure!(manager
        .admit_validator_group(&shard, &committee, &selected, &simplex_options(1))
        .is_none());
    anyhow::ensure!(manager.destroyed_sessions.is_empty());
    anyhow::ensure!(ours.store.retired(), "the signer lookup observed the deadline");
    teardown(manager).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missing_transport_key_defers_the_group_until_it_is_loaded() -> Result<()> {
    let ours = Member::new(0x54, 0)?;
    let theirs = Member::new(0x55, 0)?;
    let fixture = build_fixture(
        &[&ours, &theirs],
        &[],
        1,
        Some(custody_of(&ours, &[(ours.store.clone(), 0)])),
        &[],
    )
    .await?;
    let mut manager = manager_of(&fixture);
    update(&mut manager, &fixture.state).await;
    anyhow::ensure!(manager.current_sessions.is_empty(), "a group without its transport key");
    anyhow::ensure!(manager.destroyed_sessions.is_empty(), "the deferral fenced the session");
    fixture.engine.late_transport_keys.write().unwrap().push(ours.transport.clone());
    update(&mut manager, &fixture.state).await;
    anyhow::ensure!(
        manager.current_sessions.values().any(|group| group.consensus_signer().is_some()),
        "the deferred group was not created once its transport key was loaded"
    );
    teardown(manager).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn protocol_2_custody_selects_the_validator_admission() -> Result<()> {
    let ours = Member::new(0x56, 0)?;
    let theirs = Member::new(0x57, 0)?;
    let fixture = build_fixture(
        &[&ours, &theirs],
        &[],
        2,
        Some(custody_of(&ours, &[(ours.store.clone(), 0)])),
        &[&ours],
    )
    .await?;
    let committee = masterchain_committee(&fixture)?;
    let manager = manager_of(&fixture);
    let selected = manager.local_validator_id(&committee).expect("custody member");
    anyhow::ensure!(selected == ours.validator_id);
    let runtime = manager
        .simplex_session_runtime(
            &fixture.state,
            &ShardIdent::masterchain(),
            0,
            0,
            0,
            &committee,
            Some(&selected),
            true,
        )?
        .ok_or_else(|| error!("no admission"))?;
    let LocalRole::Validator(index) = runtime.local_role() else { fail!("observer admission") };
    anyhow::ensure!(committee[index as usize].validator_id()? == ours.validator_id);
    anyhow::ensure!(runtime.local_adnl() == ours.transport.id());
    // Its exact signer is the custody store of that descriptor.
    let admitted = manager
        .admit_validator_group(
            &ShardIdent::masterchain(),
            &committee,
            &selected,
            &simplex_options(2),
        )
        .ok_or_else(|| error!("not admitted"))?;
    anyhow::ensure!(admitted.index == index);
    anyhow::ensure!(Arc::ptr_eq(admitted.signer.as_ref().unwrap().store(), &ours.store));
    teardown(manager).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn observers_are_selected_by_custody_outside_the_committee() -> Result<()> {
    let first = Member::new(0x58, 0)?;
    let second = Member::new(0x59, 0)?;
    let outside = Member::new(0x5b, 0)?;
    let previous = [outside.descriptor(), first.descriptor()];
    let (first_ref, second_ref, outside_ref, previous_ref) = (&first, &second, &outside, &previous);
    let config = move |custody| async move {
        let fixture = build_fixture(
            &[first_ref, second_ref],
            previous_ref,
            2,
            custody,
            &[first_ref, outside_ref],
        )
        .await?;
        let committee = masterchain_committee(&fixture)?;
        let manager = manager_of(&fixture);
        let observers = manager
            .local_observers(fixture.state.config_params()?, &committee)?
            .into_iter()
            .map(|observer| observer.adnl().clone())
            .collect::<Vec<_>>();
        let runtime = manager.simplex_session_runtime(
            &fixture.state,
            &ShardIdent::masterchain(),
            0,
            0,
            0,
            &committee,
            None,
            true,
        )?;
        teardown(manager).await?;
        Ok::<_, anyhow::Error>((observers, runtime))
    };
    // Custody of a previous validator outside the committee: an observer at
    // that descriptor's transport identity.
    let (observers, runtime) =
        config(Some(custody_of(&outside, &[(outside.store.clone(), 0)]))).await?;
    anyhow::ensure!(observers == vec![outside.transport.id().clone()]);
    let runtime = runtime.ok_or_else(|| error!("no observer admission"))?;
    anyhow::ensure!(runtime.local_role() == LocalRole::Observer);
    anyhow::ensure!(runtime.local_adnl() == outside.transport.id());
    // A committee member is never an observer, whatever it holds; holding only
    // a transport key selects nothing.
    let (observers, runtime) =
        config(Some(custody_of(&first, &[(first.store.clone(), 0)]))).await?;
    anyhow::ensure!(observers.is_empty() && runtime.is_none());
    let (observers, runtime) = config(None).await?;
    anyhow::ensure!(observers.is_empty() && runtime.is_none());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_signer_matches_the_exact_descriptor_key() -> Result<()> {
    let ours = Member::new(0x5c, 0)?;
    let theirs = Member::new(0x5d, 0)?;
    let fixture = build_fixture(
        &[&ours, &theirs],
        &[],
        1,
        Some(custody_of(
            &ours,
            &[
                (ours.store.clone(), 0),
                (Arc::new(ConsensusKeyStore::from_seed(&[0x5f; 32], 0)?), 0),
            ],
        )),
        &[&ours],
    )
    .await?;
    let manager = manager_of(&fixture);
    let shard = ShardIdent::masterchain();
    // A descriptor that records our key identity with another public key: the
    // key identity alone makes this node a member, but no held store matches.
    let mut forged = ours.descriptor();
    if let rtos_block::ValidatorKey::Pq(key) = &mut forged.key {
        key.public_key = theirs.store.consensus_key().public_key.clone();
    }
    // Custody also holds a second key of our identity: it never signs for a
    // set that records the first.
    let committee = vec![ours.descriptor(), theirs.descriptor()];
    let admitted = manager
        .admit_validator_group(&shard, &committee, &ours.validator_id, &simplex_options(1))
        .ok_or_else(|| error!("listed key not admitted"))?;
    anyhow::ensure!(Arc::ptr_eq(admitted.signer.as_ref().unwrap().store(), &ours.store));
    let committee = vec![forged, theirs.descriptor()];
    let selected = manager.local_validator_id(&committee).expect("member by key identity");
    anyhow::ensure!(manager
        .admit_validator_group(&shard, &committee, &selected, &simplex_options(1))
        .is_none());
    // A classical committee never gets a Simplex group.
    let classical = Ed25519KeyOption::<ZeroizingBytes>::generate()?;
    let mut manager = manager;
    manager.validator_list_status.add_list(UInt256::from([0x5e; 32]), vec![classical.clone()]);
    let committee =
        vec![ValidatorDescr::with_params(SigPubKey::from_bytes(classical.pub_key()?)?, 1, None)];
    let selected = manager.local_validator_id(&committee).expect("classical member");
    anyhow::ensure!(manager
        .admit_validator_group(&shard, &committee, &selected, &simplex_options(1))
        .is_none());
    teardown(manager).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_group_takes_only_the_signer_of_its_admitted_member() -> Result<()> {
    let ours = Member::new(0x60, 0)?;
    let theirs = Member::new(0x61, 0)?;
    let fixture = build_fixture(
        &[&ours, &theirs],
        &[],
        1,
        Some(custody_of(&ours, &[(ours.store.clone(), 0)])),
        &[&ours],
    )
    .await?;
    let set = ValidatorSet::with_cc_seqno(0, 0, 0, 0, masterchain_committee(&fixture)?)?;
    let committee = set.list().to_vec();
    let shard = ShardIdent::masterchain();
    let manager = manager_of(&fixture);
    let runtime = manager
        .simplex_session_runtime(
            &fixture.state,
            &shard,
            0,
            0,
            0,
            &committee,
            Some(&ours.validator_id),
            false,
        )?
        .unwrap();
    let (info, id) = derive_governing_session_info(&fixture.state, &shard, &committee, 0, 0, 0)?;
    let ConsensusOptions::Simplex(options) = simplex_options(1) else { unreachable!() };
    let options = SimplexSessionOptions {
        proto_version: runtime.carrier_version(),
        wire_profile: runtime.wire_profile(),
        slots_per_leader_window: runtime.slots_per_leader_window(),
        ..options
    };
    let group = || {
        ValidatorGroup::new(
            info.clone(),
            ours.transport.clone(),
            id.clone(),
            UInt256::from([1; 32]),
            set.clone(),
            0,
            ConsensusOptions::Simplex(options.clone()),
            fixture.engine.clone(),
            false,
            None,
        )
    };
    let signer = |custody: &PqCustodyShared, validator: &Member| {
        let descriptor = committee
            .iter()
            .find(|member| member.validator_id().unwrap() == validator.validator_id)
            .unwrap();
        custody.read(|custody| {
            simplex::SessionSigner::from_custody_match(
                custody,
                &validator.validator_id,
                descriptor,
                1,
            )
        })
    };
    let ours_custody = custody_of(&ours, &[(ours.store.clone(), 0)]);
    let ours_signer = signer(&ours_custody, &ours)?;
    // Without the runtime there is no admitted member to sign for.
    anyhow::ensure!(group().with_consensus_signer(ours_signer.clone()).is_err());
    let attached = group().with_authenticated_runtime(runtime.clone())?;
    anyhow::ensure!(attached.consensus_signer().is_none());
    let attached = attached.with_consensus_signer(ours_signer.clone())?;
    anyhow::ensure!(attached.consensus_signer().is_some());
    anyhow::ensure!(attached.with_consensus_signer(ours_signer).is_err(), "signer replaced");
    // Another member's signer is refused.
    let theirs_signer = signer(&custody_of(&theirs, &[(theirs.store.clone(), 0)]), &theirs)?;
    anyhow::ensure!(group()
        .with_authenticated_runtime(runtime)?
        .with_consensus_signer(theirs_signer)
        .is_err());
    teardown(manager).await
}
