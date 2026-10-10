/*
 * Copyright (C) 2026 RTOS contributors.
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
use super::*;
use crate::{
    collator_test_bundle::create_engine_allocated,
    validator::validator_manager::emulator_network_bootstrap::EmulatorNetworkBootstrap,
};
use rtos_block::{PqConsensusKey, UInt256};
use std::sync::atomic::AtomicUsize;

struct SnapshotEngine {
    zero: BlockIdExt,
    fail_after: AtomicUsize,
}
impl EngineOperations for SnapshotEngine {
    fn zerostate_id(&self) -> Result<&BlockIdExt> {
        let left = self.fail_after.fetch_sub(1, Ordering::SeqCst);
        if left == 1 {
            return Err(error!("injected later overlay construction failure"));
        }
        Ok(&self.zero)
    }
    fn check_stop(&self) -> bool {
        true
    }
}

fn isolate_quic(bootstrap: &EmulatorNetworkBootstrap) -> Result<()> {
    let mut config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&bootstrap.config_path)?)?;
    config["ip_address_quic"] = "127.0.0.1:0".into();
    std::fs::write(&bootstrap.config_path, serde_json::to_vec_pretty(&config)?)?;
    Ok(())
}

struct Fixture {
    router: Arc<FullNodeOverlaysRouter>,
    engine: Arc<SnapshotEngine>,
    bootstrap: EmulatorNetworkBootstrap,
}
impl Fixture {
    async fn new() -> Result<Self> {
        let bootstrap = EmulatorNetworkBootstrap::build(2)?;
        isolate_quic(&bootstrap)?;
        let allocated = create_engine_allocated();
        #[cfg(feature = "telemetry")]
        let telemetry = crate::collator_test_bundle::create_engine_telemetry();
        let network = NodeNetwork::new(
            bootstrap.load_node_config().await?,
            tokio_util::sync::CancellationToken::new(),
            #[cfg(feature = "telemetry")]
            telemetry.clone(),
            allocated.clone(),
        )
        .await?;
        let engine = Arc::new(SnapshotEngine {
            zero: bootstrap.zerostate_id.clone(),
            fail_after: AtomicUsize::new(usize::MAX),
        });
        let router = Arc::new(FullNodeOverlaysRouter {
            engine: engine.clone(),
            network,
            service: Arc::new(FullNodeOverlayService::new(engine.clone(), false)),
            policy: DhtSearchPolicy::default(),
            public_overlays: lockfree::map::Map::new(),
            fast_sync_overlays: lockfree::map::Map::new(),
            custom_overlays: lockfree::map::Map::new(),
            public_overlays_awaiters: AwaitersPool::new(
                "snapshot fixture",
                #[cfg(feature = "telemetry")]
                telemetry,
                allocated,
            ),
            fast_sync_snapshot: tokio::sync::Mutex::new(None),
            monitor_min_split_for_fast_sync: AtomicU8::new(0),
            last_known_keyblock_id: tokio::sync::Mutex::new(None),
            actual_monitor_min_split: AtomicU8::new(0),
            monitor_min_split_worker_started: AtomicBool::new(false),
            fast_sync_peer_resolver: tokio::sync::Mutex::new(None),
        });
        Ok(Self { router, engine, bootstrap })
    }
    fn member(&self, index: usize) -> ValidatorDescr {
        ValidatorDescr::with_pq_params(
            UInt256::from([20 + index as u8; 32]),
            PqConsensusKey {
                algorithm_id: 1,
                key_id: rtos_block::derive_consensus_key_id(1, &vec![40 + index as u8; 1312]),
                public_key: vec![40 + index as u8; 1312],
            },
            1,
            UInt256::from(*self.bootstrap.validators[index].adnl_key.id().data()),
        )
    }
    async fn stop(&self) {
        self.router.clear_fast_sync_overlays();
        self.router.network.stop_adnl().await;
    }
}
fn set(members: Vec<ValidatorDescr>) -> ValidatorSet {
    ValidatorSet::with_cc_seqno(0, u32::MAX, members.len() as u16, 0, members).unwrap()
}
fn overlay(router: &FullNodeOverlaysRouter, shard: &ShardIdent) -> Arc<FastSyncOverlayClient> {
    router.fast_sync_overlays.get(shard).unwrap().val().clone()
}
fn assert_replaced(old: &Arc<FastSyncOverlayClient>, new: &Arc<FastSyncOverlayClient>) {
    assert!(!Arc::ptr_eq(old, new), "configuration change must replace the actual overlay");
    assert!(old.client().cancellation_token().is_cancelled(), "previous authority must be revoked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_sync_snapshot_previous_next_and_transport_changes_replace_live_overlays() -> Result<()>
{
    let f = Fixture::new().await?;
    let empty = ValidatorSet::default();
    let current = set(vec![f.member(0)]);
    let previous = set(vec![f.member(1)]);
    let key = f.router.find_transport_key(&[&current]).await?.unwrap();
    f.router
        .update_fast_sync_overlays(&empty, &current, &empty, 0, Some(&key), false, false)
        .await?;
    let mut master = overlay(&f.router, &ShardIdent::MASTERCHAIN);
    let mut shard = overlay(&f.router, &ShardIdent::BASE_WORKCHAIN);
    f.router
        .update_fast_sync_overlays(&empty, &current, &empty, 0, Some(&key), false, false)
        .await?;
    assert!(Arc::ptr_eq(&master, &overlay(&f.router, &ShardIdent::MASTERCHAIN)));
    for (prev, next, mc, base) in [
        (&previous, &empty, false, false),
        (&empty, &previous, false, false),
        (&empty, &previous, true, false),
        (&empty, &previous, true, true),
    ] {
        f.router.update_fast_sync_overlays(prev, &current, next, 0, Some(&key), mc, base).await?;
        let new_master = overlay(&f.router, &ShardIdent::MASTERCHAIN);
        let new_shard = overlay(&f.router, &ShardIdent::BASE_WORKCHAIN);
        assert_replaced(&master, &new_master);
        assert_replaced(&shard, &new_shard);
        assert_eq!(new_master.use_twostep(), mc);
        assert_eq!(new_shard.use_twostep(), base);
        assert!(new_master.client().neighbours().contains(f.bootstrap.validators[1].adnl_key.id()));
        master = new_master;
        shard = new_shard;
    }
    f.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_sync_snapshot_local_rotation_and_loss_revoke_old_authority() -> Result<()> {
    let f = Fixture::new().await?;
    let empty = ValidatorSet::default();
    let current = set(vec![f.member(0), f.member(1)]);
    let first = f.bootstrap.validators[0].adnl_key.clone();
    let second = f.bootstrap.validators[1].adnl_key.clone();
    for key in [&first, &second] {
        f.router
            .network
            .context()
            .stack
            .adnl
            .add_key(key.clone(), 900 + usize::from(key.id() == second.id()))?;
    }
    f.router
        .update_fast_sync_overlays(&empty, &current, &empty, 0, Some(&first), false, false)
        .await?;
    let master = overlay(&f.router, &ShardIdent::MASTERCHAIN);
    f.router
        .update_fast_sync_overlays(&empty, &current, &empty, 0, Some(&second), false, false)
        .await?;
    let rotated = overlay(&f.router, &ShardIdent::MASTERCHAIN);
    assert_replaced(&master, &rotated);
    f.router.update_fast_sync_overlays(&empty, &current, &empty, 0, None, false, false).await?;
    assert_eq!(f.router.fast_sync_overlays.iter().count(), 0);
    assert!(rotated.client().cancellation_token().is_cancelled());
    f.router
        .update_fast_sync_overlays(&empty, &current, &empty, 0, Some(&second), false, false)
        .await?;
    assert_eq!(f.router.fast_sync_overlays.iter().count(), 2);
    f.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_sync_snapshot_failure_revokes_partial_generation_and_retries() -> Result<()> {
    let f = Fixture::new().await?;
    let empty = ValidatorSet::default();
    let current = set(vec![f.member(0)]);
    let key = f.router.find_transport_key(&[&current]).await?.unwrap();
    f.router
        .update_fast_sync_overlays(&empty, &current, &empty, 0, Some(&key), false, false)
        .await?;
    let old = overlay(&f.router, &ShardIdent::MASTERCHAIN);
    f.engine.fail_after.store(2, Ordering::SeqCst);
    let error = f
        .router
        .update_fast_sync_overlays(&empty, &current, &empty, 1, Some(&key), false, false)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("injected later overlay"));
    assert!(old.client().cancellation_token().is_cancelled());
    assert_eq!(f.router.fast_sync_overlays.iter().count(), 0);
    assert!(f.router.fast_sync_snapshot.lock().await.is_none());
    assert!(f
        .router
        .network
        .context()
        .stack
        .overlay
        .get_query_prefix(&Arc::new(old.id().clone()))
        .is_err());
    f.engine.fail_after.store(usize::MAX, Ordering::SeqCst);
    f.router
        .update_fast_sync_overlays(&empty, &current, &empty, 1, Some(&key), false, false)
        .await?;
    assert_eq!(f.router.fast_sync_overlays.iter().count(), 3);
    f.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_sync_snapshot_prior_only_transport_registration_is_rechecked_without_chain_changes(
) -> Result<()> {
    use rtos_block::{ConfigParam32, ConfigParam34, ConfigParamEnum};
    let f = Fixture::new().await?;
    let previous = set(vec![f.member(0)]);
    let mut remote = f.member(1);
    remote.adnl_addr = Some(UInt256::from([199; 32]));
    let current = set(vec![remote]);
    let mut config = f.bootstrap.config_params().clone();
    config
        .set_config(ConfigParamEnum::ConfigParam32(ConfigParam32::with_validator_set(previous)))?;
    config
        .set_config(ConfigParamEnum::ConfigParam34(ConfigParam34::with_validator_set(current)))?;
    // This is an unexpired classical validator transport registration, which
    // can authorize fast-sync even when the chain descriptor uses PQ keys.
    // No PQ consensus identity or held signing key is inferred from it.
    let transport = f.bootstrap.validators[0].adnl_key.id();
    assert!(!f.router.network.config_handler().get_actual_validator_key_ids()?.contains(transport));
    f.router.update_private_overlays(&config).await?;
    let initial = overlay(&f.router, &ShardIdent::MASTERCHAIN);
    assert_eq!(
        f.router.fast_sync_snapshot.lock().await.as_ref().unwrap().local_key.as_ref(),
        Some(transport)
    );
    let handler = f.router.network.config_handler();
    handler
        .add_validator_adnl_key(
            f.bootstrap.validators[0].validator_key.id().data(),
            f.bootstrap.validators[1].adnl_key.id().data(),
        )
        .await?;
    // Same config; the transport key remains loaded in ADNL, but its local
    // configuration has been revoked. Cached presence must not authorize it.
    assert!(f.router.network.context().stack.adnl.key_by_id(transport).is_ok());
    f.router.update_private_overlays(&config).await?;
    assert_eq!(f.router.fast_sync_overlays.iter().count(), 0);
    assert!(initial.client().cancellation_token().is_cancelled());
    handler
        .add_validator_adnl_key(
            f.bootstrap.validators[0].validator_key.id().data(),
            transport.data(),
        )
        .await?;
    f.router.update_private_overlays(&config).await?;
    assert_eq!(f.router.fast_sync_overlays.iter().count(), 2);
    let recovered = overlay(&f.router, &ShardIdent::MASTERCHAIN);
    assert_replaced(&initial, &recovered);
    f.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fast_sync_snapshot_real_engine_pq_transport_startup_and_keyring_notification() -> Result<()>
{
    use crate::engine::{run, EngineFlags, Stopper};
    use rtos_block::{ConfigParam32, ConfigParam34, ConfigParamEnum};
    use std::time::Duration;
    let bootstrap = EmulatorNetworkBootstrap::build_with_config(2, |config, keys| {
        let key_bytes = vec![71; 1312];
        let pq = ValidatorDescr::with_pq_params(
            UInt256::from([51; 32]),
            PqConsensusKey {
                algorithm_id: 1,
                key_id: rtos_block::derive_consensus_key_id(1, &key_bytes),
                public_key: key_bytes,
            },
            1,
            UInt256::from(*keys[0].adnl_key.id().data()),
        );
        let mut remote = pq.clone();
        remote.adnl_addr = Some(UInt256::from([199; 32]));
        // The local member exists only in the previous set; both sets use PQ
        // identities, with no corresponding consensus private key configured.
        config.set_config(ConfigParamEnum::ConfigParam32(ConfigParam32::with_validator_set(
            set(vec![pq]),
        )))?;
        config.set_config(ConfigParamEnum::ConfigParam34(ConfigParam34::with_validator_set(
            set(vec![remote]),
        )))?;
        Ok(())
    })?;
    isolate_quic(&bootstrap)?;
    let stopper = Arc::new(Stopper::new());
    let (engine, join) = run(
        bootstrap.load_node_config().await?,
        bootstrap.config_dir().to_str(),
        tokio::runtime::Handle::current(),
        tokio::runtime::Handle::current(),
        EngineFlags { initial_sync_disabled: true, force_check_db: false, truncate_db: None },
        stopper.clone(),
        None,
    )
    .await?;
    let result: Result<()> = async {
        let router = engine.overlays_router()?;
        let first = overlay(router, &ShardIdent::MASTERCHAIN);
        assert_eq!(
            router.fast_sync_snapshot.lock().await.as_ref().unwrap().local_key.as_ref(),
            Some(bootstrap.validators[0].adnl_key.id())
        );
        engine
            .network()
            .config_handler()
            .add_validator_adnl_key(
                bootstrap.validators[0].validator_key.id().data(),
                bootstrap.validators[1].adnl_key.id().data(),
            )
            .await?;
        tokio::time::timeout(Duration::from_secs(10), async {
            while router.fast_sync_overlays.iter().count() != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        assert!(first.client().cancellation_token().is_cancelled());
        assert_eq!(engine.load_last_applied_mc_block_id()?.unwrap().seq_no, 0);
        Ok(())
    }
    .await;
    stopper.set_stop();
    tokio::time::timeout(Duration::from_secs(30), join).await??;
    tokio::time::timeout(Duration::from_secs(30), engine.wait_stop()).await??;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_sync_snapshot_rejects_expired_missing_and_implicit_transport_registration(
) -> Result<()> {
    let f = Fixture::new().await?;
    let registered = set(vec![f.member(0)]);
    let empty = ValidatorSet::default();
    let handler = f.router.network.config_handler();
    let local = &f.bootstrap.validators[0];
    let key = f.router.find_transport_key(&[&registered]).await?.unwrap();
    f.router
        .update_fast_sync_overlays(&empty, &registered, &empty, 0, Some(&key), false, false)
        .await?;
    let old = overlay(&f.router, &ShardIdent::MASTERCHAIN);
    // Updating a registration clears its ADNL field; put that field back so
    // expiration, rather than missing registration, is the cause of rejection.
    handler.add_validator_key(local.validator_key.id().data(), 1, 1).await?;
    handler
        .add_validator_adnl_key(local.validator_key.id().data(), local.adnl_key.id().data())
        .await?;
    let no_key = f.router.find_transport_key(&[&registered]).await?;
    assert!(no_key.is_none(), "expired classical registration must not authorize transport");
    f.router
        .update_fast_sync_overlays(&empty, &registered, &empty, 0, no_key.as_ref(), false, false)
        .await?;
    assert!(old.client().cancellation_token().is_cancelled());
    assert_eq!(f.router.fast_sync_overlays.iter().count(), 0);

    handler.add_validator_key(local.validator_key.id().data(), 1, i32::MAX).await?;
    let mut implicit = f.member(0);
    implicit.adnl_addr = Some(UInt256::from(*local.validator_key.id().data()));
    assert!(
        f.router.find_transport_key(&[&set(vec![implicit])]).await?.is_none(),
        "a classical signing key must not become a transport fallback without registration"
    );
    handler.add_validator_adnl_key(local.validator_key.id().data(), &[198; 32]).await?;
    let mut missing = f.member(0);
    missing.adnl_addr = Some(UInt256::from([198; 32]));
    assert!(
        f.router.find_transport_key(&[&set(vec![missing])]).await?.is_none(),
        "an ADNL ID without its local private key is not custody"
    );
    f.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_sync_snapshot_primary_adnl_is_an_independent_transport_source() -> Result<()> {
    let f = Fixture::new().await?;
    let primary = f.router.network.context().stack.adnl.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY)?;
    assert!(!f
        .router
        .network
        .config_handler()
        .get_actual_validator_adnl_key_ids()?
        .contains(primary.id()));
    let mut descriptor = f.member(0);
    descriptor.adnl_addr = Some(UInt256::from(*primary.id().data()));
    let previous = set(vec![descriptor]);
    let key = f.router.find_transport_key(&[&previous]).await?.unwrap();
    assert_eq!(key.id(), primary.id());
    let empty = ValidatorSet::default();
    f.router
        .update_fast_sync_overlays(&previous, &empty, &empty, 0, Some(&key), false, false)
        .await?;
    assert_eq!(f.router.fast_sync_overlays.iter().count(), 2);
    f.stop().await;
    Ok(())
}
