/*
 * RTOS project modifications (2026-10-10): project and crate naming; explicit target wire profile integration; owned consumer readiness and authenticated finality recovery.
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
/// The router encapsulates work with full node overlays at the logical level. It abstracts creation,
/// deletion, and getting of specific overlay clients from higher-level classes. For lower-level
/// classes, overlays are physical entities not tied to shards or other blockchain entities.
///
/// ValidatorManager  Collator  ValidatorQuery  etc.   <- high level node commponents
///       v              v             v
///                 Engine
///                  v ^
///         **FullNodeOverlaysRouter** contains list of FullNodeOverlayClient
///                    v
///               NodeNetwork                   <- low level node components
///                    v
///            network protocols
mod propagation;
use crate::{
    block::BlockStuff,
    block_proof::{BlockProofStuff, BootstrapAuthority},
    engine_traits::EngineOperations,
    network::{
        build_block_broadcast, build_block_broadcast_compressed,
        build_block_broadcast_compressed_v2, build_block_candidate_broadcast_compressed,
        custom_overlay_client::CustomOverlayClient,
        fast_sync_overlay_client::{fast_sync_transport_authority, FastSyncOverlayClient},
        full_node_overlay_client::FullNodeOverlayClient,
        full_node_service::FullNodeOverlayService,
        node_network::NodeNetwork,
        overlay_client::OverlayClient,
        pack_block_signatures,
    },
    types::{
        awaiters_pool::AwaitersPool, owned_tasks::OwnedTasks, top_block_descr::TopBlockDescrStuff,
    },
    validator::validator_utils::{compute_validator_list_id, get_adnl_id, sigpubkey_to_publickey},
};
#[cfg(feature = "xp25")]
use adnl::OverlayNode;
use adnl::{
    common::{add_unbound_object_to_map_with_update, TaggedByteSlice},
    node::AdnlSendMethod,
    DhtSearchPolicy, OverlayUtils,
};
#[cfg(feature = "telemetry")]
use rtos_api::{
    ton::ton_node::broadcast::{
        BlockBroadcast, BlockBroadcastCompressed, BlockBroadcastCompressedV2,
    },
    BoxedSerialize, Constructor,
};
use rtos_api::{
    ton::{
        engine::validator::customoverlay::CustomOverlay,
        ton_node::{
            broadcast::{
                ExternalMessageBroadcast, NewShardBlockBroadcast, OutMsgQueueProofBroadcast,
            },
            externalmessage::ExternalMessage,
        },
    },
    IntoBoxed,
};
use rtos_block::{
    base64_encode, error, AccountIdPrefixFull, BlockIdExt, BlockSignaturesVariant, Cell,
    ConfigParams, ImportedMsgQueueLimits, KeyId, KeyOption, Result, ShardIdent, ValidatorDescr,
    ValidatorSet, BASE_WORKCHAIN_ID,
};
use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc,
    },
};

/// The router encapsulates work with full node overlays at the logical level. It abstracts creation,
/// deletion, and getting of specific overlay clients from higher-level classes. For lower-level
/// classes, overlays are physical entities not tied to shards or other blockchain entities.
///
/// ValidatorManager  Collator  ValidatorQuery  etc.   <- high level node commponents
///       v              v             v
///                 Engine
///                  v ^
///         **FullNodeOverlaysRouter** contains list of FullNodeOverlayClient
///                    v
///               NodeNetwork                   <- low level node components
///                    v
///            network protocols
#[derive(Debug, thiserror::Error)]
#[error("fast-sync inputs changed during transport refresh")]
struct RetryFastSyncRefresh;

struct FastSyncRefreshBinding {
    transport_revision: u64,
    applied_id: Option<BlockIdExt>,
    valid_until: Option<u64>,
}

struct LocalFastSyncTransport {
    key: Arc<dyn KeyOption>,
    valid_until: Option<u64>,
}

#[derive(Clone, PartialEq)]
struct FastSyncSnapshot {
    previous: ValidatorSet,
    current: ValidatorSet,
    next: ValidatorSet,
    monitor_min_split: u8,
    local_key: Option<Arc<KeyId>>,
    mc_use_quic: bool,
    shard_use_quic: bool,
}

pub struct FullNodeOverlaysRouter {
    engine: Arc<dyn EngineOperations>,
    tasks: Arc<OwnedTasks>,
    #[cfg(test)]
    pub(crate) init_gate:
        std::sync::Mutex<Option<Arc<crate::network::overlay_client::OverlayInitGate>>>,
    network: Arc<NodeNetwork>,
    service: Arc<FullNodeOverlayService>,
    policy: DhtSearchPolicy,
    public_generations:
        std::sync::Mutex<std::collections::HashMap<ShardIdent, Arc<tokio::sync::Mutex<()>>>>,
    public_overlays: lockfree::map::Map<ShardIdent, Arc<FullNodeOverlayClient>>,
    fast_sync_overlays: lockfree::map::Map<ShardIdent, Arc<FastSyncOverlayClient>>,
    custom_overlays: lockfree::map::Map<String, Arc<CustomOverlayClient>>,
    public_overlays_awaiters: AwaitersPool<ShardIdent, Arc<FullNodeOverlayClient>>,
    fast_sync_snapshot: tokio::sync::Mutex<Option<FastSyncSnapshot>>,
    propagation_config: std::sync::RwLock<Option<propagation::PropagationConfig>>,
    propagation_config_ready: AtomicBool,
    candidate_relays: tokio::sync::Mutex<crate::validator::propagation::CandidateRelayDeduplicator>,
    fast_sync_refresh: tokio::sync::Mutex<()>,
    fast_sync_retiring: Arc<std::sync::Mutex<Vec<Arc<FastSyncOverlayClient>>>>,
    #[cfg(test)]
    fast_sync_refresh_gate: std::sync::Mutex<
        Option<(tokio::sync::oneshot::Sender<()>, tokio::sync::oneshot::Receiver<()>)>,
    >,
    monitor_min_split_for_fast_sync: AtomicU8,
    last_known_keyblock_id: tokio::sync::Mutex<Option<BlockIdExt>>,
    actual_monitor_min_split: AtomicU8,
    monitor_min_split_worker_started: AtomicBool,
    fast_sync_peer_resolver: tokio::sync::Mutex<Option<tokio_util::sync::CancellationToken>>,
}

// Keeps a partially constructed generation unreachable through the router and
// revokes all completed registrations if construction fails or is cancelled.
struct PendingFastSync {
    retiring: Arc<std::sync::Mutex<Vec<Arc<FastSyncOverlayClient>>>>,
    overlays: Vec<(ShardIdent, Arc<FastSyncOverlayClient>)>,
    cancellation: tokio_util::sync::CancellationToken,
    committed: bool,
}

impl Drop for PendingFastSync {
    fn drop(&mut self) {
        if !self.committed {
            self.cancellation.cancel();
            let mut retiring = self.retiring.lock().unwrap();
            for (_, overlay) in self.overlays.drain(..) {
                retiring.push(overlay.clone());
                overlay.stop();
            }
        }
    }
}

impl FullNodeOverlaysRouter {
    pub fn create(
        engine: Arc<dyn EngineOperations>,
        network: Arc<NodeNetwork>,
        policy: DhtSearchPolicy,
    ) -> Result<Arc<Self>> {
        let tasks = Arc::new(OwnedTasks::new(network.cancellation_token().child_token()));
        let service = Arc::new(FullNodeOverlayService::new(engine.clone(), false, tasks.clone())); // compression = false
        let public_overlays_awaiters = AwaitersPool::new(
            "public_overlays_awaiters",
            #[cfg(feature = "telemetry")]
            engine.engine_telemetry().clone(),
            engine.engine_allocated().clone(),
        );
        let actual_monitor_min_split = AtomicU8::new(engine.get_monitor_min_split());
        Ok(Arc::new(Self {
            tasks,
            #[cfg(test)]
            init_gate: std::sync::Mutex::new(None),
            engine,
            network,
            service,
            policy,
            public_generations: Default::default(),
            public_overlays: lockfree::map::Map::new(),
            fast_sync_overlays: lockfree::map::Map::new(),
            custom_overlays: lockfree::map::Map::new(),
            public_overlays_awaiters,
            fast_sync_snapshot: tokio::sync::Mutex::new(None),
            propagation_config: Default::default(),
            propagation_config_ready: AtomicBool::new(false),
            candidate_relays: Default::default(),
            fast_sync_refresh: tokio::sync::Mutex::new(()),
            fast_sync_retiring: Default::default(),
            #[cfg(test)]
            fast_sync_refresh_gate: std::sync::Mutex::new(None),
            monitor_min_split_for_fast_sync: AtomicU8::new(0),
            last_known_keyblock_id: tokio::sync::Mutex::new(None),
            actual_monitor_min_split,
            monitor_min_split_worker_started: AtomicBool::new(false),
            fast_sync_peer_resolver: tokio::sync::Mutex::new(None),
        }))
    }

    pub async fn initialize(self: &Arc<Self>) -> Result<()> {
        let _admission = self.tasks.enter()?;
        futures::try_join!(
            self.overlay_client(&ShardIdent::MASTERCHAIN),
            self.overlay_client(&ShardIdent::BASE_WORKCHAIN)
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn hold_test_auxiliary_listeners(
        self: &Arc<Self>,
    ) -> Result<Vec<tokio::sync::oneshot::Sender<()>>> {
        use rtos_api::ton::engine::validator::customoverlaynode::CustomOverlayNode;
        use rtos_block::{Ed25519KeyOption, SigPubKey, UInt256, ZeroizingBytes};
        let local = self.network.context().stack.adnl.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY)?;
        let peer = Ed25519KeyOption::<ZeroizingBytes>::generate()?;
        let validators = ValidatorSet::new(
            0,
            u32::MAX,
            2,
            vec![
                ValidatorDescr::with_params(
                    SigPubKey::from_bytes(local.pub_key()?)?,
                    1,
                    Some(UInt256::from_slice(local.id().data())),
                ),
                ValidatorDescr::with_params(
                    SigPubKey::from_bytes(peer.pub_key()?)?,
                    1,
                    Some(UInt256::from_slice(peer.id().data())),
                ),
            ],
        )?;
        self.update_fast_sync_overlays(
            &ValidatorSet::default(),
            &validators,
            &ValidatorSet::default(),
            0,
            Some(&local),
            false,
            false,
        )
        .await?;
        let config = CustomOverlay {
            name: "owned-drain-test".into(),
            nodes: vec![local.id(), peer.id()]
                .into_iter()
                .map(|id| CustomOverlayNode {
                    adnl_id: UInt256::from_slice(id.data()),
                    msg_sender: true.into(),
                    msg_sender_priority: 0,
                    block_sender: true.into(),
                })
                .collect(),
            sender_shards: vec![(&ShardIdent::MASTERCHAIN).into()],
            skip_public_msg_send: false.into(),
            use_quic: false.into(),
        };
        self.update_custom_overlays(Some(&[config])).await?;
        self.update_public_overlays(self.engine.zerostate_id()?, 0).await?;
        let mut gates = Vec::new();
        for entry in self.fast_sync_overlays.iter() {
            gates.push(entry.val().hold_listener_exit());
        }
        for entry in self.custom_overlays.iter() {
            gates.push(entry.val().hold_listener_exit());
        }
        assert_eq!(gates.len(), 3, "two fast-sync and one active custom listener");
        Ok(gates)
    }

    #[cfg(test)]
    pub(crate) fn test_block_download_queries(&self) -> usize {
        self.service.test_block_download_queries()
    }

    #[cfg(test)]
    pub(crate) fn test_bounded_reply(
        &self,
        peer: Arc<rtos_block::KeyId>,
        id: BlockIdExt,
        full: bool,
        bytes: Vec<u8>,
    ) {
        self.service.test_bounded_reply(peer, id, full, bytes);
    }
    #[cfg(test)]
    pub(crate) fn test_clear_history_replies(&self) { self.service.test_clear_history_replies(); }

    #[cfg(test)]
    pub(crate) fn test_pss_reply(&self, peer: Arc<rtos_block::KeyId>, state: rtos_api::ton::ton_node::persistentstateidv2::PersistentStateIdV2, offset: Option<i64>, bytes: Vec<u8>) {
        self.service.test_pss_reply(peer, state, offset, bytes);
    }
    #[cfg(test)]
    pub(crate) fn test_bounded_queries(&self) -> usize {
        self.service.test_bounded_queries()
    }

    pub async fn overlay_client(
        self: &Arc<Self>,
        shard: &ShardIdent,
    ) -> Result<Arc<FullNodeOverlayClient>> {
        let shard = trim_shard(shard, self.actual_monitor_min_split.load(Ordering::Relaxed))?;
        self.overlay_client_for_shard(shard).await
    }

    // Configuration updates create the requested physical shard before
    // publishing the new query depth; they must not trim it to the old depth.
    async fn overlay_client_for_shard(
        self: &Arc<Self>,
        shard: ShardIdent,
    ) -> Result<Arc<FullNodeOverlayClient>> {
        let _admission = self.tasks.enter()?;
        let generation =
            self.public_generations.lock().unwrap().entry(shard.clone()).or_default().clone();
        let _generation = generation.lock().await;
        loop {
            match self.public_overlays.get(&shard) {
                Some(guard) => {
                    let client = guard.val();
                    if client.overlay_client().is_active() {
                        return Ok(client.clone());
                    } else if client.overlay_client().is_died() {
                        log::debug!("Overlay client {} is dead - will be recreated", shard);
                        client.stop_and_wait().await?;
                        if self
                            .public_overlays
                            .get(&shard)
                            .is_some_and(|current| Arc::ptr_eq(current.val(), client))
                        {
                            self.public_overlays.remove(&shard);
                        }
                    } else {
                        log::debug!(
                            "Overlay client {} was not died yet - will be activated",
                            shard
                        );
                        let _ = client.overlay_client().activate();
                    }
                }
                None => {
                    let result = self
                        .public_overlays_awaiters
                        .do_or_wait(&shard, Some(10_000), async {
                            let wc = shard.workchain_id();
                            let pfx = shard.shard_prefix_with_tag() as i64;
                            let zerostate_file_hash = self.engine.zerostate_id()?.file_hash();
                            let id_full = OverlayUtils::calc_overlay_id_with_profile(
                                wc,
                                pfx,
                                zerostate_file_hash.as_slice(),
                                self.network.context().stack.overlay.wire_profile(),
                            )?;
                            let id = OverlayUtils::calc_overlay_short_id_with_profile(
                                wc,
                                pfx,
                                zerostate_file_hash.as_slice(),
                                self.network.context().stack.overlay.wire_profile(),
                            )?;
                            log::info!(
                                "Creating public overlay for shard {}, id {}, full id {}",
                                shard,
                                id,
                                base64_encode(id_full)
                            );
                            #[cfg(test)]
                            let gate = if shard == ShardIdent::BASE_WORKCHAIN {
                                self.init_gate.lock().unwrap().clone()
                            } else {
                                None
                            };
                            let client = OverlayClient::new_public(
                                id,
                                id_full,
                                self.network.context().clone(),
                                self.tasks.cancellation().child_token(),
                                self.policy.clone(),
                                self.network.default_rldp_roundtrip(),
                                self.tasks.clone(),
                                #[cfg(test)]
                                gate,
                            )
                            .await?;
                            if let Err(error) = client.add_consumer(self.service.clone()) {
                                let _ = client.delete();
                                return Err(error);
                            }
                            let fullnode_client = FullNodeOverlayClient::new(
                                self.engine.clone(),
                                client,
                                shard.clone(),
                                self.tasks.clone(),
                            )?;
                            if let Err(error) = self.configure_public_propagation(&fullnode_client)
                            {
                                fullnode_client.stop_and_wait().await?;
                                return Err(error);
                            }
                            self.public_overlays.insert(shard.clone(), fullnode_client.clone());

                            Ok(fullnode_client)
                        })
                        .await?;
                    if let Some(client) = result {
                        return Ok(client);
                    }
                }
            }
        }
    }

    // The worker periodically checks for new key blocks (if node is not in sync)
    // and updates monitor min split accordingly. It is so important to know the actual
    // monitor_min_split, otherwise the node may send queries to not existing overlays.
    fn start_monitor_min_split_worker(
        self: Arc<Self>,
        last_known_keyblock_id: BlockIdExt,
        last_known_monitor_min_split: u8,
    ) {
        if self.monitor_min_split_worker_started.fetch_or(true, Ordering::Relaxed) {
            return;
        }

        async fn try_update(
            router: &Arc<FullNodeOverlaysRouter>,
            history: &mut Option<BootstrapAuthority>,
        ) -> Result<()> {
            let result = advance_monitor_history(router.engine.as_ref(), history).await;
            if let Some(authority) = history {
                // Publish the authenticated prefix even when a later download
                // fails. Read config from its proof, without trusting new bytes.
                let min_split = authority.config()?.base_workchain()?.monitor_min_split();
                router.update_public_overlays(authority.id(), min_split).await?;
            }
            result
        }

        let tasks = self.tasks.clone();
        let _ = tasks.spawn_cancelable("monitor min split", async move {
            log::info!(
                "Starting monitor min split worker: last observed keyblock {}, monitor min split {}",
                last_known_keyblock_id, last_known_monitor_min_split
            );
            let mut history = None;
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {},
                    _ = self.network.transport_config_changed() => {},
                }
                if let Err(error) = self.refresh_fast_sync_from_applied_state().await {
                    log::warn!("Fast-sync transport refresh: {error}");
                }
                if self.engine.check_sync().await.unwrap_or(false) {
                    log::trace!("Monitor min split worker: node is in sync - skipping iteration");
                } else {
                    log::trace!("Monitor min split worker: attempt to get newer key blocks...");
                    if let Err(e) = try_update(&self, &mut history).await {
                        log::warn!("Monitor min split worker: {}", e);
                    }
                }
            }
        });
    }

    pub(crate) async fn update_public_overlays(
        self: &Arc<Self>,
        keyblock_id: &BlockIdExt,
        new_mms: u8,
    ) -> Result<()> {
        let _admission = self.tasks.enter()?;
        check_monitor_min_split(new_mms)?;
        // Serialize updates and commit the cursor only after overlay work
        // succeeds, so a failed creation can be retried at the same key block.
        let mut last_known_id = self.last_known_keyblock_id.lock().await;
        if !monitor_update_needed(last_known_id.as_ref(), keyblock_id)? {
            return Ok(());
        }
        self.clone().start_monitor_min_split_worker(keyblock_id.clone(), new_mms);

        let old_mms = self.actual_monitor_min_split.load(Ordering::Relaxed);
        if old_mms == new_mms {
            *last_known_id = Some(keyblock_id.clone());
            return Ok(());
        }
        log::info!("Updating monitor min split from {} to {}", old_mms, new_mms);
        if new_mms < old_mms {
            for guard in self.public_overlays.iter() {
                let shard = guard.key();
                if shard.is_base_workchain() {
                    if shard.prefix_len() > new_mms {
                        log::info!("Deactivating public overlay {}", shard);
                        guard.val().overlay_client().deactivate();
                    }
                }
            }
        } else {
            let to_add = calc_new_shards(old_mms, new_mms)?;
            let mut tasks = Vec::new();
            for new in &to_add {
                tasks.push(self.overlay_client_for_shard(new.clone()));
            }
            futures::future::try_join_all(tasks).await?;
        }
        self.actual_monitor_min_split.store(new_mms, Ordering::Relaxed);
        *last_known_id = Some(keyblock_id.clone());
        Ok(())
    }

    pub(crate) async fn refresh_fast_sync_from_applied_state(self: &Arc<Self>) -> Result<()> {
        // Read after taking the refresh lock: a delayed caller must not install
        // an older applied configuration after a newer refresh has completed.
        let _refresh = self.fast_sync_refresh.lock().await;
        loop {
            let state = self.engine.load_last_applied_mc_state().await?;
            match self
                .update_private_overlays_inner(
                    state.config_params()?,
                    Some(state.block_id().clone()),
                )
                .await
            {
                Err(error) if error.is::<RetryFastSyncRefresh>() => continue,
                result => return result,
            }
        }
    }

    pub(crate) async fn special_update_fastsync_overlays(self: &Arc<Self>) -> Result<()> {
        let _admission = self.tasks.enter()?;
        if self.network.context().stack.overlay.wire_profile() == rtos_api::WireProfile::T0 {
            return self.refresh_fast_sync_from_applied_state().await;
        }
        // Special case: create fast sync overlays when we are a validator from the
        // previous set. The normal flow (update_validator_lists in validator_manager)
        // only processes current and next sets, so the prev set ADNL key is never
        // loaded and fast sync overlays are not created at startup.

        // 0) Load last master state and config
        let mc_state = self.engine.load_last_applied_mc_state().await?;
        let config = mc_state.config_params()?;

        // 1) Read prev validator set
        let prev_vset = config.prev_validator_set()?;
        let cur_vset = config.validator_set()?;
        let next_vset = config.next_validator_set()?;

        if prev_vset.list().is_empty() {
            return Ok(());
        }

        // 2) Check if keyring (not ADNL) contains a key from the prev set
        //    and doesn't contain anyone from current/next
        let config_handler = self.network.config_handler();
        let validator_key_ids = config_handler.get_actual_validator_key_ids()?;
        if validator_key_ids.is_empty() {
            return Ok(());
        }

        let matched = prev_vset.list().iter().find(|descr| {
            descr.public_key().is_ok_and(|key| {
                let pubkey = sigpubkey_to_publickey(key);
                validator_key_ids.iter().any(|kid| kid == pubkey.id())
            })
        });
        let Some(matched_descr) = matched else {
            log::info!("special_update_fastsync: not a validator in prev set");
            return Ok(());
        };
        if cur_vset.list().iter().chain(next_vset.list().iter()).any(|descr| {
            descr.public_key().is_ok_and(|key| {
                let pubkey = sigpubkey_to_publickey(key);
                validator_key_ids.iter().any(|kid| kid == pubkey.id())
            })
        }) {
            log::info!("special_update_fastsync: is a validator in current or next set - skipping");
            return Ok(());
        }

        let pubkey = sigpubkey_to_publickey(matched_descr.public_key()?);
        let adnl_id = get_adnl_id(matched_descr)?;
        let (_, election_id) = config_handler
            .get_validator_key(pubkey.id())
            .await
            .ok_or_else(|| error!("special_update_fastsync: validator key not found in keyring"))?;

        // Build ADNL key candidates: adnl_id from descriptor, pubkey as fallback
        let mut candidates = vec![adnl_id.clone()];
        if *pubkey.id() != adnl_id {
            candidates.push(pubkey.id().clone());
        }

        let adnl = &self.network.context().stack.adnl;

        // Check if ADNL key is already loaded
        let mut adnl_key = None;
        for cid in &candidates {
            if let Ok(key) = adnl.key_by_id(cid) {
                adnl_key = Some(key);
                break;
            }
        }

        // 3) Load the key to ADNL
        if adnl_key.is_none() {
            for cid in &candidates {
                let Some((key, _)) = config_handler.get_validator_key(cid).await else {
                    continue;
                };
                if let Err(e) = adnl.add_key(key.clone(), election_id as usize) {
                    log::warn!("special_update_fastsync: cannot add ADNL key {cid}: {e}");
                    continue;
                }

                // Add to QUIC if available
                if let Some(quic) = &self.network.context().stack.quic {
                    let adnl_ip = adnl.ip_address_adnl();
                    let quic_addr = if let Some(addr) = self.network.context().quic_address {
                        addr
                    } else if let Some(port) =
                        adnl_ip.port().checked_add(adnl::QuicNode::OFFSET_PORT)
                    {
                        SocketAddr::new(Ipv4Addr::from(adnl_ip.ip()).into(), port)
                    } else {
                        log::warn!(
                            "special_update_fastsync: QUIC port overflow for ADNL port {}",
                            adnl_ip.port()
                        );
                        adnl_key = Some(key);
                        break;
                    };
                    let bind_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), quic_addr.port());
                    match key.pvt_key() {
                        Ok(pvt_key) => {
                            if let Err(e) = quic.add_key(
                                (&pvt_key.lock()? as &[u8]).try_into()?,
                                cid,
                                bind_addr,
                            ) {
                                log::warn!(
                                    "special_update_fastsync: cannot add QUIC key {cid}: {e}"
                                );
                            }
                        }
                        Err(e) => {
                            log::warn!(
                                "special_update_fastsync: cannot get private key for {cid}: {e}"
                            );
                        }
                    }
                }

                log::info!(
                    "special_update_fastsync: loaded ADNL key {cid} (election_id={election_id})"
                );
                adnl_key = Some(key);
                break;
            }
        }

        let Some(adnl_key) = adnl_key else {
            log::warn!(
                "special_update_fastsync: matched prev set validator {} \
                 but no ADNL key could be loaded",
                hex::encode(pubkey.id().data())
            );
            return Ok(());
        };

        // 4) Start periodic_store_ip_addr to DHT
        self.tasks.spawn_handle("fast-sync DHT address announcements", || {
            NodeNetwork::start_periodic_store_ip_addr(
                self.network.context().stack.dht.clone(),
                adnl_key.clone(),
                self.tasks.cancellation().child_token(),
            )
        })?;

        // In update_fast_sync_overlays:
        // 5) Resolve peers and 6) create fast sync overlays
        let mc_use_quic = config.get_mc_simplex_config()?.map_or(false, |c| c.use_quic);
        let shard_use_quic = config.get_shard_simplex_config()?.map_or(false, |c| c.use_quic);
        self.update_fast_sync_overlays(
            &prev_vset,
            &cur_vset,
            &next_vset,
            config.base_workchain()?.monitor_min_split(),
            Some(&adnl_key),
            mc_use_quic,
            shard_use_quic,
        )
        .await
    }

    #[cfg(test)]
    async fn update_private_overlays(self: &Arc<Self>, config: &ConfigParams) -> Result<()> {
        let _refresh = self.fast_sync_refresh.lock().await;
        loop {
            match self.update_private_overlays_inner(config, None).await {
                Err(error) if error.is::<RetryFastSyncRefresh>() => continue,
                result => return result,
            }
        }
    }

    async fn update_private_overlays_inner(
        self: &Arc<Self>,
        config: &ConfigParams,
        applied_id: Option<BlockIdExt>,
    ) -> Result<()> {
        let _admission = self.tasks.enter()?;
        let mut binding = FastSyncRefreshBinding {
            transport_revision: self.network.config_handler().validator_transport_revision()?,
            applied_id,
            valid_until: None,
        };
        let prev_vset = config.prev_validator_set()?;
        let this_vset = config.validator_set()?;
        let next_vset = config.next_validator_set()?;
        let key =
            if self.network.context().stack.overlay.wire_profile() == rtos_api::WireProfile::T0 {
                match self.find_transport_authority(&[&this_vset, &prev_vset, &next_vset]).await {
                    Ok(selected) => selected.map(|selected| {
                        binding.valid_until = selected.valid_until;
                        selected.key
                    }),
                    Err(error) => {
                        let _admission = self.tasks.enter()?;
                        let mut installed = self.fast_sync_snapshot.lock().await;
                        *installed = None;
                        self.clear_fast_sync_overlays().await?;
                        if let Some(resolver) = self.fast_sync_peer_resolver.lock().await.take() {
                            resolver.cancel();
                        }
                        return Err(error);
                    }
                }
            } else if let Some(k) = self.try_get_our_key(&this_vset)? {
                Some(k)
            } else if let Some(k) = self.try_get_our_key(&prev_vset)? {
                Some(k)
            } else {
                self.try_get_our_key(&next_vset)?
            };
        let mc_use_quic = config.get_mc_simplex_config()?.map_or(false, |c| c.use_quic);
        let shard_use_quic = config.get_shard_simplex_config()?.map_or(false, |c| c.use_quic);
        #[cfg(test)]
        {
            let gate = self.fast_sync_refresh_gate.lock().unwrap().take();
            if let Some((entered, release)) = gate {
                let _ = entered.send(());
                let _ = release.await;
            }
        }
        self.update_propagation_config(config, key.as_ref(), &binding).await?;
        self.update_fast_sync_overlays_checked(
            &prev_vset,
            &this_vset,
            &next_vset,
            config.base_workchain()?.monitor_min_split(),
            key.as_ref(),
            mc_use_quic,
            shard_use_quic,
            Some(&binding),
        )
        .await?;
        Ok(())
    }

    pub async fn update_custom_overlays(&self, configs: Option<&[CustomOverlay]>) -> Result<()> {
        let _admission = self.tasks.enter()?;
        if let Some(configs) = configs {
            for config in configs {
                add_unbound_object_to_map_with_update(
                    &self.custom_overlays,
                    config.name.clone(),
                    |prev| {
                        if prev.is_some() {
                            log::info!(
                                "Custom overlay \"{}\" already exists - skipping creation",
                                config.name
                            );
                            Ok(None)
                        } else {
                            log::info!("Creating custom overlay \"{}\"", config.name);
                            Ok(Some(CustomOverlayClient::new(
                                config,
                                self.tasks.cancellation().child_token(),
                                self.network.context().stack.clone(),
                                self.engine.clone(),
                                self.tasks.clone(),
                            )?))
                        }
                    },
                )?;
            }
        }

        let mut to_remove = Vec::new();
        for guard in self.custom_overlays.iter() {
            let name = guard.key();
            if let Some(configs) = configs {
                if !configs.iter().any(|c| &c.name == name) {
                    log::info!("Deleting custom overlay \"{}\"", name);
                    guard.val().stop_and_wait().await?;
                    to_remove.push(name.clone());
                    continue;
                }
            }
            if let Err(e) = guard.val().clone().try_activate() {
                log::warn!("Error activating custom overlay \"{}\": {:?}", name, e);
            }
        }
        for name in to_remove {
            self.custom_overlays.remove(&name);
        }

        Ok(())
    }

    async fn update_fast_sync_overlays(
        self: &Arc<Self>,
        prev_validators: &ValidatorSet,
        this_validators: &ValidatorSet,
        next_validators: &ValidatorSet,
        new_monitor_min_split: u8,
        key: Option<&Arc<dyn KeyOption>>,
        mc_use_quic: bool,
        shard_use_quic: bool,
    ) -> Result<()> {
        self.update_fast_sync_overlays_checked(
            prev_validators,
            this_validators,
            next_validators,
            new_monitor_min_split,
            key,
            mc_use_quic,
            shard_use_quic,
            None,
        )
        .await
    }

    async fn update_fast_sync_overlays_checked(
        self: &Arc<Self>,
        prev_validators: &ValidatorSet,
        this_validators: &ValidatorSet,
        next_validators: &ValidatorSet,
        new_monitor_min_split: u8,
        key: Option<&Arc<dyn KeyOption>>,
        mc_use_quic: bool,
        shard_use_quic: bool,
        binding: Option<&FastSyncRefreshBinding>,
    ) -> Result<()> {
        let _admission = self.tasks.enter()?;
        let mut installed = self.fast_sync_snapshot.lock().await;
        self.publish_fast_sync(binding, || Ok(()))?;
        let desired = FastSyncSnapshot {
            previous: prev_validators.clone(),
            current: this_validators.clone(),
            next: next_validators.clone(),
            monitor_min_split: new_monitor_min_split,
            local_key: key.map(|key| key.id().clone()),
            mc_use_quic,
            shard_use_quic,
        };
        if installed.as_ref() == Some(&desired) {
            return Ok(());
        }
        // Revoke the old generation before installing any new authority. On
        // failure the snapshot stays unset, so the same input is retried.
        *installed = None;
        self.clear_fast_sync_overlays().await?;
        if let Some(previous) = self.fast_sync_peer_resolver.lock().await.take() {
            previous.cancel();
        }
        self.monitor_min_split_for_fast_sync.store(new_monitor_min_split, Ordering::Relaxed);
        let Some(local_key) = key else {
            return self.publish_fast_sync(binding, || {
                *installed = Some(desired);
                Ok(())
            });
        };
        let mut pending = PendingFastSync {
            retiring: self.fast_sync_retiring.clone(),
            overlays: Vec::new(),
            cancellation: self.tasks.cancellation().child_token(),
            committed: false,
        };
        let result: Result<()> = async {
            check_monitor_min_split(new_monitor_min_split)?;
            // Root members = union of past + current + next validator sets.
            // Duplicates (a validator present in multiple rounds) are collapsed by
            // the HashSet/HashMap inside add_semiprivate_overlay
            let mut validators: Vec<ValidatorDescr> = Vec::with_capacity(
                prev_validators.list().len()
                    + this_validators.list().len()
                    + next_validators.list().len(),
            );
            validators.extend(prev_validators.list().iter().cloned());
            validators.extend(this_validators.list().iter().cloned());
            validators.extend(next_validators.list().iter().cloned());

            let generation = pending.cancellation.clone();
            let create_overlay = |shard: &ShardIdent, use_quic: bool| {
                FastSyncOverlayClient::new(
                    shard.clone(),
                    &validators,
                    key,
                    None,
                    generation.child_token(),
                    self.network.context().clone(),
                    self.engine.clone(),
                    self.policy.clone(),
                    self.network.default_rldp_roundtrip(),
                    use_quic,
                    self.tasks.clone(),
                )
            };

            // Resolve ADNL addresses for fastsync root members (prev/this/next union)
            // OverlayNode::pending_peers retry promotes peers automatically as soon
            // as they appear in ADNL.
            let local_key_id = local_key.id().clone();
            let adnl = &self.network.context().stack.adnl;
            let mut to_resolve: Vec<Arc<KeyId>> = Vec::new();
            let mut seen: HashSet<Arc<KeyId>> = HashSet::new();
            let (transport_ids, _) = fast_sync_transport_authority(
                &validators,
                self.network.context().stack.overlay.wire_profile(),
            )?;
            for adnl_id in transport_ids {
                if !seen.insert(adnl_id.clone()) {
                    continue;
                }
                if adnl_id == local_key_id {
                    continue;
                }
                if matches!(adnl.peer_ip_address(&local_key_id, &adnl_id), Ok(Some(_))) {
                    continue;
                }
                to_resolve.push(adnl_id);
            }
            {
                let mut slot = self.fast_sync_peer_resolver.lock().await;
                if let Some(prev) = slot.take() {
                    prev.cancel();
                }
                if !to_resolve.is_empty() {
                    log::info!(
                        "fastsync: scheduling DHT resolve for {} peers under {local_key_id}",
                        to_resolve.len()
                    );
                    let token = pending.cancellation.child_token();
                    self.tasks.spawn_handle("fast-sync peer resolver", || {
                        NodeNetwork::spawn_overlay_peer_resolver(
                            local_key_id.clone(),
                            to_resolve,
                            self.network.context().stack.dht.clone(),
                            self.network.context().stack.overlay.clone(),
                            token.clone(),
                            "fastsync".to_string(),
                        )
                    })?;
                    *slot = Some(token);
                }
            }

            let masterchain = ShardIdent::MASTERCHAIN;
            let master = create_overlay(&masterchain, mc_use_quic).await?;
            pending.overlays.push((masterchain, master.clone()));
            self.configure_fast_sync_propagation(&master)?;
            for prefix in 0u64..(1u64 << new_monitor_min_split) {
                let shard_prefix = if new_monitor_min_split == 0 {
                    0
                } else {
                    prefix << (64 - new_monitor_min_split)
                };
                let shard = ShardIdent::with_prefix_len(
                    new_monitor_min_split,
                    BASE_WORKCHAIN_ID,
                    shard_prefix,
                )?;
                let overlay = create_overlay(&shard, shard_use_quic).await?;
                pending.overlays.push((shard, overlay.clone()));
                self.configure_fast_sync_propagation(&overlay)?;
            }

            self.monitor_min_split_for_fast_sync.store(new_monitor_min_split, Ordering::Relaxed);
            Ok(())
        }
        .await;
        if let Err(error) = result {
            self.clear_fast_sync_overlays().await?;
            if let Some(resolver) = self.fast_sync_peer_resolver.lock().await.take() {
                resolver.cancel();
            }
            return Err(error);
        }
        self.publish_fast_sync(binding, || {
            for (shard, overlay) in pending.overlays.drain(..) {
                self.fast_sync_overlays.insert(shard, overlay);
            }
            pending.committed = true;
            *installed = Some(desired);
            Ok(())
        })
    }

    fn publish_fast_sync<T>(
        &self,
        binding: Option<&FastSyncRefreshBinding>,
        publish: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let Some(binding) = binding else {
            return publish();
        };
        self.network
            .config_handler()
            .with_validator_transport_revision(binding.transport_revision, || {
                if let Some(expected) = &binding.applied_id {
                    if self.engine.load_last_applied_mc_block_id()?.as_deref() != Some(expected) {
                        return Err(RetryFastSyncRefresh.into());
                    }
                }
                if binding
                    .valid_until
                    .is_some_and(|deadline| deadline <= rtos_block::UnixTime::now() as u64)
                {
                    return Err(RetryFastSyncRefresh.into());
                }
                publish()
            })?
            .ok_or_else(|| error!(RetryFastSyncRefresh))?
    }

    async fn clear_fast_sync_overlays(&self) -> Result<()> {
        let shards: Vec<_> =
            self.fast_sync_overlays.iter().map(|entry| entry.key().clone()).collect();
        for shard in shards {
            if let Some(old) = self.fast_sync_overlays.remove(&shard) {
                // Register before stopping or awaiting: cancelled refreshes must
                // drain this generation before creating its replacement.
                self.fast_sync_retiring.lock().unwrap().push(old.val().clone());
                old.val().stop();
            }
        }
        let retiring = self.fast_sync_retiring.lock().unwrap().clone();
        for old in retiring {
            old.stop_and_wait().await?;
            self.fast_sync_retiring.lock().unwrap().retain(|entry| !Arc::ptr_eq(entry, &old));
        }
        Ok(())
    }

    // The full-node ADNL identity and unexpired classical validator transport
    // registrations are existing local transport authorities. Neither grants
    // PQ voting custody; that separately requires held validator/key bindings.
    // Re-read registrations so cached list contexts cannot retain revoked keys.
    #[cfg(test)]
    async fn find_transport_key(
        &self,
        sets: &[&ValidatorSet],
    ) -> Result<Option<Arc<dyn KeyOption>>> {
        Ok(self.find_transport_authority(sets).await?.map(|selected| selected.key))
    }

    async fn find_transport_authority(
        &self,
        sets: &[&ValidatorSet],
    ) -> Result<Option<LocalFastSyncTransport>> {
        let handler = self.network.config_handler();
        let now = rtos_block::UnixTime::now();
        let local_ids = handler
            .get_actual_validator_keys()?
            .into_iter()
            .filter(|entry| i64::from(entry.expire_at) > now as i64)
            .filter_map(|entry| entry.validator_adnl_key_id.map(|id| (id, entry.expire_at)))
            .map(|(id, deadline)| {
                let bytes = rtos_block::base64_decode(&id)?;
                Ok((KeyId::from_data(bytes.as_slice().try_into()?), deadline as u64))
            })
            .collect::<Result<Vec<_>>>()?;
        let context = self.network.context();
        let primary = context.stack.adnl.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY)?;
        let bindings = handler.consensus_transport_bindings()?;
        for validators in sets {
            for binding in &bindings {
                let authorized = validators.list().iter().any(|member| {
                    matches!(member.key, rtos_block::ValidatorKey::Pq(_))
                        && member.validator_id().ok().as_ref() == Some(&binding.validator_id)
                        && member.adnl_addr().ok().as_ref() == Some(&binding.adnl_key_id)
                });
                if !authorized {
                    continue;
                }
                let key = handler.consensus_transport_key(&binding.adnl_key_id).await?;
                if context.stack.adnl.key_by_id(&binding.adnl_key_id)?.id() != key.id() {
                    rtos_block::fail!(
                        "Configured consensus transport does not match loaded ADNL identity"
                    );
                }
                return Ok(Some(LocalFastSyncTransport { key, valid_until: None }));
            }
            let (members, _) =
                fast_sync_transport_authority(validators.list(), rtos_api::WireProfile::T0)?;
            if members.contains(primary.id()) {
                return Ok(Some(LocalFastSyncTransport {
                    key: primary.clone(),
                    valid_until: None,
                }));
            }
            for id in members {
                let Some(deadline) = local_ids
                    .iter()
                    .filter(|(registered, _)| registered == &id)
                    .map(|(_, deadline)| *deadline)
                    .max()
                else {
                    continue;
                };
                let Some((key, election_id)) = handler.get_validator_key(&id).await else {
                    continue;
                };
                if key.id() != &id || key.pvt_key().is_err() {
                    continue;
                }
                if context.stack.adnl.key_by_id(&id).is_err() {
                    if let Err(error) =
                        context.stack.adnl.add_key(key.clone(), election_id as usize)
                    {
                        log::warn!("Cannot activate fast-sync transport {id}: {error}");
                        continue;
                    }
                    NodeNetwork::start_periodic_store_ip_addr(
                        context.stack.dht.clone(),
                        key.clone(),
                        self.network.cancellation_token().child_token(),
                    );
                }
                // Retry QUIC registration even if an earlier attempt already
                // installed ADNL before failing to bind its QUIC endpoint.
                if let Some(quic) = &context.stack.quic {
                    let address = context.stack.adnl.ip_address_adnl();
                    let port = match context.quic_address {
                        Some(address) => address.port(),
                        None => address
                            .port()
                            .checked_add(adnl::QuicNode::OFFSET_PORT)
                            .ok_or_else(|| error!("Fast-sync QUIC port overflow"))?,
                    };
                    let private = key.pvt_key()?;
                    quic.add_key(
                        (&private.lock()? as &[u8]).try_into()?,
                        &id,
                        SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port),
                    )?;
                }
                return Ok(Some(LocalFastSyncTransport { key, valid_until: Some(deadline) }));
            }
        }
        Ok(None)
    }

    /// Look up the local ADNL key for the given validator set.
    ///
    /// Returns `None` both when the node is not a validator and when it is a validator
    /// but the ADNL/overlay context is not yet ready. Callers must tolerate `None`
    /// gracefully.
    fn try_get_our_key(
        self: &Arc<Self>,
        validators: &ValidatorSet,
    ) -> Result<Option<Arc<dyn KeyOption>>> {
        if validators.list().is_empty() {
            return Ok(None);
        }

        let val_list_id = compute_validator_list_id(validators.list(), None)?
            .ok_or_else(|| error!("Can't compute validator list id"))?;
        match self.network.try_get_validator_adnl_key(&val_list_id) {
            None => {
                log::info!(
                    "No local validator ADNL key for list {:x} (node is either not a validator \
                    for this list yet, or validator network context is still not ready)",
                    val_list_id
                );
                return Ok(None);
            }
            Some(k) => Ok(Some(k)),
        }
    }

    /// Send block broadcast to network overlays.
    ///
    /// Supports both ordinary (catchain) and simplex signature variants:
    /// - For ordinary signatures: Uses V1 format (backward compatible with older nodes)
    /// - For simplex signatures: Uses V2 format (required for simplex signature scheme)
    ///
    /// This matches C++ behavior in `serialize_block_broadcast()` which automatically
    /// chooses V2 for non-ordinary signatures.
    pub async fn send_block_broadcast(
        self: &Arc<Self>,
        block: &BlockStuff,
        proof: &BlockProofStuff,
        signatures: &BlockSignaturesVariant,
    ) -> Result<()> {
        let _admission = self.tasks.enter()?;
        log::debug!("Sending block broadcast {}...", block.id());

        let mut custom_overlays = vec![];
        for guard in self.custom_overlays.iter() {
            let overlay = guard.val();
            if overlay.sends_blocks_to(block.id().shard()) {
                custom_overlays.push(overlay.clone());
            }
        }
        let fast_sync_client = self.fast_sync_overlay(block.id().shard());

        match signatures {
            BlockSignaturesVariant::SimplexPq(_) => {
                rtos_block::fail!("PQ block broadcast requires the PQ network signature format")
            }
            BlockSignaturesVariant::Ordinary(sigs) => {
                // Use V1 format for ordinary signatures (backward compatibility)
                let packed_signatures = pack_block_signatures(sigs)?;
                let catchain_seqno = sigs.validator_info.catchain_seqno;
                let validator_set_hash = sigs.validator_info.validator_list_hash_short;

                if fast_sync_client.is_some() || !custom_overlays.is_empty() {
                    let broadcast = TaggedByteSlice {
                        object: &self.network.context().stack.overlay.wire_profile().serialize(
                            &build_block_broadcast_compressed(
                                self.network.context().stack.overlay.wire_profile(),
                                block,
                                proof,
                                catchain_seqno,
                                packed_signatures.clone(),
                                validator_set_hash,
                            )?
                            .into_boxed(),
                        )?,
                        #[cfg(feature = "telemetry")]
                        tag: BlockBroadcastCompressed::constructor_const(),
                    };
                    if let Some(fast_sync_client) = &fast_sync_client {
                        if fast_sync_client.use_twostep() {
                            fast_sync_client.send_twostep_broadcast(&broadcast, 0).await?;
                        } else {
                            fast_sync_client
                                .send_broadcast(&broadcast, 0, AdnlSendMethod::Fast)
                                .await?;
                        }
                    }
                    for overlay in custom_overlays {
                        overlay.send_broadcast(&broadcast, 0).await?;
                    }
                }

                let client = self.overlay_client(block.id().shard()).await?;
                let broadcast = TaggedByteSlice {
                    object: &self.network.context().stack.overlay.wire_profile().serialize(
                        &build_block_broadcast(
                            block,
                            proof,
                            catchain_seqno,
                            packed_signatures,
                            validator_set_hash,
                        )
                        .into_boxed(),
                    )?,
                    #[cfg(feature = "telemetry")]
                    tag: BlockBroadcast::constructor_const(),
                };
                client.send_broadcast(&broadcast, 0, AdnlSendMethod::Fast).await?;
            }
            BlockSignaturesVariant::Simplex(_) => {
                // Use V2 format for simplex signatures (required for proper verification)
                let broadcast_data =
                    self.network.context().stack.overlay.wire_profile().serialize(
                        &build_block_broadcast_compressed_v2(block, proof, signatures)?
                            .into_boxed(),
                    )?;
                let broadcast = TaggedByteSlice {
                    object: &broadcast_data,
                    #[cfg(feature = "telemetry")]
                    tag: BlockBroadcastCompressedV2::constructor_const(),
                };

                if let Some(fast_sync_client) = &fast_sync_client {
                    if fast_sync_client.use_twostep() {
                        fast_sync_client.send_twostep_broadcast(&broadcast, 0).await?;
                    } else {
                        fast_sync_client
                            .send_broadcast(&broadcast, 0, AdnlSendMethod::Fast)
                            .await?;
                    }
                }
                for overlay in custom_overlays {
                    overlay.send_broadcast(&broadcast, 0).await?;
                }

                let client = self.overlay_client(block.id().shard()).await?;
                client.send_broadcast(&broadcast, 0, AdnlSendMethod::Fast).await?;
            }
        }

        Ok(())
    }

    pub async fn send_top_shard_block_description(
        self: &Arc<Self>,
        tbd: Arc<TopBlockDescrStuff>,
    ) -> Result<()> {
        let _admission = self.tasks.enter()?;
        log::debug!("Sending top shard blocks broadcast {}...", tbd.proof_for());

        let broadcast = TaggedByteSlice {
            object: &self.network.context().stack.overlay.wire_profile().serialize(
                &NewShardBlockBroadcast { block: tbd.new_shard_block()? }.into_boxed(),
            )?,
            #[cfg(feature = "telemetry")]
            tag: NewShardBlockBroadcast::constructor_const(),
        };

        #[cfg(not(feature = "xp25"))]
        let flags = 0;
        #[cfg(feature = "xp25")]
        let flags = OverlayNode::FLAG_BCAST_REPEATED;

        if let Some(client) = self.fast_sync_overlay(&ShardIdent::masterchain()) {
            client.send_broadcast(&broadcast, flags, AdnlSendMethod::Fast).await?;
        }
        let client = self.overlay_client(tbd.proof_for().shard()).await?;
        client.send_broadcast(&broadcast, flags, AdnlSendMethod::Fast).await?;
        Ok(())
    }

    pub async fn send_ext_message_broadcast(
        self: &Arc<Self>,
        to: &AccountIdPrefixFull,
        data: &[u8],
    ) -> Result<()> {
        let _admission = self.tasks.enter()?;
        let broadcast = TaggedByteSlice {
            object: &self.network.context().stack.overlay.wire_profile().serialize(
                &ExternalMessageBroadcast { message: ExternalMessage { data: data.to_vec() } }
                    .into_boxed(),
            )?,
            #[cfg(feature = "telemetry")]
            tag: ExternalMessageBroadcast::constructor_const(),
        };
        let mut skip_public = false;
        for guard in self.custom_overlays.iter() {
            let overlay = guard.val();
            if overlay.sends_msgs_to(to) {
                overlay.send_broadcast(&broadcast, 0).await?;
                if overlay.skip_public_msg_send() {
                    skip_public = true;
                }
            }
        }
        if !skip_public {
            self.overlay_client(&to.shard_ident()?)
                .await?
                .send_broadcast(&broadcast, 0, AdnlSendMethod::Fast)
                .await?;
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn send_block_candidate_broadcast(
        &self,
        id: &BlockIdExt,
        cc_seqno: u32,
        validator_set_hash: u32,
        block_root: &Cell,
    ) -> Result<()> {
        let _admission = self.tasks.enter()?;
        let mut custom_overlays = vec![];
        for guard in self.custom_overlays.iter() {
            let overlay = guard.val();
            if overlay.sends_blocks_to(id.shard()) {
                custom_overlays.push(overlay.clone());
            }
        }
        let fast_sync_client = self.fast_sync_overlay(id.shard());
        if !custom_overlays.is_empty() || fast_sync_client.is_some() {
            log::debug!("Sending block candidate broadcast {id}...");
            let broadcast = build_block_candidate_broadcast_compressed(
                id.clone(),
                cc_seqno,
                validator_set_hash,
                block_root,
            )?
            .into_boxed();
            let broadcast = TaggedByteSlice {
                object: &self
                    .network
                    .context()
                    .stack
                    .overlay
                    .wire_profile()
                    .serialize(&broadcast)?,
                #[cfg(feature = "telemetry")]
                tag: broadcast.bare_object().constructor(),
            };
            for overlay in custom_overlays {
                overlay.send_broadcast(&broadcast, 0).await?;
            }
            if let Some(client) = fast_sync_client {
                if client.use_twostep() {
                    client.send_twostep_broadcast(&broadcast, 0).await?;
                } else {
                    client.send_broadcast(&broadcast, 0, AdnlSendMethod::Fast).await?;
                }
            }
        }
        Ok(())
    }

    // This function will be sent from the collator in the future.
    // It is part of the separated collator feature.
    #[allow(dead_code)]
    pub async fn send_out_msg_queue_proof_broadcast(
        &self,
        id: &BlockIdExt,
        dst_shard: &ShardIdent,
        state_proof_boc: Vec<u8>,
        queue_proof_boc: Vec<u8>,
        msg_count: u32,
        limits: ImportedMsgQueueLimits,
    ) -> Result<()> {
        let _admission = self.tasks.enter()?;
        if let Some(client) = self.fast_sync_overlay(&dst_shard) {
            log::debug!("Sending out msg queue proof broadcast {} for shard {}...", id, dst_shard);
            let broadcast = OutMsgQueueProofBroadcast {
                dst_shard: dst_shard.into(),
                block: id.clone(),
                limits: rtos_api::ton::ton_node::importedmsgqueuelimits::ImportedMsgQueueLimits {
                    max_bytes: limits.max_bytes as i32,
                    max_msgs: limits.max_msgs as i32,
                }
                .into_boxed(),
                proof: rtos_api::ton::ton_node::outmsgqueueproof::OutMsgQueueProof {
                    queue_proofs: queue_proof_boc,
                    block_state_proofs: state_proof_boc,
                    msg_counts: vec![msg_count as i32],
                }
                .into_boxed(),
            }
            .into_boxed();
            let broadcast = TaggedByteSlice {
                object: &self
                    .network
                    .context()
                    .stack
                    .overlay
                    .wire_profile()
                    .serialize(&broadcast)?,
                #[cfg(feature = "telemetry")]
                tag: OutMsgQueueProofBroadcast::constructor_const(),
            };
            client.send_broadcast(&broadcast, 0, AdnlSendMethod::Fast).await?;
        }
        Ok(())
    }

    pub fn stop(&self) {
        self.tasks.stop();
        self.delete_overlays();
    }

    pub async fn stop_and_wait(&self) -> Result<()> {
        self.stop();
        // Includes admitted constructors and all real worker joins, even for
        // clients already retired or whose constructor was cancelled.
        let _ = self.tasks.wait().await;
        self.delete_overlays();
        for key in self.public_overlays.iter().map(|g| g.key().clone()).collect::<Vec<_>>() {
            self.public_overlays.remove(&key);
        }
        for key in self.fast_sync_overlays.iter().map(|g| g.key().clone()).collect::<Vec<_>>() {
            self.fast_sync_overlays.remove(&key);
        }
        for key in self.custom_overlays.iter().map(|g| g.key().clone()).collect::<Vec<_>>() {
            self.custom_overlays.remove(&key);
        }
        self.tasks.wait().await
    }

    fn delete_overlays(&self) {
        for guard in self.public_overlays.iter() {
            guard.val().stop();
            let id = guard.val().overlay_client().id();
            log::info!("Deleting public overlay {}", id);
            match guard.val().overlay_client().delete() {
                Ok(result) => log::info!("Deleted overlay {} ({})", guard.key(), result),
                Err(e) => log::warn!("Deleting overlay {}: {}", guard.key(), e),
            }
        }
        for guard in self.fast_sync_overlays.iter() {
            let id = guard.val().id();
            log::info!("Deleting fast sync overlay {} {}", guard.key(), id);
            guard.val().stop();
        }
        for guard in self.custom_overlays.iter() {
            guard.val().stop();
        }
    }

    #[cfg(feature = "telemetry")]
    pub fn log_stat(&self) {
        for guard in self.fast_sync_overlays.iter() {
            let client = guard.val();
            let shard = guard.key();
            log::debug!(target: "telemetry", "Fast sync overlay for shard {}, id {}",
                shard, client.id());
            client.client().neighbours().log_neighbors_stat();
        }
        for guard in self.public_overlays.iter() {
            let client = guard.val().overlay_client();
            if client.is_died() {
                continue;
            }
            log::debug!(
                target: "telemetry",
                "Public overlay {}{}, short id {}, full id {}",
                guard.key(),
                if client.is_active() {
                    ""
                } else {
                    " (inactive)"
                },
                client.id(),
                base64_encode(client.id_full()),
            );
            client.neighbours().log_neighbors_stat();
        }
    }

    #[cfg(test)]
    pub(crate) fn test_fast_sync_received(&self, id: &rtos_block::BlockIdExt) -> bool {
        self.fast_sync_overlay(id.shard())
            .is_some_and(|overlay| overlay.received_candidate_and_finality(id))
    }

    fn fast_sync_overlay(&self, shard: &ShardIdent) -> Option<Arc<FastSyncOverlayClient>> {
        let shard =
            trim_shard(shard, self.monitor_min_split_for_fast_sync.load(Ordering::Relaxed)).ok()?;
        self.fast_sync_overlays.get(&shard).map(|g| g.val().clone())
    }
}

/// Advance only from the configured local pin or an authority previously
/// authenticated by this worker. Peer IDs and database cursors only locate data.
/// Bound work per poll and retain progress even if a later peer response fails.
pub(crate) async fn advance_monitor_history(
    engine: &dyn EngineOperations,
    history: &mut Option<BootstrapAuthority>,
) -> Result<()> {
    let pin = engine.init_mc_block_id();
    if history.as_ref().is_some_and(|authority| authority.anchor() != pin) {
        *history = None;
    }
    if history.is_none() {
        *history = Some(if pin.seq_no == 0 {
            if pin != engine.zerostate_id()? {
                rtos_block::fail!("Monitor pin differs from network zerostate");
            }
            BootstrapAuthority::from_zerostate(pin, engine.load_mc_zero_state().await?)?
        } else {
            BootstrapAuthority::from_checkpoint(
                pin,
                crate::boot::load_history_proof(engine, pin, true, true).await?,
            )?
        });
    }
    let mut remaining = 100usize;
    while remaining > 0 {
        if engine.check_stop() {
            rtos_block::fail!("Monitor history authentication stopped");
        }
        let authority = history.as_ref().unwrap();
        let mut ids = engine.download_next_key_blocks_ids(authority.id()).await?;
        if ids.is_empty() {
            return Ok(());
        }
        if ids.len() > 5 {
            rtos_block::fail!("Monitor key-block response exceeds request limit");
        }
        ids.sort_by_key(|id| id.seq_no);
        for id in ids {
            if engine.check_stop() {
                rtos_block::fail!("Monitor history authentication stopped");
            }
            if remaining == 0 {
                return Ok(());
            }
            let authority = history.as_ref().unwrap();
            if !id.shard().is_masterchain_ext() || id.seq_no <= authority.id().seq_no {
                rtos_block::fail!("Monitor key-block response does not advance the masterchain");
            }
            let proof = crate::boot::load_history_proof(engine, &id, false, true).await?;
            let next = authority.advance_key_block(&id, proof.clone())?;
            engine.store_block_proof(&id, None, &proof).await?;
            *history = Some(next);
            remaining -= 1;
        }
    }
    Ok(())
}

fn monitor_update_needed(previous: Option<&BlockIdExt>, next: &BlockIdExt) -> Result<bool> {
    if !next.shard().is_masterchain_ext() {
        rtos_block::fail!("Monitor update requires a full masterchain identity");
    }
    if let Some(previous) = previous {
        if previous.seq_no == next.seq_no && previous != next {
            rtos_block::fail!("Conflicting monitor key-block identity at the same height");
        }
        return Ok(previous.seq_no < next.seq_no);
    }
    Ok(true)
}

fn check_monitor_min_split(value: u8) -> Result<()> {
    if value > crate::engine::Engine::MAX_MONITOR_MIN_SPLIT {
        rtos_block::fail!("Unsupported monitor_min_split {}", value);
    }
    Ok(())
}

fn calc_new_shards(old_min_split: u8, new_min_split: u8) -> Result<HashSet<ShardIdent>> {
    let mut new_shards = HashSet::new();
    for len in old_min_split + 1..=new_min_split {
        for prefix in 0..(1 << len) {
            let shard_prefix = if len == 0 { 0 } else { prefix << 64 - len };
            new_shards.insert(ShardIdent::with_prefix_len(len, BASE_WORKCHAIN_ID, shard_prefix)?);
        }
    }
    Ok(new_shards)
}

fn trim_shard(shard: &ShardIdent, min_split: u8) -> Result<ShardIdent> {
    if shard.is_masterchain() {
        Ok(ShardIdent::MASTERCHAIN)
    } else if min_split == 0 || !shard.is_base_workchain() {
        Ok(ShardIdent::full(shard.workchain_id()))
    } else if shard.prefix_len() <= min_split {
        Ok(shard.clone())
    } else {
        let prefix = shard.shard_prefix_without_tag();
        let mask = (1 << (64 - min_split)) - 1;
        let new_prefix = prefix & !mask;
        ShardIdent::with_prefix_len(min_split, shard.workchain_id(), new_prefix)
    }
}

#[cfg(test)]
#[path = "tests/test_full_node_overlays.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/test_fast_sync_snapshot.rs"]
mod snapshot_tests;
