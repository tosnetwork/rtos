/*
 * RTOS project modifications (2026-10-10): project and crate naming; explicit target wire profile integration.
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::{
    config::{ConfigEvent, NodeConfigHandler, NodeConfigSubscriber, TonNodeConfig},
    engine_traits::{EngineAlloc, PrivateOverlayOperations, ValidatorListOutcome},
    network::catchain_client::CatchainClient,
};
#[cfg(feature = "telemetry")]
use crate::{engine_traits::EngineTelemetry, network::telemetry::FullNodeNetworkTelemetry};
use adnl::{
    common::{
        add_counted_object_to_map, spawn_cancelable, AdnlPeers, CountedObject, Counter,
        QueryAnswer, QueryResult, Subscriber,
    },
    declare_counted,
    node::AdnlNode,
    AddressSearchContext, DhtNode, DhtSearchPolicy, NetworkStack, OverlayNode, OverlayShortId,
    PrivateOverlayShortId, RldpNode,
};
use catchain::{
    CatchainFactory, CatchainNode, CatchainOverlay, CatchainOverlayListenerPtr,
    CatchainOverlayLogReplayListenerPtr, CatchainOverlayManagerPtr, CatchainOverlayPtr, PrivateKey,
};
use rtos_block::{error, fail, KeyId, KeyOption, Result, UInt256};
use std::{
    hash::Hash,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicI32, Ordering},
        Arc,
    },
    time::Duration,
};

const USE_CATCHAIN_ADNL_OVERLAY: bool = true;

pub struct NetworkContext {
    pub stack: Arc<NetworkStack>,
    pub catchain_overlay_manager: CatchainOverlayManagerPtr,
    pub broadcast_hops: Option<u8>,
    /// Explicit QUIC address from config (None = derive as same_ip:adnl_port+1000)
    pub quic_address: Option<SocketAddr>,
    #[cfg(feature = "telemetry")]
    pub telemetry: FullNodeNetworkTelemetry,
    #[cfg(feature = "telemetry")]
    pub engine_telemetry: Arc<EngineTelemetry>,
    pub engine_allocated: Arc<EngineAlloc>,
}

// Transports dispatch through the node-owned overlay without retaining a
// reverse strong edge. Each accepted callback keeps its target alive until done.
struct WeakOverlaySubscriber(std::sync::Weak<OverlayNode>);

#[async_trait::async_trait]
impl Subscriber for WeakOverlaySubscriber {
    async fn poll(&self, start: &Arc<std::time::Instant>) {
        if let Some(overlay) = self.0.upgrade() {
            overlay.poll(start).await;
        }
    }
    async fn try_consume_custom(&self, data: &[u8], peers: &AdnlPeers) -> Result<bool> {
        match self.0.upgrade() {
            Some(overlay) => overlay.try_consume_custom(data, peers).await,
            None => Ok(false),
        }
    }
    async fn try_consume_object(
        &self,
        object: rtos_api::TLObject,
        peers: &AdnlPeers,
    ) -> Result<bool> {
        match self.0.upgrade() {
            Some(overlay) => overlay.try_consume_object(object, peers).await,
            None => Ok(false),
        }
    }
    async fn try_consume_raw_query(
        &self,
        bytes: &[u8],
        peers: &AdnlPeers,
    ) -> Result<Option<QueryAnswer>> {
        match self.0.upgrade() {
            Some(overlay) => overlay.try_consume_raw_query(bytes, peers).await,
            None => Ok(None),
        }
    }
    async fn try_consume_query(
        &self,
        object: rtos_api::TLObject,
        peers: &AdnlPeers,
    ) -> Result<QueryResult> {
        match self.0.upgrade() {
            Some(overlay) => overlay.try_consume_query(object, peers).await,
            None => Ok(QueryResult::Rejected(object)),
        }
    }
    async fn try_consume_query_bundle(
        &self,
        objects: Vec<rtos_api::TLObject>,
        peers: &AdnlPeers,
    ) -> Result<QueryResult> {
        match self.0.upgrade() {
            Some(overlay) => overlay.try_consume_query_bundle(objects, peers).await,
            None => Ok(QueryResult::RejectedBundle(objects)),
        }
    }
}

pub struct NodeNetwork {
    tasks: crate::types::owned_tasks::OwnedTasks,
    #[cfg(test)]
    pub(crate) test_broadcast_faults: Arc<super::test_broadcast_faults::BroadcastFaults>,
    network_context: Arc<NetworkContext>,
    validator_context: ValidatorContext,
    runtime_handle: tokio::runtime::Handle,
    config_handler: Arc<NodeConfigHandler>,
    default_rldp_roundtrip: Option<u32>,
    cancellation_token: tokio_util::sync::CancellationToken,
}

declare_counted!(
    struct PeerContext {
        count: AtomicI32,
    }
);

declare_counted!(
    struct ValidatorAdnlKeyId {
        key_id: Arc<KeyId>,
    }
);

type ValidatorAdnlKeyIds = lockfree::map::Map<i32, ValidatorAdnlKeyId>;

struct ValidatorContext {
    overlay_lifecycle: std::sync::Mutex<()>,
    private_overlays: Arc<lockfree::map::Map<Arc<OverlayShortId>, Arc<CatchainClient>>>,
    catchain_overlays: Arc<lockfree::map::Map<Arc<PrivateOverlayShortId>, CatchainOverlayPtr>>,
    adnl_key_ids: Arc<ValidatorAdnlKeyIds>,
    all_validator_peers: Arc<lockfree::map::Map<Arc<KeyId>, Arc<PeerContext>>>,
    sets_contexts: Arc<lockfree::map::Map<UInt256, Arc<ValidatorSetContext>>>,
    current_set: Arc<lockfree::map::Map<u8, UInt256>>, // zero or one element [0]
}

/// Select the local node's entry from the validator list by local-key order.
///
/// Returns `(Some(node), adnl_missing)` where `adnl_missing` is true when the matched
/// validator's ADNL identity cannot be resolved from locally known ADNL keys, including
/// C++-parity fallback to validator pubkey short ID. This mirrors the C++
/// `get_validator()` function (`manager.cpp`) which iterates `temp_keys_` and returns the
/// first local key that belongs to the validator set. C++ does not consider ADNL readiness
/// at this layer; the `adnl_missing` flag is a Rust-side diagnostic only.
fn select_local_validator_candidate<'a>(
    validators: &'a [CatchainNode],
    validator_key_ids: &[Arc<KeyId>],
    validator_adnl_key_ids: &[Arc<KeyId>],
) -> (Option<&'a CatchainNode>, bool) {
    for key_id in validator_key_ids {
        if let Some(local_validator) = validators.iter().find(|val| val.public_key.id() == key_id) {
            let adnl_missing = !validator_adnl_key_ids.contains(&local_validator.adnl_id)
                && !validator_adnl_key_ids.contains(local_validator.public_key.id());
            return (Some(local_validator), adnl_missing);
        }
    }
    (None, false)
}

fn collect_local_validator_candidates<'a>(
    validators: &'a [CatchainNode],
    validator_key_ids: &[Arc<KeyId>],
) -> Vec<&'a CatchainNode> {
    validator_key_ids
        .iter()
        .filter_map(|key_id| validators.iter().find(|val| val.public_key.id() == key_id))
        .collect()
}

fn local_validator_adnl_candidates(local_validator: &CatchainNode) -> Vec<Arc<KeyId>> {
    let mut ids = vec![local_validator.adnl_id.clone()];
    let fallback = local_validator.public_key.id().clone();
    if fallback != local_validator.adnl_id.clone() {
        ids.push(fallback);
    }
    ids
}

declare_counted!(
    struct ValidatorSetContext {
        validator_peers: Vec<Arc<KeyId>>,
        validator_key: Arc<dyn KeyOption>,
        validator_adnl_key: Arc<dyn KeyOption>,
    }
);

impl NodeNetwork {
    pub const TAG_DHT_KEY: usize = 1;
    pub const TAG_OVERLAY_KEY: usize = 2;

    const TIMEOUT_FIND_DHT_NODES: Duration = Duration::from_secs(60);
    const TIMEOUT_SEARCH_VALIDATOR_KEYS: Duration = Duration::from_secs(1);
    const TIMEOUT_STORE_IP_ADDRESS_FAIL: Duration = Duration::from_secs(30);
    const TIMEOUT_STORE_IP_ADDRESS_OK: Duration = Duration::from_secs(500);

    pub async fn new(
        config: TonNodeConfig,
        cancellation_token: tokio_util::sync::CancellationToken,
        #[cfg(feature = "telemetry")] engine_telemetry: Arc<EngineTelemetry>,
        engine_allocated: Arc<EngineAlloc>,
    ) -> Result<Arc<Self>> {
        let global_config = config.load_global_config()?;
        let masterchain_zero_state_id = global_config.zero_state()?;
        let broadcast_hops = config.extensions().broadcast_hops;

        let adnl = AdnlNode::with_config(config.adnl_node()?).await?;
        if config.extensions().adnl_compression {
            adnl.set_options(AdnlNode::OPTION_FORCE_COMPRESSION)
        }
        let dht = DhtNode::with_adnl_node(adnl.clone(), Self::TAG_DHT_KEY)?;
        let overlay = OverlayNode::with_params_and_profile(
            adnl.clone(),
            masterchain_zero_state_id.file_hash.as_slice(),
            Self::TAG_OVERLAY_KEY,
            rtos_api::WireProfile::T0,
        )?;
        if config.extensions().disable_broadcast_retransmit {
            overlay.set_broadcast_retransmit(false)
        }
        let overlay_subscriber: Arc<dyn Subscriber> =
            Arc::new(WeakOverlaySubscriber(Arc::downgrade(&overlay)));
        let rldp = RldpNode::with_params(adnl.clone(), vec![overlay_subscriber.clone()], None)?;
        overlay.set_rldp(rldp.clone())?;

        // Initialize QUIC transport (lazy: no endpoint bound until add_key() is called).
        // Validator ADNL keys are registered when a validator set is activated.
        #[cfg(test)]
        let test_broadcast_faults =
            Arc::new(super::test_broadcast_faults::BroadcastFaults::default());
        let quic = {
            #[cfg(test)]
            let subscriber: Arc<dyn adnl::common::Subscriber> =
                Arc::new(super::test_broadcast_faults::ObservedOverlay {
                    overlay: overlay_subscriber.clone(),
                    faults: test_broadcast_faults.clone(),
                });
            #[cfg(not(test))]
            let subscriber: Arc<dyn adnl::common::Subscriber> = overlay_subscriber;
            let quic = adnl::QuicNode::new(
                vec![subscriber],
                cancellation_token.clone(),
                tokio::runtime::Handle::current(),
                None,
            );
            overlay.set_quic(quic.clone())?;
            Some(quic)
        };

        let nodes = global_config.dht_nodes()?;
        for peer in nodes.iter() {
            dht.add_peer(peer)?;
        }

        let default_rldp_roundtrip = config.default_rldp_roundtrip();
        let quic_address = config.quic_address();

        if quic_address.is_some() {
            log::info!("QUIC address set for advertising: {:?}", adnl.ip_address_quic());
        }

        let dht_key = adnl.key_by_tag(Self::TAG_DHT_KEY)?;

        let overlay_key = adnl.key_by_tag(Self::TAG_OVERLAY_KEY)?;
        let (config_handler, config_handler_context) =
            NodeConfigHandler::create(config, tokio::runtime::Handle::current())?;

        let stack = Arc::new(NetworkStack { adnl, dht, overlay, rldp, quic });

        //TODO: remove CatchainClient and configure overlay manager to track private peers
        let catchain_tracks_private_peers = false;
        let catchain_overlay_manager = CatchainFactory::create_adnl_overlay_manager(
            tokio::runtime::Handle::current(),
            stack.clone(),
            broadcast_hops,
            catchain_tracks_private_peers,
        )?;

        let validator_context = ValidatorContext {
            overlay_lifecycle: std::sync::Mutex::new(()),
            private_overlays: Arc::new(lockfree::map::Map::new()),
            catchain_overlays: Arc::new(lockfree::map::Map::new()),
            adnl_key_ids: Arc::new(lockfree::map::Map::new()),
            all_validator_peers: Arc::new(lockfree::map::Map::new()),
            sets_contexts: Arc::new(lockfree::map::Map::new()),
            current_set: Arc::new(lockfree::map::Map::new()),
        };

        let network_context = NetworkContext {
            stack,
            catchain_overlay_manager,
            broadcast_hops,
            quic_address,
            #[cfg(feature = "telemetry")]
            telemetry: FullNodeNetworkTelemetry::new_client(),
            #[cfg(feature = "telemetry")]
            engine_telemetry,
            engine_allocated,
        };
        let network_context = Arc::new(network_context);

        let node_network = NodeNetwork {
            tasks: crate::types::owned_tasks::OwnedTasks::new(cancellation_token.child_token()),
            #[cfg(test)]
            test_broadcast_faults,
            network_context: network_context.clone(),
            validator_context,
            runtime_handle: tokio::runtime::Handle::current(),
            config_handler,
            default_rldp_roundtrip,
            cancellation_token,
        };
        let node_network = Arc::new(node_network);

        let initialized = (|| -> Result<()> {
            // Bind QUIC immediately on the default overlay ADNL key, validator key will be added later
            if let Some(quic) = &node_network.network_context.stack.quic {
                let adnl_ip = node_network.network_context.stack.adnl.ip_address_adnl();
                match Self::compute_quic_bind_addr(adnl_ip, quic_address) {
                    Ok((_quic_addr, bind_addr)) => {
                        if let Err(e) = Self::bind_quic_key(quic, &overlay_key, bind_addr) {
                            log::warn!(
                                "Cannot register default ADNL key {} on QUIC: {e}",
                                overlay_key.id()
                            );
                        }
                    }
                    Err(e) => log::warn!("Skipping default QUIC identity: {e}"),
                }
            }

            NodeConfigHandler::start_sheduler(
                node_network.config_handler.clone(),
                config_handler_context,
                vec![node_network.clone()],
            )?;
            for key in [dht_key, overlay_key] {
                node_network.tasks.spawn_handle("network DHT announcement", || {
                    Self::periodic_store_ip_addr(
                        node_network.network_context.stack.dht.clone(),
                        key,
                        None,
                        node_network.cancellation_token.clone(),
                    )
                })?;
            }
            node_network.tasks.spawn_handle("network DHT discovery", || {
                Self::find_dht_nodes(
                    node_network.network_context.stack.dht.clone(),
                    node_network.cancellation_token.clone(),
                )
            })?;
            Ok(())
        })();
        if let Err(error) = initialized {
            // Keep cleanup owned if the failed constructor's caller is cancelled.
            let cleanup = node_network.clone();
            let drain = tokio::spawn(async move { cleanup.stop_adnl().await });
            if let Err(cleanup_error) = drain.await? {
                return Err(error!(
                    "Network config initialization: {error}; cleanup: {cleanup_error}"
                ));
            }
            return Err(error);
        }
        // Keep key loading and failure cleanup owned even if construction is cancelled.
        let (ready, receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            match node_network.load_consensus_transport_bindings().await {
                Ok(()) => {
                    if ready.send(Ok(node_network.clone())).is_err() {
                        let _ = node_network.stop_adnl().await;
                    }
                }
                Err(error) => {
                    let result = match node_network.stop_adnl().await {
                        Ok(()) => Err(error),
                        Err(cleanup) => Err(error!(
                            "Consensus transport initialization: {error}; cleanup: {cleanup}"
                        )),
                    };
                    let _ = ready.send(result);
                }
            }
        });
        receiver.await?
    }

    async fn load_consensus_transport_bindings(&self) -> Result<()> {
        for (index, binding) in
            self.config_handler.consensus_transport_bindings()?.iter().enumerate()
        {
            let key = self.config_handler.consensus_transport_key(&binding.adnl_key_id).await?;
            // Static transport bindings use a separate tag range from positive i32
            // election identifiers and the default DHT/overlay tags. Never overwrite
            // an existing tag or register a fictitious validator election.
            if self.network_context.stack.adnl.key_by_id(&binding.adnl_key_id).is_err() {
                let tag = (i32::MAX as usize)
                    .checked_add(1)
                    .and_then(|base| base.checked_add(index))
                    .ok_or_else(|| error!("Consensus transport tag overflow"))?;
                self.network_context.stack.adnl.add_key(key.clone(), tag)?;
            }
            if let Some(quic) = &self.network_context.stack.quic {
                let (_, bind_addr) = Self::compute_quic_bind_addr(
                    self.network_context.stack.adnl.ip_address_adnl(),
                    self.network_context.quic_address,
                )?;
                Self::bind_quic_key(quic, &key, bind_addr)?;
            }
            self.tasks.spawn_handle("consensus transport DHT announcement", || {
                Self::periodic_store_ip_addr(
                    self.network_context.stack.dht.clone(),
                    key,
                    None,
                    self.cancellation_token.clone(),
                )
            })?;
        }
        Ok(())
    }

    pub async fn start(&self) -> Result<()> {
        log::info!(
            "start network: ip: {}, adnl_id: {}",
            self.network_context.stack.adnl.ip_address_adnl(),
            self.network_context.stack.adnl.key_by_tag(Self::TAG_OVERLAY_KEY)?.id()
        );
        self.network_context.stack.start_over_udp_tcp().await?;
        log::info!(
            "network started; TCP support {}",
            if self.network_context.stack.is_tcp_available() { "ON" } else { "OFF" }
        );
        Ok(())
    }

    pub fn context(&self) -> &Arc<NetworkContext> {
        &self.network_context
    }

    pub fn try_get_validator_adnl_key(&self, val_list_id: &UInt256) -> Option<Arc<dyn KeyOption>> {
        self.validator_context
            .sets_contexts
            .get(val_list_id)
            .map(|set_context| set_context.val().validator_adnl_key.clone())
    }

    pub(crate) async fn transport_config_changed(&self) {
        self.config_handler.validator_transport_changed().await;
    }

    pub fn cancellation_token(&self) -> &tokio_util::sync::CancellationToken {
        &self.cancellation_token
    }

    pub fn default_rldp_roundtrip(&self) -> Option<u32> {
        self.default_rldp_roundtrip
    }

    pub fn get_key_id_by_tag(&self, tag: usize) -> Result<Arc<KeyId>> {
        let key_id = self.network_context.stack.adnl.key_by_tag(tag)?;
        Ok(key_id.id().clone())
    }

    pub fn config_handler(&self) -> Arc<NodeConfigHandler> {
        self.config_handler.clone()
    }

    pub async fn stop_adnl(&self) -> Result<()> {
        log::info!("Stopping node network loops...");
        self.config_handler.stop();
        self.cancellation_token.cancel();
        // A queued subscriber must finish before transport shutdown, otherwise
        // it can register a new endpoint after the old endpoints were stopped.
        let config_result = self.config_handler.stop_and_wait().await;
        let workers_result = self.tasks.wait().await;
        let quic_result = if let Some(quic) = &self.network_context.stack.quic {
            log::info!("Stopping QUIC...");
            quic.shutdown_and_wait().await
        } else {
            Ok(())
        };
        log::info!("Node network loops stopped. Stopping adnl...");
        let adnl_result = self.network_context.stack.adnl.stop_checked().await;
        log::info!("Stopped adnl");
        match (config_result, workers_result, quic_result, adnl_result) {
            (Ok(()), Ok(()), Ok(()), Ok(())) => Ok(()),
            (config, workers, quic, adnl) => Err(error!(
                "Network shutdown: config={:?}; workers={:?}; QUIC={:?}; ADNL={:?}",
                config.err(),
                workers.err(),
                quic.err(),
                adnl.err()
            )),
        }
    }

    fn try_add_counted_object<K: Hash + Ord + Clone, T: CountedObject>(
        &self,
        map: &Arc<lockfree::map::Map<K, Arc<T>>>,
        id: &K,
        factory: impl FnMut() -> Result<Arc<T>>,
        msg: String,
    ) -> Result<Arc<T>> {
        add_counted_object_to_map(map, id.clone(), factory)?;
        if let Some(found) = map.get(id) {
            Ok(found.val().clone())
        } else {
            fail!("Cannot add {msg}")
        }
    }

    pub(crate) fn start_periodic_store_ip_addr(
        dht: Arc<DhtNode>,
        node_key: Arc<dyn KeyOption>,
        cancellation_token: tokio_util::sync::CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        Self::periodic_store_ip_addr(dht, node_key, None, cancellation_token)
    }

    fn bind_quic_key(
        quic: &Arc<adnl::QuicNode>,
        key: &Arc<dyn KeyOption>,
        bind_addr: SocketAddr,
    ) -> Result<()> {
        let pvt_key = key.pvt_key()?.lock()?;
        quic.add_key(pvt_key.as_ref().try_into()?, key.id(), bind_addr)
    }

    fn compute_quic_bind_addr(
        adnl_ip: &adnl::node::IpAddress,
        quic_address: Option<SocketAddr>,
    ) -> Result<(SocketAddr, SocketAddr)> {
        let quic_addr = if let Some(addr) = quic_address {
            addr
        } else {
            let quic_port = adnl_ip
                .port()
                .checked_add(adnl::QuicNode::OFFSET_PORT)
                .ok_or_else(|| error!("QUIC port overflow for ADNL port {}", adnl_ip.port()))?;
            SocketAddr::new(Ipv4Addr::from(adnl_ip.ip()).into(), quic_port)
        };
        let bind_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), quic_addr.port());
        if quic_addr.ip() != IpAddr::from(Ipv4Addr::UNSPECIFIED)
            && quic_addr.ip() != IpAddr::from(Ipv4Addr::from(adnl_ip.ip()))
        {
            log::warn!(
                "QUIC configured address {quic_addr} differs from ADNL IP {adnl_ip}; \
                 binding to {bind_addr} but advertising {quic_addr}"
            );
        }
        Ok((quic_addr, bind_addr))
    }

    fn find_dht_nodes(
        dht: Arc<DhtNode>,
        cancellation_token: tokio_util::sync::CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        spawn_cancelable(cancellation_token, async move {
            loop {
                let mut iter = None;
                while let Some(id) = dht.get_known_peer(&mut iter) {
                    if let Err(e) = dht.find_dht_nodes(&id).await {
                        log::warn!("find_dht_nodes result: {:?}", e)
                    }
                }
                tokio::time::sleep(Self::TIMEOUT_FIND_DHT_NODES).await;
            }
        })
    }

    fn periodic_store_ip_addr(
        dht: Arc<DhtNode>,
        node_key: Arc<dyn KeyOption>,
        validator_info: Option<(Arc<ValidatorAdnlKeyIds>, i32)>,
        cancellation_token: tokio_util::sync::CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        spawn_cancelable(cancellation_token, async move {
            let key_id = node_key.id();
            loop {
                let timeout = if let Err(e) = dht.store_ip_address(&node_key).await {
                    log::warn!("store {key_id} IP address ERROR: {e}");
                    Self::TIMEOUT_STORE_IP_ADDRESS_FAIL
                } else {
                    Self::TIMEOUT_STORE_IP_ADDRESS_OK
                };
                tokio::time::sleep(timeout).await;
                if let Some((adnl_key_ids, election_id)) = validator_info.as_ref() {
                    if adnl_key_ids.get(&election_id).is_none() {
                        log::info!("stop storing {key_id} IP address for elections {election_id}");
                        break;
                    }
                }
            }
        })
    }

    fn search_validator_keys_for_validator(
        &self,
        local_adnl_id: Arc<KeyId>,
        validators_contexts: Arc<lockfree::map::Map<UInt256, Arc<ValidatorSetContext>>>,
        validator_list_id: UInt256,
        validators: Vec<CatchainNode>,
    ) -> Result<()> {
        let dht = self.network_context.stack.dht.clone();
        let adnl = self.network_context.stack.adnl.clone();
        let overlay = self.network_context.stack.overlay.clone();

        self.tasks.spawn_cancelable("validator key discovery", async move {
            let mut current_validators = validators;
            loop {
                match Self::search_validator_keys_round(
                    local_adnl_id.clone(),
                    &adnl,
                    &dht,
                    &overlay,
                    current_validators,
                    None,
                )
                .await
                {
                    Ok(missing_validators) => {
                        current_validators = missing_validators;
                    }
                    Err(e) => {
                        log::warn!("{:?}", e);
                        break;
                    }
                }
                if current_validators.is_empty() {
                    log::info!("search_validator_keys: finished.");
                    break;
                } else {
                    log::info!(
                        "search_validator_keys: {} missing validator keys",
                        current_validators.len()
                    );
                }
                tokio::time::sleep(Self::TIMEOUT_SEARCH_VALIDATOR_KEYS).await;
                if validators_contexts.get(&validator_list_id).is_none() {
                    break;
                }
            }
        })?;
        Ok(())
    }

    /// Spawn a background task that DHT-resolves ADNL addresses for a list of
    /// overlay peer KeyIds and registers them under `local_key_id` via
    /// `OverlayNode::add_private_peers_to_adnl`. The task retries unresolved
    /// peers with a fixed 1-second backoff and exits when all are resolved or
    /// `cancellation_token` fires. Empty input is a no-op.
    ///
    /// `label` prefixes log lines so callers can disambiguate (overlay short
    /// id, "fastsync", etc.).
    pub fn spawn_overlay_peer_resolver(
        local_key_id: Arc<KeyId>,
        peers: Vec<Arc<KeyId>>,
        dht: Arc<DhtNode>,
        overlay: Arc<OverlayNode>,
        cancellation_token: tokio_util::sync::CancellationToken,
        label: String,
    ) -> tokio::task::JoinHandle<()> {
        spawn_cancelable(cancellation_token, async move {
            let mut peers = peers;
            loop {
                match Self::resolve_overlay_peers_round(&local_key_id, &dht, &overlay, peers).await
                {
                    Ok(unresolved) => peers = unresolved,
                    Err(e) => {
                        log::warn!("{label}: UNEXPECTED ERROR while resolving peers: {e}");
                        break;
                    }
                }
                if peers.is_empty() {
                    log::info!("{label} resolve_peers: finished.");
                    break;
                } else {
                    log::debug!("{label} resolve_peers: {} peers still unresolved.", peers.len());
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        })
    }

    async fn resolve_overlay_peers_round(
        local_key_id: &Arc<KeyId>,
        dht: &Arc<DhtNode>,
        overlay: &Arc<OverlayNode>,
        peers: Vec<Arc<KeyId>>,
    ) -> Result<Vec<Arc<KeyId>>> {
        let mut unresolved = Vec::new();
        for peer in peers {
            match dht
                .find_address(&mut AddressSearchContext::with_params(
                    &peer,
                    DhtSearchPolicy::default(),
                )?)
                .await
            {
                Ok(Some((adnl_addr, quic_addr, key))) => {
                    match &quic_addr {
                        Some(q) => log::info!(
                            "peer {peer}: resolved adnl {adnl_addr} quic {q}, key {key:x?}"
                        ),
                        None => log::info!("peer {peer}: resolved adnl {adnl_addr}, key {key:x?}"),
                    }
                    overlay.add_private_peers_to_adnl(
                        local_key_id,
                        vec![(adnl_addr, quic_addr, key)],
                    )?;
                }
                Ok(None) => {
                    log::warn!("find address for {peer} failed");
                    unresolved.push(peer);
                }
                Err(e) => {
                    log::warn!("find address for {peer} failed: {e}");
                    unresolved.push(peer);
                }
            }
        }
        Ok(unresolved)
    }

    async fn search_validator_keys_round<'a>(
        local_adnl_id: Arc<KeyId>,
        adnl: &'a AdnlNode,
        dht: &'a Arc<DhtNode>,
        overlay: &'a OverlayNode,
        validators: Vec<CatchainNode>,
        full_node_callback: Option<Arc<dyn Fn(Arc<KeyId>) + Sync + Send>>,
    ) -> Result<Vec<CatchainNode>> {
        let mut lost_validators = Vec::new();
        for val in validators {
            match dht
                .find_address(&mut AddressSearchContext::with_params(
                    &val.adnl_id,
                    DhtSearchPolicy::default(),
                )?)
                .await
            {
                Ok(Some((adnl_addr, quic_addr, key))) => {
                    log::info!("peer {}: found ip: {adnl_addr:?}, key: {key:x?}", val.adnl_id);
                    match full_node_callback {
                        Some(ref callback) => {
                            adnl.add_peer(
                                &local_adnl_id,
                                &adnl_addr,
                                quic_addr.as_ref(),
                                &Arc::new(key),
                            )?;
                            callback(val.adnl_id.clone());
                        }
                        None => {
                            overlay.add_private_peers_to_adnl(
                                &local_adnl_id,
                                vec![(adnl_addr, quic_addr, key)],
                            )?;
                        }
                    }
                }
                Ok(None) => {
                    log::warn!("find address for {} failed", &val.adnl_id);
                    lost_validators.push(val);
                }
                Err(e) => {
                    log::error!("find address for {} failed: {e:?}", &val.adnl_id);
                    lost_validators.push(val.clone());
                }
            }
        }
        Ok(lost_validators)
    }

    #[cfg(feature = "telemetry")]
    pub fn telemetry(&self) -> &FullNodeNetworkTelemetry {
        &self.network_context.telemetry
    }

    async fn load_and_store_validator_adnl_key(
        &self,
        key_id: Arc<KeyId>,
        election_id: i32,
    ) -> Result<bool> {
        log::info!("load_and_store_validator_adnl_key: id {key_id} elections {election_id}");
        let added =
            add_counted_object_to_map(&self.validator_context.adnl_key_ids, election_id, || {
                Ok(ValidatorAdnlKeyId {
                    key_id: key_id.clone(),
                    counter: self
                        .network_context
                        .engine_allocated
                        .validator_adnl_keys
                        .clone()
                        .into(),
                })
            })?;
        if let Some(key_id_stored) = self.validator_context.adnl_key_ids.get(&election_id) {
            let key_id_stored = &key_id_stored.val().key_id;
            if key_id_stored != &key_id {
                fail!("ADNL key mismatch for election {election_id}: {key_id_stored} vs. {key_id}");
            }
        } else {
            fail!("Cannot get saved ADNL key for election {election_id}");
        };
        if !added {
            log::info!(
                "load_and_store_validator_adnl_key: \
                id {key_id} already added for elections {election_id}"
            );
            return Ok(false);
        }
        let Some((adnl_key, _)) = self.config_handler.get_validator_key(&key_id).await else {
            fail!("Cannot find validator ADNL key {key_id} for election {election_id} in config");
        };
        self.network_context.stack.adnl.add_key(adnl_key.clone(), election_id as usize).map_err(
            |e| error!("Cannot add validator ADNL key {key_id} for election {election_id}: {e}"),
        )?;
        if let Some(quic) = &self.network_context.stack.quic {
            let adnl_ip = self.network_context.stack.adnl.ip_address_adnl();
            let (_quic_addr, bind_addr) =
                match Self::compute_quic_bind_addr(adnl_ip, self.network_context.quic_address) {
                    Ok(v) => v,
                    Err(e) => {
                        log::warn!("Skipping QUIC key {key_id}: {e}");
                        return Ok(true);
                    }
                };
            if let Err(e) = Self::bind_quic_key(quic, &adnl_key, bind_addr) {
                log::warn!("Cannot add validator ADNL key {key_id} to QUIC: {e}");
            }
        }
        let stored_key = self.network_context.stack.adnl.key_by_id(&key_id)?;
        self.tasks.spawn_handle("validator DHT announcement", || {
            NodeNetwork::periodic_store_ip_addr(
                self.network_context.stack.dht.clone(),
                stored_key,
                Some((self.validator_context.adnl_key_ids.clone(), election_id)),
                self.cancellation_token.clone(),
            )
        })?;
        log::info!(
            "load_and_store_validator_adnl_key: \
            id {key_id} added for elections {election_id}"
        );
        Ok(true)
    }

    async fn resolve_validator_adnl_key(
        &self,
        validator_list_id: UInt256,
        local_validator: &CatchainNode,
        election_id: i32,
    ) -> Option<Arc<dyn KeyOption>> {
        let candidate_ids = local_validator_adnl_candidates(local_validator);

        for candidate_id in &candidate_ids {
            if let Ok(adnl_key) = self.network_context.stack.adnl.key_by_id(candidate_id) {
                if candidate_id.as_ref() != local_validator.adnl_id.as_ref() {
                    log::warn!(
                        target: "validator_manager",
                        "set_validator_list {:x}: using validator-pubkey ADNL fallback {} \
                         instead of descriptor ADNL {}",
                        validator_list_id,
                        candidate_id,
                        local_validator.adnl_id.as_ref()
                    );
                }
                return Some(adnl_key);
            }
        }

        for candidate_id in &candidate_ids {
            if let Err(e) =
                self.load_and_store_validator_adnl_key(candidate_id.clone(), election_id).await
            {
                log::warn!(
                    target: "validator_manager",
                    "set_validator_list {:x}: cannot load/store ADNL key {} (election_id={}): {}",
                    validator_list_id,
                    candidate_id,
                    election_id,
                    e
                );
                continue;
            }

            if let Ok(adnl_key) = self.network_context.stack.adnl.key_by_id(candidate_id) {
                if candidate_id.as_ref() != local_validator.adnl_id.as_ref() {
                    log::warn!(
                        target: "validator_manager",
                        "set_validator_list {:x}: loaded validator-pubkey ADNL fallback {} \
                         instead of descriptor ADNL {}",
                        validator_list_id,
                        candidate_id,
                        local_validator.adnl_id.as_ref()
                    );
                }
                return Some(adnl_key);
            }
        }

        log::warn!(
            target: "validator_manager",
            "set_validator_list {:x}: validator pubkey {} matched but no ADNL key is available \
             yet (descriptor_adnl={}, pubkey_fallback={}); continuing with membership only",
            validator_list_id,
            hex::encode(local_validator.public_key.id().data()),
            local_validator.adnl_id.as_ref(),
            local_validator.public_key.id().as_ref(),
        );
        None
    }
}

#[async_trait::async_trait]
impl PrivateOverlayOperations for NodeNetwork {
    fn wire_profile(&self) -> rtos_api::WireProfile {
        self.network_context.stack.overlay.wire_profile()
    }

    /// Check local validator membership, set up ADNL keys, and prepare overlay peers.
    ///
    /// Flow:
    /// 1. Match local public keys against the validator list (`select_local_validator_candidate`)
    /// 2. If matched, load or store the ADNL key for the validator's overlay address
    /// 3. Fetch peer addresses via DHT; queue missing peers for background resolution
    /// 4. Create the `ValidatorSetContext` and register overlay peers
    ///
    /// Returns `Selected` whenever pubkey membership is confirmed.
    ///
    /// ADNL/network setup is best-effort: if ADNL key/context cannot be prepared yet,
    /// the function logs warnings and returns membership-only `Selected` so validator
    /// lifecycle decisions are not blocked by transport readiness.
    async fn set_validator_list(
        &self,
        validator_list_id: UInt256,
        validators: &[CatchainNode],
    ) -> Result<ValidatorListOutcome> {
        log::trace!("start set_validator_list validator_list_id: {validator_list_id:x}");

        let validator_adnl_key_ids = self.config_handler.get_actual_validator_adnl_key_ids()?;
        let validator_key_ids = self.config_handler.get_actual_validator_key_ids()?;

        let local_validators = collect_local_validator_candidates(validators, &validator_key_ids);
        let (local_validator, pubkey_matched_but_adnl_missing) = select_local_validator_candidate(
            validators,
            &validator_key_ids,
            &validator_adnl_key_ids,
        );
        let Some(local_validator) = local_validator.cloned() else {
            log::trace!(
                target: "validator_manager",
                "set_validator_list {:x}: no local key found among {} validators \
                 (local key_ids: {}, adnl_ids: {})",
                validator_list_id,
                validators.len(),
                validator_key_ids.len(),
                validator_adnl_key_ids.len()
            );
            return Ok(ValidatorListOutcome::NotValidator);
        };

        let (local_validator_key, election_id) = self
            .config_handler
            .get_validator_key(local_validator.public_key.id())
            .await
            .ok_or_else(|| error!("validator key not found!"))?;

        let mut matching_local_keys = Vec::with_capacity(local_validators.len());
        for validator in &local_validators {
            let (validator_key, _) = self
                .config_handler
                .get_validator_key(validator.public_key.id())
                .await
                .ok_or_else(|| error!("validator key not found!"))?;
            matching_local_keys.push(validator_key);
        }

        if pubkey_matched_but_adnl_missing {
            log::warn!(
                target: "validator_manager",
                "set_validator_list {:x}: public key {} matches local key but ADNL id {} \
                 is not in actual ADNL key set ({} keys). Will also try C++-style \
                 pubkey-derived ADNL fallback.",
                validator_list_id,
                hex::encode(local_validator.public_key.id().data()),
                hex::encode(local_validator.adnl_id.data()),
                validator_adnl_key_ids.len()
            );
        }
        let local_validator_adnl_key = self
            .resolve_validator_adnl_key(validator_list_id.clone(), &local_validator, election_id)
            .await;
        let Some(local_validator_adnl_key) = local_validator_adnl_key else {
            return Ok(ValidatorListOutcome::Selected {
                key: local_validator_key.clone(),
                matching_keys: matching_local_keys,
            });
        };

        let mut peers = Vec::new();
        let mut lost_validators = Vec::new();
        let mut peers_ids = Vec::new();

        for val in validators {
            if val.public_key.id() == local_validator_key.id() {
                continue;
            }
            peers_ids.push(val.adnl_id.clone());
            match self.network_context.stack.dht.fetch_address(&val.adnl_id).await {
                Ok(Some((adnl_addr, quic_addr, key))) => {
                    log::info!("addr: {:?}, key: {:x?}", &adnl_addr, &key);
                    peers.push((adnl_addr, quic_addr, key));
                }
                Ok(None) => {
                    log::info!("addr: {:?} skipped.", &val.adnl_id);
                    lost_validators.push(val.clone());
                }
                Err(e) => {
                    log::error!("find address failed: {:?}", e);
                    lost_validators.push(val.clone());
                }
            }
        }

        self.network_context
            .stack
            .overlay
            .add_private_peers_to_adnl(local_validator_adnl_key.id(), peers)?;

        let context = self.try_add_counted_object(
            &self.validator_context.sets_contexts,
            &validator_list_id,
            || {
                let ret = ValidatorSetContext {
                    validator_peers: peers_ids.clone(),
                    validator_key: local_validator_key.clone(),
                    validator_adnl_key: local_validator_adnl_key.clone(),
                    counter: self.network_context.engine_allocated.validator_sets.clone().into(),
                };
                #[cfg(feature = "telemetry")]
                self.network_context.engine_telemetry.validator_sets.update(
                    self.network_context.engine_allocated.validator_sets.load(Ordering::Relaxed),
                );
                Ok(Arc::new(ret))
            },
            format!("vaidator set for validator list id {validator_list_id:x}"),
        )?;

        log::info!(
            target: "validator_manager",
            "set_validator_list {:x}: binding confirmed — election_id={} \
             validator_key={} adnl_key={} peers={}",
            validator_list_id,
            election_id,
            hex::encode(context.validator_key.id().data()),
            hex::encode(context.validator_adnl_key.id().data()),
            context.validator_peers.len(),
        );

        if !lost_validators.is_empty() {
            self.search_validator_keys_for_validator(
                local_validator_adnl_key.id().clone(),
                //                self.network_context.dht.clone(),
                //                self.network_context.overlay.clone(),
                self.validator_context.sets_contexts.clone(),
                validator_list_id.clone(),
                lost_validators,
            )?;
        }

        for peer in context.validator_peers.iter() {
            match self.validator_context.all_validator_peers.get(peer) {
                None => {
                    self.try_add_counted_object(
                        &self.validator_context.all_validator_peers,
                        peer,
                        || {
                            let ret = PeerContext {
                                count: AtomicI32::new(0),
                                counter: self
                                    .network_context
                                    .engine_allocated
                                    .validator_peers
                                    .clone()
                                    .into(),
                            };
                            #[cfg(feature = "telemetry")]
                            self.network_context.engine_telemetry.validator_peers.update(
                                self.network_context
                                    .engine_allocated
                                    .validator_peers
                                    .load(Ordering::Relaxed),
                            );
                            Ok(Arc::new(ret))
                        },
                        format!("context for validator peer {peer}"),
                    )?;
                }
                Some(peer_context) => {
                    peer_context.val().count.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        log::trace!("finish set_validator_list validator_list_id: {:x}", validator_list_id);
        Ok(ValidatorListOutcome::Selected {
            key: context.validator_key.clone(),
            matching_keys: matching_local_keys,
        })
    }

    fn has_validator_list_context(&self, validator_list_id: &UInt256) -> bool {
        self.validator_context.sets_contexts.get(validator_list_id).is_some()
    }

    fn activate_validator_list(&self, validator_list_id: UInt256) -> Result<()> {
        log::trace!("activate_validator_list {:x}", validator_list_id);
        if let Some(context) = self.validator_context.sets_contexts.get(&validator_list_id) {
            if let Some(quic) = &self.network_context.stack.quic {
                quic.activate_key(context.val().validator_adnl_key.id());
            }
        }
        self.validator_context.current_set.insert(0, validator_list_id);
        Ok(())
    }

    fn remove_validator_list(&self, validator_list_id: UInt256) -> Result<bool> {
        let context = self.validator_context.sets_contexts.get(&validator_list_id);
        let mut status = false;
        if let Some(context) = context {
            let adnl_key = &context.val().validator_adnl_key;
            let mut removed_peers = Vec::new();
            let mut removed_peers_from_context = Vec::new();

            for peer in context.val().validator_peers.iter() {
                match self.validator_context.all_validator_peers.get(peer) {
                    None => {
                        removed_peers.push(peer.clone());
                    }
                    Some(peer_context) => {
                        let val = peer_context.val().count.fetch_sub(1, Ordering::Relaxed);
                        if val <= 0 {
                            removed_peers_from_context.push(peer.clone());
                            removed_peers.push(peer.clone());
                        }
                    }
                }
            }
            for peer in removed_peers_from_context.iter() {
                self.validator_context.all_validator_peers.remove(peer);
            }

            self.network_context
                .stack
                .overlay
                .delete_private_peers(adnl_key.id(), &removed_peers)?;
            self.validator_context.sets_contexts.remove(&validator_list_id);
            log::trace!("remove validator list (validator key id: {validator_list_id:x})");
            status = true;
        }

        Ok(status)
    }

    fn create_catchain_client(
        &self,
        validator_list_id: UInt256,
        local_validator_key: &PrivateKey,
        overlay_short_id: &Arc<PrivateOverlayShortId>,
        nodes_public_keys: &[CatchainNode],
        listener: CatchainOverlayListenerPtr,
        _log_replay_listener: CatchainOverlayLogReplayListenerPtr,
        broadcast_hops: Option<u8>,
        transport_type: consensus_common::OverlayTransportType,
        block_sync_params: Option<consensus_common::BlockSyncOverlayParams>,
    ) -> Result<Arc<dyn CatchainOverlay + Send>> {
        let validator_set_context =
            self.validator_context.sets_contexts.get(&validator_list_id).ok_or_else(|| {
                error!(
                    "validator list context is not ready ({})",
                    validator_list_id.to_hex_string()
                )
            })?;
        let adnl_key = self
            .network_context
            .stack
            .adnl
            .key_by_id(validator_set_context.val().validator_adnl_key.id())
            .map_err(|e| {
                error!(
                    "validator list context exists but ADNL key is not loaded \
                     ({}, key={}): {}",
                    validator_list_id.to_hex_string(),
                    validator_set_context.val().validator_adnl_key.id(),
                    e
                )
            })?;

        if USE_CATCHAIN_ADNL_OVERLAY {
            let _lifecycle = self.validator_context.overlay_lifecycle.lock().unwrap();
            let overlay = self.network_context.catchain_overlay_manager.start_overlay(
                &local_validator_key,
                overlay_short_id,
                nodes_public_keys,
                listener,
                _log_replay_listener,
                transport_type,
                block_sync_params,
            )?;

            self.validator_context
                .catchain_overlays
                .insert(overlay_short_id.clone(), overlay.clone());

            return Ok(overlay);
        }

        let client = self.try_add_counted_object(
            &self.validator_context.private_overlays,
            overlay_short_id,
            || {
                let ret = CatchainClient::new(
                    &self.runtime_handle,
                    overlay_short_id,
                    &self.network_context,
                    nodes_public_keys,
                    &adnl_key,
                    validator_set_context.val().validator_key.clone(),
                    listener.clone(),
                    broadcast_hops,
                )?;
                Ok(Arc::new(ret))
            },
            format!("catchain overlay {overlay_short_id}"),
        )?;

        CatchainClient::run_wait_broadcast(
            client.clone(),
            &self.runtime_handle,
            overlay_short_id,
            &self.network_context.stack.overlay,
            client.validator_keys(),
            client.catchain_listener(),
        );
        Ok(client as Arc<dyn CatchainOverlay + Send>)
    }

    fn create_authenticated_consensus_client(
        &self,
        _validator_list_id: UInt256,
        local_transport_key: &PrivateKey,
        overlay_short_id: &Arc<PrivateOverlayShortId>,
        runtime: Arc<consensus_common::session_runtime::AuthenticatedSessionRuntime>,
        listener: CatchainOverlayListenerPtr,
        replay_listener: CatchainOverlayLogReplayListenerPtr,
        _broadcast_hops: Option<u8>,
        transport_type: consensus_common::OverlayTransportType,
    ) -> Result<consensus_common::ConsensusOverlayPtr> {
        if runtime.wire_profile() != self.network_context.stack.overlay.wire_profile() {
            fail!("Authenticated consensus runtime/transport wire profile mismatch");
        }
        if local_transport_key.id() != runtime.local_adnl() {
            fail!("Authenticated consensus runtime/local transport identity mismatch");
        }
        // Resolve real loaded custody; runtime roles never supply a signing key.
        // No lookup in a classical consensus-key validator list is required for
        // a noncommittee observer's independently configured ADNL identity.
        let transport_key = self.network_context.stack.adnl.key_by_id(runtime.local_adnl())?;
        let _lifecycle = self.validator_context.overlay_lifecycle.lock().unwrap();
        let overlay = self.network_context.catchain_overlay_manager.start_authenticated_overlay(
            &transport_key,
            overlay_short_id,
            runtime,
            listener,
            replay_listener,
            transport_type,
        )?;
        self.validator_context.catchain_overlays.insert(overlay_short_id.clone(), overlay.clone());
        Ok(overlay)
    }

    fn stop_catchain_client_checked(
        &self,
        id: &Arc<PrivateOverlayShortId>,
        overlay: &consensus_common::ConsensusOverlayPtr,
    ) -> Result<()> {
        let _lifecycle = self.validator_context.overlay_lifecycle.lock().unwrap();
        let manager = &self.network_context.catchain_overlay_manager;
        match self.validator_context.catchain_overlays.get(id) {
            Some(current) if !Arc::ptr_eq(current.val(), overlay) => {
                fail!("Consensus overlay generation does not match registered id {id}");
            }
            Some(_) => {}
            None if manager.overlay_drained(overlay) => {
                // Completion does not imply success: retrieve the retained
                // worker result even after this generation left the registry.
                return manager.stop_overlay_checked(id, overlay);
            }
            None => fail!("Consensus overlay is not registered under id {id}"),
        }
        let result = manager.stop_overlay_checked(id, overlay);
        if manager.overlay_drained(overlay) {
            // Creation and retirement share this lock: the pointer check cannot
            // race installation of a successor with the same overlay id.
            if self
                .validator_context
                .catchain_overlays
                .get(id)
                .is_some_and(|current| Arc::ptr_eq(current.val(), overlay))
            {
                self.validator_context.catchain_overlays.remove(id);
            }
        }
        result
    }

    fn catchain_client_drained(&self, overlay: &consensus_common::ConsensusOverlayPtr) -> bool {
        self.network_context.catchain_overlay_manager.overlay_drained(overlay)
    }

    fn stop_catchain_client(&self, overlay_short_id: &Arc<PrivateOverlayShortId>) {
        if let Some(catchain_client) =
            self.validator_context.private_overlays.remove(overlay_short_id)
        {
            let client = catchain_client.val().clone();
            self.runtime_handle.spawn(async move {
                client.stop().await;
            });
        } else {
            let overlay = self
                .validator_context
                .catchain_overlays
                .get(overlay_short_id)
                .map(|entry| entry.val().clone());
            if let Some(overlay) = overlay {
                if let Err(error) = self.stop_catchain_client_checked(overlay_short_id, &overlay) {
                    log::error!("Consensus overlay shutdown: {error}");
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl NodeConfigSubscriber for NodeNetwork {
    async fn event(&self, sender: ConfigEvent) -> Result<bool> {
        // Wake the existing router monitor even when transport setup fails: a
        // removed local identity must revoke its old overlay authority.
        self.config_handler.notify_validator_transport_changed();
        match sender {
            ConfigEvent::AddValidatorAdnlKey(validator_adnl_key_id, election_id) => {
                self.load_and_store_validator_adnl_key(validator_adnl_key_id, election_id).await
            }
            ConfigEvent::RemoveValidatorAdnlKey(validator_adnl_key_id, election_id) => {
                log::info!(
                    "config event (RemoveValidatorAdnlKey) id: {} election: {}",
                    &validator_adnl_key_id,
                    election_id
                );
                // Remove from ADNL peer table and key config
                self.network_context
                    .stack
                    .adnl
                    .delete_key(&validator_adnl_key_id, election_id as usize)?;
                // Remove from QUIC server cert resolver
                if let Some(quic) = &self.network_context.stack.quic {
                    let adnl_ip = self.network_context.stack.adnl.ip_address_adnl();
                    let quic_port = if let Some(addr) = self.network_context.quic_address {
                        addr.port()
                    } else {
                        adnl_ip.port().saturating_add(adnl::QuicNode::OFFSET_PORT)
                    };
                    let bind_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), quic_port);
                    if let Err(e) = quic.remove_key(&validator_adnl_key_id, bind_addr) {
                        log::warn!(
                            "Cannot remove validator ADNL key {} from QUIC: {e}",
                            validator_adnl_key_id
                        );
                    }
                }
                // Remove from adnl_key_ids — this causes periodic_store_ip_addr
                // to exit its loop, stopping DHT announcements for this key.
                let removed = self.validator_context.adnl_key_ids.remove(&election_id).is_some();
                log::info!(
                    "config event (RemoveValidatorAdnlKey) id: {} finished (removed={removed})",
                    &validator_adnl_key_id
                );
                Ok(removed)
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/test_node_network_validator_list.rs"]
mod tests;
