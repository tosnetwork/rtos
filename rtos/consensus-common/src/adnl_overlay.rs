/*
 * RTOS project modifications (2026-10-10): project and crate naming; typed Simplex protocol and membership admission; explicit target wire profile integration.
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::async_owner::AsyncOwner;
use crate::{
    utils::MetricsHandle, BlockPayloadPtr, ConsensusCommonFactory, ConsensusNode, ConsensusOverlay,
    ConsensusOverlayListenerPtr, ConsensusOverlayLogReplayListenerPtr, ConsensusOverlayManager,
    ConsensusOverlayManagerPtr, ConsensusOverlayPtr, OverlayTransportType, PrivateKey,
    PublicKeyHash, QueryResponseCallback, Result,
};
use adnl::{
    common::{
        AdnlPeers, Answer, QueryAnswer, QueryResult, Subscriber, TaggedByteSlice, TaggedTlObject,
        TimedAnswer,
    },
    node::{AdnlNode, AdnlSendMethod},
    BroadcastCheck, CatchainData, DhtNode, NetworkStack, OverlayNode, OverlayParams,
    PrivateOverlayShortId,
};
use rtos_api::{
    deserialize_boxed, serialize_bare, serialize_boxed,
    ton::{
        catchain::BroadcastWrapper,
        consensus::{
            simplex::{Certificate as SimplexCertificate, Vote as SimplexVote},
            RequestError as ConsensusRequestError,
        },
        overlay::{
            broadcast::BroadcastTwostepSimple, broadcast_twostep::id::Id as BroadcastTwostepId,
            broadcast_twostep_simple::tosign::ToSign as BroadcastTwostepSimpleToSign,
            Certificate as OverlayCertificate,
        },
    },
    BoxedSerialize, IntoBoxed, Serializer, TLObject,
};
use rtos_block::{error, fail, sha256_digest, KeyId, KeyOption, UInt256};
use std::{
    any::Any,
    collections::{HashMap, HashSet},
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, Weak,
    },
    time::{Duration, Instant, SystemTime},
};
use tokio::sync::mpsc;

const LOG_TARGET: &str = "consensus_adnl_overlay";

fn describe_query_response_error(error: &ConsensusRequestError) -> &'static str {
    match error {
        ConsensusRequestError::Consensus_RequestError => "consensus.requestError",
    }
}

fn extract_query_response_error(data: &[u8]) -> Option<String> {
    let message = deserialize_boxed(data).ok()?;
    let error = message.downcast::<ConsensusRequestError>().ok()?;
    Some(describe_query_response_error(&error).to_string())
}

fn normalize_query_response_payload(data: Vec<u8>) -> Result<BlockPayloadPtr> {
    if let Some(error_name) = extract_query_response_error(data.as_slice()) {
        return Err(error!("Peer returned {}", error_name));
    }

    Ok(ConsensusCommonFactory::create_block_payload(data))
}

/// Stream tags for task processor routing in ADNL overlay
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdnlOverlayStreamTag {
    OutgoingMessages = 0,
    OutgoingQueries = 1,
    OutgoingRldp = 2,
    OutgoingBroadcasts = 3,
}

impl AdnlOverlayStreamTag {
    /// Get the number of stream tags
    pub const fn count() -> u32 {
        4
    }
}

impl From<AdnlOverlayStreamTag> for u32 {
    fn from(tag: AdnlOverlayStreamTag) -> Self {
        tag as u32
    }
}

/*
    Task processor for sequential execution of closures
*/

struct TaskDesc {
    // Store a closure that produces a Future when called
    // This ensures the Future is constructed only in the task processor's loop
    task: Box<dyn FnOnce() -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> + Send + 'static>,
    creation_time: SystemTime,
}

pub struct TaskProcessor {
    name: String,
    task_sender: mpsc::UnboundedSender<TaskDesc>,
    stop_requested: Arc<AtomicBool>,
    tasks: Arc<AsyncOwner>,
    post_counter: metrics::Counter,
}

impl TaskProcessor {
    /// Create and immediately start new task processor with given name and metrics
    pub fn new(
        name: String,
        metrics_handle: MetricsHandle,
        runtime_handle: tokio::runtime::Handle,
    ) -> Self {
        log::debug!(target: LOG_TARGET, "Creating and starting TaskProcessor: {}", name);

        let (task_sender, mut task_receiver) = mpsc::unbounded_channel::<TaskDesc>();
        let stop_requested = Arc::new(AtomicBool::new(false));
        let tasks = AsyncOwner::new(runtime_handle.clone());

        let post_counter = metrics_handle
            .sink()
            .register_counter(&format!("task_processor_{}.posts", name).into());
        let pull_counter = metrics_handle
            .sink()
            .register_counter(&format!("task_processor_{}.pulls", name).into());

        // Start the async task loop immediately
        let name_clone = name.clone();
        let stop_requested_clone = stop_requested.clone();
        let pull_counter_clone = pull_counter.clone();

        tasks.spawn("task processor", async move {
            const CHECK_INTERVAL: Duration = Duration::from_millis(100);
            const TASK_AGE_WARNING_THRESHOLD: Duration = Duration::from_secs(5);
            const WARNING_THROTTLE_INTERVAL: Duration = Duration::from_secs(10);

            // Allow first warning immediately
            let mut last_warning_time = Instant::now() - WARNING_THROTTLE_INTERVAL;

            log::debug!(target: LOG_TARGET, "TaskProcessor loop started: {}", name_clone);

            loop {
                // Check stop flag every iteration (eliminates select! starvation)
                if stop_requested_clone.load(Ordering::Relaxed) {
                    log::debug!(target: LOG_TARGET, "TaskProcessor {} stop requested", name_clone);
                    break;
                }

                // Try to receive task with timeout
                match tokio::time::timeout(CHECK_INTERVAL, task_receiver.recv()).await {
                    Ok(Some(task_desc)) => {
                        // Task received - process it
                        pull_counter_clone.increment(1);

                        // Check task age and warn if it's too old (throttled to avoid spam)
                        if let Ok(elapsed) = task_desc.creation_time.elapsed() {
                            if elapsed > TASK_AGE_WARNING_THRESHOLD {
                                let now = Instant::now();
                                if now.duration_since(last_warning_time)
                                    >= WARNING_THROTTLE_INTERVAL
                                {
                                    log::warn!(
                                        target: LOG_TARGET,
                                        "TaskProcessor {name_clone}: \
                                        Processing delayed task (age: {elapsed:?})"
                                    );
                                    last_warning_time = now;
                                }
                            }
                        }

                        let future = (task_desc.task)();
                        future.await;
                    }
                    Ok(None) => {
                        // Channel closed
                        log::debug!(
                            target: LOG_TARGET,
                            "TaskProcessor channel closed: {name_clone}"
                        );
                        break;
                    }
                    Err(_) => {
                        // Timeout occurred - continue loop to check stop flag
                        continue;
                    }
                }
            }

            log::debug!(target: LOG_TARGET, "TaskProcessor loop finished: {}", name_clone);
        });

        Self { name, task_sender, stop_requested, tasks, post_counter }
    }

    /// Post an async closure to the task queue
    pub fn post_closure<F>(&self, closure: F)
    where
        F: FnOnce() -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> + Send + 'static,
    {
        if self.stop_requested.load(Ordering::Relaxed) {
            log::trace!(
                target: LOG_TARGET,
                "TaskProcessor {} stop requested, ignoring posted closure",
                self.name
            );
            return;
        }

        // Store the closure directly using Box::new
        let task_desc = TaskDesc { task: Box::new(closure), creation_time: SystemTime::now() };

        if let Err(_) = self.task_sender.send(task_desc) {
            log::warn!(target: LOG_TARGET, "Failed to send task to TaskProcessor {}", self.name);
        } else {
            self.post_counter.increment(1);
        }
    }

    /// Stop the task processor asynchronously
    pub fn stop_async(&self) {
        log::debug!(target: LOG_TARGET, "Stopping TaskProcessor asynchronously: {}", self.name);
        self.stop_requested.store(true, Ordering::Relaxed);
    }

    /// Stop the task processor and wait for completion
    pub fn stop(&self) {
        log::debug!(target: LOG_TARGET, "Stopping TaskProcessor synchronously: {}", self.name);

        self.stop_async();

        if let Err(error) = self.tasks.wait_sync() {
            log::error!("{error}");
        }
    }
}

impl Drop for TaskProcessor {
    fn drop(&mut self) {
        log::debug!(target: LOG_TARGET, "Dropping TaskProcessor: {}", self.name);
        self.stop_async();
        self.tasks.close();
        log::debug!(target: LOG_TARGET, "Dropped TaskProcessor: {}", self.name);
    }
}

/*
    Task processor manager for managing multiple task processors
*/

pub struct TaskProcessorManager {
    name: String,
    processors: HashMap<u32, Arc<TaskProcessor>>,
    metrics_handle: MetricsHandle,
    stop_requested: Arc<AtomicBool>,
    tasks: Arc<AsyncOwner>,
    runtime_handle: tokio::runtime::Handle,
}

impl TaskProcessorManager {
    /// Create new task processor manager with processors for each tag
    pub fn new(
        name: String,
        _adnl_ids: &[PublicKeyHash],
        num_tags: u32,
        runtime_handle: tokio::runtime::Handle,
    ) -> Self {
        log::info!(
            target: LOG_TARGET,
            "Creating TaskProcessorManager {name} with {num_tags} tags"
        );

        let metrics_handle = MetricsHandle::new(Some(Duration::from_secs(30)));
        let mut processors = HashMap::new();
        let stop_requested = Arc::new(AtomicBool::new(false));
        let tasks = AsyncOwner::new(runtime_handle.clone());
        let mut processor_names = Vec::new();

        // Create TaskProcessor for each tag
        for tag in 0..num_tags {
            let processor_name = format!("stream{:03}", tag);
            processor_names.push(processor_name.clone());

            let processor = Arc::new(TaskProcessor::new(
                processor_name,
                metrics_handle.clone(),
                runtime_handle.clone(),
            ));
            processors.insert(tag, processor);
        }

        log::info!(
            target: LOG_TARGET,
            "TaskProcessorManager {name}: Created and started {} TaskProcessors",
            processors.len()
        );

        let manager = Self {
            name: name.clone(),
            processors,
            metrics_handle,
            stop_requested,
            tasks,
            runtime_handle,
        };

        // Start metrics reporting automatically
        manager.start_metrics_reporting(processor_names);

        manager
    }

    /// Start the metrics reporting task
    fn start_metrics_reporting(&self, processor_names: Vec<String>) {
        let metrics_handle = self.metrics_handle.clone();
        let stop_requested = self.stop_requested.clone();
        let manager_name = self.name.clone();

        log::debug!(
            target: LOG_TARGET,
            "TaskProcessorManager {manager_name}: Starting metrics reporting"
        );

        self.tasks.background("processor metrics", async move {
            const METRICS_DUMP_PERIOD: Duration = Duration::from_secs(30);
            const SLEEP_PERIOD: Duration = Duration::from_millis(300);

            let mut next_metrics_dump_time = SystemTime::now() + METRICS_DUMP_PERIOD;

            log::debug!(
                target: LOG_TARGET,
                "TaskProcessorManager {manager_name}: Metrics loop started"
            );

            while !stop_requested.load(Ordering::Relaxed) {
                tokio::time::sleep(SLEEP_PERIOD).await;

                // Check if it's time to dump metrics
                if SystemTime::now() >= next_metrics_dump_time {
                    if log::log_enabled!(log::Level::Debug) {
                        // Create metrics dumper inside the task to avoid Send issues
                        let mut metrics_dumper = Self::create_metrics_dumper(&processor_names);
                        metrics_dumper.update(&metrics_handle);

                        log::debug!(
                            target: LOG_TARGET,
                            "TaskProcessorManager {manager_name} metrics:"
                        );
                        metrics_dumper.dump(
                            |string| log::debug!(target: LOG_TARGET, "{manager_name}: {string}"),
                        );
                    }

                    next_metrics_dump_time = SystemTime::now() + METRICS_DUMP_PERIOD;
                }
            }

            log::debug!(
                target: LOG_TARGET,
                "TaskProcessorManager {manager_name}: Metrics loop finished"
            );
        });
    }

    /// Create metrics dumper for TaskProcessorManager
    fn create_metrics_dumper(processor_names: &[String]) -> crate::utils::MetricsDumper {
        let mut metrics_dumper = crate::utils::MetricsDumper::new();

        // Add derivative metrics for each task processor's posts and pulls
        for processor_name in processor_names {
            let posts_metric = format!("task_processor_{}.posts", processor_name);
            let pulls_metric = format!("task_processor_{}.pulls", processor_name);

            metrics_dumper.add_derivative_metric(&posts_metric);
            metrics_dumper.add_derivative_metric(&pulls_metric);
        }

        // Add computed queue size metrics for task processors
        for processor_name in processor_names {
            let queue_metric = format!("task_processor_{}_queue", processor_name);
            metrics_dumper
                .add_compute_handler(&queue_metric, crate::utils::compute_queue_size_counter);
        }

        metrics_dumper
    }

    /// Post an async closure to the appropriate task processor
    pub fn post_closure<F>(&self, _adnl_id: &PublicKeyHash, tag: u32, closure: F)
    where
        F: FnOnce() -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> + Send + 'static,
    {
        if self.stop_requested.load(Ordering::Relaxed) {
            log::trace!(
                target: LOG_TARGET,
                "TaskProcessorManager {} is stopped, ignoring posted closure",
                self.name
            );
            return;
        }

        if let Some(processor) = self.processors.get(&tag) {
            processor.post_closure(closure);
        } else {
            log::warn!(
                target: LOG_TARGET,
                "TaskProcessorManager {}: No TaskProcessor found for tag {tag}",
                self.name
            );
        }
    }

    /// Stop all task processors asynchronously
    pub fn stop_async(&self) {
        log::info!(
            target: LOG_TARGET,
            "TaskProcessorManager {}: Stopping asynchronously",
            self.name
        );

        self.stop_requested.store(true, Ordering::Relaxed);

        // Stop all task processors asynchronously
        for processor in self.processors.values() {
            processor.stop_async();
        }
    }

    /// Stop all task processors and wait for completion
    pub fn stop(&self) {
        log::info!(
            target: LOG_TARGET,
            "TaskProcessorManager {}: Stopping synchronously",
            self.name
        );

        self.stop_async();

        if let Err(error) = self.stop_checked() {
            log::error!("{error}");
        }
    }

    fn stop_checked(&self) -> Result<()> {
        self.stop_async();
        let mut errors = Vec::new();
        for processor in self.processors.values() {
            if let Err(error) = processor.tasks.wait_sync() {
                errors.push(error.to_string());
            }
        }
        if let Err(error) = self.tasks.wait_sync() {
            errors.push(error.to_string());
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(error!("{}", errors.join("; ")))
        }
    }

    fn drained(&self) -> bool {
        self.tasks.drained() && self.processors.values().all(|processor| processor.tasks.drained())
    }
}

impl Drop for TaskProcessorManager {
    fn drop(&mut self) {
        log::info!(
            target: LOG_TARGET,
            "TaskProcessorManager {}: Dropping with {} processors",
            self.name,
            self.processors.len()
        );
        self.stop_async();
        self.tasks.close();
        log::info!(target: LOG_TARGET, "TaskProcessorManager {}: Dropped", self.name);
    }
}

/*
    Peer with async address resolution
*/

struct Peer {
    leases: AtomicUsize,
    src_adnl_addr: Arc<KeyId>,
    dst_adnl_addr: Arc<KeyId>,
    overlay_node: Arc<OverlayNode>,
    dht_node: Arc<DhtNode>,
    is_stop_requested: Arc<AtomicBool>,
    tasks: Arc<AsyncOwner>,
}

impl Peer {
    /// Create new peer and start address resolution loop
    fn new(
        src_adnl_addr: Arc<KeyId>,
        dst_adnl_addr: Arc<KeyId>,
        overlay_node: Arc<OverlayNode>,
        dht_node: Arc<DhtNode>,
        runtime_handle: tokio::runtime::Handle,
    ) -> Arc<Self> {
        let peer = Arc::new(Self {
            leases: AtomicUsize::new(1),
            src_adnl_addr,
            dst_adnl_addr,
            overlay_node,
            dht_node,
            is_stop_requested: Arc::new(AtomicBool::new(false)),
            tasks: AsyncOwner::new(runtime_handle.clone()),
        });

        // Start address resolution loop
        let peer_clone = peer.clone();
        peer.tasks.background("peer resolver", async move {
            peer_clone.run_address_resolution_loop().await;
        });

        peer
    }

    /// Run async loop to resolve and update peer addresses
    async fn run_address_resolution_loop(self: Arc<Self>) {
        let mut current_addr = None;
        let mut last_resolution = Instant::now();
        let resolution_interval = Duration::from_secs(10);
        let check_interval = Duration::from_millis(100);

        loop {
            // Check stop flag every 100ms
            if self.is_stop_requested.load(Ordering::Relaxed) {
                break;
            }

            // Resolve address only every 10 seconds
            if last_resolution.elapsed() < resolution_interval {
                tokio::time::sleep(check_interval).await;
                continue;
            }

            last_resolution = Instant::now();

            // Try to fetch address from DHT
            match self.dht_node.fetch_address(&self.dst_adnl_addr).await {
                Ok(Some((adnl_addr, quic_addr, key))) => {
                    // Check if address changed (first time or address different)
                    let addr_changed = current_addr.is_none();

                    if addr_changed {
                        // Delete old address if exists
                        if current_addr.is_some() {
                            if let Err(e) = self.overlay_node.delete_private_peers(
                                &self.src_adnl_addr,
                                &[self.dst_adnl_addr.clone()],
                            ) {
                                log::warn!(
                                    target: LOG_TARGET,
                                    "Error deleting old peer address: {e:?}"
                                );
                            }
                        }

                        // Add new address
                        let add_result = self.overlay_node.add_private_peers_to_adnl(
                            &self.src_adnl_addr,
                            vec![(adnl_addr, quic_addr, key)],
                        );

                        if let Err(e) = add_result {
                            log::warn!(target: LOG_TARGET, "Error adding peer address: {:?}", e);
                        } else {
                            log::debug!(
                                target: LOG_TARGET,
                                "Peer address updated: {:?}",
                                self.dst_adnl_addr
                            );
                            current_addr = Some(()); // Mark that we have an address
                        }
                    }
                }
                Ok(None) => {
                    log::trace!(
                        target: LOG_TARGET,
                        "Peer address not found in DHT: {:?}",
                        self.dst_adnl_addr
                    );
                }
                Err(e) => {
                    log::warn!(
                        target: LOG_TARGET,
                        "DHT fetch error for peer {:?}: {e:?}",
                        self.dst_adnl_addr
                    );
                }
            }
        }

        // Delete private peer when exiting resolution loop
        if let Err(e) = self
            .overlay_node
            .delete_private_peers(&self.src_adnl_addr, &[self.dst_adnl_addr.clone()])
        {
            log::warn!(target: LOG_TARGET, "Error deleting peer at loop exit: {:?}", e);
        }
    }

    /// Stop peer resolution loop asynchronously
    fn stop_async(&self) {
        self.is_stop_requested.store(true, Ordering::Relaxed);
        self.tasks.close();
    }

    fn stop_checked(&self) -> Result<()> {
        self.stop_async();
        let result = self.tasks.wait_sync();
        let cleanup = self
            .overlay_node
            .delete_private_peers(&self.src_adnl_addr, &[self.dst_adnl_addr.clone()]);
        result.and(cleanup.map(|_| ()))
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.stop_async();
        self.tasks.close();
    }
}

/*
    Peer storage
*/

struct PeerStorage {
    peers: Arc<Mutex<HashMap<(Arc<KeyId>, Arc<KeyId>), Weak<Peer>>>>,
}

impl PeerStorage {
    fn new() -> Self {
        Self { peers: Arc::new(Mutex::new(HashMap::new())) }
    }

    /// Get or create peer for given src/dst ADNL addresses
    fn get_peer(
        self: &Arc<Self>,
        src_adnl_addr: Arc<KeyId>,
        dst_adnl_addr: Arc<KeyId>,
        overlay_node: Arc<OverlayNode>,
        dht_node: Arc<DhtNode>,
        runtime_handle: tokio::runtime::Handle,
    ) -> Arc<Peer> {
        let mut peers = self.peers.lock().expect("PeerStorage mutex poisoned");
        let key = (src_adnl_addr.clone(), dst_adnl_addr.clone());

        // Try to upgrade existing weak reference
        if let Some(weak_peer) = peers.get(&key) {
            if let Some(peer) = weak_peer.upgrade() {
                peer.leases.fetch_add(1, Ordering::Relaxed);
                return peer;
            }
        }

        // Create new peer if not exists or was dropped
        let peer = Peer::new(src_adnl_addr, dst_adnl_addr, overlay_node, dht_node, runtime_handle);

        peers.insert(key, Arc::downgrade(&peer));
        peer
    }

    fn remove_peers(&self, peers: Vec<Arc<Peer>>) -> (bool, Result<()>) {
        let mut map = self.peers.lock().expect("PeerStorage mutex poisoned");
        let mut errors = Vec::new();
        let mut drained = true;
        for peer in peers {
            if peer.leases.fetch_sub(1, Ordering::AcqRel) == 1 {
                map.remove(&(peer.src_adnl_addr.clone(), peer.dst_adnl_addr.clone()));
                if let Err(error) = peer.stop_checked() {
                    errors.push(error.to_string());
                }
                drained &= peer.tasks.drained();
            }
        }
        (drained, if errors.is_empty() { Ok(()) } else { Err(error!("{}", errors.join("; "))) })
    }
}

/*
    ADNL-based consensus overlay consumer implementation
*/

struct AdnlOverlayConsumer {
    overlay_id: Arc<PrivateOverlayShortId>, //overlay identifier for logging
    overlay: Weak<AdnlOverlay>,             //weak reference to overlay to avoid cycles
    stop_requested: Arc<AtomicBool>,        //shared stop flag with overlay
}

impl AdnlOverlayConsumer {
    /// Create new consumer with weak reference to overlay
    pub fn new(
        overlay_id: Arc<PrivateOverlayShortId>,
        overlay: Weak<AdnlOverlay>,
        stop_requested: Arc<AtomicBool>,
    ) -> Self {
        log::debug!(
            target: LOG_TARGET,
            "Creating AdnlOverlayConsumer for overlay_id={overlay_id}"
        );
        Self { overlay_id, overlay, stop_requested }
    }
}

#[async_trait::async_trait]
impl Subscriber for AdnlOverlayConsumer {
    async fn try_consume_custom(&self, data: &[u8], peers: &AdnlPeers) -> Result<bool> {
        let overlay = self.overlay.upgrade().ok_or_else(|| error!("Overlay stopped"))?;
        let object = overlay.stack.overlay.wire_profile().deserialize(data)?;

        // Handle catchain broadcast wrapper
        let object = match object.downcast::<BroadcastWrapper>() {
            Ok(BroadcastWrapper::Catchain_BroadcastWrapper(broadcast)) => {
                if let Some(overlay) = self.overlay.upgrade() {
                    let sender_id = crate::utils::int256_to_public_key_hash(&broadcast.sender_id);
                    let data = broadcast.data;
                    overlay.validate_and_process_broadcast(sender_id, &data);
                }
                return Ok(true);
            }
            // Not a broadcast wrapper - keep the original object
            Err(object) => object,
        };

        // Handle simplex direct messages (may come as custom messages in some paths)
        let simplex_kind = if object.is::<SimplexVote>() {
            Some("vote")
        } else if object.is::<SimplexCertificate>() {
            Some("certificate")
        } else {
            None
        };
        if let Some(simplex_kind) = simplex_kind {
            if let Some(overlay) = self.overlay.upgrade() {
                let payload = crate::ConsensusCommonFactory::create_block_payload(data.to_vec());
                let sender_id = peers.other().clone();
                log::trace!(
                    target: LOG_TARGET,
                    "AdnlOverlayConsumer: received simplex {} (custom) from {}",
                    simplex_kind,
                    sender_id
                );
                overlay.process_message(sender_id, payload);
            }
            return Ok(true);
        }

        Ok(false)
    }

    /// Try to consume query - upgrade weak reference and delegate to overlay
    async fn try_consume_query(&self, query: TLObject, _peers: &AdnlPeers) -> Result<QueryResult> {
        // Check if overlay is stopped
        if self.stop_requested.load(Ordering::Relaxed) {
            log::warn!(
                target: LOG_TARGET,
                "AdnlOverlayConsumer: Overlay {} was stopped!",
                &self.overlay_id
            );
            fail!("Overlay {} was stopped!", &self.overlay_id);
        }

        // Try to upgrade weak reference to overlay
        if let Some(overlay) = self.overlay.upgrade() {
            overlay.process_query(query, _peers).await
        } else {
            log::warn!(
                target: LOG_TARGET,
                "AdnlOverlayConsumer: Overlay {} was dropped!",
                &self.overlay_id
            );
            fail!("Overlay {} was dropped!", &self.overlay_id);
        }
    }
}

/*
    ADNL-based consensus overlay implementation
*/

struct AdnlOverlay {
    lower_generation: adnl::OverlayShutdown,
    lower_block_sync_generation: Option<adnl::OverlayShutdown>,
    tasks: Arc<AsyncOwner>,
    shutdown: Arc<AsyncOwner>,
    shutdown_started: Mutex<bool>,
    shutdown_errors: Arc<Mutex<Vec<String>>>,
    cleanup_complete: Arc<AtomicBool>,
    stack: Arc<NetworkStack>,               //ADNL network stack
    overlay_id: Arc<PrivateOverlayShortId>, //private overlay short identifier
    local_id: PublicKeyHash,                //local validator key hash
    private_runtime: Option<Arc<crate::session_runtime::AuthenticatedSessionRuntime>>,
    local_validator_key: Arc<dyn KeyOption>, //local validator key for signing broadcasts
    local_adnl_key: Arc<dyn KeyOption>,      //local ADNL key for two-step broadcast signing
    adnl_to_validator: HashMap<PublicKeyHash, PublicKeyHash>, //ADNL key hash to validator key hash
    all_node_ids: Vec<PublicKeyHash>, //all node ADNL IDs in the overlay for multicast emulation of broadcast messages
    listener: ConsensusOverlayListenerPtr, //consensus overlay listener for incoming events
    stop_requested: Arc<AtomicBool>,  //atomic flag indicating if overlay stop is requested
    consumer: Arc<AdnlOverlayConsumer>, //consumer for handling overlay messages
    runtime_handle: tokio::runtime::Handle, //runtime handle for spawning broadcast listeners
    peers: Mutex<Vec<Arc<Peer>>>,     //active peers with address resolution
    peers_storage: Arc<PeerStorage>,  //peer storage for cleanup
    is_tcp_available: bool,           //flag indicating if TCP or QUIC is available for multicast
    is_quic_available: bool,          //flag indicating if QUIC transport is available
    task_processor_manager: Arc<TaskProcessorManager>, //task processor manager for sequential processing
    /// Short id of the parallel block-sync overlay; `Some` when `enable_observers=true`
    /// routes candidate broadcasts here instead of the consensus private overlay
    block_sync_overlay_id: Option<Arc<PrivateOverlayShortId>>,
    /// Consumer for the block-sync overlay (paired with `block_sync_overlay_id`)
    block_sync_consumer: Option<Arc<AdnlOverlayConsumer>>,
    /// ADNL pubkey hashes of the current validator set; sender check on receive
    block_sync_authorized: HashSet<PublicKeyHash>,
    /// Cumulative counters for the block-sync overlay; `Some` together with `block_sync_overlay_id`
    block_sync_stats: Option<Arc<crate::BlockSyncStats>>,
}

/// Broadcast auth for the block-sync overlay (C++ `OverlayPrivacyRules`).
pub struct BlockSyncCheck {
    pub overlay_id: Arc<PrivateOverlayShortId>,
    pub authorized: HashSet<PublicKeyHash>,
    pub max_payload_size: u32,
    /// Ordered current-set ADNL pubkey hashes; index gives the leader for a slot bucket
    pub current_set: Vec<PublicKeyHash>,
    /// simplex_config_v2.slots_per_leader_window
    pub slots_per_leader_window: u32,
    /// Optional counters; bumped on every Err return and on leader-schedule mismatch
    pub stats: Option<Arc<crate::BlockSyncStats>>,
}

impl BlockSyncCheck {
    fn drop_with(&self, reason: String) -> Result<()> {
        if let Some(stats) = &self.stats {
            stats.bump_precheck_drop();
        }
        fail!("BlockSync overlay {}: {reason}", self.overlay_id)
    }
}

impl BroadcastCheck for BlockSyncCheck {
    fn on_send(&self, src: &Arc<KeyId>, payload_size: usize) -> Result<()> {
        if !self.authorized.contains(src) {
            return self.drop_with(format!("sender {src} not authorized to originate broadcasts"));
        }
        if payload_size as u64 > self.max_payload_size as u64 {
            return self.drop_with(format!(
                "payload size {payload_size} exceeds authorized cap {}",
                self.max_payload_size
            ));
        }
        Ok(())
    }

    fn on_recv(&self, src: &Arc<KeyId>, extra: Option<&[u8]>) -> Result<()> {
        // (1) sender authority check
        if !self.authorized.contains(src) {
            return self.drop_with(format!("sender {src} not in current-set authorized_keys"));
        }
        // (2) parse extra as consensus.broadcastExtra
        let Some(extra_bytes) = extra else {
            return self.drop_with("missing broadcastExtra".to_string());
        };
        let extra_obj: rtos_api::ton::consensus::BroadcastExtra =
            match rtos_api::deserialize_boxed(extra_bytes) {
                Ok(obj) => match obj.downcast() {
                    Ok(e) => e,
                    Err(_) => {
                        return self.drop_with(
                            "broadcastExtra deserialization wrong constructor".to_string(),
                        );
                    }
                },
                Err(e) => return self.drop_with(format!("broadcastExtra parse failed: {e}")),
            };
        let slot = *extra_obj.slot();
        if slot < 0 {
            return self.drop_with(format!("broadcastExtra.slot={slot} is negative"));
        }
        // (3) expected leader check (defensive guards on empty/zero schedule)
        if self.current_set.is_empty() || (self.slots_per_leader_window == 0) {
            return Ok(());
        }
        let leader_idx = ((slot as u64) / (self.slots_per_leader_window as u64))
            % (self.current_set.len() as u64);
        let expected = &self.current_set[leader_idx as usize];
        if src != expected {
            if let Some(stats) = &self.stats {
                stats.bump_leader_mismatch();
            }
            return self.drop_with(format!(
                "leader-schedule mismatch: sender {src} != expected {expected} for slot {slot} \
                 (leader_idx={leader_idx}, window={}, N={})",
                self.slots_per_leader_window,
                self.current_set.len(),
            ));
        }
        Ok(())
    }
}

struct OverlayRegistration {
    node: Arc<OverlayNode>,
    ids: Vec<Arc<PrivateOverlayShortId>>,
}
impl Drop for OverlayRegistration {
    fn drop(&mut self) {
        for id in &self.ids {
            if let Err(error) = self.node.delete_private_overlay(id) {
                log::error!("Partial overlay construction cleanup: {error}");
            }
        }
    }
}

impl AdnlOverlay {
    /// Create new overlay implementation
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runtime_handle: tokio::runtime::Handle,
        stack: Arc<NetworkStack>,
        overlay_id: Arc<PrivateOverlayShortId>,
        local_validator_key: PrivateKey,
        listener: ConsensusOverlayListenerPtr,
        nodes: &[ConsensusNode],
        broadcast_hops: Option<u8>,
        track_private_peers: bool,
        peer_storage: Arc<PeerStorage>,
        transport_type: OverlayTransportType,
        block_sync_params: Option<crate::BlockSyncOverlayParams>,
    ) -> Result<Arc<Self>> {
        Self::new_with_runtime(
            runtime_handle,
            stack,
            overlay_id,
            local_validator_key,
            listener,
            nodes,
            broadcast_hops,
            track_private_peers,
            peer_storage,
            transport_type,
            block_sync_params,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_runtime(
        runtime_handle: tokio::runtime::Handle,
        stack: Arc<NetworkStack>,
        overlay_id: Arc<PrivateOverlayShortId>,
        local_validator_key: PrivateKey,
        listener: ConsensusOverlayListenerPtr,
        nodes: &[ConsensusNode],
        broadcast_hops: Option<u8>,
        track_private_peers: bool,
        peer_storage: Arc<PeerStorage>,
        transport_type: OverlayTransportType,
        block_sync_params: Option<crate::BlockSyncOverlayParams>,
        private_runtime: Option<Arc<crate::session_runtime::AuthenticatedSessionRuntime>>,
    ) -> Result<Arc<Self>> {
        if let Some(runtime) = &private_runtime {
            if !runtime.protocol().observers_in_private_overlay()
                || runtime.local_adnl() != local_validator_key.id()
                || runtime.overlay_short_id()? != overlay_id
                || runtime.wire_profile() != stack.overlay.wire_profile()
                || block_sync_params.is_some()
            {
                fail!("Private runtime overlay binding mismatch");
            }
        }
        if let Some(params) = &block_sync_params {
            params.membership()?;
            if params.overlay_id.is_none() {
                fail!("Block-sync overlay identity is missing");
            }
        }
        // Set by simplex via with_overlay_id; None = no block-sync overlay.
        let block_sync_overlay_id = block_sync_params.as_ref().and_then(|p| p.overlay_id.clone());
        let local_id = local_validator_key.id();
        let allow_tcp_communication = transport_type.allow_tcp();
        let use_quic = transport_type.use_quic();

        log::debug!(
            target: LOG_TARGET,
            "Creating new AdnlOverlay: overlay_id={overlay_id}, local_id={local_id}, \
            nodes_count={}, transport={transport_type:?}",
            nodes.len()
        );

        // Find local ADNL key from nodes by matching local_id
        let mut local_adnl_key: Option<Arc<dyn KeyOption>> = None;
        let mut peers = Vec::new();

        for node in nodes {
            if (node.public_key.pq_key().is_some() && &node.adnl_id == local_id)
                || (node.public_key.pq_key().is_none() && node.public_key.id() == local_id)
            {
                // Found local node - extract ADNL key
                local_adnl_key = Some(stack.adnl.key_by_id(&node.adnl_id)?);
                log::trace!(
                    target: LOG_TARGET,
                    "Found local ADNL key: local_id={local_id}, adnl_id={}",
                    node.adnl_id
                );
                continue; // Skip adding local node to peers
            }
            peers.push(node.adnl_id.clone());
        }

        if let Some(runtime) = &private_runtime {
            local_adnl_key = Some(stack.adnl.key_by_id(runtime.local_adnl())?);
            peers = runtime
                .members()
                .iter()
                .filter(|id| *id != runtime.local_adnl())
                .cloned()
                .collect();
        }
        let local_adnl_key = local_adnl_key
            .ok_or_else(|| error!("Local ADNL key not found in nodes for local_id: {local_id}"))?;

        if let Some(params) = &block_sync_params {
            let current: Vec<_> = nodes.iter().map(|node| node.adnl_id.clone()).collect();
            if params.current_set != current {
                fail!("Block-sync validator order differs from consensus session");
            }
            params.membership()?.validator_index(local_adnl_key.id())?;
        }

        log::debug!(
            target: LOG_TARGET,
            "AdnlOverlay setup: overlay_id={overlay_id}, local_adnl_key={}, peers_count={}",
            local_adnl_key.id(),
            peers.len()
        );

        // Register QUIC keys if QUIC is enabled
        let quic_enabled = if use_quic {
            if let Some(quic) = &stack.quic {
                // Register local validator's ADNL key as a TLS identity on a per-port endpoint
                let ip_addr = stack.adnl.ip_address_adnl();
                let quic_port =
                    ip_addr.port().checked_add(adnl::QuicNode::OFFSET_PORT).ok_or_else(|| {
                        error!(
                            "QUIC bind port overflow: ADNL port {} + offset {} exceeds u16",
                            ip_addr.port(),
                            adnl::QuicNode::OFFSET_PORT
                        )
                    })?;
                let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), quic_port);
                quic.add_key(
                    (&local_adnl_key.pvt_key()?.lock()? as &[u8]).try_into()?,
                    local_adnl_key.id(),
                    bind_addr,
                )?;
                log::info!(
                    target: LOG_TARGET,
                    "Registered QUIC key for local ADNL id={}",
                    local_adnl_key.id()
                );

                log::info!(
                    target: LOG_TARGET,
                    "Using QUIC overlay transport for overlay {overlay_id}"
                );
                true
            } else {
                log::warn!(
                    target: LOG_TARGET,
                    "use_quic=true but QUIC transport not available, falling back to ADNL"
                );
                false
            }
        } else {
            false
        };

        // Initialize private overlay
        let params = OverlayParams {
            flags: 0,
            hops: broadcast_hops,
            overlay_id: &overlay_id,
            runtime: Some(runtime_handle.clone()),
        };
        let candidate_check: Option<Arc<dyn BroadcastCheck>> =
            private_runtime.as_ref().map(|runtime| {
                let current_set: Vec<_> = nodes
                    .iter()
                    .map(|node| {
                        if node.public_key.pq_key().is_some() {
                            node.adnl_id.clone()
                        } else {
                            node.public_key.id().clone()
                        }
                    })
                    .collect();
                Arc::new(BlockSyncCheck {
                    overlay_id: overlay_id.clone(),
                    authorized: current_set.iter().cloned().collect(),
                    max_payload_size: runtime.max_candidate_size(),
                    current_set,
                    slots_per_leader_window: runtime.slots_per_leader_window(),
                    stats: None,
                }) as Arc<dyn BroadcastCheck>
            });
        if !stack.overlay.add_private_overlay(
            params,
            &local_adnl_key,
            &peers,
            use_quic,
            candidate_check,
        )? {
            fail!("Overlay id is already registered");
        }
        let mut registration =
            OverlayRegistration { node: stack.overlay.clone(), ids: vec![overlay_id.clone()] };

        // create the parallel block-sync overlay when enable_observers=true.
        // Membership is the prev|curr|next mc validator union (block_sync_params.members),
        // separate from the consensus session's `peers` (which is the current session subset).
        // Authorized senders are the current set only with per-key payload caps
        let (block_sync_overlay_id, block_sync_authorized, block_sync_stats) = match (
            block_sync_overlay_id,
            block_sync_params,
        ) {
            (Some(bs_id), Some(bs_params)) => {
                // Skip overlay creation if our ADNL key isn't in any of prev|curr|next
                if !bs_params.members.contains(local_adnl_key.id()) {
                    log::warn!(
                        target: LOG_TARGET,
                        "BlockSync: local ADNL key {} not in block-sync members; skipping overlay creation",
                        local_adnl_key.id()
                    );
                    (None, HashSet::new(), None)
                } else {
                    let bs_params_for_log =
                        (bs_params.members.len(), bs_params.authorized_keys.len());
                    let bs_authorized: HashSet<PublicKeyHash> =
                        bs_params.authorized_keys.keys().cloned().collect();
                    let stats = crate::BlockSyncStats::new(
                        bs_id.clone(),
                        crate::BlockSyncRole::Validator,
                        bs_params.shard.clone(),
                        bs_params.session_id.clone(),
                    );
                    let check: Arc<dyn BroadcastCheck> = Arc::new(BlockSyncCheck {
                        overlay_id: bs_id.clone(),
                        authorized: bs_authorized.clone(),
                        max_payload_size: bs_params.max_broadcast_size,
                        current_set: bs_params.current_set.clone(),
                        slots_per_leader_window: bs_params.slots_per_leader_window,
                        stats: Some(stats.clone()),
                    });
                    let bs_overlay_params = OverlayParams {
                        flags: 0,
                        hops: broadcast_hops,
                        overlay_id: &bs_id,
                        runtime: Some(runtime_handle.clone()),
                    };
                    if !stack.overlay.add_private_overlay(
                        bs_overlay_params,
                        &local_adnl_key,
                        &bs_params.members,
                        use_quic,
                        Some(check),
                    )? {
                        fail!("Block-sync overlay id is already registered");
                    }
                    registration.ids.push(bs_id.clone());
                    log::info!(
                        target: LOG_TARGET,
                        "created block-sync overlay {bs_id} (members={}, authorized={}, \
                         leader_window={}, current_set_len={})",
                        bs_params_for_log.0, bs_params_for_log.1,
                        bs_params.slots_per_leader_window, bs_params.current_set.len(),
                    );
                    (Some(bs_id), bs_authorized, Some(stats))
                }
            }
            _ => (None, HashSet::new(), None),
        };

        let stop_requested = Arc::new(AtomicBool::new(false));

        // Create Peer objects for address resolution if tracking is enabled
        let peer_objects = if track_private_peers {
            let mut peer_vec = Vec::new();
            for peer_id in &peers {
                let peer = peer_storage.get_peer(
                    local_adnl_key.id().clone(),
                    peer_id.clone(),
                    stack.overlay.clone(),
                    stack.dht.clone(),
                    runtime_handle.clone(),
                );
                peer_vec.push(peer);
            }
            log::trace!(
                target: LOG_TARGET,
                "AdnlOverlay: Created {} peer objects for address resolution",
                peer_vec.len()
            );
            peer_vec
        } else {
            Vec::new()
        };

        // Create overlay instance (without consumer)
        let local_id = local_id.clone();
        let block_sync_overlay_id_for_cyclic = block_sync_overlay_id.clone();
        let block_sync_stats_for_cyclic = block_sync_stats.clone();
        let lower_generation = stack.overlay.overlay_generation(&overlay_id)?;
        let lower_block_sync_generation = block_sync_overlay_id
            .as_ref()
            .map(|id| stack.overlay.overlay_generation(id))
            .transpose()?;
        let overlay = Arc::new_cyclic(|weak_overlay| {
            // Create consumer with weak reference to overlay
            let consumer = Arc::new(AdnlOverlayConsumer::new(
                overlay_id.clone(),
                weak_overlay.clone(),
                stop_requested.clone(),
            ));

            // Paired consumer for the block-sync overlay; same dispatcher as the consensus one
            let block_sync_consumer = block_sync_overlay_id_for_cyclic.as_ref().map(|bs_id| {
                Arc::new(AdnlOverlayConsumer::new(
                    bs_id.clone(),
                    weak_overlay.clone(),
                    stop_requested.clone(),
                ))
            });

            // Point-to-point multicast is used for broadcasts when TCP transport is available
            let is_tcp_available = stack.is_tcp_available() && allow_tcp_communication;
            if is_tcp_available {
                log::debug!(
                    target: LOG_TARGET,
                    "AdnlOverlay: using multicast for overlay {overlay_id} \
                    (tcp={allow_tcp_communication}, quic={use_quic})"
                );
            } else {
                log::debug!(
                    target: LOG_TARGET,
                    "AdnlOverlay: using UDP only for overlay {overlay_id} \
                    (allow_tcp_communication={allow_tcp_communication})"
                );
            }

            // Initialize TaskProcessorManager with overlay_short_id as name
            let overlay_name = format!("overlay_{}", overlay_id);
            let all_node_ids: Vec<PublicKeyHash> =
                nodes.iter().map(|node| node.adnl_id.clone()).collect();
            let task_processor_manager = TaskProcessorManager::new(
                overlay_name,
                &all_node_ids,
                AdnlOverlayStreamTag::count(),
                runtime_handle.clone(),
            );

            // Build ADNL key → validator key mapping for two-step broadcast receive
            let adnl_to_validator: HashMap<PublicKeyHash, PublicKeyHash> = nodes
                .iter()
                .map(|node| {
                    (
                        node.adnl_id.clone(),
                        if node.public_key.pq_key().is_some() {
                            node.adnl_id.clone()
                        } else {
                            node.public_key.id().clone()
                        },
                    )
                })
                .collect();

            AdnlOverlay {
                lower_generation,
                lower_block_sync_generation,
                tasks: AsyncOwner::new(runtime_handle.clone()),
                shutdown: AsyncOwner::new(runtime_handle.clone()),
                shutdown_started: Mutex::new(false),
                shutdown_errors: Arc::new(Mutex::new(Vec::new())),
                cleanup_complete: Arc::new(AtomicBool::new(false)),
                stack,
                overlay_id: overlay_id.clone(),
                local_id,
                private_runtime: private_runtime.clone(),
                local_validator_key,
                local_adnl_key: local_adnl_key.clone(),
                adnl_to_validator,
                listener: listener.clone(),
                stop_requested: stop_requested.clone(),
                consumer,
                runtime_handle: runtime_handle.clone(),
                peers: Mutex::new(peer_objects),
                peers_storage: peer_storage.clone(),
                is_tcp_available: is_tcp_available,
                is_quic_available: quic_enabled,
                all_node_ids: all_node_ids,
                task_processor_manager: Arc::new(task_processor_manager),
                block_sync_overlay_id: block_sync_overlay_id_for_cyclic.clone(),
                block_sync_consumer,
                block_sync_authorized,
                block_sync_stats: block_sync_stats_for_cyclic.clone(),
            }
        });

        registration.ids.clear(); // The constructed overlay now owns teardown.

        // Add consumer to overlay node for message handling
        if !overlay
            .stack
            .overlay
            .add_consumer_for_generation(&overlay.lower_generation, overlay.consumer.clone())?
        {
            fail!("Consensus consumer was already registered");
        }

        if let (Some(bs_id), Some(bs_consumer)) =
            (&overlay.block_sync_overlay_id, &overlay.block_sync_consumer)
        {
            let generation = overlay
                .lower_block_sync_generation
                .as_ref()
                .ok_or_else(|| error!("Missing block-sync generation"))?;
            if !overlay
                .stack
                .overlay
                .add_consumer_for_generation(generation, bs_consumer.clone())?
            {
                fail!("Block-sync consumer was already registered");
            }
        }

        // Periodic stats dump (lives as long as the overlay's stop flag is unset)
        if let Some(stats) = &overlay.block_sync_stats {
            let stats = stats.clone();
            overlay.tasks.background("block sync metrics", async move {
                let mut ticker = tokio::time::interval(crate::BLOCK_SYNC_STATS_LOG_INTERVAL);
                loop {
                    ticker.tick().await;
                    stats.dump();
                }
            });
        }

        log::debug!(
            target: LOG_TARGET,
            "Successfully initialized AdnlOverlay: overlay_id={overlay_id}"
        );

        Ok(overlay)
    }

    fn begin_stop(&self) {
        let mut started = self.shutdown_started.lock().unwrap();
        if *started {
            return;
        }
        *started = true;
        self.stop_requested.store(true, Ordering::Release);
        self.tasks.close();
        self.task_processor_manager.stop_async();
        let tasks = self.tasks.clone();
        let manager = self.task_processor_manager.clone();
        let peers = std::mem::take(&mut *self.peers.lock().unwrap());
        let storage = self.peers_storage.clone();
        let overlay = self.stack.overlay.clone();
        let generation = self.lower_generation.clone();
        let block_sync = self.lower_block_sync_generation.clone();
        let errors = self.shutdown_errors.clone();
        let cleanup_complete = self.cleanup_complete.clone();
        let runtime = self.runtime_handle.clone();
        self.shutdown.spawn("overlay resource finalizer", async move {
            if let Err(error) = tasks.wait().await {
                errors.lock().unwrap().push(error.to_string());
            }
            let errors_for_blocking = errors.clone();
            let result = runtime
                .spawn_blocking(move || {
                    if let Err(error) = manager.stop_checked() {
                        errors_for_blocking.lock().unwrap().push(error.to_string());
                    }
                    let (drained, peer_result) = storage.remove_peers(peers);
                    if let Err(error) = peer_result {
                        errors_for_blocking.lock().unwrap().push(error.to_string());
                    }
                    drained
                })
                .await;
            let peers_drained = match result {
                Ok(drained) => drained,
                Err(error) => {
                    errors.lock().unwrap().push(error.to_string());
                    false
                }
            };
            if let Err(error) = overlay.delete_private_overlay_checked(&generation).await {
                errors.lock().unwrap().push(error.to_string());
            }
            let mut network_drained = generation.drained();
            if let Some(generation) = block_sync {
                if let Err(error) = overlay.delete_private_overlay_checked(&generation).await {
                    errors.lock().unwrap().push(error.to_string());
                }
                network_drained &= generation.drained();
            }
            cleanup_complete.store(peers_drained && network_drained, Ordering::Release);
        });
        self.shutdown.close();
    }

    fn stop_checked(&self) -> Result<()> {
        self.begin_stop();
        self.shutdown.wait_sync()?;
        let errors = self.shutdown_errors.lock().unwrap();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(error!("{}", errors.join("; ")))
        }
    }

    pub fn stop(&self) {
        if let Err(error) = self.stop_checked() {
            log::error!("Overlay shutdown: {error}");
        }
    }

    fn drained(&self) -> bool {
        self.cleanup_complete.load(Ordering::Acquire)
            && self.shutdown.drained()
            && self.tasks.drained()
            && self.task_processor_manager.drained()
    }

    /// Process incoming query from consumer
    pub async fn process_query(&self, query: TLObject, peers: &AdnlPeers) -> Result<QueryResult> {
        log::trace!(
            target: LOG_TARGET,
            "AdnlOverlay::process_query: overlay_id={}",
            self.overlay_id
        );

        let now = Instant::now();
        let profile = self.stack.overlay.wire_profile();
        let data = profile.serialize(&query).map_err(|e| {
            log::warn!(target: LOG_TARGET, "AdnlOverlay: query is bad: {:?}", e);
            e
        })?;

        let listener = self.listener.clone();
        let peer = peers.other().clone();
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let admitted = self.tasks.background("incoming query response", async move {
            let result = async move {
                let listener =
                    listener.upgrade().ok_or_else(|| error!("Overlay listener stopped"))?;
                let (answer_tx, answer_rx) = tokio::sync::oneshot::channel();
                listener.on_query(
                    peer,
                    &crate::ConsensusCommonFactory::create_block_payload(data),
                    Box::new(move |result| {
                        let _ = answer_tx.send(result);
                    }),
                );
                // The listener owns accepted consensus work. This overlay owns
                // only response delivery; cancelling it does not cancel that work.
                let payload = answer_rx.await.map_err(|_| error!("Query callback dropped"))??;
                let answer = profile.deserialize(payload.data())?;
                metrics::histogram!("rtos_node_network_consensus_overlay_query_seconds")
                    .record(now.elapsed());
                Ok(TimedAnswer {
                    answer: Some(Answer::Object(answer.into())),
                    #[cfg(feature = "telemetry")]
                    actual_start_at: None,
                })
            }
            .await;
            let _ = result_tx.send(result);
        });
        if !admitted {
            fail!("Overlay query admission closed");
        }
        // Protocol API requires a JoinHandle. This proxy owns only the result receiver;
        // the actual accepted operation remains owned above if the caller drops it.
        let handle = self.runtime_handle.spawn(async move {
            result_rx.await.map_err(|_| error!("Owned query worker failed"))?
        });
        Ok(QueryResult::Consumed(QueryAnswer::Pending(handle)))
    }

    /// Process incoming broadcast data - deliver directly to listener.
    /// Called from BroadcastWrapper (catchain-style) on the consensus overlay
    fn validate_and_process_broadcast(self: Arc<Self>, recv_from: PublicKeyHash, data: &[u8]) {
        let payload = crate::ConsensusCommonFactory::create_block_payload(data.to_vec());
        self.process_broadcast(recv_from, payload, crate::BroadcastSource::ConsensusOverlay);
    }

    /// Process incoming broadcast; translate `recv_from` (ADNL or validator key hash)
    /// to validator key hash when possible. `source` tells the listener which
    /// overlay the broadcast arrived on
    fn process_broadcast(
        self: Arc<Self>,
        recv_from: PublicKeyHash,
        data: BlockPayloadPtr,
        source_overlay: crate::BroadcastSource,
    ) {
        let source =
            self.adnl_to_validator.get(&recv_from).cloned().unwrap_or_else(|| recv_from.clone());
        log::trace!(
            target: LOG_TARGET,
            "AdnlOverlay: {source_overlay:?} broadcast received (recv_from={recv_from}, source={source})"
        );
        if let Some(listener) = self.listener.upgrade() {
            listener.on_broadcast(source, &data, source_overlay);
        }
    }

    /// Process incoming direct message (e.g., simplex votes)
    fn process_message(&self, recv_from: PublicKeyHash, data: BlockPayloadPtr) {
        log::trace!(target: LOG_TARGET, "AdnlOverlay: direct message received from {}", recv_from);
        if let Some(listener) = self.listener.upgrade() {
            listener.on_message(recv_from, &data);
        }
    }

    /// Start broadcast listeners (similar to CatchainClient::run_wait_broadcast)
    /// Drain inbound broadcasts on the block-sync overlay (no-op when not configured)
    pub fn run_wait_block_sync_broadcast(self: Arc<Self>) {
        let Some(bs_id) = self.block_sync_overlay_id.clone() else {
            return;
        };
        log::trace!(
            target: LOG_TARGET,
            "BlockSync: starting block-sync broadcast listener for overlay_id={bs_id}"
        );
        let overlay_weak = Arc::downgrade(&self);
        let overlay_node = self.stack.overlay.clone();
        let stop_requested = self.stop_requested.clone();
        self.tasks.background("overlay listener or send", async move {
            loop {
                if stop_requested.load(Ordering::Relaxed) {
                    log::trace!(
                        target: LOG_TARGET,
                        "BlockSync: block-sync broadcast listener stopping for overlay_id={bs_id}"
                    );
                    break;
                }
                match overlay_node.wait_for_broadcast(&bs_id).await {
                    Ok(Some(message)) => {
                        log::trace!(
                            target: LOG_TARGET,
                            "BlockSync: block-sync broadcast received \
                             data_len={} recv_from={} overlay={bs_id}",
                            message.data.len(), message.recv_from,
                        );
                        if let Some(overlay) = overlay_weak.upgrade() {
                            // Drop self-broadcasts and senders not in the current-set
                            // authorized_keys (C++ `block-sync-overlay.cpp:120-123`)
                            if message.recv_from == *overlay.local_adnl_key.id() {
                                log::trace!(
                                    target: LOG_TARGET,
                                    "BlockSync: block-sync self-broadcast dropped (recv_from=local)"
                                );
                                continue;
                            }
                            if !overlay.block_sync_authorized.contains(&message.recv_from) {
                                if let Some(stats) = &overlay.block_sync_stats {
                                    stats.bump_auth_drop();
                                }
                                log::warn!(
                                    target: LOG_TARGET,
                                    "BlockSync: block-sync broadcast from non-validator {} dropped \
                                     (not in current-set authorized_keys)",
                                    message.recv_from
                                );
                                continue;
                            }
                            if let Some(stats) = &overlay.block_sync_stats {
                                stats.bump_recv();
                            }
                            let payload =
                                crate::ConsensusCommonFactory::create_block_payload(message.data);
                            overlay.process_broadcast(
                                message.recv_from,
                                payload,
                                crate::BroadcastSource::BlockSyncOverlay,
                            );
                        }
                    }
                    Ok(None) => {
                        log::trace!(
                            target: LOG_TARGET,
                            "BlockSync: block-sync broadcast listener finished for overlay_id={bs_id}"
                        );
                        break;
                    }
                    Err(e) => {
                        log::error!(
                            target: LOG_TARGET,
                            "BlockSync: block-sync overlay broadcast error: {e}"
                        );
                    }
                }
            }
        });
    }

    pub fn run_wait_broadcast(self: Arc<Self>) {
        log::trace!(
            target: LOG_TARGET,
            "Starting broadcast listeners for overlay_id={}",
            self.overlay_id
        );

        let overlay_id = self.overlay_id.clone();
        let overlay = Arc::downgrade(&self);
        let overlay_node = self.stack.overlay.clone();
        let stop_requested1 = self.stop_requested.clone();
        let stop_requested2 = self.stop_requested.clone();

        // Spawn task for regular broadcasts
        self.tasks.background("overlay listener or send", async move {
            log::trace!(
                target: LOG_TARGET,
                "AdnlOverlay::wait_broadcasts started for overlay_id={overlay_id}"
            );

            let receiver = overlay_node.clone();

            loop {
                if stop_requested1.load(Ordering::Relaxed) {
                    log::trace!(
                        target: LOG_TARGET,
                        "AdnlOverlay::wait_broadcasts stopping for overlay_id={overlay_id}"
                    );
                    break;
                }

                let message = receiver.wait_for_broadcast(&overlay_id).await;
                match message {
                    Ok(Some(message)) => {
                        log::trace!(
                            target: LOG_TARGET,
                            "AdnlOverlay::wait_broadcasts: received broadcast \
                            data_len={} recv_from={} overlay={overlay_id}",
                            message.data.len(),
                            message.recv_from
                        );
                        if let Some(overlay) = overlay.upgrade() {
                            let payload =
                                crate::ConsensusCommonFactory::create_block_payload(message.data);
                            overlay.process_broadcast(
                                message.recv_from,
                                payload,
                                crate::BroadcastSource::ConsensusOverlay,
                            );
                        }
                    }
                    Ok(None) => {
                        log::trace!(
                            target: LOG_TARGET,
                            "AdnlOverlay::wait_broadcasts finished for overlay_id={overlay_id}"
                        );
                        break;
                    }
                    Err(e) => {
                        log::error!(
                            target: LOG_TARGET,
                            "AdnlOverlay: private overlay broadcast error: {e}"
                        );
                    }
                }
            }
        });

        let overlay_id = self.overlay_id.clone();
        let overlay_node = self.stack.overlay.clone();
        let listener = self.listener.clone();

        // Spawn task for consensus broadcasts
        self.tasks.background("overlay listener or send", async move {
            log::trace!(
                target: LOG_TARGET,
                "AdnlOverlay::wait_consensus_broadcast started for overlay_id={overlay_id}"
            );

            let receiver = overlay_node.clone();
            let consensus_listener = listener.clone();

            loop {
                if stop_requested2.load(Ordering::Relaxed) {
                    log::trace!(
                        target: LOG_TARGET,
                        "AdnlOverlay::wait_consensus_broadcast stopping for overlay_id={overlay_id}"
                    );
                    break;
                }

                let message = receiver.wait_for_catchain(&overlay_id).await;
                match message {
                Ok(Some((catchain_block_update, inner_update, source_id))) => {
                    log::trace!(
                        target: LOG_TARGET,
                        "AdnlOverlay: catchain broadcast ValidatorSession_BlockUpdate received"
                    );
                    if let Some(listener) = consensus_listener.upgrade() {
                        // Serialize catchain block update and inner update similar to reference
                        let mut data: crate::RawBuffer = crate::RawBuffer::default();
                        let mut serializer = Serializer::new(&mut data);

                        match serializer.write_boxed(&catchain_block_update.into_boxed()) {
                            Ok(_) => {
                                match inner_update {
                                    CatchainData::Catchain(upd) => {
                                        if let Err(e) = serializer.write_boxed(&upd.into_boxed()) {
                                            log::error!(
                                                target: LOG_TARGET,
                                                "AdnlOverlay: Failed to serialize catchain update: {e}"
                                            );
                                            continue;
                                        }
                                    }
                                    CatchainData::ValidatorSession(upd) => {
                                        if let Err(e) = serializer.write_boxed(&upd.into_boxed()) {
                                            log::error!(
                                                target: LOG_TARGET,
                                                "AdnlOverlay: Failed to serialize validator session update: {e}"
                                            );
                                            continue;
                                        }
                                    }
                                }

                                let data = crate::ConsensusCommonFactory::create_block_payload(data);
                                log::trace!(
                                    target: LOG_TARGET,
                                    "AdnlOverlay: routing consensus broadcast to listener via on_message"
                                );
                                listener.on_message(source_id, &data);
                            }
                            Err(e) => {
                                log::error!(
                                    target: LOG_TARGET,
                                    "AdnlOverlay: Failed to serialize catchain block update: {e}"
                                );
                            }
                        }
                    }
                }
                    Ok(None) => {
                        log::trace!(
                            target: LOG_TARGET,
                            "AdnlOverlay::wait_consensus_broadcast finished for overlay_id={overlay_id}"
                        );
                        break;
                    }
                    Err(e) => {
                        log::error!(
                            target: LOG_TARGET,
                            "AdnlOverlay: consensus broadcast error: {e}"
                        );
                    }
                }
            }
        });
    }
}

impl Drop for AdnlOverlay {
    fn drop(&mut self) {
        self.begin_stop();
    }
}

impl ConsensusOverlay for AdnlOverlay {
    /// Get implementation-specific object
    fn get_impl(&self) -> &dyn Any {
        self
    }

    /// Send direct message to specific receiver
    fn send_message(
        &self,
        receiver_id: &PublicKeyHash,
        sender_id: &PublicKeyHash,
        message: &BlockPayloadPtr,
        is_retransmission: bool,
    ) {
        // Delegate to multicast with single receiver
        self.send_message_multicast(&[receiver_id.clone()], sender_id, message, is_retransmission);
    }

    /// Send message to multiple receivers (multicast)
    fn send_message_multicast(
        &self,
        receiver_ids: &[PublicKeyHash],
        sender_id: &PublicKeyHash,
        message: &BlockPayloadPtr,
        _is_retransmission: bool,
    ) {
        if self.stop_requested.load(Ordering::Relaxed) {
            log::warn!(
                target: LOG_TARGET,
                "AdnlOverlay: Overlay {} was stopped!",
                &self.overlay_id
            );
            return;
        }

        log::trace!(
            target: LOG_TARGET,
            "AdnlOverlay::send_message_multicast (overlay: {}, from: {}, to: [{:#?}])",
            &self.overlay_id,
            &sender_id,
            &receiver_ids,
        );

        // Send message to each receiver through TaskProcessorManager
        for receiver_id in receiver_ids {
            let overlay_node = self.stack.overlay.clone();
            let overlay_id = self.overlay_id.clone();
            let msg = message.clone();
            let receiver = receiver_id.clone();
            let sender_id = sender_id.clone();
            let is_quic = self.is_quic_available;

            // Post async closure to task processor for this receiver with OutgoingMessages tag
            self.task_processor_manager.post_closure(
                receiver_id,
                AdnlOverlayStreamTag::OutgoingMessages.into(),
                move || {
                    Box::pin(async move {
                        // Execute async message sending directly in task processor loop
                        // Extract message data and calculate tag from first 4 bytes (little-endian)
                        let buf = &msg.data();
                        let msg_tagged = TaggedByteSlice {
                            #[cfg(feature = "telemetry")]
                            tag: 0x80000001, // Catchain one-way messages
                            object: &buf[..],
                        };

                        // Execute async message sending — via QUIC if available, else ADNL
                        let result = if is_quic {
                            overlay_node.message_via_quic(&receiver, &msg_tagged, &overlay_id).await
                        } else {
                            overlay_node.message(&receiver, &msg_tagged, &overlay_id).await
                        };

                        if let Err(e) = result {
                            let tag = if buf.len() >= 4 {
                                u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
                            } else {
                                0
                            };

                            log::warn!(
                                target: LOG_TARGET,
                                "AdnlOverlay: Failed to send message with tag {tag:08x} \
                                from {sender_id} to {receiver}: {e}"
                            );
                        }
                    })
                },
            );
        }
    }

    /// Send query with response callback
    fn send_query(
        &self,
        receiver_id: &PublicKeyHash,
        _sender_id: &PublicKeyHash,
        _name: &str,
        timeout: Duration,
        message: &BlockPayloadPtr,
        response_callback: QueryResponseCallback,
    ) {
        let receiver = receiver_id.clone();
        let msg = message.clone();
        let overlay_id = self.overlay_id.clone();
        let overlay_node = self.stack.overlay.clone();
        let stop_requested = self.stop_requested.clone();
        let is_quic = self.is_quic_available;

        if stop_requested.load(Ordering::Relaxed) {
            log::warn!(target: LOG_TARGET, "AdnlOverlay: Overlay {} was stopped!", &overlay_id);
            return;
        }

        self.tasks.background("overlay listener or send", async move {
            if stop_requested.load(Ordering::Relaxed) {
                log::warn!(target: LOG_TARGET, "AdnlOverlay: Overlay {} was stopped!", &overlay_id);
                return;
            }

            // Execute query with timeout and handle result
            let result = async {
                let query: TaggedTlObject =
                    overlay_node.wire_profile().deserialize(msg.data())?.into();
                let timeout_ms = Some(AdnlNode::calc_timeout(Some(timeout.as_millis() as u64)));
                let now = Instant::now();

                let result = if is_quic {
                    overlay_node.query_via_quic(&receiver, &query, &overlay_id, timeout_ms).await?
                } else {
                    overlay_node.query(&receiver, &query, &overlay_id, timeout_ms).await?
                };

                let elapsed = now.elapsed();
                log::trace!(
                    target: LOG_TARGET,
                    "AdnlOverlay::send_query result (overlay: {}, key_id: {}): {:?} ({}ms)",
                    overlay_id,
                    receiver,
                    result,
                    elapsed.as_millis()
                );

                metrics::histogram!("rtos_node_network_consensus_overlay_query_seconds")
                    .record(elapsed);

                let result = result.ok_or_else(|| error!("answer is None!"))?;
                let data = overlay_node.wire_profile().serialize(&result)?;
                normalize_query_response_payload(data)
            }
            .await;

            // Only call callback if overlay is not stopped
            if !stop_requested.load(Ordering::Relaxed) {
                response_callback(result);
            } else {
                log::trace!(
                    target: LOG_TARGET,
                    "AdnlOverlay: Skipping query callback - overlay stopped"
                );
            }
        });
    }

    /// Send query via RLDP for large messages.
    /// On QUIC-enabled overlays (simplex+quic) the query is routed through QUIC
    /// bi-directional streams instead, since QUIC handles flow control natively
    /// and doesn't need `max_answer_size`.
    fn send_query_via_rldp(
        &self,
        dst_adnl_id: PublicKeyHash,
        _name: String,
        response_callback: QueryResponseCallback,
        _timeout: std::time::SystemTime,
        query: BlockPayloadPtr,
        max_answer_size: u64,
        v2: bool,
    ) {
        let overlay_id = self.overlay_id.clone();
        let overlay_node = self.stack.overlay.clone();
        let stop_requested = self.stop_requested.clone();
        let is_quic = self.is_quic_available;

        if stop_requested.load(Ordering::Relaxed) {
            log::warn!(target: LOG_TARGET, "AdnlOverlay: Overlay {} was stopped!", &overlay_id);
            return;
        }

        self.tasks.background("overlay RLDP query", async move {
            if stop_requested.load(Ordering::Relaxed) {
                log::warn!(target: LOG_TARGET, "AdnlOverlay: Overlay {} was stopped!", &overlay_id);
                return;
            }

            let result = async {
                let query_body = overlay_node.wire_profile().deserialize(query.data())?;

                if is_quic {
                    // QUIC path: use bi-directional stream query (no max_answer_size needed)
                    let tagged: TaggedTlObject = query_body.into();
                    let result = overlay_node
                        .query_via_quic(&dst_adnl_id, &tagged, &overlay_id, None)
                        .await?;
                    let result = result.ok_or_else(|| error!("QUIC query answer is None!"))?;
                    let data = overlay_node.wire_profile().serialize(&result)?;
                    normalize_query_response_payload(data)
                } else {
                    // RLDP path: traditional large-message query
                    let mut query_data = overlay_node.get_query_prefix(&overlay_id)?;
                    overlay_node.wire_profile().serialize_append(&mut query_data, &query_body)?;

                    let (data, _) = overlay_node
                        .query_via_rldp(
                            &dst_adnl_id,
                            &TaggedByteSlice {
                                object: &query_data[..],
                                #[cfg(feature = "telemetry")]
                                tag: query_body.bare_object().constructor(),
                            },
                            &overlay_id,
                            Some(max_answer_size),
                            v2,
                            None,
                        )
                        .await?;
                    let data = data.ok_or_else(|| error!("answer is None!"))?;
                    normalize_query_response_payload(data)
                }
            }
            .await;

            log::info!(target: LOG_TARGET, "AdnlOverlay::send_query_via_rldp: {:?}", result);

            // Only call callback if overlay is not stopped
            if !stop_requested.load(Ordering::Relaxed) {
                response_callback(result);
            } else {
                log::trace!(
                    target: LOG_TARGET,
                    "AdnlOverlay: Skipping RLDP query callback - overlay stopped"
                );
            }
        });
    }

    /// Send broadcast with FEC (Forward Error Correction)
    fn send_broadcast_fec_ex(
        &self,
        sender_id: &PublicKeyHash,
        _send_as: &PublicKeyHash,
        payload: BlockPayloadPtr,
        extra: Option<Vec<u8>>,
    ) {
        // Only candidate broadcasts (with `extra`) go through block-sync overlay.
        let use_block_sync = extra.is_some() && self.block_sync_overlay_id.is_some();
        let overlay_id = if use_block_sync {
            self.block_sync_overlay_id.clone().unwrap()
        } else {
            self.overlay_id.clone()
        };
        let stop_requested = self.stop_requested.clone();

        if stop_requested.load(Ordering::Relaxed) {
            log::warn!(target: LOG_TARGET, "AdnlOverlay: Overlay {overlay_id} was stopped!");
            return;
        }

        if self.is_quic_available || !self.is_tcp_available || use_block_sync {
            // QUIC or ADNL/UDP path
            let msg = payload.clone();
            let overlay_node = self.stack.overlay.clone();
            // block-sync signs by ADNL pubkey (block-sync-overlay.cpp:43,78);
            // consensus private overlay signs by validator pubkey (private-overlay.cpp:51,126).
            let src_key = if use_block_sync {
                self.local_adnl_key.clone()
            } else {
                self.local_validator_key.clone()
            };
            let transport = if self.is_quic_available { "QUIC" } else { "ADNL/UDP" };
            let stats = if use_block_sync { self.block_sync_stats.clone() } else { None };
            if let Some(stats) = &stats {
                stats.bump_sent();
            }

            self.tasks.background("overlay listener or send", async move {
                if stop_requested.load(Ordering::Relaxed) {
                    log::warn!(
                        target: LOG_TARGET,
                        "AdnlOverlay: Overlay {overlay_id} was stopped!"
                    );
                    return;
                }

                let msg_tagged = TaggedByteSlice {
                    object: msg.data(),
                    #[cfg(feature = "telemetry")]
                    tag: 0x80000002, // Consensus broadcast
                };

                let result = if let Some(extra) = extra {
                    // Twostep broadcast with extra
                    overlay_node
                        .broadcast_twostep(&overlay_id, &msg_tagged, Some(&src_key), 0, extra)
                        .await
                } else {
                    // Canonic broadcast
                    overlay_node
                        .broadcast(
                            &overlay_id,
                            &msg_tagged,
                            Some(&src_key),
                            0,
                            AdnlSendMethod::Fast,
                        )
                        .await
                };

                match &result {
                    Ok(info) if info.send_to == 0 => {
                        if let Some(stats) = &stats {
                            stats.bump_send_err();
                        }
                        log::warn!(
                            target: LOG_TARGET,
                            "AdnlOverlay::send_broadcast_fec_ex ({transport}) \
                            overlay={overlay_id}: send_to=0 packets={} — \
                            broadcast emitted to 0 neighbours (overlay known_peers empty?)",
                            info.packets,
                        );
                    }
                    Ok(info) => log::debug!(
                        target: LOG_TARGET,
                        "AdnlOverlay::send_broadcast_fec_ex ({transport}) \
                        overlay={overlay_id} packets={} send_to={}",
                        info.packets, info.send_to,
                    ),
                    Err(e) => {
                        if let Some(stats) = &stats {
                            stats.bump_send_err();
                        }
                        log::warn!(
                            target: LOG_TARGET,
                            "AdnlOverlay::send_broadcast_fec_ex ({transport}) \
                            overlay={overlay_id} FAILED: {e:?}"
                        );
                    }
                }
            });
        } else {
            // TCP path: manually build BroadcastTwostepSimple and multicast
            const IS_RETRANSMISSION: bool = false;

            log::trace!(
                target: LOG_TARGET,
                "AdnlOverlay::send_broadcast_fec_ex: is_tcp_available=true, \
                sending BroadcastTwostepSimple (payload_len={}) to {} peers",
                payload.data().len(), self.all_node_ids.len(),
            );

            let result = (|| -> Result<()> {
                let data = payload.data().to_vec();
                let extra = extra.unwrap_or_default();
                let date = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i32;
                let flags: i32 = 0;

                let data_hash = sha256_digest(&data);
                let bcast_id = {
                    let id = BroadcastTwostepId {
                        date,
                        flags,
                        src: UInt256::from_slice(self.local_adnl_key.id().data()),
                        src_adnl_id: UInt256::from_slice(self.local_adnl_key.id().data()),
                        data_hash: UInt256::with_array(data_hash),
                        // Broadcast simulation over TCP, no partitioning
                        data_size: data.len() as i32,
                        part_size: data.len() as i32,
                        extra: extra.clone(),
                    };
                    let id_bytes = serialize_bare(&id)?;
                    sha256_digest(&id_bytes)
                };

                let to_sign = BroadcastTwostepSimpleToSign {
                    id: UInt256::with_array(bcast_id),
                    data: data.clone(),
                };
                let to_sign_bytes = serialize_bare(&to_sign)?;
                let signature = self.local_adnl_key.sign(&to_sign_bytes)?;

                // Build BroadcastTwostepSimple TL
                let bcast = BroadcastTwostepSimple {
                    date,
                    flags,
                    src: (&self.local_adnl_key).try_into()?,
                    src_adnl_id: UInt256::from_slice(self.local_adnl_key.id().data()),
                    certificate: OverlayCertificate::Overlay_EmptyCertificate,
                    data,
                    extra,
                    signature,
                }
                .into_boxed();

                // Serialize as overlay Broadcast (same format the overlay layer
                // expects on the receive side in try_consume_custom)
                let serialized = serialize_boxed(&bcast)?;
                let broadcast_payload =
                    crate::ConsensusCommonFactory::create_block_payload(serialized);

                log::trace!(
                    target: LOG_TARGET,
                    "AdnlOverlay::send_broadcast_fec_ex: sending BroadcastTwostepSimple \
                    ({} bytes payload) via TCP multicast to {} peers",
                    broadcast_payload.data().len(),
                    self.all_node_ids.len(),
                );

                self.send_message_multicast(
                    &self.all_node_ids,
                    sender_id,
                    &broadcast_payload,
                    IS_RETRANSMISSION,
                );
                Ok(())
            })();

            if let Err(err) = result {
                log::error!(
                    target: LOG_TARGET,
                    "AdnlOverlay::send_broadcast_fec_ex: failed to build/send TCP broadcast: {err}"
                );
            }
        }
    }
}

/*
    ADNL-based overlay manager implementation
*/

pub struct AdnlOverlayManager {
    lifecycle: Mutex<()>,
    runtime_handle: tokio::runtime::Handle, //runtime handle for spawning tasks
    stack: Arc<NetworkStack>,               // ADNL network stack
    overlays: Arc<spin::Mutex<HashMap<Arc<PrivateOverlayShortId>, Arc<AdnlOverlay>>>>, //active overlays managed by this manager
    broadcast_hops: Option<u8>, //default broadcast hops from network context
    track_private_peers: bool,  //flag to track and manage private peers
    peers_storage: Arc<PeerStorage>, //peer storage with ref counting for all overlays
}

impl AdnlOverlayManager {
    /// Create new overlay manager
    pub fn create(
        runtime_handle: tokio::runtime::Handle,
        stack: Arc<NetworkStack>,
        broadcast_hops: Option<u8>,
        track_private_peers: bool,
    ) -> Result<ConsensusOverlayManagerPtr> {
        log::trace!(
            target: LOG_TARGET,
            "Creating AdnlOverlayManager (broadcast_hops={:?}, track_private_peers={})",
            broadcast_hops,
            track_private_peers
        );

        Ok(Arc::new(Self {
            lifecycle: Mutex::new(()),
            runtime_handle,
            stack,
            overlays: Arc::new(spin::Mutex::new(HashMap::new())),
            broadcast_hops,
            track_private_peers,
            peers_storage: Arc::new(PeerStorage::new()),
        }))
    }
}

impl Drop for AdnlOverlayManager {
    fn drop(&mut self) {
        let overlay_count = self.overlays.lock().len();
        log::debug!(
            target: LOG_TARGET,
            "Dropping AdnlOverlayManager ({} active overlays)",
            overlay_count
        );
    }
}

impl ConsensusOverlayManager for AdnlOverlayManager {
    fn wire_profile(&self) -> rtos_api::WireProfile {
        self.stack.overlay.wire_profile()
    }

    /// Start new consensus overlay with given parameters
    fn start_overlay(
        &self,
        local_validator_key: &PrivateKey,
        overlay_short_id: &Arc<PrivateOverlayShortId>,
        nodes: &[ConsensusNode],
        overlay_listener: ConsensusOverlayListenerPtr,
        _log_replay_listener: ConsensusOverlayLogReplayListenerPtr,
        transport_type: OverlayTransportType,
        block_sync_params: Option<crate::BlockSyncOverlayParams>,
    ) -> Result<ConsensusOverlayPtr> {
        let _lifecycle = self.lifecycle.lock().unwrap();
        // Searching for existing overlay
        if let Some(existing) = self.overlays.lock().get(overlay_short_id) {
            return Ok(existing.clone());
        }

        let local_id = local_validator_key.id();

        log::trace!(
            target: LOG_TARGET,
            "Starting overlay: overlay_id={}, local_id={}, nodes_count={}, transport={:?}",
            overlay_short_id,
            local_id,
            nodes.len(),
            transport_type,
        );

        // Create new overlay instance with improved initialization
        let overlay = AdnlOverlay::new(
            self.runtime_handle.clone(),
            self.stack.clone(),
            overlay_short_id.clone(),
            local_validator_key.clone(),
            overlay_listener,
            nodes,
            self.broadcast_hops, // Use broadcast_hops from manager configuration
            self.track_private_peers,
            self.peers_storage.clone(),
            transport_type,
            block_sync_params,
        )?;

        // Atomic overlay addition under lock
        let overlay = {
            let mut overlays = self.overlays.lock();

            // Check if overlay already exists under lock
            if let Some(existing) = overlays.get(overlay_short_id) {
                return Ok(existing.clone());
            }

            // Add to managed overlays atomically
            overlays.insert(overlay_short_id.clone(), overlay.clone());

            log::trace!(
                target: LOG_TARGET,
                "Successfully started overlay: overlay_id={overlay_short_id}"
            );

            overlay
        };

        // Start broadcast listeners (consensus and, if present, block-sync)
        overlay.clone().run_wait_broadcast();
        if overlay.block_sync_overlay_id.is_some() {
            overlay.clone().run_wait_block_sync_broadcast();
        }

        Ok(overlay)
    }

    fn start_authenticated_overlay(
        &self,
        key: &PrivateKey,
        id: &Arc<PrivateOverlayShortId>,
        runtime: Arc<crate::session_runtime::AuthenticatedSessionRuntime>,
        listener: ConsensusOverlayListenerPtr,
        _replay: ConsensusOverlayLogReplayListenerPtr,
        transport: OverlayTransportType,
    ) -> Result<ConsensusOverlayPtr> {
        let _lifecycle = self.lifecycle.lock().unwrap();
        if key.id() != runtime.local_adnl()
            || id != &runtime.overlay_short_id()?
            || runtime.wire_profile() != self.stack.overlay.wire_profile()
        {
            fail!("Authenticated overlay key, ID or wire profile mismatch");
        }
        if let Some(existing) = self.overlays.lock().get(id) {
            let same =
                existing.private_runtime.as_ref().is_some_and(|old| old.same_admission(&runtime));
            if !same {
                fail!("Existing overlay belongs to a different runtime");
            }
            return Ok(existing.clone());
        }
        let nodes = runtime.consensus_nodes()?;
        let overlay = AdnlOverlay::new_with_runtime(
            self.runtime_handle.clone(),
            self.stack.clone(),
            id.clone(),
            key.clone(),
            listener,
            &nodes,
            self.broadcast_hops,
            self.track_private_peers,
            self.peers_storage.clone(),
            transport,
            None,
            Some(runtime),
        )?;
        self.overlays.lock().insert(id.clone(), overlay.clone());
        overlay.clone().run_wait_broadcast();
        Ok(overlay)
    }

    fn stop_overlay_checked(
        &self,
        id: &Arc<PrivateOverlayShortId>,
        overlay: &ConsensusOverlayPtr,
    ) -> Result<()> {
        let _lifecycle = self.lifecycle.lock().unwrap();
        let implementation = overlay
            .get_impl()
            .downcast_ref::<AdnlOverlay>()
            .ok_or_else(|| error!("Unknown overlay implementation"))?;
        let result = implementation.stop_checked();
        if implementation.drained() {
            let mut overlays = self.overlays.lock();
            if overlays
                .get(id)
                .is_some_and(|current| std::ptr::eq(Arc::as_ptr(current), implementation))
            {
                overlays.remove(id);
            }
        }
        result
    }

    fn overlay_drained(&self, overlay: &ConsensusOverlayPtr) -> bool {
        overlay.get_impl().downcast_ref::<AdnlOverlay>().is_some_and(AdnlOverlay::drained)
    }

    /// Stop existing consensus overlay
    fn stop_overlay(
        &self,
        overlay_short_id: &Arc<PrivateOverlayShortId>,
        overlay: &ConsensusOverlayPtr,
    ) {
        if let Err(error) = self.stop_overlay_checked(overlay_short_id, overlay) {
            log::error!("Overlay stop: {error}");
        }
    }
}

#[cfg(test)]
#[path = "tests/test_adnl_overlay.rs"]
mod tests;

#[cfg(test)]
mod blocksync_check_tests {
    //! Tests for the recv side (`on_recv`) of `BlockSyncCheck`.
    //! Covers C++ `block-sync-overlay.cpp:135-155` `precheck_broadcast`:
    //! sender in current set, broadcastExtra parses, sender == expected_leader_for(slot)

    use super::*;
    use rtos_api::{ton::consensus::broadcastextra::BroadcastExtra, IntoBoxed};
    use rtos_block::KeyId;

    fn key(seed: u8) -> Arc<KeyId> {
        KeyId::from_data([seed; 32])
    }

    fn overlay_id() -> Arc<PrivateOverlayShortId> {
        KeyId::from_data([0u8; 32])
    }

    /// Build a check that only does the sender check (current_set empty
    /// disables the collator check via the defensive bypass)
    fn sender_only_check(authorized_seeds: &[u8]) -> BlockSyncCheck {
        BlockSyncCheck {
            overlay_id: overlay_id(),
            authorized: authorized_seeds.iter().map(|&s| key(s)).collect(),
            max_payload_size: u32::MAX,
            current_set: Vec::new(),
            slots_per_leader_window: 0,
            stats: None,
        }
    }

    /// Build a fully-armed check with a leader schedule
    fn schedule_check(ordered_seeds: &[u8], window: u32) -> BlockSyncCheck {
        let current_set: Vec<_> = ordered_seeds.iter().map(|&s| key(s)).collect();
        BlockSyncCheck {
            overlay_id: overlay_id(),
            authorized: current_set.iter().cloned().collect(),
            max_payload_size: u32::MAX,
            current_set,
            slots_per_leader_window: window,
            stats: None,
        }
    }

    /// Serialize a `consensus.broadcastExtra{slot}` for use as `extra` bytes
    fn extra_with_slot(slot: i32) -> Vec<u8> {
        let extra = BroadcastExtra { slot };
        rtos_api::serialize_boxed(&extra.into_boxed()).unwrap()
    }

    // === Sender-only checks (when no schedule is configured) ===

    #[test]
    fn authorized_sender_passes() {
        let cb = sender_only_check(&[1, 2, 3]);
        assert!(cb.on_recv(&key(2), Some(&extra_with_slot(0))).is_ok());
    }

    #[test]
    fn unauthorized_sender_rejected() {
        let cb = sender_only_check(&[1, 2, 3]);
        let err = cb
            .on_recv(&key(99), Some(&extra_with_slot(0)))
            .expect_err("expected unauthorized sender to be rejected");
        assert!(err.to_string().contains("not in current-set authorized_keys"));
    }

    #[test]
    fn empty_authorized_rejects_everyone() {
        let cb = sender_only_check(&[]);
        assert!(cb.on_recv(&key(1), Some(&extra_with_slot(0))).is_err());
    }

    // === Extra parse failure modes ===

    #[test]
    fn missing_extra_rejected() {
        let cb = sender_only_check(&[1]);
        let err = cb.on_recv(&key(1), None).expect_err("expected missing broadcastExtra");
        assert!(err.to_string().contains("missing broadcastExtra"));
    }

    #[test]
    fn malformed_extra_rejected() {
        let cb = sender_only_check(&[1]);
        let err = cb
            .on_recv(&key(1), Some(&[0xde, 0xad, 0xbe, 0xef]))
            .expect_err("expected malformed extra to be rejected");
        assert!(err.to_string().contains("broadcastExtra"));
    }

    #[test]
    fn negative_slot_rejected() {
        let cb = sender_only_check(&[1]);
        let err = cb
            .on_recv(&key(1), Some(&extra_with_slot(-1)))
            .expect_err("expected negative slot to be rejected");
        assert!(err.to_string().contains("negative"));
    }

    // === Collator check (with leader schedule) ===

    #[test]
    fn correct_leader_for_slot_zero_passes() {
        let cb = schedule_check(&[1, 2, 3, 4], 2);
        assert!(cb.on_recv(&key(1), Some(&extra_with_slot(0))).is_ok());
        assert!(cb.on_recv(&key(1), Some(&extra_with_slot(1))).is_ok());
        assert!(cb.on_recv(&key(2), Some(&extra_with_slot(2))).is_ok());
        assert!(cb.on_recv(&key(2), Some(&extra_with_slot(3))).is_ok());
    }

    #[test]
    fn wrong_leader_rejected() {
        let cb = schedule_check(&[1, 2, 3, 4], 2);
        let err = cb
            .on_recv(&key(2), Some(&extra_with_slot(0)))
            .expect_err("expected wrong-leader broadcast to be rejected");
        assert!(err.to_string().contains("leader-schedule mismatch"));
    }

    #[test]
    fn leader_wraps_around_modulo_n() {
        let cb = schedule_check(&[1, 2, 3], 1);
        assert!(cb.on_recv(&key(1), Some(&extra_with_slot(0))).is_ok());
        assert!(cb.on_recv(&key(1), Some(&extra_with_slot(3))).is_ok());
        assert!(cb.on_recv(&key(1), Some(&extra_with_slot(6))).is_ok());
        assert!(cb.on_recv(&key(2), Some(&extra_with_slot(3))).is_err());
    }

    #[test]
    fn unauthorized_sender_rejected_before_extra_parse() {
        let cb = schedule_check(&[1, 2, 3], 1);
        let err = cb
            .on_recv(&key(99), Some(&extra_with_slot(0)))
            .expect_err("unauthorized sender must be rejected");
        assert!(err.to_string().contains("not in current-set authorized_keys"));
    }

    // === on_send checks ===

    #[test]
    fn on_send_authorized_within_cap_passes() {
        let mut cb = sender_only_check(&[1]);
        cb.max_payload_size = 100;
        assert!(cb.on_send(&key(1), 50).is_ok());
        assert!(cb.on_send(&key(1), 100).is_ok());
    }

    #[test]
    fn on_send_unauthorized_rejected() {
        let cb = sender_only_check(&[1]);
        let err = cb.on_send(&key(99), 10).expect_err("unauthorized must be rejected");
        assert!(err.to_string().contains("not authorized"));
    }

    #[test]
    fn on_send_oversized_rejected() {
        let mut cb = sender_only_check(&[1]);
        cb.max_payload_size = 100;
        let err = cb.on_send(&key(1), 101).expect_err("oversize must be rejected");
        assert!(err.to_string().contains("exceeds authorized cap"));
    }
}
