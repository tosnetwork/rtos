// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Exercises actual Receiver callback/worker boundaries over an owned ADNL overlay.
//! Callback injection is explicit; this is not a packet-source authentication test.
use super::*;
use adnl::PrivateOverlayShortId;
use consensus_common::*;

struct CaptureManager {
    actual: ConsensusOverlayManagerPtr,
    ingress: Mutex<Option<Arc<dyn ConsensusOverlayListener + Send + Sync>>>,
    overlay: Mutex<Option<ConsensusOverlayPtr>>,
}
impl ConsensusOverlayManager for CaptureManager {
    fn wire_profile(&self) -> rtos_api::WireProfile {
        self.actual.wire_profile()
    }
    fn start_overlay(
        &self,
        _: &PrivateKey,
        _: &Arc<PrivateOverlayShortId>,
        _: &[ConsensusNode],
        _: ConsensusOverlayListenerPtr,
        _: ConsensusOverlayLogReplayListenerPtr,
        _: OverlayTransportType,
        _: Option<BlockSyncOverlayParams>,
    ) -> Result<ConsensusOverlayPtr> {
        anyhow::bail!("Authenticated test must not use legacy overlay creation")
    }
    fn start_authenticated_overlay(
        &self,
        key: &PrivateKey,
        id: &Arc<PrivateOverlayShortId>,
        runtime: Arc<consensus_common::session_runtime::AuthenticatedSessionRuntime>,
        listener: ConsensusOverlayListenerPtr,
        replay: ConsensusOverlayLogReplayListenerPtr,
        transport: OverlayTransportType,
    ) -> Result<ConsensusOverlayPtr> {
        *self.ingress.lock().unwrap() = listener.upgrade();
        let overlay = self
            .actual
            .start_authenticated_overlay(key, id, runtime, listener, replay, transport)?;
        *self.overlay.lock().unwrap() = Some(overlay.clone());
        Ok(overlay)
    }
    fn stop_overlay(&self, id: &Arc<PrivateOverlayShortId>, overlay: &ConsensusOverlayPtr) {
        self.actual.stop_overlay(id, overlay);
    }
    fn stop_overlay_checked(
        &self,
        id: &Arc<PrivateOverlayShortId>,
        overlay: &ConsensusOverlayPtr,
    ) -> Result<()> {
        self.actual.stop_overlay_checked(id, overlay)
    }
    fn overlay_drained(&self, overlay: &ConsensusOverlayPtr) -> bool {
        self.actual.overlay_drained(overlay)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_observer_receiver_verifies_pq_candidate_and_authorizes_query_members(
) -> Result<()> {
    use adnl::{
        node::{AdnlNode, AdnlNodeConfig},
        DhtNode, NetworkStack, OverlayNode, RldpNode,
    };
    let store = Arc::new(rtos_pq_consensus::ConsensusKeyStore::from_seed(&[0x98; 32], 0)?);
    let (mut nodes, _) = crate::pq_fixture::members();
    nodes[1] = crate::SimplexSessionNode::from_descriptor(
        &crate::signing_coordinator::tests::custody_descriptor(&store),
    )?;
    let observer =
        rtos_block::Ed25519KeyOption::<rtos_block::ZeroizingBytes>::from_private_key(&[0x71; 32])?;
    let (runtime, key, options) = crate::authenticated_fixture::runtime_with_members(
        nodes.iter().map(|node| node.descriptor.clone().unwrap()).collect(),
        observer,
    );
    let (_, config) =
        AdnlNodeConfig::from_ip_address_and_private_keys("127.0.0.1:0", vec![([0x71; 32], 0)])?;
    let adnl = AdnlNode::with_config(config).await?;
    let dht = DhtNode::with_adnl_node(adnl.clone(), 0)?;
    let overlay = OverlayNode::with_params_and_profile(
        adnl.clone(),
        &[24; 32],
        0,
        rtos_api::WireProfile::T0,
    )?;
    let rldp = RldpNode::with_params(adnl.clone(), vec![overlay.clone()], None)?;
    overlay.set_rldp(rldp.clone())?;
    let stack = Arc::new(NetworkStack { adnl: adnl.clone(), dht, overlay, rldp, quic: None });
    adnl.start_over_udp(vec![stack.overlay.clone(), stack.dht.clone(), stack.rldp.clone()]).await?;
    let actual = ConsensusCommonFactory::create_adnl_overlay_manager(
        tokio::runtime::Handle::current(),
        stack,
        None,
        false,
    )?;
    let manager =
        Arc::new(CaptureManager { actual, ingress: Mutex::new(None), overlay: Mutex::new(None) });
    let (listener, stats) = TestReceiverListener::create(99);
    let listener_dyn: Arc<dyn ReceiverListener + Send + Sync> = listener.clone();
    let panicked = Arc::new(AtomicBool::new(false));
    let receiver = crate::receiver::ReceiverWrapper::create_with_runtime(
        runtime.session_id().clone(),
        runtime.shard(),
        &nodes,
        &key,
        manager.clone(),
        Arc::downgrade(&listener_dyn),
        panicked.clone(),
        Arc::new(crate::receiver::ReceiverHealthCounters::new()),
        crate::receiver::ReceiverSettings::from_session_options(&options, 8 << 20, 9 << 20),
        Some(&runtime),
    );
    let result = async {
        let receiver = receiver.as_ref().map_err(|error| error!("Receiver creation: {error}"))?;
        receiver.start();
        let ingress = manager
            .ingress
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| error!("No actual callback registered"))?;
        let slot = options.slots_per_leader_window;
        receiver.set_ingress_progress_slot(slot);
        let parent = (SlotIndex::new(slot - 1), UInt256::from([5; 32]));
        let block = crate::pq_fixture::block_id("empty");
        let hash = crate::utils::compute_candidate_id_hash_empty(&block, (parent.0, &parent.1));
        let preimage = crate::utils::create_data_to_sign(
            runtime.session_id(),
            &crate::utils::create_candidate_id_to_sign(SlotIndex::new(slot), &hash),
        );
        let candidate = rtos_api::ton::consensus::candidatedata::Empty {
            slot: slot as i32,
            parent: TlCandidateId { slot: (slot - 1) as i32, hash: parent.1 }.into_boxed(),
            block,
            signature: store.sign_consensus(&preimage)?.bytes.to_vec(),
        }
        .into_boxed();
        let bytes = options.wire_profile.serialize(&candidate)?;
        let payload = ConsensusCommonFactory::create_block_payload(bytes.clone());
        ingress.on_broadcast(
            nodes[1].adnl_id.clone(),
            &payload,
            BroadcastSource::ConsensusOverlay,
        );
        let query = rtos_api::ton::rpc::consensus::simplex::RequestCandidate {
            id: TlCandidateId { slot: slot as i32, hash: hash.clone() }.into_boxed(),
            want_candidate: true.into(),
            want_notar: false.into(),
        };
        let query =
            ConsensusCommonFactory::create_block_payload(options.wire_profile.serialize(&query)?);
        let request = |source| {
            let (send, receive) = tokio::sync::oneshot::channel();
            ingress.on_query(
                source,
                &query,
                Box::new(move |result| {
                    let _ = send.send(result);
                }),
            );
            receive
        };
        // Sender is the local observer, not the candidate author. This is valid
        // because query membership and candidate author authentication are distinct.
        let response =
            tokio::time::timeout(Duration::from_secs(3), request(runtime.local_adnl().clone()))
                .await???;
        let decoded = options
            .wire_profile
            .deserialize(response.data())?
            .downcast::<rtos_api::ton::consensus::simplex::CandidateAndCert>()
            .map_err(|_| error!("Wrong query response type"))?;
        anyhow::ensure!(decoded.candidate().as_slice() == bytes.as_slice());
        anyhow::ensure!(stats.broadcasts_received.load(Ordering::SeqCst) == 1);
        let unauthorized = rtos_block::KeyId::from_data([99; 32]);
        anyhow::ensure!(tokio::time::timeout(
            Duration::from_secs(3),
            request(unauthorized.clone())
        )
        .await??
        .is_err());
        ingress.on_broadcast(unauthorized, &payload, BroadcastSource::ConsensusOverlay);
        let mut corrupt = candidate.clone();
        let CandidateData::Consensus_Empty(ref mut value) = corrupt else { unreachable!() };
        value.signature[0] ^= 1;
        ingress.on_broadcast(
            nodes[1].adnl_id.clone(),
            &ConsensusCommonFactory::create_block_payload(
                options.wire_profile.serialize(&corrupt)?,
            ),
            BroadcastSource::ConsensusOverlay,
        );
        // Same queue query completion is a barrier for both preceding rejections.
        tokio::time::timeout(Duration::from_secs(3), request(runtime.local_adnl().clone()))
            .await???;
        anyhow::ensure!(
            stats.broadcasts_received.load(Ordering::SeqCst) == 1,
            "invalid candidate reached session callback"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Ok(receiver) = &receiver {
        receiver.stop();
    }
    drop(receiver);
    let overlay_drained = manager
        .overlay
        .lock()
        .unwrap()
        .as_ref()
        .is_none_or(|overlay| manager.overlay_drained(overlay));
    drop(manager);
    let drained = adnl.stop_checked().await;
    drained?;
    anyhow::ensure!(overlay_drained && !panicked.load(Ordering::SeqCst));
    result
}

/// Records every direct message and query destination of one overlay.
#[derive(Default)]
struct RecordingOverlay {
    messages: Mutex<Vec<PublicKeyHash>>,
    queries: Mutex<Vec<PublicKeyHash>>,
}
impl ConsensusOverlay for RecordingOverlay {
    fn send_message(&self, to: &PublicKeyHash, _: &PublicKeyHash, _: &BlockPayloadPtr, _: bool) {
        self.messages.lock().unwrap().push(to.clone());
    }
    fn send_message_multicast(
        &self,
        to: &[PublicKeyHash],
        _: &PublicKeyHash,
        _: &BlockPayloadPtr,
        _: bool,
    ) {
        self.messages.lock().unwrap().extend(to.iter().cloned());
    }
    fn send_query(
        &self,
        to: &PublicKeyHash,
        _: &PublicKeyHash,
        _: &str,
        _: Duration,
        _: &BlockPayloadPtr,
        _: QueryResponseCallback,
    ) {
        self.queries.lock().unwrap().push(to.clone());
    }
    fn send_query_via_rldp(
        &self,
        to: PublicKeyHash,
        _: String,
        _: QueryResponseCallback,
        _: SystemTime,
        _: BlockPayloadPtr,
        _: u64,
        _: bool,
    ) {
        // The callback is dropped unanswered: the request times out and retries.
        self.queries.lock().unwrap().push(to);
    }
    fn send_broadcast_fec_ex(
        &self,
        _: &PublicKeyHash,
        _: &PublicKeyHash,
        _: BlockPayloadPtr,
        _: Option<Vec<u8>>,
    ) {
    }
    fn get_impl(&self) -> &dyn std::any::Any {
        self
    }
}

struct RecordingManager(Arc<RecordingOverlay>);
impl ConsensusOverlayManager for RecordingManager {
    fn wire_profile(&self) -> rtos_api::WireProfile {
        rtos_api::WireProfile::T0
    }
    fn start_overlay(
        &self,
        _: &PrivateKey,
        _: &Arc<PrivateOverlayShortId>,
        _: &[ConsensusNode],
        _: ConsensusOverlayListenerPtr,
        _: ConsensusOverlayLogReplayListenerPtr,
        _: OverlayTransportType,
        _: Option<BlockSyncOverlayParams>,
    ) -> Result<ConsensusOverlayPtr> {
        anyhow::bail!("Authenticated test must not use legacy overlay creation")
    }
    fn start_authenticated_overlay(
        &self,
        _: &PrivateKey,
        _: &Arc<PrivateOverlayShortId>,
        _: Arc<consensus_common::session_runtime::AuthenticatedSessionRuntime>,
        _: ConsensusOverlayListenerPtr,
        _: ConsensusOverlayLogReplayListenerPtr,
        _: OverlayTransportType,
    ) -> Result<ConsensusOverlayPtr> {
        Ok(self.0.clone())
    }
    fn stop_overlay(&self, _: &Arc<PrivateOverlayShortId>, _: &ConsensusOverlayPtr) {}
}

/// A protocol 2 validator sends each newly cast vote directly to every private
/// overlay member but itself, observers included (C++ apply_own_vote
/// BroadcastToAll), replays its votes on standstill to the validators only
/// (BroadcastToValidators), and resolves candidates from any other member
/// (OutgoingOverlayRequest without a destination).
#[test]
fn authenticated_validator_votes_reach_observers_directly_and_resolver_asks_any_member() {
    let (nodes, keys) = crate::pq_fixture::members();
    let committee: Vec<_> = nodes.iter().map(|node| node.descriptor.clone().unwrap()).collect();
    let observer_store =
        rtos_pq_consensus::ConsensusKeyStore::from_seed(&[0x97; 32], 0).expect("observer key");
    let observer_adnl = UInt256::from([0x96; 32]);
    let mut total = committee.clone();
    total.push(rtos_block::ValidatorDescr::with_pq_params(
        UInt256::from([9; 32]),
        observer_store.consensus_key().clone(),
        1,
        observer_adnl.clone(),
    ));
    let (runtime, key, options) = crate::authenticated_fixture::runtime_with_total_set(
        committee,
        total,
        keys[0].clone(),
        ShardIdent::masterchain(),
        0,
        false,
    );
    let observer = rtos_block::KeyId::from_data(*observer_adnl.as_array());
    let validator = nodes[1].adnl_id.clone();
    assert!(runtime.members().contains(&observer), "observer is an overlay member");
    let overlay = Arc::new(RecordingOverlay::default());
    let manager: ConsensusOverlayManagerPtr = Arc::new(RecordingManager(overlay.clone()));
    let (listener, _) = TestReceiverListener::create(0);
    let listener: Arc<dyn ReceiverListener + Send + Sync> = listener;
    let mut settings =
        crate::receiver::ReceiverSettings::from_session_options(&options, 8 << 20, 9 << 20);
    settings.standstill_timeout = Duration::from_millis(200);
    settings.candidate_resolve_config.timeout = Duration::from_millis(100);
    settings.candidate_resolve_config.timeout_cap = Duration::from_millis(100);
    settings.candidate_resolve_config.cooldown = Duration::from_millis(10);
    let receiver = crate::receiver::ReceiverWrapper::create_with_runtime(
        runtime.session_id().clone(),
        runtime.shard(),
        &nodes,
        &key,
        manager,
        Arc::downgrade(&listener),
        Arc::new(AtomicBool::new(false)),
        Arc::new(crate::receiver::ReceiverHealthCounters::new()),
        settings,
        Some(&runtime),
    )
    .expect("receiver");
    receiver.start();
    let count = |list: &Mutex<Vec<PublicKeyHash>>, peer: &PublicKeyHash| {
        list.lock().unwrap().iter().filter(|to| *to == peer).count()
    };
    let TlVoteBoxed::Consensus_Simplex_Vote(vote) =
        crate::pq_fixture::vote("skip", "skip", 0, crate::pq_fixture::CONTEXT);

    // Standstill replay of a cached vote: validators only.
    receiver.cache_our_vote_for_standstill(vote.clone());
    receiver.set_standstill_slots(0, 200);
    receiver.reschedule_standstill();
    wait_until(Duration::from_secs(5), || count(&overlay.messages, &validator) >= 1);
    assert!(count(&overlay.messages, &validator) >= 1, "standstill replay reached no validator");
    assert_eq!(count(&overlay.messages, &observer), 0, "standstill replay reached an observer");
    assert_eq!(count(&overlay.messages, runtime.local_adnl()), 0, "sent to itself");

    // A newly cast vote: every other member, the observer included.
    receiver.send_vote(vote);
    wait_until(Duration::from_secs(5), || count(&overlay.messages, &observer) >= 1);
    assert_eq!(count(&overlay.messages, &observer), 1, "observer did not get the vote directly");
    assert_eq!(count(&overlay.messages, runtime.local_adnl()), 0, "sent to itself");

    // Candidate resolution rotates over every other member.
    receiver.request_candidate(120, UInt256::from([0x33; 32]));
    wait_until(Duration::from_secs(10), || {
        count(&overlay.queries, &observer) >= 1 && count(&overlay.queries, &validator) >= 1
    });
    assert!(count(&overlay.queries, &observer) >= 1, "resolver never asked the observer");
    assert!(count(&overlay.queries, &validator) >= 1, "resolver never asked the validator");
    assert_eq!(count(&overlay.queries, runtime.local_adnl()), 0, "queried itself");
    receiver.stop();
}
