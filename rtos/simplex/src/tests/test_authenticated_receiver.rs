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
