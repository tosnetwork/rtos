/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! Unit tests for `adnl_overlay.rs` helpers.

use super::*;
use rtos_api::{
    serialize_boxed,
    ton::consensus::{
        simplex::candidateandcert::CandidateAndCert, RequestError as ConsensusRequestError,
    },
    IntoBoxed,
};

#[test]
fn test_extract_query_response_error_recognizes_request_error() {
    let bytes = serialize_boxed(&ConsensusRequestError::Consensus_RequestError)
        .expect("serialize requestError");

    let error_name =
        extract_query_response_error(bytes.as_slice()).expect("requestError must be extracted");
    assert_eq!(error_name, "consensus.requestError");
}

#[test]
fn test_normalize_query_response_payload_rejects_request_error() {
    let bytes = serialize_boxed(&ConsensusRequestError::Consensus_RequestError)
        .expect("serialize requestError");

    let err =
        normalize_query_response_payload(bytes).expect_err("requestError must become query error");
    assert!(err.to_string().contains("consensus.requestError"), "unexpected error: {err}");
}

#[test]
fn test_normalize_query_response_payload_accepts_candidate_and_cert() {
    let bytes = serialize_boxed(
        &CandidateAndCert { candidate: Vec::<u8>::new().into(), notar: Vec::<u8>::new().into() }
            .into_boxed(),
    )
    .expect("serialize CandidateAndCert");

    let payload =
        normalize_query_response_payload(bytes.clone()).expect("candidateAndCert must pass");
    assert_eq!(payload.data(), &bytes);
}

struct HeldListener {
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
    callback: Mutex<Option<QueryResponseCallback>>,
}
impl crate::ConsensusOverlayListener for HeldListener {
    fn on_message(&self, _: PublicKeyHash, _: &BlockPayloadPtr) {}
    fn on_broadcast(&self, _: PublicKeyHash, _: &BlockPayloadPtr, _: crate::BroadcastSource) {}
    fn on_query(&self, _: PublicKeyHash, _: &BlockPayloadPtr, callback: QueryResponseCallback) {
        if let Some(entered) = self.entered.lock().unwrap().take() {
            entered.send(()).unwrap();
        }
        self.release.lock().unwrap().recv_timeout(Duration::from_secs(5)).unwrap();
        *self.callback.lock().unwrap() = Some(callback);
    }
}
async fn real_overlay(listener: ConsensusOverlayListenerPtr, seed: u8) -> Arc<AdnlOverlay> {
    real_overlay_with_profile(listener, seed, rtos_api::WireProfile::Legacy).await
}
async fn real_overlay_with_profile(
    listener: ConsensusOverlayListenerPtr,
    seed: u8,
    profile: rtos_api::WireProfile,
) -> Arc<AdnlOverlay> {
    let (_, config) = adnl::node::AdnlNodeConfig::from_ip_address_and_private_keys(
        "127.0.0.1:0",
        vec![([seed; 32], 0)],
    )
    .unwrap();
    let adnl = AdnlNode::with_config(config).await.unwrap();
    let key = adnl.key_by_tag(0).unwrap();
    let dht = DhtNode::with_adnl_node(adnl.clone(), 0).unwrap();
    let overlay = OverlayNode::with_params_and_profile(adnl.clone(), &[1; 32], 0, profile).unwrap();
    let rldp = adnl::RldpNode::with_params(adnl.clone(), vec![overlay.clone()], None).unwrap();
    overlay.set_rldp(rldp.clone()).unwrap();
    let stack = Arc::new(NetworkStack { adnl, dht, overlay, rldp, quic: None });
    stack
        .adnl
        .start_over_udp(vec![stack.overlay.clone(), stack.dht.clone(), stack.rldp.clone()])
        .await
        .unwrap();
    let overlay = AdnlOverlay::new(
        tokio::runtime::Handle::current(),
        stack,
        KeyId::from_data([seed; 32]),
        key.clone(),
        listener,
        &[ConsensusNode { adnl_id: key.id().clone(), public_key: key.into() }],
        None,
        true,
        Arc::new(PeerStorage::new()),
        OverlayTransportType::Catchain,
        None,
    )
    .unwrap();
    overlay.clone().run_wait_broadcast();
    overlay
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn overlay_custom_control_dispatch_preserves_bundles_and_rejects_control_postfix() {
    for (seed, profile) in [(88, rtos_api::WireProfile::Legacy), (90, rtos_api::WireProfile::T0)] {
        let (_release_tx, release_rx) = std::sync::mpsc::channel();
        let listener: Arc<dyn crate::ConsensusOverlayListener + Send + Sync> =
            Arc::new(HeldListener {
                entered: Mutex::new(None),
                release: Mutex::new(release_rx),
                callback: Mutex::new(None),
            });
        let overlay = real_overlay_with_profile(Arc::downgrade(&listener), seed, profile).await;
        let peers =
            AdnlPeers::with_keys(overlay.local_adnl_key.id().clone(), KeyId::from_data([89; 32]));
        let consumer = AdnlOverlayConsumer::new(
            overlay.overlay_id.clone(),
            Arc::downgrade(&overlay),
            overlay.stop_requested.clone(),
        );
        let profile = overlay.stack.overlay.wire_profile();
        let mut bundle = profile.serialize(&rtos_api::ton::catchain::Update::default()).unwrap();
        bundle.extend(
            profile.serialize(&rtos_api::ton::validator_session::BlockUpdate::default()).unwrap(),
        );
        let bundle_result = consumer.try_consume_custom(&bundle, &peers).await;
        bundle.push(3); // The legacy private-overlay hop postfix belongs to its bundle parser.
        let hop_result = consumer.try_consume_custom(&bundle, &peers).await;
        let mut controls = Vec::new();
        for bytes in [
            profile.serialize(&BroadcastWrapper::default()).unwrap(),
            profile.serialize(&SimplexVote::default()).unwrap(),
            profile.serialize(&SimplexCertificate::default()).unwrap(),
        ] {
            let accepted = consumer.try_consume_custom(&bytes, &peers).await;
            let mut postfix = bytes.clone();
            postfix.push(0);
            let rejected = consumer.try_consume_custom(&postfix, &peers).await;
            let truncated = consumer.try_consume_custom(&bytes[..bytes.len() - 1], &peers).await;
            controls.push((accepted, rejected, truncated));
        }
        // Clean up before asserting: a deliberately failing admission regression
        // must not leave UDP blocking-task joins hanging in Tokio teardown.
        let owner = overlay.clone();
        tokio::task::spawn_blocking(move || owner.stop_checked()).await.unwrap().unwrap();
        overlay.stack.adnl.stop_checked().await.unwrap();
        assert!(matches!(bundle_result, Ok(false)), "{bundle_result:?}");
        assert!(matches!(hop_result, Ok(false)), "{hop_result:?}");
        for (accepted, rejected, truncated) in controls {
            assert!(matches!(accepted, Ok(true)), "{accepted:?}");
            assert!(rejected.unwrap_err().to_string().contains("Trailing bytes"));
            assert!(truncated.is_err());
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn overlay_owned_real_query_listener_join_and_response_handoff() {
    use rtos_api::AnyBoxedSerialize;
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let listener = Arc::new(HeldListener {
        entered: Mutex::new(Some(entered_tx)),
        release: Mutex::new(release_rx),
        callback: Mutex::new(None),
    });
    let listener_trait: Arc<dyn crate::ConsensusOverlayListener + Send + Sync> = listener.clone();
    let overlay = real_overlay(Arc::downgrade(&listener_trait), 81).await;
    let peers =
        AdnlPeers::with_keys(overlay.local_adnl_key.id().clone(), KeyId::from_data([82; 32]));
    let query = overlay
        .process_query(ConsensusRequestError::Consensus_RequestError.into_tl_object(), &peers)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), entered_rx).await.unwrap().unwrap();
    let owner = overlay.clone();
    let mut stop = tokio::task::spawn_blocking(move || owner.stop_checked());
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut stop).await.is_err());
    assert!(!overlay.drained());
    release_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), stop).await.unwrap().unwrap().unwrap();
    assert!(overlay.drained());
    assert!(
        listener.callback.lock().unwrap().is_some(),
        "response callback belongs to consensus after listener handoff"
    );
    drop(query);
    drop(listener.callback.lock().unwrap().take());
    let owner = overlay.clone();
    tokio::task::spawn_blocking(move || owner.stop_checked()).await.unwrap().unwrap();
    let node = overlay.stack.adnl.clone();
    let weak = Arc::downgrade(&overlay);
    drop(overlay);
    assert!(weak.upgrade().is_none());
    node.stop_checked().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn overlay_owned_real_processor_panic_sticky_after_join() {
    let (_, release_rx) = std::sync::mpsc::channel();
    let listener: Arc<dyn crate::ConsensusOverlayListener + Send + Sync> = Arc::new(HeldListener {
        entered: Mutex::new(None),
        release: Mutex::new(release_rx),
        callback: Mutex::new(None),
    });
    let overlay = real_overlay(Arc::downgrade(&listener), 83).await;
    let (entered, started) = tokio::sync::oneshot::channel();
    let (release, held) = tokio::sync::oneshot::channel();
    overlay.task_processor_manager.processors[&0].post_closure(move || {
        Box::pin(async move {
            entered.send(()).unwrap();
            held.await.unwrap();
            panic!("real processor injected failure");
        })
    });
    started.await.unwrap();
    let owner = overlay.clone();
    let mut stop = tokio::task::spawn_blocking(move || owner.stop_checked());
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut stop).await.is_err());
    release.send(()).unwrap();
    let first = tokio::time::timeout(Duration::from_secs(5), stop)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err()
        .to_string();
    assert!(first.contains("task processor"));
    assert!(overlay.drained(), "joined panic is distinct from unknown drain");
    let owner = overlay.clone();
    assert_eq!(
        first,
        tokio::task::spawn_blocking(move || owner.stop_checked())
            .await
            .unwrap()
            .unwrap_err()
            .to_string()
    );
    overlay.stack.adnl.stop_checked().await.unwrap();
}

struct ImmediateListener;
impl crate::ConsensusOverlayListener for ImmediateListener {
    fn on_message(&self, _: PublicKeyHash, _: &BlockPayloadPtr) {}
    fn on_broadcast(&self, _: PublicKeyHash, _: &BlockPayloadPtr, _: crate::BroadcastSource) {}
    fn on_query(&self, _: PublicKeyHash, _: &BlockPayloadPtr, callback: QueryResponseCallback) {
        callback(Ok(ConsensusCommonFactory::create_block_payload(
            serialize_boxed(&ConsensusRequestError::Consensus_RequestError).unwrap(),
        )));
    }
}
struct Replay;
impl crate::ConsensusOverlayLogReplayListener for Replay {
    fn on_time_changed(&self, _: SystemTime) {}
}
async fn response_still_works(overlay: &ConsensusOverlayPtr) {
    use rtos_api::AnyBoxedSerialize;
    let implementation = overlay.get_impl().downcast_ref::<AdnlOverlay>().unwrap();
    let peers = AdnlPeers::with_keys(
        implementation.local_adnl_key.id().clone(),
        KeyId::from_data([115; 32]),
    );
    let response = implementation
        .process_query(ConsensusRequestError::Consensus_RequestError.into_tl_object(), &peers)
        .await
        .unwrap();
    let QueryResult::Consumed(QueryAnswer::Pending(response)) = response else {
        panic!("expected real response worker")
    };
    assert!(tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .answer
        .is_some());
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn overlay_owned_manager_concurrent_creation_and_old_stop_preserve_new_generation() {
    let listener: Arc<dyn crate::ConsensusOverlayListener + Send + Sync> =
        Arc::new(ImmediateListener);
    let baseline = real_overlay(Arc::downgrade(&listener), 112).await;
    let stack = baseline.stack.clone();
    let manager =
        AdnlOverlayManager::create(tokio::runtime::Handle::current(), stack.clone(), None, true)
            .unwrap();
    let key = baseline.local_validator_key.clone();
    let nodes = vec![ConsensusNode { adnl_id: key.id().clone(), public_key: key.clone().into() }];
    let replay: Arc<dyn crate::ConsensusOverlayLogReplayListener + Send + Sync> = Arc::new(Replay);
    let id = KeyId::from_data([113; 32]);
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let mut starts = Vec::new();
    for _ in 0..2 {
        let (manager, key, nodes, id, listener, replay, barrier) = (
            manager.clone(),
            key.clone(),
            nodes.clone(),
            id.clone(),
            listener.clone(),
            replay.clone(),
            barrier.clone(),
        );
        starts.push(tokio::task::spawn_blocking(move || {
            barrier.wait();
            manager
                .start_overlay(
                    &key,
                    &id,
                    &nodes,
                    Arc::downgrade(&listener),
                    Arc::downgrade(&replay),
                    OverlayTransportType::Catchain,
                    None,
                )
                .unwrap()
        }));
    }
    let first = starts.remove(0).await.unwrap();
    let second = starts.remove(0).await.unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    response_still_works(&first).await;
    // A different constructor cannot claim and later roll back this live ID.
    assert!(AdnlOverlay::new(
        tokio::runtime::Handle::current(),
        stack.clone(),
        id.clone(),
        key.clone(),
        Arc::downgrade(&listener),
        &nodes,
        None,
        true,
        Arc::new(PeerStorage::new()),
        OverlayTransportType::Catchain,
        None
    )
    .is_err());
    response_still_works(&first).await;
    let (m, i, o) = (manager.clone(), id.clone(), first.clone());
    tokio::task::spawn_blocking(move || m.stop_overlay_checked(&i, &o)).await.unwrap().unwrap();
    let replacement = manager
        .start_overlay(
            &key,
            &id,
            &nodes,
            Arc::downgrade(&listener),
            Arc::downgrade(&replay),
            OverlayTransportType::Catchain,
            None,
        )
        .unwrap();
    assert!(!Arc::ptr_eq(&first, &replacement));
    let (m, i, o) = (manager.clone(), id.clone(), first.clone());
    tokio::task::spawn_blocking(move || m.stop_overlay_checked(&i, &o)).await.unwrap().unwrap();
    response_still_works(&replacement).await;
    let current = manager
        .start_overlay(
            &key,
            &id,
            &nodes,
            Arc::downgrade(&listener),
            Arc::downgrade(&replay),
            OverlayTransportType::Catchain,
            None,
        )
        .unwrap();
    assert!(Arc::ptr_eq(&current, &replacement));
    let (m, i, o) = (manager.clone(), id.clone(), replacement.clone());
    tokio::task::spawn_blocking(move || m.stop_overlay_checked(&i, &o)).await.unwrap().unwrap();
    tokio::task::spawn_blocking(move || baseline.stop_checked()).await.unwrap().unwrap();
    stack.adnl.stop_checked().await.unwrap();
}
