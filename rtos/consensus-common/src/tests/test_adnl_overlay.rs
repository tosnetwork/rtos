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
    let (_, config) = adnl::node::AdnlNodeConfig::from_ip_address_and_private_keys(
        "127.0.0.1:0",
        vec![([seed; 32], 0)],
    )
    .unwrap();
    let adnl = AdnlNode::with_config(config).await.unwrap();
    let key = adnl.key_by_tag(0).unwrap();
    let dht = DhtNode::with_adnl_node(adnl.clone(), 0).unwrap();
    let overlay = OverlayNode::with_params(adnl.clone(), &[1; 32], 0).unwrap();
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
