// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Real production wrapper/registry/manager/lower-dispatch ownership, not socket interop.
use super::*;
use crate::{
    collator_test_bundle::create_engine_allocated,
    validator::{
        consensus_overlay::ConsensusOverlayManagerImpl,
        validator_manager::emulator_network_bootstrap::EmulatorNetworkBootstrap,
    },
};
use consensus_common::{
    BlockPayloadPtr, ConsensusCommonFactory, ConsensusOverlayListener,
    ConsensusOverlayLogReplayListener, ConsensusOverlayManager, ConsensusOverlayPtr,
    QueryResponseCallback,
};
use futures::FutureExt;
use rtos_api::{AnyBoxedSerialize, IntoBoxed};
use std::{
    sync::Mutex,
    time::{Duration, SystemTime},
};

struct Held {
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
    panic: bool,
}
impl ConsensusOverlayListener for Held {
    fn on_message(&self, _: Arc<KeyId>, _: &BlockPayloadPtr) {}
    fn on_broadcast(
        &self,
        _: Arc<KeyId>,
        _: &BlockPayloadPtr,
        _: consensus_common::BroadcastSource,
    ) {
    }
    fn on_query(&self, _: Arc<KeyId>, _: &BlockPayloadPtr, callback: QueryResponseCallback) {
        if let Some(entered) = self.entered.lock().unwrap().take() {
            let _ = entered.send(());
        }
        self.release.lock().unwrap().recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(!self.panic, "production-wrapper controlled query-worker panic");
        callback(Ok(ConsensusCommonFactory::create_block_payload(
            rtos_api::WireProfile::T0
                .serialize(&rtos_api::ton::consensus::RequestError::Consensus_RequestError)
                .unwrap(),
        )));
    }
}
struct Replay;
impl ConsensusOverlayLogReplayListener for Replay {
    fn on_time_changed(&self, _: SystemTime) {}
}
struct Release(Option<std::sync::mpsc::Sender<()>>);
impl Release {
    fn release(&mut self) {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(());
        }
    }
}
impl Drop for Release {
    fn drop(&mut self) {
        self.release();
    }
}

async fn stop(
    wrapper: Arc<ConsensusOverlayManagerImpl>,
    id: Arc<PrivateOverlayShortId>,
    overlay: ConsensusOverlayPtr,
) -> Result<()> {
    tokio::task::spawn_blocking(move || wrapper.stop_overlay_checked(&id, &overlay)).await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn production_wrapper_held_query_profile_generation_and_sticky_failure() -> Result<()> {
    for panic in [false, true] {
        let bootstrap = EmulatorNetworkBootstrap::build(2)?;
        // Keep every transport endpoint isolated; dynamic key tags must not shadow
        // the node's built-in DHT/public tags.
        let mut config: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&bootstrap.config_path)?)?;
        config["ip_address_quic"] = "127.0.0.1:0".into();
        for key in config["validator_keys"].as_array_mut().unwrap() {
            key["election_id"] = (key["election_id"].as_i64().unwrap() + 1000).into();
        }
        std::fs::write(&bootstrap.config_path, serde_json::to_vec(&config)?)?;
        let network = NodeNetwork::new(
            bootstrap.load_node_config().await?,
            tokio_util::sync::CancellationToken::new(),
            #[cfg(feature = "telemetry")]
            crate::collator_test_bundle::create_engine_telemetry(),
            create_engine_allocated(),
        )
        .await?;
        let list_id = UInt256::from([81; 32]);
        let nodes: Vec<_> = bootstrap
            .validators
            .iter()
            .map(|keys| CatchainNode {
                public_key: keys.validator_key.clone().into(),
                adnl_id: keys.adnl_key.id().clone(),
            })
            .collect();
        let wrapper =
            Arc::new(ConsensusOverlayManagerImpl::new(network.clone(), list_id.clone(), None));
        let result = std::panic::AssertUnwindSafe(async {
            // Node construction schedules transport registration callbacks.
            // Membership selection alone does not guarantee their completion.
            network.config_handler.wait_test_subscribers().await?;
            let selected = network.set_validator_list(list_id.clone(), &nodes).await?;
            let crate::engine_traits::ValidatorListOutcome::Selected { key, .. } = selected else {
                fail!("fixture failed to register real local transport");
            };
            // Private membership is activated only after ADNL has resolved the
            // configured member's address. This dispatcher fixture has no DHT
            // peer, so supply its public key/address through the real resolver
            // destination API before normal overlay creation. Reserve the UDP
            // endpoint throughout the exercise; this is not socket interop.
            let local = network
                .validator_context
                .sets_contexts
                .get(&list_id)
                .expect("transport registration must finish before wrapper dispatch")
                .val()
                .validator_adnl_key
                .id()
                .clone();
            let remote =
                bootstrap.validators.iter().find(|keys| keys.adnl_key.id() != &local).unwrap();
            let endpoint = std::net::UdpSocket::bind("127.0.0.1:0")?;
            let address = adnl::node::IpAddress::from_versioned_string(
                &endpoint.local_addr()?.to_string(),
                None,
            )?;
            network.context().stack.overlay.add_private_peers_to_adnl(
                &local,
                vec![(address, None, remote.adnl_key.clone())],
            )?;
            assert_eq!(wrapper.wire_profile(), rtos_api::WireProfile::T0);
            let id = PrivateOverlayShortId::from_data([82; 32]);
            let (entered, started) = tokio::sync::oneshot::channel();
            let (release, held) = std::sync::mpsc::channel();
            let mut release = Release(Some(release));
            let listener: Arc<dyn ConsensusOverlayListener + Send + Sync> = Arc::new(Held {
                entered: Mutex::new(Some(entered)),
                release: Mutex::new(held),
                panic,
            });
            let replay: Arc<dyn ConsensusOverlayLogReplayListener + Send + Sync> = Arc::new(Replay);
            let overlay = wrapper.start_overlay(
                &key,
                &id,
                &nodes,
                Arc::downgrade(&listener),
                Arc::downgrade(&replay),
                consensus_common::OverlayTransportType::Catchain,
                None,
            )?;
            assert!(network.validator_context.catchain_overlays.get(&id).is_some());
            let other = nodes.iter().find(|n| n.adnl_id != local).unwrap().adnl_id.clone();
            let peers = AdnlPeers::with_keys(local, other);
            let query = network
                .context()
                .stack
                .overlay
                .try_consume_query_bundle(
                    vec![
                        rtos_api::ton::rpc::overlay::Query { overlay: UInt256::from(*id.data()) }
                            .into_tl_object(),
                        rtos_api::ton::consensus::RequestError::Consensus_RequestError
                            .into_tl_object(),
                    ],
                    &peers,
                )
                .await?;
            tokio::time::timeout(Duration::from_secs(5), started).await??;
            let owner = wrapper.clone();
            let stop_id = id.clone();
            let old = overlay.clone();
            let mut stopping = tokio::spawn(async move { stop(owner, stop_id, old).await });
            assert!(tokio::time::timeout(Duration::from_millis(50), &mut stopping).await.is_err());
            assert!(!wrapper.overlay_drained(&overlay));
            assert!(
                network.validator_context.catchain_overlays.get(&id).is_some(),
                "registry retired before lower worker drain"
            );
            release.release();
            // Resolve the real lower response receipt as well as the wrapper.
            if let QueryResult::Consumed(QueryAnswer::Pending(answer)) = query {
                let _ = tokio::time::timeout(Duration::from_secs(5), answer).await?;
            }
            let first = tokio::time::timeout(Duration::from_secs(10), stopping).await??;
            assert!(wrapper.overlay_drained(&overlay));
            assert!(network.validator_context.catchain_overlays.get(&id).is_none());
            let repeated = stop(wrapper.clone(), id.clone(), overlay.clone()).await;
            if panic {
                assert!(first.is_err(), "real worker panic must reach wrapper");
                assert_eq!(first.unwrap_err().to_string(), repeated.unwrap_err().to_string());
            } else {
                first?;
                repeated?;
            }
            // A newly created same-id generation is not owned by the old receipt.
            let (release, held) = std::sync::mpsc::channel();
            let _release = Release(Some(release));
            let next_listener: Arc<dyn ConsensusOverlayListener + Send + Sync> = Arc::new(Held {
                entered: Mutex::new(None),
                release: Mutex::new(held),
                panic: false,
            });
            let next = wrapper.start_overlay(
                &key,
                &id,
                &nodes,
                Arc::downgrade(&next_listener),
                Arc::downgrade(&replay),
                consensus_common::OverlayTransportType::Catchain,
                None,
            )?;
            assert!(!Arc::ptr_eq(&overlay, &next));
            assert!(stop(wrapper.clone(), id.clone(), overlay).await.is_err());
            assert!(network
                .validator_context
                .catchain_overlays
                .get(&id)
                .is_some_and(|g| Arc::ptr_eq(g.val(), &next)));
            stop(wrapper.clone(), id, next).await?;
            Ok::<_, anyhow::Error>(())
        })
        .catch_unwind()
        .await;
        // Cleanup happens even if a causal control trips an assertion.
        let remaining: Vec<_> = network
            .validator_context
            .catchain_overlays
            .iter()
            .map(|g| (g.key().clone(), g.val().clone()))
            .collect();
        for (id, overlay) in remaining {
            let _ = stop(wrapper.clone(), id, overlay).await;
        }
        let shutdown = network.stop_adnl().await;
        match result {
            Ok(result) => {
                result?;
                shutdown?;
            }
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
    Ok(())
}
