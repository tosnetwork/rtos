use crate::{
    common::{
        AdnlPeers, Answer, QueryAnswer, QueryResult, Subscriber, TaggedByteSlice, TaggedByteVec,
    },
    node::{AdnlNode, AdnlNodeConfig},
    RldpNode, RldpQueryTimeout,
};
use futures::FutureExt;
use rtos_api::{
    deserialize_boxed, serialize_boxed,
    ton::{rldp2, rpc::overlay::Query},
    TLObject,
};
use rtos_block::{Result, UInt256};
use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

#[derive(Default)]
struct HeldReply {
    messages: std::sync::atomic::AtomicUsize,
    message_received: tokio::sync::Notify,
    message_hash: Mutex<Option<String>>,
    calls: std::sync::atomic::AtomicUsize,
    response_bytes: std::sync::atomic::AtomicUsize,
    hold: AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
#[async_trait::async_trait]
impl Subscriber for HeldReply {
    async fn try_consume_custom(&self, bytes: &[u8], _: &AdnlPeers) -> Result<bool> {
        if bytes == b"churn" || bytes.starts_with(b"mtu:") {
            *self.message_hash.lock().unwrap() =
                Some(hex::encode(rtos_block::sha256_digest(bytes)));
            self.messages.fetch_add(1, Ordering::Release);
            self.message_received.notify_one();
            return Ok(true);
        }
        Ok(false)
    }
    async fn try_consume_query(&self, object: TLObject, _: &AdnlPeers) -> Result<QueryResult> {
        match object.downcast::<Query>() {
            Ok(_) => {
                self.calls.fetch_add(1, Ordering::Release);
                if self.hold.load(Ordering::Acquire) {
                    self.entered.notify_one();
                    self.release.notified().await;
                }
                Ok(QueryResult::Consumed(QueryAnswer::Ready(Some(Answer::Raw(TaggedByteVec {
                    object: vec![42; self.response_bytes.load(Ordering::Acquire).max(64)],
                    #[cfg(feature = "telemetry")]
                    tag: 0,
                })))))
            }
            Err(object) => Ok(QueryResult::Rejected(object)),
        }
    }
}

#[derive(Default)]
struct ResponsePackets {
    confirm_packets: std::sync::atomic::AtomicUsize,
    confirm_received: Mutex<Option<(Vec<u8>, i32)>>,
    complete_packets: std::sync::atomic::AtomicUsize,
    complete_transfer_ids: Mutex<HashSet<Vec<u8>>>,
    part_one_completions: std::sync::atomic::AtomicUsize,
    part_two_completions: std::sync::atomic::AtomicUsize,
    transfers: Mutex<HashSet<Vec<u8>>>,
    drop_parts: AtomicBool,
    handler: Mutex<Option<std::sync::Weak<RldpNode>>>,
    processed_parts: std::sync::atomic::AtomicUsize,
}
#[async_trait::async_trait]
impl Subscriber for ResponsePackets {
    async fn try_consume_custom(&self, bytes: &[u8], peers: &AdnlPeers) -> Result<bool> {
        let mut is_data_part = false;
        if let Ok(message) = deserialize_boxed(bytes) {
            if let Ok(part) = message.downcast::<rldp2::MessagePart>() {
                match part {
                    rldp2::MessagePart::Rldp2_MessagePart(part) => {
                        is_data_part = true;
                        self.transfers
                            .lock()
                            .unwrap()
                            .insert(part.0.transfer_id.as_slice().to_vec());
                        if self.drop_parts.load(Ordering::Acquire) {
                            return Ok(true);
                        }
                    }
                    rldp2::MessagePart::Rldp2_Confirm(confirm) => {
                        if let Some((id, received)) = &mut *self.confirm_received.lock().unwrap() {
                            if confirm.transfer_id.as_slice() == id.as_slice() {
                                *received = (*received).max(confirm.received_count);
                            }
                        }
                        self.confirm_packets.fetch_add(1, Ordering::Release);
                    }
                    rldp2::MessagePart::Rldp2_Complete(part) => {
                        self.complete_transfer_ids
                            .lock()
                            .unwrap()
                            .insert(part.transfer_id.as_slice().to_vec());
                        self.complete_packets.fetch_add(1, Ordering::Release);
                        if part.part == 1 {
                            self.part_one_completions.fetch_add(1, Ordering::Release);
                        } else if part.part == 2 {
                            self.part_two_completions.fetch_add(1, Ordering::Release);
                        }
                    }
                }
            }
        }
        // In tests requiring a negative state assertion, acknowledge processing only
        // after the real handler returns. Consume here to prevent double dispatch.
        let handler = self.handler.lock().unwrap().as_ref().and_then(std::sync::Weak::upgrade);
        if let Some(handler) = handler {
            let consumed = handler.try_consume_custom(bytes, peers).await?;
            if is_data_part {
                assert!(consumed, "real RLDP handler must consume the test packet");
                self.processed_parts.fetch_add(1, Ordering::Release);
            }
            return Ok(consumed);
        }
        Ok(false) // Observe authenticated packets, then let the real receiver handle them.
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expired_rldp2_query_does_not_start_a_late_response() {
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_late_response_context.tsv").trim(),
        "10 64 1024 1100 500"
    );
    let (reply, packets, nodes, rldps, peers) = pair().await;
    let outcome = std::panic::AssertUnwindSafe(async {
        let bytes = serialize_boxed(&Query { overlay: UInt256::default() }).unwrap();
        let query = TaggedByteSlice {
            object: &bytes,
            #[cfg(feature = "telemetry")]
            tag: 0,
        };
        let (answer, _) = rldps[0].query(&query, Some(1024), &peers, true, None).await.unwrap();
        assert_eq!(answer.unwrap(), vec![42; 64]);
        let before = packets.transfers.lock().unwrap().clone();
        assert_eq!(before.len(), 1, "positive control must observe a real response transfer");
        let started_before = rldps[1].allocated.response_lifecycle.0.load(Ordering::Acquire);
        assert_eq!(started_before, 1, "positive control must count an actual sender start");
        tokio::time::timeout(Duration::from_secs(5), async {
            while rldps[1].allocated.response_lifecycle.1.load(Ordering::Acquire) != 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        reply.hold.store(true, Ordering::Release);
        let request = rldps[0].query(&query, Some(1024), &peers, true, None);
        let observe = async {
            tokio::time::timeout(Duration::from_secs(5), reply.entered.notified()).await.unwrap();
        };
        let (result, ()) = tokio::join!(request, observe);
        let error = result.unwrap_err();
        assert!(error.downcast_ref::<RldpQueryTimeout>().is_some(), "{error:#}");
        tokio::time::sleep(Duration::from_millis(1100)).await;
        reply.hold.store(false, Ordering::Release);
        reply.release.notify_one();
        tokio::time::timeout(Duration::from_secs(5), async {
            while rldps[1].allocated.response_lifecycle.1.load(Ordering::Acquire) != 2 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("released subscriber must finish processing");
        assert_eq!(
            rldps[1].allocated.response_lifecycle.0.load(Ordering::Acquire),
            started_before,
            "expired response started a sender even if it emitted no packet"
        );
        // Same bounded post-release observation window as the native lifetime fixture.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            *packets.transfers.lock().unwrap(),
            before,
            "expired response opened a new wire transfer"
        );
        assert_eq!(
            rldps[1].allocated.send_transfers.load(Ordering::Acquire),
            0,
            "expired response retained a live sender despite no received packets"
        );
        let (answer, _) = rldps[0].query(&query, Some(1024), &peers, true, None).await.unwrap();
        assert_eq!(answer.unwrap(), vec![42; 64], "same peer must recover");
    })
    .catch_unwind()
    .await;
    reply.hold.store(false, Ordering::Release);
    reply.release.notify_one();
    let stopped = futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await;
    for result in stopped {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

async fn pair(
) -> (Arc<HeldReply>, Arc<ResponsePackets>, Vec<Arc<AdnlNode>>, Vec<Arc<RldpNode>>, AdnlPeers) {
    topology(2).await
}

async fn topology(
    count: usize,
) -> (Arc<HeldReply>, Arc<ResponsePackets>, Vec<Arc<AdnlNode>>, Vec<Arc<RldpNode>>, AdnlPeers) {
    topology_with_remote_observer(count, None).await
}

async fn topology_with_remote_observer(
    count: usize,
    remote_observer: Option<Arc<ResponsePackets>>,
) -> (Arc<HeldReply>, Arc<ResponsePackets>, Vec<Arc<AdnlNode>>, Vec<Arc<RldpNode>>, AdnlPeers) {
    let reply = Arc::new(HeldReply::default());
    let packets = Arc::new(ResponsePackets::default());
    let mut nodes = Vec::new();
    let mut rldps = Vec::new();
    for index in 0..count {
        let mut attempts = 0;
        let (node, rldp) = loop {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let (_, config) = AdnlNodeConfig::from_ip_address_and_private_keys(
                &socket.local_addr().unwrap().to_string(),
                if index == 1 {
                    vec![([18; 32], 0), ([39; 32], 1)]
                } else {
                    vec![([if index == 22 { 79 } else { 17 + index as u8 }; 32], 0)]
                },
            )
            .unwrap();
            let node = AdnlNode::with_config(
                config,
                #[cfg(feature = "dump")]
                None,
            )
            .await
            .unwrap();
            let rldp = RldpNode::with_params(
                node.clone(),
                vec![reply.clone()],
                None,
                #[cfg(feature = "debug")]
                None,
                #[cfg(feature = "debug")]
                None,
            )
            .unwrap();
            let mut subscribers: Vec<Arc<dyn Subscriber>> = Vec::new();
            if index == 0 {
                subscribers.push(packets.clone());
            }
            if index == 1 {
                if let Some(observer) = &remote_observer {
                    subscribers.push(observer.clone());
                }
            }
            subscribers.push(rldp.clone());
            // Retain the OS reservation through async construction. Retry only
            // a close-to-rebind race, after joining the failed startup owner.
            drop(socket);
            match node.start_over_udp(subscribers).await {
                Ok(()) => break (node, rldp),
                Err(error) => {
                    node.stop_checked().await.unwrap();
                    attempts += 1;
                    assert!(
                        attempts < 8
                            && error
                                .downcast_ref::<std::io::Error>()
                                .is_some_and(|error| error.kind() == std::io::ErrorKind::AddrInUse),
                        "{error:#}"
                    );
                }
            }
        };
        nodes.push(node);
        rldps.push(rldp);
    }
    let keys: Vec<_> = nodes.iter().map(|node| node.key_by_tag(0).unwrap()).collect();
    for index in (0..count).filter(|&index| index != 1) {
        nodes[index]
            .add_peer(keys[index].id(), nodes[1].ip_address_adnl(), None, &keys[1])
            .unwrap();
        nodes[1]
            .add_peer(keys[1].id(), nodes[index].ip_address_adnl(), None, &keys[index])
            .unwrap();
    }
    let peers = AdnlPeers::with_keys(keys[0].id().clone(), keys[1].id().clone());
    (reply, packets, nodes, rldps, peers)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unacknowledged_rldp2_response_keeps_the_query_deadline() {
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_sender_deadline_context.tsv").trim(),
        "10 64 1024 2000 13000"
    );
    let (_reply, packets, nodes, rldps, peers) = pair().await;
    let outcome = std::panic::AssertUnwindSafe(async {
        packets.drop_parts.store(true, Ordering::Release);
        let bytes = serialize_boxed(&Query { overlay: UInt256::default() }).unwrap();
        let query = TaggedByteSlice {
            object: &bytes,
            #[cfg(feature = "telemetry")]
            tag: 0,
        };
        let request = rldps[0].query(&query, Some(1024), &peers, true, None);
        let observe = async {
            tokio::time::timeout(Duration::from_secs(5), async {
                while rldps[1].allocated.response_lifecycle.0.load(Ordering::Acquire) == 0 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("actual response sender must start");
            tokio::time::sleep(Duration::from_secs(2)).await;
            assert!(
                !packets.transfers.lock().unwrap().is_empty(),
                "drop control must observe response packets"
            );
            assert_eq!(
                rldps[1].allocated.send_transfers.load(Ordering::Acquire),
                1,
                "an unacknowledged answer must survive until the query deadline"
            );
        };
        let (result, ()) = tokio::join!(request, observe);
        let error = result.unwrap_err();
        assert!(error.downcast_ref::<RldpQueryTimeout>().is_some(), "{error:#}");
        tokio::time::timeout(Duration::from_secs(3), async {
            while rldps[1].allocated.response_lifecycle.1.load(Ordering::Acquire) != 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("answer sender must finish at query expiry");
        assert_eq!(rldps[1].allocated.send_transfers.load(Ordering::Acquire), 0);
        packets.drop_parts.store(false, Ordering::Release);
        let (answer, _) = rldps[0].query(&query, Some(1024), &peers, true, None).await.unwrap();
        assert_eq!(answer.unwrap(), vec![42; 64], "same peer must recover after expiry");
    })
    .catch_unwind()
    .await;
    packets.drop_parts.store(false, Ordering::Release);
    let stopped = futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await;
    for result in stopped {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_rldp2_peer_does_not_starve_a_healthy_peer() {
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_sender_fairness_context.tsv").trim(),
        "8 60 10 64 1024"
    );
    use rtos_api::{ton::rldp, IntoBoxed, RldpChunk};
    let (_reply, packets, nodes, rldps, attacker_peers) = topology(3).await;
    let outcome = std::panic::AssertUnwindSafe(async {
        packets.drop_parts.store(true, Ordering::Release);
        let worker_count = rldps[1].send_pool.workers;
        let query_bytes = serialize_boxed(&Query { overlay: UInt256::default() }).unwrap();
        // Authenticated raw requests advertise a 60s wire deadline and never
        // acknowledge responses; the ordinary client API fixes its own at10s.
        for index in 0..8 {
            let request = serialize_boxed(
                &rldp::message::Query {
                    query_id: UInt256::from([80 + index as u8; 32]),
                    max_answer_size: 1024,
                    timeout: super::Version::get() + 60,
                    data: query_bytes.clone(),
                }
                .into_boxed(),
            )
            .unwrap();
            let mut encoder = crate::RaptorqEncoder::with_data(&request, None);
            let mut seqno = 0;
            let chunk = RldpChunk {
                transfer_id: UInt256::from([120 + index as u8; 32]),
                fec_type: encoder.params().clone().into_boxed(),
                part: 0,
                total_size: request.len() as i64,
                data: encoder.encode(&mut seqno).unwrap(),
                seqno: seqno as i32,
            };
            let wire =
                serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
            nodes[0]
                .send_custom(
                    &TaggedByteSlice {
                        object: &wire,
                        #[cfg(feature = "telemetry")]
                        tag: 0,
                    },
                    &attacker_peers,
                )
                .await
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while packets.transfers.lock().unwrap().len() < worker_count
                || rldps[1].allocated.response_lifecycle.0.load(Ordering::Acquire) < 8
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("every silent response must reach an actual sender worker");
        assert_eq!(rldps[1].allocated.send_transfers.load(Ordering::Acquire), 8);
        let healthy = nodes[2].key_by_tag(0).unwrap();
        let server = nodes[1].key_by_tag(0).unwrap();
        let peers = AdnlPeers::with_keys(healthy.id().clone(), server.id().clone());
        let data = TaggedByteSlice {
            object: &query_bytes,
            #[cfg(feature = "telemetry")]
            tag: 0,
        };
        let (answer, _) = tokio::time::timeout(
            Duration::from_secs(12),
            rldps[2].query(&data, Some(1024), &peers, true, None),
        )
        .await
        .expect("healthy query must finish")
        .expect("silent peer starved the healthy query");
        assert_eq!(answer.unwrap(), vec![42; 64]);
        for id in packets.transfers.lock().unwrap().iter() {
            let id: [u8; 32] = id.as_slice().try_into().unwrap();
            assert!(
                matches!(
                    rldps[1]
                        .peers
                        .find_v2(attacker_peers.other(), attacker_peers.local())
                        .unwrap()
                        .transfers
                        .get(&id)
                        .unwrap()
                        .val(),
                    super::RldpTransfer::Send(_)
                ),
                "healthy progress must not evict the silent peer's valid responses"
            );
        }
    })
    .catch_unwind()
    .await;
    packets.drop_parts.store(false, Ordering::Release);
    let stopped = futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await;
    for result in stopped {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sixteen_large_silent_responses_retain_initialized_encoders() {
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_retained_encoder_context.tsv").trim(),
        "16 60 10 262144 524288"
    );
    use rtos_api::{ton::rldp, IntoBoxed, RldpChunk};
    let (reply, packets, nodes, rldps, attacker_peers) = topology(3).await;
    let outcome = std::panic::AssertUnwindSafe(async {
        packets.drop_parts.store(true, Ordering::Release);
        reply.response_bytes.store(262144, Ordering::Release);
        let worker_count = 16;
        let query_bytes = serialize_boxed(&Query { overlay: UInt256::default() }).unwrap();
        // Authenticated raw requests advertise a 60s wire deadline and never
        // acknowledge responses; the ordinary client API fixes its own at10s.
        for index in 0..16 {
            let request = serialize_boxed(
                &rldp::message::Query {
                    query_id: UInt256::from([80 + index as u8; 32]),
                    max_answer_size: 524288,
                    timeout: super::Version::get() + 60,
                    data: query_bytes.clone(),
                }
                .into_boxed(),
            )
            .unwrap();
            let mut encoder = crate::RaptorqEncoder::with_data(&request, None);
            let mut seqno = 0;
            let chunk = RldpChunk {
                transfer_id: UInt256::from({ let mut id = [120; 32]; id[0] = index as u8; id }),
                fec_type: encoder.params().clone().into_boxed(),
                part: 0,
                total_size: request.len() as i64,
                data: encoder.encode(&mut seqno).unwrap(),
                seqno: seqno as i32,
            };
            let wire =
                serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
            nodes[0]
                .send_custom(
                    &TaggedByteSlice {
                        object: &wire,
                        #[cfg(feature = "telemetry")]
                        tag: 0,
                    },
                    &attacker_peers,
                )
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                while rldps[1].allocated.response_lifecycle.0.load(Ordering::Acquire) < index + 1 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }).await.expect("raw query must reach responder before next query");
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while packets.transfers.lock().unwrap().len() < worker_count
                || rldps[1].allocated.response_lifecycle.0.load(Ordering::Acquire) < 16
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|e| panic!("{e}: observed={} started={} live={}", packets.transfers.lock().unwrap().len(), rldps[1].allocated.response_lifecycle.0.load(Ordering::Acquire), rldps[1].allocated.send_transfers.load(Ordering::Acquire)));
        assert_eq!(rldps[1].allocated.send_transfers.load(Ordering::Acquire), 16);
        eprintln!("ENCODER_PROBE: 16 distinct response packets observed; 16 live senders; payload bytes=262144 each");
        let healthy = nodes[2].key_by_tag(0).unwrap();
        let server = nodes[1].key_by_tag(0).unwrap();
        let peers = AdnlPeers::with_keys(healthy.id().clone(), server.id().clone());
        let data = TaggedByteSlice {
            object: &query_bytes,
            #[cfg(feature = "telemetry")]
            tag: 0,
        };
        let (answer, _) = tokio::time::timeout(
            Duration::from_secs(12),
            rldps[2].query(&data, Some(524288), &peers, true, None),
        )
        .await
        .expect("healthy query must finish")
        .expect("silent peer starved the healthy query");
        assert_eq!(answer.unwrap(), vec![42; 262144]);
        for id in packets.transfers.lock().unwrap().iter() {
            let id: [u8; 32] = id.as_slice().try_into().unwrap();
            assert!(
                matches!(rldps[1].peers.find_v2(attacker_peers.other(), attacker_peers.local()).unwrap().transfers.get(&id).unwrap().val(), super::RldpTransfer::Send(_)),
                "healthy progress must not evict the silent peer's valid responses"
            );
        }
    })
    .catch_unwind()
    .await;
    packets.drop_parts.store(false, Ordering::Release);
    let stopped = futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await;
    for result in stopped {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_outbound_count_matches_native_256() {
    outbound_count_boundary(OutboundBoundary::Count).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_outbound_admission_isolated_by_local_identity() {
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_local_identity_context.tsv").trim(),
        "256 1 64 60"
    );
    outbound_count_boundary(OutboundBoundary::LocalIdentity).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_outbound_ack_releases_exactly_one_slot() {
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_ack_reuse_context.tsv").trim(),
        "257 64 60"
    );
    outbound_count_boundary(OutboundBoundary::AckReuse).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_refused_query_keeps_deadline_without_implicit_retry() {
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_refused_query_context.tsv").trim(),
        "256 60 10 64 1024"
    );
    outbound_count_boundary(OutboundBoundary::RefusedQuery).await;
}

enum OutboundBoundary {
    Count,
    LocalIdentity,
    AckReuse,
    RefusedQuery,
}

async fn outbound_count_boundary(mode: OutboundBoundary) {
    let second_local = matches!(mode, OutboundBoundary::LocalIdentity);
    let ack_reuse = matches!(mode, OutboundBoundary::AckReuse);
    let refused_query = matches!(mode, OutboundBoundary::RefusedQuery);
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_outbound_count_context.tsv").trim(),
        "257"
    );
    use rtos_api::{ton::rldp, IntoBoxed, RldpChunk};
    let (reply, packets, nodes, rldps, attacker_peers) = topology(3).await;
    let mut checked_peer = None;
    let outcome = std::panic::AssertUnwindSafe(async {
        packets.drop_parts.store(true, Ordering::Release);
        reply.response_bytes.store(64, Ordering::Release);
        let worker_count = 256;
        let query_bytes = serialize_boxed(&Query { overlay: UInt256::default() }).unwrap();
        // Authenticated raw requests advertise a 60s wire deadline and never
        // acknowledge responses; the ordinary client API fixes its own at10s.
        let request_count = if refused_query { 256 } else { 257 };
        for index in 0..request_count {
            let request = serialize_boxed(
                &rldp::message::Query {
                    query_id: UInt256::from({
                        let mut id = [80; 32];
                        id[..4].copy_from_slice(&(index as u32).to_le_bytes());
                        id
                    }),
                    max_answer_size: 1024,
                    timeout: super::Version::get() + 60,
                    data: query_bytes.clone(),
                }
                .into_boxed(),
            )
            .unwrap();
            let mut encoder = crate::RaptorqEncoder::with_data(&request, None);
            let mut seqno = 0;
            let chunk = RldpChunk {
                transfer_id: UInt256::from({
                    let mut id = [120; 32];
                    id[..4].copy_from_slice(&(index as u32).to_le_bytes());
                    id
                }),
                fec_type: encoder.params().clone().into_boxed(),
                part: 0,
                total_size: request.len() as i64,
                data: encoder.encode(&mut seqno).unwrap(),
                seqno: seqno as i32,
            };
            let wire =
                serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
            nodes[0]
                .send_custom(
                    &TaggedByteSlice {
                        object: &wire,
                        #[cfg(feature = "telemetry")]
                        tag: 0,
                    },
                    &attacker_peers,
                )
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                while reply.calls.load(Ordering::Acquire) < index + 1 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("raw query must reach responder before next query");
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while packets.transfers.lock().unwrap().len() < worker_count
                || rldps[1].allocated.response_lifecycle.0.load(Ordering::Acquire) < 256
                || rldps[1].allocated.response_lifecycle.1.load(Ordering::Acquire) < (request_count - 256) as u64
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|e| {
            panic!(
                "{e}: observed={} started={} live={}",
                packets.transfers.lock().unwrap().len(),
                rldps[1].allocated.response_lifecycle.0.load(Ordering::Acquire),
                rldps[1].allocated.send_transfers.load(Ordering::Acquire)
            )
        });
        assert_eq!(rldps[1].allocated.send_transfers.load(Ordering::Acquire), 256);
        assert_eq!(
            rldps[1].allocated.response_lifecycle.0.load(Ordering::Acquire),
            256,
            "native admits only 256 concurrent outbound transfers per connection"
        );
        if refused_query {
            let server = nodes[1].key_by_tag(0).unwrap();
            let client = nodes[0].key_by_tag(0).unwrap();
            let reverse = AdnlPeers::with_keys(server.id().clone(), client.id().clone());
            let peer = rldps[1].get_peer(server.id(), client.id(), true, None).await.unwrap();
            assert_eq!(peer.transfer_slots.available_permits(), 0);
            let saturated = rldps[1].allocated.send_transfers.load(Ordering::Acquire);
            let request = TaggedByteSlice { object: &query_bytes, #[cfg(feature = "telemetry")] tag: 0 };
            let started = tokio::time::Instant::now();
            let query = rldps[1].query(&request, Some(1024), &reverse, true, None);
            tokio::pin!(query);
            // Poll on this task: once it yields with the outbound lease held,
            // no concurrent poll can race freeing the saturated transfer slots.
            assert!(futures::poll!(query.as_mut()).is_pending());
            assert_eq!(peer.outbound_semaphore.available_permits(), 2);
            assert_eq!(reply.calls.load(Ordering::Acquire), 256);
            packets.drop_parts.store(false, Ordering::Release);
            let drain = tokio::time::timeout(Duration::from_secs(5), async {
                while peer.transfer_slots.available_permits() != 256 || rldps[1].allocated.send_transfers.load(Ordering::Acquire) != 0 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            });
            tokio::select! {
                biased;
                result = query.as_mut() => panic!("refused query completed while slots drained: {result:?}"),
                result = drain => result.expect("silent responses must drain before the refused query deadline"),
            }
            let drained_before_deadline = started.elapsed() < Duration::from_secs(9);
            assert!(drained_before_deadline);
            let result = tokio::time::timeout(Duration::from_secs(12), query.as_mut()).await.expect("refused query must terminate");
            let elapsed_ms = started.elapsed().as_millis();
            let timed_out = result.unwrap_err().downcast_ref::<RldpQueryTimeout>().is_some();
            assert!(timed_out);
            assert!((9500..13000).contains(&elapsed_ms), "elapsed={elapsed_ms}");
            let implicit_retry = reply.calls.load(Ordering::Acquire) != 256;
            assert!(!implicit_retry, "refused query was implicitly retried");
            let (answer, _) = rldps[1].query(&request, Some(1024), &reverse, true, None).await.unwrap();
            let answer = answer.unwrap();
            assert_eq!(answer, vec![42; 64]);
            assert_eq!(reply.calls.load(Ordering::Acquire), 257);
            checked_peer = Some(peer);
            let actual = serde_json::json!({
                "saturated": saturated, "drained_before_deadline": drained_before_deadline,
                "timeout": timed_out, "implicit_retry": implicit_retry, "fresh_answer_bytes": answer.len(),
            });
            assert_eq!(actual, refused_query_native_effects());
            eprintln!("REFUSED_QUERY_EFFECTS: {actual} elapsed_ms={elapsed_ms}");
            return;
        }
        let mut completed_id = None;
        if ack_reuse {
            let server = nodes[1].key_by_tag(0).unwrap();
            let client = nodes[0].key_by_tag(0).unwrap();
            let peer = rldps[1].get_peer(server.id(), client.id(), true, None).await.unwrap();
            assert_eq!(peer.transfer_slots.available_permits(), 0);
            let initial = rldps[1].allocated.send_transfers.load(Ordering::Acquire);
            let id: [u8; 32] = packets
                .transfers
                .lock()
                .unwrap()
                .iter()
                .next()
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap();
            completed_id = Some(id);
            let completed_state = rldps[1].get_v2_state(&id, 0, &AdnlPeers::with_keys(server.id().clone(), client.id().clone())).unwrap();
            let ack = serialize_boxed(
                &rldp2::messagepart::Complete { transfer_id: UInt256::from(id), part: 0 }
                    .into_boxed(),
            )
            .unwrap();
            nodes[0]
                .send_custom(
                    &TaggedByteSlice {
                        object: &ack,
                        #[cfg(feature = "telemetry")]
                        tag: 0,
                    },
                    &attacker_peers,
                )
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                while completed_state.is_finished().is_none() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("actual completion must mark the acknowledged part successful");
            assert_eq!(completed_state.is_finished(), Some(true), "ACK must complete successfully");
            let completed = u64::from(completed_state.is_finished() == Some(true));
            // The allocation counter includes this part state. Release our
            // observer before asserting that its actual allocation was freed.
            drop(completed_state);
            tokio::time::timeout(Duration::from_secs(5), async {
                while peer.transfer_slots.available_permits() != 1
                    || rldps[1].allocated.send_transfers.load(Ordering::Acquire) != 255
                    || rldps[1].allocated.response_lifecycle.1.load(Ordering::Acquire) != 2
                {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("actual completion must release one sender and admission slot");
            assert!(rldps[1].peers.find_v2(attacker_peers.other(), attacker_peers.local()).unwrap().transfers.get(&id).is_none(), "completed sender must retire");
            let after_ack = rldps[1].allocated.send_transfers.load(Ordering::Acquire);

            let request = serialize_boxed(
                &rldp::message::Query {
                    query_id: UInt256::from([72; 32]),
                    max_answer_size: 1024,
                    timeout: super::Version::get() + 60,
                    data: query_bytes.clone(),
                }
                .into_boxed(),
            )
            .unwrap();
            let mut encoder = crate::RaptorqEncoder::with_data(&request, None);
            let mut seqno = 0;
            let chunk = RldpChunk {
                transfer_id: UInt256::from([73; 32]),
                fec_type: encoder.params().clone().into_boxed(),
                part: 0,
                total_size: request.len() as i64,
                data: encoder.encode(&mut seqno).unwrap(),
                seqno: seqno as i32,
            };
            let wire =
                serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
            nodes[0]
                .send_custom(
                    &TaggedByteSlice {
                        object: &wire,
                        #[cfg(feature = "telemetry")]
                        tag: 0,
                    },
                    &attacker_peers,
                )
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                while rldps[1].allocated.response_lifecycle.0.load(Ordering::Acquire) != 257
                    || packets.transfers.lock().unwrap().len() != 257
                {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("replacement must use the freed slot and reach the wire");
            assert_eq!(peer.transfer_slots.available_permits(), 0);
            assert_eq!(rldps[1].allocated.send_transfers.load(Ordering::Acquire), 256);
            let after_replacement = rldps[1].allocated.send_transfers.load(Ordering::Acquire);
            let started = rldps[1].allocated.response_lifecycle.0.load(Ordering::Acquire);
            // Re-enter the authenticated custom-message handler synchronously,
            // so duplicate-ACK assertions do not depend on a UDP sleep window.
            let reverse = AdnlPeers::with_keys(server.id().clone(), client.id().clone());
            assert!(rldps[1].try_consume_custom(&ack, &reverse).await.unwrap());
            assert_eq!(peer.transfer_slots.available_permits(), 0);
            assert_eq!(rldps[1].allocated.send_transfers.load(Ordering::Acquire), 256);
            let actual = serde_json::json!({
                "initial": initial, "after_ack": after_ack,
                "after_replacement": after_replacement, "started": started,
                "completed": completed,
                "duplicate_ack_retained": rldps[1].allocated.send_transfers.load(Ordering::Acquire),
            });
            assert_eq!(actual, ack_reuse_native_effects());
            eprintln!("ACK_REUSE_EFFECTS: {actual}");
            checked_peer = Some(peer);
        }
        if second_local {
            let local = nodes[1].key_by_tag(1).unwrap();
            let remote = nodes[0].key_by_tag(0).unwrap();
            nodes[0].add_peer(remote.id(), nodes[1].ip_address_adnl(), None, &local).unwrap();
            nodes[1].add_peer(local.id(), nodes[0].ip_address_adnl(), None, &remote).unwrap();
            let route = AdnlPeers::with_keys(remote.id().clone(), local.id().clone());
            let request = serialize_boxed(
                &rldp::message::Query {
                    query_id: UInt256::from([19; 32]),
                    max_answer_size: 1024,
                    timeout: super::Version::get() + 60,
                    data: query_bytes.clone(),
                }
                .into_boxed(),
            )
            .unwrap();
            let mut encoder = crate::RaptorqEncoder::with_data(&request, None);
            let mut seqno = 0;
            let chunk = RldpChunk {
                transfer_id: UInt256::from([51; 32]),
                fec_type: encoder.params().clone().into_boxed(),
                part: 0,
                total_size: request.len() as i64,
                data: encoder.encode(&mut seqno).unwrap(),
                seqno: seqno as i32,
            };
            let wire =
                serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
            nodes[0]
                .send_custom(
                    &TaggedByteSlice {
                        object: &wire,
                        #[cfg(feature = "telemetry")]
                        tag: 0,
                    },
                    &route,
                )
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                while reply.calls.load(Ordering::Acquire) < 258 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("second local identity must receive authenticated query");
            tokio::time::timeout(Duration::from_secs(5), async {
                while rldps[1].allocated.response_lifecycle.0.load(Ordering::Acquire) < 257
                    && rldps[1].allocated.response_lifecycle.1.load(Ordering::Acquire) < 2
                {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("second handler must start a sender or finish refusing");
            assert_eq!(
                rldps[1].allocated.response_lifecycle.0.load(Ordering::Acquire),
                257,
                "one saturated local identity must not consume another identity's admission"
            );
        }
        let healthy = nodes[2].key_by_tag(0).unwrap();
        let server = nodes[1].key_by_tag(0).unwrap();
        let peers = AdnlPeers::with_keys(healthy.id().clone(), server.id().clone());
        let data = TaggedByteSlice {
            object: &query_bytes,
            #[cfg(feature = "telemetry")]
            tag: 0,
        };
        let (answer, _) = tokio::time::timeout(
            Duration::from_secs(12),
            rldps[2].query(&data, Some(1024), &peers, true, None),
        )
        .await
        .expect("healthy query must finish")
        .expect("silent peer starved the healthy query");
        assert_eq!(answer.unwrap(), vec![42; 64]);
        for id in packets.transfers.lock().unwrap().iter() {
            let id: [u8; 32] = id.as_slice().try_into().unwrap();
            if completed_id == Some(id) {
                continue;
            }
            let still_sending = (0..=u8::from(second_local)).any(|tag| {
                let local = nodes[1].key_by_tag(tag as usize).unwrap();
                rldps[1].peers.find_v2(local.id(), attacker_peers.local()).is_some_and(|peer| {
                    peer.transfers.get(&id).is_some_and(|entry| matches!(entry.val(), super::RldpTransfer::Send(_)))
                })
            });
            assert!(
                still_sending,
                "healthy progress must not evict the silent peer's valid responses"
            );
        }
    })
    .catch_unwind()
    .await;
    packets.drop_parts.store(false, Ordering::Release);
    let stopped = futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await;
    for result in stopped {
        result.unwrap();
    }
    if let Some(peer) = checked_peer {
        assert_eq!(
            peer.transfer_slots.available_permits(),
            256,
            "shutdown must restore every sender slot"
        );
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_connection_count_matches_native_global_cap() {
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_connection_count_context.tsv").trim(),
        "4097"
    );
    let (_, _, nodes, rldps, _) = topology(2).await;
    let outcome = std::panic::AssertUnwindSafe(async {
        let local = nodes[0].key_by_tag(0).unwrap();
        tokio::time::timeout(Duration::from_secs(30), async {
            for index in 0..4097u32 {
                let mut id = [0; 32];
                id[..4].copy_from_slice(&index.to_le_bytes());
                let route =
                    AdnlPeers::with_keys(local.id().clone(), rtos_block::KeyId::from_data(id));
                let result = rldps[0]
                    .message(
                        &TaggedByteSlice {
                            object: b"x",
                            #[cfg(feature = "telemetry")]
                            tag: 0,
                        },
                        &route,
                        true,
                        None,
                    )
                    .await;
                assert!(result.is_err(), "fabricated peer must not have an ADNL route");
            }
        })
        .await
        .expect("fabricated-route probe must finish within its bound");
        let retained = rldps[0].allocated.peers.load(Ordering::Acquire);
        eprintln!("CONNECTION_PROBE: submitted=4097 retained={retained}");
        assert!(
            retained <= 4096,
            "native retains at most4096 connections, Rust retained{retained}"
        );
    })
    .catch_unwind()
    .await;
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_connection_eviction_fails_query_and_recovers() {
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_connection_query_context.tsv").trim(),
        "4097 10 64 1024"
    );
    let (reply, _, nodes, rldps, peers) = pair().await;
    let outcome = std::panic::AssertUnwindSafe(async {
        reply.hold.store(true, Ordering::Release);
        let bytes = serialize_boxed(&Query { overlay: UInt256::default() }).unwrap();
        let data = TaggedByteSlice {
            object: &bytes,
            #[cfg(feature = "telemetry")]
            tag: 0,
        };
        let request = rldps[0].query(&data, Some(1024), &peers, true, None);
        let flood = async {
            tokio::time::timeout(Duration::from_secs(5), reply.entered.notified()).await.unwrap();
            let local = nodes[0].key_by_tag(0).unwrap();
            for index in 0..4097u32 {
                let mut id = [0; 32];
                id[..4].copy_from_slice(&index.to_le_bytes());
                let route =
                    AdnlPeers::with_keys(local.id().clone(), rtos_block::KeyId::from_data(id));
                assert!(rldps[0]
                    .message(
                        &TaggedByteSlice {
                            object: b"x",
                            #[cfg(feature = "telemetry")]
                            tag: 0
                        },
                        &route,
                        true,
                        None
                    )
                    .await
                    .is_err());
            }
            assert_eq!(rldps[0].allocated.peers.load(Ordering::Acquire), 4096);
            assert_eq!(rldps[0].peers.evicted.load(Ordering::Acquire), 2);
            reply.hold.store(false, Ordering::Release);
            reply.release.notify_one();
        };
        let (answer, ()) = tokio::join!(request, flood);
        let error = answer.unwrap_err();
        assert!(
            matches!(
                error.downcast_ref::<super::SendCancelled>(),
                Some(super::SendCancelled::PeerEvicted)
            ),
            "{error:#}"
        );
        let answer = rldps[0].query(&data, Some(1024), &peers, true, None).await.unwrap();
        assert_eq!(answer.0.unwrap(), vec![42; 64], "fresh query must recover after eviction");
    })
    .catch_unwind()
    .await;
    reply.hold.store(false, Ordering::Release);
    reply.release.notify_waiters();
    reply.release.notify_one();
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

fn ack_reuse_native_effects() -> serde_json::Value {
    let context = include_bytes!("../../../ci/conformance/rldp2_ack_reuse_context.tsv");
    let effects = include_bytes!("../../../ci/conformance/rldp2_ack_reuse_effects.json");
    let meta: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../ci/conformance/rldp2_ack_reuse_metadata.json"
    ))
    .unwrap();
    assert_eq!(meta["reference_commit"], include_str!("../../../ci/conformance/REFERENCE").trim());
    for (key, bytes) in [
        ("cases_sha256", context.as_slice()),
        ("effects_sha256", effects.as_slice()),
        (
            "probe_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_ack_reuse_reference.cpp").as_slice(),
        ),
        (
            "runner_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_runtime_reference.py").as_slice(),
        ),
    ] {
        assert_eq!(meta[key], hex::encode(rtos_block::sha256_digest(bytes)), "{key}");
    }
    serde_json::from_slice(effects).unwrap()
}

fn refused_query_native_effects() -> serde_json::Value {
    let context = include_bytes!("../../../ci/conformance/rldp2_refused_query_context.tsv");
    let effects = include_bytes!("../../../ci/conformance/rldp2_refused_query_effects.json");
    let meta: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../ci/conformance/rldp2_refused_query_metadata.json"
    ))
    .unwrap();
    assert_eq!(meta["reference_commit"], include_str!("../../../ci/conformance/REFERENCE").trim());
    for (key, bytes) in [
        ("cases_sha256", context.as_slice()),
        ("effects_sha256", effects.as_slice()),
        (
            "probe_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_refused_query_reference.cpp").as_slice(),
        ),
        (
            "runner_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_runtime_reference.py").as_slice(),
        ),
    ] {
        assert_eq!(meta[key], hex::encode(rtos_block::sha256_digest(bytes)), "{key}");
    }
    let mut effects: serde_json::Value = serde_json::from_slice(effects).unwrap();
    let elapsed = effects.as_object_mut().unwrap().remove("elapsed_ms").unwrap().as_u64().unwrap();
    assert!((9500..13000).contains(&elapsed), "native deadline outside comparison window");
    effects
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_completed_retention_matches_native_under_churn() {
    use rtos_api::{ton::rldp, IntoBoxed, RldpChunk};
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_completed_churn_context.tsv").trim(),
        "2049"
    );
    let (reply, _packets, nodes, rldps, peers) = pair().await;
    let outcome = std::panic::AssertUnwindSafe(async {
        let message = serialize_boxed(&rldp::message::Message { id: UInt256::default(), data: b"churn".to_vec() }.into_boxed()).unwrap();
        let mut encoder = crate::RaptorqEncoder::with_data(&message, None);
        let mut seqno = 0;
        let symbol = encoder.encode(&mut seqno).unwrap();
        let wire = |value: u32| {
            let mut id = [0; 32]; id[..4].copy_from_slice(&value.to_le_bytes());
            let chunk = RldpChunk { transfer_id: UInt256::from(id), fec_type: encoder.params().clone().into_boxed(), part: 0, total_size: message.len() as i64, data: symbol.clone(), seqno: seqno as i32 };
            serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap()
        };
        let started = tokio::time::Instant::now();
        for value in 0..2049u32 {
            let wire = wire(value);
            nodes[0].send_custom(&TaggedByteSlice { object: &wire, #[cfg(feature = "telemetry")] tag: 0 }, &peers).await.unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                while reply.messages.load(Ordering::Acquire) < value as usize + 1 { reply.message_received.notified().await; }
            }).await.expect("unique message did not reach actual subscriber");
        }
        assert!(started.elapsed() < Duration::from_secs(10), "churn must precede20s expiry");
        let unique_delivered = reply.messages.load(Ordering::Acquire);
        assert_eq!(unique_delivered, 2049);
        let remembered = rldps[1].peers.find_v2(peers.other(), peers.local()).unwrap().inbound_transfers.iter().filter(|entry| matches!(entry.val(), super::RldpTransfer::Done)).count();
        assert_eq!(remembered, 2048, "native bounds completed IDs independently of time");
        let oldest = wire(0);
        nodes[0].send_custom(&TaggedByteSlice { object: &oldest, #[cfg(feature = "telemetry")] tag: 0 }, &peers).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while reply.messages.load(Ordering::Acquire) < 2050 { reply.message_received.notified().await; }
        }).await.expect("native reassembles oldest ID after cache eviction");
        let oldest_replayed = reply.messages.load(Ordering::Acquire) == 2050;
        // A remembered ID is suppressed synchronously by the normal handler.
        let reverse = AdnlPeers::with_keys(peers.other().clone(), peers.local().clone());
        assert!(rldps[1].try_consume_custom(&wire(2048), &reverse).await.unwrap());
        let delivered = reply.messages.load(Ordering::Acquire);
        let actual = serde_json::json!({"unique_delivered":unique_delivered,"remembered":remembered,"oldest_replayed":oldest_replayed,"recent_suppressed":delivered==2050,"delivered":delivered});
        assert_eq!(actual, completed_churn_native_effects());
        tokio::time::timeout(Duration::from_secs(5), async {
            while rldps[1].allocated.recv_transfers.load(Ordering::Acquire) != 0 { tokio::task::yield_now().await; }
        }).await.expect("completed receivers must release their payload/context without a20s timer");
        eprintln!("COMPLETED_CHURN_FINAL: {actual} live_receivers=0 elapsed_ms={}", started.elapsed().as_millis());
    }).catch_unwind().await;
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

fn completed_churn_native_effects() -> serde_json::Value {
    let context = include_bytes!("../../../ci/conformance/rldp2_completed_churn_context.tsv");
    let effects = include_bytes!("../../../ci/conformance/rldp2_completed_churn_effects.json");
    let meta: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../ci/conformance/rldp2_completed_churn_metadata.json"
    ))
    .unwrap();
    assert_eq!(meta["reference_commit"], include_str!("../../../ci/conformance/REFERENCE").trim());
    for (key, bytes) in [
        ("cases_sha256", context.as_slice()),
        ("effects_sha256", effects.as_slice()),
        (
            "probe_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_completed_churn_reference.cpp")
                .as_slice(),
        ),
        (
            "runner_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_runtime_reference.py").as_slice(),
        ),
    ] {
        assert_eq!(meta[key], hex::encode(rtos_block::sha256_digest(bytes)), "{key}");
    }
    serde_json::from_slice(effects).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_solicited_replies_share_native_completed_bound() {
    let (_reply, _packets, nodes, rldps, peers) = pair().await;
    let outcome = std::panic::AssertUnwindSafe(async {
        let bytes = serialize_boxed(&Query { overlay: UInt256::default() }).unwrap();
        let query = TaggedByteSlice {
            object: &bytes,
            #[cfg(feature = "telemetry")]
            tag: 0,
        };
        let peer = rldps[0].get_peer(peers.local(), peers.other(), true, None).await.unwrap();
        let started = tokio::time::Instant::now();
        for value in 0..2049usize {
            let (answer, _) = rldps[0].query(&query, Some(1024), &peers, true, None).await.unwrap();
            assert_eq!(answer, Some(vec![42; 64]), "query {value} must return its answer");
            if [0, 127, 128, 2047, 2048].contains(&value) {
                assert_eq!(peer.completed.lock().unwrap().len(), (value + 1).min(2048));
            }
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "must observe the count bound before TTL pruning"
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            while rldps[0].allocated.recv_transfers.load(Ordering::Acquire) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        eprintln!(
            "SOLICITED_CHURN: replies=2049 remembered=2048 live_receivers=0 elapsed_ms={}",
            started.elapsed().as_millis()
        );
    })
    .catch_unwind()
    .await;
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_outbound_completion_retires_sender_ids() {
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_outbound_retirement_context.tsv").trim(),
        "2049\t64\t60"
    );
    let (reply, _packets, nodes, rldps, peers) = pair().await;
    let outcome = std::panic::AssertUnwindSafe(async {
        let bytes = serialize_boxed(&Query { overlay: UInt256::default() }).unwrap();
        let query = TaggedByteSlice {
            object: &bytes,
            #[cfg(feature = "telemetry")]
            tag: 0,
        };
        let peer = rldps[0].get_peer(peers.local(), peers.other(), true, None).await.unwrap();
        let started = tokio::time::Instant::now();
        for value in 0..2049usize {
            let (answer, _) = rldps[0].query(&query, Some(1024), &peers, true, None).await.unwrap();
            assert_eq!(answer.unwrap(), vec![42; 64]);
            if [0, 127, 128, 2047, 2048].contains(&value) {
                assert_eq!(peer.completed.lock().unwrap().len(), (value + 1).min(2048));
            }
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "must observe the count bound before TTL pruning"
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            while rldps[0].allocated.recv_transfers.load(Ordering::Acquire) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        for node in &rldps {
            tokio::time::timeout(Duration::from_secs(5), async {
                while node.allocated.send_transfers.load(Ordering::Acquire) != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
        let other = rldps[1].get_peer(peers.other(), peers.local(), true, None).await.unwrap();
        let expected = outbound_retirement_native_effects();
        // Admission is released just before the final sender registration.
        // The response-handler receipt is published after both have drained.
        tokio::time::timeout(Duration::from_secs(5), async {
            while rldps[1].allocated.response_lifecycle.1.load(Ordering::Acquire) != 2049 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("all response handlers must observe actual sender completion");
        assert_eq!(reply.calls.load(Ordering::Acquire), 2049);
        for (side, peer) in [peer, other].iter().enumerate() {
            tokio::time::timeout(Duration::from_secs(5), async {
                while peer.transfer_slots.available_permits() != 256 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let retained =
                peer.registrations.lock().unwrap().len() - peer.completed.lock().unwrap().len();
            eprintln!(
                "OUTBOUND_RETIREMENT: side={side} completed=2049 outbound_retained={retained}"
            );
            assert_eq!(
                retained,
                expected["outbound_retained"].as_u64().unwrap() as usize,
                "completed outbound IDs must retire with actual senders"
            );
            assert_eq!(
                reply.calls.load(Ordering::Acquire),
                expected["completed"].as_u64().unwrap() as usize
            );
        }
    })
    .catch_unwind()
    .await;
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

fn outbound_retirement_native_effects() -> serde_json::Value {
    let context = include_bytes!("../../../ci/conformance/rldp2_outbound_retirement_context.tsv");
    let effects = include_bytes!("../../../ci/conformance/rldp2_outbound_retirement_effects.json");
    let meta: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../ci/conformance/rldp2_outbound_retirement_metadata.json"
    ))
    .unwrap();
    assert_eq!(meta["reference_commit"], include_str!("../../../ci/conformance/REFERENCE").trim());
    for (key, bytes) in [
        ("cases_sha256", context.as_slice()),
        ("effects_sha256", effects.as_slice()),
        (
            "probe_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_outbound_retirement_reference.cpp")
                .as_slice(),
        ),
        (
            "runner_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_runtime_reference.py").as_slice(),
        ),
    ] {
        assert_eq!(meta[key], hex::encode(rtos_block::sha256_digest(bytes)), "{key}");
    }
    serde_json::from_slice(effects).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_same_transfer_id_isolated_by_connection() {
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_transfer_identity_context.tsv").trim(),
        "3"
    );
    use rtos_api::{ton::rldp, IntoBoxed, RldpChunk};
    let (reply, _packets, nodes, rldps, peers) = topology(3).await;
    let outcome = std::panic::AssertUnwindSafe(async {
        let local = nodes[1].key_by_tag(1).unwrap();
        let remote = nodes[0].key_by_tag(0).unwrap();
        nodes[0].add_peer(remote.id(), nodes[1].ip_address_adnl(), None, &local).unwrap();
        nodes[1].add_peer(local.id(), nodes[0].ip_address_adnl(), None, &remote).unwrap();
        let routes = [
            (0, peers.clone()),
            (2, AdnlPeers::with_keys(nodes[2].key_by_tag(0).unwrap().id().clone(), peers.other().clone())),
            (0, AdnlPeers::with_keys(remote.id().clone(), local.id().clone())),
        ];
        let message = serialize_boxed(&rldp::message::Message { id: UInt256::default(), data: b"churn".to_vec() }.into_boxed()).unwrap();
        let mut encoder = crate::RaptorqEncoder::with_data(&message, None);
        let mut seqno = 0;
        let chunk = RldpChunk { transfer_id: UInt256::default(), fec_type: encoder.params().clone().into_boxed(), part: 0, total_size: message.len() as i64, data: encoder.encode(&mut seqno).unwrap(), seqno: seqno as i32 };
        let wire = serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
        for (index, (sender, route)) in routes.iter().enumerate() {
            nodes[*sender].send_custom(&TaggedByteSlice { object: &wire, #[cfg(feature = "telemetry")] tag: 0 }, route).await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                while reply.messages.load(Ordering::Acquire) < index + 1 { reply.message_received.notified().await; }
            }).await.expect("same transfer ID on another authenticated connection must deliver independently");
        }
        let mut remembered = Vec::new();
        for (_, route) in &routes {
            let reverse = AdnlPeers::with_keys(route.other().clone(), route.local().clone());
            assert!(rldps[1].try_consume_custom(&wire, &reverse).await.unwrap());
            let peer = rldps[1].get_peer(reverse.local(), reverse.other(), true, None).await.unwrap();
            remembered.push(peer.completed.lock().unwrap().len());
        }
        // Same outgoing ID on all three connections: one connection's ACK
        // must finish only its own part. Real UDP above validates route identity;
        // this phase drives the normal authenticated handler synchronously.
        let mut senders = Vec::new();
        let mut states = Vec::new();
        for (_, route) in &routes {
            let peer = rldps[1].get_peer(route.other(), route.local(), true, None).await.unwrap();
            let (ping, _pong) = tokio::sync::mpsc::unbounded_channel();
            let (sender, state) = super::SendTransfer::new(vec![42u8; 64].into(), [7; 32], rldps[1].allocated.send_transfers.clone(), ping, true).unwrap();
            let super::SendTransferState::V2(parts) = &state else { unreachable!() };
            states.push(parts[0].clone());
            peer.insert_transfer(&peer.transfers, [7; 32], super::RldpTransfer::sender(state)).unwrap();
            senders.push(sender);
        }
        let ack = serialize_boxed(&rldp2::messagepart::Complete { transfer_id: UInt256::from([7; 32]), part: 0 }.into_boxed()).unwrap();
        let mut ack_pending = Vec::new();
        for (index, (_, route)) in routes.iter().enumerate() {
            let reverse = AdnlPeers::with_keys(route.other().clone(), route.local().clone());
            for _ in 0..2 {
                assert!(rldps[1].try_consume_custom(&ack, &reverse).await.unwrap());
                let finished: Vec<_> = states.iter().map(|state| state.is_finished()).collect();
                let expected: Vec<_> = (0..3).map(|other| if other <= index { Some(true) } else { None }).collect();
                assert_eq!(finished, expected, "ACK must affect only its own connection");
            }
            ack_pending.push(states.iter().map(|state| usize::from(state.is_finished() != Some(true))).collect::<Vec<_>>());
        }
        let actual = serde_json::json!({"delivered":reply.messages.load(Ordering::Acquire),"remembered":remembered,"duplicates_suppressed":reply.messages.load(Ordering::Acquire)==3,"ack_pending":ack_pending});
        eprintln!("TRANSFER_IDENTITY: {actual}");
        assert_eq!(actual, transfer_identity_native_effects());
    }).catch_unwind().await;
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    assert_eq!(rldps[1].allocated.send_transfers.load(Ordering::Acquire), 0);
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

fn transfer_identity_native_effects() -> serde_json::Value {
    let context = include_bytes!("../../../ci/conformance/rldp2_transfer_identity_context.tsv");
    let effects = include_bytes!("../../../ci/conformance/rldp2_transfer_identity_effects.json");
    let meta: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../ci/conformance/rldp2_transfer_identity_metadata.json"
    ))
    .unwrap();
    assert_eq!(meta["reference_commit"], include_str!("../../../ci/conformance/REFERENCE").trim());
    for (key, bytes) in [
        ("cases_sha256", context.as_slice()),
        ("effects_sha256", effects.as_slice()),
        (
            "probe_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_transfer_identity_reference.cpp")
                .as_slice(),
        ),
        (
            "runner_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_runtime_reference.py").as_slice(),
        ),
    ] {
        assert_eq!(meta[key], hex::encode(rtos_block::sha256_digest(bytes)), "{key}");
    }
    serde_json::from_slice(effects).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_replayed_query_does_not_replace_active_response() {
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_outbound_id_reuse_context.tsv").trim(),
        "64\t65\t60"
    );
    use rtos_api::{ton::rldp, IntoBoxed, RldpChunk};
    fn wire(data: &[u8], id: [u8; 32]) -> Vec<u8> {
        let mut encoder = crate::RaptorqEncoder::with_data(data, None);
        let mut seqno = 0;
        let chunk = RldpChunk {
            transfer_id: UInt256::from(id),
            fec_type: encoder.params().clone().into_boxed(),
            part: 0,
            total_size: data.len() as i64,
            data: encoder.encode(&mut seqno).unwrap(),
            seqno: seqno as i32,
        };
        serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap()
    }
    let (reply, packets, nodes, rldps, peers) = pair().await;
    packets.drop_parts.store(true, Ordering::Release);
    let outcome = std::panic::AssertUnwindSafe(async {
        let request = serialize_boxed(&rldp::message::Query { query_id: UInt256::from([9;32]), max_answer_size: 1024, timeout: super::Version::get()+60, data: serialize_boxed(&Query { overlay: UInt256::default() }).unwrap() }.into_boxed()).unwrap();
        let request = wire(&request, [248;32]);
        fn tagged(bytes: &[u8]) -> TaggedByteSlice<'_> { TaggedByteSlice { object: bytes, #[cfg(feature = "telemetry")] tag: 0 } }
        nodes[0].send_custom(&tagged(&request), &peers).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while rldps[1].allocated.response_lifecycle.0.load(Ordering::Acquire) != 1 || packets.transfers.lock().unwrap().len() != 1 { tokio::task::yield_now().await; }
        }).await.expect("original response must reach the wire and remain unacknowledged");
        let reverse = AdnlPeers::with_keys(peers.other().clone(), peers.local().clone());
        let peer = rldps[1].get_peer(reverse.local(), reverse.other(), true, None).await.unwrap();
        let original = rldps[1].get_v2_state(&[7;32], 0, &reverse).unwrap();
        assert_eq!(original.is_finished(), None);
        let before = rldps[1].allocated.response_lifecycle.0.load(Ordering::Acquire);
        let churn = serialize_boxed(&rldp::message::Message { id: UInt256::default(), data: b"churn".to_vec() }.into_boxed()).unwrap();
        for value in 0..2048u32 {
            let mut id = [0;32]; id[..4].copy_from_slice(&value.to_le_bytes());
            let chunk = wire(&churn, id);
            nodes[0].send_custom(&tagged(&chunk), &peers).await.unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                while reply.messages.load(Ordering::Acquire) != value as usize + 1 { reply.message_received.notified().await; }
            }).await.unwrap();
        }
        assert!(!peer.completed.lock().unwrap().iter().any(|(id,_)| *id == [248;32]));
        assert_eq!(original.is_finished(), None, "original response must still be active before replay");
        reply.response_bytes.store(65, Ordering::Release);
        nodes[0].send_custom(&tagged(&request), &peers).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while reply.calls.load(Ordering::Acquire) != 2 ||
                (rldps[1].allocated.response_lifecycle.0.load(Ordering::Acquire) == 1 && rldps[1].allocated.response_lifecycle.1.load(Ordering::Acquire) < 2049) { tokio::task::yield_now().await; }
        }).await.expect("replayed query must attempt a response or finish refusing it");
        let after = rldps[1].allocated.response_lifecycle.0.load(Ordering::Acquire);
        eprintln!("OUTBOUND_ID_REUSE: started_before={before} started_after_replay={after}");
        assert_eq!(after, 1, "native refuses duplicate active outbound ID before creating a replacement");
        assert!(Arc::ptr_eq(&original, &rldps[1].get_v2_state(&[7;32],0,&reverse).unwrap()));
        let ack = serialize_boxed(&rldp2::messagepart::Complete { transfer_id: UInt256::from([7;32]), part: 0 }.into_boxed()).unwrap();
        assert!(rldps[1].try_consume_custom(&ack,&reverse).await.unwrap());
        assert_eq!(original.is_finished(),Some(true));
        let completed = u64::from(original.is_finished()==Some(true));
        drop(original);
        tokio::time::timeout(Duration::from_secs(5), async {
            while rldps[1].allocated.send_transfers.load(Ordering::Acquire) != 0 || peer.transfer_slots.available_permits()!=256 { tokio::task::yield_now().await; }
        }).await.expect("original response must still ACK and drain");
        let actual=serde_json::json!({"started_before":before,"started_after_replay":after,"completed":completed,"retained":rldps[1].allocated.send_transfers.load(Ordering::Acquire)});
        eprintln!("OUTBOUND_ID_REUSE_EFFECTS: {actual}");
        assert_eq!(actual,outbound_id_reuse_native_effects());
    }).catch_unwind().await;
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

fn outbound_id_reuse_native_effects() -> serde_json::Value {
    let context = include_bytes!("../../../ci/conformance/rldp2_outbound_id_reuse_context.tsv");
    let effects = include_bytes!("../../../ci/conformance/rldp2_outbound_id_reuse_effects.json");
    let meta: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../ci/conformance/rldp2_outbound_id_reuse_metadata.json"
    ))
    .unwrap();
    assert_eq!(meta["reference_commit"], include_str!("../../../ci/conformance/REFERENCE").trim());
    for (key, bytes) in [
        ("cases_sha256", context.as_slice()),
        ("effects_sha256", effects.as_slice()),
        (
            "probe_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_outbound_id_reuse_reference.cpp")
                .as_slice(),
        ),
        (
            "runner_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_runtime_reference.py").as_slice(),
        ),
    ] {
        assert_eq!(meta[key], hex::encode(rtos_block::sha256_digest(bytes)), "{key}");
    }
    serde_json::from_slice(effects).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_inbound_id_does_not_alias_active_outbound() {
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_directional_identity_context.tsv").trim(),
        "64 60"
    );
    use rtos_api::{ton::rldp, IntoBoxed, RldpChunk};
    let (reply, _packets, nodes, rldps, peers) = pair().await;
    let outcome = std::panic::AssertUnwindSafe(async {
        let peer = rldps[1].get_peer(peers.other(), peers.local(), true, None).await.unwrap();
        let (ping, _pong) = tokio::sync::mpsc::unbounded_channel();
        let (sender, state) = super::SendTransfer::new(
            vec![42u8; 64].into(),
            [7; 32],
            rldps[1].allocated.send_transfers.clone(),
            ping,
            true,
        )
        .unwrap();
        let super::SendTransferState::V2(parts) = &state else { unreachable!() };
        let original = parts[0].clone();
        peer.insert_transfer(&peer.transfers, [7; 32], super::RldpTransfer::sender(state)).unwrap();
        let registration = super::owned_send::SendRegistration {
            _query_admission: None,
            v2: true,
            inbound: None,
            peer: Some((Arc::downgrade(&peer), peer.closed.clone())),
            transfers: peer.transfers.clone(),
            send: [7; 32],
            receive: None,
            owner: nodes[1].tasks().clone(),
            bounded_permit: None,
        };
        let message = serialize_boxed(
            &rldp::message::Message { id: UInt256::default(), data: b"churn".to_vec() }
                .into_boxed(),
        )
        .unwrap();
        let mut encoder = crate::RaptorqEncoder::with_data(&message, None);
        let mut seqno = 0;
        let chunk = RldpChunk {
            transfer_id: UInt256::from([7; 32]),
            fec_type: encoder.params().clone().into_boxed(),
            part: 0,
            total_size: message.len() as i64,
            data: encoder.encode(&mut seqno).unwrap(),
            seqno: seqno as i32,
        };
        let wire = serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
        nodes[0]
            .send_custom(
                &TaggedByteSlice {
                    object: &wire,
                    #[cfg(feature = "telemetry")]
                    tag: 0,
                },
                &peers,
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while reply.messages.load(Ordering::Acquire) != 1 {
                reply.message_received.notified().await;
            }
        })
        .await
        .expect("inbound payload must deliver despite same-ID active outbound sender");
        assert_eq!(
            original.is_finished(),
            None,
            "inbound completion must not finish outbound state"
        );
        let reverse = AdnlPeers::with_keys(peers.other().clone(), peers.local().clone());
        let ack = serialize_boxed(
            &rldp2::messagepart::Complete { transfer_id: UInt256::from([7; 32]), part: 0 }
                .into_boxed(),
        )
        .unwrap();
        assert!(rldps[1].try_consume_custom(&ack, &reverse).await.unwrap());
        assert_eq!(original.is_finished(), Some(true));
        drop(sender);
        drop(registration);
        assert!(
            peer.registrations.lock().unwrap().contains(&[7; 32]),
            "retiring sender must retain the inbound registration"
        );
        let actual = serde_json::json!({
            "delivered": reply.messages.load(Ordering::Acquire),
            "outbound_pending_after_inbound": true,
            "ack_completed": usize::from(original.is_finished() == Some(true)),
            "outbound_retained": peer.transfers.iter().count(),
            "inbound_remembered": peer.completed.lock().unwrap().len(),
        });
        assert_eq!(actual, directional_identity_native_effects());
    })
    .catch_unwind()
    .await;
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    assert_eq!(rldps[1].allocated.send_transfers.load(Ordering::Acquire), 0);
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

fn directional_identity_native_effects() -> serde_json::Value {
    let context = include_bytes!("../../../ci/conformance/rldp2_directional_identity_context.tsv");
    let effects = include_bytes!("../../../ci/conformance/rldp2_directional_identity_effects.json");
    let meta: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../ci/conformance/rldp2_directional_identity_metadata.json"
    ))
    .unwrap();
    assert_eq!(meta["reference_commit"], include_str!("../../../ci/conformance/REFERENCE").trim());
    for (key, bytes) in [
        ("cases_sha256", context.as_slice()),
        ("effects_sha256", effects.as_slice()),
        (
            "probe_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_directional_identity_reference.cpp")
                .as_slice(),
        ),
        (
            "runner_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_runtime_reference.py").as_slice(),
        ),
    ] {
        assert_eq!(meta[key], hex::encode(rtos_block::sha256_digest(bytes)), "{key}");
    }
    serde_json::from_slice(effects).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_pending_query_admission_refuses_before_waiting_for_sender() {
    use futures::StreamExt;
    let (reply, _packets, nodes, rldps, peers) = pair().await;
    let outcome = std::panic::AssertUnwindSafe(async {
        let bytes = serialize_boxed(&Query { overlay: UInt256::default() }).unwrap();
        let query = TaggedByteSlice { object: &bytes, #[cfg(feature = "telemetry")] tag: 0 };
        let (answer, _) = rldps[0].query(&query, Some(1024), &peers, true, None).await.unwrap();
        assert_eq!(answer.unwrap(), vec![42;64]);
        assert_eq!(query_admission_native_effects()["warm_pending"], 0);
        let admission_started = std::time::Instant::now();
        let before_admission = rldps[0].query_budget.remaining(&peers);
        assert_eq!(before_admission, (8192, 256), "completed warm query must return its admission before caller resumes");
        reply.hold.store(true, Ordering::Release);
        let mut pending = futures::stream::FuturesUnordered::new();
        for _ in 0..257 { pending.push(rldps[0].query(&query, Some(1024), &peers, true, None)); }
        let refused = tokio::time::timeout(Duration::from_secs(2), pending.next()).await
            .expect("query257 must be refused immediately, before its query deadline or sender admission").unwrap();
        let error = refused.expect_err("capacity overflow cannot answer successfully");
        assert!(error.to_string().contains("from this peer"), "wrong refusal: {error:#}");
        let expected = query_admission_native_effects();
        assert_eq!(pending.len(), expected["pending"].as_u64().unwrap() as usize);
        assert_eq!(expected["refused"], 1);
        assert_eq!(expected["other"], 0);
        let additional = pending.next().now_or_never();
        assert!(additional.is_none(), "additional={additional:?}, warm_remaining={before_admission:?}, elapsed={:?}", admission_started.elapsed());
        assert_eq!(rldps[0].query_budget.remaining(&peers).1, 0);
        assert_eq!(rldps[0].query_budget.remaining(&peers).0, 8192 - 256,
            "refused connection admission must not consume global capacity");
        drop(pending);
        reply.hold.store(false, Ordering::Release);
        reply.release.notify_waiters();
        tokio::time::timeout(Duration::from_secs(5), async {
            while rldps[0].query_budget.remaining(&peers) != (8192, 256) {
                reply.release.notify_waiters();
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await.expect("cancelled query owners must release pending-query admission");
        assert_eq!(rldps[0].query_budget.remaining(&peers).1, 256);
        let (answer, _) = rldps[0].query(&query, Some(1024), &peers, true, None).await.unwrap();
        assert_eq!(answer.unwrap(), vec![42;64]);
    }).catch_unwind().await;
    reply.hold.store(false, Ordering::Release);
    reply.release.notify_waiters();
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_pending_query_global_admission_refuses_before_sender_wait() {
    use futures::StreamExt;
    let (reply, _packets, nodes, rldps, _peers) = topology(34).await;
    let outcome = std::panic::AssertUnwindSafe(async {
        let bytes = serialize_boxed(&Query { overlay: UInt256::default() }).unwrap();
        let query = TaggedByteSlice {
            object: &bytes,
            #[cfg(feature = "telemetry")]
            tag: 0,
        };
        let local = nodes[1].key_by_tag(0).unwrap();
        let routes: Vec<_> = (0..34)
            .filter(|&i| i != 1)
            .map(|i| {
                AdnlPeers::with_keys(
                    local.id().clone(),
                    nodes[i].key_by_tag(0).unwrap().id().clone(),
                )
            })
            .collect();
        let (answer, _) = rldps[1].query(&query, Some(1024), &routes[0], true, None).await.unwrap();
        assert_eq!(answer.unwrap(), vec![42; 64]);
        assert_eq!(query_admission_native_effects()["warm_pending"], 0);
        let admission_started = std::time::Instant::now();
        let before_admission = rldps[1].query_budget.remaining(&routes[0]);
        assert_eq!(
            before_admission,
            (8192, 256),
            "completed warm query must return both admission levels"
        );
        reply.hold.store(true, Ordering::Release);
        let mut pending = futures::stream::FuturesUnordered::new();
        for (index, route) in routes.iter().enumerate() {
            for _ in 0..if index == 32 { 1 } else { 256 } {
                pending.push(rldps[1].query(&query, Some(1024), route, true, None));
            }
        }
        let refused = tokio::time::timeout(Duration::from_secs(2), pending.next())
            .await
            .expect("query8193 must be refused by the global pending-query cap before its deadline")
            .unwrap();
        let error = refused.expect_err("global capacity overflow cannot answer successfully");
        assert_eq!(error.to_string(), "too many RLDP queries are already awaiting an answer");
        let expected = query_admission_native_effects();
        assert_eq!(pending.len(), expected["global_pending"].as_u64().unwrap() as usize);
        assert_eq!(expected["global_refused"], 1);
        assert_eq!(expected["global_other"], 0);
        let additional = pending.next().now_or_never();
        assert!(
            additional.is_none(),
            "additional={additional:?}, warm_remaining={before_admission:?}, elapsed={:?}",
            admission_started.elapsed()
        );
        assert_eq!(rldps[1].query_budget.remaining(&routes[0]).0, 0);
        drop(pending);
        reply.hold.store(false, Ordering::Release);
        reply.release.notify_waiters();
        tokio::time::timeout(Duration::from_secs(5), async {
            while rldps[1].query_budget.remaining(&routes[0]).0 != 8192 {
                reply.release.notify_waiters();
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("global query capacity must return after real owner drain");
        let (answer, _) =
            rldps[1].query(&query, Some(1024), &routes[32], true, None).await.unwrap();
        assert_eq!(answer.unwrap(), vec![42; 64]);
    })
    .catch_unwind()
    .await;
    reply.hold.store(false, Ordering::Release);
    reply.release.notify_waiters();
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

fn query_admission_native_effects() -> serde_json::Value {
    let context = include_bytes!("../../../ci/conformance/rldp2_query_admission_context.tsv");
    let effects = include_bytes!("../../../ci/conformance/rldp2_query_admission_effects.json");
    let meta: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../ci/conformance/rldp2_query_admission_metadata.json"
    ))
    .unwrap();
    assert_eq!(meta["reference_commit"], include_str!("../../../ci/conformance/REFERENCE").trim());
    for (key, bytes) in [
        ("cases_sha256", context.as_slice()),
        ("effects_sha256", effects.as_slice()),
        (
            "probe_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_query_admission_reference.cpp")
                .as_slice(),
        ),
        (
            "runner_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_runtime_reference.py").as_slice(),
        ),
    ] {
        assert_eq!(meta[key], hex::encode(rtos_block::sha256_digest(bytes)), "{key}");
    }
    serde_json::from_slice(effects).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_refused_query_does_not_extend_connection_expiry() {
    assert_eq!(
        include_str!("../../../ci/conformance/rldp2_query_refusal_expiry_context.tsv").trim(),
        "256 10 1 130.5"
    );
    use futures::StreamExt;
    let (reply, _packets, nodes, rldps, peers) = pair().await;
    let outcome = std::panic::AssertUnwindSafe(async {
        let bytes = serialize_boxed(&Query { overlay: UInt256::default() }).unwrap();
        let query = TaggedByteSlice {
            object: &bytes,
            #[cfg(feature = "telemetry")]
            tag: 0,
        };
        let (answer, _) = rldps[0].query(&query, Some(1024), &peers, true, None).await.unwrap();
        assert_eq!(answer.unwrap(), vec![42; 64]);
        reply.hold.store(true, Ordering::Release);
        let mut pending = futures::stream::FuturesUnordered::new();
        for _ in 0..256 {
            pending.push(rldps[0].query(&query, Some(1024), &peers, true, None));
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), pending.next()).await.is_err(),
            "all256 admitted queries must still await replies"
        );
        assert_eq!(rldps[0].query_budget.remaining(&peers).0, 8192 - 256);
        // Every admitted query already captured its10s deadline. This cutoff
        // includes its120s connection retention, but precedes the refused call's.
        let original_expiry = tokio::time::Instant::now() + Duration::from_millis(130500);
        tokio::time::sleep(Duration::from_secs(1)).await;
        let rejected = rldps[0].query(&query, Some(1024), &peers, true, None).await.unwrap_err();
        assert!(rejected.to_string().contains("from this peer"));
        rldps[0].peers.expire(original_expiry);
        let live = usize::from(rldps[0].peers.find_v2(peers.local(), peers.other()).is_some());
        let actual = serde_json::json!({"refused":1,"live_after_original_expiry":live});
        assert_eq!(
            actual,
            query_refusal_expiry_native_effects(),
            "refused query must not extend the connection beyond admitted-query retention"
        );
    })
    .catch_unwind()
    .await;
    reply.hold.store(false, Ordering::Release);
    reply.release.notify_waiters();
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

fn query_refusal_expiry_native_effects() -> serde_json::Value {
    let context = include_bytes!("../../../ci/conformance/rldp2_query_refusal_expiry_context.tsv");
    let effects = include_bytes!("../../../ci/conformance/rldp2_query_refusal_expiry_effects.json");
    let meta: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../ci/conformance/rldp2_query_refusal_expiry_metadata.json"
    ))
    .unwrap();
    assert_eq!(meta["reference_commit"], include_str!("../../../ci/conformance/REFERENCE").trim());
    for (key, bytes) in [
        ("cases_sha256", context.as_slice()),
        ("effects_sha256", effects.as_slice()),
        (
            "probe_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_query_refusal_expiry_reference.cpp")
                .as_slice(),
        ),
        (
            "runner_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_runtime_reference.py").as_slice(),
        ),
    ] {
        assert_eq!(meta[key], hex::encode(rtos_block::sha256_digest(bytes)), "{key}");
    }
    serde_json::from_slice(effects).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_incomplete_inbound_transfers_follow_native_cap() {
    use rtos_api::{IntoBoxed, RldpChunk};
    let (_reply, packets, nodes, rldps, peers) = pair().await;
    let outcome = std::panic::AssertUnwindSafe(async {
        let route = AdnlPeers::with_keys(peers.other().clone(), peers.local().clone());
        let peer = rldps[0].get_peer(peers.local(), peers.other(), true, None).await.unwrap();
        let mut encoder = crate::RaptorqEncoder::with_data(&vec![42; 2048], None);
        let mut seqno = 0;
        let symbol = encoder.encode(&mut seqno).unwrap();
        let mut source_symbols = vec![symbol.clone()];
        for index in 1..3u32 {
            let mut sequence = index;
            source_symbols.push(encoder.encode(&mut sequence).unwrap());
        }

        for n in 0..257u32 {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&n.to_le_bytes());
            let chunk = RldpChunk {
                transfer_id: UInt256::from(id),
                fec_type: encoder.params().clone().into_boxed(),
                part: 0,
                total_size: 2048,
                data: symbol.clone(),
                seqno: seqno as i32,
            };
            let wire =
                serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
            nodes[1]
                .send_custom(
                    &TaggedByteSlice {
                        object: &wire,
                        #[cfg(feature = "telemetry")]
                        tag: 0,
                    },
                    &route,
                )
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                while !packets.transfers.lock().unwrap().contains(id.as_slice()) {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .expect("every test part must reach authenticated receiver");
            if n < 256 {
                tokio::time::timeout(Duration::from_secs(2), async {
                    while peer.inbound_transfers.get(&id).is_none() {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                })
                .await
                .expect("native-admitted partial transfer must remain active");
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let live = peer
            .inbound_transfers
            .iter()
            .filter(|entry| matches!(entry.val(), super::RldpTransfer::Recv(_)))
            .count();
        assert_eq!(live, 256, "incomplete inbound transfer admission must match native cap");
        for index in 1..3u32 {
            let seqno = index;
            let chunk = RldpChunk {
                transfer_id: UInt256::from([0; 32]),
                fec_type: encoder.params().clone().into_boxed(),
                part: 0,
                total_size: 2048,
                data: source_symbols[index as usize].clone(),
                seqno: seqno as i32,
            };
            let wire =
                serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
            nodes[1]
                .send_custom(
                    &TaggedByteSlice {
                        object: &wire,
                        #[cfg(feature = "telemetry")]
                        tag: 0,
                    },
                    &route,
                )
                .await
                .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while !peer
                .inbound_transfers
                .get(&[0; 32])
                .is_some_and(|e| matches!(e.val(), super::RldpTransfer::Done))
            {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("completion must return inbound capacity before upper-layer parsing");
        let after_completion = peer
            .inbound_transfers
            .iter()
            .filter(|e| matches!(e.val(), super::RldpTransfer::Recv(_)))
            .count();
        let mut retry_id = [0; 32];
        retry_id[..4].copy_from_slice(&256u32.to_le_bytes());
        let chunk = RldpChunk {
            transfer_id: UInt256::from(retry_id),
            fec_type: encoder.params().clone().into_boxed(),
            part: 0,
            total_size: 2048,
            data: symbol.clone(),
            seqno: 0,
        };
        let wire = serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
        nodes[1]
            .send_custom(
                &TaggedByteSlice {
                    object: &wire,
                    #[cfg(feature = "telemetry")]
                    tag: 0,
                },
                &route,
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while peer.inbound_transfers.get(&retry_id).is_none() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("refused transfer must be retryable when capacity returns");
        let after_retry = peer
            .inbound_transfers
            .iter()
            .filter(|e| matches!(e.val(), super::RldpTransfer::Recv(_)))
            .count();
        // A registered query response shares the same actual inbound capacity.
        let query_bytes = serialize_boxed(&Query { overlay: UInt256::default() }).unwrap();
        let query = TaggedByteSlice { object: &query_bytes, #[cfg(feature="telemetry")] tag: 0 };
        let request = rldps[0].query(&query, Some(1024), &peers, true, None);
        tokio::pin!(request);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                tokio::select! {
                    result = &mut request => panic!("solicited answer bypassed saturated inbound capacity: {result:?}"),
                    _ = tokio::time::sleep(Duration::from_millis(1)) => {
                        if packets.transfers.lock().unwrap().len() > 257 { break; }
                    }
                }
            }
        }).await.expect("a solicited answer part must reach the receiver");
        assert!(tokio::time::timeout(Duration::from_millis(100), &mut request).await.is_err(),
            "solicited answer must not bypass saturated inbound capacity");
        assert_eq!(peer.inbound_active.lock().unwrap().len(), 256);
        for index in 1..3u32 {
            let seqno = index;
            let mut id = [0;32]; id[0] = 1;
            let chunk = RldpChunk {
                transfer_id: UInt256::from(id), fec_type: encoder.params().clone().into_boxed(),
                part: 0, total_size: 2048, data: source_symbols[index as usize].clone(), seqno: seqno as i32,
            };
            let wire = serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
            nodes[1].send_custom(&TaggedByteSlice { object: &wire, #[cfg(feature="telemetry")] tag: 0 }, &route).await.unwrap();
        }
        let (answer, _) = tokio::time::timeout(Duration::from_secs(3), &mut request).await
            .expect("solicited answer must recover after inbound capacity returns").unwrap();
        assert_eq!(answer.unwrap(), vec![42;64]);
        let expected = inbound_admission_native_effects();
        assert_eq!(expected["solicited_blocked"], true);
        assert_eq!(expected["solicited_recovered"], true);

        assert_eq!(live, expected["inbound"].as_u64().unwrap() as usize);
        assert_eq!(after_completion, expected["after_completion"].as_u64().unwrap() as usize);
        assert_eq!(after_retry, expected["after_retry"].as_u64().unwrap() as usize);
    })
    .catch_unwind()
    .await;
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

fn inbound_admission_native_effects() -> serde_json::Value {
    let context = include_bytes!("../../../ci/conformance/rldp2_inbound_admission_context.tsv");
    let effects = include_bytes!("../../../ci/conformance/rldp2_inbound_admission_effects.json");
    let meta: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../ci/conformance/rldp2_inbound_admission_metadata.json"
    ))
    .unwrap();
    assert_eq!(meta["reference_commit"], include_str!("../../../ci/conformance/REFERENCE").trim());
    for (key, bytes) in [
        ("cases_sha256", context.as_slice()),
        ("effects_sha256", effects.as_slice()),
        (
            "probe_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_inbound_admission_reference.cpp")
                .as_slice(),
        ),
        (
            "runner_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_runtime_reference.py").as_slice(),
        ),
    ] {
        assert_eq!(meta[key], hex::encode(rtos_block::sha256_digest(bytes)), "{key}");
    }
    serde_json::from_slice(effects).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_pruned_completed_id_rechecks_inbound_admission_at_creation() {
    let (_reply, _packets, nodes, rldps, peers) = pair().await;
    let outcome = std::panic::AssertUnwindSafe(async {
        let peer = rldps[0].get_peer(peers.local(), peers.other(), true, None).await.unwrap();
        // Exercise the production admission/creation split at an exact interleaving.
        // UDP saturation and recovery are tested separately above.
        for n in 0..256u32 {
            let mut id = [0; 32];
            id[..4].copy_from_slice(&n.to_le_bytes());
            assert!(peer.admit_inbound(id, true, true, true).unwrap());
        }
        let stale = [77; 32];
        peer.finish_inbound(
            &peer.inbound_transfers,
            stale,
            &tokio_util::sync::CancellationToken::new(),
            tokio::time::Instant::now(),
        );
        assert!(
            peer.admit_inbound(stale, true, true, true).unwrap(),
            "completed duplicates bypass active capacity"
        );
        for n in 0..2048u32 {
            let mut id = [88; 32];
            id[..4].copy_from_slice(&n.to_le_bytes());
            peer.finish_inbound(
                &peer.inbound_transfers,
                id,
                &tokio_util::sync::CancellationToken::new(),
                tokio::time::Instant::now(),
            );
        }
        assert!(peer.inbound_transfers.get(&stale).is_none());
        assert_eq!(peer.inbound_active.lock().unwrap().len(), 256);
        let created = rldps[0].inbound(&stale, &peers, true, peer.clone(), 0, 1024).await.unwrap();
        assert!(
            matches!(created, super::InboundRegistration::Refused),
            "pruned completed ID must not bypass full inbound admission at creation"
        );
        assert!(peer.inbound_transfers.get(&stale).is_none());
    })
    .catch_unwind()
    .await;
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

fn inbound_validation_native_effects() -> serde_json::Value {
    let context = include_bytes!("../../../ci/conformance/rldp2_inbound_validation_context.tsv");
    let effects = include_bytes!("../../../ci/conformance/rldp2_inbound_validation_effects.json");
    let meta: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../ci/conformance/rldp2_inbound_validation_metadata.json"
    ))
    .unwrap();
    assert_eq!(meta["reference_commit"], include_str!("../../../ci/conformance/REFERENCE").trim());
    for (key, bytes) in [
        ("cases_sha256", context.as_slice()),
        ("effects_sha256", effects.as_slice()),
        (
            "probe_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_inbound_validation_reference.cpp")
                .as_slice(),
        ),
        (
            "runner_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_runtime_reference.py").as_slice(),
        ),
    ] {
        assert_eq!(meta[key], hex::encode(rtos_block::sha256_digest(bytes)), "{key}");
    }
    serde_json::from_slice(effects).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_invalid_part_geometry_does_not_allocate_receive_state() {
    use rtos_api::{ton::rldp, IntoBoxed, RldpChunk};
    async fn send(node: &Arc<AdnlNode>, route: &AdnlPeers, part: i32, total: i64, bytes: &[u8]) {
        let mut encoder = crate::RaptorqEncoder::with_data(bytes, None);
        let mut seqno = 0;
        let chunk = RldpChunk {
            transfer_id: UInt256::from([0; 32]),
            fec_type: encoder.params().clone().into_boxed(),
            part,
            total_size: total,
            data: encoder.encode(&mut seqno).unwrap(),
            seqno: seqno as i32,
        };
        let wire = serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
        node.send_custom(
            &TaggedByteSlice {
                object: &wire,
                #[cfg(feature = "telemetry")]
                tag: 0,
            },
            route,
        )
        .await
        .unwrap();
    }
    let mut actual = Vec::new();
    for line in include_str!("../../../ci/conformance/rldp2_inbound_validation_context.tsv").lines()
    {
        let fields: Vec<_> = line.split_whitespace().collect();
        let name = fields[0];
        let part: i32 = fields[1].parse().unwrap();
        let total: i64 = fields[2].parse().unwrap();
        let bytes: usize = fields[3].parse().unwrap();
        let (reply, packets, nodes, rldps, peers) = pair().await;
        *packets.handler.lock().unwrap() = Some(Arc::downgrade(&rldps[0]));
        let outcome = std::panic::AssertUnwindSafe(async {
            let replay = name == "completed_replay";
            let (sender, receiver, route) = if replay { (0,1,peers.clone()) }
                else { (1,0,AdnlPeers::with_keys(peers.other().clone(), peers.local().clone())) };
            let peer = rldps[receiver].get_peer(route.other(), route.local(), true, None).await.unwrap();
            if replay {
                let warm = serialize_boxed(&rldp::message::Message { id:UInt256::default(),data:b"churn".to_vec() }.into_boxed()).unwrap();
                send(&nodes[sender], &route, 0, warm.len() as i64, &warm).await;
                tokio::time::timeout(Duration::from_secs(2), async {
                    while reply.messages.load(Ordering::Acquire) != 1 { reply.message_received.notified().await; }
                }).await.expect("warm message must actually deliver");
            }
            send(&nodes[sender], &route, part, total, &vec![42;bytes]).await;
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let observed = if replay { packets.part_one_completions.load(Ordering::Acquire)>0 }
                        else { packets.processed_parts.load(Ordering::Acquire)>0 };
                    if observed { break; }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }).await.unwrap_or_else(|error| panic!("{name}: input or completed-ID replay acknowledgement must reach the authenticated receiver: {error}"));
            let inbound = peer.inbound_transfers.iter().filter(|e| matches!(e.val(),super::RldpTransfer::Recv(_))).count();
            let completed = peer.inbound_transfers.iter().filter(|e| matches!(e.val(),super::RldpTransfer::Done)).count();
            serde_json::json!({"id":name,"inbound":inbound,"completed":completed,"replay_complete_packets":packets.part_one_completions.load(Ordering::Acquire)})
        }).catch_unwind().await;
        for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await
        {
            result.unwrap();
        }
        match outcome {
            Ok(value) => actual.push(value),
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
    assert_eq!(
        serde_json::Value::Array(actual),
        inbound_validation_native_effects(),
        "invalid part geometry must be dropped before receive allocation or completion caching"
    );
}

// Exercise the same decoder method called by RldpNode's receive owner. This
// synchronous boundary makes the absence of a first Complete deterministic.
#[test]
fn rldp2_decoder_completion_ack_matches_native() {
    use rtos_api::{IntoBoxed, RldpChunk};
    use std::sync::atomic::AtomicU64;
    let expected = checked_ack_native_effects(
        include_bytes!("../../../ci/conformance/rldp2_completion_ack_context.tsv"),
        include_bytes!("../../../ci/conformance/rldp2_completion_ack_effects.jsonl"),
        include_bytes!("../../../ci/conformance/rldp2_completion_ack_reference.cpp"),
        include_bytes!("../../../ci/conformance/rldp2_completion_ack_metadata.json"),
    );
    let mut actual = Vec::new();
    for line in include_str!("../../../ci/conformance/rldp2_completion_ack_context.tsv").lines() {
        let bytes: usize = line.parse().unwrap();
        let payload = vec![42; bytes];
        let mut encoder = crate::RaptorqEncoder::with_data(&payload, Some(768));
        let fec = encoder.params().clone().into_boxed();
        let mut receiver = super::recv::RecvTransfer::new(
            [0; 32],
            Arc::new(AtomicU64::new(0)),
            true,
            None,
            #[cfg(feature = "debug")]
            Arc::new(std::sync::atomic::AtomicPtr::new(std::ptr::null_mut())),
        );
        let chunk = |seqno: i32, data: Vec<u8>| {
            super::Chunk::V2(rldp2::messagepart::MessagePart(RldpChunk {
                transfer_id: UInt256::default(),
                fec_type: fec.clone(),
                part: 0,
                total_size: bytes as i64,
                seqno,
                data,
            }))
        };
        let mut first_symbol = None;
        let mut first_complete = 0;
        for index in 0..bytes.div_ceil(768) {
            let mut seqno = index as u32;
            let data = encoder.encode(&mut seqno).unwrap();
            if index == 0 {
                first_symbol = Some((seqno, data.clone()));
            }
            if receiver.process_chunk(chunk(seqno as i32, data)).unwrap().is_some() {
                first_complete += 1;
            }
        }
        assert_eq!(receiver.data, payload, "real decoder must deliver all bytes");
        let (seqno, data) = first_symbol.unwrap();
        let duplicate_complete =
            usize::from(receiver.process_chunk(chunk(seqno as i32, data)).unwrap().is_some());
        assert_eq!(receiver.data, payload, "duplicate must not append delivered bytes");
        actual.push(serde_json::json!({"bytes":bytes,"first_complete":first_complete,
            "duplicate_complete":duplicate_complete,"deliveries":1}));
    }
    assert_eq!(actual, expected, "first decode and duplicate ACKs must match native");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_query_sender_survives_legacy_adaptive_timeout() {
    let native = checked_ack_native_effects(
        include_bytes!("../../../ci/conformance/rldp2_sender_absolute_deadline_context.tsv"),
        include_bytes!("../../../ci/conformance/rldp2_sender_absolute_deadline_effects.jsonl"),
        include_bytes!("../../../ci/conformance/rldp2_sender_absolute_deadline_reference.cpp"),
        include_bytes!("../../../ci/conformance/rldp2_sender_absolute_deadline_metadata.json"),
    );
    assert_eq!(native[0]["pending"], 1);
    assert_eq!(native[0]["expired"], 0);
    assert_eq!(native[0]["deadline_ms"], RldpNode::TIMEOUT_MAX_MS);
    let loss_ms = native[0]["loss_ms"].as_u64().unwrap();
    let (_reply, packets, nodes, rldps, peers) = pair().await;
    let outcome = std::panic::AssertUnwindSafe(async {
        packets.drop_parts.store(true, Ordering::Release);
        let node = rldps[1].clone();
        let route = AdnlPeers::with_keys(peers.other().clone(), peers.local().clone());
        let query = tokio::spawn(async move {
            let bytes = serialize_boxed(&Query { overlay: UInt256::default() }).unwrap();
            node.query(
                &TaggedByteSlice {
                    object: &bytes,
                    #[cfg(feature = "telemetry")]
                    tag: 0,
                },
                Some(1024),
                &route,
                true,
                None,
            )
            .await
        });
        // Native forwards the query's absolute deadline to its sender. Losing
        // the first 700ms of packets must not trigger the old 500ms timeout.
        tokio::time::sleep(Duration::from_millis(loss_ms)).await;
        let prematurely_finished = query.is_finished();
        packets.drop_parts.store(false, Ordering::Release);
        let result =
            tokio::time::timeout(Duration::from_secs(9), query).await.unwrap().unwrap().unwrap();
        assert!(!prematurely_finished, "V2 sender ended before the native query deadline");
        assert_eq!(result.0, Some(vec![42; 64]));
    })
    .catch_unwind()
    .await;
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

pub(super) fn checked_ack_native_effects(
    context: &[u8],
    effects: &[u8],
    source: &[u8],
    metadata: &[u8],
) -> Vec<serde_json::Value> {
    let meta: serde_json::Value = serde_json::from_slice(metadata).unwrap();
    assert_eq!(meta["reference_commit"], include_str!("../../../ci/conformance/REFERENCE").trim());
    assert_eq!(meta["exit"], 0);
    for (key, bytes) in [
        ("cases_sha256", context),
        ("effects_sha256", effects),
        ("probe_source_sha256", source),
        (
            "runner_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_runtime_reference.py").as_slice(),
        ),
    ] {
        assert_eq!(meta[key], hex::encode(rtos_block::sha256_digest(bytes)), "{key}");
    }
    std::str::from_utf8(effects)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_message_uses_native_ten_second_deadline() {
    let (_reply, packets, nodes, rldps, peers) = pair().await;
    let outcome = std::panic::AssertUnwindSafe(async {
        packets.drop_parts.store(true, Ordering::Release);
        let route = AdnlPeers::with_keys(peers.other().clone(), peers.local().clone());
        let started = tokio::time::Instant::now();
        let error = tokio::time::timeout(
            Duration::from_secs(12),
            rldps[1].message(
                &TaggedByteSlice {
                    object: b"churn",
                    #[cfg(feature = "telemetry")]
                    tag: 0,
                },
                &route,
                true,
                None,
            ),
        )
        .await
        .expect("native message deadline must precede legacy hard timeout")
        .unwrap_err();
        assert!(
            started.elapsed() >= Duration::from_secs(10),
            "message ended before native deadline"
        );
        assert!(matches!(
            error.downcast_ref::<super::SendCancelled>(),
            Some(super::SendCancelled::Deadline)
        ));
    })
    .catch_unwind()
    .await;
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

fn completed_packet_validation_native_effects() -> serde_json::Value {
    let context =
        include_bytes!("../../../ci/conformance/rldp2_completed_packet_validation_context.tsv");
    let effects =
        include_bytes!("../../../ci/conformance/rldp2_completed_packet_validation_effects.jsonl");
    let meta: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../ci/conformance/rldp2_completed_packet_validation_metadata.json"
    ))
    .unwrap();
    assert_eq!(meta["exit"], 0);
    assert_eq!(meta["reference_commit"], include_str!("../../../ci/conformance/REFERENCE").trim());
    for (key, bytes) in [
        ("cases_sha256", context.as_slice()),
        ("effects_sha256", effects.as_slice()),
        (
            "probe_source_sha256",
            include_bytes!(
                "../../../ci/conformance/rldp2_completed_packet_validation_reference.cpp"
            )
            .as_slice(),
        ),
        (
            "runner_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_runtime_reference.py").as_slice(),
        ),
    ] {
        assert_eq!(meta[key], hex::encode(rtos_block::sha256_digest(bytes)), "{key}");
    }
    serde_json::from_slice(effects).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_completed_packet_validation_matches_native() {
    use rtos_api::{ton::rldp, IntoBoxed, RldpChunk};
    async fn send(
        node: &Arc<AdnlNode>,
        route: &AdnlPeers,
        part: i32,
        total: i64,
        bytes: &[u8],
        forced_seqno: Option<i32>,
        symbol_size: i32,
    ) {
        let mut encoder = crate::RaptorqEncoder::with_data(bytes, None);
        let mut seqno = 0;
        let mut fec = encoder.params().clone();
        fec.symbol_size = symbol_size;
        let chunk = RldpChunk {
            transfer_id: UInt256::from([0; 32]),
            fec_type: fec.into_boxed(),
            part,
            total_size: total,
            data: encoder.encode(&mut seqno).unwrap(),
            seqno: forced_seqno.unwrap_or(seqno as i32),
        };
        let wire = serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
        node.send_custom(
            &TaggedByteSlice {
                object: &wire,
                #[cfg(feature = "telemetry")]
                tag: 0,
            },
            route,
        )
        .await
        .unwrap();
    }
    let mut actual = Vec::new();
    for line in
        include_str!("../../../ci/conformance/rldp2_completed_packet_validation_context.tsv")
            .lines()
    {
        let fields: Vec<_> = line.split_whitespace().collect();
        let name = fields[0];
        let forced_seqno: i32 = fields[1].parse().unwrap();
        let symbol_size: i32 = fields[2].parse().unwrap();
        let (reply, packets, nodes, rldps, peers) = pair().await;
        let outcome = std::panic::AssertUnwindSafe(async {
            let (sender, receiver, route) = (0, 1, peers.clone());
            let peer = rldps[receiver].get_peer(route.other(), route.local(), true, None).await.unwrap();
            {
                let warm = serialize_boxed(&rldp::message::Message { id:UInt256::default(),data:b"churn".to_vec() }.into_boxed()).unwrap();
                send(&nodes[sender], &route, 0, warm.len() as i64, &warm, None, 768).await;
                tokio::time::timeout(Duration::from_secs(2), async {
                    while reply.messages.load(Ordering::Acquire) != 1 { reply.message_received.notified().await; }
                }).await.expect("warm message must actually deliver");
            }
            send(&nodes[sender], &route, 1, 2048, &vec![42;2048], Some(forced_seqno), symbol_size).await;
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let observed = packets.part_one_completions.load(Ordering::Acquire) > 0;
                    if observed { break; }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }).await.unwrap_or_else(|error| panic!("{name}: input or completed-ID replay acknowledgement must reach the authenticated receiver: {error}"));
            let inbound = peer.inbound_transfers.iter().filter(|e| matches!(e.val(),super::RldpTransfer::Recv(_))).count();
            let completed = peer.inbound_transfers.iter().filter(|e| matches!(e.val(),super::RldpTransfer::Done)).count();
            serde_json::json!({"id":name,"inbound":inbound,"completed":completed,"replay_complete_packets":packets.part_one_completions.load(Ordering::Acquire)})
        }).catch_unwind().await;
        for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await
        {
            result.unwrap();
        }
        match outcome {
            Ok(value) => actual.push(value),
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
    assert_eq!(
        serde_json::Value::Array(actual),
        completed_packet_validation_native_effects(),
        "completed IDs must be acknowledged before packet validation"
    );
}

// The production TL handler must reject malformed live/new input before it
// claims capacity or queues data, including the bounded wire-limit shortcut.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_malformed_packet_cannot_admit_or_queue() {
    use rtos_api::{IntoBoxed, RldpChunk};
    let (_, _, nodes, rldps, peers) = pair().await;
    let outcome = std::panic::AssertUnwindSafe(async {
        let peer = rldps[0].get_peer(peers.local(), peers.other(), true, None).await.unwrap();
        let mut encoder = crate::RaptorqEncoder::with_data(&vec![42; 2048], None);
        let mut sequence = 0;
        let symbol = encoder.encode(&mut sequence).unwrap();
        for registered in [false, true] {
            for wire_limit in [None, Some(1024)] {
                for (seqno, symbol_size) in [(-1, 768), (0, 1)] {
                    let id = [73; 32];
                    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
                    if registered {
                        super::add_unbound_object_to_map(&peer.inbound_transfers, id, || {
                            Ok(super::RldpTransfer::receiver(tx.clone(), wire_limit))
                        })
                        .unwrap();
                        assert!(peer.admit_inbound(id, true, true, true).unwrap());
                    }
                    let before = peer.inbound_active.lock().unwrap().len();
                    let mut fec = encoder.params().clone();
                    fec.symbol_size = symbol_size;
                    let chunk = RldpChunk {
                        transfer_id: UInt256::from(id),
                        fec_type: fec.into_boxed(),
                        part: 0,
                        total_size: 2048,
                        seqno,
                        data: symbol.clone(),
                    };
                    let wire =
                        serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed())
                            .unwrap();
                    assert!(rldps[0].try_consume_custom(&wire, &peers).await.unwrap());
                    let after = peer.inbound_active.lock().unwrap().len();
                    assert_eq!(after, before, "malformed input must not claim an inbound slot");
                    assert!(
                        matches!(rx.try_recv(), Err(tokio::sync::mpsc::error::TryRecvError::Empty)),
                        "malformed input must not reach the decoder or bounded-limit notification"
                    );
                    assert_eq!(peer.inbound_transfers.get(&id).is_some(), registered);
                    if registered {
                        // A valid packet still reaches this same live registration.
                        let chunk = RldpChunk {
                            transfer_id: UInt256::from(id),
                            fec_type: encoder.params().clone().into_boxed(),
                            part: 0,
                            total_size: 2048,
                            seqno: 0,
                            data: symbol.clone(),
                        };
                        let wire =
                            serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed())
                                .unwrap();
                        assert!(rldps[0].try_consume_custom(&wire, &peers).await.unwrap());
                        assert!(
                            rx.try_recv().is_ok(),
                            "valid control must reach the registered receiver"
                        );
                        peer.inbound_transfers.remove(&id);
                        peer.inbound_active.lock().unwrap().remove(&id);
                    }
                }
            }
        }
    })
    .catch_unwind()
    .await;
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

fn fec_symbol_count_native_effects() -> serde_json::Value {
    let context = include_bytes!("../../../ci/conformance/rldp_fec_symbol_count_context.tsv");
    let effects = include_bytes!("../../../ci/conformance/rldp_fec_symbol_count_effects.jsonl");
    let meta: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../ci/conformance/rldp_fec_symbol_count_metadata.json"
    ))
    .unwrap();
    assert_eq!(meta["exit"], 0);
    assert_eq!(meta["reference_commit"], include_str!("../../../ci/conformance/REFERENCE").trim());
    for (key, bytes) in [
        ("cases_sha256", context.as_slice()),
        ("effects_sha256", effects.as_slice()),
        (
            "probe_source_sha256",
            include_bytes!("../../../ci/conformance/rldp_fec_symbol_count_reference.cpp")
                .as_slice(),
        ),
        (
            "runner_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_runtime_reference.py").as_slice(),
        ),
    ] {
        assert_eq!(meta[key], hex::encode(rtos_block::sha256_digest(bytes)), "{key}");
    }
    serde_json::from_slice(effects).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_fec_symbol_count_matches_native_admission() {
    use rtos_api::{IntoBoxed, RldpChunk};
    let mut actual = Vec::new();
    for line in include_str!("../../../ci/conformance/rldp_fec_symbol_count_context.tsv").lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let name = fields[0];
        let count: i32 = fields[1].parse().unwrap();
        let (_, packets, nodes, rldps, peers) = pair().await;
        *packets.handler.lock().unwrap() = Some(Arc::downgrade(&rldps[0]));
        let outcome = std::panic::AssertUnwindSafe(async {
            let peer = rldps[0].get_peer(peers.local(), peers.other(), true, None).await.unwrap();
            let route = AdnlPeers::with_keys(peers.other().clone(), peers.local().clone());
            let mut encoder = crate::RaptorqEncoder::with_data(&vec![42; 2048], None);
            let mut seqno = 0;
            let mut fec = encoder.params().clone();
            fec.symbols_count = count;
            let chunk = RldpChunk {
                transfer_id: UInt256::from([0; 32]), fec_type: fec.into_boxed(),
                part: 0, total_size: 2048, data: encoder.encode(&mut seqno).unwrap(), seqno: 0,
            };
            let wire = serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
            nodes[1].send_custom(&TaggedByteSlice { object: &wire, #[cfg(feature="telemetry")] tag: 0 }, &route).await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                while packets.processed_parts.load(Ordering::Acquire) == 0 {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }).await.expect("real receiver must process the authenticated FEC packet");
            let inbound = peer.inbound_transfers.iter().filter(|e| matches!(e.val(),super::RldpTransfer::Recv(_))).count();
            let completed = peer.inbound_transfers.iter().filter(|e| matches!(e.val(),super::RldpTransfer::Done)).count();
            serde_json::json!({"id":name,"inbound":inbound,"completed":completed,"replay_complete_packets":0})
        }).catch_unwind().await;
        for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await
        {
            result.unwrap();
        }
        match outcome {
            Ok(value) => actual.push(value),
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
    assert_eq!(
        serde_json::Value::Array(actual),
        fec_symbol_count_native_effects(),
        "FEC symbol count must match native admission before receiver allocation"
    );
}

fn symbol_length_native_effects() -> serde_json::Value {
    let context = include_bytes!("../../../ci/conformance/rldp_symbol_length_context.tsv");
    let effects = include_bytes!("../../../ci/conformance/rldp_symbol_length_effects.jsonl");
    let meta: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../ci/conformance/rldp_symbol_length_metadata.json"
    ))
    .unwrap();
    assert_eq!(meta["exit"], 0);
    assert_eq!(meta["reference_commit"], include_str!("../../../ci/conformance/REFERENCE").trim());
    for (key, bytes) in [
        ("cases_sha256", context.as_slice()),
        ("effects_sha256", effects.as_slice()),
        (
            "probe_source_sha256",
            include_bytes!("../../../ci/conformance/rldp_symbol_length_reference.cpp").as_slice(),
        ),
        (
            "runner_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_runtime_reference.py").as_slice(),
        ),
    ] {
        assert_eq!(meta[key], hex::encode(rtos_block::sha256_digest(bytes)), "{key}");
    }
    serde_json::from_slice(effects).unwrap()
}

#[test]
fn rldp2_symbol_length_decoder_matches_native() {
    use rtos_api::{IntoBoxed, RldpChunk};
    let expected = symbol_length_native_effects();
    let mut actual = Vec::new();
    for line in include_str!("../../../ci/conformance/rldp_symbol_length_context.tsv").lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let name = fields[0];
        let length: usize = fields[1].parse().unwrap();
        let seqno: i32 = fields[2].parse().unwrap();
        let warm: i32 = fields[3].parse().unwrap();
        let mut encoder = crate::RaptorqEncoder::with_data(&vec![42; 2048], None);
        let fec = encoder.params().clone().into_boxed();
        let mut receiver = super::recv::RecvTransfer::new(
            [0; 32],
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
            true,
            None,
            #[cfg(feature = "debug")]
            Arc::new(std::sync::atomic::AtomicPtr::new(std::ptr::null_mut())),
        );
        let chunk = |seqno, data| {
            super::Chunk::V2(rldp2::messagepart::MessagePart(RldpChunk {
                transfer_id: UInt256::default(),
                fec_type: fec.clone(),
                part: 0,
                total_size: 2048,
                seqno,
                data,
            }))
        };
        if warm >= 0 {
            let data = if warm == 0 {
                encoder.encode(&mut 0).unwrap()
            } else {
                for i in 0..3 {
                    encoder.encode(&mut (i as u32)).unwrap();
                }
                encoder.encode(&mut (warm as u32)).unwrap()
            };
            assert!(receiver.process_chunk(chunk(warm, data)).unwrap().is_none());
        }
        let error = receiver.process_chunk(chunk(seqno, vec![42; length])).is_err();
        assert!(
            receiver.data.is_empty(),
            "one or two symbols cannot deliver this three-symbol transfer"
        );
        actual.push(serde_json::json!({"id":name,"errors":usize::from(error),"deliveries":0}));
    }
    let expected: Vec<_> = expected.as_array().unwrap().iter().map(|row|
        serde_json::json!({"id":row["id"],"errors":row["errors"],"deliveries":row["deliveries"]})
    ).collect();
    assert_eq!(
        actual, expected,
        "native decoder rejection must preserve duplicate/window ordering"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_symbol_length_error_retires_actual_receiver() {
    use rtos_api::{IntoBoxed, RldpChunk};
    let (_, _, nodes, rldps, peers) = pair().await;
    let outcome = std::panic::AssertUnwindSafe(async {
        let peer = rldps[0].get_peer(peers.local(), peers.other(), true, None).await.unwrap();
        let encoder = crate::RaptorqEncoder::with_data(&vec![42; 2048], None);
        let chunk = RldpChunk {
            transfer_id: UInt256::default(),
            fec_type: encoder.params().clone().into_boxed(),
            part: 0,
            total_size: 2048,
            seqno: 0,
            data: Vec::new(),
        };
        let wire = serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
        let route = AdnlPeers::with_keys(peers.other().clone(), peers.local().clone());
        nodes[1]
            .send_custom(
                &TaggedByteSlice {
                    object: &wire,
                    #[cfg(feature = "telemetry")]
                    tag: 0,
                },
                &route,
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !peer
                .inbound_transfers
                .get(&[0; 32])
                .is_some_and(|e| matches!(e.val(), super::RldpTransfer::Done))
            {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("malformed symbol must retire the receiver as native does");
        let expected = symbol_length_native_effects();
        let row = expected.as_array().unwrap().iter().find(|r| r["id"] == "empty_symbol").unwrap();
        let active = peer.inbound_active.lock().unwrap().len();
        let completed = peer
            .inbound_transfers
            .iter()
            .filter(|e| matches!(e.val(), super::RldpTransfer::Done))
            .count();
        assert_eq!(active as u64, row["inbound"].as_u64().unwrap());
        assert_eq!(completed as u64, row["completed"].as_u64().unwrap());
    })
    .catch_unwind()
    .await;
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

pub(super) fn ack_retry_native_effects() -> Vec<serde_json::Value> {
    checked_ack_native_effects(
        include_bytes!("../../../ci/conformance/rldp2_ack_retries_context.tsv"),
        include_bytes!("../../../ci/conformance/rldp2_ack_retries_effects.jsonl"),
        include_bytes!("../../../ci/conformance/rldp2_ack_retries_reference.cpp"),
        include_bytes!("../../../ci/conformance/rldp2_ack_retries_metadata.json"),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_ack_retries_without_new_symbols_match_native() {
    use rtos_api::{IntoBoxed, RldpChunk};
    let expected = ack_retry_native_effects()
        .iter()
        .filter(|row| {
            row["case"] == "retry" && row["ms"].as_u64().unwrap() < 1000 && row["sent"] == true
        })
        .count();
    assert_eq!(expected, 8);
    let (_, packets, nodes, _, peers) = pair().await;
    let outcome = std::panic::AssertUnwindSafe(async {
        let mut encoder = crate::RaptorqEncoder::with_data(&vec![42; 2048], None);
        let mut seqno = 0;
        let chunk = RldpChunk {
            transfer_id: UInt256::default(),
            fec_type: encoder.params().clone().into_boxed(),
            part: 0,
            total_size: 2048,
            data: encoder.encode(&mut seqno).unwrap(),
            seqno: 0,
        };
        let wire = serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
        nodes[0]
            .send_custom(
                &TaggedByteSlice {
                    object: &wire,
                    #[cfg(feature = "telemetry")]
                    tag: 0,
                },
                &peers,
            )
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while packets.confirm_packets.load(Ordering::Acquire) < expected {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "native sends {expected} confirmations without new symbols; Rust sent {}",
                packets.confirm_packets.load(Ordering::Acquire)
            )
        });
        assert_eq!(packets.confirm_packets.load(Ordering::Acquire), expected);
    })
    .catch_unwind()
    .await;
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

fn sequence_error_native_effects() -> serde_json::Value {
    let context =
        include_bytes!("../../../ci/conformance/rldp2_sequence_error_lifetime_context.tsv");
    let effects =
        include_bytes!("../../../ci/conformance/rldp2_sequence_error_lifetime_effects.jsonl");
    let meta: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../ci/conformance/rldp2_sequence_error_lifetime_metadata.json"
    ))
    .unwrap();
    assert_eq!(meta["exit"], 0);
    assert_eq!(meta["reference_commit"], include_str!("../../../ci/conformance/REFERENCE").trim());
    for (key, bytes) in [
        ("cases_sha256", context.as_slice()),
        ("effects_sha256", effects.as_slice()),
        (
            "probe_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_sequence_error_lifetime_reference.cpp")
                .as_slice(),
        ),
        (
            "runner_source_sha256",
            include_bytes!("../../../ci/conformance/rldp2_runtime_reference.py").as_slice(),
        ),
    ] {
        assert_eq!(meta[key], hex::encode(rtos_block::sha256_digest(bytes)), "{key}");
    }
    serde_json::from_slice(effects).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_sequence_error_lifetime_matches_native() {
    use rtos_api::{IntoBoxed, RldpChunk};
    let expected = sequence_error_native_effects();
    let mut actual = Vec::new();
    for line in
        include_str!("../../../ci/conformance/rldp2_sequence_error_lifetime_context.tsv").lines()
    {
        let fields: Vec<_> = line.split_whitespace().collect();
        let name = fields[0];
        let seqno: i32 = fields[2].parse().unwrap();
        let expected_row = expected.as_array().unwrap().iter().find(|r| r["id"] == name).unwrap();
        let (_, packets, nodes, rldps, peers) = pair().await;
        *packets.handler.lock().unwrap() = Some(Arc::downgrade(&rldps[0]));
        let outcome = std::panic::AssertUnwindSafe(async {
            let peer = rldps[0].get_peer(peers.local(), peers.other(), true, None).await.unwrap();
            let encoder = crate::RaptorqEncoder::with_data(&vec![42; 2048], None);
            let chunk = RldpChunk {
                transfer_id: UInt256::default(),
                fec_type: encoder.params().clone().into_boxed(),
                part: 0,
                total_size: 2048,
                seqno,
                data: vec![42; 768],
            };
            let wire =
                serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
            let route = AdnlPeers::with_keys(peers.other().clone(), peers.local().clone());
            nodes[1]
                .send_custom(
                    &TaggedByteSlice {
                        object: &wire,
                        #[cfg(feature = "telemetry")]
                        tag: 0,
                    },
                    &route,
                )
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                while packets.processed_parts.load(Ordering::Acquire) == 0 {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .expect("authenticated packet must finish the actual handler");
            if expected_row["completed"] == 1 {
                // Record all four actual states before comparing; the old
                // implementation drops the large IDs without a completion.
                let _ = tokio::time::timeout(Duration::from_secs(2), async {
                    while !peer
                        .inbound_transfers
                        .get(&[0; 32])
                        .is_some_and(|e| matches!(e.val(), super::RldpTransfer::Done))
                    {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                })
                .await;
            }
            let inbound = peer
                .inbound_transfers
                .iter()
                .filter(|e| matches!(e.val(), super::RldpTransfer::Recv(_)))
                .count();
            let completed = peer
                .inbound_transfers
                .iter()
                .filter(|e| matches!(e.val(), super::RldpTransfer::Done))
                .count();
            serde_json::json!({"id":name,"inbound":inbound,"completed":completed})
        })
        .catch_unwind()
        .await;
        for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await
        {
            result.unwrap();
        }
        match outcome {
            Ok(value) => actual.push(value),
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
    let expected: Vec<_> = expected
        .as_array()
        .unwrap()
        .iter()
        .map(
            |r| serde_json::json!({"id":r["id"],"inbound":r["inbound"],"completed":r["completed"]}),
        )
        .collect();
    assert_eq!(
        actual, expected,
        "sequence syntax rejection and decoder failure must preserve native lifetimes"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_sequence_decoder_error_reaches_query_caller() {
    use rtos_api::{IntoBoxed, RldpChunk};
    // Native RldpIn::receive_message forwards the transport error to the
    // matching query promise; it must not become a successful empty reply.
    let native = sequence_error_native_effects();
    assert_eq!(
        native.as_array().unwrap().iter().find(|r| r["id"] == "first_invalid_seqno").unwrap()
            ["errors"],
        1
    );
    let (reply, _, nodes, rldps, peers) = pair().await;
    let outcome = std::panic::AssertUnwindSafe(async {
        reply.hold.store(true, Ordering::Release);
        let bytes = serialize_boxed(&Query { overlay: UInt256::default() }).unwrap();
        let query = TaggedByteSlice {
            object: &bytes,
            #[cfg(feature = "telemetry")]
            tag: 0,
        };
        let request = rldps[0].query(&query, Some(4096), &peers, true, None);
        let inject = async {
            tokio::time::timeout(Duration::from_secs(2), reply.entered.notified())
                .await
                .expect("real query must reach held subscriber");
            let peer = rldps[0].get_peer(peers.local(), peers.other(), true, None).await.unwrap();
            let id = *peer
                .inbound_transfers
                .iter()
                .find(|e| matches!(e.val(), super::RldpTransfer::Recv(_)))
                .expect("query must register its answer transfer")
                .key();
            let encoder = crate::RaptorqEncoder::with_data(&vec![42; 2048], None);
            let chunk = RldpChunk {
                transfer_id: id.into(),
                fec_type: encoder.params().clone().into_boxed(),
                part: 0,
                total_size: 2048,
                seqno: 1 << 24,
                data: vec![42; 768],
            };
            let wire =
                serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
            let route = AdnlPeers::with_keys(peers.other().clone(), peers.local().clone());
            nodes[1]
                .send_custom(
                    &TaggedByteSlice {
                        object: &wire,
                        #[cfg(feature = "telemetry")]
                        tag: 0,
                    },
                    &route,
                )
                .await
                .unwrap();
        };
        let (result, ()) =
            tokio::time::timeout(Duration::from_secs(3), async { tokio::join!(request, inject) })
                .await
                .expect("decoder error must resolve query before its deadline");
        let error = result.expect_err("native decoder errors must propagate to the query caller");
        assert!(
            error.to_string().contains("24 bits"),
            "expected the actual decoder sequence error, got {error}"
        );
    })
    .catch_unwind()
    .await;
    reply.hold.store(false, Ordering::Release);
    reply.release.notify_waiters();
    reply.release.notify_one();
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_overdue_ack_progresses_with_ready_receive_queue() {
    use rtos_api::{IntoBoxed, RldpChunk};
    let native = checked_ack_native_effects(
        include_bytes!("../../../ci/conformance/rldp2_ack_ready_queue_context.tsv"),
        include_bytes!("../../../ci/conformance/rldp2_ack_ready_queue_effects.jsonl"),
        include_bytes!("../../../ci/conformance/rldp2_ack_ready_queue_reference.cpp"),
        include_bytes!("../../../ci/conformance/rldp2_ack_ready_queue_metadata.json"),
    );
    for row in native {
        let (_, packets, nodes, _, peers) = pair().await;
        let outcome = std::panic::AssertUnwindSafe(async {
            let queued = row["queued"].as_u64().unwrap() as usize;
            let mut encoder = crate::RaptorqEncoder::with_data(&vec![42; 2048], None);
            let mut seqno = 0;
            let chunk = RldpChunk {
                transfer_id: UInt256::default(),
                fec_type: encoder.params().clone().into_boxed(),
                part: 0,
                total_size: 2048,
                data: encoder.encode(&mut seqno).unwrap(),
                seqno: 0,
            };
            let mut receiver = super::recv::RecvTransfer::new(
                [0; 32],
                Arc::new(std::sync::atomic::AtomicU64::new(0)),
                true,
                Some(2048),
                #[cfg(feature = "debug")]
                Arc::new(std::sync::atomic::AtomicPtr::new(std::ptr::null_mut())),
            );
            assert!(receiver
                .process_chunk(super::Chunk::V2(rldp2::messagepart::MessagePart(chunk.clone())))
                .unwrap()
                .is_none());
            tokio::time::sleep(Duration::from_millis(20)).await;
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            for _ in 0..queued {
                tx.send(super::Chunk::V2(rldp2::messagepart::MessagePart(chunk.clone()))).unwrap();
            }
            let mut context = super::recv::RecvContext {
                adnl: nodes[1].clone(),
                peers: AdnlPeers::with_keys(peers.other().clone(), peers.local().clone()),
                queue_reader: rx,
                recv_transfer: receiver,
                transfer_id: [0; 32],
                #[cfg(feature = "debug")]
                loss_fn: None,
            };
            let mut confirms = 0;
            for remaining in (0..queued).rev() {
                // The production poll must service its timer even though recv()
                // is immediately ready. Keep the producer alive: no close or
                // idle timeout is used to trigger the confirmation.
                let next = RldpNode::receive_chunk(&mut context, true, &mut confirms)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(context.queue_reader.len(), remaining);
                assert!(context.recv_transfer.process_chunk(next).unwrap().is_none());
            }
            assert_eq!(confirms > 0, row["ack_progress"].as_bool().unwrap());
            assert_eq!(
                u64::from(!context.recv_transfer.data.is_empty()),
                row["deliveries"].as_u64().unwrap()
            );
            tokio::time::timeout(Duration::from_secs(2), async {
                while packets.confirm_packets.load(Ordering::Acquire) == 0 {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .expect("the confirmation must reach the real ADNL peer");
            drop(tx);
        })
        .catch_unwind()
        .await;
        for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await
        {
            result.unwrap();
        }
        if let Err(panic) = outcome {
            std::panic::resume_unwind(panic);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_later_first_part_does_not_activate_pending_query_receive() {
    check_native_part_admission(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_skipped_part_recovers_after_predecessor_over_adnl() {
    check_native_part_admission(true).await;
}

async fn check_native_part_admission(sequential: bool) {
    use rtos_api::{IntoBoxed, RldpChunk};
    let total_size = if sequential { 4_000_001 } else { 2_000_001 };
    let last_part = if sequential { 2 } else { 1 };
    let native = if sequential {
        checked_ack_native_effects(
            include_bytes!("../../../ci/conformance/rldp2_sequential_part_admission_context.tsv"),
            include_bytes!("../../../ci/conformance/rldp2_sequential_part_admission_effects.jsonl"),
            include_bytes!("../../../ci/conformance/rldp2_sequential_part_admission_reference.cpp"),
            include_bytes!("../../../ci/conformance/rldp2_sequential_part_admission_metadata.json"),
        )
    } else {
        checked_ack_native_effects(
            include_bytes!("../../../ci/conformance/rldp2_first_part_admission_context.tsv"),
            include_bytes!("../../../ci/conformance/rldp2_first_part_admission_effects.jsonl"),
            include_bytes!("../../../ci/conformance/rldp2_first_part_admission_reference.cpp"),
            include_bytes!("../../../ci/conformance/rldp2_first_part_admission_metadata.json"),
        )
    };
    let remote_packets = Arc::new(ResponsePackets::default());
    let completed_parts = if sequential {
        &remote_packets.part_two_completions
    } else {
        &remote_packets.part_one_completions
    };
    let (reply, packets, nodes, rldps, peers) =
        topology_with_remote_observer(2, Some(remote_packets.clone())).await;
    *packets.handler.lock().unwrap() = Some(Arc::downgrade(&rldps[0]));
    let outcome = std::panic::AssertUnwindSafe(async {
        reply.hold.store(true, Ordering::Release);
        let bytes = serialize_boxed(&Query { overlay: UInt256::default() }).unwrap();
        let request = TaggedByteSlice {
            object: &bytes,
            #[cfg(feature = "telemetry")] tag: 0,
        };
        let deliveries = std::sync::atomic::AtomicUsize::new(0);
        let query = async {
            let result = rldps[0].query(&request, Some(total_size), &peers, true, None).await;
            deliveries.fetch_add(1, Ordering::Release);
            result
        };
        let inject = async {
            tokio::time::timeout(Duration::from_secs(2), reply.entered.notified())
                .await.expect("real query reaches held server");
            let peer = rldps[0].get_peer(peers.local(), peers.other(), true, None).await.unwrap();
            let id = *peer.inbound_transfers.iter()
                .find(|e| matches!(e.val(), super::RldpTransfer::Recv(_)))
                .expect("query registers a response before any answer part").key();
            assert_eq!(peer.inbound_active.lock().unwrap().len(), 0);
            let route = AdnlPeers::with_keys(peers.other().clone(), peers.local().clone());
            let mut actual = Vec::new();
            for row in &native {
                let part = row["part"].as_i64().unwrap() as i32;
                let mut encoder = crate::RaptorqEncoder::with_data(
                    &vec![42; if part < last_part { 2_000_000 } else { 1 }], None,
                );
                let mut seqno = 0;
                let chunk = RldpChunk {
                    transfer_id: id.into(), fec_type: encoder.params().clone().into_boxed(),
                    part, total_size: total_size as i64, data: encoder.encode(&mut seqno).unwrap(), seqno: 0,
                };
                let wire = serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
                let before = packets.processed_parts.load(Ordering::Acquire);
                nodes[1].send_custom(&TaggedByteSlice {
                    object: &wire,
                    #[cfg(feature = "telemetry")] tag: 0,
                }, &route).await.unwrap();
                tokio::time::timeout(Duration::from_secs(2), async {
                    while packets.processed_parts.load(Ordering::Acquire) == before {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                }).await.expect("actual authenticated handler must finish the input");
                let expected_complete = row["complete_packets"].as_u64().unwrap() as usize;
                if expected_complete > 0 {
                    tokio::time::timeout(Duration::from_secs(2), async {
                        while completed_parts.load(Ordering::Acquire) < expected_complete {
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                    }).await.expect("last part accepted after its predecessor must acknowledge its replay");
                }
                let active = peer.inbound_active.lock().unwrap().len();
                let completed = peer.inbound_transfers.iter()
                    .filter(|e| matches!(e.val(), super::RldpTransfer::Done)).count();
                actual.push(serde_json::json!({"part":part,"active":active,"completed":completed,"complete_packets":completed_parts.load(Ordering::Acquire),"deliveries":deliveries.load(Ordering::Acquire)}));
            }
            assert_eq!(actual, native, "native part admission and recovery effects");
        };
        tokio::select! {
            result = query => panic!("partial transfer must not resolve held query: {result:?}"),
            () = inject => {},
        }
    }).catch_unwind().await;
    reply.hold.store(false, Ordering::Release);
    reply.release.notify_waiters();
    reply.release.notify_one();
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_later_first_part_cannot_reopen_a_pruned_completed_id() {
    let (_, _, nodes, rldps, peers) = pair().await;
    let outcome = std::panic::AssertUnwindSafe(async {
        let peer = rldps[0].get_peer(peers.local(), peers.other(), true, None).await.unwrap();
        let stale = [97; 32];
        peer.finish_inbound(
            &peer.inbound_transfers,
            stale,
            &tokio_util::sync::CancellationToken::new(),
            tokio::time::Instant::now(),
        );
        assert!(
            peer.admit_inbound(stale, true, false, true).unwrap(),
            "completed replay keeps priority even for a later part"
        );
        for n in 0..2048u32 {
            let mut id = [98; 32];
            id[..4].copy_from_slice(&n.to_le_bytes());
            peer.finish_inbound(
                &peer.inbound_transfers,
                id,
                &tokio_util::sync::CancellationToken::new(),
                tokio::time::Instant::now(),
            );
        }
        assert!(peer.inbound_transfers.get(&stale).is_none());
        let later = rldps[0].inbound(&stale, &peers, true, peer.clone(), 1, 1024).await.unwrap();
        assert!(
            matches!(later, super::InboundRegistration::Refused),
            "pruned completed duplicate cannot create a receiver from a later part"
        );
        assert!(peer.inbound_transfers.get(&stale).is_none());
        assert!(peer.inbound_active.lock().unwrap().is_empty());
        assert!(peer.admit_inbound(stale, true, true, true).unwrap());
        let oversized =
            rldps[0].inbound(&stale, &peers, true, peer.clone(), 0, 7684).await.unwrap();
        assert!(matches!(oversized, super::InboundRegistration::Refused));
        assert!(peer.inbound_transfers.get(&stale).is_none());
        assert!(peer.inbound_active.lock().unwrap().is_empty());
        let first = rldps[0].inbound(&stale, &peers, true, peer.clone(), 0, 1024).await.unwrap();
        assert!(matches!(first, super::InboundRegistration::Created(_)));
        assert_eq!(peer.inbound_active.lock().unwrap().len(), 1);
    })
    .catch_unwind()
    .await;
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_changed_total_overruns_original_receive_and_recovers() {
    use rtos_api::{IntoBoxed, RldpChunk};
    // Native RldpIn::receive_message forwards the transport error to the
    // matching query promise; it must not become a successful empty reply.
    let native = checked_ack_native_effects(
        include_bytes!("../../../ci/conformance/rldp2_transfer_size_changes_context.tsv"),
        include_bytes!("../../../ci/conformance/rldp2_transfer_size_changes_effects.jsonl"),
        include_bytes!("../../../ci/conformance/rldp2_transfer_size_changes_reference.cpp"),
        include_bytes!("../../../ci/conformance/rldp2_transfer_size_changes_metadata.json"),
    );
    let effect = native.iter().find(|r| r["id"] == "changed_next_oversize").unwrap();
    assert_eq!(effect["errors"], 1);
    assert_eq!(effect["active"], 0);
    assert_eq!(effect["completed"], 1);
    let (reply, packets, nodes, rldps, peers) = pair().await;
    *packets.handler.lock().unwrap() = Some(Arc::downgrade(&rldps[0]));
    let outcome = std::panic::AssertUnwindSafe(async {
        reply.hold.store(true, Ordering::Release);
        let bytes = serialize_boxed(&Query { overlay: UInt256::default() }).unwrap();
        let query = TaggedByteSlice {
            object: &bytes,
            #[cfg(feature = "telemetry")]
            tag: 0,
        };
        let request = rldps[0].query(&query, Some(4_000_001), &peers, true, None);
        let inject = async {
            tokio::time::timeout(Duration::from_secs(2), reply.entered.notified())
                .await
                .expect("real query must reach held subscriber");
            let peer = rldps[0].get_peer(peers.local(), peers.other(), true, None).await.unwrap();
            let id = *peer
                .inbound_transfers
                .iter()
                .find(|e| matches!(e.val(), super::RldpTransfer::Recv(_)))
                .expect("query must register its answer transfer")
                .key();
            let route = AdnlPeers::with_keys(peers.other().clone(), peers.local().clone());
            for (part, total, size) in [(0, 2_000_001, 2_000_000), (1, 2_000_002, 2)] {
                let mut encoder = crate::RaptorqEncoder::with_data(&vec![42; size], Some(768));
                let mut seqno = 0;
                let chunk = RldpChunk {
                    transfer_id: id.into(),
                    fec_type: encoder.params().clone().into_boxed(),
                    part,
                    total_size: total,
                    data: encoder.encode(&mut seqno).unwrap(),
                    seqno: 0,
                };
                let wire =
                    serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed()).unwrap();
                let before = packets.processed_parts.load(Ordering::Acquire);
                nodes[1]
                    .send_custom(
                        &TaggedByteSlice {
                            object: &wire,
                            #[cfg(feature = "telemetry")]
                            tag: 0,
                        },
                        &route,
                    )
                    .await
                    .unwrap();
                tokio::time::timeout(Duration::from_secs(2), async {
                    while packets.processed_parts.load(Ordering::Acquire) == before {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                })
                .await
                .expect("authenticated handler must enqueue each packet in order");
            }
            tokio::time::timeout(Duration::from_secs(2), async {
                while !peer
                    .inbound_transfers
                    .get(&id)
                    .is_some_and(|e| matches!(e.val(), super::RldpTransfer::Done))
                {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .expect("overrun must retire the actual receive into completed cache");
            assert!(!peer.inbound_active.lock().unwrap().contains(&id));
        };
        let (result, ()) =
            tokio::time::timeout(Duration::from_secs(3), async { tokio::join!(request, inject) })
                .await
                .expect("decoder error must resolve query before its deadline");
        let error = result.expect_err("native decoder errors must propagate to the query caller");
        assert!(
            error.to_string().contains("original transfer size"),
            "expected the actual part offset error, got {error}"
        );
        reply.hold.store(false, Ordering::Release);
        reply.release.notify_one();
        let (answer, _) = tokio::time::timeout(
            Duration::from_secs(3),
            rldps[0].query(&query, Some(1024), &peers, true, None),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(answer.unwrap(), vec![42; 64], "same peer must recover after the error");
    })
    .catch_unwind()
    .await;
    reply.hold.store(false, Ordering::Release);
    reply.release.notify_waiters();
    reply.release.notify_one();
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_existing_part_fec_changes_continue_through_adnl() {
    use rtos_api::IntoBoxed;
    let native = checked_ack_native_effects(
        include_bytes!("../../../ci/conformance/rldp2_existing_part_fec_context.tsv"),
        include_bytes!("../../../ci/conformance/rldp2_existing_part_fec_effects.jsonl"),
        include_bytes!("../../../ci/conformance/rldp2_existing_part_fec_reference.cpp"),
        include_bytes!("../../../ci/conformance/rldp2_existing_part_fec_metadata.json"),
    );
    for (name, original, changed) in [("changed_grow", 2048, 3072), ("changed_shrink", 3072, 2048)]
    {
        let effect = native.iter().find(|row| row["id"] == name).unwrap();
        assert_eq!(effect["errors"], 0);
        assert_eq!(effect["active"], 1);
        let expected = effect["max_received"].as_i64().unwrap() as i32;
        let remote = Arc::new(ResponsePackets::default());
        let (reply, packets, nodes, rldps, peers) =
            topology_with_remote_observer(2, Some(remote.clone())).await;
        *packets.handler.lock().unwrap() = Some(Arc::downgrade(&rldps[0]));
        let outcome = std::panic::AssertUnwindSafe(async {
            reply.hold.store(true, Ordering::Release);
            let bytes = serialize_boxed(&Query { overlay: UInt256::default() }).unwrap();
            let query = TaggedByteSlice {
                object: &bytes,
                #[cfg(feature = "telemetry")]
                tag: 0,
            };
            let inject = async {
                tokio::time::timeout(Duration::from_secs(2), reply.entered.notified())
                    .await
                    .unwrap();
                let peer =
                    rldps[0].get_peer(peers.local(), peers.other(), true, None).await.unwrap();
                let id = *peer
                    .inbound_transfers
                    .iter()
                    .find(|e| matches!(e.val(), super::RldpTransfer::Recv(_)))
                    .expect("held query registers answer transfer")
                    .key();
                *remote.confirm_received.lock().unwrap() = Some((id.to_vec(), 0));
                let route = AdnlPeers::with_keys(peers.other().clone(), peers.local().clone());
                for (size, sequence) in [(original, 0), (changed, 1), (changed, 1)] {
                    let mut encoder = crate::RaptorqEncoder::with_data(&vec![42; size], Some(768));
                    let mut seq = sequence;
                    let chunk = rtos_api::RldpChunk {
                        transfer_id: id.into(),
                        fec_type: encoder.params().clone().into_boxed(),
                        part: 0,
                        total_size: size as i64,
                        data: encoder.encode(&mut seq).unwrap(),
                        seqno: sequence as i32,
                    };
                    let wire =
                        serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed())
                            .unwrap();
                    let before = packets.processed_parts.load(Ordering::Acquire);
                    nodes[1]
                        .send_custom(
                            &TaggedByteSlice {
                                object: &wire,
                                #[cfg(feature = "telemetry")]
                                tag: 0,
                            },
                            &route,
                        )
                        .await
                        .unwrap();
                    tokio::time::timeout(Duration::from_secs(2), async {
                        while packets.processed_parts.load(Ordering::Acquire) == before {
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                    })
                    .await
                    .expect("authenticated handler enqueues packets in order");
                }
                // This ACK is a decoder-processing witness, not merely enqueue observation.
                tokio::time::timeout(Duration::from_secs(2), async {
                    while remote.confirm_received.lock().unwrap().as_ref().unwrap().1 < expected {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                })
                .await
                .expect("native-equivalent ACK must reach authenticated remote peer");
                assert_eq!(remote.confirm_received.lock().unwrap().as_ref().unwrap().1, expected);
                assert!(peer.inbound_active.lock().unwrap().contains(&id));
            };
            tokio::select! {
                result = rldps[0].query(&query, Some(4_000_001), &peers, true, None) =>
                    panic!("{name}: incomplete native transfer must not resolve query: {result:?}"),
                () = inject => {}
            }
            reply.hold.store(false, Ordering::Release);
            reply.release.notify_one();
            let (answer, _) = tokio::time::timeout(
                Duration::from_secs(3),
                rldps[0].query(&query, Some(1024), &peers, true, None),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(answer.unwrap(), vec![42; 64]);
        })
        .catch_unwind()
        .await;
        reply.hold.store(false, Ordering::Release);
        reply.release.notify_waiters();
        reply.release.notify_one();
        for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await
        {
            result.unwrap();
        }
        if let Err(panic) = outcome {
            std::panic::resume_unwind(panic);
        }
    }
}

async fn check_unsolicited_mtu(name: &str) {
    use rtos_api::IntoBoxed;
    let native = checked_ack_native_effects(
        include_bytes!("../../../ci/conformance/rldp2_unsolicited_mtu_context.tsv"),
        include_bytes!("../../../ci/conformance/rldp2_unsolicited_mtu_effects.jsonl"),
        include_bytes!("../../../ci/conformance/rldp2_unsolicited_mtu_reference.cpp"),
        include_bytes!("../../../ci/conformance/rldp2_unsolicited_mtu_metadata.json"),
    );
    let expected = native.iter().find(|row| row["id"] == name).unwrap();
    let line = include_str!("../../../ci/conformance/rldp2_unsolicited_mtu_context.tsv")
        .lines()
        .find(|line| line.split_whitespace().next() == Some(name))
        .unwrap();
    let size: usize = line.split_whitespace().nth(1).unwrap().parse().unwrap();
    let remote = Arc::new(ResponsePackets::default());
    let (reply, packets, nodes, rldps, peers) =
        topology_with_remote_observer(2, Some(remote.clone())).await;
    *packets.handler.lock().unwrap() = Some(Arc::downgrade(&rldps[0]));
    let outcome = std::panic::AssertUnwindSafe(async {
        assert_eq!(rldps[0].peer_inbound_cap(peers.other(), false), 2048);
        assert_eq!(rldps[0].peer_inbound_cap(peers.other(), true), 7680);
        rldps[0].change_inbound_cap_for_peers(&[peers.other().clone()], 1).unwrap();
        assert_eq!(rldps[0].peer_inbound_cap(peers.other(), false), 16 * 1024 * 1024);
        assert_eq!(rldps[0].peer_inbound_cap(peers.other(), true), 16 * 1024 * 1024);
        rldps[0].change_inbound_cap_for_peers(&[peers.other().clone()], -1).unwrap();
        assert_eq!(rldps[0].peer_inbound_cap(peers.other(), false), 2048);
        assert_eq!(rldps[0].peer_inbound_cap(peers.other(), true), 7680);
        let mut payload = vec![42; size];
        payload[..4].copy_from_slice(b"mtu:");
        let message = serialize_boxed(
            &rtos_api::ton::rldp::message::Message { id: UInt256::default(), data: payload }
                .into_boxed(),
        )
        .unwrap();
        assert_eq!(message.len() as u64, expected["wire_size"].as_u64().unwrap());
        let mut encoder = crate::RaptorqEncoder::with_data(&message, Some(768));
        let mut wire_packets = Vec::new();
        for sequence in 0..message.len().div_ceil(768) {
            let mut seq = sequence as u32;
            let data = encoder.encode(&mut seq).unwrap();
            assert_eq!(seq, sequence as u32);
            wire_packets.push(
                serialize_boxed(
                    &rldp2::messagepart::MessagePart(rtos_api::RldpChunk {
                        transfer_id: UInt256::default(),
                        fec_type: encoder.params().clone().into_boxed(),
                        part: 0,
                        total_size: message.len() as i64,
                        seqno: seq as i32,
                        data,
                    })
                    .into_boxed(),
                )
                .unwrap(),
            );
        }
        let replay = wire_packets[0].clone();
        let mut transcript = wire_packets.concat();
        transcript.extend(&replay);
        assert_eq!(
            hex::encode(rtos_block::sha256_digest(&transcript)),
            expected["input_sha256"].as_str().unwrap()
        );
        let route = AdnlPeers::with_keys(peers.other().clone(), peers.local().clone());
        let peer = rldps[0].get_peer(peers.local(), peers.other(), true, None).await.unwrap();
        let deliver = expected["deliveries"].as_u64().unwrap();
        for wire in wire_packets.iter().chain(std::iter::once(&replay)) {
            let before = packets.processed_parts.load(Ordering::Acquire);
            nodes[1]
                .send_custom(
                    &TaggedByteSlice {
                        object: wire,
                        #[cfg(feature = "telemetry")]
                        tag: 0,
                    },
                    &route,
                )
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(2), async {
                while packets.processed_parts.load(Ordering::Acquire) == before {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .expect("authenticated handler returned");
            if deliver == 0 {
                // Native drops over-MTU packets before creating any receiver.
                assert!(
                    peer.inbound_transfers.get(&[0; 32]).is_none(),
                    "{name}: over-MTU packet acquired receiver/cache state"
                );
                assert!(!peer.inbound_active.lock().unwrap().contains(&[0; 32]));
            }
        }
        if deliver > 0 {
            tokio::time::timeout(Duration::from_secs(2), async {
                while reply.messages.load(Ordering::Acquire) < deliver as usize {
                    reply.message_received.notified().await;
                }
                while remote.complete_packets.load(Ordering::Acquire)
                    < expected["complete_packets"].as_u64().unwrap() as usize
                {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .expect("native accepted message must be delivered and replay acknowledged");
            assert_eq!(
                reply.message_hash.lock().unwrap().as_deref().unwrap(),
                expected["payload_sha256"].as_str().unwrap()
            );
        }
        assert_eq!(reply.messages.load(Ordering::Acquire) as u64, deliver);
        assert_eq!(
            remote.complete_packets.load(Ordering::Acquire) as u64,
            expected["complete_packets"].as_u64().unwrap()
        );
    })
    .catch_unwind()
    .await;
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_unsolicited_mtu_legacy_exact() {
    check_unsolicited_mtu("legacy_exact").await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_unsolicited_mtu_legacy_above() {
    check_unsolicited_mtu("legacy_above").await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_unsolicited_mtu_native_exact() {
    check_unsolicited_mtu("native_exact").await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_unsolicited_mtu_native_above() {
    check_unsolicited_mtu("native_above").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rldp2_completed_receive_preserves_queued_replay_ack() {
    use rtos_api::IntoBoxed;
    let expected = checked_ack_native_effects(
        include_bytes!("../../../ci/conformance/rldp2_unsolicited_mtu_context.tsv"),
        include_bytes!("../../../ci/conformance/rldp2_unsolicited_mtu_effects.jsonl"),
        include_bytes!("../../../ci/conformance/rldp2_unsolicited_mtu_reference.cpp"),
        include_bytes!("../../../ci/conformance/rldp2_unsolicited_mtu_metadata.json"),
    )
    .into_iter()
    .find(|row| row["id"] == "legacy_exact")
    .unwrap();
    let (_, packets, nodes, _, peers) = pair().await;
    let outcome = std::panic::AssertUnwindSafe(async {
        let mut payload = vec![42; 2008];
        payload[..4].copy_from_slice(b"mtu:");
        let message = serialize_boxed(
            &rtos_api::ton::rldp::message::Message { id: UInt256::default(), data: payload }
                .into_boxed(),
        )
        .unwrap();
        assert_eq!(message.len(), 2048);
        let mut encoder = crate::RaptorqEncoder::with_data(&message, Some(768));
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut chunks = Vec::new();
        let mut transcript = Vec::new();
        for sequence in 0..message.len().div_ceil(768) {
            let mut seqno = sequence as u32;
            chunks.push(rldp2::messagepart::MessagePart(rtos_api::RldpChunk {
                transfer_id: UInt256::default(),
                fec_type: encoder.params().clone().into_boxed(),
                part: 0,
                total_size: message.len() as i64,
                seqno: sequence as i32,
                data: encoder.encode(&mut seqno).unwrap(),
            }));
            assert_eq!(seqno, sequence as u32);
        }
        for chunk in chunks.iter().chain(std::iter::once(&chunks[0])) {
            transcript.extend(serialize_boxed(&chunk.clone().into_boxed()).unwrap());
            tx.send(super::Chunk::V2(chunk.clone())).unwrap();
        }
        assert_eq!(
            hex::encode(rtos_block::sha256_digest(&transcript)),
            expected["input_sha256"].as_str().unwrap()
        );
        let mut context = super::recv::RecvContext {
            adnl: nodes[1].clone(),
            peers: AdnlPeers::with_keys(peers.other().clone(), peers.local().clone()),
            queue_reader: rx,
            recv_transfer: super::recv::RecvTransfer::new(
                [0; 32],
                Arc::new(std::sync::atomic::AtomicU64::new(0)),
                true,
                Some(7680),
                #[cfg(feature = "debug")]
                Arc::new(std::sync::atomic::AtomicPtr::new(std::ptr::null_mut())),
            ),
            // Solicited contexts name the outgoing request, not the response.
            transfer_id: [255; 32],
            #[cfg(feature = "debug")]
            loss_fn: None,
        };
        RldpNode::receive_loop(&mut context, true).await;
        assert_eq!(context.recv_transfer.data, message);
        assert!(context.queue_reader.is_empty());
        tokio::time::timeout(Duration::from_secs(2), async {
            while packets.complete_packets.load(Ordering::Acquire) == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("queued post-completion replay must produce native Complete ACK");
        assert_eq!(
            packets.complete_packets.load(Ordering::Acquire) as u64,
            expected["complete_packets"].as_u64().unwrap()
        );
        assert_eq!(
            *packets.complete_transfer_ids.lock().unwrap(),
            HashSet::from([vec![0; 32]]),
            "Complete must identify the received response, not its request"
        );
        drop(tx);
    })
    .catch_unwind()
    .await;
    for result in futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await {
        result.unwrap();
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}
