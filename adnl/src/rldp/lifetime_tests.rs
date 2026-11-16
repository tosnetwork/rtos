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
    calls: std::sync::atomic::AtomicUsize,
    response_bytes: std::sync::atomic::AtomicUsize,
    hold: AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
#[async_trait::async_trait]
impl Subscriber for HeldReply {
    async fn try_consume_custom(&self, bytes: &[u8], _: &AdnlPeers) -> Result<bool> {
        if bytes == b"churn" {
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
    transfers: Mutex<HashSet<Vec<u8>>>,
    drop_parts: AtomicBool,
}
#[async_trait::async_trait]
impl Subscriber for ResponsePackets {
    async fn try_consume_custom(&self, bytes: &[u8], _: &AdnlPeers) -> Result<bool> {
        if let Ok(message) = deserialize_boxed(bytes) {
            if let Ok(rldp2::MessagePart::Rldp2_MessagePart(part)) =
                message.downcast::<rldp2::MessagePart>()
            {
                self.transfers.lock().unwrap().insert(part.0.transfer_id.as_slice().to_vec());
                if self.drop_parts.load(Ordering::Acquire) {
                    return Ok(true);
                }
            }
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
        assert!(pending.next().now_or_never().is_none());
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
        assert!(pending.next().now_or_never().is_none());
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
            assert!(peer.admit_inbound(id).unwrap());
        }
        let stale = [77; 32];
        peer.finish_inbound(
            &peer.inbound_transfers,
            stale,
            &tokio_util::sync::CancellationToken::new(),
            tokio::time::Instant::now(),
        );
        assert!(peer.admit_inbound(stale).unwrap(), "completed duplicates bypass active capacity");
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
        let created = rldps[0].inbound(&stale, &peers, true, peer.clone()).await.unwrap();
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
