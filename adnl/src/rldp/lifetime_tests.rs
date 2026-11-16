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
    hold: AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
#[async_trait::async_trait]
impl Subscriber for HeldReply {
    async fn try_consume_query(&self, object: TLObject, _: &AdnlPeers) -> Result<QueryResult> {
        match object.downcast::<Query>() {
            Ok(_) => {
                if self.hold.load(Ordering::Acquire) {
                    self.entered.notify_one();
                    self.release.notified().await;
                }
                Ok(QueryResult::Consumed(QueryAnswer::Ready(Some(Answer::Raw(TaggedByteVec {
                    object: vec![42; 64],
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
                vec![([17 + index as u8; 32], 0)],
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
                matches!(rldps[1].transfers.get(&id).unwrap().val(), super::RldpTransfer::Send(_)),
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
