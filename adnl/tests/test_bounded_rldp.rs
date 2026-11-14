use adnl::{
    common::{
        AdnlPeers, Answer, QueryAnswer, QueryResult, Subscriber, TaggedByteSlice, TaggedByteVec,
    },
    node::{AdnlNode, DataCompression},
    QueryResponseLimits, ResponseLimitExceeded, RldpNode,
};
use futures::FutureExt;
use rtos_api::{serialize_boxed, ton::rpc::overlay::Query, TLObject};
use rtos_block::{Result, UInt256};
use std::sync::Arc;
#[path = "test_utils.rs"]
mod test_utils;

struct Reply {
    gate: Option<Arc<(tokio::sync::Notify, tokio::sync::Notify)>>,
}
#[async_trait::async_trait]
impl Subscriber for Reply {
    async fn try_consume_query(&self, object: TLObject, _: &AdnlPeers) -> Result<QueryResult> {
        if let Some(gate) = &self.gate {
            gate.0.notify_one();
            gate.1.notified().await;
        }
        match object.downcast::<Query>() {
            Ok(_) => {
                Ok(QueryResult::Consumed(QueryAnswer::Ready(Some(Answer::Raw(TaggedByteVec {
                    object: vec![42; 4096],
                    #[cfg(feature = "telemetry")]
                    tag: 0,
                })))))
            }
            Err(object) => Ok(QueryResult::Rejected(object)),
        }
    }
}

#[test]
fn bounded_rldp_real_compressed_answer_rejects_expansion_and_then_succeeds() {
    let runtime =
        tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();
    runtime.block_on(async {
        let mut nodes = Vec::new();
        let mut rldps = Vec::new();
        for _ in 0..2 {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let address = socket.local_addr().unwrap().to_string();
            let config = test_utils::generate_adnl_configs(&address, vec![0], None).unwrap().1;
            drop(socket);
            let node = AdnlNode::with_config(config).await.unwrap();
            node.set_options(AdnlNode::OPTION_FORCE_COMPRESSION);
            let rldp = RldpNode::with_params(
                node.clone(),
                vec![Arc::new(Reply { gate: None })],
                None,
                #[cfg(feature = "debug")]
                None,
                #[cfg(feature = "debug")]
                None,
            )
            .unwrap();
            node.start_over_udp(vec![rldp.clone()]).await.unwrap();
            nodes.push(node);
            rldps.push(rldp);
        }
        let key0 = nodes[0].key_by_tag(0).unwrap();
        let key1 = nodes[1].key_by_tag(0).unwrap();
        nodes[0].add_peer(key0.id(), nodes[1].ip_address_adnl(), None, &key1).unwrap();
        nodes[1].add_peer(key1.id(), nodes[0].ip_address_adnl(), None, &key0).unwrap();
        let outcome = std::panic::AssertUnwindSafe(async {
            let peers = AdnlPeers::with_keys(key0.id().clone(), key1.id().clone());
            let bytes = serialize_boxed(&Query { overlay: UInt256::default() }).unwrap();
            let data = TaggedByteSlice {
                object: &bytes,
                #[cfg(feature = "telemetry")]
                tag: 0,
            };
            let error = rldps[0]
                .query_bounded(
                    &data,
                    QueryResponseLimits { wire_bytes: 1024, decoded_bytes: 1024 },
                    &peers,
                    true,
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(error.downcast_ref::<ResponseLimitExceeded>().unwrap().actual, 4096);
            let (reply, _) = rldps[0]
                .query_bounded(
                    &data,
                    QueryResponseLimits { wire_bytes: 1024, decoded_bytes: 4096 },
                    &peers,
                    true,
                    None,
                )
                .await
                .unwrap();
            assert_eq!(reply.unwrap(), vec![42; 4096]);
        })
        .catch_unwind()
        .await;
        nodes[0].stop_checked().await.unwrap();
        nodes[1].stop_checked().await.unwrap();
        if let Err(error) = outcome {
            std::panic::resume_unwind(error);
        }
    });
}

#[test]
fn bounded_rldp_transparent_expansion_checks_advertised_size() {
    let compressed = DataCompression::compress_raw(&vec![17; 4096]).unwrap();
    assert!(compressed.len() < 1024);
    assert!(DataCompression::decompress_raw_bounded(&compressed, 1024)
        .unwrap_err()
        .downcast_ref::<ResponseLimitExceeded>()
        .is_some());
    assert_eq!(
        DataCompression::decompress_raw_bounded(&compressed, 4096).unwrap().unwrap(),
        vec![17; 4096]
    );
}

#[test]
fn bounded_rldp_cancelled_client_drains_while_server_retains_subscriber() {
    let runtime =
        tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();
    runtime.block_on(async {
        let gate = Arc::new((tokio::sync::Notify::new(), tokio::sync::Notify::new()));
        let mut nodes = Vec::new();
        let mut rldps = Vec::new();
        for index in 0..2 {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let address = socket.local_addr().unwrap().to_string();
            let config = test_utils::generate_adnl_configs(&address, vec![0], None).unwrap().1;
            drop(socket);
            let node = AdnlNode::with_config(config).await.unwrap();
            node.set_options(AdnlNode::OPTION_FORCE_COMPRESSION);
            let rldp = RldpNode::with_params(
                node.clone(),
                vec![Arc::new(Reply { gate: (index == 1).then(|| gate.clone()) })],
                None,
                #[cfg(feature = "debug")]
                None,
                #[cfg(feature = "debug")]
                None,
            )
            .unwrap();
            node.start_over_udp(vec![rldp.clone()]).await.unwrap();
            nodes.push(node);
            rldps.push(rldp);
        }
        let key0 = nodes[0].key_by_tag(0).unwrap();
        let key1 = nodes[1].key_by_tag(0).unwrap();
        nodes[0].add_peer(key0.id(), nodes[1].ip_address_adnl(), None, &key1).unwrap();
        nodes[1].add_peer(key1.id(), nodes[0].ip_address_adnl(), None, &key0).unwrap();

        let peers = AdnlPeers::with_keys(key0.id().clone(), key1.id().clone());
        let client = rldps[0].clone();
        let caller = tokio::spawn(async move {
            let bytes = serialize_boxed(&Query { overlay: UInt256::default() }).unwrap();
            let data = TaggedByteSlice {
                object: &bytes,
                #[cfg(feature = "telemetry")]
                tag: 0,
            };
            client
                .query_bounded(
                    &data,
                    QueryResponseLimits { wire_bytes: 1024, decoded_bytes: 4096 },
                    &peers,
                    true,
                    None,
                )
                .await
        });
        let entered = tokio::time::timeout(std::time::Duration::from_secs(10), gate.0.notified())
            .await
            .is_ok();
        caller.abort();
        let _ = caller.await;
        let client = nodes[0].clone();
        let server = nodes[1].clone();
        let mut client_stop = tokio::spawn(async move { client.stop_checked().await });
        let mut server_stop = tokio::spawn(async move { server.stop_checked().await });
        // The gate belongs to the remote subscriber, not the idle client
        // receiver. Cancelling that receiver may finish normally; the server
        // must retain the actual subscriber future through its completion.
        let client_observed =
            tokio::time::timeout(std::time::Duration::from_secs(10), &mut client_stop).await;
        let server_observed =
            tokio::time::timeout(std::time::Duration::from_millis(80), &mut server_stop).await;
        let client_drained = client_observed.is_ok();
        let server_retained = server_observed.is_err();

        // Release before any assertion, and collect both real JoinHandles even
        // when an observation failed. A timeout never drops a live stop owner.
        gate.1.notify_one();
        let client_stopped = match client_observed {
            Ok(result) => result,
            Err(_) => client_stop.await,
        };
        let server_stopped = match server_observed {
            Ok(result) => result,
            Err(_) => server_stop.await,
        };
        client_stopped.expect("client stop task must join").expect("client must drain");
        server_stopped.expect("server stop task must join").expect("server must drain");
        assert!(entered, "actual peer must receive the query");
        assert!(client_drained, "cancelled idle client receiver must terminate and join");
        assert!(server_retained, "server stop must retain the gated live subscriber");
    });
}

// A deliberately nonconforming remote ADNL subscriber sends raw RLDP packets.
// It never enters the ordinary responder's max_answer_size check.
struct OversizeWirePeer {
    node: std::sync::Weak<AdnlNode>,
    armed: std::sync::atomic::AtomicBool,
    observed: std::sync::atomic::AtomicUsize,
    v2: bool,
}
#[async_trait::async_trait]
impl Subscriber for OversizeWirePeer {
    async fn try_consume_custom(&self, data: &[u8], peers: &AdnlPeers) -> Result<bool> {
        use rtos_api::{
            deserialize_boxed,
            ton::{rldp, rldp2},
            IntoBoxed,
        };
        use std::sync::atomic::Ordering;
        if !self.armed.load(Ordering::Acquire) {
            return Ok(false);
        }
        let Ok(message) = deserialize_boxed(data) else { return Ok(false) };
        let (mut chunk, complete) = if self.v2 {
            let Ok(rldp2::MessagePart::Rldp2_MessagePart(part)) =
                message.downcast::<rldp2::MessagePart>()
            else {
                return Ok(false);
            };
            let complete = serialize_boxed(
                &rldp2::messagepart::Complete {
                    transfer_id: part.0.transfer_id.clone(),
                    part: part.0.part,
                }
                .into_boxed(),
            )?;
            (part.0, complete)
        } else {
            let Ok(rldp::MessagePart::Rldp_MessagePart(part)) =
                message.downcast::<rldp::MessagePart>()
            else {
                return Ok(false);
            };
            let complete = serialize_boxed(
                &rldp::messagepart::Complete {
                    transfer_id: part.0.transfer_id.clone(),
                    part: part.0.part,
                }
                .into_boxed(),
            )?;
            (part.0, complete)
        };
        // This is a single ordinary query symbol, not an allocated 4096-byte
        // answer. The production receiver must reject the declared total first.
        assert!(chunk.data.len() <= 1024);
        let mut response_id = [0u8; 32];
        response_id.copy_from_slice(chunk.transfer_id.as_slice());
        for byte in &mut response_id {
            *byte ^= 0xff;
        }
        chunk.transfer_id = UInt256::from(response_id);
        chunk.total_size = 4096;
        chunk.part = 0;
        chunk.seqno = 0;
        let malicious = if self.v2 {
            serialize_boxed(&rldp2::messagepart::MessagePart(chunk).into_boxed())?
        } else {
            serialize_boxed(&rldp::messagepart::MessagePart(chunk).into_boxed())?
        };
        let node = self.node.upgrade().expect("remote node remains owned until checked stop");
        self.observed.fetch_add(1, Ordering::Release);
        for bytes in [&complete, &malicious] {
            node.send_custom(
                &TaggedByteSlice {
                    object: bytes,
                    #[cfg(feature = "telemetry")]
                    tag: 0,
                },
                peers,
            )
            .await?;
        }
        Ok(true)
    }
}

#[test]
fn bounded_rldp_real_malicious_wire_total_rejected_before_decode_v1_v2() {
    use std::{sync::atomic::Ordering, time::Duration};
    let runtime =
        tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();
    runtime.block_on(async {
        for v2 in [false, true] {
            let mut nodes = Vec::new();
            let mut rldps = Vec::new();
            let mut remote = None;
            for index in 0..2 {
                let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                let address = socket.local_addr().unwrap().to_string();
                let config = test_utils::generate_adnl_configs(&address, vec![0], None).unwrap().1;
                drop(socket);
                let node = AdnlNode::with_config(config).await.unwrap();
                node.set_options(AdnlNode::OPTION_FORCE_COMPRESSION);
                let rldp = RldpNode::with_params(
                    node.clone(),
                    vec![Arc::new(Reply { gate: None })],
                    None,
                    #[cfg(feature = "debug")]
                    None,
                    #[cfg(feature = "debug")]
                    None,
                )
                .unwrap();
                let mut subscribers: Vec<Arc<dyn Subscriber>> = Vec::new();
                if index == 1 {
                    let hostile = Arc::new(OversizeWirePeer {
                        node: Arc::downgrade(&node),
                        armed: true.into(),
                        observed: 0.into(),
                        v2,
                    });
                    subscribers.push(hostile.clone());
                    remote = Some(hostile);
                }
                subscribers.push(rldp.clone());
                node.start_over_udp(subscribers).await.unwrap();
                nodes.push(node);
                rldps.push(rldp);
            }
            let key0 = nodes[0].key_by_tag(0).unwrap();
            let key1 = nodes[1].key_by_tag(0).unwrap();
            nodes[0].add_peer(key0.id(), nodes[1].ip_address_adnl(), None, &key1).unwrap();
            nodes[1].add_peer(key1.id(), nodes[0].ip_address_adnl(), None, &key0).unwrap();
            let hostile = remote.unwrap();
            let result = std::panic::AssertUnwindSafe(async {
                let peers = AdnlPeers::with_keys(key0.id().clone(), key1.id().clone());
                let bytes = serialize_boxed(&Query { overlay: UInt256::default() }).unwrap();
                let data = TaggedByteSlice {
                    object: &bytes,
                    #[cfg(feature = "telemetry")]
                    tag: 0,
                };
                let limits = QueryResponseLimits { wire_bytes: 1024, decoded_bytes: 4096 };
                let error = tokio::time::timeout(
                    Duration::from_secs(20),
                    rldps[0].query_bounded(&data, limits, &peers, v2, None),
                )
                .await
                .expect("actual malicious response must complete, not time out")
                .unwrap_err();
                let exceeded = error
                    .downcast_ref::<ResponseLimitExceeded>()
                    .unwrap_or_else(|| panic!("expected peer-declared wire bound, got {error:#}"));
                // Current protocol allowance reserves 64 bytes for RldpAnswer TL
                // overhead in addition to the advertised payload wire limit.
                assert_eq!((exceeded.limit, exceeded.actual), (1024 + 64, 4096));
                assert!(hostile.observed.load(Ordering::Acquire) > 0);
                hostile.armed.store(false, Ordering::Release);
                let (answer, _) = tokio::time::timeout(
                    Duration::from_secs(20),
                    rldps[0].query_bounded(&data, limits, &peers, v2, None),
                )
                .await
                .expect("ordinary response must recover on the same connection")
                .unwrap();
                assert_eq!(answer.unwrap(), vec![42; 4096]);
            })
            .catch_unwind()
            .await;
            hostile.armed.store(false, Ordering::Release);
            // Collect both real joins before propagating any test failure.
            let stopped =
                futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await;
            for stop in stopped {
                stop.unwrap();
            }
            if let Err(panic) = result {
                std::panic::resume_unwind(panic);
            }
        }
    });
}
