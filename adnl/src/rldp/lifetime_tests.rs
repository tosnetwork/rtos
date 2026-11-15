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
struct ResponsePackets(Mutex<HashSet<Vec<u8>>>);
#[async_trait::async_trait]
impl Subscriber for ResponsePackets {
    async fn try_consume_custom(&self, bytes: &[u8], _: &AdnlPeers) -> Result<bool> {
        if let Ok(message) = deserialize_boxed(bytes) {
            if let Ok(rldp2::MessagePart::Rldp2_MessagePart(part)) =
                message.downcast::<rldp2::MessagePart>()
            {
                self.0.lock().unwrap().insert(part.0.transfer_id.as_slice().to_vec());
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
    let reply = Arc::new(HeldReply::default());
    let packets = Arc::new(ResponsePackets::default());
    let mut nodes = Vec::new();
    let mut rldps = Vec::new();
    for index in 0..2 {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let (_, config) = AdnlNodeConfig::from_ip_address_and_private_keys(
            &socket.local_addr().unwrap().to_string(),
            vec![([17 + index as u8; 32], 0)],
        )
        .unwrap();
        drop(socket);
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
        node.start_over_udp(subscribers).await.unwrap();
        nodes.push(node);
        rldps.push(rldp);
    }
    let keys = [nodes[0].key_by_tag(0).unwrap(), nodes[1].key_by_tag(0).unwrap()];
    for index in 0..2 {
        nodes[index]
            .add_peer(keys[index].id(), nodes[1 - index].ip_address_adnl(), None, &keys[1 - index])
            .unwrap();
    }
    let outcome = std::panic::AssertUnwindSafe(async {
        let peers = AdnlPeers::with_keys(keys[0].id().clone(), keys[1].id().clone());
        let bytes = serialize_boxed(&Query { overlay: UInt256::default() }).unwrap();
        let query = TaggedByteSlice {
            object: &bytes,
            #[cfg(feature = "telemetry")]
            tag: 0,
        };
        let (answer, _) = rldps[0].query(&query, Some(1024), &peers, true, None).await.unwrap();
        assert_eq!(answer.unwrap(), vec![42; 64]);
        let before = packets.0.lock().unwrap().clone();
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
            *packets.0.lock().unwrap(),
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
