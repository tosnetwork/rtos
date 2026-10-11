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
            let config =
                test_utils::get_adnl_config("bounded-rldp", &address, vec![0], true).await.unwrap();
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
fn bounded_rldp_cancelled_waiter_keeps_receiver_owned_until_stop() {
    let runtime =
        tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap();
    runtime.block_on(async {
        let gate = Arc::new((tokio::sync::Notify::new(), tokio::sync::Notify::new()));
        let mut nodes = Vec::new();
        let mut rldps = Vec::new();
        for index in 0..2 {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let address = socket.local_addr().unwrap().to_string();
            let config =
                test_utils::get_adnl_config("bounded-rldp", &address, vec![0], true).await.unwrap();
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
        let node = nodes[0].clone();
        let stopping = tokio::spawn(async move { node.stop_checked().await });
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let retained = !stopping.is_finished();
        gate.1.notify_one();
        let stopped = tokio::time::timeout(std::time::Duration::from_secs(40), stopping).await;
        nodes[1].stop_checked().await.unwrap();
        assert!(entered, "actual peer must receive the query");
        assert!(retained, "cancelled observer cannot discard the live receive owner");
        stopped.expect("bounded receive must terminate and join").unwrap().unwrap();
    });
}
