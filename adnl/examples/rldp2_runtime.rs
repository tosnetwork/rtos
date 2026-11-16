//! Observe the production RLDP2 query entry using a fixed sequence on one peer pair.
use adnl::{
    common::{
        AdnlPeers, Answer, QueryAnswer, QueryResult, Subscriber, TaggedByteSlice, TaggedByteVec,
    },
    node::AdnlNode,
    RldpNode,
};
use rtos_api::{serialize_boxed, ton::rpc::overlay::Query, TLObject};
use rtos_block::{Result, UInt256};
use std::{io::BufRead, sync::Arc, time::Duration};

#[path = "../tests/test_utils.rs"]
mod test_utils;

struct Reply;

#[async_trait::async_trait]
impl Subscriber for Reply {
    async fn try_consume_query(&self, object: TLObject, _: &AdnlPeers) -> Result<QueryResult> {
        match object.downcast::<Query>() {
            Ok(query) => {
                let size = u32::from_le_bytes(query.overlay.as_slice()[..4].try_into()?) as usize;
                anyhow::ensure!(size <= 2 * 1024 * 1024, "probe reply exceeds input bound");
                let object = (0..size).map(|i| (i % 251) as u8).collect();
                Ok(QueryResult::Consumed(QueryAnswer::Ready(Some(Answer::Raw(TaggedByteVec {
                    object,
                    #[cfg(feature = "telemetry")]
                    tag: 0,
                })))))
            }
            Err(object) => Ok(QueryResult::Rejected(object)),
        }
    }
}

#[tokio::main(worker_threads = 4)]
async fn main() -> Result<()> {
    // Parse all bounded inputs before opening sockets. Columns: id direction size limit.
    let mut cases = Vec::new();
    for line in std::io::stdin().lock().lines() {
        let line = line?;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        anyhow::ensure!(fields.len() == 4, "expected four columns");
        anyhow::ensure!(
            fields[0].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
            "invalid case id"
        );
        let direction: usize = fields[1].parse()?;
        let size: u32 = fields[2].parse()?;
        let limit: u64 = fields[3].parse()?;
        anyhow::ensure!(
            direction < 2 && size <= 2 * 1024 * 1024 && limit <= 2 * 1024 * 1024,
            "input exceeds probe bound"
        );
        cases.push((fields[0].to_owned(), direction, size, limit));
        anyhow::ensure!(cases.len() <= 100, "too many cases");
    }
    anyhow::ensure!(!cases.is_empty(), "empty scenario");
    let mut nodes = Vec::new();
    let mut rldps = Vec::new();
    let outcome: Result<()> = async {
        for _ in 0..2 {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
            let address = socket.local_addr()?.to_string();
            let config = test_utils::generate_adnl_configs(&address, vec![0], None)?.1;
            drop(socket);
            let node = AdnlNode::with_config(config).await?;
            nodes.push(node.clone());
            let rldp = RldpNode::with_params(
                node.clone(), vec![Arc::new(Reply)], None,
                #[cfg(feature = "debug")] None,
                #[cfg(feature = "debug")] None,
            )?;
            node.start_over_udp(vec![rldp.clone()]).await?;
            rldps.push(rldp);
        }
        let keys = [nodes[0].key_by_tag(0)?, nodes[1].key_by_tag(0)?];
        for i in 0..2 {
            nodes[i].add_peer(keys[i].id(), nodes[1-i].ip_address_adnl(), None, &keys[1-i])?;
        }
        for (id, direction, size, limit) in cases {
            let mut request = [0; 32];
            request[..4].copy_from_slice(&size.to_le_bytes());
            let bytes = serialize_boxed(&Query { overlay: UInt256::with_array(request) })?;
            let query = TaggedByteSlice {
                object: &bytes,
                #[cfg(feature = "telemetry")] tag: 0,
            };
            let peers = AdnlPeers::with_keys(keys[direction].id().clone(), keys[1-direction].id().clone());
            let started = std::time::Instant::now();
            let result = tokio::time::timeout(Duration::from_secs(30), rldps[direction].query(&query, Some(limit), &peers, true, None)).await;
            let (status, payload, diagnostic) = match result {
                Ok(Ok((Some(bytes), _))) => ("answer", hex::encode(bytes), String::new()),
                Ok(Ok((None, _))) => ("no_answer", String::new(), String::new()),
                Ok(Err(error)) if error.downcast_ref::<adnl::RldpQueryTimeout>().is_some() => ("timeout", String::new(), error.to_string()),
                Ok(Err(error)) => ("error", String::new(), format!("{error:#}")),
                Err(error) => ("harness_timeout", String::new(), error.to_string()),
            };
            println!("{}", serde_json::json!({"id":id,"status":status,"payload_hex":payload,"diagnostic":diagnostic,"elapsed_ms":started.elapsed().as_millis()}));
            anyhow::ensure!(status != "harness_timeout", "query exceeded harness deadline");
        }
        Ok(())
    }.await;
    // Join both nodes even if an input operation or the first stop failed.
    let stops = futures::future::join_all(nodes.iter().map(|node| node.stop_checked())).await;
    outcome?;
    for stopped in stops {
        stopped?;
    }
    Ok(())
}
