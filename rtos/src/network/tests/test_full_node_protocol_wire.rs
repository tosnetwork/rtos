// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Real nodes on loopback: full-node queries, answers and messages travel
//! through the actual overlay, ADNL, RLDP and QUIC paths. Expected values come
//! from the C++ driver outputs of the parent module.
use super::*;
use crate::network::{
    full_node_overlay_client::FullNodeOverlayClient, node_network::NodeNetwork,
    overlay_client::OverlayClient,
};
use adnl::DhtSearchPolicy;
use futures::FutureExt;

pub(super) const CPP_DST: &str = include_str!("data/fullnode-proto/out-dst.txt");

pub(super) struct WireNode {
    pub network: Arc<NodeNetwork>,
    pub client: Arc<OverlayClient>,
    pub full: Arc<FullNodeOverlayClient>,
    pub service: Arc<FullNodeOverlayService>,
    pub engine: Arc<MemoryBlocks>,
    pub key: Arc<rtos_block::KeyId>,
    pub overlay_id: Arc<adnl::OverlayShortId>,
}

/// One node with a public overlay for `shard`, its full-node client and the
/// full-node service as the overlay's consumer.
pub(super) async fn wire_node(
    tag: &str,
    port: u16,
    shard: &ShardIdent,
    engine: Arc<MemoryBlocks>,
) -> WireNode {
    let network = crate::test_helper::create_network(None, Some(tag), &format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    network.start().await.unwrap();
    let context = network.context().clone();
    let prefix = shard.shard_prefix_with_tag() as i64;
    let overlay = &context.stack.overlay;
    let overlay_id = overlay.calc_overlay_short_id(shard.workchain_id(), prefix).unwrap();
    let id_full = overlay.calc_overlay_id(shard.workchain_id(), prefix).unwrap();
    let tasks = Arc::new(crate::types::owned_tasks::OwnedTasks::new(
        network.cancellation_token().child_token(),
    ));
    let client = OverlayClient::new_public(
        overlay_id.clone(),
        id_full,
        context.clone(),
        network.cancellation_token().clone(),
        DhtSearchPolicy::default(),
        None,
        tasks.clone(),
        None,
        None,
    )
    .await
    .unwrap();
    let service = Arc::new(FullNodeOverlayService::new(engine.clone(), false, tasks.clone()));
    client.add_consumer(service.clone()).unwrap();
    let full =
        FullNodeOverlayClient::new(engine.clone(), client.clone(), shard.clone(), tasks).unwrap();
    let key = context.stack.adnl.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY).unwrap().id().clone();
    WireNode { network, client, full, service, engine, key, overlay_id }
}

/// Makes the two nodes overlay members and neighbours of each other.
pub(super) fn connect(a: &WireNode, b: &WireNode) {
    for (local, remote) in [(a, b), (b, a)] {
        let local_stack = &local.network.context().stack;
        let remote_stack = &remote.network.context().stack;
        let advertised = remote_stack.overlay.get_signed_node(&remote.overlay_id, false).unwrap();
        let key = local_stack
            .overlay
            .add_public_peer(remote_stack.adnl.ip_address_adnl(), &advertised, &local.overlay_id)
            .unwrap()
            .unwrap();
        assert_eq!(&key, &remote.key);
        // RLDP transfers go over QUIC when the peer's QUIC key is known.
        let adnl_address = remote_stack.adnl.ip_address_adnl();
        let quic_port = adnl_address.port() + adnl::QuicNode::OFFSET_PORT;
        let quic_address = std::net::SocketAddr::new(
            std::net::Ipv4Addr::from(adnl_address.ip()).into(),
            quic_port,
        );
        local_stack.quic.as_ref().unwrap().add_peer_key(key.clone(), quic_address).unwrap();
        local.client.neighbours().add_overlay_peer(key.clone());
        assert!(local.client.neighbours().add(key).unwrap());
    }
}

pub(super) async fn stop(nodes: Vec<WireNode>) {
    for node in nodes {
        node.full.stop_and_wait().await.unwrap();
        node.network.stop_adnl().await.unwrap();
    }
}

/// Stops the nodes, then re-raises a failure of the test body.
pub(super) async fn finish(nodes: Vec<WireNode>, outcome: std::thread::Result<()>) {
    stop(nodes).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

/// The driver's DownloadState case: its outcome and the slices it asked for.
fn cpp_download(case: &str) -> (bool, Vec<(i64, i64)>, Vec<String>) {
    let line = cpp_value(CPP_DST, case);
    let ok = line.starts_with("ok");
    let queries = line
        .split(" queries ")
        .nth(1)
        .unwrap()
        .split(" slices ")
        .next()
        .unwrap()
        .split_whitespace()
        .map(|q| q.split('/').skip(1).take(2).collect::<Vec<_>>().join("/"))
        .collect();
    let slices = line
        .split(" slices ")
        .nth(1)
        .unwrap_or("")
        .split_whitespace()
        .map(|s| {
            let (offset, size) = s.split_once('+').unwrap();
            (offset.parse().unwrap(), size.parse().unwrap())
        })
        .collect();
    (ok, slices, queries)
}

/// A persistent state of exactly `size` bytes that starts with a BOC header.
fn state_bytes(size: usize) -> Vec<u8> {
    let mut bytes =
        rtos_block::write_boc(&rtos_block::BuilderData::default().into_cell().unwrap()).unwrap();
    assert!(bytes.len() < size);
    bytes.resize(size, 0x5c);
    bytes
}

// The advertised sizes of the driver's DownloadState cases (its inputs).
const CPP_PERSISTENT_STATE_SIZES: [(&str, usize); 8] = [
    ("whole_5mib", 5 * (1 << 20) + 7),
    ("whole_exact_2mib", 2 << 20),
    ("whole_small", 100),
    ("whole_oversized", 5 << 20),
    ("whole_truncated", 5 << 20),
    ("whole_last_oversized", (4 << 20) + 10),
    ("part_3mib", 3 << 20),
    ("part_truncated", 3 << 20),
];

fn cpp_state_size(case: &str) -> usize {
    CPP_PERSISTENT_STATE_SIZES.iter().find(|(c, _)| *c == case).unwrap().1
}

/// The driver's misbehaving peer: past the first slice an oversized answer
/// carries one byte too many and a truncated one a byte too few; the last
/// oversized case adds a byte to the last slice only.
fn misbehaving_slice(case: &str, state: &[u8], offset: usize, max_size: usize) -> Vec<u8> {
    let end = (offset + max_size).min(state.len());
    let mut bytes = state[offset..end].to_vec();
    let last = offset + max_size >= state.len();
    if (case.ends_with("_oversized") && !case.contains("last") && offset > 0)
        || (case == "whole_last_oversized" && last)
    {
        bytes.push(0x5c);
    }
    if case.ends_with("_truncated") && offset > 0 {
        bytes.pop();
    }
    bytes
}

#[tokio::test]
async fn persistent_state_slices_follow_the_reference_requester() {
    let block = cpp_chain("small", 1, -1, &[(3, 5)])[1].0.clone();
    for (case, size) in CPP_PERSISTENT_STATE_SIZES {
        let (cpp_ok, cpp_slices, _) = cpp_download(case);
        let state = state_bytes(size);
        let id = if case.starts_with("part") {
            PersistentStatePartId::Part(block.clone(), 0x4000_0000_0000_0000)
        } else {
            PersistentStatePartId::WholeState(block.clone())
        };
        let requested = std::sync::Mutex::new(Vec::new());
        let mut dest = std::io::Cursor::new(Vec::new());
        let result = crate::full_node::state_helper::download_slices(
            &id,
            size,
            &mut dest,
            &|| Ok(()),
            |offset, max_size, _attempt| {
                requested.lock().unwrap().push((offset as i64, max_size as i64));
                let bytes = misbehaving_slice(case, &state, offset, max_size);
                async move { Ok(bytes) }
            },
        )
        .await;
        assert_eq!(result.is_ok(), cpp_ok, "{case}: {result:?}");
        assert_eq!(*requested.lock().unwrap(), cpp_slices, "{case}: slices");
        if cpp_ok {
            assert_eq!(dest.into_inner(), state, "{case}: the state as served");
        }
    }
}

#[tokio::test]
async fn persistent_state_slice_transport_failures_are_retried_then_end_the_attempt() {
    let block = cpp_chain("small", 1, -1, &[(3, 5)])[1].0.clone();
    let id = PersistentStatePartId::WholeState(block);
    let state = state_bytes(100);
    let calls = std::sync::Mutex::new(Vec::new());
    let mut dest = std::io::Cursor::new(Vec::new());
    // Two failed transfers, then the answer.
    let result = crate::full_node::state_helper::download_slices(
        &id,
        state.len(),
        &mut dest,
        &|| Ok(()),
        |offset, max_size, attempt| {
            calls.lock().unwrap().push(attempt);
            let bytes = state[offset..offset + max_size].to_vec();
            async move {
                if attempt < 2 {
                    fail!("No bounded RLDP answer");
                }
                Ok(bytes)
            }
        },
    )
    .await;
    assert!(result.is_ok());
    assert_eq!(*calls.lock().unwrap(), vec![0, 1, 2]);
    // A slice above the requested size is not retried.
    let calls = std::sync::Mutex::new(0);
    let mut dest = std::io::Cursor::new(Vec::new());
    let result = crate::full_node::state_helper::download_slices(
        &PersistentStatePartId::WholeState(cpp_chain("small", 1, -1, &[(3, 5)])[1].0.clone()),
        state.len(),
        &mut dest,
        &|| Ok(()),
        |_offset, limit, _attempt| {
            *calls.lock().unwrap() += 1;
            async move { Err(adnl::ResponseLimitExceeded { limit, actual: limit + 1 }.into()) }
        },
    )
    .await;
    assert!(result.is_err());
    assert_eq!(*calls.lock().unwrap(), 1);
}

/// A whole state over the real overlay and RLDP: the reference's small case.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wire_persistent_state_whole() {
    let case = "whole_small";
    let size = cpp_state_size(case);
    let (cpp_ok, cpp_slices, cpp_queries) = cpp_download(case);
    assert!(cpp_ok);
    let shard = ShardIdent::masterchain();
    let chain = cpp_chain("small", 1, -1, &[(3, 5)]);
    let block = chain[1].0.clone();
    let mut nodes = vec![];
    for (i, serving) in [false, true, true].into_iter().enumerate() {
        let engine = Arc::new(MemoryBlocks::new(chain.clone()));
        if serving {
            engine.serve_state(&block, state_bytes(size), "");
        }
        nodes.push(wire_node(&format!("wire_pss_{i}"), 4620 + i as u16, &shard, engine).await);
    }
    connect(&nodes[0], &nodes[1]);
    connect(&nodes[0], &nodes[2]);
    let outcome = std::panic::AssertUnwindSafe(async {
        let nodes = &nodes;
        let id = PersistentStatePartId::WholeState(block.clone());
        let mut dest = std::io::Cursor::new(Vec::new());
        crate::full_node::state_helper::download_pss_part(
            &id,
            &block,
            &mut dest,
            &nodes[0].full,
            Some(1),
            &|| Ok(()),
        )
        .await
        .unwrap();
        assert_eq!(dest.into_inner(), state_bytes(size), "the state as served");
        // One peer serves the whole sequence in the reference's order: the
        // prepare query, the size query, then exactly its slices.
        let served: Vec<_> =
            nodes[1..].iter().filter(|n| !n.service.test_pss_requests().is_empty()).collect();
        assert_eq!(served.len(), 1, "all requests go to the peer that was asked first");
        let mut expected = vec!["prepare".to_string(), "size".to_string()];
        expected.extend(cpp_slices.iter().map(|(o, s)| format!("{o}+{s}")));
        assert_eq!(served[0].service.test_pss_requests(), expected);
        assert_eq!(
            cpp_queries[..2],
            ["adnl/dc44a7f3".to_string(), "rldp/00c1a022".to_string()],
            "the reference prepares over ADNL and asks for the size over RLDP"
        );
    })
    .catch_unwind()
    .await;
    finish(nodes, outcome).await;
}

/// A part over the real overlay: the reference asks a part's size over ADNL,
/// without a prepare query, then asks for its slices.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wire_persistent_state_part() {
    let (cpp_ok, _, cpp_queries) = cpp_download("part_3mib");
    assert!(cpp_ok);
    assert_eq!(cpp_queries[0], "adnl/00c1a022");
    assert!(cpp_queries[1..].iter().all(|q| q == "rldp/94271ee8"));
    let shard = ShardIdent::masterchain();
    let chain = cpp_chain("small", 1, -1, &[(3, 5)]);
    let block = chain[1].0.clone();
    let size = 100;
    let a = wire_node("wire_pss_part_a", 4635, &shard, Arc::new(MemoryBlocks::new(chain.clone())))
        .await;
    let engine = Arc::new(MemoryBlocks::new(chain));
    engine.serve_state(&block, state_bytes(size), "");
    let b = wire_node("wire_pss_part_b", 4636, &shard, engine).await;
    connect(&a, &b);
    let nodes = vec![a, b];
    let outcome = std::panic::AssertUnwindSafe(async {
        let nodes = &nodes;
        let id = PersistentStatePartId::Part(block.clone(), 0x4000_0000_0000_0000);
        let mut dest = std::io::Cursor::new(Vec::new());
        crate::full_node::state_helper::download_pss_part(
            &id,
            &block,
            &mut dest,
            &nodes[0].full,
            Some(1),
            &|| Ok(()),
        )
        .await
        .unwrap();
        assert_eq!(dest.into_inner(), state_bytes(size));
        assert_eq!(
            nodes[1].service.test_pss_requests(),
            vec!["size".to_string(), format!("0+{size}")]
        );
    })
    .catch_unwind()
    .await;
    finish(nodes, outcome).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wire_persistent_state_not_found() {
    assert!(cpp_value(CPP_DST, "whole_notfound").starts_with("error 651"));
    assert!(cpp_value(CPP_DST, "part_notfound").starts_with("error 651"));
    let shard = ShardIdent::masterchain();
    let chain = cpp_chain("small", 1, -1, &[(3, 5)]);
    let block = chain[1].0.clone();
    let a =
        wire_node("wire_pss_nf_a", 4632, &shard, Arc::new(MemoryBlocks::new(chain.clone()))).await;
    let b = wire_node("wire_pss_nf_b", 4633, &shard, Arc::new(MemoryBlocks::new(chain))).await;
    connect(&a, &b);
    let nodes = vec![a, b];
    let outcome = std::panic::AssertUnwindSafe(async {
        let nodes = &nodes;
        for id in [
            PersistentStatePartId::WholeState(block.clone()),
            PersistentStatePartId::Part(block.clone(), 0x4000_0000_0000_0000),
        ] {
            let found = nodes[0].full.check_persistent_state(&id, &block).await.unwrap();
            assert!(found.is_none(), "{id}: not found is not ready, not an error");
        }
    })
    .catch_unwind()
    .await;
    finish(nodes, outcome).await;
}

#[test]
fn advertised_state_sizes_are_validated() {
    use crate::network::full_node_overlay_client::checked_state_size;
    // The reference requester refuses a zero size after a prepared state.
    assert!(cpp_value(CPP_DST, "whole_zero").starts_with("error"));
    assert!(checked_state_size(0).is_err());
    assert!(checked_state_size(-1).is_err());
    assert_eq!(checked_state_size(5).unwrap(), 5);
}
