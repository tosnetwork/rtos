// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{
    common::{Answer, TimedAnswer},
    node::AdnlNodeConfig,
    QuicRateLimitConfig,
};
use rtos_api::{
    ton::{
        rpc::ton_node::DownloadBlock,
        ton_node::{data::Data, Data as DataBoxed},
    },
    WireProfile,
};
use std::{
    net::{SocketAddr, UdpSocket},
    sync::Mutex,
};
use tokio_util::sync::CancellationToken;

struct Observed {
    overlay: Arc<OverlayNode>,
    rejected: tokio::sync::mpsc::UnboundedSender<()>,
}
#[async_trait::async_trait]
impl Subscriber for Observed {
    async fn try_consume_raw_query(
        &self,
        bytes: &[u8],
        peers: &AdnlPeers,
    ) -> Result<Option<QueryAnswer>> {
        let result = self.overlay.try_consume_raw_query(bytes, peers).await;
        if result.is_err() {
            self.rejected.send(()).unwrap();
        }
        result
    }
    async fn try_consume_query_bundle(
        &self,
        objects: Vec<TLObject>,
        peers: &AdnlPeers,
    ) -> Result<QueryResult> {
        self.overlay.try_consume_query_bundle(objects, peers).await
    }
}
struct DownloadConsumer(Mutex<Vec<u32>>);
#[async_trait::async_trait]
impl Subscriber for DownloadConsumer {
    async fn try_consume_query(&self, object: TLObject, _: &AdnlPeers) -> Result<QueryResult> {
        let query = object.downcast::<DownloadBlock>().map_err(|_| error!("download expected"))?;
        assert_eq!(query.block.root_hash, UInt256::from([21; 32]));
        self.0.lock().unwrap().push(query.block.seq_no);
        let answer = Answer::Object(
            Data { data: query.block.seq_no.to_le_bytes().to_vec() }
                .into_boxed()
                .into_tl_object()
                .into(),
        );
        if query.block.seq_no % 2 == 0 {
            return Ok(QueryResult::Consumed(QueryAnswer::Ready(Some(answer))));
        }
        Ok(QueryResult::Consumed(QueryAnswer::Pending(tokio::spawn(async move {
            tokio::task::yield_now().await;
            Ok(TimedAnswer {
                answer: Some(answer),
                #[cfg(feature = "telemetry")]
                actual_start_at: None,
            })
        }))))
    }
}
struct Endpoint {
    adnl: Arc<AdnlNode>,
    overlay: Arc<OverlayNode>,
    quic: Arc<QuicNode>,
    key: Arc<dyn KeyOption>,
    udp: SocketAddr,
    quic_addr: SocketAddr,
    token: CancellationToken,
    rejected: tokio::sync::mpsc::UnboundedReceiver<()>,
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        self.token.cancel();
    }
}
fn free_address() -> SocketAddr {
    UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}
async fn endpoint(seed: u8, profile: WireProfile) -> Endpoint {
    let udp = free_address();
    let quic_addr = free_address();
    let (_, config) =
        AdnlNodeConfig::from_ip_address_and_private_keys(&udp.to_string(), vec![([seed; 32], 0)])
            .unwrap();
    let key = config.key_by_tag(0).unwrap().clone();
    let adnl = AdnlNode::with_config(
        config,
        #[cfg(feature = "dump")]
        None,
    )
    .await
    .unwrap();
    let overlay =
        OverlayNode::with_params_and_profile(adnl.clone(), &[31; 32], 0, profile).unwrap();
    let token = CancellationToken::new();
    let (tx, rejected) = tokio::sync::mpsc::unbounded_channel();
    let observed = Arc::new(Observed { overlay: overlay.clone(), rejected: tx });
    let quic = QuicNode::new(
        vec![observed.clone()],
        token.clone(),
        tokio::runtime::Handle::current(),
        Some(QuicRateLimitConfig::disabled()),
    );
    quic.add_key(&[seed; 32], key.id(), quic_addr).unwrap();
    overlay.set_quic(quic.clone()).unwrap();
    let rldp = RldpNode::with_params(adnl.clone(), vec![observed.clone()], None).unwrap();
    overlay.set_rldp(rldp.clone()).unwrap();
    adnl.start_over_udp(vec![rldp, observed]).await.unwrap();
    Endpoint { adnl, overlay, quic, key, udp, quic_addr, token, rejected }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn target_namespace_real_adnl_quic_rldp_ready_pending_and_rejections() {
    for profile in [WireProfile::Legacy, WireProfile::T0] {
        let a = endpoint(111, profile).await;
        let mut b = endpoint(112, profile).await;
        let id = OverlayShortId::from_data([113; 32]);
        for (local, remote) in [(&a, &b), (&b, &a)] {
            local.quic.add_peer_key(remote.key.id().clone(), remote.quic_addr).unwrap();
            let udp = IpAddress::from_versioned_string(&remote.udp.to_string(), None).unwrap();
            let quic =
                IpAddress::from_versioned_string(&remote.quic_addr.to_string(), None).unwrap();
            local.adnl.add_peer(local.key.id(), &udp, Some(&quic), &remote.key).unwrap();
            local
                .overlay
                .add_private_overlay(
                    OverlayParams::with_id_only(&id),
                    &local.key,
                    &[remote.key.id().clone()],
                    true,
                    None,
                )
                .unwrap();
        }
        let consumer = Arc::new(DownloadConsumer(Mutex::new(Vec::new())));
        b.overlay.add_consumer(&id, consumer.clone()).unwrap();
        let block = rtos_block::BlockIdExt::with_params(
            rtos_block::ShardIdent::masterchain(),
            17,
            UInt256::from([21; 32]),
            UInt256::from([22; 32]),
        );
        for seqno in [17, 18] {
            for transport in 0..4 {
                let mut block = block.clone();
                block.seq_no = seqno + transport * 2;
                let expected = block.seq_no.to_le_bytes().to_vec();
                let request: TaggedTlObject = DownloadBlock { block }.into_tl_object().into();
                let result = tokio::time::timeout(Duration::from_secs(20), async {
                    match transport {
                        0 => a
                            .overlay
                            .query(b.key.id(), &request, &id, Some(3000))
                            .await?
                            .ok_or_else(|| error!("ADNL answer missing")),
                        1 => a
                            .overlay
                            .query_via_quic(b.key.id(), &request, &id, Some(3000))
                            .await?
                            .ok_or_else(|| error!("QUIC answer missing")),
                        _ => {
                            let mut wire = a.overlay.get_query_prefix(&id)?;
                            profile.serialize_append(&mut wire, &request.object)?;
                            let (raw, _) = a
                                .overlay
                                .query_via_rldp(
                                    b.key.id(),
                                    &TaggedByteSlice {
                                        object: &wire,
                                        #[cfg(feature = "telemetry")]
                                        tag: 0,
                                    },
                                    &id,
                                    Some(1 << 20),
                                    transport == 3,
                                    None,
                                )
                                .await?;
                            profile.deserialize(&raw.ok_or_else(|| error!("RLDP answer missing"))?)
                        }
                    }
                })
                .await
                .expect("bounded actual transport query")
                .unwrap();
                assert_eq!(result.downcast::<DataBoxed>().unwrap().data(), &expected);
            }
        }
        // ADNL backup retries may deliver a request more than once.
        for seqno in 17..25 {
            assert!(consumer.0.lock().unwrap().contains(&seqno));
        }
        if profile == WireProfile::T0 {
            let peers = AdnlPeers::with_keys(a.key.id().clone(), b.key.id().clone());
            let mut invalid_block = block;
            invalid_block.seq_no = 99;
            let request = DownloadBlock { block: invalid_block }.into_tl_object();
            for malformed in 0..3 {
                let overlay_id =
                    if malformed == 2 { OverlayShortId::from_data([114; 32]) } else { id.clone() };
                let mut wire =
                    serialize_boxed(&OverlayQuery { overlay: UInt256::from(*overlay_id.data()) })
                        .unwrap();
                (if malformed == 0 { WireProfile::Legacy } else { profile })
                    .serialize_append(&mut wire, &request)
                    .unwrap();
                if malformed == 1 {
                    wire.push(7);
                }
                // Observe a real dispatcher rejection, not absence after a sleep.
                let (reply, rejected) = tokio::join!(
                    a.quic.query(wire, Some(&a.adnl), &peers, Some(500)),
                    tokio::time::timeout(Duration::from_secs(5), b.rejected.recv()),
                );
                assert!(reply.is_err() || reply.unwrap().is_none());
                assert_eq!(rejected.unwrap(), Some(()));
                assert!(!consumer.0.lock().unwrap().contains(&99));
            }
        }
        a.token.cancel();
        b.token.cancel();
        a.adnl.stop().await;
        b.adnl.stop().await;
    }
}
