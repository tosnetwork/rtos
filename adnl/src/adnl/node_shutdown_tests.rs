// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::common::{QueryAnswer, TimedAnswer};
use rtos_api::AnyBoxedSerialize;
use std::{
    net::{TcpStream, UdpSocket},
    sync::atomic::AtomicBool,
};
use tokio::sync::{oneshot, Notify};

async fn node(seed: u8) -> (Arc<AdnlNode>, u16) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    let (_, config) = AdnlNodeConfig::from_ip_address_and_private_keys(
        &format!("127.0.0.1:{port}"),
        vec![([seed; 32], 0)],
    )
    .unwrap();
    let node = AdnlNode::with_config(
        config,
        #[cfg(feature = "dump")]
        None,
    )
    .await
    .unwrap();
    (node, port)
}
async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("shutdown did not reach actual terminal state")
}
fn udp_released(port: u16) {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).expect("UDP socket still owned");
}

fn tcp_released(port: u16) {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    socket.set_reuse_address(true).unwrap();
    socket
        .bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port).into())
        .expect("TCP listener still owned");
    socket.listen(1).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adnl_owned_udp_stop_releases_socket_and_node() {
    let (node, port) = node(41).await;
    node.start_over_udp(Vec::new()).await.unwrap();
    assert!(UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_err());
    let weak = Arc::downgrade(&node);
    bounded(node.stop_checked()).await.unwrap();
    udp_released(port);
    bounded(node.stop_checked()).await.unwrap();
    assert!(node.start_over_udp(Vec::new()).await.is_err());
    drop(node);
    assert!(weak.upgrade().is_none());
}

struct HeldPoll {
    entered: Notify,
    release: Notify,
    finished: AtomicBool,
}
#[async_trait::async_trait]
impl Subscriber for HeldPoll {
    async fn poll(&self, _: &Arc<Instant>) {
        self.entered.notify_one();
        self.release.notified().await;
        self.finished.store(true, Ordering::Release);
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adnl_owned_udp_stop_waiter_cancel_and_concurrent_drain() {
    let (node, port) = node(42).await;
    let poll = Arc::new(HeldPoll {
        entered: Notify::new(),
        release: Notify::new(),
        finished: AtomicBool::new(false),
    });
    node.start_over_udp(vec![poll.clone()]).await.unwrap();
    bounded(poll.entered.notified()).await;
    let mut first = Box::pin(node.stop_checked());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut first).await.is_err(),
        "stop returned before subscriber completion"
    );
    drop(first);
    assert!(!poll.finished.load(Ordering::Acquire));
    let one = {
        let node = node.clone();
        tokio::spawn(async move { node.stop_checked().await })
    };
    let two = {
        let node = node.clone();
        tokio::spawn(async move { node.stop_checked().await })
    };
    assert!(!one.is_finished() && !two.is_finished());
    poll.release.notify_one();
    bounded(one).await.unwrap().unwrap();
    bounded(two).await.unwrap().unwrap();
    assert!(poll.finished.load(Ordering::Acquire));
    udp_released(port);
    let weak = Arc::downgrade(&node);
    drop(node);
    assert!(weak.upgrade().is_none());
}

struct PanicPoll {
    release: Notify,
}
#[async_trait::async_trait]
impl Subscriber for PanicPoll {
    async fn poll(&self, _: &Arc<Instant>) {
        self.release.notified().await;
        panic!("injected ADNL subscriber panic");
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adnl_owned_async_panic_closes_transport_and_is_sticky() {
    let (node, port) = node(43).await;
    let poll = Arc::new(PanicPoll { release: Notify::new() });
    node.start_over_udp(vec![poll.clone()]).await.unwrap();
    poll.release.notify_one();
    bounded(node.tasks.cancelled()).await;
    let error = bounded(node.stop_checked()).await.unwrap_err().to_string();
    assert!(error.contains("subscriber poll"));
    assert_eq!(node.stop_checked().await.unwrap_err().to_string(), error);
    udp_released(port);
    let weak = Arc::downgrade(&node);
    drop(node);
    assert!(weak.upgrade().is_none());
}

struct PanicReceiver {
    _receiver: Box<dyn AdnlReceiver>,
}
impl AdnlReceiver for PanicReceiver {
    fn recv(&mut self) -> Result<Option<&[u8]>> {
        panic!("injected actual receiver thread panic");
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adnl_owned_receiver_thread_panic_is_joined() {
    let (node, port) = node(44).await;
    let started = node
        .start(
            |node| {
                let (sender, receiver) = udp_sender_receiver(node)?;
                Ok((sender, Box::new(PanicReceiver { _receiver: receiver })))
            },
            Vec::new(),
        )
        .await;
    // Failure can close admission before sender startup; either startup outcome
    // still owns and joins every thread already created.
    let _ = started;
    bounded(node.tasks.cancelled()).await;
    assert!(bounded(node.stop_checked()).await.unwrap_err().to_string().contains("ADNL receiver"));
    udp_released(port);
    let weak = Arc::downgrade(&node);
    drop(node);
    assert!(weak.upgrade().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adnl_owned_tcp_accept_and_udp_are_joined() {
    let (node, port) = node(45).await;
    node.start_over_udp_tcp(Vec::new()).await.unwrap();
    let peer = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    bounded(node.stop_checked()).await.unwrap();
    drop(peer);
    udp_released(port);
    tcp_released(port);
    let weak = Arc::downgrade(&node);
    drop(node);
    assert!(weak.upgrade().is_none());
}

struct PendingSubscriber {
    claimed: AtomicBool,
    entered: Notify,
    return_pending: Notify,
    pending_started: Arc<Notify>,
    release: Arc<Notify>,
    done: Arc<AtomicBool>,
}
#[async_trait::async_trait]
impl Subscriber for PendingSubscriber {
    async fn try_consume_raw_query(&self, _: &[u8], _: &AdnlPeers) -> Result<Option<QueryAnswer>> {
        if self.claimed.swap(true, Ordering::AcqRel) {
            return Ok(Some(QueryAnswer::Ready(None)));
        }
        self.entered.notify_one();
        self.return_pending.notified().await;
        let release = self.release.clone();
        let done = self.done.clone();
        let entered = self.pending_started.clone();
        Ok(Some(QueryAnswer::Pending(tokio::spawn(async move {
            entered.notify_one();
            release.notified().await;
            done.store(true, Ordering::Release);
            Ok(TimedAnswer {
                answer: None,
                #[cfg(feature = "telemetry")]
                actual_start_at: None,
            })
        }))))
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adnl_owned_real_udp_pending_child_after_close_drains() {
    let (server, port) = node(46).await;
    let (client, _) = node(47).await;
    let pending = Arc::new(PendingSubscriber {
        claimed: AtomicBool::new(false),
        entered: Notify::new(),
        return_pending: Notify::new(),
        pending_started: Arc::new(Notify::new()),
        release: Arc::new(Notify::new()),
        done: Arc::new(AtomicBool::new(false)),
    });
    server.start_over_udp(vec![pending.clone()]).await.unwrap();
    client.start_over_udp(Vec::new()).await.unwrap();
    let local = client.key_by_tag(0).unwrap();
    let remote = server.key_by_tag(0).unwrap();
    client.add_peer(local.id(), server.ip_address_adnl(), None, &remote).unwrap();
    let query = {
        let client = client.clone();
        let peers = AdnlPeers::with_keys(local.id().clone(), remote.id().clone());
        tokio::spawn(async move {
            let query = TaggedTlObject {
                object: rtos_api::ton::rpc::adnl::Ping { value: 9 }.into_tl_object(),
                #[cfg(feature = "telemetry")]
                tag: 0,
            };
            client.query(&query, &peers, Some(500)).await
        })
    };
    bounded(pending.entered.notified()).await;
    let mut stopping = Box::pin(server.stop_checked());
    assert!(tokio::time::timeout(Duration::from_millis(20), &mut stopping).await.is_err());
    pending.return_pending.notify_one();
    bounded(pending.pending_started.notified()).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut stopping).await.is_err(),
        "accepted pending answer detached"
    );
    drop(stopping);
    pending.release.notify_one();
    bounded(server.stop_checked()).await.unwrap();
    assert!(pending.done.load(Ordering::Acquire));
    bounded(client.stop_checked()).await.unwrap();
    let _ = bounded(query).await.unwrap();
    udp_released(port);
    let weak = Arc::downgrade(&server);
    drop(server);
    assert!(weak.upgrade().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adnl_owned_thread_join_survives_all_waiters_cancelled() {
    let owner = AdnlTasks::new();
    let (release, hold) = std::sync::mpsc::channel();
    let (entered, ready) = oneshot::channel();
    let cleaned = Arc::new(AtomicBool::new(false));
    let cleaned_local = cleaned.clone();
    owner.on_stopped(move || {
        cleaned_local.store(true, Ordering::Release);
    });
    owner
        .thread("held native thread".into(), move || {
            entered.send(()).unwrap();
            hold.recv().unwrap();
        })
        .unwrap();
    bounded(ready).await.unwrap();
    let mut stopping = Box::pin(owner.wait());
    assert!(tokio::time::timeout(Duration::from_millis(20), &mut stopping).await.is_err());
    drop(stopping);
    assert!(owner.enter().is_err());
    assert!(!cleaned.load(Ordering::Acquire));
    release.send(()).unwrap();
    bounded(async {
        while !cleaned.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await;
    bounded(owner.wait()).await.unwrap();
    assert!(cleaned.load(Ordering::Acquire));
    let weak = Arc::downgrade(&owner);
    drop(owner);
    // Finalizer's own Arc can live until it returns from notifying completion.
    bounded(async {
        while weak.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await;
}

struct PanicSender {
    _sender: Box<dyn AdnlSender>,
}
impl AdnlSender for PanicSender {
    fn send_fast(&self, _: &[u8], _: socket2::SockAddr) -> Result<usize> {
        panic!("injected actual sender thread panic");
    }
    fn send_safe(
        &self,
        _: Vec<u8>,
        _: socket2::SockAddr,
        _: &Arc<AdnlNode>,
    ) -> Result<Option<usize>> {
        panic!("injected sender");
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adnl_owned_sender_panic_wakes_blocking_udp_receiver() {
    let (node, port) = node(48).await;
    node.start(
        |node| {
            let (sender, receiver) = udp_sender_receiver(node)?;
            Ok((Box::new(PanicSender { _sender: sender }), receiver))
        },
        Vec::new(),
    )
    .await
    .unwrap();
    node.send_pipeline.put_normal(SendJob::Data(SendData {
        destination: 0x7F0000010000 | u64::from(port),
        data: vec![1],
        method: AdnlSendMethodDetailed::FastNormal,
    }));
    bounded(node.tasks.cancelled()).await;
    assert!(bounded(node.stop_checked()).await.unwrap_err().to_string().contains("ADNL sender"));
    udp_released(port);
    let weak = Arc::downgrade(&node);
    drop(node);
    assert!(weak.upgrade().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adnl_owned_partial_transport_startup_closes_registered_threads() {
    let (node, port) = node(49).await;
    let result = node
        .start(
            |node| {
                let _resources = udp_tcp_sender_receiver(node)?;
                fail!("injected failure after TCP listener registration")
            },
            Vec::new(),
        )
        .await;
    assert!(result.is_err());
    bounded(node.stop_checked()).await.unwrap();
    udp_released(port);
    tcp_released(port);
    let weak = Arc::downgrade(&node);
    drop(node);
    assert!(weak.upgrade().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adnl_owned_normal_tcp_query_then_transport_owner_release() {
    let (server, server_port) = node(50).await;
    let (client, client_port) = node(51).await;
    server.start_over_udp_tcp(Vec::new()).await.unwrap();
    client.start_over_udp_tcp(Vec::new()).await.unwrap();
    let local = client.key_by_tag(0).unwrap();
    let remote = server.key_by_tag(0).unwrap();
    client.add_peer(local.id(), server.ip_address_adnl(), None, &remote).unwrap();
    let peers = AdnlPeers::with_keys(local.id().clone(), remote.id().clone());
    let query = TaggedTlObject {
        object: rtos_api::ton::rpc::adnl::Ping { value: 123 }.into_tl_object(),
        #[cfg(feature = "telemetry")]
        tag: 0,
    };
    let response =
        bounded(client.query_get_status(&query, &peers, Some(2000), AdnlSendMethod::Safe))
            .await
            .unwrap();
    let pong = response
        .reply
        .expect("TCP query returned no answer")
        .downcast::<rtos_api::ton::adnl::Pong>()
        .unwrap();
    assert_eq!(pong.value(), &123);
    bounded(client.stop_checked()).await.unwrap();
    bounded(server.stop_checked()).await.unwrap();
    udp_released(client_port);
    udp_released(server_port);
    tcp_released(client_port);
    tcp_released(server_port);
    let client_owner = Arc::downgrade(&client.tasks);
    let server_owner = Arc::downgrade(&server.tasks);
    let client_weak = Arc::downgrade(&client);
    let server_weak = Arc::downgrade(&server);
    drop(client);
    drop(server);
    assert!(client_weak.upgrade().is_none() && server_weak.upgrade().is_none());
    bounded(async {
        while client_owner.upgrade().is_some() || server_owner.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await;
}
