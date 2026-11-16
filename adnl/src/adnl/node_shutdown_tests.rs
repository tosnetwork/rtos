// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::common::{QueryAnswer, TimedAnswer};
use rtos_api::AnyBoxedSerialize;
use std::{
    net::{TcpListener, TcpStream, UdpSocket},
    sync::atomic::AtomicBool,
};
use tokio::sync::{oneshot, Notify};

struct TestNode(Arc<AdnlNode>);
impl std::ops::Deref for TestNode {
    type Target = Arc<AdnlNode>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Drop for TestNode {
    fn drop(&mut self) {
        self.0.tasks.close();
    }
}

async fn node(seed: u8) -> (TestNode, u16) {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    let port = socket.local_addr().unwrap().port();
    let node = node_on_port(seed, port).await;
    // Keep the reservation through asynchronous node construction.
    drop(socket);
    (node, port)
}

async fn node_on_port(seed: u8, port: u16) -> TestNode {
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
    TestNode(node)
}

fn reserve_tcp_udp() -> std::io::Result<(UdpSocket, TcpListener, u16)> {
    for _ in 0..64 {
        let udp = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        let port = udp.local_addr()?.port();
        match TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)) {
            Ok(tcp) => return Ok((udp, tcp, port)),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(std::io::ErrorKind::AddrInUse, "no shared TCP/UDP test port"))
}

async fn started_tcp_node(seed: u8) -> Result<(TestNode, u16)> {
    started_tcp_node_with(seed, |_, _, _, tcp| {
        drop(tcp);
        Ok(())
    })
    .await
}

async fn started_tcp_node_with(
    seed: u8,
    mut before_start: impl FnMut(usize, &TestNode, u16, TcpListener) -> Result<()>,
) -> Result<(TestNode, u16)> {
    for attempt in 0..8 {
        let (udp, tcp, port) = reserve_tcp_udp()?;
        let node = node_on_port(seed, port).await;
        // Production startup binds its own sockets. Minimize this handoff gap
        // and retry only a real bind collision after fully draining its owner.
        drop(udp);
        // Transfer the reservation to the hook: failure injection must not
        // drop and rebind it, which races with unrelated port users.
        let started = match before_start(attempt, &node, port, tcp) {
            Ok(()) => node.start_over_udp_tcp(Vec::new()).await,
            Err(error) => Err(error),
        };
        match started {
            Ok(()) => return Ok((node, port)),
            Err(error) => {
                let retry = error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::AddrInUse);
                bounded(node.stop_checked()).await.map_err(|cleanup| {
                    error!("TCP fixture startup failed: {error:#}; cleanup failed: {cleanup:#}")
                })?;
                drop(node);
                if !retry || attempt == 7 {
                    return Err(error);
                }
            }
        }
    }
    unreachable!("last failed startup returns its error")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adnl_tcp_fixture_retries_real_bind_collision_after_owner_release() {
    let mut held_tcp = None;
    let mut first_port = 0;
    let mut first_owner = None;
    let mut attempts = 0;
    let (node, port) = started_tcp_node_with(60, |attempt, node, port, tcp| {
        attempts += 1;
        if attempt == 0 {
            first_port = port;
            first_owner = Some(Arc::downgrade(&node.0));
            assert_eq!(tcp.local_addr()?.port(), port);
            assert_eq!(
                TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).unwrap_err().kind(),
                std::io::ErrorKind::AddrInUse,
                "the reserved socket must still exclude another TCP bind"
            );
            held_tcp = Some(tcp);
        } else {
            assert!(
                first_owner.as_ref().unwrap().upgrade().is_none(),
                "failed node must be released before another startup"
            );
            udp_bind_checked(Ipv4Addr::UNSPECIFIED, first_port, "tcp-failed-owner-released");
        }
        Ok(())
    })
    .await
    .unwrap();
    assert!((2..=8).contains(&attempts), "one forced conflict plus bounded real conflicts");
    assert_ne!(port, first_port);
    assert!(held_tcp.is_some());
    bounded(node.stop_checked()).await.unwrap();
    udp_released(port);
    tcp_released(port);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adnl_tcp_fixture_does_not_retry_non_bind_startup_failure() {
    for close_owner in [true, false] {
        let mut attempts = 0;
        let mut owner = None;
        let result = started_tcp_node_with(61, |_, node, _, tcp| {
            drop(tcp);
            attempts += 1;
            owner = Some(Arc::downgrade(&node.0));
            if close_owner {
                node.tasks.close();
                Ok(())
            } else {
                Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into())
            }
        })
        .await;
        let error = match result {
            Ok(_) => panic!("non-bind failure must refuse startup"),
            Err(error) => error,
        };
        if close_owner {
            assert!(error.to_string().contains("ADNL task admission closed"), "{error:#}");
        } else {
            assert_eq!(
                error.downcast_ref::<std::io::Error>().unwrap().kind(),
                std::io::ErrorKind::PermissionDenied
            );
        }
        assert_eq!(attempts, 1, "non-bind errors must not be retried");
        assert!(owner.unwrap().upgrade().is_none());
    }
}

async fn bounded<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("shutdown did not reach actual terminal state")
}
fn udp_port_diagnostic(port: u16, stage: &str) {
    eprintln!(
        "UDP_PORT_FAILURE stage={stage} port={port} thread={:?}",
        std::thread::current().name()
    );
    #[cfg(target_os = "linux")]
    for table_path in ["/proc/net/udp", "/proc/net/udp6"] {
        let Ok(table) = std::fs::read_to_string(table_path) else {
            eprintln!("UDP_PORT_TABLE_UNAVAILABLE path={table_path}");
            continue;
        };
        let suffix = format!(":{port:04X}");
        for row in table
            .lines()
            .skip(1)
            .filter(|row| row.split_whitespace().nth(1).is_some_and(|addr| addr.ends_with(&suffix)))
        {
            eprintln!("UDP_PORT_ROW stage={stage} port={port} table={table_path} row={row}");
            if let Some(inode) = row.split_whitespace().nth(9) {
                let target = format!("socket:[{inode}]");
                if let Ok(fds) = std::fs::read_dir("/proc/self/fd") {
                    for fd in fds.flatten() {
                        if std::fs::read_link(fd.path())
                            .is_ok_and(|link| link.to_string_lossy() == target)
                        {
                            eprintln!(
                                "UDP_PORT_SELF_FD stage={stage} port={port} fd={} inode={inode}",
                                fd.file_name().to_string_lossy()
                            );
                        }
                    }
                }
            }
        }
    }
}

fn udp_bind_checked(address: Ipv4Addr, port: u16, stage: &str) -> UdpSocket {
    UdpSocket::bind((address, port)).unwrap_or_else(|error| {
        udp_port_diagnostic(port, stage);
        panic!("UDP bind failed: stage={stage} address={address} port={port} error={error}")
    })
}

fn udp_released(port: u16) {
    udp_bind_checked(Ipv4Addr::LOCALHOST, port, "post-stop");
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
    node.start_over_udp(Vec::new()).await.unwrap_or_else(|error| {
        udp_port_diagnostic(port, "startup");
        panic!("UDP startup failed: port={port} error={error:#}");
    });
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
    node.start_over_udp(vec![poll.clone()]).await.unwrap_or_else(|error| {
        udp_port_diagnostic(port, "startup");
        panic!("UDP startup failed: port={port} error={error:#}");
    });
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
    let (node, port) = started_tcp_node(45).await.unwrap();
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
    let mut previous_owner: Option<std::sync::Weak<AdnlNode>> = None;
    for attempt in 0..8 {
        if let Some(previous) = &previous_owner {
            assert!(previous.upgrade().is_none(), "failed startup owner must be released");
        }
        let (udp, tcp, port) = reserve_tcp_udp().unwrap();
        let node = node_on_port(49, port).await;
        // The first attempt intentionally cannot reach the injection. It must
        // be classified as a bind collision, not as successful partial cleanup.
        let held_tcp = if attempt == 0 {
            Some(tcp)
        } else {
            drop(tcp);
            None
        };
        drop(udp);
        let registered = AtomicBool::new(false);
        let result = node
            .start(
                |node| {
                    let _resources = udp_tcp_sender_receiver(node)?;
                    registered.store(true, Ordering::Release);
                    fail!("injected failure after TCP listener registration")
                },
                Vec::new(),
            )
            .await;
        bounded(node.stop_checked()).await.unwrap();
        let error = result.expect_err("injected startup must fail");
        let bind_collision = error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::AddrInUse);
        if attempt == 0 {
            assert!(bind_collision, "reserved TCP port must refuse startup: {error:#}");
            assert!(!registered.load(Ordering::Acquire));
        }
        if bind_collision {
            assert!(!registered.load(Ordering::Acquire));
            previous_owner = Some(Arc::downgrade(&node.0));
            drop(node);
            drop(held_tcp);
            continue;
        }
        assert!(registered.load(Ordering::Acquire), "failed before TCP registration: {error:#}");
        assert_eq!(error.to_string(), "injected failure after TCP listener registration");
        udp_released(port);
        tcp_released(port);
        let weak = Arc::downgrade(&node);
        drop(node);
        assert!(weak.upgrade().is_none());
        return;
    }
    panic!("TCP registration injection was never reached within eight attempts");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adnl_owned_normal_tcp_query_then_transport_owner_release() {
    let (server, server_port) = started_tcp_node(50).await.unwrap();
    let (client, client_port) = started_tcp_node(51).await.unwrap();
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

#[tokio::test]
async fn adnl_owned_pipeline_stop_between_reservation_and_admission() {
    let (node, _) = node(52).await;
    let pipeline = Arc::new(RecvPipeline::with_params(node.clone(), Arc::new(Vec::new())));
    let reservation = pipeline.reserve_worker().unwrap();
    assert_eq!(pipeline.workers.load(Ordering::Acquire), 1);
    // This is the exact production split between the successful workers CAS
    // and owner admission, ordered explicitly rather than by scheduling delays.
    node.tasks.close();
    pipeline.spawn_reserved(reservation);
    assert_eq!(pipeline.workers.load(Ordering::Acquire), 0);
    assert_eq!(pipeline.proc_normal_packets.load(Ordering::Acquire), 0);
    assert_eq!(pipeline.proc_urgent_packets.load(Ordering::Acquire), 0);
    bounded(node.stop_checked()).await.unwrap();
}

struct PanicCustom;
#[async_trait::async_trait]
impl Subscriber for PanicCustom {
    async fn try_consume_custom(&self, _: &[u8], _: &AdnlPeers) -> Result<bool> {
        panic!("injected panic inside receive pipeline processing");
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adnl_owned_pipeline_panic_returns_worker_and_processing_counts() {
    let (server, port) = node(53).await;
    let (client, _) = node(54).await;
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
    socket.set_nonblocking(true).unwrap();
    let socket = tokio::net::UdpSocket::from_std(socket).unwrap();
    let pipeline =
        Arc::new(RecvPipeline::with_params(server.clone(), Arc::new(vec![Arc::new(PanicCustom)])));
    client.start_over_udp(Vec::new()).await.unwrap();
    let local = client.key_by_tag(0).unwrap();
    let remote = server.key_by_tag(0).unwrap();
    client.add_peer(local.id(), server.ip_address_adnl(), None, &remote).unwrap();
    let peers = AdnlPeers::with_keys(local.id().clone(), remote.id().clone());
    client
        .send_custom(
            &TaggedByteSlice {
                object: b"panic in subscriber",
                #[cfg(feature = "telemetry")]
                tag: 0,
            },
            &peers,
        )
        .await
        .unwrap();
    bounded(async {
        let mut bytes = [0; 1500];
        loop {
            tokio::select! {
                _ = server.tasks.cancelled() => break,
                packet = socket.recv(&mut bytes) => { pipeline.put(bytes[..packet.unwrap()].to_vec()); }
            }
        }
    }).await;
    let server_result = bounded(server.stop_checked()).await;
    bounded(client.stop_checked()).await.unwrap();
    assert!(server_result.unwrap_err().to_string().contains("receive pipeline"));
    assert_eq!(pipeline.workers.load(Ordering::Acquire), 0);
    assert_eq!(pipeline.proc_normal_packets.load(Ordering::Acquire), 0);
    assert_eq!(pipeline.proc_urgent_packets.load(Ordering::Acquire), 0);
    bounded(client.stop_checked()).await.unwrap();
}
