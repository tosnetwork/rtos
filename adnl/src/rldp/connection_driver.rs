// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Owned asynchronous driver for the native-compatible Connection state machine.
//! Production RldpNode routing is wired separately; this owns the execution boundary.
use super::{
    owned_send::{fec_limited, SendCancelled, SendControl},
    rldp2::{
        budget::PeerId,
        connection::{Connection, Events, TransferId},
    },
};
use crate::adnl::tasks::AdnlTasks;
use rtos_block::{error, Result};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

pub(super) enum Command {
    Receive(Vec<u8>),
    Packet { data: Vec<u8>, mtu: u64 },
    Send { id: TransferId, data: Vec<u8>, deadline: Option<Instant>, answer: bool },
    ReceiveLimit { id: TransferId, deadline: Instant, max_size: u64 },
    Mtu(u64),
    Cancel { send: TransferId, receive: Option<TransferId> },
}
impl Command {
    fn bytes(&self) -> usize {
        match self {
            Self::Receive(data) | Self::Packet { data, .. } | Self::Send { data, .. } => {
                data.capacity()
            }
            _ => 0,
        }
    }
    fn apply(self, connection: &mut Connection) -> Result<bool> {
        // Sample wall time first so conversion cannot shorten an absolute deadline.
        let wall_now = Instant::now();
        let now = connection.now();
        let deadline = |at: Instant| now + at.saturating_duration_since(wall_now).as_secs_f64();
        match self {
            Self::Packet { data, mtu } => {
                connection.set_default_mtu(mtu);
                connection.receive_raw_at(&data, now);
                Ok(true)
            }
            Self::Receive(data) => {
                connection.receive_raw_at(&data, now);
                Ok(true)
            }
            Self::Send { id, data, deadline: at, answer } => {
                if answer && at.is_some_and(|at| at <= Instant::now()) {
                    return Ok(false);
                }
                connection.send_at(id, data, now, at.map(deadline))
            }
            Self::ReceiveLimit { id, deadline: at, max_size } => {
                Ok(connection.set_receive_limits(id, deadline(at), max_size))
            }
            Self::Cancel { send, receive } => {
                connection.cancel_transfer(send, false);
                if let Some(id) = receive {
                    connection.cancel_transfer(id, true);
                }
                Ok(true)
            }
            Self::Mtu(value) => {
                connection.set_default_mtu(value);
                Ok(true)
            }
        }
    }
}
struct Envelope {
    command: Command,
    reply: oneshot::Sender<Result<bool>>,
    _bytes: OwnedSemaphorePermit,
}
pub(super) struct ConnectionDriver {
    commands: mpsc::Sender<Envelope>,
    bytes: Arc<Semaphore>,
    control: Arc<SendControl>,
    drained: CancellationToken,
}
struct Drain(CancellationToken);
impl Drop for Drain {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
impl Drop for ConnectionDriver {
    fn drop(&mut self) {
        self.control.cancel(SendCancelled::PeerEvicted);
    }
}
impl ConnectionDriver {
    // Bounded transport mailbox, independent of Connection's native transfer budgets.
    const QUEUED_BYTES: usize = 16 * 1024 * 1024;
    pub(super) fn start(
        peer: PeerId,
        owner: Arc<AdnlTasks>,
        fec_slots: Arc<Semaphore>,
    ) -> Result<(Self, mpsc::Receiver<Events>)> {
        let token = owner.enter()?;
        let (commands, mut requests) = mpsc::channel::<Envelope>(64);
        let (events, event_rx) = mpsc::channel(1);
        let control = SendControl::new();
        let worker_control = control.clone();
        let drained = CancellationToken::new();
        let drain = Drain(drained.clone());
        let worker_owner = owner.clone();
        owner.spawn_admitted("RLDP2 Connection driver", token, async move {
            let _drain = drain;
            let mut connection = Connection::new(peer);
            let mut wakeup: Option<Instant> = None;
            loop {
                // Due protocol timers take priority over a continuously ready mailbox.
                let request = tokio::select! {
                    biased;
                    _ = worker_control.cancelled() => break,
                    _ = worker_owner.cancelled() => break,
                    _ = async {
                        match wakeup {
                            Some(at) => tokio::time::sleep_until(at.into()).await,
                            None => std::future::pending().await,
                        }
                    } => None,
                    request = requests.recv() => match request { Some(request) => Some(request), None => break },
                };
                let work = fec_limited(
                    connection, worker_control.clone(), worker_owner.clone(), fec_slots.clone(),
                    move |connection| {
                        let reply = request.map(|request| {
                            let result = request.command.apply(connection);
                            (request.reply, result)
                        });
                        Ok((reply, connection.run()?))
                    },
                ).await;
                let (next, (reply, output)) = match work {
                    Ok(value) => value,
                    Err(error) => {
                        if !worker_owner.is_closed() && worker_control.check().is_ok() {
                            worker_owner.failed(format!("RLDP2 Connection driver: {error}"));
                        }
                        break;
                    }
                };
                // A cancellation receipt certifies that the actual blocking work
                // has joined, not just that its closure applied a command.
                if let Some((reply, result)) = reply {
                    let _ = reply.send(result);
                }
                wakeup = output.wakeup.map(|at| {
                    Instant::now() + Duration::from_secs_f64((at - next.now()).max(0.0))
                });
                connection = next;
                if !output.received.is_empty() || !output.parts.is_empty()
                    || !output.packets.is_empty() || !output.sent.is_empty() {
                    tokio::select! {
                        biased;
                        _ = worker_control.cancelled() => break,
                        _ = worker_owner.cancelled() => break,
                        result = events.send(output) => if result.is_err() { break; },
                    }
                }
            }
            requests.close();
            // Dropping queued replies reports closure, and releases their byte leases.
        });
        Ok((
            Self {
                commands,
                bytes: Arc::new(Semaphore::new(Self::QUEUED_BYTES)),
                control,
                drained,
            },
            event_rx,
        ))
    }
    pub(super) async fn submit(&self, command: Command) -> Result<bool> {
        let bytes = command.bytes();
        if bytes > Self::QUEUED_BYTES {
            return Err(error!("RLDP2 command exceeds mailbox byte bound"));
        }
        let permit = tokio::select! {
            biased;
            _ = self.control.cancelled() => return Err(error!("RLDP2 driver closed")),
            permit = self.bytes.clone().acquire_many_owned(bytes as u32) => permit?,
        };
        let (reply, result) = oneshot::channel();
        tokio::select! {
            biased;
            _ = self.control.cancelled() => return Err(error!("RLDP2 driver closed")),
            sent = self.commands.send(Envelope { command, reply, _bytes: permit }) => sent.map_err(|_| error!("RLDP2 driver closed"))?,
        }
        result.await.map_err(|_| error!("RLDP2 driver closed"))?
    }
    #[cfg(test)]
    pub(super) fn test_control(&self) -> Arc<SendControl> {
        self.control.clone()
    }
    pub(super) async fn close(&self) {
        self.control.cancel(SendCancelled::PeerEvicted);
        self.drained.cancelled().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn idle_driver_delivers_receive_deadline_without_more_packets() {
        let owner = AdnlTasks::new();
        let (driver, mut events) =
            ConnectionDriver::start([1; 32], owner.clone(), Arc::new(Semaphore::new(1))).unwrap();
        let id = [2; 32];
        driver
            .submit(Command::ReceiveLimit {
                id,
                deadline: Instant::now() + Duration::from_millis(40),
                max_size: 7680,
            })
            .await
            .unwrap();
        let result =
            tokio::time::timeout(Duration::from_secs(2), events.recv()).await.unwrap().unwrap();
        assert_eq!(result.received.len(), 1);
        assert_eq!(result.received[0].0, id);
        assert!(result.received[0].1.is_err());
        driver.close().await;
        owner.wait().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn driver_close_retains_running_fec_and_its_permit_after_caller_drop() {
        let owner = AdnlTasks::new();
        let slots = Arc::new(Semaphore::new(1));
        let (driver, _events) =
            ConnectionDriver::start([3; 32], owner.clone(), slots.clone()).unwrap();
        let driver = Arc::new(driver);
        let (started, entered) = oneshot::channel();
        let started = Arc::new(std::sync::Mutex::new(Some(started)));
        let (release, blocked) = std::sync::mpsc::channel();
        let blocked = Arc::new(std::sync::Mutex::new(blocked));
        *driver.control.test_after_fec.lock().unwrap() = Some(Arc::new(move || {
            if let Some(started) = started.lock().unwrap().take() {
                let _ = started.send(());
            }
            blocked.lock().unwrap().recv().unwrap();
        }));
        let caller = {
            let driver = driver.clone();
            tokio::spawn(async move { driver.submit(Command::Mtu(7680)).await })
        };
        entered.await.unwrap();
        caller.abort();
        let _ = caller.await;
        assert_eq!(slots.available_permits(), 0);
        assert!(tokio::time::timeout(Duration::from_millis(20), driver.close()).await.is_err());
        assert!(!driver.drained.is_cancelled());
        assert_eq!(slots.available_permits(), 0);
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), driver.close()).await.unwrap();
        assert_eq!(slots.available_permits(), 1);
        owner.wait().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn driver_refuses_expired_answer_and_drives_send_expiration() {
        let owner = AdnlTasks::new();
        let (driver, mut events) =
            ConnectionDriver::start([4; 32], owner.clone(), Arc::new(Semaphore::new(1))).unwrap();
        assert!(!driver
            .submit(Command::Send {
                id: [5; 32],
                data: vec![1; 64],
                deadline: Some(Instant::now() - Duration::from_secs(1)),
                answer: true
            })
            .await
            .unwrap());
        assert!(events.try_recv().is_err());
        let id = [6; 32];
        assert!(driver
            .submit(Command::Send {
                id,
                data: vec![1; 64],
                deadline: Some(Instant::now() + Duration::from_millis(40)),
                answer: false
            })
            .await
            .unwrap());
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let event = events.recv().await.unwrap();
                if let Some((actual, result)) = event.sent.into_iter().next() {
                    assert_eq!(actual, id);
                    assert!(result.is_err());
                    break;
                }
            }
        })
        .await
        .unwrap();
        driver.close().await;
        owner.wait().await.unwrap();
    }
}
