// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Connection event routing owned by an authenticated PeerTable entry.
use super::*;
use crate::adnl::tasks::AdnlTasks;
use std::{
    collections::BTreeMap,
    sync::{Mutex, Weak},
};
use tokio::sync::{oneshot, Notify, OwnedSemaphorePermit};
use tokio_util::sync::CancellationToken;

struct PendingQuery {
    reply: oneshot::Sender<Result<Vec<u8>>>,
    admission: Arc<query_admission::QueryAdmission>,
    deadline: tokio::time::Instant,
}
// On non-answer envelopes, enqueue normal application delivery before failing
// the solicited-answer waiter, matching RldpIn::receive_message ordering.
struct InvalidAnswer(Option<PendingQuery>);
impl Drop for InvalidAnswer {
    fn drop(&mut self) {
        if let Some(query) = self.0.take() {
            query.admission.release();
            let _ = query.reply.send(Err(error!("received invalid RLDP query answer")));
        }
    }
}
#[derive(Default)]
struct Waiters {
    received: BTreeMap<TransferId, PendingQuery>,
    sent: BTreeMap<TransferId, oneshot::Sender<Result<()>>>,
}
struct WaiterRegistration {
    waiters: Arc<Mutex<Waiters>>,
    send: TransferId,
    receive: Option<TransferId>,
    #[cfg(test)]
    finished: Arc<AtomicU64>,
}
impl Drop for WaiterRegistration {
    fn drop(&mut self) {
        let mut waiters = self.waiters.lock().unwrap();
        waiters.sent.remove(&self.send);
        if let Some(id) = self.receive {
            if let Some(query) = waiters.received.remove(&id) {
                query.admission.release();
            }
        }
        #[cfg(test)]
        {
            drop(waiters);
            self.finished.fetch_add(1, Ordering::Release);
        }
    }
}
struct CloseWaiters(Arc<Mutex<Waiters>>);
impl Drop for CloseWaiters {
    fn drop(&mut self) {
        let mut waiters = self.0.lock().unwrap();
        for (_, query) in std::mem::take(&mut waiters.received) {
            query.admission.release();
        }
        waiters.sent.clear();
    }
}

pub(super) struct NativeConnection {
    pub(super) driver: Arc<connection_driver::ConnectionDriver>,
    owner: Arc<AdnlTasks>,
    closed: CancellationToken,
    waiters: Arc<Mutex<Waiters>>,
    #[cfg(test)]
    pub(super) completed_sends: Arc<AtomicU64>,
    #[cfg(test)]
    pub(super) routed_receives: Arc<AtomicU64>,
    #[cfg(test)]
    pub(super) receive_hash_probe: Arc<Mutex<Option<oneshot::Sender<(TransferId, [u8; 32])>>>>,
    #[cfg(test)]
    pub(super) processed_data_packets: AtomicU64,
    #[cfg(test)]
    pub(super) data_receipts: Mutex<BTreeMap<(TransferId, i32, i32), u64>>,
    #[cfg(test)]
    pub(super) data_processed: Notify,
    #[cfg(test)]
    pub(super) completed_send_ids: Arc<Mutex<Vec<TransferId>>>,
    #[cfg(test)]
    pub(super) failed_send_ids: Arc<Mutex<Vec<TransferId>>>,
    #[cfg(test)]
    pub(super) query_send_results: Mutex<Vec<(TransferId, bool)>>,
    #[cfg(test)]
    pub(super) retired_registrations: Arc<AtomicU64>,
}
impl NativeConnection {
    #[cfg(test)]
    pub(super) fn waiter_counts(&self) -> (usize, usize) {
        let waiters = self.waiters.lock().unwrap();
        (waiters.sent.len(), waiters.received.len())
    }
    pub(super) fn start(
        node: Weak<RldpNode>,
        adnl: Arc<AdnlNode>,
        route: AdnlPeers,
        pool: &SendWorkerPool,
        closed: CancellationToken,
        drained: CancellationToken,
        permit: OwnedSemaphorePermit,
        wake: Arc<Notify>,
    ) -> Result<Arc<Self>> {
        let owner = adnl.tasks().clone();
        let token = owner.enter()?;
        let (driver, mut events) = connection_driver::ConnectionDriver::start(
            *route.other().data(),
            owner.clone(),
            pool.fec_slots(),
        )?;
        let driver = Arc::new(driver);
        let waiters = Arc::new(Mutex::new(Waiters::default()));
        let ret = Arc::new(Self {
            driver: driver.clone(),
            owner: owner.clone(),
            closed: closed.clone(),
            waiters: waiters.clone(),
            #[cfg(test)]
            completed_sends: Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            routed_receives: Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            receive_hash_probe: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            processed_data_packets: AtomicU64::new(0),
            #[cfg(test)]
            data_receipts: Mutex::new(BTreeMap::new()),
            #[cfg(test)]
            data_processed: Notify::new(),
            #[cfg(test)]
            completed_send_ids: Arc::new(Mutex::new(Vec::new())),
            #[cfg(test)]
            failed_send_ids: Arc::new(Mutex::new(Vec::new())),
            #[cfg(test)]
            query_send_results: Mutex::new(Vec::new()),
            #[cfg(test)]
            retired_registrations: Arc::new(AtomicU64::new(0)),
        });
        #[cfg(test)]
        let completed_sends = ret.completed_sends.clone();
        #[cfg(test)]
        let routed_receives = ret.routed_receives.clone();
        #[cfg(test)]
        let receive_hash_probe = ret.receive_hash_probe.clone();
        #[cfg(test)]
        let completed_send_ids = ret.completed_send_ids.clone();
        #[cfg(test)]
        let failed_send_ids = ret.failed_send_ids.clone();
        let lifetime = owner.clone();
        owner.spawn_admitted("RLDP2 Connection events", token, async move {
            // Keep this entry's capacity until actual transport work ends.
            // Application callbacks are separately retained by the node owner.
            let _permit = permit;
            let close_waiters = CloseWaiters(waiters.clone());
            loop {
                let event = tokio::select! {
                    biased;
                    _ = closed.cancelled() => break,
                    _ = lifetime.cancelled() => break,
                    event = events.recv() => match event { Some(event) => event, None => break },
                };
                for (id, result) in event.sent {
                    #[cfg(test)]
                    if result.is_ok() {
                        completed_send_ids.lock().unwrap().push(id);
                        completed_sends.fetch_add(1, Ordering::Release);
                    }
                    #[cfg(test)]
                    if result.is_err() {
                        failed_send_ids.lock().unwrap().push(id);
                    }
                    if let Some(reply) = waiters.lock().unwrap().sent.remove(&id) {
                        let _ = reply.send(result.map_err(|error| error!("RLDP2 send: {error}")));
                    } else if let Err(error) = result {
                        log::debug!(target: TARGET, "RLDP2 send: {error}");
                    }
                }
                for packet in event.packets {
                    if let Err(error) = adnl
                        .send_custom(
                            &TaggedByteSlice {
                                object: &packet,
                                #[cfg(feature = "telemetry")]
                                tag: 0,
                            },
                            &route,
                        )
                        .await
                    {
                        log::debug!(target: TARGET, "RLDP2 packet send: {error}");
                    }
                }
                for (id, result) in event.received {
                    #[cfg(test)]
                    if let Ok(data) = &result {
                        if let Some(probe) = receive_hash_probe.lock().unwrap().take() {
                            let _ = probe.send((id, rtos_block::sha256_digest(data)));
                        }
                    }
                    let (data, invalid_answer) = Self::route_received(&waiters, id, result);
                    #[cfg(test)]
                    routed_receives.fetch_add(1, Ordering::Release);
                    let _invalid_answer = InvalidAnswer(invalid_answer);
                    let Some(data) = data else { continue };
                    let Some(node) = node.upgrade() else {
                        break;
                    };
                    let route = route.clone();
                    let application_owner = lifetime.clone();
                    let Ok(application_token) = application_owner.enter() else {
                        continue;
                    };
                    let application_lifetime = application_owner.clone();
                    application_owner.spawn_admitted(
                        "RLDP2 application",
                        application_token,
                        async move {
                            // Refuse callbacks that have not started when the node
                            // closes. Once entered, retain the subscriber's actual
                            // awaiter even if its original peer actor is evicted.
                            if application_lifetime.is_closed() {
                                return;
                            }
                            let result = RldpNode::process_message(
                                MessageContext {
                                    native: true,
                                    adnl: &node.adnl,
                                    peers: &route,
                                    data: &data,
                                    transfer_id: id,
                                    #[cfg(feature = "debug")]
                                    timestamp: &node.timestamp,
                                },
                                node.subscribers.clone(),
                                true,
                                &node.peers,
                                #[cfg(feature = "telemetry")]
                                node.telemetry.send_transfers.clone(),
                                node.allocated.send_transfers.clone(),
                                #[cfg(test)]
                                &node.allocated.response_lifecycle,
                            )
                            .await;
                            #[cfg(test)]
                            node.allocated.response_lifecycle.1.fetch_add(1, Ordering::Release);
                            if let Err(error) = result {
                                log::debug!(target: TARGET, "RLDP2 application: {error}");
                            }
                        },
                    );
                }
            }
            closed.cancel();
            // Release logical waiters at eviction; physical transport owners
            // still retain the peer permit until the blocking driver drains.
            drop(close_waiters);
            driver.close().await;
            drained.cancel();
            wake.notify_one();
        });
        Ok(ret)
    }

    fn route_received(
        waiters: &Mutex<Waiters>,
        id: TransferId,
        result: std::result::Result<Vec<u8>, crate::fec::Refusal>,
    ) -> (Option<Vec<u8>>, Option<PendingQuery>) {
        let query = waiters.lock().unwrap().received.remove(&id);
        let data = match result {
            Ok(data) => data,
            Err(error) => {
                if let Some(query) = query {
                    query.admission.release();
                    let error = if tokio::time::Instant::now() >= query.deadline {
                        RldpQueryTimeout.into()
                    } else {
                        error.into()
                    };
                    let _ = query.reply.send(Err(error));
                }
                return (None, None);
            }
        };
        if let Some(query) = query {
            let answer = deserialize_boxed(&data)
                .ok()
                .and_then(|value| value.downcast::<RldpMessageBoxed>().ok());
            if matches!(answer, Some(RldpMessageBoxed::Rldp_Answer(_))) {
                query.admission.release();
                let _ = query.reply.send(Ok(data));
                return (None, None);
            }
            // Valid Message/Query envelopes keep their normal application side
            // effect. Malformed envelopes have no application dispatch.
            return (answer.is_some().then_some(data), Some(query));
        }
        (Some(data), None)
    }

    pub(super) async fn outbound(
        self: &Arc<Self>,
        data: Vec<u8>,
        max_answer_size: Option<u64>,
        deadline: tokio::time::Instant,
        admission: Option<Arc<query_admission::QueryAdmission>>,
        bounded: Option<BoundedReceive>,
        control: Arc<SendControl>,
        permit: Arc<OwnedSemaphorePermit>,
    ) -> Result<Option<Vec<u8>>> {
        let token = self.owner.enter()?;
        let this = self.clone();
        let (done, result) = oneshot::channel();
        self.owner.spawn_admitted("RLDP2 outbound query/message", token, async move {
            let mut command_permit = Some(permit);
            let _bounded = bounded;
            let send: TransferId = rand::thread_rng().gen();
            let receive = max_answer_size.map(|_| send.map(|byte| byte ^ 0xff));
            let (sent, sent_result) = oneshot::channel();
            let (received, received_result) = oneshot::channel();
            {
                let mut waiters = this.waiters.lock().unwrap();
                // Random IDs are never allowed to replace a live waiter.
                if waiters.sent.contains_key(&send)
                    || receive.is_some_and(|id| waiters.received.contains_key(&id)) {
                    let _ = done.send(Err(error!("RLDP2 active transfer ID collision")));
                    return;
                }
                waiters.sent.insert(send, sent);
                if let Some(id) = receive {
                    waiters.received.insert(id, PendingQuery {
                        reply: received,
                        admission: admission.as_ref().expect("query admission").clone(),
                        deadline,
                    });
                }
            }
            let _registration = WaiterRegistration {
                waiters: this.waiters.clone(), send, receive,
                #[cfg(test)]
                finished: this.retired_registrations.clone(),
            };
            let mut sent_result = Some(sent_result);
            let mut accepted = false;
            let work = async {
                if let Some(id) = receive {
                    this.driver.submit(connection_driver::Command::ReceiveLimit {
                        id, deadline: deadline.into_std(), max_size: max_answer_size.unwrap(),
                    }).await?;
                }
                accepted = this.driver.submit(connection_driver::Command::Send {
                    id: send, data, deadline: Some(deadline.into_std()), answer: false,
                }).await?;
                #[cfg(test)]
                if receive.is_some() {
                    this.query_send_results.lock().unwrap().push((send, accepted));
                }
                // This lease bounds submission owners, not queries awaiting an
                // application answer. The blocking command has actually joined;
                // native Connection transfer/receive limits now own admission.
                drop(command_permit.take());
                if receive.is_some() {
                    // Native ignores send refusal for a query: its receive limit
                    // remains live until an answer or the original deadline.
                    Ok(Some(received_result.await.map_err(|_| error!("RLDP2 query owner closed"))??))
                } else {
                    if accepted {
                        sent_result.take().unwrap().await
                            .map_err(|_| error!("RLDP2 send owner closed"))??;
                    }
                    Ok(None)
                }
            };
            let (outcome, cancel) = tokio::select! {
                biased;
                _ = control.cancelled() => (Err(control.check().unwrap_err()), true),
                _ = this.owner.cancelled() => (Err(SendCancelled::OwnerClosed.into()), true),
                _ = this.closed.cancelled() => (Err(SendCancelled::PeerEvicted.into()), true),
                _ = tokio::time::sleep_until(deadline) => (
                    Err(if receive.is_some() { RldpQueryTimeout.into() } else { SendCancelled::Deadline.into() }), true),
                outcome = work => (outcome, false),
            };
            if let Some(admission) = &admission { admission.release(); }
            // Deliver the logical terminal result before retaining transport
            // cleanup. Bounded callers separately await _bounded.done dropping.
            let _ = done.send(outcome);
            if cancel {
                if this.driver.submit(connection_driver::Command::Cancel { send, receive }).await.is_err() {
                    this.driver.close().await;
                }
            } else if receive.is_some() && accepted {
                // An answer may arrive before our request's final ACK. Keep
                // that actual transport owned without delaying a normal query.
                tokio::select! {
                    _ = sent_result.take().unwrap() => {},
                    _ = this.owner.cancelled() => this.driver.close().await,
                    _ = this.closed.cancelled() => this.driver.close().await,
                }
            }
            if this.closed.is_cancelled() || this.owner.is_closed() {
                this.driver.close().await;
            }
        });
        result.await.map_err(|_| error!("RLDP2 outbound owner closed"))?
    }
}
