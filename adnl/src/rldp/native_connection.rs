// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Connection event routing owned by an authenticated PeerTable entry.
use super::*;
use std::sync::Weak;
use tokio::sync::{Notify, OwnedSemaphorePermit};
use tokio_util::sync::CancellationToken;

pub(super) struct NativeConnection {
    pub(super) driver: Arc<connection_driver::ConnectionDriver>,
    #[cfg(test)]
    pub(super) completed_sends: Arc<AtomicU64>,
}
impl NativeConnection {
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
        let ret = Arc::new(Self {
            driver: driver.clone(),
            #[cfg(test)]
            completed_sends: Arc::new(AtomicU64::new(0)),
        });
        #[cfg(test)]
        let completed_sends = ret.completed_sends.clone();
        let lifetime = owner.clone();
        owner.spawn_admitted("RLDP2 Connection events", token, async move {
            // Keep this entry's capacity until actual transport work ends.
            // Application callbacks are separately retained by the node owner.
            let _permit = permit;
            loop {
                let event = tokio::select! {
                    biased;
                    _ = closed.cancelled() => break,
                    _ = lifetime.cancelled() => break,
                    event = events.recv() => match event { Some(event) => event, None => break },
                };
                for (_, result) in event.sent {
                    #[cfg(test)]
                    if result.is_ok() {
                        completed_sends.fetch_add(1, Ordering::Release);
                    }
                    if let Err(error) = result {
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
                    let data = match result {
                        Ok(data) => data,
                        Err(error) => {
                            log::debug!(target: TARGET, "RLDP2 receive: {error}");
                            continue;
                        }
                    };
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
            driver.close().await;
            drained.cancel();
            wake.notify_one();
        });
        Ok(ret)
    }
}
