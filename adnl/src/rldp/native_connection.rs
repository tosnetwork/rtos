// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Connection event routing owned by an authenticated PeerTable entry.
use super::*;
use futures::{future::BoxFuture, stream::FuturesUnordered, FutureExt};
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
            // Keep this entry's capacity until both transport work and application
            // callbacks have actually ended, including after peer eviction.
            let _permit = permit;
            let mut applications = FuturesUnordered::<BoxFuture<'static, Result<()>>>::new();
            loop {
                let event = tokio::select! {
                    biased;
                    _ = closed.cancelled() => break,
                    _ = lifetime.cancelled() => break,
                    result = applications.next(), if !applications.is_empty() => {
                        if let Some(Err(error)) = result {
                            log::warn!(target: TARGET, "RLDP2 application: {error}");
                        }
                        continue;
                    },
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
                    let (driver, route) = (driver.clone(), route.clone());
                    applications.push(
                        async move {
                            RldpNode::process_message(
                                MessageContext {
                                    driver: Some(&driver),
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
                            .await?;
                            Ok(())
                        }
                        .boxed(),
                    );
                }
            }
            closed.cancel();
            driver.close().await;
            // A subscriber can own a pending answer task. Never drop its awaiter
            // during shutdown and silently detach that application's work.
            while let Some(result) = applications.next().await {
                if let Err(error) = result {
                    log::debug!(target: TARGET, "RLDP2 closing application: {error}");
                }
            }
            drained.cancel();
            wake.notify_one();
        });
        Ok(ret)
    }
}
