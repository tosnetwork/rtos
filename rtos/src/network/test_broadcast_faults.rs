// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Instance-local faults after real QUIC authentication, before overlay dispatch.
use adnl::{
    common::{AdnlPeers, QueryAnswer, QueryResult, Subscriber},
    OverlayNode,
};
use rtos_api::TLObject;
use rtos_block::Result;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub(crate) struct Receipt {
    pub constructor: u32,
    pub simple_id: Option<[u8; 32]>,
    pub wire: Vec<u8>,
    pub dropped: bool,
    pub error: Option<String>,
}

#[derive(Default)]
struct State {
    peer: Option<[u8; 32]>,
    prefix: Vec<u8>,
    remaining: usize,
    receipts: Vec<Receipt>,
}

#[derive(Default)]
pub(crate) struct BroadcastFaults(Mutex<State>);

impl BroadcastFaults {
    pub fn configure(&self, peer: [u8; 32], prefix: Vec<u8>, drops: usize) {
        assert!(!prefix.is_empty());
        *self.0.lock().unwrap() =
            State { peer: Some(peer), prefix, remaining: drops, receipts: vec![] };
    }

    pub fn receipts(&self) -> Vec<Receipt> {
        self.0.lock().unwrap().receipts.clone()
    }

    fn classify(&self, bytes: &[u8], peers: &AdnlPeers) -> Option<Receipt> {
        let mut state = self.0.lock().unwrap();
        if state.peer != Some(*peers.other().data()) || !bytes.starts_with(&state.prefix) {
            return None;
        }
        let constructor = u32::from_le_bytes(
            bytes.get(state.prefix.len()..state.prefix.len() + 4)?.try_into().ok()?,
        );
        let drop = state.remaining > 0;
        if drop && state.remaining != usize::MAX {
            state.remaining -= 1;
        }
        let simple_id = rtos_api::deserialize_boxed(&bytes[state.prefix.len()..])
            .ok()
            .and_then(|object| object.downcast::<rtos_api::ton::overlay::Broadcast>().ok())
            .and_then(|broadcast| match broadcast {
                rtos_api::ton::overlay::Broadcast::Overlay_BroadcastPlumtreeSimple(value) => {
                    Some(*value.broadcast_id.as_array())
                }
                _ => None,
            });
        Some(Receipt {
            constructor,
            simple_id,
            wire: if simple_id.is_some() && bytes.len() <= 16_384 {
                bytes.to_vec()
            } else {
                vec![]
            },
            dropped: drop,
            error: None,
        })
    }

    fn record(&self, receipt: Receipt) {
        let mut state = self.0.lock().unwrap();
        assert!(state.receipts.len() < 1024, "fault fixture exceeded its observation budget");
        state.receipts.push(receipt);
    }
}

pub(crate) struct ObservedOverlay {
    pub overlay: Arc<OverlayNode>,
    pub faults: Arc<BroadcastFaults>,
}

#[async_trait::async_trait]
impl Subscriber for ObservedOverlay {
    async fn try_consume_custom(&self, bytes: &[u8], peers: &AdnlPeers) -> Result<bool> {
        let selected = self.faults.classify(bytes, peers);
        if selected.as_ref().is_some_and(|receipt| receipt.dropped) {
            self.faults.record(selected.unwrap());
            return Ok(true); // Real received message deliberately lost at this boundary.
        }
        let result = self.overlay.try_consume_custom(bytes, peers).await;
        if let Some(mut receipt) = selected {
            receipt.error = result.as_ref().err().map(ToString::to_string);
            self.faults.record(receipt);
        }
        result
    }

    async fn try_consume_raw_query(
        &self,
        bytes: &[u8],
        peers: &AdnlPeers,
    ) -> Result<Option<QueryAnswer>> {
        self.overlay.try_consume_raw_query(bytes, peers).await
    }

    async fn try_consume_query_bundle(
        &self,
        objects: Vec<TLObject>,
        peers: &AdnlPeers,
    ) -> Result<QueryResult> {
        self.overlay.try_consume_query_bundle(objects, peers).await
    }
}

/// Pause the actual consumer before pop while its subscription remains owned.
pub(crate) struct ConsumerGate {
    entered: std::sync::atomic::AtomicBool,
    changed: tokio::sync::Notify,
    release: tokio::sync::Semaphore,
}

impl ConsumerGate {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: false.into(),
            changed: tokio::sync::Notify::new(),
            release: tokio::sync::Semaphore::new(0),
        })
    }
    pub async fn wait_entered(&self) {
        loop {
            let changed = self.changed.notified();
            if self.entered.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }
    pub fn release(&self) {
        self.release.add_permits(1);
    }
    pub async fn hold(&self, cancellation: &tokio_util::sync::CancellationToken) -> bool {
        self.entered.store(true, std::sync::atomic::Ordering::Release);
        self.changed.notify_waiters();
        tokio::select! {
            _ = cancellation.cancelled() => false,
            permit = self.release.acquire() => { drop(permit); true }
        }
    }
}
