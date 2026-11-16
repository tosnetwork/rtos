/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2019-2023 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
#[cfg(feature = "telemetry")]
use crate::adnl::telemetry::Metric;
use crate::{
    adnl::{
        common::{
            add_counted_object_to_map, add_unbound_object_to_map, AdnlPeers, CountedObject,
            Counter, Custom, Query, QueryId, Subscriber, TaggedByteSlice, TimedAnswer, Version,
        },
        node::{AdnlNode, DataCompression},
    },
    declare_counted,
};
use futures::stream::StreamExt;
use rand::Rng;
#[cfg(feature = "telemetry")]
use rtos_api::BoxedSerialize;
use rtos_api::{
    deserialize_boxed, serialize_boxed,
    ton::{
        fec::Type as FecType,
        rldp::{
            message::{Message as RldpMessage, Query as RldpQuery},
            messagepart::{Complete as RldpComplete, MessagePart as RldpMessagePart},
            Message as RldpMessageBoxed, MessagePart as RldpMessagePartBoxed,
        },
        rldp2::{
            messagepart::{Complete as Rldp2Complete, MessagePart as Rldp2MessagePart},
            MessagePart as Rldp2MessagePartBoxed,
        },
    },
    AnyBoxedSerialize, IntoBoxed,
};
use rtos_block::{base64_encode, error, fail, KeyId, Result, UInt256};
#[cfg(feature = "debug")]
use std::sync::atomic::AtomicPtr;
#[cfg(any(feature = "debug", feature = "telemetry"))]
use std::sync::atomic::AtomicU32;
#[cfg(any(feature = "debug", feature = "telemetry"))]
use std::time::Instant;
use std::{
    cmp::min,
    collections::HashSet,
    sync::{
        atomic::{AtomicI32, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

mod recv;
pub use recv::RaptorqDecoder;
use recv::{RecvContext, RecvTransfer, RecvTransferState};

mod send;
pub use send::RaptorqEncoder;
use send::{
    OwnedSendPart, SendActionV2, SendContext, SendPartContextV2, SendPartStateV1, SendPartStateV2,
    SendPartV2, SendTransfer, SendTransferState,
};

mod owned_send;
mod peers;
use owned_send::{SendCancelled, SendControl, SendWorkerPool};

pub mod rldp2;
mod stat;
use stat::{StatsConfigV2, StatsV2};

const TARGET: &str = "rldp";

pub enum Chunk {
    V1(RldpMessagePart),
    V2(Rldp2MessagePart),
}

impl Chunk {
    fn transfer_id(&self) -> &TransferId {
        match self {
            Chunk::V1(RldpMessagePart(chunk)) => chunk.transfer_id.as_array(),
            Chunk::V2(Rldp2MessagePart(chunk)) => chunk.transfer_id.as_array(),
        }
    }
}

pub struct Constraints {
    pub data_size: usize,
}

impl Constraints {
    const DEFAULT_INBOUND_TRANSFER_SIZE: usize = 2 << 10; // 2 KB
    const MAX_PARTS_IN_TRANSIT: usize = 20;
    const MAX_TOTAL_TRANSFER_SIZE: usize = 16 << 20; // 16 MB
    const RLDP_ANSWER_TL_OVERHEAD: usize = 64; // RldpAnswer { query_id, data } serialize overhead
    const SLICE: usize = 2000000;
    const SYMBOL: usize = 768;

    pub fn check_data_size(&self, data_size: i32) -> Result<()> {
        if data_size == 0 {
            fail!("Empty RaptorQ data payload")
        }
        if data_size as usize > self.data_size {
            fail!("Too big RaptorQ data payload: {}", data_size)
        }
        Ok(())
    }

    pub fn check_fec_type(&self, fec_type: &FecType) -> Result<()> {
        match fec_type {
            FecType::Fec_RaptorQ(fec_type) => {
                if fec_type.symbol_size as usize != Self::SYMBOL {
                    fail!("Bad RaptorQ symbol size: {}", fec_type.symbol_size)
                }
                self.check_data_size(fec_type.data_size)?;
            }
            x => fail!("Bad FEC type {:?}", x),
        }
        Ok(())
    }

    pub fn check_seqno(seqno: u32) -> Result<()> {
        if (seqno & 0xff000000) != 0 {
            fail!("RaptorQ seqno is longer than 24 bits: {:x}", seqno)
        }
        Ok(())
    }
}

#[cfg(feature = "debug")]
pub type LossFn = fn(&Chunk) -> bool;

#[derive(Debug)]
enum MessagePart {
    V1(RldpMessagePartBoxed),
    V2(Rldp2MessagePartBoxed),
}

type TransferId = [u8; 32];

enum RldpTransfer {
    Recv(tokio::sync::mpsc::UnboundedSender<Chunk>),
    Send(SendTransferState),
    Done,
}

// The expiry is an update, never a new registration. A delayed timer must not
// resurrect an ID removed by the receive owner during shutdown or completion.
async fn expire_inbound_transfer(
    transfers: Arc<lockfree::map::Map<TransferId, RldpTransfer>>,
    transfer_id: TransferId,
    owner: Arc<crate::adnl::tasks::AdnlTasks>,
    timer: impl std::future::Future<Output = ()>,
    peer: Option<Arc<RldpPeer>>,
    finished: Option<tokio_util::sync::CancellationToken>,
) {
    tokio::select! {
        biased;
        _ = owner.cancelled() => return,
        _ = timer => {},
    }
    // Cancellation in the caller's select cannot stop a mutation already
    // polling on another worker. Serialize the final write with old-generation
    // close/cleanup, so an expired timer cannot overwrite a reopened ID.
    let _ids = peer.as_ref().map(|peer| peer.registrations.lock().unwrap());
    if peer.as_ref().is_some_and(|peer| peer.closed.is_cancelled())
        || finished.as_ref().is_some_and(|finished| finished.is_cancelled())
    {
        return;
    }
    transfers.insert_with(transfer_id, |_, _, found| {
        if found.is_some() {
            lockfree::map::Preview::New(RldpTransfer::Done)
        } else {
            // Also discard a prepared replacement if a concurrent remove won
            // and insert_with invokes this callback again with no entry.
            lockfree::map::Preview::Discard
        }
    });
}

#[cfg(feature = "telemetry")]
#[derive(Default)]
struct RldpStats {
    transfers_sent_all: AtomicU64,
    transfers_recv_all: AtomicU64,
    transfers_sent_now: AtomicU64,
    transfers_recv_now: AtomicU64,
}

#[cfg(feature = "telemetry")]
impl RldpStats {
    fn inc(stat: &AtomicU64) -> u64 {
        stat.fetch_add(1, Ordering::Relaxed) + 1
    }
    fn dec(stat: &AtomicU64) -> u64 {
        stat.fetch_sub(1, Ordering::Relaxed) - 1
    }
}

struct SendJob {
    ctx: SendContext,
    send_id: TransferId,
    v2: bool,
    done: tokio::sync::oneshot::Sender<Result<bool>>,
}

impl SendJob {
    async fn run(
        self,
        peer: Arc<RldpPeer>,
        transfers: &Arc<lockfree::map::Map<TransferId, RldpTransfer>>,
        pool: &Arc<SendWorkerPool>,
        min_timeout_ms: u64,
    ) {
        let owner = self.ctx.adnl.tasks().clone();
        let control = self.ctx.control.clone();
        let permit = self.ctx.permit.clone();
        let admission = self.ctx.admission.clone();
        let registration = self.ctx.registration.clone();
        let closed = peer.closed.clone();
        let work =
            owned_send::supervise(control.clone(), owner.clone(), control.deadline(), async {
                control.check()?;
                if self.v2 {
                    match RldpNode::fetch_transfer_state_v2(transfers, &self.send_id) {
                        Ok(state) => {
                            RldpNode::send_loop_v2(self.ctx, state, &peer, pool, min_timeout_ms)
                                .await
                        }
                        Err(e) => Err(e),
                    }
                } else {
                    let work_control = control.clone();
                    let fec_slots = pool.fec_slots();
                    let receipt = pool.submit(work_control, async move {
                        RldpNode::send_loop_v1(self.ctx, &peer, min_timeout_ms, fec_slots).await
                    })?;
                    receipt.await.map_err(|_| error!("RLDP v1 owner lost its receipt"))?
                }
            });
        tokio::pin!(work);
        let result = tokio::select! {
            biased;
            _ = closed.cancelled() => {
                control.cancel(if owner.is_closed() { SendCancelled::OwnerClosed } else { SendCancelled::PeerEvicted });
                work.await
            },
            result = &mut work => result,
        };
        if !matches!(result, Ok(true)) {
            control.cancel(SendCancelled::SiblingFailed);
        }
        control.drain().await;
        let result = control.take_failure().unwrap_or(result);
        drop(permit);
        drop(admission);
        drop(registration);
        self.done.send(result).ok();
    }
}

declare_counted!(
    struct RldpPeer {
        outbound_semaphore: Arc<tokio::sync::Semaphore>,
        transfer_slots: Arc<tokio::sync::Semaphore>,
        closed: tokio_util::sync::CancellationToken,
        drained: tokio_util::sync::CancellationToken,
        registrations: Arc<std::sync::Mutex<HashSet<TransferId>>>,
        completed: std::sync::Mutex<std::collections::VecDeque<(TransferId, tokio::time::Instant)>>,
        tx: tokio::sync::mpsc::UnboundedSender<SendJob>,
        stats: StatsV2,
        #[cfg(test)]
        idle: Arc<tokio::sync::Notify>,
    }
);

struct RldpAlloc {
    #[cfg(test)]
    response_lifecycle: Arc<(AtomicU64, AtomicU64)>, // (senders started, inbound handlers finished)
    peers: Arc<AtomicU64>,
    send_transfers: Arc<AtomicU64>,
    recv_transfers: Arc<AtomicU64>,
}

#[cfg(feature = "telemetry")]
struct RldpTelemetry {
    peers: Arc<Metric>,
    recv_transfers: Arc<Metric>,
    send_transfers: Arc<Metric>,
}

pub use rtos_api::DecodeLimitExceeded as ResponseLimitExceeded;

#[derive(Debug)]
pub struct RldpQueryTimeout;

impl std::fmt::Display for RldpQueryTimeout {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RLDP2 query deadline expired")
    }
}

impl std::error::Error for RldpQueryTimeout {}

#[derive(Clone, Copy, Debug)]
pub struct QueryResponseLimits {
    pub wire_bytes: usize,
    pub decoded_bytes: usize,
}
impl QueryResponseLimits {
    pub fn validate(self) -> Result<()> {
        for value in [self.wire_bytes, self.decoded_bytes] {
            if value == 0 || value > Constraints::MAX_TOTAL_TRANSFER_SIZE {
                return Err(ResponseLimitExceeded {
                    limit: Constraints::MAX_TOTAL_TRANSFER_SIZE,
                    actual: value,
                }
                .into());
            }
        }
        Ok(())
    }
}
struct BoundedReceive {
    limits: QueryResponseLimits,
    token: tokio_util::task::task_tracker::TaskTrackerToken,
    done: tokio::sync::oneshot::Sender<()>,
    permit: Arc<tokio::sync::OwnedSemaphorePermit>,
}

/// Rldp Node
pub struct RldpNode {
    adnl: Arc<AdnlNode>,
    local_id: Option<Arc<KeyId>>,
    min_timeout_ms: u64,
    peers: Arc<peers::PeerTable>,
    extended_caps: lockfree::map::Map<Arc<KeyId>, Arc<AtomicI32>>,
    send_pool: Arc<SendWorkerPool>,
    #[cfg(feature = "telemetry")]
    stats: Arc<RldpStats>,
    subscribers: Arc<Vec<Arc<dyn Subscriber>>>,
    transfers: Arc<lockfree::map::Map<TransferId, RldpTransfer>>,
    #[cfg(feature = "debug")]
    timestamp: Arc<AtomicPtr<Instant>>,
    #[cfg(feature = "telemetry")]
    telemetry: RldpTelemetry,
    allocated: RldpAlloc,
    #[cfg(test)]
    test_control: std::sync::Mutex<Option<Arc<SendControl>>>,
    #[cfg(feature = "debug")]
    loss_fn: Option<LossFn>,
}

impl RldpNode {
    const ACK_DELAY_MS: u64 = 1; // RLDPv2 confirmation delay
    const MAX_OUTBOUNDS_PER_PEER: u32 = 3;
    const SIZE_TRANSFER_WAVE: u32 = 10;
    const SPINNER_MS: u64 = 1;
    const SPINNER_V1_SEND_MS: u64 = 10;
    const TIMEOUT_MAX_MS: u64 = 10000;
    const TIMEOUT_MIN_MS: u64 = 500;
    const TIMEOUT_OUTBOUND_HARD_MS: u64 = 30000;
    const TIMEOUT_WARN_MS: u64 = 5000;
    #[cfg(feature = "telemetry")]
    const TIMEOUT_TELEMETRY_SEC: u64 = 10;

    /// Constructor
    pub fn with_params(
        adnl: Arc<AdnlNode>,
        subscribers: Vec<Arc<dyn Subscriber>>,
        local_id: Option<Arc<KeyId>>,
        #[cfg(feature = "debug")] loss_fn: Option<LossFn>,
        #[cfg(feature = "debug")] min_timeout_ms: Option<u64>,
    ) -> Result<Arc<Self>> {
        #[cfg(feature = "telemetry")]
        let telemetry = RldpTelemetry {
            peers: adnl.add_metric("Alloc RLDP peers"),
            recv_transfers: adnl.add_metric("Alloc RLDP recv"),
            send_transfers: adnl.add_metric("Alloc RLDP send"),
        };
        let allocated = RldpAlloc {
            #[cfg(test)]
            response_lifecycle: Arc::new((AtomicU64::new(0), AtomicU64::new(0))),
            peers: Arc::new(AtomicU64::new(0)),
            recv_transfers: Arc::new(AtomicU64::new(0)),
            send_transfers: Arc::new(AtomicU64::new(0)),
        };
        #[cfg(not(feature = "debug"))]
        let min_timeout_ms = Self::TIMEOUT_MIN_MS;
        #[cfg(feature = "debug")]
        let min_timeout_ms = min_timeout_ms.unwrap_or(Self::TIMEOUT_MIN_MS);
        #[cfg(feature = "debug")]
        let timestamp = Box::new(Instant::now());
        let send_pool = Arc::new(SendWorkerPool::new(adnl.tasks().clone()));
        let transfers = Arc::new(lockfree::map::Map::new());
        let peers = peers::PeerTable::new(
            adnl.clone(),
            send_pool.clone(),
            transfers.clone(),
            allocated.peers.clone(),
            min_timeout_ms,
        )?;
        let ret = Self {
            adnl,
            local_id,
            min_timeout_ms,
            peers,
            extended_caps: lockfree::map::Map::new(),
            send_pool,
            #[cfg(feature = "telemetry")]
            stats: Arc::new(RldpStats::default()),
            subscribers: Arc::new(subscribers),
            transfers,
            #[cfg(feature = "debug")]
            timestamp: Arc::new(AtomicPtr::new(Box::into_raw(timestamp))),
            #[cfg(feature = "telemetry")]
            telemetry,
            allocated,
            #[cfg(test)]
            test_control: std::sync::Mutex::new(None),
            #[cfg(feature = "debug")]
            loss_fn,
        };
        Ok(Arc::new(ret))
    }

    /// +1/-1 the extended-inbound-cap counter for all given peers.
    /// Duplicates and local ADNL keys are filtered out.
    pub fn change_inbound_cap_for_peers(&self, peers: &[Arc<KeyId>], delta: i32) -> Result<()> {
        for id in peers.iter().filter(|p| self.adnl.key_by_id(p).is_err()).collect::<HashSet<_>>() {
            // Retry if a concurrent caller wins the insert race
            loop {
                if let Some(g) = self.extended_caps.get(id) {
                    g.val().fetch_add(delta, Ordering::Relaxed);
                    break;
                }
                let new_cap = Arc::new(AtomicI32::new(delta));
                if add_unbound_object_to_map(&self.extended_caps, id.clone(), || {
                    Ok(new_cap.clone())
                })? {
                    break;
                }
            }
        }
        Ok(())
    }

    fn send_control(&self) -> Arc<SendControl> {
        #[cfg(test)]
        if let Some(control) = self.test_control.lock().unwrap().clone() {
            return control;
        }
        SendControl::new()
    }

    /// Send message
    pub async fn message(
        &self,
        data: &TaggedByteSlice<'_>,
        peers: &AdnlPeers,
        v2: bool,
        roundtrip: Option<u64>,
    ) -> Result<u64> {
        let ret = self.outbound(data, None, peers, v2, roundtrip, None, None).await;
        #[cfg(feature = "telemetry")]
        let prefix = if v2 { "RLDP STAT recv v2" } else { "RLDP STAT recv v1" };
        #[cfg(feature = "telemetry")]
        if let Err(e) = &ret {
            log::info!(
                target: TARGET,
                "{prefix}: failed {:x} from {}: {e}",
                data.tag,
                peers.other()
            );
        }
        ret.map(|(_, timeout)| timeout)
    }

    /// Caller cancellation does not detach a scoped query or its receiver.
    /// The ADNL owner joins both, including transfer cleanup during shutdown.
    pub async fn query_bounded(
        self: &Arc<Self>,
        data: &TaggedByteSlice<'_>,
        limits: QueryResponseLimits,
        peers: &AdnlPeers,
        v2: bool,
        roundtrip: Option<u64>,
    ) -> Result<(Option<Vec<u8>>, u64)> {
        limits.validate()?;
        static CAPACITY: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> =
            std::sync::OnceLock::new();
        let permit = Arc::new(
            CAPACITY
                .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(32)))
                .clone()
                .try_acquire_owned()
                .map_err(|_| error!("Bounded RLDP query capacity exhausted"))?,
        );
        let token = self.adnl.tasks().enter()?;
        let receive_token = self.adnl.tasks().enter()?;
        let bytes = data.object.to_vec();
        #[cfg(feature = "telemetry")]
        let tag = data.tag;
        let peers = peers.clone();
        let node = self.clone();
        let control = self.send_control();
        let _cancel = control.guard();
        let (sent, received) = tokio::sync::oneshot::channel();
        self.adnl.tasks().spawn_admitted("bounded RLDP query", token, async move {
            let (done, joined) = tokio::sync::oneshot::channel();
            let scope =
                BoundedReceive { limits, token: receive_token, done, permit: permit.clone() };
            let data = TaggedByteSlice {
                object: &bytes,
                #[cfg(feature = "telemetry")]
                tag,
            };
            let result = node
                .outbound(
                    &data,
                    Some(limits.wire_bytes as u64),
                    &peers,
                    v2,
                    roundtrip,
                    Some(scope),
                    Some(control),
                )
                .await;
            // Sender is dropped on every pre-receiver error. A spawned receiver
            // remains admitted to ADNL until its real worker/supervisor joins.
            let _ = joined.await;
            drop(permit);
            let _ = sent.send(result);
        });
        received.await.map_err(|_| error!("Bounded RLDP query owner failed"))?
    }

    /// Send query
    pub async fn query(
        &self,
        data: &TaggedByteSlice<'_>,
        max_answer_size: Option<u64>,
        peers: &AdnlPeers,
        v2: bool,
        roundtrip: Option<u64>,
    ) -> Result<(Option<Vec<u8>>, u64)> {
        let max_answer_size = max_answer_size.or(Some(128 * 1024));
        let ret = self.outbound(data, max_answer_size, peers, v2, roundtrip, None, None).await;
        #[cfg(feature = "telemetry")]
        let prefix = if v2 { "RLDP STAT query v2" } else { "RLDP STAT query v1" };
        #[cfg(feature = "telemetry")]
        match &ret {
            Err(e) => log::info!(
                target: TARGET,
                "{prefix}: failed {:x} from {}: {e}",
                data.tag,
                peers.other()
            ),
            Ok((Some(reply), _)) => log::info!(
                target: TARGET,
                "{prefix}: success {:x} from {}: {} bytes",
                data.tag,
                peers.other(),
                reply.len()
            ),
            Ok((None, _)) => log::info!(
                target: TARGET,
                "{prefix}: no data {:x} from {}",
                data.tag,
                peers.other()
            ),
        }
        ret
    }

    #[cfg(feature = "debug")]
    /// For time measurements
    pub fn check_time(&self, msg: &str) {
        Self::check_timestamp(&self.timestamp, msg)
    }

    #[cfg(feature = "debug")]
    /// For time measurements
    fn check_timestamp(timestamp: &Arc<AtomicPtr<Instant>>, msg: &str) {
        let timestamp = timestamp.load(Ordering::Relaxed);
        let elapsed = unsafe { (*timestamp).elapsed() };
        println!("{}; elapsed: {}s", msg, (elapsed.as_micros() as f32) / 1000000.0);
    }

    #[cfg(feature = "debug")]
    /// For time measurements
    pub fn reset_timestamp(&self) {
        let timestamp = Box::new(Instant::now());
        self.timestamp.store(Box::into_raw(timestamp), Ordering::Relaxed);
    }

    fn check_message(fec_type: Option<&FecType>, seqno: i32) -> Result<()> {
        const CONSTRAINTS: Constraints = Constraints { data_size: Constraints::SLICE };
        if let Some(fec_type) = fec_type {
            CONSTRAINTS.check_fec_type(fec_type)?
        }
        Constraints::check_seqno(seqno as u32)
    }

    fn check_too_long_transfer(
        start_ms: u64,
        last_warn_ms: &mut u64,
        timestamp_ms: u64,
        transfer_str: &str,
        msg: &str,
    ) {
        let elapsed_ms = timestamp_ms - start_ms;
        if elapsed_ms > Self::TIMEOUT_MAX_MS {
            if timestamp_ms - *last_warn_ms > Self::TIMEOUT_WARN_MS {
                *last_warn_ms = elapsed_ms;
                log::warn!(
                    target: TARGET,
                    "{msg} {transfer_str} took {elapsed_ms}ms"
                );
            }
        }
    }

    async fn consume_chunk_message(&self, chunk: Chunk, peers: &AdnlPeers) -> Result<()> {
        let transfer_id = chunk.transfer_id();
        let (v2, part, seqno) = match &chunk {
            Chunk::V1(RldpMessagePart(chunk)) => (false, chunk.part, chunk.seqno),
            Chunk::V2(Rldp2MessagePart(chunk)) => (true, chunk.part, chunk.seqno),
        };
        loop {
            let result = if let Some(transfer) = self.transfers.get(transfer_id) {
                if let RldpTransfer::Recv(queue_sender) = transfer.val() {
                    queue_sender.send(chunk)
                } else {
                    // Chunk for a completed transfer — send Complete only (no Confirm),
                    // matching C++ behavior for both RLDP V1 and V2.
                    let reply = if v2 {
                        Rldp2Complete { transfer_id: transfer_id.into(), part }
                            .into_boxed()
                            .into_tl_object()
                    } else {
                        RldpComplete { transfer_id: transfer_id.into(), part }
                            .into_boxed()
                            .into_tl_object()
                    };
                    #[cfg(feature = "telemetry")]
                    let tag = reply.bare_object().constructor();
                    let data = serialize_boxed(&reply)?;
                    self.adnl
                        .send_custom(
                            &TaggedByteSlice {
                                object: &data,
                                #[cfg(feature = "telemetry")]
                                tag,
                            },
                            &peers,
                        )
                        .await?;
                    log::trace!(
                        target: TARGET,
                        "Sent Complete for closed {} transfer {}, part {}, seqno {}",
                        if v2 { "RLDPv2" } else { "RLDPv1" },
                        base64_encode(transfer_id), part, seqno
                    );
                    break;
                }
            } else if let Some(queue_sender) = self.inbound(transfer_id, peers, v2).await? {
                queue_sender.send(chunk)
            } else {
                continue;
            };
            match result {
                Ok(()) => (),
                Err(tokio::sync::mpsc::error::SendError(_)) => (),
            }
            break;
        }
        Ok(())
    }

    async fn consume_message_part(&self, msg: MessagePart, peers: &AdnlPeers) -> Result<bool> {
        let (check, v2) = match &msg {
            MessagePart::V1(RldpMessagePartBoxed::Rldp_MessagePart(part)) => {
                let RldpMessagePart(part) = part;
                (Self::check_message(Some(&part.fec_type), part.seqno), false)
            }
            MessagePart::V2(Rldp2MessagePartBoxed::Rldp2_MessagePart(part)) => {
                let Rldp2MessagePart(part) = part;
                (Self::check_message(Some(&part.fec_type), part.seqno), true)
            }
            MessagePart::V1(RldpMessagePartBoxed::Rldp_Confirm(confirm)) => {
                (Self::check_message(None, confirm.seqno), false)
            }
            MessagePart::V2(Rldp2MessagePartBoxed::Rldp2_Confirm(confirm)) => {
                (Self::check_message(None, confirm.max_seqno), true)
            }
            MessagePart::V1(RldpMessagePartBoxed::Rldp_Complete(_)) => (Ok(()), false),
            MessagePart::V2(Rldp2MessagePartBoxed::Rldp2_Complete(_)) => (Ok(()), true),
        };
        if let Err(e) = check {
            // Ignore invalid messages as early as possible
            log::warn!(
                target: TARGET, "Received bad RLDP {} message. {}",
                if v2 {
                    "v2"
                } else {
                    "v1"
                },
                e
            );
            return Ok(true);
        }
        if v2 {
            self.peers.get(peers.local(), peers.other(), true, None).await?;
        }
        match msg {
            MessagePart::V1(RldpMessagePartBoxed::Rldp_Complete(msg)) => {
                if let Some(state) = self.get_v1_state(msg.transfer_id.as_ref(), msg.part as u32) {
                    state.set_next_part(msg.part as u32 + 1)
                }
            }
            MessagePart::V2(Rldp2MessagePartBoxed::Rldp2_Complete(msg)) => {
                if let Some(state) = self.get_v2_state(msg.transfer_id.as_ref(), msg.part as u32) {
                    state.set_finished(true)
                }
            }
            MessagePart::V1(RldpMessagePartBoxed::Rldp_Confirm(msg)) => {
                if let Some(state) = self.get_v1_state(msg.transfer_id.as_ref(), msg.part as u32) {
                    state.set_seqno_recv(msg.seqno as u32);
                }
            }
            MessagePart::V2(Rldp2MessagePartBoxed::Rldp2_Confirm(msg)) => {
                if let Some(state) = self.get_v2_state(msg.transfer_id.as_ref(), msg.part as u32) {
                    state.set_recv_info(
                        msg.max_seqno as u32,
                        msg.received_count as u32,
                        msg.received_mask as u32,
                    )
                }
            }
            MessagePart::V1(RldpMessagePartBoxed::Rldp_MessagePart(msg)) => {
                self.consume_chunk_message(Chunk::V1(msg), peers).await?
            }
            MessagePart::V2(Rldp2MessagePartBoxed::Rldp2_MessagePart(msg)) => {
                self.consume_chunk_message(Chunk::V2(msg), peers).await?
            }
        }
        Ok(true)
    }

    #[cfg(feature = "telemetry")]
    fn fetch_tag(data: &[u8]) -> u32 {
        if data.len() >= 4 {
            let mut tag = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            // Uncover Overlay.Query internal message if possible
            if (tag == 0xCCFD8443) && (data.len() >= 40) {
                tag = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);
            }
            tag
        } else {
            0
        }
    }

    fn fetch_transfer_state_v2(
        transfers: &Arc<lockfree::map::Map<TransferId, RldpTransfer>>,
        transfer_id: &TransferId,
    ) -> Result<Arc<Vec<Arc<SendPartStateV2>>>> {
        match transfers
            .get(transfer_id)
            .ok_or_else(|| error!("No state for transfer {}", base64_encode(transfer_id)))?
            .val()
        {
            RldpTransfer::Send(SendTransferState::V2(state)) => Ok(state.clone()),
            _ => fail!("Wrong state for transfer {}", base64_encode(transfer_id)),
        }
    }

    async fn get_peer(
        &self,
        local: &Arc<KeyId>,
        id: &Arc<KeyId>,
        v2: bool,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<Arc<RldpPeer>> {
        let peer = self.peers.get(local, id, v2, deadline).await?;
        peer.stats.v1.on_connect();
        #[cfg(feature = "telemetry")]
        self.telemetry.peers.update(self.allocated.peers.load(Ordering::Relaxed));
        Ok(peer)
    }

    fn get_v1_state(&self, transfer_id: &TransferId, part: u32) -> Option<Arc<SendPartStateV1>> {
        let mut ret = None;
        if let Some(transfer) = self.transfers.get(transfer_id) {
            match transfer.val() {
                RldpTransfer::Send(SendTransferState::V1(state)) => {
                    if state.part() == part {
                        ret.replace(state.clone());
                    }
                }
                RldpTransfer::Send(SendTransferState::V2(_)) => log::warn!(
                    target: TARGET,
                    "Received V1 message in V2 transfer {}",
                    base64_encode(transfer.key())
                ),
                _ => (),
            }
        }
        ret
    }

    fn get_v2_state(&self, transfer_id: &TransferId, part: u32) -> Option<Arc<SendPartStateV2>> {
        let mut ret = None;
        if let Some(transfer) = self.transfers.get(transfer_id) {
            match transfer.val() {
                RldpTransfer::Send(SendTransferState::V1(_)) => log::warn!(
                    target: TARGET,
                    "Received V2 message in V1 transfer {}",
                    base64_encode(transfer.key())
                ),
                RldpTransfer::Send(SendTransferState::V2(states)) => {
                    if (part as usize) < states.len() {
                        ret.replace(states[part as usize].clone());
                    }
                }
                _ => (),
            }
        }
        ret
    }

    async fn inbound(
        &self,
        transfer_id: &TransferId,
        peers: &AdnlPeers,
        v2: bool,
    ) -> Result<Option<tokio::sync::mpsc::UnboundedSender<Chunk>>> {
        let rldp = if v2 { "RLDPv2" } else { "RLDPv1" };
        let peer = self.get_peer(peers.local(), peers.other(), v2, None).await?;
        let (queue_sender, queue_reader) = tokio::sync::mpsc::unbounded_channel();
        let inserted = {
            let mut ids = peer.registrations.lock().unwrap();
            if peer.closed.is_cancelled() {
                return Err(SendCancelled::PeerEvicted.into());
            }
            let inserted = add_unbound_object_to_map(&self.transfers, *transfer_id, || {
                Ok(RldpTransfer::Recv(queue_sender.clone()))
            })?;
            if inserted {
                ids.insert(*transfer_id);
            }
            inserted
        };
        if !inserted {
            return Ok(None);
        }
        let registration = Arc::new(owned_send::SendRegistration {
            inbound: v2.then(|| (*transfer_id, tokio_util::sync::CancellationToken::new())),
            peer: Some((Arc::downgrade(&peer), peer.closed.clone())),
            transfers: self.transfers.clone(),
            send: *transfer_id,
            receive: None,
            owner: self.adnl.tasks().clone(),
            bounded_permit: None,
        });
        #[cfg(feature = "telemetry")]
        let all = RldpStats::inc(&self.stats.transfers_recv_all);
        #[cfg(feature = "telemetry")]
        let now = RldpStats::inc(&self.stats.transfers_recv_now);
        #[cfg(feature = "telemetry")]
        log::trace!(target: TARGET, "{rldp} STAT recv: transfers total {all}, active {now}");
        let mut context = RecvContext {
            adnl: self.adnl.clone(),
            peers: peers.clone(),
            queue_reader,
            recv_transfer: RecvTransfer::new(
                *transfer_id,
                self.allocated.recv_transfers.clone(),
                v2,
                Some(self.peer_inbound_cap(peers.other())),
                #[cfg(feature = "debug")]
                self.timestamp.clone(),
            ),
            transfer_id: *transfer_id,
            #[cfg(feature = "debug")]
            loss_fn: self.loss_fn,
        };
        #[cfg(feature = "telemetry")]
        self.telemetry.recv_transfers.update(self.allocated.recv_transfers.load(Ordering::Relaxed));
        let peer_table = self.peers.clone();
        #[cfg(feature = "telemetry")]
        let stats = self.stats.clone();
        #[cfg(feature = "telemetry")]
        let send_metric = self.telemetry.send_transfers.clone();
        let send_counter = self.allocated.send_transfers.clone();
        #[cfg(test)]
        let response_lifecycle = self.allocated.response_lifecycle.clone();
        let subscribers = self.subscribers.clone();
        let transfers = self.transfers.clone();
        let owner = self.adnl.tasks().clone();
        let token = owner.enter()?;
        let lifetime = owner.clone();
        let inbound_finished = registration.inbound.as_ref().map(|(_, finished)| finished.clone());
        let connection_closed = peer.closed.clone();
        let expiry_peer = peer.clone();
        owner.spawn_admitted("RLDP inbound", token, async move {
            let _registration = registration;
            tokio::select! {
                biased;
                _ = peer.closed.cancelled() => return,
                _ = Self::receive_loop(&mut context, v2) => {},
            }
            if v2 {
                _registration.finish_inbound();
            } else if peer
                .insert_transfer(&transfers, context.transfer_id, RldpTransfer::Done)
                .is_err()
            {
                return;
            }
            let send_transfer_id = Self::inbound_loop(
                &mut context,
                subscribers,
                transfers.clone(),
                v2,
                &peer_table,
                #[cfg(feature = "telemetry")]
                send_metric,
                send_counter,
                #[cfg(test)]
                &response_lifecycle,
            )
            .await
            .unwrap_or_else(|e| {
                log::warn!(
                    target: TARGET,
                    "ERROR: Incoming {rldp}: {e}, transfer {} from {}",
                    base64_encode(&context.transfer_id),
                    context.peers.other()
                );
                None
            });
            #[cfg(test)]
            response_lifecycle.1.fetch_add(1, Ordering::Release);
            #[cfg(feature = "telemetry")]
            let all = stats.transfers_recv_all.load(Ordering::Relaxed);
            #[cfg(feature = "telemetry")]
            let now = RldpStats::dec(&stats.transfers_recv_now);
            #[cfg(feature = "telemetry")]
            log::trace!(
                target: TARGET,
                "{rldp} STAT recv: transfers total {all}, active {now}"
            );
            // V2 retains only a bounded completed ID, not the receiver, decoded
            // payload and two per-transfer expiry tasks for another20seconds.
            if v2 {
                return;
            }
            tokio::select! {
                _ = lifetime.cancelled() => {},
                _ = tokio::time::sleep(Duration::from_millis(Self::TIMEOUT_MAX_MS * 2)) => {},
            }
            let mut ids = peer.registrations.lock().unwrap();
            if !peer.closed.is_cancelled() {
                if let Some(send_transfer_id) = send_transfer_id {
                    transfers.remove(&send_transfer_id);
                    ids.remove(&send_transfer_id);
                }
                transfers.remove(&context.transfer_id);
                ids.remove(&context.transfer_id);
            }
        });
        let transfers = self.transfers.clone();
        let transfer_id = *transfer_id;
        let lifetime = owner.clone();
        owner.spawn("RLDP inbound expiry", async move {
            tokio::select! {
                biased;
                _ = connection_closed.cancelled() => {},
                _ = async {
                    if let Some(finished) = &inbound_finished { finished.cancelled().await; }
                    else { std::future::pending::<()>().await; }
                } => {},
                _ = expire_inbound_transfer(transfers, transfer_id, lifetime,
                    tokio::time::sleep(Duration::from_millis(Self::TIMEOUT_MAX_MS)), Some(expiry_peer), inbound_finished.clone()) => {},
            }
        });
        Ok(Some(queue_sender))
    }

    async fn inbound_loop(
        context: &mut RecvContext,
        subscribers: Arc<Vec<Arc<dyn Subscriber>>>,
        transfers: Arc<lockfree::map::Map<TransferId, RldpTransfer>>,
        v2: bool,
        peer_table: &Arc<peers::PeerTable>,
        #[cfg(feature = "telemetry")] send_metric: Arc<Metric>,
        send_counter: Arc<AtomicU64>,
        #[cfg(test)] response_lifecycle: &(AtomicU64, AtomicU64),
    ) -> Result<Option<TransferId>> {
        fn try_decompress(context: &mut RecvContext, data: &mut Vec<u8>) -> bool {
            if let Some(decompressed) = DataCompression::decompress_raw(data) {
                context.adnl.set_options(AdnlNode::OPTION_FORCE_COMPRESSION);
                *data = decompressed;
                true
            } else {
                context.adnl.check_options(AdnlNode::OPTION_FORCE_COMPRESSION)
            }
        }

        let rldp = if v2 { "RLDPv2" } else { "RLDPv1" };
        let mut query = match deserialize_boxed(&context.recv_transfer.data[..])?
            .downcast::<RldpMessageBoxed>()
        {
            Ok(RldpMessageBoxed::Rldp_Query(query)) => query,
            Ok(RldpMessageBoxed::Rldp_Message(mut message)) => {
                try_decompress(context, &mut message.data);
                #[cfg(feature = "debug")]
                Self::check_timestamp(&context.recv_transfer.timestamp, "Begin message process");
                if !Custom::process(&subscribers, &message.data, &context.peers).await? {
                    let len = min(16, message.data.len());
                    fail!("No subscribers for message {:?}...", hex::encode(&message.data[..len]));
                }
                #[cfg(feature = "debug")]
                Self::check_timestamp(&context.recv_transfer.timestamp, "End message process");
                return Ok(None);
            }
            Ok(message) => fail!("Unexpected {rldp} message: {message:?}"),
            Err(object) => fail!("Unexpected message in {rldp}: {object:?}"),
        };

        let now = Version::get();
        if now > query.timeout + Self::TIMEOUT_MAX_MS as i32 / 1000 {
            fail!(
                "{rldp} query was received expired on {} sec in transfer {} from {}",
                now - query.timeout,
                base64_encode(&context.transfer_id),
                context.peers.other()
            )
        }
        let compression = try_decompress(context, &mut query.data);
        #[cfg(feature = "debug")]
        Self::check_timestamp(&context.recv_transfer.timestamp, "Begin query process");
        #[cfg(feature = "telemetry")]
        let query_tag = Self::fetch_tag(&query.data[..]);
        let Some(answer) = Query::process_rldp(&subscribers, &query, &context.peers).await? else {
            fail!("No subscribers for query {:?}", query)
        };
        #[cfg(feature = "debug")]
        Self::check_timestamp(&context.recv_transfer.timestamp, "End query process");
        let answer = match answer.try_finalize()? {
            (Some(answer), _) => answer.try_wait().await?,
            (None, answer) => TimedAnswer {
                answer,
                #[cfg(feature = "telemetry")]
                actual_start_at: None,
            },
        };
        let Some(mut answer) = answer.answer else { return Ok(None) };
        // Match the native response path: a subscriber may finish after the
        // wire query deadline, in which case no new transfer may be opened.
        let response_deadline = if v2 {
            let monotonic_now = std::time::Instant::now();
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
            let Some(remaining) = u64::try_from(query.timeout)
                .ok()
                .and_then(|seconds| Duration::from_secs(seconds).checked_sub(now))
                .filter(|remaining| !remaining.is_zero())
            else {
                return Ok(None);
            };
            // Native limits a response to the wire deadline or 60 seconds,
            // whichever is sooner. Keep one monotonic deadline across queues.
            Some(monotonic_now + remaining.min(Duration::from_secs(60)))
        } else {
            None
        };
        let peer = peer_table
            .get(
                context.peers.local(),
                context.peers.other(),
                v2,
                response_deadline.map(tokio::time::Instant::from_std),
            )
            .await?;
        if response_deadline.is_some_and(|at| std::time::Instant::now() >= at) {
            return Ok(None);
        }

        // Native RldpConnection::send refuses before retaining outbound state.
        // This is shared by requests and responses on the same peer.
        let admission = if v2 {
            match peer.transfer_slots.clone().try_acquire_owned() {
                Ok(permit) => Some(Arc::new(permit)),
                Err(_) => return Ok(None),
            }
        } else {
            None
        };
        if compression {
            answer.object.data = DataCompression::compress_raw(&answer.object.data)?;
        }
        let (len, max) = (answer.object.data.len(), query.max_answer_size as usize);
        if len > max {
            fail!("Exceeded max {rldp} answer size: {} vs {}", len, max)
        }
        #[cfg(feature = "telemetry")]
        let tag = answer.tag;
        let data = Arc::from(serialize_boxed(&answer.object.into_boxed())?);
        let mut send_transfer_id = context.transfer_id;
        for x in &mut send_transfer_id {
            *x ^= 0xFF
        }
        log::trace!(
            target: TARGET,
            "{rldp} answer ({len} bytes) to be sent in transfer {}/{} to {}",
            base64_encode(&context.transfer_id),
            base64_encode(&send_transfer_id),
            context.peers.other()
        );
        let (ping, pong) = tokio::sync::mpsc::unbounded_channel();
        if response_deadline.is_some_and(|at| std::time::Instant::now() >= at) {
            return Ok(None);
        }
        let send_transfer = peer.insert_transfer_with(&transfers, send_transfer_id, || {
            let (transfer, state) =
                SendTransfer::new(data, send_transfer_id, send_counter.clone(), ping, v2)?;
            Ok((RldpTransfer::Send(state), transfer))
        })?;
        #[cfg(feature = "telemetry")]
        send_metric.update(send_counter.load(Ordering::Relaxed));
        #[cfg(test)]
        response_lifecycle.0.fetch_add(1, Ordering::Release);
        let control = SendControl::with_protocol_deadline(response_deadline);
        let _cancel = control.guard();
        let registration = Arc::new(owned_send::SendRegistration {
            inbound: None,
            peer: Some((Arc::downgrade(&peer), peer.closed.clone())),
            transfers: transfers.clone(),
            send: send_transfer_id,
            receive: None,
            owner: context.adnl.tasks().clone(),
            bounded_permit: None,
        });
        let context_send = SendContext {
            admission,
            registration,
            control,
            permit: None,
            adnl: context.adnl.clone(),
            peers: context.peers.clone(),
            pong,
            send_transfer,
            #[cfg(feature = "debug")]
            timestamp: context.recv_transfer.timestamp.clone(),
            transfer_id: context.transfer_id,
            #[cfg(feature = "telemetry")]
            tag,
        };
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        peer.tx
            .send(SendJob { ctx: context_send, send_id: send_transfer_id, v2, done: done_tx })
            .map_err(|_| error!("Peer task is gone"))?;
        let ok = match done_rx.await {
            Ok(result) => result?,
            Err(_) => false,
        };
        if ok {
            log::trace!(
                target: TARGET,
                "{rldp} answer ({len} bytes) sent in transfer {} to {}",
                base64_encode(&context.transfer_id),
                context.peers.other()
            );
            #[cfg(feature = "telemetry")]
            log::info!(
                target: TARGET,
                "{rldp} STAT send: answer on {query_tag:x} ({len} bytes) sent in transfer {} to {}",
                base64_encode(&context.transfer_id),
                context.peers.other()
            );
        } else {
            log::warn!(
                target: TARGET,
                "Timeout >{} ms on answer in {rldp} transfer {} to {}",
                peer.stats.v1.timeout(),
                base64_encode(&context.transfer_id),
                context.peers.other()
            );
            #[cfg(feature = "telemetry")]
            log::info!(
                target: TARGET,
                "{rldp} STAT send: answer on {query_tag:x} timed out in transfer {} to {}",
                base64_encode(&context.transfer_id),
                context.peers.other()
            );
        }
        Ok(Some(send_transfer_id))
    }

    async fn outbound(
        &self,
        data: &TaggedByteSlice<'_>,
        max_answer_size: Option<u64>,
        peers: &AdnlPeers,
        v2: bool,
        roundtrip: Option<u64>,
        bounded: Option<BoundedReceive>,
        control: Option<Arc<SendControl>>,
    ) -> Result<(Option<Vec<u8>>, u64)> {
        let query_deadline = (v2 && max_answer_size.is_some())
            .then(|| tokio::time::Instant::now() + Duration::from_millis(Self::TIMEOUT_MAX_MS));
        let response_limits = bounded.as_ref().map(|scope| scope.limits);
        let retained_permit = bounded.as_ref().map(|scope| scope.permit.clone());
        #[cfg(feature = "telemetry")]
        let tag = data.tag;
        let data = if self.adnl.check_options(AdnlNode::OPTION_FORCE_COMPRESSION) {
            DataCompression::compress_raw(&data.object)?
        } else {
            data.object.to_vec()
        };
        let (query_id, message) = if let Some(max_answer_size) = max_answer_size {
            let query_id: QueryId = rand::thread_rng().gen();
            let message = RldpQuery {
                query_id: UInt256::with_array(query_id),
                max_answer_size: max_answer_size as i64,
                timeout: Version::get() + Self::TIMEOUT_MAX_MS as i32 / 1000,
                data,
            }
            .into_boxed();
            (Some(query_id), message)
        } else {
            let message = RldpMessage { id: UInt256::rand(), data }.into_boxed();
            (None::<QueryId>, message)
        };
        let data: Arc<[u8]> = Arc::from(serialize_boxed(&message)?);
        // Native send_message also supplies a ten-second transfer deadline;
        // connection retention is that deadline plus the 120-second idle span.
        let connection_deadline = v2.then(|| {
            query_deadline.unwrap_or_else(|| {
                tokio::time::Instant::now() + Duration::from_millis(Self::TIMEOUT_MAX_MS)
            })
        });
        let get_peer = self.get_peer(peers.local(), peers.other(), v2, connection_deadline);
        let peer = match tokio::time::timeout_at(
            query_deadline.unwrap_or_else(|| {
                tokio::time::Instant::now() + Duration::from_millis(Self::TIMEOUT_OUTBOUND_HARD_MS)
            }),
            get_peer,
        )
        .await
        {
            Ok(peer) => peer?,
            Err(_) if query_deadline.is_some() => return Err(RldpQueryTimeout.into()),
            Err(_) => return Err(SendCancelled::Deadline.into()),
        };
        if let Some(roundtrip) = roundtrip {
            peer.stats.set_roundtrip(roundtrip)?
        }
        let control = control.unwrap_or_else(|| self.send_control());
        let _cancel = control.guard();
        let permit = tokio::select! {
            _ = control.cancelled() => { control.check()?; unreachable!() },
            _ = self.adnl.tasks().cancelled() => return Err(SendCancelled::OwnerClosed.into()),
            _ = async {
                if let Some(deadline) = query_deadline {
                    tokio::time::sleep_until(deadline).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                control.cancel(SendCancelled::Deadline);
                return Err(RldpQueryTimeout.into());
            },
            permit = peer.outbound_semaphore.clone().acquire_owned() => Arc::new(permit?),
        };
        #[cfg(feature = "telemetry")]
        log::trace!(
            target: TARGET,
            "RLDP STAT send: peer {} outbound permit acquired (available {})",
            peers.other(),
            peer.outbound_semaphore.available_permits(),
        );
        let admission = if v2 {
            match peer.transfer_slots.clone().try_acquire_owned() {
                Ok(permit) => Some(Arc::new(permit)),
                Err(_) => {
                    // Native silently drops a send at capacity. A query still
                    // completes at its original deadline, without a retry.
                    if let Some(deadline) = query_deadline {
                        tokio::select! {
                            _ = tokio::time::sleep_until(deadline) => return Err(RldpQueryTimeout.into()),
                            _ = control.cancelled() => { control.check()?; unreachable!() },
                            _ = self.adnl.tasks().cancelled() => return Err(SendCancelled::OwnerClosed.into()),
                        }
                    }
                    return Ok((None, peer.stats.v1.roundtrip()));
                }
            }
        } else {
            None
        };
        #[cfg(feature = "telemetry")]
        let all = RldpStats::inc(&self.stats.transfers_sent_all);
        #[cfg(feature = "telemetry")]
        let now = RldpStats::inc(&self.stats.transfers_sent_now);
        #[cfg(feature = "telemetry")]
        log::trace!(target: TARGET, "RLDP STAT send: transfers total {all}, active {now}");
        let (ping, pong) = tokio::sync::mpsc::unbounded_channel();
        let total_to_send = data.len();
        let send_transfer_id: TransferId = rand::thread_rng().gen();
        let (send_transfer, send_transfer_state) = SendTransfer::new(
            data,
            send_transfer_id.clone(),
            self.allocated.send_transfers.clone(),
            ping,
            v2,
        )?;
        #[cfg(feature = "telemetry")]
        self.telemetry.send_transfers.update(self.allocated.send_transfers.load(Ordering::Relaxed));
        peer.insert_transfer(
            &self.transfers,
            send_transfer_id,
            RldpTransfer::Send(send_transfer_state),
        )?;
        let (recv_context, recv_transfer_id) = if query_id.is_some() {
            let mut recv_transfer_id = send_transfer_id;
            for x in &mut recv_transfer_id {
                *x ^= 0xFF
            }
            let (queue_sender, queue_reader) = tokio::sync::mpsc::unbounded_channel();
            let expected_total_size = max_answer_size.map(|size| {
                if v2 {
                    // V2 limits the complete serialized response, including its
                    // envelope. A zero receive limit selects the default MTU.
                    usize::try_from(if size == 0 { rldp2::DEFAULT_MTU } else { size })
                        .unwrap_or(usize::MAX)
                } else {
                    (size as usize).saturating_add(Constraints::RLDP_ANSWER_TL_OVERHEAD)
                }
            });
            let recv_transfer = RecvTransfer::new(
                recv_transfer_id,
                self.allocated.recv_transfers.clone(),
                v2,
                expected_total_size,
                #[cfg(feature = "debug")]
                self.timestamp.clone(),
            );
            #[cfg(feature = "telemetry")]
            self.telemetry
                .recv_transfers
                .update(self.allocated.recv_transfers.load(Ordering::Relaxed));
            peer.insert_transfer(
                &self.transfers,
                recv_transfer_id,
                RldpTransfer::Recv(queue_sender),
            )?;
            let recv_context = RecvContext {
                adnl: self.adnl.clone(),
                peers: peers.clone(),
                queue_reader,
                recv_transfer,
                transfer_id: send_transfer_id,
                #[cfg(feature = "debug")]
                loss_fn: self.loss_fn,
            };
            log::trace!(
                target: TARGET,
                "outbound query: transfer id {}/{}, total to send {total_to_send}",
                base64_encode(&send_transfer_id),
                base64_encode(&recv_transfer_id),
            );
            (Some(recv_context), Some(recv_transfer_id))
        } else {
            log::trace!(
                target: TARGET,
                "outbound message: transfer id {}, total to send {total_to_send}",
                base64_encode(&send_transfer_id)
            );
            (None, None)
        };
        let registration = Arc::new(owned_send::SendRegistration {
            inbound: if v2 {
                recv_transfer_id.map(|id| (id, tokio_util::sync::CancellationToken::new()))
            } else {
                None
            },
            peer: Some((Arc::downgrade(&peer), peer.closed.clone())),
            transfers: self.transfers.clone(),
            send: send_transfer_id,
            receive: recv_transfer_id,
            owner: self.adnl.tasks().clone(),
            bounded_permit: retained_permit,
        });
        let send_context = SendContext {
            admission,
            registration: registration.clone(),
            control: control.clone(),
            permit: Some(permit.clone()),
            adnl: self.adnl.clone(),
            peers: peers.clone(),
            pong,
            send_transfer,
            #[cfg(feature = "debug")]
            timestamp: self.timestamp.clone(),
            transfer_id: send_transfer_id,
            #[cfg(feature = "telemetry")]
            tag,
        };
        #[cfg(feature = "debug")]
        self.check_time("Outbound begin");
        let outbound_started_at = std::time::Instant::now();
        log::debug!(
            target: TARGET,
            "outbound start: transfer {} to {}, query={}, total_to_send={total_to_send}",
            base64_encode(&send_transfer_id),
            peers.other(),
            query_id.is_some(),
        );
        let hard_deadline = tokio::time::Instant::now() + control.deadline();
        let deadline = query_deadline.map_or(hard_deadline, |query| query.min(hard_deadline));
        let res = match tokio::time::timeout_at(
            deadline,
            async {
                tokio::select! {
                    biased;
                    _ = peer.closed.cancelled() => {
                        control.cancel(SendCancelled::PeerEvicted);
                        Err(SendCancelled::PeerEvicted.into())
                    },
                    result = self.outbound_loop(send_context, recv_context, &send_transfer_id, v2, &peer, bounded) => result,
                }
            },
        )
        .await
        {
            Ok(res) => res,
            Err(_) => {
                control.cancel(SendCancelled::Deadline);
                log::warn!(
                    target: TARGET,
                    "outbound deadline after {} ms: transfer {} to {}, query={}, \
                     total_to_send={total_to_send}",
                    outbound_started_at.elapsed().as_millis(),
                    base64_encode(&send_transfer_id),
                    peers.other(),
                    query_id.is_some(),
                );
                if query_deadline.is_some_and(|query| query <= deadline) {
                    Err(RldpQueryTimeout.into())
                } else {
                    Err(SendCancelled::Deadline.into())
                }
            }
        };
        log::debug!(
            target: TARGET,
            "outbound end: transfer {} to {}, elapsed {} ms, ok={}",
            base64_encode(&send_transfer_id),
            peers.other(),
            outbound_started_at.elapsed().as_millis(),
            res.is_ok(),
        );
        // Actual sender/receiver descendants retain their registration. A caller
        // timeout only cancels them; it cannot release their IDs or permits.
        drop(registration);
        #[cfg(feature = "telemetry")]
        let all = self.stats.transfers_sent_all.load(Ordering::Relaxed);
        #[cfg(feature = "telemetry")]
        let now = RldpStats::dec(&self.stats.transfers_sent_now);
        #[cfg(feature = "telemetry")]
        log::trace!(target: TARGET, "RLDP STAT send: transfers total {all}, actual {now}");
        #[cfg(feature = "debug")]
        self.check_time("Outbound end");
        // _permit drops here, releasing the outbound slot.
        let answer = res?;
        if let Some(answer) = answer {
            let Some(query_id) = query_id else {
                fail!("Unexpected answer {answer:?} to RLDP message");
            };
            let decoded = match response_limits {
                Some(limits) => Ok(rtos_api::WireProfile::Legacy
                    .deserialize_value_bounded::<RldpMessageBoxed>(&answer, limits.wire_bytes)?),
                None => deserialize_boxed(&answer[..])?.downcast::<RldpMessageBoxed>(),
            };
            match decoded {
                Ok(RldpMessageBoxed::Rldp_Answer(answer)) => {
                    if answer.query_id.as_slice() != &query_id {
                        fail!("Unknown query ID in RLDP answer")
                    } else {
                        // Native RLDP2 checks the original payload limit even
                        // when a zero transport limit selected the default MTU.
                        if v2 {
                            if let Some(limit) = max_answer_size {
                                if answer.data.len() as u64 > limit {
                                    return Err(ResponseLimitExceeded {
                                        limit: usize::try_from(limit).unwrap_or(usize::MAX),
                                        actual: answer.data.len(),
                                    }
                                    .into());
                                }
                            }
                        }
                        let decompressed = match response_limits {
                            Some(limits) => DataCompression::decompress_raw_bounded(
                                &answer.data,
                                limits.decoded_bytes,
                            )?,
                            None => DataCompression::decompress_raw(&answer.data),
                        };
                        let data = match decompressed {
                            Some(data) => {
                                self.adnl.set_options(AdnlNode::OPTION_FORCE_COMPRESSION);
                                data
                            }
                            None => {
                                if let Some(limits) = response_limits {
                                    if answer.data.len() > limits.decoded_bytes {
                                        return Err(ResponseLimitExceeded {
                                            limit: limits.decoded_bytes,
                                            actual: answer.data.len(),
                                        }
                                        .into());
                                    }
                                }
                                answer.data.to_vec()
                            }
                        };
                        if let Some(limits) = response_limits {
                            if data.len() > limits.decoded_bytes {
                                return Err(ResponseLimitExceeded {
                                    limit: limits.decoded_bytes,
                                    actual: data.len(),
                                }
                                .into());
                            }
                        }
                        if data.len() >= 4 {
                            log::trace!(
                                target: TARGET,
                                "RLDP answer {:02x}{:02x}{:02x}{:02x}...",
                                data[0], data[1], data[2], data[3]
                            )
                        }
                        Ok((Some(data), peer.stats.v1.roundtrip()))
                    }
                }
                Ok(answer) => fail!("Unexpected answer to RLDP query: {:?}", answer),
                Err(answer) => fail!("Unexpected answer to RLDP query: {:?}", answer),
            }
        } else {
            Ok((None, peer.stats.v1.roundtrip()))
        }
    }

    async fn outbound_loop(
        &self,
        send_context: SendContext,
        recv_context: Option<RecvContext>,
        send_transfer_id: &TransferId,
        v2: bool,
        peer: &Arc<RldpPeer>,
        bounded: Option<BoundedReceive>,
    ) -> Result<Option<Vec<u8>>> {
        let transfer_str =
            Self::transfer_string(&send_context.transfer_id, &send_context.peers, "to");
        let propagate_failure = bounded.is_some();
        let recv_state = if let Some(mut recv_context) = recv_context {
            let (ping, pong) = tokio::sync::mpsc::unbounded_channel();
            let recv_state = recv_context.recv_transfer.state().clone();
            let registration = send_context.registration.clone();
            let permit = send_context.permit.clone();
            let control = send_context.control.clone();
            let token = if let Some(scope) = &bounded {
                scope.token.clone()
            } else {
                self.adnl.tasks().enter()?
            };
            self.adnl.tasks().spawn_admitted("RLDP outbound receiver", token, async move {
                let _registration = registration;
                let _permit = permit;
                Self::receive_loop_controlled(
                    &mut recv_context,
                    v2,
                    Some(&control),
                    v2 && !propagate_failure,
                )
                .await;
                _registration.finish_inbound();
                let _ = ping.send(recv_context.recv_transfer);
                if let Some(scope) = bounded {
                    let _ = scope.done.send(());
                }
            });
            Some((recv_state, pong))
        } else {
            None
        };
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        peer.tx
            .send(SendJob { ctx: send_context, send_id: *send_transfer_id, v2, done: done_tx })
            .map_err(|_| error!("Peer task is gone"))?;
        let ok = match done_rx.await {
            Ok(result) => result?,
            Err(_) => false,
        };
        #[cfg(feature = "debug")]
        self.check_time(if recv_state.is_some() {
            "Outbound sent, wait reply"
        } else {
            "Outbound sent"
        });
        peer.insert_transfer(&self.transfers, *send_transfer_id, RldpTransfer::Done)?;
        let outbound_str = if recv_state.is_some() { "outbound query" } else { "outbound message" };
        if ok {
            log::trace!(target: TARGET, "RLDP {outbound_str} sent in transfer {transfer_str}");
        } else {
            log::warn!(
                target: TARGET,
                "Timeout >{} ms on {outbound_str} in RLDP transfer {transfer_str}",
                peer.stats.v1.timeout()
            );
            return Ok(None);
        }
        let Some((recv_state, mut pong)) = recv_state else {
            return Ok(None);
        };
        self.wait_answer(peer, &transfer_str, recv_state, &mut pong, propagate_failure, v2).await
    }

    async fn wait_answer(
        &self,
        peer: &Arc<RldpPeer>,
        transfer_str: &str,
        recv_state: Arc<RecvTransferState>,
        recv_pong: &mut tokio::sync::mpsc::UnboundedReceiver<RecvTransfer>,
        propagate_failure: bool,
        v2: bool,
    ) -> Result<Option<Vec<u8>>> {
        let start_ms = peer.stats.v1.timestamp_ms();
        let mut last_warn_ms = start_ms;
        let mut last_diag_ms = start_ms;
        let mut updates = recv_state.updates();
        loop {
            match tokio::time::timeout(Duration::from_millis(Self::SPINNER_MS), recv_pong.recv())
                .await
            {
                Ok(Some(reply)) => {
                    log::trace!(target: TARGET, "Got reply in {transfer_str}");
                    peer.stats.v1.update(self.min_timeout_ms);
                    if let Some(error) = reply.failure {
                        if propagate_failure {
                            return Err(error);
                        }
                        if v2 {
                            // A rejected transfer has no complete answer to decode.
                            return Ok(None);
                        }
                    }
                    return Ok(Some(reply.data));
                }
                Ok(None) => {
                    log::warn!(target: TARGET, "Error in RLDP transfer {transfer_str}");
                    break;
                }
                Err(_) => (),
            }
            let new_updates = recv_state.updates();
            if new_updates > updates {
                log::trace!(
                    target: TARGET,
                    "Recv updates {updates} -> {new_updates} in {transfer_str}"
                );
                let timestamp_ms = peer.stats.v1.timestamp_ms();
                let elapsed_ms = timestamp_ms - start_ms;
                let timeout = peer.stats.v1.timeout();
                if (timeout > 0)
                    && (elapsed_ms / timeout > 10)
                    && (timestamp_ms - last_diag_ms > Self::TIMEOUT_WARN_MS)
                {
                    log::warn!(
                        target: TARGET,
                        "RLDP query recv {transfer_str} masked timeout: \
                         elapsed {elapsed_ms} ms > 10*{timeout} ms, updates {new_updates}"
                    );
                    last_diag_ms = timestamp_ms;
                }
                peer.stats.v1.update(self.min_timeout_ms);
                updates = new_updates;
            } else if !v2 && peer.stats.v1.try_timeout(start_ms) {
                log::warn!(
                    target: TARGET,
                    "Weak activity in RLDP {transfer_str} last {} ms, aborting",
                    peer.stats.v1.timeout()
                );
                break;
            }
            Self::check_too_long_transfer(
                start_ms,
                &mut last_warn_ms,
                peer.stats.v1.timestamp_ms(),
                &transfer_str,
                "RLDP query recv",
            );
        }
        Ok(None)
    }

    #[cfg(test)]
    pub(crate) fn inbound_cap_leases_for_test(&self, peer: &Arc<KeyId>) -> i32 {
        self.extended_caps.get(peer).map_or(0, |cap| cap.val().load(Ordering::Acquire))
    }

    fn peer_inbound_cap(&self, peer: &Arc<KeyId>) -> usize {
        if let Some(cap) = self.extended_caps.get(peer) {
            if cap.val().load(Ordering::Relaxed) > 0 {
                return Constraints::MAX_TOTAL_TRANSFER_SIZE;
            }
        }
        Constraints::DEFAULT_INBOUND_TRANSFER_SIZE
    }

    #[cfg(feature = "telemetry")]
    fn print_stats(&self) {}

    async fn receive_loop(context: &mut RecvContext, v2: bool) {
        Self::receive_loop_controlled(context, v2, None, false).await;
    }

    async fn receive_loop_controlled(
        context: &mut RecvContext,
        v2: bool,
        control: Option<&Arc<SendControl>>,
        discard_oversize: bool,
    ) {
        let transfer_str = Self::transfer_string(&context.transfer_id, &context.peers, "from");
        let rldp = if v2 { "RLDPv2" } else { "RLDPv1" };
        let spin = Duration::from_millis(Self::ACK_DELAY_MS);
        let start = std::time::Instant::now();
        let mut last_diag = start;
        let mut packets_received: u32 = 0;
        let mut confirmations_sent: u32 = 0;
        loop {
            if context.adnl.tasks().is_closed() || control.is_some_and(|c| c.check().is_err()) {
                break;
            }
            if (start.elapsed() > Duration::from_millis(Self::TIMEOUT_MAX_MS))
                && (last_diag.elapsed() > Duration::from_millis(Self::TIMEOUT_WARN_MS))
            {
                let received = context.recv_transfer.data.len();
                let total = context.recv_transfer.total_size.unwrap_or(0);
                log::warn!(
                    target: TARGET,
                    "{rldp} receive_loop {transfer_str} running {} ms, {received}/{total} bytes, \
                    packets_received={packets_received}, confirmations_sent={confirmations_sent}",
                    start.elapsed().as_millis()
                );
                last_diag = std::time::Instant::now();
            }
            let job = match tokio::time::timeout(spin, context.queue_reader.recv()).await {
                Ok(Some(job)) => job,
                Ok(None) => break,
                Err(_) => {
                    if v2 {
                        match context.send_confirmations().await {
                            Ok(sent) => {
                                confirmations_sent = confirmations_sent.saturating_add(sent)
                            }
                            Err(e) => log::warn!(target: TARGET, "{rldp} confirmation error: {e}"),
                        }
                    }
                    continue;
                }
            };
            packets_received = packets_received.saturating_add(1);
            let (chunk_v2, chunk_part, chunk_seqno, chunk_data_len) = match &job {
                Chunk::V1(RldpMessagePart(c)) => (false, c.part, c.seqno, c.data.len()),
                Chunk::V2(Rldp2MessagePart(c)) => (true, c.part, c.seqno, c.data.len()),
            };
            log::debug!(
                target: TARGET,
                "{rldp} packet {transfer_str} part={chunk_part} seqno={chunk_seqno} \
                data_len={chunk_data_len} v2={chunk_v2} \
                (#{packets_received} in transfer)"
            );
            #[cfg(feature = "debug")]
            if context.loss_fn.map_or(false, |loss_fn| loss_fn(&job)) {
                continue;
            }
            match context.recv_transfer.process_chunk(job) {
                Err(e) => {
                    if discard_oversize && e.downcast_ref::<ResponseLimitExceeded>().is_some() {
                        // Invalid response parts do not complete a query. Its
                        // absolute deadline remains in charge of completion.
                        continue;
                    }
                    log::warn!(
                        target: TARGET,
                        "{rldp} error in {transfer_str}: {e}, dropping transfer"
                    );
                    context.recv_transfer.failure = Some(e);
                    break;
                }
                Ok(reply) => {
                    if let Some(reply) = reply {
                        if let Err(e) = context.adnl.send_custom(&reply, &context.peers).await {
                            log::warn!(target: TARGET, "{rldp} reply error: {e}")
                        }
                    }
                }
            }
            context.recv_transfer.state().set_updates();
            if let Some(total_size) = context.recv_transfer.total_size {
                if total_size == context.recv_transfer.data.len() {
                    log::trace!(
                        target: TARGET,
                        "{transfer_str}, receive completed ({total_size} bytes)"
                    );
                    #[cfg(feature = "debug")]
                    Self::check_timestamp(
                        &context.recv_transfer.timestamp,
                        format!(
                            "Recv transfer finished, {} data packets, {} confirm packets",
                            context.recv_transfer.total_data_packets,
                            context.recv_transfer.total_confirm_packets
                        )
                        .as_str(),
                    );
                    break;
                }
            } else {
                log::warn!("INTERNAL ERROR: {rldp} total size not set")
            }
        }
        // Graceful close
        context.queue_reader.close();
        while context.queue_reader.recv().await.is_some() {}
    }

    async fn send_loop_v1(
        mut context: SendContext,
        peer: &Arc<RldpPeer>,
        min_timeout_ms: u64,
        fec_slots: Arc<tokio::sync::Semaphore>,
    ) -> Result<bool> {
        let transfer_str = Self::transfer_string(&context.transfer_id, &context.peers, "to");
        let SendTransfer::V1(mut transfer) = context.send_transfer else {
            fail!("Unexpected V2 send transfer in V1 send loop")
        };
        let start_ms = peer.stats.v1.timestamp_ms();
        let mut last_warn_ms = start_ms;
        let mut last_diag_ms = start_ms;
        #[cfg(feature = "debug")]
        let mut last_seqno = 0;
        #[cfg(any(feature = "debug", feature = "telemetry"))]
        let mut total_packets: u32 = 0;
        loop {
            if context.adnl.tasks().is_closed() {
                context.control.cancel(SendCancelled::OwnerClosed);
            }
            context.control.check()?;
            let (returned, mut transfer_wave) = owned_send::fec_limited(
                transfer,
                context.control.clone(),
                context.adnl.tasks().clone(),
                fec_slots.clone(),
                |part| part.start_next_part(),
            )
            .await?;
            transfer = returned;
            context.control.check()?;
            if transfer_wave == 0 {
                #[cfg(feature = "debug")]
                Self::check_timestamp(
                    &context.timestamp,
                    format!("Send transfer finished, packets {total_packets}").as_str(),
                );
                break;
            }
            transfer_wave = min(transfer_wave, Self::SIZE_TRANSFER_WAVE);
            let part = transfer.state().part();
            let mut recv_seqno = 0;
            'part: loop {
                for _ in 0..transfer_wave {
                    #[cfg(any(feature = "debug", feature = "telemetry"))]
                    {
                        total_packets += 1;
                    }
                    #[cfg(feature = "debug")]
                    {
                        last_seqno = transfer.state().seqno_send()
                    }
                    context.control.check()?;
                    let (returned, (object, do_next)) = owned_send::fec_limited(
                        transfer,
                        context.control.clone(),
                        context.adnl.tasks().clone(),
                        fec_slots.clone(),
                        |part| {
                            let (bytes, next) = part.prepare_chunk()?;
                            Ok((bytes.to_vec(), next))
                        },
                    )
                    .await?;
                    transfer = returned;
                    if context.adnl.tasks().is_closed() {
                        context.control.cancel(SendCancelled::OwnerClosed);
                    }
                    context.control.check()?;
                    let chunk = TaggedByteSlice {
                        object: &object,
                        #[cfg(feature = "telemetry")]
                        tag: context.tag,
                    };
                    context.adnl.send_custom(&chunk, &context.peers).await?;
                    if !do_next {
                        #[cfg(feature = "debug")]
                        Self::check_timestamp(
                            &context.timestamp,
                            format!("Part {} transfer suspended, seqno {}", part, last_seqno)
                                .as_str(),
                        );
                        break 'part;
                    }
                    if transfer.state().is_transfer_finished_or_next_part(part)? {
                        #[cfg(feature = "debug")]
                        Self::check_timestamp(
                            &context.timestamp,
                            format!(
                                "Part {} transfer finished in progress, seqno {}",
                                part, last_seqno
                            )
                            .as_str(),
                        );
                        break 'part;
                    }
                }
                tokio::select! {
                    _ = context.control.cancelled() => { context.control.check()?; unreachable!() },
                    _ = context.adnl.tasks().cancelled() => return Err(SendCancelled::OwnerClosed.into()),
                    _ = tokio::time::timeout(Duration::from_millis(Self::SPINNER_V1_SEND_MS), context.pong.recv()) => {},
                }
                if transfer.state().is_transfer_finished_or_next_part(part)? {
                    #[cfg(feature = "debug")]
                    Self::check_timestamp(
                        &context.timestamp,
                        format!("Part {} transfer finished after wait, seqno {}", part, last_seqno)
                            .as_str(),
                    );
                    break;
                }
                let new_recv_seqno = transfer.state().seqno_recv();
                if new_recv_seqno > recv_seqno {
                    log::trace!(
                        target: TARGET,
                        "Send part {} updates {} -> {} in {}",
                        part, recv_seqno, new_recv_seqno, transfer_str
                    );
                    Self::check_too_long_transfer(
                        start_ms,
                        &mut last_warn_ms,
                        peer.stats.v1.timestamp_ms(),
                        &transfer_str,
                        "RLDPv1 send",
                    );
                    let timestamp_ms = peer.stats.v1.timestamp_ms();
                    let elapsed_ms = timestamp_ms - start_ms;
                    let timeout = peer.stats.v1.timeout();
                    if (timeout > 0)
                        && (elapsed_ms / timeout > 10)
                        && (timestamp_ms - last_diag_ms > Self::TIMEOUT_WARN_MS)
                    {
                        log::warn!(
                            target: TARGET,
                            "RLDPv1 send {transfer_str} masked timeout: \
                             elapsed {elapsed_ms} ms > 10*{timeout} ms, recv_seqno {new_recv_seqno}"
                        );
                        last_diag_ms = timestamp_ms;
                    }
                    peer.stats.v1.update(min_timeout_ms);
                    recv_seqno = new_recv_seqno;
                } else if peer.stats.v1.try_timeout(start_ms) {
                    #[cfg(feature = "telemetry")]
                    log::info!(
                        target: TARGET,
                        "RLDPv1 send: packets sent {total_packets} (timeout) in {transfer_str}"
                    );
                    return Ok(false);
                }
            }
            peer.stats.v1.update(min_timeout_ms);
        }
        #[cfg(feature = "telemetry")]
        log::info!(target: TARGET, "RLDPv1 send: packets sent {total_packets} in {transfer_str}");
        Ok(true)
    }

    async fn send_loop_v2(
        mut context: SendContext,
        transfer_state: Arc<Vec<Arc<SendPartStateV2>>>,
        peer: &Arc<RldpPeer>,
        pool: &Arc<SendWorkerPool>,
        min_timeout_ms: u64,
    ) -> Result<bool> {
        let transfer_str = Self::transfer_string(&context.transfer_id, &context.peers, "to");
        let SendTransfer::V2(part_transfers) = &mut context.send_transfer else {
            fail!("Unexpected V1 send transfer in V2 send loop")
        };
        #[cfg(any(feature = "debug", feature = "telemetry"))]
        let total_packets = Arc::new(AtomicU32::new(0));
        let progress = Arc::new(AtomicU64::new(0));
        peer.stats.bbr_step()?;
        let start_ms = peer.stats.v1.timestamp_ms();
        let control = context.control.clone();
        let owner = context.adnl.tasks().clone();
        let mut pending = futures::stream::FuturesUnordered::new();
        let mut failure: Option<Result<bool>> = None;
        loop {
            if owner.is_closed() {
                control.cancel(SendCancelled::OwnerClosed);
            }
            if failure.is_none() {
                if let Err(error) = control.check() {
                    failure = Some(Err(error));
                }
            }
            while failure.is_none()
                && pending.len() < Constraints::MAX_PARTS_IN_TRANSIT
                && !part_transfers.is_empty()
            {
                let transfer = part_transfers.remove(0);
                let part_context = SendPartContextV2 {
                    fec_slots: pool.fec_slots(),
                    adnl: context.adnl.clone(),
                    part_states: transfer_state.clone(),
                    peer: peer.clone(),
                    peers: context.peers.clone(),
                    progress: progress.clone(),
                    #[cfg(feature = "telemetry")]
                    tag: context.tag,
                    #[cfg(feature = "debug")]
                    timestamp: context.timestamp.clone(),
                    #[cfg(any(feature = "debug", feature = "telemetry"))]
                    total_packets: total_packets.clone(),
                    transfer_str: transfer_str.clone(),
                };
                let child_control = control.clone();
                let permit = context.permit.clone();
                match pool.submit_v2(control.clone(), async move {
                    let _permit = permit;
                    Self::send_one_part_v2(
                        transfer,
                        &part_context,
                        start_ms,
                        min_timeout_ms,
                        child_control,
                    )
                    .await
                }) {
                    Ok(receipt) => pending.push(receipt),
                    Err(error) => {
                        let mut result = Err(error);
                        control.record_failure(&mut result);
                        failure = Some(result);
                    }
                }
            }
            if pending.is_empty() {
                break;
            }
            tokio::select! {
                result = pending.next() => {
                    let result = result.expect("nonempty part set")
                        .unwrap_or_else(|_| Err(error!("RLDP part owner lost its receipt")));
                    if !matches!(result, Ok(true)) && failure.is_none() {
                        failure = Some(result);
                        control.cancel(SendCancelled::SiblingFailed);
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(Self::SPINNER_MS)) => {}
            }
            if failure.is_none() {
                let step = peer.stats.bbr_step();
                #[cfg(test)]
                let step = if control.test_bbr_error.swap(false, Ordering::AcqRel) {
                    Err(error!("controlled BBR step error"))
                } else {
                    step
                };
                if let Err(error) = step {
                    let mut result = Err(error);
                    control.record_failure(&mut result);
                    failure = Some(result);
                }
            }
        }
        let ok = control.take_failure().or(failure).unwrap_or(Ok(true))?;
        #[cfg(feature = "telemetry")]
        log::info!(
            target: TARGET,
            "RLDPv2 send: packets sent {} ({}) in {transfer_str}",
            total_packets.load(Ordering::Relaxed),
            if ok { "ok" } else { "timeout" }
        );
        Ok(ok)
    }

    async fn send_one_part_v2(
        transfer: SendPartV2,
        context: &SendPartContextV2,
        start_ms: u64,
        min_timeout_ms: u64,
        control: Arc<SendControl>,
    ) -> Result<bool> {
        control.check()?;
        let transfer = OwnedSendPart { part: transfer, peer: context.peer.clone() };
        #[cfg(test)]
        let hook = control.test_after_start.lock().unwrap().clone();
        let (mut transfer, early) = owned_send::fec_limited(
            transfer,
            control.clone(),
            context.adnl.tasks().clone(),
            context.fec_slots.clone(),
            move |part| {
                part.start()?;
                #[cfg(test)]
                if let Some(hook) = hook {
                    return hook(part.state().part());
                }
                Ok(None::<bool>)
            },
        )
        .await?;
        if let Some(result) = early {
            return Ok(result);
        }
        let part = transfer.state().part();
        let on_ack = |transfer: &mut SendPartV2, ack| -> Result<u32> {
            transfer.on_ack_and_wake(
                ack,
                &context.peer,
                min_timeout_ms,
                &context.part_states,
                &context.progress,
            )
        };
        let mut updates = 0;
        let mut new_received = 0;
        let mut last_warn_ms = context.peer.stats.v1.timestamp_ms();
        let mut last_diag_ms = last_warn_ms;
        let ok = loop {
            if context.adnl.tasks().is_closed() {
                control.cancel(SendCancelled::OwnerClosed);
            }
            control.check()?;
            if let Some(ok) = transfer.state().is_finished() {
                break ok;
            }
            // Heartbeat: fires regardless of which iteration branch we take below,
            // so silent-peer transfers (where `new_received == 0` always) still emit
            // evidence that the loop is iterating past the elapsed-timeout horizon.
            {
                let timestamp_ms = context.peer.stats.v1.timestamp_ms();
                let elapsed_ms = timestamp_ms - start_ms;
                let timeout = context.peer.stats.v1.timeout();
                if (timeout > 0)
                    && (elapsed_ms / timeout > 10)
                    && (timestamp_ms - last_diag_ms > Self::TIMEOUT_WARN_MS)
                {
                    log::warn!(
                        target: TARGET,
                        "RLDPv2 send_one_part_v2 {} part {part} stuck: \
                         elapsed {elapsed_ms} ms > 10*{timeout} ms, \
                         updates {updates}, new_received {new_received}",
                        context.transfer_str
                    );
                    last_diag_ms = timestamp_ms;
                }
            }
            if new_received > 0 {
                log::trace!(
                    target: TARGET,
                    "Send part {} updates {} -> {} in {}",
                    part, updates, updates + new_received, context.transfer_str
                );
                Self::check_too_long_transfer(
                    start_ms,
                    &mut last_warn_ms,
                    context.peer.stats.v1.timestamp_ms(),
                    &context.transfer_str,
                    "RLDPv2 send",
                );
                context.peer.stats.v1.update(min_timeout_ms);
                updates += new_received
            } else if control.protocol_deadline.is_none()
                && context.peer.stats.v1.try_timeout(start_ms)
            {
                transfer.state().set_finished(false);
                continue;
            }
            new_received = 0;
            let peer = context.peer.clone();
            let (returned, prepared) = owned_send::fec_limited(
                transfer,
                control.clone(),
                context.adnl.tasks().clone(),
                context.fec_slots.clone(),
                move |part| {
                    Ok(match part.prepare_chunk(&peer)? {
                        SendActionV2::Send((bytes, info)) => Ok((bytes.to_vec(), info)),
                        SendActionV2::Wait(delay) => Err(delay),
                    })
                },
            )
            .await?;
            transfer = returned;
            control.check()?;
            let (object, is_probe) = match prepared {
                Ok(packet) => packet,
                Err(timeout_micros) => {
                    #[cfg(feature = "debug")]
                    Self::check_timestamp(
                        &context.timestamp,
                        format!(
                            "Part {} suspended on {} micros, seqno {}",
                            part,
                            timeout_micros,
                            transfer.state().seqno_send()
                        )
                        .as_str(),
                    );
                    let received = tokio::select! {
                        _ = control.cancelled() => { control.check()?; unreachable!() },
                        _ = context.adnl.tasks().cancelled() => return Err(SendCancelled::OwnerClosed.into()),
                        received = tokio::time::timeout(Duration::from_micros(timeout_micros), transfer.ack_pong.recv()) => received,
                    };
                    if let Ok(Some(Some(ack))) = received {
                        new_received = on_ack(&mut transfer, ack)?;
                    }
                    continue;
                }
            };
            #[cfg(any(feature = "debug", feature = "telemetry"))]
            context.total_packets.fetch_add(1, Ordering::Relaxed);
            let chunk = TaggedByteSlice {
                object: &object,
                #[cfg(feature = "telemetry")]
                tag: context.tag,
            };
            let sent_at_micros = context.peer.stats.timestamp_micros();
            context.adnl.send_custom(&chunk, &context.peers).await?;
            transfer.on_send(is_probe, sent_at_micros, &context.peer)?;
            if let Ok(Some(ack)) = transfer.ack_pong.try_recv() {
                new_received = on_ack(&mut transfer, ack)?
            }
        };
        #[cfg(feature = "debug")]
        Self::check_timestamp(
            &context.timestamp,
            format!(
                "Part {} finished {} in progress, seqno {}",
                part,
                if ok { "ok" } else { "with failure" },
                transfer.state().seqno_send()
            )
            .as_str(),
        );
        Ok(ok)
    }

    fn transfer_string(transfer_id: &TransferId, peers: &AdnlPeers, dir: &str) -> String {
        format!("transfer {} {dir} {}", base64_encode(transfer_id), peers.other())
    }
}

#[async_trait::async_trait]
impl Subscriber for RldpNode {
    #[cfg(feature = "telemetry")]
    async fn poll(&self, start: &Arc<Instant>) {
        if ((start.elapsed().as_secs() + 1) % Self::TIMEOUT_TELEMETRY_SEC) == 0 {
            self.print_stats()
        }
        self.telemetry.peers.update(self.allocated.peers.load(Ordering::Relaxed));
        self.telemetry.recv_transfers.update(self.allocated.recv_transfers.load(Ordering::Relaxed));
        self.telemetry.send_transfers.update(self.allocated.send_transfers.load(Ordering::Relaxed));
    }

    async fn try_consume_custom(&self, data: &[u8], peers: &AdnlPeers) -> Result<bool> {
        if let Some(local_id) = &self.local_id {
            if peers.local() != local_id {
                return Ok(false);
            }
        }
        let msg = if let Ok(msg) = deserialize_boxed(data) { msg } else { return Ok(false) };
        let msg = match msg.downcast::<RldpMessagePartBoxed>() {
            Ok(msg) => return self.consume_message_part(MessagePart::V1(msg), peers).await,
            Err(msg) => msg,
        };
        match msg.downcast::<Rldp2MessagePartBoxed>() {
            Ok(msg) => self.consume_message_part(MessagePart::V2(msg), peers).await,
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod lifetime_tests;
