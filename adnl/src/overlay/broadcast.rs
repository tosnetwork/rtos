/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::{
    common::{
        add_unbound_object_to_map, hash, AdnlPeers, CountedObject, Counter, TaggedByteSlice,
        UpdatedAt,
    },
    declare_counted,
    node::PeerHistory,
    overlay::{
        privacy::{
            BroadcastCheckResult, OverlayCertificate as SourceCertificate,
            BROADCAST_FLAG_ANY_SENDER, BROADCAST_FLAG_FIXED_NEIGHBOURS, MAX_FEC_BROADCAST_SIZE,
        },
        Overlay, OverlayNode, OverlayType, TARGET, TARGET_BROADCAST,
    },
    rldp::{RaptorqDecoder, RaptorqEncoder},
};
#[cfg(feature = "telemetry")]
use rtos_api::Constructor;
use rtos_api::{
    serialize_bare, serialize_boxed,
    ton::{
        fec::{type_::RaptorQ as FecTypeRaptorQ, Type as FecType},
        overlay::{
            broadcast::{
                id::Id as BroadcastSimpleId, tosign::ToSign as BroadcastToSign,
                Broadcast as BroadcastSimple, BroadcastFec, BroadcastStream, BroadcastTwostepFec,
                BroadcastTwostepSimple,
            },
            broadcast_fec::{id::Id as BroadcastFecId, partid::PartId as BroadcastFecPartId},
            broadcast_twostep::id::Id as BroadcastTwostepId,
            broadcast_twostep_fec::tosign::ToSign as BroadcastTwostepFecToSign,
            broadcast_twostep_simple::tosign::ToSign as BroadcastTwostepSimpleToSign,
            Broadcast, Certificate as OverlayCertificate,
        },
    },
    IntoBoxed,
};
#[cfg(test)]
use crate::common::Version;
use rtos_block::{base64_encode, error, fail, sha256_digest, KeyId, KeyOption, Result, UInt256};
#[cfg(feature = "telemetry")]
use std::sync::atomic::AtomicU32;
use std::{
    collections::HashSet,
    fmt::{Display, Formatter},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

/// Half-width of the accepted broadcast date window (C++ `OverlayImpl::check_date`).
pub(crate) const BROADCAST_DATE_WINDOW_SEC: f64 = 20.0;

/// C++ `OverlayImpl::check_date`: the wire date is read as an unsigned 32-bit value
/// and compared with the fractional system clock; a broadcast dated more than 20 s
/// before or after `now` is dropped without delivery or relay.
pub(crate) fn broadcast_date_admissible(date: i32, now: f64) -> bool {
    let date = f64::from(date as u32);
    !(date < now - BROADCAST_DATE_WINDOW_SEC) && !(date > now + BROADCAST_DATE_WINDOW_SEC)
}

pub(crate) struct BroadcastCheckInfo {
    bcast_id: BroadcastId,
    dup: bool,
    // Source verdict of protocols that decide it once per broadcast
    verdict: BroadcastCheckResult,
    data_len: usize,
    seqno: u32,
    #[cfg(feature = "telemetry")]
    maybe_tag: Option<u32>,
}

pub(crate) enum BroadcastData<'a> {
    Buf(Vec<u8>),
    None,
    Raw(&'a [u8]),
    // Re-serialized broadcast without the hops postfix
    Rebuilt(Vec<u8>),
    Stream(Option<BroadcastStream>),
}

pub(crate) type BroadcastId = [u8; 32];

pub(crate) enum BroadcastJob {
    Background(u32),
    Foreground(Broadcast),
}

pub(crate) struct BroadcastNeighbours {
    expected_count: u32,
    hops: Option<u8>,
    ids: Option<Vec<Arc<KeyId>>>,
}

impl BroadcastNeighbours {
    fn get_ids(&mut self) -> Option<&mut Vec<Arc<KeyId>>> {
        self.ids.as_mut().and_then(|ids| if ids.is_empty() { None } else { Some(ids) })
    }
    fn skip(&mut self, skip: Option<&Arc<KeyId>>) {
        if let Some(ids) = &mut self.ids {
            if let Some(skip) = skip {
                ids.retain(|id| id != skip);
            }
        }
    }
}

pub struct BroadcastRecvInfo {
    pub packets: u32,
    pub data: Vec<u8>,
    pub extra: Option<Vec<u8>>,
    pub recv_from: Arc<KeyId>,
}

#[derive(Debug, Default)]
pub struct BroadcastSendInfo {
    pub packets: u32,
    pub send_to: u32,
}

pub(crate) struct BroadcastRecvContext<'a> {
    pub(crate) data: BroadcastData<'a>,
    pub(crate) hops: Option<u8>,
    pub(crate) overlay: &'a Arc<Overlay>,
    pub(crate) peers: &'a AdnlPeers,
    pub(crate) verdict: BroadcastCheckResult,
}

pub(crate) struct BroadcastSendContext<'a> {
    // Source certificate attached to every carrier and part
    pub(crate) certificate: OverlayCertificate,
    pub(crate) data: &'a TaggedByteSlice<'a>,
    pub(crate) flags: u32,
    pub(crate) overlay: &'a Arc<Overlay>,
    pub(crate) src_key: &'a Arc<dyn KeyOption>,
    pub(crate) src_adnl_key_id: &'a Arc<KeyId>,
}

pub(crate) enum BroadcastSendMethod {
    Fast,
    QuicOrRldp,
    Safe,
}

impl Display for BroadcastSendMethod {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let msg = match self {
            Self::Fast => "datagram ADNL",
            Self::QuicOrRldp => "QUIC/RLDP",
            Self::Safe => "stream ADNL",
        };
        write!(f, "{msg}")
    }
}

#[derive(Clone, PartialEq)]
pub(crate) enum BroadcastType {
    Fec,
    Simple,
    StreamSimple,
    TwostepFec,
    TwostepSimple,
}

impl Display for BroadcastType {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let msg = match self {
            Self::Fec => "datagram FEC",
            Self::Simple => "datagram simple",
            Self::StreamSimple => "stream simple",
            Self::TwostepFec => "two-step datagram FEC",
            Self::TwostepSimple => "two-step datagram simple",
        };
        write!(f, "{msg}")
    }
}

pub(crate) enum OwnedBroadcast {
    Send,
    RecvFec(RecvTransferFec<BroadcastFec>),
    RecvTwostepFec(RecvTransferFec<BroadcastTwostepFec>),
    WillBeRecv(BroadcastType),
}

/// Parts of one ordinary FEC broadcast that wait for its application check.
const MAX_HELD_PARTS: usize = 4096;

struct HeldPart {
    buf: Vec<u8>,
    seqno: u32,
    count: u32,
    local: Arc<KeyId>,
    skip: Arc<KeyId>,
}

#[derive(Default)]
struct FecRelayState {
    // The application check approved the broadcast
    checked: bool,
    // The application check refused the broadcast
    refused: bool,
    held: Vec<HeldPart>,
    fixed_neighbours: Option<Vec<Arc<KeyId>>>,
}

declare_counted!(
    pub(crate) struct RecvTransferFec<T> {
        accepted_parts: Mutex<HashSet<u32>>,
        completed: AtomicBool,
        data_hash: [u8; 32],
        history: PeerHistory,
        relay: Mutex<FecRelayState>,
        sender: tokio::sync::mpsc::UnboundedSender<Option<(T, bool)>>,
        src_key_id: Arc<KeyId>,
        #[cfg(feature = "telemetry")]
        telemetry: RecvTransferFecTelemetry,
        updated_at: UpdatedAt,
    }
);

#[cfg(feature = "telemetry")]
impl<T> RecvTransferFec<T> {
    pub(crate) fn get_telemetry_tag_and_len(&self) -> Option<(u32, u32)> {
        if self.updated_at.is_expired(5) {
            return None;
        }
        let mut tag = self.telemetry.tag.load(Ordering::Relaxed);
        let flags = self.telemetry.flags.load(Ordering::Relaxed);
        if (flags & RecvTransferFecTelemetry::FLAG_RECEIVED) == 0 {
            tag |= flags;
        }
        Some((tag, self.telemetry.len.load(Ordering::Relaxed)))
    }
}

#[cfg(feature = "telemetry")]
struct RecvTransferFecTelemetry {
    flags: AtomicU32,
    len: AtomicU32,
    tag: AtomicU32,
}

#[cfg(feature = "telemetry")]
impl RecvTransferFecTelemetry {
    const FLAG_RECEIVE_STARTED: u32 = 0x01;
    const FLAG_RECEIVED: u32 = 0x02;
    const FLAG_FAILED: u32 = 0x04;
}

declare_counted!(
    struct SendTransferFec {
        bcast_id: BroadcastId,
        certificate: OverlayCertificate,
        data_hash: [u8; 32],
        date: i32,
        encoder: RaptorqEncoder,
        extra: Vec<u8>,
        flags: u32,
        seqno: u32,
        src_key: Arc<dyn KeyOption>,
        src_adnl_key_id: Arc<KeyId>,
    }
);

// Broadcast traits ***********************************************************

pub(crate) trait BroadcastParsed {
    fn certificate(&self) -> &OverlayCertificate;
    fn date(&self) -> i32;
    fn src_key(&self) -> Result<Arc<dyn KeyOption>>;
    #[cfg(feature = "telemetry")]
    fn default_tag(&self) -> u32;
    #[cfg(feature = "xp25")]
    fn flags(&self) -> u32;
}

#[async_trait::async_trait]
pub(crate) trait BroadcastProtocol<T: BroadcastParsed + Send + 'static>:
    Send + Sync
{
    // Common

    fn broadcast_type() -> BroadcastType;
    fn calc_broadcast_neighbours(
        &self,
        overlay: &Arc<Overlay>,
        hops: Option<u8>,
    ) -> Result<BroadcastNeighbours>;
    fn select_broadcast_neighbours(
        &self,
        overlay: &Arc<Overlay>,
        neighbours: &mut BroadcastNeighbours,
        skip: Option<&Arc<KeyId>>,
    );
    fn send_method(&self) -> BroadcastSendMethod;

    fn calc_broadcast_timeout(#[cfg(feature = "xp25")] flags: u32) -> u64 {
        #[cfg(feature = "xp25")]
        if (flags & OverlayNode::FLAG_BCAST_REPEATED) != 0 {
            return Overlay::TIMEOUT_REPEATED_BROADCAST_SEC;
        }
        Overlay::TIMEOUT_ONE_TIME_BROADCAST_SEC
    }

    async fn distribute_broadcast(
        overlay: &Arc<Overlay>,
        bcast: &[u8],
        bcast_id: &BroadcastId,
        seqno: u32,
        neighbours: &[Arc<KeyId>],
        src_adnl_key_id: &Arc<KeyId>,
        send_method: &BroadcastSendMethod,
        #[cfg(feature = "telemetry")] tag: u32,
    ) -> Result<()> {
        overlay
            .distribute_broadcast(
                &TaggedByteSlice {
                    object: bcast,
                    #[cfg(feature = "telemetry")]
                    tag,
                },
                bcast_id,
                seqno,
                src_adnl_key_id,
                neighbours,
                send_method,
            )
            .await
    }

    // Receive side

    fn check_broadcast(&self, bcast: &T, ctx: &BroadcastRecvContext) -> Result<BroadcastCheckInfo>;
    async fn process_broadcast(
        &self,
        bcast: T,
        ctx: &mut BroadcastRecvContext,
        bcast_id: &BroadcastId,
    ) -> Result<(Option<BroadcastRecvInfo>, bool)>;

    fn build_rebroadcast(
        &self,
        ctx: &mut BroadcastRecvContext,
        neighbours: &mut BroadcastNeighbours,
    ) -> Result<()> {
        // Transit broadcasts will be traced untagged
        if let BroadcastData::Rebuilt(rebuilt) = &mut ctx.data {
            let mut buf = std::mem::take(rebuilt);
            if let Some(hops) = neighbours.hops.or(ctx.hops) {
                buf.push(hops);
            }
            ctx.data = BroadcastData::Buf(buf);
        } else if let Some(hops) = &neighbours.hops {
            let BroadcastData::Raw(raw_data) = &ctx.data else {
                fail!("INTERNAL ERROR: unexpected broadcast data type for rebroadcast");
            };
            let mut len = raw_data.len();
            if ctx.hops.is_none() {
                // Initial broadcast didn't count hops
                len += 1;
            }
            let mut buf = Vec::with_capacity(len);
            buf.extend_from_slice(raw_data);
            if ctx.hops.is_some() {
                buf[len - 1] = *hops;
            } else {
                buf.push(*hops);
            }
            ctx.data = BroadcastData::Buf(buf);
        }
        // The TOS simple-broadcast actor propagates to its full neighbour set,
        // including the forwarding peer; duplicate registration stops echoes.
        let skip = if ctx.overlay.wire_profile == rtos_api::WireProfile::T0
            && matches!(Self::broadcast_type(), BroadcastType::Simple) {
            None
        } else { Some(ctx.peers.other()) };
        Ok(self.select_broadcast_neighbours(ctx.overlay, neighbours, skip))
    }

    async fn recv<'a>(&mut self, bcast: T, mut ctx: BroadcastRecvContext<'a>) -> Result<()> {
        let bcast_type = Self::broadcast_type();
        if !broadcast_date_admissible(bcast.date(), ctx.overlay.clock.unix_seconds()) {
            log::warn!(
                target: TARGET,
                "{bcast_type} broadcast dated {} outside the accepted window from {} in overlay {}",
                bcast.date() as u32,
                ctx.peers.other(),
                ctx.overlay.overlay_id
            );
            return Ok(());
        }
        let now = ctx.overlay.broadcast_time();
        #[cfg(feature = "xp25")]
        let flags = bcast.flags();
        let timeout_sec = Self::calc_broadcast_timeout(
            #[cfg(feature = "xp25")]
            flags,
        );
        if bcast.date() + (timeout_sec as i32) < now {
            log::warn!(
                target: TARGET,
                "Old {bcast_type} broadcast {} seconds old from {} in overlay {}",
                now - bcast.date(),
                ctx.peers.other(),
                ctx.overlay.overlay_id
            );
            return Ok(());
        }
        let info = self.check_broadcast(&bcast, &ctx)?;
        let bcast_id = base64_encode(&info.bcast_id);
        if info.dup {
            log::info!(target: TARGET, "Received duplicated {bcast_type} broadcast {bcast_id}");
            return Ok(());
        };
        log::trace!(
            target: TARGET,
            "Received {bcast_type} broadcast {bcast_id}, {} bytes",
            info.data_len
        );
        #[cfg(feature = "telemetry")]
        let tag = info.maybe_tag.unwrap_or(bcast.default_tag());
        #[cfg(feature = "telemetry")]
        log::info!(
            target: TARGET_BROADCAST,
            "Broadcast trace: recv {bcast_type} {} {} bytes, \
            tag {tag:08x} hops {:?} from {} in overlay {}",
            base64_encode(&info.bcast_id),
            info.data_len,
            ctx.hops,
            ctx.peers.other(),
            ctx.overlay.overlay_id
        );
        ctx.verdict = info.verdict;
        let (recv, resend) = self.process_broadcast(bcast, &mut ctx, &info.bcast_id).await?;
        if let Some(recv) = recv {
            ctx.overlay.received_rawbytes.push(recv);
            ctx.overlay.setup_broadcast_purge(
                info.bcast_id,
                #[cfg(feature = "xp25")]
                flags,
            )?;
        }
        if resend {
            self.resend_broadcast(
                &mut ctx,
                &info.bcast_id,
                info.seqno,
                #[cfg(feature = "telemetry")]
                tag,
            )
            .await?;
        }
        Ok(())
    }

    async fn resend_broadcast(
        &mut self,
        ctx: &mut BroadcastRecvContext,
        bcast_id: &BroadcastId,
        seqno: u32,
        #[cfg(feature = "telemetry")] tag: u32,
    ) -> Result<()> {
        let options = ctx.overlay.options.load(Ordering::Relaxed);
        if (options & Overlay::OPTION_DISABLE_BROADCAST_RETRANSMIT) != 0 {
            return Ok(());
        }
        let hops = if let Some(hops) = ctx.hops {
            if (hops & 0x0F) <= 1 {
                return Ok(());
            }
            Some(hops)
        } else {
            ctx.overlay.hops
        };
        let mut neighbours = self.calc_broadcast_neighbours(ctx.overlay, hops)?;
        self.build_rebroadcast(ctx, &mut neighbours)?;
        let Some(neighbours) = neighbours.get_ids() else {
            return Ok(());
        };
        let data = match &ctx.data {
            BroadcastData::Buf(data) | BroadcastData::Rebuilt(data) => data,
            BroadcastData::None => return Ok(()),
            BroadcastData::Raw(data) => *data,
            BroadcastData::Stream(_) => fail!("INTERNAL ERROR: unprepared stream data"),
        };
        #[cfg(feature = "telemetry")]
        match Self::broadcast_type() {
            BroadcastType::Fec | BroadcastType::TwostepFec => {
                let stats = ctx.overlay.get_per_transfer_stats(bcast_id)?;
                stats.resent.fetch_add(neighbours.len() as u64, Ordering::Relaxed);
            }
            _ => (),
        };
        Self::distribute_broadcast(
            ctx.overlay,
            data,
            bcast_id,
            seqno,
            &neighbours,
            ctx.peers.local(),
            &self.send_method(),
            #[cfg(feature = "telemetry")]
            tag,
        )
        .await
    }

    // Send side

    fn calc_broadcast_id(
        &self,
        ctx: &BroadcastSendContext,
        date: i32,
    ) -> Result<(BroadcastId, bool)>;
    fn build_broadcast(
        &mut self,
        ctx: &BroadcastSendContext,
        bcast_id: &BroadcastId,
        date: i32,
        neighbours: &mut BroadcastNeighbours,
    ) -> Result<BroadcastJob>;

    async fn send<'a>(&mut self, ctx: BroadcastSendContext<'a>) -> Result<BroadcastSendInfo> {
        let mut neighbours = self.calc_broadcast_neighbours(ctx.overlay, ctx.overlay.hops)?;
        let bcast_type = Self::broadcast_type();
        let date = ctx.overlay.broadcast_time();
        let (bcast_id, allow_dup) = self.calc_broadcast_id(&ctx, date)?;
        let added = add_unbound_object_to_map(&ctx.overlay.owned_broadcasts, bcast_id, || {
            Ok(OwnedBroadcast::Send)
        })?;
        if !added && !allow_dup {
            let msg = base64_encode(bcast_id);
            #[cfg(feature = "telemetry")]
            let msg = format!("{msg}, tag {:08x}", ctx.data.tag);
            log::warn!(target: TARGET, "Try to send duplicated {bcast_type} broadcast {msg}");
            return Ok(BroadcastSendInfo::default());
        }
        let repeated = !added && allow_dup;
        #[cfg(feature = "xp25")]
        let repeated = repeated || ((ctx.flags & OverlayNode::FLAG_BCAST_REPEATED) != 0);
        if repeated {
            let msg = base64_encode(&bcast_id);
            #[cfg(feature = "telemetry")]
            let msg = format!("{msg}, tag {:08x}", ctx.data.tag);
            log::debug!(target: TARGET, "Sending repeated {bcast_type} broadcast {msg}");
        }
        #[cfg(feature = "telemetry")]
        log::info!(
            target: TARGET_BROADCAST,
            "Broadcast trace: send {bcast_type} {} {} bytes, tag {:08x} to overlay {}",
            base64_encode(&bcast_id),
            ctx.data.object.len(),
            ctx.data.tag,
            ctx.overlay.overlay_id
        );
        match self.build_broadcast(&ctx, &bcast_id, date, &mut neighbours)? {
            BroadcastJob::Background(packets) => {
                let send_to = if let Some(neighbours) = neighbours.get_ids() {
                    neighbours.len() as u32
                } else {
                    0
                };
                Ok(BroadcastSendInfo { packets, send_to })
            }
            BroadcastJob::Foreground(bcast) => {
                if ctx.overlay.wire_profile == rtos_api::WireProfile::T0 {
                    if let Broadcast::Overlay_Broadcast(simple) = &bcast {
                        // TOS sends a locally signed simple carrier through the
                        // same run/check/relay/deliver path as a received one.
                        ctx.overlay.owned_broadcasts.remove(&bcast_id);
                        let bytes = ctx.overlay.serialize_broadcast(&bcast)?;
                        let peers = AdnlPeers::with_keys(
                            ctx.src_adnl_key_id.clone(), ctx.src_adnl_key_id.clone(),
                        );
                        let send_to = ctx.overlay.neighbours.count();
                        BroadcastSimpleProtocol.recv(simple.clone(), BroadcastRecvContext {
                            data: BroadcastData::Raw(&bytes), hops: None, overlay: ctx.overlay,
                            peers: &peers, verdict: BroadcastCheckResult::Allowed,
                        }).await?;
                        return Ok(BroadcastSendInfo { packets: 1, send_to });
                    }
                }
                let mut buf = ctx.overlay.serialize_broadcast(&bcast)?;
                if let Some(hops) = &neighbours.hops {
                    buf.push(*hops);
                }
                self.select_broadcast_neighbours(ctx.overlay, &mut neighbours, None);
                let send_to = if let Some(neighbours) = neighbours.get_ids() {
                    Self::distribute_broadcast(
                        ctx.overlay,
                        &buf,
                        &bcast_id,
                        0,
                        &neighbours,
                        &ctx.src_adnl_key_id,
                        &self.send_method(),
                        #[cfg(feature = "telemetry")]
                        ctx.data.tag,
                    )
                    .await?;
                    ctx.overlay.setup_broadcast_purge(
                        bcast_id,
                        #[cfg(feature = "xp25")]
                        ctx.flags,
                    )?;
                    neighbours.len() as u32
                } else {
                    0
                };
                Ok(BroadcastSendInfo { packets: 1, send_to })
            }
        }
    }
}

pub(crate) trait FecBroadcastParsed: BroadcastParsed {
    fn data_hash(&self) -> &[u8; 32];
    fn data_size(&self) -> usize;
    fn wire_flags(&self) -> u32;
    fn extra(&self) -> Option<&[u8]> {
        None
    }
    fn fec_type(&self) -> Option<FecTypeRaptorQ>;
    fn part_data(&self) -> &[u8];
    fn seqno(&self) -> u32;
    fn signature(&self) -> &[u8];
}

#[async_trait::async_trait]
trait FecProtocol<T: FecBroadcastParsed + Send + 'static>: BroadcastProtocol<T> {
    /// Two-step FEC re-checks the date after its precheck, where reception can
    /// suspend, before a part reaches the decoder (C++ broadcast-twostep.cpp).
    const RECHECK_DATE_BEFORE_DECODE: bool = false;
    /// Two-step broadcasts are checked as never sent by any sender; ordinary
    /// FEC broadcasts carry the any-sender flag on the wire.
    const TWOSTEP: bool = false;

    fn build_broadcast_part(
        data: Vec<u8>,
        transfer: &SendTransferFec,
        signature: Vec<u8>,
    ) -> Result<Broadcast>;
    fn calc_to_sign(
        bcast_id: &BroadcastId,
        data_size: usize,
        part_data: &[u8],
        seqno: u32,
        date: i32,
    ) -> Result<Vec<u8>>;
    fn unwrap_transfer(wrapped: &OwnedBroadcast) -> Option<&RecvTransferFec<T>>;
    fn wrap_transfer(transfer: RecvTransferFec<T>) -> OwnedBroadcast;

    fn is_any_sender(bcast: &T) -> bool {
        !Self::TWOSTEP && (bcast.wire_flags() & BROADCAST_FLAG_ANY_SENDER) != 0
    }

    fn create_transfer(
        ctx: &BroadcastRecvContext,
        bcast_id: &BroadcastId,
        bcast: &T,
    ) -> Result<OwnedBroadcast> {
        let bcast_type = Self::broadcast_type();
        let Some(fec_type) = bcast.fec_type() else {
            fail!("Wrong FEC type set for {bcast_type} broadcast");
        };
        let (sender, mut reader) = tokio::sync::mpsc::unbounded_channel::<Option<(T, bool)>>();
        let mut decoder = RaptorqDecoder::with_params(fec_type.clone())?;
        let bcast_id_recv = *bcast_id;
        let overlay = ctx.overlay.clone();
        let src_key = bcast.src_key()?;
        let src_key_id = src_key.id().clone();
        let tasks = overlay.tasks.clone();
        tasks.spawn_cancelable("overlay FEC transfer", async move {
            let mut received = false;
            let mut packets = 0;
            let mut extra: Option<Vec<u8>> = None;
            #[cfg(feature = "telemetry")]
            let mut flags = RecvTransferFecTelemetry::FLAG_RECEIVE_STARTED;
            #[cfg(feature = "telemetry")]
            let mut len = 0;
            let mut tag = 0;
            while let Some(bcast) = reader.recv().await {
                let (bcast, untrusted): (T, bool) = match bcast {
                    Some(bcast) => bcast,
                    None => break,
                };
                if extra.is_none() {
                    extra = bcast.extra().map(|extra| extra.to_vec());
                }
                packets += 1;
                let Some(fec_type) = bcast.fec_type() else {
                    log::warn!(
                        target: TARGET,
                        "FEC type is not properly set for {bcast_type} broadcast in overlay {}",
                        overlay.overlay_id
                    );
                    continue;
                };
                let other_fec_type = decoder.params();
                if fec_type != *other_fec_type {
                    log::warn!(
                        target: TARGET,
                        "Mismatch in FEC parameters of {bcast_type} broadcast in overlay {}: \
                        {fec_type:?} vs. {other_fec_type:?}",
                        overlay.overlay_id
                    );
                    continue;
                }
                match Self::process_part(
                    &mut decoder, &bcast_id_recv, &bcast, overlay.broadcast_time(),
                ) {
                    Err(e) => {
                        log::warn!(
                            target: TARGET,
                            "Error when processing {bcast_type} broadcast in overlay {}: {e}",
                            overlay.overlay_id
                        );
                        #[cfg(feature = "telemetry")]
                        {
                            flags |= RecvTransferFecTelemetry::FLAG_FAILED;
                        }
                    }
                    Ok(Some(data)) => {
                        if data.len() > 4 {
                            tag = u32::from_le_bytes([data[0], data[1], data[2], data[3]])
                        }
                        #[cfg(feature = "telemetry")]
                        {
                            len = data.len() as u32;
                            flags |= RecvTransferFecTelemetry::FLAG_RECEIVED;
                        }
                        // The part completing the decode decides: a part whose
                        // source needs a check delivers only after approval.
                        let approved = if untrusted {
                            match overlay.application_check(&src_key_id, &data).await {
                                Ok(()) => true,
                                Err(e) => {
                                    log::debug!(
                                        target: TARGET,
                                        "Application check refused {bcast_type} broadcast {} \
                                        in overlay {}: {e}",
                                        base64_encode(&bcast_id_recv),
                                        overlay.overlay_id
                                    );
                                    false
                                }
                            }
                        } else {
                            true
                        };
                        if approved {
                            overlay.received_rawbytes.push(BroadcastRecvInfo {
                                packets,
                                data,
                                extra,
                                recv_from: src_key_id.clone(),
                            });
                            received = true;
                        }
                        if untrusted {
                            Self::checked(&overlay, &bcast_id_recv, approved).await;
                        }
                        if !approved {
                            if let Some(transfer) = overlay.owned_broadcasts.get(&bcast_id_recv) {
                                if let Some(transfer) = Self::unwrap_transfer(transfer.val()) {
                                    transfer.completed.store(true, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                    Ok(None) => continue,
                }
                break;
            }
            if received {
                if let Some(transfer) = overlay.owned_broadcasts.get(&bcast_id_recv) {
                    if let Some(transfer) = Self::unwrap_transfer(transfer.val()) {
                        transfer.completed.store(true, Ordering::Relaxed);
                        #[cfg(feature = "telemetry")]
                        {
                            transfer.telemetry.flags.fetch_or(flags, Ordering::Relaxed);
                            transfer.telemetry.len.store(len, Ordering::Relaxed);
                            transfer.telemetry.tag.store(tag, Ordering::Relaxed);
                        }
                        log::debug!(
                            target: TARGET,
                            "Recv {bcast_type} broadcast {} with tag {tag:08x} \
                            in overlay {} from {src_key_id}",
                            base64_encode(&bcast_id_recv),
                            overlay.overlay_id
                        )
                    } else {
                        log::error!(
                            target: TARGET,
                            "INTERNAL ERROR: recv {bcast_type} broadcast {} mismatch in overlay {}",
                            base64_encode(&bcast_id_recv),
                            overlay.overlay_id
                        )
                    }
                }
            }
            // Graceful close
            reader.close();
            while reader.recv().await.is_some() {}
        });
        let timeout_sec = Self::calc_broadcast_timeout(
            #[cfg(feature = "xp25")]
            bcast.flags(),
        );
        let bcast_id_wait = *bcast_id;
        let bcast_type = Self::broadcast_type();
        let data_size = bcast.data_size();
        #[cfg(feature = "xp25")]
        let flags = bcast.flags();
        let overlay = ctx.overlay.clone();
        let tasks = overlay.tasks.clone();
        tasks.spawn_cancelable("overlay FEC transfer", async move {
            loop {
                tokio::time::sleep(Duration::from_millis(timeout_sec * 100)).await;
                if let Some(transfer) = overlay.owned_broadcasts.get(&bcast_id_wait) {
                    if let Some(transfer) = Self::unwrap_transfer(transfer.val()) {
                        if !transfer.updated_at.is_expired(timeout_sec) {
                            continue;
                        }
                        if !transfer.completed.load(Ordering::Relaxed) {
                            log::warn!(
                                target: TARGET,
                                "{bcast_type} broadcast {} ({data_size} bytes) \
                                dropped incompleted by timeout in overlay {}",
                                base64_encode(&bcast_id_wait),
                                overlay.overlay_id
                            )
                        }
                        // Abort receiving loop
                        transfer.sender.send(None).ok();
                    } else {
                        log::error!(
                            target: TARGET,
                            "INTERNAL ERROR: recv {bcast_type} broadcast {} mismatch in overlay {}",
                            base64_encode(&bcast_id_wait),
                            overlay.overlay_id
                        )
                    }
                }
                break;
            }
            if let Err(e) = overlay.setup_broadcast_purge(
                bcast_id_wait,
                #[cfg(feature = "xp25")]
                flags,
            ) {
                log::warn!(
                    target: TARGET,
                    "Cannot setup {bcast_type} broadcast {} purge after recv: {e}",
                    base64_encode(&bcast_id_wait),
                )
            }
        });
        let transfer = RecvTransferFec {
            accepted_parts: Mutex::new(HashSet::new()),
            completed: AtomicBool::new(false),
            data_hash: *bcast.data_hash(),
            history: PeerHistory::for_recv(),
            relay: Mutex::new(FecRelayState::default()),
            sender,
            src_key_id: src_key.id().clone(),
            #[cfg(feature = "telemetry")]
            telemetry: RecvTransferFecTelemetry {
                flags: AtomicU32::new(0),
                len: AtomicU32::new(0),
                tag: AtomicU32::new(0),
            },
            updated_at: UpdatedAt::new(),
            counter: ctx.overlay.allocated.recv_transfers.clone().into(),
        };
        #[cfg(feature = "telemetry")]
        ctx.overlay
            .telemetry
            .recv_transfers
            .update(ctx.overlay.allocated.recv_transfers.load(Ordering::Relaxed));
        Ok(Self::wrap_transfer(transfer))
    }

    /// Outcome of an application check of a broadcast whose completing part
    /// needed one. Ordinary FEC releases the parts it held back on approval.
    async fn checked(overlay: &Arc<Overlay>, bcast_id: &BroadcastId, approved: bool) {
        if Self::TWOSTEP {
            return;
        }
        let held = {
            let Some(transfer) = overlay.owned_broadcasts.get(bcast_id) else {
                return;
            };
            let Some(transfer) = Self::unwrap_transfer(transfer.val()) else {
                return;
            };
            let Ok(mut relay) = transfer.relay.lock() else {
                return;
            };
            if approved {
                relay.checked = true;
            } else {
                relay.refused = true;
            }
            let held = std::mem::take(&mut relay.held);
            if !approved {
                return;
            }
            held.into_iter()
                .map(|part| {
                    let neighbours = relay.fixed_neighbours.clone().unwrap_or_else(|| {
                        overlay.select_broadcast_neighbours(part.count, Some(&part.skip))
                    });
                    (part, neighbours)
                })
                .collect::<Vec<_>>()
        };
        for (part, neighbours) in held {
            if let Err(e) = overlay
                .distribute_broadcast(
                    &TaggedByteSlice {
                        object: &part.buf,
                        #[cfg(feature = "telemetry")]
                        tag: 0,
                    },
                    bcast_id,
                    part.seqno,
                    &part.local,
                    &neighbours,
                    &BroadcastSendMethod::Fast,
                )
                .await
            {
                log::warn!(
                    target: TARGET,
                    "Cannot relay checked broadcast {} part {}: {e}",
                    base64_encode(bcast_id),
                    part.seqno
                );
            }
        }
    }

    fn prepare_part(overlay: &Arc<Overlay>, transfer: &mut SendTransferFec) -> Result<Vec<u8>> {
        let seqno_original = transfer.seqno;
        let chunk = transfer.encoder.encode(&mut transfer.seqno)?;
        let to_sign = Self::calc_to_sign(
            &transfer.bcast_id,
            transfer.encoder.params().data_size as usize,
            &chunk,
            transfer.seqno,
            transfer.date,
        )?;
        let signature = transfer.src_key.sign(&to_sign)?;
        let bcast = Self::build_broadcast_part(chunk, transfer, signature)?;
        if seqno_original == transfer.seqno {
            transfer.seqno += 1;
        }
        overlay.serialize_broadcast(&bcast)
    }

    /// Admit one received part: source verdict, duplicate and same-source
    /// checks, the part signature, then the decoder. Returns `None` for a
    /// dropped part, otherwise whether its source needs an application check.
    async fn admit_part(
        bcast: T,
        ctx: &BroadcastRecvContext,
        bcast_id: &BroadcastId,
    ) -> Result<Option<bool>> {
        #[cfg(feature = "telemetry")]
        log::info!(
            target: TARGET_BROADCAST,
            "Broadcast FEC trace: recv {} part {}, hops {:?} to overlay {}",
            base64_encode(&bcast_id),
            bcast.seqno(),
            ctx.hops,
            ctx.overlay.overlay_id
        );
        #[cfg(feature = "telemetry")]
        let stats = ctx.overlay.get_per_transfer_stats(bcast_id)?;
        #[cfg(feature = "telemetry")]
        stats.income.fetch_add(1, Ordering::Relaxed);
        // on_recv check if any runs on first FEC part, before reassembly
        if ctx.overlay.owned_broadcasts.get(bcast_id).is_none() {
            if let OverlayType::Private { bcast_check: Some(check), .. } = &ctx.overlay.overlay_type
            {
                if let Err(reason) = check.on_recv(bcast.src_key()?.id(), bcast.extra()) {
                    log::warn!(
                        target: TARGET,
                        "precheck rejected broadcast {} in overlay {}: {reason}",
                        base64_encode(bcast_id),
                        ctx.overlay.overlay_id
                    );
                    return Ok(None);
                }
            }
        }
        let bcast_type = Self::broadcast_type();
        let src_key = bcast.src_key()?;
        let peer = ctx.peers.other();
        if Self::TWOSTEP
            && ctx.overlay.has_public_policy()
            && (bcast.data_size() > MAX_FEC_BROADCAST_SIZE as usize
                || bcast.part_data().len() >= bcast.data_size())
        {
            log::debug!(
                target: TARGET,
                "Bad {bcast_type} broadcast {} dimensions in overlay {}",
                base64_encode(bcast_id),
                ctx.overlay.overlay_id
            );
            return Ok(None);
        }
        let any_sender = Self::is_any_sender(&bcast);
        let verdict = ctx.overlay.broadcast_verdict(
            &src_key,
            bcast.certificate(),
            bcast.data_size(),
            true,
            any_sender,
            peer,
        );
        if verdict == BroadcastCheckResult::Forbidden {
            log::debug!(
                target: TARGET,
                "Forbidden {bcast_type} broadcast {} from {peer} in overlay {}",
                base64_encode(bcast_id),
                ctx.overlay.overlay_id
            );
            return Ok(None);
        }
        if let Some(existing) = ctx.overlay.owned_broadcasts.get(bcast_id) {
            if let Some(transfer) = Self::unwrap_transfer(existing.val()) {
                let seen = transfer
                    .accepted_parts
                    .lock()
                    .map_err(|_| error!("FEC part table lock poisoned"))?
                    .contains(&bcast.seqno());
                if seen {
                    return Ok(None);
                }
                if !Self::TWOSTEP
                    && verdict != BroadcastCheckResult::NeedCheck
                    && !any_sender
                    && &transfer.src_key_id != src_key.id()
                {
                    log::debug!(
                        target: TARGET,
                        "Bad source of {bcast_type} broadcast {} part in overlay {}",
                        base64_encode(bcast_id),
                        ctx.overlay.overlay_id
                    );
                    return Ok(None);
                }
            }
        }
        let to_sign = Self::calc_to_sign(
            bcast_id,
            bcast.data_size(),
            bcast.part_data(),
            bcast.seqno(),
            bcast.date(),
        )?;
        if let Err(e) =
            ctx.overlay.verify_broadcast_signature(&src_key, &to_sign, bcast.signature(), peer)
        {
            if ctx.overlay.wire_profile == rtos_api::WireProfile::T0 {
                return Err(e);
            }
            log::debug!(
                target: TARGET,
                "Bad signature of {bcast_type} broadcast {} part {} from {peer}: {e}",
                base64_encode(bcast_id),
                bcast.seqno()
            );
            return Ok(None);
        }
        let transfer = loop {
            if let Some(transfer) = ctx.overlay.owned_broadcasts.get(bcast_id) {
                break transfer;
            }
            if !add_unbound_object_to_map(&ctx.overlay.owned_broadcasts, *bcast_id, || {
                Ok(OwnedBroadcast::WillBeRecv(bcast_type.clone()))
            })? {
                tokio::task::yield_now().await;
                continue;
            }
            #[cfg(feature = "xp25")]
            if (bcast.flags() & OverlayNode::FLAG_BCAST_REPEATED) != 0 {
                log::debug!(
                    target: TARGET,
                    "Receiving repeated {bcast_type} broadcast {}",
                    base64_encode(bcast_id)
                );
            }
            let transfer = Self::create_transfer(ctx, bcast_id, &bcast);
            if transfer.is_err() {
                ctx.overlay.owned_broadcasts.remove(bcast_id);
            }
            let ok = match ctx.overlay.owned_broadcasts.insert(*bcast_id, transfer?) {
                Some(removed) => matches!(
                    removed.val(),
                    OwnedBroadcast::WillBeRecv(x) if x == &bcast_type
                ),
                _ => false,
            };
            if !ok {
                log::error!(
                    target: TARGET,
                    "INTERNAL ERROR: recv {bcast_type} broadcast {} create mismatch in overlay {}",
                    base64_encode(bcast_id),
                    ctx.overlay.overlay_id
                )
            }
        };
        let Some(transfer) = Self::unwrap_transfer(transfer.val()) else {
            // Not a proper broadcast
            return Ok(None);
        };
        transfer.updated_at.refresh();
        if &transfer.data_hash != bcast.data_hash() {
            log::warn!(
                target: TARGET,
                "Same broadcast ID {} but different hash: {} vs {} (src {} vs {}) in overlay {}",
                base64_encode(bcast_id),
                base64_encode(transfer.data_hash),
                base64_encode(bcast.data_hash()),
                transfer.src_key_id,
                src_key.id(),
                ctx.overlay.overlay_id
            );
            return Ok(None);
        }
        if !transfer.history.update(bcast.seqno() as u64, TARGET_BROADCAST).await? {
            log::debug!(
                target: TARGET,
                "Broadcast {} part {} dropped by history filter in overlay {}",
                base64_encode(bcast_id),
                bcast.seqno(),
                ctx.overlay.overlay_id
            );
            return Ok(None);
        }
        if Self::RECHECK_DATE_BEFORE_DECODE
            && !broadcast_date_admissible(bcast.date(), ctx.overlay.clock.unix_seconds())
        {
            log::warn!(
                target: TARGET,
                "Broadcast {} part {} dated {} left the accepted window in overlay {}",
                base64_encode(bcast_id),
                bcast.seqno(),
                bcast.date() as u32,
                ctx.overlay.overlay_id
            );
            return Ok(None);
        }
        transfer
            .accepted_parts
            .lock()
            .map_err(|_| error!("FEC part table lock poisoned"))?
            .insert(bcast.seqno());
        let untrusted = verdict != BroadcastCheckResult::Allowed;
        if !transfer.completed.load(Ordering::Relaxed) {
            transfer
                .sender
                .send(Some((bcast, untrusted)))
                .map_err(|e| error!("Error sending broadcast packet to processing: {e}"))?;
        }
        #[cfg(feature = "telemetry")]
        stats.passed.fetch_add(1, Ordering::Relaxed);
        Ok(Some(untrusted))
    }

    /// Decode one part whose source and signature were already checked.
    fn process_part(
        decoder: &mut RaptorqDecoder,
        bcast_id: &BroadcastId,
        bcast: &T,
        now: i32,
    ) -> Result<Option<Vec<u8>>> {
        let bcast_type = Self::broadcast_type();
        if let Some(ret) = decoder.decode(bcast.seqno(), bcast.part_data()) {
            let ret = if ret.len() != bcast.data_size() as usize {
                fail!("Expected {} bytes, but received {}", bcast.data_size(), ret.len())
            } else {
                let test_hash = sha256_digest(&ret);
                if &test_hash != bcast.data_hash() {
                    fail!(
                        "Expected {bcast_type} broadcast {} data hash, but received {}",
                        base64_encode(bcast.data_hash()),
                        base64_encode(test_hash),
                    )
                }
                let delay = now - bcast.date();
                if delay > 1 {
                    log::warn!(
                        target: TARGET,
                        "Received overlay {bcast_type} broadcast {} ({} bytes) in {delay} seconds",
                        base64_encode(bcast_id),
                        ret.len()
                    )
                } else {
                    log::trace!(
                        target: TARGET,
                        "Received overlay {bcast_type} broadcast {} ({} bytes) in {delay} seconds",
                        base64_encode(bcast_id),
                        ret.len()
                    )
                }
                ret
            };
            Ok(Some(ret))
        } else {
            Ok(None)
        }
    }
}

/// Re-serialize a received certificate in its normalized wire form.
fn normalized_certificate(certificate: &OverlayCertificate) -> Result<OverlayCertificate> {
    Ok(match SourceCertificate::from_tl(certificate)? {
        Some(certificate) => certificate.to_tl(),
        None => OverlayCertificate::Overlay_EmptyCertificate,
    })
}

trait BroadcastMultistep {
    fn calc_broadcast_neighbours(
        overlay: &Arc<Overlay>,
        hops: Option<u8>,
        neighbours: u8,
    ) -> Result<BroadcastNeighbours> {
        let (hops, expected_count) = overlay.calc_broadcast_neighbours(hops, neighbours)?;
        Ok(BroadcastNeighbours { expected_count, hops, ids: None })
    }

    fn select_broadcast_neighbours(
        overlay: &Arc<Overlay>,
        neighbours: &mut BroadcastNeighbours,
        skip: Option<&Arc<KeyId>>,
    ) {
        if neighbours.ids.is_some() {
            neighbours.skip(skip);
        } else {
            neighbours.ids =
                Some(overlay.select_broadcast_neighbours(neighbours.expected_count, skip));
        }
    }
}

trait BroadcastTwostep {
    fn calc_broadcast_id(
        data_hash: [u8; 32],
        date: i32,
        data_size: usize,
        part_size: usize,
        src_key: &Arc<dyn KeyOption>,
        src_adnl_key_id: &Arc<KeyId>,
        flags: u32,
        extra: &[u8],
    ) -> Result<BroadcastId> {
        let bcast_id = BroadcastTwostepId {
            date,
            flags: flags as i32,
            src: UInt256::from_slice(src_key.id().data()),
            src_adnl_id: UInt256::from_slice(src_adnl_key_id.data()),
            data_hash: UInt256::with_array(data_hash),
            data_size: data_size as i32,
            part_size: part_size as i32,
            extra: extra.to_vec(),
        };
        hash(bcast_id)
    }

    fn calc_broadcast_id_when_send(
        ctx: &BroadcastSendContext,
        date: i32,
        data_size: usize,
        part_size: usize,
        extra: &[u8],
    ) -> Result<(BroadcastId, bool)> {
        let bcast_id = Self::calc_broadcast_id(
            sha256_digest(ctx.data.object),
            date,
            data_size,
            part_size,
            &ctx.src_key,
            &ctx.src_adnl_key_id,
            ctx.flags,
            extra,
        )?;
        Ok((bcast_id, true))
    }

    fn calc_broadcast_neighbours(overlay: &Arc<Overlay>) -> BroadcastNeighbours {
        let neighbours = overlay.select_broadcast_twostep_neighbours(None);
        BroadcastNeighbours {
            hops: None,
            expected_count: neighbours.len() as u32,
            ids: Some(neighbours),
        }
    }

    fn select_broadcast_neighbours(
        neighbours: &mut BroadcastNeighbours,
        skip: Option<&Arc<KeyId>>,
    ) {
        neighbours.skip(skip);
    }
}

// Broadcast FEC **************************************************************

#[rustfmt::skip]
impl BroadcastParsed for BroadcastFec {
    fn certificate(&self) -> &OverlayCertificate { &self.certificate }
    fn date(&self) -> i32 { self.date }
    fn src_key(&self) -> Result<Arc<dyn KeyOption>> { (&self.src).try_into() }
    #[cfg(feature = "telemetry")]
    fn default_tag(&self) -> u32 { BroadcastFec::constructor_const() }
    #[cfg(feature = "xp25")]
    fn flags(&self) -> u32 { self.flags as u32 }
}

#[rustfmt::skip]
impl FecBroadcastParsed for BroadcastFec {
    fn data_hash(&self) -> &[u8; 32] { self.data_hash.as_slice() }
    fn data_size(&self) -> usize { self.data_size as usize }
    fn wire_flags(&self) -> u32 { self.flags as u32 }
    fn part_data(&self) -> &[u8] { &self.data }
    fn seqno(&self) -> u32 { self.seqno as u32 }
    fn signature(&self) -> &[u8] { &self.signature }

    fn fec_type(&self) -> Option<FecTypeRaptorQ> {
        if let FecType::Fec_RaptorQ(fec_type) = &self.fec {
            Some(fec_type.clone())
        } else {
            None
        }
    }
}

pub(crate) struct BroadcastFecProtocol {
    encoder: Option<RaptorqEncoder>,
}

impl BroadcastFecProtocol {
    const SIZE_WAVE: u32 = 4;
    const TIMEOUT_WAVE_MS: u64 = 3;

    pub(crate) fn for_recv() -> Self {
        Self { encoder: None }
    }

    pub(crate) fn for_send(ctx: &BroadcastSendContext) -> Self {
        Self { encoder: Some(RaptorqEncoder::with_data(ctx.data.object, None)) }
    }

    fn calc_broadcast_id(
        data_hash: [u8; 32],
        data_size: usize,
        src_key: &Arc<dyn KeyOption>,
        flags: u32,
        fec_type: FecTypeRaptorQ,
    ) -> Result<BroadcastId> {
        let bcast_id = BroadcastFecId {
            src: if ((flags as u32) & OverlayNode::FLAG_BCAST_ANY_SENDER) != 0 {
                UInt256::ZERO
            } else {
                UInt256::from_slice(src_key.id().data())
            },
            type_: UInt256::with_array(hash(fec_type)?),
            data_hash: UInt256::with_array(data_hash),
            size: data_size as i32,
            flags: flags as i32,
        };
        hash(bcast_id)
    }
}

impl BroadcastMultistep for BroadcastFecProtocol {}

#[async_trait::async_trait]
impl BroadcastProtocol<BroadcastFec> for BroadcastFecProtocol {
    // Common

    fn broadcast_type() -> BroadcastType {
        BroadcastType::Fec
    }

    fn calc_broadcast_neighbours(
        &self,
        overlay: &Arc<Overlay>,
        hops: Option<u8>,
    ) -> Result<BroadcastNeighbours> {
        <Self as BroadcastMultistep>::calc_broadcast_neighbours(
            overlay,
            hops,
            Overlay::SIZE_NEIGHBOURS_LONG_BROADCAST,
        )
    }

    fn select_broadcast_neighbours(
        &self,
        overlay: &Arc<Overlay>,
        neighbours: &mut BroadcastNeighbours,
        skip: Option<&Arc<KeyId>>,
    ) {
        <Self as BroadcastMultistep>::select_broadcast_neighbours(overlay, neighbours, skip);
    }

    fn send_method(&self) -> BroadcastSendMethod {
        BroadcastSendMethod::Fast
    }

    // Receive side

    fn check_broadcast(
        &self,
        bcast: &BroadcastFec,
        _ctx: &BroadcastRecvContext,
    ) -> Result<BroadcastCheckInfo> {
        let fec_type = if let FecType::Fec_RaptorQ(fec_type) = &bcast.fec {
            fec_type.clone()
        } else {
            fail!("Unsupported FEC type {} broadcast", Self::broadcast_type())
        };
        Ok(BroadcastCheckInfo {
            bcast_id: Self::calc_broadcast_id(
                *bcast.data_hash.as_slice(),
                bcast.data_size as usize,
                &bcast.src_key()?,
                bcast.flags as u32,
                fec_type,
            )?,
            dup: false,
            verdict: BroadcastCheckResult::Allowed,
            data_len: bcast.data.len(),
            seqno: bcast.seqno(),
            #[cfg(feature = "telemetry")]
            maybe_tag: None,
        })
    }

    async fn process_broadcast(
        &self,
        bcast: BroadcastFec,
        ctx: &mut BroadcastRecvContext,
        bcast_id: &BroadcastId,
    ) -> Result<(Option<BroadcastRecvInfo>, bool)> {
        let seqno = bcast.seqno();
        let flags = bcast.flags as u32;
        // A relayed part carries the envelope rebuilt from its parsed fields,
        // with the certificate in its normalized wire form.
        let relay = ctx.overlay.serialize_broadcast(
            &BroadcastFec {
                certificate: normalized_certificate(&bcast.certificate)?,
                ..bcast.clone()
            }
            .into_boxed(),
        )?;
        let Some(untrusted) =
            <Self as FecProtocol<BroadcastFec>>::admit_part(bcast, ctx, bcast_id).await?
        else {
            return Ok((None, false));
        };
        let options = ctx.overlay.options.load(Ordering::Relaxed);
        if (options & Overlay::OPTION_DISABLE_BROADCAST_RETRANSMIT) != 0 {
            return Ok((None, false));
        }
        let hops = match ctx.hops {
            Some(hops) if (hops & 0x0F) <= 1 => return Ok((None, false)),
            Some(hops) => Some(hops),
            None => ctx.overlay.hops,
        };
        let (relay_hops, count) =
            ctx.overlay.calc_broadcast_neighbours(hops, Overlay::SIZE_NEIGHBOURS_LONG_BROADCAST)?;
        let mut buf = relay;
        if let Some(hops) = relay_hops.or(ctx.hops) {
            buf.push(hops);
        }
        let neighbours = {
            let Some(guard) = ctx.overlay.owned_broadcasts.get(bcast_id) else {
                return Ok((None, false));
            };
            let Some(transfer) = Self::unwrap_transfer(guard.val()) else {
                return Ok((None, false));
            };
            let mut relay =
                transfer.relay.lock().map_err(|_| error!("FEC relay state lock poisoned"))?;
            // Parts whose source needs a check wait for the broadcast's verdict.
            if untrusted && !relay.checked {
                if !relay.refused && relay.held.len() < MAX_HELD_PARTS {
                    relay.held.push(HeldPart {
                        buf,
                        seqno,
                        count,
                        local: ctx.peers.local().clone(),
                        skip: ctx.peers.other().clone(),
                    });
                }
                return Ok((None, false));
            }
            if (flags & BROADCAST_FLAG_FIXED_NEIGHBOURS) != 0 {
                relay
                    .fixed_neighbours
                    .get_or_insert_with(|| {
                        ctx.overlay.select_broadcast_neighbours(count, Some(ctx.peers.other()))
                    })
                    .clone()
            } else {
                ctx.overlay.select_broadcast_neighbours(count, Some(ctx.peers.other()))
            }
        };
        if neighbours.is_empty() {
            return Ok((None, false));
        }
        #[cfg(feature = "telemetry")]
        ctx.overlay
            .get_per_transfer_stats(bcast_id)?
            .resent
            .fetch_add(neighbours.len() as u64, Ordering::Relaxed);
        Self::distribute_broadcast(
            ctx.overlay,
            &buf,
            bcast_id,
            seqno,
            &neighbours,
            ctx.peers.local(),
            &self.send_method(),
            #[cfg(feature = "telemetry")]
            BroadcastFec::constructor_const(),
        )
        .await?;
        Ok((None, false))
    }

    // Send side

    fn calc_broadcast_id(
        &self,
        ctx: &BroadcastSendContext,
        _date: i32,
    ) -> Result<(BroadcastId, bool)> {
        let fec_type = if let Some(encoder) = &self.encoder {
            encoder.params().clone()
        } else {
            fail!("INTERNAL ERROR: no RaptorQ encoder set in FEC broadcast");
        };
        let bcast_id = Self::calc_broadcast_id(
            sha256_digest(ctx.data.object),
            ctx.data.object.len(),
            &ctx.src_key,
            ctx.flags,
            fec_type,
        )?;
        Ok((bcast_id, false))
    }

    fn build_broadcast(
        &mut self,
        ctx: &BroadcastSendContext,
        bcast_id: &BroadcastId,
        date: i32,
        neighbours: &mut BroadcastNeighbours,
    ) -> Result<BroadcastJob> {
        #[cfg(feature = "telemetry")]
        let tag = ctx.data.tag;
        let data_size = ctx.data.object.len() as u32;
        let Some(encoder) = self.encoder.take() else {
            fail!("INTERNAL ERROR: no RaptorQ encoder set in FEC broadcast");
        };
        let mut transfer = SendTransferFec {
            bcast_id: *bcast_id,
            certificate: ctx.certificate.clone(),
            data_hash: sha256_digest(ctx.data.object),
            date,
            encoder,
            extra: Vec::new(),
            flags: ctx.flags,
            seqno: 0,
            src_key: ctx.src_key.clone(),
            src_adnl_key_id: ctx.src_adnl_key_id.clone(),
            counter: ctx.overlay.allocated.send_transfers.clone().into(),
        };
        #[cfg(feature = "telemetry")]
        ctx.overlay
            .telemetry
            .send_transfers
            .update(ctx.overlay.allocated.send_transfers.load(Ordering::Relaxed));
        let bcast_type = Self::broadcast_type();
        let max_seqno = (data_size / transfer.encoder.params().symbol_size as u32 + 1) * 3 / 2;
        let overlay = ctx.overlay.clone();
        let (sender, mut reader) = tokio::sync::mpsc::unbounded_channel();
        let tasks = overlay.tasks.clone();
        tasks.spawn_cancelable("overlay FEC transfer", async move {
            while transfer.seqno <= max_seqno {
                for _ in 0..Self::SIZE_WAVE {
                    let seqno = transfer.seqno;
                    let result = Self::prepare_part(&overlay, &mut transfer).and_then(|data| {
                        sender.send((data, seqno))?;
                        Ok(())
                    });
                    if let Err(e) = result {
                        log::warn!(
                            target: TARGET,
                            "Error when sending overlay {} {bcast_type} broadcast: {e}",
                            overlay.overlay_id
                        );
                        return;
                    }
                    if transfer.seqno > max_seqno {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(Self::TIMEOUT_WAVE_MS)).await;
            }
        });
        let bcast_id = *bcast_id;
        let bcast_type = Self::broadcast_type();
        let flags = ctx.flags;
        let hops = neighbours.hops;
        let neighbours_count = neighbours.expected_count;
        self.select_broadcast_neighbours(ctx.overlay, neighbours, None);
        let mut neighbours =
            if let Some(ids) = neighbours.get_ids() { ids.clone() } else { Vec::new() };
        let overlay = ctx.overlay.clone();
        let send_method = self.send_method();
        let src_adnl_key_id = ctx.src_adnl_key_id.clone();
        let tasks = overlay.tasks.clone();
        tasks.spawn_cancelable("overlay FEC transfer", async move {
            while let Some((mut buf, seqno)) = reader.recv().await {
                if let Some(hops) = &hops {
                    buf.push(*hops)
                }
                if let Err(e) = Self::distribute_broadcast(
                    &overlay,
                    &buf,
                    &bcast_id,
                    seqno,
                    &neighbours,
                    &src_adnl_key_id,
                    &send_method,
                    #[cfg(feature = "telemetry")]
                    tag,
                )
                .await
                {
                    log::warn!(
                        target: TARGET,
                        "Error when sending overlay {} {bcast_type} broadcast: {e}",
                        overlay.overlay_id
                    );
                }
                // FixedNeighbours sends every part to one neighbour set.
                if (flags & BROADCAST_FLAG_FIXED_NEIGHBOURS) == 0 {
                    neighbours = overlay.select_broadcast_neighbours(neighbours_count, None);
                }
            }
            // Graceful close
            reader.close();
            while reader.recv().await.is_some() {}
            if let Err(e) = overlay.setup_broadcast_purge(
                bcast_id,
                #[cfg(feature = "xp25")]
                flags,
            ) {
                log::warn!(
                    target: TARGET,
                    "Cannot setup {bcast_type} broadcast {} purge after send: {e}",
                    base64_encode(&bcast_id)
                )
            }
        });
        Ok(BroadcastJob::Background(max_seqno))
    }
}

impl FecProtocol<BroadcastFec> for BroadcastFecProtocol {
    fn build_broadcast_part(
        data: Vec<u8>,
        transfer: &SendTransferFec,
        signature: Vec<u8>,
    ) -> Result<Broadcast> {
        Ok(BroadcastFec {
            src: (&transfer.src_key).try_into()?,
            certificate: transfer.certificate.clone(),
            data_hash: UInt256::with_array(transfer.data_hash),
            data_size: transfer.encoder.params().data_size,
            flags: transfer.flags as i32,
            data,
            seqno: transfer.seqno as i32,
            fec: transfer.encoder.params().clone().into_boxed(),
            date: transfer.date,
            signature,
        }
        .into_boxed())
    }

    fn calc_to_sign(
        bcast_id: &BroadcastId,
        _data_size: usize,
        part_data: &[u8],
        seqno: u32,
        date: i32,
    ) -> Result<Vec<u8>> {
        let part_data_hash: [u8; 32] = sha256_digest(part_data);
        let part_id = BroadcastFecPartId {
            broadcast_hash: UInt256::from_slice(bcast_id),
            data_hash: UInt256::with_array(part_data_hash),
            seqno: seqno as i32,
        };
        let part_hash = hash(part_id)?;
        let to_sign = BroadcastToSign { hash: UInt256::with_array(part_hash), date }.into_boxed();
        serialize_boxed(&to_sign)
    }

    fn unwrap_transfer(wrapped: &OwnedBroadcast) -> Option<&RecvTransferFec<BroadcastFec>> {
        match wrapped {
            OwnedBroadcast::RecvFec(transfer) => Some(transfer),
            _ => None,
        }
    }

    fn wrap_transfer(transfer: RecvTransferFec<BroadcastFec>) -> OwnedBroadcast {
        OwnedBroadcast::RecvFec(transfer)
    }
}

// Broadcast simple ***********************************************************

#[rustfmt::skip]
impl BroadcastParsed for BroadcastSimple {
    fn certificate(&self) -> &OverlayCertificate { &self.certificate }
    fn date(&self) -> i32 { self.date }
    fn src_key(&self) -> Result<Arc<dyn KeyOption>> { (&self.src).try_into() }
    #[cfg(feature = "telemetry")]
    fn default_tag(&self) -> u32 { BroadcastSimple::constructor_const() }
    #[cfg(feature = "xp25")]
    fn flags(&self) -> u32 { self.flags as u32 }
}

pub(crate) struct BroadcastSimpleProtocol;

impl BroadcastSimpleProtocol {
    fn build_broadcast(
        ctx: &BroadcastSendContext,
        bcast_id: &BroadcastId,
        date: i32,
    ) -> Result<BroadcastSimple> {
        let to_sign = Self::calc_to_sign(bcast_id, date)?;
        let signature = ctx.src_key.sign(&to_sign)?;
        Ok(BroadcastSimple {
            src: ctx.src_key.try_into()?,
            certificate: ctx.certificate.clone(),
            flags: ctx.flags as i32,
            data: ctx.data.object.to_vec(),
            date,
            signature,
        })
    }

    fn calc_broadcast_id(
        data: &[u8],
        src_key: &Arc<dyn KeyOption>,
        flags: u32,
    ) -> Result<BroadcastId> {
        let data_hash = sha256_digest(data);
        let bcast_id = BroadcastSimpleId {
            src: if (flags & OverlayNode::FLAG_BCAST_ANY_SENDER) != 0 {
                UInt256::ZERO
            } else {
                UInt256::from_slice(src_key.id().data())
            },
            data_hash: UInt256::with_array(data_hash),
            flags: flags as i32,
        };
        hash(bcast_id)
    }

    fn calc_to_sign(bcast_id: &BroadcastId, date: i32) -> Result<Vec<u8>> {
        let to_sign = BroadcastToSign { hash: UInt256::from(bcast_id), date }.into_boxed();
        serialize_boxed(&to_sign)
    }

    fn check_broadcast(
        bcast: &BroadcastSimple,
        ctx: &BroadcastRecvContext,
    ) -> Result<BroadcastCheckInfo> {
        let src_key: Arc<dyn KeyOption> = (&bcast.src).try_into()?;
        let flags = bcast.flags as u32;
        let bcast_id = Self::calc_broadcast_id(&bcast.data, &src_key, flags)?;
        let mut verdict = BroadcastCheckResult::Allowed;
        let dup = if add_unbound_object_to_map(&ctx.overlay.owned_broadcasts, bcast_id, || {
            Ok(OwnedBroadcast::Send)
        })? {
            verdict = ctx.overlay.broadcast_verdict(
                &src_key,
                &bcast.certificate,
                bcast.data.len(),
                false,
                (flags & BROADCAST_FLAG_ANY_SENDER) != 0,
                ctx.peers.other(),
            );
            let checked = if verdict == BroadcastCheckResult::Forbidden {
                Err(error!("Broadcast is forbidden"))
            } else {
                Self::calc_to_sign(&bcast_id, bcast.date).and_then(|to_sign| {
                    ctx.overlay.verify_broadcast_signature(
                        &src_key,
                        &to_sign,
                        &bcast.signature,
                        ctx.peers.other(),
                    )
                })
            };
            if let Err(e) = checked {
                // A refused broadcast is not registered: a valid copy may follow.
                ctx.overlay.owned_broadcasts.remove(&bcast_id);
                return Err(e);
            }
            false
        } else {
            true
        };
        let data_len = bcast.data.len();
        Ok(BroadcastCheckInfo {
            bcast_id,
            dup,
            verdict,
            data_len,
            seqno: 0,
            #[cfg(feature = "telemetry")]
            maybe_tag: if data_len >= 4 {
                let data = &bcast.data;
                Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
            } else {
                None
            },
        })
    }

    fn process_broadcast(bcast: BroadcastSimple) -> Result<(Option<BroadcastRecvInfo>, bool)> {
        let src_key: Arc<dyn KeyOption> = (&bcast.src).try_into()?;
        let info = BroadcastRecvInfo {
            packets: 1,
            data: bcast.data.into(),
            extra: None,
            recv_from: src_key.id().clone(),
        };
        Ok((Some(info), true))
    }

    /// The relayed envelope, rebuilt with the normalized certificate.
    fn relay_bytes(overlay: &Overlay, bcast: &BroadcastSimple) -> Result<Vec<u8>> {
        overlay.serialize_broadcast(
            &BroadcastSimple {
                certificate: normalized_certificate(&bcast.certificate)?,
                ..bcast.clone()
            }
            .into_boxed(),
        )
    }

    /// Application check of a `NeedCheck` simple broadcast, then delivery and
    /// relay. Runs apart from the receive path; the broadcast stays
    /// registered either way, so a refused copy is not processed again.
    fn check_then_relay(
        ctx: &BroadcastRecvContext,
        bcast_id: &BroadcastId,
        info: BroadcastRecvInfo,
        relay: Vec<u8>,
    ) {
        let overlay = ctx.overlay.clone();
        let peers = ctx.peers.clone();
        let hops = ctx.hops;
        let verdict = ctx.verdict;
        let bcast_id = *bcast_id;
        let tasks = overlay.tasks.clone();
        tasks.spawn_cancelable("overlay broadcast application check", async move {
            let approved = overlay.application_check(&info.recv_from, &info.data).await;
            let purge = overlay.setup_broadcast_purge(
                bcast_id,
                #[cfg(feature = "xp25")]
                0,
            );
            if let Err(e) = purge {
                log::warn!(target: TARGET, "Cannot setup broadcast purge: {e}");
            }
            if let Err(e) = approved {
                log::debug!(
                    target: TARGET,
                    "Application check refused broadcast {} in overlay {}: {e}",
                    base64_encode(&bcast_id),
                    overlay.overlay_id
                );
                return;
            }
            overlay.received_rawbytes.push(info);
            let mut ctx = BroadcastRecvContext {
                data: BroadcastData::Rebuilt(relay),
                hops,
                overlay: &overlay,
                peers: &peers,
                verdict,
            };
            if let Err(e) = BroadcastSimpleProtocol
                .resend_broadcast(
                    &mut ctx,
                    &bcast_id,
                    0,
                    #[cfg(feature = "telemetry")]
                    BroadcastSimple::constructor_const(),
                )
                .await
            {
                log::warn!(
                    target: TARGET,
                    "Cannot relay checked broadcast {}: {e}",
                    base64_encode(&bcast_id)
                );
            }
        });
    }
}

impl BroadcastMultistep for BroadcastSimpleProtocol {}

#[async_trait::async_trait]
impl BroadcastProtocol<BroadcastSimple> for BroadcastSimpleProtocol {
    // Common

    fn broadcast_type() -> BroadcastType {
        BroadcastType::Simple
    }

    fn calc_broadcast_neighbours(
        &self,
        overlay: &Arc<Overlay>,
        hops: Option<u8>,
    ) -> Result<BroadcastNeighbours> {
        <Self as BroadcastMultistep>::calc_broadcast_neighbours(
            overlay,
            hops,
            Overlay::SIZE_NEIGHBOURS_SHORT_BROADCAST,
        )
    }

    fn select_broadcast_neighbours(
        &self,
        overlay: &Arc<Overlay>,
        neighbours: &mut BroadcastNeighbours,
        skip: Option<&Arc<KeyId>>,
    ) {
        <Self as BroadcastMultistep>::select_broadcast_neighbours(overlay, neighbours, skip);
    }

    fn send_method(&self) -> BroadcastSendMethod {
        BroadcastSendMethod::Fast
    }

    // Receive side

    fn check_broadcast(
        &self,
        bcast: &BroadcastSimple,
        ctx: &BroadcastRecvContext,
    ) -> Result<BroadcastCheckInfo> {
        Self::check_broadcast(bcast, ctx)
    }

    async fn process_broadcast(
        &self,
        bcast: BroadcastSimple,
        ctx: &mut BroadcastRecvContext,
        bcast_id: &BroadcastId,
    ) -> Result<(Option<BroadcastRecvInfo>, bool)> {
        let relay = Self::relay_bytes(ctx.overlay, &bcast)?;
        let (info, resend) = Self::process_broadcast(bcast)?;
        if ctx.verdict != BroadcastCheckResult::Allowed {
            if let Some(info) = info {
                Self::check_then_relay(ctx, bcast_id, info, relay);
            }
            return Ok((None, false));
        }
        ctx.data = BroadcastData::Rebuilt(relay);
        Ok((info, resend))
    }

    // Send side

    fn calc_broadcast_id(
        &self,
        ctx: &BroadcastSendContext,
        _date: i32,
    ) -> Result<(BroadcastId, bool)> {
        Ok((Self::calc_broadcast_id(ctx.data.object, &ctx.src_key, ctx.flags)?, false))
    }

    fn build_broadcast(
        &mut self,
        ctx: &BroadcastSendContext,
        bcast_id: &BroadcastId,
        date: i32,
        _neighbours: &mut BroadcastNeighbours,
    ) -> Result<BroadcastJob> {
        Ok(BroadcastJob::Foreground(Self::build_broadcast(ctx, bcast_id, date)?.into_boxed()))
    }
}

// Broadcast stream simple ****************************************************

#[rustfmt::skip]
impl BroadcastParsed for BroadcastStream {
    fn certificate(&self) -> &OverlayCertificate { &self.data.certificate }
    fn date(&self) -> i32 { self.data.date }
    fn src_key(&self) -> Result<Arc<dyn KeyOption>> { (&self.data.src).try_into() }
    #[cfg(feature = "telemetry")]
    fn default_tag(&self) -> u32 { BroadcastStream::constructor_const() }
    #[cfg(feature = "xp25")]
    fn flags(&self) -> u32 { self.data.flags as u32 }
}

pub(crate) struct BroadcastStreamSimpleProtocol;

impl BroadcastMultistep for BroadcastStreamSimpleProtocol {}

#[async_trait::async_trait]
impl BroadcastProtocol<BroadcastStream> for BroadcastStreamSimpleProtocol {
    // Common

    fn broadcast_type() -> BroadcastType {
        BroadcastType::StreamSimple
    }

    fn calc_broadcast_neighbours(
        &self,
        overlay: &Arc<Overlay>,
        hops: Option<u8>,
    ) -> Result<BroadcastNeighbours> {
        <Self as BroadcastMultistep>::calc_broadcast_neighbours(
            overlay,
            hops,
            Overlay::SIZE_NEIGHBOURS_STREAM_BROADCAST,
        )
    }

    fn select_broadcast_neighbours(
        &self,
        overlay: &Arc<Overlay>,
        neighbours: &mut BroadcastNeighbours,
        skip: Option<&Arc<KeyId>>,
    ) {
        <Self as BroadcastMultistep>::select_broadcast_neighbours(overlay, neighbours, skip);
    }

    fn send_method(&self) -> BroadcastSendMethod {
        BroadcastSendMethod::Safe
    }

    // Receive side

    fn check_broadcast(
        &self,
        bcast: &BroadcastStream,
        ctx: &BroadcastRecvContext,
    ) -> Result<BroadcastCheckInfo> {
        BroadcastSimpleProtocol::check_broadcast(&bcast.data, ctx)
    }

    fn build_rebroadcast(
        &self,
        ctx: &mut BroadcastRecvContext,
        neighbours: &mut BroadcastNeighbours,
    ) -> Result<()> {
        let BroadcastData::Stream(bcast) = &mut ctx.data else {
            fail!(
                "INTERNAL ERROR: unexpected broadcast data type for {} rebroadcast",
                Self::broadcast_type()
            );
        };
        let Some(mut bcast) = bcast.take() else {
            fail!("INTERNAL ERROR: no stream data for rebroadcast");
        };
        self.select_broadcast_neighbours(ctx.overlay, neighbours, Some(ctx.peers.other()));
        let hops = neighbours.hops;
        let Some(neighbours) = neighbours.get_ids() else {
            ctx.data = BroadcastData::None;
            return Ok(());
        };
        neighbours.retain(|n| !bcast.trace.iter().any(|k| k.as_slice() == n.data()));
        for neighbour in neighbours.iter() {
            bcast.trace.push(UInt256::from_slice(neighbour.data()));
        }
        let mut buf = ctx.overlay.serialize_broadcast(&bcast.into_boxed())?;
        if let Some(hops) = hops {
            buf.push(hops);
        }
        ctx.data = BroadcastData::Buf(buf);
        Ok(())
    }

    async fn process_broadcast(
        &self,
        bcast: BroadcastStream,
        ctx: &mut BroadcastRecvContext,
        bcast_id: &BroadcastId,
    ) -> Result<(Option<BroadcastRecvInfo>, bool)> {
        let ret = BroadcastSimpleProtocol::process_broadcast(bcast.data.clone())?;
        if ctx.verdict != BroadcastCheckResult::Allowed {
            let src_key: Arc<dyn KeyOption> = (&bcast.data.src).try_into()?;
            if let Err(e) = ctx.overlay.application_check(src_key.id(), &bcast.data.data).await {
                log::debug!(
                    target: TARGET,
                    "Application check refused stream broadcast {} in overlay {}: {e}",
                    base64_encode(bcast_id),
                    ctx.overlay.overlay_id
                );
                ctx.overlay.setup_broadcast_purge(
                    *bcast_id,
                    #[cfg(feature = "xp25")]
                    0,
                )?;
                return Ok((None, false));
            }
        }
        ctx.data = BroadcastData::Stream(Some(bcast));
        Ok(ret)
    }

    // Send side

    fn calc_broadcast_id(
        &self,
        ctx: &BroadcastSendContext,
        _date: i32,
    ) -> Result<(BroadcastId, bool)> {
        let bcast_id =
            BroadcastSimpleProtocol::calc_broadcast_id(ctx.data.object, &ctx.src_key, ctx.flags)?;
        Ok((bcast_id, false))
    }

    fn build_broadcast(
        &mut self,
        ctx: &BroadcastSendContext,
        bcast_id: &BroadcastId,
        date: i32,
        neighbours: &mut BroadcastNeighbours,
    ) -> Result<BroadcastJob> {
        let bcast = BroadcastSimpleProtocol::build_broadcast(ctx, bcast_id, date)?;
        self.select_broadcast_neighbours(ctx.overlay, neighbours, None);
        let trace = if let Some(ids) = neighbours.get_ids() {
            ids.iter().map(|k| UInt256::from_slice(k.data())).collect()
        } else {
            Vec::new()
        };
        Ok(BroadcastJob::Foreground(BroadcastStream { data: bcast, trace }.into_boxed()))
    }
}

// Broadcast two-step FEC *****************************************************

#[rustfmt::skip]
impl BroadcastParsed for BroadcastTwostepFec {
    fn certificate(&self) -> &OverlayCertificate { &self.certificate }
    fn date(&self) -> i32 { self.date }
    fn src_key(&self) -> Result<Arc<dyn KeyOption>> { (&self.src).try_into() }
    #[cfg(feature = "telemetry")]
    fn default_tag(&self) -> u32 { BroadcastTwostepFec::constructor_const() }
    #[cfg(feature = "xp25")]
    fn flags(&self) -> u32 { self.flags as u32 }
}

#[rustfmt::skip]
impl FecBroadcastParsed for BroadcastTwostepFec {
    fn data_hash(&self) -> &[u8; 32] { self.data_hash.as_slice() }
    fn data_size(&self) -> usize { self.data_size as usize }
    fn wire_flags(&self) -> u32 { self.flags as u32 }
    fn fec_type(&self) -> Option<FecTypeRaptorQ> {
        if self.part.is_empty() {
            return None;
        }
        let symbol_size = self.part.len() as i32;
        Some(FecTypeRaptorQ {
            data_size: self.data_size,
            symbols_count: (self.data_size + symbol_size - 1) / symbol_size,
            symbol_size,
        })
    }
    fn extra(&self) -> Option<&[u8]> { Some(&self.extra) }
    fn part_data(&self) -> &[u8] { &self.part }
    fn seqno(&self) -> u32 { self.seqno as u32 }
    fn signature(&self) -> &[u8] { &self.signature }
}

struct BroadcastTwostepSendContext {
    neighbours: u32,
    part_size: usize,
}

pub(crate) struct BroadcastTwostepFecProtocol {
    extra: Option<Vec<u8>>,
    send_ctx: Option<BroadcastTwostepSendContext>,
}

impl BroadcastTwostepFecProtocol {
    pub(crate) fn for_recv() -> Self {
        Self { extra: None, send_ctx: None }
    }

    pub(crate) fn for_send(data: &[u8], neighbours: u32, extra: Vec<u8>) -> Result<Self> {
        if neighbours <= 3 {
            fail!("Not enough neighbours to build {} broadcast", Self::broadcast_type());
        }
        if data.is_empty() {
            fail!("Empty payload for {} broadcast", Self::broadcast_type());
        }
        let k = ((neighbours as usize) * 2 - 2) / 3;
        let part_size = (data.len() + k - 1) / k;
        let ctx = BroadcastTwostepSendContext { neighbours, part_size };
        Ok(Self { extra: Some(extra), send_ctx: Some(ctx) })
    }
}

impl BroadcastTwostep for BroadcastTwostepFecProtocol {}

#[async_trait::async_trait]
impl BroadcastProtocol<BroadcastTwostepFec> for BroadcastTwostepFecProtocol {
    // Common

    fn broadcast_type() -> BroadcastType {
        BroadcastType::TwostepFec
    }

    fn calc_broadcast_neighbours(
        &self,
        overlay: &Arc<Overlay>,
        _hops: Option<u8>,
    ) -> Result<BroadcastNeighbours> {
        Ok(<Self as BroadcastTwostep>::calc_broadcast_neighbours(overlay))
    }

    fn select_broadcast_neighbours(
        &self,
        _overlay: &Arc<Overlay>,
        neighbours: &mut BroadcastNeighbours,
        skip: Option<&Arc<KeyId>>,
    ) {
        <Self as BroadcastTwostep>::select_broadcast_neighbours(neighbours, skip);
    }

    fn send_method(&self) -> BroadcastSendMethod {
        BroadcastSendMethod::QuicOrRldp
    }

    // Receive side

    fn check_broadcast(
        &self,
        bcast: &BroadcastTwostepFec,
        _ctx: &BroadcastRecvContext,
    ) -> Result<BroadcastCheckInfo> {
        let src_key: Arc<dyn KeyOption> = (&bcast.src).try_into()?;
        let src_adnl_key_id = KeyId::from_data(*bcast.src_adnl_id.as_slice());
        Ok(BroadcastCheckInfo {
            bcast_id: <Self as BroadcastTwostep>::calc_broadcast_id(
                *bcast.data_hash.as_slice(),
                bcast.date,
                bcast.data_size as usize,
                bcast.part.len(),
                &src_key,
                &src_adnl_key_id,
                bcast.flags as u32,
                &bcast.extra,
            )?,
            dup: false,
            verdict: BroadcastCheckResult::Allowed,
            data_len: bcast.part.len(),
            seqno: bcast.seqno(),
            #[cfg(feature = "telemetry")]
            maybe_tag: None,
        })
    }

    async fn process_broadcast(
        &self,
        bcast: BroadcastTwostepFec,
        ctx: &mut BroadcastRecvContext,
        bcast_id: &BroadcastId,
    ) -> Result<(Option<BroadcastRecvInfo>, bool)> {
        let src_adnl_key_id = KeyId::from_data(*bcast.src_adnl_id.as_slice());
        let admitted =
            <Self as FecProtocol<BroadcastTwostepFec>>::admit_part(bcast, ctx, bcast_id).await?;
        // Only a part received from its origin is relayed, before any
        // application check; the check gates local delivery only.
        Ok((None, admitted.is_some() && ctx.peers.other() == &src_adnl_key_id))
    }

    // Send side

    fn calc_broadcast_id(
        &self,
        ctx: &BroadcastSendContext,
        date: i32,
    ) -> Result<(BroadcastId, bool)> {
        let Some(send_ctx) = self.send_ctx.as_ref() else {
            fail!("No send context set for {} broadcast", Self::broadcast_type());
        };
        <Self as BroadcastTwostep>::calc_broadcast_id_when_send(
            ctx,
            date,
            ctx.data.object.len(),
            send_ctx.part_size,
            self.extra.as_deref().unwrap_or_default(),
        )
    }

    fn build_broadcast(
        &mut self,
        ctx: &BroadcastSendContext,
        bcast_id: &BroadcastId,
        date: i32,
        neighbours: &mut BroadcastNeighbours,
    ) -> Result<BroadcastJob> {
        let Some(neighbours) = neighbours.get_ids() else {
            fail!(
                "No neighbours to build {} broadcast {} to",
                Self::broadcast_type(),
                base64_encode(&bcast_id)
            );
        };
        let Some(send_ctx) = self.send_ctx.take() else {
            fail!(
                "Send context is not set for {} broadcast {}",
                Self::broadcast_type(),
                base64_encode(&bcast_id)
            );
        };
        if send_ctx.neighbours != neighbours.len() as u32 {
            fail!(
                "Expected {} neighbours for {} broadcast {}, but got {}",
                send_ctx.neighbours,
                Self::broadcast_type(),
                base64_encode(&bcast_id),
                neighbours.len(),
            );
        }
        let mut transfer = SendTransferFec {
            bcast_id: *bcast_id,
            certificate: ctx.certificate.clone(),
            data_hash: sha256_digest(ctx.data.object),
            date,
            encoder: RaptorqEncoder::with_data(ctx.data.object, Some(send_ctx.part_size as u32)),
            extra: self.extra.take().unwrap_or_default(),
            flags: ctx.flags,
            seqno: 0,
            src_key: ctx.src_key.clone(),
            src_adnl_key_id: ctx.src_adnl_key_id.clone(),
            counter: ctx.overlay.allocated.send_transfers.clone().into(),
        };
        #[cfg(feature = "telemetry")]
        ctx.overlay
            .telemetry
            .send_transfers
            .update(ctx.overlay.allocated.send_transfers.load(Ordering::Relaxed));
        let bcast_id = *bcast_id;
        let neighbours = neighbours.clone();
        let overlay = ctx.overlay.clone();
        let send_method = self.send_method();
        #[cfg(feature = "xp25")]
        let flags = ctx.flags;
        #[cfg(feature = "telemetry")]
        let tag = ctx.data.tag;
        let tasks = overlay.tasks.clone();
        tasks.spawn_cancelable("overlay FEC transfer", async move {
            for i in 0..neighbours.len() {
                let bcast = match Self::prepare_part(&overlay, &mut transfer) {
                    Err(e) => {
                        log::warn!(
                            target: TARGET,
                            "Error when preparing two-step FEC broadcast: {e}"
                        );
                        return;
                    }
                    Ok(part) => part,
                };
                if let Err(e) = Self::distribute_broadcast(
                    &overlay,
                    &bcast,
                    &bcast_id,
                    i as u32,
                    &neighbours[i..i + 1],
                    &transfer.src_adnl_key_id,
                    &send_method,
                    #[cfg(feature = "telemetry")]
                    tag,
                )
                .await
                {
                    log::warn!(
                        target: TARGET,
                        "Error when distributing two-step FEC broadcast to {}: {e}",
                        neighbours[i]
                    );
                }
            }
            if let Err(e) = overlay.setup_broadcast_purge(
                bcast_id,
                #[cfg(feature = "xp25")]
                flags,
            ) {
                log::warn!(
                    target: TARGET,
                    "Cannot setup {} broadcast {} purge after send: {e}",
                    Self::broadcast_type(),
                    base64_encode(&bcast_id)
                )
            }
        });
        Ok(BroadcastJob::Background(1))
    }
}

impl FecProtocol<BroadcastTwostepFec> for BroadcastTwostepFecProtocol {
    const RECHECK_DATE_BEFORE_DECODE: bool = true;
    const TWOSTEP: bool = true;

    fn build_broadcast_part(
        data: Vec<u8>,
        transfer: &SendTransferFec,
        signature: Vec<u8>,
    ) -> Result<Broadcast> {
        Ok(BroadcastTwostepFec {
            date: transfer.date,
            flags: transfer.flags as i32,
            src: (&transfer.src_key).try_into()?,
            src_adnl_id: UInt256::from_slice(transfer.src_adnl_key_id.data()),
            certificate: transfer.certificate.clone(),
            data_hash: UInt256::with_array(transfer.data_hash),
            data_size: transfer.encoder.params().data_size as i32,
            seqno: transfer.seqno as i32,
            part: data,
            extra: transfer.extra.clone(),
            signature,
        }
        .into_boxed())
    }

    fn calc_to_sign(
        bcast_id: &BroadcastId,
        _data_size: usize,
        part_data: &[u8],
        seqno: u32,
        _date: i32,
    ) -> Result<Vec<u8>> {
        let to_sign = BroadcastTwostepFecToSign {
            id: UInt256::from_slice(bcast_id),
            seqno: seqno as i32,
            part: part_data.to_vec(),
        };
        serialize_bare(&to_sign)
    }

    fn unwrap_transfer(wrapped: &OwnedBroadcast) -> Option<&RecvTransferFec<BroadcastTwostepFec>> {
        match wrapped {
            OwnedBroadcast::RecvTwostepFec(transfer) => Some(transfer),
            _ => None,
        }
    }

    fn wrap_transfer(transfer: RecvTransferFec<BroadcastTwostepFec>) -> OwnedBroadcast {
        OwnedBroadcast::RecvTwostepFec(transfer)
    }
}

// Broadcast two-step simple **************************************************

#[rustfmt::skip]
impl BroadcastParsed for BroadcastTwostepSimple {
    fn certificate(&self) -> &OverlayCertificate { &self.certificate }
    fn date(&self) -> i32 { self.date }
    fn src_key(&self) -> Result<Arc<dyn KeyOption>> { (&self.src).try_into() }
    #[cfg(feature = "telemetry")]
    fn default_tag(&self) -> u32 { BroadcastTwostepSimple::constructor_const() }
    #[cfg(feature = "xp25")]
    fn flags(&self) -> u32 { self.flags as u32 }
}

pub(crate) struct BroadcastTwostepSimpleProtocol {
    extra: Option<Vec<u8>>,
    reliable: bool,
}

impl BroadcastTwostepSimpleProtocol {
    pub(crate) fn for_recv(reliable: bool) -> Self {
        Self { reliable, extra: None }
    }
    pub(crate) fn for_send(reliable: bool, extra: Vec<u8>) -> Self {
        Self { reliable, extra: Some(extra) }
    }
    fn calc_to_sign(bcast_id: BroadcastId, data: &[u8]) -> Result<Vec<u8>> {
        let to_sign =
            BroadcastTwostepSimpleToSign { id: UInt256::with_array(bcast_id), data: data.to_vec() };
        serialize_bare(&to_sign)
    }
}

impl BroadcastTwostep for BroadcastTwostepSimpleProtocol {}

#[async_trait::async_trait]
impl BroadcastProtocol<BroadcastTwostepSimple> for BroadcastTwostepSimpleProtocol {
    // Common

    fn broadcast_type() -> BroadcastType {
        BroadcastType::TwostepSimple
    }

    fn calc_broadcast_neighbours(
        &self,
        overlay: &Arc<Overlay>,
        _hops: Option<u8>,
    ) -> Result<BroadcastNeighbours> {
        Ok(<Self as BroadcastTwostep>::calc_broadcast_neighbours(overlay))
    }

    fn select_broadcast_neighbours(
        &self,
        _overlay: &Arc<Overlay>,
        neighbours: &mut BroadcastNeighbours,
        skip: Option<&Arc<KeyId>>,
    ) {
        <Self as BroadcastTwostep>::select_broadcast_neighbours(neighbours, skip);
    }

    fn send_method(&self) -> BroadcastSendMethod {
        if self.reliable {
            BroadcastSendMethod::QuicOrRldp
        } else {
            BroadcastSendMethod::Fast
        }
    }

    // Receive side

    fn check_broadcast(
        &self,
        bcast: &BroadcastTwostepSimple,
        ctx: &BroadcastRecvContext,
    ) -> Result<BroadcastCheckInfo> {
        let data_hash = sha256_digest(&bcast.data);
        let data_size = bcast.data.len();
        let src_key: Arc<dyn KeyOption> = (&bcast.src).try_into()?;
        let src_adnl_key_id = KeyId::from_data(*bcast.src_adnl_id.as_slice());
        let bcast_id = <Self as BroadcastTwostep>::calc_broadcast_id(
            data_hash,
            bcast.date,
            data_size,
            data_size,
            &src_key,
            &src_adnl_key_id,
            bcast.flags as u32,
            &bcast.extra,
        )?;
        let mut verdict = BroadcastCheckResult::Allowed;
        let dup = if add_unbound_object_to_map(&ctx.overlay.owned_broadcasts, bcast_id, || {
            Ok(OwnedBroadcast::Send)
        })? {
            // Two-step checks its simple carrier as FEC and never any-sender.
            verdict = ctx.overlay.broadcast_verdict(
                &src_key,
                &bcast.certificate,
                data_size,
                true,
                false,
                ctx.peers.other(),
            );
            let checked = if verdict == BroadcastCheckResult::Forbidden {
                Err(error!("Broadcast is forbidden"))
            } else {
                Self::calc_to_sign(bcast_id, &bcast.data).and_then(|to_sign| {
                    ctx.overlay.verify_broadcast_signature(
                        &src_key,
                        &to_sign,
                        &bcast.signature,
                        ctx.peers.other(),
                    )
                })
            };
            if let Err(e) = checked {
                ctx.overlay.owned_broadcasts.remove(&bcast_id);
                return Err(e);
            }
            false
        } else {
            true
        };
        let data_len = bcast.data.len();
        Ok(BroadcastCheckInfo {
            bcast_id,
            dup,
            verdict,
            data_len,
            seqno: 0,
            #[cfg(feature = "telemetry")]
            maybe_tag: if data_len >= 4 {
                let data = &bcast.data;
                Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
            } else {
                None
            },
        })
    }

    async fn process_broadcast(
        &self,
        bcast: BroadcastTwostepSimple,
        ctx: &mut BroadcastRecvContext,
        bcast_id: &BroadcastId,
    ) -> Result<(Option<BroadcastRecvInfo>, bool)> {
        // on_recv check if any runs on simple two-step path too (matches FEC path)
        if let OverlayType::Private { bcast_check: Some(check), .. } = &ctx.overlay.overlay_type {
            if let Err(reason) = check.on_recv(bcast.src_key()?.id(), Some(&bcast.extra)) {
                log::warn!(
                    target: TARGET,
                    "precheck rejected twostep-simple broadcast {} in overlay {}: {reason}",
                    base64_encode(bcast_id),
                    ctx.overlay.overlay_id
                );
                ctx.overlay.owned_broadcasts.remove(bcast_id);
                return Ok((None, false));
            }
        }
        let src_adnl_key_id = KeyId::from_data(*bcast.src_adnl_id.as_slice());
        let resend = ctx.peers.other() == &src_adnl_key_id;
        let src_key_id = bcast.src_key()?.id().clone();
        let info = BroadcastRecvInfo {
            packets: 1,
            data: bcast.data.into(),
            extra: Some(bcast.extra),
            recv_from: src_adnl_key_id,
        };
        if ctx.verdict != BroadcastCheckResult::Allowed {
            // Relay may precede the application check, which gates delivery.
            let overlay = ctx.overlay.clone();
            let bcast_id = *bcast_id;
            let tasks = overlay.tasks.clone();
            tasks.spawn_cancelable("overlay broadcast application check", async move {
                let approved = overlay.application_check(&src_key_id, &info.data).await;
                if let Err(e) = overlay.setup_broadcast_purge(
                    bcast_id,
                    #[cfg(feature = "xp25")]
                    0,
                ) {
                    log::warn!(target: TARGET, "Cannot setup broadcast purge: {e}");
                }
                match approved {
                    Ok(()) => overlay.received_rawbytes.push(info),
                    Err(e) => log::debug!(
                        target: TARGET,
                        "Application check refused two-step broadcast {} in overlay {}: {e}",
                        base64_encode(&bcast_id),
                        overlay.overlay_id
                    ),
                }
            });
            return Ok((None, resend));
        }
        Ok((Some(info), resend))
    }

    // Send side

    fn calc_broadcast_id(
        &self,
        ctx: &BroadcastSendContext,
        date: i32,
    ) -> Result<(BroadcastId, bool)> {
        let data_size = ctx.data.object.len();
        <Self as BroadcastTwostep>::calc_broadcast_id_when_send(
            ctx,
            date,
            data_size,
            data_size,
            self.extra.as_deref().unwrap_or_default(),
        )
    }

    fn build_broadcast(
        &mut self,
        ctx: &BroadcastSendContext,
        bcast_id: &BroadcastId,
        date: i32,
        _neighbours: &mut BroadcastNeighbours,
    ) -> Result<BroadcastJob> {
        let data = ctx.data.object.to_vec();
        let to_sign = Self::calc_to_sign(*bcast_id, &data)?;
        let signature = ctx.src_key.sign(&to_sign)?;
        Ok(BroadcastJob::Foreground(
            BroadcastTwostepSimple {
                date,
                flags: ctx.flags as i32,
                src: ctx.src_key.try_into()?,
                src_adnl_id: UInt256::from_slice(ctx.src_adnl_key_id.data()),
                certificate: ctx.certificate.clone(),
                data,
                extra: self.extra.take().unwrap_or_default(),
                signature,
            }
            .into_boxed(),
        ))
    }
}

#[cfg(test)]
#[path = "broadcast_date_tests.rs"]
mod date_tests;

#[cfg(test)]
#[path = "broadcast_privacy_tests.rs"]
mod privacy_tests;

#[cfg(test)]
#[path = "broadcast_send_tests.rs"]
mod send_tests;
