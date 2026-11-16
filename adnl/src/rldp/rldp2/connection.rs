// Copyright 2017-2020 Telegram Systems LLP
// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Owned RLDP2 connection state. Times are monotonic seconds since connection creation.
use super::{
    budget::{self, InboundBudget, Kind, PeerId, Reservation},
    outbound::OutboundConnection,
    timer::TimerHeap,
    DEFAULT_MTU, PART_SIZE, SYMBOL_SIZE,
};
use crate::fec::{Decoder, PeerFecType, Refusal};
use rtos_api::{
    ton::rldp2::{
        messagepart::{Complete, Confirm},
        MessagePart,
    },
    IntoBoxed, WireProfile,
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
    time::Instant,
};
pub type TransferId = [u8; 32];
const MAX_TRANSFERS: usize = 256;
const MAX_COMPLETED: usize = 2048;

#[derive(Default)]
pub struct Events {
    pub received: Vec<(TransferId, Result<Vec<u8>, Refusal>)>,
    pub parts: Vec<(TransferId, u32, u64)>,
    pub packets: Vec<Vec<u8>>,
    pub sent: Vec<(TransferId, Result<(), String>)>,
    pub wakeup: Option<f64>,
}
#[derive(Default)]
struct Receiver {
    max_seqno: u32,
    mask: u32,
    count: u32,
    ack_at: Option<f64>,
    repeats: u32,
}
impl Receiver {
    fn receive(&mut self, seqno: u32, now: f64) -> bool {
        if seqno > self.max_seqno {
            let diff = seqno - self.max_seqno;
            self.mask = if diff >= 32 { 0 } else { self.mask << diff };
            self.max_seqno = seqno;
        }
        let offset = self.max_seqno - seqno;
        if offset >= 32 || self.mask & (1 << offset) != 0 {
            return false;
        }
        self.mask |= 1 << offset;
        self.count = self.count.wrapping_add(1);
        self.repeats = 0;
        relax(&mut self.ack_at, now + 0.001);
        true
    }
    fn ack_sent(&mut self, now: f64) {
        self.repeats += 1;
        self.ack_at = (self.repeats <= 7).then(|| now + 0.001 * (1u32 << self.repeats) as f64);
    }
}
fn relax(time: &mut Option<f64>, value: f64) {
    if time.is_none_or(|old| value < old) {
        *time = Some(value);
    }
}
struct Part {
    decoder: Decoder,
    receiver: Receiver,
    reservation: Reservation,
    solver_bytes: u64,
    assembly_bytes: u64,
}
struct Inbound {
    total: u64,
    offset: u64,
    next_part: u32,
    parts: BTreeMap<u32, Part>,
    decoded: Vec<Vec<u8>>,
    finished: Vec<Reservation>,
    kind: Kind,
}
impl Inbound {
    fn new(total: u64, kind: Kind) -> Self {
        Self {
            total,
            offset: 0,
            next_part: 0,
            parts: BTreeMap::new(),
            decoded: Vec::new(),
            finished: Vec::new(),
            kind,
        }
    }
    fn open_part(
        &mut self,
        index: u32,
        fec: &PeerFecType,
        budget: &Arc<InboundBudget>,
        peer: PeerId,
    ) -> Result<bool, Refusal> {
        if self.parts.contains_key(&index) {
            return Ok(true);
        }
        if index != self.next_part || self.parts.len() >= 20 {
            return Ok(false);
        }
        let p = fec.parameters();
        let size = p.data_size as u64;
        if size > self.total - self.offset {
            return Err(Refusal("unclassified"));
        }
        let cost =
            budget::decoder_reservation_bytes(size, p.symbol_size as u64, p.symbols_count as u64)
                .ok_or(Refusal("unclassified"))?;
        let solver_bytes =
            budget::solver_working_bytes(p.symbol_size as u64, p.symbols_count as u64)
                .ok_or(Refusal("unclassified"))?;
        let assembly_bytes =
            if index > 0 && size == self.total - self.offset { self.total } else { 0 };
        let charge = cost.checked_add(assembly_bytes).ok_or(Refusal("unclassified"))?;
        let Some(reservation) = budget.reserve(self.kind, peer, 1, charge, solver_bytes) else {
            return Err(Refusal("budget"));
        };
        // Match CPP order: reserve before creating the codec; an error terminates the transfer.
        self.offset += size;
        let decoder = fec.create_decoder()?;
        self.parts.insert(
            index,
            Part {
                decoder,
                receiver: Receiver::default(),
                reservation,
                solver_bytes,
                assembly_bytes,
            },
        );
        self.decoded.push(Vec::new());
        self.next_part += 1;
        Ok(true)
    }
    fn finish_part(&mut self, index: u32) -> (u64, bool) {
        let Part { decoder, mut reservation, assembly_bytes, .. } =
            self.parts.remove(&index).unwrap();
        let data = decoder.into_decoded_data().expect("successful decode owns data");
        let size = data.len() as u64;
        reservation.shrink_to(0, size + assembly_bytes);
        self.finished.push(reservation);
        self.decoded[index as usize] = data;
        (size, self.parts.is_empty() && self.offset == self.total)
    }
    fn assemble(mut self) -> Vec<u8> {
        if self.decoded.len() == 1 {
            return self.decoded.pop().unwrap();
        }
        let mut data = Vec::with_capacity(self.total as usize);
        for part in &self.decoded {
            data.extend_from_slice(part);
        }
        data
    }
}
struct Limit {
    max_size: u64,
    solicited: bool,
}
/// One authenticated peer's RLDP2 state. The caller supplies the authenticated peer identity.
/// Admission tokens account protocol costs; they are not an allocator/whole-process memory cap.
pub struct Connection {
    peer: PeerId,
    budget: Arc<InboundBudget>,
    default_mtu: u64,
    inbound: BTreeMap<TransferId, Inbound>,
    outbound: OutboundConnection,
    limits: BTreeMap<TransferId, Limit>,
    outstanding: usize,
    timers: TimerHeap<(TransferId, bool)>,
    completed: BTreeSet<TransferId>,
    completed_queue: VecDeque<(TransferId, f64)>,
    pending: Events,
    epoch: Instant,
}
impl Connection {
    pub fn new(peer: PeerId) -> Self {
        Self::with_budget(peer, InboundBudget::process_default())
    }
    pub fn with_budget(peer: PeerId, budget: Arc<InboundBudget>) -> Self {
        Self {
            peer,
            budget,
            default_mtu: DEFAULT_MTU,
            inbound: BTreeMap::new(),
            outbound: OutboundConnection::new(),
            limits: BTreeMap::new(),
            outstanding: 0,
            timers: TimerHeap::default(),
            completed: BTreeSet::new(),
            completed_queue: VecDeque::new(),
            pending: Events::default(),
            epoch: Instant::now(),
        }
    }
    pub fn now(&self) -> f64 {
        self.epoch.elapsed().as_secs_f64()
    }
    pub fn set_default_mtu(&mut self, value: u64) {
        self.default_mtu = value;
    }
    pub fn inbound_transfer_count(&self) -> usize {
        self.inbound.len()
    }
    pub fn outbound_transfer_count(&self) -> usize {
        self.outbound.transfer_count()
    }
    pub fn send(
        &mut self,
        id: TransferId,
        data: Vec<u8>,
        deadline: Option<f64>,
    ) -> anyhow::Result<bool> {
        self.send_at(id, data, self.now(), deadline)
    }
    pub fn send_at(
        &mut self,
        id: TransferId,
        data: Vec<u8>,
        now: f64,
        deadline: Option<f64>,
    ) -> anyhow::Result<bool> {
        anyhow::ensure!(
            deadline.is_none_or(|at| at.is_finite() && at > 0.0),
            "invalid monotonic deadline"
        );
        let Some(id) = self.outbound.send_with_id(id, data, now, None)? else {
            return Ok(false);
        };
        if let Some(at) = deadline {
            assert!(self.timers.insert((id, false), at));
        }
        Ok(true)
    }
    pub fn completed_transfer_count(&self) -> usize {
        self.completed.len()
    }
    pub fn outstanding_requests(&self) -> usize {
        self.outstanding
    }
    /// A local request, never a wire field, grants solicited admission under this exact ID.
    pub fn set_receive_limits(&mut self, id: TransferId, deadline: f64, max_size: u64) -> bool {
        assert!(deadline.is_finite() && deadline > 0.0);
        if self.limits.get(&id).is_some_and(|limit| limit.solicited) {
            return false;
        }
        if self.outstanding >= MAX_TRANSFERS {
            self.pending.received.push((id, Err(Refusal("unclassified"))));
            return false;
        }
        if self.limits.contains_key(&id) {
            self.drop_limit(&id);
            self.inbound.remove(&id);
        }
        self.limits.insert(id, Limit { max_size, solicited: true });
        assert!(self.timers.insert((id, true), deadline));
        self.outstanding += 1;
        true
    }
    /// Local API cancellation is serialized with decoding by the owned driver.
    /// An unknown ID must not create a completed-cache entry.
    pub(crate) fn cancel_transfer(&mut self, id: TransferId, inbound: bool) {
        if inbound {
            if self.limits.contains_key(&id) || self.inbound.contains_key(&id) {
                self.complete(id, self.now());
                self.drop_limit(&id);
                self.pending.received.push((id, Err(Refusal("cancelled"))));
            }
        } else if self.outbound.remove(id) {
            self.timers.erase(&(id, false));
            self.pending.sent.push((id, Err("cancelled".into())));
        }
    }

    fn drop_limit(&mut self, id: &TransferId) {
        self.timers.erase(&(*id, true));
        if let Some(limit) = self.limits.remove(id) {
            if limit.solicited {
                self.outstanding -= 1;
            }
        }
    }
    fn complete(&mut self, id: TransferId, now: f64) {
        self.inbound.remove(&id);
        self.completed.insert(id);
        self.completed_queue.push_back((id, now + 20.0));
        while self.completed_queue.len() > MAX_COMPLETED
            || (self.completed_queue.len() > 128
                && self.completed_queue.front().is_some_and(|x| x.1 <= now))
        {
            let (id, _) = self.completed_queue.pop_front().unwrap();
            self.completed.remove(&id);
        }
    }
    fn send_complete(&mut self, id: TransferId, part: i32) {
        self.pending.packets.push(
            WireProfile::T0
                .serialize(&Complete { transfer_id: id.into(), part }.into_boxed())
                .expect("fixed TL framing"),
        );
    }
    pub fn receive_raw(&mut self, bytes: &[u8]) {
        self.receive_raw_at(bytes, self.now());
    }
    /// `now` must be finite, nonnegative, and monotonic with prior connection calls.
    pub fn receive_raw_at(&mut self, bytes: &[u8], now: f64) {
        let Ok(message) =
            crate::adnl::wire::decode::<MessagePart>(bytes, |reason| Refusal(reason).into())
        else {
            return;
        };
        match message {
            MessagePart::Rldp2_MessagePart(part) => self.receive_part(part.0, now),
            MessagePart::Rldp2_Complete(message) => {
                let id = *message.transfer_id.as_array();
                let before = self.outbound.transfer_count();
                self.outbound.on_complete(id, message.part);
                if self.outbound.transfer_count() < before {
                    self.timers.erase(&(id, false));
                }
            }
            MessagePart::Rldp2_Confirm(message) => {
                if let Err(error) = self.outbound.on_confirm(
                    *message.transfer_id.as_array(),
                    message.part,
                    message.max_seqno as u32,
                    message.received_mask as u32,
                    message.received_count as u32,
                    now,
                ) {
                    log::error!("RLDP2 outbound confirmation: {error}");
                }
            }
        }
    }
    fn receive_part(&mut self, packet: rtos_api::RldpChunk, now: f64) {
        let id = *packet.transfer_id.as_array();
        if self.completed.contains(&id) {
            self.send_complete(id, packet.part);
            return;
        }
        let Ok(total) = u64::try_from(packet.total_size) else {
            return;
        };
        let Ok(fec) = PeerFecType::from_tl(&packet.fec_type) else {
            return;
        };
        if fec.parameters().symbol_size as u64 != SYMBOL_SIZE {
            return;
        }
        let Ok(seqno) = u32::try_from(packet.seqno) else {
            return;
        };
        let limit = self.limits.get(&id);
        let max_size = limit.filter(|x| x.max_size != 0).map_or(self.default_mtu, |x| x.max_size);
        let has_limit = limit.is_some();
        let kind =
            if limit.is_some_and(|x| x.solicited) { Kind::Solicited } else { Kind::Unsolicited };
        if total > max_size {
            return;
        }
        let index = packet.part as u32;
        let n_parts = total.div_ceil(PART_SIZE);
        if index as u64 >= n_parts {
            return;
        }
        let expected = if index as u64 + 1 == n_parts && total % PART_SIZE != 0 {
            total % PART_SIZE
        } else {
            PART_SIZE
        };
        if fec.parameters().data_size as u64 != expected {
            return;
        }
        let created = !self.inbound.contains_key(&id);
        if created {
            if self.inbound.len() >= MAX_TRANSFERS || index != 0 {
                return;
            }
            self.inbound.insert(id, Inbound::new(total, kind));
        }
        let inbound = self.inbound.get_mut(&id).unwrap();
        let result = inbound.open_part(index, &fec, &self.budget, self.peer);
        match result {
            Err(Refusal("budget")) => {
                if created {
                    self.inbound.remove(&id);
                }
                return;
            }
            Err(error) => {
                self.drop_limit(&id);
                self.complete(id, now);
                self.pending.received.push((id, Err(error)));
                return;
            }
            Ok(false) => {
                if index < inbound.next_part {
                    self.send_complete(id, packet.part);
                }
                self.add_unsolicited_limit(id, created, has_limit, max_size, now);
                return;
            }
            Ok(true) => {}
        }
        let part = inbound.parts.get_mut(&index).unwrap();
        if part.receiver.receive(seqno + 1, now) {
            if let Err(error) = part.decoder.add_symbol(seqno, packet.data) {
                self.drop_limit(&id);
                self.complete(id, now);
                self.pending.received.push((id, Err(error)));
                return;
            }
            let solver = part
                .decoder
                .may_try_decode()
                .then(|| self.budget.reserve(inbound.kind, self.peer, 0, part.solver_bytes, 0))
                .flatten();
            if let Some(solver) = solver {
                let decoded = part.decoder.try_decode_with_encoder(false).is_ok();
                drop(solver);
                if decoded {
                    let (size, done) = inbound.finish_part(index);
                    self.pending.parts.push((id, index, size));
                    if done {
                        let data = self.inbound.remove(&id).unwrap().assemble();
                        self.drop_limit(&id);
                        self.complete(id, now);
                        self.pending.received.push((id, Ok(data)));
                        return;
                    }
                }
            }
        }
        self.add_unsolicited_limit(id, created, has_limit, max_size, now);
    }
    fn add_unsolicited_limit(
        &mut self,
        id: TransferId,
        created: bool,
        has_limit: bool,
        max_size: u64,
        now: f64,
    ) {
        if created && !has_limit {
            self.limits.insert(id, Limit { max_size, solicited: false });
            assert!(self.timers.insert((id, true), now + 10.0));
        }
    }
    pub fn run(&mut self) -> anyhow::Result<Events> {
        self.run_at(self.now())
    }
    /// Drive timers using the same monotonic epoch as `receive_raw_at`.
    pub fn run_at(&mut self, now: f64) -> anyhow::Result<Events> {
        let outbound = self.outbound.run(now)?;
        self.pending.packets.extend(outbound.packets);
        self.pending.sent.extend(outbound.completed);
        let mut wakeup = outbound.wakeup;
        for (id, inbound) in &mut self.inbound {
            for (index, part) in &mut inbound.parts {
                if part.receiver.ack_at.is_some_and(|at| at <= now) {
                    let ack = &part.receiver;
                    self.pending.packets.push(
                        WireProfile::T0
                            .serialize(
                                &Confirm {
                                    transfer_id: (*id).into(),
                                    part: *index as i32,
                                    max_seqno: ack.max_seqno as i32,
                                    received_mask: ack.mask as i32,
                                    received_count: ack.count as i32,
                                }
                                .into_boxed(),
                            )
                            .expect("fixed TL framing"),
                    );
                    part.receiver.ack_sent(now);
                }
                if let Some(at) = part.receiver.ack_at {
                    relax(&mut wakeup, at);
                }
            }
        }
        // The same indexed four-ary heap as CPP preserves equal-deadline callback order.
        while let Some(((id, inbound), _)) = self.timers.pop_due(now) {
            if inbound {
                self.complete(id, now);
                self.pending.received.push((id, Err(Refusal("unclassified"))));
                self.drop_limit(&id);
            } else if self.outbound.remove(id) {
                self.pending.sent.push((id, Err("timeout".into())));
            }
        }
        if let Some((at, _)) = self.timers.peek() {
            relax(&mut wakeup, at);
        }
        let mut events = std::mem::take(&mut self.pending);
        events.wakeup = wakeup;
        Ok(events)
    }
}
