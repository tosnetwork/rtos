// Copyright 2017-2020 Telegram Systems LLP
// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Stateful RLDP2 outbound scheduling, with a clock supplied by the connection.
//! Ported from TOS1181/TON857b RLDP2 connection, sender and congestion controller.
use super::timer::TimerHeap;
use super::{FecHelper, PART_SIZE, SYMBOL_SIZE};
use crate::fec::{Algorithm, Encoder};
use anyhow::{ensure, Result};
use rtos_api::{
    ton::{
        fec::{type_::RaptorQ, Type},
        rldp2::messagepart::MessagePart,
    },
    IntoBoxed, RldpChunk, WireProfile,
};
use rtos_block::UInt256;
use std::collections::{BTreeMap, VecDeque};
#[path = "outbound/stats.rs"]
mod stats;
use stats::{Bandwidth, Bbr, Loss, Pacer, PacketInfo, Rtt};

pub type TransferId = [u8; 32];
pub const MAX_OUTBOUND_TRANSFERS: usize = 256;

/// Events are drained by the owning connection after its receive/part callbacks.
#[derive(Default)]
pub struct OutboundEvents {
    pub packets: Vec<Vec<u8>>,
    pub completed: Vec<(TransferId, std::result::Result<(), String>)>,
    pub wakeup: Option<f64>,
}

#[derive(Clone, Copy)]
struct Packet {
    seqno: u32,
    sent_at: f64,
    in_flight: bool,
    bandwidth: PacketInfo,
}
#[derive(Default)]
struct SenderPackets {
    packets: VecDeque<Packet>,
    in_flight: u32,
    received: u32,
    last_seqno: u32,
    max_packet: Option<Packet>,
    total_ack: u32,
    total_lost: u32,
    prev_ack: u32,
    prev_lost: u32,
    left_ack: u32,
}
impl SenderPackets {
    fn get_mut(&mut self, seqno: u32) -> Option<&mut Packet> {
        let first = self.packets.front()?.seqno;
        self.packets.get_mut(seqno.checked_sub(first)? as usize)
    }
    fn mark(&mut self, seqno: u32, acknowledged: bool) {
        let Some(packet) = self.get_mut(seqno) else {
            return;
        };
        if !packet.in_flight {
            return;
        }
        packet.in_flight = false;
        self.in_flight -= 1;
        if acknowledged {
            self.left_ack = self.left_ack.saturating_sub(1);
            self.total_ack = self.total_ack.wrapping_add(1);
        } else {
            self.total_lost = self.total_lost.wrapping_add(1);
        }
    }
    fn ack(&mut self, max: u32, mask: u32, count: u32) -> (u32, bool) {
        let max = max.min(self.last_seqno);
        let count = count.min(max);
        let received = count.saturating_sub(self.received);
        if received > 0 {
            self.left_ack = self.left_ack.wrapping_add(received).min(self.in_flight);
            self.received = count;
        }
        if self.max_packet.is_some_and(|p| p.seqno > max) {
            return (received, false);
        }
        let Some(packet) = self.get_mut(max).copied() else {
            return (received, false);
        };
        let updated = self.max_packet.is_none_or(|p| p.seqno < max);
        if updated {
            self.max_packet = Some(packet);
        }
        for i in 0..32 {
            if mask & (1 << i) == 0 {
                continue;
            }
            let Some(seqno) = max.checked_sub(i) else {
                break;
            };
            if self.get_mut(seqno).is_none() {
                break;
            }
            self.mark(seqno, true);
        }
        (received, updated)
    }
    fn drop_before(&mut self, sent_at: f64, seqno: u32) -> (u32, u32) {
        while let Some(packet) = self.packets.front() {
            if packet.in_flight && packet.sent_at >= sent_at && packet.seqno >= seqno {
                break;
            }
            let seqno = packet.seqno;
            self.mark(seqno, self.left_ack > 0);
            self.packets.pop_front();
        }
        let counts = (
            self.total_ack.wrapping_sub(self.prev_ack),
            self.total_lost.wrapping_sub(self.prev_lost),
        );
        self.prev_ack = self.total_ack;
        self.prev_lost = self.total_lost;
        counts
    }
}

struct Part {
    encoder: Encoder,
    sender: SenderPackets,
    extra: u32,
    probe_at: f64,
    probe_k: u32,
}
impl Part {
    fn new(data: Vec<u8>) -> Result<Self> {
        let encoder = Encoder::new(Algorithm::RaptorQ, data, SYMBOL_SIZE as u32)?;
        let extra = FecHelper {
            symbols_count: encoder.parameters().symbols_count,
            received_symbols_count: 0,
        }
        .remaining()
        .unwrap();
        Ok(Self { encoder, sender: SenderPackets::default(), extra, probe_at: 0.0, probe_k: 1 })
    }
    fn next(&self, only_probe: bool, now: f64) -> std::result::Result<(u32, bool), f64> {
        let regular = !only_probe && self.extra > self.sender.in_flight;
        if regular || self.probe_at <= now {
            Ok((self.sender.last_seqno.wrapping_add(1), !regular))
        } else {
            Err(self.probe_at)
        }
    }
    fn sent(&mut self, seqno: u32, probe: bool, now: f64, rtt: &Rtt, bandwidth: &Bandwidth) {
        let first = self.sender.packets.front().map_or(now, |p| p.sent_at.min(now));
        self.sender.packets.push_back(Packet {
            seqno,
            sent_at: now,
            in_flight: true,
            bandwidth: bandwidth.sent(first),
        });
        self.sender.last_seqno = seqno;
        self.sender.in_flight += 1;
        self.probe_at = now + rtt.probe_delay(self.probe_k);
        self.probe_k = if probe { (self.probe_k * 2).min(10) } else { 1 };
    }
    fn ack(
        &mut self,
        max: u32,
        mask: u32,
        count: u32,
        now: f64,
        rtt: &mut Rtt,
        bandwidth: &mut Bandwidth,
        loss: &mut Loss,
    ) -> Result<()> {
        let (received, updated) = self.sender.ack(max, mask, count);
        if !updated {
            return Ok(());
        }
        let packet = self.sender.max_packet.unwrap();
        rtt.sample(now - packet.sent_at, now);
        bandwidth.ack(packet.bandwidth, packet.sent_at, now, received);
        let (ack, lost) =
            self.sender.drop_before(now - rtt.loss_delay(), packet.seqno.saturating_sub(3));
        loss.update(ack, lost);
        let remaining = FecHelper {
            symbols_count: self.encoder.parameters().symbols_count,
            received_symbols_count: self.sender.received,
        }
        .remaining()
        .ok_or_else(|| anyhow::anyhow!("RLDP2 FEC target overflow"))?;
        self.extra = loss.send_n(remaining);
        Ok(())
    }
}

struct Transfer {
    data: Vec<u8>,
    parts: BTreeMap<u32, Part>,
    next_part: u32,
}
impl Transfer {
    fn prepare_parts(&mut self) -> Result<()> {
        while self.parts.len() < 20 {
            let offset = self.next_part as usize * PART_SIZE as usize;
            if offset >= self.data.len() {
                break;
            }
            let end = self.data.len().min(offset + PART_SIZE as usize);
            self.parts.insert(self.next_part, Part::new(self.data[offset..end].to_vec())?);
            self.next_part += 1;
        }
        Ok(())
    }
    fn done(&self) -> bool {
        self.next_part as usize * PART_SIZE as usize >= self.data.len() && self.parts.is_empty()
    }
}

/// One authenticated peer connection's outbound state. The owner supplies a
/// monotonic clock (seconds); all packets in a run use the same instant.
#[derive(Default)]
pub struct OutboundConnection {
    transfers: BTreeMap<TransferId, Transfer>,
    in_flight: u32,
    rtt: Rtt,
    bandwidth: Bandwidth,
    loss: Loss,
    bbr: Bbr,
    pacer: Pacer,
    completed: Vec<(TransferId, std::result::Result<(), String>)>,
    started: u64,
    deadlines: TimerHeap<TransferId>,
}
impl OutboundConnection {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn transfer_count(&self) -> usize {
        self.transfers.len()
    }
    pub fn in_flight_count(&self) -> u32 {
        self.in_flight
    }
    pub fn started_count(&self) -> u64 {
        self.started
    }

    /// Zero ids draw a random id, as in the product connection. The caller can
    /// supply a nonzero id when it needs to bind a response to a local request.
    pub fn send(
        &mut self,
        id: TransferId,
        data: Vec<u8>,
        now: f64,
        deadline: Option<f64>,
    ) -> Result<bool> {
        Ok(self.send_with_id(id, data, now, deadline)?.is_some())
    }
    /// Returns the actual generated transfer ID so the owning connection can manage a shared timer heap.
    pub fn send_with_id(
        &mut self,
        mut id: TransferId,
        data: Vec<u8>,
        now: f64,
        deadline: Option<f64>,
    ) -> Result<Option<TransferId>> {
        ensure!(
            now.is_finite() && now >= 0.0 && deadline.is_none_or(|d| d.is_finite() && d > 0.0),
            "invalid monotonic deadline"
        );
        ensure!(data.len() <= i64::MAX as usize, "RLDP2 transfer exceeds signed wire length");
        if id == [0; 32] {
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut id);
        } else if self.transfers.contains_key(&id) {
            return Ok(None);
        }
        if self.transfers.len() >= MAX_OUTBOUND_TRANSFERS {
            return Ok(None);
        }
        self.transfers.insert(id, Transfer { data, parts: BTreeMap::new(), next_part: 0 });
        if let Some(deadline) = deadline {
            self.deadlines.insert(id, deadline);
        }
        self.started += 1;
        Ok(Some(id))
    }
    pub fn remove(&mut self, id: TransferId) -> bool {
        let Some(transfer) = self.transfers.remove(&id) else {
            return false;
        };
        for part in transfer.parts.values() {
            self.in_flight -= part.sender.in_flight;
        }
        self.deadlines.erase(&id);
        true
    }
    pub fn on_complete(&mut self, id: TransferId, part: i32) {
        let Some(transfer) = self.transfers.get_mut(&id) else {
            return;
        };
        if let Some(part) = transfer.parts.remove(&(part as u32)) {
            self.in_flight -= part.sender.in_flight;
        }
        if transfer.done() {
            self.transfers.remove(&id);
            self.deadlines.erase(&id);
            self.completed.push((id, Ok(())));
        }
    }
    pub fn on_confirm(
        &mut self,
        id: TransferId,
        part: i32,
        max: u32,
        mask: u32,
        count: u32,
        now: f64,
    ) -> Result<()> {
        ensure!(now.is_finite() && now >= 0.0, "invalid monotonic time");
        let Some(part) = self.transfers.get_mut(&id).and_then(|t| t.parts.get_mut(&(part as u32)))
        else {
            return Ok(());
        };
        let before = part.sender.in_flight;
        let result =
            part.ack(max, mask, count, now, &mut self.rtt, &mut self.bandwidth, &mut self.loss);
        self.in_flight -= before - part.sender.in_flight;
        result
    }
    pub fn run(&mut self, now: f64) -> Result<OutboundEvents> {
        ensure!(now.is_finite() && now >= 0.0, "invalid monotonic time");
        self.bbr.step(&self.rtt, &self.bandwidth, self.in_flight, now);
        self.pacer.set_speed(self.bbr.rate());
        let window = self.bbr.window();
        let mut events = OutboundEvents::default();
        let mut queue: VecDeque<_> = self.transfers.keys().copied().collect();
        while let Some(id) = queue.pop_front() {
            let transfer = self.transfers.get_mut(&id).unwrap();
            transfer.prepare_parts()?;
            let mut only_probe = self.in_flight > window;
            let mut wakeup = None;
            if self.pacer.wakeup > now {
                only_probe = true;
                relax(&mut wakeup, self.pacer.wakeup);
            }
            let mut sent = false;
            for (&index, part) in &mut transfer.parts {
                match part.next(only_probe, now) {
                    Err(at) => relax(&mut wakeup, at),
                    Ok((seqno, probe)) => {
                        let wire_seqno = seqno.wrapping_sub(1);
                        let (_, data) = part.encoder.symbol(wire_seqno)?;
                        let p = part.encoder.parameters();
                        let message = MessagePart(RldpChunk {
                            transfer_id: UInt256::with_array(id),
                            fec_type: Type::Fec_RaptorQ(RaptorQ {
                                data_size: p.data_size as i32,
                                symbol_size: p.symbol_size as i32,
                                symbols_count: p.symbols_count as i32,
                            }),
                            part: index as i32,
                            total_size: transfer.data.len() as i64,
                            seqno: wire_seqno as i32,
                            data,
                        });
                        events.packets.push(WireProfile::T0.serialize(&message.into_boxed())?);
                        if !probe {
                            self.pacer.send(now);
                        }
                        part.sent(seqno, probe, now, &self.rtt, &self.bandwidth);
                        self.in_flight += 1;
                        sent = true;
                        break;
                    }
                }
            }
            if sent {
                queue.push_back(id);
            } else if let Some(at) = wakeup {
                relax(&mut events.wakeup, at);
            }
        }
        if self.in_flight > window || self.in_flight == 0 {
            self.bandwidth.pause(now);
        }
        // CPP runs its limit loop after sending, so even an expired outbound
        // transfer gets this run's send turn before reporting timeout.
        while let Some((id, _)) = self.deadlines.pop_due(now) {
            self.remove(id);
            self.completed.push((id, Err("timeout".into())));
        }
        if let Some((at, _)) = self.deadlines.peek() {
            relax(&mut events.wakeup, at);
        }
        events.completed = std::mem::take(&mut self.completed);
        Ok(events)
    }
}

fn relax(slot: &mut Option<f64>, value: f64) {
    if slot.is_none_or(|old| value < old) {
        *slot = Some(value);
    }
}
