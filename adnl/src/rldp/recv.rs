/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
#[cfg(feature = "debug")]
use crate::rldp::LossFn;
use crate::{
    adnl::common::{AdnlPeers, CountedObject, Counter, TaggedByteSlice},
    declare_counted,
    node::AdnlNode,
    rldp::{Chunk, Constraints, RldpNode, TransferId},
};
use rtos_api::{
    serialize_bare_inplace,
    ton::{
        fec::{type_::RaptorQ as FecTypeRaptorQ, Type as FecType},
        rldp::messagepart::{
            Complete as RldpComplete, Confirm as RldpConfirm, MessagePart as RldpMessagePart,
        },
        rldp2::messagepart::{
            Complete as Rldp2Complete, Confirm as Rldp2Confirm, MessagePart as Rldp2MessagePart,
        },
    },
};
#[cfg(feature = "telemetry")]
use rtos_api::{BareSerialize, Constructor};
use rtos_block::{error, fail, Result, UInt256};
#[cfg(feature = "debug")]
use std::sync::atomic::AtomicPtr;
use std::{
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

enum Complete {
    V1(RldpComplete),
    V2(Rldp2Complete),
}

enum Confirm {
    V1(RldpConfirm),
    V2(Rldp2Confirm),
}

/// RaptorQ decoder
pub struct RaptorqDecoder {
    engine: raptorq::Decoder,
    params: FecTypeRaptorQ,
}

impl RaptorqDecoder {
    /// Construct with parameters
    pub fn with_params(params: FecTypeRaptorQ) -> Result<Self> {
        const MAX_SOURCE_SYMBOLS: i32 = 56_403; // K'_max per RFC 6330 §5.1.2
        if params.symbol_size <= 0 {
            fail!("Invalid FEC params: symbol_size must be > 0, got {}", params.symbol_size);
        }
        if params.data_size <= 0 {
            fail!("Invalid FEC params: data_size must be > 0, got {}", params.data_size);
        }
        let config = if params.symbol_size as usize == Constraints::SYMBOL {
            raptorq::ObjectTransmissionInformation::with_defaults(
                params.data_size as u64,
                params.symbol_size as u16,
            )
        } else {
            // Two-step broadcast case: symbol_size was set by the sender without alignment
            // rounding (alignment=1). Use the same config as the encoder.
            // symbol_size can exceed u16::MAX for large blocks with few validators
            // (matches C++ behaviour which uses size_t for symbol_size).
            //
            // With source_blocks=1, raptorq asserts ceil(data_size/symbol_size) <=
            // MAX_SOURCE_SYMBOLS_PER_BLOCK (K'_max = 56403, RFC 6330 §5.1.2).
            // Validate before calling to prevent a panic on malformed network messages.
            let source_symbols = (params.data_size as i64 + params.symbol_size as i64 - 1)
                / params.symbol_size as i64;
            if source_symbols > MAX_SOURCE_SYMBOLS as i64 {
                fail!(
                    "Invalid FEC params: source symbol count {source_symbols} \
                    exceeds raptorq limit {MAX_SOURCE_SYMBOLS} (data_size={}, symbol_size={})",
                    params.data_size,
                    params.symbol_size
                );
            }
            raptorq::ObjectTransmissionInformation::new(
                params.data_size as u64,
                params.symbol_size as u32,
                1,
                1,
                1,
            )
        };
        Ok(Self { engine: raptorq::Decoder::new(config), params })
    }

    /// Decode
    pub fn decode(&mut self, seqno: u32, data: &[u8]) -> Option<Vec<u8>> {
        let packet = raptorq::EncodingPacket::new(raptorq::PayloadId::new(0, seqno), data.to_vec());
        self.engine.decode(packet)
    }

    /// Parameters
    pub fn params(&self) -> &FecTypeRaptorQ {
        &self.params
    }
}

pub(crate) struct RecvContext {
    pub(crate) adnl: Arc<AdnlNode>,
    pub(crate) peers: AdnlPeers,
    pub(crate) queue_reader: tokio::sync::mpsc::UnboundedReceiver<Chunk>,
    pub(crate) recv_transfer: RecvTransfer,
    pub(crate) transfer_id: TransferId,
    #[cfg(feature = "debug")]
    pub(crate) loss_fn: Option<LossFn>,
}

impl RecvContext {
    pub(crate) async fn send_confirmations(&mut self) -> Result<u32> {
        let RecvParts::V2(parts) = &mut self.recv_transfer.parts else {
            fail!("RLDP version mismatch in RLDP confirm: expected v2, got v1")
        };
        let Confirm::V2(confirm) = &mut self.recv_transfer.confirm else {
            fail!("RLDP version mismatch in RLDP confirm: expected v2, got v1")
        };
        let elapsed = self.recv_transfer.start.elapsed().as_millis() as u64;
        let mut sent: u32 = 0;
        for i in 0..parts.len() {
            let part = &mut parts[i];
            if (part.confirm_at == 0) || (part.confirm_at > elapsed) {
                continue;
            }
            confirm.part = i as i32;
            confirm.max_seqno = part.core.max_seqno as i32;
            confirm.received_count = part.received_count as i32;
            confirm.received_mask = part.received_mask as i32;
            part.confirmation_sent(elapsed);
            serialize_bare_inplace(&mut self.recv_transfer.buf, confirm)?;
            let reply = TaggedByteSlice {
                object: &self.recv_transfer.buf[..],
                #[cfg(feature = "telemetry")]
                tag: Rldp2Confirm::constructor_const(),
            };
            #[cfg(feature = "debug")]
            {
                self.recv_transfer.total_confirm_packets += 1
            }
            self.adnl.send_custom(&reply, &self.peers).await?;
            sent = sent.saturating_add(1);
        }
        Ok(sent)
    }
}

struct RecvPart {
    decoder: Option<RaptorqDecoder>,
    max_seqno: u32,
}

impl RecvPart {
    fn new() -> Self {
        Self { decoder: None, max_seqno: 0 }
    }

    fn get_decoder(&mut self, fec_type: FecTypeRaptorQ) -> Result<&mut RaptorqDecoder> {
        let decoder = &mut self.decoder;
        match decoder {
            Some(decoder) => {
                if fec_type != decoder.params {
                    fail!(
                        "Incorrect parameters in RLDP packet: {:?} vs {:?}",
                        fec_type,
                        decoder.params
                    )
                } else {
                    Ok(decoder)
                }
            }
            None => Ok(decoder.insert(RaptorqDecoder::with_params(fec_type)?)),
        }
    }
}

struct RecvPartV1 {
    core: RecvPart,
    confirm_count: usize,
    part: u32,
}

struct RecvPartV2 {
    confirm_at: u64,
    confirm_retries: u8,
    core: RecvPart,
    data: Option<Vec<u8>>,
    received_count: u32,
    received_mask: u32,
}

impl RecvPartV2 {
    fn schedule_confirmation(&mut self, elapsed: u64) {
        self.confirm_retries = 0;
        let next = elapsed.saturating_add(RldpNode::ACK_DELAY_MS);
        if self.confirm_at == 0 || next < self.confirm_at {
            self.confirm_at = next;
        }
    }

    fn confirmation_sent(&mut self, elapsed: u64) {
        self.confirm_retries = self.confirm_retries.saturating_add(1);
        self.confirm_at = if self.confirm_retries <= 7 {
            elapsed.saturating_add(RldpNode::ACK_DELAY_MS * (1u64 << self.confirm_retries))
        } else {
            0
        };
    }
}

enum RecvParts {
    V1(RecvPartV1),
    V2(Vec<RecvPartV2>),
}

pub(crate) struct RecvTransfer {
    pub(crate) data: Vec<u8>,
    pub(crate) failure: Option<anyhow::Error>,
    pub(crate) total_size: Option<usize>,
    #[cfg(feature = "debug")]
    pub(crate) timestamp: Arc<AtomicPtr<Instant>>,
    #[cfg(feature = "debug")]
    pub(crate) total_confirm_packets: u32,
    #[cfg(feature = "debug")]
    pub(crate) total_data_packets: u32,
    buf: Vec<u8>,
    complete: Complete,
    confirm: Confirm,
    expected_total_size: Option<usize>,
    parts: RecvParts,
    start: Instant,
    state: Arc<RecvTransferState>,
}

impl RecvTransfer {
    pub(crate) fn new(
        transfer_id: TransferId,
        counter: Arc<AtomicU64>,
        v2: bool,
        expected_total_size: Option<usize>,
        #[cfg(feature = "debug")] timestamp: Arc<AtomicPtr<Instant>>,
    ) -> Self {
        let (complete, confirm, parts) = if v2 {
            let complete = Rldp2Complete { transfer_id: UInt256::with_array(transfer_id), part: 0 };
            let confirm = Rldp2Confirm {
                transfer_id: UInt256::with_array(transfer_id),
                part: 0,
                max_seqno: 0,
                received_count: 0,
                received_mask: 0,
            };
            (Complete::V2(complete), Confirm::V2(confirm), RecvParts::V2(Vec::new()))
        } else {
            let complete = RldpComplete { transfer_id: UInt256::with_array(transfer_id), part: 0 };
            let confirm =
                RldpConfirm { transfer_id: UInt256::with_array(transfer_id), part: 0, seqno: 0 };
            let part = RecvPartV1 { core: RecvPart::new(), confirm_count: 0, part: 0 };
            (Complete::V1(complete), Confirm::V1(confirm), RecvParts::V1(part))
        };
        Self {
            buf: Vec::new(),
            complete,
            confirm,
            data: Vec::new(),
            failure: None,
            expected_total_size,
            parts,
            start: Instant::now(),
            state: Arc::new(RecvTransferState {
                updates: AtomicU32::new(0),
                counter: counter.into(),
            }),
            #[cfg(feature = "debug")]
            timestamp,
            #[cfg(feature = "debug")]
            total_confirm_packets: 0,
            #[cfg(feature = "debug")]
            total_data_packets: 0,
            total_size: None,
        }
    }

    #[allow(clippy::boxed_local)]
    pub(crate) fn process_chunk(&mut self, chunk: Chunk) -> Result<Option<TaggedByteSlice<'_>>> {
        self.process_chunk_at(chunk, self.start.elapsed().as_millis() as u64)
    }

    fn process_chunk_at(
        &mut self,
        chunk: Chunk,
        elapsed: u64,
    ) -> Result<Option<TaggedByteSlice<'_>>> {
        #[cfg(feature = "debug")]
        {
            self.total_data_packets += 1
        }
        let v2 = if let Confirm::V1(_) = &self.confirm { false } else { true };
        let chunk = match chunk {
            Chunk::V1(RldpMessagePart(chunk)) => {
                if v2 {
                    fail!("RLDP version mismatch in RLDP packet: expected v1, got v2")
                } else {
                    chunk
                }
            }
            Chunk::V2(Rldp2MessagePart(chunk)) => {
                if v2 {
                    chunk
                } else {
                    fail!("RLDP version mismatch in RLDP packet: expected v2, got v1")
                }
            }
        };
        let fec_type = if let FecType::Fec_RaptorQ(fec_type) = chunk.fec_type {
            fec_type
        } else {
            fail!("Unsupported FEC type in RLDP packet")
        };
        let total_size = if let Some(total_size) = self.total_size {
            // Native V2 validates each packet's geometry but keeps the first
            // transfer total. A changed declaration does not reset the decoder.
            if v2 {
                let max_wire =
                    Constraints::MAX_TOTAL_TRANSFER_SIZE + Constraints::RLDP_ANSWER_TL_OVERHEAD;
                let cap = self.expected_total_size.map(|s| s.min(max_wire)).unwrap_or(max_wire);
                if chunk.total_size as usize > cap {
                    return Ok(None);
                }
            } else if total_size != chunk.total_size as usize {
                log::warn!(
                    "Incorrect total size {} in RLDP chunk - expected {total_size}, skipping",
                    chunk.total_size
                );
                return Ok(None);
            }
            total_size
        } else {
            let total_size = chunk.total_size as usize;
            let max_wire =
                Constraints::MAX_TOTAL_TRANSFER_SIZE + Constraints::RLDP_ANSWER_TL_OVERHEAD;
            let cap = self.expected_total_size.map(|s| s.min(max_wire)).unwrap_or(max_wire);
            if total_size > cap {
                return Err(super::ResponseLimitExceeded { limit: cap, actual: total_size }.into());
            }
            self.total_size = Some(total_size);
            self.data
                .try_reserve_exact(total_size)
                .map_err(|e| error!("RLDP total size {total_size} is too big: {e}"))?;
            total_size
        };
        let chunk_part_usize = chunk.part as usize;
        let chunk_seqno_u32 = chunk.seqno as u32;
        let decoder = match &mut self.parts {
            RecvParts::V1(part) => match part.part {
                current_part if current_part == chunk.part as u32 => {
                    if chunk_seqno_u32 > part.core.max_seqno {
                        part.core.max_seqno = chunk_seqno_u32
                    }
                    part.core.get_decoder(fec_type)?
                }
                current_part if current_part > chunk.part as u32 => {
                    return self.build_part_completed_reply(chunk.part)
                }
                _ => return Ok(None),
            },
            RecvParts::V2(parts) => {
                let part = if chunk_part_usize >= parts.len() {
                    // Native InboundTransfer::get_part only opens the next part.
                    // A skipped part must be retransmitted after its predecessor
                    // has been admitted; do not allocate or decode holes.
                    if chunk_part_usize != parts.len() {
                        return Ok(None);
                    }
                    // Native reserves offsets when a decoder is opened, not
                    // when its data finishes decoding. Include unfinished parts.
                    let offset = parts
                        .iter()
                        .try_fold(0usize, |sum, part| {
                            sum.checked_add(
                                part.core
                                    .decoder
                                    .as_ref()
                                    .map_or(0, |decoder| decoder.params().data_size as usize),
                            )
                        })
                        .ok_or_else(|| error!("RLDP part offsets overflow"))?;
                    if offset > total_size || fec_type.data_size as usize > total_size - offset {
                        fail!("RLDP part exceeds original transfer size {total_size}");
                    }
                    let mut in_transit = parts.len();
                    if in_transit > Constraints::MAX_PARTS_IN_TRANSIT {
                        for part in parts.iter() {
                            if part.data.is_none() {
                                break;
                            }
                            in_transit -= 1
                        }
                        if in_transit > Constraints::MAX_PARTS_IN_TRANSIT {
                            log::warn!(
                                "Too big RLDP part number {} in chunk, \
                                we did not finish previous {in_transit} yet, skipping",
                                chunk.part
                            );
                            return Ok(None);
                        }
                    }
                    while parts.len() <= chunk_part_usize {
                        let part = RecvPartV2 {
                            confirm_at: 0,
                            confirm_retries: 0,
                            core: RecvPart::new(),
                            data: None,
                            received_count: 0,
                            received_mask: 0,
                        };
                        parts.push(part)
                    }
                    &mut parts[chunk_part_usize]
                } else if parts[chunk_part_usize].data.is_none() {
                    &mut parts[chunk_part_usize]
                } else {
                    return self.build_part_completed_reply(chunk.part);
                };
                if chunk_seqno_u32 > part.core.max_seqno {
                    let diff = chunk_seqno_u32 - part.core.max_seqno;
                    if diff >= 32 {
                        part.received_mask = 0;
                    } else {
                        part.received_mask <<= diff;
                    }
                    part.core.max_seqno = chunk_seqno_u32;
                }
                let diff = part.core.max_seqno - chunk_seqno_u32;
                if diff < 32 {
                    let mask = 1 << diff;
                    if (part.received_mask & mask) == 0 {
                        part.received_count += 1;
                        part.received_mask |= mask;
                    } else {
                        // Native Ack rejects duplicates before inspecting symbols.
                        return Ok(None);
                    }
                } else {
                    // Symbols outside the acknowledgement window are not new.
                    return Ok(None);
                }
                part.core.get_decoder(fec_type)?
            }
        };
        if v2 && chunk.data.len() != decoder.params().symbol_size as usize {
            fail!(
                "Invalid RLDP2 symbol length: {}, expected {}",
                chunk.data.len(),
                decoder.params().symbol_size
            )
        }
        if v2 {
            Constraints::check_seqno(chunk_seqno_u32)?;
        }
        if let Some(mut data) = decoder.decode(chunk_seqno_u32, &chunk.data) {
            match &mut self.parts {
                RecvParts::V1(part) => {
                    if data.len() + self.data.len() > total_size {
                        fail!(
                            "Too big size for RLDP transfer {}, expected {total_size}",
                            data.len() + self.data.len()
                        )
                    } else {
                        self.data.append(&mut data)
                    }
                    if self.data.len() < total_size {
                        part.core.decoder = None;
                        part.core.max_seqno = 0;
                        part.confirm_count = 0;
                        part.part += 1;
                    }
                }
                RecvParts::V2(parts) => {
                    // Native finish_part removes the receiver, including its ACK timer.
                    parts[chunk_part_usize].confirm_at = 0;
                    parts[chunk_part_usize].data = Some(data);
                    let mut len = 0;
                    for part in parts.iter() {
                        let Some(data) = &part.data else { break };
                        len += data.len()
                    }
                    if len > total_size {
                        fail!("Too big size for RLDP transfer {len}, expected {total_size}")
                    } else if len == total_size {
                        for part in parts {
                            let Some(data) = &mut part.data else {
                                fail!("RLDP transfer is completed by size {len}, but not finished")
                            };
                            self.data.append(data)
                        }
                    }
                }
            }
            #[cfg(feature = "debug")]
            RldpNode::check_timestamp(
                &self.timestamp,
                format!("Send part recv complete, seqno {}", chunk.seqno).as_str(),
            );
            // Native RLDP2 acknowledges completed parts on a subsequent packet,
            // not on the symbol that first finishes decoding the part.
            if matches!(self.parts, RecvParts::V2(_)) {
                Ok(None)
            } else {
                self.build_part_completed_reply(chunk.part)
            }
        } else {
            match &mut self.parts {
                RecvParts::V1(part) => {
                    if part.confirm_count == 9 {
                        let Confirm::V1(confirm) = &mut self.confirm else {
                            fail!("RLDP version mismatch in RLDP confirm: expected v2, got v1")
                        };
                        confirm.part = part.part as i32;
                        confirm.seqno = part.core.max_seqno as i32;
                        part.confirm_count = 0;
                        serialize_bare_inplace(&mut self.buf, confirm)?;
                        let ret = TaggedByteSlice {
                            object: &self.buf[..],
                            #[cfg(feature = "telemetry")]
                            tag: RldpConfirm::constructor_const(),
                        };
                        #[cfg(feature = "debug")]
                        {
                            self.total_confirm_packets += 1
                        }
                        Ok(Some(ret))
                    } else {
                        part.confirm_count += 1;
                        Ok(None)
                    }
                }
                RecvParts::V2(parts) => {
                    parts[chunk_part_usize].schedule_confirmation(elapsed);
                    Ok(None)
                }
            }
        }
    }

    pub(crate) fn state(&self) -> &Arc<RecvTransferState> {
        &self.state
    }

    fn build_part_completed_reply(&mut self, part: i32) -> Result<Option<TaggedByteSlice<'_>>> {
        match &mut self.complete {
            Complete::V1(complete) => {
                complete.part = part;
                serialize_bare_inplace(&mut self.buf, complete)?;
            }
            Complete::V2(complete) => {
                complete.part = part;
                serialize_bare_inplace(&mut self.buf, complete)?;
            }
        }
        let ret = TaggedByteSlice {
            object: &self.buf[..],
            #[cfg(feature = "telemetry")]
            tag: match &self.complete {
                Complete::V1(complete) => complete.constructor(),
                Complete::V2(complete) => complete.constructor(),
            },
        };
        #[cfg(feature = "debug")]
        {
            self.total_confirm_packets += 1
        }
        Ok(Some(ret))
    }
}

declare_counted!(
    pub(crate) struct RecvTransferState {
        updates: AtomicU32,
    }
);

impl RecvTransferState {
    pub(crate) fn updates(&self) -> u32 {
        self.updates.load(Ordering::Relaxed)
    }
    pub(crate) fn set_updates(&self) {
        self.updates.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod bounded_receive_tests {
    use super::*;
    #[test]
    fn bounded_receive_declared_wire_limit_precedes_allocation() {
        let mut receiver = RecvTransfer::new(
            [7; 32],
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
            false,
            Some(96),
            #[cfg(feature = "debug")]
            Arc::new(std::sync::atomic::AtomicPtr::new(std::ptr::null_mut())),
        );
        let chunk = Chunk::V1(RldpMessagePart(rtos_api::RldpChunk {
            transfer_id: [7; 32].into(),
            fec_type: FecType::Fec_RaptorQ(FecTypeRaptorQ {
                data_size: 4096,
                symbol_size: 768,
                symbols_count: 6,
            }),
            part: 0,
            total_size: 4096,
            seqno: 0,
            data: vec![0; 768],
        }));
        let error =
            receiver.process_chunk(chunk).err().expect("declared wire size must be rejected");
        assert!(error.downcast_ref::<crate::ResponseLimitExceeded>().is_some());
        assert_eq!(receiver.data.capacity(), 0);
        assert!(receiver.total_size.is_none());
    }
}

#[cfg(test)]
mod completion_timer_tests {
    use super::*;
    use rtos_api::IntoBoxed;

    #[test]
    fn completed_rldp2_part_cancels_pending_confirmation() {
        let native = super::super::lifetime_tests::checked_ack_native_effects(
            include_bytes!("../../../ci/conformance/rldp2_completed_part_timer_context.tsv"),
            include_bytes!("../../../ci/conformance/rldp2_completed_part_timer_effects.jsonl"),
            include_bytes!("../../../ci/conformance/rldp2_completed_part_timer_reference.cpp"),
            include_bytes!("../../../ci/conformance/rldp2_completed_part_timer_metadata.json"),
        );
        assert_eq!(native[0]["confirm_packets"], 0);
        assert_eq!(native[0]["deliveries"], 0);
        let bytes = native[0]["bytes"].as_u64().unwrap() as usize;
        let data = vec![42; bytes];
        let mut encoder = crate::RaptorqEncoder::with_data(&data, Some(768));
        let fec = encoder.params().clone().into_boxed();
        let mut receiver = RecvTransfer::new(
            [0; 32],
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
            true,
            Some(bytes + 1),
            #[cfg(feature = "debug")]
            Arc::new(std::sync::atomic::AtomicPtr::new(std::ptr::null_mut())),
        );
        let mut first_complete = 0usize;
        let mut duplicate = None;
        for index in 0..bytes.div_ceil(768) {
            let mut seqno = index as u32;
            let symbol = encoder.encode(&mut seqno).unwrap();
            if index == 0 {
                duplicate = Some((seqno, symbol.clone()));
            }
            first_complete += usize::from(
                receiver
                    .process_chunk(Chunk::V2(Rldp2MessagePart(rtos_api::RldpChunk {
                        transfer_id: UInt256::default(),
                        fec_type: fec.clone(),
                        part: 0,
                        total_size: (bytes + 1) as i64,
                        seqno: seqno as i32,
                        data: symbol,
                    })))
                    .unwrap()
                    .is_some(),
            );
        }
        assert_eq!(native[0]["first_complete"], first_complete);
        let RecvParts::V2(parts) = &receiver.parts else { unreachable!() };
        assert_eq!(parts[0].data.as_ref().unwrap(), &data, "first part really decoded");
        assert!(receiver.data.is_empty(), "whole transfer must still await its next part");
        assert_eq!(
            parts[0].confirm_at, 0,
            "native removes the completed part receiver and its pending ACK"
        );
        let (seqno, symbol) = duplicate.unwrap();
        let reply = receiver
            .process_chunk(Chunk::V2(Rldp2MessagePart(rtos_api::RldpChunk {
                transfer_id: UInt256::default(),
                fec_type: fec,
                part: 0,
                total_size: (bytes + 1) as i64,
                seqno: seqno as i32,
                data: symbol,
            })))
            .unwrap();
        assert_eq!(native[0]["duplicate_complete"], usize::from(reply.is_some()));
    }
}

#[cfg(test)]
mod ack_retry_tests {
    use super::*;
    use rtos_api::IntoBoxed;
    #[test]
    fn rldp2_ack_retry_schedule_matches_native() {
        let expected = super::super::lifetime_tests::ack_retry_native_effects();
        let mut previous = String::new();
        let new_receiver = || {
            RecvTransfer::new(
                [0; 32],
                Arc::new(AtomicU64::new(0)),
                true,
                None,
                #[cfg(feature = "debug")]
                Arc::new(std::sync::atomic::AtomicPtr::new(std::ptr::null_mut())),
            )
        };
        let mut receiver = new_receiver();
        let mut actual = Vec::new();
        for line in include_str!("../../../ci/conformance/rldp2_ack_retries_context.tsv").lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            let name = fields[0];
            let op = fields[1];
            let ms: u64 = fields[2].parse().unwrap();
            let seqno: i32 = fields[3].parse().unwrap();
            if name != previous {
                receiver = new_receiver();
                previous = name.to_owned();
            }
            let mut accepted = false;
            let mut sent = false;
            if op == "recv" {
                let before = match &receiver.parts {
                    RecvParts::V2(parts) => parts.first().map_or(0, |p| p.received_count),
                    _ => unreachable!(),
                };
                // Native RldpReceiver uses wire seqno + 1. Keep this incomplete
                // so we exercise the real production receive/ACK state machine.
                let chunk = Chunk::V2(Rldp2MessagePart(rtos_api::RldpChunk {
                    transfer_id: UInt256::default(),
                    fec_type: FecTypeRaptorQ {
                        data_size: 8192,
                        symbol_size: 768,
                        symbols_count: 11,
                    }
                    .into_boxed(),
                    part: 0,
                    total_size: 8192,
                    seqno: seqno - 1,
                    data: vec![42; 768],
                }));
                assert!(receiver.process_chunk_at(chunk, ms).unwrap().is_none());
                let RecvParts::V2(parts) = &receiver.parts else { unreachable!() };
                accepted = parts[0].received_count > before;
            } else {
                let RecvParts::V2(parts) = &mut receiver.parts else { unreachable!() };
                let part = &mut parts[0];
                if part.confirm_at != 0 && part.confirm_at <= ms {
                    sent = true;
                    part.confirmation_sent(ms);
                }
            }
            let RecvParts::V2(parts) = &receiver.parts else { unreachable!() };
            let next = parts[0].confirm_at;
            let ready = next != 0 && next <= ms;
            actual.push(serde_json::json!({"case":name,"op":op,"ms":ms,"accepted":accepted,"sent":sent,"ready":ready,"next_ms":if ready {0}else{next}}));
        }
        assert_eq!(actual, expected, "ACK retry cap/reset/deadline must match native scheduling");
        #[allow(dead_code)]
        struct PreviousPart {
            confirm_at: u64,
            core: RecvPart,
            data: Option<Vec<u8>>,
            received_count: u32,
            received_mask: u32,
        }
        let before = std::mem::size_of::<PreviousPart>();
        let after = std::mem::size_of::<RecvPartV2>();
        eprintln!("ACK_PART_BYTES: before={before} after={after}");
        assert!(after <= before + 8, "bounded retry counter must not add unbounded per-part state");
    }
}

#[cfg(test)]
mod sequential_part_tests {
    use super::*;
    use rtos_api::IntoBoxed;

    #[test]
    fn rldp2_skipped_part_does_not_decode_or_ack_before_predecessor() {
        let native = super::super::lifetime_tests::checked_ack_native_effects(
            include_bytes!("../../../ci/conformance/rldp2_sequential_part_admission_context.tsv"),
            include_bytes!("../../../ci/conformance/rldp2_sequential_part_admission_effects.jsonl"),
            include_bytes!("../../../ci/conformance/rldp2_sequential_part_admission_reference.cpp"),
            include_bytes!("../../../ci/conformance/rldp2_sequential_part_admission_metadata.json"),
        );
        let mut receiver = RecvTransfer::new(
            [0; 32],
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
            true,
            Some(4_000_001),
            #[cfg(feature = "debug")]
            Arc::new(std::sync::atomic::AtomicPtr::new(std::ptr::null_mut())),
        );
        let mut completes = 0;
        for row in native {
            let part = row["part"].as_i64().unwrap() as i32;
            let mut encoder = crate::RaptorqEncoder::with_data(
                &vec![42; if part < 2 { 2_000_000 } else { 1 }],
                Some(768),
            );
            let mut seqno = 0;
            let chunk = Chunk::V2(Rldp2MessagePart(rtos_api::RldpChunk {
                transfer_id: UInt256::default(),
                fec_type: encoder.params().clone().into_boxed(),
                part,
                total_size: 4_000_001,
                data: encoder.encode(&mut seqno).unwrap(),
                seqno: 0,
            }));
            completes += usize::from(receiver.process_chunk(chunk).unwrap().is_some());
            assert_eq!(
                completes,
                row["complete_packets"].as_u64().unwrap() as usize,
                "completed-part replay effects after input part {part}"
            );
            assert_eq!(
                usize::from(!receiver.data.is_empty()),
                row["deliveries"].as_u64().unwrap() as usize
            );
        }
    }
}

#[cfg(test)]
mod transfer_size_change_tests {
    use super::*;
    use rtos_api::IntoBoxed;

    #[test]
    fn rldp2_changed_total_preserves_native_decoder_admission() {
        let native = super::super::lifetime_tests::checked_ack_native_effects(
            include_bytes!("../../../ci/conformance/rldp2_transfer_size_changes_context.tsv"),
            include_bytes!("../../../ci/conformance/rldp2_transfer_size_changes_effects.jsonl"),
            include_bytes!("../../../ci/conformance/rldp2_transfer_size_changes_reference.cpp"),
            include_bytes!("../../../ci/conformance/rldp2_transfer_size_changes_metadata.json"),
        );
        assert_eq!(native.len(), 5, "all declared size-change cases must be present");
        let mut actual = Vec::new();
        let mut expected = Vec::new();
        for (line, row) in
            include_str!("../../../ci/conformance/rldp2_transfer_size_changes_context.tsv")
                .lines()
                .zip(native)
        {
            let fields: Vec<_> = line.split_whitespace().collect();
            let values: Vec<usize> = fields[1..].iter().map(|s| s.parse().unwrap()).collect();
            let (original, changed, part, bytes, seq) =
                (values[0], values[1], values[2], values[3], values[4]);
            let mut receiver = RecvTransfer::new(
                [0; 32],
                Arc::new(std::sync::atomic::AtomicU64::new(0)),
                true,
                Some(4_000_001),
                #[cfg(feature = "debug")]
                Arc::new(std::sync::atomic::AtomicPtr::new(std::ptr::null_mut())),
            );
            let mut errors = 0;
            let mut completes = 0;
            for (total, index, size, sequence) in [
                (original, 0, 2_000_000, 0),
                (changed, part, bytes, seq),
                (changed, part, bytes, seq),
            ] {
                let mut encoder = crate::RaptorqEncoder::with_data(&vec![42; size], Some(768));
                let mut number = sequence as u32;
                let chunk = Chunk::V2(Rldp2MessagePart(rtos_api::RldpChunk {
                    transfer_id: UInt256::default(),
                    fec_type: encoder.params().clone().into_boxed(),
                    part: index as i32,
                    total_size: total as i64,
                    data: encoder.encode(&mut number).unwrap(),
                    seqno: sequence as i32,
                }));
                match receiver.process_chunk(chunk) {
                    Ok(reply) => completes += usize::from(reply.is_some()),
                    Err(_) => {
                        errors += 1;
                        break;
                    }
                }
            }
            let RecvParts::V2(parts) = &receiver.parts else { unreachable!() };
            let received = parts
                .iter()
                .filter(|p| p.data.is_none())
                .map(|p| p.received_count)
                .max()
                .unwrap_or(0);
            actual.push(serde_json::json!({"id":fields[0],"errors":errors,"received":if errors==0 {Some(received)}else{None},"completes":if errors==0{Some(completes)}else{None}}));
            let native_error = row["errors"].as_u64().unwrap();
            expected.push(serde_json::json!({"id":row["id"],"errors":native_error,"received":if native_error==0{Some(row["max_received"].clone())}else{None},"completes":if native_error==0{Some(row["complete_packets"].clone())}else{None}}));
        }
        assert_eq!(actual, expected, "native total-size mutation effects");
    }
}
