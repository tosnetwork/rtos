// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Random-access FEC codecs, with deferred receive-side decoding.
//! Receive ordering and round-robin semantics follow td/fec in TON/TOS.
use anyhow::{ensure, Result};
use raptorq::{
    EncodingPacket, ObjectTransmissionInformation, PayloadId, SourceBlockDecoder,
    SourceBlockEncoder,
};
use std::collections::HashSet;
mod online;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    RaptorQ,
    RoundRobin,
    Online,
}

#[derive(Clone, Copy, Debug)]
pub struct Parameters {
    pub data_size: usize,
    pub symbol_size: u32,
    pub symbols_count: u32,
}
impl Parameters {
    pub fn new(data_size: usize, symbol_size: u32) -> Result<Self> {
        ensure!(symbol_size > 0 && symbol_size <= 2048, "invalid local symbol size");
        ensure!(
            data_size > 0 && data_size <= symbol_size as usize * 56403,
            "invalid local data size"
        );
        Ok(Self {
            data_size,
            symbol_size,
            symbols_count: data_size.div_ceil(symbol_size as usize) as u32,
        })
    }
    fn config(self) -> ObjectTransmissionInformation {
        ObjectTransmissionInformation::new(self.data_size as u64, self.symbol_size, 1, 1, 1)
    }
}

pub struct Encoder {
    algorithm: Algorithm,
    parameters: Parameters,
    data: Vec<u8>,
    engine: Option<SourceBlockEncoder>,
    online: Option<online::Encoder>,
}
impl Encoder {
    pub fn new(algorithm: Algorithm, data: Vec<u8>, symbol_size: u32) -> Result<Self> {
        let parameters = Parameters::new(data.len(), symbol_size)?;
        Ok(Self { algorithm, parameters, data, engine: None, online: None })
    }
    pub fn parameters(&self) -> Parameters {
        self.parameters
    }
    pub fn symbol(&mut self, mut id: u32) -> Result<(u32, Vec<u8>)> {
        let p = self.parameters;
        if self.algorithm == Algorithm::Online {
            let engine = self.online.get_or_insert_with(|| online::Encoder::new(&self.data, p));
            return Ok((id, engine.symbol(id)));
        }
        if self.algorithm == Algorithm::RoundRobin {
            id %= p.symbols_count;
        } else {
            ensure!(id < 1 << 24, "invalid local RaptorQ symbol id");
        }
        if id < p.symbols_count {
            let start = id as usize * p.symbol_size as usize;
            let mut data =
                self.data[start..self.data.len().min(start + p.symbol_size as usize)].to_vec();
            if self.algorithm == Algorithm::RaptorQ {
                data.resize(p.symbol_size as usize, 0);
            }
            return Ok((id, data));
        }
        let engine = self.engine.get_or_insert_with(|| {
            let mut padded = self.data.clone();
            padded.resize(p.symbols_count as usize * p.symbol_size as usize, 0);
            SourceBlockEncoder::new2(0, &p.config(), &padded)
        });
        let packet = engine.repair_packets(id - p.symbols_count, 1).pop().unwrap();
        Ok((id, packet.data().to_vec()))
    }
}

/// Codes emitted by the native receiver, rather than adapter-side predictions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal(pub &'static str);
impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Refusal {}

pub struct Decoder {
    algorithm: Algorithm,
    parameters: Parameters,
    packets: Vec<EncodingPacket>,
    received: HashSet<u32>,
    sources: u32,
    may_decode: bool,
    result: Option<Vec<u8>>,
    regenerator: Option<SourceBlockEncoder>,
    online: Option<online::Decoder>,
}
impl Decoder {
    pub fn new(algorithm: Algorithm, parameters: Parameters) -> Result<Self> {
        let p = Parameters::new(parameters.data_size, parameters.symbol_size)?;
        ensure!(p.symbols_count == parameters.symbols_count, "inconsistent local source count");
        Ok(Self {
            algorithm,
            parameters,
            packets: Vec::new(),
            received: HashSet::new(),
            sources: 0,
            may_decode: false,
            result: None,
            regenerator: None,
            online: (algorithm == Algorithm::Online).then(|| online::Decoder::new(p)),
        })
    }
    pub fn add_symbol(&mut self, mut id: u32, data: Vec<u8>) -> std::result::Result<(), Refusal> {
        let p = self.parameters;
        if data.len() != p.symbol_size as usize {
            return Err(Refusal("symbol_length"));
        }
        if let Some(online) = &mut self.online {
            online.add_symbol(id, data);
            self.may_decode = online.is_ready();
            return Ok(());
        }
        if self.algorithm == Algorithm::RaptorQ {
            if id >= 1 << 24 {
                return Err(Refusal("symbol_id_range"));
            }
            if self.result.is_some() {
                return Ok(());
            }
            if id >= p.symbols_count && self.packets.len() >= p.symbols_count as usize + 10 {
                return Ok(());
            }
        } else {
            id %= p.symbols_count;
        }
        if !self.received.insert(id) {
            return Ok(());
        }
        if id < p.symbols_count {
            self.sources += 1;
        }
        self.packets.push(EncodingPacket::new(PayloadId::new(0, id), data));
        self.may_decode = if self.algorithm == Algorithm::RoundRobin {
            self.sources == p.symbols_count
        } else {
            self.packets.len() >= p.symbols_count as usize
        };
        Ok(())
    }
    pub fn may_try_decode(&self) -> bool {
        self.may_decode
    }
    pub fn try_decode(&mut self) -> std::result::Result<&[u8], Refusal> {
        if !self.may_decode {
            return Err(Refusal("need_more_symbols"));
        }
        if self.result.is_none() {
            let p = self.parameters;
            if let Some(online) = &self.online {
                self.result = Some(online.data(p.data_size));
            } else if self.sources == p.symbols_count {
                let mut data = vec![0; p.data_size];
                for packet in &self.packets {
                    let id = packet.payload_id().encoding_symbol_id();
                    if id < p.symbols_count {
                        let offset = id as usize * p.symbol_size as usize;
                        let len = (p.data_size - offset).min(p.symbol_size as usize);
                        data[offset..offset + len].copy_from_slice(&packet.data()[..len]);
                    }
                }
                self.result = Some(data);
            } else {
                self.may_decode = false;
                let mut engine = SourceBlockDecoder::new2(0, &p.config(), p.data_size as u64);
                let (mut data, regenerator) = engine
                    .decode_with_encoder(self.packets.clone())
                    .ok_or(Refusal("unclassified"))?;
                self.regenerator = Some(regenerator);
                data.truncate(p.data_size);
                self.result = Some(data);
            }
        }
        Ok(self.result.as_deref().unwrap())
    }

    pub fn take_encoder(&mut self) -> Result<Encoder> {
        let data = self.result.as_ref().ok_or_else(|| anyhow::anyhow!("decode first"))?;
        let algorithm = if self.algorithm == Algorithm::Online {
            Algorithm::RoundRobin
        } else {
            self.algorithm
        };
        let mut encoder = Encoder::new(algorithm, data.clone(), self.parameters.symbol_size)?;
        encoder.engine = self.regenerator.take();
        Ok(encoder)
    }
}
