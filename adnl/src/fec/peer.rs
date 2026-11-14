// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Peer-announced FEC parameters. Parsing a type does not admit a transfer.
use super::{Decoder, Parameters, Refusal};
use anyhow::Result;
use rtos_api::{
    ton::fec::{type_::RaptorQ, Type},
    WireProfile,
};

#[derive(Clone, Debug)]
pub struct PeerFecType {
    parameters: Parameters,
}
impl PeerFecType {
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let value: Type = crate::adnl::wire::decode(bytes, |reason| Refusal(reason).into())?;
        Self::from_tl(&value)
    }
    pub fn from_tl(value: &Type) -> Result<Self> {
        let data_size = u32::try_from(*value.data_size()).map_err(|_| Refusal("fec_negative"))?;
        let symbol_size =
            u32::try_from(*value.symbol_size()).map_err(|_| Refusal("fec_negative"))?;
        let symbols_count =
            u32::try_from(*value.symbols_count()).map_err(|_| Refusal("fec_negative"))?;
        // This floor is a TOS policy; TON857 only rejects zero.
        if symbol_size < 768 {
            return Err(Refusal("fec_symbol_size_small").into());
        }
        if symbol_size > 2048 {
            return Err(Refusal("fec_symbol_size_large").into());
        }
        if data_size as u64 > symbol_size as u64 * (1 << 24) {
            return Err(Refusal("fec_too_many_symbols").into());
        }
        if symbols_count != data_size.div_ceil(symbol_size) {
            return Err(Refusal("fec_symbols_count").into());
        }
        if !matches!(value, Type::Fec_RaptorQ(_)) {
            return Err(Refusal("fec_not_raptorq").into());
        }
        Ok(Self {
            parameters: Parameters { data_size: data_size as usize, symbol_size, symbols_count },
        })
    }
    pub fn parameters(&self) -> Parameters {
        self.parameters
    }
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        let p = self.parameters;
        WireProfile::T0.serialize(&Type::Fec_RaptorQ(RaptorQ {
            data_size: p.data_size as i32,
            symbol_size: p.symbol_size as i32,
            symbols_count: p.symbols_count as i32,
        }))
    }
    /// Codec capacity is a later boundary than peer-type validation.
    pub fn create_decoder(&self) -> std::result::Result<Decoder, Refusal> {
        Decoder::from_peer(self.parameters)
    }
}
