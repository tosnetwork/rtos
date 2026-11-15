// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Dynamic `VarUInteger n` readers. Structural and minimal encodings have
//! deliberately different acceptance rules, as in block-parse.cpp.

use crate::{BuilderData, IBitstring, Result, SliceData};
use num::{bigint::Sign, BigInt};

/// VM variable integer loading uses the complete range of the length prefix;
/// it neither checks a TL-B bound nor requires a minimal encoding.
pub fn load_var_integer(slice: &mut SliceData, prefix_bits: usize, signed: bool) -> Result<BigInt> {
    if prefix_bits > 5 {
        crate::fail!("variable integer length prefix exceeds five bits");
    }
    let mut next = slice.clone();
    let len = next.get_next_int(prefix_bits)? as usize;
    let bytes = next.get_next_bytes(len)?;
    let value = if signed {
        BigInt::from_signed_bytes_be(&bytes)
    } else {
        BigInt::from_bytes_be(Sign::Plus, &bytes)
    };
    *slice = next;
    Ok(value)
}

/// Validation rules used by the schema and handwritten TL-B readers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VarUIntegerEncoding {
    /// The schema permits leading zero bytes.
    Structural,
    /// The handwritten reader requires the shortest encoding, including zero.
    Minimal,
    /// The positive handwritten reader also rejects zero.
    Positive,
}

/// A bounded TL-B variable unsigned integer with a runtime schema bound.
#[derive(Clone, Copy, Debug)]
pub struct VarUIntegerCodec {
    bound: usize,
    prefix_bits: usize,
}

impl VarUIntegerCodec {
    /// Supports the node's `VarUInteger` bounds from 1 through 32.
    pub fn new(bound: usize) -> Option<Self> {
        (1..=32).contains(&bound).then(|| Self {
            bound,
            prefix_bits: (usize::BITS - (bound - 1).leading_zeros()) as usize,
        })
    }

    fn length(&self, slice: &mut SliceData, encoding: VarUIntegerEncoding) -> Option<usize> {
        let len = slice.get_next_int(self.prefix_bits).ok()? as usize;
        if len >= self.bound || len * 8 > slice.remaining_bits() {
            return None;
        }
        if encoding != VarUIntegerEncoding::Structural {
            if len == 0 {
                if encoding == VarUIntegerEncoding::Positive {
                    return None;
                }
            } else if slice.get_int(8).ok()? == 0 {
                return None;
            }
        }
        Some(len)
    }

    /// Advances one value without allocating its integer. Failure leaves the
    /// input unchanged; success need not consume the complete slice.
    pub fn skip(&self, slice: &mut SliceData, encoding: VarUIntegerEncoding) -> bool {
        let mut next = slice.clone();
        let Some(len) = self.length(&mut next, encoding) else {
            return false;
        };
        if next.move_by(len * 8).is_err() {
            return false;
        }
        *slice = next;
        true
    }

    /// Reads one unsigned value, with the same cursor contract as `skip`.
    pub fn read(&self, slice: &mut SliceData, encoding: VarUIntegerEncoding) -> Option<BigInt> {
        let mut next = slice.clone();
        let len = self.length(&mut next, encoding)?;
        let bytes = next.get_next_bytes(len).ok()?;
        *slice = next;
        Some(BigInt::from_bytes_be(Sign::Plus, &bytes))
    }

    /// The handwritten `as_uint` accessor is a peek: it checks the eight-byte
    /// machine bound, rather than the TL-B bound or minimal encoding.
    pub fn as_uint(&self, slice: &SliceData) -> u64 {
        let mut next = slice.clone();
        let Ok(len) = next.get_next_int(self.prefix_bits) else {
            return u64::MAX;
        };
        if len > 8 {
            return u64::MAX;
        }
        next.get_next_int(len as usize * 8).unwrap_or(u64::MAX)
    }

    /// Writes the shortest unsigned encoding. Range failure returns `None`;
    /// builder capacity failures retain the builder's usual error behavior.
    pub fn write(&self, value: &BigInt) -> Result<Option<BuilderData>> {
        if value.sign() == Sign::Minus || value.bits() > ((self.bound - 1) * 8) as u64 {
            return Ok(None);
        }
        let (_, mut bytes) = value.to_bytes_be();
        if value.bits() == 0 {
            bytes.clear();
        }
        let mut builder = BuilderData::new();
        builder.append_bits(bytes.len(), self.prefix_bits)?;
        builder.append_raw(&bytes, bytes.len() * 8)?;
        Ok(Some(builder))
    }
}

#[cfg(test)]
#[path = "tests/test_varuint.rs"]
mod tests;
