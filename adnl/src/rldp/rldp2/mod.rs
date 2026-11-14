// Copyright 2017-2020 Telegram Systems LLP
// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! RLDP2 framing and receiver admission primitives.
pub mod budget;
pub mod connection;
mod timer;
pub const PART_SIZE: u64 = super::Constraints::SLICE as u64;
pub const SYMBOL_SIZE: u64 = super::Constraints::SYMBOL as u64;
pub const DEFAULT_MTU: u64 = 7680;

/// Sender repair demand, shared with the existing native send state machine.
pub struct FecHelper {
    pub symbols_count: u32,
    pub received_symbols_count: u32,
}
impl FecHelper {
    /// Next strict target; None if the u32 counter cannot represent it.
    /// Protocol callers keep both counters below 2^30.
    pub fn target(&self) -> Option<u32> {
        let first = self.symbols_count.checked_add(5)?;
        if first > self.received_symbols_count {
            return Some(first);
        }
        let steps = (self.received_symbols_count - first) / 5 + 1;
        first.checked_add(steps.checked_mul(5)?)
    }
    pub fn remaining(&self) -> Option<u32> {
        self.target()?.checked_sub(self.received_symbols_count)
    }
}
