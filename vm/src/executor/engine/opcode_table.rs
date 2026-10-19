// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Code page 0 dispatch table of the reference implementation (see cp0_table.rs) and the
//! generic dispatch stage that precedes every instruction: lookup on the zero-padded 24-bit
//! prefix, rejection of unassigned ranges and of instructions above the global version, and the
//! instruction gas `10 + total bits`, charged before the instruction length is checked.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    /// Unassigned range: 10 gas, invalid opcode.
    Dummy,
    /// Instruction without operands.
    Simplest,
    /// Instruction with fixed-width operands.
    Fixed,
    /// Instruction with operands of computed length (data and references checked by the body).
    Ext,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Entry {
    pub start: u32,
    #[allow(dead_code)]
    pub end: u32,
    pub kind: Kind,
    #[allow(dead_code)]
    pub opc_bits: u8,
    pub tot_bits: u8,
    /// Lowest global version that has the instruction (0: always).
    pub version: u8,
}

/// Gas of every dispatched instruction before its body runs.
pub(super) const GAS_PER_INSTRUCTION: i64 = 10;

/// Index of the table entry containing the first opcode with each leading byte (and one past the
/// last entry), so that a lookup only searches the entries sharing the leading byte.
const FIRST_BYTE_INDEX: [u16; 257] = {
    let table = &super::cp0_table::CP0;
    let mut index = [0u16; 257];
    let mut byte = 0;
    let mut entry = 0;
    while byte < 256 {
        let opcode = (byte as u32) << 16;
        while table[entry].end <= opcode {
            entry += 1;
        }
        index[byte] = entry as u16;
        byte += 1;
    }
    index[256] = table.len() as u16;
    index
};

/// Entry for a 24-bit opcode (code shorter than 24 bits is padded with zero bits).
pub(super) fn lookup(opcode: u32) -> &'static Entry {
    let table = &super::cp0_table::CP0;
    let byte = (opcode >> 16) as usize & 0xff;
    let first = usize::from(FIRST_BYTE_INDEX[byte]);
    // The entry holding the next byte's first opcode may start inside this byte.
    let last = (usize::from(FIRST_BYTE_INDEX[byte + 1]) + 1).min(table.len());
    let candidates = &table[first..last];
    let index = candidates.partition_point(|entry| entry.start <= opcode);
    &candidates[index.saturating_sub(1)]
}

/// The dispatch decision for `bits` available bits (1..=24) holding `opcode` (zero-padded):
/// the gas charged by the stage and whether the instruction body may run. A rejection (unassigned
/// range, instruction above the global version, fewer bits than the instruction) is an invalid
/// opcode after that gas.
pub(super) fn dispatch(opcode: u32, bits: usize, version: u32) -> (i64, bool) {
    let entry = lookup(opcode);
    if entry.kind == Kind::Dummy || u32::from(entry.version) > version {
        return (GAS_PER_INSTRUCTION, false);
    }
    (GAS_PER_INSTRUCTION + i64::from(entry.tot_bits), bits >= usize::from(entry.tot_bits))
}

#[cfg(test)]
mod tests {
    use super::{super::cp0_table, *};

    #[test]
    fn table_covers_the_opcode_space_in_order() {
        let table = &cp0_table::CP0;
        assert_eq!(table[0].start, 0);
        for pair in table.windows(2) {
            assert!(pair[0].start < pair[0].end);
            assert_eq!(pair[0].end, pair[1].start);
        }
        assert_eq!(table[table.len() - 1].end, 1 << 24);
        for entry in table {
            assert_eq!(lookup(entry.start).start, entry.start);
            assert_eq!(lookup(entry.end - 1).start, entry.start);
        }
        // The leading-byte index agrees with a search over the whole table.
        let full = |opcode: u32| {
            let index = table.partition_point(|entry| entry.start <= opcode);
            table[index - 1].start
        };
        for opcode in (0..1u32 << 24).step_by(97).chain((0..256u32).flat_map(|b| {
            let first = b << 16;
            [first, first + 1, first + 0xffff, first.saturating_sub(1)]
        })) {
            assert_eq!(lookup(opcode).start, full(opcode), "{opcode:06x}");
        }
        assert_eq!(cp0_table::REFERENCE_COMMIT.len(), 40);
        assert_eq!(cp0_table::DUMP_SHA256.len(), 64);
    }
}
