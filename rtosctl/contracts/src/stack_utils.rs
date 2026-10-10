/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use rtos_api::ton::tvm::StackEntry;

/// Helper to create a number stack entry from bytes (big-endian 256-bit)
pub(crate) fn bytes_to_stack_entry(bytes: &[u8; 32]) -> StackEntry {
    let n = rtos_api::ton::tvm::numberdecimal::NumberDecimal {
        number: "0x".to_owned() + &hex::encode_upper(bytes),
    };
    StackEntry::Tvm_StackEntryNumber(rtos_api::ton::tvm::stackentry::StackEntryNumber {
        number: rtos_api::ton::tvm::Number::Tvm_NumberDecimal(n),
    })
}

/// Helper to create a number stack entry from i64
pub(crate) fn i64_to_stack_entry(value: i64) -> StackEntry {
    let n = rtos_api::ton::tvm::numberdecimal::NumberDecimal { number: value.to_string() };
    StackEntry::Tvm_StackEntryNumber(rtos_api::ton::tvm::stackentry::StackEntryNumber {
        number: rtos_api::ton::tvm::Number::Tvm_NumberDecimal(n),
    })
}
