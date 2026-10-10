// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
// RTOS modifications: use the self-contained, verification-only backend.
use super::{
    engine::{storage::fetch_stack, Engine},
    gas::gas_state::Gas,
    types::Instruction,
};
use crate::stack::StackItem;
use rtos_block::{fail, Cell, CellType, ExceptionCode, Result, Status};
use rtos_pq_crypto::{MAX_CONTEXT_BYTES, MAX_MESSAGE_BYTES, PUBLIC_KEY_BYTES, SIGNATURE_BYTES};
const BASE_GAS: i64 = 50_000;
const CHUNK_BYTES: usize = 127;

fn read_bytes(engine: &mut Engine, cell: Cell, limit: usize) -> Result<Vec<u8>> {
    read_bytes_priced(engine, cell, limit, 1)
}

fn read_bytes_priced(
    engine: &mut Engine,
    mut cell: Cell,
    limit: usize,
    byte_gas: i64,
) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    loop {
        if cell.level() != 0 {
            fail!(ExceptionCode::CellUnderflow, "PQ cells must have level zero");
        }
        // Meter the actual cell load, including repeated-cell cache hits, but do
        // not resolve library references into a different byte string.
        let slice = engine.load_hashed_cell(cell, false)?;
        let size = slice.remaining_bits() / 8;
        let refs = slice.remaining_references();
        if slice.cell_type() != CellType::Ordinary
            || slice.level() != 0
            || slice.remaining_bits() % 8 != 0
            || refs > 1
            || size > CHUNK_BYTES
            || (refs != 0 && size != CHUNK_BYTES)
            || (size == 0 && (!result.is_empty() || refs != 0))
            || size > limit.saturating_sub(result.len())
        {
            fail!(ExceptionCode::CellUnderflow, "noncanonical PQ byte chain");
        }
        let charge = (size as i64).checked_mul(byte_gas);
        let Some(charge) = charge else {
            fail!(ExceptionCode::OutOfGas);
        };
        engine.try_use_gas(charge)?;
        result.extend_from_slice(&slice.get_bytestring(0));
        if refs == 0 {
            return Ok(result);
        }
        cell = slice.reference(0)?;
    }
}

pub(super) fn execute_pq_mldsa44(engine: &mut Engine) -> Status {
    // Preserve historical exception metering before activation. From v4 the
    // invalid-instruction charge can exhaust gas before exception dispatch;
    // older versions charge the exception too before detecting exhaustion.
    if engine.block_version() < 16 {
        if engine.block_version() >= 4 {
            engine.try_use_gas(Gas::basic_gas_price(0, 0))?;
        } else {
            engine.use_gas(Gas::basic_gas_price(0, 0));
        }
        fail!(ExceptionCode::InvalidOpcode);
    }
    engine.load_instruction(Instruction::new("PQCHECKSIG_MLDSA44"))?;
    if engine.cc.stack.depth() < 4 {
        fail!(ExceptionCode::StackUnderflow);
    }
    engine.try_use_gas(BASE_GAS)?;
    fetch_stack(engine, 4)?;
    // Type-check all four values before decoding any, in top-to-bottom order.
    let key = engine.cmd.var(0).as_cell()?.clone();
    let signature = engine.cmd.var(1).as_cell()?.clone();
    let context = engine.cmd.var(2).as_cell()?.clone();
    let message = engine.cmd.var(3).as_cell()?.clone();
    let key = read_bytes(engine, key, PUBLIC_KEY_BYTES)?;
    let signature = read_bytes(engine, signature, SIGNATURE_BYTES)?;
    let context = read_bytes(engine, context, MAX_CONTEXT_BYTES)?;
    let message = read_bytes(engine, message, MAX_MESSAGE_BYTES)?;
    if key.len() != PUBLIC_KEY_BYTES || signature.len() != SIGNATURE_BYTES {
        fail!(ExceptionCode::CellUnderflow, "incorrect ML-DSA-44 input length");
    }
    let valid = match rtos_pq_crypto::verify(&message, &context, &signature, &key) {
        Ok(valid) => valid,
        Err(rtos_pq_crypto::VerifyError::Backend(_)) => {
            fail!(ExceptionCode::FatalError, "ML-DSA verifier backend failure");
        }
        Err(_) => fail!(ExceptionCode::CellUnderflow, "incorrect ML-DSA-44 input length"),
    };
    // Deliberately do not consult chksig_always_succeed or the classic free-call allowance.
    engine.cc.stack.push(StackItem::boolean(valid));
    Ok(())
}

pub(super) fn execute_pq_falcon512(engine: &mut Engine) -> Status {
    use rtos_pq_crypto::falcon512::{MAX_MESSAGE_BYTES, PUBLIC_KEY_BYTES, SIGNATURE_BYTES};
    if engine.block_version() < 19 {
        return engine.reject_unavailable_instruction();
    }
    engine.load_instruction(Instruction::new("PQCHECKSIG_FALCON512_PADDED"))?;
    if engine.cc.stack.depth() < 3 {
        fail!(ExceptionCode::StackUnderflow);
    }
    engine.try_use_gas(20_000)?;
    fetch_stack(engine, 3)?;
    // Type-check all three values before decoding any, in top-to-bottom order.
    let key = engine.cmd.var(0).as_cell()?.clone();
    let signature = engine.cmd.var(1).as_cell()?.clone();
    let message = engine.cmd.var(2).as_cell()?.clone();
    let key = read_bytes(engine, key, PUBLIC_KEY_BYTES)?;
    let signature = read_bytes(engine, signature, SIGNATURE_BYTES)?;
    let message = read_bytes(engine, message, MAX_MESSAGE_BYTES)?;
    if key.len() != PUBLIC_KEY_BYTES || signature.len() != SIGNATURE_BYTES {
        fail!(ExceptionCode::CellUnderflow, "incorrect Falcon-512 input length");
    }
    let valid = match rtos_pq_crypto::falcon512::verify(&message, &signature, &key) {
        Ok(valid) => valid,
        Err(rtos_pq_crypto::falcon512::VerifyError::Backend(_)) => {
            fail!(ExceptionCode::FatalError, "Falcon-512 verifier backend failure");
        }
        Err(_) => fail!(ExceptionCode::CellUnderflow, "incorrect Falcon-512 input length"),
    };
    // Deliberately do not consult chksig_always_succeed or the classic free-call allowance.
    engine.cc.stack.push(StackItem::boolean(valid));
    Ok(())
}
