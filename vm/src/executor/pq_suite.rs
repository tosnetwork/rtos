// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
// RTOS: bounded suite dispatch through self-contained verification backends.
use super::{
    engine::{storage::fetch_stack, Engine},
    pq::{read_bytes_priced, PQ_FALCON512_MIN_VERSION, PQ_SUITE_MIN_VERSION},
    types::Instruction,
};
use crate::stack::StackItem;
use rtos_block::{fail, ExceptionCode, Status};
use rtos_pq_crypto::{falcon512, lms_fee, slhdsa128s};

pub(super) fn execute_pq_suite(engine: &mut Engine) -> Status {
    if engine.block_version() < PQ_SUITE_MIN_VERSION {
        return engine.reject_unavailable_instruction();
    }
    engine.load_instruction(Instruction::new("PQCHECKSIG_SUITE"))?;
    if engine.cc.stack.depth() < 5 {
        fail!(ExceptionCode::StackUnderflow);
    }
    fetch_stack(engine, 5)?;
    let suite = engine.cmd.var(0).as_integer_value(0..=255)?;
    // Every operand is type-checked before dispatch, charging or decoding.
    let key = engine.cmd.var(1).as_cell()?.clone();
    let signature = engine.cmd.var(2).as_cell()?.clone();
    let context = engine.cmd.var(3).as_cell()?.clone();
    let message = engine.cmd.var(4).as_cell()?.clone();
    let valid = match suite {
        1 => {
            use rtos_pq_crypto::{
                MAX_CONTEXT_BYTES, MAX_MESSAGE_BYTES, PUBLIC_KEY_BYTES, SIGNATURE_BYTES,
            };
            let key = read_bytes_priced(engine, key, PUBLIC_KEY_BYTES, 0)?;
            let signature = read_bytes_priced(engine, signature, SIGNATURE_BYTES, 0)?;
            let context = read_bytes_priced(engine, context, MAX_CONTEXT_BYTES, 0)?;
            let message = read_bytes_priced(engine, message, MAX_MESSAGE_BYTES, 0)?;
            engine.register_signature_call()?;
            match rtos_pq_crypto::verify(&message, &context, &signature, &key) {
                Ok(valid) => valid,
                Err(rtos_pq_crypto::VerifyError::Backend(_)) => {
                    fail!(ExceptionCode::FatalError, "ML-DSA verifier backend failure");
                }
                Err(_) => fail!(ExceptionCode::CellUnderflow, "malformed ML-DSA input"),
            }
        }
        2 => {
            // Generic dispatch cannot activate Falcon before its dedicated opcode.
            if engine.block_version() < PQ_FALCON512_MIN_VERSION {
                fail!(ExceptionCode::RangeCheckError, "PQ suite not active at this version");
            }
            engine.try_use_gas(20_000)?;
            read_bytes_priced(engine, context, 0, 1)?;
            let key = read_bytes_priced(engine, key, falcon512::PUBLIC_KEY_BYTES, 1)?;
            let signature = read_bytes_priced(engine, signature, falcon512::SIGNATURE_BYTES, 1)?;
            let message = read_bytes_priced(engine, message, falcon512::MAX_MESSAGE_BYTES, 1)?;
            match falcon512::verify(&message, &signature, &key) {
                Ok(valid) => valid,
                Err(falcon512::VerifyError::Backend(_)) => {
                    fail!(ExceptionCode::FatalError, "Falcon verifier backend failure");
                }
                Err(_) => fail!(ExceptionCode::CellUnderflow, "malformed Falcon input"),
            }
        }
        3 => {
            engine.register_slh_attempt()?;
            engine.try_use_gas(4_500)?;
            let key = read_bytes_priced(engine, key, slhdsa128s::PUBLIC_KEY_BYTES, 0)?;
            let signature = read_bytes_priced(engine, signature, slhdsa128s::SIGNATURE_BYTES, 0)?;
            let context = read_bytes_priced(engine, context, slhdsa128s::MAX_CONTEXT_BYTES, 0)?;
            let message = read_bytes_priced(engine, message, slhdsa128s::MAX_MESSAGE_BYTES, 0)?;
            match slhdsa128s::verify(&message, &context, &signature, &key) {
                Ok(valid) => valid,
                Err(slhdsa128s::VerifyError::Backend(_)) => {
                    fail!(ExceptionCode::FatalError, "SLH-DSA verifier backend failure");
                }
                Err(_) => fail!(ExceptionCode::CellUnderflow, "malformed SLH-DSA input"),
            }
        }
        4 => {
            read_bytes_priced(engine, context, 0, 0)?;
            let key = read_bytes_priced(engine, key, lms_fee::PUBLIC_KEY_BYTES, 0)?;
            let message = read_bytes_priced(engine, message, lms_fee::MAX_MESSAGE_BYTES, 0)?;
            let Some(worst) = lms_fee::worst_compressions(&key, message.len()) else {
                fail!(ExceptionCode::CellUnderflow, "unsupported LMS fee profile");
            };
            let Some(gas) = worst
                .checked_mul(3)
                .and_then(|v| v.checked_add(500))
                .and_then(|v| i64::try_from(v).ok())
            else {
                fail!(ExceptionCode::FatalError, "LMS fee cost exceeds gas range");
            };
            // Charge the admitted profile's worst case before reading the signature.
            engine.try_use_gas(gas)?;
            let signature = read_bytes_priced(engine, signature, lms_fee::MAX_SIGNATURE_BYTES, 0)?;
            match lms_fee::verify(&message, &signature, &key) {
                lms_fee::Outcome::Valid => true,
                lms_fee::Outcome::Invalid => false,
                lms_fee::Outcome::Malformed => {
                    fail!(ExceptionCode::CellUnderflow, "malformed LMS input")
                }
            }
        }
        _ => fail!(ExceptionCode::RangeCheckError, "unknown PQ suite"),
    };
    engine.cc.stack.push(StackItem::boolean(valid));
    Ok(())
}
