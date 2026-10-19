// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::{
    engine::{storage::fetch_stack, Engine},
    pq::{read_bytes_priced, PQ_LMS_FEE_HASH_MIN_VERSION},
    types::Instruction,
};
use crate::stack::StackItem;
use rtos_block::{fail, ExceptionCode, Status};
use rtos_pq_crypto::lms_fee::{self, Outcome};

pub(super) fn execute_lms_fee_hash(engine: &mut Engine) -> Status {
    if engine.block_version() < PQ_LMS_FEE_HASH_MIN_VERSION {
        return engine.reject_unavailable_instruction();
    }
    engine.load_instruction(Instruction::new("LMSCHECKFEEHASH"))?;
    if engine.cc.stack.depth() < 4 {
        fail!(ExceptionCode::StackUnderflow);
    }
    fetch_stack(engine, 4)?;
    let key = engine.cmd.var(0).as_cell()?.clone();
    let signature = engine.cmd.var(1).as_cell()?.clone();
    let leaf = engine.cmd.var(2).as_integer_value(0..=(1u32 << 20) - 1)?;
    let digest = engine.cmd.var(3).as_integer()?;
    // Unlike the bounded leaf conversion, C++ pop_int_finite rejects NaN
    // with integer overflow before checking the unsigned 256-bit range.
    if digest.is_nan() {
        fail!(ExceptionCode::IntegerOverflow);
    }
    let message = digest.as_u256()?;
    let key = read_bytes_priced(engine, key, lms_fee::PUBLIC_KEY_BYTES, 0)?;
    let Some(compressions) = lms_fee::worst_compressions(&key, 32) else {
        fail!(ExceptionCode::CellUnderflow, "unsupported LMS fee profile");
    };
    let Some(gas) = i64::try_from(compressions)
        .ok()
        .and_then(|n| n.checked_mul(3))
        .and_then(|n| n.checked_add(500))
    else {
        fail!(ExceptionCode::OutOfGas);
    };
    engine.try_use_gas(gas)?;
    let signature = read_bytes_priced(engine, signature, lms_fee::MAX_SIGNATURE_BYTES, 0)?;
    let accepted = match lms_fee::verify(&message, &signature, &key) {
        Outcome::Valid => u32::from_be_bytes(signature[4..8].try_into().unwrap()) == leaf,
        Outcome::Invalid => false,
        Outcome::Malformed => {
            fail!(ExceptionCode::CellUnderflow, "malformed LMS fee signature");
        }
    };
    engine.cc.stack.push(StackItem::boolean(accepted));
    Ok(())
}
