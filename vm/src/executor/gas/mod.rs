/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::{
    executor::{
        engine::{storage::fetch_stack, Engine},
        types::Instruction,
    },
    stack::{
        integer::{conversion::FromInt, IntegerData},
        StackItem,
    },
};
use num::Signed;
use rtos_block::{fail, ExceptionCode, Status};

pub mod gas_state;

fn setgaslimit(engine: &mut Engine, gas_limit: i64) -> Status {
    if gas_limit < engine.gas_used() {
        fail!(ExceptionCode::OutOfGas);
    }
    engine.new_gas_limit(gas_limit);
    Ok(())
}

// Application-specific primitives - A.10; Gas-related primitives - A.10.2
// ACCEPT - F800
pub fn execute_accept(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("ACCEPT"))?;
    engine.new_gas_limit(i64::MAX);
    Ok(())
}
// Application-specific primitives - A.11; Gas-related primitives - A.11.2
// SETGASLIMIT - F801
pub fn execute_setgaslimit(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("SETGASLIMIT"))?;
    fetch_stack(engine, 1)?;
    let gas_limit = engine.cmd.var(0).as_integer()?.take_value_of(|x| {
        Some(if x.is_positive() { i64::from_int(x).unwrap_or(i64::MAX) } else { 0 })
    })?;
    setgaslimit(engine, gas_limit)
}

// Returns gas consumed by VM so far (including this instruction).
pub fn execute_gasconsumed(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("GASCONSUMED"))?;
    let gas = engine.gas_used();
    engine.cc.stack.push(int!(gas));
    Ok(())
}

// Application-specific primitives - A.11; Gas-related primitives - A.11.2
// COMMIT - F80F
pub fn execute_commit(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("COMMIT"))?;
    engine.try_commit()
}
