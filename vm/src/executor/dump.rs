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
        engine::Engine,
        types::{Instruction, InstructionOptions},
    },
    stack::StackItem,
};
use rtos_block::{Mask, Status};
use std::{cmp, str, sync::Arc};

const STR: u8 = 0x01;
const HEX: u8 = 0x02;
const BIN: u8 = 0x04;
const DEPTH: u8 = 0x08; // integer 1..15
const INDEX: u8 = 0x10; // integer 0..15
const FLUSH: u8 = 0x20; // flush

fn dump_var(item: &StackItem, how: u8) -> String {
    dump_var_impl(item, how, false)
}

fn dump_tuple_impl(x: &[StackItem], how: u8, in_tuple: bool) -> String {
    if in_tuple {
        String::from("(<tuple>)")
    } else {
        format!(
            "({})",
            x.iter().map(|v| dump_var_impl(v, how, true)).collect::<Vec<_>>().join(", ")
        )
    }
}

fn dump_var_impl(item: &StackItem, how: u8, in_tuple: bool) -> String {
    if how.bit(HEX) {
        match item {
            StackItem::None => String::new(),
            StackItem::Builder(x) => format!("BC<{:X}>", Arc::as_ref(x)),
            StackItem::Cell(x) => format!("C<{:X}>", x),
            StackItem::Continuation(x) => {
                x.code().cell_opt().map_or(String::new(), |cell| format!("R<{:X}>", cell))
            }
            StackItem::Integer(x) => format!("{:X}", Arc::as_ref(x)),
            StackItem::Slice(x) => {
                format!("CS<{:X}>({}..{})", x, x.pos(), x.pos() + x.remaining_bits())
            }
            StackItem::Tuple(x) => dump_tuple_impl(x, how, in_tuple),
        }
    } else if how.bit(BIN) {
        match item {
            StackItem::None => String::new(),
            StackItem::Builder(x) => format!("BC<{:b}>", Arc::as_ref(x)),
            StackItem::Cell(x) => format!("C<{:b}>", x),
            StackItem::Continuation(x) => {
                x.code().cell_opt().map_or(String::new(), |cell| format!("R<{:b}>", cell))
            }
            StackItem::Integer(x) => format!("{:b}", Arc::as_ref(x)),
            StackItem::Slice(x) => x.cell().map_or(String::new(), |cell| {
                format!("CS<{:b}>({}..{})", cell, x.pos(), x.pos() + x.remaining_bits())
            }),
            StackItem::Tuple(x) => dump_tuple_impl(x, how, in_tuple),
        }
    } else if how.bit(STR) {
        let string = match item {
            StackItem::None => return String::new(),
            StackItem::Builder(x) => x.data().to_vec(),
            StackItem::Cell(x) => x.data().to_vec(),
            StackItem::Continuation(x) => x.code().get_bytestring(0).into_vec(),
            StackItem::Integer(x) => return format!("{}", Arc::as_ref(x)),
            StackItem::Slice(x) => x.get_bytestring(0).into_vec(),
            StackItem::Tuple(x) => dump_tuple_impl(x, how, in_tuple).as_bytes().to_vec(),
        };
        match str::from_utf8(&string) {
            Ok(result) => result.into(),
            Err(err) => err.to_string(),
        }
    } else {
        match item {
            StackItem::None => String::new(),
            StackItem::Builder(x) => format!("BC<{:X}>", Arc::as_ref(x)),
            StackItem::Cell(x) => format!("C<{:X}>", x),
            StackItem::Continuation(x) => {
                x.code().cell_opt().map_or(String::new(), |cell| format!("R<{:X}>", cell))
            }
            StackItem::Integer(x) => format!("{}", Arc::as_ref(x)),
            StackItem::Slice(x) => x.cell_opt().map_or(String::new(), |cell| {
                format!("CS<{:X}>({}..{})", cell, x.pos(), x.pos() + x.remaining_bits())
            }),
            StackItem::Tuple(x) => dump_tuple_impl(x, how, in_tuple),
        }
    }
}
/// dumps stack vars using internal fn dump_var
fn dump_stack(engine: &mut Engine, depth: usize, print_depth: bool) -> Status {
    for i in 0..depth {
        let dump = dump_var(engine.cc.stack.get(i)?, 0) + "\n";
        engine.dump(&dump);
    }
    if print_depth {
        engine.dump(&format!("{}\n", depth));
    }
    engine.flush();
    Ok(())
}
/// internal dump with how and closure
fn internal_dump<F>(engine: &mut Engine, name: &'static str, how: u8, op: F) -> Status
where
    F: FnOnce(&mut Engine) -> Status,
{
    let mut instruction = Instruction::new(name);
    if how.bit(DEPTH) {
        instruction = instruction.set_opts(InstructionOptions::Integer(1..15))
    }
    if how.bit(INDEX) {
        instruction = instruction.set_opts(InstructionOptions::Integer(0..15))
    }
    engine.load_instruction(instruction)?;
    if engine.debug() {
        op(engine)?;
    }
    if how.bit(FLUSH) {
        engine.flush();
    }
    Ok(())
}
/// dumps all the stack
pub(crate) fn execute_dump_stack(engine: &mut Engine) -> Status {
    internal_dump(engine, "DUMPSTK", FLUSH, |engine| {
        let depth = cmp::min(engine.cc.stack.depth(), 255);
        dump_stack(engine, depth, true)
    })
}
/// dumps al least top 1..15 registers
pub(crate) fn execute_dump_stack_top(engine: &mut Engine) -> Status {
    internal_dump(engine, "DUMPSTKTOP", FLUSH | DEPTH, |engine| {
        let depth = cmp::min(engine.cc.stack.depth(), engine.cmd.integer() as usize);
        dump_stack(engine, depth, false)
    })
}
/// buffers s0 as hex
pub(crate) fn execute_print_hex(engine: &mut Engine) -> Status {
    internal_dump(engine, "HEXPRINT", 0, |engine| {
        if engine.cc.stack.depth() > 0 {
            let dump = dump_var(engine.cc.stack.get(0)?, HEX);
            engine.dump(&dump);
        }
        Ok(())
    })
}
/// buffers s0 as binary
pub(crate) fn execute_print_bin(engine: &mut Engine) -> Status {
    internal_dump(engine, "BINPRINT", 0, |engine| {
        if engine.cc.stack.depth() > 0 {
            let dump = dump_var(engine.cc.stack.get(0)?, BIN);
            engine.dump(&dump);
        }
        Ok(())
    })
}
/// buffers s0 as string
pub(crate) fn execute_print_str(engine: &mut Engine) -> Status {
    internal_dump(engine, "STRPRINT", 0, |engine| {
        if engine.cc.stack.depth() > 0 {
            let dump = dump_var(engine.cc.stack.get(0)?, STR);
            engine.dump(&dump);
        }
        Ok(())
    })
}
/// dumps s0 as hex
pub(crate) fn execute_dump_hex(engine: &mut Engine) -> Status {
    internal_dump(engine, "HEXDUMP", FLUSH, |engine| {
        if engine.cc.stack.depth() > 0 {
            let dump = dump_var(engine.cc.stack.get(0)?, HEX) + "\n";
            engine.dump(&dump);
        }
        Ok(())
    })
}
/// dumps s0 as binary
pub(crate) fn execute_dump_bin(engine: &mut Engine) -> Status {
    internal_dump(engine, "BINDUMP", FLUSH, |engine| {
        if engine.cc.stack.depth() > 0 {
            let dump = dump_var(engine.cc.stack.get(0)?, BIN) + "\n";
            engine.dump(&dump);
        }
        Ok(())
    })
}
/// dumps s0 as string
pub(crate) fn execute_dump_str(engine: &mut Engine) -> Status {
    internal_dump(engine, "STRDUMP", FLUSH, |engine| {
        if engine.cc.stack.depth() > 0 {
            let dump = dump_var(engine.cc.stack.get(0)?, STR) + "\n";
            engine.dump(&dump);
        }
        Ok(())
    })
}
/// turns debug output on
pub(crate) fn execute_debug_on(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("DEBUGON"))?;
    engine.switch_debug(true);
    Ok(())
}
/// turns debug output off
pub(crate) fn execute_debug_off(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("DEBUGOFF"))?;
    engine.switch_debug(true);
    Ok(())
}
/// dumps s(n)
pub(crate) fn execute_dump_var(engine: &mut Engine) -> Status {
    internal_dump(engine, "DUMP", FLUSH | INDEX, |engine| {
        let index = engine.cmd.integer() as usize;
        if index < engine.cc.stack.depth() {
            let dump = format!("{}\n", engine.cc.stack.get(index)?);
            engine.dump(&dump);
        }
        Ok(())
    })
}
/// prints s(n)
pub(crate) fn execute_print_var(engine: &mut Engine) -> Status {
    internal_dump(engine, "PRINT", INDEX, |engine| {
        let index = engine.cmd.integer() as usize;
        if index < engine.cc.stack.depth() {
            let dump = format!("{}\n", engine.cc.stack.get(index)?);
            engine.dump(&dump);
        }
        Ok(())
    })
}

/// 0xFEFn: a debug string of n + 1 bytes. Execution only skips the bytes: the instruction is
/// charged as a 16-bit opcode and fails (InvalidOpcode) only when the code ends before the
/// declared data. The content never raises an exception; with debug output enabled the first
/// byte selects the log form and the rest is logged lossily.
pub(crate) fn execute_dump_string(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("DEBUGSTR").set_opts(InstructionOptions::Bytestring(12, 0, 4, 1)),
    )?;
    if engine.debug() {
        let bytes = engine.cmd.slice().get_bytestring(0);
        if let Some((kind, text)) = bytes.split_first() {
            let text = String::from_utf8_lossy(text).into_owned();
            match kind {
                0 if text.is_empty() => engine.flush(),
                0 => engine.dump(&text),
                1 => {
                    engine.dump(&text);
                    engine.flush();
                }
                _ => engine.dump(&text),
            }
        }
    }
    Ok(())
}

/// Debug opcodes without a debug action (0xFE0F, 0xFE16..0xFE1D, 0xFE2F, 0xFE3F,
/// 0xFE40..0xFEEF): 16-bit no-ops.
pub(crate) fn execute_dummy_debug(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("DEBUG"))
}

#[cfg(test)]
#[path = "../tests/test_dump.rs"]
mod tests;
