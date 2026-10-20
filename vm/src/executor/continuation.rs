/*
 * RTOS project modifications (2026-10-10): historical continuation save semantics and snapshot preservation.
 * RTOS project modifications (2026-10-19): jumps resolve continuation chains in one place, with
 * the nested-jump charge; loops, envelopes and PushInt keep full continuations; control-data
 * writes follow the reference force-cdata rules.
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
    error::tvm_exception_or_custom_code,
    executor::{
        engine::{
            data::convert,
            storage::{copy_to_var, fetch_reference, fetch_stack, swap},
            Engine,
        },
        gas::gas_state::Gas,
        microcode::{CC, CELL, CONTINUATION, CTRL, VAR},
        types::{Instruction, InstructionOptions},
        RunChildVm,
    },
    stack::{
        continuation::{ContinuationData, ContinuationType},
        integer::{behavior::Signaling, IntegerData},
        savelist::SaveList,
        Stack, StackItem,
    },
};
use rtos_block::{fail, ExceptionCode, Mask, Result, Status};
use std::{
    mem,
    ops::Range,
    sync::{Arc, LazyLock},
};

const CALLX: u8 = 0x40; // CALLX to found value
const SWITCH: u8 = 0x80; // SWITCH to found value
const PREPARE: u8 = 0xC0; // pass found value to stack
const TVM_VERSION_14: u32 = 14;
/// Jumps resolved inside one jump that are free of charge; each further one costs 1 gas.
const FREE_NESTED_CONT_JUMP: usize = 8;
/// First global version with the nested-jump charge and the in-chain stack adjustment.
const NESTED_JUMP_VERSION: u32 = 9;

// Continuation values ********************************************************

static QUIT0: LazyLock<StackItem> = LazyLock::new(|| {
    let quit = ContinuationType::Quit(ExceptionCode::NormalTermination as i32);
    StackItem::continuation(ContinuationData::with_type(quit))
});
static QUIT1: LazyLock<StackItem> = LazyLock::new(|| {
    let quit = ContinuationType::Quit(ExceptionCode::AlternativeTermination as i32);
    StackItem::continuation(ContinuationData::with_type(quit))
});

/// The shared quit continuation for exit code 0 or 1.
fn quit(code: i32) -> StackItem {
    if code == ExceptionCode::NormalTermination as i32 {
        QUIT0.clone()
    } else {
        QUIT1.clone()
    }
}

fn unwrap_arc(data: Arc<ContinuationData>) -> ContinuationData {
    Arc::try_unwrap(data).unwrap_or_else(|data| (*data).clone())
}

/// Takes the continuation out of a stack item (type check as in the reference `as_cont`).
fn item_into_cont(mut item: StackItem) -> Result<ContinuationData> {
    Ok(unwrap_arc(item.take_continuation()?))
}

/// A continuation being jumped to: owned, or shared with other holders.
// Short-lived on the stack of a jump; boxing the owned variant would allocate on every jump.
#[allow(clippy::large_enum_variant)]
enum Cont {
    Owned(ContinuationData),
    Shared(Arc<ContinuationData>),
}

impl Cont {
    fn get(&self) -> &ContinuationData {
        match self {
            Cont::Owned(cont) => cont,
            Cont::Shared(cont) => cont,
        }
    }

    fn into_owned(self) -> ContinuationData {
        match self {
            Cont::Owned(cont) => cont,
            Cont::Shared(cont) => unwrap_arc(cont),
        }
    }
}

/// A copy of control register `index`; an empty register reads as a type error.
fn ctrl_cont(engine: &Engine, index: usize) -> Result<ContinuationData> {
    match engine.ctrls.get(index) {
        Some(item) => Ok(item.as_continuation()?.clone()),
        None => fail!(ExceptionCode::TypeCheckError, "control register c{} is empty", index),
    }
}

fn set_ctrl_cont(engine: &mut Engine, index: usize, cont: ContinuationData) {
    engine.ctrls.put_opt(index, StackItem::continuation(cont));
}

// Stack and gas helpers (reference stack and gas semantics) ******************

pub(in crate::executor) fn consume_gas(engine: &mut Engine, gas: i64) -> Status {
    if engine.block_version() >= 4 {
        engine.try_use_gas(gas)
    } else {
        engine.use_gas(gas);
        Ok(())
    }
}

fn consume_stack_gas(engine: &mut Engine, depth: usize) -> Status {
    consume_gas(engine, Gas::stack_price(depth))
}

fn check_underflow(engine: &Engine, depth: usize) -> Status {
    if engine.cc.stack.depth() < depth {
        fail!(
            ExceptionCode::StackUnderflow,
            "stack underflow: {} needed, depth {}",
            depth,
            engine.cc.stack.depth()
        )
    }
    Ok(())
}

/// Splits off the top `count` items (caller has checked the depth), order preserved.
fn split_top(stack: &mut Stack, count: usize) -> Stack {
    let depth = stack.depth();
    Stack::with_storage(stack.storage.split_off(depth - count))
}

/// Moves the top `count` items of `src` onto the top of `dst` (caller has checked the depth).
fn move_from_stack(dst: &mut Stack, src: &mut Stack, count: usize) {
    let depth = src.depth();
    let mut moved = src.storage.split_off(depth - count);
    dst.storage.append(&mut moved);
}

fn pop_cont(engine: &mut Engine) -> Result<ContinuationData> {
    let item = engine.cc.stack.pop()?;
    item_into_cont(item)
}

fn pop_bool(engine: &mut Engine) -> Result<bool> {
    engine.cc.stack.pop()?.as_bool()
}

fn pop_smallint_range(engine: &mut Engine, max: isize, min: isize) -> Result<isize> {
    let item = engine.cc.stack.pop()?;
    item.as_integer()?.as_integer_value(min..=max)
}

fn push_code(engine: &mut Engine) {
    let code = engine.cc.code().clone();
    engine.cc.stack.push(StackItem::Slice(code));
}

// Jumps, calls and returns ***************************************************

/// Captures the current continuation (`extract_cc`): `save_cr` bits 1/2/4 move c0/c1/c2 into
/// it (c0 and c1 are reset to the quit continuations); `stack_copy` top items stay current.
pub(in crate::executor) fn extract_cc(
    engine: &mut Engine,
    save_cr: u8,
    stack_copy: isize,
    cc_args: isize,
) -> Result<ContinuationData> {
    let depth = engine.cc.stack.depth();
    let cc_stack = if stack_copy < 0 || stack_copy as usize == depth {
        Stack::new()
    } else if stack_copy > 0 {
        let copy = stack_copy as usize;
        check_underflow(engine, copy)?;
        let top = split_top(&mut engine.cc.stack, copy);
        let rest = mem::replace(&mut engine.cc.stack, top);
        consume_stack_gas(engine, copy)?;
        rest
    } else {
        mem::take(&mut engine.cc.stack)
    };
    let code = mem::take(engine.cc.code_mut());
    let mut cc = ContinuationData::with_code_and_stack(code, cc_stack);
    cc.nargs = cc_args;
    if save_cr & 1 != 0 {
        if let Some(c0) = engine.ctrls.remove(0) {
            cc.savelist.put_opt(0, c0);
        }
        engine.ctrls.put_opt(0, quit(ExceptionCode::NormalTermination as i32));
    }
    if save_cr & 2 != 0 {
        if let Some(c1) = engine.ctrls.remove(1) {
            cc.savelist.put_opt(1, c1);
        }
        engine.ctrls.put_opt(1, quit(ExceptionCode::AlternativeTermination as i32));
    }
    if save_cr & 4 != 0 {
        if let Some(c2) = engine.ctrls.remove(2) {
            cc.savelist.put_opt(2, c2);
        }
    }
    Ok(cc)
}

/// Prepares the stack for a jump to `cont` (`adjust_jump_cont`): checks the argument counts,
/// merges a captured stack or drops the bottom of the current one.
fn adjust_jump_cont(engine: &mut Engine, cont: Cont, pass_args: isize) -> Result<Cont> {
    let depth = engine.cc.stack.depth() as isize;
    let data = cont.get();
    if data.has_cdata() {
        if pass_args > depth || data.nargs > depth {
            fail!(
                ExceptionCode::StackUnderflow,
                "stack underflow while jumping to a continuation: not enough arguments on stack"
            )
        }
        if data.nargs > pass_args && pass_args >= 0 {
            fail!(
                ExceptionCode::StackUnderflow,
                "stack underflow while jumping to closure continuation: not enough arguments passed"
            )
        }
        let mut copy = data.nargs;
        if pass_args >= 0 && copy < 0 {
            copy = pass_args;
        }
        if !data.stack.is_empty() {
            if copy < 0 {
                copy = depth;
            }
            let mut cont = cont.into_owned();
            let mut new_stack = mem::take(&mut cont.stack);
            move_from_stack(&mut new_stack, &mut engine.cc.stack, copy as usize);
            let new_depth = new_stack.depth();
            engine.cc.stack = new_stack;
            consume_stack_gas(engine, new_depth)?;
            return Ok(Cont::Owned(cont));
        } else if copy >= 0 && copy < depth {
            engine.cc.stack.storage.drain(..(depth - copy) as usize);
            consume_stack_gas(engine, copy as usize)?;
        }
    } else if pass_args >= 0 {
        if pass_args > depth {
            fail!(
                ExceptionCode::StackUnderflow,
                "stack underflow while jumping to a continuation: not enough arguments on stack"
            )
        } else if pass_args < depth {
            engine.cc.stack.storage.drain(..(depth - pass_args) as usize);
            consume_stack_gas(engine, pass_args as usize)?;
        }
    }
    Ok(cont)
}

fn apply_shared_savelist(engine: &mut Engine, cont: &ContinuationData) {
    for index in SaveList::REGS {
        if let Some(item) = cont.savelist.get(index) {
            engine.ctrls.put_opt(index, item.clone());
        }
    }
}

/// One link of a loop continuation held uniquely: updated in place and installed as c0 again
/// (the reference reuses the object in this case). Returns the continuation to hand over to,
/// or gives the loop back when the general path applies.
fn loop_in_place(
    engine: &mut Engine,
    mut cont: Arc<ContinuationData>,
) -> Result<std::result::Result<Cont, Arc<ContinuationData>>> {
    let Some(data) = Arc::get_mut(&mut cont) else {
        return Ok(Err(cont));
    };
    let next = match &mut data.type_of {
        ContinuationType::Repeat { count, body, .. } if *count > 0 && !body.has_c0() => {
            *count -= 1;
            body.clone()
        }
        ContinuationType::Again { body } if !body.has_c0() => body.clone(),
        ContinuationType::While { check_cond: check_cond @ false, cond, .. } if !cond.has_c0() => {
            *check_cond = true;
            cond.clone()
        }
        ContinuationType::While { check_cond: check_cond @ true, body, after, .. } => {
            if !pop_bool(engine)? {
                return Ok(Ok(Cont::Shared(after.clone())));
            }
            if body.has_c0() {
                return Ok(Ok(Cont::Shared(body.clone())));
            }
            *check_cond = false;
            body.clone()
        }
        ContinuationType::Until { body, after } => {
            if pop_bool(engine)? {
                return Ok(Ok(Cont::Shared(after.clone())));
            }
            if body.has_c0() {
                return Ok(Ok(Cont::Shared(body.clone())));
            }
            body.clone()
        }
        _ => return Ok(Err(cont)),
    };
    engine.ctrls.put_opt(0, StackItem::Continuation(cont));
    Ok(Ok(Cont::Shared(next)))
}

/// Resolves one link of a jump; returns the continuation the link hands over to, if any.
fn jump_once(engine: &mut Engine, cont: Cont) -> Result<Option<Cont>> {
    let shared = match cont {
        Cont::Owned(cont) => return jump_once_owned(engine, cont),
        Cont::Shared(cont) => cont,
    };
    let shared = match loop_in_place(engine, shared)? {
        Ok(next) => return Ok(Some(next)),
        Err(shared) => shared,
    };
    match Arc::try_unwrap(shared) {
        Ok(cont) => jump_once_owned(engine, cont),
        Err(shared) => match &shared.type_of {
            ContinuationType::Ordinary => {
                apply_shared_savelist(engine, &shared);
                *engine.cc.code_mut() = shared.code().clone();
                engine.cc.nargs = -1;
                Ok(None)
            }
            ContinuationType::Envelope(next) => {
                apply_shared_savelist(engine, &shared);
                Ok(Some(Cont::Shared(next.clone())))
            }
            ContinuationType::PushInt(value, next) => {
                engine.cc.stack.push(int!(*value));
                Ok(Some(Cont::Shared(next.clone())))
            }
            _ => jump_once_owned(engine, (*shared).clone()),
        },
    }
}

fn jump_once_owned(engine: &mut Engine, mut cont: ContinuationData) -> Result<Option<Cont>> {
    match mem::take(&mut cont.type_of) {
        ContinuationType::Ordinary => {
            engine.ctrls.apply(&mut cont.savelist);
            *engine.cc.code_mut() = mem::take(cont.code_mut());
            engine.cc.nargs = -1;
            Ok(None)
        }
        ContinuationType::Envelope(next) => {
            engine.ctrls.apply(&mut cont.savelist);
            Ok(Some(Cont::Shared(next)))
        }
        ContinuationType::PushInt(value, next) => {
            engine.cc.stack.push(int!(value));
            Ok(Some(Cont::Shared(next)))
        }
        ContinuationType::Quit(code) => {
            engine.finish(code);
            Ok(None)
        }
        ContinuationType::ExcQuit => {
            let code = match pop_smallint_range(engine, 0xffff, 0) {
                Ok(code) => code as i32,
                Err(err) => tvm_exception_or_custom_code(&err),
            };
            engine.finish(code);
            Ok(None)
        }
        ContinuationType::Repeat { count, body, after } => {
            if count <= 0 {
                return Ok(Some(Cont::Shared(after)));
            }
            if body.has_c0() {
                return Ok(Some(Cont::Shared(body)));
            }
            let next = body.clone();
            let repeat = ContinuationType::Repeat { count: count - 1, body, after };
            set_ctrl_cont(engine, 0, ContinuationData::with_type(repeat));
            Ok(Some(Cont::Shared(next)))
        }
        ContinuationType::Again { body } => {
            if body.has_c0() {
                return Ok(Some(Cont::Shared(body)));
            }
            let next = body.clone();
            set_ctrl_cont(engine, 0, ContinuationData::with_type(ContinuationType::Again { body }));
            Ok(Some(Cont::Shared(next)))
        }
        ContinuationType::Until { body, after } => {
            if pop_bool(engine)? {
                return Ok(Some(Cont::Shared(after)));
            }
            if body.has_c0() {
                return Ok(Some(Cont::Shared(body)));
            }
            let next = body.clone();
            let until = ContinuationType::Until { body, after };
            set_ctrl_cont(engine, 0, ContinuationData::with_type(until));
            Ok(Some(Cont::Shared(next)))
        }
        ContinuationType::While { check_cond: true, cond, body, after } => {
            if !pop_bool(engine)? {
                return Ok(Some(Cont::Shared(after)));
            }
            if body.has_c0() {
                return Ok(Some(Cont::Shared(body)));
            }
            let next = body.clone();
            let loop_ = ContinuationType::While { check_cond: false, cond, body, after };
            set_ctrl_cont(engine, 0, ContinuationData::with_type(loop_));
            Ok(Some(Cont::Shared(next)))
        }
        ContinuationType::While { check_cond: false, cond, body, after } => {
            if cond.has_c0() {
                return Ok(Some(Cont::Shared(cond)));
            }
            let next = cond.clone();
            let loop_ = ContinuationType::While { check_cond: true, cond, body, after };
            set_ctrl_cont(engine, 0, ContinuationData::with_type(loop_));
            Ok(Some(Cont::Shared(next)))
        }
    }
}

/// Resolves a whole jump (`jump_to`). Every link counts; from the nested-jump version each
/// link after the first eight costs 1 gas, and a link with a captured stack or a fixed
/// argument count is stack-adjusted before it is entered.
fn resolve(engine: &mut Engine, cont: Cont) -> Status {
    let nested = engine.block_version() >= NESTED_JUMP_VERSION;
    let mut next = Some(cont);
    let mut count = 0usize;
    while let Some(cont) = next.take() {
        next = jump_once(engine, cont)?;
        count += 1;
        if nested && count > FREE_NESTED_CONT_JUMP {
            consume_gas(engine, 1)?;
        }
        if nested {
            if let Some(cont) = next.take() {
                next = Some(if cont.get().needs_stack_adjust() {
                    adjust_jump_cont(engine, cont, -1)?
                } else {
                    cont
                });
            }
        }
    }
    Ok(())
}

pub(in crate::executor) fn jump_to(engine: &mut Engine, cont: ContinuationData) -> Status {
    resolve(engine, Cont::Owned(cont))
}

fn jump_cont(engine: &mut Engine, cont: Cont) -> Status {
    if cont.get().needs_stack_adjust() {
        let cont = adjust_jump_cont(engine, cont, -1)?;
        resolve(engine, cont)
    } else {
        resolve(engine, cont)
    }
}

/// Simple jump (`jump(cont)`).
pub(in crate::executor) fn jump(engine: &mut Engine, cont: ContinuationData) -> Status {
    jump_cont(engine, Cont::Owned(cont))
}

/// Jump passing `pass_args` stack items (-1 for all), `jump(cont, pass_args)`.
pub(in crate::executor) fn jump_args(
    engine: &mut Engine,
    cont: ContinuationData,
    pass_args: isize,
) -> Status {
    let cont = adjust_jump_cont(engine, Cont::Owned(cont), pass_args)?;
    resolve(engine, cont)
}

/// The return continuation of a call: the rest of the current code with c0 saved.
fn return_cont(engine: &mut Engine, stack: Stack, ret_args: isize) -> ContinuationData {
    let code = mem::take(engine.cc.code_mut());
    let mut ret = ContinuationData::with_code_and_stack(code, stack);
    ret.nargs = ret_args;
    if let Some(c0) = engine.ctrls.remove(0) {
        ret.savelist.put_opt(0, c0);
    }
    ret
}

/// Simple call (`call(cont)`).
pub(in crate::executor) fn call(engine: &mut Engine, cont: ContinuationData) -> Status {
    if cont.has_cdata() {
        if cont.has_c0() {
            return jump(engine, cont);
        }
        if cont.needs_stack_adjust() {
            return call_args(engine, cont, -1, -1);
        }
    }
    let ret = return_cont(engine, Stack::new(), -1);
    set_ctrl_cont(engine, 0, ret);
    jump_to(engine, cont)
}

/// Call passing `pass_args` items and expecting `ret_args` results (-1 for all).
pub(in crate::executor) fn call_args(
    engine: &mut Engine,
    mut cont: ContinuationData,
    pass_args: isize,
    ret_args: isize,
) -> Status {
    let depth = engine.cc.stack.depth() as isize;
    if cont.has_cdata() {
        if cont.has_c0() {
            return jump_args(engine, cont, pass_args);
        }
        if pass_args > depth || cont.nargs > depth {
            fail!(
                ExceptionCode::StackUnderflow,
                "stack underflow while calling a continuation: not enough arguments on stack"
            )
        }
        if cont.nargs > pass_args && pass_args >= 0 {
            fail!(
                ExceptionCode::StackUnderflow,
                "stack underflow while calling a closure continuation: not enough arguments passed"
            )
        }
        let mut copy = cont.nargs;
        let mut skip = 0;
        if pass_args >= 0 {
            if copy >= 0 {
                skip = pass_args - copy;
            } else {
                copy = pass_args;
            }
        }
        let new_stack = if !cont.stack.is_empty() {
            if copy < 0 {
                copy = depth;
            }
            let mut new_stack = mem::take(&mut cont.stack);
            move_from_stack(&mut new_stack, &mut engine.cc.stack, copy as usize);
            if skip > 0 {
                let left = engine.cc.stack.depth();
                engine.cc.stack.storage.truncate(left - skip as usize);
            }
            let new_depth = new_stack.depth();
            consume_stack_gas(engine, new_depth)?;
            new_stack
        } else if copy >= 0 {
            let new_stack = split_top(&mut engine.cc.stack, copy as usize);
            if skip > 0 {
                let left = engine.cc.stack.depth();
                engine.cc.stack.storage.truncate(left - skip as usize);
            }
            consume_stack_gas(engine, copy as usize)?;
            new_stack
        } else {
            mem::take(&mut engine.cc.stack)
        };
        let rest = mem::replace(&mut engine.cc.stack, new_stack);
        let ret = return_cont(engine, rest, ret_args);
        set_ctrl_cont(engine, 0, ret);
        jump_to(engine, cont)
    } else {
        if pass_args > depth {
            fail!(
                ExceptionCode::StackUnderflow,
                "stack underflow while calling a continuation: not enough arguments on stack"
            )
        }
        let new_stack = if pass_args >= 0 {
            let new_stack = split_top(&mut engine.cc.stack, pass_args as usize);
            consume_stack_gas(engine, pass_args as usize)?;
            new_stack
        } else {
            mem::take(&mut engine.cc.stack)
        };
        let rest = mem::replace(&mut engine.cc.stack, new_stack);
        let ret = return_cont(engine, rest, ret_args);
        set_ctrl_cont(engine, 0, ret);
        jump_to(engine, cont)
    }
}

fn take_ctrl_for_return(engine: &mut Engine, index: usize, code: i32) -> Result<Cont> {
    let item = engine.ctrls.remove(index);
    engine.ctrls.put_opt(index, quit(code));
    match item {
        Some(mut item) => Ok(Cont::Shared(item.take_continuation()?)),
        None => Ok(Cont::Owned(ContinuationData::with_type(ContinuationType::Quit(code)))),
    }
}

/// Return to c0, which is replaced by the quit continuation.
pub(in crate::executor) fn ret(engine: &mut Engine) -> Status {
    let cont = take_ctrl_for_return(engine, 0, ExceptionCode::NormalTermination as i32)?;
    jump_cont(engine, cont)
}

fn ret_args(engine: &mut Engine, ret_args: isize) -> Status {
    let cont = take_ctrl_for_return(engine, 0, ExceptionCode::NormalTermination as i32)?;
    let cont = adjust_jump_cont(engine, cont, ret_args)?;
    resolve(engine, cont)
}

/// Return to c1, which is replaced by the alternative quit continuation.
fn ret_alt(engine: &mut Engine) -> Status {
    let cont = take_ctrl_for_return(engine, 1, ExceptionCode::AlternativeTermination as i32)?;
    jump_cont(engine, cont)
}

/// `c1_envelope`: optionally saves c1 and c0 into `cont`, then installs it as c1.
fn c1_envelope(engine: &mut Engine, mut cont: ContinuationData, save: bool) -> ContinuationData {
    if save {
        let c1 = engine.ctrls.get(1).cloned();
        let c0 = engine.ctrls.get(0).cloned();
        let cdata = cont.force_cdata();
        cdata.define_opt(1, c1);
        cdata.define_opt(0, c0);
    }
    set_ctrl_cont(engine, 1, cont.clone());
    cont
}

fn c1_envelope_if(engine: &mut Engine, cond: bool, cont: ContinuationData) -> ContinuationData {
    if cond {
        c1_envelope(engine, cont, true)
    } else {
        cont
    }
}

/// `c1_save_set`: saves c1 into c0, then c1 = c0.
fn c1_save_set(engine: &mut Engine) -> Status {
    let mut c0 = ctrl_cont(engine, 0)?;
    let c1 = engine.ctrls.get(1).cloned();
    c0.force_cdata().define_opt(1, c1);
    set_ctrl_cont(engine, 0, c0.clone());
    set_ctrl_cont(engine, 1, c0);
    Ok(())
}

// Wrappers for continuations taken from instruction variables ****************

fn take_var_cont(engine: &mut Engine, index: usize) -> Result<ContinuationData> {
    let item = mem::take(engine.cmd.var_mut(index));
    item_into_cont(item)
}

/// Simple call of the continuation in variable `callee` (converted from a cell if asked).
pub(super) fn callx(engine: &mut Engine, callee: usize, need_convert: bool) -> Status {
    let vars = engine.cmd.var_count();
    if vars < callee {
        fail!("callx {:X}", callee)
    } else if vars == callee {
        fetch_stack(engine, 1)?;
    } else if need_convert && engine.cmd.var(callee).as_cell().is_ok() {
        convert(engine, var!(callee), CONTINUATION, CELL)?;
    }
    let cont = take_var_cont(engine, callee)?;
    call(engine, cont)
}

/// Simple jump to the continuation in the variable at `address`.
pub(super) fn switch(engine: &mut Engine, address: u16) -> Status {
    if address_tag!(address) != VAR {
        fail!("switch: {:X}", address)
    }
    let cont = take_var_cont(engine, storage_index!(address))?;
    jump(engine, cont)
}

// switch to continuation from var!(0)
fn jmpx(engine: &mut Engine, need_convert: bool) -> Status {
    if need_convert && engine.cmd.var(0).as_cell().is_ok() {
        convert(engine, var!(0), CONTINUATION, CELL)?;
    }
    let cont = take_var_cont(engine, 0)?;
    jump(engine, cont)
}

fn ref_cont(engine: &mut Engine) -> Result<ContinuationData> {
    let index = engine.cmd.var_count();
    fetch_reference(engine, CC)?;
    convert(engine, var!(index), CONTINUATION, CELL)?;
    take_var_cont(engine, index)
}

// Loops **********************************************************************

fn repeat(
    engine: &mut Engine,
    body: ContinuationData,
    after: ContinuationData,
    count: isize,
) -> Status {
    if count <= 0 {
        drop(body);
        jump(engine, after)
    } else {
        let repeat = ContinuationType::Repeat {
            count: count as i64,
            body: Arc::new(body),
            after: Arc::new(after),
        };
        jump(engine, ContinuationData::with_type(repeat))
    }
}

fn again(engine: &mut Engine, body: ContinuationData) -> Status {
    jump(engine, ContinuationData::with_type(ContinuationType::Again { body: Arc::new(body) }))
}

fn until(engine: &mut Engine, body: ContinuationData, after: ContinuationData) -> Status {
    if !body.has_c0() {
        let until =
            ContinuationType::Until { body: Arc::new(body.clone()), after: Arc::new(after) };
        set_ctrl_cont(engine, 0, ContinuationData::with_type(until));
    }
    jump(engine, body)
}

fn loop_while(
    engine: &mut Engine,
    cond: ContinuationData,
    body: ContinuationData,
    after: ContinuationData,
) -> Status {
    if !cond.has_c0() {
        let loop_ = ContinuationType::While {
            check_cond: true,
            cond: Arc::new(cond.clone()),
            body: Arc::new(body),
            after: Arc::new(after),
        };
        set_ctrl_cont(engine, 0, ContinuationData::with_type(loop_));
    }
    jump(engine, cond)
}

fn exec_repeat(engine: &mut Engine, name: &'static str, brk: bool) -> Status {
    engine.load_instruction(Instruction::new(name))?;
    check_underflow(engine, 2)?;
    let body = pop_cont(engine)?;
    let count = pop_smallint_range(engine, 0x7fffffff, -0x80000000)?;
    if count <= 0 {
        return Ok(());
    }
    let cc = extract_cc(engine, 1, -1, -1)?;
    let after = c1_envelope_if(engine, brk, cc);
    repeat(engine, body, after, count)
}

fn exec_repeat_end(engine: &mut Engine, name: &'static str, brk: bool) -> Status {
    engine.load_instruction(Instruction::new(name))?;
    check_underflow(engine, 1)?;
    let count = pop_smallint_range(engine, 0x7fffffff, -0x80000000)?;
    if count <= 0 {
        return ret(engine);
    }
    let body = extract_cc(engine, 0, -1, -1)?;
    let c0 = ctrl_cont(engine, 0)?;
    let after = c1_envelope_if(engine, brk, c0);
    repeat(engine, body, after, count)
}

fn exec_until(engine: &mut Engine, name: &'static str, brk: bool) -> Status {
    engine.load_instruction(Instruction::new(name))?;
    check_underflow(engine, 1)?;
    let body = pop_cont(engine)?;
    let cc = extract_cc(engine, 1, -1, -1)?;
    let after = c1_envelope_if(engine, brk, cc);
    until(engine, body, after)
}

fn exec_until_end(engine: &mut Engine, name: &'static str, brk: bool) -> Status {
    engine.load_instruction(Instruction::new(name))?;
    let body = extract_cc(engine, 0, -1, -1)?;
    let c0 = ctrl_cont(engine, 0)?;
    let after = c1_envelope_if(engine, brk, c0);
    until(engine, body, after)
}

fn exec_while(engine: &mut Engine, name: &'static str, brk: bool) -> Status {
    engine.load_instruction(Instruction::new(name))?;
    check_underflow(engine, 2)?;
    let body = pop_cont(engine)?;
    let cond = pop_cont(engine)?;
    let cc = extract_cc(engine, 1, -1, -1)?;
    let after = c1_envelope_if(engine, brk, cc);
    loop_while(engine, cond, body, after)
}

fn exec_while_end(engine: &mut Engine, name: &'static str, brk: bool) -> Status {
    engine.load_instruction(Instruction::new(name))?;
    check_underflow(engine, 1)?;
    let cond = pop_cont(engine)?;
    let body = extract_cc(engine, 0, -1, -1)?;
    let c0 = ctrl_cont(engine, 0)?;
    let after = c1_envelope_if(engine, brk, c0);
    loop_while(engine, cond, body, after)
}

fn exec_again(engine: &mut Engine, name: &'static str, brk: bool) -> Status {
    engine.load_instruction(Instruction::new(name))?;
    if brk {
        let cc = extract_cc(engine, 3, -1, -1)?;
        set_ctrl_cont(engine, 1, cc);
    }
    check_underflow(engine, 1)?;
    let body = pop_cont(engine)?;
    again(engine, body)
}

fn exec_again_end(engine: &mut Engine, name: &'static str, brk: bool) -> Status {
    engine.load_instruction(Instruction::new(name))?;
    if brk {
        c1_save_set(engine)?;
    }
    let body = extract_cc(engine, 0, -1, -1)?;
    again(engine, body)
}

// (c - ), execute C infinitely
pub(super) fn execute_again(engine: &mut Engine) -> Status {
    exec_again(engine, "AGAIN", false)
}

// (c - ), execute C infinitely with break
pub(super) fn execute_again_break(engine: &mut Engine) -> Status {
    exec_again(engine, "AGAINBRK", true)
}

// ( - ), execute CC infinitely
pub(super) fn execute_againend(engine: &mut Engine) -> Status {
    exec_again_end(engine, "AGAINEND", false)
}

// ( - ), execute CC infinitely with break
pub(super) fn execute_againend_break(engine: &mut Engine) -> Status {
    exec_again_end(engine, "AGAINENDBRK", true)
}

// (integer_repeat_count body_continuation - )
pub(super) fn execute_repeat(engine: &mut Engine) -> Status {
    exec_repeat(engine, "REPEAT", false)
}

pub(super) fn execute_repeat_break(engine: &mut Engine) -> Status {
    exec_repeat(engine, "REPEATBRK", true)
}

// (integer_repeat_count - )
pub(super) fn execute_repeatend(engine: &mut Engine) -> Status {
    exec_repeat_end(engine, "REPEATEND", false)
}

pub(super) fn execute_repeatend_break(engine: &mut Engine) -> Status {
    exec_repeat_end(engine, "REPEATENDBRK", true)
}

// (body - )
pub(super) fn execute_until(engine: &mut Engine) -> Status {
    exec_until(engine, "UNTIL", false)
}

pub(super) fn execute_until_break(engine: &mut Engine) -> Status {
    exec_until(engine, "UNTILBRK", true)
}

// cc is body
pub(super) fn execute_untilend(engine: &mut Engine) -> Status {
    exec_until_end(engine, "UNTILEND", false)
}

pub(super) fn execute_untilend_break(engine: &mut Engine) -> Status {
    exec_until_end(engine, "UNTILENDBRK", true)
}

// (condition body - )
pub(super) fn execute_while(engine: &mut Engine) -> Status {
    exec_while(engine, "WHILE", false)
}

pub(super) fn execute_while_break(engine: &mut Engine) -> Status {
    exec_while(engine, "WHILEBRK", true)
}

// cc is body, (condition - )
pub(super) fn execute_whileend(engine: &mut Engine) -> Status {
    exec_while_end(engine, "WHILEEND", false)
}

pub(super) fn execute_whileend_break(engine: &mut Engine) -> Status {
    exec_while_end(engine, "WHILEENDBRK", true)
}

// Jumps and calls ************************************************************

// (continuation - ), simple call
pub(super) fn execute_callx(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("CALLX"))?;
    let cont = pop_cont(engine)?;
    call(engine, cont)
}

// (continuation - ), call with p,r (0xDA) or p,-1 (0xDB0p)
pub(super) fn execute_callxargs(engine: &mut Engine) -> Status {
    let cmd = engine.last_cmd();
    engine.load_instruction(Instruction::new("CALLXARGS").set_opts(if cmd == 0xDA {
        InstructionOptions::ArgumentAndReturnConstraints
    } else {
        InstructionOptions::Pargs(0..16)
    }))?;
    let pass_args = engine.cmd.pargs() as isize;
    let ret_args = if cmd == 0xDA { engine.cmd.rargs() as isize } else { -1 };
    let cont = pop_cont(engine)?;
    call_args(engine, cont, pass_args, ret_args)
}

// (continuation p r - )
pub(super) fn execute_callxva(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("CALLXVARARGS"))?;
    check_underflow(engine, 3)?;
    let ret_args = pop_smallint_range(engine, 254, -1)?;
    let pass_args = pop_smallint_range(engine, 254, -1)?;
    let cont = pop_cont(engine)?;
    call_args(engine, cont, pass_args, ret_args)
}

// (continuation - )
pub(super) fn execute_jmpx(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("JMPX"))?;
    let cont = pop_cont(engine)?;
    jump(engine, cont)
}

// (continuation - ), jump passing p items
pub(super) fn execute_jmpxargs(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("JMPXARGS").set_opts(InstructionOptions::Pargs(0..16)),
    )?;
    let pass_args = engine.cmd.pargs() as isize;
    let cont = pop_cont(engine)?;
    jump_args(engine, cont, pass_args)
}

// (continuation p - )
pub(super) fn execute_jmpxva(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("JMPXVARARGS"))?;
    check_underflow(engine, 2)?;
    let pass_args = pop_smallint_range(engine, 254, -1)?;
    check_underflow(engine, (pass_args + 1) as usize)?;
    let cont = pop_cont(engine)?;
    jump_args(engine, cont, pass_args)
}

// (continuation - ), cc pushed for the callee
pub(super) fn execute_callcc(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("CALLCC"))?;
    let cont = pop_cont(engine)?;
    let cc = extract_cc(engine, 3, -1, -1)?;
    engine.cc.stack.push_cont(cc);
    jump(engine, cont)
}

// (continuation - ), cc capturing all but p items, returning r
pub(super) fn execute_callccargs(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("CALLCCARGS").set_opts(InstructionOptions::ArgumentConstraints),
    )?;
    let pass_args = engine.cmd.pargs() as isize;
    let ret_args = engine.cmd.nargs();
    check_underflow(engine, (pass_args + 1) as usize)?;
    let cont = pop_cont(engine)?;
    let cc = extract_cc(engine, 3, pass_args, ret_args)?;
    engine.cc.stack.push_cont(cc);
    jump(engine, cont)
}

// (continuation p r - )
pub(super) fn execute_callccva(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("CALLCCVARARGS"))?;
    check_underflow(engine, 3)?;
    let ret_args = pop_smallint_range(engine, 254, -1)?;
    let pass_args = pop_smallint_range(engine, 254, -1)?;
    check_underflow(engine, (pass_args + 1) as usize)?;
    let cont = pop_cont(engine)?;
    let cc = extract_cc(engine, 3, pass_args, ret_args)?;
    engine.cc.stack.push_cont(cc);
    jump(engine, cont)
}

// equivalent to PUSHREFCONT; CALLX
pub(super) fn execute_callref(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("CALLREF"))?;
    let cont = ref_cont(engine)?;
    call(engine, cont)
}

pub(super) fn execute_jmpref(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("JMPREF"))?;
    let cont = ref_cont(engine)?;
    jump(engine, cont)
}

pub(super) fn execute_jmprefdata(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("JMPREFDATA"))?;
    let cont = ref_cont(engine)?;
    push_code(engine);
    jump(engine, cont)
}

// (continuation - code), jump with the rest of the current code on the stack
pub(super) fn execute_jmpxdata(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("JMPXDATA"))?;
    let cont = pop_cont(engine)?;
    push_code(engine);
    jump(engine, cont)
}

// return to c[0]
pub(super) fn execute_ret(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("RET"))?;
    ret(engine)
}

// return to c[1]
pub(super) fn execute_retalt(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("RETALT"))?;
    ret_alt(engine)
}

// return to c[0] with p items
pub(super) fn execute_retargs(engine: &mut Engine) -> Status {
    engine
        .load_instruction(Instruction::new("RETARGS").set_opts(InstructionOptions::Pargs(0..16)))?;
    let count = engine.cmd.pargs() as isize;
    ret_args(engine, count)
}

// (r - ) return to c[0] with r items
pub(super) fn execute_retva(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("RETVARARGS"))?;
    let count = pop_smallint_range(engine, 254, -1)?;
    ret_args(engine, count)
}

// (condition - ), if condition != 0 then RET else RETALT
pub(super) fn execute_retbool(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("RETBOOL"))?;
    if pop_bool(engine)? {
        ret(engine)
    } else {
        ret_alt(engine)
    }
}

// ( - code), return with the rest of the current code on the stack
pub(super) fn execute_retdata(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("RETDATA"))?;
    push_code(engine);
    ret(engine)
}

//(c - ), c0 = PushInt(-1, cc), c1 = PushInt(0, cc), jump to c
pub(super) fn execute_booleval(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("BOOLEVAL"))?;
    let cont = pop_cont(engine)?;
    let cc = Arc::new(extract_cc(engine, 3, -1, -1)?);
    set_ctrl_cont(
        engine,
        0,
        ContinuationData::with_type(ContinuationType::PushInt(-1, cc.clone())),
    );
    set_ctrl_cont(engine, 1, ContinuationData::with_type(ContinuationType::PushInt(0, cc)));
    jump(engine, cont)
}

// n ( - n), calls the continuation in c3
fn execute_call(engine: &mut Engine, name: &'static str, range: Range<isize>, how: u8) -> Status {
    engine.load_instruction(Instruction::new(name).set_opts(InstructionOptions::Integer(range)))?;
    let n = engine.cmd.integer();
    engine.cc.stack.push(int!(n));
    match how {
        PREPARE => {
            copy_to_var(engine, ctrl!(3))?;
            engine.cc.stack.push(engine.cmd.pop_var()?);
            Ok(())
        }
        SWITCH => {
            let c3 = ctrl_cont(engine, 3)?;
            jump(engine, c3)
        }
        CALLX => {
            let c3 = ctrl_cont(engine, 3)?;
            call(engine, c3)
        }
        _ => fail!("how: 0x{:X}", how),
    }
}

// 0 =< n =< 255
pub(super) fn execute_call_short(engine: &mut Engine) -> Status {
    execute_call(engine, "CALLDICT", 0..256, CALLX)
}
// 0 =< n < (2 ^ 14)
pub(super) fn execute_call_long(engine: &mut Engine) -> Status {
    execute_call(engine, "CALLDICT", 0..16384, CALLX)
}
// 0 =< n < (2 ^ 14)
pub(super) fn execute_jmp(engine: &mut Engine) -> Status {
    execute_call(engine, "JMP", 0..16384, SWITCH)
}
// 0 =< n < (2 ^ 14)
pub(super) fn execute_prepare(engine: &mut Engine) -> Status {
    execute_call(engine, "PREPARE", 0..16384, PREPARE)
}

// Conditional jumps **********************************************************

// (f x y - ), x f != 0 else y
pub(super) fn execute_condsel(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("CONDSEL"))?;
    fetch_stack(engine, 3)?;
    if !engine.cmd.var(2).as_bool()? {
        engine.cc.stack.push(engine.cmd.vars.remove(0));
    } else {
        engine.cc.stack.push(engine.cmd.vars.remove(1));
    }
    Ok(())
}

// (f x y - ), x f != 0 else y, throws exception, if types mismatch
pub(super) fn execute_condselchk(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("CONDSELCHK"))?;
    fetch_stack(engine, 3)?;
    if !engine.cmd.var(0).same_type(engine.cmd.var(1)) {
        fail!(ExceptionCode::TypeCheckError)
    }
    if !engine.cmd.var(2).as_bool()? {
        engine.cc.stack.push(engine.cmd.vars.remove(0));
    } else {
        engine.cc.stack.push(engine.cmd.vars.remove(1));
    }
    Ok(())
}

const CALL: u8 = 0x00; // call cont
const JMP: u8 = 0x01; // jump to cont
const RET: u8 = 0x04; // ret to c0
const ALT: u8 = 0x08; // ret to c1
const REF: u8 = 0x10; // use refslice as cont
const REF2: u8 = 0x02; // use refslice as second cont
const INV: u8 = 0x20; // condition not
const ELSE: u8 = 0x40; // IFELSE
const THROW: u8 = 0x80; // checks if condition is NaN then throw IntegerOverflow

fn execute_if_mask(engine: &mut Engine, name: &'static str, how: u8) -> Status {
    let mut params = 2;
    if how.bit(ELSE) {
        params += 1;
    }
    if how.bit(REF) {
        params -= 1;
    }
    if how.bit(REF2) {
        params -= 1;
    }
    if how.bit(RET) {
        params -= 1;
    }

    engine.load_instruction(Instruction::new(name))?;
    if how.bit(REF) {
        fetch_reference(engine, CC)?
    }
    if how.bit(REF2) {
        fetch_reference(engine, CC)?
    }
    fetch_stack(engine, params)?;
    // Continuations taken from the stack are type-checked before the condition, in stack order.
    let first_stack_var = usize::from(how.bit(REF)) + usize::from(how.bit(REF2));
    for index in first_stack_var..engine.cmd.var_count() - 1 {
        engine.cmd.var(index).as_continuation()?;
    }
    if how.bit(THROW) && engine.cmd.last_var()?.as_integer()?.is_nan() {
        fail!(ExceptionCode::IntegerOverflow)
    }
    match engine.cmd.last_var()?.as_bool()? ^ how.bit(INV) {
        false if how.bit(ELSE) => {
            if !how.bit(REF) {
                engine.cmd.var(0).as_continuation()?;
            }
            callx(engine, 1, how.bit(REF2))
        }
        false => Ok(()),
        true if how.bit(ELSE) => {
            if !how.bit(REF2) {
                engine.cmd.var(1).as_continuation()?;
            }
            callx(engine, 0, how.bit(REF))
        }
        true if how.bit(JMP) => jmpx(engine, how.bit(REF)),
        true if how.bit(ALT) => ret_alt(engine),
        true if how.bit(RET) => ret(engine),
        true => callx(engine, 0, how.bit(REF)),
    }
}

// (condition continuation - ): callx if condition != 0
pub(super) fn execute_if(engine: &mut Engine) -> Status {
    execute_if_mask(engine, "IF", CALL)
}

// (condition continuation1 continuation2 - ): if condition != 0 callx continuation1 else callx continuation2
pub(super) fn execute_ifelse(engine: &mut Engine) -> Status {
    execute_if_mask(engine, "IFELSE", CALL | ELSE | INV)
}

// (condition continuation - ): equivalent to PUSHREFCONT; IFELSE
pub(super) fn execute_ifelseref(engine: &mut Engine) -> Status {
    execute_if_mask(engine, "IFELSEREF", CALL | ELSE | INV | REF)
}

// (condition continuation - ): switch if condition != 0
pub(super) fn execute_ifjmp(engine: &mut Engine) -> Status {
    execute_if_mask(engine, "IFJMP", JMP)
}

// (condition continuation - ): callx if condition == 0
pub(super) fn execute_ifnot(engine: &mut Engine) -> Status {
    execute_if_mask(engine, "IFNOT", CALL | INV)
}

// (condition continuation - ): switch if condition == 0
pub(super) fn execute_ifnotjmp(engine: &mut Engine) -> Status {
    execute_if_mask(engine, "IFNOTJMP", JMP | INV)
}

// (condition - Continuation): pushrefcont if condition == 0
pub(super) fn execute_ifnotref(engine: &mut Engine) -> Status {
    execute_if_mask(engine, "IFNOTREF", CALL | INV | REF)
}

// (condition - ): switch to continuation from references[0] if condition != 0
pub(super) fn execute_ifjmpref(engine: &mut Engine) -> Status {
    execute_if_mask(engine, "IFJMPREF", JMP | REF)
}

// (condition - ): switch to continuation from references[0] if condition == 0
pub(super) fn execute_ifnotjmpref(engine: &mut Engine) -> Status {
    execute_if_mask(engine, "IFNOTJMPREF", JMP | INV | REF)
}

// (condition - ): switch if condition == 0
pub(super) fn execute_ifnotret(engine: &mut Engine) -> Status {
    execute_if_mask(engine, "IFNOTRET", RET | INV)
}

// (condition - Continuation): pushrefcont if condition != 0
pub(super) fn execute_ifref(engine: &mut Engine) -> Status {
    execute_if_mask(engine, "IFREF", CALL | REF)
}

// (condition continuation - ): equivalent to PUSHREFCONT; SWAP; IFELSE
pub(super) fn execute_ifrefelse(engine: &mut Engine) -> Status {
    execute_if_mask(engine, "IFREFELSE", CALL | ELSE | REF)
}

// (condition - ): equivalent to PUSHREFCONT; PUSHREFCONT; IFELSE
pub(super) fn execute_ifrefelseref(engine: &mut Engine) -> Status {
    execute_if_mask(engine, "IFREFELSEREF", CALL | ELSE | REF | REF2)
}

// (condition - ): switch if condition != 0
pub(super) fn execute_ifret(engine: &mut Engine) -> Status {
    execute_if_mask(engine, "IFRET", RET | THROW)
}

// (f - ), RETALT f != 0
pub(super) fn execute_ifretalt(engine: &mut Engine) -> Status {
    execute_if_mask(engine, "IFRETALT", RET | ALT)
}

// (f - ), RETALT f == 0
pub(super) fn execute_ifnotretalt(engine: &mut Engine) -> Status {
    execute_if_mask(engine, "IFNOTRETALT", RET | ALT | INV)
}

fn execute_ifbit_mask(engine: &mut Engine, name: &'static str, how: u8) -> Status {
    engine.load_instruction(Instruction::new(name).set_opts(InstructionOptions::Integer(0..32)))?;
    if how.bit(REF) {
        fetch_reference(engine, CC)?;
    } else {
        fetch_stack(engine, 1)?;
        engine.cmd.var(0).as_continuation()?;
    }
    if engine.cc.stack.depth() < 1 {
        fail!(ExceptionCode::StackUnderflow);
    }
    let is_zero = {
        let x = engine.cc.stack.get(0)?.as_integer()?;
        let nbit = engine.cmd.integer() as u32;
        let test_bit_mask = IntegerData::from_u32(1 << nbit);
        x.and::<Signaling>(&test_bit_mask)?.is_zero()
    };
    if is_zero ^ how.bit(INV) {
        Ok(())
    } else {
        jmpx(engine, how.bit(REF))
    }
}

// (x continuation - x), switch if n's bit of x is set
pub(super) fn execute_ifbitjmp(engine: &mut Engine) -> Status {
    execute_ifbit_mask(engine, "IFBITJMP", 0)
}

// (x continuation - x), switch if n's bit of x is not set
pub(super) fn execute_ifnbitjmp(engine: &mut Engine) -> Status {
    execute_ifbit_mask(engine, "IFNBITJMP", INV)
}

// (x - x), switch pattern if n'th bit is set
pub(super) fn execute_ifbitjmpref(engine: &mut Engine) -> Status {
    execute_ifbit_mask(engine, "IFBITJMPREF", REF)
}

// (x - x), switch pattern if n'th bit is not set
pub(super) fn execute_ifnbitjmpref(engine: &mut Engine) -> Status {
    execute_ifbit_mask(engine, "IFNBITJMPREF", REF | INV)
}

// Continuation changes *******************************************************

/// `exec_setcontargs_common`: copies `copy` items into the continuation and sets `more`.
fn setcontargs_common(engine: &mut Engine, copy: usize, more: isize) -> Status {
    check_underflow(engine, copy + 1)?;
    let mut cont = pop_cont(engine)?;
    if copy > 0 || more >= 0 {
        let cdata = cont.force_cdata();
        if copy > 0 {
            if cdata.nargs >= 0 && (cdata.nargs as usize) < copy {
                fail!(
                    ExceptionCode::StackOverflow,
                    "too many arguments copied into a closure continuation"
                )
            }
            move_from_stack(&mut cdata.stack, &mut engine.cc.stack, copy);
            let captured = cdata.stack.depth();
            if cdata.nargs >= 0 {
                cdata.nargs -= copy as isize;
            }
            consume_stack_gas(engine, captured)?;
        }
        let cdata = cont.force_cdata();
        if more >= 0 {
            if cdata.nargs > more {
                cdata.nargs = 0x40000000; // will throw an exception if run
            } else if cdata.nargs < 0 {
                cdata.nargs = more;
            }
        }
    }
    engine.cc.stack.push_cont(cont);
    Ok(())
}

// (x1 ... xR continuation - continuation)
pub(super) fn execute_setcontargs(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("SETCONTARGS").set_opts(InstructionOptions::ArgumentConstraints),
    )?;
    let copy = engine.cmd.pargs();
    let more = engine.cmd.nargs();
    setcontargs_common(engine, copy, more)
}

// (x1 ... xR continuation R N - continuation)
pub(super) fn execute_setcontva(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("SETCONTVARARGS"))?;
    check_underflow(engine, 2)?;
    let more = pop_smallint_range(engine, 255, -1)?;
    let copy = pop_smallint_range(engine, 255, 0)?;
    setcontargs_common(engine, copy as usize, more)
}

// (continuation n - continuation)
pub(super) fn execute_setnumvarargs(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("SETNUMVARARGS"))?;
    check_underflow(engine, 2)?;
    let more = pop_smallint_range(engine, 255, -1)?;
    setcontargs_common(engine, 0, more)
}

/// `exec_return_args_common`: keeps the top `count` items, moves the rest into c0.
fn return_args_common(engine: &mut Engine, count: usize) -> Status {
    check_underflow(engine, count)?;
    let depth = engine.cc.stack.depth();
    if depth == count {
        return Ok(());
    }
    let copy = depth - count;
    let top = split_top(&mut engine.cc.stack, count);
    let mut alt = mem::replace(&mut engine.cc.stack, top);
    let mut cont = ctrl_cont(engine, 0)?;
    let cdata = cont.force_cdata();
    if cdata.nargs >= 0 && (cdata.nargs as usize) < copy {
        fail!(ExceptionCode::StackOverflow, "too many arguments copied into a closure continuation")
    }
    move_from_stack(&mut cdata.stack, &mut alt, copy);
    let captured = cdata.stack.depth();
    if cdata.nargs >= 0 {
        cdata.nargs -= copy as isize;
    }
    consume_stack_gas(engine, captured)?;
    set_ctrl_cont(engine, 0, cont);
    Ok(())
}

// (xN ... x0 - xR-1 ... x0), c0.stack.push(xN ... xR)
pub(super) fn execute_returnargs(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("RETURNARGS").set_opts(InstructionOptions::Rargs(0..16)),
    )?;
    let count = engine.cmd.rargs();
    return_args_common(engine, count)
}

// (xN ... x0 r - xR-1 ... x0)
pub(super) fn execute_returnva(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("RETURNVARARGS"))?;
    let count = pop_smallint_range(engine, 255, 0)?;
    return_args_common(engine, count as usize)
}

fn pop_cellslice(engine: &mut Engine) -> Result<rtos_block::SliceData> {
    let item = engine.cc.stack.pop()?;
    Ok(item.as_slice()?.clone())
}

// (slice - continuation)
pub(super) fn execute_bless(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("BLESS"))?;
    check_underflow(engine, 1)?;
    let code = pop_cellslice(engine)?;
    engine.cc.stack.push_cont(ContinuationData::with_code(code));
    Ok(())
}

fn bless_args_common(engine: &mut Engine, copy: usize, more: isize) -> Status {
    check_underflow(engine, copy + 1)?;
    let code = pop_cellslice(engine)?;
    let stack = split_top(&mut engine.cc.stack, copy);
    consume_stack_gas(engine, copy)?;
    let mut cont = ContinuationData::with_code_and_stack(code, stack);
    cont.nargs = more;
    engine.cc.stack.push_cont(cont);
    Ok(())
}

// (x1 ... xR slice - continuation)
pub(super) fn execute_blessargs(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("BLESSARGS").set_opts(InstructionOptions::ArgumentConstraints),
    )?;
    let copy = engine.cmd.pargs();
    let more = engine.cmd.nargs();
    bless_args_common(engine, copy, more)
}

// (x1 ... xR slice R N - continuation)
pub(super) fn execute_blessva(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("BLESSVARARGS"))?;
    check_underflow(engine, 2)?;
    let more = pop_smallint_range(engine, 255, -1)?;
    let copy = pop_smallint_range(engine, 255, 0)?;
    bless_args_common(engine, copy as usize, more)
}

/// `ControlRegs::define(idx, value, silent_if_set)` on forced control data.
fn define_reg(cont: &mut ContinuationData, index: usize, value: StackItem, silent: bool) -> bool {
    let cdata = cont.force_cdata();
    if !SaveList::REGS.contains(&index) || !SaveList::can_put(index, &value) {
        return false;
    }
    if cdata.savelist.get(index).is_some() {
        return index == 7 || silent;
    }
    cdata.define(index, value)
}

fn silent_if_set(engine: &Engine) -> bool {
    engine.block_version() >= TVM_VERSION_14
}

fn get_reg(engine: &Engine, index: usize) -> StackItem {
    engine.ctrls.get(index).cloned().unwrap_or_default()
}

fn type_check(ok: bool) -> Status {
    if !ok {
        fail!(ExceptionCode::TypeCheckError, "invalid value type for control register")
    }
    Ok(())
}

// (x continuation - continuation), continuation.savelist[i] = x
pub(super) fn execute_setcontctr(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("SETCONTCTR").set_opts(InstructionOptions::ControlRegister),
    )?;
    let creg = engine.cmd.creg();
    check_underflow(engine, 2)?;
    let mut cont = pop_cont(engine)?;
    let value = engine.cc.stack.pop()?;
    let silent = silent_if_set(engine);
    type_check(define_reg(&mut cont, creg, value, silent))?;
    engine.cc.stack.push_cont(cont);
    Ok(())
}

// (x continuation i - continuation), continuation.savelist[i] = x
pub(super) fn execute_setcontctrx(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("SETCONTCTRX"))?;
    check_underflow(engine, 3)?;
    let creg = pop_smallint_range(engine, 16, 0)? as usize;
    if !SaveList::REGS.contains(&creg) {
        fail!(ExceptionCode::RangeCheckError, "control register index out of range")
    }
    let mut cont = pop_cont(engine)?;
    let value = engine.cc.stack.pop()?;
    let silent = silent_if_set(engine);
    type_check(define_reg(&mut cont, creg, value, silent))?;
    engine.cc.stack.push_cont(cont);
    Ok(())
}

fn setcontctrmany_common(engine: &mut Engine, mask: usize) -> Status {
    if mask & (1 << 6) != 0 {
        fail!(ExceptionCode::RangeCheckError, "no control register c6")
    }
    let mut cont = pop_cont(engine)?;
    let silent = silent_if_set(engine);
    for i in 0..8usize {
        if mask & (1 << i) != 0 {
            let value = get_reg(engine, i);
            type_check(define_reg(&mut cont, i, value, silent))?;
        }
    }
    engine.cc.stack.push_cont(cont);
    Ok(())
}

// (continuation - continuation), continuation.savelist[i] = c[i] for the mask bits
pub(super) fn execute_setcontctrmany(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("SETCONTCTRMANY").set_opts(InstructionOptions::Length(0..256)),
    )?;
    let mask = engine.cmd.length();
    setcontctrmany_common(engine, mask)
}

// (continuation x - continuation)
pub(super) fn execute_setcontctrmanyx(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("SETCONTCTRMANYX"))?;
    check_underflow(engine, 2)?;
    let mask = pop_smallint_range(engine, 255, 0)? as usize;
    setcontctrmany_common(engine, mask)
}

fn setctr_in_register(engine: &mut Engine, register: usize) -> Status {
    let creg = engine.cmd.creg();
    let mut cont = ctrl_cont(engine, register)?;
    let value = engine.cc.stack.pop()?;
    let silent = silent_if_set(engine);
    type_check(define_reg(&mut cont, creg, value, silent))?;
    set_ctrl_cont(engine, register, cont);
    Ok(())
}

// (x - ), c0.savelist[i] = x
pub(super) fn execute_setretctr(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("SETRETCTR").set_opts(InstructionOptions::ControlRegister),
    )?;
    setctr_in_register(engine, 0)
}

// (x - ), c1.savelist[i] = x
pub(super) fn execute_setaltctr(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("SETALTCTR").set_opts(InstructionOptions::ControlRegister),
    )?;
    setctr_in_register(engine, 1)
}

fn save_in_register(engine: &mut Engine, register: usize) -> Status {
    let creg = engine.cmd.creg();
    let mut cont = ctrl_cont(engine, register)?;
    let value = get_reg(engine, creg);
    let silent = silent_if_set(engine);
    type_check(define_reg(&mut cont, creg, value, silent))?;
    set_ctrl_cont(engine, register, cont);
    Ok(())
}

// ( - ), c[0].savelist[i] = c[i] if empty
pub(super) fn execute_save(engine: &mut Engine) -> Status {
    engine
        .load_instruction(Instruction::new("SAVE").set_opts(InstructionOptions::ControlRegister))?;
    save_in_register(engine, 0)
}

// ( - ), c[1].savelist[i] = c[i] if empty
pub(super) fn execute_savealt(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("SAVEALT").set_opts(InstructionOptions::ControlRegister),
    )?;
    save_in_register(engine, 1)
}

// ( - ), c[0] and c[1] savelist[i] = c[i] where empty
pub(super) fn execute_saveboth(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("SAVEBOTH").set_opts(InstructionOptions::ControlRegister),
    )?;
    let creg = engine.cmd.creg();
    let mut c0 = ctrl_cont(engine, 0)?;
    let mut c1 = ctrl_cont(engine, 1)?;
    let value = get_reg(engine, creg);
    define_reg(&mut c0, creg, value.clone(), false);
    define_reg(&mut c1, creg, value, false);
    set_ctrl_cont(engine, 0, c0);
    set_ctrl_cont(engine, 1, c1);
    Ok(())
}

// ( - ), c[1] = c[0]
pub(super) fn execute_samealt(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("SAMEALT"))?;
    let c0 = ctrl_cont(engine, 0)?;
    set_ctrl_cont(engine, 1, c0);
    Ok(())
}

// ( - ), c[0].savelist[1] = c[1], c[1] = c[0]
pub(super) fn execute_samealt_save(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("SAMEALTSAVE"))?;
    let mut c0 = ctrl_cont(engine, 0)?;
    let c1 = engine.ctrls.get(1).cloned();
    c0.force_cdata().define_opt(1, c1);
    set_ctrl_cont(engine, 0, c0.clone());
    set_ctrl_cont(engine, 1, c0);
    Ok(())
}

fn compos(engine: &mut Engine, name: &'static str, mask: u8) -> Status {
    engine.load_instruction(Instruction::new(name))?;
    check_underflow(engine, 2)?;
    let value = pop_cont(engine)?;
    let mut cont = pop_cont(engine)?;
    let cdata = cont.force_cdata();
    let value = StackItem::continuation(value);
    if mask & 1 != 0 {
        cdata.define_opt(0, Some(value.clone()));
    }
    if mask & 2 != 0 {
        cdata.define_opt(1, Some(value));
    }
    engine.cc.stack.push_cont(cont);
    Ok(())
}

// (continuation1 continuation2 - continuation1), continuation1.savelist[0] = continuation2
pub(super) fn execute_compos(engine: &mut Engine) -> Status {
    compos(engine, "COMPOS", 1)
}

// (continuation1 continuation2 - continuation1), continuation1.savelist[1] = continuation2
pub(super) fn execute_composalt(engine: &mut Engine) -> Status {
    compos(engine, "COMPOSALT", 2)
}

// (continuation1 continuation2 - continuation1), both slots
pub(super) fn execute_composboth(engine: &mut Engine) -> Status {
    compos(engine, "COMPOSBOTH", 3)
}

// (continuation - ), continuation.savelist[0] = c[0], c[0] = continuation
pub(super) fn execute_atexit(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("ATEXIT"))?;
    let mut cont = pop_cont(engine)?;
    let c0 = engine.ctrls.get(0).cloned();
    cont.force_cdata().define_opt(0, c0);
    set_ctrl_cont(engine, 0, cont);
    Ok(())
}

// (continuation - ), continuation.savelist[1] = c[1], c[1] = continuation
pub(super) fn execute_atexitalt(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("ATEXITALT"))?;
    let mut cont = pop_cont(engine)?;
    let c1 = engine.ctrls.get(1).cloned();
    cont.force_cdata().define_opt(1, c1);
    set_ctrl_cont(engine, 1, cont);
    Ok(())
}

// (continuation - ), continuation.savelist[0] = c[0], continuation.savelist[1] = c[1],
// c[1] = continuation
pub(super) fn execute_setexitalt(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("SETEXITALT"))?;
    let mut cont = pop_cont(engine)?;
    let c0 = engine.ctrls.get(0).cloned();
    let c1 = engine.ctrls.get(1).cloned();
    let cdata = cont.force_cdata();
    cdata.define_opt(0, c0);
    cdata.define_opt(1, c1);
    set_ctrl_cont(engine, 1, cont);
    Ok(())
}

// (continuation - continuation), continuation.savelist[0] = c[0]
pub(super) fn execute_thenret(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("THENRET"))?;
    let mut cont = pop_cont(engine)?;
    let c0 = engine.ctrls.get(0).cloned();
    cont.force_cdata().define_opt(0, c0);
    engine.cc.stack.push_cont(cont);
    Ok(())
}

// (continuation - continuation), continuation.savelist[0] = c[1]
pub(super) fn execute_thenretalt(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("THENRETALT"))?;
    let mut cont = pop_cont(engine)?;
    let c1 = engine.ctrls.get(1).cloned();
    cont.force_cdata().define_opt(0, c1);
    engine.cc.stack.push_cont(cont);
    Ok(())
}

// c[0] <-> c[1]
pub(super) fn execute_invert(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("INVERT"))?;
    swap(engine, ctrl!(0), ctrl!(1))
}

/// POPSAVE c(i): the reference saves the old c(i) into a copy of c0 that is installed only
/// for i != 0 (for i == 0 the new value replaces it).
pub(in crate::executor) fn popsave(engine: &mut Engine, creg: usize) -> Status {
    let value = engine.cc.stack.pop()?;
    let mut c0 = ctrl_cont(engine, 0)?;
    type_check(creg != 0 || value.as_continuation().is_ok())?;
    let old = get_reg(engine, creg);
    define_reg(&mut c0, creg, old, false);
    if creg == 0 {
        set_ctrl_cont(engine, 0, c0);
        type_check(SaveList::can_put(0, &value))?;
        engine.ctrls.put_opt(0, value);
    } else {
        type_check(SaveList::can_put(creg, &value))?;
        engine.ctrls.put_opt(creg, value);
        set_ctrl_cont(engine, 0, c0);
    }
    Ok(())
}

// TRY ************************************************************************

/// `exec_try`: the handler gets c2 = old c2 and c0 = cc where empty; c0 = cc, c2 = handler.
pub(in crate::executor) fn try_catch(engine: &mut Engine, args: Option<(usize, usize)>) -> Status {
    let need = args.map_or(2, |(params, _)| params + 2);
    check_underflow(engine, need)?;
    let mut handler = pop_cont(engine)?;
    let cont = pop_cont(engine)?;
    let old_c2 = engine.ctrls.get(2).cloned();
    let cc = match args {
        Some((params, retvals)) => extract_cc(engine, 7, params as isize, retvals as isize)?,
        None => extract_cc(engine, 7, -1, -1)?,
    };
    let cdata = handler.force_cdata();
    cdata.define_opt(2, old_c2);
    cdata.define_opt(0, Some(StackItem::continuation(cc.clone())));
    set_ctrl_cont(engine, 0, cc);
    set_ctrl_cont(engine, 2, handler);
    jump(engine, cont)
}

// RUNVM **********************************************************************

fn run_vm(engine: &mut Engine, mode: isize) -> Status {
    debug_assert!(engine.block_version() >= 4, "But block version is {}", engine.block_version());
    if mode >= 512 {
        fail!(ExceptionCode::RangeCheckError, "invalid flags {mode:#x}");
    }
    engine.try_use_gas(Gas::runvm_gas_price())?;
    let mut gas_max = if mode.bit(64) {
        engine.cc.stack.pop()?.as_integer_value(0..=Gas::infinity())?
    } else {
        Gas::infinity()
    };
    let gas_limit = if mode.bit(8) {
        engine.cc.stack.pop()?.as_integer_value(0..=Gas::infinity())?
    } else {
        Gas::infinity()
    };
    gas_max = if mode.bit(64) { gas_max.max(gas_limit) } else { gas_limit };
    let c7 = if mode.bit(16) { engine.cc.stack.pop()? } else { StackItem::tuple(Vec::new()) };
    c7.as_tuple()?;
    let data =
        if mode.bit(4) { engine.cc.stack.pop()? } else { StackItem::cell(Default::default()) };
    data.as_cell()?;
    let ret_vals =
        if mode.bit(256) { engine.cc.stack.pop()?.as_integer_value(0..=1i32 << 30)? } else { -1 };
    let code = engine.cc.stack.pop()?.as_slice()?.clone();
    let stack_size = engine.cc.stack.pop()?.as_integer_value(0..=engine.cc.stack.depth())?;
    engine.try_use_gas(Gas::stack_price(stack_size))?;
    fetch_stack(engine, stack_size)?;

    let mut stack = engine.cmd.withdraw_vars();
    stack.reverse();
    let stack = Stack::with_storage(stack);

    let params = RunChildVm {
        code,
        c7,
        data,
        stack,
        gas_max,
        gas_limit,
        push_0: mode.mask(3) == 3,
        same_c3: mode.bit(1),
        return_data: mode.bit(4),
        return_actions: mode.bit(32),
        return_gas: mode.bit(8),
        isolate_gas: mode.bit(128),
        ret_vals,
    };
    log::debug!(
        target: "tvm",
        "Child VM run with mode: {mode:#b}, params: {params:?}\n"
    );
    engine.run_child_vm(params)?;
    Ok(())
}

pub(super) fn execute_runvm(engine: &mut Engine) -> Status {
    let opts = InstructionOptions::Integer(0..0x1000);
    engine.load_instruction(Instruction::new("RUNVM").set_opts(opts))?;
    let mode = engine.cmd.integer();
    run_vm(engine, mode)
}

pub(super) fn execute_runvmx(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("RUNVMX"))?;
    let mode = engine.cc.stack.pop()?.as_integer_value(0..=0xFFF)?;
    run_vm(engine, mode)
}
