/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * RTOS project modifications (2026-10-19): stack moves for jumps live with the jump resolver.
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
        microcode::{CC, CC_SAVELIST, CTRL, CTRL_SAVELIST, STACK, VAR, VAR_SAVELIST},
    },
    stack::{savelist::SaveList, StackItem},
};
use rtos_block::{error, fail, ExceptionCode, Result, Status};
use std::mem;

// Swapping *******************************************************************

struct Info {
    flags: u16,
    index: usize,
}

impl std::fmt::UpperHex for Info {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "flags: {:X}, index: {:X}", self.flags, self.index)
    }
}

impl Info {
    fn item<'a>(&self, engine: &'a mut Engine) -> Result<&'a mut StackItem> {
        match address_tag!(self.flags) {
            VAR => Ok(engine.cmd.var_mut(self.index)),
            _ => fail!("Info.item {:x}\n", self.flags),
        }
    }
    #[rustfmt::skip]
    fn list<'a>(&mut self, engine: &'a mut Engine) -> Result<&'a mut SaveList> {
        match address_tag!(self.flags) {
            CC_SAVELIST => {
                self.index = savelist_index!(self.flags);
                Ok(&mut engine.cc.savelist)
            },
            CTRL => Ok(&mut engine.ctrls),
            CTRL_SAVELIST => {
                let continuation = engine.ctrls.get_mut(storage_index!(self.flags))
                    .ok_or_else(|| error!("Info.list: {:X} - {}", self, storage_index!(self.flags)))?
                    .as_continuation_mut()?;
                self.index = savelist_index!(self.flags);
                Ok(&mut continuation.savelist)
            },
            VAR_SAVELIST => {
                let continuation = engine.cmd.var_mut(storage_index!(self.flags))
                    .as_continuation_mut()?;
                self.index = savelist_index!(self.flags);
                Ok(&mut continuation.savelist)
            }
            _ => fail!("Info.list {:X}\n", self)
        }
    }
}

fn put_to_list(engine: &mut Engine, x: &mut Info, y: StackItem) -> Result<Option<StackItem>> {
    x.list(engine)?.put(x.index, y)
}

fn put_to_list_from_item(engine: &mut Engine, x: &mut Info, y: &Info) -> Result<Option<StackItem>> {
    if !SaveList::can_put(x.index, y.item(engine)?) {
        if log::log_enabled!(log::Level::Error) {
            let value = x.list(engine)?.get(x.index).cloned().unwrap_or_else(StackItem::default);
            log::error!(
                target: "tvm",
                "Cannot set: {} to list with index: {} and value: {}",
                y.item(engine)?.clone(), x.index, value
            );
        }
        fail!(ExceptionCode::TypeCheckError)
    } else {
        let y = y.item(engine)?.withdraw();
        x.list(engine)?.put(x.index, y)
    }
}

fn put_to_list_from_list(
    engine: &mut Engine,
    x: &mut Info,
    y: &mut Info,
) -> Result<Option<StackItem>> {
    x.list(engine)?;
    if let Some(new) = y.list(engine)?.get(y.index) {
        if SaveList::can_put(x.index, new) {
            if let Some(y) = y.list(engine)?.remove(y.index) {
                return x.list(engine)?.put(x.index, y);
            }
        }
    }
    if log::log_enabled!(log::Level::Error) {
        let old = x.list(engine)?.get(x.index).cloned().unwrap_or_else(StackItem::default);
        let new = y.list(engine)?.get(y.index).cloned().unwrap_or_else(StackItem::default);
        log::error!(
            target: "tvm",
            "Cannot set: {} to list with index: {} and value: {}",
            new, x.index, old
        );
    }
    fail!(ExceptionCode::TypeCheckError)
}

fn swap_with_list(engine: &mut Engine, mut x: Info, y: Info) -> Status {
    if x.list(engine)?.get(x.index).is_some() || !y.item(engine)?.is_null() {
        *y.item(engine)? = match put_to_list_from_item(engine, &mut x, &y)? {
            Some(x) => x,
            None => StackItem::None,
        };
    }
    Ok(())
}

fn swap_between_lists(engine: &mut Engine, mut x: Info, mut y: Info) -> Status {
    if y.list(engine)?.get(y.index).is_some() {
        if let Some(x) = put_to_list_from_list(engine, &mut x, &mut y)? {
            put_to_list(engine, &mut y, x)?;
        }
    } else if x.list(engine)?.get(x.index).is_some() {
        put_to_list_from_list(engine, &mut y, &mut x)?;
    }
    Ok(())
}

// x <-> y
// x and y addressing is described in executor/microcode.rs
pub(in crate::executor) fn swap(engine: &mut Engine, mut x: u16, mut y: u16) -> Status {
    if address_tag!(x) > address_tag!(y) {
        mem::swap(&mut x, &mut y);
    }
    let x = Info { flags: x, index: storage_index!(x) };
    let y = Info { flags: y, index: storage_index!(y) };
    match address_tag!(x.flags) {
        CC_SAVELIST | CTRL | CTRL_SAVELIST | VAR_SAVELIST => match address_tag!(y.flags) {
            CC_SAVELIST | CTRL | CTRL_SAVELIST | VAR_SAVELIST => swap_between_lists(engine, x, y),
            VAR => swap_with_list(engine, x, y),
            _ => fail!("swap_any: {:X}, {:X}", x, y),
        },
        CC => match address_tag!(y.flags) {
            CTRL => match engine.ctrls.get_mut(y.index) {
                Some(c) => {
                    mem::swap(c.as_continuation_mut()?, &mut engine.cc);
                    Ok(())
                }
                None => fail!(ExceptionCode::TypeCheckError),
            },
            VAR => {
                mem::swap(engine.cmd.var_mut(y.index).as_continuation_mut()?, &mut engine.cc);
                Ok(())
            }
            _ => fail!("swap CC-{:X}", y),
        },
        VAR => match address_tag!(y.flags) {
            CC_SAVELIST | CTRL_SAVELIST | VAR_SAVELIST => swap_with_list(engine, y, x),
            VAR => {
                engine.cmd.vars.swap(x.index, y.index);
                Ok(())
            }
            _ => fail!("swap_any: {:X}, {:X}", x, y),
        },
        _ => {
            fail!("swap_any {:X}-{:X}", x, y)
        }
    }
}

// Microfunctions *************************************************************

// ctx.cmd.push_var(copy-of-src)
// src addressing is described in executor/microcode.rs
pub(in crate::executor) fn copy_to_var(engine: &mut Engine, src: u16) -> Status {
    let copy = match address_tag!(src) {
        CC => {
            let copy = engine.cc.copy_without_stack();
            StackItem::continuation(copy)
        }
        CTRL => engine.ctrls.get(storage_index!(src)).cloned().unwrap_or_default(),
        // CTRL => match engine.ctrls.get(storage_index!(src)) {
        //     Some(ctrl) => ctrl.clone(),
        //     None => fail!(ExceptionCode::TypeCheckError, "read empty control register {}", storage_index!(src))
        // }
        STACK => engine.cc.stack.get(stack_index!(src))?.clone(),
        VAR => engine.cmd.var(storage_index!(src)).clone(),
        _ => fail!("copy_to_var: {}", src),
    };
    engine.cmd.push_var(copy);
    Ok(())
}

// ctx.cmd.push_var(src.references[0])
pub(in crate::executor) fn fetch_reference(engine: &mut Engine, src: u16) -> Status {
    let cell = match address_tag!(src) {
        CC => engine.cc.drain_reference()?,
        _ => fail!("fetch_reference: {:X}", src),
    };
    engine.cmd.push_var(StackItem::Cell(cell));
    Ok(())
}

// ctx.cmd.push_var(CC.stack[0..depth])
pub(in crate::executor) fn fetch_stack(engine: &mut Engine, depth: usize) -> Status {
    if engine.cc.stack.depth() < depth {
        fail!(
            ExceptionCode::StackUnderflow,
            "fetch_stack: depth: {}, stack depth: {}",
            depth,
            engine.cc.stack.depth()
        )
    } else {
        engine.cmd.vars.append(&mut engine.cc.stack.drop_range(0..depth)?);
        Ok(())
    }
}
