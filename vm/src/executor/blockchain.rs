/*
 * RTOS project modifications (2026-10-10): project naming and message execution compatibility.
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
        serialize_currency_collection,
        types::Instruction,
    },
    stack::{
        integer::{behavior::OperationBehavior, IntegerData},
        StackItem,
    },
};
use num::{bigint::Sign, BigInt};
use rtos_block::{
    error, fail, BuilderData, Cell, Deserializable, ExceptionCode, GasConsumer, IBitstring,
    MsgAddressInt, MsgForwardPrices, Result, SizeLimitsConfig, SliceData, Status,
    ACTION_CHANGE_LIB, ACTION_RESERVE, ACTION_SEND_MSG, ACTION_SET_CODE,
};

fn get_bigint(slice: &SliceData) -> BigInt {
    let bits = slice.remaining_bits();
    if bits == 0 {
        BigInt::from(0)
    } else if bits < 256 {
        BigInt::from_bytes_be(Sign::Plus, &slice.get_bytestring(0)) << (256 - bits)
    } else {
        BigInt::from_bytes_be(Sign::Plus, &slice.get_bytestring(0)[..32])
    }
}

// Blockchain related instructions ********************************************

fn add_action(
    engine: &mut Engine,
    action_id: u32,
    cell: Option<Cell>,
    suffix: BuilderData,
) -> Status {
    let mut new_action = BuilderData::new();
    let c5 = engine.ctrls.get(5).ok_or(ExceptionCode::TypeCheckError)?;
    new_action.checked_append_reference(c5.as_cell()?.clone())?;
    new_action.append_u32(action_id)?.append_builder(&suffix)?;
    if let Some(cell) = cell {
        new_action.checked_append_reference(cell)?;
    }
    let cell = engine.finalize_cell(new_action)?;
    engine.ctrls.put(5, StackItem::Cell(cell))?;
    Ok(())
}

/// The mode operand of SETLIBCODE and CHANGELIB: up to 2, optionally with flag 16, from
/// version 4; at most 2 before.
fn lib_mode(engine: &Engine, item: &StackItem) -> Result<u8> {
    if engine.block_version() >= 4 {
        let mode = item.as_integer_value(0..=31u8)?;
        if mode & !16 > 2 {
            fail!(ExceptionCode::RangeCheckError, "invalid library mode {mode}");
        }
        Ok(mode)
    } else {
        item.as_integer_value(0..=2u8)
    }
}

/// CHANGELIB (h x - )
pub(super) fn execute_changelib(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("CHANGELIB"))?;
    fetch_stack(engine, 2)?;
    let x = lib_mode(engine, engine.cmd.var(0))?;
    let hash = engine.cmd.var(1).as_integer()?.as_u256()?;
    let mut suffix = BuilderData::with_raw(vec![x * 2], 8)?;
    suffix.append_raw(&hash, 256)?;
    add_action(engine, ACTION_CHANGE_LIB, None, suffix)
}

// SENDMSG walks the original envelope references, stopping the entire walk at
// the cell limit. This is a VM fee simulation, not action-phase size validation.
fn sendmsg_storage(
    engine: &mut Engine,
    cell: Cell,
    limit: u64,
    visited: &mut std::collections::HashSet<rtos_block::UInt256>,
    cells: &mut u64,
    bits: &mut u64,
) -> Result<bool> {
    let mut pending = vec![cell];
    while let Some(cell) = pending.pop() {
        if !visited.insert(cell.repr_hash().clone()) {
            continue;
        }
        if *cells >= limit {
            return Ok(false);
        }
        *cells += 1;
        let slice = engine.load_hashed_cell(cell, false)?;
        *bits += slice.remaining_bits() as u64;
        for i in (0..slice.remaining_references()).rev() {
            pending.push(slice.reference(i)?);
        }
    }
    Ok(true)
}

// MYADDR is an arbitrary c7 slice. This consumer reads only the workchain
// prefix, including the reference reader's quiet EOF behavior; it does not
// validate the address tail or impose the shared address codec's constraints.
fn sendmsg_workchain(mut slice: SliceData) -> Result<i32> {
    if slice.get_next_int(1).unwrap_or(u64::MAX) != 1 {
        fail!(ExceptionCode::RangeCheckError, "not an internal message address");
    }
    let is_var = slice.get_next_int(1).unwrap_or(u64::MAX) != 0;
    if slice.get_next_int(1).unwrap_or(u64::MAX) == 1 {
        if let Ok(depth) = slice.get_next_int(5) {
            if depth <= 30 {
                let _ = slice.move_by(depth as usize);
            }
        }
    }
    if is_var {
        let _ = slice.move_by(9);
        Ok(slice.get_next_int(32).unwrap_or(0) as u32 as i32)
    } else {
        Ok(slice.get_next_int(8).unwrap_or(0) as u8 as i8 as i32)
    }
}

fn sendmsg_grams_bits(value: u128) -> usize {
    4 + (128 - value.leading_zeros() as usize).div_ceil(8) * 8
}

fn sendmsg_value_bits(value: &Option<BigInt>) -> usize {
    // The unsigned bit-size operation returns INT_MAX for NaN/negative
    // values; SENDMSG uses that size to decide whether the body must move.
    let bits = value
        .as_ref()
        .filter(|n| n.sign() != Sign::Minus)
        .map_or(i32::MAX as usize, |n| n.bits() as usize);
    4 + bits.div_ceil(8) * 8
}

struct SendMessageInfo {
    external: bool,
    dest_bits: usize,
    dest_masterchain: bool,
    value: u128,
    extra: bool,
    ihr_disabled: bool,
    user_fwd: u128,
    user_ihr: u128,
    extra_flags_bits: usize,
}
fn sendmsg_varuint(slice: &mut SliceData) -> Result<(u128, usize, bool)> {
    let bytes = slice.get_next_int(4)? as usize;
    let mut value = 0u128;
    let mut canonical = true;
    for i in 0..bytes {
        let byte = slice.get_next_byte()?;
        if i == 0 && byte == 0 {
            canonical = false;
        }
        value = (value << 8) | byte as u128;
    }
    Ok((value, 4 + bytes * 8, canonical))
}
fn sendmsg_header(slice: &mut SliceData) -> Result<SendMessageInfo> {
    if !slice.get_next_bit()? {
        let flags = slice.get_next_int(3)?;
        rtos_block::MsgAddressIntOrNone::skip(slice)?;
        let before = slice.remaining_bits();
        let dest = MsgAddressInt::construct_from(slice)?;
        let dest_bits = before - slice.remaining_bits();
        let (value, _, canonical) = sendmsg_varuint(slice)?;
        if !canonical {
            fail!(ExceptionCode::UnknownError);
        }
        let extra = slice.get_next_bit()?;
        if extra {
            slice.checked_drain_reference()?;
        }
        let (user_ihr, extra_flags_bits, canonical) = sendmsg_varuint(slice)?;
        let user_ihr = if canonical { user_ihr } else { 0 };
        let (user_fwd, _, canonical) = sendmsg_varuint(slice)?;
        let user_fwd = if canonical { user_fwd } else { 0 };
        slice.move_by(96)?;
        Ok(SendMessageInfo {
            external: false,
            dest_bits,
            dest_masterchain: dest.is_masterchain(),
            value,
            extra,
            ihr_disabled: flags & 4 != 0,
            user_fwd,
            user_ihr,
            extra_flags_bits,
        })
    } else {
        if !slice.get_next_bit()? {
            fail!(ExceptionCode::UnknownError);
        }
        rtos_block::MsgAddressIntOrNone::skip(slice)?;
        let before = slice.remaining_bits();
        rtos_block::MsgAddressExt::skip(slice)?;
        let dest_bits = before - slice.remaining_bits();
        slice.move_by(96)?;
        Ok(SendMessageInfo {
            external: true,
            dest_bits,
            dest_masterchain: false,
            value: 0,
            extra: false,
            ihr_disabled: true,
            user_fwd: 0,
            user_ihr: 0,
            extra_flags_bits: 0,
        })
    }
}

/// SENDMSG (c x – fee): simulate forwarding fees using the original message
/// layout, and optionally append the original cell to the action list.
pub(super) fn execute_send_msg(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("SENDMSG"))?;
    fetch_stack(engine, 2)?;
    let mut mode = engine.cmd.var(0).as_integer_value(0..=2047)?;
    let send = (mode & 1024) == 0;
    mode &= !1024;
    if mode >= 256 {
        fail!(ExceptionCode::RangeCheckError);
    }
    let cell = engine.cmd.var(1).as_cell()?.clone();
    let original = engine.load_cell(cell.clone())?;
    // Parse the envelope without loading referenced StateInit or body cells.
    // Those references are opaque at this stage and are visited below with gas.
    let parsed = (|| -> Result<_> {
        let mut slice = original.clone();
        let header = sendmsg_header(&mut slice)?;
        let have_init = slice.get_next_bit()?;
        let mut init_ref = false;
        let (mut init_bits, mut init_refs) = (0, 0);
        if have_init {
            init_ref = slice.get_next_bit()?;
            if init_ref {
                slice.checked_drain_reference()?;
            } else {
                let before = slice.remainig();
                rtos_block::StateInit::skip(&mut slice)?;
                init_bits = before.0 - slice.remaining_bits();
                init_refs = before.1 - slice.remaining_references();
            }
        }
        let body_ref = slice.get_next_bit()?;
        let (body_bits, body_refs) = if body_ref {
            slice.checked_drain_reference()?;
            if !slice.is_empty_cell() {
                fail!(ExceptionCode::UnknownError);
            }
            (0, 0)
        } else {
            slice.remainig()
        };
        Ok((header, have_init, init_ref, init_bits, init_refs, body_ref, body_bits, body_refs))
    })()
    .map_err(|_| rtos_block::error!(ExceptionCode::UnknownError))?;
    let (header, have_init, mut init_ref, init_bits, init_refs, mut body_ref, body_bits, body_refs) =
        parsed;
    let my_addr = engine.smci_param(8)?.as_slice()?;
    let my_addr_bits = my_addr.remaining_bits();
    let my_workchain = sendmsg_workchain(my_addr.clone())?;
    let version = engine.block_version();
    let SendMessageInfo {
        external,
        dest_bits,
        value,
        mut extra,
        ihr_disabled,
        user_fwd,
        user_ihr,
        extra_flags_bits,
        dest_masterchain,
    } = header;
    let mut value = Some(BigInt::from(value));
    let ihr_disabled = ihr_disabled || version >= 11;
    let user_ihr = if version >= 12 { 0 } else { user_ihr };
    let masterchain = my_workchain == -1 || dest_masterchain;
    let prices = if version >= 6 {
        let index = if masterchain { 4 } else { 5 };
        let slice = engine
            .smci_extra_param(14, index)?
            .as_slice()
            .map_err(|_| rtos_block::error!(ExceptionCode::UnknownError))?;
        MsgForwardPrices::construct_from(&mut slice.clone())
            .map_err(|_| rtos_block::error!(ExceptionCode::CellUnderflow))?
    } else {
        let cell = engine
            .get_config_param(if masterchain { 24 } else { 25 })?
            .ok_or(ExceptionCode::UnknownError)?;
        MsgForwardPrices::construct_from(&mut engine.load_cell(cell)?)
            .map_err(|_| rtos_block::error!(ExceptionCode::CellUnderflow))?
    };
    let max_cells = if version >= 6 {
        match engine.smci_extra_param(14, 6)?.as_slice() {
            Ok(slice) => {
                SizeLimitsConfig::construct_from(&mut slice.clone())
                    .map_err(|_| rtos_block::error!(ExceptionCode::CellUnderflow))?
                    .max_msg_cells
            }
            Err(_) => SizeLimitsConfig::default().max_msg_cells,
        }
    } else {
        1 << 13
    };
    let envelope = engine.load_cell(cell.clone())?;
    let (mut cells, mut bits) = (0u64, 0u64);
    let mut visited = std::collections::HashSet::new();
    for i in usize::from(version >= 10 && extra)..envelope.remaining_references() {
        if !sendmsg_storage(
            engine,
            envelope.reference(i)?,
            max_cells as u64,
            &mut visited,
            &mut cells,
            &mut bits,
        )? {
            break;
        }
    }
    if !external {
        let balance = if mode & 128 != 0 {
            Some((7, false))
        } else if mode & 64 != 0 {
            Some((11, true))
        } else {
            None
        };
        if let Some((index, add)) = balance {
            let amount = engine.smci_extra_param(index, 0)?.as_integer()?.as_int();
            value = if add {
                value.as_ref().zip(amount.as_ref()).map(|(value, amount)| value + amount)
            } else {
                amount.clone()
            };
            if version < 10 {
                extra |= engine.smci_extra_param(index, 1)?.as_cell().is_ok();
            }
        }
    }
    let compute_fees = |bits, cells| {
        // The reference VM's forwarding arithmetic takes the low 64 bits.
        let computed = prices.calc_fwd_fee(bits, cells) as u64 as u128;
        let ihr = if ihr_disabled {
            0
        } else {
            (computed * prices.ihr_price_factor as u128 >> 16) as u64 as u128
        };
        if version < 14 {
            (computed.max(user_fwd), ihr.max(if ihr_disabled { 0 } else { user_ihr }))
        } else {
            (computed, ihr)
        }
    };
    let root_size = |fee: u128, ihr: u128, init_ref: bool, body_ref: bool| {
        let header = if external {
            2 + my_addr_bits + dest_bits + 96
        } else {
            4 + my_addr_bits
                + dest_bits
                + sendmsg_value_bits(&value)
                + 1
                + 96
                + sendmsg_grams_bits(
                    fee - ((fee >> 16) * prices.first_frac as u128
                        + ((fee & 65535) * prices.first_frac as u128 >> 16)),
                )
                + if version >= 12 { extra_flags_bits } else { sendmsg_grams_bits(ihr) }
        };
        (
            header
                + 2
                + usize::from(have_init)
                + if have_init && !init_ref { init_bits } else { 0 }
                + if body_ref { 0 } else { body_bits },
            usize::from(extra)
                + if have_init {
                    if init_ref {
                        1
                    } else {
                        init_refs
                    }
                } else {
                    0
                }
                + if body_ref { 1 } else { body_refs },
        )
    };
    let (mut fee, mut ihr) = compute_fees(bits, cells);
    let (root_bits, root_refs) = root_size(fee, ihr, init_ref, body_ref);
    if have_init && !init_ref && (root_bits > 1023 || root_refs > 4) {
        init_ref = true;
        cells += 1;
        bits += init_bits as u64;
        (fee, ihr) = compute_fees(bits, cells);
    }
    let (root_bits, root_refs) = root_size(fee, ihr, init_ref, body_ref);
    if !body_ref && (root_bits > 1023 || root_refs > 4) {
        body_ref = true;
        cells += 1;
        bits += body_bits as u64;
        (fee, ihr) = compute_fees(bits, cells);
    }
    let _ = body_ref;
    engine.cc.stack.push(StackItem::int(fee + ihr));
    if send {
        add_action(
            engine,
            ACTION_SEND_MSG,
            Some(cell),
            BuilderData::with_raw(vec![mode as u8], 8)?,
        )?;
    }
    Ok(())
}

/// SENDRAWMSG (c x – ): pop mode and message cell from stack and put it at the
/// end of output actions list.
pub(super) fn execute_sendrawmsg(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("SENDRAWMSG"))?;
    fetch_stack(engine, 2)?;
    let x = engine.cmd.var(0).as_integer_value(0..=255)?;
    let cell = engine.cmd.var(1).as_cell()?.clone();
    let suffix = BuilderData::with_raw(vec![x], 8)?;
    add_action(engine, ACTION_SEND_MSG, Some(cell), suffix)
}

/// SETCODE (c - )
pub(super) fn execute_setcode(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("SETCODE"))?;
    fetch_stack(engine, 1)?;
    let cell = engine.cmd.var(0).as_cell()?.clone();
    add_action(engine, ACTION_SET_CODE, Some(cell), BuilderData::new())
}

/// SETLIBCODE (c x - )
pub(super) fn execute_setlibcode(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("SETLIBCODE"))?;
    fetch_stack(engine, 2)?;
    let x = lib_mode(engine, engine.cmd.var(0))?;
    let cell = engine.cmd.var(1).as_cell()?.clone();
    let suffix = BuilderData::with_raw(vec![x * 2 + 1], 8)?;
    add_action(engine, ACTION_CHANGE_LIB, Some(cell), suffix)
}

fn reserve_amount(item: &StackItem) -> Result<u128> {
    let amount = item.as_integer()?;
    amount.take_value_of(|_| Some(()))?;
    amount.check_neg()?;
    if !amount.ufits_in(120)? {
        fail!(ExceptionCode::CellOverflow, "reserve amount does not fit Grams");
    }
    item.as_coins()
}

/// RAWRESERVE (x y - )
pub(super) fn execute_rawreserve(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("RAWRESERVE"))?;
    fetch_stack(engine, 2)?;
    let y = engine.cmd.var(0).as_integer_value(0..=0b0001_1111)?;
    let mut suffix = BuilderData::with_raw(vec![y], 8)?;
    let x = reserve_amount(engine.cmd.var(1))?;
    suffix.append_builder(&serialize_currency_collection(x, None)?)?;
    add_action(engine, ACTION_RESERVE, None, suffix)
}

/// RAWRESERVEX (s y - )
pub(super) fn execute_rawreservex(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("RAWRESERVEX"))?;
    fetch_stack(engine, 3)?;
    let y = engine.cmd.var(0).as_integer_value(0..=0b0001_1111)?;
    let mut suffix = BuilderData::with_raw(vec![y], 8)?;
    let other = engine.cmd.var(1).as_dict()?;
    let x = reserve_amount(engine.cmd.var(2))?;
    suffix.append_builder(&serialize_currency_collection(x, other.cloned())?)?;
    add_action(engine, ACTION_RESERVE, None, suffix)
}

pub(super) fn execute_ldmsgaddr<T: OperationBehavior>(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new(if T::quiet() {
        "LDMSGADDRQ"
    } else {
        "LDMSGADDR"
    }))?;
    fetch_stack(engine, 1)?;
    let mut slice = engine.cmd.var(0).as_slice()?.clone();
    let mut remainder = slice.clone();
    if parse_address(&mut remainder).is_ok() {
        slice.shrink_by_remainder(&remainder);
        engine.cc.stack.push(StackItem::Slice(slice));
        engine.cc.stack.push(StackItem::Slice(remainder));
        if T::quiet() {
            engine.cc.stack.push_bool(true);
        }
        Ok(())
    } else if T::quiet() {
        let var = engine.cmd.pop_var()?;
        engine.cc.stack.push(var);
        engine.cc.stack.push_bool(false);
        Ok(())
    } else {
        fail!(ExceptionCode::CellUnderflow)
    }
}

fn ldoptstdaddr(engine: &mut Engine, quiet: bool, none_allowed: bool) -> Status {
    fetch_stack(engine, 1)?;
    let mut slice = engine.cmd.var(0).as_slice()?.clone();
    match parse_opt_std_address(&mut slice, none_allowed) {
        Ok(result) => {
            engine.cc.stack.push(result);
            engine.cc.stack.push(StackItem::Slice(slice));
            if quiet {
                engine.cc.stack.push_bool(true);
            }
        }
        Err(err) => {
            if quiet {
                engine.cc.stack.push(engine.cmd.var_mut(0).withdraw());
                engine.cc.stack.push_bool(false);
            } else {
                return Err(err);
            }
        }
    }
    Ok(())
}

pub(super) fn execute_ldoptstdaddr<T: OperationBehavior>(engine: &mut Engine) -> Status {
    let name = if T::quiet() { "LDOPTSTDADDRQ" } else { "LDOPTSTDADDR" };
    engine.load_instruction(Instruction::new(name))?;
    ldoptstdaddr(engine, T::quiet(), true)
}

pub(super) fn execute_ldstdaddr<T: OperationBehavior>(engine: &mut Engine) -> Status {
    let name = if T::quiet() { "LDSTDADDRQ" } else { "LDSTDADDR" };
    engine.load_instruction(Instruction::new(name))?;
    ldoptstdaddr(engine, T::quiet(), false)
}

fn load_address<F, T>(engine: &mut Engine, name: &'static str, op: F) -> Status
where
    F: FnOnce(Vec<StackItem>, &mut dyn GasConsumer) -> Result<Vec<StackItem>>,
    T: OperationBehavior,
{
    engine.load_instruction(Instruction::new(name))?;
    fetch_stack(engine, 1)?;
    let mut slice = engine.cmd.var(0).as_slice()?.clone();
    let result = match parse_address(&mut slice) {
        Ok(addr) if slice.is_empty_cell() => match op(addr, engine) {
            Ok(mut stack) => {
                stack.drain(..).for_each(|var| {
                    engine.cc.stack.push(var);
                });
                None
            }
            Err(err) => Some(err),
        },
        Ok(_) => Some(error!(ExceptionCode::CellUnderflow, "trailing address data")),
        Err(err) => Some(err),
    };
    if T::quiet() {
        engine.cc.stack.push_bool(result.is_none());
    } else if let Some(err) = result {
        return Err(err);
    }
    Ok(())
}

pub(super) fn execute_parsemsgaddr<T: OperationBehavior>(engine: &mut Engine) -> Status {
    load_address::<_, T>(
        engine,
        if T::quiet() { "PARSEMSGADDRQ" } else { "PARSEMSGADDR" },
        |tuple, _| Ok(vec![StackItem::tuple(tuple)]),
    )
}

// (s - x y) compose rewrite_pfx and address to a 256 bit integer
pub(super) fn execute_rewrite_std_addr<T: OperationBehavior>(engine: &mut Engine) -> Status {
    load_address::<_, T>(
        engine,
        if T::quiet() { "REWRITESTDADDRQ" } else { "REWRITESTDADDR" },
        |tuple, _| {
            if tuple.len() == 4 {
                let addr = tuple[3].as_slice()?;
                let mut y = match addr.remaining_bits() {
                    256 => IntegerData::from(get_bigint(addr))?,
                    _ => fail!(ExceptionCode::CellUnderflow),
                };
                if tuple[1].is_slice() {
                    let rewrite_pfx = tuple[1].as_slice()?;
                    let bits = rewrite_pfx.remaining_bits();
                    if bits > 256 {
                        fail!(ExceptionCode::CellUnderflow)
                    } else if bits > 0 {
                        let prefix = IntegerData::from(get_bigint(rewrite_pfx))?;
                        let mask = IntegerData::mask(256 - bits);
                        y = y.and::<T>(&mask)?.or::<T>(&prefix)?;
                    }
                };
                let x = tuple[2].clone();
                Ok(vec![x, StackItem::int(y)])
            } else {
                fail!(ExceptionCode::CellUnderflow)
            }
        },
    )
}

// (s - x s') compose rewrite_pfx and address to a slice
pub(super) fn execute_rewrite_var_addr<T: OperationBehavior>(engine: &mut Engine) -> Status {
    load_address::<_, T>(
        engine,
        if T::quiet() { "REWRITEVARADDRQ" } else { "REWRITEVARADDR" },
        |tuple, gas_consumer| {
            if tuple.len() == 4 {
                let mut addr = tuple[3].as_slice()?.clone();
                if let Ok(rewrite_pfx) = tuple[1].as_slice() {
                    let bits = rewrite_pfx.remaining_bits();
                    if bits > addr.remaining_bits() {
                        fail!(ExceptionCode::CellUnderflow)
                    } else if bits > 0 {
                        let mut b = rewrite_pfx.as_builder()?;
                        addr.shrink_data(bits..);
                        b.append_bytestring(&addr)?;
                        addr = gas_consumer.finalize_cell_and_load(b)?;
                    }
                };
                let x = tuple[2].clone();
                Ok(vec![x, StackItem::Slice(addr)])
            } else {
                fail!(ExceptionCode::CellUnderflow)
            }
        },
    )
}

fn read_rewrite_pfx(slice: &mut SliceData) -> Result<Option<SliceData>> {
    match slice.get_next_bit()? {
        true => {
            let len = slice.get_next_int(5)?;
            Ok(Some(slice.get_next_slice(len as usize)?))
        }
        false => Ok(None),
    }
}

fn parse_address(cell: &mut SliceData) -> Result<Vec<StackItem>> {
    let addr_type = cell.get_next_int(2)? as u8;
    let mut tuple = vec![int!(addr_type)];
    match addr_type & 0b11 {
        0b00 => (),
        0b01 => {
            let len = cell.get_next_int(9)?;
            tuple.push(StackItem::Slice(cell.get_next_slice(len as usize)?));
        }
        0b10 => {
            tuple.push(match read_rewrite_pfx(cell)? {
                Some(_slice) => {
                    fail!(ExceptionCode::CellUnderflow, "Anycast is not allowed")
                    // StackItem::Slice(slice)
                }
                None => StackItem::None,
            });
            tuple.push(int!(cell.get_next_byte()? as i8));
            tuple.push(StackItem::Slice(cell.get_next_slice(256)?));
        }
        0b11 => {
            fail!(ExceptionCode::CellUnderflow, "AddVar is not allowed")
            // tuple.push(match read_rewrite_pfx(cell)? {
            //     Some(slice) => StackItem::Slice(slice),
            //     None => StackItem::None
            // });
            // let len = cell.get_next_int(9)?;
            // tuple.push(int!(cell.get_next_i32()?));
            // tuple.push(StackItem::Slice(cell.get_next_slice(len as usize)?));
        }
        _ => (),
    }
    Ok(tuple)
}

fn parse_opt_std_address(slice: &mut SliceData, none_allowed: bool) -> Result<StackItem> {
    let mut cell = slice.clone();
    match slice.get_next_int(2)? {
        0b10 => {
            if read_rewrite_pfx(slice)?.is_some() {
                fail!(ExceptionCode::CellUnderflow, "Anycast is not allowed")
            }
            slice.move_by(8 + 256)?;
            cell.shrink_by_remainder(slice);
            Ok(StackItem::Slice(cell))
        }
        0b00 if none_allowed => Ok(StackItem::None),
        tag => fail!(ExceptionCode::CellUnderflow, "0b{tag:02b} is not a standard address tag"),
    }
}
