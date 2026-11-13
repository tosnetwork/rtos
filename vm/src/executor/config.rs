/*
 * RTOS project modifications (2026-10-10): historical fee operand priority and GETPARAMLONG range.
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
        gas::gas_state::Gas,
        types::{Instruction, InstructionOptions},
    },
    stack::{
        integer::{behavior::Signaling, math::Round, IntegerData},
        StackItem,
    },
};
use rtos_block::{
    error, fail, BuilderData, Cell, Deserializable, ExceptionCode, GasConsumer, GasLimitsPrices,
    HashmapE, MsgForwardPrices, Result, Serializable, SliceData, Status, StoragePrices,
    VarUInteger32,
};

fn execute_config_param(engine: &mut Engine, name: &'static str, opt: bool) -> Status {
    engine.load_instruction(Instruction::new(name))?;
    fetch_stack(engine, 1)?;
    let index = engine.cmd.var(0).as_integer()?.as_integer_value(i32::MIN..=i32::MAX).ok();
    let value = if let Some(index) = index {
        engine.get_config_param(index)?
    } else {
        // The configuration root is checked even when the integer is not a key.
        engine.smci_param(9)?.as_dict()?;
        None
    };
    if let Some(value) = value {
        engine.cc.stack.push(StackItem::Cell(value));
        if !opt {
            engine.cc.stack.push(boolean!(true));
        }
    } else {
        let value = match opt {
            true => StackItem::None,
            false => boolean!(false),
        };
        engine.cc.stack.push(value);
    }
    Ok(())
}

// - t
pub(super) fn execute_balance(engine: &mut Engine) -> Status {
    extract_config(engine, "BALANCE")
}

/// The first calls of GETEXTRABALANCE in a VM (counted across non-isolated child VMs) are cheap.
const EXTRA_BALANCE_CHEAP_CALLS: usize = 5;
/// Cell-load gas charged by one cheap call; loads beyond it are recorded as free gas.
const EXTRA_BALANCE_CHEAP_MAX_GAS: i64 = 200;

/// Cell loads of one cheap GETEXTRABALANCE call: each load is still registered as visited and
/// priced as usual, but only the first `EXTRA_BALANCE_CHEAP_MAX_GAS` of this call is charged;
/// once that allowance is used up the rest is recorded as free gas. Cell creation is not
/// charged.
struct CheapCellLoads<'a> {
    engine: &'a mut Engine,
    remaining: i64,
}

impl GasConsumer for CheapCellLoads<'_> {
    fn finalize_cell(&mut self, builder: BuilderData) -> Result<Cell> {
        builder
            .finalize(1024)
            .map_err(|err| error!(ExceptionCode::CellOverflow, "finalize cell error: {:?}", err))
    }
    fn load_cell(&mut self, cell: Cell) -> Result<SliceData> {
        let remaining = &mut self.remaining;
        self.engine.load_hashed_cell_charged(cell, true, &mut |engine, first| {
            let price = Gas::load_cell_price(first);
            let charged = price.min(*remaining);
            engine.try_use_gas(charged)?;
            *remaining = remaining.saturating_sub(charged);
            if *remaining == 0 {
                engine.use_free_gas(price.saturating_sub(charged));
            }
            Ok(())
        })
    }
    fn finalize_cell_and_load(&mut self, builder: BuilderData) -> Result<SliceData> {
        let cell = self.finalize_cell(builder)?;
        self.load_cell(cell)
    }
}

// - int
pub(super) fn execute_extra_balance(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("GETEXTRABALANCE"))?;
    fetch_stack(engine, 1)?;
    let index = engine.cmd.var(0).as_integer_value(0..=u32::MAX)?;
    let extra = engine.smci_param(7)?.tuple_item_ref(1)?.as_dict()?;
    let dict = HashmapE::with_hashmap(32, extra.cloned());
    let key = index.write_to_bitstring()?;
    // The call is counted after the operand and balance checks and before the lookup, so a
    // failing lookup still uses up a cheap call.
    engine.get_extra_balance_counter = engine
        .get_extra_balance_counter
        .checked_add(1)
        .ok_or_else(|| error!(ExceptionCode::IntegerOverflow, "extra balance call counter"))?;
    let value = if engine.get_extra_balance_counter <= EXTRA_BALANCE_CHEAP_CALLS {
        let mut loads = CheapCellLoads { engine, remaining: EXTRA_BALANCE_CHEAP_MAX_GAS };
        dict.get_with_gas(key, &mut loads)?
    } else {
        dict.get_with_gas(key, engine)?
    };
    let value = if let Some(mut slice) = value {
        StackItem::int(VarUInteger32::construct_from(&mut slice)?.inner())
    } else {
        StackItem::int(0)
    };
    engine.cc.stack.push(value);
    Ok(())
}

// ( - D 32)
pub(super) fn execute_config_dict(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("CONFIGDICT"))?;
    let dict = engine.smci_param(9)?.clone();
    engine.cc.stack.push(dict);
    engine.cc.stack.push(int!(32));
    Ok(())
}

/// (i - c?)
pub(super) fn execute_config_opt_param(engine: &mut Engine) -> Status {
    execute_config_param(engine, "CONFIGOPTPARAM", true)
}

/// (i - c -1 or 0)
pub(super) fn execute_config_ref_param(engine: &mut Engine) -> Status {
    execute_config_param(engine, "CONFIGPARAM", false)
}

fn extract_config(engine: &mut Engine, name: &'static str) -> Status {
    engine.load_instruction(Instruction::new(name).set_opts(InstructionOptions::Length(0..16)))?;
    let value = engine.smci_param(engine.cmd.length())?.clone();
    engine.cc.stack.push(value);
    Ok(())
}

fn extract_config_index(engine: &mut Engine, name: &'static str, index: usize) -> Status {
    engine.load_instruction(Instruction::new(name))?;
    let value = engine.smci_param(index)?.clone();
    engine.cc.stack.push(value);
    Ok(())
}

// - D
pub(super) fn execute_config_root(engine: &mut Engine) -> Status {
    extract_config(engine, "CONFIGROOT")
}

// - x
pub(super) fn execute_getparam(engine: &mut Engine) -> Status {
    extract_config(engine, "GETPARAM")
}

// - integer
pub(super) fn execute_now(engine: &mut Engine) -> Status {
    extract_config(engine, "NOW")
}

// - integer
pub(super) fn execute_blocklt(engine: &mut Engine) -> Status {
    extract_config(engine, "BLOCKLT")
}

// - integer
pub(super) fn execute_ltime(engine: &mut Engine) -> Status {
    extract_config(engine, "LTIME")
}

// - slice
pub(super) fn execute_my_addr(engine: &mut Engine) -> Status {
    extract_config(engine, "MYADDR")
}

// - cell
pub(super) fn execute_my_code(engine: &mut Engine) -> Status {
    extract_config(engine, "MYCODE")
}

// - x
pub(super) fn execute_randseed(engine: &mut Engine) -> Status {
    extract_config(engine, "RANDSEED")
}

// - integer
pub(super) fn execute_incoming_value(engine: &mut Engine) -> Status {
    extract_config(engine, "INCOMINGVALUE")
}

// - integer dict
pub(super) fn execute_storage_fees_collected(engine: &mut Engine) -> Status {
    extract_config(engine, "STORAGEFEES")
}

// - integer
pub(super) fn execute_due_payment(engine: &mut Engine) -> Status {
    extract_config(engine, "DUEPAYMENT")
}

// - tuple
pub(super) fn execute_prev_blocks_tuple(engine: &mut Engine) -> Status {
    extract_config(engine, "PREVBLOCKSINFOTUPLE")
}

// - tuple
pub(super) fn execute_unpacked_config(engine: &mut Engine) -> Status {
    extract_config(engine, "UNPACKEDCONFIGTUPLE")
}

// - p
pub(super) fn execute_getparam_long(engine: &mut Engine) -> Status {
    let index = engine.last_cmd() as usize;
    engine.load_instruction(Instruction::new("GETPARAMLONG"))?;
    let value = engine.smci_param(index)?.clone();
    engine.cc.stack.push(value);
    Ok(())
}

// - p
pub(super) fn execute_in_msg_param(engine: &mut Engine) -> Status {
    engine.load_instruction(
        Instruction::new("INMSGPARAM").set_opts(InstructionOptions::Length(0..16)),
    )?;
    let index = engine.cmd.length();
    let value = engine.smci_param(17)?.tuple_item_ref(index)?.clone();
    engine.cc.stack.push(value);
    Ok(())
}

// - tuple
pub(super) fn execute_get_precompiled_gas(engine: &mut Engine) -> Status {
    extract_config_index(engine, "GETPRECOMPILEDGAS", 16)
}

fn extract_unpacked_smci_param(
    engine: &mut Engine,
    name: &'static str,
    index: usize,
    sub_index: usize,
) -> Status {
    engine.load_instruction(Instruction::new(name))?;
    let result = engine.smci_param(index)?.tuple_item(sub_index, false)?;
    engine.cc.stack.push(result);
    Ok(())
}

// - tuple
pub(super) fn execute_get_prev_mc_blocks(engine: &mut Engine) -> Status {
    extract_unpacked_smci_param(engine, "PREVMCBLOCKS", 13, 0)
}

// - tuple
pub(super) fn execute_get_prev_key_block(engine: &mut Engine) -> Status {
    extract_unpacked_smci_param(engine, "PREVKEYBLOCK", 13, 1)
}

// - tuple
pub(super) fn execute_get_prev_mc_blocks100(engine: &mut Engine) -> Status {
    extract_unpacked_smci_param(engine, "PREVMCBLOCKS_100", 13, 2)
}

// - integer
pub(super) fn execute_get_global_id(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("GLOBALID"))?;
    let slice = engine.smci_extra_param(14, 1)?.as_slice()?;
    engine.cc.stack.push_int(slice.get_int(32)? as i32);
    Ok(())
}

fn calc_gas_fee(engine: &mut Engine, name: &'static str, simple: bool) -> Status {
    engine.load_instruction(Instruction::new(name))?;
    let count = 2;
    if engine.block_version() >= 9 {
        fetch_stack(engine, count)?;
    } else {
        fetch_stack(engine, 1)?;
    }
    let is_masterchain = engine.cmd.var(0).as_bool()?;
    if engine.block_version() < 9 {
        fetch_stack(engine, 1)?;
    }
    let gas = engine.cmd.var(1).as_integer_value(0..=u64::MAX / 2)?;
    let index = if is_masterchain { 2 } else { 3 };
    let slice = engine.smci_extra_param(14, index)?.as_slice()?;
    let prices = GasLimitsPrices::construct_from(&mut slice.clone())?;
    // The reference VM converts the uint64 configuration prices to signed integers.
    let variable_gas = if simple { gas } else { gas.saturating_sub(prices.flat_gas_limit) };
    let product = i128::from(prices.gas_price as i64) * i128::from(variable_gas);
    let variable_fee = (product + 0xffff) >> 16;
    let flat_fee = if simple { 0 } else { i128::from(prices.flat_gas_price as i64) };
    engine.cc.stack.push(StackItem::int(variable_fee + flat_fee));
    Ok(())
}

// (gas is_masterchain - integer)
pub(super) fn execute_calc_gas_fee(engine: &mut Engine) -> Status {
    calc_gas_fee(engine, "GETGASFEE", false)
}

// (gas is_masterchain - integer)
pub(super) fn execute_calc_gas_fee_simple(engine: &mut Engine) -> Status {
    calc_gas_fee(engine, "GETGASFEESIMPLE", true)
}

// (cells bits delta is_masterchain - integer)
pub(super) fn execute_calc_storage_fee(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("GETSTORAGEFEE"))?;
    let count = 4;
    if engine.block_version() >= 9 {
        fetch_stack(engine, count)?;
    } else {
        fetch_stack(engine, 1)?;
    }
    let is_masterchain = engine.cmd.var(0).as_bool()?;
    if engine.block_version() < 9 {
        fetch_stack(engine, 1)?;
    }
    let delta = engine.cmd.var(1).as_integer_value(0..=u64::MAX / 2)?;
    if engine.block_version() < 9 {
        fetch_stack(engine, 1)?;
    }
    let bits = engine.cmd.var(2).as_integer_value(0..=u64::MAX / 2)?;
    if engine.block_version() < 9 {
        fetch_stack(engine, 1)?;
    }
    let cells = engine.cmd.var(3).as_integer_value(0..=u64::MAX / 2)?;
    let slice = engine.smci_extra_param(14, 0)?.as_slice()?;
    if slice.is_empty_cell() {
        engine.cc.stack.push(StackItem::int(0));
    } else {
        let prices = StoragePrices::construct_from(&mut slice.clone())?;
        let fee = prices.calc_storage_fee_part(cells, bits, delta, is_masterchain);
        let fee = (fee + 0xffffu32) >> 16;
        engine.cc.stack.push(StackItem::int(fee));
    }
    Ok(())
}

fn calc_forward_prices(engine: &mut Engine, name: &'static str, simple: bool) -> Status {
    engine.load_instruction(Instruction::new(name))?;
    let count = 3;
    if engine.block_version() >= 9 {
        fetch_stack(engine, count)?;
    } else {
        fetch_stack(engine, 1)?;
    }
    let is_masterchain = engine.cmd.var(0).as_bool()?;
    if engine.block_version() < 9 {
        fetch_stack(engine, 1)?;
    }
    let bits = engine.cmd.var(1).as_integer_value(0..=u64::MAX / 2)?;
    if engine.block_version() < 9 {
        fetch_stack(engine, 1)?;
    }
    let cells = engine.cmd.var(2).as_integer_value(0..=u64::MAX / 2)?;
    let index = if is_masterchain { 4 } else { 5 };
    let slice = engine.smci_extra_param(14, index)?.as_slice()?;
    let prices = MsgForwardPrices::construct_from(&mut slice.clone())?;
    let fwd_fee = if simple {
        prices.calc_fwd_fee_simple(bits, cells)
    } else {
        prices.calc_fwd_fee(bits, cells)
    };
    engine.cc.stack.push(StackItem::int(fwd_fee));
    Ok(())
}

// (cells bits is_masterchain - integer)
pub(super) fn execute_calc_forward_fee(engine: &mut Engine) -> Status {
    calc_forward_prices(engine, "GETFORWARDFEE", false)
}

// (cells bits is_masterchain - integer)
pub(super) fn execute_calc_forward_fee_simple(engine: &mut Engine) -> Status {
    calc_forward_prices(engine, "GETFORWARDFEESIMPLE", true)
}

// (fwd_fee bits is_masterchain - integer)
pub(super) fn execute_get_original_forward_fee(engine: &mut Engine) -> Status {
    engine.load_instruction(Instruction::new("GETORIGINALFWDFEE"))?;
    let count = 2;
    if engine.block_version() >= 9 {
        fetch_stack(engine, count)?;
    } else {
        fetch_stack(engine, 1)?;
    }
    let is_masterchain = engine.cmd.var(0).as_bool()?;
    if engine.block_version() < 9 {
        fetch_stack(engine, 1)?;
    }
    let fwd_fee = engine.cmd.var(1).as_integer()?;
    if fwd_fee.is_neg() {
        fail!(ExceptionCode::RangeCheckError, "fwd_fee is negative");
    }
    let fwd_fee = fwd_fee.shl::<Signaling>(16)?;
    let index = if is_masterchain { 4 } else { 5 };
    let slice = engine.smci_extra_param(14, index)?.as_slice()?;
    let prices = MsgForwardPrices::construct_from(&mut slice.clone())?;
    let (fwd_fee, _) = fwd_fee.div::<Signaling>(
        &IntegerData::from((1 << 16) - (prices.first_frac as u32))?,
        Round::FloorToZero,
    )?;
    engine.cc.stack.push(StackItem::int(fwd_fee));
    Ok(())
}
