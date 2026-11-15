/*
 * RTOS project modifications (2026-10-10): node getter context and versioned library selection.
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
    executor::{gas::gas_state::Gas, Engine},
    stack::{integer::IntegerData, savelist::SaveList, Stack, StackItem},
};
use rtos_api::{
    ton::tvm::{
        stackentry::{
            StackEntryCell, StackEntryList, StackEntryNumber, StackEntrySlice, StackEntryTuple,
        },
        StackEntry,
    },
    IntoBoxed,
};
use rtos_block::{
    error, fail, read_single_root_boc, write_boc, Account, BlockIdExt, Cell, ConfigParams,
    CurrencyCollection, Deserializable, ExtBlkRef, HashmapAugType, KeyExtBlkRef, Message,
    OldMcBlocksInfo, Result, Serializable, Sha256, ShardStateUnsplit, SliceData, UInt256, UnixTime,
};
use std::{borrow::Cow, mem};

/*
The smart-contract information
structure SmartContractInfo, passed in the first reference of the cell contained
in control register c5, is serialized as follows:

smc_info#076ef1ea actions:uint16 msgs_sent:uint16
unixtime:uint32 block_lt:uint64 trans_lt:uint64
rand_seed:uint256 balance_remaining:CurrencyCollection
myself:MsgAddress = SmartContractInfo;
*/

#[derive(Clone, Debug)]
pub enum PrevBlocksInfo {
    Tuple(StackItem),
    Raw(KeyExtBlkRef, OldMcBlocksInfo),
}

impl Default for PrevBlocksInfo {
    fn default() -> Self {
        PrevBlocksInfo::Tuple(StackItem::None)
    }
}

/// Full original external inbound message DAG, including its root cell.
#[derive(Clone, Debug)]
pub struct IncomingStorageStats {
    pub hash: UInt256,
    pub cells: u64,
    pub bits: u64,
}

#[derive(Clone, Debug, Default)]
pub struct SmartContractInfo {
    pub actions: u16,
    pub msgs_sent: u16,
    pub unix_time: u32,
    pub block_lt: u64,
    pub trans_lt: u64,
    pub rand_seed: IntegerData,
    pub balance: CurrencyCollection,
    pub myself: SliceData,
    pub config_params: ConfigParams,
    pub mycode: Cell,
    pub in_msg: Option<Message>,
    pub incoming_storage_stats: Option<IncomingStorageStats>,
    pub incoming_value: CurrencyCollection, // remaining value
    pub storage_fees_collected: u128,
    pub prev_blocks_info: PrevBlocksInfo,
    pub due_payment: u128,
    pub precompiled_gas_usage: u64,
}

pub struct SmcMethodResult {
    pub exit_code: i32,
    pub gas_used: i64,
    pub stack: Vec<StackItem>,
    pub smc_info: SmartContractInfo,
    /// Preserve absence for initial-c7 responses after a null-code VM run.
    pub code_present: bool,
}

impl SmcMethodResult {
    /// Initial node getter context. The reduced response hides configuration and
    /// uses a fresh seed, as it is independent of the context used for execution.
    pub fn initial_c7(&self, full: bool) -> Result<StackItem> {
        self.initial_c7_with_rng(full, &mut rand::rngs::OsRng)
    }

    fn initial_c7_with_rng<R: rand::RngCore + rand::CryptoRng>(
        &self,
        full: bool,
        rng: &mut R,
    ) -> Result<StackItem> {
        let mut context = self.smc_info.as_get_method_data_item_with_code(
            self.code_present.then_some(&self.smc_info.mycode),
        )?;
        if full {
            return Ok(context);
        }
        let mut outer = context.as_tuple_mut()?;
        let mut fields = outer.remove(0).as_tuple_mut()?;
        fields.truncate(10);
        fields[9] = StackItem::None;
        let mut seed = [0; 32];
        rng.try_fill_bytes(&mut seed)?;
        fields[6] = StackItem::integer(IntegerData::from_unsigned_bytes_be(&seed));
        Ok(StackItem::tuple(vec![StackItem::tuple(fields)]))
    }

    pub fn into_run_result(self) -> Result<rtos_api::ton::smc::runresult::RunResult> {
        Ok(rtos_api::ton::smc::runresult::RunResult {
            gas_used: self.gas_used,
            stack: convert_stack(&self.stack)?,
            exit_code: self.exit_code,
        })
    }
}

impl SmartContractInfo {
    pub fn with_params(
        account: Option<&Account>,
        message_root: Option<Cell>,
        mc_state_root: Option<Cell>, // state root could be virtualized
    ) -> Result<Self> {
        let mut smci = Self { unix_time: UnixTime::now() as u32, ..Default::default() };
        if let Some(mc_state_root) = mc_state_root {
            let mc_state = ShardStateUnsplit::construct_from_cell(mc_state_root)?;
            let extra =
                mc_state.read_custom()?.ok_or_else(|| error!("No custom data in mc_state"))?;
            smci.prev_blocks_info = PrevBlocksInfo::Raw(
                KeyExtBlkRef {
                    key: extra.after_key_block,
                    blk_ref: ExtBlkRef {
                        end_lt: mc_state.gen_lt(),
                        seq_no: mc_state.seq_no(),
                        root_hash: UInt256::default(),
                        file_hash: UInt256::default(),
                    },
                },
                extra.prev_blocks,
            );
            smci.block_lt = mc_state.gen_lt() + 1;
            smci.unix_time = mc_state.gen_time() + 1;
            smci.config_params = extra.config;
        }
        if let Some(account) = account {
            if let Some(addr) = account.get_addr() {
                smci.myself = addr.write_to_bitstring()?;
            }
            if let Some(balance) = account.balance() {
                smci.balance = balance.clone();
            }
            smci.mycode = account.get_code().unwrap_or_default();
            smci.due_payment = account.due_payment().map_or(0, |g| g.as_u128());
        }
        if let Some(message_root) = message_root {
            let message = Message::construct_from_cell(message_root)?;
            if let Some(incoming_value) = message.value() {
                smci.incoming_value = incoming_value.clone();
            }
            smci.in_msg = Some(message);
        }
        Ok(smci)
    }

    pub fn unix_time(&self) -> u32 {
        self.unix_time
    }

    pub fn set_mycode(&mut self, code: Cell) {
        self.mycode = code;
    }

    pub fn set_precompiled_gas_usage(&mut self, precompiled_gas_usage: u64) {
        self.precompiled_gas_usage = precompiled_gas_usage;
    }

    // The rand_seed field here is initialized deterministically starting from the
    // rand_seed of the block, and the account address.
    pub fn calc_rand_seed(&mut self, rand_seed_block: UInt256, account_address_anycast: &[u8]) {
        // combine all parameters to vec and calculate hash of them
        self.rand_seed = if !rand_seed_block.is_zero() {
            let mut hasher = Sha256::new();
            hasher.update(&rand_seed_block);
            hasher.update(account_address_anycast);

            let sha256 = hasher.finalize();
            IntegerData::from_unsigned_bytes_be(sha256)
        } else {
            // if the user forgot to set the rand_seed_block value, then this 0 will be clearly visible on tests
            log::warn!(target: "tvm", "Not set rand_seed_block");
            IntegerData::zero()
        };
    }

    fn cc2tuple(value: &CurrencyCollection) -> StackItem {
        StackItem::tuple(vec![
            StackItem::int(value.coins.as_u128()),
            StackItem::dict(value.other.root()),
        ])
    }

    fn id2tuple(id: &ExtBlkRef) -> StackItem {
        StackItem::tuple(vec![
            StackItem::int(-1),
            StackItem::int(0x8000_0000_0000_0000u64),
            StackItem::int(id.seq_no),
            StackItem::integer(IntegerData::from_unsigned_bytes_be(id.root_hash.as_slice())),
            StackItem::integer(IntegerData::from_unsigned_bytes_be(id.file_hash.as_slice())),
        ])
    }

    fn get_block_id(&self, mc_seqno: u32) -> Result<Option<Cow<'_, ExtBlkRef>>> {
        let PrevBlocksInfo::Raw(last_mc_block_id, old_mc_blocks_info) = &self.prev_blocks_info
        else {
            return Ok(None);
        };
        if mc_seqno == last_mc_block_id.blk_ref.seq_no {
            Ok(Some(Cow::Borrowed(&last_mc_block_id.blk_ref)))
        } else if let Some(id) = old_mc_blocks_info.get(&mc_seqno)? {
            Ok(Some(Cow::Owned(id.blk_ref)))
        } else {
            Ok(None)
        }
    }

    // [ wc:Integer shard:Integer seqno:Integer root_hash:Integer file_hash:Integer] = BlockId;
    // [ last_mc_blocks:[BlockId...]
    //   prev_key_block:BlockId
    //   last_mc_blocks_100[BlockId...] ] : PrevBlocksInfo
    fn get_prev_blocks_info(&self) -> StackItem {
        let (last_mc_block_id, old_mc_blocks_info) = match &self.prev_blocks_info {
            PrevBlocksInfo::Tuple(tuple) => return tuple.clone(),
            PrevBlocksInfo::Raw(last_mc_block_id, old_mc_blocks_info) => {
                (last_mc_block_id, old_mc_blocks_info)
            }
        };
        if let Err(err) = self.get_block_id(0) {
            log::warn!(target: "tvm", "cannot read zero state id {err}")
        }
        let last_mc_seqno = last_mc_block_id.blk_ref.seq_no;

        // last 16 mc blocks
        let mut seqno = last_mc_seqno;
        let mut vec = vec![Self::id2tuple(&last_mc_block_id.blk_ref)];
        loop {
            if seqno == 0 || vec.len() >= 16 {
                break;
            }
            seqno -= 1;
            let Ok(Some(id)) = self.get_block_id(seqno) else {
                break;
            };
            vec.push(Self::id2tuple(&id));
        }
        let mut tuple = vec![StackItem::tuple(vec)];

        // last key block
        if last_mc_block_id.key {
            tuple.push(Self::id2tuple(&last_mc_block_id.blk_ref));
        } else if let Ok(Some(id)) = old_mc_blocks_info.get_prev_key_block(last_mc_seqno) {
            tuple.push(Self::id2tuple(&id));
        } else {
            tuple.push(StackItem::None);
        }

        // last 16 100th mc blocks
        let mut vec = Vec::new();
        let mut seqno = last_mc_seqno / 100 * 100;
        loop {
            if let Ok(Some(id)) = self.get_block_id(seqno) {
                vec.push(Self::id2tuple(&id));
            } else {
                break;
            }
            if seqno < 100 || vec.len() >= 16 {
                break;
            }
            seqno -= 100;
        }
        tuple.push(StackItem::tuple(vec));
        StackItem::tuple(tuple)
    }

    fn config_param_slice(&self, index: u32) -> StackItem {
        self.config_params.config_cell_slice(index).map_or(StackItem::None, StackItem::Slice)
    }

    fn get_unpacked_config_tuple(&self) -> StackItem {
        let mut storage_price = StackItem::None;
        if let Ok(storage_prices) = self.config_params.storage_prices() {
            let mut best_utime_since = 0u32;
            let _ = storage_prices.map.iterate_slices_with_keys(|mut key, slice| {
                let utime_since = key.get_next_u32()?;
                if (utime_since <= self.unix_time) && (utime_since >= best_utime_since) {
                    best_utime_since = utime_since;
                    storage_price = StackItem::slice(slice);
                }
                Ok(true)
            });
        };
        let mut tuple = vec![storage_price];
        tuple.push(self.config_param_slice(19)); // global_id
        tuple.push(self.config_param_slice(20)); // config_mc_gas_prices
        tuple.push(self.config_param_slice(21)); // config_gas_prices
        tuple.push(self.config_param_slice(24)); // config_mc_fwd_prices
        tuple.push(self.config_param_slice(25)); // config_fwd_prices
        tuple.push(self.config_param_slice(43)); // size_limits_config
        StackItem::tuple(tuple)
    }
    fn get_message_info(&self) -> StackItem {
        let mut tuple = vec![];
        if let Some(msg) = self.in_msg.as_ref() {
            if let Some(int) = msg.int_header() {
                tuple.push(StackItem::boolean(int.bounce));
                tuple.push(StackItem::boolean(int.bounced));
                tuple.push(StackItem::slice(int.src.write_to_bitstring().unwrap_or_default()));
                tuple.push(StackItem::int(int.fwd_fee().as_u128()));
                tuple.push(StackItem::int(int.created_lt));
                tuple.push(StackItem::int(int.created_at));
                tuple.push(StackItem::int(int.value.coins.as_u128()));
            } else if let Some(ext) = msg.ext_in_header() {
                tuple.push(StackItem::boolean(false));
                tuple.push(StackItem::boolean(false));
                tuple.push(StackItem::slice(ext.src.write_to_bitstring().unwrap_or_default()));
                tuple.push(StackItem::int(ext.import_fee.as_u128()));
                tuple.push(StackItem::int(0));
                tuple.push(StackItem::int(0));
                tuple.push(StackItem::int(0));
            }
            tuple.push(StackItem::int(self.incoming_value.coins.as_u128()));
            tuple.push(StackItem::dict(self.incoming_value.other.root()));
            if let Some(init) = msg.state_init() {
                tuple.push(StackItem::cell(init.serialize().unwrap_or_default()));
            } else {
                tuple.push(StackItem::default());
            }
        } else {
            tuple.push(StackItem::boolean(false)); // bounce
            tuple.push(StackItem::boolean(false)); // bounced
            let addr_none =
                rtos_block::MsgAddressExt::AddrNone.write_to_bitstring().unwrap_or_default();
            tuple.push(StackItem::Slice(addr_none)); // src
            tuple.push(StackItem::int(0)); // import fee
            tuple.push(StackItem::int(0)); // created lt
            tuple.push(StackItem::int(0)); // created at
            tuple.push(StackItem::int(0)); // original value
            tuple.push(StackItem::int(0)); // value
            tuple.push(StackItem::default()); // extra
            tuple.push(StackItem::default()); // state init
        }
        StackItem::tuple(tuple)
    }

    /// Checked history tuple shared by getter and block replay contexts.
    /// An unavailable history returns null; dictionary traversal errors propagate.
    pub fn get_method_prev_blocks_info(
        state: &ShardStateUnsplit,
        current: &BlockIdExt,
    ) -> Result<StackItem> {
        let extra = state.read_custom()?.ok_or_else(|| error!("No custom data in mc_state"))?;
        let current_ref = ExtBlkRef {
            seq_no: current.seq_no(),
            end_lt: state.gen_lt(),
            root_hash: current.root_hash().clone(),
            file_hash: current.file_hash().clone(),
        };
        let lookup = |seq_no: u32| -> Result<Option<ExtBlkRef>> {
            if seq_no == current.seq_no() {
                Ok(Some(current_ref.clone()))
            } else {
                // Dictionary traversal errors remain fatal. An absent or malformed
                // historical record makes the optional getter history unavailable.
                let Some(mut slice) = extra.prev_blocks.get_as_slice(&seq_no)? else {
                    return Ok(None);
                };
                Ok(KeyExtBlkRef::construct_from(&mut slice)
                    .ok()
                    .filter(|entry| {
                        entry.blk_ref.seq_no == seq_no
                            && slice.remaining_bits() == 0
                            && slice.remaining_references() == 0
                    })
                    .map(|entry| entry.blk_ref))
            }
        };
        let mut recent = Vec::new();
        for seq_no in (current.seq_no().saturating_sub(15)..=current.seq_no()).rev() {
            let Some(block) = lookup(seq_no)? else {
                return Ok(StackItem::None);
            };
            recent.push(Self::id2tuple(&block));
        }
        let last_key =
            if extra.after_key_block { Some(&current_ref) } else { extra.last_key_block.as_ref() };
        let Some(last_key) = last_key else {
            return Ok(StackItem::None);
        };
        let mut fields = vec![StackItem::tuple(recent), Self::id2tuple(last_key)];
        if extra.config.global_version() >= 9 {
            let mut centuries = Vec::new();
            let mut seq_no = current.seq_no() / 100 * 100;
            loop {
                let Some(block) = lookup(seq_no)? else {
                    return Ok(StackItem::None);
                };
                centuries.push(Self::id2tuple(&block));
                if centuries.len() == 16 || seq_no < 100 {
                    break;
                }
                seq_no -= 100;
            }
            fields.push(StackItem::tuple(centuries));
        }
        Ok(StackItem::tuple(fields))
    }

    fn get_method_precompiled(&self, code: &Cell) -> Result<Option<rtos_block::PrecompiledSmc>> {
        let Some(param) = self.config_params.config_params.get(45u32.write_to_bitstring()?)? else {
            return Ok(None);
        };
        let Some(cell) = param.reference_opt(0) else {
            return Ok(None);
        };
        let mut slice = SliceData::load_cell(cell)?;
        // The optional parameter and leaf records must decode exactly. Keep
        // dictionary traversal failures distinct from malformed optional records.
        let mut list = rtos_block::HashmapE::with_bit_len(256);
        if slice.get_next_byte().ok() != Some(0xc0)
            || list.read_from(&mut slice).is_err()
            || slice.remaining_bits() != 0
            || slice.remaining_references() != 0
        {
            return Ok(None);
        }
        let Some(mut entry) = list.get(code.repr_hash().write_to_bitstring()?)? else {
            return Ok(None);
        };
        Ok(rtos_block::PrecompiledSmc::construct_from(&mut entry)
            .ok()
            .filter(|_| entry.remaining_bits() == 0 && entry.remaining_references() == 0))
    }

    /// Node getter context follows the lite-server profile. It has no
    /// authenticated message import; from version16 the incoming storage slot
    /// is present and null. Historical tuple lengths remain observable.
    pub fn as_get_method_data_item(&self) -> Result<StackItem> {
        self.as_get_method_data_item_with_code(Some(&self.mycode))
    }

    /// Getter profile with the account's actual optional code root. No-code
    /// accounts must not look up a precompiled entry for an empty-cell hash.
    pub fn as_get_method_data_item_with_code(&self, code: Option<&Cell>) -> Result<StackItem> {
        let version = self.config_params.global_version();
        let mut outer = self.as_temp_data_item().as_tuple_mut()?;
        let mut fields = outer.remove(0).as_tuple_mut()?;
        let length = if version < 4 {
            10
        } else if version < 6 {
            14
        } else if version < 11 {
            17
        } else if version < 16 {
            18
        } else {
            19
        };
        fields.truncate(length);
        if version >= 4 {
            fields[10] = code.map_or(StackItem::None, |cell| StackItem::cell(cell.clone()));
        }
        if version >= 16 {
            // A getter never has authenticated message import statistics,
            // including when this helper is used with a transaction profile.
            fields[18] = StackItem::None;
        }
        if version >= 6 {
            // A configured zero cost is an integer, distinct from no entry.
            let precompiled =
                code.map(|cell| self.get_method_precompiled(cell)).transpose()?.flatten();
            fields[16] = precompiled
                .map(|contract| StackItem::int(contract.gas_usage))
                .unwrap_or(StackItem::None);
        }
        Ok(StackItem::tuple(vec![StackItem::tuple(fields)]))
    }

    pub fn as_temp_data_item(&self) -> StackItem {
        // let config = rtos_block_json::debug_config(&self.config_params).unwrap();
        // std::fs::write("d:\\config.json", config)?;
        // extra read some config params for usage tree
        {
            let _ = self.config_params.config(5);
            let _ = self.config_params.config(9);
            self.config_params
                .suspended_address_list()
                .unwrap_or_default()
                .unwrap_or_default()
                .is_empty();
        }
        let version = self.config_params.global_version();
        let prev_blocks_info = self.get_prev_blocks_info();
        let config_info = self.get_unpacked_config_tuple();
        let msg_info = self.get_message_info();
        let precompiled_gas_usage = if self.precompiled_gas_usage == 0 {
            StackItem::None
        } else {
            StackItem::int(self.precompiled_gas_usage)
        };
        let mut params = vec![
            StackItem::int(0x076ef1ea), // magic - should be changed because of structure change
            StackItem::int(self.actions), // actions
            StackItem::int(self.msgs_sent), // msgs
            StackItem::int(self.unix_time), // unix time
            StackItem::int(self.block_lt), // logical time
            StackItem::int(self.trans_lt), // transaction time
            StackItem::int(self.rand_seed.clone()),
            Self::cc2tuple(&self.balance),
            StackItem::Slice(self.myself.clone()),
            StackItem::dict(self.config_params.root()),
            StackItem::cell(self.mycode.clone()),
            Self::cc2tuple(&self.incoming_value),
            StackItem::int(self.storage_fees_collected),
            prev_blocks_info,
            config_info,
            StackItem::int(self.due_payment),
            precompiled_gas_usage,
        ];
        if version >= 11 {
            params.push(msg_info);
        }
        if version >= 16 {
            params.push(self.incoming_storage_stats.as_ref().map_or(StackItem::None, |stats| {
                StackItem::tuple(vec![
                    StackItem::int(1),
                    StackItem::int(IntegerData::from_unsigned_bytes_be(stats.hash.as_slice())),
                    StackItem::int(stats.cells),
                    StackItem::int(stats.bits),
                ])
            }));
        }
        StackItem::tuple(vec![StackItem::tuple(params)])
    }
}

fn render_stack(items: &[StackItem]) -> String {
    items.iter().map(|item| item.dump_as_fift()).collect::<Vec<_>>().join(" ")
}

fn parse_stack_number(number: &str) -> Result<IntegerData> {
    let (negative, value) =
        if let Some(value) = number.strip_prefix('-') { (true, value) } else { (false, number) };

    let (radix, digits) = if let Some(hex) = value.strip_prefix("0x") {
        (16, hex)
    } else if let Some(hex) = value.strip_prefix("0X") {
        (16, hex)
    } else {
        (10, value)
    };

    // Validate hexadecimal digits explicitly to provide a clearer error on malformed input.
    if radix == 16 && !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        fail!("invalid hexadecimal literal: {number}");
    }
    let literal = if negative { Cow::Owned(format!("-{digits}")) } else { Cow::Borrowed(digits) };
    IntegerData::from_str_radix(&literal, radix)
}

pub fn convert_stack(items: &[StackItem]) -> Result<Vec<StackEntry>> {
    fn convert_item(item: &StackItem) -> Result<StackEntry> {
        let stack_entry = match item {
            StackItem::Integer(value) => {
                let number = value.to_str_hex();
                let number =
                    rtos_api::ton::tvm::numberdecimal::NumberDecimal { number: number.into() }
                        .into_boxed();
                StackEntryNumber { number }.into_boxed()
            }
            StackItem::Slice(slice) => {
                let cell = slice.clone().into_cell()?;
                let bytes = write_boc(&cell)?;
                let slice = rtos_api::ton::tvm::slice::Slice { bytes };
                StackEntrySlice { slice }.into_boxed()
            }
            StackItem::Cell(cell) => {
                let bytes = write_boc(cell)?;
                let cell = rtos_api::ton::tvm::cell::Cell { bytes };
                StackEntryCell { cell }.into_boxed()
            }
            StackItem::None => {
                let list = rtos_api::ton::tvm::list::List { elements: Vec::new() }.into_boxed();
                StackEntryList { list }.into_boxed()
            }
            StackItem::Tuple(elements) => {
                let mut probe = elements;
                let list = loop {
                    if probe.len() == 2 {
                        match probe.last() {
                            Some(StackItem::Tuple(next_tuple)) => probe = next_tuple,
                            Some(StackItem::None) => break true,
                            _ => break false,
                        }
                    } else {
                        break false;
                    }
                };
                if list {
                    let mut tuple = elements;
                    let mut elements = Vec::new();
                    while let Some(item) = tuple.first() {
                        elements.push(convert_item(item)?);
                        let Some(StackItem::Tuple(next_tuple)) = tuple.last() else {
                            break;
                        };
                        tuple = next_tuple;
                    }
                    let list = rtos_api::ton::tvm::list::List { elements }.into_boxed();
                    StackEntryList { list }.into_boxed()
                } else {
                    let elements = convert_stack(elements)?;
                    let tuple = rtos_api::ton::tvm::tuple::Tuple { elements }.into_boxed();
                    StackEntryTuple { tuple }.into_boxed()
                }
            }
            _ => StackEntry::Tvm_StackEntryUnsupported,
        };
        Ok(stack_entry)
    }

    let mut result = Vec::with_capacity(items.len());
    for item in items {
        result.push(convert_item(item)?)
    }
    Ok(result)
}

pub fn convert_ton_stack(items: &[StackEntry]) -> Result<Vec<StackItem>> {
    let mut result = Vec::with_capacity(items.len());
    for item in items {
        let stack_item = match item {
            StackEntry::Tvm_StackEntryCell(cell) => {
                let cell = &cell.cell;
                let cell = read_single_root_boc(&cell.bytes)?;
                StackItem::cell(cell)
            }
            StackEntry::Tvm_StackEntryList(list) => {
                let elements = convert_ton_stack(list.list.elements())?;
                let mut tuple = StackItem::None;
                for elem in elements.into_iter().rev() {
                    tuple = StackItem::tuple(vec![elem, tuple]);
                }
                tuple
            }
            StackEntry::Tvm_StackEntryNumber(number) => {
                let number = &number.number;
                let value = parse_stack_number(number.number().as_str()?)?;
                StackItem::int(value)
            }
            StackEntry::Tvm_StackEntrySlice(slice) => {
                let cell = read_single_root_boc(&slice.slice.bytes)?;
                let slice = SliceData::load_cell(cell)?;
                StackItem::slice(slice)
            }
            StackEntry::Tvm_StackEntryTuple(tuple) => {
                let elements = convert_ton_stack(tuple.tuple.elements())?;
                StackItem::tuple(elements)
            }
            StackEntry::Tvm_StackEntryUnsupported => {
                fail!("Unsupported stack entry encountered")
            }
        };
        result.push(stack_item);
    }
    Ok(result)
}

/// Execute without a block identifier; the current block hashes in history are zero.
/// Node callers with a pinned snapshot should use `run_smc_method_with_block_id`.
pub fn run_smc_method(
    account: &Account,
    mc_state_cell: Cell,
    method_id: u32,
    stack: Vec<StackEntry>,
    gen_utime: u32,
    gen_lt: u64,
) -> Result<SmcMethodResult> {
    run_smc_method_with_rng(
        account,
        mc_state_cell,
        method_id.into(),
        stack,
        gen_utime,
        gen_lt,
        None,
        &mut rand::rngs::OsRng,
    )
}

/// Execute a getter with its pinned masterchain identifier and full signed method ID.
pub fn run_smc_method_with_block_id(
    account: &Account,
    mc_state_cell: Cell,
    mc_block_id: &BlockIdExt,
    method_id: i64,
    stack: Vec<StackEntry>,
    gen_utime: u32,
    gen_lt: u64,
) -> Result<SmcMethodResult> {
    run_smc_method_with_rng(
        account,
        mc_state_cell,
        method_id,
        stack,
        gen_utime,
        gen_lt,
        Some(mc_block_id),
        &mut rand::rngs::OsRng,
    )
}

fn run_smc_method_with_rng<R: rand::RngCore + rand::CryptoRng>(
    account: &Account,
    mc_state_cell: Cell,
    method_id: i64,
    stack: Vec<StackEntry>,
    gen_utime: u32,
    gen_lt: u64,
    mc_block_id: Option<&BlockIdExt>,
    rng: &mut R,
) -> Result<SmcMethodResult> {
    let mut seed = [0u8; 32];
    rng.try_fill_bytes(&mut seed)?;
    run_smc_method_with_seed(
        account,
        mc_state_cell,
        method_id,
        stack,
        gen_utime,
        gen_lt,
        seed,
        mc_block_id,
    )
}

fn run_smc_method_with_seed(
    account: &Account,
    mc_state_cell: Cell,
    method_id: i64,
    stack: Vec<StackEntry>,
    gen_utime: u32,
    gen_lt: u64,
    seed: [u8; 32],
    mc_block_id: Option<&BlockIdExt>,
) -> Result<SmcMethodResult> {
    if !account.is_active() {
        fail!("Getter account is not active");
    }
    let code = account.get_code();
    let data = account.get_data().unwrap_or_default();
    let mc_state = ShardStateUnsplit::construct_from_cell(mc_state_cell.clone())?;
    let current = mc_block_id.cloned().unwrap_or_else(|| {
        BlockIdExt::with_params(
            mc_state.shard().clone(),
            mc_state.seq_no(),
            UInt256::default(),
            UInt256::default(),
        )
    });
    if !mc_state.shard().is_masterchain()
        || current.shard() != mc_state.shard()
        || current.seq_no() != mc_state.seq_no()
    {
        fail!(
            "Getter masterchain block identifier disagrees with snapshot shard or sequence number"
        );
    }
    // The node config entrypoint requires a valid zero-state reference even
    // when this VM version does not expose previous blocks in c7.
    if mc_state.seq_no() != 0 {
        let extra = mc_state.read_custom()?.ok_or_else(|| error!("No custom data in mc_state"))?;
        let mut zero = extra
            .prev_blocks
            .get_as_slice(&0)?
            .ok_or_else(|| error!("Masterchain history has no zero-state reference"))?;
        let entry = KeyExtBlkRef::construct_from(&mut zero)?;
        if entry.blk_ref.seq_no != 0
            || zero.remaining_bits() != 0
            || zero.remaining_references() != 0
        {
            fail!("Masterchain history has an invalid zero-state reference");
        }
    }
    let mut smc_info =
        SmartContractInfo::with_params(Some(account), None, Some(mc_state_cell.clone()))?;
    smc_info.unix_time = gen_utime;
    smc_info.block_lt = gen_lt;
    smc_info.trans_lt = gen_lt;
    smc_info.rand_seed = IntegerData::from_unsigned_bytes_be(&seed);
    smc_info.prev_blocks_info =
        PrevBlocksInfo::Tuple(if smc_info.config_params.global_version() >= 4 {
            SmartContractInfo::get_method_prev_blocks_info(&mc_state, &current)?
        } else {
            StackItem::None
        });

    let mut storage = convert_ton_stack(&stack)?;
    storage.push(StackItem::int(method_id));
    let stack = Stack::with_storage(storage);

    let mut ctrls = SaveList::new();
    ctrls.put(7, smc_info.as_get_method_data_item_with_code(code.as_ref())?)?;
    ctrls.put(4, StackItem::Cell(data))?;

    let gas = Gas::new(1000000, 0, 1000000, 1000000);

    // Global libraries take precedence over the account dictionary. From
    // version 15 the account dictionary is no longer eligible for getters.
    let mut libraries = vec![mc_state.libraries().clone().inner()];
    if smc_info.config_params.global_version() < 15 {
        libraries.push(account.libraries().inner());
    }

    let caps = smc_info.config_params.capabilities();
    let code_present = code.is_some();
    let mut vm = Engine::with_capabilities(caps)
        .setup_with_optional_code(code, ctrls, stack, gas, libraries)?;

    let block_version = smc_info.config_params.get_global_version()?.version;
    vm.set_block_version(block_version);

    let result = vm.execute();
    let mut stack = mem::take(&mut vm.withdraw_stack().storage);
    let exit_code = match result {
        Ok(exit_code) => exit_code,
        Err(err) => {
            stack.pop();
            log::debug!(target: "executor", "VM terminated with full exception: {}", err);
            crate::error::tvm_exception_or_custom_code(&err)
        }
    };
    log::debug!("run_smc_method: exit_code={}\n", exit_code);
    log::debug!("run_smc_method: gas used={}\n", vm.gas_used());
    log::debug!("run_smc_method: result_stack_depth={}\n", stack.len());
    log::debug!("run_smc_method: result_stack dump: [ {} ]\n", render_stack(&stack));

    Ok(SmcMethodResult { exit_code, gas_used: vm.gas_used(), stack, smc_info, code_present })
}

#[cfg(test)]
#[path = "tests/test_smart_contract_info.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/test_get_context.rs"]
mod get_context_tests;

#[cfg(test)]
#[path = "tests/test_get_history_context.rs"]
mod get_history_context_tests;

#[cfg(test)]
#[path = "tests/test_get_method_id.rs"]
mod get_method_id_tests;
