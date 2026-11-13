// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Structural checks of configuration parameters against the block schema.
//!
//! Each function follows the validator generated from the schema for the
//! constructor named next to it. Typed references are visited from an
//! explicit work list, so nesting never grows the call stack; the verdict
//! does not depend on visit order because every check must pass and the
//! visit budget only bounds their total number.

use crate::{Cell, CellType, SliceData, VarUIntegerCodec, VarUIntegerEncoding};
use tlb::AugKind;

#[path = "tlb_schema.rs"]
mod tlb;
pub use tlb::{tlb_type_is_valid, TlbProfile, TlbType};

/// Reference visits allowed when checking one configuration parameter.
pub(crate) const PARAM_VISIT_BUDGET: u32 = 1024;
/// Reference visits allowed when checking the shape of a `ConfigParams` value.
pub(crate) const CONFIG_SHAPE_VISIT_BUDGET: u32 = 10000;

/// Every parameter index the schema defines.
pub const SCHEMA_CONFIG_PARAMS: [u32; 49] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 39, 40, 43, 44, 45, 48, 71, 72, 73, 79, 81, 82, 83,
];

#[derive(Clone, Copy)]
enum Leaf {
    Typed(TlbType, TlbProfile),
    /// `True` or `Unit`: no data.
    Empty,
    /// A fixed-width integer or bit string.
    Bits(usize),
    /// `^Cell`: one reference that is not visited.
    AnyRef,
    VarUInteger32,
    WorkchainDescr,
    StoragePrices,
    ValidatorDescr,
    ValidatorSignedTempKey,
    PrecompiledSmc,
}

#[derive(Clone, Copy)]
enum Node {
    HandwrittenAugHashmap(usize, AugKind),
    CheckAugmentation(usize, AugKind),
    GeneratedAugHashmap(usize, TlbType, TlbType),
    Typed(TlbType, TlbProfile),
    Param(u32),
    ConfigParams,
    ValidatorDescr,
    Hashmap(usize, Leaf),
    ConfigProposalSetup,
    ValidatorTempKey,
    SignedCertificate,
    NewConsensusConfig,
    JettonBridgePrices,
}

struct Walker {
    pending: Vec<(Cell, Node, bool)>,
    weak: bool,
}

/// Checks a referenced parameter value as the schema type of `index`.
pub fn config_param_is_valid(index: u32, cell: Cell) -> bool {
    config_param_is_valid_with_budget(index, cell, PARAM_VISIT_BUDGET)
}

/// The generated parameter validator with an explicit reference-visit budget.
pub fn config_param_is_valid_with_budget(index: u32, cell: Cell, budget: u32) -> bool {
    visit_all(cell, Node::Param(index), budget)
}

/// Structural `ValidatorDescr` validation, independent of consensus policy.
pub fn validator_descr_is_valid_with_budget(cell: Cell, budget: u32) -> bool {
    visit_all(cell, Node::ValidatorDescr, budget)
}

/// Checks a complete `ConfigParams` cell, including its dictionary reference.
pub fn config_params_is_valid_with_budget(cell: Cell, budget: u32) -> bool {
    visit_all(cell, Node::ConfigParams, budget)
}

/// Checks a `Hashmap 32 ^Cell` root as the `config` field of `ConfigParams`;
/// the values are references that are not visited.
pub(crate) fn config_dictionary_shape_is_valid(root: Cell) -> bool {
    config_dictionary_shape_is_valid_with_budget(root, CONFIG_SHAPE_VISIT_BUDGET)
}

/// Checks dictionary structure without following the untyped value references.
pub fn config_dictionary_shape_is_valid_with_budget(root: Cell, budget: u32) -> bool {
    visit_all(root, Node::Hashmap(32, Leaf::AnyRef), budget)
}

fn visit_all(root: Cell, node: Node, budget: u32) -> bool {
    let mut walker = Walker { pending: vec![(root, node, false)], weak: false };
    let mut remaining = budget;
    while let Some((cell, node, weak)) = walker.pending.pop() {
        walker.weak = weak;
        if let Node::CheckAugmentation(n, kind) = node {
            if !tlb::check_augmented_cell(cell, n, kind).unwrap_or(false) {
                return false;
            }
            continue;
        }
        remaining = match remaining.checked_sub(1) {
            Some(value) => value,
            None => return false,
        };
        if weak && cell.cell_type() == CellType::PrunedBranch {
            continue;
        }
        let special = matches!(node, Node::Typed(TlbType::MerkleStateUpdate, _));
        if (cell.cell_type() != CellType::Ordinary) != special {
            return false;
        }
        let Ok(mut slice) = SliceData::load_cell(cell) else {
            return false;
        };
        if !walker.node(node, &mut slice) || !slice.is_empty_cell() {
            return false;
        }
    }
    true
}

fn skip(slice: &mut SliceData, bits: usize) -> bool {
    slice.move_by(bits).is_ok()
}

fn uint(slice: &mut SliceData, bits: usize) -> Option<u64> {
    slice.get_next_int(bits).ok()
}

fn tag(slice: &mut SliceData, bits: usize, value: u64) -> bool {
    uint(slice, bits) == Some(value)
}

/// Width of a `#<= bound` field: the bit length of `bound`.
fn leq_width(bound: usize) -> usize {
    (usize::BITS - bound.leading_zeros()) as usize
}

/// `VarUInteger n`: `len:(#< n) value:(uint (len * 8))`, any encoding length.
fn var_uinteger(slice: &mut SliceData, n: usize) -> bool {
    VarUIntegerCodec::new(n).is_some_and(|codec| codec.skip(slice, VarUIntegerEncoding::Structural))
}

fn tomis(slice: &mut SliceData) -> bool {
    var_uinteger(slice, 16)
}

fn bool_bit(slice: &mut SliceData) -> Option<bool> {
    slice.get_next_bit().ok()
}

/// `HmLabel ~l n`: short, long or same label; noncanonical forms are allowed.
fn hm_label(slice: &mut SliceData, n: usize) -> Option<usize> {
    if !bool_bit(slice)? {
        // hml_short$0 len:(Unary ~n) s:(n * Bit)
        let mut len = 0usize;
        while bool_bit(slice)? {
            len = len.checked_add(1)?;
        }
        if len > n || !skip(slice, len) {
            return None;
        }
        return Some(len);
    }
    let same = bool_bit(slice)?;
    if same {
        // hml_same$11 v:Bit n:(#<= m)
        bool_bit(slice)?;
    }
    let len = usize::try_from(uint(slice, leq_width(n))?).ok()?;
    if len > n {
        return None;
    }
    if !same && !skip(slice, len) {
        return None;
    }
    Some(len)
}

fn sig_pub_key(slice: &mut SliceData) -> bool {
    tag(slice, 32, 0x8e81278a) && skip(slice, 256)
}

fn crypto_signature_simple(slice: &mut SliceData) -> bool {
    tag(slice, 4, 5) && skip(slice, 512)
}

fn param_limits(slice: &mut SliceData) -> bool {
    if !tag(slice, 8, 0xc3) {
        return false;
    }
    let (Some(underload), Some(soft)) = (uint(slice, 32), uint(slice, 32)) else {
        return false;
    };
    if underload > soft {
        return false;
    }
    matches!(uint(slice, 32), Some(hard) if soft <= hard)
}

fn at_least_one(slice: &mut SliceData, bits: usize) -> bool {
    matches!(uint(slice, bits), Some(value) if value >= 1)
}

fn zero(slice: &mut SliceData, bits: usize) -> bool {
    uint(slice, bits) == Some(0)
}

impl Walker {
    fn push_ref(&mut self, slice: &mut SliceData, node: Node) -> bool {
        match slice.checked_drain_reference() {
            Ok(cell) => {
                self.pending.push((cell, node, self.weak));
                true
            }
            Err(_) => false,
        }
    }

    /// `Hashmap n X` stored in the current slice.
    fn hashmap(&mut self, slice: &mut SliceData, n: usize, leaf: Leaf) -> bool {
        let Some(len) = hm_label(slice, n) else {
            return false;
        };
        match n.checked_sub(len) {
            Some(0) => self.leaf(slice, leaf),
            Some(rest) => match rest.checked_sub(1) {
                Some(child) => {
                    self.push_ref(slice, Node::Hashmap(child, leaf))
                        && self.push_ref(slice, Node::Hashmap(child, leaf))
                }
                None => false,
            },
            None => false,
        }
    }

    /// `HashmapE n X`: hme_empty$0 or hme_root$1 root:^(Hashmap n X).
    fn hashmap_e(&mut self, slice: &mut SliceData, n: usize, leaf: Leaf) -> bool {
        match bool_bit(slice) {
            Some(false) => true,
            Some(true) => self.push_ref(slice, Node::Hashmap(n, leaf)),
            None => false,
        }
    }

    fn maybe_ref(&mut self, slice: &mut SliceData, node: Node) -> bool {
        match bool_bit(slice) {
            Some(false) => true,
            Some(true) => self.push_ref(slice, node),
            None => false,
        }
    }

    fn leaf(&mut self, slice: &mut SliceData, leaf: Leaf) -> bool {
        match leaf {
            Leaf::Typed(kind, profile) => self.typed(kind, profile, slice),
            Leaf::Empty => true,
            Leaf::Bits(bits) => skip(slice, bits),
            Leaf::AnyRef => slice.checked_drain_reference().is_ok(),
            Leaf::VarUInteger32 => var_uinteger(slice, 32),
            Leaf::WorkchainDescr => workchain_descr(slice),
            // _#cc utime_since:uint32 bit_price_ps:uint64 cell_price_ps:uint64
            //   mc_bit_price_ps:uint64 mc_cell_price_ps:uint64 = StoragePrices
            Leaf::StoragePrices => tag(slice, 8, 0xcc) && skip(slice, 288),
            Leaf::ValidatorDescr => validator_descr(slice),
            // signed_temp_key#4 key:^ValidatorTempKey signature:CryptoSignature
            Leaf::ValidatorSignedTempKey => {
                tag(slice, 4, 4)
                    && self.push_ref(slice, Node::ValidatorTempKey)
                    && self.crypto_signature(slice)
            }
            // precompiled_smc#b0 gas_usage:uint64
            Leaf::PrecompiledSmc => tag(slice, 8, 0xb0) && skip(slice, 64),
        }
    }

    /// `CryptoSignature`: a simple signature (#5) or chained_signature#f
    /// signed_cert:^SignedCertificate temp_key_signature:CryptoSignatureSimple.
    fn crypto_signature(&mut self, slice: &mut SliceData) -> bool {
        match slice.get_int(4).ok() {
            Some(5) => crypto_signature_simple(slice),
            Some(15) => {
                skip(slice, 4)
                    && self.push_ref(slice, Node::SignedCertificate)
                    && crypto_signature_simple(slice)
            }
            _ => false,
        }
    }

    fn node(&mut self, node: Node, slice: &mut SliceData) -> bool {
        match node {
            Node::HandwrittenAugHashmap(n, kind) => self.handwritten_aug_hashmap(slice, n, kind),
            Node::CheckAugmentation(..) => unreachable!("augmentation checks are post-order tasks"),
            Node::GeneratedAugHashmap(n, value, extra) => {
                self.generated_aug_hashmap(slice, n, value, extra)
            }
            Node::Typed(kind, profile) => self.typed(kind, profile, slice),
            Node::Param(index) => self.param(index, slice),
            Node::ConfigParams => {
                skip(slice, 256) && self.push_ref(slice, Node::Hashmap(32, Leaf::AnyRef))
            }
            Node::ValidatorDescr => validator_descr(slice),
            Node::Hashmap(n, leaf) => self.hashmap(slice, n, leaf),
            // cfg_vote_cfg#36 min_tot_rounds:(## 8) max_tot_rounds:(## 8)
            //   { min_tot_rounds <= max_tot_rounds } min_wins:uint8 max_losses:uint8
            //   min_store_sec:(## 32) max_store_sec:(## 32) { min_store_sec <= max_store_sec }
            //   bit_price:uint32 cell_price:uint32
            Node::ConfigProposalSetup => {
                if !tag(slice, 8, 0x36) {
                    return false;
                }
                let (Some(min_rounds), Some(max_rounds)) = (uint(slice, 8), uint(slice, 8)) else {
                    return false;
                };
                if min_rounds > max_rounds || !skip(slice, 16) {
                    return false;
                }
                let (Some(min_store), Some(max_store)) = (uint(slice, 32), uint(slice, 32)) else {
                    return false;
                };
                min_store <= max_store && skip(slice, 64)
            }
            // validator_temp_key#3 adnl_addr:bits256 temp_public_key:SigPubKey seqno:#
            //   valid_until:uint32
            Node::ValidatorTempKey => {
                tag(slice, 4, 3) && skip(slice, 256) && sig_pub_key(slice) && skip(slice, 64)
            }
            // signed_certificate$_ certificate:Certificate certificate_signature:CryptoSignature,
            // certificate#4 temp_key:SigPubKey valid_since:uint32 valid_until:uint32
            Node::SignedCertificate => {
                tag(slice, 4, 4)
                    && sig_pub_key(slice)
                    && skip(slice, 64)
                    && self.crypto_signature(slice)
            }
            Node::NewConsensusConfig => self.new_consensus_config(slice),
            // jetton_bridge_prices#_ six Coins fields
            Node::JettonBridgePrices => (0..6).all(|_| tomis(slice)),
        }
    }

    // simplex_config#21 flags:(## 7) use_quic:Bool target_rate_ms:uint32
    //   slots_per_leader_window:(## 32) { slots_per_leader_window >= 1 }
    //   first_block_timeout_ms:uint32 max_leader_window_desync:uint32
    // simplex_config_v2#22 flags:(## 5) protocol_version:(## 2) use_quic:Bool
    //   slots_per_leader_window:(## 32) { slots_per_leader_window >= 1 }
    //   noncritical_params:(HashmapE 8 uint32)
    fn new_consensus_config(&mut self, slice: &mut SliceData) -> bool {
        match uint(slice, 8) {
            Some(0x21) => skip(slice, 40) && at_least_one(slice, 32) && skip(slice, 64),
            Some(0x22) => {
                skip(slice, 8)
                    && at_least_one(slice, 32)
                    && self.hashmap_e(slice, 8, Leaf::Bits(32))
            }
            _ => false,
        }
    }

    // validators#11 utime_since:uint32 utime_until:uint32 total:(## 16) main:(## 16)
    //   { main <= total } { main >= 1 } list:(Hashmap 16 ValidatorDescr)
    // validators_ext#12 ... total_weight:uint64 list:(HashmapE 16 ValidatorDescr)
    fn validator_set(&mut self, slice: &mut SliceData) -> bool {
        let extended = match uint(slice, 8) {
            Some(0x11) => false,
            Some(0x12) => true,
            _ => return false,
        };
        if !skip(slice, 64) {
            return false;
        }
        let (Some(total), Some(main)) = (uint(slice, 16), uint(slice, 16)) else {
            return false;
        };
        if main > total || main < 1 {
            return false;
        }
        if extended {
            skip(slice, 64) && self.hashmap_e(slice, 16, Leaf::ValidatorDescr)
        } else {
            self.hashmap(slice, 16, Leaf::ValidatorDescr)
        }
    }

    // jetton_bridge_params_v0#00 bridge_address:bits256 oracles_address:bits256
    //   oracles:(HashmapE 256 uint256) state_flags:uint8 burn_bridge_fee:Coins
    // jetton_bridge_params_v1#01 bridge_address:bits256 oracles_address:bits256
    //   oracles:(HashmapE 256 uint256) state_flags:uint8 prices:^JettonBridgePrices
    //   external_chain_address:bits256
    fn jetton_bridge_params(&mut self, slice: &mut SliceData) -> bool {
        match uint(slice, 8) {
            Some(0) => {
                skip(slice, 512)
                    && self.hashmap_e(slice, 256, Leaf::Bits(256))
                    && skip(slice, 8)
                    && tomis(slice)
            }
            Some(1) => {
                skip(slice, 512)
                    && self.hashmap_e(slice, 256, Leaf::Bits(256))
                    && skip(slice, 8)
                    && self.push_ref(slice, Node::JettonBridgePrices)
                    && skip(slice, 256)
            }
            _ => false,
        }
    }

    fn param(&mut self, index: u32, slice: &mut SliceData) -> bool {
        match index {
            // config_addr, elector_addr, minter_addr, fee_collector_addr, dns_root_addr: bits256
            0..=4 => skip(slice, 256),
            // burning_config#01 blackhole_addr:(Maybe bits256) fee_burn_num:#
            //   fee_burn_denom:# { fee_burn_num <= fee_burn_denom } { fee_burn_denom >= 1 }
            5 => {
                if !tag(slice, 8, 1) {
                    return false;
                }
                match bool_bit(slice) {
                    Some(true) if !skip(slice, 256) => return false,
                    None => return false,
                    _ => {}
                }
                let (Some(num), Some(denom)) = (uint(slice, 32), uint(slice, 32)) else {
                    return false;
                };
                num <= denom && denom >= 1
            }
            // mint_new_price:Tomis mint_add_price:Tomis
            6 => tomis(slice) && tomis(slice),
            // to_mint:ExtraCurrencyCollection = HashmapE 32 (VarUInteger 32)
            7 => self.hashmap_e(slice, 32, Leaf::VarUInteger32),
            // capabilities#c4 version:uint32 capabilities:uint64
            8 => tag(slice, 8, 0xc4) && skip(slice, 96),
            // mandatory_params / critical_params: (Hashmap 32 True)
            9 | 10 => self.hashmap(slice, 32, Leaf::Empty),
            // cfg_vote_setup#91 normal_params:^ConfigProposalSetup
            //   critical_params:^ConfigProposalSetup
            11 => {
                tag(slice, 8, 0x91)
                    && self.push_ref(slice, Node::ConfigProposalSetup)
                    && self.push_ref(slice, Node::ConfigProposalSetup)
            }
            // workchains:(HashmapE 32 WorkchainDescr)
            12 => self.hashmap_e(slice, 32, Leaf::WorkchainDescr),
            // complaint_prices#1a deposit:Tomis bit_price:Tomis cell_price:Tomis
            13 => tag(slice, 8, 0x1a) && tomis(slice) && tomis(slice) && tomis(slice),
            // block_tomis_created#6b masterchain_block_fee:Tomis basechain_block_fee:Tomis
            14 => tag(slice, 8, 0x6b) && tomis(slice) && tomis(slice),
            // four uint32 election timings
            15 => skip(slice, 128),
            // max_validators:(## 16) max_main_validators:(## 16) min_validators:(## 16)
            //   { max_validators >= max_main_validators }
            //   { max_main_validators >= min_validators } { min_validators >= 1 }
            16 => {
                let (Some(max), Some(max_main), Some(min)) =
                    (uint(slice, 16), uint(slice, 16), uint(slice, 16))
                else {
                    return false;
                };
                max_main <= max && min <= max_main && min >= 1
            }
            // min_stake:Tomis max_stake:Tomis min_total_stake:Tomis max_stake_factor:uint32
            17 => tomis(slice) && tomis(slice) && tomis(slice) && skip(slice, 32),
            // (Hashmap 32 StoragePrices)
            18 => self.hashmap(slice, 32, Leaf::StoragePrices),
            // global_id:int32
            19 => skip(slice, 32),
            20 | 21 => gas_limits_prices(slice),
            22 | 23 => block_limits(slice),
            // msg_forward_prices#ea lump_price:uint64 bit_price:uint64 cell_price:uint64
            //   ihr_price_factor:uint32 first_frac:uint16 next_frac:uint16
            24 | 25 => tag(slice, 8, 0xea) && skip(slice, 256),
            28 => catchain_config(slice),
            29 => consensus_config(slice),
            // new_consensus_config_all#10 mc:(Maybe ^NewConsensusConfig)
            //   shard:(Maybe ^NewConsensusConfig)
            30 => {
                tag(slice, 8, 0x10)
                    && self.maybe_ref(slice, Node::NewConsensusConfig)
                    && self.maybe_ref(slice, Node::NewConsensusConfig)
            }
            // fundamental_smc_addr:(HashmapE 256 True)
            31 => self.hashmap_e(slice, 256, Leaf::Empty),
            32..=37 => self.validator_set(slice),
            // (HashmapE 256 ValidatorSignedTempKey)
            39 => self.hashmap_e(slice, 256, Leaf::ValidatorSignedTempKey),
            // misbehaviour_punishment_config_v1#01 default_flat_fine:Tomis followed by
            // 176 bits of uint32/uint16 fields
            40 => tag(slice, 8, 1) && tomis(slice) && skip(slice, 176),
            43 => size_limits_config(slice),
            // suspended_address_list#00 addresses:(HashmapE 288 Unit) suspended_until:uint32
            44 => tag(slice, 8, 0) && self.hashmap_e(slice, 288, Leaf::Empty) && skip(slice, 32),
            // precompiled_contracts_config#c0 list:(HashmapE 256 PrecompiledSmc)
            45 => tag(slice, 8, 0xc0) && self.hashmap_e(slice, 256, Leaf::PrecompiledSmc),
            // auth_policy_v1#a1 network_tag:bits256 policy_sequence:uint64 retired:uint16
            //   retire_at:(HashmapE 8 uint32) policy_spec_hash:bits256
            48 => {
                tag(slice, 8, 0xa1)
                    && skip(slice, 336)
                    && self.hashmap_e(slice, 8, Leaf::Bits(32))
                    && skip(slice, 256)
            }
            // oracle_bridge_params#_ bridge_address:bits256 oracle_mutlisig_address:bits256
            //   oracles:(HashmapE 256 uint256) external_chain_address:bits256
            71..=73 => {
                skip(slice, 512) && self.hashmap_e(slice, 256, Leaf::Bits(256)) && skip(slice, 256)
            }
            79 | 81 | 82 | 83 => self.jetton_bridge_params(slice),
            _ => false,
        }
    }
}

// workchain#a6 / workchain_v2#a7 enabled_since:uint32 monitor_min_split:(## 8)
//   min_split:(## 8) max_split:(## 8) { monitor_min_split <= min_split }
//   { min_split <= max_split } { max_split <= 60 } basic:(## 1) active:Bool
//   accept_msgs:Bool flags:(## 13) { flags = 0 } zerostate_root_hash:bits256
//   zerostate_file_hash:bits256 version:uint32 format:(WorkchainFormat basic)
//   [v2: split_merge_timings:WcSplitMergeTimings persistent_state_split_depth:(## 8)
//   { persistent_state_split_depth <= 63 }]
fn workchain_descr(slice: &mut SliceData) -> bool {
    let v2 = match uint(slice, 8) {
        Some(0xa6) => false,
        Some(0xa7) => true,
        _ => return false,
    };
    if !skip(slice, 32) {
        return false;
    }
    let (Some(monitor), Some(min), Some(max)) = (uint(slice, 8), uint(slice, 8), uint(slice, 8))
    else {
        return false;
    };
    if monitor > min || min > max || max > 60 {
        return false;
    }
    let Some(basic) = bool_bit(slice) else {
        return false;
    };
    if !skip(slice, 2) || !zero(slice, 13) || !skip(slice, 544) || !workchain_format(slice, basic) {
        return false;
    }
    if !v2 {
        return true;
    }
    // wc_split_merge_timings#0 four uint32
    zero(slice, 4) && skip(slice, 128) && matches!(uint(slice, 8), Some(depth) if depth <= 63)
}

// wfmt_basic#1 vm_version:int32 vm_mode:uint64 = WorkchainFormat 1
// wfmt_ext#0 min_addr_len:(## 12) max_addr_len:(## 12) addr_len_step:(## 12)
//   { min_addr_len >= 64 } { min_addr_len <= max_addr_len } { max_addr_len <= 1023 }
//   { addr_len_step <= 1023 } workchain_type_id:(## 32) { workchain_type_id >= 1 }
//   = WorkchainFormat 0
fn workchain_format(slice: &mut SliceData, basic: bool) -> bool {
    match uint(slice, 4) {
        Some(1) => basic && skip(slice, 96),
        Some(0) => {
            let (Some(min), Some(max), Some(step)) =
                (uint(slice, 12), uint(slice, 12), uint(slice, 12))
            else {
                return false;
            };
            min >= 64
                && min <= max
                && max <= 1023
                && step <= 1023
                && at_least_one(slice, 32)
                && !basic
        }
        _ => false,
    }
}

// gas_prices#dd (384 bits), gas_prices_ext#de (448 bits),
// gas_flat_pfx#d1 flat_gas_limit:uint64 flat_gas_price:uint64 other:GasLimitsPrices
fn gas_limits_prices(slice: &mut SliceData) -> bool {
    loop {
        match uint(slice, 8) {
            Some(0xdd) => return skip(slice, 384),
            Some(0xde) => return skip(slice, 448),
            Some(0xd1) => {
                if !skip(slice, 128) {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

// block_limits#5d bytes:ParamLimits gas:ParamLimits lt_delta:ParamLimits
// block_limits_v2#5e bytes gas lt_delta collated_data:ParamLimits
//   imported_msg_queue:ImportedMsgQueueLimits (imported_msg_queue_limits#d3 two #)
fn block_limits(slice: &mut SliceData) -> bool {
    match uint(slice, 8) {
        Some(0x5d) => (0..3).all(|_| param_limits(slice)),
        Some(0x5e) => (0..4).all(|_| param_limits(slice)) && tag(slice, 8, 0xd3) && skip(slice, 64),
        _ => false,
    }
}

// catchain_config#c1 four (## 32) fields, each >= 1
// catchain_config_new#c2 flags:(## 7) { flags = 0 } shuffle_mc_validators:Bool
//   followed by the same four fields
fn catchain_config(slice: &mut SliceData) -> bool {
    match uint(slice, 8) {
        Some(0xc1) => (0..4).all(|_| at_least_one(slice, 32)),
        Some(0xc2) => zero(slice, 7) && skip(slice, 1) && (0..4).all(|_| at_least_one(slice, 32)),
        _ => false,
    }
}

// consensus_config#d6 round_candidates:# { round_candidates >= 1 } then 224 bits
// consensus_config_new#d7 flags:(## 7) { flags = 0 } new_catchain_ids:Bool
//   round_candidates:(## 8) { round_candidates >= 1 } then 224 bits
// consensus_config_v3#d8 as #d7 then 240 bits
// consensus_config_v4#d9 flags:(## 6) { flags = 0 } use_quic:Bool new_catchain_ids:Bool
//   round_candidates:(## 8) { round_candidates >= 1 } then 272 bits
fn consensus_config(slice: &mut SliceData) -> bool {
    match uint(slice, 8) {
        Some(0xd6) => at_least_one(slice, 32) && skip(slice, 224),
        Some(0xd7) => {
            zero(slice, 7) && skip(slice, 1) && at_least_one(slice, 8) && skip(slice, 224)
        }
        Some(0xd8) => {
            zero(slice, 7) && skip(slice, 1) && at_least_one(slice, 8) && skip(slice, 240)
        }
        Some(0xd9) => {
            zero(slice, 6) && skip(slice, 2) && at_least_one(slice, 8) && skip(slice, 272)
        }
        _ => false,
    }
}

// size_limits_config#01 (160 bits), size_limits_config_v2#02 (360 bits),
// size_limits_config_v3#03 360 bits, max_transaction_library_loads:(Maybe uint32),
//   max_total_msg_bits:uint32 max_total_msg_cells:uint32
//   out_msg_queue_size_hard_limit:uint32 out_msg_queue_size_soft_limit:uint32
fn size_limits_config(slice: &mut SliceData) -> bool {
    match uint(slice, 8) {
        Some(1) => skip(slice, 160),
        Some(2) => skip(slice, 360),
        Some(3) => {
            if !skip(slice, 360) {
                return false;
            }
            match bool_bit(slice) {
                Some(true) if !skip(slice, 32) => return false,
                None => return false,
                _ => {}
            }
            skip(slice, 128)
        }
        _ => false,
    }
}

// validator#53 public_key:SigPubKey weight:uint64
// validator_addr#73 public_key:SigPubKey weight:uint64 adnl_addr:bits256
// validator_pq#b3 validator_id:bits256 algorithm_id:uint16 key_id:bits256
//   public_key:^Cell weight:uint64 adnl_addr:bits256 (the key cell is not visited)
fn validator_descr(slice: &mut SliceData) -> bool {
    match uint(slice, 8) {
        Some(0x53) => sig_pub_key(slice) && skip(slice, 64),
        Some(0x73) => sig_pub_key(slice) && skip(slice, 320),
        Some(0xb3) => skip(slice, 848) && slice.checked_drain_reference().is_ok(),
        _ => false,
    }
}

/// One leaf of a dictionary walk: the key and the value slice after the label.
pub(crate) type DictionaryLeaf = (u64, SliceData);

/// Walks a dictionary with keys of `key_bits <= 64` bits the way the
/// reference dictionary traversal does: labels may be noncanonical, a fork
/// holds exactly its label and two references, and any special cell or
/// malformed node fails the walk. Leaves are returned in key order.
pub(crate) fn dictionary_leaves(root: Cell, key_bits: usize) -> Option<Vec<DictionaryLeaf>> {
    if key_bits > 64 {
        return None;
    }
    let mut leaves = Vec::new();
    // (cell, key prefix, remaining key bits)
    let mut pending = vec![(root, 0u64, key_bits)];
    while let Some((cell, prefix, remaining)) = pending.pop() {
        if cell.cell_type() != CellType::Ordinary {
            return None;
        }
        let mut slice = SliceData::load_cell(cell).ok()?;
        let (len, bits) = dictionary_label(&mut slice, remaining)?;
        let prefix = shift_in(prefix, len, bits)?;
        let rest = remaining.checked_sub(len)?;
        if rest == 0 {
            leaves.push((prefix, slice));
            continue;
        }
        if slice.remaining_bits() != 0 || slice.remaining_references() != 2 {
            return None;
        }
        let child = rest.checked_sub(1)?;
        let left = slice.reference(0).ok()?;
        let right = slice.reference(1).ok()?;
        // Push the right branch first so leaves come out in key order.
        pending.push((right, shift_in(prefix, 1, 1)?, child));
        pending.push((left, shift_in(prefix, 1, 0)?, child));
    }
    Some(leaves)
}

fn shift_in(prefix: u64, len: usize, bits: u64) -> Option<u64> {
    if len == 0 {
        return Some(prefix);
    }
    let shifted = if len >= 64 { 0 } else { prefix.checked_shl(u32::try_from(len).ok()?)? };
    Some(shifted | bits)
}

/// Parses a dictionary node label of at most `max` bits; returns its length
/// and its bits as an integer (`max <= 64`).
fn dictionary_label(slice: &mut SliceData, max: usize) -> Option<(usize, u64)> {
    let kind = slice.get_int(2).ok()?;
    match kind {
        0 => {
            skip(slice, 2).then_some(())?;
            Some((0, 0))
        }
        1 => {
            skip(slice, 1).then_some(())?;
            let mut len = 0usize;
            while slice.get_bit_opt(len) == Some(true) {
                len = len.checked_add(1)?;
            }
            if len > max || slice.remaining_bits() < len.checked_mul(2)?.checked_add(1)? {
                return None;
            }
            skip(slice, len.checked_add(1)?).then_some(())?;
            Some((len, uint(slice, len)?))
        }
        2 => {
            skip(slice, 2).then_some(())?;
            let len = usize::try_from(uint(slice, leq_width(max))?).ok()?;
            if len > max {
                return None;
            }
            Some((len, uint(slice, len)?))
        }
        _ => {
            if slice.remaining_bits() < leq_width(max).checked_add(3)? {
                return None;
            }
            skip(slice, 2).then_some(())?;
            let bit = bool_bit(slice)?;
            let len = usize::try_from(uint(slice, leq_width(max))?).ok()?;
            if len > max {
                return None;
            }
            let bits = match (bit, len) {
                (false, _) | (true, 0) => 0,
                (true, 64..) => u64::MAX,
                (true, len) => 1u64.checked_shl(u32::try_from(len).ok()?)?.checked_sub(1)?,
            };
            Some((len, bits))
        }
    }
}
