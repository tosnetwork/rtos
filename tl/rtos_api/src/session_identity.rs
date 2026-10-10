// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// RTOS Rust adaptation of the fixed reference session commitment rules.
//! Canonical session commitments. Derivation alone does not authenticate a state
//! or admit its members; callers must establish the governing state separately.
use crate::{ton, IntoBoxed};
use rtos_block::{Cell, Result, ShardIdent, UInt256, ValidatorDescr, ValidatorKey};

pub fn session_config_hash(global_id: i32, options_hash: &UInt256, selected: &Cell) -> UInt256 {
    let mut bytes = b"TOS-VALIDATOR-SESSION-CONFIG-v1".to_vec();
    bytes.extend_from_slice(&global_id.to_le_bytes());
    bytes.extend_from_slice(options_hash.as_slice());
    bytes.extend_from_slice(selected.repr_hash().as_slice());
    UInt256::calc_file_hash(&bytes)
}

/// Structural conversion, including unadmitted descriptors for diagnostics.
/// Live consensus must validate its complete governing set before this call.
pub fn session_members(
    validators: &[ValidatorDescr],
) -> Result<Vec<ton::engine::validator::GroupMember>> {
    use ton::engine::validator::validator::groupmember::{GroupMember, GroupMemberPQ};
    validators
        .iter()
        .map(|v| {
            let weight = i64::try_from(v.weight)?;
            let adnl = v.adnl_addr.clone().unwrap_or_default();
            Ok(match &v.key {
                ValidatorKey::Ed25519(_) => {
                    GroupMember { public_key_hash: v.validator_id()?, adnl, weight }.into_boxed()
                }
                ValidatorKey::Pq(key) => GroupMemberPQ {
                    validator_id: v.validator_id()?,
                    key_id: key.key_id.clone(),
                    adnl,
                    weight,
                }
                .into_boxed(),
            })
        })
        .collect()
}

#[derive(Clone, Copy)]
pub struct SessionCoordinates<'a> {
    pub shard: &'a ShardIdent,
    pub catchain_seqno: u32,
    pub vertical_seqno: u32,
    pub last_key_block_seqno: u32,
    pub new_catchain_ids: bool,
}

/// TL int/long fields carry unsigned protocol coordinates as their exact bit pattern.
pub fn session_group_bytes(
    coordinates: SessionCoordinates<'_>,
    config_hash: &UInt256,
    validators: &[ValidatorDescr],
) -> Result<Vec<u8>> {
    use ton::validator::group::{Group, GroupEx, GroupNew};
    let members = session_members(validators)?;
    let workchain = coordinates.shard.workchain_id();
    let shard = coordinates.shard.shard_prefix_with_tag() as i64;
    let catchain_seqno = coordinates.catchain_seqno as i32;
    let vertical_seqno = coordinates.vertical_seqno as i32;
    let config_hash = config_hash.clone();
    let group = if coordinates.new_catchain_ids {
        GroupNew {
            workchain,
            shard,
            vertical_seqno,
            last_key_block_seqno: coordinates.last_key_block_seqno as i32,
            catchain_seqno,
            config_hash,
            members,
        }
        .into_boxed()
    } else if coordinates.vertical_seqno == 0 {
        Group { workchain, shard, catchain_seqno, config_hash, members }.into_boxed()
    } else {
        GroupEx { workchain, shard, vertical_seqno, catchain_seqno, config_hash, members }
            .into_boxed()
    };
    crate::serialize_boxed(&group)
}

#[derive(Debug, PartialEq, Eq)]
pub struct SessionIdentity {
    pub config_hash: UInt256,
    pub session_id: UInt256,
}

pub fn derive_session_identity(
    global_id: i32,
    options_hash: &UInt256,
    selected_simplex_cell: &Cell,
    coordinates: SessionCoordinates<'_>,
    validators: &[ValidatorDescr],
) -> Result<SessionIdentity> {
    let config_hash = session_config_hash(global_id, options_hash, selected_simplex_cell);
    let bytes = session_group_bytes(coordinates, &config_hash, validators)?;
    Ok(SessionIdentity { config_hash, session_id: UInt256::calc_file_hash(&bytes) })
}

/// Canonical Param29 options encoding. Runtime overrides and block height never
/// enter this commitment. Unsigned TL words retain their full bit pattern.
pub fn session_options_bytes(
    config: &rtos_block::ConsensusConfig,
    catchain: &rtos_block::CatchainConfig,
) -> Result<Vec<u8>> {
    use ton::validator_session::config::{Config, ConfigNew, ConfigVersioned, ConfigVersionedV2};
    let opts = match config.proto_version {
        0 if !config.new_catchain_ids => Config {
            catchain_idle_timeout: (f64::from(config.consensus_timeout_ms) * 0.001).into(),
            catchain_max_deps: config.catchain_max_deps as i32,
            round_candidates: config.round_candidates as i32,
            next_candidate_delay: (f64::from(config.next_candidate_delay_ms) * 0.001).into(),
            round_attempt_duration: config.attempt_duration as i32,
            max_round_attempts: config.fast_attempts as i32,
            max_block_size: config.max_block_bytes as i32,
            max_collated_data_size: config.max_collated_bytes as i32,
        }
        .into_boxed(),
        0 => ConfigNew {
            catchain_idle_timeout: (f64::from(config.consensus_timeout_ms) * 0.001).into(),
            catchain_max_deps: config.catchain_max_deps as i32,
            round_candidates: config.round_candidates as i32,
            next_candidate_delay: (f64::from(config.next_candidate_delay_ms) * 0.001).into(),
            round_attempt_duration: config.attempt_duration as i32,
            max_round_attempts: config.fast_attempts as i32,
            max_block_size: config.max_block_bytes as i32,
            max_collated_data_size: config.max_collated_bytes as i32,
            new_catchain_ids: config.new_catchain_ids.into(),
        }
        .into_boxed(),
        1 => ConfigVersioned {
            catchain_idle_timeout: (f64::from(config.consensus_timeout_ms) * 0.001).into(),
            catchain_max_deps: config.catchain_max_deps as i32,
            round_candidates: config.round_candidates as i32,
            next_candidate_delay: (f64::from(config.next_candidate_delay_ms) * 0.001).into(),
            round_attempt_duration: config.attempt_duration as i32,
            max_round_attempts: config.fast_attempts as i32,
            max_block_size: config.max_block_bytes as i32,
            max_collated_data_size: config.max_collated_bytes as i32,
            version: config.proto_version as i32,
        }
        .into_boxed(),
        _ => ConfigVersionedV2 {
            catchain_opts: ton::validator_session::catchainoptions::CatchainOptions {
                idle_timeout: (f64::from(config.consensus_timeout_ms) * 0.001).into(),
                max_deps: config.catchain_max_deps as i32,
                max_block_size: 16 * 1024,
                block_hash_covers_data: true.into(),
                // The reference stores the low uint32 word of this uint64 product.
                max_block_height_ceoff: (u64::from(config.catchain_max_blocks_coeff)
                    * u64::from(
                        catchain.mc_catchain_lifetime.max(catchain.shard_catchain_lifetime),
                    )) as u32 as i32,
                debug_disable_db: false.into(),
            }
            .into_boxed(),
            round_candidates: config.round_candidates as i32,
            next_candidate_delay: (f64::from(config.next_candidate_delay_ms) * 0.001).into(),
            round_attempt_duration: config.attempt_duration as i32,
            max_round_attempts: config.fast_attempts as i32,
            max_block_size: config.max_block_bytes as i32,
            max_collated_data_size: config.max_collated_bytes as i32,
            version: config.proto_version as i32,
        }
        .into_boxed(),
    };
    crate::serialize_boxed(&opts)
}

/// Use the governing state's intrinsic global ID and exact selected Param30 cell.
/// ConfigParams must come from an authenticated state, not a peer's JSON claim.
pub fn derive_session_from_config(
    global_id: i32,
    config: &rtos_block::ConfigParams,
    mut coordinates: SessionCoordinates<'_>,
    validators: &[ValidatorDescr],
) -> Result<SessionIdentity> {
    use rtos_block::{error, ConfigParamEnum};
    rtos_block::validate_validator_list(validators)?;
    let consensus = match config.config(29)? {
        Some(ConfigParamEnum::ConfigParam29(value)) => value,
        _ => return Err(error!("governing Param29 is missing")),
    };
    let catchain = match config.config(28)? {
        Some(ConfigParamEnum::ConfigParam28(value)) => value,
        _ => return Err(error!("governing Param28 is missing")),
    };
    let selected = config
        .selected_simplex_config(coordinates.shard.is_masterchain())?
        .ok_or_else(|| error!("selected governing Param30 is missing"))?;
    selected.config.validate_protocol_version()?;
    coordinates.new_catchain_ids = consensus.new_catchain_ids;
    let options_hash = UInt256::calc_file_hash(&session_options_bytes(&consensus, &catchain)?);
    derive_session_identity(global_id, &options_hash, selected.cell(), coordinates, validators)
}

/// Strict, bounded decoding for tooling that consumes a serialized session group.
/// This validates shape, not consensus authority.
pub fn decode_session_group(bytes: &[u8]) -> Result<ton::validator::Group> {
    use crate::Constructor;
    use rtos_block::{error, fail};
    use ton::validator::group::{Group, GroupEx, GroupNew};
    let constructor = u32::from_le_bytes(
        bytes.get(..4).ok_or_else(|| error!("truncated session group"))?.try_into()?,
    );
    let count_offset = if constructor == Group::constructor_const() {
        52
    } else if constructor == GroupEx::constructor_const() {
        56
    } else if constructor == GroupNew::constructor_const() {
        60
    } else {
        fail!("unknown session group constructor");
    };
    let count = u32::from_le_bytes(
        bytes
            .get(count_offset..count_offset + 4)
            .ok_or_else(|| error!("truncated session group header"))?
            .try_into()?,
    );
    if count > u16::MAX as u32 || bytes.len() > 64 + 108 * u16::MAX as usize {
        fail!("session group exceeds the validator limit");
    }
    let mut remaining = bytes;
    let group = crate::Deserializer::new(&mut remaining).read_boxed::<ton::validator::Group>()?;
    if !remaining.is_empty() {
        fail!("session group has trailing bytes");
    }
    Ok(group)
}
