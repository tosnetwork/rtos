// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// RTOS Rust adaptation of the fixed reference session commitment rules.
//! Canonical session commitments. Derivation alone does not authenticate a state
//! or admit its members; callers must establish the governing state separately.
use crate::{ton, IntoBoxed};
use rtos_block::{Cell, Result, ShardIdent, UInt256, ValidatorDescr, ValidatorKey};

pub fn session_config_hash(global_id: i32, options_hash: &UInt256, selected: &Cell) -> UInt256 {
    session_config_hash_from_hash(global_id, options_hash, &selected.repr_hash())
}

/// Structural commitment to an explicit selected config hash; no authentication.
pub fn session_config_hash_from_hash(
    global_id: i32,
    options_hash: &UInt256,
    selected_hash: &UInt256,
) -> UInt256 {
    let mut bytes = b"TOS-VALIDATOR-SESSION-CONFIG-v1".to_vec();
    bytes.extend_from_slice(&global_id.to_le_bytes());
    bytes.extend_from_slice(options_hash.as_slice());
    bytes.extend_from_slice(selected_hash.as_slice());
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

/// Explicit wire coordinates. Unlike ShardIdent, this does not establish that
/// the workchain or shard is admitted by the chain's configuration.
#[derive(Clone, Copy)]
pub struct ExplicitSessionCoordinates {
    pub workchain: i32,
    pub shard: u64,
    pub catchain_seqno: u32,
    pub vertical_seqno: u32,
    pub last_key_block_seqno: u32,
    pub new_catchain_ids: bool,
}
impl From<SessionCoordinates<'_>> for ExplicitSessionCoordinates {
    fn from(value: SessionCoordinates<'_>) -> Self {
        Self {
            workchain: value.shard.workchain_id(),
            shard: value.shard.shard_prefix_with_tag(),
            catchain_seqno: value.catchain_seqno,
            vertical_seqno: value.vertical_seqno,
            last_key_block_seqno: value.last_key_block_seqno,
            new_catchain_ids: value.new_catchain_ids,
        }
    }
}

/// TL int/long fields carry unsigned protocol coordinates as their exact bit pattern.
pub fn session_group_bytes(
    coordinates: SessionCoordinates<'_>,
    config_hash: &UInt256,
    validators: &[ValidatorDescr],
) -> Result<Vec<u8>> {
    explicit_session_group_bytes(coordinates.into(), config_hash, validators)
}

pub fn explicit_session_group_bytes(
    coordinates: ExplicitSessionCoordinates,
    config_hash: &UInt256,
    validators: &[ValidatorDescr],
) -> Result<Vec<u8>> {
    use ton::validator::group::{Group, GroupEx, GroupNew};
    let members = session_members(validators)?;
    let workchain = coordinates.workchain;
    let shard = coordinates.shard as i64;
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
    crate::serialize_boxed(&session_options_value(config, catchain))
}
fn session_options_value(
    config: &rtos_block::ConsensusConfig,
    catchain: &rtos_block::CatchainConfig,
) -> ton::validator_session::Config {
    ExplicitSessionOptions::from_config(config, catchain).to_tl()
}

/// Node session options before TL commitment. This preserves explicit double
/// values and unsigned words; construction does not admit a protocol version.
#[derive(Clone, Debug)]
pub struct ExplicitSessionOptions {
    pub proto_version: u32,
    pub new_catchain_ids: bool,
    pub idle_timeout: f64,
    pub max_deps: u32,
    pub max_serialized_block_size: u32,
    pub block_hash_covers_data: bool,
    pub max_block_height_coeff: u64,
    pub debug_disable_db: bool,
    pub round_candidates: u32,
    pub next_candidate_delay: f64,
    pub round_attempt_duration: u32,
    pub max_round_attempts: u32,
    pub max_block_size: u32,
    pub max_collated_data_size: u32,
}
impl ExplicitSessionOptions {
    pub fn from_config(
        config: &rtos_block::ConsensusConfig,
        catchain: &rtos_block::CatchainConfig,
    ) -> Self {
        Self {
            proto_version: u32::from(config.proto_version),
            new_catchain_ids: config.new_catchain_ids,
            idle_timeout: f64::from(config.consensus_timeout_ms) * 0.001,
            max_deps: config.catchain_max_deps,
            max_serialized_block_size: 16 * 1024,
            block_hash_covers_data: config.proto_version >= 2,
            // The reference commits the low uint32 word of this uint64 product.
            max_block_height_coeff: u64::from(config.catchain_max_blocks_coeff)
                * u64::from(catchain.mc_catchain_lifetime.max(catchain.shard_catchain_lifetime)),
            debug_disable_db: false,
            round_candidates: config.round_candidates,
            next_candidate_delay: f64::from(config.next_candidate_delay_ms) * 0.001,
            round_attempt_duration: config.attempt_duration,
            max_round_attempts: config.fast_attempts,
            max_block_size: config.max_block_bytes,
            max_collated_data_size: config.max_collated_bytes,
        }
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        crate::serialize_boxed(&self.to_tl())
    }
    fn to_tl(&self) -> ton::validator_session::Config {
        use ton::validator_session::config::{
            Config, ConfigNew, ConfigVersioned, ConfigVersionedV2,
        };
        let opts = match self.proto_version {
            0 if !self.new_catchain_ids => Config {
                catchain_idle_timeout: self.idle_timeout.into(),
                catchain_max_deps: self.max_deps as i32,
                round_candidates: self.round_candidates as i32,
                next_candidate_delay: self.next_candidate_delay.into(),
                round_attempt_duration: self.round_attempt_duration as i32,
                max_round_attempts: self.max_round_attempts as i32,
                max_block_size: self.max_block_size as i32,
                max_collated_data_size: self.max_collated_data_size as i32,
            }
            .into_boxed(),
            0 => ConfigNew {
                catchain_idle_timeout: self.idle_timeout.into(),
                catchain_max_deps: self.max_deps as i32,
                round_candidates: self.round_candidates as i32,
                next_candidate_delay: self.next_candidate_delay.into(),
                round_attempt_duration: self.round_attempt_duration as i32,
                max_round_attempts: self.max_round_attempts as i32,
                max_block_size: self.max_block_size as i32,
                max_collated_data_size: self.max_collated_data_size as i32,
                new_catchain_ids: self.new_catchain_ids.into(),
            }
            .into_boxed(),
            1 => ConfigVersioned {
                catchain_idle_timeout: self.idle_timeout.into(),
                catchain_max_deps: self.max_deps as i32,
                round_candidates: self.round_candidates as i32,
                next_candidate_delay: self.next_candidate_delay.into(),
                round_attempt_duration: self.round_attempt_duration as i32,
                max_round_attempts: self.max_round_attempts as i32,
                max_block_size: self.max_block_size as i32,
                max_collated_data_size: self.max_collated_data_size as i32,
                version: self.proto_version as i32,
            }
            .into_boxed(),
            _ => ConfigVersionedV2 {
                catchain_opts: ton::validator_session::catchainoptions::CatchainOptions {
                    idle_timeout: self.idle_timeout.into(),
                    max_deps: self.max_deps as i32,
                    max_block_size: self.max_serialized_block_size as i32,
                    block_hash_covers_data: self.block_hash_covers_data.into(),
                    max_block_height_ceoff: self.max_block_height_coeff as i32,
                    debug_disable_db: self.debug_disable_db.into(),
                }
                .into_boxed(),
                round_candidates: self.round_candidates as i32,
                next_candidate_delay: self.next_candidate_delay.into(),
                round_attempt_duration: self.round_attempt_duration as i32,
                max_round_attempts: self.max_round_attempts as i32,
                max_block_size: self.max_block_size as i32,
                max_collated_data_size: self.max_collated_data_size as i32,
                version: self.proto_version as i32,
            }
            .into_boxed(),
        };
        opts
    }
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
    coordinates.new_catchain_ids = consensus.new_catchain_ids;
    derive_session_from_options(
        global_id,
        &ExplicitSessionOptions::from_config(&consensus, &catchain),
        &selected,
        coordinates,
        validators,
    )
}

/// Derive from already decoded options and the exact selected cell. Like the
/// C++ detail factory, this checks protocol support but grants no governing
/// authority and performs no Param19/header-global-ID admission check.
pub fn derive_session_from_options(
    global_id: i32,
    options: &ExplicitSessionOptions,
    selected: &rtos_block::SelectedSimplexConfig,
    mut coordinates: SessionCoordinates<'_>,
    validators: &[ValidatorDescr],
) -> Result<SessionIdentity> {
    selected.config.validate_protocol_version()?;
    coordinates.new_catchain_ids = options.new_catchain_ids;
    let options_hash = UInt256::calc_file_hash(&options.bytes()?);
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

/// Bounded serialization with exact counting before the output allocation.
fn serialize_bounded<T: crate::BoxedSerialize>(
    value: &T,
    budget: &dyn rtos_block::config_read_budget::ConfigReadBudget,
) -> Result<Vec<u8>> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("TL length overflow"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    crate::Serializer::new(&mut count).write_boxed(value)?;
    let mut output = rtos_block::config_read_budget::vector::<u8>(budget, count.0)?;
    crate::Serializer::new(&mut output).write_boxed(value)?;
    Ok(output)
}
pub fn derive_session_from_decoded_bounded(
    global_id: i32,
    config: &rtos_block::DecodedSessionConfig,
    mut coordinates: SessionCoordinates<'_>,
    validators: &[ValidatorDescr],
    budget: &dyn rtos_block::config_read_budget::ConfigReadBudget,
) -> Result<SessionIdentity> {
    use ton::engine::validator::validator::groupmember::{GroupMember, GroupMemberPQ};
    use ton::validator::group::{Group, GroupEx, GroupNew};
    rtos_block::validators::validate_validator_list_bounded(validators, budget)?;
    config.selected.config.validate_protocol_version()?;
    coordinates.new_catchain_ids = config.consensus.new_catchain_ids;
    let options =
        serialize_bounded(&session_options_value(&config.consensus, &config.catchain), budget)?;
    let options_hash = UInt256::calc_file_hash(&options);
    // The commitment input is fixed, independent of dictionary/body sizes.
    const DOMAIN: &[u8] = b"TOS-VALIDATOR-SESSION-CONFIG-v1";
    let mut commitment = [0u8; b"TOS-VALIDATOR-SESSION-CONFIG-v1".len() + 4 + 32 + 32];
    // Keep the domain size checked rather than silently changing hash preimages.
    let mut cursor = std::io::Cursor::new(commitment.as_mut_slice());
    use std::io::Write;
    cursor.write_all(DOMAIN)?;
    cursor.write_all(&global_id.to_le_bytes())?;
    cursor.write_all(options_hash.as_slice())?;
    cursor.write_all(config.selected.cell_hash().as_slice())?;
    let length = cursor.position() as usize;
    drop(cursor);
    let config_hash = UInt256::calc_file_hash(&commitment[..length]);
    let mut members = rtos_block::config_read_budget::vector(budget, validators.len())?;
    for v in validators {
        budget.step()?;
        let weight = i64::try_from(v.weight)?;
        let adnl = v.adnl_addr.clone().unwrap_or_default();
        members.push(match &v.key {
            ValidatorKey::Ed25519(_) => {
                GroupMember { public_key_hash: v.validator_id_bounded(budget)?, adnl, weight }
                    .into_boxed()
            }
            ValidatorKey::Pq(key) => GroupMemberPQ {
                validator_id: v.validator_id_bounded(budget)?,
                key_id: key.key_id.clone(),
                adnl,
                weight,
            }
            .into_boxed(),
        });
    }
    let workchain = coordinates.shard.workchain_id();
    let shard = coordinates.shard.shard_prefix_with_tag() as i64;
    let catchain_seqno = coordinates.catchain_seqno as i32;
    let vertical_seqno = coordinates.vertical_seqno as i32;
    let group = if coordinates.new_catchain_ids {
        GroupNew {
            workchain,
            shard,
            vertical_seqno,
            last_key_block_seqno: coordinates.last_key_block_seqno as i32,
            catchain_seqno,
            config_hash: config_hash.clone(),
            members,
        }
        .into_boxed()
    } else if vertical_seqno == 0 {
        Group { workchain, shard, catchain_seqno, config_hash: config_hash.clone(), members }
            .into_boxed()
    } else {
        GroupEx {
            workchain,
            shard,
            vertical_seqno,
            catchain_seqno,
            config_hash: config_hash.clone(),
            members,
        }
        .into_boxed()
    };
    let bytes = serialize_bounded(&group, budget)?;
    Ok(SessionIdentity { config_hash, session_id: UInt256::calc_file_hash(&bytes) })
}
