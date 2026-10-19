/*
 * RTOS project modifications (2026-10-10): project and crate naming; typed Simplex protocol and membership admission; explicit target wire profile integration.
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
#[cfg(test)]
use super::consensus::EmulatorConsensusOptions;
#[cfg(test)]
use super::consensus::{serialize_tl_boxed_object, RawBuffer};
use super::consensus::{
    CatchainSessionOptions, ConsensusNode, ConsensusOptions, PublicKey, SimplexSessionOptions,
};
#[cfg(test)]
use super::validator_utils::get_group_members_by_validator_descrs;
use crate::{
    config::ValidatorManagerConfig,
    engine::Engine,
    engine_traits::{EngineOperations, ValidatorListOutcome},
    shard_state::ShardStateStuff,
    validator::{
        out_msg_queue::OutMsgQueueInfoStuff,
        validator_group::{SessionSnapshot, ValidatorGroup, ValidatorGroupStatus},
        validator_utils::{
            compute_validator_list_id, get_masterchain_seqno, try_calc_subset_for_workchain,
            try_calc_subset_for_workchain_standard, validatordescr_to_consensus_node,
            validatorset_to_string, GeneralSessionInfo, PrevBlockHistory, ValidatorListHash,
            ValidatorSubsetInfo,
        },
    },
};
#[cfg(test)]
use consensus_common::EmulatorDelaySpec;
use futures::FutureExt;
#[cfg(test)]
use rtos_api::IntoBoxed;
use rtos_block::{
    base64_encode, error, fail, AcceleratedConsensusConfig, BlockIdExt, CatchainConfig,
    ConfigParamEnum, ConsensusConfig, FutureSplitMerge, McStateExtra, Result, ShardDescr,
    ShardIdent, SimplexConfig, UInt256, UnixTime, ValidatorDescr, ValidatorSet,
};
use std::{
    cmp::max,
    collections::{HashMap, HashSet},
    ops::RangeInclusive,
    sync::{atomic::Ordering, Arc},
    time::{Duration, SystemTime},
};

#[cfg(feature = "xp25")]
const MC_ACCELERATED_CONSENSUS_ENABLED: bool = true;
#[cfg(not(feature = "xp25"))]
const MC_ACCELERATED_CONSENSUS_ENABLED: bool = false;

fn format_shard_short(shard: &ShardIdent) -> String {
    if shard.is_masterchain() {
        "MC".to_string()
    } else {
        format!("{}:{:04X}..", shard.workchain_id(), shard.shard_prefix_with_tag() >> 48)
    }
}

fn format_time_ago(now_unix: u64, ts: u64) -> String {
    if ts == 0 {
        "-".to_string()
    } else if now_unix >= ts {
        format_duration_short(Duration::from_secs(now_unix - ts))
    } else {
        "0s".to_string()
    }
}

fn format_duration_short(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    }
}

const SHARD_EMPTY_BLOCK_MC_LAG_THRESHOLD: u32 = 8;

fn simplex_empty_block_lag_threshold(shard: &ShardIdent) -> Option<u32> {
    if shard.is_masterchain() {
        None
    } else {
        Some(SHARD_EMPTY_BLOCK_MC_LAG_THRESHOLD)
    }
}

fn applied_top_for_session_shard(
    mc_state: &ShardStateStuff,
    mc_state_extra: &McStateExtra,
    shard: &ShardIdent,
) -> Result<Option<BlockIdExt>> {
    if shard.is_masterchain() {
        Ok(Some(mc_state.block_id().clone()))
    } else {
        mc_registered_top_for_shard(mc_state_extra, shard)
    }
}

fn mc_registered_top_for_shard(
    mc_state_extra: &McStateExtra,
    shard: &ShardIdent,
) -> Result<Option<BlockIdExt>> {
    mc_state_extra.shards().find_shard(shard).map(|record| record.map(|r| r.block_id().clone()))
}

/// Rebuild protocol options from the authenticated historical config, without
/// emulator overrides or current-node timing defaults.
pub(crate) fn build_historical_simplex_options(
    config: &rtos_block::ConfigParams,
    shard: &ShardIdent,
) -> Result<simplex::SessionOptions> {
    let consensus = match config.config(29)? {
        Some(ConfigParamEnum::ConfigParam29(value)) => value,
        _ => fail!("Historical Param 29 is unavailable"),
    };
    let catchain = config.catchain_config()?;
    let selected = config
        .selected_simplex_config(shard.is_masterchain())?
        .ok_or_else(|| error!("Historical Simplex config is unavailable"))?;
    let base = get_session_options(&consensus, &catchain, false, &None);
    build_runtime_simplex_session_options(shard, &selected.config, &base)
}

/// Reuse already decoded, request-budgeted historical parameters.
pub(crate) fn build_historical_simplex_options_decoded(
    config: &rtos_block::DecodedSessionConfig,
    shard: &ShardIdent,
) -> Result<simplex::SessionOptions> {
    let base = get_session_options(&config.consensus, &config.catchain, false, &None);
    build_runtime_simplex_session_options(shard, &config.selected.config, &base)
}

fn build_runtime_simplex_session_options(
    shard: &ShardIdent,
    cfg: &SimplexConfig,
    catchain_options: &CatchainSessionOptions,
) -> Result<SimplexSessionOptions> {
    cfg.validate_protocol_version()?;
    let protocol = consensus_common::simplex_protocol::SimplexProtocol::try_from(u32::from(
        cfg.protocol_version,
    ))?;
    // V2 is admitted only through the authenticated factory selected below.
    let np = &cfg.noncritical_params;
    Ok(SimplexSessionOptions {
        wire_profile: rtos_api::WireProfile::T0,
        proto_version: catchain_options.proto_version as u32,
        slots_per_leader_window: cfg.slots_per_leader_window,
        target_rate: Duration::from_millis(np.target_rate_ms as u64),
        min_block_interval: Duration::from_millis(np.min_block_interval_ms as u64),
        first_block_timeout: Duration::from_millis(np.first_block_timeout_ms as u64),
        first_block_timeout_multiplier: f32::from_bits(np.first_block_timeout_multiplier_bits)
            as f64,
        first_block_timeout_cap: Duration::from_millis(np.first_block_timeout_cap_ms as u64),
        candidate_resolve_timeout: Duration::from_millis(np.candidate_resolve_timeout_ms as u64),
        candidate_resolve_timeout_multiplier: f32::from_bits(
            np.candidate_resolve_timeout_multiplier_bits,
        ) as f64,
        candidate_resolve_timeout_cap: Duration::from_millis(
            np.candidate_resolve_timeout_cap_ms as u64,
        ),
        candidate_resolve_cooldown: Duration::from_millis(np.candidate_resolve_cooldown_ms as u64),
        standstill_timeout: Duration::from_millis(np.standstill_timeout_ms as u64),
        standstill_max_egress_bytes_per_s: np.standstill_max_egress_bytes_per_s,
        standstill_min_egress_bytes_per_s: np.standstill_min_egress_bytes_per_s,
        certificate_gossip_neighbors: np.certificate_gossip_neighbors,
        max_leader_window_desync: np.max_leader_window_desync,
        bad_signature_ban_duration: Duration::from_millis(np.bad_signature_ban_duration_ms as u64),
        candidate_resolve_rate_limit: np.candidate_resolve_rate_limit,
        max_block_size: catchain_options.max_block_size as usize,
        max_collated_data_size: catchain_options.max_collated_data_size as usize,
        use_callback_thread: false,
        use_quic: cfg.use_quic,
        protocol,
        no_empty_blocks_on_error_timeout: Duration::from_millis(
            np.no_empty_blocks_on_error_timeout_ms as u64,
        ),
        // C++ parity: shard sessions use lag threshold 8 for empty-block recovery.
        // MC sessions use internal consensus-finalized tracking and keep this unset.
        empty_block_mc_lag_threshold: simplex_empty_block_lag_threshold(shard),
        ..Default::default()
    })
}

fn validation_state_phase_label(status: ValidatorGroupStatus) -> &'static str {
    match status {
        ValidatorGroupStatus::Created | ValidatorGroupStatus::EngineCreated => "pre-start",
        ValidatorGroupStatus::Sync => "pre-commit",
        ValidatorGroupStatus::Active => "post-commit",
        ValidatorGroupStatus::Stopping => "stopping",
        ValidatorGroupStatus::Stopped => "stopped",
    }
}

/// Magic suffix appended to session-ID serialization when accelerated consensus is enabled.
///
/// **Rust-specific extension**: the C++ reference (`get_validator_set_id()` in `manager.cpp`)
/// does not include this tag because C++ does not yet support accelerated consensus in the
/// validator manager (`bridge.cpp` has only a TODO). When accelerated consensus is
/// disabled (the default for C++ interop), session IDs are byte-identical to C++.
#[cfg(test)]
const ACCELERATED_CONSENSUS_MAGIC_TAG: u32 = 0xACCE1E8A;

#[derive(Clone)]
pub struct SessionsOptions {
    pub mc_options: CatchainSessionOptions,
    pub shard_options: CatchainSessionOptions,
}

impl SessionsOptions {
    pub fn get_session_options(&self, shard_id: &ShardIdent) -> &CatchainSessionOptions {
        if shard_id.is_masterchain() {
            &self.mc_options
        } else {
            &self.shard_options
        }
    }
}

/// Historical upstream fixture encoder, compiled only for tests.
/// Production group creation calls derive_governing_session_info.
#[cfg(test)]
fn get_session_id_serialize(
    session_info: Arc<GeneralSessionInfo>,
    vals: &[ValidatorDescr],
    new_catchain_ids: bool,
) -> Result<RawBuffer> {
    let mut members = Vec::new();
    get_group_members_by_validator_descrs(vals, &mut members)?;

    if !new_catchain_ids {
        fail!("Old catchain IDs format (new_catchain_ids=false) is not supported");
    }
    // Historical fixture-only encoding. Production uses session_identity below.
    let mut bytes = 0x9843a14du32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&session_info.shard.workchain_id().to_le_bytes());
    bytes.extend_from_slice(&session_info.shard.shard_prefix_with_tag().to_le_bytes());
    bytes.extend_from_slice(&session_info.max_vertical_seqno.to_le_bytes());
    bytes.extend_from_slice(&session_info.key_seqno.to_le_bytes());
    bytes.extend_from_slice(&session_info.catchain_seqno.to_le_bytes());
    bytes.extend_from_slice(session_info.opts_hash.as_slice());
    bytes.extend_from_slice(&(members.len() as u32).to_le_bytes());
    for member in members {
        bytes.extend_from_slice(member.public_key_hash.as_slice());
        bytes.extend_from_slice(member.adnl.as_slice());
        bytes.extend_from_slice(&member.weight.to_le_bytes());
    }
    Ok(bytes)
}

/// Compute session ID by hashing the serialized `validator.groupNew` TL object.
///
/// When `accelerated_consensus_enabled` is true, appends [`ACCELERATED_CONSENSUS_MAGIC_TAG`]
/// before hashing to differentiate accelerated sessions from standard ones. Without the
/// tag, the resulting hash is byte-identical to C++ `get_validator_set_id()`.
#[cfg(test)]
fn get_session_id(
    session_info: Arc<GeneralSessionInfo>,
    val_set: &[ValidatorDescr],
    new_catchain_ids: bool,
    accelerated_consensus_enabled: bool,
) -> Result<UInt256> {
    let mut serialized = get_session_id_serialize(session_info, val_set, new_catchain_ids)?;
    if accelerated_consensus_enabled {
        serialized.extend_from_slice(&ACCELERATED_CONSENSUS_MAGIC_TAG.to_le_bytes());
    }
    Ok(UInt256::calc_file_hash(&serialized))
}

#[cfg(test)]
fn compute_session_unsafe_serialized(session_id: &UInt256, rotate_id: u32) -> Vec<u8> {
    let mut unsafe_id_serialized: Vec<u8> = session_id.as_slice().to_vec();
    let mut rotate_id_serialized: Vec<u8> = rotate_id.to_le_bytes().to_vec();
    unsafe_id_serialized.append(&mut rotate_id_serialized);
    unsafe_id_serialized
}

/// C++ parity: during unsafe rotation (`force_recover`), skip all non-masterchain shards.
///
/// Mirrors the `force_recover` early-continue in C++ `update_shards()`:
/// ```cpp
/// if (force_recover && !desc.first.is_masterchain()) { continue; }
/// ```
fn should_skip_session_for_unsafe_rotation(
    do_unsafe_catchain_rotate: bool,
    shard: &ShardIdent,
) -> bool {
    do_unsafe_catchain_rotate && !shard.is_masterchain()
}

#[cfg(test)]
fn unsafe_rotation_block_seqno(
    shard: &ShardIdent,
    last_masterchain_block: &BlockIdExt,
) -> Option<u32> {
    shard.is_masterchain().then_some(last_masterchain_block.seq_no)
}

enum ExistingSessionSource<T> {
    Current(T),
    Future(T),
}

fn select_existing_session_for_current_map<T: Clone>(
    session_id: &UInt256,
    current_sessions: &HashMap<UInt256, T>,
    future_sessions: &mut HashMap<UInt256, T>,
) -> Option<ExistingSessionSource<T>> {
    if let Some(existing) = current_sessions.get(session_id) {
        return Some(ExistingSessionSource::Current(existing.clone()));
    }

    future_sessions.remove(session_id).map(ExistingSessionSource::Future)
}

/// Computes session_id and if unsafe rotation is taking place,
/// replaces session_id with unsafe rotation session id.
/// The `do_unsafe_catchain_rotate` flag mirrors C++ `force_recover`:
/// the per-shard rotation check only runs when the global gate is set.
#[cfg(test)]
fn get_session_unsafe_id(
    session_info: Arc<GeneralSessionInfo>,
    val_set: &[ValidatorDescr],
    new_catchain_ids: bool,
    do_unsafe_catchain_rotate: bool,
    rotation_block_seqno_opt: Option<u32>,
    vm_config: &ValidatorManagerConfig,
    accelerated_consensus_enabled: bool,
) -> Result<UInt256> {
    let session_id = get_session_id(
        session_info.clone(),
        val_set,
        new_catchain_ids,
        accelerated_consensus_enabled,
    )?;

    if do_unsafe_catchain_rotate && session_info.shard.is_masterchain() {
        if let Some(rotate_id) = vm_config
            .check_unsafe_catchain_rotation(rotation_block_seqno_opt, session_info.catchain_seqno)
        {
            let unsafe_serialized = compute_session_unsafe_serialized(&session_id, rotate_id);
            let unsafe_id = UInt256::calc_file_hash(unsafe_serialized.as_slice());

            log::warn!(
                target: "validator_manager",
                "Unsafe master session rotation: session {} at block={:?}, cc={} -> rotate_id={}, new session {}",
                session_id.to_hex_string(),
                rotation_block_seqno_opt,
                session_info.catchain_seqno,
                rotate_id,
                unsafe_id.to_hex_string()
            );
            return Ok(unsafe_id);
        }
    }
    Ok(session_id)
}

#[cfg(test)]
fn validator_session_options_serialize(opts: &CatchainSessionOptions) -> RawBuffer {
    match opts.proto_version {
        0 => {
            if !opts.new_catchain_ids {
                serialize_tl_boxed_object!(&rtos_api::ton::validator_session::config::Config {
                    catchain_idle_timeout: opts.catchain_idle_timeout.as_secs_f64().into(),
                    catchain_max_deps: i32::try_from(opts.catchain_max_deps).unwrap(),
                    round_candidates: i32::try_from(opts.round_candidates).unwrap(),
                    next_candidate_delay: opts.next_candidate_delay.as_secs_f64().into(),
                    round_attempt_duration: i32::try_from(opts.round_attempt_duration.as_secs())
                        .unwrap(),
                    max_round_attempts: i32::try_from(opts.max_round_attempts).unwrap(),
                    max_block_size: i32::try_from(opts.max_block_size).unwrap(),
                    max_collated_data_size: i32::try_from(opts.max_collated_data_size).unwrap()
                }
                .into_boxed())
            } else {
                serialize_tl_boxed_object!(&rtos_api::ton::validator_session::config::ConfigNew {
                    catchain_idle_timeout: opts.catchain_idle_timeout.as_secs_f64().into(),
                    catchain_max_deps: i32::try_from(opts.catchain_max_deps).unwrap(),
                    round_candidates: i32::try_from(opts.round_candidates).unwrap(),
                    next_candidate_delay: opts.next_candidate_delay.as_secs_f64().into(),
                    round_attempt_duration: i32::try_from(opts.round_attempt_duration.as_secs())
                        .unwrap(),
                    max_round_attempts: i32::try_from(opts.max_round_attempts).unwrap(),
                    max_block_size: i32::try_from(opts.max_block_size).unwrap(),
                    max_collated_data_size: i32::try_from(opts.max_collated_data_size).unwrap(),
                    new_catchain_ids: rtos_api::ton::Bool::from(opts.new_catchain_ids)
                }
                .into_boxed())
            }
        }
        1 => {
            serialize_tl_boxed_object!(&rtos_api::ton::validator_session::config::ConfigVersioned {
                catchain_idle_timeout: opts.catchain_idle_timeout.as_secs_f64().into(),
                catchain_max_deps: i32::try_from(opts.catchain_max_deps).unwrap(),
                round_candidates: i32::try_from(opts.round_candidates).unwrap(),
                next_candidate_delay: opts.next_candidate_delay.as_secs_f64().into(),
                round_attempt_duration: i32::try_from(opts.round_attempt_duration.as_secs())
                    .unwrap(),
                max_round_attempts: i32::try_from(opts.max_round_attempts).unwrap(),
                max_block_size: i32::try_from(opts.max_block_size).unwrap(),
                max_collated_data_size: i32::try_from(opts.max_collated_data_size).unwrap(),
                version: opts.proto_version as i32
            }
            .into_boxed())
        }
        _ => {
            serialize_tl_boxed_object!(
                &rtos_api::ton::validator_session::config::ConfigVersionedV2 {
                    catchain_opts:
                        rtos_api::ton::validator_session::catchainoptions::CatchainOptions {
                            idle_timeout: opts.catchain_idle_timeout.as_secs_f64().into(),
                            max_deps: i32::try_from(opts.catchain_max_deps).unwrap(),
                            max_block_size: i32::try_from(opts.catchain_max_serialized_block_size)
                                .unwrap(),
                            block_hash_covers_data: rtos_api::ton::Bool::from(
                                opts.catchain_block_hash_covers_data
                            ),
                            max_block_height_ceoff: i32::try_from(
                                opts.catchain_max_block_height_coeff
                            )
                            .unwrap(),
                            debug_disable_db: rtos_api::ton::Bool::from(opts.catchain_disable_db)
                        }
                        .into_boxed(),
                    round_candidates: i32::try_from(opts.round_candidates).unwrap(),
                    next_candidate_delay: opts.next_candidate_delay.as_secs_f64().into(),
                    round_attempt_duration: i32::try_from(opts.round_attempt_duration.as_secs())
                        .unwrap(),
                    max_round_attempts: i32::try_from(opts.max_round_attempts).unwrap(),
                    max_block_size: i32::try_from(opts.max_block_size).unwrap(),
                    max_collated_data_size: i32::try_from(opts.max_collated_data_size).unwrap(),
                    version: opts.proto_version as i32
                }
                .into_boxed()
            )
        }
    }
}

#[cfg(test)]
fn get_validator_session_options_hash(
    mut opts: CatchainSessionOptions,
    last_masterchain_block_seqno: u32,
) -> (UInt256, RawBuffer) {
    const THRESHOLD: u32 = 9407194;
    if last_masterchain_block_seqno >= THRESHOLD {
        opts.proto_version = max(1, opts.proto_version);
    }
    let serialized = validator_session_options_serialize(&opts);
    (UInt256::calc_file_hash(&serialized), serialized)
}

#[cfg_attr(feature = "xp25", allow(dead_code))]
#[cfg(test)]
fn get_cxx_interop_session_options_hash(
    opts: &CatchainSessionOptions,
    last_masterchain_block_seqno: u32,
) -> (UInt256, RawBuffer) {
    let mut interop_opts = opts.clone();
    let defaults = CatchainSessionOptions::default();

    interop_opts.accelerated_consensus_enabled = false;
    interop_opts.accelerated_consensus_collation_retry_timeout =
        defaults.accelerated_consensus_collation_retry_timeout;
    interop_opts.accelerated_consensus_skip_rounds_count_for_collator_rotation =
        defaults.accelerated_consensus_skip_rounds_count_for_collator_rotation;
    interop_opts.accelerated_consensus_max_precollated_blocks =
        defaults.accelerated_consensus_max_precollated_blocks;

    get_validator_session_options_hash(interop_opts, last_masterchain_block_seqno)
}

/// Build the session-options view used by C++ `ValidatorSessionOptions opts{config}`.
///
/// This is intentionally derived only from config 29 / catchain config and never from
/// Rust's runtime accelerated-consensus toggles. It is used only in non-`xp25` builds
/// where Rust must preserve the C++ single-`opts_hash` behavior.
#[cfg_attr(feature = "xp25", allow(dead_code))]
#[cfg(test)]
fn get_cxx_interop_session_options(
    opts: &ConsensusConfig,
    catchain_config: &CatchainConfig,
) -> CatchainSessionOptions {
    let no_accelerated_consensus_config = None;
    get_session_options(opts, catchain_config, false, &no_accelerated_consensus_config)
}

#[cfg(feature = "xp25")]
#[cfg(test)]
fn get_session_id_hashes(
    _consensus_config: &ConsensusConfig,
    _catchain_config: &CatchainConfig,
    mc_options: &CatchainSessionOptions,
    shard_options: &CatchainSessionOptions,
    last_masterchain_block_seqno: u32,
) -> ((UInt256, RawBuffer), (UInt256, RawBuffer)) {
    (
        get_validator_session_options_hash(mc_options.clone(), last_masterchain_block_seqno),
        get_validator_session_options_hash(shard_options.clone(), last_masterchain_block_seqno),
    )
}

#[cfg(not(feature = "xp25"))]
#[cfg(test)]
fn get_session_id_hashes(
    consensus_config: &ConsensusConfig,
    catchain_config: &CatchainConfig,
    _mc_options: &CatchainSessionOptions,
    _shard_options: &CatchainSessionOptions,
    last_masterchain_block_seqno: u32,
) -> ((UInt256, RawBuffer), (UInt256, RawBuffer)) {
    let session_id_options = get_cxx_interop_session_options(consensus_config, catchain_config);
    let (session_id_hash, session_id_options_serialized) =
        get_cxx_interop_session_options_hash(&session_id_options, last_masterchain_block_seqno);
    (
        (session_id_hash.clone(), session_id_options_serialized.clone()),
        (session_id_hash, session_id_options_serialized),
    )
}

fn get_session_options(
    opts: &ConsensusConfig,
    catchain_config: &CatchainConfig,
    accelerated_consensus_enabled: bool,
    accelerated_consensus_config: &Option<AcceleratedConsensusConfig>,
) -> CatchainSessionOptions {
    let default_opts = CatchainSessionOptions::default();

    let mut result = CatchainSessionOptions {
        catchain_idle_timeout: Duration::from_millis(opts.consensus_timeout_ms.into()),
        catchain_max_deps: opts.catchain_max_deps,
        catchain_max_serialized_block_size: default_opts.catchain_max_serialized_block_size, // always set to default
        catchain_max_block_height_coeff: {
            let catchain_lifetime =
                max(catchain_config.mc_catchain_lifetime, catchain_config.shard_catchain_lifetime);
            u64::from(opts.catchain_max_blocks_coeff) * u64::from(catchain_lifetime)
        },
        proto_version: opts.proto_version as u32,
        catchain_block_hash_covers_data: {
            const BLOCK_HASH_COVERS_DATA_FROM_VERSION: u32 = 2;
            if opts.proto_version as u32 >= BLOCK_HASH_COVERS_DATA_FROM_VERSION {
                true
            } else {
                default_opts.catchain_block_hash_covers_data
            }
        },
        catchain_disable_db: default_opts.catchain_disable_db,
        catchain_skip_processed_blocks: false, // Debugging option, not found in consensus config
        round_candidates: opts.round_candidates,
        next_candidate_delay: Duration::from_millis(opts.next_candidate_delay_ms.into()),
        round_attempt_duration: Duration::from_secs(opts.attempt_duration.into()),
        max_round_attempts: opts.fast_attempts,
        max_block_size: opts.max_block_bytes,
        max_collated_data_size: opts.max_collated_bytes,
        new_catchain_ids: opts.new_catchain_ids,
        skip_single_node_session_validations: false, // This should be set to true for single-node sessions
        catchain_receiver_max_neighbours_count: default_opts.catchain_receiver_max_neighbours_count,
        catchain_receiver_neighbours_sync_min_period: default_opts
            .catchain_receiver_neighbours_sync_min_period,
        catchain_receiver_neighbours_sync_max_period: default_opts
            .catchain_receiver_neighbours_sync_max_period,
        catchain_receiver_max_sources_sync_attempts: default_opts
            .catchain_receiver_max_sources_sync_attempts,
        catchain_receiver_neighbours_rotate_min_period: default_opts
            .catchain_receiver_neighbours_rotate_min_period,
        catchain_receiver_neighbours_rotate_max_period: default_opts
            .catchain_receiver_neighbours_rotate_max_period,
        accelerated_consensus_enabled,
        accelerated_consensus_collation_retry_timeout: default_opts
            .accelerated_consensus_collation_retry_timeout,
        accelerated_consensus_skip_rounds_count_for_collator_rotation: default_opts
            .accelerated_consensus_skip_rounds_count_for_collator_rotation,
        accelerated_consensus_max_precollated_blocks: default_opts
            .accelerated_consensus_max_precollated_blocks,
        validation_retry_attempts: default_opts.validation_retry_attempts,
        validation_retry_timeout: default_opts.validation_retry_timeout,
        block_candidate_sending_retry_timeout: default_opts.block_candidate_sending_retry_timeout,
        block_candidate_sending_retry_attempts: default_opts.block_candidate_sending_retry_attempts,
        use_callback_thread: default_opts.use_callback_thread,
    };

    if accelerated_consensus_enabled {
        if let Some(accelerated_consensus_config) = accelerated_consensus_config {
            result.accelerated_consensus_collation_retry_timeout = Duration::from_millis(
                accelerated_consensus_config.failed_collation_retry_timeout_ms.into(),
            );
            result.accelerated_consensus_skip_rounds_count_for_collator_rotation =
                accelerated_consensus_config.skip_rounds_count_for_collator_rotation;
            result.accelerated_consensus_max_precollated_blocks =
                accelerated_consensus_config.max_precollated_blocks;
        }
    }

    result
}

fn derive_governing_session_info(
    state: &ShardStateStuff,
    shard: &ShardIdent,
    validators: &[ValidatorDescr],
    catchain_seqno: u32,
    key_seqno: u32,
    vertical_seqno: u32,
) -> Result<(Arc<GeneralSessionInfo>, UInt256)> {
    use rtos_api::session_identity::{derive_session_from_config, SessionCoordinates};
    let identity = derive_session_from_config(
        state.state()?.global_id(),
        state.config_params()?,
        SessionCoordinates {
            shard,
            catchain_seqno,
            vertical_seqno,
            last_key_block_seqno: key_seqno,
            new_catchain_ids: false,
        },
        validators,
    )?;
    Ok((
        Arc::new(GeneralSessionInfo {
            shard: shard.clone(),
            opts_hash: identity.config_hash,
            catchain_seqno,
            key_seqno,
            max_vertical_seqno: vertical_seqno,
        }),
        identity.session_id,
    ))
}

#[repr(u8)]
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug)]
pub enum ValidationStatus {
    Disabled = 0,
    Waiting = 1,
    Active = 2,
}

impl ValidationStatus {
    fn allows_validate(&self) -> bool {
        match self {
            Self::Disabled | Self::Waiting => false,
            Self::Active => true,
        }
    }
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => ValidationStatus::Waiting,
            2 => ValidationStatus::Active,
            _ => ValidationStatus::Disabled,
        }
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
enum NoCurrentSessionHealthReason {
    MissingOwnedCurrentSubsetSession,
    FutureSubsetOnly,
    NoCurrentSubsetOwned,
}

impl NoCurrentSessionHealthReason {
    fn label(&self) -> &'static str {
        match self {
            Self::MissingOwnedCurrentSubsetSession => "owned_current_subset_missing_session",
            Self::FutureSubsetOnly => "future_subset_only",
            Self::NoCurrentSubsetOwned => "no_current_subset_owned",
        }
    }

    fn should_warn(&self) -> bool {
        matches!(self, Self::MissingOwnedCurrentSubsetSession)
    }
}

fn classify_no_current_session_health(
    in_current_set: bool,
    validation_status: ValidationStatus,
    current_sessions_len: usize,
    owned_current_shards: usize,
    owned_future_shards: usize,
) -> Option<NoCurrentSessionHealthReason> {
    if !in_current_set || !validation_status.allows_validate() || current_sessions_len > 0 {
        return None;
    }

    if owned_current_shards > 0 {
        Some(NoCurrentSessionHealthReason::MissingOwnedCurrentSubsetSession)
    } else if owned_future_shards > 0 {
        Some(NoCurrentSessionHealthReason::FutureSubsetOnly)
    } else {
        Some(NoCurrentSessionHealthReason::NoCurrentSubsetOwned)
    }
}

/// Local node's participation record for a single validator list.
///
/// Stores local validator keys in the same local-key order that C++ uses for `temp_keys_`,
/// so per-shard selection can still pick the first matching local key within a subset.
struct LocalValidatorListEntry {
    keys: Vec<PublicKey>,
}

/// Tracks which validator lists the local node belongs to.
///
/// Maintains the current and next validator list IDs (mirroring the masterchain state's
/// current and next validator sets) along with the local node's keys for each.
///
/// C++ does not have a direct equivalent structure; it relies on `temp_keys_` for
/// membership checks and `allow_validate_` for the enable/disable gate.
#[derive(Default)]
struct ValidatorListStatus {
    known_lists: HashMap<ValidatorListHash, LocalValidatorListEntry>,
    curr: Option<ValidatorListHash>,
    next: Option<ValidatorListHash>,
    /// for observer mode keeps the local ADNL key alive
    prev: Option<ValidatorListHash>,
    curr_utime_since: Option<u32>,
    next_utime_since: Option<u32>,
    prev_utime_since: Option<u32>,
}

impl ValidatorListStatus {
    fn add_list(&mut self, list_id: ValidatorListHash, keys: Vec<PublicKey>) {
        self.known_lists.insert(list_id, LocalValidatorListEntry { keys });
    }

    fn contains_list(&self, list_id: &ValidatorListHash) -> bool {
        self.known_lists.contains_key(list_id)
    }

    fn remove_list(&mut self, list_id: &ValidatorListHash) {
        self.known_lists.remove(list_id);
    }

    fn get_list(&self, list_id: &ValidatorListHash) -> Option<&LocalValidatorListEntry> {
        self.known_lists.get(list_id)
    }

    #[cfg(test)]
    fn get_local_keys_for_list(&self, list_id: &ValidatorListHash) -> Option<&[PublicKey]> {
        self.get_list(list_id).map(|entry| entry.keys.as_slice())
    }

    /// The classical keys this node holds, the reference node's temporary and
    /// permanent keys: every local key the engine matched for any known list.
    /// They confer membership of a classical descriptor only.
    fn classical_keys(&self) -> std::collections::BTreeSet<UInt256> {
        self.known_lists
            .values()
            .flat_map(|entry| entry.keys.iter())
            .map(|key| UInt256::from(*key.id().data()))
            .collect()
    }

    /// The local classical key with this identity, if one is held.
    #[cfg(test)]
    fn classical_key(&self, id: &UInt256) -> Option<PublicKey> {
        self.known_lists
            .values()
            .flat_map(|entry| entry.keys.iter())
            .find(|key| key.id().data() == id.as_array())
            .cloned()
    }

    fn actual_or_coming(&self, list_id: &ValidatorListHash) -> bool {
        match &self.curr {
            Some(curr_id) if list_id == curr_id => return true,
            _ => (),
        };
        match &self.next {
            Some(next_id) if list_id == next_id => return true,
            _ => (),
        };
        match &self.prev {
            Some(prev_id) => list_id == prev_id,
            _ => false,
        }
    }

    fn known_hashes(&self) -> HashSet<ValidatorListHash> {
        return self.known_lists.keys().cloned().collect();
    }
}

fn rotate_all_shards(mc_state_extra: &McStateExtra) -> bool {
    mc_state_extra.validator_info.nx_cc_updated
}

/// Core validator manager state.
///
/// Mirrors `ValidatorManagerImpl` in C++ (`manager.cpp`). Tracks active and future
/// validator sessions, the local node's membership in validator lists, and a blacklist
/// of destroyed session IDs to prevent recreation during the same masterchain cycle.
/// Candidate cleanup claims examined per tick.
const CLEANUP_CLAIM_PAGE: usize = 64;

/// A dispatched cleanup worker: one namespace delete, or one session's
/// candidate-table delete for its durable claim.
enum CleanupWork {
    Namespace {
        namespace: String,
        session: UInt256,
        generation: u64,
        attempt: u64,
    },
    Claim {
        session: UInt256,
        attempt: u64,
    },
    /// A journaled attempt of an authenticated namespace.
    V2 {
        namespace: String,
        session: UInt256,
        generation: u64,
        attempt: u64,
    },
}

/// What happens next to an authenticated namespace whose attempt is not
/// running. Its reservations stay with the manager throughout.
enum V2Next {
    /// Refused before anything was journaled: release and complete.
    Release,
    /// Continue from the durable journal under the same reservation.
    Resume,
    /// Confirm the durable record as exactly one of these by a synced
    /// re-write, then continue from it.
    Confirm {
        intended: consensus_common::validator_cleanup::PendingValidatorCleanup,
        previous: consensus_common::validator_cleanup::PendingValidatorCleanup,
    },
    /// Gone: erase the record.
    Erase,
}

/// An authenticated namespace between attempts, under reservation
/// `(generation, attempt)`; its in-flight entry stays until released.
struct V2Parked {
    session: UInt256,
    generation: u64,
    attempt: u64,
    next: V2Next,
}

fn journal_state(journal: &consensus_common::validator_cleanup::CleanupJournal) -> &'static str {
    use consensus_common::validator_cleanup::CleanupJournal;
    match journal {
        CleanupJournal::Pending => "pending",
        CleanupJournal::Deleting(_) => "deleting",
        CleanupJournal::Deleted(_) => "deleted",
        CleanupJournal::Releasing(_) => "releasing",
    }
}

/// Why validation is disabled: a retirement fences and records every group;
/// a shutdown does neither. Neither clears the fence or the rotation block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DisableReason {
    Retire,
    Shutdown,
}

/// What a cleanup worker produced.
enum CleanupOutcome {
    Gone(Result<bool>),
    V2(super::validator_cleanup_gc::V2Outcome),
}

/// Dry verdicts kept for observability.
const CLEANUP_VERDICTS_KEPT: usize = 256;

/// What the group-creation checks admitted this node as: its committee index,
/// the transport key of its descriptor and, for a post-quantum committee, the
/// custody signer of exactly that descriptor.
struct AdmittedValidator {
    index: u32,
    transport_key: PublicKey,
    signer: Option<simplex::SessionSigner>,
}

struct ValidatorManagerImpl {
    engine: Arc<dyn EngineOperations>,
    startup_recovery_gate: Option<super::finality_recovery_owner::RecoveryBootstrapGate>,
    rt: tokio::runtime::Handle,
    /// Sessions for the current validator set (started or starting).
    current_sessions: HashMap<UInt256, Arc<ValidatorGroup>>,
    /// Sessions for the next (future) validator set with pre-created engines.
    future_sessions: HashMap<UInt256, Arc<ValidatorGroup>>,
    // Retiring objects remain owned across cancellation and failed teardown.
    // The first retirement fixes the database policy for all later waiters.
    /// Groups being stopped, with the cleanup generation their close confirms
    /// (None when nothing was recorded, e.g. shutdown or admission replacement).
    retiring_groups: Vec<(UInt256, Arc<ValidatorGroup>, Option<(String, u64)>)>,
    /// Cleanup records built at retirement, persisted with the fence before
    /// any of their groups may close.
    pending_cleanup_records: Vec<consensus_common::validator_cleanup::PendingValidatorCleanup>,
    /// The fence gained a retirement that is not yet synced; no retiring group
    /// may close until it is, even if its cleanup record could not be built.
    fence_dirty: bool,
    cleanup: consensus_common::validator_cleanup::ValidatorCleanupManager,
    /// Next cleanup tick; persists across wakeups of the manager loop.
    cleanup_tick_at: tokio::time::Instant,
    /// Blocking delete workers; joined before shutdown returns.
    cleanup_workers: tokio::task::JoinSet<CleanupOutcome>,
    /// The last attempt outcome per authenticated namespace (bounded).
    cleanup_v2_verdicts: std::collections::BTreeMap<String, String>,
    /// Authenticated namespaces between attempts.
    cleanup_v2_parked: HashMap<String, V2Parked>,
    /// The reservations of every authenticated namespace from its dispatch
    /// until released or its erase is acknowledged; attempts and their
    /// children hold shares.
    cleanup_v2_held: HashMap<String, Arc<super::validator_cleanup_gc::CleanupHeld>>,
    /// The erase batch decided once per namespace (the claim to write, if
    /// any), reused by every retry until acknowledged.
    cleanup_erase_claims: HashMap<String, Option<UInt256>>,
    cleanup_worker_ids: HashMap<tokio::task::Id, CleanupWork>,
    /// Storage cleanup reservations by namespace, with the attempt holding it.
    cleanup_storage: HashMap<String, (u64, consensus_common::StorageCleanupReservation)>,
    /// Cursor over durable candidate cleanup claims.
    cleanup_claim_cursor: String,
    retiring_observers: Vec<Arc<super::block_sync_observer::BlockSyncObserver>>,
    lifecycle_errors: HashSet<String>,
    background_tasks: tokio_util::task::TaskTracker,
    background_panicked: Arc<std::sync::atomic::AtomicBool>,
    /// Number of current subsets selected for the local node on the last successful
    /// `update_shards()` pass.
    owned_current_shards: usize,
    /// Number of future subsets selected for the local node on the last successful
    /// `update_shards()` pass.
    owned_future_shards: usize,
    validator_list_status: ValidatorListStatus,
    config: ValidatorManagerConfig,
    /// Session IDs that have been destroyed and must not be recreated until the next
    /// full shard rotation. Mirrors C++ `destroyed_validator_sessions_` in `manager.cpp`.
    ///
    /// Persisted in the validator-state DB and cleared when `rotate_all_shards()` returns
    /// true, matching the C++ lifecycle around init-block updates.
    destroyed_sessions: HashSet<UInt256>,
    /// Set to `true` once `check_sync()` succeeds, enabling `Waiting -> Active`.
    sync_complete: bool,
    /// Wall-clock timestamp of the last full metrics dump.
    last_metrics_dump: tokio::time::Instant,
    /// active block-sync observers, keyed by session_id
    block_sync_observers: HashMap<UInt256, Arc<super::block_sync_observer::BlockSyncObserver>>,
}

impl ValidatorManagerImpl {
    /// Runs one cleanup tick when its deadline has passed. The deadline is
    /// re-armed before the body and never reset by other wakeups, so MC
    /// arrivals and retries cannot starve cleanup.
    async fn run_cleanup_tick_if_due(&mut self) {
        if !self.config.consensus_cleanup_enabled {
            return;
        }
        let now = tokio::time::Instant::now();
        if now < self.cleanup_tick_at {
            return;
        }
        self.cleanup_tick_at = now + self.config.consensus_cleanup_tick;
        self.run_cleanup_tick().await;
    }

    /// One tick: retry pending erases, maintain the GC floor, then at most one
    /// pass over a page of durable records bound to the published floor, and
    /// one page of session-level candidate cleanup claims.
    async fn run_cleanup_tick(&mut self) {
        use super::validator_cleanup_gc as gc;
        use consensus_common::validator_cleanup::Oracles;
        // No attempt of any kind before this process has its own durable
        // incarnation; retried each tick.
        if !self.cleanup.incarnation_established() {
            match self.engine.next_cleanup_incarnation() {
                Ok(incarnation) if self.cleanup.establish_incarnation(incarnation) => {
                    log::info!(target: "validator_manager",
                        "VALCLEANUP incarnation={incarnation}");
                }
                Ok(incarnation) => {
                    log::warn!(target: "validator_manager",
                        "VALCLEANUP incarnation {incarnation} refused");
                    return;
                }
                Err(e) => {
                    log::warn!(target: "validator_manager",
                        "VALCLEANUP incarnation not established, retrying: {e}");
                    return;
                }
            }
        }
        self.retry_cleanup_erases();
        self.resume_parked_v2();
        if let Err(e) = self.engine.maintain_validator_cleanup_floor().await {
            log::warn!(target: "validator_manager", "VALCLEANUP floor maintenance failed: {e}");
        }
        let Some((gc_id, gc_state)) = self.engine.validator_cleanup_floor() else {
            return;
        };
        if gc_state.block_id() != &gc_id {
            return;
        }
        if let Some(request) = self.cleanup.begin_tick() {
            let page = match self
                .engine
                .load_validator_cleanup_page(&request.after_key, request.max_keys)
            {
                Ok(page) => Some(page),
                Err(e) => {
                    if self.cleanup.abort_pass(request.token).is_some() {
                        log::warn!(target: "validator_manager", "VALCLEANUP pass did not run: {e}");
                    }
                    None
                }
            };
            if let Some(page) = page {
                let db_root = self.engine.db_root_dir().map(str::to_owned);
                let (current, future, retiring) =
                    (&self.current_sessions, &self.future_sessions, &self.retiring_groups);
                let is_live = |session: &UInt256| {
                    current.contains_key(session)
                        || future.contains_key(session)
                        || retiring.iter().any(|(id, _, _)| id == session)
                };
                let ancestor =
                    |checkpoint: &BlockIdExt| gc::ancestor_or_equal(&gc_state, checkpoint);
                let catchain = |shard: &ShardIdent| gc::shard_catchain_seqno(&gc_state, shard);
                let veto = gc::authenticated_cleanup_veto;
                let oracles = Oracles {
                    gc: gc_id.clone(),
                    ancestor_or_equal_of_gc: &ancestor,
                    gc_shard_catchain_seqno: &catchain,
                    is_live: &is_live,
                    custody_veto: &veto,
                };
                let candidates = self.cleanup.on_page(&request, &page, &oracles);
                let mut reserved = Vec::new();
                for candidate in candidates {
                    // Exclusive storage authority first: no opener may get in
                    // while this delete is reserved, and a live or unclean
                    // namespace refuses.
                    let storage = match db_root.as_deref() {
                        Ok(root) => match gc::namespace_storage_any(root, &candidate) {
                            Some((parent, id)) => {
                                consensus_common::reserve_storage_cleanup(&parent, &id)
                                    .ok()
                                    .flatten()
                            }
                            None => None,
                        },
                        Err(_) => None,
                    };
                    let current_record = self
                        .engine
                        .load_validator_cleanup_record(&candidate.namespace)
                        .map_err(|e| e.to_string());
                    let Some(item) = self.cleanup.on_point_read_result(
                        request.token,
                        &candidate,
                        &current_record,
                        &is_live,
                    ) else {
                        continue;
                    };
                    // An authenticated namespace also takes the exclusive
                    // Cleanup admission, so no session or replay opens it.
                    let admission =
                        match consensus_common::validator_cleanup::parse_canonical_namespace_name(
                            &item.record.namespace,
                            &item.record.session_id,
                        ) {
                            Some(parsed)
                                if parsed.layout
                                    != consensus_common::validator_cleanup::NamespaceLayout::V1 =>
                            {
                                match self.engine.reserve_cleanup_admission(
                                    &item.record.session_id,
                                    &parsed.layout,
                                ) {
                                    Ok(Some(admission)) => Some(Some(admission)),
                                    _ => None,
                                }
                            }
                            Some(_) => Some(None),
                            None => None,
                        };
                    match (storage, admission) {
                        (Some(storage), Some(admission)) => {
                            reserved.push((item, storage, admission))
                        }
                        (_, Some(Some(admission))) => {
                            admission.release();
                            self.cleanup.on_delete_completed(
                                &item.record.namespace,
                                item.generation,
                                item.attempt_id,
                                false,
                            );
                        }
                        _ => {
                            // Storage is occupied: release the driver's
                            // reservation; a later cycle examines it again.
                            self.cleanup.on_delete_completed(
                                &item.record.namespace,
                                item.generation,
                                item.attempt_id,
                                false,
                            );
                        }
                    }
                }
                if self.cleanup.pass_verified() {
                    let summary = self.cleanup.end_pass();
                    if summary.reserved > 0 || self.cleanup.in_first_scan() || summary.wrapped {
                        log::info!(target: "validator_manager",
                            "VALCLEANUP pass gc_seqno={} examined={} reserved={} wrapped={} \
                            in_flight={}",
                            gc_id.seq_no(), summary.examined, reserved.len(), summary.wrapped,
                            self.cleanup.in_flight_count()
                        );
                    }
                }
                for (item, storage, admission) in reserved {
                    match admission {
                        None => self.dispatch_cleanup_delete(item, storage),
                        Some(admission) => self.dispatch_v2_reserved(item, storage, admission),
                    }
                }
            }
        }
        self.run_candidate_claims();
    }

    fn session_is_live(&self, session: &UInt256) -> bool {
        self.current_sessions.contains_key(session)
            || self.future_sessions.contains_key(session)
            || self.retiring_groups.iter().any(|(id, _, _)| id == session)
    }

    /// One page of durable candidate cleanup claims. A claim whose session
    /// is live again or has any durable namespace record belongs to a newer
    /// incarnation and is erased without deleting; otherwise the session's
    /// candidate table is deleted by an owned worker.
    fn run_candidate_claims(&mut self) {
        let (claims, last_key, reached_end) = match self
            .engine
            .load_candidate_claims_page(&self.cleanup_claim_cursor, CLEANUP_CLAIM_PAGE)
        {
            Ok(page) => page,
            Err(e) => {
                log::warn!(target: "validator_manager", "VALCLEANUP claim page failed: {e}");
                return;
            }
        };
        self.cleanup_claim_cursor = if reached_end { String::new() } else { last_key };
        for (session, namespace) in claims {
            if self.cleanup.is_delete_in_flight(&session) {
                continue;
            }
            let superseded = self.session_is_live(&session)
                || match self.engine.session_has_other_cleanup_records(&namespace, &session) {
                    Ok(other) => other,
                    Err(e) => {
                        log::warn!(target: "validator_manager",
                            "VALCLEANUP claim check failed for session={}: {e}",
                            session.to_hex_string());
                        continue;
                    }
                }
                || match self.engine.load_validator_cleanup_record(&namespace) {
                    Ok(record) => record.is_some(),
                    Err(_) => continue,
                };
            if superseded {
                if let Err(e) = self.engine.erase_candidate_claim(&session) {
                    log::warn!(target: "validator_manager",
                        "VALCLEANUP superseded claim erase failed for session={}: {e}",
                        session.to_hex_string());
                }
                continue;
            }
            let Some(attempt) = self.cleanup.begin_claim(&session) else {
                continue;
            };
            log::info!(target: "validator_manager",
                "VALCLEANUP claim session={} attempt={attempt}", session.to_hex_string());
            let engine = self.engine.clone();
            let target = session.clone();
            let handle = self.cleanup_workers.spawn_blocking_on(
                move || CleanupOutcome::Gone(engine.delete_candidate_table(&target)),
                &self.rt,
            );
            self.cleanup_worker_ids.insert(handle.id(), CleanupWork::Claim { session, attempt });
        }
    }

    /// Hands one reserved delete to a blocking worker owned by the manager.
    /// The reservation stays here until the worker's real completion.
    fn dispatch_cleanup_delete(
        &mut self,
        item: consensus_common::validator_cleanup::ReservedDelete,
        storage: consensus_common::StorageCleanupReservation,
    ) {
        let namespace = item.record.namespace.clone();
        log::info!(target: "validator_manager",
            "VALCLEANUP reserve session={} generation={} attempt={} dir={} retirement_seqno={}",
            item.record.session_id.to_hex_string(), item.generation, item.attempt_id, namespace,
            item.record.retirement_checkpoint.seq_no()
        );
        let engine = self.engine.clone();
        let record = item.record.clone();
        let handle = self.cleanup_workers.spawn_blocking_on(
            move || CleanupOutcome::Gone(engine.delete_validator_consensus_namespace(&record)),
            &self.rt,
        );
        self.cleanup_worker_ids.insert(
            handle.id(),
            CleanupWork::Namespace {
                namespace: namespace.clone(),
                session: item.record.session_id.clone(),
                generation: item.generation,
                attempt: item.attempt_id,
            },
        );
        self.cleanup_storage.insert(namespace, (item.attempt_id, storage));
    }

    /// A delete worker finished: a panic, a cancellation or an error counts as
    /// not gone. A confirmed namespace delete erases its record; a confirmed
    /// candidate delete erases its claim; otherwise the attempt is released
    /// and a later cycle sees the durable record or claim again.
    fn on_cleanup_worker_joined(
        &mut self,
        joined: std::result::Result<(tokio::task::Id, CleanupOutcome), tokio::task::JoinError>,
    ) {
        use super::validator_cleanup_gc::V2Outcome;
        let (id, gone, verdict) = match joined {
            Ok((id, CleanupOutcome::Gone(Ok(gone)))) => (id, gone, None),
            Ok((id, CleanupOutcome::Gone(Err(e)))) => {
                log::warn!(target: "validator_manager", "VALCLEANUP delete failed: {e}");
                (id, false, None)
            }
            Ok((id, CleanupOutcome::V2(outcome))) => (id, false, Some(outcome)),
            Err(e) => {
                log::warn!(target: "validator_manager", "VALCLEANUP delete worker did not finish: {e}");
                (e.id(), false, None)
            }
        };
        match self.cleanup_worker_ids.remove(&id) {
            None => {}
            Some(CleanupWork::V2 { namespace, session, generation, attempt }) => {
                let next = match verdict {
                    Some(V2Outcome::Kept(reason)) => {
                        self.note_v2(&namespace, format!("kept: {reason}"));
                        V2Next::Release
                    }
                    Some(V2Outcome::Retained(reason)) => {
                        self.note_v2(&namespace, format!("retained: {reason}"));
                        V2Next::Resume
                    }
                    Some(V2Outcome::Uncertain { intended, previous, reason }) => {
                        self.note_v2(&namespace, format!("uncertain: {reason}"));
                        V2Next::Confirm { intended, previous }
                    }
                    Some(V2Outcome::Gone) => {
                        self.note_v2(&namespace, "gone".into());
                        V2Next::Erase
                    }
                    // A panic or cancellation: whatever it journaled stays
                    // durable; resume from it once its children are done.
                    None => {
                        self.note_v2(&namespace, "attempt did not finish".into());
                        V2Next::Resume
                    }
                };
                self.cleanup_v2_parked
                    .insert(namespace.clone(), V2Parked { session, generation, attempt, next });
                self.advance_v2(&namespace, false);
            }
            Some(CleanupWork::Namespace { namespace, session, generation, attempt }) => {
                if gone {
                    log::info!(target: "validator_manager",
                        "VALCLEANUP delete_done dir={namespace} generation={generation} \
                        attempt={attempt} confirmed_gone=1");
                } else {
                    log::warn!(target: "validator_manager",
                        "VALCLEANUP delete_done dir={namespace} generation={generation} \
                        attempt={attempt} confirmed_gone=0");
                }
                if self.cleanup.on_delete_completed(&namespace, generation, attempt, gone) {
                    self.erase_cleanup_record(&namespace, &session, generation, attempt);
                } else {
                    self.release_cleanup_storage(&namespace, attempt);
                }
            }
            Some(CleanupWork::Claim { session, attempt }) => {
                if gone {
                    match self.engine.erase_candidate_claim(&session) {
                        Ok(()) => log::info!(target: "validator_manager",
                            "VALCLEANUP claim_done session={} attempt={attempt}",
                            session.to_hex_string()),
                        Err(e) => log::warn!(target: "validator_manager",
                            "VALCLEANUP claim erase failed for session={}, retrying: {e}",
                            session.to_hex_string()),
                    }
                }
                self.cleanup.end_claim(&session, attempt);
            }
        }
    }

    /// Hands a reserved authenticated namespace to its journaled attempt. The
    /// manager keeps the reservations for the whole lifecycle; the attempt
    /// and its children only hold shares.
    fn dispatch_v2_reserved(
        &mut self,
        item: consensus_common::validator_cleanup::ReservedDelete,
        storage: consensus_common::StorageCleanupReservation,
        admission: super::finality_recovery_owner::RecoveryReservation,
    ) {
        let held = Arc::new(super::validator_cleanup_gc::CleanupHeld { storage, admission });
        self.cleanup_v2_held.insert(item.record.namespace.clone(), held);
        self.dispatch_v2(item.record, item.generation, item.attempt_id);
    }

    /// Runs one journaled attempt as an owned task under the reservation
    /// `(generation, attempt)`, with a share of the namespace's ownership.
    fn dispatch_v2(
        &mut self,
        record: consensus_common::validator_cleanup::PendingValidatorCleanup,
        generation: u64,
        attempt: u64,
    ) {
        let namespace = record.namespace.clone();
        let session = record.session_id.clone();
        let Some(held) = self.cleanup_v2_held.get(&namespace).cloned() else {
            // Never dispatched without ownership; the attempt stays parked.
            log::error!(target: "validator_manager",
                "VALCLEANUP v2 dispatch without ownership dir={namespace}");
            self.cleanup_v2_parked
                .insert(namespace, V2Parked { session, generation, attempt, next: V2Next::Resume });
            return;
        };
        log::info!(target: "validator_manager",
            "VALCLEANUP v2_attempt dir={namespace} attempt={attempt} journal={:?}",
            journal_state(&record.journal));
        let engine = self.engine.clone();
        let token = super::validator_cleanup_gc::AttemptToken { generation, attempt };
        let handle = self.cleanup_workers.spawn_on(
            async move { CleanupOutcome::V2(engine.execute_v2_cleanup(record, token, held).await) },
            &self.rt,
        );
        self.cleanup_worker_ids
            .insert(handle.id(), CleanupWork::V2 { namespace, session, generation, attempt });
    }

    fn note_v2(&mut self, namespace: &str, outcome: String) {
        log::info!(target: "validator_manager", "VALCLEANUP v2_outcome dir={namespace} {outcome}");
        if self.cleanup_v2_verdicts.len() >= CLEANUP_VERDICTS_KEPT
            && !self.cleanup_v2_verdicts.contains_key(namespace)
        {
            self.cleanup_v2_verdicts.pop_first();
        }
        self.cleanup_v2_verdicts.insert(namespace.to_owned(), outcome);
    }

    /// Whether a child of an earlier attempt (a blocking worker or an owner
    /// request) still holds a share of the namespace's ownership.
    fn v2_draining(&self, namespace: &str) -> bool {
        self.cleanup_v2_held.get(namespace).is_some_and(|held| Arc::strong_count(held) > 1)
    }

    /// Releases the namespace's reservations; only the sole owner can.
    fn release_v2(&mut self, namespace: &str) {
        if let Some(held) = self.cleanup_v2_held.remove(namespace) {
            match Arc::try_unwrap(held) {
                Ok(held) => held.release(),
                // Unreachable once drained; never released implicitly.
                Err(_) => log::error!(target: "validator_manager",
                    "VALCLEANUP v2 reservations still shared at release dir={namespace}"),
            }
        }
    }

    /// Acts on a parked authenticated namespace unless a child of its last
    /// attempt is still running. A refusal releases and an erase proceeds at
    /// once; a resume or confirmation runs only from the tick (`resume`),
    /// at most once per tick. The in-flight entry stays until released.
    fn advance_v2(&mut self, namespace: &str, resume: bool) {
        if self.v2_draining(namespace) {
            if self.cleanup_v2_parked.contains_key(namespace) {
                self.note_v2(namespace, "draining".into());
            }
            return;
        }
        let Some(parked) = self.cleanup_v2_parked.remove(namespace) else {
            return;
        };
        let V2Parked { session, generation, attempt, next } = parked;
        match next {
            V2Next::Release => {
                self.release_v2(namespace);
                self.cleanup.on_delete_completed(namespace, generation, attempt, false);
            }
            V2Next::Erase => {
                if self.cleanup.on_delete_completed(namespace, generation, attempt, true) {
                    self.erase_cleanup_record(namespace, &session, generation, attempt);
                } else {
                    self.release_v2(namespace);
                }
            }
            next if !resume => {
                self.cleanup_v2_parked
                    .insert(namespace.to_owned(), V2Parked { session, generation, attempt, next });
            }
            V2Next::Resume => {
                let token = super::validator_cleanup_gc::AttemptToken { generation, attempt };
                match self.engine.load_validator_cleanup_record(namespace) {
                    Ok(Some(record)) if token.owns(&record) => {
                        self.dispatch_v2(record, generation, attempt)
                    }
                    Ok(Some(_)) => {
                        self.note_v2(namespace, "journal owned by another attempt".into());
                        self.cleanup_v2_parked.insert(
                            namespace.to_owned(),
                            V2Parked { session, generation, attempt, next: V2Next::Resume },
                        );
                    }
                    // Absent, malformed or unreadable: never decided from it.
                    Ok(None) | Err(_) => {
                        self.cleanup_v2_parked.insert(
                            namespace.to_owned(),
                            V2Parked { session, generation, attempt, next: V2Next::Resume },
                        );
                    }
                }
            }
            V2Next::Confirm { intended, previous } => {
                let current = match self.engine.load_validator_cleanup_record(namespace) {
                    Ok(Some(record)) => Some(record),
                    Ok(None) | Err(_) => None,
                };
                let confirmed = match current {
                    Some(current) if current == intended => Some(intended.clone()),
                    Some(current) if current == previous => Some(previous.clone()),
                    _ => None,
                };
                let next = V2Next::Confirm { intended, previous };
                let Some(confirmed) = confirmed else {
                    self.note_v2(namespace, "uncertain: unexpected durable state".into());
                    self.cleanup_v2_parked.insert(
                        namespace.to_owned(),
                        V2Parked { session, generation, attempt, next },
                    );
                    return;
                };
                match self.engine.rewrite_validator_cleanup_record(&confirmed) {
                    Ok(()) => self.dispatch_v2(confirmed, generation, attempt),
                    Err(error) => {
                        self.note_v2(namespace, format!("uncertain: re-write failed: {error}"));
                        self.cleanup_v2_parked.insert(
                            namespace.to_owned(),
                            V2Parked { session, generation, attempt, next },
                        );
                    }
                }
            }
        }
    }

    /// Advances every parked authenticated namespace whose attempt is not
    /// running: each at most once per tick.
    fn resume_parked_v2(&mut self) {
        let running: HashSet<String> = self
            .cleanup_worker_ids
            .values()
            .filter_map(|work| match work {
                CleanupWork::V2 { namespace, .. } => Some(namespace.clone()),
                _ => None,
            })
            .collect();
        let parked: Vec<String> = self
            .cleanup_v2_parked
            .keys()
            .filter(|namespace| !running.contains(*namespace))
            .cloned()
            .collect();
        for namespace in parked {
            self.advance_v2(&namespace, true);
        }
    }

    /// Synced erase of a confirmed-gone record. When this namespace is the
    /// session's last holder (no other durable record, no live or retiring
    /// group, no retirement awaiting its close, no other delete in flight),
    /// the same batch writes the session's candidate cleanup claim. All of
    /// this runs on the manager task, so two namespaces of one session cannot
    /// both skip the claim. Only the acknowledged erase releases the
    /// reservation; a failed check or erase stays in flight for a retry.
    fn erase_cleanup_record(
        &mut self,
        namespace: &str,
        session: &UInt256,
        generation: u64,
        attempt: u64,
    ) {
        let claim = match self.cleanup_erase_claims.get(namespace) {
            Some(decided) => decided.clone(),
            None => {
                let last = !self.session_is_live(session)
                    && !self.cleanup.session_has_other_holders(session, namespace)
                    && match self.engine.session_has_other_cleanup_records(namespace, session) {
                        Ok(other) => !other,
                        Err(e) => {
                            log::warn!(target: "validator_manager",
                                "VALCLEANUP last-holder check failed for dir={namespace}, \
                                retrying: {e}");
                            return;
                        }
                    };
                let decided = last.then(|| session.clone());
                self.cleanup_erase_claims.insert(namespace.to_owned(), decided.clone());
                decided
            }
        };
        let last = claim.is_some();
        let claim = claim.as_ref();
        match self.engine.erase_validator_cleanup_record(namespace, claim) {
            Ok(()) => {
                self.cleanup.on_erase_acknowledged(namespace, generation, attempt);
                self.release_cleanup_storage(namespace, attempt);
                self.cleanup_erase_claims.remove(namespace);
                self.release_v2(namespace);
                log::info!(target: "validator_manager",
                    "VALCLEANUP erase_ack dir={namespace} generation={generation} \
                    attempt={attempt} claim={}", u8::from(last));
            }
            Err(e) => log::warn!(target: "validator_manager",
                "VALCLEANUP erase failed for dir={namespace}, retrying next tick: {e}"),
        }
    }

    fn retry_cleanup_erases(&mut self) {
        for (namespace, session, generation, attempt) in self.cleanup.erasing_entries() {
            self.erase_cleanup_record(&namespace, &session, generation, attempt);
        }
    }

    fn release_cleanup_storage(&mut self, namespace: &str, attempt: u64) {
        if self.cleanup_storage.get(namespace).is_some_and(|(held, _)| *held == attempt) {
            self.cleanup_storage.remove(namespace);
        }
    }

    /// Before a group of `session` is created: the session's candidate
    /// cleanup claim is erased with a successful synced write (never inferred
    /// from an absent read), then its candidate table is admitted. False
    /// defers creation to a later pass.
    fn admit_session_creation(&self, session: &UInt256) -> bool {
        if let Err(e) = self.engine.erase_candidate_claim(session) {
            log::warn!(target: "validator_manager",
                "Deferring session {session:x}: candidate claim invalidation failed: {e}");
            return false;
        }
        if let Err(e) = self.engine.admit_candidate_table(session) {
            log::warn!(target: "validator_manager",
                "Deferring session {session:x}: candidate table admission failed: {e}");
            return false;
        }
        true
    }

    /// Joins every dispatched delete worker, tolerating panics, and feeds each
    /// real completion through the normal path before any reservation drops.
    async fn drain_cleanup_workers(&mut self) {
        while let Some(joined) = self.cleanup_workers.join_next_with_id().await {
            self.on_cleanup_worker_joined(joined);
        }
    }

    /// Shutdown only: waits until no child or owner request of any attempt
    /// still holds a share of an authenticated namespace's reservations. It
    /// starts nothing new; what remains held is kept until the manager drops.
    async fn drain_cleanup_shares(&mut self) {
        while self.cleanup_v2_held.values().any(|held| Arc::strong_count(held) > 1) {
            tokio::time::sleep(Duration::from_millis(10)).await;
            self.drain_cleanup_workers().await;
        }
    }

    /// Retry incomplete materialization even when neither MC nor recovery
    /// ownership changes. A separate deadline prevents short stats intervals
    /// from turning transient history/storage failures into a busy loop.
    async fn wait_next_mc_or_materialization_retry(
        &mut self,
        current: &Arc<storage::block_handle_db::BlockHandle>,
        recovery_generation: u64,
    ) -> Result<Option<Arc<storage::block_handle_db::BlockHandle>>> {
        let mut retry_at = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            if self.engine.check_stop() {
                return Ok(None);
            }
            self.run_cleanup_tick_if_due().await;
            let cleanup_tick_at = self.cleanup_tick_at;
            let cleanup_enabled = self.config.consensus_cleanup_enabled;
            let workers_running = !self.cleanup_workers.is_empty();
            tokio::select! {
                Some(joined) = self.cleanup_workers.join_next_with_id(), if workers_running => {
                    self.on_cleanup_worker_joined(joined);
                }
                _ = tokio::time::sleep_until(cleanup_tick_at), if cleanup_enabled => {
                    self.run_cleanup_tick_if_due().await;
                }
                next = self.engine.wait_next_applied_mc_block(current, None) => {
                    return Ok(Some(next?.0));
                }
                changed = self.engine.wait_finality_recovery_change(recovery_generation) => {
                    changed?;
                    return Ok(Some(current.clone()));
                }
                _ = tokio::time::sleep_until(retry_at) => {
                    for group in self.current_sessions.values().chain(self.future_sessions.values()) {
                        if group.needs_materialization_retry().await {
                            return Ok(Some(current.clone()));
                        }
                    }
                    retry_at = tokio::time::Instant::now() + Duration::from_secs(1);
                }
                _ = tokio::time::sleep(self.config.update_interval.max(Duration::from_millis(10))) => {
                    self.stats().await;
                }
            }
        }
    }

    fn create(
        engine: Arc<dyn EngineOperations>,
        rt: tokio::runtime::Handle,
        config: ValidatorManagerConfig,
    ) -> Self {
        engine.set_validation_status(ValidationStatus::Disabled);
        ValidatorManagerImpl {
            engine: engine.clone(),
            startup_recovery_gate: None,
            rt: rt.clone(),
            current_sessions: HashMap::default(),
            future_sessions: HashMap::default(),
            retiring_groups: Vec::new(),
            pending_cleanup_records: Vec::new(),
            fence_dirty: false,
            cleanup: Default::default(),
            cleanup_tick_at: tokio::time::Instant::now() + config.consensus_cleanup_tick,
            cleanup_workers: tokio::task::JoinSet::new(),
            cleanup_worker_ids: HashMap::new(),
            cleanup_storage: HashMap::new(),
            cleanup_claim_cursor: String::new(),
            cleanup_v2_verdicts: std::collections::BTreeMap::new(),
            cleanup_v2_parked: HashMap::new(),
            cleanup_v2_held: HashMap::new(),
            cleanup_erase_claims: HashMap::new(),
            retiring_observers: Vec::new(),
            lifecycle_errors: HashSet::new(),
            background_tasks: tokio_util::task::TaskTracker::new(),
            background_panicked: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            owned_current_shards: 0,
            owned_future_shards: 0,
            validator_list_status: ValidatorListStatus::default(),
            config,
            destroyed_sessions: HashSet::new(),
            sync_complete: false,
            last_metrics_dump: tokio::time::Instant::now(),
            block_sync_observers: HashMap::new(),
        }
    }

    #[cfg(test)]
    fn override_with_emulator_consensus_options(
        &self,
        shard: &ShardIdent,
        original_consensus: &str,
        simplex_options: Option<SimplexSessionOptions>,
    ) -> Option<ConsensusOptions> {
        let emulator_config = self.config.test_emulator_consensus.as_ref()?;
        assert!(
            !emulator_config.validator_keys.is_empty(),
            "test emulator consensus requires at least one validator key"
        );

        log::warn!(
            target: "validator_manager",
            "TEST CONSENSUS OVERRIDE: forcing emulator consensus for shard={} \
             original_consensus={}",
            shard,
            original_consensus
        );
        let mut emulator_options =
            EmulatorConsensusOptions::fixed_local(emulator_config.validator_keys.clone());
        emulator_options.emulator_options.initial_params.slot_interval = EmulatorDelaySpec::new(
            emulator_config.slot_interval_min_ms,
            emulator_config.slot_interval_max_ms,
            emulator_config.slot_interval_reliability,
        );
        if let Some(simplex_options) = simplex_options {
            emulator_options.simplex_options = simplex_options;
        }
        Some(ConsensusOptions::Emulator(emulator_options))
    }

    fn load_destroyed_sessions(&mut self) -> Result<()> {
        let persisted = self.engine.load_destroyed_session_ids()?;
        self.destroyed_sessions = persisted.into_iter().collect();
        if !self.destroyed_sessions.is_empty() {
            log::info!(
                target: "validator_manager",
                "Loaded {} destroyed session IDs from persistent storage",
                self.destroyed_sessions.len()
            );
        }
        Ok(())
    }

    fn persist_destroyed_sessions(&self) -> Result<()> {
        self.engine.save_destroyed_session_ids(&self.destroyed_sessions)
    }

    /// An all-shards rotation (as T0 `updated_init_block`): capture the
    /// fence, save the rotation block synced, then remove exactly the
    /// captured sessions with a synced fence write, publishing the pruned
    /// fence in memory only after that write succeeds. Cleanup records are
    /// never touched. A failed write prunes nothing and is latched.
    fn rotate_init_block(&mut self, block: &BlockIdExt) -> Result<()> {
        let captured = self.destroyed_sessions.clone();
        if let Err(error) = self.engine.save_last_rotation_block_id(block) {
            self.lifecycle_errors.insert(format!("init block rotation: {error}"));
            return self.check_lifecycle_errors();
        }
        if captured.is_empty() {
            return Ok(());
        }
        let remaining: HashSet<UInt256> =
            self.destroyed_sessions.difference(&captured).cloned().collect();
        if let Err(error) = self.engine.persist_validator_retirement(&remaining, &[]) {
            self.lifecycle_errors.insert(format!("fence pruning: {error}"));
            return self.check_lifecycle_errors();
        }
        log::debug!(target: "validator_manager",
            "Pruned {} destroyed session IDs at rotation {block}", captured.len());
        self.destroyed_sessions = remaining;
        Ok(())
    }

    /// One read decision over the custody, empty when none is configured.
    fn with_custody<R>(
        &self,
        decide: impl FnOnce(&rtos_pq_consensus::PqConsensusCustody) -> R,
    ) -> R {
        match self.engine.pq_consensus_custody() {
            Some(custody) => custody.read(decide),
            None => decide(&rtos_pq_consensus::PqConsensusCustody::default()),
        }
    }

    /// The validator identity this node is a member of `set` as, the reference
    /// node's get_validator_id, at a fresh custody-clock read. A post-quantum
    /// descriptor is ours only while custody holds, unexpired, the exact key it
    /// records; a network or operator key never makes this node a member. A
    /// classical descriptor is matched by the local classical keys; whether
    /// such a set can run a group is decided at group admission.
    fn local_validator_id(&self, set: &[ValidatorDescr]) -> Option<UInt256> {
        let now = self.engine.pq_custody_now();
        let classical = self.validator_list_status.classical_keys();
        let permanent = std::collections::BTreeSet::new();
        self.with_custody(|custody| {
            rtos_pq_consensus::local_consensus_member(set, &classical, &permanent, custody, now)
        })
    }

    /// The observer transport identities this node may join `committee` with:
    /// the descriptors of the previous, current and next total sets that are
    /// not members of the committee and that this node holds, as the reference
    /// node's get_observer_adnl_ids selects them.
    fn local_observers(
        &self,
        config: &rtos_block::ConfigParams,
        committee: &[ValidatorDescr],
    ) -> Result<Vec<consensus_common::session_runtime::AuthorizedObserver>> {
        let now = self.engine.pq_custody_now();
        let classical = self.validator_list_status.classical_keys();
        let permanent = std::collections::BTreeSet::new();
        self.with_custody(|custody| {
            consensus_common::session_runtime::AuthorizedObserver::select(
                config,
                committee,
                |descriptor| {
                    rtos_pq_consensus::local_consensus_descriptor(
                        descriptor, &classical, &permanent, custody, now,
                    )
                },
            )
        })
    }

    /// Whether custody makes this node a member of the current or next total
    /// set, and of any of the previous, current and next total sets.
    fn custody_set_roles(&self, config: &rtos_block::ConfigParams) -> Result<(bool, bool)> {
        if self.engine.pq_consensus_custody().is_none() {
            return Ok((false, false));
        }
        let (current, next, previous) =
            (config.validator_set()?, config.next_validator_set()?, config.prev_validator_set()?);
        let now = self.engine.pq_custody_now();
        let none = std::collections::BTreeSet::new();
        Ok(self.with_custody(|custody| {
            let member = |set: &ValidatorSet| {
                rtos_pq_consensus::local_consensus_member(set.list(), &none, &none, custody, now)
                    .is_some()
            };
            let active = member(&current) || member(&next);
            (active, active || member(&previous))
        }))
    }

    /// The local admission of a Simplex session over `committee`: as the
    /// validator the caller selected, or, where the protocol puts observers
    /// in the private overlay, as the first authorized observer.
    #[allow(clippy::too_many_arguments)]
    fn simplex_session_runtime(
        &self,
        mc_state: &ShardStateStuff,
        shard: &ShardIdent,
        catchain_seqno: u32,
        vertical_seqno: u32,
        last_key_block_seqno: u32,
        committee: &[ValidatorDescr],
        selected: Option<&UInt256>,
        observers_in_overlay: bool,
    ) -> Result<Option<Arc<consensus_common::session_runtime::AuthenticatedSessionRuntime>>> {
        use consensus_common::session_runtime::{
            AuthenticatedSessionRuntime, LocalAdmission, SessionNetworkPin,
        };
        let config = mc_state.config_params()?;
        let admission = match selected {
            Some(validator_id) => {
                let index = committee
                    .iter()
                    .position(|member| member.validator_id().is_ok_and(|id| &id == validator_id))
                    .ok_or_else(|| error!("Selected validator is not a committee member"))?;
                LocalAdmission::Validator {
                    validator_id: validator_id.clone(),
                    index: u32::try_from(index)?,
                }
            }
            None if observers_in_overlay => {
                match self.local_observers(config, committee)?.into_iter().next() {
                    Some(observer) => LocalAdmission::Observer(observer),
                    None => return Ok(None),
                }
            }
            None => return Ok(None),
        };
        let runtime = AuthenticatedSessionRuntime::from_authenticated_admission(
            SessionNetworkPin {
                global_id: mc_state.state()?.global_id(),
                zerostate: self.engine.zerostate_id()?.clone(),
            },
            config,
            rtos_api::session_identity::SessionCoordinates {
                shard,
                catchain_seqno,
                vertical_seqno,
                last_key_block_seqno,
                new_catchain_ids: false,
            },
            committee.to_vec(),
            admission,
        )?
        .bind_recovery_anchor(mc_state.block_id().clone())?;
        Ok(Some(Arc::new(runtime)))
    }

    /// The reference node's group-creation checks once the caller selected
    /// this node as `selected`, in its order: membership read again at a fresh
    /// custody clock (a key that expired since makes this node a member no
    /// longer), a committee that is not post-quantum, then the exact custody
    /// signer at a fresh clock. Each refusal is logged and retried at the next
    /// update; none fences the session.
    fn admit_validator_group(
        &self,
        shard: &ShardIdent,
        committee: &[ValidatorDescr],
        selected: &UInt256,
        consensus_options: &ConsensusOptions,
    ) -> Option<AdmittedValidator> {
        let Some(validator_id) =
            self.local_validator_id(committee).filter(|validator_id| validator_id == selected)
        else {
            log::error!(target: "validator_manager",
                "refusing to create validator group for {shard}: this node no longer holds an \
                 unexpired consensus key the set records for it");
            return None;
        };
        let (index, descriptor) = committee
            .iter()
            .enumerate()
            .find(|(_, member)| member.validator_id().is_ok_and(|id| id == validator_id))?;
        let index = u32::try_from(index).ok()?;
        let Some(key) = descriptor.pq_key() else {
            // A classical committee runs only the test emulator.
            #[cfg(test)]
            if matches!(consensus_options, ConsensusOptions::Emulator(_)) {
                let transport_key = self.validator_list_status.classical_key(&validator_id)?;
                return Some(AdmittedValidator { index, transport_key, signer: None });
            }
            let _ = consensus_options;
            log::error!(target: "validator_manager",
                "refusing to create validator group for {shard}: the set is not post-quantum; \
                 validation for this shard is disabled until the set is post-quantum");
            return None;
        };
        let now = self.engine.pq_custody_now();
        let signer = self.with_custody(|custody| {
            simplex::SessionSigner::from_custody_match(custody, &validator_id, descriptor, now).ok()
        });
        let Some(signer) = signer else {
            log::error!(target: "validator_manager",
                "refusing to create validator group for {shard}: this node is post-quantum \
                 validator {} but does not custody, unexpired, the exact consensus key the set \
                 records for it (key {}); validation for this shard is disabled until the key is \
                 provisioned",
                validator_id.to_hex_string(), key.key_id.to_hex_string());
            return None;
        };
        // Transport is not a membership predicate. Without the descriptor's
        // transport key loaded this node cannot construct the group at all, so
        // construction is deferred and retried, unfenced.
        let adnl = descriptor.adnl_addr().ok()?;
        let Some(transport_key) = self.engine.adnl_key_by_id(&adnl) else {
            log::warn!(target: "validator_manager",
                "deferring validator group for {shard}: transport key {adnl} of validator {} is \
                 not loaded", validator_id.to_hex_string());
            return None;
        };
        Some(AdmittedValidator { index, transport_key, signer: Some(signer) })
    }

    /// The transport key and signer a new group of a session is created with.
    /// A validator group passes the reference creation-time checks; an
    /// observer group joins with its authorized observer transport key and
    /// takes no signer. `None` means no group is created now: it is retried at
    /// the next update and the session is not fenced.
    fn admit_session_group(
        &self,
        shard: &ShardIdent,
        committee: &[ValidatorDescr],
        selected: Option<&UInt256>,
        runtime: Option<&consensus_common::session_runtime::AuthenticatedSessionRuntime>,
        consensus_options: &ConsensusOptions,
    ) -> Option<(PublicKey, Option<simplex::SessionSigner>)> {
        use consensus_common::session_runtime::LocalRole;
        if let Some(runtime) = runtime.filter(|runtime| runtime.local_role() == LocalRole::Observer)
        {
            let Some(key) = self.engine.adnl_key_by_id(runtime.local_adnl()) else {
                log::warn!(target: "validator_manager",
                    "deferring observer group for {shard}: transport key {} is not loaded",
                    runtime.local_adnl());
                return None;
            };
            return Some((key, None));
        }
        let admitted =
            self.admit_validator_group(shard, committee, selected?, consensus_options)?;
        if runtime
            .is_some_and(|runtime| runtime.local_role() != LocalRole::Validator(admitted.index))
        {
            log::error!(target: "validator_manager",
                "refusing to create validator group for {shard}: this node no longer holds an \
                 unexpired consensus key the set records for it");
            return None;
        }
        Some((admitted.transport_key, admitted.signer))
    }

    /// Try to spawn a `BlockSyncObserver` for a shard we are not validating
    ///
    /// Requires `enable_observers=true` (caller has already checked via `Some(bs_params)`)
    /// and a descriptor of the previous, current or next total set outside the
    /// session committee that this node holds. `Err` carries a reason
    #[allow(clippy::too_many_arguments)]
    fn try_spawn_observer(
        &mut self,
        shard: &ShardIdent,
        session_id: &UInt256,
        mc_state: &ShardStateStuff,
        committee: &[ValidatorDescr],
        bs_params: consensus_common::BlockSyncOverlayParams,
        use_quic: bool,
        proto_version: u32,
    ) -> Result<()> {
        // (1) The observer identity: a descriptor of the previous, current or
        // next total set that is not a committee member and that this node
        // holds, selected by custody (or a classical key for a classical one).
        // One observer per session joins with the first selected identity.
        let observers = self.local_observers(mc_state.config_params()?, committee)?;
        let local_adnl_id =
            observers.first().map(|observer| observer.adnl().clone()).ok_or_else(|| {
                error!(
                    "this node holds no descriptor of a previous, current or next validator \
                     outside this committee"
                )
            })?;

        // (3) Resolve the ADNL KeyOption from the adnl node.
        let overlay_node = self
            .engine
            .overlay_node()
            .ok_or_else(|| error!("engine.overlay_node() returned None"))?;
        let local_adnl_key = self.engine.adnl_key_by_id(&local_adnl_id).ok_or_else(|| {
            error!("local ADNL key {local_adnl_id} not registered with adnl node yet")
        })?;

        // (4) Spawn the observer with the session's negotiated proto version
        let observer = super::block_sync_observer::BlockSyncObserver::create(
            self.rt.clone(),
            overlay_node,
            local_adnl_key,
            bs_params,
            session_id.clone(),
            shard.clone(),
            self.engine.clone(),
            use_quic,
            /*broadcast_hops*/ None,
            proto_version,
        )?;
        log::info!(
            target: "validator_manager",
            "SESSION_LIFECYCLE: observer_started shard={shard} session_id={:x}",
            session_id,
        );
        self.block_sync_observers.insert(session_id.clone(), observer);
        Ok(())
    }

    /// Register the local node in a validator list and return its hash if matched.
    ///
    /// Calls [`EngineOperations::set_validator_list`] which checks local keys against the
    /// validator set and attempts to set up ADNL/overlay infrastructure.
    /// Membership is cached in [`ValidatorListStatus`] independently from transport readiness.
    ///
    /// Returns `Ok(None)` only when the local node is genuinely not in the validator set.
    async fn update_single_validator_list(
        &mut self,
        validator_list: &[ValidatorDescr],
        name: &str,
    ) -> Result<Option<ValidatorListHash>> {
        let list_id = match compute_validator_list_id(validator_list, None)? {
            None => return Ok(None),
            Some(l) => l,
        };
        if self.validator_list_status.contains_list(&list_id)
            && self.engine.validator_network().has_validator_list_context(&list_id)
        {
            return Ok(Some(list_id));
        }

        let nodes_res: Vec<ConsensusNode> = validator_list
            .iter()
            .map(validatordescr_to_consensus_node)
            .collect::<Result<Vec<ConsensusNode>>>()?;

        log::info!(target: "validator_manager", "Updating {} validator list (id {:x}):", name, list_id);
        for x in &nodes_res {
            log::debug!(target: "validator_manager", "pk: {}, pk_id: {}, adnl_id: {}",
                format!("{:?}", x.public_key),
                hex::encode(x.public_key.id().data()),
                hex::encode(x.adnl_id.data())
            );
        }

        match self.engine.set_validator_list(list_id.clone(), &nodes_res).await? {
            ValidatorListOutcome::Selected { key, matching_keys } => {
                self.validator_list_status.add_list(list_id.clone(), matching_keys);
                let context_ready =
                    self.engine.validator_network().has_validator_list_context(&list_id);
                if context_ready {
                    log::info!(target: "validator_manager", "Local node: pk_id: {} id: {}",
                        hex::encode(key.pub_key().unwrap()),
                        hex::encode(key.id().data())
                    );
                } else {
                    log::warn!(
                        target: "validator_manager",
                        "Local node is a {} validator by pubkey (id {:x}, key {}), \
                         but ADNL/network context is still pending; continuing with membership only",
                        name,
                        list_id,
                        hex::encode(key.id().data())
                    );
                }
                Ok(Some(list_id))
            }
            ValidatorListOutcome::NotValidator => {
                log::info!(target: "validator_manager", "Local node is not a {} validator", name);
                Ok(None)
            }
        }
    }

    /// Refresh the current and next validator lists from the masterchain state.
    ///
    /// Returns `true` if the local node belongs to at least one validator set (current or
    /// next), `false` if it is not a validator at all. The caller uses `false` to disable
    /// validation entirely.
    ///
    /// Mirrors the implicit list-management in C++ `update_shards()` where `get_validator()`
    /// is called per-shard. In Rust, we pre-resolve membership once per update round.
    async fn update_validator_lists(&mut self, mc_state: &ShardStateStuff) -> Result<bool> {
        let (validator_set, next_validator_set, prev_validator_set) =
            match mc_state.state()?.read_custom()? {
                None => return Ok(false),
                Some(state) => (
                    state.config.validator_set()?,
                    state.config.next_validator_set()?,
                    state.config.prev_validator_set()?,
                ),
            };

        self.validator_list_status.curr =
            self.update_single_validator_list(validator_set.list(), "current").await?;
        self.validator_list_status.curr_utime_since = Some(validator_set.utime_since());
        if let Some(id) = self.validator_list_status.curr.as_ref() {
            self.engine.activate_validator_list(id.clone())?;
            if !self.engine.validator_network().has_validator_list_context(id) {
                log::warn!(
                    target: "validator_manager",
                    "Current validator list {:x} is selected by pubkey but transport context is \
                     still pending; session ownership remains active and startup will retry",
                    id
                );
            }
        }
        self.validator_list_status.next =
            self.update_single_validator_list(next_validator_set.list(), "next").await?;
        self.validator_list_status.next_utime_since = Some(next_validator_set.utime_since());

        // Register prev to keep the local ADNL key alive for prev-only observer mode
        self.validator_list_status.prev =
            self.update_single_validator_list(prev_validator_set.list(), "prev").await?;
        self.validator_list_status.prev_utime_since = Some(prev_validator_set.utime_since());

        metrics::gauge!("rtos_node_validator_in_current_set")
            .set(self.validator_list_status.curr.is_some() as u8 as f64);
        metrics::gauge!("rtos_node_validator_in_next_set")
            .set(self.validator_list_status.next.is_some() as u8 as f64);
        metrics::gauge!("rtos_node_validator_in_prev_set")
            .set(self.validator_list_status.prev.is_some() as u8 as f64);
        Ok(self.validator_list_status.curr.is_some()
            || self.validator_list_status.next.is_some()
            || self.validator_list_status.prev.is_some())
    }

    async fn is_active_shard(&self, shard: &ShardIdent) -> bool {
        for group in self.current_sessions.values().chain(self.future_sessions.values()) {
            if group.shard() == shard {
                match group.get_status().await {
                    ValidatorGroupStatus::Sync | ValidatorGroupStatus::Active => return true,
                    _ => (),
                }
            }
        }
        false
    }

    async fn garbage_collect_lists(&mut self) -> Result<()> {
        log::trace!(target: "validator_manager", "Garbage collect lists");
        let mut lists_gc = self.validator_list_status.known_hashes();

        for id in self.current_sessions.values().chain(self.future_sessions.values()) {
            lists_gc.remove(&id.get_validator_list_id());
        }

        for id in lists_gc {
            if !self.validator_list_status.actual_or_coming(&id) {
                log::trace!(target: "validator_manager", "Removing validator list: {:x}", id);
                self.validator_list_status.remove_list(&id);
                self.engine.remove_validator_list(id.clone())?;
                log::trace!(target: "validator_manager", "Validator list removed: {:x}", id);
            } else {
                log::trace!(target: "validator_manager", "Validator list is still actual: {:x}", id);
            }
        }
        log::trace!(target: "validator_manager", "Garbage collect lists -- ok");

        Ok(())
    }

    async fn garbage_collect(&mut self) {
        if let Err(e) = self.garbage_collect_lists().await {
            log::error!(target: "validator_manager", "Error while garbage collecting validator lists: `{}`", e);
        }
    }

    /// Notify simplex sessions with the currently applied top for their session shard.
    ///
    /// This should be called after each masterchain state update:
    /// - masterchain simplex sessions receive the applied masterchain block id
    /// - shard simplex sessions receive the shard top currently registered in masterchain
    ///
    /// This is an applied-top signal, not a session-local finalization signal.
    /// Current MC sessions use it to track accepted/applied head ordering, while
    /// local finalized progression remains owned by the Simplex session itself.
    ///
    /// Delivery is enqueued into each validator group's ordered action queue without
    /// blocking the manager's hot path.
    ///
    /// # Arguments
    /// * `mc_state` - Current applied masterchain state
    /// * `mc_state_extra` - Current masterchain extra containing shard descriptors
    fn notify_simplex_sessions_applied_tops(
        &self,
        mc_state: &ShardStateStuff,
        mc_state_extra: &McStateExtra,
    ) {
        consensus_common::check_execution_time!(5000); // 5ms max

        for (session_id, group) in self.current_sessions.iter() {
            if !group.is_simplex() {
                continue;
            }
            let applied_top =
                match applied_top_for_session_shard(mc_state, mc_state_extra, group.shard()) {
                    Ok(Some(block_id)) => block_id,
                    Ok(None) => {
                        log::trace!(
                            target: "validator_manager",
                            "Skipping applied-top notify for session {:x} (shard {}): \
                            no matching top in current MC state",
                            session_id,
                            group.shard(),
                        );
                        continue;
                    }
                    Err(e) => {
                        log::warn!(
                            target: "validator_manager",
                            "Failed to lookup shard {} in MC state for session {:x}: {}",
                            group.shard(),
                            session_id,
                            e
                        );
                        continue;
                    }
                };
            log::trace!(
                target: "validator_manager",
                "Notifying session {:x} (shard {}) about applied top: {}",
                session_id,
                group.shard(),
                applied_top
            );
            group.notify_mc_finalized(applied_top);
            log::trace!(
                target: "validator_manager",
                "Applied-top notification queued for session {:x}",
                session_id
            );
        }
    }

    /// Retires a group that is no longer active or pending: fence the session
    /// against recreation and record a durable cleanup intent. The group then
    /// closes WITHOUT deleting its namespace; deletion happens only later under
    /// the checkpoint-bound cleanup gate. Mirrors the reference retirement in
    /// `update_shards()`.
    fn retire_group(&mut self, id: UInt256, group: Arc<ValidatorGroup>) {
        self.destroyed_sessions.insert(id.clone());
        self.fence_dirty = true;
        let generation = match self.cleanup_record(&id, &group) {
            Ok(record) => {
                let generation = self.cleanup.on_group_retired(&record);
                let namespace = record.namespace.clone();
                self.pending_cleanup_records.push(record);
                Some((namespace, generation))
            }
            Err(error) => {
                // Without a record the namespace is only ever kept, never deleted.
                log::error!(target: "validator_manager",
                    "No cleanup record for retired session {id:x}; its namespace is retained: {error}");
                None
            }
        };
        self.retire_group_generation(id, group, generation);
    }

    /// The durable cleanup record for a retiring group, bound to the last
    /// applied masterchain block as its retirement checkpoint.
    fn cleanup_record(
        &self,
        id: &UInt256,
        group: &ValidatorGroup,
    ) -> Result<consensus_common::validator_cleanup::PendingValidatorCleanup> {
        use consensus_common::validator_cleanup::{make_record, NamespaceLayout};
        let checkpoint = self
            .engine
            .load_last_applied_mc_block_id()?
            .ok_or_else(|| error!("No applied masterchain block to bind the retirement to"))?;
        // The configured protocol decides the layout: an authenticated group
        // whose runtime is missing is never mistaken for a V1 directory.
        let authenticated = group.configured_authenticated_protocol()
            || group.authenticated_runtime().is_some_and(|runtime| {
                runtime.protocol()
                    == consensus_common::simplex_protocol::SimplexProtocol::PrivateObserversPlumtree
            });
        let layout = if authenticated {
            let runtime = group
                .authenticated_runtime()
                .ok_or_else(|| error!("Authenticated group without its runtime"))?;
            match runtime.local_role() {
                consensus_common::session_runtime::LocalRole::Validator(_) => {
                    NamespaceLayout::V2Validator
                }
                consensus_common::session_runtime::LocalRole::Observer => {
                    NamespaceLayout::V2Observer(UInt256::from(*runtime.local_adnl().data()))
                }
            }
        } else {
            NamespaceLayout::V1
        };
        let record = make_record(id, &layout, group.shard(), group.cc_seqno(), &checkpoint)?;
        if layout == NamespaceLayout::V1 {
            return Ok(record);
        }
        // An authenticated namespace is re-verified from history before any
        // delete, so its record carries the identity that re-authenticates
        // it. Without a recovery binding no record is written: the fence
        // keeps the session and its namespace is only ever retained.
        let runtime = group
            .authenticated_runtime()
            .ok_or_else(|| error!("Authenticated namespace without its runtime"))?;
        let binding = runtime
            .recovery_binding()
            .cloned()
            .ok_or_else(|| error!("Authenticated runtime without a recovery binding"))?;
        record.with_identity(consensus_common::validator_cleanup::CleanupIdentity {
            pin: runtime.pin().clone(),
            binding,
            local_adnl: UInt256::from(*runtime.local_adnl().data()),
        })
    }

    /// Retires the old group of a replaced authenticated admission. The
    /// session stays live, so the fence is unchanged. A v2 observer namespace
    /// is keyed by its local ADNL: when the replacement no longer uses it
    /// (another ADNL, or a validator role), the old namespace is orphaned
    /// and gets a durable cleanup record, persisted before the old group
    /// closes. Any other replacement reuses its namespace and records nothing.
    fn retire_replaced_admission(
        &mut self,
        id: UInt256,
        old: Arc<ValidatorGroup>,
        replacement: &consensus_common::session_runtime::AuthenticatedSessionRuntime,
    ) {
        use consensus_common::{session_runtime::LocalRole, validator_cleanup::NamespaceLayout};
        let layout = |runtime: &consensus_common::session_runtime::AuthenticatedSessionRuntime| {
            match runtime.local_role() {
                LocalRole::Validator(_) => NamespaceLayout::V2Validator,
                LocalRole::Observer => {
                    NamespaceLayout::V2Observer(UInt256::from(*runtime.local_adnl().data()))
                }
            }
        };
        let orphaned = old.authenticated_runtime().is_some_and(|previous| {
            matches!(layout(&previous), NamespaceLayout::V2Observer(_))
                && layout(&previous) != layout(replacement)
        });
        let generation = if orphaned {
            match self.cleanup_record(&id, &old) {
                Ok(record) => {
                    let generation = self.cleanup.on_group_retired(&record);
                    let namespace = record.namespace.clone();
                    self.pending_cleanup_records.push(record);
                    Some((namespace, generation))
                }
                Err(error) => {
                    log::error!(target: "validator_manager",
                        "No cleanup record for the orphaned observer namespace of {id:x}; \
                        it is retained: {error}");
                    None
                }
            }
        } else {
            None
        };
        self.retire_group_generation(id, old, generation);
    }

    // Replacing an authenticated admission keeps the session ID live. Only the
    // old instance is retired; the ordinary destruction blacklist is unchanged.
    fn retire_group_generation(
        &mut self,
        id: UInt256,
        group: Arc<ValidatorGroup>,
        generation: Option<(String, u64)>,
    ) {
        if !self.retiring_groups.iter().any(|(_, old, _)| Arc::ptr_eq(old, &group)) {
            let consensus = if group.is_simplex() { "simplex" } else { "catchain" };
            self.retiring_groups.push((id, group, generation));
            metrics::counter!("rtos_node_validator_session_destroyed_total", "consensus" => consensus).increment(1);
        }
    }

    fn retire_observer(&mut self, id: &UInt256) {
        if let Some(observer) = self.block_sync_observers.remove(id) {
            self.retiring_observers.push(observer.clone());
            observer.stop();
        }
    }

    // Every object is registered before the first await. A cancelled caller can
    // resume this drain without forgetting siblings or changing their policy.
    async fn drain_retiring(&mut self) -> Result<()> {
        // The fence and every new cleanup record are durable before any
        // retiring group may begin to close, so a crash mid-close always
        // leaves a record for its namespace.
        if self.fence_dirty || !self.pending_cleanup_records.is_empty() {
            if let Err(error) = self.engine.persist_validator_retirement(
                &self.destroyed_sessions,
                &self.pending_cleanup_records,
            ) {
                // No group closes without its durable record; latch like any
                // other teardown failure so every aggregator reports it.
                self.lifecycle_errors.insert(format!("retirement persistence: {error}"));
                return self.check_lifecycle_errors();
            }
            self.pending_cleanup_records.clear();
            self.fence_dirty = false;
        }
        let rt = self.rt.clone();
        let groups = self.retiring_groups.clone();
        let results = futures::future::join_all(
            groups.iter().map(|(_, group, _)| group.clone().stop(rt.clone(), false)),
        )
        .await;
        for ((id, group, generation), result) in groups.into_iter().zip(results) {
            match result {
                Ok(()) => {
                    // Condition D: only a verified teardown confirms the close
                    // of the incarnation the record was retired at.
                    if let Some((namespace, generation)) = generation {
                        if group.storage_close_verified() {
                            self.cleanup.on_close_confirmed(&namespace, generation);
                        }
                    }
                    self.retiring_groups.retain(|(_, old, _)| !Arc::ptr_eq(old, &group));
                    if !self.is_active_shard(group.shard()).await {
                        self.engine.remove_last_validation_time(group.shard());
                        self.engine.remove_last_collation_time(group.shard());
                    }
                }
                Err(error) => {
                    self.lifecycle_errors.insert(format!("session {id:x}: {error}"));
                }
            }
        }
        for observer in self.retiring_observers.clone() {
            match observer.stop_and_wait().await {
                Ok(()) => self.retiring_observers.retain(|old| !Arc::ptr_eq(old, &observer)),
                Err(error) => {
                    self.lifecycle_errors.insert(format!("observer: {error}"));
                }
            }
        }
        self.check_lifecycle_errors()
    }

    fn report_teardown_failure(&self, error: String) {
        let drained = self.current_sessions.is_empty()
            && self.future_sessions.is_empty()
            && self.block_sync_observers.is_empty()
            && self.background_tasks.is_empty()
            && self.retiring_observers.iter().all(|observer| observer.teardown_drained())
            && self.retiring_groups.iter().all(|(_, group, _)| group.teardown_drained());
        self.engine.report_service_failure(
            if drained { Engine::MASK_SERVICE_VALIDATOR_MANAGER } else { 0 },
            error,
        );
    }

    fn check_lifecycle_errors(&self) -> Result<()> {
        if !self.lifecycle_errors.is_empty() {
            let mut errors: Vec<_> = self.lifecycle_errors.iter().cloned().collect();
            errors.sort();
            fail!("validator teardown failed: {}", errors.join("; "));
        }
        Ok(())
    }

    async fn stop_and_remove_sessions(
        &mut self,
        sessions_to_remove: &HashSet<UInt256>,
    ) -> Result<()> {
        for id in sessions_to_remove {
            if let Some(group) = self.current_sessions.remove(id) {
                self.retire_group(id.clone(), group);
            }
            if let Some(group) = self.future_sessions.remove(id) {
                self.retire_group(id.clone(), group);
            }
            if self.destroyed_sessions.insert(id.clone()) {
                self.fence_dirty = true;
            }
        }
        self.drain_retiring().await
    }

    async fn replace_current_sessions(
        &mut self,
        selected: HashMap<UInt256, Arc<ValidatorGroup>>,
    ) -> Result<()> {
        let old = std::mem::replace(&mut self.current_sessions, selected);
        for (id, group) in old {
            if !self.current_sessions.get(&id).is_some_and(|new| Arc::ptr_eq(new, &group)) {
                self.retire_group(id, group);
            }
        }
        self.drain_retiring().await
    }

    async fn cull_stale_future_sessions(&mut self) -> Result<()> {
        let stale_ids: Vec<_> = self
            .future_sessions
            .iter()
            .filter(|(_, future)| {
                self.current_sessions.values().any(|current| {
                    let equal = current.shard() == future.shard();
                    let related = current.shard().is_ancestor_for(future.shard())
                        || future.shard().is_ancestor_for(current.shard());
                    (equal && current.cc_seqno() >= future.cc_seqno())
                        || (related && current.cc_seqno() > future.cc_seqno())
                })
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale_ids {
            let group = self.future_sessions.remove(&id).expect("collected future owner");
            self.retire_group(id, group);
        }
        self.drain_retiring().await
    }

    fn spawn_split_queue_precalculation(&self, id: BlockIdExt) {
        let engine = self.engine.clone();
        let panicked = self.background_panicked.clone();
        self.background_tasks.spawn_on(async move {
            let work = async move {
                match OutMsgQueueInfoStuff::precalc_split_queues(&engine, &id).await {
                    Ok(()) => log::trace!(target: "validator_manager", "Split queues precalculated for {id}"),
                    Err(error) => log::error!(target: "validator_manager", "Cannot precalculate split queues for {id}: {error}"),
                }
            };
            if let Err(payload) = std::panic::AssertUnwindSafe(work).catch_unwind().await {
                panicked.store(true, Ordering::Release);
                std::panic::resume_unwind(payload);
            }
        }, &self.rt);
    }

    async fn compute_session_options(
        &mut self,
        mc_state_extra: &McStateExtra,
        catchain_config: &CatchainConfig,
    ) -> Result<SessionsOptions> {
        let consensus_config = match mc_state_extra.config.config(29)? {
            Some(ConfigParamEnum::ConfigParam29(consensus_config)) => consensus_config,
            _ => fail!("no CatchainConfig in config_params"),
        };
        let accelerated_consensus_config = self.get_accelerated_consensus_config(mc_state_extra);

        // Compute session options for masterchain (accelerated consensus controlled by constant)
        let mc_accelerated_consensus_enabled = MC_ACCELERATED_CONSENSUS_ENABLED
            && accelerated_consensus_config.as_ref().map(|x| x.enabled).unwrap_or(false);
        let mc_options = get_session_options(
            &consensus_config,
            catchain_config,
            mc_accelerated_consensus_enabled,
            &accelerated_consensus_config,
        );

        // Compute session options for shards (accelerated consensus may be enabled)
        let shard_accelerated_consensus_enabled =
            accelerated_consensus_config.as_ref().map(|x| x.enabled).unwrap_or(false);
        let shard_options = get_session_options(
            &consensus_config,
            catchain_config,
            shard_accelerated_consensus_enabled,
            &accelerated_consensus_config,
        );
        let mc_session_id_options_serialized =
            rtos_api::session_identity::session_options_bytes(&consensus_config, catchain_config)?;
        let mc_session_id_hash = UInt256::calc_file_hash(&mc_session_id_options_serialized);
        let shard_session_id_hash = mc_session_id_hash.clone();
        let shard_session_id_options_serialized = mc_session_id_options_serialized.clone();

        log::trace!(
            target: "validator_manager",
            "MC SessionOptions from config.29: {mc_options:?}"
        );
        log::trace!(
            target: "validator_manager",
            "MC Session-ID SessionOptions serialized: {} hash: {:x}",
            hex::encode(mc_session_id_options_serialized),
            mc_session_id_hash
        );
        log::trace!(
            target: "validator_manager",
            "Shard Session-ID SessionOptions serialized: {} hash: {:x}",
            hex::encode(shard_session_id_options_serialized),
            shard_session_id_hash
        );
        log::trace!(
            target: "validator_manager",
            "Shard SessionOptions from config.29: {shard_options:?}"
        );

        Ok(SessionsOptions { mc_options, shard_options })
    }

    fn get_accelerated_consensus_config(
        &self,
        mc_state_extra: &McStateExtra,
    ) -> Option<AcceleratedConsensusConfig> {
        match mc_state_extra.config.accelerated_consensus_params() {
            Ok(accelerated_config) => Some(accelerated_config),
            _ => None,
        }
    }

    fn is_accelerated_consensus_enabled(&self, mc_state_extra: &McStateExtra) -> bool {
        // Check if disabled in config first
        if self.config.accelerated_consensus_disabled {
            return false;
        }

        if let Some(accelerated_config) = self.get_accelerated_consensus_config(mc_state_extra) {
            return accelerated_config.enabled;
        }

        false
    }

    fn is_accelerated_consensus_enabled_for_shard(
        &self,
        mc_state_extra: &McStateExtra,
        shard_id: &ShardIdent,
    ) -> bool {
        // For masterchain, use the constant to control accelerated consensus
        if shard_id.is_masterchain() {
            if !MC_ACCELERATED_CONSENSUS_ENABLED {
                return false;
            }
        }

        // Use the general accelerated consensus check for shards
        self.is_accelerated_consensus_enabled(mc_state_extra)
    }

    /// Select consensus only from a successfully decoded governing configuration.
    /// Missing, malformed and unsupported configurations cannot start a group.
    fn select_consensus_options(
        &self,
        session_id: &UInt256,
        shard: &ShardIdent,
        mc_state: &ShardStateStuff,
        catchain_options: &CatchainSessionOptions,
        _cc_seqno: u32,
        cur_subset: &ValidatorSet,
    ) -> Result<(ConsensusOptions, Option<consensus_common::BlockSyncOverlayParams>)> {
        let config_params = mc_state.config_params()?;
        let simplex_cfg = config_params.selected_simplex_config(shard.is_masterchain())?;

        if let Some(selected) = simplex_cfg {
            let cfg = selected.config;
            log::trace!(
                target: "validator_manager",
                "Simplex config found for {}: target_rate={}ms, slots_per_window={}, first_block_timeout={}ms",
                shard,
                cfg.noncritical_params.target_rate_ms,
                cfg.slots_per_leader_window,
                cfg.noncritical_params.first_block_timeout_ms
            );

            // C++ ref: mc-config.cpp maps noncritical params to
            // NewConsensusConfig::NoncriticalParams fields via ENUMERATE_NONCRITICAL_PARAMS.
            // Doubles are stored as f32 bits in the u32 values.
            //
            // TODO: C++ also applies per-shard/cc_seqno overrides here via
            // get_noncritical_params() in validator-options.hpp.
            let opts = build_runtime_simplex_session_options(shard, &cfg, catchain_options)?;
            #[cfg(test)]
            if let Some(options) =
                self.override_with_emulator_consensus_options(shard, "simplex", Some(opts.clone()))
            {
                return Ok((options, None));
            }

            if cur_subset.list().iter().any(|member| member.pq_key().is_none()) {
                fail!("target Simplex requires PQ consensus keys for every member");
            }
            rtos_block::validate_validator_list(cur_subset.list())?;

            // when enable_observers=true for this shard, compute the
            // block-sync overlay membership + authorization from the masterchain
            // ConfigParams (prev|curr|next validator sets, current-set authz).
            // C++ parity: manager.cpp builds overlay_members + block-sync-overlay.cpp
            // builds authorized_keys from bus.validator_set (current set only)
            // Network requires observers - fail loudly if we can't honour it.
            let block_sync_params = if opts.protocol.uses_block_sync() {
                let p = consensus_common::BlockSyncOverlayParams::from_config(
                    config_params,
                    cfg.slots_per_leader_window,
                    cur_subset,
                )
                .map_err(|e| error!("Block-sync params build failed for {shard}: {e}"))?;
                let overlay_id = simplex::utils::compute_block_sync_overlay_short_id(session_id)
                    .map_err(|e| error!("Block-sync overlay id for {shard}: {e}"))?;
                log::debug!(
                    target: "validator_manager",
                    "Block-sync overlay params built for {}: members={}, authorized={}, \
                     leader_window={}",
                    shard,
                    p.members.len(),
                    p.authorized_keys.len(),
                    p.slots_per_leader_window,
                );
                Some(p.with_overlay_id(overlay_id))
            } else {
                None
            };
            return Ok((ConsensusOptions::Simplex(opts), block_sync_params));
        }

        #[cfg(test)]
        if let Some(options) =
            self.override_with_emulator_consensus_options(shard, "catchain", None)
        {
            return Ok((options, None));
        }
        fail!("no admitted Simplex configuration for {shard}")
    }

    async fn update_validation_status(
        &mut self,
        mc_state: &ShardStateStuff,
        mc_state_extra: &McStateExtra,
    ) -> Result<()> {
        let prev_status = self.engine.validation_status();
        match prev_status {
            ValidationStatus::Waiting => {
                let last_masterchain_block = mc_state.block_id();
                let later_than_hardfork =
                    self.engine.get_last_fork_masterchain_seqno() <= last_masterchain_block.seq_no;

                let synced = self.engine.check_sync().await?;
                log::trace!(target: "validator_manager",
                    "update_validation_status: Waiting check: synced={} later_than_hardfork={} \
                     mc_seqno={}",
                    synced, later_than_hardfork, last_masterchain_block.seq_no);

                // Phase 1: mark sync complete and backfill future engines.
                // C++ parity: sync_complete() sets started_=true and sweeps both
                // validator_groups_ and next_validator_groups_ calling
                // create_session() on all groups (manager.cpp sync_complete).
                if synced && later_than_hardfork && !self.sync_complete {
                    self.sync_complete = true;
                    if !self.future_sessions.is_empty() {
                        log::info!(target: "validator_manager",
                            "SESSION_LIFECYCLE: backfill_pre_create_engine for {} future sessions \
                             after sync_complete",
                            self.future_sessions.len());
                        for (id, group) in &self.future_sessions {
                            let g = group.clone();
                            let session_id = id.clone();
                            g.clone().spawn_root_task(&self.rt, async move {
                                if let Err(e) = g.pre_create_engine().await {
                                    log::error!(target: "validator_manager",
                                        "SESSION_LIFECYCLE: backfill_pre_create_failed \
                                         session_id={:x}: {}",
                                        session_id, e);
                                }
                            });
                        }
                    }
                }

                // Phase 2: transition Waiting -> Active.
                // C++ parity: allow_validate_ is set purely from
                // rotated_all_shards() || seqno==0 plus the fork check
                // (manager.cpp update_shards).  sync_complete (started_)
                // only gates create_session() on existing groups (Phase 1
                // above), NOT the allow_validate_ / status transition.
                let rotated =
                    rotate_all_shards(mc_state_extra) || last_masterchain_block.seq_no == 0;
                if rotated && later_than_hardfork {
                    let bootstrap = last_masterchain_block.seq_no == 0;
                    log::info!(target: "validator_manager",
                        "VALIDATION_STATUS: Waiting -> Active \
                         (rotated_all_shards={}, mc_seqno={}, sync_complete={}, bootstrap={}, \
                         no_countdown_for_zerostate={})",
                        rotate_all_shards(mc_state_extra),
                        last_masterchain_block.seq_no,
                        self.sync_complete,
                        bootstrap,
                        self.config.no_countdown_for_zerostate);
                    self.engine.set_validation_status(ValidationStatus::Active);
                } else if !rotated {
                    log::trace!(target: "validator_manager",
                        "update_validation_status: rotated_all_shards=false, \
                         deferring Waiting -> Active (mc_seqno={})",
                        last_masterchain_block.seq_no);
                }
            }
            ValidationStatus::Disabled | ValidationStatus::Active => {}
        }
        Ok(())
    }

    async fn disable_validation(&mut self, reason: DisableReason) -> Result<()> {
        let prev_status = self.engine.validation_status();
        let n_current = self.current_sessions.len();
        let n_future = self.future_sessions.len();
        log::info!(target: "validator_manager",
            "VALIDATION_STATUS: {prev_status:?} -> Disabled (reason={reason:?}, \
            current_sessions={n_current}, future_sessions={n_future})"
        );

        self.engine.set_validation_status(ValidationStatus::Disabled);
        self.sync_complete = false;
        self.owned_current_shards = 0;
        self.owned_future_shards = 0;

        for (id, group) in std::mem::take(&mut self.current_sessions)
            .into_iter()
            .chain(std::mem::take(&mut self.future_sessions))
        {
            if reason == DisableReason::Retire {
                self.retire_group(id, group);
            } else {
                // Shutdown is not a retirement: no fence, no cleanup record.
                self.retire_group_generation(id, group, None);
            }
        }
        let observer_ids: Vec<_> = self.block_sync_observers.keys().cloned().collect();
        for id in observer_ids {
            self.retire_observer(&id);
        }
        // Split precomputation belongs to the manager, not a particular group.
        // No manager task can register more work while this &mut self is held.
        self.background_tasks.close();
        // drain_retiring latches every failure; aggregate again after the
        // background barrier so simultaneous failure sources are not lost.
        let _ = self.drain_retiring().await;
        self.background_tasks.wait().await;
        self.drain_cleanup_workers().await;
        self.drain_cleanup_shares().await;
        if self.background_panicked.load(Ordering::Acquire) {
            self.lifecycle_errors.insert("manager background task panicked".to_owned());
        }
        self.check_lifecycle_errors()?;
        self.background_tasks.reopen();
        self.garbage_collect().await;
        self.engine.set_will_validate(false);
        // Neither reason clears the fence or the rotation block (as T0).
        self.persist_destroyed_sessions()?;
        log::info!(target: "validator_manager",
            "VALIDATION_STATUS: Disabled complete (stopped {} current + {} future sessions)",
            n_current, n_future);
        Ok(())
    }

    async fn stop_validation(&mut self) -> Result<()> {
        self.disable_validation(DisableReason::Shutdown).await
    }

    fn enable_validation(&mut self) {
        self.engine.set_will_validate(true);
        let current = self.engine.validation_status();
        // C++ parity: enable_validation() only ensures we are at least
        // Waiting. The Waiting -> Active promotion is handled by
        // update_validation_status() based on rotated_all_shards(),
        // matching C++'s allow_validate_ which is independent of sync.
        let target = max(current, ValidationStatus::Waiting);
        if target != current {
            log::info!(target: "validator_manager",
                "VALIDATION_STATUS: {:?} -> {:?}",
                current, target);
        }
        self.engine.set_validation_status(target);
    }

    /// Create and start validator sessions for all currently active shards.
    ///
    /// Mirrors the `new_shards` loop in C++ `update_shards()` (`manager.cpp`):
    /// - Skips non-masterchain shards during unsafe rotation (`force_recover`)
    /// - Computes validator subset and session ID (with optional unsafe-rotation patch)
    /// - Skips sessions in the [`destroyed_sessions`] blacklist
    /// - Finds the local validator key in the subset
    /// - Creates or reuses the `ValidatorGroup` and starts it if newly created
    #[allow(clippy::too_many_arguments)]
    async fn start_sessions(
        &mut self,
        new_shards: HashMap<ShardIdent, Vec<BlockIdExt>>,
        our_current_shards: &mut HashMap<ShardIdent, ValidatorSet>,
        keyblock_seqno: u32,
        sessions_options: &SessionsOptions,
        gc_validator_sessions: &mut HashSet<UInt256>,
        mc_now: u32,
        mc_state: &ShardStateStuff,
        mc_state_extra: &McStateExtra,
        master_cc_range: &RangeInclusive<u32>,
        last_masterchain_block: &BlockIdExt,
    ) -> Result<()> {
        let full_validator_set = mc_state_extra.config.validator_set()?;
        let validator_list_id = match self.validator_list_status.curr.as_ref() {
            Some(list_id) => list_id.clone(),
            None if self.custody_set_roles(mc_state.config_params()?)?.1 => {
                compute_validator_list_id(full_validator_set.list(), None)?
                    .ok_or_else(|| error!("Authenticated current set is empty"))?
            }
            None => return Ok(()),
        };

        let catchain_config = self.read_catchain_config(mc_state)?;

        let do_unsafe_catchain_rotate = self
            .config
            .check_unsafe_catchain_rotation(
                Some(last_masterchain_block.seq_no),
                mc_state_extra.validator_info.catchain_seqno,
            )
            .is_some();

        log::trace!(target: "validator_manager", "Starting/updating sessions {}",
            if do_unsafe_catchain_rotate {"(unsafe rotate)"} else {""}
        );
        // C++ parity: rebuild current-session ownership in a fresh map each update pass.
        // We retain only sessions selected by the current shard iteration and swap atomically
        // at the end. Old current entries that are not selected are stopped right after swap.
        let mut new_current_sessions: HashMap<UInt256, Arc<ValidatorGroup>> = HashMap::new();
        // same pattern for block-sync observers.
        // Session ids touched this pass survive the swap; the rest are
        // reaped (stop + remove). D3 lifecycle: an observer dies when
        // we start validating its shard (session_id won't appear in this pass)
        // or the session simply ends
        let mut touched_observer_sessions: HashSet<UInt256> = HashSet::new();

        for (ident, prev_blocks) in new_shards {
            let cc_seqno_from_state = if ident.is_masterchain() {
                *master_cc_range.end()
            } else {
                mc_state_extra.shards().calc_shard_cc_seqno(&ident)?
            };

            let cc_seqno = cc_seqno_from_state;

            // C++ parity: during unsafe rotation, skip all non-masterchain shards
            // before any expensive subset/session-id computation.
            if should_skip_session_for_unsafe_rotation(do_unsafe_catchain_rotate, &ident) {
                log::trace!(
                    target: "validator_manager",
                    "Shard {}, cc_seqno {}: unsafe rotation skipping",
                    ident, cc_seqno
                );
                continue;
            }

            log::trace!(
                target: "validator_manager",
                "Trying to start/update session for shard {ident}, cc_seqno {cc_seqno_from_state}"
            );

            let prev = PrevBlockHistory::with_prevs(&ident, prev_blocks);
            let subset = match try_calc_subset_for_workchain(
                &full_validator_set,
                mc_state,
                &ident,
                cc_seqno,
                prev.get_next_seqno().unwrap_or_default(),
            )? {
                Some(x) => x,
                None => {
                    log::debug!(
                        target: "validator_manager",
                        "Cannot compute validator set for workchain {}: less than {} of {}",
                        ident,
                        catchain_config.shard_validators_num,
                        full_validator_set.list().len()
                    );
                    continue;
                }
            };

            let vsubset =
                ValidatorSet::with_cc_seqno(0, 0, 0, cc_seqno, subset.validators.clone())?;
            let max_vertical_seqno = self.engine.hardforks().len() as u32;

            if do_unsafe_catchain_rotate {
                fail!("unsafe rotation cannot alter the canonical consensus session ID");
            }
            if self.is_accelerated_consensus_enabled_for_shard(mc_state_extra, &ident) {
                fail!("accelerated consensus has not been admitted for the target protocol");
            }
            let (general_session_info, session_id) = derive_governing_session_info(
                mc_state,
                &ident,
                vsubset.list(),
                cc_seqno,
                keyblock_seqno,
                max_vertical_seqno,
            )?;

            // The reference node's get_validator_id at the caller's selection:
            // custody decides membership, never a transport key this node holds.
            let local_member = self.local_validator_id(&subset.validators);

            if local_member.is_some() {
                // Track owned current subsets independently of whether this specific session
                // is temporarily suppressed by the destroyed-session blacklist.
                // Otherwise health classification can mislabel a missing owned current session
                // as benign `NoCurrentSubsetOwned`.
                our_current_shards.insert(ident.clone(), vsubset.clone());
            }

            // C++ parity: skip sessions in the destroyed set
            if self.destroyed_sessions.contains(&session_id) {
                log::trace!(
                    target: "validator_manager",
                    "Skipping destroyed session {:x} for shard {}", session_id, ident
                );
                continue;
            }
            // Creation waits while a cleanup delete of this session is in flight.
            if self.cleanup.is_delete_in_flight(&session_id) {
                log::info!(target: "validator_manager",
                    "Deferring session {session_id:x} for shard {ident}: cleanup delete in flight");
                continue;
            }
            if !self.admit_session_creation(&session_id) {
                continue;
            }

            // Select consensus type based on ConfigParam 30. Computed
            // unconditionally so the observer branch (below) can also see
            // `block_sync_overlay_params` when we're NOT in this shard's
            // validator subset
            let current_session_options = sessions_options.get_session_options(&ident);
            let (consensus_options, block_sync_overlay_params) = match self
                .select_consensus_options(
                    &session_id,
                    &ident,
                    mc_state,
                    current_session_options,
                    cc_seqno,
                    &vsubset,
                ) {
                Ok(v) => v,
                Err(e) => {
                    log::error!(
                        target: "validator_manager",
                        "Skipping session {session_id:x} for shard {ident}: {e}"
                    );
                    continue;
                }
            };

            // The test emulator carries Simplex options but runs no Simplex session.
            let simplex_protocol = match &consensus_options {
                ConsensusOptions::Simplex(options) => Some(options.protocol),
                _ => None,
            };
            let observers_in_overlay = simplex_protocol
                == Some(
                    consensus_common::simplex_protocol::SimplexProtocol::PrivateObserversPlumtree,
                );
            // Every Simplex session, of every protocol, is admitted from this
            // authenticated snapshot: as the validator custody selected, or as
            // an observer the reference observer selection admits.
            let authenticated = match simplex_protocol {
                Some(_) => self.simplex_session_runtime(
                    mc_state,
                    &ident,
                    cc_seqno,
                    max_vertical_seqno,
                    keyblock_seqno,
                    vsubset.list(),
                    local_member.as_ref(),
                    observers_in_overlay,
                )?,
                None => None,
            };
            if observers_in_overlay && authenticated.is_none() {
                // Neither a member nor an authorized observer of this session.
                continue;
            }
            if let Some(runtime) = &authenticated {
                if self.engine.finality_recovery_owns(runtime) {
                    // A recovery owner will wake this manager after checked join.
                    // Preserve any existing group during a reservation race;
                    // exclusive source DB ownership still decides who can start.
                    if let Some(group) = self.current_sessions.get(&session_id) {
                        new_current_sessions.insert(session_id.clone(), group.clone());
                    }
                    gc_validator_sessions.remove(&session_id);
                    our_current_shards.remove(&ident);
                    continue;
                }
                use consensus_common::session_runtime::LocalRole;
                if matches!(runtime.local_role(), LocalRole::Validator(_)) {
                    our_current_shards.insert(ident.clone(), vsubset.clone());
                } else {
                    our_current_shards.remove(&ident);
                }
                // Admission changes can happen without changing the committee/session
                // hash. Drain the previous generation before publishing its replacement.
                let incompatible = |group: &Arc<ValidatorGroup>| {
                    !group.authenticated_runtime().is_some_and(|old| old.same_admission(runtime))
                };
                if self.current_sessions.get(&session_id).is_some_and(incompatible) {
                    let old = self.current_sessions.remove(&session_id).unwrap();
                    self.retire_replaced_admission(session_id.clone(), old, runtime);
                }
                if self.future_sessions.get(&session_id).is_some_and(incompatible) {
                    let old = self.future_sessions.remove(&session_id).unwrap();
                    self.retire_replaced_admission(session_id.clone(), old, runtime);
                }
                self.drain_retiring().await?;
            }
            // A test emulator session over a classical committee is the only
            // group created without an authenticated runtime.
            let runs_group =
                authenticated.is_some() || (simplex_protocol.is_none() && local_member.is_some());
            if runs_group {
                self.retire_observer(&session_id);
                self.drain_retiring().await?;
                log::debug!(
                    target: "validator_manager",
                    "subset for session: shard {}, cc_seqno {}, keyblock_seqno {}, \
                    validator_set {}, session_id {:x}",
                    ident, cc_seqno, keyblock_seqno,
                    validatorset_to_string(&vsubset), session_id
                );

                gc_validator_sessions.remove(&session_id);

                let engine = self.engine.clone();
                let allow_unsafe_self_blocks_resync =
                    self.config.unsafe_resync_catchains.contains(&cc_seqno);

                let session = match select_existing_session_for_current_map(
                    &session_id,
                    &self.current_sessions,
                    &mut self.future_sessions,
                ) {
                    Some(ExistingSessionSource::Current(existing)) => {
                        log::trace!(
                            target: "validator_manager",
                            "SESSION_LIFECYCLE: keep_current shard={} cc_seqno={} session_id={:x}",
                            ident,
                            cc_seqno,
                            session_id
                        );
                        existing
                    }
                    Some(ExistingSessionSource::Future(promoted)) => {
                        log::info!(
                            target: "validator_manager",
                            "SESSION_LIFECYCLE: promote shard={} cc_seqno={} session_id={:x} \
                             future -> current",
                            ident,
                            cc_seqno,
                            session_id
                        );
                        promoted
                    }
                    None => {
                        let consensus_name = match &consensus_options {
                            ConsensusOptions::Simplex(_) => "simplex",
                            #[cfg(test)]
                            ConsensusOptions::Emulator(_) => "emulator",
                            ConsensusOptions::Catchain(_) => "catchain",
                        };
                        let Some((transport_key, signer)) = self.admit_session_group(
                            &ident,
                            vsubset.list(),
                            local_member.as_ref(),
                            authenticated.as_deref(),
                            &consensus_options,
                        ) else {
                            continue;
                        };
                        log::info!(target: "validator_manager",
                            "SESSION_LIFECYCLE: create_current shard={} cc_seqno={} \
                             session_id={:x} consensus={} local_key={}",
                            ident, cc_seqno, session_id, consensus_name,
                            hex::encode(transport_key.id().data()));
                        metrics::counter!(
                            "rtos_node_validator_session_created_total",
                            "consensus" => consensus_name
                        )
                        .increment(1);
                        self.cleanup.on_group_created(&session_id);
                        let group = ValidatorGroup::new(
                            general_session_info.clone(),
                            transport_key,
                            session_id.clone(),
                            validator_list_id.clone(),
                            vsubset.clone(),
                            full_validator_set.utime_since(),
                            consensus_options.clone(),
                            engine,
                            allow_unsafe_self_blocks_resync,
                            block_sync_overlay_params.clone(),
                        );
                        let group = match &authenticated {
                            Some(runtime) => {
                                group.with_recovered_authenticated_runtime(runtime.clone()).await?
                            }
                            None => group,
                        };
                        Arc::new(match signer {
                            Some(signer) => group.with_consensus_signer(signer)?,
                            None => group,
                        })
                    }
                };
                // Promotion removed the future owner. Register the selected
                // group before any await/start, including on a partial pass.
                self.current_sessions.insert(session_id.clone(), session.clone());
                new_current_sessions.insert(session_id.clone(), session.clone());

                let session_status = session.get_status().await;
                if session.try_prepare_start().await? {
                    log::trace!(
                        target: "validator_manager",
                        "Current shard {ident}, session {session_id:x}: starting"
                    );

                    session
                        .start_session(
                            prev.get_prevs().to_vec(),
                            last_masterchain_block.clone(),
                            SystemTime::UNIX_EPOCH + Duration::from_secs(mc_now as u64),
                            self.rt.clone(),
                        )
                        .await?;
                } else if session.is_start_pending().await {
                    log::trace!(
                        target: "validator_manager",
                        "Current shard {}, session {:x}: start pending",
                        ident,
                        session_id
                    );
                } else if session_status >= ValidatorGroupStatus::Stopping {
                    log::error!(
                        target: "validator_manager",
                        "Cannot start stopped session {}",
                        session.info().await
                    );
                } else {
                    log::trace!(
                        target: "validator_manager",
                        "Current shard {ident}, session {session_id:x}: working"
                    );
                }
            } else {
                log::trace!(target: "validator_manager", "We are not in subset for {}", ident);
                // Observer mode for shards we don't validate
                // (C++ `manager.cpp:2462-2554`, `get_or_make_next_group` is_validator=false)
                if let Some(bs_params) = block_sync_overlay_params.as_ref() {
                    touched_observer_sessions.insert(session_id.clone());
                    if !self.block_sync_observers.contains_key(&session_id) {
                        let simplex = consensus_options.as_simplex();
                        let use_quic = simplex.map(|o| o.use_quic).unwrap_or(false);
                        let proto_version = simplex.map(|o| o.proto_version).unwrap_or(5);
                        if let Err(e) = self.try_spawn_observer(
                            &ident,
                            &session_id,
                            mc_state,
                            vsubset.list(),
                            bs_params.clone(),
                            use_quic,
                            proto_version,
                        ) {
                            log::warn!(
                                target: "validator_manager",
                                "observer not spawned for shard={ident} session={session_id:x}: {e}"
                            );
                        }
                    }
                }
            }
            log::trace!(target: "validator_manager", "Session {} started (if necessary)", ident);
        }
        let old_current_count = self.current_sessions.len();
        self.replace_current_sessions(new_current_sessions).await?;

        log::trace!(
            target: "validator_manager",
            "Starting/updating sessions, end of list (current map swapped: old={} new={})",
            old_current_count,
            self.current_sessions.len()
        );

        // reap observers whose session_id wasn't touched this pass.
        // Triggers when we begin validating a previously-observed
        // shard (the group arm fires instead of the observer arm)
        // or when the shard simply rotates out
        let stale_observer_ids: Vec<UInt256> = self
            .block_sync_observers
            .keys()
            .filter(|sid| !touched_observer_sessions.contains(*sid))
            .cloned()
            .collect();
        for sid in stale_observer_ids {
            self.retire_observer(&sid);
        }
        self.drain_retiring().await?;
        Ok(())
    }

    /// Main per-masterchain-block update loop.
    ///
    /// Mirrors `ValidatorManagerImpl::update_shards()` in C++ (`manager.cpp`).
    /// Responsibilities:
    /// 1. Refresh validator list membership (`update_validator_lists`)
    /// 2. Collect current and future shards from the masterchain state
    /// 3. Create/start sessions for current shards (`start_sessions`)
    /// 4. Pre-create sessions for upcoming shards (future-sessions loop)
    /// 5. GC sessions that are no longer needed (`stop_and_remove_sessions`)
    /// 6. Clear the destroyed-sessions blacklist on full shard rotation
    async fn update_shards(&mut self, mc_state: Arc<ShardStateStuff>) -> Result<()> {
        let mc_state_extra = mc_state.shard_state_extra()?;
        let master_cc_seqno = get_masterchain_seqno(self.engine.clone(), &mc_state).await?;
        let catchain_config = self.read_catchain_config(&mc_state)?;
        let sessions_options =
            self.compute_session_options(mc_state_extra, &catchain_config).await?;

        log::trace!(target: "validator_manager",
            "update_shards: mc_seqno={} mc_cc_seqno={} current_sessions={} future_sessions={}",
            mc_state.block_id().seq_no, master_cc_seqno,
            self.current_sessions.len(), self.future_sessions.len());

        let has_validator_key = self.update_validator_lists(&mc_state).await?;
        // Custody membership of the current or next set, and of any total set.
        let (custody_active, custody_listed) = self.custody_set_roles(mc_state.config_params()?)?;
        if !has_validator_key && !custody_listed {
            log::info!(target: "validator_manager",
                "VALIDATION_STATUS: not a validator (not in prev/curr/next set), disabling");
            self.disable_validation(DisableReason::Retire).await?;
            return Ok(());
        }

        // Observer-only path: we hold a key in prev only (rotated out of curr/next).
        // Validator groups stay disabled, but the per-shard loop still runs so the
        // observer arm and the observer reaper at the bottom rotate session_ids
        let observer_only = self.validator_list_status.curr.is_none()
            && self.validator_list_status.next.is_none()
            && !custody_active;
        if observer_only {
            if custody_listed {
                // Observer sessions still own their runtime and receive state, but
                // must not advertise validator eligibility or acquire signer rights.
                self.engine.set_will_validate(false);
                self.engine.set_validation_status(ValidationStatus::Disabled);
                if !self.sync_complete {
                    self.sync_complete = self.engine.check_sync().await?;
                }
            } else {
                log::info!(target: "validator_manager",
                    "VALIDATION_STATUS: prev-only (observer mode), validator groups disabled");
                self.disable_validation(DisableReason::Retire).await?;
            }
        }

        let last_masterchain_block = mc_state.block_id();
        let keyblock_seqno = if mc_state_extra.after_key_block {
            mc_state.block_id().seq_no
        } else {
            mc_state_extra
                .last_key_block
                .as_ref()
                .map(|id| id.seq_no)
                .expect("masterchain state must contain info about previous key block")
        };
        let mc_now = mc_state.state()?.gen_time();

        if !observer_only {
            self.enable_validation();
            self.update_validation_status(&mc_state, mc_state_extra).await?;
        }

        let master_cc_range = master_cc_seqno..=master_cc_seqno; // Todo: compute always

        // Collect info about shards
        let mut gc_validator_sessions: HashSet<UInt256> =
            self.current_sessions.keys().chain(self.future_sessions.keys()).cloned().collect();

        // Shards that are working or about to start (continue) in this masterstate: shard_ident -> prevs
        let mut new_shards = HashMap::new();
        // Validator sets for shards that are working or about to start
        let mut our_current_shards: HashMap<ShardIdent, ValidatorSet> = HashMap::new();

        // Shards that will eventually be started (in later masterstates): need to prepare
        let mut future_shards: HashSet<ShardIdent> = HashSet::new();
        // Validator sets for shards that will eventually be started
        // Tuple: (subset, next_cc_seqno, validator_list_id, epoch_utime_since)
        // where epoch_utime_since is the governing validator set's utime_since
        // (used for lifecycle epoch routing; the subset itself is built with a
        // zeroed utime_since to keep session_id hashing C++-compatible).
        let mut our_future_shards: HashMap<
            ShardIdent,
            (ValidatorSubsetInfo, u32, ValidatorListHash, u32),
        > = HashMap::new();
        let mut blocks_before_split: HashSet<BlockIdExt> = HashSet::new();

        new_shards.insert(ShardIdent::masterchain(), vec![last_masterchain_block.clone()]);
        future_shards.insert(ShardIdent::masterchain());
        mc_state_extra.shards().iterate_shards(|ident: ShardIdent, descr: ShardDescr| {
            // Add all shards that are effective from now
            // ValidatorGroups will be created and appropriate sessions started for these shards
            let top_block = BlockIdExt::with_params(
                ident.clone(),
                descr.seq_no,
                descr.root_hash,
                descr.file_hash,
            );

            if descr.before_split {
                let lr_shards = ident.split();
                match lr_shards {
                    Err(e) => log::error!(target: "validator_manager", "Cannot split shard: `{e}`"),
                    Ok((l, r)) => {
                        new_shards.insert(l, vec![top_block.clone()]);
                        new_shards.insert(r, vec![top_block.clone()]);
                        blocks_before_split.insert(top_block);
                    }
                }
            } else if descr.before_merge {
                let parent_shard = ident.merge();
                match parent_shard {
                    Err(e) => log::error!(target: "validator_manager", "Cannot merge shard: `{e}`"),
                    Ok(p) => {
                        let mut prev_blocks = match new_shards.get(&p) {
                            Some(pb) => pb.clone(),
                            None => vec![BlockIdExt::default(), BlockIdExt::default()],
                        };

                        // Add previous block for the shard: there are two parents for merge, so two prevs
                        let (_l, r) = p.split()?;
                        prev_blocks[(r == ident) as usize] = top_block;
                        new_shards.insert(p, prev_blocks);
                    }
                }
            } else {
                new_shards.insert(ident.clone(), vec![top_block]);
            }

            // Create list of shards which will be effective soon
            // ValidatorGroups will be created for these shards, but not started.
            let cur_time = UnixTime::now();
            match descr.split_merge_at {
                FutureSplitMerge::None => {
                    future_shards.insert(ident);
                }
                FutureSplitMerge::Split { split_utime: time, interval: _interval } => {
                    if (time as u64) < cur_time + 60 {
                        match ident.split() {
                            Ok((l, r)) => {
                                future_shards.insert(l);
                                future_shards.insert(r);
                            }
                            Err(e) => log::error!(
                                target: "validator_manager",
                                "Cannot split shard {ident}: `{e}`"
                            ),
                        }
                    } else {
                        future_shards.insert(ident);
                    }
                }
                FutureSplitMerge::Merge { merge_utime: time, interval: _interval } => {
                    if (time as u64) < cur_time + 60 {
                        match ident.merge() {
                            Ok(p) => {
                                future_shards.insert(p);
                            }
                            Err(e) => log::error!(
                                target: "validator_manager",
                                "Cannot merge shard {ident}: `{e}`"
                            ),
                        }
                    } else {
                        future_shards.insert(ident);
                    }
                }
            };

            Ok(true)
        })?;

        // Initializing future shards
        log::debug!(target: "validator_manager", "Future shards initialization:");
        let next_validator_set = mc_state_extra.config.next_validator_set()?;
        let full_validator_set = mc_state_extra.config.validator_set()?;
        let possible_validator_change = next_validator_set.total() > 0;
        let mut mc_validators = Vec::with_capacity(full_validator_set.total() as usize);

        for ident in future_shards.iter() {
            log::trace!(target: "validator_manager", "Future shard {}", ident);
            let (cc_seqno_from_state, cc_lifetime) = if ident.is_masterchain() {
                (master_cc_seqno, catchain_config.mc_catchain_lifetime)
            } else {
                (
                    mc_state_extra.shards().calc_shard_cc_seqno(ident)?,
                    catchain_config.shard_catchain_lifetime,
                )
            };

            let near_validator_change = possible_validator_change
                && next_validator_set.utime_since() <= (mc_now / cc_lifetime + 1) * cc_lifetime;
            let future_validator_set = if near_validator_change {
                log::info!(
                    target: "validator_manager",
                    "Validator change will happen during catchain session lifetime \
                    for shard {}: cc_lifetime {}, now {}, next set since {}",
                    ident, cc_lifetime, mc_now, next_validator_set.utime_since()
                );
                &next_validator_set
            } else {
                &full_validator_set
            };

            let vnext_list_id = match compute_validator_list_id(future_validator_set.list(), None)?
            {
                None => continue,
                Some(l) => l,
            };

            let next_cc_seqno = cc_seqno_from_state + 1;

            let next_subset_opt = try_calc_subset_for_workchain_standard(
                future_validator_set,
                mc_state.config_params()?,
                ident,
                next_cc_seqno,
            )?;

            let next_subset = match next_subset_opt {
                Some(x) => x,
                None => {
                    log::error!(
                        target: "validator_manager",
                        "Cannot compute validator set for workchain {}: less than {} of {}",
                        ident,
                        catchain_config.shard_validators_num,
                        future_validator_set.list().len()
                    );
                    continue;
                }
            };

            our_future_shards.insert(
                ident.clone(),
                (next_subset, next_cc_seqno, vnext_list_id, future_validator_set.utime_since()),
            );
            log::trace!(
                target: "validator_manager",
                "Future shard {}: computing next subset with cc_seqno {} -- done",
                ident, next_cc_seqno
            );
        }

        // Iterate over shards and start all missing sessions
        log::trace!(target: "validator_manager", "Starting missing sessions");
        let validation_status = self.engine.validation_status();
        if validation_status.allows_validate() || custody_listed {
            self.start_sessions(
                new_shards,
                &mut our_current_shards,
                keyblock_seqno,
                &sessions_options,
                &mut gc_validator_sessions,
                mc_now,
                &mc_state,
                mc_state_extra,
                &master_cc_range,
                last_masterchain_block,
            )
            .await?;
        }
        log::trace!(target: "validator_manager", "Missing sessions started. Current shards:");

        // Iterate over future shards and create all future sessions
        let mut owned_future_shards = 0usize;
        for (ident, (wc, next_cc_seqno, next_val_list_id, epoch_utime_since)) in
            our_future_shards.iter()
        {
            if ident.is_masterchain() {
                mc_validators.append(&mut wc.validators.clone());
            }

            // A future group exists only for a session this node is a member of,
            // as custody selects it at this read of the custody clock.
            if let Some(selected) = self.local_validator_id(&wc.validators) {
                let max_vertical_seqno = self.engine.hardforks().len() as u32;
                if self.is_accelerated_consensus_enabled_for_shard(mc_state_extra, &ident) {
                    fail!("accelerated consensus has not been admitted for the target protocol");
                }
                if self
                    .config
                    .check_unsafe_catchain_rotation(
                        Some(last_masterchain_block.seq_no),
                        *next_cc_seqno,
                    )
                    .is_some()
                {
                    fail!("unsafe rotation cannot alter the canonical consensus session ID");
                }
                let (new_session_info, session_id) = derive_governing_session_info(
                    &mc_state,
                    &ident,
                    &wc.validators,
                    *next_cc_seqno,
                    keyblock_seqno,
                    max_vertical_seqno,
                )?;

                // C++ parity: skip sessions in the destroyed set
                if self.destroyed_sessions.contains(&session_id) {
                    log::trace!(
                        target: "validator_manager",
                        "Skipping destroyed future session {:x} for shard {}", session_id, ident
                    );
                    continue;
                }
                if self.cleanup.is_delete_in_flight(&session_id) {
                    log::info!(target: "validator_manager",
                        "Deferring future session {session_id:x} for shard {ident}: cleanup delete in flight");
                    continue;
                }
                if !self.admit_session_creation(&session_id) {
                    continue;
                }

                let vsubset = wc.compute_validator_set(*next_cc_seqno)?;
                let current_session_options = sessions_options.get_session_options(&ident);
                gc_validator_sessions.remove(&session_id);

                // Select consensus type based on ConfigParam 30
                let (consensus_options, block_sync_overlay_params) = match self
                    .select_consensus_options(
                        &session_id,
                        &ident,
                        mc_state.as_ref(),
                        current_session_options,
                        *next_cc_seqno,
                        &vsubset,
                    ) {
                    Ok(v) => v,
                    Err(e) => {
                        log::error!(
                            target: "validator_manager",
                            "Skipping future session {session_id:x} for shard {ident}: {e}"
                        );
                        continue;
                    }
                };

                let authenticated = match &consensus_options {
                    ConsensusOptions::Simplex(_) => self.simplex_session_runtime(
                        &mc_state,
                        ident,
                        *next_cc_seqno,
                        max_vertical_seqno,
                        keyblock_seqno,
                        vsubset.list(),
                        Some(&selected),
                        false,
                    )?,
                    _ => None,
                };
                if authenticated
                    .as_ref()
                    .is_some_and(|runtime| self.engine.finality_recovery_owns(runtime))
                {
                    continue;
                }
                owned_future_shards += 1;
                if let Some(runtime) = &authenticated {
                    if self.future_sessions.get(&session_id).is_some_and(|group| {
                        !group
                            .authenticated_runtime()
                            .is_some_and(|old| old.same_admission(runtime))
                    }) {
                        let old = self.future_sessions.remove(&session_id).unwrap();
                        self.retire_replaced_admission(session_id.clone(), old, runtime);
                        self.drain_retiring().await?;
                    }
                }

                if self.current_sessions.contains_key(&session_id) {
                    log::trace!(
                        target: "validator_manager",
                        "Future session {:x} for shard {} already in current_sessions, skipping",
                        session_id, ident
                    );
                    continue;
                }

                let group = if let Some(group) = self.future_sessions.get(&session_id) {
                    group.clone()
                } else {
                    let Some((transport_key, signer)) = self.admit_session_group(
                        ident,
                        vsubset.list(),
                        Some(&selected),
                        authenticated.as_deref(),
                        &consensus_options,
                    ) else {
                        continue;
                    };
                    let consensus_name = match &consensus_options {
                        ConsensusOptions::Simplex(_) => "simplex",
                        #[cfg(test)]
                        ConsensusOptions::Emulator(_) => "emulator",
                        ConsensusOptions::Catchain(_) => "catchain",
                    };
                    log::info!(target: "validator_manager",
                            "SESSION_LIFECYCLE: create_future shard={} cc_seqno={} \
                            session_id={:x} consensus={}",
                            ident, next_cc_seqno, session_id, consensus_name);
                    metrics::counter!(
                        "rtos_node_validator_session_created_total",
                        "consensus" => consensus_name
                    )
                    .increment(1);
                    self.cleanup.on_group_created(&session_id);
                    let group = ValidatorGroup::new(
                        new_session_info,
                        transport_key,
                        session_id.clone(),
                        next_val_list_id.clone(),
                        vsubset.clone(),
                        *epoch_utime_since,
                        consensus_options.clone(),
                        self.engine.clone(),
                        self.config.unsafe_resync_catchains.contains(next_cc_seqno),
                        block_sync_overlay_params.clone(),
                    );
                    let group = match &authenticated {
                        Some(runtime) => {
                            group.with_recovered_authenticated_runtime(runtime.clone()).await?
                        }
                        None => group,
                    };
                    let group = Arc::new(match signer {
                        Some(signer) => group.with_consensus_signer(signer)?,
                        None => group,
                    });
                    self.future_sessions.insert(session_id.clone(), group.clone());
                    group
                };

                if self.sync_complete {
                    log::debug!(target: "validator_manager",
                        "Pre-creating engine for future session shard={} cc_seqno={} session_id={:x}",
                        ident, next_cc_seqno, session_id);
                    let g = group.clone();
                    let sid = session_id.clone();
                    g.clone().spawn_root_task(&self.rt, async move {
                        if let Err(e) = g.pre_create_engine().await {
                            log::error!(target: "validator_manager",
                                "SESSION_LIFECYCLE: pre_create_engine_failed session_id={:x} error={}", sid, e);
                        }
                    });
                }
            }
        }

        self.owned_current_shards = our_current_shards.len();
        self.owned_future_shards = owned_future_shards;

        self.cull_stale_future_sessions().await?;

        let mut precalc_split_queues_for: HashSet<BlockIdExt> = HashSet::new();
        for session in self.current_sessions.values().chain(self.future_sessions.values()) {
            for id in &blocks_before_split {
                if id.shard().is_parent_for(session.shard()) {
                    log::trace!(
                        target: "validator_manager", "precalc_split_queues_for {}", id
                    );
                    precalc_split_queues_for.insert(id.clone());
                }
            }
        }

        // start background tasks which will precalculate split out messages queues
        for id in precalc_split_queues_for {
            self.spawn_split_queue_precalculation(id);
        }

        // Notify simplex sessions with the currently applied top for their shard.
        // This drives C++-parity empty-block recovery logic and MC validation ordering.
        self.notify_simplex_sessions_applied_tops(mc_state.as_ref(), mc_state_extra);

        log::trace!(target: "validator_manager", "starting stop&remove");
        self.stop_and_remove_sessions(&gc_validator_sessions).await?;

        if rotate_all_shards(mc_state_extra) {
            log::info!(target: "validator_manager", "New last rotation block: {}", last_masterchain_block);
            self.rotate_init_block(last_masterchain_block)?;
        } else {
            self.persist_destroyed_sessions()?;
        }

        log::trace!(target: "validator_manager", "starting garbage collect");
        self.garbage_collect().await;
        log::trace!(target: "validator_manager", "exiting");
        Ok(())
    }

    /// Light per-iteration update: Prometheus gauges, engine timing, health warnings.
    /// Called on every wait-loop iteration (every few seconds).
    async fn stats(&mut self) {
        let validation_status = self.engine.validation_status();
        let in_current_set = self.validator_list_status.curr.is_some();

        let mut state_counts: HashMap<&'static str, u64> = HashMap::new();
        let mut stalled_count: u64 = 0;
        let mut simplex_count: u64 = 0;
        let mut catchain_count: u64 = 0;

        for group in self.current_sessions.values() {
            let status = group.get_status().await;
            let is_stalled = group.stalled.load(Ordering::Relaxed);
            *state_counts.entry(status.metric_label()).or_default() += 1;
            if is_stalled {
                stalled_count += 1;
            }
            if group.is_simplex() {
                simplex_count += 1;
            } else {
                catchain_count += 1;
            }
            if status == ValidatorGroupStatus::Sync
                || status == ValidatorGroupStatus::Active
                || status == ValidatorGroupStatus::Stopping
            {
                self.engine
                    .set_last_validation_time(group.shard().clone(), group.last_validation_time());
                self.engine
                    .set_last_collation_time(group.shard().clone(), group.last_collation_time());
            }
        }
        for group in self.future_sessions.values() {
            let status = group.get_status().await;
            *state_counts.entry(status.metric_label()).or_default() += 1;
            if group.is_simplex() {
                simplex_count += 1;
            } else {
                catchain_count += 1;
            }
        }

        // Health warnings for operator attention
        if stalled_count > 0 {
            log::warn!(target: "validator_manager",
                "HEALTH_CHECK: {} session(s) stalled (validation queue inactive)", stalled_count);
        }
        if let Some(reason) = classify_no_current_session_health(
            in_current_set,
            validation_status,
            self.current_sessions.len(),
            self.owned_current_shards,
            self.owned_future_shards,
        ) {
            if reason.should_warn() {
                log::warn!(target: "validator_manager",
                    "HEALTH_CHECK: node is in current validator set but has no current sessions \
                     (reason={}, owned_current_shards={}, owned_future_shards={}, \
                     future_sessions={}, validation_status={:?})",
                    reason.label(),
                    self.owned_current_shards,
                    self.owned_future_shards,
                    self.future_sessions.len(),
                    validation_status);
            }
        }
        if validation_status.allows_validate() {
            let sync_count = state_counts.get("sync").copied().unwrap_or(0);
            let active_count = state_counts.get("active").copied().unwrap_or(0);
            if sync_count == 0 && active_count == 0 && !self.current_sessions.is_empty() {
                log::warn!(target: "validator_manager",
                    "HEALTH_CHECK: validation enabled but no current session reached sync yet \
                     (possible startup/session-start regression, validation_status={:?})",
                    validation_status);
            }
        }

        // Prometheus metrics
        metrics::gauge!("rtos_node_validator_sessions_total", "role" => "current")
            .set(self.current_sessions.len() as f64);
        metrics::gauge!("rtos_node_validator_sessions_total", "role" => "future")
            .set(self.future_sessions.len() as f64);
        metrics::gauge!("rtos_node_validator_sessions_by_consensus", "type" => "simplex")
            .set(simplex_count as f64);
        metrics::gauge!("rtos_node_validator_sessions_by_consensus", "type" => "catchain")
            .set(catchain_count as f64);
        for (state, count) in &state_counts {
            metrics::gauge!("rtos_node_validator_sessions_by_state", "state" => *state)
                .set(*count as f64);
        }
        metrics::gauge!("rtos_node_validator_group_stalled").set(stalled_count as f64);
        metrics::gauge!("rtos_node_validator_sync_complete").set(self.sync_complete as u8 as f64);

        // Full metrics dump once per minute
        if self.last_metrics_dump.elapsed() >= Duration::from_secs(60) {
            self.last_metrics_dump = tokio::time::Instant::now();
            self.dump_metrics().await;
        }
    }

    /// Comprehensive metrics dump emitted once per minute.
    /// Structured for easy grep and readable operator dashboards.
    async fn dump_metrics(&self) {
        let now = SystemTime::now();
        let now_unix = now.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs();
        let validation_status = self.engine.validation_status();
        let in_current_set = self.validator_list_status.curr.is_some();
        let in_next_set = self.validator_list_status.next.is_some();
        // ── Header: overall manager state ──
        let mut simplex_count = 0u32;
        let mut catchain_count = 0u32;
        let mut stalled_count = 0u32;
        let mut state_counts: HashMap<&'static str, u32> = HashMap::new();

        // Collect current session snapshots
        let mut current_snapshots: Vec<(SessionSnapshot, bool, bool, u64, u64)> = Vec::new();
        for group in self.current_sessions.values() {
            let snap = group.snapshot().await;
            let is_stalled = group.stalled.load(Ordering::Relaxed);
            let is_collating = group.is_collating();
            let last_val = group.last_validation_time();
            let last_col = group.last_collation_time();
            *state_counts.entry(snap.status.metric_label()).or_default() += 1;
            if is_stalled {
                stalled_count += 1;
            }
            if snap.consensus_type == super::consensus::ConsensusType::Simplex {
                simplex_count += 1;
            } else {
                catchain_count += 1;
            }
            current_snapshots.push((snap, is_stalled, is_collating, last_val, last_col));
        }

        // Collect future session snapshots
        let mut future_snapshots: Vec<SessionSnapshot> = Vec::new();
        for group in self.future_sessions.values() {
            let snap = group.snapshot().await;
            *state_counts.entry(snap.status.metric_label()).or_default() += 1;
            if snap.consensus_type == super::consensus::ConsensusType::Simplex {
                simplex_count += 1;
            } else {
                catchain_count += 1;
            }
            future_snapshots.push(snap);
        }

        let state_str: String =
            state_counts.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join(" ");

        let mut lines = Vec::<String>::new();
        lines.push(format!(
            "=== VALIDATOR MANAGER METRICS (once/min) ===\n\
             \x20 validation_status={:?}  sync_complete={}\n\
             \x20 in_current_set={}  in_next_set={}\n\
             \x20 owned_subsets: current={} future={}\n\
             \x20 sessions: current={} future={} total={} (simplex={} catchain={})\n\
             \x20 by_state: [{}]  stalled={}",
            validation_status,
            self.sync_complete,
            in_current_set,
            in_next_set,
            self.owned_current_shards,
            self.owned_future_shards,
            self.current_sessions.len(),
            self.future_sessions.len(),
            self.current_sessions.len() + self.future_sessions.len(),
            simplex_count,
            catchain_count,
            state_str,
            stalled_count,
        ));

        if let Some(reason) = classify_no_current_session_health(
            in_current_set,
            validation_status,
            self.current_sessions.len(),
            self.owned_current_shards,
            self.owned_future_shards,
        ) {
            lines.push(format!(
                "  NO CURRENT SESSIONS: reason={} owned_current_shards={} \
                 owned_future_shards={} current_sessions={} future_sessions={}",
                reason.label(),
                self.owned_current_shards,
                self.owned_future_shards,
                self.current_sessions.len(),
                self.future_sessions.len(),
            ));
        }

        // ── Validator keys ──
        lines.push(String::from("  VALIDATOR KEYS:"));
        for (role, list_id_opt, utime_opt) in [
            (
                "current",
                &self.validator_list_status.curr,
                self.validator_list_status.curr_utime_since,
            ),
            ("next", &self.validator_list_status.next, self.validator_list_status.next_utime_since),
        ] {
            if let Some(list_id) = list_id_opt {
                let entry = self.validator_list_status.get_list(list_id);
                let context_ready =
                    self.engine.validator_network().has_validator_list_context(list_id);
                let key_strs: Vec<String> = entry
                    .map(|e| e.keys.iter().map(|k| base64_encode(k.id().data())).collect())
                    .unwrap_or_default();
                lines.push(format!(
                    "    [{}] list_id={:x} election_utime={} context_ready={} keys=[{}]",
                    role,
                    list_id,
                    utime_opt.map_or("-".to_string(), |u| u.to_string()),
                    context_ready,
                    key_strs.join(", "),
                ));
            } else {
                lines.push(format!("    [{}] not in set", role));
            }
        }

        // ── Config-level key bindings (election_id → validator_key, adnl_key) ──
        match self.engine.get_validator_key_bindings() {
            Ok(bindings) => {
                lines.push(format!("  KEY BINDINGS ({}):", bindings.len()));
                let mut seen_elections: HashMap<i32, usize> = HashMap::new();
                for (idx, b) in bindings.iter().enumerate() {
                    let adnl_str = b.validator_adnl_key_id.as_deref().unwrap_or("(none)");
                    lines.push(format!(
                        "    election_id={:<12} key={} adnl={} expire_at={}",
                        b.election_id, b.validator_key_id, adnl_str, b.expire_at,
                    ));
                    if let Some(prev_idx) = seen_elections.insert(b.election_id, idx) {
                        log::error!(
                            target: "validator_manager",
                            "KEY BINDING INVARIANT VIOLATION: duplicate election_id={}: \
                             binding[{}] and binding[{}] share the same election_id",
                            b.election_id, prev_idx, idx,
                        );
                    }
                    if b.validator_adnl_key_id.is_none() {
                        log::warn!(
                            target: "validator_manager",
                            "KEY BINDING: election_id={} has validator_key={} but no ADNL key bound",
                            b.election_id, b.validator_key_id,
                        );
                    }
                }
            }
            Err(e) => {
                lines.push(format!("  KEY BINDINGS: error retrieving: {e}"));
            }
        }

        // ── Current sessions detail ──
        if current_snapshots.is_empty() {
            lines.push(String::from("  CURRENT SESSIONS: (none)"));
        } else {
            lines.push(format!("  CURRENT SESSIONS ({}):", current_snapshots.len()));
            for (snap, is_stalled, is_collating, last_val, last_col) in &current_snapshots {
                let shard_str = format_shard_short(&snap.shard);
                let consensus_str =
                    if snap.consensus_type == super::consensus::ConsensusType::Simplex {
                        "splx"
                    } else {
                        "cch"
                    };
                let age = now.duration_since(snap.created_at).unwrap_or_default();
                let val_ago = format_time_ago(now_unix, *last_val);
                let col_ago = format_time_ago(now_unix, *last_col);
                let status_str = format!("{}", snap.status);
                let last_mc =
                    snap.last_accepted_mc_seqno.map_or("-".to_string(), |s| s.to_string());
                let phase_str = validation_state_phase_label(snap.status);
                lines.push(format!(
                    "    {:<8} cc={:<4} {:<4} {:<14} phase={:<13} rnd={:<4} collator={:<3} \
                     collating={:<3} stall={:<3} val_ago={:<6} col_ago={:<6} \
                     mc_init={:<6} mc_last={:<6} age={} id={:x}",
                    shard_str,
                    snap.cc_seqno,
                    consensus_str,
                    status_str,
                    phase_str,
                    snap.round,
                    if snap.is_collator { "yes" } else { "no" },
                    if *is_collating { "yes" } else { "no" },
                    if *is_stalled { "yes" } else { "no" },
                    val_ago,
                    col_ago,
                    snap.mc_initial_seqno,
                    last_mc,
                    format_duration_short(age),
                    snap.session_id,
                ));
            }
        }

        // ── Future sessions detail ──
        if future_snapshots.is_empty() {
            lines.push(String::from("  FUTURE SESSIONS: (none)"));
        } else {
            lines.push(format!("  FUTURE SESSIONS ({}):", future_snapshots.len()));
            for snap in &future_snapshots {
                let shard_str = format_shard_short(&snap.shard);
                let consensus_str =
                    if snap.consensus_type == super::consensus::ConsensusType::Simplex {
                        "splx"
                    } else {
                        "cch"
                    };
                let age = now.duration_since(snap.created_at).unwrap_or_default();
                lines.push(format!(
                    "    {:<8} cc={:<4} {:<4} {:<14} engine={:<3} key_seq={} age={} id={:x}",
                    shard_str,
                    snap.cc_seqno,
                    consensus_str,
                    format!("{}", snap.status),
                    if snap.has_engine { "yes" } else { "no" },
                    snap.key_seqno,
                    format_duration_short(age),
                    snap.session_id,
                ));
            }
        }

        lines.push(String::from("=== END VALIDATOR MANAGER METRICS ==="));
        log::info!(target: "validator_manager", "{}", lines.join("\n"));
    }

    fn read_catchain_config(&self, state: &ShardStateStuff) -> Result<CatchainConfig> {
        let state_extra = state.shard_state_extra()?;
        state_extra.config.catchain_config()
    }

    /// infinite loop with possible error cancellation
    async fn invoke(&mut self) -> Result<()> {
        self.load_destroyed_sessions()?;
        let last_applied_block_id =
            self.engine.load_last_applied_mc_block_id()?.ok_or_else(|| {
                error!("Cannot run validator_manager if no last applied block is present")
            })?;
        let last_applied_block_handle =
            self.engine.load_block_handle(&last_applied_block_id)?.ok_or_else(|| {
                error!("Cannot load handle for last applied master block {}", last_applied_block_id)
            })?;
        let mut mc_handle = if let Some(id) = self.engine.load_last_rotation_block_id()? {
            log::info!(
                target: "validator_manager",
                "Validator manager initialization: last rotation block: {}",
                id
            );
            self.engine
                .load_block_handle(&id)?
                .ok_or_else(|| error!("Cannot load handle for master block {}", id))?
        } else {
            log::info!(
                target: "validator_manager",
                "Validator manager initialization: no last rotation block, \
                using last applied block: {last_applied_block_id}"
            );
            last_applied_block_handle.clone()
        };

        //let block_observer = self.initialize_block_observer(&last_applied_block_handle).await?;

        while !self.engine.check_stop() {
            // Sample before update_shards so a release during that update is
            // observed even if no later masterchain block arrives.
            let recovery_generation = self.engine.finality_recovery_generation();
            log::trace!(
                target: "validator_manager",
                "Trying to load state for masterblock {}",
                mc_handle.id().seq_no
            );

            match self.engine.load_state(mc_handle.id()).await {
                Ok(mc_state) => {
                    let seqno = mc_handle.id().seq_no;
                    log::info!(target: "validator_manager", "Processing masterblock {seqno}");
                    log::trace!(
                        target: "validator_manager",
                        "Processing messages from masterblock {seqno}"
                    );
                    log::trace!(
                        target: "validator_manager",
                        "Updating shards according to masterblock {seqno}"
                    );
                    let update = self.update_shards(mc_state).await;
                    self.startup_recovery_gate.take();
                    match update {
                        Ok(()) => log::trace!(target: "validator_manager",
                            "Shards for masterblock {seqno} updated"),
                        Err(error) if crate::retired_history::is_retryable(&error) => {
                            // start_session releases its reservation on preparation
                            // failure. Keep the same group and retry through the
                            // bounded-frequency production wait path below.
                            log::warn!(target: "validator_manager",
                                "History preparation deferred at MC {seqno}: {error}");
                        }
                        Err(error) => return Err(error),
                    }
                }
                Err(e) => {
                    self.startup_recovery_gate.take();
                    if self.engine.validation_status().allows_validate() {
                        fail!(
                            "State for {} lost while validating (status {:?}): error '{}'",
                            mc_handle.id(),
                            self.engine.validation_status(),
                            e
                        )
                    }
                    log::info!(
                        target: "validator_manager",
                        "Processing masterblock {}: state not available, going forward",
                        mc_handle.id().seq_no
                    );
                }
            }

            mc_handle = match self
                .wait_next_mc_or_materialization_retry(&mc_handle, recovery_generation)
                .await?
            {
                Some(next) => next,
                None => return Ok(()),
            };
        }

        log::info!(
            target: "validator_manager",
            "Engine is stopped. Exiting from invocation loop (while applying state)"
        );
        Ok(())
    }
}

/// main entry point to validation process
pub fn start_validator_manager(
    engine: Arc<dyn EngineOperations>,
    runtime: tokio::runtime::Handle,
    config: ValidatorManagerConfig,
) -> Result<()> {
    spawn_validator_manager(engine, runtime, config)?;
    Ok(())
}

pub(crate) fn start_validator_manager_with_startup_gate(
    engine: Arc<dyn EngineOperations>,
    runtime: tokio::runtime::Handle,
    config: ValidatorManagerConfig,
    gate: super::finality_recovery_owner::RecoveryBootstrapGate,
) -> Result<()> {
    spawn_validator_manager_with_startup_gate(engine, runtime, config, Some(gate))?;
    Ok(())
}

fn spawn_validator_manager(
    engine: Arc<dyn EngineOperations>,
    runtime: tokio::runtime::Handle,
    config: ValidatorManagerConfig,
) -> Result<tokio::task::JoinHandle<()>> {
    spawn_validator_manager_with_startup_gate(engine, runtime, config, None)
}

fn spawn_validator_manager_with_startup_gate(
    engine: Arc<dyn EngineOperations>,
    runtime: tokio::runtime::Handle,
    config: ValidatorManagerConfig,
    startup_recovery_gate: Option<super::finality_recovery_owner::RecoveryBootstrapGate>,
) -> Result<tokio::task::JoinHandle<()>> {
    const CHECK_VALIDATOR_TIMEOUT: u64 = 60; //secs
    engine.clone().register_service_task("validator manager", 0, Box::new(move || {
        // This owner alone knows whether group/thread teardown was certified.
        engine.acquire_stop(Engine::MASK_SERVICE_VALIDATOR_MANAGER);
        runtime.clone().spawn(async move {
        let mut startup_recovery_gate = startup_recovery_gate;
        log::info!(
            target: "validator_manager",
            "checking if current node is a validator during {CHECK_VALIDATOR_TIMEOUT} secs"
        );
        match engine.consensus_transport_bindings() {
            Ok(bindings) if !bindings.is_empty() => log::warn!(target: "validator_manager",
                "consensus_transport_bindings are configured but confer no consensus membership, \
                 signer or transport identity; custody and the governing descriptors decide them"),
            Ok(_) => {}
            Err(error) => log::warn!(target: "validator_manager",
                "consensus_transport_bindings are unreadable and are ignored: {error}"),
        }
        // A node that holds no classical validator key and no consensus key
        // cannot be a member of any set.
        while !engine.has_local_validator_keys() {
            // With no local validator key there is no normal namespace to protect.
            startup_recovery_gate.take();
            log::trace!(target: "validator_manager", "Not a validator, waiting...");
            for _ in 0..CHECK_VALIDATOR_TIMEOUT {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if engine.check_stop() {
                    log::error!(target: "validator_manager", "Engine is stopped. exiting");
                    engine.release_stop(Engine::MASK_SERVICE_VALIDATOR_MANAGER);
                    return;
                }
            }
        }

        log::trace!(target: "validator_manager", "Starting validator manager");

        loop {
            if engine.check_stop() {
                break;
            }
            let mut manager =
                ValidatorManagerImpl::create(engine.clone(), runtime.clone(), config.clone());
            manager.startup_recovery_gate = startup_recovery_gate.take();
            let res = match std::panic::AssertUnwindSafe(manager.invoke()).catch_unwind().await {
                Ok(result) => result,
                Err(_) => {
                    manager.lifecycle_errors.insert("validator manager invocation panicked".to_owned());
                    Err(error!("validator manager invocation panicked"))
                }
            };
            let teardown = std::panic::AssertUnwindSafe(manager.stop_validation()).catch_unwind().await;
            let teardown = match teardown {
                Ok(result) => result,
                Err(_) => {
                    // A panic inside drain leaves ownership uncertified. Request
                    // global failure without exempting the manager's live bit.
                    engine.report_service_failure(0, "validator manager teardown panicked before certifying drain".to_owned());
                    return;
                }
            };
            if let Err(e) = teardown {
                // No replacement manager and no successful service-stop signal
                // when teardown could not certify termination.
                log::error!(target: "validator_manager", "FATAL: validator teardown failed; restart refused: {e}");
                manager.report_teardown_failure(e.to_string());
                return;
            }
            let Err(e) = res else { break };
            log::error!(
                target: "validator_manager",
                "FATAL!!! Unexpected error in validator manager, restarting: {e}"
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        log::info!(target: "validator_manager", "Exiting, validator manager is stopped");
        engine.release_stop(Engine::MASK_SERVICE_VALIDATOR_MANAGER);
    })
    }))
}

#[cfg(test)]
#[path = "tests/test_session_id.rs"]
mod test_session_id;

#[cfg(test)]
#[path = "tests/emulator_network_bootstrap.rs"]
pub(crate) mod emulator_network_bootstrap;

#[cfg(test)]
#[path = "tests/test_manager_lifecycle.rs"]
mod lifecycle_tests;

#[cfg(test)]
#[path = "tests/test_manager_cleanup.rs"]
mod cleanup_tests;

/// Drives the manager's retirement and cleanup paths against any engine,
/// for integration tests outside this module.
#[cfg(test)]
pub(crate) struct CleanupHarness(ValidatorManagerImpl);

#[cfg(test)]
impl CleanupHarness {
    pub(crate) fn new(engine: Arc<dyn EngineOperations>) -> Self {
        Self(ValidatorManagerImpl::create(
            engine,
            tokio::runtime::Handle::current(),
            ValidatorManagerConfig::default(),
        ))
    }
    /// Retires a group through the production path: fence and cleanup
    /// record persisted synced, then the preserving close.
    pub(crate) async fn retire(&mut self, id: UInt256, group: Arc<ValidatorGroup>) -> Result<()> {
        self.0.retire_group(id, group);
        self.0.drain_retiring().await
    }
    /// One cleanup tick, then every dispatched delete joined and completed.
    pub(crate) async fn tick(&mut self) {
        self.0.run_cleanup_tick().await;
        self.0.drain_cleanup_workers().await;
    }
    pub(crate) fn v2_outcome(&self, namespace: &str) -> Option<String> {
        self.0.cleanup_v2_verdicts.get(namespace).cloned()
    }
    pub(crate) fn delete_in_flight(&self, session: &UInt256) -> bool {
        self.0.cleanup.is_delete_in_flight(session)
    }
}
