// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Authenticate an untrusted retired-session locator before any source DB opens.
//! This grants neither signing authority nor permission to skip source PQ checks.
use crate::{
    engine_traits::EngineOperations,
    retired_history::authenticate_state as authenticate_recovered_state,
    shard_state::ShardStateStuff,
    validator::validator_utils::try_calc_subset_for_workchain_standard,
};
use consensus_common::{
    finality_delivery::{CloseFinalityRequest, FinalityDeliveryRole},
    session_runtime::{
        AuthenticatedSessionRuntime, LocalRole, SessionNetworkPin, SessionRecoveryBinding,
    },
    simplex_protocol::SimplexProtocol,
};
use rtos_api::{session_identity::SessionCoordinates, WireProfile};
use rtos_block::{error, fail, BlockIdExt, KeyId, Result, ShardDescr, ShardIdent};
use simplex::finality_recovery::SessionRecoveryRecord;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

/// Node-only authentication receipt. Its private fields can only be produced
/// after pinned history, scheduled membership, options and start parents agree.
#[derive(Debug)]
pub(crate) struct AuthenticatedRetiredSession {
    runtime: Arc<AuthenticatedSessionRuntime>,
    options: simplex::SessionOptions,
    record: SessionRecoveryRecord,
}
impl AuthenticatedRetiredSession {
    pub(crate) fn runtime(&self) -> &Arc<AuthenticatedSessionRuntime> {
        &self.runtime
    }
    pub(crate) fn options(&self) -> &simplex::SessionOptions {
        &self.options
    }
    pub(crate) fn record(&self) -> &SessionRecoveryRecord {
        &self.record
    }
}

/// Rebuild only historical session identity. No source floor, session worker,
/// signer or current transport secret is created/required by this operation.
async fn authenticate_identity(
    engine: &dyn EngineOperations,
    pin: &SessionNetworkPin,
    binding: &SessionRecoveryBinding,
    local_adnl: &rtos_block::UInt256,
) -> Result<(AuthenticatedSessionRuntime, Arc<ShardStateStuff>)> {
    let verified = authenticate_recovered_state(engine, &binding.governing_masterchain).await?;
    derive_identity(engine, pin, binding, local_adnl, &verified)
}

fn derive_identity(
    engine: &dyn EngineOperations,
    pin: &SessionNetworkPin,
    binding: &SessionRecoveryBinding,
    local_adnl: &rtos_block::UInt256,
    verified: &crate::block_proof::VerifiedMasterchainState,
) -> Result<(AuthenticatedSessionRuntime, Arc<ShardStateStuff>)> {
    if &pin.zerostate != engine.zerostate_id()? {
        fail!("Closing/retired network pin mismatch");
    }
    if verified.state().block_id() != &binding.governing_masterchain {
        fail!("Verified source recovery anchor differs from binding");
    }
    let state = verified.state().clone();
    if state.state()?.global_id() != pin.global_id {
        fail!("Retired session global ID mismatch");
    }
    let coordinates = &binding.coordinates;
    let extra = state.shard_state_extra()?;
    let key_seqno = if extra.after_key_block || state.block_id().seq_no() == 0 {
        state.block_id().seq_no()
    } else {
        extra.last_key_block.as_ref().ok_or_else(|| error!("Missing historical key block"))?.seq_no
    };
    if coordinates.last_key_block_seqno != key_seqno
        || coordinates.new_catchain_ids
        || coordinates.vertical_seqno as usize > engine.hardforks().len()
    {
        fail!("Retired session derivation coordinates mismatch");
    }
    let config = state.config_params()?;
    let catchain = config.catchain_config()?;
    let (current_cc, lifetime) = if coordinates.shard.is_masterchain() {
        (extra.validator_info.catchain_seqno, catchain.mc_catchain_lifetime)
    } else {
        (extra.shards().calc_shard_cc_seqno(&coordinates.shard)?, catchain.shard_catchain_lifetime)
    };
    let current = config.validator_set()?;
    let next = config.next_validator_set()?;
    let set = if coordinates.catchain_seqno == current_cc {
        &current
    } else if current_cc.checked_add(1) == Some(coordinates.catchain_seqno) {
        if lifetime == 0 {
            fail!("Zero historical catchain lifetime");
        }
        let next_boundary =
            (u64::from(state.state()?.gen_time()) / u64::from(lifetime) + 1) * u64::from(lifetime);
        if next.total() > 0 && u64::from(next.utime_since()) <= next_boundary {
            &next
        } else {
            &current
        }
    } else {
        fail!("Retired session catchain is outside current/next schedule");
    };
    let subset = try_calc_subset_for_workchain_standard(
        set,
        config,
        &coordinates.shard,
        coordinates.catchain_seqno,
    )?
    .ok_or_else(|| error!("Retired session committee unavailable"))?;
    let runtime = AuthenticatedSessionRuntime::from_authenticated_config(
        SessionNetworkPin {
            global_id: state.state()?.global_id(),
            zerostate: engine.zerostate_id()?.clone(),
        },
        config,
        SessionCoordinates {
            shard: &coordinates.shard,
            catchain_seqno: coordinates.catchain_seqno,
            vertical_seqno: coordinates.vertical_seqno,
            last_key_block_seqno: key_seqno,
            new_catchain_ids: coordinates.new_catchain_ids,
        },
        subset.validators,
        KeyId::from_data(*local_adnl.as_array()),
    )?
    .bind_recovery_anchor(binding.governing_masterchain.clone())?;
    Ok((runtime, state))
}

/// Authenticate a closed source's confirmation identity without retaining its
/// consensus-start floor. The node still verifies the exact source confirmation
/// and its private durable custody; this runtime alone authorizes no release.
pub(crate) async fn authenticate_closing_runtime(
    engine: &dyn EngineOperations,
    request: &CloseFinalityRequest,
    namespace: &Path,
) -> Result<Arc<AuthenticatedSessionRuntime>> {
    let domain = &request.domain;
    if domain.protocol != SimplexProtocol::PrivateObserversPlumtree
        || domain.wire_profile != WireProfile::T0
        || request.canonical.role != FinalityDeliveryRole::Final
        || !request.canonical.block_id.shard().is_masterchain()
        || request.canonical.block_id.seq_no() == 0
    {
        fail!("Unsupported closing source domain/role");
    }
    let binding = domain
        .recovery_binding
        .as_ref()
        .ok_or_else(|| error!("Closing identity lacks authenticated recovery anchor"))?;
    let (runtime, _) =
        authenticate_identity(engine, &domain.pin, binding, &request.canonical.local_adnl).await?;
    validate_closing_identity(&runtime, request)?;
    let root = PathBuf::from(engine.db_root_dir()?).join("catchains");
    let expected = PathBuf::from(
        runtime.runtime_directory(root.to_str().ok_or_else(|| error!("Invalid DB root"))?)?,
    );
    if namespace != expected {
        fail!("Closing source namespace mismatch");
    }
    Ok(Arc::new(runtime))
}

fn validate_closing_identity(
    runtime: &AuthenticatedSessionRuntime,
    request: &CloseFinalityRequest,
) -> Result<()> {
    let domain = &request.domain;
    let binding = domain
        .recovery_binding
        .as_ref()
        .ok_or_else(|| error!("Closing identity lacks recovery anchor"))?;
    if domain.protocol != SimplexProtocol::PrivateObserversPlumtree
        || domain.wire_profile != WireProfile::T0
        || request.canonical.role != FinalityDeliveryRole::Final
        || !request.canonical.block_id.shard().is_masterchain()
        || request.canonical.block_id.seq_no() == 0
    {
        fail!("Unsupported closing source domain/role");
    }
    let role = match runtime.local_role() {
        LocalRole::Validator(i) => Some(i),
        LocalRole::Observer => None,
    };
    if runtime.protocol() != domain.protocol
        || runtime.carrier_version() != domain.carrier_version
        || runtime.wire_profile() != domain.wire_profile
        || runtime.profile() != &domain.profile
        || runtime.session_id() != &domain.session_id
        || role != request.canonical.local_validator_index
        || runtime.recovery_binding() != Some(binding)
        || runtime.shard() != request.canonical.block_id.shard()
        || !runtime
            .committee()
            .iter()
            .any(|v| v.validator_id().ok().as_ref() == Some(&request.canonical.source_validator))
    {
        fail!("Closing source historical identity/role mismatch");
    }
    Ok(())
}

/// Consume the caller's already authenticated state under its own read budget.
/// No IO or unbudgeted reauthentication occurs in this identity derivation.
pub(crate) fn validate_close_recovery_binding(
    engine: &dyn EngineOperations,
    binding: &crate::repair_lease_binding::RepairLeaseBinding,
    verified: &crate::block_proof::VerifiedMasterchainState,
) -> Result<()> {
    use consensus_common::finality_delivery::FinalityCloseDomain;
    binding.validate()?;
    let domain = &binding.domain;
    if &domain.history_init != engine.init_mc_block_id() {
        fail!("Close history checkpoint mismatch");
    }
    let recovery = SessionRecoveryBinding {
        governing_masterchain: domain.source_recovery_anchor.clone(),
        coordinates: domain.source_recovery_coordinates.clone(),
    };
    let pin =
        SessionNetworkPin { zerostate: domain.zerostate.clone(), global_id: domain.global_id };
    let (runtime, _) =
        derive_identity(engine, &pin, &recovery, &binding.canonical.local_adnl, verified)?;
    let request = CloseFinalityRequest {
        canonical: binding.canonical.clone(),
        domain: FinalityCloseDomain {
            pin,
            protocol: domain.protocol,
            carrier_version: domain.carrier_version,
            wire_profile: domain.wire_profile,
            profile: domain.profile.clone(),
            session_id: domain.session_id.clone(),
            recovery_binding: Some(recovery),
        },
        source_digest: binding.source_digest.clone(),
        created_at_unix_secs: binding.created_at_unix_secs,
    };
    validate_closing_identity(&runtime, &request)
}

pub(crate) async fn authenticate_retired_session(
    engine: &dyn EngineOperations,
    record: &SessionRecoveryRecord,
) -> Result<AuthenticatedRetiredSession> {
    if &record.pin.zerostate != engine.zerostate_id()? {
        fail!("Retired session network pin mismatch");
    }
    if record.protocol != SimplexProtocol::PrivateObserversPlumtree
        || record.wire_profile != WireProfile::T0
    {
        fail!("Retired session protocol/wire unsupported");
    }
    let binding = &record.binding;
    let (runtime, state) =
        authenticate_identity(engine, &record.pin, binding, &record.local_adnl).await?;
    let coordinates = &binding.coordinates;
    let config = state.config_params()?;
    let role = match runtime.local_role() {
        LocalRole::Validator(index) => Some(index),
        LocalRole::Observer => None,
    };
    if runtime.protocol() != record.protocol
        || runtime.carrier_version() != record.carrier_version
        || runtime.wire_profile() != record.wire_profile
        || runtime.profile() != &record.profile
        || runtime.session_id() != &record.session_id
        || role != record.local_validator_index
        || runtime.recovery_binding() != Some(binding)
    {
        fail!("Retired session identity/role mismatch");
    }
    let root = PathBuf::from(engine.db_root_dir()?).join("catchains");
    let expected = PathBuf::from(
        runtime.runtime_directory(root.to_str().ok_or_else(|| error!("Invalid DB root"))?)?,
    );
    if record.namespace != expected {
        fail!("Retired session namespace mismatch");
    }

    // SessionProcessor initializes its sequence floor directly from prev_blocks.
    // An arbitrary high persisted floor could silently skip certificate debt.
    // Future sessions can start after their governing snapshot: authenticate the
    // separate start anchor and derive the ordered parents from its shard tops.
    if record.start_masterchain.seq_no() < binding.governing_masterchain.seq_no() {
        fail!("Retired session start predates governing anchor");
    }
    let start = authenticate_recovered_state(engine, &record.start_masterchain).await?;
    if start.state().block_id() != state.block_id()
        && !start.state().has_prev_block(state.block_id())?
    {
        fail!("Retired session start does not descend from governing anchor");
    }
    let parents = authenticated_start_parents(start.state(), &coordinates.shard)?;
    if record.prev_blocks != parents {
        fail!("Retired session previous block floor mismatch");
    }
    let options =
        super::validator_manager::build_historical_simplex_options(config, &coordinates.shard)?;
    options.validate_authenticated(&runtime)?;
    Ok(AuthenticatedRetiredSession { runtime: Arc::new(runtime), options, record: record.clone() })
}

/// Same effective-shard parent ordering used by manager::update_shards.
fn authenticated_start_parents(
    state: &ShardStateStuff,
    shard: &ShardIdent,
) -> Result<Vec<BlockIdExt>> {
    if shard.is_masterchain() {
        return Ok(vec![state.block_id().clone()]);
    }
    let mut parents: HashMap<ShardIdent, Vec<Option<BlockIdExt>>> = HashMap::new();
    state.shard_state_extra()?.shards().iterate_shards(
        |ident: ShardIdent, descr: ShardDescr| {
            let top = BlockIdExt::with_params(
                ident.clone(),
                descr.seq_no,
                descr.root_hash,
                descr.file_hash,
            );
            if descr.before_split {
                let (left, right) = ident.split()?;
                parents.insert(left, vec![Some(top.clone())]);
                parents.insert(right, vec![Some(top)]);
            } else if descr.before_merge {
                let parent = ident.merge()?;
                let (_, right) = parent.split()?;
                let entries = parents.entry(parent).or_insert_with(|| vec![None, None]);
                entries[usize::from(right == ident)] = Some(top);
            } else {
                parents.insert(ident, vec![Some(top)]);
            }
            Ok(true)
        },
    )?;
    parents
        .remove(shard)
        .ok_or_else(|| error!("Retired session shard absent from authenticated start"))?
        .into_iter()
        .map(|parent| parent.ok_or_else(|| error!("Incomplete authenticated merge parents")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtos_block::{Deserializable, Serializable, ShardStateUnsplit, UInt256, ValidatorSet};

    struct HistoryEngine {
        state: Arc<ShardStateStuff>,
        pin: BlockIdExt,
        root: tempfile::TempDir,
    }
    #[async_trait::async_trait]
    impl EngineOperations for HistoryEngine {
        fn zerostate_id(&self) -> Result<&BlockIdExt> {
            Ok(&self.pin)
        }
        fn init_mc_block_id(&self) -> &BlockIdExt {
            &self.pin
        }
        fn db_root_dir(&self) -> Result<&str> {
            Ok(self.root.path().to_str().unwrap())
        }
        fn hardforks(&self) -> &[BlockIdExt] {
            &[]
        }
        fn check_stop(&self) -> bool {
            false
        }
        async fn load_mc_zero_state(&self) -> Result<Arc<ShardStateStuff>> {
            Ok(self.state.clone())
        }
        async fn load_state(&self, id: &BlockIdExt) -> Result<Arc<ShardStateStuff>> {
            if id != self.state.block_id() {
                fail!("Historical state unavailable");
            }
            Ok(self.state.clone())
        }
    }

    // Real canonical state + explicit full zerostate pin, with an I/O-only
    // adapter. No mock "verified" receipt or preauthenticated config shortcut.
    fn history(next_since: u32) -> Result<HistoryEngine> {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../full_node/finality/testdata/v2-publication-spool.json"
        ))?;
        let bytes = hex::decode(fixture["state_boc"].as_str().unwrap())?;
        let mut state = ShardStateUnsplit::construct_from_bytes(&bytes)?;
        let mut extra = state.read_custom()?.unwrap();
        extra.validator_info.catchain_seqno = 7;
        extra.after_key_block = true;
        let mut catchain = extra.config.catchain_config()?;
        catchain.mc_catchain_lifetime = 100;
        catchain.shard_catchain_lifetime = 100;
        extra.config.set_config(rtos_block::ConfigParamEnum::ConfigParam28(catchain))?;
        let current = extra.config.validator_set()?;
        let mut next = current.list().to_vec();
        next.rotate_left(1);
        let next = ValidatorSet::with_cc_seqno(next_since, u32::MAX, current.main(), 0, next)?;
        extra.config.set_config(rtos_block::ConfigParamEnum::ConfigParam36(
            rtos_block::ConfigParam36 { next_validators: next },
        ))?;
        state.set_gen_time(1002);
        state.write_custom(Some(&extra))?;
        pinned(state)
    }
    fn pinned(state: ShardStateUnsplit) -> Result<HistoryEngine> {
        let cell = state.serialize()?;
        let bytes = rtos_block::write_boc(&cell)?;
        let pin = BlockIdExt::with_params(
            ShardIdent::masterchain(),
            0,
            cell.repr_hash().clone(),
            UInt256::calc_file_hash(&bytes),
        );
        let state = ShardStateStuff::from_root_cell(
            pin.clone(),
            cell,
            #[cfg(feature = "telemetry")]
            &crate::collator_test_bundle::create_engine_telemetry(),
            &crate::collator_test_bundle::create_engine_allocated(),
        )?;
        Ok(HistoryEngine { state, pin, root: tempfile::tempdir()? })
    }
    fn locator(
        engine: &HistoryEngine,
        cc: u32,
        use_next: bool,
        observer: bool,
    ) -> Result<SessionRecoveryRecord> {
        locator_for_shard(engine, cc, use_next, observer, ShardIdent::masterchain())
    }
    fn locator_for_shard(
        engine: &HistoryEngine,
        cc: u32,
        use_next: bool,
        observer: bool,
        shard: ShardIdent,
    ) -> Result<SessionRecoveryRecord> {
        let config = engine.state.config_params()?;
        let set = if use_next { config.next_validator_set()? } else { config.validator_set()? };
        let subset = try_calc_subset_for_workchain_standard(&set, config, &shard, cc)?.unwrap();
        let local = if observer {
            KeyId::from_data([0x79; 32])
        } else {
            subset.validators[0].adnl_addr()?
        };
        let runtime = AuthenticatedSessionRuntime::from_authenticated_config(
            SessionNetworkPin {
                global_id: engine.state.state()?.global_id(),
                zerostate: engine.pin.clone(),
            },
            config,
            SessionCoordinates {
                shard: &shard,
                catchain_seqno: cc,
                vertical_seqno: 0,
                last_key_block_seqno: 0,
                new_catchain_ids: false,
            },
            subset.validators,
            local,
        )?
        .bind_recovery_anchor(engine.pin.clone())?;
        let root = engine.root.path().join("catchains");
        Ok(SessionRecoveryRecord {
            pin: runtime.pin().clone(),
            binding: runtime.recovery_binding().unwrap().clone(),
            protocol: runtime.protocol(),
            carrier_version: runtime.carrier_version(),
            wire_profile: runtime.wire_profile(),
            profile: runtime.profile().clone(),
            session_id: runtime.session_id().clone(),
            local_adnl: UInt256::from(*runtime.local_adnl().data()),
            local_validator_index: match runtime.local_role() {
                LocalRole::Validator(index) => Some(index),
                LocalRole::Observer => None,
            },
            start_masterchain: engine.pin.clone(),
            prev_blocks: authenticated_start_parents(&engine.state, &shard)?,
            namespace: PathBuf::from(runtime.runtime_directory(root.to_str().unwrap())?),
        })
    }

    #[tokio::test]
    async fn retired_session_auth_rebuilds_current_next_and_observer_from_pinned_state(
    ) -> Result<()> {
        for next_since in [1100, 1101] {
            let engine = history(next_since)?;
            for observer in [false, true] {
                for cc in [7, 8] {
                    let record = locator(&engine, cc, cc == 8 && next_since == 1100, observer)?;
                    let authenticated = authenticate_retired_session(&engine, &record).await?;
                    let runtime = authenticated.runtime();
                    assert_eq!(runtime.session_id(), &record.session_id);
                    assert_eq!(runtime.recovery_binding(), Some(&record.binding));
                    assert_eq!(runtime.local_role() == LocalRole::Observer, observer);
                }
            }
        }
        // This authenticated-but-invalid schedule must remain rejected. Do not
        // let the fixture fix silently turn zero-period input into a default.
        let original = history(1100)?;
        let mut state = original.state.state()?.clone();
        let mut extra = state.read_custom()?.unwrap();
        let mut catchain = extra.config.catchain_config()?;
        catchain.mc_catchain_lifetime = 0;
        extra.config.set_config(rtos_block::ConfigParamEnum::ConfigParam28(catchain))?;
        state.write_custom(Some(&extra))?;
        let zero = pinned(state)?;
        let error = authenticate_retired_session(&zero, &locator(&zero, 8, true, false)?)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Zero historical catchain lifetime"), "{error}");
        Ok(())
    }

    #[tokio::test]
    async fn retired_session_auth_rejects_untrusted_identity_history_and_previous_floor(
    ) -> Result<()> {
        let engine = history(0)?;
        let valid = locator(&engine, 7, false, false)?;
        let mut bad = Vec::new();
        let mut item = valid.clone();
        item.pin.zerostate.file_hash = UInt256::from([1; 32]);
        bad.push(item);
        let mut item = valid.clone();
        item.pin.global_id += 1;
        bad.push(item);
        let mut item = valid.clone();
        item.binding.governing_masterchain.root_hash = UInt256::from([2; 32]);
        bad.push(item);
        let mut item = valid.clone();
        item.start_masterchain.file_hash = UInt256::from([3; 32]);
        bad.push(item);
        let mut item = valid.clone();
        item.profile = UInt256::from([4; 32]);
        bad.push(item);
        let mut item = valid.clone();
        item.session_id = UInt256::from([5; 32]);
        bad.push(item);
        let mut item = valid.clone();
        item.local_validator_index = Some(1);
        bad.push(item);
        let mut item = valid.clone();
        item.local_adnl = UInt256::from([6; 32]);
        bad.push(item);
        let mut item = valid.clone();
        item.carrier_version += 1;
        bad.push(item);
        let mut item = valid.clone();
        item.wire_profile = WireProfile::Legacy;
        bad.push(item);
        let mut item = valid.clone();
        item.namespace.push("..");
        bad.push(item);
        let mut item = valid.clone();
        item.binding.coordinates.last_key_block_seqno = 1;
        bad.push(item);
        let mut item = valid.clone();
        item.binding.coordinates.vertical_seqno = 1;
        bad.push(item);
        let mut item = valid.clone();
        item.binding.coordinates.new_catchain_ids = true;
        bad.push(item);
        let mut item = valid.clone();
        item.binding.coordinates.catchain_seqno = 9;
        bad.push(item);
        let mut item = valid.clone();
        item.prev_blocks[0].seq_no = 10000;
        bad.push(item);
        let mut item = valid.clone();
        item.prev_blocks.clear();
        bad.push(item);
        // A fully rederived but wrongly scheduled next committee is also rejected.
        bad.push(locator(&engine, 8, false, false)?);
        for (index, record) in bad.into_iter().enumerate() {
            assert!(
                authenticate_retired_session(&engine, &record).await.is_err(),
                "mutation {index} accepted"
            );
        }
        let later = history(u32::MAX)?;
        assert!(authenticate_retired_session(&later, &locator(&later, 8, true, false)?)
            .await
            .is_err());
        // A substituted state with an unchanged advertised ID cannot replace the
        // actual state committed by the explicit network pin.
        let mut forged = history(u32::MAX)?;
        forged.state = ShardStateStuff::from_root_cell(
            engine.pin.clone(),
            forged.state.root_cell().clone(),
            #[cfg(feature = "telemetry")]
            &crate::collator_test_bundle::create_engine_telemetry(),
            &crate::collator_test_bundle::create_engine_allocated(),
        )?;
        forged.pin = engine.pin.clone();
        assert!(authenticate_retired_session(&forged, &valid).await.is_err());
        Ok(())
    }
    #[tokio::test]
    async fn retired_session_auth_checks_ordered_split_and_merge_start_parents() -> Result<()> {
        let original = history(0)?;
        let mut state = original.state.state()?.clone();
        let mut extra = state.read_custom()?.unwrap();
        let full = ShardIdent::with_tagged_prefix(0, rtos_block::SHARD_FULL)?;
        let (left, right) = full.split()?;
        if extra.shards().get_shard(&full)?.is_none() {
            extra.shards.add_workchain(
                0,
                0,
                UInt256::from([0x41; 32]),
                UInt256::from([0x42; 32]),
            )?;
        }
        extra.shards.update_shard(&full, |mut top| {
            top.seq_no = 17;
            top.next_catchain_seqno = 7;
            top.before_split = true;
            Ok(top)
        })?;
        state.write_custom(Some(&extra))?;
        let split = pinned(state.clone())?;
        for shard in [&left, &right] {
            let cc = split.state.shard_state_extra()?.shards().calc_shard_cc_seqno(shard)?;
            let record = locator_for_shard(&split, cc, false, false, shard.clone())?;
            assert_eq!(record.prev_blocks.len(), 1);
            assert_eq!(record.prev_blocks[0].shard(), &full);
            authenticate_retired_session(&split, &record).await?;
        }
        extra.shards.split_shard(&full, |mut top| {
            top.before_split = false;
            top.before_merge = true;
            let mut other = top.clone();
            other.seq_no = 19;
            other.root_hash = UInt256::from([0x43; 32]);
            other.file_hash = UInt256::from([0x44; 32]);
            Ok((top, other))
        })?;
        state.write_custom(Some(&extra))?;
        let merge = pinned(state)?;
        let cc = merge.state.shard_state_extra()?.shards().calc_shard_cc_seqno(&full)?;
        let record = locator_for_shard(&merge, cc, false, false, full)?;
        assert_eq!(record.prev_blocks.len(), 2);
        assert_eq!(record.prev_blocks[0].shard(), &left);
        assert_eq!(record.prev_blocks[1].shard(), &right);
        authenticate_retired_session(&merge, &record).await?;
        let mut reversed = record.clone();
        reversed.prev_blocks.reverse();
        assert!(authenticate_retired_session(&merge, &reversed).await.is_err());
        let mut high = record.clone();
        high.prev_blocks[1].seq_no += 1;
        assert!(authenticate_retired_session(&merge, &high).await.is_err());
        Ok(())
    }
    #[tokio::test]
    async fn retired_session_auth_receipt_freezes_historical_runtime_options() -> Result<()> {
        let original = history(1100)?;
        let mut state = original.state.state()?.clone();
        let mut extra = state.read_custom()?.unwrap();
        let mut consensus = extra.config.consensus_config()?;
        consensus.max_block_bytes = 123456;
        consensus.max_collated_bytes = 234567;
        extra.config.set_config(rtos_block::ConfigParamEnum::ConfigParam29(consensus))?;
        let mut selected = extra.config.selected_simplex_config(true)?.unwrap().config;
        selected.slots_per_leader_window = 5;
        selected.noncritical_params.target_rate_ms = 237;
        selected.noncritical_params.candidate_resolve_timeout_ms = 731;
        selected.noncritical_params.candidate_resolve_cooldown_ms = 619;
        selected.noncritical_params.standstill_max_egress_bytes_per_s = 7654321;
        selected.use_quic = false;
        extra.config.set_config(rtos_block::ConfigParamEnum::ConfigParam30(
            rtos_block::NewConsensusConfigAll { mc: Some(selected.clone()), shard: Some(selected) },
        ))?;
        state.write_custom(Some(&extra))?;
        let engine = pinned(state)?;
        let mut record = locator(&engine, 7, false, false)?;
        let authenticated = authenticate_retired_session(&engine, &record).await?;
        let options = authenticated.options();
        assert_eq!(options.max_block_size, 123456);
        assert_eq!(options.max_collated_data_size, 234567);
        assert_eq!(options.slots_per_leader_window, 5);
        assert_eq!(options.target_rate, std::time::Duration::from_millis(237));
        assert_eq!(options.candidate_resolve_timeout, std::time::Duration::from_millis(731));
        assert_eq!(options.candidate_resolve_cooldown, std::time::Duration::from_millis(619));
        assert_eq!(options.standstill_max_egress_bytes_per_s, 7654321);
        assert!(!options.use_quic);
        assert!(options.empty_block_mc_lag_threshold.is_none());
        options.validate_authenticated(authenticated.runtime())?;
        record.prev_blocks.clear();
        record.profile = UInt256::ZERO;
        assert!(!authenticated.record().prev_blocks.is_empty());
        assert_ne!(authenticated.record().profile, record.profile);
        assert_eq!(authenticated.record().session_id, *authenticated.runtime().session_id());
        Ok(())
    }
    fn closing_request(
        record: &SessionRecoveryRecord,
        source_validator: UInt256,
    ) -> CloseFinalityRequest {
        use consensus_common::finality_delivery::{CanonicalFinalityRequest, FinalityCloseDomain};
        CloseFinalityRequest {
            canonical: CanonicalFinalityRequest {
                node_receipt: UInt256::from([0x52; 32]),
                block_id: BlockIdExt::with_params(
                    ShardIdent::masterchain(),
                    1,
                    UInt256::from([0x53; 32]),
                    UInt256::from([0x54; 32]),
                ),
                role: FinalityDeliveryRole::Final,
                local_adnl: record.local_adnl.clone(),
                local_validator_index: record.local_validator_index,
                source_validator,
            },
            domain: FinalityCloseDomain {
                pin: record.pin.clone(),
                protocol: record.protocol,
                carrier_version: record.carrier_version,
                wire_profile: record.wire_profile,
                profile: record.profile.clone(),
                session_id: record.session_id.clone(),
                recovery_binding: Some(record.binding.clone()),
            },
            source_digest: UInt256::from([0x55; 32]),
            created_at_unix_secs: 100,
        }
    }
    #[tokio::test]
    async fn closing_identity_authenticates_historical_role_without_start_floor() -> Result<()> {
        let engine = history(0)?;
        for observer in [false, true] {
            let mut record = locator(&engine, 7, false, observer)?;
            let (expected, _) =
                authenticate_identity(&engine, &record.pin, &record.binding, &record.local_adnl)
                    .await?;
            let request = closing_request(&record, expected.committee()[0].validator_id()?);
            // The closing API has no start/prev inputs. These invalid consensus
            // replay coordinates must still fail the original session API.
            record.start_masterchain.file_hash = UInt256::from([0xfa; 32]);
            record.prev_blocks.clear();
            let runtime =
                authenticate_closing_runtime(&engine, &request, &record.namespace).await?;
            assert_eq!(runtime.local_role(), expected.local_role());
            assert_eq!(runtime.session_id(), expected.session_id());
            assert!(authenticate_retired_session(&engine, &record).await.is_err());
        }
        Ok(())
    }
    #[tokio::test]
    async fn closing_identity_rejects_domain_anchor_coordinates_role_and_namespace() -> Result<()> {
        let engine = history(0)?;
        let record = locator(&engine, 7, false, false)?;
        let (runtime, _) =
            authenticate_identity(&engine, &record.pin, &record.binding, &record.local_adnl)
                .await?;
        let valid = closing_request(&record, runtime.committee()[0].validator_id()?);
        for mutation in 0..12 {
            let mut request = valid.clone();
            let mut path = record.namespace.clone();
            match mutation {
                0 => request.domain.recovery_binding = None,
                1 => {
                    request.domain.recovery_binding.as_mut().unwrap().coordinates.catchain_seqno =
                        99
                }
                2 => {
                    request
                        .domain
                        .recovery_binding
                        .as_mut()
                        .unwrap()
                        .governing_masterchain
                        .file_hash = UInt256::from([0xee; 32])
                }
                3 => request.domain.session_id = UInt256::default(),
                4 => request.canonical.local_validator_index = None,
                5 => request.canonical.local_adnl = UInt256::default(),
                6 => path.push(".."),
                7 => request.domain.pin.global_id += 1,
                8 => request.domain.profile = UInt256::default(),
                9 => request.canonical.role = FinalityDeliveryRole::Approval,
                10 => request.canonical.source_validator = UInt256::default(),
                _ => {
                    request
                        .domain
                        .recovery_binding
                        .as_mut()
                        .unwrap()
                        .coordinates
                        .last_key_block_seqno = 1
                }
            }
            assert!(
                authenticate_closing_runtime(&engine, &request, &path).await.is_err(),
                "mutation {mutation}"
            );
        }
        // A substitute root under the same advertised anchor must not provide
        // authority even if its claimed coordinates happen to match.
        let mut forged = history(1101)?;
        forged.pin = engine.pin.clone();
        assert!(authenticate_closing_runtime(&forged, &valid, &record.namespace).await.is_err());
        Ok(())
    }
    #[tokio::test]
    async fn closing_binding_uses_exact_preverified_anchor_and_shared_derivation() -> Result<()> {
        use crate::repair_lease_binding::{RepairLeaseBinding, RepairLeaseDomain};
        let engine = history(0)?;
        let record = locator(&engine, 7, false, false)?;
        let verified =
            authenticate_recovered_state(&engine, &record.binding.governing_masterchain).await?;
        let (runtime, _) =
            derive_identity(&engine, &record.pin, &record.binding, &record.local_adnl, &verified)?;
        let request = closing_request(&record, runtime.committee()[0].validator_id()?);
        let binding = RepairLeaseBinding {
            record_id: 1,
            delivery_id: request.canonical.node_receipt.clone(),
            canonical: request.canonical,
            domain: RepairLeaseDomain {
                zerostate: record.pin.zerostate,
                global_id: record.pin.global_id,
                history_init: engine.pin.clone(),
                source_recovery_anchor: record.binding.governing_masterchain,
                source_recovery_coordinates: record.binding.coordinates,
                protocol: record.protocol,
                profile: record.profile,
                session_id: record.session_id,
                carrier_version: record.carrier_version,
                wire_profile: record.wire_profile,
            },
            source_digest: request.source_digest,
            canonical_digest: UInt256::from([7; 32]),
            created_at_unix_secs: 100,
            expires_at_unix_secs: 200,
            effects_digest: UInt256::from([8; 32]),
            close_generation: 1,
        };
        validate_close_recovery_binding(&engine, &binding, &verified)?;
        for variant in 0..5 {
            let mut bad = binding.clone();
            match variant {
                0 => bad.domain.source_recovery_anchor.file_hash = UInt256::default(),
                1 => bad.domain.source_recovery_coordinates.catchain_seqno += 5,
                2 => bad.domain.session_id = UInt256::default(),
                3 => bad.canonical.local_validator_index = None,
                _ => bad.domain.history_init.file_hash = UInt256::default(),
            }
            assert!(
                validate_close_recovery_binding(&engine, &bad, &verified).is_err(),
                "case {variant}"
            );
        }
        Ok(())
    }
}
