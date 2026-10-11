// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Authenticate an untrusted retired-session locator before any source DB opens.
//! This grants neither signing authority nor permission to skip source PQ checks.
use crate::{
    boot::authenticate_recovered_state, engine_traits::EngineOperations,
    shard_state::ShardStateStuff,
    validator::validator_utils::try_calc_subset_for_workchain_standard,
};
use consensus_common::{
    session_runtime::{AuthenticatedSessionRuntime, LocalRole, SessionNetworkPin},
    simplex_protocol::SimplexProtocol,
};
use rtos_api::{session_identity::SessionCoordinates, WireProfile};
use rtos_block::{error, fail, BlockIdExt, KeyId, Result, ShardDescr, ShardIdent};
use simplex::finality_recovery::SessionRecoveryRecord;
use std::{collections::HashMap, path::PathBuf, sync::Arc};

pub(crate) async fn authenticate_retired_session(
    engine: &dyn EngineOperations,
    record: &SessionRecoveryRecord,
) -> Result<Arc<AuthenticatedSessionRuntime>> {
    if &record.pin.zerostate != engine.zerostate_id()? {
        fail!("Retired session network pin mismatch");
    }
    if record.protocol != SimplexProtocol::PrivateObserversPlumtree
        || record.wire_profile != WireProfile::T0
    {
        fail!("Retired session protocol/wire unsupported");
    }
    let binding = &record.binding;
    let verified = authenticate_recovered_state(engine, &binding.governing_masterchain).await?;
    let state = verified.state();
    if state.state()?.global_id() != record.pin.global_id {
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
        KeyId::from_data(*record.local_adnl.as_array()),
    )?
    .bind_recovery_anchor(binding.governing_masterchain.clone())?;
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
    Ok(Arc::new(runtime))
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
        for next_since in [0, u32::MAX] {
            let engine = history(next_since)?;
            for observer in [false, true] {
                for cc in [7, 8] {
                    let record = locator(&engine, cc, cc == 8 && next_since == 0, observer)?;
                    let runtime = authenticate_retired_session(&engine, &record).await?;
                    assert_eq!(runtime.session_id(), &record.session_id);
                    assert_eq!(runtime.recovery_binding(), Some(&record.binding));
                    assert_eq!(runtime.local_role() == LocalRole::Observer, observer);
                }
            }
        }
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
}
