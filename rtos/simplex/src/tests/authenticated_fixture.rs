// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Authenticated configuration fixtures; transport secrets are not PQ signing keys.
use consensus_common::session_runtime::{AuthenticatedSessionRuntime, SessionNetworkPin};
use rtos_api::session_identity::SessionCoordinates;
use rtos_block::*;
use std::sync::Arc;

pub fn runtime(
    validator: bool,
) -> (Arc<AuthenticatedSessionRuntime>, crate::PrivateKey, crate::SessionOptions) {
    let (nodes, keys) = crate::pq_fixture::members();
    let members: Vec<_> = nodes.iter().map(|node| node.descriptor.clone().unwrap()).collect();
    let transport = if validator {
        keys[0].clone()
    } else {
        Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[0x71; 32]).unwrap()
    };
    runtime_with_members(members, transport)
}

pub fn runtime_with_members(
    members: Vec<ValidatorDescr>, transport: crate::PrivateKey,
) -> (Arc<AuthenticatedSessionRuntime>, crate::PrivateKey, crate::SessionOptions) {
    runtime_with_members_on_shard(members, transport, ShardIdent::masterchain())
}

pub fn runtime_with_members_on_shard(
    members: Vec<ValidatorDescr>, transport: crate::PrivateKey, shard: ShardIdent,
) -> (Arc<AuthenticatedSessionRuntime>, crate::PrivateKey, crate::SessionOptions) {
    let selected = SimplexConfig { protocol_version: 2, ..Default::default() };
    let selected_cell = selected.serialize().unwrap();
    let mut wrapper = BuilderData::new();
    wrapper.append_u8(0x10).unwrap();
    wrapper.append_bit_one().unwrap();
    wrapper.checked_append_reference(selected_cell.clone()).unwrap();
    wrapper.append_bit_one().unwrap();
    wrapper.checked_append_reference(selected_cell).unwrap();
    let mut value = BuilderData::new();
    value.checked_append_reference(wrapper.into_cell().unwrap()).unwrap();
    let mut config = ConfigParams::default();
    config.config_params.set_builder(30u32.write_to_bitstring().unwrap(), &value).unwrap();
    config
        .set_config(ConfigParamEnum::ConfigParam29(ConsensusConfig {
            round_candidates: 1,
            ..Default::default()
        }))
        .unwrap();
    config.set_config(ConfigParamEnum::ConfigParam28(CatchainConfig::default())).unwrap();
    config
        .set_config(ConfigParamEnum::ConfigParam34(ConfigParam34 {
            cur_validators: ValidatorSet::new(1, 100, 2, members.clone()).unwrap(),
        }))
        .unwrap();
    let runtime = Arc::new(
        AuthenticatedSessionRuntime::from_authenticated_config(
            SessionNetworkPin {
                global_id: -239,
                zerostate: BlockIdExt::with_params(
                    ShardIdent::masterchain(),
                    0,
                    UInt256::from([21; 32]),
                    UInt256::from([22; 32]),
                ),
            },
            &config,
            SessionCoordinates {
                shard: &shard,
                catchain_seqno: 7,
                vertical_seqno: 0,
                last_key_block_seqno: 0,
                new_catchain_ids: false,
            },
            members,
            transport.id().clone(),
        )
        .unwrap().bind_recovery_anchor(BlockIdExt::with_params(ShardIdent::masterchain(), 0, UInt256::from([21; 32]), UInt256::from([22; 32]))).unwrap(),
    );
    let options = crate::SessionOptions {
        protocol: runtime.protocol(),
        proto_version: runtime.carrier_version(),
        wire_profile: runtime.wire_profile(),
        slots_per_leader_window: runtime.slots_per_leader_window(),
        wait_for_db_init: true,
        ..Default::default()
    };
    (runtime, transport, options)
}

pub fn description(validator: bool) -> crate::session_description::SessionDescription {
    let (runtime, key, options) = runtime(validator);
    let nodes = runtime
        .committee()
        .iter()
        .map(crate::SimplexSessionNode::from_descriptor)
        .collect::<Result<Vec<_>>>()
        .unwrap();
    crate::session_description::SessionDescription::new_with_runtime(
        &options,
        runtime.session_id().clone(),
        1,
        &nodes,
        key,
        runtime.shard(),
        std::time::SystemTime::now(),
        None,
        Some(&runtime),
    )
    .unwrap()
    .bind_pq_session(runtime.catchain_seqno())
    .unwrap()
}

#[test]
fn authenticated_observer_has_no_validator_signing_authority() {
    use crate::{
        block::SlotIndex,
        simplex_state::{SkipVote, Vote},
    };
    let observer = description(false);
    assert!(observer.local_validator_index().is_none());
    assert!(!observer.is_validator());
    assert!(observer.require_validator_index().is_err());
    assert!(observer.get_legacy_signing_key().is_err());
    assert!(observer
        .sign_own_vote(&Vote::Skip(SkipVote { slot: SlotIndex::new(0) }))
        .unwrap_err()
        .to_string()
        .contains("Observer"));
    let validator = description(true);
    assert_eq!(validator.require_validator_index().unwrap().value(), 0);
    assert!(validator
        .sign_own_vote(&Vote::Skip(SkipVote { slot: SlotIndex::new(0) }))
        .unwrap_err()
        .to_string()
        .contains("Disabled"));
}

pub struct TestDirectory(std::path::PathBuf);
impl TestDirectory {
    pub fn new() -> Self {
        let path = std::env::temp_dir()
            .join(format!("rtos-v2-fixture-{}", UInt256::rand().to_hex_string()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    pub fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn authenticated_observer_fsm_never_emits_timeout_votes() {
    use crate::simplex_state::{SimplexEvent, SimplexState};
    for validator in [false, true] {
        let desc = description(validator);
        let mut state = SimplexState::new(&desc).unwrap();
        state.reset_timeouts_on_start(&desc);
        desc.set_time(desc.get_time() + std::time::Duration::from_secs(60));
        state.check_all(&desc);
        let mut votes = 0;
        while let Some(event) = state.pull_event() {
            votes += usize::from(matches!(event, SimplexEvent::BroadcastVote(_)));
        }
        if validator {
            assert!(votes > 0);
        } else {
            assert_eq!(votes, 0);
            assert!(state.get_next_timeout().is_none());
        }
    }
}
