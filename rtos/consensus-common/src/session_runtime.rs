// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Immutable runtime snapshot derived by the authenticated governing-state caller.
//! Construction checks consistency; it cannot authenticate the origin of a config.
use crate::{
    simplex_protocol::{OverlayMemberRole, SimplexMembership, SimplexProtocol},
    PublicKeyHash,
};
use rtos_api::{
    pq_finality::PqSessionContext,
    session_identity::{derive_session_from_config, SessionCoordinates},
    WireProfile,
};
use rtos_block::{
    error, fail, BlockIdExt, ConfigParams, Result, ShardIdent, UInt256, ValidatorDescr,
};
use std::collections::BTreeSet;

pub type LocalRole = OverlayMemberRole;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionNetworkPin {
    pub global_id: i32,
    pub zerostate: BlockIdExt,
}

#[derive(Clone, Debug)]
pub struct AuthenticatedSessionRuntime {
    pin: SessionNetworkPin,
    profile: UInt256,
    session: UInt256,
    shard: ShardIdent,
    catchain_seqno: u32,
    protocol: SimplexProtocol,
    carrier_version: u32,
    slots_per_leader_window: u32,
    max_candidate_size: u32,
    wire_profile: WireProfile,
    committee: Vec<ValidatorDescr>,
    members: Vec<PublicKeyHash>,
    current_total_set: Vec<PublicKeyHash>,
    local_role: LocalRole,
    local_adnl: PublicKeyHash,
    pq_context: Option<PqSessionContext>,
}

impl AuthenticatedSessionRuntime {
    /// Config, coordinates and the ordered subset must originate from the same
    /// authenticated governing snapshot. Never construct this from peer claims.
    pub fn from_authenticated_config(
        pin: SessionNetworkPin,
        config: &ConfigParams,
        coordinates: SessionCoordinates<'_>,
        committee: Vec<ValidatorDescr>,
        local_adnl: PublicKeyHash,
    ) -> Result<Self> {
        if !pin.zerostate.shard().is_masterchain()
            || pin.zerostate.seq_no() != 0
            || pin.zerostate.root_hash().is_zero()
            || pin.zerostate.file_hash().is_zero()
        {
            fail!("Session pin requires a masterchain zerostate");
        }
        let selected = config
            .selected_simplex_config(coordinates.shard.is_masterchain())?
            .ok_or_else(|| error!("Authenticated session has no selected Param30"))?;
        let protocol = SimplexProtocol::try_from(u32::from(selected.config.protocol_version))?;
        let carrier = config.consensus_config()?;
        let carrier_version = u32::from(carrier.proto_version);
        let max_candidate_size = u32::try_from(
            u64::from(carrier.max_block_bytes)
                + u64::from(carrier.max_collated_bytes)
                + (1u64 << 20),
        )?;
        let identity = derive_session_from_config(pin.global_id, config, coordinates, &committee)?;
        let ordered =
            committee.iter().map(ValidatorDescr::adnl_addr).collect::<Result<Vec<_>>>()?;
        let current = config.validator_set()?;
        let current_total_set =
            current.list().iter().map(ValidatorDescr::adnl_addr).collect::<Result<Vec<_>>>()?;
        let mut members: BTreeSet<_> = ordered.iter().cloned().collect();
        if protocol == SimplexProtocol::PrivateObserversPlumtree {
            for set in [config.prev_validator_set()?, current, config.next_validator_set()?] {
                for member in set.list() {
                    members.insert(member.adnl_addr()?);
                }
            }
            // A local observer uses its independent authenticated transport key.
            members.insert(local_adnl.clone());
        }
        let membership = SimplexMembership::new(&ordered, members.iter().cloned())?;
        let local_role = membership.role(&local_adnl)?;
        let pq_context =
            if committee.iter().any(|v| matches!(v.key, rtos_block::ValidatorKey::Pq(_))) {
                Some(PqSessionContext::from_authenticated_session_members(
                    identity.session_id.clone(),
                    coordinates.shard.clone(),
                    coordinates.catchain_seqno,
                    committee.clone(),
                )?)
            } else {
                None
            };
        Ok(Self {
            pin,
            profile: identity.config_hash,
            session: identity.session_id,
            shard: coordinates.shard.clone(),
            catchain_seqno: coordinates.catchain_seqno,
            protocol,
            carrier_version,
            slots_per_leader_window: selected.config.slots_per_leader_window,
            max_candidate_size,
            wire_profile: WireProfile::T0,
            committee,
            members: members.into_iter().collect(),
            current_total_set,
            local_role,
            local_adnl,
            pq_context,
        })
    }
    /// Whether a live group may retain its immutable admission snapshot.
    /// The session hash alone does not encode a change to transport members.
    pub fn same_admission(&self, other: &Self) -> bool {
        self.pin == other.pin
            && self.profile == other.profile
            && self.session == other.session
            && self.shard == other.shard
            && self.catchain_seqno == other.catchain_seqno
            && self.protocol == other.protocol
            && self.carrier_version == other.carrier_version
            && self.slots_per_leader_window == other.slots_per_leader_window
            && self.max_candidate_size == other.max_candidate_size
            && self.wire_profile == other.wire_profile
            && self.committee == other.committee
            && self.members == other.members
            && self.current_total_set == other.current_total_set
            && self.local_role == other.local_role
            && self.local_adnl == other.local_adnl
    }

    pub fn runtime_directory(&self, root: &str) -> Result<String> {
        if self.protocol != SimplexProtocol::PrivateObserversPlumtree {
            return crate::simplex_protocol::SimplexNamespace {
                protocol: self.protocol,
                role: self.local_role,
                shard: &self.shard,
                catchain_seqno: self.catchain_seqno,
                session_id: &self.session,
            }
            .runtime_directory(root);
        }
        let role = match self.local_role {
            LocalRole::Validator(_) => "validator".to_owned(),
            LocalRole::Observer => format!("observer.{}", hex::encode(self.local_adnl.data())),
        };
        Ok(format!(
            "{root}/consensus/v2/consensus.{}.{:016x}.{}.{}.{}",
            self.shard.workchain_id(),
            self.shard.shard_prefix_with_tag(),
            self.catchain_seqno,
            self.session.to_hex_string(),
            role
        ))
    }
    pub fn committee_digest(&self) -> Result<UInt256> {
        let mut bytes = Vec::new();
        for (node, member) in self.consensus_nodes()?.iter().zip(&self.committee) {
            bytes.extend_from_slice(node.public_key.id().data());
            bytes.extend_from_slice(node.adnl_id.data());
            bytes.extend_from_slice(&member.weight.to_le_bytes());
            if let Some(key) = node.public_key.pq_key() {
                bytes.extend_from_slice(&key.algorithm_id.to_le_bytes());
                bytes.extend_from_slice(key.key_id.as_slice());
                bytes.extend_from_slice(&key.public_key);
            }
        }
        Ok(UInt256::calc_file_hash(&bytes))
    }
    pub fn consensus_nodes(&self) -> Result<Vec<crate::ConsensusNode>> {
        self.committee
            .iter()
            .map(|member| {
                Ok(crate::ConsensusNode {
                    adnl_id: member.adnl_addr()?,
                    public_key: crate::ValidatorIdentity::from_descriptor(member)?,
                })
            })
            .collect()
    }
    pub fn overlay_short_id(&self) -> Result<PublicKeyHash> {
        use rtos_api::IntoBoxed;
        let nodes = self
            .consensus_nodes()?
            .into_iter()
            .map(|node| {
                UInt256::from(*if node.public_key.pq_key().is_some() {
                    node.adnl_id.data()
                } else {
                    node.public_key.id().data()
                })
            })
            .collect();
        let seed = rtos_api::ton::consensus::overlayid::OverlayId {
            session_id: self.session.clone(),
            nodes,
        };
        let name = rtos_api::serialize_boxed(&seed.into_boxed())?;
        let key = rtos_api::ton::pub_::publickey::Overlay { name }.into_boxed();
        Ok(rtos_block::KeyId::from_data(adnl::common::hash_boxed(&key)?))
    }
    pub fn max_candidate_size(&self) -> u32 {
        self.max_candidate_size
    }
    pub fn pin(&self) -> &SessionNetworkPin {
        &self.pin
    }
    pub fn profile(&self) -> &UInt256 {
        &self.profile
    }
    pub fn session_id(&self) -> &UInt256 {
        &self.session
    }
    pub fn shard(&self) -> &ShardIdent {
        &self.shard
    }
    pub fn catchain_seqno(&self) -> u32 {
        self.catchain_seqno
    }
    pub fn protocol(&self) -> SimplexProtocol {
        self.protocol
    }
    pub fn slots_per_leader_window(&self) -> u32 {
        self.slots_per_leader_window
    }
    pub fn carrier_version(&self) -> u32 {
        self.carrier_version
    }
    pub fn wire_profile(&self) -> WireProfile {
        self.wire_profile
    }
    pub fn committee(&self) -> &[ValidatorDescr] {
        &self.committee
    }
    pub fn members(&self) -> &[PublicKeyHash] {
        &self.members
    }
    pub fn current_total_set(&self) -> &[PublicKeyHash] {
        &self.current_total_set
    }
    pub fn local_role(&self) -> LocalRole {
        self.local_role
    }
    pub fn local_adnl(&self) -> &PublicKeyHash {
        &self.local_adnl
    }
    pub fn pq_context(&self) -> Option<&PqSessionContext> {
        self.pq_context.as_ref()
    }
    pub fn membership(&self) -> Result<SimplexMembership> {
        let ordered =
            self.committee.iter().map(ValidatorDescr::adnl_addr).collect::<Result<Vec<_>>>()?;
        SimplexMembership::new(&ordered, self.members.iter().cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtos_block::*;

    fn fixture() -> (SessionNetworkPin, ConfigParams, Vec<ValidatorDescr>) {
        let nodes: Vec<_> = (1..=3)
            .map(|i| {
                let public_key = vec![i; 1312];
                ValidatorDescr::with_pq_params(
                    UInt256::from([i; 32]),
                    PqConsensusKey {
                        algorithm_id: 1,
                        key_id: derive_consensus_key_id(1, &public_key),
                        public_key,
                    },
                    1,
                    UInt256::from([i + 10; 32]),
                )
            })
            .collect();
        let selected =
            SimplexConfig { protocol_version: 2, ..Default::default() }.serialize().unwrap();
        let mut wrapper = BuilderData::new();
        wrapper.append_u8(0x10).unwrap();
        wrapper.append_bit_one().unwrap();
        wrapper.checked_append_reference(selected.clone()).unwrap();
        wrapper.append_bit_one().unwrap();
        wrapper.checked_append_reference(selected).unwrap();
        let mut value = BuilderData::new();
        value.checked_append_reference(wrapper.into_cell().unwrap()).unwrap();
        let mut config = ConfigParams::default();
        config.config_params.set_builder(30u32.write_to_bitstring().unwrap(), &value).unwrap();
        config
            .set_config(ConfigParamEnum::ConfigParam29(ConsensusConfig {
                round_candidates: 1,
                ..ConsensusConfig::default()
            }))
            .unwrap();
        config.set_config(ConfigParamEnum::ConfigParam28(CatchainConfig::default())).unwrap();
        let set = ValidatorSet::new(1, 100, 3, nodes.clone()).unwrap();
        config
            .set_config(ConfigParamEnum::ConfigParam34(ConfigParam34 { cur_validators: set }))
            .unwrap();
        let pin = SessionNetworkPin {
            global_id: -239,
            zerostate: BlockIdExt::with_params(
                ShardIdent::masterchain(),
                0,
                UInt256::from([21; 32]),
                UInt256::from([22; 32]),
            ),
        };
        (pin, config, nodes)
    }
    fn coords(shard: &ShardIdent) -> SessionCoordinates<'_> {
        SessionCoordinates {
            shard,
            catchain_seqno: 7,
            vertical_seqno: 0,
            last_key_block_seqno: 0,
            new_catchain_ids: true,
        }
    }
    #[test]
    fn authenticated_runtime_preserves_committee_order_and_independent_observer_transport() {
        let (pin, config, nodes) = fixture();
        let shard = ShardIdent::masterchain();
        let subset = vec![nodes[2].clone(), nodes[0].clone()];
        let observer_key = KeyId::from_data([99; 32]);
        let observer = AuthenticatedSessionRuntime::from_authenticated_config(
            pin.clone(),
            &config,
            coords(&shard),
            subset.clone(),
            observer_key.clone(),
        )
        .unwrap();
        assert_eq!(observer.local_role(), LocalRole::Observer);
        assert_eq!(observer.members().len(), 4);
        assert_eq!(observer.current_total_set().len(), 3);
        assert!(observer.membership().unwrap().validator_index(&observer_key).is_err());
        let validator = AuthenticatedSessionRuntime::from_authenticated_config(
            pin,
            &config,
            coords(&shard),
            subset.clone(),
            nodes[2].adnl_addr().unwrap(),
        )
        .unwrap();
        assert_eq!(validator.local_role(), LocalRole::Validator(0));
        assert_eq!(observer.session_id(), validator.session_id());
        assert_eq!(
            observer.committee()[0].validator_id().unwrap(),
            nodes[2].validator_id().unwrap()
        );
        let expected = derive_session_from_config(-239, &config, coords(&shard), &subset).unwrap();
        assert_eq!(observer.session_id(), &expected.session_id);
        assert_eq!(observer.profile(), &expected.config_hash);
        assert!(observer.pq_context().is_some());
    }
    #[test]
    fn authenticated_runtime_rejects_unknown_protocol_and_invalid_pin_or_duplicate_committee() {
        let (pin, config, nodes) = fixture();
        let shard = ShardIdent::masterchain();
        let create = |pin, config: &ConfigParams, nodes| {
            AuthenticatedSessionRuntime::from_authenticated_config(
                pin,
                config,
                coords(&shard),
                nodes,
                KeyId::from_data([99; 32]),
            )
        };
        assert!(create(
            SessionNetworkPin { zerostate: BlockIdExt::default(), ..pin.clone() },
            &config,
            nodes.clone()
        )
        .is_err());
        assert!(create(pin.clone(), &config, vec![nodes[0].clone(), nodes[0].clone()]).is_err());
        let mut absent = config;
        absent
            .set_config(ConfigParamEnum::ConfigParam30(NewConsensusConfigAll::default()))
            .unwrap();
        assert!(create(pin, &absent, nodes).is_err());
        assert!(SimplexProtocol::try_from(3).is_err());
    }
}
