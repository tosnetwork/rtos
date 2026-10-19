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

/// How the caller admits this node to a session. A validator is admitted by
/// the stable validator identity its consensus-key custody selected, never by
/// a transport key it happens to hold; its transport identity is then the one
/// the committee descriptor records for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalAdmission {
    /// The selected validator identity and its index in the ordered committee.
    Validator { validator_id: UInt256, index: u32 },
    /// A transport identity produced by the authorized observer selection.
    Observer(AuthorizedObserver),
}

/// An observer transport identity. It can only be produced by `select`, which
/// mirrors the reference observer selection: descriptors of the previous,
/// current and next total validator sets that are not members of the session
/// committee and that the caller's membership predicate accepts as its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedObserver {
    adnl: PublicKeyHash,
}

impl AuthorizedObserver {
    pub fn select(
        config: &ConfigParams,
        committee: &[ValidatorDescr],
        is_local: impl Fn(&ValidatorDescr) -> bool,
    ) -> Result<Vec<Self>> {
        let mut selected = BTreeSet::new();
        for descriptor in Self::candidates(config, committee)? {
            if is_local(&descriptor) {
                selected.insert(descriptor.adnl_addr()?);
            }
        }
        Ok(selected.into_iter().map(|adnl| Self { adnl }).collect())
    }
    pub fn adnl(&self) -> &PublicKeyHash {
        &self.adnl
    }
    fn candidates(
        config: &ConfigParams,
        committee: &[ValidatorDescr],
    ) -> Result<Vec<ValidatorDescr>> {
        let members =
            committee.iter().map(ValidatorDescr::validator_id).collect::<Result<BTreeSet<_>>>()?;
        let mut candidates = Vec::new();
        for set in
            [config.prev_validator_set()?, config.validator_set()?, config.next_validator_set()?]
        {
            for descriptor in set.list() {
                if !members.contains(&descriptor.validator_id()?) {
                    candidates.push(descriptor.clone());
                }
            }
        }
        Ok(candidates)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionNetworkPin {
    pub global_id: i32,
    pub zerostate: BlockIdExt,
}

/// Complete, owned session derivation coordinates for historical recovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRecoveryCoordinates {
    pub shard: ShardIdent,
    pub catchain_seqno: u32,
    pub vertical_seqno: u32,
    pub last_key_block_seqno: u32,
    pub new_catchain_ids: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRecoveryBinding {
    pub governing_masterchain: BlockIdExt,
    pub coordinates: SessionRecoveryCoordinates,
}

#[derive(Clone, Debug)]
pub struct AuthenticatedSessionRuntime {
    pin: SessionNetworkPin,
    coordinates: SessionRecoveryCoordinates,
    recovery_binding: Option<SessionRecoveryBinding>,
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
    /// Construct a runtime for an explicit local admission. A validator must sit
    /// at the expected committee index under exactly that validator identity,
    /// and its local transport identity is the one its descriptor records. An
    /// observer must come from the authorized observer selection over this same
    /// configuration. The resulting role must be the admitted one. This does
    /// not widen which protocols a session may run; that stays with the caller.
    pub fn from_authenticated_admission(
        pin: SessionNetworkPin,
        config: &ConfigParams,
        coordinates: SessionCoordinates<'_>,
        committee: Vec<ValidatorDescr>,
        admission: LocalAdmission,
    ) -> Result<Self> {
        let local_adnl = match &admission {
            LocalAdmission::Validator { validator_id, index } => {
                if validator_id.is_zero() {
                    fail!("Validator admission names no validator identity");
                }
                let member = committee
                    .get(*index as usize)
                    .ok_or_else(|| error!("Admitted validator index is outside the committee"))?;
                if member.validator_id()? != *validator_id {
                    fail!("Admitted validator is not the committee member at its index");
                }
                for (other, descriptor) in committee.iter().enumerate() {
                    if other != *index as usize && descriptor.validator_id()? == *validator_id {
                        fail!("Admitted validator identity appears twice in the committee");
                    }
                }
                member.adnl_addr()?
            }
            LocalAdmission::Observer(observer) => {
                let candidates = AuthorizedObserver::candidates(config, &committee)?;
                let mut authorized = false;
                for descriptor in &candidates {
                    if descriptor.adnl_addr()? == observer.adnl {
                        authorized = true;
                    }
                }
                if !authorized {
                    fail!("Observer admission is not from this configuration's total sets");
                }
                observer.adnl.clone()
            }
        };
        let runtime =
            Self::from_authenticated_config(pin, config, coordinates, committee, local_adnl)?;
        match (&admission, runtime.local_role) {
            (LocalAdmission::Validator { index, .. }, LocalRole::Validator(role))
                if role == *index =>
            {
                Ok(runtime)
            }
            (LocalAdmission::Observer(_), LocalRole::Observer) => Ok(runtime),
            _ => fail!("Session role differs from the explicit local admission"),
        }
    }

    /// Config, coordinates and the ordered subset must originate from the same
    /// authenticated governing snapshot. Never construct this from peer claims.
    pub fn from_authenticated_config(
        pin: SessionNetworkPin,
        config: &ConfigParams,
        coordinates: SessionCoordinates<'_>,
        mut committee: Vec<ValidatorDescr>,
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
        // Subset selection and ValidatorSet construction can supply different
        // cached prefix sums for the same ordered, weighted committee. Own a
        // canonical representation before deriving any runtime consumers.
        Self::normalize_committee_prefixes(&mut committee)?;
        let identity = derive_session_from_config(pin.global_id, config, coordinates, &committee)?;
        let ordered =
            committee.iter().map(ValidatorDescr::adnl_addr).collect::<Result<Vec<_>>>()?;
        let current = config.validator_set()?;
        let current_total_set =
            current.list().iter().map(ValidatorDescr::adnl_addr).collect::<Result<Vec<_>>>()?;
        let mut members: BTreeSet<_> = ordered.iter().cloned().collect();
        if protocol.observers_in_private_overlay() {
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
            coordinates: SessionRecoveryCoordinates {
                shard: coordinates.shard.clone(), catchain_seqno: coordinates.catchain_seqno,
                vertical_seqno: coordinates.vertical_seqno,
                last_key_block_seqno: coordinates.last_key_block_seqno,
                new_catchain_ids: coordinates.new_catchain_ids,
            },
            recovery_binding: None,
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
    /// Bind the exact authenticated MC state which supplied this configuration.
    /// This checks consistency only: the caller must have authenticated the
    /// anchor and its state against `pin`, not obtained it from a peer claim.
    /// A runtime retains its first anchor; binding it twice is forbidden.
    pub fn bind_recovery_anchor(mut self, anchor: BlockIdExt) -> Result<Self> {
        if self.recovery_binding.is_some() { fail!("Session recovery anchor already bound"); }
        if !anchor.shard().is_masterchain() || anchor.root_hash().is_zero() || anchor.file_hash().is_zero()
            || (anchor.seq_no() == 0 && anchor != self.pin.zerostate) {
            fail!("Invalid governing masterchain recovery anchor");
        }
        self.recovery_binding = Some(SessionRecoveryBinding {
            governing_masterchain: anchor, coordinates: self.coordinates.clone(),
        });
        Ok(self)
    }
    pub fn recovery_binding(&self) -> Option<&SessionRecoveryBinding> { self.recovery_binding.as_ref() }

    /// Whether a live group may retain its immutable admission snapshot.
    /// The session hash alone does not encode a change to transport members.
    pub fn same_admission(&self, other: &Self) -> bool {
        self.admission_mismatch(other).is_none()
    }

    /// First inconsistent public admission field, for restart diagnostics.
    /// Anchors may differ when two authenticated states admit the same session.
    pub fn admission_mismatch(&self, other: &Self) -> Option<&'static str> {
        macro_rules! compare {
            ($($field:ident),+ $(,)?) => {
                $(if self.$field != other.$field { return Some(stringify!($field)); })+
            };
        }
        compare!(pin, coordinates, profile, session, shard, catchain_seqno,
            protocol, carrier_version, slots_per_leader_window, max_candidate_size,
            wire_profile, committee, members, current_total_set, local_role, local_adnl);
        None
    }

    fn normalize_committee_prefixes(committee: &mut [ValidatorDescr]) -> Result<()> {
        let mut prefix = 0;
        for member in committee {
            member.prev_weight_sum = prefix;
            prefix = rtos_block::checked_add_validator_weight(prefix, member.weight)?;
        }
        Ok(())
    }

    pub fn runtime_directory(&self, root: &str) -> Result<String> {
        // A durable layout: each existing directory keeps the exact spelling it
        // was created with, so the layout follows the exact protocol version.
        // The layout is storage-only. The reference node names its session
        // databases differently, but a directory name never reaches the
        // network or the session identity, and renaming an existing one would
        // reopen an empty vote journal at restart and let this node vote twice
        // in a slot it has already voted in. A new protocol version already
        // gets a new session id, so it never reuses an older journal.
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
        let layout = match self.local_role {
            LocalRole::Validator(_) => crate::validator_cleanup::NamespaceLayout::V2Validator,
            LocalRole::Observer => crate::validator_cleanup::NamespaceLayout::V2Observer(
                UInt256::from(*self.local_adnl.data()),
            ),
        };
        Ok(format!(
            "{root}/consensus/{}",
            crate::validator_cleanup::namespace_relative_name(
                &layout,
                &self.shard,
                self.catchain_seqno,
                &self.session,
            )
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
        fixture_for(2)
    }
    fn fixture_for(protocol_version: u8) -> (SessionNetworkPin, ConfigParams, Vec<ValidatorDescr>) {
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
            SimplexConfig { protocol_version, ..Default::default() }.serialize().unwrap();
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
    #[test]
    fn authenticated_recovery_anchor_retains_coordinates_without_spurious_rotation() {
        let (pin, config, nodes) = fixture();
        let shard = ShardIdent::masterchain();
        let runtime = AuthenticatedSessionRuntime::from_authenticated_config(pin.clone(), &config,
            coords(&shard), nodes, KeyId::from_data([99; 32])).unwrap();
        assert!(runtime.recovery_binding().is_none());
        let first = runtime.clone().bind_recovery_anchor(pin.zerostate.clone()).unwrap();
        let later_anchor = BlockIdExt::with_params(shard.clone(), 1, UInt256::from([5; 32]), UInt256::from([6; 32]));
        let later = runtime.clone().bind_recovery_anchor(later_anchor).unwrap();
        assert!(first.same_admission(&later));
        assert!(first.clone().bind_recovery_anchor(pin.zerostate.clone()).is_err());
        assert!(runtime.bind_recovery_anchor(BlockIdExt::default()).is_err());
        let binding = first.recovery_binding().unwrap();
        assert_eq!(binding.governing_masterchain, pin.zerostate);
        assert_eq!(binding.coordinates.shard, shard);
        assert_eq!(binding.coordinates.catchain_seqno, coords(&shard).catchain_seqno);
        assert_eq!(binding.coordinates.vertical_seqno, coords(&shard).vertical_seqno);
        assert_eq!(binding.coordinates.last_key_block_seqno, coords(&shard).last_key_block_seqno);
        assert_eq!(binding.coordinates.new_catchain_ids, coords(&shard).new_catchain_ids);
    }

    #[test]
    fn validator_admission_selects_by_identity_and_descriptor_transport() {
        for protocol in [0, 1, 2] {
            let (pin, config, nodes) = fixture_for(protocol);
            let shard = ShardIdent::masterchain();
            let subset = vec![nodes[2].clone(), nodes[0].clone()];
            let admit = |admission| {
                AuthenticatedSessionRuntime::from_authenticated_admission(
                    pin.clone(),
                    &config,
                    coords(&shard),
                    subset.clone(),
                    admission,
                )
            };
            let runtime = admit(LocalAdmission::Validator {
                validator_id: nodes[0].validator_id().unwrap(),
                index: 1,
            })
            .unwrap();
            assert_eq!(runtime.local_role(), LocalRole::Validator(1), "protocol {protocol}");
            assert_eq!(runtime.local_adnl(), &nodes[0].adnl_addr().unwrap());
            let legacy = AuthenticatedSessionRuntime::from_authenticated_config(
                pin.clone(),
                &config,
                coords(&shard),
                subset.clone(),
                nodes[0].adnl_addr().unwrap(),
            )
            .unwrap();
            assert!(runtime.same_admission(&legacy));
            for (validator_id, index) in [
                (nodes[2].validator_id().unwrap(), 1),
                (nodes[0].validator_id().unwrap(), 0),
                (nodes[0].validator_id().unwrap(), 2),
                (nodes[1].validator_id().unwrap(), 0),
                (UInt256::default(), 0),
            ] {
                assert!(
                    admit(LocalAdmission::Validator { validator_id, index }).is_err(),
                    "protocol {protocol}: admitted index {index}"
                );
            }
        }
    }
    #[test]
    fn observer_admission_requires_the_authorized_selection() {
        let (pin, config, nodes) = fixture();
        let shard = ShardIdent::masterchain();
        let subset = vec![nodes[2].clone(), nodes[0].clone()];
        let local = nodes[1].validator_id().unwrap();
        let selected = AuthorizedObserver::select(&config, &subset, |descriptor| {
            descriptor.validator_id().is_ok_and(|id| id == local)
        })
        .unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].adnl(), &nodes[1].adnl_addr().unwrap());
        // A committee member is never an observer candidate, whatever it holds.
        assert!(AuthorizedObserver::select(&config, &subset, |_| true).unwrap().len() == 1);
        assert!(AuthorizedObserver::select(&config, &subset, |_| false).unwrap().is_empty());
        let observer = AuthenticatedSessionRuntime::from_authenticated_admission(
            pin.clone(),
            &config,
            coords(&shard),
            subset.clone(),
            LocalAdmission::Observer(selected[0].clone()),
        )
        .unwrap();
        assert_eq!(observer.local_role(), LocalRole::Observer);
        for adnl in [KeyId::from_data([99; 32]), nodes[0].adnl_addr().unwrap()] {
            let forged = AuthorizedObserver { adnl };
            assert!(AuthenticatedSessionRuntime::from_authenticated_admission(
                pin.clone(),
                &config,
                coords(&shard),
                subset.clone(),
                LocalAdmission::Observer(forged),
            )
            .is_err());
        }
    }

    include!("session_runtime_bounded_tests.rs");
}

include!("session_runtime_bounded.rs");
