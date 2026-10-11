// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Exact event coordinates. This data is never authentication or release authority.
use consensus_common::{
    finality_delivery::{CanonicalFinalityRequest, FinalityDeliveryRole},
    simplex_protocol::SimplexProtocol,
};
use rtos_api::WireProfile;
use rtos_block::{fail, BlockIdExt, Result, UInt256};
use serde_derive::{Deserialize, Serialize};
use std::str::FromStr;

pub(crate) const MAX_REPAIR_BINDING_BYTES: usize = 8192;
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RepairLeaseDomain {
    pub zerostate: BlockIdExt,
    pub global_id: i32,
    pub history_init: BlockIdExt,
    pub source_recovery_anchor: BlockIdExt,
    pub source_recovery_coordinates: consensus_common::session_runtime::SessionRecoveryCoordinates,
    pub session_id: UInt256,
    pub profile: UInt256,
    pub protocol: SimplexProtocol,
    pub carrier_version: u32,
    pub wire_profile: WireProfile,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RepairLeaseBinding {
    pub record_id: u64,
    pub delivery_id: UInt256,
    pub canonical: CanonicalFinalityRequest,
    pub domain: RepairLeaseDomain,
    pub source_digest: UInt256,
    pub canonical_digest: UInt256,
    pub created_at_unix_secs: u64,
    pub expires_at_unix_secs: u64,
    pub effects_digest: UInt256,
    pub close_generation: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    version: u32,
    record_id: u64,
    delivery_id: String,
    block_id: String,
    role: String,
    local_adnl: String,
    local_validator_index: Option<u32>,
    source_validator: String,
    zerostate: String,
    global_id: i32,
    history_init: String,
    source_recovery_anchor: String,
    source_recovery_coordinates: Coordinates,
    session_id: String,
    profile: String,
    protocol: String,
    carrier_version: u32,
    wire_profile: String,
    source_digest: String,
    canonical_digest: String,
    created_at_unix_secs: u64,
    expires_at_unix_secs: u64,
    effects_digest: String,
    close_generation: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Coordinates {
    workchain: i32,
    shard_prefix: u64,
    catchain_seqno: u32,
    vertical_seqno: u32,
    last_key_block_seqno: u32,
    new_catchain_ids: bool,
}
impl RepairLeaseBinding {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.canonical.role != FinalityDeliveryRole::Final
            || self.delivery_id != self.canonical.node_receipt
            || !self.canonical.block_id.shard().is_masterchain()
            || self.canonical.block_id.seq_no() == 0
            || !self.domain.zerostate.shard().is_masterchain()
            || self.domain.zerostate.seq_no() != 0
            || !self.domain.history_init.shard().is_masterchain()
            || !self.domain.source_recovery_anchor.shard().is_masterchain()
            || self.domain.source_recovery_anchor.seq_no() < self.domain.history_init.seq_no()
            || !self.domain.source_recovery_coordinates.shard.is_masterchain()
            || self.domain.protocol != SimplexProtocol::PrivateObserversPlumtree
            || self.domain.wire_profile != WireProfile::T0
            || self.close_generation == 0
            || self.expires_at_unix_secs <= self.created_at_unix_secs
        {
            fail!("Invalid repair lease event binding");
        }
        Ok(())
    }
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let d = &self.domain;
        let c = &self.canonical;
        let bytes = serde_json::to_vec(&Wire {
            version: 1,
            record_id: self.record_id,
            delivery_id: format!("{:x}", self.delivery_id),
            block_id: c.block_id.to_string(),
            role: "final".into(),
            local_adnl: format!("{:x}", c.local_adnl),
            local_validator_index: c.local_validator_index,
            source_validator: format!("{:x}", c.source_validator),
            zerostate: d.zerostate.to_string(),
            global_id: d.global_id,
            history_init: d.history_init.to_string(),
            source_recovery_anchor: d.source_recovery_anchor.to_string(),
            source_recovery_coordinates: Coordinates {
                workchain: d.source_recovery_coordinates.shard.workchain_id(),
                shard_prefix: d.source_recovery_coordinates.shard.shard_prefix_with_tag(),
                catchain_seqno: d.source_recovery_coordinates.catchain_seqno,
                vertical_seqno: d.source_recovery_coordinates.vertical_seqno,
                last_key_block_seqno: d.source_recovery_coordinates.last_key_block_seqno,
                new_catchain_ids: d.source_recovery_coordinates.new_catchain_ids,
            },
            session_id: format!("{:x}", d.session_id),
            profile: format!("{:x}", d.profile),
            protocol: "private-observers-plumtree".into(),
            carrier_version: d.carrier_version,
            wire_profile: "t0".into(),
            source_digest: format!("{:x}", self.source_digest),
            canonical_digest: format!("{:x}", self.canonical_digest),
            created_at_unix_secs: self.created_at_unix_secs,
            expires_at_unix_secs: self.expires_at_unix_secs,
            effects_digest: format!("{:x}", self.effects_digest),
            close_generation: self.close_generation,
        })?;
        if bytes.len() > MAX_REPAIR_BINDING_BYTES {
            fail!("Repair binding exceeds bound");
        }
        Ok(bytes)
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_REPAIR_BINDING_BYTES {
            fail!("Repair binding exceeds bound");
        }
        let w: Wire = serde_json::from_slice(bytes)?;
        if w.version != 1
            || w.role != "final"
            || w.protocol != "private-observers-plumtree"
            || w.wire_profile != "t0"
        {
            fail!("Unsupported repair binding schema/domain");
        }
        let digest = |s: &str| -> Result<UInt256> {
            if s.len() != 64 {
                fail!("Repair binding digest length");
            }
            UInt256::from_str(s)
        };
        let delivery_id = digest(&w.delivery_id)?;
        let binding = Self {
            record_id: w.record_id,
            delivery_id: delivery_id.clone(),
            canonical: CanonicalFinalityRequest {
                node_receipt: delivery_id,
                block_id: w.block_id.parse()?,
                role: FinalityDeliveryRole::Final,
                local_adnl: digest(&w.local_adnl)?,
                local_validator_index: w.local_validator_index,
                source_validator: digest(&w.source_validator)?,
            },
            domain: RepairLeaseDomain {
                zerostate: w.zerostate.parse()?,
                global_id: w.global_id,
                history_init: w.history_init.parse()?,
                source_recovery_anchor: w.source_recovery_anchor.parse()?,
                source_recovery_coordinates:
                    consensus_common::session_runtime::SessionRecoveryCoordinates {
                        shard: rtos_block::ShardIdent::with_tagged_prefix(
                            w.source_recovery_coordinates.workchain,
                            w.source_recovery_coordinates.shard_prefix,
                        )?,
                        catchain_seqno: w.source_recovery_coordinates.catchain_seqno,
                        vertical_seqno: w.source_recovery_coordinates.vertical_seqno,
                        last_key_block_seqno: w.source_recovery_coordinates.last_key_block_seqno,
                        new_catchain_ids: w.source_recovery_coordinates.new_catchain_ids,
                    },
                session_id: digest(&w.session_id)?,
                profile: digest(&w.profile)?,
                protocol: SimplexProtocol::PrivateObserversPlumtree,
                carrier_version: w.carrier_version,
                wire_profile: WireProfile::T0,
            },
            source_digest: digest(&w.source_digest)?,
            canonical_digest: digest(&w.canonical_digest)?,
            created_at_unix_secs: w.created_at_unix_secs,
            expires_at_unix_secs: w.expires_at_unix_secs,
            effects_digest: digest(&w.effects_digest)?,
            close_generation: w.close_generation,
        };
        binding.validate()?;
        Ok(binding)
    }
}
