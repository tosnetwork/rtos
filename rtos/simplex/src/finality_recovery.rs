// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Retired source discovery. Persisted claims never authenticate a runtime.
use consensus_common::session_runtime::{SessionNetworkPin, SessionRecoveryBinding};
use consensus_common::simplex_protocol::SimplexProtocol;
use rtos_api::WireProfile;
use rtos_block::{BlockIdExt, UInt256};
use std::path::PathBuf;

/// Untrusted locator for a source session with incomplete certificate delivery.
/// Engine must authenticate the exact governing MC state against the full pin,
/// recompute the current/next-set committee and derive the same session/profile.
/// Local role and transport are claims requiring independent binding checks.
#[derive(Clone, Debug)]
pub struct SessionRecoveryRecord {
    pub pin: SessionNetworkPin,
    pub binding: SessionRecoveryBinding,
    pub protocol: SimplexProtocol,
    pub carrier_version: u32,
    pub wire_profile: WireProfile,
    pub profile: UInt256,
    pub session_id: UInt256,
    pub local_adnl: UInt256,
    pub local_validator_index: Option<u32>,
    pub prev_blocks: Vec<BlockIdExt>,
    pub namespace: PathBuf,
}
