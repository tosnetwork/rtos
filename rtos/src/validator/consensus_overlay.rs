/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use super::consensus::{
    ConsensusNode, ConsensusOverlayListenerPtr, ConsensusOverlayLogReplayListenerPtr,
    ConsensusOverlayManager, ConsensusOverlayPtr, OverlayTransportType, PrivateKey,
};
use crate::engine_traits::PrivateOverlayOperations;
use adnl::PrivateOverlayShortId;
use consensus_common::BlockSyncOverlayParams;
use rtos_block::{Result, UInt256};
use std::sync::Arc;

pub(crate) struct ConsensusOverlayManagerImpl {
    network: Arc<dyn PrivateOverlayOperations>,
    validator_list_id: UInt256,
    /// Block-sync overlay membership and authorization; `None` for catchain or when observers disabled
    block_sync_params: Option<BlockSyncOverlayParams>,
}

impl ConsensusOverlayManagerImpl {
    pub fn new(
        network: Arc<dyn PrivateOverlayOperations>,
        validator_list_id: UInt256,
        block_sync_params: Option<BlockSyncOverlayParams>,
    ) -> Self {
        Self { network, validator_list_id, block_sync_params }
    }
}

impl ConsensusOverlayManager for ConsensusOverlayManagerImpl {
    fn wire_profile(&self) -> rtos_api::WireProfile { self.network.wire_profile() }

    fn stop_overlay_checked(
        &self, id: &Arc<PrivateOverlayShortId>, overlay: &ConsensusOverlayPtr,
    ) -> Result<()> {
        self.network.stop_catchain_client_checked(id, overlay)
    }

    fn overlay_drained(&self, overlay: &ConsensusOverlayPtr) -> bool {
        self.network.catchain_client_drained(overlay)
    }

    fn start_overlay(
        &self,
        local_validator_key: &PrivateKey,
        overlay_short_id: &Arc<PrivateOverlayShortId>,
        nodes: &[ConsensusNode],
        listener: ConsensusOverlayListenerPtr,
        replay_listener: ConsensusOverlayLogReplayListenerPtr,
        transport_type: OverlayTransportType,
        // simplex passes None; the real params live on self.block_sync_params.
        _block_sync_params_unused: Option<BlockSyncOverlayParams>,
    ) -> Result<ConsensusOverlayPtr> {
        self.network.create_catchain_client(
            self.validator_list_id.clone(),
            local_validator_key,
            overlay_short_id,
            nodes,
            listener,
            replay_listener,
            None,
            transport_type,
            self.block_sync_params.clone(),
        )
    }

    fn start_authenticated_overlay(
        &self, key: &PrivateKey, id: &Arc<PrivateOverlayShortId>,
        runtime: Arc<consensus_common::session_runtime::AuthenticatedSessionRuntime>,
        listener: ConsensusOverlayListenerPtr, replay: ConsensusOverlayLogReplayListenerPtr,
        transport: OverlayTransportType,
    ) -> Result<ConsensusOverlayPtr> {
        self.network.create_authenticated_consensus_client(self.validator_list_id.clone(), key, id, runtime, listener, replay, None, transport)
    }

    /// Stop existing overlay
    fn stop_overlay(
        &self,
        overlay_short_id: &Arc<PrivateOverlayShortId>,
        _overlay: &ConsensusOverlayPtr,
    ) {
        let engine_network = self.network.clone();
        engine_network.stop_catchain_client(overlay_short_id);
    }
}
