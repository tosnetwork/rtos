// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use crate::*;
use std::sync::{Arc, Mutex};

/// Records every overlay created by a session so its external owner can verify
/// resource joins even if a consensus worker unwinds before normal teardown.
pub struct OverlayOwner {
    inner: ConsensusOverlayManagerPtr,
    overlays: Mutex<Vec<(Arc<adnl::PrivateOverlayShortId>, ConsensusOverlayPtr)>>,
}
impl OverlayOwner {
    pub fn new(inner: ConsensusOverlayManagerPtr) -> Arc<Self> {
        Arc::new(Self { inner, overlays: Mutex::new(Vec::new()) })
    }
    pub fn drained(&self) -> bool {
        self.overlays.lock().unwrap().iter().all(|(_, overlay)| self.inner.overlay_drained(overlay))
    }
    pub fn stop_checked(&self) -> Result<()> {
        let overlays = self.overlays.lock().unwrap().clone();
        let mut errors = Vec::new();
        for (id, overlay) in overlays {
            if let Err(error) = self.inner.stop_overlay_checked(&id, &overlay) {
                errors.push(error.to_string());
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(rtos_block::error!("{}", errors.join("; ")))
        }
    }
}
impl ConsensusOverlayManager for OverlayOwner {
    fn wire_profile(&self) -> rtos_api::WireProfile {
        self.inner.wire_profile()
    }
    fn start_overlay(
        &self,
        key: &PrivateKey,
        id: &Arc<adnl::PrivateOverlayShortId>,
        nodes: &[ConsensusNode],
        listener: ConsensusOverlayListenerPtr,
        replay: ConsensusOverlayLogReplayListenerPtr,
        transport: OverlayTransportType,
        sync: Option<BlockSyncOverlayParams>,
    ) -> Result<ConsensusOverlayPtr> {
        let overlay =
            self.inner.start_overlay(key, id, nodes, listener, replay, transport, sync)?;
        self.overlays.lock().unwrap().push((id.clone(), overlay.clone()));
        Ok(overlay)
    }
    fn stop_overlay(&self, id: &Arc<adnl::PrivateOverlayShortId>, overlay: &ConsensusOverlayPtr) {
        if let Err(error) = self.stop_overlay_checked(id, overlay) {
            log::error!("Overlay shutdown: {error}");
        }
    }
    fn stop_overlay_checked(
        &self,
        id: &Arc<adnl::PrivateOverlayShortId>,
        overlay: &ConsensusOverlayPtr,
    ) -> Result<()> {
        self.inner.stop_overlay_checked(id, overlay)
    }
    fn overlay_drained(&self, overlay: &ConsensusOverlayPtr) -> bool {
        self.inner.overlay_drained(overlay)
    }
}
