// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use crate::common::AdnlPeers;
use rtos_block::Result;

#[derive(Clone, Copy, Debug)]
pub enum BroadcastTransportMethod {
    Datagram,
    Stream,
    Reliable,
    Sender { reliable: bool },
}

#[derive(Clone, Copy, Debug, Default)]
pub struct FixedMemberOverlayOptions {
    pub twostep: bool,
    /// The owned live sender backend; an explicitly installed edge may stand in.
    pub use_quic: bool,
}

/// The network edge after broadcast construction and authorization. Implementations
/// send the complete overlay message; protocol validation and delivery stay owned
/// by OverlayNode. Bind before creating overlays, never from a peer message.
#[async_trait::async_trait]
pub trait OverlayBroadcastTransport: Send + Sync {
    /// Whether this edge can route an authenticated overlay peer by identity.
    /// This provides reachability, not overlay membership or source authority.
    fn has_peer(&self, local: &[u8; 32], peer: &[u8; 32]) -> bool;

    async fn send_message(
        &self,
        data: &[u8],
        peers: &AdnlPeers,
        method: BroadcastTransportMethod,
    ) -> Result<()>;
}
