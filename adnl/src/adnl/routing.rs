// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Destination lookup shared by the socket receive pipeline and in-process transports.
use super::packet::Refusal;
use anyhow::Result;

pub enum Destination<L, C> {
    Local(L),
    Channel(C),
}

/// Resolve the destination before decrypting. Local identities take precedence over
/// channel registrations, as in the TOS/TON peer table. The lookups borrow the
/// caller's live registries; this function neither admits peers nor installs keys.
pub fn route_datagram<L, C>(
    datagram: &[u8],
    local: impl FnOnce(&[u8; 32]) -> Option<L>,
    channel: impl FnOnce(&[u8; 32]) -> Option<C>,
) -> Result<Destination<L, C>> {
    let id: &[u8; 32] = datagram.get(..32).ok_or(Refusal("datagram_short"))?.try_into()?;
    if let Some(local) = local(id) {
        return Ok(Destination::Local(local));
    }
    channel(id).map(Destination::Channel).ok_or_else(|| Refusal("unknown_destination").into())
}
