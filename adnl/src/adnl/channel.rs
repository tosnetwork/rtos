// Copyright 2017-2020 Telegram Systems LLP
// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! The TOS/TON symmetric ADNL channel profile, independent of actor/peer installation.
use super::{
    packet::{Packet, Refusal},
    wire_keys::{decrypt_symmetric, encrypt_symmetric, NetworkPrivateKey, NetworkPublicKey},
};
use anyhow::{ensure, Result};
use rtos_api::{ton, Constructor};
use rtos_block::{sha256_digest, ZeroizingBytes};

/// Directional secrets are owned zeroizing buffers; channel creation grants no peer admission.
pub struct Channel {
    incoming: ZeroizingBytes,
    outgoing: ZeroizingBytes,
    in_id: [u8; 32],
    out_id: [u8; 32],
    peer_id: [u8; 32],
}
impl Channel {
    pub fn from_keys(
        local: &NetworkPrivateKey,
        peer: &NetworkPublicKey,
        local_id: [u8; 32],
        peer_id: [u8; 32],
    ) -> Result<Self> {
        ensure!(
            local.kind() == "ed25519" && peer.kind() == "ed25519",
            "Ed25519 channel keys required"
        );
        let shared = local.shared_secret(peer)?;
        let shared = shared.lock()?;
        ensure!(shared.len() == 32, "channel shared secret must be 32 bytes");
        let forward = ZeroizingBytes::new(shared.to_vec());
        let reverse = ZeroizingBytes::new(forward.iter().rev().copied().collect());
        let (incoming, outgoing) = match local_id.cmp(&peer_id) {
            std::cmp::Ordering::Less => (forward, reverse),
            std::cmp::Ordering::Greater => (reverse, forward),
            std::cmp::Ordering::Equal => {
                let copy = ZeroizingBytes::new(forward.to_vec());
                (copy, forward)
            }
        };
        let in_id = Self::secret_id(&incoming);
        let out_id = Self::secret_id(&outgoing);
        Ok(Self { incoming, outgoing, in_id, out_id, peer_id })
    }
    fn secret_id(secret: &[u8]) -> [u8; 32] {
        // pub.aes has the same constructor/field layout in Legacy and T0.
        let mut wire = ZeroizingBytes::new(Vec::with_capacity(36));
        wire.extend_from_slice(&ton::pub_::publickey::Aes::constructor_const().to_le_bytes());
        wire.extend_from_slice(secret);
        sha256_digest(&wire)
    }
    pub fn in_id(&self) -> [u8; 32] {
        self.in_id
    }
    pub fn out_id(&self) -> [u8; 32] {
        self.out_id
    }
    /// Produces the routed datagram: destination channel ID, digest and ciphertext.
    pub fn send(&self, plain: &[u8]) -> Vec<u8> {
        let mut out = self.out_id.to_vec();
        out.extend(encrypt_symmetric(self.outgoing.as_slice().try_into().unwrap(), plain));
        out
    }
    /// Routes before decrypting; the channel key authenticates this packet, not a packet signature.
    pub fn receive(&self, datagram: &[u8]) -> Result<Packet> {
        if datagram.len() < 32 {
            return Err(Refusal("datagram_short").into());
        }
        if datagram[..32] != self.in_id {
            return Err(Refusal("unknown_channel").into());
        }
        self.decrypt(&datagram[32..])
    }
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Packet> {
        let plain = decrypt_symmetric(self.incoming.as_slice().try_into()?, ciphertext)?;
        let packet = Packet::from_wire(&plain)?;
        if packet.source_short().is_some_and(|id| id != self.peer_id) {
            return Err(Refusal("channel_source_mismatch").into());
        }
        Ok(packet)
    }
}
