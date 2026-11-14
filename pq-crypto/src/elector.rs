// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Frozen elector authorization preimages, matching crypto/pq/pq-elector.h.
//! These serializers neither sign nor authorize a request.

pub fn stake_preimage(
    global_id: i32,
    stake_at: u32,
    max_factor: u32,
    source: &[u8; 32],
    adnl: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(80);
    out.extend_from_slice(&0x654c5074u32.to_be_bytes());
    out.extend_from_slice(&stake_at.to_be_bytes());
    out.extend_from_slice(&max_factor.to_be_bytes());
    out.extend_from_slice(source);
    out.extend_from_slice(adnl);
    out.extend_from_slice(&global_id.to_be_bytes());
    out
}

pub fn config_vote_preimage(
    global_id: i32,
    validator_set: &[u8; 32],
    validator: &[u8; 32],
    index: u16,
    proposal: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(106);
    out.extend_from_slice(&0x5051564fu32.to_be_bytes());
    out.extend_from_slice(&global_id.to_be_bytes());
    out.extend_from_slice(validator_set);
    out.extend_from_slice(validator);
    out.extend_from_slice(&index.to_be_bytes());
    out.extend_from_slice(proposal);
    out
}

pub fn complaint_vote_preimage(
    global_id: i32,
    validator_set: &[u8; 32],
    validator: &[u8; 32],
    index: u16,
    election_id: u32,
    complaint: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(110);
    out.extend_from_slice(&0x5051434fu32.to_be_bytes());
    out.extend_from_slice(&global_id.to_be_bytes());
    out.extend_from_slice(validator_set);
    out.extend_from_slice(validator);
    out.extend_from_slice(&index.to_be_bytes());
    out.extend_from_slice(&election_id.to_be_bytes());
    out.extend_from_slice(complaint);
    out
}
