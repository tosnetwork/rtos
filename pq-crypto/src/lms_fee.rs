// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// RTOS modification (2026-10-10): portable Rust implementation of the fixed fee profile.
//! One-level HSS with LMS_SHA256_M32_H20 and LMOTS_SHA256_N32_W4 (RFC 8554).
//! Verification only: possession of a valid signature does not authorize its key.
use sha2::{Digest, Sha256};

pub const PUBLIC_KEY_BYTES: usize = 60;
pub const SIGNATURE_BYTES: usize = 2832;
pub const MAX_SIGNATURE_BYTES: usize = SIGNATURE_BYTES;
pub const MAX_MESSAGE_BYTES: usize = 8192;
const HEIGHT: u32 = 20;
const CHAINS: usize = 67;
const LMS_TYPE: u32 = 8;
const LMOTS_TYPE: u32 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Valid,
    Invalid,
    Malformed,
}

fn word(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(input[offset..offset + 4].try_into().unwrap())
}

/// SHA-256 compressions for the most expensive admitted signature, including
/// padding. Bounds and the fixed profile are checked before any arithmetic.
/// The W4 checksum limits the 67 chains to 990 steps, rather than 67 * 15.
pub fn worst_compressions(public_key: &[u8], message_bytes: usize) -> Option<u64> {
    if public_key.len() != PUBLIC_KEY_BYTES
        || message_bytes > MAX_MESSAGE_BYTES
        || word(public_key, 0) != 1
        || word(public_key, 4) != LMS_TYPE
        || word(public_key, 8) != LMOTS_TYPE
    {
        return None;
    }
    let blocks = |bytes: usize| ((bytes + 9 + 63) / 64) as u64;
    Some(
        blocks(54 + message_bytes)
            + blocks(22 + 32 * CHAINS)
            + 990 * blocks(55)
            + blocks(54)
            + u64::from(HEIGHT) * blocks(86),
    )
}

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut state = Sha256::new();
    for part in parts {
        state.update(part);
    }
    state.finalize().into()
}

fn nibble(bytes: &[u8], index: usize) -> u8 {
    (bytes[index / 2] >> if index % 2 == 0 { 4 } else { 0 }) & 15
}

/// Unsupported key profiles and incorrect lengths are malformed; signatures
/// with mismatched profile tags, out-of-range leaf indices or bad proofs are invalid.
pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Outcome {
    if worst_compressions(public_key, message.len()).is_none() || signature.len() != SIGNATURE_BYTES
    {
        return Outcome::Malformed;
    }
    // Exact input lengths above bound every offset and the fixed 20-node path.
    let q = word(signature, 4);
    if word(signature, 0) != 0
        || q >= 1 << HEIGHT
        || word(signature, 8) != LMOTS_TYPE
        || word(signature, 2188) != LMS_TYPE
    {
        return Outcome::Invalid;
    }
    let ident = &public_key[12..28];
    let leaf_index = q.to_be_bytes();
    let digest = hash(&[ident, &leaf_index, &[0x81, 0x81], &signature[12..44], message]);
    let mut coefficients = [0u8; 34];
    coefficients[..32].copy_from_slice(&digest);
    // At most 64 * 15 = 960, and shifting by four still fits in u16.
    let checksum: u16 = (0..64).map(|i| u16::from(15 - nibble(&digest, i))).sum();
    coefficients[32..].copy_from_slice(&(checksum << 4).to_be_bytes());

    let mut public_chains = [0u8; CHAINS * 32];
    for i in 0..CHAINS {
        let mut value: [u8; 32] = signature[44 + i * 32..76 + i * 32].try_into().unwrap();
        let chain_index = (i as u16).to_be_bytes();
        for step in nibble(&coefficients, i)..15 {
            value = hash(&[ident, &leaf_index, &chain_index, &[step], &value]);
        }
        public_chains[i * 32..(i + 1) * 32].copy_from_slice(&value);
    }
    let candidate_key = hash(&[ident, &leaf_index, &[0x80, 0x80], &public_chains]);
    let mut node = (1 << HEIGHT) + q;
    let mut candidate_root = hash(&[ident, &node.to_be_bytes(), &[0x82, 0x82], &candidate_key]);
    for level in 0..HEIGHT as usize {
        let sibling = &signature[2192 + level * 32..2224 + level * 32];
        let parent = node / 2;
        candidate_root = if node & 1 == 0 {
            hash(&[ident, &parent.to_be_bytes(), &[0x83, 0x83], &candidate_root, sibling])
        } else {
            hash(&[ident, &parent.to_be_bytes(), &[0x83, 0x83], sibling, &candidate_root])
        };
        node = parent;
    }
    if candidate_root == public_key[28..60] {
        Outcome::Valid
    } else {
        Outcome::Invalid
    }
}
