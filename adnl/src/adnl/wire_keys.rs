// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Network wire key profiles. A parsed key or a legacy no-signature profile
//! does not authenticate a peer or grant packet/DHT admission.
use super::common::AdnlCryptoUtils;
use rtos_api::{ton, IntoBoxed, WireProfile};
use rtos_block::{
    address_crc, sha256_digest, Ed25519KeyOption, KeyOption, Result, SecretBytes, UInt256,
    ZeroizingBytes,
};
use std::sync::Arc;

#[derive(Debug)]
pub struct KeyRefusal(pub &'static str);
impl std::fmt::Display for KeyRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for KeyRefusal {}
fn refused(reason: &'static str) -> anyhow::Error {
    KeyRefusal(reason).into()
}

fn wire_value<T: rtos_api::BoxedDeserialize>(bytes: &[u8]) -> Result<T> {
    super::wire::decode(bytes, refused)
}

/// A wire public-key profile, independent of an admitted ADNL peer identity.
#[derive(Clone)]
pub struct NetworkPublicKey(ton::PublicKey);
impl NetworkPublicKey {
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        Ok(Self(wire_value(bytes)?))
    }
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        WireProfile::T0.serialize(&self.0)
    }
    pub fn short_id(&self) -> Result<[u8; 32]> {
        Ok(sha256_digest(self.to_wire()?))
    }
    /// The key API's size estimate, separate from the actual padded TL length.
    pub fn serialized_size_estimate(&self) -> u32 {
        match &self.0 {
            ton::PublicKey::Pub_Ed25519(_) | ton::PublicKey::Pub_Aes(_) => 36,
            ton::PublicKey::Pub_Unenc(key) => (key.data.len() as u32).wrapping_add(8),
            ton::PublicKey::Pub_Overlay(key) => (key.name.len() as u32).wrapping_add(8),
        }
    }
    pub fn kind(&self) -> &'static str {
        match &self.0 {
            ton::PublicKey::Pub_Ed25519(_) => "ed25519",
            ton::PublicKey::Pub_Aes(_) => "aes",
            ton::PublicKey::Pub_Unenc(_) => "unenc",
            ton::PublicKey::Pub_Overlay(_) => "overlay",
        }
    }
    pub fn ed25519(&self) -> Option<&[u8]> {
        match &self.0 {
            ton::PublicKey::Pub_Ed25519(key) => Some(key.key.as_slice()),
            _ => None,
        }
    }
    pub fn adnl_id_text(&self) -> Result<Option<String>> {
        Ok(if self.ed25519().is_some() { Some(encode_adnl_id(&self.short_id()?)) } else { None })
    }
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        match &self.0 {
            ton::PublicKey::Pub_Ed25519(key) => {
                rtos_block::ed25519_verify(key.key.as_slice(), message, signature)
                    .map_err(|_| refused("invalid_signature"))
            }
            ton::PublicKey::Pub_Aes(_) => Err(refused("signing_unsupported")),
            ton::PublicKey::Pub_Unenc(_) => Ok(()),
            ton::PublicKey::Pub_Overlay(_) => {
                let ton::dht::KeyDescription::Dht_KeyDescription(value) = wire_value(message)?;
                if !signature.is_empty()
                    || value.update_rule != ton::dht::UpdateRule::Dht_UpdateRule_OverlayNodes
                    || !value.signature.is_empty()
                {
                    return Err(refused("overlay_signature_invalid"));
                }
                Ok(())
            }
        }
    }
    /// Deterministic legacy profiles only. Ed25519 encryption needs a fresh
    /// ephemeral key and is provided by the ADNL handshake instead.
    pub fn encrypt_deterministic(&self, data: &[u8]) -> Result<Vec<u8>> {
        match &self.0 {
            ton::PublicKey::Pub_Aes(key) => {
                let digest = sha256_digest(data);
                let mut body = data.to_vec();
                AdnlCryptoUtils::build_cipher_secure(key.key.as_slice().try_into()?, &digest)
                    .apply_keystream(&mut body);
                let mut result = Vec::with_capacity(32 + body.len());
                result.extend_from_slice(&digest);
                result.extend_from_slice(&body);
                Ok(result)
            }
            ton::PublicKey::Pub_Unenc(_) => Ok(data.to_vec()),
            ton::PublicKey::Pub_Overlay(_) => Err(refused("encryption_unsupported")),
            ton::PublicKey::Pub_Ed25519(_) => {
                Err(anyhow::anyhow!("ed25519 encryption requires fresh randomness"))
            }
        }
    }
}

enum PrivateMaterial {
    Ed25519(Arc<dyn KeyOption>),
    Aes(ZeroizingBytes),
    Unenc(ZeroizingBytes),
    Overlay(ZeroizingBytes),
}
/// Local key material is neither Debug nor Clone and is kept in the existing
/// guarded/zeroizing secret containers. Only its public wire form is exported.
pub struct NetworkPrivateKey(PrivateMaterial);
impl NetworkPrivateKey {
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let value = wire_value::<ton::PrivateKey>(bytes)?;
        Ok(Self(match value {
            ton::PrivateKey::Pk_Ed25519(key) => {
                PrivateMaterial::Ed25519(Ed25519KeyOption::<ZeroizingBytes>::from_private_key(
                    key.key.as_slice().try_into()?,
                )?)
            }
            ton::PrivateKey::Pk_Aes(key) => {
                PrivateMaterial::Aes(ZeroizingBytes::new(key.key.as_slice().to_vec()))
            }
            ton::PrivateKey::Pk_Unenc(key) => PrivateMaterial::Unenc(ZeroizingBytes::new(key.data)),
            ton::PrivateKey::Pk_Overlay(key) => {
                PrivateMaterial::Overlay(ZeroizingBytes::new(key.name))
            }
        }))
    }
    pub fn kind(&self) -> &'static str {
        match &self.0 {
            PrivateMaterial::Ed25519(_) => "ed25519",
            PrivateMaterial::Aes(_) => "aes",
            PrivateMaterial::Unenc(_) => "unenc",
            PrivateMaterial::Overlay(_) => "overlay",
        }
    }
    pub fn public_key(&self) -> Result<NetworkPublicKey> {
        Ok(NetworkPublicKey(match &self.0 {
            PrivateMaterial::Ed25519(key) => ton::pub_::publickey::Ed25519 {
                key: UInt256::from(<[u8; 32]>::try_from(key.pub_key()?)?),
            }
            .into_boxed(),
            PrivateMaterial::Aes(key) => ton::pub_::publickey::Aes {
                key: UInt256::from(<[u8; 32]>::try_from(key.as_slice())?),
            }
            .into_boxed(),
            PrivateMaterial::Unenc(key) => {
                ton::pub_::publickey::Unenc { data: key.to_vec() }.into_boxed()
            }
            PrivateMaterial::Overlay(key) => {
                ton::pub_::publickey::Overlay { name: key.to_vec() }.into_boxed()
            }
        }))
    }
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        match &self.0 {
            PrivateMaterial::Ed25519(key) => key.sign(message),
            PrivateMaterial::Aes(_) => Err(refused("signing_unsupported")),
            PrivateMaterial::Unenc(_) => Ok(Vec::new()),
            PrivateMaterial::Overlay(_) => Err(refused("key_unusable")),
        }
    }
    pub fn shared_secret(&self, peer: &NetworkPublicKey) -> Result<Box<dyn SecretBytes>> {
        let PrivateMaterial::Ed25519(key) = &self.0 else {
            return Err(anyhow::anyhow!("local key is not ed25519"));
        };
        let peer = peer.ed25519().ok_or_else(|| anyhow::anyhow!("peer key is not ed25519"))?;
        key.shared_secret(peer).map_err(peer_error)
    }
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        match &self.0 {
            PrivateMaterial::Ed25519(key) => {
                if ciphertext.len() < 64 {
                    return Err(refused("ciphertext_short"));
                }
                let shared = key.shared_secret(&ciphertext[..32]).map_err(peer_error)?;
                let locked = shared.lock()?;
                decrypt_symmetric(locked.as_ref().try_into()?, &ciphertext[32..])
            }
            PrivateMaterial::Aes(key) => decrypt_symmetric(key.as_slice().try_into()?, ciphertext),
            PrivateMaterial::Unenc(_) => Ok(ciphertext.to_vec()),
            PrivateMaterial::Overlay(_) => Err(refused("key_unusable")),
        }
    }
}
fn peer_error(error: anyhow::Error) -> anyhow::Error {
    if error.is::<rtos_block::DegeneratePublicKey>() {
        refused("degenerate_public_key")
    } else {
        error
    }
}
fn decrypt_symmetric(secret: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < 32 {
        return Err(refused("ciphertext_short"));
    }
    let digest: &[u8; 32] = ciphertext[..32].try_into()?;
    let mut body = ciphertext[32..].to_vec();
    AdnlCryptoUtils::build_cipher_secure(secret, digest).apply_keystream(&mut body);
    if sha256_digest(&body) != *digest {
        return Err(refused("digest_mismatch"));
    }
    Ok(body)
}

const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
/// Public ADNL identity text: fixed prefix, base32 and CRC16, without admission.
pub fn encode_adnl_id(id: &[u8; 32]) -> String {
    let mut wire = [0u8; 35];
    wire[0] = 0x2d;
    wire[1..33].copy_from_slice(id);
    let crc = address_crc(&wire[..33]);
    wire[33..].copy_from_slice(&crc.to_be_bytes());
    let mut text = String::with_capacity(56);
    let mut bits = 0u32;
    let mut n = 0;
    for byte in wire {
        bits = (bits << 8) | u32::from(byte);
        n += 8;
        while n >= 5 {
            n -= 5;
            text.push(BASE32[((bits >> n) & 31) as usize] as char);
        }
    }
    text.remove(0);
    text
}
pub fn decode_adnl_id(text: &str) -> Result<[u8; 32]> {
    if text.len() != 55 {
        return Err(refused("adnl_id_length"));
    }
    let mut wire = [0u8; 35];
    let mut bits = 0u32;
    let mut n = 0;
    let mut pos = 0;
    for c in std::iter::once(b'f').chain(text.bytes()) {
        let c = c.to_ascii_lowercase();
        let value =
            BASE32.iter().position(|v| *v == c).ok_or_else(|| refused("adnl_id_encoding"))?;
        bits = (bits << 5) | value as u32;
        n += 5;
        if n >= 8 {
            n -= 8;
            wire[pos] = (bits >> n) as u8;
            pos += 1;
        }
    }
    if wire[0] != 0x2d {
        return Err(refused("adnl_id_prefix"));
    }
    if address_crc(&wire[..33]) != u16::from_be_bytes(wire[33..].try_into()?) {
        return Err(refused("adnl_id_checksum"));
    }
    Ok(wire[1..33].try_into()?)
}
