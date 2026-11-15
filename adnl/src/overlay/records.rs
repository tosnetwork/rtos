// Copyright 2017-2020 Telegram Systems LLP
// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Typed overlay records. Parsing and signature checks do not install or authorize a peer.
use crate::{packet::Refusal, wire_keys::NetworkPublicKey};
use anyhow::Result;
use rtos_api::{ton, IntoBoxed, WireProfile};

/// Signed wire expiry uses a three-second grace, including negative timestamps.
pub fn certificate_expired(expire_at: i32, now: f64) -> bool {
    (expire_at as f64) < now - 3.0
}

pub struct MemberFlags;
impl MemberFlags {
    pub fn valid(flags: u32) -> bool {
        flags & !3 == 0
    }
    pub fn receives_regular(flags: u32) -> bool {
        Self::valid(flags) && flags & 1 == 0
    }
    pub fn receives_plumtree(flags: u32) -> bool {
        Self::valid(flags) && flags & 3 == 0
    }
    pub fn public_flags(flags: u32, enabled: bool, original_sender: bool) -> u32 {
        flags | if !enabled || original_sender { 2 } else { 0 }
    }
}

pub fn overlay_public_key(name: &[u8]) -> Result<NetworkPublicKey> {
    NetworkPublicKey::from_wire(
        &WireProfile::T0
            .serialize(&ton::pub_::publickey::Overlay { name: name.to_vec() }.into_boxed())?,
    )
}

#[derive(Clone)]
pub struct MemberCertificate {
    tl: ton::overlay::MemberCertificate,
}
impl MemberCertificate {
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        Ok(Self::from_tl(crate::adnl::wire::decode(bytes, |s| Refusal(s).into())?))
    }
    pub fn from_tl(tl: ton::overlay::MemberCertificate) -> Self {
        Self { tl }
    }
    pub fn tl(&self) -> &ton::overlay::MemberCertificate {
        &self.tl
    }
    pub fn value(&self) -> Option<&ton::overlay::membercertificate::MemberCertificate> {
        match &self.tl {
            ton::overlay::MemberCertificate::Overlay_MemberCertificate(v) => Some(v),
            ton::overlay::MemberCertificate::Overlay_EmptyMemberCertificate => None,
        }
    }
    pub fn expire_at(&self) -> i32 {
        self.value().map_or(i32::MAX, |v| v.expire_at)
    }
    pub fn is_expired(&self, now: f64) -> bool {
        certificate_expired(self.expire_at(), now)
    }
    pub fn to_sign(&self, node: [u8; 32]) -> Result<Option<Vec<u8>>> {
        self.value()
            .map(|v| {
                WireProfile::T0.serialize(
                    &ton::overlay::membercertificateid::MemberCertificateId {
                        node: ton::adnl::id::short::Short { id: node.into() },
                        flags: v.flags,
                        slot: v.slot,
                        expire_at: v.expire_at,
                    }
                    .into_boxed(),
                )
            })
            .transpose()
    }
    pub fn verify_signature(&self, node: [u8; 32]) -> Result<()> {
        let v = self.value().ok_or(Refusal("empty_certificate"))?;
        NetworkPublicKey::from_wire(&WireProfile::T0.serialize(&v.issued_by)?)?
            .verify(&self.to_sign(node)?.unwrap(), &v.signature)
    }
}

pub struct NodeRecord {
    node: ton::overlay::node::Node,
    short_id: [u8; 32],
    certificate: MemberCertificate,
}
impl NodeRecord {
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let ton::overlay::Node::Overlay_Node(node) =
            crate::adnl::wire::decode(bytes, |s| Refusal(s).into())?;
        Self::from_tl(node)
    }
    pub fn from_tl(node: ton::overlay::node::Node) -> Result<Self> {
        if !MemberFlags::valid(node.flags as u32) {
            return Err(Refusal("overlay_node_invalid").into());
        }
        let key = NetworkPublicKey::from_wire(&WireProfile::T0.serialize(&node.id)?)?;
        if key.ed25519().is_none() {
            return Err(Refusal("not_ed25519").into());
        }
        let short_id = key.short_id()?;
        let certificate = MemberCertificate::from_tl(node.certificate.clone());
        Ok(Self { node, short_id, certificate })
    }
    pub fn node(&self) -> &ton::overlay::node::Node {
        &self.node
    }
    pub fn short_id(&self) -> [u8; 32] {
        self.short_id
    }
    pub fn certificate(&self) -> &MemberCertificate {
        &self.certificate
    }
    pub fn to_sign(&self) -> Result<Vec<u8>> {
        WireProfile::T0.serialize(
            &ton::overlay::node::tosign::ToSign {
                id: ton::adnl::id::short::Short { id: self.short_id.into() },
                overlay: self.node.overlay.clone(),
                flags: self.node.flags,
                version: self.node.version,
            }
            .into_boxed(),
        )
    }
    pub fn verify_signature(&self) -> Result<()> {
        NetworkPublicKey::from_wire(&WireProfile::T0.serialize(&self.node.id)?)?
            .verify(&self.to_sign()?, &self.node.signature)
    }
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        WireProfile::T0.serialize(&self.node.clone().into_boxed())
    }
}
