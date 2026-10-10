// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Explicit Simplex membership. No consensus secret key is retained here.
use consensus_common::{PublicKeyHash, SessionNode, ValidatorIdentity};
use rtos_block::{KeyId, Result, ValidatorDescr};

#[derive(Clone, Debug)]
pub struct SimplexSessionNode {
    pub adnl_id: PublicKeyHash,
    pub identity: ValidatorIdentity,
    pub weight: u64,
    pub(crate) descriptor: Option<ValidatorDescr>,
}
impl SimplexSessionNode {
    pub fn from_descriptor(descriptor: &ValidatorDescr) -> Result<Self> {
        Ok(Self {
            adnl_id: KeyId::from_data(
                *descriptor
                    .adnl_addr
                    .as_ref()
                    .ok_or_else(|| rtos_block::error!("PQ transport identity missing"))?
                    .as_array(),
            ),
            identity: ValidatorIdentity::from_descriptor(descriptor)?,
            weight: descriptor.weight,
            descriptor: Some(descriptor.clone()),
        })
    }
}
impl From<SessionNode> for SimplexSessionNode {
    fn from(node: SessionNode) -> Self {
        Self {
            adnl_id: node.adnl_id,
            identity: node.public_key.into(),
            weight: node.weight,
            descriptor: None,
        }
    }
}
