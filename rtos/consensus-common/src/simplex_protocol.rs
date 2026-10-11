/*
 * Copyright (C) 2026 RTOS contributors.
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! ConfigParam 30 protocol semantics, separate from the carrier envelope version.
//! A recognized protocol is not necessarily admitted for execution.
use crate::{PublicKeyHash, Result};
use rtos_block::{error, fail, ShardIdent, UInt256};
use std::collections::{BTreeSet, HashMap};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SimplexProtocol {
    #[default]
    Private,
    BlockSync,
    PrivateObserversPlumtree,
}

impl TryFrom<u32> for SimplexProtocol {
    type Error = anyhow::Error;
    fn try_from(version: u32) -> Result<Self> {
        match version {
            0 => Ok(Self::Private),
            1 => Ok(Self::BlockSync),
            2 => Ok(Self::PrivateObserversPlumtree),
            _ => fail!("Unsupported Simplex protocol version {version}"),
        }
    }
}

impl SimplexProtocol {
    pub fn version(self) -> u32 {
        match self {
            Self::Private => 0,
            Self::BlockSync => 1,
            Self::PrivateObserversPlumtree => 2,
        }
    }

    pub fn uses_block_sync(self) -> bool {
        self == Self::BlockSync
    }

    pub fn admits_runtime(self) -> Result<()> {
        if self == Self::PrivateObserversPlumtree {
            fail!("Simplex protocol version 2 runtime is not implemented");
        }
        Ok(())
    }
}

/// Transport role only. This value never authorizes a consensus signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverlayMemberRole {
    Validator(u32),
    Observer,
}

/// Ordered consensus senders and the wider transport membership are distinct.
/// The caller supplies members from its authenticated governing configuration.
#[derive(Clone, Debug)]
pub struct SimplexMembership {
    members: BTreeSet<PublicKeyHash>,
    validators: HashMap<PublicKeyHash, u32>,
}

impl SimplexMembership {
    pub fn new(
        ordered_validators: &[PublicKeyHash],
        members: impl IntoIterator<Item = PublicKeyHash>,
    ) -> Result<Self> {
        if ordered_validators.is_empty() {
            fail!("Simplex membership has no validators");
        }
        let members: BTreeSet<_> = members.into_iter().collect();
        let mut validators = HashMap::new();
        for (index, key) in ordered_validators.iter().enumerate() {
            if !members.contains(key) {
                fail!("Simplex validator is absent from transport membership");
            }
            let index = u32::try_from(index)?;
            if validators.insert(key.clone(), index).is_some() {
                fail!("Duplicate Simplex validator transport identity");
            }
        }
        Ok(Self { members, validators })
    }

    pub fn role(&self, key: &PublicKeyHash) -> Result<OverlayMemberRole> {
        if let Some(index) = self.validators.get(key) {
            Ok(OverlayMemberRole::Validator(*index))
        } else if self.members.contains(key) {
            Ok(OverlayMemberRole::Observer)
        } else {
            fail!("ADNL identity is not a Simplex overlay member")
        }
    }

    pub fn validator_index(&self, key: &PublicKeyHash) -> Result<u32> {
        match self.role(key)? {
            OverlayMemberRole::Validator(index) => Ok(index),
            OverlayMemberRole::Observer => fail!("Observer has no validator index"),
        }
    }
}

/// An explicit directory selection. Existing 0/1 directories remain unchanged:
/// changing their spelling would silently create an empty signing journal.
/// No role or protocol transition migrates, clears, or falls back to another DB.
pub struct SimplexNamespace<'a> {
    pub protocol: SimplexProtocol,
    pub role: OverlayMemberRole,
    pub shard: &'a ShardIdent,
    pub catchain_seqno: u32,
    pub session_id: &'a UInt256,
}

impl SimplexNamespace<'_> {
    pub fn runtime_directory(&self, root: &str) -> Result<String> {
        self.protocol.admits_runtime()?;
        if self.role == OverlayMemberRole::Observer {
            return Err(error!("Block-sync observers have no consensus database"));
        }
        Ok(format!(
            "{root}/consensus/consensus.{}.{:016x}.{}.{}",
            self.shard.workchain_id(),
            self.shard.shard_prefix_with_tag(),
            self.catchain_seqno,
            self.session_id.to_hex_string()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtos_block::KeyId;

    fn key(byte: u8) -> PublicKeyHash {
        KeyId::from_data([byte; 32])
    }

    #[test]
    fn membership_preserves_order_without_granting_observers_validator_authority() {
        let membership =
            SimplexMembership::new(&[key(3), key(1)], [key(1), key(2), key(3), key(2)]).unwrap();
        assert_eq!(membership.validator_index(&key(3)).unwrap(), 0);
        assert_eq!(membership.validator_index(&key(1)).unwrap(), 1);
        assert_eq!(membership.role(&key(2)).unwrap(), OverlayMemberRole::Observer);
        assert!(membership.validator_index(&key(2)).is_err());
        assert!(membership.role(&key(4)).is_err());
        assert!(SimplexMembership::new(&[key(1), key(1)], [key(1)]).is_err());
        assert!(SimplexMembership::new(&[key(1)], [key(2)]).is_err());
        assert!(SimplexMembership::new(&[], [key(1)]).is_err());
    }

    #[test]
    fn recognized_v2_and_unknown_versions_never_select_a_runtime_directory() {
        let shard = ShardIdent::masterchain();
        let session = UInt256::from([0x12; 32]);
        for version in 0..=2 {
            let protocol = SimplexProtocol::try_from(version).unwrap();
            assert_eq!(protocol.uses_block_sync(), version == 1);
            let namespace = SimplexNamespace {
                protocol,
                role: OverlayMemberRole::Validator(0),
                shard: &shard,
                catchain_seqno: 7,
                session_id: &session,
            };
            if version == 2 {
                assert!(namespace.runtime_directory("/isolated").is_err());
            } else {
                assert_eq!(
                    namespace.runtime_directory("/isolated").unwrap(),
                    format!(
                        "/isolated/consensus/consensus.-1.8000000000000000.7.{}",
                        "12".repeat(32)
                    )
                );
            }
            let observer = SimplexNamespace { role: OverlayMemberRole::Observer, ..namespace };
            assert!(observer.runtime_directory("/isolated").is_err());
        }
        assert!(SimplexProtocol::try_from(3).is_err());
        assert!(SimplexProtocol::try_from(u32::MAX).is_err());
    }
}
