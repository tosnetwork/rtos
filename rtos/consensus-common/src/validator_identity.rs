// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Consensus identity is distinct from the key used by the network transport.
use crate::{PublicKey, PublicKeyHash, Result};
use rtos_block::{fail, KeyId, PqConsensusKey, UInt256, ValidatorDescr, ValidatorKey};

#[derive(Clone, Debug)]
pub enum ValidatorIdentity {
    Classical(PublicKey),
    Pq(PqValidatorIdentity),
}

#[derive(Clone, Debug)]
pub struct PqValidatorIdentity {
    validator_id: PublicKeyHash,
    key: PqConsensusKey,
}

impl From<PublicKey> for ValidatorIdentity {
    fn from(key: PublicKey) -> Self {
        Self::Classical(key)
    }
}

impl ValidatorIdentity {
    pub fn from_descriptor(descriptor: &ValidatorDescr) -> Result<Self> {
        descriptor.validate_consensus()?;
        let ValidatorKey::Pq(key) = &descriptor.key else {
            fail!("PQ consensus descriptor required");
        };
        Ok(Self::Pq(PqValidatorIdentity {
            validator_id: KeyId::from_data(*descriptor.validator_id()?.as_array()),
            key: key.clone(),
        }))
    }

    pub fn id(&self) -> &PublicKeyHash {
        match self {
            Self::Classical(key) => key.id(),
            Self::Pq(identity) => &identity.validator_id,
        }
    }

    pub fn pq_key(&self) -> Option<&PqConsensusKey> {
        match self {
            Self::Pq(identity) => Some(&identity.key),
            Self::Classical(_) => None,
        }
    }

    pub fn classical_key(&self) -> Result<&PublicKey> {
        match self {
            Self::Classical(key) => Ok(key),
            Self::Pq(_) => fail!("PQ consensus identity is not a classical or transport key"),
        }
    }

    /// The block creator is the authenticated validator identity for PQ members.
    pub fn block_creator(&self) -> Result<UInt256> {
        match self {
            Self::Classical(key) => Ok(UInt256::from_slice(key.pub_key()?)),
            Self::Pq(identity) => Ok(UInt256::from(*identity.validator_id.data())),
        }
    }

    /// Verify a canonical session-wrapped Simplex preimage under its frozen context.
    /// This public identity deliberately exposes no signing operation.
    pub fn verify_simplex(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        match self {
            Self::Classical(key) => key.verify(message, signature),
            Self::Pq(identity) => {
                if !rtos_pq_crypto::verify_simplex(message, signature, &identity.key.public_key)? {
                    fail!("invalid PQ Simplex signature");
                }
                Ok(())
            }
        }
    }
}

/// Verification-only interface; transport signing keys are never used for PQ.
pub trait SimplexSignatureVerifier {
    fn verify_simplex(&self, message: &[u8], signature: &[u8]) -> Result<()>;
}
impl SimplexSignatureVerifier for PublicKey {
    fn verify_simplex(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        self.verify(message, signature)
    }
}
impl SimplexSignatureVerifier for ValidatorIdentity {
    fn verify_simplex(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        ValidatorIdentity::verify_simplex(self, message, signature)
    }
}
