// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Local consensus signing material, isolated from wallet and ADNL keyrings.
//!
//! A store signs nothing by itself being held: a durable session coordinator
//! enforces replay, equivocation and publication rules before using one.
#![deny(unsafe_op_in_unsafe_fn)]

mod custody;
mod key_file;
mod membership;
mod schedule;
mod store;

pub use custody::{HeldKey, PqConsensusCustody};
pub use key_file::{load_consensus_key, KeyFileError};
pub use membership::{
    local_consensus_descriptor, local_consensus_member, node_validator_membership,
    pq_signer_for_set, PqSetSigner,
};
pub use rtos_pq_crypto::SIMPLEX_CONTEXT;
pub use schedule::{
    plan_key_load, select_stake_key, validate_schedule, validate_windows, ConfiguredKey, KeyWindow,
    MAX_HELD_KEYS,
};
pub use store::{
    consensus_key_retired, ConsensusKeyStore, ConsensusSignature, CONFIG_VOTE_CONTEXT,
    ELECTION_CONTEXT, SEED_BYTES,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    SeedLength(usize),
    Randomness,
    Backend(i32),
    MessageTooLong,
    Expired,
    Retired,
    InvalidSchedule(&'static str),
    NoScheduledKey,
    UnexpectedScheduledKey,
    UnavailableScheduledKey,
    DeadlineMismatch,
    InvalidValidator,
    NotSetValidator,
    UnheldSetKey([u8; 32]),
    KeyFile(KeyFileError),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SeedLength(n) => write!(f, "consensus seed must have 32 bytes, received {n}"),
            Self::Randomness => f.write_str("OS randomness unavailable"),
            Self::Backend(code) => write!(f, "consensus signing backend failed ({code})"),
            Self::MessageTooLong => f.write_str("consensus preimage exceeds the protocol limit"),
            Self::Expired => f.write_str("consensus key has expired"),
            Self::Retired => f.write_str("consensus key was retired in this process"),
            Self::InvalidSchedule(reason) => write!(f, "invalid consensus key schedule: {reason}"),
            Self::NoScheduledKey => f.write_str("no key is scheduled for this election"),
            Self::UnexpectedScheduledKey => {
                f.write_str("requested key differs from the scheduled key")
            }
            Self::UnavailableScheduledKey => {
                f.write_str("the scheduled key is unavailable; no fallback is permitted")
            }
            Self::DeadlineMismatch => {
                f.write_str("store signing deadline differs from custody window")
            }
            Self::InvalidValidator => f.write_str("validator identity must not be zero"),
            Self::NotSetValidator => f.write_str("not a validator of the set"),
            Self::UnheldSetKey(key_id) => {
                f.write_str("the set records consensus key ")?;
                for byte in key_id {
                    write!(f, "{byte:02x}")?;
                }
                f.write_str(" for this validator, which this node does not hold unexpired")
            }
            Self::KeyFile(error) => write!(f, "consensus seed file refused: {error}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<KeyFileError> for Error {
    fn from(error: KeyFileError) -> Self {
        Self::KeyFile(error)
    }
}

#[cfg(test)]
mod tests;
