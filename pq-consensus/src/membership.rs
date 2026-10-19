// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Which members of a validator set this node is, and which held key signs for
//! it there. These helpers answer membership for every descriptor kind; whether
//! a set can run a post-quantum group is a separate admission decision.
use crate::{ConsensusKeyStore, Error, PqConsensusCustody};
use rtos_block::{UInt256, ValidatorDescr, ValidatorKey};
use std::{collections::BTreeSet, sync::Arc};

/// Whether `descriptor` is this node's own at `now`. A post-quantum descriptor
/// is ours only while custody holds, unexpired, the exact key identity the
/// descriptor records for that validator identity: no network or operator key
/// can answer for it. A classical descriptor is ours when its key identity is
/// one of the local temporary or permanent keys.
pub fn local_consensus_descriptor(
    descriptor: &ValidatorDescr,
    temp_keys: &BTreeSet<UInt256>,
    permanent_keys: &BTreeSet<UInt256>,
    custody: &PqConsensusCustody,
    now: u32,
) -> bool {
    let Ok(validator) = descriptor.validator_id() else {
        return false;
    };
    match &descriptor.key {
        ValidatorKey::Pq(key) => custody.holds(&validator, key.key_id.as_array(), now),
        ValidatorKey::Ed25519(_) => {
            temp_keys.contains(&validator) || permanent_keys.contains(&validator)
        }
    }
}

/// The validator identity this node is a member of `set` as, if any: the first
/// descriptor, in set order, that `local_consensus_descriptor` accepts.
pub fn local_consensus_member(
    set: &[ValidatorDescr],
    temp_keys: &BTreeSet<UInt256>,
    permanent_keys: &BTreeSet<UInt256>,
    custody: &PqConsensusCustody,
    now: u32,
) -> Option<UInt256> {
    set.iter()
        .find(|descriptor| {
            local_consensus_descriptor(descriptor, temp_keys, permanent_keys, custody, now)
        })
        .and_then(|descriptor| descriptor.validator_id().ok())
}

/// `(has_local_keys, is_member_of_set)`. Holding no key at all is reported
/// separately so a caller can answer "unknown" rather than a false negative;
/// custodying a post-quantum consensus key counts as holding one.
pub fn node_validator_membership(
    set: &[ValidatorDescr],
    temp_keys: &BTreeSet<UInt256>,
    permanent_keys: &BTreeSet<UInt256>,
    custody: &PqConsensusCustody,
    now: u32,
) -> (bool, bool) {
    let has_keys = !temp_keys.is_empty() || !permanent_keys.is_empty() || !custody.is_empty();
    (has_keys, local_consensus_member(set, temp_keys, permanent_keys, custody, now).is_some())
}

/// Where `validator` stands in `members`, and the held key that signs for it
/// there: only the key the member's descriptor records, held unexpired at
/// `now`. A member whose descriptor records any other key gets no signer, and
/// never another held key.
pub struct PqSetSigner {
    pub index: usize,
    pub descriptor: ValidatorDescr,
    pub signer: Arc<ConsensusKeyStore>,
}

pub fn pq_signer_for_set(
    members: &[ValidatorDescr],
    validator: &UInt256,
    custody: &PqConsensusCustody,
    now: u32,
) -> Result<PqSetSigner, Error> {
    for (index, descriptor) in members.iter().enumerate() {
        let ValidatorKey::Pq(key) = &descriptor.key else {
            continue;
        };
        if descriptor.validator_id().ok().as_ref() != Some(validator) {
            continue;
        }
        let signer = custody
            .get_matching_store(validator, descriptor, now)
            .ok_or(Error::UnheldSetKey(*key.key_id.as_array()))?;
        return Ok(PqSetSigner { index, descriptor: descriptor.clone(), signer });
    }
    Err(Error::NotSetValidator)
}
