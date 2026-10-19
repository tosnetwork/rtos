// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use crate::Error;
use std::{collections::BTreeSet, path::PathBuf};
pub const MAX_HELD_KEYS: usize = 8;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfiguredKey {
    pub key_file: PathBuf,
    pub valid_from: u32,
    pub expire_at: u32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyWindow {
    /// None means an expired seed was not loaded. Its election range is retained.
    pub key_id: Option<[u8; 32]>,
    pub valid_from: u32,
    pub expire_at: u32,
}
impl KeyWindow {
    pub fn expired(&self, now: u32) -> bool {
        self.expire_at != 0 && now >= self.expire_at
    }
}
pub fn validate_windows(keys: &[KeyWindow]) -> Result<(), Error> {
    if keys.is_empty() {
        return Err(Error::InvalidSchedule("no consensus key is configured"));
    }
    if keys.len() > MAX_HELD_KEYS {
        return Err(Error::InvalidSchedule("at most 8 consensus keys may be held at once"));
    }
    let mut starts = BTreeSet::new();
    for key in keys {
        if key.expire_at != 0 && key.expire_at <= key.valid_from {
            return Err(Error::InvalidSchedule(
                "a consensus key expires not after its window opens",
            ));
        }
        if !starts.insert(key.valid_from) {
            return Err(Error::InvalidSchedule(
                "two consensus keys are valid from the same election date",
            ));
        }
    }
    Ok(())
}
pub fn validate_schedule(keys: &[KeyWindow]) -> Result<(), Error> {
    validate_windows(keys)?;
    let mut identities = BTreeSet::new();
    for key in keys {
        if let Some(id) = key.key_id {
            if !identities.insert(id) {
                return Err(Error::InvalidSchedule("a consensus key is configured twice"));
            }
        }
    }
    Ok(())
}
/// Decided before any seed is read. File paths are refused first, key by key,
/// and only then the windows, so the first refusal reported for a configuration
/// is the same one the reference node reports.
pub fn plan_key_load(keys: &[ConfiguredKey], now: u32) -> Result<Vec<usize>, Error> {
    let mut paths = BTreeSet::new();
    let mut windows = Vec::with_capacity(keys.len());
    for key in keys {
        if key.key_file.as_os_str().is_empty() {
            return Err(Error::InvalidSchedule("a consensus key is configured with no key file"));
        }
        if !paths.insert(&key.key_file) {
            return Err(Error::InvalidSchedule("a consensus key file is configured twice"));
        }
        windows.push(KeyWindow {
            key_id: None,
            valid_from: key.valid_from,
            expire_at: key.expire_at,
        });
    }
    validate_windows(&windows)?;
    let load: Vec<_> = windows
        .iter()
        .enumerate()
        .filter_map(|(i, key)| (!key.expired(now)).then_some(i))
        .collect();
    if load.is_empty() {
        return Err(Error::InvalidSchedule("every configured consensus key has expired"));
    }
    Ok(load)
}
/// The greatest valid_from <= election_date decides first. Expiry or missing
/// custody rejects that choice; it never causes a search for an older key.
pub fn select_stake_key(
    keys: &[KeyWindow],
    election_date: u32,
    now: u32,
    requested: Option<&[u8; 32]>,
) -> Result<usize, Error> {
    validate_schedule(keys)?;
    let (index, chosen) = keys
        .iter()
        .enumerate()
        .filter(|(_, key)| key.valid_from <= election_date)
        .max_by_key(|(_, key)| key.valid_from)
        .ok_or(Error::NoScheduledKey)?;
    if requested.is_some() && requested != chosen.key_id.as_ref() {
        return Err(Error::UnexpectedScheduledKey);
    }
    if chosen.key_id.is_none()
        || chosen.expired(now)
        || (chosen.expire_at != 0 && chosen.expire_at <= election_date)
    {
        return Err(Error::UnavailableScheduledKey);
    }
    Ok(index)
}
