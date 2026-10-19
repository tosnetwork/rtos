// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use crate::{
    load_consensus_key, plan_key_load, select_stake_key, validate_schedule, ConfiguredKey,
    ConsensusKeyStore, Error, KeyWindow,
};
use rtos_block::{UInt256, ValidatorDescr, ValidatorKey};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

#[derive(Clone)]
pub struct HeldKey {
    pub store: Arc<ConsensusKeyStore>,
    pub valid_from: u32,
    pub expire_at: u32,
}
#[derive(Default)]
pub struct PqConsensusCustody {
    held: BTreeMap<UInt256, BTreeMap<[u8; 32], HeldKey>>,
    unloaded: BTreeMap<UInt256, Vec<KeyWindow>>,
}
impl PqConsensusCustody {
    /// Load an entire configured binding before exposing it. Any live seed or
    /// derived-ID error rejects startup; it is never downgraded to an observer.
    pub fn load(validator: UInt256, config: &[ConfiguredKey], now: u32) -> Result<Self, Error> {
        Self::load_with_key_ids(validator, config, now).map(|(custody, _)| custody)
    }
    /// The startup order of the reference node: plan the load before reading any
    /// seed, load every unexpired seed, check the schedule over the identities the
    /// seeds derive (the same seed under two paths is refused only here), install
    /// every loaded key, and only then record the windows of expired keys that
    /// were not loaded. Also returns the derived key identity of each loaded file.
    pub fn load_with_key_ids(
        validator: UInt256,
        config: &[ConfiguredKey],
        now: u32,
    ) -> Result<(Self, BTreeMap<PathBuf, [u8; 32]>), Error> {
        if validator == UInt256::default() {
            return Err(Error::InvalidValidator);
        }
        let to_load = plan_key_load(config, now)?;
        let mut loaded = Vec::with_capacity(to_load.len());
        let mut schedule = Vec::with_capacity(to_load.len());
        let mut key_ids_by_file = BTreeMap::new();
        for &index in &to_load {
            let entry = &config[index];
            let store = Arc::new(load_consensus_key(&entry.key_file, entry.expire_at)?);
            let id = *store.consensus_key().key_id.as_array();
            schedule.push(KeyWindow {
                key_id: Some(id),
                valid_from: entry.valid_from,
                expire_at: entry.expire_at,
            });
            key_ids_by_file.insert(entry.key_file.clone(), id);
            loaded.push((store, entry.valid_from, entry.expire_at));
        }
        validate_schedule(&schedule)?;
        let mut result = Self::default();
        for (store, valid_from, expire_at) in loaded {
            result.install(validator.clone(), store, valid_from, expire_at)?;
        }
        for (index, entry) in config.iter().enumerate() {
            if !to_load.contains(&index) {
                result.record_unloaded(validator.clone(), entry.valid_from, entry.expire_at)?;
            }
        }
        Ok((result, key_ids_by_file))
    }
    pub fn install(
        &mut self,
        validator: UInt256,
        store: Arc<ConsensusKeyStore>,
        valid_from: u32,
        expire_at: u32,
    ) -> Result<(), Error> {
        if validator == UInt256::default() {
            return Err(Error::InvalidValidator);
        }
        if store.expire_at() != expire_at {
            return Err(Error::DeadlineMismatch);
        }
        if store.retired() {
            return Err(Error::Retired);
        }
        let id = *store.consensus_key().key_id.as_array();
        let mut windows = self.windows(&validator);
        windows.retain(|window| window.key_id != Some(id));
        windows.push(KeyWindow { key_id: Some(id), valid_from, expire_at });
        validate_schedule(&windows)?;
        self.held
            .entry(validator)
            .or_default()
            .insert(id, HeldKey { store, valid_from, expire_at });
        Ok(())
    }
    pub fn record_unloaded(
        &mut self,
        validator: UInt256,
        valid_from: u32,
        expire_at: u32,
    ) -> Result<(), Error> {
        if validator == UInt256::default() {
            return Err(Error::InvalidValidator);
        }
        let window = KeyWindow { key_id: None, valid_from, expire_at };
        let mut windows = self.windows(&validator);
        windows.push(window.clone());
        validate_schedule(&windows)?;
        self.unloaded.entry(validator).or_default().push(window);
        Ok(())
    }
    pub fn held_keys(&self, validator: &UInt256) -> BTreeMap<[u8; 32], HeldKey> {
        self.held.get(validator).cloned().unwrap_or_default()
    }
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }
    pub fn holds(&self, validator: &UInt256, key_id: &[u8; 32], now: u32) -> bool {
        self.held
            .get(validator)
            .and_then(|keys| keys.get(key_id))
            .is_some_and(|held| !held.store.expired_at(u64::from(now)))
    }
    pub fn usable_key_ids(&self, validator: &UInt256, now: u32) -> Vec<[u8; 32]> {
        self.held
            .get(validator)
            .into_iter()
            .flat_map(|keys| keys.iter())
            .filter_map(|(id, held)| (!held.store.expired_at(u64::from(now))).then_some(*id))
            .collect()
    }
    /// An ADNL key, a validator identity alone, or another held PQ key cannot
    /// substitute for the exact authenticated descriptor supplied by the caller.
    pub fn get_matching_store(
        &self,
        validator: &UInt256,
        descriptor: &ValidatorDescr,
        now: u32,
    ) -> Option<Arc<ConsensusKeyStore>> {
        if descriptor.validator_id().ok().as_ref() != Some(validator) {
            return None;
        }
        let ValidatorKey::Pq(key) = &descriptor.key else {
            return None;
        };
        let held = self.held.get(validator)?.get(key.key_id.as_array())?;
        if held.store.expired_at(u64::from(now)) || held.store.consensus_key() != key {
            return None;
        }
        Some(held.store.clone())
    }
    pub fn select_stake_store(
        &self,
        validator: &UInt256,
        election_date: u32,
        now: u32,
        requested: Option<&[u8; 32]>,
    ) -> Result<Arc<ConsensusKeyStore>, Error> {
        // Observe every held deadline at this one caller-supplied time, latching
        // retirement even if another window is the scheduled choice.
        if let Some(keys) = self.held.get(validator) {
            for held in keys.values() {
                held.store.expired_at(u64::from(now));
            }
        }
        let windows = self.windows(validator);
        let selected = select_stake_key(&windows, election_date, now, requested)?;
        let id = windows[selected].key_id.ok_or(Error::UnavailableScheduledKey)?;
        let held = self
            .held
            .get(validator)
            .and_then(|keys| keys.get(&id))
            .ok_or(Error::UnavailableScheduledKey)?;
        if held.store.expired_at(u64::from(now)) {
            return Err(Error::Expired);
        }
        Ok(held.store.clone())
    }
    pub fn key_expired(&self, validator: &UInt256, key_id: &[u8; 32], now: u32) -> bool {
        self.held
            .get(validator)
            .and_then(|keys| keys.get(key_id))
            .is_some_and(|held| held.store.expired_at(u64::from(now)))
    }
    pub fn report_expired(
        &self,
        validator: &UInt256,
        key_id: Option<&[u8; 32]>,
        expire_at: u32,
        now: u32,
    ) -> bool {
        if let Some(held) = key_id.and_then(|id| self.held.get(validator)?.get(id)) {
            return held.store.expired_at(u64::from(now));
        }
        expire_at != 0 && now >= expire_at
    }
    pub fn removal_refusal(
        &self,
        validator: &UInt256,
        key_id: &[u8; 32],
        now: u32,
        sets: &[&[ValidatorDescr]],
    ) -> Option<&'static str> {
        let Some(keys) = self.held.get(validator) else {
            return Some("no such held consensus key");
        };
        let Some(key) = keys.get(key_id) else {
            return Some("no such held consensus key");
        };
        if !key.store.expired_at(u64::from(now)) && sets.iter().flat_map(|set| set.iter()).any(|descriptor| {
            descriptor.validator_id().ok().as_ref() == Some(validator) && matches!(&descriptor.key, ValidatorKey::Pq(pq) if pq.key_id.as_array() == key_id)
        }) { return Some("a previous, current or next validator set still lists this key"); }
        if !keys.iter().any(|(id, held)| id != key_id && !held.store.expired_at(u64::from(now))) {
            return Some("removal would leave no usable consensus key");
        }
        None
    }
    /// The owner must first check removal_refusal against its authenticated sets.
    pub fn remove_key(&mut self, validator: &UInt256, key_id: &[u8; 32]) -> bool {
        let Some(keys) = self.held.get_mut(validator) else {
            return false;
        };
        let removed = keys.remove(key_id).is_some();
        if keys.is_empty() {
            self.held.remove(validator);
        }
        removed
    }
    pub fn remove(&mut self, validator: &UInt256) {
        self.held.remove(validator);
        self.unloaded.remove(validator);
    }
    fn windows(&self, validator: &UInt256) -> Vec<KeyWindow> {
        let mut windows: Vec<_> = self
            .held
            .get(validator)
            .into_iter()
            .flat_map(|keys| keys.iter())
            .map(|(id, held)| KeyWindow {
                key_id: Some(*id),
                valid_from: held.valid_from,
                expire_at: held.expire_at,
            })
            .collect();
        if let Some(unloaded) = self.unloaded.get(validator) {
            windows.extend_from_slice(unloaded);
        }
        windows
    }
}
