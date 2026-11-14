// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Config::unpack_validator_set's shared 100-entry LRU. Wire/schema decoders and
//! bounded readers remain independent; cached values have passed full decoding.
use crate::{error, Cell, Deserializable, Result, UInt256, ValidatorSet};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, LazyLock, Mutex},
};

const CAPACITY: usize = 100;
struct Cache {
    values: HashMap<UInt256, Arc<ValidatorSet>>,
    newest: VecDeque<UInt256>,
}
impl Cache {
    fn new() -> Self {
        Self {
            values: HashMap::with_capacity(CAPACITY + 1),
            newest: VecDeque::with_capacity(CAPACITY + 1),
        }
    }
    fn get(&mut self, key: &UInt256) -> Option<Arc<ValidatorSet>> {
        let value = self.values.get(key)?.clone();
        self.newest.retain(|entry| entry != key);
        self.newest.push_front(key.clone());
        Some(value)
    }
    fn put(&mut self, key: UInt256, value: Arc<ValidatorSet>) {
        self.values.insert(key.clone(), value);
        self.newest.retain(|entry| entry != &key);
        self.newest.push_front(key);
        if self.values.len() > CAPACITY {
            if let Some(oldest) = self.newest.pop_back() {
                self.values.remove(&oldest);
            }
        }
    }
}
static CACHE: LazyLock<Mutex<Cache>> = LazyLock::new(|| Mutex::new(Cache::new()));

fn unpack(root: Cell, use_cache: bool, cache: &Mutex<Cache>) -> Result<Arc<ValidatorSet>> {
    // Like C++ load_cell(), load this root even on a hit. Loader errors cannot
    // be hidden by a known hash, and usage roots must still record the load.
    let tracked = root.load_usage_tracking()?;
    let use_cache = use_cache && !tracked;
    let key = use_cache.then(|| root.repr_hash().clone());
    if let Some(key) = &key {
        if let Some(value) = cache.lock().map_err(|_| error!("validator cache poisoned"))?.get(key)
        {
            return Ok(value);
        }
    }
    crate::proof::require_proof_cell(&root)?;
    let value = Arc::new(ValidatorSet::construct_from_full_cell(root)?);
    if let Some(key) = key {
        cache.lock().map_err(|_| error!("validator cache poisoned"))?.put(key, value.clone());
    }
    Ok(value)
}

impl ValidatorSet {
    /// Decode a configuration's validator set, optionally resolving an already
    /// validated root hash. A usage-tracked root always bypasses get and put.
    pub fn unpack_with_cache(root: Cell, use_cache: bool) -> Result<Arc<Self>> {
        unpack(root, use_cache, &CACHE)
    }
}

#[cfg(test)]
#[path = "tests/test_validator_set_cache.rs"]
mod tests;
