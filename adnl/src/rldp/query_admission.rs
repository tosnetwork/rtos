// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Pending queries follow native RldpIn's node-wide (local, remote) registry.
use crate::common::AdnlPeers;
use rtos_block::{error, KeyId, Result};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

type Key = (Arc<KeyId>, Arc<KeyId>);
#[derive(Default)]
struct State {
    total: usize,
    connections: BTreeMap<Key, usize>,
}
pub(super) struct QueryBudget {
    state: Mutex<State>,
    global_limit: usize,
    connection_limit: usize,
}
impl QueryBudget {
    pub(super) fn new(global_limit: usize, connection_limit: usize) -> Arc<Self> {
        Arc::new(Self { state: Mutex::new(State::default()), global_limit, connection_limit })
    }
    pub(super) fn acquire(self: &Arc<Self>, peers: &AdnlPeers) -> Result<Arc<QueryAdmission>> {
        let key = (peers.local().clone(), peers.other().clone());
        let mut state = self.state.lock().unwrap();
        if state.total >= self.global_limit {
            return Err(error!("too many RLDP queries are already awaiting an answer"));
        }
        if state.connections.get(&key).copied().unwrap_or(0) >= self.connection_limit {
            return Err(error!(
                "too many RLDP queries are already awaiting an answer from this peer"
            ));
        }
        *state.connections.entry(key.clone()).or_default() += 1;
        state.total += 1;
        Ok(Arc::new(QueryAdmission { budget: self.clone(), key }))
    }
    #[cfg(test)]
    pub(super) fn remaining(&self, peers: &AdnlPeers) -> (usize, usize) {
        let state = self.state.lock().unwrap();
        (
            self.global_limit - state.total,
            self.connection_limit
                - state
                    .connections
                    .get(&(peers.local().clone(), peers.other().clone()))
                    .copied()
                    .unwrap_or(0),
        )
    }
}
pub(super) struct QueryAdmission {
    budget: Arc<QueryBudget>,
    key: Key,
}
impl Drop for QueryAdmission {
    fn drop(&mut self) {
        // Return both levels atomically, and retain no empty identity records.
        let mut state = self.budget.state.lock().unwrap();
        let count =
            state.connections.get_mut(&self.key).expect("live query admission is registered");
        *count -= 1;
        if *count == 0 {
            state.connections.remove(&self.key);
        }
        state.total -= 1;
    }
}
