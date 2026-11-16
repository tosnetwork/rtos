// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Pending queries follow native RldpIn's node-wide (local, remote) registry.
use crate::common::AdnlPeers;
use rtos_block::{error, KeyId, Result};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
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
        Ok(Arc::new(QueryAdmission { budget: self.clone(), key, released: AtomicBool::new(false) }))
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
    released: AtomicBool,
}
impl QueryAdmission {
    pub(super) fn release(&self) {
        if self.released.swap(true, Ordering::AcqRel) {
            return;
        }
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

impl Drop for QueryAdmission {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completed_query_releases_once_while_transport_retains_owner() {
        let peers = AdnlPeers::with_keys(KeyId::from_data([1; 32]), KeyId::from_data([2; 32]));
        let other = AdnlPeers::with_keys(peers.local().clone(), KeyId::from_data([3; 32]));
        let budget = QueryBudget::new(2, 1);
        let old = budget.acquire(&peers).unwrap();
        let retained_transport = old.clone();
        let other_query = budget.acquire(&other).unwrap();
        assert_eq!(budget.remaining(&peers), (0, 0));
        old.release();
        old.release();
        assert_eq!(budget.remaining(&peers), (1, 1));
        let fresh = budget.acquire(&peers).unwrap();
        assert!(budget.acquire(&peers).is_err());
        drop(old);
        drop(retained_transport);
        assert_eq!(
            budget.remaining(&peers),
            (0, 0),
            "old owner drop must not release the fresh query"
        );
        drop(fresh);
        assert_eq!(budget.remaining(&peers), (1, 1));
        drop(other_query);
        assert_eq!(budget.remaining(&peers), (2, 1));
        let cancelled = budget.acquire(&peers).unwrap();
        let descendant = cancelled.clone();
        drop(cancelled);
        assert_eq!(
            budget.remaining(&peers),
            (1, 0),
            "unresolved cancellation retains admission until owner drain"
        );
        drop(descendant);
        assert_eq!(budget.remaining(&peers), (2, 1));
    }
}
