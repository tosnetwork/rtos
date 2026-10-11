// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Engine-scoped reservations for recovery sessions and manager wakeups.
use consensus_common::session_runtime::{AuthenticatedSessionRuntime, LocalRole};
use rtos_block::{error, fail, Result, UInt256};
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

// A validator namespace is shared across transport-key changes; observers have
// separate identity-suffixed namespaces. Match runtime_directory, not custody.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum RecoveryRole {
    Validator,
    Observer(UInt256),
}
type RecoveryKey = (UInt256, RecoveryRole);
fn role_key(role: LocalRole, local_adnl: UInt256) -> RecoveryRole {
    match role {
        LocalRole::Validator(_) => RecoveryRole::Validator,
        LocalRole::Observer => RecoveryRole::Observer(local_adnl),
    }
}
#[derive(Default)]
struct Reservations {
    stopping: bool,
    occupied: HashSet<RecoveryKey>,
}

pub(crate) struct RecoveryRegistry {
    reservations: Mutex<Reservations>,
    changed: tokio::sync::watch::Sender<u64>,
}
impl Default for RecoveryRegistry {
    fn default() -> Self {
        Self {
            reservations: Mutex::new(Reservations::default()),
            changed: tokio::sync::watch::channel(0).0,
        }
    }
}
impl RecoveryRegistry {
    fn key(runtime: &AuthenticatedSessionRuntime) -> RecoveryKey {
        (
            runtime.session_id().clone(),
            role_key(runtime.local_role(), UInt256::from(*runtime.local_adnl().data())),
        )
    }
    pub(crate) fn generation(&self) -> u64 {
        *self.changed.borrow()
    }
    pub(crate) fn owns(&self, runtime: &AuthenticatedSessionRuntime) -> bool {
        self.reservations.lock().unwrap().occupied.contains(&Self::key(runtime))
    }
    pub(crate) fn reserve(
        self: &Arc<Self>,
        runtime: &AuthenticatedSessionRuntime,
    ) -> Result<Option<RecoveryReservation>> {
        self.reserve_key(Self::key(runtime))
    }
    fn reserve_key(self: &Arc<Self>, key: RecoveryKey) -> Result<Option<RecoveryReservation>> {
        let mut state = self.reservations.lock().unwrap();
        if state.stopping {
            fail!("Recovery session admission stopped");
        }
        if !state.occupied.insert(key.clone()) {
            return Ok(None);
        }
        self.changed.send_modify(|generation| *generation = generation.wrapping_add(1));
        Ok(Some(RecoveryReservation { registry: self.clone(), key }))
    }
    pub(crate) fn stop(&self) {
        self.reservations.lock().unwrap().stopping = true;
        self.changed.send_modify(|generation| *generation = generation.wrapping_add(1));
    }
    pub(crate) async fn wait_changed(&self, seen: u64) -> Result<()> {
        let mut receiver = self.changed.subscribe();
        loop {
            if *receiver.borrow_and_update() != seen {
                return Ok(());
            }
            if self.reservations.lock().unwrap().stopping {
                return Ok(());
            }
            receiver.changed().await.map_err(|e| error!("Recovery registry closed: {e}"))?;
        }
    }
}

/// Release is explicit and belongs after checked session shutdown/join (or a
/// failed construction which created no session). Dropping an observer or an
/// unwinding owner must not advertise the namespace as free while threads live.
pub(crate) struct RecoveryReservation {
    registry: Arc<RecoveryRegistry>,
    key: RecoveryKey,
}
impl RecoveryReservation {
    pub(crate) fn release(self) {
        let removed = self.registry.reservations.lock().unwrap().occupied.remove(&self.key);
        if removed {
            self.registry
                .changed
                .send_modify(|generation| *generation = generation.wrapping_add(1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovery_registry_follows_validator_and_observer_namespace_identity() {
        let registry = Arc::new(RecoveryRegistry::default());
        let session = UInt256::from([3; 32]);
        let first = UInt256::from([4; 32]);
        let rotated = UInt256::from([5; 32]);
        let validator = registry
            .reserve_key((session.clone(), role_key(LocalRole::Validator(0), first.clone())))
            .unwrap()
            .unwrap();
        assert!(
            registry
                .reserve_key((session.clone(), role_key(LocalRole::Validator(1), rotated.clone())))
                .unwrap()
                .is_none(),
            "transport rotation cannot open a second validator namespace"
        );
        let observer_a = registry
            .reserve_key((session.clone(), role_key(LocalRole::Observer, first)))
            .unwrap()
            .unwrap();
        let observer_b = registry
            .reserve_key((session, role_key(LocalRole::Observer, rotated)))
            .unwrap()
            .unwrap();
        observer_a.release();
        observer_b.release();
        validator.release();
        assert!(registry.reservations.lock().unwrap().occupied.is_empty());
    }
    #[tokio::test]
    async fn recovery_registry_release_wakes_same_state_without_losing_notifications() {
        let registry = Arc::new(RecoveryRegistry::default());
        let key = (UInt256::from([1; 32]), RecoveryRole::Observer(UInt256::from([2; 32])));
        let before = registry.generation();
        let lease = registry.reserve_key(key.clone()).unwrap().unwrap();
        registry.wait_changed(before).await.unwrap();
        assert!(registry.reserve_key(key.clone()).unwrap().is_none());
        let held = registry.generation();
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(10),
            registry.wait_changed(held)
        )
        .await
        .is_err());
        assert!(registry.reservations.lock().unwrap().occupied.contains(&key));
        lease.release();
        // Release precedes subscription: a Notify-only design could lose this wakeup.
        registry.wait_changed(held).await.unwrap();
        assert!(!registry.reservations.lock().unwrap().occupied.contains(&key));
        let lease = registry.reserve_key(key.clone()).unwrap().unwrap();
        drop(lease);
        assert!(
            registry.reservations.lock().unwrap().occupied.contains(&key),
            "unwinding cannot release a possibly live session"
        );
        let seen = registry.generation();
        registry.stop();
        registry.wait_changed(seen).await.unwrap();
        assert!(registry.reserve_key((UInt256::from([3; 32]), key.1)).is_err());
    }
}
