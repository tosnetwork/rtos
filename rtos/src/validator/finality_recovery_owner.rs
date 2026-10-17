// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Engine-scoped reservations for recovery sessions and manager wakeups.
use consensus_common::session_runtime::{AuthenticatedSessionRuntime, LocalRole};
use rtos_block::{error, fail, Result, UInt256};
use std::{
    collections::HashMap,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdmissionKind {
    Normal,
    Recovery,
    /// Exclusive deletion authority over a retired authenticated namespace:
    /// no session, recovery or closure replay may open it meanwhile.
    Cleanup,
}

#[derive(Default)]
struct Reservations {
    stopping: bool,
    bootstrap_holds: u32,
    occupied: HashMap<RecoveryKey, (AdmissionKind, u64)>,
    next_lease: u64,
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
    /// Let the normal manager classify authenticated current namespaces before
    /// historical replay can claim one. Existing leases are never preempted.
    pub(crate) fn defer_recovery_admission(self: &Arc<Self>) -> Result<RecoveryBootstrapGate> {
        let mut state = self.reservations.lock().unwrap();
        if state.stopping {
            fail!("Recovery session admission stopped");
        }
        state.bootstrap_holds = state.bootstrap_holds.checked_add(1)
            .ok_or_else(|| error!("Recovery bootstrap gate count exhausted"))?;
        Ok(RecoveryBootstrapGate { registry: self.clone() })
    }
    pub(crate) fn recovery_admission_deferred(&self) -> bool {
        self.reservations.lock().unwrap().bootstrap_holds != 0
    }

    pub(crate) fn generation(&self) -> u64 {
        *self.changed.borrow()
    }
    pub(crate) fn owns(&self, runtime: &AuthenticatedSessionRuntime) -> bool {
        self.reservations
            .lock()
            .unwrap()
            .occupied
            .get(&Self::key(runtime))
            .is_some_and(|(kind, _)| *kind == AdmissionKind::Recovery)
    }
    pub(crate) fn reserve(
        self: &Arc<Self>,
        runtime: &AuthenticatedSessionRuntime,
    ) -> Result<Option<RecoveryReservation>> {
        self.reserve_key(Self::key(runtime))
    }
    pub(crate) fn reserve_normal(
        self: &Arc<Self>,
        runtime: &AuthenticatedSessionRuntime,
    ) -> Result<Option<RecoveryReservation>> {
        self.reserve_kind(Self::key(runtime), AdmissionKind::Normal)
    }
    fn reserve_key(self: &Arc<Self>, key: RecoveryKey) -> Result<Option<RecoveryReservation>> {
        self.reserve_kind(key, AdmissionKind::Recovery)
    }
    fn reserve_kind(
        self: &Arc<Self>,
        key: RecoveryKey,
        kind: AdmissionKind,
    ) -> Result<Option<RecoveryReservation>> {
        let mut state = self.reservations.lock().unwrap();
        if state.stopping {
            fail!("Recovery session admission stopped");
        }
        if kind == AdmissionKind::Recovery && state.bootstrap_holds != 0 {
            return Ok(None);
        }
        if state.occupied.contains_key(&key) {
            return Ok(None);
        }
        state.next_lease = state
            .next_lease
            .checked_add(1)
            .ok_or_else(|| error!("Session admission generation exhausted"))?;
        let lease = state.next_lease;
        state.occupied.insert(key.clone(), (kind, lease));
        self.changed.send_modify(|generation| *generation = generation.wrapping_add(1));
        Ok(Some(RecoveryReservation { registry: self.clone(), key, lease }))
    }
    /// Reserves a retired authenticated namespace for cleanup, keyed exactly
    /// like the runtime that ran there. `None` means a session, recovery or
    /// another cleanup holds it. A V1 namespace has no admission key.
    pub(crate) fn reserve_cleanup(
        self: &Arc<Self>,
        session: &UInt256,
        layout: &consensus_common::validator_cleanup::NamespaceLayout,
    ) -> Result<Option<RecoveryReservation>> {
        use consensus_common::validator_cleanup::NamespaceLayout;
        let role = match layout {
            NamespaceLayout::V1 => fail!("A V1 namespace has no admission key"),
            NamespaceLayout::V2Validator => RecoveryRole::Validator,
            NamespaceLayout::V2Observer(adnl) => RecoveryRole::Observer(adnl.clone()),
        };
        self.reserve_kind((session.clone(), role), AdmissionKind::Cleanup)
    }
    #[cfg(test)]
    pub(crate) fn reserve_validator_for_test(
        self: &Arc<Self>,
        session: UInt256,
    ) -> Result<Option<RecoveryReservation>> {
        self.reserve_kind((session, RecoveryRole::Validator), AdmissionKind::Normal)
    }
    #[cfg(test)]
    fn owns_key_for_test(&self, key: &RecoveryKey) -> bool {
        self.reservations
            .lock()
            .unwrap()
            .occupied
            .get(key)
            .is_some_and(|(kind, _)| *kind == AdmissionKind::Recovery)
    }
    #[cfg(test)]
    pub(crate) fn validator_reserved_for_test(&self, session: &UInt256) -> bool {
        self.reservations
            .lock()
            .unwrap()
            .occupied
            .contains_key(&(session.clone(), RecoveryRole::Validator))
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

/// This gate is only startup scheduling, never namespace or signing authority.
/// Drop on the first normal classification attempt (or its owner's failure).
/// Normal reservations continue to exclude recovery after the gate opens.
pub(crate) struct RecoveryBootstrapGate {
    registry: Arc<RecoveryRegistry>,
}
impl Drop for RecoveryBootstrapGate {
    fn drop(&mut self) {
        {
            let mut state = self.registry.reservations.lock().unwrap();
            state.bootstrap_holds = state.bootstrap_holds.checked_sub(1)
                .expect("owned recovery bootstrap gate");
        }
        self.registry.changed.send_modify(|generation| *generation = generation.wrapping_add(1));
    }
}

/// Release is explicit and belongs after checked session shutdown/join (or a
/// failed construction which created no session). Dropping an observer or an
/// unwinding owner must not advertise the namespace as free while threads live.
pub struct RecoveryReservation {
    registry: Arc<RecoveryRegistry>,
    key: RecoveryKey,
    lease: u64,
}
impl RecoveryReservation {
    #[cfg(test)]
    pub(crate) fn release_for_test(self) -> bool {
        self.release();
        true
    }
    pub(crate) fn release(self) {
        let removed = {
            let mut state = self.registry.reservations.lock().unwrap();
            if state.occupied.get(&self.key).is_some_and(|(_, lease)| *lease == self.lease) {
                state.occupied.remove(&self.key);
                true
            } else {
                false
            }
        };
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
    fn startup_classification_reserves_normal_without_releasing_its_lease() {
        let registry = Arc::new(RecoveryRegistry::default());
        let gate = registry.defer_recovery_admission().unwrap();
        let key = (UInt256::from([7; 32]), RecoveryRole::Validator);
        assert!(registry.reserve_key(key.clone()).unwrap().is_none());
        let normal = registry.reserve_kind(key.clone(), AdmissionKind::Normal).unwrap().unwrap();
        let generation = registry.generation();
        drop(gate);
        assert!(registry.generation() != generation);
        assert!(registry.reserve_key(key.clone()).unwrap().is_none(), "normal owner still holds its actual lease");
        normal.release();
        registry.reserve_key(key).unwrap().unwrap().release();
    }

    #[test]
    fn nested_startup_gates_open_only_after_the_last_owner_drops() {
        let registry = Arc::new(RecoveryRegistry::default());
        let first = registry.defer_recovery_admission().unwrap();
        let second = registry.defer_recovery_admission().unwrap();
        let key = (UInt256::from([8; 32]), RecoveryRole::Validator);
        drop(first);
        assert!(registry.recovery_admission_deferred());
        assert!(registry.reserve_key(key.clone()).unwrap().is_none());
        drop(second);
        assert!(!registry.recovery_admission_deferred());
        registry.reserve_key(key).unwrap().unwrap().release();
    }

    #[test]
    fn opening_a_startup_gate_does_not_reopen_stopped_admission() {
        let registry = Arc::new(RecoveryRegistry::default());
        let gate = registry.defer_recovery_admission().unwrap();
        registry.stop();
        drop(gate);
        assert!(registry.defer_recovery_admission().is_err());
        assert!(registry.reserve_key((UInt256::from([9;32]),RecoveryRole::Validator)).is_err());
    }

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
    #[test]
    fn normal_and_recovery_admission_are_atomic_and_stale_release_is_harmless() {
        for first in [AdmissionKind::Normal, AdmissionKind::Recovery] {
            let registry = Arc::new(RecoveryRegistry::default());
            let key = (UInt256::from([9; 32]), RecoveryRole::Validator);
            let owner = registry.reserve_kind(key.clone(), first).unwrap().unwrap();
            let stale = RecoveryReservation {
                registry: registry.clone(),
                key: key.clone(),
                lease: owner.lease,
            };
            let other = registry.clone();
            let other_key = key.clone();
            let loser = std::thread::spawn(move || {
                other
                    .reserve_kind(
                        other_key,
                        if first == AdmissionKind::Normal {
                            AdmissionKind::Recovery
                        } else {
                            AdmissionKind::Normal
                        },
                    )
                    .unwrap()
                    .is_none()
            });
            assert!(loser.join().unwrap());
            owner.release();
            let next = registry.reserve_kind(key.clone(), AdmissionKind::Normal).unwrap().unwrap();
            let generation = registry.generation();
            stale.release();
            assert_eq!(registry.generation(), generation);
            assert!(registry.reserve_key(key).unwrap().is_none());
            next.release();
            assert!(registry.reservations.lock().unwrap().occupied.is_empty());
        }
    }

    #[test]
    fn cleanup_admission_excludes_sessions_and_recovery_per_physical_namespace() {
        use consensus_common::validator_cleanup::NamespaceLayout;
        let registry = Arc::new(RecoveryRegistry::default());
        let session = UInt256::from([6; 32]);
        let adnl = UInt256::from([7; 32]);
        let validator_key = (session.clone(), RecoveryRole::Validator);
        let observer_key = (session.clone(), RecoveryRole::Observer(adnl.clone()));
        // Cleanup holds the validator namespace: no session or recovery opens it.
        let cleanup =
            registry.reserve_cleanup(&session, &NamespaceLayout::V2Validator).unwrap().unwrap();
        assert!(registry
            .reserve_kind(validator_key.clone(), AdmissionKind::Normal)
            .unwrap()
            .is_none());
        assert!(registry.reserve_key(validator_key.clone()).unwrap().is_none());
        assert!(!registry.owns_key_for_test(&validator_key), "cleanup is not a recovery owner");
        // The observer namespace of the same session is independent.
        let observer = registry
            .reserve_cleanup(&session, &NamespaceLayout::V2Observer(adnl))
            .unwrap()
            .unwrap();
        assert!(registry.reserve_key(observer_key.clone()).unwrap().is_none());
        // A live session refuses cleanup.
        cleanup.release();
        let live = registry.reserve_kind(validator_key, AdmissionKind::Normal).unwrap().unwrap();
        assert!(registry
            .reserve_cleanup(&session, &NamespaceLayout::V2Validator)
            .unwrap()
            .is_none());
        assert!(registry.reserve_cleanup(&session, &NamespaceLayout::V1).is_err());
        live.release();
        observer.release();
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
        assert!(registry.reservations.lock().unwrap().occupied.contains_key(&key));
        lease.release();
        // Release precedes subscription: a Notify-only design could lose this wakeup.
        registry.wait_changed(held).await.unwrap();
        assert!(!registry.reservations.lock().unwrap().occupied.contains_key(&key));
        let lease = registry.reserve_key(key.clone()).unwrap().unwrap();
        drop(lease);
        assert!(
            registry.reservations.lock().unwrap().occupied.contains_key(&key),
            "unwinding cannot release a possibly live session"
        );
        let seen = registry.generation();
        registry.stop();
        registry.wait_changed(seen).await.unwrap();
        assert!(registry.reserve_key((UInt256::from([3; 32]), key.1)).is_err());
    }
}
