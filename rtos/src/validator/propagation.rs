// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Routing after authentication. A plan grants no candidate or final-proof authority.
use crate::block::BlockStuff;
use consensus_common::simplex_protocol::SimplexProtocol;
use rtos_block::{BlockIdExt, UInt256};
use std::collections::VecDeque;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TargetSet {
    pub public: bool,
    pub fast_sync: bool,
    pub custom: bool,
}
impl TargetSet {
    pub const NONE: Self = Self { public: false, fast_sync: false, custom: false };
    pub const ALL: Self = Self { public: true, fast_sync: true, custom: true };
    pub const AUXILIARY: Self = Self { public: false, fast_sync: true, custom: true };
    pub const CUSTOM: Self = Self { public: false, fast_sync: false, custom: true };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PropagationEvent {
    CandidateGenerated,
    CandidateReceived,
    Finalized,
}

#[derive(Clone, Debug)]
pub struct PropagationPlan {
    pub candidate_targets: TargetSet,
    pub block_targets: TargetSet,
    pub finality_targets: TargetSet,
    pub send_shard_description: bool,
    pub protocol: SimplexProtocol,
    pub locally_generated: bool,
    exact_destination: Option<PropagationDestination>,
}
impl PropagationPlan {
    pub fn destination(&self) -> Option<&PropagationDestination> {
        self.exact_destination.as_ref()
    }

    pub fn targets_for(&self, kind: PropagationKind) -> TargetSet {
        match kind {
            PropagationKind::Candidate => self.candidate_targets,
            PropagationKind::Block => self.block_targets,
            PropagationKind::Finality => self.finality_targets,
            PropagationKind::ShardDescription => TargetSet::NONE,
        }
    }

    /// Restrict an authenticated plan to one previously resolved destination.
    /// Durable retry tracks that destination separately; it never re-expands a
    /// saved custom name into all overlays present after a configuration change.
    pub fn for_destination(
        &self,
        destination: &PropagationDestination,
    ) -> rtos_block::Result<Self> {
        if self.exact_destination.as_ref().is_some_and(|saved| saved != destination) {
            rtos_block::fail!("Cannot change a previously resolved propagation destination");
        }
        let targets = self.targets_for(destination.kind);
        let allowed = match &destination.target {
            PropagationTarget::Public => targets.public,
            PropagationTarget::FastSync => targets.fast_sync,
            PropagationTarget::Custom(_) => targets.custom,
            PropagationTarget::ShardDescription => {
                destination.kind == PropagationKind::ShardDescription && self.send_shard_description
            }
        };
        if !allowed {
            rtos_block::fail!("Destination is outside the authenticated propagation plan");
        }
        let mut plan = self.clone();
        plan.candidate_targets = TargetSet::NONE;
        plan.block_targets = TargetSet::NONE;
        plan.finality_targets = TargetSet::NONE;
        plan.send_shard_description = false;
        let selected = match &destination.target {
            PropagationTarget::Public => TargetSet { public: true, ..TargetSet::NONE },
            PropagationTarget::FastSync => TargetSet { fast_sync: true, ..TargetSet::NONE },
            PropagationTarget::Custom(_) => TargetSet::CUSTOM,
            PropagationTarget::ShardDescription => TargetSet::NONE,
        };
        match destination.kind {
            PropagationKind::Candidate => plan.candidate_targets = selected,
            PropagationKind::Block => plan.block_targets = selected,
            PropagationKind::Finality => plan.finality_targets = selected,
            PropagationKind::ShardDescription => plan.send_shard_description = true,
        }
        plan.exact_destination = Some(destination.clone());
        Ok(plan)
    }

    /// Inputs must describe the authenticated session and candidate. `is_creator`
    /// means a local validator owns the candidate's verified leader index; an
    /// observer must always supply false. Empty consensus candidates have no block.
    pub fn for_event(
        protocol: SimplexProtocol,
        event: PropagationEvent,
        id: &BlockIdExt,
        nonempty: bool,
        is_creator: bool,
        is_final: bool,
        last_mc_finalized_seqno: u32,
        candidate_already_sent: bool,
    ) -> Self {
        let v2 = protocol == SimplexProtocol::PrivateObserversPlumtree;
        let mut plan = Self {
            candidate_targets: TargetSet::NONE,
            block_targets: TargetSet::NONE,
            finality_targets: TargetSet::NONE,
            send_shard_description: !v2,
            protocol,
            locally_generated: is_creator,
            exact_destination: None,
        };
        if !nonempty {
            return plan;
        }
        let candidate_recent =
            last_mc_finalized_seqno < 4 || id.seq_no() > last_mc_finalized_seqno - 4;
        if !candidate_already_sent
            && ((v2
                && (event == PropagationEvent::CandidateReceived
                    || (event == PropagationEvent::Finalized && candidate_recent)))
                || (!v2
                    && event == PropagationEvent::CandidateGenerated
                    && !id.shard().is_masterchain()))
        {
            plan.candidate_targets = if v2 { TargetSet::ALL } else { TargetSet::AUXILIARY };
        }
        if event != PropagationEvent::Finalized {
            return plan;
        }
        if last_mc_finalized_seqno >= 2 && id.seq_no() < last_mc_finalized_seqno - 2 {
            return plan;
        }
        plan.block_targets = TargetSet::CUSTOM;
        if is_creator {
            plan.block_targets.public = true;
            plan.block_targets.fast_sync = !v2;
        }
        if v2 {
            if is_final {
                plan.finality_targets = TargetSet::ALL;
            }
        } else if candidate_already_sent {
            plan.block_targets.fast_sync = false;
            plan.block_targets.custom = false;
        }
        plan
    }
}

/// Shared CandidateReceived/Finalize relay LRU (T0 candidate-relay-policy.h).
/// Successful delivery attempts are remembered; failed/deferred sends may retry.
/// Block/finality outcome retry state must never reuse this cache.
#[derive(Default)]
pub struct CandidateRelayDeduplicator {
    entries: VecDeque<BlockIdExt>,
}
impl CandidateRelayDeduplicator {
    pub const CAPACITY: usize = 256;
    pub fn contains(&mut self, id: &BlockIdExt) -> bool {
        let Some(index) = self.entries.iter().position(|entry| entry == id) else {
            return false;
        };
        let entry = self.entries.remove(index).unwrap();
        self.entries.push_back(entry);
        true
    }
    pub fn record_sent(&mut self, id: BlockIdExt) {
        if self.contains(&id) {
            return;
        }
        if self.entries.len() == Self::CAPACITY {
            self.entries.pop_front();
        }
        self.entries.push_back(id);
    }
}

/// Constructed by the validated group callback after leader/source/PQ checks,
/// or by acceptance after verifying a quorum bound to the exact candidate and
/// block bytes. This wrapper itself performs no consensus verification and does
/// not confer final-proof authority (an accepted approval may also relay).
#[derive(Clone)]
pub struct ValidatedCandidateRelay {
    block: BlockStuff,
    catchain_seqno: u32,
    validator_set_hash: u32,
    session_id: UInt256,
}
impl ValidatedCandidateRelay {
    pub(super) fn from_validated_group_candidate(
        block: BlockStuff,
        catchain_seqno: u32,
        validator_set_hash: u32,
        session_id: UInt256,
    ) -> Self {
        Self { block, catchain_seqno, validator_set_hash, session_id }
    }
    pub fn block(&self) -> &BlockStuff {
        &self.block
    }
    pub fn catchain_seqno(&self) -> u32 {
        self.catchain_seqno
    }
    pub fn validator_set_hash(&self) -> u32 {
        self.validator_set_hash
    }
    pub fn session_id(&self) -> &UInt256 {
        &self.session_id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PropagationKind {
    Candidate,
    Block,
    Finality,
    ShardDescription,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PropagationTarget {
    Public,
    FastSync,
    Custom(String),
    ShardDescription,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PropagationDestination {
    pub kind: PropagationKind,
    pub target: PropagationTarget,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PropagationStatus {
    /// The transport accepted the send attempt, not an application acknowledgement.
    Sent,
    Skipped(String),
    Deferred(String),
    Failed(String),
}
#[derive(Clone, Debug)]
pub struct PropagationReceipt {
    pub kind: PropagationKind,
    pub target: PropagationTarget,
    pub status: PropagationStatus,
}
#[derive(Clone, Debug, Default)]
pub struct PropagationOutcome {
    pub receipts: Vec<PropagationReceipt>,
}
impl PropagationOutcome {
    pub fn failed_for_plan(
        kind: PropagationKind,
        plan: &PropagationPlan,
        error: impl std::fmt::Display,
    ) -> Self {
        if let Some(destination) = plan.destination().filter(|d| d.kind == kind) {
            let mut outcome = Self::default();
            outcome.record(
                kind,
                destination.target.clone(),
                PropagationStatus::Failed(error.to_string()),
            );
            outcome
        } else {
            Self::failed(kind, plan.targets_for(kind), error)
        }
    }

    pub fn failed(
        kind: PropagationKind,
        targets: TargetSet,
        error: impl std::fmt::Display,
    ) -> Self {
        let mut outcome = Self::default();
        let mut selected = vec![];
        if targets.public {
            selected.push(PropagationTarget::Public);
        }
        if targets.fast_sync {
            selected.push(PropagationTarget::FastSync);
        }
        if targets.custom {
            selected.push(PropagationTarget::Custom(String::new()));
        }
        for target in selected {
            outcome.record(kind, target, PropagationStatus::Failed(error.to_string()));
        }
        outcome
    }
    pub fn record(
        &mut self,
        kind: PropagationKind,
        target: PropagationTarget,
        status: PropagationStatus,
    ) {
        self.receipts.push(PropagationReceipt { kind, target, status });
    }
    pub fn needs_retry(&self) -> bool {
        self.receipts.iter().any(|r| {
            matches!(r.status, PropagationStatus::Failed(_) | PropagationStatus::Deferred(_))
        })
    }
    pub fn attempted(&self) -> bool {
        self.receipts.iter().any(|r| matches!(r.status, PropagationStatus::Sent))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtos_block::ShardIdent;
    fn id(seq: u32, mc: bool) -> BlockIdExt {
        BlockIdExt::with_params(
            if mc { ShardIdent::MASTERCHAIN } else { ShardIdent::BASE_WORKCHAIN },
            seq,
            UInt256::from([1; 32]),
            UInt256::from([2; 32]),
        )
    }
    #[test]
    fn propagation_exact_destination_does_not_expand_custom_retry() {
        let plan = PropagationPlan::for_event(
            SimplexProtocol::PrivateObserversPlumtree,
            PropagationEvent::Finalized,
            &id(10, false),
            true,
            true,
            true,
            10,
            false,
        );
        let destination = PropagationDestination {
            kind: PropagationKind::Finality,
            target: PropagationTarget::Custom("old-name".into()),
        };
        let retry = plan.for_destination(&destination).unwrap();
        assert_eq!(retry.block_targets, TargetSet::NONE);
        assert_eq!(retry.candidate_targets, TargetSet::NONE);
        assert_eq!(retry.finality_targets, TargetSet::CUSTOM);
        assert_eq!(retry.destination(), Some(&destination));
        assert!(retry
            .for_destination(&PropagationDestination {
                kind: PropagationKind::Finality,
                target: PropagationTarget::Custom("new-name".into()),
            })
            .is_err());
        assert!(retry.for_destination(&destination).is_ok());
        let failed =
            PropagationOutcome::failed_for_plan(PropagationKind::Finality, &retry, "closed");
        assert_eq!(failed.receipts.len(), 1);
        assert_eq!(failed.receipts[0].target, destination.target);
        assert!(failed.needs_retry());
        assert!(!failed.attempted());
        assert!(plan
            .for_destination(&PropagationDestination {
                kind: PropagationKind::ShardDescription,
                target: PropagationTarget::ShardDescription,
            })
            .is_err());
    }

    #[test]
    fn propagation_v2_creator_observer_and_approval_modes() {
        for creator in [true, false] {
            for final_ in [true, false] {
                let plan = PropagationPlan::for_event(
                    SimplexProtocol::PrivateObserversPlumtree,
                    PropagationEvent::Finalized,
                    &id(10, false),
                    true,
                    creator,
                    final_,
                    10,
                    false,
                );
                assert_eq!(plan.candidate_targets, TargetSet::ALL);
                assert_eq!(
                    plan.block_targets,
                    TargetSet { public: creator, fast_sync: false, custom: true }
                );
                assert_eq!(
                    plan.finality_targets,
                    if final_ { TargetSet::ALL } else { TargetSet::NONE }
                );
                assert!(!plan.send_shard_description);
            }
        }
    }
    #[test]
    fn propagation_v0_v1_generated_candidate_and_block_modes() {
        for protocol in [SimplexProtocol::Private, SimplexProtocol::BlockSync] {
            for mc in [true, false] {
                let plan = PropagationPlan::for_event(
                    protocol,
                    PropagationEvent::CandidateGenerated,
                    &id(10, mc),
                    true,
                    true,
                    false,
                    10,
                    false,
                );
                assert_eq!(
                    plan.candidate_targets,
                    if mc { TargetSet::NONE } else { TargetSet::AUXILIARY }
                );
                assert_eq!(plan.finality_targets, TargetSet::NONE);
            }
            let plan = PropagationPlan::for_event(
                protocol,
                PropagationEvent::Finalized,
                &id(10, false),
                true,
                true,
                true,
                10,
                true,
            );
            assert_eq!(
                plan.block_targets,
                TargetSet { public: true, fast_sync: false, custom: false }
            );
            assert_eq!(plan.finality_targets, TargetSet::NONE);
            assert!(plan.send_shard_description);
        }
    }
    #[test]
    fn propagation_candidate_recovery_and_block_staleness_are_distinct() {
        let plan = |seq, last, event| {
            PropagationPlan::for_event(
                SimplexProtocol::PrivateObserversPlumtree,
                event,
                &id(seq, false),
                true,
                true,
                true,
                last,
                false,
            )
        };
        assert_eq!(plan(6, 10, PropagationEvent::Finalized).candidate_targets, TargetSet::NONE);
        assert_eq!(plan(7, 10, PropagationEvent::Finalized).candidate_targets, TargetSet::ALL);
        assert_eq!(plan(7, 10, PropagationEvent::Finalized).block_targets, TargetSet::NONE);
        assert_eq!(plan(8, 10, PropagationEvent::Finalized).finality_targets, TargetSet::ALL);
        assert_eq!(
            plan(u32::MAX, u32::MAX, PropagationEvent::Finalized).candidate_targets,
            TargetSet::ALL
        );
        assert_eq!(
            plan(1, 10, PropagationEvent::CandidateReceived).candidate_targets,
            TargetSet::ALL
        );
        let empty = PropagationPlan::for_event(
            SimplexProtocol::PrivateObserversPlumtree,
            PropagationEvent::CandidateReceived,
            &id(10, false),
            false,
            true,
            true,
            10,
            false,
        );
        assert_eq!(empty.candidate_targets, TargetSet::NONE);
    }
    #[test]
    fn propagation_shared_candidate_lru_is_bounded_and_refreshes_duplicates() {
        let mut cache = CandidateRelayDeduplicator::default();
        for seq in 0..256 {
            cache.record_sent(id(seq, false));
        }
        assert!(cache.contains(&id(0, false)));
        cache.record_sent(id(256, false));
        assert!(!cache.contains(&id(1, false)));
        assert!(cache.contains(&id(0, false)));
        assert_eq!(cache.entries.len(), 256);
    }
}
