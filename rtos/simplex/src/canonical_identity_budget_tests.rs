// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::finality_recovery::SourceHistoryDebtBudget;
#[derive(Default)]
struct Budget(Mutex<Vec<usize>>);
impl SourceHistoryDebtBudget for Budget {
    fn step(&self) -> Result<()> {
        Ok(())
    }
    fn workspace(&self, bytes: usize) -> Result<()> {
        self.0.lock().unwrap().push(bytes);
        Ok(())
    }
    fn read_bytes(&self, _: usize) -> Result<()> {
        fail!("data-only identity must not read storage")
    }
}
fn reply(
    runtime: &AuthenticatedSessionRuntime,
    draft: &FinalizedDeliveryDraft,
) -> (PendingFinalityRecord, CanonicalFinalityRecord) {
    let original = PendingFinalityRecord::from_draft(runtime, draft).unwrap();
    let response = CanonicalFinalityRecord {
        request: original.request(UInt256::calc_file_hash(b"node-receipt")),
        data: draft.data.clone(),
        finality: draft.finality.clone(),
        last_mc_finalized_seqno: draft.last_mc_finalized_seqno,
        candidate_already_sent: draft.candidate_already_sent,
        created_at_unix_secs: draft.created_at_unix_secs,
    };
    (original, response)
}
#[test]
fn canonical_identity_bounded_matches_original_final_and_approval_schema() {
    for finality in [true, false] {
        let (runtime, draft) = tests::fixture_role(
            finality,
            rtos_block::ShardIdent::with_tagged_prefix(0, 1u64 << 63).unwrap(),
        );
        let (original, response) = reply(&runtime, &draft);
        let budget = Budget::default();
        assert_eq!(
            canonical_source_identity_bounded(
                &runtime,
                &response,
                &original.signature_set,
                &budget
            )
            .unwrap(),
            canonical_source_identity(&runtime, &response).unwrap()
        );
        let allocations = budget.0.lock().unwrap();
        assert_eq!(allocations[0], original.data.len() + original.signature_set.len());
        assert_eq!(allocations[1], 2 * allocations[0]);
        assert_eq!(
            *allocations.last().unwrap(),
            original.encode().unwrap().len(),
            "exact JSON allocation is charged before serialization"
        );
    }
}
#[test]
fn canonical_identity_bounded_rejects_budget_before_payload_copy() {
    struct Deny;
    impl SourceHistoryDebtBudget for Deny {
        fn step(&self) -> Result<()> {
            Ok(())
        }
        fn workspace(&self, _: usize) -> Result<()> {
            fail!("injected identity workspace limit")
        }
        fn read_bytes(&self, _: usize) -> Result<()> {
            panic!("unexpected IO")
        }
    }
    let (runtime, draft) = tests::fixture();
    let (original, response) = reply(&runtime, &draft);
    let error =
        canonical_source_identity_bounded(&runtime, &response, &original.signature_set, &Deny)
            .unwrap_err();
    assert!(error.to_string().contains("identity workspace limit"));
}
