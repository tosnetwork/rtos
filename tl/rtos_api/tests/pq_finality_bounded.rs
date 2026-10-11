// Copyright 2026 RTOS contributors. SPDX-License-Identifier: LGPL-2.0-or-later
#[path = "common/pq_finality.rs"]
mod fixture;
use rtos_api::pq_finality::PqVerificationContext;
use rtos_block::{config_read_budget::ConfigReadBudget, *};
use std::sync::Mutex;
const DOMAIN: &str = "TOS-CONSENSUS-SIMPLEX-v1";
#[derive(Debug)]
struct Refused;
impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "test budget refused")
    }
}
impl std::error::Error for Refused {}
struct Budget {
    used: Mutex<(usize, usize)>,
    limits: (usize, usize),
}
impl Budget {
    fn new(steps: usize, bytes: usize) -> Self {
        Self { used: Mutex::new((0, 0)), limits: (steps, bytes) }
    }
    fn ample() -> Self {
        Self::new(10_000_000, 128 << 20)
    }
}
impl ConfigReadBudget for Budget {
    fn step(&self) -> Result<()> {
        let mut used = self.used.lock().unwrap();
        if used.0 >= self.limits.0 {
            return Err(Refused.into());
        }
        used.0 += 1;
        Ok(())
    }
    fn workspace(&self, bytes: usize) -> Result<()> {
        let mut used = self.used.lock().unwrap();
        if bytes > self.limits.1.saturating_sub(used.1) {
            return Err(Refused.into());
        }
        used.1 += bytes;
        Ok(())
    }
}
fn context(config: &ConfigParams, budget: &Budget) -> Result<PqVerificationContext> {
    PqVerificationContext::from_governing_config_bounded(
        -239,
        config,
        fixture::block_id(),
        1,
        10,
        7,
        budget,
    )
}
#[test]
fn pq_bounded_context_ignores_unused_malformed_previous_next_sets() {
    let mut config = fixture::config();
    for index in [32u32, 33, 36, 37] {
        let mut value = BuilderData::new();
        value.checked_append_reference(Cell::default()).unwrap();
        config.config_params.set_builder(index.write_to_bitstring().unwrap(), &value).unwrap();
        assert!(config.config(index).is_err());
    }
    let ordinary = fixture::context(&config);
    let bounded = context(&config, &Budget::ample()).unwrap();
    assert_eq!(ordinary.expected_session_id(), bounded.expected_session_id());
    assert_eq!(ordinary.subset_hash(), bounded.subset_hash());
    let carrier = fixture::signed(&[1], "finalize", DOMAIN);
    assert_eq!(
        ordinary.verify_final(&carrier).unwrap().weight(),
        bounded.verify_final_bounded(&carrier, &Budget::ample()).unwrap().weight()
    );
}
#[test]
fn pq_bounded_preserves_quorum_roles_and_checks_all_supplied_signatures() {
    let context = context(&fixture::config(), &Budget::ample()).unwrap();
    for indices in [&[][..], &[0][..], &[1][..], &[0, 1][..]] {
        let carrier = fixture::signed(indices, "finalize", DOMAIN);
        assert_eq!(
            context.verify_final(&carrier).is_ok(),
            context.verify_final_bounded(&carrier, &Budget::ample()).is_ok()
        );
    }
    let mut bad = fixture::signed(&[0, 1], "finalize", DOMAIN);
    // Signer 1 alone suffices; corruption of extra signer 0 must still fail.
    bad.signatures[0].signature[0] ^= 1;
    assert!(context.verify_final(&bad).is_err());
    assert!(context.verify_final_bounded(&bad, &Budget::ample()).is_err());
    let notarize = fixture::signed(&[1], "notarize", DOMAIN);
    assert!(context.verify_final(&notarize).is_err());
    assert!(context.verify_final_bounded(&notarize, &Budget::ample()).is_err());
    let mut session = fixture::signed(&[1], "finalize", DOMAIN);
    session.session_id = UInt256::default();
    assert!(context.verify_final_bounded(&session, &Budget::ample()).is_err());
}
#[test]
fn pq_bounded_budget_is_cumulative_and_preserves_typed_refusal() {
    let config = fixture::config();
    for limit in [Budget::new(0, usize::MAX), Budget::new(usize::MAX, 0)] {
        assert!(context(&config, &limit).unwrap_err().downcast_ref::<Refused>().is_some());
    }
    let counted = Budget::ample();
    let context = context(&config, &counted).unwrap();
    let carrier = fixture::signed(&[1], "finalize", DOMAIN);
    context.verify_final_bounded(&carrier, &counted).unwrap();
    let (steps, bytes) = *counted.used.lock().unwrap();
    assert!(steps > 0 && bytes > 0);
    // Exactly one derivation+verification fits; a second on the SAME owner fails.
    let exact = Budget::new(steps, bytes);
    let context = PqVerificationContext::from_governing_config_bounded(
        -239,
        &config,
        fixture::block_id(),
        1,
        10,
        7,
        &exact,
    )
    .unwrap();
    context.verify_final_bounded(&carrier, &exact).unwrap();
    assert!(context
        .verify_final_bounded(&carrier, &exact)
        .unwrap_err()
        .downcast_ref::<Refused>()
        .is_some());
    for limit in [Budget::new(0, usize::MAX), Budget::new(usize::MAX, 0)] {
        assert!(context
            .verify_final_bounded(&carrier, &limit)
            .unwrap_err()
            .downcast_ref::<Refused>()
            .is_some());
    }
}

#[test]
fn pq_bounded_network_preserves_final_role_and_rejects_masterchain_approval() {
    use rtos_api::pq_finality::{PqApproval, PqNetworkSignatureSet};
    let context = context(&fixture::config(), &Budget::ample()).unwrap();
    let carrier = fixture::signed(&[1], "finalize", DOMAIN);
    let fields = PqNetworkSignatureSet::from_final_fields(&carrier).unwrap().to_node();
    let parsed =
        PqNetworkSignatureSet::from_node_bounded(fields.clone(), &Budget::ample()).unwrap();
    let (bounded, receipt) =
        context.verify_network_bounded(&parsed, &Budget::ample()).unwrap().into_final().unwrap();
    assert_eq!(bounded, carrier);
    assert_eq!(receipt.weight(), carrier.sig_weight);
    assert!(context
        .verify_network_bounded(&parsed, &Budget::new(0, usize::MAX))
        .unwrap_err()
        .downcast_ref::<Refused>()
        .is_some());
    assert!(PqNetworkSignatureSet::from_node_bounded(fields, &Budget::new(usize::MAX, 0))
        .unwrap_err()
        .downcast_ref::<Refused>()
        .is_some());
    let approval =
        PqApproval::from_notarization_fields(fixture::signed(&[1], "notarize", DOMAIN)).unwrap();
    let parsed = PqNetworkSignatureSet::from_node_bounded(
        PqNetworkSignatureSet::from_approval(&approval).unwrap().to_node(),
        &Budget::ample(),
    )
    .unwrap();
    assert!(context.verify_network(&parsed).is_err());
    assert!(context.verify_network_bounded(&parsed, &Budget::ample()).is_err());
    let mut bad =
        PqNetworkSignatureSet::from_final_fields(&fixture::signed(&[0, 1], "finalize", DOMAIN))
            .unwrap()
            .to_node();
    bad.signatures[0].signature[0] ^= 1;
    let bad = PqNetworkSignatureSet::from_node_bounded(bad, &Budget::ample()).unwrap();
    assert!(context.verify_network_bounded(&bad, &Budget::ample()).is_err());
}
