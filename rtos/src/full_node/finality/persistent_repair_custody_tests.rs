// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{
    publication_repair::{obtain_durable_mc_custody, reopen_durable_mc_custody},
    repair_lease_binding::{RepairLeaseBinding, RepairLeaseDomain},
};
use consensus_common::{
    finality_delivery::{CanonicalFinalityRequest, FinalityDeliveryRole},
    session_runtime::SessionRecoveryCoordinates,
};
fn binding(fixture: &Fixture) -> RepairLeaseBinding {
    let r = &fixture.request;
    let info = fixture.target.block().unwrap().read_info().unwrap();
    let receipt = UInt256::from([0x67; 32]);
    RepairLeaseBinding {
        record_id: 1,
        delivery_id: receipt.clone(),
        canonical: CanonicalFinalityRequest {
            node_receipt: receipt,
            block_id: r.block_id.clone(),
            role: FinalityDeliveryRole::Final,
            local_adnl: UInt256::from([0x91; 32]),
            local_validator_index: None,
            source_validator: fixture
                .target
                .block()
                .unwrap()
                .read_extra()
                .unwrap()
                .created_by()
                .clone(),
        },
        domain: RepairLeaseDomain {
            zerostate: r.pin.zerostate.clone(),
            global_id: r.pin.global_id,
            history_init: r.history_init.clone(),
            source_recovery_anchor: fixture.parent.id().clone(),
            source_recovery_coordinates: SessionRecoveryCoordinates {
                shard: r.block_id.shard().clone(),
                catchain_seqno: info.gen_catchain_seqno(),
                vertical_seqno: info.vert_seq_no(),
                last_key_block_seqno: info.prev_key_block_seqno(),
                new_catchain_ids: false,
            },
            session_id: r.session_id.clone(),
            profile: r.profile.clone(),
            protocol: r.protocol,
            carrier_version: r.carrier_version,
            wire_profile: r.wire_profile,
        },
        source_digest: UInt256::from([0x68; 32]),
        canonical_digest: UInt256::from([0x69; 32]),
        created_at_unix_secs: 100,
        expires_at_unix_secs: 200,
        effects_digest: UInt256::from([0x70; 32]),
        close_generation: 1,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_repair_custody_actual_engine_cache_cold_gc_and_exact_binding() {
    let fixture = fixture(true).await;
    let exact = binding(&fixture);
    let Fixture { dir, engine, parent, target, request } = fixture;
    let run = std::panic::AssertUnwindSafe(async {
        let cap = obtain_durable_mc_custody(engine.clone(), request.clone(), exact.clone())
            .await
            .unwrap();
        let generation = cap.lease_generation();
        let digest = cap.dependency_digest().clone();
        drop(cap);
        // Both full and predecessor authority caches are warm from fixture and
        // first repair. Dedicated provenance must still be exactly identical.
        let cap = obtain_durable_mc_custody(engine.clone(), request.clone(), exact.clone())
            .await
            .unwrap();
        assert_eq!(cap.lease_generation(), generation);
        assert_eq!(cap.dependency_digest(), &digest);
        drop(cap);
        engine.shard_states_keeper().test_retire_history_state(target.id());
        assert!(!engine.shard_states_keeper().allow_state_gc(parent.id()).unwrap());
        assert!(!engine.shard_states_keeper().allow_state_gc(target.id()).unwrap());
        // Exercise actual archive/unapplied deletion APIs, then cold read.
        engine.db().archive_gc(target.id()).await.unwrap();
        (generation, digest)
    })
    .catch_unwind()
    .await;
    close(engine).await;
    let (generation, digest) = run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    let engine = open_engine(dir.path()).await;
    let run = std::panic::AssertUnwindSafe(async {
        engine.shard_states_keeper().test_retire_history_state(target.id());
        let cap =
            reopen_durable_mc_custody(engine.clone(), generation, exact.clone(), digest.clone())
                .await
                .unwrap();
        assert_eq!(cap.binding(), &exact);
        drop(cap);
        assert!(engine.db().test_contains_dynamic_state_record(parent.id()).unwrap());
        assert!(engine.db().test_contains_dynamic_state_record(target.id()).unwrap());
        let mut conflict = exact;
        conflict.effects_digest = UInt256::default();
        assert!(reopen_durable_mc_custody(engine.clone(), generation, conflict, digest)
            .await
            .is_err());
    })
    .catch_unwind()
    .await;
    close(engine).await;
    run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_repair_custody_missing_parent_refuses_durable_lease() {
    let fixture = fixture(false).await;
    let exact = binding(&fixture);
    let Fixture { dir, engine, parent, target: _, request } = fixture;
    engine.shard_states_keeper().test_retire_history_state(parent.id());
    let run = std::panic::AssertUnwindSafe(async {
        tokio::time::timeout(Duration::from_secs(15), async {
            while engine.db().test_contains_dynamic_state_record(parent.id()).unwrap() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert!(obtain_durable_mc_custody(engine.clone(), request, exact).await.is_err());
    })
    .catch_unwind()
    .await;
    close(engine).await;
    drop(dir);
    run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_repair_custody_capsule_internal_closure_repairs_real_history_then_cold_checks()
{
    let fixture = fixture(true).await;
    let exact = binding(&fixture);
    let Fixture { dir, engine, parent, target, request } = fixture;
    let setup = std::panic::AssertUnwindSafe(async {
        let state = engine.load_state(parent.id()).await.unwrap();
        let config = state.config_params().unwrap();
        let coords = &exact.domain.source_recovery_coordinates;
        let (committee, _) = config
            .validator_set()
            .unwrap()
            .calc_subset(&config.catchain_config().unwrap(), SHARD_FULL, -1, coords.catchain_seqno)
            .unwrap();
        let runtime = AuthenticatedSessionRuntime::from_authenticated_config(
            request.pin.clone(),
            config,
            rtos_api::session_identity::SessionCoordinates {
                shard: &coords.shard,
                catchain_seqno: coords.catchain_seqno,
                vertical_seqno: coords.vertical_seqno,
                last_key_block_seqno: coords.last_key_block_seqno,
                new_catchain_ids: coords.new_catchain_ids,
            },
            committee,
            rtos_block::KeyId::from_data([0x91; 32]),
        )
        .unwrap()
        .bind_recovery_anchor(parent.id().clone())
        .unwrap();
        crate::retired_history::prepare(engine.clone(), Arc::new(runtime), target.id().clone())
            .await
            .unwrap();
        let proof = engine
            .load_block_proof(&engine.load_block_handle(parent.id()).unwrap().unwrap(), false)
            .await
            .unwrap();
        (PathBuf::from(engine.db_root_dir().unwrap()), proof.data().to_vec())
    })
    .catch_unwind()
    .await;
    close(engine).await;
    let (root, proof) = setup.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    let _backups = withdraw_proof(&root, &proof);
    let engine = open_engine(dir.path()).await;
    let run = std::panic::AssertUnwindSafe(async {
        let cap = obtain_durable_mc_custody(engine.clone(), request, exact.clone()).await.unwrap();
        let generation = cap.lease_generation();
        let digest = cap.dependency_digest().clone();
        drop(cap);
        let record = engine
            .db()
            .repair_leases()
            .lookup(
                generation,
                &crate::history_read_budget::HistoryReadBudget::new(Default::default()),
            )
            .unwrap();
        assert!(record
            .dependencies
            .iter()
            .any(|d| d.kind == "capsule-state" && d.id == parent.id().to_string()));
        assert!(record
            .dependencies
            .iter()
            .any(|d| d.kind == "proof" && d.id == parent.id().to_string()));
        let actual = engine
            .load_block_proof(&engine.load_block_handle(parent.id()).unwrap().unwrap(), false)
            .await
            .unwrap();
        assert_eq!(
            actual.data(),
            proof.as_slice(),
            "capsule proof was restored to real normal storage"
        );
        (generation, digest)
    })
    .catch_unwind()
    .await;
    close(engine).await;
    let (generation, digest) = run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    let capsule = root.join("retired-history-v1");
    let withdrawn = root.join("withdrawn-custody-capsule");
    std::fs::rename(&capsule, &withdrawn).unwrap();
    let engine = open_engine(dir.path()).await;
    let run = std::panic::AssertUnwindSafe(async {
        assert!(
            reopen_durable_mc_custody(engine.clone(), generation, exact.clone(), digest.clone())
                .await
                .is_err(),
            "missing physical capsule cannot be replaced by a ledger claim"
        );
    })
    .catch_unwind()
    .await;
    close(engine).await;
    run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    std::fs::rename(&withdrawn, &capsule).unwrap();
    let engine = open_engine(dir.path()).await;
    let run = std::panic::AssertUnwindSafe(async {
        drop(reopen_durable_mc_custody(engine.clone(), generation, exact, digest).await.unwrap());
    })
    .catch_unwind()
    .await;
    close(engine).await;
    run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_repair_history_real_local_limits_never_enter_capsule_or_network_fallback() {
    let Fixture { dir, engine, parent, .. } = fixture(true).await;
    let result = std::panic::AssertUnwindSafe(async {
        for depth_limit in [false, true] {
            let mut limits = crate::history_read_budget::HistoryReadLimits::default();
            if depth_limit { limits.depth = 0; } else { limits.cells = 0; }
            let budget = crate::history_read_budget::HistoryReadBudget::new(limits);
            for _ in 0..2 {
                let error = crate::boot::load_history_proof_with_budget(
                    engine.as_ref(), parent.id(), false, true, Some(&budget),
                ).await.unwrap_err();
                assert!(crate::history_read_budget::stops_fallback(&error), "{error:#}");
                assert_eq!(budget.local_proof_fallbacks(), 0,
                    "actual local proof resource denial must precede capsule/network fallback");
            }
        }
    }).catch_unwind().await;
    close(engine).await;
    drop(dir);
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[path = "persistent_custody_crash_tests.rs"]
mod crash_tests;

#[path = "persistent_ledger_startup_tests.rs"]
mod ledger_startup_tests;
