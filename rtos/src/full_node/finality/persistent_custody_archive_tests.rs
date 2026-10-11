// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Actual signed blocks, real custody, archive relocation/GC and cold authentication.
use super::*;
#[path = "persistent_closure_chain.rs"]
mod chain;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires RTOS_PUBLIC_FIXTURE_SIGNER; real Engine archive custody integration"]
async fn persistent_repair_custody_real_pack_gc_control_and_cold_authentication() {
    use storage::archives::{package_entry_id::PackageEntryId, package_id::PackageId, ARCHIVE_SLICE_SIZE};
    let signer = std::env::var("RTOS_PUBLIC_FIXTURE_SIGNER").unwrap();
    let mut fixture = fixture(false).await;
    let engine = fixture.engine.clone();
    let run = std::panic::AssertUnwindSafe(async {
        // MC1/2 occupy archive slice 0. A genuine new key block creates slice 3;
        // MC1 remains a physically readable, unleased control in the earlier slice.
        let control = fixture.parent.id().clone();
        engine.db().archive_block(&control, None).await.unwrap();
        let mut previous = fixture.target.id().clone();
        let mut root = engine.load_state(&previous).await.unwrap().root_cell().clone();
        let state = ShardStateUnsplit::construct_from_cell(root.clone()).unwrap();
        let extra = state.read_custom().unwrap().unwrap();
        let cc = extra.validator_info.catchain_seqno;
        let creator = extra.config.validator_set().unwrap().list()[0].validator_id().unwrap();
        for (key, epoch) in [(true, 0), (false, 3)] {
            let (id, expected, row) = chain::successor(&signer, &previous, &root, key, epoch, cc, &creator);
            let block = fixture_block(&row);
            let proof = BlockProofStuff::deserialize(&id, decode(&row["proof_boc"]), false).unwrap();
            proof.check_proof(engine.as_ref()).await.unwrap();
            let handle = engine.store_block(&block).await.unwrap().to_any();
            engine.store_block_proof(&id, Some(handle.clone()), &proof).await.unwrap();
            engine.clone().download_and_apply_block(&id, id.seq_no(), false).await.unwrap();
            assert!(handle.is_applied());
            assert_eq!(engine.load_state(&id).await.unwrap().root_cell().repr_hash(), expected.repr_hash());
            previous = id;
            root = expected;
            if key { fixture.parent = block; } else { fixture.target = block; }
        }
        let context = engine.historical_pq_publication_context(
            fixture.target.id(), fixture.target.block().unwrap()).await.unwrap();
        fixture.request = McFinalRepairRequest {
            pin: SessionNetworkPin { global_id: context.global_id(), zerostate: context.zerostate().clone() },
            history_init: context.history_init().clone(), block_id: fixture.target.id().clone(),
            session_id: context.verifier().expected_session_id().clone(), profile: context.profile().clone(),
            protocol: context.protocol(), carrier_version: context.carrier_version(), wire_profile: WireProfile::T0,
        };
        let exact = binding(&fixture);
        let cap = obtain_durable_mc_custody(engine.clone(), fixture.request.clone(), exact.clone()).await.unwrap();
        let generation = cap.lease_generation();
        let digest = cap.dependency_digest().clone();
        drop(cap);
        let ledger = engine.db().repair_leases().lookup(generation,
            &crate::history_read_budget::HistoryReadBudget::new(Default::default())).unwrap();
        assert_eq!(ledger.state, crate::publication_dependency_leases::LeaseState::DurableCustody);
        assert!(ledger.dependencies.iter().all(|d| d.id != control.to_string()),
            "control must be outside the actual authenticated dependency closure");
        let root_dir = PathBuf::from(engine.db_root_dir().unwrap());
        let target = fixture.target.id();
        let handle = engine.load_block_handle(target).unwrap().unwrap();
        let proof = engine.load_block_proof(&handle, false).await.unwrap();
        let loose_body = root_dir.join("archive/unapplied").join(PackageEntryId::Block(target).filename_short());
        let loose_proof = root_dir.join("archive/unapplied").join(PackageEntryId::Proof(target).filename_short());
        // Actual repair writes these loose artifacts, even when its input was packed.
        assert!(!handle.is_archived());
        assert_eq!(std::fs::read(&loose_body).unwrap(), fixture.target.data());
        assert_eq!(std::fs::read(&loose_proof).unwrap(), proof.data());
        engine.db().archive_block(target, None).await.unwrap();
        engine.db().sync_publication_metadata(&handle).await.unwrap();
        assert!(handle.is_archived());
        assert!(!loose_body.exists() && !loose_proof.exists());
        let control_pack = PackageId::for_block(0).full_path(&root_dir, control.shard()).unwrap();
        let protected_pack = PackageId::for_block(3).full_path(&root_dir, target.shard()).unwrap();
        assert!(control_pack.exists() && protected_pack.exists());
        let control_handle = engine.load_block_handle(&control).unwrap().unwrap();
        assert_eq!(engine.load_block(&control_handle).await.unwrap().id(), &control);
        engine.load_block_proof(&control_handle, false).await.unwrap().check_proof(engine.as_ref()).await.unwrap();
        // Cutoff is only a GC range selector, never authentication authority.
        // It selects both slice 0 and slice 3 under the real production slice size.
        let cutoff = BlockIdExt::with_params(ShardIdent::masterchain(), 3 + ARCHIVE_SLICE_SIZE,
            UInt256::default(), UInt256::default());
        engine.db().archive_gc(&cutoff).await.unwrap();
        assert!(!control_pack.exists(), "same-cutoff unleased archive package must really be destroyed");
        assert!(protected_pack.exists(), "leased archive package must survive the same actual GC");
        assert!(engine.load_block(&control_handle).await.is_err());
        assert_eq!(engine.load_block(&handle).await.unwrap().data(), fixture.target.data());
        assert_eq!(engine.load_block_proof(&handle, false).await.unwrap().data(), proof.data());
        (exact, generation, digest, control_pack, protected_pack)
    }).catch_unwind().await;
    drop(engine);
    let Fixture { dir, engine, .. } = fixture;
    close(engine).await;
    let (exact, generation, digest, control_pack, protected_pack) =
        run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    let engine = open_engine(dir.path()).await;
    let run = std::panic::AssertUnwindSafe(async {
        assert!(!control_pack.exists() && protected_pack.exists());
        let cap = reopen_durable_mc_custody(engine.clone(), generation, exact.clone(), digest.clone()).await.unwrap();
        assert_eq!(cap.binding(), &exact);
        assert_eq!(cap.dependency_digest(), &digest);
        drop(cap);
        assert!(!control_pack.exists());
    }).catch_unwind().await;
    close(engine).await;
    run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}
