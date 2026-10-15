// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Actual signed blocks, real custody, archive relocation/GC and cold authentication.
use super::*;
#[path = "persistent_closure_chain.rs"]
mod chain;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires RTOS_PUBLIC_FIXTURE_SIGNER; real Engine archive custody integration"]
async fn persistent_repair_custody_real_pack_gc_control_and_cold_authentication() {
    real_pack_gc(false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires RTOS_PUBLIC_FIXTURE_SIGNER; real selected archive GC versus custody registration"]
async fn persistent_repair_custody_selected_archive_gc_rechecks_actual_registration() {
    real_pack_gc(true, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires RTOS_PUBLIC_FIXTURE_SIGNER; protected package cold corruption preservation"]
async fn persistent_repair_custody_protected_pack_cold_damage_is_nondestructive() {
    real_pack_gc(false, true).await;
}

async fn real_pack_gc(preselected: bool, cold_damage: bool) {
    use storage::archives::{package_entry_id::PackageEntryId, package_id::PackageId, ARCHIVE_SLICE_SIZE};
    let signer = std::env::var("RTOS_PUBLIC_FIXTURE_SIGNER").unwrap();
    let mut fixture = fixture(false).await;
    let engine = fixture.engine.clone();
    let mut gc_task = None;
    let mut release_gc = None;
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
        // This range selects both actual slices; it is not an authenticated ID.
        let cutoff = BlockIdExt::with_params(ShardIdent::masterchain(), 3 + ARCHIVE_SLICE_SIZE,
            UInt256::default(), UInt256::default());
        if preselected {
            let (selected, release) = engine.db().test_pause_archive_gc_selection();
            release_gc = Some(release);
            let gc_engine = engine.clone();
            let gc_cutoff = cutoff.clone();
            gc_task = Some(tokio::spawn(async move { gc_engine.db().archive_gc(&gc_cutoff).await }));
            let keys = tokio::time::timeout(Duration::from_secs(30), selected).await
                .expect("real archive GC must reach candidate selection").unwrap();
            assert!(keys.contains(&0) && keys.contains(&3), "same GC batch must select both real slices: {keys:?}");
            // No deletion lock is held here. Real authentication and durable
            // registration must finish before this same selected batch resumes.
        }
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
        if let Some(release) = &release_gc { release.notify_one(); }
        if let Some(task) = gc_task.take() {
            task.await.unwrap().unwrap();
        } else {
            engine.db().archive_gc(&cutoff).await.unwrap();
        }
        assert!(!control_pack.exists(), "same-cutoff unleased archive package must really be destroyed");
        assert!(protected_pack.exists(), "leased archive package must survive the same actual GC");
        assert!(engine.load_block(&control_handle).await.is_err());
        assert_eq!(engine.load_block(&handle).await.unwrap().data(), fixture.target.data());
        assert_eq!(engine.load_block_proof(&handle, false).await.unwrap().data(), proof.data());
        (exact, generation, digest, control_pack, protected_pack)
    }).catch_unwind().await;
    // Release/join the actual selected GC on every assertion-failure path.
    if let Some(release) = release_gc { release.notify_one(); }
    let gc_cleanup = match gc_task {
        Some(task) => task.await.map_err(|e| rtos_block::error!("archive GC owner: {e}"))
            .and_then(|result| result),
        None => Ok(()),
    };
    drop(engine);
    let Fixture { dir, engine, .. } = fixture;
    let stopped = engine.clone().wait_stop().await;
    drop(engine);
    let (exact, generation, digest, control_pack, protected_pack) =
        run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    gc_cleanup.unwrap();
    stopped.unwrap();
    if cold_damage {
        protected_pack_cold_damage_checks(dir.path(), &protected_pack, generation, &exact, &digest).await;
        let root = protected_pack.ancestors().nth(4).unwrap();
        let key_pack = PackageId::for_key_block(0).full_path(root, &rtos_block::ShardIdent::masterchain()).unwrap();
        assert!(key_pack.exists(), "real MC3 key proof must have a non-sliced provider");
        protected_pack_cold_damage_checks(dir.path(), &key_pack, generation, &exact, &digest).await;
    }
    let engine = open_engine(dir.path()).await;
    let run = std::panic::AssertUnwindSafe(async {
        assert!(!control_pack.exists() && protected_pack.exists());
        let cap = reopen_durable_mc_custody(engine.clone(), generation, exact.clone(), digest.clone()).await.unwrap();
        assert_eq!(cap.binding(), &exact);
        assert_eq!(cap.dependency_digest(), &digest);
        drop(cap);
        assert!(!control_pack.exists());
    }).catch_unwind().await;
    let stopped = engine.clone().wait_stop().await;
    drop(engine);
    run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    stopped.unwrap();
}


#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_repair_archive_owner_cancel_waiter_and_shutdown_drain() {
    let Fixture { dir, engine, target, .. } = fixture(false).await;
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let mut caller = None;
    let mut waiting = None;
    let mut stopping = None;
    let mut completed_stop = None;
    let run = std::panic::AssertUnwindSafe(async {
        let handle = engine.load_block_handle(target.id()).unwrap().unwrap();
        assert!(!handle.is_archived(), "repair fixture must require actual migration");
        engine.db().test_hold_archive_migration(entered.clone(), release.clone());
        let caller_engine = engine.clone();
        let id = target.id().clone();
        caller = Some(tokio::spawn(async move { caller_engine.db().archive_block(&id, None).await }));
        entered.notified().await;
        caller.as_ref().unwrap().abort();
        assert!(caller.take().unwrap().await.unwrap_err().is_cancelled());
        let waiting_engine = engine.clone();
        let id = target.id().clone();
        waiting = Some(tokio::spawn(async move { waiting_engine.db().archive_block(&id, None).await }));
        if tokio::time::timeout(Duration::from_millis(50), waiting.as_mut().unwrap()).await.is_ok() {
            waiting.take(); // Already joined by timeout; never poll it twice.
            panic!("second migration bypassed the held admission permit");
        }
        let stopping_engine = engine.clone();
        stopping = Some(tokio::spawn(async move { stopping_engine.wait_stop().await }));
        tokio::time::timeout(Duration::from_secs(30), async {
            while !engine.db().test_archive_admission_closed() {
                tokio::task::yield_now().await;
            }
        }).await.expect("shutdown must close admission even with an active IO owner");
        assert!(waiting.take().unwrap().await.unwrap().unwrap_err().to_string().contains("admission stopped"));
        if let Ok(result) = tokio::time::timeout(Duration::from_millis(50), stopping.as_mut().unwrap()).await {
            stopping.take();
            completed_stop = Some(result);
            panic!("shutdown passed the real admitted migration owner");
        }
        assert!(!handle.is_archived());
        handle
    }).catch_unwind().await;
    // Release before joining anything, including every assertion-failure path.
    release.notify_one();
    let mut child_failures = Vec::new();
    for child in [caller.take(), waiting.take()].into_iter().flatten() {
        child.abort();
        if let Err(error) = child.await {
            if !error.is_cancelled() { child_failures.push(error.to_string()); }
        }
    }
    let stopped = if let Some(result) = completed_stop {
        result.map_err(|error| rtos_block::error!("shutdown owner: {error}"))
            .and_then(|result| result)
    } else if let Some(child) = stopping.take() {
        child.await.map_err(|error| rtos_block::error!("shutdown owner: {error}"))
            .and_then(|result| result)
    } else {
        engine.clone().wait_stop().await
    };
    // A panicked shutdown observation still cannot skip the actual Engine drain.
    let drained = engine.clone().wait_stop().await;
    let weak = Arc::downgrade(&engine);
    drop(engine);
    let handle = run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    stopped.unwrap();
    drained.unwrap();
    assert!(child_failures.is_empty(), "observer failures: {child_failures:?}");
    assert!(weak.upgrade().is_none());
    assert!(handle.is_archived(), "cancelled observer's actual migration must complete");
    drop(handle);
    drop(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_repair_archive_metadata_wal_failure_retains_loose_and_cold_recovers() {
    use storage::archives::package_entry_id::{GetFileName, PackageEntryId};
    let Fixture { dir, engine, target, .. } = fixture(false).await;
    let id = target.id().clone();
    let run = std::panic::AssertUnwindSafe(async {
        let handle = engine.load_block_handle(&id).unwrap().unwrap();
        assert!(!handle.is_archived());
        let proof = engine.load_block_proof(&handle, false).await.unwrap();
        let base = PathBuf::from(engine.db_root_dir().unwrap()).join("archive/unapplied");
        let body_path = base.join(PackageEntryId::Block(&id).filename_short());
        let proof_path = base.join(PackageEntryId::Proof(&id).filename_short());
        let observed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed_worker = observed.clone();
        // Inject EIO at the real WAL boundary; this does not claim an OS syscall
        // returned EIO. The observer cannot fake a successful synchronization.
        engine.db().set_publication_sync_observer(Some(Arc::new(move |point, _| {
            if point == storage::durability::SyncPoint::Wal {
                observed_worker.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                return Err(std::io::Error::from_raw_os_error(5).into());
            }
            Ok(())
        })));
        let error = engine.db().archive_block(&id, None).await.unwrap_err();
        assert!(error.to_string().contains("Failed to move block"));
        assert_eq!(observed.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(handle.is_archived(), "failure occurred after metadata flag/enqueue, at the WAL boundary");
        assert_eq!(std::fs::read(&body_path).unwrap(), target.data());
        assert_eq!(std::fs::read(&proof_path).unwrap(), proof.data());
        engine.db().set_publication_sync_observer(None);
        assert!(engine.db().archive_block(&id, None).await.unwrap_err().to_string().contains("admission stopped"),
            "unknown WAL result must not be hidden by the in-memory archived flag");
        (proof, body_path, proof_path)
    }).catch_unwind().await;
    engine.db().set_publication_sync_observer(None);
    let stopped = engine.clone().wait_stop().await;
    let weak = Arc::downgrade(&engine);
    drop(engine);
    let (proof, body_path, proof_path) = run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    assert!(stopped.is_err(), "actual migration failure must reach Engine shutdown");
    assert!(weak.upgrade().is_none());
    let engine = open_engine(dir.path()).await;
    let run = std::panic::AssertUnwindSafe(async {
        let handle = engine.load_block_handle(&id).unwrap().unwrap();
        assert_eq!(engine.load_block(&handle).await.unwrap().data(), target.data());
        assert_eq!(engine.load_block_proof(&handle, false).await.unwrap().data(), proof.data());
        engine.db().sync_publication_metadata(&handle).await.unwrap();
        assert_eq!(std::fs::read(&body_path).unwrap(), target.data());
        assert_eq!(std::fs::read(&proof_path).unwrap(), proof.data());
    }).catch_unwind().await;
    let stopped = engine.clone().wait_stop().await;
    drop(engine);
    run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    stopped.unwrap();
}


async fn protected_pack_cold_damage_checks(
    directory: &Path, pack: &Path, generation: u64, exact: &RepairLeaseBinding, digest: &UInt256,
) {
    use crate::{config::TonNodeConfig, engine::{EngineFlags, Stopper}};
    use std::collections::BTreeMap;
    // PackageId::full_path is <db>/archive/packages/<group>/<package>.
    let root = pack.ancestors().nth(4).unwrap();
    let snapshot = || {
        let db = open_cells_for_fault_injection(root);
        ["files", "key_files", "repair_dependency_leases_v1", "entry_meta_db_3",
            "block_index_db_3", "offsets_db_3", "status_db_3", "entry_meta_key_db_0",
            "block_index_key_db_0", "offsets_key_db_0", "status_key_db_0"].into_iter().map(|name| {
            let table = db.clone().table::<String>(name, false).unwrap();
            let mut rows = BTreeMap::new();
            table.for_each(&mut |key, bytes| { rows.insert(key.to_vec(), bytes.to_vec()); Ok(true) }).unwrap();
            (name.to_owned(), rows)
        }).collect::<BTreeMap<_, _>>()
    };
    let original = std::fs::read(pack).unwrap();
    assert!(original.len() > 8);
    for mode in ["bad-magic", "short-header", "short-body", "extra-tail", "missing"] {
        let before = snapshot();
        let mut damaged = original.clone();
        match mode {
            "bad-magic" => damaged[0] ^= 0xff,
            "short-header" => damaged.truncate(2),
            "short-body" => { damaged.pop(); },
            "extra-tail" => damaged.extend_from_slice(b"uncommitted-tail"),
            "missing" => (),
            _ => unreachable!(),
        }
        if mode == "missing" { std::fs::remove_file(pack).unwrap(); }
        else { std::fs::write(pack, &damaged).unwrap(); }
        let config = TonNodeConfig::from_file(directory.to_str().unwrap(), "config.json", None, "config.json", None).await.unwrap();
        let stopper = Arc::new(Stopper::new());
        let result = Engine::new(config,
            EngineFlags { initial_sync_disabled: true, force_check_db: false, truncate_db: None },
            stopper.clone()).await;
        let (rejection, unexpected_stop) = match result {
            Ok(engine) => (None, Some(engine.wait_stop().await)),
            Err(error) => (Some(error), None),
        };
        let drained = tokio::time::timeout(Duration::from_secs(20), async {
            while Arc::strong_count(&stopper) != 1 { tokio::task::yield_now().await; }
        }).await;
        let after_file = std::fs::read(pack).ok();
        // Restore exact fixture evidence before assertions, even on regression.
        std::fs::write(pack, &original).unwrap();
        std::fs::File::open(pack).unwrap().sync_all().unwrap();
        std::fs::File::open(pack.parent().unwrap()).unwrap().sync_all().unwrap();
        let after = snapshot();
        if let Some(result) = unexpected_stop { result.unwrap(); }
        drained.expect("failed package startup must drain actual constructor owners");
        let error = rejection.expect("protected pack damage must reject Engine construction");
        let message = format!("{error:#}");
        let expected = match mode {
            "bad-magic" => "Package file header mismatch",
            "missing" => "Protected package open failed",
            _ => "Protected package physical length differs from durable metadata",
        };
        assert!(message.contains(expected), "protected {mode} rejected for unexpected reason: {message}");
        assert_eq!(after_file, if mode == "missing" { None } else { Some(damaged) },
            "protected {mode} must not be rewritten, recreated or deleted");
        assert_eq!(after, before, "protected {mode} must preserve archive indexes and ledger");
        let engine = open_engine(directory).await;
        let verified = std::panic::AssertUnwindSafe(async {
            let cap = reopen_durable_mc_custody(engine.clone(), generation, exact.clone(), digest.clone()).await.unwrap();
            assert_eq!(cap.binding(), exact);
        }).catch_unwind().await;
        let stopped = engine.clone().wait_stop().await;
        drop(engine);
        verified.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        stopped.unwrap();
    }
}


#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn persistent_repair_archive_owner_panic_still_drains_queued_handle() {
    struct HeldQueueCallback {
        id: BlockIdExt,
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
        completed: std::sync::atomic::AtomicBool,
    }
    #[async_trait::async_trait]
    impl storage::block_handle_db::Callback for HeldQueueCallback {
        async fn invoke(&self, job: storage::block_handle_db::StoreJob, ok: bool) {
            assert!(ok, "actual archive handle write failed");
            match job {
                storage::block_handle_db::StoreJob::SaveHandle(handle) => assert_eq!(handle.id(), &self.id),
                _ => panic!("unexpected queue command"),
            }
            self.entered.notify_one();
            self.release.notified().await;
            self.completed.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let Fixture { dir, engine, target, .. } = fixture(false).await;
    let enqueue_entered = Arc::new(tokio::sync::Notify::new());
    let enqueue_release = Arc::new(tokio::sync::Notify::new());
    let callback = Arc::new(HeldQueueCallback {
        id: target.id().clone(), entered: Default::default(), release: Default::default(),
        completed: std::sync::atomic::AtomicBool::new(false),
    });
    engine.db().test_panic_archive_after_handle_enqueue(enqueue_entered.clone(), enqueue_release.clone());
    let owner_engine = engine.clone(); let id = target.id().clone(); let queued_callback = callback.clone();
    let mut caller = Some(tokio::spawn(async move { owner_engine.db().archive_block(&id, Some(queued_callback)).await }));
    let mut stopping = None;
    let run = std::panic::AssertUnwindSafe(async {
        tokio::time::timeout(Duration::from_secs(30), enqueue_entered.notified()).await.expect("archive owner did not enqueue");
        tokio::time::timeout(Duration::from_secs(30), callback.entered.notified()).await.expect("actual handle writer did not enter");
        enqueue_release.notify_one();
        assert!(caller.take().unwrap().await.unwrap().is_err());
        assert!(engine.db().test_join_archive_tasks().await.is_err());
        assert_eq!(engine.db().test_archive_io_outstanding(), 1, "real queued command must outlive failed archive owner");
        let stopping_engine = engine.clone();
        stopping = Some(tokio::spawn(async move { stopping_engine.wait_stop().await }));
        tokio::time::timeout(Duration::from_secs(30), async {
            while !engine.db().test_archive_queue_drain_started() { tokio::task::yield_now().await; }
        }).await.expect("shutdown did not reach actual queue drain");
        assert_eq!(engine.db().test_archive_io_outstanding(), 1);
        assert!(!stopping.as_ref().unwrap().is_finished(), "shutdown passed a held queue owner");
        assert!(!callback.completed.load(std::sync::atomic::Ordering::SeqCst));
    }).catch_unwind().await;
    // Release the actual queue owner even when an assertion failed.
    enqueue_release.notify_one(); callback.release.notify_one();
    if let Some(caller) = caller { let _ = caller.await; }
    let stopped = if let Some(stopping) = stopping { stopping.await.unwrap() } else { engine.clone().wait_stop().await };
    let repeated = engine.clone().wait_stop().await;
    assert_eq!(engine.db().test_archive_io_outstanding(), 0);
    assert!(callback.completed.load(std::sync::atomic::Ordering::SeqCst));
    let weak = Arc::downgrade(&engine); drop(engine);
    run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    assert!(stopped.is_err()); assert!(repeated.is_err()); assert!(weak.upgrade().is_none());
    drop(dir);
}
