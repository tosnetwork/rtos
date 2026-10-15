// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Real Engine context refusals at local read and authenticated write admission.
use super::*;
use crate::history_read_budget::{HistoryBudgetExceeded, HistoryReadBudget, HistoryReadLimits};
use std::{collections::BTreeMap, sync::atomic::{AtomicUsize, Ordering}};
use storage::archives::{
    bounded_read::ArchiveReadNotStarted,
    context::ArchiveContextError,
    package_entry_id::{GetFileName, PackageEntryId},
};

// Snapshot every archive-root entry, including staging and empty directories.
// RocksDB files elsewhere in the fixture are deliberately outside this inventory.
fn artifact_snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    fn walk(root: &Path, path: &Path, inside: bool, out: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
        let inside = inside || path.file_name().is_some_and(|name| name == "archive");
        if inside { out.insert(path.strip_prefix(root).unwrap().to_owned(), None); }
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let kind = entry.file_type().unwrap();
            assert!(!kind.is_symlink(), "unexpected fixture symlink: {}", path.display());
            if kind.is_dir() {
                walk(root, &path, inside, out);
            } else if inside {
                out.insert(path.strip_prefix(root).unwrap().to_owned(), Some(std::fs::read(path).unwrap()));
            }
        }
    }
    let mut files = BTreeMap::new();
    walk(root, root, false, &mut files);
    files
}

async fn refuse(engine: &Engine, mode: u8) -> ArchiveContextError {
    let view = engine.db().test_archive_view();
    let domain = view.binding().domain().clone();
    let epoch = view.epoch();
    if mode == 1 {
        let parent = view.enter().unwrap();
        drop(parent.child().handoff(()));
        drop(parent);
        assert!(domain.recovery_required());
        ArchiveContextError::RecoveryRequired(epoch)
    } else {
        let closed = domain.close(epoch).unwrap();
        tokio::time::timeout(Duration::from_secs(20), closed.wait()).await.unwrap();
        if mode == 2 {
            domain.test_publish_next_epoch(epoch).unwrap();
            ArchiveContextError::Stale { expected: epoch, current: epoch + 1 }
        } else {
            ArchiveContextError::Closed(epoch)
        }
    }
}

fn assert_refusal(error: &anyhow::Error, expected: &ArchiveContextError) {
    assert_eq!(error.downcast_ref::<ArchiveContextError>(), Some(expected), "{error:#}");
    assert!(!error.is::<ArchiveReadNotStarted>());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn archive_context_real_missing_files_calibrate_fallback_counters() {
    let Fixture { dir, engine, target, request, .. } = fixture(false).await;
    let run = std::panic::AssertUnwindSafe(async {
        let handle = engine.load_block_handle(target.id()).unwrap().unwrap();
        assert!(!handle.is_archived(), "successful repair fixture must have real loose artifacts");
        let root = PathBuf::from(engine.db_root_dir().unwrap()).join("archive/unapplied");
        for entry in [PackageEntryId::Block(target.id()), PackageEntryId::Proof(target.id())] {
            let path = root.join(entry.filename_short());
            assert!(!std::fs::read(&path).unwrap().is_empty());
            std::fs::remove_file(path).unwrap();
        }
        let limits = || HistoryReadBudget::new(HistoryReadLimits {
            cells: 0, cell_bytes: 0, ..Default::default()
        });
        let missing = crate::publication_repair::read_pair(engine.as_ref(), target.id(), &limits())
            .await.err().unwrap();
        assert!(missing.downcast_ref::<ArchiveReadNotStarted>().unwrap().is_not_found());
        engine.db().test_reset_read_refusal_effects();
        let publication = crate::publication_repair::repair_with_budget_for_test(
            engine.clone(), request, limits(),
        ).await.err().unwrap();
        assert_eq!(publication.downcast_ref::<HistoryBudgetExceeded>().map(|e| e.0),
            Some("Merkle workspace"), "{publication:#}");
        assert!(!publication.is::<ArchiveContextError>());
        assert_eq!(engine.db().test_read_refusal_effects(), [1, 0]);
        engine.initialize_full_node_overlays(adnl::DhtSearchPolicy::default()).await.unwrap();
        let budget = limits();
        let history = crate::boot::load_history_proof_with_budget(
            engine.as_ref(), target.id(), false, false, Some(&budget),
        ).await.err().unwrap();
        assert_eq!(history.downcast_ref::<HistoryBudgetExceeded>().map(|e| e.0),
            Some("network graph capacity"), "{history:#}");
        assert!(!history.is::<ArchiveContextError>());
        assert_eq!(budget.local_proof_fallbacks(), 1);
        eprintln!("fallback_calibration publication=1 history=1 publication_error={publication:#} history_error={history:#}");
    }).catch_unwind().await;
    close(engine).await;
    drop(dir);
    run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn archive_context_actual_early_refusal_stops_publication_and_history_effects() {
    refusal_cases(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn archive_context_actual_late_refusal_stops_authenticated_repair_effects() {
    refusal_cases(true).await;
}

async fn refusal_cases(late: bool) {
    for epoch in [false, true] {
        for mode in 0..3 {
            let Fixture { dir, engine, parent, target, request } = fixture_backend(false, epoch).await;
            let mut gate = None;
            let mut task = None;
            let run = std::panic::AssertUnwindSafe(async {
                let syncs = Arc::new(AtomicUsize::new(0));
                let observed = syncs.clone();
                engine.db().set_publication_sync_observer(Some(Arc::new(move |_, _| {
                    observed.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })));
                engine.db().test_reset_read_refusal_effects();
                drop(repair_mc_final(engine.clone(), request.clone()).await.unwrap());
                assert_eq!(engine.db().test_read_refusal_effects(), [0, 1]);
                assert!(syncs.load(Ordering::SeqCst) > 0, "success must calibrate real sync observation");
                engine.db().archive_block(target.id(), None).await.unwrap();
                let handle = engine.load_block_handle(target.id()).unwrap().unwrap();
                assert!(handle.is_archived() && handle.has_data() && handle.has_proof());
                let proof = engine.load_block_proof(&handle, false).await.unwrap();
                assert!(!proof.is_link());
                assert_eq!(engine.load_block(&handle).await.unwrap().data(), target.data());
                let budget = HistoryReadBudget::new(Default::default());
                assert_eq!(crate::boot::load_history_proof_with_budget(
                    engine.as_ref(), target.id(), false, false, Some(&budget),
                ).await.unwrap().data(), proof.data());
                assert_eq!(budget.local_proof_fallbacks(), 0);
                if late {
                    let held = crate::publication_repair::install_test_gate(&engine);
                    gate = Some(held.clone());
                    task = Some(tokio::spawn(repair_mc_final(engine.clone(), request.clone())));
                    tokio::time::timeout(Duration::from_secs(30), held.entered.acquire())
                        .await.unwrap().unwrap().forget();
                }
                // For late refusal these observations start only after authentication.
                let files = artifact_snapshot(dir.path());
                assert!(!files.is_empty());
                let flags = (handle.is_archived(), handle.has_data(), handle.has_proof(),
                    handle.is_applied(), handle.has_state(), handle.has_saved_state());
                let parent_root = engine.load_state(parent.id()).await.unwrap().root_cell().repr_hash().clone();
                let target_root = engine.load_state(target.id()).await.unwrap().root_cell().repr_hash().clone();
                let indexes = (engine.db().has_repair_state_index(parent.id()).unwrap(),
                    engine.db().has_repair_state_index(target.id()).unwrap());
                engine.db().test_reset_read_refusal_effects();
                syncs.store(0, Ordering::SeqCst);
                let expected = refuse(engine.as_ref(), mode).await;
                let publication = if late {
                    gate.as_ref().unwrap().release.add_permits(1);
                    let result = tokio::time::timeout(Duration::from_secs(35), task.as_mut().unwrap())
                        .await.unwrap().unwrap();
                    drop(task.take());
                    result
                } else {
                    repair_mc_final(engine.clone(), request.clone()).await
                };
                let effects = engine.db().test_read_refusal_effects();
                assert_eq!(effects[0], 0,
                    "context refusal entered publication fallback: epoch={epoch} late={late} mode={mode} effects={effects:?}");
                assert_eq!(effects[1], 0,
                    "context refusal crossed authenticated repair admission: epoch={epoch} late={late} mode={mode} effects={effects:?}");
                let publication = publication.err().expect(if late {
                    "late context refusal must fail"
                } else {
                    "early context refusal must fail"
                });
                assert_refusal(&publication, &expected);
                let budget = HistoryReadBudget::new(Default::default());
                let history = crate::boot::load_history_proof_with_budget(
                    engine.as_ref(), target.id(), false, false, Some(&budget),
                ).await;
                assert_eq!(budget.local_proof_fallbacks(), 0,
                    "context refusal entered boot history fallback: epoch={epoch} late={late} mode={mode}");
                let history = history.err().unwrap();
                assert_refusal(&history, &expected);
                // Existing fullproof is present and exact: initial store is a no-op.
                let proof_sync = engine.db().sync_repair_history_proof(
                    &proof, &HistoryReadBudget::new(Default::default()),
                ).await.err().unwrap();
                assert_refusal(&proof_sync, &expected);
                assert_eq!(engine.db().test_read_refusal_effects(), [0, 0]);
                assert_eq!(syncs.load(Ordering::SeqCst), 0);
                assert_eq!(artifact_snapshot(dir.path()), files);
                assert_eq!((handle.is_archived(), handle.has_data(), handle.has_proof(),
                    handle.is_applied(), handle.has_state(), handle.has_saved_state()), flags);
                assert_eq!(engine.load_state(parent.id()).await.unwrap().root_cell().repr_hash(), &parent_root);
                assert_eq!(engine.load_state(target.id()).await.unwrap().root_cell().repr_hash(), &target_root);
                assert_eq!((engine.db().has_repair_state_index(parent.id()).unwrap(),
                    engine.db().has_repair_state_index(target.id()).unwrap()), indexes);
                eprintln!("context_refusal epoch={epoch} late={late} mode={mode} typed={expected:?} publication_fallback=0 history_fallback=0 after_admission=0 syncs=0 artifacts_unchanged=true state_unchanged=true");
            }).catch_unwind().await;
            if let Some(gate) = gate { gate.release.add_permits(1); }
            if let Some(task) = task { let _ = task.await; }
            engine.db().set_publication_sync_observer(None);
            // A pre-gate error leaves a registry entry; remove only after the
            // actual Engine-owned worker has terminated, not just its observer.
            let stopped = engine.clone().wait_stop().await;
            crate::publication_repair::remove_test_gate(&engine);
            let weak = Arc::downgrade(&engine);
            drop(engine);
            let released = weak.upgrade().is_none();
            drop(dir);
            stopped.unwrap();
            assert!(released, "refusal fixture must release actual Engine owners");
            eprintln!("context_refusal_cleanup epoch={epoch} late={late} mode={mode} stopped=true engine_released=true fixture_released=true");
            run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        }
    }
}
