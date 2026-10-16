// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::db::rocksdb::AccessType;
use std::time::Duration;

fn fixture() -> (tempfile::TempDir, Arc<RocksDb>, Arc<ArchiveDomain>, ArchiveProvider) {
    let dir = tempfile::tempdir().unwrap();
    let db = RocksDb::new(dir.path(), "db", None, AccessType::ReadWrite).unwrap();
    let domain = ArchiveDomain::new();
    let provider = db.bind_archive_domain(domain.clone()).unwrap();
    (dir, db, domain, provider)
}
#[tokio::test]
async fn claim_is_exclusive_and_drain_holds_no_old_ticket() -> Result<()> {
    let (_dir, _db, domain, provider) = fixture();
    let view = provider.view()?;
    let parent = view.enter()?;
    let child = parent.inherit(&provider)?;
    let owner = domain.begin_recovery(view.epoch(), &[provider.clone()])?;
    assert!(view.enter().is_err());
    assert_eq!(domain.outstanding(), 2);
    assert!(domain.begin_recovery(view.epoch(), &[provider.clone()]).is_err());
    assert!(owner.spawn_phase(|| Ok(())).is_err());
    let mut wait = Box::pin(owner.wait_for_old_io());
    assert!(futures::poll!(&mut wait).is_pending()); drop(wait);
    drop(parent); assert_eq!(domain.outstanding(), 1); drop(child);
    owner.wait_for_old_io().await?;
    assert!(domain.test_publish_next_epoch(view.epoch()).is_err());
    drop(owner);
    assert!(!domain.recovery_required()); assert!(view.enter().is_err());
    drop(domain.begin_recovery(view.epoch(), &[provider])?);
    Ok(())
}
#[test]
fn invalid_provider_sets_do_not_close_admission() -> Result<()> {
    let (_dir, _db, domain, provider) = fixture();
    let (_other_dir, _other_db, _other_domain, other) = fixture();
    assert!(domain.begin_recovery(0, &[]).is_err());
    assert!(domain.begin_recovery(0, &[provider.clone(), provider.clone()]).is_err());
    assert!(domain.begin_recovery(0, &[other]).is_err());
    assert!(domain.begin_recovery(1, &[provider.clone()]).is_err());
    drop(provider.view()?.enter()?);
    Ok(())
}
#[tokio::test]
async fn consuming_phase_keeps_operation_claim_and_effect_history() -> Result<()> {
    let (dir, db, domain, provider) = fixture();
    let owner = domain.begin_recovery(0, &[provider.clone()])?;
    owner.wait_for_old_io().await?;
    let path = dir.path().join("owned-work"); let work_path = path.clone();
    let receipt = owner.spawn_phase(move || {
        std::fs::write(&work_path, b"phase one")?;
        let file = std::fs::File::open(work_path)?; file.sync_all()?;
        Ok(())
    })?.await??;
    assert!(owner.spawn_phase(|| Ok(())).is_err());
    receipt.consume(|_| Ok(()))?;
    assert!(domain.begin_recovery(0, &[provider]).is_err());
    assert!(!domain.recovery_required());
    let work_db = db.clone();
    owner.spawn_phase(move || { work_db.db().put(b"phase", b"two")?; work_db.sync_wal()?; Ok(()) })?.await??.consume(|_| Ok(()))?;
    assert_eq!(std::fs::read(path)?, b"phase one");
    assert_eq!(db.db().get(b"phase")?.as_deref(), Some(b"two".as_slice()));
    // Phase acknowledgements are not a full recovery completion receipt.
    drop(owner); assert!(domain.recovery_required());
    Ok(())
}
#[tokio::test]
async fn failed_unconsumed_and_panicking_phases_latch_immediately() -> Result<()> {
    for case in 0..5 {
        let (_dir, _db, domain, provider) = fixture();
        let owner = domain.begin_recovery(0, &[provider])?;
        match case {
            0 => { assert!(owner.spawn_phase(|| -> Result<()> { anyhow::bail!("native phase failure") })?.await?.is_err()); },
            1 => { drop(owner.spawn_phase(|| Ok(()))?.await??); },
            2 => { assert!(owner.spawn_phase(|| Ok(()))?.await??.consume(|_| anyhow::bail!("metadata phase failure")).is_err()); },
            3 => { assert!(owner.spawn_phase(|| -> Result<()> { panic!("native phase panic") })?.await.is_err()); },
            _ => {
                let receipt = owner.spawn_phase(|| Ok(()))?.await??;
                domain.latch_failure();
                assert!(receipt.consume(|_| panic!("failed domain must not start metadata phase")).is_err());
            },
        }
        assert!(domain.recovery_required());
        assert!(owner.spawn_phase(|| Ok(())).is_err());
    }
    Ok(())
}
#[test]
fn queued_owner_cancellation_prevents_effects_with_or_without_handle_abort() -> Result<()> {
    for abort_handle in [false, true] {
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).max_blocking_threads(1).enable_all().build()?;
        let (dir, _db, domain, provider) = fixture();
        runtime.block_on(async {
            let (started_tx, started_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                started_tx.send(()).unwrap(); release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            });
            started_rx.recv_timeout(Duration::from_secs(10))?;
            let owner = domain.begin_recovery(0, &[provider.clone()])?;
            let ran = Arc::new(AtomicBool::new(false)); let work_ran = ran.clone();
            let output = dir.path().join("cancelled-before-first-write"); let work_output = output.clone();
            let queued = owner.spawn_phase(move || {
                std::fs::write(work_output, b"must never be written")?;
                work_ran.store(true, Ordering::Release); Ok(())
            })?;
            if abort_handle { queued.abort(); }
            drop(owner);
            assert!(domain.begin_recovery(0, &[provider.clone()]).is_err());
            assert!(!domain.recovery_required());
            release_tx.send(())?; blocker.await?;
            if abort_handle {
                assert!(queued.await.err().expect("cancelled queued phase").is_cancelled());
            } else {
                let error = queued.await?.err().expect("cancelled owner must prevent native work");
                assert_eq!(error.downcast_ref::<ArchiveContextError>(), Some(&ArchiveContextError::RecoveryCancelled));
            }
            assert!(!ran.load(Ordering::Acquire)); assert!(!output.exists());
            assert!(!domain.recovery_required());
            drop(domain.begin_recovery(0, &[provider])?);
            Ok::<_, anyhow::Error>(())
        })?;
    }
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_running_observer_preserves_provider_until_job_and_receipt_drop() -> Result<()> {
    let (_dir, db, domain, provider) = fixture();
    let weak = Arc::downgrade(&db);
    let owner = domain.begin_recovery(0, &[provider.clone()])?;
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    struct Completion(Option<tokio::sync::oneshot::Sender<()>>);
    impl Drop for Completion { fn drop(&mut self) { if let Some(tx) = self.0.take() { let _ = tx.send(()); } } }
    let task = owner.spawn_phase(move || {
        let _ = started_tx.send(());
        release_rx.recv_timeout(Duration::from_secs(10))?;
        Ok(Completion(Some(done_tx)))
    })?;
    started_rx.await?; task.abort(); drop(task); drop(owner); drop(provider); drop(db);
    assert!(weak.upgrade().is_some());
    assert!(domain.recovery_required(), "owner cancellation after native start latches immediately");
    assert!(domain.state.lock().unwrap().recovery_claimed);
    release_tx.send(())?; done_rx.await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        while domain.state.lock().unwrap().recovery_claimed { tokio::task::yield_now().await; }
    }).await?;
    assert!(domain.recovery_required()); assert!(weak.upgrade().is_none());
    Ok(())
}

#[test]
fn competing_claims_retain_every_native_participant_until_last_owner() -> Result<()> {
    let (_dir, main, domain, main_provider) = fixture();
    let epoch_dir = tempfile::tempdir()?;
    let epoch = RocksDb::new(epoch_dir.path(), "archive_db", None, AccessType::ReadWrite)?;
    let epoch_provider = epoch.bind_archive_domain(domain.clone())?;
    let weak_main = Arc::downgrade(&main); let weak_epoch = Arc::downgrade(&epoch);
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let workers: Vec<_> = (0..2).map(|_| {
        let domain = domain.clone(); let barrier = barrier.clone();
        let providers = [main_provider.clone(), epoch_provider.clone()];
        std::thread::spawn(move || { barrier.wait(); domain.begin_recovery(0, &providers) })
    }).collect();
    barrier.wait();
    let results: Vec<_> = workers.into_iter().map(|worker| worker.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    drop(main_provider); drop(epoch_provider); drop(main); drop(epoch);
    assert!(weak_main.upgrade().is_some()); assert!(weak_epoch.upgrade().is_some());
    drop(results);
    assert!(weak_main.upgrade().is_none()); assert!(weak_epoch.upgrade().is_none());
    assert!(!domain.recovery_required());
    assert!(!domain.state.lock().unwrap().recovery_claimed);
    Ok(())
}

#[tokio::test]
async fn idle_package_registry_is_weak_and_carries_no_io_ticket() -> Result<()> {
    use crate::archives::package::Package;
    let (dir, _db, domain, provider) = fixture();
    let view = provider.view()?;
    let operation = view.enter()?;
    let package = Package::open(view.clone(), &operation, dir.path().join("idle.pack"), false, true).await?;
    drop(operation);
    assert_eq!(domain.outstanding(), 0);
    let owner = domain.begin_recovery(view.epoch(), &[provider])?;
    owner.wait_for_old_io().await?;
    let snapshot = owner.snapshot_packages()?;
    assert_eq!(snapshot.len(), 1);
    let weak = Arc::downgrade(&snapshot[0]);
    drop(snapshot);
    assert!(weak.upgrade().is_some());
    drop(package);
    assert!(weak.upgrade().is_none(), "weak registry must not keep idle files alive");
    assert!(owner.snapshot_packages()?.is_empty());
    assert_eq!(domain.lock()?.packages.len(), 0);
    Ok(())
}

#[test]
fn retirement_snapshot_includes_constructor_that_finishes_while_closing() -> Result<()> {
    use crate::archives::package::Package;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all()
        .max_blocking_threads(1).build()?;
    runtime.block_on(async {
        let (dir, _db, domain, provider) = fixture();
        let view = provider.view()?;
        let operation = view.enter()?;
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            started_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(10))?;
        let path = dir.path().join("late.pack");
        let mut opening = Box::pin(Package::open(view.clone(), &operation, path.clone(), false, true));
        assert!(futures::poll!(&mut opening).is_pending());
        let owner = domain.begin_recovery(view.epoch(), &[provider])?;
        assert_eq!(owner.snapshot_packages().err().unwrap().downcast_ref::<ArchiveContextError>(),
            Some(&ArchiveContextError::NotDrained));
        assert!(domain.lock()?.packages.is_empty());
        release_tx.send(())?;
        blocker.await?;
        let package = opening.await?;
        drop(operation);
        owner.wait_for_old_io().await?;
        let snapshot = owner.snapshot_packages()?;
        assert_eq!(snapshot.len(), 1);
        assert_eq!(std::fs::metadata(&path)?.len(), 4);
        assert_eq!(domain.outstanding(), 0);
        drop(snapshot); drop(package);
        assert!(!domain.recovery_required());
        Ok(())
    })
}

#[tokio::test]
async fn retirement_snapshot_refuses_missing_live_package_provider() -> Result<()> {
    use crate::archives::package::Package;
    let (dir, _db, domain, provider) = fixture();
    let epoch_db = RocksDb::new(dir.path(), "epoch", None, AccessType::ReadWrite)?;
    let epoch_provider = epoch_db.bind_archive_domain(domain.clone())?;
    let view = epoch_provider.view()?;
    let operation = view.enter()?;
    let _package = Package::open(view.clone(), &operation, dir.path().join("epoch.pack"), false, true).await?;
    drop(operation);
    let incomplete = domain.begin_recovery(0, &[provider.clone()])?;
    incomplete.wait_for_old_io().await?;
    let error = incomplete.snapshot_packages().err().unwrap();
    assert_eq!(error.downcast_ref::<ArchiveContextError>(), Some(&ArchiveContextError::InvalidRecoveryProviders));
    drop(incomplete);
    let complete = domain.begin_recovery(0, &[provider, epoch_provider])?;
    assert_eq!(complete.snapshot_packages()?.len(), 1);
    assert!(!domain.recovery_required());
    Ok(())
}

#[tokio::test]
async fn recovery_mutation_gate_requires_its_own_successfully_consumed_close_receipt() -> Result<()> {
    let (dir, _db, domain, provider) = fixture();
    let owner = domain.begin_recovery(0, &[provider])?;
    let output = dir.path().join("recovery-effect");
    let work_output = output.clone();
    let error = owner.spawn_recovery_phase(move || {
        std::fs::write(work_output, b"must not run before retirement")?; Ok(())
    }).err().unwrap();
    assert_eq!(error.downcast_ref::<ArchiveContextError>(), Some(&ArchiveContextError::RetirementRequired));
    assert!(!output.exists());
    let receipt = owner.retire_packages()?.await??;
    assert!(owner.spawn_recovery_phase(|| Ok(())).is_err());
    receipt.consume(|_| {
        assert!(owner.spawn_recovery_phase(|| Ok(())).is_err(), "callback is still inside retirement consumption");
        Ok(())
    })?;
    let work_output = output.clone();
    owner.spawn_recovery_phase(move || {
        std::fs::write(work_output, b"after retirement")?; Ok(())
    })?.await??.consume(|_| Ok(()))?;
    assert_eq!(std::fs::read(output)?, b"after retirement");
    // Even another fully drained domain cannot use this execution's receipt.
    let (_other_dir, _other_db, other_domain, other_provider) = fixture();
    let other = other_domain.begin_recovery(0, &[other_provider])?;
    assert!(other.spawn_recovery_phase(|| Ok(())).is_err());
    Ok(())
}

#[tokio::test]
async fn retirement_callback_failure_or_domain_failure_never_opens_mutation_gate() -> Result<()> {
    for latch_in_callback in [false, true] {
        let (_dir, _db, domain, provider) = fixture();
        let owner = domain.begin_recovery(0, &[provider])?;
        let receipt = owner.retire_packages()?.await??;
        let result = receipt.consume(|_| {
            if latch_in_callback { domain.latch_failure(); Ok(()) }
            else { Err(anyhow::anyhow!("retirement registration refused")) }
        });
        assert!(result.is_err());
        assert!(!owner.state.packages_retired.load(Ordering::Acquire));
        assert!(domain.recovery_required());
        assert!(owner.spawn_recovery_phase(|| -> Result<()> { panic!("must not run") }).is_err());
    }
    Ok(())
}
