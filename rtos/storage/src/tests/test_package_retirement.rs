// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::time::Duration;

#[tokio::test]
async fn actual_idle_close_has_consumable_receipt_and_permanently_retires_old_package() -> Result<()> {
    let (dir, view, operation) = package_fixture_context()?;
    let path = dir.path().join("retire.pack");
    let package = Package::open(view.clone(), &operation, path.clone(), false, true).await?;
    let fd = package.writer_fd_for_io_test().await?;
    let fd_path = PathBuf::from(format!("/proc/self/fd/{fd}"));
    assert_eq!(std::fs::read_link(&fd_path)?, path);
    drop(operation);
    let domain = view.binding().domain();
    let owner = domain.begin_recovery(view.epoch(), &[view.binding().clone()])?;
    owner.wait_for_old_io().await?;
    let receipt = owner.retire_packages()?.await??;
    assert!(std::fs::read_link(fd_path).map_or(true, |target| target != path));
    assert!(package.state.retired.load(Ordering::Acquire));
    assert!(package.lock_writer().await.is_none());
    assert!(owner.spawn_phase(|| Ok(())).is_err(), "unconsumed close receipt must keep the phase busy");
    receipt.consume(|report| {
        assert!(report.identity > 0);
        assert_eq!(report.packages, 1);
        assert_eq!(report.closed_files, 1);
        Ok(())
    })?;
    assert_eq!(package.read_entry(0).await.err().unwrap().downcast_ref::<crate::archives::context::ArchiveContextError>(),
        Some(&crate::archives::context::ArchiveContextError::Retired(0)));
    assert!(package.sync_durable(None).await.unwrap_err().to_string().contains("permanently retired"));
    assert!(package.remove().await.unwrap_err().to_string().contains("permanently retired"));
    owner.spawn_phase(|| Ok(()))?.await??.consume(|_| Ok(()))?;
    assert!(path.exists());
    Ok(())
}

#[test]
fn cancelled_queued_retirement_keeps_actual_writer_open() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().max_blocking_threads(1).build()?;
    runtime.block_on(async {
        let (dir, view, operation) = package_fixture_context()?;
        let package = Package::open(view.clone(), &operation, dir.path().join("queued.pack"), false, true).await?;
        drop(operation);
        let owner = view.binding().domain().begin_recovery(0, &[view.binding().clone()])?;
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            started_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(10))?;
        let job = owner.retire_packages()?;
        drop(owner);
        release_tx.send(())?;
        blocker.await?;
        assert!(job.await?.is_err());
        assert!(!package.state.retired.load(Ordering::Acquire));
        assert!(package.lock_writer().await.as_ref().unwrap().metadata().is_ok());
        assert!(!view.binding().domain().recovery_required());
        Ok(())
    })
}

#[tokio::test]
async fn uncertain_close_result_retains_provider_in_preallocated_quarantine() -> Result<()> {
    let (dir, view, operation) = package_fixture_context()?;
    let path = dir.path().join("uncertain.pack");
    let package = Package::open(view.clone(), &operation, path.clone(), false, true).await?;
    let fd = package.writer_fd_for_io_test().await?;
    let provider = Arc::downgrade(view.binding().db());
    package.state.fail_retirement_close.store(true, Ordering::Release);
    let quarantine = Arc::new(Quarantine::new());
    let native_quarantine = quarantine.clone();
    let state = package.state.clone();
    drop(operation);
    assert!(tokio::task::spawn_blocking(move || state.retire_with(&native_quarantine)).await?.is_err());
    assert!(std::fs::read_link(format!("/proc/self/fd/{fd}")).map_or(true, |target| target != path));
    assert!(quarantine.restart.load(Ordering::Acquire));
    assert_eq!(quarantine.slots.lock().unwrap().iter().filter(|s| s.is_some()).count(), 1);
    assert!(package.lock_writer().await.is_none());
    drop(package); drop(view);
    assert!(provider.upgrade().is_some());
    // This local test quarantine can be dropped only because the injection is
    // after a proven successful close. The production static has no release API.
    drop(quarantine);
    assert!(provider.upgrade().is_none());
    Ok(())
}

#[tokio::test]
async fn quarantine_capacity_refuses_before_taking_another_file() -> Result<()> {
    let (dir, view, operation) = package_fixture_context()?;
    let package = Package::open(view, &operation, dir.path().join("capacity.pack"), false, true).await?;
    let quarantine = Quarantine::new();
    let reservations: Vec<_> = (0..QUARANTINE_CAPACITY)
        .map(|_| quarantine.reserve(&package.state).unwrap()).collect();
    assert!(quarantine.reserve(&package.state).is_err());
    assert!(quarantine.restart.load(Ordering::Acquire));
    assert_eq!(quarantine.slots.lock().unwrap().iter().filter(|s| s.is_some()).count(), QUARANTINE_CAPACITY);
    assert!(package.lock_writer().await.is_some());
    drop(reservations);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_started_retirement_retains_native_file_provider_and_receipt() -> Result<()> {
    let (dir, view, operation) = package_fixture_context()?;
    let path = dir.path().join("started.pack");
    let package = Package::open(view.clone(), &operation, path.clone(), false, true).await?;
    let fd = package.writer_fd_for_io_test().await?;
    let provider = Arc::downgrade(view.binding().db());
    let domain = view.binding().domain().clone();
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    *package.state.retirement_probe.lock().unwrap() = Some(AppendProbe { started: started_tx, release: release_rx });
    drop(operation);
    let owner = domain.begin_recovery(0, &[view.binding().clone()])?;
    let job = owner.retire_packages()?;
    started_rx.recv_timeout(Duration::from_secs(10))?;
    drop(owner); drop(package); drop(view);
    assert!(domain.recovery_required());
    assert!(provider.upgrade().is_some());
    assert_eq!(std::fs::read_link(format!("/proc/self/fd/{fd}"))?, path);
    release_tx.send(())?;
    let receipt = job.await??;
    assert!(std::fs::read_link(format!("/proc/self/fd/{fd}")).map_or(true, |target| target != path));
    assert!(provider.upgrade().is_some(), "actual result must retain provider until receipt destruction");
    drop(receipt);
    assert!(provider.upgrade().is_none());
    Ok(())
}
