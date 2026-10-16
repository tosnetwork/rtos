// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::time::Duration;

#[test]
fn cancelled_queued_append_preserves_bytes_and_can_retry() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).max_blocking_threads(1).enable_all().build()?;
    runtime.block_on(async {
        let (dir, view, operation) = package_fixture_context()?;
        let path = dir.path().join("queued.pack");
        let package = Package::open(view.clone(), &operation, path.clone(), false, true).await?;
        let original = std::fs::read(&path)?;
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            started_tx.send(()).unwrap(); release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(10))?;
        let calls = AtomicU64::new(0);
        let mut append = Box::pin(package.append_entry(PackageEntry::with_data("cancel".into(), vec![1;64]), |_,_| {
            calls.fetch_add(1, Ordering::SeqCst); Ok(())
        }));
        assert!(futures::poll!(&mut append).is_pending());
        assert!(package.state.write_mutex.try_lock().is_err());
        drop(append); release_tx.send(())?; blocker.await?;
        // The queued native owner still holds this exact guard until it checks
        // cancellation and exits. Acquiring it observes actual retirement.
        drop(tokio::time::timeout(Duration::from_secs(10), package.lock_writer()).await?);
        assert_eq!(calls.load(Ordering::SeqCst), 0); assert_eq!(std::fs::read(&path)?, original);
        assert!(package.state.write_healthy.load(Ordering::SeqCst));
        assert!(!view.binding().domain().recovery_required());
        package.append_entry(PackageEntry::with_data("retry".into(), vec![2;64]), |_,_| Ok(())).await?;
        assert!(std::fs::read(path)?.len() > original.len());
        Ok(())
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_started_append_keeps_provider_and_writer_until_native_completion() -> Result<()> {
    let (dir, view, operation) = package_fixture_context()?;
    let path = dir.path().join("running.pack");
    let package = Arc::new(Package::open(view.clone(), &operation, path.clone(), false, true).await?);
    let domain = view.binding().domain().clone(); let epoch = view.epoch();
    let weak_provider = Arc::downgrade(view.binding().db());
    let weak_state = Arc::downgrade(&package.state);
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    *package.state.append_probe.lock().unwrap() = Some(AppendProbe { started: started_tx, release: release_rx });
    let calls = Arc::new(AtomicU64::new(0)); let worker_calls = calls.clone();
    let worker = package.clone();
    let append = tokio::spawn(async move {
        worker.append_entry(PackageEntry::with_data("running".into(), vec![3;1024]), |_,_| {
            worker_calls.fetch_add(1, Ordering::SeqCst); Ok(())
        }).await
    });
    started_rx.recv_timeout(Duration::from_secs(10))?;
    append.abort(); assert!(append.await.err().expect("cancelled append").is_cancelled());
    assert!(domain.recovery_required()); assert!(package.state.write_mutex.try_lock().is_err());
    drop(package); drop(operation); drop(view);
    assert!(weak_provider.upgrade().is_some()); assert!(weak_state.upgrade().is_some());
    let closed = domain.close(epoch)?;
    release_tx.send(())?;
    tokio::time::timeout(Duration::from_secs(10), closed.wait()).await?;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(std::fs::metadata(path)?.len() > PKG_HEADER_SIZE as u64);
    assert!(weak_state.upgrade().is_none()); assert!(weak_provider.upgrade().is_none());
    Ok(())
}

#[tokio::test]
async fn metadata_panic_leaves_native_append_fenced() -> Result<()> {
    let (dir, view, operation) = package_fixture_context()?;
    let package = Arc::new(Package::open(view.clone(), &operation, dir.path().join("panic.pack"), false, true).await?);
    let worker = package.clone();
    assert!(tokio::spawn(async move {
        worker.append_entry(PackageEntry::with_data("panic".into(), vec![1]), |_,_| panic!("metadata panic")).await
    }).await.is_err());
    assert!(!package.state.write_healthy.load(Ordering::SeqCst));
    assert!(view.binding().domain().recovery_required());
    assert!(package.state.write_mutex.try_lock().is_ok());
    Ok(())
}

#[tokio::test]
async fn closed_domain_refuses_mutations_before_waiting_for_writer_lock() -> Result<()> {
    let (dir, view, operation) = package_fixture_context()?;
    let package = Package::open(view.clone(), &operation, dir.path().join("closed.pack"), false, true).await?;
    let _writer = package.lock_writer().await;
    let _closed = view.binding().domain().close(view.epoch())?;
    let mut append = Box::pin(package.append_entry(PackageEntry::with_data("x".into(), vec![1]), |_,_| Ok(())));
    assert!(matches!(futures::poll!(&mut append), std::task::Poll::Ready(Err(_))));
    let mut truncate = Box::pin(package.truncate(0));
    assert!(matches!(futures::poll!(&mut truncate), std::task::Poll::Ready(Err(_))));
    Ok(())
}

#[test]
fn admitted_queued_append_can_finish_after_domain_closes() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).max_blocking_threads(1).enable_all().build()?;
    runtime.block_on(async {
        let (dir, view, operation) = package_fixture_context()?;
        let package = Package::open(view.clone(), &operation, dir.path().join("admitted.pack"), false, true).await?;
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            started_tx.send(()).unwrap(); release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(10))?;
        let mut append = Box::pin(package.append_entry(PackageEntry::with_data("admitted".into(), vec![5]), |_,_| Ok(())));
        assert!(futures::poll!(&mut append).is_pending());
        let closed = view.binding().domain().close(view.epoch())?;
        release_tx.send(())?; blocker.await?;
        let entry = append.await?; assert_eq!(entry.data(), &[5]);
        assert!(!view.binding().domain().recovery_required());
        drop(operation);
        tokio::time::timeout(Duration::from_secs(10), closed.wait()).await?;
        Ok(())
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_append_and_truncate_wait_for_transient_write_health() -> Result<()> {
    for truncate in [false, true] {
        let (dir, view, operation) = package_fixture_context()?;
        let package = Arc::new(Package::open(view.clone(), &operation, dir.path().join("serialized.pack"), false, true).await?);
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        *package.state.append_probe.lock().unwrap() = Some(AppendProbe { started: started_tx, release: release_rx });
        let worker = package.clone();
        let first = tokio::spawn(async move {
            worker.append_entry(PackageEntry::with_data("first".into(), vec![1;32]), |_,_| Ok(())).await
        });
        started_rx.recv_timeout(Duration::from_secs(10))?;
        assert!(!package.state.write_healthy.load(Ordering::SeqCst));
        let mut second = Box::pin(async {
            if truncate { package.truncate(0).await }
            else { package.append_entry(PackageEntry::with_data("second".into(), vec![2;16]), |_,_| Ok(())).await.map(|_| ()) }
        });
        assert!(futures::poll!(&mut second).is_pending(), "normal contention must wait, not fail on transient health");
        release_tx.send(())?;
        let first = first.await??; second.await?;
        assert!(package.state.write_healthy.load(Ordering::SeqCst));
        assert!(!view.binding().domain().recovery_required());
        if truncate { assert_eq!(package.size(), 0); }
        else {
            assert_eq!(package.read_entry(0).await?.data(), first.data());
            assert_eq!(package.read_entry(first.serialized_size()?).await?.filename(), "second");
        }
    }
    Ok(())
}

#[tokio::test]
async fn actual_native_syscall_errors_preserve_bytes_and_fence_domain() -> Result<()> {
    for truncate in [false, true] {
        let (dir, view, operation) = package_fixture_context()?;
        let path = dir.path().join("readonly-fd.pack");
        let package = Package::open(view.clone(), &operation, path.clone(), false, true).await?;
        let original = std::fs::read(&path)?;
        let mut readonly = std::fs::File::open(&path)?;
        std::io::Seek::seek(&mut readonly, SeekFrom::End(0))?;
        *package.lock_writer().await = Some(readonly);
        let result = if truncate { package.truncate(10).await }
        else { package.append_entry(PackageEntry::with_data("refused".into(), vec![1]), |_,_| panic!("failed write reached metadata")).await.map(|_| ()) };
        let error = result.err().expect("read-only native descriptor must refuse mutation");
        assert!(error.downcast_ref::<std::io::Error>().is_some(), "{error:#}");
        assert_eq!(std::fs::read(path)?, original);
        assert!(!package.state.write_healthy.load(Ordering::SeqCst));
        assert!(view.binding().domain().recovery_required());
        assert!(package.state.write_mutex.try_lock().is_ok());
    }
    Ok(())
}

#[test]
fn cancelled_queued_opens_drain_actual_custody_and_preserve_files() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1).max_blocking_threads(1).enable_all().build()?;
    runtime.block_on(async {
        for mode in 0..5 {
            let (dir, view, operation) = package_fixture_context()?;
            let path = dir.path().join("open.pack");
            let original = if mode != 0 {
                let package = Package::open(view.clone(), &operation, path.clone(), false, true).await?;
                drop(package);
                Some(std::fs::read(&path)?)
            } else { None };
            let (started_tx, started_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                started_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            });
            started_rx.recv_timeout(Duration::from_secs(10))?;
            let mut opening = Box::pin(async {
                match mode {
                    0 => Package::open(view.clone(), &operation, path.clone(), false, true).await,
                    1 => Package::open(view.clone(), &operation, path.clone(), false, false).await,
                    2 => Package::open(view.clone(), &operation, path.clone(), true, false).await,
                    _ => Package::open_existing_exact(view.clone(), &operation, path.clone(), mode == 4, 0).await,
                }
            });
            assert!(futures::poll!(&mut opening).is_pending());
            drop(opening);
            let closed = view.binding().domain().close(view.epoch())?;
            drop(operation);
            assert!(view.binding().domain().outstanding() > 0);
            release_tx.send(())?;
            blocker.await?;
            tokio::time::timeout(Duration::from_secs(10), closed.wait()).await?;
            assert!(!view.binding().domain().recovery_required());
            match original {
                Some(bytes) => assert_eq!(std::fs::read(&path)?, bytes),
                None => assert!(!path.exists()),
            }
        }
        Ok(())
    })
}

#[tokio::test]
async fn native_open_preserves_short_file_and_invalid_header_policy() -> Result<()> {
    for create in [false, true] {
        for len in [0, 3, 4] {
            let (dir, view, operation) = package_fixture_context()?;
            let path = dir.path().join("invalid.pack");
            let original = vec![0xff; len];
            std::fs::write(&path, &original)?;
            let result = Package::open(view.clone(), &operation, path.clone(), false, create).await;
            if create && len < PKG_HEADER_SIZE {
                let package = result?;
                assert_eq!(package.size(), 0);
                assert_eq!(std::fs::read(&path)?, PKG_HEADER_MAGIC.to_le_bytes());
                package.append_entry(PackageEntry::with_data("after-header".into(), vec![9]), |_,_| Ok(())).await?;
                assert_eq!(package.read_entry(0).await?.data(), &[9]);
            } else {
                assert!(result.is_err());
                assert_eq!(std::fs::read(&path)?, original);
            }
            assert_eq!(view.binding().domain().recovery_required(), create && len == PKG_HEADER_SIZE);
        }
    }
    // Ordinary readonly opens historically inspect length only. Exact opens
    // additionally validate the magic, but neither path can repair the file.
    for exact in [false, true] {
        let (dir, view, operation) = package_fixture_context()?;
        let path = dir.path().join("readonly.pack");
        let original = [0xff; PKG_HEADER_SIZE];
        std::fs::write(&path, original)?;
        let result = if exact {
            Package::open_existing_exact(view.clone(), &operation, path.clone(), true, 0).await
        } else {
            Package::open(view.clone(), &operation, path.clone(), true, true).await
        };
        assert_eq!(result.is_err(), exact);
        assert_eq!(std::fs::read(&path)?, original);
        assert!(!view.binding().domain().recovery_required());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn started_sync_cancellation_retains_writer_and_observer_until_native_end() -> Result<()> {
    let (dir, view, operation) = package_fixture_context()?;
    let package = Arc::new(Package::open(view.clone(), &operation, dir.path().join("sync.pack"), false, true).await?);
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let release_rx = std::sync::Mutex::new(release_rx);
    let observer: Arc<crate::durability::SyncObserver> = Arc::new(move |point, _| {
        if point == crate::durability::SyncPoint::File {
            started_tx.send(())?;
            release_rx.lock().unwrap().recv_timeout(Duration::from_secs(10))?;
        }
        Ok(())
    });
    let weak_observer = Arc::downgrade(&observer);
    let worker = package.clone();
    let task = tokio::spawn(async move { worker.sync_durable(Some(observer)).await });
    started_rx.recv_timeout(Duration::from_secs(10))?;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(view.binding().domain().recovery_required());
    assert!(weak_observer.upgrade().is_some());
    assert!(package.state.write_mutex.try_lock().is_err());
    let closed = view.binding().domain().close(view.epoch())?;
    drop(operation);
    assert!(view.binding().domain().outstanding() > 0);
    release_tx.send(())?;
    tokio::time::timeout(Duration::from_secs(10), closed.wait()).await?;
    assert!(weak_observer.upgrade().is_none());
    assert!(package.state.write_mutex.try_lock().is_ok());
    Ok(())
}

#[test]
fn cancelled_queued_sync_has_no_effect_and_allows_retry() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1)
        .max_blocking_threads(1).enable_all().build()?;
    runtime.block_on(async {
        let (dir, view, operation) = package_fixture_context()?;
        let package = Package::open(view.clone(), &operation, dir.path().join("queued-sync.pack"), false, true).await?;
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            started_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        });
        started_rx.recv_timeout(Duration::from_secs(10))?;
        let calls = Arc::new(AtomicU64::new(0));
        let observed = calls.clone();
        let mut sync = Box::pin(package.sync_durable(Some(Arc::new(move |_, _| {
            observed.fetch_add(1, Ordering::SeqCst); Ok(())
        }))));
        assert!(futures::poll!(&mut sync).is_pending());
        drop(sync);
        release_tx.send(())?;
        blocker.await?;
        drop(tokio::time::timeout(Duration::from_secs(10), package.lock_writer()).await?);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!view.binding().domain().recovery_required());
        package.sync_durable(None).await?;
        // A failure at the actual synchronization boundary must fence the domain.
        assert!(package.sync_durable(Some(Arc::new(|_, _| Err(anyhow::anyhow!("sync observer failure"))))).await.is_err());
        assert!(view.binding().domain().recovery_required());
        Ok(())
    })
}
