/*
 * RTOS project modifications (2026-10-10): naming and deterministic waiter registration in tests.
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use super::*;
use crate::collator_test_bundle::create_engine_allocated;
#[cfg(feature = "telemetry")]
use crate::collator_test_bundle::create_engine_telemetry;
use rtos_block::fail;
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

async fn op(number: Arc<AtomicU32>) -> Result<u32> {
    futures_timer::Delay::new(Duration::from_millis(1000)).await;
    number.fetch_add(1, Ordering::SeqCst);
    Ok(number.load(Ordering::SeqCst))
}

const TASKS: u32 = 50;
const OPS: u32 = 10;

#[tokio::test(flavor = "multi_thread")]
async fn test_awaiters_pool() {
    let pool = Arc::new(AwaitersPool::new(
        "",
        #[cfg(feature = "telemetry")]
        create_engine_telemetry(),
        create_engine_allocated(),
    ));
    let mut ns = vec![];
    let mut sums = vec![];
    let mut handles = vec![];

    for id in 0..OPS {
        let n = Arc::new(AtomicU32::new(id));
        let sum = Arc::new(AtomicU32::new(0));
        ns.push(n.clone());
        sums.push(sum.clone());

        for i in 0..TASKS {
            let n = n.clone();
            let pool = pool.clone();
            let sum = sum.clone();
            handles.push(tokio::spawn(async move {
                futures_timer::Delay::new(Duration::from_millis((i % 5) as u64)).await;

                if n.load(Ordering::SeqCst) != id + 1 {
                    if i % 2 == 0 {
                        if let Some(nn) = pool.do_or_wait(&id, None, op(n.clone())).await.unwrap() {
                            assert_eq!(nn, id + 1);
                        } else {
                            assert_eq!(n.load(Ordering::SeqCst), id + 1);
                        }
                    } else if let Some(nn) = pool.wait(&id, None, || Ok(false)).await.unwrap() {
                        assert_eq!(nn, id + 1);
                    } else {
                        assert_eq!(n.load(Ordering::SeqCst), id + 1);
                    }
                }
                sum.fetch_add(1, Ordering::SeqCst);
            }));
        }
    }
    futures::future::join_all(handles).await;

    for i in 0..OPS {
        assert_eq!(ns[i as usize].load(Ordering::SeqCst), i + 1);
        assert_eq!(sums[i as usize].load(Ordering::SeqCst), TASKS);
    }
}

async fn op_fail() -> Result<u32> {
    //futures_timer::Delay::new(Duration::from_millis(1)).await;
    fail!("test_awaiters_pool_fail!")
}

#[tokio::test(flavor = "multi_thread")]
async fn test_awaiters_pool_fail() {
    let pool = Arc::new(AwaitersPool::new(
        "",
        #[cfg(feature = "telemetry")]
        create_engine_telemetry(),
        create_engine_allocated(),
    ));
    let mut handles = vec![];

    for _ in 0..10000 {
        let pool = pool.clone();
        handles.push(tokio::spawn(async move {
            for id in 1..10 {
                loop {
                    match pool.do_or_wait(&id, None, op_fail()).await {
                        Ok(None) => println!("Ok(None)"),
                        Ok(Some(_)) => panic!("Ok(Some)"),
                        Err(e) => {
                            assert_eq!(
                                e.to_string().get(..24).unwrap(),
                                "test_awaiters_pool_fail!"
                            );
                            break;
                        }
                    }
                }
            }
        }));
    }

    futures::future::join_all(handles)
        .await
        .into_iter()
        .find(|r| r.is_err())
        .unwrap_or(Ok(()))
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_completion_does_not_orphan_an_existing_waiter() {
    let pool = Arc::new(AwaitersPool::<u32, u32>::new(
        "external completion",
        #[cfg(feature = "telemetry")]
        create_engine_telemetry(),
        create_engine_allocated(),
    ));
    let complete = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (registered_tx, mut registered_rx) = tokio::sync::mpsc::unbounded_channel();
    let waiter_pool = pool.clone();
    let waiter_complete = complete.clone();
    let mut waiter = tokio::spawn(async move {
        waiter_pool
            .wait(&1, None, || {
                let done = waiter_complete.load(std::sync::atomic::Ordering::SeqCst);
                registered_tx.send(()).unwrap();
                Ok(done)
            })
            .await
    });
    let watchdog = Duration::from_secs(2);
    tokio::time::timeout(watchdog, registered_rx.recv()).await.unwrap().unwrap();
    // A second reader sees the newly stored state before the storing task
    // publishes its result. It must not detach the already registered reader.
    complete.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(pool.wait(&1, None, || Ok(true)).await.unwrap(), None);
    assert_eq!(pool.do_or_wait(&1, None, async { Ok(7) }).await.unwrap(), Some(7));
    let observed = tokio::time::timeout(watchdog, &mut waiter).await;
    if observed.is_err() {
        waiter.abort();
        let _ = waiter.await;
    }
    assert!(observed.is_ok(), "external completion orphaned a registered state waiter");
    assert!(matches!(observed.unwrap().unwrap().unwrap(), None | Some(7)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_completion_preserves_the_active_operation_owner() {
    let pool = Arc::new(AwaitersPool::<u32, u32>::new(
        "external completion with owner",
        #[cfg(feature = "telemetry")]
        create_engine_telemetry(),
        create_engine_allocated(),
    ));
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let owner_pool = pool.clone();
    let owner = tokio::spawn(async move {
        owner_pool
            .do_or_wait(&1, None, async move {
                started_tx.send(()).unwrap();
                release_rx.await.unwrap();
                Ok(7)
            })
            .await
    });
    let watchdog = Duration::from_secs(2);
    tokio::time::timeout(watchdog, started_rx).await.unwrap().unwrap();
    assert_eq!(pool.wait(&1, None, || Ok(true)).await.unwrap(), None);
    // The external predicate may become true before the owner finishes its
    // remaining writes. A new caller must still subscribe to that owner.
    let follower_pool = pool.clone();
    let follower = async move {
        follower_pool.do_or_wait(&1, None, async { panic!("duplicate operation owner") }).await
    };
    tokio::pin!(follower);
    tokio::select! {
        result = &mut follower => panic!("follower finished before owner: {result:?}"),
        _ = tokio::time::sleep(Duration::from_millis(10)) => {},
    }
    release_tx.send(()).unwrap();
    assert_eq!(tokio::time::timeout(watchdog, owner).await.unwrap().unwrap().unwrap(), Some(7));
    assert_eq!(tokio::time::timeout(watchdog, follower).await.unwrap().unwrap(), Some(7));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_awaiters_pool_timeout() {
    let pool = Arc::new(AwaitersPool::new(
        "",
        #[cfg(feature = "telemetry")]
        create_engine_telemetry(),
        create_engine_allocated(),
    ));
    // Keep the operation pending until both waiters have observed this exact
    // registration. Wall-clock sleeps cannot establish that ordering: a late
    // waiter would otherwise create a new entry after the result was removed.
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let operation_pool = pool.clone();
    let operation = tokio::spawn(async move {
        operation_pool
            .do_or_wait(&1_u32, None, async move {
                started_tx.send(()).unwrap();
                release_rx.await.unwrap();
                Ok(())
            })
            .await
    });
    let watchdog = Duration::from_secs(30);
    tokio::time::timeout(watchdog, started_rx).await.unwrap().unwrap();

    let (registered_tx, mut registered_rx) = tokio::sync::mpsc::unbounded_channel();
    let waiter_pool = pool.clone();
    let waiter = tokio::spawn(async move {
        waiter_pool
            .wait(&1_u32, None, || {
                // This callback runs after wait_operation subscribes to the
                // result. Completion remains false while the gate is held.
                registered_tx.send(()).unwrap();
                Ok(false)
            })
            .await
    });
    tokio::time::timeout(watchdog, registered_rx.recv()).await.unwrap().unwrap();
    let error = tokio::time::timeout(watchdog, pool.wait(&1_u32, Some(1), || Ok(false)))
        .await
        .unwrap()
        .unwrap_err();
    assert!(error.to_string().contains("timeout"), "{error}");
    assert!(!operation.is_finished(), "one waiter's timeout must not cancel the operation");
    assert!(!waiter.is_finished(), "another waiter must remain subscribed");

    release_tx.send(()).unwrap();
    assert_eq!(
        tokio::time::timeout(watchdog, operation).await.unwrap().unwrap().unwrap(),
        Some(())
    );
    assert_eq!(tokio::time::timeout(watchdog, waiter).await.unwrap().unwrap().unwrap(), Some(()));
}

const WAIT_2_TASKS: usize = 100;

#[tokio::test(flavor = "multi_thread")]
async fn test_awaiters_pool_wait_2() {
    let mut handles = Vec::with_capacity(WAIT_2_TASKS * 2);
    let pool = Arc::new(AwaitersPool::new(
        "test_awaiters_pool_wait_2",
        #[cfg(feature = "telemetry")]
        create_engine_telemetry(),
        create_engine_allocated(),
    ));
    let err = Arc::new(AtomicU32::new(0));
    let ok = Arc::new(AtomicU32::new(0));
    let already_done = Arc::new(AtomicU32::new(0));

    for id in 0..WAIT_2_TASKS {
        let done = Arc::new(AtomicBool::new(false));

        {
            let pool = pool.clone();
            let done = done.clone();
            handles.push(tokio::spawn(async move {
                futures_timer::Delay::new(Duration::from_millis(1)).await;
                pool.do_or_wait(&id, None, async move {
                    futures_timer::Delay::new(Duration::from_millis(1)).await;
                    done.store(true, Ordering::Relaxed);
                    Ok(())
                })
                .await
                .unwrap()
                .unwrap();
            }));
        }

        for _ in 0..WAIT_2_TASKS {
            let err = err.clone();
            let ok = ok.clone();
            let done = done.clone();
            let already_done = already_done.clone();
            let pool = pool.clone();
            handles.push(tokio::spawn(async move {
                loop {
                    if !done.load(Ordering::Relaxed) {
                        futures_timer::Delay::new(Duration::from_millis(1)).await;
                        match pool.wait(&id, Some(1000), || Ok(done.load(Ordering::Relaxed))).await
                        {
                            Ok(None) => continue,
                            Ok(Some(_)) => break,
                            Err(_) => {
                                err.fetch_add(1, Ordering::Relaxed);
                                return;
                            }
                        }
                    } else {
                        already_done.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                }
                ok.fetch_add(1, Ordering::Relaxed);
            }));
        }
    }

    futures::future::join_all(handles).await;

    let ok = ok.load(Ordering::Relaxed);
    let err = err.load(Ordering::Relaxed);

    print!("ok {}  err {}  already_done {}", ok, err, already_done.load(Ordering::Relaxed));

    assert!(ok + err == (WAIT_2_TASKS * WAIT_2_TASKS) as u32);
    assert!(err == 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_awaiters_pool_shunt() {
    let mut handles = Vec::new();

    let pool = Arc::new(AwaitersPool::new(
        "test_awaiters_pool_shunt",
        #[cfg(feature = "telemetry")]
        create_engine_telemetry(),
        create_engine_allocated(),
    ));

    handles.push(tokio::spawn({
        let pool = pool.clone();
        async move {
            let r = pool.wait(&1, None, || Ok(false)).await.unwrap();
            assert_eq!(r, Some("shunt"));
        }
    }));

    handles.push(tokio::spawn({
        let pool = pool.clone();
        async move {
            let r = pool
                .do_or_wait(&1, None, async move {
                    futures_timer::Delay::new(Duration::from_millis(5_000)).await;
                    Ok("done")
                })
                .await
                .unwrap();
            assert_eq!(r, Some("shunt"))
        }
    }));

    futures_timer::Delay::new(Duration::from_millis(5)).await;

    handles.push(tokio::spawn({
        let pool = pool.clone();
        async move {
            pool.shunt(&1, || Ok("shunt")).unwrap();
        }
    }));

    for r in futures::future::join_all(handles).await {
        if let Err(e) = r {
            panic!("Error: {:?}", e);
        }
    }
}

#[tokio::test]
async fn test_awaiters_pool_cancelled_owner_releases_waiters_and_allows_retry() {
    let pool = Arc::new(AwaitersPool::new(
        "cancelled-owner",
        #[cfg(feature = "telemetry")]
        create_engine_telemetry(),
        create_engine_allocated(),
    ));
    let (entered, ready) = tokio::sync::oneshot::channel();
    let owner_pool = pool.clone();
    let owner = tokio::spawn(async move {
        owner_pool
            .do_or_wait(&42_u32, None, async move {
                entered.send(()).unwrap();
                std::future::pending::<Result<u32>>().await
            })
            .await
    });
    ready.await.unwrap();
    let (subscribed, registered) = tokio::sync::oneshot::channel();
    let subscribed = std::sync::Mutex::new(Some(subscribed));
    let waiter_pool = pool.clone();
    let waiter = tokio::spawn(async move {
        waiter_pool
            .wait(&42, None, || {
                if let Some(tx) = subscribed.lock().unwrap().take() {
                    tx.send(()).unwrap();
                }
                Ok(false)
            })
            .await
    });
    registered.await.unwrap();
    owner.abort();
    assert!(owner.await.unwrap_err().is_cancelled());
    let cancelled = tokio::time::timeout(Duration::from_secs(2), waiter)
        .await
        .expect("cancelled owner must notify its existing waiters")
        .unwrap()
        .unwrap_err();
    assert!(cancelled.to_string().contains("operation cancelled"), "{cancelled}");
    let result =
        tokio::time::timeout(Duration::from_secs(2), pool.do_or_wait(&42, None, async { Ok(7) }))
            .await
            .expect("retry must acquire a fresh owner")
            .unwrap();
    assert_eq!(result, Some(7));
    assert!(pool.ops_awaiters.get(&42).is_none());
}

#[tokio::test]
async fn test_awaiters_pool_stale_completion_keeps_replacement_owner() {
    let pool = AwaitersPool::<u32, u32>::new(
        "stale-owner",
        #[cfg(feature = "telemetry")]
        create_engine_telemetry(),
        create_engine_allocated(),
    );
    let old = OperationAwaiters::new(
        true,
        #[cfg(feature = "telemetry")]
        &pool.telemetry,
        &pool.allocated,
    );
    pool.ops_awaiters.insert(42, old.clone());
    pool.finalize(&42, &old, Ok(1));
    let replacement = OperationAwaiters::new(
        true,
        #[cfg(feature = "telemetry")]
        &pool.telemetry,
        &pool.allocated,
    );
    pool.ops_awaiters.insert(42, replacement.clone());
    // A cancelled old owner can finish after a shunt and same-key replacement.
    pool.finalize(&42, &old, Err(error!("late cancellation")));
    let current = pool.ops_awaiters.get(&42).expect("old completion removed replacement");
    assert!(Arc::ptr_eq(&current.1, &replacement));
    assert_eq!(*old.rx.borrow().as_ref().unwrap().as_ref().unwrap(), 1);
    assert!(replacement.rx.borrow().is_none());
    pool.finalize(&42, &replacement, Ok(2));
    assert!(pool.ops_awaiters.get(&42).is_none());
}

#[tokio::test]
async fn test_awaiters_pool_owner_observes_first_published_result() {
    let pool = AwaitersPool::<u32, u32>::new(
        "first-result",
        #[cfg(feature = "telemetry")]
        create_engine_telemetry(),
        create_engine_allocated(),
    );
    for operation_fails in [false, true] {
        let result = pool
            .do_or_wait(&42, None, async {
                // Publish while the operation is being polled, so select must take
                // the operation's Ready branch after the shunt has already won.
                pool.shunt(&42, || Ok(1))?;
                if operation_fails {
                    Err(error!("later operation failure"))
                } else {
                    Ok(2)
                }
            })
            .await
            .unwrap();
        assert_eq!(result, Some(1), "owner must agree with its already notified waiters");
        assert!(pool.ops_awaiters.get(&42).is_none());
    }
}
