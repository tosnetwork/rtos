// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Exercise the production download policy dispatch with controlled workers.
use super::*;
use crate::collator_test_bundle::create_engine_allocated;
#[cfg(feature = "telemetry")]
use crate::collator_test_bundle::create_engine_telemetry;
use std::sync::atomic::{AtomicUsize, Ordering};

fn pool() -> AwaitersPool<BlockDownloadKey, u32> {
    AwaitersPool::new(
        "download policy regression",
        #[cfg(feature = "telemetry")]
        create_engine_telemetry(),
        create_engine_allocated(),
    )
}

#[tokio::test]
async fn download_policy_limited_failure_does_not_fail_ordinary_apply() {
    for limited_first in [true, false] {
        let pool = pool();
        let id = BlockIdExt::default();
        let calls = AtomicUsize::new(0);
        let (fail, failed) = tokio::sync::oneshot::channel::<()>();
        let (succeed, succeeded) = tokio::sync::oneshot::channel::<()>();
        let mut limited = Box::pin(download_with_policy(&pool, &id, Some(1), None, async {
            calls.fetch_add(1, Ordering::SeqCst);
            failed.await.unwrap();
            fail!("Downloader: out of attempts")
        }));
        let mut ordinary = Box::pin(download_with_policy(&pool, &id, None, None, async {
            calls.fetch_add(1, Ordering::SeqCst);
            succeeded.await.unwrap();
            Ok(42)
        }));
        if limited_first {
            assert!(futures::poll!(&mut limited).is_pending());
            assert!(futures::poll!(&mut ordinary).is_pending());
        } else {
            assert!(futures::poll!(&mut ordinary).is_pending());
            assert!(futures::poll!(&mut limited).is_pending());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let mut same_policy = Box::pin(download_with_policy(&pool, &id, None, None, async {
            panic!("identical ordinary policy must share its active worker")
        }));
        assert!(futures::poll!(&mut same_policy).is_pending());
        fail.send(()).unwrap();
        assert_eq!(limited.await.unwrap_err().to_string(), "Downloader: out of attempts");
        assert!(futures::poll!(&mut ordinary).is_pending());
        succeed.send(()).unwrap();
        assert_eq!(ordinary.await.unwrap(), Some(42));
        assert_eq!(same_policy.await.unwrap(), Some(42));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn download_policy_timeout_and_cancellation_are_isolated() {
    let pool = pool();
    let id = BlockIdExt::default();
    let calls = AtomicUsize::new(0);
    let mut cancelled = Box::pin(download_with_policy(&pool, &id, Some(10), None, async {
        calls.fetch_add(1, Ordering::SeqCst);
        std::future::pending::<Result<u32>>().await
    }));
    let mut backoff = Box::pin(download_with_policy(
        &pool, &id, Some(10), Some((50, 15, 500)), async {
            calls.fetch_add(1, Ordering::SeqCst);
            std::future::pending::<Result<u32>>().await
        },
    ));
    assert!(futures::poll!(&mut cancelled).is_pending());
    assert!(futures::poll!(&mut backoff).is_pending());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let mut waiter = Box::pin(download_with_policy(&pool, &id, Some(10), None, async {
        panic!("same policy must share")
    }));
    assert!(futures::poll!(&mut waiter).is_pending());
    drop(cancelled);
    assert!(waiter.await.unwrap_err().to_string().contains("operation cancelled"));
    assert!(futures::poll!(&mut backoff).is_pending());
    assert_eq!(download_with_policy(&pool, &id, Some(10), None, async { Ok(7) }).await.unwrap(), Some(7));
    pool.shunt_matching(|key| key.id == id, || Ok(9)).unwrap();
    assert_eq!(backoff.await.unwrap(), Some(9));
}

#[tokio::test]
async fn download_policy_candidate_shunt_constructs_once_for_all_policies() {
    let pool = pool();
    let id = BlockIdExt::default();
    let mut one = Box::pin(download_with_policy(&pool, &id, Some(1), None,
        std::future::pending::<Result<u32>>()));
    let mut unlimited = Box::pin(download_with_policy(&pool, &id, None, None,
        std::future::pending::<Result<u32>>()));
    assert!(futures::poll!(&mut one).is_pending());
    assert!(futures::poll!(&mut unlimited).is_pending());
    let mut builds = 0;
    pool.shunt_matching(|key| key.id == id, || { builds += 1; Ok(17) }).unwrap();
    assert_eq!(builds, 1);
    assert_eq!(one.await.unwrap(), Some(17));
    assert_eq!(unlimited.await.unwrap(), Some(17));
    assert_eq!(download_with_policy(&pool, &id, Some(1), None, async { Ok(18) }).await.unwrap(), Some(18));
}

#[tokio::test]
async fn download_policy_masterchain_candidate_does_not_end_full_proof_download() {
    let pool = pool();
    let mc = BlockIdExt::with_params(ShardIdent::masterchain(), 12, UInt256::from([1; 32]),
        UInt256::from([2; 32]));
    let (finish, finished) = tokio::sync::oneshot::channel::<()>();
    let mut full = Box::pin(download_with_policy(&pool, &mc, None, None, async {
        finished.await.unwrap();
        Ok(5)
    }));
    let mut finality = Box::pin(download_with_policy(&pool, &mc, Some(1), None,
        std::future::pending::<Result<u32>>()));
    assert!(futures::poll!(&mut full).is_pending());
    assert!(futures::poll!(&mut finality).is_pending());
    let mut builds = 0;
    assert!(!shunt_candidate_downloads(&pool, &mc, || { builds += 1; Ok(99) }).unwrap());
    assert_eq!(builds, 0, "a masterchain candidate must not build a proof link");
    assert!(futures::poll!(&mut full).is_pending());
    assert!(futures::poll!(&mut finality).is_pending());
    finish.send(()).unwrap();
    assert_eq!(full.await.unwrap(), Some(5));
    drop(finality);

    let shard = BlockIdExt::with_params(ShardIdent::full(0), 12, UInt256::from([1; 32]),
        UInt256::from([2; 32]));
    let mut ordinary = Box::pin(download_with_policy(&pool, &shard, None, None,
        std::future::pending::<Result<u32>>()));
    let mut limited = Box::pin(download_with_policy(&pool, &shard, Some(1), None,
        std::future::pending::<Result<u32>>()));
    assert!(futures::poll!(&mut ordinary).is_pending());
    assert!(futures::poll!(&mut limited).is_pending());
    assert!(shunt_candidate_downloads(&pool, &shard, || { builds += 1; Ok(11) }).unwrap());
    assert_eq!(builds, 1);
    assert_eq!(ordinary.await.unwrap(), Some(11));
    assert_eq!(limited.await.unwrap(), Some(11));
}
