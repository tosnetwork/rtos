// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::*;
use crate::collator_test_bundle::create_engine_allocated;
#[cfg(feature = "telemetry")]
use crate::collator_test_bundle::create_engine_telemetry;

fn pool() -> Arc<AwaitersPool<u32, u32>> {
    Arc::new(AwaitersPool::new(
        "typed",
        #[cfg(feature = "telemetry")]
        create_engine_telemetry(),
        create_engine_allocated(),
    ))
}

// The owner and a registered waiter both observe the AUTH classification; an
// unclassified failure keeps its message as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn published_auth_refusal_keeps_its_type_for_owner_and_waiter() {
    for typed in [true, false] {
        let pool = pool();
        let (started, started_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = tokio::sync::oneshot::channel::<()>();
        let owner_pool = pool.clone();
        let owner = tokio::spawn(async move {
            owner_pool
                .do_or_wait(&7, None, async move {
                    let _ = started.send(());
                    let _ = release_rx.await;
                    if typed {
                        Err(AuthPolicyRefused("refused".to_string()).into())
                    } else {
                        Err(error!("plain failure"))
                    }
                })
                .await
        });
        started_rx.await.unwrap();
        let waiter_pool = pool.clone();
        let waiter = tokio::spawn(async move {
            waiter_pool.do_or_wait(&7, None, async { panic!("the waiter must not run") }).await
        });
        // The operation stays owned until released, so the second caller can only
        // register as a waiter on the same entry.
        tokio::time::sleep(Duration::from_millis(100)).await;
        release.send(()).unwrap();
        for result in [owner.await.unwrap(), waiter.await.unwrap()] {
            let error = result.unwrap_err();
            assert_eq!(AuthPolicyRefused::is(&error), typed, "{error}");
            assert_eq!(error.to_string(), if typed { "refused" } else { "plain failure" });
        }
    }
}
