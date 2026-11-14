// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Actual Engine acceptance with per-database synchronization fault injection.
//! These tests do not simulate a power cut. Trace the positive test's real fsync
//! calls separately; an observer returning Ok always performs the actual sync.
use super::*;
use crate::propagation_outbox::{inspect_delivery, Limits, OutboxDomain, PublicationStage};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Mutex,
};
use storage::durability::SyncPoint;

#[derive(Clone, Copy, Debug)]
enum Failure {
    File,
    ProofFile,
    Directory,
    ArtifactWal,
    StateWal,
    RebuiltStateWal,
    HandleWal,
    CatchainWal,
}

async fn exercise_sync_boundary(failure: Option<Failure>) {
    let SpoolFixture { dir, engine, runtime, block, row, .. } = SpoolFixture::new(0).await;
    let domain = OutboxDomain {
        zerostate: runtime.pin().zerostate.clone(),
        global_id: runtime.pin().global_id,
        wire_profile: runtime.wire_profile(),
    };
    let hit = Arc::new(AtomicBool::new(false));
    let events = Arc::new(Mutex::new(Vec::new()));
    let hit_observer = hit.clone();
    let events_observer = events.clone();
    let node_wals = AtomicUsize::new(0);
    let files = AtomicUsize::new(0);
    engine.db().set_publication_sync_observer(Some(Arc::new(move |point, path| {
        let name = path.file_name().and_then(|name| name.to_str());
        let node_ordinal = if point == SyncPoint::Wal && name == Some("db") {
            node_wals.fetch_add(1, Ordering::SeqCst) + 1
        } else {
            0
        };
        events_observer.lock().unwrap().push((point, path.to_path_buf()));
        eprintln!("PUBLICATION_SYNC_BEGIN {point:?} {}", path.display());
        let selected = match failure {
            Some(Failure::File) => point == SyncPoint::File,
            Some(Failure::ProofFile) => {
                point == SyncPoint::File && files.fetch_add(1, Ordering::SeqCst) + 1 == 2
            }
            Some(Failure::Directory) => point == SyncPoint::Directory,
            // This fixture reconstructs a missing state: flush pending state,
            // then the rebuilt state, before the final handle metadata barrier.
            Some(Failure::ArtifactWal) => node_ordinal == 1,
            Some(Failure::StateWal) => node_ordinal == 2,
            Some(Failure::RebuiltStateWal) => node_ordinal == 3,
            Some(Failure::HandleWal) => node_ordinal == 4,
            Some(Failure::CatchainWal) => point == SyncPoint::Wal && name == Some("catchains"),
            None => false,
        };
        if selected {
            hit_observer.store(true, Ordering::SeqCst);
            eprintln!("PUBLICATION_SYNC_INJECTED_EIO {point:?} {}", path.display());
            return Err(std::io::Error::from_raw_os_error(5).into());
        }
        Ok(())
    })));
    let result = std::panic::AssertUnwindSafe(async {
        let sink = engine.clone().durable_finality_sink(runtime.clone()).await.unwrap();
        let id = stage_spool(&sink, spool_draft(&runtime, &block, &row, false)).await.unwrap();
        eprintln!("PUBLICATION_DRAFT_WAL_RECEIPT {id:x}");
        let accepted = tokio::time::timeout(
            Duration::from_secs(30),
            engine.clone().await_publication(id.clone()),
        )
        .await
        .expect("acceptance/failed owner must reach a terminal result");
        let (_, stored) = inspect_delivery(engine.db(), &domain, &Limits::default(), &id)
            .unwrap()
            .expect("source WAL receipt lost");
        if failure.is_some() {
            assert!(
                hit.load(Ordering::SeqCst),
                "selected real sync boundary was not reached: {failure:?}"
            );
            assert!(accepted.is_err(), "failed durability barrier returned acceptance");
            assert_eq!(stored.stage, PublicationStage::DraftDurable);
            assert!(stored.pending.is_empty());
            assert!(stored.record.effects.is_empty());
            eprintln!("PUBLICATION_FAILED_SYNC_RETAINS_DRAFT {id:x}");
        } else {
            let accepted = accepted.unwrap();
            assert_eq!(accepted.block(), &block);
            assert_eq!(stored.stage, PublicationStage::AcceptedDraft);
            assert!(stored.pending.is_empty());
            assert!(stored.record.effects.is_empty());
            let events = events.lock().unwrap();
            let artifact_barrier = events
                .iter()
                .position(|(point, path)| {
                    *point == SyncPoint::Wal && path.file_name().is_some_and(|name| name == "db")
                })
                .expect("artifact metadata WAL barrier");
            let artifacts = &events[..artifact_barrier];
            assert_eq!(
                artifacts.iter().filter(|(point, _)| *point == SyncPoint::File).count(),
                2,
                "body and proof must share one artifact durability barrier"
            );
            let mut directories = std::collections::HashSet::new();
            for (_, path) in artifacts.iter().filter(|(point, _)| *point == SyncPoint::Directory) {
                assert!(directories.insert(path.clone()), "shared artifact directory synced twice");
            }
            assert!(events.iter().filter(|(point, _)| *point == SyncPoint::File).count() >= 2);
            assert!(events.iter().any(|(point, _)| *point == SyncPoint::Directory));
            assert!(
                events
                    .iter()
                    .filter(|(point, path)| *point == SyncPoint::Wal
                        && path.file_name().is_some_and(|name| name == "db"))
                    .count()
                    == 4
            );
            assert!(events.iter().any(|(point, path)| *point == SyncPoint::Wal
                && path.file_name().is_some_and(|name| name == "catchains")));
            eprintln!("PUBLICATION_ACCEPTED_DRAFT_WAL_CONFIRMED {id:x}");
        }
        id
    })
    .catch_unwind()
    .await;
    // The failure is sticky but must not hang shutdown or leave detached IO.
    let stop = tokio::time::timeout(Duration::from_secs(30), engine.clone().wait_stop())
        .await
        .expect("durability fault left an unjoinable owner");
    if failure.is_some() {
        assert!(stop.is_err(), "durability failure was not sticky");
    } else {
        stop.unwrap();
    }
    drop(engine);
    let id = result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    let reopened = open_engine(dir.path()).await;
    let (_, stored) = inspect_delivery(reopened.db(), &domain, &Limits::default(), &id)
        .unwrap()
        .expect("checkpoint vanished on reopen");
    assert_eq!(
        stored.stage,
        if failure.is_some() {
            PublicationStage::DraftDurable
        } else {
            PublicationStage::AcceptedDraft
        }
    );
    reopened.clone().wait_stop().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_sync_real_calls_precede_accepted_draft() {
    exercise_sync_boundary(None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publication_sync_faults_never_promote_draft_and_drain_owned_io() {
    for failure in [
        Failure::File,
        Failure::ProofFile,
        Failure::Directory,
        Failure::ArtifactWal,
        Failure::StateWal,
        Failure::RebuiltStateWal,
        Failure::HandleWal,
        Failure::CatchainWal,
    ] {
        exercise_sync_boundary(Some(failure)).await;
    }
}
