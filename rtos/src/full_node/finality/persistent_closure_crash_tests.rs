// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Process-exit windows, not power-loss simulation. Only production source IO
//! can mint the confirmation passed through the interceptors below.
use super::*;
use consensus_common::finality_delivery::{
    CanonicalFinalityCompletion, CanonicalFinalityRequest, CloseFinalityRequest,
    DurableFinalitySink, DurableFinalitySinkPtr, FinalityCloseCompletion,
    FinalityTerminalCompletion, FinalizedDeliveryCompletion,
};
use std::io::Write;

const MODE: &str = "RTOS_SOURCE_CLOSE_CRASH_WINDOW";
const NOTE: &str = "RTOS_SOURCE_CLOSE_CRASH_NOTE";

/// Abrupt process loss at an already synchronized cut point. Unlike exit, this
/// skips C atexit handlers as well as Rust drops while native workers are live.
/// This defines the crash simulation; it does not diagnose prior SIGSEGVs.
fn abrupt_exit(status: std::ffi::c_int) -> ! {
    unsafe extern "C" {
        fn _exit(status: std::ffi::c_int) -> !;
    }
    unsafe { _exit(status) }
}

struct ExitAfterOffer {
    real: DurableFinalitySinkPtr,
    window: i32,
}
impl DurableFinalitySink for ExitAfterOffer {
    fn stage(
        &self,
        draft: FinalizedDeliveryDraft,
        done: FinalizedDeliveryCompletion,
    ) -> Result<()> {
        self.real.stage(draft, done)
    }
    fn retain_canonical(
        &self,
        request: CanonicalFinalityRequest,
        done: CanonicalFinalityCompletion,
    ) -> Result<()> {
        self.real.retain_canonical(request, done)
    }
    fn lookup_terminal(
        &self,
        request: CloseFinalityRequest,
        done: FinalityTerminalCompletion,
    ) -> Result<()> {
        self.real.lookup_terminal(request, done)
    }
    fn offer_close(
        &self,
        request: CloseFinalityRequest,
        done: FinalityCloseCompletion,
    ) -> Result<()> {
        let window = self.window;
        self.real.offer_close(
            request,
            Box::new(move |result| {
                if window == 72 && result.is_ok() {
                    abrupt_exit(72);
                }
                done(result);
            }),
        )
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "subprocess entry only; needs explicit public fixture signer"]
async fn persistent_closure_crash_child() {
    let window: i32 = std::env::var(MODE).unwrap().parse().unwrap();
    assert!([72, 73, 74].contains(&window));
    let signer = std::env::var("RTOS_PUBLIC_FIXTURE_SIGNER").unwrap();
    let pair = Pair::with_source_transport("included").await;
    let run = std::panic::AssertUnwindSafe(async {
        let engine = &pair.provider;
        engine.clone().download_and_apply_block(pair.master.id(), 1, false).await.unwrap();
        let zero = engine.load_state(&pair.anchor).await.unwrap();
        let config = zero.config_params().unwrap();
        let cc = pair.master.block().unwrap().read_info().unwrap().gen_catchain_seqno();
        let (committee, _) = config
            .validator_set()
            .unwrap()
            .calc_subset(&config.catchain_config().unwrap(), SHARD_FULL, -1, cc)
            .unwrap();
        let local = engine
            .network()
            .context()
            .stack
            .adnl
            .key_by_tag(NodeNetwork::TAG_OVERLAY_KEY)
            .unwrap()
            .id()
            .clone();
        let runtime = Arc::new(
            AuthenticatedSessionRuntime::from_authenticated_config(
                SessionNetworkPin { global_id: -239, zerostate: pair.anchor.clone() },
                config,
                rtos_api::session_identity::SessionCoordinates {
                    shard: pair.anchor.shard(),
                    catchain_seqno: cc,
                    vertical_seqno: 0,
                    last_key_block_seqno: 0,
                    new_catchain_ids: false,
                },
                committee,
                local,
            )
            .unwrap()
            .bind_recovery_anchor(pair.anchor.clone())
            .unwrap(),
        );
        let creator = runtime.committee()[0].validator_id().unwrap();
        let namespace = PathBuf::from(
            runtime
                .runtime_directory(
                    Path::new(engine.db_root_dir().unwrap()).join("catchains").to_str().unwrap(),
                )
                .unwrap(),
        );
        let real = engine.clone().durable_finality_sink(runtime.clone()).await.unwrap();
        let sink = Arc::new(ExitAfterOffer { real, window });
        let real_confirm =
            engine.ensure_publication_worker().await.unwrap().delivered_sink(runtime.clone());
        let confirm: simplex::finality_delivery::DeliveredCompletionSink =
            Arc::new(move |receipt, done| {
                // Receipt cannot be constructed here: source file+directory sync
                // and original-copy validation have already completed.
                if window == 73 {
                    abrupt_exit(73);
                }
                real_confirm(
                    receipt,
                    Box::new(move |result| {
                        // Actual node Released WAL ended, but source has not received
                        // the acknowledgement that would sync node_confirmed=true.
                        if window == 74 && result.is_ok() {
                            abrupt_exit(74);
                        }
                        done(result);
                    }),
                )
            });
        let source =
            FinalityDeliveryTestDriver::open(runtime.clone(), &namespace, sink, confirm).unwrap();
        // A fresh real session factory prepares this provenance directory before
        // source delivery. Reopening parents never manufacture missing provenance.
        source.prepare_intents(false).unwrap();
        let root = engine.load_state(pair.master.id()).await.unwrap().root_cell().clone();
        let (id, _, row) =
            chain::successor(&signer, pair.master.id(), &root, false, 0, cc, &creator);
        let block = fixture_block(&row);
        let proof = BlockProofStuff::deserialize(&id, decode(&row["proof_boc"]), false).unwrap();
        let created =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let draft = FinalizedDeliveryDraft {
            block_id: id.clone(),
            source_info: BlockSourceInfo {
                source: ValidatorIdentity::from_descriptor(&runtime.committee()[0]).unwrap(),
                priority: BlockCandidatePriority {
                    round: id.seq_no(),
                    first_block_round: 0,
                    priority: 0,
                },
            },
            data: ConsensusCommonFactory::create_block_payload(block.data().to_vec()),
            finality: SessionFinality::Carrier(proof.drain_signatures().unwrap()),
            last_mc_finalized_seqno: 0,
            candidate_already_sent: false,
            created_at_unix_secs: created,
        };
        // Test locator only: never consumed as production authority. Parent
        // authenticates through the normally reopened Engine and source scanner.
        let note = serde_json::json!({ "provider":pair._dir.path().join("provider"),
            "namespace":namespace, "zero":pair.anchor.to_string(), "block":id.to_string(),
            "created":created, "session":runtime.session_id().to_hex_string() });
        let path = PathBuf::from(std::env::var(NOTE).unwrap());
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(&serde_json::to_vec(&note).unwrap()).unwrap();
        file.sync_all().unwrap();
        std::fs::File::open(path.parent().unwrap()).unwrap().sync_all().unwrap();
        engine.set_test_chain_time(Some(1002 + id.seq_no()));
        pair.receiver.set_test_chain_time(Some(1002 + id.seq_no()));
        engine.enable_publication_worker().await.unwrap();
        tokio::time::timeout(Duration::from_secs(60), async {
            loop {
                if source.poll(draft.clone()).unwrap() && source.counts().unwrap().1 == 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("real node/source canonical reference must be durable");
        tokio::time::timeout(Duration::from_secs(120), async {
            loop {
                source.maintain().unwrap();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("real close transition never reached selected exit window");
    })
    .catch_unwind()
    .await;
    // Successful windows intentionally skip destructors. Every ordinary failure
    // still joins both Engines, rather than leaving a fixture-owned background task.
    pair.stop_all().await;
    run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    panic!("crash child returned without selected exit");
}

struct ChildOwner(std::process::Child);
impl Drop for ChildOwner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
async fn cold_window(window: i32) {
    cold_window_mode(window, false).await;
}

async fn cold_window_mode(window: i32, canonical_only: bool) {
    let _ = env_logger::builder().is_test(true).try_init();
    let signer =
        std::env::var("RTOS_PUBLIC_FIXTURE_SIGNER").expect("public fixture signer required");
    assert!(Path::new(&signer).is_file());
    let dir = tempfile::tempdir().unwrap();
    let note = dir.path().join("locator.json");
    let stdout = std::fs::File::create(dir.path().join("child.log")).unwrap();
    let stderr = stdout.try_clone().unwrap();
    let mut child = ChildOwner(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "persistent_closure_crash_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(MODE, window.to_string())
            .env(NOTE, &note)
            .env("TMPDIR", dir.path())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .unwrap(),
    );
    let status = tokio::time::timeout(Duration::from_secs(240), async {
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    // On timeout Drop always kill+wait; do not abandon a child owning two Engines.
    let status = status.unwrap_or_else(|error| {
        panic!("child window {window}: {error}; log {}", dir.path().join("child.log").display())
    });
    #[cfg(unix)]
    let signal = std::os::unix::process::ExitStatusExt::signal(&status);
    #[cfg(not(unix))]
    let signal: Option<i32> = None;
    assert_eq!(
        status.code(),
        Some(window),
        "child status={status:?} signal={signal:?}; log: {}",
        std::fs::read_to_string(dir.path().join("child.log")).unwrap()
    );
    drop(child);
    let note: serde_json::Value = serde_json::from_slice(&std::fs::read(&note).unwrap()).unwrap();
    let provider = PathBuf::from(note["provider"].as_str().unwrap());
    assert!(provider.starts_with(dir.path()), "child artifacts must stay under owned temp root");
    let namespace = PathBuf::from(note["namespace"].as_str().unwrap());
    let domain = OutboxDomain {
        zerostate: note["zero"].as_str().unwrap().parse().unwrap(),
        global_id: -239,
        wire_profile: WireProfile::T0,
    };
    let expected_id: BlockIdExt = note["block"].as_str().unwrap().parse().unwrap();
    if canonical_only {
        assert_eq!(window, 72);
        canonical_after_offer(&provider, &namespace, &domain, &expected_id, &note).await;
        return;
    }
    // No network peer or source signer is restarted. Closing identity recovery
    // must not depend on the historical transport secret still being configured.
    let config_path = provider.join("config.json");
    let mut config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
    config["validator_key_ring"] = serde_json::json!({});
    config["consensus_transport_bindings"] = serde_json::json!([]);
    let (replacement, _) =
        Ed25519KeyOption::<ZeroizingBytes>::from_private_key_with_json(&[0x79; 32]).unwrap();
    for key in config["adnl_node"]["keys"].as_array_mut().unwrap() {
        if key["tag"] == NodeNetwork::TAG_OVERLAY_KEY {
            key["data"] = serde_json::to_value(&replacement).unwrap();
        }
    }
    std::fs::write(config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    let mut previous = None;
    for reopen in 0..2 {
        let engine = open_engine(&provider).await;
        let mut recovery_service = None;
        let run = std::panic::AssertUnwindSafe(async {
            let (active, closed) = inspect_closure_progress(engine.db(), &domain).unwrap();
            assert_eq!(closed.len(), 1, "actual close offer must precede each crash");
            let original = closed[0].clone();
            assert!(
                engine
                    .adnl_key_by_id(&rtos_block::KeyId::from_data(
                        *original.binding.canonical.local_adnl.as_array()
                    ))
                    .is_none(),
                "the retired source transport key must actually be absent"
            );
            assert_eq!(original.binding.canonical.block_id, expected_id);
            assert_eq!(original.binding.created_at_unix_secs, note["created"].as_u64().unwrap());
            assert_eq!(
                original.binding.domain.session_id.to_hex_string(),
                note["session"].as_str().unwrap()
            );
            if reopen == 0 {
                assert_eq!(original.released, window == 74);
                assert_eq!(active.len(), usize::from(window != 74));
                let records = source_directory(&namespace).join("references-v1");
                let paths: Vec<_> =
                    std::fs::read_dir(records).unwrap().map(|e| e.unwrap().path()).collect();
                assert_eq!(
                    paths
                        .iter()
                        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("reference"))
                        .count(),
                    usize::from(window == 72)
                );
                let delivered: Vec<_> = paths
                    .iter()
                    .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("delivered"))
                    .collect();
                assert_eq!(delivered.len(), usize::from(window != 72));
                if let Some(path) = delivered.first() {
                    let disk: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
                    assert_eq!(
                        disk["node_confirmed"], false,
                        "crash must precede source confirmation acknowledgement"
                    );
                }
            } else {
                assert_eq!(Some(&original), previous.as_ref());
                assert!(active.is_empty());
            }
            engine.ensure_publication_worker().await.unwrap();
            let service = engine.ensure_retired_session_recovery().await.unwrap();
            recovery_service = Some(service.clone());
            // This is the only recovery driver. No runtime, source payload,
            // SourceDriver, stage, resume, or manual node confirmation is supplied.
            let final_record = tokio::time::timeout(Duration::from_secs(90), async {
                loop {
                    let (active, closed) = inspect_closure_progress(engine.db(), &domain).unwrap();
                    if closed.len() == 1 && closed[0].released && active.is_empty() {
                        let batch =
                            simplex::finality_delivery::scan_finality_closures_namespace_report(
                                &namespace, None, 16,
                            )
                            .unwrap();
                        if batch.next_cursor.is_some() && batch.items.is_empty() {
                            break closed[0].clone();
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await
            .unwrap_or_else(|timeout| {
                let ledger =
                    inspect_closure_progress(engine.db(), &domain).map(|(active, closed)| {
                        (
                            active.len(),
                            closed.len(),
                            closed.iter().filter(|record| record.released).count(),
                        )
                    });
                let scanner = simplex::finality_delivery::scan_finality_closures_namespace_report(
                    &namespace, None, 16,
                )
                .map(|batch| {
                    let errors: Vec<_> = batch
                        .items
                        .iter()
                        .filter_map(|(_, item)| item.as_ref().err().map(ToString::to_string))
                        .collect();
                    (batch.next_cursor.is_some(), batch.items.len(), errors)
                });
                panic!(
                    "background compact-only closing recovery timed out: {timeout}; \
                    window={window} reopen={reopen} service={:?} \
                    ledger(active,closed,released)={ledger:?} \
                    scanner(cursor,items,errors)={scanner:?}",
                    service.snapshot()
                );
            });
            assert_eq!(final_record.binding, original.binding);
            assert_eq!(final_record.lease_generation, original.lease_generation);
            assert_eq!(final_record.dependency_digest, original.dependency_digest);
            assert!(reference_backup(&namespace).is_none());
            assert!(std::fs::read_dir(source_directory(&namespace)).unwrap().all(|e| !matches!(
                e.unwrap().path().extension().and_then(|s| s.to_str()),
                Some("json" | "acked")
            )));
            // Independent history authentication is used only to inspect released
            // registry ownership, not to feed the background recovery service.
            let runtime = crate::validator::retired_session_auth::authenticate_closing_runtime(
                engine.as_ref(),
                &final_record.offer().request,
                &namespace,
            )
            .await
            .unwrap();
            tokio::time::timeout(Duration::from_secs(10), async {
                while engine.finality_recovery_registry().owns(&runtime) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("actual callback owners must release the recovery reservation");
            let lease =
                engine.finality_recovery_registry().reserve_normal(&runtime).unwrap().unwrap();
            lease.release();
            final_record
        })
        .catch_unwind()
        .await;
        engine.clone().wait_stop().await.unwrap();
        if let Some(service) = recovery_service {
            assert_eq!(
                service.snapshot().active,
                0,
                "actual service shutdown must drain every owner"
            );
        }
        drop(engine);
        previous = Some(run.unwrap_or_else(|panic| std::panic::resume_unwind(panic)));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real child process crash, PQ public fixture signer and network/WAL required"]
async fn persistent_closure_cold_service_after_offer_exit72() {
    cold_window(72).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real child process crash, PQ public fixture signer and network/WAL required"]
async fn persistent_closure_cold_service_after_delivered_exit73() {
    cold_window(73).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real child process crash, PQ public fixture signer and network/WAL required"]
async fn persistent_closure_cold_service_after_released_exit74() {
    cold_window(74).await;
}

/// A separate cold-read contract: this intentionally supplies an independently
/// authenticated runtime only to the read-only canonical verification. The background
/// service tests above continue to recover without such external input.
async fn canonical_after_offer(
    provider: &Path,
    namespace: &Path,
    domain: &OutboxDomain,
    expected_id: &BlockIdExt,
    note: &serde_json::Value,
) {
    let (reference_path, original_reference) =
        reference_backup(namespace).expect("exit72 must retain the original source reference");
    for _ in 0..2 {
        let engine = open_engine(provider).await;
        let run = std::panic::AssertUnwindSafe(async {
            let (_, closed) = inspect_closure_progress(engine.db(), domain).unwrap();
            assert_eq!(closed.len(), 1);
            let original = closed[0].clone();
            let request = original.offer().request;
            let runtime = crate::validator::retired_session_auth::authenticate_closing_runtime(
                engine.as_ref(),
                &request,
                namespace,
            )
            .await
            .unwrap();
            let canonical = crate::publication_worker::inspect_canonical_record(
                engine.db(), domain, &runtime, &request.canonical,
            ).expect("offer-before-source-sync must retain replayable canonical evidence");
            // Verify real DB payload using production canonical authentication
            // before any Offered/active marker. Early deletion must fail with
            // Cold canonical delivery missing, not only a stage assertion.
            assert_eq!(canonical.request, request.canonical);
            assert_eq!(&canonical.request.block_id, expected_id);
            assert_eq!(canonical.created_at_unix_secs, note["created"].as_u64().unwrap());
            assert_eq!(canonical.created_at_unix_secs, request.created_at_unix_secs);
            assert_eq!(runtime.session_id().to_hex_string(), note["session"].as_str().unwrap());
            let (source_id, digest) =
                simplex::finality_delivery::canonical_source_identity(&runtime, &canonical)
                    .unwrap();
            assert_eq!(source_id, simplex::finality_delivery::close_source_id(&request).unwrap());
            // The original schema digest covers the full body, exact carrier,
            // role/origin/domain, timestamp, last MC and candidate-sent flag.
            assert_eq!(digest, request.source_digest);
            assert!(!canonical.data.data().is_empty());
            let (active, after) = inspect_closure_progress(engine.db(), domain).unwrap();
            assert_eq!(after, closed);
            assert!(!original.released);
            assert_eq!(active.len(), 1);
            assert_eq!(std::fs::read(&reference_path).unwrap(), original_reference);
            assert!(std::fs::read_dir(source_directory(namespace).join("references-v1"))
                .unwrap()
                .all(|entry| entry.unwrap().path().extension().and_then(|s| s.to_str())
                    != Some("delivered")));
        })
        .catch_unwind()
        .await;
        // Even failed lookups/assertions drain the actual worker and Engine.
        let stopped = engine.clone().wait_stop().await;
        drop(engine);
        run.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        stopped.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real exit72 child, historical authentication and canonical WAL lookup"]
async fn persistent_closure_cold_canonical_replay_before_source_sync() {
    cold_window_mode(72, true).await;
}
