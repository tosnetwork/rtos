/* Copyright (C) 2026 RTOS contributors. GPL-3.0; see LICENSE. */
use super::*;
use crate::SessionPtr;
use consensus_common::*;
use rtos_block::{BlockSignaturesVariant, Ed25519KeyOption, Result, UInt256, ZeroizingBytes};
use std::time::Instant;

#[derive(Default)]
struct Listener(Mutex<Option<Box<dyn FnOnce() + Send>>>, std::sync::atomic::AtomicUsize);
impl SessionListener for Listener {
    fn on_candidate(
        &self,
        _: BlockSourceInfo,
        _: BlockHash,
        _: BlockPayloadPtr,
        _: BlockPayloadPtr,
        _: ValidatorBlockCandidateDecisionCallback,
    ) {
    }
    fn on_generate_slot(
        &self,
        _: BlockSourceInfo,
        _: AsyncCollationRequestPtr,
        _: CollationParentHint,
        _: ValidatorBlockCandidateCallback,
    ) {
        self.1.fetch_add(1, Ordering::SeqCst);
    }
    fn on_block_committed(
        &self,
        _: BlockSourceInfo,
        _: BlockHash,
        _: BlockHash,
        _: BlockPayloadPtr,
        _: BlockSignaturesVariant,
        _: Vec<(PublicKeyHash, BlockPayloadPtr)>,
        _: SessionStats,
    ) {
    }
    fn on_block_skipped(&self, _: u32) {}
    fn get_approved_candidate(
        &self,
        _: PublicKey,
        _: BlockHash,
        _: BlockHash,
        _: BlockHash,
        _: ValidatorBlockCandidateCallback,
    ) {
    }
    fn on_candidate_observed(
        &self,
        _: BlockIdExt,
        _: BlockPayloadPtr,
        _: BlockPayloadPtr,
        _: CandidateObservedFlags,
    ) {
        let callback = self.0.lock().unwrap().take();
        if let Some(callback) = callback {
            callback();
        }
    }
}

fn create(
    path: &std::path::Path,
    id: &UInt256,
    listener: &Arc<Listener>,
    callbacks: bool,
) -> Result<SessionPtr> {
    let key: PrivateKey = Ed25519KeyOption::<ZeroizingBytes>::generate().unwrap();
    let listener: Arc<dyn SessionListener + Send + Sync> = listener.clone();
    SessionImpl::create(
        &SessionOptions {
            wait_for_db_init: true,
            use_callback_thread: callbacks,
            ..Default::default()
        },
        id,
        &ShardIdent::masterchain(),
        vec![SessionNode { adnl_id: key.id().clone(), public_key: key.clone(), weight: 1 }.into()],
        &key,
        path.to_str().unwrap().to_owned(),
        ConsensusCommonFactory::create_dummy_overlay_manager(),
        Arc::downgrade(&listener),
        None,
        1,
    )
}

#[test]
fn session_lifecycle_external_stop_joins_actual_worker_exit() {
    let dir = TestDirectory::new();
    let listener = Arc::new(Listener::default());
    let session = create(dir.path(), &UInt256::rand(), &listener, true).unwrap();
    let (entered, observed) = std::sync::mpsc::channel();
    let (release, wait) = std::sync::mpsc::channel();
    *session.as_any().downcast_ref::<SessionImpl>().unwrap().worker_exit_gate.lock().unwrap() =
        Some((entered, wait));
    let owned = session.clone();
    let stopped = thread::spawn(move || owned.stop());
    observed.recv_timeout(Duration::from_secs(10)).unwrap();
    let returned_early = stopped.is_finished();
    release.send(()).unwrap();
    stopped.join().unwrap();
    assert!(!returned_early, "stop returned before the actual worker exit");
    assert!(session.is_stopped());
    session.stop();
}

#[test]
fn session_lifecycle_callback_stop_async_and_invalid_sync_stop_do_not_deadlock() {
    for synchronous in [false, true] {
        let dir = TestDirectory::new();
        let listener = Arc::new(Listener::default());
        let session = create(dir.path(), &UInt256::rand(), &listener, true).unwrap();
        let (entered, observed) = std::sync::mpsc::channel();
        let owned = session.clone();
        *listener.0.lock().unwrap() = Some(Box::new(move || {
            entered.send(()).unwrap();
            if synchronous {
                owned.stop();
            } else {
                owned.stop_async();
            }
        }));
        session
            .as_any()
            .downcast_ref::<SessionImpl>()
            .unwrap()
            ._callbacks
            .notify_candidate_observed(
                BlockIdExt::default(),
                ConsensusCommonFactory::create_block_payload(Vec::new()),
                ConsensusCommonFactory::create_block_payload(Vec::new()),
                CandidateObservedFlags::default(),
            );
        observed.recv_timeout(Duration::from_secs(5)).unwrap();
        session.stop();
        assert!(session.is_stopped());
        assert_eq!(session.is_panicked(), synchronous);
    }
}

#[test]
fn session_lifecycle_init_failure_callback_disabled_and_future_destroy() {
    let dir = TestDirectory::new();
    let listener = Arc::new(Listener::default());
    let id = UInt256::rand();
    let bad = dir.path().join("not-a-directory");
    std::fs::write(&bad, b"fixture").unwrap();
    assert!(create(&bad, &id, &listener, false).is_err());
    let session = create(dir.path(), &id, &listener, false).unwrap();
    let database = dir.path().join(id.to_hex_string());
    assert!(database.exists());
    session.destroy();
    assert!(session.is_stopped());
    assert!(!database.exists(), "destroy must remove even an unstarted future session DB");
}

#[test]
fn checked_creation_failure_joins_workers_and_retains_cleanup_error() {
    let dir = TestDirectory::new();
    let listener = Arc::new(Listener::default());
    let id = UInt256::rand();
    let bad = dir.path().join("not-a-directory");
    std::fs::write(&bad, b"fixture").unwrap();
    let error = create(&bad, &id, &listener, true).err().expect("worker DB init must fail");
    let failure =
        error.downcast_ref::<crate::SessionCreationFailure>().expect("typed cleanup receipt");
    assert!(failure.cleanup_drained());
    // No worker retains the failed namespace: the same path can now become a DB.
    std::fs::remove_file(&bad).unwrap();
    let session = create(&bad, &id, &listener, true).unwrap();
    session.stop_checked().unwrap();
    assert!(session.threads_drained());
}

#[test]
fn checked_creation_failure_waits_for_actual_worker_exit() {
    let dir = TestDirectory::new();
    let listener = Arc::new(Listener::default());
    let session = create(dir.path(), &UInt256::rand(), &listener, true).unwrap();
    let (entered, observed) = std::sync::mpsc::channel();
    let (release, wait) = std::sync::mpsc::channel();
    *session.as_any().downcast_ref::<SessionImpl>().unwrap().worker_exit_gate.lock().unwrap() =
        Some((entered, wait));
    let retained = session.clone();
    let cleanup = thread::spawn(move || {
        crate::SessionCreationFailure::after_attempt(
            rtos_block::error!("injected post-construction failure"),
            Some(retained),
        )
    });
    let reached = observed.recv_timeout(Duration::from_secs(10));
    let returned_early = cleanup.is_finished();
    let _ = release.send(());
    let mut failure = cleanup.join().unwrap();
    reached.unwrap();
    assert!(!returned_early, "cleanup receipt must wait for the real worker join");
    assert!(failure.cleanup_drained());
    assert!(failure.retry_cleanup());
    assert!(session.threads_drained());
    assert!(failure.to_string().contains("injected post-construction failure"));
}

struct TestDirectory(std::path::PathBuf);
impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir()
            .join(format!("rtos-session-lifecycle-{}", UInt256::rand().to_hex_string()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Real worker -> Receiver -> common manager -> ADNL private overlay creation and drain.
/// This does not stand in for root's NodeNetwork wrapper test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_observer_real_adnl_session_reopens_after_checked_drain() {
    use adnl::{
        node::{AdnlNode, AdnlNodeConfig},
        DhtNode, NetworkStack, OverlayNode, RldpNode,
    };
    let (runtime, key, options) = crate::authenticated_fixture::runtime(false);
    let (_, config) =
        AdnlNodeConfig::from_ip_address_and_private_keys("127.0.0.1:0", vec![([0x71; 32], 0)])
            .unwrap();
    let adnl = AdnlNode::with_config(config).await.unwrap();
    let dht = DhtNode::with_adnl_node(adnl.clone(), 0).unwrap();
    let overlay =
        OverlayNode::with_params_and_profile(adnl.clone(), &[22; 32], 0, rtos_api::WireProfile::T0)
            .unwrap();
    let rldp = RldpNode::with_params(adnl.clone(), vec![overlay.clone()], None).unwrap();
    overlay.set_rldp(rldp.clone()).unwrap();
    let stack = Arc::new(NetworkStack { adnl: adnl.clone(), dht, overlay, rldp, quic: None });
    adnl.start_over_udp(vec![stack.overlay.clone(), stack.dht.clone(), stack.rldp.clone()])
        .await
        .unwrap();
    let directory = TestDirectory::new();
    let path = directory.path().join("observer");
    let manager = ConsensusCommonFactory::create_adnl_overlay_manager(
        tokio::runtime::Handle::current(),
        stack,
        None,
        false,
    )
    .unwrap();
    let listener: Arc<dyn SessionListener + Send + Sync> = Arc::new(Listener::default());
    let result = (|| -> Result<()> {
        for _ in 0..2 {
            let session = crate::SessionFactory::create_authenticated_session(
                &options,
                runtime.clone(),
                &key,
                path.to_str().unwrap().to_owned(),
                manager.clone(),
                Arc::downgrade(&listener),
                None,
                Some(Arc::new(RejectFinalitySink)),
            )?;
            let stopped = session.stop_checked();
            let drained = session.threads_drained();
            stopped?;
            anyhow::ensure!(drained, "Actual session worker/overlay did not join");
            anyhow::ensure!(
                path.join(runtime.session_id().to_hex_string()).exists(),
                "DB was lost on stop"
            );
        }
        // A mismatched durable domain is rejected before the overlay can be recreated.
        std::fs::write(path.join("session-runtime.json"), b"{}")?;
        let rejected = crate::SessionFactory::create_authenticated_session(
            &options,
            runtime.clone(),
            &key,
            path.to_str().unwrap().to_owned(),
            manager.clone(),
            Arc::downgrade(&listener),
            None,
            Some(Arc::new(RejectFinalitySink)),
        );
        if let Ok(session) = rejected {
            session.stop_checked()?;
            anyhow::bail!("Mismatched durable runtime was accepted");
        }
        Ok(())
    })();
    drop(manager);
    let drained = adnl.stop_checked().await;
    drained.unwrap();
    result.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_validator_isolated_worker_signs_and_retains_journal_on_destroy() {
    use adnl::{
        node::{AdnlNode, AdnlNodeConfig},
        DhtNode, NetworkStack, OverlayNode, RldpNode,
    };
    let directory = TestDirectory::new();
    let store = Arc::new(rtos_pq_consensus::ConsensusKeyStore::from_seed(&[0x97; 32], 0).unwrap());
    let (mut nodes, keys) = crate::pq_fixture::members();
    nodes[1] = crate::SimplexSessionNode::from_descriptor(
        &crate::signing_coordinator::tests::custody_descriptor(&store),
    )
    .unwrap();
    let (runtime, key, mut options) = crate::authenticated_fixture::runtime_with_members(
        nodes.iter().map(|node| node.descriptor.clone().unwrap()).collect(),
        keys[1].clone(),
    );
    options.first_block_timeout = Duration::from_millis(30);
    options.target_rate = Duration::from_millis(30);
    // The session's members are the runtime's committee, with its canonical
    // weight prefixes, not the fixture descriptors it was built from.
    let nodes = runtime
        .committee()
        .iter()
        .map(crate::SimplexSessionNode::from_descriptor)
        .collect::<Result<Vec<_>>>()
        .unwrap();
    let path = std::path::PathBuf::from(
        runtime.runtime_directory(directory.path().to_str().unwrap()).unwrap(),
    );
    crate::runtime_manifest::RuntimeManifest::provision_test_validator(&runtime, &path).unwrap();
    let (_, config) =
        AdnlNodeConfig::from_ip_address_and_private_keys("127.0.0.1:0", vec![([0x73; 32], 0)])
            .unwrap();
    let adnl = AdnlNode::with_config(config).await.unwrap();
    adnl.add_key(key.clone(), 1).unwrap();
    let dht = DhtNode::with_adnl_node(adnl.clone(), 0).unwrap();
    let overlay =
        OverlayNode::with_params_and_profile(adnl.clone(), &[23; 32], 0, rtos_api::WireProfile::T0)
            .unwrap();
    let rldp = RldpNode::with_params(adnl.clone(), vec![overlay.clone()], None).unwrap();
    overlay.set_rldp(rldp.clone()).unwrap();
    let stack = Arc::new(NetworkStack { adnl: adnl.clone(), dht, overlay, rldp, quic: None });
    adnl.start_over_udp(vec![stack.overlay.clone(), stack.dht.clone(), stack.rldp.clone()])
        .await
        .unwrap();
    let manager = ConsensusCommonFactory::create_adnl_overlay_manager(
        tokio::runtime::Handle::current(),
        stack,
        None,
        false,
    )
    .unwrap();
    let concrete_listener = Arc::new(Listener::default());
    let listener: Arc<dyn SessionListener + Send + Sync> = concrete_listener.clone();
    let result = (|| -> Result<()> {
        let create = |initialize| {
            SessionImpl::create_with_profile(
                &options,
                runtime.session_id(),
                runtime.shard(),
                nodes.clone(),
                &key,
                path.to_str().unwrap().to_owned(),
                manager.clone(),
                Arc::downgrade(&listener),
                None,
                runtime.catchain_seqno(),
                Some(runtime.clone()),
                Some(Arc::new(RejectFinalitySink)),
                false,
                Some(crate::signing_coordinator::OwnSigner::Isolated(
                    crate::signing_coordinator::TestSessionSigner {
                        store: store.clone(),
                        owner_root: directory.path().to_owned(),
                        generation: 1,
                        initialize,
                    },
                )),
            )
        };
        let session = create(true)?;
        session.start(vec![runtime.pin().zerostate.clone()], runtime.pin().zerostate.clone());
        let deadline = Instant::now() + Duration::from_secs(5);
        while store.consensus_signatures_produced() == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let stopped = session.destroy_checked();
        let drained = session.threads_drained();
        stopped?;
        anyhow::ensure!(drained);
        let count = store.consensus_signatures_produced();
        anyhow::ensure!(count > 0, "actual session processor never reached native custody signer");
        let read_journal = || -> Result<_> {
            let db =
                crate::database::SimplexDb::open(&path, &runtime.session_id().to_hex_string())?;
            let rows = db
                .storage
                .get_by_prefix(crate::signing_coordinator::PREFIX.to_vec(), None)
                .wait()?;
            db.close(None)?;
            Ok(rows)
        };
        let before = read_journal()?;
        anyhow::ensure!(before.len() > 1, "actual worker did not persist signed own decisions");
        // Recovery authenticates the actual journal before exposing its receiver.
        // Do not start the FSM again: reopening alone cannot call the signer.
        let recovered = create(false)?;
        let stopped = recovered.destroy_checked();
        let drained = recovered.threads_drained();
        stopped?;
        anyhow::ensure!(drained);
        anyhow::ensure!(
            read_journal()? == before,
            "destroy or recovery changed durable signed decisions"
        );
        anyhow::ensure!(
            store.consensus_signatures_produced() == count,
            "recovery invoked native signer"
        );
        let record = crate::finality_recovery::SessionRecoveryRecord {
            pin: runtime.pin().clone(),
            binding: runtime.recovery_binding().unwrap().clone(),
            protocol: runtime.protocol(),
            carrier_version: runtime.carrier_version(),
            wire_profile: runtime.wire_profile(),
            profile: runtime.profile().clone(),
            session_id: runtime.session_id().clone(),
            local_adnl: UInt256::from(*runtime.local_adnl().data()),
            local_validator_index: Some(1),
            prev_blocks: vec![runtime.pin().zerostate.clone()],
            start_masterchain: runtime.pin().zerostate.clone(),
            namespace: path.clone(),
        };
        let collations = concrete_listener.1.load(Ordering::SeqCst);
        // Start the real worker with the old validator journal, but no signer.
        let retired = crate::SessionFactory::create_finality_recovery_session(
            &options,
            runtime.clone(),
            &key,
            directory.path().to_str().unwrap(),
            &record,
            manager.clone(),
            Arc::downgrade(&listener),
            Arc::new(RejectFinalitySink),
        )?;
        let deadline = Instant::now() + Duration::from_secs(5);
        while !retired.finality_recovery_complete() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let complete = retired.finality_recovery_complete();
        // Cross several original producer deadlines, retaining the old role.
        std::thread::sleep(Duration::from_millis(150));
        let stopped = retired.stop_checked();
        let drained = retired.threads_drained();
        stopped?;
        anyhow::ensure!(complete && drained, "Read-only worker did not complete and join");
        anyhow::ensure!(
            concrete_listener.1.load(Ordering::SeqCst) == collations,
            "Retired worker requested collation"
        );
        anyhow::ensure!(
            store.consensus_signatures_produced() == count,
            "Retired worker invoked native signer"
        );
        anyhow::ensure!(read_journal()? == before, "Retired worker mutated the own journal");

        Ok(())
    })();
    drop(manager);
    let drained = adnl.stop_checked().await;
    drained.unwrap();
    result.unwrap();
}

#[path = "test_production_session.rs"]
mod production_session;

struct RejectFinalitySink;
impl consensus_common::finality_delivery::DurableFinalitySink for RejectFinalitySink {
    fn stage(
        &self,
        _: consensus_common::finality_delivery::FinalizedDeliveryDraft,
        _: consensus_common::finality_delivery::FinalizedDeliveryCompletion,
    ) -> Result<()> {
        anyhow::bail!("Lifecycle fixture does not accept finality")
    }
}

/// Real session/receiver/private ADNL resources must remain an incomplete
/// recovery owner while the retained certificate's candidate is unavailable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn source_finality_real_retired_worker_preserves_missing_body_obligation() {
    use adnl::{
        node::{AdnlNode, AdnlNodeConfig},
        DhtNode, NetworkStack, OverlayNode, RldpNode,
    };
    let directory = TestDirectory::new();
    let (runtime, draft) = crate::finality_delivery::tests::fixture();
    let key = Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[0x71; 32]).unwrap();
    let options = crate::SessionOptions {
        protocol: runtime.protocol(),
        proto_version: runtime.carrier_version(),
        wire_profile: runtime.wire_profile(),
        slots_per_leader_window: runtime.slots_per_leader_window(),
        wait_for_db_init: true,
        ..Default::default()
    };
    let path = std::path::PathBuf::from(
        runtime.runtime_directory(directory.path().to_str().unwrap()).unwrap(),
    );
    let (_, config) =
        AdnlNodeConfig::from_ip_address_and_private_keys("127.0.0.1:0", vec![([0x71; 32], 0)])
            .unwrap();
    let adnl = AdnlNode::with_config(config).await.unwrap();
    let dht = DhtNode::with_adnl_node(adnl.clone(), 0).unwrap();
    let overlay =
        OverlayNode::with_params_and_profile(adnl.clone(), &[25; 32], 0, rtos_api::WireProfile::T0)
            .unwrap();
    let rldp = RldpNode::with_params(adnl.clone(), vec![overlay.clone()], None).unwrap();
    overlay.set_rldp(rldp.clone()).unwrap();
    let stack = Arc::new(NetworkStack { adnl: adnl.clone(), dht, overlay, rldp, quic: None });
    adnl.start_over_udp(vec![stack.overlay.clone(), stack.dht.clone(), stack.rldp.clone()])
        .await
        .unwrap();
    let manager = ConsensusCommonFactory::create_adnl_overlay_manager(
        tokio::runtime::Handle::current(),
        stack,
        None,
        false,
    )
    .unwrap();
    let listener: Arc<dyn SessionListener + Send + Sync> = Arc::new(Listener::default());
    let sink = Arc::new(crate::finality_delivery::tests::HeldSink::default());
    let result = (|| -> Result<()> {
        let session = crate::SessionFactory::create_authenticated_session(
            &options,
            runtime.clone(),
            &key,
            path.to_string_lossy().into_owned(),
            manager.clone(),
            Arc::downgrade(&listener),
            None,
            Some(sink.clone()),
        )?;
        session.stop_checked()?;
        anyhow::ensure!(session.threads_drained());
        let SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(proof)) = &draft.finality
        else {
            unreachable!()
        };
        let candidate = rtos_api::pq_finality::PqNetworkSignatureSet::from_final_fields(proof)?
            .to_node()
            .candidate;
        let hash = UInt256::calc_file_hash(&rtos_api::serialize_boxed(&candidate)?);
        let event = crate::simplex_state::BlockFinalizedEvent {
            slot: crate::block::SlotIndex::new(proof.slot),
            block_hash: hash.clone(),
            block_id: None,
            certificate: Arc::new(crate::certificate::Certificate {
                vote: crate::simplex_state::FinalizeVote {
                    slot: crate::block::SlotIndex::new(proof.slot),
                    block_hash: hash,
                },
                signatures: proof
                    .signatures
                    .iter()
                    .enumerate()
                    .map(|(index, signature)| crate::certificate::VoteSignature {
                        validator_idx: crate::block::ValidatorIndex::new(index as u32),
                        signature: signature.signature.clone(),
                    })
                    .collect(),
            }),
        };
        let source = crate::finality_delivery::SourceFinalityDelivery::open(
            runtime.clone(),
            &path,
            sink.clone(),
        )?;
        source.bind_start(runtime.pin().zerostate.clone())?;
        source.retain_intent(vec![runtime.pin().zerostate.clone()], &event)?;
        drop(source);
        let records = crate::finality_recovery::scan_finality_recovery(directory.path())?;
        anyhow::ensure!(records.len() == 1);
        let recovered = crate::SessionFactory::create_finality_recovery_session(
            &options,
            runtime.clone(),
            &key,
            directory.path().to_str().unwrap(),
            &records[0],
            manager.clone(),
            Arc::downgrade(&listener),
            sink.clone(),
        )?;
        let deadline = Instant::now() + Duration::from_secs(5);
        while recovered.finality_recovery_pending().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let pending = recovered.finality_recovery_pending();
        let premature = recovered.finality_recovery_complete();
        let staged = sink.0.lock().unwrap().len();
        let live_scan = crate::finality_recovery::scan_finality_recovery(directory.path());
        let stop = recovered.stop_checked();
        let drained = recovered.threads_drained();
        stop?;
        anyhow::ensure!(
            pending == Some(1) && drained && !premature && staged == 0,
            "missing body incorrectly completed or staged: {pending:?}"
        );
        anyhow::ensure!(live_scan?.is_empty(), "live namespace was stealable");
        anyhow::ensure!(
            crate::finality_recovery::scan_finality_recovery(directory.path())?.len() == 1,
            "checked stop discarded certificate debt"
        );
        // A canonical but forged source certificate must fail before the factory
        // exposes a receiver, rather than producing an indefinitely idle owner.
        use rtos_api::IntoBoxed;
        let intent_path = std::fs::read_dir(path.join("finality-intents"))?.next().unwrap()?.path();
        let mut disk: serde_json::Value = serde_json::from_slice(&std::fs::read(&intent_path)?)?;
        let wire: rtos_api::ton::consensus::simplex::Certificate = options
            .wire_profile
            .deserialize_typed(&hex::decode(disk["certificate"].as_str().unwrap())?)?;
        let mut wire = wire.only();
        let mut signatures = wire.signatures.only();
        let mut signature = signatures.votes[0].clone().only();
        signature.signature[0] ^= 1;
        signatures.votes[0] = signature.into_boxed();
        wire.signatures = signatures.into_boxed();
        disk["certificate"] =
            hex::encode(options.wire_profile.serialize(&wire.into_boxed())?).into();
        std::fs::write(&intent_path, serde_json::to_vec(&disk)?)?;
        let rejected = crate::SessionFactory::create_finality_recovery_session(
            &options,
            runtime.clone(),
            &key,
            directory.path().to_str().unwrap(),
            &records[0],
            manager.clone(),
            Arc::downgrade(&listener),
            sink.clone(),
        );
        if let Ok(session) = rejected {
            session.stop_checked()?;
            anyhow::bail!("Forged source FinalCert was exposed by recovery factory");
        }
        anyhow::ensure!(intent_path.exists(), "Rejected source evidence was deleted");

        Ok(())
    })();
    drop(manager);
    adnl.stop_checked().await.unwrap();
    result.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn source_finality_namespace_release_waits_for_real_node_completion() {
    use adnl::{
        node::{AdnlNode, AdnlNodeConfig},
        DhtNode, NetworkStack, OverlayNode, RldpNode,
    };
    let directory = TestDirectory::new();
    let (runtime, draft) = crate::finality_delivery::tests::fixture();
    let key = Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[0x71; 32]).unwrap();
    let options = crate::SessionOptions {
        protocol: runtime.protocol(),
        proto_version: runtime.carrier_version(),
        wire_profile: runtime.wire_profile(),
        slots_per_leader_window: runtime.slots_per_leader_window(),
        wait_for_db_init: true,
        ..Default::default()
    };
    let path = std::path::PathBuf::from(
        runtime.runtime_directory(directory.path().to_str().unwrap()).unwrap(),
    );
    let (_, config) =
        AdnlNodeConfig::from_ip_address_and_private_keys("127.0.0.1:0", vec![([0x71; 32], 0)])
            .unwrap();
    let adnl = AdnlNode::with_config(config).await.unwrap();
    let dht = DhtNode::with_adnl_node(adnl.clone(), 0).unwrap();
    let overlay =
        OverlayNode::with_params_and_profile(adnl.clone(), &[25; 32], 0, rtos_api::WireProfile::T0)
            .unwrap();
    let rldp = RldpNode::with_params(adnl.clone(), vec![overlay.clone()], None).unwrap();
    overlay.set_rldp(rldp.clone()).unwrap();
    let stack = Arc::new(NetworkStack { adnl: adnl.clone(), dht, overlay, rldp, quic: None });
    adnl.start_over_udp(vec![stack.overlay.clone(), stack.dht.clone(), stack.rldp.clone()])
        .await
        .unwrap();
    let manager = ConsensusCommonFactory::create_adnl_overlay_manager(
        tokio::runtime::Handle::current(),
        stack,
        None,
        false,
    )
    .unwrap();
    let listener: Arc<dyn SessionListener + Send + Sync> = Arc::new(Listener::default());
    let sink = Arc::new(crate::finality_delivery::tests::HeldSink::default());
    let result = (|| -> Result<()> {
        for succeed in [false, true] {
            let session = crate::SessionFactory::create_authenticated_session(
                &options,
                runtime.clone(),
                &key,
                path.to_string_lossy().into_owned(),
                manager.clone(),
                Arc::downgrade(&listener),
                None,
                Some(sink.clone()),
            )?;
            let callbacks = &session.as_any().downcast_ref::<SessionImpl>().unwrap()._callbacks;
            callbacks.bind_delivery_start(runtime.pin().zerostate.clone())?;
            anyhow::ensure!(!callbacks.poll_durable_finality(draft.clone())?);
            session.stop_checked()?;
            let workers_joined = session.threads_drained();
            let namespace_early = session.namespace_drained();
            let reopened_early = crate::finality_delivery::SourceFinalityDelivery::open(
                runtime.clone(),
                &path,
                sink.clone(),
            )
            .is_ok();
            let (_, completion) = sink.0.lock().unwrap().pop().unwrap();
            completion(if succeed {
                Ok(UInt256::from([88; 32]))
            } else {
                Err(rtos_block::error!("held WAL failure"))
            });
            anyhow::ensure!(
                workers_joined && !namespace_early && !reopened_early,
                "worker join cannot release namespace retained by node completion"
            );
            anyhow::ensure!(
                session.namespace_drained(),
                "source completion failed to release real stores"
            );
            let reopened = crate::finality_delivery::SourceFinalityDelivery::open(
                runtime.clone(),
                &path,
                sink.clone(),
            )?;
            drop(reopened);
        }
        Ok(())
    })();
    drop(manager);
    let drained = adnl.stop_checked().await;
    drained.unwrap();
    result.unwrap();
}
