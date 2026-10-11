/* Copyright (C) 2026 RTOS contributors. GPL-3.0; see LICENSE. */
use super::*;
use crate::SessionPtr;
use std::time::Instant;
use consensus_common::*;
use rtos_block::{BlockSignaturesVariant, Ed25519KeyOption, Result, UInt256, ZeroizingBytes};

#[derive(Default)]
struct Listener(Mutex<Option<Box<dyn FnOnce() + Send>>>);
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
    use adnl::{node::{AdnlNode, AdnlNodeConfig}, DhtNode, NetworkStack, OverlayNode, RldpNode};
    let directory = TestDirectory::new();
    let store = Arc::new(rtos_pq_consensus::ConsensusKeyStore::from_seed(&[0x97; 32], 0).unwrap());
    let (mut nodes, keys) = crate::pq_fixture::members();
    nodes[1] = crate::SimplexSessionNode::from_descriptor(
        &crate::signing_coordinator::tests::custody_descriptor(&store)).unwrap();
    let (runtime, key, mut options) = crate::authenticated_fixture::runtime_with_members(
        nodes.iter().map(|node| node.descriptor.clone().unwrap()).collect(), keys[1].clone());
    options.first_block_timeout = Duration::from_millis(30);
    options.target_rate = Duration::from_millis(30);
    let path = directory.path().join("validator");
    crate::runtime_manifest::RuntimeManifest::provision_test_validator(&runtime, &path).unwrap();
    let (_, config) = AdnlNodeConfig::from_ip_address_and_private_keys("127.0.0.1:0", vec![([0x73; 32], 0)]).unwrap();
    let adnl = AdnlNode::with_config(config).await.unwrap();
    adnl.add_key(key.clone(), 1).unwrap();
    let dht = DhtNode::with_adnl_node(adnl.clone(), 0).unwrap();
    let overlay = OverlayNode::with_params_and_profile(adnl.clone(), &[23; 32], 0, rtos_api::WireProfile::T0).unwrap();
    let rldp = RldpNode::with_params(adnl.clone(), vec![overlay.clone()], None).unwrap();
    overlay.set_rldp(rldp.clone()).unwrap();
    let stack = Arc::new(NetworkStack { adnl: adnl.clone(), dht, overlay, rldp, quic: None });
    adnl.start_over_udp(vec![stack.overlay.clone(), stack.dht.clone(), stack.rldp.clone()]).await.unwrap();
    let manager = ConsensusCommonFactory::create_adnl_overlay_manager(tokio::runtime::Handle::current(), stack, None, false).unwrap();
    let listener: Arc<dyn SessionListener + Send + Sync> = Arc::new(Listener::default());
    let result = (|| -> Result<()> {
        let create = |initialize| SessionImpl::create_with_profile(&options, runtime.session_id(), runtime.shard(), nodes.clone(),
            &key, path.to_str().unwrap().to_owned(), manager.clone(), Arc::downgrade(&listener), None,
            runtime.catchain_seqno(), Some(runtime.clone()), Some(crate::signing_coordinator::TestSessionSigner {
                store: store.clone(), owner_root: directory.path().to_owned(), generation: 1, initialize,
            }));
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
            let db = crate::database::SimplexDb::open(&path, &runtime.session_id().to_hex_string())?;
            let rows = db.storage.get_by_prefix(crate::signing_coordinator::PREFIX.to_vec(), None).wait()?;
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
        anyhow::ensure!(read_journal()? == before, "destroy or recovery changed durable signed decisions");
        anyhow::ensure!(store.consensus_signatures_produced() == count, "recovery invoked native signer");
        Ok(())
    })();
    drop(manager);
    let drained = adnl.stop_checked().await;
    drained.unwrap();
    result.unwrap();
}
