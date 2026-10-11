/*
 * RTOS project modifications (2026-10-10): project and crate naming.
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
use crate::validator::consensus::ConsensusCommonFactory;
use rtos_block::{
    signature::SigPubKey, validators::ValidatorDescr, Ed25519KeyOption, KeyId, Serializable,
    ZeroizingBytes,
};
use std::{
    any::Any,
    sync::{atomic::AtomicBool, Mutex},
    time::Duration,
};
use validator_session::AsyncRequest;

#[derive(Default)]
struct DummyEngine;

#[async_trait::async_trait]
impl EngineOperations for DummyEngine {
    fn destroy_block_candidates(&self, _: &SessionId) -> Result<bool> {
        Ok(true)
    }
    // `on_candidate_observed` persists a valid candidate body
    async fn store_block(
        &self,
        _block: &crate::block::BlockStuff,
    ) -> Result<crate::internal_db::BlockResult> {
        fail!("dummy engine does not persist blocks")
    }
}

#[derive(Default)]
struct MockSimplexSession {
    requests: Mutex<Vec<(BlockIdExt, EnsureCandidateAvailabilityOptions)>>,
    stopped: AtomicBool,
    drained: AtomicBool,
    stop_calls: std::sync::atomic::AtomicUsize,
    panic_on_stop: AtomicBool,
    stop_gate: Mutex<Option<(tokio::sync::oneshot::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
}

impl Display for MockSimplexSession {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "mock_simplex_session")
    }
}

impl Session for MockSimplexSession {
    fn stop_checked(&self) -> Result<()> {
        self.stop();
        Ok(())
    }

    fn destroy_checked(&self) -> Result<()> {
        self.stop_checked()
    }

    fn threads_drained(&self) -> bool {
        // A stop request is not the held synchronous worker's completion proof.
        self.drained.load(Ordering::Acquire)
    }

    fn start(&self, _prev_blocks: Vec<BlockIdExt>, _min_masterchain_block_id: BlockIdExt) {}

    fn stop(&self) {
        self.stop_calls.fetch_add(1, Ordering::Relaxed);
        assert!(!self.panic_on_stop.load(Ordering::Relaxed), "controlled blocking stop panic");
        if let Some((entered, release)) = self.stop_gate.lock().unwrap().take() {
            let _ = entered.send(());
            release.recv_timeout(Duration::from_secs(10)).expect("stop gate watchdog");
        }
        self.stopped.store(true, Ordering::Relaxed);
        self.drained.store(true, Ordering::Release);
    }

    fn stop_async(&self) {
        self.stopped.store(true, Ordering::Relaxed);
    }

    fn destroy(&self) {
        self.stopped.store(true, Ordering::Relaxed);
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_group_stop_waits_for_session_exit() {
    let group = make_simplex_group_for_resolver_tests();
    let session = Arc::new(MockSimplexSession::default());
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    *session.stop_gate.lock().unwrap() = Some((entered_tx, release_rx));
    let holder = Arc::new(super::consensus::SessionHolder::simplex(session.clone()));
    group.group_impl.execute_sync(|inner| inner.session = Some(holder)).await;
    let stopped = tokio::spawn(group.clone().stop(tokio::runtime::Handle::current(), false));
    tokio::time::timeout(Duration::from_secs(5), entered_rx).await.unwrap().unwrap();
    let completed_before_exit = stopped.is_finished();
    release_tx.send(()).unwrap();
    stopped.await.unwrap().unwrap();
    assert!(!completed_before_exit, "group stop returned before the session exited");
    assert!(session.stopped.load(Ordering::Relaxed));
    assert!(group.get_status().await == ValidatorGroupStatus::Stopped);
}

impl super::consensus::SimplexSession for MockSimplexSession {
    fn notify_mc_finalized(&self, _applied_top: BlockIdExt) {}

    fn ensure_candidate_available(
        &self,
        block_id: BlockIdExt,
        opts: EnsureCandidateAvailabilityOptions,
    ) {
        self.requests.lock().expect("requests lock poisoned").push((block_id, opts));
    }

    fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Relaxed)
    }

    fn is_panicked(&self) -> bool {
        false
    }
}

fn make_group_impl_for_start_tests() -> ValidatorGroupImpl {
    ValidatorGroupImpl::new(
        &KeyId::from_data([0u8; 32]),
        ShardIdent::masterchain(),
        1,
        UInt256::default(),
        false,
        false,
        ConsensusType::Catchain,
        None,
    )
}

fn make_simplex_group_for_resolver_tests() -> Arc<ValidatorGroup> {
    make_simplex_group_for_engine(Arc::new(DummyEngine))
}

/// Controlled Session boundary for the actual manager -> group teardown path.
pub(crate) async fn gated_lifecycle_group(
) -> (Arc<ValidatorGroup>, tokio::sync::oneshot::Receiver<()>, std::sync::mpsc::Sender<()>) {
    let group = make_simplex_group_for_resolver_tests();
    let session = Arc::new(MockSimplexSession::default());
    let (entered, observed) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    *session.stop_gate.lock().unwrap() = Some((entered, wait));
    let holder = Arc::new(super::consensus::SessionHolder::simplex(session));
    group.group_impl.execute_sync(|inner| inner.session = Some(holder)).await;
    (group, observed, release)
}

#[tokio::test(flavor = "current_thread")]
async fn test_group_stop_waits_for_descendants_and_rejects_late_root_tasks() {
    let group = make_simplex_group_for_resolver_tests();
    let (parent_release, parent_gate) = tokio::sync::oneshot::channel();
    let (child_entered, child_observed) = tokio::sync::oneshot::channel();
    let (child_release, child_gate) = tokio::sync::oneshot::channel();
    let owner = group.clone();
    group.spawn_root_task(&tokio::runtime::Handle::current(), async move {
        parent_gate.await.unwrap();
        owner.spawn_task(&tokio::runtime::Handle::current(), async move {
            child_entered.send(()).unwrap();
            child_gate.await.unwrap();
        });
    });
    let mut stopped = Box::pin(group.clone().stop(tokio::runtime::Handle::current(), false));
    assert!(futures::poll!(&mut stopped).is_pending());
    group.stop_requested.cancelled().await;
    let late = Arc::new(AtomicBool::new(false));
    let observed = late.clone();
    group.spawn_root_task(&tokio::runtime::Handle::current(), async move {
        observed.store(true, Ordering::Relaxed);
    });
    parent_release.send(()).unwrap();
    child_observed.await.unwrap();
    assert!(futures::poll!(&mut stopped).is_pending());
    child_release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), stopped).await.unwrap().unwrap();
    assert!(!late.load(Ordering::Relaxed));
    assert!(group.tasks.is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn test_group_stop_reports_task_panic_instead_of_stopped() {
    let group = make_simplex_group_for_resolver_tests();
    let task = group.spawn_task(&tokio::runtime::Handle::current(), async {
        panic!("controlled group task panic");
    });
    assert!(task.await.unwrap_err().is_panic());
    let error = group.clone().stop(tokio::runtime::Handle::current(), false).await.unwrap_err();
    assert!(error.to_string().contains("task panicked"));
    assert!(group.get_status().await == ValidatorGroupStatus::Stopping);
    assert!(group.tasks.is_empty());
}

pub(crate) fn make_simplex_group_for_engine(
    engine: Arc<dyn EngineOperations>,
) -> Arc<ValidatorGroup> {
    let local_key: PrivateKey =
        Ed25519KeyOption::<ZeroizingBytes>::generate().expect("key must be generated");
    let validator_descr = ValidatorDescr::with_params(
        SigPubKey::from_bytes(local_key.pub_key().expect("pubkey bytes"))
            .expect("valid sig pubkey"),
        1,
        None,
    );
    let validator_set =
        ValidatorSet::with_cc_seqno(0, 0, 0, 1, vec![validator_descr]).expect("validator set");

    let session_info = Arc::new(GeneralSessionInfo {
        shard: ShardIdent::masterchain(),
        opts_hash: UInt256::default(),
        catchain_seqno: 1,
        key_seqno: 0,
        max_vertical_seqno: 0,
    });

    let group = ValidatorGroup::new(
        session_info,
        local_key,
        UInt256::rand(),
        UInt256::rand(),
        validator_set,
        0,
        ConsensusOptions::Simplex(Default::default()),
        engine,
        false,
        None,
    );
    Arc::new(group)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_resolver_cache_bridge_requests_simplex_candidate_availability() {
    let group = make_simplex_group_for_resolver_tests();
    let mock_session = Arc::new(MockSimplexSession::default());
    let session_ptr: super::consensus::SimplexSessionPtr = mock_session.clone();
    let session_holder: SessionHolderPtr =
        Arc::new(super::consensus::SessionHolder::simplex(session_ptr));
    group
        .group_impl
        .execute_sync(move |group_impl| {
            group_impl.session = Some(session_holder.clone());
        })
        .await;

    let backend: Arc<dyn ResolverBackend> = group.clone();
    group.state_resolver_cache.lock().await.set_backend(Arc::downgrade(&backend));

    // Feed a real, parseable block whose root hash matches the observed block
    // id so the body-present success path stores the deserialized body and
    // extracted parent ids.
    let mut block = Block::default();
    block.set_global_id(42);
    let root_hash = block.serialize().expect("serialize block cell").repr_hash().clone();
    let block_bytes = block.write_to_bytes().expect("serialize block bytes");
    let block_id =
        BlockIdExt::with_params(ShardIdent::masterchain(), 77, root_hash, UInt256::rand());
    group
        .on_candidate_observed(
            block_id.clone(),
            ConsensusCommonFactory::create_block_payload(block_bytes),
            ConsensusCommonFactory::create_block_payload(Vec::new()),
            CandidateObservedFlags {
                body_present: true,
                parent_ready: false,
                local_collated: false,
            },
        )
        .await;

    {
        let cache = group.state_resolver_cache.lock().await;
        assert!(cache.try_get_entry(&block_id).is_some(), "observed candidate must be cached");
        cache.request_availability(&block_id, ResolverPurpose::SimplexValidationParent);
    }

    let mut attempts = 0u32;
    loop {
        let requests = mock_session.requests.lock().expect("requests lock poisoned");
        if !requests.is_empty() {
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].0, block_id);
            assert_eq!(requests[0].1.purpose, ResolverPurpose::SimplexValidationParent);
            assert!(
                requests[0].1.include_parent_chain,
                "resolver requests must include parent chain for repair"
            );
            break;
        }
        drop(requests);
        attempts += 1;
        assert!(attempts < 50, "timed out waiting for resolver bridge request");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A candidate whose body fails to deserialize must still be recorded in the
/// resolver cache (flags only, no body), so later flag updates can OR-merge and
/// a subsequent valid body can overwrite the entry instead of stranding
/// resolver waiters on a dropped observation.
#[tokio::test(flavor = "multi_thread")]
async fn test_on_candidate_observed_caches_observation_when_body_deserialize_fails() {
    let group = make_simplex_group_for_resolver_tests();

    let block_id =
        BlockIdExt::with_params(ShardIdent::masterchain(), 88, UInt256::rand(), UInt256::rand());
    group
        .on_candidate_observed(
            block_id.clone(),
            // Not a valid BOC, so both `deserialize_block` and the cache's
            // fallback re-parse fail and no body is stored.
            ConsensusCommonFactory::create_block_payload(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            ConsensusCommonFactory::create_block_payload(Vec::new()),
            CandidateObservedFlags {
                body_present: true,
                parent_ready: true,
                local_collated: false,
            },
        )
        .await;

    let cache = group.state_resolver_cache.lock().await;
    let entry = cache
        .try_get_entry(&block_id)
        .expect("observation must be cached even when the body fails to deserialize");
    assert!(entry.data.is_none(), "invalid body must not be stored");
    assert!(entry.flags.body_present, "body_present flag must be preserved");
    assert!(entry.flags.parent_ready, "parent_ready flag must be preserved");
}

/// A catchain group so `on_generate_slot` reaches the shared `is_collating`
/// compare-and-swap guard without taking the simplex parent-availability path
/// (which a simplex group would require an `Explicit` parent and a wired resolver
/// backend for). Construction mirrors [`make_simplex_group_for_resolver_tests`].
fn make_catchain_group_for_cas_tests() -> Arc<ValidatorGroup> {
    let local_key: PrivateKey =
        Ed25519KeyOption::<ZeroizingBytes>::generate().expect("key must be generated");
    let validator_descr = ValidatorDescr::with_params(
        SigPubKey::from_bytes(local_key.pub_key().expect("pubkey bytes"))
            .expect("valid sig pubkey"),
        1,
        None,
    );
    let validator_set =
        ValidatorSet::with_cc_seqno(0, 0, 0, 1, vec![validator_descr]).expect("validator set");
    let session_info = Arc::new(GeneralSessionInfo {
        shard: ShardIdent::masterchain(),
        opts_hash: UInt256::default(),
        catchain_seqno: 1,
        key_seqno: 0,
        max_vertical_seqno: 0,
    });
    let group = ValidatorGroup::new(
        session_info,
        local_key,
        UInt256::rand(),
        UInt256::rand(),
        validator_set,
        0,
        ConsensusOptions::Catchain(Default::default()),
        Arc::new(DummyEngine),
        false,
        None,
    );
    Arc::new(group)
}

/// Non-cancelled [`AsyncCollationRequest`] mock: `on_generate_slot` only reads its id /
/// cancelled flag / creation time before reaching the guard under test (collation
/// deadlines inherit the trait defaults).
struct CasDummyRequest;

impl AsyncRequest for CasDummyRequest {
    fn cancel(&self) {}
    fn get_request_id(&self) -> u32 {
        0
    }
    fn is_cancelled(&self) -> bool {
        false
    }
    fn get_creation_time(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH
    }
}

impl validator_session::AsyncCollationRequest for CasDummyRequest {}

/// `on_generate_slot` must not silently drop a collation request when the
/// single-collation guard is already held. Under simplex the callback is the only
/// signal back to the `CollationController`, so a dropped request would strand its
/// `block_generation_active` marker and wedge the pipeline. When the `is_collating`
/// CAS fails, the request is reported as failed through the callback and the guard
/// belonging to the in-flight collation is left untouched.
#[tokio::test(flavor = "multi_thread")]
async fn on_generate_slot_reports_error_when_already_collating() {
    let group = make_catchain_group_for_cas_tests();

    // A collation pipeline is already running: the CAS check must fail.
    group.is_collating.store(true, Ordering::Relaxed);

    let source = Ed25519KeyOption::<ZeroizingBytes>::generate().expect("generate key");
    let source_info = validator_session::BlockSourceInfo {
        source: source.into(),
        priority: consensus_common::BlockCandidatePriority {
            round: 0,
            priority: 0,
            first_block_round: 0,
        },
    };
    let request: validator_session::AsyncCollationRequestPtr = Arc::new(CasDummyRequest);

    let outcome = Arc::new(Mutex::new(None));
    let sink = outcome.clone();
    let callback: ValidatorBlockCandidateCallback = Box::new(move |res| {
        *sink.lock().expect("callback sink poisoned") = Some(res.is_err());
    });

    group.on_generate_slot(source_info, request, CollationParentHint::Implicit, callback).await;

    assert_eq!(
        *outcome.lock().expect("callback sink poisoned"),
        Some(true),
        "a CAS failure must report the request as failed through the callback, not drop it"
    );
    assert!(group.is_collating(), "the CAS failure must not reset the in-flight collation's guard");
}

#[test]
fn test_stale_finalized_rebroadcast_suppression_none_allows() {
    assert!(!should_suppress_stale_finalized_rebroadcast(None, 0));
    assert!(!should_suppress_stale_finalized_rebroadcast(None, 100));
}

#[test]
fn test_stale_finalized_rebroadcast_suppression_matches_cpp_cutoff() {
    assert!(!should_suppress_stale_finalized_rebroadcast(Some(0), 0));
    assert!(!should_suppress_stale_finalized_rebroadcast(Some(1), 0));
    assert!(!should_suppress_stale_finalized_rebroadcast(Some(2), 0));

    // C++ condition uses strict `< last_mc_finalized_seqno - 2`.
    assert!(!should_suppress_stale_finalized_rebroadcast(Some(10), 8));
    assert!(should_suppress_stale_finalized_rebroadcast(Some(10), 7));
}

#[test]
fn test_sync_last_notified_mc_finalized_seqno_is_monotonic() {
    let mut group = make_group_impl_for_start_tests();

    let top10 = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        10,
        UInt256::from([0x03; 32]),
        UInt256::from([0x04; 32]),
    );
    sync_last_notified_mc_finalized_seqno(&mut group, &top10);
    assert_eq!(group.last_notified_mc_finalized_seqno, Some(10));

    let top7 = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        7,
        UInt256::from([0x05; 32]),
        UInt256::from([0x06; 32]),
    );
    sync_last_notified_mc_finalized_seqno(&mut group, &top7);
    assert_eq!(
        group.last_notified_mc_finalized_seqno,
        Some(10),
        "external notify cursor must stay monotonic"
    );
}

#[test]
fn test_mc_fork_prevention_none_allows() {
    let parent0 = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        0,
        UInt256::from([0x01; 32]),
        UInt256::from([0x02; 32]),
    );
    let parent100 = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        100,
        UInt256::from([0x11; 32]),
        UInt256::from([0x12; 32]),
    );
    assert!(!should_reject_stale_mc_candidate(None, &parent0));
    assert!(!should_reject_stale_mc_candidate(None, &parent100));
}

#[test]
fn test_mc_fork_prevention_equal_allows() {
    let block = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        10,
        UInt256::from([0x21; 32]),
        UInt256::from([0x22; 32]),
    );
    assert!(!should_reject_stale_mc_candidate(Some(&block), &block));
}

#[test]
fn test_mc_fork_prevention_ahead_allows() {
    let accepted = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        10,
        UInt256::from([0x31; 32]),
        UInt256::from([0x32; 32]),
    );
    let parent11 = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        11,
        UInt256::from([0x41; 32]),
        UInt256::from([0x42; 32]),
    );
    let parent100 = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        100,
        UInt256::from([0x51; 32]),
        UInt256::from([0x52; 32]),
    );
    assert!(!should_reject_stale_mc_candidate(Some(&accepted), &parent11));
    assert!(!should_reject_stale_mc_candidate(Some(&accepted), &parent100));
}

#[test]
fn test_mc_fork_prevention_stale_rejects() {
    let accepted10 = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        10,
        UInt256::from([0x61; 32]),
        UInt256::from([0x62; 32]),
    );
    let parent9 = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        9,
        UInt256::from([0x71; 32]),
        UInt256::from([0x72; 32]),
    );
    let parent0 = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        0,
        UInt256::from([0x81; 32]),
        UInt256::from([0x82; 32]),
    );
    let accepted100 = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        100,
        UInt256::from([0x91; 32]),
        UInt256::from([0x92; 32]),
    );
    let parent50 = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        50,
        UInt256::from([0xa1; 32]),
        UInt256::from([0xa2; 32]),
    );
    assert!(should_reject_stale_mc_candidate(Some(&accepted10), &parent9));
    assert!(should_reject_stale_mc_candidate(Some(&accepted10), &parent0));
    assert!(should_reject_stale_mc_candidate(Some(&accepted100), &parent50));
}

#[test]
fn test_mc_fork_prevention_same_seqno_conflicting_parent_rejects() {
    let accepted = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        10,
        UInt256::from([0xb1; 32]),
        UInt256::from([0xb2; 32]),
    );
    let stale_same_seqno = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        10,
        UInt256::from([0xb0; 32]),
        UInt256::from([0xb2; 32]),
    );
    let ahead_same_seqno = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        10,
        UInt256::from([0xb2; 32]),
        UInt256::from([0xb2; 32]),
    );
    assert!(should_reject_stale_mc_candidate(Some(&accepted), &stale_same_seqno));
    assert!(
        !should_reject_stale_mc_candidate(Some(&accepted), &ahead_same_seqno),
        "strict C++ parity compares full BlockIdExt order: only parent<head is stale"
    );
}

#[tokio::test]
async fn test_wait_for_mc_validation_parent_waits_for_accepted_head() {
    let candidate_block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        8,
        UInt256::from([0x41; 32]),
        UInt256::from([0x42; 32]),
    );
    let candidate_parent_block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        7,
        UInt256::from([0x51; 32]),
        UInt256::from([0x52; 32]),
    );
    let (tx, rx) = tokio::sync::watch::channel(None);
    let wait_parent_block_id = candidate_parent_block_id.clone();

    let wait_task = tokio::spawn(async move {
        wait_for_mc_validation_parent(rx, &candidate_block_id, &wait_parent_block_id).await
    });

    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        !wait_task.is_finished(),
        "C++ parity: validation must wait until accepted head reaches the candidate parent"
    );

    tx.send(Some(candidate_parent_block_id)).expect("watch receiver should still be alive");
    assert!(wait_task.await.expect("wait task join").is_ok());
}

#[tokio::test]
async fn test_wait_for_mc_validation_parent_genesis_parent_waits_until_accepted_head_arrives() {
    let candidate_block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        1,
        UInt256::from([0x53; 32]),
        UInt256::from([0x54; 32]),
    );
    let genesis_parent_block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        0,
        UInt256::from([0xdb; 32]),
        UInt256::from([0xdc; 32]),
    );
    let (tx, rx) = tokio::sync::watch::channel(None);

    let wait_parent_block_id = genesis_parent_block_id.clone();
    let wait_task = tokio::spawn(async move {
        wait_for_mc_validation_parent(rx, &candidate_block_id, &wait_parent_block_id).await
    });

    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        !wait_task.is_finished(),
        "strict C++ parity waits while accepted_head < expected_parent (including genesis)"
    );

    tx.send(Some(genesis_parent_block_id)).expect("watch receiver should still be alive");
    assert!(wait_task.await.expect("wait task join").is_ok());
}

#[tokio::test]
async fn test_wait_for_mc_validation_parent_rejects_stale_branch() {
    let candidate_block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        11,
        UInt256::from([0x61; 32]),
        UInt256::from([0x62; 32]),
    );
    let candidate_parent_block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        9,
        UInt256::from([0x71; 32]),
        UInt256::from([0x72; 32]),
    );
    let accepted_head = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        10,
        UInt256::from([0x81; 32]),
        UInt256::from([0x82; 32]),
    );
    let (_tx, rx) = tokio::sync::watch::channel(Some(accepted_head));

    let err = wait_for_mc_validation_parent(rx, &candidate_block_id, &candidate_parent_block_id)
        .await
        .expect_err("stale parent must be rejected");
    assert!(
        err.to_string().contains("MC fork prevention"),
        "error should explain why the stale branch was rejected"
    );
}

#[tokio::test]
async fn test_wait_for_mc_validation_parent_rejects_same_seqno_conflicting_parent() {
    let candidate_block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        11,
        UInt256::from([0x91; 32]),
        UInt256::from([0x92; 32]),
    );
    let candidate_parent_block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        10,
        UInt256::from([0x11; 32]),
        UInt256::from([0x12; 32]),
    );
    let accepted_head = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        10,
        UInt256::from([0x11; 32]),
        UInt256::from([0x13; 32]),
    );
    let (_tx, rx) = tokio::sync::watch::channel(Some(accepted_head));

    let err = wait_for_mc_validation_parent(rx, &candidate_block_id, &candidate_parent_block_id)
        .await
        .expect_err("same-seqno conflicting parent must be rejected");
    assert!(
        err.to_string().contains("MC fork prevention"),
        "error should explain why the conflicting same-seqno branch was rejected"
    );
}

#[tokio::test]
async fn test_wait_for_mc_validation_parent_same_seqno_higher_hash_waits_then_resolves() {
    let candidate_block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        11,
        UInt256::from([0xa1; 32]),
        UInt256::from([0xa2; 32]),
    );
    let candidate_parent_block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        10,
        UInt256::from([0x33; 32]),
        UInt256::from([0x12; 32]),
    );
    let accepted_head = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        10,
        UInt256::from([0x11; 32]),
        UInt256::from([0x13; 32]),
    );
    let (tx, rx) = tokio::sync::watch::channel(Some(accepted_head));
    let wait_parent_block_id = candidate_parent_block_id.clone();

    let wait_task = tokio::spawn(async move {
        wait_for_mc_validation_parent(rx, &candidate_block_id, &wait_parent_block_id).await
    });

    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        !wait_task.is_finished(),
        "when candidate_parent > accepted_head in full BlockIdExt order, strict C++ parity waits"
    );

    tx.send(Some(candidate_parent_block_id)).expect("watch receiver should still be alive");
    assert!(wait_task.await.expect("wait task join").is_ok());
}

#[test]
fn test_sync_last_accepted_mc_head_from_block_is_monotonic() {
    let mut group = make_group_impl_for_start_tests();

    let top10 = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        10,
        UInt256::from([0x11; 32]),
        UInt256::from([0x12; 32]),
    );
    sync_last_accepted_mc_head_from_block(&mut group, &top10);
    assert_eq!(group.last_accepted_mc_seqno, Some(10));
    assert_eq!(group.last_accepted_mc_block_id.as_ref(), Some(&top10));

    let top7 = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        7,
        UInt256::from([0x21; 32]),
        UInt256::from([0x22; 32]),
    );
    sync_last_accepted_mc_head_from_block(&mut group, &top7);
    assert_eq!(group.last_accepted_mc_seqno, Some(10));
    assert_eq!(group.last_accepted_mc_block_id.as_ref(), Some(&top10));

    let top10_new_hash = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        10,
        UInt256::from([0x11; 32]),
        UInt256::from([0x13; 32]),
    );
    sync_last_accepted_mc_head_from_block(&mut group, &top10_new_hash);
    assert_eq!(group.last_accepted_mc_seqno, Some(10));
    assert_eq!(group.last_accepted_mc_block_id.as_ref(), Some(&top10_new_hash));

    let top11 = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        11,
        UInt256::from([0x31; 32]),
        UInt256::from([0x32; 32]),
    );
    sync_last_accepted_mc_head_from_block(&mut group, &top11);
    assert_eq!(group.last_accepted_mc_seqno, Some(11));
    assert_eq!(group.last_accepted_mc_block_id.as_ref(), Some(&top11));
}

#[test]
fn test_sync_last_accepted_mc_head_from_block_seeds_genesis_head() {
    let mut group = make_group_impl_for_start_tests();

    let genesis = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        0,
        UInt256::from([0xdd; 32]),
        UInt256::from([0xde; 32]),
    );
    sync_last_accepted_mc_head_from_block(&mut group, &genesis);

    assert_eq!(group.last_accepted_mc_seqno, Some(0));
    assert_eq!(group.last_accepted_mc_block_id.as_ref(), Some(&genesis));
}

#[test]
fn test_initial_accepted_mc_head_from_start_inputs_falls_back_to_min_mc_when_prev_empty() {
    let shard = ShardIdent::masterchain();
    let min_mc = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        0,
        UInt256::from([0xca; 32]),
        UInt256::from([0xcb; 32]),
    );
    let prev: Vec<BlockIdExt> = Vec::new();

    let initial = initial_accepted_mc_head_from_start_inputs(&shard, &prev, &min_mc);
    assert_eq!(
        initial.as_ref(),
        Some(&min_mc),
        "strict C++ parity: startup MC accepted head must not remain None when prevs are empty"
    );
}

#[test]
fn test_initial_accepted_mc_head_from_start_inputs_prefers_prev_head_when_available() {
    let shard = ShardIdent::masterchain();
    let min_mc = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        0,
        UInt256::from([0xca; 32]),
        UInt256::from([0xcb; 32]),
    );
    let prev_head = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        1,
        UInt256::from([0xda; 32]),
        UInt256::from([0xdb; 32]),
    );
    let prev = vec![prev_head.clone()];

    let initial = initial_accepted_mc_head_from_start_inputs(&shard, &prev, &min_mc);
    assert_eq!(
        initial.as_ref(),
        Some(&prev_head),
        "startup MC accepted head should use exact prev head when present"
    );
}

#[test]
fn test_initial_accepted_mc_head_from_start_inputs_non_masterchain_returns_none() {
    let shard = ShardIdent::with_tagged_prefix(0, 0x8000_0000_0000_0000).unwrap();
    let min_mc = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        0,
        UInt256::from([0xca; 32]),
        UInt256::from([0xcb; 32]),
    );
    let prev = vec![BlockIdExt::with_params(
        ShardIdent::masterchain(),
        1,
        UInt256::from([0xda; 32]),
        UInt256::from([0xdb; 32]),
    )];

    let initial = initial_accepted_mc_head_from_start_inputs(&shard, &prev, &min_mc);
    assert!(initial.is_none(), "non-masterchain groups must not seed MC accepted head");
}

#[test]
fn test_publish_accepted_mc_head_persists_value_without_active_receivers() {
    let group = make_simplex_group_for_resolver_tests();
    let block_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        7,
        UInt256::from([0x41; 32]),
        UInt256::from([0x42; 32]),
    );

    // No receiver is held across this call, so plain watch::send would drop the update.
    group.publish_accepted_mc_head(Some(block_id.clone()));

    let rx = group.accepted_mc_block_tx.subscribe();
    assert_eq!(
        rx.borrow().as_ref(),
        Some(&block_id),
        "accepted MC head must be retained for future subscribers"
    );
}

#[test]
fn test_publish_accepted_mc_seqno_persists_value_without_active_receivers() {
    let group = make_simplex_group_for_resolver_tests();
    group.publish_accepted_mc_seqno(Some(11));

    let rx = group.accepted_mc_seqno_tx.subscribe();
    assert_eq!(*rx.borrow(), Some(11), "accepted MC seqno must be retained for future subscribers");
}

#[test]
fn test_prepare_start_immediate_keeps_created_and_marks_pending() {
    let mut group = make_group_impl_for_start_tests();

    assert!(group.prepare_start());
    assert!(group.status == ValidatorGroupStatus::Created);
    assert!(group.start_pending);
}

#[test]
fn test_prepare_start_keeps_created_status() {
    let mut group = make_group_impl_for_start_tests();

    assert!(group.prepare_start());
    assert!(group.status == ValidatorGroupStatus::Created);
    assert!(group.start_pending);
}

#[test]
fn test_prepare_start_rejects_duplicate_pending_start() {
    let mut group = make_group_impl_for_start_tests();

    assert!(group.prepare_start());
    assert!(!group.prepare_start());
    assert!(group.status == ValidatorGroupStatus::Created);
    assert!(group.start_pending);
}

#[test]
fn test_reset_after_start_failure_restores_retryable_state() {
    let mut group = make_group_impl_for_start_tests();

    assert!(group.prepare_start());
    group.reset_after_start_failure();

    assert!(group.status == ValidatorGroupStatus::Created);
    assert!(!group.start_pending);
    assert!(group.session.is_none());
}

// --- Status ordering / transition table tests (WS6) ---

#[test]
fn test_status_ordering_is_monotonic() {
    let states = [
        ValidatorGroupStatus::Created,
        ValidatorGroupStatus::EngineCreated,
        ValidatorGroupStatus::Sync,
        ValidatorGroupStatus::Active,
        ValidatorGroupStatus::Stopping,
        ValidatorGroupStatus::Stopped,
    ];
    for i in 0..states.len() {
        for j in i + 1..states.len() {
            assert!(states[i] < states[j], "{} must be < {}", states[i], states[j]);
        }
    }
}

#[test]
fn test_before_allows_forward_transitions() {
    let created = ValidatorGroupStatus::Created;
    let engine_created = ValidatorGroupStatus::EngineCreated;
    let sync = ValidatorGroupStatus::Sync;
    let active = ValidatorGroupStatus::Active;
    let stopping = ValidatorGroupStatus::Stopping;

    assert!(created.before(&engine_created));
    assert!(engine_created.before(&sync));
    assert!(sync.before(&active));
    assert!(active.before(&stopping));
}

#[test]
fn test_before_rejects_backward_transitions() {
    let sync = ValidatorGroupStatus::Sync;
    let active = ValidatorGroupStatus::Active;
    let created = ValidatorGroupStatus::Created;

    assert!(!active.before(&sync));
    assert!(!sync.before(&created));
}

#[test]
fn test_engine_created_state_between_created_and_sync() {
    let created = ValidatorGroupStatus::Created;
    let engine_created = ValidatorGroupStatus::EngineCreated;
    let sync = ValidatorGroupStatus::Sync;

    assert!(created < engine_created);
    assert!(engine_created < sync);
    assert!(created.before(&engine_created));
    assert!(engine_created.before(&sync));
}

#[test]
fn test_prepare_start_accepts_engine_created_state() {
    let mut group = make_group_impl_for_start_tests();
    group.status = ValidatorGroupStatus::EngineCreated;

    assert!(group.prepare_start());
    assert!(group.status == ValidatorGroupStatus::EngineCreated);
    assert!(group.start_pending);
}

#[test]
fn test_prepare_start_rejects_sync_and_later_states() {
    for status in [
        ValidatorGroupStatus::Sync,
        ValidatorGroupStatus::Active,
        ValidatorGroupStatus::Stopping,
        ValidatorGroupStatus::Stopped,
    ] {
        let mut group = make_group_impl_for_start_tests();
        group.status = status;
        assert!(!group.prepare_start(), "prepare_start should reject status {}", status);
    }
}

// --- Stale-future culling predicate tests (mirrors manager.cpp equal+related) ---

/// Reproduces the stale-future culling predicate from validator_manager.rs
/// to verify correctness in isolation with various shard topologies.
fn should_cull_future(
    active_shard: &ShardIdent,
    active_cc: u32,
    future_shard: &ShardIdent,
    future_cc: u32,
) -> bool {
    let shards_equal = active_shard == future_shard;
    let shards_related =
        active_shard.is_ancestor_for(future_shard) || future_shard.is_ancestor_for(active_shard);
    let equal_condition = shards_equal && active_cc >= future_cc;
    let related_condition = shards_related && active_cc > future_cc;
    equal_condition || related_condition
}

#[test]
fn test_cull_same_shard_equal_seqno() {
    let shard = ShardIdent::with_tagged_prefix(0, 0x8000_0000_0000_0000).unwrap();
    assert!(should_cull_future(&shard, 5, &shard, 5));
}

#[test]
fn test_cull_same_shard_higher_active_seqno() {
    let shard = ShardIdent::with_tagged_prefix(0, 0x8000_0000_0000_0000).unwrap();
    assert!(should_cull_future(&shard, 6, &shard, 5));
}

#[test]
fn test_no_cull_same_shard_lower_active_seqno() {
    let shard = ShardIdent::with_tagged_prefix(0, 0x8000_0000_0000_0000).unwrap();
    assert!(!should_cull_future(&shard, 4, &shard, 5));
}

#[test]
fn test_cull_ancestor_shard_higher_seqno() {
    let parent = ShardIdent::with_tagged_prefix(0, 0x8000_0000_0000_0000).unwrap();
    let child = ShardIdent::with_tagged_prefix(0, 0x4000_0000_0000_0000).unwrap();
    assert!(parent.is_ancestor_for(&child));
    assert!(should_cull_future(&parent, 6, &child, 5));
}

#[test]
fn test_cull_descendant_shard_higher_seqno() {
    let parent = ShardIdent::with_tagged_prefix(0, 0x8000_0000_0000_0000).unwrap();
    let child = ShardIdent::with_tagged_prefix(0, 0x4000_0000_0000_0000).unwrap();
    assert!(should_cull_future(&child, 6, &parent, 5));
}

#[test]
fn test_no_cull_related_shard_equal_seqno() {
    let parent = ShardIdent::with_tagged_prefix(0, 0x8000_0000_0000_0000).unwrap();
    let child = ShardIdent::with_tagged_prefix(0, 0x4000_0000_0000_0000).unwrap();
    // For related (non-equal) shards, the condition is strict >
    assert!(!should_cull_future(&parent, 5, &child, 5));
}

#[test]
fn test_no_cull_unrelated_shards() {
    let shard_a = ShardIdent::with_tagged_prefix(0, 0x4000_0000_0000_0000).unwrap();
    let shard_b = ShardIdent::with_tagged_prefix(0, 0xC000_0000_0000_0000).unwrap();
    assert!(!shard_a.is_ancestor_for(&shard_b));
    assert!(!shard_b.is_ancestor_for(&shard_a));
    assert!(!should_cull_future(&shard_a, 100, &shard_b, 1));
}

#[test]
fn test_no_cull_different_workchain() {
    let shard_wc0 = ShardIdent::with_tagged_prefix(0, 0x8000_0000_0000_0000).unwrap();
    let shard_wc1 = ShardIdent::with_tagged_prefix(1, 0x8000_0000_0000_0000).unwrap();
    assert!(!should_cull_future(&shard_wc0, 10, &shard_wc1, 5));
}

#[test]
fn test_metric_label_covers_all_states() {
    let states = vec![
        (ValidatorGroupStatus::Created, "created"),
        (ValidatorGroupStatus::EngineCreated, "engine_created"),
        (ValidatorGroupStatus::Sync, "sync"),
        (ValidatorGroupStatus::Active, "active"),
        (ValidatorGroupStatus::Stopping, "stopping"),
        (ValidatorGroupStatus::Stopped, "stopped"),
    ];
    for (status, expected_label) in states {
        assert_eq!(status.metric_label(), expected_label, "metric_label mismatch for {}", status);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn pq_live_group_uses_stable_local_identity_through_accept_and_broadcast() {
    use super::accept_block::live_pq_tests::{node_fixture, PqAcceptEngine};
    use std::sync::atomic::AtomicUsize;
    let (block, state, _, full_set, carrier) = node_fixture("current", "finalize");
    let config = state.shard_state_extra().unwrap().config.clone();
    let (members, _) = full_set
        .calc_subset(
            &config.catchain_config().unwrap(),
            block.id().shard().shard_prefix_with_tag(),
            0,
            7,
        )
        .unwrap();
    let source = consensus_common::ValidatorIdentity::from_descriptor(
        members.iter().find(|v| v.validator_id().unwrap() == UInt256::from([1; 32])).unwrap(),
    )
    .unwrap();
    let set = ValidatorSet::with_cc_seqno(0, 100000, 2, 7, members).unwrap();
    let transport = Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[0x50; 32]).unwrap();
    assert_ne!(source.id(), transport.id());
    let storage = crate::collator_test_bundle::create_block_handle_storage(None).unwrap();
    let handle = storage
        .create_handle(block.id().clone(), storage::types::BlockMeta::default(), None)
        .unwrap()
        .unwrap();
    handle.set_data();
    handle.set_state();
    let engine = Arc::new(PqAcceptEngine {
        handle,
        state,
        proof: Default::default(),
        proofs: AtomicUsize::new(0),
        tops: AtomicUsize::new(0),
        broadcasts: AtomicUsize::new(0),
    });
    let info = Arc::new(GeneralSessionInfo {
        shard: block.id().shard().clone(),
        opts_hash: UInt256::default(),
        catchain_seqno: 7,
        key_seqno: 10,
        max_vertical_seqno: 0,
    });
    let group = ValidatorGroup::new(
        info,
        transport,
        carrier.session_id.clone(),
        UInt256::default(),
        set,
        0,
        ConsensusOptions::Simplex(Default::default()),
        engine.clone(),
        false,
        None,
    );
    assert_eq!(group.local_identity.as_ref().unwrap().id(), source.id());
    let mut corrupt = carrier.clone();
    corrupt.signatures[0].signature[0] ^= 1;
    group
        .on_block_finalized(
            block.id().clone(),
            99,
            source.clone(),
            block.id().root_hash.clone(),
            block.id().file_hash.clone(),
            ConsensusCommonFactory::create_block_payload(
                block.block().unwrap().write_to_bytes().unwrap(),
            ),
            consensus_common::SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(corrupt)),
            vec![],
        )
        .await;
    assert_eq!(engine.proofs.load(Ordering::Relaxed), 0);
    group
        .on_block_finalized(
            block.id().clone(),
            99,
            source,
            block.id().root_hash.clone(),
            block.id().file_hash.clone(),
            ConsensusCommonFactory::create_block_payload(
                block.block().unwrap().write_to_bytes().unwrap(),
            ),
            consensus_common::SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(carrier)),
            vec![],
        )
        .await;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while engine.broadcasts.load(Ordering::Relaxed) == 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(engine.proofs.load(Ordering::Relaxed), 1);
    assert_eq!(engine.tops.load(Ordering::Relaxed), 1);
    assert_eq!(
        engine.broadcasts.load(Ordering::Relaxed),
        1,
        "local PQ creator must retain broadcast ownership"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_group_stop_survives_cancelled_waiter_and_is_idempotent() {
    let group = make_simplex_group_for_resolver_tests();
    let session = Arc::new(MockSimplexSession::default());
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    *session.stop_gate.lock().unwrap() = Some((entered_tx, release_rx));
    let holder = Arc::new(super::consensus::SessionHolder::simplex(session.clone()));
    group.group_impl.execute_sync(|inner| inner.session = Some(holder)).await;
    let first = tokio::spawn(group.clone().stop(tokio::runtime::Handle::current(), false));
    tokio::time::timeout(Duration::from_secs(5), entered_rx).await.unwrap().unwrap();
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    let second = tokio::spawn(group.clone().stop(tokio::runtime::Handle::current(), false));
    release_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), second).await.unwrap().unwrap().unwrap();
    group.clone().stop(tokio::runtime::Handle::current(), false).await.unwrap();
    assert_eq!(session.stop_calls.load(Ordering::Relaxed), 1);
    assert!(group
        .stop(tokio::runtime::Handle::current(), true)
        .await
        .unwrap_err()
        .to_string()
        .contains("preserve/destroy"));
}

struct StoreGateEngine {
    entered: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
}
#[async_trait::async_trait]
impl EngineOperations for StoreGateEngine {
    async fn store_block(
        &self,
        _: &crate::block::BlockStuff,
    ) -> Result<crate::internal_db::BlockResult> {
        self.entered.add_permits(1);
        self.release.acquire().await.unwrap().forget();
        fail!("controlled store completion")
    }
}

#[tokio::test(flavor = "current_thread")]
async fn test_group_stop_drains_actual_validation_queue_action() {
    let engine = Arc::new(StoreGateEngine {
        entered: tokio::sync::Semaphore::new(0),
        release: tokio::sync::Semaphore::new(0),
    });
    let group = make_simplex_group_for_engine(engine.clone());
    let mut block = Block::default();
    block.set_global_id(42);
    let bytes = block.write_to_bytes().unwrap();
    let id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        77,
        block.serialize().unwrap().repr_hash().clone(),
        UInt256::calc_file_hash(&bytes),
    );
    let receiver = group.receiver.lock().unwrap().take().unwrap();
    let queue_group = group.clone();
    let rt = tokio::runtime::Handle::current();
    group.spawn_task(&rt.clone(), async move {
        process_validation_queue(receiver, queue_group, rt).await
    });
    group
        .action_queue
        .send(ValidationAction::OnCandidateObserved {
            block_id: id.clone(),
            data: ConsensusCommonFactory::create_block_payload(bytes),
            collated_data: ConsensusCommonFactory::create_block_payload(Vec::new()),
            flags: CandidateObservedFlags {
                body_present: true,
                parent_ready: false,
                local_collated: false,
            },
        })
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), engine.entered.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    let mut stopped = Box::pin(group.clone().stop(tokio::runtime::Handle::current(), false));
    assert!(futures::poll!(&mut stopped).is_pending());
    group.session_exit_observed.cancelled().await;
    let returned_before_action = futures::poll!(&mut stopped).is_ready();
    let status_before_action = group.get_status().await;
    engine.release.add_permits(1);
    assert!(!returned_before_action, "stop returned with a live validation action");
    assert!(status_before_action == ValidatorGroupStatus::Stopping);
    tokio::time::timeout(Duration::from_secs(5), stopped).await.unwrap().unwrap();
    assert!(group.tasks.is_empty());
    assert!(group.action_queue.is_closed());
}

#[tokio::test(flavor = "current_thread")]
async fn test_group_stop_joins_real_simplex_threads_and_reopens_preserved_database() {
    let directory = tempfile::tempdir().unwrap();
    let group = make_simplex_group_for_resolver_tests();
    for _ in 0..2 {
        let options = simplex::SessionOptions { wait_for_db_init: true, ..Default::default() };
        let nodes = vec![consensus_common::SessionNode {
            adnl_id: group.local_key.id().clone(),
            public_key: group.local_key.clone(),
            weight: 1,
        }];
        let session = simplex::SessionFactory::create_session(
            &options,
            &group.session_id,
            &group.shard,
            nodes,
            &group.local_key,
            directory.path().to_str().unwrap().to_owned(),
            ConsensusCommonFactory::create_dummy_overlay_manager(),
            group.make_validator_session_callback(),
            None,
            1,
        )
        .unwrap();
        // Each iteration is a new manager-owned group using the same real session DB.
        let owner = make_simplex_group_for_resolver_tests();
        let holder = Arc::new(super::consensus::SessionHolder::simplex(session.clone()));
        owner.group_impl.execute_sync(|inner| inner.session = Some(holder)).await;
        tokio::time::timeout(
            Duration::from_secs(10),
            owner.clone().stop(tokio::runtime::Handle::current(), false),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(session.is_stopped());
        assert!(!session.is_panicked());
        assert!(directory.path().read_dir().unwrap().next().is_some());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn test_group_stop_blocking_join_panic_does_not_certify_worker_exit() {
    let group = make_simplex_group_for_resolver_tests();
    let session = Arc::new(MockSimplexSession::default());
    session.panic_on_stop.store(true, Ordering::Relaxed);
    let holder = Arc::new(super::consensus::SessionHolder::simplex(session));
    group.group_impl.execute_sync(|inner| inner.session = Some(holder)).await;
    let error = group.clone().stop(tokio::runtime::Handle::current(), false).await.unwrap_err();
    assert!(error.to_string().contains("session teardown failed"));
    assert!(!group.teardown_drained(), "a failed join must not certify consensus exit");
}
