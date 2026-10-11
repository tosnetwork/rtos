// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Actual Engine historical sink tests; private-network service replay follows separately.
use super::*;
use crate::{
    propagation_outbox::{Limits, PropagationOutbox, PublicationStage},
    validator::{
        accept_block::AcceptancePhase, retired_session_auth::authenticate_retired_session,
    },
};
use consensus_common::{
    finality_delivery::{DurableFinalitySinkPtr, FinalizedDeliveryDraft},
    session_runtime::LocalRole,
    BlockCandidatePriority, BlockSourceInfo, ConsensusCommonFactory, SessionFinality,
    ValidatorIdentity,
};

fn locator(fixture: &SpoolFixture) -> simplex::finality_recovery::SessionRecoveryRecord {
    let runtime = &fixture.runtime;
    let root = std::path::PathBuf::from(fixture.engine.db_root_dir().unwrap()).join("catchains");
    simplex::finality_recovery::SessionRecoveryRecord {
        pin: runtime.pin().clone(),
        binding: runtime.recovery_binding().unwrap().clone(),
        protocol: runtime.protocol(),
        carrier_version: runtime.carrier_version(),
        wire_profile: runtime.wire_profile(),
        profile: runtime.profile().clone(),
        session_id: runtime.session_id().clone(),
        local_adnl: UInt256::from(*runtime.local_adnl().data()),
        local_validator_index: match runtime.local_role() {
            LocalRole::Validator(index) => Some(index),
            LocalRole::Observer => None,
        },
        prev_blocks: vec![fixture.block.construct_prev_id().unwrap().0],
        start_masterchain: runtime.recovery_binding().unwrap().governing_masterchain.clone(),
        namespace: runtime.runtime_directory(root.to_str().unwrap()).unwrap().into(),
    }
}
fn draft(fixture: &SpoolFixture, final_role: bool) -> FinalizedDeliveryDraft {
    let mut row = fixture.row.clone();
    if !final_role {
        row["signatures"] = row["approval_signatures"].clone();
    }
    let mut carrier = fixture_carrier(&row);
    carrier.slot = row["slot"].as_u64().unwrap() as u32;
    FinalizedDeliveryDraft {
        block_id: fixture.block.id().clone(),
        source_info: BlockSourceInfo {
            source: ValidatorIdentity::from_descriptor(&fixture.runtime.committee()[0]).unwrap(),
            priority: BlockCandidatePriority { round: 99, first_block_round: 0, priority: 0 },
        },
        data: ConsensusCommonFactory::create_block_payload(fixture.block.data().to_vec()),
        finality: if final_role {
            SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(carrier))
        } else {
            SessionFinality::PqApproval(
                rtos_api::pq_finality::PqApproval::from_notarization_fields(carrier).unwrap(),
            )
        },
        last_mc_finalized_seqno: 0,
        candidate_already_sent: false,
        created_at_unix_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    }
}
async fn stage(sink: &DurableFinalitySinkPtr, draft: FinalizedDeliveryDraft) -> Result<UInt256> {
    let (sent, received) = tokio::sync::oneshot::channel();
    sink.stage(
        draft,
        Box::new(move |result| {
            let _ = sent.send(result);
        }),
    )?;
    tokio::time::timeout(Duration::from_secs(20), received)
        .await
        .map_err(|_| rtos_block::error!("Historical sink WAL completion timeout"))?
        .map_err(|error| rtos_block::error!("Historical sink completion dropped: {error}"))?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retired_service_historical_sink_accepts_without_key_and_reauthenticates_each_block() {
    for row in 0..2 {
        for final_role in [false, true] {
            let fixture = SpoolFixture::new_for_transport(row, 0x60).await;
            let recovery = locator(&fixture);
            let valid = draft(&fixture, final_role);
            let mut wrong_creator = valid.clone();
            wrong_creator.source_info.source =
                ValidatorIdentity::from_descriptor(&fixture.runtime.committee()[1]).unwrap();
            let mut wrong_body = valid.clone();
            let mut bytes = fixture.block.data().to_vec();
            bytes[0] ^= 1;
            wrong_body.data = ConsensusCommonFactory::create_block_payload(bytes);
            let mut bad_carrier = fixture_carrier(&fixture.row);
            bad_carrier.slot = fixture.row["slot"].as_u64().unwrap() as u32;
            if !final_role {
                let mut approval = fixture.row.clone();
                approval["signatures"] = approval["approval_signatures"].clone();
                bad_carrier = fixture_carrier(&approval);
                bad_carrier.slot = fixture.row["slot"].as_u64().unwrap() as u32;
            }
            bad_carrier.signatures[0].signature[0] ^= 1;
            let mut wrong_signature = valid.clone();
            wrong_signature.finality = if final_role {
                SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(bad_carrier))
            } else {
                SessionFinality::PqApproval(
                    rtos_api::pq_finality::PqApproval::from_notarization_fields(bad_carrier)
                        .unwrap(),
                )
            };
            let SpoolFixture { dir, engine, runtime, block, state_root, .. } = fixture;
            engine.clone().wait_stop().await.unwrap();
            drop(engine);
            let path = dir.path().join("config.json");
            let mut config: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            config["validator_key_ring"] = serde_json::json!({});
            config["consensus_transport_bindings"] = serde_json::json!([]);
            std::fs::write(path, serde_json::to_vec(&config).unwrap()).unwrap();
            let reopened = open_engine(dir.path()).await;
            let result = std::panic::AssertUnwindSafe(async {
                assert!(reopened.adnl_key_by_id(runtime.local_adnl()).is_none());
                let authenticated =
                    authenticate_retired_session(reopened.as_ref(), &recovery).await.unwrap();
                let sink = reopened
                    .ensure_publication_worker()
                    .await
                    .unwrap()
                    .historical_sink(&authenticated)
                    .unwrap();
                for rejected in [wrong_creator, wrong_body, wrong_signature] {
                    assert!(
                        stage(&sink, rejected).await.is_err(),
                        "session receipt bypassed per-block authentication"
                    );
                }
                assert!(reopened.load_block_handle(block.id()).unwrap().is_none());
                let id = stage(&sink, valid.clone()).await.unwrap();
                assert_eq!(stage(&sink, valid).await.unwrap(), id);
                let accepted = tokio::time::timeout(
                    Duration::from_secs(20),
                    reopened.clone().await_publication(id.clone()),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(accepted.block(), &block);
                assert_eq!(accepted.is_final(), final_role);
                assert_eq!(accepted.phase(), AcceptancePhase::Preapplied);
                assert_eq!(
                    reopened.load_state(block.id()).await.unwrap().root_cell().repr_hash(),
                    &state_root
                );
                id
            })
            .catch_unwind()
            .await;
            reopened.clone().wait_stop().await.unwrap();
            drop(reopened);
            let id = result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
            let reopened = open_engine(dir.path()).await;
            let result = std::panic::AssertUnwindSafe(async {
                let domain = crate::propagation_outbox::OutboxDomain {
                    zerostate: recovery.pin.zerostate,
                    global_id: recovery.pin.global_id,
                    wire_profile: recovery.wire_profile,
                };
                let ledger =
                    PropagationOutbox::open(reopened.db().clone(), domain, Limits::default())
                        .unwrap();
                assert_eq!(
                    ledger.pending().unwrap().len(),
                    1,
                    "rejected/duplicate evidence created durable debt"
                );
                let (delivery, entry) = ledger.delivery(&id).unwrap().unwrap();
                assert_eq!(entry.stage, PublicationStage::AcceptedDraft);
                assert!(entry.pending.is_empty() && entry.record.effects.is_empty());
                assert!(!entry.record.locally_generated, "target60 must not impersonate creator61");
                assert_eq!(delivery.origin.unwrap().local_adnl, recovery.local_adnl);
                assert_eq!(entry.record.block_data, block.data());
                assert_eq!(
                    reopened.load_state(block.id()).await.unwrap().root_cell().repr_hash(),
                    &state_root
                );
                assert!(!reopened.load_block_handle(block.id()).unwrap().unwrap().is_applied());
            })
            .catch_unwind()
            .await;
            reopened.clone().wait_stop().await.unwrap();
            drop(reopened);
            result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        }
    }
}

use consensus_common::{
    AsyncCollationRequestPtr, BlockHash, BlockPayloadPtr, CandidateObservedFlags,
    CollationParentHint, ConsensusOverlayListener, ConsensusOverlayLogReplayListener,
    ConsensusOverlayManagerPtr, ConsensusOverlayPtr, OverlayTransportType, PrivateKey, PublicKey,
    PublicKeyHash, QueryResponseCallback, SessionListener, SessionStats,
    ValidatorBlockCandidateCallback, ValidatorBlockCandidateDecisionCallback,
};
use rtos_api::IntoBoxed;

#[derive(Default)]
struct SocketListener {
    observed: std::sync::atomic::AtomicUsize,
}
impl SessionListener for SocketListener {
    fn on_candidate(
        &self,
        _: BlockSourceInfo,
        _: BlockHash,
        _: BlockPayloadPtr,
        _: BlockPayloadPtr,
        done: ValidatorBlockCandidateDecisionCallback,
    ) {
        done(Err(rtos_block::error!("Fixture has no voting authority")));
    }
    fn on_generate_slot(
        &self,
        _: BlockSourceInfo,
        _: AsyncCollationRequestPtr,
        _: CollationParentHint,
        done: ValidatorBlockCandidateCallback,
    ) {
        done(Err(rtos_block::error!("Fixture cannot collate")));
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
        done: ValidatorBlockCandidateCallback,
    ) {
        done(Err(rtos_block::error!("Fixture never supplies candidate bodies")));
    }
    fn on_candidate_observed(
        &self,
        _: BlockIdExt,
        _: BlockPayloadPtr,
        _: BlockPayloadPtr,
        _: CandidateObservedFlags,
    ) {
        self.observed.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }
}
impl ConsensusOverlayListener for SocketListener {
    fn on_message(&self, _: PublicKeyHash, _: &BlockPayloadPtr) {}
    fn on_broadcast(
        &self,
        _: PublicKeyHash,
        _: &BlockPayloadPtr,
        _: consensus_common::BroadcastSource,
    ) {
    }
    fn on_query(&self, _: PublicKeyHash, _: &BlockPayloadPtr, done: QueryResponseCallback) {
        done(Err(rtos_block::error!("Raw emitter has no candidate cache")));
    }
}
impl ConsensusOverlayLogReplayListener for SocketListener {
    fn on_time_changed(&self, _: std::time::SystemTime) {}
}

fn socket_manager(f: &SpoolFixture) -> ConsensusOverlayManagerPtr {
    Arc::new(crate::validator::consensus_overlay::ConsensusOverlayManagerImpl::new(
        f.engine.validator_network(),
        f.runtime.session_id().clone(),
        None,
    ))
}
fn socket_key(f: &SpoolFixture) -> PrivateKey {
    f.engine.adnl_key_by_id(f.runtime.local_adnl()).unwrap()
}
fn connect_socket(left: &SpoolFixture, right: &SpoolFixture) {
    let local = left.engine.network().context();
    let remote = right.engine.network().context();
    let remote_key = socket_key(right);
    local
        .stack
        .adnl
        .add_peer(left.runtime.local_adnl(), remote.stack.adnl.ip_address_adnl(), None, &remote_key)
        .unwrap();
    local
        .stack
        .quic
        .as_ref()
        .unwrap()
        .add_peer_key(
            remote_key.id().clone(),
            remote.stack.quic.as_ref().unwrap().local_addr(remote_key.id()).unwrap(),
        )
        .unwrap();
}
/// Explicit trusted fixture setup, separate from session admission/recovery.
/// Uses the same real async RocksDB factory as SimplexDb; no marker-file stand-in.
async fn provision_socket_namespace(f: &SpoolFixture) {
    let receipt = authenticate_retired_session(f.engine.as_ref(), &locator(f)).await.unwrap();
    let runtime = receipt.runtime().clone();
    let directory = receipt.record().namespace.clone();
    tokio::task::spawn_blocking(move || {
        use std::io::Write;
        assert!(!directory.exists(), "fresh fixture provisioning must never repair existing state");
        std::fs::create_dir_all(&directory).unwrap();
        let database = ConsensusCommonFactory::create_async_key_value_storage(
            &directory, &runtime.session_id().to_hex_string(),
            consensus_common::AsyncKeyValueStorageOptions { use_callback_thread: false },
        ).unwrap();
        database.close(None).unwrap();
        drop(database);
        assert!(directory.join(runtime.session_id().to_hex_string()).join("CURRENT").is_file());
        let LocalRole::Validator(index) = runtime.local_role() else { panic!("validator fixture required") };
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema":1,"role":"validator","validator_index":Some(index),
            "local_adnl":hex::encode(runtime.local_adnl().data()),
            "global_id":runtime.pin().global_id,"zerostate":runtime.pin().zerostate.to_string(),
            "profile":runtime.profile().to_hex_string(),"session":runtime.session_id().to_hex_string(),
            "shard_workchain":runtime.shard().workchain_id(),"shard_prefix":runtime.shard().shard_prefix_with_tag(),
            "catchain_seqno":runtime.catchain_seqno(),"simplex_protocol":runtime.protocol().version(),
            "carrier_version":runtime.carrier_version(),"wire_profile":runtime.wire_profile() as u8,
            "slots_per_window":runtime.slots_per_leader_window(),"committee":runtime.committee_digest().unwrap().to_hex_string(),
        })).unwrap();
        let mut manifest = std::fs::OpenOptions::new().write(true).create_new(true).open(directory.join("session-runtime.json")).unwrap();
        manifest.write_all(&bytes).unwrap(); manifest.sync_all().unwrap();
        std::fs::File::open(&directory).unwrap().sync_all().unwrap();
        std::fs::File::open(directory.parent().unwrap()).unwrap().sync_all().unwrap();
    }).await.unwrap();
}

async fn live_socket_session(
    f: &SpoolFixture,
    listener: &Arc<SocketListener>,
) -> simplex::SessionPtr {
    let receipt = authenticate_retired_session(f.engine.as_ref(), &locator(f)).await.unwrap();
    let sink =
        f.engine.ensure_publication_worker().await.unwrap().historical_sink(&receipt).unwrap();
    let listener: Arc<dyn SessionListener + Send + Sync> = listener.clone();
    let options = receipt.options().clone();
    let runtime = f.runtime.clone();
    let key = socket_key(f);
    let path = receipt.record().namespace.to_string_lossy().into_owned();
    let manager = socket_manager(f);
    let session = tokio::task::spawn_blocking(move || {
        match simplex::SessionFactory::create_authenticated_session_checked(
            &options,
            runtime,
            &key,
            path,
            manager,
            Arc::downgrade(&listener),
            None,
            Some(sink),
        ) {
            Ok(session) => session,
            Err(mut failure) => {
                while !failure.retry_cleanup() {
                    std::thread::sleep(Duration::from_millis(10));
                }
                panic!("Checked socket fixture construction: {failure}");
            }
        }
    })
    .await
    .unwrap();
    session.start(receipt.record().prev_blocks.clone(), receipt.record().start_masterchain.clone());
    session
}
async fn stop_socket_session(session: simplex::SessionPtr) {
    let retained = session.clone();
    let result = tokio::task::spawn_blocking(move || session.stop_checked()).await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !retained.namespace_drained() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(retained.threads_drained() && retained.namespace_drained());
    result.unwrap();
}

struct RawSocket {
    manager: ConsensusOverlayManagerPtr,
    overlay: ConsensusOverlayPtr,
    id: PublicKeyHash,
    _listener: Arc<SocketListener>,
}
impl RawSocket {
    fn start(f: &SpoolFixture) -> Self {
        let listener = Arc::new(SocketListener::default());
        let events: Arc<dyn ConsensusOverlayListener + Send + Sync> = listener.clone();
        let replay: Arc<dyn ConsensusOverlayLogReplayListener + Send + Sync> = listener.clone();
        let manager = socket_manager(f);
        let id = f.runtime.overlay_short_id().unwrap();
        let overlay = manager
            .start_authenticated_overlay(
                &socket_key(f),
                &id,
                f.runtime.clone(),
                Arc::downgrade(&events),
                Arc::downgrade(&replay),
                OverlayTransportType::SimplexQuic,
            )
            .unwrap();
        Self { manager, overlay, id, _listener: listener }
    }
    async fn stop(self) {
        tokio::task::spawn_blocking(move || {
            self.manager.stop_overlay_checked(&self.id, &self.overlay).unwrap();
            assert!(self.manager.overlay_drained(&self.overlay));
        })
        .await
        .unwrap();
    }
}

fn native_candidate(f: &SpoolFixture, row: &serde_json::Value) -> Vec<u8> {
    use rtos_api::ton::consensus::{candidatedata, candidateid::CandidateId, CandidateParent};
    let slot = row["slot"].as_u64().unwrap() as u32;
    let leader =
        &f.runtime.committee()[row["trigger_leader_subset_index"].as_u64().unwrap() as usize];
    let original_index = leader.validator_id().unwrap().as_slice()[0] as usize - 1;
    let signature = decode(&row["candidate_signatures"][original_index]["signature"]);
    let wire = if slot == 99 {
        let inner = rtos_api::ton::validator_session::candidate::Candidate {
            src: UInt256::default(),
            round: f.block.id().seq_no as i32,
            root_hash: f.block.id().root_hash.clone(),
            data: f.block.data().to_vec(),
            collated_data: vec![],
        }
        .into_boxed();
        candidatedata::Block {
            slot: slot as i32,
            candidate: rtos_api::serialize_boxed(&inner).unwrap(),
            parent: CandidateParent::Consensus_CandidateWithoutParents,
            signature,
        }
        .into_boxed()
    } else {
        let candidate = decode(&row["candidate"]);
        candidatedata::Empty {
            slot: slot as i32,
            block: f.block.id().clone(),
            parent: CandidateId { slot: 99, hash: UInt256::from_slice(&candidate[88..120]) }
                .into_boxed(),
            signature,
        }
        .into_boxed()
    };
    rtos_api::WireProfile::T0.serialize(&wire).unwrap()
}
fn native_certificate(f: &SpoolFixture, row: &serde_json::Value, final_vote: bool) -> Vec<u8> {
    use rtos_api::ton::consensus::{
        candidateid::CandidateId,
        simplex::{
            certificate::Certificate,
            unsignedvote::{FinalizeVote, NotarizeVote},
            votesignature::VoteSignature,
            votesignatureset::VoteSignatureSet,
        },
    };
    let votes = f
        .runtime
        .committee()
        .iter()
        .enumerate()
        .map(|(index, member)| {
            let original = member.validator_id().unwrap().as_slice()[0] as usize - 1;
            VoteSignature {
                who: index as i32,
                signature: decode(
                    &row[if final_vote { "signatures" } else { "approval_signatures" }][original]
                        ["signature"],
                ),
            }
            .into_boxed()
        })
        .collect();
    let id = CandidateId {
        slot: row["slot"].as_u64().unwrap() as i32,
        hash: UInt256::calc_file_hash(&decode(&row["candidate"])),
    }
    .into_boxed();
    let vote = if final_vote {
        FinalizeVote { id }.into_boxed()
    } else {
        NotarizeVote { id }.into_boxed()
    };
    let wire =
        Certificate { vote, signatures: VoteSignatureSet { votes }.into_boxed() }.into_boxed();
    rtos_api::WireProfile::T0.serialize(&wire).unwrap()
}

fn broadcast_native(raw: &RawSocket, sender: &SpoolFixture, row: &serde_json::Value) {
    let extra = rtos_api::ton::consensus::broadcastextra::BroadcastExtra {
        slot: row["slot"].as_u64().unwrap() as i32,
    }
    .into_boxed();
    raw.overlay.send_broadcast_fec_ex(
        sender.runtime.local_adnl(),
        sender.runtime.local_adnl(),
        ConsensusCommonFactory::create_block_payload(native_candidate(sender, row)),
        Some(rtos_api::WireProfile::T0.serialize(&extra).unwrap()),
    );
}
async fn query_cached_native(
    raw: &RawSocket,
    sender: &SpoolFixture,
    provider: &SpoolFixture,
    row: &serde_json::Value,
) {
    use rtos_api::ton::{
        consensus::candidateid::CandidateId, rpc::consensus::simplex::RequestCandidate,
    };
    let request = RequestCandidate {
        id: CandidateId {
            slot: row["slot"].as_u64().unwrap() as i32,
            hash: UInt256::calc_file_hash(&decode(&row["candidate"])),
        }
        .into_boxed(),
        want_candidate: true.into(),
        want_notar: true.into(),
    };
    let payload = ConsensusCommonFactory::create_block_payload(
        rtos_api::WireProfile::T0.serialize(&request).unwrap(),
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let (sent, received) = tokio::sync::oneshot::channel();
        raw.overlay.send_query(
            provider.runtime.local_adnl(),
            sender.runtime.local_adnl(),
            "fixture requestCandidate",
            Duration::from_secs(2),
            &payload,
            Box::new(move |result| {
                let _ = sent.send(result);
            }),
        );
        if let Ok(Ok(Ok(reply))) = tokio::time::timeout(Duration::from_secs(3), received).await {
            if let Ok(answer) = rtos_api::WireProfile::T0
                .deserialize_typed::<rtos_api::ton::consensus::simplex::CandidateAndCert>(
                reply.data(),
            ) {
                let expected = native_candidate(provider, row);
                if answer.candidate() == &expected && !answer.notar().is_empty() {
                    return;
                }
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "Actual provider never served native candidate+notarization"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn retired_service_socket_missing_body_reaches_node_wal_and_checked_join() {
    for final_row in 0..2 {
        let input: serde_json::Value =
            serde_json::from_str(include_str!("testdata/v2-retired-socket.json")).unwrap();
        let mut target = SpoolFixture::from_transport_fixture(input.clone(), final_row, 0x61).await;
        let seed = |index: usize| {
            0x60 + target.runtime.committee()[index].validator_id().unwrap().as_slice()[0] - 1
        };
        let mut emitter =
            SpoolFixture::from_transport_fixture(input.clone(), final_row, seed(1)).await;
        let provider =
            SpoolFixture::from_transport_fixture(input.clone(), final_row, seed(2)).await;
        let listener = Arc::new(SocketListener::default());
        let mut sessions = Vec::<simplex::SessionPtr>::new();
        let mut raws = Vec::<RawSocket>::new();
        let result = std::panic::AssertUnwindSafe(async {
            // Warm a genuine Receiver using each candidate's actual leader identity.
            for (left, right) in [
                (&target, &provider),
                (&provider, &target),
                (&emitter, &provider),
                (&provider, &emitter),
            ] {
                connect_socket(left, right);
            }
            provision_socket_namespace(&provider).await;
            let provider_session = live_socket_session(&provider, &listener).await;
            sessions.push(provider_session.clone());
            raws.push(RawSocket::start(&target));
            broadcast_native(raws.last().unwrap(), &target, &input["rows"][0]);
            raws.last().unwrap().overlay.send_message(
                provider.runtime.local_adnl(),
                target.runtime.local_adnl(),
                &ConsensusCommonFactory::create_block_payload(native_certificate(
                    &target,
                    &input["rows"][0],
                    false,
                )),
                false,
            );
            query_cached_native(raws.last().unwrap(), &target, &provider, &input["rows"][0]).await;
            raws.pop().unwrap().stop().await;
            if final_row == 1 {
                raws.push(RawSocket::start(&emitter));
                broadcast_native(raws.last().unwrap(), &emitter, &input["rows"][1]);
                raws.last().unwrap().overlay.send_message(
                    provider.runtime.local_adnl(),
                    emitter.runtime.local_adnl(),
                    &ConsensusCommonFactory::create_block_payload(native_certificate(
                        &emitter,
                        &input["rows"][1],
                        false,
                    )),
                    false,
                );
                query_cached_native(raws.last().unwrap(), &emitter, &provider, &input["rows"][1])
                    .await;
                raws.pop().unwrap().stop().await;
            }
            // Remove all live provider gossip before creating the target's bodyless debt.
            // Provider candidates remain only in its real session storage.
            stop_socket_session(provider_session).await;
            restart_socket_engine(&mut target, &provider.engine).await;
            restart_socket_engine(&mut emitter, &provider.engine).await;
            connect_socket(&target, &emitter);
            connect_socket(&emitter, &target);
            provision_socket_namespace(&target).await;
            let target_session = live_socket_session(&target, &listener).await;
            sessions.push(target_session.clone());
            raws.push(RawSocket::start(&emitter));
            raws.last().unwrap().overlay.send_message(
                target.runtime.local_adnl(),
                emitter.runtime.local_adnl(),
                &ConsensusCommonFactory::create_block_payload(native_certificate(
                    &emitter,
                    &input["rows"][final_row],
                    true,
                )),
                false,
            );
            let intent = locator(&target).namespace.join("finality-intents").join(format!(
                "{}-{}.json",
                input["rows"][final_row]["slot"].as_u64().unwrap(),
                UInt256::calc_file_hash(&decode(&input["rows"][final_row]["candidate"]))
                    .to_hex_string()
            ));
            tokio::time::timeout(Duration::from_secs(20), async {
                while !intent.is_file() {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("Live target never retained the real FinalCert");
            assert!(!target_session.finality_recovery_complete());
            assert!(
                target.engine.load_block_handle(target.block.id()).unwrap().is_none(),
                "body appeared before any provider route"
            );
            stop_socket_session(target_session).await;
            raws.pop().unwrap().stop().await;
            let source_root =
                std::path::PathBuf::from(target.engine.db_root_dir().unwrap()).join("catchains");
            assert_eq!(
                simplex::finality_recovery::scan_finality_recovery(&source_root).unwrap().len(),
                1
            );
            restart_socket_engine(&mut target, &provider.engine).await;
            // Only now can the restored target contact the genuine provider.
            connect_socket(&target, &provider);
            connect_socket(&provider, &target);
            let expected = expected_socket_record(&target);
            let id = crate::propagation_outbox::delivery_id(&expected).unwrap();
            let service = target.engine.ensure_retired_session_recovery().await.unwrap();
            tokio::time::timeout(Duration::from_secs(20), async {
                while service.snapshot().active != 1 {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("Retired owner never entered unresolved source session");
            // A real receiver/owner is running, but the only body provider is stopped.
            for _ in 0..10 {
                assert_eq!(service.snapshot().completed, 0);
                assert!(crate::propagation_outbox::inspect_delivery(
                    target.engine.db(),
                    &expected.domain,
                    &Limits::default(),
                    &id
                )
                .unwrap()
                .is_none());
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            let replies = provider
                .engine
                .network()
                .test_broadcast_faults
                .capture_candidate_replies(*target.runtime.local_adnl().data());
            sessions.push(live_socket_session(&provider, &listener).await);
            tokio::time::timeout(Duration::from_secs(40), async {
                while service.snapshot().completed != 1 {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("Retired owner did not fetch body and acknowledge node WAL");
            assert_eq!(service.snapshot().active, 0);
            let replies = replies.lock().unwrap().clone();
            for row in 0..=final_row {
                let candidate = native_candidate(&provider, &input["rows"][row]);
                assert!(
                    replies.iter().any(|wire| rtos_api::WireProfile::T0
                        .deserialize_typed::<rtos_api::ton::consensus::simplex::CandidateAndCert>(
                            wire
                        )
                        .is_ok_and(|answer| answer.candidate() == &candidate)),
                    "Recovery did not receive actual provider candidate row {row}"
                );
            }

            let accepted = tokio::time::timeout(
                Duration::from_secs(20),
                target.engine.clone().await_publication(id.clone()),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(accepted.block(), &target.block);
            assert_eq!(accepted.phase(), AcceptancePhase::Preapplied);
            let (_, entry) = crate::propagation_outbox::inspect_delivery(
                target.engine.db(),
                &expected.domain,
                &Limits::default(),
                &id,
            )
            .unwrap()
            .unwrap();
            assert_eq!(entry.stage, PublicationStage::AcceptedDraft);
            assert_eq!(entry.record.block_data, target.block.data());
            // The source scanner can reopen only after checked session/namespace drain.
            assert!(simplex::finality_recovery::scan_finality_recovery(&source_root)
                .unwrap()
                .is_empty());
            assert_eq!(
                target.engine.load_state(target.block.id()).await.unwrap().root_cell().repr_hash(),
                &target.state_root
            );
            assert!(!target
                .engine
                .load_block_handle(target.block.id())
                .unwrap()
                .unwrap()
                .is_applied());
        })
        .catch_unwind()
        .await;
        for raw in raws {
            raw.stop().await;
        }
        for session in sessions {
            stop_socket_session(session).await;
        }
        target.engine.clone().wait_stop().await.unwrap();
        provider.engine.clone().wait_stop().await.unwrap();
        emitter.engine.clone().wait_stop().await.unwrap();
        result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        let expected = expected_socket_record(&target);
        let id = crate::propagation_outbox::delivery_id(&expected).unwrap();
        let stopped = std::mem::replace(&mut target.engine, emitter.engine.clone());
        drop(stopped);
        let reopened = open_engine(target.dir.path()).await;
        let checked = std::panic::AssertUnwindSafe(async {
            let ledger =
                PropagationOutbox::open(reopened.db().clone(), expected.domain, Limits::default())
                    .unwrap();
            let (_, entry) =
                ledger.delivery(&id).unwrap().expect("Node takeover disappeared after reopen");
            assert_eq!(entry.stage, PublicationStage::AcceptedDraft);
            assert_eq!(entry.record.block_data, target.block.data());
            assert_eq!(
                reopened.load_state(target.block.id()).await.unwrap().root_cell().repr_hash(),
                &target.state_root
            );
            assert!(!reopened.load_block_handle(target.block.id()).unwrap().unwrap().is_applied());
            let root = std::path::PathBuf::from(reopened.db_root_dir().unwrap()).join("catchains");
            assert!(simplex::finality_recovery::scan_finality_recovery(&root).unwrap().is_empty());
        })
        .catch_unwind()
        .await;
        reopened.clone().wait_stop().await.unwrap();
        checked.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    }
}

fn expected_socket_record(f: &SpoolFixture) -> crate::propagation_outbox::PublicationRecord {
    let mut carrier = fixture_carrier(&f.row);
    carrier.slot = f.row["slot"].as_u64().unwrap() as u32;
    let network =
        rtos_api::pq_finality::PqNetworkSignatureSet::from_final_fields(&carrier).unwrap();
    crate::propagation_outbox::PublicationRecord {
        domain: crate::propagation_outbox::OutboxDomain {
            zerostate: f.runtime.pin().zerostate.clone(),
            global_id: f.runtime.pin().global_id,
            wire_profile: f.runtime.wire_profile(),
        },
        protocol: f.runtime.protocol(),
        profile: f.runtime.profile().clone(),
        session_id: f.runtime.session_id().clone(),
        block_id: f.block.id().clone(),
        block_data: f.block.data().to_vec(),
        proof_data: None,
        prev: vec![f.block.construct_prev_id().unwrap().0],
        carrier: crate::propagation_outbox::StoredCarrier::Final(
            f.runtime.wire_profile().serialize(&network.to_node().into_boxed()).unwrap(),
        ),
        locally_generated: true,
        created_at_unix_secs: 0,
        expires_at_unix_secs: 0,
        effects: vec![],
    }
}

async fn restart_socket_engine(fixture: &mut SpoolFixture, placeholder: &Arc<Engine>) {
    let previous = std::mem::replace(&mut fixture.engine, placeholder.clone());
    previous.clone().wait_stop().await.unwrap();
    drop(previous);
    fixture.engine = open_engine(fixture.dir.path()).await;
}
