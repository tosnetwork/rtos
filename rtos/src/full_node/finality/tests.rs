// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{
    block::BlockStuff,
    block_proof::BlockProofStuff,
    internal_db::BlockResult,
    validator::accept_block::{create_new_proof_link, live_pq_tests::node_fixture},
};
use rtos_api::{
    pq_finality::{PqApproval, PqNetworkSignatureSet},
    IntoBoxed, WireProfile,
};
use rtos_block::BlockSignaturesSimplexPq;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use storage::block_handle_db::BlockHandle;

fn evidence(carrier: &BlockSignaturesSimplexPq) -> NetworkSignatureSet {
    NetworkSignatureSet::PostQuantum(PqNetworkSignatureSet::from_final_fields(carrier).unwrap())
}
fn peer(byte: u8) -> Arc<KeyId> {
    KeyId::from_data([byte; 32])
}

#[test]
fn pending_finality_has_exact_sender_capacity_and_expiry_bounds() {
    let (block, _, _, _, carrier) = node_fixture("current", "finalize");
    let id = block.id().clone();
    let now = Instant::now();
    let mut store = PendingFinality::default();
    assert!(store.admit(id.clone(), peer(1), evidence(&carrier), 0, false, now).is_err());
    assert!(store
        .admit(id.clone(), peer(1), evidence(&carrier), CARRIER_BYTES + 1, false, now)
        .is_err());
    for n in 0..4 {
        let mut next = id.clone();
        next.seq_no += n;
        store.admit(next, peer(1), evidence(&carrier), CARRIER_BYTES, false, now).unwrap();
    }
    let mut next = id.clone();
    next.seq_no += 4;
    assert!(store.admit(next, peer(1), evidence(&carrier), 1, false, now).is_err());
    assert!(store.admit(id.clone(), peer(1), evidence(&carrier), 1, false, now).is_err());
    for byte in 2..=13 {
        store.admit(id.clone(), peer(byte), evidence(&carrier), CARRIER_BYTES, false, now).unwrap();
    }
    assert!(store.admit(id.clone(), peer(14), evidence(&carrier), 1, false, now).is_err());
    store.admit(id.clone(), peer(14), evidence(&carrier), CARRIER_BYTES, true, now).unwrap();
    store.expire(now + RETENTION - Duration::from_nanos(1));
    assert!(!store.entries.is_empty());
    store.expire(now + RETENTION);
    assert!(store.entries.is_empty());
    store.admit(id, peer(1), evidence(&carrier), 1, false, now + RETENTION).unwrap();
}

#[test]
fn pending_finality_reserved_capacity_uses_transport_identity_and_exact_coordinates() {
    let (block, state, _, set, carrier) = node_fixture("current", "finalize");
    let mut store = PendingFinality::default();
    let transport = set.list()[0].adnl_addr().unwrap();
    let stable = KeyId::from_data(*set.list()[0].validator_id().unwrap().as_array());
    assert_ne!(transport, stable);
    assert!(store.reserved(&state, block.id(), &carrier.validator_info, &transport).unwrap());
    assert!(!store.reserved(&state, block.id(), &carrier.validator_info, &stable).unwrap());
    let mut bad = carrier.validator_info.clone();
    bad.catchain_seqno += 2;
    assert!(!store.reserved(&state, block.id(), &bad, &transport).unwrap());
    let mut bad = carrier.validator_info.clone();
    bad.validator_list_hash_short ^= 1;
    assert!(!store.reserved(&state, block.id(), &bad, &transport).unwrap());
    assert_eq!(store.authorities.len(), 1, "claimed hashes must not create memo entries");
    let (child, _) = block.id().shard().split().unwrap();
    let mut child_id = block.id().clone();
    child_id.shard_id = child;
    assert!(!store.reserved(&state, &child_id, &carrier.validator_info, &transport).unwrap());
}

struct RecoveryEngine {
    state: Arc<ShardStateStuff>,
    block: BlockStuff,
    stopped: AtomicBool,
    downloads: AtomicUsize,
    stores: AtomicUsize,
    observed: tokio::sync::Notify,
    #[cfg(feature = "telemetry")]
    telemetry: crate::full_node::telemetry::FullNodeTelemetry,
}
#[async_trait::async_trait]
impl EngineOperations for RecoveryEngine {
    fn check_stop(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }
    async fn load_last_applied_mc_state(&self) -> Result<Arc<ShardStateStuff>> {
        Ok(self.state.clone())
    }
    async fn download_block(
        &self,
        id: &BlockIdExt,
        limit: Option<u32>,
    ) -> Result<(BlockStuff, BlockProofStuff)> {
        assert_eq!(id, self.block.id());
        assert_eq!(limit, Some(1));
        self.downloads.fetch_add(1, Ordering::SeqCst);
        let block = BlockStuff::deserialize_block_checked(id.clone(), self.block.data_arc())?;
        let proof = create_new_proof_link(&block)?;
        self.observed.notify_one();
        Ok((block, proof))
    }
    fn load_block_handle(&self, _: &BlockIdExt) -> Result<Option<Arc<BlockHandle>>> {
        Ok(None)
    }
    async fn store_block(&self, block: &BlockStuff) -> Result<BlockResult> {
        assert_eq!(block.id(), self.block.id());
        assert_eq!(block.data(), self.block.data());
        self.stores.fetch_add(1, Ordering::SeqCst);
        self.observed.notify_one();
        fail!("authenticated storage boundary")
    }
    #[cfg(feature = "telemetry")]
    fn full_node_telemetry(&self) -> &crate::full_node::telemetry::FullNodeTelemetry {
        &self.telemetry
    }
}
fn engine() -> (Arc<RecoveryEngine>, BlockSignaturesSimplexPq) {
    let (block, state, _, _, carrier) = node_fixture("current", "finalize");
    (
        Arc::new(RecoveryEngine {
            state,
            block,
            stopped: AtomicBool::new(false),
            downloads: AtomicUsize::new(0),
            stores: AtomicUsize::new(0),
            observed: tokio::sync::Notify::new(),
            #[cfg(feature = "telemetry")]
            telemetry: Default::default(),
        }),
        carrier,
    )
}

#[tokio::test]
async fn pq_finality_regular_download_checks_before_storage() {
    let (engine, carrier) = engine();
    let ops: Arc<dyn EngineOperations> = engine.clone();
    let result = recover(&ops, engine.block.id(), &evidence(&carrier)).await.unwrap_err();
    assert_eq!(result.to_string(), "authenticated storage boundary");
    assert_eq!(engine.stores.load(Ordering::SeqCst), 1);
    let mut bad = carrier.clone();
    bad.signatures[0].signature[0] ^= 1;
    recover(&ops, engine.block.id(), &evidence(&bad)).await.unwrap();
    assert_eq!(
        engine.stores.load(Ordering::SeqCst),
        1,
        "bad evidence must be retired before any storage"
    );
    let (block, state, _, _, approve) = node_fixture("current", "notarize");
    let approval = PqNetworkSignatureSet::from_approval(
        &PqApproval::from_notarization_fields(approve).unwrap(),
    )
    .unwrap();
    let verified = super::super::shard_client::validate_pq_broadcast(
        &approval,
        &state,
        block.id(),
        block.block().unwrap(),
    )
    .unwrap();
    assert!(!verified.is_final());
    assert!(verified.into_final().is_err());
}

#[tokio::test]
async fn finality_ingress_worker_uses_download_and_releases_on_stop() {
    let (engine, carrier) = engine();
    let pending: SharedPendingFinality = Default::default();
    let wire = BlockFinalityBroadcast {
        id: engine.block.id().clone(),
        signature_set: PqNetworkSignatureSet::from_final_fields(&carrier)
            .unwrap()
            .to_node()
            .into_boxed(),
    };
    let bytes = WireProfile::T0.serialize(&wire.clone().into_boxed()).unwrap();
    assert!(receive(engine.clone(), pending.clone(), wire.clone(), peer(80), 0).await.is_err());
    assert_eq!(engine.downloads.load(Ordering::SeqCst), 0);
    receive(engine.clone(), pending.clone(), wire, peer(80), bytes.len()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while engine.stores.load(Ordering::SeqCst) == 0 {
            engine.observed.notified().await;
        }
    })
    .await
    .unwrap();
    engine.stopped.store(true, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if pending.lock().workers == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(pending.lock().entries.is_empty());
}

#[tokio::test]
#[ignore = "requires isolated reproducible 400-key public capacity fixture"]
async fn authenticated_max_parented_finality_download_and_admission() {
    use rtos_block::*;
    let path = std::env::var("RTOS_CAPACITY_FIXTURE").unwrap();
    let data: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let row = &data["rows"][0];
    let bytes = |value: &serde_json::Value| hex::decode(value.as_str().unwrap()).unwrap();
    let candidate = bytes(&row["candidate"]);
    let parsed: rtos_api::ton::consensus::CandidateHashData =
        WireProfile::T0.deserialize_typed(&candidate).unwrap();
    let block = BlockStuff::deserialize_block_checked(
        parsed.block().clone(),
        Arc::new(bytes(&row["block_boc"])),
    )
    .unwrap();
    let state = ShardStateUnsplit::construct_from_bytes(&bytes(&data["state_boc"])).unwrap();
    let state = ShardStateStuff::from_state(
        BlockIdExt::with_params(
            ShardIdent::masterchain(),
            10,
            UInt256::from([10; 32]),
            UInt256::from([11; 32]),
        ),
        state,
        #[cfg(feature = "telemetry")]
        &crate::collator_test_bundle::create_engine_telemetry(),
        &crate::collator_test_bundle::create_engine_allocated(),
    )
    .unwrap();
    let signatures = row["signatures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            let mut id = [0; 32];
            id[..4].copy_from_slice(&(row["index"].as_u64().unwrap() as u32 + 1).to_le_bytes());
            PqBlockSignaturePair {
                validator_id: id.into(),
                algorithm_id: 1,
                signature: bytes(&row["signature"]),
            }
        })
        .collect();
    let carrier = BlockSignaturesSimplexPq {
        validator_info: ValidatorBaseInfo::with_params(
            row["subset_hash"].as_u64().unwrap() as u32,
            7,
        ),
        sig_count: 400,
        sig_weight: 400,
        signatures,
        session_id: UInt256::from_slice(&bytes(&row["session"])),
        slot: 99,
        candidate_data: BlockSignaturesSimplex::bytes_to_cell_tree(&candidate).unwrap(),
    };
    let engine = Arc::new(RecoveryEngine {
        state,
        block,
        stopped: AtomicBool::new(false),
        downloads: AtomicUsize::new(0),
        stores: AtomicUsize::new(0),
        observed: tokio::sync::Notify::new(),
        #[cfg(feature = "telemetry")]
        telemetry: Default::default(),
    });
    let ops: Arc<dyn EngineOperations> = engine.clone();
    let error = recover(&ops, engine.block.id(), &evidence(&carrier)).await.unwrap_err();
    assert_eq!(error.to_string(), "authenticated storage boundary");
    assert_eq!(engine.stores.load(Ordering::SeqCst), 1);
    let mut bad = carrier.clone();
    bad.signatures[399].signature[0] ^= 1;
    recover(&ops, engine.block.id(), &evidence(&bad)).await.unwrap();
    assert_eq!(engine.stores.load(Ordering::SeqCst), 1);
    let wire = BlockFinalityBroadcast {
        id: engine.block.id().clone(),
        signature_set: PqNetworkSignatureSet::from_final_fields(&carrier)
            .unwrap()
            .to_node()
            .into_boxed(),
    };
    let wire_bytes = WireProfile::T0.serialize(&wire.clone().into_boxed()).unwrap();
    assert_eq!(wire_bytes.len(), 984300);
    let pending: SharedPendingFinality = Default::default();
    receive(engine.clone(), pending.clone(), wire, peer(81), wire_bytes.len()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while engine.stores.load(Ordering::SeqCst) < 2 {
            engine.observed.notified().await;
        }
    })
    .await
    .unwrap();
    engine.stopped.store(true, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if pending.lock().workers == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(pending.lock().entries.is_empty());
}

#[test]
fn pending_authenticated_strength_and_generation_completion() {
    let (block, _, _, _, carrier) = node_fixture("current", "finalize");
    let id = block.id().clone();
    let now = Instant::now();
    let mut store = PendingFinality::default();
    let first = store.admit(id.clone(), peer(1), evidence(&carrier), 4096, false, now).unwrap();
    let second = store.admit(id.clone(), peer(2), evidence(&carrier), 4096, false, now).unwrap();
    assert!(matches!(store.work(now), Work::Run(_, entry) if entry.generation == first));
    assert!(
        matches!(store.work(now), Work::Stop),
        "one block must have one signature verification in flight"
    );
    store.mark_verified(&id, first);
    assert!(store.admit(id.clone(), peer(3), evidence(&carrier), 4096, false, now).is_err());
    store.complete(&id, first, true);
    assert!(
        !store.entries.contains_key(&id),
        "authenticated final acceptance supersedes trailing candidates"
    );
    let replacement =
        store.admit(id.clone(), peer(2), evidence(&carrier), 4096, false, now).unwrap();
    assert!(replacement > second);
    store.complete(&id, first, true);
    assert_eq!(
        store.entries[&id][0].generation, replacement,
        "stale completion cannot erase a replacement"
    );
    store.complete(&id, replacement, false);
    assert!(store.entries.is_empty());
}

#[test]
fn pending_worker_drop_releases_only_owned_generation() {
    let (block, _, _, _, carrier) = node_fixture("current", "finalize");
    let id = block.id().clone();
    let now = Instant::now();
    let store: SharedPendingFinality = Default::default();
    let generation =
        store.lock().admit(id.clone(), peer(1), evidence(&carrier), 4096, false, now).unwrap();
    store.lock().workers = 1;
    let lease =
        WorkerLease { store: store.clone(), active: Some((id.clone(), generation)), counted: true };
    store.lock().remove(&id, generation);
    let next =
        store.lock().admit(id.clone(), peer(1), evidence(&carrier), 4096, false, now).unwrap();
    drop(lease);
    assert_eq!(store.lock().workers, 0);
    assert_eq!(store.lock().entries[&id][0].generation, next);
    store.lock().workers = 1;
    let lease = WorkerLease { store: store.clone(), active: Some((id, next)), counted: true };
    drop(lease);
    assert!(store.lock().entries.is_empty());
    assert_eq!(store.lock().workers, 0);
}

#[test]
fn pending_verified_upgrade_is_atomic_and_does_not_renew_equal_strength() {
    let (block, _, _, _, carrier) = node_fixture("current", "finalize");
    let id = block.id().clone();
    let now = Instant::now();
    // Policy-unit inputs: production admits Classical only after verification.
    let classical = |is_final| {
        NetworkSignatureSet::Classical(rtos_block::BlockSignaturesVariant::Simplex(
            rtos_block::BlockSignaturesSimplex { is_final, ..Default::default() },
        ))
    };
    let mut store = PendingFinality::default();
    let old = store.admit(id.clone(), peer(1), classical(false), 4096, false, now).unwrap();
    let expiry = store.entries[&id][0].expires;
    assert!(store
        .admit(id.clone(), peer(2), classical(false), 4096, false, now + Duration::from_secs(1))
        .is_err());
    assert_eq!(store.entries[&id][0].expires, expiry);
    let (_, _, _, _, notar) = node_fixture("current", "notarize");
    let notar = NetworkSignatureSet::PostQuantum(
        PqNetworkSignatureSet::from_approval(&PqApproval::from_notarization_fields(notar).unwrap())
            .unwrap(),
    );
    assert!(store.admit(id.clone(), peer(2), notar, 4096, false, now).is_err());
    store.admit(id.clone(), peer(2), evidence(&carrier), 4096, false, now).unwrap();
    assert_eq!(store.entries[&id].len(), 2);
    assert!(store
        .admit(id.clone(), peer(3), classical(true), CARRIER_BYTES + 1, false, now)
        .is_err());
    assert_eq!(store.entries[&id][0].generation, old);
    let new = store.admit(id.clone(), peer(3), classical(true), CARRIER_BYTES, false, now).unwrap();
    assert_eq!(store.entries[&id].len(), 1);
    assert_eq!(store.entries[&id][0].generation, new);
    store.complete(&id, old, true);
    assert_eq!(store.entries[&id][0].generation, new);
    assert!(store.admit(id, peer(4), classical(false), 4096, false, now).is_err());
}
