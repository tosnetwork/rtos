// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use consensus_common::SessionFinality;
use rtos_api::pq_finality::{PqApproval, PqSessionContext};
use rtos_block::{
    BlockSignaturesSimplex, BlockSignaturesSimplexPq, ConfigParams, PqBlockSignaturePair,
};
struct NoIoEngine;
#[async_trait::async_trait]
impl EngineOperations for NoIoEngine {
    fn load_block_handle(&self, _: &BlockIdExt) -> Result<Option<Arc<BlockHandle>>> {
        panic!("unauthenticated finality reached block-handle access")
    }
}
fn fixture(
    kind: &str,
    role: &str,
) -> (BlockIdExt, PqSessionContext, ValidatorSet, BlockSignaturesSimplexPq) {
    let d: serde_json::Value =
        serde_json::from_str(include_str!("../../../tl/rtos_api/tests/data/live-pq.json")).unwrap();
    let bytes = |s: &serde_json::Value| hex::decode(s.as_str().unwrap()).unwrap();
    let config = ConfigParams::construct_from_cell(
        rtos_block::read_single_root_boc(&bytes(&d["config_boc"])).unwrap(),
    )
    .unwrap();
    let set = config.validator_set().unwrap();
    let rows: Vec<_> = d["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| {
            r["kind"] == kind && r["role"] == role && r["context"] == "TOS-CONSENSUS-SIMPLEX-v1"
        })
        .collect();
    let candidate = bytes(&rows[0]["candidate"]);
    let parsed: rtos_api::ton::consensus::CandidateHashData =
        rtos_api::Deserializer::new(&mut std::io::Cursor::new(&candidate)).read_boxed().unwrap();
    let id = parsed.block().clone();
    let session = UInt256::from_slice(&bytes(&d["session"]));
    let context = PqSessionContext::from_authenticated_session_members(
        session.clone(),
        id.shard().clone(),
        7,
        set.list().to_vec(),
    )
    .unwrap();
    let signatures = rows
        .iter()
        .map(|r| PqBlockSignaturePair {
            validator_id: UInt256::from([r["index"].as_u64().unwrap() as u8 + 1; 32]),
            algorithm_id: 1,
            signature: bytes(&r["signature"]),
        })
        .collect();
    let carrier = BlockSignaturesSimplexPq {
        validator_info: context.validator_info(),
        sig_count: 2,
        sig_weight: 3,
        signatures,
        session_id: session,
        slot: 99,
        candidate_data: BlockSignaturesSimplex::bytes_to_cell_tree(&candidate).unwrap(),
    };
    (id, context, set, carrier)
}
#[tokio::test]
async fn pq_live_accept_rejects_before_handle_or_storage() {
    for kind in ["empty", "ordinary", "shard_empty", "shard_ordinary"] {
        let (id, context, set, good) = fixture(kind, "finalize");
        let mut bad = good.clone();
        bad.signatures[0].signature[0] ^= 1;
        let result = accept_session_block(
            id.clone(),
            None,
            vec![BlockIdExt::default()],
            set.clone(),
            SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(bad)),
            Some(context.clone()),
            true,
            Arc::new(NoIoEngine),
        )
        .await;
        assert!(result.is_err());
        assert!(accept_session_block(
            id.clone(),
            None,
            vec![BlockIdExt::default()],
            set.clone(),
            SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(good.clone())),
            None,
            true,
            Arc::new(NoIoEngine)
        )
        .await
        .is_err());
        assert!(accept_session_block(
            id.clone(),
            None,
            vec![BlockIdExt::default()],
            set.clone(),
            SessionFinality::Carrier(BlockSignaturesVariant::Ordinary(BlockSignatures::default())),
            Some(context.clone()),
            true,
            Arc::new(NoIoEngine)
        )
        .await
        .is_err());
        let (_, _, _, notar) = fixture(kind, "notarize");
        assert!(accept_session_block(
            id.clone(),
            None,
            vec![BlockIdExt::default()],
            set.clone(),
            SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(notar)),
            Some(context.clone()),
            true,
            Arc::new(NoIoEngine)
        )
        .await
        .is_err());
        let approval = PqApproval::from_notarization_fields(good).unwrap();
        assert!(accept_session_block(
            id,
            None,
            vec![BlockIdExt::default()],
            set,
            SessionFinality::PqApproval(approval),
            Some(context),
            true,
            Arc::new(NoIoEngine)
        )
        .await
        .is_err());
    }
}
struct AuthenticatedBoundaryEngine;
#[async_trait::async_trait]
impl EngineOperations for AuthenticatedBoundaryEngine {
    fn load_block_handle(&self, _: &BlockIdExt) -> Result<Option<Arc<BlockHandle>>> {
        fail!("authenticated boundary reached")
    }
}
#[tokio::test]
async fn pq_live_accept_valid_quorums_reach_storage_boundary() {
    for (kind, role) in [
        ("empty", "finalize"),
        ("ordinary", "finalize"),
        ("shard_empty", "notarize"),
        ("shard_ordinary", "finalize"),
    ] {
        let (id, context, set, carrier) = fixture(kind, role);
        let finality = if role == "finalize" {
            SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(carrier))
        } else {
            SessionFinality::PqApproval(PqApproval::from_notarization_fields(carrier).unwrap())
        };
        let error = accept_session_block(
            id,
            None,
            vec![BlockIdExt::default()],
            set,
            finality,
            Some(context),
            true,
            Arc::new(AuthenticatedBoundaryEngine),
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "authenticated boundary reached");
    }
}

pub(crate) fn node_fixture(
    kind: &str,
    role: &str,
) -> (BlockStuff, Arc<ShardStateStuff>, PqSessionContext, ValidatorSet, BlockSignaturesSimplexPq) {
    use rtos_block::*;
    let data: serde_json::Value =
        serde_json::from_str(include_str!("../../../tl/rtos_api/tests/data/live-pq-node.json"))
            .unwrap();
    let row = data["rows"].as_array().unwrap().iter().find(|r| r["kind"] == kind).unwrap();
    let bytes = |s: &serde_json::Value| hex::decode(s.as_str().unwrap()).unwrap();
    let config = ConfigParams::construct_from_cell(
        read_single_root_boc(&bytes(&data["config_boc"])).unwrap(),
    )
    .unwrap();
    let candidate = bytes(&row["candidate"]);
    let parsed: rtos_api::ton::consensus::CandidateHashData =
        rtos_api::deserialize_typed(&candidate).unwrap();
    let id = parsed.block().clone();
    let mut set = if kind == "next" {
        config.next_validator_set().unwrap()
    } else {
        config.validator_set().unwrap()
    };
    set.set_catchain_seqno(7);
    let (members, _) =
        set.calc_subset(&config.catchain_config().unwrap(), SHARD_FULL, 0, 7).unwrap();
    let context = PqSessionContext::from_authenticated_session_members(
        UInt256::from_slice(&bytes(&row["session"])),
        id.shard().clone(),
        7,
        members,
    )
    .unwrap();
    let signatures = row["signatures"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["role"] == role)
        .map(|r| PqBlockSignaturePair {
            validator_id: UInt256::from(
                [r["index"].as_u64().unwrap() as u8 + if kind == "next" { 101 } else { 1 }; 32],
            ),
            algorithm_id: 1,
            signature: bytes(&r["signature"]),
        })
        .collect();
    let carrier = BlockSignaturesSimplexPq {
        validator_info: context.validator_info(),
        sig_count: 2,
        sig_weight: row["weight"].as_u64().unwrap(),
        signatures,
        session_id: UInt256::from_slice(&bytes(&row["session"])),
        slot: 99,
        candidate_data: BlockSignaturesSimplex::bytes_to_cell_tree(&candidate).unwrap(),
    };
    let block = BlockStuff::deserialize_block(id, Arc::new(bytes(&row["block_boc"]))).unwrap();
    let state = ShardStateUnsplit::construct_from_cell(
        read_single_root_boc(&bytes(&data["state_boc"])).unwrap(),
    )
    .unwrap();
    let state_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        10,
        UInt256::from([10; 32]),
        UInt256::from([11; 32]),
    );
    let state = ShardStateStuff::from_state(
        state_id,
        state,
        #[cfg(feature = "telemetry")]
        &crate::collator_test_bundle::create_engine_telemetry(),
        &crate::collator_test_bundle::create_engine_allocated(),
    )
    .unwrap();
    (block, state, context, set, carrier)
}

#[tokio::test]
async fn pq_live_top_description_authenticates_current_and_allowed_next_set() {
    use crate::types::top_block_descr::Mode;
    for kind in ["current", "next"] {
        let (block, state, context, _, carrier) = node_fixture(kind, "finalize");
        let proof = create_pq_session_proof(
            &block,
            &SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(carrier.clone())),
            &context.for_block(block.id().clone()).unwrap(),
        )
        .unwrap();
        let make = |carrier: BlockSignaturesSimplexPq, is_fake: bool| {
            let mut top = TopBlockDescr::with_id_and_signatures(
                block.id().clone(),
                BlockSignaturesVariant::SimplexPq(carrier),
            );
            top.append_proof(proof.merkle_proof_root_cell().clone());
            TopBlockDescrStuff::new(top, block.id(), is_fake, false).unwrap()
        };
        let top = make(carrier.clone(), false);
        assert_eq!(top.validate(&state).unwrap(), 1);
        let mut flags = 0;
        let current_only = top.prevalidate(state.block_id(), &state, Mode::empty(), &mut flags);
        assert_eq!(current_only.is_ok(), kind == "current", "{kind}: {current_only:?}");
        let mut corrupted = carrier.clone();
        corrupted.signatures[0].signature[0] ^= 1;
        for fake in [false, true] {
            let bad = make(corrupted.clone(), fake);
            assert!(bad
                .prevalidate(
                    state.block_id(),
                    &state,
                    Mode::ALLOW_NEXT_VSET | Mode::SKIP_CHECK_SIG,
                    &mut flags
                )
                .is_err());
        }
        // A cached successful check cannot authenticate against a different trusted set.
        let mut changed = state.state().unwrap().clone();
        let mut extra = changed.read_custom().unwrap().unwrap();
        let mut set = extra.config.validator_set().unwrap();
        let mut members = set.list().to_vec();
        members[0].adnl_addr = Some(UInt256::from([44; 32]));
        set = rtos_block::ValidatorSet::new(0, 100000, 2, members).unwrap();
        extra
            .config
            .set_config(rtos_block::ConfigParamEnum::ConfigParam34(rtos_block::ConfigParam34 {
                cur_validators: set.clone(),
            }))
            .unwrap();
        extra
            .config
            .set_config(rtos_block::ConfigParamEnum::ConfigParam36(rtos_block::ConfigParam36 {
                next_validators: set,
            }))
            .unwrap();
        changed.write_custom(Some(&extra)).unwrap();
        let changed = ShardStateStuff::from_state(
            state.block_id().clone(),
            changed,
            #[cfg(feature = "telemetry")]
            &crate::collator_test_bundle::create_engine_telemetry(),
            &crate::collator_test_bundle::create_engine_allocated(),
        )
        .unwrap();
        assert!(top.validate(&changed).is_err());
    }
}

pub(crate) struct PqAcceptEngine {
    pub(crate) handle: Arc<BlockHandle>,
    pub(crate) state: Arc<ShardStateStuff>,
    pub(crate) proof: std::sync::Mutex<Option<BlockProofStuff>>,
    pub(crate) proofs: std::sync::atomic::AtomicUsize,
    pub(crate) tops: std::sync::atomic::AtomicUsize,
    pub(crate) broadcasts: std::sync::atomic::AtomicUsize,
}
#[async_trait::async_trait]
impl EngineOperations for PqAcceptEngine {
    fn load_block_handle(&self, id: &BlockIdExt) -> Result<Option<Arc<BlockHandle>>> {
        assert_eq!(id, self.handle.id());
        Ok(Some(self.handle.clone()))
    }
    fn store_block_prev1(&self, _: &Arc<BlockHandle>, _: &BlockIdExt) -> Result<()> {
        Ok(())
    }
    async fn store_block_proof(
        &self,
        id: &BlockIdExt,
        _: Option<Arc<BlockHandle>>,
        proof: &BlockProofStuff,
    ) -> Result<crate::internal_db::BlockResult> {
        assert_eq!(id, self.handle.id());
        *self.proof.lock().unwrap() = Some(proof.clone());
        if proof.is_link() { self.handle.set_proof_link(); } else { self.handle.set_proof(); }
        self.proofs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(crate::internal_db::BlockResult::with_status(
            self.handle.clone(),
            crate::internal_db::DataStatus::Updated,
        ))
    }
    async fn load_block_proof(
        &self,
        _: &Arc<BlockHandle>,
        is_link: bool,
    ) -> Result<BlockProofStuff> {
        assert!(is_link);
        Ok(self.proof.lock().unwrap().clone().unwrap())
    }
    async fn load_last_applied_mc_state(&self) -> Result<Arc<ShardStateStuff>> {
        Ok(self.state.clone())
    }
    async fn send_top_shard_block_description(
        &self,
        top: Arc<TopBlockDescrStuff>,
        cc_seqno: u32,
        _: bool,
    ) -> Result<()> {
        assert_eq!(cc_seqno, 7);
        assert_eq!(top.validate(&self.state)?, 1);
        self.tops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
    async fn send_block_broadcast(
        &self,
        _: &BlockStuff,
        _: &BlockProofStuff,
        carrier: &BlockSignaturesVariant,
    ) -> Result<()> {
        assert!(matches!(carrier, BlockSignaturesVariant::SimplexPq(_)));
        self.broadcasts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}
#[tokio::test]
async fn pq_live_accept_notarized_state_promotes_only_with_authenticated_final() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (block, state, context, set, notar) = node_fixture("current", "notarize");
    let storage = crate::collator_test_bundle::create_block_handle_storage(None).unwrap();
    let handle = storage
        .create_handle(block.id().clone(), storage::types::BlockMeta::default(), None)
        .unwrap()
        .unwrap();
    handle.set_data();
    handle.set_state();
    let engine = Arc::new(PqAcceptEngine {
        handle: handle.clone(),
        state,
        proof: Default::default(),
        proofs: AtomicUsize::new(0),
        tops: AtomicUsize::new(0),
        broadcasts: AtomicUsize::new(0),
    });
    let prev = BlockIdExt::with_params(
        block.id().shard().clone(),
        41,
        UInt256::from([41; 32]),
        UInt256::from([42; 32]),
    );
    let data = rtos_block::write_boc(block.root_cell()).unwrap();
    accept_session_block(
        block.id().clone(),
        Some(data.clone()),
        vec![prev.clone()],
        set.clone(),
        SessionFinality::PqApproval(PqApproval::from_notarization_fields(notar.clone()).unwrap()),
        Some(context.clone()),
        true,
        engine.clone(),
    )
    .await
    .unwrap();
    assert_eq!(engine.proofs.load(Ordering::Relaxed), 1);
    assert_eq!(engine.tops.load(Ordering::Relaxed), 0);
    assert_eq!(engine.broadcasts.load(Ordering::Relaxed), 0);
    let (_, _, _, _, final_carrier) = node_fixture("current", "finalize");
    accept_session_block(
        block.id().clone(),
        Some(data),
        vec![prev.clone()],
        set.clone(),
        SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(final_carrier.clone())),
        Some(context.clone()),
        true,
        engine.clone(),
    )
    .await
    .unwrap();
    assert_eq!(engine.proofs.load(Ordering::Relaxed), 2);
    assert_eq!(engine.tops.load(Ordering::Relaxed), 1);
    assert_eq!(engine.broadcasts.load(Ordering::Relaxed), 1);
    handle.set_block_applied();
    assert!(accept_session_block(
        block.id().clone(),
        None,
        vec![prev.clone()],
        set.clone(),
        SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(notar)),
        Some(context.clone()),
        true,
        engine.clone()
    )
    .await
    .is_err());
    accept_session_block(
        block.id().clone(),
        None,
        vec![prev],
        set,
        SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(final_carrier)),
        Some(context),
        true,
        engine.clone(),
    )
    .await
    .unwrap();
    assert_eq!(engine.proofs.load(Ordering::Relaxed), 2);
    assert_eq!(engine.tops.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn pq_live_accept_result_separates_persistence_publication_and_inclusion() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (block, state, context, _, approval) = node_fixture("current", "notarize");
    let storage = crate::collator_test_bundle::create_block_handle_storage(None).unwrap();
    let handle = storage
        .create_handle(block.id().clone(), storage::types::BlockMeta::default(), None)
        .unwrap()
        .unwrap();
    handle.set_data();
    handle.set_state();
    let engine = Arc::new(PqAcceptEngine {
        handle: handle.clone(),
        state,
        proof: Default::default(),
        proofs: AtomicUsize::new(0),
        tops: AtomicUsize::new(0),
        broadcasts: AtomicUsize::new(0),
    });
    let prev = BlockIdExt::with_params(
        block.id().shard().clone(),
        41,
        UInt256::from([41; 32]),
        UInt256::from([42; 32]),
    );
    let data = rtos_block::write_boc(block.root_cell()).unwrap();
    let approved = accept_pq_session_block(
        block.id().clone(),
        Some(data.clone()),
        vec![prev.clone()],
        SessionFinality::PqApproval(PqApproval::from_notarization_fields(approval).unwrap()),
        context.clone(),
        engine.clone(),
    )
    .await
    .unwrap();
    assert_eq!(approved.phase(), AcceptancePhase::Preapplied);
    assert!(!approved.is_final());
    assert!(!approved.network_signatures().unwrap().is_final());
    assert!(approved.final_network_signatures().is_err());
    assert_eq!(engine.tops.load(Ordering::Relaxed), 0);
    assert_eq!(engine.broadcasts.load(Ordering::Relaxed), 0);

    let (_, _, _, _, finality) = node_fixture("current", "finalize");
    let accepted = accept_pq_session_block(
        block.id().clone(),
        Some(data.clone()),
        vec![prev.clone()],
        SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(finality.clone())),
        context.clone(),
        engine.clone(),
    )
    .await
    .unwrap();
    assert!(accepted.is_final());
    assert_eq!(accepted.phase(), AcceptancePhase::Preapplied);
    assert!(!accepted.already_present());
    assert!(accepted.final_network_signatures().unwrap().is_final());
    assert_eq!(engine.proofs.load(Ordering::Relaxed), 2);
    assert_eq!(engine.tops.load(Ordering::Relaxed), 0);
    assert_eq!(engine.broadcasts.load(Ordering::Relaxed), 0);

    let cached = accepted.current_receipt(engine.as_ref()).unwrap().unwrap();
    assert_eq!(cached.phase(), AcceptancePhase::Preapplied);
    assert!(!cached.already_present());
    assert!(cached.is_final());
    assert!(!approved.current_receipt(engine.as_ref()).unwrap().unwrap().is_final());
    // A pruned state must force the ordinary acceptance path, even with a
    // process-local verified receipt. This is a mock of GC prerequisites.
    handle.reset_state();
    assert!(accepted.current_receipt(engine.as_ref()).unwrap().is_none());
    handle.set_state();

    // This mock represents inclusion already recorded elsewhere; it is not an
    // execution or MC-proof test. Reconstructing a publication must not rewrite
    // the accepted proof or require apply to run a second time.
    handle.set_block_applied();
    let advanced = accepted.current_receipt(engine.as_ref()).unwrap().unwrap();
    assert_eq!(advanced.phase(), AcceptancePhase::Applied);
    assert!(advanced.already_present());
    assert!(advanced.is_final());
    let approved_after_inclusion = approved.current_receipt(engine.as_ref()).unwrap().unwrap();
    assert_eq!(approved_after_inclusion.phase(), AcceptancePhase::Applied);
    assert!(!approved_after_inclusion.is_final(), "inclusion must never upgrade the receipt's role");
    assert_eq!(engine.proofs.load(Ordering::Relaxed), 2);
    let retried = accept_pq_session_block(
        block.id().clone(),
        Some(data.clone()),
        vec![prev.clone()],
        SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(finality.clone())),
        context.clone(),
        engine.clone(),
    )
    .await
    .unwrap();
    assert!(retried.already_present());
    assert_eq!(retried.phase(), AcceptancePhase::Applied);
    assert_eq!(engine.proofs.load(Ordering::Relaxed), 2);
    assert_eq!(retried.network_signatures().unwrap().block_id(), block.id());
    let mut invalid = finality;
    invalid.signatures[0].signature[0] ^= 1;
    assert!(accept_pq_session_block(
        block.id().clone(),
        Some(data),
        vec![prev],
        SessionFinality::Carrier(BlockSignaturesVariant::SimplexPq(invalid)),
        context,
        engine.clone(),
    )
    .await
    .is_err());
    assert_eq!(engine.proofs.load(Ordering::Relaxed), 2);
}

#[test]
fn pq_accept_header_binds_file_hash_for_ordinary_blocks() {
    let (block, _, _, _, _) = node_fixture("current", "finalize");
    let prev = BlockIdExt::with_params(
        block.id().shard().clone(),
        41,
        UInt256::from([41; 32]),
        UInt256::from([42; 32]),
    );
    precheck_header(&block, &[prev.clone()], false, false).unwrap();
    let mut wrong_id = block.id().clone();
    wrong_id.file_hash = UInt256::from([0xA5; 32]);
    // This constructor deliberately checks only the root; the acceptance
    // boundary must bind the file hash even for a well-formed block body.
    let unchecked =
        BlockStuff::deserialize_block(wrong_id, Arc::new(block.data().to_vec())).unwrap();
    let error = precheck_header(&unchecked, &[prev], false, false).unwrap_err();
    assert!(error.to_string().contains("block file hash mismatch"), "{error}");
}
