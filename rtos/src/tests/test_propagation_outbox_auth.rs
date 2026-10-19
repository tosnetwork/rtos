// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{
    engine_traits::{PrivateOverlayOperations, ValidatorListOutcome},
    propagation_outbox::{
        OutboxDomain, PublicationEffect, PublicationKind, PublicationRecord, PublicationStage,
        PublicationTarget, RecordId, StoredCarrier,
    },
    shard_state::ShardStateStuff,
};
use rtos_api::{pq_finality::PqApproval, IntoBoxed};
use rtos_block::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Network(WireProfile);
#[async_trait::async_trait]
impl PrivateOverlayOperations for Network {
    fn wire_profile(&self) -> WireProfile {
        self.0
    }
    async fn set_validator_list(
        &self,
        _: UInt256,
        _: &[catchain::CatchainNode],
    ) -> Result<ValidatorListOutcome> {
        unreachable!()
    }
    fn has_validator_list_context(&self, _: &UInt256) -> bool {
        unreachable!()
    }
    fn activate_validator_list(&self, _: UInt256) -> Result<()> {
        unreachable!()
    }
    fn remove_validator_list(&self, _: UInt256) -> Result<bool> {
        unreachable!()
    }
    fn stop_catchain_client(&self, _: &Arc<adnl::PrivateOverlayShortId>) {
        unreachable!()
    }
    fn create_catchain_client(
        &self,
        _: UInt256,
        _: &validator_session::PrivateKey,
        _: &Arc<adnl::PrivateOverlayShortId>,
        _: &[catchain::CatchainNode],
        _: catchain::CatchainOverlayListenerPtr,
        _: catchain::CatchainOverlayLogReplayListenerPtr,
        _: Option<u8>,
        _: consensus_common::OverlayTransportType,
        _: Option<consensus_common::BlockSyncOverlayParams>,
    ) -> Result<Arc<dyn catchain::CatchainOverlay + Send>> {
        unreachable!()
    }
}
struct HistoryEngine {
    zero: Arc<ShardStateStuff>,
    pin: BlockIdExt,
    wire: WireProfile,
    deny_history: bool,
    reads: AtomicUsize,
}
#[async_trait::async_trait]
impl EngineOperations for HistoryEngine {
    fn zerostate_id(&self) -> Result<&BlockIdExt> {
        Ok(&self.pin)
    }
    fn init_mc_block_id(&self) -> &BlockIdExt {
        &self.pin
    }
    fn validator_network(&self) -> Arc<dyn PrivateOverlayOperations> {
        Arc::new(Network(self.wire))
    }
    async fn load_mc_zero_state(&self) -> Result<Arc<ShardStateStuff>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if self.deny_history {
            fail!("Injected unavailable authenticated history");
        }
        Ok(self.zero.clone())
    }
}
async fn fixture(final_role: bool) -> (HistoryEngine, UnverifiedRecord) {
    // Fixed B commit d870fec; public deterministic test signatures, no production signer.
    // Fixture SHA-256: 7fd017b1f60a704e8710f8db4e768d63fa018ebbcb18a60daa014ce3247bf11e.
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../full_node/finality/testdata/v2-propagation-recovery.json"
    ))
    .unwrap();
    let bytes = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let zero_bytes = bytes(&fixture["state_boc"]);
    let root = read_single_root_boc(&zero_bytes).unwrap();
    let pin = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        0,
        root.repr_hash().clone(),
        UInt256::calc_file_hash(&zero_bytes),
    );
    let zero = ShardStateStuff::from_root_cell(
        pin.clone(),
        root,
        #[cfg(feature = "telemetry")]
        &crate::collator_test_bundle::create_engine_telemetry(),
        &crate::collator_test_bundle::create_engine_allocated(),
    )
    .unwrap();
    let engine = HistoryEngine {
        zero,
        pin,
        wire: WireProfile::T0,
        deny_history: false,
        reads: AtomicUsize::new(0),
    };
    let row = &fixture["rows"][0];
    let candidate_bytes = bytes(&row["candidate"]);
    let candidate: rtos_api::ton::consensus::CandidateHashData =
        WireProfile::T0.deserialize_typed(&candidate_bytes).unwrap();
    let block = BlockStuff::deserialize_block_checked(
        candidate.block().clone(),
        Arc::new(bytes(&row["block_boc"])),
    )
    .unwrap();
    let context = MasterchainProofVerifier::default()
        .pq_publication_context(&engine, block.id(), block.block().unwrap())
        .await
        .unwrap();
    let signatures = if final_role { &row["signatures"] } else { &row["approval_signatures"] };
    let carrier = BlockSignaturesSimplexPq {
        validator_info: ValidatorBaseInfo::with_params(
            row["subset_hash"].as_u64().unwrap() as u32,
            7,
        ),
        sig_count: signatures.as_array().unwrap().len() as u32,
        sig_weight: row["weight"].as_u64().unwrap(),
        slot: 99,
        session_id: UInt256::from_slice(&bytes(&row["session"])),
        candidate_data: BlockSignaturesSimplex::bytes_to_cell_tree(&candidate_bytes).unwrap(),
        signatures: signatures
            .as_array()
            .unwrap()
            .iter()
            .map(|item| {
                let mut identity = [0; 32];
                identity[..4]
                    .copy_from_slice(&(item["index"].as_u64().unwrap() as u32 + 1).to_le_bytes());
                PqBlockSignaturePair {
                    validator_id: identity.into(),
                    algorithm_id: 1,
                    signature: bytes(&item["signature"]),
                }
            })
            .collect(),
    };
    let network = if final_role {
        PqNetworkSignatureSet::from_final_fields(&carrier).unwrap()
    } else {
        PqNetworkSignatureSet::from_approval(
            &PqApproval::from_notarization_fields(carrier).unwrap(),
        )
        .unwrap()
    };
    let encoded = WireProfile::T0.serialize(&network.to_node().into_boxed()).unwrap();
    let effect =
        PublicationEffect { kind: PublicationKind::Block, target: PublicationTarget::Public };
    let record = PublicationRecord {
        domain: OutboxDomain {
            zerostate: engine.pin.clone(),
            global_id: context.global_id(),
            wire_profile: WireProfile::T0,
        },
        protocol: context.protocol(),
        profile: context.profile().clone(),
        session_id: context.verifier().expected_session_id().clone(),
        block_id: block.id().clone(),
        block_data: block.data().to_vec(),
        proof_data: None,
        prev: construct_and_check_prev_stuff(block.root_cell(), block.id(), false).unwrap().1.prev,
        carrier: if final_role {
            StoredCarrier::Final(encoded)
        } else {
            StoredCarrier::Approval(encoded)
        },
        locally_generated: false,
        created_at_unix_secs: 100,
        expires_at_unix_secs: 200,
        effects: vec![effect.clone()],
    };
    (
        engine,
        UnverifiedRecord {
            id: RecordId(1),
            stage: PublicationStage::Prepared,
            record: std::sync::Arc::new(record),
            pending: vec![effect],
        },
    )
}

#[tokio::test]
async fn outbox_auth_real_v2_final_and_approval_from_pinned_history() {
    for final_role in [true, false] {
        let (engine, mut entry) = fixture(final_role).await;
        for stage in [PublicationStage::Prepared, PublicationStage::Ready] {
            entry.stage = stage;
            let receipt = authenticate_publication(
                &MasterchainProofVerifier::default(),
                &engine,
                entry.clone(),
                &Limits::default(),
            )
            .await
            .unwrap();
            assert_eq!(receipt.entry().id, entry.id);
            assert_eq!(receipt.block().id(), &entry.record.block_id);
            assert_eq!(receipt.context().profile(), &entry.record.profile);
            let (_, _, _, carrier) = receipt.into_parts();
            assert_eq!(carrier.is_final(), final_role);
            if final_role {
                carrier.into_final().unwrap();
            } else {
                carrier.into_approval().unwrap();
            }
        }
        assert!(engine.reads.load(Ordering::SeqCst) >= 3);
    }
}

#[tokio::test]
async fn outbox_auth_rejects_tampered_domains_body_carrier_and_pending() {
    let (engine, good) = fixture(true).await;
    let mut cases = Vec::new();
    macro_rules! bad {
        ($field:ident, $value:expr) => {{
            let mut entry = good.clone();
            std::sync::Arc::make_mut(&mut entry.record).$field = $value;
            cases.push(entry);
        }};
    }
    bad!(profile, UInt256::from([9; 32]));
    bad!(session_id, UInt256::from([9; 32]));
    bad!(protocol, consensus_common::simplex_protocol::SimplexProtocol::try_from(1u32).unwrap());
    let mut entry = good.clone();
    std::sync::Arc::make_mut(&mut entry.record).domain.global_id += 1;
    cases.push(entry);
    let mut entry = good.clone();
    std::sync::Arc::make_mut(&mut entry.record).domain.zerostate.file_hash = UInt256::from([9; 32]);
    cases.push(entry);
    let mut entry = good.clone();
    std::sync::Arc::make_mut(&mut entry.record).domain.wire_profile = WireProfile::Legacy;
    cases.push(entry);
    let mut entry = good.clone();
    std::sync::Arc::make_mut(&mut entry.record).block_data[0] ^= 1;
    cases.push(entry);
    let mut entry = good.clone();
    std::sync::Arc::make_mut(&mut entry.record).block_id.seq_no += 1;
    cases.push(entry);
    let mut entry = good.clone();
    std::sync::Arc::make_mut(&mut entry.record).prev[0].file_hash = UInt256::from([9; 32]);
    cases.push(entry);
    bad!(carrier, StoredCarrier::Approval(good.record.carrier.bytes().to_vec()));
    let mut appended = good.record.carrier.bytes().to_vec();
    appended.push(0);
    bad!(carrier, StoredCarrier::Final(appended));
    let mut truncated = good.record.carrier.bytes().to_vec();
    truncated.pop();
    bad!(carrier, StoredCarrier::Final(truncated));
    let wire: SignatureSet =
        WireProfile::T0.deserialize_typed(good.record.carrier.bytes()).unwrap();
    let SignatureSet::TonNode_SignatureSet_SimplexPq(mut fields) = wire else { unreachable!() };
    fields.signatures[0].signature[0] ^= 1;
    bad!(carrier, StoredCarrier::Final(WireProfile::T0.serialize(&fields.into_boxed()).unwrap()));
    let mut entry = good.clone();
    entry.pending.push(entry.pending[0].clone());
    cases.push(entry);
    let mut entry = good.clone();
    entry.pending[0].target = PublicationTarget::FastSync;
    cases.push(entry);
    for (index, entry) in cases.into_iter().enumerate() {
        assert!(
            authenticate_publication(
                &MasterchainProofVerifier::default(),
                &engine,
                entry,
                &Limits::default()
            )
            .await
            .is_err(),
            "tampered case {index}"
        );
    }
    // Accepting a non-minimal TL bytes length would preserve the signature but
    // violate the persisted canonical carrier format. Expand the first signature
    // prefix from the normal 4-byte form into its legal 8-byte TL representation.
    let wire: SignatureSet =
        WireProfile::T0.deserialize_typed(good.record.carrier.bytes()).unwrap();
    let SignatureSet::TonNode_SignatureSet_SimplexPq(fields) = wire else { unreachable!() };
    let signature = &fields.signatures[0].signature;
    let encoded = good.record.carrier.bytes();
    let offset = encoded.windows(signature.len()).position(|part| part == signature).unwrap();
    assert_eq!(encoded[offset - 4], 254);
    let mut noncanonical = encoded[..offset - 4].to_vec();
    noncanonical.push(255);
    noncanonical.extend_from_slice(&(signature.len() as u64).to_le_bytes()[..7]);
    noncanonical.extend_from_slice(&encoded[offset..]);
    let mut entry = good.clone();
    std::sync::Arc::make_mut(&mut entry.record).carrier = StoredCarrier::Final(noncanonical);
    assert!(authenticate_publication(
        &MasterchainProofVerifier::default(),
        &engine,
        entry,
        &Limits::default()
    )
    .await
    .is_err());
    let mut limits = Limits::default();
    limits.max_carrier_bytes = 1;
    assert!(authenticate_publication(&MasterchainProofVerifier::default(), &engine, good, &limits)
        .await
        .is_err());
    // An approval authorizes no shard description; its finality broadcast of a
    // shard block, as the reference block accepter sends it, is a valid effect.
    let (engine, mut approval) = fixture(false).await;
    std::sync::Arc::make_mut(&mut approval.record).effects[0] = PublicationEffect {
        kind: PublicationKind::ShardDescription,
        target: PublicationTarget::ShardDescription,
    };
    approval.pending = approval.record.effects.clone();
    assert!(authenticate_publication(
        &MasterchainProofVerifier::default(),
        &engine,
        approval,
        &Limits::default()
    )
    .await
    .is_err());
}

#[tokio::test]
async fn outbox_auth_ready_and_cached_metadata_cannot_replace_history() {
    let (mut engine, mut entry) = fixture(true).await;
    entry.stage = PublicationStage::Ready;
    engine.deny_history = true;
    assert!(authenticate_publication(
        &MasterchainProofVerifier::default(),
        &engine,
        entry.clone(),
        &Limits::default()
    )
    .await
    .is_err());
    engine.deny_history = false;
    engine.pin.file_hash = UInt256::from([17; 32]);
    std::sync::Arc::make_mut(&mut entry.record).domain.zerostate = engine.pin.clone();
    assert!(
        authenticate_publication(
            &MasterchainProofVerifier::default(),
            &engine,
            entry.clone(),
            &Limits::default()
        )
        .await
        .is_err(),
        "matching serialized pin must not authenticate wrong state"
    );
    engine.pin = engine.zero.block_id().clone();
    std::sync::Arc::make_mut(&mut entry.record).domain.zerostate = engine.pin.clone();
    engine.wire = WireProfile::Legacy;
    assert!(authenticate_publication(
        &MasterchainProofVerifier::default(),
        &engine,
        entry,
        &Limits::default()
    )
    .await
    .is_err());
}
