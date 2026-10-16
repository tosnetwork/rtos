// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Retained authenticated finality consumed by the production executable at boot.
use super::*;
use crate::propagation_outbox::{
    delivery_id, inspect_delivery, Limits, OutboxDomain, PublicationRecord, StoredCarrier,
};
use consensus_common::session_runtime::{AuthenticatedSessionRuntime, SessionNetworkPin};
use rtos_api::{pq_finality::PqNetworkSignatureSet, IntoBoxed};
use rtos_block::{BlockSignaturesVariant, UInt256};
use simplex::finality_delivery::{retain_pending_finality, scan_pending_finality, PendingFinalityRecord};

pub(super) async fn prepare(root: &Path, fixture: &Fixture) -> Result<PublicationRecord> {
    let db = open_db(root).await?;
    let id = fixture.id(3, false);
    let handle = db.load_block_handle(&id)?.unwrap();
    let block = db.load_block_data(&handle).await?;
    let proof = db.load_block_proof(&handle, false).await?;
    let info = block.block()?.read_info()?;
    let state = db.load_shard_state_dynamic(&fixture.id(info.prev_key_block_seqno(), false))?;
    let config = state.config_params()?;
    eprintln!("Retained finality governing key={}, catchain={}, vertical={}, global={}",
        info.prev_key_block_seqno(), info.gen_catchain_seqno(), info.vert_seq_no(), state.state()?.global_id());
    let (committee, _) = config.validator_set()?.calc_subset(
        &config.catchain_config()?, rtos_block::SHARD_FULL, -1, info.gen_catchain_seqno(),
    )?;
    let local = committee[0].adnl_addr()?;
    let runtime = AuthenticatedSessionRuntime::from_authenticated_config(
        SessionNetworkPin { global_id: state.state()?.global_id(), zerostate: fixture.id(0, false) },
        config,
        rtos_api::session_identity::SessionCoordinates {
            shard: id.shard(), catchain_seqno: info.gen_catchain_seqno(),
            vertical_seqno: info.vert_seq_no(), last_key_block_seqno: info.prev_key_block_seqno(),
            new_catchain_ids: false,
        },
        committee, local,
    )?;
    let BlockSignaturesVariant::SimplexPq(carrier) = proof.drain_signatures()? else {
        rtos_block::fail!("Expected authenticated PQ finality fixture");
    };
    assert_eq!(&carrier.session_id, runtime.session_id());
    let signature_set = runtime.wire_profile().serialize(
        &PqNetworkSignatureSet::from_final_fields(&carrier)?.to_node().into_boxed(),
    )?;
    let source = PendingFinalityRecord {
        pin: runtime.pin().clone(), protocol: runtime.protocol(),
        carrier_version: runtime.carrier_version(), wire_profile: runtime.wire_profile(),
        profile: runtime.profile().clone(), session_id: runtime.session_id().clone(),
        block_id: id, local_adnl: UInt256::from(*runtime.local_adnl().data()),
        local_validator_index: Some(0),
        source_validator: block.block()?.read_extra()?.created_by().clone(),
        data: block.data().to_vec(), signature_set, is_final: true,
        last_mc_finalized_seqno: 0, candidate_already_sent: false,
        created_at_unix_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?.as_secs(),
    };
    let expected = PublicationRecord {
        domain: OutboxDomain { zerostate: source.pin.zerostate.clone(),
            global_id: source.pin.global_id, wire_profile: source.wire_profile },
        protocol: source.protocol, profile: source.profile.clone(),
        session_id: source.session_id.clone(), block_id: source.block_id.clone(),
        block_data: source.data.clone(), proof_data: None,
        prev: vec![block.construct_prev_id()?.0],
        carrier: StoredCarrier::Final(source.signature_set.clone()),
        locally_generated: true, created_at_unix_secs: source.created_at_unix_secs,
        expires_at_unix_secs: source.created_at_unix_secs + Limits::default().max_retention_secs,
        effects: Vec::new(),
    };
    let source_root = root.join("node_db/catchains");
    let namespace = PathBuf::from(runtime.runtime_directory(source_root.to_str().unwrap())?);
    let (physical, _) = db.sst_databases_for_test();
    drop((state, block, handle));
    db.stop_states_db().await?;
    drop(db);
    tokio::time::timeout(Duration::from_secs(30), wait_for_db_release(physical)).await?;
    retain_pending_finality(&namespace, &source)?;
    let pending = scan_pending_finality(&source_root)?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].record().data, expected.block_data);
    Ok(expected)
}

pub(super) async fn verify(root: &Path, db: &Arc<InternalDb>, expected: &PublicationRecord) -> Result<()> {
    assert!(scan_pending_finality(&root.join("node_db/catchains"))?.is_empty(),
        "actual startup did not acknowledge retained source finality");
    let id = delivery_id(expected)?;
    let (delivery, entry) = inspect_delivery(db, &expected.domain, &Limits::default(), &id)?
        .expect("actual startup did not durably retain the source delivery");
    assert_eq!(delivery.delivery_id, id);
    assert_eq!(entry.record.domain, expected.domain);
    assert_eq!(entry.record.block_id, expected.block_id);
    assert_eq!(entry.record.block_data, expected.block_data);
    assert_eq!(entry.record.carrier, expected.carrier);
    assert_eq!(entry.record.session_id, expected.session_id);
    assert_eq!(entry.record.profile, expected.profile);
    assert_eq!(entry.record.protocol, expected.protocol);
    assert_eq!(entry.record.locally_generated, expected.locally_generated);
    assert_eq!(entry.record.expires_at_unix_secs, expected.expires_at_unix_secs);
    assert_eq!(entry.record.prev, expected.prev);
    assert_eq!(entry.record.created_at_unix_secs, expected.created_at_unix_secs);
    let origin = delivery.origin.expect("source recovery lost its authenticated origin");
    assert_eq!(origin.local_validator_index, Some(0));
    let handle = db.load_block_handle(&expected.block_id)?.unwrap();
    let proof = db.load_block_proof(&handle, false).await?;
    proof.check_trusted_checkpoint(&expected.block_id)?;
    let recovered_config = proof.get_config_params()?;
    let block = db.load_block_data(&handle).await?;
    let extra = block.block()?.read_extra()?.read_custom()?.unwrap();
    let full_config = extra.config().unwrap();
    for parameter in [19, 28, 29, 30] {
        assert_eq!(recovered_config.config(parameter)?, full_config.config(parameter)?,
            "recovered key proof lost governing configuration {parameter}");
    }
    let path = root.join("finality-recovery.json");
    fs::write(&path, serde_json::to_vec_pretty(&serde_json::json!({
        "delivery_id": id.to_hex_string(), "pending_sources": 0,
        "complete_boots": 2, "exact_block_and_certificate": true,
        "validator_keys_configured": false, "governing_parameters": [19, 28, 29, 30],
    }))?)?;
    keep_evidence(root, &path)?;
    eprintln!("Actual node retained finality recovery: two boots, source acknowledged, exact block and certificate durable");
    Ok(())
}
