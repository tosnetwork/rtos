// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{
    history_read_budget::HistoryReadBudget,
    repair_lease_binding::{RepairLeaseBinding, RepairLeaseDomain},
};
use consensus_common::{
    finality_delivery::{CanonicalFinalityRequest, FinalityDeliveryRole},
    session_runtime::SessionRecoveryCoordinates,
    simplex_protocol::SimplexProtocol,
};
use rtos_block::ShardIdent;
fn block(seq: u32) -> BlockIdExt {
    BlockIdExt::with_params(
        ShardIdent::masterchain(),
        seq,
        UInt256::from([seq as u8 + 1; 32]),
        UInt256::from([seq as u8 + 2; 32]),
    )
}
fn binding() -> RepairLeaseBinding {
    let receipt = UInt256::from([8; 32]);
    RepairLeaseBinding {
        record_id: 1,
        delivery_id: receipt.clone(),
        canonical: CanonicalFinalityRequest {
            node_receipt: receipt,
            block_id: block(2),
            role: FinalityDeliveryRole::Final,
            local_adnl: UInt256::from([9; 32]),
            local_validator_index: None,
            source_validator: UInt256::from([10; 32]),
        },
        domain: RepairLeaseDomain {
            zerostate: block(0),
            global_id: 7,
            history_init: block(0),
            source_recovery_anchor: block(0),
            source_recovery_coordinates: SessionRecoveryCoordinates {
                shard: ShardIdent::masterchain(),
                catchain_seqno: 0,
                vertical_seqno: 0,
                last_key_block_seqno: 0,
                new_catchain_ids: false,
            },
            session_id: UInt256::from([11; 32]),
            profile: UInt256::from([12; 32]),
            protocol: SimplexProtocol::PrivateObserversPlumtree,
            carrier_version: 2,
            wire_profile: rtos_api::WireProfile::T0,
        },
        source_digest: UInt256::from([13; 32]),
        canonical_digest: UInt256::from([14; 32]),
        created_at_unix_secs: 100,
        expires_at_unix_secs: 200,
        effects_digest: UInt256::from([15; 32]),
        close_generation: 1,
    }
}
fn dependencies() -> Vec<Dependency> {
    vec![Dependency {
        kind: "state".into(),
        id: block(1).to_string(),
        digest: format!("{:x}", UInt256::from([16; 32])),
        bytes: 123,
        root: Some(format!("{:x}", UInt256::from([17; 32]))),
    }]
}
fn open(path: &std::path::Path) -> Result<(Arc<RocksDb>, Arc<DependencyLeases>)> {
    let db = RocksDb::new(path, "ledger", None, storage::db::rocksdb::AccessType::ReadWrite)?;
    let leases = DependencyLeases::open(db.clone(), true)?;
    Ok((db, leases))
}
#[tokio::test]
async fn persistent_repair_ledger_protecting_cold_recovery_and_generation_binding() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (db, leases) = open(dir.path())?;
    let budget = HistoryReadBudget::new(Default::default());
    let guard = leases.protection.authentication().await?;
    let generation = leases.begin(&binding(), dependencies(), &budget)?;
    assert!(leases.protection.state(&block(1)));
    assert!(leases.protection.try_deletion().is_none());
    drop(guard);
    drop(leases);
    drop(db);
    let (db, leases) = open(dir.path())?;
    let budget = HistoryReadBudget::new(Default::default());
    assert!(leases.protection.state(&block(1)), "protection is loaded before consumers start");
    assert_eq!(leases.lookup(generation, &budget)?.state, LeaseState::Protecting);
    assert_eq!(leases.begin(&binding(), dependencies(), &budget)?, generation);
    let mut conflict = binding();
    conflict.effects_digest = UInt256::default();
    assert!(leases.begin(&conflict, dependencies(), &budget).is_err());
    leases.durable(generation, &budget)?;
    drop(leases);
    drop(db);
    let (_db, leases) = open(dir.path())?;
    assert_eq!(
        leases.lookup(generation, &HistoryReadBudget::new(Default::default()))?.state,
        LeaseState::DurableCustody
    );
    Ok(())
}
#[tokio::test]
async fn persistent_repair_ledger_unknown_wal_poison_and_bad_record_fail_closed() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (db, leases) = open(dir.path())?;
    *leases.observer.lock().unwrap() = Some(Arc::new(|_, _| fail!("real ledger WAL observer EIO")));
    assert!(leases
        .begin(&binding(), dependencies(), &HistoryReadBudget::new(Default::default()))
        .is_err());
    assert!(leases.protection.state(&block(99)), "unknown sync disables all domain deletion");
    assert!(leases.protection.authentication().await.is_err());
    drop(leases);
    drop(db);
    let (db, leases) = open(dir.path())?;
    assert_eq!(
        leases.lookup(1, &HistoryReadBudget::new(Default::default()))?.state,
        LeaseState::Protecting
    );
    leases.table.put_raw(b"lease/00000000000000000001", b"{bad-ledger")?;
    leases.table.sync_wal()?;
    drop(leases);
    drop(db);
    let db = RocksDb::new(dir.path(), "ledger", None, storage::db::rocksdb::AccessType::ReadWrite)?;
    assert!(DependencyLeases::open(db.clone(), true).is_err());
    assert!(db.repair_protection().state(&block(99)));
    Ok(())
}
#[test]
fn persistent_repair_binding_strict_codec_no_approval_or_unknown_fields() -> Result<()> {
    let item = binding();
    let bytes = item.encode()?;
    assert_eq!(RepairLeaseBinding::decode(&bytes)?, item);
    let mut json: serde_json::Value = serde_json::from_slice(&bytes)?;
    json["unknown"] = true.into();
    assert!(RepairLeaseBinding::decode(&serde_json::to_vec(&json)?).is_err());
    let mut wrong = item.clone();
    wrong.canonical.role = FinalityDeliveryRole::Approval;
    assert!(wrong.encode().is_err());
    assert!(RepairLeaseBinding::decode(&vec![
        b' ';
        crate::repair_lease_binding::MAX_REPAIR_BINDING_BYTES
            + 1
    ])
    .is_err());
    Ok(())
}

#[tokio::test]
async fn persistent_repair_ledger_durable_sync_failure_and_wrong_domain() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (db, leases) = open(dir.path())?;
    let budget = HistoryReadBudget::new(Default::default());
    let generation = leases.begin(&binding(), dependencies(), &budget)?;
    *leases.observer.lock().unwrap() = Some(Arc::new(|_, _| fail!("DurableCustody WAL failed")));
    assert!(leases.durable(generation, &budget).is_err());
    assert!(leases.lookup(generation, &budget).is_err());
    assert!(leases.protection.state(&block(1)));
    drop(leases);
    drop(db);
    let (_db, leases) = open(dir.path())?;
    assert!(leases.protection.state(&block(1)));
    // A recovered marker is still data, never an authentication capability.
    assert!(leases.verify_domain(&block(0), &block(1)).is_err());
    assert!(leases.protection.authentication().await.is_err());
    Ok(())
}

// These are storage admission fixtures, not authenticated custody capabilities.
fn capacity_binding(n: u64) -> RepairLeaseBinding {
    let mut value = binding();
    value.record_id = n;
    value.close_generation = n;
    value
}
fn capacity_record(n: u64, deps: &[Dependency]) -> Result<LeaseRecord> {
    let record = LeaseRecord {
        schema: 1,
        generation: n,
        binding: capacity_binding(n).encode()?,
        dependency_digest: format!("{:x}", dependency_digest(deps)?),
        dependencies: deps.to_vec(),
        state: LeaseState::Protecting,
    };
    record.validate()?;
    Ok(record)
}
fn physical_ledger(leases: &DependencyLeases) -> Result<BTreeMap<Vec<u8>, (usize, UInt256)>> {
    let mut result = BTreeMap::new();
    leases.table.for_each(&mut |key, bytes| {
        result.insert(key.to_vec(), (bytes.len(), UInt256::calc_file_hash(bytes)));
        Ok(true)
    })?;
    Ok(result)
}
async fn ledger_real_capacity(dependency_count: usize) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (db, leases) = open(dir.path())?;
    let mut deps = Vec::new();
    for n in 1..=dependency_count as u32 {
        let mut dep = dependencies().remove(0);
        // Unlike block(), this accepts sequence numbers beyond one byte.
        dep.id = BlockIdExt::with_params(ShardIdent::masterchain(), n,
            UInt256::from([1; 32]), UInt256::from([2; 32])).to_string();
        deps.push(dep);
    }
    deps.sort();
    let mut total = 0usize;
    let mut rows = Vec::new();
    for n in 1..=MAX_LEASES as u64 + 1 {
        let bytes = serde_json::to_vec(&capacity_record(n, &deps)?)?;
        assert!(bytes.len() <= MAX_RECORD_BYTES);
        if rows.len() == MAX_LEASES || total + bytes.len() > MAX_TOTAL_BYTES { break; }
        total += bytes.len();
        rows.push(bytes);
    }
    let count = rows.len();
    assert!(count > 1);
    let last = rows.pop().unwrap();
    let mut batch = leases.table.begin_transaction()?;
    for (index, bytes) in rows.iter().enumerate() {
        batch.put_raw(format!("lease/{:020}", index + 1).as_bytes(), bytes)?;
    }
    batch.put_raw(b"next", &((count - 1) as u64).to_le_bytes())?;
    batch.commit()?;
    leases.table.sync_wal()?;
    drop(rows);
    drop(leases);
    drop(db);
    let (db, leases) = open(dir.path())?;
    let guard = leases.protection.authentication().await?;
    assert_eq!(leases.begin(&capacity_binding(count as u64), deps.clone(),
        &HistoryReadBudget::new(Default::default()))?, count as u64);
    assert_eq!(leases.memory.lock().unwrap().bytes, total);
    let before = physical_ledger(&leases)?;
    assert_eq!(before.get(format!("lease/{:020}", count).as_bytes()),
        Some(&(last.len(), UInt256::calc_file_hash(&last))));
    let error = leases.begin(&capacity_binding(count as u64 + 1), deps.clone(),
        &HistoryReadBudget::new(Default::default())).unwrap_err().to_string();
    if count == MAX_LEASES {
        assert!(error.contains("history capacity exhausted"), "{error}");
    } else {
        assert!(error.contains("lease capacity exhausted"), "{error}");
        assert!(total + serde_json::to_vec(&capacity_record(count as u64 + 1, &deps)?)?.len()
            > MAX_TOTAL_BYTES);
    }
    eprintln!("ledger capacity: dependencies={dependency_count}, records={count}, bytes={total}, rejection={error}");
    assert_eq!(physical_ledger(&leases)?, before);
    assert!(!leases.memory.lock().unwrap().poisoned);
    drop(guard);
    drop(leases);
    drop(db);
    let (_db, leases) = open(dir.path())?;
    assert_eq!(physical_ledger(&leases)?, before);
    assert_eq!(leases.memory.lock().unwrap().records.len(), count);
    assert_eq!(leases.memory.lock().unwrap().bytes, total);
    Ok(())
}
#[tokio::test]
async fn persistent_repair_ledger_real_small_record_capacity_preserves_cold_records() -> Result<()> {
    ledger_real_capacity(1).await
}
#[tokio::test]
async fn persistent_repair_ledger_real_large_record_byte_capacity_preserves_cold_records() -> Result<()> {
    ledger_real_capacity(MAX_DEPENDENCIES).await
}
