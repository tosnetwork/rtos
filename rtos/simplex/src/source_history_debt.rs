// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Read-only source certificate authority, retaining the actual namespace lock.
use super::*;
use std::sync::Arc;

/// Charges the caller's single owned recovery request; no fresh budget here.
pub trait SourceHistoryDebtBudget: Send + Sync {
    fn step(&self) -> Result<()>;
    fn workspace(&self, bytes: usize) -> Result<()>;
    fn read_bytes(&self, bytes: usize) -> Result<()>;
}

#[derive(Debug)]
pub struct SourceHistoryDebtBusy;
impl std::fmt::Display for SourceHistoryDebtBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Source history debt owner busy")
    }
}
impl std::error::Error for SourceHistoryDebtBusy {}

/// Not serializable or constructible outside this module. Keep the entire value
/// in the actual capsule commit owner, not just its digest or record clone.
pub struct SourceHistoryDebt {
    record: SessionRecoveryRecord,
    digest: UInt256,
    _owner: Arc<crate::finality_delivery::PendingFinalityStore>,
}
impl SourceHistoryDebt {
    pub fn record(&self) -> &SessionRecoveryRecord {
        &self.record
    }
    pub fn digest(&self) -> &UInt256 {
        &self.digest
    }
}

fn same_record(a: &SessionRecoveryRecord, b: &SessionRecoveryRecord) -> bool {
    a.pin == b.pin
        && a.binding == b.binding
        && a.protocol == b.protocol
        && a.carrier_version == b.carrier_version
        && a.wire_profile == b.wire_profile
        && a.profile == b.profile
        && a.session_id == b.session_id
        && a.local_adnl == b.local_adnl
        && a.local_validator_index == b.local_validator_index
        && a.prev_blocks == b.prev_blocks
        && a.start_masterchain == b.start_masterchain
        && a.namespace == b.namespace
}

/// Call in an owned blocking job. Busy is a deferred error, never a blocking
/// file-lock wait. Caller must first authenticate historical anchors/parents;
/// this gate adds real retained FinalCert authority, not historical state proof.
pub fn authenticate_source_history_debt(
    record: &SessionRecoveryRecord,
    runtime: &AuthenticatedSessionRuntime,
    budget: &dyn SourceHistoryDebtBudget,
) -> Result<SourceHistoryDebt> {
    budget.step()?;
    let role = match runtime.local_role() {
        LocalRole::Validator(i) => Some(i),
        LocalRole::Observer => None,
    };
    if record.protocol != SimplexProtocol::PrivateObserversPlumtree
        || record.wire_profile != WireProfile::T0
        || runtime.pin() != &record.pin
        || runtime.recovery_binding() != Some(&record.binding)
        || runtime.protocol() != record.protocol
        || runtime.carrier_version() != record.carrier_version
        || runtime.wire_profile() != record.wire_profile
        || runtime.profile() != &record.profile
        || runtime.session_id() != &record.session_id
        || UInt256::from(*runtime.local_adnl().data()) != record.local_adnl
        || role != record.local_validator_index
    {
        fail!("Source history debt differs from authenticated runtime");
    }
    let root = record
        .namespace
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .ok_or_else(|| error!("Source history namespace has no root"))?;
    if PathBuf::from(
        runtime.runtime_directory(root.to_str().ok_or_else(|| error!("Invalid source path"))?)?,
    ) != record.namespace
    {
        fail!("Source history namespace mismatch");
    }
    let owner = crate::finality_delivery::PendingFinalityStore::lock(
        record.namespace.join("finality-pending"),
    )?
    .ok_or(SourceHistoryDebtBusy)?;
    let directory = record.namespace.join(DIRECTORY);
    let mut paths = Vec::new();
    let mut pending_bytes = 0u64;
    let mut completed_bytes = 0u64;
    let mut pending_count = 0usize;
    let mut completed_count = 0usize;
    // One legacy resolved copy and one completed copy may coexist after crash.
    let mut entries = std::collections::VecDeque::from([std::fs::read_dir(&directory)?]);
    while let Some(entries_in_directory) = entries.pop_front() {
        for entry in entries_in_directory {
            budget.step()?;
            budget.workspace(4096)?;
            let entry = entry?;
            let path = entry.path();
            if path == directory.join("outputs-v1") {
                if !entry.file_type()?.is_dir() {
                    fail!("Source output index not directory");
                }
                continue;
            }
            if path == directory.join(COMPLETED_DIRECTORY) {
                if !entry.file_type()?.is_dir() {
                    fail!("Completed intent index not directory");
                }
                entries.push_back(std::fs::read_dir(&path)?);
                continue;
            }
            if !entry.file_type()?.is_file() {
                fail!("Unexpected source history artifact");
            }
            let in_completed = path.parent() == Some(directory.join(COMPLETED_DIRECTORY).as_path());
            let ext = path.extension().and_then(|s| s.to_str());
            let completed = in_completed || ext == Some("resolved");
            let size = entry.metadata()?.len();
            if size > MAX_INTENT_BYTES {
                fail!("Source history artifact oversized");
            }
            let (count, total, limit_count, limit_bytes) = if completed {
                (
                    &mut completed_count,
                    &mut completed_bytes,
                    MAX_COMPLETED * 2 + 1,
                    MAX_COMPLETED_TOTAL + MAX_INTENT_BYTES,
                )
            } else {
                (
                    &mut pending_count,
                    &mut pending_bytes,
                    MAX_INTENTS + 1,
                    MAX_INTENT_TOTAL + MAX_INTENT_BYTES,
                )
            };
            *count += 1;
            *total += size;
            if *count > limit_count || *total > limit_bytes {
                fail!("Source history debt quota exceeded");
            }
            // An intact pending-write temp can supply a certificate for the
            // normal authenticated replay. It proves no completion or node ACK.
            // Completed-write temps still need their canonical pending proof.
            if in_completed && ext == Some("tmp") {
                continue;
            }
            if (in_completed && ext != Some("complete"))
                || (!in_completed && !matches!(ext, Some("json" | "resolved" | "tmp")))
            {
                fail!("Unexpected source history artifact");
            }
            paths.push(path);
        }
    }
    paths.sort();
    if paths.is_empty() {
        fail!("Source history has no retained certificate");
    }
    // Digests cover the original exact records, including candidate target and
    // start/governing fields; sorting prevents directory order changing identity.
    budget.workspace(
        paths
            .len()
            .checked_add(1)
            .and_then(|n| n.checked_mul(32))
            .ok_or_else(|| error!("Source digest overflow"))?,
    )?;
    let mut digests = Vec::with_capacity((paths.len() + 1) * 96);
    digests.extend_from_slice(
        UInt256::calc_file_hash(record.namespace.as_os_str().as_encoded_bytes()).as_slice(),
    );
    let mut verified_certificates = 0usize;
    for path in paths {
        budget.step()?;
        let file = File::open(&path)?;
        let length = file.metadata()?.len();
        if length > MAX_INTENT_BYTES {
            fail!("Source history intent oversized");
        }
        let length = usize::try_from(length)?;
        budget.read_bytes(length + 1)?;
        // JSON strings, hex/TL buffers and verified signatures coexist briefly.
        budget.workspace(
            length
                .checked_mul(12)
                .and_then(|n| n.checked_add(1))
                .ok_or_else(|| error!("Source history workspace overflow"))?,
        )?;
        let mut bytes = Vec::with_capacity(length + 1);
        file.take((length + 1) as u64).read_to_end(&mut bytes)?;
        if bytes.len() != length {
            fail!("Source history intent changed size during read");
        }
        // TL vectors reserve up to 1024 elements before reading their first
        // item; even a tiny malformed certificate can trigger this allocation.
        budget.workspace(
            1024 * std::mem::size_of::<rtos_api::ton::consensus::simplex::VoteSignature>(),
        )?;
        let (actual, _certificate, wire) = match decode_intent_typed(&path, &record.namespace, &bytes) {
            Ok(value) => value,
            Err(error) if interrupted_pending_id(&path, &error).is_some() => {
                // Physical debt is retained and bound into the receipt, but
                // contributes no certificate authority. At least one intact,
                // matching quorum proof below remains mandatory.
                digests.extend_from_slice(UInt256::calc_file_hash(b"uncommitted-source-intent").as_slice());
                digests.extend_from_slice(UInt256::calc_file_hash(path.file_name().unwrap().as_encoded_bytes()).as_slice());
                digests.extend_from_slice(UInt256::calc_file_hash(&bytes).as_slice());
                continue;
            }
            Err(error) => return Err(error),
        };
        if !same_record(record, &actual) {
            fail!("Source history certificate locator mismatch");
        }
        budget.workspace(
            runtime
                .committee()
                .len()
                .checked_mul(8192)
                .ok_or_else(|| error!("Source committee workspace overflow"))?,
        )?;
        let verified = crate::certificate::Certificate::<crate::simplex_state::Vote>::from_authenticated_runtime(
            &wire, runtime, &|| budget.step())?;
        if !matches!(verified.vote, crate::simplex_state::Vote::Finalize(_)) {
            fail!("Source history certificate is not FinalCert");
        }
        verified_certificates += 1;
        digests.extend_from_slice(UInt256::calc_file_hash(&bytes).as_slice());
    }
    if verified_certificates == 0 {
        fail!("Source history has no verified retained certificate");
    }
    Ok(SourceHistoryDebt {
        record: record.clone(),
        digest: UInt256::calc_file_hash(&digests),
        _owner: owner,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Budget;
    impl SourceHistoryDebtBudget for Budget {
        fn step(&self) -> Result<()> {
            Ok(())
        }
        fn workspace(&self, _: usize) -> Result<()> {
            Ok(())
        }
        fn read_bytes(&self, _: usize) -> Result<()> {
            Ok(())
        }
    }
    fn retained(
        root: &std::path::Path,
    ) -> (Arc<AuthenticatedSessionRuntime>, SessionRecoveryRecord, PathBuf) {
        let (runtime, draft) = crate::finality_delivery::tests::fixture();
        let namespace = PathBuf::from(runtime.runtime_directory(root.to_str().unwrap()).unwrap());
        std::fs::create_dir_all(&namespace).unwrap();
        let consensus_common::SessionFinality::Carrier(
            rtos_block::BlockSignaturesVariant::SimplexPq(proof),
        ) = draft.finality
        else {
            unreachable!()
        };
        let candidate = rtos_api::pq_finality::PqNetworkSignatureSet::from_final_fields(&proof)
            .unwrap()
            .to_node()
            .candidate;
        let hash = UInt256::calc_file_hash(&rtos_api::serialize_boxed(&candidate).unwrap());
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
                    .map(|(i, s)| crate::certificate::VoteSignature {
                        validator_idx: crate::block::ValidatorIndex::new(i as u32),
                        signature: s.signature.clone(),
                    })
                    .collect(),
            }),
        };
        let source = crate::finality_delivery::SourceFinalityDelivery::open(
            runtime.clone(),
            &namespace,
            Arc::new(crate::finality_delivery::tests::HeldSink::default()),
        )
        .unwrap();
        source.bind_start(runtime.pin().zerostate.clone()).unwrap();
        source.retain_intent(vec![runtime.pin().zerostate.clone()], &event).unwrap();
        drop(source);
        let record = scan_finality_recovery_namespace(&namespace).unwrap().unwrap();
        let path = FinalityIntentStore::new(&namespace).paths().unwrap().remove(0);
        (runtime, record, path)
    }
    #[test]
    fn source_history_debt_pending_temporary_requires_real_certificate_without_publication() {
        let root = crate::authenticated_fixture::TestDirectory::new();
        let (runtime, record, path) = retained(root.path());
        let original = std::fs::read(&path).unwrap();
        let temporary = path.with_extension("tmp");
        std::fs::rename(&path, &temporary).unwrap();
        let receipt = authenticate_source_history_debt(&record, &runtime, &Budget).unwrap();
        assert!(same_record(receipt.record(), &record));
        assert_eq!(std::fs::read(&temporary).unwrap(), original);
        assert!(!path.exists(), "authentication must not publish an uncommitted intent");
        drop(receipt);
        let mut disk: DiskIntent = serde_json::from_slice(&original).unwrap();
        let mut wire: rtos_api::ton::consensus::simplex::Certificate =
            WireProfile::T0.deserialize_typed(&hex::decode(&disk.certificate).unwrap()).unwrap();
        let rtos_api::ton::consensus::simplex::Certificate::Consensus_Simplex_Certificate(
            ref mut cert,
        ) = wire;
        let rtos_api::ton::consensus::simplex::VoteSignatureSet::Consensus_Simplex_VoteSignatureSet(
            ref mut signatures,
        ) = cert.signatures;
        signatures.votes = Vec::new().into();
        disk.certificate = hex::encode(WireProfile::T0.serialize(&wire).unwrap());
        let invalid = serde_json::to_vec(&disk).unwrap();
        std::fs::write(&temporary, &invalid).unwrap();
        let error = authenticate_source_history_debt(&record, &runtime, &Budget).err().unwrap();
        assert!(error.to_string().contains("Not enough signatures"), "{error:#}");
        assert_eq!(std::fs::read(&temporary).unwrap(), invalid);
        assert!(!path.exists());
        assert!(
            crate::finality_delivery::PendingFinalityStore::lock(
                record.namespace.join("finality-pending")
            )
            .unwrap()
            .is_some(),
            "failed authentication releases its owner"
        );
    }

    #[test]
    fn source_history_debt_torn_input_never_supplies_certificate_authority() {
        let root = crate::authenticated_fixture::TestDirectory::new();
        let (runtime, record, canonical) = retained(root.path());
        let (_, target) = super::super::tests::signed_fixture_event(1);
        let store = FinalityIntentStore::new(&record.namespace);
        store.retain(&runtime, record.prev_blocks.clone(), record.start_masterchain.clone(), &target).unwrap();
        let path = record.namespace.join(DIRECTORY).join(format!("{}-{}.json", target.slot.value(), target.block_hash.to_hex_string()));
        let temporary = path.with_extension("tmp");
        std::fs::rename(&path, &temporary).unwrap();
        std::fs::write(&temporary, b"").unwrap();
        let receipt = authenticate_source_history_debt(&record, &runtime, &Budget).unwrap();
        assert_eq!(std::fs::read(&temporary).unwrap(), b"");
        assert!(!path.exists());
        drop(receipt);
        std::fs::remove_file(canonical).unwrap();
        assert!(authenticate_source_history_debt(&record, &runtime, &Budget).is_err(), "torn data alone grants no authority");
        assert_eq!(std::fs::read(&temporary).unwrap(), b"");
    }

    #[test]
    fn source_history_debt_real_certificate_holds_owner_until_receipt_drop() {
        let root = crate::authenticated_fixture::TestDirectory::new();
        let (runtime, record, path) = retained(root.path());
        let original = std::fs::read(&path).unwrap();
        let receipt = authenticate_source_history_debt(&record, &runtime, &Budget).unwrap();
        assert!(same_record(receipt.record(), &record));
        assert!(crate::finality_delivery::PendingFinalityStore::lock(
            record.namespace.join("finality-pending")
        )
        .unwrap()
        .is_none());
        assert!(authenticate_source_history_debt(&record, &runtime, &Budget)
            .err()
            .unwrap()
            .to_string()
            .contains("owner busy"));
        let digest = receipt.digest().clone();
        drop(receipt);
        let again = authenticate_source_history_debt(&record, &runtime, &Budget).unwrap();
        assert_eq!(&digest, again.digest());
        assert_eq!(std::fs::read(path).unwrap(), original);
    }
    #[test]
    fn source_history_debt_valid_identity_bad_certificate_has_no_receipt() {
        let root = crate::authenticated_fixture::TestDirectory::new();
        let (runtime, record, path) = retained(root.path());
        let original = std::fs::read(&path).unwrap();
        let mut disk: DiskIntent = serde_json::from_slice(&original).unwrap();
        let mut wire: rtos_api::ton::consensus::simplex::Certificate =
            WireProfile::T0.deserialize_typed(&hex::decode(&disk.certificate).unwrap()).unwrap();
        let rtos_api::ton::consensus::simplex::Certificate::Consensus_Simplex_Certificate(
            ref mut cert,
        ) = wire;
        let rtos_api::ton::consensus::simplex::VoteSignatureSet::Consensus_Simplex_VoteSignatureSet(
            ref mut signatures,
        ) = cert.signatures;
        signatures.votes = Vec::new().into();
        disk.certificate = hex::encode(WireProfile::T0.serialize(&wire).unwrap());
        let invalid = serde_json::to_vec(&disk).unwrap();
        std::fs::write(&path, &invalid).unwrap();
        let error = authenticate_source_history_debt(&record, &runtime, &Budget).err().unwrap();
        assert!(error.to_string().contains("Not enough signatures"), "{error:#}");
        assert_eq!(std::fs::read(&path).unwrap(), invalid);
        // Error released the actual lock, and restoring real bytes reauthenticates.
        std::fs::write(&path, original).unwrap();
        assert!(authenticate_source_history_debt(&record, &runtime, &Budget).is_ok());
    }
    #[test]
    fn source_history_debt_budget_and_locator_failures_release_owner() {
        struct DenyRead;
        impl SourceHistoryDebtBudget for DenyRead {
            fn step(&self) -> Result<()> {
                Ok(())
            }
            fn workspace(&self, _: usize) -> Result<()> {
                Ok(())
            }
            fn read_bytes(&self, _: usize) -> Result<()> {
                fail!("injected request read budget exhausted")
            }
        }
        let root = crate::authenticated_fixture::TestDirectory::new();
        let (runtime, record, path) = retained(root.path());
        let original = std::fs::read(&path).unwrap();
        let failure = authenticate_source_history_debt(&record, &runtime, &DenyRead).err().unwrap();
        assert!(failure.to_string().contains("read budget exhausted"));
        let mut changed = record.clone();
        changed.prev_blocks[0].seq_no += 1;
        let failure = authenticate_source_history_debt(&changed, &runtime, &Budget).err().unwrap();
        assert!(failure.to_string().contains("locator mismatch"));
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert!(authenticate_source_history_debt(&record, &runtime, &Budget).is_ok());
    }
    #[test]
    fn source_history_debt_initial_tl_vector_is_charged_before_decode() {
        struct DenyVector;
        impl SourceHistoryDebtBudget for DenyVector {
            fn step(&self) -> Result<()> {
                Ok(())
            }
            fn workspace(&self, bytes: usize) -> Result<()> {
                if bytes
                    == 1024
                        * std::mem::size_of::<rtos_api::ton::consensus::simplex::VoteSignature>()
                {
                    fail!("injected TL vector allocation limit");
                }
                Ok(())
            }
            fn read_bytes(&self, _: usize) -> Result<()> {
                Ok(())
            }
        }
        let root = crate::authenticated_fixture::TestDirectory::new();
        let (runtime, record, path) = retained(root.path());
        let bytes = std::fs::read(&path).unwrap();
        let error = authenticate_source_history_debt(&record, &runtime, &DenyVector).err().unwrap();
        assert!(error.to_string().contains("TL vector allocation limit"));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert!(authenticate_source_history_debt(&record, &runtime, &Budget).is_ok());
    }
    #[test]
    fn source_history_debt_declared_signature_bytes_rejected_before_allocation() {
        let root = crate::authenticated_fixture::TestDirectory::new();
        let (runtime, record, path) = retained(root.path());
        let original = std::fs::read(&path).unwrap();
        let mut disk: DiskIntent = serde_json::from_slice(&original).unwrap();
        let raw = hex::decode(&disk.certificate).unwrap();
        let wire: rtos_api::ton::consensus::simplex::Certificate =
            WireProfile::T0.deserialize_value_bounded(&raw, raw.len()).unwrap();
        let signature = wire.signatures().votes()[0].signature();
        assert!(signature.len() > 253);
        let start =
            raw.windows(signature.len()).position(|bytes| bytes == signature.as_slice()).unwrap();
        assert_eq!(raw[start - 4], 254, "real fixture signature uses u24 length");
        let mut malicious = raw[..start - 4].to_vec();
        malicious.extend_from_slice(&[254, 0xff, 0xff, 0x7f]);
        assert!(malicious.len() < 1024, "test must remain a small declared-length attack");
        disk.certificate = hex::encode(malicious);
        let invalid = serde_json::to_vec(&disk).unwrap();
        std::fs::write(&path, &invalid).unwrap();
        // Both the ordinary scanner and gate share the same allocation guard.
        let scanner_error = read_intent(&path, &record.namespace).err().unwrap();
        let gate_error =
            authenticate_source_history_debt(&record, &runtime, &Budget).err().unwrap();
        for error in [scanner_error, gate_error] {
            let limit = error
                .downcast_ref::<rtos_api::DecodeLimitExceeded>()
                .expect("typed preallocation refusal");
            assert_eq!(limit.actual, 0x7fffff);
            assert!(limit.limit < 1024);
        }
        assert_eq!(std::fs::read(&path).unwrap(), invalid);
        std::fs::write(&path, original).unwrap();
        assert!(authenticate_source_history_debt(&record, &runtime, &Budget).is_ok());
    }
}
