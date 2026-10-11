// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Exact trigger output closure; no scalar slot frontier authorizes collection.
use super::*;
use std::io::Read;
const OUTPUT_DIRECTORY: &str = "outputs-v1";
const MAX_OUTPUTS: usize = 1024;
const MAX_OUTPUT_BYTES: u64 = 256 << 10;
const MAX_OUTPUT_TOTAL: u64 = 32 << 20;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExpectedFinalityOutput {
    pub block_id: String,
    pub is_final: bool,
    pub source_validator: String,
}
impl ExpectedFinalityOutput {
    pub(crate) fn new(block: &BlockIdExt, is_final: bool, source: &UInt256) -> Self {
        Self { block_id: block.to_string(), is_final, source_validator: source.to_hex_string() }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputSet {
    schema: u32,
    digest: String,
    metadata: DiskIntent,
    outputs: Vec<ExpectedFinalityOutput>,
    released: bool,
}
impl OutputSet {
    fn read(path: &std::path::Path) -> Result<Self> {
        let file = File::open(path)?;
        if file.metadata()?.len() > MAX_OUTPUT_BYTES {
            fail!("Source output map oversized");
        }
        let mut data = Vec::new();
        file.take(MAX_OUTPUT_BYTES + 1).read_to_end(&mut data)?;
        if data.len() as u64 > MAX_OUTPUT_BYTES {
            fail!("Source output map grew");
        }
        Self::parse(&data)
    }
    fn parse(data: &[u8]) -> Result<Self> {
        let result: Self = serde_json::from_slice(data)?;
        if result.schema != 1
            || !result.metadata.certificate.is_empty()
            || result.outputs.is_empty()
            || result.outputs.len() > MAX_OUTPUTS
        {
            fail!("Invalid source sealed outputs");
        }
        let _: UInt256 = result.digest.parse()?;
        let mut unique = std::collections::HashSet::new();
        for output in &result.outputs {
            let block: BlockIdExt = output.block_id.parse()?;
            let source: UInt256 = output.source_validator.parse()?;
            if !unique.insert((block, output.is_final, source)) {
                fail!("Duplicate source output");
            }
        }
        Ok(result)
    }
}
impl FinalityIntentStore {
    fn output_path(&self, id: &crate::block::RawCandidateId) -> PathBuf {
        self.namespace.join(DIRECTORY).join(OUTPUT_DIRECTORY).join(format!(
            "{}-{}.outputs",
            id.slot.value(),
            id.hash.to_hex_string()
        ))
    }
    pub(super) fn validate_output_directory(path: &std::path::Path) -> Result<()> {
        let mut count = 0;
        let mut bytes = 0u64;
        let mut temps = 0;
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if !entry.file_type()?.is_file() {
                fail!("Source outputs must be files");
            }
            let size = entry.metadata()?.len();
            if size > MAX_OUTPUT_BYTES {
                fail!("Source output record cap");
            }
            if path.extension().and_then(|s| s.to_str()) == Some("tmp") {
                temps += 1;
                if temps > 1 {
                    fail!("Uncertain source output temporaries");
                }
            } else if path.extension().and_then(|s| s.to_str()) != Some("outputs") {
                fail!("Unexpected source output artifact");
            }
            count += 1;
            bytes += size;
            if count > MAX_COMPLETED + 1 || bytes > MAX_OUTPUT_TOTAL + MAX_OUTPUT_BYTES {
                fail!("Source output history capacity exceeded");
            }
        }
        Ok(())
    }
    fn write_outputs(&self, path: &std::path::Path, value: &OutputSet) -> Result<()> {
        let parent = path.parent().unwrap();
        std::fs::create_dir_all(parent)?;
        File::open(parent.parent().unwrap())?.sync_all()?;
        Self::validate_output_directory(parent)?;
        let bytes = serde_json::to_vec(value)?;
        if bytes.len() as u64 > MAX_OUTPUT_BYTES {
            fail!("Source output map cap");
        }
        let mut count = 0;
        let mut total = 0;
        for entry in std::fs::read_dir(parent)? {
            let entry = entry?;
            if entry.path() != path {
                count += 1;
                total += entry.metadata()?.len();
            }
        }
        if count >= MAX_COMPLETED || total + bytes.len() as u64 > MAX_OUTPUT_TOTAL {
            fail!("Source output map backpressure");
        }
        let temporary = path.with_extension("tmp");
        Self::prepare_temporary(&temporary)?;
        let mut file =
            OpenOptions::new().create(true).truncate(true).write(true).open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    }
    fn canonical_intent(path: &std::path::Path) -> Result<DiskIntent> {
        let file = File::open(path)?;
        if file.metadata()?.len() > MAX_INTENT_BYTES {
            fail!("Intent oversized");
        }
        let mut bytes = Vec::new();
        file.take(MAX_INTENT_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_INTENT_BYTES {
            fail!("Intent grew");
        }
        if path.extension().and_then(|s| s.to_str()) == Some("complete") {
            let record: CompletedIntent = serde_json::from_slice(&bytes)?;
            if record.schema != 1 {
                fail!("Intent schema");
            }
            Ok(record.record)
        } else {
            Ok(serde_json::from_slice(&bytes)?)
        }
    }
    pub(crate) fn seal_outputs(
        &self,
        id: &crate::block::RawCandidateId,
        mut outputs: Vec<ExpectedFinalityOutput>,
    ) -> Result<()> {
        let _guard = self.mutation.lock().unwrap();
        if outputs.is_empty() || outputs.len() > MAX_OUTPUTS {
            fail!("Cannot seal absent/unbounded output set");
        }
        outputs.sort_by(|a, b| {
            (&a.block_id, a.is_final, &a.source_validator).cmp(&(
                &b.block_id,
                b.is_final,
                &b.source_validator,
            ))
        });
        outputs.dedup();
        let path = self.output_path(id);
        if path.exists() {
            let existing = OutputSet::read(&path)?;
            if existing.outputs != outputs {
                fail!("Finality output set changed");
            }
            File::open(&path)?.sync_all()?;
            File::open(path.parent().unwrap())?.sync_all()?;
            return Ok(());
        }
        let pending = self.namespace.join(DIRECTORY).join(format!(
            "{}-{}.json",
            id.slot.value(),
            id.hash.to_hex_string()
        ));
        let completed = self.completed_path(&pending);
        let resolved = pending.with_extension("resolved");
        let original = Self::canonical_intent(if completed.exists() {
            &completed
        } else if pending.exists() {
            &pending
        } else {
            &resolved
        })?;
        let digest = UInt256::calc_file_hash(&serde_json::to_vec(&original)?).to_hex_string();
        let mut metadata = original;
        metadata.certificate.clear();
        self.write_outputs(
            &path,
            &OutputSet { schema: 1, digest, metadata, outputs, released: false },
        )
    }
    pub(super) fn output_is_released(&self, id: &crate::block::RawCandidateId) -> Result<bool> {
        let path = self.output_path(id);
        if !path.exists() {
            return Ok(false);
        }
        let value = OutputSet::read(&path)?;
        if value.released {
            File::open(&path)?.sync_all()?;
            File::open(path.parent().unwrap())?.sync_all()?;
        }
        Ok(value.released)
    }
    pub(super) fn released_intent(&self, record: &DiskIntent) -> Result<bool> {
        let id = crate::block::RawCandidateId {
            slot: crate::block::SlotIndex::new(record.slot),
            hash: record.candidate_hash.parse()?,
        };
        let path = self.output_path(&id);
        if !path.exists() {
            return Ok(false);
        }
        let output = OutputSet::read(&path)?;
        if !output.released {
            return Ok(false);
        }
        let mut metadata = record.clone();
        metadata.certificate.clear();
        if serde_json::to_vec(&metadata)? != serde_json::to_vec(&output.metadata)? {
            fail!("Released intent domain mismatch");
        }
        File::open(&path)?.sync_all()?;
        File::open(path.parent().unwrap())?.sync_all()?;
        Ok(true)
    }
    pub(super) fn needs_output_rebuild(&self, path: &std::path::Path) -> Result<bool> {
        if !matches!(path.extension().and_then(|s| s.to_str()), Some("complete" | "resolved")) {
            return Ok(false);
        }
        let output = self
            .namespace
            .join(DIRECTORY)
            .join(OUTPUT_DIRECTORY)
            .join(path.file_name().unwrap())
            .with_extension("outputs");
        if output.exists() {
            Ok(OutputSet::read(&output)?.released)
        } else {
            Ok(true)
        }
    }
    pub(crate) fn legacy_output_count(&self) -> Result<usize> {
        let _guard = self.mutation.lock().unwrap();
        self.paths()?
            .iter()
            .try_fold(0usize, |n, path| Ok(n + usize::from(self.needs_output_rebuild(path)?)))
    }
    pub(crate) fn pending_with_legacy_outputs(&self) -> Result<Vec<Vec<u8>>> {
        let mut pending = self.pending()?;
        let _guard = self.mutation.lock().unwrap();
        for path in self.paths()? {
            if self.needs_output_rebuild(&path)? {
                pending.push(read_intent(&path, &self.namespace)?.1);
            }
            if pending.len() > MAX_INTENTS + MAX_COMPLETED {
                fail!("Legacy output reconstruction batch bound exceeded");
            }
        }
        Ok(pending)
    }
    pub(crate) fn collect_delivered(
        &self,
        runtime: &AuthenticatedSessionRuntime,
        mut delivered: impl FnMut(&ExpectedFinalityOutput) -> Result<bool>,
    ) -> Result<()> {
        let _guard = self.mutation.lock().unwrap();
        let paths: Vec<_> = self
            .paths()?
            .into_iter()
            .filter(|p| {
                matches!(p.extension().and_then(|s| s.to_str()), Some("complete" | "resolved"))
            })
            .collect();
        if paths.is_empty() {
            return Ok(());
        }
        let start = self.output_cursor.fetch_add(16, std::sync::atomic::Ordering::Relaxed);
        // The directory has explicit count/byte bounds. A cold closure must finish
        // every eligible certificate before it can hide its confirmed locator.
        for offset in 0..paths.len() {
            let cert = &paths[(start + offset) % paths.len()];
            let path = self
                .namespace
                .join(DIRECTORY)
                .join(OUTPUT_DIRECTORY)
                .join(cert.file_name().unwrap())
                .with_extension("outputs");
            if !path.exists() {
                continue;
            }
            read_intent(cert, &self.namespace)?.0.validate_runtime(runtime)?;
            let mut output = OutputSet::read(&path)?;
            let canonical = Self::canonical_intent(cert)?;
            if UInt256::calc_file_hash(&serde_json::to_vec(&canonical)?).to_hex_string()
                != output.digest
            {
                fail!("Sealed output certificate changed");
            }
            let mut all = true;
            for item in &output.outputs {
                if !delivered(item)? {
                    all = false;
                    break;
                }
            }
            if !all {
                continue;
            }
            output.released = true;
            self.write_outputs(&path, &output)?;
            // Terminal marker first; deleting the full certificate never creates absence.
            std::fs::remove_file(cert)?;
            File::open(cert.parent().unwrap())?.sync_all()?;
        }
        Ok(())
    }
}

/// Most released output sets retirement preparation will inventory.
pub(crate) const MAX_RETIREMENT_SETS: usize = MAX_COMPLETED;
/// Most output-set bytes retirement preparation will read.
pub(crate) const MAX_RETIREMENT_SET_BYTES: u64 = MAX_OUTPUT_TOTAL;
/// Largest single output-set file and output count a source can seal.
#[cfg(test)]
pub(crate) const MAX_SEALED_SET_FILE: (u64, usize) = (MAX_OUTPUT_BYTES, MAX_OUTPUTS);

/// Compares the runtime-derivable fields of sealed metadata with the
/// authenticated runtime. Session parents and start are not in the runtime;
/// the caller checks that every set agrees on them.
fn metadata_matches_runtime(m: &DiskIntent, runtime: &AuthenticatedSessionRuntime) -> bool {
    let Some(binding) = runtime.recovery_binding() else {
        return false;
    };
    let c = &binding.coordinates;
    let index = match runtime.local_role() {
        LocalRole::Validator(i) => Some(i),
        LocalRole::Observer => None,
    };
    m.schema == 1
        && m.certificate.is_empty()
        && m.global_id == runtime.pin().global_id
        && m.zerostate == runtime.pin().zerostate.to_string()
        && m.governing_masterchain == binding.governing_masterchain.to_string()
        && m.workchain == c.shard.workchain_id()
        && m.shard_prefix == c.shard.shard_prefix_with_tag()
        && m.catchain_seqno == c.catchain_seqno
        && m.vertical_seqno == c.vertical_seqno
        && m.last_key_block_seqno == c.last_key_block_seqno
        && m.new_catchain_ids == c.new_catchain_ids
        && m.protocol == runtime.protocol().version()
        && m.carrier_version == runtime.carrier_version()
        && m.wire_profile == runtime.wire_profile() as u8
        && m.profile == runtime.profile().to_hex_string()
        && m.session_id == runtime.session_id().to_hex_string()
        && m.local_adnl == UInt256::from(*runtime.local_adnl().data()).to_hex_string()
        && m.local_validator_index == index
}

/// Read-only inventory of the intent directory for retirement preparation;
/// the caller holds the namespace locks. Every certificate must already be
/// collected into a released output set: a pending, resolved or completed
/// certificate, a temporary or any unknown entry refuses.
pub(crate) fn retirement_sealed_sets(
    namespace: &std::path::Path,
    runtime: &AuthenticatedSessionRuntime,
    charge: &mut crate::finality_delivery::source_retirement::Charge,
) -> crate::finality_delivery::source_retirement::Refusal<
    Vec<crate::finality_delivery::source_retirement::RetirementSealedSet>,
> {
    use crate::finality_delivery::source_retirement::{
        existing_directory, failed, read_bounded, Bucket, RetirementRefusal, RetirementSealedSet,
    };
    let directory = namespace.join(DIRECTORY);
    existing_directory(&directory)?;
    let mut outputs_directory = None;
    for entry in std::fs::read_dir(&directory).map_err(failed)? {
        charge.step()?;
        let entry = entry.map_err(failed)?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(failed)?;
        if entry.file_name() == OUTPUT_DIRECTORY && file_type.is_dir() {
            outputs_directory = Some(path);
            continue;
        }
        if entry.file_name() == COMPLETED_DIRECTORY && file_type.is_dir() {
            // Any entry here is a certificate not yet collected: the first refuses.
            if let Some(entry) = std::fs::read_dir(&path).map_err(failed)?.next() {
                charge.step()?;
                let entry = entry.map_err(failed)?;
                let path = entry.path();
                let file_type = entry.file_type().map_err(failed)?;
                return Err(match path.extension().and_then(|s| s.to_str()) {
                    Some("complete") if file_type.is_file() => {
                        RetirementRefusal::UnreleasedOutputSet(path)
                    }
                    Some("tmp") => RetirementRefusal::UncertainTemporary(path),
                    _ => RetirementRefusal::UnknownArtifact(path),
                });
            }
            continue;
        }
        return Err(match path.extension().and_then(|s| s.to_str()) {
            Some("json" | "resolved") if file_type.is_file() => {
                RetirementRefusal::UnsealedIntent(path)
            }
            Some("tmp") => RetirementRefusal::UncertainTemporary(path),
            _ => RetirementRefusal::UnknownArtifact(path),
        });
    }
    let Some(outputs_directory) = outputs_directory else {
        return Ok(Vec::new());
    };
    existing_directory(&outputs_directory)?;
    let mut sets = Vec::new();
    let mut session_start: Option<(Vec<String>, String)> = None;
    for entry in std::fs::read_dir(&outputs_directory).map_err(failed)? {
        charge.step()?;
        let entry = entry.map_err(failed)?;
        let path = entry.path();
        if !entry.file_type().map_err(failed)?.is_file() {
            return Err(RetirementRefusal::UnknownArtifact(path));
        }
        match path.extension().and_then(|s| s.to_str()) {
            Some("outputs") => {}
            Some("tmp") => return Err(RetirementRefusal::UncertainTemporary(path)),
            _ => return Err(RetirementRefusal::UnknownArtifact(path)),
        }
        if sets.len() >= MAX_RETIREMENT_SETS {
            return Err(RetirementRefusal::BudgetExhausted("output set cap".into()));
        }
        let bytes = read_bounded(&path, MAX_OUTPUT_BYTES, Bucket::Sets, charge)?;
        charge.parse("output set parse", bytes.len())?;
        let set = OutputSet::parse(&bytes)
            .map_err(|e| RetirementRefusal::LegacyFormat(path.clone(), format!("{e:#}")))?;
        if !set.released {
            return Err(RetirementRefusal::UnreleasedOutputSet(path));
        }
        let hash: UInt256 = set.metadata.candidate_hash.parse().map_err(|e| {
            RetirementRefusal::DigestMismatch(path.clone(), format!("candidate hash: {e:#}"))
        })?;
        if path.file_stem().and_then(|s| s.to_str())
            != Some(&format!("{}-{}", set.metadata.slot, hash.to_hex_string()))
        {
            return Err(RetirementRefusal::DigestMismatch(
                path,
                "file name differs from sealed slot/candidate".into(),
            ));
        }
        if !metadata_matches_runtime(&set.metadata, runtime) {
            return Err(RetirementRefusal::DomainMismatch(
                path,
                "sealed metadata differs from authenticated runtime".into(),
            ));
        }
        let start = (set.metadata.prev_blocks.clone(), set.metadata.start_masterchain.clone());
        match &session_start {
            Some(existing) if existing != &start => {
                return Err(RetirementRefusal::DomainMismatch(
                    path,
                    "sealed sets disagree on session start".into(),
                ))
            }
            Some(_) => {}
            None => session_start = Some(start),
        }
        let mut copies = 0usize;
        for output in &set.outputs {
            copies = output
                .block_id
                .len()
                .checked_add(output.source_validator.len())
                .and_then(|entry| entry.checked_add(std::mem::size_of::<(String, bool, String)>()))
                .and_then(|entry| copies.checked_add(entry))
                .ok_or_else(|| RetirementRefusal::BudgetExhausted("output copy overflow".into()))?;
        }
        charge.workspace("output set copy", copies)?;
        sets.push(RetirementSealedSet {
            file_hash: UInt256::calc_file_hash(&bytes),
            outputs: set
                .outputs
                .iter()
                .map(|o| (o.block_id.clone(), o.is_final, o.source_validator.clone()))
                .collect(),
            path,
        });
    }
    Ok(sets)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_output_set_preserves_ancestor_role_holes_and_rebuilds_legacy() {
        let directory = crate::authenticated_fixture::TestDirectory::new();
        let (runtime, _) = crate::finality_delivery::tests::fixture();
        assert!(runtime.recovery_binding().is_some());
        let namespace =
            PathBuf::from(runtime.runtime_directory(directory.path().to_str().unwrap()).unwrap());
        let _owner = crate::finality_delivery::PendingFinalityStore::open(&namespace).unwrap();
        let store = FinalityIntentStore::new(&namespace);
        // Structural cert fixture tests exact source storage, not PQ verification.
        let event = crate::simplex_state::BlockFinalizedEvent {
            slot: crate::block::SlotIndex::new(100),
            block_hash: UInt256::from([7; 32]),
            block_id: None,
            certificate: std::sync::Arc::new(crate::certificate::Certificate {
                vote: crate::simplex_state::FinalizeVote {
                    slot: crate::block::SlotIndex::new(100),
                    block_hash: UInt256::from([7; 32]),
                },
                signatures: Vec::new(),
            }),
        };
        let trigger =
            crate::block::RawCandidateId { slot: event.slot, hash: event.block_hash.clone() };
        store
            .retain(
                &runtime,
                vec![runtime.pin().zerostate.clone()],
                runtime.pin().zerostate.clone(),
                &event,
            )
            .unwrap();
        store.resolve(&trigger).unwrap();
        assert_eq!(store.pending_count().unwrap(), 0);
        assert_eq!(store.legacy_output_count().unwrap(), 1);
        assert_eq!(
            store.pending_with_legacy_outputs().unwrap().len(),
            1,
            "old completed certificate must reach real recovery walk"
        );
        let mut block = runtime.pin().zerostate.clone();
        block.seq_no = 1;
        let source = UInt256::from([3; 32]);
        let final_output = ExpectedFinalityOutput::new(&block, true, &source);
        let approval_same_block = ExpectedFinalityOutput::new(&block, false, &source);
        block.seq_no = 2;
        let ancestor = ExpectedFinalityOutput::new(&block, false, &source);
        let outputs = vec![final_output.clone(), approval_same_block.clone(), ancestor.clone()];
        store.seal_outputs(&trigger, outputs.clone()).unwrap();
        assert_eq!(store.legacy_output_count().unwrap(), 0);
        let pending =
            namespace.join(DIRECTORY).join(format!("100-{}.json", trigger.hash.to_hex_string()));
        let completed = store.completed_path(&pending);
        let original = std::fs::read(&completed).unwrap();
        // A higher ancestor and Final for the same block do not close Approval.
        store.collect_delivered(&runtime, |output| Ok(output != &approval_same_block)).unwrap();
        assert_eq!(std::fs::read(&completed).unwrap(), original);
        assert!(
            store.seal_outputs(&trigger, vec![final_output]).is_err(),
            "sealed set cannot shrink after restart"
        );
        drop(store);
        let store = FinalityIntentStore::new(&namespace);
        store.collect_delivered(&runtime, |_| Ok(true)).unwrap();
        assert!(!completed.exists());
        assert!(store.output_is_released(&trigger).unwrap());
        store
            .retain(
                &runtime,
                vec![runtime.pin().zerostate.clone()],
                runtime.pin().zerostate.clone(),
                &event,
            )
            .unwrap();
        assert!(!pending.exists(), "released event replay never recreates large certificate");
        store.seal_outputs(&trigger, outputs).unwrap();
        store.resolve(&trigger).unwrap();
    }
}

#[cfg(test)]
#[path = "finality_output_capacity_tests.rs"]
mod capacity_tests;
