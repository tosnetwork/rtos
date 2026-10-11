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
        let result: Self = serde_json::from_slice(&data)?;
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
        Ok(!output.exists())
    }
    pub(crate) fn pending_with_legacy_outputs(&self) -> Result<Vec<Vec<u8>>> {
        let mut pending = self.pending()?;
        let _guard = self.mutation.lock().unwrap();
        for path in self.paths()? {
            if self.needs_output_rebuild(&path)? {
                pending.push(read_intent(&path, &self.namespace)?.1);
            }
            if pending.len() > MAX_INTENTS {
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
        for offset in 0..paths.len().min(16) {
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
