// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Exact source completion. Disk records and offers are not consumed capabilities.
use super::*;
use std::sync::atomic::Ordering;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DiskRecoveryBinding {
    governing: String,
    workchain: i32,
    shard: u64,
    catchain: u32,
    vertical: u32,
    last_key: u32,
    new_ids: bool,
}
impl DiskRecoveryBinding {
    pub(super) fn from_binding(
        value: &consensus_common::session_runtime::SessionRecoveryBinding,
    ) -> Self {
        let c = &value.coordinates;
        Self {
            governing: value.governing_masterchain.to_string(),
            workchain: c.shard.workchain_id(),
            shard: c.shard.shard_prefix_with_tag(),
            catchain: c.catchain_seqno,
            vertical: c.vertical_seqno,
            last_key: c.last_key_block_seqno,
            new_ids: c.new_catchain_ids,
        }
    }
    fn binding(&self) -> Result<consensus_common::session_runtime::SessionRecoveryBinding> {
        Ok(consensus_common::session_runtime::SessionRecoveryBinding {
            governing_masterchain: self.governing.parse()?,
            coordinates: consensus_common::session_runtime::SessionRecoveryCoordinates {
                shard: rtos_block::ShardIdent::with_tagged_prefix(self.workchain, self.shard)?,
                catchain_seqno: self.catchain,
                vertical_seqno: self.vertical,
                last_key_block_seqno: self.last_key,
                new_catchain_ids: self.new_ids,
            },
        })
    }
}
/// Only this module can construct this value, after real source synchronization.
/// No Clone, Deserialize or public constructor intentionally exists.
pub struct DeliveredConfirmation {
    offer: CloseOffer,
    source_id: UInt256,
}
impl DeliveredConfirmation {
    pub fn offer(&self) -> &CloseOffer {
        &self.offer
    }
    pub fn source_id(&self) -> &UInt256 {
        &self.source_id
    }
}
pub type DeliveredCompletion = Box<dyn FnOnce(Result<()>) + Send>;
pub type DeliveredCompletionSink =
    Arc<dyn Fn(DeliveredConfirmation, DeliveredCompletion) -> Result<()> + Send + Sync>;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveredDisk {
    schema: u32,
    reference: CanonicalReference,
    generation: u64,
    #[serde(default)]
    node_confirmed: bool,
}
impl DeliveredDisk {
    fn offer(&self) -> Result<CloseOffer> {
        if self.schema != 1 || self.generation == 0 {
            fail!("Unknown Delivered schema/generation");
        }
        Ok(CloseOffer { request: reference_request(&self.reference)?, generation: self.generation })
    }
    fn read(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        if file.metadata()?.len() > MAX_REFERENCE_BYTES {
            fail!("Delivered record oversized");
        }
        let mut bytes = Vec::new();
        file.take(MAX_REFERENCE_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_REFERENCE_BYTES {
            fail!("Delivered record grew");
        }
        Self::parse(path, &bytes)
    }
    fn parse(path: &Path, bytes: &[u8]) -> Result<Self> {
        let value: Self = serde_json::from_slice(bytes)?;
        value.offer()?;
        if path.file_stem().and_then(|s| s.to_str())
            != Some(&value.reference.metadata_record()?.id()?.to_hex_string())
        {
            fail!("Delivered filename mismatch");
        }
        Ok(value)
    }
}
fn reference_request(reference: &CanonicalReference) -> Result<CloseFinalityRequest> {
    let record = reference.metadata_record()?;
    Ok(CloseFinalityRequest {
        canonical: reference.request()?,
        domain: {
            let mut domain = record.close_domain();
            domain.recovery_binding = reference
                .recovery_binding
                .as_ref()
                .map(DiskRecoveryBinding::binding)
                .transpose()?;
            domain
        },
        source_digest: reference.digest.parse()?,
        created_at_unix_secs: record.created_at_unix_secs,
    })
}
fn check_binding(
    runtime: &AuthenticatedSessionRuntime,
    reference: &CanonicalReference,
) -> Result<()> {
    let record = reference.metadata_record()?;
    if reference_request(reference)?.domain != FinalityCloseDomain::from_runtime(runtime)
        || record.local_adnl != UInt256::from(*runtime.local_adnl().data())
        || record.local_validator_index
            != match runtime.local_role() {
                consensus_common::session_runtime::LocalRole::Validator(index) => Some(index),
                consensus_common::session_runtime::LocalRole::Observer => None,
            }
    {
        fail!("Delivered source runtime binding mismatch");
    }
    if !record.is_final || !record.block_id.shard().is_masterchain() {
        fail!("Delivered requires MC Final custody");
    }
    let mut found = false;
    for descriptor in runtime.committee() {
        if UInt256::from(
            *crate::SimplexSessionNode::from_descriptor(descriptor)?.identity.id().data(),
        ) == record.source_validator
        {
            found = true;
        }
    }
    if !found {
        fail!("Delivered source absent from authenticated committee");
    }
    Ok(())
}
impl PendingFinalityStore {
    pub(super) fn delivered_path(&self, id: &UInt256) -> PathBuf {
        self.directory.join(REFERENCE_DIRECTORY).join(format!("{}.delivered", id.to_hex_string()))
    }
    pub(super) fn delivered_reference(&self, id: &UInt256) -> Result<Option<CanonicalReference>> {
        let path = self.delivered_path(id);
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(DeliveredDisk::read(&path)?.reference))
    }
    pub(super) fn close_locator(
        self: &Arc<Self>,
        id: &UInt256,
    ) -> Result<Option<FinalityCloseRecovery>> {
        let _guard = self.mutation.lock().unwrap();
        self.check_delivered_health()?;
        let delivered = self.delivered_path(id);
        let reference = self.reference_path(id);
        let reference = if delivered.exists() {
            DeliveredDisk::read(&delivered)?.reference
        } else if reference.exists() {
            CanonicalReference::read(&reference)?
        } else {
            let ack = self.directory.join(format!("{}.acked", id.to_hex_string()));
            if !ack.exists() {
                return Ok(None);
            }
            let record = PendingFinalityRecord::read(&ack)?;
            let ack = AcknowledgedRecord::read(&ack)?;
            let mut metadata: DiskRecord = serde_json::from_slice(&record.encode()?)?;
            metadata.data.clear();
            metadata.signature_set.clear();
            CanonicalReference {
                recovery_binding: ack
                    .recovery_binding
                    .or_else(|| self.runtime_binding.lock().unwrap().clone()),
                schema: 1,
                node_receipt: ack.node_receipt,
                digest: record.canonical_digest()?.to_hex_string(),
                metadata,
            }
        };
        reference_request(&reference)?;
        let record = reference.metadata_record()?;
        if !record.is_final || !record.block_id.shard().is_masterchain() {
            if delivered.exists() {
                fail!("Delivered role outside MC Final custody");
            }
            // Other roles retain their ordinary WAL custody and must re-enter
            // node acceptance. They cannot use the MC Final release protocol.
            return Ok(None);
        }
        Ok(Some(FinalityCloseRecovery { store: self.clone(), reference }))
    }
    pub(super) fn check_delivered_health(&self) -> Result<()> {
        if self.delivered_uncertain.load(Ordering::Acquire) {
            fail!("Source Delivered sync uncertain: reopen required");
        }
        Ok(())
    }
    fn mark_node_confirmed(&self, id: &UInt256, offer: &CloseOffer) -> Result<()> {
        let _guard = self.mutation.lock().unwrap();
        self.check_delivered_health()?;
        let path = self.delivered_path(id);
        let mut record = DeliveredDisk::read(&path)?;
        if record.offer()? != *offer {
            fail!("Node terminal completion changed source offer");
        }
        let result = (|| -> Result<()> {
            record.node_confirmed = true;
            let bytes = serde_json::to_vec(&record)?;
            if bytes.len() as u64 > MAX_REFERENCE_BYTES {
                fail!("Confirmed source record cap");
            }
            let temp = path.with_extension("tmp");
            Self::prepare_temporary(&temp)?;
            let mut file =
                OpenOptions::new().create(true).truncate(true).write(true).open(&temp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            #[cfg(test)]
            if let Some(gate) = self.confirmed_rename_gate.lock().unwrap().take() {
                gate.wait();
            }
            std::fs::rename(temp, &path)?;
            #[cfg(test)]
            if self.fail_confirmed_once.swap(false, Ordering::AcqRel) {
                fail!("Injected source confirmed sync boundary failure");
            }
            File::open(path.parent().unwrap())?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            self.delivered_uncertain.store(true, Ordering::Release);
        }
        result
    }
    fn confirmed_without_backup(&self, id: &UInt256) -> Result<bool> {
        let path = self.delivered_path(id);
        if !path.exists() {
            return Ok(false);
        }
        let disk = DeliveredDisk::read(&path)?;
        Ok(disk.node_confirmed
            && !self.reference_path(id).exists()
            && !["json", "acked"]
                .iter()
                .any(|ext| self.directory.join(format!("{}.{ext}", id.to_hex_string())).exists()))
    }
    fn output_delivered(
        &self,
        runtime: &AuthenticatedSessionRuntime,
        output: &crate::finality_recovery::ExpectedFinalityOutput,
    ) -> Result<bool> {
        self.check_delivered_health()?;
        for path in self.paths()? {
            if path.extension().and_then(|s| s.to_str()) != Some("delivered") {
                continue;
            }
            let disk = DeliveredDisk::read(&path)?;
            let record = disk.reference.metadata_record()?;
            if record.block_id.to_string() == output.block_id
                && record.is_final == output.is_final
                && record.source_validator.to_hex_string() == output.source_validator
            {
                let _receipt = self.commit_delivered(runtime, &disk.reference, &disk.offer()?)?;
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn commit_delivered(
        &self,
        runtime: &AuthenticatedSessionRuntime,
        reference: &CanonicalReference,
        offer: &CloseOffer,
    ) -> Result<DeliveredConfirmation> {
        let _guard = self.mutation.lock().unwrap();
        self.check_delivered_health()?;
        check_binding(runtime, reference)?;
        if runtime.recovery_binding().is_none() {
            fail!("Delivered source has no authenticated recovery anchor");
        }
        let expected_namespace = PathBuf::from(runtime.runtime_directory("")?);
        if self.directory.parent().and_then(Path::file_name) != expected_namespace.file_name() {
            fail!("Delivered store is not the authenticated runtime namespace");
        }
        if offer.request != reference_request(reference)? || offer.generation == 0 {
            fail!("Delivered offer exact binding mismatch");
        }
        let id = reference.metadata_record()?.id()?;
        let path = self.delivered_path(&id);
        let parent = path.parent().unwrap();
        // Check all old copies before beginning a potentially uncertain transition.
        for extension in ["json", "acked"] {
            let full = self.directory.join(format!("{}.{extension}", id.to_hex_string()));
            if full.exists() {
                reference.matches(&PendingFinalityRecord::read(&full)?)?;
            }
        }
        let old_reference = self.reference_path(&id);
        if old_reference.exists()
            && reference_request(&CanonicalReference::read(&old_reference)?)? != offer.request
        {
            fail!("Delivered conflicts with canonical reference");
        }
        let disk = DeliveredDisk {
            schema: 1,
            reference: reference.clone(),
            generation: offer.generation,
            node_confirmed: false,
        };
        let bytes = serde_json::to_vec(&disk)?;
        if bytes.len() as u64 > MAX_REFERENCE_BYTES {
            fail!("Delivered exceeds record quota");
        }
        if path.exists() {
            if DeliveredDisk::read(&path)?.offer()? != *offer {
                fail!("Conflicting Delivered generation");
            }
        } else {
            let paths = self.paths_under_mutation()?;
            let compact: Vec<_> = paths
                .iter()
                .filter(|p| {
                    matches!(
                        p.extension().and_then(|s| s.to_str()),
                        Some("reference" | "delivered")
                    )
                })
                .collect();
            let count = compact.len();
            let total = compact
                .iter()
                .try_fold(0u64, |n, p| Ok::<_, anyhow::Error>(n + std::fs::metadata(p)?.len()))?;
            // Reserve one transition record; never delete old source evidence to make space.
            if count >= MAX_REFERENCES - 1
                || total + bytes.len() as u64 > MAX_REFERENCE_TOTAL - MAX_REFERENCE_BYTES
            {
                fail!("Delivered history capacity exhausted");
            }
        }
        let result = (|| -> Result<()> {
            std::fs::create_dir_all(parent)?;
            File::open(&self.directory)?.sync_all()?;
            if !path.exists() {
                let temp = path.with_extension("tmp");
                Self::prepare_temporary(&temp)?;
                let mut file =
                    OpenOptions::new().create(true).truncate(true).write(true).open(&temp)?;
                file.write_all(&bytes)?;
                file.sync_all()?;
                drop(file);
                std::fs::rename(temp, &path)?;
            }
            #[cfg(test)]
            if self.fail_delivered_once.swap(false, Ordering::AcqRel) {
                fail!("Injected Delivered directory sync failure");
            }
            // Reopen is not a receipt: actual file+directory sync is repeated.
            if DeliveredDisk::read(&path)?.offer()? != *offer {
                fail!("Delivered changed during sync");
            }
            File::open(&path)?.sync_all()?;
            File::open(parent)?.sync_all()?;
            for old in [
                self.directory.join(format!("{}.json", id.to_hex_string())),
                self.directory.join(format!("{}.acked", id.to_hex_string())),
                old_reference,
            ] {
                match std::fs::remove_file(old) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
            File::open(parent)?.sync_all()?;
            #[cfg(test)]
            if self.fail_delivered_cleanup_once.swap(false, Ordering::AcqRel) {
                fail!("Injected source cleanup sync boundary failure");
            }
            File::open(&self.directory)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            self.delivered_uncertain.store(true, Ordering::Release);
        }
        result?;
        Ok(DeliveredConfirmation { offer: offer.clone(), source_id: id })
    }
}
/// A locator holding the actual source directory lock; not a consumed receipt.
/// `metadata` contains empty payload/carrier and must be historically authorized.
pub struct FinalityCloseRecovery {
    store: Arc<PendingFinalityStore>,
    pub(super) reference: CanonicalReference,
}
impl FinalityCloseRecovery {
    pub fn namespace(&self) -> &Path {
        self.store.directory.parent().expect("source namespace")
    }
    pub fn metadata(&self) -> Result<PendingFinalityRecord> {
        self.reference.metadata_record()
    }
    pub fn request(&self) -> Result<CloseFinalityRequest> {
        reference_request(&self.reference)
    }
    pub fn resume(
        mut self,
        runtime: Arc<AuthenticatedSessionRuntime>,
        sink: consensus_common::finality_delivery::DurableFinalitySinkPtr,
        confirm: DeliveredCompletionSink,
        completion: DeliveredCompletion,
    ) -> Result<()> {
        if self.reference.recovery_binding.is_none() {
            self.reference.recovery_binding =
                runtime.recovery_binding().map(DiskRecoveryBinding::from_binding);
        }
        check_binding(&runtime, &self.reference)?;
        let request = self.request()?;
        let expected = request.clone();
        let lookup_sink = sink.clone();
        sink.lookup_terminal(
            request,
            Box::new(move |result| {
                let offer_request = expected.clone();
                let finish = move |offer: Result<CloseOffer>| {
                    let result = offer.and_then(|offer| {
                        if offer.request != expected {
                            fail!("Node returned unrelated finality close offer");
                        }
                        self.store.commit_delivered(&runtime, &self.reference, &offer)
                    });
                    match result {
                        Err(error) => {
                            drop(self);
                            completion(Err(error));
                        }
                        Ok(receipt) => {
                            // Keep this store lock until the node's actual terminal completion.
                            let expected_offer = receipt.offer().clone();
                            let source_id = receipt.source_id().clone();
                            let owner = self;
                            let done = Arc::new(Mutex::new(Some(completion)));
                            let callback_done = done.clone();
                            let admitted = confirm(
                                receipt,
                                Box::new(move |result| {
                                    let result = result.and_then(|()| {
                                        owner
                                            .store
                                            .intents
                                            .collect_delivered(&runtime, |output| {
                                                owner.store.output_delivered(&runtime, output)
                                            })?;
                                        owner.store.mark_node_confirmed(&source_id, &expected_offer)
                                    });
                                    drop(owner);
                                    if let Some(done) = callback_done.lock().unwrap().take() {
                                        done(result);
                                    }
                                }),
                            );
                            if let Err(error) = admitted {
                                if let Some(done) = done.lock().unwrap().take() {
                                    done(Err(error));
                                }
                            }
                        }
                    }
                };
                match result {
                    Ok(
                        FinalityTerminalLookup::CloseOffered(offer)
                        | FinalityTerminalLookup::Released(offer),
                    ) => finish(Ok(offer)),
                    Ok(FinalityTerminalLookup::Retained) => {
                        // An admitted offer callback owns source retention. Admission errors must
                        // still complete the outer lookup exactly once.
                        let finish = Arc::new(Mutex::new(Some(finish)));
                        let callback = finish.clone();
                        if let Err(error) = lookup_sink.offer_close(
                            offer_request,
                            Box::new(move |result| {
                                if let Some(finish) = callback.lock().unwrap().take() {
                                    finish(result);
                                }
                            }),
                        ) {
                            if let Some(finish) = finish.lock().unwrap().take() {
                                finish(Err(error));
                            }
                        }
                    }
                    Err(error) => finish(Err(error)),
                }
            }),
        )
    }
}

/// Bounded source terminal locators. Busy namespaces are skipped; malformed
/// records are errors. The caller must authenticate each metadata domain before resume.
pub fn scan_finality_closures(root: &Path) -> Result<Vec<FinalityCloseRecovery>> {
    let base = root.join("consensus/v2");
    if !base.exists() {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    let mut namespaces = 0;
    for entry in std::fs::read_dir(base)? {
        let entry = entry?;
        namespaces += 1;
        if namespaces > MAX_REFERENCES {
            fail!("Closure namespace scan bound");
        }
        if !entry.file_type()?.is_dir() {
            continue;
        }
        result.extend(scan_finality_closures_namespace(&entry.path())?);
        if result.len() > MAX_REFERENCES {
            fail!("Closure aggregate scan bound");
        }
    }
    Ok(result)
}
/// Single owned namespace. Callers may select a bounded batch and drop others;
/// prefer the cursor variant in a long-running recovery service.
pub fn scan_finality_closures_namespace(namespace: &Path) -> Result<Vec<FinalityCloseRecovery>> {
    scan_finality_closures_namespace_batch(namespace, None, MAX_REFERENCES)
}
/// Stable source-ID order with wraparound. Advance `after` even when an item
/// fails authentication/admission, so a low-ID failure cannot starve later debt.
pub struct FinalityClosureBatch {
    /// Includes per-record failures; those files remain untouched.
    pub items: Vec<(UInt256, Result<FinalityCloseRecovery>)>,
    /// Last visited ID, including confirmed and malformed records.
    pub next_cursor: Option<UInt256>,
}
pub fn scan_finality_closures_namespace_batch(
    namespace: &Path,
    after: Option<&UInt256>,
    limit: usize,
) -> Result<Vec<FinalityCloseRecovery>> {
    scan_finality_closures_namespace_report(namespace, after, limit)?
        .items
        .into_iter()
        .map(|(_, item)| item)
        .collect()
}
pub fn scan_finality_closures_namespace_report(
    namespace: &Path,
    after: Option<&UInt256>,
    limit: usize,
) -> Result<FinalityClosureBatch> {
    if limit == 0 || limit > MAX_REFERENCES {
        fail!("Invalid source closure batch limit");
    }
    let mut batch = FinalityClosureBatch { items: Vec::new(), next_cursor: None };
    let directory = namespace.join(DIRECTORY);
    if !directory.exists() {
        return Ok(batch);
    }
    let Some(store) = PendingFinalityStore::lock(directory)? else {
        return Ok(batch);
    };
    let mut ids = std::collections::BTreeSet::new();
    // Enumeration is bounded by physical directory quotas, before decoding.
    for path in store.paths()? {
        if !matches!(
            path.extension().and_then(|s| s.to_str()),
            Some("acked" | "reference" | "delivered")
        ) {
            continue;
        }
        let id: UInt256 = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| error!("Closure filename"))?
            .parse()?;
        ids.insert(id);
    }
    let mut ordered: Vec<_> = ids.into_iter().collect();
    if let Some(after) = after {
        let split = ordered.partition_point(|id| id <= after);
        ordered.rotate_left(split);
    }
    let mut bytes = 0u64;
    for id in ordered.into_iter().take(limit) {
        batch.next_cursor = Some(id.clone());
        let item = (|| -> Result<Option<FinalityCloseRecovery>> {
            if store.confirmed_without_backup(&id)? {
                return Ok(None);
            }
            let locator = store.close_locator(&id)?;
            if let Some(locator) = &locator {
                bytes += serde_json::to_vec(&locator.reference)?.len() as u64;
                if bytes > MAX_REFERENCE_TOTAL {
                    fail!("Closure scan byte bound");
                }
            }
            Ok(locator)
        })();
        match item {
            Ok(Some(locator)) => batch.items.push((id, Ok(locator))),
            Ok(None) => {}
            Err(error) => batch.items.push((id, Err(error))),
        }
    }
    Ok(batch)
}

impl SourceFinalityDelivery {
    pub(crate) fn consumed(&self, draft: &FinalizedDeliveryDraft) -> Result<bool> {
        let _timing = self.operation_timer("consumed");
        let id = PendingFinalityRecord::from_draft(&self.runtime, draft)?.id()?;
        if matches!(
            self.stages.lock().unwrap().get(&id),
            Some(SourceStage::Consumed | SourceStage::AcceptanceConsumed)
        ) {
            return Ok(true);
        }
        if self.store.confirmed_without_backup(&id)? {
            let disk = DeliveredDisk::read(&self.store.delivered_path(&id))?;
            let _receipt =
                self.store.commit_delivered(&self.runtime, &disk.reference, &disk.offer()?)?;
            return Ok(true);
        }
        Ok(false)
    }
    pub(super) fn lookup_before_replay(
        self: &Arc<Self>,
        id: UInt256,
        mut locator: FinalityCloseRecovery,
        source_info: consensus_common::BlockSourceInfo,
    ) -> Result<()> {
        if locator.reference.recovery_binding.is_none() {
            locator.reference.recovery_binding =
                self.runtime.recovery_binding().map(DiskRecoveryBinding::from_binding);
        }
        let request = locator.request()?;
        let expected = request.clone();
        let owner = self.clone();
        self.sink.lookup_terminal(
            request,
            Box::new(move |result| match result {
                Ok(FinalityTerminalLookup::Retained) => {
                    if locator.store.delivered_path(&id).exists() {
                        owner.retry(&id);
                        return; // node terminal regression; never rehydrate Delivered
                    }
                    if let Err(error) =
                        owner.lookup_reference(id.clone(), locator.reference, source_info)
                    {
                        log::error!("Retained source canonical replay failed: {error}");
                        owner.retry(&id);
                    }
                }
                Ok(
                    FinalityTerminalLookup::CloseOffered(offer)
                    | FinalityTerminalLookup::Released(offer),
                ) => {
                    if offer.request != expected {
                        owner.retry(&id);
                        return;
                    }
                    owner.resume_close(id, locator);
                }
                Err(error) => {
                    log::debug!("Source terminal replay retained: {error}");
                    owner.retry(&id);
                }
            }),
        )
    }
    fn resume_close(self: &Arc<Self>, id: UInt256, locator: FinalityCloseRecovery) {
        let Some(confirm) = self.delivered_sink.clone() else {
            return;
        };
        let owner = self.clone();
        let completed_id = id.clone();
        let result = locator.resume(
            self.runtime.clone(),
            self.sink.clone(),
            confirm,
            Box::new(move |result| {
                owner.closing.lock().unwrap().remove(&completed_id);
                match result {
                    Ok(()) => {
                        owner.stages.lock().unwrap().insert(completed_id, SourceStage::Consumed);
                        owner.notify_ready();
                    }
                    Err(error) => {
                        log::debug!("Source Delivered remains retained for retry: {error}");
                        let replay = matches!(
                            owner.stages.lock().unwrap().get(&completed_id),
                            Some(SourceStage::Running)
                        );
                        if replay {
                            owner.retry(&completed_id);
                        }
                    }
                }
            }),
        );
        if let Err(error) = result {
            self.closing.lock().unwrap().remove(&id);
            let replay = matches!(self.stages.lock().unwrap().get(&id), Some(SourceStage::Running));
            if replay {
                self.retry(&id);
            }
            log::debug!("Source close not admitted: {error}");
        }
    }
    /// Like C++ actor IO awaits, source closure maintenance must not execute
    /// filesystem scans on the consensus event loop. Coalesce wakeups while
    /// one scan is running; its Arc retains the namespace and shutdown receipt.
    pub(crate) fn request_closing_maintenance(self: &Arc<Self>) -> Result<bool> {
        // Only MC Final can enter the release protocol (close_locator and
        // validate_runtime enforce the same custody rule). WC acceptance keeps
        // its normal replay path; scanning those retained files cannot close it.
        if self.delivered_sink.is_none() || !self.runtime.shard().is_masterchain() {
            return Ok(false);
        }
        {
            let mut state = self
                .closing_maintenance
                .lock()
                .map_err(|_| error!("Source maintenance scheduling poisoned"))?;
            let now = std::time::Instant::now();
            if state.running || now < state.next_attempt {
                return Ok(false);
            }
            state.running = true;
            state.next_attempt = now + std::time::Duration::from_secs(1);
        }
        let owner = self.clone();
        let name = format!("SXClose-{}", &self.runtime.session_id().to_hex_string()[..8]);
        if let Err(error) = std::thread::Builder::new().name(name).spawn(move || {
            let _completion = ClosingMaintenanceCompletion(owner.clone());
            if let Err(error) = owner.maintain_closing() {
                log::error!("Source closure retained: {error}");
            }
        }) {
            self.closing_maintenance.lock().unwrap().running = false;
            return Err(error.into());
        }
        Ok(true)
    }

    /// Bounded round-robin batch; failed requests wait at least one second.
    pub(crate) fn maintain_closing(self: &Arc<Self>) -> Result<()> {
        let _timing = self.operation_timer("maintain_closing");
        if self.delivered_sink.is_none() || !self.runtime.shard().is_masterchain() {
            return Ok(());
        }
        let mut cursor = self.close_cursor.lock().unwrap();
        if cursor.0.elapsed() < std::time::Duration::from_secs(1) {
            return Ok(());
        }
        cursor.0 = std::time::Instant::now();
        let paths = self.store.paths()?;
        let candidates: Vec<_> = paths
            .into_iter()
            .filter(|p| {
                matches!(
                    p.extension().and_then(|s| s.to_str()),
                    Some("acked" | "reference" | "delivered")
                )
            })
            .collect();
        if candidates.is_empty() {
            return Ok(());
        }
        let count = candidates.len().min(16);
        let mut batch = Vec::with_capacity(count);
        for _ in 0..count {
            let path = &candidates[cursor.1 % candidates.len()];
            cursor.1 = cursor.1.wrapping_add(1);
            let id: UInt256 = path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| error!("Invalid source closure name"))?
                .parse()?;
            batch.push(id);
        }
        drop(cursor);
        for id in batch {
            if matches!(self.stages.lock().unwrap().get(&id), Some(SourceStage::Consumed)) {
                continue;
            }
            {
                let mut closing = self.closing.lock().unwrap();
                if closing.len() >= 16 || !closing.insert(id.clone()) {
                    continue;
                }
            }
            match self.store.close_locator(&id) {
                Ok(Some(locator)) => self.resume_close(id, locator),
                Ok(None) => {
                    self.closing.lock().unwrap().remove(&id);
                }
                Err(error) => {
                    self.closing.lock().unwrap().remove(&id);
                    return Err(error);
                }
            }
        }
        self.intents.collect_delivered(&self.runtime, |output| {
            self.store.output_delivered(&self.runtime, output)
        })?;
        Ok(())
    }
}

/// Comparison-only source ID, using the single original ID implementation.
pub fn close_source_id(request: &CloseFinalityRequest) -> Result<UInt256> {
    let domain = &request.domain;
    let canonical = &request.canonical;
    PendingFinalityRecord {
        pin: domain.pin.clone(),
        protocol: domain.protocol,
        carrier_version: domain.carrier_version,
        wire_profile: domain.wire_profile,
        profile: domain.profile.clone(),
        session_id: domain.session_id.clone(),
        block_id: canonical.block_id.clone(),
        local_adnl: canonical.local_adnl.clone(),
        local_validator_index: canonical.local_validator_index,
        source_validator: canonical.source_validator.clone(),
        data: Vec::new(),
        signature_set: Vec::new(),
        is_final: canonical.role == FinalityDeliveryRole::Final,
        last_mc_finalized_seqno: 0,
        candidate_already_sent: false,
        created_at_unix_secs: request.created_at_unix_secs,
    }
    .id()
}

impl PendingFinalityStore {
    /// Read-only inventory of the pending directory for retirement
    /// preparation; the caller holds this store's lock. Anything other than
    /// node-confirmed Delivered records refuses. Each record is re-synced so a
    /// confirmation whose rename sync was uncertain before reopen is durable.
    pub(super) fn retirement_delivered(
        &self,
        runtime: &AuthenticatedSessionRuntime,
        charge: &mut super::source_retirement::Charge,
    ) -> super::source_retirement::Refusal<Vec<super::source_retirement::RetirementDelivered>> {
        use super::source_retirement::{
            existing_directory, failed, read_bounded, Bucket, RetirementDelivered,
            RetirementRefusal,
        };
        let _guard = self.mutation.lock().map_err(|_| failed("source mutation lock poisoned"))?;
        let mut references = None;
        for entry in std::fs::read_dir(&self.directory).map_err(failed)? {
            charge.step()?;
            let entry = entry.map_err(failed)?;
            let path = entry.path();
            let name = entry.file_name();
            let file_type = entry.file_type().map_err(failed)?;
            if name == ".lock" && file_type.is_file() {
                continue;
            }
            if name == REFERENCE_DIRECTORY && file_type.is_dir() {
                references = Some(path);
                continue;
            }
            match path.extension().and_then(|s| s.to_str()) {
                Some("tmp") => return Err(RetirementRefusal::UncertainTemporary(path)),
                Some("json" | "acked") if file_type.is_file() => {
                    return Err(RetirementRefusal::PendingRecord(path))
                }
                _ => return Err(RetirementRefusal::UnknownArtifact(path)),
            }
        }
        let Some(references) = references else {
            return Ok(Vec::new());
        };
        existing_directory(&references)?;
        let mut delivered = Vec::new();
        for entry in std::fs::read_dir(&references).map_err(failed)? {
            charge.step()?;
            let entry = entry.map_err(failed)?;
            let path = entry.path();
            if !entry.file_type().map_err(failed)?.is_file() {
                return Err(RetirementRefusal::UnknownArtifact(path));
            }
            match path.extension().and_then(|s| s.to_str()) {
                Some("delivered") => {}
                Some("tmp") => return Err(RetirementRefusal::UncertainTemporary(path)),
                Some("reference") => return Err(RetirementRefusal::PendingRecord(path)),
                _ => return Err(RetirementRefusal::UnknownArtifact(path)),
            }
            if delivered.len() >= MAX_REFERENCES {
                return Err(RetirementRefusal::BudgetExhausted("Delivered record cap".into()));
            }
            let bytes = read_bounded(&path, MAX_REFERENCE_BYTES, Bucket::Delivered, charge)?;
            charge.parse("Delivered parse", bytes.len())?;
            let disk = DeliveredDisk::parse(&path, &bytes)
                .map_err(|e| RetirementRefusal::LegacyFormat(path.clone(), format!("{e:#}")))?;
            check_binding(runtime, &disk.reference)
                .map_err(|e| RetirementRefusal::DomainMismatch(path.clone(), format!("{e:#}")))?;
            if !disk.node_confirmed {
                return Err(RetirementRefusal::NotNodeConfirmed(path));
            }
            let record = disk.reference.metadata_record().map_err(failed)?;
            let offer = disk.offer().map_err(failed)?;
            File::open(&path).and_then(|f| f.sync_all()).map_err(failed)?;
            delivered.push(RetirementDelivered {
                file_hash: UInt256::calc_file_hash(&bytes),
                block_id: record.block_id.to_string(),
                is_final: record.is_final,
                source_validator: record.source_validator.to_hex_string(),
                source_id: record.id().map_err(failed)?,
                offer,
                path,
            });
        }
        File::open(&references).and_then(|f| f.sync_all()).map_err(failed)?;
        Ok(delivered)
    }
}

#[cfg(test)]
impl PendingFinalityStore {
    /// Drives one acknowledged record through real Delivered and node confirmation.
    pub(super) fn confirm_delivered_for_test(
        self: &Arc<Self>,
        runtime: &AuthenticatedSessionRuntime,
        id: &UInt256,
        offer: &CloseOffer,
    ) -> Result<()> {
        let reference =
            self.close_locator(id)?.ok_or_else(|| error!("no source locator"))?.reference;
        drop(self.commit_delivered(runtime, &reference, offer)?);
        self.mark_node_confirmed(id, offer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use consensus_common::finality_delivery::{
        DurableFinalitySink, FinalityTerminalCompletion, FinalizedDeliveryCompletion,
    };
    use std::sync::atomic::AtomicBool;

    pub(super) fn setup() -> (
        crate::authenticated_fixture::TestDirectory,
        Arc<AuthenticatedSessionRuntime>,
        Arc<PendingFinalityStore>,
        PendingFinalityRecord,
        CloseOffer,
    ) {
        let dir = crate::authenticated_fixture::TestDirectory::new();
        let (runtime, draft) = super::super::tests::fixture();
        assert!(runtime.recovery_binding().is_some());
        let namespace =
            PathBuf::from(runtime.runtime_directory(dir.path().to_str().unwrap()).unwrap());
        let store = PendingFinalityStore::open(&namespace).unwrap();
        *store.runtime_binding.lock().unwrap() =
            runtime.recovery_binding().map(DiskRecoveryBinding::from_binding);
        let record = PendingFinalityRecord::from_draft(&runtime, &draft).unwrap();
        store.retain(&record).unwrap();
        let receipt = UInt256::from([0x44; 32]);
        store.acknowledge(&record.id().unwrap(), receipt.clone()).unwrap();
        let mut request = record.close_request(receipt).unwrap();
        request.domain = FinalityCloseDomain::from_runtime(&runtime);
        let offer = CloseOffer { request, generation: 1 };
        (dir, runtime, store, record, offer)
    }
    #[test]
    fn source_delivered_full_ack_reopen_preserves_recovery_coordinates() {
        for compact in [false, true] {
            let (_dir, _runtime, store, record, offer) = setup();
            let id = record.id().unwrap();
            let namespace = store.directory.parent().unwrap().to_owned();
            drop(store);
            let store = PendingFinalityStore::open(&namespace).unwrap();
            assert!(store.runtime_binding.lock().unwrap().is_none());
            if compact {
                store.compact(&record, offer.request.canonical.node_receipt.clone()).unwrap();
            }
            let locator = store.close_locator(&id).unwrap().unwrap();
            assert_eq!(locator.request().unwrap(), offer.request,
                "full durable ACK must retain checked-history coordinates before canonical compaction");
            assert!(!store.delivered_path(&id).exists(), "reopening is not a completed delivery");
        }
    }

    #[test]
    fn source_delivered_full_ack_coordinates_are_not_completion_authority() {
        for legacy in [false, true] {
            let (_dir, runtime, store, record, offer) = setup();
            let id = record.id().unwrap();
            let ack = store.directory.join(format!("{}.acked", id.to_hex_string()));
            let mut disk: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&ack).unwrap()).unwrap();
            if legacy {
                disk.as_object_mut().unwrap().remove("recovery_binding");
            } else {
                let mut wrong = runtime.recovery_binding().unwrap().clone();
                wrong.governing_masterchain.root_hash = UInt256::from([99; 32]);
                disk["recovery_binding"]["governing"] =
                    serde_json::json!(wrong.governing_masterchain.to_string());
            }
            std::fs::write(&ack, serde_json::to_vec(&disk).unwrap()).unwrap();
            let namespace = store.directory.parent().unwrap().to_owned();
            drop(store);
            let store = PendingFinalityStore::open(&namespace).unwrap();
            let locator = store.close_locator(&id).unwrap().unwrap();
            if legacy {
                assert!(locator.request().unwrap().domain.recovery_binding.is_none());
            }
            assert!(store.commit_delivered(&runtime, &locator.reference, &offer).is_err());
            assert!(ack.exists());
            assert!(!store.delivered_path(&id).exists());
        }
    }

    fn concurrent_confirmed_scan(unlocked_control: bool) {
        use std::{sync::mpsc, time::Duration};
        let (_dir, runtime, store, record, offer) = setup();
        let id = record.id().unwrap();
        let namespace = store.directory.parent().unwrap().to_owned();
        let reference = store.close_locator(&id).unwrap().unwrap().reference;
        drop(store.commit_delivered(&runtime, &reference, &offer).unwrap());
        let (writer_entered_tx, writer_entered) = mpsc::channel();
        let (writer_release, writer_release_rx) = mpsc::channel();
        *store.confirmed_rename_gate.lock().unwrap() =
            Some(SourceIoGate { entered: writer_entered_tx, release: writer_release_rx });
        let (scan_entered_tx, scan_entered) = mpsc::channel();
        let (scan_release, scan_release_rx) = mpsc::channel();
        *store.scan_metadata_gate.lock().unwrap() =
            Some(SourceIoGate { entered: scan_entered_tx, release: scan_release_rx });
        let (scan_started_tx, scan_started) = mpsc::channel();
        if !unlocked_control {
            *store.scan_started.lock().unwrap() = Some(scan_started_tx);
        }
        let (scan_finished_tx, scan_finished) = mpsc::channel();
        let owner = store.clone();
        let writer_id = id.clone();
        let writer_offer = offer.clone();
        let mut writer =
            Some(std::thread::spawn(move || owner.mark_node_confirmed(&writer_id, &writer_offer)));
        let mut reader = None;
        let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            writer_entered.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(
                store.mutation.try_lock().is_err(),
                "actual confirmed writer owns mutation through sync/rename"
            );
            assert!(store.delivered_path(&id).with_extension("tmp").exists());
            let scan_store = store.clone();
            reader = Some(std::thread::spawn(move || {
                // The negative control invokes exactly the former unsynchronized
                // enumeration, not a copied algorithm or swallowed IO error.
                let result = if unlocked_control {
                    scan_store.paths_under_mutation()
                } else {
                    scan_store.paths()
                };
                let _ = scan_finished_tx.send(());
                result
            }));
            if unlocked_control {
                scan_entered.recv_timeout(Duration::from_secs(5)).unwrap();
            } else {
                scan_started.recv_timeout(Duration::from_secs(5)).unwrap();
                // The writer still owns mutation and its real temporary file.
                // Removing only the production scan lock lets the reader reach
                // this exact metadata gate, failing before writer release.
                assert_eq!(
                    scan_entered.recv_timeout(Duration::from_millis(500)),
                    Err(mpsc::RecvTimeoutError::Timeout),
                    "scan reached temporary metadata while confirmed writer held mutation"
                );
                assert_eq!(
                    scan_finished.try_recv(),
                    Err(mpsc::TryRecvError::Empty),
                    "scan completed while confirmed writer held mutation"
                );
            }
            writer_release.send(()).unwrap();
            writer.take().unwrap().join().unwrap().unwrap();
            let _ = scan_release.send(());
            let result = reader.take().unwrap().join().unwrap();
            if unlocked_control {
                let error = result.expect_err("old scan must lose its actual tmp entry to rename");
                assert_eq!(
                    error.downcast_ref::<std::io::Error>().unwrap().kind(),
                    std::io::ErrorKind::NotFound
                );
                assert!(format!("{error:#}").contains(".tmp"), "path-specific failure: {error:#}");
            } else {
                assert_eq!(result.unwrap(), vec![store.delivered_path(&id)]);
            }
            assert!(DeliveredDisk::read(&store.delivered_path(&id)).unwrap().node_confirmed);
        }));
        // Every failure releases both real filesystem owners before unwinding.
        let _ = writer_release.send(());
        let _ = scan_release.send(());
        if let Some(task) = writer.take() {
            let _ = task.join();
        }
        if let Some(task) = reader.take() {
            let _ = task.join();
        }
        run.unwrap();
        drop(store);
        let reopened = PendingFinalityStore::open(&namespace).unwrap();
        assert!(reopened.confirmed_without_backup(&id).unwrap());
        assert_eq!(
            reopened
                .delivered_reference(&id)
                .unwrap()
                .unwrap()
                .metadata_record()
                .unwrap()
                .id()
                .unwrap(),
            id
        );
    }

    #[test]
    fn source_delivered_scan_serializes_actual_confirmed_rename() {
        concurrent_confirmed_scan(false);
    }
    #[test]
    fn source_delivered_unlocked_scan_reproduces_tmp_rename_enoent() {
        concurrent_confirmed_scan(true);
    }

    #[test]
    fn source_delivered_exact_binding_sync_reopen_and_old_backup() {
        let (_dir, runtime, store, record, offer) = super::tests::setup();
        let id = record.id().unwrap();
        let ack = store.directory.join(format!("{}.acked", id.to_hex_string()));
        let backup = std::fs::read(&ack).unwrap();
        let directory = store.directory.clone();
        let reference = store.close_locator(&id).unwrap().unwrap().reference;
        for field in 0..6 {
            let mut wrong = offer.clone();
            match field {
                0 => wrong.request.canonical.role = FinalityDeliveryRole::Approval,
                1 => wrong.request.canonical.block_id.file_hash = UInt256::from([9; 32]),
                2 => wrong.request.domain.session_id = UInt256::from([9; 32]),
                3 => wrong.request.source_digest = UInt256::from([9; 32]),
                4 => wrong.request.created_at_unix_secs += 1,
                _ => wrong.request.canonical.local_adnl = UInt256::from([9; 32]),
            }
            assert!(store.commit_delivered(&runtime, &reference, &wrong).is_err());
            assert!(ack.exists());
        }
        let confirmation = store.commit_delivered(&runtime, &reference, &offer).unwrap();
        assert_eq!(confirmation.offer(), &offer);
        assert_eq!(confirmation.source_id(), &id);
        assert_eq!(close_source_id(&offer.request).unwrap(), id);
        assert!(!ack.exists());
        assert!(!store.reference_path(&id).exists());
        // Completed source history cannot be resurrected as a fresh full record.
        assert!(store.retain(&record).is_err());
        assert!(store.delivered_path(&id).exists());
        assert!(!store.directory.join(format!("{}.json", id.to_hex_string())).exists());
        drop(confirmation);
        drop(store);
        // Restore a genuine old backup beside Delivered: exact historical bytes
        // upgrade idempotently, without generating a new proof or timestamp.
        std::fs::write(&ack, &backup).unwrap();
        let store = PendingFinalityStore::lock(directory).unwrap().unwrap();
        let locator = store.close_locator(&id).unwrap().unwrap();
        let confirmation = store.commit_delivered(&runtime, &locator.reference, &offer).unwrap();
        assert_eq!(confirmation.offer().request.created_at_unix_secs, record.created_at_unix_secs);
        assert!(!ack.exists());
        let mut stale = offer.clone();
        stale.generation += 1;
        assert!(store.commit_delivered(&runtime, &locator.reference, &stale).is_err());
    }
    #[test]
    fn source_delivered_uncertain_sync_never_mints_and_requires_reopen() {
        let (_dir, runtime, store, record, offer) = super::tests::setup();
        let id = record.id().unwrap();
        let directory = store.directory.clone();
        let reference = store.close_locator(&id).unwrap().unwrap().reference;
        store.fail_delivered_once.store(true, Ordering::Release);
        assert!(store.commit_delivered(&runtime, &reference, &offer).is_err());
        assert!(store.directory.join(format!("{}.acked", id.to_hex_string())).exists());
        assert!(store.commit_delivered(&runtime, &reference, &offer).is_err());
        assert!(store.retain(&record).is_err());
        drop(store);
        let store = PendingFinalityStore::lock(directory).unwrap().unwrap();
        let confirmation = store.commit_delivered(&runtime, &reference, &offer).unwrap();
        assert_eq!(confirmation.source_id(), &id);
    }
    #[test]
    fn source_delivered_cleanup_sync_failure_keeps_recoverable_delivered() {
        let (_dir, runtime, store, record, offer) = setup();
        let id = record.id().unwrap();
        let namespace = store.directory.parent().unwrap().to_owned();
        let reference = store.close_locator(&id).unwrap().unwrap().reference;
        let ack = store.directory.join(format!("{}.acked", id.to_hex_string()));
        let ack_bytes = std::fs::read(&ack).unwrap();
        store.compact(&record, offer.request.canonical.node_receipt.clone()).unwrap();
        std::fs::write(&ack, ack_bytes).unwrap();
        File::open(&ack).unwrap().sync_all().unwrap();
        File::open(&store.directory).unwrap().sync_all().unwrap();
        assert!(store.reference_path(&id).exists());
        store.fail_delivered_cleanup_once.store(true, Ordering::Release);
        let error = store.commit_delivered(&runtime, &reference, &offer).err().unwrap();
        assert_eq!(error.to_string(), "Injected source cleanup sync boundary failure");
        assert!(!store.reference_path(&id).exists());
        assert!(!store.directory.join(format!("{}.acked", id.to_hex_string())).exists());
        let path = store.delivered_path(&id);
        let before = std::fs::read(&path).unwrap();
        assert!(!DeliveredDisk::read(&path).unwrap().node_confirmed);
        assert!(store.commit_delivered(&runtime, &reference, &offer).is_err());
        assert!(store.mark_node_confirmed(&id, &offer).is_err());
        drop(store);
        let store = PendingFinalityStore::open(&namespace).unwrap();
        let receipt = store.commit_delivered(&runtime, &reference, &offer).unwrap();
        assert_eq!(receipt.offer(), &offer);
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    #[test]
    fn source_delivered_confirmed_sync_failure_requires_cold_resync() {
        let (_dir, runtime, store, record, offer) = setup();
        let id = record.id().unwrap();
        let namespace = store.directory.parent().unwrap().to_owned();
        let reference = store.close_locator(&id).unwrap().unwrap().reference;
        drop(store.commit_delivered(&runtime, &reference, &offer).unwrap());
        store.fail_confirmed_once.store(true, Ordering::Release);
        let error = store.mark_node_confirmed(&id, &offer).unwrap_err();
        assert_eq!(error.to_string(), "Injected source confirmed sync boundary failure");
        // Rename happened; true on disk must not override this owner's poison.
        let path = store.delivered_path(&id);
        assert!(DeliveredDisk::read(&path).unwrap().node_confirmed);
        assert!(store.commit_delivered(&runtime, &reference, &offer).is_err());
        assert!(store.mark_node_confirmed(&id, &offer).is_err());
        let bytes = std::fs::read(&path).unwrap();
        drop(store);
        let store = PendingFinalityStore::open(&namespace).unwrap();
        drop(store.commit_delivered(&runtime, &reference, &offer).unwrap());
        store.mark_node_confirmed(&id, &offer).unwrap();
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }

    struct TerminalSink(CloseOffer);
    impl DurableFinalitySink for TerminalSink {
        fn stage(
            &self,
            _draft: FinalizedDeliveryDraft,
            _done: FinalizedDeliveryCompletion,
        ) -> Result<()> {
            panic!("terminal replay must never stage or re-sign")
        }
        fn lookup_terminal(
            &self,
            request: CloseFinalityRequest,
            done: FinalityTerminalCompletion,
        ) -> Result<()> {
            assert_eq!(request, self.0.request);
            done(Ok(FinalityTerminalLookup::Released(self.0.clone())));
            Ok(())
        }
    }
    #[test]
    fn source_delivered_completion_owns_store_and_recovery_needs_no_carrier() {
        let (dir, runtime, store, record, offer) = setup();
        let id = record.id().unwrap();
        store.compact(&record, offer.request.canonical.node_receipt.clone()).unwrap();
        let directory = store.directory.clone();
        drop(store);
        let mut locators = scan_finality_closures(dir.path()).unwrap();
        assert_eq!(locators.len(), 1);
        let locator = locators.pop().unwrap();
        assert!(locator.metadata().unwrap().data.is_empty());
        let held = Arc::new(Mutex::new(None::<DeliveredCompletion>));
        let held_copy = held.clone();
        let observed = Arc::new(AtomicBool::new(false));
        let observed_copy = observed.clone();
        let confirm: DeliveredCompletionSink = Arc::new(move |receipt, done| {
            assert_eq!(receipt.source_id(), &id);
            *held_copy.lock().unwrap() = Some(done);
            Ok(())
        });
        locator
            .resume(
                runtime.clone(),
                Arc::new(TerminalSink(offer.clone())),
                confirm,
                Box::new(move |r| {
                    r.unwrap();
                    observed_copy.store(true, Ordering::Release);
                }),
            )
            .unwrap();
        assert!(!observed.load(Ordering::Acquire));
        assert!(PendingFinalityStore::lock(directory.clone()).unwrap().is_none());
        held.lock().unwrap().take().unwrap()(Ok(()));
        assert!(observed.load(Ordering::Acquire));
        let reopened = PendingFinalityStore::lock(directory).unwrap().unwrap();
        let locator = reopened.close_locator(&record.id().unwrap()).unwrap().unwrap();
        assert_eq!(locator.request().unwrap(), offer.request);
        assert!(locator.metadata().unwrap().signature_set.is_empty());
    }
    #[test]
    fn source_closing_maintenance_keeps_actor_responsive_and_namespace_owned() {
        use std::{
            sync::mpsc,
            time::{Duration, Instant},
        };
        let (_dir, runtime, store, _record, offer) = setup();
        let namespace = store.directory.parent().unwrap().to_owned();
        drop(store);
        let confirm: DeliveredCompletionSink = Arc::new(|_, done| {
            done(Ok(()));
            Ok(())
        });
        let source = SourceFinalityDelivery::open_with_delivered(
            runtime,
            &namespace,
            Arc::new(TerminalSink(offer)),
            Some(confirm),
        )
        .unwrap();
        source.close_cursor.lock().unwrap().0 = Instant::now() - Duration::from_secs(2);
        source.closing_maintenance.lock().unwrap().next_attempt = Instant::now();
        let receipt = source.namespace_release_receipt();
        let store = source.store.clone();
        let (scan_started_tx, scan_started) = mpsc::channel();
        *store.scan_started.lock().unwrap() = Some(scan_started_tx);
        // Hold the actual store's IO mutex. A synchronous actor scan would
        // block here; cleanup below releases it even if the assertion fails.
        let blocked_io = store.mutation.lock().unwrap();
        let actor_source = source.clone();
        let (returned_tx, returned) = mpsc::channel();
        let actor = std::thread::spawn(move || {
            let result = actor_source.request_closing_maintenance();
            let _ = returned_tx.send(result);
        });
        let mut source = Some(source);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert!(returned
                .recv_timeout(Duration::from_secs(2))
                .expect("actor must return while source IO is blocked")
                .unwrap());
            scan_started.recv_timeout(Duration::from_secs(2)).unwrap();
            for _ in 0..1000 {
                assert!(
                    !source.as_ref().unwrap().request_closing_maintenance().unwrap(),
                    "repeated actor wakeups must not enqueue additional scans"
                );
            }
            drop(source.take());
            assert!(
                !receipt.load(Ordering::Acquire),
                "an in-flight IO worker must own the source namespace after actor retirement"
            );
            assert!(PendingFinalityStore::lock(namespace.join(DIRECTORY)).unwrap().is_none());
        }));
        drop(blocked_io);
        drop(store);
        actor.join().unwrap();
        drop(source);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !receipt.load(Ordering::Acquire) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(receipt.load(Ordering::Acquire));
        assert!(PendingFinalityStore::lock(namespace.join(DIRECTORY)).unwrap().is_some());
        if let Err(error) = outcome {
            std::panic::resume_unwind(error);
        }
    }

    #[test]
    fn source_delivered_namespace_receipt_waits_for_actual_confirmation_completion() {
        let (dir, runtime, store, _record, offer) = setup();
        drop(store);
        let namespace =
            PathBuf::from(runtime.runtime_directory(dir.path().to_str().unwrap()).unwrap());
        let held = Arc::new(Mutex::new(None::<DeliveredCompletion>));
        let sink_held = held.clone();
        let confirm: DeliveredCompletionSink = Arc::new(move |_, completion| {
            *sink_held.lock().unwrap() = Some(completion);
            Ok(())
        });
        let source = SourceFinalityDelivery::open_with_delivered(
            runtime,
            &namespace,
            Arc::new(TerminalSink(offer)),
            Some(confirm),
        )
        .unwrap();
        let receipt = source.namespace_release_receipt();
        source.close_cursor.lock().unwrap().0 =
            std::time::Instant::now() - std::time::Duration::from_secs(2);
        source.maintain_closing().unwrap();
        assert!(held.lock().unwrap().is_some());
        drop(source);
        assert!(!receipt.load(Ordering::Acquire));
        assert!(PendingFinalityStore::lock(namespace.join(DIRECTORY)).unwrap().is_none());
        held.lock().unwrap().take().unwrap()(Ok(()));
        assert!(receipt.load(Ordering::Acquire));
        assert!(PendingFinalityStore::lock(namespace.join(DIRECTORY)).unwrap().is_some());
    }
    #[test]
    fn source_delivered_unsupported_retains_reference_and_never_confirms() {
        let (_dir, runtime, store, record, offer) = super::tests::setup();
        store.compact(&record, offer.request.canonical.node_receipt.clone()).unwrap();
        let locator = store.close_locator(&record.id().unwrap()).unwrap().unwrap();
        let confirm: DeliveredCompletionSink =
            Arc::new(|_, _| panic!("unsupported cannot confirm"));
        assert!(locator
            .resume(
                runtime,
                Arc::new(super::super::tests::HeldSink::default()),
                confirm,
                Box::new(|_| panic!("admission error cannot call completion"))
            )
            .is_err());
        assert!(store.reference_path(&record.id().unwrap()).exists());
        assert!(!store.delivered_path(&record.id().unwrap()).exists());
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;
    #[test]
    fn source_closing_workchain_never_scans_mc_custody() {
        use std::{
            sync::mpsc,
            time::{Duration, Instant},
        };
        for is_final in [false, true] {
            let dir = crate::authenticated_fixture::TestDirectory::new();
            let (runtime, draft) = super::super::tests::fixture_role(
                is_final,
                rtos_block::ShardIdent::with_tagged_prefix(0, 0x8000000000000000).unwrap(),
            );
            let namespace =
                PathBuf::from(runtime.runtime_directory(dir.path().to_str().unwrap()).unwrap());
            let source = SourceFinalityDelivery::open_with_delivered(
                runtime.clone(),
                &namespace,
                Arc::new(super::super::tests::HeldSink::default()),
                Some(Arc::new(|_, _| panic!("WC cannot close MC custody"))),
            )
            .unwrap();
            let record = PendingFinalityRecord::from_draft(&runtime, &draft).unwrap();
            source.store.retain(&record).unwrap();
            source.store.acknowledge(&record.id().unwrap(), UInt256::from([4; 32])).unwrap();
            let original = std::fs::read(
                source
                    .store
                    .directory
                    .join(format!("{}.acked", record.id().unwrap().to_hex_string())),
            )
            .unwrap();
            source.close_cursor.lock().unwrap().0 = Instant::now() - Duration::from_secs(2);
            source.closing_maintenance.lock().unwrap().next_attempt = Instant::now();
            let (tx, scans) = mpsc::channel();
            *source.store.scan_started.lock().unwrap() = Some(tx);
            source.maintain_closing().unwrap();
            assert!(
                scans.try_recv().is_err(),
                "WC has no MC custody: do not scan its retained source files"
            );
            assert!(
                !source.request_closing_maintenance().unwrap(),
                "WC must not schedule an ineligible closure worker"
            );
            assert_eq!(
                std::fs::read(
                    source
                        .store
                        .directory
                        .join(format!("{}.acked", record.id().unwrap().to_hex_string()))
                )
                .unwrap(),
                original
            );
            assert!(!source.store.delivered_path(&record.id().unwrap()).exists());
        }
    }

    #[test]
    fn source_delivered_non_mc_roles_preserve_original() {
        for (is_final, shard) in [
            (false, rtos_block::ShardIdent::with_tagged_prefix(0, 0x8000000000000000).unwrap()),
            (true, rtos_block::ShardIdent::with_tagged_prefix(0, 0x8000000000000000).unwrap()),
        ] {
            let dir = crate::authenticated_fixture::TestDirectory::new();
            let (runtime, draft) = super::super::tests::fixture_role(is_final, shard);
            let namespace =
                PathBuf::from(runtime.runtime_directory(dir.path().to_str().unwrap()).unwrap());
            let store = PendingFinalityStore::open(&namespace).unwrap();
            let record = PendingFinalityRecord::from_draft(&runtime, &draft).unwrap();
            store.retain(&record).unwrap();
            let receipt = UInt256::from([4; 32]);
            store.acknowledge(&record.id().unwrap(), receipt.clone()).unwrap();
            assert!(store.close_locator(&record.id().unwrap()).unwrap().is_none());
            store.compact(&record, receipt.clone()).unwrap();
            let reference = store.reference(&record.id().unwrap()).unwrap().unwrap();
            let offer =
                CloseOffer { request: record.close_request(receipt).unwrap(), generation: 1 };
            assert!(store.commit_delivered(&runtime, &reference, &offer).is_err());
            assert!(store
                .directory
                .join(REFERENCE_DIRECTORY)
                .join(format!("{}.reference", record.id().unwrap().to_hex_string()))
                .exists());
        }
    }
    #[test]
    fn source_delivered_report_advances_past_malformed_and_confirmed_items() {
        let (_dir, runtime, store, record, offer) = super::tests::setup();
        let good = record.id().unwrap();
        let namespace = store.directory.parent().unwrap().to_owned();
        let bad =
            if good == UInt256::default() { UInt256::from([1; 32]) } else { UInt256::default() };
        let bad_path = store.reference_path(&bad);
        std::fs::create_dir_all(bad_path.parent().unwrap()).unwrap();
        std::fs::write(&bad_path, b"not-json").unwrap();
        drop(store);
        let batch = scan_finality_closures_namespace_report(&namespace, None, 2).unwrap();
        assert_eq!(batch.items.len(), 2);
        assert!(batch.items.iter().any(|(id, item)| id == &bad && item.is_err()));
        assert!(batch.items.iter().any(|(id, item)| id == &good && item.is_ok()));
        assert_eq!(std::fs::read(&bad_path).unwrap(), b"not-json");
        drop(batch);
        let batch = scan_finality_closures_namespace_report(&namespace, Some(&bad), 1).unwrap();
        assert_eq!(batch.next_cursor.as_ref(), Some(&good));
        assert_eq!(batch.items.len(), 1);
        drop(batch);
        let store = PendingFinalityStore::open(&namespace).unwrap();
        // A bare disk scanner has no runtime authority. Bind the authenticated
        // fixture exactly as the real source owner does before confirming ACK.
        *store.runtime_binding.lock().unwrap() =
            runtime.recovery_binding().map(DiskRecoveryBinding::from_binding);
        let locator = store.close_locator(&good).unwrap().unwrap();
        store.commit_delivered(&runtime, &locator.reference, &offer).unwrap();
        store.mark_node_confirmed(&good, &offer).unwrap();
        drop(locator);
        drop(store);
        let batch = scan_finality_closures_namespace_report(&namespace, Some(&bad), 1).unwrap();
        assert_eq!(batch.next_cursor.as_ref(), Some(&good));
        assert!(batch.items.is_empty(), "confirmed still consumes the visited-ID budget");
        let next = batch.next_cursor.clone();
        drop(batch);
        let batch = scan_finality_closures_namespace_report(&namespace, next.as_ref(), 1).unwrap();
        assert_eq!(batch.items.len(), 1);
        assert_eq!(batch.items[0].0, bad);
        assert!(batch.items[0].1.is_err());
    }
}

#[cfg(test)]
#[path = "finality_delivered_capacity_tests.rs"]
mod capacity_tests;

#[cfg(test)]
#[path = "finality_delivered_disk_full_tests.rs"]
mod disk_full_tests;
