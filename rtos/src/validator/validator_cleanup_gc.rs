// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! The durable GC masterchain floor that bounds validator consensus cleanup,
//! and the deletion-gate oracles bound to its pinned state. The floor follows
//! the reference GC block: it trails every frontier, advances one verified
//! successor at a time, and never regresses.
use crate::{
    engine::Engine, engine_traits::EngineOperations, shard_state::ShardStateStuff,
    shard_states_keeper::ShardStatesKeeper,
};
use consensus_common::validator_cleanup::{
    may_advance_gc, parse_canonical_namespace_name, should_adopt_safe_checkpoint, CleanupAncestry,
    GcAdvanceInputs, NamespaceLayout, ParsedNamespace, PendingValidatorCleanup,
};
use rtos_block::{error, fail, BlockIdExt, HashmapAugType, Result, ShardIdent, UInt256, UnixTime};
use std::{
    path::{Component, Path, PathBuf},
    sync::Arc,
};

/// Candidates examined by the first-run floor search.
const BOOTSTRAP_CANDIDATES: u32 = 64;

/// What the floor driver reads: the node's frontiers, masterchain links and
/// the state keeper that pins and persists the floor.
#[async_trait::async_trait]
pub(crate) trait CleanupFloorSource: Send + Sync {
    async fn last_applied_mc_state(&self) -> Result<Arc<ShardStateStuff>>;
    fn last_rotation_block_id(&self) -> Result<Option<Arc<BlockIdExt>>>;
    fn shard_client_mc_block_id(&self) -> Result<Option<Arc<BlockIdExt>>>;
    fn pss_keeper_mc_block_id(&self) -> Result<Option<Arc<BlockIdExt>>>;
    fn block_next1(&self, id: &BlockIdExt) -> Result<BlockIdExt>;
    fn keeper(&self) -> Arc<ShardStatesKeeper>;
}

#[async_trait::async_trait]
impl CleanupFloorSource for Engine {
    async fn last_applied_mc_state(&self) -> Result<Arc<ShardStateStuff>> {
        self.load_last_applied_mc_state().await
    }
    fn last_rotation_block_id(&self) -> Result<Option<Arc<BlockIdExt>>> {
        self.load_last_rotation_block_id()
    }
    fn shard_client_mc_block_id(&self) -> Result<Option<Arc<BlockIdExt>>> {
        self.load_shard_client_mc_block_id()
    }
    fn pss_keeper_mc_block_id(&self) -> Result<Option<Arc<BlockIdExt>>> {
        self.load_pss_keeper_mc_block_id()
    }
    fn block_next1(&self, id: &BlockIdExt) -> Result<BlockIdExt> {
        self.load_block_next1(id)
    }
    fn keeper(&self) -> Arc<ShardStatesKeeper> {
        self.shard_states_keeper()
    }
}

/// Whether `checkpoint` is the floor block or a verified ancestor of it on
/// the accepted chain (hash-exact through the floor state's history).
pub(crate) fn ancestor_or_equal(floor: &ShardStateStuff, checkpoint: &BlockIdExt) -> bool {
    if checkpoint == floor.block_id() {
        return true;
    }
    checkpoint.seq_no() < floor.block_id().seq_no()
        && floor.has_prev_block(checkpoint).unwrap_or(false)
}

/// The shard's catchain seqno as of the floor state. Any error, unknown
/// topology or arithmetic overflow yields nothing, which vetoes deletion.
pub(crate) fn shard_catchain_seqno(floor: &ShardStateStuff, shard: &ShardIdent) -> Option<u32> {
    let extra = floor.shard_state_extra().ok()?;
    if shard.is_masterchain() {
        return Some(extra.validator_info.catchain_seqno);
    }
    let shards = extra.shards();
    let left = shards.find_shard(&shard.left_ancestor_mask().ok()?).ok()??;
    if left.shard().is_ancestor_for(shard) {
        return Some(left.descr.next_catchain_seqno);
    }
    if !shard.is_parent_for(left.shard()) {
        return None;
    }
    let right = shards.find_shard(&shard.right_ancestor_mask().ok()?).ok()??;
    if !shard.is_parent_for(right.shard()) {
        return None;
    }
    // A merge takes max + 1; checked, so the sentinel can never be produced.
    left.descr.next_catchain_seqno.max(right.descr.next_catchain_seqno).checked_add(1)
}

async fn advance_inputs(
    source: &dyn CleanupFloorSource,
) -> Result<Option<(GcAdvanceInputs, Arc<ShardStateStuff>)>> {
    let last = source.last_applied_mc_state().await?;
    let extra = last.shard_state_extra()?;
    let seqno = |id: Option<Arc<BlockIdExt>>| id.map(|id| id.seq_no());
    let (Some(rotation), Some(shard_client), Some(pss)) = (
        seqno(source.last_rotation_block_id()?),
        seqno(source.shard_client_mc_block_id()?),
        seqno(source.pss_keeper_mc_block_id()?),
    ) else {
        // An unknown frontier never lets the floor move.
        return Ok(None);
    };
    let last_key = if extra.after_key_block {
        last.block_id().seq_no()
    } else {
        match &extra.last_key_block {
            Some(id) => id.seq_no,
            None => return Ok(None),
        }
    };
    let inputs = GcAdvanceInputs {
        last_rotation_seqno: rotation,
        min_ref_mc_seqno: last.state()?.min_ref_mc_seqno(),
        last_applied_seqno: last.block_id().seq_no(),
        last_key_block_seqno: last_key,
        shard_client_seqno: shard_client,
        pss_keeper_seqno: pss,
        now: UnixTime::now(),
        state_ttl: source.keeper().cleanup_state_ttl(),
    };
    Ok(Some((inputs, last)))
}

/// Bootstraps or advances the floor by at most one step. A floor whose state
/// went missing is left alone: cleanup stays disabled.
pub(crate) async fn maintain_cleanup_floor(source: &dyn CleanupFloorSource) -> Result<()> {
    let keeper = source.keeper();
    keeper.resolve_uncertain_cleanup_floor()?;
    let Some((inputs, last)) = advance_inputs(source).await? else {
        return Ok(());
    };
    if keeper.cleanup_floor_unset() {
        return bootstrap(&keeper, &inputs, &last);
    }
    let Some((floor_id, floor_state)) = keeper.cleanup_floor() else {
        return Ok(());
    };
    if !may_advance_gc(floor_id.seq_no(), u64::from(floor_state.state()?.gen_time()), &inputs) {
        return Ok(());
    }
    let next = source.block_next1(&floor_id)?;
    let guard = keeper.pin_cleanup_candidate(&next)?;
    let ancestry = |current: &BlockIdExt, candidate: &BlockIdExt| {
        if candidate != guard.state().block_id() {
            return CleanupAncestry::Unknown;
        }
        match guard.state().has_prev_block(current) {
            Ok(true) => CleanupAncestry::Ancestor,
            Ok(false) => CleanupAncestry::NotAncestor,
            Err(_) => CleanupAncestry::Unknown,
        }
    };
    if next.seq_no() != floor_id.seq_no().saturating_add(1)
        || !should_adopt_safe_checkpoint(Some(&floor_id), &next, &ancestry)
    {
        return Err(error!(
            "Cleanup floor successor {next} is not a verified descendant of {floor_id}"
        ));
    }
    keeper.adopt_cleanup_floor(&next, guard)
}

fn bootstrap(
    keeper: &ShardStatesKeeper,
    inputs: &GcAdvanceInputs,
    last: &ShardStateStuff,
) -> Result<()> {
    let bound = [
        inputs.last_rotation_seqno,
        inputs.min_ref_mc_seqno,
        inputs.last_applied_seqno.saturating_sub(1024),
        inputs.last_key_block_seqno,
        inputs.shard_client_seqno,
        inputs.pss_keeper_seqno,
    ]
    .into_iter()
    .min()
    .unwrap_or(0);
    let Some(expiry) = inputs.now.checked_sub(inputs.state_ttl) else {
        return Ok(());
    };
    let extra = last.shard_state_extra()?;
    let lowest = bound.saturating_sub(BOOTSTRAP_CANDIDATES);
    for seqno in (lowest..bound).rev() {
        let Some(entry) = extra.prev_blocks.get(&seqno)? else {
            continue;
        };
        let (_, candidate, _) = entry.master_block_id();
        let Ok(guard) = keeper.pin_cleanup_candidate(&candidate) else {
            continue;
        };
        if u64::from(guard.state().state()?.gen_time()) >= expiry {
            continue;
        }
        return keeper.adopt_cleanup_floor(&candidate, guard);
    }
    Ok(())
}

/// Stage-local custody veto: only the V1 layout may be deleted here. An
/// authenticated (v2) namespace waits for its source finality custody to be
/// re-verified, so it is kept; an unparsable name is kept too.
pub(crate) fn v1_only_custody_veto(record: &PendingValidatorCleanup) -> bool {
    !matches!(
        parse_canonical_namespace_name(&record.namespace, &record.session_id),
        Some(ParsedNamespace { layout: NamespaceLayout::V1, .. })
    )
}

/// The storage registration key of a V1 record's consensus database: the
/// namespace directory and the session's storage id, exactly what the
/// session's database open registers. None for any other layout or a name
/// that is not the canonical single component for the session.
pub(crate) fn namespace_storage(
    db_root: &str,
    record: &PendingValidatorCleanup,
) -> Option<(PathBuf, String)> {
    if v1_only_custody_veto(record) || !is_single_component(&record.namespace) {
        return None;
    }
    let parent = consensus_root(db_root).join(&record.namespace);
    Some((parent, record.session_id.to_hex_string()))
}

/// Custody veto for the cleanup pass: an unparsable name is kept; an
/// authenticated namespace is kept unless its record carries the identity
/// that re-authenticates it and it is a masterchain namespace (only
/// masterchain Final outputs reach Released).
pub(crate) fn authenticated_cleanup_veto(record: &PendingValidatorCleanup) -> bool {
    match parse_canonical_namespace_name(&record.namespace, &record.session_id) {
        None => true,
        Some(ParsedNamespace { layout: NamespaceLayout::V1, .. }) => false,
        Some(parsed) => record.identity.is_none() || !parsed.shard.is_masterchain(),
    }
}

/// The storage registration key of any record's namespace database: the
/// namespace directory and the session's storage id. A V1 name is one plain
/// component; an authenticated name is `v2/` plus one plain component.
pub(crate) fn namespace_storage_any(
    db_root: &str,
    record: &PendingValidatorCleanup,
) -> Option<(PathBuf, String)> {
    let parsed = parse_canonical_namespace_name(&record.namespace, &record.session_id)?;
    let mut components = Path::new(&record.namespace).components();
    let shaped = match parsed.layout {
        NamespaceLayout::V1 => {
            matches!((components.next(), components.next()), (Some(Component::Normal(_)), None))
        }
        _ => matches!(
            (components.next(), components.next(), components.next()),
            (Some(Component::Normal(v2)), Some(Component::Normal(_)), None) if v2 == "v2"
        ),
    };
    shaped.then(|| {
        (consensus_root(db_root).join(&record.namespace), record.session_id.to_hex_string())
    })
}

fn consensus_root(db_root: &str) -> PathBuf {
    Path::new(db_root).join("catchains").join("consensus")
}

fn candidates_path(db_root: &str, session_id: &UInt256) -> PathBuf {
    Path::new(db_root).join("catchains").join(format!("candidates{:x}", session_id))
}

fn is_single_component(name: &str) -> bool {
    let mut components = Path::new(name).components();
    matches!((components.next(), components.next()), (Some(Component::Normal(_)), None))
}

/// Whether `path` may be removed: absent, or a real directory whose parent is
/// canonically `root`. A symlink, a file or a foreign parent refuses.
fn removable_under(path: &Path, root: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.into()),
        Ok(metadata) if metadata.file_type().is_dir() => {
            let Some(parent) = path.parent() else { return Ok(false) };
            Ok(std::fs::canonicalize(parent)? == std::fs::canonicalize(root)?)
        }
        Ok(_) => Ok(false),
    }
}

fn remove_if_directory(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(metadata) if metadata.file_type().is_dir() => Ok(std::fs::remove_dir_all(path)?),
        Ok(_) => fail!("{} is no longer a real directory", path.display()),
    }
}

fn confirmed_absent(path: &Path) -> bool {
    matches!(std::fs::symlink_metadata(path), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
}

/// Deletes a retired V1 namespace directory. The caller already established
/// eligibility under the gate and holds the storage cleanup reservation; this
/// is only the blocking filesystem step. The path check runs before anything
/// is destroyed. The session's candidate table is shared by its namespaces
/// and is never touched here: only the session-level claim deletes it.
/// Returns true only when the namespace is confirmed absent; any refusal or
/// error leaves the record for a later cycle.
pub(crate) fn delete_v1_namespace(db_root: &str, record: &PendingValidatorCleanup) -> Result<bool> {
    let Some((namespace, _)) = namespace_storage(db_root, record) else {
        return Ok(false);
    };
    if !removable_under(&namespace, &consensus_root(db_root))? {
        return Ok(false);
    }
    remove_if_directory(&namespace)?;
    Ok(confirmed_absent(&namespace))
}

/// Session-level candidate-table deletion for a durable claim. The path check
/// runs first; `revoke_and_destroy` then revokes the session's admission and
/// destroys any open table under the pool lock (false while still shared).
/// Returns true only when the table directory is confirmed absent.
pub(crate) fn delete_candidate_table(
    db_root: &str,
    session_id: &UInt256,
    revoke_and_destroy: &dyn Fn(&UInt256) -> Result<bool>,
) -> Result<bool> {
    let catchains = Path::new(db_root).join("catchains");
    let candidates = candidates_path(db_root, session_id);
    if !removable_under(&candidates, &catchains)? {
        return Ok(false);
    }
    if !revoke_and_destroy(session_id)? {
        return Ok(false);
    }
    remove_if_directory(&candidates)?;
    Ok(confirmed_absent(&candidates))
}

/// Whether any cleanup record key of `session` other than `namespace`'s own
/// exists, across the session's V1 and authenticated prefixes. Key-only, so
/// an oversized or malformed sibling still counts.
pub(crate) fn session_has_other_records(
    db: &crate::internal_db::InternalDb,
    namespace: &str,
    session: &UInt256,
) -> Result<bool> {
    use consensus_common::validator_cleanup::{record_key, session_record_prefixes};
    let parsed = parse_canonical_namespace_name(namespace, session)
        .ok_or_else(|| error!("Cleanup namespace is not canonical"))?;
    let own = record_key(namespace);
    for prefix in session_record_prefixes(&parsed.shard, parsed.catchain_seqno, session) {
        if db.validator_state_prefix_has_key_other_than(&prefix, &own)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Durable key of the cleanup incarnation (u64 little-endian).
const CLEANUP_INCARNATION_KEY: &str = "ValidatorCleanupIncarnationV1";

/// Reads the cleanup incarnation (absent reads as 0), writes it plus one
/// synced and returns the new value. Refuses a malformed value or one that
/// no longer fits 32 bits; an uncertain write only ever skips a value.
pub(crate) fn next_cleanup_incarnation(db: &crate::internal_db::InternalDb) -> Result<u64> {
    let current = match db.load_validator_state_key_bounded(CLEANUP_INCARNATION_KEY, 8)? {
        None => 0,
        Some(bytes) => u64::from_le_bytes(
            <[u8; 8]>::try_from(bytes.as_slice())
                .map_err(|_| error!("Malformed cleanup incarnation"))?,
        ),
    };
    let next = current.checked_add(1).ok_or_else(|| error!("Cleanup incarnation exhausted"))?;
    if next > u64::from(u32::MAX) {
        fail!("Cleanup incarnation exhausted");
    }
    db.write_validator_state_batch_sync(
        &[(CLEANUP_INCARNATION_KEY.to_owned(), next.to_le_bytes().to_vec())],
        &[],
    )?;
    Ok(next)
}

/// Re-authentication of a cold namespace waits at most this long for history.
const CLEANUP_AUTH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// The physical-namespace role of an authenticated record.
fn namespace_role(
    record: &PendingValidatorCleanup,
) -> Result<crate::publication_worker::cleanup_projection::NamespaceRole> {
    use crate::publication_worker::cleanup_projection::NamespaceRole;
    match parse_canonical_namespace_name(&record.namespace, &record.session_id) {
        Some(ParsedNamespace { layout: NamespaceLayout::V2Validator, .. }) => {
            Ok(NamespaceRole::Validator)
        }
        Some(ParsedNamespace { layout: NamespaceLayout::V2Observer(adnl), .. }) => {
            Ok(NamespaceRole::Observer(adnl))
        }
        _ => fail!("Cleanup record is not an authenticated namespace"),
    }
}

/// What a cleanup attempt of an authenticated namespace holds: the storage
/// cleanup reservation of its database and its exclusive Cleanup admission.
/// The manager keeps it in an `Arc`; every task, blocking child and owner
/// request working for the attempt holds a clone until its real completion,
/// and nothing is released or resumed while any clone remains.
pub struct CleanupHeld {
    pub storage: consensus_common::StorageCleanupReservation,
    pub admission: crate::validator::finality_recovery_owner::RecoveryReservation,
}

impl CleanupHeld {
    /// Releases both; the admission is never released implicitly.
    pub(crate) fn release(self) {
        let Self { storage, admission } = self;
        admission.release();
        drop(storage);
    }
}

/// The reservation an attempt runs under, recorded in its journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptToken {
    pub generation: u64,
    pub attempt: u64,
}

impl AttemptToken {
    /// Whether `record`'s journal names this attempt (a Pending record names
    /// none and is open to any).
    pub(crate) fn owns(&self, record: &PendingValidatorCleanup) -> bool {
        record.journal.payload().is_none_or(|payload| {
            payload.generation == self.generation && payload.attempt == self.attempt
        })
    }
}

/// Outcome of one journaled attempt of an authenticated namespace. What the
/// attempt held stays with the manager in every case.
#[derive(Debug)]
pub enum V2Outcome {
    /// Refused before B0 was dispatched: nothing was journaled.
    Kept(String),
    /// B0 was dispatched or a journal exists, then the attempt stopped
    /// short: the holder keeps the namespace and resumes later.
    Retained(String),
    /// The namespace is gone and every node obligation released: erase the
    /// record, keeping the reservations until the erase is acknowledged.
    Gone,
    /// A journal write's outcome is unknown: the durable record must read
    /// back as exactly `intended` or `previous` and be confirmed by a
    /// successful synced re-write before anything else happens.
    Uncertain {
        intended: PendingValidatorCleanup,
        previous: PendingValidatorCleanup,
        reason: String,
    },
}

/// Deletes a retired authenticated namespace directory: `v2/` plus one plain
/// component, whose parent must canonically be `consensus/v2`. True only
/// when it is confirmed absent.
pub(crate) fn delete_authenticated_namespace(
    db_root: &str,
    record: &PendingValidatorCleanup,
) -> Result<bool> {
    let Some((namespace, _)) = namespace_storage_any(db_root, record) else {
        return Ok(false);
    };
    if !v1_only_custody_veto(record) {
        return Ok(false);
    }
    if !removable_under(&namespace, &consensus_root(db_root).join("v2"))? {
        return Ok(false);
    }
    remove_if_directory(&namespace)?;
    Ok(confirmed_absent(&namespace))
}

/// Where a test may stop an attempt or block one of its children.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CleanupPoint {
    AfterTakeover,
    AfterB0,
    InB1Delete,
    AfterB1,
    AfterB1Prime,
    AfterB2,
    AfterB3,
}

/// Test control of one namespace's attempt: return Retained at a point, or
/// run a closure there (in the blocking child for `InB1Delete`).
#[cfg(test)]
pub(crate) type CleanupTestHook = Arc<dyn Fn(&str, CleanupPoint) -> bool + Send + Sync>;
#[cfg(test)]
pub(crate) static CLEANUP_TEST_HOOK: std::sync::Mutex<Option<CleanupTestHook>> =
    std::sync::Mutex::new(None);

/// One injected journal-write fault: the write at `point` of `namespace`
/// reports an error, after applying it when `applied`.
#[cfg(test)]
pub(crate) static CLEANUP_WRITE_FAULT: std::sync::Mutex<Option<(String, CleanupPoint, bool)>> =
    std::sync::Mutex::new(None);

/// Takes the injected fault for this write, if one is armed (tests only).
#[cfg(test)]
pub(crate) fn take_write_fault(namespace: &str, point: CleanupPoint) -> Option<bool> {
    let mut fault = CLEANUP_WRITE_FAULT.lock().ok()?;
    match fault.as_ref() {
        Some((armed, at, applied)) if armed == namespace && *at == point => {
            let applied = *applied;
            *fault = None;
            Some(applied)
        }
        _ => None,
    }
}

/// True when a test asks the attempt to stop at `point`; production never
/// stops.
fn test_stop(_namespace: &str, _point: CleanupPoint) -> bool {
    #[cfg(test)]
    {
        let hook = CLEANUP_TEST_HOOK.lock().ok().and_then(|hook| hook.clone());
        if let Some(hook) = hook {
            return hook(_namespace, _point);
        }
    }
    false
}

/// Writes `next` synced only if the durable record still reads back as
/// exactly `previous`. Err is a refusal with nothing written; `Ok(Err)`
/// is an uncertain write.
fn write_journal(
    engine: &Engine,
    previous: &PendingValidatorCleanup,
    next: &PendingValidatorCleanup,
) -> Result<std::result::Result<(), String>> {
    use consensus_common::validator_cleanup::{encode_record, record_key};
    let encoded = encode_record(next)?;
    match engine.load_validator_cleanup_record(&next.namespace)? {
        Some(durable) if &durable == previous => {}
        _ => fail!("Durable cleanup journal changed under the attempt"),
    }
    #[cfg(test)]
    if let Some(applied) = take_write_fault(&next.namespace, CleanupPoint::AfterB1Prime) {
        if applied {
            engine
                .db()
                .write_validator_state_batch_sync(&[(record_key(&next.namespace), encoded)], &[])?;
        }
        return Ok(Err("injected journal write fault".into()));
    }
    Ok(engine
        .db()
        .write_validator_state_batch_sync(&[(record_key(&next.namespace), encoded)], &[])
        .map_err(|error| error.to_string()))
}

/// The journaled cleanup attempt of one retired authenticated namespace
/// under the reservation `token`, with its ownership `held`. Never drops
/// ownership: every error before B0 is dispatched is Kept, every later one
/// Retained.
pub(crate) async fn execute_v2_cleanup(
    engine: Arc<Engine>,
    record: PendingValidatorCleanup,
    token: AttemptToken,
    held: Arc<CleanupHeld>,
) -> V2Outcome {
    let mut journaled =
        record.journal != consensus_common::validator_cleanup::CleanupJournal::Pending;
    match run_v2_cleanup(&engine, record, token, &held, &mut journaled).await {
        Ok(outcome) => outcome,
        Err(error) if journaled => V2Outcome::Retained(error.to_string()),
        Err(error) => V2Outcome::Kept(error.to_string()),
    }
}

/// From Pending it re-authenticates, scans under the reservation and
/// reconciles, then the publication owner judges and journals B0 (Deleting)
/// in one transition. From a journal written by another attempt it first
/// takes the journal over (a synced re-stamp with `token`). It then
/// continues: B1 removes the directory, B1′ journals Deleted, B2 removes the
/// node's closes together with journaling Releasing, B3 releases each lease
/// whose binding still belongs to the runtime. A resumed journal first
/// re-authenticates; a resumed Deleting or Deleted also reopens physical
/// custody of every association and has the owner verify each close.
async fn run_v2_cleanup(
    engine: &Arc<Engine>,
    record: PendingValidatorCleanup,
    token: AttemptToken,
    held: &Arc<CleanupHeld>,
    journaled: &mut bool,
) -> Result<V2Outcome> {
    use crate::{
        publication_dependency_leases::{LeaseBinding, LeaseRelease},
        publication_worker::{
            cleanup_projection::{
                copy_inventory, ExpectedIdentity, NamespaceSelection, ProjectionBudget,
            },
            cleanup_steps::{CleanupStep, CleanupStepOutcome},
        },
    };
    use consensus_common::validator_cleanup::{CleanupJournal, JournalPayload};
    use simplex::finality_delivery::source_retirement::{
        scan_source_retirement_with, EmptyInventoryPolicy, Quiescence,
    };
    let ownership = || -> Arc<dyn std::any::Any + Send + Sync> { held.clone() };
    let role = namespace_role(&record)?;
    let namespace_name = record.namespace.clone();
    let identity_record = record.clone();
    let authenticate = || async {
        match tokio::time::timeout(
            CLEANUP_AUTH_TIMEOUT,
            crate::validator::retired_session_auth::authenticate_cleanup_identity(
                engine.as_ref(),
                &identity_record,
            ),
        )
        .await
        {
            Ok(Ok(runtime)) => Ok(runtime),
            Ok(Err(error)) => Err(format!("re-authentication: {error}")),
            Err(_) => Err("re-authentication timed out".to_string()),
        }
    };
    let stop = |point: CleanupPoint| test_stop(&namespace_name, point);
    let worker = engine.ensure_publication_worker().await?;
    let mut record = record;
    let mut runtime = None;
    if record.journal == CleanupJournal::Pending {
        let authenticated = match authenticate().await {
            Ok(runtime) => runtime,
            Err(reason) => return Ok(V2Outcome::Kept(reason)),
        };
        let namespace = consensus_root(engine.db_root_dir()?).join(&record.namespace);
        let scan_runtime = authenticated.clone();
        let child = held.clone();
        let scanned = tokio::task::spawn_blocking(move || {
            scan_source_retirement_with(
                scan_runtime,
                &namespace,
                Quiescence::Reserved(&child.storage),
                EmptyInventoryPolicy::Accept,
                &crate::validator::validator_group::RetirementBudget,
            )
        })
        .await
        .map_err(|e| error!("Cleanup scan join: {e}"))?;
        let scan = match scanned {
            Ok(scan) => scan,
            Err(refusal) => return Ok(V2Outcome::Kept(format!("source scan: {refusal}"))),
        };
        let sink = worker.sink(authenticated.clone());
        let preparation = match scan
            .reconcile(sink.as_ref(), &crate::validator::validator_group::RetirementBudget)
            .await
        {
            Ok(preparation) => preparation,
            Err(failure) => return Ok(V2Outcome::Kept(format!("reconcile: {}", failure.refusal))),
        };
        let mut budget = ProjectionBudget::default();
        let inventory = match copy_inventory(preparation.inventory(), &mut budget) {
            Ok(inventory) => inventory,
            Err(error) => return Ok(V2Outcome::Kept(format!("projection: {error}"))),
        };
        let intended = PendingValidatorCleanup {
            journal: CleanupJournal::Deleting(JournalPayload {
                attempt: token.attempt,
                generation: token.generation,
                manifest_digest: preparation.manifest_digest().clone(),
                inventory_digest: preparation.inventory_digest().clone(),
                associations: Vec::new(),
            }),
            ..record.clone()
        };
        let expected = ExpectedIdentity::of(&authenticated)?;
        // From here the owner may journal: every outcome keeps ownership.
        *journaled = true;
        let outcome = worker
            .cleanup_step(
                CleanupStep::Commit {
                    selection: NamespaceSelection { session: record.session_id.clone(), role },
                    expected,
                    inventory,
                    budget,
                    durable: record.clone(),
                    intended,
                },
                ownership(),
            )
            .await;
        // The scan's locks span the whole decision.
        drop(preparation);
        match outcome {
            Ok(CleanupStepOutcome::Committed(committed)) => record = committed,
            Ok(CleanupStepOutcome::Uncertain(intended, reason)) => {
                return Ok(V2Outcome::Uncertain { intended, previous: record, reason })
            }
            // Refused with nothing written: as if never journaled.
            Ok(CleanupStepOutcome::Vetoed(reason)) => return Ok(V2Outcome::Kept(reason)),
            Ok(other) => {
                return Ok(V2Outcome::Retained(format!("unexpected B0 outcome {other:?}")))
            }
            Err(error) => return Ok(V2Outcome::Retained(format!("B0: {error}"))),
        }
        runtime = Some(authenticated);
        if stop(CleanupPoint::AfterB0) {
            return Ok(V2Outcome::Retained("test stop after B0".into()));
        }
    } else if !token.owns(&record) {
        // A journal of an earlier attempt (before a restart): re-stamp it
        // with this attempt before acting on it.
        let Some(payload) = record.journal.payload().cloned() else {
            fail!("journal lost its payload");
        };
        let payload =
            JournalPayload { attempt: token.attempt, generation: token.generation, ..payload };
        let restamped = PendingValidatorCleanup {
            journal: match &record.journal {
                CleanupJournal::Deleting(_) => CleanupJournal::Deleting(payload),
                CleanupJournal::Deleted(_) => CleanupJournal::Deleted(payload),
                CleanupJournal::Releasing(_) => CleanupJournal::Releasing(payload),
                CleanupJournal::Pending => fail!("journal lost its payload"),
            },
            ..record.clone()
        };
        if let Err(reason) = write_journal(engine, &record, &restamped)? {
            return Ok(V2Outcome::Uncertain { intended: restamped, previous: record, reason });
        }
        record = restamped;
        if stop(CleanupPoint::AfterTakeover) {
            return Ok(V2Outcome::Retained("test stop after takeover".into()));
        }
    }
    // A resumed journal re-establishes the runtime first; a resumed
    // Deleting or Deleted also re-establishes physical custody of every
    // association and the owner verifies each close.
    let runtime = match runtime {
        Some(runtime) => runtime,
        None => {
            let runtime = match authenticate().await {
                Ok(runtime) => runtime,
                Err(reason) => return Ok(V2Outcome::Retained(reason)),
            };
            if matches!(record.journal, CleanupJournal::Deleting(_) | CleanupJournal::Deleted(_)) {
                let Some(payload) = record.journal.payload() else {
                    fail!("journal lost its payload");
                };
                let leases = engine.db().repair_leases().clone();
                for association in &payload.associations {
                    let binding = match leases.binding_for(
                        association.lease_generation,
                        &association.binding_digest,
                        &association.dependency_digest,
                    )? {
                        LeaseBinding::Matched(binding) => binding,
                        LeaseBinding::Absent => {
                            return Ok(V2Outcome::Retained(format!(
                                "lease {} custody is missing",
                                association.lease_generation
                            )))
                        }
                        LeaseBinding::Mismatch => {
                            return Ok(V2Outcome::Retained(format!(
                                "lease {} no longer matches its journal",
                                association.lease_generation
                            )))
                        }
                    };
                    if let Err(error) = crate::publication_repair::reopen_durable_mc_custody(
                        engine.clone(),
                        association.lease_generation,
                        binding,
                        association.dependency_digest.clone(),
                    )
                    .await
                    {
                        return Ok(V2Outcome::Retained(format!("custody: {error}")));
                    }
                }
                match worker
                    .cleanup_step(
                        CleanupStep::Verify {
                            expected: ExpectedIdentity::of(&runtime)?,
                            associations: payload.associations.clone(),
                        },
                        ownership(),
                    )
                    .await?
                {
                    CleanupStepOutcome::Verified => {}
                    CleanupStepOutcome::Vetoed(reason) => return Ok(V2Outcome::Retained(reason)),
                    other => {
                        return Ok(V2Outcome::Retained(format!(
                            "unexpected verify outcome {other:?}"
                        )))
                    }
                }
            }
            runtime
        }
    };
    let expected = ExpectedIdentity::of(&runtime)?;
    loop {
        let Some(payload) = record.journal.payload().cloned() else {
            fail!("journal lost its payload");
        };
        match &record.journal {
            CleanupJournal::Pending => fail!("journal regressed"),
            CleanupJournal::Deleting(_) => {
                let root = engine.db_root_dir()?.to_owned();
                let target = record.clone();
                let child = held.clone();
                let gone = tokio::task::spawn_blocking(move || {
                    let gone = if test_stop(&target.namespace, CleanupPoint::InB1Delete) {
                        Ok(false)
                    } else {
                        delete_authenticated_namespace(&root, &target)
                    };
                    drop(child);
                    gone
                })
                .await
                .map_err(|e| error!("Cleanup delete join: {e}"))?;
                if !gone? {
                    return Ok(V2Outcome::Retained("namespace not confirmed gone".into()));
                }
                if stop(CleanupPoint::AfterB1) {
                    return Ok(V2Outcome::Retained("test stop after B1".into()));
                }
                let next = PendingValidatorCleanup {
                    journal: CleanupJournal::Deleted(payload.clone()),
                    ..record.clone()
                };
                if let Err(reason) = write_journal(engine, &record, &next)? {
                    return Ok(V2Outcome::Uncertain { intended: next, previous: record, reason });
                }
                record = next;
                if stop(CleanupPoint::AfterB1Prime) {
                    return Ok(V2Outcome::Retained("test stop after B1'".into()));
                }
            }
            CleanupJournal::Deleted(_) => {
                let next = PendingValidatorCleanup {
                    journal: CleanupJournal::Releasing(payload.clone()),
                    ..record.clone()
                };
                match worker
                    .cleanup_step(
                        CleanupStep::ReleaseCloses {
                            durable: record.clone(),
                            intended: next.clone(),
                        },
                        ownership(),
                    )
                    .await?
                {
                    CleanupStepOutcome::ClosesReleased => record = next,
                    CleanupStepOutcome::Uncertain(intended, reason) => {
                        return Ok(V2Outcome::Uncertain { intended, previous: record, reason })
                    }
                    CleanupStepOutcome::Vetoed(reason) => return Ok(V2Outcome::Retained(reason)),
                    other => {
                        return Ok(V2Outcome::Retained(format!("unexpected B2 outcome {other:?}")))
                    }
                }
                if stop(CleanupPoint::AfterB2) {
                    return Ok(V2Outcome::Retained("test stop after B2".into()));
                }
            }
            CleanupJournal::Releasing(_) => {
                for association in &payload.associations {
                    // A poisoned ledger fails the step: retained, reopen required.
                    match worker
                        .cleanup_step(
                            CleanupStep::ReleaseLease {
                                expected: expected.clone(),
                                association: association.clone(),
                            },
                            ownership(),
                        )
                        .await?
                    {
                        CleanupStepOutcome::Lease(
                            LeaseRelease::Released | LeaseRelease::AbsentAlreadyReleased,
                        ) => {}
                        CleanupStepOutcome::Lease(LeaseRelease::Busy) => {
                            return Ok(V2Outcome::Retained("lease release busy".into()))
                        }
                        other => {
                            return Ok(V2Outcome::Retained(format!(
                                "lease {} release refused: {other:?}",
                                association.lease_generation
                            )))
                        }
                    }
                }
                if stop(CleanupPoint::AfterB3) {
                    return Ok(V2Outcome::Retained("test stop after B3".into()));
                }
                return Ok(V2Outcome::Gone);
            }
        }
    }
}
