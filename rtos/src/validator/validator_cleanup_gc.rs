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
    CleanupVerdict, GcAdvanceInputs, NamespaceLayout, ParsedNamespace, PendingValidatorCleanup,
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

/// The dry cleanup attempt of one retired authenticated namespace. The
/// caller holds its storage cleanup reservation (moved in, dropped at the
/// end) and its Cleanup admission. Re-authenticates the namespace from the
/// identity its record carries, scans it under the reservation (accepting a
/// complete empty namespace as a locked zero-item scan), reconciles every
/// item with the node, and asks the publication owner to judge the node-side
/// projection. Changes nothing durable; a refusal is a veto, not an error.
pub(crate) async fn prepare_v2_cleanup(
    engine: Arc<Engine>,
    record: PendingValidatorCleanup,
    storage: consensus_common::StorageCleanupReservation,
) -> Result<CleanupVerdict> {
    use crate::publication_worker::cleanup_projection::{
        copy_inventory, CleanupDecision, ExpectedIdentity, NamespaceSelection, ProjectionBudget,
    };
    use simplex::finality_delivery::source_retirement::{
        scan_source_retirement_with, EmptyInventoryPolicy, Quiescence,
    };
    let role = namespace_role(&record)?;
    let runtime = match tokio::time::timeout(
        CLEANUP_AUTH_TIMEOUT,
        crate::validator::retired_session_auth::authenticate_cleanup_identity(
            engine.as_ref(),
            &record,
        ),
    )
    .await
    {
        Ok(Ok(runtime)) => runtime,
        Ok(Err(error)) => return Ok(CleanupVerdict::Veto(format!("re-authentication: {error}"))),
        Err(_) => return Ok(CleanupVerdict::Veto("re-authentication timed out".into())),
    };
    let namespace = consensus_root(engine.db_root_dir()?).join(&record.namespace);
    let scan_runtime = runtime.clone();
    let (scanned, storage) = tokio::task::spawn_blocking(move || {
        let scanned = scan_source_retirement_with(
            scan_runtime,
            &namespace,
            Quiescence::Reserved(&storage),
            EmptyInventoryPolicy::Accept,
            &crate::validator::validator_group::RetirementBudget,
        );
        (scanned, storage)
    })
    .await
    .map_err(|e| error!("Cleanup scan join: {e}"))?;
    let scan = match scanned {
        Ok(scan) => scan,
        Err(refusal) => return Ok(CleanupVerdict::Veto(format!("source scan: {refusal}"))),
    };
    let worker = engine.ensure_publication_worker().await?;
    let sink = worker.sink(runtime.clone());
    let preparation = match scan
        .reconcile(sink.as_ref(), &crate::validator::validator_group::RetirementBudget)
        .await
    {
        Ok(preparation) => preparation,
        Err(failure) => return Ok(CleanupVerdict::Veto(format!("reconcile: {}", failure.refusal))),
    };
    // The inventory copy is charged before it is made; the remaining budget
    // travels with the request.
    let mut budget = ProjectionBudget::default();
    let inventory = match copy_inventory(preparation.inventory(), &mut budget) {
        Ok(inventory) => inventory,
        Err(error) => return Ok(CleanupVerdict::Veto(format!("projection: {error}"))),
    };
    let decision = worker
        .project_cleanup(
            NamespaceSelection { session: record.session_id.clone(), role },
            ExpectedIdentity::of(&runtime)?,
            inventory,
            budget,
        )
        .await?;
    // The scan's locks and the reservation span the whole decision.
    drop(preparation);
    drop(storage);
    Ok(match decision {
        CleanupDecision::WouldDelete { closes } => CleanupVerdict::WouldDelete { closes },
        CleanupDecision::Veto(reason) => CleanupVerdict::Veto(reason),
    })
}
