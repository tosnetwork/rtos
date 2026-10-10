// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Sender-isolated, bounded unverified finality ingress. Transport admission is
//! never consensus authentication; the ordinary download/proof path supplies
//! the missing header before a certificate can authorize storage or application.
use crate::{
    engine_traits::EngineOperations,
    network::{unpack_signature_set, BlockBroadcastV2, NetworkSignatureSet},
    shard_state::ShardStateStuff,
};
use rtos_api::ton::ton_node::broadcast::BlockFinalityBroadcast;
use rtos_block::{fail, BlockIdExt, KeyId, Result, ShardIdent, ValidatorBaseInfo};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

// Boxed finality wrapper: tag + bare block ID = 84. Signature-set
// metadata (including vector count) = 56. Each bare PQ signature is
// 32-byte ID + i32 algorithm + 4-byte TL length + 2420 signature bytes.
// Longest CandidateHashData is ordinary with a boxed parent: 160 bytes.
// T0's 984260 cache share measures an empty/no-parent candidate and drops
// otherwise authentic 400-signer parented evidence. This local cache policy
// admits the actual maximum; signer count, wire and quorum rules are unchanged.
const CARRIER_BYTES: usize = 84 + 56 + 400 * (32 + 4 + 4 + 2420) + 160;
const MIN_CHARGE: usize = 4096;
const RETENTION: Duration = Duration::from_secs(60);
const SENDER_BUDGET: usize = CARRIER_BYTES * 4;
const PUBLIC_BUDGET: usize = CARRIER_BYTES * 16;
const VALIDATOR_BUDGET: usize = CARRIER_BYTES * 400;

impl NetworkSignatureSet {
    pub(crate) fn validator_info(&self) -> &ValidatorBaseInfo {
        match self {
            Self::Classical(value) => value.validator_info(),
            Self::PostQuantum(value) => value.validator_info(),
        }
    }
    pub(crate) fn is_final(&self) -> bool {
        match self {
            Self::Classical(value) => match value {
                rtos_block::BlockSignaturesVariant::Simplex(value) => value.is_final(),
                _ => true,
            },
            Self::PostQuantum(value) => value.is_final(),
        }
    }
}

#[derive(Clone)]
struct Entry {
    generation: u64,
    peer: Arc<KeyId>,
    signatures: Arc<NetworkSignatureSet>,
    charge: usize,
    reserved: bool,
    verified: bool,
    expires: Instant,
    next_attempt: Instant,
    delay: Duration,
}

/// Owned by one engine generation. Nothing here is persisted as verified proof.
#[derive(Default)]
pub(crate) struct PendingFinality {
    pub(crate) tasks: Arc<crate::types::owned_tasks::OwnedTasks>,
    entries: HashMap<BlockIdExt, VecDeque<Entry>>,
    // Recovery ownership outlives evidence replacement and expiry.
    active: HashMap<BlockIdExt, u64>,
    next_generation: u64,
    workers: usize,
    authority_state: Option<BlockIdExt>,
    authorities: VecDeque<((ShardIdent, u32), Vec<(u32, Vec<Arc<KeyId>>)>)>,
}

impl PendingFinality {
    fn expire(&mut self, now: Instant) {
        self.entries.retain(|_, entries| {
            entries.retain(|entry| entry.expires > now);
            !entries.is_empty()
        });
    }

    // Exact configured coordinates and a global eight-entry memo bound the cost
    // of attacker-controlled headerless arrivals. Claimed set hashes are values,
    // never cache keys. A trusted state change invalidates positive and negative results.
    fn reserved(
        &mut self,
        state: &ShardStateStuff,
        id: &BlockIdExt,
        info: &ValidatorBaseInfo,
        peer: &Arc<KeyId>,
    ) -> Result<bool> {
        if self.authority_state.as_ref() != Some(state.block_id()) {
            self.authorities.clear();
            self.authority_state = Some(state.block_id().clone());
        }
        let extra = state.shard_state_extra()?;
        let current = if id.shard().is_masterchain() {
            extra.validator_info.catchain_seqno
        } else {
            let Some(shard) = state.shards()?.get_shard(id.shard())? else { return Ok(false) };
            shard.descr.next_catchain_seqno
        };
        let claimed = info.catchain_seqno;
        if claimed != current && current.checked_add(1) != Some(claimed) {
            return Ok(false);
        }
        let key = (id.shard().clone(), claimed);
        let sets = if let Some(index) = self.authorities.iter().position(|(old, _)| old == &key) {
            self.authorities.remove(index).unwrap().1
        } else {
            let config = state.config_params()?;
            let mut candidates = vec![config.validator_set()?];
            if config.next_validator_set_present()? {
                candidates.push(config.next_validator_set()?);
            }
            let mut sets = Vec::new();
            for set in candidates {
                let (members, hash) = set.calc_subset(
                    &config.catchain_config()?,
                    id.shard().shard_prefix_with_tag(),
                    id.shard().workchain_id(),
                    claimed,
                )?;
                let roots =
                    members.iter().map(|member| member.adnl_addr()).collect::<Result<Vec<_>>>()?;
                sets.push((hash, roots));
            }
            sets
        };
        let result = sets
            .iter()
            .any(|(hash, roots)| *hash == info.validator_list_hash_short && roots.contains(peer));
        if self.authorities.len() == 8 {
            self.authorities.pop_front();
        }
        self.authorities.push_back((key, sets));
        Ok(result)
    }

    fn admit(
        &mut self,
        id: BlockIdExt,
        peer: Arc<KeyId>,
        signatures: NetworkSignatureSet,
        received_bytes: usize,
        reserved: bool,
        now: Instant,
    ) -> Result<u64> {
        self.expire(now);
        if received_bytes == 0 {
            fail!("Finality ingress lost the actual remote byte count");
        }
        let charge = received_bytes.max(MIN_CHARGE);
        if charge > CARRIER_BYTES {
            fail!("Finality sender/block byte budget exceeded");
        }
        let verified = matches!(&signatures, NetworkSignatureSet::Classical(_));
        let old = self.entries.get(&id);
        let cached = old.and_then(|items| {
            items.iter().filter(|item| item.verified).max_by_key(|item| item.signatures.is_final())
        });
        let replace = if verified {
            match cached {
                Some(item) if item.signatures.is_final() || !signatures.is_final() => {
                    fail!("Finality cache retains equal or stronger authenticated evidence");
                }
                _ => true,
            }
        } else {
            if cached.is_some_and(|item| item.signatures.is_final() || !signatures.is_final()) {
                fail!("Finality cache retains stronger authenticated evidence");
            }
            if old.is_some_and(|items| {
                items.iter().any(|item| {
                    item.peer == peer && item.signatures.is_final() == signatures.is_final()
                })
            }) {
                fail!("Finality sender already has this evidence role pending for this block");
            }
            false
        };
        // Replacement is atomic with budget admission. Failed upgrades must
        // neither discard previous authenticated evidence nor renew its TTL.
        let block_sender_bytes: usize = if replace {
            0
        } else {
            old.into_iter().flatten().filter(|item| item.peer == peer).map(|item| item.charge).sum()
        };
        // One approval and one final candidate can coexist while authentication
        // waits for the header. Untrusted role flags never replace evidence.
        if block_sender_bytes > 2 * CARRIER_BYTES - charge {
            fail!("Finality sender/block byte budget exceeded");
        }
        let retained = self
            .entries
            .iter()
            .filter(|(key, _)| !replace || *key != &id)
            .flat_map(|(_, items)| items);
        let sender_bytes: usize =
            retained.clone().filter(|item| item.peer == peer).map(|item| item.charge).sum();
        if sender_bytes > SENDER_BUDGET - charge {
            fail!("Finality sender global byte budget exceeded");
        }
        let capacity: usize =
            retained.filter(|item| item.reserved == reserved).map(|item| item.charge).sum();
        let budget = if reserved { VALIDATOR_BUDGET } else { PUBLIC_BUDGET };
        if capacity > budget - charge {
            fail!("Finality capacity byte budget exceeded");
        }
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or_else(|| rtos_block::error!("Finality generation exhausted"))?;
        let generation = self.next_generation;
        if replace {
            self.entries.remove(&id);
        }
        self.entries.entry(id).or_default().push_back(Entry {
            generation,
            peer,
            signatures: Arc::new(signatures),
            charge,
            reserved,
            verified,
            expires: now + RETENTION,
            next_attempt: now,
            delay: Duration::from_millis(500),
        });
        Ok(generation)
    }

    fn work(&mut self, now: Instant) -> Work {
        self.expire(now);
        let next = self
            .entries
            .iter()
            .filter(|(id, _)| !self.active.contains_key(*id))
            // A temporarily failing attempt must not hide another sender/role
            // behind the front entry. Retry deadlines provide bounded fairness.
            .flat_map(|(id, entries)| entries.iter().map(move |entry| (id, entry)))
            .min_by_key(|(_, entry)| (entry.next_attempt, entry.generation));
        let Some((id, entry)) = next else {
            return Work::Stop;
        };
        if entry.next_attempt > now {
            return Work::Sleep((entry.next_attempt - now).min(Duration::from_millis(500)));
        }
        let id = id.clone();
        let generation = entry.generation;
        let entry = self
            .entries
            .get_mut(&id)
            .unwrap()
            .iter_mut()
            .find(|entry| entry.generation == generation)
            .unwrap();
        let entry = entry.clone();
        self.active.insert(id.clone(), generation);
        Work::Run(id, entry)
    }

    fn mark_verified(&mut self, id: &BlockIdExt, generation: u64) {
        if let Some(entry) = self
            .entries
            .get_mut(id)
            .and_then(|items| items.iter_mut().find(|entry| entry.generation == generation))
        {
            entry.verified = true;
        }
    }

    fn release_work(&mut self, id: &BlockIdExt, generation: u64) {
        if self.active.get(id) == Some(&generation) {
            self.active.remove(id);
        }
    }

    fn complete(&mut self, id: &BlockIdExt, generation: u64, accepted: bool) {
        self.release_work(id, generation);
        let clear = accepted
            && self.entries.get(id).is_some_and(|items| {
                items
                    .iter()
                    .any(|entry| entry.generation == generation && entry.signatures.is_final())
            });
        if clear {
            self.entries.remove(id);
        } else {
            self.remove(id, generation);
        }
    }

    fn retry(&mut self, id: &BlockIdExt, generation: u64, now: Instant) {
        self.release_work(id, generation);
        if let Some(entry) = self
            .entries
            .get_mut(id)
            .and_then(|entries| entries.iter_mut().find(|entry| entry.generation == generation))
        {
            entry.next_attempt = (now + entry.delay).min(entry.expires);
            entry.delay = (entry.delay * 2).min(Duration::from_secs(8));
        }
    }

    fn remove(&mut self, id: &BlockIdExt, generation: u64) {
        self.release_work(id, generation);
        if let Some(items) = self.entries.get_mut(id) {
            items.retain(|item| item.generation != generation);
            if items.is_empty() {
                self.entries.remove(id);
            }
        }
    }
}

enum Work {
    Run(BlockIdExt, Entry),
    Sleep(Duration),
    Stop,
}

pub(crate) type SharedPendingFinality = Arc<parking_lot::Mutex<PendingFinality>>;

// The lease is captured before spawning, so even a runtime dropping an unpolled
// task releases its worker slot. Cancellation/panic retires only its own entry;
// a later generation for the same block and sender must remain untouched.
struct WorkerLease {
    store: SharedPendingFinality,
    active: Option<(BlockIdExt, u64)>,
    counted: bool,
}
impl WorkerLease {
    fn work(&mut self, now: Instant) -> Work {
        let mut pending = self.store.lock();
        let work = pending.work(now);
        if matches!(work, Work::Stop) {
            pending.workers -= 1;
            self.counted = false;
        }
        work
    }
}
impl Drop for WorkerLease {
    fn drop(&mut self) {
        let mut pending = self.store.lock();
        if let Some((id, generation)) = self.active.take() {
            pending.remove(&id, generation);
        }
        if self.counted {
            pending.workers -= 1;
        }
    }
}

pub(crate) async fn receive(
    engine: Arc<dyn EngineOperations>,
    store: SharedPendingFinality,
    broadcast: BlockFinalityBroadcast,
    peer: Arc<KeyId>,
    received_bytes: usize,
) -> Result<()> {
    let tasks = store.lock().tasks.clone();
    let _admission = tasks.enter()?;
    if engine.check_stop() || !engine.need_monitor(broadcast.id.shard())? {
        return Ok(());
    }
    if received_bytes == 0 || received_bytes > CARRIER_BYTES {
        fail!("Finality ingress missing or excessive actual remote byte count");
    }
    let signatures = unpack_signature_set(broadcast.signature_set)?;
    if broadcast.id.shard().is_masterchain() && !signatures.is_final() {
        fail!("Masterchain finality broadcast requires final signatures");
    }
    let state = engine.load_last_applied_mc_state().await?;
    if let NetworkSignatureSet::Classical(classical) = &signatures {
        super::shard_client::validate_brodcast_v2(classical, &state, &broadcast.id)?;
    }
    let start_worker = {
        let mut pending = store.lock();
        let reserved =
            pending.reserved(&state, &broadcast.id, signatures.validator_info(), &peer)?;
        pending.admit(
            broadcast.id.clone(),
            peer,
            signatures,
            received_bytes,
            reserved,
            Instant::now(),
        )?;
        let start = pending.workers < 8;
        if start {
            pending.workers += 1;
        }
        start
    };
    if start_worker {
        let mut lease = WorkerLease { store: store.clone(), active: None, counted: true };
        let cancellation = tasks.cancellation().clone();
        tasks.spawn("finality recovery", async move {
            loop {
                if engine.check_stop() || cancellation.is_cancelled() {
                    let mut pending = store.lock();
                    pending.entries.clear();
                    break;
                }
                let work = lease.work(Instant::now());
                match work {
                    Work::Stop => break,
                    Work::Sleep(delay) => tokio::select! {
                        _ = cancellation.cancelled() => break,
                        _ = tokio::time::sleep(delay) => {},
                    },
                    Work::Run(id, entry) => {
                        lease.active = Some((id.clone(), entry.generation));
                        let remaining = entry.expires.saturating_duration_since(Instant::now());
                        let result = tokio::select! {
                            value = tokio::time::timeout(remaining, prepare_authenticated(&engine, &id, &entry.signatures)) => value,
                            _ = async {
                                tokio::select! {
                                    _ = cancellation.cancelled() => {},
                                    _ = wait_stopped(&engine) => {},
                                }
                            } => {
                                store.lock().remove(&id, entry.generation);
                                lease.active = None;
                                continue;
                            }
                        };
                        // After authentication, store/apply is never selected
                        // against stop or TTL. Shutdown joins this entire phase.
                        let result = match result {
                            Ok(Ok(Some(broadcast))) => {
                                store.lock().mark_verified(&id, entry.generation);
                                Ok(commit_authenticated(&engine, &id, broadcast).await)
                            }
                            Ok(Ok(None)) => Ok(Ok(false)),
                            Ok(Err(error)) => Ok(Err(error)),
                            Err(elapsed) => Err(elapsed),
                        };
                        match result {
                            Ok(Ok(accepted)) => {
                                store.lock().complete(&id, entry.generation, accepted)
                            }
                            Err(_) => store.lock().remove(&id, entry.generation),
                            Ok(Err(error)) => {
                                log::debug!("Pending finality recovery for {id} failed: {error}");
                                store.lock().retry(&id, entry.generation, Instant::now());
                            }
                        }
                        lease.active = None;
                    }
                }
            }
        })?;
    }
    Ok(())
}

async fn wait_stopped(engine: &Arc<dyn EngineOperations>) {
    while !engine.check_stop() {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(test)]
async fn recover(
    engine: &Arc<dyn EngineOperations>,
    id: &BlockIdExt,
    signatures: &NetworkSignatureSet,
) -> Result<()> {
    if let Some(broadcast) = prepare_authenticated(engine, id, signatures).await? {
        commit_authenticated(engine, id, broadcast).await?;
    }
    Ok(())
}

async fn prepare_authenticated(
    engine: &Arc<dyn EngineOperations>,
    id: &BlockIdExt,
    signatures: &NetworkSignatureSet,
) -> Result<Option<BlockBroadcastV2>> {
    // This is ordinary authenticated block download, independent of whether a
    // Plumtree notification was dropped, duplicated or never subscribed to.
    let (block, proof) = engine.download_block(id, Some(1)).await?;
    block.verify_expected_id(id)?;
    if proof.id() != id {
        fail!("Finality recovery proof identifies another block");
    }
    let (header, _) = proof.virtualize_block()?;
    let state = engine.load_last_applied_mc_state().await?;
    match signatures {
        NetworkSignatureSet::PostQuantum(pq) => {
            // Failure to establish trusted context is retriable. Once context
            // agrees with the hash-bound header, a bad certificate is retired;
            // it must not keep occupying this sender's slot until expiry.
            let context = super::shard_client::resolve_pq_broadcast_context(
                engine.as_ref(),
                &state,
                id,
                &header,
            )
            .await?;
            if let Err(error) = context.verify_network(pq) {
                log::debug!("Discarding invalid pending finality for {id}: {error}");
                return Ok(None);
            }
        }
        NetworkSignatureSet::Classical(classical) => {
            super::shard_client::validate_brodcast_v2(classical, &state, id)?;
        }
    }
    Ok(Some(BlockBroadcastV2 {
        id: id.clone(),
        signatures: signatures.clone(),
        proof: proof.data().to_vec(),
        data: block.data().to_vec(),
    }))
}

async fn commit_authenticated(
    engine: &Arc<dyn EngineOperations>,
    id: &BlockIdExt,
    broadcast: BlockBroadcastV2,
) -> Result<bool> {
    // Re-authentication and all persistence/application finish without an
    // external cancellation boundary once the authenticated phase is admitted.
    super::shard_client::process_recovered_block_broadcast_v2(engine, broadcast).await?;
    let handle = engine
        .load_block_handle(id)?
        .ok_or_else(|| rtos_block::error!("Recovered finality block has no stored handle"))?;
    if !handle.has_state() || id.shard().is_masterchain() && !handle.is_applied() {
        fail!("Recovered finality block is stored but awaits its application window");
    }
    Ok(true)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod persistence_tests;
