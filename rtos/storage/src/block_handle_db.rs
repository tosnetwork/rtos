/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
#[cfg(feature = "telemetry")]
use crate::StorageTelemetry;
use crate::{db_impl_base, traits::Serializable, types::BlockMeta, StorageAlloc, TARGET};
use adnl::{
    common::{
        add_counted_object_to_map, add_unbound_object_to_map_with_update, CountedObject, Counter,
    },
    declare_counted,
};
use futures::FutureExt;
use rtos_block::{error, fail, BlockIdExt, Result, ShardIdent, UInt256};
#[cfg(feature = "telemetry")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    any::type_name,
    sync::{Arc, Weak},
};

#[cfg(test)]
#[path = "tests/test_block_handle_db.rs"]
mod tests;

pub(crate) const FLAG_DATA: u32 = 0x00000001;
pub(crate) const FLAG_PROOF: u32 = 0x00000002;
pub(crate) const FLAG_PROOF_LINK: u32 = 0x00000004;
//const FLAG_EXT_DB: u32                         = 0x00000008;
pub(crate) const FLAG_STATE: u32 = 0x00000010;
const FLAG_PERSISTENT_STATE: u32 = 0x00000020;
const FLAG_NEXT_1: u32 = 0x00000040;
const FLAG_NEXT_2: u32 = 0x00000080;
pub(crate) const FLAG_PREV_1: u32 = 0x00000100;
pub(crate) const FLAG_PREV_2: u32 = 0x00000200;
pub(crate) const FLAG_APPLIED: u32 = 0x00000400;
pub(crate) const FLAG_KEY_BLOCK: u32 = 0x00000800;
pub(crate) const FLAG_MOVED_TO_ARCHIVE: u32 = 0x00002000;
pub(crate) const FLAG_STATE_SAVED: u32 = 0x00010000;
const FLAG_HAS_FULL_ID: u32 = 0x00020000;

// not serializing flags (possible flags - 1, 2, 4, 8)
const FLAG_ARCHIVING: u32 = 0x80000000;

pub const VALIDATOR_STATE_DB_NAME: &str = "validator_state_db";

db_impl_base!(NodeStateDb, &'static str);

/// Meta information related to block
#[derive(Debug)]
pub struct BlockHandle {
    id: BlockIdExt,
    meta: BlockMeta,
    block_file_lock: tokio::sync::RwLock<()>,
    proof_file_lock: tokio::sync::RwLock<()>,
    saving_state_lock: tokio::sync::Mutex<()>,
    block_handle_cache: Arc<BlockHandleCache>,
    #[cfg(feature = "telemetry")]
    got_by_broadcast: AtomicBool,
}

/// Exclusive ownership of the transient migration bit. Only a successful
/// acquisition may clear it; repairing routing flags never releases this owner.
pub(crate) struct ArchiveMigrationGuard<'a>(&'a BlockHandle);
impl Drop for ArchiveMigrationGuard<'_> {
    fn drop(&mut self) {
        self.0.meta.reset(FLAG_ARCHIVING, false);
    }
}

impl BlockHandle {
    const SIZE: usize = BlockMeta::SIZE + ShardIdent::SIZE + 36;

    fn with_values(
        id: BlockIdExt,
        meta: BlockMeta,
        block_handle_cache: Arc<BlockHandleCache>,
    ) -> Self {
        Self {
            id,
            meta,
            block_file_lock: tokio::sync::RwLock::new(()),
            proof_file_lock: tokio::sync::RwLock::new(()),
            saving_state_lock: tokio::sync::Mutex::new(()),
            block_handle_cache,
            #[cfg(feature = "telemetry")]
            got_by_broadcast: AtomicBool::new(false),
        }
    }

    fn serialize(&self) -> [u8; Self::SIZE] {
        let mut ret = [0u8; Self::SIZE];
        ret[..BlockMeta::SIZE].copy_from_slice(&self.meta.serialize());
        // A stored state flag must imply a stored state. In memory the flag is
        // set once the state is handed to the state writer, which persists it
        // later; only the saved-state flag records that it is in the database.
        let flags = self.meta.flags();
        if flags & FLAG_STATE != 0 && flags & FLAG_STATE_SAVED == 0 {
            if let Ok(word) = u64::deserialize(&ret[..8]) {
                ret[..8].copy_from_slice(&(word & !((FLAG_STATE as u64) << 32)).serialize());
            }
        }
        let id = self.id();
        ret[BlockMeta::SIZE..BlockMeta::SIZE + ShardIdent::SIZE]
            .copy_from_slice(&id.shard().serialize());
        ret[BlockMeta::SIZE + ShardIdent::SIZE..BlockMeta::SIZE + ShardIdent::SIZE + 4]
            .copy_from_slice(&id.seq_no().serialize());
        ret[BlockMeta::SIZE + ShardIdent::SIZE + 4..].copy_from_slice(id.file_hash.as_slice());
        ret
    }

    fn deserialize(id: &BlockIdExt, data: &[u8]) -> Result<BlockMeta> {
        let (meta, parts) = Self::deserialize_id_parts(data)?;
        if let Some((shard_id, seq_no, file_hash)) = parts {
            let id2 = BlockIdExt::with_params(shard_id, seq_no, id.root_hash.clone(), file_hash);
            if id != &id2 {
                log::warn!("BlockHandle::deserialize: id mismatch: written {id2} != given {id}");
            }
        }
        Ok(meta)
    }

    fn deserialize_nonchecked(id: &mut BlockIdExt, data: &[u8]) -> Result<BlockMeta> {
        let (meta, parts) = Self::deserialize_id_parts(data)?;
        if let Some((shard_id, seq_no, file_hash)) = parts {
            id.shard_id = shard_id;
            id.seq_no = seq_no;
            id.file_hash = file_hash;
        }
        Ok(meta)
    }

    fn deserialize_full_id(root_hash: &UInt256, data: &[u8]) -> Result<Option<BlockIdExt>> {
        if let (_, Some((shard_id, seq_no, file_hash))) = Self::deserialize_id_parts(data)? {
            Ok(Some(BlockIdExt::with_params(shard_id, seq_no, root_hash.clone(), file_hash)))
        } else {
            Ok(None)
        }
    }

    fn deserialize_id_parts(
        data: &[u8],
    ) -> Result<(BlockMeta, Option<(ShardIdent, u32, UInt256)>)> {
        let meta = BlockMeta::deserialize(data)?;
        if (meta.flags() & FLAG_HAS_FULL_ID) == FLAG_HAS_FULL_ID {
            if data.len() < Self::SIZE {
                fail!("Not enough data to deserialize {}", type_name::<Self>())
            }
            let shard_id = ShardIdent::deserialize_checked(&data[BlockMeta::SIZE..])?;
            let seq_no = u32::deserialize_checked(&data[BlockMeta::SIZE + ShardIdent::SIZE..])?;
            let file_hash = UInt256::from(&data[BlockMeta::SIZE + ShardIdent::SIZE + 4..]);
            Ok((meta, Some((shard_id, seq_no, file_hash))))
        } else {
            Ok((meta, None))
        }
    }

    /*
        pub fn fetch_shard_state(&self, ss: &ShardStateUnsplit) -> Result<()> {
            self.meta.gen_utime().store(ss.gen_time(), Ordering::SeqCst);
            if ss.read_custom()?.map(|c| c.after_key_block).unwrap_or(false) {
                self.set_flags(FLAG_KEY_BLOCK);
            }
            self.meta.set_fetched();
            Ok(())
        }
    */

    /*
        fn fetch_info(&self, info: &BlockInfo) -> Result<()> {
            self.meta.gen_utime().store(info.gen_utime().0, Ordering::SeqCst);
            if info.key_block() {
                self.set_flags(FLAG_KEY_BLOCK);
            }
            self.meta.set_fetched();
            Ok(())
        }
    */

    /*
        pub fn fetch_block_info(&self, block: &Block) -> Result<()> {
            self.fetch_info(&block.read_info()?)
        }
    */

    // This flags might be set into true only. So flush only after transform false -> true.

    pub fn set_data(&self) -> bool {
        self.set_flag(FLAG_DATA)
    }

    pub fn set_proof(&self) -> bool {
        self.set_flag(FLAG_PROOF)
    }

    pub fn set_proof_link(&self) -> bool {
        self.set_flag(FLAG_PROOF_LINK)
    }

    /*
        pub fn set_processed_in_ext_db(&self) -> bool {
            self.set_flag(FLAG_EXT_DB)
        }
    */

    pub fn set_state(&self) -> bool {
        self.set_flag(FLAG_STATE)
    }

    pub fn set_state_saved(&self) -> bool {
        self.set_flag(FLAG_STATE_SAVED)
    }

    pub fn set_persistent_state(&self) -> bool {
        self.set_flag(FLAG_PERSISTENT_STATE)
    }

    pub fn set_next1(&self) -> bool {
        self.set_flag(FLAG_NEXT_1)
    }

    pub fn set_next2(&self) -> bool {
        self.set_flag(FLAG_NEXT_2)
    }

    pub fn set_prev1(&self) -> bool {
        self.set_flag(FLAG_PREV_1)
    }

    pub fn set_prev2(&self) -> bool {
        self.set_flag(FLAG_PREV_2)
    }

    pub fn set_block_applied(&self) -> bool {
        self.set_flag(FLAG_APPLIED)
    }

    pub fn id(&self) -> &BlockIdExt {
        &self.id
    }

    pub fn meta(&self) -> &BlockMeta {
        &self.meta
    }

    pub fn reset_data(&self) {
        self.meta.reset(FLAG_DATA, true)
    }

    pub fn reset_proof(&self) {
        self.meta.reset(FLAG_PROOF, true)
    }

    pub fn reset_proof_link(&self) {
        self.meta.reset(FLAG_PROOF_LINK, true)
    }

    pub fn reset_next1(&self) {
        self.meta.reset(FLAG_NEXT_1, false)
    }

    pub fn reset_next2(&self) {
        self.meta.reset(FLAG_NEXT_2, false)
    }

    pub fn has_data(&self) -> bool {
        self.is_flag_set(FLAG_DATA)
    }

    pub fn has_proof(&self) -> bool {
        self.is_flag_set(FLAG_PROOF)
    }

    pub fn has_proof_link(&self) -> bool {
        self.is_flag_set(FLAG_PROOF_LINK)
    }

    pub fn has_proof_or_link(&self, is_link: &mut bool) -> bool {
        *is_link = !self.id.shard().is_masterchain();
        if *is_link {
            self.has_proof_link()
        } else {
            self.has_proof()
        }
    }

    /*
        pub fn is_processed_in_ext_db(&self) -> bool {
            self.is_flag_set(FLAG_EXT_DB)
        }
    */

    pub fn has_state(&self) -> bool {
        self.is_flag_set(FLAG_STATE)
    }

    pub fn has_saved_state(&self) -> bool {
        self.is_flag_set(FLAG_STATE_SAVED)
    }

    pub fn reset_state(&self) {
        self.meta.reset(FLAG_STATE | FLAG_STATE_SAVED, false);
    }

    pub fn has_persistent_state(&self) -> bool {
        self.is_flag_set(FLAG_PERSISTENT_STATE)
    }

    pub fn has_next1(&self) -> bool {
        self.is_flag_set(FLAG_NEXT_1)
    }

    pub fn has_next2(&self) -> bool {
        self.is_flag_set(FLAG_NEXT_2)
    }

    pub fn has_prev1(&self) -> bool {
        self.is_flag_set(FLAG_PREV_1)
    }

    pub fn has_prev2(&self) -> bool {
        self.is_flag_set(FLAG_PREV_2)
    }

    pub fn is_applied(&self) -> bool {
        self.is_flag_set(FLAG_APPLIED)
    }

    pub fn end_lt(&self) -> u64 {
        self.meta.end_lt
    }

    pub fn gen_utime(&self) -> u32 {
        self.meta.gen_utime
    }

    /*
        pub fn set_gen_utime(&self, time: u32) -> Result<()> {
            if self.fetched() || self.state_inited() {
                if time != self.meta.gen_utime().load(Ordering::Relaxed) {
                    fail!("gen_utime was already set with another value")
                } else {
                    Ok(())
                }
            } else {
                self.meta.gen_utime().store(time, Ordering::SeqCst);
                Ok(())
            }
        }
    */

    pub fn masterchain_ref_seq_no(&self) -> u32 {
        if self.id.shard().is_masterchain() {
            self.id.seq_no()
        } else {
            self.meta.masterchain_ref_seq_no()
        }
    }

    pub fn set_masterchain_ref_seq_no(&self, masterchain_ref_seq_no: u32) -> Result<bool> {
        let prev = self.meta.set_masterchain_ref_seq_no(masterchain_ref_seq_no);
        if prev == 0 {
            Ok(true)
        } else if prev == masterchain_ref_seq_no {
            Ok(false)
        } else {
            fail!(
                "INTERNAL ERROR: set different masterchain ref seqno for block {}: {} -> {}",
                self.id,
                prev,
                masterchain_ref_seq_no
            )
        }
    }

    pub fn is_archived(&self) -> bool {
        self.is_flag_set(FLAG_MOVED_TO_ARCHIVE)
    }

    pub fn set_archived(&self) -> bool {
        self.set_flag(FLAG_MOVED_TO_ARCHIVE)
    }

    pub fn reset_archived(&self) {
        self.meta.reset(FLAG_MOVED_TO_ARCHIVE, false)
    }

    /*
        pub fn fetched(&self) -> bool {
            self.meta().fetched()
        }
    */

    pub fn is_key_block(&self) -> Result<bool> {
        //        if self.fetched() {
        Ok(self.is_flag_set(FLAG_KEY_BLOCK))
        /*
                } else {
                    fail!("Data is not inited yet")
                }
        */
    }

    pub(crate) fn try_begin_archive_migration(&self) -> Option<ArchiveMigrationGuard<'_>> {
        self.set_flag(FLAG_ARCHIVING).then(|| ArchiveMigrationGuard(self))
    }

    pub fn block_file_lock(&self) -> &tokio::sync::RwLock<()> {
        &self.block_file_lock
    }

    pub fn proof_file_lock(&self) -> &tokio::sync::RwLock<()> {
        &self.proof_file_lock
    }

    pub fn saving_state_lock(&self) -> &tokio::sync::Mutex<()> {
        &self.saving_state_lock
    }

    //    #[inline]
    //    fn flags(&self) -> u32 {
    //        self.meta.flags()
    //    }

    #[inline]
    fn is_flag_set(&self, flag: u32) -> bool {
        (self.meta.flags() & flag) == flag
    }

    #[inline]
    fn set_flag(&self, flag: u32) -> bool {
        (self.meta.set_flags(flag) & flag) != flag
    }
}

#[cfg(feature = "telemetry")]
impl BlockHandle {
    pub fn set_got_by_broadcast(&self, value: bool) {
        self.got_by_broadcast.store(value, Ordering::Relaxed);
    }

    pub fn got_by_broadcast(&self) -> bool {
        self.got_by_broadcast.load(Ordering::Relaxed)
    }
}

impl Drop for BlockHandle {
    fn drop(&mut self) {
        self.block_handle_cache
            .remove_with(self.id.root_hash(), |(_id, weak)| weak.object.strong_count() == 0);
    }
}

// Real value is
// - BlockMeta if FLAG_HAS_FULL_ID is not set
// - BlockMeta + wc (i32) + shard (u64) + seqno (u32) + file_hash (UInt256) if FLAG_HAS_FULL_ID is set
pub const BLOCK_HANDLE_DB_NAME: &str = "block_handle_db";

db_impl_base!(BlockHandleDb, BlockIdExt);

declare_counted!(
    struct HandleObject {
        object: Weak<BlockHandle>,
    }
);

type BlockHandleCache = lockfree::map::Map<UInt256, HandleObject>;

#[derive(Debug)]
pub enum StoreJob {
    SaveHandle(Arc<BlockHandle>),
    DropHandle(BlockIdExt),
    SaveFullNodeState((String, Arc<BlockIdExt>)),
    SaveValidatorState((String, Arc<BlockIdExt>)),
    DropValidatorState(String),
    DropFullNodeState(String),
}

#[async_trait::async_trait]
pub trait Callback: Sync + Send {
    async fn invoke(&self, job: StoreJob, ok: bool);
}

/// Table written by one queued or direct write.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Target {
    Handles,
    FullNodeState,
    ValidatorState,
}

/// Admission of one queued write. While any queued write is outstanding, a
/// direct write records a newer generation for its key, and the writer drops
/// every queued write of that key captured before it. Dropping the ticket
/// (commit, refusal or a lost queue) ends the admission.
struct QueueTicket(Arc<WriteSerializer>);

impl Drop for QueueTicket {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// One captured write. The value is serialized when the write is queued: that
/// call is the linearization point, so the stored bytes are exactly the state
/// at that moment, never flags set later.
struct WriteOp {
    target: Target,
    key: Vec<u8>,
    value: Option<Vec<u8>>,
    generation: u64,
    _ticket: QueueTicket,
}

impl WriteOp {
    fn bytes(&self) -> usize {
        self.key.len().saturating_add(self.value.as_ref().map_or(0, Vec::len))
    }
}

#[derive(Default)]
struct KeyGenerations {
    generations: std::collections::HashMap<(Target, Vec<u8>), u64>,
    queued: usize,
}

/// Serializes the ordered writer's commits with direct writes to the same
/// tables, so an older queued value never overwrites a newer direct write.
#[derive(Default)]
struct WriteSerializer {
    commit: std::sync::Mutex<()>,
    keys: std::sync::Mutex<KeyGenerations>,
}

impl WriteSerializer {
    fn capture(
        self: &Arc<Self>,
        target: Target,
        key: Vec<u8>,
        value: Option<Vec<u8>>,
    ) -> Result<WriteOp> {
        let mut keys = self.keys.lock().map_err(|_| error!("Handle write serializer poisoned"))?;
        keys.queued =
            keys.queued.checked_add(1).ok_or_else(|| error!("Handle write queue overflow"))?;
        let generation = keys.generations.get(&(target, key.clone())).copied().unwrap_or(0);
        drop(keys);
        Ok(WriteOp { target, key, value, generation, _ticket: QueueTicket(self.clone()) })
    }

    fn release(&self) {
        if let Ok(mut keys) = self.keys.lock() {
            keys.queued = keys.queued.saturating_sub(1);
            if keys.queued == 0 {
                keys.generations.clear();
            }
        }
    }

    /// Records direct writes of `ops` as newer than every queued write of the
    /// same keys. Caller holds `commit`.
    fn supersede(&self, ops: &[(Target, &[u8])]) -> Result<()> {
        let mut keys = self.keys.lock().map_err(|_| error!("Handle write serializer poisoned"))?;
        if keys.queued == 0 {
            return Ok(());
        }
        for (target, key) in ops {
            let generation = keys.generations.entry((*target, key.to_vec())).or_insert(0);
            *generation = generation
                .checked_add(1)
                .ok_or_else(|| error!("Handle write generation overflow"))?;
        }
        Ok(())
    }

    /// Whether a direct write superseded this queued write. Caller holds `commit`.
    fn superseded(&self, op: &WriteOp) -> Result<bool> {
        let keys = self.keys.lock().map_err(|_| error!("Handle write serializer poisoned"))?;
        let current = keys.generations.get(&(op.target, op.key.clone())).copied().unwrap_or(0);
        Ok(op.generation < current)
    }
}

/// One direct write: table, key, and the value to put (`None` deletes).
type DirectWrite<'a> = (Target, &'a [u8], Option<&'a [u8]>);

/// The three tables owned by the ordered writer.
#[derive(Clone)]
struct HandleTables {
    handles: Arc<BlockHandleDb>,
    full_node_state: Arc<NodeStateDb>,
    validator_state: Arc<NodeStateDb>,
}

impl HandleTables {
    fn physical(&self, target: Target) -> &Arc<crate::db::rocksdb::RocksDb> {
        match target {
            Target::Handles => self.handles.physical_db(),
            Target::FullNodeState => self.full_node_state.physical_db(),
            Target::ValidatorState => self.validator_state.physical_db(),
        }
    }

    fn add(
        &self,
        batch: &mut rocksdb::WriteBatch,
        target: Target,
        key: &[u8],
        value: Option<&[u8]>,
    ) -> Result<()> {
        match target {
            Target::Handles => self.handles.add_raw_to_batch(batch, key, value),
            Target::FullNodeState => self.full_node_state.add_raw_to_batch(batch, key, value),
            Target::ValidatorState => self.validator_state.add_raw_to_batch(batch, key, value),
        }
    }

    /// Commits queued jobs in order: each maximal run of jobs on one physical
    /// database is one synchronized batch. Returns how many leading jobs are
    /// durable, and the error that stopped the rest.
    fn commit_jobs(
        &self,
        serializer: &WriteSerializer,
        jobs: Vec<Vec<WriteOp>>,
    ) -> (usize, Option<rtos_block::Error>) {
        let _commit = match serializer.commit.lock() {
            Ok(guard) => guard,
            Err(_) => return (0, Some(error!("Handle write serializer poisoned"))),
        };
        crate::durability::crash_point("handles.before_commit");
        let mut committed = 0usize;
        let mut index = 0usize;
        while index < jobs.len() {
            let physical = jobs[index].first().map(|op| self.physical(op.target).clone());
            let mut end = index;
            while end < jobs.len() {
                let same = match (&physical, jobs[end].first()) {
                    (Some(db), Some(op)) => Arc::ptr_eq(db, self.physical(op.target)),
                    (_, None) => true,
                    (None, Some(_)) => false,
                };
                if !same {
                    break;
                }
                end += 1;
            }
            if let Some(db) = physical {
                let run = || -> Result<()> {
                    let mut batch = rocksdb::WriteBatch::default();
                    for op in jobs[index..end].iter().flatten() {
                        if !serializer.superseded(op)? {
                            self.add(&mut batch, op.target, &op.key, op.value.as_deref())?;
                        }
                    }
                    if !batch.is_empty() {
                        db.write_batch_synced(batch)?;
                    }
                    Ok(())
                };
                if let Err(error) = run() {
                    return (committed, Some(error));
                }
            }
            committed = end;
            index = end;
            if index < jobs.len() {
                crate::durability::crash_point("handles.between_runs");
            }
        }
        crate::durability::crash_point("handles.after_commit");
        (committed, None)
    }

    /// One batch of direct writes, serialized with the ordered writer's
    /// commits and synchronized unless `synced` is false. All writes must
    /// target one physical database.
    fn write_direct(
        &self,
        serializer: &WriteSerializer,
        writes: &[DirectWrite<'_>],
        synced: bool,
    ) -> Result<()> {
        let Some((first, _, _)) = writes.first() else { return Ok(()) };
        let physical = self.physical(*first).clone();
        if writes.iter().any(|(target, _, _)| !Arc::ptr_eq(&physical, self.physical(*target))) {
            fail!("Direct handle-storage writes must target one database");
        }
        let _commit =
            serializer.commit.lock().map_err(|_| error!("Handle write serializer poisoned"))?;
        let keys: Vec<(Target, &[u8])> =
            writes.iter().map(|(target, key, _)| (*target, *key)).collect();
        serializer.supersede(&keys)?;
        let mut batch = rocksdb::WriteBatch::default();
        for (target, key, value) in writes {
            self.add(&mut batch, *target, key, *value)?;
        }
        if synced {
            physical.write_batch_synced(batch)
        } else {
            Ok(physical.db().write(batch)?)
        }
    }
}

type DurableAck = tokio::sync::oneshot::Sender<Result<()>>;

struct QueuedWork {
    job: StoreJob,
    ops: Vec<WriteOp>,
    callback: Option<Arc<dyn Callback>>,
    custody: Option<crate::archives::io_owners::ArchiveIoTicket>,
    ack: Option<DurableAck>,
}

enum HandleCommand {
    Work(QueuedWork),
    Barrier(
        tokio::sync::oneshot::Sender<Result<()>>,
        crate::durability::SyncObservation,
        Option<crate::archives::io_owners::ArchiveIoTicket>,
    ),
}

/// Bounds of one group commit of the ordered writer.
const MAX_BATCH_COMMANDS: usize = 1024;
const MAX_BATCH_BYTES: usize = 4 << 20;

/// One page of a validator-state prefix scan: the entries read, the last key
/// read, and whether the prefix range was exhausted.
pub type ValidatorStatePage = (Vec<(String, Vec<u8>)>, String, bool);

type WriterCompletion = futures::future::Shared<
    futures::future::BoxFuture<'static, std::result::Result<(), Arc<tokio::task::JoinError>>>,
>;

#[cfg(test)]
struct WriterExitHook {
    entered: tokio::sync::oneshot::Sender<()>,
    release: tokio::sync::oneshot::Receiver<()>,
}

pub struct BlockHandleStorage {
    handle_db: Arc<BlockHandleDb>,
    handle_cache: Arc<BlockHandleCache>,
    no_cache: bool,
    full_node_state_db: Arc<NodeStateDb>,
    validator_state_db: Arc<NodeStateDb>,
    state_cache: lockfree::map::Map<String, Arc<BlockIdExt>>,
    tables: HandleTables,
    serializer: Arc<WriteSerializer>,
    storer: tokio::sync::mpsc::UnboundedSender<HandleCommand>,
    writer: Option<WriterCompletion>,
    #[cfg(test)]
    writer_exit_hook: Arc<std::sync::Mutex<Option<WriterExitHook>>>,
    #[cfg(feature = "telemetry")]
    telemetry: Arc<StorageTelemetry>,
    allocated: Arc<StorageAlloc>,
}

impl BlockHandleStorage {
    pub fn with_dbs(
        handle_db: Arc<BlockHandleDb>,
        full_node_state_db: Arc<NodeStateDb>,
        validator_state_db: Arc<NodeStateDb>,
        #[cfg(feature = "telemetry")] telemetry: Arc<StorageTelemetry>,
        allocated: Arc<StorageAlloc>,
    ) -> Self {
        let (sender, mut reader) = tokio::sync::mpsc::unbounded_channel();
        let tables = HandleTables {
            handles: handle_db.clone(),
            full_node_state: full_node_state_db.clone(),
            validator_state: validator_state_db.clone(),
        };
        let serializer = Arc::new(WriteSerializer::default());
        let mut ret = Self {
            handle_db: handle_db.clone(),
            handle_cache: Arc::new(lockfree::map::Map::new()),
            no_cache: false,
            full_node_state_db: full_node_state_db.clone(),
            validator_state_db: validator_state_db.clone(),
            state_cache: lockfree::map::Map::new(),
            tables: tables.clone(),
            serializer: serializer.clone(),
            storer: sender,
            writer: None,
            #[cfg(test)]
            writer_exit_hook: Default::default(),
            #[cfg(feature = "telemetry")]
            telemetry,
            allocated,
        };
        #[cfg(test)]
        let writer_exit_hook = ret.writer_exit_hook.clone();
        let writer = tokio::spawn(async move {
            // First commit or barrier failure. Once set, nothing is written and
            // nothing is acknowledged as durable: later work may depend on the
            // failed write.
            let mut failed: Option<String> = None;
            let mut held: Option<HandleCommand> = None;
            loop {
                let command = match held.take() {
                    Some(command) => command,
                    None => match reader.recv().await {
                        Some(command) => command,
                        None => break,
                    },
                };
                let first = match command {
                    HandleCommand::Barrier(reply, observer, _archive_custody) => {
                        let result = match &failed {
                            Some(reason) => Err(error!(
                                "Handle storage has an unacknowledged write failure: {reason}"
                            )),
                            None => {
                                let tables = tables.clone();
                                tokio::task::spawn_blocking(move || {
                                    tables.handles.sync_wal_observed(observer.as_deref())?;
                                    tables
                                        .full_node_state
                                        .sync_wal_observed(observer.as_deref())?;
                                    tables.validator_state.sync_wal_observed(observer.as_deref())
                                })
                                .await
                                .unwrap_or_else(|join| {
                                    Err(error!("Handle storage barrier task failed: {join}"))
                                })
                            }
                        };
                        if let Err(error) = &result {
                            failed.get_or_insert_with(|| error.to_string());
                        }
                        let _ = reply.send(result);
                        continue;
                    }
                    HandleCommand::Work(work) => work,
                };
                // Group commit: take what is already queued, bounded by count
                // and bytes, and stop in front of the next barrier.
                let mut bytes =
                    first.ops.iter().map(WriteOp::bytes).fold(0usize, usize::saturating_add);
                let mut batch = vec![first];
                while batch.len() < MAX_BATCH_COMMANDS && bytes < MAX_BATCH_BYTES {
                    match reader.try_recv() {
                        Ok(HandleCommand::Work(work)) => {
                            bytes = work
                                .ops
                                .iter()
                                .map(WriteOp::bytes)
                                .fold(bytes, usize::saturating_add);
                            batch.push(work);
                        }
                        Ok(barrier) => {
                            held = Some(barrier);
                            break;
                        }
                        Err(_) => break,
                    }
                }
                let ops: Vec<Vec<WriteOp>> =
                    batch.iter_mut().map(|work| std::mem::take(&mut work.ops)).collect();
                let committed = if failed.is_some() {
                    drop(ops);
                    0
                } else {
                    let tables = tables.clone();
                    let serializer = serializer.clone();
                    let (committed, error) =
                        tokio::task::spawn_blocking(move || tables.commit_jobs(&serializer, ops))
                            .await
                            .unwrap_or_else(|join| {
                                (0, Some(error!("Handle storage commit task failed: {join}")))
                            });
                    if let Some(error) = error {
                        log::error!(target: TARGET, "Handle storage commit failed: {error}");
                        failed.get_or_insert_with(|| error.to_string());
                    }
                    committed
                };
                // Acknowledge and notify in queue order, and only for writes
                // whose synchronized commit succeeded.
                for (index, work) in batch.into_iter().enumerate() {
                    let ok = index < committed;
                    let QueuedWork { job, ops: _, callback, custody, ack } = work;
                    if !ok {
                        log::error!(target: TARGET, "Handle storage write not durable: {job:?}");
                    }
                    if let Some(ack) = ack {
                        let _ = ack.send(if ok {
                            Ok(())
                        } else {
                            Err(error!(
                                "Handle storage write failed: {}",
                                failed.as_deref().unwrap_or("unknown failure")
                            ))
                        });
                    }
                    if let Some(callback) = callback {
                        callback.invoke(job, ok).await;
                    }
                    drop(custody);
                }
            }

            // Graceful close
            reader.close();
            while reader.recv().await.is_some() {}
            #[cfg(test)]
            {
                let hook = writer_exit_hook.lock().unwrap().take();
                if let Some(hook) = hook {
                    let _ = hook.entered.send(());
                    let _ = hook.release.await;
                }
            }
            // Keep all native provider captures alive through the exit boundary.
            drop((tables, handle_db, full_node_state_db, validator_state_db));
        });
        ret.writer = Some(async move { writer.await.map_err(Arc::new) }.boxed().shared());
        ret
    }

    /// Flush queued writes and wait for the writer to release its database references.
    /// Other provider owners must also be dropped before reopening the database.
    /// Cancelling this wait does not abort the writer or imply that it has exited.
    pub async fn close_and_wait(mut self) -> Result<()> {
        let flushed = self.sync_pending().await;
        let writer = self.writer.take().expect("handle writer is installed by constructor");
        drop(self);
        match (flushed, writer.await) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(flush), Ok(())) => Err(flush),
            (Ok(()), Err(join)) => Err(error!("Handle writer failed while closing: {join}")),
            (Err(flush), Err(join)) => Err(error!(
                "Handle writer flush failed: {flush:#}; Handle writer failed while closing: {join}"
            )),
        }
    }

    #[cfg(test)]
    fn writer_completion_for_test(&self) -> WriterCompletion {
        self.writer.as_ref().unwrap().clone()
    }

    #[cfg(test)]
    fn hold_writer_exit_for_test(
        &self,
    ) -> (tokio::sync::oneshot::Receiver<()>, tokio::sync::oneshot::Sender<()>) {
        let (entered, arrived) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let mut slot = self.writer_exit_hook.lock().unwrap();
        assert!(slot.is_none());
        *slot = Some(WriterExitHook { entered, release: released });
        (arrived, release)
    }

    pub fn set_no_cache(&mut self) {
        self.no_cache = true;
    }

    pub fn create_handle(
        &self,
        id: BlockIdExt,
        meta: BlockMeta,
        callback: Option<Arc<dyn Callback>>,
    ) -> Result<Option<Arc<BlockHandle>>> {
        meta.set_flags(FLAG_HAS_FULL_ID);
        self.create_handle_and_store(id, meta, callback, true)
    }

    pub fn drop_validator_state(&self, key: String) -> Result<()> {
        self.delete_state(&key)?;
        let op = self.serializer.capture(Target::ValidatorState, key.as_bytes().to_vec(), None)?;
        self.enqueue(StoreJob::DropValidatorState(key), vec![op], None, None, None)
            .map_err(|_| error!("Cannot drop validator state: storer thread dropped"))
    }

    pub fn drop_full_node_state(&self, key: String) -> Result<()> {
        self.delete_state(&key)?;
        let op = self.serializer.capture(Target::FullNodeState, key.as_bytes().to_vec(), None)?;
        self.enqueue(StoreJob::DropFullNodeState(key), vec![op], None, None, None)
            .map_err(|_| error!("Cannot drop fullnode state: storer thread dropped"))
    }

    pub fn load_handle_by_id(&self, id: &BlockIdExt) -> Result<Option<Arc<BlockHandle>>> {
        self.load_handle(id.clone(), false)
    }

    pub fn load_handle_by_root_hash(&self, rh: &UInt256) -> Result<Option<Arc<BlockHandle>>> {
        let id = BlockIdExt { root_hash: rh.clone(), ..Default::default() };
        self.load_handle(id, true)
    }

    pub fn load_full_block_id(&self, root_hash: &UInt256) -> Result<Option<BlockIdExt>> {
        log::trace!(target: TARGET, "load_full_block_id {:x}", root_hash);
        if !self.no_cache {
            let weak = self.handle_cache.get(root_hash);
            if let Some(Some(handle)) = weak.map(|weak| weak.val().object.upgrade()) {
                return Ok(Some(handle.id.clone()));
            }
        }
        if let Some(data) = self.handle_db.try_get_raw(root_hash.as_slice())? {
            Ok(BlockHandle::deserialize_full_id(root_hash, &data)?)
        } else {
            Ok(None)
        }
    }

    pub fn is_empty(&self) -> Result<bool> {
        self.handle_db.is_empty()
    }

    pub fn load_full_node_state(&self, key: &str) -> Result<Option<Arc<BlockIdExt>>> {
        self.load_state(key, &self.full_node_state_db)
    }

    pub fn load_validator_state(&self, key: &str) -> Result<Option<Arc<BlockIdExt>>> {
        self.load_state(key, &self.validator_state_db)
    }

    pub fn load_validator_state_raw(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.validator_state_db.try_get_raw(key.as_bytes())?.map(|value| value.to_vec()))
    }

    /// Ordered result-bearing barrier, including physical WALs, not queue admission.
    pub async fn sync_pending(&self) -> Result<()> {
        self.sync_pending_observed(None).await
    }
    pub async fn sync_pending_observed(
        &self,
        observer: crate::durability::SyncObservation,
    ) -> Result<()> {
        self.sync_pending_with_custody(observer, None).await
    }

    pub async fn sync_pending_observed_with_archive_custody(
        &self,
        observer: crate::durability::SyncObservation,
        custody: crate::archives::io_owners::ArchiveIoTicket,
    ) -> Result<()> {
        self.sync_pending_with_custody(observer, Some(custody)).await
    }

    async fn sync_pending_with_custody(
        &self,
        observer: crate::durability::SyncObservation,
        custody: Option<crate::archives::io_owners::ArchiveIoTicket>,
    ) -> Result<()> {
        let (send, receive) = tokio::sync::oneshot::channel();
        self.storer
            .send(HandleCommand::Barrier(send, observer, custody))
            .map_err(|_| error!("Handle writer stopped"))?;
        receive.await.map_err(|_| error!("Handle writer failed during durability barrier"))?
    }

    pub fn save_handle(
        &self,
        handle: &Arc<BlockHandle>,
        callback: Option<Arc<dyn Callback>>, // not invoked in no-cache mode
    ) -> Result<()> {
        self.save_handle_with_custody(handle, callback, None)
    }

    pub fn save_handle_with_archive_custody(
        &self,
        handle: &Arc<BlockHandle>,
        callback: Option<Arc<dyn Callback>>,
        custody: crate::archives::io_owners::ArchiveIoTicket,
    ) -> Result<()> {
        self.save_handle_with_custody(handle, callback, Some(custody))
    }

    fn save_handle_with_custody(
        &self,
        handle: &Arc<BlockHandle>,
        callback: Option<Arc<dyn Callback>>,
        custody: Option<crate::archives::io_owners::ArchiveIoTicket>,
    ) -> Result<()> {
        if self.no_cache {
            let _custody = custody;
            let value = handle.serialize();
            // Bulk offline import: the importer owns its final barrier, so
            // this stays an ordinary (unsynchronized) ordered write.
            return self.tables.write_direct(
                &self.serializer,
                &[(Target::Handles, handle.id().root_hash().as_slice(), Some(&value))],
                false,
            );
        }
        let op = self.handle_op(handle)?;
        self.enqueue(StoreJob::SaveHandle(handle.clone()), vec![op], callback, custody, None)
            .map_err(|_| error!("Cannot store handle {}: storer thread dropped", handle.id()))
    }

    fn handle_op(&self, handle: &Arc<BlockHandle>) -> Result<WriteOp> {
        self.serializer.capture(
            Target::Handles,
            handle.id().root_hash().as_slice().to_vec(),
            Some(handle.serialize().to_vec()),
        )
    }

    /// Saves the handle as it is now and returns after that write and every
    /// earlier queued write are durable.
    pub async fn save_handle_durable(&self, handle: &Arc<BlockHandle>) -> Result<()> {
        if self.no_cache {
            return self.save_handle(handle, None);
        }
        let op = self.handle_op(handle)?;
        self.enqueue_durable(StoreJob::SaveHandle(handle.clone()), vec![op]).await
    }

    fn state_job(
        &self,
        target: Target,
        key: String,
        id: &BlockIdExt,
    ) -> Result<(StoreJob, Vec<WriteOp>)> {
        let refid = self.create_state(key.clone(), id)?;
        let op = self.serializer.capture(
            target,
            key.as_bytes().to_vec(),
            Some(refid.serialize().to_vec()),
        )?;
        let job = match target {
            Target::ValidatorState => StoreJob::SaveValidatorState((key, refid)),
            _ => StoreJob::SaveFullNodeState((key, refid)),
        };
        Ok((job, vec![op]))
    }

    pub fn save_full_node_state(&self, key: String, id: &BlockIdExt) -> Result<()> {
        let (job, ops) = self.state_job(Target::FullNodeState, key, id)?;
        self.enqueue(job, ops, None, None, None)
            .map_err(|_| error!("Cannot store full node state {}: storer thread dropped", id))
    }

    /// Like `save_full_node_state`, but returns only after the write and every
    /// earlier queued write are durable.
    pub async fn save_full_node_state_durable(&self, key: String, id: &BlockIdExt) -> Result<()> {
        let (job, ops) = self.state_job(Target::FullNodeState, key, id)?;
        self.enqueue_durable(job, ops).await
    }

    /// Deletes a full-node state key and waits until the deletion is durable.
    pub async fn drop_full_node_state_durable(&self, key: String) -> Result<()> {
        self.delete_state(&key)?;
        let op = self.serializer.capture(Target::FullNodeState, key.as_bytes().to_vec(), None)?;
        self.enqueue_durable(StoreJob::DropFullNodeState(key), vec![op]).await
    }

    /// Writes a raw full-node state value with a synchronized write that is
    /// ordered against every queued write of the same key.
    pub fn save_full_node_state_raw_sync(&self, key: &str, data: &[u8]) -> Result<()> {
        self.delete_state(key)?;
        self.tables.write_direct(
            &self.serializer,
            &[(Target::FullNodeState, key.as_bytes(), Some(data))],
            true,
        )?;
        self.delete_state(key)
    }

    pub fn save_validator_state(&self, key: String, id: &BlockIdExt) -> Result<()> {
        let (job, ops) = self.state_job(Target::ValidatorState, key, id)?;
        self.enqueue(job, ops, None, None, None)
            .map_err(|_| error!("Cannot store validator state {}: storer thread dropped", id))
    }

    /// Flushes the validator-state memtable, switching to a fresh WAL.
    pub fn flush_validator_state(&self) -> Result<()> {
        self.validator_state_db.flush_family()
    }

    /// Raw validator-state values are written synchronously: they record
    /// session retirement, which the reference implementation also syncs.
    pub fn save_validator_state_raw(&self, key: &str, data: &[u8]) -> Result<()> {
        self.save_validator_state_raw_sync(key, data)
    }

    pub fn save_validator_state_raw_sync(&self, key: &str, data: &[u8]) -> Result<()> {
        self.delete_state(key)?;
        self.tables.write_direct(
            &self.serializer,
            &[(Target::ValidatorState, key.as_bytes(), Some(data))],
            true,
        )?;
        self.delete_state(key)
    }

    pub fn load_validator_state_raw_bounded(
        &self,
        key: &str,
        maximum: usize,
    ) -> Result<Option<Vec<u8>>> {
        match self.validator_state_db.try_get_raw(key.as_bytes())? {
            Some(value) => {
                if value.len() > maximum {
                    fail!("Validator metadata {key} exceeds its {maximum} byte limit");
                }
                Ok(Some(value.to_vec()))
            }
            None => Ok(None),
        }
    }

    /// Atomically puts and deletes several validator-state keys in one synced
    /// batch. Keys may be dynamic; none may alias a cached block-id state.
    pub fn write_validator_state_batch_sync(
        &self,
        puts: &[(String, Vec<u8>)],
        deletes: &[String],
    ) -> Result<()> {
        for key in puts.iter().map(|(key, _)| key).chain(deletes) {
            self.delete_state(key)?;
        }
        let mut writes: Vec<DirectWrite<'_>> = Vec::new();
        for (key, value) in puts.iter() {
            writes.push((Target::ValidatorState, key.as_bytes(), Some(value.as_slice())));
        }
        for key in deletes {
            writes.push((Target::ValidatorState, key.as_bytes(), None));
        }
        if writes.is_empty() {
            return Ok(());
        }
        self.tables.write_direct(&self.serializer, &writes, true)?;
        // A queued write admitted meanwhile may have refreshed the cache.
        for key in puts.iter().map(|(key, _)| key).chain(deletes) {
            self.delete_state(key)?;
        }
        Ok(())
    }

    /// Reads at most `max_keys` validator-state entries whose key starts with
    /// `prefix`, strictly after `after` (or from the prefix when empty), each
    /// value at most `max_value_bytes`. Returns the entries, the last key
    /// read, and whether the prefix range was exhausted.
    pub fn scan_validator_state_prefix(
        &self,
        prefix: &str,
        after: &str,
        max_keys: usize,
        max_value_bytes: usize,
    ) -> Result<ValidatorStatePage> {
        let start = if after.is_empty() { prefix } else { after };
        let mut entries = Vec::new();
        let mut examined = 0usize;
        let mut last_key = String::new();
        let mut reached_end = true;
        let mut failure = None;
        self.validator_state_db.for_each_from(start.as_bytes(), &mut |key, value| {
            if !key.starts_with(prefix.as_bytes()) {
                return Ok(false);
            }
            if key == after.as_bytes() {
                return Ok(true);
            }
            if examined == max_keys {
                reached_end = false;
                return Ok(false);
            }
            let Ok(key) = std::str::from_utf8(key) else {
                failure = Some(error!("Validator-state key under {prefix} is not UTF-8"));
                return Ok(false);
            };
            examined = examined.saturating_add(1);
            last_key = key.to_owned();
            // An oversized value is counted and passed, never copied, so one
            // malformed entry cannot hold the cursor in place.
            if value.len() <= max_value_bytes {
                entries.push((last_key.clone(), value.to_vec()));
            }
            Ok(true)
        })?;
        if let Some(error) = failure {
            return Err(error);
        }
        Ok((entries, last_key, reached_end))
    }

    /// Whether any validator-state key under `prefix` other than `except`
    /// exists. Key-only: a value's size or validity never hides a key, and a
    /// non-UTF-8 key counts as present.
    pub fn validator_state_prefix_has_key_other_than(
        &self,
        prefix: &str,
        except: &str,
    ) -> Result<bool> {
        let mut found = false;
        self.validator_state_db.for_each_from(prefix.as_bytes(), &mut |key, _| {
            if !key.starts_with(prefix.as_bytes()) {
                return Ok(false);
            }
            if key == except.as_bytes() {
                return Ok(true);
            }
            found = true;
            Ok(false)
        })?;
        Ok(found)
    }

    /// Deletes one raw validator-state key with a synchronized write.
    pub fn drop_validator_state_raw(&self, key: &str) -> Result<()> {
        self.delete_state(key)?;
        self.tables.write_direct(
            &self.serializer,
            &[(Target::ValidatorState, key.as_bytes(), None)],
            true,
        )?;
        self.delete_state(key)
    }

    pub fn drop_handle(&self, id: BlockIdExt, callback: Option<Arc<dyn Callback>>) -> Result<()> {
        let _ = self.handle_cache.remove(id.root_hash());
        let op =
            self.serializer.capture(Target::Handles, id.root_hash().as_slice().to_vec(), None)?;
        self.enqueue(StoreJob::DropHandle(id.clone()), vec![op], callback, None, None)
            .map_err(|_| error!("Cannot drop handle {}: storer thread dropped", id))
    }

    fn enqueue(
        &self,
        job: StoreJob,
        ops: Vec<WriteOp>,
        callback: Option<Arc<dyn Callback>>,
        custody: Option<crate::archives::io_owners::ArchiveIoTicket>,
        ack: Option<DurableAck>,
    ) -> Result<()> {
        self.storer
            .send(HandleCommand::Work(QueuedWork { job, ops, callback, custody, ack }))
            .map_err(|_| error!("Handle storer stopped"))
    }

    /// Queues `job` and waits until its synchronized commit succeeded.
    async fn enqueue_durable(&self, job: StoreJob, ops: Vec<WriteOp>) -> Result<()> {
        let (send, receive) = tokio::sync::oneshot::channel();
        self.enqueue(job, ops, None, None, Some(send))?;
        receive
            .await
            .map_err(|_| error!("Handle writer stopped before a durable acknowledgement"))?
    }

    pub fn for_each_keys(
        &self,
        predicate: &mut dyn FnMut(BlockIdExt) -> Result<bool>,
    ) -> Result<bool> {
        self.handle_db.for_each(&mut |key_bytes, _value_bytes| {
            let id = BlockIdExt::with_params(
                ShardIdent::default(),
                0,
                UInt256::from(key_bytes),
                UInt256::default(),
            );
            predicate(id)
        })
    }

    fn create_handle_and_store(
        &self,
        id: BlockIdExt,
        meta: BlockMeta,
        callback: Option<Arc<dyn Callback>>,
        store: bool,
    ) -> Result<Option<Arc<BlockHandle>>> {
        let rh = id.root_hash().clone();
        let ret = Arc::new(BlockHandle::with_values(id, meta, self.handle_cache.clone()));
        let ret = if self.no_cache {
            if self.handle_db.try_get_raw(rh.as_slice())?.is_some() {
                None
            } else {
                if store {
                    self.save_handle(&ret, callback)?
                }
                Some(ret)
            }
        } else {
            let added = add_counted_object_to_map(&self.handle_cache, rh, || {
                let ret = HandleObject {
                    object: Arc::downgrade(&ret),
                    counter: self.allocated.handles.clone().into(),
                };
                #[cfg(feature = "telemetry")]
                self.telemetry.handles.update(self.allocated.handles.load(Ordering::Relaxed));
                Ok(ret)
            })?;
            if added {
                if store {
                    self.save_handle(&ret, callback)?
                }
                Some(ret)
            } else {
                None
            }
        };
        Ok(ret)
    }

    fn create_state(&self, key: String, id: &BlockIdExt) -> Result<Arc<BlockIdExt>> {
        let id = Arc::new(id.clone());
        if !add_unbound_object_to_map_with_update(&self.state_cache, key.clone(), |_| {
            Ok(Some(id.clone()))
        })? {
            fail!("INTERNAL ERROR: cannot create {key} state")
        }
        Ok(id)
    }

    fn delete_state(&self, key: &str) -> Result<()> {
        self.state_cache.remove(key);
        Ok(())
    }

    fn load_handle(&self, mut id: BlockIdExt, rh_only: bool) -> Result<Option<Arc<BlockHandle>>> {
        if rh_only {
            log::trace!(target: TARGET, "load block handle by root hash {:x}", id.root_hash())
        } else {
            log::trace!(target: TARGET, "load block handle by id {id}")
        }
        let ret = if self.no_cache {
            if let Some(data) = self.handle_db.try_get_raw(id.root_hash().as_slice())? {
                let meta = if rh_only {
                    BlockHandle::deserialize_nonchecked(&mut id, &data)?
                } else {
                    let meta = BlockHandle::deserialize(&id, &data)?;
                    meta.set_flags(FLAG_HAS_FULL_ID);
                    meta
                };
                Some(Arc::new(BlockHandle::with_values(id, meta, self.handle_cache.clone())))
            } else {
                None
            }
        } else {
            loop {
                let weak = self.handle_cache.get(id.root_hash());
                if let Some(Some(handle)) = weak.map(|weak| weak.val().object.upgrade()) {
                    break Some(handle);
                }
                if let Some(data) = self.handle_db.try_get_raw(id.root_hash().as_slice())? {
                    let meta = if rh_only {
                        BlockHandle::deserialize_nonchecked(&mut id, &data)?
                    } else {
                        let meta = BlockHandle::deserialize(&id, &data)?;
                        meta.set_flags(FLAG_HAS_FULL_ID);
                        meta
                    };
                    let handle = self.create_handle_and_store(id.clone(), meta, None, false)?;
                    if let Some(handle) = handle {
                        break Some(handle);
                    }
                } else {
                    break None;
                }
            }
        };
        Ok(ret)
    }

    fn load_state(&self, key: &str, db: &Arc<NodeStateDb>) -> Result<Option<Arc<BlockIdExt>>> {
        log::trace!(target: TARGET, "load state {}", key);
        if let Some(id) = self.state_cache.get(key) {
            Ok(Some(id.val().clone()))
        } else if let Some(db_slice) = db.try_get_raw(key.as_bytes())? {
            let id = BlockIdExt::deserialize(db_slice.as_ref())?;
            Ok(Some(self.create_state(key.to_string(), &id)?))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
impl BlockHandleStorage {}

#[cfg(test)]
#[path = "tests/test_archive_queue_custody.rs"]
mod archive_queue_custody_tests;
