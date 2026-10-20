// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Full-node protocol behaviour against outputs of a driver built on the
//! fixed C++ baseline (data/fullnode-proto/out-*.txt). Each line there is
//! "<section> <key> <value>"; no expected value in this file is hand-written.
use super::*;
use rtos_api::WireProfile;

pub(super) fn cpp_lines(file: &'static str) -> impl Iterator<Item = (&'static str, &'static str)> {
    file.lines().filter_map(|line| {
        let mut parts = line.splitn(3, ' ');
        let _section = parts.next()?;
        let key = parts.next()?;
        Some((key, parts.next().unwrap_or("")))
    })
}

pub(super) fn cpp_value(file: &'static str, key: &str) -> &'static str {
    cpp_lines(file)
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
        .unwrap_or_else(|| panic!("C++ driver output has no {key}"))
}

pub(super) const CPP_TL: &str = include_str!("data/fullnode-proto/out-tl.txt");

/// Bytes of a query whose constructor `id` is followed by two block ids and,
/// for the slice query, an offset and a size: the layout the legacy
/// persistent-state queries had.
fn legacy_query(id: u32, slice: bool) -> Vec<u8> {
    let mut bytes = id.to_le_bytes().to_vec();
    for _ in 0..2 {
        bytes.extend_from_slice(&(-1i32).to_le_bytes());
        bytes.extend_from_slice(&(0x8000_0000_0000_0000u64 as i64).to_le_bytes());
        bytes.extend_from_slice(&7i32.to_le_bytes());
        bytes.extend_from_slice(&[0x11; 64]);
    }
    if slice {
        bytes.extend_from_slice(&0i64.to_le_bytes());
        bytes.extend_from_slice(&(1i64 << 21).to_le_bytes());
    }
    bytes
}

#[test]
fn legacy_persistent_state_queries_are_not_in_any_profile() {
    for (id, slice) in [(0x7f99e3b8u32, false), (0xf5e9e6e3, true), (0x4667fc2d, false)] {
        assert_eq!(cpp_value(CPP_TL, &format!("legacyParse.{id:08x}")), "error");
        let bytes = legacy_query(id, slice);
        for profile in [WireProfile::T0, WireProfile::Legacy] {
            assert!(
                profile.deserialize(&bytes).is_err(),
                "constructor {id:08x} must not decode under {profile:?}"
            );
        }
    }
}

// ------------------------------------------------------------ A3-07 sender

pub(super) const CPP_NBF: &str = include_str!("data/fullnode-proto/out-nbf.txt");
pub(super) const CPP_BFS: &str = include_str!("data/fullnode-proto/out-bfs.txt");
pub(super) const CPP_SHD: &str = include_str!("data/fullnode-proto/out-shd.txt");
pub(super) const CPP_NEI: &str = include_str!("data/fullnode-proto/out-nei.txt");

pub(super) fn hex_bytes(text: &str) -> Vec<u8> {
    hex::decode(text).expect("hex from the C++ driver")
}

pub(super) fn sha_hex(data: &[u8]) -> String {
    hex::encode(rtos_block::sha256_digest(data))
}

/// The driver's deterministic cell tree (see make_tree in the C++ driver).
pub(super) fn make_tree(seed: u64, cells: u32) -> rtos_block::Cell {
    let mut built: Vec<Option<rtos_block::Cell>> = vec![None; cells as usize];
    for i in (0..cells as u64).rev() {
        let mut data = [0u8; 127];
        let tag = (seed << 32) | i;
        data[..8].copy_from_slice(&tag.to_be_bytes());
        let mut x = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(i + 1);
        for byte in data.iter_mut().skip(8) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *byte = (x >> 24) as u8;
        }
        let mut builder = rtos_block::BuilderData::with_raw(data.to_vec(), 127 * 8).unwrap();
        for child in (4 * i + 1)..=(4 * i + 4) {
            if child < cells as u64 {
                builder.checked_append_reference(built[child as usize].clone().unwrap()).unwrap();
            }
        }
        built[i as usize] = Some(builder.into_cell().unwrap());
    }
    built[0].clone().unwrap()
}

/// The proof link the driver's manager serves: 0x4c494e4b and a reference to
/// the proof root.
fn link_root(proof: &rtos_block::Cell) -> rtos_block::Cell {
    let mut builder = rtos_block::BuilderData::with_raw(vec![0x4c, 0x49, 0x4e, 0x4b], 32).unwrap();
    builder.checked_append_reference(proof.clone()).unwrap();
    builder.into_cell().unwrap()
}

pub(super) fn cpp_block_id(text: &str) -> BlockIdExt {
    let id = text.split(' ').next().unwrap();
    let parts: Vec<_> = id.split(':').collect();
    let workchain: i32 = parts[0].parse().unwrap();
    let shard =
        if workchain == -1 { ShardIdent::masterchain() } else { ShardIdent::full(workchain) };
    BlockIdExt::with_params(
        shard,
        parts[1].parse().unwrap(),
        rtos_block::UInt256::from_slice(&hex_bytes(parts[2])),
        rtos_block::UInt256::from_slice(&hex_bytes(parts[3])),
    )
}

#[derive(Clone, Default)]
pub(super) struct StoredBlock {
    pub data: Vec<u8>,
    pub proof: Vec<u8>,
    pub link: Vec<u8>,
    pub has_data: bool,
    pub has_proof: bool,
    pub has_link: bool,
    pub data_error: bool,
    pub next: Option<BlockIdExt>,
}

/// Blocks served from memory with real block handles.
pub(super) struct MemoryBlocks {
    handles: std::collections::HashMap<BlockIdExt, Arc<BlockHandle>>,
    blocks: std::collections::HashMap<BlockIdExt, StoredBlock>,
    // A persistent state served for every part id of its block, and how its
    // slices misbehave: "", "oversized" or "truncated" past the first slice.
    state: std::sync::Mutex<Option<(BlockIdExt, Vec<u8>, &'static str)>>,
    // The first block stands for the last applied masterchain block.
    last_mc: Option<Arc<BlockIdExt>>,
    // Broadcasts the listener handed over.
    pub ext_messages: std::sync::Mutex<Vec<Vec<u8>>>,
    pub finality: std::sync::atomic::AtomicUsize,
    #[cfg(feature = "telemetry")]
    telemetry: crate::network::telemetry::FullNodeNetworkTelemetry,
}

fn unix_now() -> u32 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32
}

impl MemoryBlocks {
    pub(super) fn new(blocks: Vec<(BlockIdExt, StoredBlock)>) -> Self {
        let storage = crate::collator_test_bundle::create_block_handle_storage(None).unwrap();
        let mut handles = std::collections::HashMap::new();
        for (index, (id, block)) in blocks.iter().enumerate() {
            // The first block stands for a recent masterchain head, which lets
            // the listener process broadcasts.
            let meta = if index == 0 {
                storage::types::BlockMeta::with_data(0, unix_now(), 0, 0, 0)
            } else {
                storage::types::BlockMeta::default()
            };
            let handle = storage.create_handle(id.clone(), meta, None).unwrap().unwrap();
            if block.has_data {
                handle.set_data();
            }
            if block.has_proof {
                handle.set_proof();
            }
            if block.has_link {
                handle.set_proof_link();
            }
            if block.next.is_some() {
                handle.set_next1();
            }
            handles.insert(id.clone(), handle);
        }
        let last_mc = blocks.first().map(|(id, _)| Arc::new(id.clone()));
        Self {
            handles,
            blocks: blocks.into_iter().collect(),
            state: Default::default(),
            last_mc,
            ext_messages: Default::default(),
            finality: Default::default(),
            #[cfg(feature = "telemetry")]
            telemetry: crate::network::telemetry::FullNodeNetworkTelemetry::new_service(),
        }
    }

    pub(super) fn serve_state(&self, block: &BlockIdExt, bytes: Vec<u8>, misbehave: &'static str) {
        self.handles[block].set_persistent_state();
        *self.state.lock().unwrap() = Some((block.clone(), bytes, misbehave));
    }
}

#[async_trait::async_trait]
impl EngineOperations for MemoryBlocks {
    fn load_block_handle(&self, id: &BlockIdExt) -> Result<Option<Arc<BlockHandle>>> {
        Ok(self.handles.get(id).cloned())
    }
    fn load_block_next1(&self, id: &BlockIdExt) -> Result<BlockIdExt> {
        self.blocks.get(id).and_then(|b| b.next.clone()).ok_or_else(|| error!("no next for {id}"))
    }
    async fn load_block_raw(&self, handle: &Arc<BlockHandle>) -> Result<Vec<u8>> {
        match self.blocks.get(handle.id()) {
            Some(b) if !b.data_error => Ok(b.data.clone()),
            _ => fail!("no data for {}", handle.id()),
        }
    }
    async fn load_block_proof_raw(
        &self,
        handle: &Arc<BlockHandle>,
        is_link: bool,
    ) -> Result<Vec<u8>> {
        let b = self.blocks.get(handle.id()).ok_or_else(|| error!("no proof"))?;
        Ok(if is_link { b.link.clone() } else { b.proof.clone() })
    }
    fn check_stop(&self) -> bool {
        false
    }
    async fn check_sync(&self) -> Result<bool> {
        Ok(true)
    }
    fn now(&self) -> u32 {
        unix_now()
    }
    fn load_last_applied_mc_block_id(&self) -> Result<Option<Arc<BlockIdExt>>> {
        Ok(self.last_mc.clone())
    }
    #[cfg(feature = "telemetry")]
    fn full_node_service_telemetry(&self) -> &crate::network::telemetry::FullNodeNetworkTelemetry {
        &self.telemetry
    }
    async fn process_ext_msg_broadcast(
        &self,
        broadcast: rtos_api::ton::ton_node::broadcast::ExternalMessageBroadcast,
        _src: Arc<rtos_block::KeyId>,
    ) {
        self.ext_messages.lock().unwrap().push(broadcast.message.data);
    }
    async fn process_block_finality_broadcast(
        self: Arc<Self>,
        _broadcast: rtos_api::ton::ton_node::broadcast::BlockFinalityBroadcast,
        _src: Arc<rtos_block::KeyId>,
        _received_bytes: usize,
    ) -> Result<()> {
        self.finality.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    async fn load_persistent_state_size(&self, id: &PersistentStatePartId) -> Result<u64> {
        match &*self.state.lock().unwrap() {
            Some((block, bytes, _)) if block == id.block_id() => Ok(bytes.len() as u64),
            _ => fail!("no persistent state {id}"),
        }
    }
    async fn load_persistent_state_slice(
        &self,
        id: &PersistentStatePartId,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>> {
        let state = self.state.lock().unwrap();
        let Some((block, bytes, misbehave)) = &*state else { fail!("no persistent state") };
        if block != id.block_id() {
            fail!("no persistent state {id}");
        }
        let (offset, length) = (offset as usize, length as usize);
        let end = (offset + length).min(bytes.len());
        let mut out = bytes[offset.min(end)..end].to_vec();
        match *misbehave {
            "oversized" if offset > 0 => out.push(0x5c),
            "truncated" if offset > 0 => {
                out.pop();
            }
            _ => {}
        }
        Ok(out)
    }
}

pub(super) fn memory_service(blocks: Vec<(BlockIdExt, StoredBlock)>) -> FullNodeOverlayService {
    FullNodeOverlayService::new(
        Arc::new(MemoryBlocks::new(blocks)),
        false,
        Arc::new(crate::types::owned_tasks::OwnedTasks::default()),
    )
}

/// The driver's chain `chain`: block 0 without data, then one block per
/// (proof cells, block cells), each the next of the previous. The ids come
/// from the driver output and must match the rebuilt cells.
pub(super) fn cpp_chain(
    name: &str,
    chain: u64,
    workchain: i32,
    sizes: &[(u32, u32)],
) -> Vec<(BlockIdExt, StoredBlock)> {
    let shard =
        if workchain == -1 { ShardIdent::masterchain() } else { ShardIdent::full(workchain) };
    let zero = BlockIdExt::with_params(shard, 0, [chain as u8; 32].into(), [0xee; 32].into());
    let mut out = vec![(zero, StoredBlock::default())];
    for (i, (proof_cells, block_cells)) in sizes.iter().enumerate() {
        let seqno = i as u64 + 1;
        let proof = make_tree(chain * 1000 + seqno * 2 + 1, *proof_cells);
        let block = make_tree(chain * 1000 + seqno * 2 + 2, *block_cells);
        let id = cpp_block_id(cpp_value(CPP_NBF, &format!("{name}.block.{seqno}")));
        assert_eq!(
            id.root_hash(),
            block.repr_hash(),
            "rebuilt block tree differs from the driver's"
        );
        let stored = StoredBlock {
            data: rtos_block::write_boc(&block).unwrap(),
            proof: rtos_block::write_boc(&proof).unwrap(),
            link: rtos_block::write_boc(&link_root(&proof)).unwrap(),
            has_data: true,
            has_proof: true,
            has_link: true,
            data_error: false,
            next: None,
        };
        out.last_mut().unwrap().1.next = Some(id.clone());
        out.push((id, stored));
    }
    out
}

async fn next_blocks(
    service: &FullNodeOverlayService,
    prev: &BlockIdExt,
    max_blocks: i32,
) -> Vec<u8> {
    let answer = service
        .download_next_blocks_full(DownloadNextBlocksFull { prev_block: prev.clone(), max_blocks })
        .await
        .unwrap();
    WireProfile::T0.serialize(&answer).unwrap()
}

fn assert_next_blocks(case: &str, bytes: &[u8]) {
    assert_eq!(
        bytes.len().to_string(),
        cpp_value(CPP_NBF, &format!("{case}.len")),
        "{case} length"
    );
    assert_eq!(sha_hex(bytes), cpp_value(CPP_NBF, &format!("{case}.sha")), "{case} bytes");
}

fn with_block(
    mut chain: Vec<(BlockIdExt, StoredBlock)>,
    index: usize,
    f: impl FnOnce(&mut StoredBlock),
) -> Vec<(BlockIdExt, StoredBlock)> {
    f(&mut chain[index].1);
    chain
}

#[tokio::test(flavor = "multi_thread")]
async fn next_blocks_full_matches_the_reference_sender() {
    assert_eq!(cpp_value(CPP_NBF, "limits"), "10 1048576");
    let small = cpp_chain("small", 1, -1, &[(3, 5), (2, 7), (4, 4)]);
    let ids: Vec<_> = small.iter().map(|(id, _)| id.clone()).collect();
    let service = memory_service(small.clone());
    for n in [10, 2, 1, 0, -1, -7, 3] {
        assert_next_blocks(&format!("small.max{n}"), &next_blocks(&service, &ids[0], n).await);
    }
    assert_next_blocks("small.from2", &next_blocks(&service, &ids[2], 10).await);
    assert_next_blocks("small.fromlast", &next_blocks(&service, &ids[3], 10).await);
    let unknown =
        BlockIdExt::with_params(ShardIdent::masterchain(), 99, [9; 32].into(), [9; 32].into());
    assert_next_blocks("small.unknown", &next_blocks(&service, &unknown, 10).await);
    let basechain =
        BlockIdExt::with_params(ShardIdent::full(0), 0, [1; 32].into(), [0xee; 32].into());
    assert_next_blocks("small.basechain", &next_blocks(&service, &basechain, 10).await);
    for (case, f) in [
        ("small.link2", (|b: &mut StoredBlock| b.has_proof = false) as fn(&mut StoredBlock)),
        ("small.unreceived2", |b: &mut StoredBlock| b.has_data = false),
        ("small.deleted2", |b: &mut StoredBlock| b.has_data = false),
        ("small.dataerror2", |b: &mut StoredBlock| b.data_error = true),
    ] {
        let service = memory_service(with_block(small.clone(), 2, f));
        assert_next_blocks(case, &next_blocks(&service, &ids[0], 10).await);
    }
    let twelve = cpp_chain("twelve", 2, -1, &[(2, 3); 12]);
    let first = twelve[0].0.clone();
    let service = memory_service(twelve);
    assert_next_blocks("twelve.max10", &next_blocks(&service, &first, 10).await);
    assert_next_blocks("twelve.max20", &next_blocks(&service, &first, 20).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn next_blocks_full_size_cut_matches_the_reference_sender() {
    let large =
        cpp_chain("large", 3, -1, &[(20, 2600), (20, 2600), (20, 2600), (20, 2600), (20, 11000)]);
    let ids: Vec<_> = large.iter().map(|(id, _)| id.clone()).collect();
    let service = memory_service(large);
    assert_next_blocks("large.from0", &next_blocks(&service, &ids[0], 10).await);
    assert_next_blocks("large.from3", &next_blocks(&service, &ids[3], 10).await);
    assert_next_blocks("large.from4", &next_blocks(&service, &ids[4], 10).await);
    for cells in [6100u32, 6400, 6450, 6500, 6600] {
        let name = format!("edge{cells}");
        let chain = cpp_chain(&name, 4, -1, &[(10, 2000), (10, cells)]);
        let first = chain[0].0.clone();
        let service = memory_service(chain);
        assert_next_blocks(&name, &next_blocks(&service, &first, 10).await);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn single_block_sender_matches_the_reference_sender() {
    let ids: Vec<_> =
        (1..=2).map(|i| cpp_block_id(cpp_value(CPP_BFS, &format!("chain.block.{i}")))).collect();
    // The raw block and proof bytes are the driver's own, taken from its answer.
    let both = WireProfile::T0
        .deserialize_value::<DataFullBoxed>(&hex_bytes(cpp_value(CPP_BFS, "both")))
        .unwrap();
    let DataFullBoxed::TonNode_DataFull(both) = both else { panic!("expected dataFull") };
    let link = hex_bytes(cpp_value(CPP_BFS, "chain.link.1"));
    let zero =
        BlockIdExt::with_params(ShardIdent::masterchain(), 0, [5; 32].into(), [0xee; 32].into());
    let chain = |f: fn(&mut StoredBlock)| {
        let mut first = StoredBlock {
            data: both.block.clone(),
            proof: both.proof.clone(),
            link: link.clone(),
            has_data: true,
            has_proof: true,
            has_link: true,
            data_error: false,
            next: Some(ids[1].clone()),
        };
        f(&mut first);
        vec![
            (zero.clone(), StoredBlock { next: Some(ids[0].clone()), ..Default::default() }),
            (ids[0].clone(), first),
            (ids[1].clone(), StoredBlock::default()),
        ]
    };
    async fn full(service: &FullNodeOverlayService, id: &BlockIdExt) -> String {
        let answer =
            service.download_block_full(DownloadBlockFull { block: id.clone() }).await.unwrap();
        hex::encode(WireProfile::T0.serialize(&answer).unwrap())
    }
    async fn next(service: &FullNodeOverlayService, id: &BlockIdExt) -> String {
        let answer = service
            .download_next_block_full(DownloadNextBlockFull { prev_block: id.clone() })
            .await
            .unwrap();
        hex::encode(WireProfile::T0.serialize(&answer).unwrap())
    }
    let service = memory_service(chain(|_| {}));
    assert_eq!(full(&service, &ids[0]).await, cpp_value(CPP_BFS, "both"));
    assert_eq!(next(&service, &zero).await, cpp_value(CPP_BFS, "next.both"));
    assert_eq!(next(&service, &ids[1]).await, cpp_value(CPP_BFS, "next.none"));
    let unknown =
        BlockIdExt::with_params(ShardIdent::masterchain(), 77, [7; 32].into(), [7; 32].into());
    assert_eq!(full(&service, &unknown).await, cpp_value(CPP_BFS, "unknown"));
    let service = memory_service(chain(|b| b.has_proof = false));
    assert_eq!(full(&service, &ids[0]).await, cpp_value(CPP_BFS, "link"));
    let service = memory_service(chain(|b| {
        b.has_proof = false;
        b.has_link = false;
    }));
    assert_eq!(full(&service, &ids[0]).await, cpp_value(CPP_BFS, "neither"));
    let service = memory_service(chain(|b| b.has_data = false));
    assert_eq!(full(&service, &ids[0]).await, cpp_value(CPP_BFS, "unreceived"));
    assert_eq!(full(&service, &ids[0]).await, cpp_value(CPP_BFS, "deleted"));
}

#[tokio::test]
async fn capabilities_answer_matches_the_reference_shard() {
    let service = memory_service(vec![]);
    let answer = service.get_capabilities(GetCapabilities).await.unwrap();
    let bytes = hex::encode(WireProfile::T0.serialize(&answer).unwrap());
    let cpp = cpp_value(CPP_SHD, "active.queries");
    assert!(cpp.starts_with("getCapabilities=ok:"));
    assert_eq!(bytes, cpp.split(' ').next().unwrap().trim_start_matches("getCapabilities=ok:"));
}

// ------------------------------------------------------------ A3-07 neighbours

use crate::network::neighbours::{choose_from, replacement_victim, selection_weight, Neighbour};

fn neighbour(byte: u8, unreliability: u32, major: i32, minor: i32) -> Arc<Neighbour> {
    let n = Arc::new(Neighbour::new(rtos_block::KeyId::from_data([byte; 32]), 2000));
    n.set_test_state(unreliability, major, minor);
    n
}

#[test]
fn neighbour_statistics_follow_the_reference_counter() {
    assert_eq!(cpp_value(CPP_NEI, "constants"), "3 2 16 5.000000 10.000000");
    let n = neighbour(1, 0, 0, 0);
    let mut transport = false;
    for event in cpp_value(CPP_NEI, "stats").split_whitespace() {
        let parts: Vec<_> = event.split(':').collect();
        // Outcomes alternate between the transports: the counter is shared.
        transport = !transport;
        match parts[0] {
            "F" | "X" => n.query_failed(1, transport),
            "S" => n.query_success(1, transport),
            caps => {
                let digits: Vec<i32> =
                    caps[1..].chars().map(|c| c.to_digit(10).unwrap() as i32).collect();
                n.update_proto_version(
                    &rtos_api::ton::ton_node::capabilities::Capabilities {
                        version_major: digits[0],
                        version_minor: digits[1],
                    }
                    .into_boxed(),
                );
                n.query_success(1, transport);
            }
        }
        assert_eq!(n.unreliability().to_string(), parts[1], "after {event}");
        let (major, minor) = n.version();
        assert_eq!(format!("{major}.{minor}"), parts[2], "after {event}");
    }
}

fn cpp_table(name: &str) -> ((u32, u32), Vec<(u32, i32, i32)>, u64, Vec<(usize, u64)>, u64) {
    let line = cpp_value(CPP_NEI, &format!("choose.{name}"));
    let mut words: Vec<_> = line.split_whitespace().collect();
    if words[3] == "draws" {
        // An empty table prints no rows.
        words.insert(3, "");
    }
    let req: Vec<u32> = words[1].split('.').map(|x| x.parse().unwrap()).collect();
    let rows = words[3]
        .split(';')
        .filter(|r| !r.is_empty())
        .map(|r| {
            let v: Vec<i64> = r.split(',').map(|x| x.parse().unwrap()).collect();
            (v[0] as u32, v[1] as i32, v[2] as i32)
        })
        .collect();
    let draws = words[5].parse().unwrap();
    let mut counts = vec![];
    let mut zero = 0;
    for c in &words[7..] {
        let (k, v) = c.split_once('=').unwrap();
        if k == "zero" {
            zero = v.parse().unwrap();
        } else {
            counts.push((k.parse::<usize>().unwrap() - 1, v.parse().unwrap()));
        }
    }
    ((req[0], req[1]), rows, draws, counts, zero)
}

#[test]
fn neighbour_selection_matches_the_reference_distribution() {
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(7);
    for name in [
        "plain",
        "versions",
        "normalized",
        "sole",
        "sole_old",
        "cutoff",
        "required",
        "required_none",
        "required_minor",
        "empty",
    ] {
        let (required, rows, draws, counts, zero) = cpp_table(name);
        let peers: Vec<_> = rows
            .iter()
            .enumerate()
            .map(|(i, (u, ma, mi))| neighbour(i as u8 + 1, *u, *ma, *mi))
            .collect();
        // Exact weights against the reference frequencies.
        let eligible: Vec<_> = peers
            .iter()
            .filter(|n| {
                let (ma, mi) = n.version();
                ma > required.0 || (ma == required.0 && mi >= required.1)
            })
            .collect();
        let min = eligible.iter().map(|n| n.unreliability()).min();
        let weights: Vec<u64> = peers
            .iter()
            .map(|n| match (eligible.iter().any(|e| Arc::ptr_eq(e, n)), min) {
                (true, Some(min)) => {
                    selection_weight(n.unreliability(), min, n.version()).map_or(0, |w| w as u64)
                }
                _ => 0,
            })
            .collect();
        let total: u64 = weights.iter().sum();
        for (i, w) in weights.iter().enumerate() {
            let observed = counts.iter().find(|(k, _)| *k == i).map_or(0, |(_, v)| *v);
            if *w == 0 {
                assert_eq!(observed, 0, "{name}: neighbour {i} must never be chosen");
            } else {
                let expected = *w as f64 / total as f64;
                let freq = observed as f64 / draws as f64;
                assert!(
                    (expected - freq).abs() < 0.004,
                    "{name}: neighbour {i} {expected} vs {freq}"
                );
            }
        }
        assert_eq!(total == 0, zero == draws, "{name}: no neighbour");
        // The sampler itself.
        let mut ours = vec![0u64; peers.len()];
        let mut none = 0u64;
        for _ in 0..draws {
            match choose_from(&peers, required, &mut rng) {
                Some(n) => ours[peers.iter().position(|p| Arc::ptr_eq(p, &n)).unwrap()] += 1,
                None => none += 1,
            }
        }
        assert_eq!(none, zero, "{name}: unselectable draws");
        for (i, count) in ours.iter().enumerate() {
            let observed = counts.iter().find(|(k, _)| *k == i).map_or(0, |(_, v)| *v);
            let diff = (*count as f64 - observed as f64).abs() / draws as f64;
            assert!(diff < 0.006, "{name}: neighbour {i} sampled {count} vs {observed}");
        }
    }
}

#[test]
fn neighbour_rotation_matches_the_reference() {
    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::seed_from_u64(11);
    for bad in [6u32, 5] {
        let line = cpp_value(CPP_NEI, &format!("rotate.bad{bad}"));
        let words: Vec<_> = line.split_whitespace().collect();
        let trials = 2000u64;
        let mut cpp_replaced = std::collections::HashMap::new();
        for c in &words[3..] {
            let (k, v) = c.split_once('=').unwrap();
            cpp_replaced.insert(k.parse::<u8>().unwrap(), v.parse::<u64>().unwrap());
        }
        let peers: Vec<_> = (0..16u8)
            .map(|i| neighbour(i + 1, if i == 3 { bad } else { (i % 3) as u32 }, 3, 2))
            .collect();
        let mut ours = std::collections::HashMap::new();
        for _ in 0..trials {
            let (victim, is_bad) = replacement_victim(&peers, &mut rng).unwrap();
            assert_eq!(is_bad, bad > 5);
            let index = peers.iter().position(|p| Arc::ptr_eq(p, &victim)).unwrap() as u8 + 1;
            *ours.entry(index).or_insert(0u64) += 1;
        }
        if bad > 5 {
            // The unreliable neighbour goes first, every time.
            assert_eq!(cpp_replaced.get(&4), Some(&trials));
            assert_eq!(ours.get(&4), Some(&trials));
            assert_eq!(ours.len(), 1);
        } else {
            // A uniform choice: every member is replaced in about 1/16 of the trials.
            for i in 1..=16u8 {
                let cpp = *cpp_replaced.get(&i).unwrap_or(&0) as f64 / trials as f64;
                let rust = *ours.get(&i).unwrap_or(&0) as f64 / trials as f64;
                assert!((cpp - 1.0 / 16.0).abs() < 0.03 && (rust - 1.0 / 16.0).abs() < 0.03);
            }
            let inserted: u64 = words[1].parse().unwrap();
            assert_eq!(inserted, trials, "exactly one new peer per rotation");
        }
    }
}

// ------------------------------------------------------------ A3-13 key blocks

pub(super) const CPP_NKB: &str = include_str!("data/fullnode-proto/out-nkb.txt");

#[test]
fn key_block_answers_follow_the_reference_requester() {
    use crate::network::full_node_overlay_client::next_key_block_ids;
    // keyBlocks.<incomplete><error> carry one block; the reference requester
    // fails "not ready" on the error flag whatever the list holds, and takes
    // the list otherwise.
    assert!(cpp_value(CPP_NKB, "error_with_blocks").starts_with("error 651"));
    assert!(cpp_value(CPP_NKB, "error_incomplete_with_blocks").starts_with("error 651"));
    assert!(cpp_value(CPP_NKB, "incomplete_empty").starts_with("ok 0"));
    assert!(cpp_value(CPP_NKB, "complete_empty").starts_with("ok 0"));
    for (key, ok) in [
        ("keyBlocks.00", true),
        ("keyBlocks.10", true),
        ("keyBlocks.01", false),
        ("keyBlocks.11", false),
    ] {
        let answer = WireProfile::T0
            .deserialize_value::<KeyBlocks>(&hex_bytes(cpp_value(CPP_TL, key)))
            .unwrap();
        match next_key_block_ids(answer) {
            Ok(blocks) => {
                assert!(ok, "{key} must be refused");
                assert_eq!(blocks.len(), 1);
            }
            Err(_) => assert!(!ok, "{key} must be accepted"),
        }
    }
}

// ------------------------------------------------------------ A3-12 admission

pub(super) const CPP_ADM: &str = include_str!("data/fullnode-proto/out-adm.txt");

/// A query of the named type claiming `size` bytes, as the driver builds it.
pub(super) fn admission_query(name: &str, size: i64) -> TLObject {
    use rtos_api::ton::rpc::ton_node::{GetNextBlocksDescription, GetOutMsgQueueProof};
    match name {
        "getArchiveSlice" => {
            GetArchiveSlice { archive_id: 1, offset: 0, max_size: size as i32 }.into_tl_object()
        }
        "downloadPersistentStateSliceV2" => {
            DownloadPersistentStateSliceV2 { max_size: size, ..Default::default() }.into_tl_object()
        }
        "downloadZeroState" => DownloadZeroState::default().into_tl_object(),
        "downloadBlock" => DownloadBlock::default().into_tl_object(),
        "downloadBlockFull" => DownloadBlockFull::default().into_tl_object(),
        "downloadNextBlockFull" => DownloadNextBlockFull::default().into_tl_object(),
        "downloadNextBlocksFull" => {
            DownloadNextBlocksFull { max_blocks: 10, ..Default::default() }.into_tl_object()
        }
        "downloadBlockProof" => DownloadBlockProof::default().into_tl_object(),
        "downloadBlockProofLink" => DownloadBlockProofLink::default().into_tl_object(),
        "downloadKeyBlockProof" => DownloadKeyBlockProof::default().into_tl_object(),
        "downloadKeyBlockProofLink" => DownloadKeyBlockProofLink::default().into_tl_object(),
        "getOutMsgQueueProof" => GetOutMsgQueueProof::default().into_tl_object(),
        "prepareKeyBlockProof" => PrepareKeyBlockProof::default().into_tl_object(),
        "getNextBlockDescription" => GetNextBlockDescription::default().into_tl_object(),
        "getNextBlocksDescription" => GetNextBlocksDescription::default().into_tl_object(),
        "prepareBlockProof" => PrepareBlockProof::default().into_tl_object(),
        "prepareBlock" => PrepareBlock::default().into_tl_object(),
        "prepareZeroState" => PrepareZeroState::default().into_tl_object(),
        "getNextKeyBlockIds" => GetNextKeyBlockIds::default().into_tl_object(),
        "getArchiveInfo" => GetArchiveInfo::default().into_tl_object(),
        "getShardArchiveInfo" => GetShardArchiveInfo::default().into_tl_object(),
        "preparePersistentState" => PreparePersistentState::default().into_tl_object(),
        "getPersistentStateSizeV2" => GetPersistentStateSizeV2::default().into_tl_object(),
        "getCapabilities" => GetCapabilities.into_tl_object(),
        other => panic!("unknown query {other}"),
    }
}

fn admission_shards() -> [ShardIdent; 3] {
    [
        ShardIdent::masterchain(),
        ShardIdent::with_tagged_prefix(0, 0x4000_0000_0000_0000).unwrap(),
        ShardIdent::with_tagged_prefix(0, 0xc000_0000_0000_0000).unwrap(),
    ]
}

#[test]
fn admission_constants_and_answers_match_the_reference() {
    assert_eq!(cpp_value(CPP_ADM, "constants"), "1.000000 96 64 72 200 1024");
    for (key, value) in cpp_lines(CPP_ADM) {
        if let Some(name) = key.strip_prefix("refusalAnswer.") {
            let answer = capacity_refusal_answer(&admission_query(name, 1 << 21))
                .map(|a| hex::encode(WireProfile::T0.serialize(&a).unwrap()));
            assert_eq!(answer.as_deref().unwrap_or("-"), value, "refusal answer of {name}");
        }
        if let Some(limits) = key.strip_prefix("check.") {
            let v: Vec<&str> = limits.split('.').collect();
            // "<window>.<fraction>.<global>.<heavy>.<medium>"
            let window: f64 = format!("{}.{}", v[0], v[1]).parse().unwrap();
            let limits = FullNodeRateLimits::new(
                window,
                v[2].parse().unwrap(),
                v[3].parse().unwrap(),
                v[4].parse().unwrap(),
            );
            assert_eq!(if limits.check().is_ok() { "ok" } else { "error" }, value, "{key}");
        }
    }
}

#[test]
fn admission_replays_the_reference_scripts() {
    let shards = admission_shards();
    let mut current: Option<(String, FullNodeAdmission, f64)> = None;
    let mut queries = 0usize;
    for (script, line) in cpp_lines(CPP_ADM) {
        let words: Vec<&str> = line.split(' ').collect();
        match words[0] {
            "LIMITS" => {
                let limits = FullNodeRateLimits::new(
                    words[1].parse().unwrap(),
                    words[2].parse().unwrap(),
                    words[3].parse().unwrap(),
                    words[4].parse().unwrap(),
                );
                assert_eq!(limits.small.window_limit.to_string(), words[5]);
                let start = words[7].parse::<f64>().unwrap() / 1000.0;
                current = Some((
                    script.to_string(),
                    FullNodeAdmission::with_start(limits, start).unwrap(),
                    start,
                ));
            }
            "REG" | "UNREG" | "Q" => {
                let (name, admission, start) = current.as_ref().unwrap();
                assert_eq!(name, script);
                if words[0] == "REG" {
                    admission.register_shard(&shards[words[1].parse::<usize>().unwrap()]).unwrap();
                } else if words[0] == "UNREG" {
                    admission
                        .unregister_shard(&shards[words[1].parse::<usize>().unwrap()])
                        .unwrap();
                } else {
                    let t: i64 = words[1].parse().unwrap();
                    let source =
                        rtos_block::KeyId::from_data([words[2].parse::<u8>().unwrap(); 32]);
                    let shard = &shards[words[3].parse::<usize>().unwrap()];
                    let query = admission_query(words[4], words[5].parse().unwrap());
                    let now = start + t as f64 / 1000.0;
                    let decision = admission.admit(&query, shard, &source, now).unwrap();
                    let (outcome, answer) = match decision {
                        Admission::Admitted => ("A", None),
                        Admission::Answered(answer) => {
                            ("R", Some(hex::encode(WireProfile::T0.serialize(&answer).unwrap())))
                        }
                        Admission::Refused => ("E", None),
                    };
                    assert_eq!(outcome, words[6], "{script}: {line}");
                    assert_eq!(answer.as_deref(), words.get(7).copied(), "{script}: {line}");
                    queries += 1;
                }
            }
            _ => {}
        }
    }
    assert!(queries > 8000, "the scripts must have been replayed");
}

#[path = "test_full_node_protocol_wire.rs"]
mod wire;
