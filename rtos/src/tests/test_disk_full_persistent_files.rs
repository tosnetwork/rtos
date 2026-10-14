// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Actual InternalDb persistent producers and serving methods under ENOSPC.
//! Public storage fixtures only: no authenticated-chain or UDP acceptance claim.
use crate::{
    block::BlockStuff, engine_traits::EngineOperations, internal_db::InternalDb,
    network::full_node_service::FullNodeOverlayService, shard_state::ShardStateStuff,
    test_helper::TestEngine, types::owned_tasks::OwnedTasks,
};
use rtos_block::{
    read_single_root_boc, write_boc, BlockIdExt, BuilderData, Cell, Result, ShardIdent, UInt256,
};
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use storage::{
    block_handle_db::BlockHandle,
    db::DbKey,
    shardstate_db_async::SsNotificationCallback,
    types::{PersistentStatePartId, PersistentStatePartKey},
};
const TIMEOUT: Duration = Duration::from_secs(30);
struct Serving(Arc<InternalDb>);
#[async_trait::async_trait]
impl EngineOperations for Serving {
    fn load_block_handle(&self, id: &BlockIdExt) -> Result<Option<Arc<BlockHandle>>> {
        self.0.load_block_handle(id)
    }
    async fn load_persistent_state_size(&self, id: &PersistentStatePartId) -> Result<u64> {
        self.0.load_shard_state_persistent_size(id).await
    }
    async fn load_persistent_state_slice(
        &self,
        id: &PersistentStatePartId,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>> {
        self.0.load_shard_state_persistent_slice(id, offset, length).await
    }
    async fn load_persistent_state_to(
        &self,
        id: &PersistentStatePartId,
        dest: &mut Vec<u8>,
    ) -> Result<()> {
        self.0.load_shard_state_persistent_to(id, dest).await
    }
}
fn service(db: &Arc<InternalDb>) -> FullNodeOverlayService {
    FullNodeOverlayService::new(
        Arc::new(Serving(db.clone())),
        false,
        Arc::new(OwnedTasks::default()),
    )
}
fn control() -> bool {
    std::env::var("RTOS_ENOSPC_CONTROL").as_deref() == Ok("1")
}
fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/tests/static")
}
fn file_path(root: &Path, part: &PersistentStatePartId, temporary: bool) -> PathBuf {
    let key = PersistentStatePartKey::from(part);
    let name = hex::encode(key.key());
    let mut path = root.join("shard_state_persistent_db").join(&name[..4]).join(&name[4..]);
    if temporary {
        path.set_extension("tmp");
    }
    path
}
struct Filler(Vec<PathBuf>);
impl Filler {
    fn make(root: &Path, inodes: bool) -> Self {
        if inodes {
            let mut paths = Vec::new();
            loop {
                let path = root.join(format!("enospc-inode-{}", paths.len()));
                match std::fs::File::create(&path) {
                    Ok(_) => paths.push(path),
                    Err(error) => {
                        assert_eq!(error.raw_os_error(), Some(28));
                        break;
                    }
                }
            }
            Self(paths)
        } else {
            let path = root.join("enospc-filler");
            let mut file = std::fs::File::create(&path).unwrap();
            for size in [65536, 4096] {
                loop {
                    match file.write_all(&vec![0; size]) {
                        Ok(()) => (),
                        Err(error) => {
                            assert_eq!(error.raw_os_error(), Some(28));
                            break;
                        }
                    }
                }
            }
            Self(vec![path])
        }
    }
    fn free(self) {
        for path in self.0 {
            std::fs::remove_file(path).unwrap();
        }
    }
}
fn part(mode: &str, id: &BlockIdExt) -> PersistentStatePartId {
    if mode == "head" {
        PersistentStatePartId::Head(id.clone())
    } else {
        PersistentStatePartId::WholeState(id.clone())
    }
}
async fn store(db: &InternalDb, mode: &str, handle: &Arc<BlockHandle>, root: Cell) -> Result<()> {
    let id = part(mode, handle.id());
    let operation = async {
        match mode {
            "fast" => {
                db.store_shard_state_persistent_part_fast(handle, &id, root, Arc::new(|| false))
                    .await
            }
            "head" | "whole" => {
                db.store_shard_state_persistent_part(handle, &id, root, None, Arc::new(|| false))
                    .await
            }
            "raw" => db.store_shard_state_persistent_raw(handle, &write_boc(&root)?, None).await,
            _ => panic!("unknown producer"),
        }
    };
    tokio::time::timeout(TIMEOUT, operation).await.expect("persistent producer timed out")
}
async fn open(root: &Path) -> TestEngine {
    tokio::time::timeout(TIMEOUT, TestEngine::new_db_dir(root.to_str().unwrap(), None))
        .await
        .unwrap()
        .unwrap()
}
async fn close(engine: TestEngine) {
    tokio::time::timeout(TIMEOUT, engine.db.stop_states_db())
        .await
        .expect("node owners failed to stop")
        .unwrap();
    drop(engine);
}
async fn verify(
    db: &Arc<InternalDb>,
    root: &Path,
    mode: &str,
    id: &BlockIdExt,
    cell: &Cell,
    exact: Option<&[u8]>,
) -> Vec<u8> {
    let handle = db.load_block_handle(id).unwrap().expect("published handle missing");
    assert!(handle.has_persistent_state());
    let part = part(mode, id);
    let path = file_path(root, &part, false);
    let bytes = std::fs::read(path).unwrap();
    if let Some(exact) = exact {
        assert_eq!(bytes, exact, "acknowledged persistent bytes changed");
    }
    assert_eq!(read_single_root_boc(&bytes).unwrap().repr_hash(), cell.repr_hash());
    let server = service(db);
    assert_eq!(server.test_persistent_size(part.clone()).await.unwrap(), Some(bytes.len() as u64));
    assert_eq!(
        server.test_persistent_slice(&part).await.unwrap(),
        bytes,
        "service did not read the real target file"
    );
    bytes
}
async fn exercise(mode: &str, inodes: bool) {
    let case = format!("persistent-{mode}-{}", if inodes { "inodes" } else { "body" });
    let root = PathBuf::from(std::env::var_os("RTOS_ENOSPC_ROOT").expect("run in tmpfs harness"))
        .join(&case);
    std::fs::create_dir_all(&root).unwrap();
    let control = control();
    let engine = open(&root).await;
    let seed_root = BuilderData::with_raw(vec![42], 8).unwrap().into_cell().unwrap();
    let seed_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        1,
        UInt256::from([0x11; 32]),
        UInt256::from([0x12; 32]),
    );
    let seed_handle = engine.db.create_test_block_handle(&seed_id).unwrap();
    store(&engine.db, mode, &seed_handle, seed_root.clone()).await.unwrap();
    engine.db.sync_publication_metadata(&seed_handle).await.unwrap();
    let seed_bytes = verify(&engine.db, &root, mode, &seed_id, &seed_root, None).await;
    let block =
        BlockStuff::read_block_from_file(fixture_root().join("b571525").to_str().unwrap()).unwrap();
    let target_id = block.id().clone();
    let state = ShardStateStuff::read_from_file(
        target_id.clone(),
        fixture_root().join("ss571525").to_str().unwrap(),
        #[cfg(feature = "telemetry")]
        engine.engine_telemetry(),
        engine.engine_allocated(),
    )
    .unwrap();
    let target_root = state.root_cell().clone();
    let target = engine.db.store_block_data(&block, None).await.unwrap().to_any();
    if mode == "whole" {
        let callback = SsNotificationCallback::new();
        engine
            .db
            .store_shard_state_dynamic(&target, &state, None, Some(callback.clone()), false)
            .await
            .unwrap();
        tokio::time::timeout(TIMEOUT, callback.wait())
            .await
            .expect("real dynamic state callback timed out");
        engine.db.sync_publication_state().await.unwrap();
    }
    engine.db.sync_publication_metadata(&target).await.unwrap();
    assert!(!target.has_persistent_state());
    let target_part = part(mode, &target_id);
    let target_path = file_path(&root, &target_part, false);
    std::fs::create_dir_all(target_path.parent().unwrap()).unwrap();
    let filler = if control { None } else { Some(Filler::make(&root, inodes)) };
    let result = store(&engine.db, mode, &target, target_root.clone()).await;
    assert_eq!(result.is_ok(), control, "persistent acknowledgement: {result:?}");
    if let Err(error) = result {
        assert!(format!("{error:#}").contains("No space left"), "{error:#}");
        assert!(!target.has_persistent_state(), "failed producer published persistent flag");
    }
    if let Some(filler) = filler {
        filler.free();
    }
    if control {
        engine.db.sync_publication_metadata(&target).await.unwrap();
    }
    let server = service(&engine.db);
    if !control {
        assert_eq!(
            server.test_persistent_size(target_part.clone()).await.unwrap(),
            None,
            "failed persistent file advertised as available"
        );
        assert!(
            server.test_persistent_slice(&target_part).await.is_err(),
            "failed persistent slice served"
        );
    } else {
        verify(&engine.db, &root, mode, &target_id, &target_root, None).await;
    }
    verify(&engine.db, &root, mode, &seed_id, &seed_root, Some(&seed_bytes)).await;
    drop(server);
    drop(target);
    drop(seed_handle);
    drop(state);
    close(engine).await;
    let engine = open(&root).await;
    verify(&engine.db, &root, mode, &seed_id, &seed_root, Some(&seed_bytes)).await;
    let target = engine.db.load_block_handle(&target_id).unwrap().unwrap();
    assert_eq!(target.has_persistent_state(), control);
    if !control {
        let server = service(&engine.db);
        assert_eq!(
            server.test_persistent_size(target_part.clone()).await.unwrap(),
            None,
            "cold partial state advertised"
        );
        assert!(server.test_persistent_slice(&target_part).await.is_err());
    }
    store(&engine.db, mode, &target, target_root.clone()).await.unwrap();
    engine.db.sync_publication_metadata(&target).await.unwrap();
    let completed = verify(&engine.db, &root, mode, &target_id, &target_root, None).await;
    drop(target);
    close(engine).await;
    let engine = open(&root).await;
    verify(&engine.db, &root, mode, &seed_id, &seed_root, Some(&seed_bytes)).await;
    verify(&engine.db, &root, mode, &target_id, &target_root, Some(&completed)).await;
    close(engine).await;
    eprintln!("ENOSPC-CASE {case} {} ok", if control { "control" } else { "fault" });
}
macro_rules! case {
    ($name:ident,$mode:literal,$inode:literal) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        #[ignore = "requires isolated ENOSPC tmpfs and syscall trace"]
        async fn $name() {
            exercise($mode, $inode).await;
        }
    };
}
case!(disk_full_persistent_fast_body, "fast", false);
case!(disk_full_persistent_fast_inodes, "fast", true);
case!(disk_full_persistent_head_body, "head", false);
case!(disk_full_persistent_head_inodes, "head", true);
case!(disk_full_persistent_whole_body, "whole", false);
case!(disk_full_persistent_whole_inodes, "whole", true);
case!(disk_full_persistent_raw_body, "raw", false);
case!(disk_full_persistent_raw_inodes, "raw", true);
