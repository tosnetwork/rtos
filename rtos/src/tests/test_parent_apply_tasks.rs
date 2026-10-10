// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use tokio::sync::Semaphore;

struct TaskEngine {
    calls: Mutex<Vec<(u32, u32, bool, u32)>>,
    started: Semaphore,
    dropped: Semaphore,
    active: AtomicUsize,
    release: [Semaphore; 2],
    nested: bool,
    fail: bool,
}
impl TaskEngine {
    fn new(nested: bool, fail: bool) -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(vec![]),
            started: Semaphore::new(0),
            dropped: Semaphore::new(0),
            active: AtomicUsize::new(0),
            release: [Semaphore::new(0), Semaphore::new(0)],
            nested,
            fail,
        })
    }
}
struct Entered(Arc<TaskEngine>);
impl Drop for Entered {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
        self.0.dropped.add_permits(1);
    }
}
fn id(seq: u32) -> BlockIdExt {
    BlockIdExt { seq_no: seq, ..Default::default() }
}
#[async_trait::async_trait]
impl EngineOperations for TaskEngine {
    async fn download_and_apply_block_internal(
        self: Arc<Self>,
        block: &BlockIdExt,
        mc: u32,
        pre: bool,
        depth: u32,
    ) -> Result<()> {
        self.active.fetch_add(1, Ordering::SeqCst);
        let _entered = Entered(self.clone());
        self.calls.lock().unwrap().push((block.seq_no, mc, pre, depth));
        self.started.add_permits(1);
        if self.nested && block.seq_no > 1 {
            return check_prev_blocks(
                &(id(block.seq_no - 1), None),
                &(self.clone() as Arc<dyn EngineOperations>),
                mc,
                pre,
                depth,
            )
            .await;
        }
        self.release[(block.seq_no - 1) as usize].acquire().await.unwrap().forget();
        if self.fail {
            fail!("parent {} failed", block.seq_no);
        }
        Ok(())
    }
}
async fn permits(sem: &Semaphore, count: u32) {
    tokio::time::timeout(std::time::Duration::from_secs(5), sem.acquire_many(count))
        .await
        .expect("parent task lifecycle deadline")
        .unwrap()
        .forget();
}
#[tokio::test]
async fn parent_tasks_preserve_merge_completion_and_error_order() {
    let engine = TaskEngine::new(false, true);
    let cloned = engine.clone();
    let task = tokio::spawn(async move {
        check_prev_blocks(
            &(id(1), Some(id(2))),
            &(cloned as Arc<dyn EngineOperations>),
            97,
            true,
            6,
        )
        .await
    });
    permits(&engine.started, 2).await;
    engine.release[1].add_permits(1);
    permits(&engine.dropped, 1).await;
    assert!(!task.is_finished(), "both parents must finish before returning an error");
    engine.release[0].add_permits(1);
    assert_eq!(task.await.unwrap().unwrap_err().to_string(), "parent 1 failed");
    let mut calls = engine.calls.lock().unwrap().clone();
    calls.sort();
    assert_eq!(calls, vec![(1, 97, true, 7), (2, 97, true, 7)]);
    assert_eq!(engine.active.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn parent_tasks_cancel_both_merge_children() {
    let engine = TaskEngine::new(false, false);
    let cloned = engine.clone();
    let task = tokio::spawn(async move {
        check_prev_blocks(
            &(id(1), Some(id(2))),
            &(cloned as Arc<dyn EngineOperations>),
            31,
            false,
            0,
        )
        .await
    });
    permits(&engine.started, 2).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    permits(&engine.dropped, 2).await;
    assert_eq!(engine.active.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn parent_tasks_cancel_transitive_ancestors() {
    let engine = TaskEngine::new(true, false);
    let cloned = engine.clone();
    let task = tokio::spawn(async move {
        check_prev_blocks(&(id(3), None), &(cloned as Arc<dyn EngineOperations>), 42, false, 5)
            .await
    });
    permits(&engine.started, 3).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    permits(&engine.dropped, 3).await;
    assert_eq!(engine.active.load(Ordering::SeqCst), 0);
    assert_eq!(
        *engine.calls.lock().unwrap(),
        vec![(3, 42, false, 6), (2, 42, false, 7), (1, 42, false, 8)]
    );
}
