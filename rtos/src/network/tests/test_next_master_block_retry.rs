// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! The masterchain client against persistent failures to get the next block.
//! The reference node waits 100 ms after every failed attempt; a driver run of
//! its next-block loop against an always failing peer made 30 attempts in 3 s
//! (data/fullnode-proto/out-nxt.txt). Time is Tokio's paused clock, advanced
//! explicitly.
use super::*;
use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};
use storage::block_handle_db::BlockHandle;

const CPP_NXT: &str = include_str!("data/fullnode-proto/out-nxt.txt");
// A loop without the delay stops here instead of running away.
const MAX_ATTEMPTS: usize = 1000;
const ROUTER_ERROR: &str = "Overlays router is not ready or is stopping";

#[derive(Clone, Copy)]
enum Step {
    // The predecessor has no next block and the download fails.
    Fail,
    // The download fails with a timeout.
    Timeout,
    // The predecessor knows its next block, which applies.
    Next,
}

struct RetryEngine {
    without_next: HashMap<BlockIdExt, Arc<BlockHandle>>,
    with_next: HashMap<BlockIdExt, Arc<BlockHandle>>,
    next: HashMap<BlockIdExt, BlockIdExt>,
    missing_handle: bool,
    script: Mutex<VecDeque<Step>>,
    current: Mutex<Step>,
    // (time, predecessor) of every attempt.
    attempts: Mutex<Vec<(tokio::time::Instant, BlockIdExt)>>,
    stop: AtomicBool,
}

fn mc_id(seqno: u32) -> BlockIdExt {
    BlockIdExt::with_params(
        rtos_block::ShardIdent::masterchain(),
        seqno,
        [seqno as u8; 32].into(),
        [seqno as u8 + 100; 32].into(),
    )
}

impl RetryEngine {
    fn new(script: Vec<Step>, missing_handle: bool) -> Arc<Self> {
        let plain = crate::collator_test_bundle::create_block_handle_storage(None).unwrap();
        let linked = crate::collator_test_bundle::create_block_handle_storage(None).unwrap();
        let mut without_next = HashMap::new();
        let mut with_next = HashMap::new();
        let mut next = HashMap::new();
        for seqno in 1..4 {
            let id = mc_id(seqno);
            let meta = || storage::types::BlockMeta::default();
            without_next.insert(
                id.clone(),
                plain.create_handle(id.clone(), meta(), None).unwrap().unwrap(),
            );
            let handle = linked.create_handle(id.clone(), meta(), None).unwrap().unwrap();
            handle.set_next1();
            with_next.insert(id.clone(), handle);
            next.insert(id, mc_id(seqno + 1));
        }
        Arc::new(Self {
            without_next,
            with_next,
            next,
            missing_handle,
            script: Mutex::new(script.into()),
            current: Mutex::new(Step::Fail),
            attempts: Default::default(),
            stop: AtomicBool::new(false),
        })
    }

    fn attempts(&self) -> Vec<(tokio::time::Instant, BlockIdExt)> {
        self.attempts.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl EngineOperations for RetryEngine {
    fn check_stop(&self) -> bool {
        self.stop.load(Ordering::SeqCst) || self.attempts.lock().unwrap().len() >= MAX_ATTEMPTS
    }
    fn load_shard_client_mc_block_id(&self) -> Result<Option<Arc<BlockIdExt>>> {
        Ok(None)
    }
    fn load_block_handle(&self, id: &BlockIdExt) -> Result<Option<Arc<BlockHandle>>> {
        // Every attempt starts by loading its predecessor's handle.
        self.attempts.lock().unwrap().push((tokio::time::Instant::now(), id.clone()));
        let step = self.script.lock().unwrap().pop_front().unwrap_or(Step::Fail);
        *self.current.lock().unwrap() = step;
        if self.missing_handle {
            return Ok(None);
        }
        Ok(match step {
            Step::Next => self.with_next.get(id).cloned(),
            Step::Fail | Step::Timeout => self.without_next.get(id).cloned(),
        })
    }
    fn load_block_next1(&self, id: &BlockIdExt) -> Result<BlockIdExt> {
        self.next.get(id).cloned().ok_or_else(|| error!("no next for {id}"))
    }
    async fn download_and_apply_block(
        self: Arc<Self>,
        _id: &BlockIdExt,
        _mc_seq_no: u32,
        _pre_apply: bool,
    ) -> Result<()> {
        Ok(())
    }
    async fn download_next_block(
        &self,
        _prev_id: &BlockIdExt,
    ) -> Result<(BlockStuff, BlockProofStuff)> {
        match *self.current.lock().unwrap() {
            Step::Timeout => fail!(NodeError::Timeout("next block".to_string())),
            _ => fail!("{ROUTER_ERROR}"),
        }
    }
}

/// Lets the client task run until it waits on the clock.
async fn settle() {
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
}

fn cpp_attempts_in_three_seconds() -> usize {
    let line = CPP_NXT.lines().find(|l| l.starts_with("NXT persistent_error")).unwrap();
    let words: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(words[2], "seconds");
    assert!(words[3].starts_with("3.00"));
    assert_eq!(words[4], "attempts");
    words[5].parse().unwrap()
}

/// One failure every 100 ms on the paused clock, the reference's 30 attempts
/// in its 3 s window, and a stop that waits at most the remaining delay.
async fn persistent_failure(engine: Arc<RetryEngine>) {
    let start = tokio::time::Instant::now();
    let task = tokio::spawn(load_master_blocks_cycle(engine.clone(), mc_id(1)));
    settle().await;
    assert_eq!(engine.attempts().len(), 1, "one attempt, then the delay");
    tokio::time::advance(Duration::from_millis(99)).await;
    settle().await;
    assert_eq!(engine.attempts().len(), 1, "no attempt before 100 ms");
    tokio::time::advance(Duration::from_millis(1)).await;
    settle().await;
    assert_eq!(engine.attempts().len(), 2, "the next attempt at 100 ms");
    // Up to just before the end of the reference's 3 s window.
    for _ in 0..28 {
        tokio::time::advance(Duration::from_millis(100)).await;
        settle().await;
    }
    tokio::time::advance(Duration::from_millis(50)).await;
    settle().await;
    assert_eq!(start.elapsed(), Duration::from_millis(2950));
    assert_eq!(engine.attempts().len(), cpp_attempts_in_three_seconds());
    for pair in engine.attempts().windows(2) {
        assert_eq!(pair[1].0 - pair[0].0, Duration::from_millis(100));
    }
    // A stop during the delay ends the client when the delay is over, before
    // another attempt starts.
    engine.stop.store(true, Ordering::SeqCst);
    let attempts = engine.attempts().len();
    tokio::time::advance(Duration::from_millis(50)).await;
    settle().await;
    assert!(task.is_finished(), "the stop takes effect at the end of the delay");
    task.await.unwrap().unwrap();
    assert_eq!(engine.attempts().len(), attempts, "no attempt after the stop");
}

#[tokio::test(start_paused = true)]
async fn router_not_ready_is_retried_every_100_ms() {
    persistent_failure(RetryEngine::new(vec![], false)).await;
}

#[tokio::test(start_paused = true)]
async fn missing_predecessor_handle_is_retried_every_100_ms() {
    persistent_failure(RetryEngine::new(vec![], true)).await;
}

#[tokio::test(start_paused = true)]
async fn a_success_goes_on_at_once_and_resets_the_delay() {
    let engine = RetryEngine::new(vec![Step::Fail, Step::Next, Step::Fail], false);
    let start = tokio::time::Instant::now();
    let task = tokio::spawn(load_master_blocks_cycle(engine.clone(), mc_id(1)));
    settle().await;
    for _ in 0..2 {
        tokio::time::advance(Duration::from_millis(100)).await;
        settle().await;
    }
    engine.stop.store(true, Ordering::SeqCst);
    tokio::time::advance(Duration::from_millis(100)).await;
    settle().await;
    task.await.unwrap().unwrap();
    let attempts: Vec<_> = engine
        .attempts()
        .into_iter()
        .map(|(at, prev)| ((at - start).as_millis(), prev.seq_no()))
        .collect();
    // Fails at 0 ms, succeeds at 100 ms and asks for the following block at
    // once, which fails and is retried 100 ms later.
    assert_eq!(attempts, vec![(0, 1), (100, 1), (100, 2), (200, 2)]);
}

#[test]
fn expected_failures_are_sampled_in_the_log() {
    let timeout: rtos_block::Error = NodeError::Timeout("next block".to_string()).into();
    let other = error!("{ROUTER_ERROR}");
    assert_eq!(next_master_block_failure_level(1, &timeout), log::Level::Debug);
    assert_eq!(next_master_block_failure_level(127, &timeout), log::Level::Debug);
    assert_eq!(next_master_block_failure_level(128, &timeout), log::Level::Info);
    assert_eq!(next_master_block_failure_level(256, &timeout), log::Level::Info);
    for attempt in [1, 128] {
        assert_eq!(next_master_block_failure_level(attempt, &other), log::Level::Warn);
    }
}

#[tokio::test(start_paused = true)]
async fn timeouts_are_retried_like_other_failures() {
    let engine = RetryEngine::new(vec![Step::Timeout; 5], false);
    let task = tokio::spawn(load_master_blocks_cycle(engine.clone(), mc_id(1)));
    settle().await;
    for _ in 0..4 {
        tokio::time::advance(Duration::from_millis(100)).await;
        settle().await;
    }
    assert_eq!(engine.attempts().len(), 5);
    engine.stop.store(true, Ordering::SeqCst);
    tokio::time::advance(Duration::from_millis(100)).await;
    settle().await;
    task.await.unwrap().unwrap();
}
