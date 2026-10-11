// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use consensus_common::{
    AsyncCollationRequestPtr, BlockHash, BlockSignaturesVariant, BlockSourceInfo,
    CollationParentHint, PublicKey, Session as _, SessionListener, SessionStats,
    ValidatorBlockCandidateCallback, ValidatorBlockCandidateDecisionCallback,
};
use std::sync::mpsc;
struct Listener;
impl SessionListener for Listener {
    fn on_candidate(
        &self,
        _: BlockSourceInfo,
        _: BlockHash,
        _: BlockPayloadPtr,
        _: BlockPayloadPtr,
        _: ValidatorBlockCandidateDecisionCallback,
    ) {
    }
    fn on_generate_slot(
        &self,
        _: BlockSourceInfo,
        _: AsyncCollationRequestPtr,
        _: CollationParentHint,
        _: ValidatorBlockCandidateCallback,
    ) {
    }
    fn on_block_committed(
        &self,
        _: BlockSourceInfo,
        _: BlockHash,
        _: BlockHash,
        _: BlockPayloadPtr,
        _: BlockSignaturesVariant,
        _: Vec<(PublicKeyHash, BlockPayloadPtr)>,
        _: SessionStats,
    ) {
    }
    fn on_block_skipped(&self, _: u32) {}
    fn get_approved_candidate(
        &self,
        _: PublicKey,
        _: BlockHash,
        _: BlockHash,
        _: BlockHash,
        _: ValidatorBlockCandidateCallback,
    ) {
    }
}
fn actual_session(callback: bool, panic: bool) {
    let path = std::env::temp_dir().join(format!(
        "rtos-session-owned-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&path).unwrap();
    let key: PrivateKey =
        rtos_block::Ed25519KeyOption::<rtos_block::ZeroizingBytes>::generate().unwrap();
    let listener: Arc<dyn SessionListener + Send + Sync> = Arc::new(Listener);
    let options = SessionOptions { use_callback_thread: callback, ..Default::default() };
    let create = || {
        SessionFactory::create_session(
            &options,
            &SessionId::default(),
            vec![SessionNode { adnl_id: key.id().clone(), public_key: key.clone(), weight: 1 }],
            &key,
            path.to_string_lossy().into(),
            "owned".into(),
            false,
            catchain::CatchainFactory::create_dummy_overlay_manager(),
            Arc::downgrade(&listener),
        )
        .unwrap()
    };
    let session = create();
    let implementation = session.as_any().downcast_ref::<SessionImpl>().unwrap();
    let (entered, ready) = mpsc::channel();
    let (release, held) = mpsc::channel();
    let action = move || {
        entered.send(()).unwrap();
        held.recv().unwrap();
        assert!(!panic, "actual validator-session worker panic");
    };
    if callback {
        implementation._session_callbacks_task_queue.post_closure(Box::new(action));
    } else {
        implementation.main_task_queue.post_closure(Box::new(move |_| action()));
    }
    ready.recv_timeout(Duration::from_secs(10)).unwrap();
    let stopping = session.clone();
    let (finished, completion) = mpsc::channel();
    let waiter = std::thread::spawn(move || finished.send(stopping.stop_checked()).unwrap());
    assert!(completion.recv_timeout(Duration::from_millis(30)).is_err());
    assert!(!session.threads_drained());
    release.send(()).unwrap();
    let result = completion.recv_timeout(Duration::from_secs(10)).unwrap();
    waiter.join().unwrap();
    assert!(session.threads_drained());
    if panic {
        let error = result.unwrap_err().to_string();
        assert!(error.contains("actual validator-session worker panic"));
        assert_eq!(session.stop_checked().unwrap_err().to_string(), error);
    } else {
        result.unwrap();
    }
    drop(session);
    let reopened = create();
    reopened.stop_checked().unwrap();
    drop(reopened);
    std::fs::remove_dir_all(path).unwrap();
}
#[test]
fn session_owned_shutdown_joins_actual_main_before_reopen() {
    actual_session(false, false);
}
#[test]
fn session_owned_shutdown_joins_actual_callback_before_reopen() {
    actual_session(true, false);
}
#[test]
fn session_owned_shutdown_retains_main_panic() {
    actual_session(false, true);
}
#[test]
fn session_owned_shutdown_retains_callback_panic_and_joins_main() {
    actual_session(true, true);
}
