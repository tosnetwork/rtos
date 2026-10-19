// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use adnl::PublicBroadcastCheck;
use rtos_api::{
    ton::ton_node::{broadcast::ExternalMessageBroadcast, externalmessage::ExternalMessage},
    IntoBoxed,
};
use rtos_block::{
    ExternalInboundMessageHeader, Message, MsgAddressExt, MsgAddressInt, Serializable, SliceData,
};
use std::sync::atomic::AtomicUsize;

#[derive(Default)]
struct RecordingEngine {
    unsynced: AtomicBool,
    processed: AtomicUsize,
}

#[async_trait::async_trait]
impl EngineOperations for RecordingEngine {
    async fn check_sync(&self) -> Result<bool> {
        Ok(!self.unsynced.load(Ordering::SeqCst))
    }
    async fn process_ext_msg_broadcast(
        &self,
        _broadcast: ExternalMessageBroadcast,
        _src: Arc<KeyId>,
    ) {
        self.processed.fetch_add(1, Ordering::SeqCst);
    }
}

fn external_message(salt: u8) -> Vec<u8> {
    let mut header = ExternalInboundMessageHeader::default();
    header.src = MsgAddressExt::with_extern(SliceData::from_raw(vec![salt], 8)).unwrap();
    header.dst = MsgAddressInt::with_standart(None, 0, [7; 32].into()).unwrap();
    let cell = Message::with_ext_in_header(header).serialize().unwrap();
    rtos_block::write_boc(&cell).unwrap()
}

fn wire(data: &[u8]) -> Vec<u8> {
    rtos_api::WireProfile::T0
        .serialize(
            &ExternalMessageBroadcast { message: ExternalMessage { data: data.to_vec() } }
                .into_boxed(),
        )
        .unwrap()
}

struct Setup {
    engine: Arc<RecordingEngine>,
    disabled: Arc<AtomicBool>,
    active: Arc<AtomicBool>,
    messages: Arc<ShardExtMessages>,
    check: ShardExtMessageCheck,
}

fn setup() -> Setup {
    let engine = Arc::new(RecordingEngine::default());
    let disabled = Arc::new(AtomicBool::new(false));
    let active = Arc::new(AtomicBool::new(true));
    let messages = ShardExtMessages::new(engine.clone(), disabled.clone());
    let flag = active.clone();
    let check = ShardExtMessageCheck::new(
        messages.clone(),
        Box::new(move || flag.load(Ordering::SeqCst)),
        rtos_api::WireProfile::T0,
    );
    Setup { engine, disabled, active, messages, check }
}

fn peer() -> Arc<KeyId> {
    KeyId::from_data([3; 32])
}

#[tokio::test]
async fn duplicates_are_refused_until_the_bulk_clear() {
    let s = setup();
    let data = wire(&external_message(1));
    s.check.check_broadcast(&peer(), &data).await.unwrap();
    assert!(s.check.check_broadcast(&peer(), &data).await.is_err(), "same payload in window");
    assert_eq!(s.engine.processed.load(Ordering::SeqCst), 1);
    s.messages.age_hashes_for_test(EXT_MESSAGE_HASHES_LIFETIME);
    s.check.check_broadcast(&peer(), &data).await.unwrap();
    assert_eq!(s.engine.processed.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn own_messages_are_approved_without_processing() {
    let s = setup();
    let message = external_message(2);
    assert!(s.messages.admit_send(&message).unwrap());
    s.check.check_broadcast(&peer(), &wire(&message)).await.unwrap();
    assert_eq!(s.engine.processed.load(Ordering::SeqCst), 0);
    // Its echo is a duplicate, and a processed payload is not sent again.
    assert!(s.check.check_broadcast(&peer(), &wire(&message)).await.is_err());
    assert!(!s.messages.admit_send(&message).unwrap());
}

#[tokio::test]
async fn received_messages_are_not_sent_again() {
    let s = setup();
    let message = external_message(3);
    s.check.check_broadcast(&peer(), &wire(&message)).await.unwrap();
    assert!(!s.messages.admit_send(&message).unwrap());
}

#[tokio::test]
async fn inactive_shard_refuses_without_recording() {
    let s = setup();
    let data = wire(&external_message(4));
    s.active.store(false, Ordering::SeqCst);
    assert!(s.check.check_broadcast(&peer(), &data).await.is_err());
    s.active.store(true, Ordering::SeqCst);
    s.check.check_broadcast(&peer(), &data).await.unwrap();
}

#[tokio::test]
async fn disabled_rebroadcast_still_processes_locally() {
    let s = setup();
    s.disabled.store(true, Ordering::SeqCst);
    let message = external_message(5);
    assert!(s.check.check_broadcast(&peer(), &wire(&message)).await.is_err());
    assert_eq!(s.engine.processed.load(Ordering::SeqCst), 1, "processed although not relayed");
    assert!(!s.messages.admit_send(&external_message(6)).unwrap(), "nothing is sent");
}

#[tokio::test]
async fn refused_payload_is_recorded_before_admission() {
    let s = setup();
    // Structurally invalid message: refused, but its hash is recorded.
    let bad = wire(b"not a message");
    assert!(s.check.check_broadcast(&peer(), &bad).await.is_err());
    let error = s.check.check_broadcast(&peer(), &bad).await.unwrap_err().to_string();
    assert!(error.contains("duplicate"), "{error}");
    // Same for a node that is not synced.
    s.engine.unsynced.store(true, Ordering::SeqCst);
    let data = wire(&external_message(7));
    assert!(s.check.check_broadcast(&peer(), &data).await.is_err());
    s.engine.unsynced.store(false, Ordering::SeqCst);
    assert!(s
        .check
        .check_broadcast(&peer(), &data)
        .await
        .unwrap_err()
        .to_string()
        .contains("duplicate"));
    assert_eq!(s.engine.processed.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn only_external_message_broadcasts_are_checked() {
    let s = setup();
    let other = rtos_api::WireProfile::T0
        .serialize(
            &rtos_api::ton::ton_node::broadcast::IhrMessageBroadcast {
                message: rtos_api::ton::ton_node::ihrmessage::IhrMessage { data: vec![1, 2, 3] },
            }
            .into_boxed(),
        )
        .unwrap();
    assert!(s.check.check_broadcast(&peer(), &other).await.is_err());
    assert!(s.check.check_broadcast(&peer(), b"garbage").await.is_err());
}
