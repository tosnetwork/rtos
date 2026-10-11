// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use crate::*;
use std::{path::PathBuf, sync::Arc};
pub struct Listener;
impl ReceiverListener for Listener {
    fn on_started(&self) {}
    fn on_new_block(
        &self,
        _: usize,
        _: usize,
        _: BlockHash,
        _: BlockHeight,
        _: BlockHash,
        _: Vec<BlockHash>,
        _: Vec<BlockHeight>,
        _: BlockPayloadPtr,
    ) {
    }
    fn on_broadcast(&self, _: PublicKeyHash, _: BlockPayloadPtr) {}
    fn on_blame(&self, _: usize) {}
    fn on_custom_query(&self, _: PublicKeyHash, _: BlockPayloadPtr, _: QueryResponseCallback) {}
    fn on_set_time(&self, _: std::time::SystemTime) {}
}
impl CatchainListener for Listener {
    fn preprocess_block(&self, _: BlockPtr) {}
    fn process_blocks(&self, _: Vec<BlockPtr>) {}
    fn finished_processing(&self) {}
    fn started(&self) {}
    fn process_broadcast(&self, _: PublicKeyHash, _: BlockPayloadPtr) {}
    fn process_query(&self, _: PublicKeyHash, _: BlockPayloadPtr, _: QueryResponseCallback) {}
    fn set_time(&self, _: std::time::SystemTime) {}
}
pub fn fixture() -> (PathBuf, PrivateKey, Vec<CatchainNode>) {
    let path = std::env::temp_dir().join(format!(
        "rtos-classical-owned-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&path).unwrap();
    let key = secrets_vault::vault_block::get_key_option_factory().generate().unwrap();
    let nodes = vec![CatchainNode { public_key: key.clone().into(), adnl_id: key.id().clone() }];
    (path, key, nodes)
}
pub fn receiver_listener() -> Arc<dyn ReceiverListener + Send + Sync> {
    Arc::new(Listener)
}
pub fn catchain_listener() -> Arc<dyn CatchainListener + Send + Sync> {
    Arc::new(Listener)
}
