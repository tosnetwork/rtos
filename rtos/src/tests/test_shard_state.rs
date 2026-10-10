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
use super::*;
use crate::collator_test_bundle::create_engine_allocated;
#[cfg(feature = "telemetry")]
use crate::collator_test_bundle::create_engine_telemetry;
use rtos_block::{write_boc, ShardIdent};

#[test]
fn test_shard_state_deserilaize() {
    let mut ss = ShardStateUnsplit::with_ident(ShardIdent::masterchain());
    let mut zero_state_id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        0,
        UInt256::default(),
        UInt256::default(),
    );
    #[cfg(feature = "telemetry")]
    let telemetry = create_engine_telemetry();
    let allocated = create_engine_allocated();
    let cell = ss.serialize().unwrap();
    let bytes = write_boc(&cell).unwrap();
    let check = ShardStateStuff::deserialize_zerostate(
        zero_state_id.clone(),
        &bytes,
        #[cfg(feature = "telemetry")]
        &telemetry,
        &allocated,
    );
    if check.is_ok() {
        panic!("zero state must be checked")
    }
    zero_state_id.root_hash = cell.repr_hash().clone();
    zero_state_id.file_hash = UInt256::calc_file_hash(&bytes);
    let new_ss = ShardStateStuff::deserialize_zerostate(
        zero_state_id.clone(),
        &bytes,
        #[cfg(feature = "telemetry")]
        &telemetry,
        &allocated,
    )
    .expect("something wrong with zero state checking");
    assert_eq!(new_ss.state().unwrap(), &ss);

    ss.set_seq_no(1);
    let cell = ss.serialize().unwrap();
    let bytes = write_boc(&cell).unwrap();
    let block_id = BlockIdExt {
        shard_id: ShardIdent::masterchain(),
        seq_no: 1,
        root_hash: Default::default(),
        file_hash: Default::default(),
    };
    let new_ss = ShardStateStuff::deserialize_state(
        block_id,
        &bytes,
        #[cfg(feature = "telemetry")]
        &telemetry,
        &allocated,
    )
    .expect("not zero state no need to be checked");
    assert_eq!(new_ss.state().unwrap(), &ss);
}

#[tokio::test]
async fn test_zerostate_cache_is_bound_to_pinned_identity() {
    let ss = ShardStateUnsplit::with_ident(ShardIdent::masterchain());
    let bytes = write_boc(&ss.serialize().unwrap()).unwrap();
    let id = BlockIdExt::with_params(
        ShardIdent::masterchain(),
        0,
        ss.serialize().unwrap().repr_hash().clone(),
        UInt256::calc_file_hash(&bytes),
    );
    let make = |id, ss| {
        ShardStateStuff::from_state(
            id,
            ss,
            #[cfg(feature = "telemetry")]
            &create_engine_telemetry(),
            &create_engine_allocated(),
        )
        .unwrap()
    };
    let valid = make(id.clone(), ss.clone());
    valid.verify_zerostate(&id).unwrap();
    for mutation in 0..4 {
        let mut expected = id.clone();
        match mutation {
            0 => expected.seq_no = 1,
            1 => expected.shard_id = ShardIdent::full(0),
            2 => expected.root_hash = UInt256::from([1; 32]),
            3 => expected.file_hash = UInt256::from([2; 32]),
            _ => unreachable!(),
        }
        assert!(valid.verify_zerostate(&expected).is_err());
    }
    let handles = crate::collator_test_bundle::create_block_handle_storage(None).unwrap();
    let handle = handles
        .create_handle(id.clone(), storage::types::BlockMeta::default(), None)
        .unwrap()
        .unwrap();
    handle.set_state();
    for corrupt in [false, true] {
        let mut content = ss.clone();
        if corrupt {
            content.set_global_id(123);
        }
        let engine = ZeroCacheEngine { handle: handle.clone(), state: make(id.clone(), content) };
        let result = crate::boot::download_zerostate(&engine, &id).await;
        if corrupt {
            assert!(result.unwrap_err().to_string().contains("pinned root hash"));
        } else {
            assert_eq!(result.unwrap().id(), &id);
        }
    }
    // Even a matching root must not hide inconsistent embedded metadata from
    // an unchecked in-memory constructor or a corrupt cache.
    for wrong_shard in [false, true] {
        let mut content = ss.clone();
        if wrong_shard {
            content.set_shard(ShardIdent::full(0));
        } else {
            content.set_seq_no(1);
        }
        let mut claimed = id.clone();
        claimed.root_hash = content.serialize().unwrap().repr_hash().clone();
        let state = make(claimed.clone(), content);
        assert!(state
            .verify_zerostate(&claimed)
            .unwrap_err()
            .to_string()
            .contains("header differs"));
    }
}

struct ZeroCacheEngine {
    handle: std::sync::Arc<storage::block_handle_db::BlockHandle>,
    state: std::sync::Arc<ShardStateStuff>,
}

#[async_trait::async_trait]
impl crate::engine_traits::EngineOperations for ZeroCacheEngine {
    fn load_block_handle(
        &self,
        _: &BlockIdExt,
    ) -> Result<Option<std::sync::Arc<storage::block_handle_db::BlockHandle>>> {
        Ok(Some(self.handle.clone()))
    }
    async fn load_state(&self, _: &BlockIdExt) -> Result<std::sync::Arc<ShardStateStuff>> {
        Ok(self.state.clone())
    }
}
