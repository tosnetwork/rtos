// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use rtos_api::{
    ton::lite_server::{BlockData, BlockState},
    ton::rpc::lite_server::{GetBlock, GetState},
    WireProfile,
};

#[tokio::test]
async fn target_liteserver_consumer_ready_pending_and_wrong_domain() -> Result<()> {
    let engine = Arc::new(LiteServerTestEngine::new().await);
    let subscriber = LiteServerQuerySubscriber::new_with_profile(
        WireProfile::T0,
        tokio::runtime::Handle::current(),
        engine.clone(),
        16,
        16,
        1,
    )?;
    let id = engine.load_last_applied_mc_block_id()?.unwrap().as_ref().clone();
    let peers = AdnlPeers::with_keys(KeyId::from_data([0; 32]), KeyId::from_data([1; 32]));
    for pending in [false, true] {
        let inner = if pending {
            GetState { id: id.clone() }.into_tl_object()
        } else {
            GetBlock { id: id.clone() }.into_tl_object()
        };
        let bytes = WireProfile::T0.serialize(&inner)?;
        for malformed in [false, true] {
            let data = if malformed {
                let mut b = bytes.clone();
                b.push(7);
                b
            } else {
                WireProfile::Legacy.serialize(&inner)?
            };
            assert!(subscriber
                .try_consume_query(Query { data }.into_tl_object(), &peers)
                .await
                .is_err());
        }
        let result =
            subscriber.try_consume_query(Query { data: bytes }.into_tl_object(), &peers).await?;
        let answer = match result {
            QueryResult::Consumed(QueryAnswer::Ready(answer)) => {
                assert!(!pending);
                answer
            }
            QueryResult::Consumed(QueryAnswer::Pending(handle)) => {
                assert!(pending);
                handle.await??.answer
            }
            _ => panic!("target query was not consumed"),
        };
        let raw = match answer {
            Some(Answer::Raw(raw)) => raw.object,
            _ => panic!("target response must be encoded"),
        };
        assert!(WireProfile::Legacy.deserialize(&raw).is_err());
        let decoded = WireProfile::T0.deserialize(&raw)?;
        if pending {
            assert_eq!(decoded.downcast::<BlockState>().unwrap().id(), &id);
        } else {
            assert_eq!(decoded.downcast::<BlockData>().unwrap().id(), &id);
        }
    }
    Ok(())
}
