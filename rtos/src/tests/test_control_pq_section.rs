/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The post-quantum consensus section of the node configuration survives
//! every write the control interface causes, and a restart, exactly as
//! written; a write that would drop or change it is refused.

use super::{
    key_tests::{ask, ask_object, Node},
    *,
};
use crate::config::TonNodeConfig;
use rtos_api::ton::{
    engine::validator::KeyHash as KeyHashBoxed,
    pk::privatekey::Ed25519 as Ed25519Private,
    rpc::engine::validator::{
        AddAdnlId, AddValidatorAdnlAddress, AddValidatorPermanentKey, AddValidatorTempKey,
        DelAdnlId, DelValidatorAdnlAddress, DelValidatorPermanentKey, DelValidatorTempKey,
        GenerateKeyPair, ImportPrivateKey,
    },
    PrivateKey,
};
use rtos_block::UInt256;

/// A section in the form the reference node writes, with fields in an order
/// a re-encoder would not choose, a window written as a string, and a key
/// file path with characters that need escaping.
const SECTION: &str = r#"{
    "keys": [
        { "expire_at": "2000000000", "valid_from": 1000, "consensus_key_file": "keys/a \"b\"", "@type": "engine.validator.pqConsensusKey" }
    ],
    "validator_id": "ESIzRFVmd4iZqrvM3e7/ABEiM0RVZneImaq7zN3u/wA=",
    "@type": "engine.validator.pqConsensus",
    "consensus_key_file": ""
}"#;

fn section_of(saved: &serde_json::Value) -> Option<String> {
    saved.get("pq_consensus").map(|section| serde_json::to_string(section).unwrap())
}

fn expected() -> String {
    serde_json::to_string(&serde_json::from_str::<serde_json::Value>(SECTION).unwrap()).unwrap()
}

async fn generate(node: &Node) -> [u8; 32] {
    let answer = ask_object(node, 1, GenerateKeyPair::default()).await.unwrap();
    answer.downcast::<KeyHashBoxed>().unwrap().only().key_hash.inner()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_section_survives_every_control_write_and_a_restart() {
    let extra = serde_json::json!({ "pq_consensus": serde_json::from_str::<serde_json::Value>(SECTION).unwrap() });
    let node = Node::start_with(true, extra).await;
    assert_eq!(section_of(&node.saved()), Some(expected()), "kept when the file is created");
    // Field order as written, not as a re-encoder would sort it.
    let text = std::fs::read_to_string(node.dir.path().join("config.json")).unwrap();
    let at = |needle: &str| text.find(needle).unwrap();
    assert!(at("\"expire_at\": \"2000000000\"") < at("\"valid_from\": 1000"));
    assert!(
        at("\"keys\"") < at("\"validator_id\"")
            && at("\"validator_id\"") < at("\"engine.validator.pqConsensus\"")
    );
    let h = UInt256::with_array;
    // Key generation writes the configuration too.
    let k1 = generate(&node).await;
    let k2 = generate(&node).await;
    let k3 = generate(&node).await;
    assert_eq!(section_of(&node.saved()), Some(expected()), "after key generation");
    let imported = ImportPrivateKey {
        key: PrivateKey::Pk_Ed25519(Ed25519Private { key: UInt256::with_array([0x5a; 32]) }),
    };
    let mut writes = 0;
    macro_rules! write {
        ($bits:expr, $query:expr) => {{
            let reply = ask(&node, $bits, $query).await;
            assert!(reply.is_ok(), "{reply:?}");
            writes += 1;
            assert_eq!(section_of(&node.saved()), Some(expected()), "after write {writes}");
        }};
    }
    write!(1, imported);
    write!(2, AddAdnlId { key_hash: h(k1), category: 0 });
    write!(
        2,
        AddValidatorPermanentKey { key_hash: h(k2), election_date: 1000, ttl: 2_100_000_000 }
    );
    write!(
        2,
        AddValidatorTempKey { permanent_key_hash: h(k2), key_hash: h(k3), ttl: 2_100_000_000 }
    );
    write!(
        2,
        AddValidatorAdnlAddress { permanent_key_hash: h(k2), key_hash: h(k1), ttl: 2_100_000_000 }
    );
    write!(2, DelValidatorTempKey { permanent_key_hash: h(k2), key_hash: h(k3) });
    write!(2, DelValidatorAdnlAddress { permanent_key_hash: h(k2), key_hash: h(k1) });
    write!(2, DelValidatorPermanentKey { key_hash: h(k2) });
    write!(2, DelAdnlId { key_hash: h(k1) });
    node.server.shutdown().await;
    node.handler.stop_and_wait().await.unwrap();

    // After a restart the section is carried again, and still exactly.
    let configs = node.dir.path().to_str().unwrap().to_string();
    let reloaded =
        TonNodeConfig::from_file(&configs, "config.json", None, "default_config.json", None)
            .await
            .unwrap();
    let (handler, context) =
        NodeConfigHandler::create(reloaded, tokio::runtime::Handle::current()).unwrap();
    handler.clone().start_sheduler(context, vec![]).unwrap();
    handler
        .key_command(KeyCommand::AddAdnlId { id: base64_encode(k3), category: 1 })
        .await
        .unwrap();
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(node.dir.path().join("config.json")).unwrap())
            .unwrap();
    assert_eq!(section_of(&saved), Some(expected()));
    let view = handler.control_view().await.unwrap();
    assert!(view.pq_consensus.is_some(), "the projection reads the carried section");
    handler.stop_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_null_section_is_kept_and_an_absent_one_stays_absent() {
    let node = Node::start_with(true, serde_json::json!({ "pq_consensus": null })).await;
    let k1 = generate(&node).await;
    assert!(ask(&node, 2, AddAdnlId { key_hash: UInt256::with_array(k1), category: 0 })
        .await
        .is_ok());
    assert_eq!(node.saved().get("pq_consensus"), Some(&serde_json::Value::Null));
    node.server.shutdown().await;
    node.handler.stop_and_wait().await.unwrap();
    let node = Node::start(true).await;
    let k1 = generate(&node).await;
    assert!(ask(&node, 2, AddAdnlId { key_hash: UInt256::with_array(k1), category: 0 })
        .await
        .is_ok());
    assert!(node.saved().get("pq_consensus").is_none());
    node.server.shutdown().await;
    node.handler.stop_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_write_that_would_change_the_section_on_disk_is_refused() {
    let extra = serde_json::json!({ "pq_consensus": serde_json::from_str::<serde_json::Value>(SECTION).unwrap() });
    let node = Node::start_with(true, extra).await;
    let k1 = generate(&node).await;
    // Another writer changes the section on disk behind the node's back.
    let mut edited = node.saved();
    edited["pq_consensus"]["consensus_key_file"] = "keys/other".into();
    let bytes = serde_json::to_vec_pretty(&edited).unwrap();
    std::fs::write(node.dir.path().join("config.json"), &bytes).unwrap();
    let (code, message) =
        ask(&node, 2, AddAdnlId { key_hash: UInt256::with_array(k1), category: 0 })
            .await
            .unwrap()
            .unwrap();
    assert_eq!(code, 0);
    assert!(message.contains("would drop or change its pq_consensus section"), "{message}");
    assert_eq!(
        std::fs::read(node.dir.path().join("config.json")).unwrap(),
        bytes,
        "nothing written"
    );
    node.server.shutdown().await;
    node.handler.stop_and_wait().await.unwrap();
}
