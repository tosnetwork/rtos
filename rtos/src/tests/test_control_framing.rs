/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! The control-port framing against the reference engine: every case of
//! tests/data/control-surface/cpp-framing.tsv was sent byte for byte to the
//! reference engine's control port (evidence: control-surface/oracle
//! framing), and this server must answer it the same way.

use super::*;
use adnl::common::Answer;
use rtos_api::AnyBoxedSerialize;
use rtos_block::KeyId;

const DATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/tests/data/control-surface/");

/// The reference engine fully parses the body of a function it does not
/// serve; this server refuses such a function as unsupported without
/// decoding a schema it does not have.
const UNSERVED_BODY_NOT_PARSED: &[&str] = &["inner_unhandled_truncated"];

use super::key_tests::StartedEngine;

struct NotStarted;

impl StatusReporter for NotStarted {
    fn get_report(&self) -> u32 {
        0
    }
}

/// A client id for each permission label of the reference probes; `0` is
/// listed with no permissions, `unlisted` is not listed.
fn client_id(label: &str) -> [u8; 32] {
    match label {
        "unlisted" => [0xee; 32],
        bits => [bits.parse::<u8>().unwrap().wrapping_add(1); 32],
    }
}

fn subscriber(started: bool) -> ControlQuerySubscriber {
    let permissions = ["0", "1", "2", "4", "7", "15"]
        .iter()
        .filter(|label| **label != "0")
        .map(|label| (client_id(label), label.parse::<u32>().unwrap()))
        .collect();
    let (config, _) = NodeConfigHandler::create(
        serde_json::from_str("{}").unwrap(),
        tokio::runtime::Handle::current(),
    )
    .unwrap();
    ControlQuerySubscriber::new(
        if started {
            DataSource::Engine(StartedEngine::new())
        } else {
            DataSource::Status(Arc::new(NotStarted))
        },
        config.clone(),
        config,
        None,
        Arc::new(permissions),
    )
    .unwrap()
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Error(i32, String),
    Answer(String),
    Lite,
    Closed,
}

async fn outcome(subscriber: &ControlQuerySubscriber, client: &str, query: &[u8]) -> Outcome {
    let peers =
        AdnlPeers::with_keys(KeyId::from_data([9; 32]), KeyId::from_data(client_id(client)));
    match subscriber.consume_raw(query, &peers).await {
        Err(_) => Outcome::Closed,
        Ok(None) => Outcome::Lite,
        Ok(Some(QueryResult::Consumed(QueryAnswer::Ready(Some(Answer::Object(object)))))) => {
            let object = object.object;
            match object.downcast::<rtos_api::ton::engine::validator::ControlQueryError>() {
                Ok(error) => {
                    let error = error.only();
                    Outcome::Error(error.code, error.message)
                }
                Err(object) => {
                    let bytes = rtos_api::serialize_boxed(&object).unwrap();
                    Outcome::Answer(hex::encode(&bytes[..4]))
                }
            }
        }
        Ok(Some(_)) => panic!("not a ready reply"),
    }
}

fn reference_cases() -> Vec<(String, String, Vec<u8>, Outcome)> {
    let text = std::fs::read_to_string(format!("{DATA}cpp-framing.tsv")).unwrap();
    text.lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let fields: Vec<&str> = line.splitn(4, '\t').collect();
            let outcome = match fields[3].split_once(' ') {
                Some(("error", rest)) => {
                    let (code, message) = rest.split_once(' ').unwrap();
                    Outcome::Error(code.parse().unwrap(), message.to_string())
                }
                Some(("answer", id)) => Outcome::Answer(id.to_string()),
                _ if fields[3] == "lite" => Outcome::Lite,
                _ => Outcome::Closed,
            };
            (fields[0].to_string(), fields[1].to_string(), hex::decode(fields[2]).unwrap(), outcome)
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn control_port_framing_answers_as_the_reference_engine() {
    let subscriber = subscriber(true);
    let cases = reference_cases();
    assert!(cases.len() >= 40);
    for (name, client, query, expected) in cases {
        let got = outcome(&subscriber, &client, &query).await;
        if UNSERVED_BODY_NOT_PARSED.contains(&name.as_str()) {
            assert_eq!(got, Outcome::Error(621, "query not supported".into()), "{name}");
            continue;
        }
        assert_eq!(got, expected, "{name}");
    }
}

/// liteServer.getTime on the control port, in the network wire profile.
fn lite_get_time() -> adnl::common::TaggedTlObject {
    let data =
        rtos_api::WireProfile::T0.serialize(&rtos_api::ton::rpc::lite_server::GetTime).unwrap();
    rtos_api::ton::rpc::lite_server::Query { data: data.into() }.into_tl_object().into()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lite_query_is_answered_on_the_lite_path_once_started() {
    let node = super::key_tests::Node::start(true).await;
    let mut client = node.connect(1).await;
    let answer = client.query_raw(&lite_get_time(), rtos_api::WireProfile::Legacy).await.unwrap();
    let answer = rtos_api::WireProfile::T0.deserialize(&answer).unwrap();
    assert!(answer.downcast::<rtos_api::ton::lite_server::CurrentTime>().is_ok());
    client.shutdown().await.unwrap();
    node.server.shutdown().await;
    node.handler.stop_and_wait().await.unwrap();
}

/// The lite path reads the network wire profile: a function whose id
/// differs between the profiles is parsed and reaches its handler.
#[tokio::test(flavor = "multi_thread")]
async fn the_lite_path_reads_the_network_wire_profile() {
    let function = rtos_api::ton::rpc::lite_server::GetBlockHeader {
        id: rtos_block::BlockIdExt::default(),
        mode: 0,
    };
    let data = rtos_api::WireProfile::T0.serialize(&function).unwrap();
    assert_ne!(data, rtos_api::WireProfile::Legacy.serialize(&function).unwrap());
    let query: adnl::common::TaggedTlObject =
        rtos_api::ton::rpc::lite_server::Query { data: data.into() }.into_tl_object().into();
    let node = super::key_tests::Node::start(true).await;
    let mut client = node.connect(1).await;
    let answer = client.query_raw(&query, rtos_api::WireProfile::Legacy).await.unwrap();
    let answer = rtos_api::WireProfile::T0.deserialize(&answer).unwrap();
    let error = answer.downcast::<rtos_api::ton::lite_server::Error>().unwrap().only();
    assert!(error.message.contains("invalid BlockIdExt for getBlockHeader"), "{}", error.message);
    client.shutdown().await.unwrap();
    node.server.shutdown().await;
    node.handler.stop_and_wait().await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lite_query_before_start_gets_no_reply_and_the_connection_closes() {
    let node = super::key_tests::Node::start(false).await;
    let mut client = node.connect(15).await;
    assert!(client.query_raw(&lite_get_time(), rtos_api::WireProfile::Legacy).await.is_err());
    node.server.shutdown().await;
    node.handler.stop_and_wait().await.unwrap();
}

#[test]
fn the_reference_function_set_is_sorted_and_holds_every_served_function() {
    assert!(REFERENCE_FUNCTIONS.windows(2).all(|pair| pair[0] < pair[1]));
    use rtos_api::Constructor;
    for id in [
        rtos_api::ton::rpc::engine::validator::GetTime::constructor_const(),
        rtos_api::ton::rpc::engine::validator::Sign::constructor_const(),
        rtos_api::ton::rpc::engine::validator::AddAdnlId::constructor_const(),
    ] {
        assert!(REFERENCE_FUNCTIONS.binary_search(&id).is_ok());
        assert!(frame::served_fields(id).is_some());
    }
}
