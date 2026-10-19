/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
use super::*;

const SERVER_KEY: &str =
    r#"{"type_id":1209251014,"pvt_key":"cJIxGZviebMQWL726DRejqVzRTSXPv/1sO/ab6XOZXk="}"#;

fn client() -> (serde_json::Value, [u8; 32]) {
    let (_, key) = get_key_option_factory().generate_with_json().unwrap();
    let json = serde_json::json!({
        "type_id": 1209251014,
        "pub_key": base64_encode(key.pub_key().unwrap()),
    });
    (json, *key.id().data())
}

fn entry(key: &serde_json::Value, permissions: Option<serde_json::Value>) -> serde_json::Value {
    let mut entry = key.clone();
    if let Some(permissions) = permissions {
        entry["permissions"] = permissions;
    }
    entry
}

fn config(clients: serde_json::Value) -> String {
    serde_json::json!({
        "address": "127.0.0.1:0",
        "server_key": serde_json::from_str::<serde_json::Value>(SERVER_KEY).unwrap(),
        "clients": clients,
    })
    .to_string()
}

fn table(clients: serde_json::Value) -> Result<Arc<ClientPermissions>> {
    let config = AdnlServerConfig::from_json_with_permissions(&config(clients))?;
    assert!(config.is_any_client(), "the handshake admits any key");
    config.client_permissions().ok_or_else(|| error!("no permission table"))
}

#[test]
fn listed_clients_keep_their_bits_by_short_id() {
    let (a, a_id) = client();
    let (b, b_id) = client();
    let (c, c_id) = client();
    let permissions = table(serde_json::json!({ "list": [
        entry(&a, Some(7.into())),
        entry(&b, Some("2".into())),
        entry(&c, None),
    ]}))
    .unwrap();
    assert_eq!(permissions.get(&a_id), Some(&7));
    assert_eq!(permissions.get(&b_id), Some(&2), "a decimal string is accepted");
    assert_eq!(permissions.get(&c_id), None, "an absent value means no permissions");
    assert_eq!(permissions.len(), 2);
}

#[test]
fn signed_values_are_bit_sets() {
    let (a, a_id) = client();
    let (b, b_id) = client();
    let permissions = table(serde_json::json!({ "list": [
        entry(&a, Some((-1).into())),
        entry(&b, Some(0x7fffffff.into())),
    ]}))
    .unwrap();
    assert_eq!(permissions.get(&a_id), Some(&u32::MAX));
    assert_eq!(permissions.get(&b_id), Some(&0x7fffffff));
    let (c, _) = client();
    assert!(table(serde_json::json!({ "list": [entry(&c, Some(4294967296i64.into()))] })).is_err());
    assert!(table(serde_json::json!({ "list": [entry(&c, Some("x".into()))] })).is_err());
    assert!(table(serde_json::json!({ "list": [entry(&c, Some(1.5.into()))] })).is_err());
}

#[test]
fn duplicates_apply_in_order() {
    let (a, a_id) = client();
    let (b, b_id) = client();
    let permissions = table(serde_json::json!({ "list": [
        entry(&a, Some(1.into())),
        entry(&b, Some(7.into())),
        entry(&a, Some(6.into())),
        entry(&b, Some(0.into())),
    ]}))
    .unwrap();
    assert_eq!(permissions.get(&a_id), Some(&6), "a later value replaces an earlier one");
    assert_eq!(permissions.get(&b_id), None, "zero removes the client");
    let permissions = table(serde_json::json!({ "list": [
        entry(&b, Some(0.into())),
        entry(&b, Some(2.into())),
    ]}))
    .unwrap();
    assert_eq!(permissions.get(&b_id), Some(&2), "a removed client can be listed again");
}

#[test]
fn any_lists_no_client() {
    assert!(table(serde_json::json!("any")).unwrap().is_empty());
    assert!(table(serde_json::json!({ "list": [] })).unwrap().is_empty());
}

#[test]
fn handshake_servers_keep_their_allowlist() {
    let (a, _) = client();
    let listed = config(serde_json::json!({ "list": [entry(&a, Some(7.into()))] }));
    let server = AdnlServerConfig::from_json(&listed).unwrap();
    assert!(!server.is_any_client());
    assert!(server.client_permissions().is_none());
    let duplicated = config(serde_json::json!({ "list": [entry(&a, None), entry(&a, None)] }));
    assert!(AdnlServerConfig::from_json(&duplicated).is_err());
}

#[test]
fn permissions_round_trip_through_json() {
    let (a, _) = client();
    let key: KeyOptionJson = serde_json::from_value(a.clone()).unwrap();
    let server_key: KeyOptionJson = serde_json::from_str(SERVER_KEY).unwrap();
    let json = AdnlServerConfigJson::with_client_permissions(
        "127.0.0.1:0".to_string(),
        server_key.clone(),
        vec![(key.clone(), 0x7fffffff)],
        None,
    );
    let text = serde_json::to_value(&json).unwrap();
    assert_eq!(text["clients"]["list"][0]["permissions"], 0x7fffffff);
    assert_eq!(text["clients"]["list"][0]["pub_key"], a["pub_key"]);
    let plain = AdnlServerConfigJson::with_params(
        "127.0.0.1:0".to_string(),
        server_key,
        Some(vec![key]),
        None,
    );
    let text = serde_json::to_value(&plain).unwrap();
    assert!(text["clients"]["list"][0].get("permissions").is_none());
}
