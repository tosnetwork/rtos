// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use adnl::{
    channel::Channel,
    packet::Refusal,
    wire_keys::{KeyRefusal, NetworkPrivateKey, NetworkPublicKey},
};
use anyhow::{ensure, Result};
use rtos_api::{ton, Constructor, IntoBoxed, WireProfile};
use rtos_block::ZeroizingBytes;
use serde_json::{json, Value};
fn bits(v: &Value, name: &str) -> Result<[u8; 32]> {
    Ok(super::bytes(v, name, 32)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("32byte field required"))?)
}
pub(super) fn run(v: &Value) -> Result<Value> {
    let seed = ZeroizingBytes::new(super::bytes(v, "local_channel_key", 32)?);
    ensure!(seed.len() == 32, "32byte local seed required");
    let mut local_wire = ZeroizingBytes::new(
        ton::pk::privatekey::Ed25519::constructor_const().to_le_bytes().to_vec(),
    );
    local_wire.extend_from_slice(&seed);
    let local = NetworkPrivateKey::from_wire(&local_wire)?;
    let public =
        ton::pub_::publickey::Ed25519 { key: bits(v, "peer_channel_key")?.into() }.into_boxed();
    let peer = NetworkPublicKey::from_wire(&WireProfile::T0.serialize(&public)?)?;
    let channel = Channel::from_keys(&local, &peer, bits(v, "local_id")?, bits(v, "peer_id")?)?;
    let received = if v.get("datagram").is_some() {
        match channel.receive(&super::bytes(v, "datagram", 1 << 20)?) {
            Ok(p) => {
                let p = super::packet::packet_fields(&p, Value::Null)?;
                json!({"packet":p})
            }
            Err(e) => {
                json!({"reason":e.downcast_ref::<Refusal>().map(|e|e.0).or_else(||e.downcast_ref::<KeyRefusal>().map(|e|e.0)).unwrap_or("unclassified")})
            }
        }
    } else {
        Value::Null
    };
    let sent = if v.get("send").is_some() {
        Some(hex::encode(channel.send(&super::bytes(v, "send", 1 << 20)?)))
    } else {
        None
    };
    Ok(
        json!({"outcome":"channel","in_id":hex::encode(channel.in_id()),"out_id":hex::encode(channel.out_id()),"received":received,"sent":sent}),
    )
}
