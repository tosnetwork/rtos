// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Explicit-input network adapter. Native APIs produce effects, never fixture expectations.
use adnl::wire_keys::{
    decode_adnl_id, encode_adnl_id, KeyRefusal, NetworkPrivateKey, NetworkPublicKey,
};
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::io::{self, BufRead, Read, Write};
#[path = "net/fec.rs"]
mod fec;
#[path = "net/packet.rs"]
mod packet;
#[path = "net/preauth.rs"]
mod preauth;
#[path = "net/rldp2.rs"]
mod rldp2;
fn bytes(v: &Value, name: &str, max: usize) -> Result<Vec<u8>> {
    let s = v[name].as_str().context("hex bytes required")?;
    ensure!(
        s.len() % 2 == 0
            && s.len() / 2 <= max
            && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "bounded lowercase hex required"
    );
    Ok(hex::decode(s)?)
}
fn run(v: &Value) -> Result<Value> {
    let op = v["op"].as_str().context("op required")?;
    if matches!(op, "rldp2_fec_helper" | "rldp2_budget" | "rldp2_receive" | "rldp2_send") {
        return rldp2::run(v);
    }
    if matches!(op, "adnl_message" | "adnl_address_list" | "adnl_packet" | "adnl_datagram") {
        return packet::run(v);
    }
    if matches!(op, "preauth_source" | "preauth_gate") {
        return preauth::run(v);
    }
    if matches!(op, "fec_type" | "fec_encode" | "fec_decode") {
        return fec::run(v);
    }
    if op == "adnl_id" {
        ensure!(v.get("id").is_some() != v.get("text").is_some(), "one identity form required");
        let id: [u8; 32] = if v.get("id").is_some() {
            bytes(v, "id", 32)?.try_into().map_err(|_| anyhow::anyhow!("32byte id required"))?
        } else {
            let text = v["text"].as_str().context("identity text required")?;
            ensure!(text.len() <= 256, "identity too long");
            decode_adnl_id(text)?
        };
        return Ok(json!({"outcome":"adnl_id","id":hex::encode(id),"text":encode_adnl_id(&id)}));
    }
    let public = || NetworkPublicKey::from_wire(&bytes(v, "public_key", 4096)?);
    let private = || -> Result<NetworkPrivateKey> {
        NetworkPrivateKey::from_wire(&bytes(v, "private_key", 4096)?)
            .map_err(|e| anyhow::anyhow!("invalid local private key: {e}"))
    };
    Ok(match op {
        "public_key" => {
            let key = public()?;
            let wire = key.to_wire()?;
            json!({"outcome":"public_key","key_type":key.kind(),"short_id":hex::encode(key.short_id()?),"serialized":hex::encode(&wire),"serialized_size":key.serialized_size_estimate(),"adnl_id_text":key.adnl_id_text()?})
        }
        "private_key" => {
            let key = private()?;
            let public = key.public_key()?;
            json!({"outcome":"private_key","key_type":key.kind(),"public_key":hex::encode(public.to_wire()?),"short_id":hex::encode(public.short_id()?)})
        }
        "sign" => {
            let key = private()?;
            json!({"outcome":"signature","signature":hex::encode(key.sign(&bytes(v,"message",1<<20)?)?)})
        }
        "verify" => {
            let message = bytes(v, "message", 1 << 20)?;
            let signature = bytes(v, "signature", 4096)?;
            public()?.verify(&message, &signature)?;
            json!({"outcome":"verified"})
        }
        "encrypt" => {
            let data = bytes(v, "data", 1 << 20)?;
            json!({"outcome":"ciphertext","ciphertext":hex::encode(public()?.encrypt_deterministic(&data)?)})
        }
        "decrypt" => {
            let key = private()?;
            json!({"outcome":"plaintext","plaintext":hex::encode(key.decrypt(&bytes(v,"ciphertext",1<<20)?)?)})
        }
        "shared_secret" => {
            let key = private()?;
            let secret = key.shared_secret(&public()?)?;
            let locked = secret.lock()?;
            json!({"outcome":"secret","secret":hex::encode(locked.as_ref())})
        }
        _ => bail!("unsupported net operation"),
    })
}
fn main() -> Result<()> {
    let harness = std::env::args().nth(1).unwrap_or_default();
    if harness == "--info" {
        println!("{}", json!({"harnesses":["net"]}));
        return Ok(());
    }
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut line = String::new();
        let n = input.by_ref().take((96 << 20) + 2).read_line(&mut line)?;
        if n == 0 {
            break;
        }
        let result = (|| -> Result<Value> {
            ensure!(n <= 96 << 20, "context too large");
            ensure!(harness == "net", "unsupported harness");
            run(&serde_json::from_str(&line)?)
        })();
        let effect = result.unwrap_or_else(|e| {
            let reason = e
                .downcast_ref::<KeyRefusal>()
                .map(|code| code.0)
                .or_else(|| e.downcast_ref::<adnl::fec::Refusal>().map(|code| code.0))
                .or_else(|| e.downcast_ref::<adnl::packet::Refusal>().map(|code| code.0));
            match reason {
                Some(code) => json!({"outcome":"refused","reason":code}),
                None => json!({"harness_error":e.to_string()}),
            }
        });
        serde_json::to_writer(&mut output, &effect)?;
        writeln!(output)?;
        output.flush()?;
        ensure!(n <= 96 << 20, "context too large");
    }
    Ok(())
}
