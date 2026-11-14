// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use adnl::{
    records::{overlay_public_key, MemberCertificate, MemberFlags, NodeRecord},
    BroadcastCheckResult, OverlayCertificate, OverlayPrivacyRules,
};
use anyhow::{ensure, Context, Result};
use rtos_api::WireProfile;
use serde_json::{json, Value};
use std::collections::BTreeMap;
fn bits(v: &Value, name: &str) -> Result<[u8; 32]> {
    super::bytes(v, name, 32)?.try_into().map_err(|_| anyhow::anyhow!("32byte field required"))
}
fn uint(v: &Value, name: &str) -> Result<u32> {
    Ok(v[name].as_u64().context("u32 required")?.try_into()?)
}
fn int(v: &Value, name: &str) -> Result<i32> {
    Ok(v[name].as_i64().context("i32 required")?.try_into()?)
}
fn boolean(v: &Value, name: &str) -> Result<bool> {
    v[name].as_bool().context("bool required")
}
fn check(v: BroadcastCheckResult) -> &'static str {
    match v {
        BroadcastCheckResult::Forbidden => "forbidden",
        BroadcastCheckResult::NeedCheck => "need_check",
        BroadcastCheckResult::Allowed => "allowed",
    }
}
fn signature(result: Result<()>) -> Result<String> {
    match result {
        Ok(()) => Ok("valid".into()),
        Err(e) => match e.downcast_ref::<adnl::wire_keys::KeyRefusal>() {
            Some(r) => Ok(r.0.into()),
            None => Err(e),
        },
    }
}
fn member(cert: &MemberCertificate, node: [u8; 32]) -> Result<Value> {
    let canonical = hex::encode(WireProfile::T0.serialize(cert.tl())?);
    Ok(if let Some(v) = cert.value() {
        json!({"empty":false,"issued_by":hex::encode(WireProfile::T0.serialize(&v.issued_by)?),"slot":v.slot,"expire_at":v.expire_at,"to_sign":hex::encode(cert.to_sign(node)?.unwrap()),"signature":hex::encode(&v.signature),"signature_check":signature(cert.verify_signature(node))?,"canonical":canonical})
    } else {
        json!({"empty":true,"issued_by":null,"slot":null,"expire_at":cert.expire_at(),"to_sign":null,"signature":null,"signature_check":null,"canonical":canonical})
    })
}
pub(super) fn run(v: &Value) -> Result<Value> {
    Ok(match v["op"].as_str().unwrap_or_default() {
        "overlay_id" => {
            let key = overlay_public_key(&super::bytes(v, "name", 1 << 20)?)?;
            json!({"outcome":"overlay_id","short_id":hex::encode(key.short_id()?),"public_key":hex::encode(key.to_wire()?)})
        }
        "overlay_member_flags" => {
            let f = uint(v, "flags")?;
            json!({"outcome":"member_flags","valid":MemberFlags::valid(f),"receives_regular":MemberFlags::receives_regular(f),"receives_plumtree":MemberFlags::receives_plumtree(f),"public_flags":MemberFlags::public_flags(f,boolean(v,"plumtree_enabled")?,boolean(v,"original_sender")?)})
        }
        "overlay_privacy_rules" => {
            let mut keys = BTreeMap::new();
            let entries =
                v["authorized_keys"].as_array().context("authorized_keys array required")?;
            ensure!(entries.len() <= 1024, "too many authorized keys");
            for e in entries {
                ensure!(
                    keys.insert(bits(e, "key")?, uint(e, "max_size")?).is_none(),
                    "repeated key"
                );
            }
            let rules =
                OverlayPrivacyRules::new(uint(v, "max_unauth_size")?, uint(v, "flags")?, keys);
            json!({"outcome":"privacy_rules","check":check(rules.check_rules(&bits(v,"source")?,uint(v,"size")?,boolean(v,"is_fec")?,boolean(v,"is_any_sender")?)),"max_broadcast_size":rules.max_broadcast_size()})
        }
        "overlay_member_certificate" => {
            let cert = MemberCertificate::from_wire(&super::bytes(v, "certificate", 1 << 20)?)?;
            ensure!(cert.value().is_none() || cert.expire_at()<=1_000_000_000 || cert.expire_at()==i32::MAX,"certificate: expire_at must be at most 1000000000 or 2147483647 (wall-clock verdict)");
            json!({"outcome":"member_certificate","certificate":member(&cert,bits(v,"node")?)?,"expired":cert.is_expired(int(v,"now")? as f64)})
        }
        "overlay_node" => {
            let record = NodeRecord::from_wire(&super::bytes(v, "node", 1 << 20)?)?;
            let n = record.node();
            json!({"outcome":"overlay_node","adnl_short_id":hex::encode(record.short_id()),"overlay":hex::encode(n.overlay.as_slice()),"flags":n.flags as u32,"version":n.version,"to_sign":hex::encode(record.to_sign()?),"signature_check":signature(record.verify_signature())?,"receives_regular":MemberFlags::receives_regular(n.flags as u32),"receives_plumtree":MemberFlags::receives_plumtree(n.flags as u32),"certificate":member(record.certificate(),record.short_id())?,"canonical":hex::encode(record.to_wire()?)})
        }
        "overlay_certificate" => {
            let bytes = super::bytes(v, "certificate", 1 << 20)?;
            match OverlayCertificate::from_wire(&bytes)? {
                None => {
                    json!({"outcome":"certificate","empty":true,"issuer":null,"to_sign":null,"check":null,"canonical":null})
                }
                Some(c) => {
                    let o = bits(v, "overlay_id")?;
                    let n = bits(v, "issued_to")?;
                    json!({"outcome":"certificate","empty":false,"issuer":hex::encode(c.issuer_hash()),"to_sign":hex::encode(c.to_sign(&o,&n)?),"check":check(c.check(&n,&o,int(v,"unix_time")?,uint(v,"size")?,boolean(v,"is_fec")?,false)),"canonical":hex::encode(WireProfile::T0.serialize(&c.to_tl())?)})
                }
            }
        }
        _ => anyhow::bail!("unsupported overlay operation"),
    })
}
