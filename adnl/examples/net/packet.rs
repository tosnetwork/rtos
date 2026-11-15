// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use adnl::{
    packet::{AddressList, NetworkMessage, Packet},
    wire_keys::NetworkPrivateKey,
};
use anyhow::{Context, Result};
use rtos_api::{ton::adnl::Message, WireProfile};
use serde_json::{json, Value};
fn address(list: &AddressList) -> Result<Value> {
    let addresses: Result<Vec<_>> =
        list.addresses().iter().map(|a| Ok(hex::encode(WireProfile::T0.serialize(a)?))).collect();
    let quic: Vec<_> =
        list.quic().iter().map(|a| json!({"ip":a.ip().to_string(),"port":a.port()})).collect();
    Ok(
        json!({"version":list.version(),"reinit_date":list.reinit_date(),"priority":list.priority(),"expire_at":list.expire_at(),
        "empty":list.empty(),"public_only":list.public_only(),"has_reverse":list.has_reverse(),"addresses":addresses?,"quic":quic,
        "serialized_size":list.serialized_size(),"canonical":hex::encode(list.to_wire()?)}),
    )
}
fn message(m: &NetworkMessage) -> Value {
    let mut fields = match m.tl() {
        Message::Adnl_Message_CreateChannel(v) => {
            json!({"type":"create_channel","key":hex::encode(v.key.as_slice()),"date":v.date})
        }
        Message::Adnl_Message_ConfirmChannel(v) => {
            json!({"type":"confirm_channel","key":hex::encode(v.key.as_slice()),"peer_key":hex::encode(v.peer_key.as_slice()),"date":v.date})
        }
        Message::Adnl_Message_Custom(v) => json!({"type":"custom","data":hex::encode(&v.data)}),
        Message::Adnl_Message_Nop => json!({"type":"nop"}),
        Message::Adnl_Message_Reinit(v) => json!({"type":"reinit","date":v.date}),
        Message::Adnl_Message_Query(v) => {
            json!({"type":"query","query_id":hex::encode(v.query_id.as_slice()),"data":hex::encode(&v.query)})
        }
        Message::Adnl_Message_Answer(v) => {
            json!({"type":"answer","query_id":hex::encode(v.query_id.as_slice()),"data":hex::encode(&v.answer)})
        }
        Message::Adnl_Message_Part(v) => {
            json!({"type":"part","hash":hex::encode(v.hash.as_slice()),"total_size":m.part_range().unwrap().0,"offset":m.part_range().unwrap().1,"data":hex::encode(&v.data)})
        }
    };
    fields["size"] = json!(m.serialized_size());
    fields
}
pub(super) fn packet(p: &Packet) -> Result<Value> {
    let signature_check = if p.source().is_some() {
        match p.verify_signature() {
            Ok(()) => json!("valid"),
            Err(e) => json!(e
                .downcast_ref::<adnl::wire_keys::KeyRefusal>()
                .map(|e| e.0)
                .unwrap_or("unclassified")),
        }
    } else {
        Value::Null
    };
    packet_fields(p, signature_check)
}
pub(super) fn packet_fields(p: &Packet, signature_check: Value) -> Result<Value> {
    let from = p.source().map(|k| k.to_wire().map(hex::encode)).transpose()?;
    Ok(
        json!({"flags":p.flags(),"priority":p.priority(),"from":from,"from_short":p.source_short().map(hex::encode),
        "messages":p.messages().iter().map(message).collect::<Vec<_>>(),"address_list":p.address().map(address).transpose()?,
        "priority_address_list":p.priority_address().map(address).transpose()?,"seqno":p.seqno().to_string(),"confirm_seqno":p.confirm_seqno().to_string(),
        "recv_addr_list_version":p.recv_addr_list_version(),"recv_priority_addr_list_version":p.recv_priority_addr_list_version(),
        "reinit_date":p.reinit_date(),"dst_reinit_date":p.dst_reinit_date(),"signature":hex::encode(p.signature()),
        "to_sign":hex::encode(p.to_sign()?),"canonical":hex::encode(p.to_wire()?),"signature_check":signature_check}),
    )
}
pub(super) fn run(v: &Value) -> Result<Value> {
    Ok(match v["op"].as_str().context("op required")? {
        "adnl_message" => {
            let value = NetworkMessage::from_wire(&super::bytes(v, "message", 1 << 20)?)?;
            json!({"outcome":"message","message":message(&value),"canonical":hex::encode(value.to_wire()?)})
        }
        "adnl_address_list" => {
            let value = AddressList::from_wire(&super::bytes(v, "address_list", 1 << 20)?)?;
            json!({"outcome":"address_list","address_list":address(&value)?})
        }
        "adnl_packet" => {
            let value = Packet::from_wire(&super::bytes(v, "contents", 1 << 20)?)?;
            json!({"outcome":"packet","packet":packet(&value)?})
        }
        "adnl_datagram" => {
            let key = NetworkPrivateKey::from_wire(&super::bytes(v, "private_key", 4096)?)
                .map_err(|e| anyhow::anyhow!("invalid local private key: {e}"))?;
            let value = Packet::from_datagram(&key, &super::bytes(v, "datagram", 1 << 20)?)?;
            json!({"outcome":"received","from_short":hex::encode(value.source_short().context("source required")?),"packet":packet(&value)?})
        }
        _ => anyhow::bail!("unsupported packet operation"),
    })
}
