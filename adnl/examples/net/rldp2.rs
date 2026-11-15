// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use adnl::rldp2::{budget, FecHelper, DEFAULT_MTU, PART_SIZE, SYMBOL_SIZE};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
pub(super) fn decimal(v: &Value) -> Result<u64> {
    let text = v.as_str().context("decimal string required")?;
    ensure!(
        !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()),
        "decimal string required"
    );
    Ok(text.parse()?)
}
pub(super) fn run(v: &Value) -> Result<Value> {
    if v["op"] == "rldp2_fec_helper" {
        let count = u32::try_from(v["symbols_count"].as_u64().context("uint32 required")?)?;
        let received =
            u32::try_from(v["received_symbols_count"].as_u64().context("uint32 required")?)?;
        ensure!(count <= 1 << 30 && received <= 1 << 30, "counts at most2^30");
        let helper = FecHelper { symbols_count: count, received_symbols_count: received };
        return Ok(
            json!({"outcome":"fec_helper","fec_symbols_count":helper.target().context("FEC counters overflow")?,
            "left_fec_symbols_count":helper.remaining().context("FEC counters overflow")?}),
        );
    }
    if v["op"] == "rldp2_send" {
        return send(v);
    }
    if v["op"] == "rldp2_receive" {
        return receive(v);
    }
    let data = decimal(&v["data_size"])?;
    let symbol = decimal(&v["symbol_size"])?;
    let count = decimal(&v["symbols_count"])?;
    Ok(
        json!({"outcome":"budget","reservation_bytes":budget::decoder_reservation_bytes(data,symbol,count).map(|x|x.to_string()),
        "solver_bytes":budget::solver_working_bytes(symbol,count).map(|x|x.to_string()),
        "part_size":PART_SIZE,"symbol_size":SYMBOL_SIZE,"default_mtu":DEFAULT_MTU}),
    )
}

fn receive(v: &Value) -> Result<Value> {
    use adnl::rldp2::connection::Connection;
    use rtos_api::{ton::rldp2::MessagePart, WireProfile};
    let packets = v["packets"].as_array().context("packets array required")?;
    ensure!(packets.len() <= 4096, "too many packets");
    let mut raw = Vec::new();
    let mut total = 0usize;
    for value in packets {
        let bytes = super::bytes(&json!({"packet":value}), "packet", 8 << 20)?;
        total = total.checked_add(bytes.len()).context("packet size overflow")?;
        ensure!(total <= 8 << 20, "packets at most8MiB");
        raw.push(bytes);
    }
    let budget = if let Some(value) = v.get("budget") {
        budget::InboundBudget::new(decimal(&value["max_decoders"])?, decimal(&value["max_bytes"])?)
    } else {
        budget::InboundBudget::new(budget::MAX_DECODERS, budget::MAX_BYTES)
    };
    let mut connection = Connection::with_budget([0; 32], budget);
    if let Some(mtu) = v.get("default_mtu") {
        connection.set_default_mtu(decimal(mtu)?);
    }
    if let Some(requests) = v.get("requests") {
        let requests = requests.as_array().context("requests array required")?;
        ensure!(requests.len() <= 256, "too many requests");
        for request in requests {
            let id: [u8; 32] = super::bytes(request, "transfer_id", 32)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("32byte id required"))?;
            ensure!(
                connection.set_receive_limits(
                    id,
                    connection.now() + 3600.0,
                    decimal(&request["max_size"])?
                ),
                "requests refused"
            );
        }
    }
    let mut events = Vec::new();
    for (index, packet) in raw.iter().enumerate() {
        connection.receive_raw(packet);
        let output = connection.run()?;
        let mut complete = Vec::new();
        for packet in output.packets {
            let value: MessagePart =
                WireProfile::T0.deserialize_value_bounded(&packet, packet.len())?;
            if matches!(value, MessagePart::Rldp2_Complete(_)) {
                complete.push(hex::encode(packet));
            }
        }
        if output.received.is_empty() && output.parts.is_empty() && complete.is_empty() {
            continue;
        }
        let received:Vec<_>=output.received.into_iter().map(|(id,data)|match data {
            Ok(data)=>json!({"transfer_id":hex::encode(id),"reason":null,"size":data.len(),
                "data_sha256":hex::encode(rtos_block::sha256_digest(&data)),"data":if data.len()<=4096 {Some(hex::encode(data))} else {None}}),
            Err(reason)=>json!({"transfer_id":hex::encode(id),"reason":reason.0,"size":null,"data_sha256":null,"data":null})
        }).collect();
        let parts:Vec<_>=output.parts.into_iter().map(|(id,part,size)|json!({"transfer_id":hex::encode(id),"part":part,"decoded_bytes":size})).collect();
        events.push(json!({"index":index,"received":received,"parts":parts,"complete":complete}));
    }
    Ok(
        json!({"outcome":"transfers","events":events,"inbound_transfers":connection.inbound_transfer_count(),"completed_transfers":connection.completed_transfer_count()}),
    )
}

fn send(v: &Value) -> Result<Value> {
    use adnl::rldp2::connection::Connection;
    use rtos_api::{ton::rldp2::MessagePart, WireProfile};
    let id: [u8; 32] = super::bytes(v, "transfer_id", 32)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("32byte id required"))?;
    ensure!(id != [0; 32], "nonzero transfer id required");
    let data = super::bytes(v, "data", 4 << 20)?;
    ensure!(!data.is_empty(), "at least one data byte required");
    let mut connection = Connection::new([0; 32]);
    connection.send(id, data, None)?;
    let output = connection.run()?;
    let mut packets = Vec::new();
    for raw in output.packets {
        let parsed: MessagePart = WireProfile::T0.deserialize_value_bounded(&raw, raw.len())?;
        let entry = if let MessagePart::Rldp2_MessagePart(part) = parsed {
            let part = part.0;
            let fec_wire = WireProfile::T0.serialize(&part.fec_type)?;
            let constructor = i32::from_le_bytes(fec_wire[..4].try_into()?);
            json!({"type":"part","fec_type":constructor,"part":part.part,"total_size":part.total_size.to_string(),"seqno":part.seqno,
                "fec":{"data_size":part.fec_type.data_size(),"symbol_size":part.fec_type.symbol_size(),"symbols_count":part.fec_type.symbols_count()},
                "symbol_sha256":hex::encode(rtos_block::sha256_digest(&part.data)),"sha256":hex::encode(rtos_block::sha256_digest(&raw))})
        } else {
            json!({"type":"other","sha256":hex::encode(rtos_block::sha256_digest(&raw))})
        };
        packets.push(entry);
    }
    Ok(
        json!({"outcome":"sent","packets":packets,"outbound_transfers":connection.outbound_transfer_count()}),
    )
}
