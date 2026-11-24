// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! In-process native overlays. Only their network edge and application are stand-ins.
use adnl::{
    common::{AdnlPeers, Subscriber, TaggedByteSlice},
    node::{AdnlNode, AdnlNodeConfig, AdnlSendMethod},
    records::overlay_public_key,
    BroadcastClock, BroadcastTransportMethod, FixedMemberOverlayOptions, OverlayBroadcastTransport,
    OverlayNode, OverlayParams, OverlayPrivacyRules, OverlayShortId, PlumtreeConfig,
    PlumtreeRefusal, PublicBroadcastCheck,
};
use anyhow::{ensure, Context, Result};
use rtos_api::{ton, Constructor, WireProfile};
use rtos_block::{sha256_digest, Ed25519KeyOption, KeyId, KeyOption, ZeroizingBytes};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, OnceLock, Weak},
};

#[derive(Clone)]
struct Emitted {
    src: [u8; 32],
    dst: [u8; 32],
    data: Vec<u8>,
    method: BroadcastTransportMethod,
}
#[derive(Default)]
struct Record {
    emitted: Vec<Emitted>,
    delivered: Vec<Value>,
    drops: Vec<&'static str>,
}
type Shared = Arc<Mutex<Record>>;
struct Edge(Shared, Vec<[u8; 32]>);
#[async_trait::async_trait]
impl OverlayBroadcastTransport for Edge {
    fn has_peer(&self, local: &[u8; 32], peer: &[u8; 32]) -> bool {
        self.1.contains(local) && self.1.contains(peer)
    }
    async fn send_message(
        &self,
        data: &[u8],
        peers: &AdnlPeers,
        method: BroadcastTransportMethod,
    ) -> Result<()> {
        let mut record = self.0.lock().unwrap();
        ensure!(record.emitted.len() <= 1024, "overlay emission budget exceeded");
        record.emitted.push(Emitted {
            src: *peers.local().data(),
            dst: *peers.other().data(),
            data: data.to_vec(),
            method,
        });
        Ok(())
    }
}
struct Clock(f64);
impl BroadcastClock for Clock {
    fn unix_seconds(&self) -> f64 {
        self.0
    }
}
struct Approve;
#[async_trait::async_trait]
impl PublicBroadcastCheck for Approve {
    async fn check_broadcast(&self, _: &Arc<KeyId>, _: &[u8]) -> Result<()> {
        Ok(())
    }
}
struct Application {
    record: Shared,
    member: usize,
}
#[async_trait::async_trait]
impl Subscriber for Application {
    async fn try_consume_custom(&self, data: &[u8], peers: &AdnlPeers) -> Result<bool> {
        self.record.lock().unwrap().delivered.push(json!({"member":self.member,"kind":"message",
            "from_key":hex::encode(peers.other().data()),"data_sha256":hex::encode(sha256_digest(data)),"extra":""}));
        Ok(true)
    }
}

// The reference also observes peer-check drops through the node's actual log.
static LOG_RECORD: Mutex<Option<Weak<Mutex<Record>>>> = Mutex::new(None);
struct NodeLog;
impl log::Log for NodeLog {
    fn enabled(&self, m: &log::Metadata<'_>) -> bool {
        m.level() <= log::Level::Warn
    }
    fn log(&self, r: &log::Record<'_>) {
        if !self.enabled(r.metadata()) {
            return;
        }
        eprintln!("native node: {}", r.args());
        if r.args().to_string().contains("Error checking peer") {
            if let Some(record) = LOG_RECORD.lock().unwrap().as_ref().and_then(Weak::upgrade) {
                record.lock().unwrap().drops.push("overlay_unknown_source");
            }
        }
    }
    fn flush(&self) {}
}
static LOGGER: NodeLog = NodeLog;
static LOG_INIT: OnceLock<()> = OnceLock::new();

fn uint(v: &Value, name: &str) -> Result<u32> {
    Ok(v[name].as_u64().context("u32 required")?.try_into()?)
}
fn bits(v: &Value, name: &str) -> Result<[u8; 32]> {
    super::bytes(v, name, 32)?.try_into().map_err(|_| anyhow::anyhow!("32 bytes required"))
}
fn message_type(data: &[u8]) -> Result<&'static str> {
    let (_, offset) = WireProfile::T0.deserialize_with_suffix(data)?;
    let value = WireProfile::T0
        .deserialize(&data[offset..])?
        .downcast::<ton::overlay::Broadcast>()
        .map_err(|_| anyhow::anyhow!("non-broadcast emission"))?;
    use ton::overlay::Broadcast::*;
    Ok(match value {
        Overlay_Broadcast(_) => "overlay.broadcast",
        Overlay_BroadcastFec(_) => "overlay.broadcastFec",
        Overlay_BroadcastFecShort(_) => "overlay.broadcastFecShort",
        Overlay_Fec_Received(_) => "overlay.fec.received",
        Overlay_Fec_Completed(_) => "overlay.fec.completed",
        Overlay_BroadcastTwostepSimple(_) => "overlay.broadcastTwostepSimple",
        Overlay_BroadcastTwostepFec(_) => "overlay.broadcastTwostepFec",
        Overlay_BroadcastPlumtreeIHave(_) => "overlay.broadcastPlumtreeIHave",
        Overlay_BroadcastPlumtreeSimple(_) => "overlay.broadcastPlumtreeSimple",
        Overlay_BroadcastPlumtreeFec(_) => "overlay.broadcastPlumtreeFec",
        _ => anyhow::bail!("unsupported emitted broadcast constructor"),
    })
}
fn receive_error(record: &Shared, error: anyhow::Error) -> Result<()> {
    let text = error.to_string();
    if text.to_lowercase().contains("signature") {
        record.lock().unwrap().drops.push("invalid_signature");
    } else if text.to_lowercase().contains("disabled") {
        record.lock().unwrap().drops.push("broadcast_disabled");
    } else {
        ensure!(text == "Broadcast is forbidden", "unclassified native overlay receive: {error}");
    }
    Ok(())
}

pub(super) fn run(v: &Value) -> Result<Value> {
    LOG_INIT.get_or_init(|| {
        log::set_logger(&LOGGER).expect("net adapter logger");
        log::set_max_level(log::LevelFilter::Warn);
    });
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(run_async(v))
}
async fn run_async(v: &Value) -> Result<Value> {
    let now: i32 = v["now"].as_i64().context("unix time required")?.try_into()?;
    ensure!(now > 0, "positive unix time required");
    ensure!(
        matches!(v["mode"].as_str(), Some("simple" | "fec" | "twostep" | "plumtree")),
        "unsupported overlay broadcast mode"
    );
    let members = v["members"].as_array().context("members required")?;
    ensure!((2..=8).contains(&members.len()), "two to eight members required");
    if members.len() != 2 {
        ensure!(
            v["mode"] == "twostep"
                && v.get("inbound").is_none_or(|v| v.as_array().is_some_and(Vec::is_empty))
                && v["broadcast"]["fec"].as_bool() == Some(true)
                && uint(&v["broadcast"], "flags")? & OverlayNode::FLAG_BCAST_NO_TWOSTEP == 0,
            "multiple members require a pure two-step FEC send"
        );
    }
    let id = OverlayShortId::from_data(
        overlay_public_key(&super::bytes(v, "name", 1 << 20)?)?.short_id()?,
    );
    let mut keys = Vec::<Arc<dyn KeyOption>>::new();
    let mut seeds = Vec::new();
    for member in members {
        let object = json!({"key":member});
        let wire = ZeroizingBytes::new(super::bytes(&object, "key", 36)?);
        ensure!(
            wire.len() == 36
                && wire[..4] == ton::pk::privatekey::Ed25519::constructor_const().to_le_bytes(),
            "Ed25519 private key required"
        );
        let key = Ed25519KeyOption::<ZeroizingBytes>::from_private_key((&wire[4..]).try_into()?)?;
        ensure!(!keys.iter().any(|old| old.id() == key.id()), "duplicate member");
        keys.push(key);
        seeds.push(ZeroizingBytes::new(wire[4..].to_vec()));
    }
    let mut authorized = BTreeMap::new();
    let values = v["authorized_keys"].as_array().context("authorized keys required")?;
    ensure!(values.len() <= 1024, "too many authorized keys");
    for entry in values {
        ensure!(
            authorized.insert(bits(entry, "key")?, uint(entry, "max_size")?).is_none(),
            "duplicate authorized key"
        );
    }
    let rules = OverlayPrivacyRules::new(
        uint(v, "max_unauth_size")?,
        uint(v, "flags")?,
        authorized.clone(),
    );
    let record = Arc::new(Mutex::new(Record::default()));
    *LOG_RECORD.lock().unwrap() = Some(Arc::downgrade(&record));
    let mut nodes = Vec::new();
    let mut transports = Vec::new();
    let mut consumers = Vec::new();
    for (member, key) in keys.iter().enumerate() {
        let (_, config) = AdnlNodeConfig::from_ip_address_and_private_keys(
            "127.0.0.1:0",
            vec![(seeds[member].as_slice().try_into()?, 0)],
        )?;
        let adnl = AdnlNode::with_config(
            config,
            #[cfg(feature = "dump")]
            None,
        )
        .await?;
        let node = OverlayNode::with_params_profile_and_clock(
            adnl.clone(),
            &[0; 32],
            0,
            WireProfile::T0,
            Arc::new(Clock(f64::from(now))),
        )?;
        node.install_broadcast_transport(Arc::new(Edge(
            record.clone(),
            keys.iter().map(|key| *key.id().data()).collect(),
        )))?;
        let peers = keys
            .iter()
            .filter(|peer| peer.id() != key.id())
            .map(|peer| peer.id().clone())
            .collect::<Vec<_>>();
        ensure!(
            node.add_fixed_member_overlay_with_options(
                OverlayParams::with_id_only(&id),
                key,
                &peers,
                rules.clone(),
                FixedMemberOverlayOptions { twostep: v["mode"] == "twostep", ..Default::default() },
            )?,
            "overlay already present"
        );
        node.set_broadcast_check(&id, Some(Arc::new(Approve)))?;
        node.add_consumer(&id, Arc::new(Application { record: record.clone(), member }))?;
        let mut subscription = node.subscribe_broadcast(&id)?;
        let sink = record.clone();
        consumers.push(tokio::spawn(async move {
            while let Ok(Some(item)) = subscription.recv().await {
                sink.lock().unwrap().delivered.push(json!({"member":member,"kind":"broadcast","from_key":hex::encode(item.recv_from.data()),"data_sha256":hex::encode(sha256_digest(&item.data)),"extra":hex::encode(item.extra.unwrap_or_default())}));
            }
        }));
        nodes.push(node);
        transports.push(adnl);
    }
    // All consumers and overlay actors are registered before scenario input,
    // just as the reference drains its startup scheduler rounds first.
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    if v["mode"] == "plumtree" {
        for node in &nodes {
            node.configure_plumtree(
                &id,
                PlumtreeConfig {
                    authorized_keys: authorized
                        .iter()
                        .map(|(key, cap)| (*key, *cap as usize))
                        .collect(),
                    max_untrusted_size: uint(v, "max_unauth_size")? as usize,
                    untrusted_flags: uint(v, "flags")?,
                    fixed_members: true,
                    original_sender: true,
                    eager_limit: 1,
                    max_retained_bytes: 32 << 20,
                    max_broadcasts: 1024,
                },
                &tokio::runtime::Handle::current(),
            )?;
        }
    }
    if let Some(inbound) = v.get("inbound") {
        let inbound = inbound.as_array().context("inbound array required")?;
        ensure!(inbound.len() <= 64, "too many inbound messages");
        for item in inbound {
            let dst = uint(item, "dst")? as usize;
            ensure!(dst < nodes.len(), "destination member required");
            let peers =
                AdnlPeers::with_keys(keys[dst].id().clone(), KeyId::from_data(bits(item, "src")?));
            if let Err(error) = nodes[dst]
                .try_consume_custom(&super::bytes(item, "message", 1 << 20)?, &peers)
                .await
            {
                receive_error(&record, error)?;
            }
            tokio::task::yield_now().await;
        }
    }
    if let Some(send) = v.get("broadcast") {
        let old_fec = v["mode"] != "plumtree"
            && (v["mode"] != "twostep"
                || uint(send, "flags")? & OverlayNode::FLAG_BCAST_NO_TWOSTEP != 0);
        let fec = send["fec"].as_bool().context("fec bool required")?;
        let simple_limit = adnl::MAX_SIMPLE_BROADCAST_SIZE as usize;
        let limit = if !fec {
            simple_limit
        } else if old_fec {
            1535
        } else {
            1 << 20
        };
        let data = super::bytes(send, "data", limit)?;
        ensure!(fec || data.len() <= simple_limit, "simple broadcast exceeds limit");
        let tagged = TaggedByteSlice {
            object: &data,
            #[cfg(feature = "telemetry")]
            tag: 0,
        };
        let result = if v["mode"] == "plumtree" {
            nodes[0]
                .broadcast_plumtree(
                    &id,
                    &keys[0],
                    ton::overlay::Certificate::Overlay_EmptyCertificate,
                    uint(send, "flags")?,
                    if fec { None } else { Some(sha256_digest(&data)) },
                    &data,
                )
                .await
        } else if fec {
            nodes[0].broadcast_fec(&id, &tagged, None, uint(send, "flags")?).await.map(|_| ())
        } else {
            nodes[0]
                .broadcast(&id, &tagged, None, uint(send, "flags")?, AdnlSendMethod::Fast)
                .await
                .map(|_| ())
        };
        if let Err(error) = result {
            ensure!(
                error.downcast_ref::<PlumtreeRefusal>().is_some()
                    || error.to_string().to_lowercase().contains("forbidden"),
                "native send failed: {error}"
            );
        }
    }
    let mut handed = 0;
    let mut idle = 0;
    let mut seen = (0, 0);
    for _ in 0..20000 {
        tokio::task::yield_now().await;
        // The reference hands off the complete current emission batch before
        // running another scheduler round. Preserve FIFO messages per member
        // rather than inserting an extra scheduling round after every datagram.
        let batch = {
            let r = record.lock().unwrap();
            let batch = r.emitted[handed..].to_vec();
            handed = r.emitted.len();
            batch
        };
        for message in batch {
            if let Some(dst) = keys.iter().position(|key| *key.id().data() == message.dst) {
                let peers =
                    AdnlPeers::with_keys(keys[dst].id().clone(), KeyId::from_data(message.src));
                if let Err(error) = nodes[dst].try_consume_custom(&message.data, &peers).await {
                    receive_error(&record, error)?;
                }
            }
        }
        let size = {
            let r = record.lock().unwrap();
            (r.emitted.len(), r.delivered.len())
        };
        ensure!(size.0 <= 1024, "overlay emission budget exceeded");
        if size == seen && handed == size.0 {
            idle += 1;
        } else {
            idle = 0;
            seen = size;
        }
        if idle >= 64 {
            break;
        }
    }
    ensure!(idle >= 64, "overlay members did not settle");
    for node in &nodes {
        let generation = node.overlay_generation(&id)?;
        node.delete_private_overlay_checked(&generation).await?;
    }
    for consumer in consumers {
        consumer.abort();
        let _ = consumer.await;
    }
    for adnl in transports {
        adnl.stop_checked().await?;
    }
    *LOG_RECORD.lock().unwrap() = None;
    let r = record.lock().unwrap();
    let member = |id: &[u8; 32]| {
        keys.iter()
            .position(|key| key.id().data() == id)
            .map_or_else(|| json!(hex::encode(id)), |i| json!(i))
    };
    let emitted = r.emitted.iter().map(|m| Ok(json!({"src":member(&m.src),"dst":member(&m.dst),"via":match m.method {BroadcastTransportMethod::Datagram=>"adnl",_=>"sender"},"type":message_type(&m.data)?,"canonical":hex::encode(&m.data)}))).collect::<Result<Vec<Value>>>()?;
    Ok(json!({"outcome":"broadcast","emitted":emitted,"delivered":r.delivered,"drops":r.drops}))
}
