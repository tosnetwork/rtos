// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Shard overlay certificates pushed between real nodes over ADNL: the issuer
//! scan of one node reaches the receiver registered on another node's
//! full-node identity, through the network's own subscriber list.

use super::*;
use crate::{
    collator_test_bundle::create_engine_allocated,
    network::shard_overlay_certificates::{
        push_constructor, ShardOverlayCertificatePolicy, WireShard,
    },
    validator::validator_manager::emulator_network_bootstrap::EmulatorNetworkBootstrap,
};
use adnl::{node::AdnlNodeConfig, OverlayCertificate, MAX_FEC_BROADCAST_SIZE};
use rtos_api::ton::{
    engine::validator::keyhash::KeyHash, rpc::engine::validator::ImportShardOverlayCertificate,
};
use rtos_block::{
    ConfigParam34, ConfigParamEnum, Ed25519KeyOption, PqConsensusKey, UInt256, ZeroizingBytes,
};
use std::time::Duration;

struct PushEngine {
    zero: BlockIdExt,
    allocated: Arc<crate::engine_traits::EngineAlloc>,
    #[cfg(feature = "telemetry")]
    telemetry: Arc<crate::engine_traits::EngineTelemetry>,
    applied: std::sync::RwLock<Option<Arc<crate::shard_state::ShardStateStuff>>>,
}

#[async_trait::async_trait]
impl EngineOperations for PushEngine {
    fn zerostate_id(&self) -> Result<&BlockIdExt> {
        Ok(&self.zero)
    }
    fn check_stop(&self) -> bool {
        false
    }
    fn get_monitor_min_split(&self) -> u8 {
        0
    }
    fn engine_allocated(&self) -> &Arc<crate::engine_traits::EngineAlloc> {
        &self.allocated
    }
    #[cfg(feature = "telemetry")]
    fn engine_telemetry(&self) -> &Arc<crate::engine_traits::EngineTelemetry> {
        &self.telemetry
    }
    fn load_last_applied_mc_block_id(&self) -> Result<Option<Arc<BlockIdExt>>> {
        Ok(self.applied.read().unwrap().as_ref().map(|state| Arc::new(state.block_id().clone())))
    }
    async fn load_last_applied_mc_state(&self) -> Result<Arc<crate::shard_state::ShardStateStuff>> {
        self.applied.read().unwrap().clone().ok_or_else(|| error!("no fixture applied state"))
    }
    async fn check_sync(&self) -> Result<bool> {
        Ok(true)
    }
    fn load_block_handle(
        &self,
        _id: &BlockIdExt,
    ) -> Result<Option<Arc<storage::block_handle_db::BlockHandle>>> {
        Ok(None)
    }
}

/// A fixture step that fails instead of waiting forever. It cannot end a
/// step that blocks its thread.
async fn step<T>(name: &str, future: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(Duration::from_secs(30), future)
        .await
        .map_err(|_| error!("fixture step timed out: {name}"))?
}

/// An ephemeral port free for both UDP and TCP that this process has not
/// handed out before; ADNL binds both on the same port.
fn free_port() -> u16 {
    static TAKEN: std::sync::Mutex<Vec<u16>> = std::sync::Mutex::new(Vec::new());
    loop {
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = udp.local_addr().unwrap().port();
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_err() {
            continue;
        }
        let mut taken = TAKEN.lock().unwrap();
        if !taken.contains(&port) {
            taken.push(port);
            return port;
        }
    }
}

fn seed_key(seed: u8) -> Arc<dyn KeyOption> {
    Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[seed; 32]).unwrap()
}

struct Node {
    router: Arc<FullNodeOverlaysRouter>,
    full_node: Arc<dyn KeyOption>,
    _dir: tempfile::TempDir,
}

impl Node {
    fn network(&self) -> &Arc<NodeNetwork> {
        &self.router.network
    }

    async fn stop(&self) {
        tokio::time::timeout(Duration::from_secs(10), self.router.stop_and_wait())
            .await
            .expect("router workers retained after router cancellation")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(15), self.network().stop_adnl())
            .await
            .expect("network shutdown watchdog")
            .unwrap();
    }
}

/// One node of the shared zerostate: its own directory and ADNL identity on
/// an ephemeral port, the bootstrap validator keys only for the issuer.
async fn node(
    bootstrap: &EmulatorNetworkBootstrap,
    seed: u8,
    validator: bool,
    policy: ShardOverlayCertificatePolicy,
    state: &Arc<crate::shard_state::ShardStateStuff>,
    known: &[&Node],
) -> Result<Node> {
    // Another process may take a probed port before the node binds it.
    let mut attempt = 0;
    loop {
        match build_node(bootstrap, seed, validator, policy.clone(), state, known).await {
            Err(error) if attempt < 3 && error.to_string().contains("Address already in use") => {
                attempt += 1;
            }
            result => return result,
        }
    }
}

async fn build_node(
    bootstrap: &EmulatorNetworkBootstrap,
    seed: u8,
    validator: bool,
    policy: ShardOverlayCertificatePolicy,
    state: &Arc<crate::shard_state::ShardStateStuff>,
    known: &[&Node],
) -> Result<Node> {
    let dir = tempfile::tempdir()?;
    for entry in std::fs::read_dir(bootstrap.config_dir())? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            std::fs::copy(entry.path(), dir.path().join(entry.file_name()))?;
        }
    }
    let path = dir.path().join(bootstrap.config_path.file_name().unwrap());
    let mut config: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    let (adnl, _) = AdnlNodeConfig::from_ip_address_and_private_keys(
        &format!("127.0.0.1:{}", free_port()),
        vec![
            ([seed; 32], NodeNetwork::TAG_DHT_KEY),
            ([seed + 1; 32], NodeNetwork::TAG_OVERLAY_KEY),
        ],
    )?;
    config["adnl_node"] = serde_json::to_value(adnl)?;
    config["ip_address_quic"] = format!("127.0.0.1:{}", free_port()).into();
    config["internal_db_path"] = dir.path().join("node_db").to_string_lossy().to_string().into();
    if validator {
        // Election IDs are also ADNL dynamic key tags; keep clear of 1 and 2.
        for entry in config["validator_keys"].as_array_mut().unwrap() {
            entry["election_id"] = (entry["election_id"].as_i64().unwrap() + 1000).into();
        }
    } else {
        config["validator_keys"] = serde_json::json!([]);
        config["validator_key_ring"] = serde_json::json!({});
    }
    std::fs::write(&path, serde_json::to_vec_pretty(&config)?)?;
    let mut node_config = crate::config::TonNodeConfig::from_file(
        dir.path().to_str().unwrap(),
        path.file_name().unwrap().to_str().unwrap(),
        None,
        "",
        None,
    )
    .await?;
    node_config.set_shard_overlay_certificate_policy(policy);
    let allocated = create_engine_allocated();
    #[cfg(feature = "telemetry")]
    let telemetry = crate::collator_test_bundle::create_engine_telemetry();
    let network = step(
        "network creation",
        NodeNetwork::new(
            node_config,
            tokio_util::sync::CancellationToken::new(),
            #[cfg(feature = "telemetry")]
            telemetry.clone(),
            allocated.clone(),
        ),
    )
    .await?;
    if validator {
        // The configuration loads the validator transport key concurrently;
        // start the transport only once it is registered.
        let transport = bootstrap.validators[0].adnl_key.id().clone();
        step("validator key registration", async {
            while network.context().stack.adnl.key_by_id(&transport).is_err() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok(())
        })
        .await?;
    }
    step("network start", network.start()).await?;
    let engine = Arc::new(PushEngine {
        zero: bootstrap.zerostate_id.clone(),
        allocated,
        #[cfg(feature = "telemetry")]
        telemetry,
        applied: std::sync::RwLock::new(Some(state.clone())),
    });
    let local = network.context().stack.adnl.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY)?;
    for peer in known {
        network.context().stack.adnl.add_peer(
            local.id(),
            peer.network().context().stack.adnl.ip_address_adnl(),
            None,
            &peer.full_node,
        )?;
    }
    let router = FullNodeOverlaysRouter::create(engine, network, DhtSearchPolicy::default())?;
    // Requests are not served before the full node is initialized.
    assert!(router.network.shard_certificate_endpoint().serving_router().is_err());
    step("full node initialization", router.initialize()).await?;
    assert!(router.network.shard_certificate_endpoint().serving_router().is_ok());
    let full_node = router.full_node_adnl_key()?;
    assert_eq!(full_node.id(), seed_key(seed + 1).id());
    Ok(Node { router, full_node, _dir: dir })
}

fn applied_state(
    bootstrap: &EmulatorNetworkBootstrap,
) -> Result<(Arc<crate::shard_state::ShardStateStuff>, Vec<Arc<KeyId>>)> {
    use rtos_block::{McStateExtra, Serializable, ShardStateUnsplit};
    let member = ValidatorDescr::with_pq_params(
        UInt256::from([20; 32]),
        PqConsensusKey {
            algorithm_id: 1,
            key_id: rtos_block::derive_consensus_key_id(1, &vec![40; 1312]),
            public_key: vec![40; 1312],
        },
        1,
        UInt256::from(*bootstrap.validators[0].adnl_key.id().data()),
    );
    let set = ValidatorSet::with_cc_seqno(0, u32::MAX, 1, 0, vec![member])?;
    let mut config = bootstrap.config_params().clone();
    config.set_config(ConfigParamEnum::ConfigParam34(ConfigParam34::with_validator_set(
        set.clone(),
    )))?;
    let (roots, _) = fast_sync_transport_authority(set.list(), rtos_api::WireProfile::T0)?;
    let mut state = ShardStateUnsplit::with_ident(ShardIdent::MASTERCHAIN);
    state.set_gen_time(rtos_block::UnixTime::now() as u32);
    let mut extra = McStateExtra::default();
    extra.config = config;
    state.write_custom(Some(&extra))?;
    let root = state.serialize()?;
    let id = BlockIdExt::with_params(
        ShardIdent::MASTERCHAIN,
        0,
        root.repr_hash().clone(),
        UInt256::calc_file_hash(&rtos_block::write_boc(&root)?),
    );
    let allocated = create_engine_allocated();
    #[cfg(feature = "telemetry")]
    let telemetry = crate::collator_test_bundle::create_engine_telemetry();
    let state = crate::shard_state::ShardStateStuff::from_state(
        id,
        state,
        #[cfg(feature = "telemetry")]
        &telemetry,
        &allocated,
    )?;
    Ok((state, roots))
}

fn accepting(values: &[String]) -> ShardOverlayCertificatePolicy {
    let mut policy = ShardOverlayCertificatePolicy::default();
    for value in values {
        policy.add_accept_certs_from(value).unwrap();
    }
    policy
}

fn knows(sender: &Node, receiver: &Node) {
    let stack = &sender.network().context().stack;
    stack
        .adnl
        .add_peer(
            sender.full_node.id(),
            receiver.network().context().stack.adnl.ip_address_adnl(),
            None,
            &receiver.full_node,
        )
        .unwrap();
}

async fn send_raw(sender: &Node, receiver: &Node, message: &ImportShardOverlayCertificate) {
    let bytes = rtos_api::serialize_boxed(message).unwrap();
    let data = TaggedByteSlice {
        object: &bytes,
        #[cfg(feature = "telemetry")]
        tag: push_constructor(),
    };
    let peers =
        AdnlPeers::with_keys(sender.full_node.id().clone(), receiver.full_node.id().clone());
    sender.network().context().stack.adnl.send_custom(&data, &peers).await.unwrap();
}

fn held(node: &Node, shard: &ShardIdent) -> bool {
    node.router.shard_certificates().adnl_certificate(shard).is_some()
}

async fn wait_held(node: &Node, shard: &ShardIdent) -> bool {
    for _ in 0..100 {
        if held(node, shard) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pushed_certificates_cross_the_network_only_where_accepted() -> Result<()> {
    let bootstrap = EmulatorNetworkBootstrap::build(1)?;
    let (state, roots) = applied_state(&bootstrap)?;
    let issuer_id = seed_key(11).id().clone();
    let (b_seed, c_seed, d_seed) = (21u8, 31u8, 41u8);
    // B accepts the issuer; C accepts any sender; D accepts nobody.
    let b =
        node(&bootstrap, b_seed, false, accepting(&[hex::encode(issuer_id.data())]), &state, &[])
            .await?;
    let c = node(&bootstrap, c_seed, false, accepting(&["*".to_string()]), &state, &[]).await?;
    let d = node(&bootstrap, d_seed, false, ShardOverlayCertificatePolicy::default(), &state, &[])
        .await?;
    let mut issuing = ShardOverlayCertificatePolicy::default();
    issuing.add_auto_sign(&hex::encode(b.full_node.id().data()))?;
    issuing.add_auto_sign(&hex::encode(d.full_node.id().data()))?;
    let a = node(&bootstrap, 10, true, issuing, &state, &[]).await?;
    for node in [&a, &b, &c, &d] {
        node.router.update_public_authorization(&roots, &[]).await?;
    }
    for receiver in [&b, &c, &d] {
        knows(&a, receiver);
    }
    knows(&d, &b);
    knows(&d, &c);
    let mc = ShardIdent::MASTERCHAIN;
    let base = ShardIdent::BASE_WORKCHAIN;

    // The issuer's scan: one certificate per target and shard.
    let sent = a.router.issue_certificates_once().await?;
    let b_mc = wait_held(&b, &mc).await;
    let b_base = wait_held(&b, &base).await;
    let b_source = a_source_after(&b, &mc);
    // D receives the same pushes but has no receiver registered.
    let d_any = held(&d, &mc) || held(&d, &base);

    // D, no validator, forwards a validator-issued certificate: C accepts it
    // through `*`, B refuses D as an unconfigured sender.
    let signer =
        a.router.local_transport_signer(&roots, &[]).await?.expect("the issuer holds a root");
    let forward = |subject: &Node, shard: &ShardIdent| -> ImportShardOverlayCertificate {
        a.router
            .shard_certificates()
            .issue_shard_overlay_certificates(
                &signer,
                &[subject.full_node.id().clone()],
                &[shard.clone()],
                rtos_block::UnixTime::now() as i32 + 3600,
            )
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
            .message
            .unwrap()
    };
    let to_c = forward(&c, &mc);
    send_raw(&d, &c, &to_c).await;
    let c_mc = wait_held(&c, &mc).await;
    // An issuer that is no validator root is refused even under `*`.
    let stranger = seed_key(99);
    let base_overlay =
        KeyId::from_data(*c.router.overlay_client(&base).await?.overlay_client().id().data());
    let forged = ImportShardOverlayCertificate {
        workchain: base.workchain_id(),
        shard: base.shard_prefix_with_tag() as i64,
        signed_key: KeyHash { key_hash: UInt256::from(*c.full_node.id().data()) }.into_boxed(),
        cert: OverlayCertificate::sign_for_console(
            &stranger,
            base_overlay.data(),
            c.full_node.id().data(),
            rtos_block::UnixTime::now() as i32 + 3600,
            MAX_FEC_BROADCAST_SIZE,
        )?,
    };
    send_raw(&d, &c, &forged).await;
    // B already holds a base certificate; a newer one forwarded by the
    // unconfigured D must leave it unchanged.
    let before = b.router.shard_certificates().adnl_certificate(&base).map(|c| c.expire_at());
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let to_b_newer = forward(&b, &base);
    send_raw(&d, &b, &to_b_newer).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let after = b.router.shard_certificates().adnl_certificate(&base).map(|c| c.expire_at());
    let c_base = held(&c, &base);

    // A newly created overlay of B reads the live external-message setting.
    let handler = b.network().config_handler();
    handler.set_ext_messages_broadcast_disabled(true).await?;
    let split = base.split()?.0;
    let created = b.router.overlay_client_for_shard(split).await?;
    let inherited = created.ext_messages().map(|messages| messages.broadcast_disabled());

    for node in [&a, &b, &c, &d] {
        node.stop().await;
    }
    assert_eq!(sent, 4, "two shards for each of the two targets");
    assert!(b_mc && b_base, "the accepted issuer's pushes are imported");
    assert_eq!(b_source.as_ref(), Some(b.full_node.id()), "B now sends as its full-node key");
    assert!(!d_any, "a node accepting nobody imports nothing");
    assert!(c_mc, "a wildcard accepts a non-validator forwarding a validator certificate");
    assert!(!c_base, "a certificate by a non-root issuer is refused under the wildcard");
    assert_eq!(before, after, "an unconfigured sender is refused");
    assert_eq!(inherited, Some(true));
    Ok(())
}

fn a_source_after(node: &Node, shard: &ShardIdent) -> Option<Arc<KeyId>> {
    let client = node.router.public_overlays.get(shard)?.val().clone();
    node.router.public_outbound_source(&client, 4000, true).ok().map(|source| source.id().clone())
}

const CONTROL_SERVER_KEY: &str =
    r#"{"type_id":1209251014,"pvt_key":"cJIxGZviebMQWL726DRejqVzRTSXPv/1sO/ab6XOZXk="}"#;
const CONTROL_SERVER_PUB: &str =
    r#"{"type_id":1209251014,"pub_key":"cujCRU4rQbSw48yHVHxQtRPhUlbo+BuZggFTQSu04Y8="}"#;

async fn control_query<Q: rtos_api::AnyBoxedSerialize>(
    client: &mut adnl::client::AdnlClient,
    query: Q,
) -> rtos_api::TLObject {
    use rtos_api::AnyBoxedSerialize;
    let data = rtos_api::serialize_boxed(&query.into_tl_object()).unwrap();
    let wrapped = rtos_api::ton::rpc::engine::validator::ControlQuery { data: data.into() }
        .into_tl_object()
        .into();
    client.query(&wrapped).await.unwrap()
}

fn control_refusal(answer: rtos_api::TLObject) -> Option<(i32, String)> {
    answer.downcast::<rtos_api::ton::engine::validator::ControlQueryError>().ok().map(|error| {
        let error = error.only();
        (error.code, error.message.into_string().unwrap())
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_queries_reach_the_serving_full_node() -> Result<()> {
    use crate::network::control::{ControlServer, DataSource};
    use rtos_api::ton::rpc::engine::validator::{
        SetExtMessagesBroadcastDisabled, SignShardOverlayCertificate,
    };
    let bootstrap = EmulatorNetworkBootstrap::build(1)?;
    let (state, roots) = applied_state(&bootstrap)?;
    let a =
        node(&bootstrap, 10, true, ShardOverlayCertificatePolicy::default(), &state, &[]).await?;
    a.router.update_public_authorization(&roots, &[]).await?;
    let (client_private, client_key) =
        secrets_vault::vault_block::get_key_option_factory().generate_with_json()?;
    let server_config = adnl::server::AdnlServerConfig::from_json_with_permissions(
        &serde_json::json!({
            "address": "127.0.0.1:0",
            "server_key": serde_json::from_str::<serde_json::Value>(CONTROL_SERVER_KEY)?,
            "clients": { "list": [{
                "type_id": 1209251014,
                "pub_key": rtos_block::base64_encode(client_key.pub_key()?),
                "permissions": 2,
            }]},
        })
        .to_string(),
    )?;
    let network = a.network().clone();
    let server = ControlServer::with_params(
        server_config,
        DataSource::Engine(a.router.engine.clone()),
        network.config_handler(),
        network.config_handler(),
        Some(&network),
    )
    .await?;
    let (_, client_config) = adnl::client::AdnlClientConfig::from_json(
        &serde_json::json!({
            "server_address": server.local_addr().to_string(),
            "server_key": serde_json::from_str::<serde_json::Value>(CONTROL_SERVER_PUB)?,
            "client_key": serde_json::to_value(client_private)?,
        })
        .to_string(),
    )?;
    let mut client = adnl::client::AdnlClient::connect(&client_config).await?;
    let subject = seed_key(77);
    let mc = WireShard::from(&ShardIdent::MASTERCHAIN);
    let sign = |max_size: i32, shard: WireShard| SignShardOverlayCertificate {
        workchain: shard.workchain,
        shard: shard.shard,
        signed_key: KeyHash { key_hash: UInt256::from(*subject.id().data()) }.into_boxed(),
        expire_at: rtos_block::UnixTime::now() as i32 + 3600,
        max_size,
    };
    let import = |cert: rtos_api::ton::overlay::Certificate| ImportShardOverlayCertificate {
        workchain: mc.workchain,
        shard: mc.shard,
        signed_key: KeyHash { key_hash: UInt256::from(*subject.id().data()) }.into_boxed(),
        cert,
    };
    let as_certificate = |answer: rtos_api::TLObject| {
        answer.downcast::<rtos_api::ton::overlay::Certificate>().expect("a certificate reply")
    };
    let large = as_certificate(control_query(&mut client, sign(1 << 24, mc)).await);
    let small = as_certificate(control_query(&mut client, sign(768, mc)).await);
    let unknown = control_refusal(
        control_query(&mut client, sign(1 << 24, WireShard { workchain: 0, shard: 0 })).await,
    );
    let imported = control_query(&mut client, import(large.clone())).await;
    let refused_small = control_refusal(control_query(&mut client, import(small.clone())).await);
    let refused_empty = control_refusal(
        control_query(
            &mut client,
            import(rtos_api::ton::overlay::Certificate::Overlay_EmptyCertificate),
        )
        .await,
    );
    let disabled = control_query(
        &mut client,
        SetExtMessagesBroadcastDisabled { disabled: rtos_api::ton::Bool::BoolTrue },
    )
    .await;
    let live = a.router.ext_messages_broadcast_disabled();
    a.router.stop();
    let after_stop = control_refusal(control_query(&mut client, sign(1 << 24, mc)).await);
    client.shutdown().await.ok();
    server.shutdown().await;
    a.stop().await;

    assert!(matches!(large, rtos_api::ton::overlay::Certificate::Overlay_Certificate(_)));
    assert!(
        matches!(small, rtos_api::ton::overlay::Certificate::Overlay_Certificate(_)),
        "signing at 768 succeeds and replies version 1"
    );
    assert_eq!(unknown, Some((602, "failed to import cert: shard not found".to_string())));
    assert!(imported.downcast::<rtos_api::ton::engine::validator::Success>().is_ok());
    assert_eq!(
        refused_small,
        Some((0, "failed to import cert: certificate is not valid for this shard overlay".into())),
        "the 768-byte reply does not verify"
    );
    assert_eq!(refused_empty, Some((0, "failed to import cert: empty certificate".to_string())));
    assert!(disabled.downcast::<rtos_api::ton::engine::validator::Success>().is_ok());
    assert!(live, "the control query changes the full node's live setting");
    assert_eq!(after_stop, Some((651, "not started".to_string())));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_issuer_scans_as_soon_as_the_full_node_serves() -> Result<()> {
    let bootstrap = EmulatorNetworkBootstrap::build(1)?;
    let (state, roots) = applied_state(&bootstrap)?;
    let b = node(
        &bootstrap,
        21,
        false,
        accepting(&[hex::encode(seed_key(11).id().data())]),
        &state,
        &[],
    )
    .await?;
    b.router.update_public_authorization(&roots, &[]).await?;
    let mut issuing = ShardOverlayCertificatePolicy::default();
    issuing.add_auto_sign(&hex::encode(b.full_node.id().data()))?;
    // No scan is requested: the issuer task started by initialization does
    // it without waiting for the first interval.
    let a = node(&bootstrap, 10, true, issuing, &state, &[&b]).await?;
    let received = wait_held(&b, &ShardIdent::MASTERCHAIN).await;
    a.stop().await;
    b.stop().await;
    assert!(received, "the first scan runs at once");
    Ok(())
}

#[test]
fn push_message_names_its_shard_on_the_wire() {
    let shard = WireShard::from(&ShardIdent::BASE_WORKCHAIN);
    assert_eq!(shard, WireShard { workchain: 0, shard: i64::MIN });
}
