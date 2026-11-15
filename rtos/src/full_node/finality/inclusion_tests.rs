// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::block_proof::BlockProofStuff;
use futures::FutureExt;
use rtos_api::IntoBoxed;

fn decode(value: &serde_json::Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}

fn fixture_block(row: &serde_json::Value) -> BlockStuff {
    let data = decode(&row["block_boc"]);
    let root = read_single_root_boc(&data).unwrap();
    let header = Block::construct_from_cell(root.clone()).unwrap().read_info().unwrap();
    let id = BlockIdExt::with_params(
        header.shard().clone(),
        header.seq_no(),
        root.repr_hash().clone(),
        UInt256::calc_file_hash(&data),
    );
    BlockStuff::deserialize_block_checked(id, Arc::new(data)).unwrap()
}

fn fixture_carrier(row: &serde_json::Value) -> BlockSignaturesSimplexPq {
    BlockSignaturesSimplexPq {
        validator_info: ValidatorBaseInfo::with_params(
            row["subset_hash"].as_u64().unwrap() as u32,
            7,
        ),
        sig_count: 3,
        sig_weight: 3,
        slot: 99,
        session_id: UInt256::from_slice(&decode(&row["session"])),
        candidate_data: BlockSignaturesSimplex::bytes_to_cell_tree(&decode(&row["candidate"]))
            .unwrap(),
        signatures: row["signatures"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| {
                let mut id = [0; 32];
                id[..4]
                    .copy_from_slice(&(entry["index"].as_u64().unwrap() as u32 + 1).to_le_bytes());
                PqBlockSignaturePair {
                    validator_id: id.into(),
                    algorithm_id: 1,
                    signature: decode(&entry["signature"]),
                }
            })
            .collect(),
    }
}

fn full_proof(block: &BlockStuff, carrier: BlockSignaturesSimplexPq) -> BlockProofStuff {
    BlockProofStuff::new(
        BlockProof::with_params(
            block.id().clone(),
            MerkleProof::create(block.root_cell(), |_| true).unwrap().serialize().unwrap(),
            Some(BlockSignaturesVariant::SimplexPq(carrier)),
        ),
        false,
    )
    .unwrap()
}

struct Pair {
    _dir: tempfile::TempDir,
    receiver: Arc<Engine>,
    provider: Arc<Engine>,
    // Only source-circulation fixtures add a true non-validator recipient.
    observer: Option<Arc<Engine>>,
    anchor: BlockIdExt,
    shard: BlockStuff,
    shard_carrier: BlockSignaturesSimplexPq,
    shard_state_root: UInt256,
    master: BlockStuff,
    master_state_root: UInt256,
}

async fn stop_fixture_engines(engines: Vec<Arc<Engine>>) {
    // Join every owner even if one shutdown reports an error.
    let results =
        futures::future::join_all(engines.into_iter().map(|engine| engine.wait_stop())).await;
    for result in results {
        result.unwrap();
    }
}

// These isolated fixtures have no external DHT to refresh authenticated public
// advertisements. Use the actual signing and verification path, including the
// normal 600-second freshness policy, for every directed Engine pair.
async fn refresh_fixture_public_advertisements(
    engines: &[&Arc<Engine>],
    shards: &[&rtos_block::ShardIdent],
) {
    for &local in engines {
        for &remote in engines {
            if Arc::ptr_eq(local, remote) {
                continue;
            }
            for &shard in shards {
                let client = local.overlay_client(shard).await.unwrap();
                let id = adnl::OverlayShortId::from_data(*client.overlay_client().id().data());
                let advertised =
                    remote.network().context().stack.overlay.get_signed_node(&id, false).unwrap();
                local
                    .network()
                    .context()
                    .stack
                    .overlay
                    .add_public_peer(
                        remote.network().context().stack.adnl.ip_address_adnl(),
                        &advertised,
                        &id,
                    )
                    .unwrap()
                    .unwrap();
            }
        }
    }
}

// Engine::new restores storage/transport but does not execute Engine::run's
// overlay startup. Reopen fixtures must restore real reachability before the
// autonomous recovery owner starts; no runtime, record or history is supplied.
async fn initialize_cold_history_network(cold: &Arc<Engine>, peers: &[&Arc<Engine>]) {
    assert!(cold.overlays_router().is_err(), "cold fixture unexpectedly started overlays");
    for &peer in peers {
        for (local, remote) in [(cold, peer), (peer, cold)] {
            let local_adnl = &local.network().context().stack.adnl;
            let remote_adnl = &remote.network().context().stack.adnl;
            let local_key = local_adnl.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY).unwrap();
            let remote_key = remote_adnl.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY).unwrap();
            local_adnl
                .add_peer(local_key.id(), remote_adnl.ip_address_adnl(), None, &remote_key)
                .unwrap();
            local
                .network()
                .context()
                .stack
                .quic
                .as_ref()
                .unwrap()
                .add_peer_key(
                    remote_key.id().clone(),
                    remote.network().context().quic_address.unwrap(),
                )
                .unwrap();
        }
    }
    cold.initialize_test_full_node_overlays().await.unwrap();
    assert!(
        cold.overlays_router().is_ok(),
        "cold overlay initialization must finish before recovery"
    );
    // Public history transport needs no current/historical validator runtime.
    // In particular, do not refresh private overlays by loading the GC'd head.
    let shards = [rtos_block::ShardIdent::MASTERCHAIN, rtos_block::ShardIdent::BASE_WORKCHAIN];
    for &peer in peers {
        for (local, remote) in [(cold, peer), (peer, cold)] {
            let remote_key = remote
                .network()
                .context()
                .stack
                .adnl
                .key_by_tag(NodeNetwork::TAG_OVERLAY_KEY)
                .unwrap();
            for shard in &shards {
                let client = local.overlay_client(shard).await.unwrap();
                client.overlay_client().neighbours().add(remote_key.id().clone()).unwrap();
                assert!(client.overlay_client().neighbours().contains(remote_key.id()));
            }
        }
    }
    let mut engines = vec![cold];
    engines.extend_from_slice(peers);
    refresh_fixture_public_advertisements(&engines, &[&shards[0], &shards[1]]).await;
}

impl Pair {
    async fn refresh_public_advertisements(&self) {
        let mut engines = vec![&self.provider, &self.receiver];
        engines.extend(self.observer.iter());
        refresh_fixture_public_advertisements(
            &engines,
            &[self.shard.id().shard(), self.anchor.shard()],
        )
        .await;
    }
    async fn stop_all(&self) {
        let mut engines = vec![self.provider.clone(), self.receiver.clone()];
        engines.extend(self.observer.iter().cloned());
        stop_fixture_engines(engines).await;
    }
    async fn new(variant: &str, corrupt_signature: bool) -> Self {
        Self::with_propagation_profile(variant, corrupt_signature, false).await
    }

    async fn with_propagation_profile(variant: &str, corrupt_signature: bool, v2: bool) -> Self {
        Self::with_gc_options(variant, corrupt_signature, v2, false).await
    }

    async fn with_gc_options(
        variant: &str,
        corrupt_signature: bool,
        v2: bool,
        history_gc: bool,
    ) -> Self {
        Self::with_source_options(variant, corrupt_signature, v2, history_gc, false).await
    }

    async fn with_source_transport(variant: &str) -> Self {
        Self::with_source_options(variant, false, true, false, true).await
    }

    async fn with_source_options(
        variant: &str,
        corrupt_signature: bool,
        v2: bool,
        history_gc: bool,
        source_transport: bool,
    ) -> Self {
        let _ = env_logger::builder().is_test(true).try_init();
        let recovery: serde_json::Value = serde_json::from_str(if v2 {
            include_str!("testdata/v2-propagation-recovery.json")
        } else {
            include_str!("testdata/recovery.json")
        })
        .unwrap();
        let inclusion: serde_json::Value = serde_json::from_str(if history_gc {
            include_str!("testdata/v2-history-inclusion.json")
        } else if v2 {
            include_str!("testdata/v2-propagation-inclusion.json")
        } else {
            include_str!("testdata/inclusion.json")
        })
        .unwrap();
        let row =
            inclusion["rows"].as_array().unwrap().iter().find(|r| r["name"] == variant).unwrap();
        let master = fixture_block(row);
        let mut carrier = fixture_carrier(row);
        if corrupt_signature {
            carrier.signatures[0].signature[0] ^= 1;
        }
        let proof = full_proof(&master, carrier);
        let shard = fixture_block(&recovery["rows"][0]);
        let mc_data = decode(&recovery["state_boc"]);
        let mc_root = read_single_root_boc(&mc_data).unwrap();
        let anchor = BlockIdExt::with_params(
            ShardIdent::masterchain(),
            0,
            mc_root.repr_hash().clone(),
            UInt256::calc_file_hash(&mc_data),
        );
        let (master, proof, master_state_root) = if source_transport {
            persistent_closure_engine_tests::source_bootstrap(&anchor, &mc_root)
        } else {
            (
                master,
                proof,
                read_single_root_boc(&decode(&row["state_boc"])).unwrap().repr_hash().clone(),
            )
        };
        let dir = tempfile::tempdir().unwrap();
        let receiver_dir = dir.path().join("receiver");
        let provider_dir = dir.path().join("provider");
        write_recovery_config(&receiver_dir, &anchor, true);
        write_recovery_config(&provider_dir, &anchor, true);
        let observer_dir = source_transport.then(|| dir.path().join("observer"));
        if let Some(path) = &observer_dir {
            write_recovery_config(path, &anchor, true);
        }
        if v2 {
            // The provider is a governing validator transport. The receiver is
            // a public observer outside that committee, so normal T0 policy
            // receives rather than marking both nodes as original senders.
            // No test manually activates Plumtree or bypasses an authority check.
            let mut configurations = vec![
                (&provider_dir, 0x60),
                (&receiver_dir, if source_transport { 0x61 } else { 0x70 }),
            ];
            if let Some(path) = &observer_dir {
                configurations.push((path, 0x70));
            }
            for (dir, seed) in configurations {
                let file = dir.join("config.json");
                let mut config: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
                let (key, transport) =
                    Ed25519KeyOption::<ZeroizingBytes>::from_private_key_with_json(&[seed; 32])
                        .unwrap();
                for entry in config["adnl_node"]["keys"].as_array_mut().unwrap() {
                    if entry["tag"] == NodeNetwork::TAG_OVERLAY_KEY {
                        entry["data"] = serde_json::to_value(&key).unwrap();
                    }
                }
                if source_transport && seed != 0x70 {
                    // The normal source factory requires an explicit stable
                    // validator -> transport binding. Derive it from the actual
                    // governing state and persist it for the cold-open phase.
                    let governing = ShardStateUnsplit::construct_from_cell(mc_root.clone())
                        .unwrap()
                        .read_custom()
                        .unwrap()
                        .unwrap()
                        .config;
                    let validator = governing
                        .validator_set()
                        .unwrap()
                        .list()
                        .iter()
                        .find(|member| member.adnl_addr().is_ok_and(|id| id == *transport.id()))
                        .expect("source circulation key must belong to the governing committee")
                        .validator_id()
                        .unwrap();
                    config["validator_key_ring"][base64_encode(transport.id().data())] =
                        serde_json::to_value(&key).unwrap();
                    config["consensus_transport_bindings"] = serde_json::json!([{
                        "validator_id": base64_encode(validator.as_slice()),
                        "adnl_key_id": base64_encode(transport.id().data()),
                    }]);
                }
                let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                config["ip_address_quic"] = socket.local_addr().unwrap().to_string().into();
                drop(socket);
                std::fs::write(file, serde_json::to_vec(&config).unwrap()).unwrap();
            }
        }
        if history_gc {
            for dir in [&receiver_dir, &provider_dir] {
                let file = dir.join("config.json");
                let mut config: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
                config["gc"] = serde_json::json!({"enable_for_archives": false,
                    "enable_for_shard_state_persistent": false,
                    "cells_gc_config": {"gc_interval_sec": 1, "cells_lifetime_sec": 0}});
                std::fs::write(file, serde_json::to_vec(&config).unwrap()).unwrap();
            }
        }
        let receiver = open_engine(&receiver_dir).await;
        let provider = open_engine(&provider_dir).await;
        let observer = match &observer_dir {
            Some(path) => Some(open_engine(path).await),
            None => None,
        };
        let mut engines = vec![&receiver, &provider];
        let mut routes = vec![(&receiver, &provider), (&provider, &receiver)];
        if let Some(observer) = &observer {
            engines.push(observer);
            routes.extend([
                (&provider, observer),
                (observer, &provider),
                (&receiver, observer),
                (observer, &receiver),
            ]);
        }
        let setup = std::panic::AssertUnwindSafe(async {
            if v2 {
                // Private overlay creation requires a real ADNL route already
                // present. Bootstrap transport reachability before normal config
                // creates either public or fast overlays; do not bypass membership.
                for &(local, remote) in &routes {
                    let local_adnl = &local.network().context().stack.adnl;
                    let remote_adnl = &remote.network().context().stack.adnl;
                    let local_key = local_adnl.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY).unwrap();
                    let remote_key = remote_adnl.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY).unwrap();
                    local_adnl
                        .add_peer(local_key.id(), remote_adnl.ip_address_adnl(), None, &remote_key)
                        .unwrap();
                    local
                        .network()
                        .context()
                        .stack
                        .quic
                        .as_ref()
                        .unwrap()
                        .add_peer_key(
                            remote_key.id().clone(),
                            remote.network().context().quic_address.unwrap(),
                        )
                        .unwrap();
                }
            }
            for &engine in &engines {
                for bytes in [&mc_data, &decode(&recovery["prev_state_boc"])] {
                    let root = read_single_root_boc(bytes).unwrap();
                    let state = ShardStateUnsplit::construct_from_cell(root.clone()).unwrap();
                    let id = BlockIdExt::with_params(
                        state.shard().clone(),
                        state.seq_no(),
                        root.repr_hash().clone(),
                        UInt256::calc_file_hash(bytes),
                    );
                    let state = ShardStateStuff::from_root_cell(
                        id,
                        root,
                        #[cfg(feature = "telemetry")]
                        engine.engine_telemetry(),
                        engine.engine_allocated(),
                    )
                    .unwrap();
                    let (_, handle) = engine.store_zerostate(state, bytes).await.unwrap();
                    // Match boot.rs::download_zerostate: trusted bootstrap states are
                    // already applied. Successor blocks must still apply normally.
                    assert_eq!(handle.id().seq_no(), 0);
                    engine.set_applied(&handle, 0).await.unwrap();
                }
                engine.save_last_applied_mc_block_id(&anchor).unwrap();
                engine.save_shard_client_mc_block_id(&anchor).unwrap();
                assert!(!crate::network::check_sync_for_listen_bcasts(engine.as_ref()));
                engine.set_test_chain_time(Some(1002));
                assert!(crate::network::check_sync_for_listen_bcasts(engine.as_ref()));
                engine.initialize_test_full_node_overlays().await.unwrap();
                if v2 {
                    engine
                        .overlays_router()
                        .unwrap()
                        .refresh_fast_sync_from_applied_state()
                        .await
                        .unwrap();
                }
            }
            let handle = provider.store_block(&shard).await.unwrap().to_any();
            let link = crate::validator::accept_block::create_new_proof_link(&shard).unwrap();
            provider.store_block_proof(shard.id(), Some(handle), &link).await.unwrap();
            let handle = provider.store_block(&master).await.unwrap().to_any();
            provider.store_block_proof(master.id(), Some(handle), &proof).await.unwrap();
            provider
                .store_block_next1(
                    &provider.load_block_handle(&anchor).unwrap().unwrap(),
                    master.id(),
                )
                .unwrap();
            for &(local, remote) in &routes {
                let local_adnl = &local.network().context().stack.adnl;
                let remote_adnl = &remote.network().context().stack.adnl;
                let local_key = local_adnl.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY).unwrap();
                let remote_key = remote_adnl.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY).unwrap();
                if v2 {
                    // Isolated nodes have no external DHT. Supply the peer's actual
                    // advertised route; local endpoint binding still belongs solely
                    // to normal production configuration activation.
                    local
                        .network()
                        .context()
                        .stack
                        .quic
                        .as_ref()
                        .unwrap()
                        .add_peer_key(
                            remote_key.id().clone(),
                            remote.network().context().quic_address.unwrap(),
                        )
                        .unwrap();
                }
                let peer = local_adnl
                    .add_peer(local_key.id(), remote_adnl.ip_address_adnl(), None, &remote_key)
                    .unwrap()
                    .unwrap_or_else(|| remote_key.id().clone());
                for shard_id in [shard.id().shard(), anchor.shard()] {
                    let client = local.overlay_client(shard_id).await.unwrap();
                    client.overlay_client().neighbours().add(peer.clone()).unwrap();
                }
            }
            refresh_fixture_public_advertisements(&engines, &[shard.id().shard(), anchor.shard()])
                .await;
        })
        .catch_unwind()
        .await;
        if let Err(panic) = setup {
            stop_fixture_engines(engines.iter().map(|engine| (*engine).clone()).collect()).await;
            std::panic::resume_unwind(panic);
        }
        drop(routes);
        drop(engines);
        Self {
            _dir: dir,
            receiver,
            provider,
            observer,
            anchor,
            shard,
            shard_carrier: fixture_carrier(&recovery["rows"][0]),
            shard_state_root: read_single_root_boc(&decode(&recovery["next_state_boc"]))
                .unwrap()
                .repr_hash()
                .clone(),
            master,
            master_state_root,
        }
    }

    async fn apply_by_normal_clients(
        &self,
    ) -> (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>) {
        assert!(self.receiver.load_block_handle(self.master.id()).unwrap().is_none());
        let ops: Arc<dyn EngineOperations> = self.receiver.clone();
        let master = crate::full_node::shard_client::start_masterchain_client(
            ops.clone(),
            self.anchor.clone(),
        )
        .unwrap();
        let shards =
            crate::full_node::shard_client::start_shards_client(ops, self.anchor.clone()).unwrap();
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if self.receiver.load_shard_client_mc_block_id().unwrap().as_deref()
                    == Some(self.master.id())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("normal authenticated masterchain and shard clients must advance");
        let mc_handle = self.receiver.load_block_handle(self.master.id()).unwrap().unwrap();
        assert!(mc_handle.is_applied());
        assert_eq!(
            self.receiver.load_state(self.master.id()).await.unwrap().root_cell().repr_hash(),
            &self.master_state_root
        );
        assert_eq!(
            self.receiver.load_last_applied_mc_block_id().unwrap().as_deref(),
            Some(self.master.id())
        );
        (master, shards)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_masterchain_inclusion_downloads_and_applies_shard() {
    let pair = Pair::new("included", false).await;
    assert!(pair.receiver.load_block_handle(pair.shard.id()).unwrap().is_none());
    let (master, shards) = pair.apply_by_normal_clients().await;
    let handle = pair.receiver.load_block_handle(pair.shard.id()).unwrap().unwrap();
    assert!(handle.is_applied());
    assert_eq!(handle.masterchain_ref_seq_no(), pair.master.id().seq_no());
    assert_eq!(
        pair.receiver.load_state(pair.shard.id()).await.unwrap().root_cell().repr_hash(),
        &pair.shard_state_root
    );
    assert!(pair.receiver.try_get_cached_block_candidate(pair.shard.id()).is_none());
    assert!(pair.provider.overlays_router().unwrap().test_block_download_queries() > 0);
    pair.receiver.clone().wait_stop().await.unwrap();
    master.await.unwrap();
    shards.await.unwrap();
    pair.provider.clone().wait_stop().await.unwrap();
}

impl Pair {
    async fn enable_plumtree(&self, drop_messages: usize) -> Arc<adnl::OverlayShortId> {
        let mut addresses = vec![];
        for engine in [&self.receiver, &self.provider] {
            let stack = &engine.network().context().stack;
            let key = stack.adnl.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY).unwrap();
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let address = socket.local_addr().unwrap();
            drop(socket);
            let private = key.pvt_key().unwrap().lock().unwrap();
            stack
                .quic
                .as_ref()
                .unwrap()
                .add_key(private.as_ref().try_into().unwrap(), key.id(), address)
                .unwrap();
            addresses.push(address);
        }
        let provider_key = self
            .provider
            .network()
            .context()
            .stack
            .adnl
            .key_by_tag(NodeNetwork::TAG_OVERLAY_KEY)
            .unwrap();
        let receiver_key = self
            .receiver
            .network()
            .context()
            .stack
            .adnl
            .key_by_tag(NodeNetwork::TAG_OVERLAY_KEY)
            .unwrap();
        let client = self.receiver.overlay_client(self.shard.id().shard()).await.unwrap();
        let id = adnl::OverlayShortId::from_data(*client.overlay_client().id().data());
        let previous_advertisement_version = adnl::common::Version::get();
        for (index, engine, remote_key) in
            [(0, &self.receiver, &provider_key), (1, &self.provider, &receiver_key)]
        {
            let stack = &engine.network().context().stack;
            stack
                .quic
                .as_ref()
                .unwrap()
                .add_peer_key(remote_key.id().clone(), addresses[1 - index])
                .unwrap();
            stack
                .overlay
                .configure_plumtree(
                    &id,
                    adnl::PlumtreeConfig {
                        authorized_keys: std::collections::BTreeMap::from([(
                            *provider_key.id().data(),
                            2 << 20,
                        )]),
                        max_untrusted_size: 0,
                        untrusted_flags: 0,
                        fixed_members: true,
                        original_sender: index == 1,
                        eager_limit: 4,
                        max_retained_bytes: 64 << 20,
                        max_broadcasts: 64,
                    },
                    &tokio::runtime::Handle::current(),
                )
                .unwrap();
        }
        // The creation-time advertisements said Plumtree was disabled. Admit
        // fresh signed capabilities after activation, as public discovery does.
        // A same-second advertisement cannot supersede the cached version.
        tokio::time::timeout(Duration::from_secs(2), async {
            while adnl::common::Version::get() <= previous_advertisement_version {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("public advertisement version must advance after Plumtree activation");
        self.refresh_public_advertisements().await;
        let prefix = rtos_api::serialize_boxed(
            &rtos_api::ton::overlay::message::Message { overlay: UInt256::from(*id.data()) }
                .into_boxed(),
        )
        .unwrap();
        self.receiver.network().test_broadcast_faults.configure(
            *provider_key.id().data(),
            prefix,
            drop_messages,
        );
        id
    }

    async fn publish(&self, overlay: &Arc<adnl::OverlayShortId>, id: [u8; 32], data: &[u8]) {
        let stack = &self.provider.network().context().stack;
        let signer = stack.adnl.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY).unwrap();
        stack
            .overlay
            .broadcast_plumtree(
                overlay,
                &signer,
                rtos_api::ton::overlay::Certificate::Overlay_EmptyCertificate,
                0,
                Some(id),
                data,
            )
            .await
            .unwrap();
    }

    fn finality_wire(&self) -> (Vec<u8>, [u8; 32]) {
        let signature_set = PqNetworkSignatureSet::from_final_fields(&self.shard_carrier)
            .unwrap()
            .to_node()
            .into_boxed();
        let carrier = rtos_api::ton::ton_node::broadcast::BlockFinalityBroadcast {
            id: self.shard.id().clone(),
            signature_set: signature_set.clone(),
        }
        .into_boxed();
        let wire = WireProfile::T0.serialize(&carrier).unwrap();
        let identifier = rtos_api::ton::ton_node::finalitybroadcastid::FinalityBroadcastId {
            id: self.shard.id().clone(),
        }
        .into_boxed();
        let mut identity = WireProfile::T0.serialize(&identifier).unwrap();
        identity.extend_from_slice(
            UInt256::calc_file_hash(&WireProfile::T0.serialize(&signature_set).unwrap()).as_slice(),
        );
        let hash = UInt256::calc_file_hash(&identity);
        (wire, *hash.as_array())
    }

    async fn wait_preapplied(&self) {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if self
                    .receiver
                    .load_block_handle(self.shard.id())
                    .unwrap()
                    .is_some_and(|handle| handle.has_state())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("actual Plumtree delivery must reach Engine recovery");
        let handle = self.receiver.load_block_handle(self.shard.id()).unwrap().unwrap();
        assert!(!handle.is_applied());
        assert_eq!(
            self.receiver.load_state(self.shard.id()).await.unwrap().root_cell().repr_hash(),
            &self.shard_state_root
        );
        assert!(self.receiver.try_get_cached_block_candidate(self.shard.id()).is_none());
    }

    async fn finish(
        self,
        master: tokio::task::JoinHandle<()>,
        shards: tokio::task::JoinHandle<()>,
    ) {
        tokio::time::timeout(Duration::from_secs(15), self.receiver.clone().wait_stop())
            .await
            .expect("real MC/shard services must drain")
            .unwrap();
        master.await.unwrap();
        shards.await.unwrap();
        self.provider.clone().wait_stop().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_plumtree_finality_stays_preapplied_until_authenticated_mc_inclusion() {
    let pair = Pair::new("included", false).await;
    let overlay = pair.enable_plumtree(0).await;
    let (wire, id) = pair.finality_wire();
    pair.publish(&overlay, id, &wire).await;
    pair.wait_preapplied().await;
    let (master, shards) = pair.apply_by_normal_clients().await;
    let handle = pair.receiver.load_block_handle(pair.shard.id()).unwrap().unwrap();
    assert!(handle.is_applied());
    assert_eq!(handle.masterchain_ref_seq_no(), 1);
    assert!(pair.provider.overlays_router().unwrap().test_block_download_queries() > 0);
    pair.finish(master, shards).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lost_real_plumtree_notification_is_repaired_by_normal_masterchain_discovery() {
    let pair = Pair::new("included", false).await;
    let overlay = pair.enable_plumtree(usize::MAX).await;
    let (wire, id) = pair.finality_wire();
    pair.publish(&overlay, id, &wire).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if pair.receiver.network().test_broadcast_faults.receipts().iter().any(|r| r.dropped) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("fault must drop an actually received authenticated-transport frame");
    assert!(pair.receiver.load_block_handle(pair.shard.id()).unwrap().is_none());
    assert_eq!(pair.receiver.pending_finality.lock().workers, 0);
    let (master, shards) = pair.apply_by_normal_clients().await;
    let handle = pair.receiver.load_block_handle(pair.shard.id()).unwrap().unwrap();
    assert!(handle.is_applied());
    assert_eq!(handle.masterchain_ref_seq_no(), 1);
    assert!(pair.receiver.try_get_cached_block_candidate(pair.shard.id()).is_none());
    assert!(pair.provider.overlays_router().unwrap().test_block_download_queries() > 0);
    assert!(pair.receiver.network().test_broadcast_faults.receipts().iter().all(|r| r.dropped));
    pair.finish(master, shards).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_consumer_queue_loses_seen_notification_then_masterchain_repairs_it() {
    let pair = Pair::new("included", false).await;
    let overlay = pair.enable_plumtree(0).await;
    use rtos_api::Constructor;
    let receiver_key = pair
        .receiver
        .network()
        .context()
        .stack
        .adnl
        .key_by_tag(NodeNetwork::TAG_OVERLAY_KEY)
        .unwrap();
    let prefix = rtos_api::serialize_boxed(
        &rtos_api::ton::overlay::message::Message { overlay: UInt256::from(*overlay.data()) }
            .into_boxed(),
    )
    .unwrap();
    pair.provider.network().test_broadcast_faults.configure(*receiver_key.id().data(), prefix, 0);
    let client = pair.receiver.overlay_client(pair.shard.id().shard()).await.unwrap();
    let gate = client.pause_test_consumer();
    let filler = WireProfile::T0
        .serialize(
            &rtos_api::ton::ton_node::broadcast::IhrMessageBroadcast {
                message: rtos_api::ton::ton_node::ihrmessage::IhrMessage { data: vec![1].into() },
            }
            .into_boxed(),
        )
        .unwrap();
    // Wake a consumer already blocked in pop, and establish the real eager path.
    pair.publish(&overlay, [1; 32], &filler).await;
    tokio::time::timeout(Duration::from_secs(5), gate.wait_entered()).await.unwrap();
    // Consumer progress precedes the sender's Useful acknowledgement. Wait for
    // actual production dispatch, not a sleep or a synthetic eager-state edit.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if pair.provider.network().test_broadcast_faults.receipts().iter().any(|receipt| {
                receipt.constructor == rtos_api::ton::overlay::broadcast::BroadcastPlumtreeUseful::constructor_const()
                    && !receipt.dropped && receipt.error.is_none()
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await.expect("primer must establish the real Useful/eager handshake");
    for index in 0..16u8 {
        let id = [index + 2; 32];
        pair.publish(&overlay, id, &filler).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(receipt) = pair
                    .receiver
                    .network()
                    .test_broadcast_faults
                    .receipts()
                    .into_iter()
                    .find(|r| r.simple_id == Some(id))
                {
                    assert!(!receipt.dropped);
                    assert!(
                        receipt.error.is_none(),
                        "queue filled before sixteen entries: {:?}",
                        receipt
                    );
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("fill must use a real eager Plumtree payload, not only an advertisement");
    }
    let (wire, id) = pair.finality_wire();
    pair.publish(&overlay, id, &wire).await;
    let rejected = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(receipt) = pair
                .receiver
                .network()
                .test_broadcast_faults
                .receipts()
                .into_iter()
                .find(|r| r.simple_id == Some(id))
            {
                break receipt;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(!rejected.dropped);
    assert!(
        rejected.error.as_deref().is_some_and(|e| e.contains("bounded queue is full")),
        "must observe actual queue overflow: {rejected:?}"
    );
    assert!(!rejected.wire.is_empty());
    assert_eq!(
        pair.receiver.test_finality_notifications.load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    assert!(pair.receiver.load_block_handle(pair.shard.id()).unwrap().is_none());
    gate.release();
    // Re-send the exact authenticated wire frame through real QUIC. It is already
    // seen by Plumtree even though the application queue rejected its delivery.
    let stack = &pair.provider.network().context().stack;
    let local = stack.adnl.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY).unwrap();
    let remote = pair
        .receiver
        .network()
        .context()
        .stack
        .adnl
        .key_by_tag(NodeNetwork::TAG_OVERLAY_KEY)
        .unwrap();
    stack
        .quic
        .as_ref()
        .unwrap()
        .message(
            rejected.wire,
            Some(&stack.adnl),
            &adnl::common::AdnlPeers::with_keys(local.id().clone(), remote.id().clone()),
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let receipts = pair.receiver.network().test_broadcast_faults.receipts();
            let repeated: Vec<_> = receipts.iter().filter(|r| r.simple_id == Some(id)).collect();
            if repeated.len() >= 2 {
                assert!(repeated.last().unwrap().error.is_none());
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let (master, shards) = pair.apply_by_normal_clients().await;
    assert_eq!(
        pair.receiver.test_finality_notifications.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "seen notification must not be redelivered after local queue capacity returns"
    );
    let handle = pair.receiver.load_block_handle(pair.shard.id()).unwrap().unwrap();
    assert!(handle.is_applied());
    assert_eq!(handle.masterchain_ref_seq_no(), 1);
    assert!(pair.receiver.try_get_cached_block_candidate(pair.shard.id()).is_none());
    assert!(pair.provider.overlays_router().unwrap().test_block_download_queries() > 0);
    pair.finish(master, shards).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_masterchain_omission_does_not_apply_preapplied_shard() {
    let pair = Pair::new("omitted", false).await;
    let overlay = pair.enable_plumtree(0).await;
    let (wire, id) = pair.finality_wire();
    pair.publish(&overlay, id, &wire).await;
    pair.wait_preapplied().await;
    let (master, shards) = pair.apply_by_normal_clients().await;
    assert!(!pair.receiver.load_block_handle(pair.shard.id()).unwrap().unwrap().is_applied());
    pair.finish(master, shards).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_masterchain_proof_or_state_cannot_apply_preapplied_shard() {
    for (variant, corrupt_signature) in [("included", true), ("bad-old-state", false)] {
        let pair = Pair::new(variant, corrupt_signature).await;
        let overlay = pair.enable_plumtree(0).await;
        let (wire, id) = pair.finality_wire();
        pair.publish(&overlay, id, &wire).await;
        pair.wait_preapplied().await;
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            pair.receiver.clone().download_and_apply_block(pair.master.id(), 1, false),
        )
        .await
        .unwrap();
        assert!(
            result.is_err(),
            "invalid masterchain {variant} must fail normal network authentication/application"
        );
        if corrupt_signature {
            assert!(
                pair.receiver.load_block_handle(pair.master.id()).unwrap().is_none(),
                "invalid certificate cannot authorize data/proof storage"
            );
        } else {
            let handle = pair.receiver.load_block_handle(pair.master.id()).unwrap().unwrap();
            assert!(!handle.has_state());
            assert!(!handle.is_applied());
        }
        assert_eq!(
            pair.receiver.load_last_applied_mc_block_id().unwrap().as_deref(),
            Some(&pair.anchor)
        );
        assert_eq!(
            pair.receiver.load_shard_client_mc_block_id().unwrap().as_deref(),
            Some(&pair.anchor)
        );
        assert!(!pair.receiver.load_block_handle(pair.shard.id()).unwrap().unwrap().is_applied());
        pair.receiver.clone().wait_stop().await.unwrap();
        pair.provider.clone().wait_stop().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn changed_masterchain_inclusion_descriptor_fails_real_download_authentication() {
    let pair = Pair::new("included", false).await;
    let inclusion: serde_json::Value =
        serde_json::from_str(include_str!("testdata/inclusion.json")).unwrap();
    let rows = inclusion["rows"].as_array().unwrap();
    let omitted = fixture_block(rows.iter().find(|r| r["name"] == "omitted").unwrap());
    let mut block = Block::construct_from_cell(pair.master.root_cell().clone()).unwrap();
    let mut extra = block.read_extra().unwrap();
    let mut custom = extra.read_custom().unwrap().unwrap();
    *custom.shards_mut() = omitted
        .block()
        .unwrap()
        .read_extra()
        .unwrap()
        .read_custom()
        .unwrap()
        .unwrap()
        .shards()
        .clone();
    extra.write_custom(&custom).unwrap();
    block.write_extra(&extra).unwrap();
    let altered = fixture_block(
        &serde_json::json!({"block_boc":hex::encode(block.write_to_bytes().unwrap())}),
    );
    assert_ne!(altered.id(), pair.master.id());
    let carrier = fixture_carrier(rows.iter().find(|r| r["name"] == "included").unwrap());
    let proof = full_proof(&altered, carrier);
    let handle = pair.provider.store_block(&altered).await.unwrap().to_any();
    pair.provider.store_block_proof(altered.id(), Some(handle), &proof).await.unwrap();
    let error = tokio::time::timeout(
        Duration::from_secs(15),
        pair.receiver.clone().download_and_apply_block(altered.id(), 1, false),
    )
    .await
    .unwrap();
    assert!(error.is_err());
    assert!(pair.receiver.load_block_handle(altered.id()).unwrap().is_none());
    assert!(pair.receiver.load_block_handle(pair.shard.id()).unwrap().is_none());
    assert_eq!(
        pair.receiver.load_last_applied_mc_block_id().unwrap().as_deref(),
        Some(&pair.anchor)
    );
    assert_eq!(
        pair.receiver.load_shard_client_mc_block_id().unwrap().as_deref(),
        Some(&pair.anchor)
    );
    assert!(pair.provider.overlays_router().unwrap().test_block_download_queries() > 0);
    pair.receiver.clone().wait_stop().await.unwrap();
    pair.provider.clone().wait_stop().await.unwrap();
}

/// Four real Engines: publisher, receiver and two independent repair relays.
/// The receiver loses the publisher's IHAVE; the first relay reply is discarded
/// only after the production overlay has authenticated and built it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_multinode_plumtree_repairs_lost_ihave_and_first_repair_response() {
    use crate::network::test_broadcast_faults::RepairReceipts;
    use std::sync::atomic::Ordering;
    let pair = Pair::new("included", false).await;
    let relays = Pair::new("included", false).await;
    let engines = [&pair.provider, &pair.receiver, &relays.receiver, &relays.provider];
    let client = pair.receiver.overlay_client(pair.shard.id().shard()).await.unwrap();
    let overlay = adnl::OverlayShortId::from_data(*client.overlay_client().id().data());
    let keys: Vec<_> = engines
        .iter()
        .map(|engine| {
            engine.network().context().stack.adnl.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY).unwrap()
        })
        .collect();
    let mut addresses = vec![];
    for (engine, key) in engines.iter().zip(&keys) {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        drop(socket);
        let private = key.pvt_key().unwrap().lock().unwrap();
        engine
            .network()
            .context()
            .stack
            .quic
            .as_ref()
            .unwrap()
            .add_key(private.as_ref().try_into().unwrap(), key.id(), address)
            .unwrap();
        addresses.push(address);
    }
    for (index, engine) in engines.iter().enumerate() {
        let stack = &engine.network().context().stack;
        for (remote_index, remote) in engines.iter().enumerate() {
            if index == remote_index {
                continue;
            }
            let remote_stack = &remote.network().context().stack;
            let peer = stack
                .adnl
                .add_peer(
                    keys[index].id(),
                    remote_stack.adnl.ip_address_adnl(),
                    None,
                    &keys[remote_index],
                )
                .unwrap()
                .unwrap();
            engine
                .overlay_client(pair.shard.id().shard())
                .await
                .unwrap()
                .overlay_client()
                .neighbours()
                .add(peer)
                .unwrap();
            let advertisement = remote_stack.overlay.get_signed_node(&overlay, false).unwrap();
            stack
                .overlay
                .add_public_peer(remote_stack.adnl.ip_address_adnl(), &advertisement, &overlay)
                .unwrap()
                .unwrap();
            stack
                .quic
                .as_ref()
                .unwrap()
                .add_peer_key(keys[remote_index].id().clone(), addresses[remote_index])
                .unwrap();
        }
        stack
            .overlay
            .configure_plumtree(
                &overlay,
                adnl::PlumtreeConfig {
                    authorized_keys: std::collections::BTreeMap::from([(
                        *keys[0].id().data(),
                        2 << 20,
                    )]),
                    max_untrusted_size: 0,
                    untrusted_flags: 0,
                    fixed_members: true,
                    original_sender: index == 0,
                    eager_limit: 4,
                    max_retained_bytes: 64 << 20,
                    max_broadcasts: 64,
                },
                &tokio::runtime::Handle::current(),
            )
            .unwrap();
    }
    let prefix = rtos_api::serialize_boxed(
        &rtos_api::ton::overlay::message::Message { overlay: UInt256::from(*overlay.data()) }
            .into_boxed(),
    )
    .unwrap();
    let faults = &pair.receiver.network().test_broadcast_faults;
    faults.configure(*keys[0].id().data(), prefix, 1);
    faults.drop_one_ihave();
    let replies = Arc::new(RepairReceipts::default());
    for relay in [&relays.receiver, &relays.provider] {
        relay
            .network()
            .test_broadcast_faults
            .suppress_first_repair_reply(*keys[1].id().data(), replies.clone());
    }
    let (wire, id) = pair.finality_wire();
    pair.publish(&overlay, id, &wire).await;
    pair.wait_preapplied().await;
    assert_eq!(
        faults.receipts().iter().filter(|receipt| receipt.dropped).count(),
        1,
        "the real publisher IHAVE must be lost"
    );
    assert_eq!(
        replies.dropped.load(Ordering::Acquire),
        1,
        "the first real relay reply must be lost after authentication"
    );
    assert!(
        replies.delivered.load(Ordering::Acquire) >= 1,
        "another real relay must answer the production fallback query"
    );
    assert_eq!(pair.receiver.test_finality_notifications.load(Ordering::Acquire), 1);
    assert!(pair.receiver.try_get_cached_block_candidate(pair.shard.id()).is_none());
    let (master, shards) = pair.apply_by_normal_clients().await;
    assert!(pair.receiver.load_block_handle(pair.shard.id()).unwrap().unwrap().is_applied());
    pair.finish(master, shards).await;
    relays.receiver.clone().wait_stop().await.unwrap();
    relays.provider.clone().wait_stop().await.unwrap();
}

// Separate from Pair: this fixture never installs the old network block or MC
// successor, and exercises durable local acceptance with publication disabled.
struct SpoolFixture {
    dir: tempfile::TempDir,
    engine: Arc<Engine>,
    runtime: Arc<consensus_common::session_runtime::AuthenticatedSessionRuntime>,
    block: BlockStuff,
    row: serde_json::Value,
    state_root: UInt256,
}

impl SpoolFixture {
    async fn new(row_index: usize) -> Self {
        Self::new_for_transport(row_index, 0x61).await
    }

    async fn new_for_transport(row_index: usize, transport_seed: u8) -> Self {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("testdata/v2-publication-spool.json")).unwrap();
        Self::from_transport_fixture(fixture, row_index, transport_seed).await
    }

    async fn from_transport_fixture(
        fixture: serde_json::Value,
        row_index: usize,
        transport_seed: u8,
    ) -> Self {
        use consensus_common::session_runtime::{AuthenticatedSessionRuntime, SessionNetworkPin};
        let row = fixture["rows"][row_index].clone();
        let block = fixture_block(&row);
        let mc_data = decode(&fixture["state_boc"]);
        let mc_root = read_single_root_boc(&mc_data).unwrap();
        let anchor = BlockIdExt::with_params(
            ShardIdent::masterchain(),
            0,
            mc_root.repr_hash().clone(),
            UInt256::calc_file_hash(&mc_data),
        );
        let dir = tempfile::tempdir().unwrap();
        write_recovery_config(dir.path(), &anchor, true);
        let file = dir.path().join("config.json");
        let mut config: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        let (key_json, key) =
            Ed25519KeyOption::<ZeroizingBytes>::from_private_key_with_json(&[transport_seed; 32])
                .unwrap();
        let governing = ConfigParams::construct_from_cell(
            read_single_root_boc(&decode(&fixture["config_boc"])).unwrap(),
        )
        .unwrap();
        let validator = governing
            .validator_set()
            .unwrap()
            .list()
            .iter()
            .find(|member| member.adnl_addr().is_ok_and(|id| id == *key.id()))
            .expect("fixture transport must bind to its real governing identity")
            .validator_id()
            .unwrap();
        config["ip_address_quic"] = "127.0.0.1:0".into();
        config["validator_key_ring"][base64_encode(key.id().data())] =
            serde_json::to_value(key_json).unwrap();
        config["consensus_transport_bindings"] = serde_json::json!([{
            "validator_id":base64_encode(validator.as_slice()),
            "adnl_key_id":base64_encode(key.id().data()),
        }]);
        std::fs::write(file, serde_json::to_vec(&config).unwrap()).unwrap();
        let engine = open_engine(dir.path()).await;
        let setup = std::panic::AssertUnwindSafe(async {
            assert!(engine.adnl_key_by_id(key.id()).is_some(), "normal explicit key loading");
            assert!(!engine.network().config_handler().get_validator_status());
            for bytes in [&mc_data, &decode(&fixture["prev_state_boc"])] {
                let root = read_single_root_boc(bytes).unwrap();
                let state = ShardStateUnsplit::construct_from_cell(root.clone()).unwrap();
                let id = BlockIdExt::with_params(
                    state.shard().clone(),
                    state.seq_no(),
                    root.repr_hash().clone(),
                    UInt256::calc_file_hash(bytes),
                );
                let state = ShardStateStuff::from_root_cell(
                    id,
                    root,
                    #[cfg(feature = "telemetry")]
                    engine.engine_telemetry(),
                    engine.engine_allocated(),
                )
                .unwrap();
                let (_, handle) = engine.store_zerostate(state, bytes).await.unwrap();
                assert_eq!(handle.id().seq_no(), 0);
                engine.set_applied(&handle, 0).await.unwrap();
            }
            engine.save_last_applied_mc_block_id(&anchor).unwrap();
            engine.save_shard_client_mc_block_id(&anchor).unwrap();
            engine.set_test_chain_time(Some(1002));
            engine.initialize_test_full_node_overlays().await.unwrap();
            engine.overlays_router().unwrap().refresh_fast_sync_from_applied_state().await.unwrap();
            let state = engine.load_state(&anchor).await.unwrap();
            let config = state.config_params().unwrap();
            let (committee, _) = config
                .validator_set()
                .unwrap()
                .calc_subset(&config.catchain_config().unwrap(), SHARD_FULL, 0, 7)
                .unwrap();
            let runtime = AuthenticatedSessionRuntime::from_authenticated_config(
                SessionNetworkPin { global_id: -239, zerostate: anchor.clone() },
                config,
                rtos_api::session_identity::SessionCoordinates {
                    shard: block.id().shard(),
                    catchain_seqno: 7,
                    vertical_seqno: 0,
                    last_key_block_seqno: 0,
                    new_catchain_ids: false,
                },
                committee,
                key.id().clone(),
            )
            .unwrap()
            .bind_recovery_anchor(anchor.clone())
            .unwrap();
            let expected_index = runtime
                .committee()
                .iter()
                .position(|member| member.adnl_addr().is_ok_and(|id| id == *key.id()))
                .unwrap() as u32;
            assert_eq!(
                runtime.local_role(),
                consensus_common::session_runtime::LocalRole::Validator(expected_index)
            );
            assert_eq!(runtime.session_id(), &UInt256::from_slice(&decode(&row["session"])));
            Arc::new(runtime)
        })
        .catch_unwind()
        .await;
        let runtime = match setup {
            Ok(runtime) => runtime,
            Err(panic) => {
                engine.clone().wait_stop().await.unwrap();
                std::panic::resume_unwind(panic)
            }
        };
        let state_root =
            read_single_root_boc(&decode(&fixture["next_state_boc"])).unwrap().repr_hash().clone();
        Self { dir, engine, runtime, block, row, state_root }
    }
}

#[path = "propagation_tests.rs"]
mod propagation_tests;

#[path = "retired_service_tests.rs"]
mod retired_service_tests;

#[path = "history_gc_tests.rs"]
mod history_gc_tests;

#[path = "publication_repair_tests.rs"]
mod publication_repair_tests;

#[path = "bounded_download_tests.rs"]
mod bounded_download_tests;

#[path = "persistent_closure_engine_tests.rs"]
mod persistent_closure_engine_tests;

#[path = "bounded_pss_tests.rs"]
mod bounded_pss_tests;
