// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::block_proof::BlockProofStuff;
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
    anchor: BlockIdExt,
    shard: BlockStuff,
    shard_carrier: BlockSignaturesSimplexPq,
    shard_state_root: UInt256,
    master: BlockStuff,
    master_state_root: UInt256,
}

impl Pair {
    async fn new(variant: &str, corrupt_signature: bool) -> Self {
        let recovery: serde_json::Value =
            serde_json::from_str(include_str!("testdata/recovery.json")).unwrap();
        let inclusion: serde_json::Value =
            serde_json::from_str(include_str!("testdata/inclusion.json")).unwrap();
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
        let dir = tempfile::tempdir().unwrap();
        let receiver_dir = dir.path().join("receiver");
        let provider_dir = dir.path().join("provider");
        write_recovery_config(&receiver_dir, &anchor, true);
        write_recovery_config(&provider_dir, &anchor, true);
        let receiver = open_engine(&receiver_dir).await;
        let provider = open_engine(&provider_dir).await;
        for engine in [&receiver, &provider] {
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
                engine.store_zerostate(state, bytes).await.unwrap();
            }
            engine.save_last_applied_mc_block_id(&anchor).unwrap();
            engine.save_shard_client_mc_block_id(&anchor).unwrap();
            assert!(!crate::network::check_sync_for_listen_bcasts(engine.as_ref()));
            engine.set_test_chain_time(Some(1002));
            assert!(crate::network::check_sync_for_listen_bcasts(engine.as_ref()));
            engine.initialize_test_full_node_overlays().await.unwrap();
        }
        let handle = provider.store_block(&shard).await.unwrap().to_any();
        let link = crate::validator::accept_block::create_new_proof_link(&shard).unwrap();
        provider.store_block_proof(shard.id(), Some(handle), &link).await.unwrap();
        let handle = provider.store_block(&master).await.unwrap().to_any();
        provider.store_block_proof(master.id(), Some(handle), &proof).await.unwrap();
        provider
            .store_block_next1(&provider.load_block_handle(&anchor).unwrap().unwrap(), master.id())
            .unwrap();
        for (local, remote) in [(&receiver, &provider), (&provider, &receiver)] {
            let local_adnl = &local.network().context().stack.adnl;
            let remote_adnl = &remote.network().context().stack.adnl;
            let local_key = local_adnl.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY).unwrap();
            let remote_key = remote_adnl.key_by_tag(NodeNetwork::TAG_OVERLAY_KEY).unwrap();
            let peer = local_adnl
                .add_peer(local_key.id(), remote_adnl.ip_address_adnl(), None, &remote_key)
                .unwrap()
                .unwrap();
            for shard_id in [shard.id().shard(), anchor.shard()] {
                let client = local.overlay_client(shard_id).await.unwrap();
                client.overlay_client().neighbours().add(peer.clone()).unwrap();
                let id = adnl::OverlayShortId::from_data(*client.overlay_client().id().data());
                let advertised =
                    remote.network().context().stack.overlay.get_signed_node(&id, false).unwrap();
                local
                    .network()
                    .context()
                    .stack
                    .overlay
                    .add_public_peer(remote_adnl.ip_address_adnl(), &advertised, &id)
                    .unwrap()
                    .unwrap();
            }
        }
        Self {
            _dir: dir,
            receiver,
            provider,
            anchor,
            shard,
            shard_carrier: fixture_carrier(&recovery["rows"][0]),
            shard_state_root: read_single_root_boc(&decode(&recovery["next_state_boc"]))
                .unwrap()
                .repr_hash()
                .clone(),
            master,
            master_state_root: read_single_root_boc(&decode(&row["state_boc"]))
                .unwrap()
                .repr_hash()
                .clone(),
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
                if self.receiver.load_shard_client_mc_block_id().unwrap().as_ref()
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
            self.receiver.load_last_applied_mc_block_id().unwrap().as_ref(),
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
            signature_set,
        }
        .into_boxed();
        let wire = WireProfile::T0.serialize(&carrier).unwrap();
        let identifier = rtos_api::ton::ton_node::finalitybroadcastid::FinalityBroadcastId {
            id: self.shard.id().clone(),
        }
        .into_boxed();
        let hash = UInt256::calc_file_hash(&WireProfile::T0.serialize(&identifier).unwrap());
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
            pair.receiver.load_last_applied_mc_block_id().unwrap().as_ref(),
            Some(&pair.anchor)
        );
        assert_eq!(
            pair.receiver.load_shard_client_mc_block_id().unwrap().as_ref(),
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
    assert_eq!(pair.receiver.load_last_applied_mc_block_id().unwrap().as_ref(), Some(&pair.anchor));
    assert_eq!(pair.receiver.load_shard_client_mc_block_id().unwrap().as_ref(), Some(&pair.anchor));
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
