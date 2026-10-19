/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
#[cfg(feature = "telemetry")]
use crate::collator_test_bundle::create_engine_telemetry;
use crate::{
    collator_test_bundle::create_engine_allocated,
    config::TonNodeConfig,
    engine::Engine,
    engine_traits::EngineOperations,
    internal_db::{InternalDb, InternalDbConfig},
    network::{
        control::{ControlServer, DataSource, StatusReporter},
        node_network::NodeNetwork,
    },
    shard_state::ShardStateStuff,
    test_helper::{create_network, gen_master_state, init_test_log, test_async},
    validator::validator_manager::ValidationStatus,
};
use adnl::{
    client::{AdnlClient, AdnlClientConfig},
    server::AdnlServerConfig,
};
use rtos_api::{
    serialize_boxed,
    ton::{
        self,
        engine::validator::{ControlQueryError, JsonConfig, KeyHash, Stats, Success},
        rpc::engine::validator::{
            AddAdnlId, AddValidatorAdnlAddress, AddValidatorPermanentKey, ControlQuery,
            GenerateKeyPair, GetConfig, GetStats, ImportPrivateKey,
        },
    },
    AnyBoxedSerialize, TLObject,
};
use rtos_block::{base64_encode, error, fail, BlockIdExt, KeyId, Result, ShardIdent, UInt256};
use std::{
    fs::remove_dir_all,
    sync::{
        atomic::{AtomicBool, AtomicU16, AtomicU8, Ordering},
        Arc,
    },
};
use storage::block_handle_db::BlockHandle;

// key pair for server
// "pub_key": "cujCRU4rQbSw48yHVHxQtRPhUlbo+BuZggFTQSu04Y8="
// "pvt_key": "cJIxGZviebMQWL726DRejqVzRTSXPv/1sO/ab6XOZXk="

// key pair for client
// "pub_key": "RYokIiD5AFkzfTBgC6NhtAGFKm0+gwhN4suTzaW0Sjw="
// "pvt_key": "oEivbTDjSOSCgooUM0DAS2z2hIdnLw/PT82A/OFLDmA="

const ADNL_SERVER_CONFIG: &str = r#"{
    "address": "127.0.0.1:port",
    "server_key": {
        "type_id": 1209251014,
        "pvt_key": "cJIxGZviebMQWL726DRejqVzRTSXPv/1sO/ab6XOZXk="
    },
    "clients": {
        "list": [
            {
                "type_id": 1209251014,
                "pub_key": "RYokIiD5AFkzfTBgC6NhtAGFKm0+gwhN4suTzaW0Sjw=",
                "permissions": 7
            }
        ]
    }
}"#;

const ADNL_CLIENT_CONFIG: &str = r#"{
    "server_address": "127.0.0.1:port",
    "server_key": {
        "type_id": 1209251014,
        "pub_key": "cujCRU4rQbSw48yHVHxQtRPhUlbo+BuZggFTQSu04Y8="
    },
    "client_key": {
        "type_id": 1209251014,
        "pvt_key": "oEivbTDjSOSCgooUM0DAS2z2hIdnLw/PT82A/OFLDmA="
    }
}"#;

const IP_NODE: &str = "127.0.0.1:4191";

const DEFAULT_CONTROL_PORT: u16 = 4925;

async fn generate_keypair(client: &mut AdnlClient) -> Result<UInt256> {
    let answer: KeyHash = request(client, GenerateKeyPair).await?;
    Ok(answer.only().key_hash)
}

async fn import_private_key(client: &mut AdnlClient, private_key: &str) -> Result<UInt256> {
    use rtos_block::base64_decode;
    let private_key_bytes = base64_decode(private_key)?;
    let private_key = rtos_api::ton::PrivateKey::Pk_Ed25519(ton::pk::privatekey::Ed25519 {
        key: UInt256::with_array(private_key_bytes.as_slice().try_into()?),
    });
    let answer: KeyHash = request(client, ImportPrivateKey { key: private_key }).await?;
    Ok(answer.only().key_hash)
}

fn get_next_control_port() -> u16 {
    static PORT: AtomicU16 = AtomicU16::new(DEFAULT_CONTROL_PORT);
    PORT.fetch_add(1, Ordering::Relaxed)
}

async fn query(client: &mut AdnlClient, query: &TLObject) -> Result<TLObject> {
    let control_query = ControlQuery { data: serialize_boxed(query)? }.into_tl_object().into();
    match client.query(&control_query).await?.downcast::<ControlQueryError>() {
        Ok(error) => fail!("Error response to {:?}: {:?}", query, error),
        Err(answer) => Ok(answer),
    }
}

async fn request<Q, A>(client: &mut AdnlClient, request: Q) -> Result<A>
where
    A: AnyBoxedSerialize,
    Q: AnyBoxedSerialize,
{
    let boxed = request.into_tl_object();
    query(client, &boxed)
        .await?
        .downcast::<A>()
        .map_err(|answer| error!("Unsupported answer to {:?}: {:?}", boxed, answer))
}

async fn start_control_with_options(
    data_source: DataSource,
    config: Option<TonNodeConfig>,
    test_name: &str,
) -> Result<(ControlServer, AdnlClient, String, Arc<KeyId>)> {
    let network = create_network(config, Some(test_name), IP_NODE).await.unwrap();
    let key_id = network.get_key_id_by_tag(NodeNetwork::TAG_OVERLAY_KEY)?;
    let port = format!(":{}", get_next_control_port());
    let config = ADNL_SERVER_CONFIG.replace(":port", &port);
    let config = AdnlServerConfig::from_json_with_permissions(&config)?;
    let control = ControlServer::with_params(
        config,
        data_source,
        network.config_handler(),
        network.config_handler(),
        Some(&network),
    )
    .await?;
    let client_config = ADNL_CLIENT_CONFIG.replace(":port", &port);
    let (_, config) = AdnlClientConfig::from_json(&client_config)?;
    let client = AdnlClient::connect(&config).await?;
    Ok((control, client, client_config, key_id))
}

async fn start_control(
    data_source: DataSource,
    test_name: &str,
) -> Result<(ControlServer, AdnlClient, String, Arc<KeyId>)> {
    start_control_with_options(data_source, None, test_name).await
}


#[tokio::test(flavor = "multi_thread")]
async fn test_connect_to_control() {
    struct TestSource;
    impl StatusReporter for TestSource {
        fn get_report(&self) -> u32 {
            0
        }
    }

    init_test_log();
    let (control, mut client, _, _) =
        start_control(DataSource::Status(Arc::new(TestSource)), "test_connect_to_control")
            .await
            .unwrap();

    let key_hash = generate_keypair(&mut client).await.unwrap();
    log::debug!("key hash: {}", base64_encode(key_hash));
    client.shutdown().await.unwrap();
    control.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_connect_to_control_with_import_private_key() {
    init_test_log();
    // Key commands need a started engine; this one serves nothing else.
    let (control, mut client, _, _) = start_control(
        DataSource::Engine(super::key_tests::StartedEngine::new()),
        "test_connect_to_control_with_import_private_key",
    )
    .await
    .unwrap();

    let pvt_key = "TcbLvGlM7Dk/F+nHyd4MYwG2ys14YPxgGIdf0xh+Tr8=";
    log::debug!("pvt_key: {pvt_key}");
    let key_hash = import_private_key(&mut client, pvt_key).await.unwrap();
    log::debug!("key_hash: {}", base64_encode(&key_hash));
    assert_eq!(base64_encode(&key_hash), "bWTFYRDLaHY6FlS64a/2hVRfdqudGuQ7+jfz8GKo6M0=");

    // The wire field is the absolute expiry; an expired ADNL address is
    // listed but not bound, so the expiry is in the future.
    let election_date = 1763281111;
    let ttl = 2_100_000_000;
    let query = AddValidatorPermanentKey { key_hash, election_date, ttl };
    let _answer: Success = request(&mut client, query).await.unwrap();

    let election_date = 1763287777;
    let pvt_key = "5UqVPHm/95e70Q4juONPpBfKmOWM63/zQ4hhnJ86Jwo=";
    let key_hash = import_private_key(&mut client, pvt_key).await.unwrap();

    let permanent_key_hash = key_hash.clone();
    let query = AddValidatorPermanentKey { key_hash, election_date, ttl };
    let _answer: Success = request(&mut client, query).await.unwrap();

    let pvt_key = "cyO76Whw2CKnSbEftGllH53Ph29SHdqzGra9Wb93bOE=";
    let key_hash = import_private_key(&mut client, pvt_key).await.unwrap();

    // A validator ADNL address must be in the ADNL id list first.
    let query = AddAdnlId { key_hash: key_hash.clone(), category: 0 };
    let _answer: Success = request(&mut client, query).await.unwrap();
    let query = AddValidatorAdnlAddress { permanent_key_hash, key_hash, ttl };
    let _answer: Success = request(&mut client, query).await.unwrap();

    let answer: JsonConfig = request(&mut client, GetConfig).await.unwrap();

    println!("Config data: {}", answer.data());

    let json = serde_json::from_str::<serde_json::Value>(answer.data()).unwrap();
    assert_eq!(json["adnl"].as_array().unwrap().len(), 3);
    assert_eq!(json["dht"].as_array().unwrap().len(), 1);
    assert_eq!(json["validators"].as_array().unwrap().len(), 2);

    client.shutdown().await.unwrap();
    control.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_control_db_restore() {
    struct TestSource {
        broken: AtomicBool,
    }

    impl StatusReporter for TestSource {
        fn get_report(&self) -> u32 {
            if self.broken.load(Ordering::Relaxed) {
                Engine::SYNC_STATUS_DB_BROKEN
            } else {
                Engine::SYNC_STATUS_CHECKING_DB
            }
        }
    }

    init_test_log();
    let status = Arc::new(TestSource { broken: AtomicBool::new(false) });
    let (control, mut client, _, _) =
        start_control(DataSource::Status(status.clone()), "test_control_db_restore").await.unwrap();

    // While the database is checked the engine has not started: statistics
    // are refused as the reference engine refuses them before start.
    for broken in [false, true] {
        status.broken.store(broken, Ordering::Relaxed);
        let error = query(&mut client, &GetStats.into_tl_object()).await.unwrap_err().to_string();
        assert!(error.contains("code: 651"), "{error}");
        assert!(error.contains("message: \"validator manager not started\""), "{error}");
    }
    client.shutdown().await.unwrap();
    control.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn test_stats() {
    const DB_PATH: &str = "../target/multi_node_db";

    struct TestEngine {
        db: InternalDb,
        master_state_id: BlockIdExt,
        master_state: Arc<ShardStateStuff>,
        last_validation_time: lockfree::map::Map<ShardIdent, u64>,
        allocated: Arc<crate::engine_traits::EngineAlloc>,
        #[cfg(feature = "telemetry")]
        telemetry: Arc<crate::engine_traits::EngineTelemetry>,
    }

    impl TestEngine {
        async fn new() -> Self {
            #[cfg(feature = "telemetry")]
            let telemetry = create_engine_telemetry();
            let allocated = create_engine_allocated();
            let master_state = gen_master_state(
                Default::default(),
                #[cfg(feature = "telemetry")]
                Some(telemetry.clone()),
                Some(allocated.clone()),
            );
            let master_state_id = master_state.block_id().clone();
            remove_dir_all(DB_PATH).ok();
            let db_config =
                InternalDbConfig { db_directory: String::from(DB_PATH), ..Default::default() };
            let db = InternalDb::with_update(
                db_config,
                false,
                false,
                false,
                None,
                &|| Ok(()),
                None,
                Arc::new(AtomicU8::new(0)),
                None,
                #[cfg(feature = "telemetry")]
                telemetry.clone(),
                allocated.clone(),
            )
            .await
            .unwrap();
            db.create_or_load_block_handle(&master_state_id, None, Some(1), None)
                .unwrap()
                ._to_created()
                .unwrap();
            Self {
                db,
                master_state_id,
                master_state,
                last_validation_time: lockfree::map::Map::new(),
                allocated,
                #[cfg(feature = "telemetry")]
                telemetry,
            }
        }
    }

    #[async_trait::async_trait]
    impl EngineOperations for TestEngine {
        fn engine_allocated(&self) -> &Arc<crate::engine_traits::EngineAlloc> {
            &self.allocated
        }
        #[cfg(feature = "telemetry")]
        fn engine_telemetry(&self) -> &Arc<crate::engine_traits::EngineTelemetry> {
            &self.telemetry
        }
        fn calc_tps(&self, _period: u64) -> Result<u32> {
            Ok(0)
        }
        fn get_sync_status(&self) -> u32 {
            Engine::SYNC_STATUS_SYNC_BLOCKS
        }
        fn last_collation_time(&self) -> &lockfree::map::Map<ShardIdent, u64> {
            &self.last_validation_time
        }
        fn last_validation_time(&self) -> &lockfree::map::Map<ShardIdent, u64> {
            &self.last_validation_time
        }
        fn load_block_handle(&self, id: &BlockIdExt) -> Result<Option<Arc<BlockHandle>>> {
            self.db.load_block_handle(id)
        }
        fn load_last_applied_mc_block_id(&self) -> Result<Option<Arc<BlockIdExt>>> {
            Ok(Some(Arc::new(self.master_state_id.clone())))
        }
        async fn load_last_applied_mc_state(&self) -> Result<Arc<ShardStateStuff>> {
            Ok(self.master_state.clone())
        }
        fn load_shard_client_mc_block_id(&self) -> Result<Option<Arc<BlockIdExt>>> {
            Ok(Some(Arc::new(self.master_state_id.clone())))
        }
        fn validation_status(&self) -> ValidationStatus {
            ValidationStatus::Active
        }
    }

    async fn test() -> Result<()> {
        init_test_log();
        let engine = Arc::new(TestEngine::new().await);
        let (control, mut client, _, _) =
            start_control(DataSource::Engine(engine.clone()), "test_stats").await?;

        // getStats answers under the reference engine's names.
        let answer: Stats = request(&mut client, GetStats).await?;
        let names: Vec<&str> = answer.stats().iter().map(|stat| stat.key.as_str()).collect();
        assert_eq!(names.first(), Some(&"unixtime"));
        assert!(names.contains(&"masterchainblock"), "{names:?}");
        assert!(names.contains(&"masterchainblocktime"), "{names:?}");
        assert_eq!(names.last(), Some(&"stateserializerenabled"));

        client.shutdown().await?;
        control.shutdown().await;
        Ok(())
    }

    test_async(
        || Box::pin(test()),
        || {
            remove_dir_all(DB_PATH).ok();
        },
    )
    .await;
}
