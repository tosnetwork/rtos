/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2019-2021 TON Labs. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
#![cfg(any(feature = "client", feature = "server"))]

include!("../../common/src/test.rs");

#[cfg(feature = "client")]
use adnl::client::{AdnlClient, AdnlClientConfig};
#[cfg(feature = "server")]
use adnl::server::{AdnlServer, AdnlServerConfig};
#[cfg(all(feature = "client", feature = "server"))]
use rtos_block::Result;
#[cfg(feature = "client")]
use std::time::Instant;
#[cfg(feature = "server")]
use std::{thread::sleep, time::Duration};

#[cfg(feature = "client")]
const ADNL_CLIENT_CONFIG: &str = r#"{
    "server_address": "127.0.0.1:4924",
    "server_key": {
        "type_id": 1209251014,
        "pub_key": "BBKmgGAxz4ZofRgMO2qhYt+K1bGlGeowukPONVAkOcU="
    }
}"#;

#[cfg(feature = "server")]
const ADNL_SERVER_CONFIG: &str = r#"{
    "address": "0.0.0.0:4924", 
    "clients": {
        "any": null
    },
    "server_key": {
        "type_id": 1209251014,
        "pvt_key": "3CFeiTSlGkJf3D8w3ZXS4QS+6/0p+MFZGuv0XYMvMRo="
    }
}"#;

#[cfg(all(feature = "client", feature = "server"))]
async fn request_server(client: &mut AdnlClient) -> Result<()> {
    client.ping().await?;
    Ok(())
}

#[cfg(all(feature = "client", feature = "server"))]
fn init_client(config: &str, rt: &mut tokio::runtime::Runtime) -> AdnlClient {
    let (_, config) = AdnlClientConfig::from_json(config).unwrap();
    rt.block_on(AdnlClient::connect(&config)).unwrap()
}

#[cfg(all(feature = "client", feature = "server"))]
fn init_client_server_test(
    server: &str,
    client: &str,
) -> (tokio::runtime::Runtime, AdnlServer, AdnlClient) {
    let mut rt = init_test();
    let sv = init_server(server, &mut rt);
    let cl = init_client(client, &mut rt);
    (rt, sv, cl)
}

#[cfg(feature = "server")]
fn init_server(config: &str, rt: &mut tokio::runtime::Runtime) -> AdnlServer {
    let config = AdnlServerConfig::from_json(config).unwrap();
    rt.block_on(AdnlServer::listen(
        config,
        vec![],
        #[cfg(feature = "telemetry")]
        "ADNL server",
    ))
    .unwrap()
}

#[cfg(feature = "server")]
#[test]
fn tcp_no_client() {
    let mut rt = init_test();
    let server = init_server(ADNL_SERVER_CONFIG, &mut rt);
    rt.block_on(async move {
        sleep(Duration::from_millis(500));
        server.shutdown().await;
        sleep(Duration::from_millis(500));
    })
}

#[cfg(feature = "client")]
#[test]
fn tcp_no_server() {
    let (_, config) = AdnlClientConfig::from_json(ADNL_CLIENT_CONFIG).unwrap();
    let start = Instant::now();
    let rt = init_test();
    assert!(rt.block_on(AdnlClient::connect(&config)).is_err());
    assert!(start.elapsed().as_secs() < 3);
}

#[cfg(all(feature = "client", feature = "server"))]
#[test]
fn tcp_session() {
    let (rt, server, mut client) = init_client_server_test(ADNL_SERVER_CONFIG, ADNL_CLIENT_CONFIG);
    rt.block_on(async move {
        request_server(&mut client).await.unwrap();
        request_server(&mut client).await.unwrap();
        client.shutdown().await.unwrap();
        server.shutdown().await;
        // Ensure server socket close
        sleep(Duration::from_millis(200));
    })
}

#[cfg(all(feature = "client", feature = "server"))]
#[test]
fn tcp_ephemeral_listener_reports_actual_endpoint_for_client() {
    let rt = init_test();
    rt.block_on(async {
        let mut server_config: serde_json::Value = serde_json::from_str(ADNL_SERVER_CONFIG).unwrap();
        server_config["address"] = "127.0.0.1:0".into();
        let server = AdnlServer::listen(
            AdnlServerConfig::from_json(&server_config.to_string()).unwrap(),
            vec![],
            #[cfg(feature = "telemetry")]
            "ephemeral test server",
        ).await.unwrap();
        let endpoint = server.local_addr();
        let result: Result<()> = async {
            assert_ne!(endpoint.port(), 0);
            assert!(std::net::TcpListener::bind(endpoint).is_err());
            let mut config: serde_json::Value = serde_json::from_str(ADNL_CLIENT_CONFIG).unwrap();
            config["server_address"] = endpoint.to_string().into();
            let (_, config) = AdnlClientConfig::from_json(&config.to_string())?;
            let mut client = AdnlClient::connect(&config).await?;
            let ping = request_server(&mut client).await;
            client.shutdown().await?;
            ping
        }.await;
        server.shutdown().await;
        result.unwrap();
    });
}
