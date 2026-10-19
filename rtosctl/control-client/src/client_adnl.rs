/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::client_api::{
    Account, AddAdnlAddressRq, AddValidatorAdnlAddrRq, AddValidatorPermKeyRq,
    AddValidatorTempKeyRq, BlockchainConfigInfo, ClientAPI, EngineValidatorConfig,
    ImportShardOverlayCertificateRq, ShardAccountState, Shutdown, SignRq,
    SignShardOverlayCertificateRq,
};
use adnl::client::{AdnlClient, AdnlClientConfig, AdnlClientConfigJson};
use anyhow::Context;
use rtos_api::{
    AnyBoxedSerialize, IntoBoxed, TLObject, WireProfile, serialize_boxed,
    ton::{
        self, engine::validator::ControlQueryError as TonControlQueryError,
        rpc::engine::validator::ControlQuery as TonControlQuery,
    },
};
use rtos_block::{BlockIdExt, Deserializable, MsgAddressInt, UInt256};
use std::str::FromStr;

pub trait ToFromTL {
    type Rq;
    type Rs;

    fn serialize(rq: &Self::Rq) -> anyhow::Result<TLObject>;
    fn deserialize(answer: TLObject) -> anyhow::Result<Self::Rs>;
}

fn downcast<T: rtos_api::AnyBoxedSerialize>(data: TLObject) -> anyhow::Result<T> {
    match data.downcast::<T>() {
        Ok(result) => Ok(result),
        Err(obj) => anyhow::bail!("Wrong downcast {:?} to {}", obj, std::any::type_name::<T>()),
    }
}

struct GetValidatorConfigRqRs {}

impl ToFromTL for GetValidatorConfigRqRs {
    type Rq = ();
    type Rs = EngineValidatorConfig;

    fn serialize(_: &Self::Rq) -> anyhow::Result<TLObject> {
        Ok(ton::rpc::engine::validator::GetConfig.into_tl_object())
    }

    fn deserialize(rs: TLObject) -> anyhow::Result<Self::Rs> {
        let config = downcast::<rtos_api::ton::engine::validator::JsonConfig>(rs)?;
        let engine_validator_config = serde_json::from_str::<EngineValidatorConfig>(config.data())?;
        Ok(engine_validator_config)
    }
}

struct SignRqRs {}

impl ToFromTL for SignRqRs {
    type Rq = SignRq;
    type Rs = Vec<u8>;

    fn serialize(rq: &Self::Rq) -> anyhow::Result<TLObject> {
        let key_hash = UInt256::from_raw(rq.key_hash.clone(), 256);
        let ret = ton::rpc::engine::validator::Sign { key_hash, data: rq.data.clone() };
        Ok(ret.into_tl_object())
    }

    fn deserialize(rs: TLObject) -> anyhow::Result<Self::Rs> {
        let answer = downcast::<rtos_api::ton::engine::validator::Signature>(rs)?;
        let signature = answer.signature().clone();

        Ok(signature)
    }
}

struct GenerateKeyPairRqRs {}

impl ToFromTL for GenerateKeyPairRqRs {
    type Rq = ();
    type Rs = Vec<u8>;

    fn serialize(_: &Self::Rq) -> anyhow::Result<TLObject> {
        Ok(ton::rpc::engine::validator::GenerateKeyPair.into_tl_object())
    }

    fn deserialize(rs: TLObject) -> anyhow::Result<Self::Rs> {
        let ton_key_hash = downcast::<rtos_api::ton::engine::validator::KeyHash>(rs)?;
        let key_hash = ton_key_hash.key_hash().as_slice().to_vec();

        Ok(key_hash)
    }
}

struct ExportKeyPubRqRs {}

impl ToFromTL for ExportKeyPubRqRs {
    type Rq = Vec<u8>;
    type Rs = Vec<u8>;

    fn serialize(rq: &Self::Rq) -> anyhow::Result<TLObject> {
        let key_hash = UInt256::from_raw(rq.to_owned(), 256);

        let ret = ton::rpc::engine::validator::ExportPublicKey { key_hash };
        Ok(ret.into_tl_object())
    }

    fn deserialize(rs: TLObject) -> anyhow::Result<Self::Rs> {
        let answer = downcast::<rtos_api::ton::PublicKey>(rs)?;
        let pub_key = match answer.key() {
            Some(key) => key.clone().into_vec(),
            None => anyhow::bail!("Public key not found in answer!"),
        };

        Ok(pub_key)
    }
}

struct AddValidatorPermKeyRqRs {}

impl ToFromTL for AddValidatorPermKeyRqRs {
    type Rq = AddValidatorPermKeyRq;
    type Rs = ();

    fn serialize(rq: &Self::Rq) -> anyhow::Result<TLObject> {
        let key_hash = UInt256::from_raw(rq.key_hash.clone(), 256);
        let election_date = rq.election_date;
        // The wire field carries the absolute expiry.
        let ttl = rq.expire_at;

        let ret =
            ton::rpc::engine::validator::AddValidatorPermanentKey { key_hash, election_date, ttl };
        Ok(ret.into_tl_object())
    }

    fn deserialize(_: TLObject) -> anyhow::Result<Self::Rs> {
        Ok(())
    }
}

struct AddValidatorTempKeyRqRs {}

impl ToFromTL for AddValidatorTempKeyRqRs {
    type Rq = AddValidatorTempKeyRq;
    type Rs = ();

    fn serialize(rq: &Self::Rq) -> anyhow::Result<TLObject> {
        let perm_key_hash = UInt256::from_raw(rq.perm_key_hash.clone(), 256);
        let key_hash = UInt256::from_raw(rq.key_hash.clone(), 256);
        let ttl = rq.expire_at;

        let ret = ton::rpc::engine::validator::AddValidatorTempKey {
            permanent_key_hash: perm_key_hash,
            key_hash,
            ttl,
        };

        Ok(ret.into_tl_object())
    }

    fn deserialize(_: TLObject) -> anyhow::Result<Self::Rs> {
        Ok(())
    }
}

struct AddAdnlAddressRqRs {}

impl ToFromTL for AddAdnlAddressRqRs {
    type Rq = AddAdnlAddressRq;
    type Rs = ();

    fn serialize(rq: &Self::Rq) -> anyhow::Result<TLObject> {
        let key_hash = UInt256::from_raw(rq.key_hash.clone(), 256);
        let category = rq.category;

        if !(0..=15).contains(&category) {
            anyhow::bail!("category must be not negative and less than 16")
        }
        let ret = ton::rpc::engine::validator::AddAdnlId { key_hash, category };

        Ok(ret.into_tl_object())
    }

    fn deserialize(_: TLObject) -> anyhow::Result<Self::Rs> {
        Ok(())
    }
}

struct AddValidatorAdnlAddrRqRs {}

impl ToFromTL for AddValidatorAdnlAddrRqRs {
    type Rq = AddValidatorAdnlAddrRq;
    type Rs = ();

    fn serialize(rq: &Self::Rq) -> anyhow::Result<TLObject> {
        let perm_key_hash = UInt256::from_raw(rq.perm_key_hash.clone(), 256);
        let key_hash = UInt256::from_raw(rq.key_hash.clone(), 256);
        let ttl = rq.expire_at;

        let ret = ton::rpc::engine::validator::AddValidatorAdnlAddress {
            permanent_key_hash: perm_key_hash,
            key_hash,
            ttl,
        };

        Ok(ret.into_tl_object())
    }

    fn deserialize(_: TLObject) -> anyhow::Result<Self::Rs> {
        Ok(())
    }
}

fn key_hash_boxed(key_hash: &[u8]) -> anyhow::Result<ton::engine::validator::KeyHash> {
    let key_hash: [u8; 32] =
        key_hash.try_into().map_err(|_| anyhow::anyhow!("key hash must be 32 bytes"))?;
    Ok(ton::engine::validator::keyhash::KeyHash { key_hash: UInt256::from(key_hash) }.into_boxed())
}

struct SignShardOverlayCertificateRqRs {}

impl ToFromTL for SignShardOverlayCertificateRqRs {
    type Rq = SignShardOverlayCertificateRq;
    type Rs = Vec<u8>;

    fn serialize(rq: &Self::Rq) -> anyhow::Result<TLObject> {
        let ret = ton::rpc::engine::validator::SignShardOverlayCertificate {
            workchain: rq.workchain,
            shard: rq.shard,
            signed_key: key_hash_boxed(&rq.key_hash)?,
            expire_at: rq.expire_at,
            // The wire field is signed; the size keeps its bit pattern.
            max_size: rq.max_size as i32,
        };
        Ok(ret.into_tl_object())
    }

    fn deserialize(rs: TLObject) -> anyhow::Result<Self::Rs> {
        let certificate = downcast::<ton::overlay::Certificate>(rs)?;
        serialize_boxed(&certificate)
    }
}

struct ImportShardOverlayCertificateRqRs {}

impl ToFromTL for ImportShardOverlayCertificateRqRs {
    type Rq = ImportShardOverlayCertificateRq;
    type Rs = ();

    fn serialize(rq: &Self::Rq) -> anyhow::Result<TLObject> {
        let cert = rtos_api::deserialize_boxed(&rq.certificate)?
            .downcast::<ton::overlay::Certificate>()
            .map_err(|object| anyhow::anyhow!("incorrect certificate: {object:?}"))?;
        let ret = ton::rpc::engine::validator::ImportShardOverlayCertificate {
            workchain: rq.workchain,
            shard: rq.shard,
            signed_key: key_hash_boxed(&rq.key_hash)?,
            cert,
        };
        Ok(ret.into_tl_object())
    }

    fn deserialize(rs: TLObject) -> anyhow::Result<Self::Rs> {
        downcast::<ton::engine::validator::Success>(rs)?;
        Ok(())
    }
}

struct SetExtMessagesBroadcastDisabledRqRs {}

impl ToFromTL for SetExtMessagesBroadcastDisabledRqRs {
    type Rq = bool;
    type Rs = ();

    fn serialize(disabled: &Self::Rq) -> anyhow::Result<TLObject> {
        let disabled = if *disabled { ton::Bool::BoolTrue } else { ton::Bool::BoolFalse };
        Ok(ton::rpc::engine::validator::SetExtMessagesBroadcastDisabled { disabled }
            .into_tl_object())
    }

    fn deserialize(rs: TLObject) -> anyhow::Result<Self::Rs> {
        downcast::<ton::engine::validator::Success>(rs)?;
        Ok(())
    }
}

pub struct ControlClientAdnl {
    config: AdnlClientConfig,
    adnl: Option<AdnlClient>,
    max_rq_attempts: u32,
}

impl ControlClientAdnl {
    /// Create a new disconnected control client.
    ///
    /// Connection will be established when the first request is made.
    pub fn new(config: AdnlClientConfig, max_rq_attempts: u32) -> Self {
        Self { config, adnl: None, max_rq_attempts }
    }

    /// Create a new disconnected control client from a JSON configuration.
    ///
    /// Connection will be established when the first request is made.
    pub fn new_from_json(config_json: &AdnlClientConfigJson) -> anyhow::Result<Self> {
        let (_, config) = AdnlClientConfig::from_json_config(config_json)?;
        Ok(Self::new(config, 4))
    }

    /// Establish connection to the Control Server via ADNL.
    ///
    /// If connection is already established, do nothing.
    /// It is not necessary to call this method before making requests,
    /// but it can be used to force connection establishment.
    pub async fn connect(&mut self) -> anyhow::Result<()> {
        if self.adnl.is_none() {
            self.adnl = Some(
                AdnlClient::connect(&self.config)
                    .await
                    .context("failed to connect to Control Server")?,
            );
        }
        Ok(())
    }

    /// Shutdown the Control Client.
    ///
    /// If connection is not established, do nothing.
    /// Call this method to ensure the connection is closed.
    pub async fn shutdown(&mut self) -> anyhow::Result<()> {
        if let Some(adnl) = self.adnl.take() {
            adnl.shutdown().await?;
        }
        Ok(())
    }

    pub async fn ping(&mut self) -> anyhow::Result<u64> {
        let adnl = self.adnl.as_mut().context("ADNL client not connected")?;
        adnl.ping().await
    }

    pub async fn reconnect(&mut self) -> anyhow::Result<()> {
        if let Some(adnl) = self.adnl.take() {
            if let Err(e) = adnl.shutdown().await {
                tracing::error!(target: "control-client", "failed to shut down ADNL client: {}", e)
            }
        }

        self.adnl = Some(AdnlClient::connect(&self.config).await?);
        Ok(())
    }

    async fn do_rq<T>(&mut self, rq: &T::Rq) -> anyhow::Result<T::Rs>
    where
        T: ToFromTL,
    {
        let tl_object_rq = T::serialize(rq)?;
        let tl_object_rq_boxed =
            TonControlQuery { data: serialize_boxed(&tl_object_rq)? }.into_tl_object().into();

        // Establish connection if not established yet
        self.connect().await?;

        let mut attempt = 1;

        loop {
            let adnl = self.adnl.as_mut().context("control client not connected")?;
            let res = adnl.query(&tl_object_rq_boxed).await;

            match res {
                Ok(tl_object) => match tl_object.downcast::<TonControlQueryError>() {
                    Err(tl_object_rs) => match T::deserialize(tl_object_rs) {
                        Err(err) => {
                            anyhow::bail!("Wrong response to {:?}: {:?}", tl_object_rq, err)
                        }
                        Ok(result) => return Ok(result),
                    },
                    Ok(error) => anyhow::bail!("Error response to {:?}: {:?}", tl_object_rq, error),
                },
                Err(err) => {
                    tracing::debug!(target: "control-client", "control query error: {}", err);
                    if attempt >= self.max_rq_attempts {
                        tracing::error!(target: "control-client", "max reconnecting attempts reached");
                        anyhow::bail!("control query error: {}", err)
                    }

                    tracing::debug!( target: "control-client",
                        "reconnect and repeat request: attempt {}/{}",
                        attempt,
                        self.max_rq_attempts,
                    );

                    self.reconnect().await?;
                    attempt += 1;
                    continue;
                }
            }
        }
    }
}

/// Account, configuration and message queries go to the node's lite-server
/// path on the control port: a `liteServer.query` whose function and answer
/// are encoded in the network wire profile, as the reference engine and its
/// lite-server clients exchange them.
impl ControlClientAdnl {
    async fn lite_query<Q, A>(&mut self, function: &Q) -> anyhow::Result<A>
    where
        Q: rtos_api::BoxedSerialize + std::fmt::Debug,
        A: rtos_api::AnyBoxedSerialize,
    {
        let data = WireProfile::T0.serialize(function)?;
        let wrapped: TLObject = ton::rpc::lite_server::Query { data }.into_tl_object();
        let wrapped = wrapped.into();
        self.connect().await?;
        let mut attempt = 1;
        let answer = loop {
            let adnl = self.adnl.as_mut().context("control client not connected")?;
            match adnl.query_raw(&wrapped, WireProfile::Legacy).await {
                Ok(answer) => break answer,
                Err(err) if attempt < self.max_rq_attempts => {
                    tracing::debug!(target: "control-client", "lite query error: {err}");
                    self.reconnect().await?;
                    attempt += 1;
                }
                Err(err) => anyhow::bail!("lite query error: {err}"),
            }
        };
        let object = WireProfile::T0.deserialize(&answer)?;
        let object = match object.downcast::<ton::lite_server::Error>() {
            Ok(error) => {
                let error = error.only();
                anyhow::bail!("Error response to {:?}: {} {}", function, error.code, error.message)
            }
            Err(object) => object,
        };
        downcast::<A>(object)
    }

    async fn last_masterchain_block(&mut self) -> anyhow::Result<BlockIdExt> {
        let info: ton::lite_server::MasterchainInfo =
            self.lite_query(&ton::rpc::lite_server::GetMasterchainInfo).await?;
        Ok(info.only().last)
    }

    async fn lite_account_state(&mut self, address: &str) -> anyhow::Result<Account> {
        let address = MsgAddressInt::from_str(address)
            .map_err(|e| anyhow::anyhow!("bad account address {address}: {e}"))?;
        let id = self.last_masterchain_block().await?;
        let account = ton::lite_server::accountid::AccountId {
            workchain: address.workchain_id(),
            id: UInt256::from_slice(&address.address().get_bytestring(0)),
        };
        let query = ton::rpc::lite_server::GetAccountState { id, account };
        let state: ton::lite_server::AccountState = self.lite_query(&query).await?;
        let state = state.only();
        account_from_lite_state(&address, &state.state, &state.proof)
    }

    async fn lite_config(
        &mut self,
        param: Option<u32>,
    ) -> anyhow::Result<ton::lite_server::configinfo::ConfigInfo> {
        let id = self.last_masterchain_block().await?;
        let info: ton::lite_server::ConfigInfo = match param {
            None => self.lite_query(&ton::rpc::lite_server::GetConfigAll { mode: 0, id }).await?,
            Some(param) => {
                let param = i32::try_from(param)
                    .map_err(|_| anyhow::anyhow!("id value does not fit into i32"))?;
                let query =
                    ton::rpc::lite_server::GetConfigParams { mode: 0, id, param_list: vec![param] };
                self.lite_query(&query).await?
            }
        };
        Ok(info.only())
    }

    /// One configuration parameter in the JSON form the callers read, taken
    /// from the configuration proof.
    async fn lite_config_param(&mut self, param: u32) -> anyhow::Result<Vec<u8>> {
        let info = self.lite_config(Some(param)).await?;
        config_param_from_proof(&info.config_proof, param)
    }

    async fn lite_send_boc(&mut self, boc: &[u8]) -> anyhow::Result<()> {
        let query = ton::rpc::lite_server::SendMessage { body: boc.to_vec() };
        let _: ton::lite_server::SendMsgStatus = self.lite_query(&query).await?;
        Ok(())
    }
}

/// An account from a lite-server account state. An empty state is an account
/// that does not exist. The proof holds two roots, the block-to-state proof
/// and the state-to-account proof; the shard account in the second carries
/// the last transaction.
fn account_from_lite_state(
    address: &MsgAddressInt,
    state: &[u8],
    proof: &[u8],
) -> anyhow::Result<Account> {
    if state.is_empty() {
        return Ok(Account::Nonexist);
    }
    let account = rtos_block::Account::construct_from_bytes(state)?;
    let roots = rtos_block::read_boc(proof)?.roots;
    let state_proof = roots.get(1).context("account state proof without a state proof")?;
    let shard_state: rtos_block::ShardStateUnsplit =
        rtos_block::MerkleProof::construct_from_cell(state_proof.clone())?.virtualize()?;
    let shard_account = shard_state
        .read_accounts()?
        .account(address.address())?
        .context("the state proof does not hold the account")?;
    Ok(Account::ShardAccountState(ShardAccountState {
        status: account.status(),
        balance: account.balance().map_or(0, |val| val.coins.as_u128()),
        last_paid: account.last_paid(),
        last_trans: shard_account.last_trans_lt(),
        data: state.to_vec(),
    }))
}

/// One configuration parameter, in the JSON form the callers read, from a
/// configuration proof of the masterchain state.
fn config_param_from_proof(config_proof: &[u8], param: u32) -> anyhow::Result<Vec<u8>> {
    let state: rtos_block::ShardStateUnsplit =
        rtos_block::MerkleProof::construct_from_bytes(config_proof)?.virtualize()?;
    let config =
        state.read_custom()?.context("the configuration proof holds no masterchain state")?.config;
    Ok(rtos_block_json::serialize_config_param(&config, param)?.into_bytes())
}

#[async_trait::async_trait]
impl ClientAPI for ControlClientAdnl {
    async fn get_account_state(&mut self, address: &str) -> anyhow::Result<Account> {
        self.lite_account_state(address).await
    }

    async fn get_blockchain_config(&mut self) -> anyhow::Result<BlockchainConfigInfo> {
        let info = self.lite_config(None).await?;
        Ok(BlockchainConfigInfo { state_proof: info.state_proof, config_proof: info.config_proof })
    }

    async fn get_validator_config(&mut self) -> anyhow::Result<EngineValidatorConfig> {
        self.do_rq::<GetValidatorConfigRqRs>(&()).await
    }

    async fn get_config_param(&mut self, id: u32) -> anyhow::Result<Vec<u8>> {
        self.lite_config_param(id).await
    }

    async fn sign(&mut self, rq: &SignRq) -> anyhow::Result<Vec<u8>> {
        self.do_rq::<SignRqRs>(rq).await
    }

    async fn generate_key_pair(&mut self) -> anyhow::Result<Vec<u8>> {
        self.do_rq::<GenerateKeyPairRqRs>(&()).await
    }

    async fn export_key_pub(&mut self, key_hash: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.do_rq::<ExportKeyPubRqRs>(&key_hash.to_vec()).await
    }

    async fn add_validator_perm_key(&mut self, rq: &AddValidatorPermKeyRq) -> anyhow::Result<()> {
        self.do_rq::<AddValidatorPermKeyRqRs>(rq).await
    }

    async fn add_validator_temp_key(&mut self, rq: &AddValidatorTempKeyRq) -> anyhow::Result<()> {
        self.do_rq::<AddValidatorTempKeyRqRs>(rq).await
    }

    async fn add_adnl_address(&mut self, rq: &AddAdnlAddressRq) -> anyhow::Result<()> {
        self.do_rq::<AddAdnlAddressRqRs>(rq).await
    }

    async fn add_validator_adnl_addr(&mut self, rq: &AddValidatorAdnlAddrRq) -> anyhow::Result<()> {
        self.do_rq::<AddValidatorAdnlAddrRqRs>(rq).await
    }

    async fn send_boc(&mut self, boc: &[u8]) -> anyhow::Result<()> {
        self.lite_send_boc(boc).await
    }

    async fn sign_shard_overlay_certificate(
        &mut self,
        rq: &SignShardOverlayCertificateRq,
    ) -> anyhow::Result<Vec<u8>> {
        self.do_rq::<SignShardOverlayCertificateRqRs>(rq).await
    }

    async fn import_shard_overlay_certificate(
        &mut self,
        rq: &ImportShardOverlayCertificateRq,
    ) -> anyhow::Result<()> {
        self.do_rq::<ImportShardOverlayCertificateRqRs>(rq).await
    }

    async fn set_ext_messages_broadcast_disabled(&mut self, disabled: bool) -> anyhow::Result<()> {
        self.do_rq::<SetExtMessagesBroadcastDisabledRqRs>(&disabled).await
    }
}

#[async_trait::async_trait]
impl Shutdown for ControlClientAdnl {
    async fn shutdown(&mut self) -> anyhow::Result<()> {
        ControlClientAdnl::shutdown(self).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adnl::common::Timeouts;
    use rtos_block::{Ed25519KeyOption, ZeroizingBytes};
    use std::time::{Duration, Instant};

    /// Verifies that connecting to an unreachable peer does not park the
    /// tokio worker thread, by running another async task concurrently on a
    /// single-worker runtime and asserting that the other task makes progress
    /// before the ADNL connect timeout elapses.
    ///
    /// With the legacy synchronous `AdnlClient::connect` this test would fail:
    /// the worker would be parked inside `socket2::Socket::connect_timeout`
    /// for the entire timeout window, the timer would not fire, and the probe
    /// would finish only after the connect attempt returned.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn connect_to_unreachable_peer_does_not_starve_runtime() {
        // RFC 5737 TEST-NET-1: guaranteed unreachable.
        let blackhole = "192.0.2.1:12345".parse().unwrap();
        let timeouts = Timeouts::with_duration(Duration::from_millis(800));
        let server_key = Ed25519KeyOption::<ZeroizingBytes>::generate().unwrap();
        let config = AdnlClientConfig::new(None, blackhole, server_key, timeouts);
        let mut client = ControlClientAdnl::new(config, 1);

        let start = Instant::now();

        let probe = async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            Instant::now()
        };
        let try_connect = async {
            let res = client.connect().await;
            assert!(res.is_err(), "connect to blackhole must fail");
            Instant::now()
        };

        let (probe_done, connect_done) = tokio::join!(probe, try_connect);

        let probe_elapsed = probe_done.duration_since(start);
        let connect_elapsed = connect_done.duration_since(start);

        // If the environment returns a near-instant connect error (e.g. a CI
        // sandbox without a default route, giving EHOSTUNREACH), the slow
        // path is not exercised and the starvation check is meaningless.
        // Skip rather than fail in that case.
        if connect_elapsed < Duration::from_millis(100) {
            eprintln!(
                "skipping starvation check: connect to {} returned in {:?} \
                 (environment does not block the route)",
                blackhole, connect_elapsed,
            );
            return;
        }

        assert!(
            probe_elapsed < Duration::from_millis(500),
            "probe took {probe_elapsed:?}; runtime appears starved by ADNL connect"
        );
        assert!(
            connect_elapsed >= Duration::from_millis(700),
            "connect returned in {connect_elapsed:?}, expected ~800ms timeout"
        );
    }
}

#[cfg(test)]
mod key_request_tests {
    use super::*;

    /// The reference engine reads the `ttl` field of the key requests as the
    /// absolute expiry, and its console sends the expiry unchanged.
    #[test]
    fn key_requests_send_the_absolute_expiry() {
        let perm = AddValidatorPermKeyRq {
            key_hash: vec![1; 32],
            election_date: 1000,
            expire_at: 2_000_000_001,
        };
        let query = AddValidatorPermKeyRqRs::serialize(&perm)
            .unwrap()
            .downcast::<ton::rpc::engine::validator::AddValidatorPermanentKey>()
            .unwrap();
        assert_eq!((query.election_date, query.ttl), (1000, 2_000_000_001));
        let temp = AddValidatorTempKeyRq {
            perm_key_hash: vec![1; 32],
            key_hash: vec![2; 32],
            expire_at: -16,
        };
        let query = AddValidatorTempKeyRqRs::serialize(&temp)
            .unwrap()
            .downcast::<ton::rpc::engine::validator::AddValidatorTempKey>()
            .unwrap();
        assert_eq!(query.ttl, -16);
        let addr = AddValidatorAdnlAddrRq {
            perm_key_hash: vec![1; 32],
            key_hash: vec![3; 32],
            expire_at: 5,
        };
        let query = AddValidatorAdnlAddrRqRs::serialize(&addr)
            .unwrap()
            .downcast::<ton::rpc::engine::validator::AddValidatorAdnlAddress>()
            .unwrap();
        assert_eq!(query.ttl, 5);
    }
}

#[cfg(test)]
mod certificate_tests {
    use super::*;

    fn certificate() -> ton::overlay::Certificate {
        ton::overlay::certificate::Certificate {
            issued_by: ton::PublicKey::Pub_Ed25519(ton::pub_::publickey::Ed25519 {
                key: UInt256::from([7; 32]),
            }),
            expire_at: 5,
            max_size: -1,
            signature: vec![9; 64].into(),
        }
        .into_boxed()
    }

    #[test]
    fn certificate_requests_keep_wire_bit_patterns_and_bytes() {
        let rq = SignShardOverlayCertificateRq {
            workchain: 0,
            shard: i64::MIN,
            key_hash: vec![1; 32],
            expire_at: -5,
            max_size: u32::MAX,
        };
        let query = SignShardOverlayCertificateRqRs::serialize(&rq)
            .unwrap()
            .downcast::<ton::rpc::engine::validator::SignShardOverlayCertificate>()
            .unwrap();
        assert_eq!((query.shard, query.expire_at, query.max_size), (i64::MIN, -5, -1));
        let bytes = serialize_boxed(&certificate()).unwrap();
        let reply =
            SignShardOverlayCertificateRqRs::deserialize(certificate().into_tl_object()).unwrap();
        assert_eq!(reply, bytes, "the reply is returned byte for byte");
        let import = ImportShardOverlayCertificateRq {
            workchain: -1,
            shard: i64::MIN,
            key_hash: vec![2; 32],
            certificate: bytes,
        };
        let query = ImportShardOverlayCertificateRqRs::serialize(&import)
            .unwrap()
            .downcast::<ton::rpc::engine::validator::ImportShardOverlayCertificate>()
            .unwrap();
        assert_eq!(query.cert, certificate());
        let short = SignShardOverlayCertificateRq { key_hash: vec![1; 31], ..rq };
        assert!(SignShardOverlayCertificateRqRs::serialize(&short).is_err());
        let query = SetExtMessagesBroadcastDisabledRqRs::serialize(&true)
            .unwrap()
            .downcast::<ton::rpc::engine::validator::SetExtMessagesBroadcastDisabled>()
            .unwrap();
        assert_eq!(query.disabled, ton::Bool::BoolTrue);
    }
}

#[cfg(test)]
mod lite_answer_tests {
    use super::*;
    use rtos_block::{
        AccountStatus, BocWriter, ConfigParam15, ConfigParamEnum, ConfigParams, CurrencyCollection,
        McStateExtra, MerkleProof, Serializable, ShardIdent, ShardStateUnsplit, UsageTree,
    };
    use std::collections::HashSet;

    fn address() -> MsgAddressInt {
        MsgAddressInt::from_str(
            "0:1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap()
    }

    /// A lite-server account answer built as the node's lite server builds it:
    /// the account proof is the second root of the proof bag of cells.
    fn account_answer(address: &MsgAddressInt, last_trans_lt: u64) -> (Vec<u8>, Vec<u8>) {
        let account = rtos_block::Account::with_address_and_ballance(
            address,
            &CurrencyCollection::with_coins(7_000),
        );
        let mut state = ShardStateUnsplit::with_ident(ShardIdent::full(0));
        let shard_account =
            rtos_block::ShardAccount::with_params(&account, UInt256::default(), last_trans_lt)
                .unwrap();
        state.insert_account(&address.address(), &shard_account).unwrap();
        let root = state.serialize().unwrap();
        let usage = UsageTree::with_params(root.clone(), true);
        let used = ShardStateUnsplit::construct_from_cell(usage.root_cell()).unwrap();
        let found = used.read_accounts().unwrap().account(&address.address()).unwrap().unwrap();
        let account_boc = write_boc_of(&found.account_cell());
        let proof = MerkleProof::create_by_usage_tree(&root, &usage).unwrap();
        let block_proof = rtos_block::BuilderData::new().into_cell().unwrap();
        let proof = BocWriter::with_roots([block_proof, proof.serialize().unwrap()])
            .unwrap()
            .write_to_vec()
            .unwrap();
        (account_boc, proof)
    }

    fn write_boc_of(cell: &rtos_block::Cell) -> Vec<u8> {
        BocWriter::with_roots([cell.clone()]).unwrap().write_to_vec().unwrap()
    }

    #[test]
    fn account_answer_reads_the_account_and_its_last_transaction() {
        let address = address();
        let (state, proof) = account_answer(&address, 0x1234);
        let Account::ShardAccountState(account) =
            account_from_lite_state(&address, &state, &proof).unwrap()
        else {
            panic!("the account exists");
        };
        assert_eq!(account.status, AccountStatus::AccStateUninit);
        assert_eq!(account.balance, 7_000);
        assert_eq!(account.last_trans, 0x1234);
        assert_eq!(account.data, state, "the account bag of cells is returned as received");
    }

    #[test]
    fn empty_account_answer_is_an_account_that_does_not_exist() {
        assert!(matches!(
            account_from_lite_state(&address(), &[], &[]).unwrap(),
            Account::Nonexist
        ));
    }

    #[test]
    fn account_answer_without_the_account_in_its_proof_is_refused() {
        let (state, proof) = account_answer(&address(), 1);
        let other = MsgAddressInt::from_str(
            "0:2222222222222222222222222222222222222222222222222222222222222222",
        )
        .unwrap();
        assert!(account_from_lite_state(&other, &state, &proof).is_err());
        // A proof with a single root has no state proof.
        let single = write_boc_of(&rtos_block::BuilderData::new().into_cell().unwrap());
        let error = account_from_lite_state(&address(), &state, &single).unwrap_err();
        assert!(error.to_string().contains("without a state proof"), "{error}");
    }

    #[test]
    fn config_param_comes_from_the_pruned_configuration_proof() {
        let mut config = ConfigParams::default();
        let param = ConfigParam15 {
            validators_elected_for: 65536,
            elections_start_before: 32768,
            elections_end_before: 8192,
            stake_held_for: 4096,
        };
        config.set_config(ConfigParamEnum::ConfigParam15(param)).unwrap();
        let expected = rtos_block_json::serialize_config_param(&config, 15).unwrap();
        let extra = McStateExtra { config, ..Default::default() };
        let mut state = ShardStateUnsplit::with_ident(ShardIdent::masterchain());
        state.write_custom(Some(&extra)).unwrap();
        let root = state.serialize().unwrap();
        // The lite server proves the path to the parameter and its subtree.
        let usage = UsageTree::with_params(root.clone(), true);
        let used = ShardStateUnsplit::construct_from_cell(usage.root_cell()).unwrap();
        let config = used.read_custom().unwrap().unwrap().config;
        let key = rtos_block::SliceData::load_builder(15u32.write_to_new_cell().unwrap()).unwrap();
        let leaf = config.config_params.get(key).unwrap().unwrap();
        let subtrees: HashSet<UInt256> =
            [leaf.cell().unwrap().repr_hash().clone()].into_iter().collect();
        let proof = MerkleProof::create_with_subtrees(
            &root,
            |h| usage.contains(h),
            |h| subtrees.contains(h),
        )
        .unwrap();
        let proof = proof.write_to_bytes().unwrap();
        let answer = config_param_from_proof(&proof, 15).unwrap();
        assert_eq!(String::from_utf8(answer).unwrap(), expected);
        assert!(expected.contains("65536"), "{expected}");
    }
}
