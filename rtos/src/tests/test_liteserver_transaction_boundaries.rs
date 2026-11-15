// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::*;
use std::sync::Mutex;

struct BoundaryEngine {
    id: BlockIdExt,
    data: Vec<u8>,
    lookups: Mutex<Vec<u64>>,
    allocated: Arc<EngineAlloc>,
    #[cfg(feature = "telemetry")]
    telemetry: Arc<EngineTelemetry>,
}
#[async_trait::async_trait]
impl EngineOperations for BoundaryEngine {
    async fn lookup_block_by_lt(
        &self,
        _: &AccountIdPrefixFull,
        lt: u64,
    ) -> Result<Option<(BlockIdExt, Vec<u8>)>> {
        self.lookups.lock().unwrap().push(lt);
        Ok(Some((self.id.clone(), self.data.clone())))
    }
    fn engine_allocated(&self) -> &Arc<EngineAlloc> {
        &self.allocated
    }
    #[cfg(feature = "telemetry")]
    fn engine_telemetry(&self) -> &Arc<EngineTelemetry> {
        &self.telemetry
    }
    fn now(&self) -> u32 {
        1_700_000_000
    }
}
fn fixture(
    first: u64,
    len: u64,
    account: &UInt256,
) -> Result<(Vec<u8>, BlockIdExt, HashMap<u64, UInt256>)> {
    let (raw, id) = build_block_with_txs(ShardIdent::masterchain(), 9, &[])?;
    let mut block = Block::construct_from_bytes(&raw)?;
    let mut info = block.read_info()?;
    info.set_start_lt(first - 1);
    info.set_end_lt(first + len);
    block.write_info(&info)?;
    let mut hashes = HashMap::new();
    let mut previous_lt = 0;
    let mut previous_hash = UInt256::ZERO;
    let mut account_block = AccountBlock::with_address(account.clone().into());
    for lt in first..first + len {
        let mut tx = Transaction::with_address_and_status(
            account.clone().into(),
            AccountStatus::AccStateActive,
        );
        tx.set_logical_time(lt);
        tx.set_prev_trans_lt(previous_lt);
        tx.set_prev_trans_hash(previous_hash);
        previous_hash = tx.serialize()?.repr_hash().clone();
        previous_lt = lt;
        hashes.insert(lt, previous_hash.clone());
        account_block.add_transaction(&tx)?;
    }
    let mut accounts = ShardAccountBlocks::default();
    accounts.insert(&account_block)?;
    let mut extra = block.read_extra()?;
    extra.write_account_blocks(&accounts)?;
    block.write_extra(&extra)?;
    let (raw, id) = finalize_block_to_boc(id, &block)?;
    Ok((raw, id, hashes))
}
async fn query(engine: Arc<BoundaryEngine>, request: TLObject) -> Result<TLObject> {
    raw_query(engine, serialize_boxed(&request)?, rtos_api::WireProfile::Legacy).await
}
async fn raw_query(
    engine: Arc<BoundaryEngine>,
    data: Vec<u8>,
    profile: rtos_api::WireProfile,
) -> Result<TLObject> {
    let subscriber = LiteServerQuerySubscriber::new_with_profile(
        profile,
        tokio::runtime::Handle::current(),
        engine,
        16,
        16,
        1,
    )?;
    let result = subscriber
        .try_consume_query(
            Query { data }.into_tl_object(),
            &AdnlPeers::with_keys(KeyId::from_data([0; 32]), KeyId::from_data([0; 32])),
        )
        .await?;
    let answer = match result {
        QueryResult::Consumed(QueryAnswer::Ready(answer)) => answer,
        QueryResult::Consumed(QueryAnswer::Pending(handle)) => handle.await??.answer,
        _ => fail!("boundary query was not consumed"),
    };
    match answer {
        Some(Answer::Object(reply)) => Ok(reply.object),
        Some(Answer::Raw(reply)) => profile.deserialize(&reply.object),
        _ => fail!("boundary query did not return an object"),
    }
}

fn unhex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn transaction_roots(data: &[u8]) -> Result<Vec<UInt256>> {
    if data.is_empty() {
        return Ok(vec![]);
    }
    Ok(rtos_block::read_boc(data)?.roots.into_iter().map(|cell| cell.repr_hash().clone()).collect())
}
#[tokio::test]
async fn liteserver_transaction_boundary_reference() -> Result<()> {
    let account = UInt256::from([0x22; 32]);
    let low = fixture(500, 20, &account)?;
    let high = fixture((1_u64 << 63) - 8, 20, &account)?;
    let edge = fixture(u64::MAX - 1, 1, &account)?;
    let references: HashMap<_, _> = include_str!("data/liteserver-transaction-boundaries.tsv")
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .collect();
    let export = std::env::var_os("RTOS_LITESERVER_BOUNDARY_EXPORT").map(std::path::PathBuf::from);
    if let Some(path) = &export {
        std::fs::create_dir_all(path)?;
    }
    let mut failures = vec![];
    let mut outcomes = vec![];
    let mut cases = vec![];
    for count in [i32::MIN, -1, 0, 1, 2, 15, 16, 17, i32::MAX] {
        for lt in [0, 519, i64::MAX, i64::MIN, i64::MIN + 1, -2, -1] {
            cases.push((format!("count-{count}-lt-{lt}"), count, lt, -1));
        }
    }
    for count in [-1, 0, 1, i32::MAX] {
        for lt in [0, i64::MIN, -1] {
            cases.push((
                format!("invalid-wc-count-{count}-lt-{lt}"),
                count,
                lt,
                INVALID_WORKCHAIN_ID,
            ));
        }
    }
    for (name, count, lt, workchain) in cases {
        let (raw, id, hashes) = if lt == -1 || lt == -2 {
            &edge
        } else if lt == 0 || lt == 519 {
            &low
        } else {
            &high
        };
        let engine = Arc::new(BoundaryEngine {
            id: id.clone(),
            data: raw.clone(),
            lookups: Mutex::new(vec![]),
            allocated: create_engine_allocated(),
            #[cfg(feature = "telemetry")]
            telemetry: create_engine_telemetry(),
        });
        let request = GetTransactions {
            count,
            account: AccountIdTl { workchain, id: account.clone() },
            lt,
            hash: hashes.get(&(lt as u64)).cloned().unwrap_or(UInt256::from([0x55; 32])),
        }
        .into_tl_object();
        let reply = query(engine.clone(), request.clone()).await?;
        let lookups = engine.lookups.lock().unwrap().clone();
        let trace = lookups.iter().map(ToString::to_string).collect::<Vec<_>>().join(",");
        if let Some(path) = &export {
            std::fs::write(path.join(format!("{name}.block.boc")), raw)?;
            std::fs::write(path.join(format!("{name}.query.bin")), serialize_boxed(&request)?)?;
            std::fs::write(path.join(format!("{name}.rust.bin")), serialize_boxed(&reply)?)?;
            std::fs::write(path.join(format!("{name}.lookups")), &trace)?;
        }
        let check = (|| -> Result<()> {
            let row =
                references.get(name.as_str()).ok_or_else(|| error!("missing reference {name}"))?;
            let fields: Vec<_> = row.split('\t').collect();
            if fields[0] == "ERROR" {
                let expected: serde_json::Value = serde_json::from_str(fields[1])?;
                let bytes = serialize_boxed(&reply)?;
                assert_eq!(
                    i32::from_le_bytes(bytes[4..8].try_into().unwrap()) as i64,
                    expected["code"].as_i64().unwrap(),
                    "{name}: public error code"
                );
                let error = reply
                    .clone()
                    .downcast::<ErrorEnum>()
                    .map_err(|_| error!("reference error, Rust success"))?;
                if count < 0 {
                    assert!(
                        error.message().as_str().unwrap().contains("negative"),
                        "negative count is rejected before workchain validation"
                    );
                }
                if workchain == INVALID_WORKCHAIN_ID && count >= 0 {
                    assert!(error
                        .message()
                        .as_str()
                        .unwrap()
                        .contains("invalid workchain specified"));
                }
            } else {
                let mut bytes = unhex(fields[1]);
                assert_eq!(u32::from_le_bytes(bytes[..4].try_into().unwrap()), 0x8db4da3a);
                use rtos_api::Constructor;
                bytes[..4].copy_from_slice(&rtos_api::ton::lite_server::transactionlist::TransactionList::constructor_const().to_le_bytes());
                let reference = rtos_api::deserialize_boxed(bytes)?
                    .downcast::<rtos_api::ton::lite_server::TransactionList>()
                    .unwrap();
                let actual = reply
                    .clone()
                    .downcast::<rtos_api::ton::lite_server::TransactionList>()
                    .map_err(|_| error!("reference success, Rust error"))?;
                assert_eq!(actual.ids(), reference.ids(), "{name}: block identities");
                let roots = transaction_roots(actual.transactions())?;
                assert_eq!(
                    roots,
                    transaction_roots(reference.transactions())?,
                    "{name}: full transaction roots"
                );
                assert_eq!(actual.ids().len(), roots.len());
                if count == 0 || lt == 0 {
                    assert!(roots.is_empty());
                    assert!(actual.transactions().is_empty());
                } else {
                    assert!(roots.len() <= 16);
                    assert_eq!(roots.first(), hashes.get(&(lt as u64)));
                }
            }
            assert_eq!(
                trace,
                if fields[2] == "-" { "" } else { fields[2] },
                "{name}: actual unsigned database lookup LT"
            );
            Ok(())
        })();
        if let Err(error) = check {
            failures.push(format!("{name}: {error}"));
        }
        outcomes.push(format!("{name}\t{:?}\t{trace}", reply));
    }
    if let Some(path) = export {
        std::fs::write(path.join("outcomes.tsv"), outcomes.join("\n") + "\n")?;
    }
    assert!(failures.is_empty(), "{} reference differences: {:?}", failures.len(), failures);
    Ok(())
}

#[tokio::test]
async fn liteserver_one_transaction_boundary_reference() -> Result<()> {
    let account = UInt256::from([0x22; 32]);
    let references: HashMap<_, _> = include_str!("data/liteserver-one-transaction-boundaries.tsv")
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .collect();
    let export =
        std::env::var_os("RTOS_LITESERVER_ONE_BOUNDARY_EXPORT").map(std::path::PathBuf::from);
    if let Some(path) = &export {
        std::fs::create_dir_all(path)?;
    }
    let mut failures = vec![];
    for (label, first, len) in
        [("low", 500, 20), ("high", (1_u64 << 63) - 8, 20), ("edge", u64::MAX - 1, 1)]
    {
        let (raw, id, hashes) = fixture(first, len, &account)?;
        let mut engine = LiteServerTestEngine::new().await;
        engine.add_mock_block_with_handle(id.clone(), raw.clone()).await?;
        let engine = Arc::new(engine);
        for lt in [0, 519, i64::MAX, i64::MIN, i64::MIN + 1, -2, -1] {
            for (kind, workchain, addr) in [
                ("present-account", -1, account.clone()),
                ("missing-account", -1, UInt256::from([0x33; 32])),
                ("wrong-workchain", 0, account.clone()),
            ] {
                let name = format!("{label}-{kind}-lt-{lt}");
                let request = GetOneTransaction {
                    id: id.clone(),
                    account: AccountIdTl { workchain, id: addr.clone() },
                    lt,
                }
                .into_tl_object();
                let reply = send_query(engine.clone(), request.clone(), &name).await?;
                if let Some(path) = &export {
                    std::fs::write(path.join(format!("{name}.block.boc")), &raw)?;
                    std::fs::write(
                        path.join(format!("{name}.query.bin")),
                        serialize_boxed(&request)?,
                    )?;
                    std::fs::write(
                        path.join(format!("{name}.rust.bin")),
                        serialize_boxed(&reply)?,
                    )?;
                }
                let fields: Vec<_> = references[name.as_str()].split('\t').collect();
                if fields[0] == "ERROR" {
                    let reference_error: String = serde_json::from_str(fields[1])?;
                    let code: i32 = reference_error.split('\t').nth(1).unwrap().parse()?;
                    let bytes = serialize_boxed(&reply)?;
                    assert_eq!(
                        i32::from_le_bytes(bytes[4..8].try_into().unwrap()),
                        code,
                        "{name}: public error code"
                    );
                    let error = reply.downcast::<ErrorEnum>().expect("wrong workchain is an error");
                    if !error.message().as_str().unwrap().contains("cannot contain account") {
                        failures.push(format!("{name}: {}", error.message()));
                    }
                    continue;
                }
                let mut bytes = unhex(fields[1]);
                assert_eq!(
                    u32::from_le_bytes(bytes[..4].try_into().unwrap()),
                    (-12693415i32) as u32
                );
                use rtos_api::Constructor;
                bytes[..4].copy_from_slice(&rtos_api::ton::lite_server::transactioninfo::TransactionInfo::constructor_const().to_le_bytes());
                let reference = rtos_api::deserialize_boxed(bytes)?
                    .downcast::<rtos_api::ton::lite_server::TransactionInfo>()
                    .unwrap();
                let present = addr == account && hashes.contains_key(&(lt as u64));
                super::absence_reference::check_one(&reference, &id, &addr, lt as u64, present)?;
                match reply.downcast::<rtos_api::ton::lite_server::TransactionInfo>() {
                    Ok(actual) => {
                        super::absence_reference::check_one(
                            &actual, &id, &addr, lt as u64, present,
                        )?;
                        assert_eq!(
                            transaction_roots(actual.transaction())?,
                            transaction_roots(reference.transaction())?,
                            "{name}"
                        );
                    }
                    Err(_) => failures
                        .push(format!("{name}: reference proof-bearing success, Rust error")),
                }
            }
        }
    }
    assert!(failures.is_empty(), "{} one-transaction differences: {:?}", failures.len(), failures);
    Ok(())
}

#[tokio::test]
async fn liteserver_transaction_error_reference() -> Result<()> {
    let account = UInt256::from([0x22; 32]);
    let references: HashMap<_, _> = include_str!("data/liteserver-transaction-errors.tsv")
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .collect();
    let export = std::env::var_os("RTOS_LITESERVER_ERROR_EXPORT").map(std::path::PathBuf::from);
    if let Some(path) = &export {
        std::fs::create_dir_all(path)?;
    }
    let mut failures = vec![];
    for (label, first, len, lt) in [
        ("low", 500, 20, 519),
        ("high", (1_u64 << 63) - 8, 20, i64::MIN),
        ("edge", u64::MAX - 1, 1, -2),
    ] {
        let (raw, id, hashes) = fixture(first, len, &account)?;
        for variant in [
            "zero-hash",
            "wrong-hash",
            "missing-account",
            "zero-count",
            "negative-count-invalid-wc",
            "zero-count-invalid-wc",
            "negative-count-truncated",
            "positive-count-truncated",
            "count-truncated-4",
            "count-truncated-5",
            "count-truncated-7",
        ] {
            let name = format!("{label}-{variant}");
            let mut count = 1;
            let mut workchain = -1;
            let mut addr = account.clone();
            let mut hash = hashes[&(lt as u64)].clone();
            match variant {
                "zero-hash" => hash = UInt256::ZERO,
                "wrong-hash" => hash = UInt256::from([0x55; 32]),
                "missing-account" => addr = UInt256::from([0x33; 32]),
                "zero-count" => count = 0,
                "negative-count-invalid-wc" => {
                    count = -1;
                    workchain = INVALID_WORKCHAIN_ID;
                }
                "zero-count-invalid-wc" => {
                    count = 0;
                    workchain = INVALID_WORKCHAIN_ID;
                }
                "negative-count-truncated" => count = -1,
                "positive-count-truncated"
                | "count-truncated-4"
                | "count-truncated-5"
                | "count-truncated-7" => {}
                _ => unreachable!(),
            }
            let engine = Arc::new(BoundaryEngine {
                id: id.clone(),
                data: raw.clone(),
                lookups: Mutex::new(vec![]),
                allocated: create_engine_allocated(),
                #[cfg(feature = "telemetry")]
                telemetry: create_engine_telemetry(),
            });
            let request =
                GetTransactions { count, account: AccountIdTl { workchain, id: addr }, lt, hash }
                    .into_tl_object();
            let mut raw_request = serialize_boxed(&request)?;
            if variant == "negative-count-truncated" || variant == "positive-count-truncated" {
                raw_request.truncate(8);
            }
            if let Some(len) = variant.strip_prefix("count-truncated-") {
                raw_request.truncate(len.parse()?);
            }
            let reply = raw_query(engine, raw_request.clone(), rtos_api::WireProfile::Legacy).await;
            if let Some(path) = &export {
                std::fs::write(path.join(format!("{name}.block.boc")), &raw)?;
                std::fs::write(path.join(format!("{name}.query.bin")), &raw_request)?;
            }
            let reply = match reply {
                Ok(reply) => reply,
                Err(error) => {
                    failures.push(format!("{name}: unframed error {error}"));
                    continue;
                }
            };
            let bytes = serialize_boxed(&reply)?;
            if let Some(path) = &export {
                std::fs::write(path.join(format!("{name}.rust.bin")), &bytes)?;
            }
            let fields: Vec<_> = references[name.as_str()].split('\t').collect();
            if fields[0] == "ERROR" {
                match reply.downcast::<ErrorEnum>() {
                    Ok(error) => {
                        let code = i32::from_le_bytes(bytes[4..8].try_into().unwrap());
                        if code != fields[1].parse::<i32>()? {
                            failures.push(format!("{name}: code {code}, expected {}", fields[1]));
                        }
                        let message = fields[2].strip_suffix(" at 8").unwrap_or(fields[2]);
                        let category_matches = if variant == "positive-count-truncated"
                            || variant.starts_with("count-truncated-")
                        {
                            !error.message().as_str().unwrap().contains("negative")
                        } else {
                            error.message().as_str().unwrap().contains(message)
                        };
                        if !category_matches {
                            failures
                                .push(format!("{name}: wrong error category {}", error.message()));
                        }
                    }
                    Err(_) => failures.push(format!("{name}: reference rejection, Rust success")),
                }
            } else {
                let actual = reply
                    .downcast::<rtos_api::ton::lite_server::TransactionList>()
                    .expect("zero count is successful");
                assert!(actual.ids().is_empty());
                assert!(actual.transactions().is_empty());
            }
        }
    }
    assert!(failures.is_empty(), "{} error semantics differences: {:?}", failures.len(), failures);
    Ok(())
}

#[tokio::test]
async fn liteserver_transaction_decode_profile_boundaries() -> Result<()> {
    use rtos_api::{Constructor, WireProfile};
    let export = std::env::var_os("RTOS_LITESERVER_DECODE_EXPORT").map(std::path::PathBuf::from);
    if let Some(path) = &export {
        std::fs::create_dir_all(path)?;
    }
    let account = UInt256::from([0x22; 32]);
    let (raw, id, hashes) = fixture(500, 20, &account)?;
    let engine = Arc::new(BoundaryEngine {
        id,
        data: raw,
        lookups: Mutex::new(vec![]),
        allocated: create_engine_allocated(),
        #[cfg(feature = "telemetry")]
        telemetry: create_engine_telemetry(),
    });
    for profile in [WireProfile::Legacy, WireProfile::T0] {
        for (count, length) in [(-1, 84), (-1, 8), (1, 8), (1, 4), (1, 5), (1, 7)] {
            let request = GetTransactions {
                count,
                account: AccountIdTl { workchain: INVALID_WORKCHAIN_ID, id: account.clone() },
                lt: 519,
                hash: hashes[&519].clone(),
            };
            let mut bytes = profile.serialize(&request)?;
            assert_eq!(
                bytes,
                WireProfile::Legacy.serialize(&request)?,
                "getTransactions has a shared constructor/layout"
            );
            bytes.truncate(length);
            if let Some(path) = &export {
                std::fs::write(
                    path.join(format!("{profile:?}-list-{count}-{length}.query.bin")),
                    &bytes,
                )?;
            }
            let reply = raw_query(engine.clone(), bytes, profile).await?;
            let bytes = serialize_boxed(&reply)?;
            let error = reply.downcast::<ErrorEnum>().expect("decode error is a public reply");
            assert_eq!(i32::from_le_bytes(bytes[4..8].try_into().unwrap()), 0);
            assert_eq!(error.message().as_str().unwrap().contains("negative"), count < 0);
        }
    }
    for profile in [WireProfile::Legacy, WireProfile::T0] {
        let request = GetOneTransaction {
            id: engine.id.clone(),
            account: AccountIdTl { workchain: -1, id: account.clone() },
            lt: 519,
        };
        for line in include_str!("data/liteserver-one-transaction-decode-errors.tsv").lines() {
            let fields: Vec<_> = line.split('\t').collect();
            let mut bytes = profile.serialize(&request)?;
            bytes.truncate(fields[0].parse()?);
            if let Some(path) = &export {
                std::fs::write(
                    path.join(format!("{profile:?}-one-{}.query.bin", fields[0])),
                    &bytes,
                )?;
            }
            let reply = raw_query(engine.clone(), bytes, profile).await?;
            let bytes = serialize_boxed(&reply)?;
            let error = reply
                .downcast::<ErrorEnum>()
                .expect("one-transaction decode error is a public reply");
            assert_eq!(
                i32::from_le_bytes(bytes[4..8].try_into().unwrap()),
                fields[2].parse::<i32>()?
            );
            assert!(!error.message().as_str().unwrap().contains("negative"));
        }
    }
    for constructor in [GetOneTransaction::constructor_const(), 0xdeadbeef] {
        let mut bytes = constructor.to_le_bytes().to_vec();
        bytes.extend_from_slice(&(-1_i32).to_le_bytes());
        assert!(
            raw_query(engine.clone(), bytes, WireProfile::T0).await.is_err(),
            "wrong-profile or unknown constructor is not a count precheck"
        );
    }
    assert!(engine.lookups.lock().unwrap().is_empty());
    Ok(())
}
