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
    async fn lookup_block_by_lt(&self, _: &AccountIdPrefixFull, lt: u64) -> Result<Option<(BlockIdExt, Vec<u8>)>> {
        self.lookups.lock().unwrap().push(lt);
        Ok(Some((self.id.clone(), self.data.clone())))
    }
    fn engine_allocated(&self) -> &Arc<EngineAlloc> { &self.allocated }
    #[cfg(feature = "telemetry")]
    fn engine_telemetry(&self) -> &Arc<EngineTelemetry> { &self.telemetry }
    fn now(&self) -> u32 { 1_700_000_000 }
}
fn fixture(first: u64, len: u64, account: &UInt256) -> Result<(Vec<u8>, BlockIdExt, HashMap<u64, UInt256>)> {
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
        let mut tx = Transaction::with_address_and_status(account.clone().into(), AccountStatus::AccStateActive);
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
    let subscriber = LiteServerQuerySubscriber::new(tokio::runtime::Handle::current(), engine, 16, 16, 1)?;
    let result = subscriber.try_consume_query(Query { data: serialize_boxed(&request)? }.into_tl_object(),
        &AdnlPeers::with_keys(KeyId::from_data([0;32]), KeyId::from_data([0;32]))).await?;
    let answer = match result {
        QueryResult::Consumed(QueryAnswer::Ready(answer)) => answer,
        QueryResult::Consumed(QueryAnswer::Pending(handle)) => handle.await??.answer,
        _ => fail!("boundary query was not consumed"),
    };
    match answer { Some(Answer::Object(reply)) => Ok(reply.object), _ => fail!("boundary query did not return an object") }
}
fn unhex(value: &str) -> Vec<u8> {
    value.as_bytes().chunks_exact(2).map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(),16).unwrap()).collect()
}
fn transaction_roots(data: &[u8]) -> Result<Vec<UInt256>> {
    if data.is_empty() { return Ok(vec![]); }
    Ok(rtos_block::read_boc(data)?.roots.into_iter().map(|cell| cell.repr_hash().clone()).collect())
}
#[tokio::test]
async fn liteserver_transaction_boundary_reference() -> Result<()> {
    let account = UInt256::from([0x22;32]);
    let low = fixture(500, 20, &account)?;
    let high = fixture((1_u64<<63)-8, 20, &account)?;
    let edge = fixture(u64::MAX-1, 1, &account)?;
    let references: HashMap<_,_> = include_str!("data/liteserver-transaction-boundaries.tsv")
        .lines().filter_map(|line| line.split_once('\t')).collect();
    let export = std::env::var_os("RTOS_LITESERVER_BOUNDARY_EXPORT").map(std::path::PathBuf::from);
    if let Some(path) = &export { std::fs::create_dir_all(path)?; }
    let mut failures = vec![];
    let mut outcomes = vec![];
    let mut cases = vec![];
    for count in [i32::MIN,-1,0,1,2,15,16,17,i32::MAX] {
        for lt in [0,519,i64::MAX,i64::MIN,i64::MIN+1,-2,-1] {
            cases.push((format!("count-{count}-lt-{lt}"), count, lt, -1));
        }
    }
    for count in [-1,0,1,i32::MAX] {
        for lt in [0,i64::MIN,-1] {
            cases.push((format!("invalid-wc-count-{count}-lt-{lt}"),count,lt,INVALID_WORKCHAIN_ID));
        }
    }
    for (name,count,lt,workchain) in cases {
        let (raw,id,hashes) = if lt == -1 || lt == -2 { &edge } else if lt == 0 || lt == 519 { &low } else { &high };
        let engine = Arc::new(BoundaryEngine { id:id.clone(), data:raw.clone(),lookups:Mutex::new(vec![]),allocated:create_engine_allocated(),
            #[cfg(feature="telemetry")] telemetry:create_engine_telemetry() });
        let request = GetTransactions { count, account:AccountIdTl { workchain,id:account.clone() },lt,
            hash:hashes.get(&(lt as u64)).cloned().unwrap_or(UInt256::from([0x55;32])) }.into_tl_object();
        let reply = query(engine.clone(),request.clone()).await?;
        let lookups = engine.lookups.lock().unwrap().clone();
        let trace = lookups.iter().map(ToString::to_string).collect::<Vec<_>>().join(",");
        if let Some(path) = &export {
            std::fs::write(path.join(format!("{name}.block.boc")),raw)?;
            std::fs::write(path.join(format!("{name}.query.bin")),serialize_boxed(&request)?)?;
            std::fs::write(path.join(format!("{name}.rust.bin")),serialize_boxed(&reply)?)?;
            std::fs::write(path.join(format!("{name}.lookups")), &trace)?;
        }
        let check = (|| -> Result<()> {
            let row = references.get(name.as_str()).ok_or_else(|| error!("missing reference {name}"))?;
            let fields:Vec<_> = row.split('\t').collect();
            if fields[0]=="ERROR" {
                let error = reply.clone().downcast::<ErrorEnum>().map_err(|_|error!("reference error, Rust success"))?;
                if workchain==INVALID_WORKCHAIN_ID && count>=0 {
                    assert!(error.message().contains("invalid workchain specified"));
                }
            } else {
                let mut bytes=unhex(fields[1]);
                assert_eq!(u32::from_le_bytes(bytes[..4].try_into().unwrap()),0x8db4da3a);
                use rtos_api::Constructor;
                bytes[..4].copy_from_slice(&rtos_api::ton::lite_server::transactionlist::TransactionList::constructor_const().to_le_bytes());
                let reference = rtos_api::deserialize_boxed(bytes)?.downcast::<rtos_api::ton::lite_server::TransactionList>().unwrap();
                let actual = reply.clone().downcast::<rtos_api::ton::lite_server::TransactionList>().map_err(|_|error!("reference success, Rust error"))?;
                assert_eq!(actual.ids(),reference.ids(),"{name}: block identities");
                let roots=transaction_roots(actual.transactions())?;
                assert_eq!(roots,transaction_roots(reference.transactions())?,"{name}: full transaction roots");
                assert_eq!(actual.ids().len(),roots.len());
                if count==0 || lt==0 { assert!(roots.is_empty()); assert!(actual.transactions().is_empty()); }
                else { assert!(roots.len()<=16); assert_eq!(roots.first(),hashes.get(&(lt as u64))); }
            }
            assert_eq!(trace,fields[2],"{name}: actual unsigned database lookup LT");
            Ok(())
        })();
        if let Err(error)=check { failures.push(format!("{name}: {error}")); }
        outcomes.push(format!("{name}\t{:?}\t{trace}",reply));
    }
    if let Some(path)=export { std::fs::write(path.join("outcomes.tsv"),outcomes.join("\n")+"\n")?; }
    assert!(failures.is_empty(),"{} reference differences: {:?}",failures.len(),failures);
    Ok(())
}
