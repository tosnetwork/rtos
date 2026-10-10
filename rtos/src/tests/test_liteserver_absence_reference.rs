// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::*;

fn record(
    name: &str,
    block: &[u8],
    query: &TLObject,
    reply: &TLObject,
) -> Result<Option<TLObject>> {
    if let Some(path) = std::env::var_os("RTOS_LITESERVER_REFERENCE_EXPORT") {
        let path = std::path::PathBuf::from(path);
        std::fs::create_dir_all(&path)?;
        std::fs::write(path.join(format!("{name}.block.boc")), block)?;
        std::fs::write(path.join(format!("{name}.query.bin")), serialize_boxed(query)?)?;
        std::fs::write(path.join(format!("{name}.rust.bin")), serialize_boxed(reply)?)?;
        return Ok(None);
    }
    let row = include_str!("data/liteserver-absence-reference.tsv")
        .lines()
        .find(|line| line.split('\t').next() == Some(name))
        .expect("fixed actor result");
    let (_, hex) = row.split_once('\t').unwrap();
    let mut bytes: Vec<u8> = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    // Handler comparison: the reference uses a different named wire profile.
    // Adapt only the outer response constructor; retain its original payload.
    use rtos_api::Constructor;
    if name != "empty-list" {
        assert_eq!(u32::from_le_bytes(bytes[..4].try_into().unwrap()), (-12693415i32) as u32);
        bytes[..4].copy_from_slice(
            &rtos_api::ton::lite_server::transactioninfo::TransactionInfo::constructor_const()
                .to_le_bytes(),
        );
    }
    if name == "empty-list" {
        assert_eq!(u32::from_le_bytes(bytes[..4].try_into().unwrap()), 0x8db4da3a);
        bytes[..4].copy_from_slice(
            &rtos_api::ton::lite_server::transactionlist::TransactionList::constructor_const()
                .to_le_bytes(),
        );
    }
    Ok(Some(rtos_api::deserialize_boxed(bytes)?))
}

fn check_one(
    reply: &rtos_api::ton::lite_server::TransactionInfo,
    id: &BlockIdExt,
    account: &UInt256,
    lt: u64,
    present: bool,
) -> Result<()> {
    assert_eq!(reply.id(), id);
    let proof = MerkleProof::construct_from_bytes(reply.proof())?;
    assert_eq!(proof.hash, id.root_hash);
    let block: Block = proof.virtualize()?;
    let info = block.read_info()?;
    let cell = if info.start_lt() < lt && lt < info.end_lt() {
        let key = SliceData::from_raw(account.as_slice().to_vec(), 256);
        // Preserve the proof's path while avoiding eager decoding of unrelated
        // pruned transaction cells in a single-leaf account transaction map.
        if let Some(mut value) =
            block.read_extra()?.read_account_blocks()?.get_serialized_as_slice(key)?
        {
            assert_eq!(value.get_next_int(4)?, 5);
            assert_eq!(&UInt256::construct_from(&mut value)?, account);
            let refs = value.remaining_references();
            value.shrink_references(..refs - 1)?; // AccountBlock's trailing state update
            Transactions::with_hashmap(Some(value.into_cell()?))?
                .get_as_slice(&lt)?
                .map(|slice| slice.reference(0))
                .transpose()?
        } else {
            None
        }
    } else {
        None
    };
    assert_eq!(cell.is_some(), present);
    if let Some(cell) = cell {
        assert_eq!(read_single_root_boc(reply.transaction())?.repr_hash(), cell.repr_hash());
    } else {
        assert!(reply.transaction().is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn liteserver_absence_reference_matrix() -> Result<()> {
    let account = UInt256::from([0x22; 32]);
    let (raw, template) =
        build_block_with_txs(ShardIdent::masterchain(), 9, &[(account.clone(), 555)])?;
    let mut block = Block::construct_from_bytes(&raw)?;
    let mut info = block.read_info()?;
    info.set_start_lt(100);
    info.set_end_lt(1000);
    block.write_info(&info)?;
    let (raw, id) = finalize_block_to_boc(template, &block)?;
    let mut engine = LiteServerTestEngine::new().await;
    engine.add_mock_block_with_handle(id.clone(), raw.clone()).await?;
    let engine = Arc::new(engine);
    for (name, addr, lt, present) in [
        ("present", account.clone(), 555, true),
        ("missing-account", UInt256::from([0x33; 32]), 555, false),
        ("missing-lt", account.clone(), 556, false),
        ("lt-zero", account.clone(), 0, false),
        ("lt-before", account.clone(), 99, false),
        ("lt-start", account.clone(), 100, false),
        ("lt-end", account.clone(), 1000, false),
        ("lt-after", account.clone(), 1001, false),
    ] {
        let query = GetOneTransaction {
            id: id.clone(),
            account: AccountIdTl { workchain: -1, id: addr.clone() },
            lt,
        }
        .into_tl_object();
        let reply = send_query(engine.clone(), query.clone(), name).await?;
        let reference = record(name, &raw, &query, &reply)?;
        check_one(
            &reply.downcast::<rtos_api::ton::lite_server::TransactionInfo>().unwrap(),
            &id,
            &addr,
            lt as u64,
            present,
        )?;
        if let Some(reference) = reference {
            check_one(
                &reference.downcast::<rtos_api::ton::lite_server::TransactionInfo>().unwrap(),
                &id,
                &addr,
                lt as u64,
                present,
            )?;
        }
    }
    let query = GetTransactions {
        count: 10,
        account: AccountIdTl { workchain: -1, id: account },
        lt: 0,
        hash: UInt256::ZERO,
    }
    .into_tl_object();
    let reply = send_query(engine.clone(), query.clone(), "empty-list").await?;
    let reference = record("empty-list", &raw, &query, &reply)?;
    let result = reply.downcast::<rtos_api::ton::lite_server::TransactionList>().unwrap();
    assert!(result.ids().is_empty());
    assert!(result.transactions().is_empty());
    if let Some(reference) = reference {
        assert_eq!(
            reference.downcast::<rtos_api::ton::lite_server::TransactionList>().unwrap(),
            result
        );
    }
    let invalid_query = GetTransactions {
        count: 10,
        account: AccountIdTl { workchain: INVALID_WORKCHAIN_ID, id: UInt256::from([0x22; 32]) },
        lt: 0,
        hash: UInt256::ZERO,
    }
    .into_tl_object();
    let invalid_reply =
        send_query(engine.clone(), invalid_query, "invalid-workchain-zero-lt").await?;
    let error = invalid_reply
        .downcast::<ErrorEnum>()
        .expect("invalid workchain must be rejected before zero-LT success");
    assert!(error.message().contains("invalid workchain specified"));
    // Wrong workchain remains an error and cannot be disguised as absence.
    let err = LiteServerQuerySubscriber::get_one_transaction(
        &(engine as Arc<dyn EngineOperations>),
        id,
        AccountIdTl { workchain: 0, id: UInt256::ZERO },
        555,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("cannot contain account"));
    Ok(())
}
