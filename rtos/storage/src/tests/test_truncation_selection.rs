use super::*;
use rtos_block::{ShardIdent, UInt256};
use std::io::Cursor;

fn block(shard: ShardIdent, seq: u32, tag: u8) -> BlockIdExt {
    BlockIdExt::with_params(
        shard,
        seq,
        UInt256::from([tag; 32]),
        UInt256::from([tag.wrapping_add(1); 32]),
    )
}

#[test]
fn owned_selection_preserves_original_cutoff_and_shard_predicate() -> Result<()> {
    let left = ShardIdent::with_tagged_prefix(0, 0x4000_0000_0000_0000)?;
    let right = ShardIdent::with_tagged_prefix(0, 0xc000_0000_0000_0000)?;
    let cutoff = block(ShardIdent::masterchain(), 11, 1);
    let tops: Arc<[BlockIdExt]> =
        vec![block(left.clone(), 10, 2), block(right.clone(), 20, 3)].into();
    let pointer = tops.as_ptr();
    let selection = TruncationSelection::new(cutoff.clone(), tops.clone())?;
    assert_eq!(selection.top_blocks().as_ptr(), pointer);
    for shard in [ShardIdent::masterchain(), left, right, ShardIdent::full(0), ShardIdent::full(1)]
    {
        for seq in [9, 10, 11, 19, 20, 21] {
            let id = block(shard.clone(), seq, 4);
            let original = if id.shard().is_masterchain() {
                id.seq_no() >= cutoff.seq_no()
            } else {
                tops.iter()
                    .any(|top| id.shard().intersect_with(top.shard()) && id.seq_no() > top.seq_no())
            };
            assert_eq!(selection.should_delete(&id), original, "{id}");
        }
    }
    assert!(selection.should_delete(&cutoff));
    assert!(!selection.should_delete(&tops[0]));
    assert!(TruncationSelection::new(tops[0].clone(), Vec::new()).is_err());
    Ok(())
}

#[test]
fn predicate_stream_preserves_full_ids_and_next_record() -> Result<()> {
    let selection = TruncationSelection::new(
        block(ShardIdent::masterchain(), 11, 7),
        vec![block(ShardIdent::full(0), 10, 8), block(ShardIdent::full(1), 12, 9)],
    )?;
    let mut bytes = Vec::new();
    selection.write_predicate(&mut bytes)?;
    assert_eq!(bytes.len() as u64, selection.encoded_len()?);
    assert_eq!(bytes.len(), 90 + 2 * 80);
    assert_eq!(&bytes[..2], &[1, 0]);
    assert_eq!(&bytes[2..82], selection.cutoff().serialize());
    assert_eq!(&bytes[82..90], &2u64.to_le_bytes());
    bytes.extend_from_slice(b"next record");
    let mut reader = Cursor::new(bytes);
    let mut tops = Vec::new();
    let cutoff = read_predicate(&mut reader, selection.encoded_len()?, |id| {
        tops.push(id);
        Ok(())
    })?;
    assert_eq!(&cutoff, selection.cutoff());
    assert_eq!(tops, selection.top_blocks());
    assert_eq!(reader.position(), selection.encoded_len()?);
    let restored = TruncationSelection::new(cutoff, tops)?;
    for id in selection.top_blocks() {
        assert_eq!(restored.should_delete(id), selection.should_delete(id));
    }
    Ok(())
}

#[test]
fn predicate_framing_refuses_counts_before_visiting_or_allocating() -> Result<()> {
    let selection = TruncationSelection::new(block(ShardIdent::masterchain(), 11, 7), Vec::new())?;
    let mut bytes = Vec::new();
    selection.write_predicate(&mut bytes)?;
    let mut visits = 0;
    for count in [1, u64::MAX] {
        let mut corrupt = bytes.clone();
        corrupt[82..90].copy_from_slice(&count.to_le_bytes());
        assert!(read_predicate(&mut corrupt.as_slice(), 90, |_| {
            visits += 1;
            Ok(())
        })
        .is_err());
    }
    let mut corrupt = bytes.clone();
    corrupt[0] = 2;
    assert!(read_predicate(&mut corrupt.as_slice(), 90, |_| {
        visits += 1;
        Ok(())
    })
    .is_err());
    assert_eq!(visits, 0);
    for length in 0..bytes.len() {
        assert!(read_predicate(&mut &bytes[..length], 90, |_| Ok(())).is_err());
    }
    let cutoff =
        read_predicate(&mut bytes.as_slice(), 90, |_| panic!("empty selection must not visit"))?;
    assert_eq!(&cutoff, selection.cutoff());
    Ok(())
}
