// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::sync::Mutex;
#[derive(Debug)]
struct Limit;
impl std::fmt::Display for Limit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "test config limit")
    }
}
impl std::error::Error for Limit {}
struct Budget {
    left: Mutex<(usize, usize)>,
}
impl Budget {
    fn new(steps: usize, bytes: usize) -> Self {
        Self { left: Mutex::new((steps, bytes)) }
    }
}
impl ConfigReadBudget for Budget {
    fn step(&self) -> Result<()> {
        let mut u = self.left.lock().unwrap();
        if u.0 == 0 {
            return Err(Limit.into());
        }
        u.0 -= 1;
        Ok(())
    }
    fn workspace(&self, n: usize) -> Result<()> {
        let mut u = self.left.lock().unwrap();
        if n > u.1 {
            return Err(Limit.into());
        }
        u.1 -= n;
        Ok(())
    }
}
fn nodes() -> Vec<ValidatorDescr> {
    (1u8..=6)
        .map(|i| {
            let public_key = vec![i; 1312];
            ValidatorDescr::with_pq_params(
                UInt256::from([i; 32]),
                PqConsensusKey {
                    algorithm_id: 1,
                    key_id: derive_consensus_key_id(1, &public_key),
                    public_key,
                },
                u64::from(i),
                UInt256::from([i + 20; 32]),
            )
        })
        .collect()
}
#[test]
fn bounded_config_validator_decode_and_subset_equal_ordinary() {
    let set = ValidatorSet::new(1, 100, 2, nodes()).unwrap();
    let cell = set.serialize().unwrap();
    let budget = Budget::new(1_000_000, 16 << 20);
    let decoded =
        ValidatorSet::construct_bounded(&mut SliceData::load_cell(cell).unwrap(), &budget).unwrap();
    assert_eq!(decoded, set);
    for shuffle in [false, true] {
        for isolate in [false, true] {
            let config = CatchainConfig {
                shuffle_mc_validators: shuffle,
                isolate_mc_validators: isolate,
                shard_validators_num: 3,
                ..Default::default()
            };
            for (shard, wc) in [(SHARD_FULL, MASTERCHAIN_ID), (SHARD_FULL, 0)] {
                for cc in [0, 1, 99] {
                    assert_eq!(
                        set.calc_subset_bounded(&config, shard, wc, cc, &budget).unwrap(),
                        set.calc_subset(&config, shard, wc, cc).unwrap()
                    );
                }
            }
        }
    }
}
#[test]
fn bounded_config_declared_count_and_key_length_refuse_before_allocation() {
    let mut record = BuilderData::new();
    record.append_u8(VALIDATOR_SET_EX_TAG).unwrap();
    1u32.write_to(&mut record).unwrap();
    100u32.write_to(&mut record).unwrap();
    u16::MAX.write_to(&mut record).unwrap();
    1u16.write_to(&mut record).unwrap();
    1u64.write_to(&mut record).unwrap();
    // Pass the maximal-index shape check, then hit the declared vector budget
    // before attempting to read the missing low indices.
    let mut dictionary = ValidatorDescriptions::default();
    dictionary.set(&(u16::MAX - 1), &nodes()[0]).unwrap();
    dictionary.write_to(&mut record).unwrap();
    let e = ValidatorSet::construct_bounded(
        &mut SliceData::load_builder(record).unwrap(),
        &Budget::new(100, 1024),
    )
    .unwrap_err();
    assert!(e.downcast_ref::<Limit>().is_some());
    let mut key = BuilderData::new();
    8192u32.write_to(&mut key).unwrap();
    let key = key.into_cell().unwrap();
    let e =
        crate::pq_bytes::unpack_pq_bytes_bounded(&key, 8192, &Budget::new(10, 8191)).unwrap_err();
    assert!(e.downcast_ref::<Limit>().is_some());
    // At the allocation threshold the actual malformed missing-reference error is exposed.
    let e =
        crate::pq_bytes::unpack_pq_bytes_bounded(&key, 8192, &Budget::new(10, 8192)).unwrap_err();
    assert!(e.downcast_ref::<Limit>().is_none());
}
#[test]
fn bounded_config_shared_dictionary_paths_consume_work() {
    let mut leaf = BuilderData::new();
    leaf.append_bit_zero().unwrap();
    leaf.append_bit_zero().unwrap();
    nodes()[0].write_to(&mut leaf).unwrap();
    let mut root = leaf.into_cell().unwrap();
    for _ in 0..8 {
        let mut branch = BuilderData::new();
        branch.append_bit_zero().unwrap();
        branch.append_bit_zero().unwrap();
        branch.checked_append_reference(root.clone()).unwrap();
        branch.checked_append_reference(root).unwrap();
        root = branch.into_cell().unwrap();
    }
    // Eight shared branch levels cover suffixes 0..255. Prefix their root
    // label with eight zeros so the maximal index agrees with total=256.
    let mut prefixed = BuilderData::new();
    prefixed.append_bit_zero().unwrap();
    prefixed.append_u8(255).unwrap();
    prefixed.append_bit_zero().unwrap();
    prefixed.append_u8(0).unwrap();
    prefixed.checked_append_reference(root.reference(0).unwrap()).unwrap();
    prefixed.checked_append_reference(root.reference(1).unwrap()).unwrap();
    let root = prefixed.into_cell().unwrap();
    let mut record = BuilderData::new();
    record.append_u8(VALIDATOR_SET_EX_TAG).unwrap();
    1u32.write_to(&mut record).unwrap();
    100u32.write_to(&mut record).unwrap();
    256u16.write_to(&mut record).unwrap();
    1u16.write_to(&mut record).unwrap();
    256u64.write_to(&mut record).unwrap();
    record.append_bit_one().unwrap();
    record.checked_append_reference(root).unwrap();
    let e = ValidatorSet::construct_bounded(
        &mut SliceData::load_builder(record).unwrap(),
        &Budget::new(80, 1 << 20),
    )
    .unwrap_err();
    assert!(e.downcast_ref::<Limit>().is_some(), "shared paths escaped accounting: {e:#}");
}
#[test]
fn bounded_config_key_history_traversal_matches_and_stops() {
    use crate::{dictionary::hashmapaug::HashmapAugType, KeyExtBlkRef, OldMcBlocksInfo};
    let mut index = OldMcBlocksInfo::default();
    for seq in 1..=32 {
        index.set_augmentable(&seq, &KeyExtBlkRef::fake(seq % 3 == 0, seq, seq as u64)).unwrap();
    }
    let budget = Budget::new(100_000, 1 << 20);
    for seq in 0..35 {
        assert_eq!(
            index.get_next_key_block_bounded(seq, &budget).unwrap(),
            index.get_next_key_block(seq).unwrap()
        );
    }
    let e = index.get_next_key_block_bounded(1, &Budget::new(0, 1 << 20)).unwrap_err();
    assert!(e.downcast_ref::<Limit>().is_some());
}
