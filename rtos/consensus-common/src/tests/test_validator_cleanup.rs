// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Ported from the reference implementation's validator-cleanup unit tests,
//! adapted to the three RTOS namespace layouts.
use super::*;
use std::collections::BTreeSet;

fn session(byte: u8) -> UInt256 {
    UInt256::from([byte; 32])
}
fn masterchain() -> ShardIdent {
    ShardIdent::masterchain()
}
fn checkpoint(seqno: u32) -> BlockIdExt {
    BlockIdExt::with_params(
        masterchain(),
        seqno,
        UInt256::from([0x11; 32]),
        UInt256::from([0x22; 32]),
    )
}
fn fork_checkpoint(seqno: u32) -> BlockIdExt {
    BlockIdExt::with_params(
        masterchain(),
        seqno,
        UInt256::from([0x33; 32]),
        UInt256::from([0x44; 32]),
    )
}
fn record(byte: u8, retired_at: u32) -> PendingValidatorCleanup {
    make_record(&session(byte), &NamespaceLayout::V1, &masterchain(), 7, &checkpoint(retired_at))
        .unwrap()
}
fn layouts() -> Vec<NamespaceLayout> {
    vec![
        NamespaceLayout::V1,
        NamespaceLayout::V2Validator,
        NamespaceLayout::V2Observer(UInt256::from([0xab; 32])),
    ]
}

#[test]
fn validator_cleanup_record_round_trips_for_every_layout() {
    for layout in layouts() {
        let record =
            make_record(&session(9), &layout, &masterchain(), 7, &checkpoint(100)).unwrap();
        let bytes = encode_record(&record);
        assert_eq!(decode_record(&bytes), Some(record.clone()), "{layout:?}");
        // Every truncation and a wrong version are rejected.
        for length in 0..bytes.len() {
            assert!(decode_record(&bytes[..length]).is_none(), "{layout:?} truncated to {length}");
        }
        let mut versioned = bytes.clone();
        versioned[0] = 2;
        assert!(decode_record(&versioned).is_none());
        let mut tailed = bytes;
        tailed.push(b'x');
        assert!(decode_record(&tailed).is_none(), "a trailing byte breaks the canonical name");
    }
}

#[test]
fn validator_cleanup_wire_format_is_pinned() {
    let record = record(1, 100);
    let bytes = encode_record(&record);
    assert_eq!(bytes[0], 1);
    assert_eq!(&bytes[1..33], &[1u8; 32]);
    assert_eq!(&bytes[33..37], &(-1i32).to_le_bytes());
    assert_eq!(&bytes[37..45], &0x8000_0000_0000_0000u64.to_le_bytes());
    assert_eq!(&bytes[45..49], &100u32.to_le_bytes());
    assert_eq!(&bytes[49..81], &[0x11; 32]);
    assert_eq!(&bytes[81..113], &[0x22; 32]);
    assert_eq!(
        std::str::from_utf8(&bytes[113..]).unwrap(),
        format!("consensus.-1.8000000000000000.7.{}", session(1).to_hex_string())
    );
    assert_eq!(
        record_key(&record.namespace),
        format!(
            "ValidatorConsensusCleanupV2.consensus.-1.8000000000000000.7.{}",
            session(1).to_hex_string()
        )
    );
}

#[test]
fn validator_cleanup_names_match_runtime_directories() {
    // The renderer is what both runtime_directory functions use; pin it.
    let shard = ShardIdent::with_tagged_prefix(0, 0x8000_0000_0000_0000).unwrap();
    let sid = session(5);
    assert_eq!(
        namespace_relative_name(&NamespaceLayout::V1, &shard, 3, &sid),
        format!("consensus.0.8000000000000000.3.{}", sid.to_hex_string())
    );
    assert_eq!(
        namespace_relative_name(&NamespaceLayout::V2Validator, &shard, 3, &sid),
        format!("v2/consensus.0.8000000000000000.3.{}.validator", sid.to_hex_string())
    );
    let adnl = UInt256::from([0xcd; 32]);
    assert_eq!(
        namespace_relative_name(&NamespaceLayout::V2Observer(adnl.clone()), &shard, 3, &sid),
        format!(
            "v2/consensus.0.8000000000000000.3.{}.observer.{}",
            sid.to_hex_string(),
            adnl.to_hex_string()
        )
    );
}

#[test]
fn validator_cleanup_non_canonical_names_are_rejected() {
    let sid = session(9);
    let good = format!("consensus.-1.8000000000000000.7.{}", sid.to_hex_string());
    let parsed = parse_canonical_namespace_name(&good, &sid).unwrap();
    assert_eq!(parsed.layout, NamespaceLayout::V1);
    assert_eq!(parsed.shard, masterchain());
    assert_eq!(parsed.catchain_seqno, 7);
    let hex = sid.to_hex_string();
    for bad in [
        format!("consensus.-1.8000000000000000.7.{hex}.validator"), // v2 suffix without v2/
        format!("v2/consensus.-1.8000000000000000.7.{hex}"),        // v2/ without a role
        format!("consensus.-1.8000000000000000.07.{hex}"),          // leading zero
        format!("consensus.+0.8000000000000000.7.{hex}"),           // plus sign
        format!("consensus.-1.8000000000000000.7.{}", session(8).to_hex_string()), // other session
        format!("consensus.-1.8000000000000000.7.{hex}x"),          // trailing byte
        format!("consensus.-1.800000000000000.7.{hex}"),            // short shard
        format!("consensus.-1.8000000000000000x.7.{hex}"),
        format!("consensus.-1.8000000000000000.4294967295.{hex}"), // catchain seqno no-wrap
        format!("consensus.-1.8000000000000000.7.{hex}\0"),
        format!("v2/consensus.-1.8000000000000000.7.{hex}.observer.zz"),
        format!("v2/consensus.-1.8000000000000000.7.{hex}.observer.{}", "AB".repeat(32)),
        format!("other.-1.8000000000000000.7.{hex}"),
        format!("../consensus.-1.8000000000000000.7.{hex}"),
    ] {
        assert!(parse_canonical_namespace_name(&bad, &sid).is_none(), "{bad:?}");
    }
    // Hex case matters: only the lowercase rendering is canonical.
    let lettered = session(0xab);
    let upper =
        format!("consensus.-1.8000000000000000.7.{}", lettered.to_hex_string().to_uppercase());
    assert!(parse_canonical_namespace_name(&upper, &lettered).is_none());
}

#[test]
fn validator_cleanup_checkpoint_must_be_full_masterchain() {
    let shard = ShardIdent::with_tagged_prefix(0, 0x8000_0000_0000_0000).unwrap();
    let zero_root =
        BlockIdExt::with_params(masterchain(), 5, UInt256::default(), UInt256::from([1; 32]));
    let shard_block =
        BlockIdExt::with_params(shard, 5, UInt256::from([1; 32]), UInt256::from([1; 32]));
    for bad in [zero_root, shard_block, BlockIdExt::default()] {
        assert!(!is_full_masterchain_checkpoint(&bad));
        assert!(make_record(&session(1), &NamespaceLayout::V1, &masterchain(), 7, &bad).is_err());
    }
}

#[test]
fn validator_cleanup_onchain_obsolete_requires_ancestor_and_cc_strictly_past() {
    let gc = checkpoint(500);
    let retirement = checkpoint(100);
    let with = |retired: BlockIdExt, cc: u32| {
        make_record(&session(9), &NamespaceLayout::V1, &masterchain(), cc, &retired).unwrap()
    };
    let r = with(retirement.clone(), 7);
    let ancestor_is = |expected: BlockIdExt| move |queried: &BlockIdExt| *queried == expected;
    let cc = |value: u32| move |shard: &ShardIdent| (*shard == masterchain()).then_some(value);
    assert!(session_is_onchain_obsolete(&r, &gc, &ancestor_is(retirement.clone()), &cc(10)));
    // A fork at the same seqno is not an ancestor.
    assert!(!session_is_onchain_obsolete(
        &with(fork_checkpoint(100), 7),
        &gc,
        &ancestor_is(retirement.clone()),
        &cc(10)
    ));
    // Strict r < g.
    assert!(session_is_onchain_obsolete(&r, &gc, &ancestor_is(retirement.clone()), &cc(8)));
    assert!(!session_is_onchain_obsolete(&r, &gc, &ancestor_is(retirement.clone()), &cc(7)));
    assert!(!session_is_onchain_obsolete(
        &with(retirement.clone(), 8),
        &gc,
        &ancestor_is(retirement.clone()),
        &cc(7)
    ));
    assert!(!session_is_onchain_obsolete(
        &with(retirement.clone(), 20),
        &gc,
        &ancestor_is(retirement.clone()),
        &cc(7)
    ));
    // Not an ancestor, unknown catchain seqno, invalid GC checkpoint.
    assert!(!session_is_onchain_obsolete(&r, &gc, &|_: &BlockIdExt| false, &cc(10)));
    assert!(!session_is_onchain_obsolete(
        &r,
        &gc,
        &ancestor_is(retirement.clone()),
        &|_: &ShardIdent| None
    ));
    assert!(!session_is_onchain_obsolete(
        &r,
        &BlockIdExt::default(),
        &ancestor_is(retirement.clone()),
        &cc(10)
    ));
    // A non-canonical namespace is never acted on.
    let mut renamed = r.clone();
    renamed.namespace.push_str(".observer.z");
    assert!(!session_is_onchain_obsolete(&renamed, &gc, &ancestor_is(retirement), &cc(10)));
    // Equality with the GC block needs no ancestry query.
    let calls = std::cell::Cell::new(0);
    let counting = |_: &BlockIdExt| {
        calls.set(calls.get() + 1);
        false
    };
    assert!(session_is_onchain_obsolete(&with(gc.clone(), 7), &gc, &counting, &cc(10)));
    assert_eq!(calls.get(), 0);
}

#[test]
fn validator_cleanup_eligible_requires_all_four_conditions() {
    let r = record(9, 100);
    let gc = checkpoint(500);
    let retirement = checkpoint(100);
    let ancestor = move |q: &BlockIdExt| *q == retirement;
    let cc = |shard: &ShardIdent| (*shard == masterchain()).then_some(10);
    let yes = |_: &UInt256| true;
    let no = |_: &UInt256| false;
    assert!(cleanup_eligible(&r, &gc, &ancestor, &cc, &no, &yes));
    assert!(!cleanup_eligible(&r, &gc, &ancestor, &cc, &yes, &yes), "live");
    assert!(!cleanup_eligible(&r, &gc, &ancestor, &cc, &no, &no), "not closed");
    assert!(!cleanup_eligible(&r, &gc, &ancestor, &|_: &ShardIdent| None, &no, &yes), "cc unknown");
    assert!(
        !cleanup_eligible(&r, &gc, &ancestor, &|_: &ShardIdent| Some(u32::MAX), &no, &yes),
        "the u32::MAX sentinel vetoes"
    );
    assert!(!cleanup_eligible(&r, &gc, &|_: &BlockIdExt| false, &cc, &no, &yes), "not ancestor");
}

#[test]
fn validator_cleanup_safe_checkpoint_is_monotonic() {
    let a = checkpoint(100);
    let b = checkpoint(200);
    let ancestry = |x: &BlockIdExt, y: &BlockIdExt| {
        if x.seq_no() < y.seq_no() && x.root_hash() == y.root_hash() {
            CleanupAncestry::Ancestor
        } else {
            CleanupAncestry::Unknown
        }
    };
    assert!(should_adopt_safe_checkpoint(None, &a, &ancestry));
    assert!(should_adopt_safe_checkpoint(Some(&a), &b, &ancestry));
    assert!(!should_adopt_safe_checkpoint(Some(&b), &a, &ancestry), "no regression");
    assert!(!should_adopt_safe_checkpoint(Some(&a), &a, &ancestry), "no self adoption");
    assert!(
        !should_adopt_safe_checkpoint(Some(&a), &fork_checkpoint(300), &ancestry),
        "unknown ancestry"
    );
    assert!(!should_adopt_safe_checkpoint(None, &BlockIdExt::default(), &ancestry));
}

/// Durable-store stand-in plus oracles: GC at MC500, every shard at cc 10.
struct Scan {
    manager: ValidatorCleanupManager,
    store: BTreeMap<String, PendingValidatorCleanup>,
    live: BTreeSet<UInt256>,
    vetoed: BTreeSet<UInt256>,
}
impl Scan {
    fn new() -> Self {
        Self {
            manager: ValidatorCleanupManager::default(),
            store: BTreeMap::new(),
            live: BTreeSet::new(),
            vetoed: BTreeSet::new(),
        }
    }
    fn put(&mut self, record: PendingValidatorCleanup) {
        self.store.insert(record_key(&record.namespace), record);
    }
    /// One full pass: page, gate, point reads. None when the tick is skipped.
    fn pass(&mut self) -> Option<Vec<ReservedDelete>> {
        let request = self.manager.begin_tick()?;
        let mut page = Page::default();
        for (key, record) in self.store.range::<String, _>((
            std::ops::Bound::Excluded(&request.after_key),
            std::ops::Bound::Unbounded,
        )) {
            if page.records.len() == request.max_keys {
                break;
            }
            page.records.push(record.clone());
            page.last_key = key.clone();
        }
        page.reached_end = page.records.len() < request.max_keys;
        let live = self.live.clone();
        let is_live = move |s: &UInt256| live.contains(s);
        let ancestor = |q: &BlockIdExt| q.seq_no() <= 500;
        let cc = |_: &ShardIdent| Some(10);
        let vetoed = self.vetoed.clone();
        let veto = move |r: &PendingValidatorCleanup| vetoed.contains(&r.session_id);
        let oracles = Oracles {
            gc: checkpoint(500),
            ancestor_or_equal_of_gc: &ancestor,
            gc_shard_catchain_seqno: &cc,
            is_live: &is_live,
            custody_veto: &veto,
        };
        let candidates = self.manager.on_page(&request, &page, &oracles);
        let mut reserved = Vec::new();
        for candidate in candidates {
            let current = Ok(self.store.get(&record_key(&candidate.namespace)).cloned());
            if let Some(r) =
                self.manager.on_point_read_result(request.token, &candidate, &current, &is_live)
            {
                reserved.push(r);
            }
        }
        assert!(self.manager.pass_verified());
        self.manager.end_pass();
        Some(reserved)
    }
    fn complete(&mut self, reserved: &ReservedDelete, gone: bool) {
        let namespace = &reserved.record.namespace;
        if self.manager.on_delete_completed(
            namespace,
            reserved.generation,
            reserved.attempt_id,
            gone,
        ) {
            self.store.remove(&record_key(namespace));
            self.manager.on_erase_acknowledged(namespace, reserved.generation, reserved.attempt_id);
        }
    }
}

#[test]
fn validator_cleanup_manager_enforces_driver_invariants() {
    let rec = record(1, 100);
    let sid = rec.session_id.clone();
    let ns = rec.namespace.clone();
    {
        let mut scan = Scan::new();
        scan.put(rec.clone());
        let reserved = scan.pass().unwrap();
        assert_eq!(reserved.len(), 1);
        assert!(scan.manager.is_delete_in_flight(&sid));
        let r = &reserved[0];
        assert!(scan.manager.on_delete_completed(&ns, r.generation, r.attempt_id, true));
        assert!(scan.manager.is_delete_in_flight(&sid), "held until the erase is acknowledged");
        scan.manager.on_erase_acknowledged(&ns, r.generation, r.attempt_id);
        assert!(!scan.manager.is_delete_in_flight(&sid));
    }
    {
        // Only the retired incarnation's close ack counts.
        let mut scan = Scan::new();
        scan.put(rec.clone());
        scan.manager.on_group_created(&sid);
        let generation = scan.manager.on_group_retired(&rec);
        scan.manager.on_close_confirmed(&ns, generation + 1);
        assert!(scan.pass().unwrap().is_empty());
        scan.manager.on_close_confirmed(&ns, generation);
        assert_eq!(scan.pass().unwrap().len(), 1);
    }
    {
        // Reopened after its retirement closed: live again, never reserved.
        let mut scan = Scan::new();
        scan.put(rec.clone());
        scan.manager.on_group_created(&sid);
        let generation = scan.manager.on_group_retired(&rec);
        scan.manager.on_close_confirmed(&ns, generation);
        scan.manager.on_group_created(&sid);
        assert!(scan.pass().unwrap().is_empty());
    }
    {
        let mut scan = Scan::new();
        scan.put(rec.clone());
        scan.live.insert(sid.clone());
        assert!(scan.pass().unwrap().is_empty(), "live per the owner's oracle");
    }
    {
        // Unconfirmed delete: no erase, released, retried later.
        let mut scan = Scan::new();
        scan.put(rec.clone());
        let reserved = scan.pass().unwrap();
        scan.complete(&reserved[0], false);
        assert!(!scan.manager.is_delete_in_flight(&sid));
        assert!(scan.store.contains_key(&record_key(&ns)));
        assert_eq!(scan.pass().unwrap().len(), 1);
    }
    {
        let mut scan = Scan::new();
        scan.put(rec.clone());
        assert_eq!(scan.pass().unwrap().len(), 1);
        assert!(scan.pass().unwrap().is_empty(), "in flight is not reserved again");
    }
    {
        // Completions and erase acks bind to the exact generation and attempt.
        let mut scan = Scan::new();
        scan.put(rec.clone());
        let r = scan.pass().unwrap().remove(0);
        assert!(!scan.manager.on_delete_completed(&ns, r.generation + 1, r.attempt_id, true));
        assert!(!scan.manager.on_delete_completed(&ns, r.generation, r.attempt_id + 1, true));
        assert!(scan.manager.on_delete_completed(&ns, r.generation, r.attempt_id, true));
        assert!(
            !scan.manager.on_delete_completed(&ns, r.generation, r.attempt_id, true),
            "duplicate"
        );
        scan.manager.on_erase_acknowledged(&ns, r.generation + 1, r.attempt_id);
        scan.manager.on_erase_acknowledged(&ns, r.generation, r.attempt_id + 1);
        assert!(scan.manager.is_delete_in_flight(&sid));
        scan.manager.on_erase_acknowledged(&ns, r.generation, r.attempt_id);
        assert!(!scan.manager.is_delete_in_flight(&sid));
    }
}

#[test]
fn validator_cleanup_manager_point_read_rejects_changed_or_failed_records() {
    let mut scan = Scan::new();
    let rec = record(1, 100);
    scan.put(rec.clone());
    let request = scan.manager.begin_tick().unwrap();
    let page = Page {
        records: vec![rec.clone()],
        last_key: record_key(&rec.namespace),
        reached_end: true,
    };
    let ancestor = |q: &BlockIdExt| q.seq_no() <= 500;
    let cc = |_: &ShardIdent| Some(10);
    let no = |_: &UInt256| false;
    let no_veto = |_: &PendingValidatorCleanup| false;
    let oracles = Oracles {
        gc: checkpoint(500),
        ancestor_or_equal_of_gc: &ancestor,
        gc_shard_catchain_seqno: &cc,
        is_live: &no,
        custody_veto: &no_veto,
    };
    let candidates = scan.manager.on_page(&request, &page, &oracles);
    assert_eq!(candidates.len(), 1);
    // A stale token, a superseded record and a read error never reserve.
    assert!(scan
        .manager
        .on_point_read_result(request.token + 1, &rec, &Ok(Some(rec.clone())), &no)
        .is_none());
    let mut superseded = rec.clone();
    superseded.retirement_checkpoint = checkpoint(101);
    assert!(scan
        .manager
        .on_point_read_result(request.token, &rec, &Ok(Some(superseded)), &no)
        .is_none());
    assert!(scan.manager.pass_verified());
    let summary = scan.manager.end_pass();
    assert_eq!(summary.reserved, 0);
    let request = scan.manager.begin_tick().unwrap();
    let candidates = scan.manager.on_page(&request, &page, &oracles);
    assert!(scan
        .manager
        .on_point_read_result(request.token, &candidates[0], &Err("io".into()), &no)
        .is_none());
    assert!(scan.manager.end_pass().point_failed);
    // A failed page read changes nothing and a stale abort is ignored.
    let request = scan.manager.begin_tick().unwrap();
    assert!(scan.manager.abort_pass(request.token + 1).is_none());
    assert!(scan.manager.abort_pass(request.token).unwrap().page_failed);
    assert!(!scan.manager.pass_running());
}

#[test]
fn validator_cleanup_manager_budget_stops_the_cursor() {
    let mut scan = Scan::new();
    for i in 0..40u8 {
        scan.put(record(i, 100));
    }
    let mut reserved = BTreeSet::new();
    let mut passes = 0;
    while reserved.len() < 40 && passes < 10 {
        let expected: Vec<String> =
            scan.store.keys().take(ValidatorCleanupManager::DISPATCH_BUDGET).cloned().collect();
        let batch = scan.pass().unwrap();
        assert_eq!(batch.len(), expected.len());
        for (r, key) in batch.iter().zip(&expected) {
            assert_eq!(&record_key(&r.record.namespace), key, "in key order, nothing skipped");
            assert!(reserved.insert(r.record.session_id.clone()), "never twice");
        }
        assert_eq!(scan.manager.cursor().is_empty(), reserved.len() == 40);
        for r in &batch {
            scan.complete(r, true);
        }
        passes += 1;
    }
    assert_eq!(passes, 3);
    assert!(scan.store.is_empty());
}

#[test]
fn validator_cleanup_manager_caps_in_flight() {
    let mut scan = Scan::new();
    for i in 0..100u8 {
        scan.put(record(i, 100));
    }
    let mut reserved = 0;
    for _ in 0..20 {
        if let Some(batch) = scan.pass() {
            reserved += batch.len();
        }
    }
    assert_eq!(reserved, ValidatorCleanupManager::MAX_IN_FLIGHT);
    assert_eq!(scan.manager.in_flight_count(), ValidatorCleanupManager::MAX_IN_FLIGHT);
    assert!(scan.manager.begin_tick().is_none(), "a tick at the cap is skipped");
}

#[test]
fn validator_cleanup_manager_ignores_re_retire_while_in_flight() {
    let mut scan = Scan::new();
    let rec = record(1, 100);
    scan.put(rec.clone());
    let r = scan.pass().unwrap().remove(0);
    assert_eq!(scan.manager.on_group_retired(&rec), r.generation);
    assert!(scan.manager.is_delete_in_flight(&rec.session_id));
    assert_eq!(scan.manager.open_retirement_count(), 0);
    scan.complete(&r, true);
    assert!(!scan.manager.is_delete_in_flight(&rec.session_id));
}

#[test]
fn validator_cleanup_manager_reclaims_generation_state() {
    let mut scan = Scan::new();
    for i in 0..200u8 {
        let rec = record(i, 100);
        scan.put(rec.clone());
        scan.manager.on_group_created(&rec.session_id);
        let generation = scan.manager.on_group_retired(&rec);
        scan.manager.on_close_confirmed(&rec.namespace, generation);
    }
    for _ in 0..40 {
        if scan.store.is_empty() {
            break;
        }
        for r in scan.pass().unwrap() {
            scan.complete(&r, true);
        }
    }
    assert!(scan.store.is_empty());
    assert_eq!(scan.manager.in_flight_count(), 0);
    assert_eq!(scan.manager.open_retirement_count(), 0);
    assert_eq!(scan.manager.live_session_count(), 0);
    let mut scan = Scan::new();
    let rec = record(1, 100);
    scan.put(rec.clone());
    scan.manager.on_group_created(&rec.session_id);
    let first = scan.manager.on_group_retired(&rec);
    scan.manager.on_group_created(&rec.session_id);
    let second = scan.manager.on_group_retired(&rec);
    assert!(second > first);
    scan.manager.on_close_confirmed(&rec.namespace, first);
    assert!(scan.pass().unwrap().is_empty(), "a stale ack cannot stand in");
    scan.manager.on_close_confirmed(&rec.namespace, second);
    assert_eq!(scan.pass().unwrap().len(), 1);
}

#[test]
fn validator_cleanup_records_retired_after_gc_are_kept() {
    let mut scan = Scan::new();
    scan.put(record(1, 100));
    scan.put(record(2, 900));
    let reserved = scan.pass().unwrap();
    assert_eq!(reserved.len(), 1);
    assert_eq!(reserved[0].record.session_id, session(1));
}

#[test]
fn validator_cleanup_gc_floor_codec_is_strict() {
    let id = checkpoint(500);
    let bytes = encode_checkpoint(&id);
    assert_eq!(decode_checkpoint(&bytes), Some(id));
    for length in 0..bytes.len() {
        assert!(decode_checkpoint(&bytes[..length]).is_none());
    }
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(decode_checkpoint(&longer).is_none());
    let shard = BlockIdExt::with_params(
        ShardIdent::with_tagged_prefix(0, 0x8000_0000_0000_0000).unwrap(),
        5,
        UInt256::from([1; 32]),
        UInt256::from([1; 32]),
    );
    assert!(decode_checkpoint(&encode_checkpoint(&shard)).is_none(), "masterchain only");
}

#[test]
fn validator_cleanup_gc_floor_advances_only_behind_every_frontier() {
    let ready = GcAdvanceInputs {
        last_rotation_seqno: 2000,
        min_ref_mc_seqno: 2000,
        last_applied_seqno: 3000,
        last_key_block_seqno: 2000,
        shard_client_seqno: 2000,
        pss_keeper_seqno: 2000,
        now: 10_000,
        state_ttl: 1_000,
    };
    assert!(may_advance_gc(1000, 8_000, &ready));
    let blocked: Vec<(&str, GcAdvanceInputs)> = vec![
        ("rotation", GcAdvanceInputs { last_rotation_seqno: 1000, ..ready.clone() }),
        ("min ref", GcAdvanceInputs { min_ref_mc_seqno: 1000, ..ready.clone() }),
        ("1024 behind head", GcAdvanceInputs { last_applied_seqno: 2024, ..ready.clone() }),
        ("key block", GcAdvanceInputs { last_key_block_seqno: 1000, ..ready.clone() }),
        ("shard client", GcAdvanceInputs { shard_client_seqno: 1000, ..ready.clone() }),
        ("pss keeper", GcAdvanceInputs { pss_keeper_seqno: 1000, ..ready.clone() }),
        ("no head", GcAdvanceInputs { last_applied_seqno: 0, ..ready.clone() }),
        ("ttl underflow", GcAdvanceInputs { state_ttl: 20_000, ..ready.clone() }),
    ];
    for (name, inputs) in blocked {
        assert!(!may_advance_gc(1000, 8_000, &inputs), "{name}");
    }
    assert!(!may_advance_gc(1000, 9_000, &ready), "state not older than the TTL");
    assert!(may_advance_gc(1000, 8_999, &ready));
    assert!(!may_advance_gc(u32::MAX, 0, &ready), "seqno + 1024 overflow refuses");
}

#[test]
fn validator_cleanup_manager_honours_the_custody_veto_and_lists_pending_erases() {
    let rec = record(1, 100);
    let sid = rec.session_id.clone();
    let ns = rec.namespace.clone();
    let mut scan = Scan::new();
    scan.put(rec.clone());
    scan.vetoed.insert(sid.clone());
    assert!(scan.pass().unwrap().is_empty(), "a vetoed record is never reserved");
    scan.vetoed.clear();
    let r = scan.pass().unwrap().remove(0);
    assert!(scan.manager.erasing_entries().is_empty(), "deleting is not erasing");
    assert!(scan.manager.on_delete_completed(&ns, r.generation, r.attempt_id, true));
    // A failed erase leaves the entry erasing and in flight for a retry.
    assert_eq!(
        scan.manager.erasing_entries(),
        vec![(ns.clone(), sid.clone(), r.generation, r.attempt_id)]
    );
    assert!(scan.manager.is_delete_in_flight(&sid));
    scan.manager.on_erase_acknowledged(&ns, r.generation, r.attempt_id);
    assert!(scan.manager.erasing_entries().is_empty());
    assert!(!scan.manager.is_delete_in_flight(&sid));
}

#[test]
fn validator_cleanup_namespaces_sharing_a_session_are_independent() {
    let sid = session(4);
    let make = |layout: NamespaceLayout| {
        make_record(&sid, &layout, &masterchain(), 7, &checkpoint(100)).unwrap()
    };
    let validator = make(NamespaceLayout::V2Validator);
    let observer_a = make(NamespaceLayout::V2Observer(UInt256::from([0xa1; 32])));
    let observer_b = make(NamespaceLayout::V2Observer(UInt256::from([0xb2; 32])));
    let mut scan = Scan::new();
    for record in [&validator, &observer_a, &observer_b] {
        scan.put(record.clone());
    }
    assert_eq!(scan.store.len(), 3, "one key per physical namespace");
    let reserved = scan.pass().unwrap();
    assert_eq!(reserved.len(), 3);
    let first = &reserved[0];
    scan.complete(first, true);
    assert!(!scan.manager.is_namespace_in_flight(&first.record.namespace));
    assert!(scan.manager.is_delete_in_flight(&sid), "the session's other deletes are in flight");
    assert!(scan.manager.session_has_other_holders(&sid, &reserved[1].record.namespace));
    for r in &reserved[1..] {
        scan.complete(r, true);
    }
    assert!(!scan.manager.is_delete_in_flight(&sid));
    assert!(scan.store.is_empty());
    // Session prefixes cover the V1 name and every authenticated namespace.
    let [v1, v2] = session_record_prefixes(&masterchain(), 7, &sid);
    assert!(record_key(&record(4, 100).namespace).starts_with(&v1));
    for record in [&validator, &observer_a, &observer_b] {
        assert!(record_key(&record.namespace).starts_with(&v2));
    }
}

#[test]
fn validator_cleanup_candidate_claims_are_session_serialized() {
    let sid = session(5);
    let mut manager = ValidatorCleanupManager::default();
    assert_eq!(parse_candidate_claim_key(&candidate_claim_key(&sid)), Some(sid.clone()));
    assert_eq!(parse_candidate_claim_key("ValidatorCandidateCleanupV1.zz"), None);
    let attempt = manager.begin_claim(&sid).unwrap();
    assert!(manager.begin_claim(&sid).is_none(), "one claim attempt per session");
    assert!(manager.is_delete_in_flight(&sid), "creation defers while a claim runs");
    manager.end_claim(&sid, attempt + 1);
    assert!(manager.is_delete_in_flight(&sid), "a stale end is ignored");
    manager.end_claim(&sid, attempt);
    assert!(!manager.is_delete_in_flight(&sid));
    // A live or retiring session never runs its claim.
    manager.on_group_created(&sid);
    assert!(manager.begin_claim(&sid).is_none());
    let rec = make_record(&sid, &NamespaceLayout::V1, &masterchain(), 7, &checkpoint(100)).unwrap();
    let generation = manager.on_group_retired(&rec);
    assert!(manager.begin_claim(&sid).is_none(), "a retirement awaiting its close holds it");
    manager.on_close_confirmed(&rec.namespace, generation);
    assert!(manager.begin_claim(&sid).is_some());
}

#[test]
fn validator_cleanup_cap_counts_claims_and_namespaces_together() {
    let mut scan = Scan::new();
    for i in 0..20u8 {
        scan.put(record(i, 100));
    }
    // Sixty claims leave room for exactly four namespace deletes.
    for i in 0..60u8 {
        let claimed = UInt256::from([200u8.wrapping_add(i); 32]);
        assert!(scan.manager.begin_claim(&claimed).is_some(), "claim {i}");
    }
    let claims = scan.manager.operation_count();
    assert_eq!(claims, 60);
    let reserved = scan.pass().unwrap();
    assert_eq!(reserved.len(), ValidatorCleanupManager::MAX_IN_FLIGHT - 60);
    assert_eq!(scan.manager.operation_count(), ValidatorCleanupManager::MAX_IN_FLIGHT);
    assert!(scan.manager.begin_tick().is_none(), "the combined cap skips the tick");
    assert!(scan.manager.begin_claim(&session(250)).is_none(), "and refuses another claim");
}
