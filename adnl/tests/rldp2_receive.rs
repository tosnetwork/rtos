// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use adnl::{
    fec::{Algorithm, Encoder},
    rldp2::{
        budget::{self, InboundBudget, Usage},
        connection::Connection,
    },
};
use rtos_api::{
    ton::{
        fec::{type_::RaptorQ, Type},
        rldp2::{
            messagepart::{Complete, MessagePart as Part},
            MessagePart,
        },
    },
    IntoBoxed, RldpChunk, WireProfile,
};
fn packet(id: [u8; 32], total: i64, index: i32, seqno: i32, symbol: Vec<u8>) -> Vec<u8> {
    let size = if total > 2_000_000 {
        if index == 0 {
            2_000_000
        } else {
            (total - 2_000_000) as i32
        }
    } else {
        total as i32
    };
    frame(RldpChunk {
        transfer_id: id.into(),
        fec_type: Type::Fec_RaptorQ(RaptorQ {
            data_size: size,
            symbol_size: 768,
            symbols_count: (size + 767) / 768,
        }),
        part: index,
        total_size: total,
        seqno,
        data: symbol,
    })
}
fn frame(chunk: RldpChunk) -> Vec<u8> {
    WireProfile::T0.serialize(&Part(chunk).into_boxed()).unwrap()
}
fn decode(bytes: &[u8]) -> MessagePart {
    WireProfile::T0.deserialize_value_bounded(bytes, bytes.len()).unwrap()
}
fn source(id: [u8; 32], size: usize, seq: i32) -> Vec<u8> {
    packet(id, size as i64, 0, seq, vec![7; 768])
}
#[test]
fn budget_is_held_before_decode_and_released_on_finish_error_and_drop() {
    let b = InboundBudget::new(16, 8 << 20);
    let mut c = Connection::with_budget([1; 32], b.clone());
    c.receive_raw_at(&source([2; 32], 769, 0), 1.0);
    assert_eq!(
        b.usage(),
        Usage { decoders: 1, bytes: budget::decoder_reservation_bytes(769, 768, 2).unwrap() }
    );
    c.receive_raw_at(&source([2; 32], 769, 1), 1.1);
    let e = c.run_at(1.1);
    assert_eq!(e.received.len(), 1);
    assert_eq!(e.received[0].1.as_ref().unwrap(), &vec![7; 769]);
    assert_eq!(b.usage(), Usage::default());
    c.receive_raw_at(&packet([3; 32], 769, 0, 0, vec![0; 767]), 2.0);
    assert_eq!(c.run_at(2.0).received[0].1.as_ref().unwrap_err().0, "symbol_length");
    assert_eq!(b.usage(), Usage::default());
    c.receive_raw_at(&source([4; 32], 769, 0), 3.0);
    assert_eq!(b.usage().decoders, 1);
    drop(c);
    assert_eq!(b.usage(), Usage::default());
}
#[test]
fn local_request_replaces_unsolicited_owner_and_is_the_only_reserve_authority() {
    let b = InboundBudget::new(16, 8 << 20);
    let mut c = Connection::with_budget([1; 32], b.clone());
    c.receive_raw_at(&source([2; 32], 769, 0), 1.0);
    assert_eq!(b.unsolicited_usage().decoders, 1);
    assert!(c.set_receive_limits([2; 32], 100.0, 769));
    assert_eq!(b.usage(), Usage::default());
    assert!(!c.set_receive_limits([2; 32], 100.0, 769));
    assert_eq!(c.outstanding_requests(), 1);
    c.receive_raw_at(&source([2; 32], 769, 1), 2.0);
    assert_eq!(b.usage().decoders, 1);
    assert_eq!(b.unsolicited_usage(), Usage::default());
    c.receive_raw_at(&source([2; 32], 769, 0), 2.1);
    assert_eq!(c.run_at(2.1).received.len(), 1);
    assert_eq!(c.outstanding_requests(), 0);
    let tight = InboundBudget::new(15, 8 << 20);
    let mut c = Connection::with_budget([1; 32], tight.clone());
    c.receive_raw_at(&source([2; 32], 769, 0), 1.0);
    assert_eq!(c.inbound_transfer_count(), 0);
    assert_eq!(tight.usage(), Usage::default());
    assert!(c.set_receive_limits([2; 32], 100.0, 769));
    c.receive_raw_at(&source([2; 32], 769, 0), 1.0);
    assert_eq!(tight.usage().decoders, 1);
}
#[test]
fn ack_history_suppresses_duplicates_and_old_symbols_and_repeats_on_timer() {
    let b = InboundBudget::new(16, 8 << 20);
    let mut c = Connection::with_budget([1; 32], b.clone());
    c.receive_raw_at(&source([2; 32], 769, 32), 1.0);
    c.receive_raw_at(&source([2; 32], 769, 0), 1.0); // outside32 history, cannot complete source data
    let e = c.run_at(1.002);
    assert!(e.received.is_empty());
    assert_eq!(e.packets.len(), 1);
    let MessagePart::Rldp2_Confirm(ack) = decode(&e.packets[0]) else { panic!() };
    assert_eq!((ack.max_seqno, ack.received_mask, ack.received_count), (33, 1, 1));
    assert!(c.run_at(1.003).packets.is_empty());
    assert_eq!(c.run_at(1.005).packets.len(), 1);
    c.receive_raw_at(&source([2; 32], 769, 32), 1.006);
    let e = c.run_at(1.010);
    assert_eq!(e.packets.len(), 1); // duplicate does not restart ack cadence
    let MessagePart::Rldp2_Confirm(ack) = decode(&e.packets[0]) else { panic!() };
    assert_eq!(ack.received_count, 1);
    assert_eq!(b.usage().decoders, 1);
}
#[test]
fn completion_cache_precedes_field_validation_and_has_a_hard_cap() {
    let mut c = Connection::with_budget([1; 32], InboundBudget::new(16384, 512 << 20));
    for i in 0u32..2049 {
        let mut id = [0; 32];
        id[..4].copy_from_slice(&i.to_le_bytes());
        c.receive_raw_at(&source(id, 1, 0), 1.0);
        c.run_at(1.0);
    }
    assert_eq!(c.completed_transfer_count(), 2048);
    let mut id = [0; 32];
    id[..4].copy_from_slice(&2048u32.to_le_bytes());
    let mut bad = match decode(&source(id, 1, 0)) {
        MessagePart::Rldp2_MessagePart(p) => p.0,
        _ => panic!(),
    };
    bad.part = -10;
    bad.total_size = -1;
    bad.seqno = -1;
    bad.data.clear();
    c.receive_raw_at(&frame(bad), 1.1);
    let e = c.run_at(1.1);
    assert_eq!(
        e.packets,
        vec![WireProfile::T0
            .serialize(&Complete { transfer_id: id.into(), part: -10 }.into_boxed())
            .unwrap()]
    );
    c.receive_raw_at(&source([0; 32], 1, 0), 1.1);
    assert_eq!(c.run_at(1.1).received.len(), 1); // oldest evicted, reassembles
}
#[test]
fn timeout_releases_request_decoder_and_remembers_id_without_idle_cache_gc() {
    let b = InboundBudget::new(16, 8 << 20);
    let mut c = Connection::with_budget([1; 32], b.clone());
    assert!(c.set_receive_limits([2; 32], 2.0, 769));
    c.receive_raw_at(&source([2; 32], 769, 0), 1.0);
    assert!(c.run_at(1.999).received.is_empty());
    assert_eq!(b.usage().decoders, 1);
    let e = c.run_at(2.0);
    assert_eq!(e.received[0].1.as_ref().unwrap_err().0, "unclassified");
    assert_eq!(b.usage(), Usage::default());
    assert_eq!(c.outstanding_requests(), 0);
    c.run_at(100.0);
    assert_eq!(c.completed_transfer_count(), 1); // CPP expires cache only on completion and keeps128
}
#[test]
fn bounded_requests_and_decoders_do_not_allocate_claimed_total() {
    let b = InboundBudget::new(16384, 512 << 20);
    let mut c = Connection::with_budget([1; 32], b.clone());
    for i in 0u32..256 {
        let mut id = [0; 32];
        id[..4].copy_from_slice(&i.to_le_bytes());
        assert!(c.set_receive_limits(id, 100.0, u64::MAX));
    }
    assert!(!c.set_receive_limits([255; 32], 100.0, u64::MAX));
    assert_eq!(c.outstanding_requests(), 256);
    // Huge claimed transfer only opens its first bounded2MB decoder.
    c.set_default_mtu(u64::MAX);
    c.receive_raw_at(&packet([254; 32], i64::MAX, 0, 0, vec![7; 768]), 1.0);
    assert_eq!(c.inbound_transfer_count(), 1);
    assert!(b.usage().bytes < 10 << 20);
    drop(c);
    assert_eq!(b.usage(), Usage::default());
}
#[test]
fn repair_only_transfer_decodes_in_real_connection_without_a_regenerator() {
    let data: Vec<u8> = (0..3000).map(|i| (i % 251) as u8).collect();
    let mut enc = Encoder::new(Algorithm::RaptorQ, data.clone(), 768).unwrap();
    let mut c = Connection::with_budget([1; 32], InboundBudget::new(16, 8 << 20));
    let mut received = Vec::new();
    for id in 4..14 {
        let (_, symbol) = enc.symbol(id).unwrap();
        c.receive_raw_at(&packet([2; 32], 3000, 0, id as i32, symbol), 1.0);
        received.extend(c.run_at(1.0).received);
        if !received.is_empty() {
            break;
        }
    }
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].1.as_ref().unwrap(), &data);
}

#[test]
fn identity_share_applies_across_connections_and_recovers_after_owner_drop() {
    let b = InboundBudget::new(16, 8 << 20);
    let mut a = Connection::with_budget([1; 32], b.clone());
    let mut same = Connection::with_budget([1; 32], b.clone());
    let mut other = Connection::with_budget([2; 32], b.clone());
    a.receive_raw_at(&source([3; 32], 769, 0), 1.0);
    same.receive_raw_at(&source([4; 32], 769, 0), 1.0);
    assert_eq!(same.inbound_transfer_count(), 0);
    other.receive_raw_at(&source([4; 32], 769, 0), 1.0);
    assert_eq!(b.usage().decoders, 2);
    assert_eq!(b.identity_count(), 2);
    drop(a);
    same.receive_raw_at(&source([4; 32], 769, 0), 1.1);
    assert_eq!(same.inbound_transfer_count(), 1);
    assert_eq!(b.usage().decoders, 2);
    drop(other);
    drop(same);
    assert_eq!(b.usage(), Usage::default());
    assert_eq!(b.identity_count(), 0);
}

#[test]
fn active_transfer_cap_refuses_new_owner_and_timeout_recovers_all_credit() {
    let b = InboundBudget::new(16384, 512 << 20);
    let mut c = Connection::with_budget([1; 32], b.clone());
    for i in 0u32..256 {
        let mut id = [0; 32];
        id[..4].copy_from_slice(&i.to_le_bytes());
        assert!(c.set_receive_limits(id, 10.0, 769));
        c.receive_raw_at(&source(id, 769, 0), 1.0);
    }
    assert_eq!(c.inbound_transfer_count(), 256);
    assert_eq!(b.usage().decoders, 256);
    c.receive_raw_at(&source([255; 32], 769, 0), 1.0);
    assert_eq!(c.inbound_transfer_count(), 256);
    assert_eq!(b.usage().decoders, 256);
    let e = c.run_at(10.0);
    assert_eq!(e.received.len(), 256);
    assert_eq!(c.inbound_transfer_count(), 0);
    assert_eq!(c.outstanding_requests(), 0);
    assert_eq!(b.usage(), Usage::default());
    c.receive_raw_at(&source([255; 32], 769, 0), 10.1);
    assert_eq!(c.inbound_transfer_count(), 1);
}

#[test]
fn equal_request_deadlines_follow_cpp_four_ary_heap_order() {
    let mut c = Connection::with_budget([1; 32], InboundBudget::new(16, 8 << 20));
    for i in 1..=6 {
        assert!(c.set_receive_limits([i; 32], 5.0, 769));
    }
    assert!(c.run_at(4.999).received.is_empty());
    let events = c.run_at(5.0);
    let order: Vec<_> = events.received.iter().map(|(id, _)| id[0]).collect();
    // Independently queried from unchanged td::KHeap<double,4>.
    assert_eq!(order, vec![6, 1, 4, 3, 2, 5]);
    assert_eq!(c.outstanding_requests(), 0);
    assert!(c.run_at(6.0).received.is_empty());
}
