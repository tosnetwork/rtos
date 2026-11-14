// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use adnl::rldp2::{
    budget::{decoder_reservation_bytes, solver_working_bytes, InboundBudget, Kind, Usage},
    FecHelper,
};

#[test]
fn fec_demand_crosses_received_threshold_in_five_symbol_steps() {
    for (count, received, target, left) in [
        (0, 0, 5, 5),
        (1, 5, 6, 1),
        (1, 6, 11, 5),
        (10, 14, 15, 1),
        (10, 15, 20, 5),
        (100, 1000, 1005, 5),
    ] {
        let h = FecHelper { symbols_count: count, received_symbols_count: received };
        assert_eq!(h.target(), Some(target));
        assert_eq!(h.remaining(), Some(left));
    }
    assert_eq!(FecHelper { symbols_count: 0, received_symbols_count: u32::MAX }.target(), None);
}

#[test]
fn costs_check_intermediates_even_when_the_final_factor_is_zero() {
    assert_eq!(decoder_reservation_bytes(2000000, 768, 2605), Some(6681216));
    assert_eq!(solver_working_bytes(768, 2605), Some(12134912));
    assert_eq!(decoder_reservation_bytes(0, u64::MAX, 0), None);
    assert_eq!(solver_working_bytes(u64::MAX, 0), None);
    assert_eq!(decoder_reservation_bytes(u64::MAX, 768, 1), None);
}

#[test]
fn unsolicited_peers_cannot_take_the_solicited_reserve_or_another_identity_share() {
    let budget = InboundBudget::new(16, 1000);
    let a = [1; 32];
    let b = [2; 32];
    let c = [3; 32];
    assert!(budget.reserve(Kind::Unsolicited, a, 1, 200, 51).is_none());
    assert_eq!(budget.usage(), Usage::default());
    assert_eq!(budget.identity_count(), 0);
    let ra = budget.reserve(Kind::Unsolicited, a, 1, 200, 50).unwrap();
    assert_eq!(budget.usage(), Usage { decoders: 1, bytes: 200 });
    assert!(budget.reserve(Kind::Unsolicited, a, 1, 1, 0).is_none());
    let rb = budget.reserve(Kind::Unsolicited, b, 1, 200, 0).unwrap();
    assert!(budget.reserve(Kind::Unsolicited, c, 1, 101, 0).is_none());
    let solicited = budget.reserve(Kind::Solicited, c, 10, 300, 100).unwrap();
    assert_eq!(budget.usage(), Usage { decoders: 12, bytes: 700 });
    assert_eq!(budget.unsolicited_usage(), Usage { decoders: 2, bytes: 400 });
    drop((ra, rb, solicited));
    assert_eq!(budget.usage(), Usage::default());
    assert_eq!(budget.identity_count(), 0);
}

#[test]
fn shrinking_decoder_to_output_releases_slots_and_drop_releases_bytes() {
    let budget = InboundBudget::new(16, 1000);
    let peer = [7; 32];
    let mut charge = budget.reserve(Kind::Unsolicited, peer, 1, 200, 50).unwrap();
    charge.shrink_to(0, 20);
    assert_eq!(budget.identity_usage(&peer), Usage { decoders: 0, bytes: 20 });
    assert_eq!(budget.identity_count(), 1);
    charge.shrink_to(10, 1000);
    assert_eq!(charge.held(), Usage { decoders: 0, bytes: 20 });
    drop(charge);
    assert_eq!(budget.usage(), Usage::default());
    assert_eq!(budget.identity_count(), 0);
}

#[test]
fn overflowing_reservations_leave_the_existing_charge_unchanged() {
    let budget = InboundBudget::new(16, u64::MAX);
    let peer = [0; 32];
    assert!(budget.reserve(Kind::Solicited, peer, 0, 1, u64::MAX).is_none());
    assert_eq!(budget.usage(), Usage::default());
    let charge = budget.reserve(Kind::Solicited, peer, 1, u64::MAX, 0).unwrap();
    assert!(budget.reserve(Kind::Solicited, peer, 0, 1, 0).is_none());
    assert_eq!(budget.usage(), Usage { decoders: 1, bytes: u64::MAX });
    drop(charge);
    assert_eq!(budget.usage(), Usage::default());
}
