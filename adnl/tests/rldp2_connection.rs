// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use adnl::rldp2::{budget::InboundBudget, connection::Connection};
use rtos_api::{
    ton::rldp2::{messagepart::Complete, MessagePart},
    IntoBoxed, WireProfile,
};
fn connection() -> Connection {
    Connection::with_budget([1; 32], InboundBudget::new(16384, 512 << 20))
}
#[test]
fn real_connections_deliver_data_and_finish_sender_from_duplicate_completes() {
    let mut a = connection();
    let mut b = connection();
    let data: Vec<_> = (0..3000).map(|i| (i % 251) as u8).collect();
    a.send_at([2; 32], data.clone(), 1.0, Some(5.0)).unwrap();
    let first = a.run_at(1.0).unwrap();
    assert_eq!(first.packets.len(), 9);
    for packet in first.packets {
        b.receive_raw_at(&packet, 1.0);
    }
    let received = b.run_at(1.001).unwrap();
    assert_eq!(received.received.len(), 1);
    assert_eq!(received.received[0].1.as_ref().unwrap(), &data);
    assert_eq!(received.packets.len(), 5);
    for packet in received.packets {
        a.receive_raw_at(&packet, 1.002);
    }
    let done = a.run_at(1.002).unwrap();
    assert_eq!(done.sent, vec![([2; 32], Ok(()))]);
    assert_eq!(a.outbound_transfer_count(), 0);
    assert_eq!(done.wakeup, None);
    assert!(a.run_at(5.0).unwrap().sent.is_empty());
}
#[test]
fn inbound_and_outbound_share_one_timer_heap_with_cpp_tie_order() {
    let mut c = connection();
    for i in 1..=6 {
        if i % 2 == 1 {
            assert!(c.set_receive_limits([i; 32], 5.0, 769));
        } else {
            assert!(c.send_at([i; 32], vec![i; 769], 1.0, Some(5.0)).unwrap());
        }
    }
    let events = c.run_at(5.0).unwrap();
    assert_eq!(events.received.iter().map(|(id, _)| id[0]).collect::<Vec<_>>(), vec![1, 3, 5]);
    assert_eq!(events.sent.iter().map(|(id, _)| id[0]).collect::<Vec<_>>(), vec![6, 4, 2]);
    assert!(events.sent.iter().all(|(_, r)| r.as_ref().is_err_and(|s| s == "timeout")));
    assert_eq!(c.outbound_transfer_count(), 0);
    assert_eq!(c.outstanding_requests(), 0);
}
#[test]
fn random_id_deadline_and_completion_use_actual_generated_id() {
    let mut c = connection();
    assert!(c.send_at([0; 32], vec![7], 1.0, Some(5.0)).unwrap());
    let sent = c.run_at(1.0).unwrap();
    let parsed: MessagePart =
        WireProfile::T0.deserialize_value_bounded(&sent.packets[0], sent.packets[0].len()).unwrap();
    let MessagePart::Rldp2_MessagePart(p) = parsed else { panic!() };
    let id = *p.0.transfer_id.as_array();
    assert_ne!(id, [0; 32]);
    c.receive_raw_at(
        &WireProfile::T0
            .serialize(&Complete { transfer_id: id.into(), part: 0 }.into_boxed())
            .unwrap(),
        1.1,
    );
    assert_eq!(c.run_at(1.1).unwrap().sent, vec![(id, Ok(()))]);
    assert!(c.run_at(5.0).unwrap().sent.is_empty());
}
#[test]
fn same_id_bidirectional_limit_ownership_is_independent() {
    let mut c = connection();
    let id = [2; 32];
    assert!(c.set_receive_limits(id, 5.0, 769));
    assert!(c.send_at(id, vec![7], 1.0, Some(4.0)).unwrap());
    let first = c.run_at(1.0).unwrap();
    assert_eq!(first.packets.len(), 6);
    c.receive_raw_at(
        &WireProfile::T0
            .serialize(&Complete { transfer_id: id.into(), part: 0 }.into_boxed())
            .unwrap(),
        1.1,
    );
    assert_eq!(c.run_at(1.1).unwrap().sent, vec![(id, Ok(()))]);
    assert_eq!(c.outstanding_requests(), 1);
    assert!(c.run_at(4.0).unwrap().received.is_empty());
    assert_eq!(c.run_at(5.0).unwrap().received.len(), 1);
}

#[test]
fn raw_confirm_packets_release_sender_window_and_complete_transfer() {
    let mut a = connection();
    let mut b = connection();
    let id = [2; 32];
    let data: Vec<_> = (0..23040).map(|i| (i % 251) as u8).collect();
    assert!(b.set_receive_limits(id, 5.0, data.len() as u64));
    a.send_at(id, data.clone(), 1.0, Some(5.0)).unwrap();
    let mut received = Vec::new();
    let mut done = Vec::new();
    let mut confirms = 0;
    for i in 0..100 {
        let now = 1.0 + i as f64 * 0.005;
        let outgoing = a.run_at(now).unwrap();
        done.extend(outgoing.sent);
        for packet in outgoing.packets {
            b.receive_raw_at(&packet, now);
        }
        let replies = b.run_at(now + 0.002).unwrap();
        received.extend(replies.received);
        for packet in replies.packets {
            let parsed: MessagePart =
                WireProfile::T0.deserialize_value_bounded(&packet, packet.len()).unwrap();
            if matches!(parsed, MessagePart::Rldp2_Confirm(_)) {
                confirms += 1;
            }
            a.receive_raw_at(&packet, now + 0.003);
        }
        if !received.is_empty() && !done.is_empty() {
            break;
        }
    }
    assert!(confirms > 0);
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].1.as_ref().unwrap(), &data);
    assert_eq!(done, vec![(id, Ok(()))]);
    assert_eq!(a.outbound_transfer_count(), 0);
    assert_eq!(b.outstanding_requests(), 0);
}
