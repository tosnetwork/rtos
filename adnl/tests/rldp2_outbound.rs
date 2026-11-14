use adnl::{
    fec::PeerFecType,
    rldp2::outbound::{OutboundConnection, MAX_OUTBOUND_TRANSFERS},
};
use rtos_api::{ton::rldp2::MessagePart, WireProfile};

fn packet(bytes: &[u8]) -> rtos_api::RldpChunk {
    match WireProfile::T0.deserialize_value_bounded::<MessagePart>(bytes, bytes.len()).unwrap() {
        MessagePart::Rldp2_MessagePart(value) => value.0,
        _ => panic!("sender emitted non-part"),
    }
}

#[test]
fn first_burst_emits_real_source_and_repair_symbols() {
    let mut outbound = OutboundConnection::new();
    let data: Vec<_> = (0..1601).map(|i| (i * 17) as u8).collect();
    assert!(outbound.send([1; 32], data.clone(), 1.0, None).unwrap());
    let events = outbound.run(1.0).unwrap();
    assert_eq!(events.packets.len(), 8); // K=3, FecHelper next target8.
    let mut decoder = None;
    for (i, bytes) in events.packets.iter().enumerate() {
        let part = packet(bytes);
        assert_eq!((part.part, part.seqno, part.total_size), (0, i as i32, 1601));
        assert_eq!(part.transfer_id.as_array(), &[1; 32]);
        let decoder = decoder.get_or_insert_with(|| {
            PeerFecType::from_tl(&part.fec_type).unwrap().create_decoder().unwrap()
        });
        if i >= 3 {
            decoder.add_symbol(part.seqno as u32, part.data).unwrap();
        }
    }
    assert_eq!(decoder.unwrap().try_decode().unwrap(), data);
    assert!(outbound.run(1.05).unwrap().packets.is_empty());
    assert_eq!(outbound.in_flight_count(), 8);
}

#[test]
fn congestion_window_and_probe_use_fixed_clock() {
    let mut outbound = OutboundConnection::new();
    outbound.send([2; 32], vec![4; 768 * 30], 1.0, None).unwrap();
    let first = outbound.run(1.0).unwrap();
    assert_eq!(first.packets.len(), 16); // strict > window15.
    assert_eq!(first.wakeup, Some(1.1));
    assert!(outbound.run(1.05).unwrap().packets.is_empty());
    let probe = outbound.run(1.1).unwrap();
    assert_eq!(probe.packets.len(), 1);
    assert_eq!(packet(&probe.packets[0]).seqno, 16);
    assert_eq!(outbound.in_flight_count(), 17);
}

#[test]
fn confirms_clamp_peer_counters_then_release_window() {
    let mut outbound = OutboundConnection::new();
    outbound.send([3; 32], vec![1], 1.0, None).unwrap();
    assert_eq!(outbound.run(1.0).unwrap().packets.len(), 6);
    outbound.on_confirm([3; 32], 0, u32::MAX, u32::MAX, u32::MAX, 1.05).unwrap();
    assert_eq!(outbound.in_flight_count(), 0);
    assert!(!outbound.run(1.05).unwrap().packets.is_empty());
    outbound.on_complete([3; 32], -1);
    assert_eq!(outbound.transfer_count(), 1);
    outbound.on_complete([3; 32], 0);
    assert_eq!(outbound.transfer_count(), 0);
    assert_eq!(outbound.in_flight_count(), 0);
    let events = outbound.run(1.06).unwrap();
    assert_eq!(events.completed, vec![([3; 32], Ok(()))]);
}

#[test]
fn multipart_opens_later_part_as_probe_and_completes_independently() {
    let mut outbound = OutboundConnection::new();
    outbound.send([4; 32], vec![3; 2_000_001], 1.0, None).unwrap();
    let first = outbound.run(1.0).unwrap();
    let parts: Vec<_> = first.packets.iter().map(|p| packet(p)).collect();
    assert_eq!(parts.len(), 17);
    assert_eq!(parts.last().unwrap().part, 1);
    assert_eq!(parts.last().unwrap().seqno, 0);
    assert_eq!(*parts.last().unwrap().fec_type.data_size(), 1);
    outbound.on_complete([4; 32], 0);
    assert_eq!(outbound.in_flight_count(), 1);
    assert_eq!(outbound.transfer_count(), 1);
    outbound.on_complete([4; 32], 1);
    assert_eq!(outbound.transfer_count(), 0);
    assert_eq!(outbound.in_flight_count(), 0);
    assert_eq!(outbound.run(1.0).unwrap().completed, vec![([4; 32], Ok(()))]);
}

#[test]
fn transfer_queue_is_fair_and_duplicates_do_not_replace_data() {
    let mut outbound = OutboundConnection::new();
    outbound.send([2; 32], vec![2; 768 * 30], 1.0, None).unwrap();
    outbound.send([1; 32], vec![1; 768 * 30], 1.0, None).unwrap();
    assert!(!outbound.send([1; 32], vec![9], 1.0, None).unwrap());
    let events = outbound.run(1.0).unwrap();
    let ids: Vec<_> = events.packets.iter().map(|p| *packet(p).transfer_id.as_array()).collect();
    assert_eq!(ids.len(), 16);
    for (i, id) in ids.iter().enumerate() {
        assert_eq!(*id, [if i % 2 == 0 { 1 } else { 2 }; 32]);
    }
    assert_eq!(outbound.started_count(), 2);
}

#[test]
fn cap_refusal_and_timeout_leave_no_inflight_or_completion_leak() {
    let mut outbound = OutboundConnection::new();
    for i in 0..MAX_OUTBOUND_TRANSFERS {
        let mut id = [0; 32];
        id[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
        assert!(outbound.send(id, vec![1], 1.0, Some(1.5)).unwrap());
    }
    assert!(!outbound.send([255; 32], vec![1], 1.0, None).unwrap());
    assert_eq!(outbound.transfer_count(), 256);
    let expired = outbound.run(2.0).unwrap();
    assert!(!expired.packets.is_empty()); // expiry follows send, matching CPP.
    assert_eq!(expired.completed.len(), 256);
    assert!(expired.completed.iter().all(|(_, r)| r.as_ref().is_err_and(|s| s == "timeout")));
    assert_eq!(outbound.transfer_count(), 0);
    assert_eq!(outbound.in_flight_count(), 0);
    assert!(outbound.run(2.0).unwrap().completed.is_empty());
}
