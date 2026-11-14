// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use adnl::{
    packet::Refusal,
    routing::{route_datagram, Destination},
};

#[test]
fn local_identity_precedes_channel_without_touching_ciphertext() {
    // A collision must never invoke the channel lookup or decryption, even for
    // a datagram with no payload. This is registry routing, not authentication.
    let destination = route_datagram(
        &[7; 32],
        |id| (*id == [7; 32]).then_some("local"),
        |_| -> Option<()> { panic!("channel shadowed a local identity") },
    )
    .unwrap();
    assert!(matches!(destination, Destination::Local("local")));
}

#[test]
fn inbound_channel_is_resolved_by_its_registered_id() {
    let registrations = std::collections::HashMap::from([([3; 32], 17)]);
    let destination = route_datagram(&[3; 32], |_| None::<()>, |id| registrations.get(id)).unwrap();
    assert!(matches!(destination, Destination::Channel(&17)));
    for datagram in [&[4; 32][..], &[4; 31][..]] {
        let error =
            route_datagram(datagram, |_| None::<()>, |id| registrations.get(id)).err().unwrap();
        assert_eq!(
            error.downcast_ref::<Refusal>().unwrap().0,
            if datagram.len() < 32 { "datagram_short" } else { "unknown_destination" }
        );
    }
}
