/*
 * RTOS project additions (2026-10-19): Plumtree certified sources.
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Plumtree publication from a certified source, and the common signature
//! rejection of a peer relaying a bad carrier.

use super::*;
use crate::overlay::privacy::{CERTIFICATE_FLAG_ALLOW_FEC, CERTIFICATE_FLAG_TRUSTED};
use rtos_block::{Ed25519KeyOption, ZeroizingBytes};

fn key(seed: u8) -> Arc<dyn KeyOption> {
    Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[seed; 32]).unwrap()
}

const OVERLAY: [u8; 32] = [9; 32];
const NOW: f64 = 1_700_000_000.0;

fn public_policy(issuer: &Arc<dyn KeyOption>) -> PlumtreeConfig {
    PlumtreeConfig {
        authorized_keys: BTreeMap::from([(*issuer.id().data(), MAX_PLUMTREE_PAYLOAD)]),
        max_untrusted_size: MAX_PLUMTREE_PAYLOAD,
        untrusted_flags: CERTIFICATE_FLAG_ALLOW_FEC,
        fixed_members: false,
        original_sender: false,
        eager_limit: 4,
        max_retained_bytes: MAX_PLUMTREE_PAYLOAD * 8,
        max_broadcasts: 16,
    }
}

fn certificate(issuer: &Arc<dyn KeyOption>, source: &Arc<dyn KeyOption>) -> Certificate {
    OverlayCertificate::sign(
        issuer,
        &OVERLAY,
        source.id().data(),
        NOW as i32 + 3600,
        MAX_PLUMTREE_PAYLOAD as u32,
        CERTIFICATE_FLAG_TRUSTED | CERTIFICATE_FLAG_ALLOW_FEC,
    )
    .unwrap()
    .to_tl()
}

fn publish(
    engine: &mut Engine,
    source: &Arc<dyn KeyOption>,
    cert: Certificate,
    id: [u8; 32],
    data: &[u8],
) -> Result<Vec<Action>> {
    engine.publish(source, cert, 1, Some(id), data, &[], NOW, Instant::now())
}

#[test]
fn ephemeral_source_publishes_only_with_an_allowing_certificate() {
    let issuer = key(31);
    let source = key(32);
    let mut sender = Engine::new(public_policy(&issuer), OVERLAY).unwrap();
    // Unauthorized any-sender source without a certificate: not Allowed.
    assert!(publish(&mut sender, &source, Certificate::Overlay_EmptyCertificate, [1; 32], b"x")
        .is_err());
    // A certificate without Trusted gives NeedCheck, which Plumtree refuses.
    let untrusted = OverlayCertificate::sign(
        &issuer,
        &OVERLAY,
        source.id().data(),
        NOW as i32 + 3600,
        MAX_PLUMTREE_PAYLOAD as u32,
        CERTIFICATE_FLAG_ALLOW_FEC,
    )
    .unwrap()
    .to_tl();
    assert!(publish(&mut sender, &source, untrusted, [2; 32], b"x").is_err());
    publish(&mut sender, &source, certificate(&issuer, &source), [3; 32], b"certified").unwrap();
    let wire = sender.states[&[3; 32]].parts[&0].wire.clone();
    let mut receiver = Engine::new(public_policy(&issuer), OVERLAY).unwrap();
    receiver.promote(0, [4; 32], Instant::now(), true);
    let actions = receiver.receive([4; 32], wire, None, &[], NOW, Instant::now()).unwrap();
    assert_eq!(actions.iter().filter(|a| matches!(a, Action::Deliver { .. })).count(), 1);
}

#[test]
fn relayed_bad_signature_bans_the_relaying_peer() {
    let issuer = key(33);
    let source = key(34);
    let mut sender = Engine::new(public_policy(&issuer), OVERLAY).unwrap();
    publish(&mut sender, &source, certificate(&issuer, &source), [5; 32], b"first").unwrap();
    publish(&mut sender, &source, certificate(&issuer, &source), [6; 32], b"second").unwrap();
    let mut bad = sender.states[&[5; 32]].parts[&0].wire.clone();
    if let Broadcast::Overlay_BroadcastPlumtreeSimple(carrier) = &mut bad {
        carrier.signature[0] ^= 1;
    }
    let good = sender.states[&[6; 32]].parts[&0].wire.clone();
    let mut receiver = Engine::new(public_policy(&issuer), OVERLAY).unwrap();
    let (liar, honest) = ([7; 32], [8; 32]);
    for peer in [liar, honest] {
        receiver.promote(0, peer, Instant::now(), true);
    }
    assert!(receiver.receive(liar, bad, None, &[], NOW, Instant::now()).is_err());
    assert!(receiver.verifier.is_peer_banned(&KeyId::from_data(liar)));
    // While banned even a valid carrier from that peer is refused.
    assert!(receiver.receive(liar, good.clone(), None, &[], NOW, Instant::now()).is_err());
    let actions = receiver.receive(honest, good, None, &[], NOW, Instant::now()).unwrap();
    assert_eq!(actions.iter().filter(|a| matches!(a, Action::Deliver { .. })).count(), 1);
    assert!(!receiver.verifier.is_peer_banned(&KeyId::from_data(honest)));
}
