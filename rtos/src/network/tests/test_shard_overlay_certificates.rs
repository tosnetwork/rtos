// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use rtos_block::ZeroizingBytes;

fn key(seed: u8) -> Arc<dyn KeyOption> {
    Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[seed; 32]).unwrap()
}

const NOW: i32 = 1_700_000_000;

fn overlay_id(seed: u8) -> Arc<OverlayShortId> {
    KeyId::from_data([seed; 32])
}

fn shard() -> ShardIdent {
    ShardIdent::masterchain()
}

fn roots(keys: &[&Arc<dyn KeyOption>]) -> Vec<Arc<KeyId>> {
    keys.iter().map(|key| key.id().clone()).collect()
}

fn issued(
    issuer: &Arc<dyn KeyOption>,
    overlay: &Arc<OverlayShortId>,
    subject: &Arc<KeyId>,
    expire_at: i32,
    max_size: u32,
) -> CertificateTl {
    OverlayCertificate::sign(
        issuer,
        overlay.data(),
        subject.data(),
        expire_at,
        max_size,
        CERTIFICATE_FLAG_TRUSTED | CERTIFICATE_FLAG_ALLOW_FEC,
    )
    .unwrap()
    .to_tl()
}

#[test]
fn signer_is_the_first_canonical_root_held_locally() {
    let (a, b, c) = (key(1), key(2), key(3));
    let mut ids = roots(&[&a, &b, &c]);
    ids.sort_by(|l, r| r.data().cmp(l.data()));
    let local: HashSet<_> = [b.id().clone(), c.id().clone()].into_iter().collect();
    let mut held = vec![b.id().clone(), c.id().clone()];
    held.sort_by(|l, r| l.data().cmp(r.data()));
    assert_eq!(select_signer(&ids, &local), Some(held[0].clone()));
    assert_eq!(select_signer(&ids, &HashSet::new()), None);
    assert_eq!(select_signer(&[], &local), None);
}

#[test]
fn rules_follow_the_reference_shapes() {
    let startup = startup_rules();
    assert_eq!(startup.max_unauthorized_size(), MAX_FEC_BROADCAST_SIZE);
    assert_eq!(startup.flags(), 0);
    assert!(startup.authorized_keys().is_empty());
    let a = key(1);
    let rules = authority_rules(&roots(&[&a]));
    assert_eq!(rules.flags(), CERTIFICATE_FLAG_ALLOW_FEC);
    assert_eq!(rules.authorized_keys().get(a.id().data()), Some(&MAX_FEC_BROADCAST_SIZE));
    assert!(authority_rules(&[]).authorized_keys().is_empty());
}

#[test]
fn ephemeral_identity_and_certificate_survive_overlay_recreation() {
    let sources = ShardOverlayCertificates::new();
    let adnl = key(9);
    let signer = key(1);
    let first = sources.register_overlay(&shard(), &overlay_id(5), adnl.id(), NOW).unwrap();
    let local = sources.local_key(&shard()).unwrap();
    assert_eq!(first.rules, Some(startup_rules()));
    assert_eq!(first.certificates, vec![(local.id().clone(), None), (adnl.id().clone(), None)]);
    sources.update_authority(&roots(&[&signer]), Some(signer.clone()), NOW).unwrap();
    let cert = sources.local_certificate(&shard()).unwrap();
    assert_eq!(cert.issuer_hash(), signer.id().data());
    assert_eq!(cert.expire_at(), NOW + SELF_CERTIFICATE_LIFETIME_SEC);
    assert_eq!(cert.max_size(), MAX_FEC_BROADCAST_SIZE);
    assert_eq!(cert.flags(), CERTIFICATE_FLAG_TRUSTED | CERTIFICATE_FLAG_ALLOW_FEC);
    assert_eq!(
        cert.check(local.id().data(), overlay_id(5).data(), NOW, 4000, true, false),
        BroadcastCheckResult::Allowed
    );
    // Recreating the same overlay keeps the key and reinstalls the certificate.
    let again = sources.register_overlay(&shard(), &overlay_id(5), adnl.id(), NOW + 5).unwrap();
    assert_eq!(sources.local_key(&shard()).unwrap().id(), local.id());
    assert_eq!(again.rules, Some(authority_rules(&roots(&[&signer]))));
    assert_eq!(again.certificates[0], (local.id().clone(), Some(cert)));
}

#[test]
fn signer_change_resigns_and_signer_loss_keeps_held_certificates() {
    let sources = ShardOverlayCertificates::new();
    let adnl = key(9);
    let (a, b) = (key(1), key(2));
    sources.register_overlay(&shard(), &overlay_id(5), adnl.id(), NOW).unwrap();
    sources.update_authority(&roots(&[&a, &b]), Some(a.clone()), NOW).unwrap();
    let by_a = sources.local_certificate(&shard()).unwrap();
    // The same signer on a later refresh of the rules does not re-sign.
    sources.update_authority(&roots(&[&a, &b]), Some(a.clone()), NOW + 10).unwrap();
    assert_eq!(sources.local_certificate(&shard()).unwrap(), by_a);
    sources.update_authority(&roots(&[&a, &b]), Some(b.clone()), NOW + 20).unwrap();
    let by_b = sources.local_certificate(&shard()).unwrap();
    assert_eq!(by_b.issuer_hash(), b.id().data());
    // Losing the signer keeps the held certificate and stops re-signing.
    let installs = sources.update_authority(&roots(&[&a]), None, NOW + 30).unwrap();
    assert_eq!(sources.local_certificate(&shard()).unwrap(), by_b);
    assert_eq!(installs[0].rules, Some(authority_rules(&roots(&[&a]))));
    assert!(sources.refresh(NOW + 60).unwrap().is_empty());
    assert_eq!(sources.signer_id().unwrap(), None);
}

#[test]
fn refresh_resigns_with_a_new_expiry() {
    let sources = ShardOverlayCertificates::new();
    let a = key(1);
    sources.register_overlay(&shard(), &overlay_id(5), key(9).id(), NOW).unwrap();
    sources.update_authority(&roots(&[&a]), Some(a.clone()), NOW).unwrap();
    let installs = sources.refresh(NOW + 30).unwrap();
    assert_eq!(installs.len(), 1);
    assert_eq!(
        sources.local_certificate(&shard()).unwrap().expire_at(),
        NOW + 30 + SELF_CERTIFICATE_LIFETIME_SEC
    );
}

#[test]
fn root_removal_and_empty_roots_drop_stale_authority() {
    let sources = ShardOverlayCertificates::new();
    let (a, b) = (key(1), key(2));
    sources.register_overlay(&shard(), &overlay_id(5), key(9).id(), NOW).unwrap();
    sources.update_authority(&roots(&[&a, &b]), None, NOW).unwrap();
    sources.update_authority(&roots(&[&b]), None, NOW).unwrap();
    assert!(!sources.rules().unwrap().is_authorized_key(a.id().data()));
    let installs = sources.update_authority(&[], None, NOW).unwrap();
    assert!(sources.rules().unwrap().authorized_keys().is_empty());
    assert_eq!(installs[0].rules, Some(authority_rules(&[])));
}

#[test]
fn outbound_source_prefers_a_valid_adnl_certificate() {
    let sources = ShardOverlayCertificates::new();
    let (a, adnl) = (key(1), key(9));
    let overlay = overlay_id(5);
    sources.register_overlay(&shard(), &overlay, adnl.id(), NOW).unwrap();
    sources.update_authority(&roots(&[&a]), None, NOW).unwrap();
    let local = sources.local_key(&shard()).unwrap();
    let choose = |size, is_fec, now| {
        sources.choose_outbound_source(&shard(), &adnl, size, is_fec, now).unwrap().id().clone()
    };
    assert_eq!(&choose(100, false, NOW), local.id());
    sources
        .import_certificate(
            &shard(),
            adnl.id(),
            &issued(&a, &overlay, adnl.id(), NOW + 100, MAX_FEC_BROADCAST_SIZE),
            NOW,
        )
        .unwrap();
    assert_eq!(&choose(4000, true, NOW), adnl.id());
    assert_eq!(
        &choose(MAX_FEC_BROADCAST_SIZE as usize + 1, true, NOW),
        local.id(),
        "certificate cap"
    );
    assert_eq!(&choose(4000, true, NOW + 101), local.id(), "expired certificate");
    sources.update_authority(&roots(&[&key(2)]), None, NOW).unwrap();
    assert_eq!(&choose(4000, true, NOW), local.id(), "issuer no longer authorized");
    sources.update_authority(&roots(&[&a]), None, NOW).unwrap();
    assert_eq!(&choose(4000, true, NOW), adnl.id());
    let reset = sources.reset_adnl_source_certificates().unwrap();
    assert_eq!(reset[0].certificates, vec![(adnl.id().clone(), None)]);
    assert_eq!(reset[0].rules, None);
    assert_eq!(&choose(4000, true, NOW), local.id());
    // A changed full-node identity starts without the old certificate.
    sources
        .import_certificate(
            &shard(),
            adnl.id(),
            &issued(&a, &overlay, adnl.id(), NOW + 100, MAX_FEC_BROADCAST_SIZE),
            NOW,
        )
        .unwrap();
    sources.register_overlay(&shard(), &overlay, key(10).id(), NOW).unwrap();
    assert_eq!(&choose(4000, true, NOW), local.id());
}

#[test]
fn console_import_checks_each_condition() {
    let sources = ShardOverlayCertificates::new();
    let (a, stranger, adnl) = (key(1), key(3), key(9));
    let overlay = overlay_id(5);
    assert!(
        sources
            .import_certificate(
                &shard(),
                adnl.id(),
                &issued(&a, &overlay, adnl.id(), NOW + 100, 1 << 24),
                NOW
            )
            .is_err(),
        "unregistered shard"
    );
    sources.register_overlay(&shard(), &overlay, adnl.id(), NOW).unwrap();
    sources.update_authority(&roots(&[&a]), None, NOW).unwrap();
    let max = MAX_FEC_BROADCAST_SIZE;
    let error = |cert: &CertificateTl| {
        sources.import_certificate(&shard(), adnl.id(), cert, NOW).unwrap_err().to_string()
    };
    assert!(error(&CertificateTl::Overlay_EmptyCertificate).contains("empty"));
    let mut short = issued(&a, &overlay, adnl.id(), NOW + 100, max);
    if let CertificateTl::Overlay_Certificate(c) = &mut short {
        c.signature.truncate(63);
    }
    assert!(error(&short).contains("signature size"));
    assert!(error(&issued(&a, &overlay, key(4).id(), NOW + 100, max)).contains("not valid"));
    assert!(error(&issued(&a, &overlay, adnl.id(), NOW - 1, max)).contains("not valid"));
    assert!(error(&issued(&a, &overlay, adnl.id(), NOW + 100, max - 1)).contains("not valid"));
    assert!(error(&issued(&a, &overlay_id(6), adnl.id(), NOW + 100, max)).contains("not valid"));
    assert!(
        error(&issued(&stranger, &overlay, adnl.id(), NOW + 100, max)).contains("not authorized")
    );
    let local = sources.local_key(&shard()).unwrap();
    let install = sources
        .import_certificate(
            &shard(),
            local.id(),
            &issued(&a, &overlay, local.id(), NOW + 100, max),
            NOW,
        )
        .unwrap();
    assert_eq!(install.certificates[0].0, local.id().clone());
    assert_eq!(sources.local_certificate(&shard()).unwrap().expire_at(), NOW + 100);
}

#[test]
fn pushed_import_adds_the_push_restrictions_only() {
    let sources = ShardOverlayCertificates::new();
    let (a, stranger, adnl) = (key(1), key(3), key(9));
    let overlay = overlay_id(5);
    sources.register_overlay(&shard(), &overlay, adnl.id(), NOW).unwrap();
    sources.update_authority(&roots(&[&a, &stranger]), None, NOW).unwrap();
    let sender = KeyId::from_data([44; 32]);
    let accept: HashSet<_> = [sender.clone()].into_iter().collect();
    let good = issued(&a, &overlay, adnl.id(), NOW + 61, MAX_FEC_BROADCAST_SIZE);
    let push = |from: &Arc<KeyId>,
                any: bool,
                signed: &Arc<KeyId>,
                cert: &CertificateTl,
                roots: &[Arc<KeyId>]| {
        sources.import_pushed_certificate(
            &shard(),
            from,
            &accept,
            any,
            adnl.id(),
            signed,
            cert,
            roots,
            NOW,
        )
    };
    let validator_roots = roots(&[&a]);
    let other = KeyId::from_data([45; 32]);
    assert!(push(&other, false, adnl.id(), &good, &validator_roots).is_err(), "unconfigured");
    assert!(push(&sender, false, key(4).id(), &good, &validator_roots).is_err(), "wrong key");
    let soon = issued(&a, &overlay, adnl.id(), NOW + 59, MAX_FEC_BROADCAST_SIZE);
    assert!(push(&sender, false, adnl.id(), &soon, &validator_roots).is_err(), "too soon");
    // The overlay rules authorize `stranger`, but it is not a validator root.
    let by_stranger = issued(&stranger, &overlay, adnl.id(), NOW + 100, MAX_FEC_BROADCAST_SIZE);
    assert!(push(&other, true, adnl.id(), &by_stranger, &validator_roots).is_err());
    assert!(push(&other, true, adnl.id(), &good, &validator_roots).is_ok(), "wildcard source");
    assert!(push(&sender, false, adnl.id(), &good, &validator_roots).is_ok());
    // Console import does not inherit the push-only restrictions.
    assert!(sources.import_certificate(&shard(), adnl.id(), &soon, NOW).is_ok());
}

#[test]
fn console_signing_and_issuing_need_signing_authority() {
    let sources = ShardOverlayCertificates::new();
    let a = key(1);
    let overlay = overlay_id(5);
    let subject = key(9);
    sources.register_overlay(&shard(), &overlay, subject.id(), NOW).unwrap();
    assert!(sources.sign_overlay_certificate(&shard(), subject.id(), NOW + 100, 1 << 24).is_err());
    sources.update_authority(&roots(&[&a]), Some(a.clone()), NOW).unwrap();
    let reply =
        sources.sign_overlay_certificate(&shard(), subject.id(), NOW + 100, 1 << 24).unwrap();
    assert!(matches!(reply, CertificateTl::Overlay_Certificate(_)));
    let parsed = OverlayCertificate::from_tl(&reply).unwrap().unwrap();
    assert_eq!(
        parsed.check(subject.id().data(), overlay.data(), NOW, 100, true, false),
        BroadcastCheckResult::Allowed
    );
    // At 768 bytes the version-1 reply does not verify, as with the peer.
    let small = sources.sign_overlay_certificate(&shard(), subject.id(), NOW + 100, 768).unwrap();
    let parsed = OverlayCertificate::from_tl(&small).unwrap().unwrap();
    assert_eq!(
        parsed.check(subject.id().data(), overlay.data(), NOW, 100, false, false),
        BroadcastCheckResult::Forbidden
    );
    let targets = vec![KeyId::from_data([60; 32]), KeyId::from_data([61; 32])];
    let messages = sources.issue_shard_overlay_certificates(&targets, &[shard()], NOW).unwrap();
    assert_eq!(messages.len(), 2);
    for ((target, message), expected) in messages.iter().zip(&targets) {
        assert_eq!(target, expected);
        assert_eq!(message.workchain, shard().workchain_id());
        assert_eq!(message.shard, shard().shard_prefix_with_tag() as i64);
        let parsed = OverlayCertificate::from_tl(&message.cert).unwrap().unwrap();
        assert_eq!(parsed.expire_at(), NOW + SELF_CERTIFICATE_LIFETIME_SEC);
        assert_eq!(
            parsed.check(target.data(), overlay.data(), NOW, 1 << 20, true, false),
            BroadcastCheckResult::Allowed
        );
    }
}
