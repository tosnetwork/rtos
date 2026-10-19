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
fn console_import_reports_the_reference_codes_in_order() {
    let sources = ShardOverlayCertificates::new();
    let (a, adnl) = (key(1), key(9));
    let overlay = overlay_id(5);
    let code = |result: Result<OverlayInstall>| {
        let error = result.unwrap_err();
        (error_code(&error), error.to_string())
    };
    // An unknown shard is reported before an empty certificate.
    assert_eq!(
        code(sources.import_certificate(
            &shard(),
            adnl.id(),
            &CertificateTl::Overlay_EmptyCertificate,
            NOW
        )),
        (602, "shard not found".to_string())
    );
    sources.register_overlay(&shard(), &overlay, adnl.id(), NOW).unwrap();
    sources.update_authority(&roots(&[&a]), None, NOW).unwrap();
    assert_eq!(
        code(sources.import_certificate(
            &shard(),
            adnl.id(),
            &CertificateTl::Overlay_EmptyCertificate,
            NOW
        )),
        (0, "empty certificate".to_string())
    );
    // Any wire value names a shard; one not registered is not found.
    let unknown = WireShard { workchain: 0, shard: 0 };
    let cert = issued(&a, &overlay, adnl.id(), NOW + 100, MAX_FEC_BROADCAST_SIZE);
    assert_eq!(
        code(sources.import_certificate_wire(unknown, adnl.id(), &cert, NOW)).0,
        ERROR_CODE_ERROR
    );
    let (code_value, text) = code(sources.import_certificate(&shard(), key(4).id(), &cert, NOW));
    assert_eq!((code_value, text.as_str()), (0, "certificate is not valid for this shard overlay"));
}

fn policy(accept: &[&str]) -> ShardOverlayCertificatePolicy {
    let mut policy = ShardOverlayCertificatePolicy::default();
    for value in accept {
        policy.add_accept_certs_from(value).unwrap();
    }
    policy
}

#[test]
fn pushed_import_adds_the_push_restrictions_only() {
    let sources = ShardOverlayCertificates::new();
    let (a, stranger, adnl) = (key(1), key(3), key(9));
    let overlay = overlay_id(5);
    sources.register_overlay(&shard(), &overlay, adnl.id(), NOW).unwrap();
    // The validator roots of the applied state are `a` only.
    sources.update_authority(&roots(&[&a]), None, NOW).unwrap();
    let sender = KeyId::from_data([44; 32]);
    let configured = policy(&[&hex::encode(sender.data())]);
    let any = policy(&["*"]);
    let now = f64::from(NOW);
    let good = issued(&a, &overlay, adnl.id(), NOW + 61, MAX_FEC_BROADCAST_SIZE);
    let push = |from: &Arc<KeyId>,
                policy: &ShardOverlayCertificatePolicy,
                signed: &Arc<KeyId>,
                cert: &CertificateTl,
                now: f64| {
        sources.import_pushed_certificate(
            (&shard()).into(),
            from,
            policy,
            adnl.id(),
            signed,
            cert,
            now,
        )
    };
    let other = KeyId::from_data([45; 32]);
    let error = |result: Result<OverlayInstall>| result.unwrap_err().to_string();
    assert!(error(push(&other, &configured, adnl.id(), &good, now)).contains("not configured"));
    assert!(error(push(&sender, &configured, key(4).id(), &good, now)).contains("unexpected key"));
    let soon = issued(&a, &overlay, adnl.id(), NOW + 59, MAX_FEC_BROADCAST_SIZE);
    assert!(error(push(&sender, &configured, adnl.id(), &soon, now)).contains("too soon"));
    // The boundary uses fractional time: an expiry of floor(now) + 60 is
    // already too soon once a fraction of the second has passed.
    let edge = issued(&a, &overlay, adnl.id(), NOW + 60, MAX_FEC_BROADCAST_SIZE);
    assert!(push(&sender, &configured, adnl.id(), &edge, now).is_ok());
    assert!(error(push(&sender, &configured, adnl.id(), &edge, now + 0.25)).contains("too soon"));
    // The console path truncates the same clock to whole seconds and accepts.
    assert!(sources.import_certificate(&shard(), adnl.id(), &edge, (now + 0.25) as i32).is_ok());
    // A wildcard admits any sender, including one that is no validator, but
    // the certificate's issuer must still be a validator root.
    assert!(push(&other, &any, adnl.id(), &good, now).is_ok(), "non-validator forwarder");
    let by_stranger = issued(&stranger, &overlay, adnl.id(), NOW + 100, MAX_FEC_BROADCAST_SIZE);
    assert!(error(push(&other, &any, adnl.id(), &by_stranger, now)).contains("not a validator"));
    assert!(push(&sender, &configured, adnl.id(), &good, now).is_ok());
    // Console import does not inherit the push-only restrictions.
    assert!(sources.import_certificate(&shard(), adnl.id(), &soon, NOW).is_ok());
    assert_eq!(sources.adnl_certificate(&shard()).unwrap().expire_at(), NOW + 59);
}

#[test]
fn console_signing_needs_the_shard_then_signing_authority() {
    let sources = ShardOverlayCertificates::new();
    let a = key(1);
    let overlay = overlay_id(5);
    let subject = key(9);
    let error = |result: Result<CertificateTl>| {
        let error = result.unwrap_err();
        (error_code(&error), error.to_string())
    };
    assert_eq!(
        error(sources.sign_overlay_certificate(&shard(), subject.id(), NOW + 100, 1 << 24)),
        (602, "shard not found".to_string())
    );
    sources.register_overlay(&shard(), &overlay, subject.id(), NOW).unwrap();
    assert_eq!(
        error(sources.sign_overlay_certificate(&shard(), subject.id(), NOW + 100, 1 << 24)),
        (0, "Node has no key with signing authority".to_string())
    );
    sources.update_authority(&roots(&[&a]), Some(a.clone()), NOW).unwrap();
    let reply =
        sources.sign_overlay_certificate(&shard(), subject.id(), NOW + 100, 1 << 24).unwrap();
    assert!(matches!(reply, CertificateTl::Overlay_Certificate(_)));
    let parsed = OverlayCertificate::from_tl(&reply).unwrap().unwrap();
    assert_eq!(
        parsed.check(subject.id().data(), overlay.data(), NOW, 100, true, false),
        BroadcastCheckResult::Allowed
    );
    assert!(sources.import_certificate(&shard(), subject.id(), &reply, NOW).is_ok());
    // At 768 bytes signing succeeds and replies version 1, but the reply
    // does not verify, so it cannot be imported either, as with the peer.
    let small = sources.sign_overlay_certificate(&shard(), subject.id(), NOW + 100, 768).unwrap();
    assert!(matches!(small, CertificateTl::Overlay_Certificate(_)));
    let parsed = OverlayCertificate::from_tl(&small).unwrap().unwrap();
    assert_eq!(
        parsed.check(subject.id().data(), overlay.data(), NOW, 100, false, false),
        BroadcastCheckResult::Forbidden
    );
    assert!(sources.import_certificate(&shard(), subject.id(), &small, NOW).is_err());
    // Wire integers keep their bit patterns: a negative size is a huge cap.
    let huge = sources.sign_overlay_certificate(&shard(), subject.id(), -5, u32::MAX).unwrap();
    let CertificateTl::Overlay_Certificate(huge) = huge else { panic!("version 1 reply") };
    assert_eq!((huge.expire_at, huge.max_size), (-5, -1));
}

#[test]
fn issuing_signs_every_pair_and_isolates_failures() {
    let sources = ShardOverlayCertificates::new();
    let a = key(1);
    let overlay = overlay_id(5);
    sources.register_overlay(&shard(), &overlay, key(9).id(), NOW).unwrap();
    let missing = ShardIdent::with_workchain_id(0).unwrap();
    let targets = vec![KeyId::from_data([60; 32]), KeyId::from_data([61; 32])];
    let expire_at = NOW + ISSUED_CERTIFICATE_LIFETIME_SEC;
    let issued = sources
        .issue_shard_overlay_certificates(&a, &targets, &[missing.clone(), shard()], expire_at)
        .unwrap();
    assert_eq!(issued.len(), 4);
    for item in &issued {
        if item.shard == missing {
            assert!(item.message.is_err(), "a shard without an overlay fails only its pairs");
            continue;
        }
        let message = item.message.as_ref().unwrap();
        assert_eq!(message.workchain, shard().workchain_id());
        assert_eq!(message.shard, shard().shard_prefix_with_tag() as i64);
        assert_eq!(message.signed_key.key_hash().as_slice(), item.target.data());
        let parsed = OverlayCertificate::from_tl(&message.cert).unwrap().unwrap();
        assert_eq!(parsed.expire_at(), expire_at);
        assert_eq!(parsed.issuer_hash(), a.id().data());
        assert_eq!(
            parsed.check(item.target.data(), overlay.data(), NOW, 1 << 20, true, false),
            BroadcastCheckResult::Allowed
        );
    }
    assert_eq!(issued.iter().filter(|item| item.message.is_ok()).count(), 2);
}

#[test]
fn pushed_message_matches_the_reference_wire_form() {
    // Constructor numbers of the fixed reference schema.
    assert_eq!(push_constructor(), 448989784);
    let a = key(1);
    let sources = ShardOverlayCertificates::new();
    let overlay = overlay_id(5);
    sources.register_overlay(&shard(), &overlay, key(9).id(), NOW).unwrap();
    let target = KeyId::from_data([60; 32]);
    let issued = sources
        .issue_shard_overlay_certificates(&a, &[target.clone()], &[shard()], NOW + 3600)
        .unwrap();
    let message = issued.into_iter().next().unwrap().message.unwrap();
    let bytes = rtos_api::serialize_boxed(&message).unwrap();
    let word = |at: usize| i32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    assert_eq!(word(0), 448989784);
    assert_eq!(word(4), -1);
    assert_eq!(i64::from_le_bytes(bytes[8..16].try_into().unwrap()), i64::MIN);
    assert_eq!(word(16), -1027168946, "engine.validator.keyHash");
    assert_eq!(&bytes[20..52], target.data());
    assert_eq!(word(52), -526461135, "overlay.certificate");
    assert_eq!(word(56), 1209251014, "pub.ed25519");
    assert_eq!(&bytes[60..92], a.pub_key().unwrap());
    assert_eq!(word(92), NOW + 3600);
    assert_eq!(word(96), MAX_FEC_BROADCAST_SIZE as i32);
    // A 64-byte signature as a TL byte string: length byte, bytes, padding.
    assert_eq!(bytes[100], 64);
    assert_eq!(bytes.len(), 100 + 1 + 64 + 3);
}

#[test]
fn policy_follows_the_repeated_option_semantics() {
    let id = |seed: u8| hex::encode([seed; 32]);
    let mut policy = ShardOverlayCertificatePolicy::default();
    assert!(!policy.receives());
    policy.add_auto_sign(&id(2)).unwrap();
    policy.add_auto_sign(&id(1)).unwrap();
    policy.add_auto_sign(&id(2)).unwrap();
    let targets: Vec<_> = policy.auto_sign().iter().map(|t| *t.data()).collect();
    assert_eq!(targets, vec![[1; 32], [2; 32]], "duplicates collapse, id order");
    policy.add_accept_certs_from(&id(3)).unwrap();
    policy.add_accept_certs_from(&id(3)).unwrap();
    assert_eq!(policy.accepted_senders().len(), 1);
    assert!(policy.receives() && !policy.accepts_from_any());
    assert!(policy.accepts(&KeyId::from_data([3; 32])));
    assert!(!policy.accepts(&KeyId::from_data([4; 32])));
    policy.add_accept_certs_from("*").unwrap();
    policy.add_accept_certs_from(&id(5)).unwrap();
    assert!(policy.accepts_from_any(), "the wildcard stays in force");
    assert!(policy.accepts(&KeyId::from_data([4; 32])));
    for bad in ["zz", "0102", &"00".repeat(32), &format!("{}00", id(1)), "", "**"] {
        assert!(ShardOverlayCertificatePolicy::default().add_auto_sign(bad).is_err(), "{bad}");
        assert!(
            ShardOverlayCertificatePolicy::default().add_accept_certs_from(bad).is_err(),
            "{bad}"
        );
    }
    assert!(parse_adnl_id_hex(&"00".repeat(32)).unwrap_err().to_string().contains("zero"));
}

#[test]
fn certificate_shards_follow_the_reference_set() {
    use rtos_block::{ConfigParam12, ShardHashes, WorkchainDescr};
    let mut hashes = ShardHashes::default();
    hashes.add_workchain(0, 0, UInt256::from([1; 32]), UInt256::from([2; 32])).unwrap();
    let full = ShardIdent::with_workchain_id(0).unwrap();
    hashes.split_shard(&full, |d| Ok((d.clone(), d))).unwrap();
    let (left, right) = full.split().unwrap();
    hashes.split_shard(&left, |d| Ok((d.clone(), d))).unwrap();
    let mut workchains = ConfigParam12::new();
    let descr = |monitor: u8, active: bool, since: u32| WorkchainDescr {
        enabled_since: since,
        monitor_min_split: monitor,
        min_split: 2,
        max_split: 32,
        active,
        ..Default::default()
    };
    workchains.insert(0, &descr(1, true, 0)).unwrap();
    // Active without shards; inactive; enabled only later.
    workchains.insert(7, &descr(0, true, 100)).unwrap();
    workchains.insert(8, &descr(0, false, 0)).unwrap();
    workchains.insert(9, &descr(0, true, 1001)).unwrap();
    let mut config = ConfigParams::default();
    config.set_config(ConfigParamEnum::ConfigParam12(workchains)).unwrap();
    let shards = overlay_certificate_shards(&hashes, &config, 1000).unwrap();
    let ids: Vec<_> =
        shards.iter().map(|s| (s.workchain_id(), s.shard_prefix_with_tag())).collect();
    // The depth-2 shards are cut to the basechain monitor depth 1.
    assert_eq!(
        ids,
        vec![
            (-1, SHARD_FULL),
            (0, left.shard_prefix_with_tag()),
            (0, SHARD_FULL),
            (0, right.shard_prefix_with_tag()),
            (7, SHARD_FULL),
        ]
    );
    // Without a basechain description the depth is 0: all cut to the root.
    let mut bare = ConfigParam12::new();
    bare.insert(7, &descr(0, true, 0)).unwrap();
    let mut config = ConfigParams::default();
    config.set_config(ConfigParamEnum::ConfigParam12(bare)).unwrap();
    assert_eq!(overlay_certificate_shards(&hashes, &config, 1000).unwrap().len(), 3);
}

#[tokio::test]
async fn endpoint_claims_only_accepted_pushes_for_the_full_node_identity() {
    let full_node = KeyId::from_data([9; 32]);
    let sender = KeyId::from_data([44; 32]);
    let message = ImportShardOverlayCertificate {
        workchain: -1,
        shard: i64::MIN,
        signed_key: KeyHash { key_hash: UInt256::from(*full_node.data()) }.into_boxed(),
        cert: CertificateTl::Overlay_EmptyCertificate,
    };
    let bytes = rtos_api::serialize_boxed(&message).unwrap();
    let to_full_node = AdnlPeers::with_keys(full_node.clone(), sender.clone());
    let elsewhere = AdnlPeers::with_keys(KeyId::from_data([10; 32]), sender.clone());
    let closed = ShardCertificateEndpoint::new(policy(&[]), full_node.clone());
    assert!(!closed.try_consume_custom(&bytes, &to_full_node).await.unwrap(), "unsubscribed");
    let open = ShardCertificateEndpoint::new(policy(&["*"]), full_node.clone());
    assert!(open.try_consume_custom(&bytes, &to_full_node).await.unwrap());
    assert!(!open.try_consume_custom(&bytes, &elsewhere).await.unwrap(), "other identity");
    assert!(!open.try_consume_custom(&[1, 2, 3, 4, 5], &to_full_node).await.unwrap());
    // Accepted senders are consumed even before a full node exists; others
    // are consumed and dropped before decoding.
    let listed = ShardCertificateEndpoint::new(
        policy(&[&hex::encode(KeyId::from_data([45; 32]).data())]),
        full_node,
    );
    let mut garbage = bytes.clone();
    garbage.truncate(6);
    assert!(listed.try_consume_custom(&garbage, &to_full_node).await.unwrap());
    assert!(listed.serving_router().is_err());
}
