/*
 * RTOS project additions (2026-10-19): overlay broadcast authorization tests.
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! `privacy_vectors.tsv` is produced by an out-of-tree generator linked
//! against the peer implementation's own overlay library (see the header of
//! each record kind there); these tests replay it byte for byte.

use super::*;
use rtos_block::{Ed25519KeyOption, ZeroizingBytes};

const VECTORS: &str = include_str!("privacy_vectors.tsv");

fn unix_time_now() -> i32 {
    use crate::BroadcastClock;
    crate::SystemBroadcastClock.unix_seconds() as u32 as i32
}

fn records(kind: &str) -> Vec<Vec<&'static str>> {
    VECTORS
        .lines()
        .map(|line| line.split('\t').collect::<Vec<_>>())
        .filter(|fields| fields[0] == kind)
        .collect()
}

fn hex32(value: &str) -> [u8; 32] {
    hex::decode(value).unwrap().try_into().unwrap()
}

fn named_key(name: &str) -> [u8; 32] {
    let record = records("K").into_iter().find(|fields| fields[1] == name).unwrap();
    hex32(record[2])
}

fn overlay_id() -> [u8; 32] {
    hex32(records("O")[0][1])
}

fn verdict(name: &str) -> BroadcastCheckResult {
    match name {
        "Forbidden" => BroadcastCheckResult::Forbidden,
        "NeedCheck" => BroadcastCheckResult::NeedCheck,
        "Allowed" => BroadcastCheckResult::Allowed,
        other => panic!("unknown verdict {other}"),
    }
}

fn parse_cert(value: &str) -> CertificateTl {
    rtos_api::deserialize_boxed(hex::decode(value).unwrap())
        .unwrap()
        .downcast::<CertificateTl>()
        .unwrap()
}

pub(crate) fn seed_key(seed: u8) -> Arc<dyn KeyOption> {
    Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[seed; 32]).unwrap()
}

fn rules_named(name: &str) -> OverlayPrivacyRules {
    match name {
        "startup" => OverlayPrivacyRules::with_max_unauthorized_size(MAX_FEC_BROADCAST_SIZE),
        "updated" => OverlayPrivacyRules::new(
            MAX_FEC_BROADCAST_SIZE,
            CERTIFICATE_FLAG_ALLOW_FEC,
            BTreeMap::from([
                (named_key("issuer"), MAX_FEC_BROADCAST_SIZE),
                (named_key("weak_issuer"), 1000),
                (named_key("direct"), MAX_FEC_BROADCAST_SIZE),
            ]),
        ),
        "empty" => OverlayPrivacyRules::new(
            MAX_FEC_BROADCAST_SIZE,
            CERTIFICATE_FLAG_ALLOW_FEC,
            BTreeMap::new(),
        ),
        other => panic!("unknown rules {other}"),
    }
}

#[test]
fn seeds_reproduce_generator_identities() {
    for (name, seed) in
        [("issuer", 1), ("weak_issuer", 2), ("stranger", 3), ("direct", 8), ("subject", 9)]
    {
        assert_eq!(seed_key(seed).id().data(), &named_key(name), "{name}");
    }
}

#[test]
fn check_rules_matches_reference_matrix() {
    let rows = records("R");
    assert_eq!(rows.len(), 576);
    let authorized = named_key("authorized");
    let other = named_key("other");
    for row in rows {
        let max: u32 = row[1].parse().unwrap();
        let flags: u32 = row[2].parse().unwrap();
        let is_authorized = row[3] == "1";
        let cap: u32 = row[4].parse().unwrap();
        let size: u32 = row[5].parse().unwrap();
        let mut keys = BTreeMap::new();
        if is_authorized {
            keys.insert(authorized, cap);
        }
        let rules = OverlayPrivacyRules::new(max, flags, keys);
        let source = if is_authorized { &authorized } else { &other };
        assert_eq!(
            rules.check_rules(source, size, row[6] == "1", row[7] == "1"),
            verdict(row[8]),
            "{row:?}"
        );
    }
}

#[test]
fn preimage_and_normalized_serialization_are_byte_exact() {
    let rows = records("T");
    assert_eq!(rows.len(), 63);
    let overlay = overlay_id();
    for row in rows {
        let cert = OverlayCertificate::from_tl(&parse_cert(row[1])).unwrap().unwrap();
        let node = hex32(row[2]);
        assert_eq!(hex::encode(cert.to_sign(&overlay, &node).unwrap()), row[3], "{row:?}");
        assert_eq!(hex::encode(serialize_boxed(&cert.to_tl()).unwrap()), row[4], "{row:?}");
        assert_eq!(hex::encode(cert.tl_hash().unwrap()), row[5], "{row:?}");
    }
}

#[test]
fn certificate_check_matches_reference_matrix() {
    let header = &records("N")[0];
    let node = hex32(header[1]);
    let now: i32 = header[2].parse().unwrap();
    let overlay = overlay_id();
    let rows = records("C");
    assert_eq!(rows.len(), 378);
    let sizes = [0u32, 1, 768, 769, MAX_FEC_BROADCAST_SIZE];
    for row in rows {
        let cert = OverlayCertificate::from_tl(&parse_cert(row[1])).unwrap().unwrap();
        let expected: Vec<_> = row[2].split(',').map(verdict).collect();
        let mut actual = Vec::new();
        for size in sizes {
            for is_fec in [false, true] {
                actual.push(cert.check(&node, &overlay, now, size, is_fec, false));
            }
        }
        assert_eq!(actual, expected, "{}", row[1]);
    }
}

#[test]
fn issuer_without_signature_scheme_fails_only_the_signature_step() {
    let header = &records("N")[0];
    let node = hex32(header[1]);
    let now: i32 = header[2].parse().unwrap();
    let overlay = overlay_id();
    let rows = records("X");
    assert_eq!(rows.len(), 2);
    for row in rows {
        let cert = OverlayCertificate::from_tl(&parse_cert(row[2])).unwrap().unwrap();
        assert_eq!(cert.check(&node, &overlay, now, 100, true, row[1] == "1"), verdict(row[3]));
    }
}

#[test]
fn empty_certificate_parses_as_none() {
    assert!(OverlayCertificate::from_tl(&CertificateTl::Overlay_EmptyCertificate)
        .unwrap()
        .is_none());
}

fn eligibility_certificate(row: &[&str], overlay: &[u8; 32], now: i32) -> OverlayCertificate {
    let issuer = seed_key(row[3].parse().unwrap());
    let subject = if row[1] == "wrong_subject" { seed_key(8) } else { seed_key(9) };
    let offset: i32 = row[5].parse().unwrap();
    let max_size = row[6].parse::<i32>().unwrap() as u32;
    let flags = if row[8] == "1" {
        row[7].parse::<i32>().unwrap() as u32
    } else {
        OverlayCertificate::default_flags(max_size)
    };
    let mut cert = OverlayCertificate::sign(
        &issuer,
        overlay,
        subject.id().data(),
        now + offset,
        max_size,
        flags,
    )
    .unwrap();
    if row[9] == "1" {
        cert.signature[0] ^= 1;
    }
    cert
}

#[test]
fn source_eligibility_matches_reference_matrix() {
    let overlay = overlay_id();
    let rows = records("E");
    assert_eq!(rows.len(), 288);
    for row in rows {
        let now = unix_time_now();
        let rules = rules_named(row[2]);
        let source = seed_key(row[4].parse().unwrap());
        let cert = (row[13] == "1").then(|| eligibility_certificate(&row, &overlay, now));
        let verifier = BroadcastVerifier::default();
        let result = verifier.check_source_eligible_at(
            &rules,
            false,
            &overlay,
            source.id().data(),
            cert.as_ref(),
            row[10].parse().unwrap(),
            row[11] == "1",
            row[12] == "1",
            None,
            now,
            Instant::now(),
        );
        assert_eq!(result, verdict(row[14]), "{row:?}");
    }
}

#[test]
fn issuer_rate_limit_and_cache_match_reference_sequence() {
    let overlay = overlay_id();
    let rules = rules_named("updated");
    let issuer = seed_key(1);
    let subject = seed_key(9);
    let now = unix_time_now();
    let start = Instant::now();
    let check = |verifier: &BroadcastVerifier, cert: &OverlayCertificate| {
        verifier.check_source_eligible_at(
            &rules,
            false,
            &overlay,
            subject.id().data(),
            Some(cert),
            5000,
            true,
            true,
            None,
            now,
            start,
        )
    };
    let sign = |offset: i32, corrupt: bool| {
        let mut cert = OverlayCertificate::sign(
            &issuer,
            &overlay,
            subject.id().data(),
            now + offset,
            MAX_FEC_BROADCAST_SIZE,
            CERTIFICATE_FLAG_ALLOW_FEC | CERTIFICATE_FLAG_TRUSTED,
        )
        .unwrap();
        if corrupt {
            cert.signature[0] ^= 1;
        }
        cert
    };
    let rows = records("L");
    assert_eq!(rows.len(), 65);
    let verifier = BroadcastVerifier::default();
    for row in rows.iter().filter(|row| row[1] == "rate_limit") {
        let cert = sign(row[3].parse().unwrap(), false);
        assert_eq!(check(&verifier, &cert), verdict(row[4]), "{row:?}");
    }
    let cached = rows.iter().find(|row| row[1] == "cached_after_limit").unwrap();
    assert_eq!(check(&verifier, &sign(cached[3].parse().unwrap(), false)), verdict(cached[4]));
    let bad = rows.iter().find(|row| row[1] == "bad_after_limit").unwrap();
    assert_eq!(check(&verifier, &sign(bad[3].parse().unwrap(), true)), verdict(bad[4]));

    // Failed verifications are not charged to the window.
    let verifier = BroadcastVerifier::default();
    for step in 0..70 {
        check(&verifier, &sign(3600 + step, true));
    }
    let good = rows.iter().find(|row| row[1] == "good_after_bad").unwrap();
    assert_eq!(check(&verifier, &sign(good[3].parse().unwrap(), false)), verdict(good[4]));
}

#[test]
fn issuer_window_reopens_after_its_duration() {
    let overlay = overlay_id();
    let rules = rules_named("updated");
    let issuer = seed_key(1);
    let subject = seed_key(9);
    let now = unix_time_now();
    let start = Instant::now();
    let verifier = BroadcastVerifier::default();
    let check_at = |cert: &OverlayCertificate, at: Instant| {
        verifier.check_source_eligible_at(
            &rules,
            false,
            &overlay,
            subject.id().data(),
            Some(cert),
            5000,
            true,
            true,
            None,
            now,
            at,
        )
    };
    let sign = |offset: i32| {
        OverlayCertificate::sign(&issuer, &overlay, subject.id().data(), now + offset, 1 << 24, 3)
            .unwrap()
    };
    for step in 0..60 {
        assert_eq!(check_at(&sign(3600 + step), start), BroadcastCheckResult::Allowed);
    }
    assert_eq!(check_at(&sign(4000), start), BroadcastCheckResult::Forbidden);
    // The window keeps entries for exactly its duration.
    assert_eq!(
        check_at(&sign(4001), start + CERTIFICATE_CHECK_WINDOW),
        BroadcastCheckResult::Forbidden
    );
    assert_eq!(
        check_at(&sign(4002), start + CERTIFICATE_CHECK_WINDOW + Duration::from_millis(1)),
        BroadcastCheckResult::Allowed
    );
}

#[test]
fn cached_certificate_is_rechecked_for_expiry_size_flags_and_issuer() {
    let overlay = overlay_id();
    let issuer = seed_key(1);
    let subject = seed_key(9);
    let now = unix_time_now();
    let start = Instant::now();
    let rules = rules_named("updated");
    let cert = OverlayCertificate::sign(&issuer, &overlay, subject.id().data(), now + 10, 4096, 3)
        .unwrap();
    let verifier = BroadcastVerifier::default();
    let check = |rules: &OverlayPrivacyRules, size: u32, is_fec: bool, at: i32| {
        verifier.check_source_eligible_at(
            rules,
            false,
            &overlay,
            subject.id().data(),
            Some(&cert),
            size,
            is_fec,
            true,
            None,
            at,
            start,
        )
    };
    assert_eq!(check(&rules, 1000, true, now), BroadcastCheckResult::Allowed);
    // Same (subject, certificate) is now cached: each other gate still applies.
    assert_eq!(check(&rules, 1000, true, now + 11), BroadcastCheckResult::Forbidden);
    assert_eq!(check(&rules, 4097, true, now), BroadcastCheckResult::Forbidden);
    let without_issuer = OverlayPrivacyRules::new(
        MAX_FEC_BROADCAST_SIZE,
        CERTIFICATE_FLAG_ALLOW_FEC,
        BTreeMap::from([(named_key("weak_issuer"), 1000)]),
    );
    assert_eq!(check(&without_issuer, 1000, true, now), BroadcastCheckResult::Forbidden);
    let issuer_cap_reduced = OverlayPrivacyRules::new(
        MAX_FEC_BROADCAST_SIZE,
        CERTIFICATE_FLAG_ALLOW_FEC,
        BTreeMap::from([(*issuer.id().data(), 500)]),
    );
    assert_eq!(check(&issuer_cap_reduced, 1000, true, now), BroadcastCheckResult::Forbidden);
    let no_fec =
        OverlayCertificate::sign(&issuer, &overlay, subject.id().data(), now + 10, 4096, 2)
            .unwrap();
    let verdict = verifier.check_source_eligible_at(
        &rules,
        false,
        &overlay,
        subject.id().data(),
        Some(&no_fec),
        1000,
        true,
        true,
        None,
        now,
        start,
    );
    assert_eq!(verdict, BroadcastCheckResult::Forbidden);
}

#[test]
fn invalid_certificate_keeps_the_source_verdict() {
    // max(r, min(r2, issuer)): a bad certificate cannot lower NeedCheck.
    let overlay = overlay_id();
    let rules = rules_named("updated");
    let subject = seed_key(9);
    let now = unix_time_now();
    let mut cert =
        OverlayCertificate::sign(&seed_key(1), &overlay, subject.id().data(), now - 5, 4096, 3)
            .unwrap();
    let verifier = BroadcastVerifier::default();
    let result = |cert: &OverlayCertificate| {
        verifier.check_source_eligible_at(
            &rules,
            false,
            &overlay,
            subject.id().data(),
            Some(cert),
            100,
            true,
            false,
            None,
            now,
            Instant::now(),
        )
    };
    assert_eq!(result(&cert), BroadcastCheckResult::NeedCheck);
    cert.expire_at = now + 5;
    cert.signature[0] ^= 1;
    assert_eq!(result(&cert), BroadcastCheckResult::NeedCheck);
}

#[test]
fn fixed_member_lists_ignore_certificates() {
    let overlay = overlay_id();
    let rules = rules_named("updated");
    let subject = seed_key(9);
    let now = unix_time_now();
    let cert =
        OverlayCertificate::sign(&seed_key(1), &overlay, subject.id().data(), now + 60, 4096, 3)
            .unwrap();
    let verifier = BroadcastVerifier::default();
    let result = verifier.check_source_eligible_at(
        &rules,
        true,
        &overlay,
        subject.id().data(),
        Some(&cert),
        1000,
        true,
        true,
        None,
        now,
        Instant::now(),
    );
    assert_eq!(result, BroadcastCheckResult::Forbidden);
}

#[test]
fn shard_self_certificate_matches_reference_at_fixed_clock() {
    let row = &records("S")[0];
    let now: i32 = row[1].parse().unwrap();
    let cert = OverlayCertificate::sign(
        &seed_key(row[2].parse().unwrap()),
        &overlay_id(),
        seed_key(row[3].parse().unwrap()).id().data(),
        now + 3600,
        MAX_FEC_BROADCAST_SIZE,
        CERTIFICATE_FLAG_TRUSTED | CERTIFICATE_FLAG_ALLOW_FEC,
    )
    .unwrap();
    assert_eq!(hex::encode(serialize_boxed(&cert.to_tl()).unwrap()), row[4]);
    assert_eq!(hex::encode(cert.to_sign(&overlay_id(), &named_key("subject")).unwrap()), row[5]);
}

#[test]
fn console_signing_keeps_the_reference_version_one_reply() {
    let rows = records("Q");
    assert_eq!(rows.len(), 3);
    let subject = seed_key(9);
    for row in rows {
        let max_size: u32 = row[1].parse().unwrap();
        let reply = OverlayCertificate::sign_for_console(
            &seed_key(1),
            &overlay_id(),
            subject.id().data(),
            1700003600,
            max_size,
        )
        .unwrap();
        assert_eq!(hex::encode(serialize_boxed(&reply).unwrap()), row[3], "{max_size}");
        let reparsed = OverlayCertificate::from_tl(&reply).unwrap().unwrap();
        assert_eq!(
            reparsed.check(subject.id().data(), &overlay_id(), 1700000000, 100, false, false),
            verdict(row[4]),
            "{max_size}"
        );
    }
}

#[test]
fn bad_signature_bans_the_relaying_peer_for_five_seconds() {
    let key = seed_key(1);
    let message = b"payload";
    let good = key.sign(message).unwrap();
    let mut bad = good.clone();
    bad[0] ^= 1;
    let peer = KeyId::from_data([7; 32]);
    let other = KeyId::from_data([6; 32]);
    let verifier = BroadcastVerifier::default();
    let start = Instant::now();
    assert!(verifier
        .check_signature_from_peer_at(&key, message, &good, Some(&peer), start)
        .is_ok());
    assert!(verifier
        .check_signature_from_peer_at(&key, message, &bad, Some(&peer), start)
        .is_err());
    assert!(verifier.is_peer_banned_at(&peer, start));
    // Even a valid signature from the banned peer is refused, others are not.
    assert!(verifier
        .check_signature_from_peer_at(&key, message, &good, Some(&peer), start)
        .is_err());
    assert!(verifier
        .check_signature_from_peer_at(&key, message, &good, Some(&other), start)
        .is_ok());
    let later = start + SIGNATURE_REJECTION;
    assert!(!verifier.is_peer_banned_at(&peer, later));
    assert!(verifier
        .check_signature_from_peer_at(&key, message, &good, Some(&peer), later)
        .is_ok());
    // Locally checked data has no relaying peer and bans nobody.
    assert!(verifier.check_signature_from_peer_at(&key, message, &bad, None, start).is_err());
    assert!(!verifier.is_peer_banned_at(&other, start));
}

#[test]
fn bad_certificate_signature_bans_the_relaying_peer() {
    let overlay = overlay_id();
    let rules = rules_named("updated");
    let subject = seed_key(9);
    let now = unix_time_now();
    let mut cert =
        OverlayCertificate::sign(&seed_key(1), &overlay, subject.id().data(), now + 60, 4096, 3)
            .unwrap();
    cert.signature[0] ^= 1;
    let peer = KeyId::from_data([5; 32]);
    let verifier = BroadcastVerifier::default();
    let start = Instant::now();
    let result = verifier.check_source_eligible_at(
        &rules,
        false,
        &overlay,
        subject.id().data(),
        Some(&cert),
        1000,
        true,
        true,
        Some(&peer),
        now,
        start,
    );
    assert_eq!(result, BroadcastCheckResult::Forbidden);
    assert!(verifier.is_peer_banned_at(&peer, start));
}

#[test]
fn retained_limiters_follow_the_rules() {
    let overlay = overlay_id();
    let subject = seed_key(9);
    let now = unix_time_now();
    let rules = rules_named("updated");
    let cert =
        OverlayCertificate::sign(&seed_key(1), &overlay, subject.id().data(), now + 60, 4096, 3)
            .unwrap();
    let verifier = BroadcastVerifier::default();
    verifier.check_source_eligible_at(
        &rules,
        false,
        &overlay,
        subject.id().data(),
        Some(&cert),
        1000,
        true,
        true,
        None,
        now,
        Instant::now(),
    );
    assert_eq!(verifier.limiters.lock().unwrap().len(), 1);
    verifier.retain_authorized(&rules_named("empty"));
    assert!(verifier.limiters.lock().unwrap().is_empty());
}

#[test]
fn cached_certificate_uses_the_same_unenc_profile_as_direct_check() {
    let cert = OverlayCertificate::new(
        rtos_api::ton::pub_::publickey::Unenc { data: vec![3] }.into_boxed(),
        1000,
        768,
        CERTIFICATE_FLAG_TRUSTED,
        vec![9; 7],
    )
    .unwrap();
    let rules = OverlayPrivacyRules::new(0, 0, BTreeMap::from([(*cert.issuer_hash(), 768)]));
    let verifier = BroadcastVerifier::default();
    let now = Instant::now();
    for _ in 0..2 {
        assert_eq!(
            verifier.check_source_eligible_at(
                &rules,
                false,
                &[1; 32],
                &[2; 32],
                Some(&cert),
                768,
                false,
                false,
                None,
                1000,
                now,
            ),
            BroadcastCheckResult::Allowed
        );
    }
    assert_eq!(
        verifier.check_source_eligible_at(
            &rules,
            false,
            &[1; 32],
            &[2; 32],
            Some(&cert),
            768,
            false,
            false,
            None,
            1001,
            now,
        ),
        BroadcastCheckResult::Forbidden
    );
}
