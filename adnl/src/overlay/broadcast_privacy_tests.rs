/*
 * RTOS project additions (2026-10-19): public overlay broadcast receive rules.
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Receive-side source authorization of public overlays with privacy rules,
//! driven through the real overlay message entry point.

use super::*;
use crate::{
    common::Subscriber,
    node::{AdnlNode, AdnlNodeConfig},
    overlay::{
        privacy::{
            OverlayCertificate as SourceCertificate, OverlayPrivacyRules, PublicBroadcastCheck,
            CERTIFICATE_FLAG_ALLOW_FEC, CERTIFICATE_FLAG_TRUSTED,
        },
        BroadcastSubscription, OverlayParams, OverlayShortId,
    },
};
use rtos_block::{Ed25519KeyOption, ZeroizingBytes};
use std::{collections::BTreeMap, sync::atomic::AtomicUsize};

pub(super) fn seed_key(seed: u8) -> Arc<dyn KeyOption> {
    Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[seed; 32]).unwrap()
}

pub(super) struct Harness {
    pub(super) node: Arc<OverlayNode>,
    pub(super) overlay: Arc<Overlay>,
    pub(super) id: Arc<OverlayShortId>,
    pub(super) local: Arc<KeyId>,
    pub(super) subscription: BroadcastSubscription,
}

pub(super) const ISSUER: u8 = 1;
pub(super) const DIRECT: u8 = 8;

pub(super) fn shard_rules() -> OverlayPrivacyRules {
    OverlayPrivacyRules::new(
        MAX_FEC_BROADCAST_SIZE,
        CERTIFICATE_FLAG_ALLOW_FEC,
        BTreeMap::from([
            (*seed_key(ISSUER).id().data(), MAX_FEC_BROADCAST_SIZE),
            (*seed_key(DIRECT).id().data(), MAX_FEC_BROADCAST_SIZE),
        ]),
    )
}

pub(super) async fn harness(seed: u8, rules: OverlayPrivacyRules) -> Harness {
    let (_, config) =
        AdnlNodeConfig::from_ip_address_and_private_keys("127.0.0.1:0", vec![([seed; 32], 0)])
            .unwrap();
    let adnl = AdnlNode::with_config(
        config,
        #[cfg(feature = "dump")]
        None,
    )
    .await
    .unwrap();
    let local = adnl.key_by_tag(0).unwrap().id().clone();
    let node = OverlayNode::with_params(adnl, &[3; 32], 0).unwrap();
    let id = OverlayShortId::from_data([seed; 32]);
    assert!(node.add_public_overlay_with_rules(OverlayParams::with_id_only(&id), rules).unwrap());
    let overlay = node.get_overlay(&id, "fixture").unwrap();
    let mut subscription = node.subscribe_broadcast(&id).unwrap();
    // Delivery starts once the consumer has begun receiving.
    let _ = tokio::time::timeout(Duration::from_millis(1), subscription.recv()).await;
    Harness { node, overlay, id, local, subscription }
}

impl Harness {
    pub(super) async fn receive(&self, bytes: &[u8], from: u8) -> Result<bool> {
        let peers = AdnlPeers::with_keys(self.local.clone(), KeyId::from_data([from; 32]));
        self.node.try_consume_custom(bytes, &peers).await
    }

    pub(super) async fn delivered(&mut self, wait_ms: u64) -> Option<BroadcastRecvInfo> {
        tokio::time::timeout(Duration::from_millis(wait_ms), self.subscription.recv())
            .await
            .ok()
            .and_then(|r| r.ok().flatten())
    }

    pub(super) fn certificate(
        &self,
        subject: &Arc<dyn KeyOption>,
        flags: u32,
    ) -> OverlayCertificate {
        SourceCertificate::sign(
            &seed_key(ISSUER),
            self.id.data(),
            subject.id().data(),
            Version::get() + 3600,
            MAX_FEC_BROADCAST_SIZE,
            flags,
        )
        .unwrap()
        .to_tl()
    }
}

pub(super) fn simple_bytes(
    overlay: &Overlay,
    src: &Arc<dyn KeyOption>,
    certificate: OverlayCertificate,
    flags: u32,
    data: &[u8],
    corrupt: bool,
) -> Vec<u8> {
    let id = BroadcastSimpleProtocol::calc_broadcast_id(data, src, flags).unwrap();
    let date = Version::get();
    let mut signature =
        src.sign(&BroadcastSimpleProtocol::calc_to_sign(&id, date).unwrap()).unwrap();
    if corrupt {
        signature[0] ^= 1;
    }
    let bcast = BroadcastSimple {
        src: src.try_into().unwrap(),
        certificate,
        flags: flags as i32,
        data: data.to_vec(),
        date,
        signature,
    }
    .into_boxed();
    overlay.serialize_broadcast(&bcast).unwrap()
}

pub(super) fn fec_parts(
    overlay: &Overlay,
    src: &Arc<dyn KeyOption>,
    certificate: OverlayCertificate,
    flags: u32,
    data: &[u8],
    count: u32,
) -> (BroadcastId, Vec<Vec<u8>>) {
    let mut encoder = RaptorqEncoder::with_data(data, None);
    let params = encoder.params().clone();
    let data_hash = sha256_digest(data);
    let id =
        BroadcastFecProtocol::calc_broadcast_id(data_hash, data.len(), src, flags, params.clone())
            .unwrap();
    let date = Version::get();
    let mut parts = Vec::new();
    let mut next = 0;
    while parts.len() < count as usize {
        let mut seqno = next;
        let chunk = encoder.encode(&mut seqno).unwrap();
        next = seqno + 1;
        let to_sign = <BroadcastFecProtocol as FecProtocol<BroadcastFec>>::calc_to_sign(
            &id,
            data.len(),
            &chunk,
            seqno,
            date,
        )
        .unwrap();
        let bcast = BroadcastFec {
            src: src.try_into().unwrap(),
            certificate: certificate.clone(),
            data_hash: UInt256::with_array(data_hash),
            data_size: data.len() as i32,
            flags: flags as i32,
            data: chunk,
            seqno: seqno as i32,
            fec: params.clone().into_boxed(),
            date,
            signature: src.sign(&to_sign).unwrap(),
        }
        .into_boxed();
        parts.push(overlay.serialize_broadcast(&bcast).unwrap());
    }
    (id, parts)
}

/// Application check whose verdict and timing the test controls.
pub(super) struct TestCheck {
    pub(super) calls: AtomicUsize,
    pub(super) gate: tokio::sync::Semaphore,
    pub(super) approve: bool,
}

impl TestCheck {
    pub(super) fn new(approve: bool, gated: bool) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            gate: tokio::sync::Semaphore::new(if gated { 0 } else { 1 << 20 }),
            approve,
        })
    }
    pub(super) fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl PublicBroadcastCheck for TestCheck {
    async fn check_broadcast(&self, _source: &Arc<KeyId>, _data: &[u8]) -> Result<()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let _permit = self.gate.acquire().await.map_err(|e| error!("{e}"))?;
        if self.approve {
            Ok(())
        } else {
            fail!("refused by the application")
        }
    }
}

async fn eventually(mut done: impl FnMut() -> bool) {
    for _ in 0..500 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("condition not reached");
}

fn held_parts(h: &Harness, id: &BroadcastId) -> (usize, bool, bool) {
    let guard = h.overlay.owned_broadcasts.get(id).expect("transfer");
    let transfer =
        <BroadcastFecProtocol as FecProtocol<BroadcastFec>>::unwrap_transfer(guard.val()).unwrap();
    let relay = transfer.relay.lock().unwrap();
    (relay.held.len(), relay.checked, relay.refused)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn simple_verdicts_gate_delivery() {
    let mut h = harness(40, shard_rules()).await;
    let check = TestCheck::new(true, false);
    h.node.set_public_broadcast_check(&h.id, Some(check.clone())).unwrap();
    let empty = OverlayCertificate::Overlay_EmptyCertificate;
    // Authorized source: delivered without an application check.
    let direct = seed_key(DIRECT);
    h.receive(&simple_bytes(&h.overlay, &direct, empty.clone(), 0, b"direct", false), 70)
        .await
        .unwrap();
    assert_eq!(h.delivered(500).await.unwrap().data, b"direct");
    assert_eq!(check.calls(), 0);
    // Unauthorized any-sender source: forbidden, never registered.
    let stranger = seed_key(50);
    let forbidden = simple_bytes(&h.overlay, &stranger, empty.clone(), 1, b"any", false);
    assert!(h.receive(&forbidden, 70).await.is_err());
    assert!(h.delivered(200).await.is_none());
    let id = BroadcastSimpleProtocol::calc_broadcast_id(b"any", &stranger, 1).unwrap();
    assert!(h.overlay.owned_broadcasts.get(&id).is_none());
    // Unauthorized source: delivered only after the application approves.
    h.receive(&simple_bytes(&h.overlay, &stranger, empty.clone(), 0, b"checked", false), 70)
        .await
        .unwrap();
    assert_eq!(h.delivered(500).await.unwrap().data, b"checked");
    assert_eq!(check.calls(), 1);
    // A certificate of an authorized issuer makes the source trusted.
    let cert = h.certificate(&stranger, CERTIFICATE_FLAG_TRUSTED | CERTIFICATE_FLAG_ALLOW_FEC);
    h.receive(&simple_bytes(&h.overlay, &stranger, cert, 1, b"certified", false), 70)
        .await
        .unwrap();
    assert_eq!(h.delivered(500).await.unwrap().data, b"certified");
    assert_eq!(check.calls(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_or_missing_application_check_never_delivers() {
    let mut h = harness(41, shard_rules()).await;
    let stranger = seed_key(51);
    let empty = OverlayCertificate::Overlay_EmptyCertificate;
    // No application check installed: NeedCheck is not success.
    h.receive(&simple_bytes(&h.overlay, &stranger, empty.clone(), 0, b"one", false), 70)
        .await
        .unwrap();
    assert!(h.delivered(300).await.is_none());
    let check = TestCheck::new(false, false);
    h.node.set_public_broadcast_check(&h.id, Some(check.clone())).unwrap();
    h.receive(&simple_bytes(&h.overlay, &stranger, empty.clone(), 0, b"two", false), 70)
        .await
        .unwrap();
    eventually(|| check.calls() == 1).await;
    assert!(h.delivered(300).await.is_none());
    // The refused broadcast stays registered: a second copy is a duplicate.
    h.receive(&simple_bytes(&h.overlay, &stranger, empty, 0, b"two", false), 71).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(check.calls(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_signature_bans_the_relaying_peer() {
    let mut h = harness(42, shard_rules()).await;
    let direct = seed_key(DIRECT);
    let empty = OverlayCertificate::Overlay_EmptyCertificate;
    let bad = simple_bytes(&h.overlay, &direct, empty.clone(), 0, b"bad", true);
    assert!(h.receive(&bad, 72).await.is_err());
    // The refused copy is not registered and the relaying peer is banned.
    let id = BroadcastSimpleProtocol::calc_broadcast_id(b"bad", &direct, 0).unwrap();
    assert!(h.overlay.owned_broadcasts.get(&id).is_none());
    assert!(h.overlay.verifier.is_peer_banned(&KeyId::from_data([72; 32])));
    let good = simple_bytes(&h.overlay, &direct, empty, 0, b"bad", false);
    assert!(h.receive(&good, 72).await.unwrap());
    assert!(h.delivered(300).await.is_none());
    // Another peer relaying the valid copy is unaffected.
    h.receive(&good, 73).await.unwrap();
    assert_eq!(h.delivered(500).await.unwrap().data, b"bad");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn untrusted_fec_parts_are_held_until_the_application_check() {
    let mut h = harness(43, shard_rules()).await;
    let check = TestCheck::new(true, true);
    h.node.set_public_broadcast_check(&h.id, Some(check.clone())).unwrap();
    let stranger = seed_key(52);
    let data: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
    let (id, parts) = fec_parts(
        &h.overlay,
        &stranger,
        OverlayCertificate::Overlay_EmptyCertificate,
        BROADCAST_FLAG_FIXED_NEIGHBOURS,
        &data,
        12,
    );
    let mut sent = 0;
    while check.calls() == 0 {
        h.receive(&parts[sent], 74).await.unwrap();
        sent += 1;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(sent < parts.len(), "decode never requested the check");
    }
    let (held, checked, refused) = held_parts(&h, &id);
    assert_eq!((held, checked, refused), (sent, false, false), "no part relayed before verdict");
    assert!(h.delivered(100).await.is_none(), "no delivery before verdict");
    // A part arriving while the check is outstanding is held as well.
    h.receive(&parts[sent], 74).await.unwrap();
    assert_eq!(held_parts(&h, &id).0, sent + 1);
    check.gate.add_permits(1);
    assert_eq!(h.delivered(1000).await.unwrap().data, data);
    eventually(|| held_parts(&h, &id) == (0, true, false)).await;
    // After approval later untrusted parts relay at once.
    h.receive(&parts[sent + 1], 74).await.unwrap();
    assert_eq!(held_parts(&h, &id), (0, true, false));
    assert_eq!(check.calls(), 1, "completion is checked once");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_fec_broadcast_drops_its_held_parts() {
    let mut h = harness(44, shard_rules()).await;
    let check = TestCheck::new(false, false);
    h.node.set_public_broadcast_check(&h.id, Some(check.clone())).unwrap();
    let stranger = seed_key(53);
    let data: Vec<u8> = (0..3000u32).map(|i| (i * 7) as u8).collect();
    let (id, parts) = fec_parts(
        &h.overlay,
        &stranger,
        OverlayCertificate::Overlay_EmptyCertificate,
        0,
        &data,
        12,
    );
    let mut sent = 0;
    while check.calls() == 0 {
        h.receive(&parts[sent], 75).await.unwrap();
        sent += 1;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(sent < parts.len());
    }
    eventually(|| held_parts(&h, &id) == (0, false, true)).await;
    h.receive(&parts[sent], 75).await.unwrap();
    assert_eq!(held_parts(&h, &id), (0, false, true), "refused broadcasts hold nothing");
    assert!(h.delivered(300).await.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trusted_fec_parts_relay_and_deliver_without_a_check() {
    let mut h = harness(45, shard_rules()).await;
    let check = TestCheck::new(false, false);
    h.node.set_public_broadcast_check(&h.id, Some(check.clone())).unwrap();
    let stranger = seed_key(54);
    let cert = h.certificate(&stranger, CERTIFICATE_FLAG_TRUSTED | CERTIFICATE_FLAG_ALLOW_FEC);
    let data: Vec<u8> = (0..3000u32).map(|i| (i * 3) as u8).collect();
    let (id, parts) = fec_parts(&h.overlay, &stranger, cert, BROADCAST_FLAG_ANY_SENDER, &data, 12);
    for part in &parts {
        h.receive(part, 76).await.unwrap();
    }
    assert_eq!(h.delivered(1000).await.unwrap().data, data);
    assert_eq!(held_parts(&h, &id).0, 0);
    assert_eq!(check.calls(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forbidden_fec_part_creates_no_transfer() {
    let h = harness(46, shard_rules()).await;
    let stranger = seed_key(55);
    let data = vec![9u8; 3000];
    let (id, parts) = fec_parts(
        &h.overlay,
        &stranger,
        OverlayCertificate::Overlay_EmptyCertificate,
        BROADCAST_FLAG_ANY_SENDER,
        &data,
        3,
    );
    h.receive(&parts[0], 77).await.unwrap();
    assert!(h.overlay.owned_broadcasts.get(&id).is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_rules_forbid_fec_until_updated() {
    let h =
        harness(47, OverlayPrivacyRules::with_max_unauthorized_size(MAX_FEC_BROADCAST_SIZE)).await;
    let direct = seed_key(DIRECT);
    let data = vec![1u8; 3000];
    let (id, parts) = fec_parts(
        &h.overlay,
        &direct,
        OverlayCertificate::Overlay_EmptyCertificate,
        BROADCAST_FLAG_ANY_SENDER,
        &data,
        1,
    );
    h.receive(&parts[0], 78).await.unwrap();
    assert!(h.overlay.owned_broadcasts.get(&id).is_none());
    h.node.set_public_privacy_rules(&h.id, shard_rules()).unwrap();
    h.receive(&parts[0], 78).await.unwrap();
    assert!(h.overlay.owned_broadcasts.get(&id).is_some());
}

fn twostep_simple_bytes(
    overlay: &Overlay,
    src: &Arc<dyn KeyOption>,
    certificate: OverlayCertificate,
    data: &[u8],
) -> Vec<u8> {
    let date = Version::get();
    let src_adnl = src.id().clone();
    let id = <BroadcastTwostepSimpleProtocol as BroadcastTwostep>::calc_broadcast_id(
        sha256_digest(data),
        date,
        data.len(),
        data.len(),
        src,
        &src_adnl,
        0,
        &[],
    )
    .unwrap();
    let to_sign = BroadcastTwostepSimpleProtocol::calc_to_sign(id, data).unwrap();
    let bcast = BroadcastTwostepSimple {
        date,
        flags: 0,
        src: src.try_into().unwrap(),
        src_adnl_id: UInt256::from_slice(src_adnl.data()),
        certificate,
        data: data.to_vec(),
        extra: Vec::new(),
        signature: src.sign(&to_sign).unwrap(),
    }
    .into_boxed();
    overlay.serialize_broadcast(&bcast).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn twostep_uses_the_certificate_in_the_message() {
    let mut h = harness(48, shard_rules()).await;
    let check = TestCheck::new(true, true);
    h.node.set_public_broadcast_check(&h.id, Some(check.clone())).unwrap();
    let stranger = seed_key(56);
    // The received certificate makes the source allowed: no check.
    let cert = h.certificate(&stranger, CERTIFICATE_FLAG_TRUSTED | CERTIFICATE_FLAG_ALLOW_FEC);
    h.receive(&twostep_simple_bytes(&h.overlay, &stranger, cert, b"certified"), 79).await.unwrap();
    assert_eq!(h.delivered(500).await.unwrap().data, b"certified");
    assert_eq!(check.calls(), 0);
    // Without it the source needs a check, which gates delivery only.
    let empty = OverlayCertificate::Overlay_EmptyCertificate;
    h.receive(&twostep_simple_bytes(&h.overlay, &stranger, empty, b"plain"), 79).await.unwrap();
    eventually(|| check.calls() == 1).await;
    assert!(h.delivered(200).await.is_none());
    check.gate.add_permits(1);
    assert_eq!(h.delivered(500).await.unwrap().data, b"plain");
    // A certificate without AllowFec is no help: two-step checks as FEC.
    let no_fec = h.certificate(&stranger, CERTIFICATE_FLAG_TRUSTED);
    h.receive(&twostep_simple_bytes(&h.overlay, &stranger, no_fec, b"no-fec"), 79).await.unwrap();
    eventually(|| check.calls() == 2).await;
}

#[test]
fn relayed_simple_envelope_normalizes_the_certificate() {
    let src = seed_key(57);
    let issuer = seed_key(ISSUER);
    let overlay = [5u8; 32];
    let cert = SourceCertificate::sign(&issuer, &overlay, src.id().data(), 2_000_000_000, 4096, 3)
        .unwrap();
    let v2 = rtos_api::ton::overlay::certificate::CertificateV2 {
        issued_by: cert.issuer().clone(),
        expire_at: cert.expire_at(),
        max_size: 4096,
        flags: 3,
        signature: cert.signature().to_vec(),
    }
    .into_boxed();
    let bcast = BroadcastSimple {
        src: (&src).try_into().unwrap(),
        certificate: v2.clone(),
        flags: 0,
        data: b"payload".to_vec(),
        date: 1,
        signature: vec![0; 64],
    };
    let normalized = normalized_certificate(&bcast.certificate).unwrap();
    assert!(matches!(normalized, OverlayCertificate::Overlay_Certificate(_)));
    assert_eq!(normalized, cert.to_tl());
    // A non-default V2 certificate keeps its version.
    let untrusted =
        SourceCertificate::sign(&issuer, &overlay, src.id().data(), 2_000_000_000, 4096, 1)
            .unwrap()
            .to_tl();
    assert!(matches!(
        normalized_certificate(&untrusted).unwrap(),
        OverlayCertificate::Overlay_CertificateV2(_)
    ));
    assert_eq!(
        normalized_certificate(&OverlayCertificate::Overlay_EmptyCertificate).unwrap(),
        OverlayCertificate::Overlay_EmptyCertificate
    );
}

#[test]
fn public_fec_structure_follows_the_peer_limits() {
    let fec = |data_size: i32, symbols: i32| FecTypeRaptorQ {
        data_size,
        symbol_size: 768,
        symbols_count: symbols,
    };
    let message = |data_size: i32, fec_size: i32, seqno: i32| BroadcastFec {
        src: (&seed_key(1)).try_into().unwrap(),
        certificate: OverlayCertificate::Overlay_EmptyCertificate,
        data_hash: UInt256::default(),
        data_size,
        flags: 0,
        data: vec![],
        seqno,
        fec: fec(fec_size, (fec_size + 767) / 768).into_boxed(),
        date: 0,
        signature: vec![],
    };
    assert!(OverlayNode::check_public_fec_broadcast_message(&message(3000, 3000, 11)).is_ok());
    // seqno < symbols * 2 + 4
    assert!(OverlayNode::check_public_fec_broadcast_message(&message(3000, 3000, 12)).is_err());
    assert!(OverlayNode::check_public_fec_broadcast_message(&message(3000, 2999, 0)).is_err());
    let max = MAX_FEC_BROADCAST_SIZE as i32;
    assert!(OverlayNode::check_public_fec_broadcast_message(&message(max, max, 0)).is_ok());
    assert!(OverlayNode::check_public_fec_broadcast_message(&message(max + 1, max + 1, 0)).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outstanding_application_checks_are_bounded() {
    let policy = super::super::privacy::PublicBroadcastPolicy::new(shard_rules());
    let check = TestCheck::new(true, true);
    policy.set_check(Some(check.clone())).unwrap();
    let policy = Arc::new(policy);
    let source = KeyId::from_data([1; 32]);
    let mut waiting = Vec::new();
    for _ in 0..super::super::privacy::MAX_PENDING_APPLICATION_CHECKS {
        let policy = policy.clone();
        let source = source.clone();
        waiting.push(tokio::spawn(async move { policy.check(&source, b"x").await }));
    }
    eventually(|| {
        policy.outstanding_checks() == super::super::privacy::MAX_PENDING_APPLICATION_CHECKS
    })
    .await;
    assert!(policy.check(&source, b"x").await.is_err(), "one past the bound is refused");
    check.gate.add_permits(1 << 20);
    for task in waiting {
        assert!(task.await.unwrap().is_ok());
    }
    assert_eq!(policy.outstanding_checks(), 0);
}
