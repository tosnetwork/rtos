/*
 * RTOS project modifications (2026-10-10): project naming and authenticated Plumtree transport dispatch; explicit target wire profile integration; owned consumer readiness and authenticated finality recovery.
 * Copyright (C) 2019-2023 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::{
    adnl::tasks::AdnlTasks,
    common::{
        add_counted_object_to_map, add_counted_object_to_map_with_update,
        add_unbound_object_to_map_with_update, hash, hash_boxed, AdnlPeers, AsyncReceiver,
        CountedObject, Counter, Query, QueryAnswer, QueryResult, Subscriber, TaggedByteSlice,
        TaggedTlObject, Version,
    },
    declare_counted,
    node::{AddressCache, AddressCacheWithBads, AdnlNode, AdnlSendMethod, BadPolicy, IpAddress},
    quic::QuicNode,
    rldp::{Constraints, RldpNode},
};
#[cfg(feature = "telemetry")]
use crate::{common::add_unbound_object_to_map, telemetry::Metric};
use num_traits::pow::Pow;
use rtos_api::{
    deserialize_boxed, deserialize_boxed_with_suffix, serialize_boxed, serialize_boxed_append,
    ton::{
        adnl::id::short::Short as AdnlShortId,
        catchain::{
            block::inner::{
                catchain::block::data::data::Fork as CatchainFork,
                Data as CatchainBlockInnerDataBoxed,
            },
            blockupdate::BlockUpdate as CatchainBlockUpdate,
            FirstBlock as CatchainFirstBlock, Update as CatchainBlockUpdateBoxed,
        },
        fec::Type as FecType,
        overlay::{
            broadcast::BroadcastFec,
            membercertificate::MemberCertificate,
            membercertificateid::MemberCertificateId,
            message::{Message as OverlayMessage, MessageWithExtra as OverlayMessageWithExtra},
            messageextra::MessageExtra,
            node::{tosign::ToSign as NodeToSign, Node as NodeV1, ToSign as NodeToSignBoxed},
            nodes::Nodes as NodesV1,
            nodesv2::NodesV2,
            nodev2::NodeV2,
            Broadcast, Certificate as OverlayCertificateTl,
            MemberCertificate as MemberCertificateBoxed, Message as OverlayMessageBoxed,
            Nodes as NodesV1Boxed, NodesV2 as NodesV2Boxed, Pong,
        },
        pub_::publickey::Overlay as OverlayKey,
        rpc::overlay::{
            GetRandomPeers, GetRandomPeersV2, Ping, Query as OverlayQuery,
            QueryWithExtra as OverlayQueryWithExtra,
        },
        ton_node::{
            customoverlayid::CustomOverlayId, fastsyncoverlayid::FastSyncOverlayId,
            shardid::ShardId as TonNodeShardId, shardpublicoverlayid::ShardPublicOverlayId,
        },
        validator_session::{
            blockupdate::BlockUpdate as ValidatorSessionBlockUpdate,
            BlockUpdate as ValidatorSessionBlockUpdateBoxed,
        },
        PublicKey,
    },
    AnyBoxedSerialize, IntoBoxed, TLObject,
};
#[cfg(feature = "telemetry")]
use rtos_api::{BoxedSerialize, Constructor};
use rtos_block::{base64_encode, error, fail, KeyId, KeyOption, Result, UInt256, UnixTime};
use std::{
    borrow::Borrow,
    cmp::min,
    collections::{HashMap, HashSet},
    convert::TryInto,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc, OnceLock,
    },
    time::{Duration, Instant},
};

mod broadcast;
mod clock;
#[cfg(test)]
mod transport_tests;
pub use clock::{BroadcastClock, SystemBroadcastClock};
mod transport;
pub use transport::{BroadcastTransportMethod, FixedMemberOverlayOptions, OverlayBroadcastTransport};
mod plumtree;
mod privacy;
use broadcast::{
    BroadcastData, BroadcastFecProtocol, BroadcastId, BroadcastProtocol, BroadcastRecvContext,
    BroadcastSendContext, BroadcastSendMethod, BroadcastSimpleProtocol,
    BroadcastStreamSimpleProtocol, BroadcastTwostepFecProtocol, BroadcastTwostepSimpleProtocol,
    OwnedBroadcast,
};
pub use broadcast::{BroadcastRecvInfo, BroadcastSendInfo};
pub use privacy::{
    BroadcastCheckResult, OverlayCertificate, OverlayPrivacyRules, PublicBroadcastCheck,
    BROADCAST_FLAG_ANY_SENDER, BROADCAST_FLAG_FIXED_NEIGHBOURS, CERTIFICATE_FLAG_ALLOW_FEC,
    CERTIFICATE_FLAG_TRUSTED, MAX_FEC_BROADCAST_SIZE, MAX_SIMPLE_BROADCAST_SIZE,
};

/// Owned readiness lease for one concrete overlay generation. Dropping it
/// closes bounded broadcast admission; recreating an overlay creates a new queue.
pub struct BroadcastSubscription {
    receiver: Arc<AsyncReceiver<BroadcastRecvInfo>>,
    overlay_id: Arc<OverlayShortId>,
}
impl BroadcastSubscription {
    pub fn overlay_id(&self) -> &Arc<OverlayShortId> {
        &self.overlay_id
    }
    pub async fn recv(&mut self) -> Result<Option<BroadcastRecvInfo>> {
        self.receiver.pop_subscribed().await
    }
}
impl Drop for BroadcastSubscription {
    fn drop(&mut self) {
        self.receiver.release_subscription();
    }
}

pub use plumtree::PlumtreeConfig;
pub mod records;

const TARGET: &str = "overlay";
const TARGET_BROADCAST: &str = "overlay_broadcast";

/*
pub fn build_overlay_node_info(
    overlay: &Arc<OverlayShortId>,
    version: i32,
    key: &str,
    signature: &str
) -> Result<Node<NodeV1, NodeV2Boxed>> {
    let key = base64_decode(key)?;
    if key.len() != 32 {
        fail!("Bad public key length")
    }
    let key: [u8; 32] = key.as_slice().try_into()?;
    let signature = base64_decode(signature)?;
    let node = NodeV1 {
        id: Ed25519 {
            key: UInt256::with_array(key)
        }.into_boxed(),
        overlay: UInt256::with_array(*overlay.data()),
        version,
        signature: signature.into(),
    };
    Ok(Node::V1(node))
}
*/

pub enum CatchainData {
    Catchain(CatchainFork),
    ValidatorSession(ValidatorSessionBlockUpdate),
}

pub type OverlayId = [u8; 32];

#[derive(Debug)]
pub enum OverlayNodeInfo<N1: Borrow<NodeV1>, N2: Borrow<NodeV2>> {
    V1(N1),
    V2(N2),
}

impl<N1: Borrow<NodeV1>, N2: Borrow<NodeV2>> OverlayNodeInfo<N1, N2> {
    pub fn id(&self) -> &PublicKey {
        match self {
            OverlayNodeInfo::V1(node) => &node.borrow().id,
            OverlayNodeInfo::V2(node) => &node.borrow().id,
        }
    }
    pub fn version(&self) -> i32 {
        match self {
            OverlayNodeInfo::V1(node) => node.borrow().version,
            OverlayNodeInfo::V2(node) => node.borrow().version,
        }
    }
    pub fn signature(&self) -> &[u8] {
        match self {
            OverlayNodeInfo::V1(node) => &node.borrow().signature,
            OverlayNodeInfo::V2(node) => &node.borrow().signature,
        }
    }
    pub fn to_owned(&self) -> OverlayNodeInfo<NodeV1, NodeV2> {
        match self {
            OverlayNodeInfo::V1(node) => OverlayNodeInfo::V1(node.borrow().clone()),
            OverlayNodeInfo::V2(node) => OverlayNodeInfo::V2(node.borrow().clone()),
        }
    }
    pub fn key(&self) -> Result<Arc<dyn KeyOption>> {
        match self {
            OverlayNodeInfo::V1(node) => node.borrow().get_key(),
            OverlayNodeInfo::V2(node) => node.borrow().get_key(),
        }
    }
}

pub type OverlayShortId = KeyId;
pub type PrivateOverlayShortId = KeyId;

/// Broadcast auth hooks for a private overlay (C++ `OverlayPrivacyRules`).
pub trait BroadcastCheck: Send + Sync {
    fn on_send(&self, src: &Arc<KeyId>, payload_size: usize) -> Result<()>;
    fn on_recv(&self, src: &Arc<KeyId>, extra: Option<&[u8]>) -> Result<()>;
}

/// Overlay utilities
pub struct OverlayUtils;

impl OverlayUtils {
    /// Calculate overlay full ID for public shard overlay
    /// SHA256(TL(tonNode.shardPublicOverlayId))
    pub fn calc_overlay_id(
        workchain: i32,
        shard: i64,
        zero_state_file_hash: &[u8; 32],
    ) -> Result<OverlayId> {
        Self::calc_overlay_id_with_profile(
            workchain,
            shard,
            zero_state_file_hash,
            rtos_api::WireProfile::Legacy,
        )
    }

    pub fn calc_overlay_id_with_profile(
        workchain: i32,
        shard: i64,
        zero_state_file_hash: &[u8; 32],
        profile: rtos_api::WireProfile,
    ) -> Result<OverlayId> {
        let overlay = ShardPublicOverlayId {
            shard,
            workchain,
            zero_state_file_hash: UInt256::with_array(*zero_state_file_hash),
        };
        Ok(*UInt256::calc_file_hash(&profile.serialize(&overlay.into_boxed())?).as_array())
    }

    /// Calculate overlay short ID for public shard overlay
    /// SHA256(TL(pub.overlay { name: SHA256(TL(tonNode.shardPublicOverlayId)) }))
    pub fn calc_overlay_short_id(
        workchain: i32,
        shard: i64,
        zero_state_file_hash: &[u8; 32],
    ) -> Result<Arc<OverlayShortId>> {
        Self::calc_overlay_short_id_with_profile(
            workchain,
            shard,
            zero_state_file_hash,
            rtos_api::WireProfile::Legacy,
        )
    }

    pub fn calc_overlay_short_id_with_profile(
        workchain: i32,
        shard: i64,
        zero_state_file_hash: &[u8; 32],
        profile: rtos_api::WireProfile,
    ) -> Result<Arc<OverlayShortId>> {
        let overlay_key = OverlayKey {
            name: Self::calc_overlay_id_with_profile(
                workchain,
                shard,
                zero_state_file_hash,
                profile,
            )?
            .to_vec(),
        };
        Ok(OverlayShortId::from_data(hash(overlay_key)?))
    }

    /// Calculate overlay short ID for catchain private overlay
    /// SHA256(TL(pub.overlay { name: SHA256(TL(catchain.firstblock)) }))
    pub fn calc_private_overlay_short_id(
        first_block: &CatchainFirstBlock,
    ) -> Result<Arc<PrivateOverlayShortId>> {
        let serialized_first_block = serialize_boxed(first_block)?;
        let overlay_key = OverlayKey { name: serialized_first_block.into() };
        Ok(PrivateOverlayShortId::from_data(hash_boxed(&overlay_key.into_boxed())?))
    }

    /// Calculate overlay short ID for custom overlay
    /// SHA256(TL(pub.overlay { name: SHA256(TL(tonNode.customOverlayId)) }))
    pub fn calc_custom_overlay_short_id(
        zero_state_file_hash: &[u8; 32],
        name: &str,
        nodes: &[[u8; 32]],
    ) -> Result<Arc<OverlayShortId>> {
        let mut sorted: Vec<UInt256> = nodes.iter().map(|n| UInt256::with_array(*n)).collect();
        sorted.sort();
        sorted.dedup();
        let id = CustomOverlayId {
            zero_state_file_hash: UInt256::with_array(*zero_state_file_hash),
            name: name.to_string().into(),
            nodes: sorted.into_iter().collect(),
        };
        let overlay_key = OverlayKey { name: hash(id)?.to_vec() };
        Ok(OverlayShortId::from_data(hash(overlay_key)?))
    }

    /// Calculate overlay short ID for fast sync overlay
    /// SHA256(TL(pub.overlay { name: SHA256(TL(tonNode.fastSyncOverlayId)) }))
    pub fn calc_fast_sync_overlay_short_id(
        zero_state_file_hash: &[u8; 32],
        workchain: i32,
        shard: i64,
    ) -> Result<Arc<OverlayShortId>> {
        let id = FastSyncOverlayId {
            zero_state_file_hash: UInt256::with_array(*zero_state_file_hash),
            shard: TonNodeShardId { workchain, shard },
        };
        let overlay_key = OverlayKey { name: hash(id)?.to_vec() };
        Ok(OverlayShortId::from_data(hash(overlay_key)?))
    }

    /// Verify node info
    pub(crate) fn verify_node<T: NodeData>(
        overlay_id: &Arc<OverlayShortId>,
        node: &T,
    ) -> Result<()> {
        if !records::MemberFlags::valid(node.flags() as u32) {
            fail!("Unsupported overlay member flags {}", node.flags())
        }
        let key: Arc<dyn KeyOption> = node.get_key()?;
        if node.overlay().as_slice() != overlay_id.data() {
            fail!(
                "Got peer {} with wrong overlay {}, expected {overlay_id}",
                key.id(),
                base64_encode(node.overlay().as_slice())
            )
        }
        let to_sign = Self::get_node_to_sign(&key, node.overlay(), node.flags(), node.version());
        if let Err(e) = key.verify(&serialize_boxed(&to_sign)?, node.signature()) {
            fail!("Got peer {} with bad signature: {}", key.id(), e)
        }
        Ok(())
    }

    fn calc_message_prefix(overlay_id: &OverlayShortId) -> Result<Vec<u8>> {
        serialize_boxed(
            &OverlayMessage { overlay: UInt256::with_array(*overlay_id.data()) }.into_boxed(),
        )
    }

    fn get_node_to_sign(
        key: &Arc<dyn KeyOption>,
        overlay_id: &UInt256,
        flags: i32,
        version: i32,
    ) -> NodeToSignBoxed {
        let id = AdnlShortId { id: UInt256::with_array(*key.id().data()) };
        NodeToSign { flags, id, overlay: overlay_id.clone(), version }.into_boxed()
    }
}

type CatchainReceiver = AsyncReceiver<(CatchainBlockUpdate, CatchainData, Arc<KeyId>)>;

pub(crate) trait NodeData {
    fn flags(&self) -> i32;
    fn get_key(&self) -> Result<Arc<dyn KeyOption>>;
    fn overlay(&self) -> &UInt256;
    fn signature(&self) -> &[u8];
    fn version(&self) -> i32;
}

impl NodeData for NodeV1 {
    fn flags(&self) -> i32 {
        self.flags
    }
    fn get_key(&self) -> Result<Arc<dyn KeyOption>> {
        (&self.id).try_into()
    }
    fn overlay(&self) -> &UInt256 {
        &self.overlay
    }
    fn signature(&self) -> &[u8] {
        &self.signature
    }
    fn version(&self) -> i32 {
        self.version
    }
}

impl NodeData for NodeV2 {
    fn flags(&self) -> i32 {
        self.flags
    }
    fn get_key(&self) -> Result<Arc<dyn KeyOption>> {
        (&self.id).try_into()
    }
    fn overlay(&self) -> &UInt256 {
        &self.overlay
    }
    fn signature(&self) -> &[u8] {
        &self.signature
    }
    fn version(&self) -> i32 {
        self.version
    }
}

declare_counted!(
    struct NodeObject {
        v1: Option<Arc<NodeV1>>,
        v2: Option<Arc<NodeV2>>,
    }
);

impl NodeObject {
    fn advertisement(&self) -> Option<(i32, i32, &MemberCertificateBoxed)> {
        self.v1
            .iter()
            .map(|node| (node.flags, node.version, &node.certificate))
            .chain(self.v2.iter().map(|node| (node.flags, node.version, &node.certificate)))
            .max_by_key(|(_, version, _)| *version)
    }
}

enum Nodes {
    V1(NodesV1),
    V2(NodesV2),
}

struct SlaveInfo {
    node_id: Arc<KeyId>,
    expire_at: u32, // utime in seconds
}

enum OverlayType {
    Public,
    // Overlay with fixed members set; optional broadcast auth via BroadcastCheck
    Private {
        key: Arc<dyn KeyOption>,
        use_quic: bool,
        bcast_check: Option<Arc<dyn BroadcastCheck>>,
        fixed_member_list: bool,
        twostep_enabled: bool,
    },
    // Overlay with externally certified members
    CertifiedMembers {
        // Prefix to use in broadcasts instead of Overlay::message_prefix
        bcast_prefix: Vec<u8>,
        certificate: Option<MemberCertificate>,
        key: Option<Arc<dyn KeyOption>>,
        max_slaves: usize,
        // Validator ADNL IDs, bypassing the certificate check
        root_adnl_ids: HashSet<Arc<KeyId>>,
        // Validator Signing KeyId -> (Slot -> SlaveInfo)
        root_public_keys: HashMap<Arc<KeyId>, lockfree::map::Map<u32, SlaveInfo>>,
        use_quic: bool,
    },
}

impl OverlayType {
    fn bcast_prefix(&self) -> Option<Vec<u8>> {
        match self {
            OverlayType::CertifiedMembers { bcast_prefix, .. } => Some(bcast_prefix.clone()),
            OverlayType::Public | OverlayType::Private { .. } => None,
        }
    }

    fn quic_requested(&self) -> bool {
        matches!(
            self,
            OverlayType::Private { use_quic: true, .. }
                | OverlayType::CertifiedMembers { use_quic: true, .. }
        )
    }

    fn calc_message_prefix(&self, overlay_id: &OverlayShortId) -> Result<Vec<u8>> {
        match self {
            Self::CertifiedMembers { certificate, .. } => serialize_boxed(
                &OverlayMessageWithExtra {
                    overlay: UInt256::with_array(*overlay_id.data()),
                    extra: MessageExtra {
                        certificate: certificate.as_ref().map(|cert| cert.clone().into_boxed()),
                    },
                }
                .into_boxed(),
            ),
            OverlayType::Public | OverlayType::Private { .. } => {
                OverlayUtils::calc_message_prefix(overlay_id)
            }
        }
    }

    fn calc_query_prefix(&self, overlay_id: &OverlayShortId) -> Result<Vec<u8>> {
        match self {
            Self::CertifiedMembers { certificate, .. } => serialize_boxed(&OverlayQueryWithExtra {
                overlay: UInt256::with_array(*overlay_id.data()),
                extra: MessageExtra {
                    certificate: certificate.as_ref().map(|cert| cert.clone().into_boxed()),
                },
            }),
            OverlayType::Public | OverlayType::Private { .. } => {
                serialize_boxed(&OverlayQuery { overlay: UInt256::with_array(*overlay_id.data()) })
            }
        }
    }

    fn certificate(&self) -> Option<&MemberCertificate> {
        match self {
            OverlayType::CertifiedMembers { certificate, .. } => certificate.as_ref(),
            OverlayType::Public | OverlayType::Private { .. } => None,
        }
    }

    fn is_public(&self) -> bool {
        matches!(self, OverlayType::Public)
    }

    fn is_private(&self) -> bool {
        matches!(self, OverlayType::Private { .. })
    }

    fn is_fixed_member_list(&self) -> bool {
        matches!(self, OverlayType::Private { fixed_member_list: true, .. })
    }

    fn twostep_sender_enabled(&self) -> bool {
        matches!(self, Self::Private { fixed_member_list: true, twostep_enabled: true, .. })
    }

    fn accepts_twostep(&self) -> bool {
        !self.is_fixed_member_list() || self.twostep_sender_enabled()
    }

    fn has_certified_members(&self) -> bool {
        matches!(self, OverlayType::CertifiedMembers { .. })
    }
}

#[cfg(feature = "telemetry")]
declare_counted!(
    struct PeerStats {
        count: AtomicU64,
    }
);

struct OverlayAlloc {
    consumers: Arc<AtomicU64>,
    overlays: Arc<AtomicU64>,
    peers: Arc<AtomicU64>,
    recv_transfers: Arc<AtomicU64>,
    send_transfers: Arc<AtomicU64>,
    #[cfg(feature = "telemetry")]
    stats_peer: Arc<AtomicU64>,
    #[cfg(feature = "telemetry")]
    stats_transfer: Arc<AtomicU64>,
}

#[cfg(feature = "telemetry")]
struct OverlayTelemetry {
    consumers: Arc<Metric>,
    overlays: Arc<Metric>,
    peers: Arc<Metric>,
    recv_transfers: Arc<Metric>,
    send_transfers: Arc<Metric>,
    stats_peer: Arc<Metric>,
    stats_transfer: Arc<Metric>,
}

#[cfg(feature = "telemetry")]
declare_counted!(
    struct TransferStats {
        income: AtomicU64,
        passed: AtomicU64,
        resent: AtomicU64,
    }
);

declare_counted!(
    struct Overlay {
        consumer: OnceLock<Arc<dyn Subscriber>>,
        tasks: Arc<AdnlTasks>,
        inbound_caps: Arc<std::sync::Mutex<Vec<Arc<KeyId>>>>,
        adnl: Arc<AdnlNode>,
        quic: Option<Arc<QuicNode>>,
        rldp: Option<Arc<RldpNode>>,
        options: Arc<AtomicU32>,
        overlay_type: OverlayType,
        wire_profile: rtos_api::WireProfile,
        clock: Arc<dyn BroadcastClock>,
        broadcast_transport: Option<Arc<dyn OverlayBroadcastTransport>>,
        flags: u8,
        hops: Option<u8>,
        // All known peers in overlay (for private overlay - all peers except ourself)
        known_peers: AddressCacheWithBads,
        message_prefix: Vec<u8>,
        // Subset of `known_peers`. Active peers. Used for pings and queries
        neighbours: AddressCache,
        // Info about all known peers. Used for `GetRandomPeers`
        nodes: lockfree::map::Map<Arc<KeyId>, NodeObject>,
        overlay_id: Arc<OverlayShortId>,
        owned_broadcasts: lockfree::map::Map<BroadcastId, OwnedBroadcast>,
        plumtree: OnceLock<PlumtreeTransport>,
        // Configured overlay.node member flags of this node, and the flags
        // assumed for a permanent member that has not advertised itself
        member_flags: AtomicU32,
        permanent_member_flags: AtomicU32,
        // Common broadcast verifier: issuer limiters and signature rejections
        verifier: Arc<privacy::BroadcastVerifier>,
        // Explicit privacy rules of a public overlay; none keeps the overlay
        // without source authorization
        public_policy: Option<privacy::PublicBroadcastPolicy>,
        // Certificates attached to broadcasts sent with each local source key
        certificates: std::sync::RwLock<HashMap<Arc<KeyId>, OverlayCertificate>>,
        // Peers waiting for ADNL address resolution before being added to known_peers
        pending_peers: lockfree::queue::Queue<Arc<KeyId>>,
        purge_broadcasts: lockfree::queue::Queue<BroadcastId>,
        purge_broadcasts_count: AtomicU32,
        queue_one_time_broadcasts: tokio::sync::mpsc::UnboundedSender<(BroadcastId, Instant)>,
        #[cfg(feature = "xp25")]
        queue_repeated_broadcasts: tokio::sync::mpsc::UnboundedSender<(BroadcastId, Instant)>,
        query_prefix: Vec<u8>,
        // random_peers: AddressCache
        received_catchain: Option<Arc<CatchainReceiver>>,
        received_peers: Arc<AsyncReceiver<Vec<OverlayNodeInfo<NodeV1, NodeV2>>>>,
        received_rawbytes: Arc<AsyncReceiver<BroadcastRecvInfo>>,
        #[cfg(feature = "telemetry")]
        messages_recv: AtomicU64,
        #[cfg(feature = "telemetry")]
        messages_send: AtomicU64,
        #[cfg(feature = "telemetry")]
        print: AtomicU64,
        #[cfg(feature = "telemetry")]
        start: Instant,
        #[cfg(feature = "telemetry")]
        stats_per_peer_recv: lockfree::map::Map<Arc<KeyId>, lockfree::map::Map<u32, PeerStats>>,
        #[cfg(feature = "telemetry")]
        stats_per_peer_send: lockfree::map::Map<Arc<KeyId>, lockfree::map::Map<u32, PeerStats>>,
        #[cfg(feature = "telemetry")]
        stats_per_transfer: lockfree::map::Map<BroadcastId, Arc<TransferStats>>,
        #[cfg(feature = "telemetry")]
        telemetry: Arc<OverlayTelemetry>,
        allocated: Arc<OverlayAlloc>,
        // For debug
        debug_trace: AtomicU32,
    }
);

impl Overlay {
    fn broadcast_time(&self) -> i32 {
        self.clock.unix_seconds() as u32 as i32
    }

    const MEMBER_DO_NOT_RECEIVE_BROADCASTS: u32 = OverlayNode::MEMBER_DO_NOT_RECEIVE_BROADCASTS;
    const MEMBER_DO_NOT_RECEIVE_PLUMTREE: u32 = OverlayNode::MEMBER_DO_NOT_RECEIVE_PLUMTREE;
    const MEMBER_PLUMTREE_DENY: u32 =
        Self::MEMBER_DO_NOT_RECEIVE_BROADCASTS | Self::MEMBER_DO_NOT_RECEIVE_PLUMTREE;

    /// The member flags this node signs into its overlay.node, as the
    /// reference overlay computes them: a public overlay adds "no Plumtree"
    /// when Plumtree is off or this node is an original sender; any other
    /// overlay signs its configured flags.
    fn local_member_flags(&self) -> u32 {
        let configured = self.member_flags.load(Ordering::Relaxed);
        if !self.overlay_type.is_public() {
            return configured;
        }
        records::MemberFlags::public_flags(
            configured,
            self.plumtree.get().is_some(),
            self.plumtree.get().is_some_and(|p| p.original_sender),
        )
    }

    const FLAG_OVERLAY_OTHER_WORKCHAIN: u8 = 0x01;
    const MAX_HOPS: u8 = 15;
    const MAX_BROADCAST_LOG: u32 = 1000;
    const MAX_RANDOM_PEERS: u32 = 4;
    const OPTION_DISABLE_BROADCAST_RETRANSMIT: u32 = 0x01;
    const SIZE_NEIGHBOURS_LONG_BROADCAST: u8 = 5;
    const SIZE_NEIGHBOURS_SHORT_BROADCAST: u8 = 3;
    const SIZE_NEIGHBOURS_STREAM_BROADCAST: u8 = 20;
    const TIMEOUT_ONE_TIME_BROADCAST_SEC: u64 = 60;
    #[cfg(feature = "xp25")]
    const TIMEOUT_REPEATED_BROADCAST_SEC: u64 = 2;

    /// Source verdict for a received broadcast relayed by `from`. Overlays
    /// without privacy rules keep their own authorization: every source is
    /// allowed here.
    pub(crate) fn broadcast_verdict(
        &self,
        source: &Arc<dyn KeyOption>,
        certificate: &OverlayCertificateTl,
        size: usize,
        is_fec: bool,
        is_any_sender: bool,
        from: &Arc<KeyId>,
    ) -> BroadcastCheckResult {
        let Some(policy) = &self.public_policy else {
            return BroadcastCheckResult::Allowed;
        };
        let Ok(size) = u32::try_from(size) else {
            return BroadcastCheckResult::Forbidden;
        };
        let Ok(certificate) = OverlayCertificate::from_tl(certificate) else {
            return BroadcastCheckResult::Forbidden;
        };
        self.verifier.check_source_eligible_at(
            &policy.rules(),
            self.overlay_type.is_private(),
            self.overlay_id.data(),
            source.id().data(),
            certificate.as_ref(),
            size,
            is_fec,
            is_any_sender,
            Some(from),
            self.broadcast_time(),
            Instant::now(),
        )
    }

    pub(crate) fn has_public_policy(&self) -> bool {
        self.public_policy.is_some()
    }

    /// Certificate this overlay attaches to broadcasts sent as `source`.
    pub(crate) fn local_certificate(&self, source: &Arc<KeyId>) -> Option<OverlayCertificate> {
        self.certificates.read().ok().and_then(|certs| certs.get(source).cloned())
    }

    /// Sender admission of an ordinary broadcast: `Forbidden` is refused,
    /// `NeedCheck` passes the application check here unless local protocol
    /// processing owns that check together with delivery and propagation.
    async fn admit_ordinary_send(
        &self,
        source: &Arc<dyn KeyOption>,
        certificate: Option<&OverlayCertificate>,
        data: &[u8],
        is_fec: bool,
        is_any_sender: bool,
        check_in_local_protocol: bool,
    ) -> Result<()> {
        let Some(policy) = &self.public_policy else {
            return Ok(());
        };
        let size = u32::try_from(data.len()).map_err(|_| error!("Broadcast is too large"))?;
        let verdict = self.verifier.check_source_eligible_at(
            &policy.rules(),
            self.overlay_type.is_private(),
            self.overlay_id.data(),
            source.id().data(),
            certificate,
            size,
            is_fec,
            is_any_sender,
            None,
            self.broadcast_time(),
            Instant::now(),
        );
        match verdict {
            BroadcastCheckResult::Allowed => Ok(()),
            BroadcastCheckResult::NeedCheck if check_in_local_protocol => Ok(()),
            BroadcastCheckResult::NeedCheck => policy.check(source.id(), data).await,
            BroadcastCheckResult::Forbidden => {
                fail!(
                    "Broadcast source {} is forbidden in overlay {}",
                    source.id(),
                    self.overlay_id
                )
            }
        }
    }

    /// Application approval of a `NeedCheck` broadcast; refused when the
    /// overlay has no application check.
    pub(crate) async fn application_check(&self, source: &Arc<KeyId>, data: &[u8]) -> Result<()> {
        let Some(policy) = &self.public_policy else {
            fail!("Overlay {} has no application broadcast check", self.overlay_id);
        };
        policy.check(source, data).await
    }

    /// Broadcast signature check through the common verifier: a bad
    /// signature refuses the relaying peer for a short time.
    pub(crate) fn verify_broadcast_signature(
        &self,
        key: &Arc<dyn KeyOption>,
        message: &[u8],
        signature: &[u8],
        from: &Arc<KeyId>,
    ) -> Result<()> {
        self.verifier.check_signature_from_peer(key, message, signature, Some(from))
    }

    pub(crate) fn calc_broadcast_neighbours(
        &self,
        hops: Option<u8>,
        default_neighbours: u8,
    ) -> Result<(Option<u8>, u32)> {
        if let Some(mut hops) = hops {
            let initial = (hops >> 4) == 0;
            if initial {
                hops |= hops << 4;
            }
            let hops_org = hops >> 4;
            let hops_cur = hops & 0x0F;
            if hops_org > Overlay::MAX_HOPS {
                fail!("Too big hops count requested ({hops_org})")
            }
            if (hops_cur > hops_org) || (hops_cur <= 1) {
                fail!("Bad hops counter ({hops:x}), initial {initial}")
            }
            // Heuristics with zero loss, where n is the number of nodes in network
            // M3(n) = 3.42 * n^0.287
            // M4(n) = 3.86 * n^0.181
            let n = self.known_peers.all().count() as f64;
            let n = if hops_org <= 3 {
                (n.pow(0.287f64) * 3.42f64).ceil() as u32
            } else {
                (n.pow(0.181f64) * 3.86f64).ceil() as u32
            };
            if n > self.neighbours.count() {
                if initial {
                    if hops_org < Overlay::MAX_HOPS {
                        hops = ((hops_org + 1) << 4) | (hops_org + 1)
                    }
                    Ok((Some(hops), default_neighbours as u32))
                } else {
                    Ok((None, default_neighbours as u32))
                }
            } else {
                if !initial {
                    hops -= 1;
                }
                Ok((Some(hops), n))
            }
        } else {
            Ok((None, default_neighbours as u32))
        }
    }

    pub(crate) fn select_broadcast_neighbours(
        &self,
        count: u32,
        skip: Option<&Arc<KeyId>>,
    ) -> Vec<Arc<KeyId>> {
        self.neighbours.random_vec(skip, count)
    }

    pub(crate) fn select_broadcast_twostep_neighbours(
        &self,
        skip: Option<&Arc<KeyId>>,
    ) -> Vec<Arc<KeyId>> {
        let root_adnl_ids = match &self.overlay_type {
            OverlayType::CertifiedMembers { root_adnl_ids, .. } => Some(root_adnl_ids),
            // Private overlays: iterate all known_peers
            OverlayType::Private { .. } => None,
            OverlayType::Public => {
                let mut neighbours = Vec::new();
                let (mut iter, mut neighbour) = self.neighbours.first();
                while let Some(node) = neighbour {
                    let skipped = skip.map_or(false, |skip| &node == skip);
                    if !skipped {
                        neighbours.push(node);
                    }
                    neighbour = self.neighbours.next(&mut iter);
                }
                return neighbours;
            }
        };
        let mut neighbours = Vec::new();
        let mut iter = None;
        let mut neighbour = self.known_peers.next(&mut iter);
        while let Some(node) = neighbour {
            let skipped = skip.map_or(false, |skip| &node == skip);
            // Skip CertifiedMembers: only send twostep to root members (validators).
            let root = root_adnl_ids.map_or(true, |roots| roots.contains(&node));
            if !skipped && root {
                neighbours.push(node);
            }
            neighbour = self.known_peers.next(&mut iter);
        }
        if self.wire_profile == rtos_api::WireProfile::T0 {
            // CPP iterates its peer DecTree in key order when assigning parts.
            neighbours.sort_unstable_by(|a, b| a.data().cmp(b.data()));
        }
        neighbours
    }

    pub(crate) fn serialize_broadcast(&self, bcast: &Broadcast) -> Result<Vec<u8>> {
        // In semi-private overlays we use special message prefix (without certificate)
        let mut buf = self.overlay_type.bcast_prefix().unwrap_or(self.message_prefix.clone());
        serialize_boxed_append(&mut buf, bcast)?;
        Ok(buf)
    }

    fn calc_broadcast_twostep_neighbours(&self) -> u32 {
        let root_adnl_ids = match &self.overlay_type {
            OverlayType::CertifiedMembers { root_adnl_ids, .. } => Some(root_adnl_ids),
            // Private overlays: count all known_peers
            OverlayType::Private { .. } => None,
            OverlayType::Public => return self.neighbours.count(),
        };
        let mut count = 0u32;
        let mut iter = None;
        let mut neighbour = self.known_peers.next(&mut iter);
        while let Some(node) = neighbour {
            if root_adnl_ids.map_or(true, |root_adnl_ids| root_adnl_ids.contains(&node)) {
                count += 1;
            }
            neighbour = self.known_peers.next(&mut iter);
        }
        count
    }

    fn check_peer(&self, peer: &Arc<KeyId>, certificate: Option<&MemberCertificate>) -> Result<()> {
        match &self.overlay_type {
            OverlayType::Public => Ok(()),
            OverlayType::Private { key, .. } => {
                if !(peer == key.id() || self.known_peers.all().contains(peer)) {
                    fail!("Peer {peer} is not a member of the private overlay {}", self.overlay_id)
                }
                Ok(())
            }
            OverlayType::CertifiedMembers { root_adnl_ids, .. } => {
                if root_adnl_ids.contains(peer) {
                    return Ok(());
                }
                // Bcasts are sent without a certificate, hoping the target already knows
                // the sender's one.
                if let Some(guard) = self.nodes.get(peer) {
                    if let Some((_, _, certificate)) = guard.val().advertisement() {
                        let MemberCertificateBoxed::Overlay_MemberCertificate(cert) = certificate
                        else {
                            fail!(
                                "Empty certificate for known peer {peer} in overlay {}",
                                self.overlay_id
                            )
                        };
                        return self.validate_certificate(peer, cert).map_err(|e| {
                            error!(
                                "Certificate validation for known peer {peer} in overlay {}: {e}",
                                self.overlay_id
                            )
                        });
                    }
                }
                let Some(certificate) = certificate else {
                    fail!(
                        "Cannot validate {peer} with empty certificate in the overlay {}",
                        self.overlay_id
                    )
                };
                self.validate_certificate(peer, certificate).map_err(|e| {
                    error!(
                        "Certificate validation for new peer {peer} in overlay {}: {e}",
                        self.overlay_id
                    )
                })
            }
        }
    }

    async fn distribute_broadcast(
        &self,
        data: &TaggedByteSlice<'_>,
        bcast_id: &BroadcastId,
        seqno: u32,
        key: &Arc<KeyId>,
        neighbours: &[Arc<KeyId>],
        method: &BroadcastSendMethod,
    ) -> Result<()> {
        log::trace!(
            target: TARGET,
            "Broadcast {} part {seqno} via {method} {} bytes to overlay {}, {} neighbours",
            base64_encode(bcast_id),
            data.object.len(),
            self.overlay_id,
            neighbours.len()
        );
        let mut peers: Option<AdnlPeers> = None;
        #[cfg(feature = "telemetry")]
        let mut addrs = Vec::new();
        for neighbour in neighbours.iter() {
            #[cfg(feature = "telemetry")]
            if let Err(e) = self.update_stats(neighbour, data.tag, true) {
                log::warn!(
                    target: TARGET,
                    "Cannot update statistics in overlay {} for {neighbour} during broadcast: {e}",
                    self.overlay_id
                )
            }
            let peers = if let Some(peers) = &mut peers {
                peers.set_other(neighbour.clone());
                peers
            } else {
                peers.get_or_insert_with(|| AdnlPeers::with_keys(key.clone(), neighbour.clone()))
            };
            #[cfg(feature = "telemetry")]
            addrs.push(peers.other().to_string());
            // Distribution also owns this generation when called by ordinary
            // two-step/FEC broadcasts. A stalled peer must not pin retirement
            // until global transport shutdown, which happens after overlay join.
            let err = tokio::select! {
                biased;
                _ = self.tasks.cancelled() => fail!("Overlay retired during broadcast distribution"),
                result = async {
                    if let Some(transport) = &self.broadcast_transport {
                        let method = match method {
                            BroadcastSendMethod::Fast => BroadcastTransportMethod::Datagram,
                            BroadcastSendMethod::Safe => BroadcastTransportMethod::Stream,
                            BroadcastSendMethod::TwostepUnreliable => BroadcastTransportMethod::Sender { reliable: false },
                            BroadcastSendMethod::TwostepReliable => BroadcastTransportMethod::Sender { reliable: true },
                        };
                        return Ok::<_, anyhow::Error>(
                            transport.send_message(data.object, peers, method).await.err(),
                        );
                    }
                    Ok(match method {
                        BroadcastSendMethod::Fast | BroadcastSendMethod::TwostepUnreliable => self.adnl
                            .send_custom_get_status(data, peers, AdnlSendMethod::Fast).await.err(),
                        BroadcastSendMethod::TwostepReliable => {
                            if let Some(quic) = &self.quic {
                                quic.message(data.object.to_vec(), Some(&self.adnl), peers).await.err()
                            } else if let Some(rldp) = &self.rldp {
                                rldp.message(data, peers, true, None).await.err()
                            } else {
                                fail!("Neither QUIC nor RLDP sender is set in overlay {}", self.overlay_id);
                            }
                        }
                        BroadcastSendMethod::Safe => self.adnl
                            .send_custom_get_status(data, peers, AdnlSendMethod::Safe).await.err(),
                    })
                } => result?,
            };
            if let Some(e) = err {
                log::warn!(
                    target: TARGET,
                    "Cannot distribute broadcast {} part {seqno} via {method} in overlay {} \
                    to {neighbour}: {e}",
                    base64_encode(bcast_id),
                    self.overlay_id
                )
            }
        }
        #[cfg(feature = "telemetry")]
        log::info!(
            target: TARGET_BROADCAST,
            "Broadcast trace: distributed {} part {seqno} via {method} {} bytes to overlay {}, \
            peers {addrs:?}",
            base64_encode(bcast_id),
            data.object.len(),
            self.overlay_id,
        );
        Ok(())
    }

    fn use_v2_peer_advertisements(&self) -> bool {
        // The pinned target carries flags and member certificates in overlay.node
        // and supports overlay.getRandomPeers. Its schema has no V2 request.
        self.wire_profile == rtos_api::WireProfile::Legacy
            && (self.overlay_type.has_certified_members() || self.plumtree.get().is_some())
    }

    async fn get_random_peers(
        &self,
        dst: &Arc<KeyId>,
        default_key: &Arc<dyn KeyOption>,
        v2: bool,
        timeout_ms: Option<u64>,
    ) -> Result<()> {
        log::trace!(target: TARGET, "Get random peers from {dst}");
        let query: TaggedTlObject = match self.prepare_random_peers(default_key, v2)? {
            Nodes::V1(peers) => GetRandomPeers { peers }.into_tl_object().into(),
            Nodes::V2(peers) => GetRandomPeersV2 { peers }.into_tl_object().into(),
        };
        let peers = self
            .prepare_to_send(
                dst,
                default_key,
                #[cfg(feature = "telemetry")]
                query.tag,
            )
            .await?;
        let answer = self
            .adnl
            .query_with_prefix(Some(&self.query_prefix), &query, &peers, timeout_ms)
            .await?;
        if let Some(answer) = answer {
            log::trace!(target: TARGET, "Got random peers from {dst}");
            let ret = if v2 {
                self.process_random_peers(
                    default_key,
                    Query::parse::<_, NodesV2Boxed>(answer, &query.object)?.only().nodes,
                    |node| OverlayNodeInfo::V2(node),
                )?
            } else {
                self.process_random_peers(
                    default_key,
                    Query::parse::<_, NodesV1Boxed>(answer, &query.object)?.only().nodes,
                    |node| OverlayNodeInfo::V1(node),
                )?
            };
            self.received_peers.push(ret);
        } else {
            log::warn!(target: TARGET, "No random peers from {dst}");
        }
        Ok(())
    }

    fn get_signed_node(
        &self,
        default_key: &Arc<dyn KeyOption>,
        v2: bool,
    ) -> Result<OverlayNodeInfo<NodeV1, NodeV2>> {
        let key = self.overlay_key().unwrap_or(default_key);
        let overlay_id = UInt256::with_array(*self.overlay_id.data());
        let flags = i32::try_from(self.local_member_flags())?;
        let version = Version::get();
        let local_node = OverlayUtils::get_node_to_sign(key, &overlay_id, flags, version);
        let node = if v2 {
            let node = NodeV2 {
                id: key.try_into()?,
                certificate: self
                    .overlay_type
                    .certificate()
                    .map(|cert| cert.clone().into_boxed())
                    .unwrap_or_default(),
                flags,
                overlay: overlay_id,
                signature: key.sign(&serialize_boxed(&local_node)?)?.into(),
                version,
            };
            OverlayNodeInfo::V2(node)
        } else {
            let node = NodeV1 {
                id: key.try_into()?,
                flags,
                certificate: self
                    .overlay_type
                    .certificate()
                    .map(|cert| cert.clone().into_boxed())
                    .unwrap_or_default(),
                overlay: overlay_id,
                signature: key.sign(&serialize_boxed(&local_node)?)?.into(),
                version,
            };
            OverlayNodeInfo::V1(node)
        };
        Ok(node)
    }

    fn overlay_key(&self) -> Option<&Arc<dyn KeyOption>> {
        match &self.overlay_type {
            OverlayType::Private { key, .. } => Some(key),
            OverlayType::CertifiedMembers { key, .. } => key.as_ref(),
            OverlayType::Public => None,
        }
    }

    async fn ping_peer(
        &self,
        default_key: &Arc<dyn KeyOption>,
        peer: &Arc<KeyId>,
        timeout_ms: u64,
    ) -> Result<()> {
        let peers = self
            .prepare_to_send(
                peer,
                default_key,
                #[cfg(feature = "telemetry")]
                Ping::constructor_const(),
            )
            .await?;
        let query: TaggedTlObject = Ping.into_tl_object().into();
        let pong = self
            .adnl
            .query_with_prefix(Some(&self.query_prefix), &query, &peers, Some(timeout_ms))
            .await?;
        let elapsed_sec = self.adnl.elapsed_sec();
        if pong.is_some() {
            self.known_peers.amnesty(peer, elapsed_sec);
        } else if !self.overlay_type.is_private() {
            // FixedMemberList C++ equivalent: don't penalize on missed pong.
            // Consensus overlay must always target the full validator set.
            self.known_peers.penalty(peer, elapsed_sec)?;
        }
        Ok(())
    }

    fn prepare_random_peers(&self, default_key: &Arc<dyn KeyOption>, v2: bool) -> Result<Nodes> {
        let local_node = self.get_signed_node(default_key, v2)?;
        let nodes = AddressCache::with_limit(Self::MAX_RANDOM_PEERS);
        self.neighbours.random_set(&nodes, Self::MAX_RANDOM_PEERS)?;
        let (mut iter, mut current) = nodes.first();
        let ret = match local_node {
            OverlayNodeInfo::V1(node) => {
                let mut ret = vec![node];
                while let Some(node) = current {
                    match self.nodes.get(&node).map(|node| node.val().v1.clone()) {
                        Some(Some(node)) => ret.push(node.as_ref().clone()),
                        _ => (),
                    }
                    current = nodes.next(&mut iter)
                }
                Nodes::V1(NodesV1 { nodes: ret })
            }
            OverlayNodeInfo::V2(node) => {
                let mut ret = vec![node];
                while let Some(node) = current {
                    match self.nodes.get(&node).map(|node| node.val().v2.clone()) {
                        Some(Some(node)) => ret.push(node.as_ref().clone()),
                        _ => (),
                    }
                    current = nodes.next(&mut iter)
                }
                Nodes::V2(NodesV2 { nodes: ret })
            }
        };
        Ok(ret)
    }

    async fn prepare_to_send(
        &self,
        dst: &Arc<KeyId>,
        default_key: &Arc<dyn KeyOption>,
        #[cfg(feature = "telemetry")] tag: u32,
    ) -> Result<AdnlPeers> {
        let src = self.overlay_key().unwrap_or(default_key).id();
        let peers = AdnlPeers::with_keys(src.clone(), dst.clone());
        #[cfg(feature = "telemetry")]
        self.update_stats(dst, tag, true)?;
        Ok(peers)
    }

    fn process_random_peers<T: NodeData>(
        &self,
        default_key: &Arc<dyn KeyOption>,
        mut peers: Vec<T>,
        convert: impl Fn(T) -> OverlayNodeInfo<NodeV1, NodeV2>,
    ) -> Result<Vec<OverlayNodeInfo<NodeV1, NodeV2>>> {
        let self_id = self.overlay_key().unwrap_or(default_key).id();
        let mut ret = Vec::new();
        log::trace!(target: TARGET, "-------- Got random peers:");
        while let Some(peer) = peers.pop() {
            let other_key = peer.get_key()?;
            if self_id.data() == other_key.id().data() {
                continue;
            }
            log::trace!(target: TARGET, "{}", other_key.id());
            if let Err(e) = OverlayUtils::verify_node(&self.overlay_id, &peer) {
                log::warn!(target: TARGET, "Error when verifying overlay peer: {e}");
                continue;
            }
            ret.push((&convert)(peer));
        }
        Ok(ret)
    }

    async fn purge_broadcasts(
        &self,
        last_one_time_broadcast: &mut Option<(BroadcastId, Instant)>,
        recv_one_time: &mut tokio::sync::mpsc::UnboundedReceiver<(BroadcastId, Instant)>,
        #[cfg(feature = "xp25")] last_repeated_broadcast: &mut Option<(BroadcastId, Instant)>,
        #[cfg(feature = "xp25")] recv_repeated: &mut tokio::sync::mpsc::UnboundedReceiver<(
            BroadcastId,
            Instant,
        )>,
    ) {
        #[cfg(feature = "xp25")]
        loop {
            if last_repeated_broadcast.is_none() && !recv_repeated.is_empty() {
                *last_repeated_broadcast = recv_repeated.recv().await;
            }
            let Some((bcast_id, start)) = last_repeated_broadcast else {
                break;
            };
            if start.elapsed().as_secs() >= Overlay::TIMEOUT_REPEATED_BROADCAST_SEC {
                self.owned_broadcasts.remove(bcast_id);
                #[cfg(feature = "telemetry")]
                self.stats_per_transfer.remove(bcast_id);
                *last_repeated_broadcast = None
            } else {
                break;
            }
        }
        loop {
            if last_one_time_broadcast.is_none() && !recv_one_time.is_empty() {
                *last_one_time_broadcast = recv_one_time.recv().await;
            }
            let Some((bcast_id, start)) = last_one_time_broadcast else {
                break;
            };
            if start.elapsed().as_secs() >= Overlay::TIMEOUT_ONE_TIME_BROADCAST_SEC {
                self.purge_broadcasts_count.fetch_add(1, Ordering::Relaxed);
                self.purge_broadcasts.push(*bcast_id);
                *last_one_time_broadcast = None
            } else {
                break;
            }
        }
        let upto = Self::MAX_BROADCAST_LOG;
        while self.purge_broadcasts_count.load(Ordering::Relaxed) > upto {
            if let Some(bcast_id) = self.purge_broadcasts.pop() {
                self.owned_broadcasts.remove(&bcast_id);
                #[cfg(feature = "telemetry")]
                self.stats_per_transfer.remove(&bcast_id);
            }
            self.purge_broadcasts_count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    fn setup_broadcast_purge(
        &self,
        bcast_id: BroadcastId,
        #[cfg(feature = "xp25")] flags: u32,
    ) -> Result<()> {
        #[cfg(feature = "xp25")]
        if (flags & OverlayNode::FLAG_BCAST_REPEATED) != 0 {
            return self.queue_repeated_broadcasts.send((bcast_id, Instant::now())).map_err(|e| {
                error!("Error putting repeated broadcast into monitoring queue: {e}")
            });
        }
        self.queue_one_time_broadcasts
            .send((bcast_id, Instant::now()))
            .map_err(|e| error!("Error putting one time broadcast into monitoring queue: {e}"))
    }

    fn try_add_peer(&self, our_key: &Arc<KeyId>, peer: &Arc<KeyId>) -> Result<bool> {
        if self.broadcast_transport.as_ref().is_some_and(|transport| {
            transport.has_peer(our_key.data(), peer.data())
        }) || self.adnl.have_peer(our_key, peer)? {
            self.known_peers.add(peer)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn update_neighbours(&self, n: u32) -> Result<()> {
        if self.overlay_type.is_private() {
            let n = min(self.known_peers.all().count(), n);
            loop {
                self.known_peers.all().random_set(&self.neighbours, n)?;
                if self.neighbours.count() >= n {
                    break Ok(());
                }
            }
        } else {
            self.known_peers.random_set(&self.neighbours, n)
            // self.random_peers.random_set(&self.neighbours, Some(&self.bad_peers), n)
        }
    }

    // fn update_random_peers(&self, n: u32) -> Result<()> {
    //     self.known_peers.random_set(&self.random_peers, Some(&self.bad_peers), n)?;
    //     self.update_neighbours(OverlayNode::MAX_OVERLAY_NEIGHBOURS)
    // }

    fn validate_certificate(&self, peer: &Arc<KeyId>, cert: &MemberCertificate) -> Result<()> {
        let utime = UnixTime::now();
        let (max_slaves, root_public_keys) =
            if let OverlayType::CertifiedMembers { max_slaves, root_public_keys, .. } =
                &self.overlay_type
            {
                (*max_slaves, root_public_keys)
            } else {
                fail!("Overlay type is not certified members")
            };

        // 1) Expire check
        // "3" is a magic gap from cpp implementation
        if records::certificate_expired(cert.expire_at, utime as f64) {
            fail!("Certificate is expired, expire_at: {}, current time: {}", cert.expire_at, utime);
        }

        // 2) Slot (each root member has fixed number of slots)
        if cert.slot < 0 || cert.slot as usize >= max_slaves {
            fail!("Certificate has invalid slot: {}", cert.slot);
        }

        // 3) Issuer
        let issuer: Arc<dyn KeyOption> = (&cert.issued_by).try_into()?;
        let Some(slaves_info) = root_public_keys.get(issuer.id()) else {
            fail!("Certificate is issued by unknown member: {}", cert.issued_by);
        };

        // If previously used slot
        if let Some(guard) = slaves_info.get(&(cert.slot as u32)) {
            let slave_info = guard.val();

            // 4) Check for newer certificate at the same slot
            if (cert.expire_at as u32) < slave_info.expire_at {
                fail!("Certificate rejected, because we know of newer one at the same slot");
            }

            // 5) Check sender adnl id
            if (cert.expire_at as u32) == slave_info.expire_at {
                // In cpp code "if (node < el.node)", it is strange, because
                // it is not clear why node with bigger id can replace
                // node with smaller id, but node with smaller id can not.
                // I think it should be "!="
                if UInt256::from_slice(peer.data()) < UInt256::from_slice(slave_info.node_id.data())
                {
                    fail!("Certificate rejected, because we know another one at the same slot");
                }

                // 6) Check peer. Same peer means that certificate was already checked
                //    (slave_info is saved only after successfull check)
                if *peer == slave_info.node_id {
                    return Ok(());
                }
            }
        }

        // 6) Verify signature
        let data_to_sign = MemberCertificateId {
            node: AdnlShortId { id: UInt256::with_array(peer.data().clone()) },
            flags: cert.flags,
            slot: cert.slot,
            expire_at: cert.expire_at,
        }
        .into_boxed();
        issuer.verify(&serialize_boxed(&data_to_sign)?, &cert.signature)?;

        // 7) Create/update slot info
        add_unbound_object_to_map_with_update(slaves_info, cert.slot as u32, |_| {
            Ok(Some(SlaveInfo { node_id: peer.clone(), expire_at: cert.expire_at as u32 }))
        })?;
        Ok(())
    }

    #[cfg(feature = "telemetry")]
    fn get_per_transfer_stats(&self, bcast_id: &BroadcastId) -> Result<Arc<TransferStats>> {
        let stats = if let Some(stats) = self.stats_per_transfer.get(bcast_id) {
            stats.val().clone()
        } else {
            let stats = Arc::new(TransferStats {
                income: AtomicU64::new(0),
                passed: AtomicU64::new(0),
                resent: AtomicU64::new(0),
                counter: self.allocated.stats_transfer.clone().into(),
            });
            add_counted_object_to_map(&self.stats_per_transfer, bcast_id.clone(), || {
                self.telemetry
                    .stats_transfer
                    .update(self.allocated.stats_transfer.load(Ordering::Relaxed));
                Ok(stats.clone())
            })?;
            self.stats_per_transfer
                .get(bcast_id)
                .ok_or_else(|| error!("INTERNAL ERROR: Cannot count transfer statistics"))?
                .val()
                .clone()
        };
        Ok(stats)
    }

    #[cfg(feature = "telemetry")]
    fn print_stats(&self) -> Result<()> {
        let elapsed = self.start.elapsed().as_secs();
        if elapsed == 0 {
            // Too early to print stats
            return Ok(());
        }
        let messages_recv = self.messages_recv.load(Ordering::Relaxed);
        let messages_send = self.messages_send.load(Ordering::Relaxed);
        log::info!(
            target: TARGET,
            "------- OVERLAY STAT send {}: {messages_send} messages, {} messages/sec average load",
            self.overlay_id,
            messages_send / elapsed
        );
        for dst in self.stats_per_peer_send.iter() {
            log::info!(
                target: TARGET,
                "  -- OVERLAY STAT send {} to {}",
                self.overlay_id,
                dst.key()
            );
            for tag in dst.val().iter() {
                let count = tag.val().count.load(Ordering::Relaxed);
                if count / elapsed < 1 {
                    continue;
                }
                log::info!(
                    target: TARGET,
                    "  OVERLAY STAT send {} tag {:x}: {count}, {} per sec average load",
                    self.overlay_id,
                    tag.key(),
                    count / elapsed
                );
            }
        }
        log::info!(
            target: TARGET,
            "------- OVERLAY STAT recv {}: {messages_recv} messages, {} messages/sec average load",
            self.overlay_id,
            messages_recv / elapsed
        );
        for dst in self.stats_per_peer_recv.iter() {
            log::info!(
                target: TARGET,
                "  -- OVERLAY STAT recv {} from {}",
                self.overlay_id,
                dst.key()
            );
            for tag in dst.val().iter() {
                let count = tag.val().count.load(Ordering::Relaxed);
                if count / elapsed < 1 {
                    continue;
                }
                log::info!(
                    target: TARGET,
                    "  OVERLAY STAT recv {} tag {:x}: {count}, {} per sec average load",
                    self.overlay_id,
                    tag.key(),
                    count / elapsed
                );
            }
        }
        let mut inc = 0;
        let mut pas = 0;
        let mut res = 0;
        for transfer in self.stats_per_transfer.iter() {
            inc += transfer.val().income.load(Ordering::Relaxed);
            pas += transfer.val().passed.load(Ordering::Relaxed);
            res += transfer.val().resent.load(Ordering::Relaxed);
            /*
                log::info!(
                    target: TARGET,
                    "  ** OVERLAY STAT resend transfer {}: -> {} / {} -> {}",
                    base64_encode(transfer.key()),
                    transfer.val().income.load(Ordering::Relaxed),
                    transfer.val().passed.load(Ordering::Relaxed),
                    transfer.val().resent.load(Ordering::Relaxed)
                )
            */
        }
        log::info!(target: TARGET, "  ** OVERLAY STAT resend {inc} / {pas} -> {res}");
        let map = lockfree::map::Map::new();
        for transfer in self.owned_broadcasts.iter() {
            if let OwnedBroadcast::RecvFec(transfer) = transfer.val() {
                let Some((tag, len)) = transfer.get_telemetry_tag_and_len() else {
                    continue;
                };
                add_unbound_object_to_map(&map, tag, || {
                    Ok((AtomicU32::new(0), AtomicU32::new(0)))
                })?;
                if let Some(item) = map.get(&tag) {
                    let (cnt, total_len) = item.val();
                    cnt.fetch_add(1, Ordering::Relaxed);
                    total_len.fetch_add(len, Ordering::Relaxed);
                }
            }
        }
        for item in map.iter() {
            let (cnt, len) = item.val();
            let cnt = cnt.load(Ordering::Relaxed);
            let len = len.load(Ordering::Relaxed) / cnt;
            log::info!(
                target: TARGET,
                "  ** OVERLAY STAT resend by tag {:08x}: {cnt}, {len} bytes avg",
                item.key()
            )
        }
        Ok(())
    }

    #[cfg(feature = "telemetry")]
    fn update_stats(&self, dst: &Arc<KeyId>, tag: u32, is_send: bool) -> Result<()> {
        let stats = if is_send { &self.stats_per_peer_send } else { &self.stats_per_peer_recv };
        let stats = if let Some(stats) = stats.get(dst) {
            stats
        } else {
            add_unbound_object_to_map(stats, dst.clone(), || Ok(lockfree::map::Map::new()))?;
            if let Some(stats) = stats.get(dst) {
                stats
            } else {
                fail!(
                    "INTERNAL ERROR: cannot add overlay statistics for {}:{dst}",
                    self.overlay_id
                );
            }
        };
        let stats = if let Some(stats) = stats.val().get(&tag) {
            stats
        } else {
            add_counted_object_to_map(stats.val(), tag, || {
                let ret = PeerStats {
                    count: AtomicU64::new(0),
                    counter: self.allocated.stats_peer.clone().into(),
                };
                self.telemetry.stats_peer.update(self.allocated.stats_peer.load(Ordering::Relaxed));
                Ok(ret)
            })?;
            if let Some(stats) = stats.val().get(&tag) {
                stats
            } else {
                fail!(
                    "INTERNAL ERROR: cannot add overlay statistics for {}:{dst}:{tag}",
                    self.overlay_id
                );
            }
        };
        stats.val().count.fetch_add(1, Ordering::Relaxed);
        if is_send {
            self.messages_send.fetch_add(1, Ordering::Relaxed);
        } else {
            self.messages_recv.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    #[cfg(feature = "telemetry")]
    fn try_print_stats(&self) {
        let elapsed = self.start.elapsed().as_secs();
        let printed = self.print.load(Ordering::Relaxed);
        if elapsed > printed {
            if self
                .print
                .compare_exchange(printed, elapsed + 5, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                if let Err(e) = self.print_stats() {
                    log::warn!(target: TARGET, "Error printing overlay stats: {e}");
                }
            }
        }
    }
}

declare_counted!(
    struct ConsumerObject {
        object: Arc<dyn Subscriber>,
    }
);

/// Overlay parameters
pub struct OverlayParams<'a> {
    pub flags: u8,
    pub hops: Option<u8>,
    pub overlay_id: &'a Arc<OverlayShortId>,
    pub runtime: Option<tokio::runtime::Handle>,
}

impl<'a> OverlayParams<'a> {
    pub fn with_id_only(overlay_id: &'a Arc<OverlayShortId>) -> Self {
        Self { flags: 0, hops: None, overlay_id, runtime: None }
    }
}

/// Owned completion receipt for one concrete overlay generation.
#[derive(Clone)]
pub struct OverlayShutdown {
    id: Arc<OverlayShortId>,
    tasks: Arc<AdnlTasks>,
}
impl OverlayShutdown {
    pub fn drained(&self) -> bool {
        self.tasks.drained()
    }
}

/// Overlay Node
pub struct OverlayNode {
    #[cfg(test)]
    send_admission_gate: std::sync::Mutex<Option<Arc<(tokio::sync::Notify, tokio::sync::Notify)>>>,
    #[cfg(test)]
    receive_admission_gate:
        std::sync::Mutex<Option<Arc<(tokio::sync::Notify, tokio::sync::Notify)>>>,
    generations: std::sync::Mutex<()>,
    retired: std::sync::Mutex<HashMap<Arc<OverlayShortId>, std::sync::Weak<AdnlTasks>>>,
    wire_profile: rtos_api::WireProfile,
    clock: Arc<dyn BroadcastClock>,
    broadcast_transport: OnceLock<Arc<dyn OverlayBroadcastTransport>>,
    adnl: Arc<AdnlNode>,
    consumers: lockfree::map::Map<Arc<OverlayShortId>, ConsumerObject>,
    node_key: Arc<dyn KeyOption>,
    options: Arc<AtomicU32>,
    overlays: lockfree::map::Map<Arc<OverlayShortId>, Arc<Overlay>>,
    quic: OnceLock<Arc<QuicNode>>,
    rldp: OnceLock<Arc<RldpNode>>,
    zero_state_file_hash: [u8; 32],
    #[cfg(feature = "telemetry")]
    telemetry: Arc<OverlayTelemetry>,
    allocated: Arc<OverlayAlloc>,
}

impl Drop for OverlayNode {
    fn drop(&mut self) {
        for item in self.overlays.iter() {
            item.val().tasks.close();
        }
    }
}

impl OverlayNode {
    pub const FLAG_BCAST_ANY_SENDER: u32 = 0x01;
    pub const FLAG_BCAST_NO_TWOSTEP: u32 = 0x100;
    #[cfg(feature = "xp25")]
    pub const FLAG_BCAST_REPEATED: u32 = 0x80;

    const MAX_FAIL_COUNT: u8 = 3;
    const MAX_PEERS: u32 = 65536;
    const MAX_OVERLAY_NEIGHBOURS: u32 = 200;
    //    const MAX_OVERLAY_PEERS: u32 = 20;
    const MAX_SIZE_ORDINARY_BROADCAST: usize = 768;
    const MIN_BYTES_FEC_TWO_STEPS_BROADCAST: usize = 513;
    const MIN_NODES_FEC_TWO_STEPS_BROADCAST: u32 = 4;
    const PEER_BLOCK_LATENCY_SEC: u32 = 10;
    const TIMEOUT_BROADCAST_GC_MS: u64 = 1000;
    const TIMEOUT_NEIGHBOURS_MS: u64 = 60000;
    const TIMEOUT_PENDING_PEERS_MS: u64 = 200;
    const TIMEOUT_PING_MS: u64 = 1000;

    /// Constructor
    pub fn with_params(
        adnl: Arc<AdnlNode>,
        zero_state_file_hash: &[u8; 32],
        key_tag: usize,
    ) -> Result<Arc<Self>> {
        Self::with_params_and_profile(
            adnl,
            zero_state_file_hash,
            key_tag,
            rtos_api::WireProfile::Legacy,
        )
    }

    /// Bind the wire domain before any overlay is created or advertised.
    pub fn with_params_and_profile(
        adnl: Arc<AdnlNode>,
        zero_state_file_hash: &[u8; 32],
        key_tag: usize,
        wire_profile: rtos_api::WireProfile,
    ) -> Result<Arc<Self>> {
        Self::with_params_profile_and_clock(
            adnl,
            zero_state_file_hash,
            key_tag,
            wire_profile,
            Arc::new(SystemBroadcastClock),
        )
    }

    /// Bind a broadcast wall clock before any overlay or owned task is created.
    pub fn with_params_profile_and_clock(
        adnl: Arc<AdnlNode>,
        zero_state_file_hash: &[u8; 32],
        key_tag: usize,
        wire_profile: rtos_api::WireProfile,
        clock: Arc<dyn BroadcastClock>,
    ) -> Result<Arc<Self>> {
        let node_key = adnl.key_by_tag(key_tag)?;
        #[cfg(feature = "telemetry")]
        let telemetry = OverlayTelemetry {
            consumers: adnl.add_metric("Alloc OVRL consumers"),
            overlays: adnl.add_metric("Alloc OVRL overlays"),
            peers: adnl.add_metric("Alloc OVRL peers"),
            recv_transfers: adnl.add_metric("Alloc OVRL recv transfers"),
            send_transfers: adnl.add_metric("Alloc OVRL send transfers"),
            stats_peer: adnl.add_metric("Alloc OVRL peer stats"),
            stats_transfer: adnl.add_metric("Alloc OVRL transfer stats"),
        };
        let allocated = OverlayAlloc {
            consumers: Arc::new(AtomicU64::new(0)),
            overlays: Arc::new(AtomicU64::new(0)),
            peers: Arc::new(AtomicU64::new(0)),
            recv_transfers: Arc::new(AtomicU64::new(0)),
            send_transfers: Arc::new(AtomicU64::new(0)),
            #[cfg(feature = "telemetry")]
            stats_peer: Arc::new(AtomicU64::new(0)),
            #[cfg(feature = "telemetry")]
            stats_transfer: Arc::new(AtomicU64::new(0)),
        };
        let ret = Self {
            #[cfg(test)]
            send_admission_gate: std::sync::Mutex::new(None),
            #[cfg(test)]
            receive_admission_gate: std::sync::Mutex::new(None),
            wire_profile,
            clock,
            broadcast_transport: OnceLock::new(),
            adnl,
            consumers: lockfree::map::Map::new(),
            node_key,
            options: Arc::new(AtomicU32::new(0)),
            generations: std::sync::Mutex::new(()),
            retired: std::sync::Mutex::new(HashMap::new()),
            overlays: lockfree::map::Map::new(),
            quic: OnceLock::new(),
            rldp: OnceLock::new(),
            zero_state_file_hash: *zero_state_file_hash,
            #[cfg(feature = "telemetry")]
            telemetry: Arc::new(telemetry),
            allocated: Arc::new(allocated),
        };
        Ok(Arc::new(ret))
    }

    #[cfg(test)]
    async fn pause_after_send_admission(&self) {
        let gate = self.send_admission_gate.lock().unwrap().take();
        if let Some(gate) = gate {
            gate.0.notify_one();
            gate.1.notified().await;
        }
    }
    #[cfg(test)]
    async fn pause_after_receive_admission(&self) {
        let gate = self.receive_admission_gate.lock().unwrap().take();
        if let Some(gate) = gate {
            gate.0.notify_one();
            gate.1.notified().await;
        }
    }
    pub fn wire_profile(&self) -> rtos_api::WireProfile {
        self.wire_profile
    }

    /// Bind the network edge before creating the first overlay. Every overlay
    /// generation keeps its original transport until its tasks drain.
    pub fn install_broadcast_transport(
        &self,
        transport: Arc<dyn OverlayBroadcastTransport>,
    ) -> Result<()> {
        let _generation = self.generations.lock().unwrap();
        if self.overlays.iter().next().is_some() {
            fail!("Broadcast transport must be installed before overlays");
        }
        self.broadcast_transport.set(transport)
            .map_err(|_| error!("Broadcast transport is already bound"))
    }

    /// Add overlay data consumer
    pub fn add_consumer(
        &self,
        overlay_id: &Arc<OverlayShortId>,
        consumer: Arc<dyn Subscriber>,
    ) -> Result<bool> {
        let _generation = self.generations.lock().unwrap();
        let overlay = self.get_overlay(overlay_id, "Consumer registration for unknown overlay")?;
        self.add_consumer_locked(&overlay, consumer)
    }
    pub fn add_consumer_for_generation(
        &self,
        generation: &OverlayShutdown,
        consumer: Arc<dyn Subscriber>,
    ) -> Result<bool> {
        let _generation = self.generations.lock().unwrap();
        let overlay =
            self.get_overlay(&generation.id, "Consumer registration for unknown generation")?;
        if !Arc::ptr_eq(&overlay.tasks, &generation.tasks) {
            fail!("Consumer generation was replaced");
        }
        self.add_consumer_locked(&overlay, consumer)
    }
    fn add_consumer_locked(
        &self,
        overlay: &Arc<Overlay>,
        consumer: Arc<dyn Subscriber>,
    ) -> Result<bool> {
        let _lease = overlay.tasks.enter()?;
        let added = add_counted_object_to_map(&self.consumers, overlay.overlay_id.clone(), || {
            Ok(ConsumerObject {
                object: consumer.clone(),
                counter: self.allocated.consumers.clone().into(),
            })
        })?;
        if added {
            overlay
                .consumer
                .set(consumer)
                .map_err(|_| error!("Overlay consumer is already bound"))?;
        }
        Ok(added)
    }

    /// Add overlay for local workchain
    pub fn add_local_workchain_overlay(&self, params: OverlayParams) -> Result<bool> {
        self.add_overlay(OverlayType::Public, params)
    }

    /// Add a public overlay whose broadcasts are authorized by `rules`
    /// from the first received message on. An existing overlay keeps its
    /// generation; its rules are replaced when it already has a policy.
    pub fn add_public_overlay_with_rules(
        &self,
        params: OverlayParams,
        rules: OverlayPrivacyRules,
    ) -> Result<bool> {
        let _generation =
            self.generations.lock().map_err(|_| error!("Overlay generation lock poisoned"))?;
        let overlay_id = params.overlay_id.clone();
        let added = self.add_overlay_locked(OverlayType::Public, params, Some(rules.clone()))?;
        if !added {
            self.set_public_privacy_rules(&overlay_id, rules)?;
        }
        Ok(added)
    }

    /// Replace the privacy rules of a public overlay created with rules.
    pub fn set_public_privacy_rules(
        &self,
        overlay_id: &Arc<OverlayShortId>,
        rules: OverlayPrivacyRules,
    ) -> Result<()> {
        let overlay = self.get_overlay(overlay_id, "Setting privacy rules of unknown overlay")?;
        if !overlay.overlay_type.is_public() {
            fail!("Public privacy rule update requires a public overlay");
        }
        let Some(policy) = &overlay.public_policy else {
            fail!("Overlay {overlay_id} was created without privacy rules");
        };
        overlay.verifier.retain_authorized(&rules);
        policy.set_rules(rules)
    }

    /// Install, replace or (with `None`) remove the certificate attached to
    /// broadcasts this node sends in one overlay as the source `key`.
    pub fn update_certificate(
        &self,
        overlay_id: &Arc<OverlayShortId>,
        key: &Arc<KeyId>,
        certificate: Option<OverlayCertificate>,
    ) -> Result<()> {
        let overlay = self.get_overlay(overlay_id, "Updating certificate of unknown overlay")?;
        let mut certificates =
            overlay.certificates.write().map_err(|_| error!("Certificate store lock poisoned"))?;
        match certificate {
            Some(certificate) => certificates.insert(key.clone(), certificate),
            None => certificates.remove(key),
        };
        Ok(())
    }

    /// The privacy rules of a public overlay created with rules.
    pub fn public_privacy_rules(
        &self,
        overlay_id: &Arc<OverlayShortId>,
    ) -> Result<Option<OverlayPrivacyRules>> {
        let overlay = self.get_overlay(overlay_id, "Reading privacy rules of unknown overlay")?;
        Ok(overlay.public_policy.as_ref().map(|policy| (*policy.rules()).clone()))
    }

    /// The certificate attached when sending as `key` in one overlay.
    pub fn local_certificate(
        &self,
        overlay_id: &Arc<OverlayShortId>,
        key: &Arc<KeyId>,
    ) -> Result<Option<OverlayCertificate>> {
        let overlay = self.get_overlay(overlay_id, "Reading certificate of unknown overlay")?;
        Ok(overlay.local_certificate(key))
    }

    /// Install (or remove) the application check of a public overlay.
    pub fn set_public_broadcast_check(
        &self,
        overlay_id: &Arc<OverlayShortId>,
        check: Option<Arc<dyn PublicBroadcastCheck>>,
    ) -> Result<()> {
        self.set_broadcast_check(overlay_id, check)
    }

    /// Bind the application check of a public or fixed-member broadcast policy.
    pub fn set_broadcast_check(
        &self,
        overlay_id: &Arc<OverlayShortId>,
        check: Option<Arc<dyn PublicBroadcastCheck>>,
    ) -> Result<()> {
        let overlay = self.get_overlay(overlay_id, "Setting broadcast check of unknown overlay")?;
        let Some(policy) = &overlay.public_policy else {
            fail!("Overlay {overlay_id} was created without privacy rules");
        };
        policy.set_check(check)
    }

    /// Add overlay for other workchain
    pub fn add_other_workchain_overlay(&self, mut params: OverlayParams) -> Result<bool> {
        params.flags |= Overlay::FLAG_OVERLAY_OTHER_WORKCHAIN;
        self.add_overlay(OverlayType::Public, params)
    }

    /// Add private_overlay
    pub fn add_private_overlay(
        &self,
        params: OverlayParams,
        overlay_key: &Arc<dyn KeyOption>,
        peers: &[Arc<KeyId>],
        use_quic: bool,
        bcast_check: Option<Arc<dyn BroadcastCheck>>,
    ) -> Result<bool> {
        let overlay_type = OverlayType::Private {
            key: overlay_key.clone(), use_quic, bcast_check, fixed_member_list: false, twostep_enabled: true,
        };
        self.add_typed_private_overlay(overlay_type, params, peers)
    }

    /// Fixed members with ordinary broadcast source rules. Membership still
    /// passes the ordinary private-overlay peer check; source certificates do
    /// not expand authority in a fixed-member overlay.
    pub fn add_fixed_member_overlay(
        &self,
        params: OverlayParams,
        overlay_key: &Arc<dyn KeyOption>,
        peers: &[Arc<KeyId>],
        rules: OverlayPrivacyRules,
    ) -> Result<bool> {
        self.add_fixed_member_overlay_with_options(
            params, overlay_key, peers, rules, FixedMemberOverlayOptions::default(),
        )
    }

    pub fn add_fixed_member_overlay_with_options(
        &self,
        params: OverlayParams,
        overlay_key: &Arc<dyn KeyOption>,
        peers: &[Arc<KeyId>],
        rules: OverlayPrivacyRules,
        options: FixedMemberOverlayOptions,
    ) -> Result<bool> {
        let sender_available = self.broadcast_transport.get().is_some()
            || if options.use_quic { self.quic.get().is_some() } else { self.rldp.get().is_some() };
        let twostep_enabled = options.twostep && sender_available;
        if options.twostep && !sender_available {
            log::warn!(target: TARGET, "Two-step sender is not set; retaining ordinary broadcasts");
        }
        let overlay_type = OverlayType::Private {
            key: overlay_key.clone(), use_quic: options.use_quic,
            bcast_check: None, fixed_member_list: true, twostep_enabled,
        };
        self.add_typed_private_overlay_with_rules(overlay_type, params, peers, Some(rules))
    }

    /// Add private peers to ADNL layer
    pub fn add_private_peers_to_adnl(
        &self,
        local_adnl_key: &Arc<KeyId>,
        peers: Vec<(IpAddress, Option<IpAddress>, Arc<dyn KeyOption>)>,
    ) -> Result<Vec<Arc<KeyId>>> {
        let mut ret = Vec::new();
        for (ip, quic_ip, key) in peers {
            if let Some(peer) = self.adnl.add_peer(local_adnl_key, &ip, quic_ip.as_ref(), &key)? {
                ret.push(peer)
            }
        }
        Ok(ret)
    }

    /// Add public overlay peer
    pub fn add_public_peer<N1: Borrow<NodeV1>, N2: Borrow<NodeV2>>(
        &self,
        peer_ip_address: &IpAddress,
        peer: &OverlayNodeInfo<N1, N2>,
        overlay_id: &Arc<OverlayShortId>,
    ) -> Result<Option<Arc<KeyId>>> {
        self.add_public_peer_impl(Some(peer_ip_address), peer, overlay_id)
    }

    /// Reuse only an address already known under this overlay's local ADNL key.
    /// The signed advertisement and membership certificate still pass through
    /// the ordinary admission checks, even when no DHT lookup is necessary.
    pub fn add_public_peer_from_known_adnl<N1: Borrow<NodeV1>, N2: Borrow<NodeV2>>(
        &self,
        peer: &OverlayNodeInfo<N1, N2>,
        overlay_id: &Arc<OverlayShortId>,
    ) -> Result<Option<Arc<KeyId>>> {
        self.add_public_peer_impl(None, peer, overlay_id)
    }

    fn add_public_peer_impl<N1: Borrow<NodeV1>, N2: Borrow<NodeV2>>(
        &self,
        peer_ip_address: Option<&IpAddress>,
        peer: &OverlayNodeInfo<N1, N2>,
        overlay_id: &Arc<OverlayShortId>,
    ) -> Result<Option<Arc<KeyId>>> {
        let overlay = self.get_overlay(overlay_id, "Trying add peer to unknown public overlay")?;
        if overlay.overlay_type.is_private() {
            fail!("Trying to add public peer to private overlay {overlay_id}")
        }
        let (key, verify) = match peer {
            OverlayNodeInfo::V1(peer) => {
                let peer = peer.borrow();
                let key = peer.get_key()?;
                if overlay.overlay_type.has_certified_members() {
                    let cert = match &peer.certificate {
                        MemberCertificateBoxed::Overlay_MemberCertificate(cert) => Some(cert),
                        _ => None,
                    };
                    overlay.check_peer(key.id(), cert)?;
                }
                (key, OverlayUtils::verify_node(overlay_id, peer))
            }
            OverlayNodeInfo::V2(peer) => {
                let peer = peer.borrow();
                let key = peer.get_key()?;
                if overlay.overlay_type.has_certified_members() {
                    let cert = match &peer.certificate {
                        MemberCertificateBoxed::Overlay_MemberCertificate(cert) => Some(cert),
                        _ => None,
                    };
                    overlay.check_peer(key.id(), cert)?;
                }
                (key, OverlayUtils::verify_node(overlay_id, peer))
            }
        };
        if let Err(e) = verify {
            log::warn!(target: TARGET, "Error when verifying overlay peer {}: {e}", key.id());
            return Ok(None);
        }
        let local_key = overlay.overlay_key().unwrap_or(&self.node_key).id();
        let ret = if let Some(address) = peer_ip_address {
            let Some(ret) = self.adnl.add_peer(local_key, address, None, &key)? else {
                return Ok(None);
            };
            ret
        } else {
            if self.adnl.peer_ip_address(local_key, key.id())?.is_none() {
                return Ok(None);
            }
            key.id().clone()
        };
        overlay.known_peers.add(&ret)?;
        // if overlay.random_peers.count() < Self::MAX_OVERLAY_PEERS {
        //     overlay.random_peers.put(ret.clone())?;
        // }
        if overlay.neighbours.count() < Self::MAX_OVERLAY_NEIGHBOURS {
            overlay.neighbours.put(ret.clone())?;
        }
        add_counted_object_to_map_with_update(&overlay.nodes, ret.clone(), |old_node| {
            if let Some(old_node) = old_node {
                let (old_version, new_version) = match peer {
                    OverlayNodeInfo::V1(peer) => {
                        (old_node.v1.as_ref().map(|node| node.version), peer.borrow().version)
                    }
                    OverlayNodeInfo::V2(peer) => {
                        (old_node.v2.as_ref().map(|node| node.version), peer.borrow().version)
                    }
                };
                if let Some(old_version) = old_version {
                    if old_version >= new_version {
                        return Ok(None);
                    }
                }
            }
            let ret = match peer {
                OverlayNodeInfo::V1(peer) => NodeObject {
                    v1: Some(Arc::new(peer.borrow().clone())),
                    v2: old_node.map(|node| node.v2.clone()).flatten(),
                    counter: self.allocated.peers.clone().into(),
                },
                OverlayNodeInfo::V2(peer) => NodeObject {
                    v1: old_node.map(|node| node.v1.clone()).flatten(),
                    v2: Some(Arc::new(peer.borrow().clone())),
                    counter: self.allocated.peers.clone().into(),
                },
            };
            #[cfg(feature = "telemetry")]
            self.telemetry.peers.update(self.allocated.peers.load(Ordering::Relaxed));
            Ok(Some(ret))
        })?;
        Ok(Some(ret))
    }

    /// Add semiprivate overlay
    pub fn add_semiprivate_overlay(
        &self,
        params: OverlayParams,
        overlay_key: Option<&Arc<dyn KeyOption>>,
        root_adnl_ids: &[Arc<KeyId>],
        root_public_keys: &[Arc<KeyId>], // Can be empty if overlay created by non-validator
        certificate: Option<MemberCertificate>,
        max_slaves: usize,
        use_quic: bool,
    ) -> Result<bool> {
        let root_adnl_set: HashSet<Arc<KeyId>> = root_adnl_ids.iter().cloned().collect();
        let mut root_public_keys_map = HashMap::with_capacity(root_public_keys.len());
        for pk in root_public_keys {
            root_public_keys_map.insert(pk.clone(), lockfree::map::Map::new());
        }
        let overlay_type = OverlayType::CertifiedMembers {
            bcast_prefix: OverlayUtils::calc_message_prefix(params.overlay_id)?,
            certificate,
            key: overlay_key.cloned(),
            max_slaves,
            root_adnl_ids: root_adnl_set,
            root_public_keys: root_public_keys_map,
            use_quic,
        };
        self.add_typed_private_overlay(overlay_type, params, root_adnl_ids)
    }

    /// Broadcast message
    pub async fn broadcast(
        &self,
        overlay_id: &Arc<OverlayShortId>,
        data: &TaggedByteSlice<'_>,
        src_key: Option<&Arc<dyn KeyOption>>,
        flags: u32,
        method: AdnlSendMethod,
    ) -> Result<BroadcastSendInfo> {
        self.broadcast_impl(overlay_id, data, src_key, flags, method, false).await
    }

    /// Explicit FEC carrier, including payloads small enough for a simple carrier.
    pub async fn broadcast_fec(
        &self,
        overlay_id: &Arc<OverlayShortId>,
        data: &TaggedByteSlice<'_>,
        src_key: Option<&Arc<dyn KeyOption>>,
        flags: u32,
    ) -> Result<BroadcastSendInfo> {
        self.broadcast_impl(overlay_id, data, src_key, flags, AdnlSendMethod::Fast, true).await
    }

    async fn broadcast_impl(
        &self,
        overlay_id: &Arc<OverlayShortId>,
        data: &TaggedByteSlice<'_>,
        src_key: Option<&Arc<dyn KeyOption>>,
        flags: u32,
        method: AdnlSendMethod,
        force_fec: bool,
    ) -> Result<BroadcastSendInfo> {
        log::trace!(target: TARGET, "Broadcast {} bytes", data.object.len());
        let overlay = self.get_overlay(overlay_id, "Trying broadcast to unknown overlay")?;
        let _lease = overlay.tasks.enter()?;
        let is_fec = force_fec || (matches!(&method, AdnlSendMethod::Fast)
            && data.object.len() > Self::MAX_SIZE_ORDINARY_BROADCAST);
        if is_fec && self.wire_profile == rtos_api::WireProfile::T0
            && overlay.overlay_type.twostep_sender_enabled() && flags & Self::FLAG_BCAST_NO_TWOSTEP == 0 {
            return self.broadcast_twostep(overlay_id, data, src_key, flags, Vec::new()).await;
        }
        let flags = if self.wire_profile == rtos_api::WireProfile::T0 {
            flags & !Self::FLAG_BCAST_NO_TWOSTEP
        } else { flags };
        let src_key = self.calc_src_key_for_broadcast(&overlay, src_key);
        let certificate = overlay.local_certificate(src_key.id());
        let mut ctx = BroadcastSendContext {
            certificate: certificate
                .as_ref()
                .map_or(OverlayCertificateTl::Overlay_EmptyCertificate, |cert| cert.to_tl()),
            data,
            flags,
            overlay: &overlay,
            src_key,
            src_adnl_key_id: overlay.overlay_key().unwrap_or(&self.node_key).id(),
        };
        // Outgoing broadcast auth (C++ `OverlayPrivacyRules`, all paths).
        if let OverlayType::Private { bcast_check: Some(check), .. } = &overlay.overlay_type {
            check.on_send(ctx.src_key.id(), data.object.len())?;
        }
        if !is_fec && self.wire_profile == rtos_api::WireProfile::Legacy {
            // Ignore ANY_SENDER flag for non-FEC broadcasts
            ctx.flags &= !Self::FLAG_BCAST_ANY_SENDER;
        }
        overlay
            .admit_ordinary_send(
                ctx.src_key,
                certificate.as_ref(),
                data.object,
                is_fec,
                (ctx.flags & Self::FLAG_BCAST_ANY_SENDER) != 0,
                self.wire_profile == rtos_api::WireProfile::T0
                    && matches!(method, AdnlSendMethod::Fast),
            )
            .await?;
        if is_fec {
            return BroadcastFecProtocol::for_send(&ctx).send(ctx).await;
        }
        match method {
            AdnlSendMethod::Fast => BroadcastSimpleProtocol.send(ctx).await,
            AdnlSendMethod::Safe => BroadcastStreamSimpleProtocol.send(ctx).await,
        }
    }

    /// Two-step message broadcast
    pub async fn broadcast_twostep(
        &self,
        overlay_id: &Arc<OverlayShortId>,
        data: &TaggedByteSlice<'_>,
        src_key: Option<&Arc<dyn KeyOption>>,
        flags: u32,
        extra: Vec<u8>,
    ) -> Result<BroadcastSendInfo> {
        log::trace!(target: TARGET, "Two-step broadcast {} bytes", data.object.len());
        let overlay =
            self.get_overlay(overlay_id, "Trying two-step broadcast to unknown overlay")?;
        let _lease = overlay.tasks.enter()?;
        let src_key = self.calc_src_key_for_broadcast(&overlay, src_key);
        let ctx = BroadcastSendContext {
            certificate: overlay
                .local_certificate(src_key.id())
                .map_or(OverlayCertificateTl::Overlay_EmptyCertificate, |cert| cert.to_tl()),
            data,
            flags,
            overlay: &overlay,
            src_key,
            src_adnl_key_id: overlay.overlay_key().unwrap_or(&self.node_key).id(),
        };
        // Outgoing broadcast auth (C++ `OverlayPrivacyRules`).
        if let OverlayType::Private { bcast_check: Some(check), .. } = &overlay.overlay_type {
            check.on_send(ctx.src_key.id(), data.object.len())?;
        }
        if self.wire_profile == rtos_api::WireProfile::T0 {
            overlay.admit_ordinary_send(ctx.src_key, overlay.local_certificate(src_key.id()).as_ref(),
                data.object, true, false, true).await?;
        }
        let neighbours = overlay.calc_broadcast_twostep_neighbours();
        let big_data = data.object.len() >= Self::MIN_BYTES_FEC_TWO_STEPS_BROADCAST;
        let reliable = self.wire_profile == rtos_api::WireProfile::T0
            || big_data || overlay.overlay_type.quic_requested();
        let min_nodes = if self.wire_profile == rtos_api::WireProfile::T0 { 5 }
            else { Self::MIN_NODES_FEC_TWO_STEPS_BROADCAST };
        if big_data && neighbours >= min_nodes {
            BroadcastTwostepFecProtocol::for_send(data.object, neighbours, extra, self.wire_profile)?.send(ctx).await
        } else {
            BroadcastTwostepSimpleProtocol::for_send(reliable, extra).send(ctx).await
        }
    }

    /// Calculate overlay ID for public overlay
    pub fn calc_overlay_id(&self, workchain: i32, shard: i64) -> Result<OverlayId> {
        OverlayUtils::calc_overlay_id_with_profile(
            workchain,
            shard,
            &self.zero_state_file_hash,
            self.wire_profile,
        )
    }

    /// Calculate overlay short ID for public overlay
    pub fn calc_overlay_short_id(&self, workchain: i32, shard: i64) -> Result<Arc<OverlayShortId>> {
        OverlayUtils::calc_overlay_short_id_with_profile(
            workchain,
            shard,
            &self.zero_state_file_hash,
            self.wire_profile,
        )
    }

    /// Delete private_overlay
    pub fn delete_private_overlay(&self, overlay_id: &Arc<OverlayShortId>) -> Result<bool> {
        self.delete_overlay(overlay_id, true)
    }

    /// Capture a generation before starting teardown. Keep this receipt for
    /// repeated waiters; an old receipt can never remove a replacement overlay.
    pub fn overlay_generation(&self, id: &Arc<OverlayShortId>) -> Result<OverlayShutdown> {
        let overlay = self.get_overlay(id, "Capturing unknown overlay generation")?;
        Ok(OverlayShutdown { id: id.clone(), tasks: overlay.tasks.clone() })
    }

    pub async fn delete_private_overlay_checked(
        &self,
        generation: &OverlayShutdown,
    ) -> Result<bool> {
        self.delete_overlay_checked(generation, true).await
    }
    pub async fn delete_public_overlay_checked(
        &self,
        generation: &OverlayShutdown,
    ) -> Result<bool> {
        self.delete_overlay_checked(generation, false).await
    }
    async fn delete_overlay_checked(
        &self,
        generation: &OverlayShutdown,
        private: bool,
    ) -> Result<bool> {
        let removed = {
            let _generation = self.generations.lock().unwrap();
            let same = self
                .overlays
                .get(&generation.id)
                .is_some_and(|current| Arc::ptr_eq(&current.val().tasks, &generation.tasks));
            if same {
                self.delete_overlay_locked(&generation.id, private)?
            } else if generation.tasks.is_closed() {
                false
            } else {
                fail!("Overlay generation belongs to a different owner");
            }
        };
        generation.tasks.wait().await?;
        Ok(removed)
    }

    /// Delete public_overlay
    pub fn delete_public_overlay(&self, overlay_id: &Arc<OverlayShortId>) -> Result<bool> {
        self.delete_overlay(overlay_id, false)
    }

    /// Delete private overlay peers
    pub fn delete_private_peers(
        &self,
        local_key: &Arc<KeyId>,
        peers: &[Arc<KeyId>],
    ) -> Result<bool> {
        let mut ret = false;
        for peer in peers {
            ret = self.adnl.delete_peer(local_key, peer)? || ret
        }
        Ok(ret)
    }

    /// Delete public overlay peer
    pub fn delete_public_peer(
        &self,
        peer: &Arc<KeyId>,
        overlay_id: &Arc<OverlayShortId>,
    ) -> Result<bool> {
        let overlay =
            self.get_overlay(overlay_id, "Trying to delete peer from unknown public overlay")?;
        if overlay.overlay_type.is_private() {
            fail!("Trying to delete public peer from private overlay {}", overlay_id)
        }
        if !overlay.known_peers.block(peer)? {
            return Ok(false);
        }
        // if overlay.random_peers.contains(peer) {
        //     overlay.update_random_peers(Self::MAX_OVERLAY_PEERS)?
        // }
        if overlay.neighbours.contains(peer) {
            overlay.update_neighbours(1)?
        }
        if overlay.plumtree.get().is_some() {
            overlay.plumtree_engine()?.remove_peer(*peer.data());
        }
        // DO NOT DELETE from ADNL, because it may be shared between overlays
        // self.adnl.delete_peer(self.node_key.id(), peer)
        Ok(true)
    }

    /// Get debug trace
    pub fn get_debug_trace(&self, overlay_id: &Arc<OverlayShortId>) -> Result<u32> {
        let overlay = self.get_overlay(overlay_id, "Getting trace from unknown overlay")?;
        Ok(overlay.debug_trace.load(Ordering::Relaxed))
    }

    /// Get locally cached random peers
    pub fn get_cached_random_peers(
        &self,
        dst: &AddressCache,
        overlay_id: &Arc<OverlayShortId>,
        n: u32,
    ) -> Result<()> {
        let overlay =
            self.get_overlay(overlay_id, "Getting cached random peers from unknown overlay")?;
        overlay.known_peers.random_set(dst, n)
    }

    /// Get query prefix
    pub fn get_query_prefix(&self, overlay_id: &Arc<OverlayShortId>) -> Result<Vec<u8>> {
        let overlay = self.get_overlay(overlay_id, "Getting query prefix of unknown overlay")?;
        Ok(overlay.query_prefix.clone())
    }

    /// Get signed node
    pub fn get_signed_node(
        &self,
        overlay_id: &Arc<OverlayShortId>,
        v2: bool,
    ) -> Result<OverlayNodeInfo<NodeV1, NodeV2>> {
        let overlay = self.get_overlay(
            overlay_id,
            format!("Signing local {} node for unknown overlay", Self::version_str(v2)).as_str(),
        )?;
        overlay.get_signed_node(&self.node_key, v2)
    }

    /// Check whether peer is known
    pub fn have_peer(&self, local_key: Option<&Arc<KeyId>>, peer: &Arc<KeyId>) -> Result<bool> {
        let local_key = local_key.unwrap_or(self.node_key.id());
        self.adnl.have_peer(local_key, peer)
    }

    /// Send message via ADNL
    pub async fn message(
        &self,
        dst: &Arc<KeyId>,
        data: &TaggedByteSlice<'_>,
        overlay_id: &Arc<OverlayShortId>,
    ) -> Result<()> {
        let overlay = self.get_overlay(overlay_id, "Overlay admission")?;
        let _lease = overlay.tasks.enter()?;
        #[cfg(test)]
        self.pause_after_send_admission().await;
        #[cfg(feature = "telemetry")]
        let tag = data.tag;
        let (peers, data) = self
            .prepare_to_send_message(dst, data, &overlay, "Sending ADNL message to unknown overlay")
            .await?;
        self.adnl
            .send_custom(
                &TaggedByteSlice {
                    object: &data,
                    #[cfg(feature = "telemetry")]
                    tag,
                },
                &peers,
            )
            .await
    }

    /// Send message via QUIC
    pub async fn message_via_quic(
        &self,
        dst: &Arc<KeyId>,
        data: &TaggedByteSlice<'_>,
        overlay_id: &Arc<OverlayShortId>,
    ) -> Result<()> {
        let overlay = self.get_overlay(overlay_id, "Overlay admission")?;
        let _lease = overlay.tasks.enter()?;
        #[cfg(test)]
        self.pause_after_send_admission().await;
        let Some(quic) = self.quic.get() else {
            fail!("QUIC sender is not set in overlay node");
        };
        let (peers, data) = self
            .prepare_to_send_message(dst, data, &overlay, "Sending QUIC message to unknown overlay")
            .await?;
        tokio::select! {
            biased;
            _ = overlay.tasks.cancelled() => fail!("Overlay retired during QUIC message"),
            result = quic.message(data, Some(&self.adnl), &peers) => { result?; },
        }
        Ok(())
    }

    /// Send message via RLDP
    pub async fn message_via_rldp(
        &self,
        dst: &Arc<KeyId>,
        data: &TaggedByteSlice<'_>,
        overlay_id: &Arc<OverlayShortId>,
        v2: bool,
        roundtrip: Option<u64>,
    ) -> Result<u64> {
        let overlay = self.get_overlay(overlay_id, "Overlay admission")?;
        let _lease = overlay.tasks.enter()?;
        #[cfg(test)]
        self.pause_after_send_admission().await;
        #[cfg(feature = "telemetry")]
        let tag = data.tag;
        let (peers, data) = self
            .prepare_to_send_message(dst, data, &overlay, "Sending RLDP message to unknown overlay")
            .await?;
        let Some(rldp) = self.rldp.get() else {
            fail!("RLDP sender is not set in overlay node");
        };
        rldp.message(
            &TaggedByteSlice {
                object: &data,
                #[cfg(feature = "telemetry")]
                tag,
            },
            &peers,
            v2,
            roundtrip,
        )
        .await
    }

    /// Send query via ADNL
    pub async fn query(
        &self,
        dst: &Arc<KeyId>,
        query: &TaggedTlObject,
        overlay_id: &Arc<OverlayShortId>,
        timeout_ms: Option<u64>,
    ) -> Result<Option<TLObject>> {
        let overlay = self.get_overlay(overlay_id, "Overlay admission")?;
        let _lease = overlay.tasks.enter()?;
        #[cfg(test)]
        self.pause_after_send_admission().await;
        let (peers, overlay) = self
            .prepare_to_send(
                dst,
                &overlay,
                "Sending ADNL query to unknown overlay",
                #[cfg(feature = "telemetry")]
                query.tag,
            )
            .await?;
        Ok(self
            .adnl
            .query_with_prefix_profile_get_status(
                Some(&overlay.query_prefix),
                query,
                &peers,
                timeout_ms,
                crate::node::AdnlSendMethod::Fast,
                self.wire_profile,
            )
            .await?
            .reply)
    }

    /// Send query via QUIC
    pub async fn query_via_quic(
        &self,
        dst: &Arc<KeyId>,
        query: &TaggedTlObject,
        overlay_id: &Arc<OverlayShortId>,
        timeout_ms: Option<u64>,
    ) -> Result<Option<TLObject>> {
        let overlay = self.get_overlay(overlay_id, "Overlay admission")?;
        let _lease = overlay.tasks.enter()?;
        #[cfg(test)]
        self.pause_after_send_admission().await;
        let Some(quic) = self.quic.get() else {
            fail!("QUIC sender is not set in overlay node");
        };
        let (peers, overlay) = self
            .prepare_to_send(
                dst,
                &overlay,
                "Sending QUIC query to unknown overlay",
                #[cfg(feature = "telemetry")]
                query.tag,
            )
            .await?;
        let mut data = overlay.query_prefix.clone();
        self.wire_profile.serialize_append(&mut data, &query.object)?;
        let response = tokio::select! {
            biased;
            _ = overlay.tasks.cancelled() => fail!("Overlay retired during QUIC query"),
            result = quic.query(data, Some(&self.adnl), &peers, timeout_ms) => result?,
        };
        match response {
            Some(raw) => Ok(Some(match self.wire_profile {
                rtos_api::WireProfile::Legacy => deserialize_boxed(&raw)?,
                profile => profile.deserialize(&raw)?,
            })),
            None => Ok(None),
        }
    }

    /// Send query via RLDP
    pub async fn query_via_rldp(
        &self,
        dst: &Arc<KeyId>,
        data: &TaggedByteSlice<'_>,
        overlay_id: &Arc<OverlayShortId>,
        max_answer_size: Option<u64>,
        v2: bool,
        roundtrip: Option<u64>,
    ) -> Result<(Option<Vec<u8>>, u64)> {
        let overlay = self.get_overlay(overlay_id, "Overlay admission")?;
        let _lease = overlay.tasks.enter()?;
        #[cfg(test)]
        self.pause_after_send_admission().await;
        let (peers, _) = self
            .prepare_to_send(
                dst,
                &overlay,
                "Sending RLDP query to unknown overlay",
                #[cfg(feature = "telemetry")]
                data.tag,
            )
            .await?;
        let Some(rldp) = self.rldp.get() else {
            fail!("RLDP sender is not set in overlay node");
        };
        rldp.query(data, max_answer_size, &peers, v2, roundtrip).await
    }

    /// Send query via RLDP
    pub async fn query_via_rldp_bounded(
        &self,
        dst: &Arc<KeyId>,
        data: &TaggedByteSlice<'_>,
        overlay_id: &Arc<OverlayShortId>,
        limits: crate::rldp::QueryResponseLimits,
        v2: bool,
        roundtrip: Option<u64>,
    ) -> Result<(Option<Vec<u8>>, u64)> {
        let overlay = self.get_overlay(overlay_id, "Overlay admission")?;
        let lease = overlay.tasks.enter()?;
        #[cfg(test)]
        self.pause_after_send_admission().await;
        let (peers, _) = self
            .prepare_to_send(
                dst,
                &overlay,
                "Sending RLDP query to unknown overlay",
                #[cfg(feature = "telemetry")]
                data.tag,
            )
            .await?;
        let Some(rldp) = self.rldp.get() else {
            fail!("RLDP sender is not set in overlay node");
        };
        let rldp = rldp.clone();
        let bytes = data.object.to_vec();
        #[cfg(feature = "telemetry")]
        let tag = data.tag;
        let (tx, rx) = tokio::sync::oneshot::channel();
        overlay.tasks.spawn_admitted("bounded overlay RLDP query", lease, async move {
            let data = TaggedByteSlice {
                object: &bytes,
                #[cfg(feature = "telemetry")]
                tag,
            };
            let result = rldp.query_bounded(&data, limits, &peers, v2, roundtrip).await;
            let _ = tx.send(result);
        });
        rx.await.map_err(|_| error!("Bounded overlay RLDP worker stopped"))?
    }

    /// Enable/disable broadcast retransmit
    pub fn set_broadcast_retransmit(&self, enabled: bool) {
        if enabled {
            self.options
                .fetch_and(!Overlay::OPTION_DISABLE_BROADCAST_RETRANSMIT, Ordering::Relaxed);
        } else {
            self.options.fetch_or(Overlay::OPTION_DISABLE_BROADCAST_RETRANSMIT, Ordering::Relaxed);
        }
    }

    /// Set RLDP sender
    pub fn set_quic(&self, quic: Arc<QuicNode>) -> Result<()> {
        self.quic.set(quic).map_err(|_| error!("QUIC sender already set in overlay node"))
    }

    pub fn set_rldp(&self, rldp: Arc<RldpNode>) -> Result<()> {
        self.rldp.set(rldp).map_err(|_| error!("RLDP sender already set in overlay node"))
    }

    /// Statistics
    #[cfg(feature = "telemetry")]
    pub fn stats(&self) -> Result<()> {
        for overlay in self.overlays.iter() {
            overlay.val().print_stats()?
        }
        Ok(())
    }

    pub fn subscribe_broadcast(
        &self,
        overlay_id: &Arc<OverlayShortId>,
    ) -> Result<BroadcastSubscription> {
        let overlay = self.get_overlay(overlay_id, "Subscribing to unknown overlay")?;
        if overlay.flags & Overlay::FLAG_OVERLAY_OTHER_WORKCHAIN != 0 {
            fail!("Cannot subscribe to an inactive workchain overlay");
        }
        overlay.received_rawbytes.subscribe()?;
        Ok(BroadcastSubscription {
            receiver: overlay.received_rawbytes.clone(),
            overlay_id: overlay_id.clone(),
        })
    }

    /// Wait for broadcast
    pub async fn wait_for_broadcast(
        &self,
        overlay_id: &Arc<OverlayShortId>,
    ) -> Result<Option<BroadcastRecvInfo>> {
        let overlay = self.get_overlay(overlay_id, "Waiting for broadcast in unknown overlay")?;
        let _lease = overlay.tasks.enter()?;
        if (overlay.flags & Overlay::FLAG_OVERLAY_OTHER_WORKCHAIN) != 0 {
            fail!("Waiting for broadcast in overlay from other workchain")
        }
        overlay.received_rawbytes.pop().await
    }

    /// Wait for catchain
    pub async fn wait_for_catchain(
        &self,
        overlay_id: &Arc<OverlayShortId>,
    ) -> Result<Option<(CatchainBlockUpdate, CatchainData, Arc<KeyId>)>> {
        let overlay = self.get_overlay(overlay_id, "Waiting for catchain in unknown overlay")?;
        let _lease = overlay.tasks.enter()?;
        overlay
            .received_catchain
            .as_ref()
            .ok_or_else(|| error!("Waiting for catchain in public overlay {}", overlay_id))?
            .pop()
            .await
    }

    /// Wait for peers
    pub async fn wait_for_peers(
        &self,
        overlay_id: &Arc<OverlayShortId>,
    ) -> Result<Option<Vec<OverlayNodeInfo<NodeV1, NodeV2>>>> {
        let overlay = self.get_overlay(overlay_id, "Waiting for peers in unknown overlay")?;
        let _lease = overlay.tasks.enter()?;
        overlay.received_peers.pop().await
    }

    fn add_overlay(&self, overlay_type: OverlayType, params: OverlayParams) -> Result<bool> {
        let _generation = self.generations.lock().unwrap();
        self.add_overlay_locked(overlay_type, params, None)
    }
    fn add_overlay_locked(
        &self,
        overlay_type: OverlayType,
        params: OverlayParams,
        public_rules: Option<OverlayPrivacyRules>,
    ) -> Result<bool> {
        if public_rules.is_some() && !(overlay_type.is_public() || overlay_type.is_private()) {
            fail!("Privacy rules require a public or fixed-member overlay");
        }
        {
            let mut retired = self.retired.lock().unwrap();
            retired.retain(|_, tasks| tasks.upgrade().is_some_and(|tasks| !tasks.drained()));
        }
        log::debug!(target: TARGET, "Add overlay {} to node", params.overlay_id);
        if !overlay_type.is_public()
            && ((params.flags & Overlay::FLAG_OVERLAY_OTHER_WORKCHAIN) != 0)
        {
            fail!("Cannot create non-public overlay {} for other workchain", params.overlay_id)
        }
        let received_catchain =
            if overlay_type.is_private() { Some(AsyncReceiver::new()) } else { None };
        let (sender_one_time, mut receiver_one_time) = tokio::sync::mpsc::unbounded_channel();
        #[cfg(feature = "xp25")]
        let (sender_repeated, mut receiver_repeated) = tokio::sync::mpsc::unbounded_channel();
        let policy = BadPolicy {
            amnesty: Self::MAX_FAIL_COUNT,
            latency: Self::PEER_BLOCK_LATENCY_SEC,
            penalty: 1,
            to_block: Self::MAX_FAIL_COUNT,
        };
        let quic = if overlay_type.quic_requested() { self.quic.get().cloned() } else { None };
        let overlay = Overlay {
            clock: self.clock.clone(),
            broadcast_transport: self.broadcast_transport.get().cloned(),
            consumer: OnceLock::new(),
            tasks: AdnlTasks::with_runtime(
                params.runtime.clone().unwrap_or_else(tokio::runtime::Handle::current),
            ),
            inbound_caps: Arc::new(std::sync::Mutex::new(Vec::new())),
            adnl: self.adnl.clone(),
            rldp: self.rldp.get().cloned(),
            quic,
            wire_profile: self.wire_profile,
            flags: params.flags,
            hops: params.hops,
            known_peers: AddressCacheWithBads::with_params(Self::MAX_PEERS, policy),
            message_prefix: overlay_type.calc_message_prefix(params.overlay_id)?,
            query_prefix: overlay_type.calc_query_prefix(params.overlay_id)?,
            neighbours: AddressCache::with_limit(Self::MAX_OVERLAY_NEIGHBOURS),
            nodes: lockfree::map::Map::new(),
            options: self.options.clone(),
            overlay_id: params.overlay_id.clone(),
            overlay_type,
            owned_broadcasts: lockfree::map::Map::new(),
            plumtree: OnceLock::new(),
            member_flags: AtomicU32::new(0),
            permanent_member_flags: AtomicU32::new(0),
            verifier: Arc::new(privacy::BroadcastVerifier::default()),
            public_policy: public_rules.map(privacy::PublicBroadcastPolicy::new),
            certificates: std::sync::RwLock::new(HashMap::new()),
            pending_peers: lockfree::queue::Queue::new(),
            purge_broadcasts: lockfree::queue::Queue::new(),
            purge_broadcasts_count: AtomicU32::new(0),
            queue_one_time_broadcasts: sender_one_time,
            #[cfg(feature = "xp25")]
            queue_repeated_broadcasts: sender_repeated,
            // random_peers: AddressCache::with_limit(Self::MAX_OVERLAY_PEERS),
            received_catchain,
            received_peers: AsyncReceiver::new(),
            received_rawbytes: AsyncReceiver::new(),
            #[cfg(feature = "telemetry")]
            start: Instant::now(),
            #[cfg(feature = "telemetry")]
            print: AtomicU64::new(0),
            #[cfg(feature = "telemetry")]
            messages_recv: AtomicU64::new(0),
            #[cfg(feature = "telemetry")]
            messages_send: AtomicU64::new(0),
            #[cfg(feature = "telemetry")]
            stats_per_peer_recv: lockfree::map::Map::new(),
            #[cfg(feature = "telemetry")]
            stats_per_peer_send: lockfree::map::Map::new(),
            #[cfg(feature = "telemetry")]
            stats_per_transfer: lockfree::map::Map::new(),
            #[cfg(feature = "telemetry")]
            telemetry: self.telemetry.clone(),
            allocated: self.allocated.clone(),
            debug_trace: AtomicU32::new(0),
            counter: self.allocated.overlays.clone().into(),
        };
        #[cfg(feature = "telemetry")]
        self.telemetry.overlays.update(self.allocated.overlays.load(Ordering::Relaxed));
        overlay.update_neighbours(Self::MAX_OVERLAY_NEIGHBOURS)?;
        let overlay = Arc::new(overlay);

        let added = add_counted_object_to_map(&self.overlays, params.overlay_id.clone(), || {
            Ok(overlay.clone())
        })?;
        if added {
            let default_key = self.node_key.clone();
            let overlay = self.get_overlay(params.overlay_id, "Cannot add overlay")?;
            let tasks = overlay.tasks.clone();
            let caps = overlay.inbound_caps.clone();
            let rldp = overlay.rldp.clone();
            let weak_tasks = Arc::downgrade(&tasks);
            tasks.on_stopped(move || {
                if let Some(rldp) = rldp {
                    let caps = std::mem::take(&mut *caps.lock().unwrap());
                    if let Err(error) = rldp.change_inbound_cap_for_peers(&caps, -1) {
                        if let Some(tasks) = weak_tasks.upgrade() {
                            tasks.failed(format!("Overlay inbound cap cleanup: {error}"));
                        }
                    }
                }
            });
            tasks.spawn_cancelable("overlay maintenance", async move {
                let local_adnl_key = if !overlay.overlay_type.is_public() {
                    Some(overlay.overlay_key().unwrap_or(&default_key).id())
                } else {
                    None
                };
                let base_tick_ms = Self::TIMEOUT_BROADCAST_GC_MS
                    .min(Self::TIMEOUT_NEIGHBOURS_MS)
                    .min(Self::TIMEOUT_PING_MS);
                let mut timeout_broadcast_gc = 0;
                let mut timeout_neighbours = 0;
                let mut timeout_pending_peers = 0;
                let mut timeout_ping = 0;
                let mut has_pending = local_adnl_key.is_some();
                let mut last_one_time_broadcast = None;
                #[cfg(feature = "xp25")]
                let mut last_repeated_broadcast = None;
                let mut next_ping = None;
                while Arc::strong_count(&overlay) > 1 {
                    let mut tick_ms = if has_pending {
                        base_tick_ms.min(Self::TIMEOUT_PENDING_PEERS_MS)
                    } else {
                        base_tick_ms
                    };
                    // An empty pass only chooses the idle cadence. Creation or
                    // address discovery may enqueue an authorized peer later.
                    has_pending = local_adnl_key.is_some();
                    if timeout_broadcast_gc >= Self::TIMEOUT_BROADCAST_GC_MS {
                        timeout_broadcast_gc = 0;
                        overlay
                            .purge_broadcasts(
                                &mut last_one_time_broadcast,
                                &mut receiver_one_time,
                                #[cfg(feature = "xp25")]
                                &mut last_repeated_broadcast,
                                #[cfg(feature = "xp25")]
                                &mut receiver_repeated,
                            )
                            .await;
                    }
                    let mut update_neighbours = timeout_neighbours >= Self::TIMEOUT_NEIGHBOURS_MS;
                    if has_pending && (timeout_pending_peers >= Self::TIMEOUT_PENDING_PEERS_MS) {
                        timeout_pending_peers = 0;
                        if let Some(key) = &local_adnl_key {
                            let mut pending = Vec::new();
                            while let Some(peer) = overlay.pending_peers.pop() {
                                pending.push(peer);
                            }
                            if pending.is_empty() {
                                has_pending = false;
                            }
                            for peer in pending {
                                match overlay.try_add_peer(key, &peer) {
                                    Ok(true) => {
                                        log::info!(
                                            target: TARGET,
                                            "Resolved pending peer {peer} in overlay {}",
                                            overlay.overlay_id
                                        );
                                        update_neighbours = true;
                                        continue;
                                    }
                                    Err(e) => log::warn!(
                                        target: TARGET,
                                        "Error resolving pending peer {peer} in overlay {}: {e}",
                                        overlay.overlay_id
                                    ),
                                    _ => (),
                                }
                                overlay.pending_peers.push(peer);
                            }
                        }
                    }
                    if update_neighbours {
                        timeout_neighbours = 0;
                        // let result = if overlay.overlay_type.is_private() {
                        //     overlay.update_neighbours(1)
                        // } else {
                        //     overlay.update_random_peers(1)
                        // };
                        // if let Err(e) = result {
                        if let Err(e) = overlay.update_neighbours(1) {
                            log::error!(target: TARGET, "Error: {}", e)
                        }
                    }
                    let elapsed_ms = if timeout_ping >= Self::TIMEOUT_PING_MS {
                        timeout_ping = 0;
                        let peer = if let Some(iter) = next_ping.as_mut() {
                            overlay.known_peers.all().next(iter)
                        } else {
                            let (iter, peer) = overlay.known_peers.all().first();
                            next_ping.replace(iter);
                            peer
                        };
                        if let Some(peer) = peer {
                            let query_start = std::time::Instant::now();
                            let ping_task =
                                overlay.ping_peer(&default_key, &peer, Self::TIMEOUT_PING_MS);
                            let (ping_res, peers_res) = if overlay.overlay_type.is_private() {
                                (ping_task.await, None)
                            } else {
                                let v2 = overlay.use_v2_peer_advertisements();
                                let peers_task = overlay.get_random_peers(
                                    &peer,
                                    &default_key,
                                    v2,
                                    Some(Self::TIMEOUT_PING_MS),
                                );
                                let (ping_res, peers_res) = tokio::join!(ping_task, peers_task);
                                (ping_res, Some(peers_res))
                            };
                            if let Err(e) = ping_res {
                                log::info!(target: TARGET, "Error in overlay ping {peer}: {e}");
                            }
                            if let Some(Err(e)) = peers_res {
                                log::info!(
                                    target: TARGET,
                                    "Error get random peers from {peer}: {e}"
                                );
                            }
                            query_start.elapsed().as_millis() as u64
                        } else {
                            next_ping = None;
                            0
                        }
                    } else {
                        0
                    };
                    let sleep_ms = tick_ms.saturating_sub(elapsed_ms);
                    if sleep_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
                    } else {
                        tick_ms = elapsed_ms;
                    }
                    timeout_broadcast_gc += tick_ms;
                    timeout_neighbours += tick_ms;
                    timeout_pending_peers += tick_ms;
                    timeout_ping += tick_ms;
                }
            });
        }
        Ok(added)
    }

    fn add_peers_to_overlay(
        &self,
        overlay_id: &Arc<OverlayShortId>,
        peers: &[Arc<KeyId>],
        msg: &str,
    ) -> Result<usize> {
        let overlay = self.get_overlay(overlay_id, msg)?;
        let our_key = overlay.overlay_key().unwrap_or(&self.node_key).id();
        let mut ret = 0;
        for peer in peers {
            if peer == our_key {
                continue;
            }
            if overlay.try_add_peer(our_key, peer)? {
                ret += 1;
            } else {
                log::info!(
                    target: TARGET,
                    "Peer {peer} has no ADNL address yet in overlay {}, queued for later",
                    overlay.overlay_id
                );
                overlay.pending_peers.push(peer.clone());
            }
        }
        overlay.update_neighbours(Self::MAX_OVERLAY_NEIGHBOURS)?;
        Ok(ret)
    }

    fn add_typed_private_overlay(
        &self,
        overlay_type: OverlayType,
        params: OverlayParams,
        peers: &[Arc<KeyId>],
    ) -> Result<bool> {
        self.add_typed_private_overlay_with_rules(overlay_type, params, peers, None)
    }

    fn add_typed_private_overlay_with_rules(
        &self,
        overlay_type: OverlayType,
        params: OverlayParams,
        peers: &[Arc<KeyId>],
        rules: Option<OverlayPrivacyRules>,
    ) -> Result<bool> {
        let _generation = self.generations.lock().unwrap();
        let overlay_id = params.overlay_id.clone();
        if !self.add_overlay_locked(overlay_type, params, rules)? {
            return Ok(false);
        }
        let initialization = (|| -> Result<()> {
            let overlay = self.get_overlay(&overlay_id, "Private overlay initialization")?;
            let _lease = overlay.tasks.enter()?;
            self.add_peers_to_overlay(&overlay_id, peers, "Cannot add the private overlay")?;
            if let Some(rldp) = self.rldp.get() {
                rldp.change_inbound_cap_for_peers(peers, 1)?;
                let overlay = self.get_overlay(&overlay_id, "Private overlay initialization")?;
                *overlay.inbound_caps.lock().unwrap() = peers.to_vec();
            }
            Ok(())
        })();
        if let Err(error) = initialization {
            let cleanup = self.delete_overlay_locked(&overlay_id, true);
            return Err(error!(
                "Private overlay initialization failed: {error}; rollback: {cleanup:?}"
            ));
        }
        Ok(true)
    }

    fn calc_src_key_for_broadcast<'a>(
        &'a self,
        overlay: &'a Overlay,
        src_key: Option<&'a Arc<dyn KeyOption>>,
    ) -> &'a Arc<dyn KeyOption> {
        if let Some(source) = src_key {
            source
        } else if let Some(key) = overlay.overlay_key() {
            key
        } else {
            &self.node_key
        }
    }

    fn check_overlay_adnl_address(&self, overlay: &Arc<Overlay>, adnl: &Arc<KeyId>) -> bool {
        let local_adnl = overlay.overlay_key().unwrap_or(&self.node_key).id();
        if local_adnl != adnl {
            log::debug!(
                target: TARGET,
                "Bad destination ADNL address in overlay {}: expected {local_adnl}, got {adnl}",
                overlay.overlay_id
            );
            false
        } else {
            true
        }
    }

    fn check_fec_broadcast_message(message: &BroadcastFec) -> Result<()> {
        const CONSTRAINTS: Constraints = Constraints {
            data_size: 32 << 20, // NOTE: 32 MB is the max reasonable data size due to
                                 // the default decoder block count assumption.
        };
        CONSTRAINTS.check_fec_type(&message.fec)?;
        CONSTRAINTS.check_data_size(message.data_size)?;
        Constraints::check_seqno(message.seqno as u32)
    }

    /// The peer's structural FEC limits on overlays with privacy rules.
    fn check_public_fec_broadcast_message(message: &BroadcastFec) -> Result<()> {
        let FecType::Fec_RaptorQ(fec) = &message.fec else {
            fail!("Unsupported FEC type");
        };
        if fec.data_size as u32 > MAX_FEC_BROADCAST_SIZE {
            fail!("Too big FEC broadcast: {} bytes", fec.data_size as u32);
        }
        if fec.data_size != message.data_size {
            fail!("FEC data size mismatch: {} vs {}", fec.data_size, message.data_size);
        }
        if (message.seqno as u32 as u64) >= (fec.symbols_count as u32 as u64) * 2 + 4 {
            fail!("Too big FEC seqno {}", message.seqno as u32);
        }
        Ok(())
    }

    fn delete_overlay(&self, overlay_id: &Arc<OverlayShortId>, is_private: bool) -> Result<bool> {
        let _generation = self.generations.lock().unwrap();
        self.delete_overlay_locked(overlay_id, is_private)
    }
    fn delete_overlay_locked(
        &self,
        overlay_id: &Arc<OverlayShortId>,
        is_private: bool,
    ) -> Result<bool> {
        let type_of = if is_private { "private" } else { "public" };
        log::info!(target: TARGET, "Delete {} overlay {}", type_of, overlay_id);
        if let Some(overlay) = self.overlays.get(overlay_id) {
            let overlay = overlay.val();
            if is_private {
                if !overlay.overlay_type.is_private() {
                    fail!("Try to delete non-private overlay {} as private", overlay_id)
                }
                if let Some(received_catchain) = overlay.received_catchain.as_ref() {
                    received_catchain.stop();
                }
            } else if overlay.overlay_type.is_private() {
                fail!("Try to delete private overlay {} as public", overlay_id)
            }
            overlay.tasks.close();
            self.retired.lock().unwrap().insert(overlay_id.clone(), Arc::downgrade(&overlay.tasks));
            if let Some(transport) = overlay.plumtree.get() {
                transport.stopped.store(true, Ordering::Release);
            }
            overlay.received_peers.stop();
            overlay.received_rawbytes.stop();
            self.overlays.remove(overlay_id);
            log::debug!(target: TARGET, "Delete consumer {} from {} overlay", overlay_id, type_of);
            self.consumers.remove(overlay_id);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn get_overlay(&self, overlay_id: &Arc<OverlayShortId>, msg: &str) -> Result<Arc<Overlay>> {
        let ret = self
            .overlays
            .get(overlay_id)
            .ok_or_else(|| error!("{} {}", msg, overlay_id))?
            .val()
            .clone();
        Ok(ret)
    }

    async fn prepare_to_send(
        &self,
        dst: &Arc<KeyId>,
        overlay: &Arc<Overlay>,
        _err_msg: &str,
        #[cfg(feature = "telemetry")] tag: u32,
    ) -> Result<(AdnlPeers, Arc<Overlay>)> {
        let peers = overlay
            .prepare_to_send(
                dst,
                &self.node_key,
                #[cfg(feature = "telemetry")]
                tag,
            )
            .await?;
        Ok((peers, overlay.clone()))
    }

    async fn prepare_to_send_message(
        &self,
        dst: &Arc<KeyId>,
        data: &TaggedByteSlice<'_>,
        overlay: &Arc<Overlay>,
        _err_msg: &str,
    ) -> Result<(AdnlPeers, Vec<u8>)> {
        let (peers, overlay) = self
            .prepare_to_send(
                dst,
                overlay,
                _err_msg,
                #[cfg(feature = "telemetry")]
                data.tag,
            )
            .await?;
        let mut buf = overlay.message_prefix.clone();
        buf.extend_from_slice(data.object);
        Ok((peers, buf))
    }

    fn process_get_random_peers<T: NodeData>(
        &self,
        overlay: &Overlay,
        peers: Vec<T>,
        convert: impl Fn(T) -> OverlayNodeInfo<NodeV1, NodeV2>,
        v2: bool,
    ) -> Result<Option<Nodes>> {
        log::trace!(target: TARGET, "Got random peers {} request", Self::version_str(v2));
        let peers = overlay.process_random_peers(&self.node_key, peers, convert)?;
        overlay.received_peers.push(peers);
        if (overlay.flags & Overlay::FLAG_OVERLAY_OTHER_WORKCHAIN) != 0 {
            Ok(None)
        } else {
            Ok(Some(overlay.prepare_random_peers(&self.node_key, v2)?))
        }
    }

    fn version_str(v2: bool) -> &'static str {
        if v2 {
            "V2"
        } else {
            "V1"
        }
    }
}

#[async_trait::async_trait]
impl Subscriber for OverlayNode {
    #[cfg(feature = "telemetry")]
    async fn poll(&self, _start: &Arc<Instant>) {
        self.telemetry.consumers.update(self.allocated.consumers.load(Ordering::Relaxed));
        self.telemetry.overlays.update(self.allocated.overlays.load(Ordering::Relaxed));
        self.telemetry.peers.update(self.allocated.peers.load(Ordering::Relaxed));
        self.telemetry.recv_transfers.update(self.allocated.recv_transfers.load(Ordering::Relaxed));
        self.telemetry.send_transfers.update(self.allocated.send_transfers.load(Ordering::Relaxed));
        self.telemetry.stats_peer.update(self.allocated.stats_peer.load(Ordering::Relaxed));
        self.telemetry.stats_transfer.update(self.allocated.stats_transfer.load(Ordering::Relaxed));
        for overlay in self.overlays.iter() {
            overlay.val().try_print_stats();
        }
    }

    async fn try_consume_custom(&self, data: &[u8], peers: &AdnlPeers) -> Result<bool> {
        let Ok((prefix, suffix_offset)) = deserialize_boxed_with_suffix(&data) else {
            return Ok(false); // Not a TL-prefixed message — let next subscriber try
        };
        let (overlay_id, certificate) = match prefix.downcast::<OverlayMessageBoxed>() {
            Ok(msg) => {
                let id = OverlayShortId::from_data(msg.overlay().as_slice().clone());
                let certificate = if let OverlayMessageBoxed::Overlay_MessageWithExtra(msg) = msg {
                    match msg.extra.certificate {
                        Some(MemberCertificateBoxed::Overlay_MemberCertificate(cert)) => Some(cert),
                        _ => None,
                    }
                } else {
                    None
                };
                (id, certificate)
            }
            Err(_) => return Ok(false),
        };
        if suffix_offset == data.len() && !self.overlays.get(&overlay_id)
            .is_some_and(|entry| entry.val().overlay_type.is_fixed_member_list()) {
            log::warn!("Empty message in overlay {overlay_id}");
            return Ok(true);
        }
        let overlay = self.get_overlay(&overlay_id, "Message to unknown overlay")?;
        let _lease = overlay.tasks.enter()?;
        #[cfg(test)]
        self.pause_after_receive_admission().await;
        if (overlay.flags & Overlay::FLAG_OVERLAY_OTHER_WORKCHAIN) != 0 {
            return Ok(true);
        }
        if !self.check_overlay_adnl_address(&overlay, peers.local()) {
            return Ok(true);
        }
        if let Err(e) = overlay.check_peer(peers.other(), certificate.as_ref()) {
            log::warn!(
                target: TARGET,
                "Error checking peer {} in overlay {overlay_id}: {e}",
                peers.other()
            );
            return Ok(true);
        }
        if overlay.verifier.is_peer_banned(peers.other()) {
            log::debug!(
                target: TARGET,
                "Message from temporarily banned peer {} in overlay {overlay_id}",
                peers.other()
            );
            return Ok(true);
        }

        let suffix = &data[suffix_offset..];
        let consumer = if let Some(consumer) = overlay.consumer.get() {
            let consumer = consumer.clone();
            if overlay.overlay_type.is_private() && !overlay.overlay_type.is_fixed_member_list() {
                match consumer.try_consume_custom(suffix, peers).await {
                    Err(e) => {
                        log::warn!("Unsupported custom data in overlay {overlay_id}: {e}");
                        return Ok(true);
                    }
                    Ok(true) => {
                        #[cfg(feature = "telemetry")]
                        let tag = if suffix.len() < 4 {
                            0
                        } else {
                            u32::from_le_bytes([suffix[0], suffix[1], suffix[2], suffix[3]])
                        };
                        #[cfg(feature = "telemetry")]
                        overlay.update_stats(peers.other(), tag, false)?;
                        return Ok(true);
                    }
                    _ => (),
                }
            }
            Some(consumer)
        } else {
            None
        };

        let (first, mut postfix_offset) = match self.wire_profile.deserialize_with_suffix(suffix) {
            Ok(value) => value,
            Err(error) => {
                if overlay.overlay_type.is_fixed_member_list() {
                    if let Some(consumer) = &consumer {
                        return consumer.try_consume_custom(suffix, peers).await;
                    }
                }
                return Err(error);
            }
        };
        // A fixed-member overlay hands opaque application messages through raw.
        // Catchain bundles/hop postfixes belong to the older private profile.
        if overlay.overlay_type.is_fixed_member_list()
            && (!first.is::<Broadcast>() || postfix_offset != suffix.len()) {
            if let Some(consumer) = &consumer {
                return consumer.try_consume_custom(suffix, peers).await;
            }
            fail!("No dedicated consumer for custom fixed-member overlay message");
        }
        let mut second: Option<TLObject> = None;
        let mut have_postfix = false;
        if postfix_offset < suffix.len() {
            if let Ok((s, pos2)) =
                self.wire_profile.deserialize_with_suffix(&suffix[postfix_offset..])
            {
                second = Some(s);
                postfix_offset += pos2;
            }
            if postfix_offset < suffix.len() {
                if postfix_offset + 1 < suffix.len() {
                    return Ok(false);
                }
                have_postfix = true;
            }
        }

        #[cfg(feature = "telemetry")]
        overlay.update_stats(peers.other(), first.bare_object().constructor(), false)?;
        if let Some(second) = second {
            // Catchain/validator session messages in private overlay
            let catchain_update = match first.downcast::<CatchainBlockUpdateBoxed>() {
                Ok(CatchainBlockUpdateBoxed::Catchain_BlockUpdate(upd)) => upd,
                Err(msg) => fail!("Unsupported private overlay message {:?}", msg),
            };
            let inner_update = match second.downcast::<ValidatorSessionBlockUpdateBoxed>() {
                Ok(ValidatorSessionBlockUpdateBoxed::ValidatorSession_BlockUpdate(upd)) => {
                    CatchainData::ValidatorSession(upd)
                }
                Err(msg) => match msg.downcast::<CatchainBlockInnerDataBoxed>() {
                    Ok(CatchainBlockInnerDataBoxed::Catchain_Block_Data_Fork(upd)) => {
                        CatchainData::Catchain(upd)
                    }
                    Ok(msg) => fail!("Unsupported private overlay message {:?}", msg),
                    Err(msg) => fail!("Unsupported private overlay message {:?}", msg),
                },
            };
            let receiver = overlay
                .received_catchain
                .as_ref()
                .ok_or_else(|| error!("No catchain receiver in private overlay {}", overlay_id))?;
            receiver.push((catchain_update, inner_update, peers.other().clone()));
            Ok(true)
        } else {
            let (data, hops) = if have_postfix {
                (&data[..suffix_offset + postfix_offset + 1], Some(suffix[postfix_offset]))
            } else {
                (&data[..suffix_offset + postfix_offset], None)
            };
            // Broadcasts maybe
            let ctx = BroadcastRecvContext {
                data: BroadcastData::Raw(data),
                hops,
                overlay: &overlay,
                peers,
                verdict: BroadcastCheckResult::Allowed,
            };
            // As the reference overlay does, a node whose flags say it receives
            // no broadcasts drops regular broadcasts, and one that receives no
            // Plumtree broadcasts drops Plumtree payloads and announcements.
            let local_flags = overlay.local_member_flags();
            let message = match first.downcast::<Broadcast>() {
                Ok(Broadcast::Overlay_BroadcastFec(_) | Broadcast::Overlay_Broadcast(_))
                    if local_flags & Overlay::MEMBER_DO_NOT_RECEIVE_BROADCASTS != 0 =>
                {
                    return Ok(true);
                }
                Ok(
                    Broadcast::Overlay_BroadcastPlumtreeSimple(_)
                    | Broadcast::Overlay_BroadcastPlumtreeFec(_)
                    | Broadcast::Overlay_BroadcastPlumtreeIHave(_),
                ) if overlay.plumtree.get().is_some()
                    && local_flags & Overlay::MEMBER_PLUMTREE_DENY != 0 =>
                {
                    return Ok(true);
                }
                Ok(Broadcast::Overlay_BroadcastFec(bcast)) => {
                    if let Err(e) = Self::check_fec_broadcast_message(&bcast) {
                        // Ignore invalid messages as early as possible
                        log::warn!(target: TARGET, "Received bad FEC broadcast. {e}");
                        return Ok(true);
                    }
                    if overlay.public_policy.is_some() {
                        if let Err(e) = Self::check_public_fec_broadcast_message(&bcast) {
                            log::warn!(target: TARGET, "Received bad public FEC broadcast. {e}");
                            return Ok(true);
                        }
                    }
                    BroadcastFecProtocol::for_recv().recv(bcast, ctx).await?;
                    return Ok(true);
                }
                Ok(Broadcast::Overlay_Broadcast(bcast)) => {
                    BroadcastSimpleProtocol.recv(bcast, ctx).await?;
                    return Ok(true);
                }
                Ok(Broadcast::Overlay_BroadcastStream(bcast)) => {
                    BroadcastStreamSimpleProtocol.recv(bcast, ctx).await?;
                    return Ok(true);
                }
                Ok(Broadcast::Overlay_BroadcastTwostepFec(_)
                    | Broadcast::Overlay_BroadcastTwostepSimple(_))
                    if !overlay.overlay_type.accepts_twostep() =>
                    fail!("Two-step broadcast is disabled on this overlay"),
                Ok(Broadcast::Overlay_BroadcastTwostepFec(bcast)) => {
                    BroadcastTwostepFecProtocol::for_recv().recv(bcast, ctx).await?;
                    return Ok(true);
                }
                Ok(Broadcast::Overlay_BroadcastTwostepSimple(bcast)) => {
                    let big_data = bcast.data.len() >= Self::MIN_BYTES_FEC_TWO_STEPS_BROADCAST;
                    let reliable = self.wire_profile == rtos_api::WireProfile::T0
                        || big_data || ctx.overlay.overlay_type.quic_requested();
                    BroadcastTwostepSimpleProtocol::for_recv(reliable).recv(bcast, ctx).await?;
                    return Ok(true);
                }
                Ok(bcast) if plumtree::Engine::accepts(&bcast) => {
                    if have_postfix {
                        fail!("Trailing bytes in Plumtree message");
                    }
                    let neighbours = overlay.plumtree_neighbours();
                    let actions = overlay.plumtree_engine()?.receive(
                        *peers.other().data(),
                        bcast,
                        None,
                        &neighbours,
                        overlay.clock.unix_seconds(),
                        Instant::now(),
                    )?;
                    overlay.execute_plumtree(actions).await?;
                    return Ok(true);
                }
                Ok(bcast) => fail!("Unsupported overlay broadcast message {:?}", bcast),
                Err(message) => message,
            };
            // Messages to custom cosnumers
            let Some(consumer) = consumer else {
                fail!("No dedicated consumer for message {message:?} in overlay {overlay_id}")
            };
            match consumer.try_consume_object(message, peers).await {
                Err(message) => fail!("Unsupported message {message} in overlay {overlay_id}"),
                r => r,
            }
        }
    }

    async fn try_consume_raw_query(
        &self,
        bytes: &[u8],
        peers: &AdnlPeers,
    ) -> Result<Option<QueryAnswer>> {
        if self.wire_profile == rtos_api::WireProfile::Legacy {
            return Ok(None);
        }
        // Overlay prefix constructors are unchanged across domains. Only claim
        // actual overlay queries; unrelated ADNL/DHT namespaces remain untouched.
        let Ok((prefix, _)) = deserialize_boxed_with_suffix(bytes) else {
            return Ok(None);
        };
        if !prefix.is::<OverlayQuery>() && !prefix.is::<OverlayQueryWithExtra>() {
            return Ok(None);
        }
        let objects = self.wire_profile.deserialize_bundle(bytes)?;
        match self.try_consume_query_bundle(objects, peers).await? {
            QueryResult::Consumed(answer) => Ok(Some(answer.with_profile(self.wire_profile)?)),
            _ => fail!("Unconsumed query in target overlay namespace"),
        }
    }

    async fn try_consume_query_bundle(
        &self,
        mut objects: Vec<TLObject>,
        peers: &AdnlPeers,
    ) -> Result<QueryResult> {
        if objects.len() != 2 {
            return Ok(QueryResult::RejectedBundle(objects));
        }
        let (overlay_id, certificate) = match objects.remove(0).downcast::<OverlayQuery>() {
            Ok(query) => (OverlayShortId::from_data(query.overlay.inner()), None),
            Err(query) => match query.downcast::<OverlayQueryWithExtra>() {
                Ok(query) => {
                    let cert = match query.extra.certificate {
                        Some(MemberCertificateBoxed::Overlay_MemberCertificate(cert)) => Some(cert),
                        _ => None,
                    };
                    (OverlayShortId::from_data(query.overlay.inner()), cert)
                }
                Err(query) => {
                    objects.insert(0, query);
                    return Ok(QueryResult::RejectedBundle(objects));
                }
            },
        };
        let overlay = if let Some(overlay) = self.overlays.get(&overlay_id) {
            overlay.val().clone()
        } else {
            fail!("Query to unknown overlay {}", overlay_id)
        };
        let _lease = overlay.tasks.enter()?;
        #[cfg(test)]
        self.pause_after_receive_admission().await;
        if !self.check_overlay_adnl_address(&overlay, peers.local()) {
            return Ok(QueryResult::Consumed(QueryAnswer::Ready(None)));
        }
        overlay.check_peer(peers.other(), certificate.as_ref())?;
        if overlay.verifier.is_peer_banned(peers.other()) {
            fail!("Query from temporarily banned peer {} in overlay {overlay_id}", peers.other());
        }

        let other_workchain = (overlay.flags & Overlay::FLAG_OVERLAY_OTHER_WORKCHAIN) != 0;
        #[cfg(feature = "telemetry")]
        if !other_workchain {
            overlay.update_stats(peers.other(), objects[0].bare_object().constructor(), false)?;
        }
        let object = match objects.remove(0).downcast::<GetRandomPeers>() {
            Ok(query) => {
                return match self.process_get_random_peers(
                    &overlay,
                    query.peers.nodes,
                    |node| OverlayNodeInfo::V1(node),
                    false,
                )? {
                    Some(Nodes::V1(answer)) => QueryResult::consume(
                        answer,
                        #[cfg(feature = "telemetry")]
                        None,
                    ),
                    None => Ok(QueryResult::Consumed(QueryAnswer::Ready(None))),
                    _ => fail!("Unexpected V2 answer in V1 query"),
                };
            }
            Err(object) => object,
        };
        let object = match object.downcast::<GetRandomPeersV2>() {
            Ok(query) => {
                return match self.process_get_random_peers(
                    &overlay,
                    query.peers.nodes,
                    |node| OverlayNodeInfo::V2(node),
                    true,
                )? {
                    Some(Nodes::V2(answer)) => QueryResult::consume(
                        answer,
                        #[cfg(feature = "telemetry")]
                        None,
                    ),
                    None => Ok(QueryResult::Consumed(QueryAnswer::Ready(None))),
                    _ => fail!("Unexpected V1 answer in V2 query"),
                };
            }
            Err(object) => object,
        };
        let object = match object.downcast::<rtos_api::ton::rpc::overlay::RepairPlumtreePart>() {
            Ok(query) => {
                if other_workchain {
                    return Ok(QueryResult::Consumed(QueryAnswer::Ready(None)));
                }
                let answer = overlay.plumtree_engine()?.repair_query(
                    *peers.other().data(),
                    query,
                    overlay.clock.unix_seconds(),
                    Instant::now(),
                )?;
                return QueryResult::consume_boxed(
                    answer,
                    #[cfg(feature = "telemetry")]
                    None,
                );
            }
            Err(object) => object,
        };
        let object = match object.downcast::<Ping>() {
            Ok(_query) => {
                return QueryResult::consume_boxed(
                    Pong::Overlay_Pong,
                    #[cfg(feature = "telemetry")]
                    None,
                );
            }
            Err(object) => object,
        };

        if other_workchain {
            return Ok(QueryResult::Consumed(QueryAnswer::Ready(None)));
        }
        let consumer = if let Some(consumer) = overlay.consumer.get() {
            consumer.clone()
        } else {
            fail!(
                "No dedicated consumer for query {object:?} from {} in overlay {overlay_id}",
                peers.other()
            )
        };
        match consumer.try_consume_query(object, peers).await {
            Err(msg) => fail!("Unsupported query {msg} in overlay {overlay_id}"),
            Ok(QueryResult::Consumed(QueryAnswer::Pending(worker))) => {
                let (tx, rx) = tokio::sync::oneshot::channel();
                let response_tasks = overlay.tasks.clone();
                let future = async move {
                    let result = match worker.await {
                        Ok(result) => result,
                        Err(error) => {
                            response_tasks.failed(format!("Overlay response worker: {error}"));
                            Err(error!("Overlay response worker: {error}"))
                        }
                    };
                    let _ = tx.send(result);
                };
                overlay.tasks.spawn_admitted("overlay pending response", _lease, future);
                Ok(QueryResult::Consumed(QueryAnswer::Pending(tokio::spawn(async move {
                    rx.await.map_err(|_| error!("Overlay response owner failed"))?
                }))))
            }
            result => result,
        }
    }
}

struct PlumtreeTransport {
    quic: Arc<QuicNode>,
    engine: std::sync::Mutex<plumtree::Engine>,
    local: Arc<KeyId>,
    original_sender: bool,
    stopped: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
fn plumtree_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(f64::NAN, |d| d.as_secs_f64())
}

impl Overlay {
    fn plumtree_engine(&self) -> Result<std::sync::MutexGuard<'_, plumtree::Engine>> {
        let transport =
            self.plumtree.get().ok_or_else(|| error!("Plumtree is disabled on this overlay"))?;
        if transport.stopped.load(Ordering::Acquire) {
            fail!("Plumtree overlay is retired");
        }
        transport.engine.lock().map_err(|_| error!("Plumtree state lock is poisoned"))
    }

    fn plumtree_neighbours(&self) -> Vec<[u8; 32]> {
        // Public peers must have a fresh authenticated node advertisement.
        let now = Version::get();
        let mut peers = Vec::new();
        let mut iter = None;
        while let Some(peer) = self.known_peers.next(&mut iter) {
            let eligible = if let Some(node) = self.nodes.get(&peer) {
                let pair = node.val().advertisement().map(|(flags, version, _)| (flags, version));
                pair.is_some_and(|(flags, version)| {
                    flags == 0
                        && (!self.overlay_type.is_public()
                            || (version as i64 >= now as i64 - 600
                                && version as i64 <= now as i64 + 60))
                })
            } else {
                // A permanent member that has not advertised itself carries the
                // overlay's default permanent member flags.
                !self.overlay_type.is_public()
                    && self.permanent_member_flags.load(Ordering::Relaxed)
                        & Self::MEMBER_PLUMTREE_DENY
                        == 0
            };
            if eligible && self.check_peer(&peer, None).is_ok() {
                peers.push(*peer.data());
            }
        }
        // Randomize lazy selection without dropping established eager peers
        // that happen not to be among this broadcast's five active neighbours.
        use rand::seq::SliceRandom;
        peers.shuffle(&mut rand::thread_rng());
        peers
    }

    fn execute_plumtree(
        self: &Arc<Self>,
        actions: Vec<plumtree::Action>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async move {
            let transport =
                self.plumtree.get().ok_or_else(|| error!("Plumtree transport is disabled"))?;
            let quic = &transport.quic;
            let mut first_error = None;
            for action in actions {
                if transport.stopped.load(Ordering::Acquire) {
                    fail!("Plumtree overlay is retired");
                }
                match action {
                    plumtree::Action::Deliver { source, data } => {
                        if !self.received_rawbytes.try_push_bounded(
                            BroadcastRecvInfo { packets: 1, data, extra: None, recv_from: source },
                            16,
                        ) {
                            if first_error.is_none() {
                                first_error = Some(error!(
                                    "Plumtree consumer is absent or its bounded queue is full"
                                ));
                            }
                        }
                    }
                    plumtree::Action::Send { peer, message } => {
                        let peers =
                            AdnlPeers::with_keys(transport.local.clone(), KeyId::from_data(peer));
                        if let Err(err) = self.check_peer(peers.other(), None) {
                            if first_error.is_none() {
                                first_error = Some(err);
                            }
                            continue;
                        }
                        let mut bytes = self.message_prefix.clone();
                        serialize_boxed_append(&mut bytes, &message)?;
                        // A direct QUIC send may wait for peer stream credit.
                        // Overlay retirement must release that wait before its
                        // owner can join; global QUIC shutdown happens later.
                        // An interrupted send remains a failed, retryable relay.
                        let sent = tokio::select! {
                            biased;
                            _ = self.tasks.cancelled() => Err(error!("Plumtree overlay retired during send")),
                            result = quic.message(bytes, Some(&self.adnl), &peers) => result,
                        };
                        if let Err(err) = sent {
                            if first_error.is_none() {
                                first_error = Some(err);
                            }
                        }
                    }
                    plumtree::Action::Query { peer, key, query, answer_limit } => {
                        let overlay = Arc::downgrade(self);
                        let quic = quic.clone();
                        let adnl = self.adnl.clone();
                        let peers =
                            AdnlPeers::with_keys(transport.local.clone(), KeyId::from_data(peer));
                        if let Err(err) = self.check_peer(peers.other(), None) {
                            self.plumtree_engine()?.query_failed(key, peer, Instant::now());
                            if first_error.is_none() {
                                first_error = Some(err);
                            }
                            continue;
                        }
                        let mut bytes = self.query_prefix.clone();
                        serialize_boxed_append(&mut bytes, &query)?;
                        self.tasks.spawn_cancelable("plumtree repair query", async move {
                            // The total budget also bounds the QUIC helper's reconnect/retry.
                            let response = tokio::time::timeout(
                                Duration::from_secs(5),
                                quic.query_with_answer_limit(
                                    bytes,
                                    Some(&adnl),
                                    &peers,
                                    Some(5000),
                                    answer_limit,
                                ),
                            )
                            .await
                            .unwrap_or_else(|_| Err(error!("Plumtree repair deadline exceeded")));
                            let Some(overlay) = overlay.upgrade() else {
                                return;
                            };
                            let neighbours = overlay.plumtree_neighbours();
                            let result = (|| -> Result<Vec<plumtree::Action>> {
                                let mut engine = overlay.plumtree_engine()?;
                                match response {
                                    Ok(Some(bytes)) => {
                                        match plumtree::decode_repair_response(&bytes) {
                                            Ok(message) => engine.receive(
                                                peer,
                                                message,
                                                Some(key),
                                                &neighbours,
                                                overlay.clock.unix_seconds(),
                                                Instant::now(),
                                            ),
                                            Err(err) => {
                                                engine.query_failed(key, peer, Instant::now());
                                                Err(err)
                                            }
                                        }
                                    }
                                    Ok(None) => {
                                        engine.query_failed(key, peer, Instant::now());
                                        Ok(Vec::new())
                                    }
                                    Err(err) => {
                                        engine.query_failed(key, peer, Instant::now());
                                        Err(err)
                                    }
                                }
                            })();
                            let result = match result {
                                Ok(actions) => overlay.execute_plumtree(actions).await,
                                Err(err) => Err(err),
                            };
                            if let Err(err) = result {
                                log::warn!(target: TARGET, "Plumtree repair rejected: {err}");
                            }
                        });
                    }
                }
            }
            if let Some(err) = first_error {
                Err(err)
            } else {
                Ok(())
            }
        })
    }
}

impl OverlayNode {
    /// overlay.node member flag: the member receives no broadcast.
    pub const MEMBER_DO_NOT_RECEIVE_BROADCASTS: u32 = 1;
    /// overlay.node member flag: the member receives no Plumtree broadcast.
    pub const MEMBER_DO_NOT_RECEIVE_PLUMTREE: u32 = 2;

    /// Set the overlay.node member flags this node signs for `overlay_id`
    /// (a public overlay adds its Plumtree flag to them) and the flags assumed
    /// for a permanent member that has not advertised itself, as the
    /// reference overlay options local_overlay_member_flags and
    /// default_permanent_members_flags do.
    pub fn set_member_flags(
        &self,
        overlay_id: &Arc<OverlayShortId>,
        local: u32,
        permanent_default: u32,
    ) -> Result<()> {
        if local & !Overlay::MEMBER_PLUMTREE_DENY != 0
            || permanent_default & !Overlay::MEMBER_PLUMTREE_DENY != 0
        {
            fail!("Unsupported overlay member flags {local}/{permanent_default}");
        }
        let overlay = self.get_overlay(overlay_id, "Cannot set member flags of unknown overlay")?;
        overlay.member_flags.store(local, Ordering::Relaxed);
        overlay.permanent_member_flags.store(permanent_default, Ordering::Relaxed);
        Ok(())
    }

    /// The overlay.node member flags this node signs for `overlay_id`.
    pub fn local_member_flags(&self, overlay_id: &Arc<OverlayShortId>) -> Result<u32> {
        Ok(self.get_overlay(overlay_id, "Unknown overlay")?.local_member_flags())
    }

    /// Explicit opt-in for the transport implementation. This does not admit
    /// protocol v2 at the consensus manager or create any signing journal.
    pub fn configure_plumtree(
        &self,
        overlay_id: &Arc<OverlayShortId>,
        config: PlumtreeConfig,
        _runtime: &tokio::runtime::Handle,
    ) -> Result<()> {
        let _generation = self.generations.lock().unwrap();
        let overlay = self.get_overlay(overlay_id, "Configuring Plumtree on unknown overlay")?;
        let _lease = overlay.tasks.enter()?;
        if overlay.flags & Overlay::FLAG_OVERLAY_OTHER_WORKCHAIN != 0 {
            fail!("Plumtree cannot be enabled for an inactive workchain");
        }
        if !overlay.received_rawbytes.has_subscription() {
            fail!("Plumtree requires an owned broadcast consumer subscription before activation");
        }
        let quic = self
            .quic
            .get()
            .ok_or_else(|| error!("Plumtree requires an installed QUIC sender"))?
            .clone();
        // The largest supported member-certificate prefix is 160 bytes:
        // message/query tag + overlay ID + flags + 120-byte Ed25519 certificate.
        if overlay.message_prefix.len() > 160 || overlay.query_prefix.len() > 160 {
            fail!("Plumtree membership envelope exceeds its authenticated wire budget");
        }
        let original_sender = config.original_sender;
        let engine =
            plumtree::Engine::with_verifier(config, *overlay_id.data(), overlay.verifier.clone())?;
        let local = overlay.overlay_key().unwrap_or(&self.node_key).id().clone();
        overlay.plumtree.set(PlumtreeTransport { quic, engine: std::sync::Mutex::new(engine), local, original_sender, stopped: std::sync::atomic::AtomicBool::new(false) })
            .map_err(|_| error!("Plumtree policy is already installed; recreate the overlay to change its authority"))?;
        let weak = Arc::downgrade(&overlay);
        let admitted = overlay.tasks.spawn_cancelable("plumtree ticker", async move {
            let mut ticker = tokio::time::interval(Duration::from_millis(50));
            loop {
                ticker.tick().await;
                let Some(overlay) = weak.upgrade() else {
                    break;
                };
                let actions = match overlay.plumtree_engine() {
                    Ok(mut engine) => engine.tick(overlay.clock.unix_seconds(), Instant::now()),
                    Err(err) => {
                        log::error!(target: TARGET, "Plumtree timer terminated: {err}");
                        break;
                    }
                };
                if let Err(err) = overlay.execute_plumtree(actions).await {
                    log::warn!(target: TARGET, "Plumtree transport error: {err}");
                }
            }
        });
        if !admitted {
            if let Some(transport) = overlay.plumtree.get() {
                transport.stopped.store(true, Ordering::Release);
            }
            fail!("Plumtree activation raced overlay failure");
        }
        Ok(())
    }

    /// `simple_id = None` selects FEC; a supplied ID selects the simple carrier.
    /// The supplied signer is a transport signer, independent of consensus keys.
    pub async fn broadcast_plumtree(
        &self,
        overlay_id: &Arc<OverlayShortId>,
        signer: &Arc<dyn KeyOption>,
        certificate: rtos_api::ton::overlay::Certificate,
        flags: u32,
        simple_id: Option<[u8; 32]>,
        data: &[u8],
    ) -> Result<()> {
        let overlay = self.get_overlay(overlay_id, "Plumtree broadcast to unknown overlay")?;
        let _lease = overlay.tasks.enter()?;
        // Without an explicit certificate the source's own one is attached.
        let certificate = match certificate {
            OverlayCertificateTl::Overlay_EmptyCertificate => overlay
                .local_certificate(signer.id())
                .map_or(OverlayCertificateTl::Overlay_EmptyCertificate, |cert| cert.to_tl()),
            certificate => certificate,
        };
        let neighbours = overlay.plumtree_neighbours();
        let actions = overlay.plumtree_engine()?.publish(
            signer,
            certificate,
            flags as i32,
            simple_id,
            data,
            &neighbours,
            overlay.clock.unix_seconds(),
            Instant::now(),
        )?;
        if !actions.iter().any(|action| matches!(action, plumtree::Action::Send { .. })) {
            fail!("Plumtree publication has no outbound neighbour; retry after peer discovery");
        }
        overlay.execute_plumtree(actions).await
    }
}

#[cfg(test)]
#[path = "wire_profile_tests.rs"]
mod wire_profile_tests;

#[cfg(test)]
#[path = "tos_node_tests.rs"]
mod tos_node_tests;

#[cfg(test)]
#[path = "member_flags_tests.rs"]
mod member_flags_tests;

#[cfg(test)]
mod owned_shutdown_tests;
