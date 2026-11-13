/*
 * RTOS project modifications (2026-10-10): explicit target wire profiles; owned consumer readiness and authenticated finality recovery.
 * Copyright (C) 2026 RTOS contributors.
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! Constructor domains are part of the protocol, including nested boxed fields.
//! The target profile is pinned to reference 881240331ee48a291b96d73f8b8b93bae005ace0.
//! This codec translates only constructor boundaries, never opaque byte strings.
//! Local storage formats keep their explicit legacy codec; selecting a network
//! profile does not rename databases or open a new signing journal.

use crate::{AnyBoxedSerialize, BoxedSerialize, Deserializer, Serializer, TLObject};
use rtos_block::{fail, Result};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum WireProfile {
    /// Existing generated schema and local storage compatibility.
    #[default]
    Legacy = 0,
    /// Fixed target network schema. No legacy-domain fallback on decode.
    T0 = 1,
}

// (generated constructor, target constructor). Field layouts were compared
// against the fixed reference schema before inclusion. Differing layouts are
// deliberately excluded below instead of disguising them as an ID change.
const CONSTRUCTORS: &[(u32, u32)] = &[
    (0x88c9550b, 0x0d788eda), // liteserver.descV2.sliceSimple
    (0x7079c751, 0x8f2f8967), // liteServer.accountState
    (0x098fe72d, 0xdbd35e42), // liteServer.allShardsInfo
    (0xa574ed6c, 0x8890f1c9), // liteServer.blockData
    (0x752d8219, 0xa8f2a269), // liteServer.blockHeader
    (0xef7e1bef, 0x5ed68680), // liteServer.blockLinkBack
    (0x520fce1c, 0xf714a152), // liteServer.blockLinkForward
    (0x8acdbe1b, 0x6349c292), // liteServer.blockOutMsgQueueSize
    (0xabaddc0c, 0x6a385e91), // liteServer.blockState
    (0xbd8cad2b, 0xabdf2047), // liteServer.blockTransactions
    (0xfb8ffce4, 0xe16aff7e), // liteServer.blockTransactionsExt
    (0xae7b272f, 0xcfea2621), // liteServer.configInfo
    (0x5d1132d0, 0x490a7d13), // liteServer.dispatchQueueInfo
    (0x4b407931, 0xcade8c10), // liteServer.dispatchQueueMessages
    (0x6b890e25, 0xc6399fe0), // liteServer.getAccountState
    (0x5a698507, 0xf7d914c2), // liteServer.getAccountStatePrunned
    (0x74d3fd6b, 0x0beb1110), // liteServer.getAllShardsInfo
    (0x6377cf0d, 0xe6c614dc), // liteServer.getBlock
    (0x21ec069e, 0xb198f8d1), // liteServer.getBlockHeader
    (0x8f6c7779, 0xbee95a10), // liteServer.getBlockOutMsgQueueSize
    (0x8aea9c44, 0xcf763830), // liteServer.getBlockProof
    (0x911b26b7, 0x604a752e), // liteServer.getConfigAll
    (0x2a111c19, 0x231f41e2), // liteServer.getConfigParams
    (0x01e66bf3, 0x0a2f13fb), // liteServer.getDispatchQueueInfo
    (0xbbfd6439, 0x138dfd9e), // liteServer.getDispatchQueueMessages
    (0xd97693bd, 0x5709e9c6), // liteServer.getLibrariesWithProof
    (0xd40f24ea, 0x53b475cf), // liteServer.getOneTransaction
    (0x4ca60350, 0x29d17206), // liteServer.getShardBlockProof
    (0x46a2f425, 0xb742493b), // liteServer.getShardInfo
    (0xba6e2eb6, 0x4b3f7d2f), // liteServer.getState
    (0x10a927bf, 0xa572d7a8), // liteServer.libraryResultWithProof
    (0xadfcc7da, 0xc39175f1), // liteServer.listBlockTransactions
    (0x0079dd5c, 0xd191a5ec), // liteServer.listBlockTransactionsExt
    (0xfac8f71e, 0x2dd17474), // liteServer.lookupBlock
    (0x99786be7, 0x1303a6f4), // liteServer.lookupBlockResult
    (0x9c045ff8, 0x1761ead7), // liteServer.lookupBlockWithProof
    (0x85832881, 0xa50d25c9), // liteServer.masterchainInfo
    (0xa8cce0f5, 0x50fff02d), // liteServer.masterchainInfoExt
    (0x55047fee, 0x25297460), // liteServer.nonfinal.candidateId
    (0xf9d68aa7, 0x8d5e3b16), // liteServer.nonfinal.validatorGroupInfo
    (0xa7c64c85, 0xb782953b), // liteServer.outMsgQueueSize
    (0x8ed0d2c1, 0xddf5555f), // liteServer.partialBlockProof
    (0xa39a616b, 0x89131411), // liteServer.runMethodResult
    (0x5cc65dd2, 0x5e5f4cd8), // liteServer.runSmcMethod
    (0xd30dcf72, 0x56443670), // liteServer.shardBlockLink
    (0x1d62a07a, 0xe9fd9644), // liteServer.shardBlockProof
    (0x9fe6cd84, 0x8ed10095), // liteServer.shardInfo
    (0x0edeed47, 0xff3e5059), // liteServer.transactionInfo
    (0x6f26c60b, 0x8db4da3a), // liteServer.transactionList
    (0xb9f796d8, 0x5920e6d7), // liteServer.validatorStats
    (0xf117f8ff, 0x0740558c), // consensus.empty
    (0x932a6872, 0x67a868b1), // consensus.simplex.db.finalizedBlock
    (0x3af82fee, 0xdc0b0711), // consensus.stats.block
    (0x19efff8c, 0xd7e31bec), // tosNode.archiveInfo
    (0x99291683, 0xe3fec097), // tosNode.archiveNotFound
    (0xae2e1105, 0x2e0f2377), // tosNode.blockBroadcast
    (0x09fd1743, 0x3224c1b6), // tosNode.blockBroadcastCompressed
    (0xfe9113b6, 0xdeddedab), // tosNode.blockBroadcastCompressed.data
    (0x50234058, 0xdec0c75b), // tosNode.blockBroadcastCompressedV2
    (0x46a1d088, 0xcf1436b7), // tosNode.blockDescription
    (0x8384ae95, 0xc8fdecaa), // tosNode.blockDescriptionEmpty
    (0xb7cdb167, 0x96baceac), // tosNode.blockId
    (0x6752eb78, 0xb4ebeee3), // tosNode.blockIdExt
    (0x50f03c33, 0xedc41715), // tosNode.blockSignature
    (0xd62a612c, 0xb578b73c), // tosNode.blocksDescription
    (0x39b41ea6, 0xb8604bbf), // tosNode.customOverlayId
    (0x560a2484, 0xb89b71ac), // tosNode.data
    (0xbe589f93, 0x8ec3d626), // tosNode.dataFull
    (0x463d2ca5, 0x46273df4), // tosNode.dataFullCompressed
    (0x576e85ca, 0x52cdc0af), // tosNode.dataFullEmpty
    (0xe27279c3, 0x55e184bd), // tosNode.downloadBlock
    (0x6a27c49d, 0xa40b09fe), // tosNode.downloadBlockFull
    (0x4bd6478a, 0xd72dd1ee), // tosNode.downloadBlockProof
    (0x25b300c6, 0x0b02248f), // tosNode.downloadBlockProofLink
    (0xec23483a, 0x4f95e21f), // tosNode.downloadKeyBlockProof
    (0x12e42ad2, 0xc13d3142), // tosNode.downloadKeyBlockProofLink
    (0x6ea0374a, 0x87ad0787), // tosNode.downloadNextBlockFull
    (0xc4bcf88f, 0xf7e28640), // tosNode.downloadNextBlocksFull
    (0x868c8410, 0x94271ee8), // tosNode.downloadPersistentStateSliceV2
    (0xadcc1e5a, 0xf9c3b1c6), // tosNode.downloadZeroState
    (0xdc75a209, 0xc91793c5), // tosNode.externalMessage
    (0x3d1b1867, 0x8beedeb2), // tosNode.externalMessageBroadcast
    (0x1af10554, 0xfdb5f109), // tosNode.fastSyncOverlayId
    (0xab22f481, 0x14763825), // tosNode.forgetPeer
    (0x7b2dd941, 0x9c50ff1f), // tosNode.getArchiveInfo
    (0x203b5168, 0x93fa5a3e), // tosNode.getArchiveSlice
    (0xdee618f8, 0xc4461b53), // tosNode.getCapabilities
    (0x1455b0f3, 0xbe2fbd72), // tosNode.getNextBlockDescription
    (0x3f2812c4, 0x55086f12), // tosNode.getNextBlocksDescription
    (0xf2e7cfbb, 0x2bc35b22), // tosNode.getNextKeyBlockIds
    (0x844c5921, 0x54590a3b), // tosNode.getOutMsgQueueProof
    (0x4ba2a718, 0x00c1a022), // tosNode.getPersistentStateSizeV2
    (0x5c6d6cc9, 0x6074ab78), // tosNode.getPrevBlocksDescription
    (0x12fb3b58, 0x352f8a56), // tosNode.getShardArchiveInfo
    (0x4534c307, 0x3a2d418f), // tosNode.ihrMessage
    (0x525da4b3, 0x3d53902e), // tosNode.ihrMessageBroadcast
    (0xf7cde30b, 0x63405cf3), // tosNode.importedMsgQueueLimits
    (0x07664d59, 0xe49080e9), // tosNode.keyBlocks
    (0xbfed0dc0, 0x869e7e67), // tosNode.newBlockCandidateBroadcast
    (0x0cd86894, 0xa40feb13), // tosNode.newBlockCandidateBroadcastCompressed
    (0x9f0e7f35, 0x735e4059), // tosNode.newBlockCandidateBroadcastCompressedV2
    (0xa49dc229, 0x6816f601), // tosNode.newShardBlock
    (0x476cdac5, 0x6eb47142), // tosNode.nextBlocksFull
    (0x0af2fabc, 0xcdd111f0), // tosNode.newShardBlockBroadcast
    (0xe2c33da6, 0x6b9d20c5), // tosNode.notFound
    (0x32390a51, 0x69684d1f), // tosNode.notFoundState
    (0x5c021bd2, 0x0c72580a), // tosNode.outMsgQueueProof
    (0x365eefb1, 0xf6868905), // tosNode.outMsgQueueProofBroadcast
    (0xa09a0ee2, 0xebe34cdd), // tosNode.outMsgQueueProofEmpty
    (0x09ec5063, 0x0a61b4c3), // tosNode.persistentStateIdV2
    (0xf224d3d2, 0x89322fd8), // tosNode.persistentStateSize
    (0xfa56c06b, 0xfa1a8b8e), // tosNode.persistentStateSizeNotFound
    (0x75a37f4e, 0x6f5ecfa6), // tosNode.prepareBlock
    (0x875c3308, 0x1ae2e498), // tosNode.prepareBlockProof
    (0xed79b2b8, 0x565ffcb0), // tosNode.prepareBlockProofs
    (0x6affabfc, 0xd4bcd72a), // tosNode.prepareBlocks
    (0x77364c38, 0xd7252362), // tosNode.prepareKeyBlockProof
    (0x8c6cfbe4, 0x812857f5), // tosNode.prepareKeyBlockProofs
    (0xfeea269e, 0xdc44a7f3), // tosNode.preparePersistentState
    (0x41ce0825, 0x3946614c), // tosNode.prepareZeroState
    (0xeac4bbcd, 0x639aa6ae), // tosNode.prepared
    (0x899f9a4b, 0xd2cedd05), // tosNode.preparedProof
    (0xc769c17a, 0x73749400), // tosNode.preparedProofEmpty
    (0x3dff328d, 0xd27547b7), // tosNode.preparedProofLink
    (0x375bcb6d, 0x6c0a8c23), // tosNode.preparedState
    (0xa6f4d862, 0x572e1c1f), // tosNode.privateBlockOverlayId
    (0x69f324d3, 0x3f64895b), // tosNode.query
    (0x7a9236ba, 0x8501dafc), // tosNode.sessionId
    (0x28fa0877, 0x5e9837d1), // tosNode.shardId
    (0x4d9ed329, 0x6fac0afd), // tosNode.shardPublicOverlayId
    (0xacc8ad24, 0xf3a7a902), // tosNode.signatureSet.ordinary
    (0x6a23db02, 0x76fd51cc), // tosNode.signatureSet.simplex
    (0x0376f2a9, 0x8f123202), // tosNode.slave.sendExtMessage
    (0xc096244f, 0x9f8462e6), // tosNode.success
    (0x1d7235ae, 0x79378446), // tosNode.zeroStateIdExt
];

// These carriers never existed in the historical generated network domain.
const TARGET_ONLY: &[u32] = &[
    0x535666d0, 0x590da166, 0x5e6f085d, 0x8f4731ef, 0xfb759362, 0xf9f0b390, 0xe324f031, 0xeb17eafc,
    0xd11f938e, 0x485c4d7d, 0x5c2b3739, 0x1bad0e80, 0xf4beb3ff, 0xb22e2334, 0xc1e08ae5, 0xb375613b,
    0x6f0d48d9, 0xffcf1839, 0xa41a2d18, 0x6ffb5781, 0xdbb8eac6, 0xc6f4b24e, 0xf7e24955, 0x15cd0649,
    0xebb6ddd4, 0xe0d59ac5, 0xe57f583d, 0x6e80ea19, 0xcf280039, 0x8060d7f9, 0x2fc05215, 0xc4eeeadb,
    0xee13ee74, 0x4204c255, 0x043e2881, 0x5abd3e2b, 0x4f5143c7, 0xc1d8d09b, 0xd4ea9e1f, 0x5326e875,
    0x857eb803, 0x4500a07e, 0xd9a5aaa3, 0xe1fb5bca, 0x16ea71fc, 0xed630375, 0xfbf56136, 0x580bca07,
    0x28cf2fe3,
];

// Replaced target layouts have separate native types, not ID-only translations.
const REPLACED_LEGACY_LAYOUTS: &[u32] = &[
    0x1cf255fe, 0x90eb94e8, 0xc54f971a, 0x51301646, 0x6fb4f54b, 0xd1c744d2, 0xc449a474, 0x4b0f1c8b,
    0x34197fae,
];

const UNSUPPORTED: &[u32] = &[
    0xc85af8a4, // consensus.simplex.db.cert
    0xaf37a688, 0x7cb0ed4d, // consensus.simplex.db.vote
    0x92180c6f, // consensus.simplex.stats.voteReceived
    0xd317e679, // obsolete RPC vote
    0xe3973926, // consensus.stats.collateFailed
    0x126b5dfc, // consensus.stats.id
    0xc8aee82e, 0x127ce464, // consensus.stats.sessionEnd
    0x7f9bc9b3, // consensus.stats.sessionOptions
    0xf937fdce, // consensus.stats.validationFailed
];

impl WireProfile {
    /// Whether a boxed constructor belongs to the named generated schema domain.
    /// This checks only the root; nested fields still use their generated types.
    pub fn constructor_in_schema(self, id: u32, schema: &str, function: bool) -> bool {
        let Ok(id) = self.decode_constructor(id) else {
            return false;
        };
        const DOMAINS: &[(u32, &str, bool)] =
            include!(concat!(env!("OUT_DIR"), "/schema_domains.rs"));
        DOMAINS.contains(&(id, schema, function))
    }

    pub(crate) fn encode_constructor(self, id: u32) -> Result<u32> {
        if self == Self::Legacy {
            if TARGET_ONLY.contains(&id) {
                fail!("Target-only constructor {id:08x} has no legacy wire codec");
            }
            return Ok(id);
        }
        if REPLACED_LEGACY_LAYOUTS.contains(&id) {
            fail!("Legacy constructor {id:08x} has a different target layout");
        }
        if UNSUPPORTED.contains(&id) {
            fail!("Constructor {id:08x} has no target wire codec");
        }
        Ok(CONSTRUCTORS.iter().find(|(old, _)| *old == id).map_or(id, |(_, new)| *new))
    }

    pub(crate) fn decode_constructor(self, id: u32) -> Result<u32> {
        if self == Self::Legacy {
            if TARGET_ONLY.contains(&id) {
                fail!("Target-only constructor {id:08x} has no legacy wire codec");
            }
            return Ok(id);
        }
        if REPLACED_LEGACY_LAYOUTS.contains(&id) {
            fail!("Legacy constructor {id:08x} has a different target layout");
        }
        if UNSUPPORTED.contains(&id) {
            fail!("Constructor {id:08x} has no target wire codec");
        }
        if let Some((old, _)) = CONSTRUCTORS.iter().find(|(_, new)| *new == id) {
            return Ok(*old);
        }
        if CONSTRUCTORS.iter().any(|(old, _)| *old == id) {
            fail!("Legacy constructor {id:08x} is forbidden in target wire profile");
        }
        Ok(id)
    }

    pub fn serialize<T: BoxedSerialize + ?Sized>(self, value: &T) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.serialize_append(&mut bytes, value)?;
        Ok(bytes)
    }

    pub fn serialize_append<T: BoxedSerialize + ?Sized>(
        self,
        bytes: &mut Vec<u8>,
        value: &T,
    ) -> Result<()> {
        Serializer::with_profile(bytes, self).write_boxed(value)
    }

    /// Strict single object; trailing bytes are never silently ignored.
    pub fn deserialize(self, bytes: &[u8]) -> Result<TLObject> {
        let (value, consumed) = self.deserialize_with_suffix(bytes)?;
        if consumed != bytes.len() {
            fail!("Trailing bytes after wire object");
        }
        Ok(value)
    }

    pub fn deserialize_value<T: crate::BoxedDeserialize>(self, bytes: &[u8]) -> Result<T> {
        let mut reader = bytes;
        let mut de = Deserializer::with_profile(&mut reader, self);
        let value = de.read_boxed()?;
        if de.pos != bytes.len() {
            fail!("Trailing bytes after wire object");
        }
        Ok(value)
    }

    /// Decode with caller-specific declared/aggregate byte limits before Vec allocation.
    pub fn deserialize_value_bounded<T: crate::BoxedDeserialize>(
        self,
        bytes: &[u8],
        byte_budget: usize,
    ) -> Result<T> {
        let mut reader = bytes;
        let mut de = Deserializer::with_profile(&mut reader, self)
            .with_bytes_budget(byte_budget.min(bytes.len()));
        let value = de.read_boxed()?;
        if de.pos != bytes.len() {
            fail!("Trailing bytes after wire object");
        }
        Ok(value)
    }

    pub fn deserialize_typed<T: AnyBoxedSerialize>(self, bytes: &[u8]) -> Result<T> {
        crate::downcast_with_error(self.deserialize(bytes)?)
    }

    /// Explicit prefix parser for framed overlay messages, not single objects.
    pub fn deserialize_with_suffix(self, bytes: &[u8]) -> Result<(TLObject, usize)> {
        let mut reader = bytes;
        let mut de = Deserializer::with_profile(&mut reader, self);
        Ok((de.read_boxed()?, de.pos))
    }

    /// Unlike the historical bundle parser, errors after a valid first object
    /// are fatal. An overlay prefix cannot hide an invalid target request.
    pub fn deserialize_bundle(self, bytes: &[u8]) -> Result<Vec<TLObject>> {
        let mut reader = bytes;
        let mut de = Deserializer::with_profile(&mut reader, self);
        let mut objects = Vec::new();
        while de.pos < bytes.len() {
            objects.push(de.read_boxed()?);
        }
        if objects.is_empty() {
            fail!("Empty wire object bundle");
        }
        Ok(objects)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ton, IntoBoxed};

    #[test]
    fn constructor_domains_are_bijective_and_disjoint() {
        let old: std::collections::HashSet<_> = CONSTRUCTORS.iter().map(|x| x.0).collect();
        let new: std::collections::HashSet<_> = CONSTRUCTORS.iter().map(|x| x.1).collect();
        assert_eq!(old.len(), CONSTRUCTORS.len());
        assert_eq!(new.len(), CONSTRUCTORS.len());
        assert!(old.is_disjoint(&new));
        for id in &new {
            assert!(
                !crate::ton::dynamic::BY_NUMBER.contains_key(id),
                "target ID collides with a different generated constructor"
            );
        }
        for (old, new) in CONSTRUCTORS {
            assert_eq!(WireProfile::T0.encode_constructor(*old).unwrap(), *new);
            assert_eq!(WireProfile::T0.decode_constructor(*new).unwrap(), *old);
            assert!(WireProfile::T0.decode_constructor(*old).is_err());
        }
    }

    #[test]
    fn target_profile_preserves_opaque_bytes_and_rejects_suffix() {
        let payload: Vec<u8> = CONSTRUCTORS
            .iter()
            .flat_map(|(a, b)| a.to_le_bytes().into_iter().chain(b.to_le_bytes()))
            .collect();
        let object = ton::ton_node::data::Data { data: payload.clone() }.into_boxed();
        let legacy = WireProfile::Legacy.serialize(&object).unwrap();
        let target = WireProfile::T0.serialize(&object).unwrap();
        assert_ne!(&legacy[..4], &target[..4]);
        assert_eq!(&legacy[4..], &target[4..]);
        assert!(WireProfile::T0.deserialize(&legacy).is_err());
        assert!(WireProfile::Legacy.deserialize(&target).is_err());
        assert!(WireProfile::T0.deserialize(&target).is_ok());
        let mut bad = target.clone();
        bad.push(0);
        assert!(WireProfile::T0.deserialize(&bad).is_err());
        assert!(WireProfile::T0.deserialize_bundle(&bad).is_err());
        let mut mixed = target;
        mixed.extend(legacy);
        assert!(WireProfile::T0.deserialize_bundle(&mixed).is_err());
    }
}

#[cfg(test)]
#[path = "wire_fixture_tests.rs"]
mod fixture_tests;
