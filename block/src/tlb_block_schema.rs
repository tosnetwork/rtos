// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Generated Block schema, including the weak references of MERKLE_UPDATE.
use super::*;

impl Walker {
    fn block_ref(&mut self, slice: &mut SliceData, kind: TlbType) -> bool {
        self.push_ref(slice, Node::Typed(kind, TlbProfile::Generated))
    }

    pub(super) fn block_schema(&mut self, kind: TlbType, slice: &mut SliceData) -> bool {
        use TlbType::*;
        let generated = TlbProfile::Generated;
        match kind {
            Block => {
                tag(slice, 32, 0x11ef55aa)
                    && skip(slice, 32)
                    && self.block_ref(slice, BlockInfo)
                    && self.block_ref(slice, ValueFlow)
                    && self.block_ref(slice, MerkleStateUpdate)
                    && self.block_ref(slice, BlockExtra)
            }
            MerkleStateUpdate => {
                if !tag(slice, 8, 4) || !skip(slice, 544) {
                    return false;
                }
                // The generated C++ MERKLE_UPDATE validator explicitly enables
                // weak validation for both states, including their descendants.
                for _ in 0..2 {
                    let Ok(child) = slice.checked_drain_reference() else {
                        return false;
                    };
                    self.pending.push((child, Node::Typed(ShardState, generated), true));
                }
                true
            }
            CurrencyQuad => (0..4).all(|_| self.typed(CurrencyCollection, generated, slice)),
            ValueFlow => {
                let constructor = uint(slice, 32);
                matches!(constructor, Some(0xb8e48dfb | 0x3ebf98b7))
                    && self.block_ref(slice, CurrencyQuad)
                    && self.typed(CurrencyCollection, generated, slice)
                    && (constructor == Some(0xb8e48dfb)
                        || self.typed(CurrencyCollection, generated, slice))
                    && self.block_ref(slice, CurrencyQuad)
            }
            BlockExtra => {
                tag(slice, 32, 0x4a33f6fd)
                    && self.block_ref(slice, InMsgDescr)
                    && self.block_ref(slice, OutMsgDescr)
                    && self.block_ref(slice, ShardAccountBlocks)
                    && skip(slice, 512)
                    && self.maybe_ref(slice, Node::Typed(McBlockExtra, generated))
            }
            ShardAccountBlocks => {
                self.generated_aug_hashmap_e(slice, 256, AccountBlock, CurrencyCollection)
            }
            AccountBlock => {
                tag(slice, 4, 5)
                    && skip(slice, 256)
                    && self.generated_aug_hashmap(slice, 64, TransactionRef, CurrencyCollection)
                    && self.block_ref(slice, HashUpdate)
            }
            TransactionRef => self.block_ref(slice, Transaction),
            ImportFees => {
                self.typed(Coins, generated, slice)
                    && self.typed(CurrencyCollection, generated, slice)
            }
            InMsgDescr => self.generated_aug_hashmap_e(slice, 256, InMsg, ImportFees),
            OutMsgDescr => self.generated_aug_hashmap_e(slice, 256, OutMsg, CurrencyCollection),
            InMsg => self.block_in_msg(slice),
            OutMsg => self.block_out_msg(slice),
            McBlockExtra => {
                if !tag(slice, 16, 0xcca5) {
                    return false;
                }
                let Some(key_block) = bool_bit(slice) else {
                    return false;
                };
                self.hashmap_e(slice, 32, Leaf::Typed(ShardDescrTreeRef, generated))
                    && self.generated_aug_hashmap_e(slice, 96, CurrencyPair, CurrencyPair)
                    && self.block_ref(slice, McBlockExtraAux)
                    && (!key_block
                        || (skip(slice, 256)
                            && self.push_ref(slice, Node::Hashmap(32, Leaf::AnyRef))))
            }
            McBlockExtraAux => {
                self.hashmap_e(slice, 16, Leaf::Typed(SignaturePair, generated))
                    && self.maybe_ref(slice, Node::Typed(InMsg, generated))
                    && self.maybe_ref(slice, Node::Typed(InMsg, generated))
            }
            SignaturePair => skip(slice, 256) && self.crypto_signature(slice),
            _ => false,
        }
    }

    fn block_in_msg(&mut self, slice: &mut SliceData) -> bool {
        use TlbType::*;
        let Some(mut constructor) = uint(slice, 3) else {
            return false;
        };
        if constructor == 1 {
            let Some(suffix @ 0..=1) = uint(slice, 2) else {
                return false;
            };
            constructor = 8 + suffix;
        }
        match constructor {
            0 => self.block_ref(slice, Message) && self.block_ref(slice, Transaction),
            2 => {
                self.block_ref(slice, Message)
                    && self.block_ref(slice, Transaction)
                    && var(slice, 16, TlbProfile::Generated, false)
                    && slice.checked_drain_reference().is_ok()
            }
            3 | 4 | 8 => {
                self.block_ref(slice, MsgEnvelope)
                    && self.block_ref(slice, Transaction)
                    && var(slice, 16, TlbProfile::Generated, false)
            }
            5 | 9 => {
                self.block_ref(slice, MsgEnvelope)
                    && self.block_ref(slice, MsgEnvelope)
                    && (constructor == 9 || var(slice, 16, TlbProfile::Generated, false))
            }
            6 | 7 => {
                self.block_ref(slice, MsgEnvelope)
                    && skip(slice, 64)
                    && var(slice, 16, TlbProfile::Generated, false)
                    && (constructor == 6 || slice.checked_drain_reference().is_ok())
            }
            _ => false,
        }
    }

    fn block_out_msg(&mut self, slice: &mut SliceData) -> bool {
        use TlbType::*;
        match uint(slice, 3) {
            Some(0) => self.block_ref(slice, Message) && self.block_ref(slice, Transaction),
            Some(1) => self.block_ref(slice, MsgEnvelope) && self.block_ref(slice, Transaction),
            Some(2) => {
                self.block_ref(slice, MsgEnvelope)
                    && self.block_ref(slice, Transaction)
                    && self.block_ref(slice, InMsg)
            }
            Some(3 | 4 | 7) => self.block_ref(slice, MsgEnvelope) && self.block_ref(slice, InMsg),
            Some(5) => match uint(slice, 2) {
                Some(0) => self.block_ref(slice, MsgEnvelope) && self.block_ref(slice, Transaction),
                Some(1) => self.block_ref(slice, MsgEnvelope) && self.block_ref(slice, InMsg),
                _ => false,
            },
            Some(6) => match bool_bit(slice) {
                Some(false) => self.block_ref(slice, MsgEnvelope) && skip(slice, 63),
                Some(true) => skip(slice, 416),
                None => false,
            },
            _ => false,
        }
    }
}
