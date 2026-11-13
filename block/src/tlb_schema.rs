// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Exact structural TL-B checks, including the handwritten validator's rules.
//! Typed references join the parent walker's shared visit budget.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlbProfile {
    Generated,
    Handwritten,
}

#[derive(Clone, Copy, Debug)]
pub enum TlbType {
    Coins,
    ExtraCurrencyCollection,
    CurrencyCollection,
    MsgAddressInt,
    StateInit,
    StorageUsed,
    AccountStorage,
    Account,
    ShardAccount,
    Message,
    MessageRelaxed,
    Transaction,
    BlockInfo,
    McStateExtra,
    ShardStateUnsplit,
    // Internal referenced schema types.
    #[doc(hidden)]
    ExtraCurrencyValue,
    #[doc(hidden)]
    MessageRef,
    #[doc(hidden)]
    TransactionAux,
    #[doc(hidden)]
    HashUpdate,
    #[doc(hidden)]
    TransactionDescr,
    #[doc(hidden)]
    ComputeDetails,
    #[doc(hidden)]
    ActionPhase,
    #[doc(hidden)]
    ExtBlkRef,
    #[doc(hidden)]
    PrevBlocks,
    #[doc(hidden)]
    Bits(usize),
    #[doc(hidden)]
    CurrencyPair,
    #[doc(hidden)]
    ShardDescr,
    #[doc(hidden)]
    ShardDescrTree,
    #[doc(hidden)]
    ShardDescrTreeRef,
    #[doc(hidden)]
    McStateExtraAux,
    #[doc(hidden)]
    CreatorStats,
    #[doc(hidden)]
    BlockCreateStats,
    #[doc(hidden)]
    ShardStateAux,
    #[doc(hidden)]
    ShardAccountsSchema,
    #[doc(hidden)]
    DepthBalance,
    #[doc(hidden)]
    LibDescr,
    #[doc(hidden)]
    OutMsgQueueInfoSchema,
    #[doc(hidden)]
    EnqueuedMsg,
    #[doc(hidden)]
    MsgEnvelope,
    #[doc(hidden)]
    DispatchQueueEntry,
}

/// Checks the whole cell, following typed references with the supplied budget.
pub fn tlb_type_is_valid(kind: TlbType, profile: TlbProfile, cell: Cell, budget: u32) -> bool {
    visit_all(cell, Node::Typed(kind, profile), budget)
}

fn var(slice: &mut SliceData, n: usize, profile: TlbProfile, positive: bool) -> bool {
    let encoding = match (profile, positive) {
        (TlbProfile::Generated, _) => VarUIntegerEncoding::Structural,
        (TlbProfile::Handwritten, false) => VarUIntegerEncoding::Minimal,
        (TlbProfile::Handwritten, true) => VarUIntegerEncoding::Positive,
    };
    VarUIntegerCodec::new(n).is_some_and(|codec| codec.skip(slice, encoding))
}
fn maybe(slice: &mut SliceData, check: impl FnOnce(&mut SliceData) -> bool) -> bool {
    match bool_bit(slice) {
        Some(false) => true,
        Some(true) => check(slice),
        None => false,
    }
}
fn anycast(slice: &mut SliceData) -> bool {
    maybe(
        slice,
        |s| matches!(uint(s, 5), Some(depth) if (1..=30).contains(&depth) && skip(s, depth as usize)),
    )
}
fn address_int(slice: &mut SliceData, profile: TlbProfile) -> bool {
    let constructor = uint(slice, 2);
    if !matches!(constructor, Some(2 | 3)) || !anycast(slice) {
        return false;
    }
    if constructor == Some(2) {
        return skip(slice, 264);
    }
    let (Some(len), Some(workchain)) = (uint(slice, 9), uint(slice, 32)) else {
        return false;
    };
    let workchain = workchain as u32 as i32;
    skip(slice, len as usize)
        && (profile == TlbProfile::Generated
            || ((!(-128..=127).contains(&workchain) || len != 256)
                && workchain != 0
                && workchain != -1))
}
fn address_ext(slice: &mut SliceData) -> bool {
    match uint(slice, 2) {
        Some(0) => true,
        Some(1) => uint(slice, 9).is_some_and(|len| skip(slice, len as usize)),
        _ => false,
    }
}
fn address_any(slice: &mut SliceData, profile: TlbProfile) -> bool {
    match slice.get_int(1) {
        Ok(0) => address_ext(slice),
        Ok(1) => address_int(slice, profile),
        _ => false,
    }
}
fn state_init(slice: &mut SliceData) -> bool {
    maybe(slice, |s| skip(s, 5))
        && maybe(slice, |s| skip(s, 2))
        && (0..3).all(|_| maybe(slice, |s| s.checked_drain_reference().is_ok()))
}
fn storage_used(slice: &mut SliceData, profile: TlbProfile) -> bool {
    var(slice, 7, profile, false) && var(slice, 7, profile, false)
}
fn storage_info(slice: &mut SliceData, profile: TlbProfile) -> bool {
    storage_used(slice, profile)
        && match uint(slice, 3) {
            Some(0) => true,
            Some(1) => skip(slice, 256),
            _ => false,
        }
        && skip(slice, 32)
        && maybe(slice, |s| var(s, 16, profile, false))
}

fn status_change(slice: &mut SliceData) -> bool {
    match bool_bit(slice) {
        Some(false) => true,
        Some(true) => skip(slice, 1),
        None => false,
    }
}
fn storage_phase(slice: &mut SliceData, profile: TlbProfile) -> bool {
    var(slice, 16, profile, false)
        && maybe(slice, |s| var(s, 16, profile, false))
        && status_change(slice)
}
fn bounce_phase(slice: &mut SliceData, profile: TlbProfile) -> bool {
    match bool_bit(slice) {
        Some(true) => {
            storage_used(slice, profile)
                && var(slice, 16, profile, false)
                && var(slice, 16, profile, false)
        }
        Some(false) => match bool_bit(slice) {
            Some(false) => true,
            Some(true) => storage_used(slice, profile) && var(slice, 16, profile, false),
            None => false,
        },
        None => false,
    }
}
fn shard_ident(slice: &mut SliceData) -> bool {
    tag(slice, 2, 0) && matches!(uint(slice, 6), Some(bits) if bits <= 60) && skip(slice, 96)
}
fn intermediate_address(slice: &mut SliceData) -> bool {
    match bool_bit(slice) {
        Some(false) => matches!(uint(slice, 7), Some(bits) if bits <= 96),
        Some(true) => match bool_bit(slice) {
            Some(false) => skip(slice, 72),
            Some(true) => skip(slice, 96),
            None => false,
        },
        None => false,
    }
}

impl Walker {
    /// Generated HashmapAug validation checks its schema, without the
    /// handwritten augmentation arithmetic or comparisons.
    pub(super) fn generated_aug_hashmap(
        &mut self,
        slice: &mut SliceData,
        n: usize,
        value: TlbType,
        extra: TlbType,
    ) -> bool {
        let Some(label) = hm_label(slice, n) else {
            return false;
        };
        let Some(rest) = n.checked_sub(label) else {
            return false;
        };
        let profile = TlbProfile::Generated;
        if rest == 0 {
            self.typed(extra, profile, slice) && self.typed(value, profile, slice)
        } else {
            self.push_ref(slice, Node::GeneratedAugHashmap(rest - 1, value, extra))
                && self.push_ref(slice, Node::GeneratedAugHashmap(rest - 1, value, extra))
                && self.typed(extra, profile, slice)
        }
    }

    fn generated_aug_hashmap_e(
        &mut self,
        slice: &mut SliceData,
        n: usize,
        value: TlbType,
        extra: TlbType,
    ) -> bool {
        match bool_bit(slice) {
            Some(false) => self.typed(extra, TlbProfile::Generated, slice),
            Some(true) => {
                self.push_ref(slice, Node::GeneratedAugHashmap(n, value, extra))
                    && self.typed(extra, TlbProfile::Generated, slice)
            }
            None => false,
        }
    }

    pub(super) fn typed(
        &mut self,
        kind: TlbType,
        profile: TlbProfile,
        slice: &mut SliceData,
    ) -> bool {
        use TlbType::*;
        match kind {
            ShardStateUnsplit => {
                tag(slice, 32, 0x9023afe2)
                    && skip(slice, 32)
                    && shard_ident(slice)
                    && skip(slice, 192)
                    && self
                        .push_ref(slice, Node::Typed(OutMsgQueueInfoSchema, TlbProfile::Generated))
                    && skip(slice, 1)
                    && self.push_ref(slice, Node::Typed(ShardAccountsSchema, TlbProfile::Generated))
                    && self.push_ref(slice, Node::Typed(ShardStateAux, TlbProfile::Generated))
                    && self.maybe_ref(slice, Node::Typed(McStateExtra, TlbProfile::Generated))
            }
            ShardAccountsSchema => {
                self.generated_aug_hashmap_e(slice, 256, ShardAccount, DepthBalance)
            }
            DepthBalance => {
                matches!(uint(slice, 5), Some(depth) if depth <= 30)
                    && self.typed(CurrencyCollection, profile, slice)
            }
            ShardStateAux => {
                skip(slice, 128)
                    && self.typed(CurrencyPair, profile, slice)
                    && self.hashmap_e(slice, 256, Leaf::Typed(LibDescr, profile))
                    && maybe(slice, |s| skip(s, 608))
            }
            LibDescr => {
                tag(slice, 2, 0)
                    && slice.checked_drain_reference().is_ok()
                    && self.hashmap(slice, 256, Leaf::Empty)
            }
            OutMsgQueueInfoSchema => {
                self.generated_aug_hashmap_e(slice, 352, EnqueuedMsg, Bits(64))
                    && self.hashmap_e(slice, 96, Leaf::Bits(320))
                    && maybe(slice, |s| {
                        tag(s, 4, 0)
                            && self.generated_aug_hashmap_e(s, 256, DispatchQueueEntry, Bits(64))
                            && maybe(s, |s| skip(s, 48))
                    })
            }
            DispatchQueueEntry => {
                self.hashmap_e(slice, 64, Leaf::Typed(EnqueuedMsg, profile)) && skip(slice, 48)
            }
            EnqueuedMsg => {
                skip(slice, 64) && self.push_ref(slice, Node::Typed(MsgEnvelope, profile))
            }
            MsgEnvelope => {
                let constructor = uint(slice, 4);
                matches!(constructor, Some(4 | 5))
                    && intermediate_address(slice)
                    && intermediate_address(slice)
                    && var(slice, 16, profile, false)
                    && self.push_ref(slice, Node::Typed(Message, profile))
                    && (constructor == Some(4)
                        || (maybe(slice, |s| skip(s, 64))
                            && maybe(slice, |s| {
                                tag(s, 4, 0)
                                    && skip(s, 32)
                                    && address_int(s, profile)
                                    && skip(s, 64)
                            })))
            }
            Bits(bits) => skip(slice, bits),
            CurrencyPair => {
                self.typed(CurrencyCollection, profile, slice)
                    && self.typed(CurrencyCollection, profile, slice)
            }
            CreatorStats => tag(slice, 4, 4) && skip(slice, 448),
            BlockCreateStats => match uint(slice, 8) {
                Some(0x17) => {
                    self.hashmap_e(slice, 256, Leaf::Typed(CreatorStats, TlbProfile::Generated))
                }
                Some(0x34) => self.generated_aug_hashmap_e(slice, 256, CreatorStats, Bits(32)),
                _ => false,
            },
            ShardDescrTreeRef => self.push_ref(slice, Node::Typed(ShardDescrTree, profile)),
            ShardDescrTree => match bool_bit(slice) {
                Some(false) => self.typed(ShardDescr, profile, slice),
                Some(true) => {
                    self.push_ref(slice, Node::Typed(ShardDescrTree, profile))
                        && self.push_ref(slice, Node::Typed(ShardDescrTree, profile))
                }
                None => false,
            },
            ShardDescr => {
                let constructor = uint(slice, 4);
                matches!(constructor, Some(0xa | 0xb))
                    && skip(slice, 704 + 5)
                    && tag(slice, 3, 0)
                    && skip(slice, 160)
                    && match bool_bit(slice) {
                        Some(false) => true,
                        Some(true) => skip(slice, 1 + 64),
                        None => false,
                    }
                    && if constructor == Some(0xb) {
                        self.typed(CurrencyPair, profile, slice)
                    } else {
                        self.push_ref(slice, Node::Typed(CurrencyPair, profile))
                    }
            }
            McStateExtra => {
                // The handwritten McStateExtra validator delegates to the
                // generated one, including all dictionary and currency rules.
                let generated = TlbProfile::Generated;
                tag(slice, 16, 0xcc26)
                    && self.hashmap_e(slice, 32, Leaf::Typed(ShardDescrTreeRef, generated))
                    && skip(slice, 256)
                    && self.push_ref(slice, Node::Hashmap(32, Leaf::AnyRef))
                    && self.push_ref(slice, Node::Typed(McStateExtraAux, generated))
                    && self.typed(CurrencyCollection, generated, slice)
            }
            McStateExtraAux => {
                let Some(flags) = uint(slice, 16) else {
                    return false;
                };
                flags <= 1
                    && skip(slice, 65)
                    && self.generated_aug_hashmap_e(slice, 32, Bits(609), Bits(65))
                    && skip(slice, 1)
                    && maybe(slice, |s| skip(s, 608))
                    && (flags == 0 || self.typed(BlockCreateStats, TlbProfile::Generated, slice))
            }
            ExtBlkRef => skip(slice, 608),
            PrevBlocks => {
                self.push_ref(slice, Node::Typed(ExtBlkRef, profile))
                    && self.push_ref(slice, Node::Typed(ExtBlkRef, profile))
            }
            BlockInfo => self.block_info(slice, profile),
            MessageRef => self.push_ref(slice, Node::Typed(Message, profile)),
            HashUpdate => tag(slice, 8, 0x72) && skip(slice, 512),
            Transaction => {
                tag(slice, 4, 7)
                    && skip(slice, 256 + 64 + 256 + 64 + 32 + 15 + 4)
                    && self.push_ref(slice, Node::Typed(TransactionAux, profile))
                    && self.typed(CurrencyCollection, profile, slice)
                    && self.push_ref(slice, Node::Typed(HashUpdate, profile))
                    && self.push_ref(slice, Node::Typed(TransactionDescr, profile))
            }
            TransactionAux => {
                maybe(slice, |s| self.push_ref(s, Node::Typed(Message, profile)))
                    && self.hashmap_e(slice, 15, Leaf::Typed(MessageRef, profile))
            }
            ComputeDetails => {
                var(slice, 7, profile, false)
                    && var(slice, 7, profile, false)
                    && maybe(slice, |s| var(s, 3, profile, false))
                    && skip(slice, 40)
                    && maybe(slice, |s| skip(s, 32))
                    && skip(slice, 32 + 512)
            }
            ActionPhase => {
                skip(slice, 3)
                    && status_change(slice)
                    && maybe(slice, |s| var(s, 16, profile, false))
                    && maybe(slice, |s| var(s, 16, profile, false))
                    && skip(slice, 32)
                    && maybe(slice, |s| skip(s, 32))
                    && skip(slice, 64 + 256)
                    && storage_used(slice, profile)
            }
            TransactionDescr => self.transaction_descr(slice, profile),
            Coins => var(slice, 16, profile, false),
            ExtraCurrencyValue => var(slice, 32, profile, true),
            ExtraCurrencyCollection => {
                self.hashmap_e(slice, 32, Leaf::Typed(ExtraCurrencyValue, profile))
            }
            CurrencyCollection => {
                var(slice, 16, profile, false)
                    && self.typed(ExtraCurrencyCollection, profile, slice)
            }
            MsgAddressInt => address_int(slice, profile),
            StateInit => state_init(slice),
            StorageUsed => storage_used(slice, profile),
            AccountStorage => {
                skip(slice, 64)
                    && self.typed(CurrencyCollection, profile, slice)
                    && match bool_bit(slice) {
                        Some(true) => state_init(slice),
                        Some(false) => match bool_bit(slice) {
                            Some(false) => true,
                            Some(true) => skip(slice, 256),
                            None => false,
                        },
                        None => false,
                    }
            }
            Account => match bool_bit(slice) {
                Some(false) => true,
                Some(true) => {
                    address_int(slice, profile)
                        && storage_info(slice, profile)
                        && self.typed(AccountStorage, profile, slice)
                }
                None => false,
            },
            ShardAccount => skip(slice, 320) && self.push_ref(slice, Node::Typed(Account, profile)),
            Message | MessageRelaxed => {
                let relaxed = matches!(kind, MessageRelaxed);
                let src = |s: &mut SliceData| {
                    if relaxed {
                        address_any(s, profile)
                    } else {
                        address_int(s, profile)
                    }
                };
                let info = match bool_bit(slice) {
                    Some(false) => {
                        skip(slice, 3)
                            && src(slice)
                            && address_int(slice, profile)
                            && self.typed(CurrencyCollection, profile, slice)
                            && var(slice, 16, profile, false)
                            && var(slice, 16, profile, false)
                            && skip(slice, 96)
                    }
                    Some(true) => match bool_bit(slice) {
                        Some(false) => {
                            !relaxed
                                && address_ext(slice)
                                && address_int(slice, profile)
                                && var(slice, 16, profile, false)
                        }
                        Some(true) => src(slice) && address_ext(slice) && skip(slice, 96),
                        None => false,
                    },
                    None => false,
                };
                if !info {
                    return false;
                }
                let init = match bool_bit(slice) {
                    Some(false) => true,
                    Some(true) => match bool_bit(slice) {
                        Some(false) => state_init(slice),
                        Some(true) => self.push_ref(slice, Node::Typed(StateInit, profile)),
                        None => false,
                    },
                    None => false,
                };
                init && match bool_bit(slice) {
                    Some(true) => slice.checked_drain_reference().is_ok(),
                    Some(false) => {
                        let bits = slice.remaining_bits();
                        skip(slice, bits)
                            && (0..slice.remaining_references())
                                .all(|_| slice.checked_drain_reference().is_ok())
                    }
                    None => false,
                }
            }
        }
    }

    fn credit_phase(&mut self, slice: &mut SliceData, profile: TlbProfile) -> bool {
        maybe(slice, |s| var(s, 16, profile, false))
            && self.typed(TlbType::CurrencyCollection, profile, slice)
    }

    fn block_info(&mut self, slice: &mut SliceData, profile: TlbProfile) -> bool {
        use TlbType::*;
        if !tag(slice, 32, 0x9bc7a987) || !skip(slice, 32) {
            return false;
        }
        let (Some(not_master), Some(after_merge)) = (bool_bit(slice), bool_bit(slice)) else {
            return false;
        };
        if !skip(slice, 5) {
            return false;
        }
        let (Some(vert_incr), Some(flags), Some(seqno), Some(vert_seqno)) =
            (bool_bit(slice), uint(slice, 8), uint(slice, 32), uint(slice, 32))
        else {
            return false;
        };
        flags <= 1
            && seqno > 0
            && vert_seqno >= u64::from(vert_incr)
            && shard_ident(slice)
            && skip(slice, 32 + 128 + 128)
            && (flags == 0 || (tag(slice, 8, 0xc4) && skip(slice, 96)))
            && (!not_master || self.push_ref(slice, Node::Typed(ExtBlkRef, profile)))
            && self.push_ref(
                slice,
                Node::Typed(if after_merge { PrevBlocks } else { ExtBlkRef }, profile),
            )
            && (!vert_incr || self.push_ref(slice, Node::Typed(ExtBlkRef, profile)))
    }

    fn compute_phase(&mut self, slice: &mut SliceData, profile: TlbProfile) -> bool {
        match bool_bit(slice) {
            Some(true) => {
                skip(slice, 3)
                    && var(slice, 16, profile, false)
                    && self.push_ref(slice, Node::Typed(TlbType::ComputeDetails, profile))
            }
            Some(false) => match uint(slice, 2) {
                Some(0..=2) => true,
                Some(3) => tag(slice, 1, 0),
                _ => false,
            },
            None => false,
        }
    }

    fn transaction_descr(&mut self, slice: &mut SliceData, profile: TlbProfile) -> bool {
        use TlbType::*;
        match uint(slice, 4) {
            Some(0) => {
                skip(slice, 1)
                    && maybe(slice, |s| storage_phase(s, profile))
                    && maybe(slice, |s| self.credit_phase(s, profile))
                    && self.compute_phase(slice, profile)
                    && self.maybe_ref(slice, Node::Typed(ActionPhase, profile))
                    && skip(slice, 1)
                    && maybe(slice, |s| bounce_phase(s, profile))
                    && skip(slice, 1)
            }
            Some(1) => storage_phase(slice, profile),
            Some(2 | 3) => {
                storage_phase(slice, profile)
                    && self.compute_phase(slice, profile)
                    && self.maybe_ref(slice, Node::Typed(ActionPhase, profile))
                    && skip(slice, 2)
            }
            Some(4) => {
                skip(slice, 524)
                    && maybe(slice, |s| storage_phase(s, profile))
                    && self.compute_phase(slice, profile)
                    && self.maybe_ref(slice, Node::Typed(ActionPhase, profile))
                    && skip(slice, 2)
            }
            Some(5) => {
                skip(slice, 524)
                    && self.push_ref(slice, Node::Typed(Transaction, profile))
                    && skip(slice, 1)
            }
            Some(6) => skip(slice, 524) && storage_phase(slice, profile) && skip(slice, 1),
            Some(7) => {
                skip(slice, 524)
                    && self.push_ref(slice, Node::Typed(Transaction, profile))
                    && maybe(slice, |s| storage_phase(s, profile))
                    && maybe(slice, |s| self.credit_phase(s, profile))
                    && (if profile == TlbProfile::Handwritten {
                        maybe(slice, |s| self.compute_phase(s, profile))
                    } else {
                        self.compute_phase(slice, profile)
                    })
                    && self.maybe_ref(slice, Node::Typed(ActionPhase, profile))
                    && skip(slice, 2)
            }
            _ => false,
        }
    }
}
