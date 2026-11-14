// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//! Reassembly reservations following TOS rldp-inbound-budget.h.
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, OnceLock},
};
pub type PeerId = [u8; 32];
pub const MAX_DECODERS: u64 = 16384;
pub const MAX_BYTES: u64 = 512 << 20;

pub fn decoder_reservation_bytes(
    data_size: u64,
    symbol_size: u64,
    symbols_count: u64,
) -> Option<u64> {
    let symbols = symbols_count.checked_mul(2)?.checked_add(10)?;
    let per_symbol = symbol_size.checked_add(128)?;
    symbols.checked_mul(per_symbol)?.checked_add(4096)?.checked_add(data_size)
}
pub fn solver_working_bytes(symbol_size: u64, symbols_count: u64) -> Option<u64> {
    let per_symbol = symbol_size.checked_mul(6)?;
    symbols_count.checked_mul(per_symbol)?.checked_add(128 << 10)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Solicited,
    Unsolicited,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub decoders: u64,
    pub bytes: u64,
}
impl Usage {
    fn take(self, decoders: u64, bytes: u64, headroom: u64, limit: Self) -> Option<Self> {
        let next = Self {
            decoders: self.decoders.checked_add(decoders)?,
            bytes: self.bytes.checked_add(bytes)?,
        };
        (next.decoders <= limit.decoders && next.bytes.checked_add(headroom)? <= limit.bytes)
            .then_some(next)
    }
}
#[derive(Default)]
struct State {
    total: Usage,
    unsolicited: Usage,
    identities: BTreeMap<PeerId, Usage>,
}

/// Shared reservation ledger. Owners reserve before allocating, and retain
/// the token until the decoder/output buffers it charges are released.
pub struct InboundBudget {
    limit: Usage,
    unsolicited: Usage,
    per_identity: Usage,
    max_identities: u64,
    state: Mutex<State>,
}
impl InboundBudget {
    pub fn new(max_decoders: u64, max_bytes: u64) -> Arc<Self> {
        let unsolicited = Usage { decoders: max_decoders / 2, bytes: max_bytes / 2 };
        Arc::new(Self {
            limit: Usage { decoders: max_decoders, bytes: max_bytes },
            unsolicited,
            per_identity: Usage {
                decoders: unsolicited.decoders / 8,
                bytes: unsolicited.bytes / 2,
            },
            max_identities: unsolicited.decoders,
            state: Mutex::new(State::default()),
        })
    }
    pub fn process_default() -> Arc<Self> {
        static BUDGET: OnceLock<Arc<InboundBudget>> = OnceLock::new();
        BUDGET.get_or_init(|| Self::new(MAX_DECODERS, MAX_BYTES)).clone()
    }
    pub fn reserve(
        self: &Arc<Self>,
        kind: Kind,
        peer: PeerId,
        decoders: u64,
        bytes: u64,
        headroom: u64,
    ) -> Option<Reservation> {
        let mut state = self.state.lock().unwrap();
        let total = state.total.take(decoders, bytes, headroom, self.limit)?;
        if kind == Kind::Unsolicited {
            let pool = state.unsolicited.take(decoders, bytes, headroom, self.unsolicited)?;
            if decoders != 0 || bytes != 0 {
                if !state.identities.contains_key(&peer)
                    && state.identities.len() as u64 >= self.max_identities
                {
                    return None;
                }
                let identity = state.identities.get(&peer).copied().unwrap_or_default().take(
                    decoders,
                    bytes,
                    headroom,
                    self.per_identity,
                )?;
                state.identities.insert(peer, identity);
                state.unsolicited = pool;
            }
        }
        state.total = total;
        Some(Reservation { budget: self.clone(), kind, peer, held: Usage { decoders, bytes } })
    }
    fn release(&self, kind: Kind, peer: &PeerId, held: Usage) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.total.decoders < held.decoders || state.total.bytes < held.bytes {
            return false;
        }
        if kind == Kind::Unsolicited && held != Usage::default() {
            let Some(identity) = state.identities.get(peer).copied() else {
                return false;
            };
            if state.unsolicited.decoders < held.decoders
                || state.unsolicited.bytes < held.bytes
                || identity.decoders < held.decoders
                || identity.bytes < held.bytes
            {
                return false;
            }
            let identity = Usage {
                decoders: identity.decoders - held.decoders,
                bytes: identity.bytes - held.bytes,
            };
            if identity == Usage::default() {
                state.identities.remove(peer);
            } else {
                state.identities.insert(*peer, identity);
            }
            state.unsolicited.decoders -= held.decoders;
            state.unsolicited.bytes -= held.bytes;
        }
        state.total.decoders -= held.decoders;
        state.total.bytes -= held.bytes;
        true
    }
    pub fn usage(&self) -> Usage {
        self.state.lock().unwrap().total
    }
    pub fn unsolicited_usage(&self) -> Usage {
        self.state.lock().unwrap().unsolicited
    }
    pub fn identity_usage(&self, peer: &PeerId) -> Usage {
        self.state.lock().unwrap().identities.get(peer).copied().unwrap_or_default()
    }
    pub fn identity_count(&self) -> usize {
        self.state.lock().unwrap().identities.len()
    }
}

/// Owned decoder/output charge. Headroom is checked but never retained as usage.
pub struct Reservation {
    budget: Arc<InboundBudget>,
    kind: Kind,
    peer: PeerId,
    held: Usage,
}
impl Reservation {
    pub fn held(&self) -> Usage {
        self.held
    }
    pub fn shrink_to(&mut self, decoders: u64, bytes: u64) {
        let next =
            Usage { decoders: decoders.min(self.held.decoders), bytes: bytes.min(self.held.bytes) };
        let give = Usage {
            decoders: self.held.decoders - next.decoders,
            bytes: self.held.bytes - next.bytes,
        };
        if self.budget.release(self.kind, &self.peer, give) {
            self.held = next;
        } else {
            log::error!("RLDP2 inbound reservation released more than held");
        }
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.budget.release(self.kind, &self.peer, self.held) {
            log::error!("RLDP2 inbound reservation released more than held");
        }
    }
}
