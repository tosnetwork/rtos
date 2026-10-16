// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Root archive recovery wire format. Decoding does not authorize recovery IO.
use rtos_block::{error, fail, sha256_digest, Result};

pub(crate) const ROOT_KEY: &[u8] = b"ArchiveTruncationRootV1";
pub(crate) const PARTICIPANT_KEY: &[u8] = b"ArchiveTruncationParticipantV1";
pub(crate) const HEADER_SIZE: usize = 316;
const CHECKSUM_OFFSET: usize = HEADER_SIZE - 32;
const MAGIC: &[u8; 8] = b"RTOSATR1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    Building = 1,
    Ready = 2,
    Committed = 3,
    Cleaned = 4,
    Preparing = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Policy {
    Node = 2,
    StandaloneWithoutLedger = 4,
    StandaloneWithLedger = 6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FactoryMode {
    Node,
    Standalone,
}

impl Policy {
    /// Presence and trusted factory checks only. The caller must also validate
    /// the durable ledger and rebuild protection before any recovery effects.
    pub(crate) fn check_environment(self, mode: FactoryMode, ledger_exists: bool) -> Result<()> {
        let expected_mode = if self == Self::Node { FactoryMode::Node } else { FactoryMode::Standalone };
        if mode != expected_mode {
            fail!("Archive recovery factory mode mismatch");
        }
        if ledger_exists != (self != Self::StandaloneWithoutLedger) {
            fail!("Archive recovery ledger presence mismatch");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Inventory {
    pub count: u64,
    pub digest: [u8; 32],
}

impl Inventory {
    fn require(self, present: bool) -> Result<()> {
        if present {
            if self.digest == [0; 32] {
                fail!("Missing archive inventory digest");
            }
        } else if self != Self::default() {
            fail!("Unexpected archive inventory before its durable state");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Sidecar {
    pub bytes: u64,
    pub records: u64,
    pub digest: [u8; 32],
}

impl Sidecar {
    fn require(self, present: bool) -> Result<()> {
        if present {
            if self.bytes == 0 || self.digest == [0; 32] {
                fail!("Missing archive sidecar descriptor");
            }
        } else if self != Self::default() {
            fail!("Unexpected archive Ready descriptor");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RootHeader {
    pub state: State,
    pub policy: Policy,
    pub aborted: bool,
    pub operation: [u8; 16],
    pub database_identity_bytes: u64,
    pub database_identity_digest: [u8; 32],
    pub selection: Sidecar,
    pub ready: Sidecar,
    pub providers: Inventory,
    pub maps: Inventory,
    pub data: Inventory,
}

impl RootHeader {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.operation == [0; 16]
            || self.database_identity_bytes == 0
            || self.database_identity_digest == [0; 32]
        {
            fail!("Missing archive root operation or database identity");
        }
        if self.aborted && self.state != State::Cleaned {
            fail!("Archive abort disposition requires Cleaned state");
        }
        // Preparing is durable before any control directory or sidecar exists.
        // Its inventories describe the complete original canonical state.
        let unselected_abort = self.state == State::Cleaned && self.aborted
            && self.selection == Sidecar::default();
        self.selection.require(self.state != State::Preparing && !unselected_abort)?;
        self.ready.require(!matches!(self.state, State::Preparing | State::Building) && !self.aborted)?;
        self.providers.require(matches!(self.state, State::Preparing | State::Cleaned))?;
        self.maps.require(matches!(self.state, State::Preparing | State::Committed | State::Cleaned))?;
        self.data.require(matches!(self.state, State::Preparing | State::Cleaned))?;
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<[u8; HEADER_SIZE]> {
        self.validate()?;
        let mut bytes = [0; HEADER_SIZE];
        let mut pos = 0;
        let mut put = |value: &[u8]| {
            bytes[pos..pos + value.len()].copy_from_slice(value);
            pos += value.len();
        };
        put(MAGIC);
        put(&1u16.to_le_bytes());
        put(&[self.state as u8, self.policy as u8 | u8::from(self.aborted)]);
        put(&self.operation);
        put(&self.database_identity_bytes.to_le_bytes());
        put(&self.database_identity_digest);
        for sidecar in [self.selection, self.ready] {
            put(&sidecar.bytes.to_le_bytes());
            put(&sidecar.records.to_le_bytes());
            put(&sidecar.digest);
        }
        for inventory in [self.providers, self.maps, self.data] {
            put(&inventory.count.to_le_bytes());
            put(&inventory.digest);
        }
        debug_assert_eq!(pos, CHECKSUM_OFFSET);
        let checksum = sha256_digest(&bytes[..CHECKSUM_OFFSET]);
        bytes[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HEADER_SIZE {
            fail!("Archive root header length mismatch");
        }
        if sha256_digest(&bytes[..CHECKSUM_OFFSET]) != bytes[CHECKSUM_OFFSET..] {
            fail!("Archive root header checksum mismatch");
        }
        let mut reader = HeaderReader { bytes: &bytes[..CHECKSUM_OFFSET], pos: 0 };
        if reader.take::<8>()? != *MAGIC || u16::from_le_bytes(reader.take()?) != 1 {
            fail!("Unknown archive root header format");
        }
        let state = match reader.take::<1>()?[0] {
            1 => State::Building,
            2 => State::Ready,
            3 => State::Committed,
            4 => State::Cleaned,
            5 => State::Preparing,
            _ => fail!("Unknown archive root state"),
        };
        let flags = reader.take::<1>()?[0];
        let policy = match flags & !1 {
            2 => Policy::Node,
            4 => Policy::StandaloneWithoutLedger,
            6 => Policy::StandaloneWithLedger,
            _ => fail!("Unknown or invalid archive root policy"),
        };
        let header = Self {
            state,
            policy,
            aborted: flags & 1 != 0,
            operation: reader.take()?,
            database_identity_bytes: reader.u64()?,
            database_identity_digest: reader.take()?,
            selection: reader.sidecar()?,
            ready: reader.sidecar()?,
            providers: reader.inventory()?,
            maps: reader.inventory()?,
            data: reader.inventory()?,
        };
        if reader.pos != CHECKSUM_OFFSET {
            fail!("Archive root header framing mismatch");
        }
        header.validate()?;
        Ok(header)
    }

    /// Checks a proposed record transition, not whether its IO is durable.
    /// Only the actual recovery executor may establish that latter condition.
    pub(crate) fn check_successor(&self, next: &Self) -> Result<()> {
        self.validate()?;
        next.validate()?;
        if self == next {
            return Ok(()); // Re-sync the selected state after uncertain sync.
        }
        if self.operation != next.operation
            || self.policy != next.policy
            || self.database_identity_bytes != next.database_identity_bytes
            || self.database_identity_digest != next.database_identity_digest
            || (self.state != State::Preparing && self.selection != next.selection)
        {
            fail!("Archive root immutable identity changed");
        }
        let legal = match (self.state, next.state) {
            (State::Preparing, State::Building) => true,
            (State::Preparing, State::Cleaned) => next.aborted
                && next.selection == self.selection && next.providers == self.providers
                && next.maps == self.maps && next.data == self.data,
            (State::Building, State::Ready) => true,
            (State::Building, State::Cleaned) => next.aborted,
            (State::Ready, State::Committed) => self.ready == next.ready,
            (State::Committed, State::Cleaned) => {
                !next.aborted && self.ready == next.ready && self.maps == next.maps
            }
            _ => false,
        };
        if !legal {
            fail!("Invalid archive root state transition");
        }
        Ok(())
    }
}

struct HeaderReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl HeaderReader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self.pos.checked_add(N).ok_or_else(|| error!("Archive header offset overflow"))?;
        let value = self.bytes.get(self.pos..end).ok_or_else(|| error!("Truncated archive header"))?;
        self.pos = end;
        value.try_into().map_err(|_| error!("Archive header field size mismatch"))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take()?))
    }
    fn sidecar(&mut self) -> Result<Sidecar> {
        Ok(Sidecar { bytes: self.u64()?, records: self.u64()?, digest: self.take()? })
    }
    fn inventory(&mut self) -> Result<Inventory> {
        Ok(Inventory { count: self.u64()?, digest: self.take()? })
    }
}

#[cfg(test)]
#[path = "../tests/test_recovery_root.rs"]
mod tests;
