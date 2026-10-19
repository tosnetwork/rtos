// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! ConfigParam48 authentication retirement policy. Network binding here preserves
//! the configured identity across transitions; authenticating that identity is
//! the caller's governing-state responsibility.

use crate::{
    error, fail, BuilderData, Cell, CellType, ConfigParams, Deserializable, HashmapE, HashmapType,
    IBitstring, Result, Serializable, SliceData, UInt256,
};

pub const AUTH_POLICY_PROFILE: &str = "TOS-AUTH-POLICY-v1;config=48;tag=a1;suite=1;retired=u16;sequence=u64;deadline=u32;network=bits256;monotonic";

/// ConfigParam8 global version from which ConfigParam48 must be present; the
/// network launches at this version, so every launched configuration carries it.
pub const AUTH_POLICY_REQUIRED_VERSION: u32 = 16;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuthPolicy {
    pub network: UInt256,
    pub sequence: u64,
    pub retired: u16,
    /// Zero means no retirement deadline is scheduled.
    pub deadline: u32,
}

// The generic dictionary reader tolerates extra fork bits. AUTH lookups follow
// the reference's strict fork shape without broadening this change to VM maps.
fn auth_lookup(root: Option<&Cell>, mut key: SliceData) -> Result<Option<SliceData>> {
    let Some(mut cell) = root.cloned() else {
        return Ok(None);
    };
    loop {
        if cell.cell_type() != CellType::Ordinary {
            fail!("invalid AUTH dictionary cell");
        }
        let mut slice = SliceData::load_cell(cell)?;
        if slice.remaining_bits() == 0 {
            fail!("missing AUTH dictionary label");
        }
        let label = crate::dictionary::LabelReader::read_label(&mut slice, key.remaining_bits())?;
        if label.remaining_bits() < key.remaining_bits()
            && (slice.remaining_bits() != 0 || slice.remaining_references() != 2)
        {
            fail!("invalid AUTH dictionary fork");
        }
        if !label.is_empty_bitstring() && !key.erase_prefix(&label) {
            return Ok(None);
        }
        if key.is_empty_bitstring() {
            return Ok(Some(slice));
        }
        cell = slice.reference(usize::from(key.get_next_bit()?))?;
    }
}

impl Deserializable for AuthPolicy {
    fn read_from(&mut self, slice: &mut SliceData) -> Result<()> {
        if slice.cell_type() != CellType::Ordinary
            || slice.level() != 0
            || slice.remaining_bits() != 601
            || slice.get_next_byte()? != 0xa1
        {
            fail!("invalid AUTH policy cell");
        }
        let network = UInt256::construct_from(slice)?;
        let sequence = slice.get_next_u64()?;
        let retired = slice.get_next_u16()?;
        if retired & !2 != 0 {
            fail!("unknown AUTH retirement bits");
        }
        let present = slice.get_next_bit()?;
        if slice.remaining_references() != usize::from(present) {
            fail!("invalid AUTH schedule references");
        }
        let schedule = if present { Some(slice.checked_drain_reference()?) } else { None };
        if UInt256::construct_from(slice)?
            != UInt256::calc_file_hash(AUTH_POLICY_PROFILE.as_bytes())
            || !slice.is_empty_cell()
        {
            fail!("invalid AUTH policy profile");
        }
        let mut deadline = 0;
        if let Some(cell) = schedule {
            if cell.cell_type() != CellType::Ordinary || cell.level() != 0 {
                fail!("invalid AUTH schedule cell");
            }
            let map = HashmapE::with_hashmap(8, Some(cell));
            map.iterate_slices(|mut key, mut value| {
                if deadline != 0
                    || key.remaining_bits() != 8
                    || key.get_next_byte()? != 1
                    || value.remaining_bits() != 32
                    || value.remaining_references() != 0
                {
                    fail!("invalid AUTH retirement schedule");
                }
                deadline = value.get_next_u32()?;
                if deadline == 0 {
                    fail!("AUTH retirement deadline must be nonzero");
                }
                Ok(true)
            })?;
            if deadline == 0 {
                fail!("empty AUTH retirement schedule");
            }
        }
        *self = Self { network, sequence, retired, deadline };
        Ok(())
    }
}

impl Serializable for AuthPolicy {
    fn write_to(&self, builder: &mut BuilderData) -> Result<()> {
        if self.retired & !2 != 0 {
            fail!("unknown AUTH retirement bits");
        }
        builder.append_u8(0xa1)?;
        self.network.write_to(builder)?;
        self.sequence.write_to(builder)?;
        self.retired.write_to(builder)?;
        let mut schedule = HashmapE::with_bit_len(8);
        if self.deadline != 0 {
            schedule.set(1u8.write_to_bitstring()?, &self.deadline.write_to_bitstring()?)?;
        }
        schedule.write_to(builder)?;
        UInt256::calc_file_hash(AUTH_POLICY_PROFILE.as_bytes()).write_to(builder)
    }
}

/// Admission of a masterchain configuration before it becomes trusted state.
///
/// `previous` is `None` when no trusted state precedes the candidate (initial or
/// restored state); otherwise it is the lookup of the currently trusted
/// configuration. The branch order is part of the contract: a candidate lookup
/// error is reported first and never reads as an absent configuration; then a
/// previous lookup error; then a previous configuration without a root, which
/// would otherwise read as "no policy" and admit a fresh sequence-zero policy.
pub fn validate_auth_policy_admission(
    candidate: Result<&ConfigParams>,
    previous: Option<Result<&ConfigParams>>,
) -> Result<()> {
    let next = candidate?;
    let Some(previous) = previous else {
        return next.validate_auth_policy_config();
    };
    let old = previous?;
    if old.root().is_none() {
        fail!("previous AUTH configuration root is missing");
    }
    old.validate_auth_policy_transition(next)
}

impl ConfigParams {
    fn auth_parameter_cell(&self, number: u32) -> Result<Option<Cell>> {
        auth_lookup(self.root(), number.write_to_bitstring()?)?
            .map(|slice| {
                if slice.remaining_bits() != 0 || slice.remaining_references() != 1 {
                    fail!("AUTH configuration value must contain exactly one reference");
                }
                slice.reference(0)
            })
            .transpose()
    }

    pub fn auth_policy(&self) -> Result<Option<AuthPolicy>> {
        self.auth_parameter_cell(48)?.map(AuthPolicy::construct_from_cell).transpose()
    }

    pub fn validate_auth_policy_config(&self) -> Result<()> {
        if self.root().is_none() {
            fail!("AUTH configuration root is missing");
        }
        let required = match self.auth_parameter_cell(8)? {
            Some(cell) => {
                let mut slice = SliceData::load_cell(cell)?;
                if slice.remaining_bits() != 104
                    || slice.remaining_references() != 0
                    || slice.get_next_byte()? != 0xc4
                {
                    fail!("invalid AUTH governing version");
                }
                slice.get_next_u32()? >= AUTH_POLICY_REQUIRED_VERSION
            }
            None => false,
        };
        let policy = self.auth_policy()?;
        if policy.is_none() {
            if required {
                fail!("AUTH policy is required from version {AUTH_POLICY_REQUIRED_VERSION}");
            }
            return Ok(());
        }
        for number in [9, 10] {
            let cell = self
                .auth_parameter_cell(number)?
                .ok_or_else(|| error!("AUTH policy must be mandatory and critical"))?;
            if auth_lookup(Some(&cell), 48u32.write_to_bitstring()?)?.is_none() {
                fail!("AUTH policy must be mandatory and critical");
            }
        }
        Ok(())
    }

    pub fn validate_auth_policy_transition(&self, next: &Self) -> Result<()> {
        next.validate_auth_policy_config()?;
        let old_cell = self.auth_parameter_cell(48)?;
        let new_cell = next.auth_parameter_cell(48)?;
        if old_cell.is_none() && new_cell.is_none() {
            return Ok(());
        }
        let new_cell = new_cell.ok_or_else(|| error!("AUTH policy cannot be removed"))?;
        let new_policy = AuthPolicy::construct_from_cell(new_cell.clone())?;
        let Some(old_cell) = old_cell else {
            if new_policy.sequence != 0 {
                fail!("initial AUTH policy sequence must be zero");
            }
            return Ok(());
        };
        let previous = AuthPolicy::construct_from_cell(old_cell.clone())?;
        if old_cell.repr_hash() == new_cell.repr_hash() {
            return Ok(());
        }
        if previous.network != new_policy.network
            || new_policy.sequence <= previous.sequence
            || new_policy.retired & previous.retired != previous.retired
            || (previous.deadline != 0
                && (new_policy.deadline == 0 || new_policy.deadline > previous.deadline))
        {
            fail!("AUTH retirement policy cannot roll back");
        }
        Ok(())
    }
}
