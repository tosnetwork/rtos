// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Consensus descriptor transitions and the execution engines implemented locally.

use crate::{
    fail, Cell, CellType, ConfigParam12, ConfigParams, Deserializable, IBitstring, Result,
    Serializable, SliceData, WorkchainDescr, WorkchainFormat, Workchains, MASTERCHAIN_ID,
};

#[derive(Debug, PartialEq, Eq)]
enum ExecutionKey {
    Basic(i32),
    Extended(u32),
}
fn execution_key(descriptor: &WorkchainDescr) -> ExecutionKey {
    match &descriptor.format {
        WorkchainFormat::Basic(format) => ExecutionKey::Basic(format.vm_version),
        WorkchainFormat::Extended(format) => ExecutionKey::Extended(format.workchain_type_id()),
    }
}
fn address_shape(descriptor: &WorkchainDescr) -> (u16, u16, u16) {
    match &descriptor.format {
        WorkchainFormat::Basic(_) => (256, 256, 256),
        WorkchainFormat::Extended(format) => {
            (format.min_addr_len(), format.max_addr_len(), format.addr_len_step())
        }
    }
}
impl ConfigParams {
    // Validate the lookup path for parameter 12 without inspecting unrelated
    // configuration branches. The value must be exactly one reference.
    fn workchain_parameter_cell(&self) -> Result<Option<Cell>> {
        let Some(mut cell) = self.root().cloned() else {
            return Ok(None);
        };
        let mut key = 12u32.write_to_bitstring()?;
        loop {
            if cell.cell_type() != CellType::Ordinary {
                fail!("invalid workchain configuration dictionary cell");
            }
            let mut slice = SliceData::load_cell(cell)?;
            if slice.remaining_bits() == 0 {
                fail!("missing workchain configuration dictionary label");
            }
            let label =
                crate::dictionary::LabelReader::read_label(&mut slice, key.remaining_bits())?;
            if label.remaining_bits() < key.remaining_bits()
                && (slice.remaining_bits() != 0 || slice.remaining_references() != 2)
            {
                fail!("invalid workchain configuration dictionary fork");
            }
            if !label.is_empty_bitstring() && !key.erase_prefix(&label) {
                return Ok(None);
            }
            if key.is_empty_bitstring() {
                if slice.remaining_bits() != 0 || slice.remaining_references() != 1 {
                    fail!("invalid workchain configuration value");
                }
                return Ok(Some(slice.reference(0)?));
            }
            cell = slice.reference(usize::from(key.get_next_bit()?))?;
        }
    }

    fn execution_workchains(&self) -> Result<Workchains> {
        let descriptors = match self.workchain_parameter_cell()? {
            Some(cell) => ConfigParam12::construct_from_cell(cell)?.workchains,
            None => Workchains::default(),
        };
        if let Some(root) = descriptors.root() {
            validate_descriptor_tree(root.clone(), 32, false, &mut 0)?;
        }
        descriptors.iterate_with_keys(|id: i32, _: WorkchainDescr| {
            if id == i32::MIN {
                fail!("invalid workchain execution identifier");
            }
            Ok(true)
        })?;
        Ok(descriptors)
    }

    /// Existing descriptors cannot silently change execution identity or genesis.
    /// This applies to inactive descriptors too; newly added workchains are allowed.
    pub fn validate_workchain_execution_transition(&self, next: &Self) -> Result<()> {
        let old = self.execution_workchains()?;
        let new = next.execution_workchains()?;
        old.iterate_with_keys(|id: i32, previous: WorkchainDescr| {
            let Some(current) = new.get(&id)? else {
                fail!("workchain {id} removes its execution descriptor without a migration rule")
            };
            if execution_key(&previous) != execution_key(&current) {
                fail!("workchain {id} changes execution key without a migration rule")
            }
            if previous.version != current.version {
                fail!("workchain {id} changes descriptor version without a migration rule")
            }
            if let (WorkchainFormat::Basic(a), WorkchainFormat::Basic(b)) =
                (&previous.format, &current.format)
            {
                if a.vm_mode != b.vm_mode {
                    fail!("workchain {id} changes vm_mode without a migration rule")
                }
            }
            if address_shape(&previous) != address_shape(&current) {
                fail!("workchain {id} changes address-length shape without a migration rule")
            }
            if previous.zerostate_root_hash != current.zerostate_root_hash {
                fail!("workchain {id} changes zerostate_root_hash without a migration rule")
            }
            if previous.zerostate_file_hash != current.zerostate_file_hash {
                fail!("workchain {id} changes zerostate_file_hash without a migration rule")
            }
            Ok(true)
        })?;
        Ok(())
    }

    /// Check only the engine needed for this local shard. Masterchain validation
    /// may observe remote workchains whose engines are not installed locally.
    /// Workchain existence, activation time and shard layout have separate checks.
    pub fn validate_local_workchain_execution(&self, workchain: i32) -> Result<()> {
        let descriptors = self.execution_workchains()?;
        if workchain == MASTERCHAIN_ID {
            return Ok(());
        }
        let Some(descriptor) = descriptors.get(&workchain)? else {
            return Ok(());
        };
        if !descriptor.active {
            return Ok(());
        }
        match descriptor.format {
            WorkchainFormat::Basic(format) if format.vm_version == -1 => {
                if format.vm_mode != 0 {
                    fail!("workchain {workchain} TVM descriptor requires vm_mode=0")
                }
            }
            _ => fail!("missing local workchain execution engine for workchain {workchain}"),
        }
        Ok(())
    }
}

// Per-parameter validation consumes the entire value. Execution descriptor
// unpacking intentionally permits trailing data, as does the reference loader.
fn validate_descriptor_tree(
    cell: Cell,
    remaining: usize,
    exact: bool,
    cells: &mut usize,
) -> Result<()> {
    if exact {
        *cells = cells.checked_sub(1).ok_or_else(|| {
            crate::error!("workchain configuration exceeds validation cell budget")
        })?;
    }
    if cell.cell_type() != CellType::Ordinary {
        fail!("invalid workchain dictionary cell");
    }
    let mut slice = SliceData::load_cell(cell)?;
    if slice.remaining_bits() == 0 {
        fail!("missing workchain dictionary label");
    }
    let label = crate::dictionary::LabelReader::read_label(&mut slice, remaining)?;
    let remaining = remaining - label.remaining_bits();
    if remaining == 0 {
        WorkchainDescr::construct_from(&mut slice)?;
        if exact && !slice.is_empty_cell() {
            fail!("trailing workchain descriptor data");
        }
    } else {
        if slice.remaining_bits() != 0 || slice.remaining_references() != 2 {
            fail!("invalid workchain dictionary fork");
        }
        validate_descriptor_tree(slice.reference(0)?, remaining - 1, exact, cells)?;
        validate_descriptor_tree(slice.reference(1)?, remaining - 1, exact, cells)?;
    }
    Ok(())
}

impl ConfigParams {
    /// Validate only the ConfigParam12 TLB value; execution selection and
    /// descriptor-transition rules are checked independently.
    pub fn validate_workchain_descriptor_config(&self) -> Result<()> {
        let Some(cell) = self.workchain_parameter_cell()? else {
            return Ok(());
        };
        if cell.cell_type() != CellType::Ordinary {
            fail!("invalid workchain configuration cell");
        }
        let mut slice = SliceData::load_cell(cell)?;
        let present = slice.get_next_bit()?;
        if slice.remaining_bits() != 0 || slice.remaining_references() != usize::from(present) {
            fail!("trailing workchain configuration data");
        }
        if present {
            // The complete ConfigParam12 validation permits 1024 reference visits,
            // including its outer cell. Shared dictionary cells count on each visit.
            validate_descriptor_tree(slice.reference(0)?, 32, true, &mut 1023)?;
        }
        Ok(())
    }
}
