// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Abort the first durable state, before Selection has acquired a descriptor.
//! Only the exact main selection.v1 filename is owned; no Ready, stages,
//! backlinks, or canonical changes are authorized in this state.
use super::{recovery_artifacts::directory, recovery_data, recovery_participant::Anchor,
    recovery_providers::RecoveryProviders, recovery_root::{RootHeader, State}};
use rtos_block::{fail, Result};
use std::fs;

pub(super) fn prepare_abort(providers: &RecoveryProviders, root: &RootHeader) -> Result<RootHeader> {
    if root.state != State::Preparing { fail!("Expected Preparing recovery state"); }
    providers.validate_controls(root)?;
    providers.verify_provider_and_map_inventories(root)?;
    if recovery_data::inventory(providers)? != root.data { fail!("Preparing original archive data changed"); }
    for (index, participant) in providers.participants.iter().enumerate() {
        let operation = super::recovery_stages::operation(providers, root, index)?;
        let controls = operation.parent().expect("operation has parent");
        let archive = controls.parent().expect("controls have parent");
        if !directory(archive)? || !directory(controls)? { continue; }
        for entry in fs::read_dir(controls)? {
            if entry?.file_name() != operation.file_name().unwrap() { fail!("Unknown Preparing operation"); }
        }
        if !directory(&operation)? { continue; }
        for entry in fs::read_dir(&operation)? {
            let entry = entry?;
            if participant.descriptor.anchor != Anchor::Node || entry.file_name() != "selection.v1"
                || !super::recovery_stages::present(&entry.path())? {
                fail!("Unowned or invalid Preparing artifact");
            }
        }
    }
    let mut cleaned = root.clone();
    cleaned.state = State::Cleaned;
    cleaned.aborted = true;
    root.check_successor(&cleaned)?;
    Ok(cleaned)
}

pub(super) fn discard_selection(providers: &RecoveryProviders, root: &RootHeader) -> Result<()> {
    prepare_abort(providers, root)?;
    for participant in &providers.participants {
        if participant.descriptor.anchor == Anchor::Node {
            super::recovery_worker::clean_stage(&participant.archive_root, root, c"selection.v1")?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/test_recovery_preparing.rs"]
mod tests;
