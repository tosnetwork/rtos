// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Validate an interrupted Building operation against its original data.
//! Unknown child records or artifacts retain the original root and all inputs.
use super::{
    recovery_artifacts, recovery_data,
    recovery_manifest::{Kind, Record},
    recovery_parent::{self, InventoryRole},
    recovery_participant::Anchor,
    recovery_providers::RecoveryProviders,
    recovery_root::{Inventory, RootHeader, State},
};
use rtos_block::{error, fail, Result, Sha256};

pub(crate) fn prepare_abort(
    providers: &RecoveryProviders,
    root: &RootHeader,
) -> Result<RootHeader> {
    if root.state != State::Building {
        fail!("Expected Building recovery state");
    }
    providers.validate_controls(root)?;
    // Scan all operation directories before opening selection, then compare
    // every present stage with the complete ordered declaration stream.
    let actual_stages = super::recovery_stages::inventory(providers, root)?;
    let mut declared = super::recovery_stages::StageInventory::new();
    let mut present_stages = super::recovery_stages::StageInventory::new();
    let main = providers
        .participants
        .iter()
        .find(|p| p.descriptor.anchor == Anchor::Node)
        .ok_or_else(|| error!("Missing Building main provider"))?;
    let path = main
        .archive_root
        .join("archive/recovery")
        .join(hex::encode(root.operation))
        .join("selection.v1");
    let mut participants = providers.checker();
    let mut predicate = false;
    let mut maps = None;
    let mut data = None;
    recovery_artifacts::read_sidecar(
        &path,
        Kind::Selection,
        root,
        root.selection,
        |tag, length, input| {
            match tag {
                Record::Predicate => {
                    super::truncation_selection::read_predicate(input, length, |_| Ok(()))?;
                    predicate = true;
                }
                Record::Provider => participants.record(input, length)?,
                Record::MapInventory => {
                    if maps.is_some() {
                        fail!("Duplicate original map inventory");
                    }
                    maps = Some(recovery_parent::read_inventory(
                        input,
                        length,
                        InventoryRole::Original,
                    )?);
                }
                Record::ArchiveInventory => {
                    if data.is_some() || length != 43 {
                        fail!("Invalid original archive inventory framing");
                    }
                    let mut bytes = [0; 43];
                    input.read_exact(&mut bytes)?;
                    if bytes[..2] != [1, 0] || bytes[2] != root.policy as u8 {
                        fail!("Original archive inventory version or policy mismatch");
                    }
                    let inventory = Inventory {
                        count: u64::from_le_bytes(bytes[3..11].try_into()?),
                        digest: bytes[11..].try_into()?,
                    };
                    if inventory.digest == [0; 32]
                        || (inventory.count == 0 && inventory.digest != Sha256::new().finalize())
                    {
                        fail!("Invalid original archive inventory digest");
                    }
                    data = Some(inventory);
                }
                Record::ReadyIntent => {
                    let mut version = [0;2];
                    if length != 2 { fail!("Invalid Ready staging intent"); }
                    input.read_exact(&mut version)?;
                    if version != [1,0] { fail!("Unknown Ready staging version"); }
                }
                Record::Child => {
                    let stage = super::recovery_stages::Stage::decode(providers, input, length)?;
                    declared.record(stage.provider, stage.identity)?;
                    if super::recovery_stages::present(&stage.path(providers, root)?)? {
                        present_stages.record(stage.provider, stage.identity)?;
                    }
                }
                _ => fail!("Building child/staging recovery is not implemented yet"),
            }
            Ok(())
        },
    )?;
    participants.finish()?;
    if present_stages.finish() != actual_stages {
        fail!("Undeclared Building stage file");
    }
    if !predicate {
        fail!("Missing Building predicate");
    }
    let maps = maps.ok_or_else(|| error!("Missing original map inventory"))?;
    let data = data.ok_or_else(|| error!("Missing original archive inventory"))?;
    if recovery_parent::native_inventory(main.database.db())? != maps {
        fail!("Building original parent maps changed");
    }
    if recovery_data::inventory(providers)? != data {
        fail!("Building original archive data changed");
    }
    // Canonical data is unchanged. The worker must remove all declared stages
    // and revalidate before publishing this candidate Cleaned record.
    let mut cleaned = root.clone();
    cleaned.state = State::Cleaned;
    cleaned.aborted = true;
    cleaned.providers = providers.inventory()?;
    cleaned.maps = maps;
    cleaned.data = data;
    cleaned.validate()?;
    providers.validate_controls(root)?;
    Ok(cleaned)
}

pub(crate) fn discard_stages(providers: &RecoveryProviders, root: &RootHeader) -> Result<()> {
    let main = providers
        .participants
        .iter()
        .position(|p| p.descriptor.anchor == Anchor::Node)
        .ok_or_else(|| error!("Missing Building main provider"))?;
    let path = super::recovery_stages::operation(providers, root, main)?.join("selection.v1");
    recovery_artifacts::read_sidecar(
        &path,
        Kind::Selection,
        root,
        root.selection,
        |tag, length, input| {
            if tag == Record::Child {
                let stage = super::recovery_stages::Stage::decode(providers, input, length)?;
                let provider = providers.participants[stage.provider].archive_root.as_path();
                let name = std::ffi::CString::new(stage.name())?;
                super::recovery_worker::clean_stage(provider, root, &name)?;
            } else {
                std::io::copy(input, &mut std::io::sink())?;
            }
            Ok(())
        },
    )
}
