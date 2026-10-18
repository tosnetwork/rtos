// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Isolated-test-only cold body control. No DB or signing API is available here.
use crate::{
    block::{RawCandidateId, SlotIndex},
    database::Bootstrap,
    session_description::SessionDescription,
};
use rtos_block::{fail, Result, UInt256};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path},
};
const CONTROL: &str = "RTOS_TEST_COLD_BOOTSTRAP_CONTROL";
const MAX_CONTROL: u64 = 4096;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Selector {
    schema: u32,
    session_id: String,
    profile: String,
    local_adnl: String,
    local_validator_index: Option<u32>,
    global_id: i32,
    zerostate: String,
    namespace: String,
    slot: u32,
    candidate_hash: String,
}
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct Witness {
    schema: u32,
    selector_sha256: String,
    session_id: String,
    slot: u32,
    candidate_hash: String,
    payload_bytes: usize,
    payload_sha256: String,
    pid: u32,
    leader_index: u32,
    local_validator_index: Option<u32>,
    block_id: String,
    block_bytes: usize,
    block_sha256: String,
    collated_file_hash: String,
}
fn belongs(witness: &Witness, selector: &Selector, digest: &str) -> bool {
    witness.schema == 1
        && witness.selector_sha256 == digest
        && witness.pid == std::process::id()
        && witness.session_id == selector.session_id
        && witness.slot == selector.slot
        && witness.candidate_hash == selector.candidate_hash
        && witness.payload_bytes > 0
        && witness.local_validator_index == selector.local_validator_index
        && Some(witness.leader_index) != selector.local_validator_index
        && witness.block_bytes > 0
}
fn bounded(path: &Path) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_CONTROL {
        fail!("Invalid cold control file type/size");
    }
    let mut bytes = Vec::new();
    File::open(path)?.take(MAX_CONTROL + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CONTROL {
        fail!("Cold control grew beyond bound");
    }
    Ok(bytes)
}
fn load(control: &Path) -> Result<(Selector, String)> {
    if !control.is_absolute()
        || control.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        || !std::fs::symlink_metadata(control)?.file_type().is_dir()
    {
        fail!("Cold control requires a canonical owned directory");
    }
    let bytes = bounded(&control.join("selector.json"))?;
    let selector: Selector = serde_json::from_slice(&bytes)?;
    if selector.schema != 1 {
        fail!("Unknown cold control schema");
    }
    Ok((selector, UInt256::calc_file_hash(&bytes).to_hex_string()))
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}

pub(crate) fn enabled() -> bool {
    std::env::var_os(CONTROL).is_some()
}

pub(crate) fn apply_from_environment(
    description: &SessionDescription,
    bootstrap: &mut Bootstrap,
) -> Result<()> {
    if let Some(control) = std::env::var_os(CONTROL) {
        apply(Path::new(&control), description, bootstrap)?;
    }
    Ok(())
}
// The caller has authenticated the full bootstrap and rehydrated its own journal.
// Remove just one non-local body from the transient warm-up vector, never its
// metadata/certificates or the underlying database. The normal resolver reads it.
fn apply(
    control: &Path,
    description: &SessionDescription,
    bootstrap: &mut Bootstrap,
) -> Result<bool> {
    let (selector, selector_sha256) = load(control)?;
    if selector.session_id != description.get_session_id().to_hex_string() {
        return Ok(false);
    }
    let runtime = description
        .authenticated_runtime()
        .ok_or_else(|| rtos_block::error!("Cold control lacks authenticated runtime"))?;
    let local = description.local_validator_index().map(|i| i.value());
    let namespace = Path::new(&selector.namespace);
    let expected_namespace = runtime.runtime_directory("/isolated-test")?;
    if selector.profile != runtime.profile().to_hex_string()
        || selector.global_id != runtime.pin().global_id
        || selector.zerostate != runtime.pin().zerostate.to_string()
        || selector.local_adnl != UInt256::from(*runtime.local_adnl().data()).to_hex_string()
        || selector.local_validator_index != local
        || !namespace.is_absolute()
        || namespace.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        || namespace.file_name() != Path::new(&expected_namespace).file_name()
    {
        fail!("Cold control differs from authenticated session domain");
    }
    let hash: UInt256 = selector.candidate_hash.parse()?;
    if hash.to_hex_string() != selector.candidate_hash {
        fail!("Noncanonical cold candidate hash");
    }
    let id = RawCandidateId { slot: SlotIndex::new(selector.slot), hash };
    let leader = description.get_leader(id.slot);
    if description.local_validator_index() == Some(leader) {
        fail!("Cold control refuses own generated candidate");
    }
    let receipt = control.join("applied.json");
    if receipt.exists() {
        let old: Witness = serde_json::from_slice(&bounded(&receipt)?)?;
        if !belongs(&old, &selector, &selector_sha256) {
            fail!("Cold control has a stale/conflicting receipt");
        }
        return Ok(false);
    }
    if !bootstrap.final_certs.iter().any(|r| r.candidate_id == id)
        || !bootstrap
            .candidate_infos
            .iter()
            .any(|r| r.candidate_id == id && r.leader_idx == leader.value())
    {
        fail!("Cold control lacks authenticated candidate metadata/FinalCert");
    }
    let payloads: Vec<_> =
        bootstrap.candidate_payloads.iter().filter(|(other, _)| other == &id).collect();
    if payloads.len() != 1 || payloads[0].1.is_empty() {
        fail!("Cold control must select one complete retained body");
    }
    let body = &payloads[0].1;
    let info = bootstrap.candidate_infos.iter().find(|r| r.candidate_id == id).unwrap();
    let rtos_api::ton::consensus::CandidateHashData::Consensus_CandidateHashDataOrdinary(metadata) =
        &info.candidate_hash_data
    else {
        fail!("Cold body control refuses empty candidate metadata");
    };
    let candidate: rtos_api::ton::consensus::CandidateData =
        description.opts().wire_profile.deserialize_typed(body)?;
    let rtos_api::ton::consensus::CandidateData::Consensus_Block(candidate) = candidate else {
        fail!("Cold body control requires a complete ordinary candidate");
    };
    let block = crate::utils::extract_block_info_from_candidate(
        &candidate.candidate,
        description.get_shard(),
        description.opts().max_block_size + description.opts().max_collated_data_size,
        description.opts().proto_version,
    )?
    .ok_or_else(|| rtos_block::error!("Cold body is missing block bytes"))?;
    if block.data.is_empty()
        || block.block_id != metadata.block
        || block.collated_file_hash != metadata.collated_file_hash
    {
        fail!("Cold block bytes differ from authenticated candidate metadata");
    }
    let witness = Witness {
        schema: 1,
        selector_sha256,
        session_id: selector.session_id,
        slot: selector.slot,
        candidate_hash: selector.candidate_hash,
        payload_bytes: body.len(),
        payload_sha256: UInt256::calc_file_hash(body).to_hex_string(),
        pid: std::process::id(),
        leader_index: leader.value(),
        local_validator_index: local,
        block_id: block.block_id.to_string(),
        block_bytes: block.data.len(),
        block_sha256: UInt256::calc_file_hash(&block.data).to_hex_string(),
        collated_file_hash: block.collated_file_hash.to_hex_string(),
    };
    write_new(&control.join("block-before.bin"), &block.data)?;
    write_new(&control.join("payload-before.bin"), body)?;
    write_new(&receipt, &serde_json::to_vec_pretty(&witness)?)?;
    bootstrap.candidate_payloads.retain(|(other, _)| other != &id);
    log::info!("TEST_COLD_BOOTSTRAP: session={} slot={} hash={} payload_bytes={} payload_sha256={} transient body omitted; database unchanged",
        witness.session_id, witness.slot, witness.candidate_hash, witness.payload_bytes, witness.payload_sha256);
    Ok(true)
}

pub(crate) fn record_delivery(
    session: &UInt256,
    slot: SlotIndex,
    hash: &UInt256,
    body: Option<(usize, UInt256)>,
) -> Result<()> {
    let Some(control) = std::env::var_os(CONTROL) else {
        return Ok(());
    };
    record_delivery_at(Path::new(&control), session, slot, hash, body)
}
fn record_delivery_at(
    control: &Path,
    session: &UInt256,
    slot: SlotIndex,
    hash: &UInt256,
    body: Option<(usize, UInt256)>,
) -> Result<()> {
    let (selector, digest) = load(control)?;
    if selector.session_id != session.to_hex_string()
        || selector.slot != slot.value()
        || selector.candidate_hash != hash.to_hex_string()
    {
        return Ok(());
    }
    let applied: Witness = serde_json::from_slice(&bounded(&control.join("applied.json"))?)?;
    let Some((size, body_hash)) = body else {
        fail!("Cold recovery delivery has no complete body");
    };
    if !belongs(&applied, &selector, &digest)
        || applied.payload_bytes != size
        || applied.payload_sha256 != body_hash.to_hex_string()
    {
        fail!("Cold recovery body differs from authenticated bootstrap payload");
    }
    let path = control.join("delivered.json");
    let bytes = serde_json::to_vec_pretty(&applied)?;
    if path.exists() {
        if bounded(&path)? != bytes {
            fail!("Conflicting cold recovery delivery receipt");
        }
    } else {
        write_new(&path, &bytes)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/test_cold_bootstrap_control.rs"]
mod tests;
