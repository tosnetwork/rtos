// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Check native block/state checkpoints and optional authenticated final certificates.
use anyhow::{ensure, Context, Result};
use rtos_block::{
    base64_decode, base64_encode, read_single_root_boc, BlkPrevInfo, Block, BlockIdExt,
    Deserializable, ShardIdent, ShardStateUnsplit, UInt256,
};
use serde_json::{json, Value};
use std::{io::Write, path::PathBuf};

fn hash(value: &Value) -> Result<UInt256> {
    let bytes: [u8; 32] = base64_decode(value.as_str().context("base64 hash required")?)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("32-byte hash required"))?;
    Ok(UInt256::from(bytes))
}

fn identity(value: &Value) -> Result<(i64, i64, u64, UInt256, UInt256)> {
    let shard = match &value["shard"] {
        Value::String(s) => s.parse()?,
        v => v.as_i64().context("shard required")?,
    };
    Ok((
        value["workchain"].as_i64().context("workchain required")?,
        shard,
        value["seqno"].as_u64().context("seqno required")?,
        hash(&value["root_hash"])?,
        hash(&value["file_hash"])?,
    ))
}

// The fixture has one unsplit full workchain. Historical creator evidence must
// remain linked to an authenticated masterchain top through every real body.
fn workchain_parent(block: &Block) -> Result<Value> {
    let info = block.read_info()?;
    ensure!(!info.after_split() && !info.after_merge(), "split workchain ancestry is unsupported");
    let BlkPrevInfo::Block { prev } = info.read_prev_ref()? else {
        anyhow::bail!("single workchain parent required");
    };
    ensure!(prev.seq_no.checked_add(1) == Some(info.seq_no()), "workchain ancestry height gap");
    Ok(json!({"@type":"tos.blockIdExt", "workchain":info.shard().workchain_id(),
        "shard":(info.shard().shard_prefix_with_tag() as i64).to_string(),
        "seqno":prev.seq_no, "root_hash":base64_encode(prev.root_hash.as_slice()),
        "file_hash":base64_encode(prev.file_hash.as_slice())}))
}

fn check_workchain_anchor(workchain: &Value, tops: &[Value], global_id: i32) -> Result<usize> {
    let target = identity(&workchain["block"]["id"])?;
    let chain = match workchain.get("anchor_chain") {
        Some(value) => {
            value.as_array().context("workchain anchor chain array required")?.as_slice()
        }
        None => &[],
    };
    ensure!(chain.len() <= 64, "workchain anchor chain exceeds fixture bound");
    let top = chain.first().map(|link| &link["id"]).unwrap_or(&workchain["block"]["id"]);
    let mut expected = identity(top)?;
    ensure!(
        tops.iter().any(|id| identity(id).ok().as_ref() == Some(&expected)),
        "workchain block is not anchored by the checked masterchain block"
    );
    for link in chain {
        let id = identity(&link["id"])?;
        ensure!(
            id == expected && id.0 == 0 && id.1 == i64::MIN && id.2 > target.2,
            "workchain anchor link identity or order differs"
        );
        let bytes = base64_decode(link["boc"].as_str().context("anchor link BOC required")?)?;
        ensure!(UInt256::calc_file_hash(&bytes) == id.4, "workchain anchor file hash differs");
        let cell = read_single_root_boc(&bytes)?;
        ensure!(cell.repr_hash() == &id.3, "workchain anchor cell hash differs");
        let block = Block::construct_from_cell(cell)?;
        let info = block.read_info()?;
        ensure!(
            block.global_id() == global_id
                && u64::from(info.seq_no()) == id.2
                && info.shard().workchain_id() == 0
                && info.shard().shard_prefix_with_tag() == 1_u64 << 63,
            "workchain anchor header differs"
        );
        expected = identity(&workchain_parent(&block)?)?;
    }
    ensure!(expected == target, "workchain anchor does not reach the exact target");
    Ok(chain.len())
}

/// Compare native historical state bodies without claiming endpoint-head or
/// finality evidence. BOC flags/layout may differ; consensus cell roots may not.
fn check_state_copies(value: &Value) -> Result<Value> {
    let expected = identity(&value["block"]["id"])?;
    let bytes = base64_decode(value["block"]["boc"].as_str().context("block BOC required")?)?;
    ensure!(UInt256::calc_file_hash(&bytes) == expected.4, "block file hash differs");
    let root = read_single_root_boc(&bytes)?;
    ensure!(root.repr_hash() == &expected.3, "block root differs");
    let block = Block::construct_from_cell(root)?;
    let info = block.read_info()?;
    ensure!(
        u64::from(info.seq_no()) == expected.2
            && i64::from(info.shard().workchain_id()) == expected.0
            && info.shard().shard_prefix_with_tag() == expected.1 as u64,
        "block header identity differs"
    );
    let state_root = block.read_state_update()?.new_hash;
    let states = value["states"].as_array().context("state copies required")?;
    ensure!((2..=6).contains(&states.len()), "expected two to six native state copies");
    let mut names = std::collections::BTreeSet::new();
    for source in states {
        let name = source["name"].as_str().context("state source name required")?;
        ensure!(names.insert(name), "duplicate state source");
        ensure!(identity(&source["id"])? == expected, "state identity differs");
        let data = base64_decode(source["boc"].as_str().context("state BOC required")?)?;
        ensure!(
            UInt256::calc_file_hash(&data) == hash(&source["file_hash"])?,
            "state file hash differs"
        );
        let cell = read_single_root_boc(&data)?;
        ensure!(cell.repr_hash() == &state_root, "state root differs from block state update");
        let state = ShardStateUnsplit::construct_from_cell(cell)?;
        ensure!(
            state.shard() == info.shard()
                && u64::from(state.seq_no()) == expected.2
                && state.global_id() == block.global_id(),
            "state header differs"
        );
    }
    Ok(json!({"mode":"state-copies", "block":value["block"]["id"],
        "state_root_hash":base64_encode(state_root.as_slice()), "sources":names,
        "finality_checked":false}))
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let request = PathBuf::from(args.next().context("usage: interop_block_check REQUEST OUTPUT")?);
    let output = PathBuf::from(args.next().context("output argument required")?);
    ensure!(args.next().is_none(), "unexpected argument");
    let value: Value = serde_json::from_slice(&std::fs::read(request)?)?;
    let result = match value.get("mode").and_then(Value::as_str) {
        Some("state-copies") => check_state_copies(&value)?,
        Some("finality-witness") => {
            ensure!(
                value.get("reference").is_none()
                    && value.get("comparison").is_none()
                    && value.get("rust").is_none(),
                "historical witness must not claim live endpoint heads"
            );
            ensure!(
                value.get("masterchain_state").is_some()
                    && value["certificates"].as_array().is_some_and(|v| !v.is_empty()),
                "historical witness needs full state and final certificates"
            );
            let mut checked = check_request(&value, 1)?;
            checked.as_object_mut().unwrap().remove("state_update_matches_both");
            checked["mode"] = json!("finality-witness");
            checked["rpc_heads_checked"] = json!(false);
            checked["state_update_matches_full_state"] = json!(true);
            checked
        }
        None => check_request(&value, 0)?,
        Some(_) => anyhow::bail!("unknown checker mode"),
    };
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(output)?;
    file.write_all(&serde_json::to_vec_pretty(&result)?)?;
    println!("{result}");
    Ok(())
}

fn check_request(value: &Value, depth: u8) -> Result<Value> {
    ensure!(depth <= 16, "governing key-block chain exceeds fixture bound");
    // A historical governing witness needs authenticated block/state bodies,
    // not a claim that two RPC clients observed that past height as their head.
    // Root requests still require the actual native endpoint checkpoints.
    let witness_only = depth > 0
        && value.get("reference").is_none()
        && value.get("comparison").is_none()
        && value.get("rust").is_none();
    let expanded = if witness_only {
        let bytes = base64_decode(
            value["masterchain_state"]["boc"]
                .as_str()
                .context("governing state witness body required")?,
        )?;
        let state_root = read_single_root_boc(&bytes)?.repr_hash().clone();
        let mut zero = value["zerostate"].clone();
        zero["@type"] = json!("tos.blockIdExt");
        let checkpoint = json!({"init":zero, "last":value["block"]["id"],
            "state_root_hash":base64_encode(state_root.as_slice())});
        let mut expanded = value.clone();
        expanded["reference"] = checkpoint.clone();
        expanded["comparison"] = checkpoint;
        Some(expanded)
    } else {
        None
    };
    let value = expanded.as_ref().unwrap_or(value);
    let reference = &value["reference"];
    let comparison = value.get("comparison").unwrap_or(&value["rust"]);
    let zero = identity(&value["zerostate"])?;
    ensure!(zero.0 == -1 && zero.1 == i64::MIN && zero.2 == 0, "invalid pinned zerostate");
    ensure!(
        identity(&reference["init"])? == zero && identity(&comparison["init"])? == zero,
        "RPC zerostates differ from the configured identity"
    );
    for id in [
        &reference["last"],
        &reference["init"],
        &comparison["last"],
        &comparison["init"],
        &value["block"]["id"],
    ] {
        ensure!(id["@type"] == "tos.blockIdExt", "noncanonical block ID type label");
    }
    let expected = identity(&reference["last"])?;
    ensure!(
        expected.0 == -1 && expected.1 == i64::MIN && expected.2 > 0,
        "sample must be a produced masterchain block"
    );
    ensure!(identity(&comparison["last"])? == expected, "RPC block identities differ");
    ensure!(identity(&value["block"]["id"])? == expected, "block response identity differs");
    let state = hash(&reference["state_root_hash"])?;
    ensure!(hash(&comparison["state_root_hash"])? == state, "RPC state roots differ");
    let data = base64_decode(value["block"]["boc"].as_str().context("block BOC required")?)?;
    ensure!(UInt256::calc_file_hash(&data) == expected.4, "block file hash differs");
    let root = read_single_root_boc(&data)?;
    ensure!(root.repr_hash() == &expected.3, "block cell hash differs");
    let block = Block::construct_from_cell(root)?;
    let info = block.read_info()?;
    ensure!(
        u64::from(info.seq_no()) == expected.2
            && info.shard().workchain_id() == -1
            && info.shard().shard_prefix_with_tag() == 1_u64 << 63,
        "block header identity differs"
    );
    ensure!(
        block.read_state_update()?.new_hash == state,
        "block state update differs from applied states"
    );
    let mut configuration = Value::Null;
    if let Some(source) = value.get("masterchain_state") {
        ensure!(identity(&source["id"])? == expected, "masterchain state identity differs");
        let bytes =
            base64_decode(source["boc"].as_str().context("masterchain state BOC required")?)?;
        ensure!(
            UInt256::calc_file_hash(&bytes) == hash(&source["file_hash"])?,
            "masterchain state file hash differs"
        );
        let cell = read_single_root_boc(&bytes)?;
        ensure!(cell.repr_hash() == &state, "masterchain state differs from block state update");
        let snapshot = ShardStateUnsplit::construct_from_cell(cell)?;
        ensure!(
            snapshot.shard().is_masterchain()
                && u64::from(snapshot.seq_no()) == expected.2
                && snapshot.global_id() == block.global_id(),
            "masterchain state header differs"
        );
        let extra = snapshot.read_custom()?.context("masterchain state configuration required")?;
        let describe = |set: rtos_block::ValidatorSet| -> Result<Value> {
            Ok(json!({"since":set.utime_since(), "until":set.utime_until(),
                "members":set.list().iter().map(|member| Ok(json!({
                    "validator_id":base64_encode(member.validator_id()?.as_slice()),
                    "weight":member.weight}))).collect::<Result<Vec<_>>>()?}))
        };
        configuration = json!({"current":describe(extra.config.validator_set()?)?,
            "next":describe(extra.config.next_validator_set()?)?,
            "previous":describe(extra.config.prev_validator_set()?)?,
            "catchain_seqno":extra.validator_info.catchain_seqno,
            "state_root_checked":true});
    }
    let mut certificates = Vec::new();
    let mut governing_chain = Vec::new();
    if let Some(sources) = value.get("certificates") {
        let governing_state = if info.prev_key_block_seqno() == 0 {
            let genesis_bytes = base64_decode(
                value["governing_zerostate_boc"]
                    .as_str()
                    .context("governing zerostate body required")?,
            )?;
            ensure!(
                UInt256::calc_file_hash(&genesis_bytes) == zero.4,
                "governing zerostate file hash differs"
            );
            let genesis_root = read_single_root_boc(&genesis_bytes)?;
            ensure!(genesis_root.repr_hash() == &zero.3, "governing zerostate cell hash differs");
            let genesis = ShardStateUnsplit::construct_from_cell(genesis_root)?;
            ensure!(
                genesis.seq_no() == 0
                    && genesis.shard().is_masterchain()
                    && genesis.global_id() == block.global_id(),
                "invalid governing zerostate header"
            );
            genesis
        } else {
            let governing = value
                .get("governing_key_block")
                .context("certificate needs an authenticated governing key block")?;
            ensure!(
                identity(&governing["zerostate"])? == zero,
                "governing key block belongs to another Genesis"
            );
            let governing_id = identity(&governing["block"]["id"])?;
            ensure!(
                governing_id.0 == -1
                    && governing_id.1 == i64::MIN
                    && governing_id.2 == u64::from(info.prev_key_block_seqno())
                    && governing_id.2 < expected.2,
                "governing key-block identity differs from signed header"
            );
            ensure!(
                governing["certificates"].as_array().is_some_and(|sources| !sources.is_empty()),
                "governing key block needs its own final certificate"
            );
            ensure!(
                governing.get("masterchain_state").is_some(),
                "governing key block needs its complete resulting state"
            );
            let checked = check_request(governing, depth + 1)?;
            ensure!(checked["key_block"] == true, "governing block is not a key block");
            ensure!(
                checked["global_id"].as_i64() == Some(i64::from(block.global_id())),
                "governing key-block global ID differs"
            );
            ensure!(
                checked["prev_key_block_seqno"]
                    .as_u64()
                    .context("governing predecessor required")?
                    < governing_id.2,
                "governing key-block chain does not decrease"
            );
            governing_chain.extend(
                checked["verified_governing_key_blocks"]
                    .as_array()
                    .context("governing chain report required")?
                    .iter()
                    .cloned(),
            );
            governing_chain.push(json!({"block":governing["block"]["id"],
                "state_root_hash":checked["state_root_hash"],
                "verified_final_certificates":checked["verified_final_certificates"]}));
            let bytes = base64_decode(
                governing["masterchain_state"]["boc"]
                    .as_str()
                    .context("governing state body required")?,
            )?;
            ShardStateUnsplit::construct_from_cell(read_single_root_boc(&bytes)?)?
        };
        let extra = governing_state.read_custom()?.context("masterchain configuration required")?;
        let id = BlockIdExt::with_params(
            ShardIdent::masterchain(),
            expected.2.try_into()?,
            expected.3.clone(),
            expected.4.clone(),
        );
        let context = rtos_api::pq_finality::PqVerificationContext::from_governing_config(
            block.global_id(),
            &extra.config,
            id.clone(),
            info.vert_seq_no(),
            info.prev_key_block_seqno(),
            info.gen_catchain_seqno(),
        )?;
        let sources = sources.as_array().context("certificate sources required")?;
        ensure!(!sources.is_empty(), "empty certificate evidence");
        for source in sources {
            let mut matched = Vec::new();
            if source["kind"] == "rpc" {
                let cert = &source["value"];
                ensure!(identity(&cert["id"])? == expected, "certificate block identity differs");
                ensure!(
                    cert["@type"] == "blocks.blockSignatures.simplexPq",
                    "native PQ final certificate required"
                );
                let signatures = cert["signatures"]
                    .as_array()
                    .context("signatures required")?
                    .iter()
                    .map(|pair| -> Result<_> {
                        Ok(rtos_api::ton::lite_server::pqsignature::PqSignature {
                            validator_id: hash(&pair["validator_id"])?,
                            algorithm_id: pair["algorithm_id"]
                                .as_i64()
                                .context("algorithm required")?
                                .try_into()?,
                            signature: base64_decode(
                                pair["signature"].as_str().context("signature bytes required")?,
                            )?
                            .into(),
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                matched.push(rtos_api::pq_finality::PqNetworkSignatureSet::from_lite(
                    rtos_api::ton::lite_server::signature_set::signatureset::SimplexPq {
                        cc_seqno: info.gen_catchain_seqno().try_into()?,
                        validator_set_hash: context.subset_hash() as i32,
                        signatures,
                        session_id: hash(&cert["session_id"])?,
                        slot: cert["slot"].as_i64().context("slot required")?.try_into()?,
                        candidate: base64_decode(
                            cert["candidate"].as_str().context("candidate required")?,
                        )?
                        .into(),
                    },
                )?);
            } else if source["kind"] == "node" {
                let bytes = base64_decode(
                    source["signature_set"].as_str().context("node signature bytes required")?,
                )?;
                ensure!(bytes.len() <= 16 * 1024 * 1024, "node signature set too large");
                let wire: rtos_api::ton::ton_node::SignatureSet =
                    rtos_api::WireProfile::T0.deserialize_typed(&bytes)?;
                ensure!(
                    rtos_api::WireProfile::T0.serialize(&wire)? == bytes,
                    "noncanonical node signature set"
                );
                let rtos_api::ton::ton_node::SignatureSet::TonNode_SignatureSet_SimplexPq(wire) =
                    wire
                else {
                    anyhow::bail!("node PQ final certificate required");
                };
                matched.push(rtos_api::pq_finality::PqNetworkSignatureSet::from_node(wire)?);
            } else {
                ensure!(source["kind"] == "cpp_lite", "unknown certificate source");
                for response in
                    source["responses"].as_array().context("native proof responses required")?
                {
                    let bytes =
                        base64_decode(response.as_str().context("raw proof response required")?)?;
                    ensure!(bytes.len() <= 16 * 1024 * 1024, "native proof response too large");
                    let proof: rtos_api::ton::lite_server::PartialBlockProof =
                        rtos_api::WireProfile::T0.deserialize_typed(&bytes)?;
                    for step in proof.only().steps {
                        if let rtos_api::ton::lite_server::BlockLink::LiteServer_BlockLinkForward(
                            step,
                        ) = step
                        {
                            if step.to == id {
                                let rtos_api::ton::lite_server::SignatureSet::LiteServer_SignatureSet_SimplexPq(signature) = step.signatures else {
                                    anyhow::bail!("native PQ final certificate required");
                                };
                                matched.push(
                                    rtos_api::pq_finality::PqNetworkSignatureSet::from_lite(
                                        signature,
                                    )?,
                                );
                            }
                        }
                    }
                }
            }
            ensure!(matched.len() == 1, "exactly one target certificate per source required");
            let (_, verified) = context.verify_network(&matched[0])?.into_final()?;
            let carrier = matched[0].to_lite()?;
            let candidate_hash = UInt256::calc_file_hash(&carrier.candidate);
            let validator_ids: Vec<_> = carrier
                .signatures
                .iter()
                .map(|pair| base64_encode(pair.validator_id.as_slice()))
                .collect();
            certificates.push(json!({"source":source["name"], "validator_ids":validator_ids, "verified_weight":verified.weight(),
                "session_id":base64_encode(verified.session_id().as_slice()), "slot":verified.slot(),
                "candidate_hash":candidate_hash.to_hex_string(),
                "final_certificate_checked":true}));
        }
    }
    let mut shard_tops = Vec::new();
    if let Some(extra) = block.read_extra()?.read_custom()? {
        extra.shards().iterate_shards(|shard, descr| {
            shard_tops.push(json!({"@type":"tos.blockIdExt", "workchain":shard.workchain_id(),
                "shard":(shard.shard_prefix_with_tag() as i64).to_string(), "seqno":descr.seq_no,
                "root_hash":base64_encode(descr.root_hash.as_slice()),
                "file_hash":base64_encode(descr.file_hash.as_slice())}));
            Ok(true)
        })?;
    }
    let mut workchain_check = Value::Null;
    if let Some(workchain) = value.get("workchain") {
        let wc_id = identity(&workchain["block"]["id"])?;
        ensure!(
            wc_id.0 == 0 && wc_id.1 == i64::MIN && wc_id.2 > 0,
            "fixture needs a produced full workchain-0 block"
        );
        let anchor_links = check_workchain_anchor(workchain, &shard_tops, block.global_id())?;
        let bytes = base64_decode(
            workchain["block"]["boc"].as_str().context("workchain block BOC required")?,
        )?;
        ensure!(UInt256::calc_file_hash(&bytes) == wc_id.4, "workchain block file hash differs");
        let cell = read_single_root_boc(&bytes)?;
        ensure!(cell.repr_hash() == &wc_id.3, "workchain block cell hash differs");
        let wc_block = Block::construct_from_cell(cell)?;
        let wc_info = wc_block.read_info()?;
        ensure!(
            u64::from(wc_info.seq_no()) == wc_id.2
                && wc_info.shard().workchain_id() == 0
                && wc_info.shard().shard_prefix_with_tag() == 1_u64 << 63
                && wc_block.global_id() == block.global_id(),
            "workchain block header differs"
        );
        let wc_root = wc_block.read_state_update()?.new_hash;
        let states = workchain["states"].as_array().context("workchain state evidence required")?;
        let names: std::collections::BTreeSet<_> = states
            .iter()
            .map(|s| s["name"].as_str().context("state endpoint name required"))
            .collect::<Result<_>>()?;
        let required: std::collections::BTreeSet<_> = value["references"]
            .as_object()
            .context("all endpoint references required")?
            .keys()
            .map(String::as_str)
            .collect();
        let fixture_count = match value.get("fixture_validator_count") {
            Some(count) => {
                let count = count.as_u64().context("integer fixture validator count required")?;
                ensure!([3, 4, 6].contains(&count), "unsupported fixture validator count");
                let members = configuration["current"]["members"]
                    .as_array()
                    .context("authenticated full committee required for explicit fixture count")?;
                ensure!(
                    members.len() as u64 == count,
                    "fixture count differs from the authenticated current committee"
                );
                count as usize
            }
            None => 4,
        };
        ensure!(
            names == required && names.len() == states.len() && names.len() == fixture_count,
            "exactly one workchain state from every declared fixture endpoint required"
        );
        let mut checked_states = Vec::new();
        for source in states {
            ensure!(identity(&source["id"])? == wc_id, "workchain state identity differs");
            let bytes =
                base64_decode(source["boc"].as_str().context("workchain state BOC required")?)?;
            let file_hash = UInt256::calc_file_hash(&bytes);
            ensure!(file_hash == hash(&source["file_hash"])?, "workchain state file hash differs");
            let cell = read_single_root_boc(&bytes)?;
            ensure!(
                cell.repr_hash() == &wc_root,
                "workchain state differs from block state update"
            );
            let state = ShardStateUnsplit::construct_from_cell(cell)?;
            ensure!(
                u64::from(state.seq_no()) == wc_id.2
                    && state.shard() == wc_info.shard()
                    && state.global_id() == block.global_id(),
                "workchain state header differs"
            );
            checked_states.push(
                json!({"name":source["name"], "file_hash":base64_encode(file_hash.as_slice())}),
            );
        }
        workchain_check = json!({"block":workchain["block"]["id"],
            "gen_utime":wc_info.gen_utime(), "gen_catchain_seqno":wc_info.gen_catchain_seqno(),
            "created_by":base64_encode(wc_block.read_extra()?.created_by().as_slice()),
            "state_root_hash":base64_encode(wc_root.as_slice()), "states":checked_states,
            "masterchain_anchor_checked":true, "block_file_cell_and_header_checked":true,
            "masterchain_anchor_links":anchor_links, "previous_block":workchain_parent(&wc_block)?,
            "fixture_validator_count":fixture_count,
            "all_declared_states_match_block_update":true,
            "all_four_states_match_block_update":fixture_count == 4});
    }
    let result = json!({"status":"block_and_state_match", "block":reference["last"],
        "created_by":base64_encode(block.read_extra()?.created_by().as_slice()),
        "state_root_hash":base64_encode(state.as_slice()), "global_id":block.global_id(),
        "gen_utime":info.gen_utime(), "key_block":info.key_block(),
        "prev_key_block_seqno":info.prev_key_block_seqno(),
        "gen_catchain_seqno":info.gen_catchain_seqno(), "configuration":configuration,
        "file_hash_checked":true, "cell_hash_checked":true, "header_identity_checked":true,
        "state_update_matches_both":!witness_only, "governing_state_witness_checked":witness_only,
        "verified_final_certificates":certificates,
        "verified_governing_key_blocks":governing_chain,
        "shard_tops":shard_tops, "workchain_check":workchain_check,
        "active_signing_qualified":false});
    Ok(result)
}
