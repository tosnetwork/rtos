// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Check native block/state checkpoints and optional authenticated final certificates.
use anyhow::{ensure, Context, Result};
use rtos_block::{
    base64_decode, base64_encode, read_single_root_boc, Block, BlockIdExt, Deserializable,
    ShardIdent, ShardStateUnsplit, UInt256,
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

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let request = PathBuf::from(args.next().context("usage: interop_block_check REQUEST OUTPUT")?);
    let output = PathBuf::from(args.next().context("output argument required")?);
    ensure!(args.next().is_none(), "unexpected argument");
    let value: Value = serde_json::from_slice(&std::fs::read(request)?)?;
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
    let mut certificates = Vec::new();
    if let Some(sources) = value.get("certificates") {
        let genesis_bytes = base64_decode(value["governing_zerostate_boc"].as_str()
            .context("governing zerostate body required")?)?;
        ensure!(UInt256::calc_file_hash(&genesis_bytes) == zero.4, "governing zerostate file hash differs");
        let genesis_root = read_single_root_boc(&genesis_bytes)?;
        ensure!(genesis_root.repr_hash() == &zero.3, "governing zerostate cell hash differs");
        let genesis = ShardStateUnsplit::construct_from_cell(genesis_root)?;
        ensure!(genesis.seq_no() == 0 && genesis.shard().is_masterchain()
            && genesis.global_id() == block.global_id(), "invalid governing zerostate header");
        ensure!(info.prev_key_block_seqno() == 0, "certificate needs a later governing key block");
        let extra = genesis.read_custom()?.context("masterchain configuration required")?;
        let id = BlockIdExt::with_params(ShardIdent::masterchain(), expected.2.try_into()?,
            expected.3.clone(), expected.4.clone());
        let context = rtos_api::pq_finality::PqVerificationContext::from_governing_config(
            block.global_id(), &extra.config, id.clone(), info.vert_seq_no(),
            info.prev_key_block_seqno(), info.gen_catchain_seqno())?;
        let sources = sources.as_array().context("certificate sources required")?;
        ensure!(!sources.is_empty(), "empty certificate evidence");
        for source in sources {
            let mut matched = Vec::new();
            if source["kind"] == "rpc" {
                let cert = &source["value"];
                ensure!(identity(&cert["id"])? == expected, "certificate block identity differs");
                ensure!(cert["@type"] == "blocks.blockSignatures.simplexPq", "native PQ final certificate required");
                let signatures = cert["signatures"].as_array().context("signatures required")?
                    .iter().map(|pair| -> Result<_> {
                        Ok(rtos_api::ton::lite_server::pqsignature::PqSignature {
                            validator_id: hash(&pair["validator_id"])?,
                            algorithm_id: pair["algorithm_id"].as_i64().context("algorithm required")?.try_into()?,
                            signature: base64_decode(pair["signature"].as_str().context("signature bytes required")?)?.into(),
                        })
                    }).collect::<Result<Vec<_>>>()?;
                matched.push(rtos_api::pq_finality::PqNetworkSignatureSet::from_lite(
                    rtos_api::ton::lite_server::signature_set::signatureset::SimplexPq {
                        cc_seqno: info.gen_catchain_seqno().try_into()?,
                        validator_set_hash: context.subset_hash() as i32,
                        signatures, session_id: hash(&cert["session_id"])?,
                        slot: cert["slot"].as_i64().context("slot required")?.try_into()?,
                        candidate: base64_decode(cert["candidate"].as_str().context("candidate required")?)?.into(),
                    })?);
            } else {
                ensure!(source["kind"] == "cpp_lite", "unknown certificate source");
                for response in source["responses"].as_array().context("native proof responses required")? {
                    let bytes = base64_decode(response.as_str().context("raw proof response required")?)?;
                    ensure!(bytes.len() <= 16 * 1024 * 1024, "native proof response too large");
                    let proof: rtos_api::ton::lite_server::PartialBlockProof =
                        rtos_api::WireProfile::T0.deserialize_typed(&bytes)?;
                    for step in proof.only().steps {
                        if let rtos_api::ton::lite_server::BlockLink::LiteServer_BlockLinkForward(step) = step {
                            if step.to == id {
                                let rtos_api::ton::lite_server::SignatureSet::LiteServer_SignatureSet_SimplexPq(signature) = step.signatures else {
                                    anyhow::bail!("native PQ final certificate required");
                                };
                                matched.push(rtos_api::pq_finality::PqNetworkSignatureSet::from_lite(signature)?);
                            }
                        }
                    }
                }
            }
            ensure!(matched.len() == 1, "exactly one target certificate per source required");
            let (_, verified) = context.verify_network(&matched[0])?.into_final()?;
            certificates.push(json!({"source":source["name"], "verified_weight":verified.weight(),
                "session_id":base64_encode(verified.session_id().as_slice()), "slot":verified.slot(),
                "final_certificate_checked":true}));
        }
    }
    let result = json!({"status":"block_and_state_match", "block":reference["last"],
        "created_by":base64_encode(block.read_extra()?.created_by().as_slice()),
        "state_root_hash":base64_encode(state.as_slice()), "global_id":block.global_id(),
        "file_hash_checked":true, "cell_hash_checked":true, "header_identity_checked":true,
        "state_update_matches_both":true, "verified_final_certificates":certificates,
        "active_signing_qualified":false});
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(output)?;
    file.write_all(&serde_json::to_vec_pretty(&result)?)?;
    println!("{result}");
    Ok(())
}
