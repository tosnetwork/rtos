// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Structural carriers and signing bytes do not grant validator authority.
use super::{bytes_effect, identity, Inputs};
use anyhow::{bail, Context, Result};
use rtos_api::{
    pq_finality::{
        build_simplex_vote_data_for_block, ExplicitFinalityBlock, FinalityRefusal,
        PqNetworkSignatureSet,
    },
    ton, WireProfile,
};
use rtos_block::{
    pq_block_signature_reason_code, read_single_root_boc, sha256_digest, BlockSignaturesSimplexPq,
    BlockSignaturesVariant, Deserializable, PqBlockSignaturePair, PqBlockSignatureReasonCode,
    Serializable, UInt256, ValidatorBaseInfo,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

fn rejected(reason: &str) -> Value {
    json!({"outcome":"rejected","reason":reason})
}
pub(super) fn signing_data(input: &mut Inputs<'_>) -> Result<Value> {
    let v = input.values;
    let session = identity::bits(&v["session_id"])?;
    let slot = identity::u32_field(v, "slot")?;
    let candidate = input.bytes("candidate")?;
    let is_final = v["final"].as_bool().context("final boolean required")?;
    let block = &v["block_id"];
    let raw = Inputs { values: block, edits: vec![] };
    let block = ExplicitFinalityBlock {
        workchain: identity::i32_field(block, "workchain")?,
        shard: raw.uint64("shard")?,
        seqno: identity::u32_field(block, "seqno")?,
        root_hash: identity::bits(&block["root_hash"])?,
        file_hash: identity::bits(&block["file_hash"])?,
    };
    match build_simplex_vote_data_for_block(&session, slot, &candidate, is_final, &block) {
        Ok(vote) => Ok(bytes_effect(vote.data_to_sign)),
        Err(error) => match error.downcast_ref::<FinalityRefusal>() {
            Some(FinalityRefusal("candidate_malformed")) => Ok(rejected("candidate_tl")),
            Some(FinalityRefusal("block_mismatch")) => Ok(rejected("block_id_mismatch")),
            _ => Err(error),
        },
    }
}
fn carrier_error(error: anyhow::Error) -> Result<Value> {
    use PqBlockSignatureReasonCode::*;
    match pq_block_signature_reason_code(&error) {
        Some(
            code @ (DuplicateValidatorId
            | UnsupportedAlgorithm
            | SignatureLength
            | NoncanonicalPqbytes
            | DictionaryIndex
            | DictionaryMissingEntry
            | DictionaryExtraEntry
            | CandidateOversize
            | CandidateNoncanonicalChunk
            | CandidateNonByteAligned
            | CandidateMultipleRefs
            | CandidateChainLength
            | CandidateTrailingRef
            | CandidateTl
            | SignerCount
            | UnknownValidatorId
            | ValidatorAlgorithmMismatch
            | WeightMismatch
            | UnsupportedCarrier),
        ) => Ok(rejected(code.as_str())),
        _ if error.to_string() == "PQ network signature length" => Ok(rejected("signature_length")),
        _ if error.to_string() == "PQ network duplicate validator identity" => {
            Ok(rejected("duplicate_validator_id"))
        }
        _ => Err(error),
    }
}
fn summary(
    info: &ValidatorBaseInfo,
    session: &UInt256,
    slot: u32,
    candidate: &[u8],
    signatures: &[PqBlockSignaturePair],
    is_final: bool,
) -> BTreeMap<&'static str, String> {
    let mut fields = BTreeMap::new();
    fields.insert("is_pq", "true".into());
    fields.insert("is_final", is_final.to_string());
    fields.insert("size", signatures.len().to_string());
    fields.insert("validator_set_hash", info.validator_list_hash_short.to_string());
    fields.insert("catchain_seqno", info.catchain_seqno.to_string());
    fields.insert("session_id", hex::encode(session.as_slice()));
    fields.insert("slot", slot.to_string());
    fields.insert("candidate_sha256", hex::encode(sha256_digest(candidate)));
    fields.insert(
        "validator_ids",
        signatures
            .iter()
            .map(|v| hex::encode(v.validator_id.as_slice()))
            .collect::<Vec<_>>()
            .join(","),
    );
    fields.insert(
        "algorithm_ids",
        signatures.iter().map(|v| v.algorithm_id.to_string()).collect::<Vec<_>>().join(","),
    );
    fields.insert(
        "signature_sha256",
        signatures
            .iter()
            .map(|v| hex::encode(sha256_digest(&v.signature)))
            .collect::<Vec<_>>()
            .join(","),
    );
    for key in ["validator_ids", "algorithm_ids", "signature_sha256"] {
        if fields[key].is_empty() {
            fields.insert(key, "-".into());
        }
    }
    fields
}
fn fetch(input: &mut Inputs<'_>) -> Result<Value> {
    let bytes = input.bytes("boc")?;
    let root = read_single_root_boc(&bytes)?;
    let governing = if let Some(value) = input.values.get("validator_set") {
        let catchain_seqno = identity::u32_field(value, "catchain_seqno")?;
        let local = Inputs { values: value, edits: vec![] };
        let validators = identity::descriptors(&local)?;
        Some((validators, catchain_seqno))
    } else {
        None
    };
    let parsed = if let Some((validators, catchain_seqno)) = &governing {
        // Native checked carrier entry rejects a wrong tag before parsing it.
        BlockSignaturesSimplexPq::construct_from_pq_boc_with_validator_set(
            &bytes,
            validators,
            *catchain_seqno,
        )
    } else {
        match BlockSignaturesVariant::construct_from_full_cell(root.clone()) {
            Ok(BlockSignaturesVariant::SimplexPq(value)) => Ok(value),
            Ok(_) => bail!("not a post-quantum signature set"),
            Err(error) => Err(error),
        }
    };
    let value = match parsed {
        Ok(value) => value,
        Err(error) => return carrier_error(error),
    };
    let mut fields = summary(
        &value.validator_info,
        &value.session_id,
        value.slot,
        &value.candidate_bytes()?,
        &value.signatures,
        true,
    );
    if governing.is_none() {
        fields.insert("claimed_weight", value.sig_weight.to_string());
        fields.insert(
            "reserialized_equal",
            (value.serialize()?.repr_hash() == root.repr_hash()).to_string(),
        );
    }
    Ok(json!({"outcome":"record","fields":fields}))
}
fn fetch_tl(input: &mut Inputs<'_>) -> Result<Value> {
    let carrier = input.values["carrier"].as_str().context("carrier string required")?;
    let wire = input.bytes("wire")?;
    let (parsed, reserialized_equal) = match carrier {
        "node" => {
            let object: ton::ton_node::SignatureSet = match WireProfile::T0.deserialize_typed(&wire)
            {
                Ok(value) => value,
                Err(_) => return Ok(rejected("tl_parse")),
            };
            let equal = WireProfile::T0.serialize(&object)? == wire;
            let ton::ton_node::SignatureSet::TonNode_SignatureSet_SimplexPq(value) = object else {
                bail!("wrong PQ node constructor");
            };
            (PqNetworkSignatureSet::from_node(value), equal)
        }
        "lite" => {
            let object: ton::lite_server::SignatureSet =
                match WireProfile::T0.deserialize_typed(&wire) {
                    Ok(value) => value,
                    Err(_) => return Ok(rejected("tl_parse")),
                };
            let equal = WireProfile::T0.serialize(&object)? == wire;
            let ton::lite_server::SignatureSet::LiteServer_SignatureSet_SimplexPq(value) = object
            else {
                bail!("wrong PQ lite constructor");
            };
            (PqNetworkSignatureSet::from_lite(value), equal)
        }
        _ => bail!("unknown signature carrier"),
    };
    let value = match parsed {
        Ok(value) => value,
        Err(error) => return carrier_error(error),
    };
    let node = value.to_node();
    let signatures = node
        .signatures
        .into_iter()
        .map(|pair| PqBlockSignaturePair {
            validator_id: pair.validator_id,
            algorithm_id: pair.algorithm_id as u16,
            signature: pair.signature,
        })
        .collect::<Vec<_>>();
    let candidate = WireProfile::T0.serialize(&node.candidate)?;
    let mut fields = summary(
        value.validator_info(),
        value.session_id(),
        value.slot(),
        &candidate,
        &signatures,
        value.is_final(),
    );
    fields.insert("reserialized_equal", reserialized_equal.to_string());
    Ok(json!({"outcome":"record","fields":fields}))
}
pub(super) fn run(operation: &str, input: &mut Inputs<'_>) -> Result<Value> {
    match operation {
        "fetch" => fetch(input),
        "fetch_tl" => fetch_tl(input),
        _ => bail!("unsupported crypto operation"),
    }
}
