// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Codec line protocol. Unsupported type adapters remain explicit refusals.
use anyhow::{anyhow, bail, ensure, Result};
use num::BigInt;
use rtos_block::{
    base64_decode, load_var_integer, sha256_digest, AccountId, BocFlags, BocReader, BocWriter,
    BuilderData, Cell, CellType, ConfigParams, Deserializable, IBitstring, SliceData, ValidatorSet,
    VarUIntegerCodec, VarUIntegerEncoding,
};
use serde_json::{json, Value};
use std::io::{self, BufRead, Read, Write};

fn bits_cell(bits: &str) -> Result<Cell> {
    ensure!(bits.len() <= 1023, "bits: too long");
    let mut builder = BuilderData::new();
    for bit in bits.bytes() {
        ensure!(bit == b'0' || bit == b'1', "bits: expected binary digits");
        builder.append_bit_bool(bit == b'1')?;
    }
    Ok(builder.into_cell()?)
}
fn bits_text(cell: &Cell) -> Result<String> {
    let mut slice = SliceData::load_cell(cell.clone())?;
    let mut text = String::with_capacity(slice.remaining_bits());
    while slice.remaining_bits() != 0 {
        text.push(if slice.get_next_bit()? { '1' } else { '0' });
    }
    Ok(text)
}
fn roots_json(roots: &[Cell]) -> Value {
    json!(roots.iter().map(|cell| format!("{:X}", cell.repr_hash())).collect::<Vec<_>>())
}
fn rejected(reason: &str, roots: &[Cell], facts: Value) -> Value {
    json!({"outcome":"rejected", "reason":reason, "root_hashes":roots_json(roots), "facts":facts})
}
fn serialize(roots: &[Cell], mode: u8) -> Result<Vec<u8>> {
    if roots.is_empty() {
        return Ok(Vec::new());
    }
    Ok(BocWriter::with_flags(roots.iter().cloned(), BocFlags::from_bits_retain(mode))?
        .write_to_vec()?)
}
fn accepted(roots: &[Cell], bytes: &[u8], facts: Value) -> Value {
    let digest = sha256_digest(bytes);
    let digest = digest.iter().map(|b| format!("{b:02x}")).collect::<String>();
    json!({"outcome":"accepted", "root_hashes":roots_json(roots), "reserialized_sha256":digest, "facts":facts})
}
fn int(ctx: &Value, field: &str, default: Option<i64>) -> Result<i64> {
    match ctx.get(field) {
        Some(v) => v.as_i64().ok_or_else(|| anyhow!("{field}: expected integer")),
        None => default.ok_or_else(|| anyhow!("missing {field}")),
    }
}
fn text<'a>(ctx: &'a Value, field: &str) -> Result<&'a str> {
    ctx[field].as_str().ok_or_else(|| anyhow!("{field}: expected string"))
}
fn address(ctx: &Value) -> Result<AccountId> {
    let value = text(ctx, "address")?;
    ensure!(
        value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()),
        "address: expected 256 bits"
    );
    Ok(AccountId::from_string(value)?)
}
fn flag(ctx: &Value, field: &str) -> Result<bool> {
    ctx.get(field)
        .map(|v| v.as_bool().ok_or_else(|| anyhow!("{field}: expected boolean")))
        .transpose()
        .map(|v| v.unwrap_or(false))
}
fn canonical(facts: &mut Value, codec: VarUIntegerCodec, value: Option<&BigInt>) -> Result<()> {
    let builder = value.map(|v| codec.write(v)).transpose()?.flatten();
    if let Some(builder) = builder {
        let cell = builder.into_cell()?;
        facts["canonical_bits"] = json!(bits_text(&cell)?);
        facts["canonical_hash"] = json!(format!("{:X}", cell.repr_hash()));
    } else {
        facts["canonical_bits"] = Value::Null;
        facts["canonical_hash"] = Value::Null;
    }
    Ok(())
}
fn decimal_integer(text: &str) -> Result<BigInt> {
    // RefInt's decimal parser accepts an empty string as zero. Its physical
    // capacity is five balanced base-2^52 limbs, wider than a VM integer.
    if text.is_empty() {
        return Ok(BigInt::from(0));
    }
    let digits = text.strip_prefix('-').unwrap_or(text);
    ensure!(
        !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()),
        "value: decimal integer required"
    );
    let value: BigInt = text.parse()?;
    let half = BigInt::from(1) << 51usize;
    let places: BigInt = (0..5).map(|i| BigInt::from(1) << (52 * i)).sum();
    let min = -&half * &places;
    let max = (&half - 1) * places;
    ensure!(value >= min && value <= max, "value: decimal integer required");
    Ok(value)
}
fn run_varuint(ctx: &Value) -> Result<Value> {
    let n = usize::try_from(int(ctx, "n", None)?)?;
    let codec = VarUIntegerCodec::new(n).ok_or_else(|| anyhow!("n must be within 1..32"))?;
    let op = ctx.get("op").map(|_| text(ctx, "op")).transpose()?.unwrap_or("read");
    if op == "write" {
        let text = text(ctx, "value")?;
        ensure!(text.len() <= 90, "value: too long");
        let value = decimal_integer(text)?;
        let Some(builder) = codec.write(&value)? else {
            return Ok(rejected("range", &[], json!({})));
        };
        let cell = builder.into_cell()?;
        let mut facts = json!({});
        canonical(&mut facts, codec, Some(&value))?;
        return Ok(accepted(&[cell.clone()], &serialize(&[cell], 0)?, facts));
    }
    ensure!(op == "read", "op must be read or write");
    let bits = text(ctx, "bits")?;
    let cell = bits_cell(bits)?;
    let slice = SliceData::load_cell(cell.clone())?;
    let mut facts = json!({});
    let mut validated = false;
    let mut value = None;
    for (encoding, prefix) in [
        (VarUIntegerEncoding::Minimal, ""),
        (VarUIntegerEncoding::Structural, "gen_"),
        (VarUIntegerEncoding::Positive, "pos_"),
    ] {
        let mut validate = slice.clone();
        let valid = codec.skip(&mut validate, encoding);
        facts[format!("{prefix}validate_bits")] =
            if valid { json!(bits.len() - validate.remaining_bits()) } else { Value::Null };
        let mut decode = slice.clone();
        let decoded = codec.read(&mut decode, encoding);
        facts[format!("{prefix}value")] = json!(decoded.as_ref().map(|v| v.to_string()));
        facts[format!("{prefix}value_bits")] = if decoded.is_some() {
            json!(bits.len() - decode.remaining_bits())
        } else {
            Value::Null
        };
        if prefix.is_empty() {
            validated = valid && validate.is_empty_cell();
            value = decoded;
        }
    }
    let mut skip = slice.clone();
    facts["skip_bits"] = if codec.skip(&mut skip, VarUIntegerEncoding::Structural) {
        json!(bits.len() - skip.remaining_bits())
    } else {
        Value::Null
    };
    facts["as_uint"] = json!(codec.as_uint(&slice).to_string());
    let mut vm_slice = slice;
    let prefix_bits = (usize::BITS - (n - 1).leading_zeros()) as usize;
    let vm_value = load_var_integer(&mut vm_slice, prefix_bits, false).ok();
    facts["vm_bits"] = if vm_value.is_some() {
        json!(bits.len() - vm_slice.remaining_bits())
    } else {
        Value::Null
    };
    facts["vm_value"] = json!(vm_value.map(|v| v.to_string()));
    facts["storage_used"] = if n == 7 && bits.len() * 2 <= 1023 {
        let mut twice = SliceData::load_cell(bits_cell(&format!("{bits}{bits}"))?)?;
        json!(
            codec.skip(&mut twice, VarUIntegerEncoding::Minimal)
                && codec.skip(&mut twice, VarUIntegerEncoding::Minimal)
                && twice.is_empty_cell()
        )
    } else {
        Value::Null
    };
    canonical(&mut facts, codec, value.as_ref())?;
    if validated {
        Ok(accepted(&[cell.clone()], &serialize(&[cell], 0)?, facts))
    } else {
        Ok(rejected("tlb", &[cell], facts))
    }
}
fn run_codec(ctx: &Value) -> Result<Value> {
    let kind = text(ctx, "type")?;
    let budget = int(ctx, "max_cells", Some(1024))?;
    ensure!((1..=1 << 24).contains(&budget), "max_cells out of range");
    let mode = int(ctx, "mode", Some(0))?;
    ensure!((0..=31).contains(&mode), "mode must be within 0..31");
    if kind == "VarUInteger" {
        return run_varuint(ctx);
    }
    ensure!(ctx.get("boc").is_some() != ctx.get("bits").is_some(), "exactly one of boc and bits");
    let bytes = if ctx.get("boc").is_some() {
        base64_decode(text(ctx, "boc")?)?
    } else {
        serialize(&[bits_cell(text(ctx, "bits")?)?], 0)?
    };
    let roots = if bytes.is_empty() {
        Vec::new()
    } else {
        match BocReader::new().stream_read(&mut io::Cursor::new(&bytes)) {
            Ok(bag) if bag.roots.len() <= 1 << 14 && bag.roots.iter().all(|r| r.level() == 0) => {
                bag.roots
            }
            _ => return Ok(rejected("boc", &[], json!({}))),
        }
    };
    let reserialized = serialize(&roots, mode as u8)?;
    if kind == "cell" {
        return Ok(accepted(
            &roots,
            &reserialized,
            json!({"roots": roots.len(), "canonical":bytes == reserialized}),
        ));
    }
    if roots.len() != 1 {
        return Ok(rejected("roots", &roots, json!({"roots": roots.len()})));
    }
    let mut cell = roots[0].clone();
    if ctx
        .get("proof_child")
        .map(|v| v.as_bool().ok_or_else(|| anyhow!("proof_child: expected boolean")))
        .transpose()?
        .unwrap_or(false)
    {
        ensure!(
            cell.cell_type() == CellType::MerkleProof && cell.references_count() == 1,
            "proof_child: the root is not a Merkle proof"
        );
        cell = cell.reference(0)?;
    }
    if let Some(path) = ctx.get("path") {
        let path = path.as_array().ok_or_else(|| anyhow!("path: expected array"))?;
        ensure!(path.len() <= 64, "path: too long");
        for step in path {
            let index =
                usize::try_from(step.as_i64().ok_or_else(|| anyhow!("path: expected index"))?)?;
            cell = cell.reference(index)?;
        }
    }
    use rtos_block::config_param_schema as schema;
    if kind == "account_storage" {
        u32::try_from(int(ctx, "now", None)?)?;
        flag(ctx, "special")?;
        let workchain = i8::try_from(int(ctx, "workchain", Some(0))?)?;
        let address =
            if ctx.get("address").is_some() { address(ctx)? } else { AccountId::from([0; 32]) };
        let storage = rtos_block::ShardAccount::unpack_storage_slice(cell, workchain, &address)
            .ok()
            .flatten();
        return Ok(if let Some(storage) = storage {
            let bits = storage.remaining_bits();
            let refs = (0..storage.remaining_references())
                .map(|i| storage.reference(i))
                .collect::<rtos_block::Result<Vec<_>>>()?;
            let storage_cell = storage.into_cell()?;
            accepted(
                &roots,
                &reserialized,
                json!({"storage_bits":bits,"storage_hash":format!("{:X}",storage_cell.repr_hash()),"storage_refs":roots_json(&refs)}),
            )
        } else {
            rejected("semantic", &roots, json!({}))
        });
    }
    use schema::{TlbProfile, TlbType};
    let typed = match kind {
        "Coins" => Some(TlbType::Coins),
        "ExtraCurrencyCollection" => Some(TlbType::ExtraCurrencyCollection),
        "CurrencyCollection" => Some(TlbType::CurrencyCollection),
        "MsgAddressInt" => Some(TlbType::MsgAddressInt),
        "StateInit" => Some(TlbType::StateInit),
        "StorageUsed" => Some(TlbType::StorageUsed),
        "AccountStorage" => Some(TlbType::AccountStorage),
        "Account" => Some(TlbType::Account),
        "ShardAccount" => Some(TlbType::ShardAccount),
        "Message" => Some(TlbType::Message),
        "MessageRelaxed" => Some(TlbType::MessageRelaxed),
        "Transaction" => Some(TlbType::Transaction),
        "BlockInfo" => Some(TlbType::BlockInfo),
        "McStateExtra" => Some(TlbType::McStateExtra),
        "ShardStateUnsplit" => Some(TlbType::ShardStateUnsplit),
        _ => None,
    };
    if let Some(typed) = typed {
        let gen =
            schema::tlb_type_is_valid(typed, TlbProfile::Generated, cell.clone(), budget as u32);
        let generated_only = matches!(kind, "MessageRelaxed" | "BlockInfo" | "ShardStateUnsplit");
        let handwritten = generated_only
            || schema::tlb_type_is_valid(
                typed,
                TlbProfile::Handwritten,
                cell.clone(),
                budget as u32,
            );
        let mut facts = json!({"gen":gen});
        if !generated_only {
            facts["handwritten"] = json!(handwritten);
        }
        if kind == "Coins" {
            let value = SliceData::load_cell(cell).ok().and_then(|mut slice| {
                VarUIntegerCodec::new(16)?.read(&mut slice, VarUIntegerEncoding::Minimal)
            });
            facts["value"] = json!(value.map(|v| v.to_string()));
        }
        return Ok(if !gen {
            rejected("tlb", &roots, facts)
        } else if !handwritten {
            rejected("handwritten", &roots, facts)
        } else {
            accepted(&roots, &reserialized, facts)
        });
    }
    if kind == "config" {
        let mut old = ctx
            .get("old_mparams")
            .map(|_| -> Result<Cell> {
                Ok(rtos_block::read_single_root_boc(base64_decode(text(ctx, "old_mparams")?)?)?)
            })
            .transpose()?;
        if let Some(old) = old.as_mut() {
            if flag(ctx, "old_mparams_proof_child")? {
                ensure!(
                    old.cell_type() == CellType::MerkleProof && old.references_count() == 1,
                    "old_mparams_proof_child: not a Merkle proof"
                );
                *old = old.reference(0)?;
            }
        }
        let config = ConfigParams::with_address_and_params(address(ctx)?, Some(cell));
        let valid = config.config_data_is_valid(flag(ctx, "relax")?, old);
        let facts = json!({"valid":valid});
        return Ok(if valid {
            accepted(&roots, &reserialized, facts)
        } else {
            rejected("semantic", &roots, facts)
        });
    }
    if kind == "ValidatorSet" {
        let gen = schema::config_param_is_valid_with_budget(32, cell.clone(), budget as u32);
        let unpacked = ValidatorSet::construct_from_full_cell(cell).ok();
        let mut facts = json!({"gen":gen, "unpack":unpacked.is_some()});
        if let Some(set) = unpacked.as_ref() {
            facts["total"] = json!(set.total());
            facts["main"] = json!(set.main());
            facts["total_weight"] = json!(set.total_weight().to_string());
        }
        return Ok(if !gen {
            rejected("tlb", &roots, facts)
        } else if unpacked.is_none() {
            rejected("semantic", &roots, facts)
        } else {
            accepted(&roots, &reserialized, facts)
        });
    }
    let valid = match kind {
        "ConfigParams" => {
            let subject = if ctx.get("address").is_some() {
                let mut builder = BuilderData::new();
                builder.append_raw(address(ctx)?.get_bytestring(0).as_slice(), 256)?;
                builder.checked_append_reference(cell)?;
                builder.into_cell()?
            } else {
                cell
            };
            schema::config_params_is_valid_with_budget(subject, budget as u32)
        }
        "ConfigParam" => schema::config_param_is_valid_with_budget(
            u32::try_from(int(ctx, "n", None)?)?,
            cell,
            budget as u32,
        ),
        "ValidatorDescr" => schema::validator_descr_is_valid_with_budget(cell, budget as u32),
        _ => bail!("codec type adapter pending: {kind}"),
    };
    let facts = json!({"gen":valid});
    Ok(if valid { accepted(&roots, &reserialized, facts) } else { rejected("tlb", &roots, facts) })
}
fn main() -> Result<()> {
    let harness = std::env::args().nth(1).unwrap_or_default();
    if harness == "--info" {
        println!("{}", json!({"harnesses":["codec"]}));
        return Ok(());
    }
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut line = String::new();
        let size = input.by_ref().take((16 << 20) + 2).read_line(&mut line)?;
        if size == 0 {
            break;
        }
        let result = (|| -> Result<Value> {
            ensure!(size <= 16 << 20, "context too large");
            ensure!(harness == "codec", "unsupported harness");
            run_codec(&serde_json::from_str::<Value>(&line)?)
        })()
        .unwrap_or_else(|e| json!({"harness_error":e.to_string()}));
        serde_json::to_writer(&mut output, &result)?;
        writeln!(output)?;
        output.flush()?;
        ensure!(size <= 16 << 20, "context too large");
    }
    Ok(())
}

#[cfg(test)]
#[path = "../src/tests/codec_conformance_inputs.rs"]
mod fixture_inputs;

#[cfg(test)]
mod protocol_tests {
    use super::*;

    #[test]
    fn decimal_protocol_matches_cpp() {
        let rows: Vec<_> =
            include_str!("../src/tests/data/codec-decimal-reference.jsonl").lines().collect();
        assert_eq!(rows.len(), 15);
        for line in rows {
            let row: Value = serde_json::from_str(line).unwrap();
            assert_eq!(row["reference_commit"], "1181c08ed4c2d88425e6ee66efff6d696714495d");
            assert_eq!(row["reference_dirty"], false);
            let actual = run_codec(&row["context"])
                .unwrap_or_else(|e| json!({"harness_error":e.to_string()}));
            assert_eq!(actual, row["effects"], "{}", row["context"]);
        }
    }
}
