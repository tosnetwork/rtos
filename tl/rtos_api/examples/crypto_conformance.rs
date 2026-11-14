// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Explicit-input crypto adapter. All cryptographic operations use native APIs.
use anyhow::{bail, ensure, Context, Result};
use rtos_block::{base64_decode, ed25519_verify, poseidon2, sha256_digest};
use serde_json::{json, Value};
use std::io::{self, BufRead, Read, Write};

const MAX_INPUT: usize = 1 << 20;

#[path = "crypto/config.rs"]
mod config;
#[path = "crypto/identity.rs"]
mod identity;
#[path = "crypto/signatures.rs"]
mod signatures;

struct Inputs<'a> {
    values: &'a Value,
    edits: Vec<(&'a Value, bool)>,
}
impl<'a> Inputs<'a> {
    fn new(context: &'a Value) -> Result<Self> {
        let values = &context["inputs"];
        ensure!(values.is_object(), "inputs object required");
        let mut edits = Vec::new();
        if let Some(list) = context.get("edits") {
            let list = list.as_array().context("edits array required")?;
            ensure!(!list.is_empty() && list.len() <= 16, "1..16 edits required");
            for edit in list {
                edit["input"].as_str().context("edit input required")?;
                let op = edit["op"].as_str().context("edit operation required")?;
                let value = edit["value"].as_u64().context("edit value required")?;
                ensure!(value <= 255, "edit value must be a byte");
                match op {
                    "xor" => {
                        ensure!(value != 0, "xor value must be nonzero");
                        ensure!(
                            edit["offset"].as_u64().context("offset required")? < MAX_INPUT as u64,
                            "offset too large"
                        );
                    }
                    "resize" => ensure!(
                        edit["length"].as_u64().context("length required")? <= 1 << 16,
                        "resize too large"
                    ),
                    "fill" => (),
                    _ => bail!("unknown edit operation"),
                }
                edits.push((edit, false));
            }
        }
        Ok(Self { values, edits })
    }
    fn bytes(&mut self, name: &str) -> Result<Vec<u8>> {
        let text = self.values[name].as_str().context("base64 string required")?;
        ensure!(text.len() <= MAX_INPUT.div_ceil(3) * 4, "input too large");
        let mut bytes = base64_decode(text)?;
        ensure!(bytes.len() <= MAX_INPUT, "input too large");
        for (edit, used) in &mut self.edits {
            if edit["input"].as_str() != Some(name) {
                continue;
            }
            *used = true;
            let value = edit["value"].as_u64().unwrap() as u8;
            match edit["op"].as_str().unwrap() {
                "xor" => {
                    let offset = edit["offset"].as_u64().unwrap() as usize;
                    *bytes.get_mut(offset).context("edit offset outside input")? ^= value;
                }
                "resize" => bytes.resize(edit["length"].as_u64().unwrap() as usize, value),
                "fill" => bytes.fill(value),
                _ => unreachable!(),
            }
        }
        Ok(bytes)
    }
    fn uint64(&self, name: &str) -> Result<u64> {
        let text = self.values[name].as_str().context("unsigned decimal string required")?;
        ensure!(
            !text.is_empty()
                && text.len() <= 20
                && text.bytes().all(|b| b.is_ascii_digit())
                && (text.len() == 1 || !text.starts_with('0')),
            "canonical uint64 required"
        );
        Ok(text.parse()?)
    }
    fn finish(&self) -> Result<()> {
        ensure!(self.edits.iter().all(|(_, used)| *used), "edit names an unread byte input");
        Ok(())
    }
}
fn verdict(name: &str) -> Value {
    json!({"outcome":"verdict","verdict":name})
}
fn verification<E>(result: std::result::Result<bool, E>, backend: impl FnOnce(E) -> bool) -> Value {
    verdict(match result {
        Ok(true) => "valid",
        Ok(false) => "invalid",
        Err(error) => {
            if backend(error) {
                "backend_error"
            } else {
                "malformed_input"
            }
        }
    })
}
fn bytes_effect(bytes: impl AsRef<[u8]>) -> Value {
    json!({"outcome":"bytes","output":hex::encode(bytes)})
}
fn run(context: &Value) -> Result<Value> {
    let mut input = Inputs::new(context)?;
    let scheme = context["scheme"].as_str().context("scheme required")?;
    let operation = context["operation"].as_str().context("operation required")?;
    let result = match (scheme, operation) {
        ("ed25519", "verify") => {
            let message = input.bytes("message")?;
            let signature = input.bytes("signature")?;
            let key = input.bytes("public_key")?;
            verdict(if ed25519_verify(&key, &message, &signature).is_ok() {
                "valid"
            } else {
                "invalid"
            })
        }
        ("mldsa44", "verify") => {
            let message = input.bytes("message")?;
            let domain = input.bytes("context")?;
            let signature = input.bytes("signature")?;
            let key = input.bytes("public_key")?;
            verification(rtos_pq_crypto::verify(&message, &domain, &signature, &key), |e| {
                matches!(e, rtos_pq_crypto::VerifyError::Backend(_))
            })
        }
        ("mldsa44", "verify_consensus") => {
            use rtos_pq_crypto::ConsensusSurface;
            let surface = match input.values["surface"].as_str().context("surface required")? {
                "simplex" => ConsensusSurface::Simplex,
                "validator_election" => ConsensusSurface::ValidatorElection,
                "validator_config_vote" => ConsensusSurface::ValidatorConfigVote,
                "config_admin" => ConsensusSurface::ConfigAdmin,
                _ => bail!("unknown consensus surface"),
            };
            let message = input.bytes("message")?;
            let signature = input.bytes("signature")?;
            let key = input.bytes("public_key")?;
            verification(
                rtos_pq_crypto::verify_consensus(surface, &message, &signature, &key),
                |e| matches!(e, rtos_pq_crypto::VerifyError::Backend(_)),
            )
        }
        ("mldsa44", "derive_key_id") => {
            let algorithm: u16 =
                input.values["algorithm_id"].as_u64().context("algorithm required")?.try_into()?;
            let key = input.bytes("public_key")?;
            match rtos_block::try_derive_consensus_key_id(algorithm, &key) {
                Some(value) => bytes_effect(value.as_slice()),
                None => json!({"outcome":"rejected","reason":"refused"}),
            }
        }
        ("falcon512", "verify_padded") => {
            let message = input.bytes("message")?;
            let signature = input.bytes("signature")?;
            let key = input.bytes("public_key")?;
            verification(rtos_pq_crypto::falcon512::verify(&message, &signature, &key), |e| {
                matches!(e, rtos_pq_crypto::falcon512::VerifyError::Backend(_))
            })
        }
        ("slhdsa128s", "verify") => {
            let message = input.bytes("message")?;
            let domain = input.bytes("context")?;
            let signature = input.bytes("signature")?;
            let key = input.bytes("public_key")?;
            verification(
                rtos_pq_crypto::slhdsa128s::verify(&message, &domain, &signature, &key),
                |e| matches!(e, rtos_pq_crypto::slhdsa128s::VerifyError::Backend(_)),
            )
        }
        ("lms_fee", "verify") => {
            let message = input.bytes("message")?;
            let signature = input.bytes("signature")?;
            let key = input.bytes("public_key")?;
            verdict(match rtos_pq_crypto::lms_fee::verify(&message, &signature, &key) {
                rtos_pq_crypto::lms_fee::Outcome::Valid => "valid",
                rtos_pq_crypto::lms_fee::Outcome::Invalid => "invalid",
                rtos_pq_crypto::lms_fee::Outcome::Malformed => "malformed_input",
            })
        }
        ("lms_fee", "worst_compressions") => {
            let key = input.bytes("public_key")?;
            let length = input.uint64("message_bytes")?.try_into()?;
            match rtos_pq_crypto::lms_fee::worst_compressions(&key, length) {
                Some(value) => json!({"outcome":"integer","value":value.to_string()}),
                None => json!({"outcome":"rejected","reason":"unsupported"}),
            }
        }
        ("sha256", "digest") => bytes_effect(sha256_digest(input.bytes("data")?)),
        ("poseidon2", "permute") => {
            let state = input.values["state"].as_array().context("state array required")?;
            ensure!(state.len() == 8, "eight field elements required");
            let mut elements = [[0u8; 32]; 8];
            for (element, value) in elements.iter_mut().zip(state) {
                let decoded = hex::decode(value.as_str().context("hex element required")?)?;
                *element =
                    decoded.try_into().map_err(|_| anyhow::anyhow!("32-byte element required"))?;
                ensure!(poseidon2::is_canonical(element), "noncanonical field element");
            }
            bytes_effect(poseidon2::permute(&elements).concat())
        }
        ("poseidon2", "manifest_digest") => {
            bytes_effect(sha256_digest(poseidon2::manifest_bytes()))
        }
        ("quorum", "threshold") => json!({"outcome":"integer", "value":
            rtos_block::quorum_threshold(input.uint64("total_weight")?).to_string()}),
        ("quorum", "has_quorum") => json!({"outcome":"boolean", "value":
            rtos_block::quorum_weight_reached(input.uint64("signed_weight")?, input.uint64("total_weight")?)}),
        ("validator_session", operation) => identity::run(operation, &input)?,
        ("consensus", "simplex_data_to_sign") => signatures::signing_data(&mut input)?,
        ("block_signatures", operation) => signatures::run(operation, &mut input)?,
        ("config43", "parse") => config::size_limits(&mut input)?,
        ("validator_set", "unpack") => config::validators(&mut input)?,
        ("elector", operation) => {
            use rtos_pq_crypto::elector;
            let v = input.values;
            let global = identity::i32_field(v, "global_id")?;
            let hash =
                |name: &str| -> Result<[u8; 32]> { Ok(*identity::bits(&v[name])?.as_slice()) };
            bytes_effect(match operation {
                "stake_preimage" => elector::stake_preimage(
                    global,
                    identity::u32_field(v, "stake_at")?,
                    identity::u32_field(v, "max_factor")?,
                    &hash("src_addr")?,
                    &hash("adnl_addr")?,
                ),
                "config_vote_preimage" => elector::config_vote_preimage(
                    global,
                    &hash("validator_set_id")?,
                    &hash("validator_id")?,
                    identity::u32_field(v, "idx")?.try_into()?,
                    &hash("proposal_hash")?,
                ),
                "complaint_vote_preimage" => elector::complaint_vote_preimage(
                    global,
                    &hash("validator_set_id")?,
                    &hash("validator_id")?,
                    identity::u32_field(v, "idx")?.try_into()?,
                    identity::u32_field(v, "election_id")?,
                    &hash("complaint_hash")?,
                ),
                _ => bail!("unsupported crypto operation"),
            })
        }
        ("pq_bytes", "pack") => {
            use rtos_block::{BocFlags, BocWriter};
            let data = input.bytes("data")?;
            let max = identity::u32_field(input.values, "max_bytes")? as usize;
            ensure!(max <= MAX_INPUT, "byte bound too large");
            match rtos_block::pq_bytes::pack_pq_bytes(&data, max) {
                Ok(cell) => {
                    let boc =
                        BocWriter::with_flags([cell.clone()], BocFlags::from_bits_retain(31))?
                            .write_to_vec()?;
                    json!({"outcome":"record","fields":{"root_hash":hex::encode(cell.repr_hash().as_slice()),"boc":hex::encode(boc)}})
                }
                Err(_) => json!({"outcome":"rejected","reason":"refused"}),
            }
        }
        ("pq_bytes", "unpack") => {
            let data = input.bytes("boc")?;
            let max = identity::u32_field(input.values, "max_bytes")? as usize;
            ensure!(max <= MAX_INPUT, "byte bound too large");
            let root = rtos_block::read_single_root_boc(data)?;
            match rtos_block::pq_bytes::unpack_pq_bytes(&root, max) {
                Ok(data) => bytes_effect(data),
                Err(_) => json!({"outcome":"rejected","reason":"refused"}),
            }
        }
        _ => bail!("unsupported crypto operation"),
    };
    input.finish()?;
    Ok(result)
}
fn main() -> Result<()> {
    let harness = std::env::args().nth(1).unwrap_or_default();
    if harness == "--info" {
        println!("{}", json!({"harnesses":["crypto"]}));
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
        let effect = (|| -> Result<Value> {
            ensure!(size <= 16 << 20, "context too large");
            ensure!(harness == "crypto", "unsupported harness");
            run(&serde_json::from_str(&line)?)
        })()
        .unwrap_or_else(|e| json!({"harness_error":e.to_string()}));
        serde_json::to_writer(&mut output, &effect)?;
        writeln!(output)?;
        output.flush()?;
        ensure!(size <= 16 << 20, "context too large");
    }
    Ok(())
}
