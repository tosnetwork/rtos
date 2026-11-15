// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use super::{bits, flag, shard, u32_field};
use anyhow::{Context, Result};
use rtos_api::{
    pq_finality::{ExplicitFinalityBlock, FinalityRefusal},
    proof_link::{verify_key_block_proof_link, ProofLinkRefusal},
};
use rtos_block::{BlockError, BlockProofEnvelope, BlockSignaturesVariant, Deserializable};
use serde_json::{json, Value};

fn block(value: &Value) -> Result<ExplicitFinalityBlock> {
    let (workchain, shard) = shard(value)?;
    Ok(ExplicitFinalityBlock {
        workchain,
        shard,
        seqno: u32_field(value, "seqno")?,
        root_hash: bits(&value["root_hash"])?,
        file_hash: bits(&value["file_hash"])?,
    })
}
fn refused(reason: &'static str) -> anyhow::Error {
    super::proofs::ProofRefusal(reason).into()
}
pub(super) fn run(ctx: &Value) -> Result<Value> {
    (|| -> Result<Value> {
        let from = block(&ctx["key_block"])?;
        let to = block(&ctx["block"])?;
        let is_key = flag(ctx, "is_key")?;
        let read = |field: &str| -> Result<_> {
            rtos_block::read_single_root_boc(rtos_block::base64_decode(
                ctx[field].as_str().context("proof BOC required")?,
            )?)
        };
        // C++ reads both BOCs before unpacking either envelope, and decodes the
        // destination certificate before semantic link-direction/header checks.
        let source = read("key_block_proof")?;
        let destination = read("block_proof")?;
        let source = BlockProofEnvelope::construct_from_full_cell(source)
            .map_err(|_| refused("carrier_malformed"))?;
        let destination = BlockProofEnvelope::construct_from_full_cell(destination)
            .map_err(|_| refused("carrier_malformed"))?;
        let certificate = destination.signatures.clone()
            .map(BlockSignaturesVariant::construct_from_full_cell).transpose()
            .map_err(|e| refused(super::proofs::signature_error(&e)))?;
        let result = verify_key_block_proof_link(&from, &to, is_key, &source, &destination, certificate.as_ref())?;
        Ok(json!({"outcome":"linked","gen_utime":result.gen_utime,
            "expected_session_id":hex::encode_upper(result.expected_session_id.as_slice()),
            "verified_weight":result.verified_weight.to_string(),"total_weight":result.total_weight.to_string()}))
    })().map_err(|e| {
        if let Some(error) = e.downcast_ref::<ProofLinkRefusal>() { refused(error.0) }
        else if let Some(error) = e.downcast_ref::<FinalityRefusal>() { refused(error.0) }
        else if rtos_block::pq_block_signature_reason_code(&e).is_some() { refused(super::proofs::signature_error(&e)) }
        // The frozen CPP rules do not match legacy Ed25519's error wording.
        else if matches!(e.downcast_ref::<BlockError>(), Some(BlockError::BadSignature)) { refused("unclassified") }
        else { e }
    })
}

#[cfg(test)]
mod exports {
    use super::*;
    use anyhow::Result;
    use rtos_block::*;

    fn envelope(ctx: &Value, field: &str) -> Result<BlockProofEnvelope> {
        BlockProofEnvelope::construct_from_full_cell(read_single_root_boc(base64_decode(
            ctx[field].as_str().unwrap(),
        )?)?)
    }
    fn raw_block(proof: &BlockProofEnvelope) -> Result<Block> {
        Block::construct_from_full_cell(
            MerkleProof::construct_from_full_cell(proof.root.clone())?.proof,
        )
    }
    fn root(proof: &mut BlockProofEnvelope, cell: Cell) -> Result<()> {
        proof.proof_for.root_hash = cell.hash(0).clone();
        proof.root = MerkleProof { hash: cell.hash(0).clone(), depth: cell.depth(0), proof: cell }
            .serialize()?;
        Ok(())
    }
    fn put(ctx: &mut Value, field: &str, proof: &BlockProofEnvelope, update: bool) -> Result<()> {
        ctx[field] = json!(base64_encode(write_boc(&proof.serialize()?)?));
        if update {
            let id = if field == "key_block_proof" { "key_block" } else { "block" };
            ctx[id]["root_hash"] = json!(hex::encode_upper(proof.proof_for.root_hash.as_slice()));
        }
        Ok(())
    }
    fn pruned(cell: &Cell) -> Result<Cell> {
        let mut b = BuilderData::new();
        b.set_type(CellType::PrunedBranch);
        b.append_u8(1)?
            .append_u8(1)?
            .append_raw(cell.hash(0).as_slice(), 256)?
            .append_u16(cell.depth(0))?;
        Ok(b.into_cell()?)
    }
    fn config_change(
        proof: &mut BlockProofEnvelope,
        f: impl FnOnce(&mut ConfigParams) -> Result<()>,
    ) -> Result<()> {
        let mut b = raw_block(proof)?;
        let mut e = b.read_extra()?;
        let mut custom = e.read_custom()?.unwrap();
        let mut cfg = custom.config().unwrap().clone();
        f(&mut cfg)?;
        custom.set_config(cfg);
        e.write_custom(&custom)?;
        b.write_extra(&e)?;
        root(proof, b.serialize()?)
    }
    fn prune_param(cfg: &mut ConfigParams, index: u32) -> Result<()> {
        let original = cfg
            .proof_config_param_cell(index)
            .with_context(|| format!("prune param {index}"))?
            .unwrap();
        let mut b = BuilderData::new();
        b.checked_append_reference(pruned(&original)?)?;
        cfg.config_params.set_builder(index.write_to_bitstring()?, &b).map(|_| ())
    }

    /// Input-only export. Effects must be filled by the clean pinned C++ CLI.
    #[test]
    #[ignore]
    fn export_proof_link_contexts() -> Result<()> {
        let input = std::fs::read_to_string(std::env::var("RTOS_LINK_CONTEXT_IN")?)?;
        let original: Value = serde_json::from_str(&input)?;
        let source = envelope(&original, "key_block_proof")?;
        let destination = envelope(&original, "block_proof")?;
        let mut rows = Vec::new();
        let mut add = |name: &str, context: Value| {
            rows.push(json!({"fixture_id":name,"context":context}));
        };
        for field in ["key_block_proof", "block_proof"] {
            let mut ctx = original.clone();
            let mut p = envelope(&ctx, field)?;
            p.proof_for.seq_no = 1;
            p.proof_for.root_hash = UInt256::default();
            put(&mut ctx, field, &p, false)?;
            add(&format!("opaque-declared-{field}"), ctx);
        }
        let mut ctx = original.clone();
        let mut p = destination.clone();
        let mut signatures =
            BlockSignaturesVariant::construct_from_full_cell(p.signatures.clone().unwrap())?;
        signatures.as_simplex_pq().unwrap();
        if let BlockSignaturesVariant::SimplexPq(value) = &mut signatures {
            value.sig_weight = 0;
        }
        p.signatures = Some(signatures.serialize()?);
        put(&mut ctx, "block_proof", &p, false)?;
        add("declared-weight-ignored", ctx);
        let mut ctx = original.clone();
        let mut p = source.clone();
        p.signatures = Some(pruned(&Cell::default())?);
        put(&mut ctx, "key_block_proof", &p, false)?;
        add("source-certificate-opaque", ctx);
        for (name, missing, backwards) in
            [("missing-certificate", true, false), ("missing-before-bad-root", true, true)]
        {
            let mut ctx = original.clone();
            let mut p = destination.clone();
            if missing {
                p.signatures = None;
            }
            put(&mut ctx, "block_proof", &p, false)?;
            if backwards {
                let mut s = source.clone();
                s.root = Cell::default();
                put(&mut ctx, "key_block_proof", &s, false)?;
            }
            add(name, ctx);
        }
        let mut ctx = original.clone();
        let mut p = source.clone();
        p.root = Cell::default();
        put(&mut ctx, "key_block_proof", &p, false)?;
        add("bad-source-merkle", ctx);
        let mut ctx = original.clone();
        ctx["key_block"]["seqno"] = ctx["block"]["seqno"].clone();
        add("equal-height", ctx);
        let mut ctx = original.clone();
        ctx["key_block"]["workchain"] = json!(0);
        add("non-masterchain", ctx);
        let mut ctx = original.clone();
        ctx["key_block"]["shard"] = json!("0000000000000001");
        add("unadmitted-mc-prefix", ctx);
        for (name, index) in [("pruned-unused-global-id", 19), ("pruned-session-options", 29)] {
            let mut ctx = original.clone();
            let mut p = source.clone();
            config_change(&mut p, |cfg| prune_param(cfg, index))?;
            put(&mut ctx, "key_block_proof", &p, true)?;
            add(name, ctx);
        }
        let mut ctx = original.clone();
        let mut p = destination.clone();
        let mut b = raw_block(&p)?;
        let mut info = b.read_info().context("destination full info")?;
        info.set_gen_validator_list_hash_short(0);
        b.write_info(&info)?;
        root(&mut p, b.serialize()?)?;
        put(&mut ctx, "block_proof", &p, true)?;
        add("header-subset-hash", ctx.clone());
        let mut s = source.clone();
        config_change(&mut s, |cfg| prune_param(cfg, 29))?;
        put(&mut ctx, "key_block_proof", &s, true)?;
        add("header-hash-before-options", ctx);

        let mut ctx = original.clone();
        let mut p = source.clone();
        config_change(&mut p, |cfg| {
            let mut selected = cfg.selected_simplex_config(true)?.unwrap().config;
            selected.protocol_version = 3;
            cfg.set_config(ConfigParamEnum::ConfigParam30(NewConsensusConfigAll {
                mc: Some(selected),
                shard: None,
            }))?;
            prune_param(cfg, 29)
        })?;
        put(&mut ctx, "key_block_proof", &p, true)?;
        add("options-read-before-unsupported-protocol", ctx);

        let mut ctx = original.clone();
        let mut p = source.clone();
        config_change(&mut p, |cfg| {
            let catchain = cfg.config(28)?.unwrap();
            *cfg = ConfigParams::default();
            cfg.set_config(catchain)
        })?;
        put(&mut ctx, "key_block_proof", &p, true)?;
        add("missing-current-validator-set", ctx);

        // Synthesize a zerostate containing the same governing config, retaining
        // its original Param30 cell and the real destination certificate.
        let b = raw_block(&source)?;
        let cfg = b.read_key_block_config()?;
        let mut state = ShardStateUnsplit::default();
        state.set_global_id(b.global_id());
        state.set_shard(ShardIdent::masterchain());
        let mut custom = McStateExtra::default();
        custom.config = cfg;
        state.write_custom(Some(&custom))?;
        let state = state.serialize().context("serialize synthetic state")?;
        let mut p = source.clone();
        p.proof_for.seq_no = 0;
        p.signatures = None;
        root(&mut p, state)?;
        let mut ctx = original.clone();
        ctx["key_block"]["seqno"] = json!(0);
        put(&mut ctx, "key_block_proof", &p, true)?;
        add("zerostate-anchor", ctx);

        // Development-only deterministic Ed25519 key. No operational key is read
        // or exported; these fixtures are synthetic relative-anchor controls.
        let key = Ed25519KeyOption::<ZeroizingBytes>::from_private_key(&[17; 32])?;
        let node = ValidatorDescr::with_params(SigPubKey::from_bytes(key.pub_key()?)?, 1, None);
        let mut p = source.clone();
        config_change(&mut p, |cfg| {
            cfg.update_param(35, |v| *v = None)?;
            prune_param(cfg, 30).context("hide legacy-unused30")?;
            cfg.set_config(ConfigParamEnum::ConfigParam34(ConfigParam34 {
                cur_validators: ValidatorSet::new(0, u32::MAX, 1, vec![node.clone()])?,
            }))
        })?;
        let cfg = raw_block(&p)?.read_key_block_config()?;
        let catchain = cfg.legacy_proof_catchain_config()?;
        let mut target = raw_block(&destination)?;
        let mut info = target.read_info()?;
        let (_, hash) = cfg.validator_set()?.calc_subset(
            &catchain,
            SHARD_FULL,
            -1,
            info.gen_catchain_seqno(),
        )?;
        info.set_gen_validator_list_hash_short(hash);
        target.write_info(&info)?;
        let mut target_proof = destination.clone();
        root(&mut target_proof, target.serialize()?)?;
        let mut candidate = if let BlockSignaturesVariant::SimplexPq(value) =
            BlockSignaturesVariant::construct_from_full_cell(destination.signatures.unwrap())?
        {
            value.candidate_bytes()?
        } else {
            unreachable!()
        };
        candidate[20..52].copy_from_slice(target_proof.proof_for.root_hash.as_slice());
        for simplex in [false, true] {
            let message = if simplex {
                rtos_api::pq_finality::build_simplex_vote_data(
                    &UInt256::default(),
                    7,
                    &candidate,
                    true,
                )?
                .data_to_sign
            } else {
                Block::build_data_for_sign(
                    &target_proof.proof_for.root_hash,
                    &target_proof.proof_for.file_hash,
                )
                .to_vec()
            };
            let mut pure = BlockSignaturesPure::with_weight(123);
            let pair = CryptoSignaturePair::with_params(
                node.compute_node_id_short()?,
                CryptoSignature::from_bytes(&key.sign(&message)?)?,
            );
            pure.add_sigpair(pair.clone());
            let validator = ValidatorBaseInfo::with_params(hash, info.gen_catchain_seqno());
            let certificate = if simplex {
                BlockSignaturesVariant::Simplex(BlockSignaturesSimplex::new_finalize(
                    validator,
                    pure,
                    UInt256::default(),
                    7,
                    BlockSignaturesSimplex::bytes_to_cell_tree(&candidate)?,
                ))
            } else {
                BlockSignaturesVariant::Ordinary(BlockSignatures::with_params(validator, pure))
            };
            let mut target = target_proof.clone();
            target.signatures = Some(certificate.serialize()?);
            let mut ctx = original.clone();
            put(&mut ctx, "key_block_proof", &p, true)?;
            put(&mut ctx, "block_proof", &target, true)?;
            add(if simplex { "classical-simplex" } else { "classical-ordinary" }, ctx.clone());
            if !simplex {
                for kind in ["empty", "invalid", "duplicate", "unknown"] {
                    let mut bad = certificate.clone();
                    let pure = bad.pure_signatures_mut()?;
                    *pure = BlockSignaturesPure::with_weight(123);
                    let mut entry = pair.clone();
                    if kind == "invalid" {
                        entry.sign = CryptoSignature::from_bytes(&[0; 64])?;
                    }
                    if kind == "unknown" {
                        entry.node_id_short = UInt256::default();
                    }
                    if kind != "empty" {
                        pure.add_sigpair(entry.clone());
                    }
                    if kind == "duplicate" {
                        pure.add_sigpair(entry);
                    }
                    let mut target = target_proof.clone();
                    target.signatures = Some(bad.serialize()?);
                    let mut c = ctx.clone();
                    put(&mut c, "block_proof", &target, true)?;
                    add(&format!("classical-{kind}"), c);
                }
            }
        }
        std::fs::write(
            std::env::var("RTOS_LINK_CONTEXTS_OUT")?,
            rows.into_iter()
                .map(|r| serde_json::to_string(&r).map(|s| s + "\n"))
                .collect::<std::result::Result<String, _>>()?,
        )?;
        Ok(())
    }
}
