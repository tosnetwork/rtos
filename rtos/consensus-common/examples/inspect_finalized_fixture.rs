//! Decode finalized records from a stopped fixture's copied RocksDB.
//! This diagnostic does not authenticate certificates or qualify recovery.
use anyhow::{bail, Context, Result};
use rocksdb::{IteratorMode, Options, DB};
use rtos_api::{
    ton::consensus::{
        simplex::db::{
            key::{finalizedblock::FinalizedBlock as Key, FinalizedBlock as BoxedKey},
            FinalizedBlock as BoxedValue,
        },
        CandidateHashData, CandidateParent,
    },
    Constructor,
};
use serde_json::json;
use std::{fs::OpenOptions, io::Write, path::PathBuf};

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let database = PathBuf::from(args.next().context("copied fixture database path required")?);
    let output = PathBuf::from(args.next().context("new output JSON path required")?);
    if args.next().is_some() {
        bail!("usage: inspect_finalized_fixture COPIED_DATABASE NEW_OUTPUT_JSON");
    }
    // Never create, repair, or update the inspected database.
    let db = DB::open_for_read_only(&Options::default(), &database, false)?;
    let mut decoded = Vec::new();
    let mut metadata = Vec::new();
    let mut certificates = Vec::new();
    let mut votes = Vec::new();
    for entry in db.iterator(IteratorMode::Start) {
        let (key, value) = entry?;
        use rtos_api::ton::consensus::simplex::db::{candidate_resolver, key as keys, Vote};
        if key.starts_with(
            &keys::candidate_resolver::candidateinfo::CandidateInfo::constructor_const()
                .to_le_bytes(),
        ) {
            let k = rtos_api::deserialize_typed::<keys::candidate_resolver::CandidateInfo>(&key)?
                .only();
            let v =
                rtos_api::deserialize_typed::<candidate_resolver::CandidateInfo>(&value)?.only();
            let parent = match &v.candidate_hash_data {
                CandidateHashData::Consensus_CandidateHashDataEmpty(v) => {
                    Some(format!("{:?}", v.parent))
                }
                CandidateHashData::Consensus_CandidateHashDataOrdinary(v) => match &v.parent {
                    CandidateParent::Consensus_CandidateParent(p) => {
                        Some(format!("{:?}", p.id.clone().only()))
                    }
                    CandidateParent::Consensus_CandidateWithoutParents => None,
                },
            };
            metadata.push(json!({"candidate":format!("{:?}", k.candidateId), "parent":parent,
                "block":format!("{:?}", v.candidate_hash_data.block())}));
        }
        if key.starts_with(&keys::vote::Vote::constructor_const().to_le_bytes()) {
            if let Vote::Consensus_Simplex_Db_Vote(v) = rtos_api::deserialize_typed::<Vote>(&value)?
            {
                use rtos_api::ton::consensus::simplex::{UnsignedVote, Vote as SignedVote};
                let signed: SignedVote = rtos_api::deserialize_typed(&v.data)?;
                let (role, slot, candidate) = match signed.vote() {
                    UnsignedVote::Consensus_Simplex_NotarizeVote(v) => {
                        ("notar", *v.id.slot(), Some(format!("{:?}", v.id.clone().only())))
                    }
                    UnsignedVote::Consensus_Simplex_FinalizeVote(v) => {
                        ("final", *v.id.slot(), Some(format!("{:?}", v.id.clone().only())))
                    }
                    UnsignedVote::Consensus_Simplex_SkipVote(v) => ("skip", v.slot, None),
                };
                votes.push(json!({"role":role,"slot":slot,"candidate":candidate,"validator_index":v.node_idx,"seqno":v.seqno}));
            }
            if let Vote::Consensus_Simplex_Db_Cert(v) = rtos_api::deserialize_typed::<Vote>(&value)?
            {
                use rtos_api::ton::consensus::simplex::UnsignedVote;
                let (role, id) = match v.cert.vote {
                    UnsignedVote::Consensus_Simplex_NotarizeVote(v) => {
                        ("notar", format!("{:?}", v.id.only()))
                    }
                    UnsignedVote::Consensus_Simplex_FinalizeVote(v) => {
                        ("final", format!("{:?}", v.id.only()))
                    }
                    UnsignedVote::Consensus_Simplex_SkipVote(_) => continue,
                };
                certificates.push(json!({"role":role,"candidate":id}));
            }
        }
        if !key.starts_with(&Key::constructor_const().to_le_bytes()) {
            continue;
        }
        let (key, consumed) = rtos_api::deserialize_typed_with_suffix::<BoxedKey>(&key)?;
        let key = key.only();
        let (value, value_consumed) =
            rtos_api::deserialize_typed_with_suffix::<BoxedValue>(&value)?;
        let value = value.only();
        let parent = match value.parent {
            CandidateParent::Consensus_CandidateParent(parent) => {
                Some(format!("{:?}", parent.id.only()))
            }
            CandidateParent::Consensus_CandidateWithoutParents => None,
        };
        decoded.push((
            key.candidateId.slot,
            format!("{:?}", key.candidateId),
            parent,
            format!("{:?}", value.block_id),
            format!("{:?}", value.is_final),
            consumed,
            value_consumed,
        ));
    }
    decoded.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let mut expected = None;
    let records: Vec<_> = decoded
        .into_iter()
        .map(|(slot, candidate, parent, block, is_final, key_bytes, value_bytes)| {
            let record = json!({"slot":slot,"candidate":candidate,"parent":parent,
            "block":block,"is_final":is_final,"key_decoded_bytes":key_bytes,
            "value_decoded_bytes":value_bytes,"matches_previous_record":parent == expected});
            expected = Some(candidate);
            record
        })
        .collect();
    drop(db);
    let mut file = OpenOptions::new().write(true).create_new(true).open(output)?;
    serde_json::to_writer_pretty(
        &mut file,
        &json!({"schema":1,"authenticated":false,
        "database":database,"records":records,"candidate_metadata":metadata,
        "certificates":certificates,"votes":votes}),
    )?;
    file.write_all(b"\n")?;
    Ok(())
}
