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
        CandidateParent,
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
    for entry in db.iterator(IteratorMode::Start) {
        let (key, value) = entry?;
        if !key.starts_with(&Key::constructor_const().to_le_bytes()) {
            continue;
        }
        let (key, consumed) = rtos_api::deserialize_typed_with_suffix::<BoxedKey>(&key)?;
        let key = key.only();
        let (value, value_consumed) = rtos_api::deserialize_typed_with_suffix::<BoxedValue>(&value)?;
        let value = value.only();
        let parent = match value.parent {
            CandidateParent::Consensus_CandidateParent(parent) => Some(format!("{:?}", parent.id.only())),
            CandidateParent::Consensus_CandidateWithoutParents => None,
        };
        decoded.push((key.candidateId.slot, format!("{:?}", key.candidateId), parent,
            format!("{:?}", value.block_id), format!("{:?}", value.is_final), consumed, value_consumed));
    }
    decoded.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let mut expected = None;
    let records: Vec<_> = decoded.into_iter().map(|(slot, candidate, parent, block, is_final, key_bytes, value_bytes)| {
        let record = json!({"slot":slot,"candidate":candidate,"parent":parent,
            "block":block,"is_final":is_final,"key_decoded_bytes":key_bytes,
            "value_decoded_bytes":value_bytes,"matches_previous_record":parent == expected});
        expected = Some(candidate);
        record
    }).collect();
    drop(db);
    let mut file = OpenOptions::new().write(true).create_new(true).open(output)?;
    serde_json::to_writer_pretty(&mut file, &json!({"schema":1,"authenticated":false,
        "database":database,"records":records}))?;
    file.write_all(b"\n")?;
    Ok(())
}
