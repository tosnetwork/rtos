// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Signature dictionaries have one encoding. The corpus holds canonical
//! `#11`, `#12` and `#13` sets, every set differing from one of them in the
//! label encoding of exactly one dictionary node, entry-shape, key-order and
//! count variations, and the committed noncanonical-label reproducer. It and
//! the verdicts were produced by the reference C++ `BlockSignatureSet::fetch`
//! (see the TSV header); both readers here must reach the same verdicts.
use super::*;
use crate::config_read_budget::ConfigReadBudget;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Mutex};

const CORPUS_BOC: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/src/tests/data/block-signature-dictionaries.boc.lz4");
const CORPUS_TSV: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/src/tests/data/block-signature-dictionaries.tsv.lz4");

#[derive(Debug)]
struct Refused;
impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "dictionary test budget refused")
    }
}
impl std::error::Error for Refused {}

/// Remaining steps and workspace bytes.
struct Budget(Mutex<(usize, usize)>);
impl Budget {
    fn new(steps: usize, workspace: usize) -> Self {
        Self(Mutex::new((steps, workspace)))
    }
    fn ample() -> Self {
        Self::new(100_000_000, 1 << 30)
    }
    fn remaining(&self) -> (usize, usize) {
        *self.0.lock().unwrap()
    }
}
impl ConfigReadBudget for Budget {
    fn step(&self) -> Result<()> {
        let mut u = self.0.lock().unwrap();
        u.0 = u.0.checked_sub(1).ok_or(Refused)?;
        Ok(())
    }
    fn workspace(&self, n: usize) -> Result<()> {
        let mut u = self.0.lock().unwrap();
        u.1 = u.1.checked_sub(n).ok_or(Refused)?;
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
enum Verdict {
    Accept { entries: usize, weight: u64 },
    Refuse,
}

struct Case {
    name: String,
    tag: u8,
    verdict: Verdict,
    error: String,
}

fn decompress(path: &str) -> Vec<u8> {
    lz4::block::decompress(&std::fs::read(path).unwrap(), None).unwrap()
}

fn header_value<'a>(header: &'a str, key: &str) -> &'a str {
    header
        .split(' ')
        .find_map(|field| field.strip_prefix(key).and_then(|rest| rest.strip_prefix('=')))
        .unwrap_or_else(|| panic!("corpus header lacks {key}"))
}

/// The corpus BOC root is a tree of data-free index cells whose leaves, in
/// order, are the case roots; every case root holds data.
fn collect_case_roots(cell: &Cell, roots: &mut Vec<Cell>) {
    if cell.bit_length() != 0 {
        roots.push(cell.clone());
        return;
    }
    for index in 0..cell.references_count() {
        collect_case_roots(&cell.reference(index).unwrap(), roots);
    }
}

fn load_corpus() -> Vec<(Case, Cell)> {
    let tsv = String::from_utf8(decompress(CORPUS_TSV)).unwrap();
    let boc = decompress(CORPUS_BOC);
    let header = tsv.lines().nth(1).unwrap();
    assert_eq!(hex::encode_upper(Sha256::digest(&boc)), header_value(header, "boc_sha256"));
    let mut roots = Vec::new();
    collect_case_roots(&read_single_root_boc(&boc).unwrap(), &mut roots);
    let mut digest = Sha256::new();
    for root in &roots {
        digest.update(root.repr_hash().as_slice());
    }
    assert_eq!(hex::encode_upper(digest.finalize()), header_value(header, "root_hashes_sha256"));
    let cases: usize = header_value(header, "cases").parse().unwrap();
    assert_eq!(roots.len(), cases);

    let mut corpus = Vec::new();
    for line in tsv.lines().filter(|line| !line.starts_with('#')) {
        let row: Vec<_> = line.split('\t').collect();
        assert_eq!(row.len(), 7, "{line}");
        let index: usize = row[0].parse().unwrap();
        assert_eq!(index, corpus.len());
        let verdict = match row[3] {
            "accept" => Verdict::Accept {
                entries: row[4].parse().unwrap(),
                weight: row[5].parse().unwrap(),
            },
            "refuse" => Verdict::Refuse,
            other => panic!("unknown verdict {other}"),
        };
        let case = Case {
            name: row[1].to_string(),
            tag: u8::from_str_radix(row[2], 16).unwrap(),
            verdict,
            error: row[6].to_string(),
        };
        corpus.push((case, roots[index].clone()));
    }
    assert_eq!(corpus.len(), cases);
    corpus
}

fn verdict_of(signatures: Result<BlockSignaturesVariant>) -> Verdict {
    match signatures {
        Ok(BlockSignaturesVariant::SimplexPq(set)) => {
            Verdict::Accept { entries: set.signatures.len(), weight: set.sig_weight }
        }
        Ok(set) => {
            let pure = set.pure_signatures().unwrap();
            Verdict::Accept { entries: pure.signatures().len().unwrap(), weight: pure.weight() }
        }
        Err(_) => Verdict::Refuse,
    }
}

fn proof_with(signatures: &Cell) -> Cell {
    let mut proof = BuilderData::new();
    proof.append_u8(BLOCK_PROOF_TAG).unwrap();
    BlockIdExt::default().write_to(&mut proof).unwrap();
    proof.checked_append_reference(Cell::default()).unwrap();
    proof.append_bit_one().unwrap();
    proof.checked_append_reference(signatures.clone()).unwrap();
    proof.into_cell().unwrap()
}

fn signatures_of(proof: Result<BlockProof>) -> Result<BlockSignaturesVariant> {
    proof.map(|proof| proof.signatures.unwrap())
}

/// Every C++ verdict, through the ordinary reader, the ordinary proof reader,
/// the bounded proof reader and, for `#13`, the bounded carrier reader.
#[test]
fn signature_dictionaries_match_cpp_verdicts() {
    let corpus = load_corpus();
    // Each case is independent; the corpus is checked on several threads.
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get()).min(32);
    let chunk = corpus.len().div_ceil(threads);
    let outcomes: Vec<(Vec<String>, usize)> = std::thread::scope(|scope| {
        let workers: Vec<_> =
            corpus.chunks(chunk).map(|cases| scope.spawn(move || check_cases(cases))).collect();
        workers.into_iter().map(|worker| worker.join().unwrap()).collect()
    });
    let failures: Vec<_> = outcomes.iter().flat_map(|(failures, _)| failures).collect();
    assert!(failures.is_empty(), "{} mismatches:\n{failures:#?}", failures.len());

    let mut summary = BTreeMap::<(u8, &str), usize>::new();
    for (case, _) in &corpus {
        let verdict = if case.verdict == Verdict::Refuse { "refuse" } else { "accept" };
        *summary.entry((case.tag, verdict)).or_default() += 1;
    }
    println!("corpus by carrier and verdict: {summary:?}");
    // Every C++ noncanonical-dictionary refusal is a Rust refusal that names
    // the same rule.
    let noncanonical_refusals: usize = outcomes.iter().map(|(_, count)| count).sum();
    let cpp_noncanonical =
        corpus.iter().filter(|(case, _)| case.error.contains("noncanonical")).count();
    assert!(cpp_noncanonical > 0);
    assert_eq!(noncanonical_refusals, cpp_noncanonical);
}

/// Mismatches against the C++ verdicts, and how many refusals of the
/// ordinary reader named the noncanonical-dictionary rule.
fn check_cases(cases: &[(Case, Cell)]) -> (Vec<String>, usize) {
    let mut failures = Vec::new();
    let mut noncanonical_refusals = 0;
    for (case, root) in cases {
        let mut expect = |reader: &str, actual: Verdict| {
            if actual != case.verdict {
                failures.push(format!(
                    "{reader}, case {}: Rust {actual:?}, C++ {:?} {}",
                    case.name, case.verdict, case.error
                ));
            }
        };
        if root.data().first() != Some(&case.tag) {
            failures.push(format!("case {}: tag mismatch", case.name));
            continue;
        }
        let ordinary = BlockSignaturesVariant::construct_from_cell(root.clone());
        if let Err(error) = &ordinary {
            if error.to_string().contains("noncanonical dictionary") {
                noncanonical_refusals += 1;
            }
        }
        expect("ordinary reader", verdict_of(ordinary));
        let proof = proof_with(root);
        expect(
            "ordinary proof reader",
            verdict_of(signatures_of(BlockProof::construct_from_cell(proof.clone()))),
        );
        expect(
            "bounded proof reader",
            verdict_of(signatures_of(BlockProof::construct_from_cell_bounded(
                proof,
                &Budget::ample(),
            ))),
        );
        if case.tag == BLOCK_SIGNATURES_SIMPLEX_PQ_TAG {
            expect(
                "bounded #13 reader",
                verdict_of(
                    BlockSignaturesSimplexPq::construct_bounded(root.clone(), &Budget::ample())
                        .map(BlockSignaturesVariant::SimplexPq),
                ),
            );
        }
    }
    (failures, noncanonical_refusals)
}

/// The corpus reaches the count limits: 1024 classical entries and the PQ
/// signer maximum are accepted, 1025 classical entries are refused.
#[test]
fn signature_dictionary_corpus_covers_count_limits() {
    let corpus = load_corpus();
    let canonical = |name: &str| {
        &corpus.iter().find(|(case, _)| case.name == name).unwrap_or_else(|| panic!("{name}")).0
    };
    for carrier in ["ordinary", "simplex"] {
        assert_eq!(
            canonical(&format!("{carrier}-{MAX_CLASSICAL_SIGNATURES}")).verdict,
            Verdict::Accept { entries: MAX_CLASSICAL_SIGNATURES, weight: 1024 }
        );
        assert_eq!(
            canonical(&format!("{carrier}-{}", MAX_CLASSICAL_SIGNATURES + 1)).verdict,
            Verdict::Refuse
        );
        for rule in ["trailing-bit", "trailing-ref", "short-entry", "key-gap", "count-low"] {
            assert_eq!(canonical(&format!("{carrier}-{rule}")).verdict, Verdict::Refuse);
        }
    }
    assert_eq!(
        canonical(&format!("pq-{PQ_SIGNATURE_MAX_SIGNERS}")).verdict,
        Verdict::Accept {
            entries: PQ_SIGNATURE_MAX_SIGNERS as usize,
            weight: PQ_SIGNATURE_MAX_SIGNERS as u64
        }
    );
}

/// The bounded rebuild writes the cell the dictionary serializer writes.
#[test]
fn bounded_canonical_dictionary_matches_serializer() {
    let budget = Budget::ample();
    for count in (0..=130).chain([255, 256, 257, 511, 1023, 1024, 1025]) {
        let mut serialized = HashmapE::with_bit_len(SIGNATURE_DICTIONARY_KEY_BITS);
        for index in 0..count {
            let mut value = BuilderData::new();
            value.append_u32(index as u32 ^ 0x5a5a_0000).unwrap();
            serialized
                .set_builder(
                    SliceData::load_bitstring(
                        BuilderData::with_raw((index as u16).to_be_bytes().to_vec(), 16).unwrap(),
                    )
                    .unwrap(),
                    &value,
                )
                .unwrap();
        }
        let rebuilt = canonical_index_dictionary_bounded(count, &budget, &mut |index, b| {
            b.append_u32(index as u32 ^ 0x5a5a_0000)?;
            Ok(())
        })
        .unwrap();
        assert_eq!(
            rebuilt.as_ref().map(Cell::repr_hash),
            serialized.data().map(Cell::repr_hash),
            "{count} entries"
        );
    }
}

/// The rebuild is admitted through the reader's budget: one step and one cell
/// allocation per rebuilt cell, and a budget that cannot cover it refuses.
#[test]
fn bounded_dictionary_rebuild_is_charged() {
    let corpus = load_corpus();
    let root = &corpus.iter().find(|(case, _)| case.name == "ordinary-1024").unwrap().1;
    let mut slice = SliceData::load_cell(root.clone()).unwrap();
    slice.get_next_byte().unwrap();
    ValidatorBaseInfo::construct_from(&mut slice).unwrap();
    let parse_only = {
        let budget = Budget::ample();
        let mut slice = slice.clone();
        u32::construct_from(&mut slice).unwrap();
        u64::construct_from(&mut slice).unwrap();
        let mut dictionary = CryptoSignaturePairDict::default();
        dictionary.read_from(&mut slice).unwrap();
        dictionary.0.iterate_slices_bounded(&budget, |_, _| Ok(true)).unwrap();
        budget.remaining()
    };
    let budget = Budget::ample();
    let parsed = BlockSignaturesPure::construct_bounded(&mut slice.clone(), &budget).unwrap();
    assert_eq!(parsed.count(), 1024);
    let full = budget.remaining();
    let cells = 2 * 1024 - 1;
    assert!(parse_only.0 - full.0 >= cells, "{parse_only:?} {full:?}");
    assert!(
        parse_only.1 - full.1 >= cells * crate::merkle_apply_budget::NEW_CELL_ALLOCATION,
        "{parse_only:?} {full:?}"
    );
    let used_steps = Budget::ample().remaining().0 - full.0;
    let short = Budget::new(used_steps - 1, 1 << 30);
    let error = BlockSignaturesPure::construct_bounded(&mut slice.clone(), &short).unwrap_err();
    assert!(error.downcast_ref::<Refused>().is_some(), "{error}");
}

/// A carrier written by the Rust serializers passes both readers.
#[test]
fn serialized_classical_sets_pass_both_readers() {
    for count in [0usize, 1, 2, 3, 17, MAX_CLASSICAL_SIGNATURES] {
        let mut pure = BlockSignaturesPure::with_weight(count as u64);
        for index in 0..count {
            pure.add_sigpair(CryptoSignaturePair::with_params(
                UInt256::from([index as u8; 32]),
                CryptoSignature::with_bytes([0x41u8.wrapping_add(index as u8); 64]),
            ));
        }
        let set = BlockSignaturesVariant::Ordinary(BlockSignatures::with_params(
            ValidatorBaseInfo::with_params(0x3141_5926, 7),
            pure,
        ));
        let root = set.serialize().unwrap();
        assert_eq!(BlockSignaturesVariant::construct_from_cell(root.clone()).unwrap(), set);
        let proof =
            BlockProof::construct_from_cell_bounded(proof_with(&root), &Budget::ample()).unwrap();
        assert_eq!(proof.signatures.unwrap(), set);
    }
}
