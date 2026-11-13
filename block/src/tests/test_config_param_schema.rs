// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Configuration validation against verdicts of the reference implementation.
//!
//! The corpus (`config-param-schema.boc.lz4`, cases in
//! `config-param-schema.tsv.lz4`) holds single parameter values (`p`, checked as
//! the schema type of their index with a budget of 1024 reference visits),
//! whole configurations (`c`, the complete block-acceptance predicate) and
//! `ConfigParams` dictionaries (`s`, the shape check with a budget of 10000
//! visits). Expected verdicts come from the reference C++ implementation
//! (see the TSV header); every case carries a fingerprint over all of its
//! inputs so a changed corpus cannot silently reuse stale verdicts.
//!
//! The ignored `generate_config_param_schema_corpus` test regenerates the
//! raw corpus into `$RTOS_CFG_CORPUS_OUT`, and
//! `pack_config_param_schema_corpus` packs `$RTOS_CFG_CORPUS_OUT` with the
//! reference verdicts into the test data directory.
use super::*;
use crate::MerkleUpdate;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

const CORPUS_BOC: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/src/tests/data/config-param-schema.boc.lz4");
const CORPUS_TSV: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/src/tests/data/config-param-schema.tsv.lz4");

#[derive(Clone)]
struct Case {
    id: String,
    kind: char,
    index: i64,
    relax: bool,
    addr: [u8; 32],
    root: Option<Cell>,
    mparams: Option<Cell>,
}

fn hash_or_dash(cell: &Option<Cell>) -> String {
    cell.as_ref().map_or_else(|| "-".to_string(), |c| c.repr_hash().to_hex_string())
}

fn budget(kind: char) -> u32 {
    match kind {
        's' => 10000,
        _ => 1024,
    }
}

/// Fingerprint over every verdict input. The reference driver computes the
/// same string from the cells it deserialised.
fn fingerprint(case: &Case) -> String {
    let text = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        case.kind,
        case.index,
        u8::from(case.relax),
        hex::encode(case.addr),
        hash_or_dash(&case.root),
        hash_or_dash(&case.mparams),
        budget(case.kind)
    );
    // The first 64 bits of the digest are enough to tie a verdict to its inputs.
    hex::encode(&Sha256::digest(text.as_bytes())[..8])
}

fn verdict(case: &Case) -> bool {
    let config =
        || ConfigParams::with_address_and_params(AccountId::from(case.addr), case.root.clone());
    match case.kind {
        'p' => case.root.clone().is_some_and(|cell| {
            config_param_schema::config_param_is_valid(case.index as u32, cell)
        }),
        'c' => config().config_data_is_valid(case.relax, case.mparams.clone()),
        's' => config().config_params_shape_is_valid(),
        kind => panic!("unknown case kind {kind}"),
    }
}

/// Depth of the data-free index tree whose cells at this depth, in order,
/// are the stored case roots.
const INDEX_DEPTH: usize = 8;

fn index_tree(mut level: Vec<Cell>) -> Cell {
    assert!(level.len() <= 1 << (2 * INDEX_DEPTH));
    for _ in 0..INDEX_DEPTH {
        level = level.chunks(4).map(|chunk| make_cell(&[], chunk).unwrap()).collect();
        if level.is_empty() {
            level.push(empty());
        }
    }
    assert_eq!(level.len(), 1);
    level.remove(0)
}

fn index_leaves(cell: &Cell, depth: usize, out: &mut Vec<Cell>) {
    if depth == 0 {
        out.push(cell.clone());
        return;
    }
    for child in refs_of(cell) {
        index_leaves(&child, depth - 1, out);
    }
}

fn decompress(path: &str) -> Vec<u8> {
    lz4::block::decompress(&std::fs::read(path).unwrap(), None).unwrap()
}

/// A BOC root cannot have a nonzero level, so the corpus stores a case
/// cell containing pruned branches under a Merkle proof cell; readers take
/// its child. No case cell is itself a Merkle proof.
fn root_ref(roots: &[Cell], field: &str) -> Option<Cell> {
    (field != "-").then(|| {
        let cell = roots[field.parse::<usize>().unwrap()].clone();
        match cell.cell_type() {
            CellType::MerkleProof => cell.reference(0).unwrap(),
            _ => cell,
        }
    })
}

fn storable(cell: &Cell) -> Cell {
    assert_ne!(cell.cell_type(), CellType::MerkleProof);
    if cell.level() == 0 {
        return cell.clone();
    }
    let proof = crate::MerkleProof {
        hash: cell.hash(0).clone(),
        depth: cell.depth(0),
        proof: cell.clone(),
    };
    proof.serialize().unwrap()
}

#[test]
fn config_param_schema_matches_reference_verdicts() {
    let tree = read_single_root_boc(decompress(CORPUS_BOC)).unwrap();
    let mut roots = Vec::new();
    index_leaves(&tree, INDEX_DEPTH, &mut roots);
    let text = String::from_utf8(decompress(CORPUS_TSV)).unwrap();
    let mut lines = text.lines();
    let header = lines.next().unwrap();
    assert!(header.starts_with("# reference_commit=881240331ee48a291b96d73f8b8b93bae005ace0"));
    let mut mismatches = Vec::new();
    let mut counts = BTreeMap::new();
    // These two schema definitions changed after the legacy reference. Keep
    // the original corpus intact and bind the new C++ verdict to its inputs.
    let refreshed = include_str!("data/config-param-schema-43-47.tsv");
    assert!(refreshed.starts_with("# reference_commit=1181c08ed4c2d88425e6ee66efff6d696714495d "));
    let mut refreshed: BTreeMap<_, _> = refreshed
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let columns: Vec<_> = line.split('\t').collect();
            assert_eq!(columns.len(), 3);
            (columns[0], (columns[1], columns[2]))
        })
        .collect();
    for line in lines {
        let f: Vec<_> = line.split('\t').collect();
        assert_eq!(f.len(), 9, "{line}");
        let case = Case {
            id: f[0].to_string(),
            kind: f[1].chars().next().unwrap(),
            index: f[2].parse().unwrap(),
            relax: f[3] == "1",
            addr: hex::decode(f[4]).unwrap().try_into().unwrap(),
            root: root_ref(&roots, f[5]),
            mparams: root_ref(&roots, f[6]),
        };
        assert_eq!(fingerprint(&case), f[7], "fingerprint of {}", case.id);
        let reference = if case.kind == 'p' && matches!(case.index, 43 | 47) {
            let (fingerprint, verdict) =
                refreshed.remove(case.id.as_str()).expect("missing refreshed verdict");
            assert_eq!(fingerprint, f[7], "refreshed fingerprint {}", case.id);
            verdict
        } else {
            f[8]
        };
        let expected = match reference {
            "1" => true,
            "0" => false,
            other => panic!("{}: unusable reference verdict {other}", case.id),
        };
        *counts.entry((case.kind, expected)).or_insert(0usize) += 1;
        if verdict(&case) != expected {
            mismatches.push(format!("{} expected {}", case.id, expected));
        }
    }
    println!("cases by kind and verdict: {counts:?}");
    assert!(counts.values().sum::<usize>() > 1000);
    assert!(mismatches.is_empty(), "{} mismatches: {:#?}", mismatches.len(), mismatches);
    assert!(refreshed.is_empty(), "unused refreshed verdicts");
}

/// Export existing corpus inputs only; expectations are filled by the C++ CLI.
#[test]
#[ignore]
fn export_existing_schema_43_47_contexts() {
    let out = std::env::var("RTOS_CFG_CORPUS_OUT").expect("RTOS_CFG_CORPUS_OUT");
    let tree = read_single_root_boc(decompress(CORPUS_BOC)).unwrap();
    let mut roots = Vec::new();
    index_leaves(&tree, INDEX_DEPTH, &mut roots);
    let text = String::from_utf8(decompress(CORPUS_TSV)).unwrap();
    let mut contexts = String::new();
    for line in text.lines().filter(|line| !line.starts_with('#')) {
        let f: Vec<_> = line.split('\t').collect();
        if f[1] != "p" || !matches!(f[2], "43" | "47") {
            continue;
        }
        let cell = root_ref(&roots, f[5]).unwrap();
        let stored = storable(&cell);
        let boc = crate::base64_encode(crate::write_boc(&stored).unwrap());
        contexts.push_str(&format!(
            "{}\t{}\t{{\"type\":\"ConfigParam\",\"n\":{},\"boc\":\"{}\",\"proof_child\":{}}}\n",
            f[0],
            f[7],
            f[2],
            boc,
            cell.level() != 0
        ));
    }
    std::fs::write(format!("{out}/schema-43-47-contexts.tsv"), contexts).unwrap();
}

#[test]
fn schema_index_set_is_exact() {
    let cell = Cell::default();
    for index in 0..=200u32 {
        let known = config_param_schema::SCHEMA_CONFIG_PARAMS.contains(&index);
        if !known {
            assert!(!config_param_schema::config_param_is_valid(index, cell.clone()), "{index}");
        }
    }
    assert!(!config_param_schema::config_param_is_valid(u32::MAX, cell));
}

/// A certificate chain about a thousand references deep is walked to its end
/// on a small stack: references are visited from a work list, not by
/// recursion. The chain stays within the visit budget, so it is accepted.
#[test]
fn deep_certificate_chain_is_walked_without_recursion() {
    let simple = cat(&[u(5, 4), u(0, 512)]);
    let certificate_head = cat(&[u(4, 4), u(0x8e81278a, 32), u(0, 256), u(0, 64)]);
    let mut cell = make_cell(&cat(&[certificate_head.clone(), simple.clone()]), &[]).unwrap();
    for _ in 0..999 {
        let bits = cat(&[certificate_head.clone(), u(15, 4), simple.clone()]);
        cell = make_cell(&bits, &[cell]).unwrap();
    }
    let temp_key =
        make_cell(&cat(&[u(3, 4), u(0, 256), u(0x8e81278a, 32), u(0, 256), u(0, 64)]), &[])
            .unwrap();
    let leaf = cat(&[u(4, 4), u(15, 4), simple]);
    let list = build_hashmap(&[(u(1, 256), leaf, vec![temp_key, cell])], 256, Style::Canonical);
    let param = make_cell(&[true], &[list]).unwrap();
    assert!(param.depth(0) >= 1000);
    let shared = param.clone();
    let handle = std::thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(move || config_param_schema::config_param_is_valid(39, shared))
        .unwrap();
    assert!(handle.join().unwrap());
}

// ---------------------------------------------------------------------------
// Corpus generation
// ---------------------------------------------------------------------------

fn bits_of(cell: &Cell) -> Vec<bool> {
    let slice = SliceData::load_cell(cell.clone()).unwrap();
    (0..slice.remaining_bits()).map(|i| slice.get_bit(i).unwrap()).collect()
}

fn refs_of(cell: &Cell) -> Vec<Cell> {
    (0..cell.references_count()).map(|i| cell.reference(i).unwrap()).collect()
}

fn make_cell(bits: &[bool], refs: &[Cell]) -> Option<Cell> {
    let mut builder = BuilderData::new();
    for bit in bits {
        builder.append_bit_bool(*bit).ok()?;
    }
    for r in refs {
        builder.checked_append_reference(r.clone()).ok()?;
    }
    builder.into_cell().ok()
}

fn uint_bits(value: u64, width: usize) -> Vec<bool> {
    (0..width).rev().map(|i| i < 64 && (value >> i) & 1 == 1).collect()
}

fn pruned(cell: &Cell) -> Cell {
    MerkleUpdate::make_pruned_branch_cell(cell, 0).unwrap().into_cell().unwrap()
}

fn library(cell: &Cell) -> Cell {
    cell.as_library_cell()
}

fn empty() -> Cell {
    Cell::default()
}

/// Raw dictionary helpers with explicit label encodings.
#[derive(Clone, Copy, PartialEq)]
enum Style {
    Canonical,
    Short,
    Long,
}

fn label(bits: &[bool], n: usize, style: Style) -> Vec<bool> {
    let width = (usize::BITS - n.leading_zeros()) as usize;
    let short = || {
        let mut out = vec![false];
        out.extend(std::iter::repeat_n(true, bits.len()));
        out.push(false);
        out.extend_from_slice(bits);
        out
    };
    let long = || {
        let mut out = vec![true, false];
        out.extend(uint_bits(bits.len() as u64, width));
        out.extend_from_slice(bits);
        out
    };
    let same = || {
        if bits.is_empty() || bits.iter().any(|b| *b != bits[0]) {
            return None;
        }
        let mut out = vec![true, true, bits[0]];
        out.extend(uint_bits(bits.len() as u64, width));
        Some(out)
    };
    match style {
        Style::Short => short(),
        Style::Long => long(),
        Style::Canonical => {
            let mut best = short();
            for other in [Some(long()), same()].into_iter().flatten() {
                if other.len() < best.len() {
                    best = other;
                }
            }
            best
        }
    }
}

/// Builds a `Hashmap n` from sorted keys (as bit vectors) and leaf contents
/// (bits, refs) with the given label style.
fn build_hashmap(entries: &[(Vec<bool>, Vec<bool>, Vec<Cell>)], n: usize, style: Style) -> Cell {
    assert!(!entries.is_empty());
    if entries.len() == 1 {
        let (key, bits, refs) = &entries[0];
        let mut data = label(key, n, style);
        data.extend_from_slice(bits);
        return make_cell(&data, refs).unwrap();
    }
    let mut common = 0;
    while entries.iter().all(|e| e.0[common] == entries[0].0[common]) {
        common += 1;
    }
    let prefix = entries[0].0[..common].to_vec();
    let split = |bit: bool| -> Vec<(Vec<bool>, Vec<bool>, Vec<Cell>)> {
        entries
            .iter()
            .filter(|e| e.0[common] == bit)
            .map(|e| (e.0[common + 1..].to_vec(), e.1.clone(), e.2.clone()))
            .collect()
    };
    let rest = n - common - 1;
    let left = build_hashmap(&split(false), rest, style);
    let right = build_hashmap(&split(true), rest, style);
    make_cell(&label(&prefix, n, style), &[left, right]).unwrap()
}

fn key32(index: i32) -> Vec<bool> {
    uint_bits(u64::from(index as u32), 32)
}

fn raw_entries(config: &ConfigParams) -> BTreeMap<i32, Cell> {
    config_param_schema::dictionary_leaves(config.root().unwrap().clone(), 32)
        .unwrap()
        .into_iter()
        .map(|(key, value)| {
            assert!(value.remaining_bits() == 0 && value.remaining_references() == 1);
            (signed_key(key), value.reference(0).unwrap())
        })
        .collect()
}

/// A configuration dictionary with arbitrary leaf contents.
fn config_root(entries: &BTreeMap<i32, (Vec<bool>, Vec<Cell>)>, style: Style) -> Option<Cell> {
    let mut list: Vec<_> = entries
        .iter()
        .map(|(index, (bits, refs))| (key32(*index), bits.clone(), refs.clone()))
        .collect();
    list.sort_by(|a, b| a.0.cmp(&b.0));
    (!list.is_empty()).then(|| build_hashmap(&list, 32, style))
}

fn values(entries: &BTreeMap<i32, Cell>) -> BTreeMap<i32, (Vec<bool>, Vec<Cell>)> {
    entries.iter().map(|(k, v)| (*k, (vec![], vec![v.clone()]))).collect()
}

fn param_list(indices: &[i32], style: Style) -> Cell {
    let mut list: Vec<_> = indices.iter().map(|i| (key32(*i), vec![], vec![])).collect();
    list.sort_by(|a, b| a.0.cmp(&b.0));
    build_hashmap(&list, 32, style)
}

struct Corpus {
    cases: Vec<Case>,
    seen_params: std::collections::HashSet<(u32, UInt256)>,
}

impl Corpus {
    fn push(&mut self, case: Case) {
        self.cases.push(case);
    }
    fn param(&mut self, id: String, index: u32, cell: Cell) {
        if self.seen_params.insert((index, cell.repr_hash().clone())) {
            self.push(Case {
                id,
                kind: 'p',
                index: i64::from(index),
                relax: false,
                addr: [0; 32],
                root: Some(cell),
                mparams: None,
            });
        }
    }
    fn config(
        &mut self,
        id: String,
        addr: [u8; 32],
        root: Option<Cell>,
        relax: bool,
        mparams: Option<Cell>,
    ) {
        self.push(Case { id, kind: 'c', index: -1, relax, addr, root, mparams });
    }
    fn variant(
        &mut self,
        name: &str,
        addr: [u8; 32],
        label: &str,
        map: BTreeMap<i32, (Vec<bool>, Vec<Cell>)>,
        relax: bool,
        mparams: Option<Cell>,
    ) {
        let root = config_root(&map, Style::Canonical);
        self.config(format!("{name}-{label}"), addr, root, relax, mparams);
    }
    fn shape(&mut self, id: String, addr: [u8; 32], root: Option<Cell>) {
        self.push(Case { id, kind: 's', index: -1, relax: false, addr, root, mparams: None });
    }
}

fn mutations(cell: &Cell) -> Vec<(String, Cell)> {
    let bits = bits_of(cell);
    let refs = refs_of(cell);
    let mut out = Vec::new();
    let mut add = |name: String, cell: Option<Cell>| {
        if let Some(cell) = cell {
            out.push((name, cell));
        }
    };
    if !bits.is_empty() {
        add("trunc".into(), make_cell(&bits[..bits.len() - 1], &refs));
    }
    for bit in [false, true] {
        let mut b = bits.clone();
        b.push(bit);
        add(format!("append{}", u8::from(bit)), make_cell(&b, &refs));
    }
    let mut more = refs.clone();
    more.push(empty());
    add("ref-extra".into(), make_cell(&bits, &more));
    if !refs.is_empty() {
        add("ref-drop".into(), make_cell(&bits, &refs[..refs.len() - 1]));
    }
    for i in 0..refs.len() {
        for (name, special) in [("pruned", pruned(&refs[i])), ("library", library(&refs[i]))] {
            let mut r = refs.clone();
            r[i] = special;
            add(format!("{name}{i}"), make_cell(&bits, &r));
        }
    }
    let positions: Vec<usize> = if bits.len() <= 320 {
        (0..bits.len()).collect()
    } else {
        (0..64).chain((64..bits.len()).step_by(16)).collect()
    };
    for k in positions {
        let mut b = bits.clone();
        b[k] = !b[k];
        add(format!("flip{k}"), make_cell(&b, &refs));
    }
    out
}

fn add_param_with_mutations(corpus: &mut Corpus, source: &str, index: u32, cell: &Cell) {
    corpus.param(format!("{source}-p{index}"), index, cell.clone());
    corpus.param(format!("{source}-p{index}-pruned"), index, pruned(cell));
    corpus.param(format!("{source}-p{index}-library"), index, library(cell));
    for (name, m) in mutations(cell) {
        corpus.param(format!("{source}-p{index}-{name}"), index, m);
    }
    // First-level children carry the referenced schema types.
    for (i, child) in refs_of(cell).iter().enumerate() {
        let child_bits = bits_of(child);
        for k in (0..child_bits.len()).take(96) {
            let mut b = child_bits.clone();
            b[k] = !b[k];
            if let Some(mutated) = make_cell(&b, &refs_of(child)) {
                let mut r = refs_of(cell);
                r[i] = mutated;
                if let Some(parent) = make_cell(&bits_of(cell), &r) {
                    corpus.param(format!("{source}-p{index}-child{i}-flip{k}"), index, parent);
                }
            }
        }
    }
}

/// Masterchain configurations from state files; proof-wrapped states are
/// unwrapped and configurations with pruned parts are skipped.
fn config_from_state_bytes(bytes: &[u8]) -> Option<ConfigParams> {
    let mut root = read_single_root_boc(bytes).ok()?;
    if root.cell_type() == CellType::MerkleProof {
        root = root.reference(0).ok()?;
    }
    let state = crate::ShardStateUnsplit::construct_from_cell(root).ok()?;
    let config = state.read_custom().ok()??.config().clone();
    config_param_schema::dictionary_leaves(config.root()?.clone(), 32)?;
    Some(config)
}

fn varuint(value: u64, width_len: usize, len: usize) -> Vec<bool> {
    let mut out = uint_bits(len as u64, width_len);
    out.extend(uint_bits(value, len * 8));
    out
}

fn tomis(value: u64) -> Vec<bool> {
    let len = (64 - value.leading_zeros() as usize).div_ceil(8);
    varuint(value, 4, len)
}

fn cat(parts: &[Vec<bool>]) -> Vec<bool> {
    parts.concat()
}

fn u(value: u64, width: usize) -> Vec<bool> {
    uint_bits(value, width)
}

/// Targeted constraint boundaries built field by field.
fn targeted(corpus: &mut Corpus) {
    let mut p = |name: &str, index: u32, bits: Vec<bool>, refs: Vec<Cell>| {
        if let Some(cell) = make_cell(&bits, &refs) {
            corpus.param(format!("t-{name}"), index, cell);
        }
    };
    for (num, denom) in [(0, 1), (1, 1), (2, 1), (0, 0), (5, 10)] {
        p(
            &format!("p5-{num}-{denom}"),
            5,
            cat(&[u(1, 8), vec![false], u(num, 32), u(denom, 32)]),
            vec![],
        );
        p(
            &format!("p5-addr-{num}-{denom}"),
            5,
            cat(&[u(1, 8), vec![true], u(7, 256), u(num, 32), u(denom, 32)]),
            vec![],
        );
    }
    // VarUInteger encodings: every length nibble, minimal and nonminimal.
    for len in [0usize, 1, 3, 8, 15] {
        p(&format!("p6-len{len}"), 6, cat(&[varuint(1.min(len as u64), 4, len), tomis(5)]), vec![]);
    }
    p("p6-nonminimal", 6, cat(&[varuint(1, 4, 3), varuint(0, 4, 2)]), vec![]);
    for (min, max, smin, smax) in
        [(1, 1, 1, 1), (2, 1, 1, 1), (1, 2, 2, 1), (0, 255, 0, u32::MAX as u64)]
    {
        let setup = make_cell(
            &cat(&[u(0x36, 8), u(min, 8), u(max, 8), u(0, 16), u(smin, 32), u(smax, 32), u(0, 64)]),
            &[],
        )
        .unwrap();
        p(&format!("p11-{min}-{max}-{smin}-{smax}"), 11, u(0x91, 8), vec![setup.clone(), setup]);
    }
    for (a, b, c) in [(1, 1, 1), (1, 0, 1), (2, 3, 1), (0, 0, 1), (5, 5, 5), (5, 4, 3)] {
        p(&format!("p16-{a}-{b}-{c}"), 16, cat(&[u(a, 16), u(b, 16), u(c, 16)]), vec![]);
    }
    let limits = |a: u64, b: u64, c: u64| cat(&[u(0xc3, 8), u(a, 32), u(b, 32), u(c, 32)]);
    for (a, b, c) in [(1, 2, 3), (2, 1, 3), (1, 3, 2), (3, 3, 3)] {
        p(
            &format!("p22-{a}-{b}-{c}"),
            22,
            cat(&[u(0x5d, 8), limits(a, b, c), limits(1, 1, 1), limits(1, 1, 1)]),
            vec![],
        );
        p(
            &format!("p23-v2-{a}-{b}-{c}"),
            23,
            cat(&[
                u(0x5e, 8),
                limits(1, 1, 1),
                limits(1, 1, 1),
                limits(1, 1, 1),
                limits(a, b, c),
                u(0xd3, 8),
                u(0, 64),
            ]),
            vec![],
        );
    }
    for flags in [0u64, 1, 64] {
        for life in [0u64, 1] {
            p(
                &format!("p28-c1-{life}"),
                28,
                cat(&[u(0xc1, 8), u(life, 32), u(1, 32), u(1, 32), u(1, 32)]),
                vec![],
            );
            p(
                &format!("p28-c2-{flags}-{life}"),
                28,
                cat(&[
                    u(0xc2, 8),
                    u(flags, 7),
                    vec![true],
                    u(1, 32),
                    u(life, 32),
                    u(1, 32),
                    u(1, 32),
                ]),
                vec![],
            );
            p(&format!("p29-d6-{life}"), 29, cat(&[u(0xd6, 8), u(life, 32), u(0, 224)]), vec![]);
            p(
                &format!("p29-d7-{flags}-{life}"),
                29,
                cat(&[u(0xd7, 8), u(flags, 7), vec![false], u(life, 8), u(0, 224)]),
                vec![],
            );
            p(
                &format!("p29-d8-{flags}-{life}"),
                29,
                cat(&[u(0xd8, 8), u(flags, 7), vec![true], u(life, 8), u(0, 240)]),
                vec![],
            );
            p(
                &format!("p29-d9-{flags}-{life}"),
                29,
                cat(&[u(0xd9, 8), u(flags % 64, 6), vec![true, true], u(life, 8), u(0, 272)]),
                vec![],
            );
            let v1 = make_cell(
                &cat(&[u(0x21, 8), u(flags, 7), vec![true], u(0, 32), u(life, 32), u(0, 64)]),
                &[],
            )
            .unwrap();
            let v2 = make_cell(
                &cat(&[
                    u(0x22, 8),
                    u(flags % 32, 5),
                    u(3, 2),
                    vec![true],
                    u(life, 32),
                    vec![false],
                ]),
                &[],
            )
            .unwrap();
            p(
                &format!("p30-{flags}-{life}"),
                30,
                cat(&[u(0x10, 8), vec![true, true]]),
                vec![v1, v2],
            );
        }
    }
    p("p30-empty", 30, cat(&[u(0x10, 8), vec![false, false]]), vec![]);
    p(
        "p30-bad-tag",
        30,
        cat(&[u(0x10, 8), vec![true, false]]),
        vec![make_cell(&u(0x23, 8), &[]).unwrap()],
    );
    // Validator sets: main bounds and both list forms.
    let validator = cat(&[u(0x53, 8), u(0x8e81278a, 32), u(1, 256), u(10, 64)]);
    let single =
        |key: u64| build_hashmap(&[(u(key, 16), validator.clone(), vec![])], 16, Style::Canonical);
    for (total, main) in [(1, 1), (1, 0), (1, 2), (3, 2)] {
        let list = single(0);
        let mut bits = cat(&[u(0x11, 8), u(0, 64), u(total, 16), u(main, 16)]);
        bits.extend(bits_of(&list));
        p(&format!("p34-11-{total}-{main}"), 34, bits, refs_of(&list));
        p(
            &format!("p34-12-{total}-{main}"),
            34,
            cat(&[u(0x12, 8), u(0, 64), u(total, 16), u(main, 16), u(10, 64), vec![true]]),
            vec![single(0)],
        );
    }
    p(
        "p34-12-empty",
        34,
        cat(&[u(0x12, 8), u(0, 64), u(1, 16), u(1, 16), u(10, 64), vec![false]]),
        vec![],
    );
    // A post-quantum descriptor whose key cell is not visited by the schema.
    let pq = cat(&[u(0xb3, 8), u(9, 256), u(1, 16), u(2, 256), u(10, 64), u(3, 256)]);
    for key in [empty(), make_cell(&[true; 7], &[]).unwrap(), library(&empty()), pruned(&empty())] {
        let list =
            build_hashmap(&[(u(0, 16), pq.clone(), vec![key.clone()])], 16, Style::Canonical);
        let mut bits = cat(&[u(0x11, 8), u(0, 64), u(1, 16), u(1, 16)]);
        bits.extend(bits_of(&list));
        p(&format!("p34-pq-key-{}", key.repr_hash().to_hex_string()), 34, bits, refs_of(&list));
    }
    // Workchain descriptors and formats.
    let wc = |tag: u64,
              monitor: u64,
              min: u64,
              max: u64,
              basic: bool,
              flags: u64,
              format: Vec<bool>,
              tail: Vec<bool>| {
        cat(&[
            u(tag, 8),
            u(0, 32),
            u(monitor, 8),
            u(min, 8),
            u(max, 8),
            vec![basic, true, true],
            u(flags, 13),
            u(0, 544),
            format,
            tail,
        ])
    };
    let basic = cat(&[u(1, 4), u(u32::MAX as u64, 32), u(0, 64)]);
    let ext = |min: u64, max: u64, step: u64, id: u64| {
        cat(&[u(0, 4), u(min, 12), u(max, 12), u(step, 12), u(id, 32)])
    };
    let timings = |tag: u64, depth: u64| cat(&[u(tag, 4), u(0, 128), u(depth, 8)]);
    let descriptors = [
        ("ok", wc(0xa6, 0, 0, 0, true, 0, basic.clone(), vec![])),
        ("flags", wc(0xa6, 0, 0, 0, true, 1, basic.clone(), vec![])),
        ("monitor", wc(0xa6, 1, 0, 0, true, 0, basic.clone(), vec![])),
        ("split", wc(0xa6, 0, 2, 1, true, 0, basic.clone(), vec![])),
        ("max60", wc(0xa6, 0, 0, 60, true, 0, basic.clone(), vec![])),
        ("max61", wc(0xa6, 0, 0, 61, true, 0, basic.clone(), vec![])),
        ("basic-ext", wc(0xa6, 0, 0, 0, true, 0, ext(64, 256, 0, 1), vec![])),
        ("ext-basic", wc(0xa6, 0, 0, 0, false, 0, basic.clone(), vec![])),
        ("ext-ok", wc(0xa6, 0, 0, 0, false, 0, ext(64, 1023, 1023, 1), vec![])),
        ("ext-min63", wc(0xa6, 0, 0, 0, false, 0, ext(63, 256, 0, 1), vec![])),
        ("ext-order", wc(0xa6, 0, 0, 0, false, 0, ext(256, 128, 0, 1), vec![])),
        ("ext-max1024", wc(0xa6, 0, 0, 0, false, 0, ext(64, 1024, 0, 1), vec![])),
        ("ext-step1024", wc(0xa6, 0, 0, 0, false, 0, ext(64, 256, 1024, 1), vec![])),
        ("ext-id0", wc(0xa6, 0, 0, 0, false, 0, ext(64, 256, 0, 0), vec![])),
        ("v2-ok", wc(0xa7, 0, 0, 0, true, 0, basic.clone(), timings(0, 63))),
        ("v2-depth64", wc(0xa7, 0, 0, 0, true, 0, basic.clone(), timings(0, 64))),
        ("v2-timing-tag", wc(0xa7, 0, 0, 0, true, 0, basic.clone(), timings(1, 0))),
    ];
    for (name, descriptor) in descriptors {
        let list = build_hashmap(&[(u(0, 32), descriptor, vec![])], 32, Style::Canonical);
        p(&format!("p12-{name}"), 12, vec![true], vec![list]);
    }
    p("p12-empty", 12, vec![false], vec![]);
    // Size limits with and without the optional field.
    p("p43-v1", 43, cat(&[u(1, 8), u(0, 160)]), vec![]);
    p("p43-v2", 43, cat(&[u(2, 8), u(0, 360)]), vec![]);
    p("p43-v3-none", 43, cat(&[u(3, 8), u(0, 360), vec![false], u(0, 64)]), vec![]);
    p("p43-v3-some", 43, cat(&[u(3, 8), u(0, 360), vec![true], u(9, 32), u(0, 64)]), vec![]);
    p("p43-v4", 43, cat(&[u(4, 8), u(0, 360)]), vec![]);
    // Gas prices with nested flat prefixes.
    let gas = cat(&[u(0xdd, 8), u(0, 384)]);
    p("p20-flat2", 20, cat(&[u(0xd1, 8), u(0, 128), u(0xd1, 8), u(0, 128), gas.clone()]), vec![]);
    p("p21-ext", 21, cat(&[u(0xde, 8), u(0, 448)]), vec![]);
    p("p21-flat-ext", 21, cat(&[u(0xd1, 8), u(0, 128), u(0xde, 8), u(0, 448)]), vec![]);
    p("p21-bad", 21, cat(&[u(0xdf, 8), u(0, 448)]), vec![]);
    // Temporary validator keys with simple and chained signatures.
    let temp_key =
        make_cell(&cat(&[u(3, 4), u(0, 256), u(0x8e81278a, 32), u(0, 256), u(0, 64)]), &[])
            .unwrap();
    let simple = cat(&[u(5, 4), u(0, 512)]);
    let cert =
        make_cell(&cat(&[u(4, 4), u(0x8e81278a, 32), u(0, 256), u(0, 64), simple.clone()]), &[])
            .unwrap();
    let signed = |sig: Vec<bool>, extra: Vec<Cell>| {
        let mut refs = vec![temp_key.clone()];
        refs.extend(extra);
        (cat(&[u(4, 4), sig]), refs)
    };
    for (name, (bits, refs)) in [
        ("simple", signed(simple.clone(), vec![])),
        ("chained", signed(cat(&[u(15, 4), simple.clone()]), vec![cert.clone()])),
        ("bad-sig", signed(cat(&[u(6, 4), u(0, 512)]), vec![])),
        (
            "bad-cert",
            signed(cat(&[u(15, 4), simple.clone()]), vec![make_cell(&u(3, 4), &[]).unwrap()]),
        ),
    ] {
        let list = build_hashmap(&[(u(5, 256), bits, refs)], 256, Style::Canonical);
        p(&format!("p39-{name}"), 39, vec![true], vec![list]);
    }
    // Jetton bridge versions, also under parameter 83.
    let oracles = vec![false];
    let prices =
        make_cell(&cat(&[tomis(1), tomis(2), tomis(0), tomis(4), tomis(5), tomis(6)]), &[])
            .unwrap();
    for index in [79, 83] {
        p(
            &format!("p{index}-v0"),
            index,
            cat(&[u(0, 8), u(1, 512), oracles.clone(), u(0, 8), tomis(9)]),
            vec![],
        );
        p(
            &format!("p{index}-v1"),
            index,
            cat(&[u(1, 8), u(1, 512), oracles.clone(), u(0, 8), u(1, 256)]),
            vec![prices.clone()],
        );
        p(
            &format!("p{index}-v2"),
            index,
            cat(&[u(2, 8), u(1, 512), oracles.clone(), u(0, 8), tomis(9)]),
            vec![],
        );
    }
    // Controller policy and the parameter outside the schema.
    for (name, count) in [("empty", 0usize), ("one", 1), ("three", 3)] {
        if count == 0 {
            p(&format!("p47-{name}"), 47, vec![false], vec![]);
            continue;
        }
        let entries: Vec<_> =
            (0..count).map(|k| (u(k as u64 * 7 + 1, 256), vec![], vec![])).collect();
        p(
            &format!("p47-{name}"),
            47,
            vec![true],
            vec![build_hashmap(&entries, 256, Style::Canonical)],
        );
    }
    p(
        "p47-leaf-bit",
        47,
        vec![true],
        vec![build_hashmap(&[(u(1, 256), vec![true], vec![])], 256, Style::Canonical)],
    );
    let accelerated = AcceleratedConsensusConfig::default().serialize().unwrap();
    for index in [63, 26, 27, 38, 41, 42, 46, 49, 70, 74, 80, 84, 100, 1000, 0x7fff_ffff] {
        p(&format!("unknown{index}"), index, vec![], vec![]);
        p(&format!("unknown{index}-acc"), index, bits_of(&accelerated), vec![]);
    }
    // Noncanonical labels inside a parameter.
    for style in [Style::Short, Style::Long] {
        let list = param_list(&[18, 20, 21, 22], style);
        p(&format!("p9-style{}", style as u8), 9, bits_of(&list), refs_of(&list));
    }
}

/// Reference-visit budget boundaries.
fn budgets(corpus: &mut Corpus) {
    let set = |count: usize| -> Vec<(Vec<bool>, Vec<bool>, Vec<Cell>)> {
        (0..count).map(|k| (u(k as u64 * 2_654_435_761, 256), vec![], vec![])).collect()
    };
    // Parameter 31: 2 * count visits.
    for count in [511usize, 512, 513] {
        let list = build_hashmap(&set(count), 256, Style::Canonical);
        corpus.param(format!("budget-p31-{count}"), 31, make_cell(&[true], &[list]).unwrap());
    }
    // Parameter 39: 1 + (2k - 1) + k + chained visits.
    let temp_key =
        make_cell(&cat(&[u(3, 4), u(0, 256), u(0x8e81278a, 32), u(0, 256), u(0, 64)]), &[])
            .unwrap();
    let simple = cat(&[u(5, 4), u(0, 512)]);
    let cert =
        make_cell(&cat(&[u(4, 4), u(0x8e81278a, 32), u(0, 256), u(0, 64), simple.clone()]), &[])
            .unwrap();
    for chained in [0usize, 1, 2] {
        let entries: Vec<_> = (0..341usize)
            .map(|k| {
                let (sig, refs) = if k < chained {
                    (cat(&[u(15, 4), simple.clone()]), vec![temp_key.clone(), cert.clone()])
                } else {
                    (simple.clone(), vec![temp_key.clone()])
                };
                (u(k as u64 * 2_654_435_761, 256), cat(&[u(4, 4), sig]), refs)
            })
            .collect();
        let mut sorted = entries;
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        let list = build_hashmap(&sorted, 256, Style::Canonical);
        corpus.param(
            format!("budget-p39-chained{chained}"),
            39,
            make_cell(&[true], &[list]).unwrap(),
        );
    }
    // Parameter 34: 2 * count visits; the key cells are not visited.
    let key = make_cell(&[true; 9], &[]).unwrap();
    for count in [511usize, 512, 513] {
        let entries: Vec<_> = (0..count)
            .map(|k| {
                let pq =
                    cat(&[u(0xb3, 8), u(k as u64, 256), u(1, 16), u(2, 256), u(10, 64), u(3, 256)]);
                (u(k as u64, 16), pq, vec![key.clone()])
            })
            .collect();
        let list = build_hashmap(&entries, 16, Style::Canonical);
        let mut bits = cat(&[u(0x11, 8), u(0, 64), u(count as u64, 16), u(1, 16)]);
        bits.extend(bits_of(&list));
        corpus.param(format!("budget-p34-{count}"), 34, make_cell(&bits, &refs_of(&list)).unwrap());
    }
    // ConfigParams shape: 2 * count - 1 visits.
    for count in [4999usize, 5000, 5001] {
        let entries: BTreeMap<i32, (Vec<bool>, Vec<Cell>)> =
            (0..count).map(|k| (k as i32 * 7 - 9000, (vec![], vec![empty()]))).collect();
        corpus.shape(
            format!("budget-shape-{count}"),
            [0; 32],
            config_root(&entries, Style::Canonical),
        );
    }
}

fn whole_configs(corpus: &mut Corpus, name: &str, config: &ConfigParams) {
    let addr: [u8; 32] = config.config_addr.clone().get_next_hash().unwrap().inner();
    let entries = raw_entries(config);
    let original = config.root().cloned();
    let own9 = config.mandatory_params_root().unwrap();
    for relax in [false, true] {
        corpus.config(
            format!("{name}-original-r{}", u8::from(relax)),
            addr,
            original.clone(),
            relax,
            None,
        );
        corpus.config(
            format!("{name}-wrong-addr-r{}", u8::from(relax)),
            [0x5a; 32],
            original.clone(),
            relax,
            None,
        );
    }
    corpus.config(format!("{name}-own-mparams"), addr, original.clone(), false, own9);
    corpus.shape(format!("{name}-shape"), addr, original.clone());
    corpus.shape(format!("{name}-shape-none"), addr, None);
    corpus.config(format!("{name}-root-none"), addr, None, false, None);
    let base = values(&entries);
    for index in entries.keys() {
        let mut map = base.clone();
        map.remove(index);
        corpus.variant(name, addr, &format!("remove{index}"), map.clone(), false, None);
        corpus.variant(name, addr, &format!("remove{index}-relax"), map, true, None);
    }
    for index in [
        26,
        27,
        38,
        41,
        42,
        46,
        47,
        49,
        63,
        70,
        74,
        80,
        83,
        84,
        100,
        1000,
        i32::MAX,
        -1,
        -999,
        i32::MIN,
    ] {
        for (label, value) in [
            ("empty", (vec![], vec![empty()])),
            ("bits", (vec![true], vec![empty()])),
            ("norefs", (vec![], vec![])),
            ("tworefs", (vec![], vec![empty(), empty()])),
            ("pruned", (vec![], vec![pruned(&empty())])),
            (
                "accelerated",
                (vec![], vec![AcceleratedConsensusConfig::default().serialize().unwrap()]),
            ),
        ] {
            let mut map = base.clone();
            map.insert(index, value);
            corpus.variant(name, addr, &format!("add{index}-{label}"), map, false, None);
        }
    }
    for index in [0, 15, 18, 34] {
        if let Some(cell) = entries.get(&index) {
            for (label, value) in [
                ("bits", (vec![true], vec![cell.clone()])),
                ("norefs", (vec![], vec![])),
                ("tworefs", (vec![], vec![cell.clone(), cell.clone()])),
                ("pruned", (vec![], vec![pruned(cell)])),
                ("library", (vec![], vec![library(cell)])),
            ] {
                let mut map = base.clone();
                map.insert(index, value);
                corpus.variant(name, addr, &format!("shape{index}-{label}"), map, false, None);
            }
        }
    }
    // Parameter 0 variants under both address modes.
    let p0 = entries
        .get(&0)
        .map(bits_of)
        .unwrap_or_else(|| addr.iter().flat_map(|b| u(u64::from(*b), 8)).collect());
    for relax in [false, true] {
        let r = u8::from(relax);
        for (label, cell) in [
            ("bits255", make_cell(&p0[..255], &[])),
            ("bits257", make_cell(&cat(&[p0.clone(), vec![false]]), &[])),
            ("ref", make_cell(&p0, &[empty()])),
            ("other", make_cell(&vec![true; 256], &[])),
            ("same", make_cell(&p0, &[])),
        ] {
            let mut map = base.clone();
            map.insert(0, (vec![], vec![cell.unwrap()]));
            corpus.variant(name, addr, &format!("p0-{label}-r{r}"), map, relax, None);
        }
    }
    // Mandatory lists: parameter 9 and the previous list.
    let present: Vec<i32> = entries.keys().copied().collect();
    let some_present = present.iter().copied().take(3).collect::<Vec<_>>();
    for (label, list) in [
        ("p9-missing77", param_list(&[18, 77], Style::Canonical)),
        ("p9-present", param_list(&some_present, Style::Canonical)),
        ("p9-negative-missing", param_list(&[-5], Style::Canonical)),
        ("p9-long-labels", param_list(&some_present, Style::Long)),
    ] {
        let mut map = base.clone();
        map.insert(9, (vec![], vec![list]));
        corpus.variant(name, addr, &label.to_string(), map, false, None);
    }
    let mut negative = base.clone();
    negative.insert(-5, (vec![], vec![empty()]));
    corpus.variant(
        name,
        addr,
        "p9-negative-present",
        {
            let mut m = negative.clone();
            m.insert(9, (vec![], vec![param_list(&[-5, 18], Style::Canonical)]));
            m
        },
        false,
        None,
    );
    for (label, list) in [
        ("old-present", Some(param_list(&some_present, Style::Canonical))),
        ("old-missing", Some(param_list(&[77], Style::Canonical))),
        ("old-short-labels", Some(param_list(&some_present, Style::Short))),
        (
            "old-leaf-bit",
            Some(build_hashmap(&[(key32(18), vec![true], vec![])], 32, Style::Canonical)),
        ),
        (
            "old-leaf-ref",
            Some(build_hashmap(&[(key32(18), vec![], vec![empty()])], 32, Style::Canonical)),
        ),
        ("old-pruned", Some(pruned(&param_list(&[18], Style::Canonical)))),
        ("old-empty-cell", Some(empty())),
    ] {
        corpus.config(format!("{name}-{label}"), addr, original.clone(), false, list);
    }
    // The whole dictionary re-encoded with noncanonical labels.
    for style in [Style::Short, Style::Long] {
        let root = config_root(&base, style);
        corpus.config(format!("{name}-dict-style{}", style as u8), addr, root.clone(), false, None);
        corpus.shape(format!("{name}-shape-style{}", style as u8), addr, root);
    }
    // Dictionary node shape errors.
    if let Some(root) = &original {
        let bits = bits_of(root);
        let refs = refs_of(root);
        let mut more = bits.clone();
        more.push(false);
        let mut extra = refs.clone();
        extra.push(empty());
        for (label, cell) in [
            ("root-extra-bit", make_cell(&more, &refs)),
            ("root-extra-ref", make_cell(&bits, &extra)),
            ("root-one-ref", make_cell(&bits, &refs[..1.min(refs.len())])),
            ("root-pruned", Some(pruned(root))),
            ("root-library", Some(library(root))),
        ] {
            if let Some(cell) = cell {
                corpus.config(format!("{name}-{label}"), addr, Some(cell.clone()), true, None);
                corpus.shape(format!("{name}-shape-{label}"), addr, Some(cell));
            }
        }
        if refs.len() == 2 {
            for i in 0..2 {
                let mut r = refs.clone();
                r[i] = pruned(&refs[i]);
                corpus.config(
                    format!("{name}-fork{i}-pruned"),
                    addr,
                    make_cell(&bits, &r),
                    true,
                    None,
                );
            }
        }
    }
    // A parameter that is structurally valid while a typed decoder is stricter.
    let mut map = base.clone();
    let pq = cat(&[u(0xb3, 8), u(9, 256), u(1, 16), u(2, 256), u(10, 64), u(3, 256)]);
    let list = build_hashmap(
        &[(u(0, 16), pq, vec![make_cell(&[true; 5], &[]).unwrap()])],
        16,
        Style::Canonical,
    );
    let mut bits = cat(&[u(0x11, 8), u(0, 64), u(1, 16), u(1, 16)]);
    bits.extend(bits_of(&list));
    map.insert(34, (vec![], vec![make_cell(&bits, &refs_of(&list)).unwrap()]));
    corpus.variant(name, addr, "p34-pq-garbage-key", map, false, None);
    // Legacy configuration: no AUTH, no parameter 9 and optionally no parameter 0.
    let mut legacy = base.clone();
    legacy.remove(&48);
    legacy.remove(&9);
    legacy.insert(
        8,
        (vec![], vec![make_cell(&cat(&[u(0xc4, 8), u(4, 32), u(0, 64)]), &[]).unwrap()]),
    );
    corpus.variant(name, addr, "legacy-no-p9", legacy.clone(), false, None);
    legacy.remove(&0);
    corpus.variant(name, addr, "legacy-no-p0", legacy.clone(), false, None);
    corpus.variant(name, addr, "legacy-no-p0-relax", legacy, true, None);
}

fn sources() -> Vec<(String, ConfigParams)> {
    let mut out = Vec::new();
    let data = concat!(env!("CARGO_MANIFEST_DIR"), "/src/tests/data");
    let cell = read_single_root_boc(std::fs::read(format!("{data}/config.boc")).unwrap()).unwrap();
    let config = ConfigParams::with_address_and_params(AccountId::from([1; 32]), Some(cell));
    let mut real = config.clone();
    if let Some(ConfigParamEnum::ConfigParam0(p0)) = config.config(0).unwrap() {
        real.config_addr = p0.config_addr;
    }
    out.push(("legacy-real".to_string(), real));
    let base =
        read_single_root_boc(std::fs::read(format!("{data}/workchain-config-base.boc")).unwrap())
            .unwrap();
    out.push(("workchain-base".to_string(), ConfigParams::with_root(base).unwrap()));
    if let Ok(dir) = std::env::var("RTOS_CFG_CORPUS_STATES") {
        let mut paths: Vec<_> =
            std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).collect();
        paths.sort();
        let mut seen = std::collections::HashSet::new();
        for path in paths {
            let bytes = std::fs::read(&path).unwrap();
            if let Some(config) = config_from_state_bytes(&bytes) {
                if config.root().is_some()
                    && seen.insert(config.root().unwrap().repr_hash().clone())
                {
                    let name = path.file_name().unwrap().to_string_lossy().to_string();
                    out.push((format!("state-{name}"), config));
                }
            }
        }
    }
    // A configuration written by the typed serializers of this crate.
    let mut typed = ConfigParams::default();
    for param in [
        ConfigParamEnum::ConfigParam0(get_config_param0()),
        ConfigParamEnum::ConfigParam1(get_config_param1()),
        ConfigParamEnum::ConfigParam7(get_config_param7()),
        ConfigParamEnum::ConfigParam9(get_config_param9()),
        ConfigParamEnum::ConfigParam10(get_config_param10()),
        ConfigParamEnum::ConfigParam11(get_config_param11()),
        ConfigParamEnum::ConfigParam12(get_config_param12()),
        ConfigParamEnum::ConfigParam14(get_config_param14()),
        ConfigParamEnum::ConfigParam15(get_config_param15()),
        ConfigParamEnum::ConfigParam16(get_config_param16()),
        ConfigParamEnum::ConfigParam17(get_config_param17()),
        ConfigParamEnum::ConfigParam18(get_config_param18()),
        ConfigParamEnum::ConfigParam20(get_gas_limit_prices()),
        ConfigParamEnum::ConfigParam21(get_gas_limit_prices()),
        ConfigParamEnum::ConfigParam22(get_block_limits(1, false)),
        ConfigParamEnum::ConfigParam23(get_block_limits(2, true)),
        ConfigParamEnum::ConfigParam24(get_msg_forward_prices()),
        ConfigParamEnum::ConfigParam25(get_msg_forward_prices()),
        ConfigParamEnum::ConfigParam28(get_cat_chain_config()),
        ConfigParamEnum::ConfigParam29(get_config_param29()),
        ConfigParamEnum::ConfigParam30(NewConsensusConfigAll::default()),
        ConfigParamEnum::ConfigParam31(get_config_param31()),
        ConfigParamEnum::ConfigParam34(ConfigParam34 { cur_validators: get_validator_set() }),
        ConfigParamEnum::ConfigParam39(get_config_param_39()),
        ConfigParamEnum::ConfigParam40(get_config_param_40()),
        ConfigParamEnum::ConfigParam43(SizeLimitsConfig::default()),
        ConfigParamEnum::ConfigParam44(get_suspended_address_list()),
        ConfigParamEnum::ConfigParam45(get_precompiled_contracts_list()),
        ConfigParamEnum::ConfigParam47(ValidatorControllerPolicy::default()),
        ConfigParamEnum::ConfigParam71(OracleBridgeParams::default()),
        ConfigParamEnum::ConfigParam79(JettonBridgeParams::default()),
        ConfigParamEnum::ConfigParam83(JettonBridgeParams::default()),
    ] {
        typed.set_config(param).unwrap();
    }
    if let Some(ConfigParamEnum::ConfigParam0(p0)) = typed.config(0).unwrap() {
        typed.config_addr = p0.config_addr;
    }
    out.push(("typed".to_string(), typed));
    out
}

#[test]
#[ignore]
fn generate_config_param_schema_corpus() {
    let out = std::env::var("RTOS_CFG_CORPUS_OUT").expect("RTOS_CFG_CORPUS_OUT");
    let mut corpus = Corpus { cases: Vec::new(), seen_params: Default::default() };
    for (name, config) in sources() {
        for (index, cell) in raw_entries(&config) {
            if let Ok(index) = u32::try_from(index) {
                add_param_with_mutations(&mut corpus, &name, index, &cell);
                for other in config_param_schema::SCHEMA_CONFIG_PARAMS {
                    corpus.param(format!("{name}-p{index}-as{other}"), other, cell.clone());
                }
            }
        }
        whole_configs(&mut corpus, &name, &config);
    }
    targeted(&mut corpus);
    budgets(&mut corpus);
    let mut roots = Vec::new();
    let mut root_index: HashMap<UInt256, usize> = HashMap::new();
    let mut index_of = |cell: &Option<Cell>| -> String {
        match cell {
            None => "-".to_string(),
            Some(cell) => {
                let next = roots.len();
                let i = *root_index.entry(cell.repr_hash().clone()).or_insert(next);
                if i == next {
                    roots.push(storable(cell));
                }
                i.to_string()
            }
        }
    };
    let mut ids = std::collections::HashSet::new();
    let mut tsv = String::new();
    for case in &corpus.cases {
        assert!(ids.insert(case.id.clone()), "duplicate id {}", case.id);
        let root = index_of(&case.root);
        let mparams = index_of(&case.mparams);
        tsv.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            case.id,
            case.kind,
            case.index,
            u8::from(case.relax),
            hex::encode(case.addr),
            root,
            mparams,
            fingerprint(case)
        ));
    }
    std::fs::write(format!("{out}/corpus.boc"), crate::write_boc(&index_tree(roots)).unwrap())
        .unwrap();
    std::fs::write(format!("{out}/cases.tsv"), tsv).unwrap();
    println!("generated {} cases", corpus.cases.len());
}

#[test]
#[ignore]
fn pack_config_param_schema_corpus() {
    let out = std::env::var("RTOS_CFG_CORPUS_OUT").expect("RTOS_CFG_CORPUS_OUT");
    let boc = std::fs::read(format!("{out}/corpus.boc")).unwrap();
    std::fs::write(CORPUS_BOC, lz4::block::compress(&boc, None, true).unwrap()).unwrap();
    let tsv = std::fs::read(format!("{out}/expected.tsv")).unwrap();
    std::fs::write(CORPUS_TSV, lz4::block::compress(&tsv, None, true).unwrap()).unwrap();
}
