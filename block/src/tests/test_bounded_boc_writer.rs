// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{config_read_budget::ConfigReadBudget, BuilderData, IBitstring};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Budget {
    work: AtomicUsize,
    bytes: AtomicUsize,
    max_work: usize,
    max_bytes: usize,
}
impl Budget {
    fn new(max_work: usize, max_bytes: usize) -> Self {
        Self { work: AtomicUsize::new(0), bytes: AtomicUsize::new(0), max_work, max_bytes }
    }
    fn unlimited() -> Self {
        Self::new(usize::MAX, usize::MAX)
    }
}
impl ConfigReadBudget for Budget {
    fn step(&self) -> Result<()> {
        if self.work.fetch_add(1, Ordering::Relaxed) >= self.max_work {
            fail!("work limit");
        }
        Ok(())
    }
    fn workspace(&self, bytes: usize) -> Result<()> {
        if self.bytes.fetch_add(bytes, Ordering::Relaxed).saturating_add(bytes) > self.max_bytes {
            fail!("workspace limit");
        }
        Ok(())
    }
}
fn shared_tree() -> Cell {
    let mut child = Cell::default();
    // Repeated references must preserve cache bits and original weight sorting.
    for i in 0..96 {
        let mut builder = BuilderData::new();
        builder.append_u32(i).unwrap();
        builder.checked_append_reference(child.clone()).unwrap();
        builder.checked_append_reference(child).unwrap();
        child = builder.into_cell().unwrap();
    }
    child
}
#[test]
fn bounded_boc_writer_flags_and_repeated_roots_preserve_exact_bytes() {
    let root = shared_tree();
    for flags in [BocFlags::None, BocFlags::Index, BocFlags::Crc32, BocFlags::all()] {
        let roots = [root.clone(), root.reference(0).unwrap(), root.clone()];
        let ordinary = BocWriter::with_flags(roots.clone(), flags).unwrap().write_to_vec().unwrap();
        let budget = Budget::unlimited();
        let bounded =
            BocWriter::with_flags_bounded(roots, flags, &budget).unwrap().write_to_vec().unwrap();
        assert_eq!(bounded, ordinary);
        assert_eq!(
            read_single_root_boc(
                &BocWriter::with_root_bounded(&root, &Budget::unlimited())
                    .unwrap()
                    .write_to_vec()
                    .unwrap()
            )
            .unwrap(),
            root
        );
    }
}
#[test]
fn bounded_boc_writer_exact_budget_and_cumulative_refusal() {
    let root = shared_tree();
    let measure = Budget::unlimited();
    let expected = BocWriter::with_flags_bounded([root.clone()], BocFlags::all(), &measure)
        .unwrap()
        .write_to_vec()
        .unwrap();
    let work = measure.work.load(Ordering::Relaxed);
    let bytes = measure.bytes.load(Ordering::Relaxed);
    let exact = Budget::new(work, bytes);
    assert_eq!(
        BocWriter::with_flags_bounded([root.clone()], BocFlags::all(), &exact)
            .unwrap()
            .write_to_vec()
            .unwrap(),
        expected
    );
    assert!(BocWriter::with_root_bounded(&root, &exact).is_err());
    let short_work = Budget::new(work - 1, bytes);
    assert!(BocWriter::with_flags_bounded([root.clone()], BocFlags::all(), &short_work)
        .unwrap()
        .write_to_vec()
        .is_err());
    let short_bytes = Budget::new(work, bytes - 1);
    assert!(BocWriter::with_flags_bounded([root], BocFlags::all(), &short_bytes)
        .unwrap()
        .write_to_vec()
        .is_err());
}
#[test]
fn bounded_boc_writer_refuses_before_table_and_destination_mutation() {
    let root = shared_tree();
    let zero = Budget::new(usize::MAX, 0);
    assert!(BocWriter::with_root_bounded(&root, &zero).is_err());
    let measure = Budget::unlimited();
    let _ = BocWriter::with_root_bounded(&root, &measure).unwrap();
    let only_construct = Budget::new(measure.work.load(Ordering::Relaxed), usize::MAX);
    let writer = BocWriter::with_root_bounded(&root, &only_construct).unwrap();
    let mut destination = vec![0xaa];
    assert!(writer.write(&mut destination).is_err());
    assert_eq!(destination, [0xaa]);
}
