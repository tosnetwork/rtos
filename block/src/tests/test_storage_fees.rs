/*
 * Copyright (C) 2026-2026 TOS Blockchain Teams.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */

//! `accrued_storage_fee` against the node. The vector file's expected values are
//! checked against the node's own `StoragePrices::compute_storage_fees` by
//! `test-storage-fee-vectors` (crypto/block), so agreeing with the file is
//! agreeing with the node.

use super::*;

pub(crate) const VECTORS: &str = concat!(
    include_str!("../../tests/data/storage-fee-vectors.tsv"),
    include_str!("../../tests/data/storage-fee-synthetic.tsv")
);

pub(crate) struct Row {
    pub name: String,
    pub now: u32,
    pub last_paid: u32,
    pub cells: u64,
    pub bits: u64,
    pub special: bool,
    pub masterchain: bool,
    pub periods: Vec<StoragePrices>,
    pub expected: BigInt,
}

fn flag(text: &str) -> bool {
    match text {
        "0" => false,
        "1" => true,
        other => panic!("not a 0/1 flag: {other:?}"),
    }
}

fn periods(text: &str) -> Vec<StoragePrices> {
    if text == "-" {
        return Vec::new();
    }
    text.split(',')
        .map(|period| {
            let fields: Vec<&str> = period.split(':').collect();
            assert_eq!(fields.len(), 5, "a period needs five fields: {period:?}");
            StoragePrices {
                utime_since: fields[0].parse().expect("utime_since"),
                bit_price_ps: fields[1].parse().expect("bit_price_ps"),
                cell_price_ps: fields[2].parse().expect("cell_price_ps"),
                mc_bit_price_ps: fields[3].parse().expect("mc_bit_price_ps"),
                mc_cell_price_ps: fields[4].parse().expect("mc_cell_price_ps"),
            }
        })
        .collect()
}

pub(crate) fn rows(text: &str) -> Vec<Row> {
    let rows: Vec<Row> = text
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields.len(), 9, "a row needs nine fields: {line:?}");
            Row {
                name: fields[0].to_string(),
                now: fields[1].parse().expect("now"),
                last_paid: fields[2].parse().expect("last_paid"),
                cells: fields[3].parse().expect("cells"),
                bits: fields[4].parse().expect("bits"),
                special: flag(fields[5]),
                masterchain: flag(fields[6]),
                periods: periods(fields[7]),
                expected: fields[8].parse().expect("expected"),
            }
        })
        .collect();
    assert!(!rows.is_empty(), "the vector file has no rows");
    rows
}

#[test]
fn every_vector_row_matches_the_node() {
    let rows = rows(VECTORS);
    assert_eq!(rows.len(), 291);
    let mut wrong = Vec::new();
    for row in &rows {
        let fee = accrued_storage_fee(
            &row.periods,
            row.cells,
            row.bits,
            row.last_paid,
            row.now,
            row.special,
            row.masterchain,
        )
        .unwrap_or_else(|e| panic!("{}: {e}", row.name));
        if fee != row.expected {
            wrong.push(format!("{}: computed {fee}, the node charges {}", row.name, row.expected));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} rows disagree:\n{}",
        wrong.len(),
        rows.len(),
        wrong.join("\n")
    );
}

fn period(since: u32, cell: u64, bit: u64, mc_cell: u64, mc_bit: u64) -> StoragePrices {
    StoragePrices {
        utime_since: since,
        bit_price_ps: bit,
        cell_price_ps: cell,
        mc_bit_price_ps: mc_bit,
        mc_cell_price_ps: mc_cell,
    }
}

/// A special account is never charged, even with storage that would be.
#[test]
fn a_special_account_accrues_nothing() {
    let prices = [period(0, 500, 1, 500_000, 1_000)];
    let charged = accrued_storage_fee(&prices, 10, 1_000, 100, 1_000, false, true).unwrap();
    assert!(charged > BigInt::default(), "the same storage is chargeable: {charged}");
    let special = accrued_storage_fee(&prices, 10, 1_000, 100, 1_000, true, true).unwrap();
    assert_eq!(special, BigInt::default());
}

/// Unsigned maximum counts/prices become signed -1 in the node's partial
/// payment arithmetic. Values are checked against actual CPP fee controls.
#[test]
fn the_largest_inputs_do_not_overflow() {
    let max = u64::MAX;
    let prices = [period(0, max, max, max, max)];
    let one_second = accrued_storage_fee(&prices, max, max, 1, 2, false, true).unwrap();
    assert_eq!(one_second, BigInt::from(1));

    let whole_range = accrued_storage_fee(&prices, max, max, 1, u32::MAX, false, false).unwrap();
    assert_eq!(whole_range, BigInt::from(131072));
}

fn refused(prices: &[StoragePrices], last_paid: u32, now: u32) -> String {
    match accrued_storage_fee(prices, 1, 1, last_paid, now, false, true) {
        Ok(fee) => panic!("an unordered price table was accepted: fee {fee}"),
        Err(e) => {
            let text = e.to_string();
            assert!(text.contains("strictly increasing"), "refused for its order, not {text}");
            text
        }
    }
}

/// A table the node would not load is refused, including in the cases that would
/// otherwise return zero before looking at the periods.
#[test]
fn an_unordered_price_table_is_refused() {
    let duplicate = [period(0, 1, 1, 1, 1), period(100, 1, 1, 1, 1), period(100, 2, 2, 2, 2)];
    let descending = [period(0, 1, 1, 1, 1), period(200, 1, 1, 1, 1), period(100, 2, 2, 2, 2)];
    for prices in [&duplicate[..], &descending[..]] {
        refused(prices, 10, 300);
        // now not after last_paid
        refused(prices, 300, 300);
        refused(prices, 300, 10);
        // never paid
        refused(prices, 0, 300);
    }
    // now not after the first period's start
    let starts_late = [period(500, 1, 1, 1, 1), period(200, 1, 1, 1, 1)];
    refused(&starts_late, 10, 300);
    // special accounts too
    assert!(accrued_storage_fee(&duplicate, 1, 1, 10, 300, true, true).is_err());
    // and an ordered table with the same periods is accepted
    let ordered = [period(0, 1, 1, 1, 1), period(100, 1, 1, 1, 1), period(200, 2, 2, 2, 2)];
    assert!(accrued_storage_fee(&ordered, 1, 1, 10, 300, false, true).is_ok());
}

#[test]
fn storage_price_keys_are_activation_times() {
    let mut config = ConfigParam18::default();
    let later = period(u32::MAX, 50, 1, 500, 10);
    let earlier = period(200, 5, 1, 50, 10);
    config.insert(&later).unwrap();
    config.insert(&earlier).unwrap();
    assert_eq!(config.get(u32::MAX).unwrap(), later);
    assert_eq!(config.prices().unwrap(), vec![earlier.clone(), later.clone()]);
    config.insert(&later).unwrap();
    assert_eq!(config.map.len().unwrap(), 2);
    config.map.set(&0, &earlier).unwrap();
    let decoded = ConfigParam18::construct_from_cell(config.serialize().unwrap()).unwrap();
    assert!(decoded.prices().is_err());
}

#[test]
fn partial_storage_products_do_not_overflow() {
    let max = u64::MAX;
    let price = period(0, max, max, max, max);
    // The VM utility keeps counts unsigned, but price and delta are signed
    // scalar operands. Two -1 factors leave each unsigned count unchanged.
    let expected = BigInt::from(max) * 2;
    assert_eq!(price.calc_storage_fee_part(max, max, max, false), expected);
    assert_eq!(price.calc_storage_fee_part(1, 1, 65536, false), BigInt::from(-131072));
}

#[test]
fn storage_key_admission_matches_cpp_matrix() {
    for key in [0, 200, u32::MAX] {
        for since in [0, 200, u32::MAX] {
            let mut table = ConfigParam18::default();
            table.map.set(&key, &period(since, 2, 1, 4, 3)).unwrap();
            let decoded = ConfigParam18::construct_from_cell(table.serialize().unwrap()).unwrap();
            assert_eq!(decoded.prices().is_ok(), key == since, "key={key} since={since}");
        }
    }
}
