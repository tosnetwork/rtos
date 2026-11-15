// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-only
//! Consensus weight arithmetic. Membership and signature verification remain the
//! caller's responsibility; reaching a numeric threshold alone authenticates nothing.

use crate::{fail, Result};

pub const MAX_TOTAL_VALIDATOR_WEIGHT: u64 = u64::MAX / 3;

/// Smallest integral weight at least two thirds of the total, without overflow.
pub const fn quorum_threshold(total: u64) -> u64 {
    ((2 * total as u128 + 2) / 3) as u64
}

/// Numeric predicate on explicit weights, matching TOS `tos::has_quorum`.
/// This does not admit a validator set or authenticate its signed weight.
pub const fn quorum_weight_reached(signed: u64, total: u64) -> bool {
    signed >= quorum_threshold(total)
}

/// An empty or over-counted voting set cannot establish a quorum.
pub const fn has_quorum(signed: u64, total: u64) -> bool {
    total != 0 && signed <= total && quorum_weight_reached(signed, total)
}

/// Add one admitted validator's positive weight within the protocol cap.
pub fn checked_add_validator_weight(accumulated: u64, weight: u64) -> Result<u64> {
    if weight == 0 {
        fail!("validator weight must be positive");
    }
    match accumulated.checked_add(weight) {
        Some(total) if total <= MAX_TOTAL_VALIDATOR_WEIGHT => Ok(total),
        _ => fail!("total validator weight exceeds the protocol cap"),
    }
}

pub fn checked_validator_weight_sum(weights: impl IntoIterator<Item = u64>) -> Result<u64> {
    weights.into_iter().try_fold(0, checked_add_validator_weight)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thresholds_and_full_width_boundaries() {
        for (total, expected) in [
            (0, 0),
            (1, 1),
            (2, 2),
            (3, 2),
            (4, 3),
            (6, 4),
            (9, 6),
            (99, 66),
            (u64::MAX, 12297829382473034410),
        ] {
            assert_eq!(quorum_threshold(total), expected);
            if total != 0 {
                assert!(has_quorum(expected, total));
                assert!(!has_quorum(expected - 1, total));
            }
        }
        assert!(!has_quorum(0, 0));
        assert!(!has_quorum(4, 3));
        // The raw predicate is distinct from the node's membership guards.
        assert!(quorum_weight_reached(0, 0));
        assert!(quorum_weight_reached(4, 3));
        for total in [0, 1, 3, MAX_TOTAL_VALIDATOR_WEIGHT, u64::MAX] {
            for signed in [0, 1, total, u64::MAX] {
                assert_eq!(
                    quorum_weight_reached(signed, total),
                    u128::from(signed) * 3 >= u128::from(total) * 2
                );
                assert_eq!(
                    has_quorum(signed, total),
                    total != 0 && signed <= total && quorum_weight_reached(signed, total)
                );
            }
        }
        for total in (1..=1000).chain([MAX_TOTAL_VALIDATOR_WEIGHT, u64::MAX - 1]) {
            let threshold = quorum_threshold(total);
            assert!(u128::from(threshold) * 3 >= u128::from(total) * 2);
            assert!(u128::from(threshold - 1) * 3 < u128::from(total) * 2);
        }
    }

    #[test]
    fn threshold_matches_pinned_reference_vectors() {
        let fixture = include_str!("../tests/data/quorum-vectors.txt");
        let mut count = 0;
        for line in fixture.lines() {
            let (total, threshold) = line.split_once(' ').unwrap();
            assert_eq!(quorum_threshold(total.parse().unwrap()), threshold.parse::<u64>().unwrap());
            count += 1;
        }
        assert_eq!(count, 16);
    }

    #[test]
    fn validator_weights_are_positive_and_bounded() {
        let cap = MAX_TOTAL_VALIDATOR_WEIGHT;
        assert_eq!(checked_validator_weight_sum([cap - 1, 1]).unwrap(), cap);
        assert!(checked_validator_weight_sum([cap, 1]).is_err());
        assert!(checked_validator_weight_sum([0]).is_err());
        assert!(checked_add_validator_weight(u64::MAX, 1).is_err());
        assert!(checked_add_validator_weight(cap + 1, 1).is_err());
    }
}
