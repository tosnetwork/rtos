// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
// Included in validators: private fields remain private outside the parser.
use crate::config_read_budget::{self as cb, ConfigReadBudget};
use crate::HashmapType;

impl ValidatorDescr {
    fn charge_classical_identity(&self, budget: &dyn ConfigReadBudget) -> Result<()> {
        if matches!(self.key, ValidatorKey::Ed25519(_)) {
            budget.workspace(
                std::mem::size_of::<crate::Ed25519KeyOption<crate::ZeroizingBytes>>()
                    + std::mem::size_of::<crate::KeyId>()
                    + 4 * std::mem::size_of::<usize>(),
            )?;
        }
        Ok(())
    }
    pub fn validator_id_bounded(&self, budget: &dyn ConfigReadBudget) -> Result<UInt256> {
        self.charge_classical_identity(budget)?;
        self.validator_id()
    }
    pub fn consensus_key_id_bounded(&self, budget: &dyn ConfigReadBudget) -> Result<UInt256> {
        self.charge_classical_identity(budget)?;
        self.consensus_key_id()
    }
    pub fn adnl_addr_bounded(&self, budget: &dyn ConfigReadBudget) -> Result<Arc<KeyId>> {
        budget.step()?;
        if self.adnl_addr.is_some() {
            budget.workspace(std::mem::size_of::<KeyId>() + 2 * std::mem::size_of::<usize>())?;
        } else {
            self.charge_classical_identity(budget)?;
        }
        self.adnl_addr()
    }
    pub fn clone_bounded(&self, budget: &dyn ConfigReadBudget) -> Result<Self> {
        budget.step()?;
        if let ValidatorKey::Pq(key) = &self.key {
            budget.workspace(key.public_key.len())?;
        }
        Ok(self.clone())
    }
    fn construct_bounded(slice: &mut SliceData, budget: &dyn ConfigReadBudget) -> Result<Self> {
        budget.step()?;
        if slice.clone().get_next_byte()? != VALIDATOR_DESC_PQ_TAG {
            return Self::construct_from(slice);
        }
        slice.get_next_byte()?;
        let validator_id = UInt256::construct_from(slice)?;
        let algorithm_id = slice.get_next_int(16)? as u16;
        let key_id = UInt256::construct_from(slice)?;
        let public_key = crate::pq_bytes::unpack_pq_bytes_bounded(
            &slice.checked_drain_reference()?,
            PQ_BYTES_HARD_MAX,
            budget,
        )?;
        let weight = u64::construct_from(slice)?;
        let adnl_addr = Some(UInt256::construct_from(slice)?);
        if slice.remaining_bits() != 0 || slice.remaining_references() != 0 {
            fail!("post-quantum validator descriptor has trailing data");
        }
        Ok(Self {
            validator_id,
            key: ValidatorKey::Pq(PqConsensusKey { algorithm_id, key_id, public_key }),
            weight,
            adnl_addr,
            prev_weight_sum: 0,
        })
    }
}

/// Same identity/key/address and weight checks, without opaque hash-table growth.
/// One exactly-sized scratch vector is insertion-sorted per field. Comparisons
/// and movements consume work, including the adversarial quadratic case.
pub fn validate_validator_list_bounded(
    list: &[ValidatorDescr],
    budget: &dyn ConfigReadBudget,
) -> Result<u64> {
    if list.is_empty() || list.len() > u16::MAX as usize {
        fail!("invalid validator count");
    }
    let mut triples = cb::vector::<(UInt256, UInt256, Option<UInt256>)>(budget, list.len())?;
    let mut total = 0;
    for v in list {
        budget.step()?;
        if let ValidatorKey::Pq(k) = &v.key {
            budget.workspace(CONSENSUS_KEY_ID_DOMAIN.len() + 2 + k.public_key.len())?;
        }
        v.validate_consensus()?;
        triples.push((
            v.validator_id_bounded(budget)?,
            v.consensus_key_id_bounded(budget)?,
            v.adnl_addr.clone().filter(|a| !a.is_zero()),
        ));
        total = crate::checked_add_validator_weight(total, v.weight)?;
    }
    for field in 0..3 {
        fn field_value(v: &(UInt256, UInt256, Option<UInt256>), field: usize) -> Option<&UInt256> {
            match field {
                0 => Some(&v.0),
                1 => Some(&v.1),
                _ => v.2.as_ref(),
            }
        }
        for i in 1..triples.len() {
            let mut j = i;
            while j > 0 {
                budget.step()?;
                if field_value(&triples[j - 1], field) <= field_value(&triples[j], field) {
                    break;
                }
                triples.swap(j - 1, j);
                j -= 1;
            }
        }
        for pair in triples.windows(2) {
            budget.step()?;
            if field_value(&pair[0], field).is_some()
                && field_value(&pair[0], field) == field_value(&pair[1], field)
            {
                fail!("duplicate validator identity/key/network identity");
            }
        }
    }
    Ok(total)
}

impl ValidatorSet {
    pub fn construct_bounded(cell: &mut SliceData, budget: &dyn ConfigReadBudget) -> Result<Self> {
        budget.step()?;
        let tag = cell.get_next_byte()?;
        if !matches!(tag, VALIDATOR_SET_TAG | VALIDATOR_SET_EX_TAG) {
            fail!(Self::invalid_tag(tag as u32));
        }
        let utime_since = u32::construct_from(cell)?;
        let utime_until = u32::construct_from(cell)?;
        let total = Number16::construct_from(cell)?;
        let main = Number16::construct_from(cell)?;
        let mut validators = ValidatorDescriptions::default();
        let declared_weight = if tag == VALIDATOR_SET_TAG {
            budget.workspace(crate::merkle_apply_budget::NEW_CELL_ALLOCATION)?;
            validators.read_hashmap_root(cell)?;
            None
        } else {
            let weight = u64::construct_from(cell)?;
            validators.read_from(cell)?;
            Some(weight)
        };
        let mut list = cb::vector::<ValidatorDescr>(budget, total.as_usize())?;
        let mut total_weight = 0;
        for i in 0..total.as_u16() {
            cb::lookup(budget, 16)?;
            let mut raw = validators
                .0
                .get(i.write_to_bitstring()?)?
                .ok_or_else(|| crate::error!("Missing validator index {}", i))?;
            let mut val = ValidatorDescr::construct_bounded(&mut raw, budget)?;
            val.prev_weight_sum = total_weight;
            total_weight = crate::checked_add_validator_weight(total_weight, val.weight)?;
            list.push(val);
        }
        validate_validator_list_bounded(&list, budget)?;
        if declared_weight.is_some_and(|w| w != total_weight) {
            fail!("Calculated total_weight differs");
        }
        if main > total || main < Number16::new(1)? {
            fail!("Invalid validator main count");
        }
        Ok(Self { utime_since, utime_until, total, main, total_weight, cc_seqno: 0, list })
    }

    pub fn calc_subset_bounded(
        &self,
        cc: &CatchainConfig,
        shard: u64,
        workchain: i32,
        seqno: u32,
        budget: &dyn ConfigReadBudget,
    ) -> Result<(Vec<ValidatorDescr>, u32)> {
        let master = shard == SHARD_FULL && workchain == MASTERCHAIN_ID;
        let mut prng = ValidatorSetPRNG::new(shard, workchain, seqno);
        let subset = if master {
            let count = min(self.total.as_usize(), self.main.as_usize());
            let mut result = cb::vector(budget, count)?;
            if cc.shuffle_mc_validators {
                let mut indexes = cb::vector::<usize>(budget, count)?;
                indexes.resize(count, 0);
                for i in 0..count {
                    budget.step()?;
                    let j = prng.next_ranged(i as u64 + 1) as usize;
                    indexes[i] = indexes[j];
                    indexes[j] = i;
                }
                for i in indexes {
                    result.push(self.list[i].clone_bounded(budget)?);
                }
            } else {
                for v in &self.list[..count] {
                    result.push(v.clone_bounded(budget)?);
                }
            }
            result
        } else {
            let mut isolated = Vec::new();
            let (list, weight) = if cc.isolate_mc_validators {
                if self.total <= self.main && !(self.main == 0 && self.total == 0) {
                    fail!("Count of validators is too small");
                }
                isolated = cb::vector(budget, self.list.len() - self.main.as_usize())?;
                let mut weight = 0;
                for v in &self.list[self.main.as_usize()..] {
                    let mut v = v.clone_bounded(budget)?;
                    v.prev_weight_sum = weight;
                    weight = crate::checked_add_validator_weight(weight, v.weight)?;
                    isolated.push(v);
                }
                validate_validator_list_bounded(&isolated, budget)?;
                (isolated.as_slice(), weight)
            } else {
                (self.list.as_slice(), self.total_weight)
            };
            let count = min(list.len(), cc.shard_validators_num as u16 as usize);
            let mut result = cb::vector(budget, count)?;
            let mut weights = cb::vector::<IncludedValidatorWeight>(budget, count)?;
            let mut remaining = weight;
            for _ in 0..count {
                budget.step()?;
                if remaining == 0 {
                    fail!("Empty validator weight");
                }
                let mut p = prng.next_ranged(remaining);
                for w in &weights {
                    budget.step()?;
                    if p < w.prev_weight_sum {
                        break;
                    }
                    p += w.weight;
                }
                let mut selected = list.last().ok_or_else(|| crate::error!("Empty validators"))?;
                for (i, v) in list.iter().enumerate() {
                    budget.step()?;
                    if v.prev_weight_sum > p {
                        selected = &list[i - 1];
                        break;
                    }
                }
                let mut value = selected.clone_bounded(budget)?;
                value.weight = 1;
                value.prev_weight_sum = 0;
                result.push(value);
                remaining -= selected.weight;
                let w = IncludedValidatorWeight {
                    prev_weight_sum: selected.prev_weight_sum,
                    weight: selected.weight,
                };
                let mut pos = 0;
                while pos < weights.len() {
                    budget.step()?;
                    if weights[pos] > w {
                        break;
                    }
                    pos += 1;
                }
                cb::steps(budget, weights.len() - pos)?;
                weights.insert(pos, w);
            }
            result
        };
        budget.workspace(12 + subset.len() * 104)?;
        cb::steps(budget, subset.len())?;
        for v in &subset {
            v.charge_classical_identity(budget)?;
            v.charge_classical_identity(budget)?;
        }
        let hash = Self::calc_subset_hash_short(&subset, seqno)?;
        Ok((subset, hash))
    }
}
