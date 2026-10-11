// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use crate::config_read_budget::{self as config_budget, ConfigReadBudget};

/// Parsed once, still not authenticated. The caller supplies the authenticated
/// governing cell; its original selected Param30 cell remains the commitment.
pub struct DecodedSessionConfig {
    pub current: ValidatorSet,
    pub next: ValidatorSet,
    pub previous: ValidatorSet,
    pub catchain: CatchainConfig,
    pub consensus: ConsensusConfig,
    pub selected: SelectedSimplexConfig,
}
impl ConfigParams {
    pub fn config_cell_bounded(
        &self,
        number: u32,
        budget: &dyn ConfigReadBudget,
    ) -> Result<Option<Cell>> {
        config_budget::lookup(budget, 32)?;
        Ok(self
            .config_params
            .get(number.write_to_bitstring()?)?
            .and_then(|value| value.reference_opt(0)))
    }
    fn validator_param_bounded(
        &self,
        primary: u32,
        temporary: Option<u32>,
        budget: &dyn ConfigReadBudget,
    ) -> Result<ValidatorSet> {
        let mut cell = None;
        if let Some(temporary) = temporary {
            cell = self.config_cell_bounded(temporary, budget)?;
        }
        if cell.is_none() {
            cell = self.config_cell_bounded(primary, budget)?;
        }
        match cell {
            Some(cell) => ValidatorSet::construct_bounded(&mut SliceData::load_cell(cell)?, budget),
            None => Ok(ValidatorSet::default()),
        }
    }
    /// Only 32..37 are validator-set schemas. Param38 is an opaque ConfigParamAny
    /// in the ordinary decoder; use config_cell_bounded(38) for that view.
    pub fn config_validator_set_bounded(
        &self,
        param: u32,
        budget: &dyn ConfigReadBudget,
    ) -> Result<Option<ValidatorSet>> {
        if !(32..=37).contains(&param) {
            fail!("Not a validator config parameter");
        }
        self.config_cell_bounded(param, budget)?
            .map(|cell| ValidatorSet::construct_bounded(&mut SliceData::load_cell(cell)?, budget))
            .transpose()
    }
    pub fn catchain_config_bounded(&self, budget: &dyn ConfigReadBudget) -> Result<CatchainConfig> {
        config_budget::lookup(budget, 32)?;
        self.catchain_config()
    }
    pub fn validator_set_bounded(&self, budget: &dyn ConfigReadBudget) -> Result<ValidatorSet> {
        self.validator_param_bounded(34, Some(35), budget)
    }
    pub fn next_validator_set_bounded(
        &self,
        budget: &dyn ConfigReadBudget,
    ) -> Result<ValidatorSet> {
        #[cfg(feature = "mirrornet")]
        let temporary = Some(37);
        #[cfg(not(feature = "mirrornet"))]
        let temporary = None;
        self.validator_param_bounded(36, temporary, budget)
    }
    /// Retired identity also needs the next set to authorize its requested epoch.
    pub fn session_config_bounded(
        &self,
        masterchain: bool,
        budget: &dyn ConfigReadBudget,
    ) -> Result<DecodedSessionConfig> {
        self.decode_session_config_bounded(masterchain, budget, true, true)
    }
    /// Proof/PQ commitment reads current and Param28/29/30, never unused sets.
    pub fn governing_session_config_bounded(
        &self,
        masterchain: bool,
        budget: &dyn ConfigReadBudget,
    ) -> Result<DecodedSessionConfig> {
        self.decode_session_config_bounded(masterchain, budget, false, false)
    }
    /// Mirrors live runtime: previous/next membership is used only by protocol 2.
    pub fn runtime_session_config_bounded(
        &self,
        masterchain: bool,
        budget: &dyn ConfigReadBudget,
    ) -> Result<DecodedSessionConfig> {
        self.decode_session_config_bounded(masterchain, budget, false, true)
    }
    fn decode_session_config_bounded(
        &self,
        masterchain: bool,
        budget: &dyn ConfigReadBudget,
        always_next: bool,
        transport_membership: bool,
    ) -> Result<DecodedSessionConfig> {
        config_budget::lookup(budget, 32)?;
        let catchain = self.catchain_config()?;
        config_budget::lookup(budget, 32)?;
        let consensus = self.consensus_config()?;
        config_budget::lookup(budget, 32)?;
        let mut value = self
            .config_params
            .get(30u32.write_to_bitstring()?)?
            .ok_or_else(|| error!("selected governing Param30 is missing"))?;
        if value.remaining_bits() != 0 || value.remaining_references() != 1 {
            fail!("invalid ConfigParam30 dictionary value");
        }
        let mut wrapper = SliceData::load_cell(value.checked_drain_reference()?)?;
        let (mc, shard) = read_consensus_config_cells(&mut wrapper)?;
        let original_cell = (if masterchain { mc } else { shard })
            .ok_or_else(|| error!("selected governing Param30 is missing"))?;
        let mut slice = SliceData::load_cell_ref(&original_cell)?;
        let tag = slice.clone().get_next_byte()?;
        let config = if tag == SIMPLEX_CONFIG_V2_TAG {
            slice.get_next_byte()?;
            let flags = slice.get_next_byte()?;
            if flags & !7 != 0 {
                fail!("nonzero Simplex reserved flags");
            }
            let slots_per_leader_window = u32::construct_from(&mut slice)?;
            if slots_per_leader_window == 0 {
                fail!("zero Simplex leader window");
            }
            let root =
                if slice.get_next_bit()? { Some(slice.checked_drain_reference()?) } else { None };
            let params = HashmapE::with_hashmap(8, root);
            let mut noncritical_params = NoncriticalParams::default();
            // Enumerate the entire finite key space. No unmetered recursive
            // iterator or unique-cell assumption, even for shared subtrees.
            for key in 0u16..256 {
                config_budget::lookup(budget, 8)?;
                if let Some(mut raw) = params.get((key as u8).write_to_bitstring()?)? {
                    let value = u32::construct_from(&mut raw)?;
                    ensure_config_slice_empty(&raw)?;
                    noncritical_params.set(key as u8, value);
                }
            }
            SimplexConfig {
                protocol_version: (flags >> 1) & 3,
                use_quic: flags & 1 != 0,
                slots_per_leader_window,
                noncritical_params,
            }
        } else {
            // The old fixed-size constructor has no dictionary or byte vector.
            SimplexConfig::construct_from(&mut slice)?
        };
        ensure_config_slice_empty(&slice)?;
        let selected = SelectedSimplexConfig { config, original_cell };
        #[cfg(feature = "mirrornet")]
        let (previous_temporary, next_temporary) = (Some(33), Some(37));
        #[cfg(not(feature = "mirrornet"))]
        let (previous_temporary, next_temporary) = (None, None);
        Ok(DecodedSessionConfig {
            current: self.validator_param_bounded(34, Some(35), budget)?,
            previous: if transport_membership && selected.config.protocol_version == 2 {
                self.validator_param_bounded(32, previous_temporary, budget)?
            } else {
                ValidatorSet::default()
            },
            next: if always_next || (transport_membership && selected.config.protocol_version == 2)
            {
                self.validator_param_bounded(36, next_temporary, budget)?
            } else {
                ValidatorSet::default()
            },
            catchain,
            consensus,
            selected,
        })
    }
}
