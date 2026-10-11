/*
 * RTOS project modifications (2026-10-10): project and crate naming.
 * Copyright (C) 2019-2024 EverX. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use crate::{
    block::BlockIdExtExtention,
    engine_traits::EngineOperations,
    error::NodeError,
    shard_state::ShardStateStuff,
    validating_utils::build_checked_data,
    validator::validator_utils::{calc_subset_for_masterchain, ValidatorSubsetInfo},
};
use crate::{bounded_session_derivation::ConfigBudget, history_read_budget::HistoryReadBudget};
use rtos_block::{
    error, fail, write_boc, Block, BlockIdExt, BlockInfo, BlockProof, BlockSignaturesVariant,
    BocReader, Cell, ConfigParams, Deserializable, HashmapType, MerkleProof, Result, Serializable,
    UInt256,
};
use std::sync::Arc;
type ProofBudget<'a> = Option<&'a HistoryReadBudget>;

fn config_lookup(budget: ProofBudget<'_>) -> Result<()> {
    if let Some(budget) = budget {
        rtos_block::config_read_budget::lookup(&ConfigBudget(budget), 32)?;
    }
    Ok(())
}
fn find_history_block(
    state: &ShardStateStuff,
    seqno: u32,
    budget: ProofBudget<'_>,
) -> Result<BlockIdExt> {
    config_lookup(budget)?;
    state.find_block_id(seqno)
}
fn proof_subset(
    config: &ConfigParams,
    seqno: u32,
    budget: ProofBudget<'_>,
) -> Result<ValidatorSubsetInfo> {
    if let Some(budget) = budget {
        let budget = ConfigBudget(budget);
        let validators = config.validator_set_bounded(&budget)?;
        let (validators, short_hash) = validators.calc_subset_bounded(
            &config.catchain_config_bounded(&budget)?,
            rtos_block::SHARD_FULL,
            rtos_block::MASTERCHAIN_ID,
            seqno,
            &budget,
        )?;
        Ok(ValidatorSubsetInfo { validators, short_hash })
    } else {
        calc_subset_for_masterchain(&config.validator_set()?, config, seqno)
    }
}
fn pq_context(
    global_id: i32,
    config: &ConfigParams,
    id: BlockIdExt,
    vertical: u32,
    previous: u32,
    catchain: u32,
    budget: ProofBudget<'_>,
) -> Result<rtos_api::pq_finality::PqVerificationContext> {
    match budget {
        Some(budget) => {
            rtos_api::pq_finality::PqVerificationContext::from_governing_config_bounded(
                global_id,
                config,
                id,
                vertical,
                previous,
                catchain,
                &ConfigBudget(budget),
            )
        }
        None => rtos_api::pq_finality::PqVerificationContext::from_governing_config(
            global_id, config, id, vertical, previous, catchain,
        ),
    }
}

#[cfg(test)]
#[path = "tests/test_block_proof.rs"]
mod tests;

/// An authenticated bootstrap position, rooted in an explicit local pin.
/// Private fields prevent parsed peer proofs from being promoted by assignment.
/// A checkpoint pin supplies out-of-band authority, not proof of earlier history.
#[derive(Clone)]
pub(crate) struct BootstrapAuthority {
    anchor: BlockIdExt,
    global_id: i32,
    source: BootstrapSource,
}

#[derive(Clone)]
enum BootstrapSource {
    Zerostate(Arc<ShardStateStuff>),
    KeyBlock(BlockProofStuff),
}

/// Signature-authenticated masterchain proof under a particular bootstrap history.
/// This is not full execution validity and cannot by itself authorize signing.
#[derive(Debug)]
pub(crate) struct VerifiedMasterchainProof {
    proof: BlockProofStuff,
    anchor: BlockIdExt,
    global_id: i32,
}

/// State whose root is committed by an authenticated masterchain block or pin.
/// This attests to the commitment, not replayed execution or permission to sign.
pub(crate) struct VerifiedMasterchainState {
    state: Arc<ShardStateStuff>,
}

impl VerifiedMasterchainState {
    pub(crate) fn state(&self) -> &Arc<ShardStateStuff> {
        &self.state
    }
}

impl VerifiedMasterchainProof {
    pub(crate) fn authenticate_state(
        self,
        state: Arc<ShardStateStuff>,
    ) -> Result<VerifiedMasterchainState> {
        authenticate_committed_state(&self.proof, self.global_id, state)
    }
}

fn authenticate_committed_state(
    proof: &BlockProofStuff,
    global_id: i32,
    state: Arc<ShardStateStuff>,
) -> Result<VerifiedMasterchainState> {
    let root = proof.virtualize_block()?.0.read_state_update()?.new_hash;
    state.verify_state_root(proof.id(), &root)?;
    if state.state()?.global_id() != global_id {
        fail!("Recovered state global_id differs from authenticated block");
    }
    Ok(VerifiedMasterchainState { state })
}

impl std::fmt::Debug for BootstrapAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapAuthority")
            .field("anchor", &self.anchor)
            .field("current", self.id())
            .finish()
    }
}

impl BootstrapAuthority {
    pub(crate) fn from_zerostate(pin: &BlockIdExt, state: Arc<ShardStateStuff>) -> Result<Self> {
        Self::from_zerostate_with_budget(pin, state, None)
    }

    pub(crate) fn from_zerostate_with_budget(
        pin: &BlockIdExt,
        state: Arc<ShardStateStuff>,
        budget: ProofBudget<'_>,
    ) -> Result<Self> {
        if !pin.shard().is_masterchain_ext() {
            fail!("Bootstrap requires a masterchain zerostate");
        }
        state.verify_zerostate(pin)?;
        let global_id = state.state()?.global_id();
        config_lookup(budget)?;
        match state.config_params()?.config(19)? {
            Some(rtos_block::ConfigParamEnum::ConfigParam19(id)) if id == global_id as u32 => {}
            _ => fail!("Bootstrap zerostate global_id disagrees with Param19"),
        }
        Ok(Self { anchor: pin.clone(), global_id, source: BootstrapSource::Zerostate(state) })
    }

    pub(crate) fn from_checkpoint(pin: &BlockIdExt, proof: BlockProofStuff) -> Result<Self> {
        Self::from_checkpoint_with_budget(pin, proof, None)
    }

    pub(crate) fn from_checkpoint_with_budget(
        pin: &BlockIdExt,
        proof: BlockProofStuff,
        budget: ProofBudget<'_>,
    ) -> Result<Self> {
        proof.check_trusted_checkpoint_with_budget(pin, budget)?;
        let global_id = proof.virtualize_block()?.0.global_id();
        Ok(Self { anchor: pin.clone(), global_id, source: BootstrapSource::KeyBlock(proof) })
    }

    pub(crate) fn id(&self) -> &BlockIdExt {
        match &self.source {
            BootstrapSource::Zerostate(state) => state.block_id(),
            BootstrapSource::KeyBlock(proof) => proof.id(),
        }
    }
    pub(crate) fn anchor(&self) -> &BlockIdExt {
        &self.anchor
    }
    pub(crate) fn key_block_proof(&self) -> Option<&BlockProofStuff> {
        match &self.source {
            BootstrapSource::KeyBlock(proof) => Some(proof),
            _ => None,
        }
    }
    fn charge_budget(&self, budget: &crate::history_read_budget::HistoryReadBudget) -> Result<()> {
        match &self.source {
            BootstrapSource::Zerostate(state) => budget.graph(state.root_cell()),
            BootstrapSource::KeyBlock(proof) => budget.proof(proof),
        }
    }
    pub(crate) fn config(&self) -> Result<ConfigParams> {
        match &self.source {
            BootstrapSource::Zerostate(state) => Ok(state.config_params()?.clone()),
            BootstrapSource::KeyBlock(proof) => proof.get_config_params(),
        }
    }

    pub(crate) fn authenticate_current_state(
        &self,
        state: Arc<ShardStateStuff>,
    ) -> Result<VerifiedMasterchainState> {
        match &self.source {
            BootstrapSource::Zerostate(_) => {
                state.verify_zerostate(self.id())?;
                Ok(VerifiedMasterchainState { state })
            }
            BootstrapSource::KeyBlock(proof) => {
                authenticate_committed_state(proof, self.global_id, state)
            }
        }
    }

    pub(crate) fn authenticate_block(
        &self,
        expected: &BlockIdExt,
        proof: BlockProofStuff,
    ) -> Result<VerifiedMasterchainProof> {
        self.authenticate_block_with_budget(expected, proof, None)
    }

    pub(crate) fn authenticate_block_with_budget(
        &self,
        expected: &BlockIdExt,
        proof: BlockProofStuff,
        budget: ProofBudget<'_>,
    ) -> Result<VerifiedMasterchainProof> {
        if proof.id() != expected {
            fail!("Boot proof does not match requested block identity");
        }
        if proof.is_link() || !expected.shard().is_masterchain_ext() {
            fail!("Bootstrap successor requires a full masterchain proof");
        }
        if proof.virtualize_block()?.0.global_id() != self.global_id {
            fail!("Bootstrap successor belongs to a different global_id");
        }
        match &self.source {
            BootstrapSource::Zerostate(state) => {
                let (block, info) = proof.pre_check_block_proof_with_budget(budget)?;
                proof.check_with_master_state_(state, &block, &info, budget)?;
            }
            BootstrapSource::KeyBlock(previous) => {
                let (block, info) = proof.pre_check_block_proof_with_budget(budget)?;
                proof.check_with_prev_key_block_proof_(previous, &block, &info, budget)?
            }
        }
        Ok(VerifiedMasterchainProof {
            proof,
            anchor: self.anchor.clone(),
            global_id: self.global_id,
        })
    }

    pub(crate) fn advance_key_block(
        &self,
        expected: &BlockIdExt,
        proof: BlockProofStuff,
    ) -> Result<Self> {
        self.advance_key_block_with_budget(expected, proof, None)
    }

    pub(crate) fn advance_key_block_with_budget(
        &self,
        expected: &BlockIdExt,
        proof: BlockProofStuff,
        budget: ProofBudget<'_>,
    ) -> Result<Self> {
        let verified = self.authenticate_block_with_budget(expected, proof, budget)?;
        // Authority can advance only after signatures authenticate the new block,
        // and its actual header/config qualify it as a governing key block.
        verified.proof.check_trusted_checkpoint_with_budget(expected, budget)?;
        Ok(Self {
            anchor: verified.anchor,
            global_id: verified.global_id,
            source: BootstrapSource::KeyBlock(verified.proof),
        })
    }
}

/// Small, process-local cache of authenticated governing authorities. Neither
/// database flags nor parsed peer/config objects can be inserted here.
/// Both the local pin and the complete governing block ID scope every entry.
pub(crate) struct MasterchainProofVerifier {
    authorities: parking_lot::Mutex<lru::LruCache<(BlockIdExt, BlockIdExt), BootstrapAuthority>>,
}

impl Default for MasterchainProofVerifier {
    fn default() -> Self {
        Self { authorities: parking_lot::Mutex::new(lru::LruCache::new(16.try_into().unwrap())) }
    }
}

/// Routing policy recovered from the same authenticated governing history as
/// the PQ verifier. Serialized outbox metadata cannot construct this receipt.
pub struct PqPublicationContext {
    zerostate: BlockIdExt,
    history_init: BlockIdExt,
    global_id: i32,
    protocol: consensus_common::simplex_protocol::SimplexProtocol,
    profile: UInt256,
    committee: Vec<rtos_block::ValidatorDescr>,
    slots_per_leader_window: u32,
    carrier_version: u32,
    verifier: rtos_api::pq_finality::PqVerificationContext,
}

impl PqPublicationContext {
    /// Local trust checkpoint used while authenticating the governing history.
    pub fn history_init(&self) -> &BlockIdExt {
        &self.history_init
    }
    pub fn zerostate(&self) -> &BlockIdExt {
        &self.zerostate
    }
    pub fn global_id(&self) -> i32 {
        self.global_id
    }
    pub fn protocol(&self) -> consensus_common::simplex_protocol::SimplexProtocol {
        self.protocol
    }
    pub fn profile(&self) -> &UInt256 {
        &self.profile
    }
    pub fn committee(&self) -> &[rtos_block::ValidatorDescr] {
        &self.committee
    }
    pub fn slots_per_leader_window(&self) -> u32 {
        self.slots_per_leader_window
    }
    pub fn carrier_version(&self) -> u32 {
        self.carrier_version
    }
    pub fn verifier(&self) -> &rtos_api::pq_finality::PqVerificationContext {
        &self.verifier
    }
}

impl MasterchainProofVerifier {
    fn remember(&self, authority: BootstrapAuthority) {
        // Large valid proofs remain verifiable without being retained. This is
        // a serialized-size cache budget, not a resident-memory accounting bound.
        if authority.key_block_proof().is_some_and(|proof| proof.data.len() <= 1024 * 1024) {
            self.authorities
                .lock()
                .put((authority.anchor().clone(), authority.id().clone()), authority);
        }
    }

    pub(crate) async fn verify<E: EngineOperations + ?Sized>(
        &self,
        engine: &E,
        proof: &BlockProofStuff,
    ) -> Result<VerifiedMasterchainProof> {
        self.verify_with_budget(engine, proof, None).await
    }
    pub(crate) async fn verify_bounded<E: EngineOperations + ?Sized>(
        &self,
        engine: &E,
        proof: &BlockProofStuff,
        budget: Arc<crate::history_read_budget::HistoryReadBudget>,
    ) -> Result<VerifiedMasterchainProof> {
        self.verify_with_budget(engine, proof, Some(&budget)).await
    }
    async fn verify_with_budget<E: EngineOperations + ?Sized>(
        &self,
        engine: &E,
        proof: &BlockProofStuff,
        budget: Option<&Arc<crate::history_read_budget::HistoryReadBudget>>,
    ) -> Result<VerifiedMasterchainProof> {
        if let Some(budget) = budget {
            budget.step()?;
            budget.proof(proof)?;
        }
        if proof.is_link() || !proof.id().shard().is_masterchain_ext() {
            fail!("Masterchain finality requires a full proof");
        }
        let (_, info) = proof.pre_check_block_proof_with_budget(budget.map(Arc::as_ref))?;
        let epoch = info.prev_key_block_seqno();
        if epoch >= proof.id().seq_no {
            fail!("Governing epoch must precede the target masterchain block");
        }
        let history = self.governing_authority(engine, epoch, budget).await?;
        // A cache hit reuses only the governing authority. Every incoming
        // certificate, including repeat block IDs, must still pass verification.
        history.authenticate_block_with_budget(
            proof.id(),
            proof.clone_with_budget(budget.map(Arc::as_ref))?,
            budget.map(Arc::as_ref),
        )
    }

    async fn governing_authority<E: EngineOperations + ?Sized>(
        &self,
        engine: &E,
        epoch: u32,
        budget: Option<&Arc<crate::history_read_budget::HistoryReadBudget>>,
    ) -> Result<BootstrapAuthority> {
        if let Some(budget) = budget {
            budget.step()?;
        }
        if let Some(budget) = budget {
            if let Some(proofs) = budget.replay_proofs()? {
                return self.governing_repair_closure(engine, epoch, proofs, budget).await;
            }
        }
        let pin = engine.init_mc_block_id();
        if epoch < pin.seq_no {
            fail!("Governing epoch is outside the locally pinned history");
        }
        let hint = if epoch > pin.seq_no {
            let ordinary = match budget {
                Some(budget) => engine.load_last_applied_mc_state_bounded(budget.clone()).await,
                None => engine.load_last_applied_mc_state().await,
            };
            if budget.is_some() {
                if let Err(error) = &ordinary {
                    if crate::history_read_budget::stops_fallback(error) {
                        return Err(ordinary.err().unwrap());
                    }
                }
            }
            if let (Some(budget), Ok(state)) = (budget, &ordinary) {
                budget.graph(state.root_cell())?;
            }
            // Refusal must propagate, never become a lookup miss and trigger fallback.
            config_lookup(budget.map(Arc::as_ref))?;
            match ordinary {
                Ok(state) if state.find_block_id(epoch).is_ok() => Some(state),
                ordinary => {
                    match crate::retired_history::lookup_hint_with_budget(engine, epoch, budget)
                        .await?
                    {
                        Some(state) => Some(state),
                        None => {
                            let state = ordinary?;
                            find_history_block(&state, epoch, budget.map(Arc::as_ref))?;
                            Some(state)
                        }
                    }
                }
            }
        } else {
            None
        };
        let governing = match &hint {
            Some(state) => find_history_block(&state, epoch, budget.map(Arc::as_ref))?,
            None => pin.clone(),
        };
        let capture = budget.is_some(); // Bounded reads reauthenticate and avoid uncharged cache clones.
        let cached = if capture {
            None
        } else {
            self.authorities.lock().get(&(pin.clone(), governing.clone())).cloned()
        };
        let history = if let Some(history) = cached {
            history
        } else {
            // Use the newest already-authenticated predecessor that agrees with
            // the lookup index; the index itself conveys no authority.
            let predecessor = if capture {
                None
            } else {
                let cache = self.authorities.lock();
                cache
                    .iter()
                    .filter(|((anchor, id), _)| anchor == pin && id.seq_no <= epoch)
                    .filter(|((_, id), _)| {
                        id == pin
                            || hint.as_ref().is_some_and(|state| {
                                state.find_block_id(id.seq_no).is_ok_and(|found| &found == id)
                            })
                    })
                    .max_by_key(|((_, id), _)| id.seq_no)
                    .map(|(_, value)| value.clone())
            };
            let mut history = match predecessor {
                Some(history) => history,
                None if pin.seq_no == 0 => {
                    if pin != engine.zerostate_id()? {
                        fail!("Proof pin differs from network zerostate");
                    }
                    let state = match budget {
                        Some(budget) => engine.load_mc_zero_state_bounded(budget.clone()).await?,
                        None => engine.load_mc_zero_state().await?,
                    };
                    if let Some(budget) = budget {
                        budget.graph(state.root_cell())?;
                        budget.record_state(pin, state.root_cell())?;
                    }
                    BootstrapAuthority::from_zerostate_with_budget(
                        pin,
                        state,
                        budget.map(Arc::as_ref),
                    )?
                }
                None => BootstrapAuthority::from_checkpoint_with_budget(
                    pin,
                    crate::boot::load_history_proof_with_budget(engine, pin, true, true, budget)
                        .await?,
                    budget.map(Arc::as_ref),
                )?,
            };
            if let Some(budget) = budget {
                history.charge_budget(budget)?;
            }
            if budget.is_none() {
                self.remember(history.clone());
            }
            while history.id().seq_no < epoch {
                if let Some(budget) = budget {
                    budget.step()?;
                }
                if engine.check_stop() {
                    fail!("Proof history authentication stopped");
                }
                let state =
                    hint.as_ref().ok_or_else(|| error!("Missing historical proof lookup index"))?;
                let index = &state.shard_state_extra()?.prev_blocks;
                let next = match budget {
                    Some(budget) => index.get_next_key_block_bounded(
                        history.id().seq_no + 1,
                        &ConfigBudget(budget),
                    )?,
                    None => index.get_next_key_block(history.id().seq_no + 1)?,
                }
                .map(|reference| reference.master_block_id().1)
                .or_else(|| (state.block_id().seq_no == epoch).then(|| state.block_id().clone()))
                .ok_or_else(|| error!("Missing governing key-block history"))?;
                if next.seq_no <= history.id().seq_no || next.seq_no > epoch {
                    fail!("Historical proof index skipped the governing epoch");
                }
                let next_proof =
                    crate::boot::load_history_proof_with_budget(engine, &next, false, true, budget)
                        .await?;
                history = history.advance_key_block_with_budget(
                    &next,
                    next_proof,
                    budget.map(Arc::as_ref),
                )?;
                if budget.is_none() {
                    self.remember(history.clone());
                }
            }
            if history.id() != &governing {
                fail!("Governing proof differs from lookup identity");
            }
            history
        };
        if let Some(budget) = budget {
            history.charge_budget(budget)?;
        }
        Ok(history)
    }

    /// Only identities in the caller's bounded closure are locators. Every
    /// transition is reauthenticated from the actual Engine pin, without caches
    /// or dependence on a future latest-state history dictionary.
    async fn governing_repair_closure<E: EngineOperations + ?Sized>(
        &self,
        engine: &E,
        epoch: u32,
        mut proofs: Vec<BlockProofStuff>,
        budget: &Arc<crate::history_read_budget::HistoryReadBudget>,
    ) -> Result<BootstrapAuthority> {
        let pin = engine.init_mc_block_id();
        if epoch < pin.seq_no() {
            fail!("Repair closure precedes pin");
        }
        rtos_block::config_read_budget::steps(&ConfigBudget(budget), proofs.len())?;
        let mut authority = if pin.seq_no() == 0 {
            if pin != engine.zerostate_id()? {
                fail!("Repair closure pin mismatch");
            }
            let zero = engine.load_mc_zero_state_bounded(budget.clone()).await?;
            budget.record_state(pin, zero.root_cell())?;
            BootstrapAuthority::from_zerostate_with_budget(pin, zero, Some(budget))?
        } else {
            let proof = proofs
                .iter()
                .find(|p| p.id() == pin)
                .ok_or_else(|| error!("Repair closure missing checkpoint"))?
                .clone_with_budget(Some(budget))?;
            budget.record_history_proof(&proof)?;
            BootstrapAuthority::from_checkpoint_with_budget(pin, proof, Some(budget))?
        };
        for i in 1..proofs.len() {
            let mut j = i;
            while j > 0 {
                budget.step()?;
                if proofs[j - 1].id().seq_no() <= proofs[j].id().seq_no() {
                    break;
                }
                proofs.swap(j - 1, j);
                j -= 1;
            }
        }
        for proof in proofs {
            budget.step()?;
            if proof.id().seq_no() <= authority.id().seq_no() || proof.id().seq_no() > epoch {
                continue;
            }
            if !proof.pre_check_block_proof_with_budget(Some(budget))?.1.key_block() {
                continue;
            }
            budget.record_history_proof(&proof)?;
            authority = authority.advance_key_block_with_budget(
                proof.id(),
                proof.clone_with_budget(Some(budget))?,
                Some(budget),
            )?;
        }
        if authority.id().seq_no() != epoch {
            fail!("Repair closure missing governing key proof");
        }
        authority.charge_budget(budget)?;
        Ok(authority)
    }

    /// Recover publication policy from authenticated history rather than the
    /// retry record. In particular, a stored protocol tag cannot select relay
    /// behavior for a different governing configuration after restart.
    pub(crate) async fn pq_publication_context<E: EngineOperations + ?Sized>(
        &self,
        engine: &E,
        id: &BlockIdExt,
        block: &Block,
    ) -> Result<PqPublicationContext> {
        self.pq_publication_context_with_budget(engine, id, block, None).await
    }
    pub(crate) async fn pq_publication_context_bounded<E: EngineOperations + ?Sized>(
        &self,
        engine: &E,
        id: &BlockIdExt,
        block: &Block,
        budget: Arc<crate::history_read_budget::HistoryReadBudget>,
    ) -> Result<PqPublicationContext> {
        self.pq_publication_context_with_budget(engine, id, block, Some(&budget)).await
    }
    async fn pq_publication_context_with_budget<E: EngineOperations + ?Sized>(
        &self,
        engine: &E,
        id: &BlockIdExt,
        block: &Block,
        budget: Option<&Arc<crate::history_read_budget::HistoryReadBudget>>,
    ) -> Result<PqPublicationContext> {
        let verifier = self.pq_broadcast_context_with_budget(engine, id, block, budget).await?;
        let info = block.read_info()?;
        let authority =
            self.governing_authority(engine, info.prev_key_block_seqno(), budget).await?;
        let config = authority.config()?;
        let (protocol, committee, slots_per_leader_window, identity, carrier_version) =
            if let Some(budget) = budget {
                let budget = ConfigBudget(budget);
                let decoded =
                    config.governing_session_config_bounded(id.shard().is_masterchain(), &budget)?;
                let (committee, _) = decoded.current.calc_subset_bounded(
                    &decoded.catchain,
                    id.shard().shard_prefix_with_tag(),
                    id.shard().workchain_id(),
                    info.gen_catchain_seqno(),
                    &budget,
                )?;
                let protocol = consensus_common::simplex_protocol::SimplexProtocol::try_from(
                    u32::from(decoded.selected.config.protocol_version),
                )?;
                let slots = decoded.selected.config.slots_per_leader_window;
                if committee.is_empty() || slots == 0 {
                    fail!("Publication history has no valid leader schedule");
                }
                let identity = rtos_api::session_identity::derive_session_from_decoded_bounded(
                    authority.global_id,
                    &decoded,
                    rtos_api::session_identity::SessionCoordinates {
                        shard: id.shard(),
                        catchain_seqno: info.gen_catchain_seqno(),
                        vertical_seqno: info.vert_seq_no(),
                        last_key_block_seqno: info.prev_key_block_seqno(),
                        new_catchain_ids: false,
                    },
                    &committee,
                    &budget,
                )?;
                (protocol, committee, slots, identity, u32::from(decoded.consensus.proto_version))
            } else {
                let selected = config
                    .selected_simplex_config(id.shard().is_masterchain())?
                    .ok_or_else(|| error!("Publication history has no selected Simplex config"))?;
                let protocol = consensus_common::simplex_protocol::SimplexProtocol::try_from(
                    u32::from(selected.config.protocol_version),
                )?;
                let (committee, _) = config.validator_set()?.calc_subset(
                    &config.catchain_config()?,
                    id.shard().shard_prefix_with_tag(),
                    id.shard().workchain_id(),
                    info.gen_catchain_seqno(),
                )?;
                let slots_per_leader_window = selected.config.slots_per_leader_window;
                if committee.is_empty() || slots_per_leader_window == 0 {
                    fail!("Publication history has no valid leader schedule");
                }
                let identity = rtos_api::session_identity::derive_session_from_config(
                    authority.global_id,
                    &config,
                    rtos_api::session_identity::SessionCoordinates {
                        shard: id.shard(),
                        catchain_seqno: info.gen_catchain_seqno(),
                        vertical_seqno: info.vert_seq_no(),
                        last_key_block_seqno: info.prev_key_block_seqno(),
                        new_catchain_ids: false,
                    },
                    &committee,
                )?;
                (
                    protocol,
                    committee,
                    slots_per_leader_window,
                    identity,
                    u32::from(config.consensus_config()?.proto_version),
                )
            };
        if &identity.session_id != verifier.expected_session_id() {
            fail!("Publication policy differs from authenticated PQ session");
        }
        Ok(PqPublicationContext {
            zerostate: engine.zerostate_id()?.clone(),
            history_init: engine.init_mc_block_id().clone(),
            global_id: authority.global_id,
            protocol,
            profile: identity.config_hash,
            committee,
            slots_per_leader_window,
            carrier_version,
            verifier,
        })
    }

    /// Resolve a historical broadcast epoch through the same pinned key-block
    /// proof chain as masterchain proof verification. A state index is a lookup
    /// hint only: each authority transition is authenticated before config use.
    pub(crate) async fn pq_broadcast_context<E: EngineOperations + ?Sized>(
        &self,
        engine: &E,
        id: &BlockIdExt,
        block: &Block,
    ) -> Result<rtos_api::pq_finality::PqVerificationContext> {
        self.pq_broadcast_context_with_budget(engine, id, block, None).await
    }
    pub(crate) async fn pq_broadcast_context_bounded<E: EngineOperations + ?Sized>(
        &self,
        engine: &E,
        id: &BlockIdExt,
        block: &Block,
        budget: Arc<crate::history_read_budget::HistoryReadBudget>,
    ) -> Result<rtos_api::pq_finality::PqVerificationContext> {
        self.pq_broadcast_context_with_budget(engine, id, block, Some(&budget)).await
    }
    async fn pq_broadcast_context_with_budget<E: EngineOperations + ?Sized>(
        &self,
        engine: &E,
        id: &BlockIdExt,
        block: &Block,
        budget: Option<&Arc<crate::history_read_budget::HistoryReadBudget>>,
    ) -> Result<rtos_api::pq_finality::PqVerificationContext> {
        let info = block.read_info()?;
        let authority =
            self.governing_authority(engine, info.prev_key_block_seqno(), budget).await?;
        if block.global_id() != authority.global_id {
            fail!("PQ broadcast global_id differs from authenticated history");
        }
        let context = pq_context(
            authority.global_id,
            &authority.config()?,
            id.clone(),
            info.vert_seq_no(),
            info.prev_key_block_seqno(),
            info.gen_catchain_seqno(),
            budget.map(Arc::as_ref),
        )?;
        if context.subset_hash() != info.gen_validator_list_hash_short() {
            fail!("PQ broadcast header disagrees with historical governing validator set");
        }
        Ok(context)
    }
}

/// Cache flags do not authenticate a masterchain identity. An explicitly pinned
/// checkpoint is a separate trust source from an unpinned finality certificate.
pub(crate) async fn check_applied_masterchain(
    engine: &dyn EngineOperations,
    expected: &BlockIdExt,
) -> Result<()> {
    if !expected.shard().is_masterchain_ext() {
        fail!("Applied masterchain identity is not a full shard");
    }
    if expected.seq_no == 0 {
        if expected != engine.zerostate_id()? {
            fail!("Applied zerostate differs from network pin");
        }
        BootstrapAuthority::from_zerostate(expected, engine.load_mc_zero_state().await?)?;
        return Ok(());
    }
    let checkpoint = expected == engine.init_mc_block_id();
    let proof = crate::boot::load_history_proof(engine, expected, checkpoint, checkpoint).await?;
    if proof.id() != expected {
        fail!("Applied cache proof identity mismatch");
    }
    if checkpoint {
        proof.check_trusted_checkpoint(expected)
    } else {
        proof.check_proof(engine).await
    }
}

pub(crate) async fn check_block_proof_pair(
    engine: &dyn EngineOperations,
    expected: &BlockIdExt,
    block: &crate::block::BlockStuff,
    proof: &BlockProofStuff,
) -> Result<()> {
    block.verify_expected_id(expected)?;
    if proof.id() != expected {
        fail!("Block proof does not match the requested block identity");
    }
    proof.check_proof(engine).await
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct BlockProofStuff {
    proof: BlockProof,
    root: Cell,
    is_link: bool,
    id: BlockIdExt,
    data: Arc<Vec<u8>>,
}

impl BlockProofStuff {
    pub fn deserialize(block_id: &BlockIdExt, data: Vec<u8>, is_link: bool) -> Result<Self> {
        let data = Arc::new(data);
        let root = BocReader::new().read(&*data)?.withdraw_single_root()?;
        let proof = BlockProof::construct_from_cell(root.clone())?;
        if &proof.proof_for != block_id {
            fail!(NodeError::InvalidData(format!(
                "proof for another block (found: {}, expected: {})",
                proof.proof_for, block_id
            )))
        }
        if !block_id.is_masterchain() && !is_link {
            fail!(NodeError::InvalidData(format!("proof for non-masterchain block {}", block_id)))
        }
        Ok(BlockProofStuff { proof, root, is_link, id: block_id.clone(), data })
    }

    pub(crate) fn deserialize_bounded(
        block_id: &BlockIdExt,
        data: Vec<u8>,
        is_link: bool,
        budget: &crate::history_read_budget::HistoryReadBudget,
    ) -> Result<Self> {
        budget.proof_bytes(&data)?;
        let root = budget.parse_boc(&data)?;
        let proof = BlockProof::construct_from_cell_bounded(root.clone(), &ConfigBudget(budget))?;
        if &proof.proof_for != block_id || (!block_id.is_masterchain() && !is_link) {
            fail!("Bounded proof identity/type mismatch");
        }
        Ok(Self { proof, root, is_link, id: block_id.clone(), data: Arc::new(data) })
    }

    pub(crate) fn deserialize_local_artifact(
        block_id: &BlockIdExt,
        data: Vec<u8>,
        budget: &crate::history_read_budget::HistoryReadBudget,
    ) -> Result<Self> {
        Self::deserialize_local_history(block_id, data, false, budget)
    }

    /// Ordinary archive bytes are replaceable evidence, not authenticated
    /// authority. Parse failure may use another source under the SAME budget.
    pub(crate) fn deserialize_local_history(
        block_id: &BlockIdExt,
        data: Vec<u8>,
        is_link: bool,
        budget: &crate::history_read_budget::HistoryReadBudget,
    ) -> Result<Self> {
        budget.proof_bytes(&data)?;
        let root = budget.parse_local_artifact(&data)?;
        let proof = BlockProof::construct_from_cell_bounded(root.clone(), &ConfigBudget(budget))?;
        if &proof.proof_for != block_id || (!block_id.is_masterchain() && !is_link) {
            fail!("Local artifact proof identity/type mismatch");
        }
        Ok(Self { proof, root, is_link, id: block_id.clone(), data: Arc::new(data) })
    }

    pub fn new(proof: BlockProof, is_link: bool) -> Result<Self> {
        let id = proof.proof_for.clone();
        if !id.is_masterchain() && !is_link {
            fail!(NodeError::InvalidData(format!("proof for non-masterchain block {}", id)))
        }
        let cell = proof.serialize()?;
        let data = Arc::new(write_boc(&cell)?);
        Ok(Self { root: proof.serialize()?, proof, is_link, id, data })
    }

    #[cfg(test)]
    pub fn read_from_file(block_id: &BlockIdExt, filename: &str, is_link: bool) -> Result<Self> {
        let data = std::fs::read(filename)?;
        Self::deserialize(block_id, data, is_link)
    }

    #[cfg(test)]
    pub fn fake(id: &BlockIdExt) -> Result<Self> {
        let proof = BlockProof { proof_for: id.clone(), root: Cell::default(), signatures: None };
        let cell = proof.serialize()?;
        let data = Arc::new(write_boc(&cell)?);
        Ok(Self {
            root: proof.serialize()?,
            proof,
            is_link: !id.shard().is_masterchain(),
            id: id.clone(),
            data,
        })
    }

    // Unused
    //    pub fn root(&self) -> &Cell {
    //        &self.root
    //    }

    pub fn merkle_proof_root_cell(&self) -> &Cell {
        &self.proof.root
    }

    pub fn root_cell(&self) -> &Cell {
        &self.root
    }

    pub fn virtualize_block(&self) -> Result<(Block, Cell)> {
        let merkle_proof = MerkleProof::construct_from_cell(self.proof.root.clone())?;
        let block_virt_root = merkle_proof.proof.clone().virtualize(1);
        if *self.proof.proof_for.root_hash() != *block_virt_root.repr_hash() {
            fail!(NodeError::InvalidData(format!(
                "merkle proof has invalid virtual hash (found: {:x}, expected: {})",
                block_virt_root.repr_hash(),
                self.proof.proof_for
            )))
        }
        if *block_virt_root.repr_hash() != self.id().root_hash {
            fail!(NodeError::InvalidData(format!(
                "proof for block {} contains a Merkle proof with incorrect root hash: \
                expected {:x}, found: {:x} ",
                self.id(),
                self.id().root_hash,
                block_virt_root.repr_hash()
            )))
        }
        Ok((Block::construct_from_cell(block_virt_root.clone())?, block_virt_root))
    }

    pub fn get_config_params(&self) -> Result<ConfigParams> {
        let (virt_block, _) = self.virtualize_block()?;
        self.read_config_params(&virt_block)
    }

    pub fn is_link(&self) -> bool {
        self.is_link
    }

    pub fn id(&self) -> &BlockIdExt {
        &self.id
    }

    pub(crate) fn clone_with_budget(&self, budget: ProofBudget<'_>) -> Result<Self> {
        if let Some(budget) = budget {
            use rtos_block::merkle_apply_budget::MerkleApplyBudget;
            budget.step()?;
            if let Some(BlockSignaturesVariant::SimplexPq(carrier)) = &self.proof.signatures {
                budget.workspace(
                    carrier
                        .signatures
                        .len()
                        .checked_mul(std::mem::size_of::<rtos_block::PqBlockSignaturePair>())
                        .ok_or_else(|| error!("Proof clone size overflow"))?,
                )?;
                for signature in &carrier.signatures {
                    budget.step()?;
                    budget.workspace(signature.signature.len())?;
                }
            }
        }
        Ok(self.clone())
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn drain_signatures(self) -> Result<BlockSignaturesVariant> {
        self.proof.signatures.ok_or_else(|| error!("Proof doesn't contain signatures"))
    }

    /// The caller must authenticate the previous key block against its network
    /// anchor/history before using it as governing authority here.
    pub fn check_with_prev_key_block_proof(
        &self,
        prev_key_block_proof: &BlockProofStuff,
    ) -> Result<()> {
        let now = std::time::Instant::now();
        log::trace!("Checking proof for block: {}", self.id());

        let (virt_block, virt_block_info) = self.pre_check_block_proof()?;

        self.check_with_prev_key_block_proof_(
            prev_key_block_proof,
            &virt_block,
            &virt_block_info,
            None,
        )?;

        log::trace!(
            "Checked proof for block: {}   TIME {}ms",
            self.id(),
            now.elapsed().as_millis()
        );
        Ok(())
    }

    /// The caller must supply a master state authenticated against its selected
    /// network/history. A decoded state alone is not a trust anchor.
    pub fn check_with_master_state(&self, master_state: &ShardStateStuff) -> Result<()> {
        let now = std::time::Instant::now();
        log::trace!("Checking proof for block: {}", self.id());

        if self.is_link {
            fail!(NodeError::InvalidOperation(format!(
                "Can't verify block {}: can't call `check_with_master_state` for proof link",
                self.id()
            )))
        }

        let (virt_block, virt_block_info) = self.pre_check_block_proof()?;

        self.check_with_master_state_(master_state, &virt_block, &virt_block_info, None)?;

        log::trace!(
            "Checked proof for block: {}   TIME {}ms",
            self.id(),
            now.elapsed().as_millis()
        );
        Ok(())
    }

    /// Authenticate checkpoint contents against an explicitly trusted local pin.
    /// The pin itself is an out-of-band trust decision, not derived from this
    /// proof, a peer response, or a database resume cursor. This does not verify
    /// history before the checkpoint or the original full block's file bytes.
    pub(crate) fn check_trusted_checkpoint(&self, expected: &BlockIdExt) -> Result<()> {
        self.check_trusted_checkpoint_with_budget(expected, None)
    }

    fn check_trusted_checkpoint_with_budget(
        &self,
        expected: &BlockIdExt,
        budget: ProofBudget<'_>,
    ) -> Result<()> {
        if self.id() != expected || !expected.shard().is_masterchain_ext() || expected.seq_no == 0 {
            fail!("Checkpoint proof differs from the explicitly pinned masterchain identity");
        }
        let (block, info) = self.pre_check_block_proof_with_budget(budget)?;
        if !info.key_block() {
            fail!("Checkpoint must be a key block");
        }
        self.pre_check_key_block_proof_with_budget(&block, budget)?;
        let config = self.read_config_params(&block)?;
        config_lookup(budget)?;
        match config.config(19)? {
            Some(rtos_block::ConfigParamEnum::ConfigParam19(id))
                if id == block.global_id() as u32 => {}
            _ => fail!("Checkpoint global_id disagrees with missing or mismatched Param19"),
        }
        Ok(())
    }

    pub fn check_proof_as_link(&self) -> Result<()> {
        let now = std::time::Instant::now();
        log::trace!("Checking proof for block: {}", self.id());

        if self.is_link {
            fail!(NodeError::InvalidOperation(format!(
                "Can't call `check_proof_as_link` not for proof, block {}",
                self.id()
            )))
        }
        self.pre_check_block_proof()?;
        log::trace!(
            "Checked proof as link for block: {}   TIME {}ms",
            self.id(),
            now.elapsed().as_millis()
        );
        Ok(())
    }

    pub fn check_proof_link(&self) -> Result<()> {
        let now = std::time::Instant::now();
        log::trace!("Checking proof for block: {}", self.id());

        if !self.is_link {
            fail!(NodeError::InvalidOperation(format!(
                "Can't call `check_proof_link` not for proof link, block {}",
                self.id()
            )))
        }
        self.pre_check_block_proof()?;
        log::trace!(
            "Checked proof link for block: {}   TIME {}ms",
            self.id(),
            now.elapsed().as_millis()
        );
        Ok(())
    }

    pub async fn check_proof(&self, engine: &dyn EngineOperations) -> Result<()> {
        if self.id().is_masterchain() {
            engine.check_masterchain_proof(self).await
        } else {
            self.check_proof_link()
        }
    }

    // Unused
    //    pub fn get_cur_validators_set(&self) -> Result<(ValidatorSet, CatchainConfig)> {
    //        let (virt_key_block, prev_key_block_info) = self.pre_check_block_proof()?;
    //        if !prev_key_block_info.key_block() {
    //            fail!(NodeError::InvalidData(format!(
    //                "proof for key block {} contains a Merkle proof which declares non key block",
    //                self.id(),
    //            )))
    //        }
    //        let (cur_validator_set, cc_config) = virt_key_block.read_cur_validator_set_and_cc_conf()
    //            .map_err(|err| {
    //                NodeError::InvalidData(format!(
    //                    "Сan't extract config params from key block's proof {}: {}",
    //                    self.id, err
    //                ))
    //            })?;
    //        Ok((cur_validator_set, cc_config))
    //    }

    fn check_with_prev_key_block_proof_(
        &self,
        prev_key_block_proof: &BlockProofStuff,
        virt_block: &Block,
        virt_block_info: &BlockInfo,
        budget: ProofBudget<'_>,
    ) -> Result<()> {
        if !self.id().is_masterchain() {
            fail!(NodeError::InvalidData(format!(
                "Can't verify non masterchain block {} using previous key masterchain block",
                self.id()
            )))
        }
        if !prev_key_block_proof.id().is_masterchain() {
            fail!(NodeError::InvalidData(format!(
                "Invalid previous key block: it's id {} doesn't belong to the masterchain",
                prev_key_block_proof.id()
            )))
        }
        let prev_key_block_seqno = virt_block.read_info()?.prev_key_block_seqno();
        if prev_key_block_proof.id().seq_no != prev_key_block_seqno {
            fail!(NodeError::InvalidData(format!(
                "Can't verify block {} using key block {} \
                because the block declares different previous key block seqno {}",
                self.id(),
                prev_key_block_proof.id(),
                prev_key_block_seqno
            )))
        }
        if prev_key_block_proof.id().seq_no >= self.id().seq_no {
            fail!(NodeError::InvalidData(format!(
                "Can't verify block {} using key block {} with larger or equal seqno",
                self.id(),
                prev_key_block_proof.id()
            )))
        }

        let (subset, virt_prev_key_block) =
            self.process_prev_key_block_proof(prev_key_block_proof, budget)?;

        if virt_prev_key_block.read_info()?.gen_utime() > virt_block_info.gen_utime() {
            fail!(NodeError::InvalidData(format!(
                "Can't verify block {} using key block {} with larger gen_utime",
                self.id(),
                prev_key_block_proof.id()
            )))
        }

        if virt_block_info.key_block() {
            self.pre_check_key_block_proof_with_budget(virt_block, budget)?;
        }

        if let Some(BlockSignaturesVariant::SimplexPq(carrier)) = &self.proof.signatures {
            if virt_block.global_id() != virt_prev_key_block.global_id() {
                fail!("PQ target global_id differs from governing key block");
            }
            let config = prev_key_block_proof.read_config_params(&virt_prev_key_block)?;
            let context = pq_context(
                virt_prev_key_block.global_id(),
                &config,
                self.id.clone(),
                virt_block_info.vert_seq_no(),
                virt_block_info.prev_key_block_seqno(),
                carrier.validator_info.catchain_seqno,
                budget,
            )?;
            match budget {
                Some(budget) => context.verify_final_bounded(carrier, &ConfigBudget(budget))?,
                None => context.verify_final(carrier)?,
            };
            return Ok(());
        }
        self.check_signatures_with_budget(&subset, budget)
    }

    fn check_with_master_state_(
        &self,
        master_state: &ShardStateStuff,
        virt_block: &Block,
        virt_block_info: &BlockInfo,
        budget: ProofBudget<'_>,
    ) -> Result<()> {
        if virt_block_info.key_block() {
            self.pre_check_key_block_proof_with_budget(virt_block, budget)?;
        }
        let subset = self.process_given_state(master_state, virt_block_info, budget)?;
        if let Some(BlockSignaturesVariant::SimplexPq(carrier)) = &self.proof.signatures {
            let extra = master_state.shard_state_extra()?;
            let governing_key_seqno = if extra.after_key_block {
                master_state.block_id().seq_no
            } else {
                extra.last_key_block.as_ref().map(|key| key.seq_no).unwrap_or(0)
            };
            if governing_key_seqno != virt_block_info.prev_key_block_seqno() {
                fail!("PQ governing state belongs to a different key-block epoch");
            }
            let global_id = master_state.state()?.global_id();
            if virt_block.global_id() != global_id {
                fail!("PQ target global_id differs from governing state");
            }
            let context = pq_context(
                global_id,
                master_state.config_params()?,
                self.id.clone(),
                virt_block_info.vert_seq_no(),
                virt_block_info.prev_key_block_seqno(),
                carrier.validator_info.catchain_seqno,
                budget,
            )?;
            match budget {
                Some(budget) => context.verify_final_bounded(carrier, &ConfigBudget(budget))?,
                None => context.verify_final(carrier)?,
            };
            return Ok(());
        }
        self.check_signatures_with_budget(&subset, budget)
    }

    fn pre_check_block_proof(&self) -> Result<(Block, BlockInfo)> {
        self.pre_check_block_proof_with_budget(None)
    }

    fn pre_check_block_proof_with_budget(
        &self,
        budget: ProofBudget<'_>,
    ) -> Result<(Block, BlockInfo)> {
        if !self.id().is_masterchain() && self.proof.signatures.is_some() {
            fail!(NodeError::InvalidData(format!(
                "proof for non-master block {} can't contain signatures",
                self.id(),
            )))
        }
        let (virt_block, virt_block_root) = self.virtualize_block()?;
        let info = Self::pre_check_virtual_block_with_budget(
            self.id(),
            &virt_block,
            &virt_block_root,
            budget,
        )?;
        Ok((virt_block, info))
    }

    fn pre_check_virtual_block(
        id: &BlockIdExt,
        virt_block: &Block,
        virt_block_root: &Cell,
    ) -> Result<BlockInfo> {
        Self::pre_check_virtual_block_with_budget(id, virt_block, virt_block_root, None)
    }
    fn pre_check_virtual_block_with_budget(
        id: &BlockIdExt,
        virt_block: &Block,
        virt_block_root: &Cell,
        budget: ProofBudget<'_>,
    ) -> Result<BlockInfo> {
        if let Some(budget) = budget {
            budget.step()?;
        }

        if *virt_block_root.repr_hash() != id.root_hash {
            fail!(NodeError::InvalidData(format!(
                "proof for block {} contains a Merkle proof with incorrect root hash: \
                expected {:x}, found: {:x} ",
                id,
                id.root_hash,
                virt_block_root.repr_hash()
            )))
        }

        let info = virt_block.read_info()?;
        let value_flow = virt_block.read_value_flow()?;
        match budget {
            Some(budget) => value_flow.read_in_full_depth_bounded(&ConfigBudget(budget)),
            None => value_flow.read_in_full_depth(),
        }
        .map_err(|e| e.context("Can't read value flow in full depth"))?;
        let _state_update = virt_block.read_state_update()?;

        if info.version() != 0 {
            fail!(NodeError::InvalidData(format!(
                "proof for block {} contains a Merkle proof \
                with incorrect block info's version {}",
                id,
                info.version()
            )))
        }

        if info.seq_no() != id.seq_no {
            fail!(NodeError::InvalidData(format!(
                "proof for block {} contains a Merkle proof with seq_no {}, but {} is expected",
                id,
                info.seq_no(),
                id.seq_no
            )))
        }

        if info.shard() != id.shard() {
            fail!(NodeError::InvalidData(format!(
                "proof for block {} contains a Merkle proof with shard id {}, but {} is expected",
                id,
                info.shard(),
                id.shard()
            )))
        }

        if info.read_master_ref()?.is_some() == info.shard().is_masterchain() {
            fail!(NodeError::InvalidData(format!(
                "proof for block {} contains a Merkle proof \
                with invalid not_master flag in block info",
                id,
            )))
        }

        if id.is_masterchain() && (info.after_merge() || info.before_split() || info.after_split())
        {
            fail!(NodeError::InvalidData(format!(
                "proof for block {} contains a Merkle proof with a block info \
                which declares split/merge for a masterchain block",
                id,
            )))
        }

        if info.after_merge() && info.after_split() {
            fail!(NodeError::InvalidData(format!(
                "proof for block {} contains a Merkle proof with a block info \
                which declares both after merge and after split flags",
                id,
            )))
        }

        if info.after_split() && (info.shard().is_full()) {
            fail!(NodeError::InvalidData(format!(
                "proof for block {} contains a Merkle proof with a block info \
                which declares both after_split flag and non zero shard prefix",
                id,
            )))
        }

        if info.after_merge() && !info.shard().can_split() {
            fail!(NodeError::InvalidData(format!(
                "proof for block {} contains a Merkle proof with a block info \
                which declares both after_merge flag and shard prefix which can't split anymore",
                id,
            )))
        }

        if info.key_block() && !id.is_masterchain() {
            fail!(NodeError::InvalidData(format!(
                "proof for block {} contains a Merkle proof \
                which declares non master chain but key block",
                id,
            )))
        }

        if info.gen_utime() == 0 {
            fail!(NodeError::InvalidData(format!(
                "proof for block {} contains a Merkle proof with zero gen_utime",
                id,
            )))
        }

        Ok(info)
    }

    fn read_config_params(&self, virt_block: &Block) -> Result<ConfigParams> {
        let extra = virt_block.read_extra()?;
        let mut mc_extra = extra.read_custom()?.ok_or_else(|| {
            NodeError::InvalidData(format!(
                "proof for key block {} contains a Merkle proof without masterchain block extra",
                self.id(),
            ))
        })?;
        let config = mc_extra.config_mut().take().ok_or_else(|| {
            NodeError::InvalidData(format!(
                "proof for key block {} contains a Merkle proof without config params",
                self.id(),
            ))
        })?;
        Ok(config)
    }

    fn pre_check_key_block_proof(&self, virt_block: &Block) -> Result<()> {
        self.pre_check_key_block_proof_with_budget(virt_block, None)
    }

    fn pre_check_key_block_proof_with_budget(
        &self,
        virt_block: &Block,
        budget: ProofBudget<'_>,
    ) -> Result<()> {
        let config = self.read_config_params(virt_block)?;
        if let Some(budget) = budget {
            let budget = ConfigBudget(budget);
            config
                .config_validator_set_bounded(34, &budget)?
                .ok_or_else(|| error!("Key proof lacks current validators Param34"))?;
            for param in 32..=37 {
                config.config_validator_set_bounded(param, &budget)?;
            }
            config.config_cell_bounded(38, &budget)?;
            // Param28 is optional here, exactly like config(28) in the ordinary path.
            if config.config_cell_bounded(28, &budget)?.is_some() {
                config.catchain_config_bounded(&budget)?;
            }
            return Ok(());
        }
        let _cur_validator_set = config.config(34)?.ok_or_else(|| {
            NodeError::InvalidData(format!(
                "proof for key block {} contains a Merkle proof \
                without current validators config param (34)",
                self.id(),
            ))
        })?;
        for i_config in 32..=38 {
            let _val_set = config.config(i_config)?;
        }
        let _catchain_config = config.config(28)?;

        Ok(())
    }

    fn process_prev_key_block_proof(
        &self,
        prev_key_block_proof: &BlockProofStuff,
        budget: ProofBudget<'_>,
    ) -> Result<(ValidatorSubsetInfo, Block)> {
        let (virt_key_block, prev_key_block_info) =
            prev_key_block_proof.pre_check_block_proof_with_budget(budget)?;

        if !prev_key_block_info.key_block() {
            fail!(NodeError::InvalidData(format!(
                "proof for key block {} contains a Merkle proof which declares non key block",
                prev_key_block_proof.id(),
            )))
        }

        if budget.is_some() {
            let config = prev_key_block_proof.read_config_params(&virt_key_block)?;
            let subset = proof_subset(
                &config,
                self.proof
                    .signatures
                    .as_ref()
                    .map(|s| s.validator_info().catchain_seqno)
                    .unwrap_or(0),
                budget,
            )?;
            return Ok((subset, virt_key_block));
        }
        let (validator_set, _cc_config) =
            virt_key_block.read_cur_validator_set_and_cc_conf().map_err(|err| {
                NodeError::InvalidData(format!(
                    "While checking proof for {}: \
                    can't extract config params from key block's proof {}: {}",
                    self.id,
                    prev_key_block_proof.id(),
                    err
                ))
            })?;

        let config = virt_key_block
            .read_extra()?
            .read_custom()?
            .and_then(|custom| custom.config().cloned())
            .ok_or_else(|| {
                error!(NodeError::InvalidArg("State doesn't contain `custom` field".to_string()))
            })?;

        let subset = calc_subset_for_masterchain(
            &validator_set,
            &config,
            self.proof.signatures.as_ref().map(|s| s.validator_info().catchain_seqno).unwrap_or(0),
        )?;

        Ok((subset, virt_key_block))
    }

    fn check_signatures(&self, subset: &ValidatorSubsetInfo) -> Result<()> {
        self.check_signatures_with_budget(subset, None)
    }
    fn check_signatures_with_budget(
        &self,
        subset: &ValidatorSubsetInfo,
        budget: ProofBudget<'_>,
    ) -> Result<()> {
        // Pre checks
        if self.proof.signatures.is_none() {
            fail!(NodeError::InvalidData(format!(
                "Proof for {} doesn't have signatures to check",
                self.id(),
            )));
        }
        let signatures = self.proof.signatures.as_ref().unwrap();
        if signatures.validator_info().validator_list_hash_short != subset.short_hash {
            fail!(NodeError::InvalidData(format!(
                "Bad validator set hash in proof for block {}, calculated: {}, found: {}",
                self.id(),
                subset.short_hash,
                signatures.validator_info().validator_list_hash_short
            )));
        }
        let expected_count = signatures.pure_signatures()?.count() as usize;
        let count = match budget {
            Some(budget) => {
                signatures.pure_signatures()?.signatures_count_bounded(&ConfigBudget(budget))?
            }
            None => signatures.pure_signatures()?.signatures().count(expected_count)?,
        };
        if expected_count != count {
            fail!(NodeError::InvalidData(format!(
                "Proof for {}: signature count mismatch: declared: {}, calculated: {}",
                self.id(),
                expected_count,
                count
            )));
        }

        // Generate checked_data based on signature variant
        if let Some(budget) = budget {
            use rtos_block::merkle_apply_budget::MerkleApplyBudget;
            // Ordinary preimage is 68 bytes. Classical Simplex's CellString decoder
            // visits at most 16 cells, each copying at most 127 bytes; its 1024-byte
            // limit is checked after append, so charge growth through 2048 capacity
            // (sum of all geometric allocations <=4096), plus each chunk copy.
            // CandidateHashData is fixed-field; vote/DataToSign are under 256 bytes
            // each, with both serialization growth sequences charged below.
            let (steps, workspace) = match signatures {
                BlockSignaturesVariant::Ordinary(_) => (1, 68),
                BlockSignaturesVariant::Simplex(_) => (16 + 3, 4096 + 16 * 127 + 2 * 512),
                BlockSignaturesVariant::SimplexPq(_) => unreachable!(),
            };
            rtos_block::config_read_budget::steps(&ConfigBudget(budget), steps)?;
            budget.workspace(workspace)?;
        }
        let checked_data = build_checked_data(signatures, &self.id).map_err(|err| {
            NodeError::InvalidData(format!(
                "Proof for {}: failed to build checked_data: {err}",
                self.id()
            ))
        })?;

        let total_weight: u64 =
            rtos_block::checked_validator_weight_sum(subset.validators.iter().map(|v| v.weight))?;
        let weight = match budget {
            Some(budget) => signatures.pure_signatures()?.check_signatures_bounded(
                &subset.validators,
                &checked_data,
                &ConfigBudget(budget),
            )?,
            None => {
                signatures.pure_signatures()?.check_signatures(&subset.validators, &checked_data)?
            }
        };

        // Check weight
        if weight != signatures.pure_signatures()?.weight() {
            fail!(NodeError::InvalidData(format!(
                "Proof for {}: total signature weight mismatch: declared: {}, calculated: {}",
                self.id(),
                signatures.pure_signatures()?.weight(),
                weight
            )));
        }

        if !rtos_block::has_quorum(weight, total_weight) {
            fail!(NodeError::InvalidData(format!(
                "Proof for {}: too small signatures weight",
                self.id(),
            )));
        }

        Ok(())
    }

    fn process_given_state(
        &self,
        state: &ShardStateStuff,
        block_info: &BlockInfo,
        budget: ProofBudget<'_>,
    ) -> Result<ValidatorSubsetInfo> {
        // Checks
        if !state.block_id().is_masterchain() {
            fail!(NodeError::InvalidData(format!(
                "Can't check proof for {}: given state {} doesn't belong masterchain",
                self.id(),
                state.block_id()
            )));
        }
        if !self.id().is_masterchain() {
            fail!(NodeError::InvalidData(format!(
                "Can't check proof for non master block {} using master state",
                self.id(),
            )));
        }
        if state.block_id().seq_no < block_info.prev_key_block_seqno() {
            fail!(NodeError::InvalidData(format!(
                "Can't check proof for block {} using master state {}, \
                because it is older than the previous key block with seqno {}",
                self.id(),
                state.block_id(),
                block_info.prev_key_block_seqno()
            )));
        }
        if state.block_id().seq_no >= self.id().seq_no {
            fail!(NodeError::InvalidData(format!(
                "Can't check proof for block {} using newer master state {}",
                self.id(),
                state.block_id(),
            )));
        }

        if budget.is_some() {
            return proof_subset(
                state.config_params()?,
                self.proof
                    .signatures
                    .as_ref()
                    .map(|s| s.validator_info().catchain_seqno)
                    .unwrap_or(0),
                budget,
            );
        }
        let (cur_validator_set, _cc_config) =
            state.state()?.read_cur_validator_set_and_cc_conf()?;

        calc_subset_for_masterchain(
            &cur_validator_set,
            state.config_params()?,
            self.proof.signatures.as_ref().map(|s| s.validator_info().catchain_seqno).unwrap_or(0),
        )
    }
}

#[cfg(test)]
mod history_proof_budget_tests {
    use super::*;
    use crate::history_read_budget::{HistoryBudgetExceeded, HistoryReadLimits};

    #[test]
    fn history_proof_budget_counts_deep_signature_clones_cumulatively() {
        let mut proof = BlockProofStuff::default();
        proof.proof.signatures =
            Some(BlockSignaturesVariant::SimplexPq(rtos_block::BlockSignaturesSimplexPq {
                signatures: vec![rtos_block::PqBlockSignaturePair {
                    validator_id: UInt256::default(),
                    algorithm_id: 1,
                    signature: vec![7; 2048],
                }],
                ..Default::default()
            }));
        // A struct-only charge would admit both clones. The first full clone
        // fits, while the second exhausts the same request's workspace.
        let budget =
            HistoryReadBudget::new(HistoryReadLimits { cell_bytes: 3000, ..Default::default() });
        assert_eq!(proof.clone_with_budget(Some(&budget)).unwrap(), proof);
        let error = proof.clone_with_budget(Some(&budget)).unwrap_err();
        assert!(error.downcast_ref::<HistoryBudgetExceeded>().is_some());
        assert_eq!(proof.clone_with_budget(None).unwrap(), proof);
    }

    #[test]
    fn history_proof_budget_preserves_classical_weighted_quorum_and_refuses_exhaustion() {
        use rtos_block::{
            BlockSignatures, BlockSignaturesPure, CryptoSignature, CryptoSignaturePair,
            Ed25519KeyOption, ShardIdent, SigPubKey, ValidatorBaseInfo, ValidatorDescr,
            ZeroizingBytes,
        };
        let keys: Vec<_> =
            (0..3).map(|_| Ed25519KeyOption::<ZeroizingBytes>::generate().unwrap()).collect();
        let subset = ValidatorSubsetInfo {
            short_hash: 42,
            validators: keys
                .iter()
                .enumerate()
                .map(|(i, key)| {
                    ValidatorDescr::with_params(
                        SigPubKey::from_bytes(key.pub_key().unwrap()).unwrap(),
                        (i + 1) as u64,
                        None,
                    )
                })
                .collect(),
        };
        let id = BlockIdExt::with_params(
            ShardIdent::masterchain(),
            1,
            UInt256::from([1; 32]),
            UInt256::from([2; 32]),
        );
        let data = Block::build_data_for_sign(&id.root_hash, &id.file_hash);
        for (signers, accepted) in [(vec![0, 2], true), (vec![0, 1], false), (vec![0, 0, 2], false)]
        {
            let mut signatures = BlockSignaturesPure::default();
            let mut weight = 0;
            for i in signers {
                signatures.add_sigpair(CryptoSignaturePair {
                    node_id_short: subset.validators[i].compute_node_id_short().unwrap(),
                    sign: CryptoSignature::from_bytes(&keys[i].sign(&data).unwrap()).unwrap(),
                });
                weight += subset.validators[i].weight;
            }
            signatures.set_weight(weight);
            let proof = BlockProofStuff::new(
                BlockProof::with_ordinary_signatures(
                    id.clone(),
                    Cell::default(),
                    Some(BlockSignatures::with_params(
                        ValidatorBaseInfo::with_params(42, 0),
                        signatures,
                    )),
                ),
                false,
            )
            .unwrap();
            assert_eq!(proof.check_signatures(&subset).is_ok(), accepted);
            assert_eq!(
                proof
                    .check_signatures_with_budget(
                        &subset,
                        Some(&HistoryReadBudget::new(Default::default()))
                    )
                    .is_ok(),
                accepted
            );
            if accepted {
                let empty =
                    HistoryReadBudget::new(HistoryReadLimits { steps: 0, ..Default::default() });
                let error = proof.check_signatures_with_budget(&subset, Some(&empty)).unwrap_err();
                assert!(error.downcast_ref::<HistoryBudgetExceeded>().is_some());
            }
        }
    }
}
