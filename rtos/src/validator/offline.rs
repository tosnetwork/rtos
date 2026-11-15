// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Explicit-state execution of the node's candidate validator. No database or peer is consulted.
use super::{
    validate_query::{ValidateQuery, ValidatedCandidate},
    BlockCandidate,
};
use crate::{
    collator_test_bundle::create_engine_allocated,
    engine_traits::{EngineAlloc, EngineOperations},
    shard_state::ShardStateStuff,
};
#[cfg(feature = "telemetry")]
use crate::{collator_test_bundle::create_engine_telemetry, engine_traits::EngineTelemetry};
use anyhow::{ensure, Result};
use rtos_block::{BlockIdExt, Cell, OutMsgQueue, UInt256, ValidatorSet};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Debug, thiserror::Error)]
#[error("offline validation input not served: {0}")]
pub struct InputUnavailable(pub String);

pub enum Outcome {
    Accepted(ValidatedCandidate),
    Failed(anyhow::Error),
}

pub struct Request {
    pub candidate: BlockCandidate,
    pub prev: Vec<BlockIdExt>,
    pub min_masterchain: BlockIdExt,
    pub top_masterchain: BlockIdExt,
    pub validator_set_from: BlockIdExt,
    pub skip_shard_signatures: bool,
    pub states: Vec<(BlockIdExt, Cell)>,
}

struct Provider {
    roots: HashMap<BlockIdExt, Cell>,
    top: BlockIdExt,
    allocated: Arc<EngineAlloc>,
    #[cfg(feature = "telemetry")]
    telemetry: Arc<EngineTelemetry>,
    requests: Mutex<Vec<BlockIdExt>>,
    split_queues: Mutex<HashMap<BlockIdExt, (OutMsgQueue, OutMsgQueue, ahash::AHashSet<UInt256>)>>,
}
impl Provider {
    fn state(&self, id: &BlockIdExt) -> Result<Arc<ShardStateStuff>> {
        self.requests.lock().unwrap().push(id.clone());
        let root = self.roots.get(id).ok_or_else(|| InputUnavailable(id.to_string()))?;
        ShardStateStuff::from_root_cell_for_validation(
            id.clone(),
            root.clone(),
            #[cfg(feature = "telemetry")]
            &self.telemetry,
            &self.allocated,
        )
    }
}
#[async_trait::async_trait]
impl EngineOperations for Provider {
    async fn wait_state(
        self: Arc<Self>,
        id: &BlockIdExt,
        _: Option<u64>,
        _: bool,
    ) -> Result<Arc<ShardStateStuff>> {
        self.state(id)
    }
    async fn load_state(&self, id: &BlockIdExt) -> Result<Arc<ShardStateStuff>> {
        self.state(id)
    }
    async fn load_last_applied_mc_state(&self) -> Result<Arc<ShardStateStuff>> {
        self.state(&self.top)
    }
    fn load_last_applied_mc_block_id(&self) -> Result<Option<Arc<BlockIdExt>>> {
        Ok(Some(Arc::new(self.top.clone())))
    }
    fn engine_allocated(&self) -> &Arc<EngineAlloc> {
        &self.allocated
    }
    #[cfg(feature = "telemetry")]
    fn engine_telemetry(&self) -> &Arc<EngineTelemetry> {
        &self.telemetry
    }
    fn db_cells_factory(&self) -> Result<Arc<dyn rtos_block::CellsFactory>> {
        anyhow::bail!("offline provider has no persistent cell factory")
    }
    fn get_split_queues(&self, id: &BlockIdExt) -> crate::engine::SplitQueues {
        self.split_queues.lock().unwrap().get(id).cloned()
    }
    fn set_split_queues(
        &self,
        id: &BlockIdExt,
        left: OutMsgQueue,
        right: OutMsgQueue,
        visited: ahash::AHashSet<UInt256>,
    ) {
        self.split_queues.lock().unwrap().insert(id.clone(), (left, right, visited));
    }
}

/// Every state is decoded when the validator asks for it, retaining pruned-cell failures.
/// Unknown requests fail; a supplied root does not acquire network authority.
pub async fn run(request: Request) -> Result<Outcome> {
    ensure!((1..=2).contains(&request.prev.len()), "one or two previous blocks required");
    ensure!(request.states.len() <= 32, "at most32states required");
    let mut roots = HashMap::new();
    for (id, root) in request.states {
        ensure!(roots.insert(id, root).is_none(), "duplicate supplied state");
    }
    ensure!(
        request.validator_set_from.shard().is_masterchain()
            && roots.contains_key(&request.validator_set_from),
        "validator_set_from must name a supplied masterchain state"
    );
    let provider = Arc::new(Provider {
        roots,
        top: request.top_masterchain,
        allocated: create_engine_allocated(),
        #[cfg(feature = "telemetry")]
        telemetry: create_engine_telemetry(),
        requests: Mutex::default(),
        split_queues: Mutex::default(),
    });
    let state = provider.state(&request.validator_set_from)?;
    let config = state.config_params()?;
    let extra = state.shard_state_extra()?;
    let shard = request.candidate.block_id.shard().clone();
    let cc = if shard.is_masterchain() {
        extra.validator_info.catchain_seqno
    } else {
        extra.shards.calc_shard_cc_seqno(&shard)?
    };
    let validators = config.compute_validator_set_cc(&shard, cc, &mut 0)?;
    ensure!(!validators.is_empty(), "validator_set_from: no validator set for candidate shard");
    let set = ValidatorSet::with_cc_seqno(0, 0, 0, cc, validators)?;
    let result = ValidateQuery::new(
        shard,
        request.min_masterchain.seq_no(),
        request.prev,
        None,
        request.candidate,
        set,
        provider,
        request.skip_shard_signatures,
        false,
        false,
    )
    .validate_candidate()
    .await;
    Ok(match result {
        Ok(v) => Outcome::Accepted(v),
        Err(e) => Outcome::Failed(e),
    })
}
