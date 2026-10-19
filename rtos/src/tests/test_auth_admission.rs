// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! AUTH policy admission of adopted masterchain states, driven through the
//! production adoption paths of a real emulator network.
//!
//! The emulator validator produces and stores an authenticated chain while its
//! own applies are held (see `parent_apply_tests::ApplyGate`); each test then
//! adopts blocks itself. A state's AUTH configuration is replaced through
//! `auth_admission::test_override`, which every admission read honours on
//! either side of a transition.
use super::*;
use crate::{
    auth_admission::test_override, error::AuthPolicyRefused,
    validator::validator_manager::emulator_network_bootstrap::EmulatorNetworkBootstrap,
};
use parent_apply_tests::ApplyGate;
use rtos_block::{
    AuthPolicy, ConfigParam8, ConfigParamEnum, ConfigParams, GlobalVersion, HashmapE, HashmapType,
    Serializable, SliceData,
};
use tokio::sync::oneshot;

struct Hold {
    seq_no: u32,
    entered: Option<oneshot::Sender<()>>,
    release: Option<oneshot::Receiver<()>>,
}

/// Scheduled holds inside masterchain adoption, plus the order in which heads
/// were published.
#[derive(Default)]
pub(crate) struct PublicationGate {
    admission: std::sync::Mutex<Option<Hold>>,
    publication: std::sync::Mutex<Option<Hold>>,
    heads: std::sync::Mutex<Vec<u32>>,
}

impl PublicationGate {
    fn arm(
        slot: &std::sync::Mutex<Option<Hold>>,
        seq_no: u32,
    ) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (entered, entered_rx) = oneshot::channel();
        let (release_tx, release) = oneshot::channel();
        *slot.lock().unwrap() =
            Some(Hold { seq_no, entered: Some(entered), release: Some(release) });
        (entered_rx, release_tx)
    }

    async fn wait_at(slot: &std::sync::Mutex<Option<Hold>>, id: &BlockIdExt) {
        let held = {
            let mut slot = slot.lock().unwrap();
            if slot.as_ref().is_some_and(|hold| hold.seq_no == id.seq_no) {
                slot.take()
            } else {
                None
            }
        };
        if let Some(mut hold) = held {
            if let Some(entered) = hold.entered.take() {
                let _ = entered.send(());
            }
            if let Some(release) = hold.release.take() {
                let _ = release.await;
            }
        }
    }
}

impl Engine {
    fn publication_gate(&self) -> Option<Arc<PublicationGate>> {
        self.mc_publication_test_gate.lock().unwrap().clone()
    }

    /// Before a masterchain block is admitted (outside the publication lock).
    pub(crate) async fn hold_mc_admission_for_test(&self, id: &BlockIdExt) {
        if let Some(gate) = self.publication_gate() {
            PublicationGate::wait_at(&gate.admission, id).await;
        }
    }

    /// After the block is marked applied, before the head is published.
    pub(crate) async fn hold_mc_publication_for_test(&self, id: &BlockIdExt) {
        if let Some(gate) = self.publication_gate() {
            PublicationGate::wait_at(&gate.publication, id).await;
        }
    }

    pub(crate) fn record_mc_head_for_test(&self, id: &BlockIdExt) {
        if let Some(gate) = self.publication_gate() {
            gate.heads.lock().unwrap().push(id.seq_no);
        }
    }
}

const NETWORK: [u8; 32] = [9; 32];

fn policy(sequence: u64, retired: u16, deadline: u32, network: [u8; 32]) -> AuthPolicy {
    AuthPolicy { network: UInt256::from(network), sequence, retired, deadline }
}

/// The emulator network launches with a scheduled, partly retired policy so
/// every rollback form is expressible against it.
fn base_policy() -> AuthPolicy {
    policy(5, 2, 200, NETWORK)
}

fn configure_policy(config: &mut ConfigParams) -> Result<()> {
    config.set_config(ConfigParamEnum::ConfigParam48(base_policy()))?;
    for number in [9, 10] {
        let mut map = HashmapE::with_bit_len(32);
        map.set(48u32.write_to_bitstring()?, &SliceData::default())?;
        let cell = map.data().cloned().ok_or_else(|| error!("empty membership"))?;
        config.set_config(ConfigParamEnum::ConfigParamAny(number, cell))?;
    }
    Ok(())
}

fn with_policy(base: &ConfigParams, policy: Option<AuthPolicy>) -> ConfigParams {
    let mut config = base.clone();
    match policy {
        Some(policy) => config.set_config(ConfigParamEnum::ConfigParam48(policy)).unwrap(),
        None => config.update_param(48, |param| *param = None).unwrap(),
    }
    config
}

fn with_required_version(base: &ConfigParams) -> ConfigParams {
    let mut config = with_policy(base, None);
    config
        .set_config(ConfigParamEnum::ConfigParam8(ConfigParam8 {
            global_version: GlobalVersion { version: 16, capabilities: 0 },
        }))
        .unwrap();
    config
}

/// Every refused form relative to `base_policy`, and why it is refused.
fn rollback_forms(base: &ConfigParams) -> Vec<(&'static str, ConfigParams)> {
    vec![
        ("sequence down", with_policy(base, Some(policy(4, 2, 200, NETWORK)))),
        ("sequence equal, policy changed", with_policy(base, Some(policy(5, 2, 150, NETWORK)))),
        ("network changed", with_policy(base, Some(policy(6, 2, 200, [8; 32])))),
        ("retired bit cleared", with_policy(base, Some(policy(6, 0, 200, NETWORK)))),
        ("deadline extended", with_policy(base, Some(policy(6, 2, 300, NETWORK)))),
        ("deadline cleared", with_policy(base, Some(policy(6, 2, 0, NETWORK)))),
        ("policy removed", with_policy(base, None)),
        ("required version without policy", with_required_version(base)),
    ]
}

async fn run_engine(
    bootstrap: &EmulatorNetworkBootstrap,
    stopper: Arc<Stopper>,
) -> Result<(Arc<Engine>, tokio::task::JoinHandle<()>)> {
    let flags =
        EngineFlags { initial_sync_disabled: true, force_check_db: false, truncate_db: None };
    run(
        bootstrap.load_node_config().await?,
        bootstrap.config_dir().to_str(),
        tokio::runtime::Handle::current(),
        tokio::runtime::Handle::current(),
        flags,
        stopper,
        None,
    )
    .await
}

struct Network {
    bootstrap: Arc<EmulatorNetworkBootstrap>,
    engine: Arc<Engine>,
    join: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    stopper: Arc<Stopper>,
    apply_gate: Arc<ApplyGate>,
    publication_gate: Arc<PublicationGate>,
}

impl Network {
    async fn start(blocks: u32) -> Result<Self> {
        let bootstrap = Arc::new(EmulatorNetworkBootstrap::build_with_config(4, |config, _| {
            configure_policy(config)
        })?);
        let stopper = Arc::new(Stopper::new());
        let (engine, join) = run_engine(&bootstrap, stopper.clone()).await?;
        let apply_gate = ApplyGate::new();
        *engine.parent_apply_test_gate.lock().unwrap() = Some(apply_gate.clone());
        let publication_gate = Arc::new(PublicationGate::default());
        *engine.mc_publication_test_gate.lock().unwrap() = Some(publication_gate.clone());
        let join = std::sync::Mutex::new(Some(join));
        let network = Self { bootstrap, engine, join, stopper, apply_gate, publication_gate };
        tokio::time::timeout(Duration::from_secs(60), network.apply_gate.target(blocks)).await?;
        Ok(network)
    }

    async fn id(&self, seq_no: u32) -> BlockIdExt {
        self.apply_gate.target(seq_no).await
    }

    async fn stuff(&self, seq_no: u32) -> Result<(Arc<BlockHandle>, BlockStuff)> {
        let id = self.id(seq_no).await;
        let handle = self.engine.load_block_handle(&id)?.ok_or_else(|| error!("no handle {id}"))?;
        let block = self.engine.load_block(&handle).await?;
        Ok((handle, block))
    }

    fn head(&self) -> Result<BlockIdExt> {
        let head = self.engine.load_last_applied_mc_block_id()?.ok_or_else(|| error!("no head"))?;
        assert_eq!(self.engine.get_last_applied_mc_seqno(), head.seq_no, "in-memory head");
        Ok(head.as_ref().clone())
    }

    fn is_applied(&self, id: &BlockIdExt) -> Result<bool> {
        Ok(self.engine.load_block_handle(id)?.is_some_and(|handle| handle.is_applied()))
    }

    /// Full application through the block awaiters, as concurrent callers use it.
    /// Depth 1 bypasses the hold that keeps the validator's own applies parked.
    fn apply(&self, seq_no: u32) -> tokio::task::JoinHandle<Result<()>> {
        let engine = self.engine.clone();
        let apply_gate = self.apply_gate.clone();
        tokio::spawn(async move {
            let id = apply_gate.target(seq_no).await;
            let handle = engine.load_block_handle(&id)?.ok_or_else(|| error!("no handle"))?;
            let block = engine.load_block(&handle).await?;
            engine.apply_block_internal(&handle, &block, seq_no, false, 1).await
        })
    }

    async fn base_config(&self, seq_no: u32) -> Result<ConfigParams> {
        let id = self.id(seq_no).await;
        Ok(self.engine.load_state(&id).await?.config_params()?.clone())
    }

    async fn stop(&self) -> Result<()> {
        self.apply_gate.release.close();
        *self.engine.parent_apply_test_gate.lock().unwrap() = None;
        *self.engine.mc_publication_test_gate.lock().unwrap() = None;
        self.stopper.set_stop();
        let join = self.join.lock().unwrap().take();
        if let Some(join) = join {
            let _ = tokio::time::timeout(Duration::from_secs(10), join).await;
        }
        self.engine.clone().wait_stop().await
    }
}

/// Runs `body` on its own task so a failed assertion still stops the network
/// before it is reported.
async fn with_network<Fut>(blocks: u32, body: impl FnOnce(Arc<Network>) -> Fut) -> Result<()>
where
    Fut: std::future::Future<Output = Result<()>> + Send + 'static,
{
    let _ = env_logger::builder().is_test(true).try_init();
    let network = Arc::new(Network::start(blocks).await?);
    let result = tokio::spawn(body(network.clone())).await;
    for seq_no in 1..=blocks {
        test_override::clear(&network.id(seq_no).await);
    }
    network.stop().await?;
    match result {
        Ok(result) => result,
        Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
        Err(error) => Err(error.into()),
    }
}

fn assert_refused(result: Result<()>, what: &str) {
    match result {
        Err(error) => {
            assert!(AuthPolicyRefused::is(&error), "{what}: untyped error {error:?}")
        }
        Ok(()) => panic!("{what}: adopted"),
    }
}

/// Two callers of block `seq_no`: the first owns the operation and is held (at
/// the admission of block `held`, itself or its parent) until the second has
/// registered as its waiter.
async fn apply_twice(network: &Network, held: u32, seq_no: u32) -> [Result<()>; 2] {
    let (entered, release) = PublicationGate::arm(&network.publication_gate.admission, held);
    let owner = network.apply(seq_no);
    tokio::time::timeout(Duration::from_secs(10), entered).await.unwrap().unwrap();
    let waiter = network.apply(seq_no);
    // The owner holds the awaiter entry; the second caller can only wait on it
    // (its own wait times out after 1 s, so release well before that).
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!waiter.is_finished());
    release.send(()).unwrap();
    [owner.await.unwrap(), waiter.await.unwrap()]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_admission_live_application() -> Result<()> {
    with_network(8, |network| async move {
        network.apply(2).await??;
        let two = network.id(2).await;
        assert_eq!(network.head()?, two);
        let base = network.base_config(3).await?;
        let three = network.id(3).await;
        let four = network.id(4).await;

        for (form, config) in rollback_forms(&base) {
            test_override::set(&three, config);
            for result in apply_twice(&network, 3, 3).await {
                assert_refused(result, form);
            }
            assert!(!network.is_applied(&three)?, "{form}");
            assert_eq!(network.head()?, two, "{form}");
            // The successor fails through its refused parent, for every waiter.
            for result in apply_twice(&network, 3, 4).await {
                assert_refused(result, form);
            }
            assert!(!network.is_applied(&four)?, "{form}");
            // A retry is refused again; the head does not move.
            assert_refused(network.apply(3).await?, form);
            assert_eq!(network.head()?, two, "{form}");
        }

        // A valid forward transition is adopted.
        let forward = with_policy(&base, Some(policy(6, 2, 100, NETWORK)));
        test_override::set(&three, forward.clone());
        network.apply(3).await??;
        assert_eq!(network.head()?, three);
        // Block 4 really carries the launch policy, which now rolls back the
        // adopted sequence 6 policy of its predecessor.
        assert_refused(network.apply(4).await?, "launch policy after forward transition");
        assert_eq!(network.head()?, three);
        // The identical policy cell with an equal sequence is accepted.
        test_override::set(&four, forward.clone());
        network.apply(4).await??;
        assert_eq!(network.head()?, four);

        // An adopted block is never admitted again.
        test_override::set(&three, with_policy(&base, Some(policy(4, 2, 200, NETWORK))));
        network.apply(3).await??;
        assert_eq!(network.head()?, four);

        // Pre-application computes and stores the state without adopting it;
        // the cached state does not bypass admission on full application.
        let (five_handle, five_block) = network.stuff(5).await?;
        let five = five_block.id().clone();
        test_override::set(&five, with_policy(&base, Some(policy(5, 2, 100, NETWORK))));
        network.engine.clone().apply_block_worker(&five_handle, &five_block, 5, true, 1).await?;
        assert!(five_handle.has_state() && !five_handle.is_applied());
        assert_refused(network.apply(5).await?, "full apply after pre-apply");
        assert!(!network.is_applied(&five)?);
        assert_eq!(network.head()?, four);

        // A block at or below the published head is already processed: it is
        // marked applied without admission and the head does not move back.
        let six = network.id(6).await;
        network.engine.save_last_applied_mc_block_id(&six)?;
        network.apply(5).await??;
        assert!(network.is_applied(&five)?);
        assert_eq!(network.head()?, six);
        network.engine.save_last_applied_mc_block_id(&five)?;
        test_override::clear(&five);

        // Publication order: block 6 is held after it is marked applied and
        // before its head is published, while block 7 proceeds. Block 7 must
        // neither be adopted nor publish its head before block 6 publishes.
        let (entered, release) = PublicationGate::arm(&network.publication_gate.publication, 6);
        let held = network.apply(6);
        tokio::time::timeout(Duration::from_secs(10), entered).await??;
        assert!(network.is_applied(&six)?);
        assert_eq!(network.head()?, five);
        let next = network.apply(7);
        tokio::time::sleep(Duration::from_millis(500)).await;
        let seven = network.id(7).await;
        assert!(!network.is_applied(&seven)?, "block 7 adopted before block 6 published");
        assert_eq!(network.head()?, five);
        release.send(()).unwrap();
        held.await??;
        next.await??;
        assert_eq!(network.head()?, seven);
        let heads = network.publication_gate.heads.lock().unwrap().clone();
        assert!(heads.windows(2).all(|pair| pair[0] < pair[1]), "head order {heads:?}");
        assert_eq!(heads.last(), Some(&7), "{heads:?}");
        Ok(())
    })
    .await
}

/// Re-issues a block as a crafted key block carrying `config`: same predecessor
/// and state update, new identity.
fn craft_key_block(block: &BlockStuff, config: &ConfigParams) -> Result<BlockStuff> {
    let mut crafted = block.block()?.clone();
    let mut info = crafted.read_info()?;
    info.set_key_block(true);
    crafted.write_info(&info)?;
    let mut extra = crafted.read_extra()?;
    let mut custom = extra.read_custom()?.ok_or_else(|| error!("no masterchain extra"))?;
    *custom.config_mut() = Some(config.clone());
    extra.write_custom(&custom)?;
    crafted.write_extra(&extra)?;
    let cell = crafted.serialize()?;
    let data = rtos_block::write_boc(&cell)?;
    let mut id = block.id().clone();
    id.root_hash = cell.repr_hash().clone();
    id.file_hash = UInt256::calc_file_hash(&data);
    BlockStuff::deserialize_block(id, Arc::new(data))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_admission_hardfork() -> Result<()> {
    with_network(4, |network| async move {
        let crafted_dir = tempfile::tempdir()?;
        network.apply(2).await??;
        let two = network.id(2).await;
        let (_, three) = network.stuff(3).await?;
        let base = network.base_config(2).await?;
        let crafted = craft_key_block(&three, &base)?;
        let crafted_id = crafted.id().clone();
        std::fs::write(
            crafted_dir.path().join(crafted_id.root_hash().as_hex_string()),
            crafted.data(),
        )?;
        let head = Arc::new(two.clone());
        let cursors = |engine: &Engine| -> Result<_> {
            Ok((engine.load_shard_client_mc_block_id()?, engine.load_pss_keeper_mc_block_id()?))
        };
        // No cursor may point past the kept predecessor.
        let cursors_kept = |engine: &Engine| -> Result<bool> {
            let (shard_client, keeper) = cursors(engine)?;
            Ok(shard_client.is_none_or(|id| id.seq_no <= 2)
                && keeper.is_none_or(|id| id.seq_no <= 2))
        };

        // Any other failure still fails boot: the stored ordinary block 3 is
        // not a key block.
        let error =
            crate::boot::check_hardfork(&network.engine, three.id(), &head, crafted_dir.path())
                .await
                .unwrap_err();
        assert!(!AuthPolicyRefused::is(&error), "{error}");

        // A refused restored base is fatal and is not repaired by the crafted block.
        test_override::set(&two, with_required_version(&base));
        let error =
            crate::boot::check_hardfork(&network.engine, &crafted_id, &head, crafted_dir.path())
                .await
                .unwrap_err();
        assert!(AuthPolicyRefused::is(&error), "{error}");
        assert!(!network.is_applied(&crafted_id)?);
        test_override::clear(&two);

        // A refused crafted block stays unapplied; boot continues from its
        // predecessor with every cursor where it was.
        for (form, config) in rollback_forms(&base) {
            test_override::set(&crafted_id, config);
            let kept = crate::boot::check_hardfork(
                &network.engine,
                &crafted_id,
                &head,
                crafted_dir.path(),
            )
            .await?;
            assert_eq!(kept.as_ref(), Some(&two), "{form}");
            assert!(!network.is_applied(&crafted_id)?, "{form}");
            assert_eq!(network.head()?, two, "{form}");
            assert!(cursors_kept(&network.engine)?, "{form}");
        }

        // An admissible crafted block is adopted.
        test_override::clear(&crafted_id);
        let adopted =
            crate::boot::check_hardfork(&network.engine, &crafted_id, &head, crafted_dir.path())
                .await?;
        assert_eq!(adopted.as_ref(), Some(&crafted_id));
        assert!(network.is_applied(&crafted_id)?);
        assert_eq!(network.head()?, crafted_id);
        test_override::clear(&crafted_id);
        Ok(())
    })
    .await
}

/// Starts the node and returns its startup diagnostic. A node that starts is
/// stopped again and reported as such, so the caller's assertion fails cleanly.
async fn startup_refusal(bootstrap: &EmulatorNetworkBootstrap) -> String {
    let stopper = Arc::new(Stopper::new());
    match run_engine(bootstrap, stopper.clone()).await {
        Ok((engine, join)) => {
            stopper.set_stop();
            let _ = tokio::time::timeout(Duration::from_secs(10), join).await;
            let _ = engine.wait_stop().await;
            "the node started with a refused masterchain state".to_string()
        }
        Err(error) => format!("{error:#}"),
    }
}

// Warm boot: the restored head is admitted before anything uses it, the
// refusal is fatal, and it recurs on every restart while the state is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_admission_refuses_restored_state() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    let network = Network::start(3).await?;
    network.apply(2).await??;
    let bootstrap = network.bootstrap.clone();
    // Stop with the apply gate still installed (open), so it keeps recording
    // every block adopted until the engine has stopped.
    network.apply_gate.release.close();
    network.stopper.set_stop();
    let join = network.join.lock().unwrap().take();
    if let Some(join) = join {
        let _ = tokio::time::timeout(Duration::from_secs(10), join).await;
    }
    network.engine.clone().wait_stop().await?;
    *network.engine.parent_apply_test_gate.lock().unwrap() = None;
    // Every block anything tried to adopt passed the apply gate, so the
    // restored head is among them, wherever recovery places it.
    let adopted: Vec<BlockIdExt> =
        network.apply_gate.seen.lock().unwrap().values().cloned().collect();
    assert!(!adopted.is_empty());
    // Release the database before reopening it.
    drop(network);
    let refused = with_required_version(&configured_policy_config()?);
    for id in &adopted {
        test_override::set(id, refused.clone());
    }
    for _ in 0..2 {
        let diagnostic = startup_refusal(&bootstrap).await;
        assert!(diagnostic.contains("refusing restored masterchain AUTH policy"), "{diagnostic}");
    }
    for id in &adopted {
        test_override::clear(id);
    }
    // The same database starts once the restored state is admissible.
    let stopper = Arc::new(Stopper::new());
    let (engine, join) = run_engine(&bootstrap, stopper.clone()).await?;
    stopper.set_stop();
    let _ = tokio::time::timeout(Duration::from_secs(10), join).await;
    engine.wait_stop().await
}

fn configured_policy_config() -> Result<ConfigParams> {
    let mut config = ConfigParams::default();
    configure_policy(&mut config)?;
    Ok(config)
}

// Cold boot: a zero state whose configuration is refused never becomes the
// initial trusted state, and the refusal is fatal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auth_admission_refuses_initial_state() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    let bootstrap = EmulatorNetworkBootstrap::build_with_config(4, |config, _| {
        config.set_config(ConfigParamEnum::ConfigParam8(ConfigParam8 {
            global_version: GlobalVersion { version: 16, capabilities: 0 },
        }))
    })?;
    let diagnostic = startup_refusal(&bootstrap).await;
    assert!(diagnostic.contains("refusing initial masterchain AUTH policy"), "{diagnostic}");
    Ok(())
}
