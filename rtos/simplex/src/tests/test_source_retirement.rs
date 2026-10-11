// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Retirement preparation over a real released masterchain source namespace.
use super::*;
use crate::finality_recovery::{ExpectedFinalityOutput, FinalityIntentStore};
use consensus_common::finality_delivery::{
    FinalityTerminalCompletion, FinalizedDeliveryCompletion,
};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Budget;
impl SourceHistoryDebtBudget for Budget {
    fn step(&self) -> Result<()> {
        Ok(())
    }
    fn workspace(&self, _: usize) -> Result<()> {
        Ok(())
    }
    fn read_bytes(&self, _: usize) -> Result<()> {
        Ok(())
    }
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(future)
}

struct Released {
    _dir: crate::authenticated_fixture::TestDirectory,
    runtime: Arc<AuthenticatedSessionRuntime>,
    namespace: PathBuf,
    teardown: StorageTeardownReceipt,
    id: UInt256,
    offer: CloseOffer,
    output_set: PathBuf,
}
impl Released {
    fn delivered(&self) -> PathBuf {
        self.namespace
            .join(DIRECTORY)
            .join(REFERENCE_DIRECTORY)
            .join(format!("{}.delivered", self.id.to_hex_string()))
    }
    fn scan(&self) -> Refusal<PendingRetirementScan> {
        scan_source_retirement(self.runtime.clone(), &self.namespace, &self.teardown, &Budget)
    }
    fn store_locked(&self) -> bool {
        PendingFinalityStore::lock(self.namespace.join(DIRECTORY)).unwrap().is_none()
    }
    fn snapshot(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        fn walk(path: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in std::fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                let file_type = entry.file_type().unwrap();
                if file_type.is_dir() {
                    walk(&entry.path(), out);
                } else if file_type.is_symlink() {
                    out.insert(entry.path(), b"<symlink>".to_vec());
                } else {
                    out.insert(entry.path(), std::fs::read(entry.path()).unwrap());
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(&self.namespace, &mut out);
        out
    }
    fn edit_json(path: &Path, edit: impl FnOnce(&mut serde_json::Value)) {
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        edit(&mut value);
        std::fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    }
}

/// Real manifest, torn-down database, Delivered + node confirmation, and a
/// sealed output set released by the real collection path.
fn released() -> Released {
    let dir = crate::authenticated_fixture::TestDirectory::new();
    let (runtime, draft) = crate::finality_delivery::tests::fixture();
    let namespace = PathBuf::from(runtime.runtime_directory(dir.path().to_str().unwrap()).unwrap());
    drop(crate::runtime_manifest::RuntimeManifest::open(&runtime, &namespace).unwrap());
    let database =
        crate::database::SimplexDb::open(&namespace, &runtime.session_id().to_hex_string())
            .unwrap();
    let teardown = database.teardown_receipt().unwrap();
    database.close(None).unwrap();
    drop(database);
    teardown.check().unwrap();

    let store = PendingFinalityStore::open(&namespace).unwrap();
    *store.runtime_binding.lock().unwrap() =
        runtime.recovery_binding().map(delivered::DiskRecoveryBinding::from_binding);
    let record = PendingFinalityRecord::from_draft(&runtime, &draft).unwrap();
    store.retain(&record).unwrap();
    let id = record.id().unwrap();
    let node_receipt = UInt256::from([0x44; 32]);
    store.acknowledge(&id, node_receipt.clone()).unwrap();
    let mut request = record.close_request(node_receipt).unwrap();
    request.domain = FinalityCloseDomain::from_runtime(&runtime);
    let offer = CloseOffer { request, generation: 1 };
    store.confirm_delivered_for_test(&runtime, &id, &offer).unwrap();

    let intents = FinalityIntentStore::new(&namespace);
    let slot = crate::block::SlotIndex::new(100);
    let hash = UInt256::from([7; 32]);
    // Structural certificate: retirement never re-verifies collected bytes.
    let event = crate::simplex_state::BlockFinalizedEvent {
        slot,
        block_hash: hash.clone(),
        block_id: None,
        certificate: Arc::new(crate::certificate::Certificate {
            vote: crate::simplex_state::FinalizeVote { slot, block_hash: hash.clone() },
            signatures: Vec::new(),
        }),
    };
    let trigger = crate::block::RawCandidateId { slot, hash: hash.clone() };
    let zerostate = runtime.pin().zerostate.clone();
    intents.retain(&runtime, vec![zerostate.clone()], zerostate, &event).unwrap();
    intents.resolve(&trigger).unwrap();
    intents
        .seal_outputs(
            &trigger,
            vec![ExpectedFinalityOutput::new(&record.block_id, true, &record.source_validator)],
        )
        .unwrap();
    intents.collect_delivered(&runtime, |_| Ok(true)).unwrap();
    drop(intents);
    drop(store);
    let output_set = namespace
        .join("finality-intents")
        .join("outputs-v1")
        .join(format!("100-{}.outputs", hash.to_hex_string()));
    assert!(output_set.is_file(), "real collection released the sealed set");
    Released { _dir: dir, runtime, namespace, teardown, id, offer, output_set }
}

struct Terminal<F>(F);
impl<F> DurableFinalitySink for Terminal<F>
where
    F: Fn(CloseFinalityRequest) -> Result<FinalityTerminalLookup> + Send + Sync,
{
    fn stage(&self, _: FinalizedDeliveryDraft, _: FinalizedDeliveryCompletion) -> Result<()> {
        fail!("staging is not part of retirement preparation")
    }
    fn lookup_terminal(
        &self,
        request: CloseFinalityRequest,
        completion: FinalityTerminalCompletion,
    ) -> Result<()> {
        completion((self.0)(request));
        Ok(())
    }
}

#[test]
fn source_retirement_released_namespace_issues_locked_preparation() {
    let fixture = released();
    let before = fixture.snapshot();
    let scan = fixture.scan().unwrap();
    assert_eq!(scan.inventory().len(), 1);
    assert_eq!(scan.inventory()[0].source_id, fixture.id);
    assert_eq!(scan.inventory()[0].offer, fixture.offer);
    assert!(fixture.store_locked(), "scan holds the store lock");
    assert!(matches!(fixture.scan(), Err(RetirementRefusal::Busy)));
    assert!(matches!(
        crate::runtime_manifest::RuntimeManifest::open_existing(
            &fixture.runtime,
            &fixture.namespace,
            &mut Charge::new(&Budget),
        ),
        Err(RetirementRefusal::Busy)
    ));
    let digest = scan.inventory_digest().clone();
    let lookups = AtomicUsize::new(0);
    let offer = fixture.offer.clone();
    let preparation = block_on(scan.reconcile(
        &Terminal(|request: CloseFinalityRequest| {
            lookups.fetch_add(1, Ordering::SeqCst);
            assert_eq!(request, offer.request);
            Ok(FinalityTerminalLookup::Released(offer.clone()))
        }),
        &Budget,
    ))
    .map_err(|failure| failure.refusal)
    .unwrap();
    assert_eq!(lookups.load(Ordering::SeqCst), 1);
    assert_eq!(preparation.inventory_digest(), &digest);
    assert!(fixture.store_locked(), "preparation keeps the store lock");
    assert_eq!(fixture.snapshot(), before, "preparation wrote nothing");
    drop(preparation);
    assert!(!fixture.store_locked(), "dropping releases the lock");
    let again = fixture.scan().unwrap();
    assert_eq!(again.inventory_digest(), &digest, "digest is stable across reopen");
    drop(again);
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn source_retirement_refusals_leave_namespace_unchanged_and_unlocked() {
    type Mutate = fn(&Released);
    let cases: Vec<(&str, Mutate, fn(&RetirementRefusal) -> bool)> = vec![
        (
            "undelivered ACK",
            |f| std::fs::write(f.namespace.join(DIRECTORY).join("00.acked"), b"x").unwrap(),
            |r| matches!(r, RetirementRefusal::PendingRecord(_)),
        ),
        (
            "canonical reference without Delivered",
            |f| {
                std::fs::copy(f.delivered(), f.delivered().with_extension("reference"))
                    .map(drop)
                    .unwrap()
            },
            |r| matches!(r, RetirementRefusal::PendingRecord(_)),
        ),
        (
            "unsealed intent",
            |f| {
                std::fs::write(f.namespace.join("finality-intents").join("1-00.json"), b"{}")
                    .unwrap()
            },
            |r| matches!(r, RetirementRefusal::UnsealedIntent(_)),
        ),
        (
            "resolved intent",
            |f| {
                std::fs::write(f.namespace.join("finality-intents").join("1-00.resolved"), b"{}")
                    .unwrap()
            },
            |r| matches!(r, RetirementRefusal::UnsealedIntent(_)),
        ),
        (
            "completed certificate still retained",
            |f| {
                let completed = f.namespace.join("finality-intents").join("completed-v1");
                std::fs::create_dir_all(&completed).unwrap();
                std::fs::write(completed.join("1-00.complete"), b"{}").unwrap();
            },
            |r| matches!(r, RetirementRefusal::UnreleasedOutputSet(_)),
        ),
        (
            "unreleased output set",
            |f| Released::edit_json(&f.output_set, |v| v["released"] = serde_json::json!(false)),
            |r| matches!(r, RetirementRefusal::UnreleasedOutputSet(_)),
        ),
        (
            "output temporary",
            |f| std::fs::write(f.output_set.with_extension("tmp"), b"x").unwrap(),
            |r| matches!(r, RetirementRefusal::UncertainTemporary(_)),
        ),
        (
            "Delivered temporary",
            |f| std::fs::write(f.delivered().with_extension("tmp"), b"x").unwrap(),
            |r| matches!(r, RetirementRefusal::UncertainTemporary(_)),
        ),
        (
            "unknown intent artifact",
            |f| std::fs::write(f.namespace.join("finality-intents").join("stray"), b"x").unwrap(),
            |r| matches!(r, RetirementRefusal::UnknownArtifact(_)),
        ),
        (
            "renamed output set",
            |f| {
                std::fs::rename(
                    &f.output_set,
                    f.output_set.with_file_name(format!("101-{}.outputs", "07".repeat(32))),
                )
                .unwrap()
            },
            |r| matches!(r, RetirementRefusal::DigestMismatch(..)),
        ),
        (
            "sealed metadata from another session",
            |f| {
                Released::edit_json(&f.output_set, |v| {
                    v["metadata"]["session_id"] = serde_json::json!("09".repeat(32))
                })
            },
            |r| matches!(r, RetirementRefusal::DomainMismatch(..)),
        ),
        (
            "malformed output set",
            |f| std::fs::write(&f.output_set, b"{\"schema\":2}").unwrap(),
            |r| matches!(r, RetirementRefusal::LegacyFormat(..)),
        ),
        (
            "Approval output",
            |f| {
                Released::edit_json(&f.output_set, |v| {
                    v["outputs"][0]["is_final"] = serde_json::json!(false)
                })
            },
            |r| matches!(r, RetirementRefusal::Unsupported(_)),
        ),
        (
            "sealed output without Delivered",
            |f| std::fs::remove_file(f.delivered()).unwrap(),
            |r| matches!(r, RetirementRefusal::MissingDelivered(_)),
        ),
        (
            "Delivered claimed by no sealed output",
            |f| std::fs::remove_file(&f.output_set).unwrap(),
            |r| matches!(r, RetirementRefusal::OrphanDelivered(_)),
        ),
        (
            "Delivered not node-confirmed",
            |f| {
                Released::edit_json(&f.delivered(), |v| {
                    v["node_confirmed"] = serde_json::json!(false)
                })
            },
            |r| matches!(r, RetirementRefusal::NotNodeConfirmed(_)),
        ),
        (
            "Delivered unknown schema",
            |f| Released::edit_json(&f.delivered(), |v| v["schema"] = serde_json::json!(2)),
            |r| matches!(r, RetirementRefusal::LegacyFormat(..)),
        ),
        (
            "manifest bound to another runtime",
            |f| {
                Released::edit_json(&f.namespace.join("session-runtime.json"), |v| {
                    v["catchain_seqno"] = serde_json::json!(991)
                })
            },
            |r| matches!(r, RetirementRefusal::Manifest(_)),
        ),
        (
            "missing manifest",
            |f| std::fs::remove_file(f.namespace.join("session-runtime.json")).unwrap(),
            |r| matches!(r, RetirementRefusal::Missing(_)),
        ),
        (
            "symlinked manifest",
            |f| {
                let manifest = f.namespace.join("session-runtime.json");
                let moved = f.namespace.join("moved-manifest");
                std::fs::rename(&manifest, &moved).unwrap();
                std::os::unix::fs::symlink(&moved, &manifest).unwrap();
            },
            |r| matches!(r, RetirementRefusal::UnknownArtifact(_)),
        ),
        (
            "missing store lock file",
            |f| std::fs::remove_file(f.namespace.join(DIRECTORY).join(".lock")).unwrap(),
            |r| matches!(r, RetirementRefusal::Missing(_)),
        ),
        (
            "missing intent directory",
            |f| std::fs::remove_dir_all(f.namespace.join("finality-intents")).unwrap(),
            |r| matches!(r, RetirementRefusal::Missing(_)),
        ),
    ];
    for (name, mutate, expected) in cases {
        let fixture = released();
        mutate(&fixture);
        let before = fixture.snapshot();
        let refusal = fixture.scan().err().unwrap_or_else(|| panic!("{name}: issued"));
        assert!(expected(&refusal), "{name}: unexpected refusal {refusal}");
        assert_eq!(fixture.snapshot(), before, "{name}: refusal changed the namespace");
        if fixture.namespace.join(DIRECTORY).join(".lock").exists() {
            assert!(!fixture.store_locked(), "{name}: refusal kept the store lock");
        }
    }
}

#[test]
fn source_retirement_requires_masterchain_manifest_runtime_and_teardown() {
    let fixture = released();
    let before = fixture.snapshot();
    // A live instance never satisfies the teardown receipt.
    let live =
        crate::database::SimplexDb::open(fixture.namespace.join("live"), "live-storage").unwrap();
    let receipt = live.teardown_receipt().unwrap();
    let refusal =
        scan_source_retirement(fixture.runtime.clone(), &fixture.namespace, &receipt, &Budget)
            .err()
            .unwrap();
    assert!(matches!(refusal, RetirementRefusal::DatabaseTeardown(_)), "{refusal}");
    live.close(None).unwrap();
    drop(live);
    std::fs::remove_dir_all(fixture.namespace.join("live")).unwrap();
    assert_eq!(fixture.snapshot(), before);

    let (shard, _) = crate::finality_delivery::tests::fixture_role(
        true,
        rtos_block::ShardIdent::with_tagged_prefix(0, 0x8000_0000_0000_0000).unwrap(),
    );
    let refusal = scan_source_retirement(shard, &fixture.namespace, &fixture.teardown, &Budget)
        .err()
        .unwrap();
    assert!(matches!(refusal, RetirementRefusal::Unsupported(_)), "{refusal}");
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn source_retirement_budget_is_charged_and_hard_capped() {
    struct Steps(AtomicUsize);
    impl SourceHistoryDebtBudget for Steps {
        fn step(&self) -> Result<()> {
            if self.0.fetch_sub(1, Ordering::SeqCst) == 0 {
                fail!("injected step budget exhausted");
            }
            Ok(())
        }
        fn workspace(&self, _: usize) -> Result<()> {
            Ok(())
        }
        fn read_bytes(&self, _: usize) -> Result<()> {
            Ok(())
        }
    }
    let fixture = released();
    let before = fixture.snapshot();
    // Count the steps a full scan needs, then allow one fewer.
    struct Count(AtomicUsize);
    impl SourceHistoryDebtBudget for Count {
        fn step(&self) -> Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn workspace(&self, _: usize) -> Result<()> {
            Ok(())
        }
        fn read_bytes(&self, _: usize) -> Result<()> {
            Ok(())
        }
    }
    let count = Count(AtomicUsize::new(0));
    drop(
        scan_source_retirement(
            fixture.runtime.clone(),
            &fixture.namespace,
            &fixture.teardown,
            &count,
        )
        .unwrap(),
    );
    let needed = count.0.load(Ordering::SeqCst);
    assert!(needed >= 4, "every directory entry is charged");
    let short = Steps(AtomicUsize::new(needed - 1));
    let refusal = scan_source_retirement(
        fixture.runtime.clone(),
        &fixture.namespace,
        &fixture.teardown,
        &short,
    )
    .err()
    .unwrap();
    assert!(matches!(refusal, RetirementRefusal::BudgetExhausted(_)), "{refusal}");
    let exact = Steps(AtomicUsize::new(needed));
    drop(
        scan_source_retirement(
            fixture.runtime.clone(),
            &fixture.namespace,
            &fixture.teardown,
            &exact,
        )
        .unwrap(),
    );
    assert_eq!(fixture.snapshot(), before);

    // The caller's budget cannot raise the module's own caps, and each
    // directory keeps its own byte cap: small output history cannot lend
    // its share to Delivered records.
    let mut charge = Charge::new(&Budget);
    for _ in 0..Charge::MAX_ENTRIES {
        charge.step().unwrap();
    }
    assert!(matches!(charge.step(), Err(RetirementRefusal::BudgetExhausted(_))));
    for (bucket, cap) in
        [(Bucket::Delivered, Charge::MAX_DELIVERED_BYTES), (Bucket::Sets, Charge::MAX_SET_BYTES)]
    {
        let mut charge = Charge::new(&Budget);
        charge.read(bucket, usize::try_from(cap).unwrap()).unwrap();
        assert!(matches!(charge.read(bucket, 1), Err(RetirementRefusal::BudgetExhausted(_))));
    }
    let mut charge = Charge::new(&Budget);
    charge.read(Bucket::Sets, usize::try_from(Charge::MAX_SET_BYTES).unwrap()).unwrap();
    assert!(
        matches!(
            charge.read(Bucket::Delivered, usize::try_from(Charge::MAX_SET_BYTES).unwrap() + 1),
            Err(RetirementRefusal::BudgetExhausted(_))
        ),
        "Delivered bytes are capped on their own"
    );
}

/// Counts or limits each budget dimension; `None` means unlimited.
struct Meter {
    steps: AtomicUsize,
    read: AtomicUsize,
    workspace: AtomicUsize,
    limits: (Option<usize>, Option<usize>, Option<usize>),
}
impl Meter {
    fn new(limits: (Option<usize>, Option<usize>, Option<usize>)) -> Self {
        Self {
            steps: AtomicUsize::new(0),
            read: AtomicUsize::new(0),
            workspace: AtomicUsize::new(0),
            limits,
        }
    }
    fn charge(counter: &AtomicUsize, amount: usize, limit: Option<usize>) -> Result<()> {
        let total = counter.fetch_add(amount, Ordering::SeqCst) + amount;
        if limit.is_some_and(|limit| total > limit) {
            fail!("injected budget limit");
        }
        Ok(())
    }
}
impl SourceHistoryDebtBudget for Meter {
    fn step(&self) -> Result<()> {
        Self::charge(&self.steps, 1, self.limits.0)
    }
    fn read_bytes(&self, bytes: usize) -> Result<()> {
        Self::charge(&self.read, bytes, self.limits.1)
    }
    fn workspace(&self, bytes: usize) -> Result<()> {
        Self::charge(&self.workspace, bytes, self.limits.2)
    }
}

#[test]
fn source_retirement_scan_read_and_workspace_boundaries() {
    let fixture = released();
    let before = fixture.snapshot();
    let meter = Meter::new((None, None, None));
    drop(
        scan_source_retirement(
            fixture.runtime.clone(),
            &fixture.namespace,
            &fixture.teardown,
            &meter,
        )
        .unwrap(),
    );
    let read = meter.read.load(Ordering::SeqCst);
    let workspace = meter.workspace.load(Ordering::SeqCst);
    let manifest = std::fs::metadata(fixture.namespace.join("session-runtime.json")).unwrap().len();
    assert!(read as u64 > manifest, "manifest and inventory reads are charged");
    assert!(workspace > read, "derived inventory workspace is charged too");
    for limits in [(None, Some(read - 1), None), (None, None, Some(workspace - 1))] {
        let refusal = scan_source_retirement(
            fixture.runtime.clone(),
            &fixture.namespace,
            &fixture.teardown,
            &Meter::new(limits),
        )
        .err()
        .unwrap();
        assert!(matches!(refusal, RetirementRefusal::BudgetExhausted(_)), "{refusal}");
        assert!(!fixture.store_locked(), "a budget refusal releases the locks");
    }
    drop(
        scan_source_retirement(
            fixture.runtime.clone(),
            &fixture.namespace,
            &fixture.teardown,
            &Meter::new((None, Some(read), Some(workspace))),
        )
        .unwrap(),
    );

    // Each node lookup is charged before admission.
    let lookups = AtomicUsize::new(0);
    let offer = fixture.offer.clone();
    let sink = Terminal(|_: CloseFinalityRequest| {
        lookups.fetch_add(1, Ordering::SeqCst);
        Ok(FinalityTerminalLookup::Released(offer.clone()))
    });
    let failure = match block_on(
        fixture.scan().unwrap().reconcile(&sink, &Meter::new((Some(0), None, None))),
    ) {
        Ok(_) => panic!("a lookup beyond the budget issued a preparation"),
        Err(failure) => failure,
    };
    assert!(
        matches!(failure.refusal, RetirementRefusal::BudgetExhausted(_)),
        "{}",
        failure.refusal
    );
    assert_eq!(lookups.load(Ordering::SeqCst), 0, "the refused lookup was never admitted");
    drop(failure);
    drop(
        block_on(fixture.scan().unwrap().reconcile(&sink, &Meter::new((Some(1), None, None))))
            .map_err(|f| f.refusal)
            .unwrap(),
    );
    assert_eq!(lookups.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn source_retirement_rejects_foreign_teardown_and_symlinked_database() {
    let fixture = released();
    let before = fixture.snapshot();
    // A clean receipt from another storage instance proves nothing here.
    let elsewhere = crate::authenticated_fixture::TestDirectory::new();
    let foreign = crate::database::SimplexDb::open(
        elsewhere.path(),
        &fixture.runtime.session_id().to_hex_string(),
    )
    .unwrap();
    let receipt = foreign.teardown_receipt().unwrap();
    foreign.close(None).unwrap();
    drop(foreign);
    receipt.check().unwrap();
    let refusal =
        scan_source_retirement(fixture.runtime.clone(), &fixture.namespace, &receipt, &Budget)
            .err()
            .unwrap();
    assert!(matches!(refusal, RetirementRefusal::DatabaseTeardown(_)), "{refusal}");
    assert_eq!(fixture.snapshot(), before);

    let database = fixture.namespace.join(fixture.runtime.session_id().to_hex_string());
    let moved = fixture.namespace.join("moved-database");
    std::fs::rename(&database, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &database).unwrap();
    let before = fixture.snapshot();
    let refusal = fixture.scan().err().unwrap();
    assert!(matches!(refusal, RetirementRefusal::UnknownArtifact(_)), "{refusal}");
    assert_eq!(fixture.snapshot(), before, "refusal preserved every byte");
}

#[test]
fn source_retirement_reconcile_needs_no_blocking_thread() {
    // The node completes custody lookups on its blocking pool. With a single
    // blocking thread, a reconcile that blocked a pool thread would deadlock.
    struct BlockingCompletion {
        handle: tokio::runtime::Handle,
        offer: CloseOffer,
    }
    impl DurableFinalitySink for BlockingCompletion {
        fn stage(&self, _: FinalizedDeliveryDraft, _: FinalizedDeliveryCompletion) -> Result<()> {
            fail!("unused")
        }
        fn lookup_terminal(
            &self,
            _: CloseFinalityRequest,
            completion: FinalityTerminalCompletion,
        ) -> Result<()> {
            let offer = self.offer.clone();
            drop(
                self.handle.spawn_blocking(move || {
                    completion(Ok(FinalityTerminalLookup::Released(offer)))
                }),
            );
            Ok(())
        }
    }
    let fixture = released();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .max_blocking_threads(1)
        .build()
        .unwrap();
    let sink =
        BlockingCompletion { handle: runtime.handle().clone(), offer: fixture.offer.clone() };
    let (rt_runtime, namespace, teardown) =
        (fixture.runtime.clone(), fixture.namespace.clone(), fixture.teardown.clone());
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = runtime.block_on(async move {
            let scan = tokio::task::spawn_blocking(move || {
                scan_source_retirement(rt_runtime, &namespace, &teardown, &Budget)
            })
            .await
            .unwrap()
            .unwrap();
            scan.reconcile(&sink, &Budget).await.map(|p| p.inventory().len()).map_err(|f| f.refusal)
        });
        let _ = done_tx.send(result);
    });
    let result = done_rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("reconcile deadlocked on the blocking pool");
    worker.join().unwrap();
    assert_eq!(result.unwrap(), 1);
}

#[test]
fn source_retirement_reconcile_refusals_return_the_locked_scan() {
    let fixture = released();
    let before = fixture.snapshot();
    let mut other = fixture.offer.clone();
    other.generation += 1;
    let cases: Vec<(&str, FinalityTerminalLookup, fn(&RetirementRefusal) -> bool)> = vec![
        ("retained", FinalityTerminalLookup::Retained, |r| {
            matches!(r, RetirementRefusal::NotReleased { state: "retained", .. })
        }),
        ("close offered", FinalityTerminalLookup::CloseOffered(fixture.offer.clone()), |r| {
            matches!(r, RetirementRefusal::NotReleased { state: "close offered", .. })
        }),
        ("other generation", FinalityTerminalLookup::Released(other), |r| {
            matches!(r, RetirementRefusal::OfferMismatch(_))
        }),
    ];
    for (name, answer, expected) in cases {
        let scan = fixture.scan().unwrap();
        let (scan, refusal) = match block_on(
            scan.reconcile(&Terminal(move |_: CloseFinalityRequest| Ok(answer.clone())), &Budget),
        ) {
            Ok(_) => panic!("{name}: issued"),
            Err(failure) => (failure.scan, failure.refusal),
        };
        assert!(expected(&refusal), "{name}: {refusal}");
        assert!(fixture.store_locked(), "{name}: refused scan still owns the lock");
        drop(scan);
        assert!(!fixture.store_locked());
    }
    let scan = fixture.scan().unwrap();
    let Err(failure) = block_on(scan.reconcile(
        &Terminal(|_: CloseFinalityRequest| Err(error!("custody reopen failed"))),
        &Budget,
    )) else {
        panic!("custody error issued a preparation");
    };
    let ReconcileFailure { scan, refusal } = *failure;
    assert!(matches!(refusal, RetirementRefusal::CustodyUnverified { .. }), "{refusal}");
    drop(scan);
    struct Refuse;
    impl DurableFinalitySink for Refuse {
        fn stage(&self, _: FinalizedDeliveryDraft, _: FinalizedDeliveryCompletion) -> Result<()> {
            fail!("unused")
        }
    }
    let Err(failure) = block_on(fixture.scan().unwrap().reconcile(&Refuse, &Budget)) else {
        panic!("unsupported lookup issued a preparation");
    };
    let ReconcileFailure { scan, refusal } = *failure;
    assert!(matches!(refusal, RetirementRefusal::CustodyUnverified { .. }), "{refusal}");
    drop(scan);
    assert_eq!(fixture.snapshot(), before);
}

#[test]
fn source_retirement_admitted_lookup_is_never_timed_out() {
    #[derive(Default)]
    struct Held(std::sync::Mutex<Option<FinalityTerminalCompletion>>);
    impl DurableFinalitySink for Held {
        fn stage(&self, _: FinalizedDeliveryDraft, _: FinalizedDeliveryCompletion) -> Result<()> {
            fail!("unused")
        }
        fn lookup_terminal(
            &self,
            _: CloseFinalityRequest,
            completion: FinalityTerminalCompletion,
        ) -> Result<()> {
            *self.0.lock().unwrap() = Some(completion);
            Ok(())
        }
    }
    let fixture = released();
    let sink = Arc::new(Held::default());
    let scan = fixture.scan().unwrap();
    let worker_sink = sink.clone();
    let worker = std::thread::spawn(move || {
        block_on(scan.reconcile(worker_sink.as_ref(), &Budget)).map_err(|failure| failure.refusal)
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while sink.0.lock().unwrap().is_none() {
        assert!(std::time::Instant::now() < deadline, "lookup never admitted");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert!(!worker.is_finished(), "an admitted lookup must wait for its completion");
    assert!(fixture.store_locked(), "pending reconciliation keeps the lock");
    let completion = sink.0.lock().unwrap().take().unwrap();
    completion(Ok(FinalityTerminalLookup::Released(fixture.offer.clone())));
    let preparation = worker.join().unwrap().unwrap();
    assert_eq!(preparation.inventory().len(), 1);
    drop(preparation);
    assert!(!fixture.store_locked());
}
