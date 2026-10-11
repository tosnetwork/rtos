// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! File-barrier unit tests. Only the Engine fixture proves pinned authentication;
//! these tests build private receipts to isolate exact-byte durability checks.
use super::*;
use crate::history_read_budget::{HistoryReadBudget, HistoryReadLimits};
use rtos_block::{BuilderData, Cell};

fn fixture(
    state: &[u8],
    proofs: &[&[u8]],
) -> (tempfile::TempDir, Store, Domain, BlockIdExt, CapsuleDurabilityReceipt) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().to_owned(), Limits::default()).unwrap();
    let id = BlockIdExt::with_params(
        rtos_block::ShardIdent::masterchain(),
        2,
        UInt256::from([2; 32]),
        UInt256::from([3; 32]),
    );
    let domain = Domain { zero: "test-zero".into(), init: "test-init".into() };
    let manifest = Manifest {
        schema: SCHEMA,
        domain: domain.clone(),
        id: id.to_string(),
        global_id: -239,
        state: digest(state),
        proofs: proofs
            .iter()
            .enumerate()
            .map(|(index, bytes)| ProofRef {
                id: format!("proof-{index}"),
                link: false,
                blob: digest(bytes),
            })
            .collect(),
    };
    std::fs::write(dir.path().join(format!("{}.blob", manifest.state)), state).unwrap();
    for (reference, bytes) in manifest.proofs.iter().zip(proofs) {
        std::fs::write(dir.path().join(format!("{}.blob", reference.blob)), bytes).unwrap();
    }
    let raw = serde_json::to_vec(&manifest).unwrap();
    std::fs::write(dir.path().join(format!("{}.json", anchor_name(&domain, &id))), &raw).unwrap();
    let receipt =
        CapsuleDurabilityReceipt { manifest_hash: UInt256::calc_file_hash(&raw), manifest };
    (dir, store, domain, id, receipt)
}

#[test]
fn historical_capsule_barrier_rejects_exact_evidence_changes() {
    let state = rtos_block::write_boc(&Cell::default()).unwrap();
    let (dir, store, domain, id, receipt) = fixture(&state, &[b"original proof"]);
    let manifest_path = dir.path().join(format!("{}.json", anchor_name(&domain, &id)));
    let original = std::fs::read(&manifest_path).unwrap();
    // Whitespace, state reference, and a different proof set all change the
    // authenticated manifest even when their replacement checksums are valid.
    let mut variants = vec![[original.as_slice(), b" "].concat()];
    let mut replacement = receipt.manifest.clone();
    let other = b"different validly named blob";
    let other_hash = digest(other);
    std::fs::write(dir.path().join(format!("{other_hash}.blob")), other).unwrap();
    replacement.state = other_hash.clone();
    variants.push(serde_json::to_vec(&replacement).unwrap());
    replacement = receipt.manifest.clone();
    replacement.proofs[0].blob = other_hash;
    variants.push(serde_json::to_vec(&replacement).unwrap());
    for variant in variants {
        std::fs::write(&manifest_path, variant).unwrap();
        let error = store
            .sync_authenticated_capsule(
                &domain,
                &id,
                &receipt,
                &HistoryReadBudget::new(HistoryReadLimits::default()),
            )
            .unwrap_err();
        assert!(error.to_string().contains("manifest changed"), "{error:#}");
    }
    std::fs::write(&manifest_path, original).unwrap();
    for hash in [&receipt.manifest.state, &receipt.manifest.proofs[0].blob] {
        let path = dir.path().join(format!("{hash}.blob"));
        let original = std::fs::read(&path).unwrap();
        let mut damaged = original.clone();
        damaged[0] ^= 1;
        std::fs::write(&path, damaged).unwrap();
        let error = store
            .sync_authenticated_capsule(
                &domain,
                &id,
                &receipt,
                &HistoryReadBudget::new(HistoryReadLimits::default()),
            )
            .unwrap_err();
        assert!(error.to_string().contains("blob changed"), "{error:#}");
        std::fs::write(&path, original).unwrap();
    }
    store
        .sync_authenticated_capsule(
            &domain,
            &id,
            &receipt,
            &HistoryReadBudget::new(HistoryReadLimits::default()),
        )
        .unwrap();
}

#[test]
fn historical_capsule_barrier_checks_binding_and_cumulative_budget() {
    let (dir, store, domain, id, receipt) = fixture(b"state", &[b"proof"]);
    let wrong_domain = Domain { zero: "other-zero".into(), init: domain.init.clone() };
    assert!(store
        .sync_authenticated_capsule(
            &wrong_domain,
            &id,
            &receipt,
            &HistoryReadBudget::new(HistoryReadLimits::default())
        )
        .is_err());
    let mut wrong_id = id.clone();
    wrong_id.seq_no += 1;
    assert!(store
        .sync_authenticated_capsule(
            &domain,
            &wrong_id,
            &receipt,
            &HistoryReadBudget::new(HistoryReadLimits::default())
        )
        .is_err());
    // Exactly one physical state read (including growth probe) is admitted.
    let mut limits = HistoryReadLimits::default();
    limits.state_boc_bytes = b"state".len() + 1;
    let budget = HistoryReadBudget::new(limits);
    store.sync_authenticated_capsule(&domain, &id, &receipt, &budget).unwrap();
    assert!(store.sync_authenticated_capsule(&domain, &id, &receipt, &budget).is_err());
    let mut limits = HistoryReadLimits::default();
    limits.steps = 0;
    assert!(store
        .sync_authenticated_capsule(&domain, &id, &receipt, &HistoryReadBudget::new(limits))
        .is_err());
    // Refusal never rewrites evidence.
    assert_eq!(
        std::fs::read(dir.path().join(format!("{}.blob", receipt.manifest.state))).unwrap(),
        b"state"
    );
}

#[test]
fn historical_capsule_barrier_large_graph_uses_same_default_budget() {
    let mut cells = (0..18_000u32)
        .map(|index| {
            let mut bytes = vec![0x63; 127];
            bytes[..4].copy_from_slice(&index.to_be_bytes());
            BuilderData::with_raw(bytes, 127 * 8).unwrap().into_cell().unwrap()
        })
        .collect::<Vec<_>>();
    while cells.len() > 1 {
        cells = cells
            .chunks(2)
            .map(|children| {
                if children.len() == 1 {
                    return children[0].clone();
                }
                let mut parent = BuilderData::new();
                for child in children {
                    parent.checked_append_reference(child.clone()).unwrap();
                }
                parent.into_cell().unwrap()
            })
            .collect();
    }
    let raw = rtos_block::write_boc(&cells[0]).unwrap();
    assert!(raw.len() > 2 << 20);
    let (_dir, store, domain, id, receipt) = fixture(&raw, &[]);
    let budget = HistoryReadBudget::new(HistoryReadLimits::default());
    assert_eq!(budget.limits().cell_bytes, 128 << 20);
    assert_eq!(budget.limits().steps, 4_000_000);
    let evidence = store.read_budget(&domain, &id, Some(&budget)).unwrap().unwrap();
    let parsed = budget.parse_boc(&evidence.state).unwrap();
    assert_eq!(parsed.repr_hash(), cells[0].repr_hash());
    // No graph is rebuilt in the second physical read/durability barrier.
    store.sync_authenticated_capsule(&domain, &id, &receipt, &budget).unwrap();
    assert_eq!(parsed.repr_hash(), cells[0].repr_hash());
}
