// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
//! Structural storage tests. Sparse quota fillers are not authenticated events.
use super::*;

fn output(index: u32) -> ExpectedFinalityOutput {
    let id = rtos_block::BlockIdExt::with_params(
        rtos_block::ShardIdent::masterchain(),
        u32::MAX - index,
        UInt256::from([9; 32]),
        UInt256::from([8; 32]),
    );
    ExpectedFinalityOutput::new(&id, false, &UInt256::from([7; 32]))
}
fn capacity(mode: u8) {
    let dir = crate::authenticated_fixture::TestDirectory::new();
    let (runtime, _) = crate::finality_delivery::tests::fixture();
    let namespace = PathBuf::from(runtime.runtime_directory(dir.path().to_str().unwrap()).unwrap());
    let owner = crate::finality_delivery::PendingFinalityStore::open(&namespace).unwrap();
    let store = FinalityIntentStore::new(&namespace);
    let mut triggers = Vec::new();
    for slot in [100, 101] {
        let event = crate::simplex_state::BlockFinalizedEvent {
            slot: crate::block::SlotIndex::new(slot),
            block_hash: UInt256::from([7; 32]),
            block_id: None,
            certificate: std::sync::Arc::new(crate::certificate::Certificate {
                vote: crate::simplex_state::FinalizeVote {
                    slot: crate::block::SlotIndex::new(slot),
                    block_hash: UInt256::from([7; 32]),
                },
                signatures: Vec::new(),
            }),
        };
        store
            .retain(
                &runtime,
                vec![runtime.pin().zerostate.clone()],
                runtime.pin().zerostate.clone(),
                &event,
            )
            .unwrap();
        let id = crate::block::RawCandidateId { slot: event.slot, hash: event.block_hash };
        store.resolve(&id).unwrap();
        triggers.push(id);
    }
    store.seal_outputs(&triggers[0], vec![output(0)]).unwrap();
    let existing = store.output_path(&triggers[0]);
    let target = store.output_path(&triggers[1]);
    let parent = target.parent().unwrap();
    let protected: Vec<_> = [
        existing.clone(),
        store.completed_path(
            &namespace
                .join(DIRECTORY)
                .join(format!("100-{}.json", triggers[0].hash.to_hex_string())),
        ),
        store.completed_path(
            &namespace
                .join(DIRECTORY)
                .join(format!("101-{}.json", triggers[1].hash.to_hex_string())),
        ),
    ]
    .into_iter()
    .map(|path| {
        let bytes = std::fs::read(&path).unwrap();
        (path, bytes)
    })
    .collect();
    let mut metadata = FinalityIntentStore::canonical_intent(&protected[2].0).unwrap();
    let digest = UInt256::calc_file_hash(&serde_json::to_vec(&metadata).unwrap()).to_hex_string();
    metadata.certificate.clear();
    let encoded_size = |outputs: Vec<ExpectedFinalityOutput>| {
        serde_json::to_vec(&OutputSet {
            schema: 1,
            digest: digest.clone(),
            metadata: metadata.clone(),
            outputs,
            released: false,
        })
        .unwrap()
        .len() as u64
    };
    let target_bytes = encoded_size(vec![output(0)]);
    let existing_bytes = protected[0].1.len() as u64;
    let mut fillers = Vec::new();
    let (rejected, accepted) = if mode == 2 {
        // Adjacent reachable records, not an oversized fabricated metadata field.
        // Every block ID is canonical and all outputs are distinct, <=1024.
        let boundary = (1..=MAX_OUTPUTS)
            .find(|n| encoded_size((0..*n as u32).map(output).collect()) > MAX_OUTPUT_BYTES)
            .expect("canonical 1024-output record must reach the byte bound");
        assert!(boundary > 1);
        ((0..boundary as u32).map(output).collect(), (0..boundary as u32 - 1).map(output).collect())
    } else {
        let mut bytes =
            if mode == 0 { 0 } else { MAX_OUTPUT_TOTAL - existing_bytes - target_bytes + 1 };
        let count =
            if mode == 0 { MAX_COMPLETED - 1 } else { bytes.div_ceil(MAX_OUTPUT_BYTES) as usize };
        for index in 0..count {
            let path = parent.join(format!("filler-{index}.outputs"));
            let n = bytes.min(MAX_OUTPUT_BYTES);
            File::create(&path).unwrap().set_len(n).unwrap();
            bytes -= n;
            fillers.push(path);
        }
        assert_eq!(bytes, 0);
        (vec![output(0)], vec![output(0)])
    };
    let expected =
        if mode == 2 { "Source output map cap" } else { "Source output map backpressure" };
    let reject = |store: &FinalityIntentStore| {
        FinalityIntentStore::validate_output_directory(parent).unwrap();
        assert_eq!(
            store.seal_outputs(&triggers[1], rejected.clone()).unwrap_err().to_string(),
            expected
        );
        for (path, bytes) in &protected {
            assert_eq!(&std::fs::read(path).unwrap(), bytes);
        }
        assert!(!target.exists());
        assert!(!target.with_extension("tmp").exists());
    };
    reject(&store);
    drop(store);
    drop(owner);
    let owner = crate::finality_delivery::PendingFinalityStore::open(&namespace).unwrap();
    let store = FinalityIntentStore::new(&namespace);
    reject(&store);
    if mode == 0 {
        std::fs::remove_file(fillers.last().unwrap()).unwrap();
    }
    if mode == 1 {
        let file = std::fs::OpenOptions::new().write(true).open(fillers.last().unwrap()).unwrap();
        file.set_len(file.metadata().unwrap().len() - 1).unwrap();
    }
    store.seal_outputs(&triggers[1], accepted.clone()).unwrap();
    for (path, bytes) in &protected {
        assert_eq!(&std::fs::read(path).unwrap(), bytes);
    }
    let sealed = std::fs::read(&target).unwrap();
    assert!(sealed.len() as u64 <= MAX_OUTPUT_BYTES);
    if mode == 0 {
        assert_eq!(std::fs::read_dir(parent).unwrap().count(), MAX_COMPLETED);
    } else if mode == 1 {
        let total: u64 = std::fs::read_dir(parent).unwrap()
            .map(|entry| entry.unwrap().metadata().unwrap().len()).sum();
        assert_eq!(total, MAX_OUTPUT_TOTAL);
    } else {
        assert!(encoded_size(rejected) > MAX_OUTPUT_BYTES);
        assert!(encoded_size(accepted.clone()) <= MAX_OUTPUT_BYTES);
    }
    drop(store);
    drop(owner);
    let _owner = crate::finality_delivery::PendingFinalityStore::open(&namespace).unwrap();
    let store = FinalityIntentStore::new(&namespace);
    store.seal_outputs(&triggers[1], accepted).unwrap();
    assert_eq!(std::fs::read(target).unwrap(), sealed);
}
#[test]
fn source_output_capacity_count_preserves_certificates_and_cold_retry() {
    capacity(0);
}
#[test]
fn source_output_capacity_total_bytes_preserves_certificates_and_cold_retry() {
    capacity(1);
}
#[test]
fn source_output_capacity_reachable_record_bytes_preserves_certificates_and_cold_retry() {
    capacity(2);
}
