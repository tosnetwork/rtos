// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use rtos_pq_consensus::{
    ConsensusKeyStore, CONFIG_VOTE_CONTEXT, ELECTION_CONTEXT, SIMPLEX_CONTEXT,
};
use std::{fs, path::PathBuf, process::Command};

#[test]
#[ignore = "requires the separately built fixed-reference executable; see memo evidence"]
fn actual_fixed_reference_signer_and_verifier_roundtrip() {
    let reference = PathBuf::from(
        std::env::var_os("RTOS_PQ_NATIVE_REFERENCE")
            .expect("fixed-reference executable must be supplied"),
    );
    let directory = tempfile::tempdir_in(reference.parent().unwrap()).unwrap();
    let run = |mode| {
        let output = Command::new(&reference).arg(mode).arg(directory.path()).output().unwrap();
        assert!(
            output.status.success(),
            "reference {mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    run("emit");
    let key = ConsensusKeyStore::from_seed(&[0x42; 32], 0).unwrap();
    assert_eq!(
        key.consensus_key().public_key,
        fs::read(directory.path().join("public.bin")).unwrap()
    );
    assert_eq!(
        key.consensus_key().key_id.as_array().as_slice(),
        fs::read(directory.path().join("key-id.bin")).unwrap()
    );
    let message = b"native consensus parity fixture";
    let contexts = [SIMPLEX_CONTEXT, CONFIG_VOTE_CONTEXT, ELECTION_CONTEXT];
    let signatures = [
        key.sign_consensus(message).unwrap(),
        key.sign_config_vote(message).unwrap(),
        key.sign_election(message).unwrap(),
    ];
    for (i, context) in contexts.iter().enumerate() {
        let signature = fs::read(directory.path().join(format!("native-{i}.sig"))).unwrap();
        assert_eq!(
            rtos_pq_crypto::verify(message, context, &signature, &key.consensus_key().public_key),
            Ok(true)
        );
        for other in contexts
            .iter()
            .copied()
            .chain([b"tos.pq.wallet.v1".as_slice(), b"TOS-CONFIG-ADMIN-v1".as_slice()])
        {
            assert_eq!(
                rtos_pq_crypto::verify(message, other, &signature, &key.consensus_key().public_key),
                Ok(other == *context)
            );
        }
        fs::write(directory.path().join(format!("rust-{i}.sig")), signatures[i].bytes).unwrap();
    }
    run("verify");
}
