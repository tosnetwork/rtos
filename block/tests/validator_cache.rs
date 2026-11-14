// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use rtos_block::*;

fn parameter(cfg: &mut ConfigParams, index: u32, cell: Cell) {
    let mut value = BuilderData::new();
    value.checked_append_reference(cell).unwrap();
    cfg.config_params.set_builder(index.write_to_bitstring().unwrap(), &value).unwrap();
}
fn pruned(cell: &Cell) -> Cell {
    let mut value = BuilderData::new();
    value.set_type(CellType::PrunedBranch);
    value.append_u8(1).unwrap().append_u8(1).unwrap();
    value.append_raw(cell.hash(0).as_slice(), 256).unwrap().append_u16(cell.depth(0)).unwrap();
    value.into_cell().unwrap()
}

#[test]
fn config_and_proof_readers_share_validated_values_without_sharing_mutable_copies() {
    for index in [32u32, 34, 36] {
        let member =
            ValidatorDescr::with_params(SigPubKey::from_bytes(&[17; 32]).unwrap(), 1, None);
        let set = ValidatorSet::new(80_000 + index, 90_000 + index, 1, vec![member]).unwrap();
        let root = set.serialize().unwrap();
        let mut full = ConfigParams::default();
        parameter(&mut full, index, root.clone());
        let mut owned = match index {
            32 => full.prev_validator_set(),
            34 => full.validator_set(),
            _ => full.next_validator_set(),
        }
        .unwrap();
        assert_eq!(owned, set);
        owned.set_cc_seqno(42);
        let mut proof = ConfigParams::default();
        parameter(&mut proof, 35, pruned(&root));
        let dictionary = proof.config_params.data().unwrap().clone().virtualize(1);
        proof.config_params = HashmapE::with_hashmap(32, Some(dictionary));
        let resolved = proof.proof_validator_set().unwrap();
        assert_eq!(*resolved, set);
        assert_eq!(resolved.cc_seqno(), 0);
        assert_eq!(owned.cc_seqno(), 42);
        assert_eq!(proof.validator_set().unwrap(), set);
    }
    assert_eq!(ConfigParams::default().validator_set().unwrap().total(), 0);
    assert!(ConfigParams::default().proof_validator_set().is_err());
}

#[test]
fn config_reference_shape_is_checked_before_cached_value_lookup() {
    let member = ValidatorDescr::with_params(SigPubKey::from_bytes(&[27; 32]).unwrap(), 1, None);
    let set = ValidatorSet::new(180_000, 190_000, 1, vec![member]).unwrap();
    let root = set.serialize().unwrap();
    ValidatorSet::unpack_with_cache(root.clone(), true).unwrap();
    for index in [19u32, 28, 29, 30, 34, 35] {
        for (bits, refs) in [(1, 1), (0, 2), (0, 0)] {
            let mut value = BuilderData::new();
            if bits != 0 {
                value.append_bit_one().unwrap();
            }
            for _ in 0..refs {
                value.checked_append_reference(pruned(&root)).unwrap();
            }
            let mut cfg = ConfigParams::default();
            cfg.config_params.set_builder(index.write_to_bitstring().unwrap(), &value).unwrap();
            let dictionary = cfg.config_params.data().unwrap().clone().virtualize(1);
            cfg.config_params = HashmapE::with_hashmap(32, Some(dictionary));
            let check = |error: anyhow::Error| {
                assert_eq!(error.downcast_ref::<ConfigParamReferenceError>().unwrap().0, index);
            };
            check(cfg.config(index).unwrap_err());
            check(cfg.proof_config_param_cell(index).unwrap_err());
            if matches!(index, 34 | 35) {
                check(cfg.proof_validator_set().unwrap_err());
                check(cfg.validator_set().unwrap_err());
            }
        }
    }
}

#[test]
fn structural_global_id_reads_only_available_signed_prefix() {
    assert_eq!(ConfigParams::default().proof_global_id().unwrap(), None);
    let opaque = pruned(&Cell::default());
    for bits in [0, 1, 31, 32, 33, 64] {
        for with_ref in [false, true] {
            let mut value = BuilderData::new();
            for _ in 0..bits {
                value.append_bit_one().unwrap();
            }
            if with_ref {
                value.checked_append_reference(opaque.clone()).unwrap();
            }
            let mut cfg = ConfigParams::default();
            parameter(&mut cfg, 19, value.into_cell().unwrap());
            assert_eq!(cfg.proof_global_id().unwrap(), (bits >= 32).then_some(-1));
        }
    }
    let mut library = BuilderData::new();
    library.set_type(CellType::LibraryReference);
    library.append_u8(2).unwrap().append_raw(&[0; 32], 256).unwrap();
    let mut cfg = ConfigParams::default();
    parameter(&mut cfg, 19, library.into_cell().unwrap());
    assert_eq!(cfg.proof_global_id().unwrap_err().to_string(), "invalid proof global-ID cell");
    parameter(&mut cfg, 19, opaque);
    assert!(matches!(
        cfg.proof_global_id().unwrap_err().downcast_ref::<BlockError>(),
        Some(BlockError::PrunedCellAccess(_))
    ));
}
