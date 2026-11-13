use crate::{OrdinaryTransactionExecutor, TransactionExecutor};
use rtos_block::{
    read_single_root_boc, BuilderData, Serializable, SliceData, TrComputePhase, TransactionDescr,
};

mod common;
use common::*;

#[test]
fn mldsa44_transaction_uses_config_version_and_gates_actions() {
    let code = rtos_assembler::compile_code_to_cell(
        "
        DROP LDREF LDREF LDREF LDREF ENDS
        PQCHECKSIG_MLDSA44 THROWIFNOT 99
        PUSHROOT CTOS LDREF ENDS PUSHINT 0 SENDRAWMSG
        PUSHINT 77 NEWC STU 8 ENDC POPROOT
    ",
    )
    .unwrap();
    let outgoing = create_int_msg_workchain(
        0,
        RECEIVER_ACCOUNT.clone(),
        THIRD_ACCOUNT.clone(),
        1_000_000,
        false,
        BLOCK_LT,
    );
    let mut stored = BuilderData::new();
    stored.checked_append_reference(outgoing.serialize().unwrap()).unwrap();
    let stored = stored.into_cell().unwrap();
    for (version, bad, ignore, expected_exit) in
        [(15, false, false, 6), (16, false, false, 0), (16, true, false, 99), (16, true, true, 99)]
    {
        let mut account = create_test_account_workchain(
            100_000_000_000u64,
            0,
            RECEIVER_ACCOUNT.clone(),
            code.clone(),
            stored.clone(),
        );
        let before = account.clone();
        let mut message = create_int_msg_workchain(
            0,
            SENDER_ACCOUNT.clone(),
            RECEIVER_ACCOUNT.clone(),
            1_000_000_000,
            false,
            BLOCK_LT - 2,
        );
        let bytes: &[u8] = if bad {
            include_bytes!("data/pq-invalid-body.boc")
        } else {
            include_bytes!("data/pq-valid-body.boc")
        };
        message.set_body(SliceData::load_cell(read_single_root_boc(bytes).unwrap()).unwrap());
        let mut params = execute_params(BLOCK_LT + 1);
        let mut modifiers = rtos_vm::executor::BehaviorModifiers::default();
        modifiers.chksig_always_succeed = ignore;
        params.behavior_modifiers = Some(modifiers);
        let executor = OrdinaryTransactionExecutor::new(custom_config(Some(version), None));
        let tx = executor
            .execute_with_params(Some(message.serialize().unwrap()), &mut account, params)
            .unwrap();
        let TransactionDescr::Ordinary(description) = tx.read_description().unwrap() else {
            panic!("ordinary transaction expected")
        };
        assert!(description.storage_ph.is_some());
        assert!(description.credit_ph.is_some());
        let TrComputePhase::Vm(compute) = description.compute_ph else {
            panic!("VM phase expected")
        };
        assert_eq!(compute.exit_code, expected_exit, "version={version} bad={bad} ignore={ignore}");
        let success = expected_exit == 0;
        assert_eq!(compute.success, success);
        assert_eq!(description.aborted, !success);
        assert_eq!(tx.msg_count(), i16::from(success));
        if success {
            assert!(description.action.unwrap().success);
            assert_eq!(
                account.data().unwrap(),
                &rtos_block::BuilderData::with_raw(vec![77], 8).unwrap().into_cell().unwrap()
            );
        } else {
            assert!(description.action.is_none());
            assert_eq!(account.data(), before.data());
        }
        check_account_and_transaction_balances(&before, &account, &message, Some(&tx));
    }
}
