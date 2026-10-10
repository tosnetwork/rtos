use crate::{OrdinaryTransactionExecutor, TransactionExecutor};
use rtos_block::{
    BuilderData, IBitstring, Serializable, SliceData, TrComputePhase, TransactionDescr,
};

mod common;
use common::*;

#[test]
fn sha256c_transaction_uses_config_version_and_gates_actions() {
    let code = rtos_assembler::compile_code_to_cell(
        "
        DROP LDREF ENDS
        SHA256C PUSHINT 84342368487090800366523834928142263660104883695016514377462985829716817089965 EQUAL THROWIFNOT 99
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
    for (version, bad, expected_exit) in [(13, false, 6), (14, false, 0), (14, true, 9)] {
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
        let mut payload = BuilderData::new();
        if bad {
            payload.append_bit_one().unwrap();
        } else {
            payload.append_raw(b"abc", 24).unwrap();
        }
        let mut body = BuilderData::new();
        body.checked_append_reference(payload.into_cell().unwrap()).unwrap();
        message.set_body(SliceData::load_builder(body).unwrap());
        let params = execute_params(BLOCK_LT + 1);
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
        assert_eq!(compute.exit_code, expected_exit, "version={version} bad={bad}");
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
            assert!(compute.gas_used.as_u64() >= 132);
        } else {
            assert!(description.action.is_none());
            assert_eq!(account.data(), before.data());
        }
        check_account_and_transaction_balances(&before, &account, &message, Some(&tx));
    }
}
