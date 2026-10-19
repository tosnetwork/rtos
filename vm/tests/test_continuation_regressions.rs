// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//
// Focused regressions for continuation chains, full loop bodies, PushInt, TRY handlers and the
// nested-jump charge. Every row's exit code, gas, steps, committed flag and final stack were
// produced by the reference VM (rows of the same name in the continuation evidence matrix;
// continuations on the stack are listed as "cont", their structure is compared by
// test_continuation_chains).
use rtos_block::ExceptionCode;
use rtos_vm::{
    error::{tvm_exception_code, tvm_exception_or_custom_code},
    executor::{gas::gas_state::Gas, Engine},
    stack::{
        continuation::{ContinuationData, ContinuationType},
        savelist::SaveList,
        Stack, StackItem,
    },
};
use std::sync::Arc;

type Row = (u32, i64, &'static str, i32, i64, u32, bool, &'static [&'static str]);

const ROWS: &[Row] = &[
    // f2-repeatend-d8-n1-v8
    (8, 100000, "PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 5", 0, 311, 18, true, &["int:5"]),
    // f2-repeatend-d8-n1-v9
    (9, 100000, "PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 5", 0, 312, 18, true, &["int:5"]),
    // f2-repeatend-d12-n1-v8
    (8, 100000, "PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 5", 0, 455, 26, true, &["int:5"]),
    // f2-repeatend-d12-n1-v16
    (16, 100000, "PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 5", 0, 460, 26, true, &["int:5"]),
    // f2-repeatendbrk-d12-n1-v8
    (8, 100000, "PUSHINT 1 REPEATENDBRK PUSHINT 1 REPEATENDBRK PUSHINT 1 REPEATENDBRK PUSHINT 1 REPEATENDBRK PUSHINT 1 REPEATENDBRK PUSHINT 1 REPEATENDBRK PUSHINT 1 REPEATENDBRK PUSHINT 1 REPEATENDBRK PUSHINT 1 REPEATENDBRK PUSHINT 1 REPEATENDBRK PUSHINT 1 REPEATENDBRK PUSHINT 1 REPEATENDBRK PUSHINT 5", 0, 551, 26, true, &["int:5"]),
    // f2-repeatendbrk-d12-n1-v16
    (16, 100000, "PUSHINT 1 REPEATENDBRK PUSHINT 1 REPEATENDBRK PUSHINT 1 REPEATENDBRK PUSHINT 1 REPEATENDBRK PUSHINT 1 REPEATENDBRK PUSHINT 1 REPEATENDBRK PUSHINT 1 REPEATENDBRK PUSHINT 1 REPEATENDBRK PUSHINT 1 REPEATENDBRK PUSHINT 1 REPEATENDBRK PUSHINT 1 REPEATENDBRK PUSHINT 1 REPEATENDBRK PUSHINT 5", 0, 568, 26, true, &["int:5"]),
    // f8-f2-repeatend-d12-n1-v16-m1
    (16, 459, "PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 5", -14, 460, 27, false, &["int:460"]),
    // f8-f2-repeatend-d12-n1-v16-m5
    (16, 455, "PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 5", -14, 456, 27, false, &["int:456"]),
    // f8-f2-repeatend-d12-n1-v16-m6
    (16, 454, "PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 5", -14, 455, 27, false, &["int:455"]),
    // f2-repeatend-d3-after-n1-v8
    (8, 30000, "PUSHINT 50 PUSHINT 0 PUSHCONT { PUSHINT 8 } SETNUMARGS 1 POPCTR c0 PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 5", 0, 268, 15, true, &["int:8", "int:5", "int:0", "int:50"]),
    // f2-repeatend-d3-after-n1-v9
    (9, 30000, "PUSHINT 50 PUSHINT 0 PUSHCONT { PUSHINT 8 } SETNUMARGS 1 POPCTR c0 PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 5", 0, 268, 15, true, &["int:8", "int:5"]),
    // f2-repeatend-d3-after-n2-v8
    (8, 30000, "PUSHINT 50 PUSHINT 0 PUSHCONT { PUSHINT 8 } SETNUMARGS 2 POPCTR c0 PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 5", 0, 268, 15, true, &["int:8", "int:5", "int:0", "int:50"]),
    // f2-repeatend-d3-after-n2-v9
    (9, 30000, "PUSHINT 50 PUSHINT 0 PUSHCONT { PUSHINT 8 } SETNUMARGS 2 POPCTR c0 PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 1 REPEATEND PUSHINT 5", 0, 268, 15, true, &["int:8", "int:5", "int:0"]),
    // f1-repeat-c0-n3-v16
    (16, 30000, "PUSHINT 50 PUSHINT 0 PUSHINT 3 PUSHCONT { PUSHINT 99 } PUSHCONT { INC } SETCONTCTR c0 REPEAT PUSHINT 7", 0, 196, 11, true, &["int:99", "int:1", "int:50"]),
    // f1-repeat-cap1-n2-v8
    (8, 30000, "PUSHINT 50 PUSHINT 0 PUSHINT 2 PUSHINT 100 PUSHCONT { INC } SETCONTARGS 1 REPEAT PUSHINT 7", 0, 219, 13, true, &["int:7", "int:2", "int:50"]),
    // f1-repeat-cap1-n2-v9
    (9, 30000, "PUSHINT 50 PUSHINT 0 PUSHINT 2 PUSHINT 100 PUSHCONT { INC } SETCONTARGS 1 REPEAT PUSHINT 7", 0, 219, 13, true, &["int:7", "int:2", "int:50", "int:100", "int:100"]),
    // f1-until-repeatcap-v16
    (16, 30000, "PUSHINT 50 PUSHINT 0 PUSHINT 2 PUSHCONT { PUSHCTR c0 } REPEAT UNTIL PUSHINT 7", 7, 313, 16, false, &["int:0"]),
    // f1-while-body-pushint-v16
    (16, 30000, "PUSHINT 50 PUSHINT 0 PUSHCONT { DUP PUSHINT 3 LESS } PUSHCONT { PUSHCTR c1 } BOOLEVAL DROP WHILE PUSHINT 7", 7, 318, 16, false, &["int:0"]),
    // f3-booleval-c0-jmpx-v16
    (16, 100000, "PUSHINT 50 PUSHINT 0 PUSHCONT { PUSHCTR c0 JMPX } BOOLEVAL PUSHINT 7", 0, 155, 8, true, &["int:7", "int:-1", "int:0", "int:50"]),
    // f3-booleval-c1-callx-v16
    (16, 100000, "PUSHINT 50 PUSHINT 0 PUSHCONT { PUSHCTR c1 CALLX } BOOLEVAL PUSHINT 7", 0, 155, 8, true, &["int:7", "int:0", "int:0", "int:50"]),
    // f3-booleval-c0-callxargs0_1-v16
    (16, 100000, "PUSHINT 50 PUSHINT 0 PUSHCONT { PUSHCTR c0 CALLXARGS 0, 1 } BOOLEVAL PUSHINT 7", 0, 163, 8, true, &["int:7", "int:-1"]),
    // f4-try-throw-envquit-v16
    (16, 30000, "PUSHINT 50 PUSHINT 0 PUSHCONT { PUSHINT 72 THROW 73 } PUSHCONT { PUSHINT 62 } PUSHCTR c0 SETCONTCTR c1 TRY PUSHINT 7", 0, 268, 9, true, &["int:73", "int:0"]),
    // f4-try-throw-withc0-v16
    (16, 30000, "PUSHINT 50 PUSHINT 0 PUSHCONT { PUSHINT 72 THROW 73 } PUSHCONT { PUSHINT 63 } PUSHCONT { PUSHINT 64 } SETCONTCTR c0 TRY PUSHINT 7", 0, 322, 13, true, &["int:63", "int:64", "int:73", "int:0"]),
    // f4-try-throw-quit1-v16
    (16, 30000, "PUSHINT 50 PUSHINT 0 PUSHCONT { PUSHINT 72 THROW 73 } PUSHCTR c1 TRY PUSHINT 7", 1, 224, 7, true, &["int:73", "int:0"]),
    // f4-tryargs11-throw-pushint-v16
    (16, 30000, "PUSHINT 50 PUSHINT 0 PUSHCONT { PUSHINT 72 THROW 73 } PUSHCONT { PUSHCTR c1 } BOOLEVAL DROP TRYARGS 1, 1 PUSHINT 7", 2, 385, 14, false, &["int:0"]),
    // f4-try-outer-restored-v16
    (16, 100000, "PUSHINT 50 PUSHINT 0 PUSHCONT { PUSHCONT { THROW 85 } PUSHCONT { DROP DROP } TRY THROW 86 } PUSHCONT { PUSHINT 87 } TRY", 0, 413, 16, true, &["int:87", "int:86", "int:0"]),
    // f4-c2-nargs-underflow-v16
    (16, 100000, "PUSHINT 50 PUSHINT 0 PUSHCONT { PUSHINT 1 } SETNUMARGS 3 POPCTR c2 THROW 90", 2, 248, 7, false, &["int:2", "int:0"]),
    // f6-quit11-c3-v16
    (16, 30000, "PUSHCONT { PUSHINT 1 } PUSHCTR c3 DROP NEWC STSLICECONST xF_ ENDC POPROOT PUSHCTR c0 JMPX", 0, 692, 9, true, &["cont"]),
    // f6-excquit-normal-v16
    (16, 30000, "NEWC STSLICECONST xF_ ENDC POPROOT PUSHINT 0 PUSHCTR c2 JMPX", 0, 648, 7, true, &[]),
    // f6-excquit-code-v16
    (16, 30000, "NEWC STSLICECONST xF_ ENDC POPROOT PUSHINT 43 PUSHCTR c2 JMPX", 43, 656, 7, false, &[]),
    // f2-untilend-bad-d5-v16
    (16, 100000, "UNTILEND UNTILEND UNTILEND UNTILEND UNTILEND PUSHNULL TRUE TRUE TRUE TRUE", 7, 235, 12, false, &["int:0"]),
    // f5-setcontargs0-quit0-v16
    (16, 30000, "PUSHINT 50 PUSHINT 0 PUSHCTR c0 SETCONTARGS 0", 0, 101, 5, true, &["cont", "int:0", "int:50"]),
    // f5-setcontargs0m-quit0-run-v16
    (16, 30000, "PUSHINT 50 PUSHINT 0 PUSHCTR c0 SETCONTARGS 0, -1 JMPX", 0, 114, 5, true, &["int:0", "int:50"]),
    // f5-reg-popsave-c0-v16
    (16, 30000, "PUSHINT 50 PUSHINT 0 PUSHCONT { PUSHINT 4 } POPSAVE c0 RET", 0, 137, 7, true, &["int:4", "int:0", "int:50"]),
    // f5-returnargs-loop-v16
    (16, 30000, "PUSHINT 50 PUSHINT 0 PUSHINT 1 PUSHCONT { PUSHINT 2 RETURNARGS 1 } REPEAT PUSHINT 7", 0, 170, 10, true, &["int:7", "int:2", "int:0", "int:50"]),
    // f6-runvm-quit11-mode4-v16
    (16, 30000, "PUSHINT 0 PUSHSLICE xED43D9 NEWC STSLICECONST x1_ ENDC RUNVM 4", 0, 723, 9, true, &["null", "int:11"]),
    // f6-runvm-chain10-mode8m-v16
    (16, 30000, "PUSHINT 0 PUSHSLICE x71E571E571E571E571E571E571E571E571E571E575 PUSHINT 370 RUNVM 8", 0, 530, 27, true, &["int:378", "int:-14", "int:378"]),
    // f1-repeat-c0n3-n1-v9
    (9, 30000, "PUSHINT 50 PUSHINT 0 PUSHINT 1 PUSHCONT { PUSHINT 99 } PUSHCONT { INC } SETCONTCTR c0 SETNUMARGS 3 REPEAT PUSHINT 7", 2, 218, 9, false, &["int:0"]),
    // f1-repeat-c0n3-n1-v8
    (8, 30000, "PUSHINT 50 PUSHINT 0 PUSHINT 1 PUSHCONT { PUSHINT 99 } PUSHCONT { INC } SETCONTCTR c0 SETNUMARGS 3 REPEAT PUSHINT 7", 0, 222, 12, true, &["int:99", "int:1", "int:50"]),
];

fn typed(item: &StackItem) -> String {
    match item {
        StackItem::Integer(n) => format!("int:{n}"),
        StackItem::Continuation(_) => "cont".into(),
        StackItem::None => "null".into(),
        other => format!("{other}"),
    }
}

#[test]
fn continuation_regressions_match_reference() {
    for (version, gas, source, exit, gas_used, steps, committed, stack) in ROWS {
        let code = rtos_assembler::compile_code_to_cell(source).unwrap();
        let mut ctrls = SaveList::new();
        ctrls.put(7, StackItem::tuple(vec![])).unwrap();
        let mut vm = Engine::with_capabilities(0)
            .setup_checked(code, ctrls, Stack::new(), Gas::test_with_limit(*gas), vec![])
            .unwrap();
        vm.set_block_version(*version);
        let result = vm.execute();
        let (actual_exit, skip) = match &result {
            Ok(n) => (*n, 0),
            Err(e) if tvm_exception_code(e) == Some(ExceptionCode::OutOfGas) => (-14, 0),
            Err(e) => (tvm_exception_or_custom_code(e), 1),
        };
        let actual_stack = if actual_exit == -14 {
            vec![format!("int:{}", vm.gas_used())]
        } else {
            (skip..vm.stack().depth()).map(|i| typed(vm.stack().get(i).unwrap())).collect()
        };
        let actual =
            (actual_exit, vm.gas_used(), vm.steps(), vm.is_committed_state(), actual_stack);
        let expected =
            (*exit, *gas_used, *steps, *committed, stack.iter().map(|s| s.to_string()).collect());
        assert_eq!(actual, expected, "v{version} gas {gas}: {source}");
    }
}

fn nested_repeat(depth: usize) -> ContinuationData {
    let mut cont = ContinuationData::with_type(ContinuationType::Quit(0));
    for i in 0..depth {
        let body = ContinuationData::with_type(ContinuationType::PushInt(i as i32, Arc::new(cont)));
        cont = ContinuationData::with_type(ContinuationType::Repeat {
            count: 1,
            body: Arc::new(body),
            after: Arc::new(ContinuationData::new_empty()),
        });
        if i % 3 == 0 {
            let mut env = cont;
            env.force_cdata()
                .savelist
                .put_opt(1, StackItem::continuation(ContinuationData::new_empty()));
            cont = env;
        }
    }
    cont
}

// Deep continuation graphs are released, compared and printed without recursion.
#[test]
fn deep_continuation_graphs_do_not_recurse() {
    let depth = 300_000;
    let a = nested_repeat(depth);
    let b = nested_repeat(depth);
    assert!(a == b);
    let c = nested_repeat(depth - 1);
    assert!(a != c);
    assert!(!format!("{a:?}").is_empty());
    let shared = Arc::new(a);
    let pair = ContinuationData::with_type(ContinuationType::Until {
        body: shared.clone(),
        after: shared,
    });
    assert!(pair == pair.clone());
    drop(pair);
    drop(b);
    drop(c);
    let mut stack = Stack::new();
    stack.push_cont(nested_repeat(depth));
    drop(stack);
}

// A savelist chain built by the VM at a large gas budget is released at engine teardown.
#[test]
fn deep_savelist_chain_from_vm_is_released() {
    let source =
        "PUSHCTR c0 PUSHINT 60000 PUSHCONT { PUSHCONT { NOP } SETCONTCTR c0 } REPEAT DEPTH";
    let code = rtos_assembler::compile_code_to_cell(source).unwrap();
    let mut vm = Engine::with_capabilities(0)
        .setup_checked(
            code,
            SaveList::new(),
            Stack::new(),
            Gas::test_with_limit(10_000_000),
            vec![],
        )
        .unwrap();
    vm.set_block_version(16);
    assert_eq!(vm.execute().unwrap(), 0);
    assert_eq!(vm.stack().get(0).unwrap().as_integer().unwrap().to_string(), "1");
    drop(vm);
}
