// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use rtos_block::{Cell, ExceptionCode, HashmapE};
use rtos_vm::{
    error::tvm_exception_code,
    executor::{gas::gas_state::Gas, Engine},
    stack::{savelist::SaveList, Stack, StackItem},
};

fn code(text: &str) -> Cell {
    rtos_assembler::compile_code_to_cell(text).unwrap()
}
fn boc(c: &Cell) -> String {
    hex::encode(rtos_block::write_boc(c).unwrap())
}

#[test]
fn library_budget_matches_cpp() {
    let export = std::env::var("RTOS_LIBRARY_BUDGET_EXPORT").ok();
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("data/library-budget.json")).unwrap();
    let a = code("PUSHINT 1");
    let b = code("PUSHINT 2");
    let missing = code("PUSHINT 3").as_library_cell();
    let nested_child = hex::encode(
        rtos_assembler::compile_code("ONE PUSHSLICE xD030 RUNVM 0").unwrap().get_bytestring(0),
    );
    let mut cases = vec![
        ("ordinary", "CTOS DROP PUSHINT 7".to_string(), vec![a.clone()]),
        ("single", "CTOS DROP PUSHINT 7".into(), vec![a.as_library_cell()]),
        ("repeat", "DUP CTOS DROP CTOS DROP PUSHINT 7".into(), vec![a.as_library_cell()]),
        (
            "distinct",
            "CTOS DROP CTOS DROP PUSHINT 7".into(),
            vec![a.as_library_cell(), b.as_library_cell()],
        ),
        ("missing", "CTOS DROP PUSHINT 7".into(), vec![missing.clone()]),
        (
            "catch-missing",
            "SWAP POPROOT PUSHCONT { CTOS DROP } PUSHCONT { 2DROP } TRY PUSHROOT CTOS DROP PUSHINT 7".into(),
            vec![a.as_library_cell(), missing.clone()],
        ),
    ];
    for flag in [0, 128] {
        cases.push((
            if flag == 0 { "child-parent" } else { "child-parent-isolated" },
            format!("ONE PUSHSLICE xD030 RUNVM {flag} DROP CTOS DROP PUSHINT 7"),
            vec![a.as_library_cell(), b.as_library_cell()],
        ));
        cases.push((
            if flag == 0 { "parent-child" } else { "parent-child-isolated" },
            format!("CTOS DROP ONE PUSHSLICE xD030 RUNVM {flag}"),
            vec![a.as_library_cell(), b.as_library_cell()],
        ));
        cases.push((
            if flag == 0 { "child-repeat" } else { "child-repeat-isolated" },
            format!("DUP ONE PUSHSLICE xD030 RUNVM {flag} DROP CTOS DROP PUSHINT 7"),
            vec![a.as_library_cell()],
        ));
        cases.push((
            if flag == 0 { "child-missing" } else { "child-missing-isolated" },
            format!("ONE PUSHSLICE xD030 RUNVM {flag} 2DROP CTOS DROP PUSHINT 7"),
            vec![a.as_library_cell(), missing.clone()],
        ));
        cases.push((
            if flag == 0 { "nested" } else { "nested-isolated" },
            format!("ONE PUSHSLICE x{nested_child} RUNVM {flag}"),
            vec![a.as_library_cell()],
        ));
    }
    let mut output = Vec::new();
    for version in [9, 10, 14, 15, 16, 19] {
        for limit in [None, Some(0), Some(1), Some(2), Some(u32::MAX)] {
            for (label, source, input) in &cases {
                let name = format!("{label}-v{version}-limit{limit:?}");
                let mut libraries = HashmapE::with_bit_len(256);
                for cell in [&a, &b] {
                    libraries.setref(cell.repr_hash().into(), cell.clone()).unwrap();
                }
                let mut stack = Stack::new();
                for c in input {
                    stack.push(StackItem::Cell(c.clone()));
                }
                let program = code(source);
                let mut vm = Engine::with_capabilities(0)
                    .setup_checked(
                        program.clone(),
                        SaveList::new(),
                        stack,
                        Gas::test_with_limit(1_000_000),
                        vec![libraries],
                    )
                    .unwrap();
                vm.set_block_version(version);
                if let Some(limit) = limit {
                    vm.set_max_library_loads(limit);
                }
                let result = vm.execute();
                // The Rust API leaves the terminal exception code on the stack.
                // C++ run() returns that code separately, as does the RUNVM caller.
                let skip = usize::from(result.is_err());
                let exit = match result {
                    Ok(c) => c,
                    Err(e) => match tvm_exception_code(&e) {
                        Some(ExceptionCode::OutOfGas) => -14,
                        Some(c) => c as i32,
                        None => panic!("{name}: {e}"),
                    },
                };
                if skip == 1 {
                    assert_eq!(
                        vm.stack().get(0).unwrap().as_integer().unwrap().to_string(),
                        exit.to_string(),
                        "{name}: terminal exception code"
                    );
                }
                let mut values = Vec::new();
                for i in skip..vm.stack().depth() {
                    let v = vm.stack().get(i).unwrap();
                    values.push(
                        v.as_integer().map(|n| n.to_string()).unwrap_or_else(|_| "non-int".into()),
                    );
                }
                let actual =
                    serde_json::json!([exit, vm.gas_used(), values, vm.is_committed_state()]);
                if export.is_none() {
                    assert_eq!(actual, expected[&name], "{name}");
                }
                output.push(serde_json::json!({"name":name,"version":version,"limit":limit,"code":boc(&program),"inputs":input.iter().map(boc).collect::<Vec<_>>(),"libraries":[boc(&a),boc(&b)],"actual":actual}));
            }
        }
    }
    if let Some(path) = export {
        std::fs::write(path, serde_json::to_string_pretty(&output).unwrap()).unwrap();
    } else {
        assert_eq!(expected.as_object().unwrap().len(), output.len());
    }
}
