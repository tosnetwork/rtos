// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use rtos_block::ExceptionCode;
use rtos_vm::{
    error::tvm_exception_code,
    executor::{gas::gas_state::Gas, Engine},
    stack::{savelist::SaveList, Stack, StackItem},
};
#[test]
fn builder_capacity_matches_cpp() {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("data/bchk-cases.json")).unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!("data/bchk.json")).unwrap();
    let export = std::env::var("RTOS_BCHK_EXPORT").ok();
    let filter = std::env::var("RTOS_BCHK_FILTER").unwrap_or_default();
    let mut rows = vec![];
    for c in cases.as_array().unwrap() {
        for version in [13, 14] {
            for context in ["direct", "catch", "nested"] {
                let name = format!("{}-v{version}-{context}", c["name"].as_str().unwrap());
                if !name.contains(&filter) {
                    continue;
                }
                let inner = format!(
                    "{} {}",
                    if c["marker"].as_bool().unwrap_or(true) { "PUSHINT 77" } else { "" },
                    c["source"].as_str().unwrap()
                );
                let source = match context {
                    "catch" => format!("PUSHCONT {{ SWAP DROP }} POPCTR c2 {inner}"),
                    "nested" => format!("PUSHINT 0 PUSHREFSLICE {{ {inner} }} PUSHCTR c7 RUNVM 16"),
                    _ => inner,
                };
                let code = rtos_assembler::compile_code_to_cell(&source)
                    .unwrap_or_else(|e| panic!("{name}: {source}: {e}"));
                let mut ctrls = SaveList::new();
                ctrls.put(7, StackItem::tuple(vec![])).unwrap();
                let mut vm = Engine::with_capabilities(0)
                    .setup_checked(
                        code.clone(),
                        ctrls,
                        Stack::new(),
                        Gas::test_with_limit(1000000),
                        vec![],
                    )
                    .unwrap();
                vm.set_block_version(version);
                let result = vm.execute();
                let failed = result.is_err();
                let exit = match result {
                    Ok(n) => n,
                    Err(e) => match tvm_exception_code(&e) {
                        Some(ExceptionCode::OutOfGas) => -14,
                        Some(n) => n as i32,
                        None => panic!("{name}: {e}"),
                    },
                };
                if failed && exit != -14 {
                    assert_eq!(
                        vm.stack().get(0).unwrap().as_integer().unwrap().to_string(),
                        exit.to_string(),
                        "{name}"
                    );
                }
                let values = if exit == -14 {
                    vec![vm.gas_used().to_string()]
                } else {
                    (usize::from(failed)..vm.stack().depth())
                        .map(|i| {
                            vm.stack()
                                .get(i)
                                .unwrap()
                                .as_integer()
                                .map(|n| n.to_string())
                                .unwrap_or_else(|_| "non-int".into())
                        })
                        .collect::<Vec<_>>()
                };
                if context == "nested" {
                    assert!(vm.steps() >= 6, "{name}: child not executed");
                }
                if export.is_none() {
                    if name == "BCHKREFSQ-stored0-0-rPUSHINT5-b-v14-nested" {
                        assert_eq!(values, vec!["0", "0", "77"]);
                        assert_eq!(vm.steps(), 10);
                    }
                    if name == "BCHKBITREFSQ-stored4-1023-rPUSHINT0-bPUSHINT0-v14-direct" {
                        assert_eq!(values, vec!["-1", "77"]);
                    }
                }
                let gas = vm.gas_used();
                let steps = vm.steps();
                let roots = vm.get_committed_state().map(|(a, b)| {
                    vec![format!("{:x}", a.repr_hash()), format!("{:x}", b.repr_hash())]
                });
                let actual = serde_json::json!([exit, gas, values, roots.is_some(), steps, roots]);
                if export.is_none() {
                    assert_eq!(actual, expected[&name], "{name}: {source}");
                }
                rows.push(serde_json::json!({"name":name,"source":source,"version":version,"gas":1000000,"code":hex::encode(rtos_block::write_boc(&code).unwrap()),"actual":actual}));
            }
        }
    }
    assert!(!rows.is_empty());
    if let Some(path) = export {
        std::fs::write(path, serde_json::to_vec_pretty(&rows).unwrap()).unwrap()
    } else {
        assert_eq!(
            rows.len(),
            expected.as_object().unwrap().keys().filter(|n| n.contains(&filter)).count()
        );
    }
}
