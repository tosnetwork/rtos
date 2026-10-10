// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use rtos_block::{ExceptionCode, IBitstring};
use rtos_vm::{
    error::tvm_exception_code,
    executor::{gas::gas_state::Gas, Engine},
    stack::{savelist::SaveList, Stack, StackItem},
};
#[test]
fn historical_opcode_activation_matches_cpp() {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("data/opcode-activation-cases.json")).unwrap();
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("data/opcode-activation.json")).unwrap();
    let export = std::env::var("RTOS_OPCODE_ACTIVATION_EXPORT").ok();
    let filter = std::env::var("RTOS_OPCODE_ACTIVATION_FILTER").unwrap_or_default();
    let mut rows = vec![];
    for c in cases.as_array().unwrap() {
        let version = c["version"].as_u64().unwrap() as u32;
        let gas_limit = c["gas"].as_i64().unwrap();
        let name = c["name"].as_str().unwrap().to_owned();
        if !name.contains(&filter) {
            continue;
        }
        let source = c["setup"].as_str().unwrap();
        let mut builder = rtos_block::BuilderData::from_cell(
            &rtos_assembler::compile_code_to_cell(source).unwrap(),
        )
        .unwrap();
        let bytes = hex::decode(c["code"].as_str().unwrap()).unwrap();
        builder
            .append_raw(&bytes, c["bits"].as_u64().map(|n| n as usize).unwrap_or(bytes.len() * 8))
            .unwrap();
        if let Some(tail) = c["tail"].as_str() {
            let tail = rtos_assembler::compile_code_to_cell(tail).unwrap();
            builder.append_builder(&rtos_block::BuilderData::from_cell(&tail).unwrap()).unwrap();
        }
        let code = builder.into_cell().unwrap();
        let mut ctrls = SaveList::new();
        ctrls.put(7, StackItem::tuple(vec![])).unwrap();
        let mut vm = Engine::with_capabilities(0)
            .setup_checked(
                code.clone(),
                ctrls,
                Stack::new(),
                Gas::test_with_limit(gas_limit),
                vec![],
            )
            .unwrap();
        vm.set_block_version(version);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| vm.execute()));
        let result = match outcome {
            Ok(result) => result,
            Err(_) if export.is_some() => {
                rows.push(serde_json::json!({"name":name,"source":source,"version":version,"gas":gas_limit,"code":hex::encode(rtos_block::write_boc(&code).unwrap()),"actual":"panic"}));
                continue;
            }
            Err(payload) => std::panic::resume_unwind(payload),
        };
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
        let gas = vm.gas_used();
        let steps = vm.steps();
        let roots = vm
            .get_committed_state()
            .map(|(a, b)| vec![format!("{:x}", a.repr_hash()), format!("{:x}", b.repr_hash())]);
        let actual = serde_json::json!([exit, gas, values, roots.is_some(), steps, roots]);
        if export.is_none() {
            assert_eq!(actual, expected[&name], "{name}: {source}");
        }
        rows.push(serde_json::json!({"name":name,"source":source,"version":version,"gas":gas_limit,"code":hex::encode(rtos_block::write_boc(&code).unwrap()),"actual":actual}));
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
