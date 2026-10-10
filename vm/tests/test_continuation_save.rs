// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use rtos_block::{ExceptionCode, IBitstring};
use rtos_vm::{
    error::tvm_exception_code,
    executor::{gas::gas_state::Gas, Engine},
    stack::{savelist::SaveList, Stack, StackItem},
};

fn typed(item: &StackItem) -> String {
    match item {
        StackItem::None => "null".into(),
        StackItem::Integer(n) => format!("int:{n}"),
        StackItem::Cell(cell) => format!("cell:{:x}", cell.repr_hash()),
        StackItem::Builder(builder) => format!("builder:{:x}", (**builder).clone().into_cell().unwrap().repr_hash()),
        StackItem::Slice(slice) => {
            let bits = (0..slice.remaining_bits()).map(|i| if slice.get_bit_opt(i).unwrap() {'1'} else {'0'}).collect::<String>();
            let refs = (0..slice.remaining_references()).map(|i| format!("{:x}", slice.reference(i).unwrap().repr_hash())).collect::<Vec<_>>().join("|");
            format!("slice:{bits}:{refs}")
        }
        StackItem::Tuple(items) => format!("tuple[{}]", items.iter().map(typed).collect::<Vec<_>>().join("|")),
        StackItem::Continuation(_) => panic!("continuations are not present in this matrix; a typed serializer is required before adding them"),
    }
}

#[test]
fn continuation_save_matches_cpp() {
    let cases: serde_json::Value =
        serde_json::from_str(include_str!("data/continuation-save-cases.json")).unwrap();
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("data/continuation-save.json")).unwrap();
    let export = std::env::var("RTOS_CONTINUATION_SAVE_EXPORT").ok();
    let filter = std::env::var("RTOS_CONTINUATION_SAVE_FILTER").unwrap_or_default();
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
        let mut initial_stack = Stack::new();
        for _ in 0..c["initial_stack"].as_u64().unwrap_or(0) {
            initial_stack.push_int(0);
        }
        let mut vm = Engine::with_capabilities(0)
            .setup_checked(
                code.clone(),
                ctrls,
                initial_stack,
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
        let error_arg = result
            .as_ref()
            .err()
            .and_then(|e| e.downcast_ref::<rtos_vm::error::TvmError>())
            .map(|e| typed(&e.value));
        if export.is_none()
            && result
                .as_ref()
                .err()
                .is_some_and(|e| tvm_exception_code(e) == Some(ExceptionCode::OutOfGas))
        {
            assert_eq!(error_arg, Some(format!("int:{}", vm.gas_used())), "{name}: OOG payload");
        }
        let exit = match result {
            Ok(n) => n,
            Err(e) => match tvm_exception_code(&e) {
                Some(ExceptionCode::OutOfGas) => -14,
                Some(n) => n as i32,
                None => panic!("{name}: {e}"),
            },
        };
        if name.starts_with("typed-") {
            assert_eq!(exit, 0, "{name}: typed output probe must reach successful return");
        }
        // The default exception continuation adds an API-only exit item.
        // A second exception after a custom c2 was consumed can return directly
        // without that item; retain the actual stack in that case for comparison.
        let exit_item = failed
            && exit != -14
            && vm
                .stack()
                .get(0)
                .ok()
                .and_then(|v| v.as_integer().ok())
                .is_some_and(|v| v.to_string() == exit.to_string());
        if failed && exit != -14 && !exit_item {
            assert!(export.is_some(), "{name}: unexpected terminal error stack shape");
        }
        let values = if exit == -14 {
            vec![format!("int:{}", vm.gas_used())]
        } else {
            (usize::from(exit_item)..vm.stack().depth())
                .map(|i| typed(vm.stack().get(i).unwrap()))
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
        rows.push(serde_json::json!({"name":name,"source":source,"version":version,"gas":gas_limit,"code":hex::encode(rtos_block::write_boc(&code).unwrap()),"actual":actual,"initial_stack":c["initial_stack"].as_u64().unwrap_or(0),"error_arg":error_arg,"error_exit_item":exit_item,"failed":failed}));
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
