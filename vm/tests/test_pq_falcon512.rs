// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
// RTOS VM integration tests use public, frozen differential inputs.
use rtos_block::{read_single_root_boc, ExceptionCode};
use rtos_vm::{
    error::tvm_exception_code,
    executor::{gas::gas_state::Gas, BehaviorModifiers, Engine},
    stack::{savelist::SaveList, Stack, StackItem},
};

#[test]
fn falcon512_vm_matches_frozen_cpp_cases() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("data/pq-falcon512.json")).unwrap();
    let cells: Vec<_> = fixture["cells"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| read_single_root_boc(hex::decode(v.as_str().unwrap()).unwrap()).unwrap())
        .collect();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 636);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let repeats = case["repeats"].as_u64().unwrap() as usize;
        let mut stack = Stack::new();
        for _ in 0..repeats {
            for operand in case["operands"].as_array().unwrap() {
                match operand.as_str() {
                    Some("skip") => {}
                    Some("int") => {
                        stack.push(StackItem::int(1));
                    }
                    None => {
                        stack.push(StackItem::Cell(
                            cells[operand.as_u64().unwrap() as usize].clone(),
                        ));
                    }
                    _ => panic!("unknown fixture operand"),
                }
            }
        }
        let code = if let Some(index) = case["program"].as_u64() {
            let compiled = rtos_assembler::compile_code("DROP PQCHECKSIG_FALCON512_PADDED")
                .unwrap()
                .into_cell()
                .unwrap();
            assert_eq!(compiled, cells[index as usize], "{name}: compiled program differs");
            stack.push(StackItem::int(0));
            compiled
        } else {
            let program = vec!["PQCHECKSIG_FALCON512_PADDED"; repeats].join(" DROP ");
            rtos_assembler::compile_code(&program).unwrap().into_cell().unwrap()
        };
        let mut engine = Engine::with_capabilities(0)
            .setup_checked(
                code,
                SaveList::new(),
                stack,
                Gas::test_with_limit(case["gas"].as_i64().unwrap()),
                vec![],
            )
            .unwrap();
        engine.set_block_version(case["version"].as_u64().unwrap() as u32);
        let mut modifiers = BehaviorModifiers::default();
        modifiers.chksig_always_succeed = case["ignore"].as_bool().unwrap();
        engine.modify_behavior(modifiers);
        let exit = match engine.execute() {
            Ok(code) => code,
            Err(error) => match tvm_exception_code(&error) {
                Some(ExceptionCode::OutOfGas) => -14,
                Some(code) => code as i32,
                None => panic!("{name}: {error}"),
            },
        };
        let value = if exit == 0 {
            assert_eq!(engine.stack().depth(), 1, "{name}: final stack depth");
            engine.stack().get(0).unwrap().as_integer_value(-1i64..=0i64).unwrap()
        } else {
            99
        };
        let gas_used = engine.gas_used();
        let committed = engine.is_committed_state();
        let steps = engine.steps();
        let (c4, c5) = match engine.get_committed_state() {
            Some((a, b)) => {
                (hex::encode(a.repr_hash().as_slice()), hex::encode(b.repr_hash().as_slice()))
            }
            None => ("-".into(), "-".into()),
        };
        let actual = serde_json::json!([exit, gas_used, value, u8::from(committed), c4, c5, steps]);
        assert_eq!(actual, case["expected"], "{name}: exit, gas, value, commit, c4, c5");
    }
}

#[test]
fn falcon512_assembler_roundtrip_and_unallocated_neighbours() {
    let code = rtos_assembler::compile_code("PQCHECKSIG_FALCON512_PADDED").unwrap();
    assert_eq!(code.get_bytestring(0).as_ref(), &[0xf9, 0x31, 0x01]);
    let text = rtos_assembler::disasm::disasm(&mut code.clone()).unwrap();
    assert_eq!(text.trim(), "PQCHECKSIG_FALCON512_PADDED");
    let combined = rtos_assembler::compile_code("NOP PQCHECKSIG_FALCON512_PADDED DROP").unwrap();
    let text = rtos_assembler::disasm::disasm(&mut combined.clone()).unwrap();
    assert_eq!(rtos_assembler::compile_code(&text).unwrap(), combined);
    for bytes in [vec![0xf9, 0x31], vec![0xf9, 0x31, 0x03], vec![0xf9, 0x31, 0x02]] {
        let mut slice = rtos_block::SliceData::from_raw(bytes.clone(), bytes.len() * 8);
        if let Ok(text) = rtos_assembler::disasm::disasm(&mut slice) {
            assert!(!text.contains("PQCHECKSIG_FALCON512_PADDED"), "{text}");
        }
    }
}
