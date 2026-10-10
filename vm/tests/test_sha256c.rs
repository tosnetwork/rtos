// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use rtos_block::{read_single_root_boc, ExceptionCode, HashmapE};
use rtos_vm::{
    error::tvm_exception_code,
    executor::{gas::gas_state::Gas, Engine},
    stack::{savelist::SaveList, Stack, StackItem},
};

#[test]
fn sha256c_matches_cpp() {
    let cases: serde_json::Value = serde_json::from_str(include_str!("data/sha256c.json")).unwrap();
    assert_eq!(cases.as_array().unwrap().len(), 454);
    for case in cases.as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let repeats = case["repeats"].as_u64().unwrap() as usize;
        let mut stack = Stack::new();
        for _ in 0..repeats {
            match case["cell"].as_str().unwrap() {
                "skip" => {}
                "int" => {
                    stack.push(StackItem::int(1));
                }
                boc => {
                    stack.push(StackItem::Cell(
                        read_single_root_boc(hex::decode(boc).unwrap()).unwrap(),
                    ));
                }
            }
        }
        let program = vec!["SHA256C"; repeats].join(" DROP ");
        let code = rtos_assembler::compile_code(&program).unwrap().into_cell().unwrap();
        let mut libs = HashmapE::with_bit_len(256);
        for boc in case["libs"].as_array().unwrap() {
            let cell = read_single_root_boc(hex::decode(boc.as_str().unwrap()).unwrap()).unwrap();
            libs.setref(cell.repr_hash().into(), cell).unwrap();
        }
        let mut engine = Engine::with_capabilities(0)
            .setup_checked(
                code,
                SaveList::new(),
                stack,
                Gas::test_with_limit(case["gas"].as_i64().unwrap()),
                vec![libs],
            )
            .unwrap();
        engine.set_block_version(case["version"].as_u64().unwrap() as u32);
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
            hex::encode(engine.stack().get(0).unwrap().as_integer().unwrap().as_u256().unwrap())
        } else {
            "-".into()
        };
        let gas_used = engine.gas_used();
        let committed = engine.is_committed_state();
        let (c4, c5) = match engine.get_committed_state() {
            Some((a, b)) => {
                (hex::encode(a.repr_hash().as_slice()), hex::encode(b.repr_hash().as_slice()))
            }
            None => ("-".into(), "-".into()),
        };
        let actual = serde_json::json!([exit, gas_used, value, u8::from(committed), c4, c5]);
        assert_eq!(actual, case["expected"], "{name}: exit, gas, value, commit, c4, c5");
    }
}

#[test]
fn sha256c_assembler_roundtrip() {
    let code = rtos_assembler::compile_code("SHA256C").unwrap();
    assert_eq!(code.get_bytestring(0).as_ref(), &[0xf9, 0x03]);
    let text = rtos_assembler::disasm::disasm(&mut code.clone()).unwrap();
    assert_eq!(text.trim(), "SHA256C");
    let combined = rtos_assembler::compile_code("NOP SHA256C DROP").unwrap();
    let text = rtos_assembler::disasm::disasm(&mut combined.clone()).unwrap();
    assert_eq!(rtos_assembler::compile_code(&text).unwrap(), combined);
}
