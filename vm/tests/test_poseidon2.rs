// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
use rtos_block::{
    poseidon2_kat::{HASH7, PERM8},
    poseidon2_params::MODULUS_BE,
    BuilderData, Cell, ExceptionCode, HashmapE, IBitstring, Serializable, SliceData,
};
use rtos_vm::{
    error::tvm_exception_code,
    executor::{gas::gas_state::Gas, Engine},
    stack::{integer::IntegerData, savelist::SaveList, Stack, StackItem},
};

fn integer(bytes: &[u8]) -> StackItem {
    StackItem::int(IntegerData::from_unsigned_bytes_be(bytes))
}
fn boc(c: &Cell) -> String {
    hex::encode(rtos_block::write_boc(c).unwrap())
}
fn input(v: &StackItem) -> String {
    match v {
        StackItem::Integer(n) if n.is_nan() => "nan".into(),
        StackItem::Integer(n) => format!("i:{}", n),
        StackItem::Cell(c) => format!("c:{}", boc(c)),
        StackItem::None => "null".into(),
        StackItem::Tuple(_) => "tuple".into(),
        StackItem::Slice(_) => "slice".into(),
        _ => panic!("unexpected input"),
    }
}
fn chain(depth: usize, bad: Option<(usize, usize)>, root_bits: usize, extra: bool) -> Cell {
    let mut next = None;
    for node in (0..depth * 2).rev() {
        let mut b = BuilderData::new();
        for lane in 0..3 {
            let mut bytes = [0u8; 32];
            bytes[30..].copy_from_slice(&((node * 3 + lane + 1) as u16).to_be_bytes());
            if bad == Some((node, lane)) {
                bytes = MODULUS_BE;
            }
            b.append_raw(&bytes, 256).unwrap();
        }
        if node == 0 && root_bits < 768 {
            b = BuilderData::with_raw(b.data().to_vec(), root_bits).unwrap();
        }
        if node == 0 && root_bits > 768 {
            b.append_bit_one().unwrap();
        }
        if let Some(child) = next {
            b.checked_append_reference(child).unwrap();
        }
        if extra && node == 0 {
            b.checked_append_reference(Cell::default()).unwrap();
        }
        next = Some(b.into_cell().unwrap());
    }
    next.unwrap()
}
fn args(path: Cell, index: StackItem, depth: StackItem) -> Vec<StackItem> {
    vec![StackItem::int(17), StackItem::int(29), StackItem::Cell(path), index, depth]
}
#[derive(Clone)]
struct Case {
    name: String,
    source: String,
    inputs: Vec<StackItem>,
    libraries: Vec<Cell>,
}
fn add(cases: &mut Vec<Case>, name: impl Into<String>, source: &str, inputs: Vec<StackItem>) {
    cases.push(Case { name: name.into(), source: source.into(), inputs, libraries: vec![] });
}
#[test]
fn poseidon2_matches_cpp() {
    let mut cases = Vec::new();
    for (name, state, _) in PERM8 {
        add(
            &mut cases,
            format!("perm-{name}"),
            "POSEIDON2_PERM8",
            state.iter().map(|v| integer(v)).collect(),
        );
    }
    for (name, state, _) in HASH7 {
        add(
            &mut cases,
            format!("hash-{name}"),
            "POSEIDON2_HASH7",
            state.iter().map(|v| integer(v)).collect(),
        );
    }
    let bad_values = vec![
        StackItem::int(-1),
        integer(&MODULUS_BE),
        integer(&[255; 32]),
        StackItem::int(IntegerData::nan()),
        StackItem::None,
        StackItem::Cell(Cell::default()),
        StackItem::tuple(vec![]),
        StackItem::Slice(SliceData::default()),
    ];
    for opcode in ["POSEIDON2_PERM8", "POSEIDON2_HASH7"] {
        for len in 0..8 {
            add(&mut cases, format!("{opcode}-short{len}"), opcode, vec![StackItem::int(0); len]);
        }
        for lane in 0..8 {
            for (bad, v) in bad_values.iter().enumerate() {
                let mut values = vec![StackItem::int(0); 8];
                values[lane] = v.clone();
                add(&mut cases, format!("{opcode}-lane{lane}-bad{bad}"), opcode, values);
            }
        }
        let mut values = vec![StackItem::int(0); 8];
        values[7] = StackItem::None;
        values[6] = StackItem::int(-1);
        add(&mut cases, format!("{opcode}-type-before-range"), opcode, values);
    }
    let opcode = "POSEIDON2_PATH7";
    for depth in [1usize, 2, 3, 12, 32, 64] {
        for digit in 0..7 {
            let mut index = num::BigInt::from(0);
            for _ in 0..depth {
                index = index * 7 + digit;
            }
            add(
                &mut cases,
                format!("path-depth{depth}-digit{digit}"),
                opcode,
                args(
                    chain(depth, None, 768, false),
                    StackItem::big_int(&index.to_string()).unwrap(),
                    StackItem::int(depth),
                ),
            );
        }
        let index = num::BigInt::from(7u8).pow(depth as u32);
        add(
            &mut cases,
            format!("path-depth{depth}-overflow"),
            opcode,
            args(
                chain(depth, None, 768, false),
                StackItem::big_int(&index.to_string()).unwrap(),
                StackItem::int(depth),
            ),
        );
    }
    for len in 0..5 {
        add(&mut cases, format!("path-short{len}"), opcode, vec![StackItem::int(0); len]);
    }
    for (bad, v) in bad_values.iter().enumerate() {
        for lane in 0..5 {
            let mut values = args(chain(1, None, 768, false), StackItem::int(0), StackItem::int(1));
            values[lane] = v.clone();
            add(&mut cases, format!("path-lane{lane}-bad{bad}"), opcode, values);
        }
    }
    for depth in [0, 65, 256, 65536] {
        add(
            &mut cases,
            format!("path-depth{depth}"),
            opcode,
            args(chain(1, None, 768, false), StackItem::int(0), StackItem::int(depth)),
        );
    }
    for bits in [0, 1, 767, 769] {
        add(
            &mut cases,
            format!("path-bits{bits}"),
            opcode,
            args(chain(1, None, bits, false), StackItem::int(0), StackItem::int(1)),
        );
    }
    for actual in [1, 2, 3] {
        for declared in [1, 2, 3] {
            add(
                &mut cases,
                format!("path-actual{actual}-declared{declared}"),
                opcode,
                args(chain(actual, None, 768, false), StackItem::int(0), StackItem::int(declared)),
            );
        }
    }
    add(
        &mut cases,
        "path-extra-ref",
        opcode,
        args(chain(1, None, 768, true), StackItem::int(0), StackItem::int(1)),
    );
    for node in 0..6 {
        for lane in 0..3 {
            add(
                &mut cases,
                format!("path-bad-sibling{node}-{lane}"),
                opcode,
                args(
                    chain(3, Some((node, lane)), 768, false),
                    StackItem::int(0),
                    StackItem::int(3),
                ),
            );
        }
    }
    for lane in [0, 1, 2] {
        let mut values = args(chain(1, None, 768, false), StackItem::int(7), StackItem::int(1));
        values[lane] = StackItem::None;
        add(&mut cases, format!("path-index-overflow-and-type{lane}"), opcode, values);
    }
    let path = chain(2, None, 768, false);
    add(
        &mut cases,
        "path-preloaded",
        "PUSH s2 CTOS DROP POSEIDON2_PATH7",
        args(path.clone(), StackItem::int(7), StackItem::int(2)),
    );
    for kind in ["library-valid", "library-missing", "library-recursive", "merkle", "pruned-child"]
    {
        let cell = match kind {
            "merkle" => {
                rtos_block::MerkleProof::create(&path, |_| true).unwrap().serialize().unwrap()
            }
            "pruned-child" => {
                rtos_block::MerkleProof::create(&path, |h| h == path.repr_hash()).unwrap().proof
            }
            _ => path.as_library_cell(),
        };
        add(
            &mut cases,
            format!("path-{kind}"),
            opcode,
            args(cell, StackItem::int(7), StackItem::int(2)),
        );
        if kind == "library-valid" {
            cases.last_mut().unwrap().libraries.push(path.clone());
        }
        if kind == "library-recursive" {
            let lib = path.as_library_cell();
            cases.last_mut().unwrap().inputs[2] = StackItem::Cell(lib.as_library_cell());
            cases.last_mut().unwrap().libraries = vec![lib, path.clone()];
        }
    }
    let export = std::env::var("RTOS_POSEIDON_EXPORT").ok();
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("data/poseidon2.json")).unwrap();
    let mut rows = Vec::new();
    for version in [0, 3, 4, 15, 16, 17, 19] {
        for c in &cases {
            let budgets: &[i64] = if c.name == "path-depth1-digit0"
                || c.name == "path-depth2-digit0"
                || c.name == "path-depth64-digit0"
                || c.name == "perm-zero"
            {
                &[
                    0, 9, 10, 33, 34, 35, 50, 533, 534, 535, 2833, 2834, 2838, 2839, 3534, 3634,
                    3738, 3739, 3740, 6733, 6734, 6938, 6939, 205333, 205334, 205338, 205339,
                    1000000,
                ]
            } else {
                &[1000000]
            };
            for budget in budgets {
                let name = format!("{}-v{version}-gas{budget}", c.name);
                let code = rtos_assembler::compile_code_to_cell(&c.source).unwrap();
                let mut libraries = HashmapE::with_bit_len(256);
                for cell in &c.libraries {
                    libraries.setref(cell.repr_hash().into(), cell.clone()).unwrap();
                }
                let mut stack = Stack::new();
                for v in &c.inputs {
                    stack.push(v.clone());
                }
                let mut vm = Engine::with_capabilities(0)
                    .setup_checked(
                        code.clone(),
                        SaveList::new(),
                        stack,
                        Gas::test_with_limit(*budget),
                        vec![libraries],
                    )
                    .unwrap();
                vm.set_block_version(version);
                let result = vm.execute();
                let skip = usize::from(result.is_err());
                let exit = match result {
                    Ok(n) => n,
                    Err(e) => match tvm_exception_code(&e) {
                        Some(ExceptionCode::OutOfGas) => -14,
                        Some(n) => n as i32,
                        None => panic!("{name}: {e}"),
                    },
                };
                if skip == 1 && exit != -14 {
                    assert_eq!(
                        vm.stack().get(0).unwrap().as_integer().unwrap().to_string(),
                        exit.to_string(),
                        "{name}"
                    );
                }
                // The Rust API leaves its interrupted stack on out-of-gas; the C++
                // run() API returns a one-item gas stack. Compare that API value.
                let values = if exit == -14 {
                    vec![vm.gas_used().to_string()]
                } else {
                    (skip..vm.stack().depth())
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
                let actual = serde_json::json!([
                    exit,
                    vm.gas_used(),
                    values,
                    vm.is_committed_state(),
                    vm.steps()
                ]);
                if export.is_none() {
                    assert_eq!(actual, expected[&name], "{name}");
                }
                rows.push(serde_json::json!({"name":name,"version":version,"gas":budget,"code":boc(&code),"inputs":c.inputs.iter().map(input).collect::<Vec<_>>(),"libraries":c.libraries.iter().map(boc).collect::<Vec<_>>(),"actual":actual}));
            }
        }
    }
    if let Some(path) = export {
        std::fs::write(path, serde_json::to_string(&rows).unwrap()).unwrap();
    } else {
        assert_eq!(expected.as_object().unwrap().len(), rows.len());
    }
}

#[test]
fn poseidon2_mnemonics_roundtrip() {
    for (index, name) in
        ["POSEIDON2_PERM8", "POSEIDON2_HASH7", "POSEIDON2_PATH7"].iter().enumerate()
    {
        let code = rtos_assembler::compile_code(name).unwrap();
        assert_eq!(code.get_bytestring(0).as_ref(), &[0xf9, 0x32, index as u8]);
        let text = rtos_assembler::disasm::disasm(&mut code.clone()).unwrap();
        assert_eq!(text.trim(), *name);
        assert_eq!(rtos_assembler::compile_code(&text).unwrap(), code);
    }
    for bytes in [vec![0xf9, 0x32], vec![0xf9, 0x32, 0x03], vec![0xf9, 0x32, 0xff]] {
        let mut slice = SliceData::from_raw(bytes.clone(), bytes.len() * 8);
        if let Ok(text) = rtos_assembler::disasm::disasm(&mut slice) {
            assert!(!text.contains("POSEIDON2"));
        }
    }
}
