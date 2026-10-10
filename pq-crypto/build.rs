// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
use std::{env, path::PathBuf};

fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let native = root.join("native");
    let backend = native.join("mldsa-native/mldsa");
    println!("cargo:rerun-if-changed=native");
    cc::Build::new()
        .std("c90")
        .include(&native)
        .include(&backend)
        .define("MLD_CONFIG_FILE", Some("\"mldsa44-config.h\""))
        .file(backend.join("mldsa_native.c"))
        .file(native.join("abi_check.c"))
        .compile("rtos_mldsa44_verify");
    let falcon = native.join("falcon-reference");
    cc::Build::new()
        .std("c99")
        .include(&native)
        .include(&falcon)
        .define("FALCON_FPEMU", "1")
        .define("FALCON_FPNATIVE", "0")
        .define("FALCON_AVX2", "0")
        .define("FALCON_FMA", "0")
        .define("FALCON_PREFIX", "rtos_falcon_inner")
        .file(native.join("falcon512-native.c"))
        .files(["codec.c", "common.c", "shake.c", "vrfy.c"].map(|f| falcon.join(f)))
        .compile("rtos_falcon512_verify");
}
