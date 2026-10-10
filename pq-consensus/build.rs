// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
use std::{env, path::PathBuf};
fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let native = root.join("native");
    let backend = root.join("../pq-crypto/native/mldsa-native/mldsa");
    println!("cargo:rerun-if-changed=native");
    println!("cargo:rerun-if-changed={}", backend.display());
    cc::Build::new()
        .std("c90")
        .include(&native)
        .include(&backend)
        .define("MLD_CONFIG_FILE", Some("\"consensus-signer-config.h\""))
        .file(backend.join("mldsa_native.c"))
        .file(native.join("abi_check.c"))
        .compile("rtos_pq_consensus_signer");
}
