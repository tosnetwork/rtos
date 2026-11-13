/*
 * RTOS project modifications (2026-10-10): naming and Cargo-owned generated sources.
 * Copyright (C) 2019-2022 TON Labs. All Rights Reserved.
 * Modifications Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This file has been modified from its original version.
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
use rtos_tl_codegen::Config;
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

fn get_value(cmd: &str, args: &[&str]) -> String {
    if let Ok(result) = Command::new(cmd).args(args).output() {
        if let Ok(result) = String::from_utf8(result.stdout) {
            return result;
        }
    }
    "Unknown".to_string()
}

const TL_DIR: &str = "tl";
const TL_FILES: [&str; 3] = ["lite_api.tl", "ton_api.tl", "tonlib_api.tl"];

fn main() {
    println!("cargo:rerun-if-changed={}", TL_DIR);
    println!("cargo:rerun-if-changed=../rtos_tl_codegen");

    let mut files: Vec<PathBuf> =
        TL_FILES.iter().map(|file| Path::new(TL_DIR).join(file)).collect();
    files.sort();

    let mut input = String::new();
    let mut domains = String::from("&[\n");
    for file in files {
        if !input.is_empty() {
            input += "---types---\n";
        }
        let start = input.len();
        fs::File::open(&file)
            .unwrap_or_else(|_| {
                panic!("Unable to open file for reading: {}", file.to_string_lossy())
            })
            .read_to_string(&mut input)
            .unwrap_or_else(|_| panic!("Unable to read file contents: {}", file.to_string_lossy()));
        let schema = match file.file_name().unwrap().to_str().unwrap() {
            "lite_api.tl" => "lite_api",
            "ton_api.tl" => "tos_api",
            "tonlib_api.tl" => "toslib_api",
            _ => unreachable!(),
        };
        let mut function = false;
        for rtos_tl_codegen::parser::Matched(item, _) in
            rtos_tl_codegen::parser::parse_string(&input[start..]).expect("parse schema domains")
        {
            use rtos_tl_codegen::parser::{Delimiter, Item};
            match item {
                Item::Delimiter(delimiter) => function = delimiter == Delimiter::Functions,
                Item::Constructor(constructor) => {
                    if let Some(id) = constructor.tl_id {
                        domains += &format!("({id}, {schema:?}, {function}),\n");
                    }
                }
            }
        }
        println!("cargo:rerun-if-changed={}", file.to_string_lossy());
    }

    let config_path = Path::new(TL_DIR).join("codegen.json");
    let config: Option<Config> = if config_path.exists() && config_path.is_file() {
        let mut config_string = String::new();
        fs::File::open(&config_path)
            .unwrap_or_else(|_| {
                panic!("Unable to open file for reading: {}", config_path.to_string_lossy())
            })
            .read_to_string(&mut config_string)
            .unwrap_or_else(|_| {
                panic!("Unable to read file contents: {}", config_path.to_string_lossy())
            });
        Some(serde_json::from_str(&config_string).unwrap_or_else(|_| {
            panic!("Unable to parse file as JSON: {}", config_path.to_string_lossy())
        }))
    } else {
        None
    };

    // Generated files belong to the cached build output, not to a checkout.
    // Otherwise a shared target can reuse this build script's fingerprint in
    // another worktree whose ignored src/ton directory has never been generated.
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"));
    domains += "]";
    fs::write(out_dir.join("schema_domains.rs"), domains).expect("write schema domains");
    let generated = out_dir.join("ton");
    rtos_tl_codegen::generate_code_for(config, &input, &generated);
    // A path module preserves the generated root's inner attributes and its
    // relative child modules; including that root directly would not.
    fs::write(
        out_dir.join("ton_module.rs"),
        format!(
            "#[rustfmt::skip]\n#[allow(non_camel_case_types)]\n#[path = {:?}]\npub mod ton;\n",
            generated.join("mod.rs")
        ),
    )
    .expect("write generated TL module declaration");

    let git_branch = get_value("git", &["rev-parse", "--abbrev-ref", "HEAD"]);
    let git_commit = get_value("git", &["rev-parse", "HEAD"]);
    let commit_date = get_value("git", &["log", "-1", "--date=iso", "--pretty=format:%cd"]);
    let build_time = get_value("date", &["+%Y-%m-%d %T %z"]);
    let rust_version = get_value("rustc", &["--version"]);

    println!("cargo:rustc-env=BUILD_GIT_BRANCH={}", git_branch);
    println!("cargo:rustc-env=BUILD_GIT_COMMIT={}", git_commit);
    println!("cargo:rustc-env=BUILD_GIT_DATE={}", commit_date);
    println!("cargo:rustc-env=BUILD_TIME={}", build_time);
    println!("cargo:rustc-env=BUILD_RUST_VERSION={}", rust_version);
}
