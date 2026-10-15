// Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
#[cfg(target_os = "linux")]
fn check() -> anyhow::Result<()> {
    use std::{collections::BTreeMap, path::PathBuf};
    use storage::archives::{
        epoch::ArchivalModeConfig,
        recovery_check::{inspect, resolve_checked, CheckConfig},
    };
    #[derive(serde::Deserialize)]
    struct Projection {
        internal_db_path: Option<String>,
        archival_mode: Option<ArchivalModeConfig>,
    }
    let mut args = std::env::args().skip(1);
    let mut values = BTreeMap::new();
    while let Some(key) = args.next() {
        anyhow::ensure!(
            ["--node-config", "--node-working-directory", "--db-root-override"]
                .contains(&key.as_str()),
            "unknown argument"
        );
        let value = args.next().ok_or_else(|| anyhow::anyhow!("argument value missing"))?;
        anyhow::ensure!(values.insert(key, value).is_none(), "duplicate argument");
    }
    let working_arg = PathBuf::from(
        values
            .remove("--node-working-directory")
            .ok_or_else(|| anyhow::anyhow!("--node-working-directory required"))?,
    );
    let working = resolve_checked(&std::env::current_dir()?, &working_arg)?;
    anyhow::ensure!(working.is_dir(), "node working directory must be a directory");
    let config_arg = PathBuf::from(
        values.remove("--node-config").ok_or_else(|| anyhow::anyhow!("--node-config required"))?,
    );
    let config_path = resolve_checked(&working, &config_arg)?;
    let bytes = std::fs::read(&config_path)?;
    let projection: Projection = serde_json::from_slice(&bytes)?;
    let override_root = values.remove("--db-root-override");
    let root = override_root
        .clone()
        .or(projection.internal_db_path)
        .unwrap_or_else(|| rtos::config::TonNodeConfig::DEFAULT_DB_ROOT.to_owned());
    let report = inspect(&CheckConfig {
        node_root: root.into(),
        working_directory: working.clone(),
        archival_mode: projection.archival_mode,
    })?;
    anyhow::ensure!(
        resolve_checked(&working, &config_arg)? == config_path
            && std::fs::read(&config_path)? == bytes,
        "node configuration changed during inspection"
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "node_config":config_path,"config_sha256":hex::encode(rtos_block::sha256_digest(&bytes)),
            "node_working_directory":working,"db_root_override":override_root,"result":report
        }))?
    );
    Ok(())
}
fn main() {
    #[cfg(target_os = "linux")]
    if let Err(error) = check() {
        eprintln!("Archive recovery precheck inconclusive: {error}");
        std::process::exit(1);
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("Archive recovery precheck currently requires Linux native lock validation");
        std::process::exit(1);
    }
}
