// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Native TL schema/profile adapter; expectations are never read.
use anyhow::{ensure, Context, Result};
use rtos_api::{BoxedDeserialize, Constructor, WireProfile};
use serde_json::{json, Value};
use std::io::{self, BufRead, Read, Write};

fn rejected(reason: &str) -> Value {
    json!({"outcome":"rejected","reason":reason})
}
fn run(ctx: &Value) -> Result<Value> {
    let schema = match ctx["schema"].as_str().context("schema required")? {
        "tos_api" => "tos_api",
        "lite_api" => "lite_api",
        "toslib_api" => "toslib_api",
        _ => anyhow::bail!("unknown schema"),
    };
    let kind = ctx["kind"].as_str().context("kind required")?;
    ensure!(matches!(schema, "tos_api" | "lite_api" | "toslib_api"), "unknown schema");
    ensure!(matches!(kind, "object" | "function"), "kind must be object or function");
    ensure!(schema != "toslib_api" || kind == "object", "toslib_api has no TL wire functions");
    let text = ctx["bytes"].as_str().context("bytes required")?;
    ensure!(text.len() <= 2 << 20, "bytes: more than 1 MiB");
    let bytes = hex::decode(text)?;
    if bytes.len() < 4 {
        return Ok(rejected("truncated"));
    }
    let id = u32::from_le_bytes(bytes[..4].try_into()?);
    let profile = WireProfile::T0;
    if (schema == "toslib_api"
        && id != rtos_api::ton::raw::extmessageinfo::ExtMessageInfoV2::constructor_const())
        || !profile.constructor_in_schema(id, schema, kind == "function")
    {
        return Ok(rejected("unknown_constructor"));
    }
    let (value, consumed) = match profile.deserialize_schema_with_suffix(schema, &bytes) {
        Ok(value) => value,
        Err(error) => {
            let text = error.to_string();
            let reason = if error
                .downcast_ref::<rtos_api::InvalidConstructor>()
                .is_some_and(|e| e.expected == rtos_api::ton::Bool::possible_constructors())
            {
                "invalid_value"
            } else if error.downcast_ref::<rtos_api::InvalidConstructor>().is_some()
                || text.contains("constructor")
            {
                "unknown_constructor"
            } else if error
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::UnexpectedEof)
                || text.starts_with("Invalid TL vector length")
            {
                "truncated"
            } else if text.starts_with("Too big string") {
                "oversize"
            } else {
                "invalid_value"
            };
            return Ok(rejected(reason));
        }
    };
    if consumed != bytes.len() {
        return Ok(rejected("trailing_data"));
    }
    let canonical = profile.serialize(&value)?;
    Ok(json!({"outcome":"accepted","constructor":id as i32,"bytes":hex::encode(canonical)}))
}
fn main() -> Result<()> {
    let harness = std::env::args().nth(1).unwrap_or_default();
    if harness == "--info" {
        println!("{}", json!({"harnesses":["tl"]}));
        return Ok(());
    }
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    loop {
        let mut line = String::new();
        let size = input.by_ref().take((3 << 20) + 2).read_line(&mut line)?;
        if size == 0 {
            break;
        }
        let effect = (|| -> Result<Value> {
            ensure!(size <= 3 << 20, "context too large");
            ensure!(harness == "tl", "unsupported harness");
            run(&serde_json::from_str::<Value>(&line)?)
        })()
        .unwrap_or_else(|e| json!({"harness_error":e.to_string()}));
        serde_json::to_writer(&mut output, &effect)?;
        writeln!(output)?;
        output.flush()?;
        ensure!(size <= 3 << 20, "context too large");
    }
    Ok(())
}
