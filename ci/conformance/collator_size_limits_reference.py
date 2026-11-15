#!/usr/bin/env python3
# Copyright 2026 RTOS contributors. SPDX-License-Identifier: GPL-3.0-or-later
"""Generate native TOS replacements for the three legacy TON collator fixtures."""

import argparse
import hashlib
import json
import shlex
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpp-build", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    build = args.cpp_build.resolve()
    out = args.out.resolve()
    if out.exists() and any(out.iterdir()):
        raise SystemExit("output directory must be empty to preserve earlier receipts")
    repo = Path(__file__).resolve().parents[2]
    bundle_names = [
        "0.8000000000000000_76189835_5ca9034e_collator_test_bundle",
        "0.8000000000000000_76770988_db9fc78e_collator_test_bundle",
        "0.e000000000000000_67704975_6cea4ad1_collator_test_bundle",
    ]
    inputs = []
    for name in bundle_names:
        bundle = repo / "rtos/src/tests/static" / name
        index = json.loads((bundle / "index.json").read_text())
        root_hash = index["last_mc_state"].split("rh ")[1].split(",")[0]
        if len(root_hash) != 64 or any(c not in "0123456789abcdef" for c in root_hash):
            raise SystemExit("invalid fixture block hash")
        inputs.append(bundle / "states" / root_hash)
    source = Path(__file__).with_suffix(".cpp")
    cache = (build / "CMakeCache.txt").read_text()
    source_root = Path(
        next(
            line.split("=", 1)[1]
            for line in cache.splitlines()
            if line.startswith("CMAKE_HOME_DIRECTORY:INTERNAL=")
        )
    )
    revision = subprocess.check_output(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"], text=True
    ).strip()
    if revision != (source.parent / "REFERENCE").read_text().strip():
        raise SystemExit("native source revision differs from REFERENCE")
    if subprocess.check_output(
        ["git", "-C", str(source_root), "status", "--porcelain"], text=True
    ).strip():
        raise SystemExit("native source checkout is not clean")
    out.mkdir(parents=True, exist_ok=True)
    with (out / "build.log").open("w") as log:
        subprocess.run(
            [
                "ninja",
                "-C",
                str(build),
                "-j32",
                "conformance-ref-cli",
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
            check=True,
        )
        commands = subprocess.check_output(
            ["ninja", "-C", str(build), "-t", "commands", "conformance-ref-cli"],
            text=True,
        ).splitlines()
        compile_args = shlex.split(
            next(
                line
                for line in commands
                if "harness-codec.cpp.o" in line and " -c " in line
            )
        )
        compiler = (
            compile_args[1]
            if Path(compile_args[0]).name in {"ccache", "sccache"}
            else compile_args[0]
        )
        flags = []
        for index, arg in enumerate(compile_args):
            if arg.startswith(("-I", "-D", "-std=")):
                flags.append(arg)
            if arg == "-isystem":
                flags.extend([arg, compile_args[index + 1]])
        compile_command = [
            compiler,
            *flags,
            "-O1",
            "-c",
            str(source),
            "-o",
            str(out / "probe.o"),
        ]
        subprocess.run(
            compile_command, cwd=build, stdout=log, stderr=subprocess.STDOUT, check=True
        )
        link_args = shlex.split(
            next(
                line
                for line in commands
                if " -o test/conformance/libconformance-ref.so" in line
            )
        )
        libraries = [
            arg for arg in link_args if arg.endswith(".a") or arg.startswith("-l")
        ]
        link_command = [
            compiler,
            str(out / "probe.o"),
            "-o",
            str(out / "probe"),
            "-Wl,--start-group",
            *libraries,
            "-Wl,--end-group",
            "-lpthread",
            "-ldl",
        ]
        subprocess.run(
            link_command, cwd=build, stdout=log, stderr=subprocess.STDOUT, check=True
        )
    with (out / "native.log").open("w") as log:
        result = subprocess.run(
            [str(out / "probe"), *[str(path) for path in inputs]],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            check=False,
        )
    if result.returncode:
        raise SystemExit(result.returncode)
    rows = []
    cells = {}
    lines = (out / "native.log").read_text().splitlines()
    if len(lines) != len(inputs):
        raise SystemExit("native probe did not return one result per input")
    for path, line in zip(inputs, lines, strict=True):
        fields = line.split()
        if len(fields) != 10 or fields[0] != "MIGRATION":
            raise SystemExit("invalid native migration record")
        old_hash, new_hash, old_boc, new_boc = fields[1:5]
        cell = {
            "old_hash": old_hash.lower(),
            "new_hash": new_hash.lower(),
            "old_boc": old_boc,
            "new_boc": new_boc,
            "library_limit": None if fields[5] == "none" else int(fields[5]),
            "max_total_msg_bits": int(fields[6]),
            "max_total_msg_cells": int(fields[7]),
            "queue_hard": int(fields[8]),
            "queue_soft": int(fields[9]),
        }
        key = cell["old_hash"]
        if key in cells and cells[key] != cell:
            raise SystemExit("same source cell produced different native replacements")
        cells[key] = cell
        rows.append(
            {
                "path": str(path.relative_to(repo)),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "old_hash": key,
            }
        )
    fixture = {
        "reference_commit": revision,
        "source_inputs": rows,
        "cells": [cells[key] for key in sorted(cells)],
    }
    (out / "migrations.json").write_text(json.dumps(fixture, indent=2) + "\n")
    receipt = {
        "reference_commit": revision,
        "native_source": str(source_root),
        "native_build": str(build),
        "runner_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "probe_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "probe_binary_sha256": hashlib.sha256((out / "probe").read_bytes()).hexdigest(),
        "exit": result.returncode,
        "output_sha256": hashlib.sha256(
            (out / "migrations.json").read_bytes()
        ).hexdigest(),
        "compile_command": compile_command,
        "link_command": link_command,
    }
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"Native TOS generated {len(cells)} cells for {len(inputs)} fixture inputs")
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
