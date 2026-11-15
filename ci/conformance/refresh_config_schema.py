#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
"""Refresh legacy CP43/47 verdicts using only the pinned, clean C++ reference.

Export inputs with the ignored export_existing_schema_43_47_contexts Rust test;
it reads existing corpus cells and fingerprints, never Rust verdicts. Keep raw
contexts/effects outside Git. This does not modify the shared frozen fixtures.
"""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--contexts", type=Path, required=True)
    parser.add_argument("--effects", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    pin = Path(__file__).with_name("REFERENCE").read_text().strip()
    info = subprocess.run(
        [str(args.reference), "--info"],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    info = json.loads(info.stdout)
    if info.get("reference_commit") != pin or info.get("dirty") is not False:
        raise SystemExit("reference must be the clean pinned C++ build")
    rows = [line.split("\t") for line in args.contexts.read_text().splitlines()]
    if len(rows) != 390 or len({row[0] for row in rows}) != len(rows):
        raise SystemExit("expected 390 distinct original CP43/47 corpus inputs")
    contexts = [json.loads(row[2]) for row in rows]
    if any(c["type"] != "ConfigParam" or c["n"] not in (43, 47) for c in contexts):
        raise SystemExit("unexpected context type")
    result = subprocess.run(
        [str(args.reference), "codec"],
        input="".join(row[2] + "\n" for row in rows),
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
    )
    effects = [json.loads(line) for line in result.stdout.splitlines()]
    if len(effects) != len(rows):
        raise SystemExit("reference response count differs")
    output = []
    for row, effect in zip(rows, effects):
        gen = effect.get("facts", {}).get("gen")
        if not isinstance(gen, bool) or effect.get("outcome") != (
            "accepted" if gen else "rejected"
        ):
            raise SystemExit(f"unusable C++ verdict: {row[0]}")
        if not gen and effect.get("reason") != "tlb":
            raise SystemExit(f"unusable C++ rejection: {row[0]}")
        output.append(f"{row[0]}\t{row[1]}\t{int(gen)}\n")
    args.effects.write_text(result.stdout)
    header = (
        f"# reference_commit={pin} contexts_sha256={digest(args.contexts)} "
        f"reference_sha256={digest(args.reference)} effects_sha256={digest(args.effects)}\n"
        "# columns=id,input_fingerprint,generated_validate\n"
    )
    args.output.write_text(header + "".join(output))
    print(f"refreshed {len(rows)} pinned C++ verdicts")


if __name__ == "__main__":
    main()
