#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
"""Apply the pinned CPP getter-v16 shape change to legacy TSV expectations.

Only scalar length/slot probes and the final null field of full c7 are changed.
Other state-dependent legacy hashes and values remain untouched. No Rust target
is executed and no Rust output is used as an expectation.
"""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def parse_value(text):
    tokens = iter(re.findall(r"\(|\)|[^ ()]+", text))

    def read(token):
        if token != "(":
            if token == ")":
                raise ValueError("unbalanced tuple")
            return token
        values = []
        for child in tokens:
            if child == ")":
                return values
            values.append(read(child))
        raise ValueError("unterminated tuple")

    value = read(next(tokens))
    if next(tokens, None) is not None:
        raise ValueError("trailing value")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference", type=Path)
    args = parser.parse_args()
    commit = (ROOT / "ci/conformance/REFERENCE").read_text().strip()
    actual = subprocess.check_output(
        ["git", "-C", str(args.reference), "rev-parse", "HEAD"], text=True
    ).strip()
    dirty = subprocess.check_output(
        ["git", "-C", str(args.reference), "status", "--porcelain"], text=True
    ).strip()
    if actual != commit or dirty:
        raise ValueError("expected clean checkout at REFERENCE")
    fixtures = args.reference / "test/conformance/vectors/get_method/fixtures"
    provenance = {
        "reference_commit": commit,
        "rule": "CPP v16 getter c7 has19 fields; last is null",
        "sources": {},
    }
    changes = {}
    for family, legacy in [
        ("rust-get-context", "get-context.tsv"),
        ("rust-get-history-context", "get-history-context.tsv"),
    ]:
        source = fixtures / f"{family}.jsonl"
        provenance["sources"][family] = hashlib.sha256(source.read_bytes()).hexdigest()
        records = {
            r["metadata"]["fixture_id"]: r
            for r in map(json.loads, source.read_text().splitlines())
        }
        path = ROOT / "vm/src/tests/data" / legacy
        rows = []
        changed = 0
        for line in path.read_text().splitlines():
            name, exit_code, gas, stack = line.split("\t")
            match = re.match(r"(?:get|history)-v(\d+)-", name)
            if match and int(match[1]) >= 16:
                record = records[name]
                if family == "rust-get-context" and name.endswith(
                    ("-length", "-null", "-fields")
                ):
                    effect = record["effects"]
                    if effect["outcome"] != "executed":
                        raise ValueError("CPP scalar control did not execute")
                    line = f"{name}\t{effect['exit_code']}\t{effect['gas_used']}\t{','.join(effect['stack'])}"
                elif (
                    family == "rust-get-history-context"
                    and name.endswith("-context")
                    and exit_code != "ERROR"
                ):
                    effect = record["effects"]
                    fields = parse_value(effect["stack"][0])[0]
                    if len(fields) != 19 or fields[-1] != "null":
                        raise ValueError("CPP getter shape differs")
                    if effect["exit_code"] != int(exit_code) or effect[
                        "gas_used"
                    ] != int(gas):
                        raise ValueError("CPP context execution differs beyond shape")
                    # Legacy snapshots differ from the newer frozen corpus.
                    # Append only CPP's final null, preserving every old hash.
                    if not stack.endswith(";null]]"):
                        if not stack.endswith("]]"):
                            raise ValueError("legacy c7 is not an outer/inner tuple")
                        line = f"{name}\t{exit_code}\t{gas}\t{stack[:-2]};null]]"
            changed += line != f"{name}\t{exit_code}\t{gas}\t{stack}"
            rows.append(line)
        path.write_text("\n".join(rows) + "\n")
        changes[legacy] = changed
    (ROOT / "vm/src/tests/data/getter-shape-reference.json").write_text(
        json.dumps(provenance, indent=2) + "\n"
    )
    print(json.dumps(changes, sort_keys=True))


if __name__ == "__main__":
    main()
