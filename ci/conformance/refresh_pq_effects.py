#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
"""Refresh legacy PQ test expectations from the pinned shared reference fixtures."""

import argparse
import base64
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FAMILIES = ("pq-mldsa44", "pq-suite", "pq-falcon512", "lms-fee")
OPCODES = {
    "pq-mldsa44": 0xF93100,
    "pq-falcon512": 0xF93101,
    "pq-suite": 0xF93102,
    "lms-fee": 0xF93103,
}


def repeated_code(family, repeats):
    if not 1 <= repeats <= 12:
        raise ValueError("repeat count must be within 1..12")
    opcode = OPCODES[family].to_bytes(3, "big")
    code = b"\x30".join([opcode] * repeats)  # DROP separates verification calls.
    # Canonical single-root ordinary BOC, with no index or checksum.
    header = bytes.fromhex("b5ee9c720101010100")
    return base64.b64encode(
        header + bytes([len(code) + 2, 0, 0, len(code) * 2]) + code
    ).decode()


def read_family(path):
    blobs_path = path.with_suffix(".blobs.json")
    blobs = json.loads(blobs_path.read_text()) if blobs_path.exists() else {}

    def expand(value):
        if isinstance(value, dict):
            if set(value) == {"blob"}:
                return blobs[value["blob"]]
            return {k: expand(v) for k, v in value.items()}
        if isinstance(value, list):
            return [expand(v) for v in value]
        return value

    return {
        fixture["metadata"]["fixture_id"]: expand(fixture)
        for fixture in map(json.loads, path.read_text().splitlines())
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference", type=Path, help="clean TOS checkout at REFERENCE")
    args = parser.parse_args()
    expected_commit = (ROOT / "ci/conformance/REFERENCE").read_text().strip()
    actual_commit = subprocess.check_output(
        ["git", "-C", str(args.reference), "rev-parse", "HEAD"], text=True
    ).strip()
    if actual_commit != expected_commit:
        raise ValueError("reference checkout does not match REFERENCE")
    if subprocess.check_output(
        ["git", "-C", str(args.reference), "status", "--porcelain"], text=True
    ).strip():
        raise ValueError("reference checkout must be clean")
    vectors = args.reference / "test/conformance/vectors/vm/fixtures"
    overrides = read_family(vectors / "rtos-pq-chksig.jsonl")
    updates = []
    for family in FAMILIES:
        fixture_path = vectors / f"rtos-{family}.jsonl"
        fixtures = read_family(fixture_path)
        path = ROOT / "vm/tests/data" / f"{family}.json"
        data = json.loads(path.read_text())
        for case in data["cases"]:
            fixture = (
                overrides[f"{family}/{case['name']}"]
                if case["ignore"]
                else fixtures[case["name"]]
            )
            context = fixture["context"]
            if set(context) - {
                "code",
                "global_version",
                "gas",
                "stack",
                "chksig_always_succeed",
            }:
                raise ValueError("unexpected VM context field")
            if case["program"] is None and context["code"] != repeated_code(
                family, case["repeats"]
            ):
                raise ValueError(f"{family}/{case['name']}: opcode context changed")
            if context["global_version"] != case["version"] or context["gas"] != {
                "limit": case["gas"],
                "max": 1_000_000_000,
            }:
                raise ValueError(f"{family}/{case['name']}: VM context changed")
            stack = []
            for _ in range(case["repeats"]):
                for operand in case["operands"]:
                    if operand == "skip":
                        continue
                    if operand == "int":
                        stack.append({"type": "int", "value": "1"})
                    elif operand == "null":
                        stack.append({"type": "null"})
                    elif operand == "tuple":
                        stack.append({"type": "tuple", "items": []})
                    elif operand == "slice":
                        stack.append({"type": "slice", "boc": "te6ccgEBAQEAAgAAAA=="})
                    elif operand == "nan":
                        stack.append({"type": "nan"})
                    elif isinstance(operand, str) and operand.startswith("int:"):
                        stack.append({"type": "int", "value": operand[4:]})
                    else:
                        stack.append(
                            {
                                "type": "cell",
                                "boc": base64.b64encode(
                                    bytes.fromhex(data["cells"][operand])
                                ).decode(),
                            }
                        )
            if case["program"] is not None:
                stack.append({"type": "int", "value": "0"})
                if (
                    context["code"]
                    != base64.b64encode(
                        bytes.fromhex(data["cells"][case["program"]])
                    ).decode()
                ):
                    raise ValueError("program context changed")
            if (
                context["stack"] != stack
                or context.get("chksig_always_succeed", False) != case["ignore"]
            ):
                raise ValueError(f"{family}/{case['name']}: operand context changed")
            effect = fixture["effects"]
            output = [
                effect["exit_code"],
                effect["gas_used"],
                int(effect["stack"][0]) if effect["exit_code"] == 0 else 99,
                int(effect["committed"]),
                effect["c4_hash"].lower() if effect["c4_hash"] else "-",
                effect["c5_hash"].lower() if effect["c5_hash"] else "-",
                effect["steps"],
            ]
            case["expected"] = output[: len(case["expected"])]
        data["conformance"] = {
            "suite_commit": actual_commit,
            "family_sha256": hashlib.sha256(fixture_path.read_bytes()).hexdigest(),
            "override_sha256": hashlib.sha256(
                (vectors / "rtos-pq-chksig.jsonl").read_bytes()
            ).hexdigest(),
        }
        updates.append((path, json.dumps(data, indent=2) + "\n"))
    # All input checks complete before writing any family.
    for path, text in updates:
        path.write_text(text)
        print(path.relative_to(ROOT))


if __name__ == "__main__":
    main()
