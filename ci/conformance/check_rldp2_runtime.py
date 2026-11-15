#!/usr/bin/env python3
"""Compare caller-visible completion and complete payloads from runtime probes.

Implementation-specific diagnostics are retained in the original JSONL files;
this check does not qualify timing, packet traces, or resource/lifecycle effects.
"""

import argparse
import hashlib
import json
from pathlib import Path


def read_effects(path, ids):
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    if [row["id"] for row in rows] != ids:
        raise ValueError(f"{path}: missing, reordered, duplicated, or extra cases")
    for row in rows:
        if row["status"] not in {"answer", "timeout", "no_answer", "error"}:
            raise ValueError(f"{path}: invalid or harness-failed completion")
        bytes.fromhex(row["payload_hex"])
        if row["status"] != "answer" and row["payload_hex"]:
            raise ValueError(f"{path}: failed completion carries payload")
        payload = bytes.fromhex(row["payload_hex"])
        row["payload_bytes"] = len(payload)
        row["payload_sha256"] = hashlib.sha256(payload).hexdigest()
    return rows


def read_frozen(path, cases, ids):
    document = json.loads(path.read_text())
    pin = Path(__file__).with_name("REFERENCE").read_text().strip()
    if document["reference_commit"] != pin:
        raise ValueError("frozen reference is not the current pinned commit")
    if document["input_sha256"] != hashlib.sha256(cases.read_bytes()).hexdigest():
        raise ValueError("frozen reference does not match the input corpus")
    rows = document["effects"]
    if [row["id"] for row in rows] != ids:
        raise ValueError("frozen reference has missing, reordered, or extra cases")
    for row in rows:
        if row["status"] not in {"answer", "timeout", "no_answer", "error"}:
            raise ValueError("invalid frozen completion")
        if not isinstance(row["payload_bytes"], int) or row["payload_bytes"] < 0:
            raise ValueError("invalid frozen payload length")
        if len(bytes.fromhex(row["payload_sha256"])) != 32:
            raise ValueError("invalid frozen payload digest")
        if row["status"] != "answer" and row["payload_bytes"] != 0:
            raise ValueError("frozen failure carries payload")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, required=True)
    reference = parser.add_mutually_exclusive_group(required=True)
    reference.add_argument("--reference", type=Path)
    reference.add_argument("--frozen-reference", type=Path)
    parser.add_argument("--actual", type=Path, required=True)
    args = parser.parse_args()
    ids = [
        line.split()[0]
        for line in args.cases.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    if not ids or len(set(ids)) != len(ids):
        raise ValueError("empty or duplicate case ids")
    reference_path = args.reference or args.frozen_reference
    expected = (
        read_effects(args.reference, ids)
        if args.reference
        else read_frozen(args.frozen_reference, args.cases, ids)
    )
    actual = read_effects(args.actual, ids)
    differences = []
    for left, right in zip(expected, actual, strict=True):
        fields = [
            key
            for key in ("status", "payload_bytes", "payload_sha256")
            if left[key] != right[key]
        ]
        if fields:
            differences.append(
                {
                    "id": left["id"],
                    "fields": fields,
                    "reference_status": left["status"],
                    "actual_status": right["status"],
                    "reference_payload_bytes": left["payload_bytes"],
                    "actual_payload_bytes": right["payload_bytes"],
                }
            )
    print(
        json.dumps(
            {
                "cases": len(ids),
                "equal": len(ids) - len(differences),
                "differences": differences,
                "input_sha256": hashlib.sha256(args.cases.read_bytes()).hexdigest(),
                "reference_sha256": hashlib.sha256(
                    reference_path.read_bytes()
                ).hexdigest(),
                "actual_sha256": hashlib.sha256(args.actual.read_bytes()).hexdigest(),
            },
            indent=2,
        )
    )
    raise SystemExit(bool(differences))


if __name__ == "__main__":
    main()
