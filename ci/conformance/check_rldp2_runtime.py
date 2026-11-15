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
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--actual", type=Path, required=True)
    args = parser.parse_args()
    ids = [
        line.split()[0]
        for line in args.cases.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    if not ids or len(set(ids)) != len(ids):
        raise ValueError("empty or duplicate case ids")
    expected = read_effects(args.reference, ids)
    actual = read_effects(args.actual, ids)
    differences = []
    for left, right in zip(expected, actual, strict=True):
        fields = [key for key in ("status", "payload_hex") if left[key] != right[key]]
        if fields:
            differences.append(
                {
                    "id": left["id"],
                    "fields": fields,
                    "reference_status": left["status"],
                    "actual_status": right["status"],
                    "reference_payload_bytes": len(left["payload_hex"]) // 2,
                    "actual_payload_bytes": len(right["payload_hex"]) // 2,
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
                    args.reference.read_bytes()
                ).hexdigest(),
                "actual_sha256": hashlib.sha256(args.actual.read_bytes()).hexdigest(),
            },
            indent=2,
        )
    )
    raise SystemExit(bool(differences))


if __name__ == "__main__":
    main()
