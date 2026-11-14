#!/usr/bin/env python3
"""Compare native replay roots/counts to a digest-pinned canonical archive replay."""

import argparse
import hashlib
import json
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path


def check(args):
    # Disk-backed identities avoid retaining the whole archive in Python objects.
    with (
        tempfile.TemporaryDirectory(prefix="rtos-shard-tops-") as directory,
        closing(
            sqlite3.connect(str(Path(directory) / "identities.sqlite"))
        ) as identities,
    ):
        return compare(args, identities)


def compare(args, identities):
    manifest = json.loads(args.reference_manifest.read_text())
    reference = args.reference_manifest.parent / "blocks.jsonl"
    expected_artifact = manifest["outputs"]["blocks.jsonl"]
    with reference.open("rb") as stream:
        reference_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    if (
        reference_hash != expected_artifact["sha256"]
        or reference.stat().st_size != expected_artifact["bytes"]
    ):
        raise ValueError("reference block artifact digest/size mismatch")
    identities.execute(
        "CREATE TABLE blocks(wc INTEGER,shard TEXT,seqno INTEGER,root TEXT,file TEXT,PRIMARY KEY(wc,shard,seqno))"
    )
    if args.require_shard_tops:
        with reference.open() as stream:
            identities.executemany(
                "INSERT INTO blocks VALUES(?,?,?,?,?)",
                (
                    (
                        r["workchain"],
                        r["shard"],
                        r["seqno"],
                        r["root_hash"],
                        r["file_hash"],
                    )
                    for r in map(json.loads, stream)
                    if r["workchain"] != -1
                ),
            )
        identities.commit()
    expected = manifest["summary"]
    if expected["mismatches"] or expected["gave_up"]:
        raise ValueError("reference replay contains mismatches or gave up")
    blocks = sum(expected[chain]["replayed"] for chain in ("masterchain", "shardchain"))
    size = args.effects.stat().st_size
    result = {
        "passed": False,
        "complete": False,
        "compared": 0,
        "equal": 0,
        "mismatched": 0,
        "refused": 0,
        "transactions": 0,
        "expected_blocks": blocks,
        "bootstrap_records": 0,
        "release_records": 0,
        "partial_line": False,
        "snapshot_bytes": size,
        "reference_blocks_sha256": reference_hash,
        "details": [],
        "shard_top_checks": 0,
        "require_shard_tops": args.require_shard_tops,
    }
    snapshot = hashlib.sha256()
    expected_bootstraps = {
        manifest[name]["sha256"].upper() for name in ("zerostate", "basestate")
    }
    bootstraps = set()
    with args.effects.open("rb") as candidate, reference.open() as canonical:
        while candidate.tell() < size:
            line = candidate.readline(size - candidate.tell())
            if not line:
                raise ValueError("candidate truncated while reading snapshot")
            snapshot.update(line)
            if not line.endswith(b"\n"):
                result["partial_line"] = True
                break
            actual = json.loads(line)
            if actual.get("bootstrap") is True:
                if result["compared"]:
                    raise ValueError("bootstrap after replay started")
                identity = actual["file_hash"]
                if identity not in expected_bootstraps or identity in bootstraps:
                    raise ValueError("unknown or duplicate bootstrap file hash")
                if (
                    args.require_shard_tops
                    and identity == manifest["basestate"]["sha256"].upper()
                ):
                    # MC1 may register the workchain zerostate, which has no block row.
                    identities.execute(
                        "INSERT INTO blocks VALUES(0,'8000000000000000',0,?,?)",
                        (actual["root_hash"], identity),
                    )
                bootstraps.add(identity)
                result["bootstrap_records"] += 1
                continue
            if "released_master" in actual:
                if set(actual) != {"released_master"} or not result["compared"]:
                    raise ValueError("invalid release response")
                result["release_records"] += 1
                continue
            if actual.get("outcome") != "accepted":
                result["refused"] += 1
                result["details"].append(actual)
                break
            expected_line = canonical.readline()
            if not expected_line:
                raise ValueError("candidate has extra blocks")
            row = json.loads(expected_line)
            if row["status"] != "ok" or row["mode"] != "full" or not row["linked"]:
                raise ValueError("reference row is not a full linked success")
            pairs = (
                ("block_root_hash", "root_hash"),
                ("file_hash", "file_hash"),
                ("new_state_hash", "new_state_hash"),
                ("workchain", "workchain"),
                ("seqno", "seqno"),
            )
            different = [left for left, right in pairs if actual[left] != row[right]]
            if args.require_shard_tops and actual["workchain"] == -1:
                tops = actual.get("shard_tops")
                # Match the reference replay's supported one-workchain layout.
                if not isinstance(tops, list) or len(tops) != 1:
                    different.append("shard_tops_layout")
                else:
                    top = tops[0]
                    if top["workchain"] != 0 or top["shard"] != "8000000000000000":
                        different.append("shard_tops_layout")
                    else:
                        identity = identities.execute(
                            "SELECT root,file FROM blocks WHERE wc=? AND shard=? AND seqno=?",
                            (top["workchain"], top["shard"], top["seqno"]),
                        ).fetchone()
                        result["shard_top_checks"] += 1
                        if identity is None or identity != (
                            top["root_hash"],
                            top["file_hash"],
                        ):
                            different.append("shard_top_identity")
            count = len(actual["transactions"])
            if not count == row["transactions"] == row["executed"] == row["matched"]:
                different.append("transactions")
            result["compared"] += 1
            result["transactions"] += count
            if different:
                result["mismatched"] += 1
                if len(result["details"]) < 5:
                    result["details"].append(
                        {
                            "workchain": actual["workchain"],
                            "seqno": actual["seqno"],
                            "fields": different,
                        }
                    )
            else:
                result["equal"] += 1
        result["snapshot_read_bytes"] = candidate.tell()
        if result["compared"] == blocks and canonical.readline():
            raise ValueError("reference summary undercounts block records")
    result["read_sha256"] = snapshot.hexdigest()
    result["not_compared"] = blocks - result["compared"]
    result["complete"] = result["compared"] == blocks and not result["partial_line"]
    successful = (
        result["complete"]
        and result["mismatched"] == result["refused"] == 0
        and bootstraps == expected_bootstraps
        and result["transactions"] == expected["transactions"]["matched"]
    )
    if not args.allow_prefix:
        if args.execution_log is None:
            raise ValueError("final comparison requires --execution-log")
        runtime = json.loads(args.execution_log.read_text().splitlines()[0])
        result["runtime"] = runtime
        successful = (
            successful
            and runtime["blocks"] == blocks
            and runtime["transactions"] == result["transactions"]
            and runtime["retained_master_contexts"] == 0
        )
    # Prefix observations are never final passes, even if the current size reaches the end.
    result["passed"] = successful and not args.allow_prefix
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-manifest", type=Path, required=True)
    parser.add_argument("--effects", type=Path, required=True)
    parser.add_argument("--execution-log", type=Path)
    parser.add_argument("--allow-prefix", action="store_true")
    parser.add_argument("--require-shard-tops", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    with args.out.open("x") as output:
        try:
            result = check(args)
            exit_code = (
                0
                if result["passed"]
                else (1 if result["mismatched"] or result["refused"] else 2)
            )
        except (
            ValueError,
            OSError,
            KeyError,
            TypeError,
            IndexError,
            sqlite3.Error,
        ) as error:
            result = {"passed": False, "error": str(error)}
            exit_code = 1
        output.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    raise SystemExit(exit_code)
