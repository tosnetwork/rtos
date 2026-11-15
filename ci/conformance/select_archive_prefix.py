#!/usr/bin/env python3
"""Select explicit contiguous genesis prefixes without hiding the omitted source range."""

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(args):
    source_path = args.index.resolve(strict=True)
    summary_path = source_path.parent / "summary.json"
    inventory = json.loads(summary_path.read_text())
    if not inventory["complete"] or inventory.get("selection"):
        raise ValueError("require a complete original index, not a nested selection")
    limits = {}
    for spec in args.through:
        wc, shard, seqno = spec.split(":")
        wc, shard, seqno = int(wc), int(shard, 16), int(seqno)
        if (
            not -(1 << 31) <= wc < 1 << 31
            or not 0 < shard < 1 << 64
            or not 0 < seqno < 1 << 32
        ):
            raise ValueError("invalid chain/sequence limit")
        key = (wc, f"{shard:016X}")
        if key in limits:
            raise ValueError("duplicate chain limit")
        limits[key] = seqno
    chains = {(c["wc"], c["shard"]): c for c in inventory["chains"]}
    if set(limits) != set(chains):
        raise ValueError("an explicit limit is required for every indexed chain")
    for key, limit in limits.items():
        if chains[key]["first"] != 1 or limit > chains[key]["last"]:
            raise ValueError(
                "prefix must start at genesis and end within the indexed range"
            )
    initial = {
        "index_sha256": digest(source_path),
        "summary_sha256": digest(summary_path),
    }
    source = sqlite3.connect(source_path.as_uri() + "?mode=ro", uri=True)
    original_count = source.execute("SELECT count(*) FROM blocks").fetchone()[0]
    for (wc, shard), limit in limits.items():
        count = source.execute(
            "SELECT count(*) FROM blocks WHERE wc=? AND shard=? AND seqno BETWEEN 1 AND ?",
            (wc, shard, limit),
        ).fetchone()[0]
        if count != limit:
            source.close()
            raise ValueError(
                f"selected prefix contains a gap: {wc}:{shard} through {limit}"
            )
    args.out.mkdir(parents=True, exist_ok=False)
    target = sqlite3.connect(args.out / "index.sqlite")
    result = {
        "complete": False,
        "selection": {
            "source_index": str(source_path),
            **initial,
            "source_indexed_blocks": original_count,
            "limits": args.through,
        },
    }
    try:
        source.backup(target)
        with target:
            for (wc, shard), limit in limits.items():
                target.execute(
                    "DELETE FROM blocks WHERE wc=? AND shard=? AND seqno>?",
                    (wc, shard, limit),
                )
        result["chains"] = [
            dict(zip(("wc", "shard", "first", "last", "blocks"), row))
            for row in target.execute(
                "SELECT wc,shard,min(seqno),max(seqno),count(*) FROM blocks GROUP BY wc,shard"
            )
        ]
        for chain in result["chains"]:
            chain["missing_within_range"] = (
                chain["last"] - chain["first"] + 1 - chain["blocks"]
            )
        count = sum(c["blocks"] for c in result["chains"])
        result["selection"].update(
            selected_blocks=count, not_selected=original_count - count
        )
        if initial != {
            "index_sha256": digest(source_path),
            "summary_sha256": digest(summary_path),
        }:
            raise ValueError("source index changed during selection")
        result["complete"] = True
    finally:
        source.close()
        target.close()
        (args.out / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument(
        "--through",
        action="append",
        required=True,
        help="WC:SHARD_HEX:SEQNO, once for every chain",
    )
    parser.add_argument("--out", type=Path, required=True)
    run(parser.parse_args())
