#!/usr/bin/env python3
"""Verify original archive packages and index block identities, without C++ output."""

import argparse
import hashlib
import json
import re
import sqlite3
import struct
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

BLOCK = re.compile(
    r"block_\((-?\d+),([0-9a-fA-F]{1,16}),(\d+)\):([0-9a-fA-F]{64}):([0-9a-fA-F]{64})"
)


def scan(item):
    path, expected = item
    entries = []
    kinds = Counter()
    with path.open("rb") as stream:
        before = path.stat()
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != expected:
            raise ValueError(f"package digest mismatch: {path}")
        stream.seek(0)
        if stream.read(4) != struct.pack("<I", 0xAE8FDD01):
            raise ValueError(f"package magic: {path}")
        while stream.tell() < before.st_size:
            header = stream.read(8)
            if len(header) != 8:
                raise ValueError(f"truncated header: {path}")
            tag, name_size, size = struct.unpack("<HHI", header)
            if tag != 0x1E8B or not 0 < name_size <= 1024 or size > 256 << 20:
                raise ValueError(f"invalid entry header: {path}")
            name = stream.read(name_size).decode("ascii")
            offset = stream.tell()
            if len(name) != name_size or offset + size > before.st_size:
                raise ValueError(f"truncated entry: {path}")
            kinds[name.split("_", 1)[0]] += 1
            if name.startswith("block_"):
                match = BLOCK.fullmatch(name)
                if match is None:
                    raise ValueError(f"invalid block name: {path}: {name}")
                wc, shard, seqno, root, file = match.groups()
                wc, seqno = int(wc), int(seqno)
                if not -(1 << 31) <= wc < 1 << 31 or not 0 <= seqno < 1 << 32:
                    raise ValueError(f"block position out of range: {name}")
                entries.append(
                    (
                        wc,
                        f"{int(shard, 16):016X}",
                        seqno,
                        root.upper(),
                        file.upper(),
                        str(path),
                        offset,
                        size,
                        name,
                    )
                )
            stream.seek(size, 1)
        after = path.stat()
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ValueError(f"package changed during scan: {path}")
    return str(path), digest, before.st_size, entries, kinds


def run(args):
    root = args.root.resolve(strict=True)
    manifest = args.sha256_list.read_bytes()
    items = []
    seen = set()
    for line in manifest.decode().splitlines():
        digest, name = line.split(maxsplit=1)
        name = name.removeprefix("*")
        if not re.fullmatch("[0-9a-fA-F]{64}", digest):
            raise ValueError("invalid SHA256 manifest")
        path = (root / name).resolve(strict=True)
        if not path.is_relative_to(root) or path in seen:
            raise ValueError(f"duplicate or external package: {name}")
        seen.add(path)
        items.append((path, digest.lower()))
    if not items:
        raise ValueError("empty package manifest")
    args.out.mkdir(parents=True, exist_ok=False)
    db = sqlite3.connect(args.out / "index.sqlite")
    db.executescript("""
        CREATE TABLE packages(path TEXT PRIMARY KEY, sha256 TEXT, bytes INTEGER);
        CREATE TABLE blocks(wc INTEGER, shard TEXT, seqno INTEGER, root TEXT, file TEXT,
            package TEXT, offset INTEGER, size INTEGER, name TEXT,
            PRIMARY KEY(wc, shard, seqno));
    """)
    summary = {
        "complete": False,
        "packages": 0,
        "block_entries": 0,
        "duplicates": 0,
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "kinds": {},
    }
    kinds = Counter()
    try:
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            # Keep at most jobs packages/results in flight, including slow early files.
            for start in range(0, len(items), args.jobs):
                with db:
                    for path, digest, size, entries, counts in pool.map(
                        scan, items[start : start + args.jobs]
                    ):
                        db.execute(
                            "INSERT INTO packages VALUES(?,?,?)", (path, digest, size)
                        )
                        for entry in entries:
                            prior = db.execute(
                                "SELECT root,file FROM blocks WHERE wc=? AND shard=? AND seqno=?",
                                entry[:3],
                            ).fetchone()
                            if prior is not None:
                                if prior != entry[3:5]:
                                    raise ValueError(
                                        f"conflicting block identity: {entry[:3]}"
                                    )
                                summary["duplicates"] += 1
                            else:
                                db.execute(
                                    "INSERT INTO blocks VALUES(?,?,?,?,?,?,?,?,?)",
                                    entry,
                                )
                        kinds.update(counts)
                        summary["packages"] += 1
                        summary["block_entries"] += len(entries)
        summary["chains"] = [
            dict(zip(("wc", "shard", "first", "last", "blocks"), row))
            for row in db.execute(
                "SELECT wc,shard,min(seqno),max(seqno),count(*) FROM blocks GROUP BY wc,shard"
            )
        ]
        for chain in summary["chains"]:
            chain["missing_within_range"] = (
                chain["last"] - chain["first"] + 1 - chain["blocks"]
            )
        summary["complete"] = True
    except Exception as error:
        summary["error"] = str(error)
        raise
    finally:
        summary["kinds"] = dict(kinds)
        db.close()
        (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--sha256-list", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--jobs", type=int, choices=range(1, 65), default=32)
    run(parser.parse_args())
