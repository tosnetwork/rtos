#!/usr/bin/env python3
"""Inspect native block dependencies and emit a sequential, reference-counted replay plan."""

import argparse
import hashlib
import json
import sqlite3
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def request(row):
    return dict(zip(("root_hash", "file_hash", "package", "offset", "name"), row))


def inspect(binary, rows):
    proc = subprocess.run(
        [str(binary), "--inspect"],
        input="".join(json.dumps(request(r[3:])) + "\n" for r in rows),
        text=True,
        capture_output=True,
        timeout=3600,
        check=False,
    )
    if proc.returncode:
        raise ValueError(
            f"native inspection failed: {proc.stderr[-2000:]} {proc.stdout[-2000:]}"
        )
    effects = [json.loads(line) for line in proc.stdout.splitlines()]
    if len(effects) != len(rows):
        raise ValueError("native inspection count mismatch")
    result = []
    for row, effect in zip(rows, effects):
        if tuple(effect[k] for k in ("workchain", "shard", "seqno")) != row[:3]:
            raise ValueError("native inspection position mismatch")
        if effect["prev_seqno"] + 1 != row[2]:
            raise ValueError("nonconsecutive native predecessor")
        result.append(
            (
                *row[:3],
                effect["prev_root_hash"],
                effect["prev_file_hash"],
                effect["master_seqno"],
                effect["master_root_hash"],
                effect["master_file_hash"],
            )
        )
    return result


def run(args):
    args.binary = args.binary.resolve(strict=True)
    index = args.index.resolve(strict=True)
    inventory = json.loads((index.parent / "summary.json").read_text())
    if not inventory["complete"] or not inventory["chains"]:
        raise ValueError("index is incomplete or empty")
    for chain in inventory["chains"]:
        if chain["first"] != 1 or chain["missing_within_range"]:
            raise ValueError("replay requires contiguous chains starting at one")
    initial = {"index": digest(index), "binary": digest(args.binary)}
    args.out.mkdir(parents=True, exist_ok=False)
    source = sqlite3.connect(f"file:{index}?mode=ro", uri=True)
    db = sqlite3.connect(args.out / "plan.sqlite")
    source.backup(db)
    source.close()
    db.execute(
        "CREATE TABLE headers(wc INTEGER,shard TEXT,seqno INTEGER,prev_root TEXT,prev_file TEXT,mc_seq INTEGER,mc_root TEXT,mc_file TEXT,PRIMARY KEY(wc,shard,seqno))"
    )
    summary = {
        "complete": False,
        "inspected": 0,
        "planned": 0,
        "released": 0,
        "mc_limit": args.mc_limit,
        "input_sha256": initial,
        "source_selection": inventory.get("selection"),
    }
    try:
        cursor = db.execute(
            "SELECT wc,shard,seqno,root,file,package,offset,name FROM blocks ORDER BY wc,shard,seqno"
        )
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            while True:
                batches = [cursor.fetchmany(1000) for _ in range(args.jobs)]
                batches = [batch for batch in batches if batch]
                if not batches:
                    break
                with db:
                    for rows in pool.map(
                        lambda batch: inspect(args.binary, batch), batches
                    ):
                        db.executemany(
                            "INSERT INTO headers VALUES(?,?,?,?,?,?,?,?)", rows
                        )
                        summary["inspected"] += len(rows)
                print(f"inspected {summary['inspected']}", flush=True)
        bad_prev = db.execute("""SELECT h.wc,h.seqno FROM headers h LEFT JOIN blocks p
            ON p.wc=h.wc AND p.shard=h.shard AND p.seqno=h.seqno-1
            WHERE h.seqno>1 AND (p.root IS NULL OR h.prev_root!=p.root OR h.prev_file!=p.file) LIMIT 1""").fetchone()
        bad_master = db.execute("""SELECT h.wc,h.seqno FROM headers h LEFT JOIN blocks m
            ON m.wc=-1 AND m.shard='8000000000000000' AND m.seqno=h.mc_seq
            WHERE (h.wc=-1 AND h.mc_seq IS NOT NULL) OR
            (h.wc!=-1 AND (m.root IS NULL OR h.mc_root!=m.root OR h.mc_file!=m.file)) LIMIT 1""").fetchone()
        if bad_prev or bad_master:
            raise ValueError(
                f"archive dependency mismatch: predecessor={bad_prev}, master={bad_master}"
            )
        # Counts include every inspected shard consumer, even beyond a requested prefix.
        remaining = dict(
            db.execute(
                "SELECT mc_root,count(*) FROM headers WHERE mc_root IS NOT NULL GROUP BY mc_root"
            )
        )
        chains = [(r["wc"], r["shard"]) for r in inventory["chains"] if r["wc"] != -1]
        cursors = [
            db.execute(
                """SELECT b.root,b.file,b.package,b.offset,b.name,h.mc_seq,h.mc_root
            FROM blocks b JOIN headers h USING(wc,shard,seqno) WHERE b.wc=? AND b.shard=? ORDER BY b.seqno""",
                chain,
            )
            for chain in chains
        ]
        heads = [c.fetchone() for c in cursors]
        maximum = args.mc_limit or (1 << 32) - 1
        retained = set()
        with (args.out / "inputs.jsonl").open("w") as output:

            def emit(value):
                output.write(json.dumps(value) + "\n")

            for zero in args.zerostate:
                emit({"zerostate": str(zero.resolve(strict=True))})
            for row in db.execute(
                "SELECT root,file,package,offset,name,seqno FROM blocks WHERE wc=-1 AND shard='8000000000000000' AND seqno<=? ORDER BY seqno",
                (maximum,),
            ):
                emit(request(row[:5]))
                summary["planned"] += 1
                retained.add(row[0])
                for i, cursor in enumerate(cursors):
                    while heads[i] is not None and heads[i][5] <= row[5]:
                        head = heads[i]
                        if head[6] not in retained:
                            raise ValueError("master released before its last consumer")
                        emit(request(head[:5]))
                        summary["planned"] += 1
                        remaining[head[6]] -= 1
                        if remaining[head[6]] == 0:
                            emit({"release_master": head[6]})
                            retained.remove(head[6])
                            summary["released"] += 1
                        heads[i] = cursor.fetchone()
                if remaining.get(row[0], 0) == 0 and row[0] in retained:
                    emit({"release_master": row[0]})
                    retained.remove(row[0])
                    summary["released"] += 1
        summary["not_planned"] = summary["inspected"] - summary["planned"]
        if not summary["planned"] or (args.mc_limit is None and summary["not_planned"]):
            raise ValueError("unplanned blocks remain or empty plan")
        if initial != {"index": digest(index), "binary": digest(args.binary)}:
            raise ValueError("index or native binary changed")
        summary["retained_at_end"] = len(retained)
        summary["complete"] = True
    except Exception as error:
        summary["error"] = str(error)
        raise
    finally:
        db.close()
        (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--zerostate", type=Path, action="append", required=True)
    parser.add_argument("--jobs", type=int, choices=range(1, 65), default=32)
    parser.add_argument("--mc-limit", type=int)
    args = parser.parse_args()
    if args.mc_limit is not None and args.mc_limit <= 0:
        parser.error("--mc-limit must be positive")
    run(args)
