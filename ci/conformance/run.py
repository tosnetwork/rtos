#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
"""Build native adapters and run the pinned TOS runner, including Rust regressions."""

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
# package, example, optional repository regression directory
TARGETS = {
    "vm": ("rtos_vm", "conformance", "vm/tests/data/conformance/vm"),
    "get_method": (
        "rtos_vm",
        "get_method_conformance",
        "vm/tests/data/conformance/get_method",
    ),
    "txn": (
        "rtos_executor",
        "txn_conformance",
        "executor/src/tests/data/conformance/txn",
    ),
    "block": (
        "rtos_executor",
        "block_conformance",
        "executor/src/tests/data/conformance/block",
    ),
    "fee": (
        "rtos_executor",
        "fee_conformance",
        "executor/src/tests/data/conformance/fee",
    ),
    "codec": (
        "rtos_executor",
        "codec_conformance",
        "executor/src/tests/data/conformance/codec",
    ),
    "tl": ("rtos_api", "tl_conformance", "tl/rtos_api/tests/data/conformance/tl"),
    "crypto": (
        "rtos_api",
        "crypto_conformance",
        "tl/rtos_api/tests/data/conformance/crypto",
    ),
    "consensus": (
        "rtos_api",
        "consensus_conformance",
        "tl/rtos_api/tests/data/conformance/consensus",
    ),
    "net": ("adnl", "net_conformance", "adnl/tests/data/conformance/net"),
    "validate": ("rtos", "validate_conformance", None),
}
TALLY = re.compile(
    r"compared (\d+), equal (\d+), mismatched (\d+), refused (\d+), skipped (\d+)"
)


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(4 << 20):
            result.update(chunk)
    return result.hexdigest()


def git(path, *args):
    return subprocess.check_output(["git", "-C", str(path), *args], text=True).strip()


def source_identity():
    return {
        "commit": git(REPO, "rev-parse", "HEAD"),
        "status": git(REPO, "status", "--porcelain"),
        "diff_sha256": hashlib.sha256(
            subprocess.check_output(
                ["git", "-C", str(REPO), "diff", "HEAD", "--binary"]
            )
        ).hexdigest(),
        "runner_sha256": digest(Path(__file__)),
    }


def family_files(paths):
    files = []
    for path in paths:
        found = sorted(path.rglob("*.jsonl")) if path.is_dir() else [path]
        if not found:
            raise ValueError(f"no fixture family files in {path}")
        files.extend(found)
    if not files or len(set(files)) != len(files):
        raise ValueError("fixture paths must contain distinct, nonempty family files")
    return files


def combined_result(side, harness, families):
    counts = None
    if all(family.get("counts") is not None for family in families):
        counts = {
            key: sum(family["counts"][key] for family in families)
            for key in ("compared", "equal", "mismatched", "refused", "skipped")
        }
    return {
        "side": side,
        "harness": harness,
        "families": families,
        "counts": counts,
        "passed": bool(families) and all(family["passed"] for family in families),
    }


def fixture_identity(paths):
    files = set()
    for family_paths in paths.values():
        for path in family_paths:
            if path.is_file():
                files.add(path)
                sidecar = path.with_suffix(".blobs.json")
                if sidecar.is_file():
                    files.add(sidecar)
            else:
                files.update(path.rglob("*.jsonl"))
                files.update(path.rglob("*.blobs.json"))
                files.update(path.rglob("*.provenance.json"))
    return {str(p): digest(p) for p in sorted(files)}


def run_one(command, log):
    started = time.monotonic()
    with log.open("w") as output:
        done = subprocess.run(
            command, stdout=output, stderr=subprocess.STDOUT, timeout=3600, check=False
        )
    tally = next(
        (
            TALLY.fullmatch(line)
            for line in reversed(log.read_text().splitlines())
            if TALLY.fullmatch(line)
        ),
        None,
    )
    counts = (
        dict(
            zip(
                ("compared", "equal", "mismatched", "refused", "skipped"),
                map(int, tally.groups()),
                strict=True,
            )
        )
        if tally
        else None
    )
    passed = (
        done.returncode == 0
        and counts is not None
        and counts["compared"] > 0
        and counts["equal"] == counts["compared"]
        and not any(counts[key] for key in ("mismatched", "refused", "skipped"))
    )
    return {
        "command": command,
        "exit": done.returncode,
        "counts": counts,
        "passed": passed,
        "seconds": round(time.monotonic() - started, 2),
        "log": str(log),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tos", type=Path, required=True, help="clean checkout at REFERENCE"
    )
    parser.add_argument(
        "--out", type=Path, required=True, help="new directory for logs and summary"
    )
    parser.add_argument(
        "--target-dir",
        type=Path,
        default=Path(os.environ.get("CARGO_TARGET_DIR", REPO / "target")),
    )
    parser.add_argument("--jobs", type=int, default=32)
    parser.add_argument("--harness", choices=TARGETS, action="append")
    parser.add_argument(
        "--skip-build", action="store_true", help="use existing binaries explicitly"
    )
    parser.add_argument(
        "--reference-binary", type=Path, help="also compare a clean pinned C++ build"
    )
    parser.add_argument(
        "--extra-fixtures", action="append", default=[], metavar="HARNESS=PATH"
    )
    args = parser.parse_args()
    if not 1 <= args.jobs <= 64:
        parser.error("--jobs must be between 1 and 64")
    pin = Path(__file__).with_name("REFERENCE").read_text().strip()
    tos = args.tos.resolve()
    if git(tos, "rev-parse", "HEAD") != pin or git(tos, "status", "--porcelain"):
        parser.error("--tos must be a clean checkout at the exact REFERENCE commit")
    selected = sorted(set(args.harness or TARGETS))
    runner = tos / "test/conformance/runner/conformance.py"
    paths = {h: [tos / "test/conformance/vectors" / h] for h in selected}
    for h in selected:
        if TARGETS[h][2]:
            paths[h].append(REPO / TARGETS[h][2])
    for extra in args.extra_fixtures:
        h, sep, path = extra.partition("=")
        if not sep or h not in selected or not path:
            parser.error("--extra-fixtures requires a selected HARNESS=PATH")
        paths[h].append(Path(path).resolve())
    for family_paths in paths.values():
        for path in family_paths:
            if not path.exists():
                parser.error(f"fixture path does not exist: {path}")
    families = {h: family_files(family_paths) for h, family_paths in paths.items()}
    reference = args.reference_binary.resolve() if args.reference_binary else None
    if reference:
        info = json.loads(
            subprocess.check_output([str(reference), "--info"], timeout=60)
        )
        if info.get("reference_commit") != pin or info.get("dirty") is not False:
            parser.error("--reference-binary must be the clean pinned C++ build")
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=False)
    target_dir = args.target_dir.resolve()
    before = source_identity()
    fixtures = fixture_identity(paths)
    report = {
        "source": before,
        "reference_commit": pin,
        "harnesses": selected,
        "complete_suite": selected == sorted(TARGETS),
        "built": not args.skip_build,
        "reference_checked": reference is not None,
        "results": [],
        "fixtures": fixtures,
    }
    if not args.skip_build:
        command = [
            "cargo",
            "build",
            "--locked",
            f"-j{args.jobs}",
            "--target-dir",
            str(target_dir),
        ]
        for package in sorted({TARGETS[h][0] for h in selected}):
            command += ["-p", package]
        for h in selected:
            command += ["--example", TARGETS[h][1]]
        with (output / "build.log").open("w") as log:
            built = subprocess.run(
                command, cwd=REPO, stdout=log, stderr=subprocess.STDOUT, check=False
            )
        report["build"] = {"command": command, "exit": built.returncode}
        if built.returncode:
            report["passed"] = False
            (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
            print(f"build failed; see {output / 'build.log'}", file=sys.stderr)
            return 1
    binaries = {h: target_dir / "debug/examples" / TARGETS[h][1] for h in selected}
    programs = {("rust", h): binary for h, binary in binaries.items()}
    if reference:
        programs.update({("cpp", h): reference for h in selected})
    hashes = {str(p): digest(p) for p in set(programs.values())}
    report["binaries"] = hashes
    # The shared runner already creates a fresh target process per family.
    # Schedule those independent families across the same worker budget, so a
    # large transaction harness does not serialize the rest of the corpus.
    grouped = {key: [] for key in programs}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        jobs = {}
        for (side, h), binary in programs.items():
            for index, family in enumerate(families[h]):
                command = [
                    sys.executable,
                    str(runner),
                    "run",
                    "--target",
                    str(binary),
                    "--harness",
                    h,
                    str(family),
                ]
                jobs[
                    pool.submit(
                        run_one, command, output / f"{side}-{h}-{index:03d}.log"
                    )
                ] = (side, h)
        for job in concurrent.futures.as_completed(jobs):
            side, h = jobs[job]
            try:
                result = job.result()
            except (OSError, subprocess.SubprocessError, ValueError) as error:
                result = {"passed": False, "error": str(error)}
            grouped[(side, h)].append(result)
            if len(grouped[(side, h)]) == len(families[h]):
                group = combined_result(side, h, grouped[(side, h)])
                report["results"].append(group)
                print(
                    f"{side}/{h}: {'PASS' if group['passed'] else 'FAIL'} {group['counts']}",
                    flush=True,
                )
    report["results"].sort(key=lambda r: (r["side"], r["harness"]))
    report["source_unchanged"] = before == source_identity()
    report["fixtures_unchanged"] = fixtures == fixture_identity(paths)
    report["binaries_unchanged"] = all(
        digest(Path(p)) == value for p, value in hashes.items()
    )
    report["tos_unchanged"] = git(tos, "rev-parse", "HEAD") == pin and not git(
        tos, "status", "--porcelain"
    )
    report["passed"] = (
        all(r["passed"] for r in report["results"])
        and report["tos_unchanged"]
        and report["source_unchanged"]
        and report["fixtures_unchanged"]
        and report["binaries_unchanged"]
    )
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        print(f"conformance: {error}", file=sys.stderr)
        raise SystemExit(1) from error
