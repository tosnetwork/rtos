#!/usr/bin/env python3
"""Replay real proof-selection prefixes against the pinned native TOS build."""

import argparse
import base64
import hashlib
import json
import shlex
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpp-build", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--fixtures",
        type=Path,
        default=Path(__file__).resolve().parents[2]
        / "block/src/tests/data/proof-selection-native.json",
    )
    args = parser.parse_args()
    build = args.cpp_build.resolve()
    out = args.out.resolve()
    source = Path(__file__).with_suffix(".cpp")
    cache = (build / "CMakeCache.txt").read_text()
    source_root = Path(
        next(
            line.split("=", 1)[1]
            for line in cache.splitlines()
            if line.startswith("CMAKE_HOME_DIRECTORY:INTERNAL=")
        )
    )
    revision = subprocess.check_output(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"], text=True
    ).strip()
    if revision != (source.parent / "REFERENCE").read_text().strip():
        raise SystemExit("native source revision differs from REFERENCE")
    if subprocess.check_output(
        ["git", "-C", str(source_root), "status", "--porcelain"], text=True
    ).strip():
        raise SystemExit("native source checkout is not clean")
    out.mkdir(parents=True, exist_ok=False)
    with (out / "build.log").open("w") as log:
        subprocess.run(
            ["ninja", "-C", str(build), "-j32", "conformance-ref-cli"],
            stdout=log,
            stderr=subprocess.STDOUT,
            check=True,
        )
        commands = subprocess.check_output(
            ["ninja", "-C", str(build), "-t", "commands", "conformance-ref-cli"],
            text=True,
        ).splitlines()
        compile_args = shlex.split(
            next(
                line
                for line in commands
                if "harness-codec.cpp.o" in line and " -c " in line
            )
        )
        compiler = (
            compile_args[1]
            if Path(compile_args[0]).name in {"ccache", "sccache"}
            else compile_args[0]
        )
        flags = []
        for index, arg in enumerate(compile_args):
            if arg.startswith(("-I", "-D", "-std=")):
                flags.append(arg)
            if arg == "-isystem":
                flags.extend([arg, compile_args[index + 1]])
        compile_command = [
            compiler,
            *flags,
            "-O1",
            "-c",
            str(source),
            "-o",
            str(out / "probe.o"),
        ]
        subprocess.run(
            compile_command, cwd=build, stdout=log, stderr=subprocess.STDOUT, check=True
        )
        link_args = shlex.split(
            next(
                line
                for line in commands
                if " -o test/conformance/libconformance-ref.so" in line
            )
        )
        libraries = [
            arg for arg in link_args if arg.endswith(".a") or arg.startswith("-l")
        ]
        link_command = [
            compiler,
            str(out / "probe.o"),
            "-o",
            str(out / "probe"),
            "-Wl,--start-group",
            *libraries,
            "-Wl,--end-group",
            "-lpthread",
            "-ldl",
        ]
        subprocess.run(
            link_command, cwd=build, stdout=log, stderr=subprocess.STDOUT, check=True
        )
    fixtures = args.fixtures.resolve()
    profile = json.loads(fixtures.read_text())
    if not isinstance(profile.get("cases"), list) or len(profile["cases"]) != 8:
        raise SystemExit("expected exactly eight captured cases")
    if profile["reference_commit"] != revision:
        raise SystemExit("fixture native reference differs")
    repo = Path(__file__).resolve().parents[2]
    state = (repo / profile["source_state"]).resolve()
    if (
        not state.is_relative_to(repo)
        or hashlib.sha256(state.read_bytes()).hexdigest()
        != profile["source_state_sha256"]
    ):
        raise SystemExit("original state digest differs")
    view = [
        "FIXTURE_SHA256 " + hashlib.sha256(fixtures.read_bytes()).hexdigest(),
        "REFERENCE " + revision,
    ]
    for case in profile["cases"]:
        view.append(
            f"CASE {case['account']} {case['budget']} {int(case['expected']['fits'])} {case['roots_boc']} {case['expected']['visited_cells']}"
        )
        view.append("ROOTS " + " ".join(case["roots"]))
        view.extend(
            f"STATUS {item['hash']} {item['status']} {int(item['included'])}"
            for item in case["frozen"]
        )
        view.append("END")
    if fixtures.with_suffix(".tsv").read_text() != "\n".join(view) + "\n":
        raise SystemExit("generated Rust TSV view differs from JSON fixture")
    results = []
    for index, case in enumerate(profile["cases"]):
        directory = out / f"case-{index:02d}"
        directory.mkdir()
        snapshot = directory / "snapshot.txt"
        lines = [
            f"CASE {case['budget']} {int(case['expected']['fits'])} {case['dict_hash']} {case['account']} {profile['source_state_hash']}"
        ]
        lines.extend(
            f"STATUS {item['hash']} {item['status']} {int(item['included'])}"
            for item in case["frozen"]
        )
        snapshot.write_text("\n".join(lines) + "\n")
        roots, proof = directory / "roots.boc", directory / "dictionary-proof.boc"
        roots.write_bytes(base64.b64decode(case["roots_boc"], validate=True))
        proof.write_bytes(base64.b64decode(case["dict_proof_boc"], validate=True))
        command = [
            str(out / "probe"),
            str(snapshot),
            str(roots),
            str(proof),
            str(state),
        ]
        done = subprocess.run(
            command, capture_output=True, text=True, timeout=60, check=False
        )
        (directory / "stdout.json").write_text(done.stdout)
        (directory / "stderr.log").write_text(done.stderr)
        try:
            effects = json.loads(done.stdout)
        except ValueError:
            effects = None
        passed = done.returncode == 0 and effects == case["expected"]
        results.append(
            {
                "account": case["account"],
                "exit": done.returncode,
                "effects": effects,
                "passed": passed,
                "command": command,
            }
        )
        print(
            f"{case['account']}: {'PASS' if passed else 'FAIL'} {effects}", flush=True
        )
    receipt = {
        "reference_commit": revision,
        "native_source": str(source_root),
        "native_build": str(build),
        "runner_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "probe_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "probe_binary_sha256": hashlib.sha256((out / "probe").read_bytes()).hexdigest(),
        "fixture_sha256": hashlib.sha256(fixtures.read_bytes()).hexdigest(),
        "source_state_sha256": hashlib.sha256(state.read_bytes()).hexdigest(),
        "results": results,
        "passed": len(results) == 8 and all(row["passed"] for row in results),
        "compile_command": compile_command,
        "link_command": link_command,
    }
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    raise SystemExit(0 if receipt["passed"] else 1)


if __name__ == "__main__":
    main()
