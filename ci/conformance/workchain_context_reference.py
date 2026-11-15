#!/usr/bin/env python3
"""Verify test-only masterchain context migration with the pinned native TOS build."""

import argparse
import hashlib
import json
import shlex
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpp-build", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--export", type=Path, required=True)
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
    inputs = args.export.resolve()
    results = []
    expected = {
        "local-unknown": "missing workchain engine Basic:1 for workchain 0",
        "local-mode": "TVM descriptor requires vm_mode=0",
    }
    for name, error in expected.items():
        paths = [
            inputs / f"{name}-{suffix}.boc"
            for suffix in ["original", "mc1", "mc1-state", "migrated"]
        ]
        if any(path.stat().st_size > 4 << 20 for path in paths):
            raise SystemExit("context input exceeds 4 MiB")
        command = [str(out / "probe"), *map(str, paths)]
        done = subprocess.run(
            command, capture_output=True, text=True, timeout=60, check=False
        )
        (out / f"{name}.stdout.json").write_text(done.stdout)
        (out / f"{name}.stderr.log").write_text(done.stderr)
        try:
            effects = json.loads(done.stdout)
        except ValueError:
            effects = None
        passed = (
            done.returncode == 0
            and isinstance(effects, dict)
            and effects.get("local_admitted") is False
            and effects.get("tvm_control") is True
            and effects.get("error_hex") == error.encode().hex()
        )
        results.append(
            {
                "case": name,
                "exit": done.returncode,
                "effects": effects,
                "passed": passed,
                "command": command,
                "inputs": [
                    {
                        "name": path.name,
                        "bytes": path.stat().st_size,
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    }
                    for path in paths
                ],
            }
        )
        print(f"{name}: {'PASS' if passed else 'FAIL'}", flush=True)
    receipt = {
        "reference_commit": revision,
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "probe_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "probe_binary_sha256": hashlib.sha256((out / "probe").read_bytes()).hexdigest(),
        "compile_command": compile_command,
        "link_command": link_command,
        "results": results,
        "passed": all(row["passed"] for row in results),
    }
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    raise SystemExit(0 if receipt["passed"] else 1)


if __name__ == "__main__":
    main()
