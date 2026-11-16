#!/usr/bin/env python3
"""Build the native proof-budget probe against the pinned TOS Ninja build."""

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
    with (out / "native.log").open("w") as log:
        result = subprocess.run(
            [str(out / "probe")], stdout=log, stderr=subprocess.STDOUT, check=False
        )
    receipt = {
        "reference_commit": revision,
        "native_source": str(source_root),
        "native_build": str(build),
        "runner_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "probe_source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "probe_binary_sha256": hashlib.sha256((out / "probe").read_bytes()).hexdigest(),
        "exit": result.returncode,
        "compile_command": compile_command,
        "link_command": link_command,
    }
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print((out / "native.log").read_text(), end="")
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
