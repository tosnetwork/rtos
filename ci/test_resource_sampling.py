#!/usr/bin/env python3
"""Exercise wrapper exit preservation, live sampling and sampler cleanup."""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main():
    wrapper = Path(__file__).with_name("run_with_resources.sh")
    with tempfile.TemporaryDirectory() as directory:
        env = os.environ | {"CI_RESOURCE_DIR": directory}
        result = subprocess.run(
            [
                "bash",
                str(wrapper),
                "control",
                sys.executable,
                "-c",
                """import json, os, time
from pathlib import Path
raw = Path('/proc/self/stat').read_text()
fields = raw[raw.rindex(')') + 2:].split()
identity = {'pid': os.getpid(), 'start_ticks': int(fields[19]),
            'baseline_rss_kib': int(fields[21]) * os.sysconf('SC_PAGE_SIZE') // 1024}
print('CI_CONTROL_CHILD ' + json.dumps(identity), flush=True)
data = bytearray(16 * 1024 * 1024)
if data is not None:
    for offset in range(0, len(data), 4096):
        data[offset] = 1
print('child-marker', flush=True)
time.sleep(11)
raise SystemExit(37)
""",
            ],
            check=False,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 37, result
        assert "child-marker" in result.stdout
        rows = [
            json.loads(line)
            for line in (Path(directory) / "control-samples.jsonl")
            .read_text()
            .splitlines()
        ]
        assert len(rows) >= 2, rows
        assert all(row["phase"] == "control" for row in rows)
        identities = [
            json.loads(line.removeprefix("CI_CONTROL_CHILD "))
            for line in result.stdout.splitlines()
            if line.startswith("CI_CONTROL_CHILD ")
        ]
        assert len(identities) == 1, identities
        identity = identities[0]
        child_samples = [
            child
            for row in rows
            for child in row["top_rss"]
            if child["pid"] == identity["pid"]
            and child["start_ticks"] == identity["start_ticks"]
        ]
        assert child_samples, (identity, rows)
        child_peak = max(child["rss_kib"] for child in child_samples)
        # Require growth in the identified child, never the observer's own RSS.
        assert child_peak >= identity["baseline_rss_kib"] + 12 * 1024, (
            identity,
            child_samples,
        )
        assert all(
            "CI_RESOURCE_SAMPLE " + json.dumps(row, sort_keys=True) in result.stdout
            for row in rows
        )
        assert not Path("/proc", str(rows[0]["sampler_pid"])).exists(), (
            "sampler outlived wrapper"
        )
        assert all(
            "args" not in child and "environ" not in child
            for row in rows
            for child in row["top_rss"]
        )
        success = subprocess.run(
            ["bash", str(wrapper), "success", "true"],
            check=False,
            env=env,
            capture_output=True,
            timeout=10,
        )
        assert success.returncode == 0, success
        invalid = subprocess.run(
            ["bash", str(wrapper), "../invalid", "true"],
            check=False,
            env=env,
            capture_output=True,
            timeout=10,
        )
        assert invalid.returncode == 2, invalid
        # A failed observer is diagnostic only, never a replacement exit code.
        missing = Path(directory) / "run_with_resources.sh"
        missing.write_bytes(wrapper.read_bytes())
        failed_observer = subprocess.run(
            [
                "bash",
                str(missing),
                "missing_observer",
                "sh",
                "-c",
                "sleep 0.1; exit 23",
            ],
            check=False,
            env=env,
            capture_output=True,
            timeout=10,
        )
        assert failed_observer.returncode == 23, failed_observer
        print(
            json.dumps(
                {
                    "failure_status": 37,
                    "success_status": 0,
                    "invalid_status": 2,
                    "samples": len(rows),
                    "cleanup": True,
                    "child_identity": identity,
                    "child_peak_rss_kib": child_peak,
                }
            )
        )


if __name__ == "__main__":
    main()
