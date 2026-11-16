#!/usr/bin/env python3
"""Emit bounded Linux resource snapshots while the wrapping shell is alive."""

import argparse
import json
import os
import signal
import sys
import time
from datetime import UTC, datetime
from pathlib import Path


def process(pid):
    """Read identity and RSS without exposing command arguments or environment."""
    raw = (Path("/proc") / str(pid) / "stat").read_text()
    close = raw.rindex(")")
    fields = raw[close + 2 :].split()
    return {
        "pid": int(pid),
        "ppid": int(fields[1]),
        "comm": raw[raw.index("(") + 1 : close],
        "start_ticks": int(fields[19]),
        "rss_kib": int(fields[21]) * os.sysconf("SC_PAGE_SIZE") // 1024,
    }


def snapshot(root):
    processes = {}
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            try:
                row = process(entry.name)
                processes[row["pid"]] = row
            except (OSError, ValueError, IndexError):
                pass  # A process can exit during any read.
    descendants = {root}
    while True:
        expanded = descendants | {
            pid for pid, row in processes.items() if row["ppid"] in descendants
        }
        if expanded == descendants:
            break
        descendants = expanded
    rows = [processes[pid] for pid in descendants if pid in processes]
    rows.sort(key=lambda row: (-row["rss_kib"], row["pid"]))
    memory = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        if key in {"MemAvailable", "SwapTotal", "SwapFree"}:
            memory[key + "_kib"] = int(value.split()[0])
    return {
        "utc": datetime.now(UTC).isoformat(),
        "root_pid": root,
        "sampler_pid": os.getpid(),
        "process_count": len(rows),
        # RSS counts shared pages once per process, not unique physical memory.
        "sum_process_rss_kib": sum(row["rss_kib"] for row in rows),
        "top_rss": rows[:5],
        **memory,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root-pid", type=int, required=True)
    parser.add_argument("--phase", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--interval", type=float, default=10)
    args = parser.parse_args()
    if not 0.05 <= args.interval <= 60:
        parser.error("interval must be between 0.05 and 60 seconds")
    # Exit immediately on cleanup; a signal handler must not acquire a lock
    # that the interrupted sampling thread might already hold.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    try:
        identity = process(args.root_pid)["start_ticks"]
        with args.output.open("a", buffering=1) as output:
            while True:
                if process(args.root_pid)["start_ticks"] != identity:
                    break
                row = snapshot(args.root_pid)
                row["phase"] = args.phase
                line = json.dumps(row, sort_keys=True)
                output.write(line + "\n")
                print("CI_RESOURCE_SAMPLE " + line, flush=True)
                time.sleep(args.interval)
    except (OSError, ValueError, IndexError) as error:
        print(f"CI resource sampler stopped: {type(error).__name__}", flush=True)


if __name__ == "__main__":
    main()
