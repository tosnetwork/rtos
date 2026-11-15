"""Read the node's explicit build identity without treating help text as evidence."""

import re
import subprocess


def require_revision_banner(banner, revision):
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ValueError("A complete lowercase 40-digit Rust commit is required")
    commits = re.findall(r'^COMMIT_ID: "([0-9a-f]{40})"\s*$', banner, re.MULTILINE)
    if commits != [revision]:
        raise ValueError("Rust executable does not report the pinned source revision")


def require_rust_revision(binary, revision):
    result = subprocess.run(
        [str(binary), "--version"],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    require_revision_banner(result.stdout + result.stderr, revision)
