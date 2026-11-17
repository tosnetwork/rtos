"""Select bounded, recorded WC inputs for original-database recovery proofs."""

import hashlib
import json
import time
from pathlib import Path

from publication_capture import read_capture
from workchain_original_evidence import plan_workchain_requests
from workchain_output_evidence import sealed_workchain_outputs


def select_workchain_inputs(
    root, pending, state_configs, original_pid, deadline, *, require_approval=False
):
    """Select evidence only; caller still authenticates every original output.

    The caller binds pending and its sealed file bytes to the stopped process.
    Native verification, fresh state collection and DB/config/cleanup checks
    remain mandatory. No recovery budget is created here.
    """
    root = Path(root)

    def remaining():
        if time.monotonic() >= deadline:
            raise TimeoutError("Original WC input selection deadline expired")

    remaining()
    if type(original_pid) is not int or original_pid <= 0:
        raise ValueError("Original capture PID is required")
    capture = root / "wc-publication-capture"
    arm = json.loads((capture / "arm.json").read_text())
    if arm.get("pid") != original_pid:
        raise ValueError("WC capture belongs to another original process")
    if not 1 <= len(pending.records) <= 1024:
        raise ValueError("Original WC frontier is empty or exceeds its bound")
    approval = False
    for item in pending.records:
        record = item["record"]
        sealed = item.get("sealed_outputs")
        if not sealed or record.get("session_id") != arm["session"]:
            raise ValueError("Original WC frontier lacks the exact captured session")
        sealed_workchain_outputs(record, sealed["record"])
        approval |= any(not o["is_final"] for o in sealed["record"]["outputs"])
    if require_approval and not approval:
        raise ValueError("Required original Approval obligation was not captured")
    rows = read_capture(capture, original_pid, arm["session"])
    remaining()
    paths = []
    for path in (root / "checks").glob("*/sample.json"):
        if len(paths) >= 1024:
            raise ValueError("Too many retained WC checkpoint candidates")
        paths.append(path)
    total = 0
    # Deterministic selection only; correctness comes from exact parent identity
    # checks and subsequent native authentication, never the directory ordering.
    for path in sorted(paths):
        remaining()
        if path.is_symlink() or not path.is_file():
            raise ValueError("WC checkpoint requires an owned regular file")
        with path.open("rb") as stream:
            raw = stream.read((64 << 20) + 1)
        total += len(raw)
        if len(raw) > 64 << 20 or total > 128 << 20:
            raise ValueError("WC checkpoint selection exceeds its byte bound")
        checkpoint = json.loads(raw)
        if "workchain" not in checkpoint:
            continue
        try:
            for item in pending.records:
                plan_workchain_requests(
                    item["record"], item["sealed_outputs"]["record"], rows, checkpoint
                )
        except ValueError:
            continue
        names = [x["name"] for x in checkpoint["workchain"]["states"]]
        if len(names) != len(set(names)) or set(names) != set(state_configs):
            raise ValueError("Selected checkpoint does not cover every state source")
        remaining()
        selection = {
            "checkpoint": str(path),
            "checkpoint_sha256": hashlib.sha256(raw).hexdigest(),
            "original_pid": original_pid,
            "session": arm["session"],
            "original_sets": len(pending.records),
            "contains_approval": approval,
            "scope": "Selection only; native proofs and original DB recovery remain required",
        }
        destination = root / "recovery/wc-input-selection.json"
        with destination.open("x") as stream:
            json.dump(selection, stream, indent=2)
            stream.write("\n")
        return {
            "captures": rows,
            "checkpoint": checkpoint,
            "state_configs": state_configs,
        }
    raise ValueError("No retained checkpoint covers the complete original WC frontier")
