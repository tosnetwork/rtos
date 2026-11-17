"""Select a live WC capture from an exact, already checked block observation."""

import json
import re
from pathlib import Path

from runtime_manifest_observer import read_starting_manifest
from workchain_output_evidence import block_text


class CaptureSessionPending(RuntimeError):
    """Exact active WC observation is not available within the original budget yet."""


def select_session(node_directory, checked):
    """Caller owns native checker execution, process liveness and deadline.

    Log matching selects capture routing only; it never proves a carrier valid.
    """
    node = Path(node_directory)
    wc = checked.get("workchain_check", {})
    if (
        wc.get("masterchain_anchor_checked") is not True
        or wc.get("all_four_states_match_block_update") is not True
        or not checked.get("verified_final_certificates")
        or any(
            c.get("final_certificate_checked") is not True
            for c in checked["verified_final_certificates"]
        )
    ):
        raise ValueError("WC capture needs an already checked full-state checkpoint")
    block = wc["block"]
    if block["workchain"] != 0 or block["seqno"] <= 0:
        raise ValueError("WC capture requires a produced workchain block")
    pattern = re.compile(
        r"SessionCallbacks::notify_candidate_observed session_id=([0-9a-f]{64}) block_id="
        + re.escape(block_text(block))
        + r"(?:\s|$)"
    )
    with (node / "node.log").open("rb") as stream:
        stream.seek(0, 2)
        start = max(0, stream.tell() - (8 << 20))
        stream.seek(start)
        if start:
            stream.readline()
        text = stream.read(8 << 20).decode(errors="replace")
    sessions = set(pattern.findall(text))
    if not sessions:
        raise CaptureSessionPending(
            "Exact WC block has no current callback observation"
        )
    if len(sessions) != 1:
        raise ValueError("Exact WC block has ambiguous capture sessions")
    session = sessions.pop()
    matches = []
    for path in (node / "node_db/catchains/consensus/v2").glob(
        "*/session-runtime.json"
    ):
        manifest = read_starting_manifest(path)
        if manifest is None or manifest.get("session") != session:
            continue
        if (
            manifest.get("role") != "validator"
            or manifest.get("shard_workchain") != 0
            or manifest.get("shard_prefix") != int(block["shard"]) % (1 << 64)
            or manifest.get("catchain_seqno") != wc["gen_catchain_seqno"]
        ):
            raise ValueError("WC capture runtime does not match the exact active block")
        matches.append(path)
    if not matches:
        raise CaptureSessionPending("Exact WC validator runtime is still starting")
    if len(matches) != 1:
        raise ValueError("WC capture has duplicate runtime bindings")
    return session, matches[0]


def arm_capture(node_directory, checked, control, pid):
    session, runtime = select_session(node_directory, checked)
    control = Path(control)
    control.mkdir(parents=True, exist_ok=True)
    if (control / "selector").exists():
        raise ValueError("WC publication capture was already armed")
    # Keep the exact selected manifest before publishing the selector.
    (control / "selected-runtime.json").write_bytes(runtime.read_bytes())
    (control / "arm.json").write_text(
        json.dumps(
            {
                "pid": pid,
                "session": session,
                "block": checked["workchain_check"]["block"],
                "runtime": str(runtime),
                "scope": "Capture routing only, not carrier authentication",
            },
            indent=2,
        )
        + "\n"
    )
    temporary = control / "selector.tmp"
    with temporary.open("x") as stream:
        stream.write(f"{pid}\n{session}\n")
    temporary.replace(control / "selector")
    return session
