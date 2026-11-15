"""Verify retained intent cuts against their original bytes and replay proof."""

import hashlib
import json
from pathlib import Path

from scenario_matrix import require_fields

POINTS = ("before-write", "after-partial-write", "after-fsync")


def check_intent_evidence(runtime, receipt, source, recovery, point):
    if point not in POINTS:
        raise ValueError("Unsupported intent cut")
    cut = receipt.get("intent_cut")
    if not isinstance(cut, dict):
        raise TypeError("Missing intent cut receipt")
    require_fields(
        cut,
        {
            "point": point,
            "pid": recovery["old_process"]["pid"],
            "stopped_state_verified": True,
            "normal_replay_completed": True,
            "preserved_after_interruption": True,
            "preserved_before_restart": True,
        },
    )
    directory = runtime / "source-ack-partition"
    before = (directory / "intent-before.json").read_bytes()
    intended = (directory / "intent-original-record.json").read_bytes()
    completed = (directory / "intent-completed.json").read_bytes()
    for raw, size, digest in (
        (before, cut.get("bytes"), cut.get("sha256")),
        (intended, cut.get("intended_bytes"), cut.get("intended_sha256")),
    ):
        if (
            type(size) is not int
            or size != len(raw)
            or hashlib.sha256(raw).hexdigest() != digest
        ):
            raise ValueError("Intent bytes differ from cut receipt")
    if not intended or (
        point == "before-write"
        and before
        or point == "after-partial-write"
        and not (
            0 < len(before) == len(intended) // 2 < len(intended)
            and intended.startswith(before)
        )
        or point == "after-fsync"
        and before != intended
    ):
        raise ValueError("Intent bytes differ from selected cut point")
    record = json.loads(intended)
    path = Path(cut["path"])
    if (
        record.get("session_id") != source["session"]
        or record.get("slot") != cut.get("slot")
        or record.get("candidate_hash") != cut.get("candidate_hash")
        or path.parent != Path(source["pending_directory"]).parent / "finality-intents"
        or path.name != f"{cut['slot']}-{cut['candidate_hash']}.tmp"
    ):
        raise ValueError("Intent identity differs from the original source")
    if hashlib.sha256(completed).hexdigest() != cut.get("completed_sha256"):
        raise ValueError("Completed intent bytes differ")
    proof = json.loads(completed)
    if (
        type(proof.get("schema")) is not int
        or proof["schema"] != 1
        or proof.get("record") != record
    ):
        raise ValueError("Completed intent changed the stopped certificate")
    status = (directory / "intent-stopped-process.txt").read_text()
    if not any(
        line.startswith("State:") and line.split()[1] == "T"
        for line in status.splitlines()
    ):
        raise ValueError("Original process was not observed stopped")
    marker = (directory / "intent-stop.marker").read_text()
    if marker != f"intent {point} pid={cut['pid']}: {path}\n":
        raise ValueError("Intent native marker differs")
    if (directory / "intent-armed").exists() or not (
        directory / "intent-disarmed"
    ).is_file():
        raise ValueError("Intent injection remains armed")


INTENTS = {f"source-ack-intent-{point}": point for point in POINTS}


def intent_arguments(name, ack_library, packet_library):
    from scenario_ack_partition import ack_partition_arguments

    return ack_partition_arguments(
        "source-ack-partition-sync-eio", ack_library, packet_library
    ) + ["--source-ack-intent-stop", "--source-ack-intent-cut-point", INTENTS[name]]


def check_intent_result(name, combined, source, partition, recovery):
    from scenario_ack_partition import check_ack_partition_result

    if not isinstance(combined, dict):
        raise TypeError("Missing intent recovery receipt")
    cut = combined.get("intent_cut")
    if not isinstance(cut, dict):
        raise TypeError("Missing intent cut")
    require_fields(
        cut,
        {
            "point": INTENTS[name],
            "pid": recovery["old_process"]["pid"],
            "stopped_state_verified": True,
            "normal_replay_completed": True,
            "preserved_after_interruption": True,
            "preserved_before_restart": True,
        },
    )
    # The shared validator rejects cuts for ordinary combined scenarios.
    # This adapter explicitly validates the selected cut before delegation.
    ordinary = {key: value for key, value in combined.items() if key != "intent_cut"}
    check_ack_partition_result(
        "source-ack-partition-sync-eio", ordinary, source, partition, recovery
    )
