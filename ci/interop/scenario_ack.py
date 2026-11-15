"""Exact source ACK refusal and original-database recovery scenarios."""

import hashlib
import json
from pathlib import Path

from scenario_matrix import require_fields
from scenario_packet import file_hash

ACKS = {f"source-ack-{mode}": mode for mode in ("sync-eio", "write-enospc")}


def ack_artifacts(args, source):
    library = getattr(args, "source_ack_fault_library", None)
    record = getattr(args, "source_ack_fault_build_record", None)
    if library is None or record is None:
        raise ValueError("ACK scenarios require a native library and build record")
    build = json.loads(record.read_text())
    native = source.parents[1] / "rtos/src/tests/finality_source_fault.c"
    if (
        Path(build["source"]).resolve() != native.resolve()
        or Path(build["library"]).resolve() != library.resolve()
    ):
        raise ValueError("ACK build record names different source or library")
    for path, meta in (
        (native, build["source_meta"]),
        (library, build["library_meta"]),
    ):
        if path.stat().st_size != meta["bytes"] or file_hash(path) != meta["sha256"]:
            raise ValueError("ACK native source/library differs from build receipt")
    return [native, library, record]


def ack_arguments(name, library):
    return [
        "--interrupt-rust-member",
        "2",
        "--source-ack-fault",
        ACKS[name],
        "--source-ack-fault-library",
        str(library),
    ]


def check_ack_result(name, receipt, recovery, *, expired_member=False):
    if not isinstance(receipt, dict) or not isinstance(recovery, dict):
        raise TypeError("Missing ACK or original-database recovery receipt")
    mode = ACKS[name]
    member = 5 if expired_member else 2
    if expired_member and (
        recovery.get("expired_full_node", {}).get("signing_authority_restored")
        is not False
        or recovery.get("vote")
        or recovery.get("leaders")
    ):
        raise ValueError("Expired ACK recovery regained signing authority")
    require_fields(
        receipt,
        {
            "phase": "recovered",
            "mode": mode,
            "member": member,
            "interruption_returncode": -9,
            "source_acknowledged_before_interruption": False,
            "pending_preserved_after_interruption": True,
            "pending_preserved_before_restart": True,
            "original_source_ack_recovered": True,
            "manual_database_repair": False,
        },
    )
    require_fields(
        recovery,
        {
            "phase": "recovered",
            "member": member,
            "interruption_returncode": -9,
            "manual_database_repair": False,
            "all_six_applied_states_match": True,
            "workchain_states_match": True,
            "successor_finality_checked": True,
        },
    )
    limit = receipt.get("recovery_limit_seconds")
    if type(limit) not in (int, float) or limit != 180:
        raise ValueError("ACK recovery changed or omitted the original limit")
    elapsed = receipt.get("elapsed_seconds")
    temporary = receipt.get("temporary_bytes")
    if type(elapsed) not in (int, float) or not 4 <= elapsed <= 180:
        raise ValueError("ACK recovery omitted or exceeded its original budget")
    if (
        type(temporary) is not int
        or temporary < 0
        or (temporary > 0) != (mode == "sync-eio")
    ):
        raise ValueError("ACK temporary bytes differ from the failed syscall")
    old, new = recovery.get("old_process", {}), recovery.get("new_process", {})
    if (
        type(old.get("pid")) is not int
        or type(new.get("pid")) is not int
        or old["pid"] <= 0
        or new["pid"] <= 0
        or old["pid"] == new["pid"]
        or receipt.get("old_pid") != old["pid"]
        or receipt.get("new_pid") != new["pid"]
        or not new.get("start_ticks")
        or receipt.get("new_start_ticks") != new["start_ticks"]
    ):
        raise ValueError(
            "ACK recovery is not bound to original and restarted processes"
        )
    for key in (
        "pending_sha256",
        "recovered_ack_sha256",
        "recovered_node_receipt",
        "source_id",
        "session",
    ):
        value = receipt.get(key)
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(c not in "0123456789abcdef" for c in value)
        ):
            raise ValueError("Missing ACK identity/digest evidence")
    error = "Input/output error" if mode == "sync-eio" else "No space left on device"
    if (
        "Node WAL durable but source ACK needs retry:"
        not in receipt.get("native_error_line", "")
        or error not in receipt["native_error_line"]
    ):
        raise ValueError("Missing production source ACK refusal")
    if (
        receipt.get("recovered_ack_kind") not in ("acked", "reference", "delivered")
        or not receipt.get("final_checkpoint")
        or receipt["final_checkpoint"] != recovery.get("last_checkpoint")
        or receipt.get("survivor_checkpoint") != recovery.get("survivor_checkpoint")
        or (
            not expired_member
            and (
                not recovery.get("vote")
                or set(recovery.get("leaders", {})) != {"masterchain", "workchain"}
            )
        )
    ):
        raise ValueError("ACK recovery lacks matching checkpoints or participation")


def check_ack_evidence(runtime, receipt):
    directory = runtime / "source-ack-fault"
    before = (directory / "retained-before.json").read_bytes()
    after = (directory / "recovered-ack.json").read_bytes()
    if (
        len(before) != receipt["pending_bytes"]
        or hashlib.sha256(before).hexdigest() != receipt["pending_sha256"]
        or hashlib.sha256(after).hexdigest() != receipt["recovered_ack_sha256"]
    ):
        raise ValueError("Retained ACK bytes differ from the semantic receipt")
    original, ack = json.loads(before), json.loads(after)
    if (
        original["session_id"] != receipt["session"]
        or original["block_id"] != receipt["source_block"]
    ):
        raise ValueError("ACK retained source changed session/block")
    if receipt["recovered_ack_kind"] == "acked":
        if ack["record"] != original:
            raise ValueError("Recovered ACK changed the original retained source")
        reference = ack
    else:
        reference = (
            ack["reference"] if receipt["recovered_ack_kind"] == "delivered" else ack
        )
        if reference["digest"] != receipt["pending_sha256"] or reference[
            "metadata"
        ] != {**original, "data": "", "signature_set": ""}:
            raise ValueError("Recovered reference differs from retained source")
    if reference["node_receipt"] != receipt["recovered_node_receipt"]:
        raise ValueError("Recovered node receipt differs")
    marker = (directory / "native-error.marker").read_text()
    target = Path(receipt["pending_directory"]) / (receipt["source_id"] + ".ack.tmp")
    if marker != f"source {receipt['mode']}: {target}\n":
        raise ValueError("Native ACK marker names a different failure")
    if (directory / "armed").exists() or not (directory / "disarmed").is_file():
        raise ValueError("ACK injection was not disarmed")
