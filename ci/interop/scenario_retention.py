"""Source-retention cut inputs and exact recovered source evidence."""

import hashlib
import json
from pathlib import Path

from scenario_matrix import require_fields

RETENTIONS = {
    f"source-retention-{point}": point
    for point in ("before-write", "after-partial-write", "after-fsync")
}


def retention_arguments(name, library):
    return [
        "--interrupt-rust-member",
        "2",
        "--source-retention-cut-library",
        str(library),
        "--source-retention-cut-point",
        RETENTIONS[name],
    ]


def retention_artifacts(args, source):
    library = getattr(args, "source_retention_cut_library", None)
    record = getattr(args, "source_retention_cut_build_record", None)
    if library is None or record is None:
        raise ValueError("Retention scenarios require native library and build record")
    build = json.loads(record.read_text())
    native = source.parents[1] / "rtos/src/tests/finality_retention_cut.c"
    if (
        Path(build["source"]).resolve() != native.resolve()
        or Path(build["library"]).resolve() != library.resolve()
    ):
        raise ValueError("Retention build names different inputs")
    for path, meta in (
        (native, build["source_meta"]),
        (library, build["library_meta"]),
    ):
        if (
            path.stat().st_size != meta["bytes"]
            or hashlib.sha256(path.read_bytes()).hexdigest() != meta["sha256"]
        ):
            raise ValueError("Retention source/library differs from build record")
    return [native, library, record]


def check_retention_evidence(runtime, receipt, point):
    directory = runtime / "source-retention-cut"
    original = (directory / "retained-before.json").read_bytes()
    temporary = (directory / "temporary-before.bin").read_bytes()
    recovered = (directory / "recovered-ack.json").read_bytes()
    require_fields(
        receipt,
        {
            "mode": "retain-" + point,
            "phase": "recovered",
            "interrupted_retention_recovered": True,
            "retention_uncommitted_after_interruption": True,
            "retention_uncommitted_before_restart": True,
            "source_pending_committed_before_interruption": False,
            "stopped_state_verified": True,
        },
    )
    for raw, size, digest in (
        (original, receipt.get("pending_bytes"), receipt.get("pending_sha256")),
        (temporary, receipt.get("temporary_bytes"), receipt.get("temporary_sha256")),
    ):
        if (
            type(size) is not int
            or size != len(raw)
            or hashlib.sha256(raw).hexdigest() != digest
        ):
            raise ValueError("Retention bytes differ from receipt")
    if (
        not original
        or not original.startswith(temporary)
        or (
            point == "before-write"
            and temporary
            or point == "after-partial-write"
            and not 0 < len(temporary) == len(original) // 2 < len(original)
            or point == "after-fsync"
            and temporary != original
        )
    ):
        raise ValueError("Retained prefix differs from selected cut")
    if hashlib.sha256(recovered).hexdigest() != receipt.get("recovered_ack_sha256"):
        raise ValueError("Recovered ACK bytes differ")
    before, ack = json.loads(original), json.loads(recovered)
    if (
        before["session_id"] != receipt["session"]
        or before["block_id"] != receipt["source_block"]
    ):
        raise ValueError("Original retention identity differs")
    identity = [
        "rtos-source-finality-v1",
        before["global_id"],
        before["zerostate"],
        before["protocol"],
        before["carrier_version"],
        before["wire_profile"],
        before["profile"],
        before["session_id"],
        before["block_id"],
        before["is_final"],
        [
            before["local_adnl"],
            before["local_validator_index"],
            before["source_validator"],
        ],
    ]
    source_id = hashlib.sha256(
        json.dumps(identity, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    if (
        type(before.get("schema")) is not int
        or before["schema"] != 1
        or before["is_final"] is not True
        or receipt.get("source_id") != source_id
    ):
        raise ValueError("Retention source identity differs from original record")
    node_receipt = receipt.get("recovered_node_receipt")
    if (
        not isinstance(node_receipt, str)
        or len(node_receipt) != 64
        or any(c not in "0123456789abcdef" for c in node_receipt)
    ):
        raise ValueError("Invalid recovered node receipt")
    status = (directory / "stopped-process-status.txt").read_text()
    if not any(
        line.startswith("State:") and len(line.split()) > 1 and line.split()[1] == "T"
        for line in status.splitlines()
    ):
        raise ValueError("Original retention process was not observed stopped")
    kind = receipt.get("recovered_ack_kind")
    if kind == "acked":
        after = ack["record"]
        reference = ack
    elif kind in ("reference", "delivered"):
        reference = ack["reference"] if kind == "delivered" else ack
        after = reference["metadata"]
    else:
        raise ValueError("Unknown recovered retention kind")
    hints = (
        {"created_at_unix_secs", "last_mc_finalized_seqno", "candidate_already_sent"}
        if point != "after-fsync"
        else set()
    )
    expected = {**before, **{key: after[key] for key in hints}}
    if kind == "acked":
        valid = after == expected
    else:
        valid = (
            after == {**expected, "data": "", "signature_set": ""}
            and reference["digest"]
            == hashlib.sha256(
                json.dumps(expected, separators=(",", ":"), ensure_ascii=False).encode()
            ).hexdigest()
        )
    if not valid or reference["node_receipt"] != receipt["recovered_node_receipt"]:
        raise ValueError("Retention recovery substituted original source")
    target = Path(receipt["pending_directory"]) / (receipt["source_id"] + ".tmp")
    if (
        directory / "native-stop.marker"
    ).read_text() != f"source retain-{point} pid={receipt['stopped_pid']}: {target}\n":
        raise ValueError("Native retention marker differs")
    if (directory / "armed").exists() or not (directory / "disarmed").is_file():
        raise ValueError("Retention injection not disarmed")


def check_retention_result(name, receipt, recovery):
    if not isinstance(receipt, dict) or not isinstance(recovery, dict):
        raise TypeError("Missing retention recovery receipts")
    require_fields(
        receipt,
        {
            "mode": "retain-" + RETENTIONS[name],
            "member": 2,
            "phase": "recovered",
            "interruption_returncode": -9,
            "manual_database_repair": False,
            "pending_preserved_after_interruption": True,
            "pending_preserved_before_restart": True,
            "original_source_ack_recovered": True,
            "interrupted_retention_recovered": True,
            "source_pending_committed_before_interruption": False,
            "retention_uncommitted_after_interruption": True,
            "retention_uncommitted_before_restart": True,
        },
    )
    require_fields(
        recovery,
        {
            "member": 2,
            "phase": "recovered",
            "interruption_returncode": -9,
            "manual_database_repair": False,
            "all_six_applied_states_match": True,
            "workchain_states_match": True,
            "successor_finality_checked": True,
        },
    )
    limit, elapsed = (
        receipt.get("recovery_limit_seconds"),
        receipt.get("elapsed_seconds"),
    )
    if (
        type(limit) not in (int, float)
        or limit != 180
        or type(elapsed) not in (int, float)
        or not 4 <= elapsed <= 180
    ):
        raise ValueError("Retention omitted or exceeded the original recovery budget")
    old, new = recovery.get("old_process", {}), recovery.get("new_process", {})
    if (
        type(old.get("pid")) is not int
        or type(new.get("pid")) is not int
        or min(old["pid"], new["pid"]) <= 0
        or old["pid"] == new["pid"]
        or receipt.get("old_pid") != old["pid"]
        or receipt.get("new_pid") != new["pid"]
        or receipt.get("stopped_pid") != old["pid"]
        or not new.get("start_ticks")
        or receipt.get("new_start_ticks") != new["start_ticks"]
    ):
        raise ValueError("Retention recovery substituted process identity")
    if (
        not receipt.get("final_checkpoint")
        or receipt["final_checkpoint"] != recovery.get("last_checkpoint")
        or receipt.get("survivor_checkpoint") != recovery.get("survivor_checkpoint")
        or not recovery.get("vote")
        or set(recovery.get("leaders", {})) != {"masterchain", "workchain"}
    ):
        raise ValueError(
            "Retention recovery lacks matching checkpoints or participation"
        )
